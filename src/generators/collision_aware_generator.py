#!/usr/bin/env python3
"""
Collision-aware PAT generator that combines prevention strategies from
solana-ida-signatures-factory with our automatic resolution capabilities.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import subprocess
import tempfile
import shutil

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.collision_prevention import CollisionPrevention, EnhancedCollisionHandler
from src.generators.enhanced_pat_generator import EnhancedPATGenerator, LoggerMixin


class CollisionAwarePATGenerator(LoggerMixin):
    """
    Advanced PAT generator with comprehensive collision handling:
    1. Prevention: Pattern deduplication, version tagging, quality filtering
    2. Resolution: Automatic EXC file processing
    3. Optimization: Multi-pass generation for best results
    """
    
    def __init__(self,
                 base_generator: Optional[EnhancedPATGenerator] = None,
                 enable_prevention: bool = True,
                 enable_deduplication: bool = True,
                 enable_version_tagging: bool = False,
                 enable_quality_filter: bool = True,
                 auto_resolve_collisions: bool = True):
        """
        Initialize collision-aware generator.
        
        Args:
            base_generator: Base PAT generator to use
            enable_prevention: Enable collision prevention strategies
            enable_deduplication: Remove duplicate patterns
            enable_version_tagging: Add version suffixes to function names
            enable_quality_filter: Filter out low-quality functions
            auto_resolve_collisions: Automatically resolve sigmake collisions
        """
        super().__init__()
        
        self.base_generator = base_generator or EnhancedPATGenerator()
        self.prevention = CollisionPrevention(logger=self.logger)
        self.handler = EnhancedCollisionHandler(prevention=self.prevention)
        
        # Configuration
        self.enable_prevention = enable_prevention
        self.enable_deduplication = enable_deduplication
        self.enable_version_tagging = enable_version_tagging
        self.enable_quality_filter = enable_quality_filter
        self.auto_resolve_collisions = auto_resolve_collisions
        
        # Statistics
        self.stats = {
            'total_functions': 0,
            'filtered_functions': 0,
            'deduplicated_functions': 0,
            'collisions_prevented': 0,
            'collisions_resolved': 0
        }
    
    def generate_signatures(self,
                          rlib_path: Path,
                          output_dir: Path,
                          library_name: str,
                          library_version: Optional[str] = None,
                          generate_sig: bool = True,
                          multi_pass: bool = True) -> Dict[str, Path]:
        """
        Generate signatures with comprehensive collision handling.
        
        Args:
            rlib_path: Path to the RLIB file
            output_dir: Output directory for signatures
            library_name: Name for the library
            library_version: Optional version string for tagging
            generate_sig: Whether to generate SIG file
            multi_pass: Use multi-pass generation for optimization
            
        Returns:
            Dictionary with paths to generated files
        """
        self.logger.info(f"Generating collision-aware signatures for {library_name}")
        
        output_dir.mkdir(parents=True, exist_ok=True)
        results = {}
        
        # Step 1: Generate initial PAT using base generator
        self.logger.info("Step 1: Generating initial PAT file...")
        base_results = self.base_generator.generate_signatures(
            rlib_path=rlib_path,
            output_dir=output_dir,
            library_name=f"{library_name}_temp",
            generate_sig=False  # Don't generate SIG yet
        )
        
        if 'pat' not in base_results:
            raise ValueError("Base generator failed to create PAT file")
        
        temp_pat = base_results['pat']
        
        # Step 2: Apply collision prevention strategies
        if self.enable_prevention:
            self.logger.info("Step 2: Applying collision prevention strategies...")
            
            # Add version to filename if provided and ensure pat/ subdirectory
            pat_dir = output_dir / "pat"
            pat_dir.mkdir(parents=True, exist_ok=True)
            
            if library_version:
                final_pat = pat_dir / f"{library_name}_{library_version}.pat"
            else:
                final_pat = pat_dir / f"{library_name}.pat"
            
            prevention_stats = self.handler.process_pat_file(
                input_pat=temp_pat,
                output_pat=final_pat,
                version=library_version if self.enable_version_tagging else None,
                deduplicate=self.enable_deduplication,
                filter_low_quality=self.enable_quality_filter
            )
            
            # Update statistics
            self.stats.update(prevention_stats)
            
            # Clean up temp file
            temp_pat.unlink()
            
            results['pat'] = final_pat
        else:
            # Just rename the temp file to pat/ subdirectory
            pat_dir = output_dir / "pat"
            pat_dir.mkdir(parents=True, exist_ok=True)
            
            if library_version:
                final_pat = pat_dir / f"{library_name}_{library_version}.pat"
            else:
                final_pat = pat_dir / f"{library_name}.pat"
            temp_pat.rename(final_pat)
            results['pat'] = final_pat
        
        # Step 3: Generate SIG with collision handling
        if generate_sig:
            self.logger.info("Step 3: Generating SIG file with collision handling...")
            
            if multi_pass:
                sig_path = self._multi_pass_sig_generation(
                    pat_file=results['pat'],
                    output_dir=output_dir,
                    library_name=library_name,
                    library_version=library_version
                )
            else:
                sig_path = self._single_pass_sig_generation(
                    pat_file=results['pat'],
                    output_dir=output_dir,
                    library_name=library_name,
                    library_version=library_version
                )
            
            if sig_path and sig_path.exists():
                results['sig'] = sig_path
        
        # Step 4: Report results
        self._report_statistics()
        
        return results
    
    def _single_pass_sig_generation(self, pat_file: Path, output_dir: Path, library_name: str, library_version: Optional[str] = None) -> Optional[Path]:
        """Single-pass SIG generation with automatic collision handling"""
        # Create sig/ subdirectory and use proper naming
        sig_dir = output_dir / "sig"
        sig_dir.mkdir(parents=True, exist_ok=True)
        
        if library_version:
            sig_file = sig_dir / f"{library_name}_{library_version}.sig"
        else:
            sig_file = sig_dir / f"{library_name}.sig"
        
        # EXC file remains in same directory as PAT for sigmake to find it
        exc_file = pat_file.with_suffix('.exc')
        
        # First attempt
        sigmake_result = self._run_sigmake(pat_file, sig_file, library_name, library_version)
        
        if sigmake_result['success']:
            self.logger.info("SIG generated without collisions")
            return sig_file
        
        if ("COLLISION" in sigmake_result['error'] or "COLLISIONS:" in sigmake_result['error']) and exc_file.exists():
            self.logger.info(f"Collisions detected, resolving automatically...")
            
            if self.auto_resolve_collisions:
                # Try multiple collision resolution strategies
                strategies = ['select_unique', 'select_first', 'select_all']
                
                for strategy in strategies:
                    self.logger.info(f"Trying collision resolution strategy: {strategy}")
                    
                    # Restore original EXC file for each attempt
                    self._restore_exc_file(exc_file)
                    
                    # Automatically resolve collisions
                    resolved_count = self._enhanced_collision_resolution(
                        exc_file=exc_file,
                        strategy=strategy,
                        library_name=library_name
                    )
                    self.stats['collisions_resolved'] = resolved_count
                    
                    # Attempt SIG generation with resolved collisions
                    sigmake_result = self._run_sigmake(pat_file, sig_file, library_name, library_version)
                    
                    if sigmake_result['success']:
                        self.logger.info(f"SIG generated using {strategy} strategy after resolving {resolved_count} collisions")
                        return sig_file
                    else:
                        self.logger.warning(f"Strategy {strategy} failed: {sigmake_result['error']}")
                
                self.logger.error("All collision resolution strategies failed")
            else:
                self.logger.warning("Collisions detected but auto-resolution is disabled")
        else:
            self.logger.error(f"SIG generation failed: {sigmake_result['error']}")
        
        return None
    
    def _multi_pass_sig_generation(self, pat_file: Path, output_dir: Path, library_name: str, library_version: Optional[str] = None) -> Optional[Path]:
        """
        Multi-pass SIG generation with iterative optimization.
        
        This approach:
        1. First tries with all functions
        2. If collisions occur, analyzes them
        3. Removes problematic patterns
        4. Retries until successful or no more optimizations possible
        """
        # Create sig/ subdirectory and use proper naming
        sig_dir = output_dir / "sig"
        sig_dir.mkdir(parents=True, exist_ok=True)
        
        if library_version:
            sig_file = sig_dir / f"{library_name}_{library_version}.sig"
        else:
            sig_file = sig_dir / f"{library_name}.sig"
        
        # EXC file remains in same directory as PAT for sigmake to find it
        exc_file = pat_file.with_suffix('.exc')
        
        max_passes = 3
        current_pat = pat_file
        
        for pass_num in range(1, max_passes + 1):
            self.logger.info(f"Multi-pass generation - Pass {pass_num}/{max_passes}")
            
            # Attempt to generate SIG
            sigmake_result = self._run_sigmake(current_pat, sig_file, library_name, library_version)
            
            if sigmake_result['success']:
                self.logger.info(f"SIG generated successfully on pass {pass_num}")
                return sig_file
            
            if ("COLLISION" not in sigmake_result['error'] and "COLLISIONS:" not in sigmake_result['error']) or not exc_file.exists():
                self.logger.error(f"Non-collision error: {sigmake_result['error']}")
                break
            
            # Analyze collisions
            collision_info = self._analyze_collisions(exc_file)
            self.logger.info(f"Found {len(collision_info)} collision groups")
            
            if pass_num < max_passes:
                # Create optimized PAT for next pass (use temp directory to avoid cluttering pat/)
                optimized_pat = output_dir / f"{library_name}_pass{pass_num + 1}.pat"
                removed_count = self._create_optimized_pat(
                    current_pat, optimized_pat, collision_info
                )
                
                if removed_count == 0:
                    self.logger.info("No more optimizations possible")
                    break
                
                self.logger.info(f"Removed {removed_count} problematic patterns")
                current_pat = optimized_pat
            else:
                # Last pass - try automatic resolution
                if self.auto_resolve_collisions:
                    resolved_count = self.handler.auto_resolve_collisions(
                        exc_file=exc_file,
                        strategy='select_unique'  # More selective on final pass
                    )
                    self.stats['collisions_resolved'] = resolved_count
                    
                    # Final attempt
                    sigmake_result = self._run_sigmake(current_pat, sig_file, library_name, library_version)
                    if sigmake_result['success']:
                        self.logger.info(f"SIG generated after final collision resolution")
                        return sig_file
        
        self.logger.warning("Multi-pass generation completed without success")
        return None
    
    def _run_sigmake(self, pat_file: Path, sig_file: Path, library_name: Optional[str] = None, library_version: Optional[str] = None) -> Dict[str, Any]:
        """Run sigmake and return result with optional library name and version"""
        sigmake_path = self.base_generator.flair_generator.sigmake_path
        
        if not sigmake_path or not Path(sigmake_path).exists():
            return {'success': False, 'error': 'sigmake not found'}
        
        try:
            # Build command with optional library name and version
            cmd = [str(sigmake_path)]
            if library_name:
                # Construct display name with version if available
                if library_version:
                    display_name = f"{library_name} v{library_version}"
                else:
                    display_name = library_name
                cmd.append(f"-n{display_name}")
            cmd.extend([str(pat_file), str(sig_file)])
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0 and sig_file.exists():
                return {'success': True, 'error': None}
            else:
                return {'success': False, 'error': result.stderr}
                
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'sigmake timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _analyze_collisions(self, exc_file: Path) -> List[Dict[str, Any]]:
        """Analyze collision patterns from EXC file"""
        collisions = []
        
        with open(exc_file, 'r') as f:
            lines = f.readlines()
        
        current_group = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith(';'):
                if current_group:
                    collisions.append({
                        'functions': current_group,
                        'count': len(current_group)
                    })
                    current_group = []
            elif not line.startswith(('+', '-')):
                current_group.append(line)
        
        if current_group:
            collisions.append({
                'functions': current_group,
                'count': len(current_group)
            })
        
        return collisions
    
    def _create_optimized_pat(self, input_pat: Path, output_pat: Path, 
                             collision_info: List[Dict]) -> int:
        """Create optimized PAT by removing highly colliding patterns"""
        # Read input PAT
        with open(input_pat, 'r') as f:
            lines = f.readlines()
        
        # Identify functions to remove (those in large collision groups)
        functions_to_remove = set()
        for group in collision_info:
            if group['count'] > 5:  # Remove from large collision groups
                functions_to_remove.update(group['functions'])
        
        # Filter PAT lines
        filtered_lines = []
        removed_count = 0
        
        for line in lines:
            if line.strip() and not line.startswith((';', '---')):
                parts = line.split()
                if len(parts) >= 6:
                    func_name = parts[5]
                    if func_name in functions_to_remove:
                        removed_count += 1
                        continue
            
            filtered_lines.append(line)
        
        # Write optimized PAT
        with open(output_pat, 'w') as f:
            f.writelines(filtered_lines)
        
        return removed_count
    
    def _report_statistics(self):
        """Report generation statistics"""
        self.logger.info("=== Collision-Aware Generation Statistics ===")
        self.logger.info(f"Total functions processed: {self.stats.get('total_functions', 'N/A')}")
        self.logger.info(f"Functions filtered (quality): {self.stats.get('filtered_functions', 0)}")
        self.logger.info(f"Functions deduplicated: {self.stats.get('deduplicated_functions', 0)}")
        self.logger.info(f"Collisions prevented: {self.stats.get('collisions_prevented', 0)}")
        self.logger.info(f"Collisions resolved: {self.stats.get('collisions_resolved', 0)}")
        
        if self.enable_version_tagging:
            self.logger.info(f"Functions version-tagged: {self.stats.get('version_tagged', 0)}")
    
    def _restore_exc_file(self, exc_file: Path) -> None:
        """Restore EXC file to original state for retry attempts"""
        if exc_file.exists():
            # Create backup if doesn't exist
            backup_file = exc_file.with_suffix('.exc.backup')
            if not backup_file.exists():
                shutil.copy2(exc_file, backup_file)
            else:
                # Restore from backup
                shutil.copy2(backup_file, exc_file)
    
    def _enhanced_collision_resolution(self, exc_file: Path, strategy: str, library_name: str) -> int:
        """Enhanced collision resolution with multiple strategies"""
        if not exc_file.exists():
            return 0
        
        resolved_count = 0
        
        try:
            with open(exc_file, 'r') as f:
                lines = f.readlines()
            
            modified_lines = []
            current_group = []
            in_collision_group = False
            
            for line in lines:
                original_line = line
                line = line.strip()
                
                # Skip comment lines
                if line.startswith(';') or not line:
                    if current_group:
                        # Process current collision group
                        selected_line = self._select_collision_resolution(
                            current_group, strategy, library_name
                        )
                        if selected_line:
                            modified_lines.append(selected_line)
                            resolved_count += len(current_group) - 1  # Count resolved collisions
                        current_group = []
                        in_collision_group = False
                    modified_lines.append(original_line)
                    continue
                
                # Detect if this is a collision group (multiple functions with same signature)
                if '\t' in line and not line.startswith(('+', '-')):
                    current_group.append(original_line)
                    in_collision_group = True
                else:
                    if current_group:
                        # Process previous collision group
                        selected_line = self._select_collision_resolution(
                            current_group, strategy, library_name
                        )
                        if selected_line:
                            modified_lines.append(selected_line)
                            resolved_count += len(current_group) - 1
                        current_group = []
                    modified_lines.append(original_line)
                    in_collision_group = False
            
            # Handle final group
            if current_group:
                selected_line = self._select_collision_resolution(
                    current_group, strategy, library_name
                )
                if selected_line:
                    modified_lines.append(selected_line)
                    resolved_count += len(current_group) - 1
            
            # Write modified EXC file
            with open(exc_file, 'w') as f:
                f.writelines(modified_lines)
            
            self.logger.info(f"Resolved {resolved_count} collisions using {strategy} strategy")
            return resolved_count
            
        except Exception as e:
            self.logger.error(f"Error in collision resolution: {e}")
            return 0
    
    def _select_collision_resolution(self, collision_group: List[str], strategy: str, library_name: str) -> str:
        """Select which function to keep from a collision group"""
        if not collision_group:
            return ""
        
        if strategy == 'select_first':
            # Select first function and mark it with '+'
            selected = collision_group[0]
            if not selected.startswith('+'):
                selected = '+' + selected.lstrip('-')
            return selected
            
        elif strategy == 'select_unique':
            # Select functions that contain the library name
            library_funcs = [line for line in collision_group 
                           if library_name.replace('-', '_') in line.lower()]
            if library_funcs:
                selected = library_funcs[0]
                if not selected.startswith('+'):
                    selected = '+' + selected.lstrip('-')
                return selected
            else:
                # Fallback to first if no library-specific function found
                selected = collision_group[0]
                if not selected.startswith('+'):
                    selected = '+' + selected.lstrip('-')
                return selected
                
        elif strategy == 'select_all':
            # Mark all functions for inclusion (may still cause collisions)
            result_lines = []
            for line in collision_group:
                if not line.startswith('+'):
                    line = '+' + line.lstrip('-')
                result_lines.append(line)
            return ''.join(result_lines)
        
        # Default: select first
        selected = collision_group[0]
        if not selected.startswith('+'):
            selected = '+' + selected.lstrip('-')
        return selected


# Convenience function
def create_collision_aware_generator(**kwargs) -> CollisionAwarePATGenerator:
    """Create a collision-aware generator with sensible defaults"""
    # Extract specific parameters to avoid duplicates
    params = {
        'enable_prevention': kwargs.pop('enable_prevention', True),
        'enable_deduplication': kwargs.pop('enable_deduplication', True),
        'enable_version_tagging': kwargs.pop('enable_version_tagging', False),
        'enable_quality_filter': kwargs.pop('enable_quality_filter', True),
        'auto_resolve_collisions': kwargs.pop('auto_resolve_collisions', True)
    }
    
    # Add any remaining kwargs
    params.update(kwargs)
    
    return CollisionAwarePATGenerator(**params)