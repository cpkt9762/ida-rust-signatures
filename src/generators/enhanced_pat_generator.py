"""Enhanced PAT signature generator with FLAIR integration and rust-demangler support.

This module provides an enhanced PAT generator that combines the best of both worlds:
- FLAIR tools integration for standard signature generation
- Custom pattern extraction with rust-demangler for better function names
- Automatic collision handling for sigmake
"""

import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union

try:
    from rust_demangler import demangle as rust_demangle
    RUST_DEMANGLER_AVAILABLE = True
except ImportError:
    RUST_DEMANGLER_AVAILABLE = False
    rust_demangle = None

from .custom_pat_generator import CustomPATGenerator
from .flair_generator import FLAIRGenerator
from ..core.config import settings
from ..core.exceptions import SignatureGenerationError, ValidationError
from ..core.logger import LoggerMixin, log_execution_time
from ..extractors.rlib_extractor import RlibExtractor


class EnhancedPATGenerator(LoggerMixin):
    """Enhanced PAT generator with FLAIR integration and improved name handling."""
    
    def __init__(self, 
                 prefer_flair: bool = True,
                 custom_fallback: bool = True,
                 demangle_names: bool = True,
                 use_short_names: bool = True,
                 handle_collisions: bool = True):
        """Initialize enhanced PAT generator.
        
        Args:
            prefer_flair: Prefer FLAIR tools when available
            custom_fallback: Use custom generator as fallback
            demangle_names: Use rust-demangler for function names
            use_short_names: Extract readable short names
            handle_collisions: Automatically handle sigmake collisions
        """
        self.prefer_flair = prefer_flair
        self.custom_fallback = custom_fallback
        self.demangle_names = demangle_names
        self.use_short_names = use_short_names
        self.handle_collisions = handle_collisions
        
        # Initialize sub-generators
        self.custom_generator = CustomPATGenerator(
            demangle_rust_names=demangle_names,
            use_short_names=use_short_names
        )
        
        try:
            self.flair_generator = FLAIRGenerator()
            self.flair_available = True
        except Exception as e:
            self.flair_available = False
            self.logger.warning(f"FLAIR tools not available: {e}")
        
        self.logger.info(f"EnhancedPATGenerator initialized: "
                        f"flair={self.flair_available}, "
                        f"prefer_flair={prefer_flair}, "
                        f"demangle={demangle_names}")
    
    @log_execution_time
    def generate_signatures(self, 
                           rlib_path: Path, 
                           output_dir: Path,
                           library_name: Optional[str] = None,
                           generate_sig: bool = True) -> Dict[str, Path]:
        """Generate complete signature set from RLIB file.
        
        Args:
            rlib_path: Path to .rlib file
            output_dir: Output directory for signatures
            library_name: Library name (defaults to rlib stem)
            generate_sig: Also generate SIG file
            
        Returns:
            Dictionary with 'pat' and optionally 'sig' keys mapping to file paths
        """
        if not rlib_path.exists():
            raise ValidationError(f"RLIB file not found: {rlib_path}")
        
        if not library_name:
            library_name = rlib_path.stem
            if library_name.startswith('lib'):
                library_name = library_name[3:]
        
        self.logger.info(f"Generating signatures for {library_name} from {rlib_path}")
        
        # Ensure output directory exists
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Define output paths
        pat_path = output_dir / f"{library_name}.pat"
        results = {}
        
        # Generate PAT file
        pat_result = self._generate_pat_file(rlib_path, pat_path, library_name)
        results['pat'] = pat_result
        
        # Generate SIG file if requested
        if generate_sig and self.flair_available:
            sig_path = output_dir / f"{library_name}.sig"
            try:
                sig_result = self._generate_sig_file(pat_result, sig_path, library_name)
                results['sig'] = sig_result
            except Exception as e:
                self.logger.warning(f"SIG generation failed: {e}")
        
        return results
    
    def _generate_pat_file(self, rlib_path: Path, output_pat: Path, library_name: str) -> Path:
        """Generate PAT file using the best available method."""
        
        if self.prefer_flair and self.flair_available:
            # Try FLAIR first
            try:
                self.logger.info("Attempting PAT generation with FLAIR tools...")
                return self._generate_pat_with_flair(rlib_path, output_pat, library_name)
            except Exception as e:
                self.logger.warning(f"FLAIR PAT generation failed: {e}")
                if not self.custom_fallback:
                    raise
        
        # Use custom generator
        self.logger.info("Using custom PAT generator...")
        return self.custom_generator.generate_pat_from_rlib(
            rlib_path, output_pat, library_name
        )
    
    def _generate_pat_with_flair(self, rlib_path: Path, output_pat: Path, library_name: str) -> Path:
        """Generate PAT using FLAIR pelf tool."""
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Extract object files
            extractor = RlibExtractor(temp_path)
            object_files = extractor.extract_objects(rlib_path, temp_path / "objects")
            
            if not object_files:
                raise SignatureGenerationError(
                    f"No object files extracted from {rlib_path}",
                    stage="rlib_extraction"
                )
            
            self.logger.info(f"Extracted {len(object_files)} object files")
            
            # Use FLAIR pelf to generate PAT
            pelf_path = self.flair_generator.pelf_path
            cmd = [str(pelf_path), "-p32"] + [str(f) for f in object_files] + [str(output_pat)]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode != 0:
                raise SignatureGenerationError(
                    f"FLAIR pelf failed: {result.stderr}",
                    stage="flair_pat_generation"
                )
            
            if not output_pat.exists() or output_pat.stat().st_size == 0:
                raise SignatureGenerationError(
                    f"FLAIR pelf produced no output",
                    stage="flair_pat_generation"
                )
            
            # Post-process to improve function names
            if self.demangle_names:
                self._enhance_pat_names(output_pat, library_name)
            
            return output_pat
    
    def _enhance_pat_names(self, pat_file: Path, library_name: str):
        """Dual-layer bulletproof PAT enhancement with guaranteed 100% function retention.
        
        Architecture:
        - Layer 1 (保底层): Ensures every line is preserved regardless of processing outcome
        - Layer 2 (增强层): Attempts intelligent enhancement without affecting Layer 1 guarantee
        
        Inspired by join-pat-files.py's reliability but with our quality improvements.
        """
        
        try:
            # Read original PAT file 
            lines = pat_file.read_text(encoding='utf-8').splitlines()
            enhanced_lines = []
            
            # Comprehensive statistics
            stats = {
                'total_lines': len(lines),
                'function_lines': 0,
                'enhanced_successfully': 0,
                'preserved_original': 0,
                'enhancement_failed': 0,
                'non_function_lines': 0
            }
            
            for line in lines:
                # Handle non-function lines (comments, separators, empty lines)
                if not line.strip() or line.startswith('---') or line.startswith(';'):
                    enhanced_lines.append(line)
                    stats['non_function_lines'] += 1
                    continue
                
                # This is a function line
                stats['function_lines'] += 1
                
                # LAYER 1 (保底层): GUARANTEE - This line WILL be in the output
                output_line = line  # Absolute fallback - original line preserved
                processing_result = "preserved_original"
                
                # LAYER 2 (增强层): ATTEMPT - Try to enhance, but failure doesn't affect Layer 1
                try:
                    enhanced_line = self._attempt_line_enhancement(line)
                    if enhanced_line and self._validate_enhancement(line, enhanced_line):
                        output_line = enhanced_line
                        processing_result = "enhanced_successfully"
                        self.logger.debug(f"Enhanced line: {line[:50]}... -> {enhanced_line[:50]}...")
                    else:
                        self.logger.debug(f"Enhancement validation failed, preserved original")
                        
                except Exception as e:
                    # Any enhancement failure is handled gracefully
                    processing_result = "enhancement_failed"
                    self.logger.debug(f"Enhancement attempt failed: {str(e)[:50]}")
                
                # Update statistics
                stats[processing_result] += 1
                
                # GUARANTEE: Output the line (either enhanced or original)
                enhanced_lines.append(output_line)
            
            # Write enhanced PAT file
            enhanced_content = '\n'.join(enhanced_lines)
            pat_file.write_text(enhanced_content, encoding='utf-8')
            
            # CRITICAL VALIDATION: Verify function count is unchanged
            output_function_count = sum(1 for line in enhanced_lines 
                                      if line.strip() and not line.startswith(';') and not line.startswith('---'))
            
            if output_function_count != stats['function_lines']:
                # This should NEVER happen with our dual-layer architecture
                raise RuntimeError(
                    f"CRITICAL FAILURE: Function count mismatch! "
                    f"Input: {stats['function_lines']}, Output: {output_function_count}. "
                    f"This indicates a serious bug in the dual-layer architecture."
                )
            
            # Success report
            enhancement_rate = (stats['enhanced_successfully'] / stats['function_lines'] * 100) if stats['function_lines'] > 0 else 0
            
            self.logger.info(
                f"Bulletproof PAT processing complete - "
                f"Enhanced: {stats['enhanced_successfully']}, "
                f"Preserved: {stats['preserved_original']}, "
                f"Failed: {stats['enhancement_failed']}, "
                f"Total functions: {stats['function_lines']} "
                f"(Enhancement rate: {enhancement_rate:.1f}%)"
            )
            
            if stats['function_lines'] > 0:
                self.logger.info("✓ 100% function retention guaranteed by dual-layer architecture")
            
        except Exception as e:
            self.logger.error(f"Critical error in bulletproof PAT enhancement: {e}")
            raise
    
    def _attempt_line_enhancement(self, line: str) -> Optional[str]:
        """Layer 2: Attempt to enhance a PAT line (may fail safely).
        
        Returns:
            Enhanced line if successful, None if enhancement should not be applied
        """
        # Only attempt enhancement on lines that might contain Rust functions
        if not ('_ZN' in line or '_RNv' in line):
            return None
            
        if not RUST_DEMANGLER_AVAILABLE:
            return None
        
        # Extract mangled function name
        mangled_name = self._extract_mangled_name(line)
        if not mangled_name:
            return None
        
        # Attempt demangling with validation
        try:
            demangled = rust_demangle(mangled_name)
            if not (demangled and mangled_name.endswith('E')):
                return None
            
            # Attempt line reconstruction
            enhanced_line = self._replace_function_name_in_line(line, mangled_name, demangled)
            return enhanced_line
            
        except Exception:
            # Enhancement attempt failed, but this is expected and acceptable
            return None
    
    def _validate_enhancement(self, original_line: str, enhanced_line: str) -> bool:
        """Validate that an enhanced line is acceptable for use.
        
        Args:
            original_line: The original PAT line
            enhanced_line: The enhanced PAT line
            
        Returns:
            True if enhanced line should be used, False if original should be kept
        """
        if not enhanced_line or not enhanced_line.strip():
            return False
            
        # Basic sanity checks
        if len(enhanced_line) > len(original_line) * 5:  # Prevent extreme length explosion
            return False
            
        if enhanced_line.count(' ') < 2:  # Should maintain basic PAT structure
            return False
            
        # Should contain reasonable content
        if not any(c.isalnum() for c in enhanced_line):
            return False
            
        return True
    
    def _extract_mangled_name(self, line: str) -> Optional[str]:
        """Extract the mangled function name from a PAT line."""
        mangled_name = None
        
        # Find the longest mangled name in the line (handles multiple occurrences)
        for name_start in ['_ZN', '_RNv']:
            if name_start in line:
                parts = line.split(name_start)
                if len(parts) > 1:
                    # Get the part after the last occurrence
                    name_part = name_start + parts[-1]
                    # Extract until space or end of string
                    name_part = name_part.split()[0]
                    # Keep the longest one (most likely to be the main function)
                    if len(name_part) > len(mangled_name or ''):
                        mangled_name = name_part
        
        return mangled_name
    
    def _replace_function_name_in_line(self, line: str, mangled_name: str, demangled_name: str) -> str:
        """Replace the mangled function name with demangled name in PAT line.
        
        Attempts to preserve the original PAT format while updating the function name.
        """
        try:
            # Sanitize demangled name for PAT format compatibility
            # Remove characters that sigmake doesn't like
            safe_name = demangled_name
            
            # Replace problematic characters with underscores
            replacements = [
                ('<', '_'),
                ('>', '_'),
                ('(', '_'),
                (')', '_'),
                ('[', '_'),
                (']', '_'),
                ('{', '_'),
                ('}', '_'),
                (' ', '_'),
                (',', '_'),
                ('&', '_'),
                ('*', '_'),
                ('$', '_'),
                ('@', '_'),
                ('!', '_'),
                ('.', '_'),
                ('/', '_'),
                ('\\', '_'),
                (':', '_'),  # Keep :: for namespace separation
            ]
            
            for old_char, new_char in replacements:
                safe_name = safe_name.replace(old_char, new_char)
            
            # Keep :: for Rust namespace separation (it's visual only, doesn't affect sigmake)
            safe_name = safe_name.replace('__', '::')
            
            # Remove consecutive underscores
            while '__' in safe_name and not safe_name.startswith('__'):
                safe_name = safe_name.replace('__', '_')
            
            # For pelf multi-column format, try to preserve structure
            if mangled_name in line:
                # Simple replacement while preserving format
                return line.replace(mangled_name, safe_name, 1)
            else:
                # Fallback: just return original line if replacement fails
                return line
        except:
            # If anything goes wrong, return original line
            return line
    
    def _generate_sig_file(self, pat_file: Path, output_sig: Path, library_name: Optional[str] = None) -> Path:
        """Generate SIG file from PAT file with collision handling."""
        
        sigmake_path = self.flair_generator.sigmake_path
        
        try:
            # Build sigmake command with optional library name
            cmd = [str(sigmake_path)]
            if library_name:
                cmd.append(f"-n{library_name}")
            cmd.extend([str(pat_file), str(output_sig)])
            
            # First attempt
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0 and output_sig.exists():
                self.logger.info(f"SIG file generated successfully")
                return output_sig
            
            # Handle collisions if needed
            if self.handle_collisions and "COLLISION" in result.stderr:
                self.logger.info("Handling signature collisions...")
                return self._handle_sig_collisions(pat_file, output_sig, result.stderr, library_name)
            else:
                raise SignatureGenerationError(
                    f"sigmake failed: {result.stderr}",
                    stage="sig_generation"
                )
        
        except subprocess.TimeoutExpired:
            raise SignatureGenerationError(
                "sigmake timed out",
                stage="sig_generation"
            )
    
    def _handle_sig_collisions(self, pat_file: Path, output_sig: Path, error_msg: str, library_name: Optional[str] = None) -> Path:
        """Handle sigmake collisions automatically."""
        
        exc_file = pat_file.with_suffix('.exc')
        
        if not exc_file.exists():
            raise SignatureGenerationError(
                f"Expected collision file not found: {exc_file}",
                stage="collision_handling"
            )
        
        try:
            # Read and process collision file
            lines = exc_file.read_text(encoding='utf-8').splitlines()
            processed_lines = []
            collision_count = 0
            
            for line in lines:
                if line.strip() and not line.startswith(';'):
                    # Comment out collision entry
                    processed_lines.append(f";{line}")
                    collision_count += 1
                else:
                    processed_lines.append(line)
            
            # Write processed collision file
            exc_file.write_text('\n'.join(processed_lines), encoding='utf-8')
            
            self.logger.info(f"Commented out {collision_count} collision entries")
            
            # Retry sigmake with optional library name
            cmd = [str(self.flair_generator.sigmake_path)]
            if library_name:
                cmd.append(f"-n{library_name}")
            cmd.extend([str(pat_file), str(output_sig)])
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0 and output_sig.exists():
                self.logger.info(f"SIG file generated after collision resolution")
                return output_sig
            else:
                raise SignatureGenerationError(
                    f"sigmake still failed after collision handling: {result.stderr}",
                    stage="collision_handling"
                )
        
        except Exception as e:
            raise SignatureGenerationError(
                f"Failed to handle collisions: {e}",
                stage="collision_handling"
            ) from e
    
    def batch_generate_signatures(self, 
                                  rlib_files: List[Path], 
                                  output_dir: Path,
                                  generate_sig: bool = True) -> Dict[str, Dict[str, Path]]:
        """Generate signatures for multiple RLIB files.
        
        Args:
            rlib_files: List of .rlib files to process
            output_dir: Output directory for all signatures
            generate_sig: Also generate SIG files
            
        Returns:
            Dictionary mapping library names to their signature files
        """
        if not rlib_files:
            raise ValidationError("No RLIB files provided")
        
        self.logger.info(f"Batch generating signatures for {len(rlib_files)} libraries")
        
        results = {}
        
        for rlib_file in rlib_files:
            try:
                library_name = rlib_file.stem
                if library_name.startswith('lib'):
                    library_name = library_name[3:]
                
                lib_results = self.generate_signatures(
                    rlib_file, output_dir, library_name, generate_sig
                )
                
                results[library_name] = lib_results
                
            except Exception as e:
                self.logger.error(f"Failed to generate signatures for {rlib_file}: {e}")
                results[library_name] = {"error": str(e)}
        
        successful = sum(1 for r in results.values() if "error" not in r)
        self.logger.info(f"Batch generation complete: {successful}/{len(rlib_files)} successful")
        
        return results
    
    def get_generator_info(self) -> Dict[str, Any]:
        """Get information about available generators and tools."""
        info = {
            "flair_available": self.flair_available,
            "custom_available": True,
            "demangle_names": self.demangle_names,
            "use_short_names": self.use_short_names,
            "handle_collisions": self.handle_collisions,
        }
        
        if self.flair_available:
            info.update(self.flair_generator.get_tool_info())
        
        return info