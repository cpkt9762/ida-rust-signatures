"""Sublibrary extractor for Rust standard library components.

This module extracts Rust standard library components (core, std, alloc) from 
the main library PAT file by filtering functions based on their mangled names.
"""

from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import shutil

from ....core.config import settings
from ....core.logger import LoggerMixin


class SubLibraryExtractor(LoggerMixin):
    """Extracts Rust standard library sublibraries from main library PAT files."""
    
    # Function namespace mappings for Rust standard library components
    NAMESPACE_MAPPINGS = {
        "core": {
            "prefixes": ["_ZN4core", "_ZN94core", "_ZN95core", "_ZN96core"],
            "description": "Rust Core Library - fundamental operations",
            "output_prefix": "rust_core"
        },
        "std": {
            "prefixes": ["_ZN3std", "_ZN93std", "_ZN94std"],  
            "description": "Rust Standard Library - std namespace",
            "output_prefix": "rust_std"
        },
        "alloc": {
            "prefixes": ["_ZN5alloc", "_ZN95alloc", "_ZN96alloc"],
            "description": "Rust Allocation Library - heap allocation",
            "output_prefix": "rust_alloc"
        }
    }
    
    def __init__(self):
        """Initialize the sublibrary extractor."""
        self.signatures_dir = settings.data_dir / "solana_ebpf" / "signatures"
        self.signatures_dir.mkdir(parents=True, exist_ok=True)
        
        # IDA Pro installation directory
        self.ida_sig_dir = Path("/Applications/IDA Professional 9.1.app/Contents/MacOS/sig/solana_ebpf")
        
        self.logger.info("Sublibrary extractor initialized")
    
    def parse_pat_file(self, pat_file: Path) -> List[str]:
        """Parse a PAT file and return list of function entries.
        
        Args:
            pat_file: Path to PAT file
            
        Returns:
            List of function entry strings
        """
        if not pat_file.exists():
            raise FileNotFoundError(f"PAT file not found: {pat_file}")
        
        content = pat_file.read_text()
        lines = content.strip().split('\n')
        
        # Remove terminator and empty lines
        functions = []
        for line in lines:
            line = line.strip()
            if line and line != '---':
                functions.append(line)
        
        self.logger.debug(f"Parsed {len(functions)} functions from {pat_file}")
        return functions
    
    def categorize_functions(self, functions: List[str]) -> Dict[str, List[str]]:
        """Categorize functions by their namespace.
        
        Args:
            functions: List of PAT function entries
            
        Returns:
            Dictionary mapping component names to function lists
        """
        categorized = {
            "core": [],
            "std": [],
            "alloc": [], 
            "solana": [],
            "other": []
        }
        
        for func in functions:
            # Extract function name from PAT entry
            # PAT format: PATTERN ALEN CRC LEN :0000 FUNCTION_NAME [^REF REF_NAME] [TAIL]
            parts = func.split(' ')
            if len(parts) < 5:
                categorized["other"].append(func)
                continue
            
            # Find the function name (should be after :0000)
            func_name = None
            for i, part in enumerate(parts):
                if part == ":0000" and i + 1 < len(parts):
                    func_name = parts[i + 1]
                    break
            
            if not func_name:
                categorized["other"].append(func)
                continue
            
            # Categorize based on mangled name
            categorized_flag = False
            for component, info in self.NAMESPACE_MAPPINGS.items():
                for prefix in info["prefixes"]:
                    if func_name.startswith(prefix):
                        categorized[component].append(func)
                        categorized_flag = True
                        break
                if categorized_flag:
                    break
            
            if not categorized_flag:
                # Check for Solana functions
                if "_ZN14solana_program" in func_name or "solana" in func_name.lower():
                    categorized["solana"].append(func)
                else:
                    categorized["other"].append(func)
        
        # Log statistics
        for component, funcs in categorized.items():
            if funcs:
                self.logger.info(f"{component}: {len(funcs)} functions")
        
        return categorized
    
    def create_sublibrary_pat(self, functions: List[str], component: str, 
                             version: str, output_dir: Optional[Path] = None) -> Path:
        """Create a PAT file for a specific sublibrary component.
        
        Args:
            functions: List of function entries for this component
            component: Component name (core, std, alloc)
            version: Version string
            output_dir: Output directory (default: signatures/pat/)
            
        Returns:
            Path to created PAT file
        """
        if not functions:
            raise ValueError(f"No functions provided for component {component}")
        
        if output_dir is None:
            output_dir = self.signatures_dir / "pat"
        
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate filename following naming convention
        info = self.NAMESPACE_MAPPINGS.get(component, {})
        output_prefix = info.get("output_prefix", f"rust_{component}")
        filename = f"{output_prefix}_{version}_ebpf.pat"
        output_path = output_dir / filename
        
        # Create PAT content
        pat_content = '\n'.join(functions) + '\n---\n'
        output_path.write_text(pat_content)
        
        self.logger.info(f"Created {component} PAT: {output_path} ({len(functions)} functions)")
        return output_path
    
    def extract_sublibraries_from_pat(self, main_pat_file: Path, version: str,
                                     components: Optional[List[str]] = None,
                                     output_dir: Optional[Path] = None) -> Dict[str, Path]:
        """Extract sublibrary PAT files from main library PAT file.
        
        Args:
            main_pat_file: Path to main library PAT file
            version: Version string for output files
            components: List of components to extract (default: all)
            output_dir: Output directory for PAT files
            
        Returns:
            Dictionary mapping component names to output PAT file paths
        """
        if components is None:
            components = list(self.NAMESPACE_MAPPINGS.keys())
        
        self.logger.info(f"Extracting sublibraries from {main_pat_file}")
        
        # Parse main PAT file
        functions = self.parse_pat_file(main_pat_file)
        
        # Categorize functions by namespace
        categorized = self.categorize_functions(functions)
        
        # Create sublibrary PAT files
        results = {}
        for component in components:
            if component in categorized and categorized[component]:
                try:
                    pat_path = self.create_sublibrary_pat(
                        categorized[component], component, version, output_dir
                    )
                    results[component] = pat_path
                except Exception as e:
                    self.logger.error(f"Failed to create {component} PAT: {e}")
                    results[component] = None
            else:
                self.logger.warning(f"No functions found for component {component}")
                results[component] = None
        
        # Summary
        success_count = sum(1 for path in results.values() if path is not None)
        self.logger.info(f"Successfully extracted {success_count}/{len(components)} sublibraries")
        
        return results
    
    def get_extraction_statistics(self, main_pat_file: Path) -> Dict[str, int]:
        """Get statistics about extractable functions from main PAT file.
        
        Args:
            main_pat_file: Path to main library PAT file
            
        Returns:
            Dictionary with function counts by component
        """
        functions = self.parse_pat_file(main_pat_file)
        categorized = self.categorize_functions(functions)
        
        stats = {}
        for component, funcs in categorized.items():
            stats[component] = len(funcs)
        
        stats["total"] = len(functions)
        return stats
    
    def validate_sublibrary_extraction(self, main_pat_file: Path, 
                                      extracted_pats: Dict[str, Path]) -> Dict[str, bool]:
        """Validate that sublibrary extraction was successful.
        
        Args:
            main_pat_file: Original main library PAT file
            extracted_pats: Dictionary of extracted PAT files
            
        Returns:
            Dictionary with validation results for each component
        """
        results = {}
        
        # Get original statistics
        original_stats = self.get_extraction_statistics(main_pat_file)
        
        for component, pat_path in extracted_pats.items():
            if pat_path is None or not pat_path.exists():
                results[component] = False
                continue
            
            try:
                # Parse extracted PAT
                extracted_functions = self.parse_pat_file(pat_path)
                expected_count = original_stats.get(component, 0)
                actual_count = len(extracted_functions)
                
                # Validate function count matches
                results[component] = (actual_count == expected_count and actual_count > 0)
                
                if results[component]:
                    self.logger.info(f"✅ {component}: {actual_count} functions validated")
                else:
                    self.logger.warning(f"❌ {component}: expected {expected_count}, got {actual_count}")
                    
            except Exception as e:
                self.logger.error(f"Validation failed for {component}: {e}")
                results[component] = False
        
        return results
    
    def generate_sig_from_pat(self, pat_file: Path, output_dir: Optional[Path] = None, 
                             install_to_ida: bool = False) -> Optional[Path]:
        """Generate SIG file from PAT file using FLAIR.
        
        Args:
            pat_file: Path to PAT file
            output_dir: Output directory for SIG file (default: signatures/sig/)
            install_to_ida: Whether to install to IDA directory
            
        Returns:
            Path to generated SIG file, or None if generation failed
        """
        try:
            from ....generators.flair_generator import FLAIRGenerator
            
            # Determine output directory
            if output_dir is None:
                output_dir = self.signatures_dir / "sig"
            
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate SIG filename
            sig_filename = pat_file.stem + ".sig"
            sig_path = output_dir / sig_filename
            
            # Use FLAIR generator
            flair_gen = FLAIRGenerator()
            library_name = pat_file.stem.replace("_ebpf", "")
            
            result = flair_gen.generate_sig_with_collision_handling(
                pat_file, sig_path, library_name, mode='accept'
            )
            
            if result and result.get('success') and sig_path.exists():
                self.logger.info(f"Generated SIG file: {sig_path}")
                
                # Install to IDA if requested
                if install_to_ida:
                    self.install_sig_to_ida(sig_path)
                
                return sig_path
            else:
                self.logger.error(f"Failed to generate SIG file for {pat_file}")
                return None
                
        except Exception as e:
            self.logger.error(f"SIG generation failed for {pat_file}: {e}")
            return None
    
    def install_sig_to_ida(self, sig_file: Path) -> bool:
        """Install SIG file to IDA Pro directory.
        
        Args:
            sig_file: Path to SIG file to install
            
        Returns:
            True if installation succeeded, False otherwise
        """
        try:
            # Ensure IDA directory exists
            self.ida_sig_dir.mkdir(parents=True, exist_ok=True)
            
            # Copy SIG file to IDA directory
            ida_sig_path = self.ida_sig_dir / sig_file.name
            shutil.copy2(sig_file, ida_sig_path)
            
            self.logger.info(f"Installed SIG to IDA: {ida_sig_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to install SIG to IDA: {e}")
            return False
    
    def extract_and_generate_sigs(self, main_pat_file: Path, version: str,
                                 components: Optional[List[str]] = None,
                                 install_to_ida: bool = False) -> Dict[str, Dict[str, Optional[Path]]]:
        """Extract sublibraries and generate both PAT and SIG files.
        
        Args:
            main_pat_file: Path to main library PAT file
            version: Version string for output files
            components: List of components to extract (default: all)
            install_to_ida: Whether to install SIG files to IDA
            
        Returns:
            Dictionary with component names as keys and dictionaries containing
            'pat' and 'sig' paths as values
        """
        results = {}
        
        # Extract PAT files
        pat_results = self.extract_sublibraries_from_pat(main_pat_file, version, components)
        
        # Generate SIG files for each successful PAT
        for component, pat_path in pat_results.items():
            results[component] = {'pat': pat_path, 'sig': None}
            
            if pat_path and pat_path.exists():
                sig_path = self.generate_sig_from_pat(pat_path, install_to_ida=install_to_ida)
                results[component]['sig'] = sig_path
        
        # Summary
        success_pats = sum(1 for r in results.values() if r['pat'] is not None)
        success_sigs = sum(1 for r in results.values() if r['sig'] is not None)
        
        self.logger.info(f"Extraction summary: {success_pats}/{len(results)} PAT files, "
                        f"{success_sigs}/{len(results)} SIG files")
        
        return results