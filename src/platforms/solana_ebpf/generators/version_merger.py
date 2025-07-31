"""Solana version merger for PAT files.

This module merges PAT files from different versions of the same crate and handles
version tagging and deduplication. Core logic ported from join-pat-files.py.
"""

import hashlib
import os
import re
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from packaging.version import Version

from ....core.logger import LoggerMixin


class SolanaVersionMerger(LoggerMixin):
    """Merges PAT files from different versions of Solana crates.
    
    This class ports the version management and merging logic from the original
    solana-ida-signatures-factory join-pat-files.py.
    """
    
    def __init__(self):
        """Initialize the version merger."""
        self.logger.info("Solana version merger initialized")
    
    def pattern_hash(self, pattern: List[str]) -> str:
        """Calculate hash of a function pattern for deduplication.
        
        Ported from join-pat-files.py pattern_hash() function.
        
        Args:
            pattern: Function pattern as list of strings
            
        Returns:
            SHA256 hash of the pattern
        """
        if len(pattern) < 5:
            return hashlib.sha256(' '.join(pattern).encode()).hexdigest()
        
        p = pattern[4:-1]  # Skip first 4 and last element
        p_ = []
        
        for i in range(0, len(p), 2):
            p_.append(p[i])
            p_.append('<INTERNALREF>')
        
        joined = pattern[:4] + p_ + [pattern[-1]]
        return hashlib.sha256(' '.join(joined).encode()).hexdigest()
    
    def generate_version_range_name(self, versions: List[str]) -> str:
        """Generate version range name for merged files.
        
        Args:
            versions: List of version strings
            
        Returns:
            Version range string (e.g., "1.18.16-2.1.21" or "1.18.16+2.1.21")
        """
        if len(versions) <= 1:
            return versions[0] if versions else ""
        
        # Sort versions
        try:
            sorted_versions = sorted(versions, key=lambda v: Version(v))
        except Exception:
            # Fallback to string sort if version parsing fails
            sorted_versions = sorted(versions)
        
        # Check if versions are consecutive (for simple cases)
        if len(sorted_versions) == 2:
            return f"{sorted_versions[0]}-{sorted_versions[-1]}"
        
        # For multiple versions, check if they form a consecutive sequence
        try:
            version_objs = [Version(v) for v in sorted_versions]
            is_consecutive = True
            
            # Simple heuristic: check if major.minor versions are consecutive
            for i in range(1, len(version_objs)):
                prev = version_objs[i-1]
                curr = version_objs[i]
                
                # If major versions differ by more than 1, not consecutive
                if curr.major - prev.major > 1:
                    is_consecutive = False
                    break
                # If major is same but minor differs by more than few steps, not consecutive
                if curr.major == prev.major and curr.minor - prev.minor > 10:
                    is_consecutive = False
                    break
            
            if is_consecutive and len(sorted_versions) <= 5:
                return f"{sorted_versions[0]}-{sorted_versions[-1]}"
        except Exception:
            pass
        
        # Default: use + separator for non-consecutive versions
        return "+".join(sorted_versions)
    
    def add_version_tag(self, func_name: str, version: str) -> str:
        """Add version tag to a function name.
        
        Ported from join-pat-files.py version tagging logic.
        
        Args:
            func_name: Original function name
            version: Version string to add
            
        Returns:
            Function name with version tag
        """
        # Try Rust demangling approach first
        try:
            import rust_demangler
            rust_demangler.demangle(func_name)
            
            # If demangling succeeds and ends with 'E'
            if func_name.endswith('E'):
                appendix = f'$SP$v{version}'
                return func_name[:-1] + str(len(appendix)) + appendix + 'E'
        except:
            pass
        
        # Fallback to simple version suffix
        return f"{func_name}@v{version}"
    
    def parse_pat_file(self, pat_path: Path) -> List[List[str]]:
        """Parse a PAT file into function entries.
        
        Args:
            pat_path: Path to PAT file
            
        Returns:
            List of function entries (each entry is list of strings)
        """
        if not pat_path.exists():
            self.logger.error(f"PAT file not found: {pat_path}")
            return []
        
        functions = []
        
        try:
            with open(pat_path, 'r') as f:
                lines = f.readlines()
                
            for line in lines:
                line = line.strip()
                if line and line != '---':
                    func = line.split(' ')
                    functions.append(func)
                elif line == '---':
                    break
                    
        except Exception as e:
            self.logger.error(f"Failed to parse PAT file {pat_path}: {e}")
            return []
        
        self.logger.info(f"Parsed {len(functions)} functions from {pat_path}")
        return functions
    
    def find_pat_files(self, input_folder: Path, lib_name: str) -> List[Tuple[str, Path]]:
        """Find PAT files for a specific library.
        
        Args:
            input_folder: Directory containing PAT files
            lib_name: Library name to search for
            
        Returns:
            List of (version, file_path) tuples
        """
        pat_files = []
        
        if not input_folder.exists():
            self.logger.error(f"Input folder not found: {input_folder}")
            return []
        
        # Pattern: {lib_name}-{version}.pat, {lib_name}_{version}.pat, or {lib_name}_{version}_ebpf.pat
        patterns = [
            f"{lib_name}-*.pat",
            f"{lib_name}_*.pat", 
            f"{lib_name}*_ebpf.pat",
        ]
        
        for pattern in patterns:
            for file_path in input_folder.glob(pattern):
                # Extract version from filename
                stem = file_path.stem
                
                # Handle _ebpf suffix in new format (remove _ebpf suffix first)
                if stem.endswith('_ebpf'):
                    stem = stem[:-5]  # Remove '_ebpf'
                
                # For new format like "solana_program_1.18.16"
                if lib_name in stem:
                    # Remove lib_name prefix to get version part
                    version_part = stem.replace(lib_name, '')
                    # Remove any leading separators
                    version_part = version_part.lstrip('_-')
                    
                    # Validate version format
                    if re.match(r'^\d+\.\d+', version_part):
                        pat_files.append((version_part, file_path))
                        continue
                
                # Try legacy separators for backwards compatibility
                for sep in ['-', '_']:
                    if sep in stem:
                        parts = stem.split(sep)
                        if len(parts) >= 2:
                            # Last part should be version
                            version_part = parts[-1]
                            
                            # Validate version format
                            if re.match(r'^\d+\.\d+', version_part):
                                pat_files.append((version_part, file_path))
                                break
        
        # Sort by version
        try:
            pat_files.sort(key=lambda x: Version(x[0]))
        except Exception as e:
            self.logger.warning(f"Failed to sort by version: {e}")
            pat_files.sort(key=lambda x: x[0])  # Fallback to string sort
        
        self.logger.info(f"Found {len(pat_files)} PAT files for {lib_name}")
        return pat_files
    
    def merge_pat_files(self, input_folder: Path, lib_name: str, output_file: Path,
                       drop_duplicates: bool = True) -> bool:
        """Merge PAT files for different versions of a library.
        
        Ported from join-pat-files.py join_pat_files() function.
        
        Args:
            input_folder: Directory containing PAT files
            lib_name: Library name to merge
            output_file: Output PAT file path
            drop_duplicates: Whether to remove duplicate patterns
            
        Returns:
            True if merge successful, False otherwise
        """
        self.logger.info(f"Merging PAT files for {lib_name}")
        
        pat_files = self.find_pat_files(input_folder, lib_name)
        if not pat_files:
            self.logger.error(f"No PAT files found for {lib_name}")
            return False
        
        functions = []
        functions_idx = 0
        cache = {}
        
        for version, pat_path in pat_files:
            self.logger.info(f"Processing {lib_name} version {version}")
            
            parsed_functions = self.parse_pat_file(pat_path)
            
            for func in parsed_functions:
                if len(func) < 6:
                    self.logger.warning(f"Invalid function entry in {pat_path}: {func}")
                    continue
                
                # Calculate pattern hash for deduplication
                pat_hash = self.pattern_hash(func)
                if pat_hash not in cache:
                    cache[pat_hash] = []
                cache[pat_hash].append(functions_idx)
                
                # Add version tag to function name
                func_name = func[5]
                
                # Handle unlikely prefix
                if func_name.startswith('unlikely.'):
                    func_name = func_name[9:]
                
                # Add version tag
                func_name = self.add_version_tag(func_name, version)
                func[5] = func_name
                
                functions.append(func)
                functions_idx += 1
        
        # Select functions based on deduplication setting
        if drop_duplicates:
            out_funcs = []
            for h in cache.keys():
                # Keep only the first occurrence (lowest version)
                out_funcs.append(functions[cache[h][0]])
            self.logger.info(f"After deduplication: {len(out_funcs)} functions from {len(functions)}")
        else:
            out_funcs = functions
            self.logger.info(f"No deduplication: {len(out_funcs)} functions")
        
        # Write merged PAT file
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(output_file, 'w') as f:
                for func in out_funcs:
                    f.write(' '.join(func) + '\n')
                f.write('---\n')
            
            self.logger.info(f"Merged PAT file written to {output_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to write merged PAT file: {e}")
            return False
    
    def merge_solana_program_versions(self, input_folder: Path, 
                                    output_file: Optional[Path] = None,
                                    drop_duplicates: bool = True) -> Path:
        """Merge solana-program PAT files from different versions.
        
        Args:
            input_folder: Directory containing solana-program PAT files
            output_file: Optional output file path
            drop_duplicates: Whether to remove duplicate patterns
            
        Returns:
            Path to merged PAT file
        """
        if output_file is None:
            # Get available versions to generate intelligent filename
            pat_files = self.find_pat_files(input_folder, "solana_program")
            if pat_files:
                versions = [version for version, _ in pat_files]
                version_range = self.generate_version_range_name(versions)
                output_file = input_folder.parent / "merged" / f"solana_program_{version_range}_ebpf.pat"
            else:
                output_file = input_folder.parent / "merged" / "solana_program_merged_ebpf.pat"
        
        success = self.merge_pat_files(input_folder, "solana_program", output_file, drop_duplicates)
        if not success:
            raise RuntimeError("Failed to merge solana-program PAT files")
        
        return output_file
    
    def get_merge_statistics(self, merged_pat_path: Path) -> Dict[str, any]:
        """Get statistics about a merged PAT file.
        
        Args:
            merged_pat_path: Path to merged PAT file
            
        Returns:
            Dictionary with merge statistics
        """
        if not merged_pat_path.exists():
            return {'error': 'File not found'}
        
        functions = self.parse_pat_file(merged_pat_path)
        
        # Count versions
        version_counts = {}
        for func in functions:
            if len(func) > 5:
                func_name = func[5]
                
                # Extract version from function name
                if '@v' in func_name:
                    version = func_name.split('@v')[-1]
                elif '$SP$v' in func_name:
                    # Extract from Rust mangled name
                    parts = func_name.split('$SP$v')
                    if len(parts) > 1:
                        version_part = parts[1]
                        if 'E' in version_part:
                            version = version_part.split('E')[0]
                        else:
                            version = version_part
                else:
                    version = 'unknown'
                
                if version not in version_counts:
                    version_counts[version] = 0
                version_counts[version] += 1
        
        return {
            'total_functions': len(functions),
            'versions_found': len(version_counts),
            'version_distribution': version_counts,
            'file_size': merged_pat_path.stat().st_size,
        }