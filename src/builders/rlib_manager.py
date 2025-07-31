"""x86_64 RLIB file management and organization utilities.

This module provides functionality to manage, organize, and standardize
x86_64 RLIB files for signature generation, similar to the Solana eBPF
rlib_collector.py but tailored for x86_64 platform requirements.
"""

import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..core.config import settings
from ..core.logger import LoggerMixin
from ..core.naming_utils import get_rlib_filename


class X86_64RlibManager(LoggerMixin):
    """Manages and organizes x86_64 RLIB files for signature generation."""
    
    def __init__(self, rlibs_dir: Optional[Path] = None):
        """Initialize the RLIB manager.
        
        Args:
            rlibs_dir: Directory to store organized RLIB files
        """
        self.rlibs_dir = rlibs_dir or (settings.data_dir / "x86_64" / "rlibs")
        self.rlibs_dir.mkdir(parents=True, exist_ok=True)
        
        self.logger.info(f"x86_64 RLIB manager initialized with dir: {self.rlibs_dir}")
    
    def organize_rlib(self, source_rlib: Path, library_name: str, version: str, 
                     crate_name: Optional[str] = None) -> Path:
        """Organize an RLIB file by copying it to standard location with standard naming.
        
        Args:
            source_rlib: Source RLIB file path (e.g., from target/deps/)
            library_name: Standard library name (e.g., "rust_core", "solana_program")
            version: Version string (e.g., "1.75.0")
            crate_name: Original crate name (optional, for directory organization)
            
        Returns:
            Path to organized RLIB file with standard naming
            
        Raises:
            FileNotFoundError: If source RLIB doesn't exist
            OSError: If copy operation fails
        """
        if not source_rlib.exists():
            raise FileNotFoundError(f"Source RLIB file not found: {source_rlib}")
        
        # Use crate name for directory organization, fall back to library name
        dir_name = crate_name or library_name.replace('_', '-')
        target_dir = self.rlibs_dir / dir_name
        target_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate standard filename
        standard_filename = get_rlib_filename(library_name, version, 'x86_64')
        target_path = target_dir / standard_filename
        
        # Copy file with standard naming
        shutil.copy2(source_rlib, target_path)
        
        self.logger.info(f"Organized RLIB: {source_rlib.name} -> {target_path}")
        self.logger.debug(f"  Source: {source_rlib}")
        self.logger.debug(f"  Target: {target_path}")
        self.logger.debug(f"  Size: {target_path.stat().st_size:,} bytes")
        
        return target_path
    
    def find_organized_rlib(self, library_name: str, version: str,
                           crate_name: Optional[str] = None) -> Optional[Path]:
        """Find an organized RLIB file by library name and version.
        
        Args:
            library_name: Standard library name
            version: Version string
            crate_name: Original crate name (optional)
            
        Returns:
            Path to organized RLIB file or None if not found
        """
        # Try different directory names
        possible_dirs = []
        if crate_name:
            possible_dirs.append(crate_name)
        possible_dirs.extend([
            library_name.replace('_', '-'),  # rust_core -> rust-core
            library_name,                    # rust_core
        ])
        
        standard_filename = get_rlib_filename(library_name, version, 'x86_64')
        
        for dir_name in possible_dirs:
            potential_path = self.rlibs_dir / dir_name / standard_filename
            if potential_path.exists():
                return potential_path
        
        return None
    
    def scan_organized_rlibs(self, pattern: str = "*.rlib") -> List[Path]:
        """Scan for organized RLIB files matching a pattern.
        
        Args:
            pattern: Glob pattern to match RLIB files
            
        Returns:
            List of organized RLIB file paths
        """
        rlib_files = []
        
        # Scan all subdirectories
        for subdir in self.rlibs_dir.iterdir():
            if subdir.is_dir():
                rlib_files.extend(subdir.glob(pattern))
        
        # Also scan root directory
        rlib_files.extend(self.rlibs_dir.glob(pattern))
        
        self.logger.debug(f"Found {len(rlib_files)} organized RLIB files matching '{pattern}'")
        return sorted(rlib_files)
    
    def get_rlib_metadata(self, rlib_path: Path) -> Dict[str, str]:
        """Extract metadata from organized RLIB filename and file.
        
        Args:
            rlib_path: Path to organized RLIB file
            
        Returns:
            Dictionary with RLIB metadata
        """
        from ..core.naming_utils import FileNamingUtils
        
        metadata = {
            'path': str(rlib_path),
            'filename': rlib_path.name,
            'size': str(rlib_path.stat().st_size) if rlib_path.exists() else '0',
            'library_name': None,
            'version': None,
            'platform': None,
            'standard_format': False,
        }
        
        # Try to parse standard filename format
        parsed = FileNamingUtils.parse_standard_filename(rlib_path.name)
        if parsed:
            metadata.update({
                'library_name': parsed['library_name'],
                'version': parsed['version'],
                'platform': parsed['platform'],
                'standard_format': True,
            })
        else:
            # Fallback: try to extract from traditional Rust format
            stem = rlib_path.stem
            if stem.startswith('lib') and '-' in stem:
                # Remove 'lib' prefix and try to split name/hash
                name_part = stem[3:]  # Remove 'lib'
                # For files like 'libcore-hash', we can't reliably determine version
                metadata['library_name'] = name_part.split('-')[0]
                metadata['platform'] = 'x86_64'  # Assume x86_64 for organized files
        
        return metadata
    
    def validate_rlib(self, rlib_path: Path) -> Tuple[bool, str]:
        """Validate an RLIB file.
        
        Args:
            rlib_path: Path to RLIB file
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not rlib_path.exists():
            return False, "File does not exist"
        
        if not rlib_path.is_file():
            return False, "Path is not a file"
        
        if rlib_path.suffix != '.rlib':
            return False, "File does not have .rlib extension"
        
        if rlib_path.stat().st_size == 0:
            return False, "File is empty"
        
        # Try to read first few bytes to check if it's an archive
        try:
            with open(rlib_path, 'rb') as f:
                magic = f.read(8)
                if not magic.startswith(b'!<arch>\n'):
                    return False, "File is not a valid archive"
        except Exception as e:
            return False, f"Cannot read file: {e}"
        
        return True, "Valid RLIB file"
    
    def get_organization_summary(self) -> Dict[str, any]:
        """Get summary statistics of organized RLIB files.
        
        Returns:
            Dictionary with summary statistics
        """
        organized_rlibs = self.scan_organized_rlibs()
        
        # Group by library name
        libraries = {}
        total_size = 0
        
        for rlib_path in organized_rlibs:
            metadata = self.get_rlib_metadata(rlib_path)
            lib_name = metadata.get('library_name', 'unknown')
            
            if lib_name not in libraries:
                libraries[lib_name] = {
                    'versions': [],
                    'files': [],
                    'total_size': 0
                }
            
            libraries[lib_name]['versions'].append(metadata.get('version', 'unknown'))
            libraries[lib_name]['files'].append(rlib_path)
            
            file_size = rlib_path.stat().st_size if rlib_path.exists() else 0
            libraries[lib_name]['total_size'] += file_size
            total_size += file_size
        
        return {
            'total_libraries': len(libraries),
            'total_rlibs': len(organized_rlibs),
            'total_size_bytes': total_size,
            'total_size_mb': round(total_size / (1024 * 1024), 2),
            'libraries': libraries,
        }
    
    def cleanup_invalid_rlibs(self, dry_run: bool = True) -> List[Path]:
        """Clean up invalid organized RLIB files.
        
        Args:
            dry_run: If True, only report what would be cleaned up
            
        Returns:
            List of invalid RLIB paths that were (or would be) removed
        """
        invalid_rlibs = []
        
        organized_rlibs = self.scan_organized_rlibs()
        for rlib_path in organized_rlibs:
            is_valid, error = self.validate_rlib(rlib_path)
            if not is_valid:
                invalid_rlibs.append(rlib_path)
                if not dry_run:
                    rlib_path.unlink()
                    self.logger.info(f"Removed invalid RLIB: {rlib_path} ({error})")
                else:
                    self.logger.info(f"Would remove: {rlib_path} ({error})")
        
        return invalid_rlibs
    
    def migrate_legacy_rlib(self, source_rlib: Path, library_name: str, 
                           version: str, crate_name: Optional[str] = None,
                           move_file: bool = False) -> Path:
        """Migrate a legacy RLIB file to standard naming and organization.
        
        Args:
            source_rlib: Source legacy RLIB file
            library_name: Standard library name
            version: Version string
            crate_name: Original crate name (optional)
            move_file: If True, move instead of copy
            
        Returns:
            Path to organized RLIB file
        """
        self.logger.info(f"Migrating legacy RLIB: {source_rlib.name}")
        
        if move_file:
            # Move file (rename + relocate)
            target_path = self.organize_rlib(source_rlib, library_name, version, crate_name)
            # Remove original after successful copy
            source_rlib.unlink()
            self.logger.info(f"Moved legacy RLIB to: {target_path}")
        else:
            # Copy file (preserve original)
            target_path = self.organize_rlib(source_rlib, library_name, version, crate_name)
            self.logger.info(f"Copied legacy RLIB to: {target_path}")
        
        return target_path
    
    def create_directory_structure(self) -> None:
        """Create the standard x86_64 directory structure."""
        directories = [
            self.rlibs_dir,
            settings.data_dir / "x86_64" / "signatures",
            settings.data_dir / "x86_64" / "til",
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            self.logger.debug(f"Created directory: {directory}")
        
        self.logger.info("x86_64 directory structure created")


# Convenience functions for common operations
def organize_rlib(source_rlib: Path, library_name: str, version: str,
                 crate_name: Optional[str] = None) -> Path:
    """Convenience function to organize an RLIB file."""
    manager = X86_64RlibManager()
    return manager.organize_rlib(source_rlib, library_name, version, crate_name)


def find_organized_rlib(library_name: str, version: str,
                       crate_name: Optional[str] = None) -> Optional[Path]:
    """Convenience function to find an organized RLIB file."""
    manager = X86_64RlibManager()
    return manager.find_organized_rlib(library_name, version, crate_name)