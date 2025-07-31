"""Rlib file collection and organization utilities.

This module provides functionality to collect, organize, and manage
compiled rlib files for signature generation.
"""

import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ....core.config import settings
from ....core.logger import LoggerMixin
from ....core.naming_utils import get_rlib_filename


class RlibCollector(LoggerMixin):
    """Collects and organizes rlib files for signature generation."""
    
    def __init__(self, rlibs_dir: Optional[Path] = None):
        """Initialize the collector.
        
        Args:
            rlibs_dir: Directory containing rlib files
        """
        self.rlibs_dir = rlibs_dir or (settings.data_dir / "solana_ebpf" / "rlibs")
        self.rlibs_dir.mkdir(parents=True, exist_ok=True)
        
        self.logger.info(f"Rlib collector initialized with dir: {self.rlibs_dir}")
    
    def scan_rlibs(self, pattern: str = "*.rlib") -> List[Path]:
        """Scan for rlib files matching a pattern.
        
        Args:
            pattern: Glob pattern to match rlib files
            
        Returns:
            List of rlib file paths
        """
        rlib_files = []
        
        # Scan all subdirectories
        for subdir in self.rlibs_dir.iterdir():
            if subdir.is_dir():
                rlib_files.extend(subdir.glob(pattern))
        
        # Also scan root directory
        rlib_files.extend(self.rlibs_dir.glob(pattern))
        
        self.logger.info(f"Found {len(rlib_files)} rlib files matching '{pattern}'")
        return sorted(rlib_files)
    
    def scan_crate_rlibs(self, crate_name: str) -> List[Path]:
        """Scan for rlib files of a specific crate.
        
        Args:
            crate_name: Name of the crate
            
        Returns:
            List of rlib file paths for the crate
        """
        crate_dir = self.rlibs_dir / crate_name
        if not crate_dir.exists():
            return []
        
        return list(crate_dir.glob("*.rlib"))
    
    def get_rlib_metadata(self, rlib_path: Path) -> Dict[str, str]:
        """Extract metadata from rlib filename and file.
        
        Args:
            rlib_path: Path to rlib file
            
        Returns:
            Dictionary with rlib metadata
        """
        metadata = {
            'path': str(rlib_path),
            'filename': rlib_path.name,
            'stem': rlib_path.stem,
            'size': str(rlib_path.stat().st_size) if rlib_path.exists() else '0',
            'crate_name': None,
            'version': None,
        }
        
        # Parse filename to extract crate name and version
        # Expected format: lib{crate_name}-{version}.rlib
        stem = rlib_path.stem
        if stem.startswith('lib') and '-' in stem:
            # Remove 'lib' prefix
            name_version = stem[3:]
            
            # Find last dash to separate name and version
            last_dash = name_version.rfind('-')
            if last_dash > 0:
                metadata['crate_name'] = name_version[:last_dash]
                metadata['version'] = name_version[last_dash + 1:]
        
        return metadata
    
    def organize_rlibs_by_crate(self) -> Dict[str, List[Path]]:
        """Organize rlib files by crate name.
        
        Returns:
            Dictionary mapping crate names to lists of rlib paths
        """
        rlibs_by_crate = {}
        
        all_rlibs = self.scan_rlibs()
        for rlib_path in all_rlibs:
            metadata = self.get_rlib_metadata(rlib_path)
            crate_name = metadata.get('crate_name')
            
            if crate_name:
                if crate_name not in rlibs_by_crate:
                    rlibs_by_crate[crate_name] = []
                rlibs_by_crate[crate_name].append(rlib_path)
        
        return rlibs_by_crate
    
    def get_latest_rlib(self, crate_name: str) -> Optional[Path]:
        """Get the latest version rlib for a crate.
        
        Args:
            crate_name: Name of the crate
            
        Returns:
            Path to latest rlib or None if not found
        """
        rlibs = self.scan_crate_rlibs(crate_name)
        if not rlibs:
            return None
        
        # Sort by modification time (latest first)
        rlibs.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        return rlibs[0]
    
    def copy_rlib(self, source_path: Path, crate_name: str, version: str) -> Path:
        """Copy an rlib file to the organized directory structure.
        
        Args:
            source_path: Source rlib file path
            crate_name: Name of the crate
            version: Version of the crate
            
        Returns:
            Path to copied rlib file
        """
        # Create crate directory
        crate_dir = self.rlibs_dir / crate_name
        crate_dir.mkdir(parents=True, exist_ok=True)
        
        # Target filename - use unified naming utility
        target_filename = get_rlib_filename(crate_name, version, 'solana_ebpf')
        target_path = crate_dir / target_filename
        
        # Copy file
        shutil.copy2(source_path, target_path)
        
        self.logger.info(f"Copied rlib to {target_path}")
        return target_path
    
    def validate_rlib(self, rlib_path: Path) -> Tuple[bool, str]:
        """Validate an rlib file.
        
        Args:
            rlib_path: Path to rlib file
            
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
        
        return True, "Valid rlib file"
    
    def get_rlib_summary(self) -> Dict[str, int]:
        """Get summary statistics of rlib files.
        
        Returns:
            Dictionary with summary statistics
        """
        rlibs_by_crate = self.organize_rlibs_by_crate()
        
        total_rlibs = sum(len(rlibs) for rlibs in rlibs_by_crate.values())
        total_size = 0
        
        for rlibs in rlibs_by_crate.values():
            for rlib_path in rlibs:
                if rlib_path.exists():
                    total_size += rlib_path.stat().st_size
        
        return {
            'total_crates': len(rlibs_by_crate),
            'total_rlibs': total_rlibs,
            'total_size_bytes': total_size,
            'total_size_mb': round(total_size / (1024 * 1024), 2),
        }
    
    def list_crates(self) -> List[str]:
        """List all crates with rlib files.
        
        Returns:
            List of crate names
        """
        return list(self.organize_rlibs_by_crate().keys())
    
    def cleanup_invalid_rlibs(self, dry_run: bool = True) -> List[Path]:
        """Clean up invalid rlib files.
        
        Args:
            dry_run: If True, only report what would be cleaned up
            
        Returns:
            List of invalid rlib paths that were (or would be) removed
        """
        invalid_rlibs = []
        
        all_rlibs = self.scan_rlibs()
        for rlib_path in all_rlibs:
            is_valid, error = self.validate_rlib(rlib_path)
            if not is_valid:
                invalid_rlibs.append(rlib_path)
                if not dry_run:
                    rlib_path.unlink()
                    self.logger.info(f"Removed invalid rlib: {rlib_path} ({error})")
                else:
                    self.logger.info(f"Would remove: {rlib_path} ({error})")
        
        return invalid_rlibs