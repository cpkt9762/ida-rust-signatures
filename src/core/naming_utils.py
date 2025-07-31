"""Unified file naming utilities for consistent naming across platforms.

This module provides standardized naming functions that follow the global naming format
defined in the configuration file: {library_name}_{version}_{platform}.{extension}
"""

from pathlib import Path
from typing import Dict, Optional

from .config import settings


class FileNamingUtils:
    """Utility class for standardized file naming across all platforms."""
    
    # Platform identifiers following configuration file specification
    PLATFORM_IDENTIFIERS = {
        'x86_64': 'x86_64',
        'solana_ebpf': 'ebpf',
        'ebpf': 'ebpf',  # Alias for solana_ebpf
    }
    
    # File extension mappings
    EXTENSIONS = {
        'rlib': 'rlib',
        'pat': 'pat', 
        'sig': 'sig',
        'til': 'til',
    }
    
    # Known library name patterns for better parsing
    KNOWN_LIBRARY_PATTERNS = [
        'solana_program',
        'anchor_lang', 
        'rust_core',
        'rust_std',
        'rust_alloc',
    ]
    
    @classmethod
    def get_standard_filename(
        self,
        library_name: str,
        version: str,
        platform: str,
        extension: str,
        include_lib_prefix: bool = False
    ) -> str:
        """Generate a standard filename following the global naming format.
        
        Args:
            library_name: Name of the library (e.g., "solana_program")
            version: Version string (e.g., "1.18.16")
            platform: Platform identifier (e.g., "solana_ebpf", "x86_64")
            extension: File extension (e.g., "rlib", "pat", "sig", "til")
            include_lib_prefix: Whether to include "lib" prefix for rlib files
            
        Returns:
            Standardized filename following format: {library_name}_{version}_{platform}.{extension}
            
        Examples:
            >>> get_standard_filename("solana_program", "1.18.16", "solana_ebpf", "rlib")
            "solana_program_1.18.16_ebpf.rlib"
            
            >>> get_standard_filename("solana_program", "1.18.16", "x86_64", "pat")
            "solana_program_1.18.16_x86_64.pat"
        """
        # Clean up library name (replace hyphens with underscores)
        clean_lib_name = library_name.replace('-', '_')
        
        # Get platform identifier
        platform_id = self.PLATFORM_IDENTIFIERS.get(platform, platform)
        
        # Get extension
        ext = self.EXTENSIONS.get(extension, extension)
        
        # Sanitize version (replace dots and hyphens with underscores for filename safety)
        clean_version = version.replace('.', '_').replace('-', '_')
        
        # Build filename
        if include_lib_prefix and extension == 'rlib':
            filename = f"lib{clean_lib_name}_{clean_version}_{platform_id}.{ext}"
        else:
            filename = f"{clean_lib_name}_{clean_version}_{platform_id}.{ext}"
        
        return filename
    
    @classmethod
    def get_rlib_filename(
        self,
        library_name: str,
        version: str,
        platform: str,
        include_lib_prefix: bool = False
    ) -> str:
        """Generate a standard RLIB filename.
        
        Args:
            library_name: Name of the library
            version: Version string
            platform: Platform identifier
            include_lib_prefix: Whether to include "lib" prefix
            
        Returns:
            Standard RLIB filename
        """
        return self.get_standard_filename(
            library_name, version, platform, 'rlib', include_lib_prefix
        )
    
    @classmethod
    def get_pat_filename(
        self,
        library_name: str,
        version: str,
        platform: str
    ) -> str:
        """Generate a standard PAT filename.
        
        Args:
            library_name: Name of the library
            version: Version string
            platform: Platform identifier
            
        Returns:
            Standard PAT filename
        """
        return self.get_standard_filename(library_name, version, platform, 'pat')
    
    @classmethod
    def get_sig_filename(
        self,
        library_name: str,
        version: str,
        platform: str
    ) -> str:
        """Generate a standard SIG filename.
        
        Args:
            library_name: Name of the library
            version: Version string
            platform: Platform identifier
            
        Returns:
            Standard SIG filename
        """
        return self.get_standard_filename(library_name, version, platform, 'sig')
    
    @classmethod
    def get_til_filename(
        self,
        library_name: str,
        version: str,
        platform: str
    ) -> str:
        """Generate a standard TIL filename.
        
        Args:
            library_name: Name of the library
            version: Version string
            platform: Platform identifier
            
        Returns:
            Standard TIL filename
        """
        return self.get_standard_filename(library_name, version, platform, 'til')
    
    @classmethod
    def parse_standard_filename(self, filename: str) -> Optional[Dict[str, str]]:
        """Parse a standard filename to extract components.
        
        Args:
            filename: Filename to parse
            
        Returns:
            Dictionary with components or None if not a standard filename
            
        Example:
            >>> parse_standard_filename("solana_program_1_18_16_ebpf.pat")
            {
                'library_name': 'solana_program',
                'version': '1.18.16', 
                'platform': 'ebpf',
                'extension': 'pat'
            }
        """
        try:
            # Remove extension
            name_part, extension = filename.rsplit('.', 1)
            
            # Remove lib prefix if present
            if name_part.startswith('lib'):
                name_part = name_part[3:]
            
            # Split by underscores
            parts = name_part.split('_')
            
            if len(parts) < 3:
                return None
            
            # Handle special case for x86_64 platform (gets split into 'x86' and '64')  
            if len(parts) >= 2 and parts[-2] == 'x86' and parts[-1] == '64':
                platform = 'x86_64'
                # Remove both 'x86' and '64' from parts for further processing
                parts = parts[:-2]
            else:
                # Last part should be platform
                platform = parts[-1]
                # Remove platform from parts for further processing
                parts = parts[:-1]
            
            # For standard naming format: {library_name}_{version}_{platform}
            # We need to find where library name ends and version begins
            # This is tricky because both can contain underscores
            
            # We'll assume that the platform identifier is known  
            if platform in self.PLATFORM_IDENTIFIERS.values() or platform in self.PLATFORM_IDENTIFIERS.keys():
                # First try to match against known library patterns
                for known_lib in self.KNOWN_LIBRARY_PATTERNS:
                    lib_parts = known_lib.split('_')
                    if len(parts) >= len(lib_parts):  # lib_parts + version_parts (platform already removed)
                        # Check if the beginning matches the known library pattern
                        if parts[:len(lib_parts)] == lib_parts:
                            library_name = known_lib
                            version_parts = parts[len(lib_parts):]
                            version = '.'.join(version_parts)
                            
                            return {
                                'library_name': library_name,
                                'version': version,
                                'platform': platform,
                                'extension': extension
                            }
                
                # Fallback: try to determine library name by finding version-like patterns
                for lib_end_idx in range(1, len(parts)):
                    potential_lib_name = '_'.join(parts[:lib_end_idx])
                    potential_version_parts = parts[lib_end_idx:]
                    
                    # Check if version parts look like version numbers (start with digits)
                    if potential_version_parts and potential_version_parts[0][0].isdigit():
                        potential_version = '.'.join(potential_version_parts)
                        return {
                            'library_name': potential_lib_name,
                            'version': potential_version,
                            'platform': platform,
                            'extension': extension
                        }
                
                # Final fallback: assume first part is library name
                if len(parts) >= 2:
                    library_name = parts[0]
                    version_parts = parts[1:] 
                    version = '.'.join(version_parts)
                    
                    return {
                        'library_name': library_name,
                        'version': version,
                        'platform': platform,
                        'extension': extension
                    }
            
            return None
            
        except (ValueError, IndexError):
            return None
    
    @classmethod
    def is_standard_filename(self, filename: str) -> bool:
        """Check if a filename follows the standard naming format.
        
        Args:
            filename: Filename to check
            
        Returns:
            True if filename follows standard format
        """
        return self.parse_standard_filename(filename) is not None
    
    @classmethod
    def convert_to_standard_filename(
        self,
        old_filename: str,
        library_name: str,
        version: str,
        platform: str
    ) -> str:
        """Convert an old filename to standard format.
        
        Args:
            old_filename: Original filename
            library_name: Library name
            version: Version string
            platform: Platform identifier
            
        Returns:
            New filename in standard format
        """
        # Extract extension from old filename
        try:
            _, extension = old_filename.rsplit('.', 1)
        except ValueError:
            extension = 'unknown'
        
        return self.get_standard_filename(library_name, version, platform, extension)


# Convenience functions for backward compatibility
def get_standard_filename(library_name: str, version: str, platform: str, extension: str) -> str:
    """Convenience function for getting standard filename."""
    return FileNamingUtils.get_standard_filename(library_name, version, platform, extension)


def get_rlib_filename(library_name: str, version: str, platform: str) -> str:
    """Convenience function for getting RLIB filename."""
    return FileNamingUtils.get_rlib_filename(library_name, version, platform)


def get_pat_filename(library_name: str, version: str, platform: str) -> str:
    """Convenience function for getting PAT filename."""
    return FileNamingUtils.get_pat_filename(library_name, version, platform)


def get_sig_filename(library_name: str, version: str, platform: str) -> str:
    """Convenience function for getting SIG filename."""
    return FileNamingUtils.get_sig_filename(library_name, version, platform)


def get_til_filename(library_name: str, version: str, platform: str) -> str:
    """Convenience function for getting TIL filename."""
    return FileNamingUtils.get_til_filename(library_name, version, platform)