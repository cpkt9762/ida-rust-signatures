"""RLIB archive extraction for object file processing.

This module handles extraction of object files from Rust .rlib archives,
which are AR format archives containing compiled object files.
"""

import re
from pathlib import Path
from typing import Dict, List, Optional, Pattern

import arpy

from ..core.config import settings
from ..core.exceptions import ExtractionError, ValidationError
from ..core.logger import LoggerMixin, log_execution_time, log_progress


class RlibExtractor(LoggerMixin):
    """Extracts object files from Rust .rlib archives."""
    
    def __init__(self, output_base_dir: Optional[Path] = None):
        self.output_base_dir = output_base_dir or (settings.compiled_dir / "objects")
        self.output_base_dir.mkdir(parents=True, exist_ok=True)
        
    @log_execution_time
    def extract_objects(
        self,
        rlib_path: Path,
        output_dir: Optional[Path] = None,
        filter_pattern: Optional[str] = None,
        preserve_structure: bool = True
    ) -> List[Path]:
        """Extract object files from a .rlib archive.
        
        Args:
            rlib_path: Path to the .rlib file to extract from.
            output_dir: Directory to extract objects to (defaults to configured dir).
            filter_pattern: Optional regex pattern to filter object files.
            preserve_structure: Whether to create subdirectories for organization.
            
        Returns:
            List of paths to extracted object files.
            
        Raises:
            ExtractionError: If extraction fails.
            ValidationError: If inputs are invalid.
        """
        if not rlib_path.exists():
            raise ValidationError(
                f"RLIB file does not exist: {rlib_path}",
                field_name="rlib_path",
                field_value=str(rlib_path)
            )
        
        if not rlib_path.suffix == '.rlib':
            raise ValidationError(
                f"File is not a .rlib archive: {rlib_path}",
                field_name="rlib_path",
                field_value=str(rlib_path)
            )
        
        # Set up output directory
        if output_dir is None:
            crate_name = self._extract_crate_name_from_rlib(rlib_path)
            output_dir = self.output_base_dir / crate_name
        
        output_dir.mkdir(parents=True, exist_ok=True)
        
        self.logger.info(f"Extracting objects from {rlib_path} to {output_dir}")
        
        # Compile filter pattern if provided
        filter_regex: Optional[Pattern] = None
        if filter_pattern:
            try:
                filter_regex = re.compile(filter_pattern)
            except re.error as e:
                raise ValidationError(
                    f"Invalid filter pattern: {filter_pattern}",
                    field_name="filter_pattern",
                    field_value=filter_pattern
                ) from e
        
        extracted_files = []
        
        try:
            # Open AR archive
            archive = arpy.Archive(filename=str(rlib_path))
            
            # Get all headers
            headers = archive.infolist()
            
            # Filter for object files
            object_entries = []
            for header in headers:
                entry_name = header.name.decode('utf-8', errors='ignore')
                
                if self._is_object_file(entry_name):
                    # Apply filter if specified
                    if filter_regex and not filter_regex.search(entry_name):
                        self.logger.debug(f"Skipping {entry_name} (filtered out)")
                        continue
                    
                    object_entries.append((header, entry_name))
            
            if not object_entries:
                self.logger.warning(f"No object files found in {rlib_path}")
                archive.close()
                return extracted_files
            
            # Extract with progress tracking
            with log_progress(len(object_entries), f"Extracting from {rlib_path.name}") as update_progress:
                for header, entry_name in object_entries:
                    try:
                        extracted_path = self._extract_single_object(
                            archive, header, entry_name, output_dir, preserve_structure
                        )
                        extracted_files.append(extracted_path)
                        update_progress()
                        
                    except Exception as e:
                        self.logger.error(f"Failed to extract {entry_name}: {e}")
                        # Continue with other files
                        continue
            
            self.logger.info(f"Extracted {len(extracted_files)} object files")
            archive.close()
            return extracted_files
                
        except Exception as e:
            raise ExtractionError(
                f"Failed to extract objects from {rlib_path}: {e}",
                source_file=rlib_path,
                extracted_count=len(extracted_files)
            ) from e
    
    def _extract_single_object(
        self,
        archive: arpy.Archive,
        header,  # arpy header object
        entry_name: str,
        output_dir: Path,
        preserve_structure: bool
    ) -> Path:
        """Extract a single object file from the archive."""
        
        # Determine output filename
        if preserve_structure:
            # Keep original name but sanitize it
            safe_name = self._sanitize_filename(entry_name)
            output_path = output_dir / safe_name
        else:
            # Use simple sequential naming
            base_name = Path(entry_name).stem
            output_path = output_dir / f"{base_name}.o"
            
            # Handle name conflicts
            counter = 1
            while output_path.exists():
                output_path = output_dir / f"{base_name}_{counter}.o"
                counter += 1
        
        # Create parent directories if needed
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Extract file content
        try:
            with archive.open(header) as entry_file:
                content = entry_file.read()
                
            with open(output_path, 'wb') as output_file:
                output_file.write(content)
                
            self.logger.debug(f"Extracted {entry_name} -> {output_path}")
            return output_path
            
        except Exception as e:
            raise ExtractionError(
                f"Failed to write extracted file {output_path}: {e}",
                source_file=Path(entry_name)
            ) from e
    
    def _is_object_file(self, filename: str) -> bool:
        """Check if a filename represents an object file."""
        # Common object file extensions
        return filename.endswith(('.o', '.obj'))
    
    def _extract_crate_name_from_rlib(self, rlib_path: Path) -> str:
        """Extract crate name from .rlib filename."""
        name = rlib_path.stem
        
        # Remove lib prefix if present
        if name.startswith('lib'):
            name = name[3:]
        
        # Remove version/hash suffixes (pattern: name-hash or name-version-hash)
        parts = name.split('-')
        if len(parts) >= 2:
            # Keep only the first part (crate name)
            return parts[0]
        
        return name
    
    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename for safe filesystem usage."""
        # Replace problematic characters
        safe_name = re.sub(r'[<>:"/\\|?*]', '_', filename)
        
        # Limit length
        if len(safe_name) > 200:
            name_part = Path(safe_name).stem[:150]
            ext_part = Path(safe_name).suffix
            safe_name = f"{name_part}{ext_part}"
        
        return safe_name
    
    def batch_extract(
        self,
        rlib_files: List[Path],
        output_base_dir: Optional[Path] = None,
        filter_pattern: Optional[str] = None,
        max_parallel: int = 4
    ) -> Dict[Path, List[Path]]:
        """Extract objects from multiple .rlib files.
        
        Args:
            rlib_files: List of .rlib files to process.
            output_base_dir: Base directory for extracted objects.
            filter_pattern: Optional regex pattern to filter object files.
            max_parallel: Maximum number of parallel extractions.
            
        Returns:
            Dictionary mapping rlib paths to lists of extracted object files.
            
        Raises:
            ExtractionError: If batch extraction fails.
        """
        if not rlib_files:
            return {}
        
        results = {}
        output_dir = output_base_dir or self.output_base_dir
        
        self.logger.info(f"Batch extracting from {len(rlib_files)} .rlib files")
        
        with log_progress(len(rlib_files), "Batch extraction") as update_progress:
            for rlib_path in rlib_files:
                try:
                    extracted = self.extract_objects(
                        rlib_path,
                        output_dir / self._extract_crate_name_from_rlib(rlib_path),
                        filter_pattern
                    )
                    results[rlib_path] = extracted
                    update_progress()
                    
                except Exception as e:
                    self.logger.error(f"Failed to extract from {rlib_path}: {e}")
                    results[rlib_path] = []
                    # Continue with other files
                    continue
        
        total_extracted = sum(len(files) for files in results.values())
        self.logger.info(f"Batch extraction complete: {total_extracted} total objects extracted")
        
        return results
    
    def get_object_info(self, object_path: Path) -> Dict[str, any]:
        """Get information about an extracted object file.
        
        Args:
            object_path: Path to the object file.
            
        Returns:
            Dictionary containing object file information.
        """
        if not object_path.exists():
            return {"error": "File does not exist"}
        
        info = {
            "path": str(object_path),
            "size": object_path.stat().st_size,
            "name": object_path.name,
        }
        
        # Try to get ELF information
        try:
            from elftools.elf.elffile import ELFFile
            
            with open(object_path, 'rb') as f:
                elf = ELFFile(f)
                
                info.update({
                    "elf_class": elf.elfclass,
                    "elf_machine": elf.header.e_machine,
                    "elf_type": elf.header.e_type,
                    "sections": len(list(elf.iter_sections())),
                })
                
                # Count symbols
                symtab = elf.get_section_by_name('.symtab')
                if symtab:
                    info["symbols"] = symtab.num_symbols()
                else:
                    info["symbols"] = 0
                    
        except Exception as e:
            info["elf_error"] = str(e)
        
        return info
    
    def validate_extracted_objects(self, object_files: List[Path]) -> List[str]:
        """Validate extracted object files and return any issues.
        
        Args:
            object_files: List of object file paths to validate.
            
        Returns:
            List of validation issues found.
        """
        issues = []
        
        for obj_path in object_files:
            if not obj_path.exists():
                issues.append(f"Object file missing: {obj_path}")
                continue
            
            if obj_path.stat().st_size == 0:
                issues.append(f"Object file is empty: {obj_path}")
                continue
            
            # Check if it's a valid ELF file
            try:
                from elftools.elf.elffile import ELFFile
                
                with open(obj_path, 'rb') as f:
                    elf = ELFFile(f)
                    
                    # Basic ELF validation
                    if elf.header.e_machine not in ['EM_X86_64', 62]:  # 62 is EM_X86_64
                        issues.append(f"Object file not x86_64: {obj_path}")
                    
                    if not list(elf.iter_sections()):
                        issues.append(f"Object file has no sections: {obj_path}")
                        
            except Exception as e:
                issues.append(f"Invalid ELF file {obj_path}: {e}")
        
        return issues


class ObjectFileManager(LoggerMixin):
    """Manages collections of extracted object files."""
    
    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir or (settings.compiled_dir / "objects")
        self.base_dir.mkdir(parents=True, exist_ok=True)
    
    def organize_by_crate(self, object_files: List[Path]) -> Dict[str, List[Path]]:
        """Organize object files by their originating crate.
        
        Args:
            object_files: List of object file paths.
            
        Returns:
            Dictionary mapping crate names to object file lists.
        """
        crate_files = {}
        
        for obj_path in object_files:
            # Try to determine crate from path structure
            crate_name = "unknown"
            
            # If file is in a crate-specific subdirectory
            if obj_path.parent != self.base_dir:
                crate_name = obj_path.parent.name
            else:
                # Try to extract from filename
                name_parts = obj_path.stem.split('-')
                if len(name_parts) >= 2:
                    crate_name = name_parts[0]
            
            if crate_name not in crate_files:
                crate_files[crate_name] = []
            
            crate_files[crate_name].append(obj_path)
        
        return crate_files
    
    def cleanup_extracted_objects(self, older_than_hours: int = 24) -> int:
        """Clean up old extracted object files.
        
        Args:
            older_than_hours: Remove files older than this many hours.
            
        Returns:
            Number of files removed.
        """
        import time
        
        cutoff_time = time.time() - (older_than_hours * 3600)
        removed_count = 0
        
        for obj_path in self.base_dir.rglob("*.o"):
            try:
                if obj_path.stat().st_mtime < cutoff_time:
                    obj_path.unlink()
                    removed_count += 1
                    
            except Exception as e:
                self.logger.warning(f"Failed to remove {obj_path}: {e}")
        
        self.logger.info(f"Cleaned up {removed_count} old object files")
        return removed_count