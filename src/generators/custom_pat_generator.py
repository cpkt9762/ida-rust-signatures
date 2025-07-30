"""Custom PAT signature generator for Rust object files.

This module provides a custom implementation for generating IDA Pro FLIRT PAT signatures
from Rust ELF object files when the official FLAIR tools are not compatible.
"""

import re
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

try:
    from rust_demangler import demangle as rust_demangle
    RUST_DEMANGLER_AVAILABLE = True
except ImportError:
    RUST_DEMANGLER_AVAILABLE = False
    rust_demangle = None

from ..core.config import settings
from ..core.exceptions import SignatureGenerationError, ValidationError
from ..core.logger import LoggerMixin, log_execution_time, log_progress
from ..extractors.rlib_extractor import RlibExtractor


@dataclass
class FunctionPattern:
    """Represents a function signature pattern."""
    name: str
    hex_pattern: str
    length: int
    address: int = 0
    section_name: str = ""
    
    def to_pat_line(self) -> str:
        """Convert to PAT file format line."""
        # Ensure pattern is properly padded
        padded_pattern = self.hex_pattern
        while len(padded_pattern) < 64:  # 32 bytes = 64 hex chars
            padded_pattern += ".."
        
        return f"{padded_pattern} {self.length:02X} {self.name}"


class CustomPATGenerator(LoggerMixin):
    """Custom PAT signature generator for Rust object files."""
    
    def __init__(self, 
                 min_pattern_length: int = 8,
                 max_pattern_length: int = 32,
                 max_functions_per_object: int = 50,
                 skip_small_functions: bool = True,
                 demangle_rust_names: bool = True,
                 use_short_names: bool = True):
        """Initialize custom PAT generator.
        
        Args:
            min_pattern_length: Minimum bytes for a valid pattern
            max_pattern_length: Maximum bytes to extract for patterns
            max_functions_per_object: Limit functions per object file
            skip_small_functions: Skip functions smaller than min_pattern_length
            demangle_rust_names: Use rust-demangler to demangle function names
            use_short_names: Extract short readable names from demangled names
        """
        self.min_pattern_length = min_pattern_length
        self.max_pattern_length = max_pattern_length
        self.max_functions_per_object = max_functions_per_object
        self.skip_small_functions = skip_small_functions
        self.demangle_rust_names = demangle_rust_names and RUST_DEMANGLER_AVAILABLE
        self.use_short_names = use_short_names
        
        if demangle_rust_names and not RUST_DEMANGLER_AVAILABLE:
            self.logger.warning("rust-demangler not available, function names will not be demangled")
        
        self.logger.info(f"CustomPATGenerator initialized: "
                        f"pattern_length={min_pattern_length}-{max_pattern_length}, "
                        f"max_functions={max_functions_per_object}, "
                        f"demangle={self.demangle_rust_names}, "
                        f"short_names={use_short_names}")
    
    @log_execution_time
    def extract_patterns_from_object(self, object_file: Path) -> List[FunctionPattern]:
        """Extract function patterns from a single object file.
        
        Args:
            object_file: Path to ELF object file
            
        Returns:
            List of function patterns extracted from the file
            
        Raises:
            SignatureGenerationError: If pattern extraction fails
        """
        if not object_file.exists():
            raise ValidationError(f"Object file not found: {object_file}")
        
        patterns = []
        
        try:
            with open(object_file, 'rb') as f:
                elf = ELFFile(f)
                
                # Get symbol table
                symtab = elf.get_section_by_name('.symtab')
                if not symtab:
                    self.logger.warning(f"No symbol table in {object_file.name}")
                    return patterns
                
                # Find function symbols
                func_symbols = self._find_function_symbols(symtab)
                self.logger.debug(f"Found {len(func_symbols)} function symbols in {object_file.name}")
                
                # Extract patterns for each function
                pattern_count = 0
                for symbol in func_symbols:
                    if pattern_count >= self.max_functions_per_object:
                        self.logger.debug(f"Reached max functions limit ({self.max_functions_per_object})")
                        break
                    
                    pattern = self._extract_function_pattern(elf, symbol, object_file.name)
                    if pattern:
                        patterns.append(pattern)
                        pattern_count += 1
                
                self.logger.debug(f"Extracted {len(patterns)} patterns from {object_file.name}")
                
        except Exception as e:
            raise SignatureGenerationError(
                f"Failed to extract patterns from {object_file}: {e}",
                stage="pattern_extraction"
            ) from e
        
        return patterns
    
    def _find_function_symbols(self, symtab: SymbolTableSection) -> List[Any]:
        """Find function symbols in the symbol table."""
        func_symbols = []
        
        for symbol in symtab.iter_symbols():
            # Check if it's a function symbol with size > 0
            if (symbol['st_info']['type'] == 'STT_FUNC' and 
                symbol['st_size'] > 0 and
                symbol.name):
                
                # Skip very small functions if configured
                if self.skip_small_functions and symbol['st_size'] < self.min_pattern_length:
                    continue
                
                func_symbols.append(symbol)
        
        return func_symbols
    
    def _extract_function_pattern(self, elf: ELFFile, symbol: Any, _object_name: str) -> Optional[FunctionPattern]:
        """Extract pattern for a single function symbol."""
        func_name = symbol.name
        func_size = symbol['st_size']
        
        try:
            # Find the section containing this function
            section = self._find_function_section(elf, symbol, func_name)
            if not section:
                return None
            
            # Get function data
            section_data = section.data()
            func_offset = symbol['st_value'] - section['sh_addr']
            
            # Validate offset
            if func_offset < 0 or func_offset >= len(section_data):
                self.logger.debug(f"Invalid function offset for {func_name}: {func_offset}")
                return None
            
            # Extract pattern bytes
            pattern_length = min(self.max_pattern_length, func_size, len(section_data) - func_offset)
            if pattern_length < self.min_pattern_length:
                return None
            
            func_bytes = section_data[func_offset:func_offset + pattern_length]
            
            # Convert to hex pattern
            hex_pattern = ''.join(f'{b:02X}' for b in func_bytes)
            
            # Clean up function name
            clean_name = self._clean_function_name(func_name)
            
            return FunctionPattern(
                name=clean_name,
                hex_pattern=hex_pattern,
                length=pattern_length,
                address=symbol['st_value'],
                section_name=section.name
            )
            
        except Exception as e:
            self.logger.debug(f"Failed to extract pattern for {func_name}: {e}")
            return None
    
    def _find_function_section(self, elf: ELFFile, symbol: Any, func_name: str) -> Optional[Any]:
        """Find the section containing the function."""
        # Method 1: Look for .text.function_name sections (Rust style)
        for section in elf.iter_sections():
            if (section.name.startswith('.text.') and 
                func_name in section.name and
                section.data()):
                return section
        
        # Method 2: Use symbol's section index
        if symbol['st_shndx'] != 'SHN_UNDEF':
            try:
                section_idx = symbol['st_shndx']
                if isinstance(section_idx, int) and 0 <= section_idx < elf.num_sections():
                    section = elf.get_section(section_idx)
                    if section and section.name.startswith('.text') and section.data():
                        return section
            except Exception as e:
                self.logger.debug(f"Failed to get section by index for {func_name}: {e}")
        
        # Method 3: Find by address range
        func_addr = symbol['st_value']
        func_size = symbol['st_size']
        
        for section in elf.iter_sections():
            if (section.name.startswith('.text') and 
                section['sh_addr'] <= func_addr < section['sh_addr'] + section['sh_size']):
                return section
        
        return None
    
    def _clean_function_name(self, func_name: str) -> str:
        """Clean and simplify function names for PAT format using rust-demangler."""
        original_name = func_name
        final_name = func_name
        
        # Try to demangle Rust names
        if self.demangle_rust_names and self._is_rust_mangled_name(func_name):
            try:
                # Double-check that demangling will work before proceeding
                demangled = rust_demangle(func_name)
                if demangled and demangled != func_name:
                    # Verify this is a proper Rust mangled name (should have succeeded)
                    if not func_name.endswith('E'):
                        self.logger.debug(f"Warning: Successfully demangled name that doesn't end with 'E': {original_name[:30]}...")
                    
                    final_name = demangled
                    self.logger.debug(f"Demangled: {original_name[:50]}... -> {demangled[:50]}...")
                    
                    # Extract short readable name if requested
                    if self.use_short_names:
                        short_name = self._extract_short_name(demangled)
                        if short_name and short_name != "unnamed_func":
                            final_name = short_name
                            self.logger.debug(f"Short name: {demangled[:30]}... -> {short_name}")
                        else:
                            # If short name extraction fails, use demangled but clean it
                            final_name = demangled
                else:
                    # Demangling returned same name, treat as non-mangled
                    self.logger.debug(f"No demangling needed for: {original_name[:30]}...")
                    
            except Exception as e:
                self.logger.debug(f"Failed to demangle {original_name[:30]}...: {e}")
                # Fallback: use original name but try to make it readable
                if self.use_short_names:
                    # Try to extract readable part from mangled name
                    readable_part = self._extract_readable_from_mangled(original_name)
                    if readable_part:
                        final_name = readable_part
        else:
            # Not a Rust mangled name, but still try to make it readable if requested
            if self.use_short_names:
                short_name = self._extract_short_name(func_name)
                if short_name and short_name != "unnamed_func":
                    final_name = short_name
        
        # Clean up problematic characters for PAT format
        clean_name = self._sanitize_for_pat(final_name)
        
        # Ensure it's not empty and has reasonable length
        if not clean_name or clean_name == '_':
            # Last resort: use original name but sanitized
            clean_name = self._sanitize_for_pat(original_name)
            if not clean_name or clean_name == '_':
                clean_name = "unnamed_func"
        elif len(clean_name) > 80:  # Increased limit for better readability
            clean_name = clean_name[:77] + "..."
        
        return clean_name
    
    def _is_rust_mangled_name(self, name: str) -> bool:
        """Check if a name appears to be a Rust mangled name."""
        # Standard Rust mangled names should end with 'E'
        if not name.endswith('E'):
            return False
            
        # Check for common Rust mangled prefixes
        return (name.startswith('_ZN') or 
                name.startswith('_R') or 
                name.startswith('__Z') or
                '..rust' in name or
                name.count('$') > 2)
    
    def _extract_short_name(self, demangled_name: str) -> Optional[str]:
        """Extract a short, readable name from a demangled Rust function name."""
        name = demangled_name
        
        # Extract the main function name from module::path::function::hash
        if '::' in name:
            parts = name.split('::')
            
            # Find the function name (usually second to last, before hash)
            # Example: serde::de::SeqAccess::next_element::h3e8e91ed7a479bc2
            # We want "next_element", not the hash "h3e8e91ed7a479bc2"
            
            function_name = None
            for i in range(len(parts) - 1, -1, -1):  # Reverse order
                part = parts[i].strip()
                
                # Skip hash suffixes (start with 'h' and are hex-like)
                if part.startswith('h') and len(part) > 10 and all(c in '0123456789abcdef' for c in part[1:]):
                    continue
                
                # Skip generic parameters and empty parts
                if not part or part.startswith('<') or part.endswith('>'):
                    continue
                
                # Clean up generic parameters within the part
                if '<' in part:
                    part = part.split('<')[0]
                
                # This looks like a valid function name
                if part and len(part) > 1 and not part.isdigit():
                    function_name = part
                    break
            
            if function_name:
                name = function_name
        
        # Clean up remaining problematic characters
        patterns = [
            (r'<.*?>', ''),  # Remove any remaining generic parameters
            (r'\$\w+\$', '_'),  # Replace internal symbols
            (r'\s+', '_'),  # Spaces to underscores
            (r'[^a-zA-Z0-9_]', '_'),  # Replace non-identifier chars
        ]
        
        for pattern, replacement in patterns:
            name = re.sub(pattern, replacement, name)
        
        # Ensure it's a valid identifier
        if name and len(name) > 1 and (name[0].isalpha() or name[0] == '_'):
            return name
        
        return None
    
    def _extract_readable_from_mangled(self, mangled_name: str) -> Optional[str]:
        """Extract readable parts from mangled names when demangling fails."""
        # Try to find readable ASCII sequences in mangled names
        # This is a fallback when rust-demangler fails
        
        # Look for patterns that might be function names
        patterns = [
            r'([a-zA-Z_][a-zA-Z0-9_]{3,})',  # Valid identifiers
            r'([a-zA-Z]{4,})',  # At least 4 letter sequences
        ]
        
        candidates = []
        for pattern in patterns:
            matches = re.findall(pattern, mangled_name)
            candidates.extend(matches)
        
        # Filter out common mangled prefixes/suffixes and hash patterns
        filtered = []
        for candidate in candidates:
            # Skip common mangled patterns
            if candidate.lower() in ['rust', 'core', 'alloc', 'std', 'drop', 'place']:
                continue
            if candidate.startswith('ZN') or candidate.startswith('GT'):
                continue
            # Skip hash patterns (contains 'h' followed by long hex sequences)
            if ('h' in candidate and 
                re.search(r'h[0-9a-fA-F]{10,}', candidate)):
                continue
            # Skip very short candidates unless they look meaningful
            if len(candidate) > 5:  # Prefer longer candidates
                filtered.append(candidate)
            elif len(candidate) > 3 and candidate.lower() not in ['drop', 'vec', 'ptr']:
                filtered.append(candidate)
        
        # Return the most meaningful candidate (prefer non-generic names)
        if filtered:
            # Prefer names that contain meaningful terms like function names
            meaningful = [c for c in filtered if any(term in c.lower() for term in ['error', 'transaction', 'element', 'deserializer'])]
            if meaningful:
                return max(meaningful, key=len)
            return max(filtered, key=len)
        
        return None
    
    def _sanitize_for_pat(self, name: str) -> str:
        """Sanitize name for PAT file format."""
        # PAT format has specific requirements for function names
        # Replace problematic characters
        clean_name = re.sub(r'[<>(){}[\],;:\s]', '_', name)
        clean_name = re.sub(r'[^\w._$]', '_', clean_name)  # Allow $ for Rust
        clean_name = re.sub(r'_+', '_', clean_name)
        clean_name = clean_name.strip('_')
        
        return clean_name
    
    
    @log_execution_time
    def generate_pat_from_objects(self, 
                                  object_files: List[Path], 
                                  output_pat: Path,
                                  library_name: str = "") -> Path:
        """Generate PAT file from multiple object files.
        
        Args:
            object_files: List of object file paths
            output_pat: Output PAT file path
            library_name: Name of the library (for PAT header)
            
        Returns:
            Path to generated PAT file
            
        Raises:
            SignatureGenerationError: If PAT generation fails
        """
        if not object_files:
            raise ValidationError("No object files provided for PAT generation")
        
        # Validate object files exist
        missing_files = [f for f in object_files if not f.exists()]
        if missing_files:
            raise ValidationError(f"Object files not found: {missing_files}")
        
        self.logger.info(f"Generating PAT file from {len(object_files)} object files")
        self.logger.info(f"Output: {output_pat}")
        
        # Ensure output directory exists
        output_pat.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            # Extract patterns from all object files
            all_patterns = []
            
            with log_progress(len(object_files), "Extracting patterns") as update_progress:
                for obj_file in object_files:
                    patterns = self.extract_patterns_from_object(obj_file)
                    all_patterns.extend(patterns)
                    update_progress()
            
            if not all_patterns:
                raise SignatureGenerationError(
                    "No patterns extracted from any object files",
                    input_files=object_files,
                    stage="pattern_extraction"
                )
            
            # Remove duplicates by hex pattern
            unique_patterns = self._deduplicate_patterns(all_patterns)
            self.logger.info(f"Extracted {len(all_patterns)} patterns, {len(unique_patterns)} unique")
            
            # Write PAT file
            self._write_pat_file(output_pat, unique_patterns, library_name)
            
            # Validate generated file
            if not output_pat.exists() or output_pat.stat().st_size == 0:
                raise SignatureGenerationError(
                    f"PAT file was not generated or is empty: {output_pat}",
                    output_file=output_pat,
                    stage="file_generation"
                )
            
            self.logger.info(f"PAT file generated successfully: {len(unique_patterns)} patterns, "
                           f"{output_pat.stat().st_size} bytes")
            
            return output_pat
            
        except Exception as e:
            # Clean up partial file on error
            if output_pat.exists():
                try:
                    output_pat.unlink()
                except Exception:
                    pass
            
            if not isinstance(e, (SignatureGenerationError, ValidationError)):
                raise SignatureGenerationError(
                    f"Failed to generate PAT file: {e}",
                    input_files=object_files,
                    output_file=output_pat,
                    stage="pat_generation"
                ) from e
            else:
                raise
    
    def _deduplicate_patterns(self, patterns: List[FunctionPattern]) -> List[FunctionPattern]:
        """Remove duplicate patterns based on hex pattern."""
        seen_patterns = set()
        unique_patterns = []
        
        for pattern in patterns:
            if pattern.hex_pattern not in seen_patterns:
                seen_patterns.add(pattern.hex_pattern)
                unique_patterns.append(pattern)
        
        return unique_patterns
    
    def _write_pat_file(self, output_pat: Path, patterns: List[FunctionPattern], library_name: str):
        """Write patterns to PAT file."""
        try:
            with open(output_pat, 'w', encoding='utf-8') as f:
                # Write PAT header
                f.write("---\n")
                if library_name:
                    f.write(f"; Library: {library_name}\n")
                f.write(f"; Generated by Custom PAT Generator\n")
                f.write(f"; Patterns: {len(patterns)}\n")
                f.write(";\n")
                
                # Write patterns
                for pattern in patterns:
                    f.write(pattern.to_pat_line() + "\n")
                    
        except Exception as e:
            raise SignatureGenerationError(
                f"Failed to write PAT file {output_pat}: {e}",
                output_file=output_pat,
                stage="file_writing"
            ) from e
    
    @log_execution_time
    def generate_pat_from_rlib(self, 
                               rlib_path: Path, 
                               output_pat: Path,
                               library_name: Optional[str] = None) -> Path:
        """Generate PAT file directly from .rlib file.
        
        Args:
            rlib_path: Path to .rlib file
            output_pat: Output PAT file path
            library_name: Library name (defaults to rlib stem name)
            
        Returns:
            Path to generated PAT file
        """
        if not rlib_path.exists():
            raise ValidationError(f"RLIB file not found: {rlib_path}")
        
        if not library_name:
            library_name = rlib_path.stem
            if library_name.startswith('lib'):
                library_name = library_name[3:]
        
        self.logger.info(f"Generating PAT from RLIB: {rlib_path}")
        
        # Create temporary directory for object extraction
        temp_objects_dir = settings.output_dir / "temp_objects" / library_name
        temp_objects_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            # Extract object files from RLIB
            extractor = RlibExtractor(temp_objects_dir)
            object_files = extractor.extract_objects(rlib_path, temp_objects_dir)
            
            if not object_files:
                raise SignatureGenerationError(
                    f"No object files extracted from {rlib_path}",
                    stage="rlib_extraction"
                )
            
            self.logger.info(f"Extracted {len(object_files)} object files from RLIB")
            
            # Generate PAT from extracted objects
            return self.generate_pat_from_objects(object_files, output_pat, library_name)
            
        finally:
            # Clean up temporary objects
            try:
                import shutil
                if temp_objects_dir.exists():
                    shutil.rmtree(temp_objects_dir, ignore_errors=True)
            except Exception as e:
                self.logger.warning(f"Failed to cleanup temp objects: {e}")
    
    def get_statistics(self, pat_file: Path) -> Dict[str, Any]:
        """Get statistics about a generated PAT file."""
        if not pat_file.exists():
            return {"error": "PAT file does not exist"}
        
        try:
            lines = pat_file.read_text(encoding='utf-8').splitlines()
            
            patterns = 0
            comments = 0
            empty_lines = 0
            
            for line in lines:
                line = line.strip()
                if not line:
                    empty_lines += 1
                elif line.startswith(';') or line.startswith('---'):
                    comments += 1
                else:
                    patterns += 1
            
            return {
                "file_size": pat_file.stat().st_size,
                "total_lines": len(lines),
                "patterns": patterns,
                "comments": comments,
                "empty_lines": empty_lines,
                "average_pattern_size": pat_file.stat().st_size / patterns if patterns > 0 else 0
            }
            
        except Exception as e:
            return {"error": f"Failed to analyze PAT file: {e}"}
    
    def validate_pat_file(self, pat_file: Path) -> List[str]:
        """Validate PAT file format and content.
        
        Returns:
            List of validation issues (empty if valid)
        """
        issues = []
        
        if not pat_file.exists():
            issues.append(f"PAT file does not exist: {pat_file}")
            return issues
        
        if pat_file.stat().st_size == 0:
            issues.append(f"PAT file is empty: {pat_file}")
            return issues
        
        try:
            lines = pat_file.read_text(encoding='utf-8').splitlines()
            
            if not lines:
                issues.append("PAT file has no content")
                return issues
            
            # Check for PAT header
            if not lines[0].strip() == "---":
                issues.append("PAT file missing standard header (---)")
            
            pattern_count = 0
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line.startswith(';') or line.startswith('---'):
                    continue
                
                pattern_count += 1
                
                # Validate pattern format: HEX_PATTERN LENGTH NAME
                parts = line.split(' ', 2)
                if len(parts) < 3:
                    issues.append(f"Line {line_num}: Invalid pattern format (expected: hex length name)")
                    continue
                
                hex_pattern, length_str, name = parts
                
                # Validate hex pattern
                if not re.match(r'^[0-9A-Fa-f.]+$', hex_pattern):
                    issues.append(f"Line {line_num}: Invalid hex pattern: {hex_pattern}")
                
                # Validate length
                try:
                    length = int(length_str, 16)
                    if length <= 0 or length > 255:
                        issues.append(f"Line {line_num}: Invalid pattern length: {length}")
                except ValueError:
                    issues.append(f"Line {line_num}: Invalid length format: {length_str}")
                
                # Validate name
                if not name or len(name) > 100:
                    issues.append(f"Line {line_num}: Invalid function name: {name}")
            
            if pattern_count == 0:
                issues.append("PAT file contains no patterns")
            
        except Exception as e:
            issues.append(f"Failed to validate PAT file: {e}")
        
        return issues