"""Rust type extractor for CLI integration.

This module integrates the functionality of extract_rust_types_basic.py 
into the CLI framework for generating IDA Pro compatible type libraries.
"""

import os
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

from elftools.elf.elffile import ELFFile
from elftools.dwarf.die import DIE

from ..core.logger import LoggerMixin
from ..core.exceptions import ValidationError, ExtractionError


class RustTypeInfo:
    """Container for Rust type information."""
    
    def __init__(self, name: str, tag: str, size: int = 0, alignment: int = 1):
        self.name = name
        self.tag = tag
        self.size = size
        self.alignment = alignment
        self.members = []


class RustTypeExtractor(LoggerMixin):
    """Extract Rust type information from RLIB files for CLI integration."""
    
    def __init__(self):
        super().__init__()
        self.types = {}  # Extracted type information
        self.rust_to_c_mapping = {
            'u8': 'unsigned char',
            'u16': 'unsigned short',
            'u32': 'unsigned int', 
            'u64': 'unsigned long long',
            'i8': 'signed char',
            'i16': 'short',
            'i32': 'int',
            'i64': 'long long',
            'f32': 'float',
            'f64': 'double',
            'bool': 'unsigned char',
            'usize': 'unsigned long long',
            'isize': 'long long',
            'char': 'unsigned int',  # Rust char是32位Unicode
        }
    
    def extract_types_from_rlib(self, rlib_path: Path) -> Dict[str, RustTypeInfo]:
        """
        Extract type information from RLIB file.
        
        Args:
            rlib_path: Path to the RLIB file
            
        Returns:
            Dictionary of extracted type information
            
        Raises:
            ValidationError: If RLIB file is invalid
            ExtractionError: If extraction fails
        """
        if not rlib_path.exists():
            raise ValidationError(
                f"RLIB file not found: {rlib_path}",
                field_name="rlib_path",
                field_value=str(rlib_path)
            )
        
        self.logger.info(f"Extracting types from RLIB: {rlib_path.name}")
        self.types.clear()
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                # Extract RLIB archive
                self._extract_rlib_archive(rlib_path, temp_dir)
                
                # Process object files
                object_files = list(Path(temp_dir).glob('*.o'))
                if not object_files:
                    raise ExtractionError(
                        f"No object files found in RLIB: {rlib_path}",
                        rlib_path=rlib_path
                    )
                
                self.logger.debug(f"Processing {len(object_files)} object files")
                
                for obj_file in object_files:
                    self._process_object_file(obj_file)
                
                self.logger.info(f"Extracted {len(self.types)} types from {rlib_path.name}")
                return dict(self.types)
                
        except Exception as e:
            if isinstance(e, (ValidationError, ExtractionError)):
                raise
            else:
                raise ExtractionError(
                    f"Failed to extract types from RLIB: {e}",
                    rlib_path=rlib_path
                ) from e
    
    def _extract_rlib_archive(self, rlib_path: Path, temp_dir: str):
        """Extract RLIB archive using ar command."""
        try:
            result = subprocess.run(
                ['ar', 'x', str(rlib_path.resolve())],  # Use absolute path
                cwd=temp_dir,
                capture_output=True,
                text=True,
                check=True
            )
            self.logger.debug(f"RLIB extraction successful")
            
        except subprocess.CalledProcessError as e:
            raise ExtractionError(
                f"Failed to extract RLIB archive: {e.stderr}",
                rlib_path=rlib_path
            ) from e
        except FileNotFoundError as e:
            raise ExtractionError(
                "ar command not found - GNU binutils required for RLIB extraction",
                rlib_path=rlib_path
            ) from e
    
    def _process_object_file(self, obj_file: Path):
        """Process individual object file for type information."""
        try:
            if not obj_file.exists() or obj_file.stat().st_size == 0:
                self.logger.debug(f"Skipping empty/missing file: {obj_file.name}")
                return
            
            with open(obj_file, 'rb') as f:
                # Check ELF magic
                magic = f.read(4)
                f.seek(0)
                
                if magic != b'\x7fELF':
                    self.logger.debug(f"Skipping non-ELF file: {obj_file.name}")
                    return
                
                # Parse ELF file
                try:
                    elf_file = ELFFile(f)
                except Exception as e:
                    self.logger.warning(f"Failed to parse ELF file {obj_file.name}: {e}")
                    return
                
                # Check for DWARF debug information
                if not elf_file.has_dwarf_info():
                    self.logger.debug(f"No DWARF info in: {obj_file.name}")
                    return
                
                # Process DWARF information
                dwarf_info = elf_file.get_dwarf_info()
                self._process_dwarf_info(dwarf_info)
                
        except Exception as e:
            self.logger.warning(f"Failed to process object file {obj_file.name}: {e}")
    
    def _process_dwarf_info(self, dwarf_info):
        """Process DWARF debug information for type extraction."""
        try:
            cu_count = 0
            for cu in dwarf_info.iter_CUs():
                cu_count += 1
                for die in cu.iter_DIEs():
                    if die.tag in ['DW_TAG_structure_type', 'DW_TAG_union_type', 'DW_TAG_enumeration_type']:
                        self._extract_type_from_die(die)
            
            self.logger.debug(f"Processed {cu_count} compilation units")
            
        except Exception as e:
            self.logger.error(f"DWARF processing failed: {e}")
    
    def _extract_type_from_die(self, die: DIE):
        """Extract type information from DWARF DIE."""
        try:
            type_name = self._get_die_name(die)
            if not type_name or not self._is_valid_c_identifier(type_name):
                return
            
            # Create type info
            type_info = RustTypeInfo(
                name=type_name,
                tag=die.tag,
                size=self._get_die_attribute(die, 'DW_AT_byte_size', 0),
                alignment=self._get_die_attribute(die, 'DW_AT_alignment', 1)
            )
            
            # Extract members for structures and unions
            if die.tag in ['DW_TAG_structure_type', 'DW_TAG_union_type']:
                self._extract_members(die, type_info)
            elif die.tag == 'DW_TAG_enumeration_type':
                self._extract_enum_values(die, type_info)
            
            # Store valid types
            if type_info.size > 0 or type_info.members:
                self.types[type_name] = type_info
                self.logger.debug(f"Extracted type: {type_name} (size: {type_info.size})")
            
        except Exception as e:
            self.logger.warning(f"Failed to extract type from DIE: {e}")
    
    def _get_die_name(self, die: DIE) -> str:
        """Get name from DWARF DIE."""
        name_attr = die.attributes.get('DW_AT_name')
        if name_attr:
            return name_attr.value.decode('utf-8') if isinstance(name_attr.value, bytes) else str(name_attr.value)
        return ""
    
    def _get_die_attribute(self, die: DIE, attr_name: str, default_value: Any) -> Any:
        """Get attribute value from DWARF DIE."""
        attr = die.attributes.get(attr_name)
        return attr.value if attr else default_value
    
    def _is_valid_c_identifier(self, name: str) -> bool:
        """Check if name is a valid C identifier."""
        if not name:
            return False
        
        # Skip names with invalid characters
        invalid_chars = ['<', '>', '[', ']', '{', '}', '(', ')', '*', '&', ' ', '\t', '\n']
        if any(char in name for char in invalid_chars):
            return False
        
        # Skip compiler-generated names
        if name.startswith('_') or name.startswith('__'):
            return False
        
        # Skip very long names (likely mangled)
        if len(name) > 100:
            return False
        
        return True
    
    def _extract_members(self, die: DIE, type_info: RustTypeInfo):
        """Extract member information from structure/union DIE."""
        try:
            raw_members = []
            for child in die.iter_children():
                if child.tag == 'DW_TAG_member':
                    member_name = self._get_die_name(child)
                    member_offset = self._get_die_attribute(child, 'DW_AT_data_member_location', 0)
                    
                    if member_name:
                        member_info = {
                            'name': member_name,
                            'offset': member_offset,
                            'type': 'unknown'  # Could be enhanced to resolve type references
                        }
                        raw_members.append(member_info)
            
            # Process members to handle overlapping/duplicate offsets
            members_by_offset = {}
            for member in raw_members:
                offset = member['offset']
                if offset not in members_by_offset:
                    members_by_offset[offset] = [member]
                else:
                    members_by_offset[offset].append(member)
            
            # Resolve overlapping members
            final_members = []
            for offset, members_at_offset in sorted(members_by_offset.items()):
                if len(members_at_offset) == 1:
                    # Single member at this offset
                    final_members.append(members_at_offset[0])
                else:
                    # Multiple members at same offset - merge or pick the best one
                    # For now, pick the first one and rename others
                    for i, member in enumerate(members_at_offset):
                        if i == 0:
                            final_members.append(member)
                        else:
                            # Rename overlapping members
                            member['name'] = f"{member['name']}_variant_{i}"
                            final_members.append(member)
            
            # Sort members by offset
            final_members.sort(key=lambda m: m['offset'])
            
            # Calculate member sizes with improved logic
            for i, member in enumerate(final_members):
                if i < len(final_members) - 1:
                    next_offset = final_members[i + 1]['offset']
                    if next_offset > member['offset']:
                        # Normal case: size is difference to next member
                        member['size'] = next_offset - member['offset']
                    else:
                        # Overlapping case: use minimum size
                        member['size'] = 1
                else:
                    # Last member: size is from its offset to end of struct
                    remaining_size = type_info.size - member['offset']
                    member['size'] = max(1, remaining_size)
                
                # Ensure minimum size of 1
                member['size'] = max(1, member['size'])
            
            # Additional pass to ensure no duplicate names and avoid C++ keywords
            cpp_keywords = {
                'public', 'private', 'protected', 'class', 'struct', 'union', 'enum',
                'namespace', 'template', 'typename', 'const', 'static', 'extern',
                'inline', 'virtual', 'friend', 'operator', 'new', 'delete',
                'if', 'else', 'while', 'for', 'do', 'switch', 'case', 'default',
                'try', 'catch', 'throw', 'return', 'break', 'continue', 'goto',
                'int', 'char', 'bool', 'float', 'double', 'void', 'auto', 'register'
            }
            
            seen_names = set()
            for member in final_members:
                original_name = member['name']
                
                # Check for C++ keywords
                if original_name in cpp_keywords:
                    member['name'] = f"{original_name}_member"
                
                # Check for duplicates
                counter = 1
                while member['name'] in seen_names:
                    member['name'] = f"{original_name}_{counter}"
                    counter += 1
                seen_names.add(member['name'])
            
            type_info.members = final_members
                        
        except Exception as e:
            self.logger.warning(f"Failed to extract members: {e}")
    
    def _extract_enum_values(self, die: DIE, type_info: RustTypeInfo):
        """Extract enumeration values from enum DIE."""
        try:
            for child in die.iter_children():
                if child.tag == 'DW_TAG_enumerator':
                    enum_name = self._get_die_name(child)
                    enum_value = self._get_die_attribute(child, 'DW_AT_const_value', 0)
                    
                    if enum_name:
                        enum_info = {
                            'name': enum_name,
                            'value': enum_value
                        }
                        type_info.members.append(enum_info)
                        
        except Exception as e:
            self.logger.warning(f"Failed to extract enum values: {e}")
    
    def generate_header_content(self, lib_name: str, version: str, target: str = "x86_64-unknown-linux-gnu") -> Tuple[str, str]:
        """
        Generate C and C++ header content from extracted types.
        
        Args:
            lib_name: Library name for namespacing
            version: Library version
            target: Target architecture
            
        Returns:
            Tuple of (c_header_content, cpp_header_content)
        """
        if not self.types:
            raise ExtractionError("No types extracted - call extract_types_from_rlib() first")
        
        # Generate namespace-safe library name
        safe_lib_name = lib_name.replace('-', '_')
        namespace = f"{safe_lib_name}_v{version.replace('.', '_')}"
        
        # Generate C header
        c_header = self._generate_c_header(safe_lib_name, version, target)
        
        # Generate C++ header with namespace
        cpp_header = self._generate_cpp_header(namespace, safe_lib_name, version, target)
        
        return c_header, cpp_header
    
    def _generate_c_header(self, lib_name: str, version: str, target: str) -> str:
        """Generate C header content."""
        header_lines = [
            f"/* {lib_name} v{version} 类型定义 - C版本 */",
            f"/* 目标平台: {target} */",
            f"/* 生成时间: {self._get_timestamp()} */",
            "",
            f"#ifndef __{lib_name.upper()}_TYPES_H__",
            f"#define __{lib_name.upper()}_TYPES_H__",
            "",
            "#ifdef __cplusplus",
            "extern \"C\" {",
            "#endif",
            "",
            "/* 结构体定义 */",
        ]
        
        # Add structure definitions
        for type_name, type_info in self.types.items():
            if type_info.tag == 'DW_TAG_structure_type':
                header_lines.extend(self._generate_c_struct(type_name, type_info))
        
        # Add footer
        header_lines.extend([
            "",
            "#ifdef __cplusplus",
            "}",
            "#endif",
            "",
            f"#endif /* __{lib_name.upper()}_TYPES_H__ */"
        ])
        
        return "\n".join(header_lines)
    
    def _generate_cpp_header(self, namespace: str, lib_name: str, version: str, target: str) -> str:
        """Generate C++ header content with namespace."""
        header_lines = [
            f"/* {lib_name} v{version} 类型定义 - C++版本 */",
            f"/* 目标平台: {target} */",
            f"/* 生成时间: {self._get_timestamp()} */",
            "",
            f"#ifndef __{lib_name.upper()}_TYPES_HPP__",
            f"#define __{lib_name.upper()}_TYPES_HPP__",
            "",
            "/* 跨编译器offsetof实现 - 无外部依赖 */",
            "#ifdef __cplusplus",
            "    #if defined(__GNUC__) || defined(__clang__)",
            "        #define MANUAL_OFFSETOF(type, member) ((unsigned long long)__builtin_offsetof(type, member))",
            "    #else",
            "        #define MANUAL_OFFSETOF(type, member) ((unsigned long long)&(((type*)0)->member))",
            "    #endif",
            "#else",
            "    #define MANUAL_OFFSETOF(type, member) ((unsigned long long)&((type*)0)->member)",
            "#endif",
            "",
            f"namespace {namespace} {{",
            "",
        ]
        
        # Add structure definitions with namespace
        for type_name, type_info in self.types.items():
            if type_info.tag == 'DW_TAG_structure_type':
                header_lines.extend(self._generate_cpp_struct(type_name, type_info, namespace))
        
        # Add footer
        header_lines.extend([
            "",
            f"}} // namespace {namespace}",
            "",
            f"#endif /* __{lib_name.upper()}_TYPES_HPP__ */"
        ])
        
        return "\n".join(header_lines)
    
    def _generate_c_struct(self, type_name: str, type_info: RustTypeInfo) -> List[str]:
        """Generate C structure definition."""
        lines = [
            f"struct {type_name} {{",
        ]
        
        # Add members
        for member in type_info.members:
            lines.append(f"    unsigned char {member['name']}[{member.get('size', 1)}];  // offset: {member['offset']}")
        
        # Add padding if needed
        if type_info.size > 0 and not type_info.members:
            lines.append(f"    unsigned char data[{type_info.size}];")
        
        lines.extend([
            f"}};",
            f"/* Size: {type_info.size}, Alignment: {type_info.alignment} */",
            ""
        ])
        
        return lines
    
    def _generate_cpp_struct(self, type_name: str, type_info: RustTypeInfo, namespace: str) -> List[str]:
        """Generate C++ structure definition with accurate member layout."""
        lines = [
            f"struct {type_name} {{",
        ]
        
        if type_info.members:
            # Detect overlapping members that should be in a union
            overlapping_groups = self._detect_overlapping_members(type_info.members)
            
            if overlapping_groups:
                # Generate structure with unions for overlapping members
                current_offset = 0
                processed_members = set()
                
                for member in type_info.members:
                    if id(member) in processed_members:
                        continue
                        
                    member_offset = member['offset']
                    member_size = member['size']
                    member_name = member['name']
                    
                    # Add padding if needed before this member
                    if member_offset > current_offset:
                        padding_size = member_offset - current_offset
                        lines.append(f"    unsigned char padding_{current_offset}[{padding_size}];  // padding")
                        current_offset = member_offset
                    
                    # Check if this member is part of an overlapping group
                    overlapping_group = None
                    for group in overlapping_groups:
                        if member in group:
                            overlapping_group = group
                            break
                    
                    if overlapping_group and len(overlapping_group) > 1:
                        # Generate union for overlapping members
                        union_name = f"union_{member_offset}"
                        lines.append(f"    union {{")
                        
                        max_end_offset = member_offset
                        for overlap_member in overlapping_group:
                            lines.append(f"        unsigned char {overlap_member['name']}[{overlap_member['size']}];")
                            max_end_offset = max(max_end_offset, overlap_member['offset'] + overlap_member['size'])
                            processed_members.add(id(overlap_member))
                        
                        lines.append(f"    }} {union_name};  // offset: {member_offset}")
                        current_offset = max_end_offset
                    else:
                        # Regular member
                        lines.append(f"    unsigned char {member_name}[{member_size}];  // offset: {member_offset}")
                        current_offset = member_offset + member_size
                        processed_members.add(id(member))
                
                # Add final padding if needed
                if type_info.size > current_offset:
                    padding_size = type_info.size - current_offset
                    lines.append(f"    unsigned char padding_end[{padding_size}];  // final padding")
            else:
                # No overlapping members, use original logic
                current_offset = 0
                
                for member in type_info.members:
                    member_offset = member['offset']
                    member_size = member['size']
                    member_name = member['name']
                    
                    # Add padding if needed before this member
                    if member_offset > current_offset:
                        padding_size = member_offset - current_offset
                        lines.append(f"    unsigned char padding_{current_offset}[{padding_size}];  // padding")
                    
                    # Add the actual member
                    lines.append(f"    unsigned char {member_name}[{member_size}];  // offset: {member_offset}")
                    current_offset = member_offset + member_size
                
                # Add final padding if needed
                if type_info.size > current_offset:
                    padding_size = type_info.size - current_offset
                    lines.append(f"    unsigned char padding_end[{padding_size}];  // final padding")
        else:
            # No members, use simple byte array
            if type_info.size > 0:
                lines.append(f"    unsigned char data[{type_info.size}];")
            else:
                lines.append("    unsigned char data[1];  // placeholder")
        
        lines.append("};")
        
        # Add static assertions
        if type_info.size > 0:
            lines.append(f"static_assert(sizeof({type_name}) == {type_info.size}, \"Size mismatch for {type_name}\");")
        
        # Add member offset assertions (only for non-overlapping members to avoid union issues)
        overlapping_groups = self._detect_overlapping_members(type_info.members)
        overlapping_member_ids = set()
        for group in overlapping_groups:
            if len(group) > 1:
                for member in group:
                    overlapping_member_ids.add(id(member))
        
        for member in type_info.members:
            if id(member) not in overlapping_member_ids:
                lines.append(
                    f"static_assert(MANUAL_OFFSETOF({type_name}, {member['name']}) == {member['offset']}, "
                    f"\"Offset mismatch for {type_name}::{member['name']}\");"
                )
        
        lines.append("")
        return lines
    
    def _detect_overlapping_members(self, members: List[Dict]) -> List[List[Dict]]:
        """Detect groups of overlapping members that should be in unions."""
        if not members:
            return []
        
        # Group members by overlapping ranges
        overlapping_groups = []
        processed = set()
        
        for i, member in enumerate(members):
            if i in processed:
                continue
                
            member_start = member['offset']
            member_end = member['offset'] + member['size']
            
            # Find all members that overlap with this one
            overlapping = [member]
            processed.add(i)
            
            for j, other_member in enumerate(members[i+1:], i+1):
                if j in processed:
                    continue
                    
                other_start = other_member['offset']
                other_end = other_member['offset'] + other_member['size']
                
                # Check for overlap: either starts within range or ends within range
                if (member_start <= other_start < member_end) or \
                   (member_start < other_end <= member_end) or \
                   (other_start <= member_start < other_end) or \
                   (other_start < member_end <= other_end):
                    overlapping.append(other_member)
                    processed.add(j)
            
            if len(overlapping) > 1:
                overlapping_groups.append(overlapping)
        
        return overlapping_groups
    
    def _get_timestamp(self) -> str:
        """Get current timestamp for header generation."""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")