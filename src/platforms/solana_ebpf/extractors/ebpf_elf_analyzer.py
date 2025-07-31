"""Solana eBPF ELF file analyzer.

This module provides ELF file analysis functionality specifically for Solana eBPF programs.
Core algorithms ported from solana-ida-signatures-factory flair-preprocessor.py.
"""

import ar
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

from ....core.logger import LoggerMixin
from ..constants.relocation_types import REL_PATCH_SIZE, REL_TYPE
from .solana_relocations import SolanaRelocationHandler


class SolanaEBPFELFAnalyzer(LoggerMixin):
    """Analyzes Solana eBPF ELF files and extracts function/relocation information.
    
    This class ports the core ELF analysis algorithms from the original
    solana-ida-signatures-factory flair-preprocessor.py.
    """
    
    def __init__(self):
        """Initialize the ELF analyzer."""
        self.relocation_handler = SolanaRelocationHandler()
        self.logger.info("Solana eBPF ELF analyzer initialized")
    
    def decode_name(self, name: str) -> str:
        """Decode function/section name by removing prefixes.
        
        Ported from flair-preprocessor.py decode_name function.
        
        Args:
            name: Raw name from ELF symbol table
            
        Returns:
            Cleaned function name
        """
        name = name.replace('.rel.text.', '')
        name = name.replace('.rel.data.rel.ro.', '')
        return name
    
    def extract_relocations_and_functions(self, elffile: ELFFile) -> Tuple[Dict[int, Dict], Dict[str, Dict]]:
        """Extract relocations and functions from ELF file.
        
        This is the core function ported from flair-preprocessor.py
        extract_relocations_and_functions().
        
        Args:
            elffile: Parsed ELF file object
            
        Returns:
            Tuple of (relocations_dict, functions_dict)
        """
        sections = list(elffile.iter_sections())
        relocations = {}
        functions = {}
        
        # Extract symbol table
        symtab_s = elffile.get_section_by_name('.symtab')
        symtab = []
        
        if symtab_s:
            for sym in symtab_s.iter_symbols():
                symtab.append({
                    'name': sym.name,
                    'val': sym.entry['st_value']
                })
        
        # Process sections
        for section in sections:
            section_name = section.name
            section_type = section.header['sh_type']
            
            # Process .text.* sections (function definitions)
            if section_type == 'SHT_PROGBITS' and section_name.startswith('.text.'):
                name = section_name[5:]  # Remove '.text.' prefix
                
                # Handle .unlikely prefix
                if name.startswith('.unlikely'):
                    name = name[9:]
                if name.startswith('.'):
                    name = name[1:]
                
                if name not in functions:
                    functions[name] = {
                        'offset': section.header['sh_offset'],
                        'func_size': section.header['sh_size'],
                        'internal': [],
                        'from_relocations': False
                    }
            
            # Process dynamic relocations (.rel.dyn)
            elif section_type == 'SHT_REL' and section_name == '.rel.dyn':
                dynsym = elffile.get_section_by_name(".dynsym")
                if not dynsym or not isinstance(dynsym, SymbolTableSection):
                    continue
                
                symbols = []
                for symbol in dynsym.iter_symbols():
                    symbols.append({
                        'name': symbol.name,
                        'val': symbol.entry['st_value']
                    })
                
                for reloc in section.iter_relocations():
                    relsym = symbols[reloc['r_info_sym']]
                    name = self.decode_name(relsym['name'])
                    
                    reloc_parsed = self.relocation_handler.parse_relocation(
                        reloc['r_info_type'],
                        reloc['r_offset'],
                        relsym['val']
                    )
                    
                    mods = [{'loc': r['loc'], 'val': r['val']} for r in reloc_parsed]
                    
                    relocation = {
                        'type': reloc['r_info_type'],
                        'name': name,
                        'mods': mods
                    }
                    
                    relocations[reloc['r_offset']] = relocation
            
            # Process other relocations (.rel.text.*, etc.)
            elif section_type == 'SHT_REL':
                if not symtab_s:
                    self.logger.error("symtab section not found")
                    continue
                
                code_s = sections[section.header['sh_info']]
                base_offset = code_s.header['sh_offset']
                section_name_decoded = self.decode_name(section_name)
                
                # Process function relocations
                if section_name.startswith('.rel.text.'):
                    func_name = section_name_decoded
                    
                    # Try to demangle function name
                    try:
                        import cxxfilt
                        func_name_demangled = cxxfilt.demangle(func_name)
                    except:
                        func_name_demangled = None
                    
                    if func_name_demangled:
                        if func_name in functions:
                            if functions[func_name]['from_relocations']:
                                continue
                        
                        functions[func_name] = {
                            'offset': base_offset,
                            'func_size': code_s.header['sh_size'],
                            'internal': [],
                            'from_relocations': True
                        }
                
                elif section_name.startswith('.rel.data.rel.ro.'):
                    continue
                
                # Parse all relocations in this section
                for reloc in section.iter_relocations():
                    relsym = symtab[reloc['r_info_sym']]
                    name = self.decode_name(relsym['name'])
                    
                    reloc_parsed = self.relocation_handler.parse_relocation(
                        reloc['r_info_type'],
                        reloc['r_offset'],
                        relsym['val']
                    )
                    
                    mods = [
                        {'loc': base_offset + r['loc'], 'val': r['val']}
                        for r in reloc_parsed
                    ]
                    
                    relocation = {
                        'type': reloc['r_info_type'],
                        'name': name,
                        'mods': mods
                    }
                    
                    relocations[base_offset + reloc['r_offset']] = relocation
                    
                    # Add internal relocation to function
                    if section_name_decoded in functions:
                        internal_relocation = {
                            'type': reloc['r_info_type'],
                            'name': name,
                            'offset': reloc['r_offset'],
                            'value': relsym['val']
                        }
                        functions[section_name_decoded]['internal'].append(internal_relocation)
        
        return relocations, functions
    
    def parse_function_internals(self, libdata: bytes, relocations: Dict[int, Dict], 
                               ea: int, name: str, size: int) -> List[Dict]:
        """Parse internal relocations for a function.
        
        Ported from flair-preprocessor.py parse_function_internals().
        
        Args:
            libdata: Raw library data bytes
            relocations: Global relocations dictionary
            ea: Function start address
            name: Function name
            size: Function size
            
        Returns:
            List of internal relocations
        """
        current_ea = ea
        internal_relocations = []
        
        while current_ea < ea + size:
            if current_ea in relocations:
                reloc = {
                    'type': relocations[current_ea]['type'],
                    'name': relocations[current_ea]['name'],
                    'offset': current_ea - ea,
                    'value': 0xFFFFFFFF  # doesn't matter according to original
                }
                internal_relocations.append(reloc)
            current_ea += 1
        
        return internal_relocations
    
    def process_rlib_file(self, rlib_path: Path) -> Tuple[Dict[int, Dict], Dict[str, Dict], bytes]:
        """Process an rlib file and extract relocations, functions, and data.
        
        Args:
            rlib_path: Path to the .rlib file
            
        Returns:
            Tuple of (relocations, functions, libdata)
        """
        self.logger.info(f"Processing rlib file: {rlib_path}")
        
        with open(rlib_path, 'rb') as f:
            archive = ar.Archive(f)
            
            # Find .o files in the archive
            for entry in archive.entries:
                if entry.name.endswith('.o'):
                    self.logger.info(f"Processing object file: {entry.name}")
                    
                    with archive.open(entry, 'rb') as obj_file:
                        libdata = obj_file.read()
                        
                        # Reset file pointer for ELF parsing
                        obj_file.seek(0)
                        elffile = ELFFile(obj_file)
                        
                        relocations, functions = self.extract_relocations_and_functions(elffile)
                        
                        return relocations, functions, libdata
        
        raise ValueError(f"No .o files found in rlib: {rlib_path}")
    
    def analyze_rlib(self, rlib_path: Path) -> Dict[str, Any]:
        """Analyze an rlib file and return comprehensive information.
        
        Args:
            rlib_path: Path to the .rlib file
            
        Returns:
            Dictionary with analysis results
        """
        try:
            relocations, functions, libdata = self.process_rlib_file(rlib_path)
            
            # Calculate statistics
            total_functions = len(functions)
            total_relocations = len(relocations)
            
            functions_with_relocations = sum(
                1 for func in functions.values() 
                if func['internal']
            )
            
            analysis_result = {
                'rlib_path': str(rlib_path),
                'rlib_size': rlib_path.stat().st_size,
                'libdata_size': len(libdata),
                'total_functions': total_functions,
                'total_relocations': total_relocations,
                'functions_with_relocations': functions_with_relocations,
                'functions': functions,
                'relocations': relocations,
                'libdata': libdata,
                'success': True,
                'error': None
            }
            
            self.logger.info(f"Analysis complete: {total_functions} functions, {total_relocations} relocations")
            return analysis_result
            
        except Exception as e:
            self.logger.error(f"Failed to analyze rlib {rlib_path}: {e}")
            return {
                'rlib_path': str(rlib_path),
                'success': False,
                'error': str(e)
            }