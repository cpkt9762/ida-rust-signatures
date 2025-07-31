"""Solana eBPF PAT file generator.

This module generates IDA FLIRT PAT files from Solana eBPF rlib files.
Core algorithms completely ported from solana-ida-signatures-factory flair-preprocessor.py.
"""

from pathlib import Path
from typing import Dict, List, Optional, Any

from ....core.config import settings
from ....core.logger import LoggerMixin
from ..constants.relocation_types import REL_TYPE
from ..extractors.ebpf_elf_analyzer import SolanaEBPFELFAnalyzer
from ..extractors.solana_relocations import SolanaRelocationHandler


class SolanaPATGenerator(LoggerMixin):
    """Generates PAT files from Solana eBPF rlib files.
    
    This class ports the complete PAT generation logic from the original
    solana-ida-signatures-factory flair-preprocessor.py.
    """
    
    def __init__(self):
        """Initialize the PAT generator."""
        self.elf_analyzer = SolanaEBPFELFAnalyzer()
        self.relocation_handler = SolanaRelocationHandler()
        
        # CRC16 table ported from flair-preprocessor.py
        self.crc16_table = [
            0x0, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf, 0x8c48, 0x9dc1,
            0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7, 0x1081, 0x108, 0x3393, 0x221a,
            0x56a5, 0x472c, 0x75b7, 0x643e, 0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64,
            0xf9ff, 0xe876, 0x2102, 0x308b, 0x210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
            0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5, 0x3183, 0x200a,
            0x1291, 0x318, 0x77a7, 0x662e, 0x54b5, 0x453c, 0xbdcb, 0xac42, 0x9ed9, 0x8f50,
            0xfbef, 0xea66, 0xd8fd, 0xc974, 0x4204, 0x538d, 0x6116, 0x709f, 0x420, 0x15a9,
            0x2732, 0x36bb, 0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
            0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x528, 0x37b3, 0x263a, 0xdecd, 0xcf44,
            0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72, 0x6306, 0x728f, 0x4014, 0x519d,
            0x2522, 0x34ab, 0x630, 0x17b9, 0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3,
            0x8a78, 0x9bf1, 0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x738,
            0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70, 0x8408, 0x9581,
            0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7, 0x840, 0x19c9, 0x2b52, 0x3adb,
            0x4e64, 0x5fed, 0x6d76, 0x7cff, 0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324,
            0xf1bf, 0xe036, 0x18c1, 0x948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
            0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5, 0x2942, 0x38cb,
            0xa50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd, 0xb58b, 0xa402, 0x9699, 0x8710,
            0xf3af, 0xe226, 0xd0bd, 0xc134, 0x39c3, 0x284a, 0x1ad1, 0xb58, 0x7fe7, 0x6e6e,
            0x5cf5, 0x4d7c, 0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
            0x4a44, 0x5bcd, 0x6956, 0x78df, 0xc60, 0x1de9, 0x2f72, 0x3efb, 0xd68d, 0xc704,
            0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232, 0x5ac5, 0x4b4c, 0x79d7, 0x685e,
            0x1ce1, 0xd68, 0x3ff3, 0x2e7a, 0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3,
            0x8238, 0x93b1, 0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0xe70, 0x1ff9,
            0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330, 0x7bc7, 0x6a4e,
            0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0xf78
        ]
        
        self.signatures_dir = settings.data_dir / "solana_ebpf" / "signatures"
        self.signatures_dir.mkdir(parents=True, exist_ok=True)
        
        self.logger.info("Solana PAT generator initialized")
    
    def crc16(self, data: bytes, crc: int = 0xFFFF) -> int:
        """Calculate CRC16 checksum.
        
        Ported directly from flair-preprocessor.py crc16() function.
        
        Args:
            data: Data bytes to calculate CRC for
            crc: Initial CRC value
            
        Returns:
            16-bit CRC checksum
        """
        for byte in data:
            crc = (crc >> 8) ^ self.crc16_table[(crc ^ byte) & 0xFF]
        crc = (~crc) & 0xFFFF
        crc = (crc << 8) | ((crc >> 8) & 0xFF)
        return crc & 0xFFFF
    
    def process_function(self, libdata: bytes, relocations: Dict[int, Dict], 
                        fname: str, fdata: Dict) -> Optional[str]:
        """Process a single function and generate its PAT entry.
        
        This function is ported directly from flair-preprocessor.py process_function().
        
        Args:
            libdata: Raw library data bytes
            relocations: Global relocations dictionary
            fname: Function name
            fdata: Function data dictionary
            
        Returns:
            PAT entry string or None if function should be skipped
        """
        self.logger.debug(f"Processing function: {fname}, size: {fdata['func_size']}")
        
        fbytes = libdata[fdata['offset'] : fdata['offset'] + fdata['func_size']]
        
        # Skip functions that are too long or too short
        if len(fbytes) >= 0x8000:
            self.logger.debug(f"Skipping {fname}: too long ({len(fbytes)} bytes)")
            return None
        
        if len(fbytes) < 35:
            self.logger.debug(f"Skipping {fname}: too short ({len(fbytes)} bytes)")
            return None
        
        # Parse internal relocations if not from relocation sections
        if not fdata['from_relocations']:
            fdata['internal'] = self.elf_analyzer.parse_function_internals(
                libdata, relocations, fdata['offset'], fname, fdata['func_size']
            )
        
        fhex = fbytes.hex().upper()
        internal_names = {}
        
        # Process relocations and generate internal function names list
        for reloc in fdata['internal']:
            mods = self.relocation_handler.parse_relocation(
                reloc['type'], reloc['offset'], reloc['value']
            )
            
            # Replace bytes with '..' for variable locations
            for mod in mods:
                size = int(mod['size'] / 8) if mod['size'] else 0
                if size > 0:
                    start_pos = mod['loc'] * 2
                    end_pos = (mod['loc'] + size) * 2
                    if start_pos < len(fhex) and end_pos <= len(fhex):
                        fhex = fhex[:start_pos] + '..' * size + fhex[end_pos:]
            
            # Store internal reference names
            rel_type_name = REL_TYPE.get(reloc['type'], f'UNKNOWN_{reloc["type"]}')
            
            if rel_type_name == 'R_BPF_64_32':
                if mods:
                    loc_hex = hex(mods[0]['loc'])[2:].upper().zfill(4)
                    internal_names[loc_hex] = reloc['name']
                    
            elif rel_type_name == 'R_BPF_64_64':
                if mods:
                    loc_hex = hex(mods[0]['loc'])[2:].upper().zfill(4)
                    internal_names[loc_hex] = reloc['name']
                    
            elif rel_type_name == 'R_BPF_64_RELATIVE':
                if mods and reloc['name']:
                    loc_hex = hex(mods[0]['loc'])[2:].upper().zfill(4)
                    internal_names[loc_hex] = reloc['name']
        
        # Replace remaining unrelocated calls (ported from original)
        fhex = fhex.replace('85100000FFFFFFFF', '85100000' + '..' * 4)
        
        # Generate pattern data (first 64 hex chars)
        pat_data = fhex[:64]
        
        # Calculate alen (additional length for CRC)
        alen = 255 if len(fhex) - 64 > 255 * 2 else (len(fhex) - 64 - 2) // 2
        if '..' in fhex[64:64+alen*2]:
            alen = (fhex.index('..', 64) - 64) // 2
        
        if alen <= 2:
            self.logger.debug(f"Skipping {fname}: too short alen ({alen})")
            return None
        
        # Calculate CRC16 of the additional data
        try:
            additional_data = int(fhex[64:64+alen*2], 16).to_bytes(alen, byteorder='big')
            crc = hex(self.crc16(additional_data))[2:].upper().zfill(4)
        except ValueError as e:
            self.logger.error(f"Failed to calculate CRC for {fname}: {e}")
            return None
        
        # Format function length
        func_len = hex(fdata['func_size'])[2:].upper().zfill(4)
        
        # Build PAT entry
        pat_data += f" {hex(alen)[2:].upper().zfill(2)} {crc} {func_len} :0000 {fname}"
        
        # Add internal references
        for ioff in internal_names:
            pat_data += f" ^{ioff} {internal_names[ioff]}"
        
        # Add remaining tail data
        pat_data += f" {fhex[64+alen*2:]}"
        
        return pat_data
    
    def generate_pat_from_rlib(self, rlib_path: Path, 
                              output_path: Optional[Path] = None) -> Path:
        """Generate PAT file from an rlib file.
        
        Args:
            rlib_path: Path to the rlib file
            output_path: Optional output path for PAT file
            
        Returns:
            Path to generated PAT file
        """
        self.logger.info(f"Generating PAT from rlib: {rlib_path}")
        
        # Analyze rlib file
        analysis = self.elf_analyzer.analyze_rlib(rlib_path)
        if not analysis['success']:
            raise ValueError(f"Failed to analyze rlib: {analysis['error']}")
        
        relocations = analysis['relocations']
        functions = analysis['functions']
        libdata = analysis['libdata']
        
        # Process each function
        pat_funcs = []
        for fname, fdata in functions.items():
            pat_data = self.process_function(libdata, relocations, fname, fdata)
            if pat_data is not None:
                pat_funcs.append(pat_data)
        
        # Generate output path if not provided
        if output_path is None:
            pat_dir = self.signatures_dir / "pat"
            pat_dir.mkdir(parents=True, exist_ok=True)
            # Use configuration-compliant naming format temporarily (will be renamed to standard format later)
            output_path = pat_dir / f"{rlib_path.stem}_ebpf.pat"
        
        # Write PAT file
        pat_content = '\n'.join(pat_funcs) + '\n---\n'
        output_path.write_text(pat_content)
        
        self.logger.info(f"Generated PAT file: {output_path} ({len(pat_funcs)} functions)")
        return output_path
    
    def generate_pat_for_solana_program(self, version: str = "1.18.16") -> Path:
        """Generate PAT file for solana-program test case.
        
        Args:
            version: solana-program version
            
        Returns:
            Path to generated PAT file
        """
        # Find the compiled rlib
        rlib_dir = settings.data_dir / "solana_ebpf" / "rlibs" / "solana-program"
        rlib_pattern = f"*{version}.rlib"
        
        rlib_files = list(rlib_dir.glob(rlib_pattern))
        if not rlib_files:
            raise FileNotFoundError(f"No rlib found for solana-program {version} in {rlib_dir}")
        
        rlib_path = rlib_files[0]
        
        # Generate PAT file
        pat_path = self.generate_pat_from_rlib(rlib_path)
        
        # Rename to configuration-compliant format: {library_name}_{version}_{platform}.{extension}
        standard_name = f"solana_program_{version}_ebpf.pat"
        standard_path = pat_path.parent / standard_name
        if pat_path != standard_path:
            pat_path.rename(standard_path)
            pat_path = standard_path
        
        return pat_path
    
    def validate_pat_file(self, pat_path: Path) -> Dict[str, Any]:
        """Validate a generated PAT file.
        
        Args:
            pat_path: Path to PAT file
            
        Returns:
            Dictionary with validation results
        """
        if not pat_path.exists():
            return {'valid': False, 'error': 'File does not exist'}
        
        try:
            content = pat_path.read_text()
            lines = content.strip().split('\n')
            
            # Count functions (lines before '---')
            function_count = 0
            for line in lines:
                if line.strip() == '---':
                    break
                if line.strip():
                    function_count += 1
            
            # Basic format validation
            valid_format = content.endswith('---\n') or content.endswith('---')
            
            # Check for basic PAT structure in first few lines
            has_valid_entries = False
            for line in lines[:5]:
                if line.strip() and ':0000' in line:
                    has_valid_entries = True
                    break
            
            return {
                'valid': valid_format and has_valid_entries and function_count > 0,
                'function_count': function_count,
                'file_size': pat_path.stat().st_size,
                'has_terminator': '---' in content,
                'has_valid_entries': has_valid_entries,
            }
            
        except Exception as e:
            return {'valid': False, 'error': str(e)}
    
    def get_pat_statistics(self, pat_path: Path) -> Dict[str, Any]:
        """Get detailed statistics about a PAT file.
        
        Args:
            pat_path: Path to PAT file
            
        Returns:
            Dictionary with PAT file statistics
        """
        validation = self.validate_pat_file(pat_path)
        if not validation['valid']:
            return validation
        
        content = pat_path.read_text()
        lines = [line.strip() for line in content.split('\n') if line.strip() and line.strip() != '---']
        
        stats = {
            'total_functions': len(lines),
            'avg_pattern_length': 0,
            'functions_with_internals': 0,
            'total_internal_refs': 0,
            'pattern_lengths': [],
        }
        
        for line in lines:
            parts = line.split(' ')
            if len(parts) >= 1:
                pattern_len = len(parts[0])
                stats['pattern_lengths'].append(pattern_len)
                
                # Count internal references (marked with ^)
                internal_refs = sum(1 for part in parts if part.startswith('^'))
                if internal_refs > 0:
                    stats['functions_with_internals'] += 1
                    stats['total_internal_refs'] += internal_refs
        
        if stats['pattern_lengths']:
            stats['avg_pattern_length'] = sum(stats['pattern_lengths']) / len(stats['pattern_lengths'])
            stats['min_pattern_length'] = min(stats['pattern_lengths'])
            stats['max_pattern_length'] = max(stats['pattern_lengths'])
        
        return stats