"""eBPF instruction analyzer and function extractor.

This module provides eBPF instruction set analysis and function boundary detection.
Core algorithms ported from solana-ida-signatures-factory flair-preprocessor.py.
"""

from typing import List, Tuple, Optional, Dict, Any

from ....core.logger import LoggerMixin
from ..constants.ebpf_opcodes import (
    BRANCH_INSTRUCTIONS, CALL_INSTRUCTION, CALLX_INSTRUCTION, EXIT_INSTRUCTION
)


class EBPFInstructionAnalyzer(LoggerMixin):
    """Analyzes eBPF instructions and detects function boundaries.
    
    This class ports the eBPF instruction analysis logic from the original
    solana-ida-signatures-factory flair-preprocessor.py.
    """
    
    def __init__(self):
        """Initialize the instruction analyzer."""
        self.logger.info("eBPF instruction analyzer initialized")
    
    def resolve_jmp_addr(self, ea: int, ins_bytes: bytes) -> int:
        """Resolve jump target address.
        
        Ported from flair-preprocessor.py resolve_jmp_addr().
        
        Args:
            ea: Current instruction address
            ins_bytes: Instruction bytes (8 bytes for eBPF)
            
        Returns:
            Target address of the jump
        """
        # Extract offset from bytes 2-4 (signed 16-bit)
        offset = int.from_bytes(ins_bytes[2:4], byteorder='little', signed=True)
        addr = 8 * offset + ea + 8
        return addr
    
    def resolve_call_addr(self, ea: int, ins_bytes: bytes) -> Optional[int]:
        """Resolve call target address.
        
        Ported from flair-preprocessor.py resolve_call_addr().
        
        Args:
            ea: Current instruction address  
            ins_bytes: Instruction bytes (8 bytes for eBPF)
            
        Returns:
            Target address of the call, or None if indirect/unknown
        """
        registers = ins_bytes[1]
        src = (registers >> 4) & 15
        dst = registers & 15
        
        # Extract immediate value from bytes 4-8
        imm = int.from_bytes(ins_bytes[4:8], byteorder='little')
        
        if imm == 0xFFFFFFFF:
            return None
        
        if src == 0:
            # Direct call
            return 8 * imm
        elif src == 1:
            # PC-relative call
            return 8 * imm + ea + 8
        else:
            # Register-based call (indirect)
            return None
    
    def resolve_callx_addr(self, ea: int, ins_bytes: bytes) -> Optional[int]:
        """Resolve indirect call address.
        
        Ported from flair-preprocessor.py resolve_callx_addr().
        
        Args:
            ea: Current instruction address
            ins_bytes: Instruction bytes
            
        Returns:
            Always None since address is in register
        """
        return None  # Address is in the register, cannot be resolved statically
    
    def find_function_max_end(self, libdata: bytes, ea: int, 
                            checked_ea: List[int], max_end: int) -> Tuple[List[int], int]:
        """Find the maximum end address of a function by following control flow.
        
        Ported from flair-preprocessor.py find_function_max_end().
        
        Args:
            libdata: Raw library data bytes
            ea: Current address to analyze
            checked_ea: List of already checked addresses (to avoid cycles)
            max_end: Current maximum end address
            
        Returns:
            Tuple of (updated_checked_ea_list, updated_max_end)
        """
        while True:
            if ea in checked_ea:
                return checked_ea, max_end
            
            checked_ea.append(ea)
            
            if ea >= max_end:
                return checked_ea, max_end
            
            # Ensure we don't read beyond data bounds
            if ea + 8 > len(libdata):
                return checked_ea, max_end
            
            opcode = libdata[ea]
            
            if opcode in BRANCH_INSTRUCTIONS:
                # Follow jump
                ins_bytes = libdata[ea:ea+8]
                jump_addr = self.resolve_jmp_addr(ea, ins_bytes)
                if jump_addr is not None and 0 <= jump_addr < len(libdata):
                    checked_ea, max_end = self.find_function_max_end(
                        libdata, jump_addr, checked_ea, max_end
                    )
                    
            elif opcode == EXIT_INSTRUCTION:
                # Function ends here
                return checked_ea, max_end
            
            ea += 8  # eBPF instructions are 8 bytes
    
    def find_function_len(self, elffile, libdata: bytes, ea: int) -> int:
        """Find the length of a function starting at given address.
        
        Ported from flair-preprocessor.py find_function_len().
        
        Args:
            elffile: ELF file object (for section information)
            libdata: Raw library data bytes
            ea: Function start address
            
        Returns:
            Function length in bytes, or -1 if invalid
        """
        # Check if the address is in an executable section
        found = False
        for section in elffile.iter_sections():
            if section.header['sh_flags'] & 0x4:  # SHF_EXECINSTR flag
                section_start = section.header['sh_addr']
                section_end = section_start + section.header['sh_size']
                
                if section_start <= ea < section_end:
                    found = True
                    break
        
        if not found:
            return -1
        
        checked_ea, end = self.find_function_max_end(libdata, ea, [], -1)
        if end == -1:
            return -1
        
        return end - ea
    
    def analyze_instruction(self, ins_bytes: bytes) -> Dict[str, any]:
        """Analyze a single eBPF instruction.
        
        Args:
            ins_bytes: 8 bytes of instruction data
            
        Returns:
            Dictionary with instruction analysis
        """
        if len(ins_bytes) < 8:
            return {'valid': False, 'error': 'Insufficient bytes'}
        
        opcode = ins_bytes[0]
        registers = ins_bytes[1]
        src = (registers >> 4) & 15
        dst = registers & 15
        offset = int.from_bytes(ins_bytes[2:4], byteorder='little', signed=True)
        imm = int.from_bytes(ins_bytes[4:8], byteorder='little')
        
        analysis = {
            'valid': True,
            'opcode': opcode,
            'src_reg': src,
            'dst_reg': dst,
            'offset': offset,
            'immediate': imm,
            'is_branch': opcode in BRANCH_INSTRUCTIONS,
            'is_call': opcode == CALL_INSTRUCTION,
            'is_callx': opcode == CALLX_INSTRUCTION,
            'is_exit': opcode == EXIT_INSTRUCTION,
        }
        
        # Classify instruction type
        if analysis['is_branch']:
            analysis['type'] = 'branch'
        elif analysis['is_call'] or analysis['is_callx']:
            analysis['type'] = 'call'
        elif analysis['is_exit']:
            analysis['type'] = 'exit'
        else:
            # Determine by opcode class
            opcode_class = opcode & 0x07
            if opcode_class == 0x00:
                analysis['type'] = 'load'
            elif opcode_class == 0x01:
                analysis['type'] = 'load_reg'
            elif opcode_class == 0x02:
                analysis['type'] = 'store'
            elif opcode_class == 0x03:
                analysis['type'] = 'store_reg'
            elif opcode_class == 0x04:
                analysis['type'] = 'alu32'
            elif opcode_class == 0x07:
                analysis['type'] = 'alu64'
            else:
                analysis['type'] = 'unknown'
        
        return analysis
    
    def disassemble_function(self, libdata: bytes, start_addr: int, 
                           func_size: int) -> List[Dict[str, any]]:
        """Disassemble a function into individual instructions.
        
        Args:
            libdata: Raw library data bytes
            start_addr: Function start address
            func_size: Function size in bytes
            
        Returns:
            List of instruction analysis dictionaries
        """
        instructions = []
        addr = start_addr
        end_addr = start_addr + func_size
        
        while addr < end_addr and addr + 8 <= len(libdata):
            ins_bytes = libdata[addr:addr+8]
            analysis = self.analyze_instruction(ins_bytes)
            analysis['address'] = addr
            analysis['bytes'] = ins_bytes.hex().upper()
            
            instructions.append(analysis)
            
            # Stop at exit instruction
            if analysis.get('is_exit', False):
                break
            
            addr += 8
        
        return instructions
    
    def get_function_call_targets(self, libdata: bytes, start_addr: int, 
                                func_size: int) -> List[int]:
        """Get all call target addresses in a function.
        
        Args:
            libdata: Raw library data bytes
            start_addr: Function start address
            func_size: Function size in bytes
            
        Returns:
            List of call target addresses
        """
        call_targets = []
        instructions = self.disassemble_function(libdata, start_addr, func_size)
        
        for inst in instructions:
            if inst.get('is_call', False):
                addr = start_addr + (inst['address'] - start_addr)
                ins_bytes = bytes.fromhex(inst['bytes'])
                target = self.resolve_call_addr(addr, ins_bytes)
                if target is not None:
                    call_targets.append(target)
        
        return call_targets
    
    def analyze_function_complexity(self, libdata: bytes, start_addr: int, 
                                  func_size: int) -> Dict[str, int]:
        """Analyze the complexity metrics of a function.
        
        Args:
            libdata: Raw library data bytes
            start_addr: Function start address
            func_size: Function size in bytes
            
        Returns:
            Dictionary with complexity metrics
        """
        instructions = self.disassemble_function(libdata, start_addr, func_size)
        
        metrics = {
            'instruction_count': len(instructions),
            'branch_count': 0,
            'call_count': 0,
            'load_count': 0,
            'store_count': 0,
            'alu_count': 0,
            'unique_registers_used': set(),
        }
        
        for inst in instructions:
            if inst.get('is_branch', False):
                metrics['branch_count'] += 1
            elif inst.get('is_call', False) or inst.get('is_callx', False):
                metrics['call_count'] += 1
            elif inst.get('type', '').startswith('load'):
                metrics['load_count'] += 1
            elif inst.get('type', '').startswith('store'):
                metrics['store_count'] += 1
            elif inst.get('type', '').startswith('alu'):
                metrics['alu_count'] += 1
            
            # Track register usage
            if 'src_reg' in inst:
                metrics['unique_registers_used'].add(inst['src_reg'])
            if 'dst_reg' in inst:
                metrics['unique_registers_used'].add(inst['dst_reg'])
        
        metrics['unique_registers_count'] = len(metrics['unique_registers_used'])
        del metrics['unique_registers_used']  # Remove set from return value
        
        return metrics