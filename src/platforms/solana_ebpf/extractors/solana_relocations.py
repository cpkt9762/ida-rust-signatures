"""Solana eBPF relocation handler.

This module handles Solana-specific relocation types and processing.
Core logic ported from solana-ida-signatures-factory flair-preprocessor.py.
"""

from typing import Dict, List

from ....core.logger import LoggerMixin
from ..constants.relocation_types import REL_PATCH_SIZE, REL_TYPE


class SolanaRelocationHandler(LoggerMixin):
    """Handles Solana eBPF relocation processing.
    
    This class ports the relocation handling logic from the original
    solana-ida-signatures-factory flair-preprocessor.py.
    """
    
    def __init__(self):
        """Initialize the relocation handler."""
        self.logger.info("Solana relocation handler initialized")
    
    def parse_relocation(self, rel_type: int, loc: int, val: int) -> List[Dict[str, int]]:
        """Parse a relocation entry and return modification instructions.
        
        This function is ported directly from flair-preprocessor.py parse_relocation().
        
        Args:
            rel_type: Relocation type ID
            loc: Location/offset of relocation
            val: Value to be relocated
            
        Returns:
            List of dictionaries with 'size', 'loc', 'val' keys
        """
        type_name = REL_TYPE.get(rel_type, f'UNKNOWN_{rel_type}')
        changes = []
        
        if type_name == 'R_BPF_64_64':
            # Split 64-bit value into two 32-bit parts
            changes.append({
                'size': REL_PATCH_SIZE[rel_type],
                'loc': loc + 4,
                'val': val & 0xFFFFFFFF
            })
            changes.append({
                'size': REL_PATCH_SIZE[rel_type],
                'loc': loc + 8 + 4,
                'val': val >> 32
            })
            
        elif type_name == 'R_BPF_64_ABS64':
            changes.append({
                'size': REL_PATCH_SIZE[rel_type],
                'loc': loc,
                'val': val
            })
            
        elif type_name == 'R_BPF_64_ABS32':
            # No changes for this type according to original
            pass
            
        elif type_name == 'R_BPF_64_NODYLD32':
            changes.append({
                'size': REL_PATCH_SIZE[rel_type],
                'loc': loc,
                'val': val & 0xFFFFFFFF
            })
            
        elif type_name == 'R_BPF_64_32':
            changes.append({
                'size': REL_PATCH_SIZE[rel_type],
                'loc': loc + 4,
                'val': val & 0xFFFFFFFF
            })
            
        elif type_name == 'R_BPF_64_RELATIVE':
            # Solana-specific relocation type
            changes.append({
                'size': REL_PATCH_SIZE[rel_type],
                'loc': loc + 4,
                'val': val & 0xFFFFFFFF
            })
            
        else:
            self.logger.warning(f'Unknown relocation type: {type_name} (id: {rel_type})')
        
        return changes
    
    def get_relocation_info(self, rel_type: int) -> Dict[str, any]:
        """Get comprehensive information about a relocation type.
        
        Args:
            rel_type: Relocation type ID
            
        Returns:
            Dictionary with relocation information
        """
        type_name = REL_TYPE.get(rel_type, f'UNKNOWN_{rel_type}')
        patch_size = REL_PATCH_SIZE.get(rel_type)
        
        return {
            'id': rel_type,
            'name': type_name,
            'patch_size': patch_size,
            'is_solana_specific': rel_type == 8,  # R_BPF_64_RELATIVE
            'is_supported': rel_type in REL_TYPE,
        }
    
    def is_function_call_relocation(self, rel_type: int) -> bool:
        """Check if relocation type typically indicates a function call.
        
        Args:
            rel_type: Relocation type ID
            
        Returns:
            True if this relocation type is typically used for function calls
        """
        # Based on Solana eBPF calling conventions
        return rel_type in [1, 8, 10]  # R_BPF_64_64, R_BPF_64_RELATIVE, R_BPF_64_32
    
    def calculate_relocation_impact(self, relocations: Dict[int, Dict]) -> Dict[str, int]:
        """Calculate statistics about relocations in a function/object.
        
        Args:
            relocations: Dictionary of relocations by offset
            
        Returns:
            Dictionary with relocation statistics
        """
        stats = {
            'total_relocations': len(relocations),
            'relocation_types': {},
            'function_calls': 0,
            'data_references': 0,
        }
        
        for reloc in relocations.values():
            rel_type = reloc['type']
            type_name = REL_TYPE.get(rel_type, f'UNKNOWN_{rel_type}')
            
            # Count by type
            if type_name not in stats['relocation_types']:
                stats['relocation_types'][type_name] = 0
            stats['relocation_types'][type_name] += 1
            
            # Classify relocation purpose
            if self.is_function_call_relocation(rel_type):
                stats['function_calls'] += 1
            else:
                stats['data_references'] += 1
        
        return stats