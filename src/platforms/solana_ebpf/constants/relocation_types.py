"""Solana eBPF relocation type constants.

This module contains relocation type definitions ported from 
the solana-ida-signatures-factory flair-preprocessor.py.
"""

from typing import Dict, Optional

# Relocation patch sizes (ported from flair-preprocessor.py)
REL_PATCH_SIZE: Dict[int, Optional[int]] = {
    0: None,  # R_BPF_NONE
    1: 32,    # R_BPF_64_64
    2: 64,    # R_BPF_64_ABS64  
    3: 32,    # R_BPF_64_ABS32
    4: 32,    # R_BPF_64_NODYLD32
    8: 32,    # R_BPF_64_RELATIVE (Solana specific)
    10: 32,   # R_BPF_64_32
}

# Relocation type names (ported from flair-preprocessor.py)
REL_TYPE: Dict[int, str] = {
    0: 'R_BPF_NONE',
    1: 'R_BPF_64_64',
    2: 'R_BPF_64_ABS64',
    3: 'R_BPF_64_ABS32',
    4: 'R_BPF_64_NODYLD32',
    8: 'R_BPF_64_RELATIVE',  # Solana SPEC
    10: 'R_BPF_64_32',
}

# Extended Solana relocation types
SOLANA_RELOCATION_TYPES = {
    'R_BPF_NONE': 0,
    'R_BPF_64_64': 1,
    'R_BPF_64_ABS64': 2,
    'R_BPF_64_ABS32': 3,
    'R_BPF_64_NODYLD32': 4,
    'R_BPF_64_RELATIVE': 8,   # Solana-specific extension
    'R_BPF_64_32': 10,
}

# Reverse mapping for lookups
RELOCATION_NAME_TO_ID = {v: k for k, v in REL_TYPE.items()}

def get_relocation_name(rel_id: int) -> str:
    """Get relocation type name by ID."""
    return REL_TYPE.get(rel_id, f'UNKNOWN_{rel_id}')

def get_relocation_patch_size(rel_id: int) -> Optional[int]:
    """Get patch size for relocation type."""
    return REL_PATCH_SIZE.get(rel_id)

def is_solana_specific_relocation(rel_id: int) -> bool:
    """Check if relocation type is Solana-specific."""
    return rel_id == 8  # R_BPF_64_RELATIVE

__all__ = [
    "REL_PATCH_SIZE",
    "REL_TYPE", 
    "SOLANA_RELOCATION_TYPES",
    "RELOCATION_NAME_TO_ID",
    "get_relocation_name",
    "get_relocation_patch_size",
    "is_solana_specific_relocation",
]