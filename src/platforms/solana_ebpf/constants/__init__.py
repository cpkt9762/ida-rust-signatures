"""Constants and definitions for Solana eBPF processing."""

from .ebpf_opcodes import *
from .relocation_types import *
from .solana_syscalls import *

__all__ = [
    # eBPF opcodes
    "BPF_INSTRUCTION_CLASSES",
    "BRANCH_INSTRUCTIONS", 
    "CALL_INSTRUCTION",
    "CALLX_INSTRUCTION",
    "EXIT_INSTRUCTION",
    
    # Relocation types
    "REL_PATCH_SIZE",
    "REL_TYPE",
    "SOLANA_RELOCATION_TYPES",
    
    # Solana syscalls
    "SOLANA_SYSCALLS",
]