"""Solana system call constants and identifiers.

This module contains Solana-specific system call identifiers used in eBPF programs.
"""

from typing import Dict

# Common Solana system calls
SOLANA_SYSCALLS: Dict[str, int] = {
    # Logging syscalls
    'sol_log_': 0x01,
    'sol_log_64_': 0x02,
    'sol_log_compute_units_': 0x03,
    'sol_log_pubkey_': 0x04,
    'sol_log_slice_': 0x05,
    'sol_log_array_': 0x06,
    'sol_log_data_': 0x07,
    
    # Memory operations
    'sol_memcpy_': 0x10,
    'sol_memmove_': 0x11,
    'sol_memcmp_': 0x12,
    'sol_memset_': 0x13,
    
    # Account operations  
    'sol_create_program_address_': 0x20,
    'sol_try_find_program_address_': 0x21,
    'sol_get_processed_sibling_instruction_': 0x22,
    'sol_get_stack_height_': 0x23,
    
    # Cross-program invocation
    'sol_invoke_signed_c': 0x30,
    'sol_invoke_signed_': 0x31,
    
    # Cryptographic operations
    'sol_sha256_': 0x40,
    'sol_keccak256_': 0x41,
    'sol_secp256k1_recover_': 0x42,
    'sol_blake3_': 0x43,
    
    # Clock and slot operations
    'sol_get_clock_sysvar_': 0x50,
    'sol_get_epoch_schedule_sysvar_': 0x51,
    'sol_get_rent_sysvar_': 0x52,
    
    # Program runtime
    'sol_get_return_data_': 0x60,
    'sol_set_return_data_': 0x61,
    'sol_get_processed_sibling_instruction_': 0x62,
}

# Reverse mapping for syscall lookups
SYSCALL_ID_TO_NAME = {v: k for k, v in SOLANA_SYSCALLS.items()}

def get_syscall_name(syscall_id: int) -> str:
    """Get syscall name by ID."""
    return SYSCALL_ID_TO_NAME.get(syscall_id, f'unknown_syscall_{syscall_id}')

def is_solana_syscall(name: str) -> bool:
    """Check if a function name is a Solana syscall."""
    return name in SOLANA_SYSCALLS

def get_syscall_id(name: str) -> int:
    """Get syscall ID by name."""
    return SOLANA_SYSCALLS.get(name, -1)

__all__ = [
    "SOLANA_SYSCALLS",
    "SYSCALL_ID_TO_NAME", 
    "get_syscall_name",
    "is_solana_syscall",
    "get_syscall_id",
]