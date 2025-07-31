"""eBPF instruction set constants.

This module contains eBPF opcode definitions and instruction classification
ported from the solana-ida-signatures-factory project.
"""

from typing import List

# Source modifiers
BPF_K = 0x00  # BPF source operand modifier: 32-bit immediate value
BPF_X = 0x08  # BPF source operand modifier: src register

# Instruction classes
BPF_LD = 0x00      # Load operations
BPF_LDX = 0x01     # Load from memory
BPF_ST = 0x02      # Store immediate
BPF_STX = 0x03     # Store from register
BPF_ALU = 0x04     # 32-bit ALU operations
BPF_JMP = 0x05     # Jump operations
BPF_ALU64 = 0x07   # 64-bit ALU operations

# Jump operation codes
BPF_JA = 0x00      # jump
BPF_JEQ = 0x10     # jump if equal
BPF_JGT = 0x20     # jump if greater than
BPF_JGE = 0x30     # jump if greater or equal
BPF_JSET = 0x40    # jump if src & reg
BPF_JNE = 0x50     # jump if not equal
BPF_JSGT = 0x60    # jump if greater than (signed)
BPF_JSGE = 0x70    # jump if greater or equal (signed)
BPF_CALL = 0x80    # syscall function call
BPF_EXIT = 0x90    # return from program
BPF_JLT = 0xa0     # jump if lower than
BPF_JLE = 0xb0     # jump if lower or equal
BPF_JSLT = 0xc0    # jump if lower than (signed)
BPF_JSLE = 0xd0    # jump if lower or equal (signed)

# Combined instruction constants
BPF_INSTRUCTION_CLASSES = {
    'BPF_LD': BPF_LD,
    'BPF_LDX': BPF_LDX,
    'BPF_ST': BPF_ST,
    'BPF_STX': BPF_STX,
    'BPF_ALU': BPF_ALU,
    'BPF_JMP': BPF_JMP,
    'BPF_ALU64': BPF_ALU64,
}

# Branch instructions (ported from flair-preprocessor.py)
BRANCH_INSTRUCTIONS: List[int] = [
    BPF_JMP | BPF_JA,
    BPF_JMP | BPF_K | BPF_JEQ,
    BPF_JMP | BPF_X | BPF_JEQ,
    BPF_JMP | BPF_K | BPF_JGT,
    BPF_JMP | BPF_X | BPF_JGT,
    BPF_JMP | BPF_K | BPF_JGE,
    BPF_JMP | BPF_X | BPF_JGE,
    BPF_JMP | BPF_K | BPF_JLT,
    BPF_JMP | BPF_X | BPF_JLT,
    BPF_JMP | BPF_K | BPF_JLE,
    BPF_JMP | BPF_X | BPF_JLE,
    BPF_JMP | BPF_K | BPF_JSET,
    BPF_JMP | BPF_X | BPF_JSET,
    BPF_JMP | BPF_K | BPF_JNE,
    BPF_JMP | BPF_X | BPF_JNE,
    BPF_JMP | BPF_K | BPF_JSGT,
    BPF_JMP | BPF_X | BPF_JSGT,
    BPF_JMP | BPF_K | BPF_JSGE,
    BPF_JMP | BPF_X | BPF_JSGE,
    BPF_JMP | BPF_K | BPF_JSLT,
    BPF_JMP | BPF_X | BPF_JSLT,
    BPF_JMP | BPF_K | BPF_JSLE,
    BPF_JMP | BPF_X | BPF_JSLE,
]

# Special instruction constants
CALL_INSTRUCTION = BPF_JMP | BPF_CALL
CALLX_INSTRUCTION = BPF_JMP | BPF_X | BPF_CALL  
EXIT_INSTRUCTION = BPF_JMP | BPF_EXIT

__all__ = [
    "BPF_K", "BPF_X",
    "BPF_LD", "BPF_LDX", "BPF_ST", "BPF_STX", "BPF_ALU", "BPF_JMP", "BPF_ALU64",
    "BPF_JA", "BPF_JEQ", "BPF_JGT", "BPF_JGE", "BPF_JSET", "BPF_JNE",
    "BPF_JSGT", "BPF_JSGE", "BPF_CALL", "BPF_EXIT", "BPF_JLT", "BPF_JLE",
    "BPF_JSLT", "BPF_JSLE",
    "BPF_INSTRUCTION_CLASSES",
    "BRANCH_INSTRUCTIONS",
    "CALL_INSTRUCTION", "CALLX_INSTRUCTION", "EXIT_INSTRUCTION",
]