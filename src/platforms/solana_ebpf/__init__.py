"""Solana eBPF platform module.

This module provides specialized support for generating IDA FLIRT signatures
from Solana eBPF programs compiled from Rust crates.

Key features:
- Solana toolchain management (cargo-build-sbf)
- eBPF ELF file analysis and function extraction
- Solana-specific relocation handling
- PAT file generation using ported algorithms from solana-ida-signatures-factory
- Version management and signature merging
"""

from .builders.solana_toolchain import SolanaToolchainManager
from .builders.crate_compiler import SolanaProgramCompiler
from .extractors.ebpf_elf_analyzer import SolanaEBPFELFAnalyzer
from .generators.solana_pat_generator import SolanaPATGenerator

__version__ = "0.1.0"
__all__ = [
    "SolanaToolchainManager",
    "SolanaProgramCompiler", 
    "SolanaEBPFELFAnalyzer",
    "SolanaPATGenerator",
]