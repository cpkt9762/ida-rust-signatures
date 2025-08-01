"""Rust standard library components compiler for Solana eBPF targets.

This module provides functionality to compile individual Rust standard library
components (core, std, alloc) to eBPF format using the Solana toolchain.
"""

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set

from ....core.config import settings
from ....core.exceptions import SignatureError, BuildError
from ....core.logger import LoggerMixin
from ....core.naming_utils import get_rlib_filename
from .solana_toolchain import SolanaToolchainManager


class RustStdLibraryCompiler(LoggerMixin):
    """Compiles Rust standard library components to Solana eBPF rlib format."""
    
    # Supported Rust standard library components
    SUPPORTED_COMPONENTS = {
        "core": {
            "description": "Rust Core Library - no_std fundamentals",
            "crate_type": "rlib",
            "no_std": True,
            "dependencies": []
        },
        "alloc": {
            "description": "Rust Allocation Library - heap allocation",
            "crate_type": "rlib", 
            "no_std": True,
            "dependencies": ["core"]
        },
        "std": {
            "description": "Rust Standard Library - full standard library",
            "crate_type": "rlib",
            "no_std": False,
            "dependencies": ["core", "alloc"]
        }
    }
    
    def __init__(self, toolchain_manager: Optional[SolanaToolchainManager] = None):
        """Initialize the Rust standard library compiler.
        
        Args:
            toolchain_manager: Solana toolchain manager instance
        """
        self.toolchain_manager = toolchain_manager or SolanaToolchainManager()
        self.stdlib_crates_dir = settings.data_dir / "solana_ebpf" / "stdlib_crates"
        self.rlibs_dir = settings.data_dir / "solana_ebpf" / "rlibs"
        
        # Create directories
        self.stdlib_crates_dir.mkdir(parents=True, exist_ok=True)
        self.rlibs_dir.mkdir(parents=True, exist_ok=True)
        
        # Target architecture for Solana eBPF
        self.target_arch = "sbf-solana-solana"
        
        self.logger.info(f"Rust stdlib compiler initialized with dir: {self.stdlib_crates_dir}")
    
    def get_rust_toolchain_info(self, solana_version: str) -> Dict[str, str]:
        """Get Rust toolchain information for a Solana version.
        
        Args:
            solana_version: Solana version (e.g., "1.18.16")
            
        Returns:
            Dictionary with Rust toolchain information
        """
        # Version mapping based on configuration
        version_mapping = {
            "1.18.16": {"rust_version": "1.75.0", "channel": "stable"},
            "1.18.26": {"rust_version": "1.75.0", "channel": "stable"},  
            "2.1.21": {"rust_version": "1.79.0", "channel": "stable"}
        }
        
        if solana_version not in version_mapping:
            raise BuildError(f"Unsupported Solana version: {solana_version}")
        
        return version_mapping[solana_version]
    
    def create_stdlib_project(self, component: str, rust_version: str, solana_version: str) -> Path:
        """Create a Rust project for compiling a standard library component.
        
        Args:
            component: Component name ("core", "std", "alloc")
            rust_version: Rust version (e.g., "1.75.0")
            solana_version: Solana version for toolchain compatibility
            
        Returns:
            Path to created project directory
            
        Raises:
            BuildError: If component is not supported
        """
        if component not in self.SUPPORTED_COMPONENTS:
            raise BuildError(
                f"Unsupported component: {component}",
                f"Supported components: {list(self.SUPPORTED_COMPONENTS.keys())}"
            )
        
        comp_info = self.SUPPORTED_COMPONENTS[component]
        project_name = f"rust_{component}_{rust_version}_{solana_version}"
        project_dir = self.stdlib_crates_dir / project_name
        
        # Remove existing project
        if project_dir.exists():
            shutil.rmtree(project_dir)
        
        project_dir.mkdir(parents=True)
        
        # Generate Cargo.toml
        self._create_cargo_toml(project_dir, component, comp_info, rust_version)
        
        # Generate lib.rs
        self._create_lib_rs(project_dir, component, comp_info)
        
        self.logger.info(f"Created stdlib project: {project_dir}")
        return project_dir
    
    def _create_cargo_toml(self, project_dir: Path, component: str, comp_info: Dict, rust_version: str):
        """Create Cargo.toml for a standard library component project.
        
        Args:
            project_dir: Project directory path
            component: Component name
            comp_info: Component information dictionary
            rust_version: Rust version
        """
        package_name = f"rust_{component}_{rust_version.replace('.', '_')}"
        
        cargo_toml_content = f'''[package]
name = "{package_name}"
version = "{rust_version}"
edition = "2021"
description = "{comp_info['description']}"

[lib]
crate-type = ["{comp_info['crate_type']}"]
name = "{component}"

[profile.release]
debug = true
debug-assertions = false  
overflow-checks = true
lto = false
panic = "abort"
codegen-units = 1
opt-level = 2

[profile.dev]
debug = true
debug-assertions = true
overflow-checks = true
panic = "abort"
'''
        
        # Add no_std attribute if needed
        if comp_info["no_std"]:
            cargo_toml_content += f'''
# Force no_std compilation for eBPF compatibility
[profile.release.package."{package_name}"]
overflow-checks = true
'''
        
        cargo_toml_path = project_dir / "Cargo.toml"
        cargo_toml_path.write_text(cargo_toml_content)
    
    def _create_lib_rs(self, project_dir: Path, component: str, comp_info: Dict):
        """Create lib.rs for a standard library component.
        
        Args:
            project_dir: Project directory path  
            component: Component name
            comp_info: Component information dictionary
        """
        src_dir = project_dir / "src"
        src_dir.mkdir(exist_ok=True)
        
        # Generate lib.rs content based on component
        if component == "core":
            lib_content = '''#![no_std]
#![no_main]

// Re-export core library for eBPF compilation
pub use core::*;

// Solana eBPF specific exports
#[cfg(target_arch = "bpf")]
pub mod ebpf {
    pub use core::{mem, ptr, slice, str};
    pub use core::{fmt, ops, cmp, hash};
    pub use core::{iter, option, result, convert};
}
'''
        elif component == "alloc":
            lib_content = '''#![no_std]
#![no_main]

extern crate alloc;

// Re-export alloc library for eBPF compilation  
pub use alloc::*;

// Solana eBPF specific exports
#[cfg(target_arch = "bpf")]
pub mod ebpf {
    pub use alloc::{vec, string, collections};
    pub use alloc::{boxed, rc, sync};
    pub use alloc::borrow::{Cow, ToOwned};
}
'''
        elif component == "std":
            lib_content = '''#![allow(unused_imports)]

// Re-export std library components compatible with eBPF
pub use std::{
    collections, fmt, hash, mem, ptr, slice, str,
    ops, cmp, convert, iter, option, result,
    borrow, clone, default, marker,
};

// eBPF-compatible std modules
#[cfg(target_arch = "bpf")]
pub mod ebpf {
    pub use std::collections::{HashMap, BTreeMap, BTreeSet};
    pub use std::string::{String, ToString};
    pub use std::vec::Vec;
}

// Solana program compatibility
pub mod solana_compat {
    pub use std::collections::*;
    pub use std::fmt::{Debug, Display};
    pub use std::hash::{Hash, Hasher};
}
'''
        else:
            lib_content = f'// Placeholder for {component} component\n'
        
        lib_rs_path = src_dir / "lib.rs"
        lib_rs_path.write_text(lib_content)
    
    def compile_stdlib_component(self, component: str, rust_version: str, 
                                 solana_version: str, cleanup: bool = True) -> Path:
        """Compile a Rust standard library component to eBPF rlib.
        
        Args:
            component: Component name ("core", "std", "alloc")
            rust_version: Rust version (e.g., "1.75.0")
            solana_version: Solana version for toolchain compatibility
            cleanup: Whether to clean up build artifacts
            
        Returns:
            Path to compiled rlib file
            
        Raises:
            BuildError: If compilation fails
        """
        self.logger.info(f"Compiling Rust {component} {rust_version} for eBPF")
        
        # Create project
        project_dir = self.create_stdlib_project(component, rust_version, solana_version)
        
        # Save current rustup state
        saved_state = self.toolchain_manager._save_current_solana_state()
        
        try:
            # Ensure Solana toolchain is available
            if not self.toolchain_manager.is_toolchain_installed(solana_version):
                self.toolchain_manager.install_toolchain(solana_version)
            
            # Setup Solana toolchain environment
            self.toolchain_manager.setup_solana_toolchain(solana_version)
            
            # Compile with cargo-build-sbf
            rlib_path = self._build_with_cargo_sbf(project_dir, component, rust_version, solana_version)
            
            self.logger.info(f"Successfully compiled {component} stdlib component")
            return rlib_path
            
        except Exception as e:
            self.logger.error(f"Failed to compile {component}: {e}")
            raise BuildError(f"Compilation failed for {component}: {e}")
        
        finally:
            # Always restore original rustup state
            self.toolchain_manager._restore_solana_state(saved_state)
            
            # Cleanup if requested
            if cleanup and project_dir.exists():
                self.logger.info(f"Cleaning up build artifacts for {component}")
                shutil.rmtree(project_dir)
    
    def _build_with_cargo_sbf(self, project_dir: Path, component: str, 
                             rust_version: str, solana_version: str) -> Path:
        """Build project using cargo-build-sbf.
        
        Args:
            project_dir: Project directory path
            component: Component name
            rust_version: Rust version
            solana_version: Solana version
            
        Returns:
            Path to compiled rlib file
        """
        # Get cargo-build-sbf path from toolchain manager
        cargo_build_sbf = self.toolchain_manager.get_cargo_build_sbf_path(solana_version)
        
        # Set environment for Solana eBPF compilation
        env = os.environ.copy()
        env["CARGO_BUILD_SBF"] = "1"
        env["CARGO_PROFILE_RELEASE_DEBUG"] = "true"
        
        # Build command using the specific cargo-build-sbf from Solana toolchain  
        # Note: cargo-build-sbf doesn't use --release flag, it defaults to release mode
        cmd = [str(cargo_build_sbf)]
        
        # Clean any existing lock file before compilation (similar to crate_compiler)
        cargo_lock = project_dir / "Cargo.lock"
        if cargo_lock.exists():
            cargo_lock.unlink()
        
        self.logger.info(f"Running: {' '.join(cmd)} in {project_dir}")
        
        try:
            # Remove any existing lock file right before compilation
            cargo_lock = project_dir / "Cargo.lock"
            if cargo_lock.exists():
                cargo_lock.unlink()
                
            result = subprocess.run(
                cmd,
                cwd=project_dir,
                env=env,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            output = result.stdout + result.stderr
            # Check for success using the same pattern as crate_compiler
            success = "Finished release" in output
            
            if not success:
                self.logger.error(f"Build failed:\nOutput: {output}")
                raise BuildError(f"cargo-build-sbf compilation failed")
            
            self.logger.debug(f"Build output: {output}")
            
        except subprocess.TimeoutExpired:
            raise BuildError("Build timeout after 5 minutes")
        except FileNotFoundError:
            raise BuildError(f"cargo-build-sbf not found at {cargo_build_sbf}. Is Solana toolchain installed?")
        
        # Find and copy the rlib file
        return self._collect_rlib(project_dir, component, rust_version)
    
    def _collect_rlib(self, project_dir: Path, component: str, rust_version: str) -> Path:
        """Collect the compiled rlib file and copy to standard location.
        
        Args:
            project_dir: Project directory path
            component: Component name
            rust_version: Rust version
            
        Returns:
            Path to collected rlib file
        """
        # Look for rlib in target directory
        target_dir = project_dir / "target" / "sbf-solana-solana" / "release" / "deps"
        
        if not target_dir.exists():
            raise BuildError(f"Target directory not found: {target_dir}")
        
        # Find rlib files matching the component
        rlib_pattern = f"*{component}*.rlib"
        rlib_files = list(target_dir.glob(rlib_pattern))
        
        if not rlib_files:
            # Try alternative patterns
            alt_patterns = [
                f"lib{component}-*.rlib",
                f"rust_{component}-*.rlib",
                f"*rust_{component}*.rlib"
            ]
            
            for pattern in alt_patterns:
                rlib_files = list(target_dir.glob(pattern))
                if rlib_files:
                    break
        
        if not rlib_files:
            self.logger.error(f"Available files in {target_dir}:")
            for f in target_dir.iterdir():
                self.logger.error(f"  {f.name}")
            raise BuildError(f"No rlib file found for component {component}")
        
        # Use the largest rlib file (most likely the main one)
        source_rlib = max(rlib_files, key=lambda f: f.stat().st_size)
        
        # Create target directory structure
        component_dir = self.rlibs_dir / f"rust-{component}"
        component_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate standard filename
        standard_filename = f"rust_{component}_{rust_version}_ebpf.rlib"
        target_rlib = component_dir / standard_filename
        
        # Copy rlib file
        shutil.copy2(source_rlib, target_rlib)
        
        self.logger.info(f"Collected rlib: {source_rlib} -> {target_rlib}")
        return target_rlib
    
    def compile_all_components(self, rust_version: str, solana_version: str, 
                              components: Optional[List[str]] = None) -> Dict[str, Path]:
        """Compile all or specified standard library components.
        
        Args:
            rust_version: Rust version (e.g., "1.75.0")
            solana_version: Solana version for toolchain compatibility
            components: List of components to compile (default: all)
            
        Returns:
            Dictionary mapping component names to rlib paths
        """
        if components is None:
            components = list(self.SUPPORTED_COMPONENTS.keys())
        
        results = {}
        
        for component in components:
            try:
                rlib_path = self.compile_stdlib_component(
                    component, rust_version, solana_version
                )
                results[component] = rlib_path
                
            except Exception as e:
                self.logger.error(f"Failed to compile {component}: {e}")
                results[component] = None
        
        # Summary
        success_count = sum(1 for path in results.values() if path is not None)
        total_count = len(components)
        
        self.logger.info(f"Compiled {success_count}/{total_count} stdlib components")
        
        return results