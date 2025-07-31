"""Solana program crate compiler for eBPF targets.

This module provides functionality to compile Solana Rust crates to eBPF format
using the Solana toolchain's cargo-build-sbf tool.
"""

import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests

from ....core.config import settings
from ....core.exceptions import SignatureError, BuildError
from ....core.logger import LoggerMixin
from ....core.naming_utils import get_rlib_filename
from .solana_toolchain import SolanaToolchainManager


class SolanaProgramCompiler(LoggerMixin):
    """Compiles Solana program crates to eBPF rlib format."""
    
    def __init__(self, toolchain_manager: Optional[SolanaToolchainManager] = None):
        """Initialize the compiler.
        
        Args:
            toolchain_manager: Solana toolchain manager instance
        """
        self.toolchain_manager = toolchain_manager or SolanaToolchainManager()
        self.downloaded_crates_dir = settings.data_dir / "solana_ebpf" / "downloaded_crates"
        self.crates_dir = settings.data_dir / "solana_ebpf" / "crates"
        self.rlibs_dir = settings.data_dir / "solana_ebpf" / "rlibs"
        
        # Create directories
        self.downloaded_crates_dir.mkdir(parents=True, exist_ok=True)
        self.crates_dir.mkdir(parents=True, exist_ok=True)
        self.rlibs_dir.mkdir(parents=True, exist_ok=True)
        
        # Target architecture for Solana eBPF
        self.target_arch = "sbf-solana-solana"
        
        # Test configuration for solana-program-1.18.16
        self.test_config = {
            "crate_name": "solana-program",
            "version": "1.18.16",
            "solana_version": "1.18.16"
        }
        
        self.logger.info(f"Solana compiler initialized with crates_dir: {self.crates_dir}")
    
    def create_test_project(self, crate_name: str, crate_version: str) -> Path:
        """Create a test Rust project with specified Solana crate dependency.
        
        Args:
            crate_name: Name of the Solana crate (e.g., "solana-program")
            crate_version: Version of the crate (e.g., "1.18.16")
            
        Returns:
            Path to created project directory
        """
        project_name = f"{crate_name}-{crate_version}"
        project_dir = self.crates_dir / project_name
        
        # Remove existing project if it exists
        if project_dir.exists():
            shutil.rmtree(project_dir)
        
        project_dir.mkdir(parents=True)
        
        # Create Cargo.toml  
        package_name = project_name.replace('-', '_').replace('.', '_')
        cargo_toml_content = f'''[package]
name = "{package_name}"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
{crate_name} = "{crate_version}"

[profile.release]
debug = true
debug-assertions = false
overflow-checks = true
lto = false
panic = "abort"
codegen-units = 1
opt-level = 2
'''
        
        cargo_toml_path = project_dir / "Cargo.toml"
        cargo_toml_path.write_text(cargo_toml_content)
        
        # Create src directory and lib.rs
        src_dir = project_dir / "src"
        src_dir.mkdir()
        
        lib_rs_content = f'''//! Test library for {crate_name} {crate_version}

use {crate_name.replace('-', '_')}::*;

#[no_mangle]
pub fn test_function() -> u64 {{
    42
}}
'''
        
        lib_rs_path = src_dir / "lib.rs"
        lib_rs_path.write_text(lib_rs_content)
        
        self.logger.info(f"Created test project at {project_dir}")
        return project_dir
    
    def apply_ahash_patch(self, project_dir: Path) -> None:
        """Apply ahash version patch if needed (ported from build_crate.py).
        
        Args:
            project_dir: Path to the Rust project directory
        """
        cargo_toml_path = project_dir / "Cargo.toml"
        if not cargo_toml_path.exists():
            return
        
        # Read current content
        content = cargo_toml_path.read_text()
        
        # Check if ahash patch already applied
        if "ahash = " in content:
            return
        
        # Apply patch
        patch = "\n[dependencies]\nahash = \"=0.8.6\"\n"
        content += patch
        
        cargo_toml_path.write_text(content)
        self.logger.info("Applied ahash patch to Cargo.toml")
    
    def compile_project(self, project_dir: Path, solana_version: str, debug_mode: bool = False) -> Tuple[bool, str]:
        """Compile a Rust project to eBPF using cargo-build-sbf with rustup toolchain management.
        
        Args:
            project_dir: Path to the Rust project directory
            solana_version: Solana toolchain version to use
            debug_mode: Enable debug symbols compilation for TIL generation
            
        Returns:
            Tuple of (success, output_text)
        """
        # Ensure toolchain is installed
        if not self.toolchain_manager.is_toolchain_installed(solana_version):
            self.toolchain_manager.install_toolchain(solana_version)
        
        cargo_build_sbf = self.toolchain_manager.get_cargo_build_sbf_path(solana_version)
        
        # Save current rustup state
        saved_state = self.toolchain_manager._save_current_solana_state()
        
        try:
            # Setup solana toolchain for this compilation
            self.toolchain_manager.setup_solana_toolchain(solana_version)
            
            # Clean environment - let cargo-build-sbf handle toolchain management
            env = os.environ.copy()
            
            # Configure compilation flags based on mode
            if debug_mode:
                env["RUSTFLAGS"] = "-C debuginfo=2 -C overflow-checks=on"  # Full debug info for TIL
                env["CARGO_PROFILE_DEV_DEBUG"] = "true"
                self.logger.info(f"Compiling with debug symbols enabled for TIL generation")
            else:
                env["RUSTFLAGS"] = "-C overflow-checks=on"  # Release mode for PAT/SIG
            
            # Remove Cargo.lock if it exists to avoid version conflicts
            cargo_lock = project_dir / "Cargo.lock"
            if cargo_lock.exists():
                cargo_lock.unlink()
            
            # Compile command - simplified since cargo-build-sbf now has correct toolchain
            cmd = [str(cargo_build_sbf)]
            
            # Add debug flag for TIL generation
            if debug_mode:
                cmd.append("--debug")
            
            self.logger.info(f"Compiling project {project_dir.name} with Solana {solana_version}")
            
            # First attempt
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
                # Solana eBPF always shows "Finished release" regardless of --debug flag
                success = "Finished release" in output
                
                if not success and "use of unstable library feature 'build_hasher_simple_hash_one'" in output:
                    self.logger.info("Applying ahash patch and retrying compilation")
                    self.apply_ahash_patch(project_dir)
                    
                    # Retry compilation
                    result = subprocess.run(
                        cmd,
                        cwd=project_dir, 
                        env=env,
                        capture_output=True,
                        text=True,
                        timeout=300
                    )
                    
                    output = result.stdout + result.stderr
                    # Solana eBPF always shows "Finished release" regardless of --debug flag
                    success = "Finished release" in output
                
                return success, output
                
            except subprocess.TimeoutExpired:
                return False, "Compilation timed out"
            except Exception as e:
                return False, f"Compilation error: {e}"
                
        finally:
            # Always restore original rustup state
            self.toolchain_manager._restore_solana_state(saved_state)
    
    def find_compiled_rlib(self, project_dir: Path, crate_name: str, debug_mode: bool = False) -> Optional[Path]:
        """Find the compiled rlib file in the project target directory.
        
        Args:
            project_dir: Path to the Rust project directory
            crate_name: Name of the crate to find rlib for
            debug_mode: Not used for Solana eBPF (always uses release directory)
            
        Returns:
            Path to rlib file or None if not found
        """
        # Solana eBPF always outputs to release directory, even with --debug flag
        target_dir = project_dir / "target" / self.target_arch / "release"
        
        if not target_dir.exists():
            return None
        
        # Look for rlib files
        lib_name = crate_name.replace('-', '_')
        rlib_pattern = f"lib{lib_name}*.rlib"
        
        rlib_files = list(target_dir.glob(rlib_pattern))
        if rlib_files:
            return rlib_files[0]  # Return first match
        
        return None
    
    def extract_rlib(self, project_dir: Path, crate_name: str, version: str, debug_mode: bool = False) -> Optional[Path]:
        """Extract and save the compiled rlib file.
        
        Args:
            project_dir: Path to the Rust project directory
            crate_name: Name of the crate
            version: Version of the crate
            debug_mode: Whether to extract from debug or release build
            
        Returns:
            Path to extracted rlib file or None if not found
        """
        rlib_path = self.find_compiled_rlib(project_dir, crate_name, debug_mode)
        if not rlib_path:
            self.logger.error(f"No rlib found for {crate_name} in {project_dir}")
            return None
        
        # Create output directory
        output_dir = self.rlibs_dir / crate_name
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Target filename - use unified naming utility with debug suffix if needed
        if debug_mode:
            target_filename = get_rlib_filename(crate_name, version, 'solana_ebpf').replace('.rlib', '_debug.rlib')
        else:
            target_filename = get_rlib_filename(crate_name, version, 'solana_ebpf')
        target_path = output_dir / target_filename
        
        # Copy rlib file
        shutil.copy2(rlib_path, target_path)
        
        self.logger.info(f"Extracted rlib to {target_path}")
        return target_path
    
    def cleanup_build_artifacts(self, project_dir: Path) -> None:
        """Clean up build artifacts to save disk space.
        
        Args:
            project_dir: Path to the Rust project directory
        """
        target_dir = project_dir / "target"
        if target_dir.exists():
            shutil.rmtree(target_dir)
            self.logger.info(f"Cleaned up build artifacts for {project_dir.name}")
    
    def download_crate_manually(self, crate_name: str, version: str) -> Path:
        """Download crate from crates.io using the original project approach.
        
        Args:
            crate_name: Name of the crate to download
            version: Version of the crate
            
        Returns:
            Path to downloaded crate directory
            
        Raises:
            BuildError: If download fails
        """
        crate_dir_name = f"{crate_name}-{version}"
        crate_dir = self.downloaded_crates_dir / crate_dir_name
        
        # If already downloaded, return existing directory
        if crate_dir.exists():
            self.logger.info(f"Crate {crate_dir_name} already exists")
            return crate_dir
        
        self.logger.info(f"Downloading {crate_name} v{version} from crates.io...")
        
        # Download URL following original project pattern
        download_url = f"https://crates.io/api/v1/crates/{crate_name}/{version}/download"
        
        try:
            # Download the tar.gz file
            response = requests.get(download_url, stream=True, timeout=30)
            response.raise_for_status()
            
            # Save to temporary file
            with tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False) as tmp_file:
                for chunk in response.iter_content(chunk_size=8192):
                    tmp_file.write(chunk)
                tmp_path = Path(tmp_file.name)
            
            # Extract the tar.gz file  
            with tarfile.open(tmp_path, 'r:gz') as tar:
                tar.extractall(path=self.downloaded_crates_dir)
            
            # Clean up temporary file
            tmp_path.unlink()
            
            if not crate_dir.exists():
                raise BuildError(f"Failed to extract crate {crate_dir_name}")
            
            self.logger.info(f"Successfully downloaded {crate_dir_name}")
            return crate_dir
            
        except Exception as e:
            # Clean up on failure
            if crate_dir.exists():
                shutil.rmtree(crate_dir, ignore_errors=True)
            raise BuildError(f"Failed to download {crate_name} {version}: {e}")
    
    def compile_downloaded_crate(self, crate_name: str, version: str, 
                                solana_version: str, cleanup: bool = True, debug_mode: bool = False) -> Path:
        """Compile a downloaded crate directly (like original project approach).
        
        Args:
            crate_name: Name of the crate to compile
            version: Crate version
            solana_version: Solana toolchain version to use
            cleanup: Whether to clean up build artifacts
            debug_mode: Enable debug symbols for TIL generation
            
        Returns:
            Path to compiled rlib file
        """
        compile_mode = "debug" if debug_mode else "release"
        self.logger.info(f"Compiling {crate_name} {version} directly with Solana {solana_version} ({compile_mode} mode)")
        
        # Download crate source using manual approach (like original project)
        crate_dir = self.download_crate_manually(crate_name, version)
        
        # Apply ahash patch if needed (common for Solana crates)
        self.apply_ahash_patch(crate_dir)
        
        try:
            # Compile directly in crate directory
            success, output = self.compile_project(crate_dir, solana_version, debug_mode)
            
            if not success:
                raise BuildError(f"Failed to compile {crate_name} {version}:\n{output}")
            
            # Extract rlib from crate's target directory
            rlib_path = self.extract_rlib_from_crate(crate_dir, crate_name, version, debug_mode)
            if not rlib_path:
                raise BuildError(f"Failed to extract rlib for {crate_name} {version}")
            
            self.logger.info(f"Successfully compiled {crate_name} {version}")
            return rlib_path
            
        finally:
            if cleanup:
                self.cleanup_build_artifacts(crate_dir)
    
    def extract_rlib_from_crate(self, crate_dir: Path, crate_name: str, version: str, debug_mode: bool = False) -> Optional[Path]:
        """Extract rlib from a crate's target directory.
        
        Args:
            crate_dir: Path to crate directory
            crate_name: Name of the crate
            version: Crate version
            debug_mode: Whether this was compiled with debug symbols (affects naming only)
            
        Returns:
            Path to extracted rlib file or None if not found
        """
        # Solana eBPF always outputs to release/deps/, even with --debug flag
        target_dir = crate_dir / "target" / self.target_arch / "release" / "deps"
        
        if not target_dir.exists():
            self.logger.error(f"Target directory not found: {target_dir}")
            return None
        
        # Find the lib*.rlib file - try both with and without hash suffix
        lib_name = crate_name.replace('-', '_')
        
        # First try with hash suffix (common pattern)
        rlib_pattern_with_hash = f"lib{lib_name}-*.rlib"
        rlib_files = list(target_dir.glob(rlib_pattern_with_hash))
        
        # If not found, try without hash suffix (e.g., libsolana_program.rlib)
        if not rlib_files:
            rlib_pattern_no_hash = f"lib{lib_name}.rlib"
            rlib_files = list(target_dir.glob(rlib_pattern_no_hash))
            
        if not rlib_files:
            self.logger.error(f"No rlib files found matching patterns: {rlib_pattern_with_hash} or lib{lib_name}.rlib")
            self.logger.debug(f"Available files in {target_dir}:")
            if target_dir.exists():
                for file in target_dir.iterdir():
                    if file.name.endswith('.rlib'):
                        self.logger.debug(f"  {file.name}")
            return None
        
        # Use the first (and typically only) rlib file found
        source_rlib = rlib_files[0]
        
        # Copy to our rlibs directory with standardized name
        target_rlib_dir = self.rlibs_dir / crate_name
        target_rlib_dir.mkdir(parents=True, exist_ok=True)
        
        # Use debug suffix for debug builds
        if debug_mode:
            target_filename = get_rlib_filename(crate_name, version, 'solana_ebpf').replace('.rlib', '_debug.rlib')
        else:
            target_filename = get_rlib_filename(crate_name, version, 'solana_ebpf')
        target_rlib = target_rlib_dir / target_filename
        
        shutil.copy2(source_rlib, target_rlib)
        self.logger.info(f"Copied rlib: {source_rlib} -> {target_rlib}")
        
        # Verify debug symbols if this was a debug compilation
        if debug_mode:
            has_debug = self.verify_debug_symbols(target_rlib)
            if has_debug:
                self.logger.info(f"✅ Debug symbols verified in {target_rlib.name}")
            else:
                self.logger.warning(f"⚠️ Debug symbols not found in {target_rlib.name} (compiled with --debug)")
        
        return target_rlib
        
    def compile_solana_program(self, version: str = "1.18.16", 
                              solana_version: str = "1.18.16",
                              cleanup: bool = True, debug_mode: bool = False) -> Path:
        """Compile solana-program crate to eBPF rlib.
        
        Args:
            version: solana-program crate version
            solana_version: Solana toolchain version
            cleanup: Whether to clean up build artifacts
            debug_mode: Enable debug symbols for TIL generation
            
        Returns:
            Path to compiled rlib file
            
        Raises:
            BuildError: If compilation fails
        """
        # Use the new direct compilation method
        return self.compile_downloaded_crate("solana-program", version, solana_version, cleanup, debug_mode)
    
    def compile_test_target(self, cleanup: bool = True, debug_mode: bool = False) -> Path:
        """Compile the test target (solana-program-1.18.16).
        
        Args:
            cleanup: Whether to clean up build artifacts
            debug_mode: Enable debug symbols for TIL generation
            
        Returns:
            Path to compiled rlib file
        """
        config = self.test_config
        return self.compile_solana_program(
            version=config["version"],
            solana_version=config["solana_version"],
            cleanup=cleanup,
            debug_mode=debug_mode
        )
    
    def compile_with_debug(self, crate_name: str, version: str, solana_version: str, cleanup: bool = True) -> Path:
        """Compile crate with debug symbols specifically for TIL generation.
        
        Args:
            crate_name: Name of the crate to compile
            version: Crate version
            solana_version: Solana toolchain version
            cleanup: Whether to clean up build artifacts
            
        Returns:
            Path to compiled debug rlib file
        """
        self.logger.info(f"Compiling {crate_name} {version} with debug symbols for TIL generation")
        return self.compile_downloaded_crate(crate_name, version, solana_version, cleanup, debug_mode=True)
    
    def get_debug_rlib_path(self, crate_name: str, version: str) -> Path:
        """Get the expected path for a debug RLIB file.
        
        Args:
            crate_name: Name of the crate
            version: Crate version
            
        Returns:
            Path where debug RLIB should be located
        """
        crate_dir = self.rlibs_dir / crate_name
        debug_filename = get_rlib_filename(crate_name, version, 'solana_ebpf').replace('.rlib', '_debug.rlib')
        return crate_dir / debug_filename
    
    def get_compiled_rlibs(self, crate_name: str) -> List[Path]:
        """Get list of compiled rlib files for a crate.
        
        Args:
            crate_name: Name of the crate
            
        Returns:
            List of paths to rlib files
        """
        crate_dir = self.rlibs_dir / crate_name
        if not crate_dir.exists():
            return []
        
        return list(crate_dir.glob("*.rlib"))
    
    def get_rlib_info(self, rlib_path: Path) -> Dict[str, str]:
        """Get information about an rlib file.
        
        Args:
            rlib_path: Path to rlib file
            
        Returns:
            Dictionary with rlib information
        """
        info = {
            'path': str(rlib_path),
            'name': rlib_path.name,
            'size': str(rlib_path.stat().st_size) if rlib_path.exists() else '0',
            'exists': str(rlib_path.exists()),
        }
        
        # Try to extract version from filename
        if '-' in rlib_path.stem:
            parts = rlib_path.stem.split('-')
            if len(parts) >= 2:
                info['version'] = '-'.join(parts[1:]).replace('.rlib', '')
        
        return info
    
    def verify_debug_symbols(self, rlib_path: Path) -> bool:
        """Verify that RLIB contains debug symbols.
        
        Args:
            rlib_path: Path to RLIB file to check
            
        Returns:
            True if debug symbols are present, False otherwise
        """
        if not rlib_path.exists():
            return False
        
        try:
            # Use objdump to check for DWARF debug information
            result = subprocess.run(
                ["objdump", "--dwarf=info", str(rlib_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # If objdump succeeded and has substantial output, debug info is present
            if result.returncode == 0 and len(result.stdout) > 200:
                return True
                
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # objdump not available or timed out, try alternative method
            pass
        
        try:
            # Alternative: check for DWARF sections using ar and readelf
            # First extract to temp directory
            import tempfile
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                # Extract RLIB archive
                subprocess.run(
                    ["ar", "x", str(rlib_path)],
                    cwd=temp_path,
                    check=True,
                    capture_output=True
                )
                
                # Check for .o files with debug sections
                for obj_file in temp_path.glob("*.o"):
                    result = subprocess.run(
                        ["readelf", "--debug-dump=info", str(obj_file)],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    
                    if result.returncode == 0 and "DW_TAG_compile_unit" in result.stdout:
                        return True
                        
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
        
        # Fallback: simple file size heuristic
        # Debug RLIBs are typically much larger
        try:
            file_size = rlib_path.stat().st_size
            # If file is relatively large (>1MB), likely has debug info
            return file_size > 1024 * 1024
        except OSError:
            return False
    
    def has_debug_rlib(self, crate_name: str, version: str) -> bool:
        """Check if debug RLIB already exists for given crate and version.
        
        Args:
            crate_name: Name of the crate
            version: Crate version
            
        Returns:
            True if debug RLIB exists, False otherwise
        """
        debug_rlib_path = self.get_debug_rlib_path(crate_name, version)
        return debug_rlib_path.exists() and self.verify_debug_symbols(debug_rlib_path)