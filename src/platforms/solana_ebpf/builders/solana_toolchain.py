"""Solana toolchain management for eBPF compilation.

This module handles downloading, installing, and managing Solana toolchains
specifically for eBPF program compilation.
"""

import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Optional, Dict, List
from urllib.request import urlretrieve

from ....core.config import settings
from ....core.exceptions import SignatureError
from ....core.logger import LoggerMixin


class SolanaToolchainManager(LoggerMixin):
    """Manages Solana toolchain installation and configuration."""
    
    def __init__(self, toolchains_dir: Optional[Path] = None):
        """Initialize the toolchain manager.
        
        Args:
            toolchains_dir: Directory to store Solana toolchains.
                          Defaults to data/solana_ebpf/toolchains/
        """
        self.toolchains_dir = toolchains_dir or (settings.data_dir / "solana_ebpf" / "toolchains")
        self.toolchains_dir.mkdir(parents=True, exist_ok=True)
        
        # Target version for testing
        self.target_version = "1.18.16"
        
        # Platform-specific download URLs
        self.download_urls = {
            "1.18.16": {
                "linux": "https://github.com/solana-labs/solana/releases/download/v1.18.16/solana-release-x86_64-unknown-linux-gnu.tar.bz2",
                "darwin": "https://github.com/solana-labs/solana/releases/download/v1.18.16/solana-release-x86_64-apple-darwin.tar.bz2",
                "windows": "https://github.com/solana-labs/solana/releases/download/v1.18.16/solana-release-x86_64-pc-windows-msvc.tar.bz2",
            }
        }
        
        self.logger.info(f"Solana toolchain manager initialized with dir: {self.toolchains_dir}")
    
    def get_platform_name(self) -> str:
        """Get the current platform name for downloads."""
        import platform
        system = platform.system().lower()
        if system == "linux":
            return "linux"
        elif system == "darwin":
            return "darwin"
        elif system == "windows":
            return "windows"
        else:
            raise SignatureError(f"Unsupported platform: {system}")
    
    def get_toolchain_dir(self, version: str) -> Path:
        """Get the installation directory for a specific Solana version."""
        return self.toolchains_dir / f"solana-release-{version}"
    
    def is_toolchain_installed(self, version: str) -> bool:
        """Check if a Solana toolchain version is already installed."""
        toolchain_dir = self.get_toolchain_dir(version)
        cargo_build_sbf = toolchain_dir / "bin" / "cargo-build-sbf"
        
        # Check if directory exists and has the essential tools
        return (toolchain_dir.exists() and 
                cargo_build_sbf.exists() and 
                os.access(cargo_build_sbf, os.X_OK))
    
    def download_toolchain(self, version: str) -> Path:
        """Download Solana toolchain archive.
        
        Args:
            version: Solana version to download (e.g., "1.18.16")
            
        Returns:
            Path to downloaded archive file
            
        Raises:
            SignatureError: If download fails or version not supported
        """
        if version not in self.download_urls:
            raise SignatureError(f"Solana version {version} not supported")
        
        platform = self.get_platform_name()
        if platform not in self.download_urls[version]:
            raise SignatureError(f"Platform {platform} not supported for Solana {version}")
        
        url = self.download_urls[version][platform]
        
        # Create temporary file for download
        temp_dir = Path(tempfile.gettempdir())
        archive_name = f"solana-release-{version}-{platform}.tar.bz2"  
        archive_path = temp_dir / archive_name
        
        self.logger.info(f"Downloading Solana {version} from {url}")
        
        try:
            urlretrieve(url, archive_path)
            self.logger.info(f"Downloaded to {archive_path}")
            return archive_path
        except Exception as e:
            raise SignatureError(f"Failed to download Solana {version}: {e}")
    
    def extract_toolchain(self, archive_path: Path, version: str) -> Path:
        """Extract Solana toolchain archive.
        
        Args:
            archive_path: Path to downloaded archive
            version: Solana version being extracted
            
        Returns:
            Path to extracted toolchain directory
        """
        toolchain_dir = self.get_toolchain_dir(version)
        
        self.logger.info(f"Extracting {archive_path} to {toolchain_dir}")
        
        try:
            with tarfile.open(archive_path, 'r:bz2') as tar:
                # Extract to temporary directory first
                temp_extract_dir = self.toolchains_dir / f"temp_extract_{version}"
                tar.extractall(temp_extract_dir)
                
                # Find the actual solana directory (may be nested)
                extracted_dirs = list(temp_extract_dir.glob("solana-release*"))
                if not extracted_dirs:
                    raise SignatureError("No solana-release directory found in archive")
                
                # Move to final location
                if toolchain_dir.exists():
                    shutil.rmtree(toolchain_dir)
                shutil.move(str(extracted_dirs[0]), str(toolchain_dir))
                
                # Clean up temporary extraction
                if temp_extract_dir.exists():
                    shutil.rmtree(temp_extract_dir)
                
            self.logger.info(f"Extracted toolchain to {toolchain_dir}")
            return toolchain_dir
            
        except Exception as e:
            raise SignatureError(f"Failed to extract Solana {version}: {e}")
    
    def install_toolchain(self, version: str, force: bool = False) -> Path:
        """Install Solana toolchain.
        
        Args:
            version: Solana version to install
            force: Force reinstallation even if already exists
            
        Returns:
            Path to installed toolchain directory
        """
        if not force and self.is_toolchain_installed(version):
            self.logger.info(f"Solana {version} already installed")
            return self.get_toolchain_dir(version)
        
        self.logger.info(f"Installing Solana {version} toolchain")
        
        # Download archive
        archive_path = self.download_toolchain(version)
        
        try:
            # Extract toolchain
            toolchain_dir = self.extract_toolchain(archive_path, version)
            
            # Verify installation 
            if not self.is_toolchain_installed(version):
                raise SignatureError(f"Toolchain installation verification failed for {version}")
            
            self.logger.info(f"Successfully installed Solana {version}")
            return toolchain_dir
            
        finally:
            # Clean up downloaded archive
            if archive_path.exists():
                archive_path.unlink()
    
    def get_cargo_build_sbf_path(self, version: str) -> Path:
        """Get path to cargo-build-sbf tool.
        
        Args:
            version: Solana version
            
        Returns:
            Path to cargo-build-sbf executable
            
        Raises:
            SignatureError: If toolchain not installed
        """
        if not self.is_toolchain_installed(version):
            raise SignatureError(f"Solana {version} toolchain not installed")
        
        toolchain_dir = self.get_toolchain_dir(version)
        cargo_build_sbf_path = toolchain_dir / "bin" / "cargo-build-sbf"
        
        # Return absolute path
        return cargo_build_sbf_path.resolve()
    
    def get_installed_versions(self) -> List[str]:
        """Get list of installed Solana versions."""
        versions = []
        if self.toolchains_dir.exists():
            for path in self.toolchains_dir.iterdir():
                if path.is_dir() and path.name.startswith("solana-release-"):
                    version = path.name.replace("solana-release-", "")
                    if self.is_toolchain_installed(version):
                        versions.append(version)
        return sorted(versions)
    
    def remove_toolchain(self, version: str) -> bool:
        """Remove installed Solana toolchain.
        
        Args:
            version: Solana version to remove
            
        Returns:
            True if removed successfully, False if not installed
        """
        toolchain_dir = self.get_toolchain_dir(version)
        if not toolchain_dir.exists():
            return False
        
        self.logger.info(f"Removing Solana {version} toolchain")
        shutil.rmtree(toolchain_dir)
        return True
    
    def install_target_version(self, force: bool = False) -> Path:
        """Install the target version (1.18.16) for testing.
        
        Args:
            force: Force reinstallation
            
        Returns:
            Path to installed toolchain
        """
        return self.install_toolchain(self.target_version, force=force)
    
    def get_target_cargo_build_sbf(self) -> Path:
        """Get cargo-build-sbf path for target version."""
        return self.get_cargo_build_sbf_path(self.target_version)
    
    def verify_installation(self, version: str) -> Dict[str, bool]:
        """Verify toolchain installation completeness.
        
        Args:
            version: Solana version to verify
            
        Returns:
            Dictionary with verification results
        """
        toolchain_dir = self.get_toolchain_dir(version)
        results = {
            'toolchain_dir_exists': toolchain_dir.exists(),
            'cargo_build_sbf_exists': False,
            'cargo_build_sbf_executable': False,
            'solana_cli_exists': False,
        }
        
        if results['toolchain_dir_exists']:
            cargo_build_sbf = toolchain_dir / "bin" / "cargo-build-sbf"
            solana_cli = toolchain_dir / "bin" / "solana"
            
            results['cargo_build_sbf_exists'] = cargo_build_sbf.exists()
            results['cargo_build_sbf_executable'] = cargo_build_sbf.exists() and os.access(cargo_build_sbf, os.X_OK)
            results['solana_cli_exists'] = solana_cli.exists()
        
        return results
    
    def _save_current_solana_state(self) -> Dict[str, any]:
        """Save current solana toolchain state for later restoration.
        
        Returns:
            Dictionary containing current state information
        """
        try:
            # Check if solana toolchain exists
            result = subprocess.run(
                ["rustup", "toolchain", "list"], 
                capture_output=True, text=True, check=False
            )
            
            solana_exists = "solana" in result.stdout if result.returncode == 0 else False
            solana_path = None
            is_symlink = False
            
            if solana_exists:
                # Get actual path of solana toolchain
                solana_toolchain_path = Path.home() / ".rustup" / "toolchains" / "solana"
                if solana_toolchain_path.exists():
                    is_symlink = solana_toolchain_path.is_symlink()
                    if is_symlink:
                        solana_path = solana_toolchain_path.readlink()
            
            state = {
                "exists": solana_exists,
                "path": str(solana_path) if solana_path else None,
                "is_symlink": is_symlink
            }
            
            self.logger.debug(f"Saved solana toolchain state: {state}")
            return state
            
        except Exception as e:
            self.logger.warning(f"Failed to save solana toolchain state: {e}")
            return {"exists": False, "path": None, "is_symlink": False}
    
    def _restore_solana_state(self, saved_state: Dict[str, any]) -> None:
        """Restore solana toolchain to saved state.
        
        Args:
            saved_state: State dictionary from _save_current_solana_state()
        """
        try:
            # First, remove current solana toolchain
            result = subprocess.run(
                ["rustup", "toolchain", "uninstall", "solana"],
                capture_output=True, text=True, check=False
            )
            
            if result.returncode == 0:
                self.logger.debug("Removed temporary solana toolchain")
            
            # Restore based on saved state
            if saved_state["exists"] and saved_state["path"]:
                # Restore original link
                restore_result = subprocess.run([
                    "rustup", "toolchain", "link", 
                    "solana", saved_state["path"]
                ], capture_output=True, text=True, check=False)
                
                if restore_result.returncode == 0:
                    self.logger.info(f"Restored solana toolchain to {saved_state['path']}")
                else:
                    self.logger.error(f"Failed to restore solana toolchain: {restore_result.stderr}")
            else:
                self.logger.info("Solana toolchain removed (was not present originally)")
                
        except Exception as e:
            self.logger.error(f"Failed to restore solana toolchain: {e}")
    
    def setup_solana_toolchain(self, version: str) -> None:
        """Setup rustup solana toolchain for specified version.
        
        Args:
            version: Solana version to setup toolchain for
            
        Raises:
            SignatureError: If toolchain setup fails
        """
        if not self.is_toolchain_installed(version):
            raise SignatureError(f"Solana {version} toolchain not installed")
        
        # Get platform-tools/rust path
        platform_tools_rust = self.get_platform_tools_rust_path(version)
        if not platform_tools_rust.exists():
            raise SignatureError(f"Platform tools rust not found: {platform_tools_rust}")
        
        try:
            # Remove existing solana toolchain
            subprocess.run(
                ["rustup", "toolchain", "uninstall", "solana"],
                capture_output=True, check=False
            )
            
            # Link to current version's platform-tools/rust
            result = subprocess.run([
                "rustup", "toolchain", "link", 
                "solana", str(platform_tools_rust)
            ], capture_output=True, text=True, check=True)
            
            self.logger.info(f"Linked solana toolchain to {platform_tools_rust}")
            
        except subprocess.CalledProcessError as e:
            raise SignatureError(f"Failed to setup solana toolchain: {e.stderr}")
        except Exception as e:
            raise SignatureError(f"Failed to setup solana toolchain: {e}")
    
    def get_platform_tools_rust_path(self, version: str) -> Path:
        """Get path to platform-tools/rust directory for specified version.
        
        Args:
            version: Solana version
            
        Returns:
            Path to platform-tools/rust directory
        """
        toolchain_dir = self.get_toolchain_dir(version)
        platform_tools_rust = (toolchain_dir / "bin" / "sdk" / "sbf" / 
                              "dependencies" / "platform-tools" / "rust")
        return platform_tools_rust