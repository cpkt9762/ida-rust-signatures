"""Dependency resolution and management for Rust crates.

This module handles downloading, resolving, and managing Rust crate dependencies
for signature generation purposes.
"""

import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
from packaging import version

from ..core.config import settings
from ..core.exceptions import DependencyError, NetworkError, ValidationError
from ..core.logger import LoggerMixin, log_execution_time


class DependencyResolver(LoggerMixin):
    """Manages Rust crate dependencies for signature generation."""
    
    def __init__(self, workspace_dir: Optional[Path] = None):
        # For permanent crate storage, use dependencies_dir instead of workspace_dir
        self.workspace_dir = workspace_dir or settings.dependencies_dir
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        
    @log_execution_time
    def create_dependency_project(
        self, 
        project_name: str,
        dependencies: Dict[str, str],
        target: Optional[str] = None,
        features: Optional[List[str]] = None
    ) -> Path:
        """Create a Rust project with specified dependencies.
        
        Args:
            project_name: Name of the project to create.
            dependencies: Dictionary of crate names to version specifications.
            target: Target architecture (defaults to settings.target_arch).
            features: Optional list of features to enable.
            
        Returns:
            Path to the created project directory.
            
        Raises:
            DependencyError: If project creation fails.
            ValidationError: If inputs are invalid.
        """
        # Allow project names with version numbers (containing dots)
        if not project_name or not project_name.replace('_', '').replace('-', '').replace('.', '').isalnum():
            raise ValidationError.invalid_crate_name(project_name)
            
        if not dependencies:
            raise DependencyError("No dependencies specified")
            
        target = target or settings.target_arch
        project_dir = self.workspace_dir / project_name
        
        # Clean existing project if it exists
        if project_dir.exists():
            self.logger.info(f"Removing existing project: {project_dir}")
            shutil.rmtree(project_dir)
            
        project_dir.mkdir(parents=True)
        
        try:
            # Generate Cargo.toml
            self._generate_cargo_toml(project_dir, project_name, dependencies, features)
            
            # Generate lib.rs with usage examples
            self._generate_lib_rs(project_dir, dependencies)
            
            # Pre-fetch dependencies to validate they exist
            self._fetch_dependencies(project_dir)
            
            self.logger.info(f"Created dependency project: {project_dir}")
            return project_dir
            
        except Exception as e:
            # Clean up on failure
            if project_dir.exists():
                shutil.rmtree(project_dir, ignore_errors=True)
            
            if isinstance(e, (DependencyError, ValidationError, NetworkError)):
                raise
            else:
                raise DependencyError(
                    f"Failed to create project {project_name}: {e}",
                    dependency_chain=[project_name]
                ) from e
    
    def _generate_cargo_toml(
        self, 
        project_dir: Path, 
        name: str, 
        dependencies: Dict[str, str],
        features: Optional[List[str]] = None
    ) -> None:
        """Generate Cargo.toml file with specified dependencies."""
        
        # Build dependencies section
        deps_lines = []
        for crate, version_spec in dependencies.items():
            if self._is_simple_version(version_spec):
                deps_lines.append(f'{crate} = "{version_spec}"')
            else:
                # Handle complex version specifications
                deps_lines.append(f'{crate} = {version_spec}')
        
        deps_section = "\n".join(deps_lines)
        
        # Build features section
        features_section = ""
        if features:
            features_list = '", "'.join(features)
            features_section = f'\ndefault = ["{features_list}"]'
        
        cargo_toml = f'''[package]
name = "{name.replace('-', '_').replace('.', '_')}"
version = "0.1.0"
edition = "2021"

[dependencies]
{deps_section}

[features]{features_section}

[profile.release]
debug = true        # Preserve debug info for signature analysis
opt-level = {settings.optimization_level}
lto = false         # Disable LTO to preserve symbol information
codegen-units = 1   # Single codegen unit for better analysis
panic = "abort"     # Smaller binaries

[profile.dev]
debug = true
opt-level = 0
'''
        
        (project_dir / "Cargo.toml").write_text(cargo_toml, encoding='utf-8')
        self.logger.debug(f"Generated Cargo.toml for {name}")
    
    def _generate_lib_rs(self, project_dir: Path, dependencies: Dict[str, str]) -> None:
        """Generate lib.rs file that exercises dependency functions."""
        
        src_dir = project_dir / "src"
        src_dir.mkdir()
        
        # Generate usage patterns for common crates
        uses = []
        demo_functions = []
        
        for crate in dependencies.keys():
            crate_uses, crate_functions = self._get_crate_usage_patterns(crate)
            uses.extend(crate_uses)
            demo_functions.extend(crate_functions)
        
        # Add generic patterns for unknown crates
        if not demo_functions:
            demo_functions = [
                "    // Generic function call to ensure linking",
                "    println!(\"Dependencies loaded successfully\");"
            ]
        
        lib_rs = f'''//! Dependency demonstration library for signature generation.
//! 
//! This library imports and uses functions from dependencies to ensure
//! they are compiled into the final binary and available for signature extraction.

{chr(10).join(uses)}

/// Main demonstration function that exercises imported dependencies.
/// This ensures all dependency functions are linked and available for analysis.
#[no_mangle]
pub extern "C" fn demonstrate_dependencies() {{
{chr(10).join(demo_functions)}
}}

/// Additional utility functions to increase symbol coverage.
pub mod utils {{
    use super::*;
    
    /// Crypto-related operations for signature coverage.
    #[no_mangle]
    pub extern "C" fn crypto_operations() -> u64 {{
        demonstrate_dependencies();
        
        // Add some mathematical operations to generate more symbols
        let mut result = 0u64;
        for i in 1..=100 {{
            result = result.wrapping_add(i * i);
        }}
        result
    }}
    
    /// Network-related operations for signature coverage.
    #[no_mangle] 
    pub extern "C" fn network_operations() -> u64 {{
        crypto_operations()
    }}
}}

/// Test module to ensure all functions compile.
#[cfg(test)]
mod tests {{
    use super::*;
    
    #[test]
    fn test_dependencies() {{
        demonstrate_dependencies();
        utils::crypto_operations();
        utils::network_operations();
    }}
}}
'''
        
        (src_dir / "lib.rs").write_text(lib_rs, encoding='utf-8')
        self.logger.debug(f"Generated lib.rs with {len(demo_functions)} demo functions")
    
    def _get_crate_usage_patterns(self, crate: str) -> Tuple[List[str], List[str]]:
        """Get usage patterns for well-known crates.
        
        Returns:
            Tuple of (use statements, demo function lines).
        """
        patterns = {
            "solana-sdk": (
                [
                    "use solana_sdk::pubkey::Pubkey;",
                    "use solana_sdk::hash::Hash;", 
                    "use solana_sdk::signature::{Keypair, Signer};",
                    "use solana_sdk::system_program;",
                ],
                [
                    "    let pubkey = Pubkey::new_unique();",
                    "    let hash = Hash::default();",
                    "    let keypair = Keypair::new();",
                    "    let _ = keypair.pubkey();",
                    "    let _ = system_program::id();",
                ]
            ),
            "solana-client": (
                [
                    "use solana_client::rpc_client::RpcClient;",
                    "use solana_client::rpc_config::RpcSendTransactionConfig;",
                ],
                [
                    '    let _client = RpcClient::new("http://localhost:8899".to_string());',
                    "    let _config = RpcSendTransactionConfig::default();",
                ]
            ),
            "solana-account-decoder": (
                [
                    "use solana_account_decoder::{UiAccountEncoding, UiDataSliceConfig};",
                ],
                [
                    "    let _encoding = UiAccountEncoding::Base64;",
                    "    let _slice_config = UiDataSliceConfig::default();",
                ]
            ),
            "serde": (
                [
                    "use serde::{Serialize, Deserialize};",
                    "use serde_json;",
                ],
                [
                    "#[derive(Serialize, Deserialize)]",
                    "struct TestData { value: i32 }",
                    "let data = TestData { value: 42 };",
                    "let _ = serde_json::to_string(&data);",
                ]
            ),
            "tokio": (
                [
                    "use tokio::runtime::Runtime;",
                    "use tokio::time::{sleep, Duration};",
                ],
                [
                    "    let rt = Runtime::new();",
                    "    // Note: async operations for symbol generation only",
                ]
            ),
            "reqwest": (
                [
                    "use reqwest::Client;",
                ],
                [
                    "    let _client = Client::new();",
                ]
            ),
            "clap": (
                [
                    "use clap::{Parser, Subcommand};",
                ],
                [
                    "    // Clap structures for argument parsing symbols",
                ]
            ),
        }
        
        return patterns.get(crate, ([], []))
    
    def _is_simple_version(self, version_spec: str) -> bool:
        """Check if version specification is a simple version string."""
        return not any(c in version_spec for c in ['{', '[', '=', '<', '>', '^', '~'])
    
    @log_execution_time
    def _fetch_dependencies(self, project_dir: Path) -> None:
        """Pre-fetch dependencies to validate they exist."""
        self.logger.info("Fetching dependencies...")
        
        cmd = ["cargo", "fetch", "--verbose"]
        
        try:
            result = subprocess.run(
                cmd, 
                cwd=project_dir,
                capture_output=True, 
                text=True, 
                check=True,
                timeout=settings.crates_io_timeout * 10  # Longer timeout for fetching
            )
            
            self.logger.debug(f"Fetch output: {result.stdout}")
            
        except subprocess.TimeoutExpired as e:
            raise NetworkError(
                f"Dependency fetch timed out after {settings.crates_io_timeout * 10}s",
                context={"command": cmd, "timeout": settings.crates_io_timeout * 10}
            ) from e
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to fetch dependencies: {e.stderr}")
            
            # Try to extract specific dependency failures
            stderr = e.stderr or ""
            if "not found in registry" in stderr:
                # Extract crate name from error message
                lines = stderr.split('\n')
                for line in lines:
                    if "not found in registry" in line:
                        # Simple extraction - could be improved with regex
                        parts = line.split()
                        if len(parts) > 0:
                            crate_name = parts[0].strip('`').strip("'")
                            raise DependencyError(
                                f"Crate not found in registry: {crate_name}",
                                crate_name=crate_name
                            ) from e
            
            raise DependencyError(
                f"Failed to fetch dependencies: {stderr}"
            ) from e


class LocalDependencyManager(LoggerMixin):
    """Manages local dependency downloads and caching."""
    
    def __init__(self, deps_dir: Optional[Path] = None):
        self.deps_dir = deps_dir or settings.dependencies_dir
        self.deps_dir.mkdir(parents=True, exist_ok=True)
        
    @log_execution_time
    def download_crate_source(self, crate_name: str, version: str) -> Path:
        """Download crate source code to local directory.
        
        Args:
            crate_name: Name of the crate to download.
            version: Version specification to download.
            
        Returns:
            Path to the downloaded and extracted crate directory.
            
        Raises:
            NetworkError: If download fails.
            ValidationError: If inputs are invalid.
        """
        if not crate_name:
            raise ValidationError.invalid_crate_name(crate_name)
        if not version:
            raise ValidationError.invalid_version(version)
            
        crate_dir = self.deps_dir / f"{crate_name}-{version}"
        
        if crate_dir.exists():
            self.logger.info(f"Crate {crate_name}-{version} already exists locally")
            return crate_dir
            
        self.logger.info(f"Downloading {crate_name} v{version} from crates.io...")
        
        try:
            self._download_from_crates_io(crate_name, version, crate_dir)
            return crate_dir
            
        except Exception as e:
            # Clean up partial downloads
            if crate_dir.exists():
                shutil.rmtree(crate_dir, ignore_errors=True)
            raise
    
    def _download_from_crates_io(self, crate_name: str, version: str, target_dir: Path) -> None:
        """Download and extract crate from crates.io."""
        import tarfile
        import io
        
        # Get download URL
        download_url = f"https://crates.io/api/v1/crates/{crate_name}/{version}/download"
        
        try:
            response = requests.get(
                download_url, 
                stream=True,
                timeout=settings.crates_io_timeout
            )
            response.raise_for_status()
            
        except requests.exceptions.RequestException as e:
            if hasattr(e, 'response') and e.response is not None:
                raise NetworkError.crates_io_unavailable(
                    download_url, 
                    e.response.status_code
                ) from e
            else:
                raise NetworkError(
                    f"Failed to download {crate_name} v{version}: {e}",
                    url=download_url
                ) from e
        
        # Extract tar.gz content
        try:
            with tarfile.open(fileobj=io.BytesIO(response.content), mode='r:gz') as tar:
                tar.extractall(path=self.deps_dir)
                
        except tarfile.TarError as e:
            raise DependencyError(
                f"Failed to extract {crate_name} v{version}: {e}",
                crate_name=crate_name,
                version=version
            ) from e
        
        # Handle directory naming variations
        extracted_dir = self.deps_dir / f"{crate_name}-{version}"
        if not extracted_dir.exists():
            # Look for alternative names
            possible_dirs = list(self.deps_dir.glob(f"{crate_name}*"))
            if possible_dirs:
                # Rename the most recently created directory
                latest_dir = max(possible_dirs, key=lambda p: p.stat().st_ctime)
                latest_dir.rename(extracted_dir)
                self.logger.debug(f"Renamed {latest_dir} to {extracted_dir}")
        
        if not extracted_dir.exists():
            raise DependencyError(
                f"Extracted directory not found for {crate_name} v{version}",
                crate_name=crate_name,
                version=version
            )
        
        self.logger.info(f"Downloaded and extracted to: {extracted_dir}")


class CrateVersionManager(LoggerMixin):
    """Manages crate version information and queries."""
    
    def __init__(self):
        self.api_base = "https://crates.io/api/v1"
        
    def get_latest_version(self, crate_name: str) -> str:
        """Get the latest version of a crate.
        
        Args:
            crate_name: Name of the crate.
            
        Returns:
            Latest version string.
            
        Raises:
            NetworkError: If API request fails.
            ValidationError: If crate name is invalid.
        """
        if not crate_name:
            raise ValidationError.invalid_crate_name(crate_name)
            
        url = f"{self.api_base}/crates/{crate_name}"
        
        try:
            response = requests.get(url, timeout=settings.crates_io_timeout)
            response.raise_for_status()
            
            data = response.json()
            return data['crate']['max_version']
            
        except requests.exceptions.RequestException as e:
            if hasattr(e, 'response') and e.response is not None:
                raise NetworkError.crates_io_unavailable(url, e.response.status_code) from e
            else:
                raise NetworkError(f"Failed to query crate info: {e}", url=url) from e
    
    def get_stable_versions(self, crate_name: str, limit: int = 10) -> List[str]:
        """Get stable versions of a crate.
        
        Args:
            crate_name: Name of the crate.
            limit: Maximum number of versions to return.
            
        Returns:
            List of stable version strings, sorted by version (descending).
            
        Raises:
            NetworkError: If API request fails.
            ValidationError: If inputs are invalid.
        """
        if not crate_name:
            raise ValidationError.invalid_crate_name(crate_name)
        if limit <= 0:
            raise ValidationError("Version limit must be positive", field_name="limit", field_value=limit)
            
        url = f"{self.api_base}/crates/{crate_name}/versions"
        
        try:
            response = requests.get(url, timeout=settings.crates_io_timeout)
            response.raise_for_status()
            
            versions_data = response.json()['versions']
            stable_versions = []
            
            for v in versions_data:
                if not v['yanked'] and not any(pre in v['num'] for pre in ['alpha', 'beta', 'rc', 'pre']):
                    stable_versions.append(v['num'])
                    
                if len(stable_versions) >= limit:
                    break
                    
            # Sort by version (newest first)
            return sorted(stable_versions, key=version.parse, reverse=True)
            
        except requests.exceptions.RequestException as e:
            if hasattr(e, 'response') and e.response is not None:
                raise NetworkError.crates_io_unavailable(url, e.response.status_code) from e
            else:
                raise NetworkError(f"Failed to query versions: {e}", url=url) from e