"""Rust project builder for signature generation.

This module handles the compilation of Rust projects with specific configurations
optimized for signature extraction and analysis.
"""

import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

from ..core.config import settings
from ..core.exceptions import BuildError, ValidationError, handle_subprocess_error
from ..core.logger import LoggerMixin, log_execution_time


class RustBuilder(LoggerMixin):
    """Builds Rust projects with configurations optimized for signature extraction."""
    
    def __init__(
        self, 
        rust_version: Optional[str] = None, 
        target: Optional[str] = None
    ):
        self.rust_version = rust_version or settings.rust_version
        self.target = target or settings.target_arch
        
        # Validate Rust installation
        self._validate_rust_installation()
    
    def _validate_rust_installation(self) -> None:
        """Validate that Rust is properly installed and configured."""
        try:
            # Check rustc version for specific toolchain
            result = subprocess.run(
                ["rustup", "run", self.rust_version, "rustc", "--version"],
                capture_output=True,
                text=True,
                check=True
            )
            
            installed_version = result.stdout.strip()
            self.logger.info(f"Rust installation found: {installed_version}")
            
            # Check if target is installed for specific toolchain
            result = subprocess.run(
                ["rustup", "target", "list", "--installed", "--toolchain", self.rust_version],
                capture_output=True,
                text=True,
                check=True
            )
            
            installed_targets = result.stdout.strip().split('\n')
            if self.target not in installed_targets:
                self.logger.warning(f"Target {self.target} not installed, attempting to add...")
                self._install_target()
            else:
                self.logger.debug(f"Target {self.target} is available")
                
        except subprocess.CalledProcessError as e:
            raise BuildError(
                f"Rust validation failed: {e.stderr}",
                stderr=e.stderr,
                returncode=e.returncode
            ) from e
        except FileNotFoundError as e:
            raise BuildError(
                "Rust not found. Please install Rust via rustup: https://rustup.rs/"
            ) from e
    
    def _install_target(self) -> None:
        """Install the required target architecture."""
        try:
            subprocess.run(
                ["rustup", "target", "add", self.target, "--toolchain", self.rust_version],
                check=True,
                capture_output=True,
                text=True
            )
            self.logger.info(f"Successfully installed target {self.target}")
            
        except subprocess.CalledProcessError as e:
            raise BuildError(
                f"Failed to install target {self.target}: {e.stderr}",
                stderr=e.stderr,
                returncode=e.returncode
            ) from e
    
    @log_execution_time
    def build_project(
        self, 
        project_dir: Path,
        profile: str = "release",
        additional_flags: Optional[List[str]] = None
    ) -> Path:
        """Build a Rust project and return the dependencies directory.
        
        Args:
            project_dir: Path to the Rust project directory.
            profile: Build profile ("release" or "debug").
            additional_flags: Additional cargo build flags.
            
        Returns:
            Path to the compiled dependencies directory.
            
        Raises:
            BuildError: If compilation fails.
            ValidationError: If inputs are invalid.
        """
        if not project_dir.exists():
            raise ValidationError(
                f"Project directory does not exist: {project_dir}",
                field_name="project_dir",
                field_value=str(project_dir)
            )
        
        if not (project_dir / "Cargo.toml").exists():
            raise ValidationError(
                f"Cargo.toml not found in project directory: {project_dir}",
                field_name="project_dir",
                field_value=str(project_dir)
            )
        
        self.logger.info(f"Building Rust project: {project_dir}")
        
        # Build command with specific Rust version
        cmd = [
            "rustup", "run", self.rust_version, "cargo", "build",
            f"--{profile}",
            "--target", self.target,
            "--verbose"
        ]
        
        # Add additional flags
        if additional_flags:
            cmd.extend(additional_flags)
        
        # Add parallel jobs if specified
        if settings.parallel_jobs > 1:
            cmd.extend(["-j", str(settings.parallel_jobs)])
        
        try:
            result = subprocess.run(
                cmd,
                cwd=project_dir,
                capture_output=True,
                text=True,
                check=True,
                timeout=600  # 10 minute timeout for builds
            )
            
            self.logger.debug(f"Build output: {result.stdout}")
            
            # Determine output directory
            deps_dir = project_dir / "target" / self.target / profile / "deps"
            
            if not deps_dir.exists():
                raise BuildError(
                    f"Dependencies directory not found: {deps_dir}",
                    project_path=project_dir
                )
            
            # Count generated files
            rlib_files = list(deps_dir.glob("*.rlib"))
            self.logger.info(
                f"Build successful: {len(rlib_files)} .rlib files generated in {deps_dir}"
            )
            
            return deps_dir
            
        except subprocess.TimeoutExpired as e:
            raise BuildError(
                f"Build timed out after 600 seconds",
                project_path=project_dir
            ) from e
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Build failed for {project_dir}: {e.stderr}")
            raise handle_subprocess_error(e, cmd, project_dir)
    
    def clean_project(self, project_dir: Path) -> None:
        """Clean build artifacts from a project.
        
        Args:
            project_dir: Path to the Rust project directory.
            
        Raises:
            BuildError: If cleaning fails.
        """
        if not project_dir.exists():
            return  # Nothing to clean
        
        self.logger.info(f"Cleaning project: {project_dir}")
        
        cmd = ["cargo", "clean"]
        
        try:
            subprocess.run(
                cmd,
                cwd=project_dir,
                check=True,
                capture_output=True,
                text=True
            )
            
            self.logger.debug(f"Project cleaned: {project_dir}")
            
        except subprocess.CalledProcessError as e:
            raise handle_subprocess_error(e, cmd, project_dir)
    
    def get_build_info(self, project_dir: Path) -> Dict[str, str]:
        """Get build information for a project.
        
        Args:
            project_dir: Path to the Rust project directory.
            
        Returns:
            Dictionary containing build information.
            
        Raises:
            BuildError: If unable to get build info.
        """
        if not project_dir.exists():
            raise ValidationError(
                f"Project directory does not exist: {project_dir}",
                field_name="project_dir",
                field_value=str(project_dir)
            )
        
        info = {
            "rust_version": self.rust_version,
            "target": self.target,
            "project_dir": str(project_dir),
        }
        
        # Get Cargo.toml info
        cargo_toml = project_dir / "Cargo.toml"
        if cargo_toml.exists():
            try:
                import toml
                cargo_data = toml.load(cargo_toml)
                info.update({
                    "package_name": cargo_data.get("package", {}).get("name", "unknown"),
                    "package_version": cargo_data.get("package", {}).get("version", "unknown"),
                    "edition": cargo_data.get("package", {}).get("edition", "unknown"),
                })
            except Exception as e:
                self.logger.warning(f"Failed to parse Cargo.toml: {e}")
        
        # Get dependency count
        try:
            cmd = ["cargo", "tree", "--depth", "1"]
            result = subprocess.run(
                cmd,
                cwd=project_dir,
                capture_output=True,
                text=True,
                check=True
            )
            
            dep_lines = [line for line in result.stdout.split('\n') if line.strip() and not line.startswith(' ')]
            info["dependency_count"] = str(len(dep_lines) - 1)  # Exclude root package
            
        except subprocess.CalledProcessError:
            info["dependency_count"] = "unknown"
        
        return info
    
    def check_dependencies(self, project_dir: Path) -> List[str]:
        """Check project dependencies and return any issues.
        
        Args:
            project_dir: Path to the Rust project directory.
            
        Returns:
            List of dependency issues found.
        """
        issues = []
        
        if not project_dir.exists():
            issues.append(f"Project directory does not exist: {project_dir}")
            return issues
        
        # Check Cargo.toml
        cargo_toml = project_dir / "Cargo.toml"
        if not cargo_toml.exists():
            issues.append("Cargo.toml not found")
            return issues
        
        # Check cargo check
        try:
            cmd = ["cargo", "check", "--target", self.target]
            result = subprocess.run(
                cmd,
                cwd=project_dir,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode != 0:
                issues.append(f"cargo check failed: {result.stderr}")
            
        except subprocess.TimeoutExpired:
            issues.append("cargo check timed out")
        except Exception as e:
            issues.append(f"Failed to run cargo check: {e}")
        
        return issues


class TemporaryRustProject(LoggerMixin):
    """Context manager for temporary Rust projects."""
    
    def __init__(
        self, 
        project_name: str,
        dependencies: Dict[str, str],
        builder: Optional[RustBuilder] = None
    ):
        self.project_name = project_name
        self.dependencies = dependencies
        self.builder = builder or RustBuilder()
        self.project_dir: Optional[Path] = None
        self.temp_dir: Optional[tempfile.TemporaryDirectory] = None
    
    def __enter__(self) -> Path:
        """Create temporary project and return its path."""
        self.temp_dir = tempfile.TemporaryDirectory(prefix=f"{self.project_name}_")
        temp_path = Path(self.temp_dir.name)
        
        self.project_dir = temp_path / self.project_name
        self.project_dir.mkdir()
        
        # Create Cargo.toml
        self._create_cargo_toml()
        
        # Create lib.rs
        self._create_lib_rs()
        
        self.logger.info(f"Created temporary Rust project: {self.project_dir}")
        return self.project_dir
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Clean up temporary project."""
        if self.temp_dir:
            self.temp_dir.cleanup()
            self.logger.debug(f"Cleaned up temporary project: {self.project_name}")
    
    def _create_cargo_toml(self) -> None:
        """Create Cargo.toml for the temporary project."""
        deps_section = "\n".join([
            f'{dep} = "{version}"' for dep, version in self.dependencies.items()
        ])
        
        cargo_toml = f'''[package]
name = "{self.project_name.replace('-', '_')}"
version = "0.1.0"
edition = "2021"

[dependencies]
{deps_section}

[profile.release]
debug = true
opt-level = {settings.optimization_level}
lto = false
'''
        
        (self.project_dir / "Cargo.toml").write_text(cargo_toml)
    
    def _create_lib_rs(self) -> None:
        """Create minimal lib.rs for the temporary project."""
        src_dir = self.project_dir / "src"
        src_dir.mkdir()
        
        lib_rs = '''//! Temporary library for signature generation
pub fn dummy_function() {
    println!("Library loaded for signature extraction");
}
'''
        
        (src_dir / "lib.rs").write_text(lib_rs)