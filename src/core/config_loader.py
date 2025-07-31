"""Configuration loader and validator for batch library processing.

This module provides functionality to load and validate YAML configuration files
for batch library processing, including sub-library reference validation and
toolchain inheritance resolution.
"""

import re
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union, Set

import yaml

from .exceptions import (
    ConfigValidationError, 
    SubLibraryNotFoundError, 
    ToolchainVersionError,
    SignatureError
)
from .logger import LoggerMixin


class ConfigLoader(LoggerMixin):
    """Loads and validates batch library configuration files."""
    
    def __init__(self, config_path: Path, validation_mode: str = "strict"):
        """Initialize configuration loader.
        
        Args:
            config_path: Path to YAML configuration file
            validation_mode: Validation mode - "strict", "lenient", or "auto"
        """
        self.config_path = config_path
        self.validation_mode = validation_mode
        self.config_data: Dict[str, Any] = {}
        self.resolved_libraries: Dict[str, Any] = {}
        
        # Supported validation modes
        self.valid_modes = {"strict", "lenient", "auto"}
        if validation_mode not in self.valid_modes:
            raise ConfigValidationError(
                f"Invalid validation mode: {validation_mode}",
                suggestions=list(self.valid_modes)
            )
    
    def load_config(self) -> Dict[str, Any]:
        """Load and validate configuration file.
        
        Returns:
            Loaded and validated configuration data
            
        Raises:
            ConfigValidationError: If configuration is invalid
        """
        self.logger.info(f"Loading configuration from {self.config_path}")
        
        # Load YAML file
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                self.config_data = yaml.safe_load(f)
        except FileNotFoundError:
            raise ConfigValidationError(
                f"Configuration file not found: {self.config_path}",
                config_file=self.config_path
            )
        except yaml.YAMLError as e:
            raise ConfigValidationError(
                f"Invalid YAML syntax: {e}",
                config_file=self.config_path
            )
        
        # Validate configuration structure
        self._validate_config_structure()
        
        # Validate sub-library references
        self._validate_sub_library_references()
        
        # Validate toolchain configurations
        self._validate_toolchain_configurations()
        
        # Validate batch presets
        self._validate_batch_presets()
        
        self.logger.info("Configuration loaded and validated successfully")
        return self.config_data
    
    def _validate_config_structure(self) -> None:
        """Validate basic configuration file structure."""
        required_sections = ["libraries", "batch_presets"]
        
        for section in required_sections:
            if section not in self.config_data:
                available = list(self.config_data.keys())
                raise ConfigValidationError.missing_section(
                    section=section,
                    config_file=self.config_path,
                    available_sections=available
                )
        
        # Validate libraries section
        libraries = self.config_data.get("libraries", {})
        if not isinstance(libraries, dict):
            raise ConfigValidationError.invalid_field(
                field="libraries",
                section="root",
                expected_type="dict",
                actual_value=libraries,
                config_file=self.config_path
            )
        
        # Validate each library
        for lib_name, lib_config in libraries.items():
            self._validate_library_config(lib_name, lib_config)
    
    def _validate_library_config(self, lib_name: str, lib_config: Dict[str, Any]) -> None:
        """Validate individual library configuration."""
        required_fields = ["library_type", "platform"]
        
        for field in required_fields:
            if field not in lib_config:
                raise ConfigValidationError(
                    f"Missing required field '{field}' in library '{lib_name}'",
                    config_file=self.config_path,
                    section=f"libraries.{lib_name}",
                    field=field
                )
        
        # Validate library type
        valid_types = {"main", "sub"}
        lib_type = lib_config.get("library_type")
        if lib_type not in valid_types:
            raise ConfigValidationError(
                f"Invalid library_type '{lib_type}' in library '{lib_name}'",
                config_file=self.config_path,
                section=f"libraries.{lib_name}",
                field="library_type",
                suggestions=list(valid_types)
            )
        
        # Validate sub-library specific fields
        if lib_type == "sub":
            if "parent_library" not in lib_config:
                raise ConfigValidationError(
                    f"Sub-library '{lib_name}' missing required 'parent_library' field",
                    config_file=self.config_path,
                    section=f"libraries.{lib_name}",
                    field="parent_library"
                )
        
        # Validate versions array
        if "versions" in lib_config:
            versions = lib_config["versions"]
            if not isinstance(versions, list):
                raise ConfigValidationError(
                    f"Library '{lib_name}' versions must be a list",
                    config_file=self.config_path,
                    section=f"libraries.{lib_name}",
                    field="versions"
                )
    
    def _validate_sub_library_references(self) -> None:
        """Validate all sub-library references in the configuration."""
        libraries = self.config_data.get("libraries", {})
        global_sub_libs = self.config_data.get("global_sub_library_definitions", {})
        
        # Build available sub-libraries mapping for each main library
        for lib_name, lib_config in libraries.items():
            if lib_config.get("library_type") == "main":
                # Validate available_sub_libraries field
                available_subs = lib_config.get("available_sub_libraries", [])
                if available_subs:
                    self._validate_available_sub_libraries(
                        lib_name, available_subs, global_sub_libs
                    )
                
                # Validate include_sub_libraries field
                include_subs = lib_config.get("include_sub_libraries", [])
                if include_subs:
                    self._validate_include_sub_libraries(
                        lib_name, include_subs, available_subs
                    )
        
        # Validate batch preset library references
        batch_presets = self.config_data.get("batch_presets", {})
        for preset_name, preset_config in batch_presets.items():
            self._validate_preset_library_references_new(
                preset_name, preset_config, libraries
            )
    
    def _validate_available_sub_libraries(
        self, 
        lib_name: str, 
        available_subs: List[str],
        global_sub_libs: Dict[str, Any]
    ) -> None:
        """Validate available_sub_libraries references against global definitions."""
        for sub_lib in available_subs:
            if sub_lib not in global_sub_libs:
                available_global = list(global_sub_libs.keys())
                raise SubLibraryNotFoundError(
                    sub_library=sub_lib,
                    parent_library=lib_name,
                    available_sub_libraries=available_global,
                    config_file=self.config_path
                )
    
    def _validate_include_sub_libraries(
        self, 
        lib_name: str, 
        include_subs: List[str],
        available_subs: List[str]
    ) -> None:
        """Validate include_sub_libraries references against available_sub_libraries."""
        validation_config = self.config_data.get("config_validation", {})
        validate_sub_libs = validation_config.get("validate_sub_libraries", True)
        fail_on_unknown = validation_config.get("fail_on_unknown_sub_library", True)
        
        if not validate_sub_libs:
            return
        
        for sub_lib in include_subs:
            if sub_lib not in available_subs:
                if fail_on_unknown:
                    raise SubLibraryNotFoundError(
                        sub_library=sub_lib,
                        parent_library=lib_name,
                        available_sub_libraries=available_subs,
                        config_file=self.config_path
                    )
                else:
                    self.logger.warning(
                        f"Sub-library '{sub_lib}' not found in available_sub_libraries for '{lib_name}', skipping"
                    )
    
    def _validate_preset_library_references_new(
        self, 
        preset_name: str, 
        preset_config: Dict[str, Any],
        libraries: Dict[str, Any]
    ) -> None:
        """Validate library references in batch presets (new simplified structure)."""
        preset_libs = preset_config.get("libraries", [])
        available_libs = set(libraries.keys())
        
        for lib_ref in preset_libs:
            if isinstance(lib_ref, dict):
                lib_name = lib_ref.get("library")
                if lib_name and lib_name not in available_libs:
                    if self.validation_mode == "strict":
                        raise ConfigValidationError(
                            f"Unknown library '{lib_name}' in preset '{preset_name}'",
                            config_file=self.config_path,
                            section=f"batch_presets.{preset_name}.libraries",
                            field="library",
                            suggestions=list(available_libs)
                        )
                    elif self.validation_mode == "lenient":
                        self.logger.warning(
                            f"Unknown library '{lib_name}' in preset '{preset_name}', skipping"
                        )
                
                # Validate include_sub_libraries in preset if present
                include_subs = lib_ref.get("include_sub_libraries")
                if include_subs is not None and lib_name and lib_name in libraries:
                    lib_config = libraries[lib_name]
                    available_subs = lib_config.get("available_sub_libraries", [])
                    
                    # Handle both boolean (true = all) and array formats
                    if isinstance(include_subs, bool):
                        if include_subs:
                            # include_sub_libraries: true means include all available
                            self.logger.debug(
                                f"Preset '{preset_name}' library '{lib_name}' includes all sub-libraries"
                            )
                    elif isinstance(include_subs, list):
                        # Validate specific sub-library references
                        for sub_lib in include_subs:
                            if sub_lib not in available_subs:
                                if self.validation_mode == "strict":
                                    raise SubLibraryNotFoundError(
                                        sub_library=sub_lib,
                                        parent_library=lib_name,
                                        available_sub_libraries=available_subs,
                                        config_file=self.config_path
                                    )
                                elif self.validation_mode == "lenient":
                                    self.logger.warning(
                                        f"Sub-library '{sub_lib}' not found in '{lib_name}' for preset '{preset_name}', skipping"
                                    )
                    else:
                        raise ConfigValidationError(
                            f"Invalid include_sub_libraries value in preset '{preset_name}', library '{lib_name}': must be boolean or array",
                            config_file=self.config_path,
                            section=f"batch_presets.{preset_name}.libraries",
                            field="include_sub_libraries"
                        )
    
    def _validate_toolchain_configurations(self) -> None:
        """Validate toolchain configurations and inheritance."""
        libraries = self.config_data.get("libraries", {})
        
        for lib_name, lib_config in libraries.items():
            # Validate toolchain inheritance for sub-libraries
            if lib_config.get("library_type") == "sub":
                self._validate_sub_library_toolchain_inheritance(lib_name, lib_config)
            
            # Validate version-specific toolchain overrides
            versions = lib_config.get("versions", [])
            for version_config in versions:
                if "toolchain" in version_config:
                    self._validate_toolchain_fields(
                        lib_name, version_config["toolchain"]
                    )
    
    def _validate_sub_library_toolchain_inheritance(
        self, 
        lib_name: str, 
        lib_config: Dict[str, Any]
    ) -> None:
        """Validate sub-library toolchain inheritance configuration."""
        toolchain_inheritance = lib_config.get("toolchain_inheritance", {})
        
        if not toolchain_inheritance:
            return
        
        # Validate version mapping if present
        version_mapping = toolchain_inheritance.get("version_mapping", {})
        if version_mapping and not isinstance(version_mapping, dict):
            raise ToolchainVersionError(
                f"Invalid version_mapping in sub-library '{lib_name}'",
                library=lib_name,
                toolchain_field="version_mapping",
                config_file=self.config_path
            )
        
        # Validate version mapping keys and values are valid version strings
        for parent_version, sub_version in version_mapping.items():
            if not self._is_valid_version_string(parent_version):
                raise ToolchainVersionError(
                    f"Invalid parent version '{parent_version}' in version_mapping for '{lib_name}'",
                    library=lib_name,
                    version=parent_version,
                    toolchain_field="version_mapping",
                    config_file=self.config_path
                )
            
            if not self._is_valid_version_string(sub_version):
                raise ToolchainVersionError(
                    f"Invalid sub version '{sub_version}' in version_mapping for '{lib_name}'",
                    library=lib_name,
                    version=sub_version,
                    toolchain_field="version_mapping",
                    config_file=self.config_path
                )
    
    def _validate_toolchain_fields(self, lib_name: str, toolchain_config: Dict[str, Any]) -> None:
        """Validate toolchain configuration fields."""
        # Define expected toolchain fields based on platform
        expected_fields = {
            "solana_ebpf": {"solana_version", "rust_version", "cargo_build_sbf_version"},
            "x86_64": {"rust_version", "rust_channel", "targets"}
        }
        
        # For now, assume solana_ebpf platform (can be enhanced later)
        expected = expected_fields.get("solana_ebpf", set())
        
        for field in expected:
            if field in toolchain_config:
                value = toolchain_config[field]
                if field.endswith("_version") and not self._is_valid_version_string(value):
                    raise ToolchainVersionError(
                        f"Invalid {field} '{value}' in library '{lib_name}'",
                        library=lib_name,
                        version=value,
                        toolchain_field=field,
                        config_file=self.config_path
                    )
    
    def _validate_batch_presets(self) -> None:
        """Validate batch processing presets."""
        batch_presets = self.config_data.get("batch_presets", {})
        
        for preset_name, preset_config in batch_presets.items():
            if not isinstance(preset_config, dict):
                raise ConfigValidationError(
                    f"Batch preset '{preset_name}' must be a dictionary",
                    config_file=self.config_path,
                    section=f"batch_presets.{preset_name}"
                )
            
            # Library reference validation is now handled in _validate_sub_library_references
            pass
    
    def _validate_preset_library_references(
        self, 
        preset_name: str, 
        preset_config: Dict[str, Any]
    ) -> None:
        """Validate library references in batch presets (legacy method - now unused)."""
        # This method is replaced by _validate_preset_library_references_new
        # but kept for backward compatibility
        pass
    
    def _is_valid_version_string(self, version: str) -> bool:
        """Check if a version string is valid (semantic versioning)."""
        if not isinstance(version, str):
            return False
        
        # Basic semantic versioning pattern
        semver_pattern = r'^(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
        
        # Also allow simple patterns like "1.18" or "stable"
        simple_patterns = [
            r'^\d+\.\d+$',      # 1.18
            r'^\d+\.\d+\.\d+$', # 1.18.16
            r'^stable$',        # stable
            r'^beta$',          # beta
            r'^nightly$'        # nightly
        ]
        
        return (re.match(semver_pattern, version) is not None or 
                any(re.match(pattern, version) for pattern in simple_patterns))
    
    def resolve_library_configuration(
        self, 
        library_name: str, 
        version: Optional[str] = None,
        toolchain_overrides: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Resolve complete configuration for a specific library and version.
        
        Args:
            library_name: Name of the library to resolve
            version: Specific version to resolve (if None, use first available)
            toolchain_overrides: Command-line toolchain overrides
            
        Returns:
            Resolved library configuration with inheritance applied
            
        Raises:
            ConfigValidationError: If library or version not found
        """
        libraries = self.config_data.get("libraries", {})
        
        if library_name not in libraries:
            available = list(libraries.keys())
            raise ConfigValidationError(
                f"Library '{library_name}' not found",
                config_file=self.config_path,
                section="libraries",
                suggestions=available
            )
        
        lib_config = libraries[library_name].copy()
        
        # Apply toolchain inheritance for sub-libraries
        if lib_config.get("library_type") == "sub":
            lib_config = self._apply_toolchain_inheritance(lib_config, toolchain_overrides)
        
        # Apply command-line toolchain overrides (highest priority)
        if toolchain_overrides:
            lib_config["resolved_toolchain"] = toolchain_overrides.copy()
        
        return lib_config
    
    def _apply_toolchain_inheritance(
        self, 
        sub_lib_config: Dict[str, Any],
        cli_overrides: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Apply toolchain inheritance for sub-libraries."""
        parent_lib_name = sub_lib_config.get("parent_library")
        if not parent_lib_name:
            return sub_lib_config
        
        libraries = self.config_data.get("libraries", {})
        parent_config = libraries.get(parent_lib_name, {})
        
        # Get toolchain inheritance configuration
        inheritance = sub_lib_config.get("toolchain_inheritance", {})
        
        if inheritance.get("inherit_from_cli") and cli_overrides:
            # CLI overrides have highest priority
            sub_lib_config["resolved_toolchain"] = cli_overrides.copy()
        elif inheritance.get("inherit_from_parent"):
            # Inherit from parent library's recommended toolchain
            parent_toolchain = parent_config.get("recommended_toolchain", {})
            sub_lib_config["resolved_toolchain"] = parent_toolchain.copy()
        
        return sub_lib_config
    
    def get_batch_preset(self, preset_name: str) -> Dict[str, Any]:
        """Get batch processing preset by name.
        
        Args:
            preset_name: Name of the batch preset
            
        Returns:
            Batch preset configuration
            
        Raises:
            ConfigValidationError: If preset not found
        """
        batch_presets = self.config_data.get("batch_presets", {})
        
        if preset_name not in batch_presets:
            available = list(batch_presets.keys())
            raise ConfigValidationError(
                f"Batch preset '{preset_name}' not found",
                config_file=self.config_path,
                section="batch_presets",
                suggestions=available
            )
        
        return batch_presets[preset_name].copy()
    
    def list_libraries(self) -> List[str]:
        """Get list of all available libraries."""
        return list(self.config_data.get("libraries", {}).keys())
    
    def list_batch_presets(self) -> List[str]:
        """Get list of all available batch presets."""
        return list(self.config_data.get("batch_presets", {}).keys())
    
    def get_library_versions(self, library_name: str) -> List[str]:
        """Get available versions for a library.
        
        Args:
            library_name: Name of the library
            
        Returns:
            List of available versions
        """
        libraries = self.config_data.get("libraries", {})
        lib_config = libraries.get(library_name, {})
        versions = lib_config.get("versions", [])
        
        return [v.get("version") if isinstance(v, dict) else str(v) for v in versions]