"""Configuration management for Rust x86_64 IDA signatures generator.

This module provides centralized configuration management using Pydantic
for environment variable handling and validation.
"""

import os
from pathlib import Path
from typing import Dict, List, Optional

from pydantic import Field, validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings from environment variables and defaults."""
    
    # Rust compilation configuration
    rust_version: str = Field("1.84.1", env="RUST_VERSION")
    target_arch: str = Field("x86_64-unknown-linux-gnu", env="TARGET_ARCH")
    
    # IDA FLAIR tools configuration
    flair_dir: Optional[Path] = Field(None, env="FLAIR_DIR")
    pelf_path: Optional[Path] = None
    sigmake_path: Optional[Path] = None
    
    # Project directories
    data_dir: Path = Field(Path("data"), env="DATA_DIR")
    workspace_dir: Path = Field(Path("data/projects"), env="WORKSPACE_DIR")
    cache_dir: Path = Field(Path("data/cache"), env="CACHE_DIR")
    output_dir: Path = Field(Path("data/signatures"), env="OUTPUT_DIR")
    dependencies_dir: Path = Field(Path("data/dependencies"), env="DEPENDENCIES_DIR")
    compiled_dir: Path = Field(Path("data/compiled"), env="COMPILED_DIR")
    
    # Build configuration
    debug_info: bool = Field(True, env="DEBUG_INFO")
    optimization_level: int = Field(2, env="OPT_LEVEL")
    parallel_jobs: int = Field(4, env="PARALLEL_JOBS")
    
    # Logging configuration
    log_level: str = Field("INFO", env="LOG_LEVEL")
    log_file: Optional[Path] = Field(Path("logs/signatures.log"), env="LOG_FILE")
    
    # Cache settings
    enable_cache: bool = Field(True, env="ENABLE_CACHE")
    cache_ttl_hours: int = Field(24, env="CACHE_TTL_HOURS")
    
    # Network settings
    crates_io_timeout: int = Field(30, env="CRATES_IO_TIMEOUT")
    max_retries: int = Field(3, env="MAX_RETRIES")
    
    @validator('flair_dir')
    def validate_flair_dir(cls, v: Optional[Path]) -> Optional[Path]:
        """Validate and auto-detect FLAIR directory if not provided."""
        if v is not None:
            return v
            
        # Auto-detect common FLAIR installation paths
        possible_paths = [
            Path("/Applications/IDA Professional 9.1.app/Contents/MacOS/tools/flair"),
            Path("/Applications/IDA Pro 9.0.app/Contents/MacOS/tools/flair"),
            Path("/opt/ida/flair"),
            Path("./flair"),
        ]
        
        for path in possible_paths:
            if path.exists() and (path / "pelf").exists():
                return path
                
        return None
    
    @validator('optimization_level')
    def validate_optimization_level(cls, v: int) -> int:
        """Validate optimization level is in valid range."""
        if not 0 <= v <= 3:
            raise ValueError("Optimization level must be between 0 and 3")
        return v
    
    @validator('parallel_jobs')
    def validate_parallel_jobs(cls, v: int) -> int:
        """Validate parallel jobs is positive."""
        if v <= 0:
            raise ValueError("Parallel jobs must be positive")
        return min(v, os.cpu_count() or 4)  # Cap at CPU count
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        
        # Set up FLAIR tool paths after initialization
        if self.flair_dir:
            self.pelf_path = self.flair_dir / "pelf"
            self.sigmake_path = self.flair_dir / "sigmake"
    
    def create_directories(self) -> None:
        """Create all necessary directories."""
        directories = [
            self.workspace_dir,
            self.cache_dir,
            self.output_dir,
            self.dependencies_dir,
            self.compiled_dir,
            self.compiled_dir / "rlibs",
            self.compiled_dir / "objects",
            self.output_dir / "pat",
            self.output_dir / "sig",
        ]
        
        if self.log_file:
            directories.append(self.log_file.parent)
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
    
    def get_rust_target_dir(self, project_name: str) -> Path:
        """Get the Rust target directory for a project."""
        return self.workspace_dir / project_name / "target" / self.target_arch / "release"
    
    def get_deps_dir(self, project_name: str) -> Path:
        """Get the dependencies directory for a compiled project."""
        return self.get_rust_target_dir(project_name) / "deps"
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


# Global settings instance
settings = Settings()