"""Custom exceptions for Rust x86_64 IDA signatures generator.

This module defines a hierarchy of exceptions specific to the signature
generation process, providing clear error context and handling.
"""

from pathlib import Path
from typing import Dict, List, Optional, Any


class SignatureError(Exception):
    """Base exception for all signature generation related errors."""
    
    def __init__(self, message: str, context: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.context = context or {}


class ConfigurationError(SignatureError):
    """Configuration or setup related errors."""
    
    def __init__(self, message: str, config_key: Optional[str] = None):
        super().__init__(message)
        self.config_key = config_key


class BuildError(SignatureError):
    """Rust build process failures."""
    
    def __init__(
        self, 
        message: str, 
        project_path: Optional[Path] = None,
        stderr: Optional[str] = None,
        returncode: Optional[int] = None
    ):
        super().__init__(message)
        self.project_path = project_path
        self.stderr = stderr
        self.returncode = returncode
        
    def __str__(self) -> str:
        parts = [super().__str__()]
        
        if self.project_path:
            parts.append(f"Project: {self.project_path}")
        
        if self.returncode is not None:
            parts.append(f"Return code: {self.returncode}")
            
        if self.stderr:
            parts.append(f"Stderr: {self.stderr}")
            
        return "\n".join(parts)


class DependencyError(SignatureError):
    """Dependency resolution and management errors."""
    
    def __init__(
        self, 
        message: str, 
        crate_name: Optional[str] = None,
        version: Optional[str] = None,
        dependency_chain: Optional[List[str]] = None
    ):
        super().__init__(message)
        self.crate_name = crate_name
        self.version = version
        self.dependency_chain = dependency_chain or []


class ExtractionError(SignatureError):
    """File extraction and processing errors."""
    
    def __init__(
        self, 
        message: str, 
        source_file: Optional[Path] = None,
        rlib_path: Optional[Path] = None,
        extracted_count: int = 0
    ):
        super().__init__(message)
        self.source_file = source_file
        self.rlib_path = rlib_path
        self.extracted_count = extracted_count


class GenerationError(SignatureError):
    """Code generation and compilation errors."""
    
    def __init__(
        self, 
        message: str, 
        source_path: Optional[Path] = None,
        target_path: Optional[Path] = None,
        stderr: Optional[str] = None,
        returncode: Optional[int] = None
    ):
        super().__init__(message)
        self.source_path = source_path
        self.target_path = target_path
        self.stderr = stderr
        self.returncode = returncode


class FLAIRToolError(SignatureError):
    """IDA FLAIR tools execution errors."""
    
    def __init__(
        self, 
        message: str, 
        tool_name: Optional[str] = None,
        tool_path: Optional[Path] = None,
        command: Optional[List[str]] = None,
        stderr: Optional[str] = None
    ):
        super().__init__(message)
        self.tool_name = tool_name
        self.tool_path = tool_path
        self.command = command
        self.stderr = stderr
        
    @classmethod
    def tool_not_found(cls, tool_name: str, expected_path: Path) -> "FLAIRToolError":
        """Create exception for missing FLAIR tool."""
        return cls(
            f"FLAIR tool '{tool_name}' not found at expected path: {expected_path}",
            tool_name=tool_name,
            tool_path=expected_path
        )
    
    @classmethod
    def execution_failed(
        cls, 
        tool_name: str, 
        command: List[str], 
        returncode: int, 
        stderr: str
    ) -> "FLAIRToolError":
        """Create exception for FLAIR tool execution failure."""
        return cls(
            f"FLAIR tool '{tool_name}' failed with return code {returncode}",
            tool_name=tool_name,
            command=command,
            stderr=stderr
        )


class SignatureGenerationError(SignatureError):
    """Signature generation process errors."""
    
    def __init__(
        self, 
        message: str, 
        stage: Optional[str] = None,
        input_files: Optional[List[Path]] = None,
        output_file: Optional[Path] = None
    ):
        super().__init__(message)
        self.stage = stage
        self.input_files = input_files or []
        self.output_file = output_file


class ValidationError(SignatureError):
    """Input validation and data integrity errors."""
    
    def __init__(
        self, 
        message: str, 
        field_name: Optional[str] = None,
        field_value: Optional[Any] = None,
        expected_type: Optional[type] = None
    ):
        super().__init__(message)
        self.field_name = field_name
        self.field_value = field_value
        self.expected_type = expected_type
        
    @classmethod
    def invalid_crate_name(cls, crate_name: str) -> "ValidationError":
        """Create exception for invalid crate name."""
        return cls(
            f"Invalid crate name: {crate_name}",
            field_name="crate_name",
            field_value=crate_name,
            expected_type=str
        )
    
    @classmethod
    def invalid_version(cls, version: str) -> "ValidationError":
        """Create exception for invalid version string."""
        return cls(
            f"Invalid version format: {version}",
            field_name="version",
            field_value=version,
            expected_type=str
        )


class CacheError(SignatureError):
    """Cache operations and management errors."""
    
    def __init__(
        self, 
        message: str, 
        cache_key: Optional[str] = None,
        cache_path: Optional[Path] = None
    ):
        super().__init__(message)
        self.cache_key = cache_key
        self.cache_path = cache_path


class NetworkError(SignatureError):
    """Network operations and API access errors."""
    
    def __init__(
        self, 
        message: str, 
        url: Optional[str] = None,
        status_code: Optional[int] = None,
        response_text: Optional[str] = None
    ):
        super().__init__(message)
        self.url = url
        self.status_code = status_code
        self.response_text = response_text
        
    @classmethod
    def crates_io_unavailable(cls, url: str, status_code: int) -> "NetworkError":
        """Create exception for crates.io API failures."""
        return cls(
            f"crates.io API unavailable (HTTP {status_code})",
            url=url,
            status_code=status_code
        )


class PermissionError(SignatureError):
    """File system permission and access errors."""
    
    def __init__(
        self, 
        message: str, 
        path: Optional[Path] = None,
        operation: Optional[str] = None
    ):
        super().__init__(message)
        self.path = path
        self.operation = operation


def handle_subprocess_error(
    e: Exception, 
    command: List[str], 
    cwd: Optional[Path] = None
) -> SignatureError:
    """Convert subprocess errors to appropriate SignatureError subclasses.
    
    Args:
        e: Original subprocess exception.
        command: Command that was executed.
        cwd: Working directory where command was run.
        
    Returns:
        Appropriate SignatureError subclass instance.
    """
    import subprocess
    
    if isinstance(e, subprocess.CalledProcessError):
        stderr = e.stderr or ""
        
        # Detect specific error types based on command and stderr
        if command[0] == "cargo":
            return BuildError(
                f"Cargo command failed: {' '.join(command)}",
                project_path=cwd,
                stderr=stderr,
                returncode=e.returncode
            )
        elif command[0] in ["pelf", "sigmake"]:
            return FLAIRToolError.execution_failed(
                tool_name=command[0],
                command=command,
                returncode=e.returncode,
                stderr=stderr
            )
        else:
            return SignatureError(
                f"Command failed: {' '.join(command)}",
                context={
                    "command": command,
                    "cwd": str(cwd) if cwd else None,
                    "returncode": e.returncode,
                    "stderr": stderr
                }
            )
    elif isinstance(e, FileNotFoundError):
        return ValidationError(
            f"Command not found: {command[0]}",
            field_name="command",
            field_value=command[0]
        )
    else:
        return SignatureError(
            f"Unexpected error running command: {e}",
            context={
                "command": command,
                "cwd": str(cwd) if cwd else None,
                "exception_type": type(e).__name__
            }
        )