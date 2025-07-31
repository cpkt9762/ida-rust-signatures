"""Platform-specific modules for different target architectures.

This package contains platform-specific implementations for:
- x86_64: Traditional x86_64 Linux targets
- solana_ebpf: Solana eBPF blockchain programs
"""

from enum import Enum
from typing import Dict, Type, Any


class Platform(Enum):
    """Supported target platforms."""
    X86_64 = "x86_64"
    SOLANA_EBPF = "solana_ebpf"


class PlatformRegistry:
    """Registry for platform-specific implementations."""
    
    _platforms: Dict[Platform, Dict[str, Type]] = {}
    
    @classmethod
    def register_platform(cls, platform: Platform, component_type: str, implementation: Type):
        """Register a platform-specific implementation."""
        if platform not in cls._platforms:
            cls._platforms[platform] = {}
        cls._platforms[platform][component_type] = implementation
    
    @classmethod
    def get_implementation(cls, platform: Platform, component_type: str) -> Type:
        """Get platform-specific implementation."""
        if platform not in cls._platforms:
            raise ValueError(f"Platform {platform} not registered")
        if component_type not in cls._platforms[platform]:
            raise ValueError(f"Component {component_type} not found for platform {platform}")
        return cls._platforms[platform][component_type]
    
    @classmethod
    def list_platforms(cls) -> list[Platform]:
        """List all registered platforms."""
        return list(cls._platforms.keys())


__all__ = ["Platform", "PlatformRegistry"]