"""IDA Pro .til file generator using IDAClang.

This module integrates IDAClang functionality for generating optimized
.til type library files from C++ headers.
"""

import subprocess
from pathlib import Path
from typing import Dict, Optional, Tuple

from ..core.config import settings
from ..core.logger import LoggerMixin
from ..core.exceptions import GenerationError, ValidationError


class TilGeneratorConfig:
    """Configuration for .til file generation."""
    
    def __init__(self):
        # IDA Pro tool paths
        self.idaclang_path = "/Applications/IDA Professional 9.1.app/Contents/MacOS/tools/idaclang/idaclang"
        self.tilib_path = "/Applications/IDA Professional 9.1.app/Contents/MacOS/tools/tilib/tilib"
        
        # IDA Pro standard paths
        self.ida_til_dir = "/Applications/IDA Professional 9.1.app/Contents/MacOS/til/rust"
        
        # Compilation targets
        self.default_target = "x86_64-unknown-linux-gnu"
        self.target_suffix_map = {
            "x86_64-unknown-linux-gnu": "gnulnx_x64",
            "x86_64-pc-windows-gnu": "win64_x64",
            "x86_64-apple-darwin": "darwin_x64"
        }


class TilGenerator(LoggerMixin):
    """Generate IDA Pro .til files from C++ headers using IDAClang."""
    
    def __init__(self, config: Optional[TilGeneratorConfig] = None):
        super().__init__()
        self.config = config or TilGeneratorConfig()
        self._validate_tools()
    
    def _validate_tools(self):
        """Validate that required IDA Pro tools are available."""
        if not Path(self.config.idaclang_path).exists():
            raise ValidationError(
                f"IDAClang not found: {self.config.idaclang_path}",
                field_name="idaclang_path",
                field_value=self.config.idaclang_path
            )
        
        if not Path(self.config.tilib_path).exists():
            raise ValidationError(
                f"tilib not found: {self.config.tilib_path}",
                field_name="tilib_path", 
                field_value=self.config.tilib_path
            )
        
        self.logger.debug("IDA Pro tools validation successful")
    
    def generate_til_file(
        self,
        header_file: Path,
        output_path: Path,
        lib_name: str,
        lib_version: str,
        target: str = None
    ) -> Dict[str, any]:
        """
        Generate .til file from C++ header using IDAClang.
        
        Args:
            header_file: Path to the C++ header file (.hpp)
            output_path: Path where .til file should be created
            lib_name: Name of the library for description
            lib_version: Version of the library
            target: Target architecture (defaults to Linux x64)
            
        Returns:
            Dictionary with generation results and statistics
            
        Raises:
            ValidationError: If inputs are invalid
            GenerationError: If .til generation fails
        """
        if not header_file.exists():
            raise ValidationError(
                f"Header file not found: {header_file}",
                field_name="header_file",
                field_value=str(header_file)
            )
        
        target = target or self.config.default_target
        
        # Ensure output directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Generate description
        description = f"{lib_name} Library v{lib_version} for {target}"
        
        self.logger.info(f"Generating .til file: {output_path.name}")
        self.logger.debug(f"Source header: {header_file}")
        self.logger.debug(f"Target: {target}")
        
        try:
            # Build IDAClang command
            cmd = [
                self.config.idaclang_path,
                "-target", target,
                "-x", "c++",
                "-std=c++11",
                "--idaclang-tilname", str(output_path),
                "--idaclang-tildesc", description,
                str(header_file)
            ]
            
            self.logger.debug(f"IDAClang command: {' '.join(cmd)}")
            
            # Execute IDAClang
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=300  # 5 minute timeout
            )
            
            # Check if .til file was created
            if not output_path.exists():
                raise GenerationError(
                    f"IDAClang completed but .til file not found: {output_path}",
                    source_path=header_file,
                    target_path=output_path
                )
            
            # Analyze generated .til file
            analysis = self._analyze_til_file(output_path)
            
            # Prepare results
            results = {
                'til_file': output_path,
                'description': description,
                'target': target,
                'header_source': header_file,
                'analysis': analysis,
                'idaclang_output': result.stdout,
                'warnings': result.stderr if result.stderr else None
            }
            
            self.logger.info(f"✅ .til file generated successfully: {output_path.name}")
            if analysis:
                self.logger.info(f"   📊 Symbols: {analysis.get('symbols', 0)}, "
                               f"Size: {analysis.get('size_human', 'unknown')}")
                
            return results
            
        except subprocess.TimeoutExpired as e:
            raise GenerationError(
                f"IDAClang timed out after 300 seconds",
                source_path=header_file,
                target_path=output_path
            ) from e
            
        except subprocess.CalledProcessError as e:
            raise GenerationError(
                f"IDAClang failed: {e.stderr}",
                source_path=header_file,
                target_path=output_path,
                stderr=e.stderr,
                returncode=e.returncode
            ) from e
    
    def _analyze_til_file(self, til_path: Path) -> Optional[Dict[str, any]]:
        """Analyze .til file content using tilib."""
        try:
            result = subprocess.run(
                [self.config.tilib_path, "-l", str(til_path)],
                capture_output=True,
                text=True,
                check=True,
                timeout=30
            )
            
            lines = result.stdout.split('\n')
            
            # Count symbols and structures
            symbol_count = len([line for line in lines if line and line[0].isdigit()])
            struct_count = len([line for line in lines if 'struct' in line])
            
            # Get file size
            file_size = til_path.stat().st_size
            size_human = (f"{file_size/1024:.1f}K" if file_size < 1024*1024 
                         else f"{file_size/(1024*1024):.1f}M")
            
            return {
                'symbols': symbol_count,
                'structs': struct_count,
                'size_bytes': file_size,
                'size_human': size_human,
                'tilib_output': result.stdout
            }
            
        except Exception as e:
            self.logger.warning(f"Failed to analyze .til file: {e}")
            return None
    
    def generate_til_to_ida_location(
        self,
        header_file: Path,
        lib_name: str,
        lib_version: str,
        target: str = None
    ) -> Dict[str, any]:
        """
        Generate .til file directly to IDA Pro standard location.
        
        Args:
            header_file: Path to the C++ header file
            lib_name: Name of the library
            lib_version: Version of the library
            target: Target architecture
            
        Returns:
            Dictionary with generation results
        """
        target = target or self.config.default_target
        target_suffix = self.config.target_suffix_map.get(target, "unknown")
        
        # Generate .til filename following IDA conventions with version
        # Convert version to filename-safe format (replace dots and dashes with underscores)
        version_safe = lib_version.replace('.', '_').replace('-', '_')
        til_filename = f"rust_{lib_name}_v{version_safe}_{target_suffix}.til"
        til_path = Path(self.config.ida_til_dir) / til_filename
        
        # Ensure IDA til directory exists
        try:
            til_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Test write permissions
            test_file = til_path.parent / ".write_test"
            test_file.touch()
            test_file.unlink()
            
        except PermissionError:
            self.logger.warning(f"No write permission to IDA til directory: {til_path.parent}")
            # Fallback to project data directory
            fallback_dir = Path(settings.output_dir) / "til"
            fallback_dir.mkdir(parents=True, exist_ok=True)
            til_path = fallback_dir / til_filename
            self.logger.info(f"Using fallback location: {til_path}")
        
        # Generate .til file
        return self.generate_til_file(header_file, til_path, lib_name, lib_version, target)
    
    def batch_generate_til_files(
        self,
        headers_config: Dict[str, Dict[str, any]],
        target: str = None
    ) -> Dict[str, Dict[str, any]]:
        """
        Generate multiple .til files in batch.
        
        Args:
            headers_config: Dictionary mapping lib_name to config dict with:
                - header_file: Path to header file
                - version: Library version
                - lib_name: Library name (optional, uses key if not provided)
            target: Target architecture
            
        Returns:
            Dictionary mapping lib_name to generation results
        """
        target = target or self.config.default_target
        results = {}
        
        self.logger.info(f"Batch generating {len(headers_config)} .til files")
        
        for lib_name, config in headers_config.items():
            try:
                self.logger.info(f"Processing {lib_name}...")
                
                header_file = Path(config['header_file'])
                version = config['version']
                actual_lib_name = config.get('lib_name', lib_name)
                
                result = self.generate_til_to_ida_location(
                    header_file=header_file,
                    lib_name=actual_lib_name,
                    lib_version=version,
                    target=target
                )
                
                results[lib_name] = {
                    'success': True,
                    'result': result
                }
                
            except Exception as e:
                self.logger.error(f"Failed to generate .til for {lib_name}: {e}")
                results[lib_name] = {
                    'success': False,
                    'error': str(e)
                }
        
        # Generate summary
        success_count = sum(1 for r in results.values() if r['success'])
        self.logger.info(f"Batch generation completed: {success_count}/{len(headers_config)} successful")
        
        return results
    
    def validate_til_file(self, til_path: Path) -> bool:
        """
        Validate that a .til file is properly formatted.
        
        Args:
            til_path: Path to the .til file
            
        Returns:
            True if valid, False otherwise
        """
        if not til_path.exists():
            return False
        
        try:
            # Check file magic (IDA .til files start with 'IDATIL')
            with open(til_path, 'rb') as f:
                magic = f.read(6)
                if magic != b'IDATIL':
                    return False
            
            # Try to analyze with tilib
            analysis = self._analyze_til_file(til_path)
            if analysis and analysis.get('symbols', 0) > 0:
                return True
            
            return False
            
        except Exception as e:
            self.logger.warning(f"Validation failed for {til_path}: {e}")
            return False
    
    def get_til_info(self, til_path: Path) -> Optional[Dict[str, any]]:
        """
        Get information about a .til file.
        
        Args:
            til_path: Path to the .til file
            
        Returns:
            Dictionary with .til file information, or None if analysis fails
        """
        if not self.validate_til_file(til_path):
            return None
        
        return self._analyze_til_file(til_path)