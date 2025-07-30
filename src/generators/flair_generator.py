"""IDA FLAIR signature generator using official FLAIR tools.

This module provides the primary signature generation approach using
IDA Pro's official FLAIR tools (pelf and sigmake).
"""

import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional, Dict, Any

from ..core.config import settings
from ..core.exceptions import FLAIRToolError, SignatureGenerationError, ValidationError
from ..core.logger import LoggerMixin, log_execution_time


class FLAIRGenerator(LoggerMixin):
    """Generates IDA FLIRT signatures using official FLAIR tools."""
    
    def __init__(self, flair_dir: Optional[Path] = None):
        # Auto-detect or use provided FLAIR directory
        if flair_dir is None:
            flair_dir = self._detect_flair_path()
        
        self.flair_dir = flair_dir
        self.pelf_path = flair_dir / "pelf"
        self.sigmake_path = flair_dir / "sigmake"
        
        # Validate tools are available
        self._validate_tools()
        
        self.logger.info(f"FLAIR generator initialized with tools at: {flair_dir}")
    
    def _detect_flair_path(self) -> Path:
        """Auto-detect FLAIR tools installation path."""
        # Use configured path if available
        if settings.flair_dir and settings.flair_dir.exists():
            return settings.flair_dir
        
        # Common installation paths
        possible_paths = [
            Path("/Applications/IDA Professional 9.1.app/Contents/MacOS/tools/flair"),
            Path("/Applications/IDA Pro 9.0.app/Contents/MacOS/tools/flair"), 
            Path("/Applications/IDA Professional 8.4.app/Contents/MacOS/tools/flair"),
            Path("/opt/ida/flair"),
            Path("/usr/local/ida/flair"),
            Path("./flair"),
            Path("../flair"),
        ]
        
        for path in possible_paths:
            if path.exists() and (path / "pelf").exists() and (path / "sigmake").exists():
                self.logger.info(f"Auto-detected FLAIR tools at: {path}")
                return path
        
        raise FLAIRToolError(
            "FLAIR tools not found. Please install IDA Pro with FLAIR tools or set FLAIR_DIR environment variable."
        )
    
    def _validate_tools(self) -> None:
        """Validate that required FLAIR tools exist and are executable."""
        for tool_name, tool_path in [("pelf", self.pelf_path), ("sigmake", self.sigmake_path)]:
            if not tool_path.exists():
                raise FLAIRToolError.tool_not_found(tool_name, tool_path)
            
            if not tool_path.is_file():
                raise FLAIRToolError(
                    f"FLAIR tool is not a regular file: {tool_path}",
                    tool_name=tool_name,
                    tool_path=tool_path
                )
            
            # Test tool executability
            try:
                result = subprocess.run(
                    [str(tool_path)],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                # pelf and sigmake return non-zero when run without args, which is expected
                self.logger.debug(f"Tool {tool_name} is executable")
                
            except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                raise FLAIRToolError(
                    f"FLAIR tool {tool_name} is not executable: {e}",
                    tool_name=tool_name,
                    tool_path=tool_path
                ) from e
    
    @log_execution_time
    def generate_pat(
        self, 
        object_files: List[Path], 
        output_pat: Path, 
        lib_name: str = "",
        additional_args: Optional[List[str]] = None
    ) -> Path:
        """Generate PAT file from object files using pelf.
        
        Args:
            object_files: List of object file paths to process.
            output_pat: Output path for the PAT file.
            lib_name: Library name for the signature.
            additional_args: Additional command-line arguments for pelf.
            
        Returns:
            Path to the generated PAT file.
            
        Raises:
            FLAIRToolError: If pelf execution fails.
            ValidationError: If inputs are invalid.
        """
        if not object_files:
            raise ValidationError(
                "No object files provided for PAT generation",
                field_name="object_files",
                field_value=[]
            )
        
        # Validate all object files exist
        missing_files = [f for f in object_files if not f.exists()]
        if missing_files:
            raise ValidationError(
                f"Object files not found: {missing_files}",
                field_name="object_files",
                field_value=missing_files
            )
        
        self.logger.info(f"Generating PAT file: {output_pat}")
        self.logger.info(f"Processing {len(object_files)} object files")
        
        # Ensure output directory exists
        output_pat.parent.mkdir(parents=True, exist_ok=True)
        
        # Build pelf command
        cmd = [str(self.pelf_path)]
        
        # Add standard options for x86_64 ELF files
        cmd.extend([
            "-B32",        # 32-byte pattern start
            "-r8192",      # Maximum relocations
        ])
        
        # Add library name if specified
        if lib_name:
            cmd.append(f"-n{lib_name}")
        
        # Add additional arguments
        if additional_args:
            cmd.extend(additional_args)
        
        # Add object files
        cmd.extend([str(f) for f in object_files])
        
        try:
            # Run pelf and redirect output to PAT file
            with open(output_pat, 'w', encoding='utf-8') as pat_file:
                result = subprocess.run(
                    cmd,
                    stdout=pat_file,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=True,
                    timeout=300  # 5 minute timeout
                )
            
            # Verify PAT file was created and has content
            if not output_pat.exists() or output_pat.stat().st_size == 0:
                raise FLAIRToolError(
                    f"PAT file was not generated or is empty: {output_pat}",
                    tool_name="pelf",
                    command=cmd
                )
            
            # Count patterns in PAT file
            pattern_count = self._count_pat_patterns(output_pat)
            self.logger.info(f"PAT file generated successfully: {pattern_count} patterns")
            
            return output_pat
            
        except subprocess.TimeoutExpired as e:
            raise FLAIRToolError(
                f"pelf timed out after 300 seconds",
                tool_name="pelf",
                command=cmd
            ) from e
            
        except subprocess.CalledProcessError as e:
            raise FLAIRToolError.execution_failed(
                tool_name="pelf",
                command=cmd,
                returncode=e.returncode,
                stderr=e.stderr or ""
            ) from e
    
    @log_execution_time
    def generate_sig(
        self, 
        pat_file: Path, 
        output_sig: Path,
        lib_name: Optional[str] = None,
        handle_collisions: bool = True
    ) -> Path:
        """Generate SIG file from PAT file using sigmake.
        
        Args:
            pat_file: Input PAT file path.
            output_sig: Output path for the SIG file.
            lib_name: Optional library name for the signature (prevents "Unnamed sample library").
            handle_collisions: Whether to automatically handle signature collisions.
            
        Returns:
            Path to the generated SIG file.
            
        Raises:
            FLAIRToolError: If sigmake execution fails.
            ValidationError: If inputs are invalid.
        """
        if not pat_file.exists():
            raise ValidationError(
                f"PAT file does not exist: {pat_file}",
                field_name="pat_file",
                field_value=str(pat_file)
            )
        
        if pat_file.stat().st_size == 0:
            raise ValidationError(
                f"PAT file is empty: {pat_file}",
                field_name="pat_file",
                field_value=str(pat_file)
            )
        
        self.logger.info(f"Generating SIG file: {output_sig}")
        
        # Ensure output directory exists
        output_sig.parent.mkdir(parents=True, exist_ok=True)
        
        # Build sigmake command
        cmd = [str(self.sigmake_path)]
        
        # Add library name if specified (prevents "Unnamed sample library")
        if lib_name:
            cmd.append(f"-n{lib_name}")
        
        # Add input and output files
        cmd.extend([str(pat_file), str(output_sig)])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=120  # 2 minute timeout
            )
            
            # Verify SIG file was created
            if not output_sig.exists():
                raise FLAIRToolError(
                    f"SIG file was not generated: {output_sig}",
                    tool_name="sigmake",
                    command=cmd
                )
            
            self.logger.info(f"SIG file generated successfully: {output_sig}")
            return output_sig
            
        except subprocess.CalledProcessError as e:
            stderr = e.stderr or ""
            
            # Check if this is a collision error that we can handle
            if handle_collisions and "collision" in stderr.lower():
                self.logger.warning("Signature collisions detected, attempting to resolve...")
                return self._handle_collisions(pat_file, output_sig, cmd)
            else:
                raise FLAIRToolError.execution_failed(
                    tool_name="sigmake",
                    command=cmd,
                    returncode=e.returncode,
                    stderr=stderr
                ) from e
        
        except subprocess.TimeoutExpired as e:
            raise FLAIRToolError(
                f"sigmake timed out after 120 seconds",
                tool_name="sigmake",
                command=cmd
            ) from e
    
    def _handle_collisions(self, pat_file: Path, output_sig: Path, original_cmd: List[str]) -> Path:
        """Handle signature collisions by processing .exc file."""
        exc_file = pat_file.with_suffix('.exc')
        
        if not exc_file.exists():
            raise FLAIRToolError(
                f"Expected collision file not found: {exc_file}",
                tool_name="sigmake",
                command=original_cmd
            )
        
        self.logger.info(f"Processing collision file: {exc_file}")
        
        try:
            # Read collision file and comment out all collision entries
            lines = exc_file.read_text(encoding='utf-8').splitlines()
            processed_lines = []
            
            collision_count = 0
            for line in lines:
                if line.strip() and not line.startswith(';'):
                    # Comment out collision entry
                    processed_lines.append(f";{line}")
                    collision_count += 1
                else:
                    processed_lines.append(line)
            
            # Write back the processed collision file
            exc_file.write_text('\n'.join(processed_lines), encoding='utf-8')
            
            self.logger.info(f"Commented out {collision_count} collision entries")
            
            # Retry sigmake with processed collision file
            result = subprocess.run(
                original_cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=120
            )
            
            if not output_sig.exists():
                raise FLAIRToolError(
                    f"SIG file still not generated after collision resolution: {output_sig}",
                    tool_name="sigmake",
                    command=original_cmd
                )
            
            self.logger.info(f"SIG file generated successfully after collision resolution")
            return output_sig
            
        except subprocess.CalledProcessError as e:
            raise FLAIRToolError(
                f"sigmake failed even after collision resolution: {e.stderr}",
                tool_name="sigmake",
                command=original_cmd,
                stderr=e.stderr or ""
            ) from e
        
        except Exception as e:
            raise FLAIRToolError(
                f"Failed to handle collisions: {e}",
                tool_name="sigmake",
                command=original_cmd
            ) from e
    
    def _count_pat_patterns(self, pat_file: Path) -> int:
        """Count the number of patterns in a PAT file."""
        try:
            lines = pat_file.read_text(encoding='utf-8').splitlines()
            pattern_count = 0
            
            for line in lines:
                line = line.strip()
                if line and not line.startswith(';') and not line.startswith('---'):
                    pattern_count += 1
            
            return pattern_count
            
        except Exception as e:
            self.logger.warning(f"Failed to count PAT patterns: {e}")
            return 0
    
    @log_execution_time
    def generate_signature_set(
        self,
        object_files: List[Path],
        output_dir: Path,
        signature_name: str,
        lib_name: Optional[str] = None
    ) -> Dict[str, Path]:
        """Generate a complete signature set (PAT and SIG) from object files.
        
        Args:
            object_files: List of object files to process.
            output_dir: Directory to store generated signatures.
            signature_name: Base name for signature files.
            lib_name: Optional library name for signatures.
            
        Returns:
            Dictionary with 'pat' and 'sig' keys mapping to generated file paths.
            
        Raises:
            SignatureGenerationError: If signature generation fails.
        """
        if not object_files:
            raise ValidationError(
                "No object files provided for signature generation",
                field_name="object_files",
                field_value=[]
            )
        
        if not signature_name:
            raise ValidationError(
                "Signature name cannot be empty",
                field_name="signature_name",
                field_value=signature_name
            )
        
        # Ensure output directory exists
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Define output paths
        pat_path = output_dir / f"{signature_name}.pat"
        sig_path = output_dir / f"{signature_name}.sig"
        
        try:
            self.logger.info(f"Generating signature set '{signature_name}' from {len(object_files)} objects")
            
            # Generate PAT file
            self.generate_pat(object_files, pat_path, lib_name or signature_name)
            
            # Generate SIG file
            self.generate_sig(pat_path, sig_path, lib_name or signature_name)
            
            result = {
                'pat': pat_path,
                'sig': sig_path
            }
            
            self.logger.info(f"Signature set generated successfully: {result}")
            return result
            
        except Exception as e:
            # Clean up partial files on failure
            for path in [pat_path, sig_path]:
                if path.exists():
                    try:
                        path.unlink()
                    except Exception:
                        pass  # Ignore cleanup errors
            
            if isinstance(e, (FLAIRToolError, ValidationError)):
                raise
            else:
                raise SignatureGenerationError(
                    f"Failed to generate signature set '{signature_name}': {e}",
                    stage="signature_set_generation",
                    input_files=object_files,
                    output_file=sig_path
                ) from e
    
    def get_tool_info(self) -> Dict[str, Any]:
        """Get information about FLAIR tools."""
        info = {
            "flair_dir": str(self.flair_dir),
            "pelf_path": str(self.pelf_path),
            "sigmake_path": str(self.sigmake_path),
        }
        
        # Try to get tool versions
        for tool_name, tool_path in [("pelf", self.pelf_path), ("sigmake", self.sigmake_path)]:
            try:
                result = subprocess.run(
                    [str(tool_path)],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                # Extract version info from stderr (tools typically show usage/version there)
                output = (result.stderr or result.stdout or "").strip()
                version_line = output.split('\n')[0] if output else "Unknown"
                info[f"{tool_name}_version"] = version_line
                
            except Exception as e:
                info[f"{tool_name}_version"] = f"Error: {e}"
        
        return info
    
    def validate_signature_file(self, sig_file: Path) -> List[str]:
        """Validate a generated signature file.
        
        Args:
            sig_file: Path to the SIG file to validate.
            
        Returns:
            List of validation issues found (empty if valid).
        """
        issues = []
        
        if not sig_file.exists():
            issues.append(f"SIG file does not exist: {sig_file}")
            return issues
        
        if sig_file.stat().st_size == 0:
            issues.append(f"SIG file is empty: {sig_file}")
            return issues
        
        # Basic signature file validation
        try:
            with open(sig_file, 'rb') as f:
                header = f.read(64)
                
            # Check for IDA signature file magic bytes
            if not header.startswith(b'FLIRT'):
                issues.append(f"SIG file does not have valid FLIRT header: {sig_file}")
            
        except Exception as e:
            issues.append(f"Failed to read SIG file: {e}")
        
        return issues