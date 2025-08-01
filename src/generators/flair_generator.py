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
            # Read collision file and intelligently select best functions
            lines = exc_file.read_text(encoding='utf-8').splitlines()
            collision_groups = self._parse_exc_collision_groups(lines)
            
            # Create mapping of selected functions
            selected_functions = {}
            selected_count = 0
            total_collision_functions = 0
            
            for group_functions in collision_groups.values():
                total_collision_functions += len(group_functions)
                if len(group_functions) > 1:
                    # Select best function from collision group
                    best_function_line = self._select_best_function_from_group(group_functions)
                    best_func_name = best_function_line.split('\t')[0]
                    
                    # Mark which functions are selected in this group
                    for func_line in group_functions:
                        func_name = func_line.split('\t')[0]
                        selected_functions[func_name] = (func_name == best_func_name)
                        if func_name == best_func_name:
                            selected_count += 1
                else:
                    # Single function, no collision - always select
                    func_name = group_functions[0].split('\t')[0]
                    selected_functions[func_name] = True
                    selected_count += 1
            
            # Process original lines and add prefixes
            processed_lines = []
            skip_headers = True
            for line in lines:
                stripped_line = line.strip()
                
                # Skip header comment lines (until we find first function)
                if skip_headers and (stripped_line.startswith(';') or not stripped_line):
                    continue
                elif '\t' in stripped_line:
                    # This is a function line - we've found functions, stop skipping headers
                    skip_headers = False
                    func_name = stripped_line.split('\t')[0]
                    if func_name in selected_functions:
                        if selected_functions[func_name]:
                            # Selected function - add '+' prefix
                            processed_lines.append(f"+{line}")
                        else:
                            # Not selected - keep as-is (will be excluded)
                            processed_lines.append(line)
                    else:
                        # Unknown function - keep as-is
                        processed_lines.append(line)
                else:
                    # Other lines after headers - keep as-is
                    if not skip_headers:
                        processed_lines.append(line)
            
            # Write back the processed collision file
            exc_file.write_text('\n'.join(processed_lines), encoding='utf-8')
            
            self.logger.info(f"Processed {len(collision_groups)} collision groups, selected {selected_count} best functions from {total_collision_functions} total functions")
            
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
    
    def generate_sig_with_collision_handling(
        self, 
        pat_file: Path, 
        output_sig: Path,
        lib_name: Optional[str] = None,
        mode: str = 'strict'
    ) -> Optional[Dict[str, Any]]:
        """Generate SIG file with advanced collision handling modes.
        
        Args:
            pat_file: Input PAT file path.
            output_sig: Output path for the SIG file.
            lib_name: Optional library name for the signature.
            mode: Collision handling mode ('strict', 'accept', 'force', 'manual').
            
        Returns:
            Dictionary with generation results and statistics, or None if failed.
        """
        if not pat_file.exists():
            raise ValidationError(
                f"PAT file does not exist: {pat_file}",
                field_name="pat_file", 
                field_value=str(pat_file)
            )
        
        self.logger.info(f"Generating SIG file with {mode} collision mode: {output_sig}")
        
        # Ensure output directory exists
        output_sig.parent.mkdir(parents=True, exist_ok=True)
        
        if mode == 'strict':
            # Use existing generate_sig method with intelligent collision handling
            try:
                self.generate_sig(pat_file, output_sig, lib_name, handle_collisions=True)
                return {'success': True, 'mode': mode}
            except Exception:
                return None
                
        elif mode == 'accept':
            # Accept mode: generate partial signatures, skip collisions
            return self._generate_sig_accept_mode(pat_file, output_sig, lib_name)
            
        elif mode == 'force':
            # Force mode: use sigmake -c to override collisions
            return self._generate_sig_force_mode(pat_file, output_sig, lib_name) 
            
        elif mode == 'manual':
            # Manual mode: generate EXC files for user editing
            return self._generate_sig_manual_mode(pat_file, output_sig, lib_name)
            
        else:
            raise ValueError(f"Unknown collision mode: {mode}")
    
    def _generate_sig_with_filtered_pat(
        self, 
        pat_file: Path, 
        output_sig: Path, 
        lib_name: Optional[str],
        mode: str
    ) -> Optional[Dict[str, Any]]:
        """Generate SIG using filtered PAT file method - unified logic for accept/force modes."""
        
        try:
            # First, run sigmake to detect collisions and generate EXC file
            cmd = [str(self.sigmake_path)]
            if lib_name:
                cmd.append(f"-n{lib_name}")
            cmd.extend([str(pat_file), str(output_sig)])
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            exc_file = pat_file.with_suffix('.exc')
            if exc_file.exists():
                # Process collisions by selecting best functions
                self.logger.info(f"Collisions detected, applying {mode} mode resolution...")
                
                # Process collision information without modifying the original EXC file
                original_exc_lines = exc_file.read_text(encoding='utf-8').splitlines()
                
                # Get collision resolution results
                selected_functions, original_count, processed_count = self._get_collision_resolution(original_exc_lines)
                
                # Create a filtered PAT file without colliding functions
                filtered_pat = self._create_filtered_pat_file_v2(pat_file, original_exc_lines, selected_functions)
                
                # Generate SIG from filtered PAT
                cmd = [str(self.sigmake_path)]
                if lib_name:
                    cmd.append(f"-n{lib_name}")
                cmd.extend([str(filtered_pat), str(output_sig)])
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=120
                )
                
                # Clean up temporary filtered PAT file
                if filtered_pat.exists():
                    filtered_pat.unlink()
                
                if output_sig.exists():
                    return {
                        'success': True,
                        'mode': mode,
                        'stats': {
                            'collisions_detected': original_count - processed_count,
                            'functions_included': processed_count,
                            'functions_skipped': original_count - processed_count
                        }
                    }
                else:
                    return None
            else:
                # No collisions detected, file should have been generated successfully
                if output_sig.exists():
                    return {
                        'success': True,
                        'mode': mode, 
                        'stats': {
                            'collisions_detected': 0,
                            'functions_included': self._count_pat_patterns(pat_file),
                            'functions_skipped': 0
                        }
                    }
                else:
                    return None
                    
        except Exception as e:
            self.logger.error(f"{mode.title()} mode generation failed: {e}")
            return None

    def _generate_sig_accept_mode(
        self, 
        pat_file: Path, 
        output_sig: Path, 
        lib_name: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        """Generate SIG in accept mode - create filtered PAT file without collisions."""
        return self._generate_sig_with_filtered_pat(pat_file, output_sig, lib_name, 'accept')
    
    def _generate_sig_force_mode(
        self, 
        pat_file: Path, 
        output_sig: Path, 
        lib_name: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        """Generate SIG in force mode - create filtered PAT file without collisions."""
        return self._generate_sig_with_filtered_pat(pat_file, output_sig, lib_name, 'force')
    
    def _generate_sig_manual_mode(
        self, 
        pat_file: Path, 
        output_sig: Path, 
        lib_name: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        """Generate EXC files for manual collision resolution."""
        
        # Build sigmake command 
        cmd = [str(self.sigmake_path)]
        if lib_name:
            cmd.append(f"-n{lib_name}")
        cmd.extend([str(pat_file), str(output_sig)])
        
        try:
            # Run sigmake to generate EXC file (expect it to fail)
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            exc_file = pat_file.with_suffix('.exc')
            if exc_file.exists():
                # EXC file generated, ready for manual editing
                return {
                    'success': True,
                    'mode': 'manual',
                    'exc_files': [exc_file],
                    'stats': {
                        'collisions_detected': self._count_exc_collisions(exc_file),
                        'manual_resolution_required': True
                    }
                }
            else:
                # No collisions detected, generate normally
                if result.returncode == 0 and output_sig.exists():
                    return {
                        'success': True,
                        'mode': 'manual',
                        'stats': {
                            'collisions_detected': 0,
                            'functions_included': self._count_pat_patterns(pat_file)
                        }
                    }
                else:
                    return None
                    
        except Exception as e:
            self.logger.error(f"Manual mode preparation failed: {e}")
            return None
    
    def _select_best_function_from_group(self, collision_group: list[str]) -> str:
        """Select the best function from a collision group.
        
        Selection priority:
        1. Non-unlikely functions over unlikely functions
        2. Shorter function names (less specialized)
        3. Lexicographically smaller names for ties
        """
        def get_function_score(line: str) -> tuple[int, int, str]:
            func_name = line.split('\t')[0]
            
            # Priority 1: unlikely penalty
            unlikely_penalty = 1 if func_name.startswith('unlikely.') else 0
            
            # Priority 2: name length (shorter is better)
            name_length = len(func_name)
            
            # Priority 3: lexicographic order
            return (unlikely_penalty, name_length, func_name)
        
        # Sort by priority and return the best one
        best_function = min(collision_group, key=get_function_score)
        return best_function
    
    
    def _create_filtered_pat_file(self, original_pat: Path, exc_file: Path, original_exc_lines: list[str]) -> Path:
        """Create a filtered PAT file excluding functions that have collisions."""
        
        # Read processed EXC file to get selected functions
        exc_lines = exc_file.read_text(encoding='utf-8').splitlines()
        selected_functions = set()
        
        for line in exc_lines:
            line = line.strip()
            if line.startswith('+'):
                # Extract function name from EXC line: +FUNC_NAME<TAB>...
                parts = line[1:].split('\t')
                if parts:
                    selected_functions.add(parts[0])
        
        self.logger.debug(f"Selected {len(selected_functions)} functions from processed EXC file")
        
        # Get all functions that have collisions from original EXC file
        collision_functions = set()
        for line in original_exc_lines:
            line = line.strip()
            if line and not line.startswith(';') and '\t' in line:
                # This is a collision line: FUNC_NAME<TAB>CRC pattern...
                parts = line.split('\t')
                if parts:
                    collision_functions.add(parts[0])
        
        self.logger.debug(f"Found {len(collision_functions)} functions with collisions")
        
        # Read original PAT file and filter out colliding functions
        pat_lines = original_pat.read_text(encoding='utf-8').splitlines()
        filtered_lines = []
        
        for line in pat_lines:
            line_stripped = line.strip()
            
            # Keep header lines and comments
            if line_stripped.startswith(';') or line_stripped.startswith('---') or not line_stripped:
                filtered_lines.append(line)
                continue
            
            # For function lines, check if the function should be included
            # PAT format: FUNC_NAME length CRC16 pattern...
            parts = line_stripped.split()
            if len(parts) >= 4:
                func_name = parts[0]
                
                # Include function if:
                # 1. It's selected from collision resolution, OR
                # 2. It's not involved in any collision
                if func_name in selected_functions:
                    filtered_lines.append(line)
                    self.logger.debug(f"Including selected function: {func_name}")
                elif func_name not in collision_functions:
                    # Function is not involved in any collision, keep it
                    filtered_lines.append(line)
            else:
                # Keep non-function lines as-is
                filtered_lines.append(line)
        
        # Create filtered PAT file
        filtered_pat = original_pat.with_suffix('.filtered.pat')
        filtered_pat.write_text('\n'.join(filtered_lines), encoding='utf-8')
        
        original_func_count = self._count_pat_patterns(original_pat)
        filtered_func_count = self._count_pat_patterns(filtered_pat)
        
        self.logger.info(f"Created filtered PAT file: {filtered_pat}")
        self.logger.info(f"Original functions: {original_func_count}, Filtered functions: {filtered_func_count}")
        return filtered_pat
    
    def _get_collision_resolution(self, original_exc_lines: list[str]) -> tuple[set[str], int, int]:
        """Process collision resolution without modifying files - return selected functions."""
        
        original_count = 0
        signature_groups = {}
        
        # First pass: organize functions by signature and collect headers
        for line in original_exc_lines:
            stripped_line = line.strip()
            
            # Skip header lines that start with semicolon or empty lines
            if stripped_line.startswith(';') or not stripped_line:
                continue
            
            # Function entry - check if it contains tab-separated data
            if '\t' in stripped_line:
                parts = stripped_line.split('\t')
                if len(parts) >= 2:
                    func_name = parts[0]
                    pattern_data = parts[1]
                    
                    # Parse pattern data - format is: CRC PATTERN
                    pattern_parts = pattern_data.split(' ', 2)
                    if len(pattern_parts) >= 2:
                        crc = pattern_parts[0]
                        pattern = pattern_parts[1]
                        
                        # Create signature key from CRC and pattern
                        sig_key = f"{crc}:{pattern}"
                        
                        if sig_key not in signature_groups:
                            signature_groups[sig_key] = []
                        
                        signature_groups[sig_key].append(line)
                        original_count += 1
        
        # Second pass: select best function from each collision group
        selected_functions = set()
        processed_count = 0
        collision_groups_processed = 0
        
        for sig_key, group in signature_groups.items():
            if len(group) > 1:
                # This is a collision group - select the best function
                best_function = self._select_best_function_from_group(group)
                func_name = best_function.split('\t')[0]
                selected_functions.add(func_name)
                collision_groups_processed += 1
                processed_count += 1
                
                self.logger.debug(f"Collision group with {len(group)} functions, selected: {func_name}")
            else:
                # No collision, keep as-is
                func_name = group[0].split('\t')[0]
                selected_functions.add(func_name)
                processed_count += 1
        
        self.logger.info(f"Processed collisions: {original_count} original functions, kept {processed_count} (resolved {collision_groups_processed} collision groups)")
        
        return selected_functions, original_count, processed_count
    
    def _create_filtered_pat_file_v2(self, original_pat: Path, original_exc_lines: list[str], selected_functions: set[str]) -> Path:
        """Create a filtered PAT file using collision resolution results."""
        
        # Get all functions that have collisions from original EXC file
        collision_functions = set()
        for line in original_exc_lines:
            line = line.strip()
            if line and not line.startswith(';') and '\t' in line:
                # This is a collision line: FUNC_NAME<TAB>CRC pattern...
                parts = line.split('\t')
                if parts:
                    collision_functions.add(parts[0])
        
        self.logger.debug(f"Found {len(collision_functions)} functions with collisions")
        self.logger.debug(f"Selected {len(selected_functions)} functions from collision resolution")
        
        # Read original PAT file and filter out colliding functions
        pat_lines = original_pat.read_text(encoding='utf-8').splitlines()
        filtered_lines = []
        
        for line in pat_lines:
            line_stripped = line.strip()
            
            # Keep header lines and comments
            if line_stripped.startswith(';') or line_stripped.startswith('---') or not line_stripped:
                filtered_lines.append(line)
                continue
            
            # For function lines, check if the function should be included
            # PAT format: <pattern> <length> <CRC> <offset> :<address> <function_name> <references...>
            if ':' in line_stripped:
                colon_parts = line_stripped.split(':', 1)
                if len(colon_parts) == 2:
                    after_colon = colon_parts[1].strip()
                    # Function name is the first word after ":<address> "
                    after_colon_parts = after_colon.split()
                    if len(after_colon_parts) >= 2:
                        func_name = after_colon_parts[1]  # Skip the address part
                        
                        # Include function if:
                        # 1. It's selected from collision resolution, OR  
                        # 2. It's not involved in any collision
                        if func_name in selected_functions:
                            filtered_lines.append(line)
                            self.logger.debug(f"Including selected function: {func_name}")
                        elif func_name not in collision_functions:
                            # Function is not involved in any collision, keep it
                            filtered_lines.append(line)
                            self.logger.debug(f"Including non-collision function: {func_name}")
                        else:
                            # This function is in collision but not selected, skip it
                            self.logger.debug(f"Skipping collision function: {func_name}")
                    else:
                        # Keep lines that don't match expected format
                        filtered_lines.append(line)
                else:
                    # Keep lines without colon
                    filtered_lines.append(line)
            else:
                # Keep non-function lines as-is
                filtered_lines.append(line)
        
        # Create filtered PAT file
        filtered_pat = original_pat.with_suffix('.filtered.pat')
        filtered_pat.write_text('\n'.join(filtered_lines), encoding='utf-8')
        
        original_func_count = self._count_pat_patterns(original_pat)
        filtered_func_count = self._count_pat_patterns(filtered_pat)
        
        self.logger.info(f"Created filtered PAT file: {filtered_pat}")
        self.logger.info(f"Original functions: {original_func_count}, Filtered functions: {filtered_func_count}")
        return filtered_pat
    
    def _count_exc_collisions(self, exc_file: Path) -> int:
        """Count collision groups in EXC file."""
        try:
            lines = exc_file.read_text(encoding='utf-8').splitlines()
            collision_count = 0
            
            for line in lines:
                if line.strip() and not line.startswith(';'):
                    collision_count += 1
            
            return collision_count
            
        except Exception as e:
            self.logger.warning(f"Failed to count EXC collisions: {e}")
            return 0
    
    def _parse_exc_collision_groups(self, lines: list[str]) -> dict[str, list[str]]:
        """Parse EXC file lines into collision groups by signature pattern.
        
        Args:
            lines: List of lines from EXC file
            
        Returns:
            Dictionary mapping signature keys to lists of collision function lines
        """
        collision_groups = {}
        
        for line in lines:
            stripped_line = line.strip()
            
            # Skip header lines and empty lines
            if stripped_line.startswith(';') or not stripped_line:
                continue
            
            # Parse function entry with tab-separated data
            if '\t' in stripped_line:
                parts = stripped_line.split('\t')
                if len(parts) >= 2:
                    func_name = parts[0]
                    pattern_data = parts[1]
                    
                    # Parse pattern data - format is: CRC PATTERN
                    pattern_parts = pattern_data.split(' ', 2)
                    if len(pattern_parts) >= 2:
                        crc = pattern_parts[0] 
                        pattern = pattern_parts[1]
                        
                        # Create signature key from CRC and pattern
                        sig_key = f"{crc}:{pattern}"
                        
                        if sig_key not in collision_groups:
                            collision_groups[sig_key] = []
                        
                        collision_groups[sig_key].append(stripped_line)
        
        return collision_groups