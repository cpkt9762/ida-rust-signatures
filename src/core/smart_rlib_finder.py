"""Smart RLIB file finder with intelligent path resolution.

This module provides automatic RLIB file discovery based on crate names,
handling different project structures including workspaces and versioned directories.
"""

import re
import toml
from pathlib import Path
from typing import List, Optional, Tuple, Dict
from dataclasses import dataclass

from .logger import LoggerMixin


@dataclass
class RlibSearchResult:
    """Result of RLIB search operation."""
    rlib_path: Path
    crate_name: str
    version: Optional[str]
    project_path: Path
    is_workspace: bool
    confidence: float  # 0.0 to 1.0


class SmartRlibFinder(LoggerMixin):
    """Smart RLIB file finder with intelligent path resolution."""
    
    def __init__(self, dependencies_dir: Optional[Path] = None):
        super().__init__()
        if dependencies_dir:
            self.dependencies_dir = Path(dependencies_dir)
        else:
            # Use absolute path relative to project root
            project_root = Path(__file__).parent.parent.parent
            self.dependencies_dir = project_root / "data" / "dependencies"
        
    def find_rlib(self, crate_name_or_path: str, version: Optional[str] = None, 
                  target: str = "x86_64-unknown-linux-gnu") -> Optional[RlibSearchResult]:
        """
        Find RLIB file by crate name or path.
        
        Args:
            crate_name_or_path: Either a full path to RLIB or just crate name
            version: Optional version to match
            target: Target architecture
            
        Returns:
            RlibSearchResult if found, None otherwise
        """
        # If it's already a valid path, return it directly
        potential_path = Path(crate_name_or_path)
        if potential_path.exists() and potential_path.suffix == '.rlib':
            return self._analyze_existing_rlib(potential_path)
        
        # Search in dependencies directory
        if self.dependencies_dir.exists():
            results = self._search_in_dependencies(crate_name_or_path, version, target)
            if results:
                # Return the best match
                return max(results, key=lambda r: r.confidence)
        
        return None
    
    def _analyze_existing_rlib(self, rlib_path: Path) -> RlibSearchResult:
        """Analyze an existing RLIB file to extract metadata."""
        # Extract crate name from filename
        filename = rlib_path.stem
        if filename.startswith('lib'):
            filename = filename[3:]  # Remove 'lib' prefix
        
        # Try to extract crate name (remove hash if present)
        crate_name = filename.split('-')[0] if '-' in filename else filename
        
        # Try to find project root
        project_path = self._find_project_root(rlib_path)
        
        # Try to extract version from Cargo.toml
        version = None
        is_workspace = False
        if project_path:
            version, is_workspace = self._extract_version_from_cargo(project_path, crate_name)
        
        return RlibSearchResult(
            rlib_path=rlib_path,
            crate_name=crate_name,
            version=version,
            project_path=project_path or rlib_path.parent,
            is_workspace=is_workspace,
            confidence=1.0
        )
    
    def _search_in_dependencies(self, crate_name: str, version: Optional[str], 
                               target: str) -> List[RlibSearchResult]:
        """Search for RLIB files in dependencies directory."""
        results = []
        
        # Normalize crate name for searching
        normalized_name = crate_name.replace('_', '-')
        
        # Search patterns: exact match, with version, fuzzy match
        search_patterns = [
            normalized_name,  # exact: jupiter-swap-api-client
            f"{normalized_name}-*",  # with version: solana-sdk-2.1.21
            f"*{normalized_name}*",  # fuzzy: *jupiter*
        ]
        
        for pattern in search_patterns:
            matches = list(self.dependencies_dir.glob(pattern))
            for project_dir in matches:
                if project_dir.is_dir():
                    rlib_results = self._search_in_project(project_dir, crate_name, version, target)
                    results.extend(rlib_results)
        
        return results
    
    def _search_in_project(self, project_dir: Path, crate_name: str, 
                          version: Optional[str], target: str) -> List[RlibSearchResult]:
        """Search for RLIB files within a specific project directory."""
        results = []
        
        # Check if it's a workspace
        cargo_toml_path = project_dir / "Cargo.toml"
        if not cargo_toml_path.exists():
            return results
        
        try:
            with open(cargo_toml_path, 'r', encoding='utf-8') as f:
                cargo_data = toml.load(f)
        except Exception as e:
            self.logger.warning(f"Failed to parse {cargo_toml_path}: {e}")
            return results
        
        is_workspace = 'workspace' in cargo_data
        
        if is_workspace:
            # Handle workspace projects
            results.extend(self._search_workspace(project_dir, cargo_data, crate_name, version, target))
        else:
            # Handle single crate projects
            result = self._search_single_crate(project_dir, cargo_data, crate_name, version, target)
            if result:
                results.append(result)
        
        return results
    
    def _search_workspace(self, workspace_dir: Path, cargo_data: dict, 
                         crate_name: str, version: Optional[str], target: str) -> List[RlibSearchResult]:
        """Search for RLIB files in a workspace project."""
        results = []
        
        # Check workspace members
        members = cargo_data.get('workspace', {}).get('members', [])
        
        for member in members:
            member_dir = workspace_dir / member
            if member_dir.exists():
                member_cargo_path = member_dir / "Cargo.toml"
                if member_cargo_path.exists():
                    try:
                        with open(member_cargo_path, 'r', encoding='utf-8') as f:
                            member_cargo = toml.load(f)
                        
                        member_name = member_cargo.get('package', {}).get('name', '')
                        if self._name_matches(member_name, crate_name):
                            # Look for RLIB in workspace target directory
                            rlib_files = self._find_rlib_files(workspace_dir, member_name, target)
                            for rlib_path in rlib_files:
                                confidence = self._calculate_confidence(member_name, crate_name, version)
                                results.append(RlibSearchResult(
                                    rlib_path=rlib_path,
                                    crate_name=member_name,
                                    version=member_cargo.get('package', {}).get('version'),
                                    project_path=workspace_dir,
                                    is_workspace=True,
                                    confidence=confidence
                                ))
                    except Exception as e:
                        self.logger.warning(f"Failed to parse {member_cargo_path}: {e}")
        
        return results
    
    def _search_single_crate(self, project_dir: Path, cargo_data: dict, 
                            crate_name: str, version: Optional[str], target: str) -> Optional[RlibSearchResult]:
        """Search for RLIB files in a single crate project."""
        package_info = cargo_data.get('package', {})
        package_name = package_info.get('name', '')
        
        if not self._name_matches(package_name, crate_name):
            return None
        
        # Look for RLIB files
        rlib_files = self._find_rlib_files(project_dir, package_name, target)
        if not rlib_files:
            return None
        
        # Pick the most recent RLIB file
        latest_rlib = max(rlib_files, key=lambda x: x.stat().st_mtime)
        
        confidence = self._calculate_confidence(package_name, crate_name, version)
        
        return RlibSearchResult(
            rlib_path=latest_rlib,
            crate_name=package_name,
            version=package_info.get('version'),
            project_path=project_dir,
            is_workspace=False,
            confidence=confidence
        )
    
    def _find_rlib_files(self, project_dir: Path, crate_name: str, target: str) -> List[Path]:
        """Find RLIB files for a given crate in target directories."""
        normalized_name = crate_name.replace('-', '_')
        
        # Search in multiple target directories
        search_dirs = [
            project_dir / "target" / target / "release" / "deps",
            project_dir / "target" / target / "release", 
            project_dir / "target" / target / "debug" / "deps",
            project_dir / "target" / target / "debug",
            project_dir / "target" / "release" / "deps",
            project_dir / "target" / "release",
            project_dir / "target" / "debug" / "deps", 
            project_dir / "target" / "debug",
        ]
        
        patterns = [
            f"lib{normalized_name}-*.rlib",  # with hash
            f"lib{normalized_name}.rlib"     # without hash
        ]
        
        rlib_files = []
        for search_dir in search_dirs:
            if search_dir.exists():
                for pattern in patterns:
                    found_files = list(search_dir.glob(pattern))
                    rlib_files.extend(found_files)
                    self.logger.debug(f"Found {len(found_files)} files with pattern '{pattern}' in {search_dir}")
        
        return rlib_files
    
    def _name_matches(self, actual_name: str, search_name: str) -> bool:
        """Check if crate names match, handling underscore/hyphen conversion."""
        if not actual_name or not search_name:
            return False
        
        # Normalize both names
        actual_normalized = actual_name.replace('_', '-').lower()
        search_normalized = search_name.replace('_', '-').lower()
        
        return actual_normalized == search_normalized
    
    def _calculate_confidence(self, actual_name: str, search_name: str, 
                            expected_version: Optional[str]) -> float:
        """Calculate confidence score for a match."""
        confidence = 0.0
        
        # Name match
        if self._name_matches(actual_name, search_name):
            confidence += 0.7
        elif search_name.lower() in actual_name.lower():
            confidence += 0.4
        
        # Version match (if specified)
        if expected_version:
            # TODO: Could add version matching logic
            confidence += 0.2
        else:
            confidence += 0.3  # Bonus for not requiring specific version
        
        return min(confidence, 1.0)
    
    def _find_project_root(self, rlib_path: Path) -> Optional[Path]:
        """Find the project root directory for an RLIB file."""
        current = rlib_path.parent
        max_depth = 10
        
        for _ in range(max_depth):
            if (current / "Cargo.toml").exists():
                return current
            
            parent = current.parent
            if parent == current:  # Reached filesystem root
                break
            current = parent
        
        return None
    
    def _extract_version_from_cargo(self, project_path: Path, crate_name: str) -> Tuple[Optional[str], bool]:
        """Extract version and workspace info from Cargo.toml."""
        cargo_toml_path = project_path / "Cargo.toml"
        if not cargo_toml_path.exists():
            return None, False
        
        try:
            with open(cargo_toml_path, 'r', encoding='utf-8') as f:
                cargo_data = toml.load(f)
            
            is_workspace = 'workspace' in cargo_data
            
            if is_workspace:
                # For workspace, try to find the specific member
                members = cargo_data.get('workspace', {}).get('members', [])
                
                for member in members:
                    member_dir = project_path / member
                    member_cargo_path = member_dir / "Cargo.toml"
                    if member_cargo_path.exists():
                        try:
                            with open(member_cargo_path, 'r', encoding='utf-8') as f:
                                member_cargo = toml.load(f)
                            
                            member_name = member_cargo.get('package', {}).get('name', '')
                            if self._name_matches(member_name, crate_name):
                                return member_cargo.get('package', {}).get('version'), True
                        except Exception:
                            continue
            else:
                # Single crate
                version = cargo_data.get('package', {}).get('version')
                return version, False
            
        except Exception as e:
            self.logger.warning(f"Failed to parse {cargo_toml_path}: {e}")
        
        return None, is_workspace