#!/usr/bin/env python3
"""
Collision prevention strategies inspired by solana-ida-signatures-factory
Combined with our automatic collision resolution for a comprehensive approach
"""

import hashlib
import re
from typing import Dict, List, Set, Tuple, Optional
from pathlib import Path
import logging


class CollisionPrevention:
    """Implements collision prevention strategies for PAT file generation"""
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.pattern_cache: Dict[str, List[int]] = {}
        self.function_index = 0
        
    def pattern_hash(self, pattern_parts: List[str]) -> str:
        """
        Calculate a hash for a PAT pattern to detect duplicates.
        Inspired by solana-ida-signatures-factory's approach.
        
        Args:
            pattern_parts: List of pattern components from a PAT line
            
        Returns:
            SHA256 hash of the normalized pattern
        """
        if len(pattern_parts) < 6:
            return ""
            
        # Extract the pattern bytes (first part)
        pattern_bytes = pattern_parts[0]
        
        # Normalize the pattern by replacing variable bytes with placeholders
        normalized = []
        i = 0
        while i < len(pattern_bytes):
            if i + 1 < len(pattern_bytes) and pattern_bytes[i:i+2] == '..':
                normalized.append('<VAR>')
                i += 2
            else:
                normalized.append(pattern_bytes[i])
                i += 1
        
        # Include CRC and length in the hash for better uniqueness
        crc = pattern_parts[1] if len(pattern_parts) > 1 else ""
        length = pattern_parts[2] if len(pattern_parts) > 2 else ""
        
        # Create a canonical representation
        canonical = f"{''.join(normalized)}|{crc}|{length}"
        
        return hashlib.sha256(canonical.encode()).hexdigest()
    
    def add_version_suffix(self, function_name: str, version: str) -> str:
        """
        Add version suffix to function name to prevent cross-version collisions.
        
        Args:
            function_name: Original function name
            version: Version string (e.g., "1.2.3")
            
        Returns:
            Function name with version suffix
        """
        # Check if it's a Rust mangled name
        if function_name.startswith('_ZN') and function_name.endswith('E'):
            # Insert version before the final 'E'
            appendix = f'$SP$v{version}'
            # Add length encoding as per Rust mangling rules
            version_part = f'{len(appendix)}{appendix}'
            return function_name[:-1] + version_part + 'E'
        else:
            # For non-mangled names, append version
            return f'{function_name}@v{version}'
    
    def should_filter_function(self, pattern_bytes: bytes, function_size: int) -> Tuple[bool, str]:
        """
        Determine if a function should be filtered out based on quality criteria.
        
        Args:
            pattern_bytes: The function's byte pattern
            function_size: Size of the function in bytes
            
        Returns:
            Tuple of (should_filter, reason)
        """
        # Size-based filtering (from solana-ida-signatures-factory)
        if function_size < 35:
            return True, "Function too short (<35 bytes)"
        
        if function_size >= 0x8000:  # 32KB
            return True, "Function too long (>=32KB)"
        
        # Check pattern quality
        if len(pattern_bytes) < 32:
            return True, "Pattern too short for reliable matching"
        
        # Count variable bytes
        pattern_str = pattern_bytes.hex().upper()
        variable_count = pattern_str.count('..')
        total_bytes = len(pattern_bytes)
        
        # If more than 50% of the pattern is variable, it's not reliable
        if variable_count * 2 > total_bytes:
            return True, f"Too many variable bytes ({variable_count * 2}/{total_bytes})"
        
        return False, ""
    
    def should_filter_pat_pattern(self, pattern_str: str) -> Tuple[bool, str]:
        """
        Determine if a PAT pattern should be filtered out based on consecutive fixed bytes.
        
        Args:
            pattern_str: The PAT pattern string (first field of PAT line)
            
        Returns:
            Tuple of (should_filter, reason)
        """
        if not pattern_str:
            return True, "Empty pattern"
        
        # Count leading consecutive fixed bytes
        consecutive_fixed = self._count_leading_consecutive_fixed_bytes(pattern_str)
        
        # Check if pattern has trailing wildcards after the consecutive fixed bytes
        has_trailing_wildcards = self._has_trailing_wildcards(pattern_str, consecutive_fixed)
        
        # Filter if less than 5 consecutive fixed bytes at start and has trailing wildcards
        if consecutive_fixed < 5 and has_trailing_wildcards:
            return True, f"Too few leading consecutive fixed bytes ({consecutive_fixed} < 5) with trailing wildcards"
        
        return False, ""
    
    def _count_leading_consecutive_fixed_bytes(self, pattern_str: str) -> int:
        """
        Count consecutive fixed bytes from the beginning of a PAT pattern.
        
        Args:
            pattern_str: PAT pattern string
            
        Returns:
            Number of consecutive fixed bytes from start
        """
        consecutive_count = 0
        i = 0
        
        # Process pattern in 2-character chunks (hex bytes)
        while i < len(pattern_str) - 1:
            # Check if current position is a wildcard (..)
            if pattern_str[i:i+2] == '..':
                break
            else:
                # This is a fixed byte (hex characters)
                consecutive_count += 1
                i += 2
        
        return consecutive_count
    
    def _has_trailing_wildcards(self, pattern_str: str, start_offset: int) -> bool:
        """
        Check if pattern has only wildcards after the given offset.
        
        Args:
            pattern_str: PAT pattern string
            start_offset: Number of bytes to skip from start
            
        Returns:
            True if all remaining bytes are wildcards
        """
        # Start checking from after the consecutive fixed bytes
        i = start_offset * 2  # Convert byte offset to character offset
        
        # If we've reached the end, there are no trailing wildcards
        if i >= len(pattern_str):
            return False
        
        # Check if all remaining characters form wildcards (..)
        while i < len(pattern_str) - 1:
            if pattern_str[i:i+2] != '..':
                return False
            i += 2
        
        return True
    
    def deduplicate_patterns(self, pat_lines: List[str], keep_strategy: str = 'first') -> List[str]:
        """
        Remove duplicate patterns from PAT file lines.
        
        Args:
            pat_lines: List of PAT file lines
            keep_strategy: Strategy for keeping patterns ('first', 'last', 'best_name')
            
        Returns:
            Deduplicated list of PAT lines
        """
        seen_hashes: Dict[str, List[Tuple[int, str]]] = {}
        result_lines = []
        
        for i, line in enumerate(pat_lines):
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith(';') or line.startswith('---'):
                result_lines.append(line)
                continue
            
            parts = line.split()
            if len(parts) < 6:
                result_lines.append(line)
                continue
            
            # Calculate pattern hash
            pattern_hash = self.pattern_hash(parts)
            if not pattern_hash:
                result_lines.append(line)
                continue
            
            # Track duplicates
            if pattern_hash not in seen_hashes:
                seen_hashes[pattern_hash] = []
            seen_hashes[pattern_hash].append((i, line))
        
        # Apply deduplication strategy
        selected_indices = set()
        
        for pattern_hash, occurrences in seen_hashes.items():
            if len(occurrences) == 1:
                selected_indices.add(occurrences[0][0])
            else:
                # Multiple occurrences - apply strategy
                if keep_strategy == 'first':
                    selected_indices.add(occurrences[0][0])
                elif keep_strategy == 'last':
                    selected_indices.add(occurrences[-1][0])
                elif keep_strategy == 'best_name':
                    # Keep the one with the most readable name
                    best_idx = self._select_best_name(occurrences)
                    selected_indices.add(best_idx)
                
                self.logger.info(f"Found {len(occurrences)} duplicates for pattern {pattern_hash[:8]}...")
        
        # Build final result preserving order
        final_lines = []
        for i, line in enumerate(pat_lines):
            if i in selected_indices or line.strip().startswith((';', '---')) or not line.strip():
                final_lines.append(line)
        
        self.logger.info(f"Deduplicated {len(pat_lines)} lines to {len(final_lines)} lines")
        return final_lines
    
    def _select_best_name(self, occurrences: List[Tuple[int, str]]) -> int:
        """Select the occurrence with the best function name"""
        best_score = -1
        best_idx = occurrences[0][0]
        
        for idx, line in occurrences:
            parts = line.split()
            if len(parts) >= 6:
                name = parts[5]
                score = self._score_function_name(name)
                if score > best_score:
                    best_score = score
                    best_idx = idx
        
        return best_idx
    
    def _score_function_name(self, name: str) -> int:
        """Score a function name based on readability"""
        score = 0
        
        # Prefer demangled names
        if '::' in name:
            score += 100
        
        # Prefer non-mangled names
        if not name.startswith(('_ZN', '_RNv')):
            score += 50
        
        # Prefer shorter names (but not too short)
        if 10 < len(name) < 100:
            score += 20
        
        # Penalize generic names
        if name.startswith(('sub_', 'loc_', 'unk_')):
            score -= 50
        
        # Penalize names with hash suffixes
        if re.search(r'h[0-9a-f]{16}$', name):
            score -= 20
        
        return score
    
    def merge_collision_strategies(self, pat_file: Path, exc_file: Path) -> Dict[str, str]:
        """
        Merge collision information with prevention strategies.
        
        Returns a mapping of function names to their collision resolution strategy.
        """
        collision_map = {}
        
        if exc_file.exists():
            with open(exc_file, 'r') as f:
                lines = f.readlines()
            
            for line in lines:
                line = line.strip()
                if line and not line.startswith(';'):
                    # Parse collision entry
                    if line.startswith(('+', '-')):
                        action = line[0]
                        function_name = line[1:].strip()
                        collision_map[function_name] = 'selected' if action == '+' else 'excluded'
                    else:
                        # Unresolved collision
                        collision_map[line] = 'unresolved'
        
        return collision_map


class EnhancedCollisionHandler:
    """Enhanced collision handler combining prevention and resolution"""
    
    def __init__(self, prevention: Optional[CollisionPrevention] = None):
        self.prevention = prevention or CollisionPrevention()
        self.logger = logging.getLogger(__name__)
    
    def process_pat_file(self, input_pat: Path, output_pat: Path, 
                        version: Optional[str] = None,
                        deduplicate: bool = True,
                        filter_low_quality: bool = True) -> Dict[str, int]:
        """
        Process a PAT file with collision prevention strategies.
        
        Returns:
            Statistics about the processing
        """
        stats = {
            'total_functions': 0,
            'filtered_functions': 0,
            'deduplicated_functions': 0,
            'version_tagged': 0
        }
        
        with open(input_pat, 'r') as f:
            lines = f.readlines()
        
        # Filter low quality functions if requested
        if filter_low_quality:
            filtered_lines = []
            for line in lines:
                if line.strip() and not line.startswith((';', '---')):
                    # This is a function line
                    stats['total_functions'] += 1
                    
                    # Check if we should filter it
                    parts = line.split()
                    if len(parts) >= 6:
                        pattern = parts[0]
                        
                        # Apply new consecutive fixed bytes filtering
                        should_filter, reason = self.prevention.should_filter_pat_pattern(pattern)
                        if should_filter:
                            stats['filtered_functions'] += 1
                            self.logger.debug(f"Filtered pattern: {reason} - {pattern[:32]}...")
                            continue
                        
                        # Apply original length-based filtering as backup
                        if len(pattern) < 64:  # Less than 32 bytes
                            stats['filtered_functions'] += 1
                            self.logger.debug(f"Filtered short pattern: {pattern}")
                            continue
                
                filtered_lines.append(line)
            lines = filtered_lines
        
        # Add version tags if provided
        if version:
            versioned_lines = []
            for line in lines:
                if line.strip() and not line.startswith((';', '---')):
                    parts = line.split()
                    if len(parts) >= 6:
                        # Add version to function name
                        parts[5] = self.prevention.add_version_suffix(parts[5], version)
                        line = ' '.join(parts) + '\n'
                        stats['version_tagged'] += 1
                versioned_lines.append(line)
            lines = versioned_lines
        
        # Deduplicate if requested
        if deduplicate:
            original_count = len([l for l in lines if l.strip() and not l.startswith((';', '---'))])
            lines = self.prevention.deduplicate_patterns(lines, keep_strategy='best_name')
            new_count = len([l for l in lines if l.strip() and not l.startswith((';', '---'))])
            stats['deduplicated_functions'] = original_count - new_count
        
        # Write processed file
        with open(output_pat, 'w') as f:
            f.writelines(lines)
        
        return stats
    
    def auto_resolve_collisions(self, exc_file: Path, strategy: str = 'select_all') -> int:
        """
        Automatically resolve collisions in an EXC file.
        
        Args:
            exc_file: Path to the .exc file
            strategy: Resolution strategy ('select_all', 'select_unique', 'manual')
            
        Returns:
            Number of collisions resolved
        """
        if not exc_file.exists():
            return 0
        
        with open(exc_file, 'r') as f:
            lines = f.readlines()
        
        resolved_lines = []
        resolved_count = 0
        header_done = False
        
        for line in lines:
            # Skip header
            if line.startswith(';---------'):
                header_done = True
                continue
            elif line.startswith(';') and not header_done:
                continue
            
            # Process collision entries
            if line.strip() and not line.startswith((';', '+', '-')):
                if strategy == 'select_all':
                    # Select all functions
                    resolved_lines.append('+' + line)
                    resolved_count += 1
                elif strategy == 'select_unique':
                    # Only select if it appears to be unique
                    parts = line.split()
                    if parts and not parts[0].startswith('sub_'):
                        resolved_lines.append('+' + line)
                        resolved_count += 1
                    else:
                        resolved_lines.append('-' + line)
                else:
                    # Keep as is for manual resolution
                    resolved_lines.append(line)
            else:
                resolved_lines.append(line)
        
        # Write back
        with open(exc_file, 'w') as f:
            f.writelines(resolved_lines)
        
        return resolved_count


# Example usage
if __name__ == '__main__':
    import logging
    logging.basicConfig(level=logging.INFO)
    
    # Test collision prevention
    prevention = CollisionPrevention()
    
    # Test pattern hashing
    pattern1 = ["4889F8488B4E08", "10", "5B3B", "0070", ":0000", "test_function"]
    pattern2 = ["4889F8488B4E08", "10", "5B3B", "0070", ":0000", "another_function"]
    
    hash1 = prevention.pattern_hash(pattern1)
    hash2 = prevention.pattern_hash(pattern2)
    
    print(f"Pattern 1 hash: {hash1[:16]}...")
    print(f"Pattern 2 hash: {hash2[:16]}...")
    print(f"Hashes are {'same' if hash1 == hash2 else 'different'}")
    
    # Test version suffix
    mangled = "_ZN4core3ptr13drop_in_place17hc7f2d4b2b40a26eaE"
    versioned = prevention.add_version_suffix(mangled, "1.2.3")
    print(f"\nOriginal: {mangled}")
    print(f"Versioned: {versioned}")