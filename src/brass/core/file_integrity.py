"""
File integrity checking for BrassAI.

Detects file modifications during read operations to prevent
analyzing corrupted or partially written files.
"""

import os
from pathlib import Path
from typing import Optional, Tuple, NamedTuple
from datetime import datetime

from brass.core.logging_config import get_logger

logger = get_logger(__name__)


class FileStats(NamedTuple):
    """File statistics for integrity checking."""
    size: int
    mtime: float
    inode: int  # Unix only, 0 on Windows


class FileIntegrityChecker:
    """
    Detects file modifications during read operations.
    
    Uses file metadata (size, mtime, inode) to detect changes
    that occur while reading files. This prevents analyzing
    corrupted data from concurrent modifications.
    """
    
    @staticmethod
    def read_with_integrity_check(file_path: Path, 
                                 encoding: str = 'utf-8',
                                 errors: str = 'strict') -> Optional[str]:
        """
        Read file content with integrity verification.
        
        Args:
            file_path: Path to file to read
            encoding: Text encoding (default: utf-8)
            errors: Error handling mode (default: strict)
            
        Returns:
            File content if unchanged during read, None if modified
        """
        try:
            # Get initial file stats
            stats_before = FileIntegrityChecker._get_file_stats(file_path)
            
            # Read file content
            content = file_path.read_text(encoding=encoding, errors=errors)
            
            # Get final file stats
            stats_after = FileIntegrityChecker._get_file_stats(file_path)
            
            # Check if file changed
            if FileIntegrityChecker._stats_changed(stats_before, stats_after):
                logger.warning(
                    f"File modified during read: {file_path} "
                    f"(size: {stats_before.size}→{stats_after.size}, "
                    f"mtime: {stats_before.mtime}→{stats_after.mtime})"
                )
                return None
            
            return content
            
        except Exception as e:
            logger.debug(f"Failed to read file with integrity check {file_path}: {e}")
            return None
    
    @staticmethod
    def read_binary_with_integrity_check(file_path: Path) -> Optional[bytes]:
        """
        Read binary file with integrity verification.
        
        Args:
            file_path: Path to file to read
            
        Returns:
            File content if unchanged during read, None if modified
        """
        try:
            # Get initial file stats
            stats_before = FileIntegrityChecker._get_file_stats(file_path)
            
            # Read file content
            content = file_path.read_bytes()
            
            # Get final file stats
            stats_after = FileIntegrityChecker._get_file_stats(file_path)
            
            # Check if file changed
            if FileIntegrityChecker._stats_changed(stats_before, stats_after):
                logger.warning(f"Binary file modified during read: {file_path}")
                return None
            
            return content
            
        except Exception as e:
            logger.debug(f"Failed to read binary file with integrity check {file_path}: {e}")
            return None
    
    @staticmethod
    def _get_file_stats(file_path: Path) -> FileStats:
        """
        Get file statistics for comparison.
        
        Args:
            file_path: Path to file
            
        Returns:
            FileStats with size, mtime, and inode
        """
        stat = file_path.stat()
        
        # Get inode on Unix, 0 on Windows
        inode = getattr(stat, 'st_ino', 0)
        
        return FileStats(
            size=stat.st_size,
            mtime=stat.st_mtime,
            inode=inode
        )
    
    @staticmethod
    def _stats_changed(before: FileStats, after: FileStats) -> bool:
        """
        Check if file stats indicate modification.
        
        Args:
            before: Stats before read
            after: Stats after read
            
        Returns:
            True if file was modified
        """
        # Size change is definitive
        if before.size != after.size:
            return True
        
        # mtime change indicates modification
        if before.mtime != after.mtime:
            return True
        
        # On Unix, inode change means file was replaced
        if before.inode != 0 and before.inode != after.inode:
            return True
        
        return False
    
    @staticmethod
    def monitor_file_changes(file_path: Path, 
                           check_interval_ms: int = 100) -> Tuple[bool, float]:
        """
        Monitor a file for changes over a time period.
        
        Args:
            file_path: File to monitor
            check_interval_ms: How long to monitor in milliseconds
            
        Returns:
            Tuple of (changed, elapsed_ms)
        """
        start_time = datetime.now()
        stats_initial = FileIntegrityChecker._get_file_stats(file_path)
        
        # Wait for specified interval
        import time
        time.sleep(check_interval_ms / 1000.0)
        
        stats_final = FileIntegrityChecker._get_file_stats(file_path)
        elapsed_ms = (datetime.now() - start_time).total_seconds() * 1000
        
        changed = FileIntegrityChecker._stats_changed(stats_initial, stats_final)
        
        return changed, elapsed_ms


def safe_file_read(file_path: Path, encoding: str = 'utf-8', 
                  errors: str = 'ignore') -> Optional[str]:
    """
    Convenience function for reading files with integrity checking.
    
    Drop-in replacement for file reading with race condition detection.
    
    Args:
        file_path: Path to file to read
        encoding: Text encoding (default: utf-8)
        errors: Error handling (default: ignore)
        
    Returns:
        File content if stable, None if modified during read
    """
    return FileIntegrityChecker.read_with_integrity_check(
        file_path, encoding=encoding, errors=errors
    )