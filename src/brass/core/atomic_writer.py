"""
Atomic file writing utilities for BrassAI.

Provides atomic write operations to prevent partial file corruption
when operations are interrupted (Ctrl+C, kill, crashes).
"""

import os
import stat
import yaml
import tempfile
from pathlib import Path
from typing import Dict, Any, Optional
import platform

from brass.core.logging_config import get_logger

logger = get_logger(__name__)


# Owner-only permissions for files containing analysis output. BrassCoders scans private
# source code, so .brass/ contents must not be world-readable. POSIX-only; on Windows
# we rely on filesystem ACLs.
_OWNER_ONLY_FILE_MODE = stat.S_IRUSR | stat.S_IWUSR  # 0o600


def _apply_owner_only_perms(file_path: Path) -> None:
    """Set 0600 perms on POSIX. Best-effort, never raises."""
    if platform.system() == 'Windows':
        return
    try:
        os.chmod(file_path, _OWNER_ONLY_FILE_MODE)
    except OSError as exc:
        logger.debug(f"Could not chmod 0600 on {file_path}: {exc}")


class AtomicFileWriter:
    """
    Provides atomic write operations for files.
    
    Uses the temp-file + rename pattern to ensure files are either
    fully written or not written at all. Handles platform differences.
    """
    
    @staticmethod
    def write_yaml_atomic(file_path: Path, data: Dict[str, Any], 
                         yaml_kwargs: Optional[Dict[str, Any]] = None) -> None:
        """
        Write YAML data atomically to prevent corruption.
        
        Args:
            file_path: Target file path
            data: Data to write as YAML
            yaml_kwargs: Optional kwargs for yaml.dump()
            
        Raises:
            Exception: If write fails (original file unchanged)
        """
        # Default YAML formatting options
        if yaml_kwargs is None:
            yaml_kwargs = {
                'default_flow_style': False,
                'sort_keys': False,
                'allow_unicode': True,
                'indent': 2,
                'width': 120
            }
        
        # Create temp file in same directory (for atomic rename)
        temp_fd, temp_path = tempfile.mkstemp(
            dir=file_path.parent,
            prefix=f'.{file_path.stem}_',
            suffix='.tmp'
        )
        
        try:
            # Write to temp file
            with os.fdopen(temp_fd, 'w', encoding='utf-8') as f:
                yaml.dump(data, f, **yaml_kwargs)
                # Ensure data is written to disk
                f.flush()
                os.fsync(f.fileno())
            
            # Platform-specific atomic rename
            if platform.system() == 'Windows':
                # Windows doesn't support atomic rename if target exists
                if file_path.exists():
                    file_path.unlink()
            
            # Atomic rename
            Path(temp_path).rename(file_path)
            _apply_owner_only_perms(file_path)
            logger.debug(f"Atomically wrote file: {file_path}")

        except Exception as e:
            # Clean up temp file on error
            try:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
            except:
                pass

            logger.error(f"Atomic write failed for {file_path}: {e}")
            raise

    @staticmethod
    def write_text_atomic(file_path: Path, content: str,
                         encoding: str = 'utf-8') -> None:
        """
        Write text content atomically.
        
        Args:
            file_path: Target file path
            content: Text content to write
            encoding: Text encoding (default: utf-8)
            
        Raises:
            Exception: If write fails (original file unchanged)
        """
        # Create temp file in same directory
        temp_fd, temp_path = tempfile.mkstemp(
            dir=file_path.parent,
            prefix=f'.{file_path.stem}_',
            suffix='.tmp'
        )
        
        try:
            # Write to temp file
            with os.fdopen(temp_fd, 'w', encoding=encoding) as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            
            # Platform-specific atomic rename
            if platform.system() == 'Windows':
                if file_path.exists():
                    file_path.unlink()
            
            # Atomic rename
            Path(temp_path).rename(file_path)
            _apply_owner_only_perms(file_path)
            logger.debug(f"Atomically wrote text file: {file_path}")

        except Exception as e:
            # Clean up temp file on error
            try:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
            except:
                pass

            logger.error(f"Atomic text write failed for {file_path}: {e}")
            raise
    
    @staticmethod
    def can_write_atomic(directory: Path) -> bool:
        """
        Check if atomic writes are possible in a directory.
        
        Args:
            directory: Directory to check
            
        Returns:
            True if atomic writes are supported
        """
        try:
            # Try to create a temp file
            temp_fd, temp_path = tempfile.mkstemp(
                dir=directory,
                prefix='.atomic_test_',
                suffix='.tmp'
            )
            
            # Clean up
            os.close(temp_fd)
            os.unlink(temp_path)
            
            return True
            
        except Exception:
            return False