"""
Centralized logging configuration for the BrassCoders system.

Provides consistent logging setup across all modules with appropriate
formatting, levels, and handlers for different use cases.
"""

import logging
import sys
from typing import Optional
from pathlib import Path


class BrassLogger:
    """
    Centralized logging configuration for the BrassCoders system.
    
    Provides consistent logging setup with:
    - Structured log formatting
    - Appropriate log levels for different components
    - Optional file output for debugging
    - Performance-friendly configuration
    """
    
    _configured = False
    _loggers = {}
    
    @classmethod
    def setup_logging(cls, 
                     level: int = logging.INFO,
                     verbose: bool = False,
                     log_file: Optional[Path] = None) -> None:
        """
        Configure logging for the entire BrassCoders system.
        
        Args:
            level: Base logging level
            verbose: Enable verbose (DEBUG) logging
            log_file: Optional file path for log output
        """
        # Allow reconfiguration for different log files or settings
        # Remove existing handlers to avoid duplicates
        
        # Determine effective log level
        effective_level = logging.DEBUG if verbose else level
        
        # Configure brass logger hierarchy
        brass_logger = logging.getLogger('brass')
        brass_logger.setLevel(effective_level)
        
        # Remove existing handlers to avoid duplicates
        for handler in brass_logger.handlers[:]:
            brass_logger.removeHandler(handler)
        
        # Create formatter
        formatter = logging.Formatter(
            fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Console handler for internal logging (not user-facing output)
        # Only show WARNING and above on console to avoid cluttering user output
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(logging.WARNING)
        console_handler.setFormatter(formatter)
        brass_logger.addHandler(console_handler)
        
        # File handler for detailed logging (if specified)
        if log_file:
            try:
                log_file.parent.mkdir(parents=True, exist_ok=True)
                file_handler = logging.FileHandler(log_file)
                file_handler.setLevel(effective_level)
                file_handler.setFormatter(formatter)
                brass_logger.addHandler(file_handler)
                # brass.log contains source-fragment debug output, raw paths,
                # and stack traces with embedded source — same sensitivity
                # tier as the YAML files. Match the 0600 invariant the YAML
                # writer enforces. POSIX-only; on Windows we rely on the
                # 0700 directory perm.
                import os as _os
                import platform as _platform
                if _platform.system() != 'Windows':
                    try:
                        _os.chmod(log_file, 0o600)
                    except OSError:
                        pass
            except Exception as e:
                # Fallback: log to stderr if file logging fails
                brass_logger.warning(f"Could not setup file logging to {log_file}: {e}")
        
        cls._configured = True
    
    @classmethod
    def get_logger(cls, name: str) -> logging.Logger:
        """
        Get a logger instance for a specific module.
        
        Args:
            name: Logger name (typically __name__ from calling module)
            
        Returns:
            Configured logger instance
        """
        if name not in cls._loggers:
            # Ensure logging is configured
            if not cls._configured:
                cls.setup_logging()
            
            # Create logger under brass namespace
            if not name.startswith('brass.'):
                if '.' in name and name.split('.')[-1] in ['brass_cli', 'code_scanner', 'privacy_scanner', 
                                                          'intelligence_ranker', 'output_generator', 
                                                          'file_watcher', 'content_safety']:
                    logger_name = f"brass.{name.split('.')[-1]}"
                else:
                    logger_name = f"brass.{name}"
            else:
                logger_name = name
            
            cls._loggers[name] = logging.getLogger(logger_name)
        
        return cls._loggers[name]
    
    @classmethod
    def reset_configuration(cls) -> None:
        """Reset logging configuration (primarily for testing)."""
        cls._configured = False
        cls._loggers.clear()


def get_logger(name: str) -> logging.Logger:
    """
    Convenience function to get a logger instance.
    
    Args:
        name: Logger name (typically __name__ from calling module)
        
    Returns:
        Configured logger instance
    """
    return BrassLogger.get_logger(name)


# Module-level convenience functions for common log levels
def log_info(name: str, message: str) -> None:
    """Log an info message."""
    get_logger(name).info(message)

def log_warning(name: str, message: str) -> None:
    """Log a warning message."""
    get_logger(name).warning(message)

def log_error(name: str, message: str, exc_info: bool = False) -> None:
    """Log an error message."""
    get_logger(name).error(message, exc_info=exc_info)

def log_debug(name: str, message: str) -> None:
    """Log a debug message."""
    get_logger(name).debug(message)