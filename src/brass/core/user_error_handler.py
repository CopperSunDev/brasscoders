"""
User-friendly error handling for BrassAI.

Provides clear, actionable error messages for common issues
to help users resolve problems quickly.
"""

import sys
import traceback
from typing import Optional, Dict, Any
from pathlib import Path


class UserFriendlyError(Exception):
    """Base class for user-friendly errors with helpful messages."""
    
    def __init__(self, message: str, solution: str, details: Optional[str] = None):
        self.message = message
        self.solution = solution
        self.details = details
        super().__init__(message)
    
    def display(self):
        """Display the error in a user-friendly format."""
        print(f"\n❌ {self.message}")
        print(f"\n💡 Solution: {self.solution}")
        if self.details:
            print(f"\n📋 Details: {self.details}")


def handle_common_errors(func):
    """Decorator to catch and convert common errors to user-friendly messages."""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except PermissionError as e:
            raise UserFriendlyError(
                message="Permission denied while accessing files",
                solution="Check that you have read/write permissions in this directory. "
                        "Try running from your home directory or a project you own.",
                details=str(e)
            )
        except FileNotFoundError as e:
            file_path = str(e).split("'")[1] if "'" in str(e) else "unknown"
            raise UserFriendlyError(
                message=f"File or directory not found: {file_path}",
                solution="Check that the path exists and you typed it correctly. "
                        "Use absolute paths to avoid confusion.",
                details=str(e)
            )
        except UnicodeDecodeError as e:
            raise UserFriendlyError(
                message="Unable to read file due to encoding issues",
                solution="The file may be binary or use a non-UTF-8 encoding. "
                        "BrassAI will skip this file and continue.",
                details=f"Position {e.start}-{e.end}"
            )
        except MemoryError:
            raise UserFriendlyError(
                message="Out of memory while analyzing project",
                solution="Try analyzing a smaller project or set BRASS_MAX_FILES=10000 "
                        "to limit the number of files processed.",
                details="Your system ran out of available memory"
            )
        except KeyboardInterrupt:
            raise UserFriendlyError(
                message="Scan interrupted by user",
                solution="The scan was cancelled. Run 'brasscoders scan' again to restart. "
                        "Partial results may be available in .brass/",
                details="Ctrl+C detected"
            )
        except ModuleNotFoundError as e:
            module = e.name
            raise UserFriendlyError(
                message=f"Required module '{module}' not found",
                solution=f"Install the missing module with: pip install {module}",
                details="This module is required for BrassAI to function"
            )
        except OSError as e:
            if "No space left on device" in str(e):
                raise UserFriendlyError(
                    message="No disk space available",
                    solution="Free up disk space or run BrassAI on a different drive. "
                            "At least 100MB free space is recommended.",
                    details=str(e)
                )
            elif "Too many open files" in str(e):
                raise UserFriendlyError(
                    message="Too many files open",
                    solution="Increase your system's file handle limit with: "
                            "ulimit -n 4096",
                    details=str(e)
                )
            else:
                # Re-raise unknown OS errors
                raise
    return wrapper


def get_error_context() -> Dict[str, Any]:
    """Gather context about the error for better diagnostics."""
    import platform
    
    return {
        "python_version": sys.version,
        "platform": platform.platform(),
        "cwd": str(Path.cwd()),
        "brass_version": "2.0.0",  # TODO: Get from version file
    }


def format_error_report(error: Exception) -> str:
    """Format an error for reporting or logging."""
    context = get_error_context()
    
    report = f"""
BrassAI Error Report
====================

Error Type: {type(error).__name__}
Message: {str(error)}

Context:
- Python: {context['python_version'].split()[0]}
- Platform: {context['platform']}
- Directory: {context['cwd']}
- BrassAI: v{context['brass_version']}

Traceback:
{traceback.format_exc()}
"""
    return report


def suggest_fix_for_error(error: Exception) -> Optional[str]:
    """Suggest a fix for common errors."""
    error_msg = str(error).lower()
    
    fixes = {
        "permission denied": "Try running from a directory where you have write permissions",
        "no such file": "Check that the file path is correct and the file exists",
        "unicode": "The file may contain non-UTF-8 characters. It will be skipped.",
        "memory": "Try setting BRASS_MAX_FILES=10000 to limit memory usage",
        "module": "Install missing dependencies with: pip install -r requirements.txt",
        "disk space": "Free up at least 100MB of disk space",
        "too many open": "Increase file handle limit with: ulimit -n 4096",
        "syntax error": "This file has syntax errors but BrassAI will continue",
        "timeout": "The operation took too long. Try analyzing fewer files.",
        "connection": "Check your internet connection or use --offline mode",
    }
    
    for key, fix in fixes.items():
        if key in error_msg:
            return fix
    
    return None


def setup_global_error_handler():
    """Set up a global error handler for uncaught exceptions."""
    def handle_exception(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            # Handle Ctrl+C gracefully
            print("\n\n⚠️  Scan interrupted by user (Ctrl+C)")
            print("💡 Partial results may be available in .brass/")
            sys.exit(1)
        
        if issubclass(exc_type, UserFriendlyError):
            # Display user-friendly errors
            exc_value.display()
            sys.exit(1)
        
        # For unexpected errors, provide helpful context
        print("\n❌ An unexpected error occurred!")
        
        # Try to suggest a fix
        fix = suggest_fix_for_error(exc_value)
        if fix:
            print(f"\n💡 Suggestion: {fix}")
        
        print("\n📋 Error details:")
        print(f"   Type: {exc_type.__name__}")
        print(f"   Message: {exc_value}")
        
        print("\n💬 Please report this issue at:")
        print("   https://github.com/your-repo/brasscoders/issues")
        
        print("\n📊 Error context:")
        context = get_error_context()
        for key, value in context.items():
            print(f"   {key}: {value}")
        
        # In verbose mode, show full traceback
        if "--verbose" in sys.argv or "-v" in sys.argv:
            print("\n🔍 Full traceback:")
            traceback.print_exception(exc_type, exc_value, exc_traceback)
        else:
            print("\n💡 Run with --verbose for full error details")
        
        sys.exit(1)
    
    sys.excepthook = handle_exception