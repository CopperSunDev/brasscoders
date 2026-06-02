"""
Standardized error handling utilities for the BrassCoders system.

Provides consistent error handling patterns, structured error reporting,
and recovery strategies across all components.
"""

import traceback
from typing import Optional, Any, Dict, Type, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from brass.core.logging_config import get_logger

logger = get_logger(__name__)


class ErrorCategory(Enum):
    """Categories of errors for structured reporting."""
    USER_INPUT = "user_input"          # Invalid user input or arguments
    FILE_ACCESS = "file_access"        # File system access issues
    PARSING = "parsing"                # Code/data parsing failures
    ANALYSIS = "analysis"              # Analysis logic failures
    SYSTEM = "system"                  # System-level errors (permissions, resources)
    CONFIGURATION = "configuration"   # Configuration/setup issues
    NETWORK = "network"                # Network-related errors
    DEPENDENCY = "dependency"          # Missing or failed dependencies


@dataclass
class BrassError:
    """
    Structured error information for consistent error handling.
    
    Provides detailed error context for logging, debugging, and user feedback.
    """
    category: ErrorCategory
    message: str
    component: str
    operation: str
    timestamp: datetime = field(default_factory=datetime.now)
    
    # Optional detailed information
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    original_exception: Optional[Exception] = None
    recovery_suggestion: Optional[str] = None
    user_message: Optional[str] = None  # User-friendly message
    
    # Error context
    context: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary for serialization."""
        return {
            'category': self.category.value,
            'message': self.message,
            'component': self.component,
            'operation': self.operation,
            'timestamp': self.timestamp.isoformat(),
            'file_path': self.file_path,
            'line_number': self.line_number,
            'original_exception': str(self.original_exception) if self.original_exception else None,
            'recovery_suggestion': self.recovery_suggestion,
            'user_message': self.user_message,
            'context': self.context
        }
    
    def get_user_message(self) -> str:
        """Get user-friendly error message."""
        if self.user_message:
            return self.user_message
        
        # Generate appropriate user message based on category
        if self.category == ErrorCategory.FILE_ACCESS:
            return f"Unable to access file: {self.file_path or 'unknown file'}"
        elif self.category == ErrorCategory.PARSING:
            return f"Failed to parse content in {self.file_path or 'file'}"
        elif self.category == ErrorCategory.USER_INPUT:
            return f"Invalid input: {self.message}"
        else:
            return f"Error in {self.component}: {self.message}"


class ErrorHandler:
    """
    Centralized error handling with consistent patterns.
    
    Provides utilities for handling, logging, and recovering from different
    types of errors across the BrassCoders system.
    """
    
    @staticmethod
    def handle_error(error: BrassError, 
                    log_level: str = "error",
                    raise_exception: bool = False,
                    report_error: bool = True) -> BrassError:
        """
        Handle an error with consistent logging and optional exception raising.
        
        Args:
            error: BrassError instance with error details
            log_level: Logging level ('debug', 'info', 'warning', 'error')
            raise_exception: Whether to raise the original exception
            report_error: Whether to add error to structured reporting
            
        Returns:
            The processed BrassError for further handling
        """
        # Log the error with appropriate level
        log_message = f"{error.component}.{error.operation}: {error.message}"
        if error.file_path:
            log_message += f" (file: {error.file_path}"
            if error.line_number:
                log_message += f":{error.line_number}"
            log_message += ")"
        
        if error.original_exception:
            log_message += f" - {type(error.original_exception).__name__}: {error.original_exception}"
        
        # Log based on specified level
        log_func = getattr(logger, log_level.lower(), logger.error)
        log_func(log_message, exc_info=error.original_exception is not None)
        
        # Add to structured error reporting if requested
        if report_error:
            try:
                # Import here to avoid circular imports
                from brass.core.error_reporter import report_error as report_to_system
                report_to_system(error)
            except ImportError:
                # Error reporter not available, skip reporting
                pass
        
        # Optionally raise the original exception
        if raise_exception and error.original_exception:
            raise error.original_exception
        
        return error
    
    @staticmethod
    def safe_execute(operation: Callable,
                    component: str,
                    operation_name: str,
                    error_category: ErrorCategory = ErrorCategory.ANALYSIS,
                    default_return: Any = None,
                    **error_context) -> Any:
        """
        Safely execute an operation with consistent error handling.
        
        Args:
            operation: Function to execute
            component: Component name for error reporting
            operation_name: Operation name for error reporting
            error_category: Category of potential errors
            default_return: Value to return on error
            **error_context: Additional context for error reporting
            
        Returns:
            Operation result or default_return on error
        """
        try:
            return operation()
        except Exception as e:
            error = BrassError(
                category=error_category,
                message=str(e),
                component=component,
                operation=operation_name,
                original_exception=e,
                context=error_context
            )
            
            ErrorHandler.handle_error(error)
            return default_return
    
    @staticmethod
    def create_file_access_error(file_path: str,
                               component: str,
                               operation: str,
                               exception: Exception) -> BrassError:
        """Create a standardized file access error."""
        return BrassError(
            category=ErrorCategory.FILE_ACCESS,
            message=f"Failed to access file: {exception}",
            component=component,
            operation=operation,
            file_path=file_path,
            original_exception=exception,
            recovery_suggestion="Check file permissions and path validity",
            user_message=f"Cannot access file '{file_path}'. Please check the file exists and you have permission to read it."
        )
    
    @staticmethod
    def create_parsing_error(content_type: str,
                           component: str,
                           operation: str,
                           exception: Exception,
                           file_path: Optional[str] = None,
                           line_number: Optional[int] = None) -> BrassError:
        """Create a standardized parsing error."""
        return BrassError(
            category=ErrorCategory.PARSING,
            message=f"Failed to parse {content_type}: {exception}",
            component=component,
            operation=operation,
            file_path=file_path,
            line_number=line_number,
            original_exception=exception,
            recovery_suggestion=f"Check {content_type} syntax and format",
            user_message=f"Parse error in {file_path or content_type}. The content may have syntax errors."
        )
    
    @staticmethod
    def create_analysis_error(analysis_type: str,
                            component: str,
                            operation: str,
                            exception: Exception,
                            file_path: Optional[str] = None) -> BrassError:
        """Create a standardized analysis error."""
        return BrassError(
            category=ErrorCategory.ANALYSIS,
            message=f"Analysis failed for {analysis_type}: {exception}",
            component=component,
            operation=operation,
            file_path=file_path,
            original_exception=exception,
            recovery_suggestion="Review analysis input and configuration",
            user_message=f"Analysis error in {file_path or analysis_type}. This file will be skipped."
        )


# Convenience functions for common error patterns
def handle_file_error(file_path: str, component: str, operation: str, exception: Exception) -> BrassError:
    """Handle file access errors consistently."""
    error = ErrorHandler.create_file_access_error(file_path, component, operation, exception)
    return ErrorHandler.handle_error(error)

def handle_parsing_error(content_type: str, component: str, operation: str, exception: Exception,
                        file_path: Optional[str] = None, line_number: Optional[int] = None) -> BrassError:
    """Handle parsing errors consistently."""
    error = ErrorHandler.create_parsing_error(content_type, component, operation, exception, file_path, line_number)
    return ErrorHandler.handle_error(error)

def handle_analysis_error(analysis_type: str, component: str, operation: str, exception: Exception,
                         file_path: Optional[str] = None) -> BrassError:
    """Handle analysis errors consistently."""
    error = ErrorHandler.create_analysis_error(analysis_type, component, operation, exception, file_path)
    return ErrorHandler.handle_error(error)

def safe_file_operation(file_path: str, operation: Callable, component: str, 
                       operation_name: str, default_return: Any = None) -> Any:
    """Safely perform file operations with consistent error handling."""
    return ErrorHandler.safe_execute(
        operation=operation,
        component=component,
        operation_name=operation_name,
        error_category=ErrorCategory.FILE_ACCESS,
        default_return=default_return,
        file_path=file_path
    )