"""
Unit tests for the error handling system.

Tests the BrassError dataclass, ErrorHandler, and error reporting functionality
to ensure consistent error handling across the system.
"""

import pytest
from datetime import datetime
from unittest.mock import Mock, patch

from brass.core.error_handling import (
    BrassError, ErrorCategory, ErrorHandler,
    handle_file_error, handle_parsing_error, handle_analysis_error,
    safe_file_operation
)


class TestBrassError:
    """Test the BrassError dataclass."""
    
    def test_brass_error_creation(self):
        """BrassError can be created with required fields."""
        error = BrassError(
            category=ErrorCategory.FILE_ACCESS,
            message="Test error message",
            component="TestComponent",
            operation="test_operation"
        )
        
        assert error.category == ErrorCategory.FILE_ACCESS
        assert error.message == "Test error message"
        assert error.component == "TestComponent"
        assert error.operation == "test_operation"
        assert isinstance(error.timestamp, datetime)
    
    def test_brass_error_optional_fields(self):
        """BrassError handles optional fields correctly."""
        error = BrassError(
            category=ErrorCategory.PARSING,
            message="Parse error",
            component="Parser",
            operation="parse_file",
            file_path="test.py",
            line_number=42,
            recovery_suggestion="Check syntax",
            user_message="File has syntax errors"
        )
        
        assert error.file_path == "test.py"
        assert error.line_number == 42
        assert error.recovery_suggestion == "Check syntax"
        assert error.user_message == "File has syntax errors"
    
    def test_brass_error_to_dict(self):
        """BrassError can be serialized to dictionary."""
        error = BrassError(
            category=ErrorCategory.ANALYSIS,
            message="Analysis failed",
            component="Analyzer",
            operation="analyze_code",
            context={"retry_count": 3}
        )
        
        error_dict = error.to_dict()
        
        assert error_dict['category'] == 'analysis'
        assert error_dict['message'] == 'Analysis failed'
        assert error_dict['component'] == 'Analyzer'
        assert error_dict['operation'] == 'analyze_code'
        assert error_dict['context'] == {"retry_count": 3}
        assert 'timestamp' in error_dict
    
    def test_get_user_message_defaults(self):
        """BrassError generates appropriate user messages by category."""
        # File access error
        file_error = BrassError(
            category=ErrorCategory.FILE_ACCESS,
            message="Permission denied",
            component="FileReader",
            operation="read_file",
            file_path="protected.py"
        )
        
        user_msg = file_error.get_user_message()
        assert "protected.py" in user_msg
        assert "access file" in user_msg.lower()
        
        # Parsing error
        parse_error = BrassError(
            category=ErrorCategory.PARSING,
            message="Invalid syntax",
            component="Parser",
            operation="parse_ast",
            file_path="broken.py"
        )
        
        user_msg = parse_error.get_user_message()
        assert "broken.py" in user_msg
        assert "parse" in user_msg.lower()
    
    def test_get_user_message_custom(self):
        """BrassError uses custom user message when provided."""
        error = BrassError(
            category=ErrorCategory.SYSTEM,
            message="Out of memory",
            component="System",
            operation="allocate",
            user_message="The system is running low on memory"
        )
        
        assert error.get_user_message() == "The system is running low on memory"


class TestErrorHandler:
    """Test the ErrorHandler class."""
    
    @patch('brass.core.error_handling.logger')
    def test_handle_error_logging(self, mock_logger):
        """ErrorHandler logs errors with correct format."""
        error = BrassError(
            category=ErrorCategory.FILE_ACCESS,
            message="File not found",
            component="FileReader",
            operation="read_file",
            file_path="missing.py"
        )
        
        result = ErrorHandler.handle_error(error, log_level="warning")
        
        # Check that logging was called
        mock_logger.warning.assert_called_once()
        call_args = mock_logger.warning.call_args[0][0]
        assert "FileReader.read_file" in call_args
        assert "File not found" in call_args
        assert "missing.py" in call_args
        
        # Check return value
        assert result is error
    
    @patch('brass.core.error_handling.logger')
    def test_handle_error_with_exception(self, mock_logger):
        """ErrorHandler handles original exceptions correctly."""
        original_exception = ValueError("Invalid value")
        error = BrassError(
            category=ErrorCategory.PARSING,
            message="Parse failed",
            component="Parser", 
            operation="parse_data",
            original_exception=original_exception
        )
        
        # Test without raising
        result = ErrorHandler.handle_error(error, raise_exception=False)
        assert result is error
        
        # Test with raising
        with pytest.raises(ValueError, match="Invalid value"):
            ErrorHandler.handle_error(error, raise_exception=True)
    
    def test_safe_execute_success(self):
        """safe_execute returns operation result on success."""
        def successful_operation():
            return "success_result"
        
        result = ErrorHandler.safe_execute(
            operation=successful_operation,
            component="TestComponent",
            operation_name="test_op",
            default_return="default"
        )
        
        assert result == "success_result"
    
    @patch('brass.core.error_handling.logger')
    def test_safe_execute_failure(self, mock_logger):
        """safe_execute returns default value on failure."""
        def failing_operation():
            raise ValueError("Operation failed")
        
        result = ErrorHandler.safe_execute(
            operation=failing_operation,
            component="TestComponent", 
            operation_name="test_op",
            default_return="default_value"
        )
        
        assert result == "default_value"
        mock_logger.error.assert_called_once()
    
    def test_create_file_access_error(self):
        """ErrorHandler creates proper file access errors."""
        exception = FileNotFoundError("No such file")
        
        error = ErrorHandler.create_file_access_error(
            file_path="missing.py",
            component="FileReader",
            operation="read_file", 
            exception=exception
        )
        
        assert error.category == ErrorCategory.FILE_ACCESS
        assert error.file_path == "missing.py"
        assert error.component == "FileReader"
        assert error.operation == "read_file"
        assert error.original_exception is exception
        assert "permission" in error.recovery_suggestion.lower()
    
    def test_create_parsing_error(self):
        """ErrorHandler creates proper parsing errors."""
        exception = SyntaxError("Invalid syntax")
        
        error = ErrorHandler.create_parsing_error(
            content_type="Python code",
            component="CodeScanner",
            operation="parse_ast", 
            exception=exception,
            file_path="broken.py",
            line_number=15
        )
        
        assert error.category == ErrorCategory.PARSING
        assert error.file_path == "broken.py"
        assert error.line_number == 15
        assert error.original_exception is exception
        assert "Python code" in error.message
    
    def test_create_analysis_error(self):
        """ErrorHandler creates proper analysis errors."""
        exception = RuntimeError("Analysis failed")
        
        error = ErrorHandler.create_analysis_error(
            analysis_type="code complexity",
            component="CodeScanner",
            operation="analyze_complexity",
            exception=exception,
            file_path="complex.py"
        )
        
        assert error.category == ErrorCategory.ANALYSIS
        assert error.file_path == "complex.py"
        assert error.original_exception is exception
        assert "code complexity" in error.message


class TestErrorHandlingHelpers:
    """Test convenience functions for error handling."""
    
    @patch('brass.core.error_handling.ErrorHandler.handle_error')
    def test_handle_file_error(self, mock_handle):
        """handle_file_error creates and handles file errors."""
        exception = PermissionError("Access denied")
        
        handle_file_error("protected.py", "FileReader", "read", exception)
        
        # Check that handle_error was called
        mock_handle.assert_called_once()
        error_arg = mock_handle.call_args[0][0]
        assert error_arg.category == ErrorCategory.FILE_ACCESS
        assert error_arg.file_path == "protected.py"
    
    @patch('brass.core.error_handling.ErrorHandler.handle_error')
    def test_handle_parsing_error(self, mock_handle):
        """handle_parsing_error creates and handles parsing errors."""
        exception = SyntaxError("Bad syntax")
        
        handle_parsing_error("YAML", "Parser", "parse", exception, "config.yaml", 10)
        
        mock_handle.assert_called_once()
        error_arg = mock_handle.call_args[0][0]
        assert error_arg.category == ErrorCategory.PARSING
        assert error_arg.file_path == "config.yaml"
        assert error_arg.line_number == 10
    
    @patch('brass.core.error_handling.ErrorHandler.handle_error')  
    def test_handle_analysis_error(self, mock_handle):
        """handle_analysis_error creates and handles analysis errors."""
        exception = RuntimeError("Analysis crashed")
        
        handle_analysis_error("security", "Scanner", "scan", exception, "test.py")
        
        mock_handle.assert_called_once()
        error_arg = mock_handle.call_args[0][0]
        assert error_arg.category == ErrorCategory.ANALYSIS
        assert error_arg.file_path == "test.py"
    
    def test_safe_file_operation_success(self):
        """safe_file_operation returns operation result on success."""
        def read_file():
            return "file contents"
        
        result = safe_file_operation(
            file_path="test.py",
            operation=read_file,
            component="FileReader",
            operation_name="read",
            default_return=""
        )
        
        assert result == "file contents"
    
    @patch('brass.core.error_handling.ErrorHandler.safe_execute')
    def test_safe_file_operation_calls_safe_execute(self, mock_safe_execute):
        """safe_file_operation uses ErrorHandler.safe_execute."""
        def dummy_op():
            return "result"
        
        safe_file_operation("test.py", dummy_op, "Component", "op", "default")
        
        mock_safe_execute.assert_called_once()
        args = mock_safe_execute.call_args
        assert args[1]['error_category'] == ErrorCategory.FILE_ACCESS
        assert args[1]['file_path'] == "test.py"


class TestErrorCategories:
    """Test ErrorCategory enum."""
    
    def test_error_category_values(self):
        """ErrorCategory has expected values."""
        expected_categories = {
            'USER_INPUT', 'FILE_ACCESS', 'PARSING', 'ANALYSIS',
            'SYSTEM', 'CONFIGURATION', 'NETWORK', 'DEPENDENCY'
        }
        
        actual_categories = {cat.name for cat in ErrorCategory}
        assert expected_categories.issubset(actual_categories)
    
    def test_error_category_string_values(self):
        """ErrorCategory has proper string values."""
        assert ErrorCategory.FILE_ACCESS.value == "file_access"
        assert ErrorCategory.PARSING.value == "parsing"
        assert ErrorCategory.ANALYSIS.value == "analysis"