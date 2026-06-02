"""
Unit tests for the centralized logging configuration system.

Tests the BrassLogger class and logging utilities to ensure consistent
logging behavior across all system components.
"""

import pytest
import logging
from unittest.mock import Mock, patch, mock_open
from pathlib import Path

from brass.core.logging_config import (
    BrassLogger, get_logger, log_info, log_warning, log_error, log_debug
)


class TestBrassLogger:
    """Test the centralized BrassLogger configuration."""
    
    def setup_method(self):
        """Reset logger configuration before each test."""
        BrassLogger.reset_configuration()
    
    def test_brass_logger_setup_does_not_duplicate_handlers(self):
        """Successive setup_logging calls don't accumulate handlers.

        Originally asserted setup_logging was a one-shot singleton; the actual
        code intentionally allows reconfiguration (different log file paths /
        verbosity levels per scan). The real contract worth holding is that
        repeated setup doesn't *duplicate* console handlers — that would
        produce double-logged output.
        """
        BrassLogger.setup_logging(verbose=True)
        brass_logger = logging.getLogger('brass')
        first_handler_count = len(brass_logger.handlers)

        BrassLogger.setup_logging(verbose=False)
        second_handler_count = len(brass_logger.handlers)

        # Should be the same — setup_logging removes existing handlers
        # before adding new ones.
        assert first_handler_count == second_handler_count
    
    def test_setup_logging_verbose_mode(self):
        """setup_logging configures verbose (DEBUG) mode correctly."""
        with patch('brass.core.logging_config.logging.getLogger') as mock_get_logger:
            mock_logger = Mock()
            mock_logger.handlers = []  # Mock the handlers list
            mock_get_logger.return_value = mock_logger
            
            BrassLogger.setup_logging(verbose=True)
            
            # Should set DEBUG level for verbose mode
            mock_logger.setLevel.assert_called_with(logging.DEBUG)
    
    def test_setup_logging_normal_mode(self):
        """setup_logging configures normal (INFO) mode correctly."""
        with patch('brass.core.logging_config.logging.getLogger') as mock_get_logger:
            mock_logger = Mock()
            mock_logger.handlers = []  # Mock the handlers list
            mock_get_logger.return_value = mock_logger
            
            BrassLogger.setup_logging(verbose=False)
            
            # Should set INFO level for normal mode
            mock_logger.setLevel.assert_called_with(logging.INFO)
    
    def test_setup_logging_with_file_output(self):
        """setup_logging configures file output when specified."""
        test_log_file = Path("/tmp/test_brass.log")
        
        with patch('brass.core.logging_config.logging.getLogger') as mock_get_logger, \
             patch('brass.core.logging_config.logging.FileHandler') as mock_file_handler:
            
            mock_logger = Mock()
            mock_logger.handlers = []  # Mock the handlers list
            mock_get_logger.return_value = mock_logger
            mock_handler = Mock()
            mock_file_handler.return_value = mock_handler
            
            BrassLogger.setup_logging(log_file=test_log_file)
            
            # Should create file handler
            mock_file_handler.assert_called_once_with(test_log_file)
            mock_logger.addHandler.assert_called()
    
    def test_setup_logging_file_error_handling(self):
        """setup_logging handles file creation errors gracefully."""
        test_log_file = Path("/invalid/path/test.log")
        
        with patch('brass.core.logging_config.logging.getLogger') as mock_get_logger, \
             patch('brass.core.logging_config.logging.FileHandler') as mock_file_handler:
            
            mock_logger = Mock()
            mock_logger.handlers = []  # Mock the handlers list
            mock_get_logger.return_value = mock_logger
            mock_file_handler.side_effect = PermissionError("Cannot create file")
            
            # Should not raise exception
            BrassLogger.setup_logging(log_file=test_log_file)
            
            # Should log warning about file logging failure
            mock_logger.warning.assert_called()
    
    def test_get_logger_creates_brass_namespace(self):
        """get_logger creates loggers in brass namespace."""
        logger1 = BrassLogger.get_logger("test_module")
        logger2 = BrassLogger.get_logger("brass.already_namespaced")
        logger3 = BrassLogger.get_logger("some.module.code_scanner")
        
        # Should create appropriate logger names
        assert logger1.name == "brass.test_module"
        assert logger2.name == "brass.already_namespaced"
        assert logger3.name == "brass.code_scanner"  # Should extract known component
    
    def test_get_logger_caching(self):
        """get_logger returns cached logger instances."""
        logger1 = BrassLogger.get_logger("test_component")
        logger2 = BrassLogger.get_logger("test_component")
        
        # Should return same instance
        assert logger1 is logger2
    
    def test_reset_configuration(self):
        """reset_configuration clears state properly."""
        # Setup initial state
        BrassLogger.setup_logging(verbose=True)
        logger = BrassLogger.get_logger("test")
        
        # Reset
        BrassLogger.reset_configuration()
        
        # Should be able to setup again
        with patch('brass.core.logging_config.logging.getLogger') as mock_get_logger:
            mock_logger = Mock()
            mock_logger.handlers = []  # Mock the handlers list
            mock_get_logger.return_value = mock_logger
            
            BrassLogger.setup_logging(verbose=False)
            mock_logger.setLevel.assert_called_with(logging.INFO)


class TestLoggingUtilities:
    """Test logging utility functions."""
    
    def setup_method(self):
        """Reset logger configuration before each test."""
        BrassLogger.reset_configuration()
    
    def test_get_logger_convenience_function(self):
        """get_logger convenience function works correctly."""
        logger = get_logger("test_module")
        
        assert logger is not None
        assert isinstance(logger, logging.Logger)
        assert "brass" in logger.name
    
    @patch('brass.core.logging_config.get_logger')
    def test_log_info_convenience(self, mock_get_logger):
        """log_info convenience function works correctly."""
        mock_logger = Mock()
        mock_get_logger.return_value = mock_logger
        
        log_info("test_module", "Test info message")
        
        mock_get_logger.assert_called_once_with("test_module")
        mock_logger.info.assert_called_once_with("Test info message")
    
    @patch('brass.core.logging_config.get_logger')
    def test_log_warning_convenience(self, mock_get_logger):
        """log_warning convenience function works correctly."""
        mock_logger = Mock()
        mock_get_logger.return_value = mock_logger
        
        log_warning("test_module", "Test warning message")
        
        mock_get_logger.assert_called_once_with("test_module")
        mock_logger.warning.assert_called_once_with("Test warning message")
    
    @patch('brass.core.logging_config.get_logger')
    def test_log_error_convenience(self, mock_get_logger):
        """log_error convenience function works correctly."""
        mock_logger = Mock()
        mock_get_logger.return_value = mock_logger
        
        log_error("test_module", "Test error message", exc_info=True)
        
        mock_get_logger.assert_called_once_with("test_module")
        mock_logger.error.assert_called_once_with("Test error message", exc_info=True)
    
    @patch('brass.core.logging_config.get_logger')
    def test_log_debug_convenience(self, mock_get_logger):
        """log_debug convenience function works correctly."""
        mock_logger = Mock()
        mock_get_logger.return_value = mock_logger
        
        log_debug("test_module", "Test debug message")
        
        mock_get_logger.assert_called_once_with("test_module")
        mock_logger.debug.assert_called_once_with("Test debug message")


class TestLoggingIntegration:
    """Test logging system integration."""
    
    def setup_method(self):
        """Reset logger configuration before each test."""
        BrassLogger.reset_configuration()
    
    def test_logger_hierarchy(self):
        """Loggers maintain proper hierarchy."""
        # Setup logging
        BrassLogger.setup_logging(verbose=True)
        
        # Get different loggers
        parent_logger = get_logger("brass.parent")
        child_logger = get_logger("brass.parent.child")
        
        # Both should be valid Logger instances
        assert isinstance(parent_logger, logging.Logger)
        assert isinstance(child_logger, logging.Logger)
        
        # Names should be correct
        assert parent_logger.name == "brass.parent"
        assert child_logger.name == "brass.parent.child"
    
    def test_logging_levels_configuration(self):
        """Different logging levels are configured correctly."""
        # Test DEBUG level (verbose mode)
        BrassLogger.setup_logging(verbose=True)
        logger = get_logger("test_debug")
        
        # Logger should be configured
        assert logger.level <= logging.DEBUG or logger.parent.level <= logging.DEBUG
        
        # Reset and test INFO level (normal mode)
        BrassLogger.reset_configuration()
        BrassLogger.setup_logging(verbose=False)
        logger = get_logger("test_info")
        
        # Logger should be configured for INFO or inherited
        assert logger.level <= logging.INFO or logger.parent.level <= logging.INFO
    
    def test_multiple_components_logging(self):
        """Multiple components can use logging simultaneously."""
        BrassLogger.setup_logging(verbose=False)
        
        # Get loggers for different components
        scanner_logger = get_logger("code_scanner")
        cli_logger = get_logger("brass_cli")
        output_logger = get_logger("output_generator")
        
        # All should be valid and have appropriate names
        assert scanner_logger.name == "brass.code_scanner"
        assert cli_logger.name == "brass.brass_cli"
        assert output_logger.name == "brass.output_generator"
        
        # All should be different instances but share configuration
        assert scanner_logger is not cli_logger
        assert cli_logger is not output_logger
        assert scanner_logger is not output_logger