"""
Test fixtures package for New BrassCoders System v2.0.

Provides comprehensive, stable test data for consistent testing
across unit, integration, and end-to-end test suites.
"""

from .fixture_manager import (
    FixtureManager,
    FixtureType,
    TestProjectTemplate,
    create_temp_project,
    get_all_expected_findings,
    get_fixture_stats
)

from .security_test_files import SecurityTestFiles
from .privacy_test_files import PrivacyTestFiles  
from .code_quality_test_files import CodeQualityTestFiles

__all__ = [
    # Main fixture manager
    'FixtureManager',
    'FixtureType',
    'TestProjectTemplate',
    
    # Convenience functions
    'create_temp_project',
    'get_all_expected_findings',
    'get_fixture_stats',
    
    # Specific fixture classes
    'SecurityTestFiles',
    'PrivacyTestFiles',
    'CodeQualityTestFiles'
]

# Package metadata
__version__ = '2.0.0'
__description__ = 'Comprehensive test fixtures for New BrassCoders System v2.0'