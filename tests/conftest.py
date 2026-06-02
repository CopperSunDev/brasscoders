"""
Pytest configuration and fixtures for New BrassCoders System v2.0.
Provides reusable test fixtures following separation of concerns.
"""

import pytest
import tempfile
import shutil
import sys
from pathlib import Path

# Add src to path for all tests
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from brass.scanners.professional_code_scanner import ProfessionalCodeScanner
from brass.scanners.brass2_privacy_scanner import Brass2PrivacyScanner
from brass.scanners.content_moderation_scanner import ContentModerationScanner
from brass.models.finding import Finding, FindingType, Severity


@pytest.fixture
def temp_project():
    """Create a temporary project directory for testing."""
    temp_dir = Path(tempfile.mkdtemp())
    yield temp_dir
    if temp_dir.exists():
        shutil.rmtree(temp_dir)


@pytest.fixture
def code_scanner(temp_project):
    """Create a ProfessionalCodeScanner instance for testing."""
    return ProfessionalCodeScanner(str(temp_project))


@pytest.fixture
def brass2_privacy_scanner(temp_project):
    """Create a Brass2PrivacyScanner instance for testing."""
    return Brass2PrivacyScanner(str(temp_project))

@pytest.fixture
def content_moderation_scanner(temp_project):
    """Create a ContentModerationScanner instance for testing."""
    return ContentModerationScanner(str(temp_project))


@pytest.fixture
def sample_python_file(temp_project):
    """Create a sample Python file for testing."""
    python_file = temp_project / "sample.py"
    python_file.write_text('print("Hello, world!")')
    return python_file


@pytest.fixture
def complex_python_file(temp_project):
    """Create a complex Python file for testing complexity detection."""
    complex_code = '''
def complex_function(x, y, z):
    if x > 0:
        if y > 0:
            for i in range(10):
                if i % 2 == 0:
                    while z > 0:
                        try:
                            if z > 5:
                                return True
                            elif z > 3:
                                return False
                            else:
                                z -= 1
                        except:
                            pass
                else:
                    continue
        else:
            return None
    return False
'''
    complex_file = temp_project / "complex.py"
    complex_file.write_text(complex_code)
    return complex_file


@pytest.fixture
def security_issues_file(temp_project):
    """Create a Python file with security issues for testing."""
    security_code = '''
def dangerous_function(user_input):
    # Dangerous eval usage
    result = eval(user_input)
    
    # Dangerous exec usage
    exec(user_input)
    
    # Hardcoded API key
    api_key = "sk-1234567890abcdef1234567890abcdef"
    
    return result
'''
    security_file = temp_project / "security_issues.py"
    security_file.write_text(security_code)
    return security_file


@pytest.fixture
def todo_comments_file(temp_project):
    """Create a Python file with TODO comments for testing."""
    todo_code = '''
# TODO: Implement this function
def todo_function():
    pass

# FIXME: This is broken
def broken_function():
    # HACK: Temporary workaround
    return None

# XXX: This needs review
def review_function():
    pass
'''
    todo_file = temp_project / "todos.py"
    todo_file.write_text(todo_code)
    return todo_file


@pytest.fixture
def privacy_issues_file(temp_project):
    """Create a file with privacy issues for testing."""
    privacy_code = '''
# This file contains various PII for testing
user_email = "john.doe@example.com"
phone_number = "+1-555-123-4567"
ssn = "123-45-6789"
credit_card = "4532-1234-5678-9012"

def process_user_data():
    # Process sensitive data
    return {
        "email": user_email,
        "phone": phone_number,
        "ssn": ssn
    }
'''
    privacy_file = temp_project / "privacy_issues.py"
    privacy_file.write_text(privacy_code)
    return privacy_file


@pytest.fixture
def sample_finding():
    """Create a sample Finding for testing."""
    return Finding(
        id="test_finding_001",
        type=FindingType.SECURITY,
        severity=Severity.HIGH,
        file_path="test.py",
        line_number=42,
        title="Test Security Finding",
        description="This is a test security finding for unit tests",
        confidence=0.95,
        impact_score=0.85,
        detected_by="TestScanner"
    )


@pytest.fixture
def sample_findings():
    """Create sample findings for testing (compatible with test expectations)."""
    return [
        Finding(
            id="test_finding_001",
            type=FindingType.SECURITY,
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=42,
            title="Test Security Finding",
            description="This is a test security finding for unit tests",
            confidence=0.95,
            impact_score=0.85,
            detected_by="TestScanner"
        )
    ]


@pytest.fixture
def multiple_findings():
    """Create multiple findings for testing ranking and aggregation."""
    return [
        Finding(
            id="critical_security",
            type=FindingType.SECURITY,
            severity=Severity.CRITICAL,
            file_path="critical.py",
            line_number=1,
            title="Critical Security Issue",
            description="Very dangerous security vulnerability",
            confidence=0.99,
            impact_score=0.95,
            detected_by="SecurityScanner"
        ),
        Finding(
            id="medium_quality",
            type=FindingType.CODE_QUALITY,
            severity=Severity.MEDIUM,
            file_path="quality.py",
            line_number=10,
            title="Code Quality Issue",
            description="Moderate code quality concern",
            confidence=0.80,
            impact_score=0.60,
            detected_by="QualityScanner"
        ),
        Finding(
            id="low_todo",
            type=FindingType.TODO,
            severity=Severity.LOW,
            file_path="todo.py",
            line_number=5,
            title="TODO Comment",
            description="Simple TODO comment",
            confidence=1.0,
            impact_score=0.30,
            detected_by="TodoScanner"
        )
    ]