"""
Unit tests for ProfessionalCodeScanner and its components.

Comprehensive test suite covering:
- Intelligent filtering logic
- Severity adjustment algorithms
- Tool integration error handling
- Input validation edge cases
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import tempfile
import os

from src.brass.scanners.professional_code_scanner import (
    ProfessionalCodeScanner,
    BanditIntegration,
    PylintIntegration,
    LegacyPatternScanner,
    ToolResult
)
from src.brass.models.finding import Finding, FindingType, Severity


class TestProfessionalCodeScanner(unittest.TestCase):
    """Test suite for ProfessionalCodeScanner main class."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.scanner = ProfessionalCodeScanner(self.temp_dir)

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_initialization_success(self):
        """Test successful scanner initialization."""
        self.assertIsNotNone(self.scanner.project_path)
        self.assertIsNotNone(self.scanner.file_classifier)
        self.assertIsNotNone(self.scanner.bandit)
        self.assertIsNotNone(self.scanner.pylint)
        self.assertIsNotNone(self.scanner.legacy_scanner)

    def test_get_tool_status_contains_config_validation(self):
        """Test tool status contains configuration validation results."""
        status = self.scanner.get_tool_status()
        self.assertIsInstance(status, dict)
        # Should contain configuration status for bandit and pylint
        self.assertIn('bandit_config', status)
        self.assertIn('pylintrc_config', status)


class TestIntelligentFiltering(unittest.TestCase):
    """Test suite for intelligent filtering logic."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.scanner = ProfessionalCodeScanner(self.temp_dir)

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_should_filter_formatting_noise(self):
        """Test filtering of formatting/style noise patterns."""
        noise_findings = [
            Finding(
                id="test1", type=FindingType.CODE_QUALITY, severity=Severity.LOW,
                file_path="test.py", line_number=1, title="trailing-whitespace",
                description="Line has trailing whitespace", detected_by="test"
            ),
            Finding(
                id="test2", type=FindingType.CODE_QUALITY, severity=Severity.LOW,
                file_path="test.py", line_number=2, title="line-too-long",
                description="Line exceeds maximum length", detected_by="test"
            ),
            Finding(
                id="test3", type=FindingType.CODE_QUALITY, severity=Severity.LOW,
                file_path="test.py", line_number=3, title="missing-final-newline",
                description="Missing final newline", detected_by="test"
            ),
            Finding(
                id="test4", type=FindingType.CODE_QUALITY, severity=Severity.LOW,
                file_path="test.py", line_number=4, title="wrong-import-order",
                description="Imports not ordered correctly", detected_by="test"
            )
        ]

        for finding in noise_findings:
            with self.subTest(finding=finding.title):
                self.assertTrue(
                    self.scanner._should_filter_finding(finding),
                    f"Should filter noise pattern: {finding.title}"
                )

    def test_should_not_filter_genuine_issues(self):
        """Test that genuine code issues are not filtered."""
        genuine_findings = [
            Finding(
                id="test1", type=FindingType.SECURITY, severity=Severity.HIGH,
                file_path="test.py", line_number=1, title="SQL Injection Risk",
                description="Potential SQL injection vulnerability", detected_by="bandit"
            ),
            Finding(
                id="test2", type=FindingType.CODE_QUALITY, severity=Severity.MEDIUM,
                file_path="test.py", line_number=2, title="unused-variable",
                description="Variable defined but never used", detected_by="pylint"
            ),
            Finding(
                id="test3", type=FindingType.TODO, severity=Severity.LOW,
                file_path="test.py", line_number=3, title="TODO Comment",
                description="TODO: implement feature", detected_by="legacy"
            )
        ]

        for finding in genuine_findings:
            with self.subTest(finding=finding.title):
                self.assertFalse(
                    self.scanner._should_filter_finding(finding),
                    f"Should not filter genuine issue: {finding.title}"
                )

    def test_should_filter_test_specific_noise(self):
        """Test filtering of test-specific noise patterns."""
        test_noise_findings = [
            Finding(
                id="test1", type=FindingType.SECURITY, severity=Severity.MEDIUM,
                file_path="tests/test_auth.py", line_number=1, title="assert_used",
                description="Use of assert detected", detected_by="bandit"
            ),
            Finding(
                id="test2", type=FindingType.SECURITY, severity=Severity.MEDIUM,
                file_path="tests/fixtures/data.py", line_number=2, title="hardcoded_password",
                description="Hardcoded password in test fixture", detected_by="bandit"
            ),
            Finding(
                id="test3", type=FindingType.SECURITY, severity=Severity.LOW,
                file_path="test_utils.py", line_number=3, title="hardcoded_tmp_directory",
                description="Hardcoded temp directory", detected_by="bandit"
            )
        ]

        for finding in test_noise_findings:
            with self.subTest(finding=finding.title):
                self.assertTrue(
                    self.scanner._should_filter_finding(finding),
                    f"Should filter test noise: {finding.title}"
                )

    def test_should_not_filter_production_security_issues(self):
        """Test that security issues in production code are not filtered."""
        production_finding = Finding(
            id="test1", type=FindingType.SECURITY, severity=Severity.HIGH,
            file_path="src/auth/login.py", line_number=1, title="hardcoded_password",
            description="Hardcoded password in production code", detected_by="bandit"
        )

        self.assertFalse(
            self.scanner._should_filter_finding(production_finding),
            "Should not filter security issues in production code"
        )


class TestSeverityAdjustment(unittest.TestCase):
    """Test suite for intelligent severity adjustment."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.scanner = ProfessionalCodeScanner(self.temp_dir)

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch('src.brass.core.file_classifier.FileClassifier.classify_file')
    def test_severity_adjustment_for_test_files(self, mock_classify):
        """Test severity downgrading for test files."""
        # Mock file context for test file
        mock_context = Mock()
        mock_context.is_test_related.return_value = True
        mock_classify.return_value = mock_context

        # Test critical -> high downgrade
        critical_finding = Finding(
            id="test1", type=FindingType.SECURITY, severity=Severity.CRITICAL,
            file_path="tests/test_auth.py", line_number=1, title="Security Issue",
            description="Critical security issue in test", detected_by="bandit"
        )

        adjusted_severity = self.scanner._adjust_severity_with_intelligence(
            critical_finding, mock_context
        )
        self.assertEqual(adjusted_severity, Severity.HIGH)

        # Test high -> medium downgrade
        high_finding = Finding(
            id="test2", type=FindingType.SECURITY, severity=Severity.HIGH,
            file_path="tests/test_auth.py", line_number=2, title="Security Issue",
            description="High security issue in test", detected_by="bandit"
        )

        adjusted_severity = self.scanner._adjust_severity_with_intelligence(
            high_finding, mock_context
        )
        self.assertEqual(adjusted_severity, Severity.MEDIUM)

    @patch('src.brass.core.file_classifier.FileClassifier.classify_file')
    def test_severity_adjustment_for_production_files(self, mock_classify):
        """Test severity preserved for production files."""
        # Mock file context for production file
        mock_context = Mock()
        mock_context.is_test_related.return_value = False
        mock_classify.return_value = mock_context

        critical_finding = Finding(
            id="test1", type=FindingType.SECURITY, severity=Severity.CRITICAL,
            file_path="src/auth/login.py", line_number=1, title="Security Issue",
            description="Critical security issue in production", detected_by="bandit"
        )

        adjusted_severity = self.scanner._adjust_severity_with_intelligence(
            critical_finding, mock_context
        )
        self.assertEqual(adjusted_severity, Severity.CRITICAL)

    def test_md5_usage_severity_adjustment(self):
        """Test severity adjustment for MD5 usage in ID generation."""
        mock_context = Mock()
        mock_context.is_test_related.return_value = False

        md5_finding = Finding(
            id="test1", type=FindingType.SECURITY, severity=Severity.HIGH,
            file_path="src/utils/id_generator.py", line_number=1, title="MD5 Usage",
            description="MD5 usage detected for ID generation", detected_by="bandit"
        )

        adjusted_severity = self.scanner._adjust_severity_with_intelligence(
            md5_finding, mock_context
        )
        self.assertEqual(adjusted_severity, Severity.LOW)

    def test_style_issue_severity_downgrade(self):
        """Test severity downgrade for style-related code quality issues."""
        mock_context = Mock()
        mock_context.is_test_related.return_value = False

        style_finding = Finding(
            id="test1", type=FindingType.CODE_QUALITY, severity=Severity.MEDIUM,
            file_path="src/module.py", line_number=1, title="import order issue",
            description="Import order should be standardized", detected_by="pylint"
        )

        adjusted_severity = self.scanner._adjust_severity_with_intelligence(
            style_finding, mock_context
        )
        self.assertEqual(adjusted_severity, Severity.LOW)


class TestBanditIntegration(unittest.TestCase):
    """Test suite for Bandit tool integration."""

    def setUp(self):
        """Set up test fixtures."""
        self.bandit = BanditIntegration()

    def test_validate_file_path_valid_file(self):
        """Test file path validation with valid file."""
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("print('hello')")
            temp_file = f.name

        try:
            result = self.bandit._validate_file_path(temp_file)
            self.assertTrue(result)
        finally:
            os.unlink(temp_file)

    def test_validate_file_path_invalid_inputs(self):
        """Test file path validation with invalid inputs."""
        invalid_paths = [
            None,
            "",
            123,  # Non-string
            "../../../etc/passwd",  # Path traversal
            "/nonexistent/file.py"  # Non-existent file
        ]

        for invalid_path in invalid_paths:
            with self.subTest(path=invalid_path):
                result = self.bandit._validate_file_path(invalid_path)
                self.assertFalse(result)

    def test_map_bandit_severity(self):
        """Test Bandit severity mapping."""
        severity_mappings = {
            'HIGH': Severity.CRITICAL,
            'MEDIUM': Severity.HIGH,
            'LOW': Severity.MEDIUM,
            'UNKNOWN': Severity.LOW
        }

        for bandit_severity, expected_severity in severity_mappings.items():
            with self.subTest(severity=bandit_severity):
                result = self.bandit._map_bandit_severity(bandit_severity)
                self.assertEqual(result, expected_severity)

    @patch('subprocess.run')
    @patch('shutil.which')
    def test_analyze_file_tool_not_found(self, mock_which, mock_run):
        """Test behavior when Bandit tool is not found."""
        mock_which.return_value = None
        
        # Re-initialize to trigger tool validation
        bandit = BanditIntegration()
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("print('hello')")
            temp_file = f.name

        try:
            result = bandit.analyze_file(temp_file)
            self.assertFalse(result.success)
            self.assertIn("not found", result.error_message)
            self.assertEqual(len(result.findings), 0)
        finally:
            os.unlink(temp_file)


class TestPylintIntegration(unittest.TestCase):
    """Test suite for Pylint tool integration."""

    def setUp(self):
        """Set up test fixtures."""
        self.pylint = PylintIntegration()

    def test_map_pylint_severity(self):
        """Test Pylint severity mapping."""
        severity_mappings = {
            'error': Severity.HIGH,
            'warning': Severity.MEDIUM,
            'refactor': Severity.LOW,
            'convention': Severity.LOW,
            'info': Severity.INFO,
            'unknown': Severity.LOW
        }

        for pylint_type, expected_severity in severity_mappings.items():
            with self.subTest(type=pylint_type):
                result = self.pylint._map_pylint_severity(pylint_type)
                self.assertEqual(result, expected_severity)

    def test_parse_pylint_output_filters_info(self):
        """Test that info-level messages are filtered out."""
        pylint_data = [
            {
                'type': 'info',
                'message-id': 'I0001',
                'line': 1,
                'symbol': 'info-message',
                'message': 'Informational message'
            },
            {
                'type': 'warning',
                'message-id': 'W0001', 
                'line': 2,
                'symbol': 'warning-message',
                'message': 'Warning message'
            }
        ]

        findings = self.pylint._parse_pylint_output(pylint_data, "test.py")
        
        # Should only have the warning, info should be filtered
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.MEDIUM)
        self.assertIn('warning-message', findings[0].title)


class TestLegacyPatternScanner(unittest.TestCase):
    """Test suite for legacy pattern scanning."""

    def setUp(self):
        """Set up test fixtures."""
        self.scanner = LegacyPatternScanner()

    def test_analyze_file_detects_todo_patterns(self):
        """Test detection of TODO/FIXME patterns."""
        file_content = """
# TODO: implement this feature
def incomplete_function():
    pass  # FIXME: this is broken
    
# HACK: temporary workaround
def workaround():
    # XXX: needs review
    return None
    
# BUG: this doesn't work
def buggy_function():
    pass
"""

        findings = self.scanner.analyze_file("test.py", file_content)
        
        # Should detect all 5 patterns
        self.assertEqual(len(findings), 5)
        
        expected_patterns = ['TODO', 'FIXME', 'HACK', 'XXX', 'BUG']
        found_patterns = [finding.title.split()[0] for finding in findings]
        
        for pattern in expected_patterns:
            self.assertIn(pattern, found_patterns)

    def test_analyze_file_ignores_non_comments(self):
        """Test that patterns in non-comment lines are ignored."""
        file_content = """
variable_name = "TODO: not a comment"
print("FIXME this is in a string")
def function_with_todo_in_name():
    pass
"""

        findings = self.scanner.analyze_file("test.py", file_content)
        
        # Should not detect any patterns since they're not in comments
        self.assertEqual(len(findings), 0)


class TestToolResult(unittest.TestCase):
    """Test suite for ToolResult dataclass."""

    def test_tool_result_creation(self):
        """Test ToolResult creation and attributes."""
        findings = [
            Finding(
                id="test1", type=FindingType.SECURITY, severity=Severity.HIGH,
                file_path="test.py", line_number=1, title="Test Finding",
                description="Test description", detected_by="test"
            )
        ]
        
        result = ToolResult(
            tool="test_tool",
            findings=findings,
            success=True,
            error_message=None
        )
        
        self.assertEqual(result.tool, "test_tool")
        self.assertEqual(len(result.findings), 1)
        self.assertTrue(result.success)
        self.assertIsNone(result.error_message)

    def test_tool_result_with_error(self):
        """Test ToolResult creation with error."""
        result = ToolResult(
            tool="test_tool",
            findings=[],
            success=False,
            error_message="Tool execution failed"
        )
        
        self.assertEqual(result.tool, "test_tool")
        self.assertEqual(len(result.findings), 0)
        self.assertFalse(result.success)
        self.assertEqual(result.error_message, "Tool execution failed")


if __name__ == '__main__':
    unittest.main()