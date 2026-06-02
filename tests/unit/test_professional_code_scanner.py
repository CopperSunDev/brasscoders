"""
Unit tests for ProfessionalCodeScanner component.

Tests the ProfessionalCodeScanner class and its tool integrations
with proper mocking to avoid dependency on external tools.
"""

import os
import tempfile
import unittest
from unittest.mock import Mock, patch, MagicMock
import json

# Add src to path for imports
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from brass.scanners.professional_code_scanner import (
    ProfessionalCodeScanner, 
    BanditIntegration, 
    PylintIntegration,
    LegacyPatternScanner,
    ToolResult
)
from brass.models.finding import Finding, FindingType, Severity


class TestProfessionalCodeScanner(unittest.TestCase):
    """Test the main ProfessionalCodeScanner class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.scanner = ProfessionalCodeScanner(self.temp_dir)
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_initialization(self):
        """Test scanner initialization."""
        self.assertEqual(str(self.scanner.project_path), self.temp_dir)
        self.assertIsInstance(self.scanner.bandit, BanditIntegration)
        self.assertIsInstance(self.scanner.pylint, PylintIntegration)
        self.assertIsInstance(self.scanner.legacy_scanner, LegacyPatternScanner)
        # _tool_status is now populated at __init__ with bandit / pylint config
        # discovery (e.g. ``'No .bandit config found - using fallback defaults'``).
        # We assert it's a dict but not the specific contents — BrassCoders's config
        # discovery is filesystem-dependent and would make tests brittle.
        self.assertIsInstance(self.scanner._tool_status, dict)
    
    @unittest.skip(
        "scan() was rewritten to use ProcessPoolExecutor with worker functions; "
        "patching _analyze_single_file no longer intercepts the call path. "
        "End-to-end coverage of this behavior lives in test_complete_workflow.py."
    )
    def test_scan_with_file_paths(self):
        pass

    @unittest.skip(
        "Parallel scanner now silently skips unreadable files (logs a warning) "
        "rather than emitting an ANALYSIS_ERROR finding. The trade-off was "
        "deliberate — error findings on transient I/O issues created noise on "
        "real projects. test_parse_error_resilience covers the actual contract."
    )
    def test_scan_with_missing_file(self):
        pass
    
    @unittest.skip(
        "_should_analyze_file was inlined into discovery in the file_classifier "
        "refactor; equivalent coverage lives in test_file_classifier and the "
        "discovery branch of test_professional_code_scanner_parallel."
    )
    def test_should_analyze_file(self):
        pass

    def test_get_tool_status(self):
        """Test tool status reporting."""
        # _tool_status is auto-populated at init now (config-discovery
        # results). Snapshot it so we can compare deltas. The contract
        # we still hold is: returns a copy, not a reference.
        baseline = self.scanner.get_tool_status()
        self.assertIsInstance(baseline, dict)

        self.scanner._tool_status['bandit'] = 'Tool not found'
        status = self.scanner.get_tool_status()
        self.assertEqual(status.get('bandit'), 'Tool not found')

        # Returns a copy: mutating the returned dict doesn't affect internal state
        status['new_key'] = 'value'
        self.assertNotIn('new_key', self.scanner._tool_status)


class TestBanditIntegration(unittest.TestCase):
    """Test BanditIntegration class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.bandit = BanditIntegration()
    
    @patch('brass.scanners.professional_code_scanner.shutil.which')
    def test_init_with_bandit_available(self, mock_which):
        """Test initialization when bandit is available."""
        mock_which.return_value = '/usr/bin/bandit'
        
        bandit = BanditIntegration()
        
        self.assertEqual(bandit.tool_name, "bandit")
        self.assertEqual(bandit._bandit_path, '/usr/bin/bandit')
        mock_which.assert_called_with('bandit')
    
    @patch('brass.scanners.professional_code_scanner.shutil.which')
    def test_init_with_bandit_unavailable(self, mock_which):
        """Test initialization when bandit is not available."""
        mock_which.return_value = None
        
        bandit = BanditIntegration()
        
        self.assertEqual(bandit.tool_name, "bandit")
        self.assertIsNone(bandit._bandit_path)
    
    def test_validate_file_path_valid(self):
        """Test file path validation with valid paths."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("print('test')")
            temp_file = f.name
        
        try:
            self.assertTrue(self.bandit._validate_file_path(temp_file))
        finally:
            os.unlink(temp_file)
    
    def test_validate_file_path_invalid(self):
        """Test file path validation with invalid paths."""
        # Non-existent file
        self.assertFalse(self.bandit._validate_file_path("/nonexistent/file.py"))
        
        # None path
        self.assertFalse(self.bandit._validate_file_path(None))
        
        # Empty string
        self.assertFalse(self.bandit._validate_file_path(""))
        
        # Path traversal attempt
        self.assertFalse(self.bandit._validate_file_path("../../../etc/passwd"))
    
    @patch('brass.scanners.professional_code_scanner.subprocess.run')
    def test_analyze_file_success(self, mock_run):
        """Test successful bandit analysis."""
        # Setup
        self.bandit._bandit_path = '/usr/bin/bandit'
        
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = json.dumps({
            'results': [{
                'test_id': 'B101',
                'issue_severity': 'HIGH',
                'line_number': 5,
                'issue_text': 'Use of assert detected',
                'issue_confidence': 'HIGH',
                'code': 'assert False'
            }]
        })
        mock_run.return_value = mock_result
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("assert False")
            temp_file = f.name
        
        try:
            # Execute
            result = self.bandit.analyze_file(temp_file)
            
            # Verify
            self.assertTrue(result.success)
            self.assertEqual(len(result.findings), 1)
            finding = result.findings[0]
            self.assertEqual(finding.type, FindingType.SECURITY)
            self.assertEqual(finding.severity, Severity.CRITICAL)  # HIGH maps to CRITICAL
            self.assertEqual(finding.line_number, 5)
            self.assertEqual(finding.detected_by, "bandit")
        finally:
            os.unlink(temp_file)
    
    def test_analyze_file_tool_not_found(self):
        """Test analysis when bandit tool is not found."""
        self.bandit._bandit_path = None
        
        # Create a valid temporary file for testing
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("print('test')")
            temp_file = f.name
        
        try:
            result = self.bandit.analyze_file(temp_file)
            
            self.assertFalse(result.success)
            self.assertIn("Bandit tool not found", result.error_message)
            self.assertEqual(result.findings, [])
        finally:
            os.unlink(temp_file)
    
    def test_analyze_file_invalid_path(self):
        """Test analysis with invalid file path."""
        self.bandit._bandit_path = '/usr/bin/bandit'
        
        result = self.bandit.analyze_file("/nonexistent/file.py")
        
        self.assertFalse(result.success)
        self.assertIn("Invalid file path", result.error_message)
        self.assertEqual(result.findings, [])
    
    @patch('brass.scanners.professional_code_scanner.subprocess.run')
    def test_analyze_file_timeout(self, mock_run):
        """Test analysis timeout handling."""
        from subprocess import TimeoutExpired
        
        self.bandit._bandit_path = '/usr/bin/bandit'
        mock_run.side_effect = TimeoutExpired('bandit', 30)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py') as f:
            result = self.bandit.analyze_file(f.name)
        
        self.assertFalse(result.success)
        self.assertIn("timed out after 30s", result.error_message)
    
    def test_map_bandit_severity(self):
        """Test bandit severity mapping."""
        self.assertEqual(self.bandit._map_bandit_severity('HIGH'), Severity.CRITICAL)
        self.assertEqual(self.bandit._map_bandit_severity('MEDIUM'), Severity.HIGH)
        self.assertEqual(self.bandit._map_bandit_severity('LOW'), Severity.MEDIUM)
        self.assertEqual(self.bandit._map_bandit_severity('UNKNOWN'), Severity.LOW)


class TestPylintIntegration(unittest.TestCase):
    """Test PylintIntegration class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.pylint = PylintIntegration()
    
    @patch('brass.scanners.professional_code_scanner.shutil.which')
    def test_init_with_pylint_available(self, mock_which):
        """Test initialization when pylint is available."""
        mock_which.return_value = '/usr/bin/pylint'
        
        pylint = PylintIntegration()
        
        self.assertEqual(pylint.tool_name, "pylint")
        self.assertEqual(pylint._pylint_path, '/usr/bin/pylint')
    
    @patch('brass.scanners.professional_code_scanner.subprocess.run')
    def test_analyze_file_success(self, mock_run):
        """Test successful pylint analysis."""
        # Setup
        self.pylint._pylint_path = '/usr/bin/pylint'
        
        mock_result = Mock()
        mock_result.returncode = 2  # Pylint returns non-zero for issues
        mock_result.stdout = json.dumps([{
            'message-id': 'C0103',
            'symbol': 'invalid-name',
            'message': 'Variable name "x" doesn\'t conform to snake_case naming style',
            'type': 'convention',
            'line': 1,
            'column': 0
        }])
        mock_run.return_value = mock_result
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("x = 1")
            temp_file = f.name
        
        try:
            # Execute
            result = self.pylint.analyze_file(temp_file)
            
            # Verify
            self.assertTrue(result.success)
            self.assertEqual(len(result.findings), 1)
            finding = result.findings[0]
            self.assertEqual(finding.type, FindingType.CODE_QUALITY)
            self.assertEqual(finding.severity, Severity.LOW)  # convention maps to LOW
            self.assertEqual(finding.line_number, 1)
            self.assertEqual(finding.detected_by, "pylint")
        finally:
            os.unlink(temp_file)
    
    def test_map_pylint_severity(self):
        """Test pylint severity mapping."""
        self.assertEqual(self.pylint._map_pylint_severity('error'), Severity.HIGH)
        self.assertEqual(self.pylint._map_pylint_severity('warning'), Severity.MEDIUM)
        self.assertEqual(self.pylint._map_pylint_severity('refactor'), Severity.LOW)
        self.assertEqual(self.pylint._map_pylint_severity('convention'), Severity.LOW)
        self.assertEqual(self.pylint._map_pylint_severity('info'), Severity.INFO)
        self.assertEqual(self.pylint._map_pylint_severity('unknown'), Severity.LOW)


class TestLegacyPatternScanner(unittest.TestCase):
    """Test LegacyPatternScanner class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.scanner = LegacyPatternScanner()
    
    def test_analyze_file_todo_patterns(self):
        """Test detection of TODO patterns."""
        file_content = """
# TODO: implement this function
def example():
    # FIXME: this is broken
    pass
    # HACK: temporary solution
    return None
"""
        
        findings = self.scanner.analyze_file("test.py", file_content)
        
        self.assertEqual(len(findings), 3)
        
        # Check TODO finding
        todo_finding = next(f for f in findings if 'TODO' in f.title)
        self.assertEqual(todo_finding.type, FindingType.TODO)
        self.assertEqual(todo_finding.severity, Severity.LOW)
        self.assertEqual(todo_finding.line_number, 2)
        
        # Check FIXME finding
        fixme_finding = next(f for f in findings if 'FIXME' in f.title)
        self.assertEqual(fixme_finding.severity, Severity.HIGH)
        
        # Check HACK finding
        hack_finding = next(f for f in findings if 'HACK' in f.title)
        self.assertEqual(hack_finding.severity, Severity.HIGH)
    
    def test_analyze_file_no_patterns(self):
        """Test analysis with no TODO patterns."""
        file_content = """
def clean_function():
    return "No issues here"
"""
        
        findings = self.scanner.analyze_file("test.py", file_content)
        
        self.assertEqual(len(findings), 0)
    
    def test_analyze_file_patterns_without_comments(self):
        """Test that patterns in strings are not detected."""
        file_content = """
text = "This TODO should not be detected"
message = 'FIXME in string should be ignored'
"""
        
        findings = self.scanner.analyze_file("test.py", file_content)
        
        self.assertEqual(len(findings), 0)


class TestToolResult(unittest.TestCase):
    """Test ToolResult dataclass."""
    
    def test_tool_result_creation(self):
        """Test ToolResult creation and attributes."""
        findings = [
            Finding(
                id="test", type=FindingType.SECURITY, severity=Severity.HIGH,
                file_path="test.py", title="Test", description="Test finding",
                detected_by="test"
            )
        ]
        
        result = ToolResult(
            tool="bandit",
            findings=findings,
            success=True,
            error_message=None
        )
        
        self.assertEqual(result.tool, "bandit")
        self.assertEqual(len(result.findings), 1)
        self.assertTrue(result.success)
        self.assertIsNone(result.error_message)
    
    def test_tool_result_failure(self):
        """Test ToolResult for failure case."""
        result = ToolResult(
            tool="pylint",
            findings=[],
            success=False,
            error_message="Tool not found"
        )
        
        self.assertEqual(result.tool, "pylint")
        self.assertEqual(len(result.findings), 0)
        self.assertFalse(result.success)
        self.assertEqual(result.error_message, "Tool not found")


if __name__ == '__main__':
    unittest.main()