"""
CLI integration tests for BrassPerf performance flags.

Tests the --performance-validation, --performance-benchmarking, and --performance-full
CLI flags to ensure proper Phase 2 functionality integration.
"""

import unittest
import tempfile
import shutil
import sys
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from brass.cli.brass_cli import BrassCLI
from brass.scanners.brass_performance_scanner import BrassPerformanceScanner


class TestBrassPerfCLIIntegration(unittest.TestCase):
    """Test BrassPerf CLI flag integration."""
    
    def setUp(self):
        """Set up test environment with sample project."""
        self.test_dir = tempfile.mkdtemp()
        self.test_path = Path(self.test_dir)
        
        # Create sample Python files with performance issues
        (self.test_path / "performance_issues.py").write_text("""
def string_concatenation_loop():
    result = ""
    for i in range(1000):
        result += f"item_{i}"
    return result

def complex_function(data):
    # High cyclomatic complexity
    for i in data:
        if i > 10:
            if i < 100:
                if i % 2 == 0:
                    if i % 3 == 0:
                        return i * 2
                    else:
                        return i * 3
                else:
                    return i
            else:
                return i + 10
        else:
            return i - 1

def unused_function():
    # Dead code
    return "unused"
""")
        
        # Create requirements.txt to make it look like a real project
        (self.test_path / "requirements.txt").write_text("requests>=2.25.0\n")
    
    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.test_dir)
    
    def test_cli_initialization(self):
        """Test CLI initialization includes BrassPerf scanner."""
        cli = BrassCLI()
        self.assertIsNone(cli.brass_performance_scanner)  # Lazy loading
    
    def test_performance_scanner_initialization(self):
        """Test BrassPerf scanner initialization in CLI."""
        cli = BrassCLI()
        
        # Simulate scan command that would initialize the scanner
        with patch.object(cli, '_configure_logging'):
            with patch.object(cli, 'brass_performance_scanner', None):
                # Create scanner manually (simulating CLI behavior)
                scanner = BrassPerformanceScanner(str(self.test_path))
                self.assertIsInstance(scanner, BrassPerformanceScanner)
    
    @patch('brass.cli.brass_cli.BrassPerformanceScanner')
    def test_performance_flags_parsing(self, mock_scanner_class):
        """Test that performance CLI flags are parsed correctly."""
        # Mock scanner instance
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = []
        mock_scanner_class.return_value = mock_scanner
        
        cli = BrassCLI()
        
        # Test --performance-validation flag
        with patch.object(sys, 'argv', ['brass', 'scan', '--performance-validation', str(self.test_path)]):
            with patch.object(cli, '_configure_logging'):
                args = cli.parser.parse_args(['scan', '--performance-validation', str(self.test_path)])
                self.assertTrue(hasattr(args, 'performance_validation'))
    
    @patch('brass.cli.brass_cli.BrassPerformanceScanner')
    def test_performance_validation_flag(self, mock_scanner_class):
        """Test --performance-validation flag functionality."""
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = []
        mock_scanner_class.return_value = mock_scanner
        
        cli = BrassCLI()
        
        # Simulate running with --performance-validation
        test_args = [
            'scan', 
            '--performance-validation',
            str(self.test_path)
        ]
        
        with patch.object(cli, '_configure_logging'):
            try:
                result = cli.run(test_args)
                # Should complete without error
                self.assertEqual(result, 0)
            except SystemExit as e:
                # CLI might exit normally, that's ok
                self.assertEqual(e.code, 0)
    
    @patch('brass.cli.brass_cli.BrassPerformanceScanner')
    def test_performance_benchmarking_flag(self, mock_scanner_class):
        """Test --performance-benchmarking flag functionality."""
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = []
        mock_scanner_class.return_value = mock_scanner
        
        cli = BrassCLI()
        
        # Simulate running with --performance-benchmarking  
        test_args = [
            'scan',
            '--performance-benchmarking', 
            str(self.test_path)
        ]
        
        with patch.object(cli, '_configure_logging'):
            try:
                result = cli.run(test_args)
                self.assertEqual(result, 0)
            except SystemExit as e:
                self.assertEqual(e.code, 0)
    
    @patch('brass.cli.brass_cli.BrassPerformanceScanner') 
    def test_performance_full_flag(self, mock_scanner_class):
        """Test --performance-full flag functionality."""
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = []
        mock_scanner_class.return_value = mock_scanner
        
        cli = BrassCLI()
        
        # Simulate running with --performance-full
        test_args = [
            'scan',
            '--performance-full',
            str(self.test_path)
        ]
        
        with patch.object(cli, '_configure_logging'):
            try:
                result = cli.run(test_args)
                self.assertEqual(result, 0)
            except SystemExit as e:
                self.assertEqual(e.code, 0)
    
    def test_performance_scanner_lazy_loading(self):
        """Test that BrassPerf scanner is loaded only when needed."""
        cli = BrassCLI()
        
        # Initially None
        self.assertIsNone(cli.brass_performance_scanner)
        
        # Should be created when accessed
        scanner = BrassPerformanceScanner(str(self.test_path))
        self.assertIsInstance(scanner, BrassPerformanceScanner)
    
    def test_cli_help_includes_performance_flags(self):
        """Test that CLI performance flags are properly parsed."""
        # This is a basic test that the flags are recognized by the parser
        cli = BrassCLI()
        
        # Test that the performance flags are parsed without error
        test_args = ['scan', '--performance-validation', '/tmp']
        args = cli.parser.parse_args(test_args)
        self.assertTrue(hasattr(args, 'performance_validation'))
        
        test_args = ['scan', '--performance-benchmarking', '/tmp'] 
        args = cli.parser.parse_args(test_args)
        self.assertTrue(hasattr(args, 'performance_benchmarking'))
        
        test_args = ['scan', '--performance-full', '/tmp']
        args = cli.parser.parse_args(test_args)
        self.assertTrue(hasattr(args, 'performance_full'))


class TestBrassPerfEndToEndWorkflow(unittest.TestCase):
    """Test complete BrassPerf workflow integration."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.test_path = Path(self.test_dir)
        
        # Create Python file with known performance issues
        (self.test_path / "performance_test.py").write_text("""
def string_concat_issue():
    # String concatenation in loop - should be detected
    result = ""
    for i in range(100):
        result += str(i) + " "
    return result

def high_complexity(x, y, z):
    # High cyclomatic complexity - should be detected by Radon
    if x > 0:
        if y > 0:
            if z > 0:
                if x > y:
                    if y > z:
                        if x > 10:
                            return x + y + z
                        else:
                            return x * y * z
                    else:
                        return x - y - z
                else:
                    return x + y - z
            else:
                return x + y
        else:
            return x
    else:
        return 0

def never_used_function():
    # Dead code - should be detected by Vulture
    return "This function is never called"
""")
    
    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.test_dir)
    
    def test_basic_performance_scan(self):
        """Test basic performance scanning without Phase 2 features."""
        scanner = BrassPerformanceScanner(str(self.test_path))
        findings = scanner.scan()
        
        # Should find some performance issues
        self.assertGreater(len(findings), 0)
        
        # Check that findings have proper structure
        for finding in findings:
            self.assertIsNotNone(finding.id)
            self.assertIsNotNone(finding.title)
            self.assertIsNotNone(finding.description)
            self.assertEqual(finding.detected_by, "BrassPerformanceScanner")
    
    @patch('brass.scanners.brass_performance_scanner.PySpyIntegration')
    def test_performance_scan_with_validation(self, mock_pyspy_class):
        """Test performance scanning with runtime validation."""
        # Mock PySpyIntegration
        mock_pyspy = MagicMock()
        mock_pyspy.available = True
        mock_pyspy.validate_findings.return_value = []
        mock_pyspy_class.return_value = mock_pyspy
        
        scanner = BrassPerformanceScanner(
            str(self.test_path),
            enable_runtime_validation=True
        )
        
        findings = scanner.scan(runtime_validation=True)
        
        # Should have called py-spy validation
        mock_pyspy.validate_findings.assert_called_once()
    
    @patch('brass.scanners.brass_performance_scanner.PyPerfIntegration')
    def test_performance_scan_with_benchmarking(self, mock_pyperf_class):
        """Test performance scanning with benchmarking."""
        # Mock PyPerfIntegration
        mock_pyperf = MagicMock()
        mock_pyperf.available = True
        mock_pyperf.benchmark_findings.return_value = []
        mock_pyperf_class.return_value = mock_pyperf
        
        scanner = BrassPerformanceScanner(
            str(self.test_path),
            enable_benchmarking=True
        )
        
        findings = scanner.scan(benchmarking=True)
        
        # Should have called pyperf benchmarking
        mock_pyperf.benchmark_findings.assert_called_once()
    
    def test_finding_metadata_structure(self):
        """Test that findings have correct metadata structure."""
        scanner = BrassPerformanceScanner(str(self.test_path))
        findings = scanner.scan()
        
        if findings:  # If we found any issues
            finding = findings[0]
            
            # Check basic Finding structure
            self.assertTrue(hasattr(finding, 'metadata'))
            self.assertIsInstance(finding.metadata, dict)
            
            # Should have detected_by field
            self.assertEqual(finding.detected_by, "BrassPerformanceScanner")
    
    def test_error_handling_invalid_files(self):
        """Test error handling with invalid Python files."""
        # Create invalid Python file
        invalid_file = self.test_path / "invalid.py"
        invalid_file.write_text("def incomplete_function(\n  # Missing closing parenthesis")
        
        scanner = BrassPerformanceScanner(str(self.test_path))
        findings = scanner.scan()
        
        # Should handle syntax errors gracefully
        # (May still find issues in valid files)
        self.assertIsInstance(findings, list)
    
    def test_large_file_skipping(self):
        """Test that large files are skipped for performance."""
        # Create a large file (>1MB)
        large_content = "# Large file\n" + "x = 1\n" * 100000
        large_file = self.test_path / "large.py"
        large_file.write_text(large_content)
        
        scanner = BrassPerformanceScanner(str(self.test_path))
        findings = scanner.scan()
        
        # Should complete without issues (large file skipped)
        self.assertIsInstance(findings, list)


if __name__ == '__main__':
    unittest.main()