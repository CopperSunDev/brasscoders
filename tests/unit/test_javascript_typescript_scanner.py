"""
Comprehensive unit tests for JavaScriptTypeScriptScanner component.

Tests the JavaScript/TypeScript scanner and its integration with Babel parser
with proper mocking to avoid dependency on external tools.
"""

import os
import tempfile
import unittest
import json
import subprocess
from unittest.mock import Mock, patch, MagicMock, call
from pathlib import Path

# Add src to path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from brass.scanners.javascript_typescript_scanner import JavaScriptTypeScriptScanner
from brass.models.finding import Finding, FindingType, Severity


class TestJavaScriptTypeScriptScanner(unittest.TestCase):
    """Test the main JavaScriptTypeScriptScanner class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.temp_path = Path(self.temp_dir)
        
        # Create mock Babel script
        self.babel_script = self.temp_path / "babel_parser.js"
        self.babel_script.write_text("// Mock Babel script")
        
        # Create some test JS/TS files
        (self.temp_path / "test.js").write_text("console.log('test');")
        (self.temp_path / "test.ts").write_text("const x: string = 'test';")
        (self.temp_path / "test.jsx").write_text("<div>Test</div>;")
        (self.temp_path / "test.tsx").write_text("const Test = () => <div>Test</div>;")
        
        # Create directories to exclude
        (self.temp_path / "node_modules").mkdir()
        (self.temp_path / "build").mkdir()
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @patch('brass.scanners.javascript_typescript_scanner.subprocess.run')
    def test_initialization_valid_path(self, mock_run):
        """Test scanner initialization with valid project path."""
        # Mock Node.js check
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "v18.0.0"
        
        with patch.object(JavaScriptTypeScriptScanner, '_locate_babel_script', return_value=self.babel_script):
            scanner = JavaScriptTypeScriptScanner(self.temp_dir)
            
        self.assertEqual(scanner.project_path, Path(self.temp_dir).resolve())
        self.assertIsInstance(scanner.js_ts_extensions, set)
        self.assertIn('.js', scanner.js_ts_extensions)
        self.assertIn('.ts', scanner.js_ts_extensions)
    
    def test_initialization_invalid_path(self):
        """Test scanner handles invalid project paths gracefully."""
        with self.assertRaises(FileNotFoundError):
            JavaScriptTypeScriptScanner("/nonexistent/path")
    
    def test_initialization_empty_path(self):
        """Test scanner handles empty project path."""
        with self.assertRaises(ValueError):
            JavaScriptTypeScriptScanner("")
    
    @patch('brass.scanners.javascript_typescript_scanner.subprocess.run')
    def test_dependency_validation_node_available(self, mock_run):
        """Test behavior when Node.js is available."""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "v18.0.0"
        
        with patch.object(JavaScriptTypeScriptScanner, '_locate_babel_script', return_value=self.babel_script):
            scanner = JavaScriptTypeScriptScanner(self.temp_dir)
            
        # Should not raise any exception
        self.assertIsNotNone(scanner)
    
    @patch('brass.scanners.javascript_typescript_scanner.subprocess.run')
    def test_dependency_validation_node_missing(self, mock_run):
        """Test graceful degradation when Node.js unavailable."""
        mock_run.side_effect = FileNotFoundError("Node.js not found")
        
        with patch.object(JavaScriptTypeScriptScanner, '_locate_babel_script', return_value=self.babel_script):
            with self.assertRaises(RuntimeError) as context:
                JavaScriptTypeScriptScanner(self.temp_dir)
            
            self.assertIn("Node.js is not installed", str(context.exception))
    
    @patch('brass.scanners.javascript_typescript_scanner.subprocess.run')
    def test_file_discovery_basic(self, mock_run):
        """Test JS/TS file discovery in standard project."""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "v18.0.0"
        
        with patch.object(JavaScriptTypeScriptScanner, '_locate_babel_script', return_value=self.babel_script):
            scanner = JavaScriptTypeScriptScanner(self.temp_dir)
            files = scanner._discover_js_ts_files()
        
        # Should find our test files
        file_names = [Path(f).name for f in files]
        self.assertIn("test.js", file_names)
        self.assertIn("test.ts", file_names)
        self.assertIn("test.jsx", file_names)
        self.assertIn("test.tsx", file_names)
    
    @patch('brass.scanners.javascript_typescript_scanner.subprocess.run')
    def test_file_discovery_excludes(self, mock_run):
        """Test exclusion patterns work correctly."""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "v18.0.0"
        
        # Create files in excluded directories
        (self.temp_path / "node_modules" / "test.js").write_text("excluded")
        (self.temp_path / "build" / "test.js").write_text("excluded")
        
        with patch.object(JavaScriptTypeScriptScanner, '_locate_babel_script', return_value=self.babel_script):
            scanner = JavaScriptTypeScriptScanner(self.temp_dir)
            files = scanner._discover_js_ts_files()
        
        # Should not find files in excluded directories
        for file_path in files:
            self.assertNotIn("node_modules", file_path)
            self.assertNotIn("build", file_path)
    
    @patch('brass.scanners.javascript_typescript_scanner.subprocess.run')
    def test_scan_filters_non_js_files_from_caller_provided_list(self, mock_run):
        """When the orchestrator passes the prefilter result as
        file_paths, that list includes every language (.py, .md,
        .json, .yml, ...). Babel then tries to parse them all and
        emits a "Parse Error" finding for each non-JS file.

        Discovered 2026-05-21 on a whisperx scan: 46 false-positive
        analysis_error findings, every one of them from Babel choking
        on a .py / .md / .json. Regression guard: when scan() gets a
        caller-provided file list, it must filter to JS/TS
        extensions before invoking Babel.
        """
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "v18.0.0"

        # Mix of JS/TS files (should be scanned) and other types
        # (should be silently dropped from the scan list).
        mixed = [
            str(self.temp_path / "test.js"),     # keep
            str(self.temp_path / "test.ts"),     # keep
            str(self.temp_path / "app.py"),      # drop
            str(self.temp_path / "README.md"),   # drop
            str(self.temp_path / "data.json"),   # drop
            str(self.temp_path / "config.yml"),  # drop
            str(self.temp_path / "build.sh"),    # drop
        ]
        # Create dummy files for the drop-list so any code that checks
        # file existence sees them.
        for p in mixed[2:]:
            Path(p).write_text("// content irrelevant — must not be parsed\n")

        with patch.object(JavaScriptTypeScriptScanner, '_locate_babel_script', return_value=self.babel_script):
            scanner = JavaScriptTypeScriptScanner(self.temp_dir)
            # Patch the babel-batch processor so the test doesn't depend
            # on a real subprocess. We just want to assert what gets
            # passed in.
            with patch.object(scanner, '_analyze_file_batch') as mock_proc:
                mock_proc.return_value = []
                scanner.scan(file_paths=mixed)

            # If the filter works, _analyze_file_batch is called only with
            # JS/TS files. Confirm no .py/.md/.json/.yml/.sh got through.
            for call_args in mock_proc.call_args_list:
                file_list = call_args.args[0] if call_args.args else []
                for fp in file_list:
                    suffix = Path(fp).suffix.lower()
                    self.assertIn(suffix, {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'},
                        f"Non-JS file {fp} reached Babel — extension filter broken")

    @patch('brass.scanners.javascript_typescript_scanner.subprocess.run')
    def test_babel_script_execution_success(self, mock_run):
        """Test successful Babel parser subprocess execution."""
        # Mock Node.js check
        node_check = Mock()
        node_check.returncode = 0
        node_check.stdout = "v18.0.0"
        
        # Mock Babel execution
        babel_result = Mock()
        babel_result.returncode = 0
        babel_result.stdout = json.dumps([{
            "file": str(self.temp_path / "test.js"),
            "success": True,
            "patterns": [{
                "type": "security",
                "pattern": "dangerous_eval",
                "severity": "high",
                "line": 1,
                "column": 0,
                "message": "eval() detected",
                "code": "eval('test')"
            }],
            "metrics": {"lines_of_code": 1}
        }])
        
        mock_run.side_effect = [node_check, node_check, babel_result]
        
        with patch.object(JavaScriptTypeScriptScanner, '_locate_babel_script', return_value=self.babel_script):
            scanner = JavaScriptTypeScriptScanner(self.temp_dir)
            files = [str(self.temp_path / "test.js")]
            findings = scanner._analyze_file_batch(files)
        
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].type, FindingType.SECURITY)
        # Filename starts with 'test.' so the test-fixture downgrade fires
        # (severity HIGH → MEDIUM). See JavaScriptTypeScriptScanner._is_test_path
        # and the Polish-4 changelog entry.
        self.assertEqual(findings[0].severity, Severity.MEDIUM)
        self.assertTrue(findings[0].metadata.get('test_context'))

    @patch('brass.scanners.javascript_typescript_scanner.subprocess.run')
    def test_babel_script_execution_failure(self, mock_run):
        """Test handling of Babel parser failures."""
        # Mock Node.js check
        node_check = Mock()
        node_check.returncode = 0
        node_check.stdout = "v18.0.0"
        
        # Mock Babel execution failure
        babel_result = Mock()
        babel_result.returncode = 1
        babel_result.stderr = "Parse error"
        babel_result.stdout = ""
        
        mock_run.side_effect = [node_check, node_check, babel_result]
        
        with patch.object(JavaScriptTypeScriptScanner, '_locate_babel_script', return_value=self.babel_script):
            scanner = JavaScriptTypeScriptScanner(self.temp_dir)
            files = [str(self.temp_path / "test.js")]
            
            with self.assertRaises(RuntimeError) as context:
                scanner._analyze_file_batch(files)
            
            self.assertIn("Babel analysis failed", str(context.exception))
    
    @patch('brass.scanners.javascript_typescript_scanner.subprocess.run')
    def test_json_parsing_valid(self, mock_run):
        """Test parsing valid Babel JSON output."""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "v18.0.0"
        
        with patch.object(JavaScriptTypeScriptScanner, '_locate_babel_script', return_value=self.babel_script):
            scanner = JavaScriptTypeScriptScanner(self.temp_dir)
        
        valid_babel_result = {
            "file": "test.js",
            "success": True,
            "patterns": [],
            "metrics": {}
        }
        
        findings = scanner._babel_result_to_findings(valid_babel_result)
        self.assertIsInstance(findings, list)
    
    @patch('brass.scanners.javascript_typescript_scanner.subprocess.run')
    def test_json_parsing_invalid(self, mock_run):
        """Test handling malformed JSON from Babel."""
        # Mock Node.js check
        node_check = Mock()
        node_check.returncode = 0
        node_check.stdout = "v18.0.0"
        
        # Mock Babel execution with invalid JSON
        babel_result = Mock()
        babel_result.returncode = 0
        babel_result.stdout = "invalid json"
        
        mock_run.side_effect = [node_check, node_check, babel_result]
        
        with patch.object(JavaScriptTypeScriptScanner, '_locate_babel_script', return_value=self.babel_script):
            scanner = JavaScriptTypeScriptScanner(self.temp_dir)
            files = [str(self.temp_path / "test.js")]
            
            with self.assertRaises(RuntimeError) as context:
                scanner._analyze_file_batch(files)
            
            self.assertIn("Invalid JSON from Babel parser", str(context.exception))
    
    @patch('brass.scanners.javascript_typescript_scanner.subprocess.run')
    def test_pattern_to_finding_conversion(self, mock_run):
        """Test conversion of Babel patterns to Finding objects."""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "v18.0.0"
        
        with patch.object(JavaScriptTypeScriptScanner, '_locate_babel_script', return_value=self.babel_script):
            scanner = JavaScriptTypeScriptScanner(self.temp_dir)
        
        pattern = {
            "type": "security",
            "pattern": "dangerous_eval",
            "severity": "high",
            "line": 5,
            "column": 10,
            "message": "eval() usage detected",
            "code": "eval('test')"
        }
        
        # Use a non-test filename so the test-fixture downgrade
        # (Polish-4 / _is_test_path) doesn't fire on this assertion.
        finding = scanner._pattern_to_finding("app.js", pattern)

        self.assertIsInstance(finding, Finding)
        self.assertEqual(finding.type, FindingType.SECURITY)
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.line_number, 5)
        self.assertIn("dangerous_eval", finding.title)
    
    @patch('brass.scanners.javascript_typescript_scanner.subprocess.run')
    def test_file_context_integration(self, mock_run):
        """Test file classifier context addition."""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "v18.0.0"
        
        with patch.object(JavaScriptTypeScriptScanner, '_locate_babel_script', return_value=self.babel_script):
            scanner = JavaScriptTypeScriptScanner(self.temp_dir)
        
        # Create a mock finding
        finding = Finding(
            id="test_id",
            type=FindingType.SECURITY,
            severity=Severity.HIGH,
            file_path="test.js",
            title="Test Finding",
            description="Test description",
            detected_by="test",
            metadata={}
        )
        
        enhanced_finding = scanner._add_file_context_to_finding(finding)
        
        self.assertIn('file_context', enhanced_finding.metadata)
        self.assertIn('file_type', enhanced_finding.metadata['file_context'])
    
    @patch('brass.scanners.javascript_typescript_scanner.subprocess.run')
    def test_batch_processing(self, mock_run):
        """Test file batch processing logic."""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "v18.0.0"
        
        # Create multiple test files
        for i in range(25):  # More than MAX_FILES_PER_BATCH (20)
            (self.temp_path / f"test{i}.js").write_text(f"console.log({i});")
        
        with patch.object(JavaScriptTypeScriptScanner, '_locate_babel_script', return_value=self.babel_script):
            with patch.object(JavaScriptTypeScriptScanner, '_analyze_file_batch', return_value=[]) as mock_analyze:
                scanner = JavaScriptTypeScriptScanner(self.temp_dir)
                scanner.scan()
                
                # Should be called twice due to batching (20 + 5 files)
                self.assertGreaterEqual(mock_analyze.call_count, 2)
    
    @patch('brass.scanners.javascript_typescript_scanner.subprocess.run')
    def test_timeout_handling(self, mock_run):
        """Test subprocess timeout scenarios."""
        # Mock Node.js check
        node_check = Mock()
        node_check.returncode = 0
        node_check.stdout = "v18.0.0"
        
        # Mock timeout
        mock_run.side_effect = [node_check, node_check, subprocess.TimeoutExpired("cmd", 30)]
        
        with patch.object(JavaScriptTypeScriptScanner, '_locate_babel_script', return_value=self.babel_script):
            scanner = JavaScriptTypeScriptScanner(self.temp_dir)
            files = [str(self.temp_path / "test.js")]
            
            with self.assertRaises(RuntimeError) as context:
                scanner._analyze_file_batch(files)
            
            self.assertIn("timed out", str(context.exception))
    
    @patch('brass.scanners.javascript_typescript_scanner.subprocess.run')
    def test_error_finding_creation(self, mock_run):
        """Test creation of error findings for failed analysis."""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "v18.0.0"
        
        with patch.object(JavaScriptTypeScriptScanner, '_locate_babel_script', return_value=self.babel_script):
            scanner = JavaScriptTypeScriptScanner(self.temp_dir)
        
        error_finding = scanner._create_analysis_error_finding("test.js", "Test error")
        
        self.assertEqual(error_finding.type, FindingType.ANALYSIS_ERROR)
        self.assertEqual(error_finding.severity, Severity.LOW)
        self.assertIn("Test error", error_finding.description)
    
    @patch('brass.scanners.javascript_typescript_scanner.subprocess.run')
    def test_parse_error_finding_creation(self, mock_run):
        """Test creation of findings for parse errors."""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "v18.0.0"
        
        with patch.object(JavaScriptTypeScriptScanner, '_locate_babel_script', return_value=self.babel_script):
            scanner = JavaScriptTypeScriptScanner(self.temp_dir)
        
        babel_result = {
            "file": "test.js",
            "success": False,
            "errors": [{
                "type": "parse_error",
                "message": "Unexpected token",
                "line": 5,
                "column": 10
            }]
        }
        
        error_finding = scanner._create_parse_error_finding(babel_result)
        
        self.assertEqual(error_finding.type, FindingType.ANALYSIS_ERROR)
        self.assertEqual(error_finding.severity, Severity.MEDIUM)
        self.assertIn("parse", error_finding.title.lower())
    
    @patch('brass.scanners.javascript_typescript_scanner.subprocess.run')
    def test_language_detection(self, mock_run):
        """Test language detection from file extensions."""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "v18.0.0"
        
        with patch.object(JavaScriptTypeScriptScanner, '_locate_babel_script', return_value=self.babel_script):
            scanner = JavaScriptTypeScriptScanner(self.temp_dir)
        
        self.assertEqual(scanner._detect_language("test.js"), "javascript")
        self.assertEqual(scanner._detect_language("test.ts"), "typescript")
        self.assertEqual(scanner._detect_language("test.jsx"), "jsx")
        self.assertEqual(scanner._detect_language("test.tsx"), "typescript")
    
    @patch('brass.scanners.javascript_typescript_scanner.subprocess.run')
    def test_large_file_exclusion(self, mock_run):
        """Test that very large files are excluded."""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "v18.0.0"
        
        # Create a large file (simulate with mock)
        large_file = self.temp_path / "large.js"
        large_file.write_text("test")
        
        with patch.object(JavaScriptTypeScriptScanner, '_locate_babel_script', return_value=self.babel_script):
            with patch('pathlib.Path.stat') as mock_stat:
                # Mock file size > MAX_FILE_SIZE_BYTES
                mock_stat.return_value.st_size = 2 * 1024 * 1024  # 2MB
                
                scanner = JavaScriptTypeScriptScanner(self.temp_dir)
                files = scanner._discover_js_ts_files()
                
                # Large file should be excluded
                large_files = [f for f in files if "large.js" in f]
                self.assertEqual(len(large_files), 0)
    
    @patch('brass.scanners.javascript_typescript_scanner.subprocess.run')
    def test_finding_id_generation(self, mock_run):
        """Test unique finding ID generation."""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "v18.0.0"
        
        with patch.object(JavaScriptTypeScriptScanner, '_locate_babel_script', return_value=self.babel_script):
            scanner = JavaScriptTypeScriptScanner(self.temp_dir)
        
        id1 = scanner._generate_finding_id("test.js", "eval", 5)
        id2 = scanner._generate_finding_id("test.js", "eval", 10)
        id3 = scanner._generate_finding_id("test.js", "eval", 5)
        
        # IDs should be unique for different lines
        self.assertNotEqual(id1, id2)
        # IDs should be consistent for same inputs
        self.assertEqual(id1, id3)
        # IDs should start with scanner prefix
        self.assertTrue(id1.startswith("js_ts_"))


class TestJavaScriptTypeScriptScannerSecurity(unittest.TestCase):
    """Security-focused tests for the JavaScript/TypeScript scanner."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.temp_path = Path(self.temp_dir)
        self.babel_script = self.temp_path / "babel_parser.js"
        self.babel_script.write_text("// Mock Babel script")
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @patch('brass.scanners.javascript_typescript_scanner.subprocess.run')
    def test_path_traversal_protection(self, mock_run):
        """Test protection against path traversal attacks."""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "v18.0.0"
        
        with patch.object(JavaScriptTypeScriptScanner, '_locate_babel_script', return_value=self.babel_script):
            scanner = JavaScriptTypeScriptScanner(self.temp_dir)
        
        # Test file outside project root
        outside_file = "/etc/passwd"
        pattern = {"type": "security", "pattern": "test", "severity": "high", "line": 1, "column": 1}
        
        finding = scanner._pattern_to_finding(outside_file, pattern)
        
        # Should handle gracefully and not crash
        self.assertIsInstance(finding, Finding)
    
    @patch('brass.scanners.javascript_typescript_scanner.subprocess.run')
    def test_subprocess_command_validation(self, mock_run):
        """Test that subprocess commands are properly constructed."""
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "v18.0.0"
        
        with patch.object(JavaScriptTypeScriptScanner, '_locate_babel_script', return_value=self.babel_script):
            scanner = JavaScriptTypeScriptScanner(self.temp_dir)
        
        # This should not raise security exceptions
        files = [str(self.temp_path / "test.js")]
        
        # Mock successful execution
        babel_result = Mock()
        babel_result.returncode = 0
        babel_result.stdout = json.dumps([{"file": files[0], "success": True, "patterns": []}])
        mock_run.return_value = babel_result
        
        findings = scanner._analyze_file_batch(files)
        self.assertIsInstance(findings, list)


if __name__ == '__main__':
    unittest.main()