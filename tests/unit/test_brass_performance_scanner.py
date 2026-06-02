"""
Comprehensive unit tests for BrassPerformanceScanner.

Tests all components of the performance intelligence scanner including:
- RadonIntegration (complexity analysis)
- VultureIntegration (dead code detection)
- PySpyIntegration (runtime validation)
- PyPerfIntegration (performance benchmarking)
- BrassPerformanceScanner (main scanner class)
- AI-specific pattern detection

Follows Brass2 testing principles with isolated component testing.
"""

import unittest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open
import sys

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from brass.scanners.brass_performance_scanner import (
    BrassPerformanceScanner,
    RadonIntegration,
    VultureIntegration,
    PySpyIntegration,
    PyPerfIntegration,
    PERFORMANCE_THRESHOLDS,
    AI_ANTIPATTERNS
)
from brass.models.finding import Finding, FindingType, Severity


class TestRadonIntegration(unittest.TestCase):
    """Test RadonIntegration for complexity analysis."""
    
    def setUp(self):
        self.radon = RadonIntegration()
    
    @patch('brass.scanners.brass_performance_scanner.RadonIntegration._check_availability')
    def test_initialization_without_radon(self, mock_check):
        """Test initialization when Radon is not available."""
        mock_check.return_value = False
        radon = RadonIntegration()
        self.assertFalse(radon.available)
    
    @patch('radon.complexity.cc_visit')
    @patch('radon.metrics.h_visit')
    def test_analyze_complexity_success(self, mock_h_visit, mock_cc_visit):
        """Test successful complexity analysis."""
        # Mock Radon results
        mock_complexity_result = MagicMock()
        mock_complexity_result.complexity = 15
        mock_complexity_result.name = "complex_function"
        mock_complexity_result.lineno = 10
        mock_cc_visit.return_value = [mock_complexity_result]
        
        mock_halstead_result = MagicMock()
        mock_halstead_result.difficulty = 25.0
        mock_halstead_result.effort = 100.0
        mock_halstead_result.lineno = 20
        mock_h_visit.return_value = [mock_halstead_result]
        
        # Test analysis
        results = self.radon.analyze_complexity("test.py", "def complex_function(): pass")
        
        # Verify results
        self.assertEqual(len(results), 2)
        
        # Check cyclomatic complexity result
        cc_result = results[0]
        self.assertEqual(cc_result["type"], "cyclomatic_complexity")
        self.assertEqual(cc_result["name"], "complex_function")
        self.assertEqual(cc_result["complexity"], 15)
        self.assertEqual(cc_result["severity"], "HIGH")
        
        # Check Halstead result
        halstead_result = results[1]
        self.assertEqual(halstead_result["type"], "halstead_difficulty")
        self.assertEqual(halstead_result["difficulty"], 25.0)
        self.assertEqual(halstead_result["severity"], "MEDIUM")
    
    def test_analyze_complexity_unavailable(self):
        """Test analysis when Radon is unavailable."""
        self.radon.available = False
        results = self.radon.analyze_complexity("test.py", "def test(): pass")
        self.assertEqual(results, [])
    
    @patch('radon.complexity.cc_visit')
    def test_analyze_complexity_exception(self, mock_cc_visit):
        """Test analysis with exception handling."""
        mock_cc_visit.side_effect = Exception("Radon error")
        
        results = self.radon.analyze_complexity("test.py", "invalid code")
        self.assertEqual(results, [])


class TestVultureIntegration(unittest.TestCase):
    """Test VultureIntegration for dead code detection.

    Vulture is invoked via subprocess (post-2026-05-22 GPL-isolation
    refactor). Tests mock ``shutil.which`` for availability and
    ``subprocess.run`` for analysis output — same pattern Pylint/Bandit
    tests use elsewhere in this module.
    """

    def setUp(self):
        self.vulture = VultureIntegration()

    @patch('brass.scanners.brass_performance_scanner.shutil.which')
    def test_initialization_without_vulture(self, mock_which):
        """Test initialization when Vulture binary is not on PATH."""
        mock_which.return_value = None
        vulture = VultureIntegration()
        self.assertFalse(vulture.available)
        self.assertIsNone(vulture._vulture_path)

    @patch('brass.scanners.brass_performance_scanner.shutil.which')
    def test_initialization_with_vulture(self, mock_which):
        """Test initialization when Vulture binary is discoverable."""
        mock_which.return_value = "/usr/local/bin/vulture"
        vulture = VultureIntegration()
        self.assertTrue(vulture.available)
        self.assertEqual(vulture._vulture_path, "/usr/local/bin/vulture")

    @patch('brass.scanners.brass_performance_scanner.subprocess.run')
    @patch('brass.scanners.brass_performance_scanner.shutil.which')
    def test_analyze_dead_code_success(self, mock_which, mock_run):
        """Test successful dead code analysis via subprocess."""
        mock_which.return_value = "/usr/local/bin/vulture"
        # Vulture rc=3 means "dead code found" (vulture/utils.py ExitCode.DeadCode).
        mock_result = MagicMock()
        mock_result.returncode = 3
        mock_result.stdout = (
            "/tmp/test.py:5: unused function 'unused_function' (80% confidence)\n"
        )
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        vulture = VultureIntegration()
        results = vulture.analyze_dead_code("test.py")

        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual(result["type"], "performance_dead_code")
        self.assertEqual(result["name"], "unused_function")
        self.assertEqual(result["code_type"], "function")
        self.assertEqual(result["line_number"], 5)
        self.assertEqual(result["confidence"], 0.8)  # 80% -> 0.8
        self.assertEqual(result["severity"], "LOW")

        # Verify the subprocess invocation matches the established pattern.
        mock_run.assert_called_once()
        called_argv = mock_run.call_args.args[0]
        self.assertEqual(called_argv[0], "/usr/local/bin/vulture")
        self.assertIn("test.py", called_argv)
        self.assertIn("--min-confidence", called_argv)

    @patch('brass.scanners.brass_performance_scanner.subprocess.run')
    @patch('brass.scanners.brass_performance_scanner.shutil.which')
    def test_analyze_dead_code_clean_exit(self, mock_which, mock_run):
        """Vulture rc=0 (no dead code found) should return []."""
        mock_which.return_value = "/usr/local/bin/vulture"
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        vulture = VultureIntegration()
        self.assertEqual(vulture.analyze_dead_code("test.py"), [])

    @patch('brass.scanners.brass_performance_scanner.subprocess.run')
    @patch('brass.scanners.brass_performance_scanner.shutil.which')
    def test_analyze_dead_code_invalid_input(self, mock_which, mock_run):
        """Vulture rc=1 (SyntaxError in target) should return [] silently."""
        mock_which.return_value = "/usr/local/bin/vulture"
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "invalid syntax"
        mock_run.return_value = mock_result

        vulture = VultureIntegration()
        self.assertEqual(vulture.analyze_dead_code("bad.py"), [])

    @patch('brass.scanners.brass_performance_scanner.subprocess.run')
    @patch('brass.scanners.brass_performance_scanner.shutil.which')
    def test_analyze_dead_code_unknown_exit(self, mock_which, mock_run):
        """Unexpected exit codes (e.g. 2 = bad CLI args) return []."""
        mock_which.return_value = "/usr/local/bin/vulture"
        mock_result = MagicMock()
        mock_result.returncode = 2
        mock_result.stdout = ""
        mock_result.stderr = "unrecognized argument"
        mock_run.return_value = mock_result

        vulture = VultureIntegration()
        self.assertEqual(vulture.analyze_dead_code("test.py"), [])

    @patch('brass.scanners.brass_performance_scanner.subprocess.run')
    @patch('brass.scanners.brass_performance_scanner.shutil.which')
    def test_analyze_dead_code_timeout(self, mock_which, mock_run):
        """A subprocess timeout should be caught and yield []."""
        import subprocess as _subprocess
        mock_which.return_value = "/usr/local/bin/vulture"
        mock_run.side_effect = _subprocess.TimeoutExpired(cmd=["vulture"], timeout=30)

        vulture = VultureIntegration()
        self.assertEqual(vulture.analyze_dead_code("test.py"), [])

    @patch('brass.scanners.brass_performance_scanner.subprocess.run')
    @patch('brass.scanners.brass_performance_scanner.shutil.which')
    def test_analyze_dead_code_filters_non_performance_types(self, mock_which, mock_run):
        """Only import / function / class types should survive
        ``_has_performance_impact`` — a 'variable' line must be dropped."""
        mock_which.return_value = "/usr/local/bin/vulture"
        mock_result = MagicMock()
        mock_result.returncode = 3
        mock_result.stdout = (
            "/tmp/test.py:1: unused variable 'x' (60% confidence)\n"
            "/tmp/test.py:2: unused function 'f' (60% confidence)\n"
            "/tmp/test.py:3: unused class 'C' (60% confidence)\n"
            "/tmp/test.py:4: unused import 'os' (90% confidence)\n"
        )
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        vulture = VultureIntegration()
        results = vulture.analyze_dead_code("test.py")

        # 4 lines in, 3 out (variable filtered).
        self.assertEqual(len(results), 3)
        kinds = {r["code_type"] for r in results}
        self.assertEqual(kinds, {"function", "class", "import"})

    def test_analyze_dead_code_unavailable(self):
        """Test analysis when Vulture is unavailable."""
        self.vulture.available = False
        self.vulture._vulture_path = None
        results = self.vulture.analyze_dead_code("test.py")
        self.assertEqual(results, [])

    def test_has_performance_impact(self):
        """Test performance impact classification.

        ``_has_performance_impact`` accepts any object with a ``.typ``
        attribute (the post-refactor ``_UnusedCodeRecord`` or, as here, a
        ``MagicMock``). This contract is unchanged from the in-process
        implementation.
        """
        mock_import = MagicMock()
        mock_import.typ = "import"
        self.assertTrue(self.vulture._has_performance_impact(mock_import))

        mock_function = MagicMock()
        mock_function.typ = "function"
        self.assertTrue(self.vulture._has_performance_impact(mock_function))

        mock_variable = MagicMock()
        mock_variable.typ = "variable"
        self.assertFalse(self.vulture._has_performance_impact(mock_variable))


class TestPySpyIntegration(unittest.TestCase):
    """Test PySpyIntegration for runtime validation."""
    
    def setUp(self):
        self.pyspy = PySpyIntegration()
    
    @patch('subprocess.run')
    def test_check_availability_success(self, mock_run):
        """Test py-spy availability check success."""
        mock_run.return_value.returncode = 0
        pyspy = PySpyIntegration()
        self.assertTrue(pyspy.available)
    
    @patch('subprocess.run')
    def test_check_availability_failure(self, mock_run):
        """Test py-spy availability check failure."""
        mock_run.side_effect = FileNotFoundError()
        pyspy = PySpyIntegration()
        self.assertFalse(pyspy.available)
    
    def test_validate_findings_unavailable(self):
        """Test validation when py-spy is unavailable."""
        self.pyspy.available = False
        findings = [MagicMock()]
        result = self.pyspy.validate_findings(findings, "/test/path")
        self.assertEqual(result, findings)
    
    def test_create_test_script_string_concatenation(self):
        """Test test script creation for string concatenation."""
        finding = MagicMock()
        finding.metadata = {"antipattern_type": "string_concatenation_loop"}
        
        script = self.pyspy._create_test_script(finding)
        self.assertIn("result += f\"item_{i} \"", script)
        self.assertIn("for i in range(1000)", script)
    
    def test_create_test_script_list_insert(self):
        """Test test script creation for list insert."""
        finding = MagicMock()
        finding.metadata = {"antipattern_type": "list_insert_zero_loop"}
        
        script = self.pyspy._create_test_script(finding)
        self.assertIn("result.insert(0, i)", script)
        self.assertIn("for i in range(1000)", script)
    
    def test_create_test_script_nested_loops(self):
        """Test test script creation for nested loops."""
        finding = MagicMock()
        finding.metadata = {
            "antipattern_type": "excessive_nested_loops",
            "nesting_level": 3
        }
        
        script = self.pyspy._create_test_script(finding)
        self.assertIn("for i in range(100)", script)
        self.assertIn("for j in range(100)", script)
        self.assertIn("for k in range(10)", script)


class TestPyPerfIntegration(unittest.TestCase):
    """Test PyPerfIntegration for performance benchmarking."""
    
    def setUp(self):
        self.pyperf = PyPerfIntegration()
    
    @patch('brass.scanners.brass_performance_scanner.PyPerfIntegration._check_availability')
    def test_initialization_without_pyperf(self, mock_check):
        """Test initialization when pyperf is not available."""
        mock_check.return_value = False
        pyperf = PyPerfIntegration()
        self.assertFalse(pyperf.available)
    
    def test_benchmark_findings_unavailable(self):
        """Test benchmarking when pyperf is unavailable."""
        self.pyperf.available = False
        findings = [MagicMock()]
        result = self.pyperf.benchmark_findings(findings, "/test/path")
        self.assertEqual(result, findings)
    
    @unittest.skipUnless(
        __import__('importlib.util').util.find_spec('pyperf'),
        "pyperf is an optional dependency; skipping when not installed",
    )
    @patch('pyperf.Runner')
    def test_create_performance_benchmark_string_concat(self, mock_runner_class):
        """Test benchmark creation for string concatenation."""
        # Mock pyperf runner
        mock_runner = MagicMock()
        mock_runner_class.return_value = mock_runner
        
        # Mock benchmark results
        mock_result_slow = MagicMock()
        mock_result_slow.get_mean.return_value = 0.1  # 100ms
        mock_result_fast = MagicMock()
        mock_result_fast.get_mean.return_value = 0.01  # 10ms
        
        mock_runner.timeit.side_effect = [mock_result_slow, mock_result_fast]
        
        # Test benchmark creation
        finding = MagicMock()
        finding.metadata = {"antipattern_type": "string_concatenation_loop"}
        
        result = self.pyperf._create_performance_benchmark(finding)
        
        # Verify benchmark results
        self.assertEqual(result["tool"], "pyperf")
        self.assertIn("100.00ms", result["inefficient_time"])
        self.assertIn("10.00ms", result["efficient_time"])
        self.assertIn("90.0% faster", result["improvement_potential"])


class TestBrassPerformanceScanner(unittest.TestCase):
    """Test main BrassPerformanceScanner class."""
    
    def setUp(self):
        # Create temporary test directory
        self.test_dir = tempfile.mkdtemp()
        self.test_path = Path(self.test_dir)
        
        # Create test Python file
        test_file = self.test_path / "test.py"
        test_file.write_text("""
def complex_function():
    result = ""
    for i in range(100):
        result += f"item_{i}"
    return result

def unused_function():
    pass
""")
    
    def tearDown(self):
        shutil.rmtree(self.test_dir)
    
    def test_initialization_success(self):
        """Test successful scanner initialization."""
        scanner = BrassPerformanceScanner(str(self.test_path))
        self.assertEqual(scanner.project_path.resolve(), self.test_path.resolve())
        self.assertIsNotNone(scanner.radon_integration)
        self.assertIsNotNone(scanner.vulture_integration)
        self.assertFalse(scanner.runtime_validation_enabled)
        self.assertFalse(scanner.benchmarking_enabled)
    
    def test_initialization_with_phase2(self):
        """Test initialization with Phase 2 capabilities."""
        scanner = BrassPerformanceScanner(
            str(self.test_path),
            enable_runtime_validation=True,
            enable_benchmarking=True
        )
        self.assertIsNotNone(scanner.pyspy_integration)
        self.assertIsNotNone(scanner.pyperf_integration)
    
    def test_initialization_invalid_path(self):
        """Test initialization with invalid path."""
        with self.assertRaises(ValueError):
            BrassPerformanceScanner("")
        
        with self.assertRaises(FileNotFoundError):
            BrassPerformanceScanner("/nonexistent/path")
    
    def test_get_python_files(self):
        """Test Python file discovery."""
        scanner = BrassPerformanceScanner(str(self.test_path))
        python_files = scanner._get_python_files()
        
        self.assertEqual(len(python_files), 1)
        self.assertTrue(python_files[0].name.endswith(".py"))
    
    def test_get_python_files_with_file_list(self):
        """Test Python file discovery with specific file list."""
        scanner = BrassPerformanceScanner(str(self.test_path))
        python_files = scanner._get_python_files(["test.py"])
        
        self.assertEqual(len(python_files), 1)
        self.assertEqual(python_files[0].name, "test.py")
    
    @patch('brass.scanners.brass_performance_scanner.RadonIntegration.analyze_complexity')
    @patch('brass.scanners.brass_performance_scanner.VultureIntegration.analyze_dead_code')
    def test_scan_basic(self, mock_vulture, mock_radon):
        """Test basic scan functionality."""
        # Mock integration results
        mock_radon.return_value = [{
            "type": "cyclomatic_complexity",
            "name": "complex_function",
            "complexity": 15,
            "line_number": 2,
            "severity": "HIGH",
            "confidence": 0.95
        }]
        
        mock_vulture.return_value = [{
            "type": "performance_dead_code",
            "name": "unused_function",
            "code_type": "function",
            "line_number": 8,
            "confidence": 0.8
        }]
        
        # Run scan
        scanner = BrassPerformanceScanner(str(self.test_path))
        findings = scanner.scan()
        
        # Verify results
        self.assertGreaterEqual(len(findings), 2)  # At least Radon + Vulture findings
        
        # Check finding types
        finding_types = [f.type for f in findings]
        self.assertIn(FindingType.PERFORMANCE, finding_types)
    
    def test_scan_no_python_files(self):
        """Test scan with no Python files."""
        # Create directory without Python files
        empty_dir = tempfile.mkdtemp()
        try:
            scanner = BrassPerformanceScanner(empty_dir)
            findings = scanner.scan()
            self.assertEqual(len(findings), 0)
        finally:
            shutil.rmtree(empty_dir)
    
    def test_filter_findings(self):
        """Test finding filtering logic."""
        scanner = BrassPerformanceScanner(str(self.test_path))
        
        # Create test findings with different confidence levels
        high_confidence = Finding(
            id="test1",
            type=FindingType.PERFORMANCE,
            severity=Severity.HIGH,
            file_path="test.py",
            title="High Confidence",
            description="Test",
            confidence=0.9,
            detected_by="test"
        )
        
        low_confidence = Finding(
            id="test2", 
            type=FindingType.PERFORMANCE,
            severity=Severity.LOW,
            file_path="test.py",
            title="Low Confidence",
            description="Test",
            confidence=0.5,
            detected_by="test"
        )
        
        findings = [high_confidence, low_confidence]
        filtered = scanner._filter_findings(findings)
        
        # Only high confidence finding should remain
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].confidence, 0.9)


class TestAIPatternDetection(unittest.TestCase):
    """Test AI-specific pattern detection methods."""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.test_path = Path(self.test_dir)
        self.scanner = BrassPerformanceScanner(str(self.test_path))
    
    def tearDown(self):
        shutil.rmtree(self.test_dir)
    
    def test_string_concatenation_detection(self):
        """Test string concatenation in loop detection."""
        # Create test file with string concatenation pattern
        test_file = self.test_path / "string_concat.py"
        test_file.write_text("""
def bad_concat():
    result = ""
    for i in range(100):
        result += f"item_{i}"
    return result
""")
        
        with open(test_file, 'r') as f:
            code = f.read()
        
        import ast
        tree = ast.parse(code)
        findings = self.scanner._detect_string_concatenation_loops(tree, test_file)
        
        self.assertGreater(len(findings), 0)
        finding = findings[0]
        self.assertIn("string_concat", finding.id)
        self.assertEqual(finding.severity, Severity.HIGH)
    
    def test_list_insert_detection(self):
        """Test list.insert(0) pattern detection."""
        test_file = self.test_path / "list_insert.py"
        test_file.write_text("""
def bad_insert():
    result = []
    for i in range(100):
        result.insert(0, i)
    return result
""")
        
        with open(test_file, 'r') as f:
            code = f.read()
        
        import ast
        tree = ast.parse(code)
        findings = self.scanner._detect_inefficient_list_operations(tree, test_file)
        
        self.assertGreater(len(findings), 0)
        finding = findings[0]
        self.assertIn("list_insert", finding.id)
        self.assertEqual(finding.severity, Severity.MEDIUM)


class TestSyntaxErrorPrePass(unittest.TestCase):
    """Regression guard for the cap-hit-drops-syntax-errors bug.

    Pre-2026-05-18: the per-file analyzer loop ran ast.parse pre-check,
    radon, vulture, and AI-patterns together. When the per-scanner
    cap (1000 findings) was hit during radon/vulture/AI-patterns for
    syntactically-valid files, the loop break'd before reaching any
    unvisited files — silently dropping their syntax-error findings
    because they never got AST-parsed. On the coppersun_brass project
    this manifested as 2 of 4 broken files missing from output.

    The fix: separate Phase 1a pre-pass AST-parses every file and emits
    syntax-error findings BEFORE the cap-bounded analyzers run.
    """

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_syntax_errors_surface_regardless_of_cap_state(self):
        """All broken files must produce critical syntax-error findings
        regardless of how many syntactically-valid files precede them
        in iteration order."""
        # Valid-but-complex files sorted alphabetically before the broken
        # ones — without the pre-pass fix, cap could fire before reaching
        # the broken files at the end of iteration.
        for i in range(10):
            (self.test_dir / f"early_{i:03d}.py").write_text(
                "def f():\n" + "    if True:\n" * 50 + "        pass\n"
            )
        (self.test_dir / "zzz_broken_one.py").write_text(
            "def broken(\n    pass\n"
        )
        (self.test_dir / "zzz_broken_two.py").write_text(
            'x = """unterminated\n'
        )

        scanner = BrassPerformanceScanner(str(self.test_dir))
        findings = scanner.scan()

        syntax_findings = [f for f in findings if "Syntax Error" in f.title]
        broken_files = {Path(f.file_path).name for f in syntax_findings}

        self.assertIn("zzz_broken_one.py", broken_files,
                      "Pre-pass must catch broken files even at end of iteration")
        self.assertIn("zzz_broken_two.py", broken_files,
                      "Pre-pass must catch all broken files, not just the first")
        for f in syntax_findings:
            self.assertEqual(f.severity, Severity.CRITICAL)
            self.assertEqual(f.type, FindingType.CODE_QUALITY)
            self.assertGreaterEqual(f.confidence, 0.90)


class TestBoundsCheckCriticalExempt(unittest.TestCase):
    """Regression guard for the BrassPerf MAX_FINDINGS_PER_SCANNER cap
    silently dropping non-syntax CRITICAL findings.

    Pre-fix: when the cap (1000) filled with MEDIUM/HIGH findings,
    later CRITICAL findings were rejected by
    _add_findings_with_bounds_check; the caller's per-file loop
    `break`'d, so CRITICAL findings from unvisited files were lost
    entirely. Syntax errors got special handling via Phase 1a pre-
    pass, but any future BrassPerf CRITICAL non-syntax finding (e.g.
    a runtime-validated security panic) would still vanish.

    Fix: CRITICAL findings are cap-exempt — appended unconditionally,
    no matter how full the list is. Return value still signals "stop"
    when only non-criticals would be dropped, so the loop cost-saving
    behavior is preserved when no critical signal is flowing.
    """

    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.scanner = BrassPerformanceScanner(str(self.test_dir))
        # Import the module-level constant for assertion clarity.
        from brass.scanners.brass_performance_scanner import (
            MAX_FINDINGS_PER_SCANNER,
        )
        self.cap = MAX_FINDINGS_PER_SCANNER

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _make_finding(self, severity: Severity, idx: int) -> Finding:
        return Finding(
            id=f"test_{idx}",
            type=FindingType.PERFORMANCE,
            severity=severity,
            file_path=f"f{idx}.py",
            line_number=1,
            title=f"test finding {idx}",
            description="test",
            confidence=0.9,
            detected_by="BrassPerformanceScanner",
        )

    def test_critical_added_even_when_cap_full(self):
        """The cap should never drop CRITICAL findings."""
        # Pre-fill findings list to exactly the cap with MEDIUM findings.
        findings_list = [
            self._make_finding(Severity.MEDIUM, i) for i in range(self.cap)
        ]
        self.assertEqual(len(findings_list), self.cap)

        critical = self._make_finding(Severity.CRITICAL, self.cap + 1)
        result = self.scanner._add_findings_with_bounds_check(
            findings_list, [critical], "test"
        )

        # CRITICAL must be appended past the cap.
        self.assertEqual(len(findings_list), self.cap + 1)
        self.assertEqual(findings_list[-1].severity, Severity.CRITICAL)
        # And return value should signal "keep going" so the caller's
        # per-file loop doesn't break before later files' CRITICALs.
        self.assertTrue(result, "Adding a CRITICAL past the cap should return True")

    def test_non_critical_dropped_when_cap_full(self):
        """Non-CRITICAL findings continue to be dropped — that's the cap's job."""
        findings_list = [
            self._make_finding(Severity.MEDIUM, i) for i in range(self.cap)
        ]
        new_findings = [self._make_finding(Severity.HIGH, self.cap + i) for i in range(5)]

        result = self.scanner._add_findings_with_bounds_check(
            findings_list, new_findings, "test"
        )

        self.assertEqual(len(findings_list), self.cap, "Non-CRITICAL findings must respect the cap")
        self.assertFalse(result, "All-non-critical cap-overflow should return False")

    def test_mixed_batch_keeps_criticals_drops_non_criticals(self):
        """When a batch has both, CRITICAL goes in, non-CRITICAL gets dropped if no room."""
        findings_list = [
            self._make_finding(Severity.MEDIUM, i) for i in range(self.cap)
        ]
        mixed = [
            self._make_finding(Severity.CRITICAL, self.cap + 1),
            self._make_finding(Severity.HIGH, self.cap + 2),
            self._make_finding(Severity.CRITICAL, self.cap + 3),
        ]

        result = self.scanner._add_findings_with_bounds_check(
            findings_list, mixed, "test"
        )

        # Both CRITICALs in; the HIGH was dropped because cap was full.
        critical_count = sum(1 for f in findings_list if f.severity == Severity.CRITICAL)
        self.assertEqual(critical_count, 2)
        self.assertEqual(len(findings_list), self.cap + 2)
        # Result True because we accepted CRITICALs (caller continues).
        self.assertTrue(result)


if __name__ == '__main__':
    unittest.main()