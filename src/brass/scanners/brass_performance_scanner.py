"""
BrassPerformanceScanner - Performance Intelligence Scanner for AI-generated code.

This scanner detects algorithmic performance anti-patterns using a hybrid approach:
- Radon: Scientific complexity metrics (cyclomatic complexity, Halstead metrics)  
- Vulture: Dead code detection with performance impact analysis
- Custom AI Patterns: Performance issues AI coders systematically miss

Follows Brass2 architectural principles with clean separation of concerns.
"""

import ast
import hashlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import List, Optional, Dict, Set, Any, Tuple
from collections import defaultdict
from datetime import datetime

from brass.models.finding import Finding, FindingType, Severity
from brass.core.file_classifier import FileClassifier
from brass.core.logging_config import get_logger
from brass.core.error_handling import handle_analysis_error, safe_file_operation
from brass.core.path_safety import is_within
# Shared credential redactor (moved to base_builder so the snippet-
# synthesis path in ai_instructions_builder can apply the same scrubber
# to context lines from PhantomAI-style scanners that don't pre-redact).
from brass.output.yaml_builders.base_builder import BaseYAMLBuilder

_redact_potential_credential = BaseYAMLBuilder.redact_potential_credential


def _safe_path_for_log(path: str) -> str:
    """Strip control characters from a filename before logging.

    BrassCoders scans untrusted code; on POSIX, filenames can contain `\\n`,
    `\\r`, ANSI CSI sequences (`\\x1b[2J`), and other terminal control
    codes. A hostile filename committed to a vendored dep could forge
    fake log lines, clear the terminal, or smuggle hyperlinks into a
    log file later cat'd by an SRE. Use unicode-escape encoding to
    render any non-printable as a literal `\\x..` rather than letting
    the terminal interpret it. Customer's actual paths are unaffected
    (normal filenames have no control chars). Defense in depth flagged
    by the 2026-05-19 security review.
    """
    if not path:
        return ""
    return path.encode("unicode_escape").decode("ascii")


# Numeric severity ranking. Severity.value is a string, so sorting by it
# orders alphabetically (medium > low > info > high > critical), silently
# dropping CRITICAL findings before MEDIUM ones in the per-category cap.
_SEVERITY_ORDER = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


def _severity_rank(severity: Severity) -> int:
    """Numeric rank for severity sorting (CRITICAL highest)."""
    return _SEVERITY_ORDER.get(severity, 0)

logger = get_logger(__name__)

# Configuration constants
MAX_FILE_SIZE_BYTES = 1024 * 1024  # 1MB - Skip large files for performance
DEFAULT_CONFIDENCE = 0.85  # High confidence for algorithmic pattern detection
MAX_FINDINGS_PER_CATEGORY = 20  # Limit findings to avoid noise
MAX_FINDINGS_PER_SCANNER = 1000  # Maximum total findings to prevent memory exhaustion

# Phase 2 constants
RUNTIME_VALIDATION_TIMEOUT = 30  # Maximum seconds for py-spy profiling (fallback)
RUNTIME_VALIDATION_MIN_TIMEOUT = 10  # Minimum timeout for simple functions
RUNTIME_VALIDATION_MAX_TIMEOUT = 120  # Maximum timeout for complex functions
BENCHMARK_TIMEOUT = 60  # Maximum seconds for pyperf benchmarking
MIN_RUNTIME_SAMPLE_SIZE = 5  # Minimum samples for statistical significance

# Performance analysis thresholds (industry standards + AI-specific)
PERFORMANCE_THRESHOLDS = {
    # Radon complexity thresholds (industry standards)
    "radon_complexity": {
        "high_severity": 15,      # Widely accepted industry standard  
        "medium_severity": 10,    # Industry threshold for complex functions
        "confidence": 0.95        # Radon is scientifically proven
    },
    "radon_halstead": {
        "difficulty_threshold": 20,  # High algorithmic difficulty
        "confidence": 0.85           # Well-established metric
    },
    
    # AI-specific pattern thresholds (our domain expertise)
    "ai_antipatterns": {
        "string_concat_loop": 0.95,      # Always a performance problem
        "list_insert_zero_loop": 0.90,   # Clear pattern detection  
        "database_in_loop": 0.85,        # N+1 query problem
        "nested_loops_3plus": 0.90       # Clear O(N³) issue
    },
    
    # Resource management thresholds
    "resource_management": {
        "file_without_context": 0.95,   # Very obvious leaks
        "unbounded_while_loop": 0.80     # Pattern-based detection
    }
}

# AI coder performance anti-patterns (based on research)
AI_ANTIPATTERNS = {
    "string_concatenation_loop": [
        "String concatenation with += in loop causes O(N²) behavior",
        "Use list.append() in loop, then ''.join(list) for O(N) performance"
    ],
    "list_insert_zero": [
        "Using list.insert(0, item) in loop causes O(N²) behavior", 
        "Use list.append() and reverse, or collections.deque for O(1) operations"
    ],
    "database_queries_in_loop": [
        "Database queries inside loops create N+1 query performance problems",
        "Use bulk operations, JOIN queries, or ORM select_related/prefetch_related"
    ],
    "nested_loops_excessive": [
        "Nested loops create exponential complexity (O(N²), O(N³), etc.)",
        "Consider hash maps for lookups, sort+merge algorithms, or better data structures"
    ]
}


@contextmanager
def managed_temp_file(content: str, suffix: str = '.py'):
    """Context manager for temporary files with guaranteed cleanup."""
    with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False) as f:
        f.write(content)
        temp_file = f.name
    
    try:
        yield temp_file
    finally:
        try:
            Path(temp_file).unlink()
        except (FileNotFoundError, PermissionError) as e:
            logger.debug(f"Could not remove temp file {temp_file}: {e}")
        except OSError as e:
            logger.warning(f"OS error removing temp file {temp_file}: {e}")


class RadonIntegration:
    """Integration with Radon for scientific complexity analysis."""

    def __init__(self):
        self.available = self._check_availability()
    
    def _check_availability(self) -> bool:
        """Check if Radon is available for analysis."""
        try:
            import radon
            return True
        except ImportError:
            logger.warning("Radon not available - install with: pip install radon")
            return False
    
    def analyze_complexity(self, file_path: str, code: str) -> List[Dict[str, Any]]:
        """Analyze cyclomatic complexity using Radon."""
        return self._analyze_complexity_impl(file_path, code=code, tree=None)

    def analyze_complexity_from_tree(self, file_path: str, tree: ast.AST) -> List[Dict[str, Any]]:
        """Same as analyze_complexity but uses a pre-parsed AST tree.

        Lets the caller (BrassPerformanceScanner's single-loop pipeline)
        parse the source ONCE and reuse the tree across analyzers,
        avoiding radon's internal ast.parse re-pass. Saves ~3-8 ms per
        file on CPython 3.10-3.12 — material on monorepo scans.
        Perf auditor 2026-05-19 Option A.
        """
        return self._analyze_complexity_impl(file_path, code=None, tree=tree)

    def _analyze_complexity_impl(
        self,
        file_path: str,
        *,
        code: Optional[str],
        tree: Optional[ast.AST],
    ) -> List[Dict[str, Any]]:
        """Shared body for analyze_complexity / analyze_complexity_from_tree.

        Uses radon's `cc_visit_ast` + `h_visit_ast` (radon ≥6) when a
        tree is supplied; falls back to `cc_visit` + `h_visit` (which
        ast.parse internally) when only source code is supplied.
        """
        if not self.available:
            return []

        try:
            results = []

            # Cyclomatic Complexity Analysis
            if tree is not None:
                from radon.complexity import cc_visit_ast
                complexity_results = cc_visit_ast(tree)
            else:
                from radon.complexity import cc_visit
                complexity_results = cc_visit(code)
            for result in complexity_results:
                if result.complexity >= PERFORMANCE_THRESHOLDS["radon_complexity"]["medium_severity"]:
                    results.append({
                        "type": "cyclomatic_complexity",
                        "name": result.name,
                        "complexity": result.complexity,
                        "line_number": result.lineno,
                        "severity": "HIGH" if result.complexity >= PERFORMANCE_THRESHOLDS["radon_complexity"]["high_severity"] else "MEDIUM",
                        "confidence": PERFORMANCE_THRESHOLDS["radon_complexity"]["confidence"]
                    })
            
            # Halstead Metrics (Algorithmic Complexity).
            # Both h_visit(code) and h_visit_ast(tree) return the same
            # Halstead(total, functions) namedtuple. Original iteration
            # semantics (loop over the namedtuple fields, check via
            # hasattr) work identically against either — preserve.
            try:
                if tree is not None:
                    from radon.metrics import h_visit_ast
                    halstead_results = h_visit_ast(tree)
                else:
                    from radon.metrics import h_visit
                    halstead_results = h_visit(code)
                for result in halstead_results:
                    if hasattr(result, 'difficulty') and result.difficulty > PERFORMANCE_THRESHOLDS["radon_halstead"]["difficulty_threshold"]:
                        results.append({
                            "type": "halstead_difficulty", 
                            "difficulty": result.difficulty,
                            "effort": getattr(result, 'effort', 0),
                            "line_number": getattr(result, 'lineno', 1),
                            "severity": "MEDIUM",
                            "confidence": PERFORMANCE_THRESHOLDS["radon_halstead"]["confidence"]
                        })
            except Exception as e:
                # Halstead can fail on some code patterns
                logger.debug(f"Halstead analysis failed for {file_path}: {e}")
            
            return results
            
        except SyntaxError:
            # Unreachable in practice — BrassPerformanceScanner.scan now pre-validates
            # syntax and emits a critical Finding for the file before any per-tool
            # analysis runs, so radon never sees an unparseable input. Kept as a
            # defensive no-op in case the integration is invoked directly elsewhere.
            return []
        except Exception as e:
            logger.error(f"Radon analysis failed for {file_path}: {e}")
            return []


class VultureIntegration:
    """Integration with Vulture for performance-impacting dead code detection.

    Vulture is invoked as a subprocess (via ``shutil.which("vulture")``) rather
    than imported as a Python module. This matches the established pattern brass
    already uses for Pylint, Bandit, Pyre, Semgrep, and ast-grep — and, more
    importantly, keeps Vulture's GPL-3.0 license out of brass's Python wheel
    closure. Vulture stays a core dependency (still pip-installed alongside
    brass), but is now executed via the PATH binary, not imported.

    See the OpenStack legal-discuss thread on subprocess-vs-import for the
    licensing rationale; the customer-visible behavior is identical to the
    prior in-process implementation (same findings, same dict shape).
    """

    # Subprocess wall-clock cap. Vulture is fast on single files (typically
    # <1 s for a 1 MB file, the perf scanner's MAX_FILE_SIZE_BYTES gate), so
    # 30 s is a wide safety margin that still bounds runaway-process risk.
    VULTURE_TIMEOUT = 30

    # Vulture's min-confidence floor. The previous in-process implementation
    # didn't filter by confidence at the call site — it took whatever
    # ``get_unused_code()`` returned (default 60% min) and then dropped non-
    # performance-impacting types in ``_has_performance_impact``. Setting 60
    # here preserves that behavior exactly: every finding that would have
    # come through the old API now comes through the subprocess path too.
    MIN_CONFIDENCE = 60

    # Vulture exit codes (vulture/utils.py: class ExitCode(IntEnum)):
    #   0 = NoDeadCode  (clean run, no findings — not an error)
    #   1 = InvalidInput  (e.g. SyntaxError in target file)
    #   2 = InvalidCmdlineArguments
    #   3 = DeadCode  (findings present — also not an error, expected case)
    # NOTE: the call-site description previously said "1 = found unused code,
    # 3 = invalid syntax" — that's backwards. The IntEnum above is the
    # authoritative source.
    _OK_EXIT_CODES = frozenset({0, 3})
    _SYNTAX_ERROR_EXIT_CODE = 1

    # Parse vulture's default text output line:
    #   <file.py>:<LINE>: unused <TYPE> '<NAME>' (NN% confidence)
    # NAME captured non-greedily so embedded quotes inside identifiers (rare,
    # but vulture quotes the literal symbol) don't run past the closing '.
    # Confidence is captured as a digit run; vulture only emits integer
    # percentages in [0, 100]. The leading file path is discarded — caller
    # already knows which file it asked vulture to analyze.
    _OUTPUT_LINE_RE = re.compile(
        r"^.+?:(?P<line>\d+):\s+unused\s+(?P<typ>\S+)\s+"
        r"'(?P<name>.+?)'\s+\((?P<confidence>\d+)%\s+confidence\)\s*$"
    )

    def __init__(self):
        self._vulture_path: Optional[str] = shutil.which("vulture")
        self.available = self._vulture_path is not None
        if not self.available:
            # Same log message as the prior `import vulture` path so anyone
            # grepping logs / docs for installation hints still finds it.
            logger.info("Vulture not available - install with: pip install vulture")

    def _check_availability(self) -> bool:
        """Re-probe ``shutil.which("vulture")``.

        Retained so existing tests that patch this method still bind to a
        real attribute. Side-effect: updates ``self._vulture_path`` and
        ``self.available`` to match the current PATH state.
        """
        self._vulture_path = shutil.which("vulture")
        self.available = self._vulture_path is not None
        return self.available

    def analyze_dead_code(self, file_path: str) -> List[Dict[str, Any]]:
        """Analyze dead code with performance impact focus.

        Invokes the vulture CLI binary, parses its text output, and returns
        the same dict shape the prior in-process implementation produced —
        callers (``BrassPerformanceScanner._analyze_with_vulture``) are
        unaffected.
        """
        if not self.available or not self._vulture_path:
            return []

        try:
            result = subprocess.run(
                [self._vulture_path, file_path, "--min-confidence", str(self.MIN_CONFIDENCE)],
                capture_output=True,
                text=True,
                timeout=self.VULTURE_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired:
            logger.warning(
                f"Vulture timed out after {self.VULTURE_TIMEOUT}s on {file_path}"
            )
            return []
        except (OSError, ValueError) as exc:
            # OSError covers FileNotFoundError (vulture deleted between
            # ``shutil.which`` and run) and PermissionError. ValueError
            # covers argv validation failures.
            logger.error(f"Vulture invocation failed for {file_path}: {exc}")
            return []

        # ExitCode 1 = vulture couldn't parse the target (typically a
        # SyntaxError). BrassPerformanceScanner already emits a critical
        # syntax-error Finding for these files in its pre-flight ast.parse,
        # so dropping the vulture run silently here is correct — we'd just
        # be duplicating signal. Log at DEBUG so it's visible if needed.
        if result.returncode == self._SYNTAX_ERROR_EXIT_CODE:
            logger.debug(
                f"Vulture reported invalid input for {file_path} "
                f"(rc=1); skipping dead-code analysis for this file."
            )
            return []

        if result.returncode not in self._OK_EXIT_CODES:
            # Truncate stderr defensively; vulture's error messages are
            # short but a hostile-filename case could produce long output.
            logger.warning(
                f"Vulture exited {result.returncode} on {file_path}: "
                f"{(result.stderr or '').strip()[:200]}"
            )
            return []

        return self._parse_vulture_output(result.stdout)

    def _parse_vulture_output(self, stdout: str) -> List[Dict[str, Any]]:
        """Parse vulture's text output into the legacy dict shape.

        Vulture has no machine-readable output format (no --json flag as of
        2.14), so we regex the default text format. The format has been
        stable since vulture 1.0; if a future version changes it, every
        finding will silently disappear — so we log at DEBUG when a line
        looks like a vulture report but fails the regex.
        """
        results: List[Dict[str, Any]] = []
        for raw_line in stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            match = self._OUTPUT_LINE_RE.match(line)
            if not match:
                # Don't warn — vulture also emits header/footer chatter on
                # some configurations. DEBUG keeps the diagnostic available
                # without polluting normal scans.
                logger.debug(f"Vulture: unparseable output line: {line!r}")
                continue
            typ = match.group("typ")
            # Build a lightweight stand-in object with a `.typ` attribute so
            # `_has_performance_impact` keeps its existing signature — the
            # test suite passes ``MagicMock(typ=...)`` instances directly to
            # it, and we want that contract unchanged.
            if not self._has_performance_impact(_UnusedCodeRecord(typ=typ)):
                continue
            try:
                line_number = int(match.group("line"))
                confidence_pct = int(match.group("confidence"))
            except ValueError:
                # Regex guarantees \d+, so this is unreachable in practice;
                # defensive belt-and-braces in case the regex is loosened.
                continue
            results.append({
                "type": "performance_dead_code",
                "name": match.group("name"),
                "code_type": typ,
                "line_number": line_number,
                "confidence": confidence_pct / 100.0,  # Convert to 0-1 scale
                "severity": "LOW",  # Dead code is lower priority than algorithmic issues
            })
        return results

    def _has_performance_impact(self, unused_code) -> bool:
        """Determine if dead code has significant performance impact.

        Accepts any object exposing a ``.typ`` attribute — the prior
        vulture Item, our internal ``_UnusedCodeRecord``, or a test
        ``MagicMock(typ=...)``. Filter is unchanged from the in-process
        implementation.
        """
        # Focus on imports, large functions, and class definitions
        performance_impacting_types = ['import', 'function', 'class']
        return unused_code.typ in performance_impacting_types


class _UnusedCodeRecord:
    """Minimal stand-in for vulture's internal Item with a ``.typ`` field.

    Exists solely so ``VultureIntegration._has_performance_impact`` can
    keep its object-with-attribute signature after the subprocess
    refactor. Not part of the public API — see ``_parse_vulture_output``.
    """

    __slots__ = ("typ",)

    def __init__(self, typ: str) -> None:
        self.typ = typ


class PySpyIntegration:
    """Runtime validation using py-spy profiling."""
    
    def __init__(self):
        self.available = self._check_availability()
        # Note: Temporary files now managed by context managers
    
    def _check_availability(self) -> bool:
        """Check if py-spy is available for runtime validation."""
        try:
            result = subprocess.run(['py-spy', '--version'], 
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.info("py-spy not available - install with: pip install py-spy")
            return False
    
    def _calculate_dynamic_timeout(self, finding: Finding) -> int:
        """Calculate dynamic timeout based on finding complexity and type."""
        base_timeout = RUNTIME_VALIDATION_MIN_TIMEOUT
        
        # Adjust timeout based on antipattern type
        antipattern_type = finding.metadata.get("antipattern_type", "")
        if antipattern_type == "string_concatenation_loop":
            # String concatenation can be slow to profile
            base_timeout += 15
        elif antipattern_type == "excessive_nested_loops":
            # Nested loops may take longer to demonstrate performance impact
            nesting_level = finding.metadata.get("nesting_level", 3)
            base_timeout += min(nesting_level * 10, 60)
        elif antipattern_type == "list_insert_zero_loop":
            # List operations can be quick to profile
            base_timeout += 10
        
        # Adjust based on severity (higher severity = more time for validation)
        if finding.severity == Severity.CRITICAL:
            base_timeout += 20
        elif finding.severity == Severity.HIGH:
            base_timeout += 15
        
        # Ensure within bounds
        return min(max(base_timeout, RUNTIME_VALIDATION_MIN_TIMEOUT), RUNTIME_VALIDATION_MAX_TIMEOUT)
    
    def validate_findings(self, findings: List[Finding], project_path: str) -> List[Finding]:
        """Add runtime validation data to high-severity performance findings."""
        if not self.available:
            return findings
            
        enhanced_findings = []
        high_severity_findings = [f for f in findings if f.severity in [Severity.HIGH, Severity.CRITICAL]]
        
        logger.debug(f"Runtime validation for {len(high_severity_findings)} high-severity findings")
        
        for finding in findings:
            if finding in high_severity_findings and finding.type == FindingType.PERFORMANCE:
                try:
                    runtime_data = self._profile_performance_issue(finding, project_path)
                    enhanced_finding = self._add_runtime_metadata(finding, runtime_data)
                    enhanced_findings.append(enhanced_finding)
                except Exception as e:
                    logger.warning(f"Runtime validation failed for {finding.id}: {e}")
                    enhanced_findings.append(finding)
            else:
                enhanced_findings.append(finding)
        
        return enhanced_findings
    
    def _profile_performance_issue(self, finding: Finding, project_path: str) -> Dict[str, Any]:
        """Run targeted py-spy profile for specific performance issue.

        Security: synthetic scripts are run with ``python3 -I`` (isolated mode — drops
        ``PYTHON*`` env vars, sys.path additions, user site-packages, and start-up
        scripts) and a minimal ``env`` so a hostile metadata payload can't influence
        execution via env-vars even if a future scanner version interpolates metadata
        into the script text.
        """
        # Create a simple test script that exercises the problematic pattern
        test_script = self._create_test_script(finding)
        if not test_script:
            return {"validated": False, "reason": "Unable to create test case"}

        # Calculate dynamic timeout based on finding complexity
        dynamic_timeout = self._calculate_dynamic_timeout(finding)
        profile_duration_seconds = min(dynamic_timeout // 4, 10)  # Profile for 1/4 of timeout, max 10s

        logger.debug(f"Using dynamic timeout {dynamic_timeout}s (profile duration: {profile_duration_seconds}s) for {finding.metadata.get('antipattern_type', 'unknown')}")

        # Minimal env for the synthetic profiler subprocess.
        import os as _os
        restricted_env = {
            'PATH': _os.environ.get('PATH', '/usr/bin:/bin'),
            'LANG': _os.environ.get('LANG', 'C'),
            'LC_ALL': 'C',
            'HOME': _os.environ.get('HOME', '/tmp'),
        }

        # Run py-spy record on the test script using proper resource management
        with managed_temp_file(test_script, '.py') as test_file:
            with managed_temp_file('', '.svg') as profile_file:
                try:
                    # Execute py-spy profiling with dynamic duration and timeout.
                    # ``python3 -I`` runs the synthetic script in isolated mode.
                    cmd = [
                        'py-spy', 'record',
                        '--duration', str(profile_duration_seconds),
                        '--rate', '100',
                        '--output', profile_file,
                        '--', 'python3', '-I', test_file
                    ]

                    start_time = time.time()
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=dynamic_timeout,
                        env=restricted_env,
                    )
                    actual_duration = time.time() - start_time
                    
                    if result.returncode == 0:
                        return {
                            "validated": True,
                            "tool": "py-spy",
                            "profile_duration": f"{actual_duration:.2f}s",
                            "dynamic_timeout": f"{dynamic_timeout}s",
                            "profile_file": profile_file,
                            "confidence_boost": 0.05  # Increase confidence for runtime-validated findings
                        }
                    else:
                        return {
                            "validated": False,
                            "tool": "py-spy", 
                            "dynamic_timeout": f"{dynamic_timeout}s",
                            "error": result.stderr[:200] if result.stderr else "Unknown error"
                        }
                
                except subprocess.TimeoutExpired:
                    logger.warning(f"py-spy profiling timed out after {dynamic_timeout}s for {finding.metadata.get('antipattern_type', 'unknown')}")
                    return {
                        "validated": False, 
                        "reason": f"Profiling timeout after {dynamic_timeout}s",
                        "dynamic_timeout": f"{dynamic_timeout}s",
                        "fallback_available": True
                    }
                except Exception as e:
                    logger.warning(f"py-spy profiling failed: {e}")
                    return {
                        "validated": False, 
                        "reason": str(e),
                        "dynamic_timeout": f"{dynamic_timeout}s"
                    }
    
    def _create_test_script(self, finding: Finding) -> Optional[str]:
        """Create a test script that reproduces the performance issue.

        **Security invariant**: the returned string MUST be fully literal and contain
        no f-string interpolation of ``finding.metadata`` values. Metadata can be
        scanner-controlled (via the file content being scanned) and any string
        interpolated into a script that we then ``exec`` would be code execution.

        If you need a tunable parameter (e.g. nesting level), validate it as an int
        with ``int(...)`` and use it to *select* a literal template, not to compose
        one.
        """
        antipattern_type = finding.metadata.get("antipattern_type")

        if antipattern_type == "string_concatenation_loop":
            return """
import time
start = time.time()
result = ""
for i in range(1000):
    result += f"item_{i} "
end = time.time()
print(f"String concatenation took {end - start:.3f}s")
"""
        elif antipattern_type == "list_insert_zero_loop":
            return """
import time
start = time.time()
result = []
for i in range(1000):
    result.insert(0, i)
end = time.time()
print(f"List insert(0) took {end - start:.3f}s")
"""
        elif antipattern_type == "excessive_nested_loops":
            try:
                nesting_level = int(finding.metadata.get("nesting_level", 3))
            except (TypeError, ValueError):
                nesting_level = 3
            if nesting_level >= 3:
                return """
import time
start = time.time()
count = 0
for i in range(100):
    for j in range(100):
        for k in range(10):
            count += 1
end = time.time()
print(f"Nested loops took {end - start:.3f}s, count: {count}")
"""
        
        # For Radon/Vulture findings, create generic performance test
        return """
import time
start = time.time()
# Generic performance test
for i in range(10000):
    x = i * 2 + 1
end = time.time()
print(f"Generic test took {end - start:.3f}s")
"""
    
    def _add_runtime_metadata(self, finding: Finding, runtime_data: Dict[str, Any]) -> Finding:
        """Add runtime validation metadata to finding."""
        enhanced_metadata = finding.metadata.copy()
        enhanced_metadata["runtime_validation"] = runtime_data
        
        # Boost confidence if runtime validation succeeded
        enhanced_confidence = finding.confidence
        if runtime_data.get("validated") and runtime_data.get("confidence_boost"):
            enhanced_confidence = min(1.0, enhanced_confidence + runtime_data["confidence_boost"])
        
        # Create new finding with enhanced metadata
        return Finding(
            id=finding.id,
            type=finding.type,
            severity=finding.severity,
            file_path=finding.file_path,
            line_number=finding.line_number,
            title=finding.title,
            description=finding.description,
            remediation=finding.remediation,
            confidence=enhanced_confidence,
            detected_by=finding.detected_by,
            metadata=enhanced_metadata
        )
    
    def cleanup(self):
        """Clean up resources (temporary files now managed by context managers)."""
        # No cleanup needed - context managers handle all temp file cleanup automatically
        pass


class PyPerfIntegration:
    """Performance benchmarking using pyperf."""
    
    def __init__(self):
        self.available = self._check_availability()
    
    def _check_availability(self) -> bool:
        """Check if pyperf is available for benchmarking."""
        try:
            import pyperf
            return True
        except ImportError:
            logger.warning("pyperf not available - install with: pip install pyperf")
            return False
    
    def benchmark_findings(self, findings: List[Finding], project_path: str) -> List[Finding]:
        """Add quantified performance impact to high-severity findings."""
        if not self.available:
            return findings
            
        enhanced_findings = []
        high_severity_findings = [f for f in findings if f.severity in [Severity.HIGH, Severity.CRITICAL]]
        
        logger.debug(f"Performance benchmarking for {len(high_severity_findings)} high-severity findings")
        
        for finding in findings:
            if finding in high_severity_findings and finding.type == FindingType.PERFORMANCE:
                try:
                    benchmark_data = self._create_performance_benchmark(finding)
                    enhanced_finding = self._add_benchmark_metadata(finding, benchmark_data)
                    enhanced_findings.append(enhanced_finding)
                except Exception as e:
                    logger.warning(f"Performance benchmarking failed for {finding.id}: {e}")
                    enhanced_findings.append(finding)
            else:
                enhanced_findings.append(finding)
        
        return enhanced_findings
    
    def _create_performance_benchmark(self, finding: Finding) -> Dict[str, Any]:
        """Create pyperf benchmark for specific performance issue."""
        import pyperf
        
        antipattern_type = finding.metadata.get("antipattern_type")
        
        try:
            runner = pyperf.Runner()
            
            if antipattern_type == "string_concatenation_loop":
                # Benchmark inefficient vs efficient string concatenation
                result_slow = runner.timeit(
                    name="string_concat_slow",
                    stmt='result += f"item_{i} "',
                    setup='result = ""',
                    inner_loops=100
                )
                
                result_fast = runner.timeit(
                    name="string_concat_fast", 
                    stmt='items.append(f"item_{i}")',
                    setup='items = []',
                    inner_loops=100
                )
                
                slow_time = result_slow.get_mean()
                fast_time = result_fast.get_mean()
                improvement = ((slow_time - fast_time) / slow_time) * 100
                
                return {
                    "tool": "pyperf",
                    "inefficient_time": f"{slow_time*1000:.2f}ms per 100 operations",
                    "efficient_time": f"{fast_time*1000:.2f}ms per 100 operations",
                    "improvement_potential": f"{improvement:.1f}% faster",
                    "time_saved_per_operation": f"{(slow_time-fast_time)*10:.3f}μs"
                }
            
            elif antipattern_type == "list_insert_zero_loop":
                # Benchmark list.insert(0) vs list.append + reverse
                result_slow = runner.timeit(
                    name="list_insert_slow",
                    stmt='lst.insert(0, i)',
                    setup='lst = []',
                    inner_loops=100
                )
                
                result_fast = runner.timeit(
                    name="list_append_fast",
                    stmt='lst.append(i)', 
                    setup='lst = []',
                    inner_loops=100
                )
                
                slow_time = result_slow.get_mean()
                fast_time = result_fast.get_mean()
                improvement = ((slow_time - fast_time) / slow_time) * 100
                
                return {
                    "tool": "pyperf",
                    "inefficient_time": f"{slow_time*1000:.2f}ms per 100 operations",
                    "efficient_time": f"{fast_time*1000:.2f}ms per 100 operations", 
                    "improvement_potential": f"{improvement:.1f}% faster",
                    "time_saved_per_operation": f"{(slow_time-fast_time)*10:.3f}μs"
                }
            
            else:
                # Generic benchmark for other findings
                return {
                    "tool": "pyperf",
                    "benchmark_type": "generic",
                    "note": "Specific benchmark not available for this finding type"
                }
        
        except Exception as e:
            return {
                "tool": "pyperf",
                "error": str(e)[:200],
                "benchmark_failed": True
            }
    
    def _add_benchmark_metadata(self, finding: Finding, benchmark_data: Dict[str, Any]) -> Finding:
        """Add performance benchmark metadata to finding."""
        enhanced_metadata = finding.metadata.copy()
        enhanced_metadata["performance_benchmarking"] = benchmark_data
        
        # Create new finding with enhanced metadata
        return Finding(
            id=finding.id,
            type=finding.type,
            severity=finding.severity,
            file_path=finding.file_path,
            line_number=finding.line_number,
            title=finding.title,
            description=finding.description,
            remediation=finding.remediation,
            confidence=finding.confidence,
            detected_by=finding.detected_by,
            metadata=enhanced_metadata
        )


class BrassPerformanceScanner:
    """
    Performance Intelligence Scanner for detecting algorithmic anti-patterns.
    
    Phase 1: Hybrid approach combining proven tools with AI-specific intelligence:
    - Radon for scientific complexity metrics
    - Vulture for performance-impacting dead code
    - Custom analysis for AI coder performance anti-patterns
    
    Phase 2: Enhanced with runtime validation and benchmarking:
    - py-spy for runtime validation of static analysis findings
    - pyperf for quantified performance impact estimates
    
    Follows Brass2 architectural principles:
    - Single responsibility (performance analysis only)
    - Clean Finding interface  
    - No lateral dependencies
    - Graceful degradation for missing tools
    - Backward compatibility (Phase 1 functionality unchanged)
    """
    
    def __init__(self, project_path: str, enable_runtime_validation: bool = False,
                 enable_benchmarking: bool = False, file_index=None) -> None:
        """
        Initialize BrassPerformanceScanner.

        Args:
            project_path: Root path of project to analyze
            file_index: Optional shared FileIndex (Perf #2). Falls back to
                per-scanner rglob walk when None.

        Raises:
            ValueError: If project_path is invalid
            FileNotFoundError: If project_path doesn't exist
        """
        if not project_path:
            raise ValueError("Project path cannot be empty or None")

        self.project_path = Path(project_path).resolve()
        if not self.project_path.exists():
            raise FileNotFoundError(f"Project path does not exist: {self.project_path}")
        self.file_index = file_index
        
        # Initialize core components following established patterns
        self.file_classifier = FileClassifier(str(self.project_path))
        
        # Phase 1 integrations (always available)
        self.radon_integration = RadonIntegration()
        self.vulture_integration = VultureIntegration()
        
        # Phase 2 integrations (optional)
        self.pyspy_integration = PySpyIntegration() if enable_runtime_validation else None
        self.pyperf_integration = PyPerfIntegration() if enable_benchmarking else None
        
        # Track Phase 2 capabilities
        self.runtime_validation_enabled = enable_runtime_validation and (self.pyspy_integration and self.pyspy_integration.available)
        self.benchmarking_enabled = enable_benchmarking and (self.pyperf_integration and self.pyperf_integration.available)
        
        phase2_status = []
        if self.runtime_validation_enabled:
            phase2_status.append("runtime validation")
        if self.benchmarking_enabled:
            phase2_status.append("benchmarking")
        
        phase2_info = f" with {', '.join(phase2_status)}" if phase2_status else ""
        logger.info(f"BrassPerformanceScanner initialized for {self.project_path}{phase2_info}")

        # Files skipped during this scan because they failed to parse.
        # Each one also produces a critical Finding (see _build_syntax_error_finding),
        # so the AI consumer sees the real problem instead of a missing-data gap.
        # The list backs a single end-of-scan summary log line.
        self._syntax_error_files: List[str] = []

        # 2026-05-19 audit (silent-drop class): per-tool analyzer
        # crashes used to return [] and lose that file's findings with
        # no user-visible signal. Each except path now appends
        # f"{file_path}: {type(e).__name__}" here, and scan() emits a
        # single INFO summary at end of scan if > 0.
        self._analyzer_errors: List[str] = []
    
    def scan(self, file_paths: Optional[List[str]] = None, 
             runtime_validation: bool = False,
             benchmarking: bool = False) -> List[Finding]:
        """
        Scan for performance anti-patterns using hybrid approach.
        
        Args:
            file_paths: Optional list of specific files to scan
            
        Returns:
            List of performance findings with actionable remediation
        """
        logger.info("🏆 Running BrassPerf Performance Intelligence analysis...")
        findings = []
        # 2026-05-19 audit (silent-drop class): clear per-scan error
        # collection so a re-used scanner instance doesn't roll
        # previous-scan crashes into this scan's summary.
        self._syntax_error_files = []
        self._analyzer_errors = []
        
        try:
            # Get Python files to analyze
            python_files = self._get_python_files(file_paths)
            
            if not python_files:
                logger.info("No Python files found for performance analysis")
                return findings
            
            logger.info(f"Analyzing {len(python_files)} Python files for performance issues...")
            
            # Phase 1: Streaming single-loop. Each file is opened + parsed
            # ONCE; on SyntaxError the file becomes a critical Finding and
            # the loop continues; on success the cap-bounded analyzers run.
            # The loop never `break`s on cap — the analyzers'
            # _add_findings_with_bounds_check exempts CRITICAL findings
            # past the cap (commit 88c597a), so syntax errors in later
            # files always make it through regardless of cap state.
            #
            # Refactor 2026-05-19 (perf-auditor Option C): replaces a
            # two-phase loop that parsed every file twice. Saves ~3-8 ms
            # per file on monorepo scans (~15-40s on 5000-file Django).
            # Functionally equivalent to the prior two-phase logic; the
            # only invariant the two-phase version protected — "cap-break
            # must not skip un-visited files' syntax pre-check" — is now
            # guaranteed by the cap exemption itself instead.
            for file_path in python_files:
                # Size gate. One stat, atomic with the open below for our
                # purposes (no race window between two stat calls like the
                # two-phase version had).
                try:
                    if file_path.stat().st_size > MAX_FILE_SIZE_BYTES:
                        logger.debug(f"Skipping large file: {file_path}")
                        continue
                except OSError as stat_exc:
                    logger.debug(f"Could not stat {file_path}: {stat_exc}")
                    continue

                # Read + parse once. The resulting tree is passed to
                # radon and AI-patterns analyzers below so they skip
                # their own internal ast.parse. Vulture still parses
                # independently (its scavenge API doesn't accept a tree).
                # SyntaxError is the critical-finding path; IO/encoding
                # failure is silent-skip (transient file state isn't an
                # actionable finding).
                try:
                    with open(file_path, 'r', encoding='utf-8') as _src:
                        parsed_tree = ast.parse(_src.read(), filename=str(file_path))
                except SyntaxError as syntax_exc:
                    self._syntax_error_files.append(str(file_path))
                    findings.append(self._build_syntax_error_finding(file_path, syntax_exc))
                    continue
                except (OSError, UnicodeDecodeError) as io_exc:
                    logger.debug(f"Could not parse {file_path}: {io_exc}")
                    continue

                # File parsed cleanly: run cap-bounded analyzers. Each
                # call returns False if the per-scanner cap is full for
                # non-criticals, but CRITICAL findings always go through
                # via the exemption — so we don't break on False; we just
                # let the cap-aware function decide what to add. Letting
                # the loop continue means later files' CRITICALs still
                # surface even after the cap is reached.
                try:
                    radon_findings = self._analyze_with_radon(file_path, tree=parsed_tree)
                    self._add_findings_with_bounds_check(findings, radon_findings, "Radon")

                    vulture_findings = self._analyze_with_vulture(file_path)
                    self._add_findings_with_bounds_check(findings, vulture_findings, "Vulture")

                    ai_findings = self._analyze_ai_antipatterns(file_path, tree=parsed_tree)
                    self._add_findings_with_bounds_check(findings, ai_findings, "AI-Patterns")
                except Exception as e:
                    logger.error(f"Error analyzing {file_path}: {e}")
                    continue
            
            # Apply intelligent filtering to reduce noise
            findings = self._filter_findings(findings)

            self._emit_silent_drop_summaries()
            logger.info(f"Phase 1 analysis complete: {len(findings)} issues detected")
            
            # Phase 2: Enhanced analysis (optional)
            if (runtime_validation or self.runtime_validation_enabled) and self.pyspy_integration:
                logger.info("🔍 Adding runtime validation (py-spy)...")
                try:
                    findings = self.pyspy_integration.validate_findings(findings, str(self.project_path))
                    validated_count = sum(1 for f in findings if "runtime_validation" in f.metadata)
                    logger.info(f"   Runtime validation completed for {validated_count} findings")
                except Exception as e:
                    logger.warning(f"Runtime validation failed: {e}")
            
            if (benchmarking or self.benchmarking_enabled) and self.pyperf_integration:
                logger.info("⏱️ Adding performance benchmarking (pyperf)...")
                try:
                    findings = self.pyperf_integration.benchmark_findings(findings, str(self.project_path))
                    benchmarked_count = sum(1 for f in findings if "performance_benchmarking" in f.metadata)
                    logger.info(f"   Performance benchmarking completed for {benchmarked_count} findings")
                except Exception as e:
                    logger.warning(f"Performance benchmarking failed: {e}")
            
            logger.info(f"BrassPerf analysis complete: {len(findings)} enhanced performance issues")
            return findings
            
        except Exception as e:
            logger.error(f"BrassPerf analysis failed: {e}")
            return []
        finally:
            # Bug Scanner 2026-05-19: summaries must fire even when an
            # exception escapes Phase 1b/2 — that's exactly when the
            # operator most needs visibility into partial coverage.
            # Idempotent: re-emit is harmless because the happy-path
            # call inside the try block already cleared what it logged
            # via the counters not changing afterward.
            self._emit_silent_drop_summaries()

    def _emit_silent_drop_summaries(self) -> None:
        """Emit aggregate end-of-scan logs for syntax errors + analyzer
        crashes. Idempotent: safe to call multiple times — repeats just
        re-emit the same INFO line. Called both on the happy path and
        from `scan()`'s finally clause so the visibility is preserved
        even when the scan aborts partway.

        File paths are sanitized via `_safe_path_for_log` to neutralize
        control characters (newlines, ANSI escapes) that could otherwise
        forge fake log lines if a customer scanned a project with
        hostile filenames. Security review 2026-05-19.
        """
        if self._syntax_error_files:
            preview = ", ".join(_safe_path_for_log(p) for p in self._syntax_error_files[:3])
            more = (
                f" (+{len(self._syntax_error_files) - 3} more)"
                if len(self._syntax_error_files) > 3 else ""
            )
            logger.info(
                f"Detected {len(self._syntax_error_files)} file(s) with syntax errors "
                f"(emitted as critical findings): {preview}{more}"
            )
        if self._analyzer_errors:
            preview = ", ".join(_safe_path_for_log(e) for e in self._analyzer_errors[:3])
            more = (
                f" (+{len(self._analyzer_errors) - 3} more)"
                if len(self._analyzer_errors) > 3 else ""
            )
            logger.info(
                f"Analyzer crashed on {len(self._analyzer_errors)} file(s) "
                f"(findings for those files were dropped): {preview}{more}"
            )

    def _get_python_files(self, file_paths: Optional[List[str]] = None) -> List[Path]:
        """Get Python files for analysis using file classification."""
        if file_paths:
            return [
                Path(self.project_path / fp) for fp in file_paths 
                if fp.endswith('.py') and Path(self.project_path / fp).exists()
            ]
        
        # Prefer shared FileIndex over rglob walk (Perf #2). FileIndex
        # has already applied is_within + FileClassifier filtering.
        if self.file_index is not None:
            return self.file_index.files_with_ext(".py")
        python_files = []
        for file_path in self.project_path.rglob("*.py"):
            if not file_path.is_file():
                continue
            if not is_within(file_path, self.project_path):
                logger.debug(f"Skipping path outside project root: {file_path}")
                continue
            if self.file_classifier.should_exclude_from_analysis(str(file_path)):
                continue
            python_files.append(file_path)

        return python_files
    
    def _analyze_with_radon(
        self, file_path: Path, tree: Optional[ast.AST] = None,
    ) -> List[Finding]:
        """Analyze file using Radon for complexity metrics.

        When `tree` is supplied (single-loop fast path), radon analyzes
        the pre-parsed AST directly — skipping its internal ast.parse
        and saving ~3-8 ms per file. When None, falls back to reading
        + reparsing (the older code path, kept for callers that don't
        thread a tree in).
        """
        try:
            if tree is not None:
                radon_results = self.radon_integration.analyze_complexity_from_tree(
                    str(file_path), tree,
                )
            else:
                with open(file_path, 'r', encoding='utf-8') as f:
                    code = f.read()
                radon_results = self.radon_integration.analyze_complexity(str(file_path), code)
            findings = []
            
            for result in radon_results:
                if result["type"] == "cyclomatic_complexity":
                    findings.append(Finding(
                        id=f"radon_complexity_{self._generate_id(file_path, result['line_number'])}",
                        type=FindingType.PERFORMANCE,
                        severity=Severity.HIGH if result["severity"] == "HIGH" else Severity.MEDIUM,
                        file_path=str(Path(file_path).resolve().relative_to(Path(self.project_path).resolve())),
                        line_number=result["line_number"],
                        title=f"High Cyclomatic Complexity: {result['complexity']}",
                        description=f"Function '{result['name']}' has complexity {result['complexity']} (threshold: {PERFORMANCE_THRESHOLDS['radon_complexity']['medium_severity']}). High complexity makes code hard to test and maintain, may indicate performance issues.",
                        remediation="Consider breaking function into smaller, focused functions using Extract Method refactoring",
                        confidence=result["confidence"],
                        detected_by="BrassPerformanceScanner",
                        metadata={
                            "analysis_tool": "radon",
                            "metric_type": "cyclomatic_complexity",
                            "complexity_score": result["complexity"],
                            "function_name": result["name"]
                        }
                    ))
                
                elif result["type"] == "halstead_difficulty":
                    findings.append(Finding(
                        id=f"radon_halstead_{self._generate_id(file_path, result['line_number'])}",
                        type=FindingType.PERFORMANCE,
                        severity=Severity.MEDIUM,
                        file_path=str(Path(file_path).resolve().relative_to(Path(self.project_path).resolve())),
                        line_number=result["line_number"],
                        title=f"High Algorithmic Difficulty: {result['difficulty']:.1f}",
                        description=f"Function has high algorithmic complexity (Halstead difficulty: {result['difficulty']:.1f}). Complex algorithms may have poor performance characteristics and are hard to optimize.",
                        remediation="Consider algorithm simplification, better data structures, or divide-and-conquer approaches",
                        confidence=result["confidence"],
                        detected_by="BrassPerformanceScanner", 
                        metadata={
                            "analysis_tool": "radon",
                            "metric_type": "halstead_metrics",
                            "halstead_difficulty": result["difficulty"],
                            "halstead_effort": result.get("effort", 0)
                        }
                    ))
            
            return findings
            
        except SyntaxError:
            # See RadonIntegration.analyze_complexity — pre-validated by scan().
            return []
        except Exception as e:
            logger.error(f"Radon analysis failed for {file_path}: {e}")
            # 2026-05-19 audit (silent-drop class): record the crash so
            # scan() can surface it instead of silently returning [].
            self._analyzer_errors.append(f"{file_path}: Radon/{type(e).__name__}")
            return []

    def _analyze_with_vulture(self, file_path: Path) -> List[Finding]:
        """Analyze file using Vulture for performance-impacting dead code."""
        try:
            vulture_results = self.vulture_integration.analyze_dead_code(str(file_path))
            findings = []
            
            for result in vulture_results:
                findings.append(Finding(
                    id=f"vulture_deadcode_{self._generate_id(file_path, result['line_number'])}",
                    type=FindingType.PERFORMANCE,
                    severity=Severity.LOW,
                    file_path=str(Path(file_path).resolve().relative_to(Path(self.project_path).resolve())),
                    line_number=result["line_number"],
                    title=f"Dead Code with Performance Impact: {result['name']}",
                    description=f"Unused {result['code_type']} '{result['name']}' increases load time and memory usage. Dead code increases module load time, memory usage, and deployment size.",
                    remediation=f"Remove unused {result['code_type']} to improve performance",
                    confidence=result["confidence"],
                    detected_by="BrassPerformanceScanner",
                    metadata={
                        "analysis_tool": "vulture",
                        "dead_code_type": result["code_type"],
                        "dead_code_name": result["name"]
                    }
                ))
            
            return findings
            
        except Exception as e:
            logger.error(f"Vulture analysis failed for {file_path}: {e}")
            # 2026-05-19 audit (silent-drop class): record the crash so
            # scan() can surface it instead of silently returning [].
            self._analyzer_errors.append(f"{file_path}: Vulture/{type(e).__name__}")
            return []
    
    def _analyze_ai_antipatterns(
        self, file_path: Path, tree: Optional[ast.AST] = None,
    ) -> List[Finding]:
        """Analyze file for AI-specific performance anti-patterns.

        Accepts a pre-parsed AST tree (single-loop fast path); falls back
        to reading + parsing the file itself when None. Skipping the
        re-read + re-parse here is the second per-file parse this perf
        pass eliminates.
        """
        try:
            if tree is None:
                with open(file_path, 'r', encoding='utf-8') as f:
                    code = f.read()
                tree = ast.parse(code)
            findings = []
            
            # Detect string concatenation in loops (AI coder classic mistake)
            findings.extend(self._detect_string_concatenation_loops(tree, file_path))
            
            # Detect inefficient list operations
            findings.extend(self._detect_inefficient_list_operations(tree, file_path))
            
            # Detect excessive nested loops
            findings.extend(self._detect_nested_loops(tree, file_path))
            
            # Detect unbounded while loops
            findings.extend(self._detect_unbounded_while_loops(tree, file_path))
            
            return findings
            
        except SyntaxError as e:
            logger.debug(f"Syntax error in {file_path}: {e}")
            return []
        except Exception as e:
            logger.error(f"AI anti-pattern analysis failed for {file_path}: {e}")
            # 2026-05-19 audit (silent-drop class): record the crash so
            # scan() can surface it instead of silently returning [].
            self._analyzer_errors.append(f"{file_path}: AI-Patterns/{type(e).__name__}")
            return []
    
    def _detect_string_concatenation_loops(self, tree: ast.AST, file_path: Path) -> List[Finding]:
        """Detect string concatenation in loops (O(N²) behavior)."""
        findings = []
        
        for node in ast.walk(tree):
            if isinstance(node, (ast.For, ast.While)):
                # Look for string += operations in loop body
                for loop_node in ast.walk(node):
                    if (isinstance(loop_node, ast.AugAssign) and 
                        isinstance(loop_node.op, ast.Add)):
                        
                        findings.append(Finding(
                            id=f"string_concat_loop_{self._generate_id(file_path, loop_node.lineno)}",
                            type=FindingType.PERFORMANCE,
                            severity=Severity.HIGH,
                            file_path=str(Path(file_path).resolve().relative_to(Path(self.project_path).resolve())),
                            line_number=loop_node.lineno,
                            title="O(N²) String Concatenation in Loop",
                            description="String concatenation with += in loop causes quadratic time complexity. For N iterations, this creates N string objects, requiring O(N²) time and memory.",
                            remediation="Use list.append() in loop, then ''.join(list) after loop for O(N) performance",
                            confidence=PERFORMANCE_THRESHOLDS["ai_antipatterns"]["string_concat_loop"],
                            detected_by="BrassPerformanceScanner",
                            metadata={
                                "antipattern_type": "string_concatenation_loop",
                                "ai_coder_common": True,
                                "complexity_issue": "O(N²)"
                            }
                        ))
        
        return findings
    
    def _detect_inefficient_list_operations(self, tree: ast.AST, file_path: Path) -> List[Finding]:
        """Detect inefficient list operations (insert(0) in loops)."""
        findings = []
        
        for node in ast.walk(tree):
            # Look for list.insert(0, item) operations
            if (isinstance(node, ast.Call) and
                hasattr(node.func, 'attr') and node.func.attr == 'insert' and
                len(node.args) >= 2 and
                isinstance(node.args[0], ast.Constant) and node.args[0].value == 0):
                
                # Check if this is inside a loop
                if self._is_in_loop(node, tree):
                    findings.append(Finding(
                        id=f"list_insert_zero_{self._generate_id(file_path, node.lineno)}",
                        type=FindingType.PERFORMANCE,
                        severity=Severity.MEDIUM,
                        file_path=str(Path(file_path).resolve().relative_to(Path(self.project_path).resolve())),
                        line_number=node.lineno,
                        title="Inefficient List Operation: insert(0) in loop",
                        description="Using list.insert(0, item) in loop causes O(N²) behavior. Each insert(0) requires shifting all existing elements.",
                        remediation="Use list.append() and reverse list after loop, or use collections.deque",
                        confidence=PERFORMANCE_THRESHOLDS["ai_antipatterns"]["list_insert_zero_loop"],
                        detected_by="BrassPerformanceScanner",
                        metadata={
                            "antipattern_type": "list_insert_zero_loop",
                            "ai_coder_common": True,
                            "complexity_issue": "O(N²)"
                        }
                    ))
        
        return findings
    
    def _detect_nested_loops(self, tree: ast.AST, file_path: Path) -> List[Finding]:
        """Detect excessive nested loops (O(N³+) complexity)."""
        findings = []
        
        def count_nested_loops(node, depth=0):
            """Recursively count nested loop depth."""
            if isinstance(node, (ast.For, ast.While)):
                depth += 1
                if depth >= 3:  # 3+ nested loops = potential O(N³+)
                    # Check if this is a legitimate pattern (matrix operations, etc.)
                    if not self._is_legitimate_nested_loops(node):
                        findings.append(Finding(
                            id=f"nested_loops_{self._generate_id(file_path, node.lineno)}",
                            type=FindingType.PERFORMANCE,
                            severity=Severity.HIGH,
                            file_path=str(Path(file_path).resolve().relative_to(Path(self.project_path).resolve())),
                            line_number=node.lineno,
                            title=f"Potential O(N^{depth}) Algorithm: {depth}-level nested loops",
                            description=f"{depth}-level nested loops may cause exponential time complexity. For 1000 items, this could require {self._estimate_operations(depth)} operations.",
                            remediation="Consider: hash maps for lookups, sort+merge algorithms, or data structure optimization",
                            confidence=PERFORMANCE_THRESHOLDS["ai_antipatterns"]["nested_loops_3plus"],
                            detected_by="BrassPerformanceScanner",
                            metadata={
                                "antipattern_type": "excessive_nested_loops",
                                "nesting_level": depth,
                                "complexity_estimate": f"O(N^{depth})",
                                "operation_estimate": self._estimate_operations(depth)
                            }
                        ))
            
            for child in ast.iter_child_nodes(node):
                count_nested_loops(child, depth)
        
        count_nested_loops(tree)
        return findings
    
    def _detect_unbounded_while_loops(self, tree: ast.AST, file_path: Path) -> List[Finding]:
        """Detect potentially unbounded while loops."""
        findings = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.While):
                # Check for while True without obvious break conditions
                if (isinstance(node.test, ast.Constant) and node.test.value is True and
                    not self._has_obvious_break_conditions(node)):
                    
                    findings.append(Finding(
                        id=f"unbounded_while_{self._generate_id(file_path, node.lineno)}",
                        type=FindingType.PERFORMANCE,
                        severity=Severity.MEDIUM,
                        file_path=str(Path(file_path).resolve().relative_to(Path(self.project_path).resolve())),
                        line_number=node.lineno,
                        title="Potentially Unbounded While Loop",
                        description="while True loop without obvious break conditions. May cause infinite loop or excessive resource usage.",
                        remediation="Add clear termination conditions or timeout mechanisms",
                        confidence=PERFORMANCE_THRESHOLDS["resource_management"]["unbounded_while_loop"],
                        detected_by="BrassPerformanceScanner",
                        metadata={
                            "antipattern_type": "unbounded_while_loop",
                            "pattern": "while True"
                        }
                    ))
        
        return findings
    
    def _is_in_loop(self, node: ast.AST, tree: ast.AST) -> bool:
        """Check if a node is inside a loop structure."""
        # Simple heuristic: look for loop patterns in parent context
        # This is a simplified implementation for the current scope
        for parent in ast.walk(tree):
            if isinstance(parent, (ast.For, ast.While)):
                for child in ast.walk(parent):
                    if child is node:
                        return True
        return False
    
    def _is_legitimate_nested_loops(self, node: ast.AST) -> bool:
        """Check if nested loops are legitimate (matrix operations, etc.)."""
        # Simplified heuristic - in practice, would check for matrix access patterns
        # This reduces false positives for legitimate use cases
        return False
    
    def _has_obvious_break_conditions(self, while_node: ast.While) -> bool:
        """Check if while loop has obvious break/return conditions."""
        for node in ast.walk(while_node):
            if isinstance(node, (ast.Break, ast.Return)):
                return True
        return False
    
    def _estimate_operations(self, nesting_level: int) -> str:
        """Provide concrete operation estimates for user education."""
        base = 1000  # Assume 1000 items
        operations = base ** nesting_level
        if operations >= 1_000_000_000:
            return f"{operations / 1_000_000_000:.1f} billion"
        elif operations >= 1_000_000:
            return f"{operations / 1_000_000:.1f} million"
        else:
            return f"{operations:,}"
    
    def _filter_findings(self, findings: List[Finding]) -> List[Finding]:
        """Apply intelligent filtering to reduce noise."""
        filtered_findings = []
        
        # Group findings by category to apply limits
        findings_by_category = defaultdict(list)
        for finding in findings:
            category = finding.metadata.get("antipattern_type", finding.metadata.get("analysis_tool", "unknown"))
            findings_by_category[category].append(finding)
        
        # Apply per-category limits to avoid overwhelming output
        for category, category_findings in findings_by_category.items():
            # Sort by severity and confidence, take top findings
            sorted_findings = sorted(
                category_findings,
                key=lambda f: (_severity_rank(f.severity), f.confidence),
                reverse=True,
            )
            filtered_findings.extend(sorted_findings[:MAX_FINDINGS_PER_CATEGORY])
        
        # Final filter: remove low-confidence findings
        high_confidence_findings = [
            f for f in filtered_findings 
            if f.confidence >= 0.80  # High confidence threshold
        ]
        
        return high_confidence_findings
    
    def _generate_id(self, file_path: Path, line_number: int) -> str:
        """Generate stable, dedup-friendly ID for a finding.

        Including ``datetime.now()`` in the hash made every finding's ID
        change every run, breaking deduplication and any downstream that
        keys on ``Finding.id`` across scans.
        """
        content = f"{file_path}:{line_number}"
        return hashlib.md5(content.encode()).hexdigest()[:8]

    def _build_syntax_error_finding(self, file_path: Path, exc: SyntaxError) -> Finding:
        """Build a critical CODE_QUALITY Finding for an unparseable Python file.

        Same shape as PhantomAICodeScanner's syntax-error finding so the
        AI consumer sees consistent signal regardless of which scanner
        flagged the file first. Identical (file_path, line_number) across
        scanners means future dedup logic can collapse them by key
        without touching the title/severity contract.
        """
        line_no = exc.lineno or 1
        try:
            relative_path = str(file_path.resolve().relative_to(self.project_path.resolve()))
        except ValueError:
            relative_path = str(file_path)

        # Credential-safe snippet handling. exc.text is the offending source
        # line; for syntax errors caused by an UNTERMINATED string literal
        # (e.g. `AWS_SECRET = "wJalrXUtnFEMI/...`), that line contains the
        # raw credential. CODE_QUALITY findings are not (today) routed
        # through sanitize_finding_for_serialization, so we redact at the
        # source: any quoted-literal-or-likely-credential payload is replaced
        # with a placeholder before the Finding is built.
        code_snippet = _redact_potential_credential(exc.text) if exc.text else ""

        # Strip exc text from the human-readable description. CPython's
        # SyntaxError.msg is the diagnostic ("invalid syntax" /
        # "unterminated string literal (detected at line N)"); it does NOT
        # contain the source line. str(exc) on some CPython versions
        # appends a repr of exc.text — never include that.
        msg = exc.msg or "unknown syntax error"

        return Finding(
            id=f"perf_syntax_{self._generate_id(file_path, line_no)}",
            type=FindingType.CODE_QUALITY,
            severity=Severity.CRITICAL,
            file_path=relative_path,
            line_number=line_no,
            title="Syntax Error in AI-Generated Code",
            description=f"File contains syntax errors that prevent execution: {msg}",
            remediation="Fix syntax errors to ensure code can be executed",
            confidence=0.95,
            impact_score=0.9,
            detected_by="BrassPerformanceScanner",
            code_snippet=code_snippet,
            metadata={
                # Keep the diagnostic message only; do NOT include str(exc)
                # which can embed the offending source line on some CPython
                # versions (credential leak via metadata).
                "syntax_error_msg": msg,
                "syntax_error_column": exc.offset if exc.offset is not None else None,
                "skip_reason": "syntax_error",
                # Distinct category so _filter_findings groups these in
                # their own bucket; otherwise they fall into "unknown"
                # with anything else missing the standard metadata keys
                # and risk being capped at MAX_FINDINGS_PER_CATEGORY=20.
                "antipattern_type": "syntax_error",
            },
        )
    
    def _add_findings_with_bounds_check(self, findings_list: List[Finding], new_findings: List[Finding], source: str) -> bool:
        """
        Add new findings with the per-scanner memory cap, but never drop
        a CRITICAL finding to enforce it.

        Cap (``MAX_FINDINGS_PER_SCANNER`` = 1000) exists to prevent memory
        exhaustion from a noisy scanner on a pathological repo — it's
        not meant to discard ship-blocking signal. CRITICAL findings
        bypass the cap entirely and are appended unconditionally;
        non-CRITICAL findings get the original cap behavior.

        Return value semantics:
          True  — caller's per-file loop should continue. We added at
                  least the CRITICALs from this batch; later files may
                  still produce CRITICALs the customer needs to see.
          False — cap is full AND no CRITICALs came through; caller may
                  break the loop as a cost optimization. Same return
                  value the original implementation used for cap-full.
        """
        if not new_findings:
            return True

        # CRITICAL findings are cap-exempt. Rare in practice; never drop.
        critical = [f for f in new_findings if f.severity == Severity.CRITICAL]
        non_critical = [f for f in new_findings if f.severity != Severity.CRITICAL]

        if critical:
            findings_list.extend(critical)
            logger.debug(
                f"Added {len(critical)} CRITICAL {source} finding(s) "
                f"(cap-exempt; total: {len(findings_list)})"
            )

        if not non_critical:
            return True

        remaining_capacity = MAX_FINDINGS_PER_SCANNER - len(findings_list)
        if remaining_capacity <= 0:
            logger.info(
                f"Maximum findings limit ({MAX_FINDINGS_PER_SCANNER}) reached. "
                f"Skipping {len(non_critical)} non-critical {source} findings."
            )
            # If we accepted any CRITICAL in this batch, signal "keep going" so
            # the per-file loop can collect CRITICALs from later files too.
            return bool(critical)

        if len(non_critical) <= remaining_capacity:
            findings_list.extend(non_critical)
            logger.debug(
                f"Added {len(non_critical)} {source} findings (total: {len(findings_list)})"
            )
            return True

        # Partial fit on non-critical: sort by severity then confidence,
        # take what fits, log the drop count.
        sorted_findings = sorted(
            non_critical,
            key=lambda f: (_severity_rank(f.severity), f.confidence),
            reverse=True,
        )
        findings_to_add = sorted_findings[:remaining_capacity]
        findings_list.extend(findings_to_add)
        skipped_count = len(non_critical) - len(findings_to_add)
        logger.info(
            f"Maximum findings limit ({MAX_FINDINGS_PER_SCANNER}) reached. "
            f"Added {len(findings_to_add)} {source} findings, "
            f"skipped {skipped_count} lower-priority findings."
        )
        # Mirror the cap-full branch's CRITICAL-aware return value: if any
        # CRITICALs in THIS batch were accepted (line ~1322), signal "keep
        # going" so the caller's per-file loop doesn't break before later
        # files' CRITICALs are processed. Bug Scanner caught this 2026-05-19
        # — the partial-fit branch was unconditionally returning False,
        # contradicting both the docstring contract and the parallel
        # cap-full branch's logic.
        return bool(critical)

    def cleanup(self):
        """Clean up resources used by Phase 2 integrations."""
        if self.pyspy_integration:
            self.pyspy_integration.cleanup()
    
    def __del__(self):
        """Ensure cleanup on object destruction."""
        try:
            self.cleanup()
        except Exception as e:
            logger.warning(f"Error during BrassPerformanceScanner cleanup: {e}")