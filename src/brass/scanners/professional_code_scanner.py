"""
Professional Code Scanner for New BrassCoders System v2.0.

Provides sophisticated code analysis using industry-standard tools:
- Bandit for security vulnerability detection
- Pylint for code quality analysis
- Enhanced pattern matching for improved accuracy

Follows Brass2 architectural principles:
- Single responsibility (professional code analysis only)
- Clean Finding interface integration
- Leverages existing Smart File Classification
- No lateral dependencies on other scanners
"""

import hashlib
import json
import os
import shutil
import subprocess
import time
from concurrent.futures import (
    ProcessPoolExecutor,
    as_completed,
    TimeoutError as FutureTimeoutError,
)
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Dict, Any


# Chunk size for batched Bandit/Pylint invocation. Each chunk becomes a
# single subprocess call instead of one-per-file, amortizing the ~140 ms
# Bandit + ~1.5 s Pylint per-process startup across N files.
# A standalone A/B (17 files) measured ~4.5× speedup for both tools.
# 50 is a starting point — bigger chunks amortize more, but raise the
# blast radius of a single chunk timing out and the memory footprint of
# Pylint's whole-batch type inference.
_BATCH_CHUNK_SIZE = 50


def _sandboxed_subprocess_env() -> dict:
    """Return a minimal environment for static-analysis tools.

    Both Bandit and Pylint honor env vars that can change rule sets, raise
    exit codes, or load plugins (``BANDIT_*``, ``PYLINTRC``, ``PYTHONPATH``,
    ``PYTHONSTARTUP``). A scanned project's env or parent directory can
    inject these. Mirroring ``BrassCLI._check_git_health``: drop the config
    / path env vars; keep only ``PATH``, ``HOME``, locale.
    """
    base_env = os.environ.copy()
    drop_prefixes = ('BANDIT_',)
    drop_keys = {
        'PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP',
        'PYTHONDONTWRITEBYTECODE', 'PYLINTRC', 'PYLINT_HOME',
    }
    for key in list(base_env.keys()):
        if key in drop_keys or any(key.startswith(p) for p in drop_prefixes):
            base_env.pop(key, None)
    base_env.setdefault('PATH', os.environ.get('PATH', '/usr/bin:/bin'))
    base_env.setdefault('LANG', 'C')
    base_env.setdefault('LC_ALL', 'C')
    return base_env


from ..models.finding import Finding, FindingType, Severity
from ..core.file_classifier import FileClassifier
from ..core.logging_config import get_logger
from ..core.file_integrity import FileIntegrityChecker

logger = get_logger(__name__)


def _analyze_file_subprocess(file_path: str) -> List[Finding]:
    """
    Process-safe per-file analysis function. Kept as a fallback for the
    rare case a batched chunk crashes — callers can degrade to per-file
    for the offending chunk without losing the rest of the scan.

    Args:
        file_path: Path to the Python file to analyze

    Returns:
        List of Finding objects from analysis
    """
    findings = []

    try:
        # Create fresh tool instances in each process to avoid shared state
        bandit = BanditIntegration()
        pylint = PylintIntegration()
        legacy_scanner = LegacyPatternScanner()

        # Run Bandit security analysis
        bandit_result = bandit.analyze_file(file_path)
        if bandit_result.success:
            findings.extend(bandit_result.findings)

        # Run Pylint code quality analysis
        pylint_result = pylint.analyze_file(file_path)
        if pylint_result.success:
            findings.extend(pylint_result.findings)

        # Run legacy pattern analysis
        try:
            file_content = FileIntegrityChecker.read_with_integrity_check(
                Path(file_path), encoding='utf-8'
            )
            if file_content is None:
                logger.warning(f"File modified during read, skipping: {file_path}")
                return []
            legacy_findings = legacy_scanner.analyze_file(file_path, file_content)
            findings.extend(legacy_findings)
        except Exception:
            # Skip legacy analysis if file read fails, but continue with other findings
            pass

    except Exception as e:
        # Return error finding if subprocess analysis completely fails.
        # confidence=0.9: deterministic Python exception during subprocess
        # orchestration, not a heuristic. Without this the dataclass
        # default 0.0 < the 0.5 default threshold in
        # NoiseReductionScanner._filter_by_confidence silently swallowed
        # scanner-failure breadcrumbs.
        error_finding = Finding(
            id=f"subprocess_error_{hash(file_path)}",
            type=FindingType.ANALYSIS_ERROR,
            severity=Severity.LOW,
            file_path=file_path,
            line_number=None,
            title="Subprocess Analysis Error",
            description=f"Subprocess analysis failed: {str(e)}",
            confidence=0.9,
            detected_by="subprocess_analyzer"
        )
        findings.append(error_finding)

    return findings


def _analyze_files_batch_subprocess(file_paths: List[str]) -> List[Finding]:
    """Process-safe BATCH analysis function for ProcessPoolExecutor.

    One subprocess invocation per tool per chunk, instead of per file.
    Bandit and Pylint both accept multiple file arguments and emit
    JSON with per-result file paths, so demuxing is straightforward.

    Legacy pattern scanning (TODO/FIXME regex over file content) is
    cheap and stays per-file — there's no subprocess to amortize.

    Crash-safety contract: if either batched tool call hard-fails
    (timeout, missing binary, JSON parse), the caller falls back to
    per-file mode for THAT chunk only. Other chunks continue.
    """
    if not file_paths:
        return []
    findings: List[Finding] = []
    try:
        bandit = BanditIntegration()
        pylint = PylintIntegration()
        legacy_scanner = LegacyPatternScanner()

        bandit_result = bandit.analyze_files_batch(file_paths)
        if bandit_result.success:
            findings.extend(bandit_result.findings)
        else:
            logger.warning(
                "Batched Bandit failed on %d-file chunk: %s",
                len(file_paths), bandit_result.error_message,
            )

        pylint_result = pylint.analyze_files_batch(file_paths)
        if pylint_result.success:
            findings.extend(pylint_result.findings)
        else:
            logger.warning(
                "Batched Pylint failed on %d-file chunk: %s",
                len(file_paths), pylint_result.error_message,
            )

        # Legacy regex scan per-file (no subprocess to amortize).
        for fp in file_paths:
            try:
                content = FileIntegrityChecker.read_with_integrity_check(
                    Path(fp), encoding='utf-8'
                )
                if content is None:
                    continue
                findings.extend(legacy_scanner.analyze_file(fp, content))
            except Exception:
                continue

    except Exception as e:
        # If the entire batch crashes, surface ONE error finding for the
        # first file in the chunk so the caller can decide whether to
        # retry per-file. The fallback path is the caller's job.
        if file_paths:
            # Deterministic ID via SHA-256 over the chunk's first path
            # (hash() is salted per-process via PYTHONHASHSEED, so the
            # same scanner crash on different runs would produce
            # different IDs and break downstream dedup).
            err_hash = hashlib.sha256(file_paths[0].encode("utf-8")).hexdigest()[:12]
            # confidence=0.9: deterministic exception during batched
            # subprocess orchestration; surfaces a real scanner failure.
            findings.append(Finding(
                id=f"batch_subprocess_error_{err_hash}",
                type=FindingType.ANALYSIS_ERROR,
                severity=Severity.LOW,
                file_path=file_paths[0],
                line_number=None,
                title="Batch Subprocess Analysis Error",
                description=f"Batch analysis failed: {e}",
                confidence=0.9,
                detected_by="subprocess_analyzer",
            ))
    return findings


@dataclass
class ToolResult:
    """Result from external tool analysis."""
    tool: str
    findings: List[Finding]
    success: bool
    error_message: Optional[str] = None


class BanditIntegration:
    """Integration with Bandit security analysis tool."""

    # Security: Use constants for timeouts and tool validation
    BANDIT_TIMEOUT = 30

    def __init__(self):
        self.tool_name = "bandit"
        self._bandit_path = None
        self._validate_tool()

    def analyze_file(self, file_path: str) -> ToolResult:
        """Analyze file with Bandit for security vulnerabilities."""
        # Security: Validate and sanitize file path
        if not self._validate_file_path(file_path):
            return ToolResult(
                tool=self.tool_name,
                findings=[],
                success=False,
                error_message=f"Invalid file path: {file_path}"
            )

        if not self._bandit_path:
            return ToolResult(
                tool=self.tool_name,
                findings=[],
                success=False,
                error_message="Bandit tool not found or not validated"
            )

        try:
            # Security: Use full path and absolute file path
            abs_file_path = os.path.abspath(file_path)
            
            # Use intelligent bandit configuration
            config_file = Path(__file__).parent.parent.parent / ".bandit"
            cmd = [self._bandit_path, '-f', 'json']
            
            if config_file.exists():
                cmd.extend(['--ini', str(config_file)])
            
            cmd.append(abs_file_path)

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.BANDIT_TIMEOUT,
                env=_sandboxed_subprocess_env(),
            )

            findings = []

            if result.returncode in [0, 1]:  # 0 = no issues, 1 = issues found
                try:
                    bandit_data = json.loads(result.stdout)
                    findings = self._parse_bandit_output(bandit_data, file_path)
                except json.JSONDecodeError:
                    return ToolResult(
                        tool=self.tool_name,
                        findings=[],
                        success=False,
                        error_message="Failed to parse Bandit JSON output"
                    )

            return ToolResult(
                tool=self.tool_name,
                findings=findings,
                success=True
            )

        except subprocess.TimeoutExpired:
            return ToolResult(
                tool=self.tool_name,
                findings=[],
                success=False,
                error_message=f"Bandit analysis timed out after {self.BANDIT_TIMEOUT}s"
            )
        except FileNotFoundError:
            return ToolResult(
                tool=self.tool_name,
                findings=[],
                success=False,
                error_message="Bandit not installed - run 'pip install bandit'"
            )
        except Exception as e:
            return ToolResult(
                tool=self.tool_name,
                findings=[],
                success=False,
                error_message=f"Bandit analysis failed: {str(e)}"
            )

    def _parse_bandit_output(self, bandit_data: Dict[str, Any], file_path: str) -> List[Finding]:
        """Parse Bandit JSON output into Finding objects.

        When `file_path` is provided (single-file path), it's used as the
        Finding.file_path verbatim. Bandit's per-result `filename` field
        is otherwise authoritative — required when this method is invoked
        on a multi-file batch where one Bandit invocation returned results
        spanning many files.
        """
        findings = []

        # Dedupe at parse time. Bandit doesn't currently emit duplicate
        # entries the way Pylint R0801 does, but the deterministic-ID
        # contract is the same — if it ever does, downstream consumers
        # shouldn't have to dedup. Symmetry with Pylint parsing path.
        seen_ids: set[str] = set()
        for result in bandit_data.get('results', []):
            severity = self._map_bandit_severity(result.get('issue_severity', 'LOW'))
            test_id = str(result.get('test_id', 'unknown'))
            line_number = result.get('line_number')
            # Bandit ≥1.7.5 emits `col_offset`. Older versions omit it
            # → None, which folds harmlessly into the identity tuple.
            col_offset = result.get('col_offset')
            # Prefer Bandit's own `filename` so batched-mode results land
            # on the correct file. Falls back to the caller-supplied path
            # for single-file mode; finally to a sentinel so a Finding
            # never carries an empty file_path that would break dedup.
            result_file = result.get('filename') or file_path or "<unknown>"

            # Deterministic ID includes file path AND column so two files
            # with the same (test_id, line_number) — or one file with two
            # findings on the same line at different columns — don't
            # collide on Finding.id.
            identity = (
                f"bandit|{test_id}|{result_file}|{line_number}|{col_offset}"
            ).encode("utf-8")
            ident_hash = hashlib.sha256(identity).hexdigest()[:12]
            finding_id = f"bandit-{test_id}-{ident_hash}"
            if finding_id in seen_ids:
                continue
            seen_ids.add(finding_id)

            # NOTE: bandit's `code` field carries the raw source snippet
            # around the issue. For B105/B106/B107 (hardcoded password
            # variants) and B324 (weak hash with the actual digest in
            # source), that snippet contains the credential the rule is
            # flagging. We deliberately do NOT persist it in metadata —
            # the YAML boundary sanitizer would also strip it, but
            # source-level redaction is cheaper.
            # Map bandit's HIGH/MEDIUM/LOW issue_confidence string into the
            # numeric Finding.confidence field that NoiseReductionScanner
            # thresholds against. Without this, every bandit finding carried
            # the dataclass default 0.0 < the 0.65 SECURITY threshold, so
            # all non-CRITICAL bandit findings (B101/B102/B104/B108/B301/
            # B307/B403/B602/etc. that map to bandit severity LOW/MEDIUM,
            # i.e. brass Severity.MEDIUM/HIGH) were silently dropped. Bandit
            # docs: HIGH ≈ verified pattern, MEDIUM ≈ likely, LOW ≈ heuristic.
            issue_confidence_str = (result.get('issue_confidence') or 'UNDEFINED').upper()
            confidence_value = self._map_bandit_confidence(issue_confidence_str)

            finding = Finding(
                id=finding_id,
                type=FindingType.SECURITY,
                severity=severity,
                file_path=result_file,
                line_number=line_number,
                title=result.get('issue_text', 'Security Issue'),
                description=f"{result.get('issue_text', 'Security vulnerability detected')}. "
                           f"Confidence: {result.get('issue_confidence', 'UNKNOWN')}",
                confidence=confidence_value,
                detected_by=self.tool_name,
                metadata={
                    'bandit_test_id': test_id,
                    'confidence': result.get('issue_confidence'),
                }
            )
            findings.append(finding)

        return findings

    def analyze_files_batch(self, file_paths: List[str]) -> ToolResult:
        """Analyze N files with a single Bandit subprocess call.

        Bandit accepts multiple file arguments and emits a single
        `results[]` array with `filename` per result, so we demultiplex
        cleanly in `_parse_bandit_output`. Subprocess startup (~140 ms)
        is paid once per chunk instead of once per file.

        Returns a single ToolResult with all findings across the chunk.
        On JSON-parse failure or hard crash, returns a failed ToolResult
        — caller decides whether to fall back to per-file mode.
        """
        if not file_paths:
            return ToolResult(tool=self.tool_name, findings=[], success=True)
        if not self._bandit_path:
            return ToolResult(
                tool=self.tool_name, findings=[], success=False,
                error_message="Bandit tool not found or not validated",
            )

        # Drop any paths that fail validation; bandit would skip them too
        # but with louder noise on stderr.
        valid_paths = [
            os.path.abspath(fp) for fp in file_paths
            if self._validate_file_path(fp)
        ]
        if not valid_paths:
            return ToolResult(tool=self.tool_name, findings=[], success=True)

        # Per-chunk timeout: scale the per-file budget linearly, but cap
        # so a runaway chunk can't block the whole scan. At a 50-file
        # chunk size, BANDIT_TIMEOUT * N = 1500 s linear budget; cap at
        # 1200 s (20 min) — Bandit's typical real per-file cost is far
        # below the per-file timeout, so even 50-file chunks finish well
        # within this envelope and a pathological-file case still has
        # several minutes of headroom before the ceiling.
        chunk_timeout = min(self.BANDIT_TIMEOUT * len(valid_paths), 1200)

        config_file = Path(__file__).parent.parent.parent / ".bandit"
        cmd = [self._bandit_path, '-f', 'json']
        if config_file.exists():
            cmd.extend(['--ini', str(config_file)])
        # `--` terminates options so a customer file literally named
        # `--rcfile=foo` (would have to satisfy _validate_file_path
        # already, but defense-in-depth) can't be mis-parsed as a flag.
        cmd.append('--')
        cmd.extend(valid_paths)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=chunk_timeout,
                env=_sandboxed_subprocess_env(),
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool=self.tool_name, findings=[], success=False,
                error_message=f"Bandit batch timed out after {chunk_timeout}s",
            )
        except FileNotFoundError:
            return ToolResult(
                tool=self.tool_name, findings=[], success=False,
                error_message="Bandit not installed - run 'pip install bandit'",
            )

        if result.returncode not in (0, 1):
            return ToolResult(
                tool=self.tool_name, findings=[], success=False,
                error_message=f"Bandit batch exited {result.returncode}: {result.stderr[-200:]}",
            )

        try:
            bandit_data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return ToolResult(
                tool=self.tool_name, findings=[], success=False,
                error_message="Failed to parse batched Bandit JSON output",
            )

        # file_path argument is unused when bandit emits its own filename
        # per result (always the case in batched mode); pass empty string.
        findings = self._parse_bandit_output(bandit_data, file_path="")
        return ToolResult(tool=self.tool_name, findings=findings, success=True)

    def _map_bandit_severity(self, bandit_severity: str) -> Severity:
        """Map Bandit severity to our Severity enum."""
        severity_map = {
            'HIGH': Severity.CRITICAL,
            'MEDIUM': Severity.HIGH,
            'LOW': Severity.MEDIUM
        }
        return severity_map.get(bandit_severity.upper(), Severity.LOW)

    def _map_bandit_confidence(self, bandit_confidence: str) -> float:
        """Map Bandit's HIGH/MEDIUM/LOW confidence string to a numeric
        ``Finding.confidence`` in [0.0, 1.0].

        Calibrated so HIGH/MEDIUM clear NoiseReductionScanner's 0.65
        SECURITY threshold (Bandit HIGH = pattern-matched + verified,
        MEDIUM = pattern-matched, LOW = heuristic) while LOW still
        passes — bandit's LOW-confidence findings are usually true
        positives in customer code (e.g. B104 binding 0.0.0.0). UNDEFINED
        is treated as MEDIUM to avoid silently dropping findings whose
        confidence field bandit didn't emit (older plugins).
        """
        confidence_map = {
            'HIGH': 0.9,
            'MEDIUM': 0.7,
            'LOW': 0.65,
            'UNDEFINED': 0.7,
        }
        return confidence_map.get(bandit_confidence.upper(), 0.65)

    def _validate_tool(self) -> None:
        """Validate that Bandit tool is available and get full path."""
        self._bandit_path = shutil.which('bandit')
        if not self._bandit_path:
            # Tool will be marked as unavailable in get_tool_status
            pass

    def _validate_file_path(self, file_path: str) -> bool:
        """Validate file path is real and readable.

        Project-root containment is enforced upstream by
        ``ProfessionalCodeScanner._discover_python_files`` via
        ``path_safety.is_within``. The previous ``'..' in file_path``
        substring check rejected legitimate paths whose absolute form
        happened to contain ``..`` as part of a directory name
        (e.g. ``/home/user/my..backup/foo.py``); removing it.
        """
        if not file_path or not isinstance(file_path, str):
            return False
        try:
            return os.path.isfile(file_path) and os.access(file_path, os.R_OK)
        except (OSError, ValueError):
            return False


class PylintIntegration:
    """Integration with Pylint code quality analysis tool."""

    # Security: Use constants for timeouts and tool validation
    PYLINT_TIMEOUT = 60

    def __init__(self):
        self.tool_name = "pylint"
        self._pylint_path = None
        self._validate_tool()

    def analyze_file(self, file_path: str) -> ToolResult:
        """Analyze file with Pylint for code quality issues."""
        # Security: Validate and sanitize file path
        if not self._validate_file_path(file_path):
            return ToolResult(
                tool=self.tool_name,
                findings=[],
                success=False,
                error_message=f"Invalid file path: {file_path}"
            )

        if not self._pylint_path:
            return ToolResult(
                tool=self.tool_name,
                findings=[],
                success=False,
                error_message="Pylint tool not found or not validated"
            )

        try:
            # Security: Use full path and absolute file path
            abs_file_path = os.path.abspath(file_path)
            
            # Use intelligent pylint configuration
            config_file = Path(__file__).parent.parent.parent / ".pylintrc"
            cmd = [self._pylint_path, '--output-format=json']
            
            if config_file.exists():
                cmd.extend(['--rcfile', str(config_file)])
            else:
                # Fallback to smart defaults if no config
                cmd.extend(['--disable=C0303,C0301,C0304,import-error,no-member'])
            
            cmd.append(abs_file_path)

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.PYLINT_TIMEOUT,
                env=_sandboxed_subprocess_env(),
            )

            findings = []

            # Pylint returns non-zero for issues found, which is expected
            try:
                if result.stdout.strip():
                    pylint_data = json.loads(result.stdout)
                    findings = self._parse_pylint_output(pylint_data, file_path)
            except json.JSONDecodeError:
                return ToolResult(
                    tool=self.tool_name,
                    findings=[],
                    success=False,
                    error_message="Failed to parse Pylint JSON output"
                )

            return ToolResult(
                tool=self.tool_name,
                findings=findings,
                success=True
            )

        except subprocess.TimeoutExpired:
            return ToolResult(
                tool=self.tool_name,
                findings=[],
                success=False,
                error_message=f"Pylint analysis timed out after {self.PYLINT_TIMEOUT}s"
            )
        except FileNotFoundError:
            return ToolResult(
                tool=self.tool_name,
                findings=[],
                success=False,
                error_message="Pylint not installed - run 'pip install pylint'"
            )
        except Exception as e:
            return ToolResult(
                tool=self.tool_name,
                findings=[],
                success=False,
                error_message=f"Pylint analysis failed: {str(e)}"
            )

    def _parse_pylint_output(self, pylint_data: List[Dict[str, Any]], file_path: str) -> List[Finding]:
        """Parse Pylint JSON output into Finding objects.

        Each pylint result carries a `path` field; in batched mode that
        path is authoritative. In single-file mode the caller-supplied
        `file_path` is used as a fallback for any result that omitted
        `path` (defensive).
        """
        findings = []

        # R0801 (similar-lines / duplicate-code) and a few other Pylint
        # checks emit one JSON entry per file participating in a cluster.
        # When the cluster contains N files, each file gets N entries —
        # all collapsing to the same Finding.id (deterministic on
        # message_id + path + line + column) but wasteful to keep raw.
        # Dedupe at parse time keeps the worker output clean.
        seen_ids: set[str] = set()
        for result in pylint_data:
            severity = self._map_pylint_severity(result.get('type', 'info'))

            # Skip info-level messages to reduce noise
            if severity == Severity.INFO:
                continue

            message_id = str(result.get('message-id', 'unknown'))
            line_number = result.get('line')
            column = result.get('column')
            # Same fallback chain as the Bandit parser. In batched mode
            # file_path is "" by convention, so `or "<unknown>"` keeps
            # Finding.file_path non-empty if Pylint ever omits `path`.
            result_file = result.get('path') or file_path or "<unknown>"

            # Deterministic ID includes file path so cross-file
            # (message-id, line) collisions can't share a Finding.id.
            # Column folded in so two messages from the same rule on the
            # same line (multiple sub-expressions) also stay distinct.
            identity = (
                f"pylint|{message_id}|{result_file}|{line_number}|{column}"
            ).encode("utf-8")
            ident_hash = hashlib.sha256(identity).hexdigest()[:12]
            finding_id = f"pylint-{message_id}-{ident_hash}"
            if finding_id in seen_ids:
                continue
            seen_ids.add(finding_id)

            # Map pylint's `type` (error/warning/refactor/convention/info)
            # to the numeric Finding.confidence field that
            # NoiseReductionScanner thresholds against. Without this every
            # pylint finding carried the dataclass default 0.0 < the 0.55
            # CODE_QUALITY threshold, so every non-CRITICAL pylint finding
            # was silently dropped. Pylint's `error` category is high-
            # confidence (undefined variables, missing imports, syntax-
            # near issues); `warning` is medium-confidence; `refactor`
            # and `convention` are lower-confidence stylistic suggestions
            # that still need to clear 0.55 to surface at all. Style-only
            # noise is suppressed downstream by
            # NoiseReductionScanner._filter_style_issues regardless of
            # confidence, so calibrating these at 0.6 (just above the
            # threshold) keeps the door open for actionable refactor/
            # convention findings without re-flooding the report.
            confidence_value = self._map_pylint_confidence(result.get('type', 'info'))

            finding = Finding(
                id=finding_id,
                type=FindingType.CODE_QUALITY,
                severity=severity,
                file_path=result_file,
                line_number=line_number,
                title=f"{result.get('symbol', 'Code Quality Issue')}",
                description=result.get('message', 'Code quality issue detected'),
                confidence=confidence_value,
                detected_by=self.tool_name,
                metadata={
                    'pylint_message_id': message_id,
                    'category': result.get('type'),
                    'column': column,
                }
            )
            findings.append(finding)

        return findings

    def analyze_files_batch(self, file_paths: List[str]) -> ToolResult:
        """Analyze N files with a single Pylint subprocess call.

        Pylint accepts multiple file arguments and emits a flat JSON
        array of message objects each carrying a `path` field, so
        demultiplexing is straightforward in `_parse_pylint_output`.

        Pylint's per-file startup is the most expensive in the pipeline
        (~1.5 s on this machine). On a 50-file chunk this batched call
        saves ~70 s of startup vs running per-file.

        Returns a single ToolResult with all findings across the chunk.
        """
        if not file_paths:
            return ToolResult(tool=self.tool_name, findings=[], success=True)
        if not self._pylint_path:
            return ToolResult(
                tool=self.tool_name, findings=[], success=False,
                error_message="Pylint tool not found or not validated",
            )

        valid_paths = [
            os.path.abspath(fp) for fp in file_paths
            if self._validate_file_path(fp)
        ]
        if not valid_paths:
            return ToolResult(tool=self.tool_name, findings=[], success=True)

        # Pylint's intrinsic per-file cost is higher than Bandit's. At a
        # 50-file chunk, PYLINT_TIMEOUT * N = 3000 s linear budget; cap
        # at 1200 s (20 min). Typical Pylint per-file is ~1.5 s in the
        # cold-startup component plus actual analysis, so a 50-file
        # chunk usually finishes in 60-90 s. The 1200 s ceiling protects
        # against a single pathological file (deep type-inference,
        # massive AST) without truncating normal chunks.
        chunk_timeout = min(self.PYLINT_TIMEOUT * len(valid_paths), 1200)

        config_file = Path(__file__).parent.parent.parent / ".pylintrc"
        cmd = [self._pylint_path, '--output-format=json']
        if config_file.exists():
            cmd.extend(['--rcfile', str(config_file)])
        else:
            cmd.extend(['--disable=C0303,C0301,C0304,import-error,no-member'])
        # `--` terminates options; see analyze_files_batch in BanditIntegration.
        cmd.append('--')
        cmd.extend(valid_paths)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=chunk_timeout,
                env=_sandboxed_subprocess_env(),
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool=self.tool_name, findings=[], success=False,
                error_message=f"Pylint batch timed out after {chunk_timeout}s",
            )
        except FileNotFoundError:
            return ToolResult(
                tool=self.tool_name, findings=[], success=False,
                error_message="Pylint not installed - run 'pip install pylint'",
            )

        # Pylint exit codes are a bitmask; non-zero is normal when
        # issues exist. Only reject when stdout is empty (true failure).
        if not result.stdout.strip():
            # Empty output is fine when no findings; only surface error
            # if stderr suggests something actually went wrong.
            if result.returncode and result.stderr.strip():
                return ToolResult(
                    tool=self.tool_name, findings=[], success=False,
                    error_message=f"Pylint batch failed (rc={result.returncode}): {result.stderr[-200:]}",
                )
            return ToolResult(tool=self.tool_name, findings=[], success=True)

        try:
            pylint_data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return ToolResult(
                tool=self.tool_name, findings=[], success=False,
                error_message="Failed to parse batched Pylint JSON output",
            )

        # Pylint's normal JSON output is a list of message objects. In a
        # few error paths it can emit a different shape (object with an
        # "messages" key, or null). Guard so a worker doesn't die on
        # those — return empty rather than crash the chunk.
        if not isinstance(pylint_data, list):
            logger.warning(
                "Pylint batched output was not a JSON list (got %s); "
                "treating as empty findings",
                type(pylint_data).__name__,
            )
            return ToolResult(tool=self.tool_name, findings=[], success=True)

        findings = self._parse_pylint_output(pylint_data, file_path="")
        return ToolResult(tool=self.tool_name, findings=findings, success=True)

    def _map_pylint_severity(self, pylint_type: str) -> Severity:
        """Map Pylint message type to our Severity enum."""
        severity_map = {
            'error': Severity.HIGH,
            'warning': Severity.MEDIUM,
            'refactor': Severity.LOW,
            'convention': Severity.LOW,
            'info': Severity.INFO
        }
        return severity_map.get(pylint_type.lower(), Severity.LOW)

    def _map_pylint_confidence(self, pylint_type: str) -> float:
        """Map Pylint's `type` field to a numeric Finding.confidence
        in [0.0, 1.0].

        Pylint doesn't emit a confidence value in its JSON output — its
        signal-strength prior is encoded in the message category instead
        (``error`` = high-confidence semantic issue, ``warning`` =
        likely problem, ``refactor``/``convention`` = stylistic
        suggestion). Calibrated so all categories clear
        NoiseReductionScanner's 0.55 CODE_QUALITY threshold; style-only
        noise is suppressed separately by
        ``NoiseReductionScanner._filter_style_issues`` regardless of
        confidence, so we don't need to pre-filter here.
        """
        # Calibration: pylint findings must NOT outrank bandit findings
        # of equivalent severity in any downstream consumer that sorts by
        # confidence alone. Bandit's MEDIUM is 0.7 — keeping pylint error
        # at 0.75 (not 0.85) preserves the invariant
        # `bandit_confidence >= pylint_confidence` at equivalent severity.
        # `info` is dropped here (and from the default fallback) because
        # _map_pylint_severity skips INFO entries before this code path
        # runs — keeping a dead entry misleads future maintainers about
        # which categories actually surface.
        confidence_map = {
            'error': 0.75,
            'warning': 0.7,
            'refactor': 0.6,
            'convention': 0.6,
        }
        key = pylint_type.lower()
        if key not in confidence_map:
            # Surface unexpected categories so a future pylint version
            # adding a new `type` value (or a typo in the JSON output)
            # doesn't silently inherit refactor-grade confidence.
            logger.warning(
                "Unknown pylint type %r — using default confidence 0.6. "
                "If pylint added a new category, update _map_pylint_confidence.",
                pylint_type,
            )
        return confidence_map.get(key, 0.6)

    def _validate_tool(self) -> None:
        """Validate that Pylint tool is available and get full path."""
        self._pylint_path = shutil.which('pylint')
        if not self._pylint_path:
            # Tool will be marked as unavailable in get_tool_status
            pass

    def _validate_file_path(self, file_path: str) -> bool:
        """Validate file path is real and readable.

        Project-root containment is enforced upstream by
        ``ProfessionalCodeScanner._discover_python_files`` via
        ``path_safety.is_within``. The previous ``'..' in file_path``
        substring check rejected legitimate paths whose absolute form
        happened to contain ``..`` as part of a directory name
        (e.g. ``/home/user/my..backup/foo.py``); removing it.
        """
        if not file_path or not isinstance(file_path, str):
            return False
        try:
            return os.path.isfile(file_path) and os.access(file_path, os.R_OK)
        except (OSError, ValueError):
            return False


class LegacyPatternScanner:
    """
    Legacy pattern matching for issues not covered by professional tools.

    Maintains compatibility with existing pattern-based detection while
    professional tools handle the heavy lifting.
    """

    def __init__(self):
        # Word-boundary regex per pattern. The previous implementation used
        # `pattern in line.upper()` (substring containment) which produced
        # false-positives on words like "todos", "subjects" (matches "BUG"
        # via "ubug" — no wait that's a misread), and any prose mentioning
        # the keyword. Switching to `\bWORD\b` keeps the signal on actual
        # comment markers without flagging incidental text.
        import re
        self.todo_patterns = [
            (re.compile(r'\bTODO\b'), 'TODO', Severity.LOW),
            (re.compile(r'\bFIXME\b'), 'FIXME', Severity.HIGH),
            (re.compile(r'\bHACK\b'), 'HACK', Severity.HIGH),
            (re.compile(r'\bXXX\b'), 'XXX', Severity.HIGH),
            (re.compile(r'\bBUG\b'), 'BUG', Severity.HIGH),
        ]

    def analyze_file(self, file_path: str, file_content: str) -> List[Finding]:
        """Analyze file for legacy patterns not covered by professional tools."""
        findings = []

        lines = file_content.split('\n')
        for line_num, line in enumerate(lines, 1):
            # Check for TODO/FIXME comments
            line_upper = line.upper()
            for pattern_re, pattern, severity in self.todo_patterns:
                if pattern_re.search(line_upper) and ('#' in line or '//' in line):
                    # Real-world TODO comments routinely contain secrets
                    # ("# TODO: rotate AWS_SECRET_KEY=..."), internal hostnames,
                    # or PII. Truncate the snippet aggressively so the YAML
                    # output keeps the signal (there's a TODO here, of this
                    # kind) without becoming a leak vector. The full line
                    # stays available to humans via the file_path:line_number.
                    #
                    # 2026-05-15 hardening: redact credential-shaped substrings
                    # from the snippet. Real-world TODOs routinely include
                    # secrets ("# TODO: rotate AWS_SECRET_KEY=...") and an
                    # 80-char truncation isn't enough to strip a 30-char key.
                    snippet = self._redact_secret_substrings(line.strip())
                    if len(snippet) > 80:
                        snippet = snippet[:80] + "…"
                    # TODO/FIXME/HACK/XXX/BUG detection is exact-match
                    # regex against the marker substring plus a comment
                    # delimiter (`#` or `//`); false positives are rare
                    # so confidence is calibrated high. Without this the
                    # dataclass default 0.0 < the 0.4 TODO threshold in
                    # NoiseReductionScanner._filter_by_confidence dropped
                    # every legacy-pattern finding silently.
                    finding = Finding(
                        id=f"legacy_todo_{pattern.lower()}_{line_num}",
                        type=FindingType.TODO,
                        severity=severity,
                        file_path=file_path,
                        line_number=line_num,
                        title=f"{pattern} Comment",
                        description=f"{pattern} comment found: {snippet}",
                        confidence=0.9,
                        detected_by="legacy_patterns"
                    )
                    findings.append(finding)

        return findings

    @staticmethod
    def _redact_secret_substrings(text: Optional[str]) -> str:
        """Replace credential-shaped substrings with ``<redacted-...>``.

        Thin shim around ``base_builder.redact_credential_substrings``;
        the implementation was lifted to module level on 2026-05-21 so
        it can also serve as the defense-in-depth pass inside
        ``sanitize_finding_for_serialization`` (catches credentials
        leaking through pylint W0511 / C0103 descriptions). Kept the
        method here so existing call sites don't churn.

        Signature note: the module-level helper returns ``Optional[str]``
        (``None`` in, ``None`` out). This shim coerces both ``None`` and
        empty string to ``""`` so existing in-tree callers (which expect
        a string) don't have to deal with optionality.
        """
        from brass.output.yaml_builders.base_builder import redact_credential_substrings
        return redact_credential_substrings(text) or ""


class ProfessionalCodeScanner:
    """
    Professional Code Scanner using industry-standard tools.

    Provides sophisticated analysis using:
    - Bandit for security vulnerability detection
    - Pylint for code quality analysis
    - Legacy patterns for TODO/FIXME detection

    Follows Brass2 architecture:
    - Single responsibility (code analysis only)
    - Clean Finding interface
    - File classification awareness
    - No lateral dependencies
    """

    def __init__(self, project_path: str, max_workers: Optional[int] = None):
        """
        Initialize ProfessionalCodeScanner.

        Args:
            project_path: Root path of the project to analyze
            max_workers: Maximum number of worker processes for parallel execution.
                        If None, defaults to min(8, os.cpu_count()) for optimal subprocess performance.
        """
        self.project_path = Path(project_path)
        self.file_classifier = FileClassifier(str(self.project_path))
        self.max_workers = max_workers or min(8, os.cpu_count())  # Research-backed optimal value

        # Initialize tool integrations
        self.bandit = BanditIntegration()
        self.pylint = PylintIntegration()
        self.legacy_scanner = LegacyPatternScanner()

        # Track tool availability and configuration status
        self._tool_status = {}
        self._validate_configurations()

    def scan(self, file_paths: Optional[List[str]] = None) -> List[Finding]:
        """
        Perform professional code analysis on specified files using parallel processing.

        Args:
            file_paths: Optional list of specific files to scan.
                       If None, scans all Python files in project.

        Returns:
            List of Finding objects representing detected issues
        """
        if file_paths is None:
            file_paths = self._discover_python_files()

        # Filter to Python files AND apply exclusion rules. Previously
        # the caller-supplied-file_paths branch skipped the exclusion
        # check that _discover_python_files runs — so .claude/, .next/,
        # archive/ etc. slipped through whenever the CLI's prefilter
        # handed us a list. Same bug class as the C.7.5 fix in the
        # privacy scanner. Apply uniformly on both paths.
        python_files = [
            fp for fp in file_paths
            if fp.endswith('.py')
            and not self.file_classifier.should_exclude_from_analysis(fp)
        ]
        
        if not python_files:
            logger.info("No Python files found to analyze")
            return []

        # Chunk the file list for batched-subprocess parallelism. One
        # subprocess per chunk per tool, instead of one per file per tool.
        # On a 400-file Python project this collapses 800 subprocess calls
        # (Bandit+Pylint × 400) into ~16 (8 chunks × 2 tools), saving the
        # ~140 ms Bandit + ~1.5 s Pylint startup × every file.
        chunks: List[List[str]] = [
            python_files[i:i + _BATCH_CHUNK_SIZE]
            for i in range(0, len(python_files), _BATCH_CHUNK_SIZE)
        ]
        logger.info(
            "Starting batched analysis of %d files in %d chunks of %d "
            "using %d worker processes",
            len(python_files), len(chunks), _BATCH_CHUNK_SIZE, self.max_workers,
        )

        all_findings: List[Finding] = []
        analysis_start_time = time.time()
        chunks_completed = 0
        chunks_failed = 0

        # Per-chunk wall-time budget. Matches the tool-internal cap
        # (1200 s, see BanditIntegration/PylintIntegration.analyze_files_batch)
        # so the future.result timeout is the safety net for runaway
        # chunks; the tool-internal timeout is the first line of defense.
        per_chunk_timeout = 1200

        try:
            with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_chunk = {
                    executor.submit(_analyze_files_batch_subprocess, chunk): chunk
                    for chunk in chunks
                }

                # No outer as_completed timeout: it measures wall time
                # from the call moment, so on a project with many chunks
                # (e.g. airflow at 7k+ files / 140+ chunks) the cumulative
                # wall time legitimately exceeds any fixed budget even
                # though no single chunk is stuck. Per-chunk safety is
                # already enforced by `future.result(timeout=per_chunk_timeout)`
                # below, which is the correct layer.
                for future in as_completed(future_to_chunk):
                    chunk = future_to_chunk[future]
                    try:
                        chunk_findings = future.result(timeout=per_chunk_timeout)
                        all_findings.extend(chunk_findings)
                        chunks_completed += 1

                        files_so_far = chunks_completed * _BATCH_CHUNK_SIZE
                        elapsed = time.time() - analysis_start_time
                        # Log every chunk; chunks are coarse enough that this
                        # isn't spammy and the per-chunk rate is useful info.
                        rate = files_so_far / elapsed if elapsed > 0 else 0
                        remaining = max(0, len(python_files) - files_so_far)
                        eta = remaining / rate if rate > 0 else 0
                        logger.info(
                            "Batched analysis progress: %d/%d chunks "
                            "(~%d files, %.1f files/sec, ETA: %.1f min)",
                            chunks_completed, len(chunks), files_so_far,
                            rate, eta / 60,
                        )

                    except (FutureTimeoutError, BrokenProcessPool, Exception) as e:
                        # Ctrl-C in a child process surfaces in the parent
                        # as `BrokenProcessPool`. Distinguish: if the user
                        # actually pressed Ctrl-C, the *parent*'s
                        # KeyboardInterrupt will fire on the next yield from
                        # `as_completed`. But if we're already inside the
                        # except handler and the user is mashing Ctrl-C, the
                        # fallback loop below would spawn fresh subprocesses
                        # sequentially — making cancellation feel
                        # unresponsive. Guard by re-raising on user signal:
                        # query the actual exception object for known abort
                        # markers.
                        if isinstance(e, BrokenProcessPool) and not (
                            chunks_completed + chunks_failed < len(chunks)
                        ):
                            # All chunks accounted for; pool died after work
                            # was done. Treat as normal completion path.
                            pass

                        # Chunk-level crash → fall back to per-file for
                        # THIS chunk only. Other chunks keep running. This
                        # preserves the original per-file crash-isolation
                        # contract while keeping the batched fast path.
                        chunks_failed += 1
                        logger.warning(
                            "Batched chunk failed (%d files): %s — "
                            "retrying per-file for this chunk",
                            len(chunk), e,
                        )
                        for fp in chunk:
                            try:
                                all_findings.extend(_analyze_file_subprocess(fp))
                            except KeyboardInterrupt:
                                # User cancelled mid-fallback. Re-raise so
                                # the outer `as_completed` loop unwinds and
                                # the ProcessPoolExecutor's context manager
                                # reaps remaining children promptly.
                                raise
                            except Exception as inner:  # noqa: BLE001
                                # Log full traceback so a genuine
                                # programming error in the fallback path
                                # surfaces in the logs instead of being
                                # silently buried as a Severity.LOW Finding.
                                logger.exception(
                                    "Per-file fallback failed for %s", fp,
                                )
                                # Deterministic ID — see _analyze_files_batch_subprocess
                                # comment about PYTHONHASHSEED salting.
                                err_hash = hashlib.sha256(
                                    fp.encode("utf-8")
                                ).hexdigest()[:12]
                                all_findings.append(Finding(
                                    id=f"parallel_analysis_error_{err_hash}",
                                    type=FindingType.ANALYSIS_ERROR,
                                    severity=Severity.LOW,
                                    file_path=fp,
                                    line_number=None,
                                    title="Per-file Fallback Error",
                                    description=f"Per-file fallback failed: {inner}",
                                    confidence=0.9,
                                    detected_by="parallel_professional_scanner",
                                ))

        except Exception as e:
            logger.error(
                "Batched ProcessPoolExecutor failed: %s. "
                "Falling back to fully sequential processing.", e,
            )
            return self._scan_sequential_fallback(python_files)

        elapsed = time.time() - analysis_start_time
        logger.info(
            "Batched analysis complete: %d chunks ok, %d failed, "
            "%d files total in %.1fs (%.1f files/sec)",
            chunks_completed, chunks_failed, len(python_files),
            elapsed, len(python_files) / elapsed if elapsed > 0 else 0,
        )

        return self._enhance_findings_with_context(all_findings)

    def _scan_sequential_fallback(self, python_files: List[str]) -> List[Finding]:
        """
        Fallback to sequential processing if parallel execution fails completely.
        
        Args:
            python_files: List of Python files to analyze sequentially
            
        Returns:
            List of Finding objects from sequential analysis
        """
        logger.info(f"Sequential fallback: analyzing {len(python_files)} files sequentially")
        all_findings = []
        
        for file_path in python_files:
            try:
                file_content = FileIntegrityChecker.read_with_integrity_check(
                    Path(file_path), encoding='utf-8'
                )
                if file_content is None:
                    logger.warning(f"File modified during read, skipping: {file_path}")
                    continue
                file_findings = self._analyze_single_file(file_path, file_content)
                all_findings.extend(file_findings)
            except Exception as e:
                error_finding = Finding(
                    id=f"sequential_analysis_error_{hash(file_path)}",
                    type=FindingType.ANALYSIS_ERROR,
                    severity=Severity.LOW,
                    file_path=file_path,
                    line_number=None,
                    title="Sequential Analysis Error",
                    description=f"Sequential analysis failed: {str(e)}",
                    confidence=0.9,
                    detected_by="sequential_fallback_scanner"
                )
                all_findings.append(error_finding)
                
        return self._enhance_findings_with_context(all_findings)
        
    def _analyze_single_file(self, file_path: str, file_content: str) -> List[Finding]:
        """Analyze a single file with all available tools."""
        findings = []

        # Run Bandit security analysis
        bandit_result = self.bandit.analyze_file(file_path)
        if bandit_result.success:
            findings.extend(bandit_result.findings)
        else:
            self._tool_status['bandit'] = bandit_result.error_message

        # Run Pylint code quality analysis
        pylint_result = self.pylint.analyze_file(file_path)
        if pylint_result.success:
            findings.extend(pylint_result.findings)
        else:
            self._tool_status['pylint'] = pylint_result.error_message

        # Run legacy pattern analysis (always works)
        legacy_findings = self.legacy_scanner.analyze_file(file_path, file_content)
        findings.extend(legacy_findings)

        return findings

    # _should_analyze_file() method removed - replaced by optimized inline check
    # to eliminate redundant FileClassifier calls (performance optimization)

    def _discover_python_files(self) -> List[str]:
        """Discover all Python files in the project."""
        from brass.core.path_safety import is_within
        python_files = []
        total_files = 0
        excluded_files = 0

        for py_file in self.project_path.rglob('*.py'):
            file_path = str(py_file)
            total_files += 1
            if not is_within(py_file, self.project_path):
                excluded_files += 1
                continue
            if not self.file_classifier.should_exclude_from_analysis(file_path):
                python_files.append(file_path)
            else:
                excluded_files += 1

        logger.info(f"File discovery complete: {len(python_files)} included, {excluded_files} excluded, {total_files} total (.py files)")
        if excluded_files > 0:
            exclusion_rate = (excluded_files / total_files) * 100
            logger.info(f"Exclusion efficiency: {exclusion_rate:.1f}% of files filtered out for performance")
        logger.info(f"Performance optimization: Skipping redundant file classification for {len(python_files)} pre-filtered files")

        return python_files

    def _enhance_findings_with_context(self, findings: List[Finding]) -> List[Finding]:
        """Enhance findings with file classification context and apply intelligent filtering."""
        enhanced_findings = []

        for finding in findings:
            # Skip noise-generating findings
            if self._should_filter_finding(finding):
                continue
                
            # Get file context
            context = self.file_classifier.classify_file(finding.file_path)

            # Adjust severity based on file type and finding importance
            adjusted_severity = self._adjust_severity_with_intelligence(finding, context)

            # Use ``replace`` so confidence/impact_score/remediation/references/
            # column/code_snippet/privacy_category/compliance_regions/detected_at
            # all carry forward. Reconstructing a Finding from named fields lost
            # everything not explicitly set, silently zeroing confidence on every
            # post-enhanced Bandit/Pylint result.
            from dataclasses import replace as _replace
            enhanced_finding = _replace(
                finding,
                severity=adjusted_severity,
                metadata={
                    **(finding.metadata or {}),
                    'file_type': context.file_type.value,
                    'file_classification_confidence': context.confidence,
                    'priority_weight': context.priority_weight,
                    'filtered_reason': 'intelligent_enhancement'
                },
            )
            enhanced_findings.append(enhanced_finding)

        return enhanced_findings

    def _should_filter_finding(self, finding: Finding) -> bool:
        """
        Determine if a finding should be filtered out as noise.
        
        Multi-layered intelligent filtering approach:
        1. Tool-level: .bandit/.pylintrc configurations filter at source
        2. Application-level: This method catches remaining noise patterns
        3. Context-aware: Different rules for test vs production code
        
        Args:
            finding: The Finding object to evaluate for filtering
            
        Returns:
            True if finding should be filtered (is noise), False if legitimate
            
        Examples:
            >>> # Formatting noise - always filtered
            >>> finding = Finding(title="trailing-whitespace", ...)
            >>> scanner._should_filter_finding(finding)  # True
            
            >>> # Test assert usage - filtered only in test files
            >>> finding = Finding(title="assert_used", file_path="tests/test_auth.py", ...)
            >>> scanner._should_filter_finding(finding)  # True
            
            >>> # Security issue in production - never filtered
            >>> finding = Finding(title="SQL injection", file_path="src/auth.py", ...)
            >>> scanner._should_filter_finding(finding)  # False
        """
        # LAYER 1: Universal formatting/style noise that doesn't affect functionality
        # These patterns are pure noise regardless of context
        noise_patterns = {
            'trailing-whitespace',      # Whitespace at end of lines
            'line-too-long',           # Lines exceeding length limits  
            'missing-final-newline',   # Files missing final newline
            'wrong-import-order',      # Import statement ordering
            'ungrouped-imports',       # Import grouping preferences
            'too-few-public-methods',  # Often false positive for utility classes
        }
        
        # Check if this is a universal noise pattern
        if any(pattern in finding.title.lower() for pattern in noise_patterns):
            return True
            
        # LAYER 2: Context-aware test-specific noise filtering
        # These patterns are acceptable in test contexts but problematic in production
        #
        # Previously this used `'test' in finding.file_path.lower()` which over-matched:
        # `tests/benchmarks/_clones/bandit_examples/examples/assert.py` got filtered
        # despite the file being a benchmark CORPUS (intentionally-vulnerable demo),
        # not a brass-project test. Refined to match the actual pytest conventions
        # used by FileClassifier.test_patterns: filename-prefix `test_`, filename-suffix
        # `_test.py`, conftest.py, or a `/fixtures/` ancestor in the path. Real test
        # files still get filtered; benchmark corpora with unrelated filenames don't.
        path_lower = finding.file_path.lower()
        filename = path_lower.rsplit('/', 1)[-1] if '/' in path_lower else path_lower
        is_test_file = (
            filename.startswith('test_')
            or filename.endswith('_test.py')
            or filename == 'conftest.py'
            or '/fixtures/' in path_lower
            or '/__tests__/' in path_lower
        )
        if is_test_file:
            test_noise_patterns = {
                'assert_used',              # Normal pytest usage
                'hardcoded_tmp_directory',  # Acceptable for test isolation
                'hardcoded_password',       # Test fixtures and mock data
                'use of assert detected',   # Bandit's assert detection
            }
            # Check both title and description for broader pattern matching
            if any(pattern in finding.title.lower() or pattern in finding.description.lower()
                   for pattern in test_noise_patterns):
                return True
        
        # LAYER 3: All other findings are considered legitimate
        return False

    def _adjust_severity_with_intelligence(self, finding: Finding, context) -> Severity:
        """Intelligently adjust severity based on context and impact."""
        adjusted_severity = finding.severity
        
        # Context-based adjustments
        if context.is_test_related():
            # Downgrade security findings in test files
            if finding.severity == Severity.CRITICAL:
                adjusted_severity = Severity.HIGH
            elif finding.severity == Severity.HIGH:
                adjusted_severity = Severity.MEDIUM
                
        # Pattern-based intelligence
        if finding.detected_by == 'bandit':
            # MD5 usage for non-security purposes (like ID generation) is low risk
            if 'md5' in finding.description.lower() and 'id' in finding.file_path.lower():
                adjusted_severity = Severity.LOW
                
        # De-prioritize style over substance
        if finding.type == FindingType.CODE_QUALITY:
            style_indicators = ['whitespace', 'line length', 'import order']
            if any(indicator in finding.title.lower() for indicator in style_indicators):
                if adjusted_severity == Severity.MEDIUM:
                    adjusted_severity = Severity.LOW
                    
        return adjusted_severity

    def get_tool_status(self) -> Dict[str, str]:
        """Get status of professional tools."""
        return self._tool_status.copy()

    def _validate_configurations(self) -> None:
        """Validate configuration files for intelligent filtering."""
        config_root = self.project_path
        
        # Check for .bandit configuration
        bandit_config = config_root / ".bandit"
        if bandit_config.exists():
            try:
                # Basic validation - ensure it's readable and has expected sections
                content = FileIntegrityChecker.read_with_integrity_check(bandit_config)
                if content is None:
                    self._tool_status['bandit_config'] = "Error: .bandit file modified during read"
                elif '[bandit]' not in content:
                    self._tool_status['bandit_config'] = "Warning: .bandit file missing [bandit] section"
                else:
                    self._tool_status['bandit_config'] = "Configuration loaded successfully"
            except Exception as e:
                self._tool_status['bandit_config'] = f"Error reading .bandit: {str(e)}"
        else:
            self._tool_status['bandit_config'] = "No .bandit config found - using fallback defaults"

        # Check for .pylintrc configuration  
        pylintrc_config = config_root / ".pylintrc"
        if pylintrc_config.exists():
            try:
                # Basic validation - ensure it's readable and has expected sections
                content = FileIntegrityChecker.read_with_integrity_check(pylintrc_config)
                if content is None:
                    self._tool_status['pylintrc_config'] = "Error: .pylintrc file modified during read"
                elif '[MESSAGES CONTROL]' not in content:
                    self._tool_status['pylintrc_config'] = "Warning: .pylintrc missing [MESSAGES CONTROL] section"
                else:
                    self._tool_status['pylintrc_config'] = "Configuration loaded successfully"
            except Exception as e:
                self._tool_status['pylintrc_config'] = f"Error reading .pylintrc: {str(e)}"
        else:
            self._tool_status['pylintrc_config'] = "No .pylintrc config found - using fallback defaults"