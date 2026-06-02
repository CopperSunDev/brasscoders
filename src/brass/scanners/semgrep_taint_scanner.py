"""
Semgrep-OSS taint scanner.

Capability 3 of the algorithmic plan: interprocedural-ish taint analysis
via the Semgrep OSS engine with brass's bundled YAML rule pack
(`mode: taint`). ~150MB pip install, no JVM. Emits Findings with
`metadata.taint_kind` for the downstream ranker.

Soft-fails when `semgrep` is missing on PATH (one-line warning, empty
findings list, scan continues).
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import hashlib
from pathlib import Path
from typing import List, Optional, Set

from brass.core.file_classifier import FileClassifier
from brass.core.path_safety import is_within
from brass.models.finding import Finding, FindingType, Severity

logger = logging.getLogger(__name__)

SEMGREP_BINARY = "semgrep"
SCAN_TIMEOUT_SECONDS = 300
MAX_OUTPUT_BYTES = 25 * 1024 * 1024  # 25MB JSON ceiling

# v1.143.0 (Nov 2025) made Multicore OCaml shared-memory parallelism the
# default. Below this we still work, but ~3× slower on large repos.
MIN_RECOMMENDED_SEMGREP_VERSION = "1.143.0"

# Module-level memo so the `semgrep --version` probe runs at most once per
# Python process per binary path. Without this, a daemon / test harness /
# batch-of-projects caller that constructs multiple SemgrepTaintScanner
# instances pays ~0.5-1s of OCaml startup per scanner. Keyed by the
# resolved binary path so a customer switching semgrep installs mid-process
# re-probes correctly.
_VERSION_PROBE_CACHE: Set[str] = set()

# Match a version-shaped token (e.g. "1.143.0", "1.143.0rc1") anywhere in
# the captured stdout — semgrep may print a setup line or two before the
# version itself on first-run / non-cached configs.
_VERSION_TOKEN_RE = re.compile(r"\b(\d+\.\d+(?:\.\d+)?(?:[A-Za-z][\w.]*)?)\b")


def _extract_version_token(stdout: str) -> Optional[str]:
    """Find the first version-shaped token in `stdout`, or None.

    Tolerates pre-version chatter from older semgrep builds. Returns None
    rather than raising on empty / non-matching input so the caller's
    fail-open path can short-circuit cleanly.
    """
    if not stdout:
        return None
    match = _VERSION_TOKEN_RE.search(stdout)
    return match.group(1) if match else None

# Map rule-metadata `brass_kind` (or fallback CWE) to severity. Pattern-only
# findings of the same category sit at HIGH; taint-confirmed findings get
# one rung higher because they carry a reaching dataflow.
KIND_SEVERITY = {
    "sql_injection": Severity.CRITICAL,
    "command_injection": Severity.CRITICAL,
    "ssrf": Severity.HIGH,
    "path_traversal": Severity.HIGH,
    "xss": Severity.HIGH,
    "deserialization": Severity.HIGH,
}


class SemgrepTaintScanner:
    """Run semgrep taint rules and emit Findings."""

    def __init__(self, project_path: str, file_index=None, since_commit: Optional[str] = None):
        self.project_path = Path(project_path).resolve()
        self.file_classifier = FileClassifier(str(self.project_path))
        # Shared file enumeration cache. Optional — when None, the
        # scanner falls back to its own rglob walk (slower but still
        # correct). The CLI orchestrator injects a populated FileIndex
        # at scan time.
        self.file_index = file_index
        # Incremental mode: when set, only scan files changed since this
        # git commit (compared against HEAD). The CLI surfaces this via
        # the --since-commit flag (Perf #4). Falls back to full scan if
        # not a git repo, no commit found, or the diff yields zero files.
        self.since_commit = since_commit
        # Rules ship with the package under src/brass/data/semgrep_rules/.
        self.rules_dir = Path(__file__).parent.parent / "data" / "semgrep_rules"
        self._available: Optional[bool] = None

    # ------------------------------------------------------------------ entry

    def scan(self) -> List[Finding]:
        if not self._is_available():
            return []
        if not self.rules_dir.is_dir():
            logger.warning("Semgrep rules dir not found: %s", self.rules_dir)
            return []
        try:
            return self._run_semgrep()
        except subprocess.TimeoutExpired:
            logger.warning("Semgrep scan timed out after %ds", SCAN_TIMEOUT_SECONDS)
            return []
        except Exception as exc:
            logger.warning("Semgrep scan failed: %s", exc)
            return []

    # -------------------------------------------------------------- availability

    def _is_available(self) -> bool:
        if self._available is not None:
            return self._available
        path = shutil.which(SEMGREP_BINARY)
        if not path:
            logger.warning(
                "semgrep not found on PATH. Skipping taint scan. "
                "Install with: pip install 'semgrep>=%s'",
                MIN_RECOMMENDED_SEMGREP_VERSION,
            )
            self._available = False
            return False
        # Set _available BEFORE the probe so any failure inside _check_version
        # (which is supposed to fail open) doesn't leave the cache unset and
        # force a re-probe on the next call.
        self._available = True
        self._check_version(path)
        return True

    def _check_version(self, path: str) -> None:
        """Probe semgrep --version and warn if below the multicore default.

        Fails open on any error — version detection is informational only.
        The probe is module-level memoized (`_VERSION_PROBE_CACHE`) so it
        runs at most once per Python process per binary path.
        """
        if path in _VERSION_PROBE_CACHE:
            return
        _VERSION_PROBE_CACHE.add(path)
        try:
            result = subprocess.run(
                [SEMGREP_BINARY, "--version"],
                capture_output=True, text=True, timeout=10,
                env=self._sandboxed_env(),
            )
            if result.returncode != 0:
                return
            # Cap stdout length defensively; real semgrep --version is <50
            # bytes. Some older semgrep versions emit setup chatter on first
            # invocation before the version line, so scan for the first
            # version-shaped token rather than blindly taking split()[0].
            stdout = result.stdout[:4096]
            version = _extract_version_token(stdout)
            if version is None:
                return
            if not self._version_at_least(version, MIN_RECOMMENDED_SEMGREP_VERSION):
                logger.warning(
                    "semgrep %s detected; >=%s recommended for multicore "
                    "(~3× faster on large repos). Upgrade: pip install -U semgrep",
                    version, MIN_RECOMMENDED_SEMGREP_VERSION,
                )
        except Exception as exc:
            # Fail open. Version detection is informational; nothing here
            # should kill a scan.
            logger.debug("semgrep version probe failed: %s", exc)

    @staticmethod
    def _version_at_least(version: str, target: str) -> bool:
        """Tuple-compare two 'X.Y.Z' strings. Pre-release suffixes (rc/post/
        dev/alpha/beta) are stripped from each part before int conversion,
        so '1.143.0rc1' parses as (1, 143, 0). Fails open on parse error."""
        def parts(v):
            out = []
            for segment in v.split('.')[:3]:
                m = re.match(r'\d+', segment)
                if not m:
                    raise ValueError(f"no leading digits in segment {segment!r}")
                out.append(int(m.group(0)))
            return tuple(out)
        try:
            return parts(version) >= parts(target)
        except (ValueError, IndexError):
            return True

    # -------------------------------------------------------------- execution

    def _run_semgrep(self) -> List[Finding]:
        # Enumerate target files ourselves. Semgrep's directory-mode discovery
        # quietly returns "0 files" when the target dir isn't a Git repo,
        # which silently breaks scans on the materialized fixture project and
        # any other non-Git tree. Passing explicit files sidesteps it and
        # keeps targets aligned with the rest of the BrassCoders pipeline's
        # FileClassifier exclusions.
        targets = self._discover_python_targets()
        if not targets:
            return []

        # Perf #4: incremental mode. When since_commit is set, intersect
        # the discovered targets with files changed in the working tree
        # since that commit. Empty intersection → no files to scan.
        if self.since_commit:
            changed = self._files_changed_since(self.since_commit)
            if changed is None:
                # WARNING rather than INFO: a CI job that asked for
                # incremental mode and silently got a full scan instead
                # will be slower than expected. Worth surfacing.
                logger.warning(
                    "Semgrep: --since-commit set but git diff failed; "
                    "falling back to full scan",
                )
            elif not changed:
                logger.info("Semgrep: no files changed since %s; skipping scan", self.since_commit)
                return []
            else:
                before = len(targets)
                targets = [t for t in targets if t in changed]
                logger.info(
                    "Semgrep: incremental mode reduced targets %d → %d (since %s)",
                    before, len(targets), self.since_commit,
                )
                if not targets:
                    return []
        cmd = [
            SEMGREP_BINARY,
            "scan",
            "--config", str(self.rules_dir),
            "--json",
            "--quiet",
            "--no-git-ignore",
            "--metrics=off",
            "--disable-version-check",
            # Bound semgrep's internal parallelism to match brass's
            # --max-workers default of 2. Without this, semgrep auto-picks
            # -j cpu_count and contends with brass's ThreadPoolExecutor
            # running other scanners concurrently (CPU-pressure feedback,
            # 2026-05-14).
            "-j", "2",
            # End-of-options sentinel: protects against a target file whose
            # name begins with `-` from being parsed as a flag by semgrep's
            # argparse-style CLI. Edge case but cheap to defend against.
            "--",
            *[str(t) for t in targets],
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT_SECONDS,
            env=self._sandboxed_env(),
            cwd=str(self.project_path),
        )
        # Semgrep uses non-zero exit codes for findings-present (1) and for
        # actual errors (2+). Trust the JSON if it parses; only warn on hard
        # error codes that also produce no parsable output.
        if len(result.stdout) > MAX_OUTPUT_BYTES:
            logger.warning(
                "Semgrep output too large (%d bytes); discarding", len(result.stdout)
            )
            return []
        try:
            payload = json.loads(result.stdout) if result.stdout else {}
        except json.JSONDecodeError as exc:
            logger.warning(
                "Semgrep produced non-JSON (rc=%s): %s; stderr=%s",
                result.returncode, exc, result.stderr[:400],
            )
            return []
        rows = payload.get("results") or []
        out: List[Finding] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            finding = self._row_to_finding(row)
            if finding is not None:
                out.append(finding)
        return out

    # -------------------------------------------------------------- conversion

    def _row_to_finding(self, row: dict) -> Optional[Finding]:
        path_raw = str(row.get("path") or "")
        rel_path, in_project = self._relativize(path_raw)
        if not in_project:
            return None
        # Exclude files the rest of the pipeline already filters (build_output,
        # virtualenvs, etc.). Keeps semgrep findings in sync with the file
        # role partition the benchmark surfaces.
        if self.file_classifier.should_exclude_from_analysis(rel_path):
            return None

        start = row.get("start") or {}
        line_number = _coerce_int(start.get("line"))

        extra = row.get("extra") or {}
        meta = extra.get("metadata") or {}
        kind = str(meta.get("brass_kind") or _kind_from_cwe(meta.get("cwe")) or "taint")
        severity = KIND_SEVERITY.get(kind, Severity.HIGH)

        message = str(extra.get("message") or row.get("check_id") or "Tainted dataflow")
        check_id = str(row.get("check_id") or "semgrep")

        # Build a 2-step path: source-as-best-effort → sink.
        # Semgrep's dataflow_trace can be richer, but isn't always populated
        # for intraprocedural cases; we degrade gracefully.
        path_steps = [{
            "file": rel_path,
            "line": line_number,
            "function": meta.get("function"),
        }]
        trace = extra.get("dataflow_trace")
        if isinstance(trace, dict):
            taint_source = trace.get("taint_source")
            if isinstance(taint_source, dict):
                src_loc = taint_source.get("location") or {}
                src_path, _ = self._relativize(str(src_loc.get("path") or ""))
                path_steps.insert(0, {
                    "file": src_path,
                    "line": _coerce_int(src_loc.get("start", {}).get("line")),
                    "function": None,
                })

        identity = f"semgrep|{kind}|{rel_path}|{line_number}|{check_id}".encode("utf-8")
        ident_hash = hashlib.sha256(identity).hexdigest()[:12]
        return Finding(
            id=f"semgrep-{kind}-{ident_hash}",
            type=FindingType.SECURITY,
            severity=severity,
            file_path=rel_path,
            line_number=line_number,
            title=f"Tainted dataflow: {kind.replace('_', ' ')}",
            description=message,
            confidence=0.85,
            impact_score=0.85,
            detected_by="SemgrepTaintScanner",
            remediation=(
                "Validate or escape tainted input before it reaches the sink, "
                "or parameterize the call (prepared statements / argument "
                "lists instead of shell strings)."
            ),
            metadata={
                "taint_kind": kind,
                "taint_path": path_steps,
                "rule_id": check_id,
            },
        )

    # File extensions semgrep can analyse with our rule pack (python + js/ts).
    _TARGET_EXTENSIONS = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")

    def _discover_python_targets(self) -> List[Path]:
        # If a shared FileIndex was injected by the caller, use it
        # (saves the redundant tree walk). Otherwise fall back to the
        # per-scanner rglob path so the scanner still works standalone
        # (e.g. unit tests, ad-hoc invocation).
        if self.file_index is not None:
            return self.file_index.files_with_ext(*self._TARGET_EXTENSIONS)
        targets: List[Path] = []
        for ext in self._TARGET_EXTENSIONS:
            targets.extend(self._discover_by_ext(ext))
        return targets

    def _files_changed_since(self, commit: str) -> Optional[set]:
        """Return a set of absolute Paths changed since `commit`, or None
        if git is unavailable / the diff failed.

        Uses `git diff --name-only <commit>...HEAD` (three-dot range) so
        merge bases are computed correctly when scanning a branch.

        Paths are joined to `self.project_path` *without* calling
        `.resolve()`. Resolving here would expand any intermediate
        symlinks and break set-membership comparison against targets
        coming from `FileIndex` (which deliberately uses
        `os.walk(followlinks=False)` and never resolves). The two paths
        must be produced by identical join semantics or the intersection
        silently drops legitimate changed files on any tree containing
        a symlink.
        """
        try:
            result = subprocess.run(
                ["git", "diff", "--name-only", f"{commit}...HEAD"],
                capture_output=True,
                text=True,
                timeout=15,
                cwd=str(self.project_path),
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            logger.warning("git diff failed: %s", exc)
            return None
        if result.returncode != 0:
            logger.warning(
                "git diff exited %s: %s", result.returncode, result.stderr[:200]
            )
            return None
        out = set()
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            out.add(self.project_path / line)
        return out

    def _discover_by_ext(self, ext: str) -> List[Path]:
        out: List[Path] = []
        for path in self.project_path.glob(f"**/*{ext}"):
            if not is_within(path, self.project_path):
                continue
            try:
                rel = str(path.relative_to(self.project_path))
            except ValueError:
                continue
            if self.file_classifier.should_exclude_from_analysis(rel):
                continue
            out.append(path)
        return out

    def _relativize(self, abs_or_rel: str) -> tuple[str, bool]:
        """Return (display_path, is_within_project)."""
        if not abs_or_rel:
            return "", False
        try:
            resolved = Path(abs_or_rel).resolve()
        except OSError:
            return abs_or_rel, False
        try:
            return str(resolved.relative_to(self.project_path)), True
        except ValueError:
            return abs_or_rel, False

    # -------------------------------------------------------------- env

    @staticmethod
    def _sandboxed_env() -> dict:
        """Allowlist env so a malicious project can't redirect semgrep."""
        keep = ("PATH", "HOME", "LANG", "LC_ALL")
        env = {k: os.environ.get(k, "") for k in keep if os.environ.get(k) is not None}
        env.setdefault("LANG", "C")
        env.setdefault("LC_ALL", "C")
        # Semgrep checks for a few of its own env knobs; silence metrics + telemetry.
        env["SEMGREP_SEND_METRICS"] = "off"
        env["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
        return env


def _kind_from_cwe(cwe) -> Optional[str]:
    """Fallback mapping from CWE id → brass_kind for rules that omit metadata."""
    if not cwe:
        return None
    if isinstance(cwe, list):
        cwe = cwe[0] if cwe else ""
    cwe = str(cwe)
    if "89" in cwe:
        return "sql_injection"
    if "78" in cwe:
        return "command_injection"
    if "918" in cwe:
        return "ssrf"
    if "22" in cwe:
        return "path_traversal"
    if "79" in cwe:
        return "xss"
    if "502" in cwe:
        return "deserialization"
    return None


def _coerce_int(value) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
