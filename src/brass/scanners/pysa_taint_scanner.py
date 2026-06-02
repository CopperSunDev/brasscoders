"""
Pysa interprocedural taint scanner.

The marquee Cap 3 capability — taint analysis that follows source-to-sink
flows across function boundaries. Built on Facebook's open-source Pyre/Pysa.

Lifecycle:
  - Soft-fails when the `pyre` binary is missing (one-line warning, empty
    findings, scan continues).
  - Also soft-fails when a typeshed installation isn't found.
  - Stages the customer project into a temporary working dir with a
    minimal .pyre_configuration pointing at BrassCoders-shipped model files +
    the located typeshed.
  - Runs `pyre analyze`, parses the JSON output, and emits one Finding
    per issue Pysa surfaces.

Known limitations (v0.1):
  - Pysa requires type annotations on customer code for call dispatch to
    resolve. Un-annotated codebases will produce few findings.
  - We don't currently extract the full taint_path (call chain). The
    finding includes the sink location and the defining function but
    not every intermediate call. Future versions can post-process
    --dump-call-graph output to reconstruct paths.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import List, Optional, Tuple

from brass.core.file_classifier import FileClassifier
from brass.core.path_safety import is_within
from brass.models.finding import Finding, FindingType, Severity

logger = logging.getLogger(__name__)

PYRE_BINARY = "pyre"
# Pysa analyze timeout — resolved dynamically per scan based on
# Python file count. Two layers:
#
#   1. BRASS_PYSA_TIMEOUT_SECONDS (env var) — explicit customer override.
#      Used as-is when set to a positive integer.
#
#   2. File-count-based sizing — when no env override, scale the timeout
#      to project size:
#          max(600s floor, file_count * 0.5s per file, cap at 7200s)
#
#      Calibrated against:
#        - 2K-file Django scan: ~5min observed
#        - 9K-file frankenproject: ~50min observed (succeeded at 3600s budget)
#      Suggesting ~0.4-0.5s/file roughly. Using 0.5 gives margin.
#
# Why dynamic instead of a single large default? Tradeoff:
#   - Static low (600s): tight for projects above ~2K files. Customer
#     hits silent skip without knowing why.
#   - Static high (3600s): wastes time on small projects when something
#     hangs — customer waits an hour for a real failure that would
#     surface in 5 minutes.
#   - Dynamic: fast-fail on small, generous on large, no env var
#     needed for either. Customer can still override.
DEFAULT_ANALYZE_TIMEOUT_SECONDS = 600   # floor for tiny projects (pyre warmup)
DYNAMIC_TIMEOUT_PER_FILE_SECONDS = 0.5  # empirical: ~0.4-0.5s/file
DYNAMIC_TIMEOUT_CEILING_SECONDS = 7200  # 2hr — hard cap
ANALYZE_TIMEOUT_SECONDS = DEFAULT_ANALYZE_TIMEOUT_SECONDS  # backward-compat import
MAX_OUTPUT_BYTES = 25 * 1024 * 1024


def _pysa_analyze_timeout_seconds(python_file_count: Optional[int] = None) -> int:
    """Resolve the Pysa analyze timeout in seconds.

    Priority order:
      1. BRASS_PYSA_TIMEOUT_SECONDS env var (positive int) — customer override
      2. Dynamic sizing based on `python_file_count` (when provided)
      3. Static default (DEFAULT_ANALYZE_TIMEOUT_SECONDS) — last resort

    Invalid env values fall back to the next layer with a warning so a
    bad config doesn't silently nullify the timeout.
    """
    raw = os.environ.get("BRASS_PYSA_TIMEOUT_SECONDS", "").strip()
    if raw:
        try:
            value = int(raw)
            if value > 0:
                return value
            logger.warning(
                "Pysa: BRASS_PYSA_TIMEOUT_SECONDS=%d is non-positive; "
                "ignoring and using dynamic sizing.",
                value,
            )
        except ValueError:
            logger.warning(
                "Pysa: BRASS_PYSA_TIMEOUT_SECONDS=%r is not an integer; "
                "ignoring and using dynamic sizing.",
                raw,
            )
        # Fall through to dynamic sizing on bad env values.

    if python_file_count is None or python_file_count <= 0:
        # Caller didn't know the file count or it's a degenerate input.
        # Use the floor as a safe default.
        return DEFAULT_ANALYZE_TIMEOUT_SECONDS

    scaled = int(python_file_count * DYNAMIC_TIMEOUT_PER_FILE_SECONDS)
    return max(
        DEFAULT_ANALYZE_TIMEOUT_SECONDS,
        min(DYNAMIC_TIMEOUT_CEILING_SECONDS, scaled),
    )

# Hard-skip Pysa above this Python-file count to prevent OOM SIGKILL
# on big monorepos. Rationale: on a 2,821-file Django scan brass peaks
# at 1.75 GB RSS, dominated by Pysa's OCaml shared-memory heap (call
# graph + taint forest). Linear extrapolation puts a 5k-file project
# at ~3 GB; super-linear behavior on the call-graph (e.g., n·log n)
# could push 5-6 GB before SIGKILL on a 16 GB laptop carrying IDE +
# browser. Pyre's own docs explicitly note "your machine doesn't have
# enough memory" as the cause of `pyre analyze` hangs. The 5,000 cap
# is the conservative floor; an operator with a workstation-class
# machine can raise it via ``BRASS_PYSA_MAX_FILES=N`` or skip the
# check entirely with ``BRASS_FORCE_PYSA=1``. Source-of-truth research
# in https://pyre-check.org/docs/pysa-tips/ (Aug 2024).
_PYSA_DEFAULT_MAX_PYTHON_FILES = 5000

# Empirical per-file Pysa memory cost (measured 2026-05-19: Django
# 2,821 files / 1.75 GB peak RSS = 0.62 MB/file). Used by
# ``_pysa_max_python_files`` to derive a host-RAM-aware cap.
_PYSA_PER_FILE_BYTES = int(0.62 * 1024 * 1024)


def _truthy_env(name: str) -> bool:
    """Return True when an env var is set to any common "on" value.
    Avoids the fragile ``== '1'`` contract: ``.env`` parsers leave
    trailing whitespace, shells uppercase booleans, dotenv libraries
    accept ``true/yes/on``. Mirrors how dotenv / Pydantic resolve
    boolean flags so user expectations carry over."""
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _detect_total_ram_bytes() -> Optional[int]:
    """Best-effort total physical RAM in bytes via POSIX ``sysconf``.
    Returns ``None`` on platforms where the detection fails (Windows
    without psutil, embedded environments, restricted sandboxes).
    Caller falls back to the conservative default threshold.
    """
    try:
        page_size = os.sysconf("SC_PAGESIZE")
        page_count = os.sysconf("SC_PHYS_PAGES")
    except (ValueError, OSError, AttributeError):
        return None
    if page_size > 0 and page_count > 0:
        return page_size * page_count
    return None


def _pysa_max_python_files() -> int:
    """Threshold for the OOM guardrail.

    Resolution order:
      1. ``BRASS_PYSA_MAX_FILES=N`` env override (positive integer).
      2. Host-RAM-aware computed cap. Reserves ~75% for OS / IDE /
         browser and allocates the rest to brass at the empirical
         0.62 MB-per-file Pysa cost. Floor at
         ``_PYSA_DEFAULT_MAX_PYTHON_FILES`` so an 8 GB laptop
         doesn't get a tighter cap than the validated default.
         Result on common configurations:
           - 16 GB laptop → ~6,400 files (was hard-coded 5,000)
           - 32 GB workstation → ~13,000 files
           - 64 GB workstation → ~26,000 files
      3. ``_PYSA_DEFAULT_MAX_PYTHON_FILES`` (5,000) when RAM
         detection fails (Windows, sandboxes).

    Malformed env values fall back to the auto-detect path so a
    typo can't silently disable the safety check.
    """
    raw = os.environ.get("BRASS_PYSA_MAX_FILES", "").strip()
    if raw:
        try:
            value = int(raw)
            if value > 0:
                return value
        except ValueError:
            logger.warning(
                "BRASS_PYSA_MAX_FILES=%r is not an integer; falling "
                "back to auto-detected cap.",
                raw,
            )
        # Fall through to auto-detect on negative / zero / non-int.
    total_bytes = _detect_total_ram_bytes()
    if total_bytes is None:
        return _PYSA_DEFAULT_MAX_PYTHON_FILES
    usable_bytes = total_bytes // 4  # 25% headroom for brass
    computed = int(usable_bytes // _PYSA_PER_FILE_BYTES)
    # Never go below the validated default — keeps small-RAM hosts
    # from getting a tighter cap than the floor we've already tested.
    return max(_PYSA_DEFAULT_MAX_PYTHON_FILES, computed)

# Pysa rule code → (kind, severity)
RULE_CODE_TO_KIND = {
    5001: ("sql_injection", Severity.CRITICAL),
    5002: ("command_injection", Severity.CRITICAL),
    5003: ("deserialization", Severity.CRITICAL),
    5004: ("ssrf", Severity.HIGH),
    5005: ("path_traversal", Severity.HIGH),
    5006: ("xss", Severity.HIGH),
}

# Locations to search for typeshed (in order). User can override with
# BRASS_TYPESHED env var. Without typeshed Pysa can't resolve stdlib
# calls and emits zero findings even on obvious cases.
TYPESHED_SEARCH_PATHS = (
    "/tmp/typeshed",  # BrassCoders-recommended location
    str(Path.home() / ".cache" / "brass" / "typeshed"),
    "/opt/typeshed",
)


class PysaTaintScanner:
    """Run Pysa with BrassCoders-shipped models against the customer's Python sources."""

    def __init__(self, project_path: str, file_index=None):
        self.project_path = Path(project_path).resolve()
        self.file_classifier = FileClassifier(str(self.project_path))
        # Optional shared FileIndex; falls back to per-scanner glob when None.
        self.file_index = file_index
        # Shipped models live alongside the rest of BrassCoders's data dir
        self.models_dir = Path(__file__).parent.parent / "data" / "pysa_models"
        # Minimal type stubs (.pyi) for the HTTP frameworks that
        # `third_party.pysa` models. Added to Pyre's `search_path` so
        # Pyre can resolve `flask.Request`, `django.http.HttpRequest`,
        # `sqlalchemy.text`, etc. — without those, every third-party
        # model line is silently dropped at parse time. Stub-only dirs
        # don't trigger full analysis (Pyre treats them as obscure-model
        # lookups), so they sidestep the 4× function-count explosion
        # that adding customer site-packages caused in the 2026-05-16
        # spike. See `data/pysa_stubs/` for the bundled set.
        self.stubs_dir = Path(__file__).parent.parent / "data" / "pysa_stubs"
        self._available: Optional[bool] = None
        self._typeshed_path: Optional[str] = None
        # Cached Python file count for this scan. Set by the OOM guardrail
        # check in scan(); reused by the dynamic-timeout sizing and the
        # timeout-error advice builder so we don't re-walk the project tree
        # 2-3× per scan.
        self._python_file_count: Optional[int] = None
        # Per-run status surfaced to the CLI orchestrator (loose end #8).
        # Tuple of (status, reason). status ∈ {"skipped", "errored"}. None
        # means "no signal — orchestrator should treat as ok". Reset at the
        # top of each scan() call so a successful re-run doesn't inherit a
        # stale value from the previous attempt.
        self.last_run_status: Optional[Tuple[str, str]] = None
        # Watch-mode log-spam guard: the OOM-guardrail WARNING fires
        # once per scanner instance even on a 5k+ monorepo where the
        # file count won't change between rescans. Subsequent rescans
        # downgrade to DEBUG so the log doesn't accumulate a duplicate
        # WARNING per file-system event in watch mode.
        self._oom_guardrail_warning_emitted: bool = False

    # ------------------------------------------------------------------ entry

    def scan(self) -> List[Finding]:
        # Clear stale status from a previous invocation. Watch mode and tests
        # both reuse scanner instances; without this reset a successful re-run
        # would still carry the prior skipped/errored signal.
        self.last_run_status = None
        if not self._is_available():
            # _is_available() set last_run_status with the specific reason
            # (binary missing vs typeshed missing). Don't overwrite it here.
            return []
        if not self.models_dir.is_dir():
            logger.warning("Pysa models dir not found: %s", self.models_dir)
            self.last_run_status = (
                "errored",
                f"Pysa bundled models dir not found at {self.models_dir}",
            )
            return []
        # Only run if the project contains Python — Pysa is Python-only.
        if not self._has_python_sources():
            self.last_run_status = ("skipped", "no .py files in project")
            return []
        # Hard-skip on big monorepos to prevent OOM SIGKILL. Pysa's
        # shared-memory heap is the dominant memory pressure source on
        # brass scans; above the file-count cap the risk of exceeding
        # 16 GB on a developer laptop is non-trivial. The count is a
        # snapshot taken before staging — files added between this
        # check and `_run_pysa` aren't re-counted, which is fine
        # because Pysa's own wall-time dominates.
        # Reset the cached file count at the start of every scan. The
        # scanner instance is reused across scans (watch mode) and the
        # underlying tree can change between runs.
        self._python_file_count = None

        if not _truthy_env("BRASS_FORCE_PYSA"):
            cap = _pysa_max_python_files()
            py_count = self._count_python_sources(cap)
            if py_count > cap:
                count_repr = (
                    f">{cap:,}" if py_count == cap + 1 else f"{py_count:,}"
                )
                reason = (
                    f"project has {count_repr} Python files (>{cap:,} "
                    f"cap); skipping Pysa to prevent OOM. Bandit + Semgrep + "
                    f"SecretsScanner continue to run. Set BRASS_FORCE_PYSA=1 "
                    f"to override on a machine with sufficient memory, or "
                    f"raise the cap with BRASS_PYSA_MAX_FILES=N."
                )
                # First skip emits WARNING; subsequent rescans (watch
                # mode on the same scanner instance) drop to DEBUG so
                # the log doesn't accumulate identical lines on every
                # filesystem event.
                if not self._oom_guardrail_warning_emitted:
                    logger.warning(
                        "Pysa skipped: %s Python files exceeds %d-file cap. "
                        "Set BRASS_FORCE_PYSA=1 to override.",
                        count_repr, cap,
                    )
                    self._oom_guardrail_warning_emitted = True
                else:
                    logger.debug(
                        "Pysa still skipped (file-count cap %d); see prior "
                        "WARNING for details.",
                        cap,
                    )
                self.last_run_status = ("skipped", reason)
                return []
            # OOM-guardrail check passed: py_count is the exact count
            # (it can only equal cap+1 when over-cap, which we just
            # filtered above). Cache for downstream use — dynamic
            # timeout sizing + the timeout-error advice builder both
            # need the same number, no point re-walking the tree.
            self._python_file_count = py_count
        try:
            return self._run_pysa()
        except subprocess.TimeoutExpired:
            # Surface the file count + override path so customers know
            # the scope of what got missed and how to fix it. Without
            # this context they're left with a generic "timed out"
            # message and no clue whether to bump the timeout or split
            # the scan.
            py_count = self._resolved_python_file_count()
            timeout_used = _pysa_analyze_timeout_seconds(py_count)
            advice = self._build_timeout_advice(py_count, timeout_used)
            logger.warning(advice)
            self.last_run_status = ("errored", advice)
            return []
        except Exception as exc:
            logger.warning("Pysa analysis failed: %s", exc)
            self.last_run_status = ("errored", f"Pysa analysis failed: {exc}")
            return []

    def _resolved_python_file_count(self) -> int:
        """Return the cached Python file count, falling back to a fresh
        rglob walk if the cache wasn't populated.

        The cache is populated by the OOM-guardrail check in scan().
        It's empty when `BRASS_FORCE_PYSA=1` skipped that check, or in
        unusual test paths that call _invoke_pyre_analyze without
        going through scan() first.
        """
        if self._python_file_count is not None:
            return self._python_file_count
        # Fallback: count once and cache for this scan.
        py_count = self._count_python_sources(None)
        self._python_file_count = py_count
        return py_count

    def _build_timeout_advice(self, py_count: int, timeout_used: int) -> str:
        """Build a context-aware timeout-error message.

        Three branches:
          - At the ceiling: bumping timeout further is rarely productive.
            Suggest narrowing scope (.brassignore, BRASS_PYSA_MAX_FILES).
          - At the floor + small project: timeout shouldn't have been
            tight. Likely a Pyre bug / OS pressure, not a sizing issue.
            Suggest diagnostic bump + investigation hints.
          - Normal range: suggest doubled budget.

        Surfaced from the /full-bugs review of 8fe1066: the previous
        `max(timeout_used * 2, 3600)` gave a 6× bump suggestion when
        a 500-file project timed out at the 600s floor — wrong
        diagnosis. And at the 7200s ceiling it suggested 14400 (which
        env-override accepts, but isn't the right answer at that scale).
        """
        if timeout_used >= DYNAMIC_TIMEOUT_CEILING_SECONDS:
            return (
                f"Pysa analysis timed out after {timeout_used}s "
                f"(the {DYNAMIC_TIMEOUT_CEILING_SECONDS // 3600}hr ceiling) "
                f"on {py_count:,} Python files. At this scale, bumping the "
                f"timeout further is rarely productive — the OS may be "
                f"thrashing or Pyre's call-graph analysis exploded. "
                f"Narrow the scan with .brassignore (exclude vendored / "
                f"generated dirs), or skip Pysa entirely above N files "
                f"with BRASS_PYSA_MAX_FILES=N. The env override "
                f"BRASS_PYSA_TIMEOUT_SECONDS=N bypasses the ceiling if "
                f"you're sure a longer run would complete."
            )
        if py_count > 0 and py_count < 500 and timeout_used <= DEFAULT_ANALYZE_TIMEOUT_SECONDS:
            # Small project + minimum timeout: this isn't a sizing problem.
            # Hung Pyre, OS memory pressure, or a recursive import loop.
            return (
                f"Pysa analysis timed out after {timeout_used}s on only "
                f"{py_count:,} Python files. A project this small should "
                f"complete in under {DEFAULT_ANALYZE_TIMEOUT_SECONDS}s. "
                f"Likely causes: a Pyre bug, OS memory pressure (close "
                f"other apps), or a deeply recursive import. "
                f"For diagnosis, try BRASS_PYSA_TIMEOUT_SECONDS="
                f"{timeout_used * 4} once; if Pysa still times out, "
                f"skip it for this scan with BRASS_PYSA_MAX_FILES=0 "
                f"and file an issue with .brass/brass.log attached."
            )
        suggested = max(timeout_used * 2, 3600)
        return (
            f"Pysa analysis timed out after {timeout_used}s "
            f"on {py_count:,} Python files. "
            f"To extend the timeout, set "
            f"BRASS_PYSA_TIMEOUT_SECONDS={suggested}. "
            f"Alternatively narrow the scan with .brassignore or "
            f"BRASS_PYSA_MAX_FILES=N (skip Pysa above N files)."
        )

    # -------------------------------------------------------------- availability

    def _is_available(self) -> bool:
        # Only the True result is cached. A previous False result is
        # deliberately re-checked: in watch mode the user may install
        # the missing dep mid-session (pip install pyre-check, or
        # cloning typeshed), and we want the next scan to recover
        # automatically. Re-running shutil.which + the typeshed search
        # is cheap; caching staleness would mislead.
        if self._available is True:
            return True
        path = shutil.which(PYRE_BINARY)
        if not path:
            logger.warning(
                "pyre not found on PATH. Skipping interprocedural taint scan. "
                "Install with: pip install pyre-check"
            )
            self._available = False
            self.last_run_status = (
                "skipped",
                "pyre binary not on PATH; pip install pyre-check",
            )
            return False
        typeshed = self._locate_typeshed()
        if typeshed is None:
            # Reach this branch only when auto-fetch was suppressed
            # (BRASS_OFFLINE=1 or explicit BRASS_AUTOFETCH_TYPESHED=0)
            # — otherwise _locate_typeshed clones typeshed on demand.
            offline = os.environ.get("BRASS_OFFLINE") == "1"
            reason = (
                "running in --offline mode; typeshed auto-fetch suppressed"
                if offline
                else "typeshed not found and auto-fetch disabled "
                     "(BRASS_AUTOFETCH_TYPESHED=0)"
            )
            logger.warning(
                "Pyre typeshed not found. Skipping Pysa scan: %s. "
                "Online scans auto-fetch typeshed to ~/.cache/brass/typeshed; "
                "you can also clone python/typeshed there manually or set "
                "BRASS_TYPESHED env to its path.",
                reason,
            )
            self._available = False
            self.last_run_status = (
                "skipped",
                f"typeshed not found ({reason})",
            )
            return False
        self._typeshed_path = typeshed
        self._available = True
        return True

    @staticmethod
    def _locate_typeshed() -> Optional[str]:
        # Env override wins, but still has to look like typeshed
        # (must contain a `stdlib/` subdir). Without that check the user
        # could set BRASS_TYPESHED=/etc and Pyre would try to load it
        # as a typeshed bundle.
        override = os.environ.get("BRASS_TYPESHED")
        if override:
            p = Path(override)
            if p.is_dir() and (p / "stdlib").is_dir():
                return override
        for candidate in TYPESHED_SEARCH_PATHS:
            p = Path(candidate)
            if p.is_dir() and (p / "stdlib").is_dir():
                return str(p)
        # Typeshed not found in any standard location → auto-fetch into
        # ~/.cache/brass/typeshed. This is the most common reason Pysa
        # silently skips on customer machines (eg after `brasscoders cache
        # clear --include-typeshed`).
        #
        # Auto-fetch is the default: pyre-check is a hard dependency in
        # pyproject.toml, so every BrassCoders install has Pysa enabled. If
        # typeshed is missing, the customer is missing scanner coverage
        # they opted into. Silently skipping is a degraded product.
        #
        # The ONLY thing that suppresses auto-fetch is the offline contract:
        #   - BRASS_OFFLINE=1 (set by the --offline CLI flag), OR
        #   - BRASS_AUTOFETCH_TYPESHED=0 (explicit opt-out)
        # Both bypass the network call and let Pysa skip with the
        # existing warning. Customers in air-gapped environments stay
        # offline-first; customers who explicitly wanted auto-fetch off
        # can still get that.
        #
        # Backward compat: BRASS_AUTOFETCH_TYPESHED=1 was the old
        # opt-in trigger; treat it as a no-op (default already fetches).
        offline = os.environ.get("BRASS_OFFLINE") == "1"
        explicit_off = os.environ.get("BRASS_AUTOFETCH_TYPESHED") == "0"
        if not offline and not explicit_off:
            cached = Path.home() / ".cache" / "brass" / "typeshed"
            if PysaTaintScanner._clone_typeshed(cached):
                return str(cached)
        return None

    @staticmethod
    def _clone_typeshed(target: Path) -> bool:
        """Clone python/typeshed to `target` (shallow). Returns True on
        success. Best-effort; returns False on any failure so the scanner
        can soft-fail cleanly.

        Runs git under the same sandboxed env as `pyre analyze` so a
        customer's `GIT_*` overrides (e.g. `GIT_SSH_COMMAND`,
        `GIT_CONFIG_*`) can't influence the clone.
        """
        if (target / "stdlib").is_dir():
            return True
        target.parent.mkdir(parents=True, exist_ok=True)
        logger.info("Pysa: typeshed not found; auto-fetching to %s", target)
        try:
            result = subprocess.run(
                [
                    "git", "clone", "--depth", "1",
                    "https://github.com/python/typeshed.git",
                    str(target),
                ],
                capture_output=True,
                text=True,
                timeout=120,
                env=PysaTaintScanner._sandboxed_env(),
            )
            if result.returncode != 0:
                logger.warning(
                    "typeshed auto-fetch failed (rc=%s): %s",
                    result.returncode, result.stderr[:400],
                )
                return False
            return (target / "stdlib").is_dir()
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            logger.warning("typeshed auto-fetch failed: %s", exc)
            return False

    # -------------------------------------------------------------- discovery

    def _has_python_sources(self) -> bool:
        """Cheap check — bail before staging if there's no .py to scan."""
        if self.file_index is not None:
            return bool(self.file_index.files_with_ext(".py"))
        for path in self.project_path.glob("**/*.py"):
            if not is_within(path, self.project_path):
                continue
            try:
                rel = str(path.relative_to(self.project_path))
            except ValueError:
                continue
            if self.file_classifier.should_exclude_from_analysis(rel):
                continue
            return True
        return False

    def _count_python_sources(self, early_break_at: Optional[int] = None) -> int:
        """Count of analyzable .py files. Used by the big-monorepo
        OOM guardrail in `scan()`. Matches `_has_python_sources`'s
        exclusion semantics so the count an operator sees in the
        skip message agrees with what Pysa would have processed.

        ``early_break_at`` short-circuits the walk once the running
        count exceeds N, returning ``N+1``. Useful for the guardrail:
        we only need to know whether we're over the cap, not the
        exact count, and on a 14k-file monorepo the walk itself
        becomes a measurable cost (the very case being guarded).
        """
        limit = (early_break_at + 1) if early_break_at is not None else None

        def _stop(count: int) -> bool:
            return limit is not None and count >= limit

        count = 0
        if self.file_index is not None:
            # FileIndex doesn't pre-apply our exclusion patterns; mirror
            # the rglob branch's filter so the count matches what Pysa
            # would actually have analyzed (vendored / build-output dirs
            # don't inflate the count and trip the cap on safe projects).
            for path in self.file_index.files_with_ext(".py"):
                try:
                    rel = str(Path(path).relative_to(self.project_path))
                except ValueError:
                    continue
                if self.file_classifier.should_exclude_from_analysis(rel):
                    continue
                count += 1
                if _stop(count):
                    return count
            return count
        for path in self.project_path.glob("**/*.py"):
            if not is_within(path, self.project_path):
                continue
            try:
                rel = str(path.relative_to(self.project_path))
            except ValueError:
                continue
            if self.file_classifier.should_exclude_from_analysis(rel):
                continue
            count += 1
            if _stop(count):
                return count
        return count

    # -------------------------------------------------------------- execution

    # Bump when the on-disk cache layout becomes incompatible with prior
    # BrassCoders releases. Folding this into the cache-dir hash means a schema
    # change automatically routes scans to fresh dirs without users
    # having to clear `~/.cache/brass/pysa-state/` manually.
    #
    # NOTE: bumping this leaves old `<old_hash>/` subdirs orphaned on
    # disk forever (no automatic reclamation). A future `brasscoders cache
    # clear` subcommand is the right home for that; the bump itself is
    # safe (no data loss, no correctness risk — just wasted disk).
    _CACHE_SCHEMA = "v1"

    # Filenames at the cache-root level (siblings of the per-project
    # <hash>/ dirs) used by the schema-orphan auto-reclaim pass.
    _SCHEMA_MARKER_FILENAME = ".schema"
    _GC_LOCK_FILENAME = ".gc.lock"

    # Per-entry manifest: an absolute path written into each cache dir
    # at creation time recording which project that cache belongs to.
    # `_prune_stale_entries` reads this to identify entries whose
    # source project no longer exists on disk (the common case: pytest
    # temp dirs, one-off scans of throwaway repos). Pre-manifest legacy
    # entries fall back to mtime-based detection (≥90 days unused).
    _SOURCE_PATH_FILENAME = ".source_path"

    # Stale-entry GC is gated by cache-root size — running the prune
    # pass on every scan when the cache is small wastes work for no
    # observable benefit. 200 MB picks a point where the per-entry
    # stat overhead is dwarfed by the analysis it's amortizing.
    _STALE_GC_SIZE_THRESHOLD_BYTES = 200 * 1024 * 1024

    # Legacy entries without a `.source_path` manifest — written by
    # brass versions before the 2026-05-16 auto-prune fix — fall back
    # to mtime-based detection. 90 days is long enough that an active
    # but seldom-scanned project survives (think: monorepo audited
    # quarterly) while accumulated test-suite cruft eventually clears.
    _STALE_MTIME_FALLBACK_SECONDS = 90 * 24 * 60 * 60

    # Pre-validated allowlist of bad root-override targets. If
    # BRASS_PYSA_CACHE_ROOT (raw or resolved) matches one of these, or
    # the resolved path has fewer than 3 components, we refuse to use
    # it and fall back to the default `~/.cache/brass/...`. Defense
    # against a confused CI env or accidental shell assignment.
    _CACHE_ROOT_BLOCKLIST = frozenset({
        "/", "/etc", "/var", "/usr", "/bin", "/sbin", "/lib",
        "/System", "/Library", "/private", "/tmp",
    })

    @staticmethod
    def _resolved_cache_root() -> Path:
        """Resolve where pysa-state subdirs live.

        Default: `~/.cache/brass/pysa-state/`.

        Override via `BRASS_PYSA_CACHE_ROOT` env var — useful for test
        isolation (tests redirect to `tmp_path`) and for custom CI
        setups that want the Pysa cache in a controlled location.
        Unsafe values (root `/`, system dirs, anything with fewer than
        3 path components after symlink resolution) silently fall back
        to the default — better a slow scan than `shutil.rmtree`-ing a
        system path during corruption recovery.

        We check the blocklist BOTH against the raw override string and
        the resolved path. On macOS `/etc`, `/var`, and `/tmp` symlink
        to `/private/etc`, `/private/var`, and `/private/tmp`, all
        3-component paths — without the raw check, the resolved-only
        check would let `BRASS_PYSA_CACHE_ROOT=/etc` slip through.
        """
        override = os.environ.get("BRASS_PYSA_CACHE_ROOT")
        default = Path.home() / ".cache" / "brass" / "pysa-state"
        if not override:
            return default
        # Raw-input check: catches the macOS symlink-resolve case where
        # /etc -> /private/etc (3 parts; would pass the post-resolve
        # check below). The `expanduser` step folds `~/...` into an
        # absolute string but does NOT follow symlinks.
        raw_normalized = str(Path(override).expanduser())
        if raw_normalized in PysaTaintScanner._CACHE_ROOT_BLOCKLIST:
            logger.warning(
                "BRASS_PYSA_CACHE_ROOT=%r is in the unsafe-roots blocklist; "
                "ignoring and using default",
                override,
            )
            return default
        try:
            resolved = Path(override).expanduser().resolve()
        except (OSError, ValueError):
            logger.warning(
                "BRASS_PYSA_CACHE_ROOT=%r could not be resolved; using default",
                override,
            )
            return default
        # Reject blatantly-unsafe roots that `shutil.rmtree(...,
        # ignore_errors=True)` would silently attempt during corruption
        # recovery. The `parts` check rejects `/`, `/usr`, `/bin`, etc.
        if str(resolved) in PysaTaintScanner._CACHE_ROOT_BLOCKLIST or len(resolved.parts) < 3:
            logger.warning(
                "BRASS_PYSA_CACHE_ROOT=%r resolves to an unsafe location (%s); "
                "ignoring and using default",
                override, resolved,
            )
            return default
        return resolved

    @staticmethod
    def _pysa_cache_dir(project_path: Path) -> Path:
        """Persistent per-project Pysa staging + cache dir.

        Pyre's `--use-cache` flag writes `.pyre/pysa.cache` inside the
        analyze cwd; we make that cwd persistent (keyed by *resolved*
        absolute project path) so the call graph and taint model query
        results survive across scans. Follows the same `~/.cache/brass/`
        convention as the typeshed cache (see TYPESHED_SEARCH_PATHS).

        The input path is always resolved here so callers can pass any
        Path shape (relative, trailing-slash, symlinked) and get the
        same cache dir for semantically-equal projects. Without this
        normalization a `brasscoders scan ./foo` and `brasscoders scan foo`
        would land on different cache dirs and never reuse each other.

        Cache size grows with project size (~10-300 MB per project for
        call-graph + taint signatures). Each unique scanned project
        gets its own subdir under `<root>/<hash>/`, where `<root>` is
        `~/.cache/brass/pysa-state/` by default or whatever
        `BRASS_PYSA_CACHE_ROOT` (validated, see `_resolved_cache_root`)
        points to.

        Stale dirs accumulate over time — a future `brasscoders cache clear`
        subcommand will reclaim them when it becomes a real issue.
        """
        resolved = Path(project_path).resolve()
        identity = f"{PysaTaintScanner._CACHE_SCHEMA}|{resolved}".encode("utf-8")
        digest = hashlib.sha256(identity).hexdigest()[:16]
        return PysaTaintScanner._resolved_cache_root() / digest

    @staticmethod
    def _reclaim_schema_orphans(cache_root: Path) -> int:
        """Reclaim cache subdirs orphaned by a `_CACHE_SCHEMA` bump.

        When _CACHE_SCHEMA changes (e.g. v1 → v2), every previously-cached
        project's hash key changes too — so all old <hash>/ subdirs become
        unreachable. They'd otherwise sit on disk forever (the loose-ends
        doc explicitly flagged this as a future support headache).

        Implementation: <cache_root>/.schema holds the schema version that
        produced the current contents. On scan, if .schema is missing or
        mismatched, sweep every sibling subdir + write the new value.

        Concurrency: exclusive `fcntl` lock at <cache_root>/.gc.lock.
        Two processes scanning different projects at the same time may
        both enter this method; one acquires the lock and sweeps, the
        other **blocks** until the holder releases. We deliberately do
        NOT skip-on-locked: if we did, our caller's just-about-to-happen
        per-project `mkdir(cache_root / <hash>)` could race the holder's
        mid-flight `rmtree` of cache_root contents, and our just-created
        dir could be wiped before we write into it. Blocking is the
        correct serialization point.

        Returns the number of entries reclaimed (0 in the no-bump steady
        state, which is the common case). Best-effort: OSError during the
        sweep is logged and ignored so a failure here can't block scans.
        """
        # Hardening: a misconfigured BRASS_PYSA_CACHE_ROOT could resolve
        # to a regular file or a non-Path value; .exists() returns True
        # for files, but iterdir() would NotADirectoryError. Bail cleanly
        # rather than rely on the outer scan-time exception handler.
        if cache_root is None or not isinstance(cache_root, Path):
            return 0
        if not cache_root.is_dir():
            return 0
        marker = cache_root / PysaTaintScanner._SCHEMA_MARKER_FILENAME
        try:
            previous = marker.read_text(encoding='utf-8').strip()
        except (OSError, UnicodeDecodeError):
            previous = ""
        if previous == PysaTaintScanner._CACHE_SCHEMA:
            return 0  # Common path: schema unchanged, nothing to do.

        try:
            import fcntl as _fcntl_mod  # noqa: PLC0415  Unix-only, lazy
        except ImportError:
            _fcntl_mod = None  # type: ignore[assignment]

        lock_path = cache_root / PysaTaintScanner._GC_LOCK_FILENAME
        lock_fd = None
        if _fcntl_mod is not None:
            try:
                lock_fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o644)
            except OSError:
                lock_fd = None
            if lock_fd is not None:
                try:
                    # Try non-blocking first (common: no contention).
                    _fcntl_mod.flock(lock_fd, _fcntl_mod.LOCK_EX | _fcntl_mod.LOCK_NB)
                except OSError:
                    # Holder is sweeping. Block — see method docstring
                    # for why skip-on-locked would race the caller's
                    # mkdir against the holder's rmtree.
                    try:
                        _fcntl_mod.flock(lock_fd, _fcntl_mod.LOCK_EX)
                    except OSError:
                        try:
                            os.close(lock_fd)
                        except OSError:
                            pass
                        lock_fd = None
            # Refuse to sweep unlocked on a platform where fcntl IS
            # available but acquisition failed (read-only fs, perm
            # cascade, etc.). An unlocked schema-orphan sweep would
            # rmtree every sibling cache_root entry concurrently with
            # another process's mid-flight `mkdir + write` — blast
            # radius is data loss across all projects, not just one.
            # Logged-and-skipped is safe: the next scan retries once
            # the lock is reachable.
            if lock_fd is None:
                logger.warning(
                    "schema-orphan sweep: skipped — could not acquire "
                    "exclusive lock at %s. Orphans will be reclaimed "
                    "on the next scan once the lock is available.",
                    lock_path,
                )
                return 0

        try:
            # Re-read marker under lock — another process may have done
            # the sweep between our pre-lock check and now.
            try:
                previous = marker.read_text(encoding='utf-8').strip()
            except (OSError, UnicodeDecodeError):
                previous = ""
            if previous == PysaTaintScanner._CACHE_SCHEMA:
                return 0

            removed = 0
            skip_names = {
                PysaTaintScanner._SCHEMA_MARKER_FILENAME,
                PysaTaintScanner._GC_LOCK_FILENAME,
            }
            for entry in cache_root.iterdir():
                if entry.name in skip_names:
                    continue
                try:
                    if entry.is_dir():
                        shutil.rmtree(entry, ignore_errors=False)
                    else:
                        entry.unlink()
                    removed += 1
                except OSError as exc:
                    logger.warning(
                        "schema-orphan sweep: could not remove %s: %s",
                        entry, exc,
                    )
            try:
                # write_bytes (not write_text) — defends against future
                # Windows newline-translation surprises if _CACHE_SCHEMA
                # ever becomes multi-line. Today's "v1" value is single-
                # line so the distinction is academic; the bytes form is
                # cheap insurance.
                marker.write_bytes(
                    PysaTaintScanner._CACHE_SCHEMA.encode('utf-8'),
                )
            except OSError as exc:
                logger.warning(
                    "schema-orphan sweep: could not write %s: %s",
                    marker, exc,
                )
            if removed:
                logger.info(
                    "schema-orphan sweep reclaimed %d entries from %s "
                    "(previous schema=%r, current=%r)",
                    removed, cache_root, previous or "(absent)",
                    PysaTaintScanner._CACHE_SCHEMA,
                )
            return removed
        finally:
            if lock_fd is not None and _fcntl_mod is not None:
                try:
                    _fcntl_mod.flock(lock_fd, _fcntl_mod.LOCK_UN)
                except OSError:
                    pass
                try:
                    os.close(lock_fd)
                except OSError:
                    pass

    @staticmethod
    def _prune_stale_entries(cache_root: Path) -> int:
        """Remove cache subdirs whose owning project no longer exists.

        Two detection paths:

        - **Manifest-based (preferred).** Each cache dir written by
          brass after the 2026-05-16 auto-prune fix contains a
          ``.source_path`` file holding the absolute resolved source
          dir. If ``Path(content).exists()`` returns False, the entry
          is removed.

        - **Mtime-based fallback (for legacy entries).** Pre-manifest
          entries — written by earlier brass versions or missing
          their manifest for any reason — are removed only if their
          mtime is older than ``_STALE_MTIME_FALLBACK_SECONDS``
          (default 90 days). This keeps a long-running but seldom-
          scanned project from being false-pruned while still
          eventually clearing accumulated cruft from test runs.

        Size-guarded internally: if the cache root holds less than
        ``_STALE_GC_SIZE_THRESHOLD_BYTES``, the prune pass is a no-op.
        Small caches don't accumulate enough cruft to justify the
        per-entry stat overhead.

        Acquires the same ``.gc.lock`` as ``_reclaim_schema_orphans``
        so two concurrent scans serialize cleanly; one wins the lock
        and prunes, the other blocks then runs against a freshly
        groomed root. Falls back to the racy path on platforms
        without ``fcntl`` (Windows) to match the prior pattern.

        Returns the number of entries removed (0 in the steady state).
        """
        if not cache_root.exists():
            return 0

        # Size guard: skip the full prune unless the cache is past the
        # threshold. Uses os.walk so the cost is bounded by dir-entry
        # count (cheap stat per file) and matches the size accounting
        # the CLI footer uses (st_blocks * 512 like `du -s`).
        try:
            total_bytes = 0
            for dirpath, _dirs, files in os.walk(
                cache_root, followlinks=False
            ):
                for fname in files:
                    try:
                        st = os.stat(os.path.join(dirpath, fname))
                    except OSError:
                        continue
                    # Prefer st_blocks (matches `du`) when available;
                    # Windows lacks it and falls back to st_size.
                    blocks = getattr(st, "st_blocks", None)
                    total_bytes += (
                        blocks * 512 if blocks is not None else st.st_size
                    )
            if total_bytes < PysaTaintScanner._STALE_GC_SIZE_THRESHOLD_BYTES:
                return 0
        except OSError:
            # Walk failed wholesale (permissions, vanished root, etc.).
            # Don't try to prune what we can't even size.
            return 0

        try:
            import fcntl as _fcntl_mod  # noqa: PLC0415  Unix-only, lazy
        except ImportError:
            _fcntl_mod = None  # type: ignore[assignment]

        lock_path = cache_root / PysaTaintScanner._GC_LOCK_FILENAME
        lock_fd = None
        if _fcntl_mod is not None:
            try:
                lock_fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o644)
            except OSError:
                lock_fd = None
            if lock_fd is not None:
                try:
                    _fcntl_mod.flock(lock_fd, _fcntl_mod.LOCK_EX | _fcntl_mod.LOCK_NB)
                except OSError:
                    try:
                        _fcntl_mod.flock(lock_fd, _fcntl_mod.LOCK_EX)
                    except OSError:
                        try:
                            os.close(lock_fd)
                        except OSError:
                            pass
                        lock_fd = None
            # Refuse to prune unlocked on a platform where fcntl IS
            # available but acquisition failed (read-only fs, perm
            # cascade, etc.). The blast radius of an unlocked prune
            # is a concurrent scan's cache being rmtree'd mid-write
            # — too high to accept for a best-effort GC. Logged
            # without raising so the rest of the scan proceeds.
            if lock_fd is None:
                logger.warning(
                    "stale-entry prune: skipped — could not acquire "
                    "exclusive lock at %s. Cache may grow until "
                    "the next successful prune.", lock_path,
                )
                return 0

        try:
            removed = 0
            now = time.time()
            mtime_limit = PysaTaintScanner._STALE_MTIME_FALLBACK_SECONDS
            skip_names = {
                PysaTaintScanner._SCHEMA_MARKER_FILENAME,
                PysaTaintScanner._GC_LOCK_FILENAME,
            }
            for entry in cache_root.iterdir():
                if entry.name in skip_names or not entry.is_dir():
                    continue
                manifest = entry / PysaTaintScanner._SOURCE_PATH_FILENAME
                is_stale = False
                if manifest.is_file():
                    try:
                        recorded = manifest.read_text(encoding="utf-8").strip()
                    except OSError:
                        recorded = ""
                    if not recorded:
                        # Empty / whitespace-only / truncated-write
                        # manifest: treat the same as "no manifest" and
                        # fall through to mtime-based staleness. Instant-
                        # stale here would delete healthy entries whose
                        # write crashed mid-flush (truncated to 0 bytes).
                        try:
                            age_seconds = now - entry.stat().st_mtime
                        except OSError:
                            age_seconds = 0
                        is_stale = age_seconds > mtime_limit
                    else:
                        is_stale = not Path(recorded).exists()
                else:
                    # No manifest: legacy entry. Mtime is the only
                    # signal we have. Use the directory's own mtime,
                    # not any contained file's, so a Pyre cache
                    # rewrite refreshes the staleness clock.
                    try:
                        age_seconds = now - entry.stat().st_mtime
                    except OSError:
                        age_seconds = 0  # can't stat → assume fresh
                    is_stale = age_seconds > mtime_limit
                if not is_stale:
                    continue
                try:
                    shutil.rmtree(entry, ignore_errors=False)
                    removed += 1
                except OSError as exc:
                    logger.warning(
                        "stale-entry prune: could not remove %s: %s",
                        entry, exc,
                    )
            if removed:
                logger.info(
                    "stale-entry prune reclaimed %d cache entries from %s",
                    removed, cache_root,
                )
            return removed
        finally:
            if lock_fd is not None and _fcntl_mod is not None:
                try:
                    _fcntl_mod.flock(lock_fd, _fcntl_mod.LOCK_UN)
                except OSError:
                    pass
                try:
                    os.close(lock_fd)
                except OSError:
                    pass

    _fcntl_unavailable_warned = False  # class-level: one-time Windows warning

    def _run_pysa(self) -> List[Finding]:
        # Schema-orphan reclaim: cheap no-op in the steady state; sweeps
        # unreachable subdirs only when _CACHE_SCHEMA has been bumped
        # since the cache was last written. Runs BEFORE per-project
        # staging so a fresh scan after a schema bump rebuilds cleanly.
        cache_root = self._resolved_cache_root()
        try:
            self._reclaim_schema_orphans(cache_root)
        except Exception as exc:  # noqa: BLE001 - never block scans
            logger.warning("schema-orphan sweep failed: %s", exc)

        # Stale-entry prune: clear cache dirs whose recorded source
        # project no longer exists on disk (common: pytest temp-dir
        # scans, throwaway repos). Gated on a size threshold so small
        # caches aren't churned. Same lock as schema-orphan reclaim
        # so concurrent scans serialize safely.
        try:
            if cache_root.exists():
                self._prune_stale_entries(cache_root)
        except Exception as exc:  # noqa: BLE001 - never block scans
            logger.warning("stale-entry prune failed: %s", exc)

        # Persistent staging dir so .pyre/pysa.cache survives across scans
        # (the whole point of Pysa's `--use-cache` flag). Was a tempdir;
        # the cache lived inside it and evaporated on context-manager exit.
        staging_path = self._pysa_cache_dir(self.project_path)
        try:
            staging_path.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.warning(
                "Pysa cache dir %s could not be created (%s); skipping Pysa",
                staging_path, exc,
            )
            self.last_run_status = (
                "errored",
                f"could not create Pysa cache dir at {staging_path}: {exc}",
            )
            return []

        # Config-drift invalidation: if the .pyre_configuration we're
        # about to write differs from the one that produced the existing
        # cache, the on-disk call graph may be keyed against stale
        # config (different typeshed location, different exclude
        # patterns, different models). Pyre won't notice; we have to.
        # Stamp config.sig once per scan and wipe-on-mismatch BEFORE
        # acquiring the lock — racing scans both wipe + recreate which
        # converges to the same correct outcome.
        self._invalidate_cache_on_config_change(staging_path)

        # Record the source path AFTER the config-drift invalidation:
        # that function may `rmtree(staging_path)` on input drift, and
        # writing the manifest before would lose it. (Bug observed on
        # the 2026-05-16 first re-scan after adding `search_path` to
        # .pyre_configuration — manifest was created then immediately
        # wiped, defeating Phase C's stale-entry detection.) Written
        # idempotently on every scan; the absolute resolved path is
        # the same input the cache-dir hash was derived from, so
        # rewriting is cheap and self-correcting.
        try:
            (staging_path / PysaTaintScanner._SOURCE_PATH_FILENAME).write_text(
                str(self.project_path), encoding="utf-8"
            )
        except OSError as exc:
            # Manifest write is best-effort: a missing manifest just
            # means the entry falls back to mtime-based staleness in
            # the next GC pass, which is correct for active scans.
            logger.debug(
                "Could not write source-path manifest at %s: %s",
                staging_path, exc,
            )

        # Concurrency guard: two `brasscoders scan` invocations against the
        # same project would otherwise race on `.pyre/pysa.cache`,
        # potentially producing a file that parses fine but encodes a
        # corrupted call graph (silent-wrong-answer). Acquire an
        # exclusive non-blocking lock; if held by another scan, skip
        # Pysa rather than risk wrong results. fcntl is Unix/macOS only
        # — Windows would soft-skip the locking but BrassCoders doesn't target
        # Windows for Pysa anyway (typeshed bundle assumes POSIX paths).
        lock_path = staging_path / ".lock"
        try:
            import fcntl as _fcntl_mod  # noqa: PLC0415  (Unix-only, lazy)
        except ImportError:
            _fcntl_mod = None  # type: ignore[assignment]
        if _fcntl_mod is None and not PysaTaintScanner._fcntl_unavailable_warned:
            logger.warning(
                "fcntl unavailable on this platform; Pysa cache concurrency "
                "protection disabled. Don't run two `brasscoders scan` against "
                "the same project simultaneously."
            )
            PysaTaintScanner._fcntl_unavailable_warned = True

        lock_fd = None
        if _fcntl_mod is not None:
            try:
                lock_fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o644)
            except OSError as exc:
                # Read-only filesystem, perms cascade, etc. Proceed unlocked
                # rather than crash the scan — equivalent to the Windows path.
                logger.warning(
                    "Pysa lock fd open failed (%s); proceeding without "
                    "concurrency protection",
                    exc,
                )
                lock_fd = None
            else:
                try:
                    _fcntl_mod.flock(lock_fd, _fcntl_mod.LOCK_EX | _fcntl_mod.LOCK_NB)
                except OSError:
                    os.close(lock_fd)
                    logger.warning(
                        "Pysa cache for %s is locked by another scan; skipping "
                        "Pysa for this run to avoid silent cache corruption",
                        staging_path,
                    )
                    self.last_run_status = (
                        "skipped",
                        "concurrent scan holds the cache lock; "
                        "wait for the other scan to complete",
                    )
                    return []

        try:
            findings = self._invoke_pyre_analyze(staging_path)
            if findings is None:
                # Probable cache corruption (Pyre emitted no parseable JSON).
                # Wipe the cache dir and retry once — simpler than validating
                # cache state up-front, and the wipe is cheap.
                logger.warning(
                    "Pysa produced no JSON; wiping cache dir %s and retrying once",
                    staging_path,
                )
                shutil.rmtree(staging_path, ignore_errors=True)
                staging_path.mkdir(parents=True, exist_ok=True)
                findings = self._invoke_pyre_analyze(staging_path)
                if findings is None:
                    # Retry also failed — return empty rather than crash the
                    # whole scan. The warning from the second attempt is
                    # already in the log.
                    self.last_run_status = (
                        "errored",
                        "Pyre produced non-parseable output even after wipe + "
                        "retry; check .brass/brass.log for the pyre stderr",
                    )
                    return []
            return findings
        finally:
            if lock_fd is not None and _fcntl_mod is not None:
                try:
                    _fcntl_mod.flock(lock_fd, _fcntl_mod.LOCK_UN)
                except OSError:
                    pass
                os.close(lock_fd)

    _CONFIG_SIG_FILENAME = "config.sig"

    def _current_config_signature(self) -> str:
        """Hash of the inputs that, if changed, should invalidate Pysa's
        cached call graph: the `.pyre_configuration` we'd write, plus
        the bundled-models mtime (catches BrassCoders-release model changes
        even when the config text is identical)."""
        config_payload = self._build_pyre_configuration_dict()
        try:
            models_mtime = self.models_dir.stat().st_mtime_ns
        except OSError:
            models_mtime = 0
        identity_blob = (
            json.dumps(config_payload, sort_keys=True) + f"|models:{models_mtime}"
        ).encode("utf-8")
        return hashlib.sha256(identity_blob).hexdigest()

    def _invalidate_cache_on_config_change(self, staging_path: Path) -> None:
        """Detect drift between the cached call graph's inputs and the
        current inputs. On mismatch, wipe the staging dir + recreate it,
        so the next `pyre analyze` starts from a clean call graph."""
        current_sig = self._current_config_signature()
        sig_path = staging_path / self._CONFIG_SIG_FILENAME
        try:
            previous_sig = sig_path.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeDecodeError):
            previous_sig = ""
        if previous_sig and previous_sig == current_sig:
            return  # cache is keyed against the same inputs; reuse.
        if previous_sig:
            logger.info(
                "Pysa cache inputs changed (config or models mtime); wiping %s",
                staging_path,
            )
        shutil.rmtree(staging_path, ignore_errors=True)
        staging_path.mkdir(parents=True, exist_ok=True)
        try:
            sig_path.write_text(current_sig, encoding="utf-8")
        except OSError as exc:
            # Best-effort: if the stamp can't be written, we'll just
            # re-invalidate on the next scan. Don't crash.
            logger.warning(
                "Could not write Pysa config.sig at %s (%s); cache may "
                "rebuild on every scan until this is fixed",
                sig_path, exc,
            )

    def _invoke_pyre_analyze(self, staging_path: Path) -> Optional[List[Finding]]:
        """Run `pyre analyze --no-verify --use-cache` from `staging_path`.

        Returns:
            - List[Finding] (possibly empty) on success.
            - None on non-parseable output (signals probable cache
              corruption to the caller, which can wipe + retry).
        """
        self._write_pyre_configuration(staging_path)
        # pyre picks up .pyre_configuration via cwd; --source-directory
        # CLI flag would conflict with the config's `source_directories`.
        # --no-verify: models reference modules (flask, django, sqlalchemy)
        # that customer environments may not have installed. Without
        # this flag pyre returns rc=10 and emits no JSON when any model
        # references an unavailable module. Models that don't apply
        # are silently ignored; the valid ones still bind.
        # --use-cache: persists the call graph + taint model query
        # results in `.pyre/pysa.cache` (under the staging dir, which
        # is now persistent — see _pysa_cache_dir).
        # Size the timeout to the project. Pyre's call-graph analysis
        # is super-linear; a one-size-fits-all timeout is wrong for
        # both ends — too tight on big monorepos, too generous on
        # small projects that fail fast. Use the cached file count
        # from the OOM-guardrail check (avoids a second tree walk).
        py_count = self._resolved_python_file_count()
        timeout_seconds = _pysa_analyze_timeout_seconds(py_count)
        # WARNING level (not INFO) so the line surfaces at the default
        # CLI log threshold. Pysa scans can run for 10s of minutes;
        # without this line the customer's terminal looks hung. The
        # other operationally-useful Pysa messages (typeshed not found,
        # OOM-cap skip) all use WARNING for the same reason.
        logger.warning(
            "Pysa: analyzing %d Python files with %ds timeout (%dm)",
            py_count, timeout_seconds, timeout_seconds // 60,
        )
        result = subprocess.run(
            [PYRE_BINARY, "analyze", "--no-verify", "--use-cache"],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=self._sandboxed_env(),
            cwd=str(staging_path),
        )
        if len(result.stdout) > MAX_OUTPUT_BYTES:
            logger.warning(
                "Pysa output too large (%d bytes); discarding",
                len(result.stdout),
            )
            return []
        # Pyre returns non-zero exit codes for both findings-present and
        # actual errors. Trust the JSON: parse stdout, succeed if it's
        # a JSON array, signal failure (None) otherwise.
        payload = self._extract_json_array(result.stdout)
        if payload is None:
            logger.warning(
                "Pysa produced non-JSON output (rc=%s): stderr=%s",
                result.returncode, result.stderr[:400],
            )
            return None
        return self._rows_to_findings(payload)

    def _build_pyre_configuration_dict(self) -> dict:
        """Compute the .pyre_configuration payload as a dict.

        Split from the file-write so both `_write_pyre_configuration`
        and the cache-drift signature (`_current_config_signature`) can
        operate on the same canonical payload — no risk of the hash
        ever disagreeing with what we actually write to disk.
        """
        return {
            "source_directories": [str(self.project_path)],
            "taint_models_path": [str(self.models_dir)],
            "typeshed": self._typeshed_path,
            # search_path is brass's bundled `pysa_stubs/` only. Stub-
            # only dirs let Pyre resolve `flask.Request`,
            # `django.http.HttpRequest`, `sqlalchemy.text`, etc. — so
            # brass's third_party.pysa source models actually apply —
            # without triggering the full-analysis path that adding
            # customer site-packages here would (which exploded the
            # analyzed function count by 4× in the 2026-05-16 spike).
            # Pyre treats stub-only modules as obscure-model lookups:
            # signatures available, no AST/call-graph expansion.
            "search_path": [str(self.stubs_dir)],
            # Exclude common noisy paths so Pysa doesn't spend time on them.
            # The last pattern covers BrassCoders's own internal hardening
            # fixture: `test_hardening_project/symlink_loop/` contains a
            # deliberate symlink cycle. Pyre's `--use-cache` mode walks
            # symlinks aggressively enough to hit ELOOP on it; without
            # the exclude, the entire Pysa scan aborts before producing
            # any findings. The fully-qualified pattern is tight enough
            # to avoid false-excludes on customer projects that happen to
            # contain a file named `symlink_loop_handler.py` or similar.
            "exclude": [
                r".*\.brass/.*",
                r".*node_modules/.*",
                r".*\.venv/.*",
                r".*__pycache__/.*",
                r".*\.git/.*",
                r".*test_hardening_project/symlink_loop/.*",
            ],
        }

    def _write_pyre_configuration(self, staging: Path) -> None:
        config = self._build_pyre_configuration_dict()
        (staging / ".pyre_configuration").write_text(json.dumps(config, indent=2))

    @staticmethod
    def _extract_json_array(text: str) -> Optional[list]:
        """Pyre prints log lines (banner, progress) before the JSON array.

        Locate the first '[' that begins a balanced array and parse it.
        """
        if not text:
            return None
        # Find the first '[' that starts a valid JSON parse. Walk from
        # each candidate '[' and try; succeed on first parse.
        idx = 0
        while True:
            idx = text.find("[", idx)
            if idx < 0:
                return None
            try:
                value = json.loads(text[idx:])
            except json.JSONDecodeError:
                idx += 1
                continue
            if isinstance(value, list):
                return value
            idx += 1

    # -------------------------------------------------------------- conversion

    def _rows_to_findings(self, rows: list) -> List[Finding]:
        out: List[Finding] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            finding = self._row_to_finding(row)
            if finding is not None:
                out.append(finding)
        return out

    def _row_to_finding(self, row: dict) -> Optional[Finding]:
        rel_path_raw = str(row.get("path") or "").strip()
        define = str(row.get("define") or "")

        # Pyre emits "*" for model-query-generated findings. Derive the
        # actual source file from the defining function's module: e.g.
        # `app.get_user` → `app.py`. This is best-effort; if we can't
        # derive a real path that exists, fall back to the raw value.
        if rel_path_raw in ("", "*"):
            module = define.rsplit(".", 1)[0] if "." in define else define
            if module:
                candidate_file = self.project_path / f"{module.replace('.', '/')}.py"
                if candidate_file.exists():
                    rel_path_raw = str(candidate_file.relative_to(self.project_path))
            if rel_path_raw in ("", "*"):
                return None

        candidate = (self.project_path / rel_path_raw).resolve()
        try:
            rel_path = str(candidate.relative_to(self.project_path))
        except ValueError:
            return None
        if self.file_classifier.should_exclude_from_analysis(rel_path):
            return None

        try:
            line_number = int(row.get("line")) if row.get("line") is not None else None
        except (TypeError, ValueError):
            line_number = None

        code = row.get("code")
        kind, severity = RULE_CODE_TO_KIND.get(code, ("taint", Severity.HIGH))

        message = str(row.get("description") or row.get("name") or f"Tainted dataflow: {kind}")

        # Perf #11: deterministic ID. Stable across runs so customer
        # tooling (PR diffs, finding suppression, baseline comparison)
        # can refer to the same finding by ID across scans.
        identity = f"pysa|{kind}|{rel_path}|{line_number}|{code}".encode("utf-8")
        ident_hash = hashlib.sha256(identity).hexdigest()[:12]
        return Finding(
            id=f"pysa-{kind}-{ident_hash}",
            type=FindingType.SECURITY,
            severity=severity,
            file_path=rel_path,
            line_number=line_number,
            title=f"Tainted dataflow: {kind.replace('_', ' ')}",
            description=message,
            confidence=0.90,
            impact_score=0.85,
            detected_by="PysaTaintScanner",
            remediation=(
                "Validate or escape tainted input before it reaches the sink, "
                "or parameterize the call (prepared statements / argument "
                "lists instead of shell strings). Pysa proved the flow "
                "exists across function boundaries — investigate the call "
                "chain ending at this sink."
            ),
            metadata={
                "taint_kind": kind,
                "pysa_rule_code": code,
                "defining_function": define,
                # taint_path: not yet extracted; see module docstring.
                "taint_path": [
                    {"file": rel_path, "line": line_number, "function": define},
                ],
            },
        )

    # -------------------------------------------------------------- env

    @staticmethod
    def _sandboxed_env() -> dict:
        """Allowlist env so a malicious project can't redirect pyre."""
        keep = ("PATH", "HOME", "LANG", "LC_ALL", "BRASS_TYPESHED")
        env = {k: os.environ.get(k, "") for k in keep if os.environ.get(k) is not None}
        env.setdefault("LANG", "C")
        env.setdefault("LC_ALL", "C")
        return env
