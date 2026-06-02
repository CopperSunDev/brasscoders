"""Unit tests for the Semgrep taint scanner — L0+L1 coverage + review follow-ups.

Covers:
- L0: version probe in `_is_available()` warns on pre-multicore semgrep and
  fails open on probe errors (including the IndexError-on-empty-stdout and
  pre-release-version cases surfaced by code review).
- L1: `-j 2` and the `--` end-of-options sentinel are present in the
  constructed subprocess cmd. `--` defends against target filenames that
  start with `-`.
- The `_version_at_least` static comparator + the `_extract_version_token`
  module helper.
- Module-level memo: probe runs at most once per Python process per path.

Doesn't require `semgrep` on PATH; subprocess + shutil.which are mocked.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from brass.scanners import semgrep_taint_scanner
from brass.scanners.semgrep_taint_scanner import (
    MIN_RECOMMENDED_SEMGREP_VERSION,
    SemgrepTaintScanner,
    _extract_version_token,
)


class _StubResult:
    def __init__(self, stdout="", returncode=0, stderr=""):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


@pytest.fixture(autouse=True)
def reset_version_probe_cache():
    """The version probe is memoized at module level so it fires once per
    process. Tests each verify a single probe behavior, so clear the memo
    between tests for isolation."""
    semgrep_taint_scanner._VERSION_PROBE_CACHE.clear()
    yield
    semgrep_taint_scanner._VERSION_PROBE_CACHE.clear()


@pytest.fixture
def scanner(tmp_path: Path) -> SemgrepTaintScanner:
    # Put a single .py file in the project so target discovery returns something.
    (tmp_path / "app.py").write_text("x = 1\n")
    return SemgrepTaintScanner(str(tmp_path))


# ----------------------------------------------------------------- L1: -j 2

def test_run_semgrep_passes_j2_and_end_of_options(scanner: SemgrepTaintScanner):
    """The semgrep subprocess invocation must include `-j 2` (CPU contention
    coordination) and a `--` end-of-options sentinel before the target
    splat (defense against filenames starting with `-`)."""
    captured = {}

    # Bypass the file-discovery code path so the test only exercises the
    # cmd construction. Without this, the test depends on FileClassifier's
    # exclusion heuristics not rejecting tmp_path/app.py.
    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _StubResult(stdout='{"results": []}', returncode=0)

    with patch("brass.scanners.semgrep_taint_scanner.shutil.which", return_value="/usr/bin/semgrep"), \
         patch("brass.scanners.semgrep_taint_scanner.subprocess.run", side_effect=fake_run), \
         patch.object(scanner, "_discover_python_targets", return_value=[Path("/tmp/app.py")]):
        scanner._available = True
        scanner._run_semgrep()

    cmd = captured["cmd"]
    assert "-j" in cmd, f"-j flag missing from cmd: {cmd}"
    j_index = cmd.index("-j")
    assert cmd[j_index + 1] == "2", f"-j arg should be '2', got {cmd[j_index + 1]!r}"
    assert "--" in cmd, f"`--` end-of-options sentinel missing from cmd: {cmd}"
    # `--` should immediately precede the target splat. -j 2 must come BEFORE `--`
    # since -j is a flag.
    assert cmd.index("-j") < cmd.index("--"), "expected -j to precede --"


# ------------------------------------------------------------ L0: version probe

def test_is_available_warns_on_old_version(scanner: SemgrepTaintScanner, caplog):
    """semgrep < 1.143.0 logs a WARNING nudging the upgrade."""
    with patch("brass.scanners.semgrep_taint_scanner.shutil.which", return_value="/usr/bin/semgrep"), \
         patch(
             "brass.scanners.semgrep_taint_scanner.subprocess.run",
             return_value=_StubResult(stdout="1.136.0\n", returncode=0),
         ):
        with caplog.at_level("WARNING", logger="brass.scanners.semgrep_taint_scanner"):
            available = scanner._is_available()

    assert available is True  # we proceed regardless
    warnings = [r.message for r in caplog.records if r.levelname == "WARNING"]
    assert any("1.136.0" in m and MIN_RECOMMENDED_SEMGREP_VERSION in m for m in warnings), (
        f"Expected version-mismatch WARNING; got: {warnings!r}"
    )


def test_is_available_silent_on_new_version(scanner: SemgrepTaintScanner, caplog):
    """semgrep >= 1.143.0 produces no version warning."""
    with patch("brass.scanners.semgrep_taint_scanner.shutil.which", return_value="/usr/bin/semgrep"), \
         patch(
             "brass.scanners.semgrep_taint_scanner.subprocess.run",
             return_value=_StubResult(stdout="1.143.0\n", returncode=0),
         ):
        with caplog.at_level("WARNING", logger="brass.scanners.semgrep_taint_scanner"):
            available = scanner._is_available()

    assert available is True
    version_warnings = [
        r.message for r in caplog.records
        if r.levelname == "WARNING" and "recommended for multicore" in r.message
    ]
    assert not version_warnings, f"Unexpected version warning: {version_warnings!r}"


def test_is_available_fail_open_on_timeout(scanner: SemgrepTaintScanner):
    """TimeoutExpired during --version → fail open, return True."""
    with patch("brass.scanners.semgrep_taint_scanner.shutil.which", return_value="/usr/bin/semgrep"), \
         patch(
             "brass.scanners.semgrep_taint_scanner.subprocess.run",
             side_effect=subprocess.TimeoutExpired(cmd="semgrep --version", timeout=10),
         ):
        assert scanner._is_available() is True


def test_is_available_fail_open_on_empty_stdout(scanner: SemgrepTaintScanner, tmp_path: Path):
    """Empty --version stdout (a malformed/wrapped binary or env-mask
    interaction) must not crash _check_version. Regression for the bug-scan
    IndexError finding."""
    with patch("brass.scanners.semgrep_taint_scanner.shutil.which", return_value="/usr/bin/semgrep"), \
         patch(
             "brass.scanners.semgrep_taint_scanner.subprocess.run",
             return_value=_StubResult(stdout="", returncode=0),
         ):
        # Must not raise IndexError and must still return True.
        assert scanner._is_available() is True


def test_is_available_fail_open_on_pre_version_chatter(scanner: SemgrepTaintScanner, caplog):
    """Older semgrep builds emit setup chatter before the version line. The
    probe must extract the version-shaped token, not blindly take split()[0].
    Regression for the bug-scan 'older semgrep stdout' finding."""
    chatter = (
        "Loading config...\n"
        "METRICS: collecting anonymous metrics\n"
        "1.136.0\n"
    )
    with patch("brass.scanners.semgrep_taint_scanner.shutil.which", return_value="/usr/bin/semgrep"), \
         patch(
             "brass.scanners.semgrep_taint_scanner.subprocess.run",
             return_value=_StubResult(stdout=chatter, returncode=0),
         ):
        with caplog.at_level("WARNING", logger="brass.scanners.semgrep_taint_scanner"):
            assert scanner._is_available() is True

    # The "1.136.0" version inside the chatter should have been extracted
    # and triggered the warning.
    warnings = [r.message for r in caplog.records if r.levelname == "WARNING"]
    assert any("1.136.0" in m for m in warnings), (
        f"Expected probe to extract version from chatter; got warnings: {warnings!r}"
    )


def test_version_probe_runs_once_per_process(scanner: SemgrepTaintScanner, tmp_path: Path):
    """The module-level _VERSION_PROBE_CACHE memo means the probe runs at
    most once per process per binary path, regardless of how many
    SemgrepTaintScanner instances are constructed."""
    run_call_count = {"n": 0}

    def fake_run(cmd, **kwargs):
        run_call_count["n"] += 1
        return _StubResult(stdout="1.143.0\n", returncode=0)

    with patch("brass.scanners.semgrep_taint_scanner.shutil.which", return_value="/usr/bin/semgrep"), \
         patch("brass.scanners.semgrep_taint_scanner.subprocess.run", side_effect=fake_run):
        # Three fresh scanner instances → still only one --version probe.
        SemgrepTaintScanner(str(tmp_path))._is_available()
        SemgrepTaintScanner(str(tmp_path))._is_available()
        SemgrepTaintScanner(str(tmp_path))._is_available()

    assert run_call_count["n"] == 1, (
        f"version probe should run once across 3 instances; ran {run_call_count['n']}"
    )


# ------------------------------------------------------ static comparator

@pytest.mark.parametrize(
    "version,target,expected",
    [
        ("1.143.0", "1.143.0", True),     # equal → True
        ("1.143.1", "1.143.0", True),     # patch newer
        ("1.144.0", "1.143.0", True),     # minor newer
        ("2.0.0",   "1.143.0", True),     # major newer
        ("1.142.9", "1.143.0", False),    # minor older
        ("1.136.0", "1.143.0", False),    # several minors older
        ("0.99.0",  "1.143.0", False),    # major older
        ("garbage", "1.143.0", True),     # parse error → fail open
        ("",        "1.143.0", True),     # empty → fail open
        # Pre-release suffixes — regression for the silent fail-open bug
        # surfaced in code review. These should compare numerically by the
        # leading digits of each segment, not crash and fail-open.
        ("1.143.0rc1",   "1.143.0", True),    # rc of equal → True
        ("1.142.0rc1",   "1.143.0", False),   # rc of older → False (used to silently True)
        ("1.143.0.post1","1.143.0", True),    # post → True
        ("1.144.0a1",    "1.143.0", True),    # alpha of newer → True
    ],
)
def test_version_at_least(version, target, expected):
    assert SemgrepTaintScanner._version_at_least(version, target) is expected


# ------------------------------------------------------ _extract_version_token

@pytest.mark.parametrize(
    "stdout,expected",
    [
        ("1.143.0\n", "1.143.0"),
        ("1.143.0", "1.143.0"),
        ("1.143.0rc1\n", "1.143.0rc1"),
        ("", None),
        ("no version here", None),
        # First version-shaped token wins, even with leading chatter.
        ("Loading...\nMETRICS: off\n1.136.0\n", "1.136.0"),
    ],
)
def test_extract_version_token(stdout, expected):
    assert _extract_version_token(stdout) == expected
