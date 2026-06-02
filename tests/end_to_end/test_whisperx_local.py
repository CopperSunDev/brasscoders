"""Local-only Track B regression check against whisperx-production.

whisperx-production is the most representative customer-shape
project we have access to (Next.js frontend + Python ML inference,
~5000 files including dependencies). It's not committed to brass-v2
and can't run in CI because the source is customer-private. But it's
the closest stand-in for "a real customer scan" that exists in our
dev env, so maintainers can run regression checks against it locally
before pushing changes that might affect customer-facing output.

Usage::

    # Default: looks for the clone at the path declared in
    # WHISPERX_LOCAL_PATH env var, falling back to the common dev path.
    pytest -m benchmarks_local -v

    # Compare against a previously-recorded baseline:
    WHISPERX_LOCAL_BASELINE=/tmp/whisperx-baseline.yaml \\
        pytest -m benchmarks_local -v

    # Record a new baseline from the current run:
    WHISPERX_LOCAL_RECORD=/tmp/whisperx-baseline.yaml \\
        pytest -m benchmarks_local -v

Skipped automatically in CI (no whisperx clone) and on any machine
where ``WHISPERX_LOCAL_PATH`` (or the default path) doesn't exist.

IMPORTANT: nothing about whisperx-production goes into Track C
publication. Its baseline numbers live only in maintainer-local
files (gitignored) and never reach coppersun.dev or any other public
surface. It's a regression-detection tool for dev workflow, not a
marketing asset.
"""

from __future__ import annotations

import os
import shutil
import site
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.benchmarks_local

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CLI_SCRIPT = PROJECT_ROOT / "src" / "brass" / "cli" / "brass_cli.py"
GENERATE_BASELINE = PROJECT_ROOT / "docs" / "benchmarks" / "generate_baseline.py"
COMPARE = PROJECT_ROOT / "docs" / "benchmarks" / "compare.py"

def _whisperx_path() -> Path:
    """Return the whisperx clone path. Skips the test if missing —
    standard pattern for local-only tests that can't run elsewhere.

    Hardcoded developer-specific defaults removed: requires
    WHISPERX_LOCAL_PATH env var. Skip otherwise. (Previously baked in
    a specific user's home directory, which leaked identity and broke
    every other maintainer's run.)
    """
    env_path = os.environ.get("WHISPERX_LOCAL_PATH")
    if not env_path:
        pytest.skip(
            "WHISPERX_LOCAL_PATH not set. This test is local-only; set "
            "WHISPERX_LOCAL_PATH to a whisperx-production clone path to run it."
        )
    candidate = Path(env_path)
    if not candidate.is_dir():
        pytest.skip(
            f"whisperx-production not found at {candidate}. Check "
            f"WHISPERX_LOCAL_PATH or skip this test."
        )
    return candidate


def _resolve_tool_paths() -> str:
    """Same PATH-building pattern as test_external_benchmarks.py —
    propagate scanner binaries through the HOME-isolated subprocess."""
    base_path = ["/usr/bin", "/bin", "/usr/local/bin"]
    extra_dirs: list[str] = []
    for tool in ("bandit", "pylint", "pyre", "semgrep", "node", "ast-grep"):
        located = shutil.which(tool)
        if located:
            parent = str(Path(located).parent)
            if parent not in base_path and parent not in extra_dirs:
                extra_dirs.append(parent)
    return os.pathsep.join(base_path + extra_dirs)


def _run_brassai_against(target: Path) -> subprocess.CompletedProcess:
    """Run brasscoders scan against the local clone. Same isolation pattern
    as the external-benchmarks tests, plus PYTHONUSERBASE per the
    fix in commit dfa2803."""
    user_site = site.getusersitepackages()
    # Inherit-and-override pattern: preserve SSL_CERT_FILE,
    # DYLD_LIBRARY_PATH, etc. while pinning the harness vars.
    # See test_external_benchmarks._run_brassai_against for rationale.
    env = {**os.environ}
    env.update({
        "PYTHONPATH": os.pathsep.join([str(PROJECT_ROOT / "src"), user_site]),
        "PATH": _resolve_tool_paths(),
        "HOME": str(target),
        "PYTHONUSERBASE": site.getuserbase(),
        "LANG": "C",
        "LC_ALL": "C",
        "BRASS_AUTOFETCH_TYPESHED": "1",
    })
    cmd = [
        sys.executable, str(CLI_SCRIPT),
        "--offline", "scan", str(target),
        "--max-workers=2",
    ]
    # 30-min cap — whisperx-production has ~5000 files; on a cold
    # cache this can take a while. Adjust upward if the local
    # machine consistently overruns.
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=1800, env=env,
    )


def _generate_baseline(scan_dir: Path, project: str, output: Path) -> None:
    """Invoke the canonical generate_baseline.py script so the local
    metrics format matches the Track B committed baselines exactly."""
    subprocess.run(
        [
            sys.executable, str(GENERATE_BASELINE),
            "--project", project,
            "--pinned-sha", "local-uncommitted",
            "--upstream-reference", "whisperx-production local snapshot",
            "--scan-dir", str(scan_dir),
            "--output", str(output),
        ],
        check=True,
    )


def test_whisperx_local_scan(capsys: pytest.CaptureFixture) -> None:
    """Scan the local whisperx-production clone and emit metrics.

    Three modes via env vars:
      - WHISPERX_LOCAL_RECORD=<path>: write current metrics to that
        file (use this to refresh the local baseline after intentional
        changes).
      - WHISPERX_LOCAL_BASELINE=<path>: compare current run against
        that baseline (use this for regression detection). Fails if
        ≥20% findings delta or ≥50% wall-time slowdown.
      - Neither set: just emit metrics to stdout. Maintainer eyeballs
        drift between runs.
    """
    whisperx = _whisperx_path()

    # Clear stale .brass/.cache so the regression check is deterministic
    # cold-cache (same contract as Track A/B in CI).
    for artifact in (".brass", ".cache"):
        path = whisperx / artifact
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)

    result = _run_brassai_against(whisperx)
    assert result.returncode == 0, (
        f"brasscoders scan failed (rc={result.returncode}):\n"
        f"stderr:\n{result.stderr[-2000:]}"
    )

    current_path = Path("/tmp/whisperx-local-current.yaml")
    _generate_baseline(whisperx / ".brass", "whisperx_local", current_path)

    # Always print metrics to stdout — useful for any of the 3 modes.
    with capsys.disabled():
        print()
        print("whisperx-production local scan metrics:")
        print(current_path.read_text())

    record_path = os.environ.get("WHISPERX_LOCAL_RECORD")
    if record_path:
        shutil.copy(current_path, record_path)
        with capsys.disabled():
            print(f"Recorded baseline to {record_path}")
        return

    baseline_path = os.environ.get("WHISPERX_LOCAL_BASELINE")
    if baseline_path:
        baseline = Path(baseline_path)
        if not baseline.is_file():
            pytest.fail(
                f"WHISPERX_LOCAL_BASELINE points to non-existent path: "
                f"{baseline}. Run with WHISPERX_LOCAL_RECORD set first "
                f"to seed it."
            )
        compare_result = subprocess.run(
            [
                sys.executable, str(COMPARE),
                "--baseline", str(baseline),
                "--current", str(current_path),
            ],
            capture_output=True, text=True,
        )
        with capsys.disabled():
            print(compare_result.stdout)
        assert compare_result.returncode == 0, (
            f"whisperx regression detected — see compare output above."
        )
