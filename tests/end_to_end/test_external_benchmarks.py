"""External-benchmarks e2e: brass against pinned third-party projects.

Track A of the external-benchmarks plan (see
``docs/perf/2026-05-17_external_benchmarks_plan.md``). Each benchmark
project lives at a PINNED COMMIT SHA in
``tests/benchmarks/_clones/<project>/`` (fetched by
``tests/benchmarks/clone.sh``), with a documented-findings manifest
in ``tests/benchmarks/<project>/expected_findings.yaml``.

For each project this test:

  1. Skips if the clone is absent (run ``tests/benchmarks/clone.sh``
     first; CI handles this in the benchmarks workflow).
  2. Runs ``brasscoders scan`` against the pinned clone.
  3. Loads the expected_findings manifest.
  4. Asserts every ``required_findings`` entry is present in the
     scan output (matched by file + line + scanner).
  5. Reports (but doesn't fail on) ``aspirational_findings`` —
     documented vulnerabilities brass doesn't yet detect, tracked
     for future improvements.

A regression in any required finding causes a loud failure with
the exact (file, line, expected scanner) tuple identifying the
gap. This is the "did brass really catch what it claims to catch"
validation that closes the gap left by brass-only-self-scan
testing.

Runtime: ~30-60s per project (depends on Pysa cold/warm). Test
file marked end_to_end so it runs in the e2e CI job rather than
on every unit pass.
"""

from __future__ import annotations

import os
import shutil
import site
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest
import yaml

# Tag every test in this file as a Track A benchmark. The unit-test
# workflow (test.yml) excludes "benchmarks"-marked tests via
# `-m "not benchmarks"` so the silent-skip noise from missing clones
# doesn't pollute its output. benchmarks.yml's track-a job clones
# the 5 projects + runs this file unfiltered.
pytestmark = pytest.mark.benchmarks

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CLI_SCRIPT = PROJECT_ROOT / "src" / "brass" / "cli" / "brass_cli.py"
BENCHMARKS_ROOT = PROJECT_ROOT / "tests" / "benchmarks"
CLONES_ROOT = BENCHMARKS_ROOT / "_clones"

# Projects with documented-findings manifests. Add a new project by
# (1) appending it to ``tests/benchmarks/clone.sh``'s PROJECTS array
# and (2) creating ``tests/benchmarks/<name>/expected_findings.yaml``.
BENCHMARK_PROJECTS = (
    "pygoat",
    "nodegoat",
    "bandit_examples",
    "detect_secrets_fixtures",
    "snyk_goof",
)


def _resolve_brass_tool_paths() -> str:
    """Locate scanner binaries on the test process's PATH and return a
    PATH string that includes their parent dirs. HOME isolation strips
    the dev shell's PATH from the subprocess, so without this any
    scanner that depends on an external binary (Bandit B-series rules,
    pylint, Pysa, Semgrep taint, JavaScript/TypeScript scanner via
    Node.js, ast-grep patterns) silently skips — and a required-finding
    assertion that needs one of those scanners always fails."""
    base_path = ["/usr/bin", "/bin", "/usr/local/bin"]
    extra_dirs: list[str] = []
    for tool in ("bandit", "pylint", "pyre", "semgrep", "node", "ast-grep"):
        located = shutil.which(tool)
        if located:
            parent = str(Path(located).parent)
            if parent not in base_path and parent not in extra_dirs:
                extra_dirs.append(parent)
    return os.pathsep.join(base_path + extra_dirs)


def _clear_scan_artifacts(scan_target: Path) -> None:
    """Remove brass's cache + output dirs from a previous run so the
    next scan starts cold. detect-secrets has shown order-dependent
    plugin-loading behavior across runs (cold-start vs warm-start can
    surface different finding counts), and Pysa's typeshed cache can
    drift between scans. Clearing per-project is the simplest way to
    keep the harness reproducible."""
    for artifact in (".brass", ".cache"):
        path = scan_target / artifact
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)


def _run_brassai_against(clone_dir: Path) -> subprocess.CompletedProcess:
    """Run brasscoders scan against a benchmark clone with HOME isolation
    so caches land in the clone dir (mirrors the pattern used by
    test_complete_workflow.py).

    HOME-isolation gotcha — macOS Python 3.9 user-site lookup:
    On macOS, Python computes USER_SITE as
    ``$HOME/Library/Python/X.Y/lib/python/site-packages``. Setting
    ``HOME=clone_dir`` reroutes USER_SITE to a path that doesn't contain
    any installed packages. The brasscoders parent process survives because
    we pass the real user-site via ``PYTHONPATH`` here — but
    ``_sandboxed_subprocess_env`` in ``professional_code_scanner.py``
    deliberately STRIPS ``PYTHONPATH`` before spawning bandit, so
    bandit's wrapper-script Python falls back to the (now wrong)
    HOME-derived USER_SITE and fails with
    ``ModuleNotFoundError: No module named 'bandit'``. Result: 0
    bandit-attributed findings on macOS Py 3.9. CI Ubuntu Py 3.12
    doesn't hit it because Linux user-site uses ``~/.local`` but the
    bandit package on a typical CI runner is installed into the system
    site-packages by ``pip install -e .[dev]``, which the HOME flip
    can't touch.

    Fix: also export ``PYTHONUSERBASE`` pointing at the *real* user
    base (resolved against the developer's real HOME, where deps were
    actually installed). ``PYTHONUSERBASE`` is honored by ``site.py``
    directly and overrides the HOME-derived default — and it survives
    ``_sandboxed_subprocess_env``'s drop list, so the bandit child
    subprocess can import its plugins. Harmless on CI Linux because the
    real user-base there is empty (deps live in system site-packages).
    """
    user_site = site.getusersitepackages()  # computed against real HOME
    user_base = site.getuserbase()  # parent of user_site, e.g. ~/Library/Python/3.9
    # Start from a copy of the runner's env so essential vars survive:
    # SSL_CERT_FILE (HTTPS for typeshed autofetch), DYLD_LIBRARY_PATH
    # (macOS dynamic linker for native scanner binaries), TMPDIR,
    # XDG_*, GITHUB_* (CI tokens for gh CLI calls), SystemRoot (Windows).
    # Replacing the env wholesale broke dylib-linked scanners + the
    # workflow env: block's BRASS_DISABLE_VERSION_CHECK never propagated.
    # The .update() below SELECTIVELY pins what the harness needs to
    # control for reproducibility while preserving everything else.
    env = {**os.environ}
    env.update({
        "PYTHONPATH": os.pathsep.join([str(PROJECT_ROOT / "src"), user_site]),
        "PATH": _resolve_brass_tool_paths(),
        "HOME": str(clone_dir),
        # See docstring: pins child Python's USER_SITE to the real
        # location, so subprocess scanners (bandit, pylint) can import
        # their installed packages even though HOME is redirected.
        "PYTHONUSERBASE": user_base,
        "LANG": "C",
        "LC_ALL": "C",
        # Autofetch typeshed so Pysa runs even on a fresh CI cache key —
        # without it Pysa skips and any Pysa-dependent required finding
        # would always fail the assertion.
        "BRASS_AUTOFETCH_TYPESHED": "1",
    })
    cmd = [
        sys.executable, str(CLI_SCRIPT),
        "--offline", "scan", str(clone_dir),
        "--max-workers=2",
    ]
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=300, env=env,
    )


def _load_manifest(project: str) -> Dict[str, Any]:
    manifest_path = BENCHMARKS_ROOT / project / "expected_findings.yaml"
    if not manifest_path.is_file():
        pytest.fail(
            f"Missing expected_findings.yaml for benchmark project "
            f"'{project}' at {manifest_path}. See "
            f"docs/perf/2026-05-17_external_benchmarks_plan.md for "
            f"the schema."
        )
    return yaml.safe_load(manifest_path.read_text())


def _collect_all_findings(clone_dir: Path) -> List[Dict[str, Any]]:
    """Pull every finding from detailed_analysis.yaml (not just
    critical_issues, which is capped). Returns a flat list with
    file_path, line_number, detected_by, severity, title."""
    detailed_path = clone_dir / ".brass" / "detailed_analysis.yaml"
    if not detailed_path.is_file():
        return []
    data = yaml.safe_load(detailed_path.read_text())
    findings = []
    for _type, block in (data.get("analysis_by_type") or {}).items():
        for f in block.get("findings", []) or []:
            findings.append(f)
    return findings


def _match_required(
    required: Dict[str, Any],
    all_findings: List[Dict[str, Any]],
) -> Tuple[bool, str]:
    """Does ``all_findings`` contain something matching the required
    entry? Match key is (file basename match, exact line, scanner
    name). ``expected_scanner`` may be a single string or a list of
    acceptable scanners — useful for findings where the detection
    legitimately varies between OS / Python versions (e.g. MD5 hits
    AstGrepScanner on macOS Python 3.9 but bandit on Linux Python
    3.12). The vulnerability is what we care about; which scanner
    attributes it is secondary. Returns (ok, diagnostic-on-fail)."""
    want_file = required["file"]
    want_line = required["line"]
    want_scanner = required["expected_scanner"]
    if isinstance(want_scanner, str):
        accepted_scanners = [want_scanner.lower()]
    else:
        accepted_scanners = [s.lower() for s in want_scanner]

    # File match is "ends-with" rather than exact — brass may report
    # the absolute path in some surfaces; expected_findings.yaml uses
    # the project-relative path.
    candidates = [
        f for f in all_findings
        if (f.get("file_path") or "").endswith(want_file)
        and f.get("line_number") == want_line
    ]
    if not candidates:
        return False, (
            f"No finding at {want_file}:{want_line}. BrassCoders found "
            f"{len(all_findings)} total findings; check "
            f"`detailed_analysis.yaml` for what landed."
        )
    scanner_match = [
        f for f in candidates
        if (f.get("detected_by") or "").lower() in accepted_scanners
    ]
    if not scanner_match:
        # `or '<unknown>'` because py3.11+ raises TypeError on
        # sorted() over mixed None + str.
        seen_scanners = sorted({f.get("detected_by") or "<unknown>" for f in candidates})
        return False, (
            f"Findings exist at {want_file}:{want_line} but none from "
            f"{want_scanner!r}. Detected by: {seen_scanners}. The "
            f"vulnerability is being seen, just by a different scanner "
            f"— update the manifest if the new scanner is acceptable, "
            f"or investigate the regression."
        )
    return True, ""


@pytest.fixture(scope="module", params=BENCHMARK_PROJECTS)
def benchmark_scan(request: pytest.FixtureRequest) -> Tuple[str, Path]:
    """Run brasscoders once per project per test module; cache the scanned
    target so the per-finding tests below all share a single scan.
    Returns (project_name, scan_target).

    ``scan_target`` is ``CLONES_ROOT/<project>`` by default, OR
    ``CLONES_ROOT/<project>/<scan_subpath>`` if the project's manifest
    declares ``scan_subpath:`` — used for projects where we only want
    to benchmark a curated subdirectory of a larger repo (e.g.
    bandit's ``examples/`` rather than scanning bandit's own
    implementation source)."""
    project = request.param
    clone_dir = CLONES_ROOT / project
    if not clone_dir.is_dir():
        pytest.skip(
            f"{project} clone not found at {clone_dir}. Run "
            f"`tests/benchmarks/clone.sh` to fetch the pinned commit."
        )
    manifest = _load_manifest(project)
    scan_subpath = manifest.get("scan_subpath")
    scan_target = clone_dir / scan_subpath if scan_subpath else clone_dir
    if not scan_target.is_dir():
        pytest.fail(
            f"{project} scan_subpath '{scan_subpath}' does not exist "
            f"at {scan_target}. Check the manifest or re-clone."
        )
    _clear_scan_artifacts(scan_target)
    result = _run_brassai_against(scan_target)
    if result.returncode != 0:
        pytest.fail(
            f"brasscoders scan against {project} failed (rc={result.returncode}):\n"
            f"stderr:\n{result.stderr[-2000:]}"
        )
    return project, scan_target


@pytest.mark.parametrize("project", BENCHMARK_PROJECTS)
def test_manifest_schema_is_valid(project: str) -> None:
    """Every benchmark project's expected_findings.yaml must declare
    the documented schema fields so the assertion machinery has the
    right shape to work with."""
    manifest = _load_manifest(project)
    required_top_level = {
        "project", "upstream", "pinned_sha", "upstream_reference",
        "baseline_scan_date", "required_findings",
    }
    missing = required_top_level - set(manifest.keys())
    assert not missing, f"{project} manifest missing keys: {missing}"

    for i, entry in enumerate(manifest.get("required_findings") or []):
        entry_keys = set(entry.keys())
        required_entry_keys = {
            "file", "line", "category", "expected_scanner",
            "vulnerability_class",
        }
        missing = required_entry_keys - entry_keys
        assert not missing, (
            f"{project} required_findings[{i}] missing keys: {missing}"
        )


def test_required_findings(benchmark_scan: Tuple[str, Path]) -> None:
    """Every required_findings entry in each project's manifest must
    appear in brass's scan output. A regression dropping any of these
    signals fails this test loudly with the specific file:line:scanner
    tuple that went missing."""
    project, clone_dir = benchmark_scan
    manifest = _load_manifest(project)
    all_findings = _collect_all_findings(clone_dir)
    assert all_findings, (
        f"brass produced no findings on {project} — check "
        f"{clone_dir / '.brass' / 'brass.log'} for scanner errors."
    )

    failures: List[str] = []
    for required in manifest["required_findings"]:
        ok, diagnostic = _match_required(required, all_findings)
        if not ok:
            failures.append(
                f"  - {required['file']}:{required['line']} "
                f"({required['expected_scanner']}, "
                f"{required['vulnerability_class']}): {diagnostic}"
            )

    if failures:
        raise AssertionError(
            f"brass missed {len(failures)} required {project} finding(s):\n"
            + "\n".join(failures) + "\n\n"
            "This is a real regression — a documented vulnerability "
            "that brass previously caught is now silently invisible. "
            "Check `detailed_analysis.yaml` in the scan output, then "
            "either fix the scanner regression or (if intentional) "
            "update expected_findings.yaml with the new baseline."
        )


def test_aspirational_findings_diagnostic(
    benchmark_scan: Tuple[str, Path], capsys: pytest.CaptureFixture,
) -> None:
    """Reports (but does NOT fail on) aspirational_findings — documented
    vulnerabilities brass doesn't yet detect. If a future brass commit
    closes one of these gaps, the diagnostic flips from 'still missed'
    to 'now detected!' and the maintainer can promote the entry to
    required_findings."""
    project, clone_dir = benchmark_scan
    manifest = _load_manifest(project)
    all_findings = _collect_all_findings(clone_dir)

    aspirational = manifest.get("aspirational_findings") or []
    closed_gaps: List[str] = []
    open_gaps: List[str] = []
    for entry in aspirational:
        hits = [
            f for f in all_findings
            if (f.get("file_path") or "").endswith(entry["file"])
            and f.get("line_number") == entry["line"]
        ]
        label = f"{entry['file']}:{entry['line']} ({entry['category']})"
        if hits:
            scanners = sorted({f.get("detected_by") or "<unknown>" for f in hits})
            closed_gaps.append(f"  - {label}: now detected by {scanners}")
        else:
            open_gaps.append(f"  - {label}")

    # Emit a summary that's visible in pytest -v output without
    # using `print()` (which pytest captures and may hide).
    with capsys.disabled():
        print()
        print(f"{project} aspirational gaps: {len(open_gaps)} open, "
              f"{len(closed_gaps)} closed")
        if closed_gaps:
            print("Newly closed (consider promoting to required_findings):")
            print("\n".join(closed_gaps))
        if open_gaps:
            print("Still open:")
            print("\n".join(open_gaps))
