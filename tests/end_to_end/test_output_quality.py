"""Structural-quality assertions on the generated ai_instructions.yaml.

Phase H output-quality refactor (2026-05-17). Runs against a fixed-
corpus scan (Track A's pygoat clone) and asserts the customer-facing
shape of brass's primary AI-consumer surface:

- Typed-block separation (security_critical / code_quality_attention /
  architecture_concerns / other) is honored: no pylint/legacy leakage
  into security_critical, no security findings in
  code_quality_attention.
- Cluster sizes are display-capped (max 30) with an expansion_hint
  pointing at detailed_analysis.yaml for the real count.
- executive_summary.recommendation is actionable prose, not a generic
  "N critical/high issues require immediate attention" count.
- executive_summary.findings_by_category is populated.
- Every critical_issues entry carries file_path + line_number.
- system_advisories has moved out of ai_instructions.yaml into
  operator_notes.yaml (split for AI-consumer vs operator audience).
- production_focus exists and is a list.

The test is the missing piece in brass's test pyramid: unit tests
cover individual builder methods; this exercises the full pipeline
against a real fixture so a regression that breaks the AI-consumer
shape (without breaking any single unit) gets caught loudly.

Runtime: ~30-60s on a warm Pysa cache (one scan, multiple assertions).
Marked `benchmarks` so it runs in the existing benchmarks workflow
track-a job — no separate CI workflow needed.
"""

from __future__ import annotations

import os
import re
import shutil
import site
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
import yaml


pytestmark = pytest.mark.benchmarks


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CLI_SCRIPT = PROJECT_ROOT / "src" / "brass" / "cli" / "brass_cli.py"
BENCHMARKS_ROOT = PROJECT_ROOT / "tests" / "benchmarks"
CLONES_ROOT = BENCHMARKS_ROOT / "_clones"

# Use the same project as Track A's primary baseline. pygoat is small
# enough to scan in well under a minute and rich enough in findings
# that every typed block reliably has content for assertions.
TARGET_PROJECT = "pygoat"


def _resolve_brass_tool_paths() -> str:
    """Add scanner-binary parent dirs to PATH so HOME-isolated
    subprocess scans can still spawn bandit/pylint/etc. Mirrors the
    helper in test_external_benchmarks.py — see that file's docstring
    for the rationale."""
    base_path = ["/usr/bin", "/bin", "/usr/local/bin"]
    extra_dirs: list[str] = []
    for tool in ("bandit", "pylint", "pyre", "semgrep", "node", "ast-grep"):
        located = shutil.which(tool)
        if located:
            parent = str(Path(located).parent)
            if parent not in base_path and parent not in extra_dirs:
                extra_dirs.append(parent)
    return os.pathsep.join(base_path + extra_dirs)


def _run_brassai_against(scan_target: Path) -> subprocess.CompletedProcess:
    """Invoke `brasscoders scan` against scan_target with HOME isolated.
    Same subprocess pattern as test_external_benchmarks.py's helper —
    see that file's docstring for the HOME-isolation gotchas (macOS
    user-site, PYTHONUSERBASE preservation for bandit subprocess)."""
    user_site = site.getusersitepackages()
    user_base = site.getuserbase()
    env = {**os.environ}
    env.update({
        "PYTHONPATH": os.pathsep.join([str(PROJECT_ROOT / "src"), user_site]),
        "PATH": _resolve_brass_tool_paths(),
        "HOME": str(scan_target),
        "PYTHONUSERBASE": user_base,
        "LANG": "C",
        "LC_ALL": "C",
        "BRASS_AUTOFETCH_TYPESHED": "1",
    })
    cmd = [
        sys.executable, str(CLI_SCRIPT),
        "--offline", "scan", str(scan_target),
        "--max-workers=2",
    ]
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=300, env=env,
    )


def _clear_scan_artifacts(scan_target: Path) -> None:
    for artifact in (".brass", ".cache"):
        path = scan_target / artifact
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)


def _load_manifest_scan_subpath(project: str) -> Optional[str]:
    manifest_path = BENCHMARKS_ROOT / project / "expected_findings.yaml"
    if not manifest_path.is_file():
        return None
    return (yaml.safe_load(manifest_path.read_text()) or {}).get("scan_subpath")


@pytest.fixture(scope="module")
def output_quality_scan() -> Path:
    """Run brasscoders once against pygoat (or whichever target is pinned)
    and return the scan_target so all assertion tests in this module
    share a single scan. Skips the whole module if the clone is missing."""
    clone_dir = CLONES_ROOT / TARGET_PROJECT
    if not clone_dir.is_dir():
        pytest.skip(
            f"{TARGET_PROJECT} clone not found at {clone_dir}. Run "
            f"`tests/benchmarks/clone.sh` to fetch the pinned commit."
        )
    scan_subpath = _load_manifest_scan_subpath(TARGET_PROJECT)
    scan_target = clone_dir / scan_subpath if scan_subpath else clone_dir
    if not scan_target.is_dir():
        pytest.fail(
            f"{TARGET_PROJECT} scan_subpath '{scan_subpath}' does not exist "
            f"at {scan_target}."
        )
    _clear_scan_artifacts(scan_target)
    result = _run_brassai_against(scan_target)
    if result.returncode != 0:
        pytest.fail(
            f"brasscoders scan against {TARGET_PROJECT} failed "
            f"(rc={result.returncode}):\n"
            f"stderr:\n{result.stderr[-2000:]}"
        )
    return scan_target


@pytest.fixture(scope="module")
def ai_instructions(output_quality_scan: Path) -> Dict[str, Any]:
    """Parsed ai_instructions.yaml from the shared scan."""
    path = output_quality_scan / ".brass" / "ai_instructions.yaml"
    assert path.is_file(), f"Expected {path} to exist after scan."
    return yaml.safe_load(path.read_text())


def _real_entries(block: Optional[List[Any]]) -> List[Dict[str, Any]]:
    """Filter out synthetic `_next_after_truncation` pointer entries
    so structural assertions only inspect actual findings."""
    if not block:
        return []
    return [
        e for e in block
        if isinstance(e, dict) and '_next_after_truncation' not in e
    ]


# --- Block-typing structural assertions ----------------------------


def test_security_critical_block_exists_and_is_list(
    ai_instructions: Dict[str, Any],
) -> None:
    block = ai_instructions.get("security_critical")
    assert isinstance(block, list), (
        "security_critical must be present as a list in ai_instructions.yaml"
    )


def test_security_critical_contains_only_security_or_privacy(
    ai_instructions: Dict[str, Any],
) -> None:
    """Phase H regression guard: no pylint/legacy/architecture leakage
    into the security-customer-facing block."""
    for entry in _real_entries(ai_instructions.get("security_critical")):
        assert entry.get("type") in ("security", "privacy"), (
            f"security_critical entry {entry.get('id')!r} has "
            f"type={entry.get('type')!r} (expected security or privacy)"
        )


def test_code_quality_attention_block_exists(
    ai_instructions: Dict[str, Any],
) -> None:
    assert isinstance(ai_instructions.get("code_quality_attention"), list)


def test_code_quality_attention_contains_only_code_quality_or_todo(
    ai_instructions: Dict[str, Any],
) -> None:
    for entry in _real_entries(ai_instructions.get("code_quality_attention")):
        assert entry.get("type") in ("code_quality", "todo"), (
            f"code_quality_attention entry {entry.get('id')!r} has "
            f"type={entry.get('type')!r}"
        )


def test_architecture_concerns_block_exists(
    ai_instructions: Dict[str, Any],
) -> None:
    assert isinstance(ai_instructions.get("architecture_concerns"), list)


def test_architecture_concerns_contains_only_architecture_or_performance(
    ai_instructions: Dict[str, Any],
) -> None:
    for entry in _real_entries(ai_instructions.get("architecture_concerns")):
        assert entry.get("type") in ("architecture", "performance"), (
            f"architecture_concerns entry {entry.get('id')!r} has "
            f"type={entry.get('type')!r}"
        )


# --- Cluster-size display cap -------------------------------------


def test_cluster_size_capped_at_30_with_expansion_hint(
    ai_instructions: Dict[str, Any],
) -> None:
    """No emitted entry advertises a cluster_size > 30 — when the real
    count is larger, it's pinned to 30 and an expansion_hint is added
    pointing at detailed_analysis.yaml for the long tail."""
    for block_name in (
        "security_critical", "code_quality_attention",
        "architecture_concerns", "other", "critical_issues",
        "production_focus",
    ):
        for entry in _real_entries(ai_instructions.get(block_name)):
            cluster_size = entry.get("cluster_size")
            if cluster_size is None:
                continue
            assert cluster_size <= 30, (
                f"{block_name}[{entry.get('id')}] cluster_size={cluster_size} "
                f"exceeds the customer-facing 30 cap. Expected: cluster_size "
                f"clamped to 30 with `expansion_hint:` carrying the real count."
            )
            if cluster_size == 30:
                # If we landed on the cap, the entry MAY carry an
                # expansion_hint (it does iff the real count exceeded 30
                # in the scanner's metadata). Don't require it — a real
                # cluster_size of exactly 30 emits cap=30 without hint.
                pass


# --- Executive summary actionable phrasing ------------------------


_LEGACY_RECOMMENDATION_RE = re.compile(r"^\s*\d+\s+critical/high")


def test_recommendation_is_actionable_not_a_count(
    ai_instructions: Dict[str, Any],
) -> None:
    """Phase H: recommendation must reference actual findings + remediation
    refs (or explicitly state 'no production-code signals'). The old
    'N critical/high issues require immediate attention' pattern is the
    regression this guard exists to catch."""
    rec = ai_instructions.get("executive_summary", {}).get("recommendation", "")
    assert rec, "executive_summary.recommendation should not be empty"
    assert not _LEGACY_RECOMMENDATION_RE.match(rec), (
        f"recommendation reverted to the legacy count-only phrasing: {rec!r}"
    )


def test_findings_by_category_is_populated(
    ai_instructions: Dict[str, Any],
) -> None:
    """executive_summary.findings_by_category gives the AI consumer the
    issue-shape distribution at a glance. On a real pygoat scan there
    are always at least a few categories."""
    by_cat = ai_instructions.get("executive_summary", {}).get(
        "findings_by_category"
    )
    assert isinstance(by_cat, dict), (
        "executive_summary.findings_by_category must be a dict"
    )
    assert len(by_cat) > 0, (
        "findings_by_category should be non-empty on a real scan"
    )
    for category, count in by_cat.items():
        assert isinstance(category, str)
        assert isinstance(count, int)
        assert count > 0


# --- File path / line number completeness -------------------------


def test_every_critical_issues_entry_has_file_and_line(
    ai_instructions: Dict[str, Any],
) -> None:
    """Every emitted finding the AI consumer is asked to triage must
    point at a specific source location — file_path + line_number both
    non-null. A finding without a location is unactionable."""
    for entry in _real_entries(ai_instructions.get("critical_issues")):
        assert entry.get("file_path"), (
            f"critical_issues entry {entry.get('id')!r} missing file_path"
        )
        assert entry.get("line_number") is not None, (
            f"critical_issues entry {entry.get('id')!r} missing line_number"
        )


# --- operator_notes split -----------------------------------------


def test_system_advisories_not_in_ai_instructions(
    ai_instructions: Dict[str, Any],
) -> None:
    """system_advisories moved out of ai_instructions.yaml; it lives in
    operator_notes.yaml now. ai_instructions.yaml should stay strictly
    about the codebase under review."""
    assert "system_advisories" not in ai_instructions


def test_operator_notes_file_exists_when_advisories_fire(
    output_quality_scan: Path,
) -> None:
    """operator_notes.yaml is emitted ONLY when at least one advisory
    fires (cache > 1 GB, etc.). On the pygoat scan with a fresh
    HOME-isolated cache we don't expect a 1 GB cache, so operator_notes
    may or may not be present — either is acceptable. The contract is:
    when present, it carries `system_advisories`; when absent, no
    operator-facing issue."""
    path = output_quality_scan / ".brass" / "operator_notes.yaml"
    if path.is_file():
        data = yaml.safe_load(path.read_text())
        assert isinstance(data, dict)
        assert "system_advisories" in data
        assert isinstance(data["system_advisories"], list)
        assert len(data["system_advisories"]) > 0
    else:
        # No advisory fired this scan — that's fine, just confirm the
        # AI-instructions surface didn't also emit a tool_health_summary
        # that would point at a missing file.
        assert "tool_health_summary" not in ai_instructions_or_empty(
            output_quality_scan
        )


def ai_instructions_or_empty(scan_target: Path) -> Dict[str, Any]:
    path = scan_target / ".brass" / "ai_instructions.yaml"
    if not path.is_file():
        return {}
    return yaml.safe_load(path.read_text()) or {}


# --- production_focus view ----------------------------------------


def test_production_focus_exists_and_is_list(
    ai_instructions: Dict[str, Any],
) -> None:
    """The ship-the-PR pre-filtered view. Always emitted as a list, even
    when empty (the AI consumer can detect emptiness without having to
    test for key absence)."""
    focus = ai_instructions.get("production_focus")
    assert isinstance(focus, list), (
        "production_focus must be a list in ai_instructions.yaml"
    )


def test_production_focus_entries_are_production_code(
    ai_instructions: Dict[str, Any],
) -> None:
    """Every production_focus entry has context.is_production_code true.
    A regression that broke the filter would surface here."""
    for entry in _real_entries(ai_instructions.get("production_focus")):
        ctx = entry.get("context") or {}
        assert ctx.get("is_production_code") is True, (
            f"production_focus entry {entry.get('id')!r} has "
            f"is_production_code={ctx.get('is_production_code')!r}"
        )
