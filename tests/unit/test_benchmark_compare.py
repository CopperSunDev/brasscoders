"""Unit tests for docs/benchmarks/compare.py.

Track B regression detection. The comparator must:
  - PASS when current matches baseline within tolerance
  - FAIL when findings_count drops ≥20% (silent miss regression)
  - FAIL when findings_count rises ≥20% (false-positive noise spike)
  - FAIL when wall_time_sec rises ≥50% (perf regression)
  - PASS when wall_time_sec drops (faster is fine)
  - Tolerate missing per-scanner / per-severity dicts gracefully
  - Tolerate baseline=0 without ZeroDivisionError
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

# Load docs/benchmarks/compare.py via importlib — it lives outside the
# Python package so a normal `from ... import compare` won't work.
_COMPARE_PATH = (
    Path(__file__).resolve().parents[2]
    / "docs" / "benchmarks" / "compare.py"
)


@pytest.fixture(scope="module")
def compare_module():
    spec = importlib.util.spec_from_file_location(
        "brass_benchmark_compare", _COMPARE_PATH,
    )
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    # Register before exec so the @dataclass(frozen=True) annotation
    # resolver can find the module via cls.__module__ lookup (Python
    # 3.9 quirk; without this the dataclass forward-reference logic
    # raises AttributeError on import).
    sys.modules["brass_benchmark_compare"] = module
    spec.loader.exec_module(module)
    return module


def _baseline(findings: int = 100, wall_time: float = 30.0, **extras):
    base = {
        "project": "flask",
        "metrics": {
            "findings_count": findings,
            "wall_time_sec": wall_time,
        },
    }
    base["metrics"].update(extras)
    return base


def test_identical_metrics_pass(compare_module):
    """Same numbers in baseline + current → PASS, no regressions."""
    baseline = _baseline(findings=100, wall_time=30.0)
    current = _baseline(findings=100, wall_time=30.0)
    result = compare_module.compare(baseline, current)
    assert result.ok
    assert result.regressions == []


def test_small_findings_drift_passes(compare_module):
    """A 5% drift in findings is well under the 20% threshold → PASS."""
    result = compare_module.compare(
        _baseline(findings=100),
        _baseline(findings=95),
    )
    assert result.ok
    assert any("findings_count delta" in n for n in result.notes)


def test_findings_drop_above_threshold_fails(compare_module):
    """≥20% drop in findings = silent-miss regression → FAIL."""
    result = compare_module.compare(
        _baseline(findings=100),
        _baseline(findings=79),  # 21% drop
    )
    assert not result.ok
    assert any("DROPPED" in r for r in result.regressions)
    assert any("21.0%" in r for r in result.regressions)


def test_findings_spike_above_threshold_fails(compare_module):
    """≥20% rise in findings = noise-spike regression → FAIL.
    Bidirectional check: brass introducing FP noise is as bad as
    losing TPs."""
    result = compare_module.compare(
        _baseline(findings=100),
        _baseline(findings=130),  # 30% spike
    )
    assert not result.ok
    assert any("SPIKED" in r for r in result.regressions)


def test_findings_exactly_at_threshold_fails(compare_module):
    """20.0% delta should trip the rule (≥ threshold, not >)."""
    result = compare_module.compare(
        _baseline(findings=100),
        _baseline(findings=80),  # exactly 20% drop
    )
    assert not result.ok


def test_wall_time_slowdown_above_threshold_fails(compare_module):
    """≥50% slower scan = perf regression → FAIL."""
    result = compare_module.compare(
        _baseline(wall_time=30.0),
        _baseline(wall_time=46.0),  # 53% slower
    )
    assert not result.ok
    assert any("SLOWED" in r for r in result.regressions)


def test_wall_time_speedup_passes(compare_module):
    """Faster scan = fine, no regression. Only slowdowns matter."""
    result = compare_module.compare(
        _baseline(wall_time=30.0),
        _baseline(wall_time=10.0),  # 67% faster
    )
    assert result.ok
    # Should still note the delta informationally
    assert any("wall_time_sec delta" in n for n in result.notes)


def test_wall_time_minor_slowdown_passes(compare_module):
    """30% slower < 50% threshold → PASS (with informational note)."""
    result = compare_module.compare(
        _baseline(wall_time=30.0),
        _baseline(wall_time=39.0),  # 30% slower
    )
    assert result.ok


def test_baseline_zero_findings_doesnt_crash(compare_module):
    """Baseline with 0 findings was reported on a clean codebase
    (e.g., vercel/commerce). The comparator must NOT treat a
    legitimate 0-noise-floor baseline as a forced regression on
    any non-zero current — there's no defined percentage delta
    from 0. Behavior contract:
      - Both zero → pass.
      - Zero → N → info note, NOT regression (current behavior
        post-2026-05-18 bug-review pass). Maintainer rebases the
        baseline manually if drift is persistent.
    """
    # Both zero → pass
    result = compare_module.compare(
        _baseline(findings=0),
        _baseline(findings=0),
    )
    assert result.ok

    # Zero → N is now informational, not a regression. The ratio
    # is undefined and forcing a 100% spike verdict would fail every
    # clean-codebase project (Vercel commerce, etc.).
    result = compare_module.compare(
        _baseline(findings=0),
        _baseline(findings=5),
    )
    assert result.ok
    # The note should mention the can't-compute-ratio case.
    assert any("baseline=0" in n for n in result.notes)


def test_per_scanner_diagnostics_attached(compare_module):
    """When per_scanner is present in both, deltas appear in notes
    so a maintainer triaging a failure sees which scanner moved."""
    baseline = _baseline(
        findings=100,
        per_scanner={"Bandit": 50, "SecretsScanner": 20, "Privacy": 30},
    )
    current = _baseline(
        findings=100,
        per_scanner={"Bandit": 40, "SecretsScanner": 30, "Privacy": 30},
    )
    result = compare_module.compare(baseline, current)
    assert result.ok  # total still 100, no regression
    scanner_note = "\n".join(result.notes)
    assert "Bandit: 50 → 40" in scanner_note
    assert "SecretsScanner: 20 → 30" in scanner_note
    # Privacy didn't change — should NOT appear
    assert "Privacy" not in scanner_note


def test_missing_metrics_keys_flagged(compare_module):
    """If a baseline has no findings_count (schema drift), report
    it as a regression rather than silently passing — otherwise a
    broken baseline file would mask real regressions forever."""
    baseline = {"project": "flask", "metrics": {}}
    current = _baseline(findings=100)
    result = compare_module.compare(baseline, current)
    assert not result.ok
    assert any("Missing findings_count" in r for r in result.regressions)


def test_missing_wall_time_skips_perf_check(compare_module):
    """If wall_time isn't recorded (e.g., legacy baseline), skip
    the perf check rather than failing — but DO surface the gap
    in the notes."""
    baseline = {"project": "flask", "metrics": {"findings_count": 100}}
    current = _baseline(findings=100, wall_time=30.0)
    result = compare_module.compare(baseline, current)
    # findings match → no regression
    assert result.ok
    assert any("Missing wall_time_sec" in n for n in result.notes)


def test_format_report_first_line_is_verdict(compare_module):
    """CI log scrapers grep for the verdict. Must be on line 1."""
    baseline = _baseline(findings=100)
    current = _baseline(findings=100)
    result = compare_module.compare(baseline, current)
    report = compare_module.format_report(result)
    assert report.startswith("[PASS] flask\n") or report == "[PASS] flask"

    # Failure path
    baseline = _baseline(findings=100)
    current = _baseline(findings=50)
    result = compare_module.compare(baseline, current)
    report = compare_module.format_report(result)
    assert report.startswith("[FAIL] flask")


def test_cli_returns_nonzero_on_regression(compare_module, tmp_path):
    """Invoking via the _main entry point returns 1 on regression,
    so the CI job step fails."""
    import yaml as _yaml
    baseline_path = tmp_path / "baseline.yaml"
    current_path = tmp_path / "current.yaml"
    baseline_path.write_text(_yaml.safe_dump(_baseline(findings=100)))
    current_path.write_text(_yaml.safe_dump(_baseline(findings=50)))
    rc = compare_module._main([
        "--baseline", str(baseline_path),
        "--current", str(current_path),
    ])
    assert rc == 1


def test_cli_returns_zero_on_pass(compare_module, tmp_path):
    """No regression → exit 0."""
    import yaml as _yaml
    baseline_path = tmp_path / "baseline.yaml"
    current_path = tmp_path / "current.yaml"
    baseline_path.write_text(_yaml.safe_dump(_baseline(findings=100)))
    current_path.write_text(_yaml.safe_dump(_baseline(findings=100)))
    rc = compare_module._main([
        "--baseline", str(baseline_path),
        "--current", str(current_path),
    ])
    assert rc == 0
