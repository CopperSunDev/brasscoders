"""Unit tests for the per-scanner status reporting (loose end #8).

Covers the ScannerStatus dataclass + the builder-side surfacing in
statistics.yaml and ai_instructions.yaml. The orchestrator-side
contract (reading scanner.last_run_status and exception-capture) is
tested via end-to-end smoke in the manual acceptance flow.
"""

from __future__ import annotations

from datetime import datetime

import pytest

from brass.core.scanner_status import ScannerStatus
from brass.output.yaml_builders.statistics_builder import YAMLStatisticsBuilder
from brass.output.yaml_builders.ai_instructions_builder import YAMLAIInstructionsBuilder


def _status(name: str, status: str, reason: str | None = None, findings: int = 0, duration: float = 0.0) -> ScannerStatus:
    return ScannerStatus(name=name, status=status, reason=reason, finding_count=findings, duration_sec=duration)


def test_scanner_status_to_dict_shape():
    s = _status("pysa_taint", "skipped", "typeshed missing", 0, 0.002)
    d = s.to_dict()
    assert d == {
        "status": "skipped",
        "reason": "typeshed missing",
        "finding_count": 0,
        "duration_sec": 0.002,
    }


def test_scanner_status_is_ok_vs_degraded():
    assert _status("x", "ok").is_ok() is True
    assert _status("x", "ok").is_degraded() is False
    assert _status("x", "skipped", "y").is_degraded() is True
    assert _status("x", "errored", "y").is_degraded() is True


def test_statistics_builder_omits_scanner_health_when_none(tmp_path):
    """Without scanner_status kwarg, builder output is unchanged from
    before #8 (backward compat with callers that don't track status)."""
    b = YAMLStatisticsBuilder(str(tmp_path), datetime.now())
    out = b.build([])
    assert "scanner_health" not in out


def test_statistics_builder_emits_scanner_health_when_provided(tmp_path):
    b = YAMLStatisticsBuilder(str(tmp_path), datetime.now())
    status_map = {
        "pysa_taint": _status("pysa_taint", "skipped", "typeshed missing", 0, 0.002),
        "code": _status("code", "ok", None, 5, 14.9),
        "semgrep_taint": _status("semgrep_taint", "errored", "TimeoutExpired: 300s", 0, 300.0),
    }
    out = b.build([], scanner_status=status_map)

    health = out["scanner_health"]
    assert health["total_scanners"] == 3
    assert health["ok"] == 1
    assert health["skipped"] == 1
    assert health["errored"] == 1
    # Degraded scanners listed errored-first.
    degraded = health["degraded_scanners"]
    assert len(degraded) == 2
    assert degraded[0]["name"] == "semgrep_taint"
    assert degraded[0]["status"] == "errored"
    assert degraded[1]["name"] == "pysa_taint"
    assert degraded[1]["status"] == "skipped"


def test_statistics_builder_scanner_health_all_ok(tmp_path):
    b = YAMLStatisticsBuilder(str(tmp_path), datetime.now())
    status_map = {
        "pysa_taint": _status("pysa_taint", "ok", None, 3, 30.0),
        "code": _status("code", "ok", None, 5, 14.9),
    }
    out = b.build([], scanner_status=status_map)
    health = out["scanner_health"]
    assert health["ok"] == 2
    assert health["skipped"] == 0
    assert health["errored"] == 0
    assert health["degraded_scanners"] == []  # empty list, not absent key


def test_ai_instructions_omits_analysis_completeness_when_all_ok(tmp_path):
    b = YAMLAIInstructionsBuilder(str(tmp_path), datetime.now())
    status_map = {
        "pysa_taint": _status("pysa_taint", "ok", None, 3, 30.0),
    }
    out = b.build([], scanner_status=status_map)
    assert "analysis_completeness" not in out["executive_summary"]


def test_ai_instructions_omits_analysis_completeness_when_no_status(tmp_path):
    """Caller that doesn't pass scanner_status → field is absent. Same
    output as before #8 (no schema drift on the legacy code path)."""
    b = YAMLAIInstructionsBuilder(str(tmp_path), datetime.now())
    out = b.build([])
    assert "analysis_completeness" not in out["executive_summary"]


def test_ai_instructions_includes_analysis_completeness_when_degraded(tmp_path):
    b = YAMLAIInstructionsBuilder(str(tmp_path), datetime.now())
    status_map = {
        "pysa_taint": _status("pysa_taint", "skipped", "typeshed missing", 0, 0.002),
        "semgrep_taint": _status("semgrep_taint", "errored", "TimeoutExpired", 0, 300.0),
        "code": _status("code", "ok", None, 5, 14.9),
    }
    out = b.build([], scanner_status=status_map)
    summary = out["executive_summary"]
    assert "analysis_completeness" in summary
    completeness = summary["analysis_completeness"]
    assert completeness["status"] == "partial"
    assert "1 scanner skipped" in completeness["note"]
    assert "1 scanner errored" in completeness["note"]
    # Degraded list: errored-first.
    degraded = completeness["degraded"]
    assert len(degraded) == 2
    # Each entry is a single-key dict {scanner_name: reason}.
    assert "semgrep_taint" in degraded[0]
    assert "pysa_taint" in degraded[1]
    assert degraded[0]["semgrep_taint"] == "TimeoutExpired"
    assert degraded[1]["pysa_taint"] == "typeshed missing"


def test_ai_instructions_completeness_singular_plural(tmp_path):
    """One degraded scanner → 'skipped' (singular)."""
    b = YAMLAIInstructionsBuilder(str(tmp_path), datetime.now())
    status_map = {
        "pysa_taint": _status("pysa_taint", "skipped", "typeshed missing", 0, 0.002),
    }
    out = b.build([], scanner_status=status_map)
    note = out["executive_summary"]["analysis_completeness"]["note"]
    assert "1 scanner skipped" in note
    assert "scanners skipped" not in note  # singular form, not plural
