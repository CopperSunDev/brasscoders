"""Unit tests for the Pysa interprocedural taint scanner.

Don't require `pyre` or typeshed to be installed; subprocess is mocked.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from brass.models.finding import FindingType, Severity
from brass.scanners.pysa_taint_scanner import PysaTaintScanner


def _make_project(tmp_path: Path) -> Path:
    src = tmp_path / "app.py"
    src.write_text(
        "import sqlite3\n"
        "def get_user(uid: str):\n"
        "    cur: sqlite3.Cursor = sqlite3.connect('x').cursor()\n"
        "    cur.execute(f'SELECT * FROM users WHERE id = {uid}')\n"
        "    return cur.fetchone()\n"
    )
    return tmp_path


class _StubResult:
    def __init__(self, stdout="", returncode=0, stderr=""):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _pyre_row(path="app.py", line=4, code=5001, define="app.get_user", name="SQL injection"):
    return {
        "path": path,
        "line": line,
        "column": 16,
        "stop_line": line,
        "stop_column": 35,
        "code": code,
        "name": name,
        "description": f"{name} [{code}]: User-controlled input flows into SQL execution",
        "define": define,
    }


# ---------------------------------------------------------------- availability


def test_scan_soft_fails_when_pyre_binary_missing(tmp_path):
    _make_project(tmp_path)
    scanner = PysaTaintScanner(str(tmp_path))
    with patch("brass.scanners.pysa_taint_scanner.shutil.which", return_value=None):
        assert scanner.scan() == []


def test_scan_soft_fails_when_typeshed_missing(tmp_path, monkeypatch):
    """Pyre is on PATH but typeshed isn't anywhere → soft-fail clean."""
    _make_project(tmp_path)
    scanner = PysaTaintScanner(str(tmp_path))
    monkeypatch.delenv("BRASS_TYPESHED", raising=False)
    with patch("brass.scanners.pysa_taint_scanner.shutil.which", return_value="/usr/bin/pyre"):
        with patch.object(PysaTaintScanner, "_locate_typeshed", staticmethod(lambda: None)):
            assert scanner.scan() == []


def test_scan_skips_projects_with_no_python(tmp_path):
    """Pysa is Python-only; non-Python projects short-circuit cheaply."""
    (tmp_path / "hello.txt").write_text("not python")
    scanner = PysaTaintScanner(str(tmp_path))
    with patch("brass.scanners.pysa_taint_scanner.shutil.which", return_value="/usr/bin/pyre"):
        with patch.object(PysaTaintScanner, "_locate_typeshed", staticmethod(lambda: "/tmp/typeshed")):
            # subprocess.run must NOT be called.
            with patch("brass.scanners.pysa_taint_scanner.subprocess.run") as run:
                assert scanner.scan() == []
                run.assert_not_called()


def test_scan_skips_above_python_file_threshold(tmp_path, monkeypatch):
    """OOM guardrail (2026-05-21): when the project has more than
    the active cap of analyzable .py files, skip Pysa entirely with
    a clear last_run_status reason. Other scanners continue to run.
    BRASS_FORCE_PYSA=1 overrides.

    Pin ``BRASS_PYSA_MAX_FILES=1000`` so the test exercises the cap
    deterministically regardless of host RAM (the 2026-05-22 auto-
    detect path varies the default by available memory: 5,000 on
    8 GB, ~6,600 on 16 GB, ~13,000 on 32 GB).
    """
    _make_project(tmp_path)
    monkeypatch.setenv("BRASS_PYSA_MAX_FILES", "1000")
    scanner = PysaTaintScanner(str(tmp_path))

    with patch("brass.scanners.pysa_taint_scanner.shutil.which", return_value="/usr/bin/pyre"):
        with patch.object(PysaTaintScanner, "_locate_typeshed", staticmethod(lambda: "/tmp/typeshed")):
            with patch.object(PysaTaintScanner, "_count_python_sources",
                              return_value=2000):  # 2x the explicit cap
                with patch("brass.scanners.pysa_taint_scanner.subprocess.run") as run:
                    findings = scanner.scan()
                    # No subprocess: skipped before staging.
                    run.assert_not_called()

    assert findings == []
    assert scanner.last_run_status is not None
    status, reason = scanner.last_run_status
    assert status == "skipped"
    assert "Python files" in reason
    assert "BRASS_FORCE_PYSA=1" in reason


def test_pysa_max_python_files_scales_with_host_ram(monkeypatch):
    """2026-05-22 RAM-aware cap: ``_pysa_max_python_files()`` returns
    a value scaled to detected host RAM when no env override is set.
    Floor at ``_PYSA_DEFAULT_MAX_PYTHON_FILES`` so small-RAM hosts
    don't get a tighter cap than the validated baseline.
    """
    from brass.scanners import pysa_taint_scanner as mod
    monkeypatch.delenv("BRASS_PYSA_MAX_FILES", raising=False)

    # 16 GB → ~6,400 files (above the 5,000 default).
    with patch.object(mod, "_detect_total_ram_bytes",
                      return_value=16 * 1024 * 1024 * 1024):
        cap = mod._pysa_max_python_files()
    assert cap > mod._PYSA_DEFAULT_MAX_PYTHON_FILES
    assert 6000 <= cap <= 7000

    # 32 GB → ~13,000.
    with patch.object(mod, "_detect_total_ram_bytes",
                      return_value=32 * 1024 * 1024 * 1024):
        cap = mod._pysa_max_python_files()
    assert 12000 <= cap <= 14000

    # 8 GB → math says ~3,300 but floor at default 5,000.
    with patch.object(mod, "_detect_total_ram_bytes",
                      return_value=8 * 1024 * 1024 * 1024):
        cap = mod._pysa_max_python_files()
    assert cap == mod._PYSA_DEFAULT_MAX_PYTHON_FILES

    # Detection failure (e.g. Windows) → default.
    with patch.object(mod, "_detect_total_ram_bytes", return_value=None):
        cap = mod._pysa_max_python_files()
    assert cap == mod._PYSA_DEFAULT_MAX_PYTHON_FILES

    # Env override always wins over auto-detect.
    monkeypatch.setenv("BRASS_PYSA_MAX_FILES", "42")
    with patch.object(mod, "_detect_total_ram_bytes",
                      return_value=64 * 1024 * 1024 * 1024):
        cap = mod._pysa_max_python_files()
    assert cap == 42


def test_scan_force_pysa_override_bypasses_threshold(tmp_path, monkeypatch):
    """``BRASS_FORCE_PYSA=1`` lets an operator who knows their machine
    has the headroom run Pysa on big codebases. The override skips the
    file-count guardrail entirely — proven by asserting that
    ``_run_pysa`` was actually invoked (the prior version of this
    test only checked the skip-message text, which a future rewrite
    could silently invalidate)."""
    from brass.scanners import pysa_taint_scanner as mod
    _make_project(tmp_path)
    scanner = PysaTaintScanner(str(tmp_path))
    monkeypatch.setenv("BRASS_FORCE_PYSA", "1")

    with patch("brass.scanners.pysa_taint_scanner.shutil.which", return_value="/usr/bin/pyre"):
        with patch.object(PysaTaintScanner, "_locate_typeshed", staticmethod(lambda: "/tmp/typeshed")):
            with patch.object(PysaTaintScanner, "_count_python_sources",
                              return_value=mod._PYSA_DEFAULT_MAX_PYTHON_FILES * 10):
                with patch.object(PysaTaintScanner, "_run_pysa",
                                  side_effect=RuntimeError("stub")) as mock_pysa:
                    scanner.scan()

    # Load-bearing assertion: the override must let execution reach
    # _run_pysa. The downstream RuntimeError is incidental (we don't
    # have a real pyre binary in the test env).
    mock_pysa.assert_called_once()


def test_force_pysa_accepts_common_truthy_values(tmp_path, monkeypatch):
    """``BRASS_FORCE_PYSA`` accepts the same truthy spellings users
    expect from other tools / dotenv files: 1/true/yes/on (any case,
    whitespace tolerated). Avoids the surprise where ``=true`` is
    silently ignored because the gate checks for the literal "1"."""
    from brass.scanners import pysa_taint_scanner as mod
    _make_project(tmp_path)

    for truthy in ("1", "true", "TRUE", "yes", "ON", " 1\n", "true "):
        scanner = PysaTaintScanner(str(tmp_path))
        monkeypatch.setenv("BRASS_FORCE_PYSA", truthy)
        with patch("brass.scanners.pysa_taint_scanner.shutil.which", return_value="/usr/bin/pyre"):
            with patch.object(PysaTaintScanner, "_locate_typeshed", staticmethod(lambda: "/tmp/typeshed")):
                with patch.object(PysaTaintScanner, "_count_python_sources",
                                  return_value=mod._PYSA_DEFAULT_MAX_PYTHON_FILES * 10):
                    with patch.object(PysaTaintScanner, "_run_pysa",
                                      side_effect=RuntimeError("stub")) as mock_pysa:
                        scanner.scan()
        assert mock_pysa.called, (
            f"BRASS_FORCE_PYSA={truthy!r} should be truthy but the "
            f"guardrail still tripped (scan never reached _run_pysa)"
        )

    # And the inverse: empty / falsy values must NOT bypass.
    for falsy in ("", "0", "no", "false", "off"):
        scanner = PysaTaintScanner(str(tmp_path))
        monkeypatch.setenv("BRASS_FORCE_PYSA", falsy)
        with patch("brass.scanners.pysa_taint_scanner.shutil.which", return_value="/usr/bin/pyre"):
            with patch.object(PysaTaintScanner, "_locate_typeshed", staticmethod(lambda: "/tmp/typeshed")):
                with patch.object(PysaTaintScanner, "_count_python_sources",
                                  return_value=mod._PYSA_DEFAULT_MAX_PYTHON_FILES * 10):
                    with patch.object(PysaTaintScanner, "_run_pysa") as mock_pysa:
                        scanner.scan()
        assert not mock_pysa.called, (
            f"BRASS_FORCE_PYSA={falsy!r} should NOT bypass the guardrail; "
            f"_run_pysa was called anyway"
        )


def test_brass_pysa_max_files_env_override(tmp_path, monkeypatch):
    """An operator who knows their machine can handle more (or wants
    a tighter cap for a CI runner) sets ``BRASS_PYSA_MAX_FILES=N``.
    Verify both the lower-cap and higher-cap directions."""
    _make_project(tmp_path)
    scanner = PysaTaintScanner(str(tmp_path))

    # Tighter cap: a project under the default 5000 but over 100 should skip.
    monkeypatch.setenv("BRASS_PYSA_MAX_FILES", "100")
    monkeypatch.delenv("BRASS_FORCE_PYSA", raising=False)
    with patch("brass.scanners.pysa_taint_scanner.shutil.which", return_value="/usr/bin/pyre"):
        with patch.object(PysaTaintScanner, "_locate_typeshed", staticmethod(lambda: "/tmp/typeshed")):
            with patch.object(PysaTaintScanner, "_count_python_sources", return_value=200):
                with patch.object(PysaTaintScanner, "_run_pysa") as mock_pysa:
                    scanner.scan()
    assert not mock_pysa.called, "tighter custom cap should skip Pysa"
    assert "100" in (scanner.last_run_status[1] if scanner.last_run_status else "")

    # Looser cap: a project at 10000 with cap raised to 20000 should run.
    scanner = PysaTaintScanner(str(tmp_path))
    monkeypatch.setenv("BRASS_PYSA_MAX_FILES", "20000")
    with patch("brass.scanners.pysa_taint_scanner.shutil.which", return_value="/usr/bin/pyre"):
        with patch.object(PysaTaintScanner, "_locate_typeshed", staticmethod(lambda: "/tmp/typeshed")):
            with patch.object(PysaTaintScanner, "_count_python_sources", return_value=10000):
                with patch.object(PysaTaintScanner, "_run_pysa",
                                  side_effect=RuntimeError("stub")) as mock_pysa:
                    scanner.scan()
    assert mock_pysa.called, "looser custom cap should let Pysa run"


# -------------------------------------- scanner status (loose end #8)


def test_last_run_status_pyre_binary_missing(tmp_path):
    """When the pyre binary isn't on PATH, scan returns [] AND
    last_run_status flags 'skipped' with a discoverable reason."""
    _make_project(tmp_path)
    scanner = PysaTaintScanner(str(tmp_path))
    with patch("brass.scanners.pysa_taint_scanner.shutil.which", return_value=None):
        assert scanner.scan() == []
    assert scanner.last_run_status is not None
    status, reason = scanner.last_run_status
    assert status == "skipped"
    assert "pyre" in reason.lower() and "path" in reason.lower()


def test_last_run_status_typeshed_missing(tmp_path, monkeypatch):
    """When typeshed isn't found, scan returns [] AND last_run_status
    explicitly identifies the missing-typeshed case (distinct from the
    missing-pyre-binary case)."""
    _make_project(tmp_path)
    scanner = PysaTaintScanner(str(tmp_path))
    monkeypatch.delenv("BRASS_TYPESHED", raising=False)
    with patch("brass.scanners.pysa_taint_scanner.shutil.which", return_value="/usr/bin/pyre"):
        with patch.object(PysaTaintScanner, "_locate_typeshed", staticmethod(lambda: None)):
            assert scanner.scan() == []
    assert scanner.last_run_status is not None
    status, reason = scanner.last_run_status
    assert status == "skipped"
    assert "typeshed" in reason.lower()


def test_last_run_status_no_python_sources(tmp_path):
    """Non-Python project → skipped with reason."""
    (tmp_path / "hello.txt").write_text("not python")
    scanner = PysaTaintScanner(str(tmp_path))
    with patch("brass.scanners.pysa_taint_scanner.shutil.which", return_value="/usr/bin/pyre"):
        with patch.object(PysaTaintScanner, "_locate_typeshed", staticmethod(lambda: "/tmp/typeshed")):
            assert scanner.scan() == []
    assert scanner.last_run_status is not None
    status, reason = scanner.last_run_status
    assert status == "skipped"
    assert ".py" in reason or "python" in reason.lower()


def test_last_run_status_resets_between_runs(tmp_path):
    """A successful re-run must clear the stale 'skipped' from a prior
    failed run. Otherwise watch-mode loops would carry stale signals."""
    _make_project(tmp_path)
    scanner = PysaTaintScanner(str(tmp_path))
    # First run: skipped (pyre missing)
    with patch("brass.scanners.pysa_taint_scanner.shutil.which", return_value=None):
        scanner.scan()
    assert scanner.last_run_status is not None
    first_reason = scanner.last_run_status[1]
    assert "PATH" in first_reason

    # Reset the cached _available so second run actually re-runs the check.
    scanner._available = None

    # Second run: scan() entry resets last_run_status; we then short-circuit
    # via no-python-sources after pyre+typeshed succeed.
    (tmp_path / "app.py").unlink()  # _make_project creates app.py
    (tmp_path / "nothing.txt").write_text("x")
    with patch("brass.scanners.pysa_taint_scanner.shutil.which", return_value="/usr/bin/pyre"):
        with patch.object(PysaTaintScanner, "_locate_typeshed", staticmethod(lambda: "/tmp/typeshed")):
            scanner.scan()
    # The key invariant: the second run's status must NOT carry the
    # stale 'pyre binary not on PATH' message from run 1. Positively
    # assert the new-run reason matches the no-python-sources path,
    # so this test catches both reset failures AND wrong-reason
    # regressions in the no-python skip site.
    assert scanner.last_run_status is not None
    status, reason = scanner.last_run_status
    assert status == "skipped"
    assert "PATH" not in reason  # would be stale carry-over from run 1
    assert ".py" in reason  # the no-python-sources reason


# ---------------------------------------------------------------- JSON parse


def test_scan_parses_pysa_json_into_findings(tmp_path):
    _make_project(tmp_path)
    scanner = PysaTaintScanner(str(tmp_path))

    rows = [_pyre_row(path="app.py", line=4, code=5001, define="app.get_user")]
    # Pyre emits log lines before the JSON array.
    pyre_output = (
        " Analysis fixpoint started ...\n"
        " Found 1 issues\n"
        + json.dumps(rows)
    )

    with patch("brass.scanners.pysa_taint_scanner.shutil.which", return_value="/usr/bin/pyre"):
        with patch.object(PysaTaintScanner, "_locate_typeshed", staticmethod(lambda: "/tmp/typeshed")):
            with patch(
                "brass.scanners.pysa_taint_scanner.subprocess.run",
                return_value=_StubResult(stdout=pyre_output, returncode=1),
            ):
                findings = scanner.scan()

    assert len(findings) == 1
    f = findings[0]
    assert f.type == FindingType.SECURITY
    assert f.severity == Severity.CRITICAL
    assert f.file_path == "app.py"
    assert f.line_number == 4
    assert f.metadata["taint_kind"] == "sql_injection"
    assert f.metadata["pysa_rule_code"] == 5001
    assert f.metadata["defining_function"] == "app.get_user"
    assert f.detected_by == "PysaTaintScanner"


def test_scan_handles_multiple_rule_codes(tmp_path):
    _make_project(tmp_path)
    scanner = PysaTaintScanner(str(tmp_path))

    rows = [
        _pyre_row(line=4, code=5001),                              # SQL
        _pyre_row(line=10, code=5002, name="Command injection"),   # cmd
        _pyre_row(line=20, code=5004, name="SSRF"),                # SSRF
    ]
    pyre_output = "banner\n" + json.dumps(rows)

    with patch("brass.scanners.pysa_taint_scanner.shutil.which", return_value="/usr/bin/pyre"):
        with patch.object(PysaTaintScanner, "_locate_typeshed", staticmethod(lambda: "/tmp/typeshed")):
            with patch(
                "brass.scanners.pysa_taint_scanner.subprocess.run",
                return_value=_StubResult(stdout=pyre_output, returncode=1),
            ):
                findings = scanner.scan()

    kinds = {f.metadata["taint_kind"] for f in findings}
    assert kinds == {"sql_injection", "command_injection", "ssrf"}
    # SSRF should be HIGH, not CRITICAL (per RULE_CODE_TO_KIND).
    ssrf = next(f for f in findings if f.metadata["taint_kind"] == "ssrf")
    assert ssrf.severity == Severity.HIGH


def test_scan_returns_empty_on_non_json_output(tmp_path):
    _make_project(tmp_path)
    scanner = PysaTaintScanner(str(tmp_path))
    with patch("brass.scanners.pysa_taint_scanner.shutil.which", return_value="/usr/bin/pyre"):
        with patch.object(PysaTaintScanner, "_locate_typeshed", staticmethod(lambda: "/tmp/typeshed")):
            with patch(
                "brass.scanners.pysa_taint_scanner.subprocess.run",
                return_value=_StubResult(stdout="just log lines, no JSON", returncode=2),
            ):
                assert scanner.scan() == []


def test_scan_drops_findings_outside_project(tmp_path):
    _make_project(tmp_path)
    scanner = PysaTaintScanner(str(tmp_path))

    # A path that resolves outside the project root.
    rows = [_pyre_row(path="../../etc/passwd", line=1)]
    pyre_output = "banner\n" + json.dumps(rows)

    with patch("brass.scanners.pysa_taint_scanner.shutil.which", return_value="/usr/bin/pyre"):
        with patch.object(PysaTaintScanner, "_locate_typeshed", staticmethod(lambda: "/tmp/typeshed")):
            with patch(
                "brass.scanners.pysa_taint_scanner.subprocess.run",
                return_value=_StubResult(stdout=pyre_output, returncode=1),
            ):
                assert scanner.scan() == []


def test_extract_json_array_handles_bracketed_log_prefixes():
    """Pyre's log lines may contain bracketed prefixes — make sure we find
    the JSON array even when '[' appears in log text."""
    rows = [{"path": "app.py", "line": 4, "code": 5001, "define": "app.f", "name": "SQL"}]
    text = "[INFO] starting\n[WARN] whatever\n[" + json.dumps(rows[0]) + "]"
    result = PysaTaintScanner._extract_json_array(text)
    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]["code"] == 5001


def test_extract_json_array_returns_none_on_no_array():
    assert PysaTaintScanner._extract_json_array("no array here") is None
    assert PysaTaintScanner._extract_json_array("") is None


def test_reclaim_schema_orphans_noop_when_schema_matches(tmp_path):
    """Steady state: .schema matches _CACHE_SCHEMA → no sweep, returns 0."""
    cache_root = tmp_path / "pysa-state"
    cache_root.mkdir()
    (cache_root / ".schema").write_text(PysaTaintScanner._CACHE_SCHEMA)
    # Plant a fake project cache subdir; sweep must NOT touch it.
    survivor = cache_root / "0123456789abcdef"
    survivor.mkdir()
    (survivor / "pysa.cache").write_bytes(b"\x00" * 100)

    removed = PysaTaintScanner._reclaim_schema_orphans(cache_root)
    assert removed == 0
    assert survivor.exists()
    assert (survivor / "pysa.cache").exists()


def test_reclaim_schema_orphans_sweeps_when_marker_absent(tmp_path):
    """First-run-after-upgrade pattern: .schema doesn't exist yet but
    project subdirs do (from a previous brass version's cache).
    Everything sweeps; marker is written."""
    cache_root = tmp_path / "pysa-state"
    cache_root.mkdir()
    # Plant two fake project caches with no .schema marker.
    for i in range(2):
        d = cache_root / f"hash{i:016x}"
        d.mkdir()
        (d / "pysa.cache").write_bytes(b"\x00" * 100)

    removed = PysaTaintScanner._reclaim_schema_orphans(cache_root)
    assert removed == 2
    assert list(p for p in cache_root.iterdir() if p.is_dir()) == []
    # Marker must be written with the current schema value.
    marker = cache_root / ".schema"
    assert marker.exists()
    assert marker.read_text().strip() == PysaTaintScanner._CACHE_SCHEMA


def test_reclaim_schema_orphans_sweeps_when_schema_bumped(tmp_path):
    """Canonical case from the loose-ends doc: _CACHE_SCHEMA bumps,
    every existing subdir becomes unreachable, sweep reclaims them."""
    cache_root = tmp_path / "pysa-state"
    cache_root.mkdir()
    # Simulate prior cache contents from an older schema.
    (cache_root / ".schema").write_text("v0_ancient")
    for i in range(3):
        d = cache_root / f"oldhash{i:014x}"
        d.mkdir()
        (d / "pysa.cache").write_bytes(b"\x00" * 100)

    removed = PysaTaintScanner._reclaim_schema_orphans(cache_root)
    assert removed == 3
    # Marker rewritten to current schema; lock/marker preserved at root.
    assert (cache_root / ".schema").read_text().strip() == PysaTaintScanner._CACHE_SCHEMA
    assert list(p for p in cache_root.iterdir() if p.is_dir()) == []


def test_reclaim_schema_orphans_noop_when_cache_root_absent(tmp_path):
    """No cache root yet (fresh install, never scanned anything) → no-op,
    no exception, no marker file created."""
    cache_root = tmp_path / "does-not-exist"
    assert not cache_root.exists()
    removed = PysaTaintScanner._reclaim_schema_orphans(cache_root)
    assert removed == 0
    assert not cache_root.exists()  # Sweep must not auto-create the root


def test_typeshed_env_override(monkeypatch, tmp_path):
    fake_typeshed = tmp_path / "ts"
    (fake_typeshed / "stdlib").mkdir(parents=True)
    monkeypatch.setenv("BRASS_TYPESHED", str(fake_typeshed))
    assert PysaTaintScanner._locate_typeshed() == str(fake_typeshed)


def test_typeshed_env_override_rejects_non_typeshed_dir(monkeypatch, tmp_path):
    """BRASS_TYPESHED must point at something with a stdlib/ subdir.

    Without this check, setting BRASS_TYPESHED=/etc would silently be
    accepted and Pyre would try to load /etc as a typeshed bundle.

    Disables auto-fetch via BRASS_OFFLINE=1 so the test focuses on the
    search-path-rejection logic without triggering a real git clone.
    """
    not_typeshed = tmp_path / "random_dir"
    not_typeshed.mkdir()  # exists, but no stdlib/
    monkeypatch.setenv("BRASS_TYPESHED", str(not_typeshed))
    monkeypatch.setenv("BRASS_OFFLINE", "1")
    # And ensure the default search paths don't accidentally rescue us.
    with patch(
        "brass.scanners.pysa_taint_scanner.TYPESHED_SEARCH_PATHS",
        (str(tmp_path / "nope"),),
    ):
        assert PysaTaintScanner._locate_typeshed() is None


def test_pysa_timeout_default_floor_when_no_file_count(monkeypatch):
    """When file count is unknown (caller didn't pass one), the helper
    returns the static floor — 600s. Safest default for a small project
    that can recover quickly if Pysa breaks. Also pins floor behavior
    for degenerate inputs: 0 (empty project), -5 (buggy caller)."""
    from brass.scanners.pysa_taint_scanner import _pysa_analyze_timeout_seconds

    monkeypatch.delenv("BRASS_PYSA_TIMEOUT_SECONDS", raising=False)
    assert _pysa_analyze_timeout_seconds() == 600
    assert _pysa_analyze_timeout_seconds(None) == 600
    assert _pysa_analyze_timeout_seconds(0) == 600
    assert _pysa_analyze_timeout_seconds(-5) == 600


def test_pysa_timeout_dynamic_sizing_below_floor(monkeypatch):
    """Small projects (≤1.2K Python files at 0.5s/file) stay at the
    600s floor — Pyre needs warmup time regardless of analysis size."""
    from brass.scanners.pysa_taint_scanner import _pysa_analyze_timeout_seconds

    monkeypatch.delenv("BRASS_PYSA_TIMEOUT_SECONDS", raising=False)
    assert _pysa_analyze_timeout_seconds(100) == 600
    assert _pysa_analyze_timeout_seconds(1000) == 600
    assert _pysa_analyze_timeout_seconds(1200) == 600  # 1200 * 0.5 = 600


def test_pysa_timeout_dynamic_sizing_mid_range(monkeypatch):
    """Mid-size projects scale linearly: 0.5s per file."""
    from brass.scanners.pysa_taint_scanner import _pysa_analyze_timeout_seconds

    monkeypatch.delenv("BRASS_PYSA_TIMEOUT_SECONDS", raising=False)
    # 2K files → 1000s (17 minutes)
    assert _pysa_analyze_timeout_seconds(2000) == 1000
    # 5K files → 2500s (~42 minutes, near the 5K hard-skip cap)
    assert _pysa_analyze_timeout_seconds(5000) == 2500
    # 9K files → 4500s (~75 min; matches frankenproject empirical
    # observation that ~3600s budget succeeds)
    assert _pysa_analyze_timeout_seconds(9000) == 4500


def test_pysa_timeout_dynamic_sizing_ceiling(monkeypatch):
    """Above 14,400 files (* 0.5 = 7200), timeout caps at 2hr.
    Beyond that the customer should split the scan, not wait longer."""
    from brass.scanners.pysa_taint_scanner import _pysa_analyze_timeout_seconds

    monkeypatch.delenv("BRASS_PYSA_TIMEOUT_SECONDS", raising=False)
    assert _pysa_analyze_timeout_seconds(14400) == 7200
    assert _pysa_analyze_timeout_seconds(50000) == 7200  # capped


def test_pysa_timeout_env_var_override_wins(monkeypatch):
    """BRASS_PYSA_TIMEOUT_SECONDS bypasses dynamic sizing entirely.
    Customer override always wins — both for fine-tuning beyond
    the ceiling and for fast-fail testing."""
    from brass.scanners.pysa_taint_scanner import _pysa_analyze_timeout_seconds

    monkeypatch.setenv("BRASS_PYSA_TIMEOUT_SECONDS", "300")
    # File count would suggest 4500s; env override wins.
    assert _pysa_analyze_timeout_seconds(9000) == 300

    monkeypatch.setenv("BRASS_PYSA_TIMEOUT_SECONDS", "10800")  # 3hr — above ceiling
    # File count would cap at 7200; env override is allowed past it.
    assert _pysa_analyze_timeout_seconds(9000) == 10800


def test_pysa_timeout_invalid_env_falls_back_to_dynamic(monkeypatch):
    """A non-integer BRASS_PYSA_TIMEOUT_SECONDS is ignored (with warning)
    and we fall through to dynamic sizing — NOT to the static floor.
    Otherwise a typo silently disables the dynamic sizing logic."""
    from brass.scanners.pysa_taint_scanner import _pysa_analyze_timeout_seconds

    monkeypatch.setenv("BRASS_PYSA_TIMEOUT_SECONDS", "thirty minutes")
    # Falls through to dynamic sizing with file count.
    assert _pysa_analyze_timeout_seconds(5000) == 2500


def test_pysa_timeout_negative_env_falls_back_to_dynamic(monkeypatch):
    """Non-positive env values fall through to dynamic sizing,
    not to the static floor. Same rationale: a misconfigured env
    shouldn't silently nullify the dynamic logic."""
    from brass.scanners.pysa_taint_scanner import _pysa_analyze_timeout_seconds

    monkeypatch.setenv("BRASS_PYSA_TIMEOUT_SECONDS", "0")
    assert _pysa_analyze_timeout_seconds(2000) == 1000

    monkeypatch.setenv("BRASS_PYSA_TIMEOUT_SECONDS", "-100")
    assert _pysa_analyze_timeout_seconds(2000) == 1000


def test_pysa_timeout_advice_normal_range():
    """Mid-range timeout: suggest doubled budget. The most common path
    when a customer's project grew past what the dynamic sizing
    predicted (e.g. they added a vendored dir)."""
    from brass.scanners.pysa_taint_scanner import PysaTaintScanner

    scanner = PysaTaintScanner("/tmp")  # path doesn't matter for this helper
    msg = scanner._build_timeout_advice(py_count=3000, timeout_used=1500)
    assert "timed out after 1500s" in msg
    assert "3,000 Python files" in msg
    assert "BRASS_PYSA_TIMEOUT_SECONDS=3600" in msg, (
        "doubled-budget suggestion (3000 → 3600 since 3000 < 3600 floor)"
    )
    assert ".brassignore" in msg


def test_pysa_timeout_advice_at_ceiling():
    """At the 2hr ceiling: do NOT suggest bumping further. Suggest
    narrowing scope (.brassignore / BRASS_PYSA_MAX_FILES). This is
    where the previous max(timeout*2, 3600) logic was wrong — at
    ceiling it would have suggested 14400s without context."""
    from brass.scanners.pysa_taint_scanner import (
        PysaTaintScanner,
        DYNAMIC_TIMEOUT_CEILING_SECONDS,
    )

    scanner = PysaTaintScanner("/tmp")
    msg = scanner._build_timeout_advice(
        py_count=15000,
        timeout_used=DYNAMIC_TIMEOUT_CEILING_SECONDS,
    )
    assert "2hr ceiling" in msg
    assert "15,000 Python files" in msg
    assert "BRASS_PYSA_MAX_FILES" in msg
    assert ".brassignore" in msg
    # Should NOT primarily push the customer to bump higher.
    # The escape-hatch mention of BRASS_PYSA_TIMEOUT_SECONDS is
    # acceptable but should be qualified.
    assert "rarely productive" in msg


def test_pysa_timeout_advice_small_project_at_floor():
    """Small project (< 500 files) that times out at the 600s floor
    almost certainly isn't a sizing problem — Pyre bug, OS pressure,
    recursive imports. Don't suggest a 6x bump; suggest diagnosis."""
    from brass.scanners.pysa_taint_scanner import (
        PysaTaintScanner,
        DEFAULT_ANALYZE_TIMEOUT_SECONDS,
    )

    scanner = PysaTaintScanner("/tmp")
    msg = scanner._build_timeout_advice(
        py_count=200,
        timeout_used=DEFAULT_ANALYZE_TIMEOUT_SECONDS,
    )
    assert "200 Python files" in msg
    assert "should complete in under 600s" in msg
    # Diagnostic path, not a routine "bump it up" suggestion
    assert "BRASS_PYSA_MAX_FILES=0" in msg
    assert "file an issue" in msg.lower() or ".brass/brass.log" in msg


def test_python_file_count_caches_across_methods(monkeypatch, tmp_path):
    """The cached count from scan()'s OOM-guardrail check should be
    used by _invoke_pyre_analyze and _resolved_python_file_count
    without re-walking the tree. Verified by counting how many times
    _count_python_sources is invoked."""
    from unittest.mock import patch
    from brass.scanners.pysa_taint_scanner import PysaTaintScanner

    scanner = PysaTaintScanner(str(tmp_path))

    # Simulate the OOM guardrail having seen 2000 files and cached it.
    scanner._python_file_count = 2000

    # _resolved_python_file_count should return the cached value WITHOUT
    # walking the tree.
    with patch.object(
        PysaTaintScanner, "_count_python_sources",
        autospec=True, return_value=999,  # would-be wrong answer
    ) as mock_count:
        result = scanner._resolved_python_file_count()
        assert result == 2000  # cached, not 999
        mock_count.assert_not_called()


def test_python_file_count_fallback_when_cache_empty(monkeypatch, tmp_path):
    """When the cache wasn't populated (e.g. BRASS_FORCE_PYSA=1 skipped
    the OOM guardrail), _resolved_python_file_count falls back to a
    fresh walk AND populates the cache for subsequent calls."""
    from unittest.mock import patch
    from brass.scanners.pysa_taint_scanner import PysaTaintScanner

    scanner = PysaTaintScanner(str(tmp_path))
    assert scanner._python_file_count is None  # cache not populated

    call_count = {"value": 0}

    def fake_count(self, early_break_at):
        call_count["value"] += 1
        return 1500

    with patch.object(PysaTaintScanner, "_count_python_sources", fake_count):
        # First call: cache miss → walks the tree.
        result1 = scanner._resolved_python_file_count()
        assert result1 == 1500
        assert call_count["value"] == 1

        # Second call: cache hit → no second walk.
        result2 = scanner._resolved_python_file_count()
        assert result2 == 1500
        assert call_count["value"] == 1  # still 1, not 2


def test_typeshed_autofetch_default_when_online(monkeypatch, tmp_path):
    """When typeshed is missing in standard paths AND no opt-out is set
    AND not in offline mode, _locate_typeshed auto-fetches into the
    BrassCoders cache. This is the post-2026-05-30 default — Pysa is a hard
    dependency, so silently skipping it after cache clear is a degraded
    product."""
    monkeypatch.delenv("BRASS_TYPESHED", raising=False)
    monkeypatch.delenv("BRASS_OFFLINE", raising=False)
    monkeypatch.delenv("BRASS_AUTOFETCH_TYPESHED", raising=False)

    with patch(
        "brass.scanners.pysa_taint_scanner.TYPESHED_SEARCH_PATHS",
        (str(tmp_path / "nope"),),
    ), patch.object(
        PysaTaintScanner, "_clone_typeshed",
        staticmethod(lambda target: True),  # simulate successful fetch
    ):
        result = PysaTaintScanner._locate_typeshed()

    assert result is not None
    assert ".cache/brass/typeshed" in result


def test_typeshed_autofetch_suppressed_by_offline(monkeypatch, tmp_path):
    """BRASS_OFFLINE=1 (set by the --offline CLI flag) must suppress
    typeshed auto-fetch. The offline contract wins over Pysa coverage."""
    monkeypatch.delenv("BRASS_TYPESHED", raising=False)
    monkeypatch.setenv("BRASS_OFFLINE", "1")

    clone_called = []
    with patch(
        "brass.scanners.pysa_taint_scanner.TYPESHED_SEARCH_PATHS",
        (str(tmp_path / "nope"),),
    ), patch.object(
        PysaTaintScanner, "_clone_typeshed",
        staticmethod(lambda target: clone_called.append(target) or True),
    ):
        result = PysaTaintScanner._locate_typeshed()

    assert result is None
    assert clone_called == [], "auto-fetch must not fire in offline mode"


def test_typeshed_autofetch_suppressed_by_explicit_zero(monkeypatch, tmp_path):
    """BRASS_AUTOFETCH_TYPESHED=0 is an explicit opt-out for customers
    who want Pysa off without using --offline (e.g. CI environments
    that have outbound network but want predictable scan time)."""
    monkeypatch.delenv("BRASS_TYPESHED", raising=False)
    monkeypatch.delenv("BRASS_OFFLINE", raising=False)
    monkeypatch.setenv("BRASS_AUTOFETCH_TYPESHED", "0")

    clone_called = []
    with patch(
        "brass.scanners.pysa_taint_scanner.TYPESHED_SEARCH_PATHS",
        (str(tmp_path / "nope"),),
    ), patch.object(
        PysaTaintScanner, "_clone_typeshed",
        staticmethod(lambda target: clone_called.append(target) or True),
    ):
        result = PysaTaintScanner._locate_typeshed()

    assert result is None
    assert clone_called == [], "auto-fetch must not fire when explicitly opted out"


def test_pyre_invocation_passes_no_verify(tmp_path):
    """--no-verify is load-bearing: without it Pyre exits 10 on any model
    referencing a library the customer doesn't have installed (flask,
    django, sqlalchemy). Guard against accidental removal."""
    _make_project(tmp_path)
    scanner = PysaTaintScanner(str(tmp_path))

    captured_cmd = []

    def _capture(cmd, **kw):
        captured_cmd.extend(cmd)
        return _StubResult(stdout="[]", returncode=0)

    with patch("brass.scanners.pysa_taint_scanner.shutil.which", return_value="/usr/bin/pyre"):
        with patch.object(PysaTaintScanner, "_locate_typeshed", staticmethod(lambda: "/tmp/typeshed")):
            with patch("brass.scanners.pysa_taint_scanner.subprocess.run", side_effect=_capture):
                scanner.scan()

    assert "analyze" in captured_cmd
    assert "--no-verify" in captured_cmd


# ---------------------------------------------------------------- --use-cache


def test_pysa_cache_dir_is_persistent(tmp_path, monkeypatch):
    """Same project always maps to the same cache dir; different
    projects map to different dirs. This is the contract that makes
    `--use-cache` actually work — the cache lives at the returned path
    and must survive across scans of the same project.

    Also verifies the resolve-input contract: a relative-vs-absolute or
    trailing-slash variant of the same project path produces the same
    cache dir, so `brasscoders scan ./foo` and `brasscoders scan foo` share a
    cache and don't each cold-start.
    """
    cache_root = tmp_path / "cache_root"
    monkeypatch.setenv("BRASS_PYSA_CACHE_ROOT", str(cache_root))

    project_a = tmp_path / "project_a"
    project_b = tmp_path / "project_b"
    project_a.mkdir()
    project_b.mkdir()

    a1 = PysaTaintScanner._pysa_cache_dir(project_a)
    a2 = PysaTaintScanner._pysa_cache_dir(project_a)
    b1 = PysaTaintScanner._pysa_cache_dir(project_b)

    assert a1 == a2, "same project must map to the same cache dir"
    assert a1 != b1, "different projects must get different cache dirs"
    # And the cache dirs land under the configured cache root.
    assert str(a1).startswith(str(cache_root))

    # Path-shape normalization: trailing slash / unresolved relative
    # paths must produce the same digest as the canonical resolved form.
    a_trailing = PysaTaintScanner._pysa_cache_dir(Path(str(project_a) + "/"))
    assert a1 == a_trailing, "trailing slash must not change the cache dir"


def test_pyre_invocation_passes_use_cache(tmp_path):
    """--use-cache is what makes repeat scans fast (Pysa stores call
    graph + taint queries in .pyre/pysa.cache). Guard against
    accidental removal — losing the flag silently regresses repeat-scan
    perf without any test failure."""
    _make_project(tmp_path)
    scanner = PysaTaintScanner(str(tmp_path))

    captured_cmd = []

    def _capture(cmd, **kw):
        captured_cmd.extend(cmd)
        return _StubResult(stdout="[]", returncode=0)

    with patch("brass.scanners.pysa_taint_scanner.shutil.which", return_value="/usr/bin/pyre"):
        with patch.object(PysaTaintScanner, "_locate_typeshed", staticmethod(lambda: "/tmp/typeshed")):
            with patch("brass.scanners.pysa_taint_scanner.subprocess.run", side_effect=_capture):
                scanner.scan()

    assert "--use-cache" in captured_cmd


def test_cache_corruption_recovery(tmp_path, monkeypatch):
    """If `pyre analyze` produces non-parseable output, wipe the cache
    dir and retry once. Validates the corruption-recovery path —
    without it a corrupted .pyre/pysa.cache poisons every subsequent
    scan until the user manually clears the cache.

    Uses BRASS_PYSA_CACHE_ROOT to redirect the cache away from the
    user's real `~/.cache/brass/pysa-state/`, so the test never writes
    to or removes anything outside `tmp_path`.
    """
    cache_root = tmp_path / "cache_root"
    monkeypatch.setenv("BRASS_PYSA_CACHE_ROOT", str(cache_root))

    _make_project(tmp_path)
    scanner = PysaTaintScanner(str(tmp_path))

    # Pre-populate the would-be cache dir with a sentinel file so we
    # can verify it gets wiped between attempts. Use the same path
    # the scanner will compute via _pysa_cache_dir.
    cache_dir = PysaTaintScanner._pysa_cache_dir(Path(str(tmp_path)).resolve())
    cache_dir.mkdir(parents=True, exist_ok=True)
    sentinel = cache_dir / "stale.cache"
    sentinel.write_text("stale data from a prior corrupted scan")

    # First subprocess call: garbage output (simulating cache corruption).
    # Second call: clean JSON array. The scanner should retry exactly once
    # and return the second-call findings.
    call_count = {"n": 0}

    def _sequenced(cmd, **kw):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _StubResult(stdout="garbage non-JSON output", returncode=2)
        # On retry the cache dir was wiped → sentinel gone.
        assert not sentinel.exists(), (
            "cache dir must be wiped between attempts; stale sentinel survived"
        )
        return _StubResult(stdout="[]", returncode=0)

    with patch("brass.scanners.pysa_taint_scanner.shutil.which", return_value="/usr/bin/pyre"):
        with patch.object(PysaTaintScanner, "_locate_typeshed", staticmethod(lambda: "/tmp/typeshed")):
            with patch("brass.scanners.pysa_taint_scanner.subprocess.run", side_effect=_sequenced):
                findings = scanner.scan()

    assert call_count["n"] == 2, "expected one retry after corruption"
    # Empty `[]` is a valid JSON array → zero findings, success path.
    assert findings == []


def test_row_to_finding_handles_wildcard_path_with_module_define(tmp_path):
    """When pyre emits path='*' (model-query findings), the scanner derives
    the actual source file from the defining function's module name."""
    src = tmp_path / "app.py"
    src.write_text("def get_user(): pass\n")
    scanner = PysaTaintScanner(str(tmp_path))

    rows = [{
        "path": "*",
        "line": 1,
        "code": 5001,
        "name": "SQL injection",
        "description": "X",
        "define": "app.get_user",
    }]
    payload = "banner\n" + json.dumps(rows)

    with patch("brass.scanners.pysa_taint_scanner.shutil.which", return_value="/usr/bin/pyre"):
        with patch.object(PysaTaintScanner, "_locate_typeshed", staticmethod(lambda: "/tmp/typeshed")):
            with patch(
                "brass.scanners.pysa_taint_scanner.subprocess.run",
                return_value=_StubResult(stdout=payload, returncode=1),
            ):
                findings = scanner.scan()

    assert len(findings) == 1
    assert findings[0].file_path == "app.py"


def test_row_to_finding_drops_unresolvable_wildcard_path(tmp_path):
    """If pyre emits path='*' and the defining function's module doesn't
    map to an on-disk file, drop the finding rather than guessing."""
    _make_project(tmp_path)  # has app.py, not whatever.py
    scanner = PysaTaintScanner(str(tmp_path))

    rows = [{
        "path": "*",
        "line": 1,
        "code": 5001,
        "name": "SQL injection",
        "define": "nonexistent_module.func",
    }]
    payload = "banner\n" + json.dumps(rows)

    with patch("brass.scanners.pysa_taint_scanner.shutil.which", return_value="/usr/bin/pyre"):
        with patch.object(PysaTaintScanner, "_locate_typeshed", staticmethod(lambda: "/tmp/typeshed")):
            with patch(
                "brass.scanners.pysa_taint_scanner.subprocess.run",
                return_value=_StubResult(stdout=payload, returncode=1),
            ):
                findings = scanner.scan()

    assert findings == []


def test_sandboxed_env_strips_attacker_keys():
    redirector_keys = ("PYTHONPATH", "PYRE_BINARY", "LD_PRELOAD")
    saved = {k: os.environ.get(k) for k in redirector_keys}
    for k in redirector_keys:
        os.environ[k] = "evil"
    try:
        env = PysaTaintScanner._sandboxed_env()
        for k in redirector_keys:
            assert k not in env, f"{k} should be stripped"
        assert "LANG" in env
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


# --- _prune_stale_entries (Phase C, 2026-05-16) ---

def _make_cache_entry(
    cache_root: Path,
    name: str,
    source_path: str | None = None,
    mtime_offset_days: int = 0,
) -> Path:
    """Create a fake pysa-state cache subdir for prune tests.

    `source_path=None` simulates a legacy (pre-manifest) entry;
    otherwise writes that path into `.source_path`. `mtime_offset_days`
    backdates the dir's mtime (negative = older).
    """
    import time as _time
    entry = cache_root / name
    entry.mkdir(parents=True)
    # Plant some content so the entry has weight in the size check.
    (entry / "pyre.cache").write_bytes(b"x" * (1024 * 1024))  # 1 MB filler
    if source_path is not None:
        (entry / PysaTaintScanner._SOURCE_PATH_FILENAME).write_text(
            source_path, encoding="utf-8"
        )
    if mtime_offset_days:
        target_mtime = _time.time() + mtime_offset_days * 86400
        os.utime(entry, (target_mtime, target_mtime))
    return entry


def test_prune_stale_entries_with_valid_manifest_keeps_entry(tmp_path: Path):
    """Manifest points at an existing project → entry is kept."""
    cache_root = tmp_path / "pysa-state"
    cache_root.mkdir()
    live_project = tmp_path / "alive"
    live_project.mkdir()
    entry = _make_cache_entry(cache_root, "hash_alive", source_path=str(live_project))
    # Force >threshold so the prune actually runs.
    (cache_root / "filler").write_bytes(
        b"y" * (PysaTaintScanner._STALE_GC_SIZE_THRESHOLD_BYTES + 1)
    )

    removed = PysaTaintScanner._prune_stale_entries(cache_root)

    assert removed == 0
    assert entry.is_dir()


def test_prune_stale_entries_with_missing_source_removes_entry(tmp_path: Path):
    """Manifest points at a path that no longer exists → entry is removed."""
    cache_root = tmp_path / "pysa-state"
    cache_root.mkdir()
    entry = _make_cache_entry(
        cache_root, "hash_dead",
        source_path=str(tmp_path / "does_not_exist"),
    )
    (cache_root / "filler").write_bytes(
        b"y" * (PysaTaintScanner._STALE_GC_SIZE_THRESHOLD_BYTES + 1)
    )

    removed = PysaTaintScanner._prune_stale_entries(cache_root)

    assert removed == 1
    assert not entry.exists()


def test_prune_stale_entries_mtime_fallback_for_legacy_entries(tmp_path: Path):
    """Pre-manifest entries: recent → kept, old → removed."""
    cache_root = tmp_path / "pysa-state"
    cache_root.mkdir()
    fresh = _make_cache_entry(
        cache_root, "hash_legacy_fresh",
        source_path=None,
        mtime_offset_days=-30,  # 30 days old; < 90d cutoff
    )
    old = _make_cache_entry(
        cache_root, "hash_legacy_old",
        source_path=None,
        mtime_offset_days=-120,  # 120 days old; > 90d cutoff
    )
    (cache_root / "filler").write_bytes(
        b"y" * (PysaTaintScanner._STALE_GC_SIZE_THRESHOLD_BYTES + 1)
    )

    removed = PysaTaintScanner._prune_stale_entries(cache_root)

    assert removed == 1
    assert fresh.is_dir()
    assert not old.exists()


def test_prune_stale_entries_below_threshold_is_noop(tmp_path: Path):
    """Small caches (< 200 MB threshold) bypass the prune entirely."""
    cache_root = tmp_path / "pysa-state"
    cache_root.mkdir()
    # This entry would be pruned (missing source) if the threshold check
    # didn't gate it, so a 0 return proves the size guard fired.
    entry = _make_cache_entry(
        cache_root, "hash_would_be_stale",
        source_path=str(tmp_path / "does_not_exist"),
    )

    removed = PysaTaintScanner._prune_stale_entries(cache_root)

    assert removed == 0
    assert entry.is_dir()


def test_prune_stale_entries_skips_top_level_marker_files(tmp_path: Path):
    """The `.schema` and `.gc.lock` siblings of per-project dirs must
    never be touched — they coordinate the schema-orphan reclaim and
    the lock would deadlock if removed mid-scan."""
    cache_root = tmp_path / "pysa-state"
    cache_root.mkdir()
    schema = cache_root / PysaTaintScanner._SCHEMA_MARKER_FILENAME
    schema.write_text("v1", encoding="utf-8")
    lock = cache_root / PysaTaintScanner._GC_LOCK_FILENAME
    lock.touch()
    (cache_root / "filler").write_bytes(
        b"y" * (PysaTaintScanner._STALE_GC_SIZE_THRESHOLD_BYTES + 1)
    )

    PysaTaintScanner._prune_stale_entries(cache_root)

    assert schema.is_file()
    assert lock.exists()


def test_prune_stale_entries_with_empty_manifest_falls_through_to_mtime(
    tmp_path: Path,
):
    """A truncated-write (zero-byte) ``.source_path`` must NOT trigger
    instant-stale. Treating empty manifest as stale would delete the
    entry on the next prune even though it's healthy and being
    actively written to — the empty file is a sign of a crash during
    ``write_text``, not of source-path absence. Falling through to
    mtime is the safe default for fresh-mtime entries."""
    import time as _time
    cache_root = tmp_path / "pysa-state"
    cache_root.mkdir()
    entry = _make_cache_entry(
        cache_root, "hash_truncated_manifest",
        source_path=None,
    )
    # Empty manifest — simulates a write_text crash mid-flush.
    (entry / PysaTaintScanner._SOURCE_PATH_FILENAME).write_text(
        "", encoding="utf-8",
    )
    # Fresh mtime → should be kept.
    _time.sleep(0.01)
    os.utime(entry, None)
    (cache_root / "filler").write_bytes(
        b"y" * (PysaTaintScanner._STALE_GC_SIZE_THRESHOLD_BYTES + 1)
    )

    removed = PysaTaintScanner._prune_stale_entries(cache_root)

    assert removed == 0
    assert entry.is_dir()


def test_source_path_manifest_survives_config_drift_invalidation(
    tmp_path: Path, monkeypatch
):
    """Regression: the `.source_path` manifest must be written AFTER
    `_invalidate_cache_on_config_change`, not before. Otherwise the
    invalidator's `rmtree(staging_path)` removes it on the first scan
    where the .pyre_configuration changed (e.g., the 2026-05-16 fix
    that added `search_path`), and Phase C's stale-entry detection
    silently loses the manifest for that project forever.
    """
    import shutil as _shutil

    # Pyre + typeshed presence isn't required — we exercise just up to
    # the manifest write by stubbing the pyre invocation.
    monkeypatch.setenv("BRASS_PYSA_CACHE_ROOT", str(tmp_path / "cache"))

    proj = _make_project(tmp_path)

    scanner = PysaTaintScanner(str(proj))
    # Pretend pyre + typeshed are available (skip the binary checks).
    scanner._available = True
    scanner._typeshed_path = str(tmp_path)  # any existing dir

    # Pre-seed an outdated config.sig so _invalidate_cache_on_config_change
    # fires its rmtree path on this scan.
    cache_dir = PysaTaintScanner._pysa_cache_dir(scanner.project_path)
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / PysaTaintScanner._CONFIG_SIG_FILENAME).write_text(
        "stale-signature-from-an-earlier-config", encoding="utf-8",
    )

    # Stub out pyre subprocess so the test doesn't need pyre installed.
    class _StubResult:
        returncode = 0
        stdout = "[]"
        stderr = ""
    with patch(
        "brass.scanners.pysa_taint_scanner.subprocess.run",
        return_value=_StubResult(),
    ):
        scanner._run_pysa()

    # Manifest must exist with the correct source path.
    manifest = cache_dir / PysaTaintScanner._SOURCE_PATH_FILENAME
    assert manifest.is_file(), (
        f"manifest missing at {manifest} — the write must happen AFTER "
        f"_invalidate_cache_on_config_change, not before"
    )
    assert manifest.read_text(encoding="utf-8") == str(scanner.project_path)
    # Sanity check: the invalidation's rmtree → mkdir path ran cleanly.
    # If the cache_dir somehow vanished, the manifest assert above would
    # already have failed, but asserting existence directly + checking
    # config.sig got freshly stamped locks in the post-rebuild contract.
    assert cache_dir.is_dir()
    sig = cache_dir / PysaTaintScanner._CONFIG_SIG_FILENAME
    assert sig.is_file()


def test_count_python_sources_short_circuits_at_threshold(tmp_path):
    """The big-monorepo guardrail uses ``_count_python_sources(early_break_at=N)``
    to avoid walking 14,000+ files just to learn that the count
    exceeds the cap. Confirm the short-circuit returns ``N+1`` on the
    very file that trips the limit, and matches the full count when
    the project is under cap. Discovered as untested code path in the
    2026-05-21 cumulative full-bugs review.
    """
    # Create 5 real .py files in the tmp project root.
    for i in range(5):
        (tmp_path / f"mod_{i}.py").write_text(f"x_{i} = 1\n")
    scanner = PysaTaintScanner(str(tmp_path))

    # Without short-circuit: counts all 5.
    full_count = scanner._count_python_sources()
    assert full_count == 5, f"expected 5 files, got {full_count}"

    # Short-circuit at 3: stops as soon as count reaches 4 (limit+1).
    truncated = scanner._count_python_sources(early_break_at=3)
    assert truncated == 4, (
        f"short-circuit should return limit+1=4 once the count "
        f"exceeds 3; got {truncated}"
    )

    # Short-circuit at a value >= total: returns the actual count.
    over = scanner._count_python_sources(early_break_at=100)
    assert over == 5, (
        f"when early_break_at > actual count, return the real count; "
        f"got {over}"
    )

    # Short-circuit at the exact count boundary: walks all files, no
    # short-circuit fires (returns the real count, NOT count+1).
    boundary = scanner._count_python_sources(early_break_at=5)
    assert boundary == 5
