"""Unit tests for the ast-grep scanner. Don't require ast-grep on PATH."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from brass.models.finding import FindingType, Severity
from brass.scanners.ast_grep_scanner import AstGrepScanner


def _make_project(tmp_path: Path) -> Path:
    src = tmp_path / "db.py"
    src.write_text(
        "import sqlite3\n"
        "def find(uid):\n"
        "    c = sqlite3.connect('x').cursor()\n"
        "    c.execute(f'SELECT * FROM u WHERE id = {uid}')\n"
        "    return c.fetchone()\n"
    )
    return tmp_path


class _StubResult:
    def __init__(self, stdout="", returncode=0, stderr=""):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _row(path, line, rule_id="brass.python.sql-injection-execute-tainted-string", text="c.execute(f'...')"):
    return {
        "file": path,
        "range": {"start": {"line": line, "column": 4}, "end": {"line": line, "column": 30}},
        "ruleId": rule_id,
        "severity": "error",
        "message": "SQL execution with tainted string",
        "text": text,
    }


# ---------------------------------------------------------------- availability


def test_scan_soft_fails_when_binary_missing(tmp_path):
    _make_project(tmp_path)
    scanner = AstGrepScanner(str(tmp_path))
    with patch("brass.scanners.ast_grep_scanner.shutil.which", return_value=None):
        assert scanner.scan() == []


# ---------------------------------------------------------------- json parse


def test_scan_parses_json_output_into_findings(tmp_path):
    _make_project(tmp_path)
    scanner = AstGrepScanner(str(tmp_path))
    rows = [_row(str(tmp_path / "db.py"), 3)]  # 0-indexed → reported as line 4

    with patch("brass.scanners.ast_grep_scanner.shutil.which", return_value="/usr/bin/ast-grep"):
        with patch(
            "brass.scanners.ast_grep_scanner.subprocess.run",
            return_value=_StubResult(stdout=json.dumps(rows), returncode=1),
        ):
            findings = scanner.scan()

    assert len(findings) == 1
    f = findings[0]
    assert f.type == FindingType.SECURITY
    assert f.severity == Severity.MEDIUM
    assert f.file_path == "db.py"
    assert f.line_number == 4  # 0-indexed +1
    assert f.metadata["rule_id"].endswith("sql-injection-execute-tainted-string")
    assert f.detected_by == "AstGrepScanner"


def test_scan_treats_exit_code_1_as_success(tmp_path):
    """ast-grep exits 1 when findings exist. Must NOT be treated as scan failure."""
    _make_project(tmp_path)
    scanner = AstGrepScanner(str(tmp_path))
    rows = [_row(str(tmp_path / "db.py"), 3)]
    with patch("brass.scanners.ast_grep_scanner.shutil.which", return_value="/usr/bin/ast-grep"):
        with patch(
            "brass.scanners.ast_grep_scanner.subprocess.run",
            return_value=_StubResult(stdout=json.dumps(rows), returncode=1),
        ):
            assert len(scanner.scan()) == 1


def test_scan_treats_exit_code_2_as_failure(tmp_path):
    _make_project(tmp_path)
    scanner = AstGrepScanner(str(tmp_path))
    with patch("brass.scanners.ast_grep_scanner.shutil.which", return_value="/usr/bin/ast-grep"):
        with patch(
            "brass.scanners.ast_grep_scanner.subprocess.run",
            return_value=_StubResult(stdout="", returncode=2, stderr="boom"),
        ):
            assert scanner.scan() == []


def test_scan_drops_findings_with_path_outside_project(tmp_path):
    _make_project(tmp_path)
    scanner = AstGrepScanner(str(tmp_path))
    rows = [_row("/etc/passwd", 0)]
    with patch("brass.scanners.ast_grep_scanner.shutil.which", return_value="/usr/bin/ast-grep"):
        with patch(
            "brass.scanners.ast_grep_scanner.subprocess.run",
            return_value=_StubResult(stdout=json.dumps(rows), returncode=1),
        ):
            assert scanner.scan() == []


def test_scan_returns_empty_when_subprocess_returns_nonjson(tmp_path):
    _make_project(tmp_path)
    scanner = AstGrepScanner(str(tmp_path))
    with patch("brass.scanners.ast_grep_scanner.shutil.which", return_value="/usr/bin/ast-grep"):
        with patch(
            "brass.scanners.ast_grep_scanner.subprocess.run",
            return_value=_StubResult(stdout="garbage not json", returncode=1),
        ):
            assert scanner.scan() == []


def test_scan_returns_empty_when_no_targets(tmp_path):
    """No .py files → no semgrep invocation, empty result, no exception."""
    scanner = AstGrepScanner(str(tmp_path))
    with patch("brass.scanners.ast_grep_scanner.shutil.which", return_value="/usr/bin/ast-grep"):
        # subprocess.run must not be called.
        with patch("brass.scanners.ast_grep_scanner.subprocess.run") as run:
            assert scanner.scan() == []
            run.assert_not_called()


def test_sandboxed_env_strips_rust_redirectors():
    redirector_keys = ("RUSTUP_HOME", "CARGO_HOME", "RUST_LOG", "RUSTC_WRAPPER")
    saved = {k: os.environ.get(k) for k in redirector_keys}
    for k in redirector_keys:
        os.environ[k] = "evil"
    try:
        env = AstGrepScanner._sandboxed_env()
        for k in redirector_keys:
            assert k not in env, f"{k} should be stripped from sandbox env"
        assert "LANG" in env
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def test_scan_handles_line_zero_correctly(tmp_path):
    """0-indexed line 0 must become line 1, not None (bool-falsy trap)."""
    _make_project(tmp_path)
    scanner = AstGrepScanner(str(tmp_path))
    rows = [_row(str(tmp_path / "db.py"), 0)]
    with patch("brass.scanners.ast_grep_scanner.shutil.which", return_value="/usr/bin/ast-grep"):
        with patch(
            "brass.scanners.ast_grep_scanner.subprocess.run",
            return_value=_StubResult(stdout=json.dumps(rows), returncode=1),
        ):
            findings = scanner.scan()
    assert len(findings) == 1
    assert findings[0].line_number == 1


def test_scan_exit_code_zero_with_empty_array(tmp_path):
    """No findings: exit 0 + stdout '[]' — must return empty cleanly."""
    _make_project(tmp_path)
    scanner = AstGrepScanner(str(tmp_path))
    with patch("brass.scanners.ast_grep_scanner.shutil.which", return_value="/usr/bin/ast-grep"):
        with patch(
            "brass.scanners.ast_grep_scanner.subprocess.run",
            return_value=_StubResult(stdout="[]", returncode=0),
        ):
            assert scanner.scan() == []


def test_scan_handles_malformed_metadata(tmp_path):
    """If `metadata` isn't a dict, fall back to inferring kind from rule_id."""
    _make_project(tmp_path)
    scanner = AstGrepScanner(str(tmp_path))
    row = _row(str(tmp_path / "db.py"), 3)
    row["metadata"] = "not-a-dict"
    with patch("brass.scanners.ast_grep_scanner.shutil.which", return_value="/usr/bin/ast-grep"):
        with patch(
            "brass.scanners.ast_grep_scanner.subprocess.run",
            return_value=_StubResult(stdout=json.dumps([row]), returncode=1),
        ):
            findings = scanner.scan()
    assert len(findings) == 1
    # Inferred from rule_id substring 'sql-injection'
    assert "sql injection" in findings[0].title


def test_scan_drops_rows_with_bool_line_number(tmp_path):
    """A bool leaking through must not become line 1 or 2."""
    _make_project(tmp_path)
    scanner = AstGrepScanner(str(tmp_path))
    row = _row(str(tmp_path / "db.py"), 3)
    row["range"]["start"]["line"] = True
    with patch("brass.scanners.ast_grep_scanner.shutil.which", return_value="/usr/bin/ast-grep"):
        with patch(
            "brass.scanners.ast_grep_scanner.subprocess.run",
            return_value=_StubResult(stdout=json.dumps([row]), returncode=1),
        ):
            findings = scanner.scan()
    assert len(findings) == 1
    assert findings[0].line_number is None


def test_discover_python_targets_excludes_test_fixtures(tmp_path):
    """Files the FileClassifier marks as excluded must not be passed to ast-grep."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "ok.py").write_text("x = 1\n")
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "junk.py").write_text("x = 1\n")

    scanner = AstGrepScanner(str(tmp_path))
    targets = scanner._discover_python_targets()
    rels = {t.relative_to(tmp_path).as_posix() for t in targets}
    assert "src/ok.py" in rels
    assert all("__pycache__" not in r for r in rels)
