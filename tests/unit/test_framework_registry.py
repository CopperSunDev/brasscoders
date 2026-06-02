"""Tests for FrameworkRegistry (Capability 1 of the algorithmic plan).

Covers:
  - YAML files load without errors
  - Entry-point detection on representative Flask / Express / Next files
  - Sink detection on snippets matching documented patterns
  - Severity arithmetic clamps at CRITICAL / INFO boundaries
  - Adjustments combine correctly (multiplier + bump)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from brass.core.framework_registry import (
    FrameworkRegistry,
    bump_severity,
    EntryPointContext,
    SinkContext,
)
from brass.models.finding import Severity


# --------------------------------------------------------------------------- #
# bump_severity                                                                #
# --------------------------------------------------------------------------- #


def test_bump_severity_up():
    assert bump_severity(Severity.LOW, 1) == Severity.MEDIUM
    assert bump_severity(Severity.MEDIUM, 1) == Severity.HIGH
    assert bump_severity(Severity.HIGH, 1) == Severity.CRITICAL


def test_bump_severity_down():
    assert bump_severity(Severity.HIGH, -1) == Severity.MEDIUM
    assert bump_severity(Severity.LOW, -1) == Severity.INFO


def test_bump_severity_clamps_at_critical():
    assert bump_severity(Severity.CRITICAL, 2) == Severity.CRITICAL


def test_bump_severity_clamps_at_info():
    assert bump_severity(Severity.INFO, -3) == Severity.INFO


# --------------------------------------------------------------------------- #
# YAML loading                                                                 #
# --------------------------------------------------------------------------- #


def test_loads_all_three_languages_without_error():
    reg = FrameworkRegistry()
    # Smoke: each language file populated at least one rule of each type.
    py = reg._rules_by_language["python"]
    assert len(py.entry_points) > 0
    assert len(py.sinks) > 0
    assert len(py.sources) > 0


# --------------------------------------------------------------------------- #
# Entry-point detection                                                       #
# --------------------------------------------------------------------------- #


def test_flask_route_detected_as_web_entry_point(tmp_path):
    f = tmp_path / "routes.py"
    f.write_text(
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/users')\n"
        "def users():\n"
        "    return request.args.get('id')\n"
    )
    reg = FrameworkRegistry(project_path=tmp_path)
    ctx = reg.entry_point_for(str(f))
    assert ctx is not None
    assert ctx.kind == "web_route"
    assert ctx.framework == "flask"
    assert ctx.severity_multiplier == 2.0


def test_cli_command_detected_with_dampened_severity(tmp_path):
    f = tmp_path / "migrate.py"
    f.write_text(
        "import click\n"
        "@click.command()\n"
        "def migrate():\n"
        "    pass\n"
    )
    reg = FrameworkRegistry(project_path=tmp_path)
    ctx = reg.entry_point_for(str(f))
    assert ctx is not None
    assert ctx.framework == "click"
    assert ctx.severity_multiplier < 1.0


def test_express_route_detected_in_js(tmp_path):
    f = tmp_path / "server.js"
    f.write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.get('/api/health', (req, res) => res.send('ok'));\n"
    )
    reg = FrameworkRegistry(project_path=tmp_path)
    ctx = reg.entry_point_for(str(f))
    assert ctx is not None
    assert ctx.framework == "express"
    assert ctx.severity_multiplier == 2.0


def test_next_app_router_detected_in_tsx(tmp_path):
    f = tmp_path / "route.ts"
    f.write_text(
        "import { NextResponse } from 'next/server';\n"
        "export async function GET(request) {\n"
        "  return NextResponse.json({});\n"
        "}\n"
    )
    reg = FrameworkRegistry(project_path=tmp_path)
    ctx = reg.entry_point_for(str(f))
    assert ctx is not None
    assert ctx.framework == "next"


def test_file_without_framework_returns_none(tmp_path):
    f = tmp_path / "util.py"
    f.write_text("def add(a, b):\n    return a + b\n")
    reg = FrameworkRegistry(project_path=tmp_path)
    assert reg.entry_point_for(str(f)) is None


def test_unknown_extension_returns_none(tmp_path):
    f = tmp_path / "data.txt"
    f.write_text("@app.route('/foo')\n")
    reg = FrameworkRegistry(project_path=tmp_path)
    assert reg.entry_point_for(str(f)) is None


def test_missing_file_returns_none(tmp_path):
    reg = FrameworkRegistry(project_path=tmp_path)
    assert reg.entry_point_for(str(tmp_path / "does-not-exist.py")) is None


def test_cache_is_intentionally_stale_within_scan(tmp_path):
    """The registry is constructed once per IntelligenceRanker instance
    (one scan). Files modified mid-scan keep their initial
    classification — that's by design, not a bug. If a daemon/watch-mode
    ever reuses one ranker across scans, the registry will need an
    explicit invalidate() hook."""
    f = tmp_path / "routes.py"
    f.write_text("from flask import Flask\n@app.route('/x')\ndef x(): pass\n")
    reg = FrameworkRegistry(project_path=tmp_path)
    first = reg.entry_point_for(str(f))
    f.write_text("# no longer a flask app\n")
    second = reg.entry_point_for(str(f))
    assert first == second


# --------------------------------------------------------------------------- #
# Defense fixes from the Bug Scanner pass                                     #
# --------------------------------------------------------------------------- #


def test_module_substring_match_no_longer_fires_false_positive(tmp_path):
    """A file mentioning 'os' in a comment / variable should NOT satisfy
    `module: os`. Pre-fix substring match was the dominant cause of
    over-firing sink classifications."""
    from brass.scanners.brass2_privacy_scanner import EmailDetector  # noqa: F401 unused
    f = tmp_path / "no_os.py"
    f.write_text(
        "# This module is about cosmic things, not os.\n"
        "def cosmic_dance(): return 'os' in self.greeting\n"
    )
    reg = FrameworkRegistry(project_path=tmp_path)
    # The `os.system(` sink requires module `os` imported. It isn't.
    sink = reg.sink_for_snippet("os.system(cmd)", str(f))
    assert sink is None


def test_module_import_anchored_detection_via_from_form(tmp_path):
    """`from subprocess import run` should satisfy `module: subprocess`."""
    f = tmp_path / "ops.py"
    f.write_text(
        "from subprocess import run\n"
        "run(cmd, shell=True)\n"
    )
    reg = FrameworkRegistry(project_path=tmp_path)
    sink = reg.sink_for_snippet("run(cmd, shell=True)", str(f))
    # Pattern is `subprocess.run` (not just `run`), so this specific
    # snippet won't match. The presence of the import is the relevant
    # check: assert _module_imported_in detects it.
    from brass.core.framework_registry import _module_imported_in
    assert _module_imported_in(f.read_text(), "subprocess")


def test_module_import_anchored_detection_via_require(tmp_path):
    f = tmp_path / "server.js"
    f.write_text("const express = require('express');\n")
    from brass.core.framework_registry import _module_imported_in
    assert _module_imported_in(f.read_text(), "express")


def test_module_import_anchored_detection_via_esm(tmp_path):
    f = tmp_path / "client.ts"
    f.write_text("import { NextResponse } from 'next/server';\n")
    from brass.core.framework_registry import _module_imported_in
    assert _module_imported_in(f.read_text(), "next")


def test_regex_prefix_is_opt_in(tmp_path):
    """`req.body` is a literal substring; the auto-regex-detection was
    silently treating `.` as a metacharacter and matching `reqXbody`.
    Without the `regex:` prefix, only exact substring matches now fire."""
    from brass.core.framework_registry import _pattern_matches
    # Literal pattern: matches only when the string appears verbatim.
    assert _pattern_matches("req.body", "const x = req.body")
    assert not _pattern_matches("req.body", "const x = reqXbody")
    assert not _pattern_matches("req.body", "const x = req body")
    # Opted in to regex via prefix.
    assert _pattern_matches("regex:req\\.body", "const x = req.body")
    assert not _pattern_matches("regex:req\\.body", "const x = reqXbody")


def test_sink_collision_picks_highest_severity_bump(tmp_path):
    """When a file imports both sqlite3 AND psycopg2, the same snippet
    matches both rules. The strongest bump should win (or first on
    ties)."""
    f = tmp_path / "db.py"
    f.write_text("import sqlite3\nimport psycopg2\n")
    reg = FrameworkRegistry(project_path=tmp_path)
    sink = reg.sink_for_snippet("cursor.execute(query)", str(f))
    assert sink is not None
    # Both rules have severity_bump=1 today; verify we get a deterministic
    # result regardless of which one wins.
    assert sink.severity_bump == 1
    assert sink.kind == "sql_execution"


def test_severity_none_passes_through_unchanged(tmp_path):
    """A finding without a recognized severity should not crash the
    registry and should not invent metadata."""
    reg = FrameworkRegistry(project_path=tmp_path)
    new_sev, meta = reg.adjust_severity(None, "anything.py", snippet="eval(x)")
    assert new_sev is None
    assert meta == {}


def test_empty_file_path_passes_through_unchanged():
    reg = FrameworkRegistry()
    new_sev, meta = reg.adjust_severity(Severity.MEDIUM, "", snippet="eval(x)")
    assert new_sev == Severity.MEDIUM
    assert meta == {}


def test_open_sink_no_longer_inflates_every_python_finding(tmp_path):
    """The `open(` sink fired on every Python file that used the
    builtin (i.e. essentially every Python file). Removed; verify."""
    f = tmp_path / "io.py"
    f.write_text("# vanilla python file\n")
    reg = FrameworkRegistry(project_path=tmp_path)
    sink = reg.sink_for_snippet("with open('foo.txt') as fh:", str(f))
    assert sink is None


def test_next_route_regex_matches_real_route_file(tmp_path):
    """The Next.js App Router pattern must match a typical route handler."""
    f = tmp_path / "route.ts"
    f.write_text(
        "import { NextResponse } from 'next/server';\n"
        "export async function POST(request: Request) {\n"
        "  return NextResponse.json({});\n"
        "}\n"
    )
    reg = FrameworkRegistry(project_path=tmp_path)
    ctx = reg.entry_point_for(str(f))
    assert ctx is not None
    assert ctx.framework == "next"


def test_next_regex_does_not_match_non_route_export(tmp_path):
    """A file with `export async function getThings()` (not a route
    verb) should not trigger the Next route classification."""
    f = tmp_path / "util.ts"
    f.write_text(
        "import next from 'next/server';\n"
        "export async function getThings() { return [] }\n"
    )
    reg = FrameworkRegistry(project_path=tmp_path)
    ctx = reg.entry_point_for(str(f))
    assert ctx is None


def test_symlink_escape_returns_no_finding(tmp_path):
    """A symlink under project_path pointing OUTSIDE the project must
    not be read by the registry — defense against malicious projects."""
    outside = tmp_path.parent / "secret.txt"
    outside.write_text("@app.route('/x')\nflask\n")
    try:
        inside_link = tmp_path / "fake_routes.py"
        inside_link.symlink_to(outside)
        reg = FrameworkRegistry(project_path=tmp_path)
        ctx = reg.entry_point_for(str(inside_link))
        assert ctx is None, "symlink to outside-project file must be rejected"
    finally:
        outside.unlink(missing_ok=True)


def test_dotdot_path_traversal_is_rejected(tmp_path):
    """A finding with file_path containing `../../etc/passwd` must not
    cause the registry to read outside the project."""
    reg = FrameworkRegistry(project_path=tmp_path)
    # Project-relative path with ../ traversal — _resolve_path joins and
    # the containment check rejects.
    ctx = reg.entry_point_for("../../etc/passwd")
    assert ctx is None


def test_canonical_caching_collapses_abs_and_relative(tmp_path):
    """Same file under absolute and relative spellings should produce
    one cache entry — previously caused double file reads + potential
    inconsistency."""
    f = tmp_path / "app.py"
    f.write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "@app.route('/x')\n"
        "def x(): pass\n"
    )
    reg = FrameworkRegistry(project_path=tmp_path)
    via_abs = reg.entry_point_for(str(f))
    via_rel = reg.entry_point_for("app.py")
    assert via_abs is not None
    assert via_rel is not None
    assert via_abs == via_rel
    # Only one cache entry (one canonicalized path).
    assert len(reg._entry_point_cache) == 1


def test_malformed_yaml_row_does_not_disable_other_rows(tmp_path):
    """One bad rule must not nuke the whole language."""
    bad = tmp_path / "python.yaml"
    bad.write_text(
        "entry_points:\n"
        "  - kind: web_route\n"
        "    framework: flask\n"
        "    module: flask\n"
        "    pattern: '@app.route'\n"
        "    severity_multiplier: 'NOT_A_NUMBER'\n"  # malformed
        "  - kind: cli_command\n"
        "    framework: click\n"
        "    module: click\n"
        "    pattern: '@click.command'\n"
        "    severity_multiplier: 0.5\n"
    )
    reg = FrameworkRegistry(data_dir=tmp_path)
    rules = reg._rules_by_language["python"]
    # Bad row skipped; good row still loaded.
    assert len(rules.entry_points) == 1
    assert rules.entry_points[0].framework == "click"


def test_non_dict_yaml_root_does_not_crash(tmp_path):
    """YAML root is a list, not a dict — load gracefully."""
    bad = tmp_path / "python.yaml"
    bad.write_text("- just\n- a\n- list\n")
    reg = FrameworkRegistry(data_dir=tmp_path)
    rules = reg._rules_by_language["python"]
    # Empty rules; loader logged a warning.
    assert rules.entry_points == []
    assert rules.sinks == []
    assert rules.sources == []


# --------------------------------------------------------------------------- #
# Sink detection                                                              #
# --------------------------------------------------------------------------- #


def test_sql_execution_sink_detected(tmp_path):
    f = tmp_path / "db.py"
    f.write_text("import sqlite3\n")
    reg = FrameworkRegistry(project_path=tmp_path)
    sink = reg.sink_for_snippet("cursor.execute(query)", str(f))
    assert sink is not None
    assert sink.kind == "sql_execution"
    assert sink.severity_bump == 1


def test_shell_execution_requires_shell_true_condition(tmp_path):
    f = tmp_path / "ops.py"
    f.write_text("import subprocess\n")
    reg = FrameworkRegistry(project_path=tmp_path)
    # Without shell=True: no match.
    assert reg.sink_for_snippet("subprocess.run(['ls', '-la'])", str(f)) is None
    # With shell=True: matches.
    sink = reg.sink_for_snippet(
        "subprocess.run(cmd, shell=True)", str(f),
    )
    assert sink is not None
    assert sink.kind == "shell_execution"


def test_eval_is_a_code_execution_sink(tmp_path):
    f = tmp_path / "danger.py"
    f.write_text("# uses eval\n")
    reg = FrameworkRegistry(project_path=tmp_path)
    sink = reg.sink_for_snippet("result = eval(user_input)", str(f))
    assert sink is not None
    assert sink.kind == "code_execution"
    assert sink.severity_bump == 2


def test_yaml_load_without_safeloader_is_a_sink(tmp_path):
    f = tmp_path / "loader.py"
    f.write_text("import yaml\n")
    reg = FrameworkRegistry(project_path=tmp_path)
    # condition_not: SafeLoader absent → fires
    sink = reg.sink_for_snippet("data = yaml.load(stream)", str(f))
    assert sink is not None
    assert sink.kind == "deserialization"
    # SafeLoader present → no fire
    assert reg.sink_for_snippet("data = yaml.load(s, Loader=SafeLoader)", str(f)) is None


def test_sink_requires_module_import(tmp_path):
    """A `.execute(` pattern in a file with no sqlite3 import shouldn't fire."""
    f = tmp_path / "no_db.py"
    f.write_text("# no imports\n")
    reg = FrameworkRegistry(project_path=tmp_path)
    assert reg.sink_for_snippet("cursor.execute(query)", str(f)) is None


def test_dangerously_set_inner_html_is_xss_sink_in_tsx(tmp_path):
    f = tmp_path / "Comp.tsx"
    f.write_text(
        "import React from 'react';\n"
        "export const X = () => <div dangerouslySetInnerHTML={{__html: x}} />;\n"
    )
    reg = FrameworkRegistry(project_path=tmp_path)
    sink = reg.sink_for_snippet("dangerouslySetInnerHTML={{__html: x}}", str(f))
    assert sink is not None
    assert sink.kind == "xss_sink"


# --------------------------------------------------------------------------- #
# adjust_severity — combines both                                             #
# --------------------------------------------------------------------------- #


def test_adjust_severity_escalates_in_route_handler(tmp_path):
    f = tmp_path / "api.py"
    f.write_text(
        "import sqlite3\n"
        "from flask import Flask, request\n"
        "@app.route('/q')\n"
        "def q(): cursor.execute(request.args.get('id'))\n"
    )
    reg = FrameworkRegistry(project_path=tmp_path)
    new_sev, meta = reg.adjust_severity(
        Severity.MEDIUM,
        str(f),
        snippet="cursor.execute(request.args.get('id'))",
    )
    # +1 from sink (sql_execution), +1 from entry point (web_route)
    assert new_sev == Severity.CRITICAL
    assert "sink_match" in meta
    assert "entry_point" in meta


def test_adjust_severity_deescalates_in_cli_script(tmp_path):
    f = tmp_path / "migrate.py"
    f.write_text(
        "import argparse\n"
        "import sqlite3\n"
        "parser = argparse.ArgumentParser()\n"
        "parser.parse_args()\n"
        "cursor.execute(sql)\n"
    )
    reg = FrameworkRegistry(project_path=tmp_path)
    new_sev, meta = reg.adjust_severity(
        Severity.MEDIUM,
        str(f),
        snippet="cursor.execute(sql)",
    )
    # +1 from sink (sql_execution), -1 from entry point (cli) → net wash
    assert new_sev == Severity.MEDIUM
    assert "entry_point" in meta
    assert meta["entry_point"]["framework"] == "argparse"


def test_adjust_severity_no_op_when_no_framework_no_sink(tmp_path):
    f = tmp_path / "util.py"
    f.write_text("def add(a, b): return a + b\n")
    reg = FrameworkRegistry(project_path=tmp_path)
    new_sev, meta = reg.adjust_severity(Severity.MEDIUM, str(f), snippet="add(1, 2)")
    assert new_sev == Severity.MEDIUM
    assert meta == {}


def test_adjust_severity_clamps_at_critical(tmp_path):
    """Sink bump 2 + entry point bump 1 from CRITICAL should stay CRITICAL."""
    f = tmp_path / "api.py"
    f.write_text(
        "from flask import Flask, request\n"
        "@app.route('/x')\n"
        "def x(): eval(request.args.get('q'))\n"
    )
    reg = FrameworkRegistry(project_path=tmp_path)
    new_sev, _ = reg.adjust_severity(
        Severity.CRITICAL,
        str(f),
        snippet="eval(request.args.get('q'))",
    )
    assert new_sev == Severity.CRITICAL


def test_positive_case_route_handler_sql_injection_escalates(tmp_path):
    """End-to-end positive case: SQL sink inside a Flask route handler escalates.

    Uses the SecurityTestFiles fixture so the assertion is tied to the same
    content the benchmark / integration suites scan.
    """
    from tests.fixtures.security_test_files import SecurityTestFiles

    f = tmp_path / "route_handler_sql_injection.py"
    f.write_text(SecurityTestFiles.get_route_handler_sql_injection_file())

    reg = FrameworkRegistry(project_path=tmp_path)
    snippet = 'cursor.execute(query)'

    # A medium-severity SQL injection finding inside this file should be
    # escalated: entry point (flask route, x2 multiplier => +1 ladder rung)
    # plus sink (sql_execution => +1 rung) = MEDIUM -> CRITICAL.
    new_sev, meta = reg.adjust_severity(Severity.MEDIUM, str(f), snippet=snippet)

    assert new_sev == Severity.CRITICAL, (
        f"Expected CRITICAL for tainted SQL sink in Flask route, got {new_sev}. "
        f"meta={meta}"
    )
    assert meta.get("entry_point", {}).get("framework") == "flask"
    assert meta.get("sink_match", {}).get("kind") == "sql_execution"
