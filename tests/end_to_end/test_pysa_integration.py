"""End-to-end integration test: Pysa actually produces findings.

Runs the real `PysaTaintScanner` (no subprocess mocking) against a
fixture aligned with brass's bundled source/sink models — Flask
`request.args` flowing into `sqlite3.Cursor.execute`. This is the
test the unit suite's mock-based tests cannot catch: if brass's
bundled models stop loading (Pyre version drift, search_path
regression, etc.), the unit tests stay green but customers see
zero Pysa findings. This test fails loudly.

Marked slow because it requires a real `pyre analyze` invocation
(~30-90s cold, ~5-15s warm). Skipped automatically when the
required tools (pyre on PATH, typeshed on disk, flask importable)
aren't available — those constraints belong to the CI environment
setup, not this test's correctness.

History: 2026-05-16. The verification scan that motivated the
search_path discovery showed Pysa returning 0 findings on the
benchmark `vulnerable_flask_app` fixture, masking 27 silently-
dropped third-party source models. The unit tests passed because
they mocked `subprocess.run`. This integration test closes that
gap.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from brass.scanners.pysa_taint_scanner import PysaTaintScanner


FIXTURE_SRC = Path(__file__).parent / "fixtures" / "pysa_stdlib_sqli"
FLASK_FIXTURE_SRC = Path(__file__).parent / "fixtures" / "pysa_flask_sqli"
KITCHEN_SINK_FIXTURE_SRC = Path(__file__).parent / "fixtures" / "pysa_kitchen_sink"


def _pyre_available() -> bool:
    """Pyre on PATH is a hard prereq for this test to mean anything."""
    return shutil.which("pyre") is not None


@pytest.mark.skipif(not _pyre_available(), reason="pyre binary not on PATH")
def test_pysa_detects_argv_to_sql_execute_flow(tmp_path: Path, monkeypatch):
    """End-to-end: bundled stdlib source + bundled stdlib sink → SQL
    injection finding (rule code 5001).

    Uses ``sys.argv`` (modeled in stdlib.pysa) flowing into
    ``sqlite3.Cursor.execute`` (also stdlib.pysa). Both ends are in
    the standard library so no customer-installed third-party deps
    are required and no search_path tweaking is needed — Pyre's
    bundled typeshed resolves everything (once cloned into the brass
    cache via the auto-fetch path enabled below).

    Sets ``BRASS_AUTOFETCH_TYPESHED=1`` so a clean CI runner without
    a pre-existing typeshed cache fetches it transparently. The clone
    is ~33 MB / ~10s — acceptable for an integration test that's
    already paying for a real ``pyre analyze`` (~30-90s).

    A failure here means one of brass's customer-facing scanners is
    silently broken. Triage hints:
      - 0 findings: run `pyre analyze` manually on the fixture WITHOUT
        `--no-verify`; the parse errors are usually the cause.
        See the 2026-05-16 model-syntax investigation for context.
      - non-5001 findings only: the SQL sink model
        (`sqlite3.Cursor.execute` in `data/pysa_models/stdlib.pysa`)
        may have regressed format-wise; Pyre logs the parse error.
    """
    monkeypatch.setenv("BRASS_AUTOFETCH_TYPESHED", "1")
    # Copy fixture into a temp dir so the scan writes its `.brass/`
    # under tmp rather than polluting the source-controlled fixture.
    project = tmp_path / "pysa_stdlib_sqli"
    shutil.copytree(FIXTURE_SRC, project)

    scanner = PysaTaintScanner(str(project))
    findings = scanner.scan()

    # Skip rather than fail if typeshed can't be fetched (network
    # outage, GitHub down, etc.) — the scanner's own soft-fail
    # reports it via last_run_status, and that's outside the scope
    # of "did Pysa correctly detect the flow."
    status, reason = scanner.last_run_status or (None, "")
    if status == "skipped" and "typeshed" in (reason or "").lower():
        pytest.skip(f"typeshed unavailable for autofetch ({reason})")

    assert findings, (
        "Pysa returned 0 findings on a fixture with a textbook "
        "sys.argv → cursor.execute SQL injection flow. brass's "
        "bundled models or .pyre_configuration is silently broken; "
        "this is the silent-fail mode a customer would experience "
        "on a real CLI tool that takes input from argv."
    )
    sqli_findings = [
        f for f in findings
        if "sql" in (f.title or "").lower() or "5001" in str(f.metadata or {})
    ]
    assert sqli_findings, (
        f"Pysa produced {len(findings)} findings but none matched "
        f"the expected SQL injection (rule 5001). Got titles: "
        f"{[f.title for f in findings]}"
    )


@pytest.mark.skipif(not _pyre_available(), reason="pyre binary not on PATH")
def test_pysa_detects_flask_request_args_to_sql_flow(tmp_path: Path, monkeypatch):
    """End-to-end: bundled-stub Flask source + stdlib sqlite sink → SQL
    injection finding (rule code 5001).

    Proves that brass's `data/pysa_stubs/flask/__init__.pyi` is being
    loaded into Pyre's search_path, that `third_party.pysa`'s
    ``flask.Request.args: TaintSource[UserControlled]`` model actually
    binds, and that the resulting taint flows through to the stdlib
    sqlite3 sink. Zero findings would mean one of:
      - stub bundle isn't being shipped in the wheel
      - search_path config drift in `_build_pyre_configuration_dict`
      - third_party.pysa model regressed format-wise

    Pairs with `test_pysa_detects_argv_to_sql_execute_flow` which
    covers the stdlib-only path. Together they prove both source
    classes (stdlib + stub-bundled third-party) work end-to-end.
    """
    monkeypatch.setenv("BRASS_AUTOFETCH_TYPESHED", "1")
    project = tmp_path / "pysa_flask_sqli"
    shutil.copytree(FLASK_FIXTURE_SRC, project)

    scanner = PysaTaintScanner(str(project))
    findings = scanner.scan()

    status, reason = scanner.last_run_status or (None, "")
    if status == "skipped" and "typeshed" in (reason or "").lower():
        pytest.skip(f"typeshed unavailable for autofetch ({reason})")

    assert findings, (
        "Pysa returned 0 findings on a Flask `request.args.get` → "
        "`cursor.execute` SQL injection flow. The bundled "
        "`data/pysa_stubs/flask/__init__.pyi` may not be loading "
        "into Pyre's search_path, or third_party.pysa's source "
        "model isn't binding."
    )
    sqli_findings = [
        f for f in findings
        if "sql" in (f.title or "").lower() or "5001" in str(f.metadata or {})
    ]
    assert sqli_findings, (
        f"Pysa produced {len(findings)} findings but none matched "
        f"the expected SQL injection (rule 5001). Got titles: "
        f"{[f.title for f in findings]}"
    )


@pytest.mark.skipif(not _pyre_available(), reason="pyre binary not on PATH")
def test_pysa_detects_breadth_across_source_sink_combinations(
    tmp_path: Path, monkeypatch,
):
    """Kitchen-sink: 10 distinct source × sink flows, expected to fire
    ≥ 8 findings across ≥ 4 distinct Pysa rule codes.

    Exercises the full bundled-model surface:
      - stdlib sources: sys.argv, os.environ, sys.stdin
      - third-party (via stub bundle): flask.Request.{args/form/json/
        cookies}, django.http.HttpRequest.GET
      - stdlib sinks: sqlite3.execute, subprocess.run, os.system,
        eval, pickle.loads, open, urllib.urlopen
      - third-party sinks: flask.render_template_string

    Each flow is a distinct function in `pysa_kitchen_sink/app.py`,
    making per-flow regression triage straightforward when this test
    fails. Loose threshold (≥8, not 10) leaves headroom for
    Pyre-version drift around obscure-model edge cases.
    """
    monkeypatch.setenv("BRASS_AUTOFETCH_TYPESHED", "1")
    project = tmp_path / "pysa_kitchen_sink"
    shutil.copytree(KITCHEN_SINK_FIXTURE_SRC, project)

    scanner = PysaTaintScanner(str(project))
    findings = scanner.scan()

    status, reason = scanner.last_run_status or (None, "")
    if status == "skipped" and "typeshed" in (reason or "").lower():
        pytest.skip(f"typeshed unavailable for autofetch ({reason})")

    assert len(findings) >= 8, (
        f"Expected ≥8 Pysa findings on the kitchen-sink fixture (10 "
        f"distinct source × sink flows); got {len(findings)}. A drop "
        f"this large means a bundled-model regression in stdlib.pysa, "
        f"third_party.pysa, or the pysa_stubs/ tree. Findings: "
        f"{[(f.title, f.file_path) for f in findings]}"
    )

    # Rule-code variety: brass embeds the RULE_CODE_TO_KIND mapping
    # in each finding's ``id`` as ``pysa-<kind>-<hash>``. Extract the
    # kind segment to assert breadth across the source-sink matrix.
    kinds = set()
    for f in findings:
        if f.id and f.id.startswith("pysa-"):
            # Format: "pysa-<kind>-<12-hex-hash>"; the hash is the
            # tail; everything between is the kind (kinds may contain
            # underscores e.g. "sql_injection").
            parts = f.id.split("-")
            if len(parts) >= 3:
                kinds.add("-".join(parts[1:-1]))
    assert len(kinds) >= 4, (
        f"Expected coverage across ≥4 distinct rule kinds (sql_injection, "
        f"command_injection, deserialization, ssrf, path_traversal, xss); "
        f"got {kinds}"
    )


@pytest.mark.skipif(not _pyre_available(), reason="pyre binary not on PATH")
def test_pyre_loads_bundled_models_without_parse_errors(tmp_path: Path):
    """Lower-level check: Pyre verifies brass's bundled models cleanly.

    The 2026-05-16 investigation found 8 stale model lines in
    `stdlib.pysa` that Pyre 0.9.25 silently dropped because of
    named-vs-positional parameter mismatches or imported-alias
    references. Running `pyre analyze` WITHOUT `--no-verify` would
    surface them; running WITH `--no-verify` hides them and Pysa
    just emits fewer findings.

    This test runs pyre WITHOUT --no-verify on a trivial fixture and
    asserts that none of the model-parse errors involve brass's
    bundled files. Module-resolution errors for third-party libs
    (sqlalchemy, django, etc.) when they aren't installed in the
    test environment are TOLERATED — those are Pyre informing brass
    that the speculative third-party model won't apply, not a bug
    in our model file.
    """
    # Minimal fixture: empty file is sufficient — we're testing the
    # model verification stage, not the analysis stage.
    project = tmp_path / "trivial"
    project.mkdir()
    (project / "main.py").write_text("def f(): pass\n")

    models_dir = (
        Path(__file__).resolve().parent.parent.parent
        / "src" / "brass" / "data" / "pysa_models"
    )
    stubs_dir = (
        Path(__file__).resolve().parent.parent.parent
        / "src" / "brass" / "data" / "pysa_stubs"
    )
    typeshed = Path.home() / ".cache" / "brass" / "typeshed"
    if not typeshed.is_dir():
        pytest.skip("typeshed not available; set BRASS_AUTOFETCH_TYPESHED=1 and run a brasscoders scan first")

    # Mirror brass's REAL .pyre_configuration (see
    # `pysa_taint_scanner.py:_build_pyre_configuration_dict`): include
    # search_path pointing at the bundled stubs. Without this, Pyre
    # resolves `requests`/`flask`/etc. via typeshed's real third-party
    # stubs whose signatures differ from brass's minimal bundled stubs
    # — e.g., `requests.api.get` has 8+ named params in typeshed but
    # `**kwargs` in our stub, so a model declaring `**kwargs` matches
    # our stub but mis-matches typeshed. The test config must mirror
    # production's stub-resolution priority or we get false failures.
    config = f'''{{
  "source_directories": ["."],
  "taint_models_path": ["{models_dir}"],
  "search_path": ["{stubs_dir}"],
  "typeshed": "{typeshed}"
}}'''
    (project / ".pyre_configuration").write_text(config)

    result = subprocess.run(
        ["pyre", "analyze"],
        cwd=project, capture_output=True, text=True, timeout=180,
    )
    # Without --no-verify, Pyre exits 10 when any model line fails
    # verification AND prints the errors to stdout. Any error
    # mentioning brass's bundled files is a regression.
    brass_path_errors = [
        line for line in result.stdout.splitlines()
        if "brass/data/pysa_models" in line and (
            "Model signature" in line
            or "imported function" in line
            or "is not a valid define" in line
        )
    ]
    assert not brass_path_errors, (
        "Pyre rejected brass's bundled model lines:\n"
        + "\n".join(brass_path_errors[:20])
    )
