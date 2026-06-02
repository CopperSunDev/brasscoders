"""Tests for the AST-level hardcoded_password detector fix (phase C.7b).

Round 3 of the brass-seo triage identified this detector as the largest
remaining source of FPs: it was checking the string LITERAL VALUE for
patterns like "password=" or "secret:" — so `console.error('Password
reset error:', err)` triggered it because the string value contained
"Password" followed by ":".

The fix moved the check to the AST PARENT — only fire when the literal
is assigned to a credential-named identifier (variable / object property
/ member), and the value itself plausibly looks like a credential
(no whitespace, length ≥ 8, has digit-or-symbol mix).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "js_password_detection"


def _have_node() -> bool:
    return shutil.which("node") is not None


def _run_babel_parser(fixture_name: str) -> dict:
    """Invoke the babel parser directly for tight unit-level testing.

    We don't go through JavaScriptTypeScriptScanner here because that
    couples us to the Python scan pipeline; the AST behavior is what
    we want to pin down.
    """
    babel_script = (
        Path(__file__).parent.parent.parent
        / "src" / "brass" / "js_analysis" / "babel_parser.js"
    )
    fixture = FIXTURE_DIR / fixture_name
    proc = subprocess.run(
        ["node", str(babel_script), str(fixture)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    import json
    if proc.returncode != 0:
        raise RuntimeError(
            f"babel_parser.js failed (exit {proc.returncode}): {proc.stderr[:500]}"
        )
    parsed = json.loads(proc.stdout)
    # babel_parser.js returns a list (one entry per input file).
    return parsed[0] if isinstance(parsed, list) else parsed


def _hardcoded_password_findings(result: dict) -> list[dict]:
    return [
        p for p in result.get("patterns", [])
        if p.get("pattern") == "hardcoded_password"
    ]


@pytest.mark.skipif(not _have_node(), reason="node not installed")
def test_real_credential_assignments_are_detected():
    result = _run_babel_parser("real_credentials.js")
    findings = _hardcoded_password_findings(result)
    # We expect: password, apiKey, jwt_secret, api_key, client_secret, access_token
    assert len(findings) == 6, f"Expected 6 findings, got: {[f.get('message') for f in findings]}"

    detected_names = []
    for f in findings:
        # Message format: "Potential hardcoded credential assigned to \"<name>\""
        msg = f["message"]
        if 'assigned to "' in msg:
            detected_names.append(msg.split('assigned to "')[1].rstrip('"'))

    # The exact names should be there. Order may vary by visitor walk.
    expected = {"password", "apiKey", "jwt_secret", "api_key", "client_secret", "access_token"}
    assert set(detected_names) == expected, f"Names mismatch: got {detected_names}"


@pytest.mark.skipif(not _have_node(), reason="node not installed")
def test_function_call_arguments_and_logger_strings_do_not_fire():
    """The brass-seo regression test — was the dominant FP in round 3."""
    result = _run_babel_parser("false_positives.js")
    findings = _hardcoded_password_findings(result)
    assert findings == [], (
        f"Expected ZERO hardcoded_password findings on the false-positive "
        f"fixture, got {len(findings)}: {[f.get('message') for f in findings]}"
    )


@pytest.mark.skipif(not _have_node(), reason="node not installed")
def test_brass_seo_specific_pattern_does_not_fire():
    """Pins the exact string that was triggering FPs in round 3."""
    code = """
function handleError(error) {
  console.error('Password reset error:', error.code || 'unknown');
  console.error('Failed to validate secret token:', error);
}
"""
    tmp = FIXTURE_DIR / "_brass_seo_repro.js"
    try:
        tmp.write_text(code)
        result = _run_babel_parser(tmp.name)
    finally:
        tmp.unlink(missing_ok=True)

    findings = _hardcoded_password_findings(result)
    assert findings == [], (
        f"brass-seo regression: console.error() with credential-named "
        f"string still fires the detector: {findings}"
    )
