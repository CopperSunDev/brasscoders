"""End-to-end regression guard for the "critical findings survive every stage" invariant.

Background (2026-05-19): A multi-day bug chase on coppersun_brass
revealed that critical findings could silently disappear between the
scanner that emitted them and the ai_instructions.yaml that the AI
consumer reads. The compounding causes — per-scanner cap break,
gateway over-clustering, typed-block cap-50 without severity-first
sort — all individually passed unit tests. Only an end-to-end check
against a project with known-broken inputs caught it.

This test is that check. It constructs a synthetic project with N
files containing intentional Python syntax errors (the most "should-
never-be-dropped" finding class brass emits — a file with a syntax
error literally cannot be imported), runs the full scan, and asserts
EVERY broken file surfaces as a critical syntax-error finding in
ai_instructions.yaml's typed blocks.

We use --no-enrich to keep runtime under ~30s. The enrichment-survival
path is covered separately by enrichment/filter.py's critical-exempt
logic + unit tests. Future enhancement: add an enriched variant that
mocks the gateway to exercise the full pipeline.

If this test fails, something in the pipeline is silently dropping
critical findings — exactly the class of bug we want to catch.
"""

from __future__ import annotations

import os
import shutil
import site
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List

import pytest
import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CLI_SCRIPT = PROJECT_ROOT / "src" / "brass" / "cli" / "brass_cli.py"


# Each entry is (filename, broken_python_source). Cover the syntax-error
# variants brass has historically had trouble with:
# - unterminated triple-quoted string (causes ast.parse to fail mid-file)
# - identifier-with-space (broken find-and-replace pattern)
# - invalid assignment target
# - mismatched parens
_BROKEN_FILES: Dict[str, str] = {
    "broken_unterminated_string.py": (
        'def main():\n'
        '    """Docstring that never closes\n'
        '    print("unreachable")\n'
        'if __name__ == "__main__":\n'
        '    main()\n'
    ),
    "broken_space_in_identifier.py": (
        'def main():\n'
        '    obj = Some Class()\n'
        '    return obj\n'
    ),
    "broken_missing_paren.py": (
        'def main():\n'
        '    result = sum([1, 2, 3]\n'
        '    return result\n'
    ),
    "broken_invalid_assignment.py": (
        'def main():\n'
        '    1 = x\n'
        '    return x\n'
    ),
}


def _resolve_brass_tool_paths() -> str:
    """PATH that includes scanner binaries even under HOME isolation."""
    base_path = ["/usr/bin", "/bin", "/usr/local/bin"]
    extra_dirs: list[str] = []
    for tool in ("bandit", "pylint", "pyre", "semgrep", "node", "ast-grep"):
        located = shutil.which(tool)
        if located:
            parent = str(Path(located).parent)
            if parent not in base_path and parent not in extra_dirs:
                extra_dirs.append(parent)
    return os.pathsep.join(base_path + extra_dirs)


def _run_brassai(scan_target: Path) -> subprocess.CompletedProcess:
    """Invoke brasscoders scan with --no-enrich (hermetic, no gateway call)."""
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
        "BRASS_DISABLE_VERSION_CHECK": "1",
    })
    cmd = [
        sys.executable, str(CLI_SCRIPT),
        "--offline", "scan", str(scan_target),
        "--max-workers=2", "--no-enrich",
    ]
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=120, env=env,
    )


@pytest.fixture(scope="module")
def critical_completeness_scan(tmp_path_factory) -> Path:
    """Build a synthetic project with N broken files, scan it once, return path."""
    scan_target = tmp_path_factory.mktemp("brass_critical_completeness")
    for fname, src in _BROKEN_FILES.items():
        (scan_target / fname).write_text(src)
    # Add a few valid Python files so the scan has non-broken context
    # to compare against (BrassPerf needs Python files to enumerate).
    (scan_target / "valid_module.py").write_text(
        "def helper():\n    return 42\n"
    )
    result = _run_brassai(scan_target)
    if result.returncode != 0:
        pytest.fail(
            f"brasscoders scan failed (rc={result.returncode}):\n"
            f"stdout:\n{result.stdout[-1000:]}\n"
            f"stderr:\n{result.stderr[-1000:]}"
        )
    return scan_target


def _load_ai_instructions(scan_target: Path) -> dict:
    yaml_path = scan_target / ".brass" / "ai_instructions.yaml"
    assert yaml_path.is_file(), f"ai_instructions.yaml not produced at {yaml_path}"
    return yaml.safe_load(yaml_path.read_text())


def _syntax_error_file_paths(doc: dict) -> List[str]:
    """Collect file_paths from every Syntax Error finding in ai_instructions."""
    paths: List[str] = []
    # Check every block where critical CODE_QUALITY findings can land,
    # not just code_quality_attention — the YAML duplicates findings
    # across blocks (production_focus, critical_issues alias, etc.).
    for block_name in ("security_critical", "code_quality_attention",
                       "architecture_concerns", "other", "critical_issues",
                       "production_focus"):
        block = doc.get(block_name) or []
        for entry in block:
            if not isinstance(entry, dict):
                continue
            if (entry.get("title") or "").startswith("Syntax Error"):
                fp = entry.get("file_path")
                if fp:
                    paths.append(fp)
    return paths


def test_every_broken_file_surfaces_in_ai_instructions(critical_completeness_scan):
    """The core invariant: every file that brass cannot parse must
    appear as a critical syntax-error finding in ai_instructions.yaml.

    This is the test that would have caught every silent-drop bug from
    the 2026-05-19 chase: gateway cross-file dedup, per-scanner cap
    break, typed-block cap-50 ranked-not-severity-sort, and the
    redaction over-relabeling regression.
    """
    doc = _load_ai_instructions(critical_completeness_scan)
    surfaced = set(_syntax_error_file_paths(doc))

    missing = [fname for fname in _BROKEN_FILES if fname not in surfaced]
    assert not missing, (
        f"{len(missing)} of {len(_BROKEN_FILES)} broken files did NOT surface "
        f"as syntax-error findings in ai_instructions.yaml: {missing}\n"
        f"Surfaced: {sorted(surfaced)}"
    )


def test_syntax_error_findings_are_critical_severity(critical_completeness_scan):
    """Syntax errors are ship-blocking (the file can't import); they
    must carry severity=critical, not high or anything lower."""
    doc = _load_ai_instructions(critical_completeness_scan)
    for block_name in ("security_critical", "code_quality_attention",
                       "critical_issues", "production_focus"):
        for entry in (doc.get(block_name) or []):
            if not isinstance(entry, dict):
                continue
            if (entry.get("title") or "").startswith("Syntax Error"):
                sev = entry.get("severity")
                assert sev == "critical", (
                    f"Syntax-error finding in {block_name} for "
                    f"{entry.get('file_path')} has severity={sev!r}, "
                    f"expected 'critical'."
                )


def test_syntax_error_findings_not_relabeled_as_credentials(critical_completeness_scan):
    """Regression guard for the 2026-05-19 over-aggressive redaction:
    adding BrassPerformanceScanner to the secret-leak allowlist + gating
    sanitize on CODE_QUALITY caused every BrassPerf syntax-error finding
    to be re-titled as 'Possible hardcoded credential (value redacted)'.
    The user couldn't find them by syntax-error title at all.

    This test asserts the negative: NO finding on a broken_*.py file
    has the credential-redaction title. (Multiple scanners produce
    syntax-error findings with different exact titles — PhantomAI uses
    "Syntax Error in AI-Generated Code", pylint uses "syntax-error" —
    so we check for the bad title pattern, not a specific good one.)
    """
    doc = _load_ai_instructions(critical_completeness_scan)
    block = doc.get("code_quality_attention") or []
    broken_file_entries = [
        entry for entry in block
        if isinstance(entry, dict) and entry.get("file_path", "").startswith("broken_")
    ]
    assert broken_file_entries, (
        "No 'broken_*.py' findings appeared in code_quality_attention — "
        "either the scan dropped them or routed them to a different block."
    )
    mislabeled = [
        (entry.get("file_path"), entry.get("title"))
        for entry in broken_file_entries
        if (entry.get("title") or "").startswith("Possible hardcoded credential")
    ]
    assert not mislabeled, (
        f"Some syntax-error findings were re-titled as credentials by an "
        f"over-aggressive redaction gate (SEC-1 regression class): {mislabeled}"
    )


def test_unterminated_string_credential_does_not_leak(critical_completeness_scan):
    """Adversarial case: a broken Python file with an unterminated
    string literal that contains a credential-shaped value. The
    SyntaxError.text — which BrassPerformanceScanner uses for
    code_snippet — would carry the raw value. Source-side redaction
    via _redact_potential_credential must scrub it.

    Constructed inline to keep the test hermetic.
    """
    # Use a separate ad-hoc scan with one specially-broken file. We can't
    # easily mutate the module-scoped fixture, so write a new tempdir.
    with tempfile.TemporaryDirectory() as td:
        target = Path(td)
        canary = "wJalrXUtnFEMI_K7MDENG_bPxRfiCYEXAMPLEKEY_2026"
        (target / "broken_with_credential.py").write_text(
            f'AWS_SECRET_ACCESS_KEY = "{canary}\n'  # unterminated quote
            'def main():\n    pass\n'
        )
        # Valid sibling to give the scan something to chew on.
        (target / "valid.py").write_text("def x(): return 1\n")
        result = _run_brassai(target)
        assert result.returncode == 0, (
            f"scan failed: rc={result.returncode}\n"
            f"stderr:{result.stderr[-500:]}"
        )
        yaml_path = target / ".brass" / "ai_instructions.yaml"
        assert yaml_path.is_file()
        raw = yaml_path.read_text()
        assert canary not in raw, (
            "Raw credential canary appears in ai_instructions.yaml — the "
            "_redact_potential_credential scrubber in BrassPerformanceScanner "
            "let an unterminated-string credential through."
        )
        # Also check detailed_analysis to be thorough.
        detailed = target / ".brass" / "detailed_analysis.yaml"
        if detailed.is_file():
            assert canary not in detailed.read_text(), (
                "Raw credential canary appears in detailed_analysis.yaml."
            )
