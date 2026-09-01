"""Exit-code behavior for the ``--fail-on-critical`` CI gate.

``brasscoders scan`` exits 0 by default (backward compatible). With
``--fail-on-critical`` it exits 2 when any critical- or high-severity finding
is present, so a CI step or pre-commit hook can fail the build deterministically.
Covers ``BrassCLI._scan_exit_code``.
"""
import argparse

from brass.cli.brass_cli import BrassCLI
from brass.models.finding import Finding, FindingType, Severity


def _finding(severity):
    return Finding(
        id="f",
        type=FindingType.SECURITY,
        severity=severity,
        file_path="a.py",
        title="t",
    )


def _args(fail_on_critical):
    return argparse.Namespace(fail_on_critical=fail_on_critical)


def test_default_exits_zero_even_with_critical():
    # No flag → exit 0 regardless of findings (non-breaking default).
    assert BrassCLI()._scan_exit_code(_args(False), [_finding(Severity.CRITICAL)]) == 0


def test_flag_gates_on_critical():
    assert BrassCLI()._scan_exit_code(_args(True), [_finding(Severity.CRITICAL)]) == 2


def test_flag_gates_on_high():
    # Finding.is_critical() covers CRITICAL and HIGH — the "critical/high" set
    # the CLI already reports as requiring attention.
    assert BrassCLI()._scan_exit_code(_args(True), [_finding(Severity.HIGH)]) == 2


def test_flag_passes_when_only_low_and_medium():
    findings = [_finding(Severity.LOW), _finding(Severity.MEDIUM), _finding(Severity.INFO)]
    assert BrassCLI()._scan_exit_code(_args(True), findings) == 0


def test_flag_passes_when_no_findings():
    assert BrassCLI()._scan_exit_code(_args(True), []) == 0


def test_missing_flag_attr_defaults_off():
    # An args namespace without the attribute must not raise and must not gate.
    assert BrassCLI()._scan_exit_code(argparse.Namespace(), [_finding(Severity.CRITICAL)]) == 0


# --- Integration coverage: exercises the real CLI wiring (cli.run → _cmd_scan
# → _scan_exit_code), not just the isolated helper above. The unit tests above
# would all still pass if _cmd_scan stopped calling _scan_exit_code entirely,
# or passed the wrong findings list (e.g. pre-filter/pre-rank instead of
# ranked_findings) — only an end-to-end run through cli.run() catches that
# class of wiring regression. --no-pysa keeps these fast and deterministic
# (Pysa's cold-start/typeshed setup can take minutes on a fresh environment);
# --offline keeps them hermetic (no enrichment network call).

def _write_critical_finding(tmp_path):
    (tmp_path / "vulnerable.py").write_text("def run(user_input):\n    return eval(user_input)\n")


def test_end_to_end_fail_on_critical_exits_two(tmp_path):
    _write_critical_finding(tmp_path)
    exit_code = BrassCLI().run(["--offline", "scan", "--fail-on-critical", "--no-pysa", str(tmp_path)])
    assert exit_code == 2


def test_end_to_end_default_exits_zero_with_same_finding(tmp_path):
    # Same fixture as above, flag omitted — isolates that the exit-2 result
    # above is actually gated by the flag, not just always 2 on any finding.
    _write_critical_finding(tmp_path)
    exit_code = BrassCLI().run(["--offline", "scan", "--no-pysa", str(tmp_path)])
    assert exit_code == 0


def test_end_to_end_dev_filter_can_suppress_the_gate(tmp_path):
    # Documents a real interaction, not a regression: --dev filters
    # test/build findings before _scan_exit_code ever sees them, so a
    # critical finding living only in a test file does not trip the gate
    # even with --fail-on-critical. Anyone combining --dev with
    # --fail-on-critical in CI should know this. If this test starts
    # failing, --dev's filtering order relative to the exit-code check
    # has changed — update the CI-gate docs on coppersun.dev to match.
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_thing.py").write_text("def run(user_input):\n    return eval(user_input)\n")
    exit_code = BrassCLI().run(["--offline", "scan", "--fail-on-critical", "--no-pysa", "--dev", str(tmp_path)])
    assert exit_code == 0
