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
