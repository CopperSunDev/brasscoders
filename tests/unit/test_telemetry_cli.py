"""CLI-level tests for opt-in usage telemetry (Part D).

Covers ``brasscoders telemetry on|off|status|reset``, the extracted
``BrassCLI._emit_scan_telemetry`` (hard ``--offline`` return, exact
lowercase-keyed wire payload, no ``offline`` field) and
``BrassCLI._maybe_prompt_telemetry`` (never prompts without a TTY, never
changes the exit code).

Template: ``test_paid_note_cli.py`` (BrassCLI() + capsys + HOME isolation).
"""

from __future__ import annotations

import argparse
import inspect
import re
from pathlib import Path

import pytest

import brass.telemetry
from brass.cli.brass_cli import BrassCLI
from brass.models.finding import Finding, FindingType, Severity
from brass.telemetry import client as tclient
from brass.telemetry import prompt as tprompt
from brass.telemetry.backend import default_debug_log_path
from brass.telemetry.consent import (
    REASON_CONSENT_FILE,
    REASON_DEFAULT,
    REASON_OFFLINE_ENV,
    REASON_TELEMETRY_ENV,
    ConsentStore,
    default_consent_path,
)

HEX32 = re.compile(r"[a-f0-9]{32}")
WIRE_KEYS = {
    "event", "brass_version", "platform", "install_id", "timestamp_ms",
    "total_findings", "finding_types", "severity_counts", "fast", "dev_mode",
}


@pytest.fixture(autouse=True)
def _reset_telemetry(monkeypatch):
    monkeypatch.setattr(tclient, "_DEFAULT_CLIENT", None)
    for name in ("BRASS_TELEMETRY", "BRASS_OFFLINE", "CI", "BRASS_GATEWAY_URL"):
        monkeypatch.delenv(name, raising=False)


def _isolate_env(monkeypatch, tmp_path: Path) -> Path:
    """HOME → tmp_path so every ``~/.brass`` store resolves under the test dir."""
    monkeypatch.setenv("HOME", str(tmp_path))
    resolved = default_consent_path().resolve()
    assert str(resolved).startswith(str(tmp_path.resolve())), (
        f"Test isolation failed: consent path {resolved} is not under {tmp_path}"
    )
    return resolved


def _capture_post(monkeypatch):
    calls = []
    monkeypatch.setattr("requests.post", lambda url, **kw: calls.append((url, kw)))
    return calls


def _findings():
    def mk(i, ftype, sev):
        return Finding(id=f"f{i}", type=ftype, severity=sev, file_path=f"src/{i}.py", title="t")

    return [
        mk(1, FindingType.SECURITY, Severity.CRITICAL),
        mk(2, FindingType.SECURITY, Severity.HIGH),
        mk(3, FindingType.CODE_QUALITY, Severity.MEDIUM),
    ]


def _args(**overrides):
    base = dict(fast=False, dev=False, offline=False)
    base.update(overrides)
    return argparse.Namespace(**base)


# --- brasscoders telemetry on|off|status|reset -------------------------------


def test_status_fresh_install(tmp_path, monkeypatch, capsys):
    path = _isolate_env(monkeypatch, tmp_path)
    assert BrassCLI().run(["telemetry", "status"]) == 0
    out = capsys.readouterr().out
    assert "OFF" in out
    assert f"Reason:      {REASON_DEFAULT}" in out
    assert "Install ID" not in out
    assert str(default_debug_log_path()) in out
    assert not path.exists()  # status never persists anything


def test_on_off_reset_roundtrip(tmp_path, monkeypatch, capsys):
    path = _isolate_env(monkeypatch, tmp_path)
    cli = BrassCLI()

    assert cli.run(["telemetry", "on"]) == 0
    out = capsys.readouterr().out
    assert "ON" in out
    first = HEX32.search(out).group(0)
    assert ConsentStore().state() == (True, REASON_CONSENT_FILE)

    assert cli.run(["telemetry", "status"]) == 0
    out = capsys.readouterr().out
    assert "ON" in out and REASON_CONSENT_FILE in out and first in out

    assert cli.run(["telemetry", "off"]) == 0
    assert "OFF" in capsys.readouterr().out
    assert ConsentStore().state() == (False, REASON_CONSENT_FILE)

    assert cli.run(["telemetry", "status"]) == 0
    assert first in capsys.readouterr().out  # stable id still shown when off

    assert cli.run(["telemetry", "reset"]) == 0
    out = capsys.readouterr().out
    fresh = HEX32.search(out).group(0)
    assert fresh != first and "Consent unchanged" in out
    assert ConsentStore().state() == (False, REASON_CONSENT_FILE)  # reset kept consent
    assert f"install_id={fresh}" in path.read_text()


@pytest.mark.parametrize("env,reason,marker", [
    (("BRASS_TELEMETRY", "on"), REASON_TELEMETRY_ENV, "ON"),
    (("BRASS_TELEMETRY", "off"), REASON_TELEMETRY_ENV, "OFF"),
    (("BRASS_OFFLINE", "1"), REASON_OFFLINE_ENV, "OFF"),
])
def test_status_explains_env_override(tmp_path, monkeypatch, capsys, env, reason, marker):
    _isolate_env(monkeypatch, tmp_path)
    ConsentStore().set(enabled=True)
    monkeypatch.setenv(*env)
    assert BrassCLI().run(["telemetry", "status"]) == 0
    out = capsys.readouterr().out
    assert marker in out.splitlines()[0]
    assert f"Reason:      {reason}" in out
    assert "unset BRASS_OFFLINE / BRASS_TELEMETRY" in out


def test_parser_accepts_reset_only_as_a_known_action(tmp_path, monkeypatch):
    _isolate_env(monkeypatch, tmp_path)
    with pytest.raises(SystemExit):
        BrassCLI().parser.parse_args(["telemetry", "bogus"])


# --- _emit_scan_telemetry ---------------------------------------------------


def test_emit_offline_mode_never_posts_or_logs(tmp_path, monkeypatch):
    _isolate_env(monkeypatch, tmp_path)
    ConsentStore().set(enabled=True)
    calls = _capture_post(monkeypatch)
    BrassCLI()._emit_scan_telemetry(_args(offline=True), _findings(), offline_mode=True)
    assert calls == []
    assert not default_debug_log_path().exists()


def test_emit_posts_exact_lowercase_payload(tmp_path, monkeypatch):
    _isolate_env(monkeypatch, tmp_path)
    ConsentStore().set(enabled=True)
    calls = _capture_post(monkeypatch)
    BrassCLI()._emit_scan_telemetry(_args(fast=True, dev=False), _findings(), offline_mode=False)
    assert len(calls) == 1
    url, kwargs = calls[0]
    assert url.endswith("/api/telemetry")
    event = kwargs["json"]
    assert set(event) == WIRE_KEYS
    assert "offline" not in event
    assert event["event"] == "scan"
    assert event["total_findings"] == 3
    assert event["finding_types"] == {"security": 2, "code_quality": 1}
    assert event["severity_counts"] == {"critical": 1, "high": 1, "medium": 1}
    assert all(k == k.lower() for k in event["finding_types"])
    assert all(k == k.lower() for k in event["severity_counts"])
    assert event["fast"] is True and event["dev_mode"] is False
    assert event["platform"] in {"darwin", "linux", "windows", "other"}
    assert HEX32.fullmatch(event["install_id"])
    # The tee holds the same bytes we sent.
    assert default_debug_log_path().read_text().count("\n") == 1


def test_emit_silent_under_offline_env_even_when_consented(tmp_path, monkeypatch):
    _isolate_env(monkeypatch, tmp_path)
    ConsentStore().set(enabled=True)
    monkeypatch.setenv("BRASS_OFFLINE", "1")
    calls = _capture_post(monkeypatch)
    BrassCLI()._emit_scan_telemetry(_args(), _findings(), offline_mode=False)
    assert calls == []


def test_emit_silent_without_consent(tmp_path, monkeypatch):
    _isolate_env(monkeypatch, tmp_path)
    calls = _capture_post(monkeypatch)
    BrassCLI()._emit_scan_telemetry(_args(), _findings(), offline_mode=False)
    assert calls == []
    assert not default_consent_path().exists()  # no id minted when off


def test_emit_swallows_record_failure(tmp_path, monkeypatch):
    _isolate_env(monkeypatch, tmp_path)

    def boom(**_):
        raise RuntimeError("telemetry exploded")

    monkeypatch.setattr(brass.telemetry, "record", boom)
    BrassCLI()._emit_scan_telemetry(_args(), _findings(), offline_mode=False)  # must not raise


def test_emit_handles_empty_findings(tmp_path, monkeypatch):
    _isolate_env(monkeypatch, tmp_path)
    ConsentStore().set(enabled=True)
    calls = _capture_post(monkeypatch)
    BrassCLI()._emit_scan_telemetry(_args(), [], offline_mode=False)
    event = calls[0][1]["json"]
    assert event["total_findings"] == 0
    assert event["finding_types"] == {} and event["severity_counts"] == {}


# --- _maybe_prompt_telemetry ------------------------------------------------


def test_prompt_skipped_without_tty(tmp_path, monkeypatch, capsys):
    path = _isolate_env(monkeypatch, tmp_path)
    monkeypatch.setattr(tprompt, "is_interactive", lambda: False)
    BrassCLI()._maybe_prompt_telemetry(False)
    assert capsys.readouterr().out == ""
    assert not path.exists()


def test_prompt_skipped_under_ci(tmp_path, monkeypatch, capsys):
    path = _isolate_env(monkeypatch, tmp_path)
    monkeypatch.setattr(tprompt, "is_interactive", lambda: True)
    monkeypatch.setenv("CI", "1")
    BrassCLI()._maybe_prompt_telemetry(False)
    assert capsys.readouterr().out == ""
    assert not path.exists()


def test_prompt_skipped_offline(tmp_path, monkeypatch, capsys):
    path = _isolate_env(monkeypatch, tmp_path)
    monkeypatch.setattr(tprompt, "is_interactive", lambda: True)
    BrassCLI()._maybe_prompt_telemetry(True)
    assert capsys.readouterr().out == ""
    assert not path.exists()


def test_prompt_enter_persists_off(tmp_path, monkeypatch, capsys):
    path = _isolate_env(monkeypatch, tmp_path)
    monkeypatch.setattr(tprompt, "is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "")
    BrassCLI()._maybe_prompt_telemetry(False)
    out = capsys.readouterr().out
    assert "Help improve BrassCoders?" in out and tprompt.DECLINED_LINE in out
    assert path.read_text() == "consent=off\n"


def test_prompt_yes_persists_on(tmp_path, monkeypatch, capsys):
    _isolate_env(monkeypatch, tmp_path)
    monkeypatch.setattr(tprompt, "is_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "y")
    BrassCLI()._maybe_prompt_telemetry(False)
    assert "✅ Telemetry on." in capsys.readouterr().out
    assert ConsentStore().state() == (True, REASON_CONSENT_FILE)


def test_prompt_failure_cannot_escape(tmp_path, monkeypatch):
    _isolate_env(monkeypatch, tmp_path)

    def boom(*_, **__):
        raise RuntimeError("prompt exploded")

    monkeypatch.setattr(brass.telemetry, "maybe_prompt_for_consent", boom)
    BrassCLI()._maybe_prompt_telemetry(False)  # must not raise


# --- ordering invariant in _cmd_scan ----------------------------------------


def test_scan_tail_order_is_footer_note_telemetry_prompt_exit():
    # ``_cmd_scan`` is wrapped by ``@handle_common_errors`` (no
    # ``functools.wraps``), so ``inspect.getsource(BrassCLI._cmd_scan)``
    # returns the decorator's wrapper. Slice the class source instead.
    full = inspect.getsource(BrassCLI)
    start = full.index("def _cmd_scan(")
    src = full[start:full.index("def _emit_scan_telemetry(", start)]
    markers = [
        "self._print_cache_footer()",
        "self._print_paid_note(self._enrichment_mode)",
        "self._emit_scan_telemetry(args, ranked_findings, offline_mode)",
        "self._maybe_prompt_telemetry(offline_mode)",
        "return self._scan_exit_code(args, ranked_findings)",
    ]
    positions = [src.index(m) for m in markers]
    assert positions == sorted(positions)
    assert src.count("self._emit_scan_telemetry(") == 1
