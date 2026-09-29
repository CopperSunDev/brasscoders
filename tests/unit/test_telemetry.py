"""Unit tests for ``brass.telemetry`` (Part D).

Covers the consent store (stable install ID, env precedence, ``--offline``
wins), the event builder (exact wire shape), ``HttpBackend`` (URL, timeout,
override, every failure swallowed), ``MockBackend`` (tee + rotation) and the
first-run consent prompt (gate matrix + persistence semantics).

``requests`` is imported lazily inside ``HttpBackend.emit``, so the tests
patch ``requests.post`` on the real module.
"""

from __future__ import annotations

import json
import platform
import re
import stat
import sys
from pathlib import Path

import pytest

from brass.enrichment.client import DEFAULT_GATEWAY_URL
from brass.telemetry import client as tclient
from brass.telemetry import prompt as tprompt
from brass.telemetry.backend import (
    DEBUG_LOG_MAX_BYTES,
    HTTP_TIMEOUT,
    TELEMETRY_PATH,
    HttpBackend,
    MockBackend,
    default_debug_log_path,
)
from brass.telemetry.client import KNOWN_PLATFORMS, TelemetryClient, TelemetryConfig, platform_name
from brass.telemetry.consent import (
    REASON_CONSENT_FILE,
    REASON_DEFAULT,
    REASON_OFFLINE_ENV,
    REASON_TELEMETRY_ENV,
    ConsentStore,
    default_consent_path,
)

HEX32 = re.compile(r"^[a-f0-9]{32}$")
WIRE_PLATFORMS = {"darwin", "linux", "windows", "other"}
BASE_KEYS = {"event", "brass_version", "platform", "install_id", "timestamp_ms"}


@pytest.fixture(autouse=True)
def _reset_telemetry(monkeypatch):
    monkeypatch.setattr(tclient, "_DEFAULT_CLIENT", None)
    for name in ("BRASS_TELEMETRY", "BRASS_OFFLINE", "CI", "BRASS_GATEWAY_URL"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def store(tmp_path) -> ConsentStore:
    return ConsentStore(path=tmp_path / "telemetry")


class _Recorder:
    """Backend stand-in that captures emitted events."""

    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


def _client_for(store: ConsentStore, backend=None) -> TelemetryClient:
    return TelemetryClient(TelemetryConfig(backend=backend or _Recorder(), consent=store))


# --- ConsentStore ---------------------------------------------------------


def test_default_is_off_and_undecided(store):
    assert store.is_enabled() is False
    assert store.has_decided() is False
    assert store.state() == (False, REASON_DEFAULT)
    assert store.install_id() is None
    assert not store.path.exists()


def test_set_on_mints_hex32_id_and_decides(store):
    install_id = store.set(enabled=True)
    assert HEX32.match(install_id)
    assert store.install_id() == install_id
    assert store.has_decided() is True
    assert store.state() == (True, REASON_CONSENT_FILE)


def test_set_off_keeps_install_id_stable(store):
    first = store.set(enabled=True)
    assert store.set(enabled=False) == first
    assert store.install_id() == first
    assert store.state() == (False, REASON_CONSENT_FILE)
    assert store.set(enabled=True) == first  # on → off → on: same install


def test_reset_changes_id_and_keeps_consent(store):
    first = store.set(enabled=False)
    fresh = store.reset()
    assert HEX32.match(fresh) and fresh != first
    assert store.state() == (False, REASON_CONSENT_FILE)
    store.set(enabled=True)
    again = store.reset()
    assert again != fresh
    assert store.state() == (True, REASON_CONSENT_FILE)


def test_ensure_install_id_persists_only_the_id(store):
    install_id = store.ensure_install_id()
    assert HEX32.match(install_id)
    assert store.path.read_text() == f"install_id={install_id}\n"
    assert store.has_decided() is False  # the prompt can still ask
    assert store.ensure_install_id() == install_id  # idempotent


@pytest.mark.skipif(platform.system() == "Windows", reason="POSIX file modes")
def test_consent_file_is_private(store):
    store.set(enabled=True)
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600


def test_consent_path_resolves_home_at_construction(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    assert default_consent_path() == tmp_path / ".brass" / "telemetry"
    assert ConsentStore().path == tmp_path / ".brass" / "telemetry"


# --- env precedence ---------------------------------------------------------


def test_env_on_enables_without_file_and_mints_id(store, monkeypatch):
    monkeypatch.setenv("BRASS_TELEMETRY", "on")
    assert store.state() == (True, REASON_TELEMETRY_ENV)
    event = _client_for(store)._build_event("scan", {})
    assert HEX32.match(event["install_id"])
    kv = store.path.read_text()
    assert "install_id=" in kv and "consent=" not in kv


def test_env_off_beats_consent_file(store, monkeypatch):
    store.set(enabled=True)
    monkeypatch.setenv("BRASS_TELEMETRY", "off")
    assert store.state() == (False, REASON_TELEMETRY_ENV)


@pytest.mark.parametrize("value", ["1", "true", "yes", "on"])
def test_offline_env_beats_everything(store, monkeypatch, value):
    store.set(enabled=True)
    monkeypatch.setenv("BRASS_TELEMETRY", "on")
    monkeypatch.setenv("BRASS_OFFLINE", value)
    assert store.state() == (False, REASON_OFFLINE_ENV)
    assert store.is_enabled() is False


def test_record_is_silent_under_offline_env(store, monkeypatch):
    store.set(enabled=True)
    monkeypatch.setenv("BRASS_OFFLINE", "1")
    recorder = _Recorder()
    _client_for(store, recorder).record(event="scan", total_findings=1)
    assert recorder.events == []


def test_record_is_silent_when_consent_off(store):
    recorder = _Recorder()
    _client_for(store, recorder).record(event="scan", total_findings=1)
    assert recorder.events == []


def test_record_never_raises_when_consent_read_fails(store, monkeypatch):
    monkeypatch.setattr(ConsentStore, "is_enabled", lambda self: (_ for _ in ()).throw(OSError("x")))
    _client_for(store).record(event="scan")  # must not raise


# --- event builder ----------------------------------------------------------


def test_build_event_wire_shape(store):
    store.set(enabled=True)
    payload = {"total_findings": 3, "finding_types": {"security": 3}, "fast": False, "skip_me": None}
    event = _client_for(store)._build_event("scan", payload)
    assert set(event) == BASE_KEYS | {"total_findings", "finding_types", "fast"}
    assert event["event"] == "scan"
    assert event["platform"] in WIRE_PLATFORMS
    assert HEX32.match(event["install_id"])
    assert isinstance(event["timestamp_ms"], int)
    assert re.match(r"^[A-Za-z0-9.\-]{1,24}$", event["brass_version"])


def test_record_emits_built_event(store):
    store.set(enabled=True)
    recorder = _Recorder()
    _client_for(store, recorder).record(event="scan", total_findings=2)
    assert len(recorder.events) == 1
    assert recorder.events[0]["total_findings"] == 2
    assert "offline" not in recorder.events[0]


def test_platform_name_maps_unknown_to_other(monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "FreeBSD")
    assert platform_name() == "other"
    for known in KNOWN_PLATFORMS:
        monkeypatch.setattr(platform, "system", lambda k=known: k.capitalize())
        assert platform_name() == known


def test_default_config_uses_http_backend():
    assert isinstance(TelemetryConfig().backend, HttpBackend)


# --- HttpBackend ------------------------------------------------------------


def _capture_post(monkeypatch, *, raise_exc=None, status=204):
    calls = []

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        if raise_exc is not None:
            raise raise_exc
        return type("Resp", (), {"status_code": status})()

    monkeypatch.setattr("requests.post", fake_post)
    return calls


def test_http_backend_posts_event_to_gateway(monkeypatch, tmp_path):
    calls = _capture_post(monkeypatch)
    event = {"event": "scan", "total_findings": 1}
    HttpBackend(debug_log=MockBackend(log_path=tmp_path / "log")).emit(event)
    assert len(calls) == 1
    url, kwargs = calls[0]
    assert url == f"{DEFAULT_GATEWAY_URL}{TELEMETRY_PATH}"
    assert url == "https://brass-api-gateway.vercel.app/api/telemetry"
    assert kwargs["json"] == event
    assert kwargs["timeout"] == HTTP_TIMEOUT == (1.0, 1.5)
    assert kwargs["headers"]["User-Agent"].startswith("brasscoders")


def test_http_backend_honors_gateway_url_override(monkeypatch):
    calls = _capture_post(monkeypatch)
    monkeypatch.setenv("BRASS_GATEWAY_URL", "http://127.0.0.1:9/")
    HttpBackend(debug_log=None).emit({"event": "scan"})
    assert calls[0][0] == "http://127.0.0.1:9/api/telemetry"


@pytest.mark.parametrize("exc_name", ["Timeout", "ConnectionError", "RequestException"])
def test_http_backend_swallows_network_errors(monkeypatch, exc_name):
    import requests

    _capture_post(monkeypatch, raise_exc=getattr(requests.exceptions, exc_name)("boom"))
    HttpBackend(debug_log=None).emit({"event": "scan"})  # must not raise


def test_http_backend_ignores_http_500(monkeypatch):
    calls = _capture_post(monkeypatch, status=500)
    HttpBackend(debug_log=None).emit({"event": "scan"})
    assert len(calls) == 1


def test_http_backend_swallows_missing_requests(monkeypatch, tmp_path):
    monkeypatch.setitem(sys.modules, "requests", None)  # `import requests` → ImportError
    log = tmp_path / "log"
    HttpBackend(debug_log=MockBackend(log_path=log)).emit({"event": "scan"})
    assert log.read_text().count("\n") == 1  # tee still happened


def test_http_backend_tees_before_posting(monkeypatch, tmp_path):
    log = tmp_path / "log"
    order = []
    monkeypatch.setattr("requests.post", lambda *a, **k: order.append(("post", log.exists())))
    HttpBackend(debug_log=MockBackend(log_path=log)).emit({"event": "scan", "a": 1})
    assert order == [("post", True)]
    assert json.loads(log.read_text()) == {"event": "scan", "a": 1}


# --- MockBackend ------------------------------------------------------------


def test_mock_backend_path_resolves_home_at_construction(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    assert default_debug_log_path() == tmp_path / ".brass" / "telemetry-debug.log"
    assert MockBackend().log_path == tmp_path / ".brass" / "telemetry-debug.log"


def test_mock_backend_appends_one_jsonl_line(tmp_path):
    log = tmp_path / ".brass" / "telemetry-debug.log"
    backend = MockBackend(log_path=log)
    backend.emit({"event": "scan", "n": 1})
    backend.emit({"event": "scan", "n": 2})
    lines = log.read_text().splitlines()
    assert [json.loads(line)["n"] for line in lines] == [1, 2]


def test_mock_backend_rotates_past_cap(tmp_path):
    log = tmp_path / "telemetry-debug.log"
    log.write_text("x" * (DEBUG_LOG_MAX_BYTES + 1))
    MockBackend(log_path=log).emit({"event": "scan"})
    rotated = log.with_name("telemetry-debug.log.1")
    assert rotated.stat().st_size == DEBUG_LOG_MAX_BYTES + 1
    assert log.read_text().count("\n") == 1


def test_mock_backend_does_not_rotate_below_cap(tmp_path):
    log = tmp_path / "telemetry-debug.log"
    log.write_text("x" * DEBUG_LOG_MAX_BYTES)  # exactly at cap: no rotation
    MockBackend(log_path=log).emit({"event": "scan"})
    assert not log.with_name("telemetry-debug.log.1").exists()


# --- first-run prompt -------------------------------------------------------


@pytest.fixture
def interactive(monkeypatch):
    monkeypatch.setattr(tprompt, "is_interactive", lambda: True)


def test_should_prompt_when_everything_clear(store, interactive):
    assert tprompt.should_prompt(store, offline=False) is True


@pytest.mark.parametrize("env", [("BRASS_OFFLINE", "1"), ("BRASS_TELEMETRY", "off"), ("BRASS_TELEMETRY", "on"), ("CI", "true")])
def test_should_not_prompt_under_env(store, interactive, monkeypatch, env):
    monkeypatch.setenv(*env)
    assert tprompt.should_prompt(store, offline=False) is False


def test_should_not_prompt_offline(store, interactive):
    assert tprompt.should_prompt(store, offline=True) is False


def test_should_not_prompt_once_decided(store, interactive):
    store.set(enabled=False)
    assert tprompt.should_prompt(store, offline=False) is False


def test_should_not_prompt_without_tty(store, monkeypatch):
    monkeypatch.setattr(tprompt, "is_interactive", lambda: False)
    assert tprompt.should_prompt(store, offline=False) is False


def test_is_interactive_false_on_error(monkeypatch):
    class Broken:
        def isatty(self):
            raise ValueError("closed")

    monkeypatch.setattr(sys, "stdin", Broken())
    assert tprompt.is_interactive() is False


def test_prompt_default_enter_persists_off(store, interactive):
    out = []
    result = tprompt.maybe_prompt_for_consent(store, offline=False, ask=lambda _: "", out=out.append)
    assert result is False
    assert store.path.read_text() == "consent=off\n"
    assert tprompt.DECLINED_LINE in out
    assert any("[y/N]" not in line and "Starting with your next scan" in line for line in out)


@pytest.mark.parametrize("answer", ["y", "Y", "yes", " yes "])
def test_prompt_yes_persists_on(store, interactive, answer):
    out = []
    result = tprompt.maybe_prompt_for_consent(store, offline=False, ask=lambda _: answer, out=out.append)
    assert result is True
    assert store.state() == (True, REASON_CONSENT_FILE)
    assert HEX32.match(store.install_id())
    assert any(line.startswith("   ✅ Telemetry on. Install ID: ") for line in out)


@pytest.mark.parametrize("answer", ["n", "no", "maybe", "ye"])
def test_prompt_anything_else_is_no(store, interactive, answer):
    assert tprompt.maybe_prompt_for_consent(store, offline=False, ask=lambda _: answer, out=lambda _: None) is False
    assert store.state() == (False, REASON_CONSENT_FILE)


def test_prompt_eof_persists_off(store, interactive):
    def ask(_):
        raise EOFError

    assert tprompt.maybe_prompt_for_consent(store, offline=False, ask=ask, out=lambda _: None) is False
    assert store.path.read_text() == "consent=off\n"


def test_prompt_ctrl_c_persists_off_and_does_not_propagate(store, interactive):
    def ask(_):
        raise KeyboardInterrupt

    assert tprompt.maybe_prompt_for_consent(store, offline=False, ask=ask, out=lambda _: None) is False
    assert store.path.read_text() == "consent=off\n"


def test_prompt_asks_only_once(store, interactive):
    asked = []
    tprompt.maybe_prompt_for_consent(store, offline=False, ask=lambda q: asked.append(q) or "", out=lambda _: None)
    second = tprompt.maybe_prompt_for_consent(store, offline=False, ask=lambda q: asked.append(q) or "y", out=lambda _: None)
    assert second is None
    assert len(asked) == 1
    assert store.state() == (False, REASON_CONSENT_FILE)


def test_prompt_not_shown_persists_nothing(store, monkeypatch):
    monkeypatch.setattr(tprompt, "is_interactive", lambda: False)
    asked = []
    result = tprompt.maybe_prompt_for_consent(store, offline=False, ask=lambda q: asked.append(q) or "y", out=lambda _: None)
    assert result is None
    assert asked == []
    assert not store.path.exists()


def test_prompt_copy_is_honest():
    text = tprompt.CONSENT_PROMPT_INTRO + tprompt.CONSENT_QUESTION
    for required in ("Starting with your next scan", "Never sent: source code", "--offline",
                     "telemetry-debug.log", "telemetry on|off|status|reset", "[y/N]"):
        assert required in text
    for banned in ("Voyage", "Team", "Pro ", "Enterprise", "upgrade"):
        assert banned not in text
