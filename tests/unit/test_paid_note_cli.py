"""Unit tests for the post-scan Paid plan note (Part C).

Covers ``BrassCLI._print_paid_note`` (shown only for
``heuristic_no_license``; suppressed by every other mode, by
``BRASS_QUIET_PAID_NOTE=1``, and by ``brasscoders paid-note off``),
``PaidNoteStore``, and the ``paid-note on|off|status`` subcommand.

Template: ``test_cache_clear_cli.py`` (BrassCLI() + capsys + HOME isolation).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from brass.cli.brass_cli import BrassCLI, PAID_NOTE_LINE
from brass.core import enrichment_mode as em
from brass.licensing.paid_note import PaidNoteStore, default_paid_note_path


def _isolate_env(monkeypatch, tmp_path: Path) -> Path:
    """HOME → tmp_path so ``PaidNoteStore()`` resolves under the test dir.
    Returns the settings path the CLI will use."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("BRASS_QUIET_PAID_NOTE", raising=False)
    resolved = default_paid_note_path().resolve()
    assert str(resolved).startswith(str(tmp_path.resolve())), (
        f"Test isolation failed: paid-note path {resolved} is not under {tmp_path}"
    )
    return resolved


# --- PaidNoteStore --------------------------------------------------


def test_store_defaults_enabled_when_file_absent(tmp_path):
    store = PaidNoteStore(path=tmp_path / "paid-note")
    assert not store.path.exists()
    assert store.is_enabled() is True


def test_store_set_roundtrip(tmp_path):
    store = PaidNoteStore(path=tmp_path / "paid-note")
    store.set(enabled=False)
    assert store.path.read_text() == "show=off\n"
    assert store.is_enabled() is False
    store.set(enabled=True)
    assert store.is_enabled() is True
    assert store.path.read_text() == "show=on\n"


def test_store_path_resolves_home_at_construction(tmp_path, monkeypatch):
    _isolate_env(monkeypatch, tmp_path)
    assert PaidNoteStore().path == tmp_path / ".brass" / "paid-note"


# --- _print_paid_note -----------------------------------------------


def test_note_shown_for_no_license_mode(tmp_path, monkeypatch, capsys):
    _isolate_env(monkeypatch, tmp_path)
    BrassCLI()._print_paid_note(em.HEURISTIC_NO_LICENSE)
    out = capsys.readouterr().out
    assert out == PAID_NOTE_LINE + "\n"
    assert out.count("\n") == 1  # exactly one line
    assert "BrassCoders Paid" in out
    assert "https://coppersun.dev/why-brass" in out
    assert "brasscoders paid-note off" in out


@pytest.mark.parametrize("mode", [
    em.ENRICHED,
    em.HEURISTIC_OFFLINE,
    em.HEURISTIC_FALLBACK,
    em.HEURISTIC_NO_ENRICH_FLAG,
    None,
])
def test_note_silent_for_every_other_mode(tmp_path, monkeypatch, capsys, mode):
    _isolate_env(monkeypatch, tmp_path)
    BrassCLI()._print_paid_note(mode)
    assert capsys.readouterr().out == ""


def test_note_suppressed_by_env(tmp_path, monkeypatch, capsys):
    _isolate_env(monkeypatch, tmp_path)
    monkeypatch.setenv("BRASS_QUIET_PAID_NOTE", "1")
    BrassCLI()._print_paid_note(em.HEURISTIC_NO_LICENSE)
    assert capsys.readouterr().out == ""


def test_note_suppressed_by_persisted_off(tmp_path, monkeypatch, capsys):
    _isolate_env(monkeypatch, tmp_path)
    PaidNoteStore().set(enabled=False)
    BrassCLI()._print_paid_note(em.HEURISTIC_NO_LICENSE)
    assert capsys.readouterr().out == ""


def test_note_shown_when_store_file_is_garbage(tmp_path, monkeypatch, capsys):
    """A corrupt settings file must neither raise nor silently hide the
    note — unparseable lines are ignored and the default (on) applies."""
    path = _isolate_env(monkeypatch, tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("this is not a key value file\n\x00\x01garbage\n")
    BrassCLI()._print_paid_note(em.HEURISTIC_NO_LICENSE)  # must not raise
    assert capsys.readouterr().out == PAID_NOTE_LINE + "\n"


def test_note_swallows_store_exceptions(tmp_path, monkeypatch, capsys):
    """If reading the store raises, the note is dropped — never the scan."""
    _isolate_env(monkeypatch, tmp_path)
    monkeypatch.setattr(
        PaidNoteStore, "is_enabled",
        lambda self: (_ for _ in ()).throw(OSError("disk on fire")),
    )
    BrassCLI()._print_paid_note(em.HEURISTIC_NO_LICENSE)  # must not raise
    assert capsys.readouterr().out == ""


# --- brasscoders paid-note on|off|status ----------------------------


def test_paid_note_subcommand_roundtrip(tmp_path, monkeypatch, capsys):
    path = _isolate_env(monkeypatch, tmp_path)
    cli = BrassCLI()

    assert cli.run(["paid-note", "status"]) == 0
    assert "ON" in capsys.readouterr().out

    assert cli.run(["paid-note", "off"]) == 0
    out = capsys.readouterr().out
    assert "OFF" in out
    assert path.read_text() == "show=off\n"
    assert PaidNoteStore().is_enabled() is False

    assert cli.run(["paid-note", "status"]) == 0
    assert "OFF" in capsys.readouterr().out

    assert cli.run(["paid-note", "on"]) == 0
    assert "ON" in capsys.readouterr().out
    assert PaidNoteStore().is_enabled() is True


def test_paid_note_off_then_scan_footer_is_silent(tmp_path, monkeypatch, capsys):
    """End-to-end within the CLI object: the subcommand's persisted
    dismiss is honored by the scan footer."""
    _isolate_env(monkeypatch, tmp_path)
    cli = BrassCLI()
    assert cli.run(["paid-note", "off"]) == 0
    capsys.readouterr()
    cli._print_paid_note(em.HEURISTIC_NO_LICENSE)
    assert capsys.readouterr().out == ""
