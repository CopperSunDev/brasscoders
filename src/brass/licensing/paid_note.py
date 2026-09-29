"""Persistent dismiss for the post-scan Paid plan note.

File: ``$HOME/.brass/paid-note`` — the same tiny ``key=value`` format
as ``~/.brass/telemetry``:

    show=off

The note is ON when the file is absent (default) or says ``show=on``.
``brasscoders paid-note off`` writes ``show=off``; ``on`` writes
``show=on``. One file per concern under ``~/.brass`` (``license``,
``telemetry``, ``paid-note``) — a generic settings store is YAGNI
with one consumer.

Network policy: this store never makes network calls.
"""

from __future__ import annotations

import os
import platform
from dataclasses import dataclass, field
from pathlib import Path

from brass.core.atomic_writer import AtomicFileWriter


def default_paid_note_path() -> Path:
    return Path(os.path.expanduser("~")) / ".brass" / "paid-note"


@dataclass
class PaidNoteStore:
    """File-backed on/off flag at ``~/.brass/paid-note``.

    ``path`` is injectable for tests (``PaidNoteStore(path=tmp / "x")``),
    and resolves ``~`` at construction time so ``HOME`` redirects work.
    """

    path: Path = field(default_factory=default_paid_note_path)

    def is_enabled(self) -> bool:
        """True unless the file explicitly says ``show=off``."""
        return self._read_kv().get("show", "on") != "off"

    def set(self, *, enabled: bool) -> None:
        kv = self._read_kv()
        kv["show"] = "on" if enabled else "off"
        self._write_kv(kv)

    def _read_kv(self) -> dict[str, str]:
        if not self.path.exists():
            return {}
        result: dict[str, str] = {}
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            result[key.strip()] = value.strip()
        return result

    def _write_kv(self, kv: dict[str, str]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if platform.system() != "Windows":
            try:
                os.chmod(self.path.parent, 0o700)
            except OSError:
                pass
        body = "\n".join(f"{k}={v}" for k, v in sorted(kv.items())) + "\n"
        AtomicFileWriter.write_text_atomic(self.path, body)


__all__ = ["PaidNoteStore", "default_paid_note_path"]
