"""Consent persistence — telemetry off by default, opt-in only."""

from __future__ import annotations

import os
import platform
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from brass.core.atomic_writer import AtomicFileWriter


CONSENT_PATH_DEFAULT = Path(os.path.expanduser("~")) / ".brass" / "telemetry"


@dataclass
class ConsentStore:
    """File-backed flag at ``~/.brass/telemetry``.

    File contents are a tiny INI-ish format:

        consent=on
        install_id=<uuid4>

    or ``consent=off`` (the default; the file may not exist at all when
    the user hasn't opted in).
    """

    path: Path = CONSENT_PATH_DEFAULT

    def is_enabled(self) -> bool:
        env = os.environ.get("BRASS_TELEMETRY", "").lower()
        if env in ("0", "off", "false", "no"):
            return False
        if env in ("1", "on", "true", "yes"):
            return True
        return self._read_kv().get("consent", "off") == "on"

    def install_id(self) -> Optional[str]:
        return self._read_kv().get("install_id") or None

    def set(self, *, enabled: bool) -> str:
        """Persist consent state. Returns the (possibly new) install_id."""
        kv = self._read_kv()
        kv["consent"] = "on" if enabled else "off"
        if enabled and not kv.get("install_id"):
            kv["install_id"] = uuid.uuid4().hex
        elif not enabled:
            # Clear install_id on opt-out so re-enabling later starts fresh.
            kv.pop("install_id", None)
        self._write_kv(kv)
        return kv.get("install_id", "")

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


def set_consent(enabled: bool, *, store: Optional[ConsentStore] = None) -> str:
    return (store or ConsentStore()).set(enabled=enabled)


__all__ = ["ConsentStore", "set_consent", "CONSENT_PATH_DEFAULT"]
