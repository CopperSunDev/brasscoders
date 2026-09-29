"""Consent persistence — telemetry off by default, opt-in only.

Resolution order for "is telemetry on?" (first match wins):

1. ``BRASS_OFFLINE`` set to a truthy value → **off**. ``--offline`` is a hard
   no-network contract and beats every other setting, including
   ``BRASS_TELEMETRY=on``.
2. ``BRASS_TELEMETRY`` env: off-values force off, on-values force on.
3. ``~/.brass/telemetry`` ``consent=on|off``.
4. Default: off (never opted in).

The install ID is stable: it is minted once and survives opt-out, so
on → off → on counts as one install, not two. ``reset()`` mints a fresh
one on request (``brasscoders telemetry reset``).
"""

from __future__ import annotations

import os
import platform
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Tuple

from brass.core.atomic_writer import AtomicFileWriter


def default_consent_path() -> Path:
    """``~/.brass/telemetry``, resolved at call time so tests that redirect
    ``HOME`` see the redirect."""
    return Path(os.path.expanduser("~")) / ".brass" / "telemetry"


# Import-time snapshot kept for import compatibility. New code should
# call ``default_consent_path()`` or rely on ``ConsentStore()``'s factory.
CONSENT_PATH_DEFAULT = default_consent_path()

_ON_VALUES = ("1", "on", "true", "yes")
_OFF_VALUES = ("0", "off", "false", "no")

# ``state()`` reasons — shown verbatim by ``brasscoders telemetry status``.
REASON_OFFLINE_ENV = "BRASS_OFFLINE env"
REASON_TELEMETRY_ENV = "BRASS_TELEMETRY env"
REASON_CONSENT_FILE = "consent file"
REASON_DEFAULT = "default (never opted in)"


def offline_env_set() -> bool:
    """True when ``BRASS_OFFLINE`` carries a truthy value."""
    return os.environ.get("BRASS_OFFLINE", "").lower() in _ON_VALUES


@dataclass
class ConsentStore:
    """File-backed flag at ``~/.brass/telemetry``.

    File contents are a tiny ``key=value`` format:

        consent=on
        install_id=<uuid4 hex>

    ``consent`` is absent until the user decides (prompt or subcommand);
    ``install_id`` may exist on its own (minted by ``ensure_install_id``).
    """

    path: Path = field(default_factory=default_consent_path)

    def state(self) -> Tuple[bool, str]:
        """``(enabled, reason)`` — why telemetry is on or off right now."""
        if offline_env_set():
            return False, REASON_OFFLINE_ENV
        env = os.environ.get("BRASS_TELEMETRY", "").lower()
        if env in _OFF_VALUES:
            return False, REASON_TELEMETRY_ENV
        if env in _ON_VALUES:
            return True, REASON_TELEMETRY_ENV
        kv = self._read_kv()
        if "consent" in kv:
            return kv["consent"] == "on", REASON_CONSENT_FILE
        return False, REASON_DEFAULT

    def is_enabled(self) -> bool:
        return self.state()[0]

    def has_decided(self) -> bool:
        """True once a ``consent=`` line exists — the prompt asks only when False."""
        return "consent" in self._read_kv()

    def install_id(self) -> Optional[str]:
        return self._read_kv().get("install_id") or None

    def ensure_install_id(self) -> str:
        """Return the install ID, minting and persisting one if absent.

        Writes ONLY the ``install_id`` key — never ``consent=`` — so the
        "undecided" state the first-run prompt relies on is untouched.
        """
        kv = self._read_kv()
        if kv.get("install_id"):
            return kv["install_id"]
        kv["install_id"] = uuid.uuid4().hex
        self._write_kv(kv)
        return kv["install_id"]

    def reset(self) -> str:
        """Mint a fresh install ID. Consent is unchanged."""
        kv = self._read_kv()
        kv["install_id"] = uuid.uuid4().hex
        self._write_kv(kv)
        return kv["install_id"]

    def set(self, *, enabled: bool) -> str:
        """Persist consent state. Returns the (possibly new) install_id.

        Opting out keeps the install ID so re-enabling later is the same
        install; only ``reset()`` changes it.
        """
        kv = self._read_kv()
        kv["consent"] = "on" if enabled else "off"
        if enabled and not kv.get("install_id"):
            kv["install_id"] = uuid.uuid4().hex
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
        if platform.system() != "Windows":
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass


def set_consent(enabled: bool, *, store: Optional[ConsentStore] = None) -> str:
    return (store or ConsentStore()).set(enabled=enabled)


__all__ = [
    "CONSENT_PATH_DEFAULT",
    "ConsentStore",
    "REASON_CONSENT_FILE",
    "REASON_DEFAULT",
    "REASON_OFFLINE_ENV",
    "REASON_TELEMETRY_ENV",
    "default_consent_path",
    "offline_env_set",
    "set_consent",
]
