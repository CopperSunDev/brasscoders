"""On-disk store for the activated license + cached validation state.

File: ``$HOME/.brass/license`` (POSIX 0600). Contents are a small JSON
dict:

    {
      "license_key": "AAAA-BBBB-...",
      "instance_id": "abc-123",
      "status": "active",
      "activated_at": "2026-05-07T17:30:00+00:00",
      "last_validated_at": "2026-05-07T17:30:00+00:00",
      "expires_at": null,
      "customer_email": "user@example.com",
      "product_name": "BrassCoders"
    }

We store enough to (a) re-validate without prompting the user and (b)
display a useful ``brasscoders license`` summary even when offline.

Network policy: the store itself never makes network calls — the caller
(``brasscoders activate / license``) decides when to phone LS. We track
``last_validated_at`` so the CLI can decide whether to re-validate or
trust the cached status.
"""

from __future__ import annotations

import json
import os
import platform
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from brass.core.atomic_writer import AtomicFileWriter


def default_store_path() -> Path:
    return Path(os.path.expanduser("~")) / ".brass" / "license"


@dataclass
class LicenseRecord:
    """Persisted local view of an active license."""

    license_key: str
    instance_id: str
    status: str
    activated_at: str
    last_validated_at: str
    expires_at: Optional[str] = None
    customer_email: Optional[str] = None
    product_name: Optional[str] = None

    def is_active(self) -> bool:
        return self.status == "active"

    def days_since_validation(self, *, now: Optional[datetime] = None) -> int:
        try:
            seen = datetime.fromisoformat(self.last_validated_at)
        except (TypeError, ValueError):
            return 99999  # treat unparseable as stale
        if seen.tzinfo is None:
            seen = seen.replace(tzinfo=timezone.utc)
        moment = now or datetime.now(timezone.utc)
        delta = moment - seen
        return max(0, delta.days)


@dataclass
class LicenseStore:
    """File-backed store at ``~/.brass/license``."""

    path: Path

    @classmethod
    def default(cls) -> "LicenseStore":
        return cls(path=default_store_path())

    def exists(self) -> bool:
        return self.path.exists()

    def read(self) -> Optional[LicenseRecord]:
        if not self.path.exists():
            return None
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict):
            return None
        try:
            return LicenseRecord(**data)
        except TypeError:
            # File is older shape from a previous version — return None so
            # the caller treats it as "no license" and prompts re-activation.
            return None

    def write(self, record: LicenseRecord) -> None:
        self._ensure_parent()
        body = json.dumps(asdict(record), sort_keys=True, indent=2) + "\n"
        AtomicFileWriter.write_text_atomic(self.path, body)

    def update_validation(
        self,
        *,
        status: str,
        validated_at: Optional[str] = None,
    ) -> None:
        """Update only the cached-validation fields without rewriting other state."""
        existing = self.read()
        if existing is None:
            return
        existing.status = status
        existing.last_validated_at = validated_at or datetime.now(timezone.utc).isoformat()
        self.write(existing)

    def delete(self) -> bool:
        if not self.path.exists():
            return False
        self.path.unlink()
        return True

    def _ensure_parent(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if platform.system() != "Windows":
            try:
                os.chmod(self.path.parent, 0o700)
            except OSError:
                pass


__all__ = ["LicenseRecord", "LicenseStore", "default_store_path"]
