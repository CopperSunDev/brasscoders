"""Pluggable telemetry backend — mock now, Plausible/PostHog later.

The real backends (Plausible, PostHog) will slot in by implementing the
``BackendProtocol`` and being wired into ``TelemetryClient`` at construction.
Until accounts exist and credentials are provisioned, we ship the mock
backend, which writes events to ``~/.brass/telemetry-debug.log`` so the
user can inspect what *would* be transmitted.
"""

from __future__ import annotations

import json
import os
import platform
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Protocol


class BackendProtocol(Protocol):
    """Contract every telemetry backend must implement."""

    def emit(self, event: Dict[str, Any]) -> None:
        """Send a single event. Failures must not raise."""
        ...


@dataclass
class MockBackend:
    """Append-only debug backend.

    Writes JSONL to ``log_path``. No network. The CLI's first launch with
    telemetry enabled will write to ``~/.brass/telemetry-debug.log`` so a
    skeptical user can audit exactly what's being recorded before any real
    transport is wired up.
    """

    log_path: Path = Path(os.path.expanduser("~")) / ".brass" / "telemetry-debug.log"

    def emit(self, event: Dict[str, Any]) -> None:
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            if platform.system() != "Windows":
                try:
                    os.chmod(self.log_path.parent, 0o700)
                except OSError:
                    pass
            line = json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
            with self.log_path.open("a", encoding="utf-8") as fh:
                fh.write(line)
            if platform.system() != "Windows" and not self.log_path.stat().st_mode & 0o077 == 0:
                try:
                    os.chmod(self.log_path, 0o600)
                except OSError:
                    pass
        except Exception:
            # Telemetry must never raise into the CLI's main flow.
            pass


__all__ = ["BackendProtocol", "MockBackend"]
