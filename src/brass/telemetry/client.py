"""Top-level telemetry client and convenience helpers."""

from __future__ import annotations

import platform
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from brass.telemetry.backend import BackendProtocol, HttpBackend
from brass.telemetry.consent import ConsentStore

# The gateway's `platform` enum. Anything else maps to "other" (the wire
# schema is strict; an unknown OS name would 400 the whole event).
KNOWN_PLATFORMS = frozenset({"darwin", "linux", "windows"})


def platform_name() -> str:
    name = platform.system().lower()
    return name if name in KNOWN_PLATFORMS else "other"


@dataclass
class TelemetryConfig:
    """Runtime configuration for the telemetry pipeline."""

    backend: BackendProtocol = field(default_factory=HttpBackend)
    consent: ConsentStore = field(default_factory=ConsentStore)


@dataclass
class TelemetryClient:
    """Thin façade callers use: ``client.record(event="scan", **payload)``.

    Records nothing if consent is off. Never raises.
    """

    config: TelemetryConfig = field(default_factory=TelemetryConfig)

    def is_enabled(self) -> bool:
        return self.config.consent.is_enabled()

    def record(self, *, event: str, **payload: Any) -> None:
        try:
            if not self.is_enabled():
                return
            full = self._build_event(event, payload)
            self.config.backend.emit(full)
        except Exception:
            pass

    def _build_event(self, event: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        try:
            from brass import __version__ as brass_version
        except (ImportError, AttributeError):
            brass_version = "unknown"
        return {
            "event": event,
            "brass_version": brass_version,
            "platform": platform_name(),
            # Stable, minted on first use; the gateway rejects an empty id.
            "install_id": self.config.consent.ensure_install_id(),
            "timestamp_ms": int(time.time() * 1000),
            **{k: v for k, v in payload.items() if v is not None},
        }


_DEFAULT_CLIENT: Optional[TelemetryClient] = None


def _client() -> TelemetryClient:
    global _DEFAULT_CLIENT
    if _DEFAULT_CLIENT is None:
        _DEFAULT_CLIENT = TelemetryClient()
    return _DEFAULT_CLIENT


def is_enabled() -> bool:
    """Convenience: is telemetry currently on?"""
    return _client().is_enabled()


def record(*, event: str, **payload: Any) -> None:
    """Convenience: emit a single event via the default client.

    Safe to call from anywhere — silently no-ops when consent is off and
    swallows any backend failure.
    """
    _client().record(event=event, **payload)


__all__ = [
    "KNOWN_PLATFORMS",
    "TelemetryClient",
    "TelemetryConfig",
    "is_enabled",
    "platform_name",
    "record",
]
