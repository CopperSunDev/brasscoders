"""Telemetry backends — HTTPS POST to the Copper Sun gateway, teed to a
local debug log.

Two backends implement ``BackendProtocol``:

- ``HttpBackend`` (the default): one synchronous ``requests.post`` per
  event to ``<gateway>/api/telemetry`` with tight connect/read timeouts.
  The gateway validates the event against a strict allowlist and
  forwards it to Axiom. Every failure — no network, DNS, timeout, HTTP
  error, missing ``requests`` — is swallowed; telemetry can never raise
  into the CLI's main flow or slow a scan by more than the timeout.
- ``MockBackend``: append-only JSONL at ``~/.brass/telemetry-debug.log``.
  ``HttpBackend`` tees every event through it *before* posting, so the
  log is the user's audit trail of exactly the bytes that were attempted.
  Single-generation rotation at ``DEBUG_LOG_MAX_BYTES``.

Consent is checked upstream by ``TelemetryClient``; ``--offline`` /
``BRASS_OFFLINE`` are honored there and at the CLI call site, so a
backend is never even constructed for an offline scan.
"""

from __future__ import annotations

import json
import os
import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Protocol, Tuple

# Route on the gateway (base URL comes from brass.enrichment.client's
# DEFAULT_GATEWAY_URL, overridable via BRASS_GATEWAY_URL — same knob
# the enrichment client uses).
TELEMETRY_PATH = "/api/telemetry"

# (connect, read) seconds. Deliberately tight: a normal round-trip is
# ~100-300 ms; a misbehaving network costs at most 2.5 s and never an
# error. A Vercel cold start can exceed the read timeout — the CLI drops
# the socket but the invocation still completes, so the event lands.
HTTP_TIMEOUT: Tuple[float, float] = (1.0, 1.5)

# Debug-log rotation threshold. One event is ~350-450 bytes, so this is
# roughly 600+ scans before the first rotation.
DEBUG_LOG_MAX_BYTES = 256 * 1024

USER_AGENT = "brasscoders/telemetry"


def default_debug_log_path() -> Path:
    """``~/.brass/telemetry-debug.log``, resolved at call time so tests that
    redirect ``HOME`` see the redirect."""
    return Path(os.path.expanduser("~")) / ".brass" / "telemetry-debug.log"


class BackendProtocol(Protocol):
    """Contract every telemetry backend must implement."""

    def emit(self, event: Dict[str, Any]) -> None:
        """Send a single event. Failures must not raise."""
        ...


@dataclass
class MockBackend:
    """Append-only debug backend.

    Writes one JSON line per event to ``log_path``. No network. Used on
    its own in tests and as the tee inside ``HttpBackend`` so a skeptical
    user can audit exactly what was sent.
    """

    log_path: Path = field(default_factory=default_debug_log_path)

    def emit(self, event: Dict[str, Any]) -> None:
        try:
            self._prepare_parent()
            self._rotate_if_needed()
            line = json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
            with self.log_path.open("a", encoding="utf-8") as fh:
                fh.write(line)
            self._restrict_mode()
        except Exception:
            # Telemetry must never raise into the CLI's main flow.
            pass

    def _prepare_parent(self) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        if platform.system() != "Windows":
            try:
                os.chmod(self.log_path.parent, 0o700)
            except OSError:
                pass

    def _rotate_if_needed(self) -> None:
        """Single-generation rotation: ``telemetry-debug.log`` →
        ``telemetry-debug.log.1`` once it exceeds ``DEBUG_LOG_MAX_BYTES``.
        The previous ``.1`` is overwritten. No dependencies, bounded disk."""
        try:
            if self.log_path.exists() and self.log_path.stat().st_size > DEBUG_LOG_MAX_BYTES:
                self.log_path.replace(self.log_path.with_name(self.log_path.name + ".1"))
        except OSError:
            pass

    def _restrict_mode(self) -> None:
        if platform.system() == "Windows":
            return
        try:
            if self.log_path.stat().st_mode & 0o077:
                os.chmod(self.log_path, 0o600)
        except OSError:
            pass


@dataclass
class HttpBackend:
    """POST each event to the gateway's ``/api/telemetry``; tee to the
    debug log first.

    Synchronous on purpose: a daemon thread would lose the event at
    interpreter exit unless joined, which reintroduces the wait. The
    bounded worst case is ``sum(timeout)`` seconds on a broken network.
    """

    timeout: Tuple[float, float] = HTTP_TIMEOUT
    debug_log: Optional[MockBackend] = field(default_factory=MockBackend)

    def emit(self, event: Dict[str, Any]) -> None:
        # Write the local copy first: the log shows what we *tried* to
        # send, whether or not the network cooperated.
        if self.debug_log is not None:
            self.debug_log.emit(event)
        try:
            import requests  # lazy — mirrors core/version_check.py
            # Lazy too: brass.enrichment.client imports requests at top level.
            from brass.enrichment.client import DEFAULT_GATEWAY_URL

            base = (os.environ.get("BRASS_GATEWAY_URL") or DEFAULT_GATEWAY_URL).rstrip("/")
            requests.post(
                base + TELEMETRY_PATH,
                json=event,
                timeout=self.timeout,
                headers={"User-Agent": USER_AGENT},
            )
        except Exception:
            # Loss-tolerant by design: never raise, never retry.
            pass


__all__ = [
    "BackendProtocol",
    "DEBUG_LOG_MAX_BYTES",
    "HTTP_TIMEOUT",
    "HttpBackend",
    "MockBackend",
    "TELEMETRY_PATH",
    "default_debug_log_path",
]
