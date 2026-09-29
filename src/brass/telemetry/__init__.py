"""Optional, opt-in usage telemetry — anonymous counts only.

**Off by default.** Enabled only when the user answers "y" to the one-time
interactive prompt after their first scan, runs ``brasscoders telemetry on``
(persisted in ``~/.brass/telemetry``), or sets ``BRASS_TELEMETRY=on``.

There is exactly one event, ``scan``, sent once per completed scan:

- ``event`` — always ``"scan"``
- ``brass_version`` — the running CLI version
- ``platform`` — ``darwin`` / ``linux`` / ``windows`` / ``other``
- ``install_id`` — random UUID minted once and stored in
  ``~/.brass/telemetry``. Counts distinct installs; identifies the
  install, not the user. Stable across opt-out; ``brasscoders telemetry
  reset`` mints a new one.
- ``timestamp_ms`` — client clock (the server stamps its own time too)
- ``total_findings`` — count after ranking
- ``finding_types`` — counts keyed by finding type (``security``, …)
- ``severity_counts`` — counts keyed by severity (``critical``, …)
- ``fast`` / ``dev_mode`` — whether ``--fast`` / ``--dev`` were used

What we **never** send:
- Source code, file paths, or filenames
- Email addresses, license keys, or any PII
- Stack traces or error messages
- The contents of ``.brass/*.yaml``

Transport: one HTTPS POST to Copper Sun's gateway (``/api/telemetry``),
which validates the event against a strict allowlist and stores it in
Axiom. ``--offline`` / ``BRASS_OFFLINE`` always win — nothing is sent,
and nothing is written to the debug log. Every event that *is* sent is
also appended to ``~/.brass/telemetry-debug.log`` so the user can audit
exactly what left the machine.
"""

from brass.telemetry.backend import BackendProtocol, HttpBackend, MockBackend
from brass.telemetry.client import (
    TelemetryClient,
    TelemetryConfig,
    is_enabled,
    record,
)
from brass.telemetry.consent import (
    ConsentStore,
    set_consent,
)
from brass.telemetry.prompt import maybe_prompt_for_consent

__all__ = [
    "BackendProtocol",
    "ConsentStore",
    "HttpBackend",
    "MockBackend",
    "TelemetryClient",
    "TelemetryConfig",
    "is_enabled",
    "maybe_prompt_for_consent",
    "record",
    "set_consent",
]
