"""Optional, opt-in telemetry — anonymized usage counts only.

**Off by default.** Enabled only when the user runs ``brasscoders telemetry on``
(persisted in ``~/.brass/telemetry``) or sets ``BRASS_TELEMETRY=on``.

What we send:
- ``brass_version`` — the running CLI version
- ``platform`` — ``darwin`` / ``linux`` / ``windows``
- ``event`` — one of ``scan``, ``filter``, ``activate``, ``watch``
- ``finding_counts`` — per-FindingType total (when applicable)
- ``duration_ms`` — round-trip wall time of the action
- ``install_id`` — random UUID generated once at first opt-in, stored in
  ``~/.brass/telemetry``. Lets us count distinct installs without
  identifying users.

What we **never** send:
- Source code, file paths, or filenames
- Email addresses, license tokens, or any PII
- Stack traces or error messages
- The contents of ``.brass/*.yaml``

Pluggable backend. The current backend is a mock that buffers events to
``~/.brass/telemetry-debug.log`` so the user can inspect what *would* be
sent. Real Plausible / PostHog / self-hosted backends slot in via the
``BackendProtocol`` once those accounts are configured at launch (see
``external-accounts-needed.md``).
"""

from brass.telemetry.backend import BackendProtocol, MockBackend
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

__all__ = [
    "BackendProtocol",
    "ConsentStore",
    "MockBackend",
    "TelemetryClient",
    "TelemetryConfig",
    "is_enabled",
    "record",
    "set_consent",
]
