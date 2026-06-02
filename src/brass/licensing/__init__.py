"""BrassCoders licensing — backed by LemonSqueezy's License API.

The Phase 4 design originally used Ed25519 offline-signed tokens. We
swapped to LemonSqueezy because LS already handles the things a
license server has to do: revocation on cancel/refund, activation
limits per subscription, customer self-service from the LS portal —
all without requiring us to operate signing keys or run our own
license server.

Architecture:

  Customer buys      → LS auto-mints a license key, emails customer
  brasscoders activate   → POST /v1/licenses/activate to LS,
                       persists key + instance_id to ~/.brass/license
  brasscoders license    → POST /v1/licenses/validate (re-validates if
                       last validation > 7 days old) and prints status
  brasscoders deactivate → POST /v1/licenses/deactivate, removes the
                       on-disk record

Network policy: only the three license-management commands above
phone LS. ``brasscoders scan / watch / filter / version / status`` make
zero outbound calls and continue to honor ``--offline``. The privacy
policy on the marketing site discloses this.

Module map:

- ``store.py``        — on-disk record at ``~/.brass/license`` (0600)
- ``lemonsqueezy.py`` — thin HTTP client over LS's three endpoints
"""

from brass.licensing.lemonsqueezy import (
    ActivationResult,
    LicenseAPIError,
    LicenseInvalidError,
    activate,
    deactivate,
    validate,
)
from brass.licensing.store import (
    LicenseRecord,
    LicenseStore,
    default_store_path,
)

__all__ = [
    "ActivationResult",
    "LicenseAPIError",
    "LicenseInvalidError",
    "LicenseRecord",
    "LicenseStore",
    "activate",
    "deactivate",
    "default_store_path",
    "validate",
]
