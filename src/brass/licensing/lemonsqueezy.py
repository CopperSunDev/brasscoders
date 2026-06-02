"""LemonSqueezy License API client.

LemonSqueezy ships a complete license-key system as part of their billing
platform. We use it instead of running our own license server. The API is
documented at https://docs.lemonsqueezy.com/api/license-api — three
endpoints, no Bearer token (the license key itself is the credential):

- ``POST /v1/licenses/activate``     — first-time activation on a machine
- ``POST /v1/licenses/validate``     — confirm the license is still active
- ``POST /v1/licenses/deactivate``   — release a machine slot

The endpoints are public (no Bearer token, no API key), so we can call
them directly from the customer's CLI without proxying through our own
server. The license key itself is the credential.

Network policy: these endpoints are the *only* outbound calls BrassCoders
makes during a license-management command (``brasscoders activate``,
``brasscoders license``, ``brasscoders deactivate``). They are NOT called during
``brasscoders scan``, ``brasscoders watch``, or ``brasscoders filter`` — BrassCoders stays
offline-first for the actual analysis path.
"""

from __future__ import annotations

import platform
import re
import socket
from dataclasses import dataclass
from typing import Optional

import requests

# Match LemonSqueezy license-key shape: uppercase alphanumeric blocks
# separated by dashes (e.g. AAAA-BBBB-CCCC-DDDD-EEEE). Defense-in-depth
# against future LS responses that echo the request body — keeps the
# customer's key out of stdout/stderr / CI logs / support tickets.
# Mirrors the redactor in cli/src/brass/enrichment/client.py.
_LICENSE_SHAPE_RE = re.compile(r"\b[A-Z0-9]{4,12}(?:-[A-Z0-9]{4,12}){1,}\b")


def _redact_license_shape(message: str) -> str:
    return _LICENSE_SHAPE_RE.sub("<REDACTED_LICENSE>", message)


API_BASE = "https://api.lemonsqueezy.com/v1/licenses"
DEFAULT_TIMEOUT = 8.0
USER_AGENT = "brasscoders/license-client"


class LicenseAPIError(Exception):
    """Network failure or unexpected response shape."""


class LicenseInvalidError(Exception):
    """LS returned a clean response saying the key is not valid (revoked / expired / bad)."""


@dataclass(frozen=True)
class ActivationResult:
    """Successful activate or validate call."""

    license_key: str
    instance_id: str
    status: str  # 'active' | 'inactive' | 'expired' | 'disabled'
    activation_usage: int
    activation_limit: Optional[int]
    expires_at: Optional[str]  # ISO-8601 string, or None for perpetual
    customer_email: Optional[str]
    customer_name: Optional[str]
    product_name: Optional[str]


def _instance_name() -> str:
    """Human-readable name for this machine. Sent to LS so customers can
    see which devices have activations in their portal.

    No more identifying than what LS already gets from the IP address.
    """
    try:
        return f"{platform.system().lower()}/{socket.gethostname()}"[:80]
    except Exception:
        return platform.system().lower()


def _post(endpoint: str, *, license_key: str, instance_id: Optional[str] = None,
          instance_name: Optional[str] = None, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """POST to a LS license endpoint and return the parsed JSON.

    Raises ``LicenseAPIError`` on transport / HTTP failure. Raises
    ``LicenseInvalidError`` when LS returns a 400-shaped error indicating
    the license key is bad / revoked.
    """
    url = f"{API_BASE}/{endpoint}"
    body = {"license_key": license_key}
    if instance_id is not None:
        body["instance_id"] = instance_id
    if instance_name is not None:
        body["instance_name"] = instance_name

    headers = {
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }
    try:
        response = requests.post(url, data=body, headers=headers, timeout=timeout)
    except requests.RequestException as exc:
        raise LicenseAPIError(f"network error talking to LemonSqueezy: {exc}") from exc

    try:
        payload = response.json()
    except ValueError as exc:
        # Redact license-shape strings before interpolating response.text.
        # An LS / CDN error page that echoes the request body would
        # otherwise put the customer's license key into stdout / CI logs.
        snippet = _redact_license_shape(response.text[:200])
        raise LicenseAPIError(
            f"LemonSqueezy returned non-JSON ({response.status_code}): "
            f"{snippet!r}"
        ) from exc

    # LS returns 400 with a JSON error body on bad keys; treat that as a
    # licensing failure (not a transport failure) so the CLI can show a
    # clean message instead of a stack trace.
    if response.status_code == 400:
        raise LicenseInvalidError(
            _redact_license_shape(payload.get("error") or "license rejected")
        )
    if response.status_code >= 500:
        raise LicenseAPIError(
            f"LemonSqueezy server error ({response.status_code}); try again shortly"
        )
    if response.status_code != 200:
        # Strip the full payload, surface only status + redacted summary
        # of any error-shaped field. Avoid printing the entire payload
        # which may contain license-key echoes from LS error pages.
        err_msg = _redact_license_shape(str(payload.get("error") or payload.get("message") or ""))
        raise LicenseAPIError(
            f"LemonSqueezy returned unexpected status {response.status_code}"
            + (f": {err_msg}" if err_msg else "")
        )

    return payload


def _payload_to_result(payload: dict) -> ActivationResult:
    """Translate the LS response shape into our ``ActivationResult``."""
    license_block = payload.get("license_key") or {}
    instance_block = payload.get("instance") or {}
    meta_block = payload.get("meta") or {}
    return ActivationResult(
        license_key=str(license_block.get("key", "")),
        instance_id=str(instance_block.get("id", "")),
        status=str(license_block.get("status", "")),
        activation_usage=int(license_block.get("activation_usage", 0) or 0),
        activation_limit=(
            int(license_block["activation_limit"])
            if license_block.get("activation_limit") is not None
            else None
        ),
        expires_at=license_block.get("expires_at"),
        customer_email=meta_block.get("customer_email"),
        customer_name=meta_block.get("customer_name"),
        product_name=meta_block.get("product_name"),
    )


def activate(license_key: str, *, instance_name: Optional[str] = None) -> ActivationResult:
    """Activate ``license_key`` on this machine. Returns the new instance_id."""
    payload = _post(
        "activate",
        license_key=license_key,
        instance_name=instance_name or _instance_name(),
    )
    if not payload.get("activated"):
        raise LicenseInvalidError(
            payload.get("error") or "activation refused (no further detail from LS)"
        )
    return _payload_to_result(payload)


def validate(license_key: str, *, instance_id: str) -> ActivationResult:
    """Confirm ``license_key`` + ``instance_id`` are still active."""
    payload = _post("validate", license_key=license_key, instance_id=instance_id)
    if not payload.get("valid"):
        raise LicenseInvalidError(
            payload.get("error") or "license is no longer valid"
        )
    return _payload_to_result(payload)


def deactivate(license_key: str, *, instance_id: str) -> bool:
    """Release the activation slot for this machine. Idempotent on the LS side."""
    payload = _post("deactivate", license_key=license_key, instance_id=instance_id)
    return bool(payload.get("deactivated"))


__all__ = [
    "API_BASE",
    "ActivationResult",
    "LicenseAPIError",
    "LicenseInvalidError",
    "activate",
    "deactivate",
    "validate",
]
