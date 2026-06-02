"""Phase 4 regression tests — LemonSqueezy license keys + on-disk store.

The licensing module is now a thin HTTP client over LS's License API plus a
JSON-backed local store. Tests mock ``requests.post`` so the suite never
talks to the real LS API.
"""

from __future__ import annotations

import json
import platform
import stat
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest


# --------------------------------------------------------------------------- #
# LS HTTP client                                                              #
# --------------------------------------------------------------------------- #


def _mock_response(status_code: int = 200, payload: dict | None = None):
    """Build a minimal stand-in for ``requests.Response``."""
    class _R:
        def __init__(self):
            self.status_code = status_code
            self._payload = payload or {}
            self.text = json.dumps(self._payload)

        def json(self):
            return self._payload

    return _R()


_OK_PAYLOAD = {
    "activated": True,
    "error": None,
    "license_key": {
        "id": 1,
        "status": "active",
        "key": "AAAA-BBBB-CCCC-DDDD",
        "activation_limit": 5,
        "activation_usage": 1,
        "created_at": "2026-05-07T17:00:00.000000Z",
        "expires_at": None,
    },
    "instance": {
        "id": "instance-abc",
        "name": "darwin/laptop",
        "created_at": "2026-05-07T17:00:00.000000Z",
    },
    "meta": {
        "store_id": 1,
        "order_id": 100,
        "product_name": "BrassCoders",
        "customer_email": "user@example.com",
        "customer_name": "User Example",
    },
}


def test_activate_ok_returns_parsed_result():
    from brass.licensing import activate

    with patch("brass.licensing.lemonsqueezy.requests.post") as mock_post:
        mock_post.return_value = _mock_response(200, _OK_PAYLOAD)
        result = activate("AAAA-BBBB-CCCC-DDDD")

    assert result.license_key == "AAAA-BBBB-CCCC-DDDD"
    assert result.instance_id == "instance-abc"
    assert result.status == "active"
    assert result.activation_usage == 1
    assert result.activation_limit == 5
    assert result.expires_at is None
    assert result.customer_email == "user@example.com"
    assert result.product_name == "BrassCoders"

    # Verify we hit the right URL with the right body shape.
    args, kwargs = mock_post.call_args
    assert args[0] == "https://api.lemonsqueezy.com/v1/licenses/activate"
    body = kwargs["data"]
    assert body["license_key"] == "AAAA-BBBB-CCCC-DDDD"
    assert "instance_name" in body  # we always send a friendly name


def test_activate_400_raises_invalid():
    from brass.licensing import activate, LicenseInvalidError

    with patch("brass.licensing.lemonsqueezy.requests.post") as mock_post:
        mock_post.return_value = _mock_response(400, {"error": "license key not found"})
        with pytest.raises(LicenseInvalidError, match="not found"):
            activate("BAD-KEY")


def test_activate_500_raises_api_error():
    from brass.licensing import activate, LicenseAPIError

    with patch("brass.licensing.lemonsqueezy.requests.post") as mock_post:
        mock_post.return_value = _mock_response(503, {})
        with pytest.raises(LicenseAPIError, match="server error"):
            activate("AAAA-BBBB-CCCC-DDDD")


def test_activate_network_error_raises_api_error():
    import requests as _requests
    from brass.licensing import activate, LicenseAPIError

    with patch("brass.licensing.lemonsqueezy.requests.post") as mock_post:
        mock_post.side_effect = _requests.ConnectionError("dns failure")
        with pytest.raises(LicenseAPIError, match="network error"):
            activate("AAAA-BBBB-CCCC-DDDD")


def test_validate_invalid_returns_clean_error():
    from brass.licensing import validate, LicenseInvalidError

    with patch("brass.licensing.lemonsqueezy.requests.post") as mock_post:
        mock_post.return_value = _mock_response(
            200,
            {
                "valid": False,
                "error": "license key has been disabled",
                "license_key": {"key": "X", "status": "disabled"},
                "instance": {"id": "instance-abc"},
                "meta": {},
            },
        )
        with pytest.raises(LicenseInvalidError, match="disabled"):
            validate("X", instance_id="instance-abc")


def test_deactivate_returns_true_on_success():
    from brass.licensing import deactivate

    with patch("brass.licensing.lemonsqueezy.requests.post") as mock_post:
        mock_post.return_value = _mock_response(200, {"deactivated": True})
        assert deactivate("AAAA-BBBB-CCCC-DDDD", instance_id="instance-abc") is True


def test_deactivate_unknown_instance_raises_invalid():
    from brass.licensing import deactivate, LicenseInvalidError

    with patch("brass.licensing.lemonsqueezy.requests.post") as mock_post:
        mock_post.return_value = _mock_response(400, {"error": "instance not found"})
        with pytest.raises(LicenseInvalidError):
            deactivate("AAAA-BBBB-CCCC-DDDD", instance_id="missing")


# --------------------------------------------------------------------------- #
# Local store                                                                 #
# --------------------------------------------------------------------------- #


def _record(now: datetime | None = None):
    from brass.licensing import LicenseRecord

    moment = (now or datetime.now(timezone.utc)).isoformat()
    return LicenseRecord(
        license_key="AAAA-BBBB-CCCC-DDDD",
        instance_id="instance-abc",
        status="active",
        activated_at=moment,
        last_validated_at=moment,
        expires_at=None,
        customer_email="user@example.com",
        product_name="BrassCoders",
    )


def test_store_round_trip_with_owner_only_perms(tmp_path):
    from brass.licensing import LicenseStore

    store = LicenseStore(path=tmp_path / "license")
    record = _record()
    store.write(record)
    assert store.exists()

    if platform.system() != "Windows":
        mode = stat.S_IMODE(store.path.stat().st_mode)
        assert mode == 0o600, f"license file should be 0600, got {oct(mode)}"

    re_read = store.read()
    assert re_read is not None
    assert re_read.license_key == "AAAA-BBBB-CCCC-DDDD"
    assert re_read.instance_id == "instance-abc"


def test_store_delete_removes_file(tmp_path):
    from brass.licensing import LicenseStore

    store = LicenseStore(path=tmp_path / "license")
    store.write(_record())
    assert store.delete() is True
    assert not store.exists()
    assert store.read() is None


def test_store_returns_none_on_empty_path(tmp_path):
    from brass.licensing import LicenseStore

    store = LicenseStore(path=tmp_path / "license")
    assert store.read() is None
    assert store.delete() is False


def test_record_days_since_validation():
    record = _record(now=datetime.now(timezone.utc) - timedelta(days=10))
    assert record.days_since_validation() >= 10


def test_record_unparseable_timestamp_treated_as_stale(tmp_path):
    from brass.licensing import LicenseRecord

    record = LicenseRecord(
        license_key="X",
        instance_id="Y",
        status="active",
        activated_at="garbage",
        last_validated_at="not-an-iso-string",
    )
    # Big number rather than 0 — caller should treat as "long overdue
    # for re-validation" rather than "just validated".
    assert record.days_since_validation() > 365


def test_update_validation_only_changes_validation_fields(tmp_path):
    from brass.licensing import LicenseStore

    store = LicenseStore(path=tmp_path / "license")
    original = _record(now=datetime(2026, 5, 1, tzinfo=timezone.utc))
    store.write(original)

    store.update_validation(status="disabled", validated_at="2026-06-01T00:00:00+00:00")
    updated = store.read()
    assert updated is not None
    assert updated.status == "disabled"
    assert updated.last_validated_at == "2026-06-01T00:00:00+00:00"
    # Activated-at stays at the original moment.
    assert updated.activated_at == original.activated_at


# --------------------------------------------------------------------------- #
# Network policy: scan/filter/watch/version do NOT phone LS                   #
# --------------------------------------------------------------------------- #


def test_licensing_module_only_imports_requests_lazily():
    """The licensing module imports requests at the top of lemonsqueezy.py
    (necessarily), but the rest of the brass package shouldn't pull license
    code into its import graph during a normal scan. Sanity check: importing
    the scan path doesn't transitively call any LS endpoint.

    This isn't a perfect test — it's a sanity assertion that our module
    boundaries match the network-policy claim ("only license commands phone
    LS"). If you accidentally wire ``brass.licensing.activate`` into
    ``brass.scanners`` somewhere, this test won't catch it directly, but
    the integration tests will.
    """
    with patch("brass.licensing.lemonsqueezy.requests.post") as mock_post:
        # Importing the scan path should not call into LS.
        import brass.cli.brass_cli  # noqa: F401
        import brass.scanners.api_security_scanner  # noqa: F401
        import brass.scanners.brass2_privacy_scanner  # noqa: F401
        assert mock_post.call_count == 0
