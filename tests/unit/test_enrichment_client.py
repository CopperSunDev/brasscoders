"""Tests for the enrichment HTTPS client.

All tests mock requests.{get,post}; no real network. Verifies the wire
format we send to the gateway, and that we map gateway HTTP statuses to
the right Python exception types so the CLI's branching is correct.
"""

from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

import pytest


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #


def _mock_response(status_code: int, payload: dict | None = None):
    r = MagicMock()
    r.status_code = status_code
    body = payload or {}
    r.json.return_value = body
    r.text = json.dumps(body)
    return r


def _client(**overrides):
    from brass.enrichment import EnrichmentClient

    defaults = {
        "license_key": "AAAA-BBBB-CCCC-DDDD",
        "instance_id": "instance-abc",
        "gateway_url": "https://test.example",
    }
    defaults.update(overrides)
    return EnrichmentClient(**defaults)


@pytest.fixture(autouse=True)
def _no_real_sleep_in_retry(monkeypatch):
    """Patch the 2-second retry sleep out of every test in this file.

    The client retries once on transient `EnrichmentUnavailableError`,
    sleeping 2s between attempts. Without this autouse patch, every
    test that exercises a 5xx / network / unexpected-4xx response
    would block for 2 real seconds. Tests that want to ASSERT on the
    sleep call still get a Mock (via `patch("...time.sleep")` in the
    test body, which shadows this monkeypatch within its `with`).
    """
    monkeypatch.setattr(
        "brass.enrichment.client.time.sleep", lambda _s: None
    )


_OK_ENRICH_BODY = {
    # New (2C) wire format: survivors only, sorted by rank_score desc,
    # cluster_size per survivor. f1 was deduped into f0 → not in
    # response; f0 reports cluster_size=2 (itself + 1 absorbed dup).
    "findings": [
        {"id": "f0", "rank_score": 0.9, "cluster_size": 2},
    ],
    "tokens_used": 1234,
    "quota_remaining": 4_998_766,
    "quota_period_end": "2026-06-09T00:00:00Z",
}


# --------------------------------------------------------------------------- #
# enrich() happy + sad paths                                                  #
# --------------------------------------------------------------------------- #


def test_enrich_ok_parses_response_into_typed_dataclasses():
    with patch("brass.enrichment.client.requests.post") as post:
        post.return_value = _mock_response(200, _OK_ENRICH_BODY)
        result = _client().enrich(
            findings=[("f0", "text 0"), ("f1", "text 1")],
            raw_files={"readme": "sig"},
        )

    assert result.tokens_used == 1234
    assert result.quota_remaining == 4_998_766
    # New (2C) wire format: response contains survivors only. f1 was
    # deduped into f0 — not in response; f0 reports cluster_size=2.
    assert len(result.findings) == 1
    assert result.findings[0].id == "f0"
    assert result.findings[0].rank_score == 0.9
    assert result.findings[0].cluster_size == 2


def test_enrich_sends_correct_wire_format():
    with patch("brass.enrichment.client.requests.post") as post:
        post.return_value = _mock_response(200, _OK_ENRICH_BODY)
        _client().enrich(
            findings=[("f0", "x"), ("f1", "y")],
            raw_files={"readme": "sig"},
            rerank_top_n=99,
            dedup_threshold=0.7,
        )

    args, kwargs = post.call_args
    assert args[0] == "https://test.example/api/enrich"
    body = kwargs["json"]
    assert body["license_key"] == "AAAA-BBBB-CCCC-DDDD"
    assert body["instance_id"] == "instance-abc"
    # New (2C) wire format: raw_files dict instead of pre-built signature.
    assert body["raw_files"] == {"readme": "sig"}
    assert body["findings"] == [
        {"id": "f0", "text": "x"},
        {"id": "f1", "text": "y"},
    ]
    assert body["options"] == {"rerank_top_n": 99, "dedup_threshold": 0.7}


def test_enrich_401_raises_license_rejected():
    from brass.enrichment import LicenseRejectedError

    with patch("brass.enrichment.client.requests.post") as post:
        post.return_value = _mock_response(401, {"error": "invalid_license", "message": "nope"})
        with pytest.raises(LicenseRejectedError, match="nope"):
            _client().enrich(findings=[("f0", "x")], raw_files={"readme": "s"})


def test_enrich_403_raises_license_rejected():
    from brass.enrichment import LicenseRejectedError

    with patch("brass.enrichment.client.requests.post") as post:
        post.return_value = _mock_response(403, {"error": "license_expired", "message": "expired"})
        with pytest.raises(LicenseRejectedError):
            _client().enrich(findings=[("f0", "x")], raw_files={"readme": "s"})


def test_enrich_402_raises_quota_exhausted_with_payload_fields():
    from brass.enrichment import QuotaExhaustedError

    with patch("brass.enrichment.client.requests.post") as post:
        post.return_value = _mock_response(
            402,
            {
                "error": "quota_exhausted",
                "message": "out of tokens",
                "tokens_needed": 360_000,
                "tokens_remaining": 1_000,
                "quota_period_end": "2026-06-09T00:00:00Z",
                "topup_url": "https://x/topup",
            },
        )
        with pytest.raises(QuotaExhaustedError) as ei:
            _client().enrich(findings=[("f0", "x")], raw_files={"readme": "s"})

    assert ei.value.tokens_needed == 360_000
    assert ei.value.tokens_remaining == 1_000
    assert ei.value.topup_url == "https://x/topup"
    assert ei.value.quota_period_end == "2026-06-09T00:00:00Z"


def test_enrich_429_raises_rate_limited_with_retry_after():
    from brass.enrichment import EnrichmentRateLimitedError

    with patch("brass.enrichment.client.requests.post") as post:
        post.return_value = _mock_response(
            429, {"error": "rate_limited", "message": "wait", "retry_after_ms": 12345}
        )
        with pytest.raises(EnrichmentRateLimitedError) as ei:
            _client().enrich(findings=[("f0", "x")], raw_files={"readme": "s"})

    assert ei.value.retry_after_ms == 12345


@pytest.mark.parametrize("status", [502, 503, 504])
def test_enrich_5xx_raises_unavailable(status):
    from brass.enrichment import EnrichmentUnavailableError

    with patch("brass.enrichment.client.requests.post") as post:
        post.return_value = _mock_response(status, {"error": "x"})
        with pytest.raises(EnrichmentUnavailableError):
            _client().enrich(findings=[("f0", "x")], raw_files={"readme": "s"})


def test_enrich_network_error_raises_unavailable():
    import requests as _requests
    from brass.enrichment import EnrichmentUnavailableError

    with patch("brass.enrichment.client.requests.post") as post:
        post.side_effect = _requests.ConnectionError("dns failure")
        with pytest.raises(EnrichmentUnavailableError, match="network"):
            _client().enrich(findings=[("f0", "x")], raw_files={"readme": "s"})


def test_enrich_unexpected_4xx_raises_unavailable_not_crash():
    """Coverage for gateway returning a status we don't have a special case for."""
    from brass.enrichment import EnrichmentUnavailableError

    with patch("brass.enrichment.client.requests.post") as post:
        post.return_value = _mock_response(418, {"error": "teapot", "message": "no"})
        with pytest.raises(EnrichmentUnavailableError):
            _client().enrich(findings=[("f0", "x")], raw_files={"readme": "s"})


# --------------------------------------------------------------------------- #
# quota()                                                                     #
# --------------------------------------------------------------------------- #


def test_quota_ok_parses_response():
    body = {
        "monthly_remaining": 4_998_766,
        "topup_remaining": 1_000_000,
        "total_remaining": 5_998_766,
        "monthly_limit": 5_000_000,
        "period_start": "2026-05-01T00:00:00Z",
        "period_end": "2026-06-01T00:00:00Z",
        "total_used_lifetime": 1_234,
    }
    with patch("brass.enrichment.client.requests.get") as get:
        get.return_value = _mock_response(200, body)
        q = _client().quota()

    assert q.monthly_remaining == 4_998_766
    assert q.topup_remaining == 1_000_000
    assert q.total_remaining == 5_998_766
    assert q.monthly_limit == 5_000_000
    assert q.total_used_lifetime == 1_234


def test_quota_url_does_not_include_credentials():
    """Replaces an earlier test that asserted query-string credentials.
    Now they belong in headers (M3); the URL must be credential-free."""
    body = {
        "monthly_remaining": 0, "topup_remaining": 0, "total_remaining": 0,
        "monthly_limit": 5_000_000,
        "period_start": "x", "period_end": "y", "total_used_lifetime": 0,
    }
    with patch("brass.enrichment.client.requests.get") as get:
        get.return_value = _mock_response(200, body)
        _client().quota()

    args, kwargs = get.call_args
    assert args[0] == "https://test.example/api/quota"
    # Either no params kwarg at all, or it's empty/None.
    assert not kwargs.get("params")


def test_quota_503_raises_unavailable():
    from brass.enrichment import EnrichmentUnavailableError

    with patch("brass.enrichment.client.requests.get") as get:
        get.return_value = _mock_response(503, {})
        with pytest.raises(EnrichmentUnavailableError):
            _client().quota()


# --------------------------------------------------------------------------- #
# portal()                                                                    #
# --------------------------------------------------------------------------- #


def test_portal_ok_returns_url():
    body = {"portal_url": "https://coppersunbrass.lemonsqueezy.com/billing?session=xyz"}
    with patch("brass.enrichment.client.requests.get") as get:
        get.return_value = _mock_response(200, body)
        url = _client().portal()

    assert url == "https://coppersunbrass.lemonsqueezy.com/billing?session=xyz"


def test_portal_url_does_not_include_credentials():
    """Same M3 discipline as quota: license key in headers, not URL params."""
    with patch("brass.enrichment.client.requests.get") as get:
        get.return_value = _mock_response(200, {"portal_url": "https://x"})
        _client().portal()

    args, kwargs = get.call_args
    assert args[0] == "https://test.example/api/portal"
    assert "params" not in kwargs or not kwargs.get("params")
    headers = kwargs["headers"]
    assert headers["X-BrassCoders-License-Key"] == "AAAA-BBBB-CCCC-DDDD"
    assert headers["X-BrassCoders-Instance-Id"] == "instance-abc"


def test_portal_401_raises_license_rejected():
    from brass.enrichment import LicenseRejectedError

    with patch("brass.enrichment.client.requests.get") as get:
        get.return_value = _mock_response(401, {"error": "invalid_license"})
        with pytest.raises(LicenseRejectedError):
            _client().portal()


def test_portal_403_raises_license_rejected():
    from brass.enrichment import LicenseRejectedError

    with patch("brass.enrichment.client.requests.get") as get:
        get.return_value = _mock_response(403, {"error": "license_expired"})
        with pytest.raises(LicenseRejectedError):
            _client().portal()


def test_portal_503_raises_unavailable():
    from brass.enrichment import EnrichmentUnavailableError

    with patch("brass.enrichment.client.requests.get") as get:
        get.return_value = _mock_response(503, {})
        with pytest.raises(EnrichmentUnavailableError):
            _client().portal()


def test_portal_missing_url_in_response_raises_unavailable():
    """Defensive: if gateway returns 200 but no portal_url, treat as upstream
    weirdness rather than crashing the CLI with a KeyError."""
    from brass.enrichment import EnrichmentUnavailableError

    with patch("brass.enrichment.client.requests.get") as get:
        get.return_value = _mock_response(200, {"unexpected": "shape"})
        with pytest.raises(EnrichmentUnavailableError):
            _client().portal()


def test_portal_empty_url_in_response_raises_unavailable():
    from brass.enrichment import EnrichmentUnavailableError

    with patch("brass.enrichment.client.requests.get") as get:
        get.return_value = _mock_response(200, {"portal_url": ""})
        with pytest.raises(EnrichmentUnavailableError):
            _client().portal()


# --------------------------------------------------------------------------- #
# Defensive checks (M2/M3/H3/L4)                                              #
# --------------------------------------------------------------------------- #


def test_quota_sends_license_in_header_not_query_string():
    """M3: license key must travel as a header so its URL doesn't end up
    in network-error exception strings or any URL-bearing log."""
    body = {
        "monthly_remaining": 1, "topup_remaining": 0, "total_remaining": 1,
        "monthly_limit": 1, "period_start": "x", "period_end": "y",
        "total_used_lifetime": 0,
    }
    with patch("brass.enrichment.client.requests.get") as get:
        get.return_value = _mock_response(200, body)
        _client().quota()

    args, kwargs = get.call_args
    # No query-string license_key/instance_id (the header carries them).
    assert "params" not in kwargs or not kwargs.get("params")
    headers = kwargs["headers"]
    assert headers["X-BrassCoders-License-Key"] == "AAAA-BBBB-CCCC-DDDD"
    assert headers["X-BrassCoders-Instance-Id"] == "instance-abc"


def test_license_shape_redaction_on_4xx_error_message():
    """Fix 6 from the 2C /full-bugs review: if a future upstream/
    platform error page reflects the request body into its error
    message, the license-key-shaped substrings must be redacted before
    the message is interpolated into the raised exception."""
    from brass.enrichment import EnrichmentUnavailableError

    with patch("brass.enrichment.client.requests.post") as post:
        # Simulate an unexpected 4xx with an error body that echoes
        # the license key (worst case — the gateway today doesn't
        # do this, but a future Vercel platform error page might).
        post.return_value = _mock_response(
            418,
            {
                "error": "echo",
                "message": "Bad request: license_key=AAAA-BBBB-CCCC-DDDD",
            },
        )
        with pytest.raises(EnrichmentUnavailableError) as ei:
            _client().enrich(findings=[("f0", "x")], raw_files={"readme": "s"})

    # Exception message must NOT contain the literal license key.
    assert "AAAA-BBBB-CCCC-DDDD" not in str(ei.value)
    # And SHOULD contain the redaction placeholder so the operator
    # knows redaction fired (and can correlate with server logs).
    assert "REDACTED" in str(ei.value)


def test_license_shape_redaction_helper_handles_edge_cases():
    """The redactor matches uppercase alphanumeric dash-separated
    blocks (LemonSqueezy license shape). Non-license strings should
    pass through untouched."""
    from brass.enrichment.client import _redact_license_shape
    # License-shaped → redacted
    assert "<REDACTED_LICENSE>" in _redact_license_shape("key=AAAA-BBBB-CCCC-DDDD ok")
    # Plain English → untouched
    assert _redact_license_shape("scan finished, 3 findings") == "scan finished, 3 findings"
    # Lowercase / mixed → untouched (license shape is uppercase)
    assert _redact_license_shape("commit aaaa-bbbb-cccc") == "commit aaaa-bbbb-cccc"
    # Single block (not enough dashes) → untouched
    assert _redact_license_shape("token=ABCD1234") == "token=ABCD1234"


def test_network_error_message_does_not_echo_request_url_or_license():
    """M3 belt-and-suspenders: the user-visible exception message must
    not contain anything that could leak the license."""
    import requests as _requests
    from brass.enrichment import EnrichmentUnavailableError

    leaky_msg = (
        "ConnectionError(MaxRetryError('HTTPSConnectionPool(host=...)\n"
        "URL: https://test.example/api/quota?license_key=AAAA-BBBB-CCCC-DDDD"
    )
    with patch("brass.enrichment.client.requests.get") as get:
        get.side_effect = _requests.ConnectionError(leaky_msg)
        with pytest.raises(EnrichmentUnavailableError) as ei:
            _client().quota()

    assert "AAAA-BBBB-CCCC-DDDD" not in str(ei.value)


def test_oserror_during_request_is_caught_as_unavailable():
    """M2: socket.gaierror / SSLError can occasionally bypass requests'
    own exception hierarchy; we wrap with OSError to be safe."""
    from brass.enrichment import EnrichmentUnavailableError

    with patch("brass.enrichment.client.requests.post") as post:
        post.side_effect = OSError("DNS broke")
        with pytest.raises(EnrichmentUnavailableError):
            _client().enrich(findings=[("f0", "x")], raw_files={"readme": "s"})


def test_enrich_oversized_response_is_rejected():
    """H3: a malicious gateway returning more enriched findings than
    were sent in is refused (DoS surface)."""
    from brass.enrichment import EnrichmentUnavailableError

    huge = {
        "findings": [
            {"id": f"f{i}", "rank_score": 0.5, "cluster_size": 1} for i in range(10_000)
        ],
        "tokens_used": 1, "quota_remaining": 1, "quota_period_end": "x",
    }
    with patch("brass.enrichment.client.requests.post") as post:
        post.return_value = _mock_response(200, huge)
        with pytest.raises(EnrichmentUnavailableError, match="malformed"):
            _client().enrich(findings=[("f0", "x")], raw_files={"readme": "s"})


def test_enrich_oversized_content_length_is_rejected():
    """H3: gateway claiming a giant content-length is refused before
    we ingest the body."""
    from brass.enrichment import EnrichmentUnavailableError

    response = MagicMock()
    response.status_code = 200
    response.headers = {"content-length": str(20 * 1024 * 1024)}  # 20 MiB > 8 MiB cap

    with patch("brass.enrichment.client.requests.post") as post:
        post.return_value = response
        with pytest.raises(EnrichmentUnavailableError, match="too large"):
            _client().enrich(findings=[("f0", "x")], raw_files={"readme": "s"})


def test_enrich_handles_non_numeric_int_fields_without_crashing():
    """L4: gateway returns junk in numeric fields → safe coercion to 0."""
    body = {
        "findings": [{"id": "f0", "rank_score": 0.5, "cluster_size": 1}],
        "tokens_used": "not-a-number",
        "quota_remaining": None,
        "quota_period_end": "x",
    }
    with patch("brass.enrichment.client.requests.post") as post:
        post.return_value = _mock_response(200, body)
        result = _client().enrich(findings=[("f0", "x")], raw_files={"readme": "s"})
    assert result.tokens_used == 0
    assert result.quota_remaining == 0


def test_402_response_with_non_numeric_tokens_needed_does_not_crash():
    from brass.enrichment import QuotaExhaustedError

    with patch("brass.enrichment.client.requests.post") as post:
        post.return_value = _mock_response(
            402,
            {
                "error": "quota_exhausted",
                "message": "no",
                "tokens_needed": "lots",   # malformed
                "tokens_remaining": None,  # missing
            },
        )
        with pytest.raises(QuotaExhaustedError) as ei:
            _client().enrich(findings=[("f0", "x")], raw_files={"readme": "s"})
    assert ei.value.tokens_needed == 0
    assert ei.value.tokens_remaining == 0


# --------------------------------------------------------------------------- #
# Transient-failure retry (2026-05-17)                                        #
# --------------------------------------------------------------------------- #


def test_enrich_retries_once_on_transient_unavailable_then_succeeds():
    """A 503 → success sequence: brass retries the request once after
    `_TRANSIENT_RETRY_DELAY_SECONDS`, and the second attempt's success
    is returned. Validates the retry catches single transient blips
    (gateway worker restart, DNS hiccup, Wi-Fi drop) without the
    customer's scan losing enrichment results."""
    from brass.enrichment import EnrichmentClient  # noqa: F401  (import side-effect)

    with patch("brass.enrichment.client.time.sleep") as sleep, \
            patch("brass.enrichment.client.requests.post") as post:
        post.side_effect = [
            _mock_response(503, {"error": "transient"}),
            _mock_response(200, _OK_ENRICH_BODY),
        ]
        result = _client().enrich(
            findings=[("f0", "x"), ("f1", "y")], raw_files={"readme": "s"},
        )
    from brass.enrichment.client import _TRANSIENT_RETRY_DELAY_SECONDS
    assert post.call_count == 2
    assert sleep.call_count == 1
    sleep.assert_called_with(_TRANSIENT_RETRY_DELAY_SECONDS)
    assert result.tokens_used == 1234


def test_enrich_network_error_retries_once_then_succeeds():
    """Network-layer failure on the first attempt — same retry policy
    as a 503 since both map to `EnrichmentUnavailableError`."""
    import requests as _requests

    with patch("brass.enrichment.client.time.sleep") as sleep, \
            patch("brass.enrichment.client.requests.post") as post:
        post.side_effect = [
            _requests.ConnectionError("dns failure"),
            _mock_response(200, _OK_ENRICH_BODY),
        ]
        result = _client().enrich(
            findings=[("f0", "x"), ("f1", "y")], raw_files={"readme": "s"},
        )
    assert post.call_count == 2
    sleep.assert_called_once()
    assert result.tokens_used == 1234


def test_enrich_gives_up_after_one_retry_on_persistent_503():
    """Two consecutive 503s: client retries once, then raises rather
    than retrying again. Bounded-retry contract — no exponential
    backoff, no third attempt."""
    from brass.enrichment import EnrichmentUnavailableError

    with patch("brass.enrichment.client.time.sleep") as sleep, \
            patch("brass.enrichment.client.requests.post") as post:
        post.return_value = _mock_response(503, {"error": "down"})
        with pytest.raises(EnrichmentUnavailableError):
            _client().enrich(findings=[("f0", "x")], raw_files={"readme": "s"})
    assert post.call_count == 2  # 1 attempt + 1 retry, no more
    assert sleep.call_count == 1


def test_enrich_voyage_429_waits_full_tpm_window_when_hint_is_short():
    """Voyage's `retry_after_ms` is a HINT, not a guarantee — observed
    2026-05-27 coppersun_brass v3 scan: Voyage returned retry-after=7s,
    the CLI honored it, retried, got 429 again because Voyage's TPM is
    a sliding 60s window that 7 seconds doesn't clear.

    Fix: wait `max(voyage_hint, MIN_WAIT)` so the full TPM window
    elapses before the retry attempt.
    """
    from brass.enrichment.client import _VOYAGE_429_MIN_RETRY_WAIT_SECONDS

    with patch("brass.enrichment.client.time.sleep") as sleep, \
            patch("brass.enrichment.client.requests.post") as post:
        post.side_effect = [
            # Voyage's hint is 7s (short — wouldn't clear a 60s TPM window).
            _mock_response(429, {"error": "rate_limited", "retry_after_ms": 7_000}),
            _mock_response(200, _OK_ENRICH_BODY),
        ]
        result = _client().enrich(
            findings=[("f0", "x")], raw_files={"readme": "s"},
        )
    assert post.call_count == 2  # 1 attempt + 1 retry
    assert sleep.call_count == 1
    # We waited the MINIMUM (60s) — not Voyage's hint (7s).
    sleep.assert_called_with(_VOYAGE_429_MIN_RETRY_WAIT_SECONDS)
    assert result.tokens_used == 1234


def test_enrich_voyage_429_honors_longer_hint_above_minimum():
    """When Voyage asks for MORE than our minimum wait (e.g. 90s),
    we honor Voyage's longer instruction — they're telling us
    something specific about their internal state."""
    with patch("brass.enrichment.client.time.sleep") as sleep, \
            patch("brass.enrichment.client.requests.post") as post:
        post.side_effect = [
            _mock_response(429, {"error": "rate_limited", "retry_after_ms": 90_000}),
            _mock_response(200, _OK_ENRICH_BODY),
        ]
        result = _client().enrich(
            findings=[("f0", "x")], raw_files={"readme": "s"},
        )
    assert post.call_count == 2
    assert sleep.call_count == 1
    sleep.assert_called_with(90.0)  # honored Voyage's longer hint
    assert result.tokens_used == 1234


def test_enrich_does_not_retry_on_voyage_429_when_retry_after_exceeds_cap():
    """If Voyage's `retry_after_ms` is longer than the CLI's max wait
    cap, don't block the scan — re-raise immediately so the caller
    falls back to heuristic for the entire scan.

    A 120s+ retry-after suggests deeper rate-limit pressure (likely
    needs commercial tier upgrade per
    cli/docs/perf/2026-05-27_voyage_rate_limit_followup.md), not
    something a single longer wait can fix.
    """
    from brass.enrichment import EnrichmentRateLimitedError

    with patch("brass.enrichment.client.time.sleep") as sleep, \
            patch("brass.enrichment.client.requests.post") as post:
        post.return_value = _mock_response(
            429, {"error": "rate_limited", "retry_after_ms": 300_000}  # 5 min
        )
        with pytest.raises(EnrichmentRateLimitedError):
            _client().enrich(findings=[("f0", "x")], raw_files={"readme": "s"})
    assert post.call_count == 1  # no retry attempted
    assert sleep.call_count == 0  # never slept


def test_enrich_propagates_after_voyage_429_retry_also_fails():
    """If the retry itself 429s, give up — the all-or-nothing
    fallback contract means a second retry would just delay the
    inevitable heuristic-fallback by another N seconds."""
    from brass.enrichment import EnrichmentRateLimitedError
    from brass.enrichment.client import _VOYAGE_429_MIN_RETRY_WAIT_SECONDS

    with patch("brass.enrichment.client.time.sleep") as sleep, \
            patch("brass.enrichment.client.requests.post") as post:
        post.return_value = _mock_response(
            429, {"error": "rate_limited", "retry_after_ms": 7_000}
        )
        with pytest.raises(EnrichmentRateLimitedError):
            _client().enrich(findings=[("f0", "x")], raw_files={"readme": "s"})
    assert post.call_count == 2  # 1 attempt + 1 retry, both 429
    assert sleep.call_count == 1  # slept once before retry
    sleep.assert_called_with(_VOYAGE_429_MIN_RETRY_WAIT_SECONDS)


def test_enrich_does_not_retry_on_402_quota_exhausted():
    """Quota exhaustion is deterministic / non-transient — retrying
    only delays the hard-fail UX without changing the outcome."""
    from brass.enrichment import QuotaExhaustedError

    with patch("brass.enrichment.client.time.sleep") as sleep, \
            patch("brass.enrichment.client.requests.post") as post:
        post.return_value = _mock_response(
            402, {"error": "quota_exhausted", "tokens_needed": 1000, "tokens_remaining": 0}
        )
        with pytest.raises(QuotaExhaustedError):
            _client().enrich(findings=[("f0", "x")], raw_files={"readme": "s"})
    assert post.call_count == 1
    assert sleep.call_count == 0


def test_enrich_does_not_retry_on_401_403_license_rejected():
    """License rejection is deterministic. Both 401 and 402 should
    raise immediately without a retry."""
    from brass.enrichment import LicenseRejectedError

    for status in (401, 403):
        with patch("brass.enrichment.client.time.sleep") as sleep, \
                patch("brass.enrichment.client.requests.post") as post:
            post.return_value = _mock_response(status, {"error": "x"})
            with pytest.raises(LicenseRejectedError):
                _client().enrich(findings=[("f0", "x")], raw_files={"readme": "s"})
        assert post.call_count == 1, f"status {status}: should not retry"
        assert sleep.call_count == 0


# --------------------------------------------------------------------------- #
# Chunking: token-budget packer in client.enrich()                            #
# --------------------------------------------------------------------------- #


def test_enrich_single_request_when_finding_count_low():
    """A small finding list packs into one chunk → single POST, no
    chunked-path merge overhead."""
    with patch("brass.enrichment.client.requests.post") as post:
        post.return_value = _mock_response(200, _OK_ENRICH_BODY)
        result = _client().enrich(
            findings=[(f"f{i}", f"t{i}") for i in range(50)],
            raw_files={"readme": "sig"},
        )
    assert post.call_count == 1
    assert result.findings[0].id == "f0"


def test_enrich_chunks_when_token_budget_exceeded():
    """Dense-text findings exceed the per-chunk token budget and
    produce multiple POSTs. Pins the core invariant of token-budget
    chunking: variance in text density is absorbed by chunk count,
    not by gateway-side rate-limit failures.

    Fixture: 2000 findings × 4000-char text each. Per-finding cost
    = 3750 (signature worst-case) + 2000 (text chars/2) = 5750 tokens.
    Total = 2000 × 5750 = 11.5M tokens. Budget = 2.5M → ≥5 chunks.
    """
    from brass.enrichment.client import _MAX_TOKENS_PER_CHUNK
    dense_text = "x" * 4000
    # Big enough to definitely exceed the per-chunk token budget.
    total = 2000
    chunk_response = {
        "findings": [],  # filled per-call via side_effect
        "tokens_used": 1000,
        "quota_remaining": 5_000_000,
        "quota_period_end": "2026-12-31T23:59:59Z",
    }

    def _capture(url, json=None, **kw):
        # Echo back the chunk's findings as enriched survivors.
        return _mock_response(200, {
            **chunk_response,
            "findings": [
                {"id": f["id"], "rank_score": 0.5, "cluster_size": 1}
                for f in json["findings"]
            ],
        })

    with patch("brass.enrichment.client.requests.post", side_effect=_capture) as post:
        result = _client().enrich(
            findings=[{"id": f"f{i}", "text": dense_text} for i in range(total)],
            raw_files={"readme": "sig"},
        )

    # Token budget exceeded → MUST chunk.
    assert post.call_count >= 2, (
        f"expected ≥2 chunks for {total} dense findings (~11.5M tokens vs "
        f"{_MAX_TOKENS_PER_CHUNK} budget), got {post.call_count}"
    )
    # All findings preserved across chunks.
    assert len(result.findings) == total


def test_enrich_chunk_failure_propagates():
    """If any chunk fails its retry, the whole enrich() raises and
    the CLI falls back to heuristic-only output for the entire scan
    (existing contract — no partial enrichment)."""
    from brass.enrichment import EnrichmentUnavailableError

    # Use dense findings so the chunker emits multiple chunks.
    dense = "x" * 4000
    with patch("brass.enrichment.client.time.sleep"), \
            patch("brass.enrichment.client.requests.post") as post:
        # First call succeeds, second fails with 503 (after retry).
        post.side_effect = [
            _mock_response(200, _OK_ENRICH_BODY),
            _mock_response(503, {"error": "down"}),
            _mock_response(503, {"error": "down"}),  # retry attempt
        ]
        with pytest.raises(EnrichmentUnavailableError):
            _client().enrich(
                findings=[{"id": f"f{i}", "text": dense} for i in range(2000)],
                raw_files={"readme": "sig"},
            )


def test_enrich_payload_per_chunk_under_gateway_schema_cap():
    """Defensive: confirm individual POST payloads never exceed the
    gateway's schema cap (3000 findings per request). Pins the
    cross-codebase contract — CLI MUST stay under the gateway's Zod
    `z.array(FindingSchema).max(3000)` regardless of how the CLI
    chunker is calibrated.
    """
    from brass.enrichment.client import _MAX_FINDINGS_PER_CHUNK
    posts: list[dict] = []
    # Schema cap from gateway/lib/schema.ts — duplicated here as a
    # contract pin, not a config knob.
    GATEWAY_SCHEMA_FINDING_CAP = 3000

    def _capture(url, json=None, **kw):
        posts.append(json)
        return _mock_response(200, {
            "findings": [
                {"id": f["id"], "rank_score": 0.5, "cluster_size": 1}
                for f in json["findings"]
            ],
            "tokens_used": 100,
            "quota_remaining": 1_000_000,
            "quota_period_end": "2026-12-31T23:59:59Z",
        })

    # Use tiny texts so token budget is generous and count cap is the
    # binding constraint. Send enough findings to force ≥3 chunks.
    total = _MAX_FINDINGS_PER_CHUNK * 3 + 5
    with patch("brass.enrichment.client.requests.post", side_effect=_capture):
        _client().enrich(
            findings=[(f"f{i}", "x") for i in range(total)],
            raw_files={"readme": "sig"},
        )

    assert len(posts) >= 3
    for i, body in enumerate(posts):
        assert len(body["findings"]) <= GATEWAY_SCHEMA_FINDING_CAP, (
            f"chunk {i} has {len(body['findings'])} findings — exceeds "
            f"gateway schema cap of {GATEWAY_SCHEMA_FINDING_CAP}"
        )
        assert len(body["findings"]) <= _MAX_FINDINGS_PER_CHUNK, (
            f"chunk {i} has {len(body['findings'])} findings — exceeds "
            f"CLI chunk count cap of {_MAX_FINDINGS_PER_CHUNK}"
        )
