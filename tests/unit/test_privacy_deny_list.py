"""Privacy scanner deny-list tests (phase C.6a).

Captures the known-test-value cases the brass-seo round 2 triage
identified as the largest source of FPs.
"""

from __future__ import annotations

import pytest

from brass.scanners._known_test_values import (
    is_aadhaar_test_value,
    is_benign_email,
    is_benign_ip,
    is_stripe_test_card,
    is_test_ssn,
    looks_like_sentry_dsn,
)


# --------------------------------------------------------------------------- #
# Stripe test cards                                                           #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("card", [
    "4242424242424242",
    "4242 4242 4242 4242",
    "4242-4242-4242-4242",
    "5555555555554444",
    "378282246310005",
    "6011111111111117",
])
def test_documented_stripe_test_cards_match(card):
    assert is_stripe_test_card(card)


def test_real_looking_card_does_not_match():
    assert not is_stripe_test_card("4929123456789012")


# --------------------------------------------------------------------------- #
# IPs                                                                         #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("ip", [
    "127.0.0.1", "127.255.255.255",
    "0.0.0.0",
    "10.0.0.5",
    "192.168.1.1",
    "172.16.5.7", "172.31.99.99",
    "169.254.169.254",
    "192.0.2.1",        # RFC 5737
    "198.51.100.42",    # RFC 5737
    "203.0.113.99",     # RFC 5737
    "8.8.8.8",
    "1.1.1.1",
])
def test_benign_ips_are_filtered(ip):
    assert is_benign_ip(ip)


@pytest.mark.parametrize("ip", [
    "54.231.83.117",
    "104.244.42.65",
    "8.8.4.4",   # not in our list — only 8.8.8.8 is famous-enough
])
def test_real_public_ips_are_not_filtered(ip):
    assert not is_benign_ip(ip)


# --------------------------------------------------------------------------- #
# Emails                                                                      #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("email", [
    "user@example.com",
    "test@example.org",
    "alice@example.net",
    "noreply@brass.dev",
    "no-reply@coppersun.dev",
    "donotreply@notification.example.org",
    "test@localhost",
    "scott@test.local",
    "CopperSunDev@users.noreply.github.com",
])
def test_benign_emails_are_filtered(email):
    assert is_benign_email(email)


@pytest.mark.parametrize("email", [
    "scott@coppersuncreative.com",
    "real-user@gmail.com",
    "support@stripe.com",
])
def test_real_emails_are_not_filtered(email):
    assert not is_benign_email(email)


# --------------------------------------------------------------------------- #
# SSNs                                                                        #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("ssn", [
    "111111111", "111-11-1111",
    "123456789", "123-45-6789",
    "987-65-4321",
    "000-00-0000", "000000000",
])
def test_test_ssns_are_filtered(ssn):
    assert is_test_ssn(ssn)


def test_real_looking_ssn_is_not_filtered():
    assert not is_test_ssn("412-87-6534")


def test_email_detector_skips_sentry_dsn_content_entirely():
    """C.9: Sentry DSNs (`https://<hex>@o<digits>.ingest.sentry.io/...`)
    contain an `o<digits>@host.ingest.sentry.io` substring that matches
    the email regex. The whole line is Sentry config, not PII — drop
    every email match in it."""
    from brass.scanners.brass2_privacy_scanner import EmailDetector
    detector = EmailDetector()
    line = (
        'dsn: "https://757216fce0e07f7890a402511466dfc0'
        '@o4509881095553024.ingest.us.sentry.io/4510812374368256"'
    )
    assert detector.detect(line) == []


# --------------------------------------------------------------------------- #
# Sentry DSN context                                                          #
# --------------------------------------------------------------------------- #

def test_sentry_dsn_context_detected():
    line = (
        "SENTRY_DSN=https://abc123def4567890abc123def4567890@o12345.ingest.sentry.io/9876543"
    )
    assert looks_like_sentry_dsn(line)


def test_non_sentry_url_is_not_a_sentry_dsn():
    line = "fetch('https://api.example.com/users')"
    assert not looks_like_sentry_dsn(line)


# --------------------------------------------------------------------------- #
# End-to-end on the actual scanner detectors                                  #
# --------------------------------------------------------------------------- #

def test_ssn_detector_skips_test_ssn():
    from brass.scanners.brass2_privacy_scanner import SSNDetector
    detector = SSNDetector()
    matches = detector.detect("Replace with test SSN (123-45-6789) or use environment variables")
    assert matches == []


def test_ssn_detector_skips_sentry_dsn_content_entirely():
    from brass.scanners.brass2_privacy_scanner import SSNDetector
    detector = SSNDetector()
    # The 32-hex key contains substrings the regex can grab.
    line = (
        "SENTRY_DSN=https://1234567890abcdef1234567890abcdef@o12345.ingest.sentry.io/1"
    )
    assert detector.detect(line) == []


def test_email_detector_skips_example_com():
    from brass.scanners.brass2_privacy_scanner import EmailDetector
    detector = EmailDetector()
    assert detector.detect("alice@example.com") == []


def test_email_detector_keeps_real_email():
    from brass.scanners.brass2_privacy_scanner import EmailDetector
    detector = EmailDetector()
    matches = detector.detect("Contact scott@coppersuncreative.com for support")
    assert len(matches) == 1
    assert matches[0].match_text == "scott@coppersuncreative.com"


def test_ip_detector_skips_loopback_and_rfc_5737():
    from brass.scanners.brass2_privacy_scanner import IPAddressDetector
    detector = IPAddressDetector()
    assert detector.detect("Connecting to 127.0.0.1") == []
    assert detector.detect("Example IP: 192.0.2.42") == []


def test_aadhaar_detector_skips_stripe_test_cards():
    from brass.scanners.brass2_privacy_scanner import IndiaAadhaarDetector
    detector = IndiaAadhaarDetector()
    # Real-world brass-seo case: docs file containing a Stripe test card.
    line = "Use test card 4242 4242 4242 4242 for development."
    assert detector.detect(line) == []


# --------------------------------------------------------------------------- #
# C.7.5: SSN regex tightened to require dashes (kills 9-digit-substring FPs)  #
# --------------------------------------------------------------------------- #

def test_ssn_detector_no_longer_fires_on_9_digit_runs():
    """The dominant FP class from round 4: 9-digit numbers in source code
    matching the old un-dashed SSN regex. These are LinkedIn URNs, GA4
    property IDs, file sizes, image-pixel constants — never SSNs."""
    from brass.scanners.brass2_privacy_scanner import SSNDetector
    detector = SSNDetector()
    # All the real brass-seo round-4 cases:
    assert detector.detect("urn:li:organization:112995115") == []
    assert detector.detect("property ID 276875078 written to DB") == []
    assert detector.detect("Downloaded from HTTPS: 240674392 bytes") == []
    assert detector.detect('"imgOptMaxInputPixels": 268402689,') == []
    # Plus other natural 9-digit-numbers in code:
    assert detector.detect("const TIMEOUT_MS = 123456789;") == []
    assert detector.detect("orderId: 987654321") == []


def test_ssn_detector_still_fires_on_dashed_format():
    """Real SSNs (in code/docs/fixtures) are almost always dashed."""
    from brass.scanners.brass2_privacy_scanner import SSNDetector
    detector = SSNDetector()
    matches = detector.detect("user.ssn = '412-87-6534';")
    assert len(matches) == 1
    assert matches[0].match_text == "412-87-6534"
