"""Known-test-value deny-lists for the privacy scanner.

Real-world projects routinely include test data that matches our PII
regexes: Stripe test cards, RFC 5737 IP addresses, sentinel emails,
example SSNs documented in API specs. These are not actual customer
PII — they're documented test fixtures or framework conventions.

Round 2 of the brass-seo triage put the privacy scanner at a 100% FP
rate (8 of 8 findings false positives). This module is the surgical
fix the user asked for: a small, explicit deny-list of known-test
values that the scanner can drop before producing a finding.

Each function is a fast membership / pattern check. We deliberately
keep the lists small and well-commented — opaque allowlists are a
smell.
"""

from __future__ import annotations

import re


# ---------------------------------------------------------------------------
# Credit cards / Aadhaar-shaped numbers
# ---------------------------------------------------------------------------

# Stripe's documented test card numbers. They pass Luhn validation
# (Stripe needs them to), so we have to match them by literal value.
# Source: https://docs.stripe.com/testing#cards (current as of 2026).
_STRIPE_TEST_CARDS = frozenset({
    # Visa
    "4242424242424242", "4000056655665556", "4000000000000002",
    "4000000000009995", "4000000000000069", "4000000000000127",
    "4000000000000119", "4242424242424241",
    # Mastercard
    "5555555555554444", "5200828282828210", "5105105105105100",
    "2223003122003222",
    # American Express
    "378282246310005", "371449635398431",
    # Discover
    "6011111111111117", "6011000990139424",
    # Diners
    "30569309025904", "38520000023237",
    # JCB
    "3530111333300000", "3566002020360505",
    # UnionPay
    "6200000000000005",
})


def is_stripe_test_card(match_text: str) -> bool:
    """True if the matched digits are a documented Stripe test card.

    Strips spaces / dashes before checking so "4242 4242 4242 4242" or
    "4242-4242-4242-4242" both hit.
    """
    digits = re.sub(r"[\s-]", "", match_text)
    return digits in _STRIPE_TEST_CARDS


# Common Aadhaar test/placeholder values seen in docs. The 12-digit
# Aadhaar regex catches Stripe 16-digit cards if a 12-digit subspan
# happens to look Aadhaar-shaped; is_stripe_test_card handles that.
# This set is for explicit Aadhaar-format test values.
_AADHAAR_TEST_VALUES = frozenset({
    "000000000000",
    "111111111111",
    "999999999999",
    "123456789012",
})


def is_aadhaar_test_value(match_text: str) -> bool:
    digits = re.sub(r"[\s-]", "", match_text)
    return digits in _AADHAAR_TEST_VALUES


# ---------------------------------------------------------------------------
# IP addresses
# ---------------------------------------------------------------------------

# Loopback and RFC-reserved address ranges. We list the most common
# string forms; an IP-parsing approach would be more thorough but
# adds complexity for marginal recall.
_BENIGN_IP_PREFIXES = (
    "127.",            # IPv4 loopback (127.0.0.0/8)
    "0.0.0.0",         # IPv4 "any"
    "255.255.",        # broadcast-ish
    "10.",             # RFC 1918 private
    "192.168.",        # RFC 1918 private
    "169.254.",        # link-local
    "192.0.2.",        # RFC 5737 TEST-NET-1
    "198.51.100.",     # RFC 5737 TEST-NET-2
    "203.0.113.",      # RFC 5737 TEST-NET-3
    "8.8.8.8",         # well-known Google DNS, not PII
    "1.1.1.1",         # well-known Cloudflare DNS, not PII
    "172.16.",         # RFC 1918 private (start of range; full range
    "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.",
    "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
    "172.29.", "172.30.", "172.31.",   # 172.16.0.0/12)
)


def is_benign_ip(match_text: str) -> bool:
    """True for loopback, RFC 1918 private, RFC 5737 test, and a few
    well-known DNS resolvers. These appear constantly in code/docs
    and almost never represent actual user IP-address leaks."""
    s = match_text.strip()
    return any(s.startswith(prefix) for prefix in _BENIGN_IP_PREFIXES)


# ---------------------------------------------------------------------------
# Emails
# ---------------------------------------------------------------------------

# RFC 2606 reserves example.com / .example.* for documentation, and
# .test / .invalid / .localhost are reserved TLDs. Plus common test
# email conventions used across many frameworks.
_BENIGN_EMAIL_DOMAIN_SUFFIXES = (
    "@example.com", "@example.org", "@example.net",
    ".example.com", ".example.org", ".example.net",
    "@test.local", "@test.com",
    "@localhost", ".localhost",
    "@invalid",
    "@noreply.github.com", "@users.noreply.github.com",
    "@anthropic.com",  # documentation references
)

# Local-parts that are by convention test/no-reply addresses.
_BENIGN_EMAIL_LOCAL_PARTS = (
    "noreply@", "no-reply@", "donotreply@", "do-not-reply@",
    "test@", "example@", "user@",
)


def is_benign_email(match_text: str) -> bool:
    s = match_text.strip().lower()
    if any(s.endswith(suffix) for suffix in _BENIGN_EMAIL_DOMAIN_SUFFIXES):
        return True
    if any(s.startswith(prefix) for prefix in _BENIGN_EMAIL_LOCAL_PARTS):
        return True
    return False


# ---------------------------------------------------------------------------
# SSNs
# ---------------------------------------------------------------------------

# Test SSNs that appear in IRS publications, RFC drafts, and common
# fixtures. Per SSA, these are explicitly non-issuable for live use.
# We list them in both dashed and undashed forms.
_TEST_SSNS = frozenset({
    "000000000",  # ssa-invalid; commonly used as a placeholder
    "111111111", "222222222", "333333333", "444444444",
    "555555555", "777777777", "888888888",
    "123456789", "987654321",
    "078051120",  # the "luckiest SSN" from a 1938 wallet ad — appears in security docs
    # Dashed forms map to the same digits via strip below.
})


def is_test_ssn(match_text: str) -> bool:
    digits = re.sub(r"[\s-]", "", match_text)
    return digits in _TEST_SSNS


# ---------------------------------------------------------------------------
# Sentry DSN heuristic
# ---------------------------------------------------------------------------

# Sentry DSNs look like https://<32-hex-key>@<host>/<project>. Embedded
# in source they often contain 32-char hex sequences that can confuse
# regexes designed for other things (incl. our credit-card regex if
# digits-only stretches appear). This pattern catches the canonical
# form so callers can short-circuit on it.
_SENTRY_DSN_RE = re.compile(
    r"https?://[a-f0-9]{32}@[a-zA-Z0-9.\-]+/\d+",
    re.IGNORECASE,
)


def looks_like_sentry_dsn(surrounding_text: str) -> bool:
    return bool(_SENTRY_DSN_RE.search(surrounding_text))
