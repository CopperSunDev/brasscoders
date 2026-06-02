"""Regression tests for PhoneDetector + UKPhoneDetector.

Both detectors previously used `\\b` anchors against non-word leading
characters (`\\(` for the parens-format US phone, `\\+44` for the
international UK phone). `\\b` requires a word/non-word transition; with
non-word on both sides (e.g. space-then-`(`) the boundary never matches
and the canonical phone formats silently slip through.

The fix replaces `\\b` with (?<!\\w)/(?!\\w) lookarounds on the affected
alternatives. These tests pin the working behavior so a future "let's
simplify these regexes back to `\\b`" refactor catches the regression.
"""

from __future__ import annotations

import pytest

from brass.scanners.brass2_privacy_scanner import PhoneDetector, UKPhoneDetector


# --------------------------------------------------------------------------- #
# PhoneDetector — US formats                                                  #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("text,expected_match", [
    # Parens variant — the regression case
    ("ADMIN_PHONE = '(555) 123-4567'", "(555) 123-4567"),
    ("Call (555) 123-4567 today", "(555) 123-4567"),
    ("(555)123-4567",                  "(555)123-4567"),    # no space
    ("(555) 123-4567",                 "(555) 123-4567"),   # leading position
    # Dashed variant (was always working; pin it)
    ("phone: 555-123-4567",            "555-123-4567"),
    # 10-digit variant (was always working; pin it)
    ("call 5551234567 back",           "5551234567"),
])
def test_phone_detector_matches_canonical_formats(text, expected_match):
    detector = PhoneDetector()
    matches = detector.detect(text)
    assert any(m.match_text == expected_match for m in matches), (
        f"Expected {expected_match!r} in matches for {text!r}; "
        f"got {[m.match_text for m in matches]}"
    )


@pytest.mark.parametrize("text", [
    # Substring inside an identifier — must NOT match the parens form
    "func(555)123-4567ext",  # `ext` is word, follows the digits
    "x(555)abc",              # not a phone shape
])
def test_phone_detector_rejects_substring_in_identifiers(text):
    detector = PhoneDetector()
    matches = detector.detect(text)
    # If `(555)123-4567` were extracted as a phone here it would be wrong.
    assert all("(555)" not in m.match_text or "ext" not in text for m in matches)


# --------------------------------------------------------------------------- #
# UKPhoneDetector — +44 international + 0-prefix domestic                     #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("text,expected_match", [
    # +44 international — the regression case (was only matching at string start)
    ("+447123456789",                    "+447123456789"),
    ("Call me at +447123456789 today",   "+447123456789"),
    ("phone: +447123456789.",            "+447123456789"),
    # 0-prefix domestic (was always working; pin it)
    ("07123456789",                       "07123456789"),
    ("UK: 07123456789",                   "07123456789"),
])
def test_uk_phone_detector_matches_canonical_formats(text, expected_match):
    detector = UKPhoneDetector()
    matches = detector.detect(text)
    assert any(m.match_text == expected_match for m in matches), (
        f"Expected {expected_match!r} in matches for {text!r}; "
        f"got {[m.match_text for m in matches]}"
    )


def test_uk_phone_detector_rejects_substring_in_identifiers():
    """`prefix07123456789suffix` shouldn't match — the leading char is a
    word character so the lookbehind correctly rejects the substring."""
    detector = UKPhoneDetector()
    matches = detector.detect("prefix07123456789suffix")
    assert all("07123456789" not in m.match_text for m in matches)


# --------------------------------------------------------------------------- #
# End-to-end via Brass2PrivacyScanner — config.py-shaped regression           #
# --------------------------------------------------------------------------- #


def test_privacy_scanner_finds_parens_phone_in_config_shaped_file(tmp_path):
    """The originally-surfacing case: a config.py with a parens-formatted
    phone number was silently missed, leading to the file producing zero
    findings and tripping the e2e test."""
    from brass.scanners.brass2_privacy_scanner import Brass2PrivacyScanner

    (tmp_path / "config.py").write_text(
        "DATABASE_URL = 'postgresql://user:password@localhost/db'\n"
        "ADMIN_PHONE = '(555) 123-4567'\n",
        encoding="utf-8",
    )
    findings = Brass2PrivacyScanner(str(tmp_path)).scan()
    pattern_types = {f.metadata.get("pattern_type") for f in findings}
    assert "phone_number" in pattern_types, (
        f"phone_number missing from privacy scan output; got {pattern_types}"
    )
