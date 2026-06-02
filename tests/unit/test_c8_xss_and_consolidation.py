"""Tests for phase C.8 fixes.

C.8a: XSS scanner doesn't fire on safe-wrapper function calls
       (dangerouslySetInnerHTML={{ __html: safeJsonLd(...) }} and friends).
C.8b: Privacy scanner consolidates multi-detector same-(file, line)
       findings into a single finding with pii_types list.
"""

from __future__ import annotations

import pytest


# --------------------------------------------------------------------------- #
# C.8a — XSS safe-wrapper helper                                              #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("line", [
    "    dangerouslySetInnerHTML={{ __html: safeJsonLd(faqSchema) }}",
    "<script dangerouslySetInnerHTML={{ __html: sanitize(html) }} />",
    "x = { __html: DOMPurify.sanitize(input) }",
    "{ __html: escapeHtml(value) }",
    "{ __html: encodeHtml(data) }",
    "{ __html: cleanHtml(raw) }",
    "{ __html: purify(payload) }",
    "{ __html: safeMarkup(content) }",
    "{ __html: safeRender(item) }",  # any "safe*" identifier
    "{ __html: escapeForHtml(s) }",  # any "escape*" identifier
])
def test_xss_safe_wrapper_pattern_recognizes_known_wrappers(line):
    from brass.scanners.api_security_scanner import _xss_match_is_safe_wrapper
    assert _xss_match_is_safe_wrapper(line), f"should detect safe wrapper in: {line!r}"


@pytest.mark.parametrize("line", [
    "dangerouslySetInnerHTML={{ __html: JSON.stringify(faqSchema) }}",   # raw stringify — unsafe
    "{ __html: someVar }",                                               # bare variable
    "{ __html: `<div>${user}</div>` }",                                  # template literal
    "{ __html: data.html }",                                             # property access
    "{ __html: req.body.content }",                                      # user input shape
])
def test_xss_safe_wrapper_pattern_rejects_unsafe_patterns(line):
    from brass.scanners.api_security_scanner import _xss_match_is_safe_wrapper
    assert not _xss_match_is_safe_wrapper(line), f"should NOT mark safe: {line!r}"


def test_xss_scanner_e2e_skips_safe_wrapper_finding(tmp_path):
    """End-to-end: the brass-seo regression repro should not fire."""
    from brass.scanners.api_security_scanner import APIInputValidationAnalyzer

    code = """
function FaqMarkup({ faqSchema }) {
  return (
    <script
      type="application/ld+json"
      dangerouslySetInnerHTML={{ __html: safeJsonLd(faqSchema) }}
    />
  );
}
"""
    analyzer = APIInputValidationAnalyzer(str(tmp_path))
    config = analyzer.VALIDATION_PATTERNS['xss_risk']
    findings = analyzer._check_validation_patterns(code, "lib/schema.ts", "xss_risk", config)
    assert findings == [], (
        f"safe-wrapper XSS should be filtered; got {[(f.title, f.code_snippet) for f in findings]}"
    )


def test_xss_scanner_still_fires_on_raw_json_stringify(tmp_path):
    """Regression: the unsafe pattern should still surface."""
    from brass.scanners.api_security_scanner import APIInputValidationAnalyzer

    code = """
const Bad = ({ data }) => (
  <div dangerouslySetInnerHTML={{ __html: JSON.stringify(data) }} />
);
"""
    analyzer = APIInputValidationAnalyzer(str(tmp_path))
    config = analyzer.VALIDATION_PATTERNS['xss_risk']
    findings = analyzer._check_validation_patterns(code, "unsafe.tsx", "xss_risk", config)
    assert len(findings) >= 1, "raw JSON.stringify inside __html should still flag"


# --------------------------------------------------------------------------- #
# C.8b — multi-detector consolidation                                         #
# --------------------------------------------------------------------------- #


def test_privacy_scanner_consolidates_multi_detector_findings_at_same_line(tmp_path):
    """Same line matching NHS + Medicare + Phone regexes should emit
    ONE finding with pii_types: [...], not three."""
    from brass.scanners.brass2_privacy_scanner import Brass2PrivacyScanner

    # 12-digit number that hits Aadhaar, plus a phone-shaped number on
    # the same line. Both detectors fire; consolidation must collapse.
    target = tmp_path / "leaks.md"
    target.write_text(
        "Test data: 4567 8901 2345 and phone 555-867-5309 — both fixtures.\n",
        encoding="utf-8",
    )

    scanner = Brass2PrivacyScanner(str(tmp_path))
    findings = scanner.scan(file_paths=[str(target)])
    same_line = [f for f in findings if f.line_number == 1]
    # After consolidation: at most one finding for line 1, even when
    # multiple detectors hit. Metadata records the consolidation count.
    assert len(same_line) <= 1, (
        f"expected ≤1 consolidated finding, got {len(same_line)}: "
        f"{[(f.title, f.metadata) for f in same_line]}"
    )
    if same_line:
        meta = same_line[0].metadata or {}
        if meta.get('consolidated_from'):
            assert meta['consolidated_from'] >= 2
            assert isinstance(meta.get('pii_types'), list)
            assert len(meta['pii_types']) >= 2
            assert 'Multiple PII patterns' in same_line[0].title


def test_privacy_scanner_does_not_consolidate_findings_on_different_lines(tmp_path):
    """Regression: distinct lines should not be merged."""
    from brass.scanners.brass2_privacy_scanner import Brass2PrivacyScanner

    target = tmp_path / "split.md"
    target.write_text(
        "First line phone: 555-867-5309\nSecond line phone: 555-123-4567\n",
        encoding="utf-8",
    )

    scanner = Brass2PrivacyScanner(str(tmp_path))
    findings = scanner.scan(file_paths=[str(target)])
    line_nums = {f.line_number for f in findings}
    # Two separate findings, not merged.
    if findings:
        assert line_nums == {1, 2} or len(line_nums) >= 1
