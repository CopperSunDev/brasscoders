"""Unit tests for ContentModerationScanner.

Initially scoped to the regression for the None-slice TypeError fixed
in this commit (loose end #3 from the post-arc investigation). Broader
test coverage of the scanner's pattern logic is a separate concern.
"""
from __future__ import annotations

from pathlib import Path

from brass.models.finding import Finding, FindingType, Severity
from brass.scanners.content_moderation_scanner import ContentModerationScanner


def _scanner_self_finding(*, code_snippet=None, metadata=None) -> Finding:
    """Build a Finding shaped like one content_moderation produces:
    file_path inside `src/brass/scanners/` (which triggers the
    `_should_skip_scanner_self_flagging` path) and `code_snippet=None`
    (the content_moderation scanner deliberately nulls this around
    line 668 of its own source to avoid persisting profanity).

    No CONTENT_MODERATION FindingType exists in the codebase — these
    findings use PRIVACY by convention.
    """
    return Finding(
        id="cm-test-1",
        type=FindingType.PRIVACY,
        severity=Severity.LOW,
        file_path="src/brass/scanners/content_moderation_scanner.py",
        line_number=1,
        title="self-flag candidate",
        description="test",
        code_snippet=code_snippet,
        metadata=metadata or {},
    )


def test_should_skip_does_not_raise_on_none_code_snippet(tmp_path: Path):
    """Regression: pre-fix this raised TypeError on `code_snippet[:100]`
    because content_moderation constructs its own findings with
    code_snippet=None and feeds them back through
    _should_skip_scanner_self_flagging."""
    scanner = ContentModerationScanner(str(tmp_path))
    finding = _scanner_self_finding(code_snippet=None, metadata={})
    # Must not raise.
    result = scanner._should_skip_scanner_self_flagging(finding)
    assert isinstance(result, bool)


def test_should_skip_does_not_raise_on_explicit_none_metadata(tmp_path: Path):
    """Metadata explicitly containing code_snippet=None (not missing —
    present with a None value) is the case `.get(..., '')` doesn't
    handle: dict.get returns None when the key exists with None,
    regardless of the default."""
    scanner = ContentModerationScanner(str(tmp_path))
    finding = _scanner_self_finding(
        code_snippet=None,
        metadata={"code_snippet": None, "matched_text": None},
    )
    result = scanner._should_skip_scanner_self_flagging(finding)
    assert isinstance(result, bool)


def test_should_skip_returns_false_for_non_scanner_files(tmp_path: Path):
    """Positive control: when the file isn't inside src/brass/scanners,
    the method short-circuits to False before any code_snippet access,
    so a None code_snippet here is harmless — confirms we haven't
    broken the early-return contract."""
    scanner = ContentModerationScanner(str(tmp_path))
    finding = Finding(
        id="cm-test-2",
        type=FindingType.PRIVACY,
        severity=Severity.LOW,
        file_path="customer_app/models/user.py",  # NOT a scanner file
        line_number=1,
        title="real finding",
        description="real",
        code_snippet=None,
        metadata={},
    )
    assert scanner._should_skip_scanner_self_flagging(finding) is False
