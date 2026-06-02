"""Unit tests for NoiseReductionScanner._apply_per_file_limits.

This logic was added 2026-05-18 as part of the confidence-audit fix
(commit 6a416db) and the follow-up bug-review pass: priority finding
types (SECURITY, PRIVACY, ANALYSIS_ERROR) are exempt from the per-file
cap; all others are sorted by (severity, type-priority, confidence,
impact) and trimmed to ``max_findings_per_file`` per file.

Prior to these tests the new behavior was only validated end-to-end
via the bandit_examples benchmark — no unit-level invariant check.
"""

from __future__ import annotations

from typing import List

from brass.models.finding import Finding, FindingType, Severity
from brass.scanners.noise_reduction_scanner import NoiseReductionScanner


def _mk(
    file_path: str,
    finding_type: FindingType,
    severity: Severity,
    confidence: float,
    title: str = "test",
) -> Finding:
    """Compact Finding constructor for table-driven tests."""
    return Finding(
        id=f"{file_path}-{finding_type}-{severity}-{confidence}-{title}",
        type=finding_type,
        severity=severity,
        file_path=file_path,
        line_number=1,
        title=title,
        description="test",
        confidence=confidence,
        detected_by="test",
    )


class TestApplyPerFileLimits:
    """The per-file cap must:
      1. Pass all SECURITY findings through untouched
      2. Pass all PRIVACY findings through untouched
      3. Pass all ANALYSIS_ERROR findings through untouched
      4. Cap non-priority findings at max_findings_per_file
      5. Sort non-priority findings by severity then type-priority then
         confidence then impact when capping
      6. Handle max_findings_per_file = 0 gracefully (priority types
         still survive)
      7. Be a no-op when total findings per file <= cap"""

    def _scanner(self, cap: int = 3) -> NoiseReductionScanner:
        # NoiseReductionScanner takes project_path; we don't touch the
        # filesystem in these tests, so any string is fine.
        s = NoiseReductionScanner(project_path=".")
        s.max_findings_per_file = cap
        return s

    def test_security_findings_exempt_from_cap(self):
        """20 SECURITY findings on one file should all survive a cap of 3."""
        scanner = self._scanner(cap=3)
        findings = [
            _mk("a.py", FindingType.SECURITY, Severity.HIGH, 0.8, f"sec-{i}")
            for i in range(20)
        ]
        result = scanner._apply_per_file_limits(findings)
        assert len(result) == 20, "all SECURITY findings must pass"
        assert all(f.type == FindingType.SECURITY for f in result)

    def test_privacy_findings_exempt_from_cap(self):
        """PRIVACY findings get the same exemption."""
        scanner = self._scanner(cap=2)
        findings = [
            _mk("a.py", FindingType.PRIVACY, Severity.HIGH, 0.9, f"priv-{i}")
            for i in range(10)
        ]
        result = scanner._apply_per_file_limits(findings)
        assert len(result) == 10

    def test_analysis_error_findings_exempt_from_cap(self):
        """ANALYSIS_ERROR breadcrumbs must survive a scanner-crash storm.
        Without the exemption a file with 16 errors and cap=15 would
        silently drop one — exactly the debug context the breadcrumb
        is supposed to preserve."""
        scanner = self._scanner(cap=3)
        findings = [
            _mk("a.py", FindingType.ANALYSIS_ERROR, Severity.LOW, 0.9, f"err-{i}")
            for i in range(8)
        ]
        result = scanner._apply_per_file_limits(findings)
        assert len(result) == 8

    def test_code_quality_findings_are_capped(self):
        """Non-priority types ARE subject to the cap."""
        scanner = self._scanner(cap=3)
        findings = [
            _mk("a.py", FindingType.CODE_QUALITY, Severity.LOW, 0.6, f"cq-{i}")
            for i in range(10)
        ]
        result = scanner._apply_per_file_limits(findings)
        assert len(result) == 3

    def test_cap_sort_picks_highest_severity_first(self):
        """When 10 CODE_QUALITY findings exist with mixed severities and
        cap=3, the 3 surviving must be the highest-severity ones."""
        scanner = self._scanner(cap=3)
        findings = (
            [_mk("a.py", FindingType.CODE_QUALITY, Severity.LOW, 0.6, f"low-{i}") for i in range(5)]
            + [_mk("a.py", FindingType.CODE_QUALITY, Severity.MEDIUM, 0.6, f"med-{i}") for i in range(3)]
            + [_mk("a.py", FindingType.CODE_QUALITY, Severity.HIGH, 0.6, f"high-{i}") for i in range(2)]
        )
        result = scanner._apply_per_file_limits(findings)
        assert len(result) == 3
        severities = [f.severity for f in result]
        assert all(s in (Severity.HIGH, Severity.MEDIUM) for s in severities)
        # The two HIGH must be present (no MEDIUM should outrank them).
        assert sum(1 for s in severities if s == Severity.HIGH) == 2

    def test_type_priority_tiebreaks_within_same_severity(self):
        """When severities tie, the type-priority order applies:
        SECURITY > PRIVACY > PERFORMANCE > ARCHITECTURE > CODE_QUALITY
        > TODO > ANALYSIS_ERROR. (For non-priority types here:
        PERFORMANCE > ARCHITECTURE > CODE_QUALITY > TODO.)"""
        scanner = self._scanner(cap=2)
        # Same severity + same confidence; only the type differs.
        findings = [
            _mk("a.py", FindingType.TODO, Severity.MEDIUM, 0.6, "todo"),
            _mk("a.py", FindingType.CODE_QUALITY, Severity.MEDIUM, 0.6, "cq"),
            _mk("a.py", FindingType.ARCHITECTURE, Severity.MEDIUM, 0.6, "arch"),
            _mk("a.py", FindingType.PERFORMANCE, Severity.MEDIUM, 0.6, "perf"),
        ]
        result = scanner._apply_per_file_limits(findings)
        assert len(result) == 2
        result_types = {f.type for f in result}
        # PERFORMANCE + ARCHITECTURE should beat CODE_QUALITY + TODO.
        assert FindingType.PERFORMANCE in result_types
        assert FindingType.ARCHITECTURE in result_types

    def test_security_plus_capped_other(self):
        """Mixed file: 5 SECURITY + 10 CODE_QUALITY with cap=3 → all 5
        security + top 3 code quality = 8 findings."""
        scanner = self._scanner(cap=3)
        findings = (
            [_mk("a.py", FindingType.SECURITY, Severity.HIGH, 0.7, f"sec-{i}") for i in range(5)]
            + [_mk("a.py", FindingType.CODE_QUALITY, Severity.LOW, 0.6, f"cq-{i}") for i in range(10)]
        )
        result = scanner._apply_per_file_limits(findings)
        assert len(result) == 8
        assert sum(1 for f in result if f.type == FindingType.SECURITY) == 5
        assert sum(1 for f in result if f.type == FindingType.CODE_QUALITY) == 3

    def test_no_op_when_under_cap(self):
        """File with 2 CODE_QUALITY findings + cap=3 → both pass."""
        scanner = self._scanner(cap=3)
        findings = [
            _mk("a.py", FindingType.CODE_QUALITY, Severity.LOW, 0.6, "cq-1"),
            _mk("a.py", FindingType.CODE_QUALITY, Severity.LOW, 0.6, "cq-2"),
        ]
        result = scanner._apply_per_file_limits(findings)
        assert len(result) == 2

    def test_cap_zero_preserves_priority_types(self):
        """Edge: cap=0 zeros the non-priority bucket entirely but
        priority types still survive."""
        scanner = self._scanner(cap=0)
        findings = (
            [_mk("a.py", FindingType.SECURITY, Severity.HIGH, 0.7, "sec")]
            + [_mk("a.py", FindingType.CODE_QUALITY, Severity.LOW, 0.6, f"cq-{i}") for i in range(5)]
        )
        result = scanner._apply_per_file_limits(findings)
        assert len(result) == 1
        assert result[0].type == FindingType.SECURITY

    def test_priority_findings_capped_at_10x_multiplier(self):
        """Pathological-case bound: SECURITY/PRIVACY/ANALYSIS_ERROR get
        a generous 10x cap (e.g. 150 with default 15) but are NOT
        unbounded. 200 SECURITY findings on one file get trimmed to
        the top 150 by severity/confidence."""
        scanner = self._scanner(cap=15)
        # 200 findings, all SECURITY, but vary severity so the sort
        # has something to do. HIGH should survive over LOW.
        findings = (
            [_mk("a.py", FindingType.SECURITY, Severity.HIGH, 0.9, f"high-{i}") for i in range(100)]
            + [_mk("a.py", FindingType.SECURITY, Severity.LOW, 0.5, f"low-{i}") for i in range(100)]
        )
        result = scanner._apply_per_file_limits(findings)
        assert len(result) == 150, "priority bucket must be capped at 10x"
        # All 100 HIGH severity must survive (they outrank the LOW ones).
        high_count = sum(1 for f in result if f.severity == Severity.HIGH)
        assert high_count == 100

    def test_priority_cap_no_op_for_normal_files(self):
        """A file with 50 SECURITY findings — well under the 150 cap
        at default — passes through untouched. The 10x cap is for
        pathological cases, not normal hot spots."""
        scanner = self._scanner(cap=15)
        findings = [
            _mk("a.py", FindingType.SECURITY, Severity.MEDIUM, 0.7, f"sec-{i}")
            for i in range(50)
        ]
        result = scanner._apply_per_file_limits(findings)
        assert len(result) == 50, "real hot spots must still surface in full"

    def test_cap_applied_per_file_not_globally(self):
        """Multi-file: cap=2 per file. Two files each get 5 CODE_QUALITY
        → result should have 4 total (2 per file), not 2."""
        scanner = self._scanner(cap=2)
        findings = (
            [_mk("a.py", FindingType.CODE_QUALITY, Severity.LOW, 0.6, f"a-{i}") for i in range(5)]
            + [_mk("b.py", FindingType.CODE_QUALITY, Severity.LOW, 0.6, f"b-{i}") for i in range(5)]
        )
        result = scanner._apply_per_file_limits(findings)
        assert len(result) == 4
        file_paths = {f.file_path for f in result}
        assert file_paths == {"a.py", "b.py"}


class TestTypeToInt:
    """Type-priority ordering used as the cap-sort tiebreaker."""

    def test_security_is_highest(self):
        s = NoiseReductionScanner(project_path=".")
        assert s._type_to_int(FindingType.SECURITY) > s._type_to_int(FindingType.PRIVACY)

    def test_privacy_beats_performance(self):
        s = NoiseReductionScanner(project_path=".")
        assert s._type_to_int(FindingType.PRIVACY) > s._type_to_int(FindingType.PERFORMANCE)

    def test_analysis_error_is_lowest(self):
        s = NoiseReductionScanner(project_path=".")
        all_types = [
            FindingType.SECURITY,
            FindingType.PRIVACY,
            FindingType.PERFORMANCE,
            FindingType.ARCHITECTURE,
            FindingType.CODE_QUALITY,
            FindingType.TODO,
            FindingType.ANALYSIS_ERROR,
        ]
        ranks = [s._type_to_int(t) for t in all_types]
        assert ranks[-1] == min(ranks), "ANALYSIS_ERROR must be the lowest-ranked type"

    def test_strict_ordering(self):
        """All ranks distinct + monotonically decreasing."""
        s = NoiseReductionScanner(project_path=".")
        ordered = [
            FindingType.SECURITY,
            FindingType.PRIVACY,
            FindingType.PERFORMANCE,
            FindingType.ARCHITECTURE,
            FindingType.CODE_QUALITY,
            FindingType.TODO,
            FindingType.ANALYSIS_ERROR,
        ]
        ranks = [s._type_to_int(t) for t in ordered]
        assert ranks == sorted(ranks, reverse=True), "type ranks must strictly decrease"
        assert len(set(ranks)) == len(ranks), "type ranks must be distinct"


class TestOtherBucketDropCounter:
    """The "other" bucket per-file cap silently dropped LOW/MEDIUM
    findings before 2026-05-21 — no counter, no end-of-scan summary.
    Now `_other_bucket_dropped` accumulates across files and a single
    INFO log fires from `scan()` when > 0. Regression guard so the
    counter doesn't silently drift back to zero.
    """

    def test_counter_tracks_drops_across_files(self):
        """Each over-cap file contributes (len-cap) to the running
        total; under-cap files contribute zero."""
        from brass.scanners.noise_reduction_scanner import NoiseReductionScanner
        scanner = NoiseReductionScanner(project_path=".", max_findings_per_file=2)

        # File A: 5 LOW code_quality findings → cap=2 → 3 dropped.
        # File B: 1 LOW code_quality → under cap → 0 dropped.
        # File C: 4 LOW todo → cap=2 → 2 dropped.
        # Expected total: 3 + 0 + 2 = 5.
        findings = []
        for i in range(5):
            findings.append(_mk("a.py", FindingType.CODE_QUALITY, Severity.LOW, 0.9, f"a{i}"))
        findings.append(_mk("b.py", FindingType.CODE_QUALITY, Severity.LOW, 0.9, "b1"))
        for i in range(4):
            findings.append(_mk("c.py", FindingType.TODO, Severity.LOW, 0.9, f"c{i}"))

        result = scanner.scan(findings)

        # Counter exposes the total cap-trim across all files.
        assert scanner._other_bucket_dropped == 5, (
            f"expected 5 drops total (3 from a.py + 2 from c.py); got "
            f"{scanner._other_bucket_dropped}"
        )
        # Result length: 2 from a.py + 1 from b.py + 2 from c.py = 5.
        assert len(result) == 5

    def test_counter_resets_between_scans(self):
        """A re-used scanner instance must not leak the previous
        scan's drop count into the current scan's summary."""
        from brass.scanners.noise_reduction_scanner import NoiseReductionScanner
        scanner = NoiseReductionScanner(project_path=".", max_findings_per_file=2)

        # First scan: 5 LOW findings on one file → 3 dropped.
        first = [_mk("a.py", FindingType.CODE_QUALITY, Severity.LOW, 0.9, f"a{i}") for i in range(5)]
        scanner.scan(first)
        assert scanner._other_bucket_dropped == 3

        # Second scan: 3 LOW findings on one file → 1 dropped.
        # If the counter weren't reset, we'd see 3 + 1 = 4 instead of 1.
        second = [_mk("b.py", FindingType.CODE_QUALITY, Severity.LOW, 0.9, f"b{i}") for i in range(3)]
        scanner.scan(second)
        assert scanner._other_bucket_dropped == 1, (
            f"counter must reset between scans; got {scanner._other_bucket_dropped}"
        )

    def test_counter_resets_even_when_input_is_empty(self):
        """The empty-input early-return must NOT leak a stale counter
        into the next non-empty scan. Sequence: scan(big) → scan([])
        → scan(small) — the third scan's counter should reflect only
        its own drops, not the first scan's. Discovered 2026-05-21
        full-bugs cumulative review: the reset originally ran AFTER
        the early-return, so the empty-input path skipped it."""
        from brass.scanners.noise_reduction_scanner import NoiseReductionScanner
        scanner = NoiseReductionScanner(project_path=".", max_findings_per_file=2)

        # Big batch first: 5 findings → 3 dropped.
        first = [_mk("a.py", FindingType.CODE_QUALITY, Severity.LOW, 0.9, f"a{i}") for i in range(5)]
        scanner.scan(first)
        assert scanner._other_bucket_dropped == 3

        # Empty batch: nothing to filter, but the counter MUST still
        # reset (was the bug — reset ran after the early-return).
        scanner.scan([])
        assert scanner._other_bucket_dropped == 0, (
            "empty-input scan must reset the counter; got "
            f"{scanner._other_bucket_dropped}"
        )

        # Now a small batch — counter must reflect only its own drops.
        third = [_mk("c.py", FindingType.CODE_QUALITY, Severity.LOW, 0.9, f"c{i}") for i in range(3)]
        scanner.scan(third)
        assert scanner._other_bucket_dropped == 1, (
            f"third-scan counter leaked previous state; got {scanner._other_bucket_dropped}"
        )
