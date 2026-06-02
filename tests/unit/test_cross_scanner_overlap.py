"""Tests for the shared cross-scanner overlap computation.

Covers the extracted `compute_cross_scanner_overlap` function and
the `stash_overlap_on_metadata` helper used by the CLI to pre-stash
peer lists on finding metadata before Voyage enrichment runs.

Phase F architectural fix (2026-05-16).
"""

from __future__ import annotations

import pytest

from brass.models.finding import Finding, FindingType, Severity
from brass.output.cross_scanner_overlap import (
    METADATA_KEY,
    compute_cross_scanner_overlap,
    stash_overlap_on_metadata,
)


def _finding(
    *, ident: str, file_path: str = "src/a.py", line: int = 10,
    detected_by: str = "test_scanner", metadata: dict | None = None,
) -> Finding:
    return Finding(
        id=ident,
        type=FindingType.SECURITY,
        severity=Severity.HIGH,
        file_path=file_path,
        line_number=line,
        title="t",
        description="d",
        detected_by=detected_by,
        confidence=0.9,
        impact_score=0.9,
        metadata=metadata or {},
    )


# --- compute_cross_scanner_overlap -------------------------------------

def test_compute_returns_peer_map_for_cross_scanner_pair():
    """Two scanners at same (file, line) → each gets the other in
    its overlap entry."""
    f1 = _finding(ident="a", detected_by="bandit")
    f2 = _finding(ident="b", detected_by="AstGrepScanner")
    overlap = compute_cross_scanner_overlap([f1, f2])
    assert overlap[("src/a.py", 10, "bandit")] == ["AstGrepScanner"]
    assert overlap[("src/a.py", 10, "AstGrepScanner")] == ["bandit"]


def test_compute_returns_empty_for_singleton_bucket():
    """Only one finding at a (file, line) → no peers, no entry."""
    f = _finding(ident="a", detected_by="bandit")
    overlap = compute_cross_scanner_overlap([f])
    assert overlap == {}


def test_compute_skips_same_scanner_duplicates():
    """Two findings from the SAME scanner at the same line are not
    cross-scanner overlap."""
    f1 = _finding(ident="a", detected_by="bandit")
    f2 = _finding(ident="b", detected_by="bandit")
    overlap = compute_cross_scanner_overlap([f1, f2])
    assert overlap == {}


def test_compute_skips_findings_with_missing_location():
    """Findings missing file_path or line_number can't be bucketed."""
    f1 = _finding(ident="a", file_path="", line=10, detected_by="bandit")
    f2 = _finding(ident="b", file_path="src/x.py", line=None, detected_by="bandit")  # type: ignore[arg-type]
    overlap = compute_cross_scanner_overlap([f1, f2])
    assert overlap == {}


def test_compute_buckets_by_distinct_file_line():
    """Same scanner on different (file, line) tuples are independent."""
    f1 = _finding(ident="a", file_path="src/a.py", line=10, detected_by="bandit")
    f2 = _finding(ident="b", file_path="src/a.py", line=10, detected_by="AstGrepScanner")
    f3 = _finding(ident="c", file_path="src/b.py", line=10, detected_by="bandit")  # different file
    f4 = _finding(ident="d", file_path="src/b.py", line=10, detected_by="SemgrepTaintScanner")
    overlap = compute_cross_scanner_overlap([f1, f2, f3, f4])
    # Both buckets emit their own peer entries
    assert ("src/a.py", 10, "bandit") in overlap
    assert ("src/b.py", 10, "bandit") in overlap
    # And the values reflect the OTHER scanner in each bucket only
    assert overlap[("src/a.py", 10, "bandit")] == ["AstGrepScanner"]
    assert overlap[("src/b.py", 10, "bandit")] == ["SemgrepTaintScanner"]


def test_compute_three_scanners_lists_other_two_each():
    """Three-way bucket: each finding lists the OTHER two scanners."""
    f1 = _finding(ident="a", detected_by="bandit")
    f2 = _finding(ident="b", detected_by="AstGrepScanner")
    f3 = _finding(ident="c", detected_by="SemgrepTaintScanner")
    overlap = compute_cross_scanner_overlap([f1, f2, f3])
    assert overlap[("src/a.py", 10, "bandit")] == ["AstGrepScanner", "SemgrepTaintScanner"]
    assert overlap[("src/a.py", 10, "AstGrepScanner")] == ["SemgrepTaintScanner", "bandit"]
    assert overlap[("src/a.py", 10, "SemgrepTaintScanner")] == ["AstGrepScanner", "bandit"]


# --- stash_overlap_on_metadata -----------------------------------------

def test_stash_adds_metadata_key_for_findings_with_peers():
    """A finding whose location+scanner has peers gets the metadata key."""
    f1 = _finding(ident="a", detected_by="bandit")
    f2 = _finding(ident="b", detected_by="AstGrepScanner")
    out = stash_overlap_on_metadata([f1, f2])
    by_id = {f.id: f for f in out}
    assert by_id["a"].metadata.get(METADATA_KEY) == ["AstGrepScanner"]
    assert by_id["b"].metadata.get(METADATA_KEY) == ["bandit"]


def test_stash_does_not_mutate_input_findings():
    """Immutability contract — input findings' metadata stays unchanged
    (Phase E precedent: enrichment also uses `dataclasses.replace`)."""
    f1 = _finding(ident="a", detected_by="bandit")
    f2 = _finding(ident="b", detected_by="AstGrepScanner")
    input_metadata_a = f1.metadata
    input_metadata_b = f2.metadata
    _ = stash_overlap_on_metadata([f1, f2])
    # Original objects' metadata unchanged
    assert METADATA_KEY not in f1.metadata
    assert METADATA_KEY not in f2.metadata
    # Identity preserved (no in-place replacement)
    assert f1.metadata is input_metadata_a
    assert f2.metadata is input_metadata_b


def test_stash_preserves_existing_metadata_keys():
    """Stash must not clobber pre-existing metadata."""
    f1 = _finding(ident="a", detected_by="bandit", metadata={"existing_key": "stay"})
    f2 = _finding(ident="b", detected_by="AstGrepScanner")
    out = stash_overlap_on_metadata([f1, f2])
    by_id = {f.id: f for f in out}
    assert by_id["a"].metadata["existing_key"] == "stay"
    assert by_id["a"].metadata[METADATA_KEY] == ["AstGrepScanner"]


def test_stash_passes_through_findings_without_peers():
    """A finding with no peers is returned by identity (no replace)."""
    f = _finding(ident="solo", detected_by="bandit")
    out = stash_overlap_on_metadata([f])
    assert out[0] is f  # exact same object
    assert METADATA_KEY not in out[0].metadata


def test_stash_empty_input_returns_empty_list():
    assert stash_overlap_on_metadata([]) == []


def test_stash_preserves_order():
    """Output list preserves input order (callers may rely on rank)."""
    findings = [
        _finding(ident="a", line=10, detected_by="bandit"),
        _finding(ident="b", line=20, detected_by="bandit"),
        _finding(ident="c", line=10, detected_by="AstGrepScanner"),
    ]
    out = stash_overlap_on_metadata(findings)
    assert [f.id for f in out] == ["a", "b", "c"]


def test_stash_handles_line_number_zero():
    """A finding at line 0 (legal — some scanners use it for file-level
    signals) must still receive peers. The guard inside stash used to
    falsy-test line_number, which silently dropped line-0 peers even
    though compute_cross_scanner_overlap bucketed them correctly."""
    f1 = _finding(ident="a", line=0, detected_by="bandit")
    f2 = _finding(ident="b", line=0, detected_by="AstGrepScanner")
    out = stash_overlap_on_metadata([f1, f2])
    by_id = {f.id: f for f in out}
    assert by_id["a"].metadata.get(METADATA_KEY) == ["AstGrepScanner"]
    assert by_id["b"].metadata.get(METADATA_KEY) == ["bandit"]


def test_stash_peer_lists_are_independent_copies():
    """Each finding's stashed peer list must be its own object — not
    aliased to the per-build overlap map, so downstream mutation on
    one finding cannot bleed to another."""
    f1 = _finding(ident="a", detected_by="bandit")
    f2 = _finding(ident="b", detected_by="AstGrepScanner")
    f3 = _finding(ident="c", detected_by="SemgrepTaintScanner")
    out = stash_overlap_on_metadata([f1, f2, f3])
    peer_lists = [f.metadata.get(METADATA_KEY) for f in out]
    # All three findings got a peer list.
    assert all(peer_lists)
    # Mutating one peer list must not change another.
    peer_lists[0].append("MUTATION")
    assert "MUTATION" not in peer_lists[1]
    assert "MUTATION" not in peer_lists[2]
