"""Cross-scanner overlap computation.

Two consumers share this module:

1. The CLI (``brass_cli.py`` just before ``_maybe_apply_enrichment``):
   stashes the peer list onto each finding's
   ``metadata['cross_scanner_overlap_peers']`` BEFORE enrichment runs.
   Without this, the gateway's semantic clusterer collapses
   cross-scanner same-line pairs into single survivors, hiding the
   cross-scanner agreement signal Phase F is supposed to surface.

2. The YAML builder (``YAMLAIInstructionsBuilder._add_optional_fields``):
   falls back to recomputing the overlap map directly when a finding
   has no pre-stashed metadata. Covers the test-isolation path where
   findings are constructed and passed to the builder without going
   through the CLI's enrichment pipeline.

The shared computation lives here so both code paths use one source
of truth.

History: Phase F (commit eeec533, 2026-05-15) shipped the
overlap computation inside the YAML builder. Yesterday's
whisperx-production benchmark revealed the bypass: heuristic-only
runs produced 7/50 ``also_detected_by`` populated; enriched runs
produced 1/18 — the gateway's dedup pass was dropping the peers.
This module is the fix.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import replace
from typing import Dict, List, Sequence, Tuple

from brass.models.finding import Finding


# Metadata key used to stash the pre-enrichment peer list on a
# Finding's metadata dict. The verbose name avoids namespace
# collisions with any current or future scanner-supplied keys.
METADATA_KEY = "cross_scanner_overlap_peers"


def compute_cross_scanner_overlap(
    findings: Sequence[Finding],
) -> Dict[Tuple[str, int, str], List[str]]:
    """Bucket findings by ``(file_path, line_number)``; for each bucket
    with ≥2 distinct ``detected_by`` values, return a per-scanner map of
    OTHER scanner names that flagged the same location.

    Map key: ``(file_path, line_number, detected_by)``.
    Map value: alphabetically-sorted list of OTHER scanner names.

    Same-scanner findings at one line are not cross-scanner overlap
    and contribute no entries. Findings missing file_path or
    line_number can't be bucketed and are silently skipped.

    Complexity: O(N) bucket build + O(K²) per-bucket emit where K is
    bucket size. Realistic K is 1–3 (a few rule engines flagging the
    same line). Pathological worst case is N² if all findings collapse
    onto one location, but that doesn't occur in normal scans.
    """
    buckets: Dict[Tuple[str, int], List[Finding]] = defaultdict(list)
    for f in findings:
        if f.line_number is None or not f.file_path:
            continue
        buckets[(f.file_path, f.line_number)].append(f)
    overlap: Dict[Tuple[str, int, str], List[str]] = {}
    for (file_path, line_number), bucket_findings in buckets.items():
        if len(bucket_findings) < 2:
            continue
        scanners_in_bucket = {
            f.detected_by for f in bucket_findings if f.detected_by
        }
        if len(scanners_in_bucket) < 2:
            # Same scanner firing multiple times on one line is not
            # cross-scanner overlap; nothing to report.
            continue
        for scanner in scanners_in_bucket:
            others = sorted(scanners_in_bucket - {scanner})
            if others:
                overlap[(file_path, line_number, scanner)] = others
    return overlap


def stash_overlap_on_metadata(
    findings: Sequence[Finding],
) -> List[Finding]:
    """Compute overlap and return a NEW list of Findings with peers
    stashed on metadata.

    Each Finding with cross-scanner peers gets a new entry:
        ``metadata['cross_scanner_overlap_peers']``: ``List[str]``
        — sorted list of OTHER scanner names at the same
        ``(file_path, line_number)``.

    Uses ``dataclasses.replace`` so the input findings are NOT
    mutated. Mirrors the immutability contract of
    ``apply_enrichment`` (which uses the same pattern for
    ``cluster_size`` per Phase E follow-up commit ``77fad97``).

    Findings without peers pass through unchanged (same object
    reference; no copy). Singleton-location findings, missing-line
    findings, and missing-detector findings are all returned as-is.

    Intended use: call this at the CLI layer just before
    ``_maybe_apply_enrichment`` so the peer metadata survives the
    gateway's duplicate-drop pass.
    """
    overlap = compute_cross_scanner_overlap(findings)
    if not overlap:
        return list(findings)
    out: List[Finding] = []
    for f in findings:
        # Use `is None` for line_number — a finding at line 0 is rare
        # but legal (some scanners use 0 for file-level signals), and
        # `compute_cross_scanner_overlap` does treat 0 as bucketable.
        # Falsy-testing here used to drop those peers silently.
        if not f.file_path or f.line_number is None or not f.detected_by:
            out.append(f)
            continue
        peers = overlap.get((f.file_path, f.line_number, f.detected_by))
        if not peers:
            out.append(f)
            continue
        new_metadata = dict(f.metadata or {})
        # Defensive copy: the overlap map shares list values across
        # the build, and downstream code (YAML serializer, enrichment)
        # could in principle mutate. Copy isolates per-finding state.
        new_metadata[METADATA_KEY] = list(peers)
        out.append(replace(f, metadata=new_metadata))
    return out
