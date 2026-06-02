"""Apply enrichment to a heuristic-filtered finding list.

Pipeline order in the CLI:
    raw scanners -> heuristic noise filter -> apply_enrichment (this) -> ranker

This module is the bridge between the in-process Finding model and the
gateway's wire format. It:
    1. Privacy-redacts and serializes each Finding for embedding
    2. Gathers raw_files context from the project root
    3. Calls the gateway, which decides survivors + order + cluster_size
    4. Maps gateway response back to Finding objects, applying cluster_size
    5. Returns the pre-sorted survivors list

2C refactor (2026-05-22): the gateway now owns dedup-survivor selection,
CRITICAL-exemption, rank_score ordering, and cluster_size computation.
The CLI just applies the response.

What stays client-side (security-relevant): finding-text construction
with privacy redaction for SECURITY/PRIVACY findings (`_finding_to_text`
+ `_safe_title`). Findings are sanitized BEFORE leaving the machine —
the gateway never sees raw secrets/PII even in embed-text form.

Gateway failures are not the caller's problem to handle — this module
passes exceptions up to the CLI, which routes them (soft fallback vs
hard fail per error type).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, replace
from typing import List, Sequence

from brass.enrichment.client import (
    EnrichmentClient,
    EnrichResult,
)
from brass.enrichment.project_signature import gather_raw_files
from brass.enrichment._wire_clamp import clamp_to_utf16_units


# Gateway schema caps (gateway/lib/schema.ts) — kept here for the wire-
# format builder to clamp against. If these drift from the schema, the
# CLI sends payloads the gateway rejects with 400. Numbers must match
# the z.string().max(N) values exactly.
_MAX_TEXT_UTF16_UNITS = 4000
_MAX_FILE_PATH_UTF16_UNITS = 1024
from brass.models.finding import Finding


logger = logging.getLogger(__name__)


@dataclass
class EnrichmentReport:
    """Diagnostic info the CLI surfaces to the user after enrichment."""
    input_count: int
    output_count: int
    duplicates_dropped: int
    tokens_used: int
    quota_remaining: int
    quota_period_end: str


def apply_enrichment(
    findings: Sequence[Finding],
    project_path: str,
    client: EnrichmentClient,
) -> tuple[List[Finding], EnrichmentReport]:
    """Run findings through the gateway and return the survivors list.

    Raises whatever EnrichmentClient raises — caller handles routing
    (soft fallback vs hard fail).

    The Finding model is preserved end-to-end; this module annotates
    cluster_size on metadata via dataclasses.replace (immutability
    contract) but never mutates contents. Order is the gateway's
    rank_score-desc order.
    """
    if not findings:
        return [], EnrichmentReport(0, 0, 0, 0, 0, "")

    # Stage 1: build wire payload. Use the input position as the
    # stable id since Finding.id isn't always populated/unique.
    indexed = list(enumerate(findings))
    payload = [
        _wire_finding(f"f{idx}", finding)
        for idx, finding in indexed
    ]

    # Stage 2: gather raw_files (README/manifest/entrypoint/filenames).
    # Gateway builds the project_signature from these server-side.
    raw_files = gather_raw_files(project_path)

    # Stage 3: call gateway.
    result: EnrichResult = client.enrich(payload, raw_files)

    # Optional debug dump — set BRASS_DEBUG_ENRICHMENT=1 (or the legacy
    # BRASS_DEBUG_VOYAGE=1 alias) to write the gateway response to
    # .brass/_enrichment_clusters.json for external auditing of
    # clustering decisions.
    if os.environ.get("BRASS_DEBUG_ENRICHMENT") == "1" or os.environ.get("BRASS_DEBUG_VOYAGE") == "1":
        _dump_debug(findings, result, project_path)

    # Stage 4: map gateway response back to Finding objects. The
    # response contains ONLY survivors, pre-sorted by rank_score desc.
    # Findings not in the response were dropped by the gateway (either
    # as cosine duplicates or because they weren't representable for
    # some reason — defensive log path below).
    output: List[Finding] = []

    # Iterate in the gateway's order (rank_score desc) to preserve the
    # server-side decision. For each survivor, find its original
    # Finding by id and annotate cluster_size if > 1. Drop entries with
    # unknown ids (gateway misbehavior) rather than passing them to
    # downstream code as None / KeyError surprises.
    findings_by_wire_id = {f"f{idx}": finding for idx, finding in indexed}
    for enriched in result.findings:
        original = findings_by_wire_id.get(enriched.id)
        if original is None:
            logger.warning(
                "enrichment: gateway returned unknown id %r; dropping",
                enriched.id,
            )
            continue
        if enriched.cluster_size > 1:
            new_metadata = dict(original.metadata or {})
            new_metadata['cluster_size'] = enriched.cluster_size
            original = replace(original, metadata=new_metadata)
        output.append(original)

    # Count findings dropped by the gateway, derived from the
    # RECOGNIZED survivor count (len(output)) not the raw response
    # count. If the gateway returns unknown ids, those don't count as
    # legitimate survivors — they're effectively dropped from the
    # caller's perspective, so they belong on the dropped side of the
    # ledger. (Previous formulation used len(result.findings), which
    # would underreport dropped count when gateway emitted bogus ids.)
    duplicates_dropped = len(findings) - len(output)
    if duplicates_dropped < 0:
        # Defensive: should be impossible (output count is bounded by
        # input count via the findings_by_wire_id lookup), but log if
        # we ever observe it.
        logger.warning(
            "enrichment: output count (%d) > input count (%d); something odd",
            len(output), len(findings),
        )
        duplicates_dropped = 0

    report = EnrichmentReport(
        input_count=len(findings),
        output_count=len(output),
        duplicates_dropped=duplicates_dropped,
        tokens_used=result.tokens_used,
        quota_remaining=result.quota_remaining,
        quota_period_end=result.quota_period_end,
    )
    return output, report


def _dump_debug(
    findings: Sequence[Finding],
    result: EnrichResult,
    project_path: str,
) -> None:
    """Write the gateway response + finding texts for external audit."""
    import json as _json
    from pathlib import Path as _Path
    dump_dir = _Path(project_path) / ".brass"
    dump_dir.mkdir(exist_ok=True)
    indexed = list(enumerate(findings))
    findings_by_wire_id = {f"f{idx}": finding for idx, finding in indexed}
    entries = []
    for enriched in result.findings:
        original = findings_by_wire_id.get(enriched.id)
        if original is None:
            continue
        entries.append({
            "id": enriched.id,
            "rank_score": enriched.rank_score,
            "cluster_size": enriched.cluster_size,
            "file_path": original.file_path,
            "line": getattr(original, "line_number", None),
            "title": _safe_title(original),
            "type": getattr(original.type, "value", str(original.type)),
            "text_excerpt": _finding_to_text(original)[:400],
        })
    with open(dump_dir / "_enrichment_clusters.json", "w", encoding="utf-8") as fh:
        _json.dump({
            "total_findings": len(findings),
            "survivors": len(result.findings),
            "duplicates_dropped": len(findings) - len(result.findings),
            "tokens_used": result.tokens_used,
            "entries": entries,
        }, fh, indent=2)


def _wire_finding(fid: str, finding: Finding) -> dict:
    """Build the wire-format dict the gateway expects.

    `type`, `title`, `file_path`, and `severity` are sent as structured
    fields (separate from the embedded `text`) so the gateway can
    pre-group by (type, title, file_path) before dedup and apply
    CRITICAL-exemption from severity.

    Titles are scanner category labels ("US Social Security Number",
    "Email Address", "hardcoded_password") — they contain no PII / no
    secrets. Safe to send unredacted regardless of finding type.
    """
    raw_file_path = getattr(finding, "file_path", None) or None
    # Defense in depth: clamp file_path to the gateway's z.string().max(1024)
    # UTF-16 cap. Deep nested generated code, symlinked vendor trees, or
    # filenames containing non-BMP characters can push a path past 1024
    # UTF-16 units even though the code-point count looks safe.
    file_path = (
        clamp_to_utf16_units(raw_file_path, _MAX_FILE_PATH_UTF16_UNITS)
        if raw_file_path
        else None
    )
    return {
        "id": fid,
        "text": _finding_to_text(finding),
        "type": _enum_value(finding.type) or None,
        "title": _safe_title(finding) or None,
        "file_path": file_path,
        "severity": _enum_value(finding.severity) or None,
    }


def _safe_title(finding: Finding) -> str:
    """Return the finding title as a category label.

    For sensitive types, scanners sometimes interpolate the matched
    value into the title (e.g. "US Social Security Number: 412*6789").
    We strip everything after the first colon so the title is purely
    a category label, suitable to send to the gateway.
    """
    raw = getattr(finding, "title", None)
    if not isinstance(raw, str) or not raw:
        return ""
    if ":" in raw:
        head, _, _ = raw.partition(":")
        return head.strip()
    return raw.strip()


def _finding_to_text(finding: Finding) -> str:
    """Build the text the gateway embeds + reranks for this finding.

    Compact representation: detector + severity + location + title +
    first 1.5KB of description / snippet. Bounded so a noisy scan does
    not blow the gateway's per-finding cap (4000 chars).

    Defense in depth: for SECURITY / PRIVACY finding types, we emit ONLY
    location + type metadata — never the description, snippet, or
    matched-text fields. Even though the privacy-redaction pipeline
    upstream is supposed to have stripped raw secrets, a future scanner
    regression must not silently exfiltrate. The reranker still has
    enough signal (file path + line + type) to prioritize meaningfully.
    """
    parts: list[str] = []
    parts.append(f"file: {finding.file_path}")
    if finding.line_number is not None:
        parts.append(f"line: {finding.line_number}")
    severity = _enum_value(finding.severity)
    if severity:
        parts.append(f"severity: {severity}")
    ftype = _enum_value(finding.type)
    if ftype:
        parts.append(f"type: {ftype}")

    if _is_sensitive_finding_type(ftype):
        # Safe-mode for SECURITY/PRIVACY findings: send the title
        # (it's a category label, scrubbed of any matched value via
        # _safe_title) but NOT the description, snippet, or metadata.
        safe = _safe_title(finding)
        if safe:
            parts.append(f"title: {safe}")
    else:
        if getattr(finding, "title", None):
            parts.append(f"title: {finding.title}")
        if getattr(finding, "description", None):
            parts.append(
                f"description: {clamp_to_utf16_units(finding.description, 1200)}"
            )
        snippet = _extract_snippet(finding)
        if snippet:
            parts.append(f"snippet: {clamp_to_utf16_units(snippet, 300)}")

    text = "\n".join(parts)
    # Final clamp to the gateway's per-finding cap. The cap is in UTF-16
    # code units (Zod `z.string().max(4000)`), so use UTF-16-aware
    # clamping rather than `text[:N]` — a code snippet from i18n test
    # fixtures or docstrings containing emoji / supplementary CJK could
    # otherwise produce a slice whose UTF-16 length exceeds the cap.
    return clamp_to_utf16_units(text, _MAX_TEXT_UTF16_UNITS)


# Finding types whose detail fields commonly contain secrets, PII, or
# other sensitive material that must not leave the user's machine even
# in opaque-embedding form.
#
# Source of truth: the FindingType enum (`models/finding.py`). The
# sensitivity decision is hard-coded against enum members below so a
# NEW FindingType added without updating this map fails a unit test
# (`test_every_finding_type_is_classified`) rather than silently
# defaulting to the non-sensitive code path. Aliases ("secret",
# "credential", etc.) are kept as belt-and-suspenders against
# non-enum strings that might reach this function from a future
# scanner integration.
from brass.models.finding import FindingType

_SENSITIVE_FINDING_TYPES = {
    FindingType.SECURITY,
    FindingType.PRIVACY,
}

# Backward-compat string aliases. Kept so a string that doesn't map to
# any current FindingType enum member can still be classified as
# sensitive if it carries an obviously-sensitive label.
_SENSITIVE_TYPE_ALIASES = {
    "security",
    "privacy",
    "secret",
    "secrets",
    "pii",
    "credential",
    "credentials",
}


def _is_sensitive_finding_type(ftype) -> bool:
    """Decide whether the finding text path should run in safe-mode
    (drops description, snippet, matched-text).

    Accepts either a FindingType enum member or a string. Enum-based
    decision is the source of truth; string fallback handles
    non-enum inputs (rare, from `_enum_value` paths).
    """
    if ftype is None or ftype == "":
        return False
    if isinstance(ftype, FindingType):
        return ftype in _SENSITIVE_FINDING_TYPES
    # String fallback: case-insensitive match against enum values and
    # alias set. Catches both enum-as-string ("security") and any
    # non-enum scanner label that happens to be in the alias set.
    return str(ftype).lower() in _SENSITIVE_TYPE_ALIASES


def _enum_value(v) -> str:
    """Render an enum member's .value, or stringify a plain value."""
    if v is None:
        return ""
    return str(getattr(v, "value", v))


def _extract_snippet(finding: Finding) -> str | None:
    """Pull a code snippet from finding.metadata if present.

    Only called for non-sensitive finding types (see _finding_to_text);
    for sensitive types we never reach here.
    """
    meta = getattr(finding, "metadata", None) or {}
    if not isinstance(meta, dict):
        return None
    for key in ("code_snippet", "snippet", "context_line", "matched_text"):
        v = meta.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None
