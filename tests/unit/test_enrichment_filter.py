"""Tests for the enrichment filter pipeline (post-2C, 2026-05-22).

Post-2C, the gateway owns dedup-survivor selection, CRITICAL-exemption,
rank_score ordering, and cluster_size computation. The CLI side just:
    1. builds the wire payload (with privacy-redacted text)
    2. gathers raw_files (README/manifest/entrypoint/filenames)
    3. calls the gateway
    4. maps survivors back to Finding objects, annotating cluster_size

These tests cover the CLI side. Gateway-side dedup/exemption/ordering
behavior is tested in `gateway/lib/enrich.test.ts`.

The privacy-redaction tests (_finding_to_text, _safe_title, _wire_finding)
remain — that logic stays client-side as defense-in-depth: findings get
sanitized BEFORE leaving the machine, regardless of what the gateway
might do with the data.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from brass.enrichment.filter import apply_enrichment, _finding_to_text
from brass.enrichment.client import EnrichResult, EnrichedFinding
from brass.models.finding import Finding, FindingType, Severity


def _finding(
    file_path: str = "src/x.py",
    line: int = 10,
    severity: Severity = Severity.HIGH,
    title: str = "Test finding",
    description: str = "Description text",
    metadata: dict | None = None,
) -> Finding:
    return Finding(
        id="auto",
        type=FindingType.SECURITY,
        severity=severity,
        file_path=file_path,
        line_number=line,
        title=title,
        description=description,
        metadata=metadata or {},
    )


def _mock_client_returning(enriched: list[EnrichedFinding], tokens_used: int = 100):
    client = MagicMock()
    client.enrich.return_value = EnrichResult(
        findings=enriched,
        tokens_used=tokens_used,
        quota_remaining=4_999_900,
        quota_period_end="2026-06-09T00:00:00Z",
    )
    return client


# --------------------------------------------------------------------------- #
# apply_enrichment — orchestrates the CLI side after 2C                      #
# --------------------------------------------------------------------------- #


def test_apply_enrichment_returns_only_gateway_survivors(tmp_path):
    """Gateway response contains survivors only. CLI keeps exactly those."""
    findings = [_finding(file_path="a.py"), _finding(file_path="b.py"), _finding(file_path="c.py")]
    # Gateway returned 2 survivors (f1 was deduped server-side); ordered by score.
    client = _mock_client_returning(
        [
            EnrichedFinding(id="f0", rank_score=0.9, cluster_size=2),  # absorbed f1
            EnrichedFinding(id="f2", rank_score=0.5, cluster_size=1),
        ]
    )

    out, report = apply_enrichment(findings, str(tmp_path), client)

    assert len(out) == 2
    # Gateway's order preserved: f0 (0.9), f2 (0.5)
    assert out[0].file_path == "a.py"
    assert out[1].file_path == "c.py"
    assert report.input_count == 3
    assert report.output_count == 2
    assert report.duplicates_dropped == 1
    assert report.tokens_used == 100


def test_cluster_size_stamped_on_survivor_metadata(tmp_path):
    """Gateway sends cluster_size; CLI stamps it on the surviving Finding."""
    findings = [_finding(file_path="a.py"), _finding(file_path="b.py")]
    client = _mock_client_returning(
        [EnrichedFinding(id="f0", rank_score=0.9, cluster_size=2)]
    )
    out, _ = apply_enrichment(findings, str(tmp_path), client)
    assert len(out) == 1
    assert out[0].metadata["cluster_size"] == 2


def test_cluster_size_absent_when_lone_survivor(tmp_path):
    """A survivor with cluster_size=1 (no absorbed dups) does NOT get a
    cluster_size key — keeps the typical-case output uncluttered."""
    findings = [_finding(file_path="a.py")]
    client = _mock_client_returning(
        [EnrichedFinding(id="f0", rank_score=0.9, cluster_size=1)]
    )
    out, _ = apply_enrichment(findings, str(tmp_path), client)
    assert len(out) == 1
    assert "cluster_size" not in out[0].metadata


def test_cluster_size_independent_per_survivor(tmp_path):
    """Two separate clusters → each carries its own count."""
    findings = [_finding(file_path=f"f{i}.py") for i in range(5)]
    client = _mock_client_returning(
        [
            EnrichedFinding(id="f0", rank_score=0.9, cluster_size=3),
            EnrichedFinding(id="f3", rank_score=0.8, cluster_size=2),
        ]
    )
    out, _ = apply_enrichment(findings, str(tmp_path), client)
    survivor_clusters = {o.file_path: o.metadata.get("cluster_size") for o in out}
    assert survivor_clusters["f0.py"] == 3
    assert survivor_clusters["f3.py"] == 2


def test_apply_enrichment_does_not_mutate_input_findings(tmp_path):
    """The cluster_size annotation goes on a NEW Finding (via
    dataclasses.replace); input findings are untouched."""
    findings = [_finding(file_path="a.py"), _finding(file_path="b.py")]
    input_metadata_refs = [f.metadata for f in findings]
    client = _mock_client_returning(
        [EnrichedFinding(id="f0", rank_score=0.9, cluster_size=2)]
    )
    out, _ = apply_enrichment(findings, str(tmp_path), client)
    assert out[0].metadata["cluster_size"] == 2
    # Input findings unchanged
    assert "cluster_size" not in findings[0].metadata
    assert findings[0].metadata is input_metadata_refs[0]
    assert findings[1].metadata is input_metadata_refs[1]


def test_apply_enrichment_preserves_gateway_order(tmp_path):
    """Gateway returns sorted by rank_score desc. CLI keeps that order."""
    findings = [_finding(file_path=f"f{i}.py") for i in range(4)]
    # Gateway pre-sorted these in this specific order:
    client = _mock_client_returning([
        EnrichedFinding(id="f2", rank_score=0.95, cluster_size=1),
        EnrichedFinding(id="f0", rank_score=0.80, cluster_size=1),
        EnrichedFinding(id="f3", rank_score=0.60, cluster_size=1),
        EnrichedFinding(id="f1", rank_score=0.40, cluster_size=1),
    ])
    out, _ = apply_enrichment(findings, str(tmp_path), client)
    assert [f.file_path for f in out] == ["f2.py", "f0.py", "f3.py", "f1.py"]


def test_apply_enrichment_sends_findings_and_raw_files(tmp_path):
    """The CLI passes findings with structured fields + raw_files dict
    to the gateway client. Both are needed for server-side processing."""
    findings = [_finding(file_path="alpha.py"), _finding(file_path="beta.py")]
    client = _mock_client_returning([
        EnrichedFinding(id="f0", rank_score=1.0, cluster_size=1),
        EnrichedFinding(id="f1", rank_score=0.5, cluster_size=1),
    ])

    apply_enrichment(findings, str(tmp_path), client)

    payload, raw_files = client.enrich.call_args.args
    payload = list(payload)
    # Each finding is a dict with id/text + structured fields the gateway
    # needs for pre-grouping and CRITICAL-exemption.
    assert payload[0]["id"] == "f0"
    assert payload[1]["id"] == "f1"
    assert "alpha.py" in payload[0]["text"]
    assert "beta.py" in payload[1]["text"]
    # Type travels for gateway bucketing.
    assert payload[0]["type"] == "security"
    # Severity travels for gateway CRITICAL-exemption (when present).
    assert payload[0]["severity"] == "high"
    # raw_files is a dict (not a pre-built signature string anymore).
    assert isinstance(raw_files, dict)


def test_apply_enrichment_logs_warning_on_unknown_gateway_id(tmp_path, caplog):
    """If the gateway returns an id that doesn't match any input
    finding (shouldn't happen — defensive), log and skip the entry."""
    findings = [_finding(file_path="a.py")]
    client = _mock_client_returning(
        [
            EnrichedFinding(id="f0", rank_score=0.9, cluster_size=1),
            EnrichedFinding(id="f99", rank_score=0.5, cluster_size=1),  # bogus
        ]
    )
    with caplog.at_level("WARNING", logger="brass.enrichment.filter"):
        out, _ = apply_enrichment(findings, str(tmp_path), client)
    # Only the real survivor makes it through
    assert len(out) == 1
    assert out[0].file_path == "a.py"
    # Warning was logged for f99
    assert any("unknown id" in r.message.lower() for r in caplog.records)


def test_apply_enrichment_empty_input_returns_empty_without_calling_gateway(tmp_path):
    client = MagicMock()
    out, report = apply_enrichment([], str(tmp_path), client)
    assert out == []
    assert report.input_count == 0
    client.enrich.assert_not_called()


# --------------------------------------------------------------------------- #
# _finding_to_text — privacy-redacting text builder (stays client-side)      #
# --------------------------------------------------------------------------- #


def test_finding_to_text_includes_file_line_severity_and_title():
    """Title + description pass through for non-sensitive finding types
    (CODE_QUALITY, ARCHITECTURE, etc.). Sensitive types are tested
    below — they go through the safe-mode redaction path."""
    f = _finding(
        file_path="src/auth.py",
        line=42,
        severity=Severity.CRITICAL,
        title="N+1 query in user-listing endpoint",
        description="loop over users issues one query per row",
    )
    f.type = FindingType.CODE_QUALITY
    text = _finding_to_text(f)
    assert "src/auth.py" in text
    assert "42" in text
    assert "critical" in text.lower()
    assert "N+1 query" in text
    assert "loop over users" in text


def test_finding_to_text_clamps_overlong_descriptions():
    huge = "X" * 50_000
    f = _finding(description=huge)
    f.type = FindingType.CODE_QUALITY
    text = _finding_to_text(f)
    assert len(text) <= 3800


def test_finding_to_text_pulls_snippet_from_metadata_for_non_sensitive_types():
    f = _finding(
        metadata={"code_snippet": "cursor.execute(f'...{user}...')"},
    )
    f.type = FindingType.CODE_QUALITY
    text = _finding_to_text(f)
    assert "snippet:" in text
    assert "cursor.execute" in text


def test_finding_to_text_drops_description_and_snippet_for_security_findings():
    """H2 defense in depth: never embed description, snippet, or
    matched-text fields for sensitive finding types. The TITLE (a
    category label) IS allowed through after C.7.6 — it's what lets the
    gateway pre-group findings by (type, title)."""
    f = _finding(
        title="AWS access key in source",
        description="Found AKIAFAKEFAKEFAKE in cursor.execute(...)",
        metadata={"code_snippet": "AWS_KEY = 'AKIAFAKEFAKEFAKE'"},
    )
    f.type = FindingType.SECURITY
    text = _finding_to_text(f)
    assert "AKIAFAKEFAKEFAKE" not in text
    assert "cursor.execute" not in text
    assert "src/x.py" in text
    assert "security" in text.lower()
    assert "AWS access key in source" in text


def test_safe_title_strips_value_after_colon():
    """Some scanners interpolate the matched value into the title
    (e.g. "US Social Security Number: 412*6789"). Strip it."""
    from brass.enrichment.filter import _safe_title
    f = _finding(title="US Social Security Number: 412*6789")
    assert _safe_title(f) == "US Social Security Number"


def test_wire_finding_includes_structured_fields_for_gateway():
    """Gateway pre-groups by (type, title, file_path) and applies
    CRITICAL-exemption from severity. All four structured fields
    must travel on the wire."""
    from brass.enrichment.filter import _wire_finding
    f = _finding(title="US Social Security Number: 412*6789", severity=Severity.CRITICAL)
    f.type = FindingType.PRIVACY
    wire = _wire_finding("f0", f)
    assert wire["id"] == "f0"
    assert wire["type"] == "privacy"
    assert wire["title"] == "US Social Security Number"
    assert wire["file_path"] == "src/x.py"
    assert wire["severity"] == "critical"
    assert "412*6789" not in wire["title"]
    assert "412*6789" not in wire["text"]


def test_finding_to_text_drops_sensitive_data_for_privacy_type():
    f = _finding(
        title="Email in log message",
        description="user@example.com appears in log line",
    )
    f.type = FindingType.PRIVACY
    text = _finding_to_text(f)
    assert "user@example.com" not in text
    assert "src/x.py" in text


# --------------------------------------------------------------------------- #
# UTF-16 boundary regressions — caught 2026-05-25 in audit                   #
# --------------------------------------------------------------------------- #


def test_finding_to_text_respects_utf16_cap_under_emoji_content():
    """`_finding_to_text`'s final clamp must produce a string whose
    UTF-16 code-unit length is ≤ 4000 (the gateway's
    z.string().max(4000) cap). Description content with emoji /
    supplementary CJK could otherwise produce a slice whose UTF-16
    length exceeds the cap even though the Python code-point count
    looks safe. Mirrors the whisperx-production raw_files.readme bug,
    one layer up the pipeline."""
    # 1900 ASCII chars + 100 emoji in description = 2000 code points,
    # 2100 UTF-16 units in the description alone. Plus the
    # file/severity/type/title headers, easily pushes total UTF-16
    # past 4000 if the clamp isn't unit-aware.
    huge_desc = ("A" * 1900) + ("🎯" * 100)
    f = _finding(description=huge_desc)
    f.type = FindingType.CODE_QUALITY  # non-sensitive so description passes through
    text = _finding_to_text(f)
    # UTF-16 code-unit length (what Zod measures) must be ≤ 4000.
    utf16_units = sum(2 if ord(c) > 0xFFFF else 1 for c in text)
    assert utf16_units <= 4000, (
        f"UTF-16 length {utf16_units} exceeds gateway cap 4000 — "
        f"gateway will 400 on this finding"
    )


def test_wire_finding_clamps_file_path_to_utf16_cap():
    """`_wire_finding` must clamp `file_path` to the gateway's
    z.string().max(1024) UTF-16 cap, not just pass through whatever
    the scanner emitted. Defense in depth against pathological scanner
    outputs from deep generated trees, symlinks, or non-BMP filenames."""
    from brass.enrichment.filter import _wire_finding
    # 900 ASCII path chars + 100 emoji = 1000 code points,
    # 1100 UTF-16 units. Under 1024 by code points but OVER by UTF-16.
    f = _finding(file_path=("A" * 900) + ("🎯" * 100))
    wire = _wire_finding("f0", f)
    fp = wire["file_path"]
    utf16_units = sum(2 if ord(c) > 0xFFFF else 1 for c in fp)
    assert utf16_units <= 1024, (
        f"file_path UTF-16 length {utf16_units} exceeds gateway cap 1024"
    )


# --------------------------------------------------------------------------- #
# Sensitivity-classification regression guard (fix 8 from /full-bugs review) #
# --------------------------------------------------------------------------- #


def test_every_finding_type_is_explicitly_classified():
    """Forcing every FindingType enum member through the sensitivity
    classifier protects against a future enum member being added
    without a deliberate decision about whether its detail fields can
    leave the customer's machine. If this test fails after adding a
    new FindingType, the contributor must either add the new type to
    `_SENSITIVE_FINDING_TYPES` in filter.py (if it contains secrets/PII)
    or update this test's expectation set (if it doesn't)."""
    from brass.enrichment.filter import _is_sensitive_finding_type

    expected_sensitive = {FindingType.SECURITY, FindingType.PRIVACY}

    for ft in FindingType:
        actual_sensitive = _is_sensitive_finding_type(ft)
        expected = ft in expected_sensitive
        assert actual_sensitive == expected, (
            f"FindingType.{ft.name} classified as "
            f"{'sensitive' if actual_sensitive else 'non-sensitive'}, "
            f"expected {'sensitive' if expected else 'non-sensitive'}. "
            f"Update filter._SENSITIVE_FINDING_TYPES or this test."
        )


def test_sensitivity_classifier_accepts_string_aliases():
    """String-fallback path: non-enum scanner labels that match the
    alias set still get safe-mode treatment."""
    from brass.enrichment.filter import _is_sensitive_finding_type
    assert _is_sensitive_finding_type("security") is True
    assert _is_sensitive_finding_type("privacy") is True
    assert _is_sensitive_finding_type("SECRET") is True  # case-insensitive
    assert _is_sensitive_finding_type("credentials") is True
    assert _is_sensitive_finding_type("code_quality") is False
    assert _is_sensitive_finding_type("") is False
    assert _is_sensitive_finding_type(None) is False
