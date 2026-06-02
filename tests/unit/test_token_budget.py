"""Unit tests for `brass.enrichment._token_budget`.

Pins the contract between the CLI's chunker and the gateway's
single-source-of-truth token estimator (`gateway/lib/voyage.ts:
estimateChunkTokens`). If either side's formula drifts, these tests
catch it.
"""

from __future__ import annotations

from brass.enrichment._token_budget import (
    MAX_SIGNATURE_TOKENS_WORST_CASE,
    estimate_text_tokens,
    pack_chunks,
    per_finding_cost,
)


# --------------------------------------------------------------------------- #
# estimate_text_tokens                                                        #
# --------------------------------------------------------------------------- #


def test_estimate_text_tokens_matches_chars_div_2_for_ascii():
    """40 ASCII chars → 20 tokens (chars/2). Pins the gateway-mirror
    formula for the common case."""
    assert estimate_text_tokens("a" * 40) == 20


def test_estimate_text_tokens_handles_odd_lengths_via_ceiling():
    """Odd-length input rounds up (ceil division). Pins the ceil
    semantic so 1-char inputs cost 1 token, not 0."""
    assert estimate_text_tokens("x") == 1
    assert estimate_text_tokens("xx") == 1
    assert estimate_text_tokens("xxx") == 2


def test_estimate_text_tokens_empty_string():
    """Empty input costs zero tokens."""
    assert estimate_text_tokens("") == 0


def test_estimate_text_tokens_counts_utf16_units_not_code_points():
    """Non-BMP characters (emoji, supplementary CJK) take TWO UTF-16
    code units each. The gateway's Zod schema and Voyage's tokenizer
    both measure UTF-16, not Python code points — the CLI must match.

    Fixture: 5 distinct non-BMP code points = 10 UTF-16 units = 5 tokens.
    """
    # 🎯 (U+1F3AF), 🏆 (U+1F3C6), 🚀 (U+1F680), 🔧 (U+1F527), 🎺 (U+1F3BA)
    text = "🎯🏆🚀🔧🎺"
    # Each is non-BMP → 2 units; 5 × 2 = 10 units; (10 + 1) // 2 = 5
    assert estimate_text_tokens(text) == 5


def test_estimate_text_tokens_mixed_bmp_and_non_bmp():
    """Mixed input correctly sums per-character UTF-16 units."""
    # 'a' (1 unit) + 🎯 (2 units) + 'b' (1 unit) = 4 units = 2 tokens
    assert estimate_text_tokens("a🎯b") == 2


# --------------------------------------------------------------------------- #
# per_finding_cost                                                            #
# --------------------------------------------------------------------------- #


def test_per_finding_cost_includes_signature_worst_case():
    """Per-finding cost = worst-case signature contribution + text tokens.
    A one-character text contributes 1 text token + MAX_SIGNATURE_TOKENS_WORST_CASE
    of signature overhead."""
    assert per_finding_cost("x") == MAX_SIGNATURE_TOKENS_WORST_CASE + 1


def test_per_finding_cost_empty_text_is_signature_overhead_only():
    """An empty-text finding still costs the signature overhead — the
    gateway re-bills the signature for every finding regardless of
    text content."""
    assert per_finding_cost("") == MAX_SIGNATURE_TOKENS_WORST_CASE


def test_max_signature_tokens_worst_case_matches_gateway_constant():
    """The CLI's worst-case is derived from gateway/lib/project_signature.ts:
    MAX_SIGNATURE_CHARS = 7500. With chars/2 estimator: 7500 // 2 = 3750.

    If gateway changes MAX_SIGNATURE_CHARS without updating this CLI
    constant, the per-pair math diverges and chunks may be sized for
    a stale assumption.
    """
    # Hardcoded literal here (not imported from gateway) because the
    # gateway is a separate TypeScript codebase. The literal pins the
    # cross-codebase contract; a manual diff is the only check we get.
    GATEWAY_MAX_SIGNATURE_CHARS = 7500
    assert MAX_SIGNATURE_TOKENS_WORST_CASE == GATEWAY_MAX_SIGNATURE_CHARS // 2


# --------------------------------------------------------------------------- #
# pack_chunks                                                                 #
# --------------------------------------------------------------------------- #


def test_pack_chunks_empty_input_yields_no_chunks():
    """An empty input produces an empty iterator — no spurious chunk."""
    assert list(pack_chunks([], max_tokens=10_000, max_count=100)) == []


def test_pack_chunks_single_finding_yields_one_chunk():
    """A single finding fits in one chunk regardless of cost."""
    findings = [{"id": "f0", "text": "hello"}]
    chunks = list(pack_chunks(findings, max_tokens=10_000_000, max_count=100))
    assert len(chunks) == 1
    assert chunks[0] == findings


def test_pack_chunks_single_oversize_finding_emitted_alone():
    """If a single finding's `per_finding_cost` already exceeds
    max_tokens, it must still be shipped (alone in its own chunk).
    Never silently drop. The gateway will reject if it's truly too
    big, but the chunker stays correct.
    """
    # A text large enough that per_finding_cost > 5000 (tiny budget)
    huge = "x" * 20_000  # 10K tokens text + 3750 signature = 13_750 tokens
    findings = [{"id": "huge", "text": huge}]
    chunks = list(pack_chunks(findings, max_tokens=5_000, max_count=100))
    assert len(chunks) == 1
    assert len(chunks[0]) == 1
    assert chunks[0][0]["id"] == "huge"


def test_pack_chunks_dense_texts_chunk_by_token_budget_not_count():
    """Many dense-text findings split into multiple chunks via the
    token budget, not the count ceiling. Pins the core invariant of
    token-budget chunking.

    100 findings × 4000-char text each → per-finding cost ≈ 3750
    (signature) + 2000 (text) = 5750. With a 20K token budget per
    chunk: ~3 findings per chunk. So 100 findings → ~33 chunks.
    """
    dense_text = "x" * 4000
    findings = [{"id": f"f{i}", "text": dense_text} for i in range(100)]
    chunks = list(pack_chunks(findings, max_tokens=20_000, max_count=10_000))
    # Token budget is the binding constraint here, not the count cap.
    assert len(chunks) > 10
    # Every chunk's total cost must respect the budget.
    for chunk in chunks:
        chunk_cost = sum(per_finding_cost(f["text"]) for f in chunk)
        assert chunk_cost <= 20_000


def test_pack_chunks_tiny_texts_hit_count_ceiling():
    """When per-finding text cost is tiny, the count ceiling binds
    instead of the token budget."""
    findings = [{"id": f"f{i}", "text": "x"} for i in range(10_000)]
    # Generous token budget so it never binds; count cap binds.
    chunks = list(pack_chunks(findings, max_tokens=10_000_000_000, max_count=3000))
    # 10000 / 3000 = 4 chunks (ceil)
    assert len(chunks) == 4
    # First 3 chunks at the ceiling; last chunk smaller.
    assert all(len(c) == 3000 for c in chunks[:-1])
    assert len(chunks[-1]) == 10_000 - 3 * 3000


def test_pack_chunks_preserves_input_order():
    """Flattening the chunked output reproduces the original input.
    Downstream consumers (the merge step in client.py) rely on this
    for stable ordering."""
    findings = [{"id": f"f{i}", "text": "x" * 100} for i in range(50)]
    chunks = list(pack_chunks(findings, max_tokens=20_000, max_count=10))
    flat = [f for chunk in chunks for f in chunk]
    assert flat == findings


def test_pack_chunks_respects_max_count_when_tighter_than_tokens():
    """The COUNT ceiling fires before the token budget when count is
    the binding constraint. Two tiny findings with max_count=1 → 2
    chunks, even though tokens fit easily."""
    findings = [
        {"id": "f0", "text": "tiny"},
        {"id": "f1", "text": "tiny"},
    ]
    chunks = list(pack_chunks(findings, max_tokens=10_000_000, max_count=1))
    assert len(chunks) == 2
    assert chunks[0] == [findings[0]]
    assert chunks[1] == [findings[1]]


def test_pack_chunks_respects_max_tokens_when_tighter_than_count():
    """The TOKEN budget fires before the count ceiling when tokens
    are the binding constraint."""
    # Two findings; each costs >= 4000 (signature) + small text. Budget
    # of 5000 admits only one per chunk despite generous count cap.
    findings = [
        {"id": "f0", "text": "a"},  # cost ~3751
        {"id": "f1", "text": "a"},  # cost ~3751
    ]
    chunks = list(pack_chunks(findings, max_tokens=5_000, max_count=100))
    assert len(chunks) == 2


def test_pack_chunks_handles_100k_findings_at_realistic_density():
    """Stress test: 100,000 findings at realistic per-finding cost.
    Validates the chunker doesn't blow up at extreme customer scale,
    chunk count tracks the math, and per-chunk caps still hold.

    Per-finding text avg ~500 chars (realistic for finding text
    after _finding_to_text clamping). Cost per finding ≈ 3750
    (signature worst case) + 250 (text chars/2) = 4000.

    With budget 1.5M: max ~375 findings per chunk via tokens.
    With count cap 3000: count never binds at this density.
    100K findings / ~375 per chunk = ~267 chunks expected.
    """
    text = "x" * 500  # realistic per-finding text size after clamping
    findings = [{"id": f"f{i}", "text": text} for i in range(100_000)]

    chunks = list(pack_chunks(
        findings,
        max_tokens=1_500_000,
        max_count=3000,
    ))

    # Chunker completed without crashing. Memory bounded (we'd OOM
    # if pack_chunks built unbounded intermediate state).
    assert chunks, "expected at least one chunk for 100K findings"

    # Every finding is in exactly one chunk.
    flat = [f for chunk in chunks for f in chunk]
    assert len(flat) == 100_000
    assert flat == findings  # order preserved

    # Every chunk respects BOTH caps. This is the load-bearing
    # invariant — if it ever fails, the chunker is broken.
    from brass.enrichment._token_budget import per_finding_cost
    for i, chunk in enumerate(chunks):
        chunk_cost = sum(per_finding_cost(f["text"]) for f in chunk)
        assert chunk_cost <= 1_500_000, (
            f"chunk {i} cost {chunk_cost} exceeds 1.5M budget "
            f"(has {len(chunk)} findings)"
        )
        assert len(chunk) <= 3000, (
            f"chunk {i} has {len(chunk)} findings, exceeds count cap"
        )

    # Sanity-check the chunk count is in the expected ballpark.
    # 100K × ~4000 tokens = ~400M total; ~267 chunks at 1.5M each.
    # Allow ±50% wobble for chars/2 ceiling rounding.
    assert 150 <= len(chunks) <= 400, (
        f"chunk count {len(chunks)} outside expected 150-400 range "
        f"for 100K realistic-density findings"
    )


def test_pack_chunks_handles_pathological_dense_text_at_50k_findings():
    """Pathological stress: 50,000 findings each at the 4000-char
    text cap (worst-case density). Each finding costs ~5750 tokens.
    50K × 5750 = ~287M total. Chunk budget 1.5M → ~260 per chunk
    → ~192 chunks. Validates chunker still emits bounded chunks at
    worst-case density without falling over."""
    from brass.enrichment._token_budget import per_finding_cost
    dense = "x" * 4000  # maximum per-finding text size
    findings = [{"id": f"f{i}", "text": dense} for i in range(50_000)]

    chunks = list(pack_chunks(
        findings,
        max_tokens=1_500_000,
        max_count=3000,
    ))

    # All findings accounted for.
    assert sum(len(c) for c in chunks) == 50_000

    # Every chunk respects token cap (the binding constraint at
    # this density).
    for chunk in chunks:
        chunk_cost = sum(per_finding_cost(f["text"]) for f in chunk)
        assert chunk_cost <= 1_500_000

    # At ~5750 tokens per finding and 1.5M budget, expect ~260
    # findings per chunk → ~192 chunks total. ±30% wobble.
    assert 130 <= len(chunks) <= 300
