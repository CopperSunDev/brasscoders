"""Token-budget chunking for the enrichment wire.

The gateway bills `/api/enrich` per (query, doc) pair:

    num_docs × query_tokens + sum(doc_tokens)

where `query_tokens` is the project_signature paid once per finding,
and `doc_tokens` is the per-finding text. The CLI must chunk findings
so that no single chunk exceeds the gateway's per-request capacity OR
saturates the customer's hourly token budget.

This module mirrors the gateway's single source of truth — the
chars/2 estimator in `gateway/lib/voyage.ts:estimateChunkTokens` — so
the CLI's chunking math agrees with the gateway's billing math. If the
gateway's estimator changes, this file MUST change in lockstep.

Why a separate module from `_wire_clamp.py`? UTF-16 clamping is about
wire-format correctness (Zod's `z.string().max(N)` measures code
units). Token estimation is about cost modeling. Both happen to count
UTF-16 units, but they answer different questions; keeping them
separate makes future changes to either one safe.
"""

from __future__ import annotations

from typing import Iterator


# Worst-case signature token contribution per finding. The gateway
# composes a project_signature server-side from the CLI's `raw_files`
# dict, then clamps to `MAX_SIGNATURE_CHARS = 7500` (see
# `gateway/lib/project_signature.ts`). chars/2 of that is the upper
# bound on per-finding query-token overhead.
#
# We use the worst case (not an estimate of the actual composed
# signature) because:
#   1. The CLI doesn't know the algorithm the gateway uses to compose
#      the signature — that lives in closed code.
#   2. A chunk sized against an under-estimate would risk 429 / 400
#      at the gateway. A chunk sized against the worst case is always
#      safe to ship; the cost is slightly smaller chunks than optimal.
MAX_SIGNATURE_TOKENS_WORST_CASE = 3750


def estimate_text_tokens(text: str) -> int:
    """Estimate the Voyage token count for a single text.

    Mirrors `gateway/lib/voyage.ts:estimateChunkTokens` exactly:
    UTF-16 code-unit length // 2 (with ceiling for odd lengths).

    Calibrated against the 2026-05-25 whisperx-production scan:
    real:estimate ratio ≈ 1.2-1.4x (estimator under-counts by ~25%).
    Compensated server-side via `RERANK_BATCH_MAX_TOKENS` and
    `EMBED_BATCH_MAX_TOKENS` sized at ~60% of Voyage's hard caps.

    Counts UTF-16 units rather than Python code points because the
    gateway's Zod schema validates `z.string().max(N)` in UTF-16 units
    — and Voyage's tokenizer behavior is closer to chars/2 of the
    UTF-16 representation than the code-point count for non-BMP text
    (CJK, emoji).
    """
    utf16_units = 0
    for c in text:
        utf16_units += 2 if ord(c) > 0xFFFF else 1
    return (utf16_units + 1) // 2  # ceil(units / 2)


def per_finding_cost(text: str) -> int:
    """Estimated per-pair cost contributed by a single finding.

    Matches the gateway's billing formula:
      cost = query_tokens (paid per finding) + doc_tokens (per text)
           = MAX_SIGNATURE_TOKENS_WORST_CASE + estimate_text_tokens(text)
    """
    return MAX_SIGNATURE_TOKENS_WORST_CASE + estimate_text_tokens(text)


def pack_chunks(
    findings: list[dict],
    max_tokens: int,
    max_count: int,
) -> Iterator[list[dict]]:
    """Greedy single-pass packer.

    Yields chunks of `findings` such that each chunk satisfies:
      sum(per_finding_cost(f["text"]) for f in chunk) <= max_tokens
      len(chunk) <= max_count

    Preserves input order: flattening the output reproduces `findings`.

    Edge case — a single finding whose `per_finding_cost` exceeds
    `max_tokens` is emitted ALONE in its own chunk. We never silently
    drop findings; if the upstream wire-format builder failed to clamp
    a text below the per-pair limit, the chunker still ships it (the
    gateway may then reject the chunk, which is a defensive failure
    mode loud enough to detect — never a silent miss).
    """
    chunk: list[dict] = []
    chunk_tokens = 0
    for finding in findings:
        cost = per_finding_cost(finding.get("text", ""))
        # Would adding this finding exceed either budget?
        would_exceed_tokens = chunk and chunk_tokens + cost > max_tokens
        would_exceed_count = len(chunk) >= max_count
        if would_exceed_tokens or would_exceed_count:
            yield chunk
            chunk = []
            chunk_tokens = 0
        chunk.append(finding)
        chunk_tokens += cost
    if chunk:
        yield chunk
