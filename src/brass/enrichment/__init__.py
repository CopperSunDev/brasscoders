"""AI enrichment client — calls the BrassCoders API gateway for embed/rerank.

Architecture (post-2C refactor, 2026-05-22):
    brasscoders CLI -> brass-api-gateway -> upstream embedding + rerank service

The gateway validates the license against LemonSqueezy, checks the per-
license quota, builds the project signature server-side from CLI-supplied
raw_files, embeds + dedups + CRITICAL-exempts + reranks + computes
cluster_size, and returns survivors only (sorted by rank_score desc).
The CLI just applies the response (annotates cluster_size on metadata).

Enrichment requires an active paid license, runs after the heuristic
noise filter, and is opt-out via ``--no-enrich``. Network failure or
503 from the gateway falls back to heuristic-only with a warning. 402
(quota exhausted) is a hard fail with a buy-more prompt.

The CLI owns finding-text construction with privacy redaction
(`_finding_to_text` + `_safe_title` in filter.py): findings are
sanitized BEFORE leaving the machine. The gateway never sees raw
secrets/PII even in embed-text form.
"""

from brass.enrichment.client import (
    EnrichmentClient,
    EnrichmentClientError,
    QuotaExhaustedError,
    LicenseRejectedError,
    EnrichmentUnavailableError,
    EnrichmentRateLimitedError,
    EnrichedFinding,
    QuotaState,
)
from brass.enrichment.filter import apply_enrichment
from brass.enrichment.project_signature import (
    gather_raw_files,
    build_project_signature,  # backward-compat alias
)

__all__ = [
    "EnrichmentClient",
    "EnrichmentClientError",
    "QuotaExhaustedError",
    "LicenseRejectedError",
    "EnrichmentUnavailableError",
    "EnrichmentRateLimitedError",
    "EnrichedFinding",
    "QuotaState",
    "apply_enrichment",
    "gather_raw_files",
    "build_project_signature",
]
