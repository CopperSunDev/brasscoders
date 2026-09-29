"""Enrichment outcome of one ``brasscoders scan``, surfaced in ai_instructions.yaml.

The CLI orchestrator records exactly one of these modes per scan (on
``BrassCLI._enrichment_mode``) and threads it into the YAML output
pipeline as ``metadata.enrichment.mode``. Five closed values:

- ``enriched``                 — the Paid AI enrichment pass (semantic
                                 dedup + reranking) ran and its result
                                 is what the YAML files contain.
- ``heuristic_no_license``     — no active license on this machine;
                                 the local noise-reduction pass is the
                                 final filter. The default for free
                                 installs.
- ``heuristic_no_enrich_flag`` — the user passed ``--no-enrich``; a
                                 deliberate opt-out.
- ``heuristic_fallback``       — a licensed scan attempted enrichment
                                 and soft-failed (gateway unavailable,
                                 rate-limited, client error); the CLI
                                 fell back to heuristic results for the
                                 ENTIRE scan (never partial).
- ``heuristic_offline``        — ``--offline`` / ``BRASS_OFFLINE=1``;
                                 nothing network-shaped is constructed.

Why a dedicated leaf module (mirrors ``core/scanner_status.py``): the
output layer needs to read the mode but must NOT import
``brass.enrichment``, which pulls ``requests`` at import time. This
module has zero dependencies so both the CLI and output layers can
import it freely.

Heuristic-only scans are complete as shown — the Paid pass is
additive, not a repair. Every ``heuristic_*`` mode also implies that
per-finding ``cluster_size`` is absent (it is produced by the
enrichment pass).
"""

from __future__ import annotations

from typing import Optional


ENRICHED = "enriched"
HEURISTIC_NO_LICENSE = "heuristic_no_license"
HEURISTIC_NO_ENRICH_FLAG = "heuristic_no_enrich_flag"
HEURISTIC_FALLBACK = "heuristic_fallback"
HEURISTIC_OFFLINE = "heuristic_offline"

ALL_MODES = frozenset({
    ENRICHED,
    HEURISTIC_NO_LICENSE,
    HEURISTIC_NO_ENRICH_FLAG,
    HEURISTIC_FALLBACK,
    HEURISTIC_OFFLINE,
})


def is_enriched(mode: Optional[str]) -> bool:
    """True only for the ``enriched`` mode; ``None`` and every
    ``heuristic_*`` value are False."""
    return mode == ENRICHED


__all__ = [
    "ENRICHED",
    "HEURISTIC_NO_LICENSE",
    "HEURISTIC_NO_ENRICH_FLAG",
    "HEURISTIC_FALLBACK",
    "HEURISTIC_OFFLINE",
    "ALL_MODES",
    "is_enriched",
]
