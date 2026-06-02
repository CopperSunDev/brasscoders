"""HTTPS client for the BrassCoders API gateway.

The gateway exposes three endpoints:
    GET  /api/health
    POST /api/enrich   (license_key + findings -> enriched findings)
    GET  /api/quota    (current quota state for a license)

This module wraps the two BrassCoders-side endpoints (enrich + quota) and maps
the gateway's HTTP status codes to typed Python exceptions so callers
can branch on outcome cleanly.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Iterable

import requests

from ._token_budget import pack_chunks

logger = logging.getLogger(__name__)

# Transient-failure retry policy. One retry only — see docstring on
# `_post_enrich` for the reasoning (no exponential backoff, predictable
# wall-clock cost, heuristic fallback already produces a valid scan).
_TRANSIENT_RETRY_COUNT = 1
_TRANSIENT_RETRY_DELAY_SECONDS = 2.0

# Voyage 429 retry policy. Different code path from transient failures
# above because the gateway's per-license hourly cap was removed
# 2026-05-27 — every 429 now is Voyage's actual commercial rate limit
# (TPM / RPM at their tier).
#
# Wait math: `max(voyage_retry_after_ms, MIN_WAIT)` capped at MAX_WAIT.
#
# Voyage's `retry_after_ms` is a HINT, not a guarantee — it means "you
# can try again" but doesn't promise the rate-limit window has cleared.
# The 2026-05-27 coppersun_brass v3 scan saw Voyage return retry-after
# = 7s; the CLI honored it, retried, and got 429 again because Voyage's
# TPM is a sliding 60-second window that 7 seconds doesn't clear.
#
# `_VOYAGE_429_MIN_RETRY_WAIT_SECONDS` guarantees a full TPM window
# elapses before the retry. `_VOYAGE_429_MAX_RETRY_WAIT_SECONDS` caps
# pathological retry-afters so a single chunk can't hang the scan
# indefinitely. If Voyage explicitly asks for longer than the max, the
# CLI falls back to heuristic (real outage territory, not transient
# rate-limit).
#
# When this fires repeatedly in real customer usage, it's a signal to
# upgrade the Voyage commercial tier; see
# cli/docs/perf/2026-05-27_voyage_rate_limit_followup.md.
_VOYAGE_429_MIN_RETRY_WAIT_SECONDS = 60.0
_VOYAGE_429_MAX_RETRY_WAIT_SECONDS = 120.0


# Production gateway. Override with BRASS_GATEWAY_URL for staging/dev.
DEFAULT_GATEWAY_URL = "https://brass-api-gateway.vercel.app"
# (connect_timeout, read_timeout) tuple. Connect should be quick — a long
# wait there is a DNS/TLS misconfig, not a slow upstream.
HTTP_TIMEOUT = (10.0, 60.0)
# Maximum response payload we'll ingest. Even a fully-loaded enrich response
# (~3000 findings × small JSON object) is well under this. Anything bigger
# is either a buggy gateway or a malicious response and we refuse it.
MAX_RESPONSE_BYTES = 8 * 1024 * 1024  # 8 MiB
USER_AGENT = "brasscoders/enrichment-client"

# Per-chunk token budget for token-aware chunking. The CLI's chunker
# (`_token_budget.pack_chunks`) packs findings into chunks until the
# sum of `per_finding_cost(f.text)` would exceed this budget. Sized
# so that even worst-case cold-cache scans complete within the
# gateway's Vercel `maxDuration=60s` ceiling — the gateway has to
# embed every uncached text against Voyage, and at 100% cache miss
# the embed phase dominates per-chunk wall-clock.
#
# Calibration history:
#   2.5M (initial, 2026-05-27): sized against warm-cache wall-clock
#     where embed mostly hit the cache. The whisperx-shape scan
#     (~1K findings, mixed density) finished in ~10-15s gateway
#     time at that budget.
#   1.5M (2026-05-27 same-day): frankenproject v2 stress scan with
#     COLD cache (after Upstash cleanup wiped all embed_cache:*)
#     showed that uncached chunks of ~1000 findings exceeded the
#     gateway's per-Voyage-call HTTP_TIMEOUT_MS of 30s. Reducing
#     chunk size by ~40% halves the per-chunk embed work, keeping
#     cold-cache scans within the 60s function budget. Trade-off:
#     more sequential POSTs per scan, but each chunk completes
#     reliably.
#
# At worst-case density (~5750 tokens per finding via 3750 sig +
# 2000 text), 1.5M budget admits ~260 findings per chunk. At typical
# density (~2000 tokens per finding), ~750 findings per chunk.
_MAX_TOKENS_PER_CHUNK = 1_500_000

# Gateway's EnrichRequestSchema caps `findings` at 3000 per request
# (Zod ``z.array(FindingSchema).max(3000)`` in lib/schema.ts). Used as
# a hard ceiling — not a soft target — so the count cap binds only on
# very-low-density scans where the token budget is generous.
_MAX_FINDINGS_PER_CHUNK = 3000


@dataclass
class EnrichedFinding:
    id: str
    rank_score: float
    cluster_size: int


@dataclass
class EnrichResult:
    """Server-decided enrichment result.

    `findings` contains ONLY survivors, pre-sorted by rank_score desc.
    Dropped findings are implicit (not in the response). cluster_size
    tells the CLI how many siblings each survivor represents.
    """
    findings: list[EnrichedFinding]
    tokens_used: int
    quota_remaining: int
    quota_period_end: str


@dataclass
class QuotaState:
    monthly_remaining: int
    topup_remaining: int
    total_remaining: int
    monthly_limit: int
    period_start: str
    period_end: str
    total_used_lifetime: int


# --- Exceptions --------------------------------------------------------------


class EnrichmentClientError(Exception):
    """Base for all enrichment-client failures."""


class LicenseRejectedError(EnrichmentClientError):
    """401 / 403 — the license is not valid for enrichment.

    Hard fail: the caller's license is not in a state where BrassCoders can
    enrich. They need to re-activate, renew, or contact support. This is
    distinct from "no license at all" (which the CLI handles upstream
    by not attempting enrichment in the first place).
    """


class QuotaExhaustedError(EnrichmentClientError):
    """402 — out of enrichment tokens for the current billing period."""

    def __init__(
        self,
        message: str,
        tokens_needed: int = 0,
        tokens_remaining: int = 0,
        quota_period_end: str = "",
        topup_url: str = "",
    ):
        super().__init__(message)
        self.tokens_needed = tokens_needed
        self.tokens_remaining = tokens_remaining
        self.quota_period_end = quota_period_end
        self.topup_url = topup_url


class EnrichmentRateLimitedError(EnrichmentClientError):
    """429 — per-license rate limit hit at the gateway.

    Soft fail: caller should fall back to heuristic-only with a warning.
    The cap exists to mitigate runaway-CLI scenarios; legitimate users
    should never see it.
    """

    def __init__(self, message: str, retry_after_ms: int = 60_000):
        super().__init__(message)
        self.retry_after_ms = retry_after_ms


class EnrichmentUnavailableError(EnrichmentClientError):
    """503 / 5xx / network failure — gateway or upstream is down.

    Soft fail: caller should fall back to heuristic-only with a warning.
    """


# --- Client ------------------------------------------------------------------


@dataclass
class EnrichmentClient:
    license_key: str
    instance_id: str
    gateway_url: str = field(default_factory=lambda: os.environ.get("BRASS_GATEWAY_URL", DEFAULT_GATEWAY_URL))

    def enrich(
        self,
        findings,
        raw_files: dict,
        rerank_top_n: int = 200,
        dedup_threshold: float = 0.85,
    ) -> EnrichResult:
        """Send findings + raw_files to the gateway and parse the enriched response.

        ``findings`` is an iterable of dicts with keys ``id``, ``text``,
        and optional ``type``, ``title``, ``file_path``, ``severity``.

        ``raw_files`` is the dict returned by
        ``project_signature.gather_raw_files`` — README/manifest/
        entrypoint/filenames chunks (each independently optional, all
        size-capped client-side).

        Response contains SURVIVORS ONLY (dropped findings implicit),
        pre-sorted by rank_score desc, with cluster_size per finding.

        Chunking: findings are packed into chunks by the token-aware
        chunker in ``_token_budget.pack_chunks``. Each chunk has a
        bounded per-pair token cost (mirroring the gateway's billing
        formula `num_docs × signature_tokens + sum(doc_tokens)`) and a
        bounded count (≤ gateway schema cap). This makes per-chunk
        wall-clock predictable across both short-text and dense-text
        scans — variance was the original motivation for moving off
        count-based chunking.

        Each chunk goes through the existing retry + error path. If
        any chunk hard-fails, the whole call fails (caller falls back
        to heuristic-only output for the entire scan — no partial
        enrichment).

        Aggregation: results are merged across chunks, then re-sorted
        globally by rank_score desc. tokens_used sums; quota_remaining
        takes the latest value (server-side monotonically decreases).
        """
        finding_list = [_normalize_finding(f) for f in findings]
        chunks = list(pack_chunks(
            finding_list,
            max_tokens=_MAX_TOKENS_PER_CHUNK,
            max_count=_MAX_FINDINGS_PER_CHUNK,
        ))

        if len(chunks) <= 1:
            # Fast path: zero findings → empty result, no HTTP call.
            # One chunk → single POST, no merge/sort overhead.
            if not chunks:
                return EnrichResult(
                    findings=[],
                    tokens_used=0,
                    quota_remaining=0,
                    quota_period_end="",
                )
            single_chunk = chunks[0]
            request_body = {
                "license_key": self.license_key,
                "instance_id": self.instance_id,
                "raw_files": raw_files,
                "findings": single_chunk,
                "options": {
                    "rerank_top_n": rerank_top_n,
                    "dedup_threshold": dedup_threshold,
                },
            }
            return self._post_enrich(
                request_body, expected_count=len(single_chunk),
            )

        # Chunked path: iterate token-budget-packed chunks. Each batch
        # is a separate POST + retry cycle. If any chunk hard-fails,
        # the whole call fails (caller falls back to heuristic-only
        # output for the entire scan).
        merged_findings: list[EnrichedFinding] = []
        total_tokens_used = 0
        latest_quota_remaining = 0
        latest_quota_period_end = ""
        for chunk in chunks:
            chunk_body = {
                "license_key": self.license_key,
                "instance_id": self.instance_id,
                "raw_files": raw_files,
                "findings": chunk,
                "options": {
                    "rerank_top_n": rerank_top_n,
                    "dedup_threshold": dedup_threshold,
                },
            }
            chunk_result = self._post_enrich(
                chunk_body, expected_count=len(chunk),
            )
            merged_findings.extend(chunk_result.findings)
            total_tokens_used += chunk_result.tokens_used
            latest_quota_remaining = chunk_result.quota_remaining
            latest_quota_period_end = chunk_result.quota_period_end
        # Each chunk arrives sorted by rank_score desc, but concatenation
        # of N sorted lists is NOT globally sorted. Downstream consumers
        # (ai_instructions builder) iterate in input order to honor the
        # gateway's ranking, so the merged list must be re-sorted to
        # preserve that invariant across chunk boundaries.
        merged_findings.sort(key=lambda f: f.rank_score, reverse=True)
        return EnrichResult(
            findings=merged_findings,
            tokens_used=total_tokens_used,
            quota_remaining=latest_quota_remaining,
            quota_period_end=latest_quota_period_end,
        )

    def quota(self) -> QuotaState:
        """Fetch current quota state for the active license.

        License credentials go in headers, not query params, so a network
        failure's URL-bearing exception message can't leak the key into
        scrollback / CI logs / support tickets.
        """
        try:
            response = requests.get(
                f"{self.gateway_url}/api/quota",
                timeout=HTTP_TIMEOUT,
                headers=self._auth_headers(),
            )
        except (requests.RequestException, OSError) as exc:
            raise EnrichmentUnavailableError(_redact_exc(exc)) from exc

        self._raise_for_status(response, op="quota")
        response_body = self._parse_json(response)
        return QuotaState(
            monthly_remaining=_safe_int(response_body.get("monthly_remaining")),
            topup_remaining=_safe_int(response_body.get("topup_remaining")),
            total_remaining=_safe_int(response_body.get("total_remaining")),
            monthly_limit=_safe_int(response_body.get("monthly_limit")),
            period_start=str(response_body.get("period_start") or ""),
            period_end=str(response_body.get("period_end") or ""),
            total_used_lifetime=_safe_int(response_body.get("total_used_lifetime")),
        )

    def portal(self) -> str:
        """Fetch the LemonSqueezy customer portal URL for the active license.

        The CLI `portal` subcommand opens this URL in the user's browser
        so they can manage their subscription, update card, view invoices,
        cancel, etc. — all on LS's hosted billing portal.

        Same credential-handling discipline as quota(): headers, not URL.

        Returns:
            The portal URL string.

        Raises:
            LicenseRejectedError: 401/403 from gateway — license invalid
                or expired/revoked.
            EnrichmentUnavailableError: 404, 5xx, or network failure.
        """
        try:
            response = requests.get(
                f"{self.gateway_url}/api/portal",
                timeout=HTTP_TIMEOUT,
                headers=self._auth_headers(),
            )
        except (requests.RequestException, OSError) as exc:
            raise EnrichmentUnavailableError(_redact_exc(exc)) from exc

        self._raise_for_status(response, op="portal")
        response_body = self._parse_json(response)
        portal_url = response_body.get("portal_url")
        if not isinstance(portal_url, str) or not portal_url:
            raise EnrichmentUnavailableError(
                "gateway returned no portal_url in /api/portal response"
            )
        return portal_url

    # --- internals --------------------------------------------------------

    def _auth_headers(self) -> dict:
        return {
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
            # Gateway also accepts these in the body for /enrich; we still
            # send them in the body there for backward compat. For /quota
            # they go ONLY in headers so they're not in the URL.
            "X-BrassCoders-License-Key": self.license_key,
            "X-BrassCoders-Instance-Id": self.instance_id,
        }

    def _post_enrich(self, request_body: dict, expected_count: int) -> EnrichResult:
        """Send the enrich request with bounded retry on transient failure.

        Two retry paths, each at most ONE retry:

        1. :class:`EnrichmentUnavailableError` (network blip, 502/503/504,
           malformed gateway response) → fixed-delay retry after
           `_TRANSIENT_RETRY_DELAY_SECONDS`.

        2. :class:`EnrichmentRateLimitedError` from Voyage's commercial
           rate limit (every 429 since 2026-05-27 is Voyage's, not
           ours — our hourly cap was removed). Honor Voyage's
           `retry_after_ms` as the wait source-of-truth, capped at
           `_VOYAGE_429_MAX_RETRY_WAIT_SECONDS` so a pathological
           retry-after can't block the scan indefinitely.

        Does NOT retry: quota-exhausted (402), license-rejected
        (401/403), or successful-but-malformed-payload cases. Those
        are deterministic — re-trying won't change the outcome.

        Why bounded retry: brass's enrichment is a single batch call
        per scan, not a stream of independent operations. A real
        gateway / upstream outage means every attempt fails — no value
        in more than one retry. The all-or-nothing fallback contract
        (see brass_cli.py caller) means a second retry would just
        delay the fallback by another N seconds without changing the
        outcome.
        """
        attempt = 0
        while True:
            try:
                return self._attempt_post_enrich(request_body, expected_count)
            except EnrichmentUnavailableError as exc:
                if attempt >= _TRANSIENT_RETRY_COUNT:
                    raise
                attempt += 1
                logger.info(
                    "enrichment transient failure (%s); retry %d/%d in %.1fs",
                    exc, attempt, _TRANSIENT_RETRY_COUNT,
                    _TRANSIENT_RETRY_DELAY_SECONDS,
                )
                time.sleep(_TRANSIENT_RETRY_DELAY_SECONDS)
            except EnrichmentRateLimitedError as exc:
                # Voyage 429. Wait `max(voyage_retry_after, MIN_WAIT)`
                # so the full sliding TPM window elapses (Voyage's
                # retry-after is a hint that doesn't guarantee the
                # window has cleared — observed 2026-05-27). Cap at
                # MAX_WAIT so a pathological retry-after doesn't hang
                # the scan. If the requested wait exceeds the cap OR
                # the retry itself 429s, re-raise so the caller falls
                # back to heuristic for the entire scan (no partial
                # enrichment).
                if attempt >= _TRANSIENT_RETRY_COUNT:
                    raise
                voyage_wait_seconds = exc.retry_after_ms / 1000.0
                if voyage_wait_seconds > _VOYAGE_429_MAX_RETRY_WAIT_SECONDS:
                    logger.info(
                        "voyage rate limit retry-after %.1fs exceeds cap "
                        "%.1fs; falling back to heuristic",
                        voyage_wait_seconds,
                        _VOYAGE_429_MAX_RETRY_WAIT_SECONDS,
                    )
                    raise
                # Use the longer of Voyage's hint and our minimum
                # window-clear wait — but never below voyage's number
                # if voyage asks for MORE than our minimum.
                wait_seconds = max(
                    voyage_wait_seconds,
                    _VOYAGE_429_MIN_RETRY_WAIT_SECONDS,
                )
                attempt += 1
                logger.info(
                    "voyage rate limit (retry-after %.1fs); waiting %.1fs "
                    "to clear TPM window, retry %d/%d",
                    voyage_wait_seconds, wait_seconds,
                    attempt, _TRANSIENT_RETRY_COUNT,
                )
                time.sleep(wait_seconds)

    def _attempt_post_enrich(self, request_body: dict, expected_count: int) -> EnrichResult:
        """Single attempt at the enrich call. Wrapped by `_post_enrich`
        for retry semantics."""
        try:
            response = requests.post(
                f"{self.gateway_url}/api/enrich",
                json=request_body,
                timeout=HTTP_TIMEOUT,
                headers={
                    **self._auth_headers(),
                    "Content-Type": "application/json",
                },
            )
        except (requests.RequestException, OSError) as exc:
            raise EnrichmentUnavailableError(_redact_exc(exc)) from exc

        self._raise_for_status(response, op="enrich")
        response_body = self._parse_json(response)

        # Sanity-bound the response shape: the survivors array cannot
        # exceed the input count (each input maps to at most one
        # survivor; duplicates are dropped, criticals are reinstated).
        # A buggy or hostile gateway returning a gigantic array would
        # otherwise eat memory.
        raw_findings = response_body.get("findings", [])
        if not isinstance(raw_findings, list) or len(raw_findings) > expected_count:
            raise EnrichmentUnavailableError(
                f"gateway returned malformed findings (size {len(raw_findings) if isinstance(raw_findings, list) else 'n/a'})"
            )

        findings = [
            EnrichedFinding(
                id=str(item["id"]),
                rank_score=float(item.get("rank_score") or 0.0),
                # cluster_size is server-computed; default to 1 for
                # defensive handling of a hypothetical missing field.
                # Cap at expected_count because a cluster cannot exceed
                # the size of its input batch — guards against a buggy
                # gateway returning absurd values that would surface in
                # YAML output as "remaining 2 billion occurrences."
                cluster_size=min(
                    expected_count,
                    max(1, _safe_int(item.get("cluster_size")) or 1),
                ),
            )
            for item in raw_findings
        ]
        return EnrichResult(
            findings=findings,
            tokens_used=_safe_int(response_body.get("tokens_used")),
            quota_remaining=_safe_int(response_body.get("quota_remaining")),
            quota_period_end=str(response_body.get("quota_period_end") or ""),
        )

    def _raise_for_status(self, response: requests.Response, op: str) -> None:
        if response.status_code < 400:
            return

        # Try to parse JSON error body for context. If that fails, fall
        # back to the raw text (truncated).
        try:
            err = response.json()
            if not isinstance(err, dict):
                err = {"error": "unknown", "message": str(err)[:500]}
        except Exception:
            err = {"error": "unknown", "message": response.text[:500]}

        # Defense in depth: redact anything that looks like a license
        # key (uppercase hex blocks separated by dashes) from the
        # error message before interpolating it into an exception.
        # The current gateway never echoes the request body in errors,
        # but if a future upstream / Vercel platform error page does,
        # we don't want the license key to surface in stack traces
        # caught by outer loggers / CI tools / support tickets.
        raw_message = str(err.get("message") or "enrichment failed")
        message = _redact_license_shape(raw_message)
        code = response.status_code

        if code in (401, 403):
            raise LicenseRejectedError(f"{op}: {message}")
        if code == 402:
            raise QuotaExhaustedError(
                f"{op}: {message}",
                tokens_needed=_safe_int(err.get("tokens_needed")),
                tokens_remaining=_safe_int(err.get("tokens_remaining")),
                quota_period_end=str(err.get("quota_period_end") or ""),
                topup_url=str(err.get("topup_url") or ""),
            )
        if code == 429:
            raise EnrichmentRateLimitedError(
                f"{op}: {message}",
                retry_after_ms=_safe_int(err.get("retry_after_ms")) or 60_000,
            )
        if code in (502, 503, 504):
            # Include the gateway's error slug + message so operators can
            # tell "voyage_unavailable" (upstream issue) from generic
            # platform 502/504 (Vercel infra blip). Also include the
            # upstream HTTP status if the gateway surfaced one — tells
            # us whether the upstream returned 4xx (likely config /
            # input issue) or 5xx (likely outage / rate cap).
            slug = err.get("error")
            slug_part = f" ({slug})" if isinstance(slug, str) and slug else ""
            upstream_status = err.get("upstream_status")
            upstream_part = (
                f" upstream={upstream_status}"
                if isinstance(upstream_status, int)
                else ""
            )
            upstream_message = err.get("upstream_message")
            upstream_msg_part = (
                f" upstream_message={_redact_license_shape(str(upstream_message))!r}"
                if isinstance(upstream_message, str) and upstream_message
                else ""
            )
            raise EnrichmentUnavailableError(
                f"{op}: gateway returned {code}{slug_part}{upstream_part}: {message}{upstream_msg_part}"
            )
        # Any other 4xx → treat as unavailable; CLI falls back to heuristic.
        # Include Zod validation `issues` if present (400 responses from the
        # gateway include them under err["issues"]). Without this, debugging
        # a schema rejection requires Vercel-log access; with it, the CLI's
        # own log shows what the gateway rejected and why.
        issues = err.get("issues")
        if isinstance(issues, list) and issues:
            issues_summary = "; ".join(
                f"{'.'.join(str(p) for p in iss.get('path', []))}: {iss.get('message', '?')}"
                for iss in issues[:5]
                if isinstance(iss, dict)
            )
            if len(issues) > 5:
                issues_summary += f" (and {len(issues) - 5} more)"
            raise EnrichmentUnavailableError(
                f"{op}: gateway returned {code}: {message} [issues: {issues_summary}]"
            )
        raise EnrichmentUnavailableError(f"{op}: gateway returned {code}: {message}")

    @staticmethod
    def _parse_json(response: requests.Response) -> dict:
        cl = response.headers.get("content-length")
        if cl is not None:
            try:
                if int(cl) > MAX_RESPONSE_BYTES:
                    raise EnrichmentUnavailableError(
                        f"gateway response too large ({cl} bytes)"
                    )
            except ValueError:
                pass  # Bad header; fall through to actual read.
        try:
            content = response.content
        except (requests.RequestException, OSError) as exc:
            raise EnrichmentUnavailableError(_redact_exc(exc)) from exc
        if len(content) > MAX_RESPONSE_BYTES:
            raise EnrichmentUnavailableError(
                f"gateway response too large ({len(content)} bytes)"
            )
        try:
            return response.json()
        except Exception as exc:
            raise EnrichmentUnavailableError(f"gateway returned non-JSON: {type(exc).__name__}") from exc


def _normalize_finding(item) -> dict:
    """Coerce a (id, text) tuple OR a dict to the gateway wire format.

    Legacy callers pass tuples. New callers pass dicts with type/title/
    file_path/severity.
    """
    if isinstance(item, tuple):
        if len(item) != 2:
            raise ValueError(f"Finding tuple must be (id, text); got {len(item)} elements")
        return {"id": str(item[0]), "text": str(item[1])}
    if isinstance(item, dict):
        out = {"id": str(item["id"]), "text": str(item["text"])}
        # Include optional discriminators only when populated — the
        # gateway treats absent fields as "no bucket info." Use an
        # explicit None / empty-string check rather than `if v:` so a
        # future scanner emitting falsy-but-meaningful values (e.g.
        # severity="0" or file_path that round-trips through some
        # weird sentinel) isn't silently dropped.
        for key in ("type", "title", "file_path", "severity"):
            v = item.get(key)
            if v is not None and v != "":
                out[key] = str(v)
        return out
    raise TypeError(f"Unsupported finding type: {type(item).__name__}")


def _safe_int(v) -> int:
    """Coerce a possibly-missing or malformed value to int. Defaults 0."""
    if v is None:
        return 0
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _redact_exc(exc: BaseException) -> str:
    """Render an exception without echoing its message (which often
    contains the request URL — and our license key was in that URL
    historically, before we moved it to a header). Belt-and-suspenders:
    only the exception type name escapes."""
    return f"network error: {type(exc).__name__}"


# Match LemonSqueezy license-key shape: uppercase alphanumeric blocks
# separated by dashes (e.g. AAAA-BBBB-CCCC-DDDD-EEEE). Conservative —
# the real format is 4 dash-separated 4-char blocks but we match 2+
# blocks of 4-12 chars to catch variations and future format drift.
import re as _re
_LICENSE_SHAPE_RE = _re.compile(r"\b[A-Z0-9]{4,12}(?:-[A-Z0-9]{4,12}){1,}\b")


def _redact_license_shape(message: str) -> str:
    """Strip license-key-shaped substrings from a message before it
    gets interpolated into an exception. Belt-and-suspenders against
    a future upstream/platform error page echoing the request body.
    """
    return _LICENSE_SHAPE_RE.sub("<REDACTED_LICENSE>", message)
