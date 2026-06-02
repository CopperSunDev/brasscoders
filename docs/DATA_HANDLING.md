# BrassCoders — data handling and security

_Last updated: 2026-05-22. Reflects the post-2C architecture
(merged into `main` on 2026-05-25 as commit `840ad14`)._

This is the technical companion to `PRIVACY_POLICY.md`. The privacy
policy is the customer-facing legal disclosure; this document
enumerates the implementation — what's transmitted, what's persisted,
what's logged, what subprocessors see — so security-conscious
customers can verify the privacy policy's claims against actual
behavior.

If anything in this document conflicts with the implementation, that's
a bug — please file an issue.

---

## TL;DR

- **Default mode (`--offline`)**: zero network calls. BrassCoders reads your
  files, runs scanners, writes `.brass/*.yaml`. Nothing leaves your
  machine.
- **Paid enrichment mode** (active license, no `--no-enrich` flag):
  - **Transmits** redacted finding metadata + four small file chunks
    (README, manifest, entrypoint, top-level filenames) to our gateway
    over TLS
  - **Persists nothing customer-derived on our servers** except:
    sha256-keyed embedding vectors (one-way), and license/quota
    metadata (your license key hash + token counters)
  - **No raw code, no full files, no findings text** is stored at rest
    on our infrastructure
- All inter-service hops use TLS 1.2/1.3.
- License keys travel in HTTP headers, never URLs — they can't leak
  into URL-bearing exception messages or proxy logs.

If your threat model requires zero data egress, `--offline` is the
contract. If you need enrichment, the rest of this document tells you
exactly what flows where.

---

## What BrassCoders reads (your machine)

For each file under the project root you point BrassCoders at, the CLI:

1. Skips files in the exclusion list (`.git`, `__pycache__`,
   `node_modules`, `.venv`, `venv`, `build`, `dist`, `.brass`,
   `.next`, `.nuxt`, `.svelte-kit`, etc.). See
   `src/brass/scanners/file_prefilter_scanner.py`.
2. Skips files whose resolved path falls outside the project root,
   even via symlink. See `src/brass/core/path_safety.py`.
3. Skips files larger than 1 MiB.
4. Reads the file content into memory.
5. Runs the relevant scanners (security, privacy, code quality,
   performance, secrets, content moderation).

BrassCoders does not read files outside your project root, and refuses to
follow symlinks pointing outside.

---

## What BrassCoders writes (your machine)

A `.brass/` directory inside the project root, with these files:

- `ai_instructions.yaml` — top-level summary for AI consumers
- `detailed_analysis.yaml` — every finding, grouped by type
- `file_intelligence.yaml` — findings collated per file
- `security_report.yaml` — security-only view
- `statistics.yaml` — aggregate metrics
- `privacy_analysis.yaml` — present only when PII findings exist
- `brass.log` — diagnostic log

`.brass/` is created with permissions `0700`; YAML files are written
with `0600` (POSIX). On Windows, BrassCoders relies on filesystem ACLs.

### Redaction in output

The privacy scanner exists to detect sensitive data; writing the raw
matches into `.brass/` would defeat the purpose. Two enforcement
layers:

1. **At the source.** `Brass2PrivacyScanner._redact_pii_metadata` runs
   after suppression heuristics and before the finding is returned.
   Replaces the matched value with a masked version (e.g.
   `4111****1111`), drops `context_line` / `code_snippet`, and clears
   `Finding.code_snippet` for any privacy finding.
2. **At the boundary.** `BaseYAMLBuilder.sanitize_metadata_for_serialization`
   strips known privacy-sensitive metadata keys (`matched_text`,
   `code_snippet`, `context_line`, `raw_match`, `context`) from any
   privacy-type finding before YAML serialization.

Hardcoded credentials detected by other scanners are redacted in-place
inside the source line via `AIAuthPatternAnalyzer._redact_secret_in_line`
before persisting.

The secret scanner records only the secret *type* and a short hash for
deduplication. The secret value itself is never written to disk by BrassCoders.

---

## What flows over the network — enrichment mode

If you scan with an active paid license and don't pass `--no-enrich`,
the CLI calls our gateway once per scan. Here's the complete inventory.

### Request (CLI → `brass-api-gateway.vercel.app`)

```json
{
  "license_key": "AAAA-BBBB-...",
  "instance_id": "host-or-machine-id",
  "raw_files": {
    "readme":     "first 5000 chars of README.md (if present)",
    "manifest":   "first 2000 chars of pyproject.toml / package.json / etc",
    "entrypoint": "first 3000 chars of main.py / index.ts / etc",
    "filenames":  ["main.py", "src/lib.py", ...]
  },
  "findings": [
    {
      "id": "f0",
      "text": "<sanitized + bounded representation of the finding>",
      "type": "security|privacy|code_quality|...",
      "title": "<category label, scrubbed of any matched value>",
      "file_path": "src/auth.py",
      "severity": "critical|high|medium|low|info"
    },
    ...
  ],
  "options": { "rerank_top_n": 200, "dedup_threshold": 0.85 }
}
```

**About `findings[].text`** — this is the embedded representation, built
by `_finding_to_text` in `src/brass/enrichment/filter.py`. For
sensitive finding types (SECURITY, PRIVACY, SECRET, CREDENTIAL, PII),
it includes ONLY file path + line number + type + scrubbed title.
Description, snippet, and matched-text fields are NEVER included for
sensitive types — defense in depth against a scanner regression
silently exfiltrating a secret. For non-sensitive types
(CODE_QUALITY, ARCHITECTURE, PERFORMANCE), title + first 1.2KB of
description + first 300 chars of code snippet are included.

**About `raw_files`** — these are file content chunks. They are
explicitly read by the CLI's `gather_raw_files()`
(`src/brass/enrichment/project_signature.py`), which refuses symlinks
to prevent a malicious project from steering `/etc/passwd`-like
content into the wire payload. Customer-side content-length caps
(5K/2K/3K/80 entries) bound the payload.

### Response (gateway → CLI)

```json
{
  "findings": [
    { "id": "f5", "rank_score": 0.95, "cluster_size": 1 },
    { "id": "f0", "rank_score": 0.89, "cluster_size": 3 },
    ...
  ],
  "tokens_used": 1234,
  "quota_remaining": 4998766,
  "quota_period_end": "2026-06-22T..."
}
```

Survivors only — dropped findings are implicit. Ordered by `rank_score`
descending. `cluster_size > 1` means this surviving finding absorbed
`cluster_size - 1` semantically-duplicate siblings.

### Quota endpoint

`GET /api/quota` — returns the customer's remaining token allowance.
License credentials travel in the `X-BrassCoders-License-Key` and
`X-BrassCoders-Instance-Id` HTTP headers, **not** in the URL. This prevents
the license key from appearing in network-error exception strings, CI
logs, or HTTP proxy access logs.

---

## What's persisted on our infrastructure (at rest)

All gateway state lives in **Upstash Redis**. There is no persistent
database. Vercel functions are stateless — no disk state survives
between requests.

| Key pattern | Value | TTL | Customer-derived? |
|---|---|---|---|
| `embed_cache:voyage-code-3:512:<sha256(finding_text)>` | `{ vector: number[512], dim, model }` | 7 days | Vector is one-way derived from finding text. Key is sha256 — original text is **not** recoverable from key or value. Vectors enable similarity comparison but not text reconstruction. |
| `license_cache:<sha256(license_key + instance_id)>` | `{ valid, status, expires_at, customer_email, product_name }` | 15 seconds | Contains your email address. ~5 entries deep at any time given the 15-second window. |
| `quota:<sha256(license_key)>` | `{ monthly_remaining, topup_remaining, period_start, period_end, total_used_lifetime }` | Persistent (per-license) | License key hash + token counters. No PII beyond what LemonSqueezy already has. |
| `revoked:<sha256(license_key)>` | `true` | Persistent until cleared by webhook (or set with TTL on grace periods, but we currently use permanent) | Set by LS webhook on `subscription_expired` / `subscription_payment_failed` / subscription-`order_refunded`. Short-circuits future `validateLicense` calls without hitting LS, so revocations propagate within webhook-delivery latency (seconds) instead of waiting up to the 15s `license_cache` TTL. |
| `cust_to_license:<lemonsqueezy_customer_id>` | `<license_key string>` | Persistent | Set by LS webhook on `license_key_created`. Used by other webhook events (which carry only `customer_id`) to resolve back to the license key. Stable for the lifetime of the license. |
| `order_processed:<lemonsqueezy_order_id>` | `true` | 10 minutes | Idempotency guard on `order_created` (topup detection). LS retries failed deliveries 3x with exponential backoff; this flag prevents double-processing on retry. |
| `order_refunded_processed:<lemonsqueezy_order_id>` | `true` | 10 minutes | Same pattern for `order_refunded` events. |
| `.gc.lock`, `.schema` (Pysa cache only, customer machine) | n/a | n/a | Customer-side only. Not on our infrastructure. |

Note: cumulative lifetime token usage is **not** a separate Redis key — it's stored as the `total_used_lifetime` field inside the `quota:<sha256>` JSON value (updated atomically by the same Lua script that decrements monthly/topup buckets).

**Explicitly not persisted on our infrastructure**:

- Raw finding text
- The `raw_files` payload (README/manifest/entrypoint chunks)
- Code snippets
- Customer file paths
- Customer source code
- Anything customer-source-derived beyond the embedding vector

Upstash encrypts data at rest as a service guarantee.

---

## What we log

The gateway logs to Vercel's serverless function logs (encrypted at
rest; 7-day retention on free tier, 30 days on Pro):

- **`[cache] pipeline.set failed at index ...`** — cache write failures.
  No finding content; only the failed index + Redis error.
- **`[enrich] upstream error: <e.message>, <e.status>`** — only on
  Voyage API failures.

  **Caveat**: Voyage's error messages occasionally include partial
  echo of the failing input (e.g., for "input too long" errors). In
  the rare case a Voyage call fails on a long finding-text input, a
  short snippet of that text could land in Vercel's logs. Not
  customer-visible, but disclosed here for completeness.

We do not log:

- Successful enrichment requests
- Finding text on the happy path
- License keys (always passed as headers, redacted from any log we
  do emit)
- IP addresses (beyond what Vercel automatically captures for routing)

---

## Subprocessors

Third-party services that touch customer data during normal operation:

| Subprocessor | What they see | Their stance |
|---|---|---|
| **Voyage AI** (embedding + rerank) | Finding text (privacy-redacted before transmission) + project signature, during the embed and rerank API calls. Per-token billing. | Public commitment: "zero data retention" — API calls are not used for training. Verify their current TOS for the latest commitment. |
| **Vercel** (gateway hosting + edge network) | All HTTPS traffic transits Vercel infrastructure. Logs request metadata, error logs (see "What we log" above). | SOC 2 Type II certified. Logs encrypted at rest. Default region: US-East. |
| **Upstash** (Redis backend) | All Redis reads/writes for embedding cache, license cache, quota state, rate limits. | SOC 2 Type II certified. Data encrypted at rest. |
| **LemonSqueezy** (license issuance + payment) | License keys, customer email, purchase records, activation metadata. **Does not see findings or code.** | SOC 2 Type II certified. They own the customer-payment relationship and tax compliance. |

### LemonSqueezy webhook flow

LemonSqueezy POSTs signed event notifications to our gateway whenever
subscription / order / license-key state changes server-side. The
gateway translates those into Upstash state mutations.

What's transmitted from LS to our gateway, per event:

- Customer email (already known to us via the license-validate path)
- Customer ID, subscription ID, order ID (LS-internal numeric IDs)
- License key string (only on `license_key_created` event)
- Subscription status (active, cancelled, expired, past_due, paused)
- Period start / end / renews_at / ends_at timestamps
- Variant ID + product ID (so the gateway can distinguish subscription
  orders from topup orders)

What the gateway does with each event is enumerated in the webhook
handler source (`gateway/api/webhooks/lemonsqueezy.ts`). Briefly: it
sets/clears revoked flags, applies topup credits, and caches the
customer-ID-to-license-key mapping. **No finding text or source code
ever transits this path** — those flow through `/api/enrich` only,
and LS never sees them.

Signature verification: every webhook delivery carries an
`x-signature` header computed as HMAC-SHA256 of the raw body using
our LS webhook signing secret. The gateway rejects (401) any payload
with an invalid or missing signature, so an attacker cannot forge
state mutations even with knowledge of the webhook URL.

---

## What we DO NOT do

- ❌ **Train on customer code.** Voyage's zero-data-retention commitment
  applies; we do not retain, mine, or train any model on customer
  findings or source.
- ❌ **Share customer code with anyone outside the subprocessor list
  above.** No analytics SDKs, no error trackers that capture request
  bodies, no third-party CDN that sees finding content.
- ❌ **Sell or share customer email beyond what LemonSqueezy needs for
  the payment relationship.**
- ❌ **Track customer scans, project signatures, or finding patterns
  for product analytics.** The gateway counts tokens for billing;
  that's it.
- ❌ **Make outbound network calls in `--offline` mode.** Every CLI
  command honors `--offline` as a hard contract.

---

## What we cannot honestly claim (yet)

These are common questions from security-conscious procurement
processes. Honest current state:

| Standard / certification | Status |
|---|---|
| TLS 1.2/1.3 in transit | ✅ All hops |
| No persistent storage of customer code on our servers | ✅ Verifiable in `gateway/lib/cache.ts`, `gateway/lib/enrich.ts` — no DB writes of finding text or raw files |
| Subprocessor list documented | ✅ This document |
| Privacy policy in place | ✅ `cli/docs/PRIVACY_POLICY.md` |
| `--offline` mode for air-gapped use | ✅ Documented contract |
| SOC 2 Type I | ❌ Not certified |
| SOC 2 Type II | ❌ Not certified |
| ISO 27001 | ❌ Not certified |
| HIPAA / BAA | ❌ BrassCoders is not approved for protected health information |
| GDPR-compliant Data Processing Agreement | ❌ Template not yet drafted |
| Penetration test report on file | ❌ |
| Bug bounty program | ❌ — responsible disclosure via `brass@coppersuncreative.com` per `SECURITY.md` |
| Customer-managed encryption keys (BYOK) | ❌ |
| Region pinning (EU-only, US-only data residency) | ❌ — default US-East via Vercel |
| Customer-accessible audit logs | ❌ |

If your procurement process requires any of these, contact
`brass@coppersuncreative.com` to discuss timeline.

---

## Customer choices

| Choice | How |
|---|---|
| Run fully offline (no enrichment, no network) | `brasscoders --offline scan` |
| Enable enrichment but skip the package-hallucination check | default (the package-hallucination check is opt-in per scan) |
| Stop using enrichment entirely | `brasscoders license deactivate` (releases the activation; on-disk record at `~/.brass/license` is removed) |
| Request deletion of your license and quota state from our gateway | Email `brass@coppersuncreative.com`. We'll remove your license + quota Redis entries. Embedding cache entries auto-expire within 7 days (and are not recoverable to text anyway). |

---

## Threat model

BrassCoders's security model centers on three scenarios:

1. **A user scanning untrusted source code.** Symlink-escape and
   git-config-inheritance attacks (CVE-2022-24765 class) are
   neutralized via path-safety enforcement and sandboxed subprocess
   env. See `cli/SECURITY.md` for closed findings.

2. **A user with a BrassCoders license trying to spoof a higher-tier
   license.** LemonSqueezy owns the license-status source of truth; the
   on-disk record at `~/.brass/license` is a cache that re-validates
   weekly. Tampering doesn't grant tier escalation because there's
   only one tier (see `MEMORY.md` for the single-tier product
   decision).

3. **Network-borne attacks against the (opt-in)
   `--check-package-hallucination` registry calls.** Lookups go to
   PyPI / npm / pkg.go.dev. The check is off by default.

Detailed scope, in-scope/out-of-scope, and closed findings are in
`cli/SECURITY.md`.

---

## Reporting a privacy or security issue

Email `brass@coppersuncreative.com` with description and reproduction
steps. We treat the following as launch-blocking:

- Unauthorized data egress
- Raw PII or credential material persisted in `.brass/` artifacts
- Path traversal letting a scanned project read outside its root
- Code execution from scanning a malicious project
- License-system attacks

Do not open a public GitHub issue for any of the above until a fix
has shipped.
