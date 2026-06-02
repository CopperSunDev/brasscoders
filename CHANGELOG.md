# Changelog

All notable changes to BrassCoders are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

_No unreleased changes._

## Launch — 2026-06-01

BrassCoders Paid tier is LIVE on LemonSqueezy. End-to-end purchase flow
verified with a real card: payment processed, license-key email
delivered, gateway received and acknowledged `subscription_created` and
`subscription_cancelled` webhooks (both 200 OK in LS delivery log).

The `coppersun.dev/pricing` and `coppersun.dev/topup` buy URLs route to
live LS variants. The OSS core stays free; Paid is $12/dev/month with
50M enrichment tokens included.

Ships with `brasscoders` 2.0.7 on PyPI. Old `brass-ai-coders` releases
yanked with rename notice.

## [2.0.7] — 2026-06-01

Sync pyproject.toml `description` field (the short tagline rendered
under the title on the PyPI listing) to match the README h1 and brand
descriptor. Was missed in 2.0.6 because the README h1 is a separate
field from `project.description`.

No code changes.

## [2.0.6] — 2026-06-01

Readme / PyPI listing polish. Install section now points at
`pipx install brasscoders` (the published path) instead of the
pre-publish editable-install hedging. Tagline updated to the Tier 2
descriptor — "catches the bugs your AI coding assistant misses" — to
match the post-rename brand positioning.

No code changes.

## [2.0.5] — 2026-06-01

First release published under the renamed `brasscoders` PyPI package
(previously `brass-ai-coders`; old releases yanked with rename notice).
Bumps the in-source `__version__` constant from the stale `2.0.0` to
match — fixes a confusing "newer version available" message on every
CLI invocation. No behavior changes.

## [2.0.4] — 2026-05-31

Polish on the Pysa dynamic-timeout work in 2.0.3 after a /full-bugs
sweep surfaced UX gaps and a perf hit on big monorepos.

### Fixed

- **Context-aware Pysa timeout-error advice.** The previous blanket
  "set BRASS_PYSA_TIMEOUT_SECONDS to 2× the current value" suggestion
  was wrong at both ends of the range:
  - At the 7200s (2hr) ceiling, suggesting 14400s rarely helps — the
    OS may be thrashing or Pyre's call graph exploded. Now suggests
    narrowing scope via `.brassignore` or `BRASS_PYSA_MAX_FILES`.
  - On small projects (<500 files) that time out at the 600s floor,
    suggesting a 6× bump was wasted time — it's almost always a Pyre
    bug / OS pressure / recursive imports, not a sizing problem.
    Now suggests diagnosis + pointing at `.brass/brass.log`.
- **Eliminated 2-3× redundant project-tree walks per Pysa scan.** The
  Python file count is now computed once during the OOM-guardrail
  check and cached on the scanner for the dynamic timeout sizing
  and the timeout-error advice builder. On a 14K-file monorepo the
  redundant walks were measurable; on the timeout-error path they
  happened exactly when the customer's tree walk was slowest.
- **Pysa startup line now surfaces at default verbosity.** The
  `Pysa: analyzing N Python files with Xs timeout (Ym)` log is now
  WARNING level (was INFO). Customers running a 30+ minute Pysa scan
  on a large project now see the analysis budget instead of silence.

## [2.0.3] — 2026-05-31

Pysa timeout improvements after Phase H stress testing surfaced
silent timeouts on large projects.

### Fixed

- **Pysa silently dropped coverage on >2K-file projects.** The
  analyze timeout was hardcoded at 600s — typical for ≤2K-file
  customer projects but tight above that. Customers saw
  `⚠️ 🧠 Pysa interprocedural taint: 0 findings (errored: timed out)`
  with no actionable next step.

### Added

- **Dynamic Pysa timeout sizing** based on Python file count:
  - 600s floor (Pyre warmup)
  - file_count × 0.5s scaling (empirical: ~0.4-0.5s/file)
  - 7200s ceiling (above that, split the scan)
  - Examples: 1K files → 600s; 5K files → 2500s; 9K files → 4500s.
- **`BRASS_PYSA_TIMEOUT_SECONDS` env override** — for customers
  fine-tuning beyond the ceiling or testing with fast-fail values.
- **Actionable timeout error message** including the file count,
  suggested override value, and `.brassignore` / `BRASS_PYSA_MAX_FILES`
  alternatives.
- **Pysa startup log** — `Pysa: analyzing N Python files with Xs
  timeout (Ym)` so the customer sees the expected analysis budget
  before Pysa runs.

## [2.0.2] — 2026-05-31

Bug fixes + the `brasscoders portal` subcommand. Released during the
LemonSqueezy live-mode cutover so customers who subscribe today
get the working CLI, not the 2.0.1 wheel that predates these fixes.

### Added

- **`brasscoders portal` subcommand** — opens the LemonSqueezy customer
  portal in the customer's browser for managing subscription, payment
  method, invoices, cancellation. Fetches a fresh signed portal URL
  via the gateway each invocation (LS portal URLs are short-lived).
- `brasscoders license` output now shows a low-quota warning (< 10M
  tokens remaining) plus a hint to `brasscoders portal` and the
  topup URL.

### Fixed

- **Pysa scanner silently skipped after `cache clear --include-typeshed`.**
  Typeshed auto-fetch is now the default (opt-out via `BRASS_OFFLINE=1`
  or `BRASS_AUTOFETCH_TYPESHED=0`) — was opt-in via an undocumented
  env var. The `--offline` flag now correctly propagates to scanners
  via `BRASS_OFFLINE=1` in the env. Cache-clear output prints a
  clear hint about auto-refetch on the next online scan.
- **Secrets / privacy scanners contaminated by BrassCoders's own output.**
  The file prefilter now excludes `.brass/` — without this, repeated
  scans on the same codebase saw the secrets count climb scan-over-scan
  (200 → 289 → 372 → 445 in one observed case) because
  `.brass/finding_cache.json` kept growing and the scanner re-matched
  finding snippets in it. The `FileClassifier` already excluded
  `.brass/` but the prefilter ran first with its own pattern list.
- **Stale `operator_notes.yaml` lingered when no advisories fired.**
  When the current scan has no operator advisories AND a stale file
  exists from a prior scan, the stale file is now removed. Customers
  no longer see a stale "your cache is huge" advisory from a scan
  three days ago alongside a fresh scan that didn't have the issue.
- **`brasscoders portal` previously couldn't fetch the LS portal URL.**
  Gateway-side fix: the customer lookup used a query LS doesn't accept
  (`?filter[customer_id]=`); switched to `?filter[user_email]=` on
  `/v1/subscriptions` and to `?include=license-keys` on
  `/v1/customers/{id}` for the related cache-miss fallback. CLI side
  is unaffected — these were API-shape fixes on the gateway.

## [2.0.1] — 2026-05-29

Re-publish after the 2026-04-29 `2.0.0` yank. Same scanner pipeline,
substantial monetization scaffolding, license change, and the
post-2C "thin client" wire format. Per-customer engineering work
between the yank and this release is captured below.

### Changed (license)

- Relicensed from MIT to **Apache 2.0**. Apache 2.0 includes an
  explicit patent grant, which a few enterprise legal teams find
  easier to clear than MIT. The 2C refactor (see "Gateway split"
  below) closed the "MIT exposes too much" concern that had paused
  the prior decision. See `LICENSE` and `NOTICE`.

### Added (monetization + paid-tier scaffolding)

- Phase 4 monetization scaffolding:
  - LemonSqueezy-backed license keys via the LS License API
    (`src/brass/licensing/{lemonsqueezy,store}.py`). LS handles
    issuance, activation limits, and revocation on cancel/refund.
  - `brasscoders activate / license / deactivate` subcommands. The CLI
    re-validates with LS at most once per week; otherwise it stays
    offline. Network policy: `scan / watch / filter / version / status`
    make zero outbound calls in OSS / unlicensed mode.
  - PyPI freshness check on `brasscoders version`. Opt-out via `--offline`
    or `BRASS_DISABLE_VERSION_CHECK=1`. Soft-warn only; never auto-update.
  - Opt-in telemetry framework (`src/brass/telemetry/`). Off by default.
    `MockBackend` writes JSONL to `~/.brass/telemetry-debug.log` so users
    can audit before any real backend (Plausible / PostHog) is wired in.
  - `brasscoders filter` post-processor — applies BrassCoders noise reduction to
    third-party AI-reviewer JSON.
  - `brasscoders telemetry on / off / status` subcommand.

### Changed (gateway split — "2C refactor")

- Moved the IP-bearing enrichment work (project signature build,
  cosine-similarity dedup, CRITICAL-exemption, cluster_size, rerank)
  from the CLI into the closed Vercel gateway. CLI now sends a
  "thin client" payload and applies the response. OSS remains
  fully self-sufficient for scanning; enrichment is the Paid-tier
  addition. See `docs/DATA_HANDLING.md` for the exhaustive
  what-leaves-the-machine inventory.
- Wire format v2: survivors-only response with `cluster_size` per
  finding. The CLI no longer computes `duplicate_of` client-side.
- Token-budget CLI chunking for large scans (`enrichment/client.py`).
  Replaces fixed 1000-finding-per-call chunking with token-aware
  packing that matches the gateway's per-pair billing formula.
  Customers with 5K-10K-finding monorepos now get full enrichment
  without hitting per-call ceilings.
- `@astrojs/sitemap` integration on the marketing site; auto-generates
  `sitemap-index.xml` + `sitemap-0.xml` from the actual routes.
- Reproducible benchmark script (`scripts/benchmark.py`) over 10 pinned
  public Python repos.
- `.github/workflows/test.yml` runs the suite on Python 3.9 / 3.10 /
  3.11 / 3.12, plus a self-scan smoke test, plus a build job.
- `LICENSE`, `CONTRIBUTING.md`, `SECURITY.md`, this `CHANGELOG.md`.
- `external-accounts-needed.md` checklist for what the launch operator
  has to sign up for.

### Changed

- Migrated marketing site from Cloudflare Pages → Vercel (`brass.coppersun.dev`).
- Output: `YAMLOutputGeneratorV2` is the only writer the CLI invokes.
  Markdown writer (`OutputGenerator`) is dead code, scheduled for
  removal in a future release.
- Privacy scanner suppression heuristic: bare `'test'` removed from the
  pattern-indicators list (was over-suppressing on `attest`,
  `manifest`, `latest`, etc.); whole-path-component matching for
  test-file detection.
- ContentModerationScanner: file walking now honors
  `file_classifier.should_exclude_from_analysis`, checks `is_file()`
  before opening (closes IsADirectoryError on `.next/types/app/feed.xml`-
  style directories).
- API security scanner: regex patterns are pre-compiled via the
  module-level `_compiled_pattern` cache; lines longer than 10KB are
  skipped before regex evaluation (closes a hang on minified-JS bundles).
- Build artifacts excluded from analysis: `.next`, `.nuxt`,
  `.svelte-kit`, `.turbo`, `.vercel`, `.cache`, `.parcel-cache`,
  `.astro`, `target`, `.gradle`, `coverage`, `dist`, `build`, `out`,
  `prisma/generated`, `generated/graphql`.
- `Brass2PrivacyScanner.scan(file_paths=None)` matches every other
  scanner's contract; honors caller's file list when supplied.
- `BaseYAMLBuilder.sanitize_finding_for_serialization` redacts
  `code_snippet` for SECURITY findings whose detector is in the
  secret-leak allowlist (`auth_pattern_analyzer`, `bandit`).
- `brasscoders watch` no longer busy-waits with `sleep(1)`; blocks on the
  watcher's shutdown event.
- `brass.log` now written `0600`. Filter command output also `0600`.

### Fixed

- 8 pre-existing unit-test failures resolved (vulture/pyperf optional-
  dep tests, logger singleton mock, professional-code-scanner API drift).
- YAMLUtils no longer unlinks an existing good output when a write fails
  (atomic writer guarantees the previous content is intact).
- `brass_performance_scanner` severity sort uses numeric ladder (was
  string-sorting `Severity.value` and dropping CRITICAL findings before
  MEDIUM ones in the per-category cap).
- `_generate_id` no longer hashes `datetime.now()`; finding IDs stable
  across runs.
- `_validate_file_path` no longer rejects valid paths whose absolute
  form happens to contain `..` as part of a directory name.
- `FilePrefilterScanner._should_exclude` uses `path_safety.is_within`
  instead of string-prefix match (was admitting sibling dirs whose name
  shared a prefix with the project root).
- `brass_performance_scanner._create_test_script` documented as
  literal-only; `nesting_level` cast through `int()`. Synthetic perf
  scripts now run under `python3 -I` with a minimal env.
- `phantom_ai_code_scanner._can_import_module` sanitizes `sys.path` to
  drop the empty-string entry that means CWD; `lru_cache(4096)` on
  module-resolution calls.
- `intelligent_noise_filter._apply_per_file_limits` pre-sorts findings
  by severity/confidence before the per-file cap (was non-deterministic
  file-order truncation).
- `statistics_builder` emits `null` for `analysis_duration` instead of
  fabricated `'28.5s'` placeholder.
- Many smaller correctness fixes — see commit history under
  `phase-0-security`, `validation-fixes`, `polish-pass`,
  `full-bugs-review` branches.

### Security

- All Phase 0 findings closed (CRITICAL-1 registry validation default-
  off, CRITICAL-2 PII redaction, HIGH-1..5 + permission lockdown).
- Bandit / Pylint / Babel subprocesses now use sandboxed environments;
  `PYTHONPATH`, `PYLINTRC`, `BANDIT_*`, `NODE_OPTIONS`, `NPM_CONFIG_*`
  are stripped.
- Privacy scanner output redaction extended to SECURITY findings whose
  detector is in the secret-leak allowlist (Bandit B105/B106, JS
  hardcoded_password, etc.).
- Symlink boundary check (`path_safety.is_within`) applied at every
  `Path.rglob` site (8 scanner sites + `FilePrefilterScanner`).

## [2.0.0] — 2026-04-29

Initial public-launch release.

- Six scanners: `ProfessionalCodeScanner`, `Brass2PrivacyScanner`,
  `ContentModerationScanner`, `JavaScriptTypeScriptScanner`,
  `PhantomAICodeScanner`, `BrassPerformanceScanner`,
  `APISecurityScanner`, `AIContextCoherenceScanner`, `SecretsScanner`.
- `IntelligenceRanker` weighted prioritization.
- `YAMLOutputGeneratorV2` writes `.brass/{ai_instructions, detailed_analysis,
  file_intelligence, security_report, statistics, privacy_analysis}.yaml`.
- CLI: `brasscoders scan / watch / status / report / version`.
- Single dependency at install time: `PyYAML`. Other runtime deps
  (`requests`, `bandit`, `pylint`, `radon`, `detect-secrets`)
  declared in `pyproject.toml` and pinned with conservative floors +
  SemVer-major caps.
- 0700 on `.brass/`, 0600 on contents.
- Default-offline. No telemetry. No outbound network calls except the
  opt-in package-hallucination check.

[Unreleased]: https://github.com/CopperSunDev/brass-intelligence/compare/v2.0.4...HEAD
[2.0.4]: https://github.com/CopperSunDev/brass-intelligence/releases/tag/v2.0.4
[2.0.3]: https://github.com/CopperSunDev/brass-intelligence/releases/tag/v2.0.3
[2.0.2]: https://github.com/CopperSunDev/brass-intelligence/releases/tag/v2.0.2
[2.0.1]: https://github.com/CopperSunDev/brass-intelligence/releases/tag/v2.0.1
[2.0.0]: https://github.com/CopperSunDev/brass-intelligence/releases/tag/v2.0.0
