# `ai_instructions.yaml` — canonical shape (post-Phase H, 2026-05-18)

> This doc captures the output shape brass ships to AI consumers (Claude Code,
> Cursor, Continue, etc.) as of commit `7d4a3b8`. It's a reference for the
> intent behind each block, not a complete schema — the schema itself lives
> in the `ai_instructions_builder.py` code and is enforced by
> `tests/end_to_end/test_output_quality.py`. Update this doc when the shape
> intentionally changes.

## Why this shape

Pre-Phase-H, `ai_instructions.yaml` had a single `critical_issues` block
that mixed every finding type. After today's confidence-propagation
unlocks landed (~3× more findings, including pylint + legacy patterns +
analysis_error that were previously silently filtered), that block
became 80% non-security signal — misleading AI consumers about
prioritization. Phase H splits findings by type so the AI consumer sees
real-security signal separately from code-quality and architecture noise,
and so the executive summary can synthesize an actually-actionable
recommendation instead of restating the count.

## Top-level structure

```yaml
metadata: { ... }                  # scan provenance — see "Metadata" below
how_to_read_this_file: { ... }     # slim glossary — pointers, not prose
executive_summary: { ... }         # see "Executive summary" below
tool_health_summary: "..."         # 1-line pointer to operator_notes.yaml
remediations: { rem_NNN: "..." }   # remediation guidance keyed by ref
security_critical: [ ... ]         # SECURITY + PRIVACY findings only, capped at 50
code_quality_attention: [ ... ]    # CODE_QUALITY + TODO findings, capped at 50
architecture_concerns: [ ... ]     # ARCHITECTURE + PERFORMANCE findings, capped at 50
other: [ ... ]                     # ANALYSIS_ERROR + future types, capped at 50
critical_issues: [ ... ]           # BACKWARD-COMPAT ALIAS (deprecated; will be removed)
_deprecated_critical_issues_note:  # warning telling consumers to migrate
production_focus: [ ... ]          # top-25 production-code findings across all blocks
ai_guidance: { ... }               # how brass thinks an AI should handle this scan
file_priorities: [ ... ]           # ranked file list
quick_actions: [ ... ]             # one-liner actions an AI can suggest immediately
```

## Metadata

`metadata` is scan provenance: how these findings were produced, so the
AI consumer knows how to read them. It is NOT operator diagnostics
(those live in `operator_notes.yaml` — see "Where things moved"). The
common fields (`generated_at`, `project_path`, `analysis_engine`,
`total_findings`) appear in every `.brass/*.yaml`; the three below are
grafted into `ai_instructions.yaml` only.

```yaml
metadata:
  generated_at: "2026-09-29T12:34:56"
  project_path: "/path/to/project"
  analysis_engine: "BrassCoders 2.x"
  total_findings: 374
  scanners_run: [ast_grep, code, privacy, secrets, ...]   # scanners with status ok
  pysa_cache:                                             # present once the Pysa cache exists
    size_mb: 42.1
    entry_count: 3
    location: "~/.cache/brass/pysa-state"
  enrichment:
    mode: heuristic_no_license                            # always present on CLI-produced files
    note: "Heuristic-only scan: ... Provenance only."     # ONLY when mode != enriched
```

- **`scanners_run`** — sorted names of the scanners that ran with status
  `ok` this scan. Omitted (not emitted as `[]`) when the caller tracks
  no scanner status. Read it to tell "scanner ran clean" from "scanner
  never ran, no signal in that category". Per-scanner skip/error reasons
  are in `statistics.yaml` under `scanner_health`.
- **`pysa_cache`** — size, entry count and (`$HOME`-redacted) location of
  the on-disk Pysa cache. Present once the cache exists; omitted before
  the first Pysa run.
- **`enrichment`** — which pass produced the findings. `mode` is one of
  the closed values in `src/brass/core/enrichment_mode.py`:
  `enriched` (the BrassCoders Paid AI enrichment pass — semantic dedup +
  reranking — ran), `heuristic_no_license`, `heuristic_no_enrich_flag`,
  `heuristic_fallback` (a licensed scan attempted enrichment and fell
  back to heuristic results for the whole scan — never partial), or
  `heuristic_offline`. Every `heuristic_*` mode carries the same
  one-sentence `note`; `enriched` carries `mode` only. Heuristic-only
  results are complete as shown — the local noise-reduction pass is the
  final filter — and imply that per-finding `cluster_size` is absent
  (it is produced by the enrichment pass). This is provenance, not an
  action item: relay it as context if the user asks how the scan ran;
  do not turn it into a recommendation.

## Per-block intent

**`security_critical`** — the "real bugs" block. Only `type in (SECURITY,
PRIVACY)`. This is what a security-focused AI consumer should read first.
Each entry has the full finding shape (file_path, line_number, code_snippet,
confidence, impact_score, cluster_size, context, remediation_ref,
false_positive_likelihood, first_seen). Credential-leak findings have
`code_snippet` REMOVED with `code_snippet_omitted_reason` explaining
why — the AI consumer should read the source line directly, not act on
a redacted snippet.

**`code_quality_attention`** — pylint, TODO/FIXME, code-quality
findings. Worth surfacing but lower urgency than security. AI consumers
in code-review mode should skim these for "is this a real issue or a
style preference?" rather than treating them as bugs.

**`architecture_concerns`** — AIContextCoherence + BrassPerf findings.
"Your component signature doesn't match its consumers" or "this O(n²)
loop in a hot path" — design-level signals, not surface bugs.

**`other`** — ANALYSIS_ERROR breadcrumbs + anything that doesn't fit
the three primary blocks. Useful for triaging "why didn't brass catch
X on my file?" — usually means a scanner crashed mid-file.

**`production_focus`** — pre-filtered list of production-code items
from the three primary blocks, capped at 25, ranked by
(is_production_code=true ahead of false, then severity, then impact).
An AI consumer in "ship-the-PR" mode goes here first instead of
reading the security_critical block in full.

## Executive summary fields

```yaml
executive_summary:
  risk_level: HIGH|MEDIUM|LOW
  recommendation: "Priority: critical X at file:line (rem_N); then critical Y at file:line (rem_M); then ..."
  # ^ ACTIONABLE: names the top 2-3 production findings with remediation refs.
  #   Does NOT match r'^\s*\d+\s+critical/high' — that phrasing is the old
  #   placeholder and is regression-tested against in test_output_quality.py.
  total_findings: 374
  files_analyzed: 227
  average_confidence: 0.764
  average_impact: 0.113
  truncated_findings_count:
    security_critical: 0
    code_quality_attention: 0
    architecture_concerns: 0
  findings_by_category:
    hardcoded_credential: 23
    sql_injection: 3
    weak_crypto: 2
    # ... etc — one entry per detected category.
    # AI consumer reads this to understand "what's the shape of issues" without parsing 50 entries.
```

## Per-finding fields (new in Phase H)

In addition to the standard fields (file_path, line_number, code_snippet,
confidence, impact_score, cluster_size, references, remediation_ref):

- **`false_positive_likelihood`** (LOW|MEDIUM|HIGH) — heuristic, derived from
  (detected_by × is_production_code × confidence). NOT a guarantee; treat
  as a triage hint. High-confidence-bandit-on-production = LOW.
  Low-confidence-keyword-secrets-on-test-fixture = HIGH.

- **`first_seen`** (ISO timestamp) — when brass first observed this finding
  on this project. Persisted in `.brass/finding_history.json` keyed by
  finding id (or content hash if id is non-stable). New findings in this
  scan get the current scan timestamp.

- **`expansion_hint`** (string, optional) — present only on findings whose
  underlying cluster_size > 30. The displayed `cluster_size` is capped at
  30; the hint says: "See detailed_analysis.yaml for the remaining N
  occurrences."

- **`code_snippet_omitted_reason`** (string, optional) — present only when
  the finding's metadata has `secret_redacted: true`. Replaces the
  `code_snippet` field for security-sensitive findings.

- **`_next_after_truncation`** (synthetic entry, optional) — appears as the
  LAST entry in a block when `truncated_findings_count[block] > 0`. Points
  to detailed_analysis.yaml for findings beyond the top-50 cap.

## Where things moved

- **System advisories** moved OUT of `ai_instructions.yaml` into a new
  `operator_notes.yaml`. The cache-size advisory ("Run brasscoders cache
  clear") is operator-facing tool diagnostics, not codebase signal — it
  doesn't belong in the AI-consumer file. `tool_health_summary` in
  ai_instructions.yaml is a 1-line pointer to operator_notes.yaml when
  diagnostics exist.

## Stability contract

The shape above is the contract for first paying customer. Regression
test `tests/end_to_end/test_output_quality.py` enforces these
properties on every push:

- `security_critical` only contains `type in ("security", "privacy")`
- `code_quality_attention` only contains `type in ("code_quality", "todo")`
- `architecture_concerns` only contains `type in ("architecture", "performance")`
- No entry has `cluster_size > 30` without `expansion_hint`
- `executive_summary.recommendation` is not a bare count
- `executive_summary.findings_by_category` exists and is non-empty
- `system_advisories` is NOT in ai_instructions.yaml (moved to operator_notes.yaml)
- Each finding has non-null `file_path` and `line_number`
- `operator_notes.yaml` exists when operator-facing info applies
- `production_focus` exists and is a list
- `metadata.enrichment.mode` is present on CLI-produced files (a closed
  value from `enrichment_mode.py`); `note` accompanies every
  `heuristic_*` mode

Adding fields is backward-compatible. Removing or renaming fields requires
a deprecation cycle (mirror the `_deprecated_critical_issues_note`
pattern: keep the old field, document it as deprecated, give consumers
N months to migrate).

## What this is NOT

This is not a security audit format (SARIF, etc.). It's a structured
advisory designed for AI coding assistants to USE while reviewing a
codebase. Different consumers want different things: SARIF for SCA
tools, this YAML for AI-coding-assistant integration. brass emits
both via separate output paths.

## Related files

- Source of truth: `src/brass/output/yaml_builders/ai_instructions_builder.py`
- Output writer: `src/brass/output/yaml_output_generator_v2.py`
- Operator-facing notes: `src/brass/output/yaml_builders/`...
  (operator_notes.yaml emission path)
- Regression test: `tests/end_to_end/test_output_quality.py`
- Canonical historical example: a fresh scan against `tests/benchmarks/_clones/pygoat/`
  produces this shape; that's the simplest reference output to inspect.
