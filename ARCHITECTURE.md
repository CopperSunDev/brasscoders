# Copper Sun Brass v2.0 — CLI Architecture

> Scope: the `brasscoders` CLI (this `cli/` half of the `brass-intelligence`
> monorepo). Architectural *principles* (single responsibility, the sacred
> `Finding` contract, one-direction data flow) live in `CLAUDE.md` and
> `docs/developer-guide/ARCHITECTURAL_PRINCIPLES.md`; this doc describes the
> runtime shape those principles produce.

## Executive summary

Copper Sun Brass v2.0 is a **CLI-induced, on-demand** code-analysis tool: the user
runs `brasscoders scan <project>`, the pipeline executes once, writes structured
YAML to `.brass/`, and exits. There is no daemon and no background process.

This is a deliberate departure from the project's **monitoring-based predecessor**
(the archived `devwatch` system — see the repo-root README's "Historical archive"
note), which ran continuous background agents. That approach was retired; the
`watch` command and its monitoring module were the last vestige and were **removed
in v2.0.9** (commits `532bbd3`, `9bd7d1b`). v2.0 is CLI-only. The "historical
context" section below records why, so the trade-off isn't relitigated.

## Why CLI-induced (settled rationale)

| Property | On-demand CLI (v2.0) | Continuous monitoring (retired) |
|---|---|---|
| Execution | Per-invocation, exits when done | Long-running daemon |
| Resource use | Bursty, bounded to the run | Continuous background load |
| When intelligence updates | When the user runs a scan | Automatically, in the background |
| Failure surface | One process to reason about | Background-agent lifecycle to manage |
| Fit | Pre-commit / CI gate / on-request deep dive | "Always-fresh context" ambition |

The CLI model won on **predictability, debuggability, and CI-nativeness** — it drops
cleanly into a pre-commit hook or a CI step, and a single invocation is trivial to
reason about and reproduce. The cost is that intelligence is a point-in-time
snapshot: it's only as fresh as the last scan. For BrassCoders' role (a deterministic
gate that AI coding assistants consume), a reproducible snapshot is the feature, not
a compromise.

## Component architecture

Data flows **one direction** — scanners produce findings, the ranker orders them,
the generator serializes them. No component calls upstream; the generator never
invokes a scanner.

```
brasscoders scan <project>
        │
        ▼
  CLI (brass/cli/brass_cli.py) — orchestration, flags, cache-replay
        │
        ▼
  Scanners (brass/scanners/*, each returns List[Finding])
        │
        ▼
  IntelligenceRanker (brass/ranking/intelligence_ranker.py)
        │  weighted scoring + confidence → ordered findings
        ▼
  YAMLOutputGeneratorV2 (brass/output/yaml_output_generator_v2.py)
        │  + yaml_builders/ (one focused builder per file)
        │  + redaction_checker.py (credential redaction at the boundary)
        ▼
  .brass/*.yaml   (consumed by Claude Code / Cursor / etc.)
```

### Scanners

Twelve finding-producing scanners run in the pipeline (several are conditional on
project shape or opt-in flags), each returning `List[Finding]`:

| Scanner | Responsibility |
|---|---|
| `ProfessionalCodeScanner` | Bandit + Pylint + legacy security patterns |
| `Brass2PrivacyScanner` | PII / privacy detection (with redaction at the source) |
| `ContentModerationScanner` | Content-policy / safety checks |
| `JavaScriptTypeScriptScanner` | JS/TS analysis (runs when JS/TS files present) |
| `PhantomAICodeScanner` | AI-generated-code completeness / hallucinated imports |
| `BrassPerformanceScanner` | Performance intelligence |
| `APISecurityScanner` | API-surface security |
| `AIContextCoherenceScanner` | AI-context coherence |
| `SecretsScanner` | Hardcoded-secret detection (detect-secrets) |
| `SemgrepTaintScanner` | Semgrep taint analysis |
| `AstGrepScanner` | ast-grep structural matches |
| `PysaTaintScanner` | Pyre/Pysa taint (RAM-aware file-cap guardrail) |

Two additional scanners support the pipeline rather than emit user findings:
`FilePrefilterScanner` (file classification / exclusion) and `NoiseReductionScanner`
(post-scan noise reduction). Adding a scanner follows one fixed pattern — see
`docs/developer-guide/ADDING_NEW_SCANNERS.md`.

### Ranker

`IntelligenceRanker` (`brass/ranking/intelligence_ranker.py`) applies weighted
scoring and confidence assessment to order all findings for AI consumption. Ranking
only — it neither scans nor serializes. Critical findings are exempt from filters
that could drop them.

### Output generator

`YAMLOutputGeneratorV2` (`brass/output/yaml_output_generator_v2.py`) orchestrates a
set of focused builders under `brass/output/yaml_builders/` (one builder per output
file). Credential redaction is enforced at the serialization boundary
(`redaction_checker.py`) as defense-in-depth on top of scanner-side redaction.
(An older `output/output_generator.py` remains in the tree but is not wired into the
live path.)

## Output artifacts

A `scan` writes a `.brass/` directory (mode `0700`, YAML files `0600`) inside the
project root:

| File | Contents | Written when |
|---|---|---|
| `ai_instructions.yaml` | Top-level summary + guidance for AI consumers | Always |
| `detailed_analysis.yaml` | Every finding, grouped by type | Always |
| `file_intelligence.yaml` | Findings collated per file | Always |
| `security_report.yaml` | Security-only view | Always |
| `statistics.yaml` | Aggregate metrics | Always |
| `privacy_analysis.yaml` | Privacy/PII view | Only when PII findings exist |
| `operator_notes.yaml` | System advisories (scanner skips, degraded state) | Only when there's ≥1 advisory (stale copies deleted) |
| `brass.log` | Diagnostic log | Always |

Output is **YAML** — the earlier Markdown/JSON artifacts (`AI_INSTRUCTIONS.md`,
`analysis_data.json`, …) are gone; a vestigial JSON-summary *read* remains in the CLI
for backward compatibility but nothing writes it.

## Historical context (predecessor, retired)

The original system was monitoring-based: `brass init` started background agents
(Scout / Watch / Strategist / Planner) that kept intelligence files continuously
fresh. That design traded predictability for freshness and carried background-process
complexity. v2.0 replaced it with the CLI model above. A `watch` subcommand briefly
offered opt-in file-change re-scanning as a bridge, but it was removed in v2.0.9 as
broken/unmaintained — the product is now purely on-demand. The full predecessor tree
is preserved in the `devwatch` archive (see repo-root README).

## Relationship to the architectural principles

This runtime shape exists to keep the four principles enforceable:

- **Single responsibility** — scanners scan, ranker ranks, generator generates.
- **No lateral/upstream dependencies** — data flows one direction only.
- **Sacred `Finding` interface** — the one contract every stage shares (see
  `CLAUDE.md`).
- **One-direction data flow** — Scanners → Ranker → Generator → `.brass/*.yaml`.

Respect them and new capabilities slot in as new scanners/builders without touching
the rest of the system.
