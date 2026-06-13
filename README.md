# BrassCoders — catches what AI assistants structurally miss

BrassCoders scans a codebase and produces a small set of structured intelligence files
(`.brass/*.yaml`) designed to be read by Claude Code, Cursor, or any other AI
coding assistant. The goal is to surface what matters — real security risks,
PII leaks, performance pitfalls — and hide what doesn't, so the AI's review
stops drowning useful signal in low-confidence noise.

BrassCoders is a **deterministic, local, free pre-merge gate**: the same scan on
the same code produces the same findings every run — no API call, no tokens, no
per-run cost. It runs automatically in CI without anyone needing to ask. There is
no background daemon, no telemetry by default, and no outbound network calls
unless you opt in.

## What it produces

After `brasscoders scan`, you'll find these files in `.brass/`:

| File | Purpose |
|---|---|
| `ai_instructions.yaml` | Top-level summary an AI should read first |
| `detailed_analysis.yaml` | Every finding, grouped by type |
| `file_intelligence.yaml` | Findings collated per file, ranked by priority |
| `security_report.yaml` | Security-only view (secrets, injection, auth issues) |
| `statistics.yaml` | Aggregate counts and severity distribution |
| `privacy_analysis.yaml` | Privacy-only view (only when PII findings exist) |

Output directory permissions are `0700`; individual files are `0600`. BrassCoders
scans private source code, so this is enforced rather than opt-in.

## What it detects

| Category | Source |
|---|---|
| Secrets (AWS, Azure, GitHub, GitLab, Slack, Stripe, NPM, PEM, JWT, …) | [`detect-secrets`](https://github.com/Yelp/detect-secrets) |
| Code-quality issues (complexity, dead code, common bugs) | Bandit + Pylint + Radon + AST patterns |
| PII (credit card, SSN, IBAN, NHS, NINO, Aadhaar, PAN, NRIC, Medicare, TFN) | Pattern + Luhn-validated regex |
| AI-coder anti-patterns (string concat in loops, insert-at-zero, nested loops, eval-on-input) | BrassCoders-specific AST analysis |
| Authentication anti-patterns (hardcoded secrets, weak JWT, no rate limit) | BrassCoders-specific regex |

Findings are de-duplicated and noise-filtered before they hit disk.

## Supported languages

BrassCoders is **Python-first**. The scanners that drive deepest analysis — Pysa
(interprocedural taint), Bandit, Pylint, and the BrassCoders-specific AI-coder
anti-pattern detectors — are Python-only.

| Language | Coverage | Notes |
|---|---|---|
| Python | Full | Interprocedural taint, security, quality, anti-patterns |
| JavaScript / TypeScript | Pattern-level | Intraprocedural Semgrep OSS rules; no interprocedural taint |
| Other | Best-effort | Secrets detection and generic patterns where applicable |

For JS-heavy applications that need deep taint analysis, BrassCoders should
be paired with a JS-specific SAST (CodeQL, etc.). The BrassCoders team is
tracking JS taint quality as a known pre-launch limitation.

## Install

```bash
# Recommended — CLI tool, isolated env.
pipx install brasscoders

# Or with pip.
pip install brasscoders

# Verify:
brasscoders --help
```

BrassCoders requires Python 3.10+ and pulls in `PyYAML`, `requests`, `bandit`,
`pylint`, `radon`, `vulture`, `detect-secrets`, and `pyre-check` as runtime
dependencies. The `requests` library is only used when you explicitly opt
into network checks (see `--check-package-hallucination` below). `pyre-check`
is pinned to a narrow version window (`>=0.9.25,<0.10`) because the Pysa
model file format has been unstable across minors; bumping requires a
verification pass on the bundled model lines.

Python 3.10 is the minimum because the recommended Semgrep version
(1.143.0+, for multicore parallelism — see below) is not available on
PyPI for Python 3.9.

**Optional**: install Semgrep for additional pattern-based taint detection.
BrassCoders recommends version 1.143.0 or later, which enables multicore
parallelism for ~3× faster scans on large repos:

```bash
pip install 'semgrep>=1.143.0'
```

## Supported platforms

| OS | Status | Notes |
|---|---|---|
| macOS (Apple Silicon + Intel) | ✅ supported | Native; primary dev target |
| Linux x86_64 | ✅ supported | Primary CI target |
| Linux arm64 | ⚠️ partial | Every scanner except Pysa works natively. `pyre-check` ships a `pyre.bin` built for linux/amd64 only — Pysa skips with a clear status on arm64 Linux. |
| Windows native | ❌ not supported | Use WSL2 |
| Windows via WSL2 | ✅ supported | Treat as Linux |

**Why Windows native isn't supported:**

- The interprocedural taint scanner (Pysa) is built on Meta's Pyre, which has no Windows support.
- `fcntl.flock` cache concurrency protection is Unix-only — BrassCoders warns and proceeds unlocked on Windows.
- `ProcessPoolExecutor` batched Bandit/Pylint scanning was validated on `fork` (Linux/macOS); Windows `spawn` semantics are untested.

Bringing Windows native to supported status is weeks-to-months of work (replace or sandbox Pyre/Pysa; add a Windows `flock` alternative; spawn-safe ProcessPool rewrites). Not on the v1 roadmap.

For Docker users on Apple Silicon: pin `--platform linux/amd64` so Pyre's bundled binary runs under Rosetta emulation. See [`docs/CI.md`](docs/CI.md) for the recipe.

## Usage

```bash
# One-shot scan of the current directory.
brasscoders --offline scan

# Watch mode: re-run incrementally on file changes.
brasscoders --offline watch

# Show last analysis summary.
brasscoders status

# Print version and which components are available.
brasscoders version
```

### First-scan note: typeshed bootstrap for Pysa

The interprocedural taint scanner (Pysa) needs Python's [typeshed](https://github.com/python/typeshed) stubs to resolve stdlib calls. BrassCoders doesn't bundle typeshed (~33 MB) and is offline-by-default, so on a fresh install Pysa skips with a clear "typeshed not found" status until you bootstrap it. The simplest path is the one-time autofetch flag:

```bash
# First scan only — let brass git-clone python/typeshed on demand.
BRASS_AUTOFETCH_TYPESHED=1 brasscoders --offline scan
```

This makes one outbound `git clone` call to GitHub the first time (no other network use; the rest of `--offline` semantics still hold). Subsequent scans reuse the cached typeshed at `~/.cache/brass/typeshed/` with no network access.

If your environment can't reach GitHub during scans, clone typeshed once into the cache location instead:

```bash
git clone --depth 1 https://github.com/python/typeshed ~/.cache/brass/typeshed
```

See [`docs/CACHE.md`](docs/CACHE.md) for the full typeshed-cache lifecycle.

### Network policy

BrassCoders is **offline by default**. The only outbound network surface is the
package-hallucination check, which validates imported package names against
PyPI / npm / pkg.go.dev. That check is disabled unless you pass
`--check-package-hallucination`. Pass `--offline` to make absolutely sure
nothing leaves your machine — it overrides the opt-in flag.

```bash
# Hard offline mode — nothing leaves your machine.
brasscoders --offline scan

# Opt in to the hallucination check (sends imported package names to public
# registries; do not use on closed-source code with private imports).
brasscoders scan --check-package-hallucination
```

### Scan modes

```bash
brasscoders scan --fast       # Quick: code analysis only, no privacy/content
brasscoders scan --dev        # Source-only: skip tests/build artifacts
brasscoders scan --code       # Just bugs / security / quality
brasscoders scan --privacy    # Just PII detection
brasscoders scan --content    # Just content moderation
```

## Performance and caching

BrassCoders caches Pysa's call-graph state at `~/.cache/brass/pysa-state/` so repeat
scans run 3–4× faster than cold. The cache is per-project, auto-invalidates on
config drift, and is safe to delete at any time. See
[`docs/CACHE.md`](docs/CACHE.md) for the full lifecycle (location, size profile,
invalidation triggers, `BRASS_PYSA_CACHE_ROOT` env var, typeshed cache).

Running BrassCoders in CI? See [`docs/CI.md`](docs/CI.md) for cache-mount recipes for
GitHub Actions, GitLab CI, and CircleCI — without a cache mount, every CI run
pays the full cold-scan cost.

## Privacy & data handling

- BrassCoders never sends your source code anywhere. The only outbound calls are
  the optional package-hallucination registry checks described above.
- The privacy scanner detects PII and writes findings to disk *with the
  matched values redacted*. Raw matched text is replaced with a masked form
  before serialization; raw context lines are dropped entirely.
- The secret scanner records the secret *type* and a short hash for
  de-duplication. The raw secret value is never persisted.
- See [`docs/PRIVACY_POLICY.md`](docs/PRIVACY_POLICY.md) for the full
  disclosure.

## Architecture

```
CLI ──► Scanners ──► IntelligenceRanker ──► YAMLOutputGeneratorV2 ──► .brass/*.yaml
```

Each scanner is single-purpose and returns `List[Finding]`. The ranker
weights and orders. The output generator writes atomic, owner-only YAML.
There is no background process, no scheduler, and no inter-scanner
communication.

The `Finding` dataclass at `src/brass/models/finding.py` is the system's
single contract; all builders, scanners, and the ranker depend on it but
not on each other.

## License

Apache 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
