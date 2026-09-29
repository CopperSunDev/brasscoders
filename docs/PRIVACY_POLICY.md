# BrassCoders — privacy & data-handling policy

_Last updated: 2026-09-29. Bound to release 2.1.0 (opt-in usage telemetry)._

This document is the customer-facing summary. For the full technical
breakdown — what's transmitted on the wire, what's persisted in Redis,
what subprocessors see, what we log, and what compliance certifications
we do and do not hold — see [`DATA_HANDLING.md`](DATA_HANDLING.md).

This document tells you exactly what BrassCoders reads, what it writes, and what
(if anything) leaves your machine. If anything in this document is incorrect
or out of date, that is a bug — please file an issue.

## What BrassCoders reads

BrassCoders scans files inside the directory you point it at (the *project root*).
For each file under that root, BrassCoders:

1. Skips it if any path component is in the exclusion list (`.git`,
   `__pycache__`, `node_modules`, `.venv`, `venv`, `build`, `dist`, `.brass`,
   etc.). See `src/brass/scanners/file_prefilter_scanner.py`.
2. Skips it if the resolved path falls outside the project root, even via a
   symlink. (See `src/brass/core/path_safety.py`.)
3. Skips files larger than 1 MiB.
4. Reads the file content into memory.
5. Runs the relevant scanner suites (security, privacy, code quality,
   performance, secrets, content moderation).

BrassCoders does **not** read files outside your project root.

## What BrassCoders writes

BrassCoders creates a `.brass/` directory inside the project root and writes:

- `ai_instructions.yaml` — top-level summary
- `detailed_analysis.yaml` — every finding, grouped by type
- `file_intelligence.yaml` — findings collated per file
- `security_report.yaml` — security-only view
- `statistics.yaml` — aggregate metrics
- `privacy_analysis.yaml` — present only when PII findings exist
- `brass.log` — diagnostic log

The `.brass/` directory is created with permissions `0700`; the YAML files
are written with `0600` (POSIX). On Windows, BrassCoders relies on filesystem ACLs.

### Redaction in output

The privacy scanner exists to *detect* sensitive data; it would defeat the
purpose to write the raw matched data into `.brass/`. BrassCoders enforces this in
two places:

1. **At the source.** `Brass2PrivacyScanner._redact_pii_metadata` runs after
   the scanner's suppression heuristic and before the finding is returned. It
   replaces the raw matched value with a masked version (e.g.
   `4111****1111`), drops the surrounding `context_line` and `code_snippet`
   entries, and clears the top-level `Finding.code_snippet` field for any
   privacy finding.
2. **At the boundary.** `BaseYAMLBuilder.sanitize_metadata_for_serialization`
   strips a known set of privacy-sensitive metadata keys
   (`matched_text`, `code_snippet`, `context_line`, `raw_match`, `context`)
   from any finding whose type is `PRIVACY` before YAML serialization.

The hardcoded-credential detection path
(`AIAuthPatternAnalyzer._redact_secret_in_line`) replaces literal values
inside string quotes with `<REDACTED>` before persisting the line.

The secret scanner records only the secret *type* and a short hash for
de-duplication. The secret value itself is never written to disk by BrassCoders.

## What leaves your machine

BrassCoders makes **no outbound network calls by default.**

The single optional network path is the *package-hallucination check*. When
enabled, BrassCoders takes each imported package name from your code and issues
HTTPS GETs to the relevant registry to confirm it exists:

| Language | Endpoint |
|---|---|
| Python | `https://pypi.org/pypi/<name>/json` |
| JavaScript | `https://registry.npmjs.org/<name>` |
| Go | `https://pkg.go.dev/<name>` |

This check is **off by default** and must be opted into per scan via
`--check-package-hallucination`. Passing `--offline` overrides the opt-in
back to off; that flag is the canonical way to assert "do not let anything
leave my machine."

You should not enable the package-hallucination check on a project that
imports private internal package names. Doing so would leak those names to
the public registry.

BrassCoders has no error reporting, crash reporting, or auto-update
mechanism. Outside a paid enrichment scan, two things can touch the network:

- `brasscoders version` (only that command) may make one HTTPS request to
  PyPI to tell you whether a newer release exists. It is skipped under
  `--offline` or `BRASS_DISABLE_VERSION_CHECK=1`.
- **Usage telemetry, which is off by default.** After your first successful
  interactive scan, BrassCoders asks once (default No; never in CI, never
  without a terminal, never under `--offline`). If you opt in, each scan
  sends one small anonymous event to Copper Sun's gateway (stored in
  Axiom): the count of findings by type and severity, whether `--fast` or
  `--dev` was used, the CLI version, your OS name, and a random install ID
  that identifies the install, not you. It never includes source code, file
  paths or names, emails, license keys, or stack traces, and it is always
  suppressed by `--offline`. Every event is also written to
  `~/.brass/telemetry-debug.log` so you can inspect it. Change your mind
  any time with `brasscoders telemetry on | off | status | reset`. The
  exact field list, transport, and storage details are in
  `DATA_HANDLING.md`.

## What BrassCoders refuses to do

- BrassCoders refuses to follow symlinks pointing outside the project root, even
  if the symlink itself is inside the project. This prevents a hostile repo
  from steering a scan into `~/.aws/credentials` or `~/.ssh/id_rsa`.
- BrassCoders refuses to inherit user/system git config when invoking `git`, to
  prevent CVE-2022-24765-class repos from achieving code execution during
  the scan-time git health check.
- BrassCoders synthetic performance scripts (`brasscoders scan --performance-full`)
  run via `python3 -I` in a minimal env, and the script bodies are static
  templates — no metadata interpolation is permitted.

## Reporting a privacy or security issue

Email `info@coppersun.dev` with a description and reproduction steps. We
treat unauthorized data egress, raw-PII serialization, and silent network
calls as launch-blocking bugs and will respond accordingly.
