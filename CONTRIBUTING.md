# Contributing to BrassCoders

BrassCoders is an MIT-licensed open-source CLI. Contributions are welcome.
This file is short on purpose: read it once, then go look at the code.

## Quick start

```bash
git clone https://github.com/coppersun/brass.git
cd brass/new_brass_system
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

You should see `~389 passed` in well under a minute. If something fails on
your machine first try, that's a real bug — file an issue with the output.

## Running BrassCoders against itself

The fastest way to make sure your change didn't regress anything is to scan
the BrassCoders codebase with the version of BrassCoders you just built:

```bash
brasscoders --offline scan
cat .brass/ai_instructions.yaml | head -60
```

If the output suddenly starts emitting build-artifact noise, raw
credentials, or hangs, your change broke something — undo and try again.

## Architecture

Read `ARCHITECTURE.md` first. BrassCoders is organized as:

```
CLI ──► Scanners ──► IntelligenceRanker ──► YAMLOutputGeneratorV2 ──► .brass/*.yaml
```

Every scanner returns `List[Finding]`; the ranker reorders; the output
generator writes atomic, owner-only YAML. `Finding` is the system's single
contract — don't break it.

## Hard constraints

These come from the launch plan. Don't ship a PR that violates them.

- **Zero outbound network calls by default.** The only opt-in network
  surface is `--check-package-hallucination`. New scanners must not phone
  home.
- **No raw secrets/PII in serialized output.** The privacy scanner exists
  to *detect* such material; persisting it would defeat the purpose.
  `BaseYAMLBuilder.sanitize_finding_for_serialization` is the canonical
  redaction layer; don't bypass it.
- **POSIX file perms `0700` on `.brass/`, `0600` on contents.** New writers
  must go through `AtomicFileWriter` to inherit this.
- **No subprocess inheriting parent env.** Bandit, Pylint, Babel, py-spy,
  git, all run in a sandboxed env (see
  `professional_code_scanner._sandboxed_subprocess_env` for the pattern).

## Adding a scanner

See `docs/developer-guide/ADDING_NEW_SCANNERS.md` if it exists; otherwise
copy-paste from `src/brass/scanners/secrets_scanner.py` (the most recent
example) and follow its pattern:
- `def __init__(self, project_path: str)`
- `def scan(self, file_paths: Optional[List[str]] = None) -> List[Finding]`
- File discovery via `path_safety.is_within` + `file_classifier`
- Findings have stable IDs, bounded `code_snippet`, no raw secrets

## Testing

- Add a `tests/unit/test_<your_module>.py` for new modules. Aim for
  contracts (what the function guarantees), not implementation.
- Add an end-to-end assertion in `tests/end_to_end/test_complete_workflow.py`
  if your change affects the YAML output.
- Don't add network-dependent tests. The CI pipeline runs with
  `BRASS_DISABLE_VERSION_CHECK=1`; assume you have no internet.

## Pull requests

Open against `main`. The CI workflow at `.github/workflows/test.yml` will
run the suite on Python 3.9 / 3.10 / 3.11 / 3.12 and try a clean
self-scan as a smoke test. PRs that break either are rejected.

Keep changes scoped. A PR that fixes one thing and refactors three
unrelated things is hard to review.

## Reporting security issues

See `SECURITY.md`. Don't open a public issue for security vulnerabilities.
