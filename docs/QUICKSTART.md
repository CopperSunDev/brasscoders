# BrassCoders quickstart

Five minutes from zero to your first AI-readable scan output.

## 1. Install

```bash
pipx install brasscoders
```

Or with `pip` in a virtualenv:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install brasscoders
```

You need Python 3.10 or newer. BrassCoders installs `bandit`, `pylint`, `radon`,
`detect-secrets`, `pyre-check`, `vulture`, `py-spy`, `requests`, and
`PyYAML` as transitive dependencies.

## 2. First scan

```bash
brasscoders --offline scan /path/to/your/project
```

`--offline` guarantees nothing leaves your machine. Drop it once you've
read the [privacy policy](PRIVACY_POLICY.md) and decided whether the
optional `--check-package-hallucination` flag is appropriate for your
codebase.

The scan typically takes 10–60 seconds on a 50k-LOC project, depending on
how aggressive your file count is. BrassCoders excludes `.git`, `node_modules`,
`__pycache__`, virtualenvs, and `.brass/` itself automatically.

## 3. Read the output

After the scan completes, look at `.brass/ai_instructions.yaml`. This is
the file you'd hand to Claude Code, Cursor, or any other coding assistant:

```bash
less /path/to/your/project/.brass/ai_instructions.yaml
```

The structure is:

```yaml
metadata: { ... }
executive_summary:
  risk_level: HIGH | MEDIUM | LOW
  recommendation: ...
  total_findings: N
critical_issues:
  - id: ...
    severity: critical
    file_path: ...
    title: ...
    description: ...
    context:
      file_type: source_code      # or test_file / build_output / ...
      is_production_code: true
      priority_for_ai: HIGH       # HIGH / MEDIUM / LOW
ai_guidance:
  security_focus: [ ... ]
  privacy_compliance: [ ... ]
file_priorities: [ ... ]
quick_actions:
  immediate: [ ... ]
```

For human review:
- **Security drill-down**: `.brass/security_report.yaml`
- **Per-file breakdown**: `.brass/file_intelligence.yaml`
- **Aggregate metrics**: `.brass/statistics.yaml`
- **PII details (if any)**: `.brass/privacy_analysis.yaml`

## 4. Hand off to your AI assistant

Copy the contents of `ai_instructions.yaml` into your Claude Code / Cursor
session and ask the assistant to address the findings in order. The YAML
is intentionally compact so it fits well within most context budgets.

## 5. Iterate with watch mode (optional)

```bash
brasscoders --offline watch
```

Watch mode re-runs the scanners on file changes (polling every 2 seconds,
debounced by 5). This is useful when you're actively editing and want the
intelligence files to stay current.

## What to do when something looks wrong

- **The output flagged a real test card / dummy SSN.** This is expected for
  unfamiliar layouts. The scanner downgrades severity for files inside
  `tests/`, `__tests__/`, `spec/`, etc., but if your repo uses an unusual
  test directory, the finding will still appear at MEDIUM. You can ignore
  these or adjust your layout.

- **A real credential is in `ai_instructions.yaml`.** It shouldn't be —
  BrassCoders redacts secret values before persisting. If you find a raw
  credential string in any `.brass/*.yaml` file, that's a security bug;
  please file an issue.

- **The scan took too long.** Use `brasscoders scan --fast` to skip the
  privacy and content moderation passes. Or use `--dev` to scan only
  source files (excluding tests).

- **You see "ModuleNotFoundError" on first run.** You're on a stale install;
  run `pip install -e .` again from the repo root. Versions before this
  document existed didn't pin the runtime deps.
