# BrassCoders in CI

This page covers running `brasscoders scan` in continuous integration: cache-mount recipes for the major providers, environment variables that matter in CI, and platform-specific gotchas.

If you're new to BrassCoders's caches, read [`CACHE.md`](CACHE.md) first.

---

## TL;DR

Without a cache mount, **every CI run is a cold scan.** That means every PR pays the full Pysa cold cost (~30–40s on a 5k-file Python project) instead of the warm cost (~3–10s). Mounting `~/.cache/brass/` in CI gives you the 3–4× warm-scan speedup measured in the perf retrospective.

Two paths to cache. The Pysa state cache (`~/.cache/brass/pysa-state/`) is the high-leverage one. The typeshed cache (`~/.cache/brass/typeshed/`) saves ~5s of git-clone time per fresh runner.

---

## GitHub Actions

```yaml
name: BrassCoders scan

on:
  pull_request:
  push:
    branches: [main]

jobs:
  brass:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.13'

      - name: Install BrassCoders
        run: pip install brasscoders
        # bandit, pylint, and pyre-check are pulled in transitively
        # from brasscoders' core dependencies (pinned to
        # versions brass is verified against). No separate install
        # needed — and a separate `pip install pyre-check` could
        # conflict with brass's pin.

      - name: Restore BrassCoders cache
        uses: actions/cache@v4
        with:
          path: |
            ~/.cache/brass/pysa-state
            ~/.cache/brass/typeshed
          key: brass-${{ runner.os }}-${{ hashFiles('pyproject.toml', 'requirements*.txt') }}
          restore-keys: |
            brass-${{ runner.os }}-

      - name: Run BrassCoders
        env:
          BRASS_AUTOFETCH_TYPESHED: '1'   # First run on a fresh cache-key clones typeshed
        run: brasscoders --offline scan
```

### Notes

- **`hashFiles(...)`** keys the cache to your dependency surface. Update the glob if your project pins dependencies elsewhere.
- **`restore-keys: brass-${{ runner.os }}-`** is the fallback: a cache miss on the exact key still restores the most recent same-OS cache, so a dependency bump doesn't force a cold scan.
- **`BRASS_AUTOFETCH_TYPESHED: '1'`** is what lets the first run on a fresh `actions/cache` entry self-bootstrap typeshed. Without it, Pysa silently skips when typeshed is missing. After the first run, typeshed lives in the cache and the env var is a no-op.
- **Autofetch failure mode is also silent.** If the runner can't reach `github.com` (network-restricted, GitHub outage, `git` missing from the image) the clone fails, Pysa skips, and the scan completes with no taint findings — no signal in the build status. For network-restricted runners, pre-populate `~/.cache/brass/typeshed/` as a build step instead and leave `BRASS_AUTOFETCH_TYPESHED` unset.
- **`--offline`** stays on. The autofetch is the one network call BrassCoders makes; everything else stays local.

### Verifying the speedup

Run the workflow twice on the same branch. The second run should show Pysa taking 3–10s instead of 30–40s. The exact numbers are in `.brass/scanner_timings.json` (in the workspace) — surface it with an extra step if you want it in the Actions log:

```yaml
      - name: Show scanner timings
        if: always()
        run: cat .brass/scanner_timings.json
```

---

## GitLab CI

```yaml
brass-scan:
  image: python:3.13
  variables:
    BRASS_PYSA_CACHE_ROOT: "$CI_PROJECT_DIR/.brass-cache/pysa-state"
    BRASS_TYPESHED:        "$CI_PROJECT_DIR/.brass-cache/typeshed"
  cache:
    key:
      files:
        - pyproject.toml
    paths:
      - .brass-cache/
  before_script:
    # bandit/pylint/pyre-check come in transitively from
    # brasscoders as pinned core deps.
    - pip install brasscoders
    - 'if [ ! -d "$BRASS_TYPESHED/stdlib" ]; then git clone --depth 1 https://github.com/python/typeshed "$BRASS_TYPESHED"; fi'
  script:
    - brasscoders --offline scan
  artifacts:
    when: always
    paths:
      - .brass/
```

### Notes

- GitLab's `cache:` stanza only persists paths under `$CI_PROJECT_DIR`. BrassCoders's caches live under `~/.cache/brass/` by default, which is **outside** the workspace and wouldn't be captured. The fix: point BrassCoders at workspace-relative directories with `BRASS_PYSA_CACHE_ROOT` and `BRASS_TYPESHED`, then cache that directory.
- The typeshed `git clone` is explicit rather than relying on `BRASS_AUTOFETCH_TYPESHED=1`, because the autofetch clones into `~/.cache/brass/typeshed/` (the hardcoded default), which `BRASS_TYPESHED` then doesn't see. Explicit clone keeps everything in one workspace-relative location.
- The `key.files` form invalidates the cache when `pyproject.toml` changes — same semantics as the GitHub Actions example.
- `artifacts: paths: [.brass/]` exposes the YAML reports as downloadable build artifacts. Drop this if you only want CI-side validation.

---

## CircleCI

```yaml
version: 2.1

jobs:
  brass-scan:
    docker:
      - image: cimg/python:3.13
    steps:
      - checkout
      - restore_cache:
          keys:
            - brass-v1-{{ checksum "pyproject.toml" }}
            - brass-v1-
      - run:
          name: Install BrassCoders
          # bandit/pylint/pyre-check are pinned core deps of
          # brasscoders, no separate install needed.
          command: pip install brasscoders
      - run:
          name: Run BrassCoders
          environment:
            BRASS_AUTOFETCH_TYPESHED: '1'
          command: brasscoders --offline scan
      - save_cache:
          key: brass-v1-{{ checksum "pyproject.toml" }}
          paths:
            - ~/.cache/brass

workflows:
  scan:
    jobs:
      - brass-scan
```

### Notes

- The `brass-v1-` prefix in the cache key lets you bust the cache deliberately by bumping it to `brass-v2-` (useful when BrassCoders itself ships a `_CACHE_SCHEMA` bump — see [`CACHE.md`](CACHE.md)).
- `cimg/python:3.13` is the CircleCI-maintained Python image; it includes `git`, which the typeshed autofetch needs.

---

## Platform gotcha — `pyre-check` is linux/amd64 only

The pip-distributed `pyre-check` wheel bundles a `pyre.bin` built for **linux/amd64 only.** This affects you if:

- You're running CI on **Apple Silicon self-hosted runners** with default Docker (which pulls linux/arm64 images).
- You're testing BrassCoders locally in Docker on Apple Silicon.

Symptom: Pysa wall time is suspiciously fast (~1s instead of ~30s), and `.brass/brass.log` contains:

```
ƛ Pyre binary is located at `/usr/local/bin/pyre.bin`
ƛ [Errno 8] Exec format error: '/usr/local/bin/pyre.bin'
```

BrassCoders's runtime catches the non-JSON output and emits an empty Pysa findings list. The scan completes "successfully" — but with no taint findings.

Workaround for Apple-Silicon Docker:

```bash
docker run --platform linux/amd64 python:3.13 ...
```

This uses Rosetta emulation under Docker Desktop. Performance is fine for CI workloads — the BrassCoders perf retrospective measured Pysa cold/warm parity within ±10% on emulated linux/amd64 vs native macOS.

GitHub's standard `ubuntu-latest` and `ubuntu-24.04` runners are linux/amd64 by default — nothing to configure. CircleCI's `cimg/*` images are also linux/amd64. GitLab's `image: python:3.13` is also linux/amd64 unless your runner pool is arm64. The gotcha only surfaces on self-hosted Apple Silicon or on a developer laptop's Docker.

---

## Why this is worth the setup

| Scenario | Pysa wall time | Cumulative cost over 100 PRs |
|---|---:|---:|
| Cold scan every PR (no cache) | 30–40 s | ~1 hour |
| Cached, warm scan after first PR | 3–10 s | ~10 minutes |

Numbers from the perf retrospective on a 5k-file Python project. Larger projects compound the difference.

The cache itself is 10–300 MB depending on project size — well under the free-tier limits of all three providers above (10 GB on GitHub Actions, 50 GB on CircleCI free, no documented limit on GitLab cache).

---

## CI-specific env vars

| Env var | Why you'd set it in CI |
|---|---|
| `BRASS_AUTOFETCH_TYPESHED=1` | Let the first scan on a fresh cache key clone typeshed automatically. Default is off; CI is the canonical place to turn it on. |
| `BRASS_PYSA_CACHE_ROOT=/path` | Move the Pysa cache out of `$HOME` if your runner has a constrained `$HOME` mount or you want to share the cache across users on a self-hosted runner. See [`CACHE.md`](CACHE.md) for validation rules. |
| `BRASS_DISABLE_VERSION_CHECK=1` | Suppress BrassCoders's once-per-day update check. CI runs are short and ephemeral; the check is noise. |

All three are read at scan time. Set them in your job's `env:` block or per-step `environment:` map.

---

## Internal regression: end-to-end leak hunt

BrassCoders ships an end-to-end test (`tests/end_to_end/test_no_secrets_in_output.py`) that runs the full pipeline against a synthetic credential-bearing fixture and asserts that no canary credential string appears in any `.brass/` output file. This is the safety net for the redaction layer — any future scanner / output-builder change that introduces a bypass fails this test immediately.

```bash
PYTHONPATH=src python3 -m pytest tests/end_to_end/test_no_secrets_in_output.py
# Runtime: ~1-2s on a warm Pysa cache, ~30s cold
```

The test is part of the standard e2e job. Customers do NOT need to run this — it's brass's own QA. If you fork brass and add a scanner that handles sensitive content, run this test before shipping; it'll fail loudly if your scanner's `detected_by` isn't in `_SECRET_LEAK_DETECTORS` or if your output emits raw `title`/`description` past the sanitizer.

## What's NOT here

- **Self-hosted Apple-Silicon runner setup.** If you need this, mount Docker with `--platform linux/amd64` or skip Pysa via `brasscoders scan --no-pysa`. The other scanners (Bandit, Pylint, semgrep, ast-grep, privacy, content moderation) all run natively on arm64.
- **Air-gapped CI.** If your runners have no GitHub access, pre-populate `~/.cache/brass/typeshed/` as part of the image build step (clone typeshed into the image directly). Leave `BRASS_AUTOFETCH_TYPESHED` unset.
- **Multi-project monorepo bench.** If you scan multiple subprojects in one CI job, each will produce its own `~/.cache/brass/pysa-state/<hash>/` entry. The cache mount above captures all of them. Per-project hashes mean independent invalidation — bumping one project's `pyproject.toml` does not invalidate caches for the others.
