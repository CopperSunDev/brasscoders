#!/usr/bin/env bash
# tests/benchmarks/clone.sh — Track A of the external-benchmarks plan.
#
# Fetches third-party benchmark projects at PINNED COMMIT SHAs into
# `tests/benchmarks/_clones/<project>/` so brass's e2e benchmark tests
# can run against known-vulnerable code with documented expected
# findings.
#
# See `docs/perf/2026-05-17_external_benchmarks_plan.md` for the full
# Safety section. The non-negotiable mitigations baked in here:
#
#   1. Pinned SHAs (not branches/tags) — locks the exact 40-char
#      commit; can't be retroactively rewritten by upstream.
#   2. Canonical org sources only — never forks. Code review enforces.
#   3. Git hooks disabled at clone (`core.hooksPath=/dev/null`).
#   4. `protocol.allow=never` to disable git's ext / file protocols.
#   5. NEVER `pip install` / `npm install` the target's deps — brass
#      scans static files only; transitive supply-chain risk doesn't
#      apply.
#   6. `_clones/` is gitignored — these clones never enter brass's
#      tree; they live in the working dir only.
#
# SHA verification: each pinned SHA below was looked up via
# `git ls-remote <url>` at the time it was added, and matched against
# the upstream project's release tag or announcement (see comments
# inline). If you bump a SHA, leave a note about which release it
# corresponds to so a future reviewer can audit the change.
#
# Idempotent: if a clone dir already exists at the right SHA, skip.
# Re-pinning to a new SHA requires removing the existing clone first.

set -euo pipefail

CLONES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_clones"
mkdir -p "$CLONES_DIR"

# ---------------------------------------------------------------------------
# Pinned projects
# ---------------------------------------------------------------------------
#
# Each entry: project_name|repository_url|commit_sha|upstream_reference
#
# upstream_reference is the human-readable release identifier that
# corresponds to the SHA (e.g. "v2.0.1 release tag", "main branch
# 2026-01-15"). Used by a future `verify_pin.sh` audit script.
PROJECTS=(
    # OWASP PyGoat — Django app demonstrating OWASP Top 10 vulnerabilities.
    # v2.0.1 (latest stable tag as of 2026-05-17). Exercises brass's full
    # Python scanner surface: Pysa, Bandit, ast-grep, Semgrep, privacy,
    # auth_pattern_analyzer.
    "pygoat|https://github.com/adeyosemanputra/pygoat.git|c11e8429349cc05ff38564d3bf7ef09fb2411874|v2.0.1 release tag"

    # OWASP NodeGoat — Express + MongoDB app demonstrating OWASP Top 10
    # vulnerabilities in Node.js. Upstream master HEAD at 2026-05-17 (no
    # release tags published). Exercises brass's JavaScript/TypeScript
    # scanner surface that PyGoat doesn't reach: JavaScriptTypeScriptScanner,
    # auth_pattern_analyzer (JS heuristics), Semgrep JS rules.
    "nodegoat|https://github.com/OWASP/NodeGoat.git|c5cb68a7084e4ae7dcc60e6a98768720a81841e8|master HEAD 2026-05-17"

    # PyCQA Bandit — Python static security scanner. The examples/
    # directory has one file per B-code rule (~50 files); since brass
    # uses Bandit internally via ProfessionalCodeScanner, these
    # examples are the canonical regression suite for "did brass's
    # bandit invocation pipeline lose a B-code?". Pinned to 1.9.4
    # release tag (latest stable as of 2026-05-17).
    "bandit_examples|https://github.com/PyCQA/bandit.git|92ae8b82fb422a639f0ed8d99e96cea769594e08|1.9.4 release tag"

    # Yelp detect-secrets — credential / secret scanner. brass uses
    # this library internally via SecretsScanner; its test fixtures
    # are the canonical "did brass keep up with detect-secrets'
    # detection surface?" regression suite. Pinned to v1.5.0 release
    # (latest stable as of 2026-05-17).
    "detect_secrets_fixtures|https://github.com/Yelp/detect-secrets.git|01886c8a910c64595c47f186ca1ffc0b77fa5458|v1.5.0 release tag"

    # Snyk Goof — modern Node.js demo app with intentionally vulnerable
    # npm dependencies and source patterns. Snyk's canonical training
    # corpus. Pinned to master HEAD as of 2026-05-17 (latest tagged
    # release 1.0.1 is from 2018; HEAD has actively-updated CVE refs).
    "snyk_goof|https://github.com/snyk/goof.git|add14ba59e98240d9e00a235dd7d42cd61ae9912|master HEAD 2026-05-17"

    # --- Track B: larger, customer-shape codebases for noise / perf
    # regression detection. NOT vulnerability-detection benchmarks
    # (Track A's job); these provide a stable scan-time + finding-
    # count baseline that compare.py uses to catch regressions
    # between brass commits.

    # pallets/flask — clean, mature Python web framework (~200 files).
    # Should produce mostly low-severity / informational findings;
    # serves as a NEGATIVE test for noise. A scan that suddenly
    # finds 50 "critical" issues in flask = brass introduced false
    # positives. Pinned to 3.1.3 release (latest stable 2026-05-17).
    "flask|https://github.com/pallets/flask.git|22d924701a6ae2e4cd01e9a15bbaf3946094af65|3.1.3 release tag"

    # tiangolo/fastapi — modern async Python web framework. More
    # extensive type annotations + Pydantic models than Flask;
    # exercises brass's Pysa typeshed integration + AI-context
    # scanner on richer call graphs. Pinned to 0.136.1 release
    # (latest stable 2026-05-17).
    "fastapi|https://github.com/tiangolo/fastapi.git|e54e5a8980ffa6d7ff68ee7b25a1c46036375521|0.136.1 release tag"

    # django/django — large mature web framework (~5000 .py files).
    # Per the external-benchmarks plan, this is the SCALE STRESS
    # TEST — confirms brass can handle a customer-shape large
    # codebase without timing out or producing pathological finding
    # counts. Pinned to 5.2 LTS (5.2.14) for long-term reproducibility.
    # LTS supported until April 2028; safe to keep this baseline
    # stable across many brass releases without bumping.
    # SHA is the dereferenced (annotated-tag-target) commit, not
    # the tag object — Django uses annotated tags, so git checkout
    # against the tag object SHA fails with "unable to read tree".
    "django|https://github.com/django/django.git|024c26b1e77ea5b1b158265167ade47927a64c06|5.2.14 LTS release tag"

    # vercel/commerce — canonical Vercel-published Next.js storefront
    # demo (~65 .ts/.tsx files). Adds JavaScript/TypeScript scanner
    # coverage to Track B's Python-only baselines (flask + fastapi +
    # django). Customer-shape: Next.js 15+ App Router + Server
    # Components, exactly the layout most paying customers would
    # bring to brass. Pinned to main HEAD at 2026-05-17; tag "v1"
    # exists but predates App Router (~1000 files of the old
    # multi-provider architecture — not representative).
    "nextjs_commerce|https://github.com/vercel/commerce.git|1df2cf6f6c935f4782eed27351fa18f276917a4d|main HEAD 2026-05-17"

    # vercel/turborepo — canonical Turborepo monorepo (~1128 JS/TS
    # files across 19 workspace packages). Per the plan, this is
    # the JS/TS counterpart to Django's scale stress test: pnpm
    # workspaces + apps/+packages/ layout = textbook monorepo shape
    # brass needs to handle without choking. Pinned to v2.9.14
    # release tag (latest stable as of 2026-05-17). Lightweight tag
    # → SHA is the commit directly (no annotated-tag deref needed).
    "turborepo|https://github.com/vercel/turborepo.git|fc62fe0d9c347d1d24f0ed8946284856593ddb93|v2.9.14 release tag"
)

clone_at_sha() {
    local name="$1" url="$2" sha="$3" ref="$4"
    local dest="$CLONES_DIR/$name"

    if [[ -d "$dest" ]]; then
        local current
        current="$(git -C "$dest" rev-parse HEAD 2>/dev/null || echo unknown)"
        if [[ "$current" == "$sha" ]]; then
            echo "OK $name: already at $sha ($ref)"
            return 0
        fi
        echo "WARN $name: existing clone at $current != pinned $sha; remove $dest to re-pin" >&2
        return 1
    fi

    echo "-> Cloning $name from $url at $sha ($ref)"
    # core.hooksPath=/dev/null: disable git hooks (defense against
    #   malicious post-checkout hooks in pathological upstream content).
    # protocol.allow=never with explicit https override: only allow
    #   the protocol we explicitly named; reject any ext/file/etc.
    GIT_TERMINAL_PROMPT=0 git \
        -c core.hooksPath=/dev/null \
        -c protocol.allow=never \
        -c protocol.https.allow=always \
        clone --no-tags "$url" "$dest"

    # Some pinned SHAs (especially release-tag commits on long-term
    # support branches like Django's 5.2.x or Turborepo's v2.9.x) are
    # NOT reachable from the default-branch history that `clone
    # --no-tags` fetched. In that case, `git checkout` fails with
    # "unable to read tree". Explicitly fetch the SHA to make it
    # available — idempotent for already-reachable SHAs.
    GIT_TERMINAL_PROMPT=0 git -C "$dest" \
        -c core.hooksPath=/dev/null \
        -c protocol.allow=never \
        -c protocol.https.allow=always \
        fetch --no-tags origin "$sha" 2>/dev/null || true

    # Check out the pinned SHA directly. Fail loudly if it still
    # doesn't exist — that signals upstream rebased / force-pushed
    # history and we need a new SHA, not a silently-different one.
    # Apply the same protocol allowlist as the clone step: a malicious
    # upstream's submodule URLs or gitattributes filters could otherwise
    # invoke ext/file protocols during checkout. Consistent with the
    # "non-negotiable mitigations" documented at top of this script.
    git -C "$dest" \
        -c core.hooksPath=/dev/null \
        -c protocol.allow=never \
        -c protocol.https.allow=always \
        checkout --detach "$sha"

    # Sanity: confirm checkout landed on the expected SHA.
    local got
    got="$(git -C "$dest" rev-parse HEAD)"
    if [[ "$got" != "$sha" ]]; then
        echo "FAIL $name: checkout landed on $got, expected $sha" >&2
        return 1
    fi

    echo "OK $name: cloned at $sha ($ref)"
}

main() {
    # Optional first arg: clone ONLY this project (matches the
    # `name` field). Used by the CI matrix to avoid cloning all
    # benchmark projects on every job (one bad SHA elsewhere would
    # otherwise fail every matrix entry via `set -euo pipefail`).
    # Empty arg = clone everything (the local-developer flow).
    local filter="${1:-}"
    local matched=0
    for entry in "${PROJECTS[@]}"; do
        IFS='|' read -r name url sha ref <<<"$entry"
        if [[ -n "$filter" && "$name" != "$filter" ]]; then
            continue
        fi
        clone_at_sha "$name" "$url" "$sha" "$ref"
        matched=1
    done
    if [[ -n "$filter" && "$matched" -eq 0 ]]; then
        echo "FAIL clone.sh: filter '$filter' matched no project in PROJECTS array" >&2
        return 1
    fi
}

main "$@"
