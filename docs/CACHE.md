# BrassCoders caches

BrassCoders keeps two on-disk caches under `~/.cache/brass/` to make repeat scans fast. This page explains what each one is, when it grows, when it's invalidated, and how to inspect or clear it.

If you're setting up CI, see [`CI.md`](CI.md) for cache-mount recipes for GitHub Actions, GitLab CI, and CircleCI.

---

## TL;DR

| Cache | Path | Size profile | What it stores |
|---|---|---|---|
| Pysa state | `~/.cache/brass/pysa-state/<hash>/` | 10–300 MB / project | Pyre call graph + taint model query results — the warm-scan speedup |
| Typeshed | `~/.cache/brass/typeshed/` | ~33 MB | Python stdlib type stubs; required for Pysa to resolve stdlib calls |

Both caches are safe to delete at any time. The next scan will rebuild whatever it needs (slower than warm, no correctness impact).

---

## The Pysa state cache

### Where it lives

`~/.cache/brass/pysa-state/<hash>/` — one subdirectory per scanned project. The `<hash>` is the first 16 hex chars of `sha256("v1|" + resolved_project_path)`, where `v1` is the on-disk cache schema version (`_CACHE_SCHEMA` in `src/brass/scanners/pysa_taint_scanner.py`).

This means:

- Scanning the same project from two different working directories — e.g. `brasscoders scan ./foo` vs `brasscoders scan /abs/path/to/foo` — produces the **same** hash (the path is resolved before hashing) and reuses the same cache.
- Scanning two different projects produces two independent caches. Caches do not cross-contaminate.

### Size profile

Empirically 10–300 MB per project, depending on:
- Python file count
- Decorator and metaprogramming density
- The size of the call graph Pyre needs to build

A customer scanning ~10 projects will accumulate roughly 1–3 GB of state. Stale entries are auto-pruned (see [Stale-entry pruning](#stale-entry-pruning) below); a manual `brasscoders cache clear` is still the way to free everything at once.

### When the cache speeds things up

Pysa is the slowest scanner BrassCoders runs. On a 5k-file Python project the cold scan is ~30–40 seconds; the warm scan (with the cache hit) is ~3–10 seconds — a **3–4× speedup**. The BrassCoders perf retrospective measured 3.52× on `brass-v2` self-scan and 3.91–4.22× on the `vulnerable-flask-app` fixture across macOS and Linux.

If you scan the same project repeatedly (CI per-PR, watch mode, iterative dev) and you're not seeing the warm speedup, your cache is being deleted between runs. CI users: see [`CI.md`](CI.md). Local dev: check that `~/.cache/brass/pysa-state/` exists and has subdirectories.

### When the cache is invalidated automatically

Three triggers, all on the next scan after the change:

1. **Schema bump.** When BrassCoders ships a new Pyre/Pysa integration that's incompatible with the prior cache layout, `_CACHE_SCHEMA` increments (`v1` → `v2`). This changes every project's hash, so all old caches become unreachable and the new scan starts cold. **Reclaim is automatic**: a sentinel file `<cache_root>/.schema` tracks the schema version that produced the current contents; on the first scan after a bump, BrassCoders sweeps the orphaned `<hash>/` directories and writes the new value. Concurrency-safe via an exclusive `fcntl` lock at `<cache_root>/.gc.lock` — concurrent scans on different projects block until the sweep completes, so no scan races against the rmtree. The sweep is a single-pass `rmtree` over the orphans (allow a minute or two if you're sitting on a multi-GB cache from a long-running install), and it's a no-op in the steady state.

2. **Config drift.** Each cache dir contains a `config.sig` file — a hash of the inputs that should invalidate the cached call graph (the `.pyre_configuration` BrassCoders writes + the bundled taint models' mtime). If those inputs change between scans, BrassCoders wipes the cache dir and recreates it. This catches changes to bundled models on BrassCoders upgrades automatically.

3. **Corruption recovery.** If Pyre exits with non-parseable output (cache file truncated, partial write from a killed process, etc.), BrassCoders wipes the cache dir once and retries the scan. Second non-parseable result and BrassCoders gives up and returns an empty Pysa findings list rather than crash. The warning appears in `.brass/brass.log`.

### Stale-entry pruning

When the cache root grows beyond ~200 MB, BrassCoders automatically prunes per-project cache entries whose source directory no longer exists on disk. This catches the common accumulation pattern: pytest temp-dir scans (`/tmp/pytest-*`), one-off audits of throwaway repos, and old branches whose worktrees have been removed.

Detection uses two paths:

1. **Manifest-based (preferred).** Each cache entry written by BrassCoders ≥ 2026-05-16 contains a `.source_path` file recording the absolute resolved source dir at scan time. If `Path(content).exists()` is `False`, the entry is pruned.
2. **Mtime-based fallback.** Entries without a manifest (pre-fix legacy entries) are pruned if the directory's mtime is older than 90 days. Active long-running projects whose mtimes refresh on each scan are not touched.

The prune runs as part of `_run_pysa()`, holds the same `.gc.lock` as the schema-orphan reclaim (so concurrent scans serialize cleanly), and is best-effort: any individual `rmtree` failure is logged and the next entry is processed.

The cache footer's `project caches` count drops after a prune pass, which can look surprising the first time but reflects the actual state — see the 2026-05-16 footer-wording fix (see commit 14d1b54 in the archived brass-v2 repo, pre-2026-05-18 monorepo migration) for context.

### When you need to clear it manually

The schema bump above only changes the hash; it doesn't free the disk. To actually reclaim space:

```bash
brasscoders cache clear                    # Clear Pysa state caches
brasscoders cache clear --include-typeshed # Also clear the typeshed cache
brasscoders cache clear --dry-run          # Preview what would be removed
```

`brasscoders cache clear` respects `BRASS_PYSA_CACHE_ROOT` — it clears whatever location the var points at, not the hardcoded default. The typeshed clear always targets `~/.cache/brass/typeshed/`; `BRASS_TYPESHED`-redirected paths are user-owned and left untouched.

**Heads-up on `BRASS_PYSA_CACHE_ROOT`:** `brasscoders cache clear` removes every subdirectory under the path you set. Point this env var only at a directory you own and treat as a brass-managed cache. The validation in [§ `BRASS_PYSA_CACHE_ROOT`](#brass_pysa_cache_root--relocating-the-cache) rejects system paths (`/etc`, `/usr`, etc.) — but a user-owned path like `~/Documents/important-project` would pass validation and have its subdirs removed. The blocklist defends against catastrophic accidents, not against pointing the cache at the wrong user-owned directory.

**Do not run `brasscoders cache clear` during an active `brasscoders scan`.** The two failure modes are concrete: (a) the clear's `rmtree` may fail mid-tree with `ENOENT` as the scan creates new cache files concurrently — you'll see a partial-success message and exit code 1; (b) more insidiously, the scan's `.lock` file may be removed underneath an in-flight Pysa analysis, leading to silently corrupt cache state that breaks the *next* scan rather than the current one. Run scans to completion, then clear.

If you need to clear by hand (recovering from a partial state, scripting around an old BrassCoders version):

```bash
rm -rf ~/.cache/brass/pysa-state/
```

This deletes every project's cache. The next scan on each project will rebuild from scratch.

### Concurrency

Each cache dir has a `.lock` file. Pysa acquires an exclusive non-blocking `fcntl.flock` before reading or writing — two `brasscoders scan` invocations against the same project run safely: one wins the lock and runs Pysa normally; the second sees the lock held and skips Pysa (with a warning) rather than risk silent cache corruption. Other scanners (Bandit, Pylint, semgrep, etc.) run normally in both invocations.

`fcntl` is available on Unix and macOS. On Windows the locking is a no-op with a one-time warning. BrassCoders doesn't officially target Windows for Pysa anyway.

### `BRASS_PYSA_CACHE_ROOT` — relocating the cache

If the default `~/.cache/brass/pysa-state/` doesn't fit your environment — e.g. CI runners with a constrained `$HOME` mount, a faster scratch filesystem — point BrassCoders at a different root:

```bash
BRASS_PYSA_CACHE_ROOT=/mnt/fast-scratch/brass brasscoders scan .
```

The variable accepts an absolute or `~`-expanded path. The override **replaces the entire default root**, including the `pysa-state` segment. Per-project caches land directly at `<override>/<hash>/`, not at `<override>/pysa-state/<hash>/`.

BrassCoders validates the override before use:

- The raw input and its resolved form are both checked against an unsafe-roots blocklist: `/`, `/bin`, `/etc`, `/lib`, `/Library`, `/private`, `/sbin`, `/System`, `/tmp`, `/usr`, `/var`. Either match → silently fall back to the default. The raw-input check is necessary on macOS, where `/etc`, `/var`, and `/tmp` symlink-resolve to 3-component `/private/*` paths that would otherwise slip past the resolved-only check.
- The resolved path must have at least 3 path components. `/` (1 component) and `/foo` (2 components) are rejected.
- The path must be resolvable. Unresolvable paths fall back to the default with a warning.

This is defense against an accidental shell assignment doing damage during corruption recovery (which calls `shutil.rmtree`).

The variable is most useful for **test isolation** (the BrassCoders test suite uses it to redirect to `tmp_path`) and for **CI cache mounts** where the cache lives on a tool-managed volume. See [`CI.md`](CI.md) for the CI side.

---

## The typeshed cache

### Where it lives

`~/.cache/brass/typeshed/` — a shallow clone of the [python/typeshed](https://github.com/python/typeshed) repository. About 33 MB on disk.

Pysa needs typeshed to resolve calls into the Python standard library (anything from `os.system` to `sqlite3.Cursor.execute`). Without typeshed, Pyre emits zero findings even on obviously vulnerable code, and the silent-fail mode is hard to debug.

### How BrassCoders finds it

`TYPESHED_SEARCH_PATHS` (in `src/brass/scanners/pysa_taint_scanner.py`) tries three locations in order:

1. `/tmp/typeshed`
2. `~/.cache/brass/typeshed`
3. `/opt/typeshed`

Override with the `BRASS_TYPESHED` env var:

```bash
BRASS_TYPESHED=/my/custom/typeshed brasscoders scan .
```

The override is validated against the presence of a `stdlib/` subdirectory; a bogus path falls back to the search list with a warning.

### Auto-fetching

If no typeshed is found in any of those locations, BrassCoders can clone it automatically — but only when you opt in:

```bash
BRASS_AUTOFETCH_TYPESHED=1 brasscoders scan .
```

This is opt-in (off by default) because it makes a network call to GitHub on the first scan. The clone is shallow (`--depth 1`) and runs under a sandboxed env so customer `GIT_*` overrides can't redirect it. After the first successful fetch, the cache is reused on subsequent scans.

For CI environments without network access during the test job, pre-populate the cache as a build step or include typeshed in your CI cache mount. See [`CI.md`](CI.md).

### When it's invalidated

Never automatically. Typeshed evolves slowly, and a stale clone produces correct-but-slightly-outdated Pysa results — not a silent failure. If you want fresh stubs:

```bash
rm -rf ~/.cache/brass/typeshed
git clone --depth 1 https://github.com/python/typeshed ~/.cache/brass/typeshed
```

### `/tmp/typeshed` won't survive a reboot on macOS

macOS purges `/tmp` on reboot. If you've been using the `/tmp` location, expect to re-clone after each reboot — or move to `~/.cache/brass/typeshed/` for persistence.

---

## What's NOT cached

For completeness:

- **Semgrep rules.** Re-loaded on every invocation (~1s warm-up). Semgrep-OSS has no native cache equivalent to Pysa's `--use-cache`.
- **Bandit / Pylint configs.** Re-parsed on every chunk of files; the cost is amortized by per-chunk subprocess batching (Perf #3 in the arc).
- **ast-grep rules.** Loaded once per scanner invocation.
- **BrassCoders's own intelligence-ranker scores.** Computed fresh from findings each scan; deterministic given identical input.

---

## Cache size awareness

After every scan, BrassCoders prints a one-line cache footer when the Pysa cache crosses size thresholds:

- **Below 100 MB:** silent (one typical project ≈ 10–300 MB; a single populated cache isn't "growing unbounded").
- **100 MB – 1 GB:** info — `🧹 BrassCoders cache: N projects, X MB (run 'brasscoders cache clear' to free)`
- **Above 1 GB:** warning — `⚠️ BrassCoders cache is X GB across N projects. Consider 'brasscoders cache clear --include-typeshed' to reclaim disk space.`

Suppress the footer entirely with `BRASS_QUIET_CACHE=1` — recommended for CI and power-user environments where the noise outweighs the awareness signal.

## Related env vars at a glance

| Env var | Default | Purpose |
|---|---|---|
| `BRASS_PYSA_CACHE_ROOT` | `~/.cache/brass/pysa-state/` | Relocate the Pysa per-project cache root |
| `BRASS_TYPESHED` | (unset; search list applies) | Force a specific typeshed location |
| `BRASS_AUTOFETCH_TYPESHED` | `0` (off) | Clone typeshed automatically when missing |
| `BRASS_QUIET_CACHE` | `0` (off) | Suppress the post-scan cache-size footer |

All four are read at scan time, not at install. Setting them in your shell, your CI environment, or a `.env` your shell auto-loads will all work.
