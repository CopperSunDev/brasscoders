# Security policy

## Reporting a vulnerability

Email **brass@coppersuncreative.com** with a description and reproduction
steps. We treat the following as launch-blocking and will respond within
one business day:

- Unauthorized data egress (BrassCoders making any network call beyond the
  documented opt-in `--check-package-hallucination` path)
- Raw PII or credential material persisted in `.brass/*.yaml`,
  `.brass/brass.log`, or any other on-disk artifact
- Path traversal that lets a scanned project read files outside its
  project root
- Code execution from scanning a malicious project (CVE-2022-24765-class
  git config inheritance, RCE through subprocess env injection, etc.)
- License-system attacks against a published BrassCoders build (forging
  activation results, bypassing the LS validate path, escalating a
  trial record to active paid status on disk)

Please do not open a public GitHub issue for any of the above until a fix
has shipped.

## What's in scope

BrassCoders is a CLI that reads source files and writes summaries to disk. The
threat model centers on:

1. A user scanning untrusted source code (a repo they didn't author)
2. A user with a BrassCoders license key trying to spoof a higher-tier license
3. Network-borne attacks against the (opt-in) PyPI / npm / pkg.go.dev
   validation calls

## What's out of scope

- Vulnerabilities in our upstream dependencies (`detect-secrets`, Bandit,
  Pylint, Radon, `requests`). Report those to the respective maintainers;
  we'll bump the pin once they fix.
- Vulnerabilities specific to a fork of BrassCoders that has modified the
  LemonSqueezy endpoints in `src/brass/licensing/lemonsqueezy.py`.
- DoS scenarios where an extremely large project takes a long time to
  scan. Performance tuning is welcome via PR; not a security issue.

## Closed findings

The following classes of issue have been audited and closed; you can read
the implementation as authoritative:

- **CVE-2022-24765-class git config inheritance** — `_check_git_health`
  passes a sandboxed env (`GIT_CONFIG_GLOBAL=/dev/null`,
  `GIT_CONFIG_SYSTEM=/dev/null`, `GIT_CONFIG_NOSYSTEM=1`). All other
  static-analysis subprocesses (Bandit, Pylint, Babel, py-spy) follow the
  same pattern.
- **Symlink-escape during file walking** — every scanner that uses
  `Path.rglob` enforces `path_safety.is_within` before reading.
- **Raw secret/PII in serialized output** — every code path that flags
  credentials masks the matched value at scanner construction time, and
  `BaseYAMLBuilder.sanitize_finding_for_serialization` strips
  privacy-sensitive metadata at the YAML boundary as defense in depth.
- **License-system attacks** — license keys are issued and tracked by
  LemonSqueezy. Activation, validation, and deactivation all go through
  `https://api.lemonsqueezy.com/v1/licenses/*`; LS owns the source of
  truth for which keys are active and how many seats they cover. The
  on-disk record at `~/.brass/license` is the validated cache, not the
  authority — tampering with it cannot escalate a trial to active paid
  status because the next weekly validate call goes back to LS. The CLI
  ships
  no signing keys and has no seller-side minting code.
- **File permissions** — `.brass/` is created with `0700`, files written
  via `AtomicFileWriter` get `0600` (POSIX). On Windows we rely on
  filesystem ACLs.

## Coordinated disclosure

If you'd like to be credited, include a name / handle and a link in your
report. We'll add it to the changelog entry for the fix release.
