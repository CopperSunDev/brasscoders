#!/usr/bin/env python3
"""Run brasscoders across the canonical real-world projects and emit
a comparable benchmark report.

The projects:
  brass-seo               — Next.js SEO marketing site (7-round triage)
  copper-sun              — Turborepo SaaS starter + Modal/ML
  whisperx-production     — Next.js + speech-to-text ML
  brass CLI               — self-scan target (conflict-of-interest noted)
  coppersun_brass         — the original brass codebase (large; tests detection
                            on a project we deliberately don't own the FP rate of)
  fixture-project         — synthetic fixture project materialized from
                            tests/fixtures (known-real + known-FP samples;
                            includes Flask route-handler SQL-injection sample
                            so the framework-aware severity registry has a
                            stable positive escalation target).

Each project gets scanned with `brasscoders scan`. The script captures:
  - Total findings (post-enrichment if license active)
  - Production-bucket count (is_production_code: true)
  - Distribution by finding category
  - Distribution by severity
  - Framework registry hits (how many findings got framework_context)
  - Wall-clock time
  - Token spend (when available)

Output: a single markdown table per run, saved to
launch-evidence/benchmarks/<timestamp>.md, plus printed to stdout.

Usage:
  python3 scripts/benchmark_real_projects.py
  python3 scripts/benchmark_real_projects.py --project brass-seo  # one only
  python3 scripts/benchmark_real_projects.py --no-enrich          # heuristic only
  python3 scripts/benchmark_real_projects.py --quick              # skip largest

Design notes:
  - Subprocesses use a sandboxed env so test runs don't pollute the user's
    real environment (PYTHONPATH, etc.).
  - The script runs `brasscoders` from the current brass CLI checkout (cli/ subdir of brass-intelligence) via
    PYTHONPATH, NOT from a pip install. This is intentional — we want to
    benchmark the in-development version.
  - Failures on one project don't kill the rest.
  - The `fixture-project` target is regenerated fresh on every invocation
    (the directory is wiped and rewritten from tests.fixtures) so changes
    to fixture content propagate without manual steps. The materialized
    files are NOT checked into git (see .gitignore).
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent  # cli/ subdir of brass-intelligence
BENCHMARK_DIR = REPO_ROOT.parent / "launch-evidence" / "benchmarks"
FIXTURE_PROJECT_DIR = REPO_ROOT / "tests" / "benchmark_fixture_project"
FIXTURE_README = """# Benchmark fixture project

Generated fixture project — do not edit. Regenerated on each
`benchmark_real_projects.py` run.

This directory is materialized from `tests/fixtures/` (security, privacy, and
code-quality test files) so the multi-project benchmark has a stable target
exercising known-real bugs and known-false-positive shapes — including a Flask
route-handler SQL injection sample that the framework-aware severity registry
(Capability 1) should escalate.

The files here are intentional bad code for scanner verification. They are
not checked into git; the benchmark wipes and rewrites this directory each
run.
"""


@dataclass
class Project:
    name: str
    path: Path
    description: str
    quick: bool = True  # included when --quick is passed
    skip_reason: Optional[str] = None


@dataclass
class ScanResult:
    project: Project
    total: int = 0
    production_bucket: int = 0
    by_category: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    # file-role partition (sourced from each finding's context.file_type).
    # The point: a project with intentional bad-code in tests/fixtures/
    # shouldn't get judged by total finding count — `source_code` is
    # the only bucket where "real bug" applies. Everything else is
    # structural (expected) signal: test data, doc examples, config
    # boilerplate. Specifically called out by the user re: original
    # brass having lots of fixtures.
    by_file_role: dict[str, int] = field(default_factory=dict)
    # Detailed list of production-bucket findings — used by the
    # triage-worksheet output when --evaluate is on.
    production_findings: list[dict] = field(default_factory=list)
    framework_context_hits: int = 0
    framework_distribution: dict[str, int] = field(default_factory=dict)
    # Per-scanner wall time captured by brass_cli's time_scanner context.
    # Reads .brass/scanner_timings.json. Empty if the scan ran on an old
    # CLI build that didn't yet emit this file.
    scanner_timings: dict[str, float] = field(default_factory=dict)
    wall_seconds: float = 0.0
    enriched_input: int = 0  # findings going IN to enrichment
    enriched_output: int = 0
    tokens_used: int = 0
    error: Optional[str] = None
    raw_stdout_tail: str = ""

    def failed(self) -> bool:
        return self.error is not None


# Project registry. Paths are absolute; adjust if these move.
PROJECTS: list[Project] = [
    Project(
        name="brass-seo",
        path=Path("/Users/scottplamondon/claude-tools/19-Brass-SEO"),
        description="Next.js SEO marketing site (7 rounds of triage history)",
        quick=True,
    ),
    Project(
        name="copper-sun",
        path=Path("/Users/scottplamondon/claude-tools/20-Copper-Sun-Marketing/copper-sun"),
        description="Turborepo SaaS starter + Modal/ML",
        quick=True,
    ),
    Project(
        name="whisperx-production",
        path=Path("/Users/scottplamondon/claude-tools/18-Tscripts2/whisperx-production"),
        description="Next.js + speech-to-text ML",
        quick=True,
    ),
    Project(
        name="brass-cli-self",
        path=REPO_ROOT,
        description="This codebase (self-scan; conflict of interest disclosed)",
        quick=True,
    ),
    Project(
        name="coppersun_brass",
        path=Path("/Users/scottplamondon/claude-tools/devwatch/coppersun_brass"),
        description="The original brass codebase (large; FP rate not curated by us)",
        quick=False,  # excluded by --quick
    ),
    Project(
        name="fixture-project",
        path=FIXTURE_PROJECT_DIR,
        description="Synthetic fixture project — known-real + known-FP samples",
        quick=True,
    ),
    Project(
        name="vulnerable-flask-app",
        path=REPO_ROOT / "tests" / "benchmark_projects" / "vulnerable_flask_app",
        description="Multi-file Flask app with cross-module taint flows (SQL + cmd injection)",
        quick=True,
    ),
    Project(
        name="keto-companion",
        path=Path("/Users/scottplamondon/claude-tools/22-Iphone apps"),
        description="iPhone app workspace — Next.js + Prisma + Sentry backend",
        quick=True,
    ),
    Project(
        name="realistic-bad-project",
        path=Path(
            "/Users/scottplamondon/claude-tools/devwatch/coppersun_brass/"
            "realistic_bad_project_test"
        ),
        description=(
            "External vulnerable Python web app fixture (310+ files, "
            "Flask routes with SQL injection, XSS, command injection, "
            "auth bypass). Not authored by this team — used as an "
            "external probe for Cap 3 taint coverage."
        ),
        quick=True,
    ),
    Project(
        name="airflow",
        path=Path("/Users/scottplamondon/claude-tools/devwatch/bench-monorepos/airflow"),
        description=(
            "Apache Airflow — ~7.2k Python files. Largest project in the "
            "bench; used to validate FileIndex (Perf #2/#12) at near-monorepo "
            "shape. Clone with: "
            "git clone --depth 1 https://github.com/apache/airflow.git"
        ),
        quick=False,  # excluded by --quick; full sweep only
    ),
]


def materialize_fixture_project() -> Optional[str]:
    """Regenerate the on-disk fixture project from tests/fixtures.

    Returns None on success, or an error message string on failure. The
    benchmark continues with the remaining projects on failure rather than
    aborting — the fixture-project row in the report will simply fail with
    a recorded reason.
    """
    try:
        # Late import so that an unrelated import error in tests/fixtures
        # doesn't kill the whole benchmark at module-load time. The error
        # is reported to stderr but we don't raise.
        sys.path.insert(0, str(REPO_ROOT))
        from tests.fixtures import (  # type: ignore[import-not-found]
            SecurityTestFiles,
            PrivacyTestFiles,
            CodeQualityTestFiles,
        )
    except Exception as exc:  # pragma: no cover - defensive
        return f"failed to import tests.fixtures: {exc}"

    try:
        # Wipe and recreate so removed fixtures don't linger between runs.
        if FIXTURE_PROJECT_DIR.exists():
            shutil.rmtree(FIXTURE_PROJECT_DIR)
        FIXTURE_PROJECT_DIR.mkdir(parents=True, exist_ok=True)

        (FIXTURE_PROJECT_DIR / "README.md").write_text(FIXTURE_README, encoding="utf-8")

        SecurityTestFiles.create_security_test_project(FIXTURE_PROJECT_DIR)
        PrivacyTestFiles.create_privacy_test_project(FIXTURE_PROJECT_DIR)
        CodeQualityTestFiles.create_code_quality_test_project(FIXTURE_PROJECT_DIR)
    except Exception as exc:  # pragma: no cover - defensive
        return f"failed to materialize fixture project: {exc}"

    return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--project", help="Run only the named project (one of: {})".format(", ".join(p.name for p in PROJECTS)))
    parser.add_argument("--no-enrich", action="store_true", help="Pass --no-enrich to brasscoders (heuristic-only)")
    parser.add_argument("--quick", action="store_true", help="Skip projects marked quick=False (default: run all)")
    parser.add_argument("--output", type=Path, default=None, help="Override markdown output path")
    return parser.parse_args()


def run_scan(project: Project, no_enrich: bool) -> ScanResult:
    result = ScanResult(project=project)

    if not project.path.exists() or not project.path.is_dir():
        result.error = f"path does not exist: {project.path}"
        return result

    # Sandboxed env: keep just enough for Python + Node + filesystem access.
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "LANG": "C",
        "LC_ALL": "C",
        "PYTHONPATH": ":".join((
            str(REPO_ROOT / "src"),
            os.path.expanduser("~/Library/Python/3.9/lib/python/site-packages"),
        )),
    }
    cmd = [sys.executable, "-m", "brass.cli.brass_cli", "scan", str(project.path)]
    if no_enrich:
        cmd.append("--no-enrich")

    started = time.monotonic()
    # Per-project timeout. Monorepo-scale targets (e.g. airflow at 7k+ .py)
    # legitimately exceed 10 minutes when Pysa is in the pipeline. Bumping
    # to 30 min lets the largest target finish; smaller projects are
    # bounded by the scanners' own internal timeouts so the larger envelope
    # doesn't change their behavior.
    per_project_timeout = 1800
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=per_project_timeout,
            env=env,
            cwd=str(project.path),
        )
    except subprocess.TimeoutExpired:
        result.error = f"scan timed out (>{per_project_timeout // 60} minutes)"
        result.wall_seconds = time.monotonic() - started
        # Wipe any partial .brass/ artifacts so a re-run after timeout
        # doesn't accidentally parse a truncated ai_instructions.yaml
        # written by the killed scan as a successful result.
        shutil.rmtree(project.path / ".brass", ignore_errors=True)
        return result

    result.wall_seconds = time.monotonic() - started
    result.raw_stdout_tail = proc.stdout[-1000:]

    if proc.returncode != 0:
        result.error = f"brasscoders exited {proc.returncode}: {proc.stderr[-500:]}"
        return result

    # Parse the enrichment progress line, e.g.
    # "   Enriched: 100 -> 19 findings (81 duplicates dropped); 19983 tokens used; ..."
    for line in proc.stdout.splitlines():
        if "Enriched:" in line:
            try:
                # Be lenient — string format varies slightly with locale / chars
                between_in_out = line.split("Enriched:")[1].split("findings")[0]
                # "100 → 19" or "100 -> 19"
                parts = between_in_out.replace("→", "->").split("->")
                if len(parts) == 2:
                    result.enriched_input = int(parts[0].strip())
                    result.enriched_output = int(parts[1].strip())
                if "tokens used" in line:
                    tok_chunk = line.split("tokens used")[0].rsplit(";", 1)[1]
                    result.tokens_used = int("".join(c for c in tok_chunk if c.isdigit()) or 0)
            except (ValueError, IndexError):
                pass

    # Read the YAML outputs to count things deterministically.
    ai_yaml = project.path / ".brass" / "ai_instructions.yaml"
    detailed_yaml = project.path / ".brass" / "detailed_analysis.yaml"
    if not ai_yaml.is_file():
        result.error = "scan produced no ai_instructions.yaml"
        return result

    try:
        ai_data = yaml.safe_load(ai_yaml.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        result.error = f"failed to parse ai_instructions.yaml: {exc}"
        return result

    result.total = int(ai_data.get("metadata", {}).get("total_findings", 0))

    # Walk critical_issues to compute production-bucket + distributions.
    # Note: as of the YAML output quality work (2026-05-15), the
    # findings_by_category block was removed from ai_instructions.yaml —
    # it was a longer-format duplicate of critical_issues. critical_issues
    # now carries the `context:` block (Phase A) so the same per-finding
    # production-code / file-role classification is available here.
    #
    # Semantic shift: by_category / by_severity / by_file_role are now
    # over critical+high findings (the population in critical_issues),
    # not over all findings as before. For the benchmark's purpose
    # (showing output-quality of brass's top-priority signal), this is
    # the more useful slice.
    seen_ids: set[str] = set()
    for f in ai_data.get("critical_issues") or []:
        cat = f.get("type", "?")
        fid = f.get("id") or f"{cat}:{f.get('file_path','')}:{f.get('line_number','')}"
        if fid in seen_ids:
            continue
        seen_ids.add(fid)
        result.by_category[cat] = result.by_category.get(cat, 0) + 1
        sev = f.get("severity", "?")
        result.by_severity[sev] = result.by_severity.get(sev, 0) + 1
        ctx = f.get("context") or {}
        file_role = ctx.get("file_type") or "unknown"
        result.by_file_role[file_role] = result.by_file_role.get(file_role, 0) + 1
        # Surface a finding in the production-bucket list when EITHER:
        #   (a) the file_classifier marks it as production code, OR
        #   (b) it's a Cap 2/3 finding (taint or pattern match) at high+
        #       severity in a file the classifier couldn't categorize.
        # The second branch keeps real signal visible on projects whose
        # directory structure escapes the classifier (e.g. external
        # fixture projects with unrecognized folder names).
        #
        # Path denylist for the second branch: skip paths that look
        # like a bundled / nested copy of another tool's source tree
        # (e.g. realistic-bad-project ships pyarmor-protected copies
        # of coppersun_brass under protected/ and src/). Findings on
        # those aren't about the target project; they're leaking
        # signal about a tool the project happens to vendor.
        is_prod = ctx.get("is_production_code")
        title = f.get("title", "")
        # critical_issues findings ship file_path + line_number rather
        # than a single `location` string (which findings_by_category
        # used). Synthesize the same shape so downstream rendering and
        # the path denylist below keep working unchanged.
        file_path = f.get("file_path", "")
        line_number = f.get("line_number")
        location = (
            f"{file_path}:{line_number}" if line_number is not None else file_path
        )
        is_cap23 = title.startswith("Tainted dataflow") or title.startswith("Pattern match")
        is_high_sev = sev in ("critical", "high")
        is_vendored = any(
            seg in location for seg in (
                "pyarmor_runtime",
                "/protected/",
                "node_modules/",
                "/.vercel/",
                "/.next/",
            )
        )
        if is_prod:
            result.production_bucket += 1
        if (is_prod
            or (is_cap23 and is_high_sev and file_role == "unknown" and not is_vendored)):
            result.production_findings.append({
                "id": fid,
                "category": cat,
                "severity": sev,
                "title": title,
                "location": location,
                "file_type": file_role,
            })

    # Per-scanner wall times. Emitted by brass_cli's time_scanner.
    timings_path = project.path / ".brass" / "scanner_timings.json"
    if timings_path.is_file():
        try:
            data = json.loads(timings_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                result.scanner_timings = {
                    str(k): float(v) for k, v in data.items()
                    if isinstance(v, (int, float))
                }
        except (OSError, ValueError, json.JSONDecodeError):
            pass

    # Framework registry hits live in detailed_analysis.yaml metadata.
    if detailed_yaml.is_file():
        try:
            text = detailed_yaml.read_text(encoding="utf-8")
            result.framework_context_hits = text.count("framework_context:")
            # Crude but works: count `framework: <name>` occurrences inside
            # framework_context blocks.
            import re
            for m in re.finditer(r"framework_context:.*?(?=\n        [a-z]+:|\Z)", text, re.DOTALL):
                for f in re.findall(r"framework: ([\w_]+)", m.group(0)):
                    result.framework_distribution[f] = result.framework_distribution.get(f, 0) + 1
        except OSError:
            pass

    return result


def render_markdown(results: list[ScanResult], args: argparse.Namespace) -> str:
    lines: list[str] = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines.append(f"# BrassCoders multi-project benchmark — {now}")
    lines.append("")
    lines.append(f"Mode: **{'heuristic only (--no-enrich)' if args.no_enrich else 'enriched'}**")
    lines.append("")

    # Summary table — production-bucket front and center; total kept as
    # a sanity number but the eye should go to the production column.
    lines.append("## Summary")
    lines.append("")
    lines.append("| Project | Total | **Production** | Test files | Fixtures | Docs | Config | Other | FW hits | Time | Bottleneck |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|")
    for r in results:
        if r.failed():
            lines.append(f"| **{r.project.name}** | ❌ | — | — | — | — | — | — | — | {r.wall_seconds:.0f}s | — |")
            continue
        roles = r.by_file_role
        # All non-source, non-test, non-doc, non-config buckets roll up
        # to "Other" (unknown / build_output if any survived).
        other_count = sum(
            v for k, v in roles.items()
            if k not in ("source_code", "test_file", "test_fixture", "documentation", "configuration")
        )
        # Identify the slowest scanner for this project. Empty if scan
        # ran on an old CLI without timing instrumentation.
        if r.scanner_timings:
            # Exclude meta keys (e.g. _meta_peak_rss_mb from Perf #10);
            # they're not scanner timings.
            scanner_only = {k: v for k, v in r.scanner_timings.items()
                            if not k.startswith("_meta_")}
            if scanner_only:
                bottleneck_name, bottleneck_secs = max(scanner_only.items(), key=lambda kv: kv[1])
                bottleneck_str = f"{bottleneck_name} ({bottleneck_secs:.1f}s)"
            else:
                bottleneck_str = "—"
        else:
            bottleneck_str = "—"
        lines.append(
            f"| **{r.project.name}** | {r.total} | **{r.production_bucket}** | "
            f"{roles.get('test_file', 0)} | {roles.get('test_fixture', 0)} | "
            f"{roles.get('documentation', 0)} | {roles.get('configuration', 0)} | "
            f"{other_count} | {r.framework_context_hits} | {r.wall_seconds:.0f}s | {bottleneck_str} |"
        )
    lines.append("")
    lines.append(
        "_Production column is the bucket where 'real bug' applies. "
        "Findings in test files / fixtures / docs / config are structural — "
        "intentionally-bad code in tests, PII-shaped strings in docs, etc. "
        "— and should be compared per-category, not lumped into total._")
    lines.append("")

    # Category breakdown (the previous summary table; still useful)
    lines.append("## Category distribution")
    lines.append("")
    lines.append("| Project | Security | Privacy | Code Quality | Performance | TODO |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    for r in results:
        if r.failed():
            continue
        cats = r.by_category
        lines.append(
            f"| {r.project.name} | {cats.get('security', 0)} | "
            f"{cats.get('privacy', 0)} | {cats.get('code_quality', 0)} | "
            f"{cats.get('performance', 0)} | {cats.get('todo', 0)} |"
        )
    lines.append("")

    # Severity distribution
    lines.append("## Severity distribution")
    lines.append("")
    lines.append("| Project | Critical | High | Medium | Low | Info |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    for r in results:
        if r.failed():
            continue
        s = r.by_severity
        lines.append(
            f"| {r.project.name} | {s.get('critical', 0)} | {s.get('high', 0)} | "
            f"{s.get('medium', 0)} | {s.get('low', 0)} | {s.get('info', 0)} |"
        )
    lines.append("")

    # Framework hits detail
    has_fw = any(r.framework_distribution for r in results if not r.failed())
    if has_fw:
        lines.append("## Framework registry hits")
        lines.append("")
        lines.append("Each entry is a finding whose severity got adjusted by the "
                     "framework-aware registry (Capability 1). Distribution by detected "
                     "framework:")
        lines.append("")
        for r in results:
            if r.failed() or not r.framework_distribution:
                continue
            dist = ", ".join(f"{k}={v}" for k, v in sorted(r.framework_distribution.items(), key=lambda kv: -kv[1]))
            lines.append(f"- **{r.project.name}** ({r.framework_context_hits} hits): {dist}")
        lines.append("")

    # Per-project detail
    lines.append("## Per-project detail")
    lines.append("")
    for r in results:
        lines.append(f"### {r.project.name}")
        lines.append("")
        lines.append(f"_{r.project.description}_")
        lines.append(f"")
        lines.append(f"Path: `{r.project.path}`")
        lines.append("")
        if r.failed():
            lines.append(f"**Failed:** {r.error}")
            lines.append("")
            continue
        lines.append(f"- Total findings: **{r.total}** (production-bucket: {r.production_bucket})")
        lines.append(f"- Enrichment: {r.enriched_input} → {r.enriched_output} findings; {r.tokens_used:,} tokens")
        lines.append(f"- Wall time: {r.wall_seconds:.1f}s")
        if r.scanner_timings:
            # Sort by descending time so the bottleneck is first.
            top = sorted(r.scanner_timings.items(), key=lambda kv: -kv[1])
            scanner_breakdown = ", ".join(f"{name}={secs:.1f}s" for name, secs in top)
            lines.append(f"- Scanner timings: {scanner_breakdown}")
        if r.framework_context_hits:
            lines.append(f"- Framework registry hits: {r.framework_context_hits}")
        if r.by_file_role:
            role_str = ", ".join(
                f"{k}={v}" for k, v in sorted(r.by_file_role.items(), key=lambda kv: -kv[1])
            )
            lines.append(f"- File-role distribution: {role_str}")
        # Production-bucket triage list — the findings that actually warrant judgment.
        if r.production_findings:
            lines.append("")
            lines.append(f"**Production-bucket findings ({len(r.production_findings)}):**")
            lines.append("")
            for f in r.production_findings:
                lines.append(
                    f"- [{f['severity']}] {f['category']}: "
                    f"`{f['title'][:60]}` @ `{f['location']}`"
                )
        lines.append("")

    # Failures section if any
    failed = [r for r in results if r.failed()]
    if failed:
        lines.append("## Failures")
        lines.append("")
        for r in failed:
            lines.append(f"- **{r.project.name}**: {r.error}")
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    BENCHMARK_DIR.mkdir(parents=True, exist_ok=True)

    # Materialize the fixture project before computing `chosen` so that
    # `--project fixture-project` works on a clean checkout. Failures here
    # are logged but non-fatal — the rest of the benchmark continues.
    fixture_err = materialize_fixture_project()
    if fixture_err is not None:
        print(f"warning: fixture-project materialization failed: {fixture_err}", file=sys.stderr)

    if args.project:
        chosen = [p for p in PROJECTS if p.name == args.project]
        if not chosen:
            print(f"unknown project: {args.project}", file=sys.stderr)
            return 2
    elif args.quick:
        chosen = [p for p in PROJECTS if p.quick]
    else:
        chosen = list(PROJECTS)

    print(f"Running brasscoders on {len(chosen)} project(s)...")
    results: list[ScanResult] = []
    for project in chosen:
        print(f"  scanning {project.name} at {project.path}...", end=" ", flush=True)
        r = run_scan(project, args.no_enrich)
        results.append(r)
        if r.failed():
            print(f"FAILED ({r.error[:60]})")
        else:
            print(f"ok ({r.total} findings, {r.production_bucket} production, {r.wall_seconds:.0f}s)")

    markdown = render_markdown(results, args)
    out_path = args.output or (BENCHMARK_DIR / f"{datetime.now(timezone.utc).strftime('%Y-%m-%d_%H%M%S')}.md")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(markdown, encoding="utf-8")

    print()
    print(f"Wrote {out_path}")
    print()
    print(markdown)

    return 0 if all(not r.failed() for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
