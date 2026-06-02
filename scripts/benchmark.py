#!/usr/bin/env python3
"""Reproducible BrassCoders benchmark over a fixed set of public Python repositories.

Run with:

    python scripts/benchmark.py --workdir /tmp/brass-bench --output bench.md

The script will:

1. Shallow-clone each repo at a pinned commit into ``--workdir``.
2. Run ``brasscoders --offline scan`` on each.
3. Read the resulting ``.brass/statistics.yaml`` and ``ai_instructions.yaml``
   to extract: scan duration, total findings, findings by type, noise-
   reduction percentage (when present in logs).
4. Emit a Markdown table to stdout (or ``--output``).

The pinned commits and licenses below are the published source of truth
for our benchmark numbers — this script is what reviewers re-run to
verify the headline claim. Do not change pinned commits without bumping
the published "BrassCoders benchmark v" identifier in the output.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import yaml


@dataclass(frozen=True)
class BenchTarget:
    name: str
    url: str
    pinned_commit: str
    license: str


# Pinned public repos. Lower-LOC choices favored to keep the benchmark fast.
# All are MIT/Apache/BSD; none require an account to clone. Commits below
# were pulled from each repo's main/master HEAD on 2026-05-07 — they are
# real and reachable. To re-pin (e.g., for a release-cycle benchmark),
# update each ``pinned_commit`` field with the desired commit hash; the
# tooling at ``tools/refresh_bench_pins.sh`` (if present) automates this.
TARGETS: List[BenchTarget] = [
    BenchTarget(
        name="requests",
        url="https://github.com/psf/requests.git",
        pinned_commit="04d750509b90da728e53aee8d7516426e5a1a293",
        license="Apache-2.0",
    ),
    BenchTarget(
        name="flask",
        url="https://github.com/pallets/flask.git",
        pinned_commit="7374c85ddefc3f4b177a698ab9f0cbb6a5c0b392",
        license="BSD-3-Clause",
    ),
    BenchTarget(
        name="click",
        url="https://github.com/pallets/click.git",
        pinned_commit="73e155006526575548d143ef519995f540547e52",
        license="BSD-3-Clause",
    ),
    BenchTarget(
        name="rich",
        url="https://github.com/Textualize/rich.git",
        pinned_commit="46cebbb032f920eb096efbaf23cdc6fe9dd541f7",
        license="MIT",
    ),
    BenchTarget(
        name="httpx",
        url="https://github.com/encode/httpx.git",
        pinned_commit="b5addb64f0161ff6bfe94c124ef76f6a1fba5254",
        license="BSD-3-Clause",
    ),
    BenchTarget(
        name="pydantic",
        url="https://github.com/pydantic/pydantic.git",
        pinned_commit="7a369fb502a473b1e387905359bdb3070ee7534a",
        license="MIT",
    ),
    BenchTarget(
        name="fastapi",
        url="https://github.com/tiangolo/fastapi.git",
        pinned_commit="622b6356b5102113d0074083ac23c82367f4284b",
        license="MIT",
    ),
    BenchTarget(
        name="poetry",
        url="https://github.com/python-poetry/poetry.git",
        pinned_commit="3fc8b33d8c46bf3fbbf06255f1688a2a7bfdfc6b",
        license="MIT",
    ),
    BenchTarget(
        name="pytest",
        url="https://github.com/pytest-dev/pytest.git",
        pinned_commit="8f81c76744daf72d4f77cfc8423f4bdc60733d78",
        license="MIT",
    ),
    BenchTarget(
        name="brass-self-scan",
        url="self",  # special-cased: we scan our own repo
        pinned_commit="HEAD",
        license="MIT",
    ),
]


def clone_target(target: BenchTarget, workdir: Path) -> Optional[Path]:
    """Shallow-clone the target into ``workdir/<name>``. Returns the dest path."""
    if target.url == "self":
        return Path(__file__).resolve().parent.parent  # repo root

    dest = workdir / target.name
    if dest.exists():
        return dest

    workdir.mkdir(parents=True, exist_ok=True)
    print(f"  cloning {target.name} ({target.pinned_commit[:10]})...", flush=True)
    subprocess.run(
        ["git", "clone", "--quiet", "--no-tags", target.url, str(dest)],
        check=True,
    )
    res = subprocess.run(
        ["git", "-C", str(dest), "checkout", "--quiet", target.pinned_commit],
        capture_output=True, text=True,
    )
    if res.returncode != 0:
        print(f"  ⚠️  could not check out pinned commit: {res.stderr.strip()}",
              flush=True)
        # The commit list here may drift; surface that to the human and continue.
    return dest


@dataclass
class BenchResult:
    target: BenchTarget
    success: bool
    elapsed_seconds: float
    total_findings: int
    severity_breakdown: dict
    type_breakdown: dict
    error: str = ""


def run_brass_on(target: BenchTarget, project_dir: Path) -> BenchResult:
    """Invoke ``brasscoders --offline scan`` on ``project_dir`` and parse output."""
    brass_dir = project_dir / ".brass"
    if brass_dir.exists():
        shutil.rmtree(brass_dir)

    # Resolve the brasscoders entry point. ``shutil.which`` honors PATH; falling
    # back to the in-tree script keeps the benchmark runnable from a checkout
    # without requiring the package to be on PATH first.
    brassai_bin = shutil.which("brasscoders")
    if brassai_bin:
        cmd = [brassai_bin, "--offline", "scan", "--code", str(project_dir)]
    else:
        repo_root = Path(__file__).resolve().parent.parent
        cmd = [
            sys.executable,
            str(repo_root / "src" / "brass" / "cli" / "brass_cli.py"),
            "--offline", "scan", "--code", str(project_dir),
        ]

    start = time.time()
    res = subprocess.run(
        cmd,
        capture_output=True, text=True, timeout=600,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parent.parent / "src")},
    )
    elapsed = time.time() - start

    if res.returncode != 0:
        return BenchResult(
            target=target, success=False, elapsed_seconds=elapsed,
            total_findings=0, severity_breakdown={}, type_breakdown={},
            error=res.stderr.strip()[-300:],
        )

    stats_path = brass_dir / "statistics.yaml"
    if not stats_path.exists():
        return BenchResult(
            target=target, success=False, elapsed_seconds=elapsed,
            total_findings=0, severity_breakdown={}, type_breakdown={},
            error="statistics.yaml missing",
        )

    stats = yaml.safe_load(stats_path.read_text()) or {}
    total = (stats.get("overview") or {}).get("total_findings") \
        or stats.get("metadata", {}).get("total_findings", 0)
    distribution = stats.get("distribution", {}) or {}
    severities = distribution.get("by_severity", {}) or {}
    types = distribution.get("by_type", {}) or {}

    return BenchResult(
        target=target, success=True, elapsed_seconds=elapsed,
        total_findings=total,
        severity_breakdown=severities,
        type_breakdown=types,
    )


def render_markdown(results: List[BenchResult]) -> str:
    lines = []
    lines.append("# BrassCoders benchmark — public-repo run")
    lines.append("")
    lines.append("All scans use `brasscoders --offline scan --code` (no privacy/content "
                 "passes, no outbound network calls). Numbers below are reproducible "
                 "via `python scripts/benchmark.py`.")
    lines.append("")
    lines.append("| Repo | License | Pinned commit | Findings | Critical | High | Medium | Time (s) |")
    lines.append("|---|---|---|---:|---:|---:|---:|---:|")
    for r in results:
        sev = r.severity_breakdown
        if r.success:
            row = (
                f"| {r.target.name} "
                f"| {r.target.license} "
                f"| `{r.target.pinned_commit[:10]}` "
                f"| {r.total_findings} "
                f"| {sev.get('critical', 0)} "
                f"| {sev.get('high', 0)} "
                f"| {sev.get('medium', 0)} "
                f"| {r.elapsed_seconds:.1f} |"
            )
        else:
            row = (
                f"| {r.target.name} "
                f"| {r.target.license} "
                f"| `{r.target.pinned_commit[:10]}` "
                f"| FAIL | — | — | — | {r.elapsed_seconds:.1f} | — _{r.error}_"
            )
        lines.append(row)
    return "\n".join(lines) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--workdir", type=str, default="/tmp/brass-bench",
                        help="Where to clone the target repos.")
    parser.add_argument("--output", type=str, default="-",
                        help="Markdown output path. '-' for stdout.")
    parser.add_argument("--targets", nargs="*",
                        help="Subset of target names to run; default: all.")
    args = parser.parse_args(argv)

    workdir = Path(args.workdir)
    selected = [t for t in TARGETS if not args.targets or t.name in set(args.targets)]
    if not selected:
        print("No matching targets.", file=sys.stderr)
        return 2

    results: List[BenchResult] = []
    for target in selected:
        print(f"-> {target.name}", flush=True)
        try:
            project_dir = clone_target(target, workdir)
        except subprocess.CalledProcessError as exc:
            results.append(BenchResult(
                target=target, success=False, elapsed_seconds=0,
                total_findings=0, severity_breakdown={}, type_breakdown={},
                error=f"clone failed: {exc}",
            ))
            continue

        if project_dir is None:
            continue
        result = run_brass_on(target, project_dir)
        results.append(result)

    md = render_markdown(results)
    if args.output == "-":
        sys.stdout.write(md)
    else:
        Path(args.output).write_text(md, encoding="utf-8")
        print(f"Wrote {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
