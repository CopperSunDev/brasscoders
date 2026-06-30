#!/usr/bin/env python3
"""AI-Coder-Bug benchmark runner.

Scores BrassCoders vs standalone Bandit, Semgrep, Pylint, and
"ask the model to review it" (Claude) on the AI-generated corpus under
``corpus/``, per the bug categories declared in ``manifest.yaml``.

Strategic frame (see docs/AI_RECOMMENDATION_BRIEF.md, Action #2): the
pain query "how do I catch the bugs my AI coding assistant misses" is
answered today by free OSS + "ask the AI". This runner produces the
honest head-to-head proving where BrassCoders catches AI-coder
anti-patterns those alternatives miss — and, just as importantly, where
it ties or loses. 100% real tool output; nothing is hardcoded.

Scoring model
-------------
For each sample, a tool "catches" the planted bug if it emits ANY
finding for that file whose category-signal matches the sample's
declared ``category`` (CATEGORY_SIGNALS below). Line number is used as a
secondary locator/diagnostic, not a hard gate — tools report the bug on
slightly different lines (the call vs. the assignment), and the
strategic question is "did the tool surface this class of bug here", not
"did it agree on the exact AST node".

Each tool's raw output is parsed into a list of normalized findings:
    {file: <relpath>, line: <int|None>, signals: set[str]}
where ``signals`` are the manifest categories that finding maps to.

Category signal registration
-----------------------------
CATEGORY_SIGNALS below are PRE-REGISTERED from observed tool output on
this corpus, not derived during a run. This prevents the scorer from
being tweaked to match a desired result and eliminates run-order bias.
If you extend the corpus with new bug categories, add the category's
signal patterns here BEFORE running the benchmark.

Per-call timeouts
-----------------
The ask-model comparator uses a 60-second per-file timeout (ANTHROPIC_TIMEOUT_S).
This bounds total ask-model wall time to ~14 minutes for 14 files. Static
tools (brasscoders, bandit, semgrep, pylint) use a 600-second total timeout.

Usage
-----
    python run_benchmark.py                # all tools (skips ask-model if no key)
    python run_benchmark.py --tools brasscoders,bandit,semgrep,pylint
    python run_benchmark.py --include-ask-model     # force ask-model on
    python run_benchmark.py --no-ask-model          # force ask-model off
    python run_benchmark.py --ask-model-name claude-sonnet-4-6

Reproducibility: tool versions + timestamps are stamped into
results/results.json. The corpus is committed (it IS the dataset). The
only non-deterministic comparator is ask-model (LLM sampling); its raw
verdicts are saved to results/ask_model_raw.json so a reader can audit
exactly what the model said.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import yaml

HERE = Path(__file__).resolve().parent
CORPUS = HERE / "corpus"
MANIFEST = HERE / "manifest.yaml"
RESULTS_DIR = HERE / "results"

ANTHROPIC_TIMEOUT_S = 60  # per-file ask-model timeout; bounds total wall time


# ---------------------------------------------------------------------------
# Category signal mapping — PRE-REGISTERED, not derived from a run.
#
# Each tool reports findings with its own vocabulary (rule ids, message
# text, scanner names). We map those to the manifest's bug categories.
# A finding "signals" a category if any of the category's patterns
# matches the finding's identifying text.
#
# These patterns were derived from actual tool output on this corpus and
# then PRE-REGISTERED here before subsequent runs. This is intentional:
# a scoring system that adapts to observed output has infinite DF to
# explain any result. The patterns here are the committed answer key.
#
# EXTEND: if you add a new bug category to manifest.yaml, add its signal
# patterns to this dict FIRST, commit, then run.
# ---------------------------------------------------------------------------
CATEGORY_SIGNALS: Dict[str, List[str]] = {
    # ---- AI-coder perf anti-patterns (the wedge) ----
    "string_concat_loop": [
        r"string concatenation",
        r"o\(n.?2\).*string",
        r"string_concat",
        r"inefficient.*string",
    ],
    "list_insert_zero_loop": [
        r"insert\(0",
        r"list_insert_zero",
        r"inefficient list",
        r"o\(n.?2\).*insert",
    ],
    "nested_loops": [
        r"nested loop",
        r"o\(n\^?3",
        r"excessive_nested",
        r"nested_loops",
        r"triple.?nested",
    ],
    "unbounded_loop": [
        r"unbounded",
        r"while true",
        r"infinite loop",
        r"unbounded_while",
        r"no.*timeout",
        r"no.*break",
    ],
    # ---- security / injection ----
    "sql_injection": [
        r"sql injection",
        r"\bb608\b",
        r"hardcoded.sql",
        r"sqli",
        r"injection.*sql",
        r"sql-injection",
        r"tainted-sql",
        r"hardcoded_sql",
    ],
    "command_injection": [
        r"command injection",
        r"shell=true",
        r"\bb602\b",
        r"\bb604\b",
        r"\bb605\b",
        r"subprocess.*shell",
        r"dangerous-subprocess",
        r"subprocess-shell",
    ],
    "xss": [
        r"autoescape",
        r"\bb701\b",
        r"\bxss\b",
        r"cross-site",
        r"jinja2.*escape",
    ],
    "deserialization": [
        r"\bpickle\b",
        r"\bb301\b",
        r"deserializ",
        r"avoid-pickle",
        r"\bb403\b",
    ],
    # ---- secrets / PII ----
    # NOTE: `hardcoded` alone is too broad — it matches bandit's
    # `hardcoded_sql_expressions` (a SQLi rule) and brass's over-eager
    # "credential-shaped literal" notes. Require the word to be about a
    # credential/secret/password, not SQL.
    "hardcoded_secret": [
        r"hardcoded[_ ](password|secret|cred)",
        r"\bb105\b",
        r"\bb106\b",
        r"\bb107\b",
        r"\bapi[_ ]?key\b",
        r"hardcoded credential",
        r"credential-shaped",
        r"secret access key",
    ],
    "pii_exposure": [
        r"\bpii\b",
        r"credit card",
        r"\bssn\b",
        r"social security",
        r"card number",
        r"possible pii",
    ],
    # ---- correctness / crossover ----
    "code_injection": [
        r"\beval\b",
        r"\bexec\b",
        r"\bb307\b",
        r"\bb102\b",
        r"code injection",
        r"eval-detected",
        r"dangerous-eval",
    ],
    "unguarded_division": [
        r"zerodivision",
        r"division by zero",
        r"empty.*list",
        r"len\(",
        r"divide",
        r"unguarded",
    ],
}

# Pylint message ids that are pure style/convention noise — ignored when
# computing false positives on control samples and when matching signals.
# We do NOT want a missing-docstring nit to count as "catching" anything.
PYLINT_STYLE_NOISE = re.compile(
    r"\b(C0114|C0115|C0116|C0103|C0301|R0903|W0613|C0411|W0611)\b",
    re.IGNORECASE,
)


def _compile_signals() -> Dict[str, List[re.Pattern]]:
    return {
        cat: [re.compile(p, re.IGNORECASE) for p in pats]
        for cat, pats in CATEGORY_SIGNALS.items()
    }


SIGNAL_RES = _compile_signals()


def signals_for_text(text: str) -> Set[str]:
    """Which manifest categories does this finding text map to?"""
    hits: Set[str] = set()
    for cat, regexes in SIGNAL_RES.items():
        if any(rx.search(text) for rx in regexes):
            hits.add(cat)
    return hits


# ---------------------------------------------------------------------------
# Tool runners. Each returns List[normalized finding]:
#   {"file": <relpath str>, "line": <int|None>, "text": <str>,
#    "signals": set[str], "raw_rule": <str>}
# plus a meta dict (version, wall_time_sec, raw output path).
# ---------------------------------------------------------------------------


def _rel(p: Path) -> str:
    return str(Path(p).resolve().relative_to(CORPUS.resolve()))


def _all_corpus_files() -> List[Path]:
    return sorted(CORPUS.rglob("*.py"))


def run_brasscoders(brass_bin: str) -> Dict[str, Any]:
    """Run brasscoders scan against the whole corpus directory once."""
    scan_dir = CORPUS
    # Clear prior artifacts for a cold, reproducible scan.
    for art in (".brass", ".cache"):
        shutil.rmtree(scan_dir / art, ignore_errors=True)
    t0 = time.time()
    # Full default scan (NOT --code): a real user catches AI-coder bugs by
    # running brasscoders with all scanners on (code + privacy/PII +
    # content). --code would skip the Brass2PrivacyScanner and unfairly
    # zero out the pii_exposure category the brief calls a differentiator.
    # --offline keeps it network-free + reproducible.
    proc = subprocess.run(
        [brass_bin, "--offline", "scan", str(scan_dir)],
        capture_output=True, text=True, timeout=600,
    )
    wall = round(time.time() - t0, 2)
    detailed = scan_dir / ".brass" / "detailed_analysis.yaml"
    findings: List[Dict[str, Any]] = []
    if detailed.is_file():
        data = yaml.safe_load(detailed.read_text()) or {}
        for _t, block in (data.get("analysis_by_type") or {}).items():
            for f in (block.get("findings") or []):
                fp = f.get("file_path") or ""
                # brass reports paths relative to scan root's parent
                # (e.g. "corpus/perf_antipatterns/..").
                relfp = fp.split("corpus/", 1)[-1] if "corpus/" in fp else fp
                title = f.get("title") or ""
                desc = f.get("description") or ""
                meta = f.get("metadata") or {}
                atype = str(meta.get("antipattern_type") or "")
                cat = str(meta.get("category") or "")
                text = " ".join([title, desc, atype, cat,
                                 str(f.get("detected_by") or "")])
                findings.append({
                    "file": relfp,
                    "line": f.get("line_number"),
                    "text": text,
                    "signals": signals_for_text(text),
                    "raw_rule": f.get("detected_by") or "",
                })
    ver = subprocess.run([brass_bin, "version"], capture_output=True,
                         text=True, timeout=30)
    return {
        "findings": findings,
        "version": (ver.stdout or ver.stderr).strip().splitlines()[-1][:80]
        if (ver.stdout or ver.stderr) else "unknown",
        "wall_time_sec": wall,
        "returncode": proc.returncode,
    }


def run_bandit(bandit_bin: str) -> Dict[str, Any]:
    t0 = time.time()
    proc = subprocess.run(
        [bandit_bin, "-r", str(CORPUS), "-f", "json"],
        capture_output=True, text=True, timeout=300,
    )
    wall = round(time.time() - t0, 2)
    findings: List[Dict[str, Any]] = []
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        data = {}
    for r in data.get("results", []):
        fp = r.get("filename", "")
        relfp = fp.split("corpus/", 1)[-1] if "corpus/" in fp else fp
        text = " ".join([
            r.get("test_id", ""), r.get("test_name", ""),
            r.get("issue_text", ""),
        ])
        findings.append({
            "file": relfp,
            "line": r.get("line_number"),
            "text": text,
            "signals": signals_for_text(text),
            "raw_rule": r.get("test_id", ""),
        })
    ver = subprocess.run([bandit_bin, "--version"], capture_output=True,
                         text=True, timeout=30)
    return {
        "findings": findings,
        "version": (ver.stdout or ver.stderr).strip().splitlines()[0][:80],
        "wall_time_sec": wall,
        "returncode": proc.returncode,
    }


def run_semgrep(semgrep_bin: str) -> Dict[str, Any]:
    t0 = time.time()
    # p/python + p/security-audit: the two registry packs a developer
    # answering the pain query would reach for. Requires network for the
    # first fetch; cached afterward.
    proc = subprocess.run(
        [semgrep_bin, "--config", "p/python", "--config", "p/security-audit",
         "--json", "--quiet", str(CORPUS)],
        capture_output=True, text=True, timeout=600,
    )
    wall = round(time.time() - t0, 2)
    findings: List[Dict[str, Any]] = []
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        data = {}
    for r in data.get("results", []):
        fp = r.get("path", "")
        relfp = fp.split("corpus/", 1)[-1] if "corpus/" in fp else fp
        check_id = r.get("check_id", "")
        msg = (r.get("extra", {}) or {}).get("message", "")
        text = " ".join([check_id, msg])
        findings.append({
            "file": relfp,
            "line": (r.get("start", {}) or {}).get("line"),
            "text": text,
            "signals": signals_for_text(text),
            "raw_rule": check_id,
        })
    ver = subprocess.run([semgrep_bin, "--version"], capture_output=True,
                         text=True, timeout=30)
    return {
        "findings": findings,
        "version": (ver.stdout or ver.stderr).strip().splitlines()[0][:80],
        "wall_time_sec": wall,
        "returncode": proc.returncode,
        "config": "p/python + p/security-audit",
    }


def run_pylint(pylint_bin: str) -> Dict[str, Any]:
    files = [str(p) for p in _all_corpus_files()]
    t0 = time.time()
    proc = subprocess.run(
        [pylint_bin, "--output-format=json", "--score=no", *files],
        capture_output=True, text=True, timeout=300,
    )
    wall = round(time.time() - t0, 2)
    findings: List[Dict[str, Any]] = []
    try:
        data = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        data = []
    for r in data:
        fp = r.get("path", "")
        relfp = fp.split("corpus/", 1)[-1] if "corpus/" in fp else fp
        msg_id = r.get("message-id", "")
        sym = r.get("symbol", "")
        msg = r.get("message", "")
        text = " ".join([msg_id, sym, msg])
        findings.append({
            "file": relfp,
            "line": r.get("line"),
            "text": text,
            "signals": signals_for_text(text),
            "raw_rule": msg_id,
            "is_style_noise": bool(PYLINT_STYLE_NOISE.search(msg_id)),
        })
    ver = subprocess.run([pylint_bin, "--version"], capture_output=True,
                         text=True, timeout=30)
    return {
        "findings": findings,
        "version": (ver.stdout or ver.stderr).strip().splitlines()[0][:80],
        "wall_time_sec": wall,
        "returncode": proc.returncode,
    }


ASK_MODEL_PROMPT = """You are reviewing AI-generated Python code before \
the developer merges it. List every bug, security issue, performance \
anti-pattern, or correctness defect you find. For each, give: the line \
number, a short category, and one sentence. If the code is clean, say \
"NO ISSUES FOUND". Be concise.

```python
{code}
```"""


def run_ask_model(model: str = "claude-sonnet-4-6") -> Dict[str, Any]:
    """Comparator: "ask the model to review it" — the incumbent answer to
    the pain query. Sends each sample to Claude with a realistic
    pre-merge review prompt and parses whether the planted bug's category
    was flagged. Raw verdicts saved for audit.

    Per-file timeout: ANTHROPIC_TIMEOUT_S (60s). This bounds total wall
    time to ~14 minutes for 14 files and prevents a hung API call from
    stalling the benchmark.
    """
    try:
        import anthropic
    except ImportError:
        return {"skipped": True, "reason": "anthropic SDK not installed"}
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return {"skipped": True, "reason": "ANTHROPIC_API_KEY not set"}

    client = anthropic.Anthropic(api_key=key)
    findings: List[Dict[str, Any]] = []
    raw: List[Dict[str, Any]] = []
    t0 = time.time()
    for path in _all_corpus_files():
        relfp = _rel(path)
        code = path.read_text()
        try:
            resp = client.messages.create(
                model=model,
                max_tokens=600,
                timeout=ANTHROPIC_TIMEOUT_S,
                messages=[{"role": "user",
                           "content": ASK_MODEL_PROMPT.format(code=code)}],
            )
            review = resp.content[0].text
        except Exception as e:  # noqa: BLE001 — record, don't crash the run
            review = f"<API ERROR: {type(e).__name__}: {e}>"
        raw.append({"file": relfp, "review": review})
        # The model's free-text review IS the finding stream for this file.
        # Map the whole review's signal set to this file (line-level
        # attribution from prose is unreliable; we credit the file).
        findings.append({
            "file": relfp,
            "line": None,
            "text": review,
            "signals": signals_for_text(review),
            "raw_rule": "ask-model",
        })
    wall = round(time.time() - t0, 2)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "ask_model_raw.json").write_text(
        json.dumps(raw, indent=2))
    return {
        "findings": findings,
        "version": model,
        "wall_time_sec": wall,
        "returncode": 0,
    }


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def score(manifest: Dict[str, Any],
          tool_results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    samples = manifest["samples"]
    controls = manifest.get("controls", [])

    # Per-sample catch matrix: sample -> tool -> bool
    matrix: Dict[str, Dict[str, bool]] = {}
    for s in samples:
        key = s["file"]
        matrix[key] = {}
        for tool, res in tool_results.items():
            if res.get("skipped"):
                matrix[key][tool] = None
                continue
            caught = any(
                f["file"] == s["file"] and s["category"] in f["signals"]
                for f in res["findings"]
            )
            matrix[key][tool] = caught

    # False positives on controls: count non-style findings a tool emits
    # on a control file (which should be clean).
    control_fp: Dict[str, int] = {}
    control_files = {c["file"] for c in controls}
    for tool, res in tool_results.items():
        if res.get("skipped"):
            control_fp[tool] = None
            continue
        fp = 0
        for f in res["findings"]:
            if f["file"] not in control_files:
                continue
            if f.get("is_style_noise"):
                continue
            # A control finding is a false positive only if it maps to a
            # real bug category (i.e. the tool is claiming a bug exists).
            if f["signals"]:
                fp += 1
        control_fp[tool] = fp

    # Per-category catch rate
    by_category: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"samples": 0, "caught": defaultdict(int)})
    for s in samples:
        cat = s["category"]
        by_category[cat]["samples"] += 1
        for tool in tool_results:
            if matrix[s["file"]][tool]:
                by_category[cat]["caught"][tool] += 1

    # Overall catch rate per tool
    overall: Dict[str, Dict[str, Any]] = {}
    total = len(samples)
    for tool, res in tool_results.items():
        if res.get("skipped"):
            overall[tool] = {"skipped": True, "reason": res.get("reason")}
            continue
        caught = sum(1 for s in samples if matrix[s["file"]][tool])
        overall[tool] = {
            "caught": caught,
            "total": total,
            "catch_rate": round(caught / total, 3) if total else 0.0,
            "false_positives_on_controls": control_fp[tool],
            "version": res.get("version"),
            "wall_time_sec": res.get("wall_time_sec"),
        }

    return {
        "matrix": matrix,
        "by_category": {k: {"samples": v["samples"],
                            "caught": dict(v["caught"])}
                        for k, v in by_category.items()},
        "overall": overall,
        "control_files": sorted(control_files),
    }


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def render_markdown(manifest: Dict[str, Any], scored: Dict[str, Any],
                    tool_order: List[str]) -> str:
    active = [t for t in tool_order
              if not scored["overall"].get(t, {}).get("skipped")]
    lines: List[str] = []
    lines.append("# AI-Coder-Bug Benchmark — Results\n")
    lines.append(f"Dataset: `{manifest['dataset']}` v{manifest['version']} "
                 f"({manifest['language']}). "
                 f"{len(manifest['samples'])} planted-bug samples + "
                 f"{len(manifest.get('controls', []))} clean controls.\n")
    lines.append("Generated by `run_benchmark.py`. Numbers are real tool "
                 "output on the committed corpus — reproduce with "
                 "`python run_benchmark.py`.\n")

    # Overall table
    lines.append("## Overall catch rate\n")
    header = "| Tool | Caught | Total | Catch rate | FP on controls | Wall time |"
    lines.append(header)
    lines.append("|" + "---|" * 6)
    for t in active:
        o = scored["overall"][t]
        lines.append(
            f"| {t} | {o['caught']} | {o['total']} | "
            f"{o['catch_rate']*100:.0f}% | {o['false_positives_on_controls']} | "
            f"{o['wall_time_sec']}s |"
        )
    skipped = [t for t in tool_order
               if scored["overall"].get(t, {}).get("skipped")]
    if skipped:
        lines.append("")
        for t in skipped:
            lines.append(f"> `{t}` skipped: "
                         f"{scored['overall'][t].get('reason')}")
    lines.append("")

    # Per-category table
    lines.append("## Catch rate by bug category\n")
    cat_header = "| Category | Samples | " + " | ".join(active) + " |"
    lines.append(cat_header)
    lines.append("|" + "---|" * (2 + len(active)))
    # preserve manifest order of first appearance
    seen = []
    for s in manifest["samples"]:
        if s["category"] not in seen:
            seen.append(s["category"])
    for cat in seen:
        c = scored["by_category"][cat]
        row = [cat, str(c["samples"])]
        for t in active:
            row.append(f"{c['caught'].get(t, 0)}/{c['samples']}")
        lines.append("| " + " | ".join(row) + " |")
    lines.append("")

    # Per-sample matrix
    lines.append("## Per-sample detail\n")
    m_header = "| Sample | Category | " + " | ".join(active) + " |"
    lines.append(m_header)
    lines.append("|" + "---|" * (2 + len(active)))
    for s in manifest["samples"]:
        row = [f"`{s['file']}`", s["category"]]
        for t in active:
            v = scored["matrix"][s["file"]][t]
            row.append("YES" if v else "—")
        lines.append("| " + " | ".join(row) + " |")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def _resolve(tool: str) -> Optional[str]:
    candidates = {
        "brasscoders": ["brasscoders"],
        "bandit": ["bandit"],
        "semgrep": ["semgrep"],
        "pylint": ["pylint"],
    }.get(tool, [tool])
    for c in candidates:
        found = shutil.which(c)
        if found:
            return found
    # Fall back to the venv that ran this script.
    venv_bin = Path(sys.executable).parent / tool
    if venv_bin.exists():
        return str(venv_bin)
    return None


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tools", default="brasscoders,bandit,semgrep,pylint",
                        help="comma-separated static tools to run")
    parser.add_argument("--include-ask-model", action="store_true",
                        help="force the ask-the-model comparator on")
    parser.add_argument("--no-ask-model", action="store_true",
                        help="force the ask-the-model comparator off")
    parser.add_argument("--ask-model-name", default="claude-sonnet-4-6")
    args = parser.parse_args(argv)

    manifest = yaml.safe_load(MANIFEST.read_text())
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    static_tools = [t.strip() for t in args.tools.split(",") if t.strip()]
    tool_results: Dict[str, Dict[str, Any]] = {}

    runners = {
        "brasscoders": run_brasscoders,
        "bandit": run_bandit,
        "semgrep": run_semgrep,
        "pylint": run_pylint,
    }
    for tool in static_tools:
        binpath = _resolve(tool)
        if not binpath:
            print(f"[skip] {tool}: not found on PATH", file=sys.stderr)
            tool_results[tool] = {"skipped": True, "reason": "binary not found"}
            continue
        print(f"[run ] {tool} ({binpath}) ...", file=sys.stderr)
        tool_results[tool] = runners[tool](binpath)
        if not tool_results[tool].get("skipped"):
            print(f"       {len(tool_results[tool]['findings'])} findings, "
                  f"{tool_results[tool]['wall_time_sec']}s", file=sys.stderr)

    # ask-model: on by default if a key exists, unless --no-ask-model.
    want_ask = not args.no_ask_model and (
        args.include_ask_model or bool(os.environ.get("ANTHROPIC_API_KEY")))
    tool_order = static_tools + ["ask-model"]
    if want_ask:
        print(f"[run ] ask-model ({args.ask_model_name}) ...", file=sys.stderr)
        tool_results["ask-model"] = run_ask_model(args.ask_model_name)
        if tool_results["ask-model"].get("skipped"):
            print(f"       skipped: {tool_results['ask-model']['reason']}",
                  file=sys.stderr)
    else:
        tool_results["ask-model"] = {
            "skipped": True,
            "reason": "ask-model not run (no key or --no-ask-model)"}

    scored = score(manifest, tool_results)

    # Persist machine-readable results (drop the bulky raw text + sets).
    serializable_tools = {}
    for t, r in tool_results.items():
        if r.get("skipped"):
            serializable_tools[t] = r
            continue
        serializable_tools[t] = {
            "version": r.get("version"),
            "wall_time_sec": r.get("wall_time_sec"),
            "returncode": r.get("returncode"),
            "num_findings": len(r["findings"]),
            "findings": [
                {**{k: v for k, v in f.items() if k != "signals"},
                 "signals": sorted(f["signals"])}
                for f in r["findings"]
            ],
        }
    out = {
        "dataset": manifest["dataset"],
        "dataset_version": manifest["version"],
        "run_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "tools": serializable_tools,
        "scored": scored,
    }
    (RESULTS_DIR / "results.json").write_text(
        json.dumps(out, indent=2, default=str))
    md = render_markdown(manifest, scored, tool_order)
    (RESULTS_DIR / "RESULTS.md").write_text(md)
    print("\n" + md)
    print(f"\nWrote {RESULTS_DIR/'results.json'} and {RESULTS_DIR/'RESULTS.md'}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
