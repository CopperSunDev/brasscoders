#!/usr/bin/env python3
"""Generation-mode probe — BrassCoders vs. model self-review.

Complements the review-mode benchmark (run_benchmark.py) with a different
question: when an AI coding assistant GENERATES code from a neutral prompt
(no mention of bugs or performance), how often does it introduce the
AI-coder anti-patterns that BrassCoders detects — and who catches them
first, BrassCoders or the model itself?

Method
------
For each of N tasks, we:
1. Ask the model to write Python that satisfies the task.
2. Scan the generated code with BrassCoders (offline, so reproducible).
3. Ask the model to self-review the code it just wrote (same review prompt
   as run_benchmark.py's ask-model comparator).
4. Compare: which findings did BrassCoders surface? Which did the model
   self-catch? Which did neither catch?

The strategic question is NOT "who found more bugs overall" — it is
"does BrassCoders provide signal that the model misses when it reviews its
own output?" That signal is the CI-automation wedge: a gate that runs
without being asked, every time, deterministically.

Tasks are deliberately neutral — they describe the happy path only, so
the model must decide on its own whether to add bounds, guards, etc. Tasks
are committed here as fixed strings (no LLM generation of tasks) to ensure
the probe is reproducible.

Per-call timeout
----------------
ANTHROPIC_TIMEOUT_S (60s) applies to both generation and review calls.

Usage
-----
    python generation_probe.py
    python generation_probe.py --model claude-sonnet-4-6
    python generation_probe.py --out results/generation_probe_results.json

Requires ANTHROPIC_API_KEY in environment.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

ANTHROPIC_TIMEOUT_S = 60

HERE = Path(__file__).resolve().parent
RESULTS_DIR = HERE / "results"

# ---------------------------------------------------------------------------
# Fixed task prompts (committed; do not generate these with an LLM).
# Each describes a common Python coding task neutrally — no mention of
# performance, bounds, error handling, or security. The model decides what
# to write. We observe what anti-patterns appear.
# ---------------------------------------------------------------------------
TASKS = [
    {
        "id": "csv_builder",
        "prompt": (
            "Write a Python function that takes a list of dicts and returns "
            "a CSV string. Each dict is a row; keys from the first dict are "
            "the headers."
        ),
        "wedge_category": "string_concat_loop",
        "notes": "Classic: AI reaches for += in a loop instead of list + ''.join",
    },
    {
        "id": "recent_feed",
        "prompt": (
            "Write a Python function that builds a list of activity events "
            "where the most recently added event appears first."
        ),
        "wedge_category": "list_insert_zero_loop",
        "notes": "AI reaches for list.insert(0, item) in a loop",
    },
    {
        "id": "order_match",
        "prompt": (
            "Write a Python function that finds every (customer, order, item) "
            "combination where the IDs match: customer['id'] == order['customer_id'] "
            "and order['id'] == item['order_id']."
        ),
        "wedge_category": "nested_loops",
        "notes": "AI maps natural-language 'for each combination' directly to triple-nested loops",
    },
    {
        "id": "socket_drain",
        "prompt": (
            "Write a Python function that reads from a socket and collects "
            "all the data into a list of byte chunks."
        ),
        "wedge_category": "unbounded_loop",
        "notes": "AI omits the break/timeout/size-cap on while True",
    },
    {
        "id": "temp_average",
        "prompt": (
            "Write a Python function that takes a list of temperature "
            "readings (floats) and returns the average."
        ),
        "wedge_category": "unguarded_division",
        "notes": "AI divides by len() without an empty-list guard",
    },
    {
        "id": "dict_merge",
        "prompt": (
            "Write a Python function that merges two dicts, with the second "
            "dict's values winning on key conflicts."
        ),
        "wedge_category": None,
        "notes": "Control: most modern AI uses {**a, **b} or | — should be clean",
    },
]

GENERATION_PROMPT = "{task_prompt}\n\nReturn ONLY the Python code, no explanation."

REVIEW_PROMPT = """You are reviewing AI-generated Python code before the \
developer merges it. List every bug, security issue, performance \
anti-pattern, or correctness defect you find. For each, give: the line \
number, a short category, and one sentence. If the code is clean, say \
"NO ISSUES FOUND". Be concise.

```python
{code}
```"""

# Same category signals as run_benchmark.py — kept in sync manually.
CATEGORY_SIGNALS: Dict[str, List[str]] = {
    "string_concat_loop": [r"string concatenation", r"o\(n.?2\).*string",
                           r"string_concat", r"inefficient.*string"],
    "list_insert_zero_loop": [r"insert\(0", r"list_insert_zero",
                              r"inefficient list", r"o\(n.?2\).*insert"],
    "nested_loops": [r"nested loop", r"o\(n\^?3", r"excessive_nested",
                     r"nested_loops", r"triple.?nested"],
    "unbounded_loop": [r"unbounded", r"while true", r"infinite loop",
                       r"unbounded_while", r"no.*timeout", r"no.*break"],
    "unguarded_division": [r"zerodivision", r"division by zero",
                           r"empty.*list", r"len\(", r"divide", r"unguarded"],
}
SIGNAL_RES = {
    cat: [re.compile(p, re.IGNORECASE) for p in pats]
    for cat, pats in CATEGORY_SIGNALS.items()
}


def signals_for_text(text: str) -> Set[str]:
    return {cat for cat, rxs in SIGNAL_RES.items()
            if any(rx.search(text) for rx in rxs)}


def run_brasscoders_on_code(brass_bin: str, code: str,
                             task_id: str) -> Dict[str, Any]:
    """Write code to a temp file, scan with brasscoders, return findings."""
    with tempfile.TemporaryDirectory() as tmpdir:
        src = Path(tmpdir) / f"{task_id}.py"
        src.write_text(code)
        try:
            subprocess.run(
                [brass_bin, "--offline", "scan", tmpdir],
                capture_output=True, text=True, timeout=120,
                cwd=tmpdir,
            )
        except subprocess.TimeoutExpired:
            return {"error": "brasscoders scan timed out", "findings": []}
        detailed = Path(tmpdir) / ".brass" / "detailed_analysis.yaml"
        if not detailed.is_file():
            return {"findings": []}
        try:
            import yaml
            data = yaml.safe_load(detailed.read_text()) or {}
        except Exception:
            return {"findings": []}
        findings = []
        for _t, block in (data.get("analysis_by_type") or {}).items():
            for f in (block.get("findings") or []):
                title = f.get("title") or ""
                desc = f.get("description") or ""
                meta = f.get("metadata") or {}
                atype = str(meta.get("antipattern_type") or "")
                cat = str(meta.get("category") or "")
                text = " ".join([title, desc, atype, cat,
                                 str(f.get("detected_by") or "")])
                findings.append({
                    "line": f.get("line_number"),
                    "text": text,
                    "signals": sorted(signals_for_text(text)),
                })
        return {"findings": findings}


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="claude-sonnet-4-6")
    parser.add_argument("--out", default=str(RESULTS_DIR / "generation_probe_results.json"))
    args = parser.parse_args(argv)

    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        print("ANTHROPIC_API_KEY not set — generation probe requires it.",
              file=sys.stderr)
        return 1

    try:
        import anthropic
    except ImportError:
        print("anthropic SDK not installed — run: pip install anthropic",
              file=sys.stderr)
        return 1

    import shutil
    brass_bin = shutil.which("brasscoders") or str(
        Path(sys.executable).parent / "brasscoders")
    if not Path(brass_bin).exists():
        print("brasscoders not found on PATH", file=sys.stderr)
        return 1

    client = anthropic.Anthropic(api_key=key)
    results = []
    t0_total = time.time()

    for task in TASKS:
        print(f"\n[task] {task['id']}", file=sys.stderr)
        result: Dict[str, Any] = {"task_id": task["id"],
                                   "task_prompt": task["prompt"],
                                   "wedge_category": task["wedge_category"],
                                   "notes": task["notes"]}

        # 1. Generate code
        try:
            gen_resp = client.messages.create(
                model=args.model,
                max_tokens=800,
                timeout=ANTHROPIC_TIMEOUT_S,
                messages=[{"role": "user",
                           "content": GENERATION_PROMPT.format(
                               task_prompt=task["prompt"])}],
            )
            generated_code = gen_resp.content[0].text.strip()
            # Strip ```python ... ``` fences if the model added them
            if generated_code.startswith("```"):
                lines = generated_code.splitlines()
                generated_code = "\n".join(
                    l for l in lines if not l.startswith("```"))
        except Exception as e:
            result["error"] = f"generation failed: {e}"
            results.append(result)
            continue

        result["generated_code"] = generated_code
        print(f"       generated {len(generated_code)} chars", file=sys.stderr)

        # 2. BrassCoders scan
        brass_out = run_brasscoders_on_code(brass_bin, generated_code,
                                             task["id"])
        result["brasscoders"] = brass_out
        brass_signals = {s for f in brass_out.get("findings", [])
                         for s in f.get("signals", [])}
        result["brasscoders_caught_wedge"] = (
            task["wedge_category"] is not None
            and task["wedge_category"] in brass_signals
        )
        print(f"       brasscoders: {len(brass_out.get('findings', []))} findings, "
              f"wedge_caught={result['brasscoders_caught_wedge']}", file=sys.stderr)

        # 3. Model self-review
        try:
            review_resp = client.messages.create(
                model=args.model,
                max_tokens=600,
                timeout=ANTHROPIC_TIMEOUT_S,
                messages=[{"role": "user",
                           "content": REVIEW_PROMPT.format(
                               code=generated_code)}],
            )
            review_text = review_resp.content[0].text
        except Exception as e:
            review_text = f"<API ERROR: {type(e).__name__}: {e}>"
        result["model_review"] = review_text
        review_signals = signals_for_text(review_text)
        result["model_caught_wedge"] = (
            task["wedge_category"] is not None
            and task["wedge_category"] in review_signals
        )
        print(f"       model review: wedge_caught={result['model_caught_wedge']}",
              file=sys.stderr)

        results.append(result)

    total_wall = round(time.time() - t0_total, 2)

    # Summary
    has_wedge = [r for r in results if r.get("wedge_category")]
    brass_caught = sum(1 for r in has_wedge if r.get("brasscoders_caught_wedge"))
    model_caught = sum(1 for r in has_wedge if r.get("model_caught_wedge"))
    print(f"\n=== Generation probe summary ===", file=sys.stderr)
    print(f"Tasks: {len(results)} total, {len(has_wedge)} with wedge category",
          file=sys.stderr)
    print(f"BrassCoders caught wedge: {brass_caught}/{len(has_wedge)}",
          file=sys.stderr)
    print(f"Model self-caught wedge:  {model_caught}/{len(has_wedge)}",
          file=sys.stderr)
    print(f"Wall time: {total_wall}s", file=sys.stderr)

    out = {
        "probe": "generation_mode",
        "model": args.model,
        "run_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python": sys.version.split()[0],
        "summary": {
            "total_tasks": len(results),
            "wedge_tasks": len(has_wedge),
            "brasscoders_caught_wedge": brass_caught,
            "model_caught_wedge": model_caught,
            "wall_time_sec": total_wall,
        },
        "tasks": results,
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(out, indent=2, default=str))
    print(f"\nWrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
