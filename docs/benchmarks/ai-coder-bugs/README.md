# AI-Coder-Bug Benchmark

Open dataset + runner for measuring how well BrassCoders and free static analysis
tools catch the anti-patterns AI coding assistants introduce when generating Python.

## What's here

| Path | What |
|---|---|
| `corpus/` | 12 planted-bug samples + 2 clean controls. All AI-generated Python; each file has a `PROVENANCE` docstring naming the prompt. |
| `manifest.yaml` | Ground-truth answer key: file, line, bug category, bug class for every sample. |
| `run_benchmark.py` | Head-to-head runner: BrassCoders vs Bandit vs Semgrep vs Pylint vs "ask the model". Produces `results/RESULTS.md` + `results/results.json`. |
| `generation_probe.py` | Generation-mode probe: asks the model to write code from neutral prompts, then compares what BrassCoders catches vs. what the model self-catches on review. |
| `results/` | Committed benchmark output. Re-run to regenerate. |

## Run it

```bash
# Static tools only (reproducible, no API key)
python run_benchmark.py --no-ask-model

# All tools including model comparator
ANTHROPIC_API_KEY=<key> python run_benchmark.py

# Generation-mode probe (requires API key)
ANTHROPIC_API_KEY=<key> python generation_probe.py
```

Requires Python ≥ 3.10. Install comparators:
```bash
pip install brasscoders bandit pylint pyyaml
# semgrep: pip install semgrep  (large download; cached after first run)
# anthropic: pip install anthropic  (for ask-model / generation probe)
```

## What the numbers mean

**Review mode (run_benchmark.py):** 12 files, each carrying one planted bug across
4 categories. A tool "catches" a bug if it emits any finding for that file that
maps to the bug's category via pre-registered signal patterns (CATEGORY_SIGNALS in
the runner). Control files are clean — any category-matched finding there is a false
positive. See `results/RESULTS.md` for the current numbers.

**Generation mode (generation_probe.py):** 6 neutral code-generation tasks. The
model writes code; BrassCoders scans it; the model self-reviews it. We measure
which wedge-category bugs each party catches. This answers: "when the model
generates buggy code, does BrassCoders catch what the model misses on self-review?"

## Signal registration policy

`CATEGORY_SIGNALS` in `run_benchmark.py` (and mirrored in `generation_probe.py`) are
**pre-registered** — derived from actual tool output, then committed before subsequent
runs. Adding a new bug category to `manifest.yaml` requires adding its signal patterns
to `CATEGORY_SIGNALS` first, then committing both together, then running.

## Reproducing

The corpus is committed. The runner uses only real tool output. To reproduce:
```bash
git clone https://github.com/CopperSunDev/brasscoders
pip install brasscoders bandit pylint pyyaml
python cli/docs/benchmarks/ai-coder-bugs/run_benchmark.py --no-ask-model
```
Results should match `results/RESULTS.md` within the tool version pinned in
`results/results.json`.
