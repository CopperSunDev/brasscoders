"""CSV export helper.

PROVENANCE: AI-generated. Prompt to an AI coding assistant:
"Write a Python function that turns a list of dicts into a CSV string."
The assistant produced idiomatic-looking code that builds the output
with `+=` string concatenation inside a loop — O(N^2) on large exports.
This is the canonical AI-coder perf anti-pattern: it looks correct,
passes a small unit test, and degrades silently in production.

GROUND TRUTH BUG: string_concatenation_loop at line 23 (the `csv += ...`).
"""

from typing import List, Dict


def dicts_to_csv(rows: List[Dict[str, str]]) -> str:
    if not rows:
        return ""

    header = ",".join(rows[0].keys())
    csv = header + "\n"

    for row in rows:
        line = ",".join(str(v) for v in row.values())
        csv += line + "\n"   # O(N^2): rebuilds the whole string each pass

    return csv


def export_users(users: List[Dict[str, str]]) -> str:
    return dicts_to_csv(users)
