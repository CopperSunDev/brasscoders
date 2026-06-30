"""CONTROL SAMPLE — the correct version of csv_export_builder.py.

PROVENANCE: AI-generated, then corrected. This is what good output looks
like: list-append + ''.join (O(N)), parameterized nothing-to-inject,
no secrets, no PII. It carries NO planted bug.

GROUND TRUTH: zero expected findings (beyond optional style nits). Used to
measure false-positive pressure: a tool that flags this is adding noise.
"""

from typing import List, Dict


def dicts_to_csv(rows: List[Dict[str, str]]) -> str:
    if not rows:
        return ""
    lines = [",".join(rows[0].keys())]
    for row in rows:
        lines.append(",".join(str(v) for v in row.values()))
    return "\n".join(lines) + "\n"
