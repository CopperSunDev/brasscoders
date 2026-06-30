"""Compute average temperature from readings.

PROVENANCE: AI-generated. Prompt: "Average these sensor readings." The
assistant divided by len(readings) without guarding the empty-list
case — a ZeroDivisionError that only fires on the empty input the demo
never exercised. This is a pure correctness defect (no security angle):
the kind of edge case AI coders skip because the prompt implied
non-empty data.

GROUND TRUTH BUG: unguarded_division at line 12 (division by len() with no
empty check). NOTE: this sample is included to test whether ANY tool in
the comparison catches a logic-only edge-case bug.
"""

from typing import List


def average(readings: List[float]) -> float:
    return sum(readings) / len(readings)   # ZeroDivisionError on []
