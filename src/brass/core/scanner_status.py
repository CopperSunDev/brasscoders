"""Per-scanner run status, surfaced in scanner_timings.json and YAML output.

The CLI orchestrator builds one ``ScannerStatus`` per scanner per scan. Three
status values:

- ``ok``      — scanner ran without exception. Finding count may be 0 (clean
                code) or N (real findings); either is a successful run.
- ``skipped`` — scanner deliberately did not analyze. Scanner-reported via
                ``self.last_run_status = ("skipped", "<reason>")`` before
                returning ``[]``. Examples: external binary missing, language
                absent, opt-in feature disabled.
- ``errored`` — scanner raised or its subprocess failed in a way the scanner
                couldn't soft-handle. Orchestrator-captured from exception, or
                scanner-reported via ``last_run_status = ("errored", "...")``
                for cases like Pyre producing non-parseable JSON.

The point of this type is to make silent-skip cases visible in the YAML output
so AI consumers and humans can tell "scanner ran, found nothing" from
"scanner never ran, you have no signal in this category." Previously a
scanner that soft-failed and one that found nothing both looked identical
in the output.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional


ScannerStatusLiteral = Literal["ok", "skipped", "errored"]


@dataclass
class ScannerStatus:
    """Run status for one scanner from one ``brasscoders scan`` invocation."""

    name: str
    status: ScannerStatusLiteral
    reason: Optional[str]      # None when status == "ok"
    finding_count: int
    duration_sec: float

    def is_ok(self) -> bool:
        return self.status == "ok"

    def is_degraded(self) -> bool:
        """True when the scanner did not contribute its full normal signal."""
        return self.status in ("skipped", "errored")

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "reason": self.reason,
            "finding_count": self.finding_count,
            "duration_sec": self.duration_sec,
        }
