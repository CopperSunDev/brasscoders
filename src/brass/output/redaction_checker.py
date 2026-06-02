"""Runtime invariant: brass output never contains credential-shaped strings.

Companion to the e2e test at ``tests/end_to_end/test_no_secrets_in_output.py``.
Where the test catches bypasses at CI time, this module catches them at
RUNTIME — every YAML file brass writes is regex-scanned for credential
patterns before being flushed to disk. If any pattern matches, brass
either:

- ``warn`` (default): emits a WARNING to brass.log + adds a
  ``_brass_leak_warning`` field at the top of the rendered YAML so
  consumers can grep for it. The file is still written.
- ``strict``: raises :class:`BrassRedactionError`, aborts the write,
  preserves the previous-good output (the atomic writer never
  replaces on exception). The CLI surfaces a clear error.

The mode is controlled by the ``BRASS_REDACTION_MODE`` env var
(``warn`` | ``strict``). Default is ``warn`` so existing brass
installations continue to behave; security-conscious customers can
opt into ``strict``.

This is brass's "we don't leak your secrets, and we prove it on
every scan" defense — defense-in-depth beyond the scanner-side
redaction allowlists.

History: the 2026-05-15 ultra-review found 9 redaction-bypass paths
in the output pipeline. All fixed at the scanner / builder layer,
but a runtime check ensures any future regression surfaces
immediately rather than silently shipping in customer output.
"""

from __future__ import annotations

import bisect
import os
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from brass.core.logging_config import get_logger

logger = get_logger(__name__)


# Patterns that should never appear in brass output. Match real-world
# credential shapes (no CANARY substring requirement — the e2e test
# handles canaries; this catches real leaks of real-shape credentials).
#
# Each entry: (human-readable name, compiled regex pattern). Kept
# conservative — false positives in customer output indicate a real
# leak worth investigating, not a noisy detector.
# Boundary lookarounds replacing `\b`. `\b` is a transition between
# `\w` and non-`\w`, so `AKIA...EXAMPLE_BACKUP` would *not* match the
# AWS pattern (the trailing `_` is a word character). These explicit
# lookarounds treat the credential body as alphanumeric only, so any
# adjacent letter/digit/underscore breaks the boundary the way you'd
# expect for an isolated credential token.
_NOT_TOKEN_BEFORE = r"(?<![A-Za-z0-9_])"
_NOT_TOKEN_AFTER = r"(?![A-Za-z0-9_])"

_LEAK_PATTERNS: List[Tuple[str, "re.Pattern[str]"]] = [
    # Bandit B105/B106/B107 historical leak shape: literal embedded in
    # `Possible hardcoded password: 'VALUE'` or `"VALUE"`. Bandit's
    # output varies by call shape (assignment vs kwarg vs funcdef).
    (
        "Bandit hardcoded-password literal",
        re.compile(r"hardcoded password: (['\"])[^'\"]{4,}\1", re.IGNORECASE),
    ),
    # GitHub Personal Access Tokens.
    ("GitHub PAT (ghp_)", re.compile(_NOT_TOKEN_BEFORE + r"ghp_[A-Za-z0-9]{20,}" + _NOT_TOKEN_AFTER)),
    ("GitHub OAuth (gho_)", re.compile(_NOT_TOKEN_BEFORE + r"gho_[A-Za-z0-9]{20,}" + _NOT_TOKEN_AFTER)),
    ("GitHub service (ghs_)", re.compile(_NOT_TOKEN_BEFORE + r"ghs_[A-Za-z0-9]{20,}" + _NOT_TOKEN_AFTER)),
    # Stripe live/test secret keys.
    ("Stripe secret key", re.compile(_NOT_TOKEN_BEFORE + r"sk_(?:live|test)_[A-Za-z0-9]{15,}" + _NOT_TOKEN_AFTER)),
    # AWS access keys (the AKIA prefix).
    ("AWS access key", re.compile(_NOT_TOKEN_BEFORE + r"AKIA[A-Z0-9]{16}" + _NOT_TOKEN_AFTER)),
    # Slack tokens.
    ("Slack token", re.compile(_NOT_TOKEN_BEFORE + r"xox[bopas]-[A-Za-z0-9-]{30,}" + _NOT_TOKEN_AFTER)),
    # JWT-shaped 3-segment base64.
    (
        "JWT",
        re.compile(
            _NOT_TOKEN_BEFORE
            + r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"
            + _NOT_TOKEN_AFTER
        ),
    ),
    # PEM private-key block markers.
    (
        "PEM private key block",
        re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----"),
    ),
    # Privacy partial-mask regression shapes. The 2026-05-15 hardening
    # replaced ``_mask_content`` with full redaction; if these reappear
    # someone regressed the privacy scanner.
    (
        "SSN partial-mask (first-3 + last-4)",
        re.compile(r"\b\d{3}[-\s]?\*{2,}[-\s]?\d{4}\b"),
    ),
    (
        "Credit-card partial-mask (first-4 + last-4)",
        # `[3-6]` covers Amex (3), Visa (4), MC (5), Discover (6).
        re.compile(r"\b[3-6]\d{3}[-\s]?\*{2,}[-\s\d]*\*+[-\s]?\d{4}\b"),
    ),
]


# The env var that gates the mode. Values: 'warn' (default), 'strict'.
_MODE_ENV_VAR = "BRASS_REDACTION_MODE"
MODE_WARN = "warn"
MODE_STRICT = "strict"


@dataclass(frozen=True)
class LeakReport:
    """A single leak match found during a runtime check."""
    pattern_name: str  # e.g. "GitHub PAT (ghp_)"
    matched_substring: str  # the actual matching text (truncated for safety)
    file_path: Optional[str]  # the YAML file being written, when known
    line_number: Optional[int]  # 1-based line in the rendered YAML

    def format_summary(self) -> str:
        """One-line human-readable summary for log messages.

        We deliberately reveal only the first 8 characters of the
        matched value. AWS keys are 20 chars (4 prefix + 16 body); a
        12-char prefix would leak half the secret body, which is
        enough to assist a brute-force prefix-match against a leaked
        key in some other system's logs. 8 chars keeps the pattern
        prefix (e.g. `AKIA`, `ghp_`) recognizable for triage while
        hiding all but a small slice of the body.
        """
        loc = f"{self.file_path}" if self.file_path else "<unknown>"
        if self.line_number is not None:
            loc = f"{loc}:{self.line_number}"
        snippet = (
            self.matched_substring[:8] + "…"
            if len(self.matched_substring) > 8
            else self.matched_substring
        )
        return f"{self.pattern_name} at {loc}: matched {snippet!r}"


class BrassRedactionError(RuntimeError):
    """Raised in strict mode when a YAML write would leak credentials.

    Carries the list of leak reports so callers can render a helpful
    user-facing message and a debugging path.
    """

    def __init__(self, file_path: str, leaks: List[LeakReport]):
        self.file_path = file_path
        self.leaks = leaks
        super().__init__(
            f"Refusing to write {file_path}: detected {len(leaks)} "
            f"credential-shaped string(s) in the rendered YAML. "
            f"This is a brass bug — please report it. "
            f"Set BRASS_REDACTION_MODE=warn to override (the file "
            f"will still be written with a _brass_leak_warning field)."
        )


def get_mode() -> str:
    """Resolve the active mode from env. Unrecognized values fall back
    to 'warn' so a typo doesn't accidentally disable the check or
    accidentally lock a customer out of their own scan."""
    raw = (os.environ.get(_MODE_ENV_VAR) or "").strip().lower()
    if raw == MODE_STRICT:
        return MODE_STRICT
    return MODE_WARN


def scan_text_for_leaks(text: str, file_path: Optional[str] = None) -> List[LeakReport]:
    """Run every credential pattern against ``text``.

    Returns the full list of matches (one report per match, not one
    per pattern). The caller decides what to do based on
    :func:`get_mode`. Empty list means clean.
    """
    if not text:
        return []
    reports: List[LeakReport] = []
    # Pre-split lines once so each match can carry a line number for
    # diagnostics. line_number is None for patterns spanning newlines.
    line_starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            line_starts.append(i + 1)
    for name, pattern in _LEAK_PATTERNS:
        for m in pattern.finditer(text):
            # Binary-search-ish: find which line contains m.start()
            ln = bisect.bisect_right(line_starts, m.start())
            reports.append(LeakReport(
                pattern_name=name,
                matched_substring=m.group(0),
                file_path=file_path,
                line_number=ln,
            ))
    return reports


def enforce_or_warn(
    text: str,
    file_path: Optional[str],
    mode: Optional[str] = None,
) -> Tuple[str, List[LeakReport]]:
    """Run the leak check and react per mode.

    Returns ``(text_to_write, leaks)``. In WARN mode with leaks, the
    returned text has a ``_brass_leak_warning`` block prepended so
    consumers can grep for it. In STRICT mode with leaks, raises
    :class:`BrassRedactionError` (the caller's existing
    atomic-write semantics will then preserve the previous-good
    output).
    """
    mode = mode or get_mode()
    leaks = scan_text_for_leaks(text, file_path=file_path)
    if not leaks:
        return text, leaks

    fp_repr = file_path or "<unknown>"
    if mode == MODE_STRICT:
        for leak in leaks:
            logger.error("redaction leak (strict): %s", leak.format_summary())
        raise BrassRedactionError(fp_repr, leaks)

    # WARN mode — log + prepend a warning block to the YAML.
    for leak in leaks:
        logger.warning("redaction leak (warn): %s", leak.format_summary())
    warning_block = _build_warning_block(leaks)
    return warning_block + text, leaks


def _build_warning_block(leaks: List[LeakReport]) -> str:
    """Build a top-of-YAML comment+key block telling the AI consumer
    that this file failed brass's runtime redaction check.

    The block is YAML-valid (comments + a top-level key with a list
    value) so the file still parses; we don't render the matched
    values themselves — only the pattern names + counts."""
    from collections import Counter
    counts = Counter(l.pattern_name for l in leaks)
    summary_lines = [f"    - {name}: {count}" for name, count in sorted(counts.items())]
    return (
        "# WARNING: brass detected credential-shaped strings in this file's\n"
        "# rendered output. This is a bug — the redaction layer should\n"
        "# have stripped them at the scanner / builder level. Run with\n"
        "# BRASS_REDACTION_MODE=strict to abort on detection instead.\n"
        "_brass_leak_warning:\n"
        f"  leak_count: {len(leaks)}\n"
        "  patterns_matched:\n"
        + "\n".join(summary_lines)
        + "\n  see_logs_for_details: true\n"
        "\n"
    )
