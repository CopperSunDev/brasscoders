"""First-run consent prompt — asked once, interactively, default No.

Gating (all must hold, else nothing is asked and nothing is persisted):

- not an ``--offline`` scan and ``BRASS_OFFLINE`` unset
- ``BRASS_TELEMETRY`` unset (an env override means the user already chose)
- ``CI`` unset (GitHub / GitLab / CircleCI / Travis / Buildkite set it)
- the user has not already decided (``consent=`` absent from the file)
- stdin AND stdout are TTYs (primary guard — Jenkins / Azure lack ``CI``
  but have no TTY; pipes and ``pipx``/CI installs therefore never block
  on ``input()``)

The prompt runs at the end of the first successful interactive scan,
AFTER that scan's (unsent) telemetry would have fired, so the copy can
honestly say "starting with your next scan."
"""

from __future__ import annotations

import os
import sys
from typing import Callable, Optional

from brass.telemetry.consent import ConsentStore

CONSENT_PROMPT_INTRO = """\
📊 Help improve BrassCoders? (optional, anonymous usage stats)

   Starting with your next scan, BrassCoders would send one small event per scan
   to Copper Sun: the count of findings by type and severity, whether --fast or
   --dev was used, your BrassCoders version, your OS name, and a random install ID
   (a UUID stored in ~/.brass/telemetry that identifies this install, not you).

   Never sent: source code, file paths or names, emails, license keys, stack
   traces, or anything from .brass/*.yaml. Nothing is ever sent with --offline.
   Every event is also written to ~/.brass/telemetry-debug.log so you can check.

   Change your mind any time: brasscoders telemetry on|off|status|reset
"""

CONSENT_QUESTION = "   Enable anonymous usage stats? [y/N]: "
DECLINED_LINE = "   OK — telemetry stays off. We won't ask again."
ACCEPTED_LINE = "   ✅ Telemetry on. Install ID: {install_id}"

_YES = ("y", "yes")


def is_interactive() -> bool:
    """True only when both stdin and stdout are TTYs. Any error → False."""
    try:
        return bool(sys.stdin.isatty() and sys.stdout.isatty())
    except Exception:
        return False


def should_prompt(store: ConsentStore, *, offline: bool) -> bool:
    """The complete gate. Every condition is a hard no."""
    if offline or os.environ.get("BRASS_OFFLINE"):
        return False
    if os.environ.get("BRASS_TELEMETRY") or os.environ.get("CI"):
        return False
    if store.has_decided():
        return False
    return is_interactive()


def maybe_prompt_for_consent(
    store: ConsentStore,
    *,
    offline: bool,
    ask: Optional[Callable[[str], str]] = None,
    out: Callable[[str], None] = print,
) -> Optional[bool]:
    """Ask once; persist the answer; return it.

    Returns ``None`` when the gate says not to ask — and persists NOTHING
    in that case (never mark "asked" when we didn't ask). Otherwise returns
    the decision. Empty Enter, ``EOFError`` and ``KeyboardInterrupt`` all
    persist **off**; Ctrl-C is swallowed so a completed scan cannot turn
    into exit 130 because of the prompt.
    """
    if not should_prompt(store, offline=offline):
        return None
    out(CONSENT_PROMPT_INTRO)
    answer = _read_answer(ask or input, out)
    enabled = answer in _YES
    install_id = store.set(enabled=enabled)
    out(ACCEPTED_LINE.format(install_id=install_id) if enabled else DECLINED_LINE)
    return enabled


def _read_answer(ask: Callable[[str], str], out: Callable[[str], None]) -> str:
    try:
        return (ask(CONSENT_QUESTION) or "").strip().lower()
    except EOFError:
        return ""
    except KeyboardInterrupt:
        out("")  # newline after the ^C so the next line starts clean
        return ""


__all__ = [
    "ACCEPTED_LINE",
    "CONSENT_PROMPT_INTRO",
    "CONSENT_QUESTION",
    "DECLINED_LINE",
    "is_interactive",
    "maybe_prompt_for_consent",
    "should_prompt",
]
