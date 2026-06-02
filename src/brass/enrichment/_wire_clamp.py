"""UTF-16-aware string clamping for wire-format builders.

The gateway validates incoming strings with Zod's ``z.string().max(N)``,
which measures **UTF-16 code units**. Python's ``text[:N]`` slices by
**code points**. A character above U+FFFF (emoji, supplementary CJK,
certain math symbols) is one code point in Python but TWO code units
in UTF-16.

Without UTF-16-aware clamping, a 5000-code-point string containing even
one emoji arrives at the gateway as 5001+ UTF-16 units → 400 schema
rejection.

Observed in the wild 2026-05-25 on whisperx-production: a README with
5 emoji (🎯🏆🚀🚀🔧) in the first 5000 code points landed as 5005 UTF-16
code units. Fixed via this helper.

Centralized here (rather than copy-pasted across wire-format builders)
so future builders can't regress on the boundary by silently using
``text[:cap]``.
"""

from __future__ import annotations


def clamp_to_utf16_units(text: str, max_units: int) -> str:
    """Return the longest prefix of ``text`` whose UTF-16 code-unit
    length is ≤ ``max_units``.

    Single-pass O(N). For pure ASCII / BMP text the loop is effectively
    a no-op fast path with no allocation. The slow path triggers only
    when a non-BMP character is encountered.

    Use anywhere a string is sliced and the result will be validated
    by the gateway's Zod schemas.
    """
    units = 0
    for i, c in enumerate(text):
        char_units = 2 if ord(c) > 0xFFFF else 1
        if units + char_units > max_units:
            return text[:i]
        units += char_units
    return text
