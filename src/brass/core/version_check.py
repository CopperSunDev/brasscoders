"""Optional, opt-in version-freshness check.

When a user runs ``brasscoders version`` (and only then), we may issue a single
HEAD request to PyPI to learn the latest published ``brasscoders``
version. If the running version is two or more releases behind, we soft-
warn. We never auto-update — that would be a serious security regression
for a tool reading source code — and we never make this call during a
scan, watch, status, filter, license, or any other subcommand.

The check respects the ``--offline`` global flag and the
``BRASS_DISABLE_VERSION_CHECK=1`` env var. Failures are silently swallowed
so a captive portal or down PyPI never makes ``brasscoders version`` itself
fail.
"""

from __future__ import annotations

import os
import re
from typing import NamedTuple, Optional


PYPI_PROJECT_URL = "https://pypi.org/pypi/brasscoders/json"
TIMEOUT_SECONDS = 2.0


class VersionCheck(NamedTuple):
    current: str
    latest: Optional[str]
    behind_by: int  # release count; 0 = current, 1 = one behind, etc.

    def is_stale(self) -> bool:
        return self.behind_by >= 2


def check_for_updates(
    current_version: str,
    *,
    offline: bool = False,
    disabled: Optional[bool] = None,
) -> Optional[VersionCheck]:
    """Best-effort version check. Returns ``None`` if check was skipped or failed.

    Args:
        current_version: The running version (e.g. ``"2.0.0"``).
        offline: When True, skip the network call. Wired to ``--offline``.
        disabled: When True, skip. Defaults to reading
            ``BRASS_DISABLE_VERSION_CHECK`` env var.

    Returns ``VersionCheck`` only on a successful network round-trip.
    """
    if disabled is None:
        disabled = os.environ.get("BRASS_DISABLE_VERSION_CHECK", "").lower() in (
            "1", "true", "yes",
        )
    if disabled or offline:
        return None

    try:
        import requests  # local import keeps the import-time graph clean
    except ImportError:
        return None

    try:
        response = requests.get(PYPI_PROJECT_URL, timeout=TIMEOUT_SECONDS)
        if response.status_code != 200:
            return None
        latest = response.json().get("info", {}).get("version")
    except Exception:
        return None

    if not latest:
        return None

    behind_by = _release_distance(current_version, latest)
    return VersionCheck(current=current_version, latest=latest, behind_by=behind_by)


def _release_distance(current: str, latest: str) -> int:
    """Rough count of full releases between ``current`` and ``latest``.

    We compare ``major.minor.patch`` and count any monotonic increase as
    one rung. Pre-releases / build metadata are ignored. This is good
    enough for soft-warn UX; we don't need PEP 440 precision.
    """
    cur = _parse_semver(current)
    lat = _parse_semver(latest)
    if cur is None or lat is None or cur >= lat:
        return 0
    return (
        (lat[0] - cur[0]) * 100
        + (lat[1] - cur[1]) * 10
        + max(0, lat[2] - cur[2])
    )


def _parse_semver(value: str) -> Optional[tuple[int, int, int]]:
    match = re.match(r"^\s*v?(\d+)\.(\d+)\.(\d+)", value or "")
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


__all__ = ["VersionCheck", "check_for_updates"]
