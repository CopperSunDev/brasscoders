"""
Path safety helpers used by every scanner that walks the filesystem.

BrassCoders scans codebases that may contain symlinks pointing anywhere — including
``~/.aws/credentials`` or ``~/.ssh/id_rsa``. Without a boundary check, ``Path.rglob``
will happily descend into those targets and any PII/secret patterns inside will be
written into ``.brass/`` output. The helper here is the single source of truth for
"is this path inside the project root?".
"""

from pathlib import Path
from typing import Union


def is_within(path: Union[str, Path], project_root: Union[str, Path]) -> bool:
    """Return True iff ``path`` resolves to a location inside ``project_root``.

    Both arguments are resolved (symlinks followed) before comparison; a symlink
    inside the project that points outside the project resolves to its target and
    is correctly rejected. ``project_root == path`` returns True.
    """
    try:
        resolved = Path(path).resolve()
        root = Path(project_root).resolve()
    except (OSError, RuntimeError):
        # Resolve can raise on broken symlinks or path-too-long. Treat as outside.
        return False

    if resolved == root:
        return True

    try:
        resolved.relative_to(root)
        return True
    except ValueError:
        return False
