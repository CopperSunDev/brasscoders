"""
Shared file enumeration cache.

Before this module existed, ~11 scanners each walked the project tree
independently via `Path.rglob` / `Path.glob` / `os.walk`. On a 50k-file
monorepo that's 11 redundant full walks — multiple seconds per scanner
on cold-cache filesystem just to rediscover the same .py / .js files.

`FileIndex` walks the tree once, applies `is_within` containment +
`FileClassifier.should_exclude_from_analysis` filtering once, and
buckets the survivors by lowercase extension. Scanners ask for the
extensions they want and receive cached lists.

Lifecycle:
- Constructed once per scan, alongside `FileClassifier`, in
  `_run_analysis_workflow`.
- Lazily built on first `files_with_ext` call (or via `build()`).
- Read-only after build; safe to share across scanner instances.

Scanners that haven't migrated yet keep their existing rglob path —
they accept `file_index` as an optional ctor arg and fall back when
it's None. Migration is incremental; this module does not force a
big-bang change.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Iterable, List, Optional

from brass.core.file_classifier import FileClassifier
from brass.core.path_safety import is_within

logger = logging.getLogger(__name__)


class FileIndex:
    """Cache of project files bucketed by extension.

    All paths returned are absolute. Containment + exclusion filtering
    is applied during the walk so consumers don't need to repeat it.
    """

    def __init__(self, project_path: Path, file_classifier: Optional[FileClassifier] = None):
        self.project_path = Path(project_path).resolve()
        self.file_classifier = file_classifier or FileClassifier(str(self.project_path))
        # Lowercased ext (including the dot) -> list[Path]
        self._by_ext: dict[str, List[Path]] = {}
        self._built = False
        self._walk_seconds: float = 0.0

    def build(self) -> None:
        """Walk the project tree once. Idempotent; second call is a no-op.

        Uses `os.walk(followlinks=False)` to avoid symlink cycles.
        `Path.rglob` follows symlinks unconditionally and will infinite-
        recurse on a `link -> .` style loop until `OSError: ELOOP` is
        raised mid-iteration — which would crash the entire scan before
        any scanner runs. `os.walk(followlinks=False)` simply skips
        symlinks to directories, which is the correct behavior for a
        static code scanner.
        """
        if self._built:
            return
        import time
        t0 = time.monotonic()
        project_str = str(self.project_path)
        try:
            for dirpath, _dirnames, filenames in os.walk(project_str, followlinks=False):
                for fname in filenames:
                    path = Path(dirpath) / fname
                    if not is_within(path, self.project_path):
                        continue
                    try:
                        rel = str(path.relative_to(self.project_path))
                    except ValueError:
                        continue
                    if self.file_classifier.should_exclude_from_analysis(rel):
                        continue
                    ext = path.suffix.lower()
                    self._by_ext.setdefault(ext, []).append(path)
        except OSError as exc:
            # Catastrophic walk failure (deleted root, permission cascade,
            # etc.). Log + leave _built=True so we don't retry forever.
            logger.warning("FileIndex walk hit OSError: %s", exc)
        self._walk_seconds = time.monotonic() - t0
        self._built = True
        logger.info(
            "FileIndex built: %d extensions, %.3fs walk time",
            len(self._by_ext), self._walk_seconds,
        )

    def files_with_ext(self, *exts: str) -> List[Path]:
        """Return all files whose extension is in `exts`.

        Extensions should include the leading dot (".py" not "py").
        Case-insensitive. Order is the filesystem-walk order (not sorted).
        Returns a fresh list; mutating it doesn't affect the cache.
        """
        if not self._built:
            self.build()
        out: List[Path] = []
        for e in exts:
            out.extend(self._by_ext.get(e.lower(), []))
        return out

    def walk_seconds(self) -> float:
        """Observability: how long did the single walk take?"""
        return self._walk_seconds
