"""Detect files changed since a reference point for incremental scans.

Two detection strategies, tried in order:
  1. git-diff against an explicit commit ref (``--since-commit``) OR
     against the cached ``last_scan_head_sha`` (``--incremental`` mode).
  2. mtime comparison against the cache's ``last_scan_at`` timestamp
     for projects that aren't git repos (e.g. customer code in a
     standalone directory).

Returns a normalized set of project-relative file paths.

Failure semantics: any error in the detection logic causes a graceful
fall-back to "treat all files as changed" — i.e., a full scan. We
NEVER silently scan a subset based on a partial change detection,
because that's the silent-drop bug class we've spent today hardening
against.
"""

from __future__ import annotations

import logging
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional, Set

logger = logging.getLogger(__name__)


def get_current_head_sha(project_path: Path) -> Optional[str]:
    """Return the project's current git HEAD sha, or None if not a git
    repo / git command fails. Hardened against CVE-2022-24765 the same
    way ``brass_cli._check_git_health`` is — empty GIT_CONFIG_* env so
    a hostile per-repo config can't run hooks.
    """
    git_dir = project_path / ".git"
    if not git_dir.exists():
        return None
    sandboxed = os.environ.copy()
    sandboxed["GIT_CONFIG_GLOBAL"] = "/dev/null"
    sandboxed["GIT_CONFIG_SYSTEM"] = "/dev/null"
    sandboxed["GIT_CONFIG_NOSYSTEM"] = "1"
    sandboxed["GIT_TERMINAL_PROMPT"] = "0"
    sandboxed["GIT_ASKPASS"] = "/bin/true"
    sandboxed.pop("GIT_DIR", None)
    sandboxed.pop("GIT_WORK_TREE", None)
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=project_path,
            capture_output=True, text=True, timeout=5,
            env=sandboxed,
        )
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def files_changed_since_commit(
    project_path: Path, since_commit: str,
) -> Optional[Set[str]]:
    """Run ``git diff --name-only <since>...HEAD`` and return the
    project-relative paths of modified files (including untracked
    via a follow-up ``git ls-files --others --exclude-standard``).

    Returns None if not a git repo or git operations fail. None
    signals the caller to fall back to mtime or full scan.

    Uses three-dot range (merge-base) to handle branch divergence
    correctly — the same convention SemgrepTaintScanner already uses.
    """
    if not (project_path / ".git").exists():
        return None
    sandboxed = os.environ.copy()
    sandboxed["GIT_CONFIG_GLOBAL"] = "/dev/null"
    sandboxed["GIT_CONFIG_SYSTEM"] = "/dev/null"
    sandboxed["GIT_CONFIG_NOSYSTEM"] = "1"
    sandboxed["GIT_TERMINAL_PROMPT"] = "0"
    sandboxed["GIT_ASKPASS"] = "/bin/true"
    sandboxed.pop("GIT_DIR", None)
    sandboxed.pop("GIT_WORK_TREE", None)

    changed: Set[str] = set()

    # Committed changes since the reference. Three-dot range gives us
    # files modified on HEAD's branch since it diverged from since_commit.
    try:
        diff = subprocess.run(
            ["git", "diff", "--name-only", f"{since_commit}...HEAD"],
            cwd=project_path,
            capture_output=True, text=True, timeout=15,
            env=sandboxed,
        )
    except (subprocess.SubprocessError, FileNotFoundError, OSError) as exc:
        logger.warning("git diff failed for incremental scan: %s", exc)
        return None
    if diff.returncode != 0:
        logger.warning(
            "git diff returned %d (incremental fallback): %s",
            diff.returncode, diff.stderr.strip()[:200],
        )
        return None
    for line in diff.stdout.splitlines():
        line = line.strip()
        if line:
            changed.add(line)

    # Uncommitted local changes (staged + unstaged) — the typical
    # dev-loop case (developer edits a file, hasn't committed yet).
    try:
        uncommitted = subprocess.run(
            ["git", "diff", "HEAD", "--name-only"],
            cwd=project_path,
            capture_output=True, text=True, timeout=15,
            env=sandboxed,
        )
        if uncommitted.returncode == 0:
            for line in uncommitted.stdout.splitlines():
                line = line.strip()
                if line:
                    changed.add(line)
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        # Best-effort: if uncommitted query fails, we still have
        # committed-diff results.
        pass

    # Untracked files — could contain code the user just created and
    # hasn't even added yet.
    try:
        untracked = subprocess.run(
            ["git", "ls-files", "--others", "--exclude-standard"],
            cwd=project_path,
            capture_output=True, text=True, timeout=15,
            env=sandboxed,
        )
        if untracked.returncode == 0:
            for line in untracked.stdout.splitlines():
                line = line.strip()
                if line:
                    changed.add(line)
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        pass

    return changed


def files_changed_since_mtime(
    project_path: Path, last_scan_at_iso: str,
) -> Optional[Set[str]]:
    """Fall-back change detection for non-git projects. Walks the
    project tree and returns project-relative paths whose mtime is
    newer than ``last_scan_at_iso``.

    Returns None if the timestamp is unparseable.
    """
    try:
        threshold = datetime.fromisoformat(last_scan_at_iso).timestamp()
    except (TypeError, ValueError) as exc:
        logger.warning(
            "Could not parse last_scan_at %r for mtime change detection: %s",
            last_scan_at_iso, exc,
        )
        return None

    project_path = Path(project_path).resolve()
    changed: Set[str] = set()
    for dirpath, dirnames, filenames in os.walk(project_path, followlinks=False):
        # Skip the .brass output dir + common heavy dirs that scanners
        # already exclude. Don't re-implement FileClassifier here —
        # this is a coarse filter just for the mtime scan.
        dirnames[:] = [
            d for d in dirnames
            if d not in (".brass", ".git", "__pycache__", "node_modules",
                         ".venv", "venv", ".cache", "dist", "build")
        ]
        for fname in filenames:
            full = Path(dirpath) / fname
            try:
                if full.stat().st_mtime > threshold:
                    changed.add(str(full.relative_to(project_path)))
            except OSError:
                continue
    return changed


def normalize_changed_files(changed: Set[str]) -> Set[str]:
    """Defensively normalize paths to a consistent project-relative
    POSIX form. Strips leading slashes / ./ and collapses Windows-style
    separators so the set can be compared against scanner-emitted
    ``file_path`` strings (which are POSIX-style relative paths).
    """
    out: Set[str] = set()
    for p in changed:
        if not p:
            continue
        # Strip ./ prefix and leading slashes
        p = p.lstrip("./").lstrip("/")
        # Normalize backslashes (defensive — git output uses forward,
        # but mtime walk might pick up Windows paths in test fixtures).
        p = p.replace("\\", "/")
        if p:
            out.add(p)
    return out
