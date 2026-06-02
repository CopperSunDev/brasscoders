"""Per-scan finding cache for incremental-scan support.

When a customer runs `brasscoders scan --incremental`, brass scans only files
that changed since the prior scan and reuses cached findings for the
unchanged files. The cache lives at ``.brass/finding_cache.json`` and is
written at the end of every full scan so the next scan has data to
diff against.

Cache scope: only "file-local" scanners' output (each finding caused
purely by content in its own ``file_path``). Cross-file scanners
(Pysa interprocedural taint, AIContextCoherence) full-scan every
time for correctness and their findings are NOT cached — re-emission
on every scan is authoritative.

Format (schema_version = 1):
    {
      "schema_version": 1,
      "last_scan_at": "<ISO timestamp>",
      "last_scan_head_sha": "<git HEAD or null>",
      "findings_by_scanner": {
        "<scanner_name>": [<serialized finding>, ...],
        ...
      }
    }

The scanner_name keys match the labels used in brass_cli.py's
scanner_tasks (``"code"``, ``"privacy"``, ``"brass_performance"``, etc.).
This keeps cache slicing per-scanner so a future scanner addition
doesn't invalidate prior cached findings from unrelated scanners.
"""

from __future__ import annotations

import json
import logging
from dataclasses import fields
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

from brass.models.finding import Finding, FindingType, Severity

logger = logging.getLogger(__name__)

# Bump when serialization shape changes incompatibly. Old caches with
# a different version are silently discarded — incremental falls back
# to a full scan on the next run.
SCHEMA_VERSION = 1

CACHE_FILENAME = "finding_cache.json"


# Scanners whose output depends ONLY on the file they're scanning. Safe
# to cache + replay for unchanged files in incremental mode.
#
# The keys here MUST match the scanner_task names used in brass_cli.py
# (the ``name`` argument to ``_add()`` in the scanner_tasks setup loop).
# Mismatch = cache silently ignored for that scanner.
FILE_LOCAL_SCANNERS: Set[str] = frozenset({
    "code",
    "privacy",
    "content_moderation",
    "javascript_typescript",
    "brass_performance",
    "secrets",
})

# Scanners whose output depends on cross-file structure (imports, taint
# flows, project-wide patterns). Cached findings from these scanners are
# NOT replayed for unchanged files — they re-run fully every scan.
CROSS_FILE_SCANNERS: Set[str] = frozenset({
    "pysa_taint",
    "semgrep_taint",       # has its own --since-commit support
    "ast_grep",            # rule-based, may match cross-file structurally
    "ai_context_coherence",
    "api_security",        # validates JS API/Python boundary; can touch >1 file
    "phantom_ai",          # tracks symbol definitions across files
})


def _finding_to_dict(f: Finding) -> Dict[str, Any]:
    """Convert a Finding to a plain JSON-serializable dict.

    Enums → their .value strings; datetime → ISO string. All other
    fields are already JSON-safe (primitives, lists, dicts).
    """
    out: Dict[str, Any] = {}
    for field_def in fields(f):
        name = field_def.name
        value = getattr(f, name)
        if isinstance(value, (FindingType, Severity)):
            out[name] = value.value
        elif isinstance(value, datetime):
            out[name] = value.isoformat()
        else:
            out[name] = value
    return out


def _dict_to_finding(d: Dict[str, Any]) -> Finding:
    """Reverse of _finding_to_dict.

    Enum strings → enum members; ISO datetime string → datetime.
    Unknown fields are ignored (forward-compat for cache files written
    by a future brass version with extra fields).
    """
    kwargs: Dict[str, Any] = {}
    known = {f.name for f in fields(Finding)}
    for name, value in d.items():
        if name not in known:
            continue
        if name == "type" and isinstance(value, str):
            kwargs[name] = FindingType(value)
        elif name == "severity" and isinstance(value, str):
            kwargs[name] = Severity(value)
        elif name == "detected_at" and isinstance(value, str):
            try:
                kwargs[name] = datetime.fromisoformat(value)
            except ValueError:
                # Skip an unparseable timestamp — Finding will default
                # to datetime.now() via the dataclass field default.
                pass
        else:
            kwargs[name] = value
    return Finding(**kwargs)


def cache_path(project_path: Path, output_dir_name: str = ".brass") -> Path:
    """Where the cache file lives for a given project."""
    return Path(project_path) / output_dir_name / CACHE_FILENAME


def write_cache(
    cache_file: Path,
    findings_by_scanner: Dict[str, Iterable[Finding]],
    *,
    head_sha: Optional[str] = None,
) -> None:
    """Persist the per-scanner findings dict for incremental scan reuse.

    Writes atomically: serialize to a tmp file then rename, so a
    half-written cache never blocks the next scan.
    """
    serialized: Dict[str, List[Dict[str, Any]]] = {}
    for scanner_name, scanner_findings in findings_by_scanner.items():
        serialized[scanner_name] = [
            _finding_to_dict(f) for f in scanner_findings
        ]
    payload = {
        "schema_version": SCHEMA_VERSION,
        "last_scan_at": datetime.now().isoformat(),
        "last_scan_head_sha": head_sha,
        "findings_by_scanner": serialized,
    }
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    tmp = cache_file.with_suffix(cache_file.suffix + ".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        tmp.replace(cache_file)
        logger.debug(
            "Wrote finding cache: %d scanners, %d findings total → %s",
            len(serialized),
            sum(len(v) for v in serialized.values()),
            cache_file,
        )
    except OSError as exc:
        logger.warning("Could not write finding cache to %s: %s", cache_file, exc)
        # Best-effort cleanup of the tmp file.
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def read_cache(cache_file: Path) -> Optional[Dict[str, Any]]:
    """Load the cache file. Returns None if missing, unreadable, or
    written by an incompatible schema version.

    Returned shape (when present):
        {
          "schema_version": int,
          "last_scan_at": str,
          "last_scan_head_sha": str | None,
          "findings_by_scanner": {scanner_name: [Finding, ...]},
        }
    """
    if not cache_file.is_file():
        return None
    try:
        with open(cache_file, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Discarding unreadable finding cache %s: %s", cache_file, exc)
        return None

    if payload.get("schema_version") != SCHEMA_VERSION:
        logger.info(
            "Discarding finding cache from schema_version %r (current: %d)",
            payload.get("schema_version"),
            SCHEMA_VERSION,
        )
        return None

    raw_by_scanner = payload.get("findings_by_scanner") or {}
    rehydrated: Dict[str, List[Finding]] = {}
    for scanner_name, finding_dicts in raw_by_scanner.items():
        if not isinstance(finding_dicts, list):
            continue
        out_list: List[Finding] = []
        for d in finding_dicts:
            if not isinstance(d, dict):
                continue
            try:
                out_list.append(_dict_to_finding(d))
            except (ValueError, TypeError) as exc:
                logger.debug(
                    "Skipping unrehydratable cached finding: %s (%s)",
                    d.get("id"), exc,
                )
        rehydrated[scanner_name] = out_list

    return {
        "schema_version": payload["schema_version"],
        "last_scan_at": payload.get("last_scan_at"),
        "last_scan_head_sha": payload.get("last_scan_head_sha"),
        "findings_by_scanner": rehydrated,
    }


def filter_cache_for_unchanged_files(
    cached: Dict[str, List[Finding]],
    changed_files: Set[str],
) -> Dict[str, List[Finding]]:
    """Slice the cached findings to only those on UNCHANGED files,
    AND only for file-local scanners. Cross-file scanner outputs are
    excluded — they re-run fully on every scan.

    ``changed_files`` is the set of project-relative file paths that
    have been modified since the cache was written. Anything else
    counts as unchanged and is eligible for cache reuse.
    """
    out: Dict[str, List[Finding]] = {}
    for scanner_name, findings in cached.items():
        if scanner_name not in FILE_LOCAL_SCANNERS:
            # Cross-file scanner — never replay from cache.
            continue
        retained = [
            f for f in findings
            if f.file_path and f.file_path not in changed_files
        ]
        if retained:
            out[scanner_name] = retained
    return out
