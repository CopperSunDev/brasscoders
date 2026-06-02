"""Framework-aware sink/source/entry-point registry.

Provides context-aware severity adjustment: a finding inside a Flask
route handler is higher-stakes than the same finding in a CLI script.

Data lives in YAML files shipped with the package:
    src/brass/data/framework_registry/{python,javascript,typescript}.yaml

The registry is invoked from IntelligenceRanker after enrichment. Two
adjustments per finding:

  1. File-level entry-point context — the finding's file_path is read
     and scanned (once, cached) for known framework decorators / route
     definitions. The matched entry-point's severity_multiplier is
     applied to the finding's ranking score.

  2. Finding-level sink match — the finding's code_snippet is matched
     against documented sink patterns. A hit bumps the severity by
     `severity_bump` rungs (CRITICAL caps the upper end).

Both adjustments are additive and bounded; multiplier compounding
cannot push severity above CRITICAL.

Design intent: deterministic, fast, no LLM. The registry encodes the
"AI Snyk" intuition about context as plain data.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Iterable, Optional

import yaml

from brass.models.finding import Severity


logger = logging.getLogger(__name__)


# Severity ladder for bump/clamp arithmetic. Lower index = lower severity.
_SEVERITY_LADDER: tuple[Severity, ...] = (
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)


# Extension → language file mapping. .ts/.tsx files use BOTH typescript.yaml
# AND javascript.yaml (TS is a superset; same JS frameworks apply).
_EXT_TO_LANGUAGES: dict[str, tuple[str, ...]] = {
    ".py": ("python",),
    ".pyi": ("python",),
    ".js": ("javascript",),
    ".mjs": ("javascript",),
    ".cjs": ("javascript",),
    ".jsx": ("javascript",),
    ".ts": ("typescript", "javascript"),
    ".tsx": ("typescript", "javascript"),
}


# Max bytes we'll read from a source file to detect entry points.
# Big enough to cover the imports + decorators block of any reasonable
# file; small enough that pathological files don't slow the scan.
_MAX_FILE_BYTES = 64 * 1024


# Pattern syntax in YAML: by default a `pattern:` value is treated as a
# literal substring. Authors who want regex semantics prefix with
# `regex:` (e.g. `pattern: "regex:export\\s+(default\\s+)?async\\s+function"`).
# This avoids the prior trap where `req.body` was auto-detected as regex
# because of the `.` and silently matched `reqXbody` / `req body` too.
_REGEX_PREFIX = "regex:"


def _module_imported_in(text: str, module: str) -> bool:
    """Detect whether `module` is actually imported in `text`, not just
    mentioned anywhere. Handles Python (`import x`, `from x import y`,
    `from x.sub import z`) and JS/TS (`require('x')`, `from 'x'`,
    `from "x"`, `import x from 'x'`) idioms. Substring match was a
    massive FP source — `module: "os"` matched files mentioning
    "cosmic", URLs, or comments.
    """
    if not module:
        return True  # Empty module means "no module requirement"

    # Escape regex metacharacters in the module name (Python dotted
    # paths like django.db legitimately contain dots).
    mod = re.escape(module)
    # Match either Python or JS/TS import shapes.
    patterns = (
        rf"(?m)^\s*import\s+{mod}\b",
        rf"(?m)^\s*from\s+{mod}(?:\.|\s+import\b)",
        rf"require\(['\"]{mod}(?:/[^'\"]*)?['\"]\)",
        rf"from\s+['\"]{mod}(?:/[^'\"]*)?['\"]",
    )
    for pat in patterns:
        if re.search(pat, text):
            return True
    return False


@dataclass
class EntryPointRule:
    kind: str
    framework: str
    module: str  # may be empty: pattern alone qualifies
    pattern: str
    severity_multiplier: float


@dataclass
class SinkRule:
    kind: str
    framework: str
    module: str  # may be empty
    pattern: str
    severity_bump: int
    condition: str = ""       # substring that must ALSO appear in the line
    condition_not: str = ""   # substring that must NOT appear in the line


@dataclass
class SourceRule:
    kind: str
    framework: str
    module: str
    pattern: str


@dataclass
class EntryPointContext:
    """The strongest entry-point match for a file. None if no entry point."""
    kind: str
    framework: str
    severity_multiplier: float


@dataclass
class SinkContext:
    """A sink rule that matched a finding's code snippet."""
    kind: str
    framework: str
    severity_bump: int


@dataclass
class _LanguageRules:
    entry_points: list[EntryPointRule] = field(default_factory=list)
    sinks: list[SinkRule] = field(default_factory=list)
    sources: list[SourceRule] = field(default_factory=list)


# Public clamp helper — exposed so the ranker can also clamp its own
# arithmetic if needed.
def bump_severity(severity: Severity, bump: int) -> Severity:
    """Move `severity` up or down the ladder by `bump` rungs. Clamped."""
    if severity not in _SEVERITY_LADDER:
        return severity
    idx = _SEVERITY_LADDER.index(severity)
    new_idx = max(0, min(len(_SEVERITY_LADDER) - 1, idx + bump))
    return _SEVERITY_LADDER[new_idx]


class FrameworkRegistry:
    """Loads YAML data files; classifies files and findings.

    Cheap to construct. File classifications are memoized per-instance
    so reading the same file repeatedly during a ranker pass is O(1).
    """

    def __init__(
        self,
        project_path: Optional[str | Path] = None,
        data_dir: Optional[Path] = None,
    ):
        self.project_path = Path(project_path).resolve() if project_path else None
        self._data_dir = data_dir or _default_data_dir()
        self._rules_by_language: dict[str, _LanguageRules] = {}
        self._entry_point_cache: dict[str, Optional[EntryPointContext]] = {}
        self._load_all()

    # ------------------------------------------------------------------ #
    # Public API                                                         #
    # ------------------------------------------------------------------ #

    def entry_point_for(self, file_path: str) -> Optional[EntryPointContext]:
        """Return the strongest entry-point match for `file_path`, or None.

        "Strongest" = highest |severity_multiplier - 1.0|; ties prefer
        escalation over deescalation. Findings reach the registry via
        a mix of absolute and project-relative paths depending on
        scanner; the cache key is the canonicalized resolved path so
        both spellings collapse to one entry.

        Results are memoized for the registry's lifetime (one
        IntelligenceRanker construction == one scan). Files modified
        mid-scan keep their initial classification — see test
        `test_cache_is_intentionally_stale_within_scan`.
        """
        key = self._cache_key(file_path)
        cached = self._entry_point_cache.get(key)
        if cached is not None or key in self._entry_point_cache:
            return cached

        result = self._compute_entry_point(file_path)
        self._entry_point_cache[key] = result
        return result

    def _cache_key(self, file_path: str) -> str:
        """Canonicalize a file path for cache lookup. Falls back to the
        raw string when no project_path is set (no anchoring possible)."""
        resolved = self._resolve_path(file_path)
        if resolved is None:
            return file_path
        try:
            return str(resolved.resolve())
        except OSError:
            return str(resolved)

    def sink_for_snippet(self, snippet: str, file_path: str) -> Optional[SinkContext]:
        """If `snippet` matches a known sink pattern for the file's
        language, return the strongest match (highest severity_bump).
        Otherwise None.

        For sinks, module presence is checked against the file via
        import-line detection (not substring), so a file mentioning
        "os" in a comment doesn't satisfy `module: os`. The
        condition / condition_not fields further narrow the snippet
        (e.g. shell=True). On multi-sink collision (e.g. a file
        importing both sqlite3 AND psycopg2, snippet `cursor.execute`),
        the rule with the highest severity_bump wins; ties fall back
        to first-encountered.
        """
        if not snippet:
            return None

        languages = self._languages_for(file_path)
        if not languages:
            return None

        # Read file once to check module imports (only needed for sinks
        # that specify `module`). Cheap: 64KB cap.
        file_text = self._read_file_head(file_path) if file_path else ""

        best: Optional[SinkContext] = None
        for lang in languages:
            rules = self._rules_by_language.get(lang)
            if not rules:
                continue
            for rule in rules.sinks:
                if not _pattern_matches(rule.pattern, snippet):
                    continue
                if rule.condition and rule.condition not in snippet:
                    continue
                if rule.condition_not and rule.condition_not in snippet:
                    continue
                if not _module_imported_in(file_text, rule.module):
                    continue
                candidate = SinkContext(
                    kind=rule.kind,
                    framework=rule.framework,
                    severity_bump=rule.severity_bump,
                )
                if best is None or candidate.severity_bump > best.severity_bump:
                    best = candidate
        return best

    def adjust_severity(
        self,
        severity: Severity,
        file_path: str,
        snippet: Optional[str] = None,
    ) -> tuple[Severity, dict]:
        """Apply all framework adjustments to a single finding.

        Returns a tuple of (new_severity, debug_metadata). Metadata
        records which rules fired so the ranker can attach it to the
        finding for explainability.

        Defensive: when `severity` is None or not a member of the
        Severity enum, return it unchanged with empty metadata. Same
        when `file_path` is empty (no file context to evaluate).
        """
        if severity not in _SEVERITY_LADDER:
            return severity, {}
        if not file_path:
            return severity, {}
        metadata: dict[str, object] = {}
        new_severity = severity

        # Sink bump first (intra-line specificity)
        if snippet:
            sink = self.sink_for_snippet(snippet, file_path)
            if sink is not None:
                new_severity = bump_severity(new_severity, sink.severity_bump)
                metadata["sink_match"] = {
                    "kind": sink.kind,
                    "framework": sink.framework,
                    "severity_bump": sink.severity_bump,
                }

        # Then file-context multiplier (inter-line context)
        entry = self.entry_point_for(file_path)
        if entry is not None:
            # Multiplier semantics: > 1 escalates, < 1 deescalates. We
            # translate that into ±rungs on the ladder so the result
            # stays within the Severity enum.
            mult = entry.severity_multiplier
            if mult >= 1.5:
                new_severity = bump_severity(new_severity, +1)
            elif mult <= 0.6:
                new_severity = bump_severity(new_severity, -1)
            metadata["entry_point"] = {
                "kind": entry.kind,
                "framework": entry.framework,
                "severity_multiplier": entry.severity_multiplier,
            }

        return new_severity, metadata

    # ------------------------------------------------------------------ #
    # Internals                                                           #
    # ------------------------------------------------------------------ #

    def _load_all(self) -> None:
        for lang in ("python", "javascript", "typescript"):
            self._rules_by_language[lang] = self._load_language(lang)

    def _load_language(self, language: str) -> _LanguageRules:
        path = self._data_dir / f"{language}.yaml"
        if not path.is_file():
            logger.warning("framework_registry: missing data file %s", path)
            return _LanguageRules()
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            logger.error("framework_registry: failed to parse %s: %s", path, exc)
            return _LanguageRules()

        # Defensive: malformed YAML with non-dict root (list, scalar)
        # would have crashed `.get()` calls below; skip with a warning.
        if not isinstance(data, dict):
            logger.error(
                "framework_registry: %s top-level must be a mapping, got %s",
                path, type(data).__name__,
            )
            return _LanguageRules()

        rules = _LanguageRules()
        # Per-rule try/except so one bad row doesn't disable the whole file.
        for raw in data.get("entry_points", []) or []:
            try:
                rules.entry_points.append(EntryPointRule(
                    kind=str(raw.get("kind", "")),
                    framework=str(raw.get("framework", "")),
                    module=str(raw.get("module") or ""),
                    pattern=str(raw.get("pattern", "")),
                    severity_multiplier=float(raw.get("severity_multiplier", 1.0)),
                ))
            except (TypeError, ValueError, AttributeError) as exc:
                logger.warning("framework_registry: skipping malformed entry_point in %s: %s (%r)", path, exc, raw)
        for raw in data.get("sinks", []) or []:
            try:
                rules.sinks.append(SinkRule(
                    kind=str(raw.get("kind", "")),
                    framework=str(raw.get("framework", "")),
                    module=str(raw.get("module") or ""),
                    pattern=str(raw.get("pattern", "")),
                    severity_bump=int(raw.get("severity_bump", 0)),
                    condition=str(raw.get("condition") or ""),
                    condition_not=str(raw.get("condition_not") or ""),
                ))
            except (TypeError, ValueError, AttributeError) as exc:
                logger.warning("framework_registry: skipping malformed sink in %s: %s (%r)", path, exc, raw)
        for raw in data.get("sources", []) or []:
            try:
                rules.sources.append(SourceRule(
                    kind=str(raw.get("kind", "")),
                    framework=str(raw.get("framework", "")),
                    module=str(raw.get("module") or ""),
                    pattern=str(raw.get("pattern", "")),
                ))
            except (TypeError, ValueError, AttributeError) as exc:
                logger.warning("framework_registry: skipping malformed source in %s: %s (%r)", path, exc, raw)
        return rules

    def _languages_for(self, file_path: str) -> tuple[str, ...]:
        suffix = Path(file_path).suffix.lower()
        return _EXT_TO_LANGUAGES.get(suffix, ())

    def _read_file_head(self, file_path: str) -> str:
        """Read up to MAX_FILE_BYTES of a file. Best-effort; missing
        files / unreadable bytes / files escaping the project return
        empty string (no crash). Containment check applies when
        project_path is set."""
        resolved = self._resolve_path(file_path)
        if resolved is None:
            return ""
        try:
            real = resolved.resolve()
        except OSError:
            return ""
        if not real.is_file():
            return ""
        if not self._within_project(real):
            # Symlink escape or `..` traversal — refuse to read.
            return ""
        try:
            with real.open("rb") as fh:
                raw = fh.read(_MAX_FILE_BYTES)
            return raw.decode("utf-8", errors="replace")
        except OSError:
            return ""

    def _resolve_path(self, file_path: str) -> Optional[Path]:
        path = Path(file_path)
        if path.is_absolute():
            return path
        if self.project_path is not None:
            return self.project_path / path
        return None

    def _within_project(self, resolved: Path) -> bool:
        """Containment check: a path is in-bounds if it lives under
        `project_path` (after resolving symlinks on both sides). When
        no project_path is configured, every readable file qualifies."""
        if self.project_path is None:
            return True
        try:
            project_resolved = self.project_path.resolve()
        except OSError:
            return False
        try:
            resolved.relative_to(project_resolved)
            return True
        except ValueError:
            return False

    def _compute_entry_point(self, file_path: str) -> Optional[EntryPointContext]:
        languages = self._languages_for(file_path)
        if not languages:
            return None
        text = self._read_file_head(file_path)
        if not text:
            return None

        # Tie-break key: (strength desc, escalation_first asc).
        # When two rules have equal |multiplier - 1.0|, prefer the
        # escalator (multiplier > 1.0) over the deescalator. Rationale:
        # a file matching both a CLI command AND a celery task is more
        # interestingly a task; safer default is to over-surface.
        best: Optional[tuple[float, int, EntryPointRule]] = None
        for lang in languages:
            rules = self._rules_by_language.get(lang)
            if not rules:
                continue
            for rule in rules.entry_points:
                if not _module_imported_in(text, rule.module):
                    continue
                if rule.pattern and not _pattern_matches(rule.pattern, text):
                    continue
                strength = abs(rule.severity_multiplier - 1.0)
                escalation_first = 0 if rule.severity_multiplier > 1.0 else 1
                key = (strength, escalation_first)
                if best is None or (key[0] > best[0]) or (
                    key[0] == best[0] and key[1] < best[1]
                ):
                    best = (key[0], key[1], rule)

        if best is None:
            return None
        rule = best[2]
        return EntryPointContext(
            kind=rule.kind,
            framework=rule.framework,
            severity_multiplier=rule.severity_multiplier,
        )


def _pattern_matches(pattern: str, text: str) -> bool:
    """Match `pattern` against `text`.

    Default: literal substring (predictable, fast). YAML authors who
    need regex semantics opt in via a `regex:` prefix on the pattern
    string. Auto-detection was a precision trap — patterns containing
    `.` (e.g. `req.body`) silently became regex and matched
    `reqXbody`, `req body`, etc.
    """
    if pattern.startswith(_REGEX_PREFIX):
        body = pattern[len(_REGEX_PREFIX):]
        try:
            return re.search(body, text) is not None
        except re.error:
            return body in text
    return pattern in text


def _default_data_dir() -> Path:
    """Locate the bundled YAML data dir, whether under `pip install -e .`
    or a wheel install."""
    # importlib.resources is the canonical 3.9+ way; fall back to file
    # system traversal for editable installs / vendored layouts. Catch
    # everything from the resources lookup — it's a best-effort discovery
    # and any failure should drop to the filesystem walk.
    try:
        ref = resources.files("brass") / "data" / "framework_registry"
        path = Path(str(ref))
        if path.is_dir():
            return path
    except Exception:  # noqa: BLE001 — resources can raise a wide variety
        pass
    # Editable-install fallback: walk from this file.
    here = Path(__file__).resolve().parent
    candidate = here.parent / "data" / "framework_registry"
    return candidate
