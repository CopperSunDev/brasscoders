"""BrassCoders-ignore file support — gitignore-style suppression rules.

A `.brassignore` file at the project root lets users suppress findings
that BrassCoders keeps surfacing but the user knows are benign. Two kinds
of rules:

    1. **Glob rules** — file paths matching one of these globs are
       excluded from scanning entirely. Same syntax as `.gitignore`
       (subset thereof — see `_matches_glob`).

    2. **Type rules** — `:<finding_type>` lines suppress findings of
       a specific type/rule across the whole project. The type matches
       BrassCoders's `Finding.metadata.rule_id` or the detector ID.

Example `.brassignore`:

    # ignore the whole vendored directory
    vendor/
    # generated openapi types
    src/api/generated/
    # specific files
    scripts/legacy-migration.js
    # suppress one detector entirely
    :hardcoded_password
    # suppress one privacy rule
    :brass2_privacy.us_ssn

Lines starting with `#` are comments. Blank lines are ignored. There's
no negation (`!`) for v1 — yagni until someone asks.

The file is parsed once per scan (on CLI invocation) and consulted by:
    - the file-prefilter (drops globbed paths before any scanner runs)
    - the noise-filter stage (drops findings whose detector matches a
      type rule)
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


@dataclass
class BrassIgnore:
    """Parsed `.brassignore` content. Empty rule sets mean "no ignores"."""

    glob_rules: list[str] = field(default_factory=list)
    type_rules: set[str] = field(default_factory=set)
    source_path: Path | None = None

    @classmethod
    def empty(cls) -> "BrassIgnore":
        return cls()

    @classmethod
    def load(cls, project_path: str | Path) -> "BrassIgnore":
        """Load `.brassignore` from the project root, if present."""
        root = Path(project_path)
        path = root / ".brassignore"
        if not path.is_file():
            return cls.empty()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return cls.empty()
        return cls.parse(text, source_path=path)

    @classmethod
    def parse(cls, text: str, source_path: Path | None = None) -> "BrassIgnore":
        globs: list[str] = []
        types: set[str] = set()
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith(":"):
                # type rule — strip the leading colon
                rule = line[1:].strip()
                if rule:
                    types.add(rule)
                continue
            globs.append(line)
        return cls(glob_rules=globs, type_rules=types, source_path=source_path)

    # --- query methods ---------------------------------------------------

    def matches_path(self, file_path: str) -> bool:
        """True if `file_path` matches any glob rule.

        Path is normalized to forward slashes and compared as a relative
        path. Both file-path and directory-prefix matches are supported,
        following gitignore semantics:

            foo/         → matches anything under foo/
            *.tmp        → matches any .tmp file at any depth
            src/*.gen.js → matches generated files in src/ (no recursion)
        """
        if not self.glob_rules:
            return False
        normalized = file_path.replace("\\", "/").lstrip("./")
        for rule in self.glob_rules:
            if _matches_glob(normalized, rule):
                return True
        return False

    def matches_finding_type(self, type_id: str | None) -> bool:
        """True if `type_id` matches one of the configured type rules."""
        if type_id is None or not self.type_rules:
            return False
        return type_id in self.type_rules

    def __bool__(self) -> bool:
        return bool(self.glob_rules or self.type_rules)


def _matches_glob(path: str, rule: str) -> bool:
    """Gitignore-subset matching.

    Supported:
        - trailing `/` means "match this directory and all descendants"
        - leading `/` anchors to project root
        - shell globs (`*`, `?`, `[abc]`) via fnmatch
        - bare names match at any depth (e.g. `node_modules` matches
          `pkg/node_modules/x.js`)
    """
    # Anchored at root.
    anchored = rule.startswith("/")
    if anchored:
        rule = rule[1:]

    # Directory rule.
    dir_rule = rule.endswith("/")
    if dir_rule:
        rule = rule.rstrip("/")

    if anchored:
        # Anchored: must match from the start of `path`.
        if dir_rule:
            return path == rule or path.startswith(rule + "/")
        return fnmatch.fnmatch(path, rule)

    # Unanchored: match anywhere in the path.
    if dir_rule:
        # Path passes through `rule` as a directory component.
        return path == rule or path.startswith(rule + "/") or f"/{rule}/" in f"/{path}/"

    # Plain glob — try each path component plus the whole path.
    if fnmatch.fnmatch(path, rule):
        return True
    for component in path.split("/"):
        if fnmatch.fnmatch(component, rule):
            return True
    return False


def filter_findings(findings: Iterable, brassignore: BrassIgnore) -> list:
    """Drop findings whose file path or type matches `brassignore`.

    Operates on anything with `.file_path` and `.metadata` attributes;
    the Finding model satisfies that contract.
    """
    if not brassignore:
        return list(findings)
    out = []
    for f in findings:
        path = getattr(f, "file_path", None)
        if isinstance(path, str) and brassignore.matches_path(path):
            continue
        # Type rules can target either the rule_id (e.g. "hardcoded_password")
        # or the dotted form "<detector>.<rule>" stored in metadata.
        meta = getattr(f, "metadata", None) or {}
        rule_id = meta.get("rule_id") if isinstance(meta, dict) else None
        detector = meta.get("detector") if isinstance(meta, dict) else None
        if brassignore.matches_finding_type(rule_id):
            continue
        if detector and rule_id and brassignore.matches_finding_type(f"{detector}.{rule_id}"):
            continue
        out.append(f)
    return out
