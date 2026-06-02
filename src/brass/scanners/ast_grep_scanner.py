"""
ast-grep pattern scanner.

Capability 2 of the algorithmic plan. Complements `SemgrepTaintScanner`:
- semgrep taint mode catches intraprocedural source→sink flows (precision)
- ast-grep pattern matching catches syntactic sink patterns regardless of
  where the input comes from (recall, including cross-module cases that
  semgrep-OSS cannot follow).

ast-grep is a small (~48 MB Homebrew install) Rust binary. The scanner
soft-fails when the binary is missing: it logs a one-line warning and
returns an empty findings list. The rest of the pipeline runs unaffected.

ast-grep exits with code 1 when findings exist; we treat that as success
and only flag exit codes ≥ 2 as scan failures.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import hashlib
from pathlib import Path
from typing import List, Optional

from brass.core.file_classifier import FileClassifier
from brass.core.path_safety import is_within
from brass.models.finding import Finding, FindingType, Severity

logger = logging.getLogger(__name__)

AST_GREP_BINARY = "ast-grep"
SCAN_TIMEOUT_SECONDS = 60
MAX_OUTPUT_BYTES = 25 * 1024 * 1024  # 25MB JSON ceiling

KIND_SEVERITY = {
    # Pattern-only findings start at MEDIUM so the Cap 1 framework registry
    # has room to escalate to HIGH (in CLI scripts, etc.) or CRITICAL (in
    # route handlers). Without this headroom the registry's +1 bump caps at
    # the existing severity and the framework-aware adjustment is wasted on
    # ast-grep findings.
    "sql_injection": Severity.MEDIUM,
    "command_injection": Severity.MEDIUM,
    "ssrf": Severity.MEDIUM,
    "path_traversal": Severity.MEDIUM,
    "xss": Severity.MEDIUM,
    "deserialization": Severity.MEDIUM,
}


class AstGrepScanner:
    """Run ast-grep against the project's Python sources with BrassCoders-shipped rules."""

    def __init__(self, project_path: str, file_index=None):
        self.project_path = Path(project_path).resolve()
        self.file_classifier = FileClassifier(str(self.project_path))
        # Optional shared FileIndex; falls back to per-scanner rglob when None.
        self.file_index = file_index
        self.rules_root = Path(__file__).parent.parent / "data" / "ast_grep_rules"
        self.config_path = self.rules_root / "sgconfig.yml"
        self._available: Optional[bool] = None

    # ------------------------------------------------------------------ entry

    def scan(self) -> List[Finding]:
        if not self._is_available():
            return []
        if not self.config_path.is_file():
            logger.warning("ast-grep config not found: %s", self.config_path)
            return []
        targets = self._discover_python_targets()
        if not targets:
            return []
        try:
            return self._run_ast_grep(targets)
        except subprocess.TimeoutExpired:
            logger.warning("ast-grep scan timed out after %ds", SCAN_TIMEOUT_SECONDS)
            return []
        except Exception as exc:
            logger.warning("ast-grep scan failed: %s", exc)
            return []

    # -------------------------------------------------------------- availability

    def _is_available(self) -> bool:
        if self._available is not None:
            return self._available
        path = shutil.which(AST_GREP_BINARY)
        if not path:
            logger.warning(
                "ast-grep not found on PATH. Skipping pattern scan. "
                "Install with: brew install ast-grep"
            )
            self._available = False
            return False
        self._available = True
        return True

    # -------------------------------------------------------------- discovery

    _TARGET_EXTENSIONS = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")

    def _discover_python_targets(self) -> List[Path]:
        # Use shared FileIndex if injected; otherwise fall back to a
        # per-scanner glob walk (same path as before this commit).
        if self.file_index is not None:
            return self.file_index.files_with_ext(*self._TARGET_EXTENSIONS)
        targets: List[Path] = []
        for ext in self._TARGET_EXTENSIONS:
            for path in self.project_path.glob(f"**/*{ext}"):
                if not is_within(path, self.project_path):
                    continue
                try:
                    rel = str(path.relative_to(self.project_path))
                except ValueError:
                    continue
                if self.file_classifier.should_exclude_from_analysis(rel):
                    continue
                targets.append(path)
        return targets

    # -------------------------------------------------------------- execution

    def _run_ast_grep(self, targets: List[Path]) -> List[Finding]:
        cmd = [
            AST_GREP_BINARY,
            "scan",
            "-c", str(self.config_path),
            "--json=compact",
            *[str(t) for t in targets],
        ]
        # Run from the rules_root so sgconfig.yml's relative `ruleDirs`
        # resolves against the shipped rule pack — never against a malicious
        # project's `./python/` directory. Target paths are absolute, so cwd
        # doesn't affect what gets scanned.
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT_SECONDS,
            env=self._sandboxed_env(),
            cwd=str(self.rules_root),
        )
        # ast-grep returns 1 when findings exist — that's success, not error.
        # Treat exit codes >= 2 as hard failure.
        if result.returncode >= 2:
            logger.warning(
                "ast-grep failed (rc=%s): %s",
                result.returncode, result.stderr[:400],
            )
            return []
        if len(result.stdout) > MAX_OUTPUT_BYTES:
            logger.warning(
                "ast-grep output too large (%d bytes); discarding",
                len(result.stdout),
            )
            return []
        try:
            rows = json.loads(result.stdout) if result.stdout.strip() else []
        except json.JSONDecodeError as exc:
            logger.warning("ast-grep produced non-JSON: %s", exc)
            return []
        if not isinstance(rows, list):
            return []
        out: List[Finding] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            finding = self._row_to_finding(row)
            if finding is not None:
                out.append(finding)
        return out

    # -------------------------------------------------------------- conversion

    def _row_to_finding(self, row: dict) -> Optional[Finding]:
        path_raw = str(row.get("file") or "")
        rel_path, in_project = self._relativize(path_raw)
        if not in_project:
            return None
        if self.file_classifier.should_exclude_from_analysis(rel_path):
            return None

        rng = row.get("range") or {}
        start = rng.get("start") or {}
        # ast-grep emits 0-indexed line numbers in JSON; the CLI displays 1-indexed.
        raw_line = start.get("line")
        # bool is a subclass of int in Python — guard so True/False can't
        # silently become line 2/1 if a malformed payload leaks through.
        if isinstance(raw_line, int) and not isinstance(raw_line, bool):
            line_number = raw_line + 1
        else:
            line_number = None
        # Column is folded into the deterministic ID so two matches from
        # the same rule on the same line (e.g. multiple subexpressions
        # in one Python statement) don't collide on a single Finding.id.
        raw_col = start.get("column")
        if isinstance(raw_col, int) and not isinstance(raw_col, bool):
            column_number: Optional[int] = raw_col
        else:
            column_number = None

        rule_id = str(row.get("ruleId") or "ast-grep")
        message = str(row.get("message") or rule_id)
        match_text = str(row.get("text") or "")[:200]

        # Try metadata.brass_kind first (our own rules set it), then infer
        # from rule_id substrings (`sql-injection` / `command-injection`).
        metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
        kind = metadata.get("brass_kind") or _kind_from_rule_id(rule_id) or "pattern"
        severity = KIND_SEVERITY.get(kind, Severity.MEDIUM)

        identity = (
            f"ast-grep|{kind}|{rel_path}|{line_number}|{column_number}|{rule_id}"
        ).encode("utf-8")
        ident_hash = hashlib.sha256(identity).hexdigest()[:12]
        return Finding(
            id=f"ast-grep-{kind}-{ident_hash}",
            type=FindingType.SECURITY,
            severity=severity,
            file_path=rel_path,
            line_number=line_number,
            title=f"Pattern match: {kind.replace('_', ' ')}",
            description=message,
            confidence=0.65,
            impact_score=0.7,
            detected_by="AstGrepScanner",
            remediation=(
                "Replace string interpolation in the sink with safer patterns "
                "(prepared statements for SQL, argument lists for shell calls)."
            ),
            metadata={
                "rule_id": rule_id,
                "match_text": match_text,
            },
        )

    def _relativize(self, abs_or_rel: str) -> tuple[str, bool]:
        if not abs_or_rel:
            return "", False
        try:
            resolved = Path(abs_or_rel).resolve()
        except OSError:
            return abs_or_rel, False
        try:
            return str(resolved.relative_to(self.project_path)), True
        except ValueError:
            return abs_or_rel, False

    # -------------------------------------------------------------- env

    @staticmethod
    def _sandboxed_env() -> dict:
        """Strip Rust/Cargo env knobs that could redirect ast-grep."""
        keep = ("PATH", "HOME", "LANG", "LC_ALL")
        env = {k: os.environ.get(k, "") for k in keep if os.environ.get(k) is not None}
        env.setdefault("LANG", "C")
        env.setdefault("LC_ALL", "C")
        return env


def _kind_from_rule_id(rule_id: str) -> Optional[str]:
    rid = (rule_id or "").lower()
    if "sql-injection" in rid or "sql_injection" in rid:
        return "sql_injection"
    if "command-injection" in rid or "command_injection" in rid:
        return "command_injection"
    if "ssrf" in rid:
        return "ssrf"
    if "path-traversal" in rid or "path_traversal" in rid:
        return "path_traversal"
    if "xss" in rid:
        return "xss"
    return None
