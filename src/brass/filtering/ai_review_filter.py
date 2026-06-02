"""
``brasscoders filter`` — apply BrassCoders's noise reduction to a third-party AI review.

This is the headline differentiator: Claude Code, Cursor, or any other AI
reviewer emits a list of "concerns" against a diff or codebase. Most of those
concerns are speculative, low-confidence, or outright duplicates. BrassCoders takes
that list as input and returns the sub-list that actually merits a developer's
attention, using the same noise-reduction logic that runs at the end of
``brasscoders scan``.

Input schema (JSON, list of objects):

    [
      {
        "file": "src/api.py",          # required
        "line": 42,                     # optional; default null
        "title": "SQL injection risk", # required
        "description": "...",          # optional; default ""
        "severity": "high",            # optional; default "medium"
        "category": "security",        # optional; default "code_quality"
        "confidence": 0.7,             # optional; default 0.7
        "detected_by": "claude-3.7"    # optional; default "ai-reviewer"
      },
      ...
    ]

Output schema: same shape, with the entries the filter chose to keep, in the
order ``NoiseReductionScanner`` returned them. Records the original count and
filter reasons in a header comment when emitting to stdout.
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, TextIO

from brass.models.finding import Finding, FindingType, Severity
from brass.scanners.noise_reduction_scanner import NoiseReductionScanner


_SEVERITY_ALIASES = {
    'critical': Severity.CRITICAL,
    'crit': Severity.CRITICAL,
    'high': Severity.HIGH,
    'hi': Severity.HIGH,
    'medium': Severity.MEDIUM,
    'med': Severity.MEDIUM,
    'mid': Severity.MEDIUM,
    'moderate': Severity.MEDIUM,
    'low': Severity.LOW,
    'minor': Severity.LOW,
    'info': Severity.INFO,
    'note': Severity.INFO,
}

_CATEGORY_ALIASES = {
    'security': FindingType.SECURITY,
    'sec': FindingType.SECURITY,
    'vulnerability': FindingType.SECURITY,
    'privacy': FindingType.PRIVACY,
    'pii': FindingType.PRIVACY,
    'code_quality': FindingType.CODE_QUALITY,
    'code-quality': FindingType.CODE_QUALITY,
    'quality': FindingType.CODE_QUALITY,
    'style': FindingType.CODE_QUALITY,
    'reliability': FindingType.CODE_QUALITY,
    'bug': FindingType.CODE_QUALITY,
    'todo': FindingType.TODO,
    'fixme': FindingType.TODO,
    'performance': FindingType.PERFORMANCE,
    'perf': FindingType.PERFORMANCE,
    'architecture': FindingType.ARCHITECTURE,
    'design': FindingType.ARCHITECTURE,
}


@dataclass
class FilterResult:
    """Outcome of running the filter over an AI-reviewer payload."""

    kept: List[Dict[str, Any]]
    original_count: int
    filtered_count: int
    reduction_percentage: float
    filters_applied: Dict[str, int]


class InvalidReviewPayload(ValueError):
    """The supplied JSON payload doesn't match the documented schema."""


def filter_ai_review(
    review_payload: Iterable[Dict[str, Any]],
    project_path: Optional[str] = None,
) -> FilterResult:
    """Filter a list of AI-reviewer findings via BrassCoders's noise-reduction pipeline.

    Args:
        review_payload: Iterable of dicts conforming to the input schema above.
        project_path: Project root used by the noise reducer to recognize
            internal-module imports. When omitted, the current working
            directory is used (which is fine for filtering pure title/severity
            content; matters only for the package-hallucination heuristic).

    Returns a ``FilterResult`` with the kept dicts in the original schema.
    """
    items = list(review_payload)
    findings = [_dict_to_finding(item) for item in items]
    by_id = {f.id: original for f, original in zip(findings, items)}

    project_root = project_path or str(Path.cwd())
    reducer = NoiseReductionScanner(project_root)
    kept_findings = reducer.scan(findings)
    stats = reducer.stats

    kept_dicts = [by_id[f.id] for f in kept_findings if f.id in by_id]

    return FilterResult(
        kept=kept_dicts,
        original_count=stats.original_count if stats else len(items),
        filtered_count=stats.filtered_count if stats else len(kept_dicts),
        reduction_percentage=stats.reduction_percentage if stats else 0.0,
        filters_applied=stats.filters_applied if stats else {},
    )


def _dict_to_finding(item: Dict[str, Any]) -> Finding:
    """Translate one AI-reviewer record into a BrassCoders ``Finding``.

    Tolerates loose input — missing severity defaults to MEDIUM, missing
    category defaults to CODE_QUALITY, missing confidence defaults to 0.7
    (the median for AI-reviewer output we've measured).
    """
    if not isinstance(item, dict):
        raise InvalidReviewPayload(f"Expected dict, got {type(item).__name__}")

    file_path = item.get('file') or item.get('file_path')
    title = item.get('title') or item.get('summary') or item.get('message')
    if not file_path or not title:
        raise InvalidReviewPayload(
            f"Each entry must include 'file' and 'title' (got: {sorted(item.keys())})"
        )

    severity_raw = (item.get('severity') or 'medium').strip().lower()
    severity = _SEVERITY_ALIASES.get(severity_raw, Severity.MEDIUM)

    category_raw = (item.get('category') or item.get('type') or 'code_quality').strip().lower()
    finding_type = _CATEGORY_ALIASES.get(category_raw, FindingType.CODE_QUALITY)

    try:
        confidence = float(item.get('confidence', 0.7))
    except (TypeError, ValueError):
        confidence = 0.7
    confidence = max(0.0, min(1.0, confidence))

    line_number = item.get('line') or item.get('line_number')
    if line_number is not None:
        try:
            line_number = int(line_number)
        except (TypeError, ValueError):
            line_number = None

    description = str(item.get('description') or '')
    detected_by = str(item.get('detected_by') or 'ai-reviewer')

    fingerprint = hashlib.sha1(
        f"{file_path}|{line_number}|{title}|{description}".encode('utf-8')
    ).hexdigest()[:12]

    return Finding(
        id=f"ai_review_{fingerprint}",
        type=finding_type,
        severity=severity,
        file_path=str(file_path),
        line_number=line_number,
        title=str(title),
        description=description,
        confidence=confidence,
        impact_score=_severity_to_impact(severity),
        detected_by=detected_by,
        metadata={'source': 'ai_review'},
    )


def _severity_to_impact(severity: Severity) -> float:
    return {
        Severity.CRITICAL: 0.9,
        Severity.HIGH: 0.75,
        Severity.MEDIUM: 0.5,
        Severity.LOW: 0.3,
        Severity.INFO: 0.1,
    }.get(severity, 0.5)


def load_payload(input_stream: TextIO) -> List[Dict[str, Any]]:
    """Read JSON from ``input_stream`` and validate it's a list of dicts.

    Accepts either a top-level array or an object with a ``findings`` /
    ``items`` / ``review`` array, since AI tools wrap their output in
    different shapes.
    """
    raw = input_stream.read().strip()
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InvalidReviewPayload(f"Input is not valid JSON: {exc}") from exc

    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        for key in ('findings', 'items', 'review', 'issues'):
            if key in parsed and isinstance(parsed[key], list):
                return parsed[key]
    raise InvalidReviewPayload(
        "Input JSON must be a list, or an object containing a 'findings' / "
        "'items' / 'review' / 'issues' array."
    )


def emit_payload(result: FilterResult, output_stream: TextIO, *, indent: int = 2) -> None:
    """Write the filter result to ``output_stream`` as JSON."""
    payload = {
        'metadata': {
            'original_count': result.original_count,
            'filtered_count': result.filtered_count,
            'reduction_percentage': round(result.reduction_percentage, 2),
            'filters_applied': result.filters_applied,
        },
        'findings': result.kept,
    }
    json.dump(payload, output_stream, indent=indent)
    output_stream.write('\n')


def main(argv: Optional[List[str]] = None) -> int:
    """``brasscoders filter`` entry point. Returns an exit code."""
    import argparse

    parser = argparse.ArgumentParser(
        prog='brasscoders filter',
        description='Apply BrassCoders noise reduction to an AI reviewer JSON payload.',
    )
    parser.add_argument(
        '--input', '-i',
        type=str,
        default='-',
        help='Path to input JSON file. "-" (default) reads from stdin.',
    )
    parser.add_argument(
        '--output', '-o',
        type=str,
        default='-',
        help='Path to write filtered JSON. "-" (default) writes to stdout.',
    )
    parser.add_argument(
        '--project-path',
        type=str,
        default=None,
        help='Project root for internal-module detection (default: cwd).',
    )

    args = parser.parse_args(argv)

    if args.input == '-':
        payload = load_payload(sys.stdin)
    else:
        with open(args.input, 'r', encoding='utf-8') as handle:
            payload = load_payload(handle)

    try:
        result = filter_ai_review(payload, project_path=args.project_path)
    except InvalidReviewPayload as exc:
        print(f"brasscoders filter: {exc}", file=sys.stderr)
        return 2

    if args.output == '-':
        emit_payload(result, sys.stdout)
    else:
        with open(args.output, 'w', encoding='utf-8') as handle:
            emit_payload(result, handle)
        # Filter output contains AI-reviewer findings keyed by file/line and
        # excerpts of the user's source. Match the 0600 invariant other BrassCoders
        # writers enforce. POSIX-only.
        try:
            import os as _os
            import platform as _platform
            if _platform.system() != 'Windows':
                _os.chmod(args.output, 0o600)
        except OSError:
            pass

    return 0


if __name__ == '__main__':
    sys.exit(main())
