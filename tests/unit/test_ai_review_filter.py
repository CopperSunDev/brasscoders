"""Tests for the ``brasscoders filter`` post-processor."""

import io
import json
from pathlib import Path

import pytest

from brass.filtering.ai_review_filter import (
    InvalidReviewPayload,
    emit_payload,
    filter_ai_review,
    load_payload,
    main,
)


@pytest.fixture
def sample_review():
    return [
        {
            "file": "src/api.py", "line": 42,
            "title": "SQL injection", "description": "user input in query",
            "severity": "high", "category": "security", "confidence": 0.85,
            "detected_by": "claude-3.7",
        },
        {
            "file": "src/api.py", "line": 60,
            "title": "TODO not tracked", "description": "TODO comment",
            "severity": "info", "category": "todo", "confidence": 0.3,
            "detected_by": "claude-3.7",
        },
        {
            "file": "src/util.py", "line": 8,
            "title": "Pylint C0301: line too long", "description": "C0301",
            "severity": "low", "category": "style", "confidence": 0.55,
            "detected_by": "pylint",
        },
        {
            "file": "src/auth.py", "line": 12,
            "title": "Hardcoded admin password", "description": "literal in source",
            "severity": "critical", "category": "security", "confidence": 0.95,
            "detected_by": "claude-3.7",
        },
    ]


def test_filter_drops_low_confidence_and_style_noise(sample_review, tmp_path):
    result = filter_ai_review(sample_review, project_path=str(tmp_path))

    titles_kept = {f['title'] for f in result.kept}
    assert 'SQL injection' in titles_kept
    assert 'Hardcoded admin password' in titles_kept
    # The TODO with confidence 0.3 falls under the TODO threshold (0.4); style
    # issues from pylint matching C0301 are stripped.
    assert 'TODO not tracked' not in titles_kept
    assert 'Pylint C0301: line too long' not in titles_kept

    assert result.original_count == 4
    assert result.filtered_count == len(result.kept) == 2
    assert result.reduction_percentage > 40.0


def test_critical_findings_always_kept_regardless_of_confidence(tmp_path):
    """A CRITICAL severity finding bypasses the confidence threshold."""
    review = [
        {
            "file": "src/x.py",
            "title": "Crit finding",
            "severity": "critical",
            "category": "security",
            "confidence": 0.1,  # Way below threshold
        }
    ]

    result = filter_ai_review(review, project_path=str(tmp_path))
    assert result.filtered_count == 1
    assert result.kept[0]['title'] == 'Crit finding'


def test_invalid_payload_raises(tmp_path):
    with pytest.raises(InvalidReviewPayload):
        filter_ai_review([{"file": "x.py"}], project_path=str(tmp_path))  # missing title

    with pytest.raises(InvalidReviewPayload):
        filter_ai_review([{"title": "x"}], project_path=str(tmp_path))  # missing file


def test_load_payload_accepts_top_level_array():
    raw = json.dumps([{"file": "a.py", "title": "t"}])
    items = load_payload(io.StringIO(raw))
    assert items == [{"file": "a.py", "title": "t"}]


def test_load_payload_accepts_wrapped_object():
    """Tools that wrap the array under 'findings' / 'items' / etc. still work."""
    for key in ("findings", "items", "review", "issues"):
        raw = json.dumps({key: [{"file": "a.py", "title": "t"}]})
        items = load_payload(io.StringIO(raw))
        assert items == [{"file": "a.py", "title": "t"}], f"key={key}"


def test_load_payload_rejects_garbage():
    with pytest.raises(InvalidReviewPayload):
        load_payload(io.StringIO("not json"))

    with pytest.raises(InvalidReviewPayload):
        load_payload(io.StringIO('{"not_a_known_key": []}'))


def test_emit_payload_round_trips(sample_review, tmp_path):
    result = filter_ai_review(sample_review, project_path=str(tmp_path))

    buf = io.StringIO()
    emit_payload(result, buf)
    buf.seek(0)
    parsed = json.loads(buf.getvalue())

    assert parsed['metadata']['original_count'] == 4
    assert parsed['metadata']['filtered_count'] == 2
    assert isinstance(parsed['findings'], list)


def test_main_reads_file_and_writes_file(sample_review, tmp_path):
    """The CLI entry point should exit 0 and produce a parseable output file."""
    in_path = tmp_path / "in.json"
    out_path = tmp_path / "out.json"
    in_path.write_text(json.dumps(sample_review))

    rc = main(['--input', str(in_path), '--output', str(out_path),
               '--project-path', str(tmp_path)])
    assert rc == 0

    parsed = json.loads(out_path.read_text())
    titles = {f['title'] for f in parsed['findings']}
    assert 'SQL injection' in titles
    assert 'Hardcoded admin password' in titles
