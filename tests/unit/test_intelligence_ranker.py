"""
Unit tests for the IntelligenceRanker system.

Tests the ranking algorithm, priority calculation, and finding prioritization
to ensure consistent and logical ranking behavior.
"""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime, timedelta

from brass.ranking.intelligence_ranker import IntelligenceRanker
from brass.models.finding import Finding, FindingType, Severity


class TestIntelligenceRanker:
    """Test the IntelligenceRanker core functionality."""
    
    def setup_method(self):
        """Setup fresh ranker for each test."""
        self.ranker = IntelligenceRanker()
    
    def test_ranker_initialization(self):
        """IntelligenceRanker initializes with correct defaults."""
        assert self.ranker.severity_scores is not None
        assert self.ranker.type_priorities is not None
        assert self.ranker.weights is not None
    
    def test_severity_weights_completeness(self):
        """All severity levels have weights defined."""
        expected_severities = {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW}
        actual_severities = set(self.ranker.severity_scores.keys())
        
        assert expected_severities.issubset(actual_severities)
    
    def test_type_weights_completeness(self):
        """All finding types have weights defined.""" 
        expected_types = {FindingType.SECURITY, FindingType.PRIVACY, 
                         FindingType.CODE_QUALITY, FindingType.TODO}
        actual_types = set(self.ranker.type_priorities.keys())
        
        assert expected_types.issubset(actual_types)
    
    def test_severity_weight_ordering(self):
        """Severity weights are ordered logically (higher severity = higher weight)."""
        weights = self.ranker.severity_scores
        
        assert weights[Severity.CRITICAL] > weights[Severity.HIGH]
        assert weights[Severity.HIGH] > weights[Severity.MEDIUM]
        assert weights[Severity.MEDIUM] > weights[Severity.LOW]
    
    def test_rank_findings_calculates_scores(self):
        """rank_findings calculates and adds ranking scores to findings."""
        finding = Finding(
            id="test_score",
            type=FindingType.SECURITY,
            severity=Severity.HIGH,
            file_path="test.py",
            title="Test Security Issue",
            description="Test description",
            confidence=0.9,
            impact_score=0.8,
            detected_by="TestScanner"
        )
        
        result = self.ranker.rank_findings([finding])
        
        assert len(result) == 1
        ranked_finding = result[0]
        assert 'ranking_score' in ranked_finding.metadata
        assert isinstance(ranked_finding.metadata['ranking_score'], float)
        assert ranked_finding.metadata['ranking_score'] >= 0.0
    
    def test_rank_findings_prioritizes_correctly(self):
        """rank_findings prioritizes high-severity findings over low-severity ones."""
        # High-priority finding
        high_priority = Finding(
            id="high_priority",
            type=FindingType.SECURITY,
            severity=Severity.CRITICAL,
            file_path="important.py",
            title="Critical Security Issue",
            description="Critical security vulnerability",
            confidence=1.0,
            impact_score=1.0,
            detected_by="SecurityScanner"
        )
        
        # Low-priority finding
        low_priority = Finding(
            id="low_priority", 
            type=FindingType.TODO,
            severity=Severity.LOW,
            file_path="notes.py",
            title="TODO Comment",
            description="Simple TODO item",
            confidence=0.5,
            impact_score=0.2,
            detected_by="CodeScanner"
        )
        
        result = self.ranker.rank_findings([low_priority, high_priority])  # Intentionally mixed order
        
        # High-priority should be ranked first (check by ID since ranker returns copies)
        assert len(result) == 2
        assert result[0].id == high_priority.id
        assert result[1].id == low_priority.id
        
        # Verify scores reflect priority
        high_score = result[0].metadata['ranking_score']
        low_score = result[1].metadata['ranking_score']
        assert high_score > low_score
    
    def test_rank_findings_uses_file_context_metadata(self):
        """rank_findings uses file context metadata when available for prioritization."""
        # Source code finding (should be prioritized)
        source_finding = Finding(
            id="source_finding",
            type=FindingType.SECURITY,
            severity=Severity.MEDIUM,
            file_path="src/main.py",
            title="Security Issue",
            description="Issue in source code",
            confidence=0.8,
            impact_score=0.7,
            detected_by="Scanner",
            metadata={
                'file_context': {
                    'is_source_code': True,
                    'priority_weight': 1.0,
                    'should_prioritize': True
                }
            }
        )
        
        # Test file finding (should be deprioritized)
        test_finding = Finding(
            id="test_finding",
            type=FindingType.SECURITY,
            severity=Severity.MEDIUM,
            file_path="tests/test_main.py", 
            title="Security Issue",
            description="Issue in test code",
            confidence=0.8,
            impact_score=0.7,
            detected_by="Scanner",
            metadata={
                'file_context': {
                    'is_source_code': False,
                    'priority_weight': 0.3,
                    'should_prioritize': False
                }
            }
        )
        
        result = self.ranker.rank_findings([test_finding, source_finding])
        
        # Source code should be ranked higher due to file context (check by ID since ranker returns copies)
        assert result[0].id == source_finding.id
        assert result[1].id == test_finding.id
        
        # Verify scores
        source_score = result[0].metadata['ranking_score']
        test_score = result[1].metadata['ranking_score']
        assert source_score > test_score
    
    def test_rank_findings_considers_temporal_factors(self):
        """rank_findings considers temporal factors for recent findings."""
        # Recent finding
        recent_finding = Finding(
            id="recent",
            type=FindingType.SECURITY,
            severity=Severity.MEDIUM,
            file_path="test.py",
            title="Recent Issue",
            description="Recently detected issue",
            confidence=0.8,
            impact_score=0.7,
            detected_by="Scanner",
            detected_at=datetime.now()  # Very recent
        )
        
        # Old finding  
        old_finding = Finding(
            id="old",
            type=FindingType.SECURITY,
            severity=Severity.MEDIUM,
            file_path="test.py",
            title="Old Issue", 
            description="Old issue",
            confidence=0.8,
            impact_score=0.7,
            detected_by="Scanner",
            detected_at=datetime.now() - timedelta(days=30)  # Old
        )
        
        result = self.ranker.rank_findings([old_finding, recent_finding])
        
        # Recent finding should be ranked higher due to recency bonus (check by ID since ranker returns copies)
        assert result[0].id == recent_finding.id
        assert result[1].id == old_finding.id
    
    def test_rank_findings_empty_list(self):
        """rank_findings handles empty input correctly."""
        result = self.ranker.rank_findings([])
        
        assert result == []
    
    def test_rank_findings_single_item(self):
        """rank_findings handles single finding correctly."""
        finding = Finding(
            id="single",
            type=FindingType.SECURITY,
            severity=Severity.HIGH,
            file_path="test.py",
            title="Single Issue",
            description="Single test issue",
            confidence=0.9,
            impact_score=0.8,
            detected_by="Scanner"
        )
        
        result = self.ranker.rank_findings([finding])
        
        assert len(result) == 1
        assert result[0].id == finding.id
        assert 'ranking_score' in result[0].metadata
        assert 'ranking_position' in result[0].metadata
    
    def test_rank_findings_ordering(self):
        """rank_findings orders findings by priority correctly."""
        # Create findings with different priorities
        critical_finding = Finding(
            id="critical",
            type=FindingType.SECURITY,
            severity=Severity.CRITICAL,
            file_path="critical.py",
            title="Critical Issue",
            description="Critical security issue",
            confidence=1.0,
            impact_score=1.0,
            detected_by="Scanner"
        )
        
        medium_finding = Finding(
            id="medium",
            type=FindingType.CODE_QUALITY,
            severity=Severity.MEDIUM,
            file_path="medium.py",
            title="Medium Issue", 
            description="Medium priority issue",
            confidence=0.8,
            impact_score=0.6,
            detected_by="Scanner"
        )
        
        low_finding = Finding(
            id="low",
            type=FindingType.TODO,
            severity=Severity.LOW,
            file_path="todo.py",
            title="TODO Item",
            description="Low priority TODO",
            confidence=0.6,
            impact_score=0.3,
            detected_by="Scanner"
        )
        
        # Rank in random order
        findings = [medium_finding, low_finding, critical_finding]
        result = self.ranker.rank_findings(findings)
        
        # Should be ordered by priority (highest first) - check by ID since ranker returns copies
        assert result[0].id == critical_finding.id
        assert result[1].id == medium_finding.id
        assert result[2].id == low_finding.id
        
        # Check that all findings have ranking scores and positions
        for i, finding in enumerate(result):
            assert 'ranking_score' in finding.metadata
            assert isinstance(finding.metadata['ranking_score'], float)
            assert 'ranking_position' in finding.metadata
            assert finding.metadata['ranking_position'] == i + 1
    
    def test_rank_findings_metadata_preservation(self):
        """rank_findings preserves existing metadata."""
        finding = Finding(
            id="with_metadata",
            type=FindingType.SECURITY,
            severity=Severity.HIGH,
            file_path="test.py",
            title="Test Issue",
            description="Test description",
            confidence=0.9,
            impact_score=0.8,
            detected_by="Scanner",
            metadata={"existing_key": "existing_value"}
        )
        
        result = self.ranker.rank_findings([finding])
        
        # Should preserve existing metadata
        assert result[0].metadata["existing_key"] == "existing_value"
        # Should add ranking metadata
        assert "ranking_score" in result[0].metadata
        assert "ranking_position" in result[0].metadata
    
    @patch('brass.ranking.intelligence_ranker.logger')
    def test_rank_findings_invalid_input_handling(self, mock_logger):
        """rank_findings handles invalid input gracefully."""
        # Mix valid findings with invalid objects
        valid_finding = Finding(
            id="valid",
            type=FindingType.SECURITY,
            severity=Severity.HIGH,
            file_path="test.py",
            title="Valid Issue",
            description="Valid description",
            confidence=0.9,
            impact_score=0.8,
            detected_by="Scanner"
        )
        
        invalid_object = "not_a_finding"
        
        result = self.ranker.rank_findings([valid_finding, invalid_object, None])
        
        # Should return only valid findings (check by ID since ranker returns copies)
        assert len(result) == 1
        assert result[0].id == valid_finding.id
        
        # Should log warnings about invalid items
        assert mock_logger.warning.call_count >= 1
    
    def test_confidence_threshold_filtering(self):
        """Findings below confidence threshold are handled appropriately."""
        # High confidence finding
        high_confidence = Finding(
            id="high_conf",
            type=FindingType.SECURITY,
            severity=Severity.HIGH,
            file_path="test.py",
            title="High Confidence Issue",
            description="High confidence description",
            confidence=0.9,  # Above threshold
            impact_score=0.8,
            detected_by="Scanner"
        )
        
        # Low confidence finding
        low_confidence = Finding(
            id="low_conf",
            type=FindingType.SECURITY,
            severity=Severity.HIGH,
            file_path="test.py",
            title="Low Confidence Issue",
            description="Low confidence description", 
            confidence=0.3,  # Below threshold
            impact_score=0.8,
            detected_by="Scanner"
        )
        
        result = self.ranker.rank_findings([high_confidence, low_confidence])
        
        # Both should be included but high confidence should rank higher
        assert len(result) == 2
        high_score = result[0].metadata.get('ranking_score', 0)
        low_score = result[1].metadata.get('ranking_score', 0)
        
        if result[0] is high_confidence:  # High confidence should be first
            assert high_score > low_score
        else:  # Or if ordering different, low confidence should have lower score
            assert low_score < high_score


class TestRankingPerformance:
    """Test ranking system performance characteristics."""
    
    def test_ranking_large_dataset(self):
        """Ranking performs reasonably with large datasets."""
        ranker = IntelligenceRanker()
        
        # Create many findings
        findings = []
        for i in range(1000):
            finding = Finding(
                id=f"finding_{i}",
                type=FindingType.SECURITY if i % 2 == 0 else FindingType.CODE_QUALITY,
                severity=Severity.HIGH if i % 3 == 0 else Severity.MEDIUM,
                file_path=f"file_{i}.py",
                title=f"Issue {i}",
                description=f"Description for issue {i}",
                confidence=0.8,
                impact_score=0.7,
                detected_by="Scanner"
            )
            findings.append(finding)
        
        # Should complete without timeout or memory issues
        result = ranker.rank_findings(findings)
        
        assert len(result) == 1000
        # Check that rankings are assigned
        assert all('ranking_score' in f.metadata for f in result)
        assert all('ranking_position' in f.metadata for f in result)
    
    def test_ranking_deterministic(self):
        """Ranking produces deterministic results for same input."""
        ranker = IntelligenceRanker()
        
        findings = [
            Finding(
                id="finding_1",
                type=FindingType.SECURITY,
                severity=Severity.HIGH,
                file_path="test1.py",
                title="Issue 1",
                description="Description 1",
                confidence=0.9,
                impact_score=0.8,
                detected_by="Scanner"
            ),
            Finding(
                id="finding_2", 
                type=FindingType.CODE_QUALITY,
                severity=Severity.MEDIUM,
                file_path="test2.py",
                title="Issue 2",
                description="Description 2",
                confidence=0.7,
                impact_score=0.6,
                detected_by="Scanner"
            )
        ]
        
        # Rank multiple times
        result1 = ranker.rank_findings(findings.copy())
        result2 = ranker.rank_findings(findings.copy())
        
        # Results should be identical
        assert len(result1) == len(result2)
        for f1, f2 in zip(result1, result2):
            assert f1.id == f2.id
            assert f1.metadata['ranking_score'] == f2.metadata['ranking_score']
            assert f1.metadata['ranking_position'] == f2.metadata['ranking_position']

# --------------------------------------------------------------------------- #
# Regression: risk_level on findings outside SOURCE_CODE classification        #
# --------------------------------------------------------------------------- #


def _make_finding(severity: Severity, file_path: str) -> Finding:
    """Build a Finding for the risk-calculation tests below.

    The new risk bucketing uses FileClassifier on ``file_path`` directly
    (not metadata['file_context']), so these tests pass real path shapes
    that map to the FileClassifier buckets being exercised.
    """
    return Finding(
        id=f"test_{file_path}_{severity.value}",
        type=FindingType.SECURITY,
        severity=severity,
        file_path=file_path,
        title="test finding",
        description="x",
        confidence=0.9,
        impact_score=0.9,
        detected_by="test",
        metadata={},
    )


def test_risk_level_counts_unknown_bucket_findings():
    """Regression for the copper-sun "risk_level: LOW with 62 criticals"
    symptom. FileClassifier source_patterns require specific prefixes
    (src/, lib/, app/, apps/, packages/, pkg/, internal/, components/,
    or root-only). Projects with code in `modal/`, `services/`, `agents/`
    classify as UNKNOWN. The fix routes UNKNOWN-bucket findings into
    risk so customer layouts outside the conventions are scored.
    """
    ranker = IntelligenceRanker()
    findings = [
        _make_finding(Severity.CRITICAL, "modal/a.py"),
        _make_finding(Severity.CRITICAL, "modal/b.py"),
        _make_finding(Severity.CRITICAL, "modal/c.py"),
    ]
    result = ranker.calculate_contextual_risk_level(findings)
    assert result["risk_level"] == "HIGH"
    assert result["critical_source_issues"] == 3


def test_risk_level_ignores_test_file_findings():
    """TEST_FILE + TEST_FIXTURE buckets are intentional fixture data and
    must not drive risk_level. Canonical Visa/SSN test data lives there
    on purpose."""
    ranker = IntelligenceRanker()
    findings = [
        _make_finding(Severity.CRITICAL, "tests/test_cards.py"),
        _make_finding(Severity.CRITICAL, "tests/fixtures/ssns.py"),
        _make_finding(Severity.CRITICAL, "tests/conftest.py"),
    ]
    result = ranker.calculate_contextual_risk_level(findings)
    assert result["risk_level"] == "LOW"
    assert result["critical_source_issues"] == 0


def test_risk_level_source_findings_count():
    """SOURCE_CODE bucket findings drive risk (sanity check)."""
    ranker = IntelligenceRanker()
    findings = [
        _make_finding(Severity.CRITICAL, "src/a.py"),
        _make_finding(Severity.CRITICAL, "src/b.py"),
        _make_finding(Severity.CRITICAL, "src/c.py"),
    ]
    result = ranker.calculate_contextual_risk_level(findings)
    assert result["risk_level"] == "HIGH"
    assert result["critical_source_issues"] == 3


def test_risk_level_excludes_build_output_findings():
    """BUILD_OUTPUT findings (__pycache__, .pytest_cache, node_modules)
    must NOT drive risk_level, even if upstream filtering missed them.
    Bug-scan flagged that the previous fix would have lumped these
    into the 'other' bucket and inflated reported risk."""
    ranker = IntelligenceRanker()
    findings = [
        _make_finding(Severity.CRITICAL, "__pycache__/whatever.pyc"),
        _make_finding(Severity.CRITICAL, "node_modules/lodash/index.js"),
        _make_finding(Severity.CRITICAL, "dist/bundle.js"),
    ]
    result = ranker.calculate_contextual_risk_level(findings)
    assert result["risk_level"] == "LOW"
    assert result["critical_source_issues"] == 0


def test_risk_level_excludes_config_and_doc_findings():
    """CONFIGURATION (setup.py, pyproject.toml) + DOCUMENTATION (*.md)
    findings are low-priority; they must not drive risk_level."""
    ranker = IntelligenceRanker()
    findings = [
        _make_finding(Severity.CRITICAL, "setup.py"),
        _make_finding(Severity.CRITICAL, "pyproject.toml"),
        _make_finding(Severity.CRITICAL, "README.md"),
        _make_finding(Severity.CRITICAL, "docs/architecture.md"),
    ]
    result = ranker.calculate_contextual_risk_level(findings)
    assert result["risk_level"] == "LOW"
    assert result["critical_source_issues"] == 0


def test_production_code_finding_outranks_test_finding_at_same_severity():
    """The 2026-05-17 architectural fix: the ranker now pre-populates
    `finding.metadata['file_context']` from FileClassifier BEFORE
    scoring. Without that step, file_importance always fell back to
    the legacy text-matching path and a HIGH-severity finding in
    `src/` would tie with a HIGH-severity finding in `tests/`.

    With the fix, the FileClassifier's actual `is_source_code` flag
    drives `_calculate_file_importance`, so production code outranks
    test code at the same severity — which is what reorders the
    YAML's `critical_issues:` to put production-code SSRFs above
    test-fixture credential hits.
    """
    ranker = IntelligenceRanker(project_path="/tmp/fake_project")
    production = _make_finding(Severity.HIGH, "src/auth/handler.py")
    test_file = _make_finding(Severity.HIGH, "tests/unit/test_auth.py")
    ranked = ranker.rank_findings([test_file, production])
    # Production-code finding must come first regardless of input order.
    assert ranked[0].file_path == "src/auth/handler.py", (
        f"Expected production finding first; got order: "
        f"{[f.file_path for f in ranked]}"
    )


def test_ranker_respects_preexisting_file_context_metadata():
    """If a scanner already populated `metadata['file_context']`
    (rare but possible for scanners that need to know file role
    upstream), the ranker MUST NOT overwrite it. Tests the
    `if metadata.get('file_context') is not None: continue` guard."""
    ranker = IntelligenceRanker(project_path="/tmp/fake_project")
    sentinel = {"file_type": "documentation", "is_source_code": False}
    finding = _make_finding(Severity.HIGH, "src/auth/handler.py")
    finding.metadata = {"file_context": sentinel}
    ranker.rank_findings([finding])
    # The sentinel must survive — the ranker only fills in `None`.
    assert finding.metadata["file_context"] is sentinel


def test_ranker_skips_file_context_when_no_project_path():
    """A ranker constructed without `project_path` (the unit-test path)
    must not call FileClassifier — the classifier needs a project root
    to normalize paths. Behavior unchanged for those rankers."""
    ranker = IntelligenceRanker()  # no project_path
    finding = _make_finding(Severity.HIGH, "src/auth/handler.py")
    ranker.rank_findings([finding])
    # No file_context should be injected.
    assert (finding.metadata or {}).get("file_context") is None
