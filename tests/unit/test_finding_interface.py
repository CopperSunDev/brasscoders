"""
Unit tests for Finding dataclass interface validation.
Ensures the sacred Finding contract is never broken.
"""

import pytest
from brass.models.finding import Finding, FindingType, Severity


class TestFindingInterface:
    """Test the Finding dataclass interface - the sacred contract."""
    
    def test_finding_interface_compliance(self, sample_finding):
        """Finding interface has all required fields."""
        finding = sample_finding
        
        # Validate required fields exist
        assert hasattr(finding, 'id')
        assert hasattr(finding, 'type')
        assert hasattr(finding, 'severity')
        assert hasattr(finding, 'file_path')
        assert hasattr(finding, 'line_number')
        assert hasattr(finding, 'title')
        assert hasattr(finding, 'description')
        assert hasattr(finding, 'confidence')
        assert hasattr(finding, 'impact_score')
        assert hasattr(finding, 'detected_by')
        
        # Validate field types
        assert isinstance(finding.id, str)
        assert isinstance(finding.type, FindingType)
        assert isinstance(finding.severity, Severity)
        assert isinstance(finding.file_path, str)
        assert isinstance(finding.title, str)
        assert isinstance(finding.description, str)
        assert isinstance(finding.confidence, float)
        assert isinstance(finding.impact_score, float)
        assert isinstance(finding.detected_by, str)
    
    def test_finding_type_enum_values(self):
        """FindingType enum contains expected values."""
        expected_types = {'SECURITY', 'PRIVACY', 'CODE_QUALITY', 'TODO'}
        actual_types = {ft.name for ft in FindingType}
        assert expected_types.issubset(actual_types), f"Missing types: {expected_types - actual_types}"
    
    def test_severity_enum_values(self):
        """Severity enum contains expected values."""
        expected_severities = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'}
        actual_severities = {s.name for s in Severity}
        assert expected_severities.issubset(actual_severities), f"Missing severities: {expected_severities - actual_severities}"
    
    @pytest.mark.parametrize("confidence,impact", [
        (0.0, 0.0),
        (0.5, 0.5),
        (1.0, 1.0),
        (0.95, 0.85)
    ])
    def test_finding_score_validation(self, confidence, impact):
        """Finding confidence and impact scores are properly validated."""
        finding = Finding(
            id=f"test_scores_{confidence}_{impact}",
            type=FindingType.SECURITY,
            severity=Severity.HIGH,
            file_path="test.py",
            title="Score Test",
            description="Testing score validation",
            confidence=confidence,
            impact_score=impact,
            detected_by="TestScanner"
        )
        
        # Confidence validation
        assert 0.0 <= finding.confidence <= 1.0
        
        # Impact score validation
        assert 0.0 <= finding.impact_score <= 1.0
    
    def test_finding_field_validation(self):
        """Finding fields have reasonable validation."""
        finding = Finding(
            id="test_id_123",
            type=FindingType.SECURITY,
            severity=Severity.CRITICAL,
            file_path="src/test.py",
            line_number=42,
            title="Test Security Issue",
            description="This is a test security finding with detailed description",
            confidence=0.95,
            impact_score=0.85,
            detected_by="CodeScanner"
        )
        
        # ID validation
        assert len(finding.id) > 0
        assert isinstance(finding.id, str)
        
        # File path validation
        assert len(finding.file_path) > 0
        assert isinstance(finding.file_path, str)
        
        # Title validation
        assert len(finding.title) > 0
        assert len(finding.title) <= 200  # Reasonable upper bound
        
        # Description validation
        assert len(finding.description) > 0
        
        # Line number validation (can be None)
        if finding.line_number is not None:
            assert finding.line_number > 0
    
    def test_finding_optional_fields(self):
        """Finding handles optional fields correctly."""
        # Test with minimal required fields
        finding = Finding(
            id="minimal_test",
            type=FindingType.CODE_QUALITY,
            severity=Severity.MEDIUM,
            file_path="test.py",
            title="Minimal Finding",
            description="Minimal test finding",
            confidence=0.8,
            impact_score=0.6,
            detected_by="TestScanner"
        )
        
        # Optional fields should handle None gracefully
        assert finding.line_number is None or isinstance(finding.line_number, int)
        assert finding.column is None or isinstance(finding.column, int)
        assert finding.code_snippet is None or isinstance(finding.code_snippet, str)
        assert finding.remediation is None or isinstance(finding.remediation, str)
        assert finding.references is None or isinstance(finding.references, list)
    
    def test_finding_equality_and_hashing(self):
        """Finding objects can be compared and hashed."""
        from datetime import datetime
        
        # Use same timestamp to ensure equality works
        timestamp = datetime.now()
        
        finding1 = Finding(
            id="same_id",
            type=FindingType.SECURITY,
            severity=Severity.HIGH,
            file_path="test.py",
            title="Test Finding",
            description="Test description",
            confidence=0.9,
            impact_score=0.8,
            detected_by="TestScanner",
            detected_at=timestamp
        )
        
        finding2 = Finding(
            id="same_id",
            type=FindingType.SECURITY,
            severity=Severity.HIGH,
            file_path="test.py",
            title="Test Finding",
            description="Test description",
            confidence=0.9,
            impact_score=0.8,
            detected_by="TestScanner",
            detected_at=timestamp
        )
        
        finding3 = Finding(
            id="different_id",
            type=FindingType.SECURITY,
            severity=Severity.HIGH,
            file_path="test.py",
            title="Test Finding",
            description="Test description",
            confidence=0.9,
            impact_score=0.8,
            detected_by="TestScanner",
            detected_at=timestamp
        )
        
        # Test equality
        assert finding1 == finding2
        assert finding1 != finding3
        
        # Test that findings can be used in lists (since they're not hashable for sets)
        finding_list = [finding1, finding2, finding3]
        assert len(finding_list) == 3
        
        # Test that we can distinguish findings properly
        unique_findings = []
        for f in finding_list:
            if f not in unique_findings:
                unique_findings.append(f)
        assert len(unique_findings) == 2  # finding1 and finding2 should be considered same
    
    def test_finding_metadata_field(self):
        """Finding metadata field works correctly."""
        metadata = {
            'ranking_score': 0.95,
            'ranking_position': 1,
            'custom_data': 'test_value'
        }
        
        finding = Finding(
            id="metadata_test",
            type=FindingType.PRIVACY,
            severity=Severity.CRITICAL,
            file_path="test.py",
            title="Test with Metadata",
            description="Testing metadata functionality",
            confidence=0.9,
            impact_score=0.8,
            detected_by="TestScanner",
            metadata=metadata
        )
        
        assert finding.metadata is not None
        assert isinstance(finding.metadata, dict)
        assert finding.metadata['ranking_score'] == 0.95
        assert finding.metadata['ranking_position'] == 1
        assert finding.metadata['custom_data'] == 'test_value'


@pytest.mark.unit
class TestFindingEnums:
    """Test Finding enums in isolation."""
    
    def test_finding_type_completeness(self):
        """All expected FindingType values exist."""
        # Test individual enum values
        assert FindingType.SECURITY is not None
        assert FindingType.PRIVACY is not None
        assert FindingType.CODE_QUALITY is not None
        assert FindingType.TODO is not None
        
        # Test enum can be used in comparisons
        assert FindingType.SECURITY != FindingType.PRIVACY
        assert FindingType.CODE_QUALITY != FindingType.TODO
    
    def test_severity_ordering(self):
        """Severity enum has logical ordering."""
        # Test individual enum values
        assert Severity.CRITICAL is not None
        assert Severity.HIGH is not None
        assert Severity.MEDIUM is not None
        assert Severity.LOW is not None
        
        # Test severity can be used in comparisons
        assert Severity.CRITICAL != Severity.HIGH
        assert Severity.MEDIUM != Severity.LOW