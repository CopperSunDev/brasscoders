"""
Unit tests for the OutputGenerator component.

Tests the public API of report generation and intelligence file creation
to ensure consistent and useful output for AI development intelligence.
"""

import pytest
import tempfile
import shutil
from pathlib import Path

from brass.output.output_generator import OutputGenerator
from brass.models.finding import Finding, FindingType, Severity


class TestOutputGenerator:
    """Test the OutputGenerator public API."""
    
    def setup_method(self):
        """Setup generator for each test with temporary directory."""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.generator = OutputGenerator(str(self.temp_dir))
    
    def teardown_method(self):
        """Clean up temporary directory after each test."""
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
    
    def test_output_generator_initialization(self):
        """OutputGenerator initializes with correct project path."""
        # resolve() is called in the constructor, so we need to compare resolved paths
        assert self.generator.project_path == self.temp_dir.resolve()
        assert self.generator.output_dir == self.temp_dir.resolve() / ".brass"
    
    def test_generate_intelligence_returns_file_paths(self):
        """generate_intelligence returns a dictionary of generated file paths."""
        findings = []
        
        result = self.generator.generate_intelligence(findings)
        
        assert isinstance(result, dict)
        # Should return paths to generated files
        assert len(result) > 0
        
        # Verify expected files are generated
        expected_keys = ['ai_instructions', 'json_export']
        for expected_key in expected_keys:
            assert expected_key in result
    
    def test_generate_intelligence_creates_directory(self):
        """generate_intelligence creates output directory if it doesn't exist."""
        findings = []
        
        # Ensure directory doesn't exist initially
        assert not self.generator.output_dir.exists()
        
        result = self.generator.generate_intelligence(findings)
        
        # Should create .brass directory
        assert self.generator.output_dir.exists()
        assert self.generator.output_dir.is_dir()
    
    def test_generate_intelligence_creates_files(self):
        """generate_intelligence creates expected output files."""
        findings = []
        
        result = self.generator.generate_intelligence(findings)
        
        # Should create expected files
        assert isinstance(result, dict)
        assert len(result) > 0
        
        # Verify some expected files exist
        for filename, filepath in result.items():
            assert Path(filepath).exists(), f"File {filename} should exist at {filepath}"
            # Verify files are not empty
            assert Path(filepath).stat().st_size > 0, f"File {filename} should not be empty"
    
    def test_generate_intelligence_with_findings(self):
        """generate_intelligence processes findings correctly."""
        findings = [
            Finding(
                id="test_finding",
                type=FindingType.SECURITY,
                severity=Severity.HIGH,
                file_path="test.py",
                line_number=42,
                title="Test Security Issue",
                description="Test description",
                confidence=0.9,
                impact_score=0.8,
                detected_by="TestScanner"
            )
        ]
        
        result = self.generator.generate_intelligence(findings)
        
        # Should generate intelligence files
        assert isinstance(result, dict)
        assert len(result) > 0
        
        # Should include AI instructions
        assert 'ai_instructions' in result
        
        # Check that the AI instructions file contains the finding
        ai_instructions_path = result['ai_instructions']
        with open(ai_instructions_path, 'r') as f:
            content = f.read()
            assert "Test Security Issue" in content
            assert "test.py" in content
    
    def test_generate_intelligence_with_multiple_finding_types(self):
        """generate_intelligence handles multiple finding types correctly."""
        findings = [
            Finding(
                id="security_finding",
                type=FindingType.SECURITY,
                severity=Severity.CRITICAL,
                file_path="src/auth.py",
                line_number=42,
                title="Hardcoded Password",
                description="Password found in source code",
                confidence=0.95,
                impact_score=0.9,
                detected_by="CodeScanner"
            ),
            Finding(
                id="privacy_finding",
                type=FindingType.PRIVACY,
                severity=Severity.HIGH,
                file_path="src/user.py",
                line_number=15,
                title="Email Address Detected",
                description="Email address found in logs",
                confidence=0.85,
                impact_score=0.8,
                detected_by="PrivacyScanner"
            ),
            Finding(
                id="todo_finding",
                type=FindingType.TODO,
                severity=Severity.LOW,
                file_path="src/utils.py",
                line_number=100,
                title="TODO Comment",
                description="TODO: Implement this function",
                confidence=1.0,
                impact_score=0.3,
                detected_by="CodeScanner"
            )
        ]
        
        result = self.generator.generate_intelligence(findings)
        
        # Should generate all expected files
        assert isinstance(result, dict)
        assert 'ai_instructions' in result
        assert 'detailed_analysis' in result
        assert 'json_export' in result
        
        # Check that findings are included in the analysis
        ai_instructions_path = result['ai_instructions']
        with open(ai_instructions_path, 'r') as f:
            content = f.read()
            assert "Hardcoded Password" in content
            assert "Email Address Detected" in content
            assert "src/auth.py" in content
            assert "src/user.py" in content
    
    def test_generate_intelligence_empty_findings(self):
        """generate_intelligence handles empty findings list gracefully."""
        findings = []
        
        result = self.generator.generate_intelligence(findings)
        
        # Should still generate files
        assert isinstance(result, dict)
        assert len(result) > 0
        
        # Should create AI instructions even with no findings
        assert 'ai_instructions' in result
        
        # Check that the file contains appropriate empty state message
        ai_instructions_path = result['ai_instructions']
        with open(ai_instructions_path, 'r') as f:
            content = f.read()
            # Should contain some indication of no findings
            assert "0 issues" in content or "No findings" in content or "Analysis complete" in content
    
    def test_generate_intelligence_with_metadata(self):
        """generate_intelligence processes finding metadata correctly."""
        finding_with_metadata = Finding(
            id="metadata_test",
            type=FindingType.SECURITY,
            severity=Severity.HIGH,
            file_path="test.py",
            title="Security Issue with Metadata",
            description="Test description",
            confidence=0.9,
            impact_score=0.8,
            detected_by="TestScanner",
            metadata={
                'ranking_score': 85.5,
                'ranking_position': 1,
                'custom_data': 'test_value'
            }
        )
        
        result = self.generator.generate_intelligence([finding_with_metadata])
        
        # Should generate analysis with metadata considered
        assert isinstance(result, dict)
        assert 'ai_instructions' in result
        
        # Verify the finding appears in output
        ai_instructions_path = result['ai_instructions']
        with open(ai_instructions_path, 'r') as f:
            content = f.read()
            assert "Security Issue with Metadata" in content
    
    def test_generate_intelligence_deterministic(self):
        """generate_intelligence produces consistent output for same input."""
        findings = [
            Finding(
                id="deterministic_test",
                type=FindingType.CODE_QUALITY,
                severity=Severity.MEDIUM,
                file_path="test.py",
                title="Code Quality Issue",
                description="Test for deterministic output",
                confidence=0.8,
                impact_score=0.6,
                detected_by="TestScanner"
            )
        ]
        
        # Generate intelligence twice
        result1 = self.generator.generate_intelligence(findings)
        result2 = self.generator.generate_intelligence(findings)
        
        # Should return same file structure
        assert result1.keys() == result2.keys()
        
        # Content should be consistent (allowing for timestamps)
        ai_path1 = result1['ai_instructions']
        ai_path2 = result2['ai_instructions']
        
        with open(ai_path1, 'r') as f1, open(ai_path2, 'r') as f2:
            content1 = f1.read()
            content2 = f2.read()
            
            # Should contain the same finding information
            assert "Code Quality Issue" in content1
            assert "Code Quality Issue" in content2
            assert "test.py" in content1
            assert "test.py" in content2


class TestOutputGeneratorEdgeCases:
    """Test edge cases and error conditions in output generation."""
    
    def setup_method(self):
        """Setup generator for edge case tests."""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.generator = OutputGenerator(str(self.temp_dir))
    
    def teardown_method(self):
        """Clean up temporary directory after each test."""
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
    
    def test_findings_without_line_numbers(self):
        """Generator handles findings without line numbers gracefully."""
        finding_without_line = Finding(
            id="no_line",
            type=FindingType.CODE_QUALITY,
            severity=Severity.MEDIUM,
            file_path="src/utils.py",
            line_number=None,  # No line number
            title="Code Quality Issue",
            description="Issue without specific line",
            confidence=0.8,
            impact_score=0.7,
            detected_by="CodeScanner"
        )
        
        result = self.generator.generate_intelligence([finding_without_line])
        
        # Should handle gracefully
        assert isinstance(result, dict)
        assert 'ai_instructions' in result
        
        # Should show file path without line number
        ai_instructions_path = result['ai_instructions']
        with open(ai_instructions_path, 'r') as f:
            content = f.read()
            assert "src/utils.py" in content
            assert "Code Quality Issue" in content
    
    def test_findings_with_very_long_descriptions(self):
        """Generator handles very long descriptions appropriately."""
        very_long_description = "A" * 1000  # 1000 character description
        
        finding_with_long_desc = Finding(
            id="long_desc",
            type=FindingType.SECURITY,
            severity=Severity.HIGH,
            file_path="src/test.py",
            title="Long Description Test",
            description=very_long_description,
            confidence=0.9,
            impact_score=0.8,
            detected_by="TestScanner"
        )
        
        result = self.generator.generate_intelligence([finding_with_long_desc])
        
        # Should handle without issues
        assert isinstance(result, dict)
        assert 'ai_instructions' in result
        
        # Should include the finding
        ai_instructions_path = result['ai_instructions']
        with open(ai_instructions_path, 'r') as f:
            content = f.read()
            assert "Long Description Test" in content
    
    def test_stale_operator_notes_yaml_is_removed_when_no_advisories(self):
        """operator_notes.yaml is conditionally generated only when
        there's at least one advisory. Before this fix, a stale file
        from a prior scan (e.g. cache-pressure warning that no longer
        applies) would silently persist — customers would see a stale
        operator advisory next to a fresh scan and not know which
        applied to current state.

        Now: when the current scan has no advisories AND a stale
        operator_notes.yaml exists on disk, it's removed.

        Surfaced 2026-05-30 during Phase F.6 of the LS launch: the
        CLI reported "Generated 6 intelligence files" while the
        on-disk count was 7 (the 7th being a stale operator_notes
        from a prior scan when cache pressure had triggered an
        advisory). The discrepancy was a UX bug, not a counting
        bug.
        """
        from unittest.mock import patch
        from brass.output.yaml_output_generator_v2 import YAMLOutputGeneratorV2

        v2 = YAMLOutputGeneratorV2(str(self.temp_dir))
        v2.output_dir.mkdir(parents=True, exist_ok=True)

        # Plant a stale operator_notes.yaml as if from a previous scan.
        stale_path = v2.output_dir / 'operator_notes.yaml'
        stale_path.write_text(
            "system_advisories:\n"
            "  - level: warning\n"
            "    code: cache_pressure\n"
            "    title: 'Stale advisory from a prior scan'\n"
        )
        assert stale_path.exists()  # Sanity: we set up the precondition.

        # Force "no advisories this scan" by patching the AI-instructions
        # builder's advisory list. Empty findings list keeps things tidy.
        with patch.object(
            v2.builders['ai_instructions'],
            '_build_system_advisories',
            return_value=[],
        ):
            result = v2._generate_operator_notes([])

        # Returned dict is empty (file was not regenerated)...
        assert result == {}
        # ...and the stale file has been removed.
        assert not stale_path.exists(), (
            "Stale operator_notes.yaml should be removed when current "
            "scan has no advisories"
        )

    def test_operator_notes_yaml_regenerated_when_advisories_fire(self):
        """Contract: when there ARE advisories, operator_notes.yaml is
        (re)written with current content. This is the existing happy
        path; pinning it here so the stale-file-cleanup change doesn't
        regress it."""
        from unittest.mock import patch
        from brass.output.yaml_output_generator_v2 import YAMLOutputGeneratorV2
        import yaml

        v2 = YAMLOutputGeneratorV2(str(self.temp_dir))
        v2.output_dir.mkdir(parents=True, exist_ok=True)
        fake_advisories = [
            {
                'level': 'warning',
                'code': 'cache_pressure',
                'title': 'BrassCoders cache is large',
                'summary': 'Test advisory.',
                'user_action': 'Run brasscoders cache clear.',
                'ai_action': 'Surface this to the user.',
            }
        ]

        with patch.object(
            v2.builders['ai_instructions'],
            '_build_system_advisories',
            return_value=fake_advisories,
        ):
            result = v2._generate_operator_notes([])

        # File was written.
        out_path = v2.output_dir / 'operator_notes.yaml'
        assert out_path.exists()
        assert result == {'operator_notes': str(out_path)}

        # Content has the advisory.
        data = yaml.safe_load(out_path.read_text())
        assert 'system_advisories' in data
        assert data['system_advisories'] == fake_advisories

    def test_findings_without_metadata(self):
        """Generator handles findings without metadata."""
        finding_without_metadata = Finding(
            id="no_metadata",
            type=FindingType.TODO,
            severity=Severity.LOW,
            file_path="src/todo.py",
            title="TODO Item",
            description="Simple TODO without metadata",
            confidence=0.6,
            impact_score=0.5,
            detected_by="CodeScanner"
            # No metadata provided
        )
        
        # Should not crash when processing findings without metadata
        result = self.generator.generate_intelligence([finding_without_metadata])
        
        assert isinstance(result, dict)
        assert 'ai_instructions' in result
        
        # Should include the finding
        ai_instructions_path = result['ai_instructions']
        with open(ai_instructions_path, 'r') as f:
            content = f.read()
            assert "TODO Item" in content