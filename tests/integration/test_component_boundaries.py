"""
Component boundary tests for New BrassCoders System v2.0.

Tests the interfaces and contracts between major system components,
ensuring clean separation of concerns and proper data flow.
"""

import pytest
import tempfile
from pathlib import Path
from typing import List, Dict

from brass.scanners.professional_code_scanner import ProfessionalCodeScanner as CodeScanner
from brass.scanners.brass2_privacy_scanner import Brass2PrivacyScanner
from brass.scanners.content_moderation_scanner import ContentModerationScanner
from brass.ranking.intelligence_ranker import IntelligenceRanker
from brass.output.output_generator import OutputGenerator
from brass.models.finding import Finding, FindingType, Severity


class TestComponentBoundaries:
    """Test clean separation between system components."""
    
    def test_scanner_finding_interface_contract(self, temp_project):
        """Test that all scanners produce valid Finding objects that conform to the sacred interface."""
        
        # Create test file that will trigger multiple finding types
        test_file = temp_project / "interface_test.py"
        test_file.write_text('''
# TODO: Test the Finding interface contract
def test_function():
    # Hardcoded secret (security)
    api_key = "sk-1234567890abcdef1234567890abcdef"
    
    # PII data (privacy)
    email = "test@example.com"
    
    # Complex function (code quality)
    if True:
        if True:
            if True:
                if True:
                    if True:
                        if True:
                            return eval("2+2")  # Also security
''')
        
        # Test each scanner produces valid Finding objects
        scanners = [
            ("CodeScanner", CodeScanner(str(temp_project))),
            ("Brass2Brass2PrivacyScanner", Brass2Brass2PrivacyScanner(str(temp_project))),
            ("ContentModerationScanner", ContentModerationScanner(str(temp_project)))
        ]
        
        for scanner_name, scanner in scanners:
            findings = scanner.scan()
            
            # Each scanner must return a list
            assert isinstance(findings, list), f"{scanner_name} must return List[Finding]"
            
            # Verify Finding interface contract for each finding
            for finding in findings:
                # Must be Finding instance
                assert isinstance(finding, Finding), f"{scanner_name} must produce Finding objects"
                
                # Sacred interface requirements
                assert isinstance(finding.id, str) and len(finding.id) > 0, "Finding.id must be non-empty string"
                assert isinstance(finding.type, FindingType), "Finding.type must be FindingType enum"
                assert isinstance(finding.severity, Severity), "Finding.severity must be Severity enum"
                assert isinstance(finding.file_path, str) and len(finding.file_path) > 0, "Finding.file_path must be non-empty string"
                assert isinstance(finding.title, str) and len(finding.title) > 0, "Finding.title must be non-empty string"
                assert isinstance(finding.description, str) and len(finding.description) > 0, "Finding.description must be non-empty string"
                assert isinstance(finding.confidence, float) and 0.0 <= finding.confidence <= 1.0, "Finding.confidence must be float [0.0, 1.0]"
                assert isinstance(finding.impact_score, float) and 0.0 <= finding.impact_score <= 1.0, "Finding.impact_score must be float [0.0, 1.0]"
                assert isinstance(finding.detected_by, str) and len(finding.detected_by) > 0, "Finding.detected_by must be non-empty string"
                
                # Optional fields validation
                if finding.line_number is not None:
                    assert isinstance(finding.line_number, int) and finding.line_number > 0, "Finding.line_number must be positive int or None"
                
                if finding.column is not None:
                    assert isinstance(finding.column, int) and finding.column >= 0, "Finding.column must be non-negative int or None"
                
                # Metadata must be dict
                assert isinstance(finding.metadata, dict), "Finding.metadata must be dict"
                
                # Scanner-specific validation
                if scanner_name == "CodeScanner":
                    assert finding.detected_by == "CodeScanner", "CodeScanner findings must have correct detected_by"
                    assert finding.type in [FindingType.SECURITY, FindingType.CODE_QUALITY, FindingType.TODO], \
                        f"CodeScanner produced unexpected type: {finding.type}"
                
                elif scanner_name == "Brass2PrivacyScanner":
                    assert finding.detected_by == "Brass2PrivacyScanner", "Brass2PrivacyScanner findings must have correct detected_by"
                    assert finding.type == FindingType.PRIVACY, f"Brass2PrivacyScanner must produce PRIVACY type, got: {finding.type}"
        
        print(f"✅ Scanner interface contract test passed!")
        for scanner_name, scanner in scanners:
            findings = scanner.scan()
            print(f"   - {scanner_name}: {len(findings)} findings, all valid")
    
    def test_ranker_preserves_finding_integrity(self, temp_project):
        """Test that IntelligenceRanker preserves Finding objects while adding ranking metadata."""
        
        # Create test file
        test_file = temp_project / "ranking_test.py"
        test_file.write_text('''
# Critical security issue
def critical_vuln():
    return eval("malicious_code")

# TODO: Low priority task
def todo_item():
    pass

# PII exposure
email = "sensitive@example.com"
''')
        
        # Get original findings
        code_scanner = CodeScanner(str(temp_project))
        privacy_scanner = Brass2PrivacyScanner(str(temp_project))
        
        original_findings = code_scanner.scan([test_file.name]) + privacy_scanner.scan([test_file.name])
        assert len(original_findings) > 0, "Need findings to test ranking"
        
        # Rank findings
        ranker = IntelligenceRanker()
        ranked_findings = ranker.rank_findings(original_findings)
        
        # Test boundary contract: Ranker preserves Finding integrity
        assert len(ranked_findings) == len(original_findings), "Ranker must preserve all findings"
        assert all(isinstance(f, Finding) for f in ranked_findings), "Ranker must preserve Finding type"
        
        # Test that all original findings are present in ranked results (order may change)
        original_ids = {f.id for f in original_findings}
        ranked_ids = {f.id for f in ranked_findings}
        assert original_ids == ranked_ids, "Ranker must preserve all original finding IDs"
        
        # Test that core finding data is unchanged for each finding
        for original in original_findings:
            # Find corresponding ranked finding
            ranked = next(f for f in ranked_findings if f.id == original.id)
            
            # Core finding data must be identical
            assert ranked.type == original.type, "Ranker must not modify Finding.type"
            assert ranked.severity == original.severity, "Ranker must not modify Finding.severity"
            assert ranked.file_path == original.file_path, "Ranker must not modify Finding.file_path"
            assert ranked.line_number == original.line_number, "Ranker must not modify Finding.line_number"
            assert ranked.title == original.title, "Ranker must not modify Finding.title"
            assert ranked.description == original.description, "Ranker must not modify Finding.description"
            assert ranked.confidence == original.confidence, "Ranker must not modify Finding.confidence"
            assert ranked.impact_score == original.impact_score, "Ranker must not modify Finding.impact_score"
            assert ranked.detected_by == original.detected_by, "Ranker must not modify Finding.detected_by"
        
        # Test that ranking metadata is properly added
        for finding in ranked_findings:
            assert 'ranking_score' in finding.metadata, "Ranker must add ranking_score to metadata"
            assert 'ranking_position' in finding.metadata, "Ranker must add ranking_position to metadata"
            assert 'ranking_percentile' in finding.metadata, "Ranker must add ranking_percentile to metadata"
            
            # Validate ranking metadata types
            assert isinstance(finding.metadata['ranking_score'], float), "ranking_score must be float"
            assert isinstance(finding.metadata['ranking_position'], int), "ranking_position must be int"
            assert isinstance(finding.metadata['ranking_percentile'], float), "ranking_percentile must be float"
            
            # Validate ranking metadata ranges
            assert finding.metadata['ranking_position'] >= 1, "ranking_position must be >= 1"
            assert finding.metadata['ranking_position'] <= len(ranked_findings), "ranking_position must be <= total findings"
            assert 0.0 <= finding.metadata['ranking_percentile'] <= 100.0, "ranking_percentile must be [0.0, 100.0]"
        
        # Test that rankings are properly ordered
        positions = [f.metadata['ranking_position'] for f in ranked_findings]
        assert positions == list(range(1, len(ranked_findings) + 1)), "Rankings must be consecutive integers starting from 1"
        
        scores = [f.metadata['ranking_score'] for f in ranked_findings]
        assert scores == sorted(scores, reverse=True), "Findings must be ordered by ranking_score (highest first)"
        
        print(f"✅ Ranker boundary integrity test passed!")
        print(f"   - Original findings: {len(original_findings)}")
        print(f"   - Ranked findings: {len(ranked_findings)}")
        print(f"   - Score range: {min(scores):.3f} - {max(scores):.3f}")
    
    def test_output_generator_consumes_ranked_findings(self, temp_project):
        """Test that OutputGenerator properly consumes ranked findings and produces expected outputs."""
        
        # Create test project with various issues
        self._create_output_test_project(temp_project)
        
        # Generate findings and rank them
        code_scanner = CodeScanner(str(temp_project))
        privacy_scanner = Brass2PrivacyScanner(str(temp_project))
        
        all_findings = code_scanner.scan() + privacy_scanner.scan()
        
        ranker = IntelligenceRanker()
        ranked_findings = ranker.rank_findings(all_findings)
        
        # Test OutputGenerator boundary contract
        generator = OutputGenerator(str(temp_project))
        generated_files = generator.generate_intelligence(ranked_findings)
        
        # Test return value contract
        assert isinstance(generated_files, dict), "OutputGenerator must return Dict[str, str]"
        assert len(generated_files) > 0, "OutputGenerator must generate at least one file"
        
        # Test expected file types are generated
        expected_file_types = ['ai_instructions', 'detailed_analysis', 'json_export', 'statistics']
        for expected_type in expected_file_types:
            assert expected_type in generated_files, f"OutputGenerator must generate {expected_type}"
            
            file_path = Path(generated_files[expected_type])
            assert file_path.exists(), f"Generated file must exist: {file_path}"
            assert file_path.stat().st_size > 0, f"Generated file must have content: {file_path}"
        
        # Test that generated content reflects the input findings
        ai_instructions_path = Path(generated_files['ai_instructions'])
        ai_content = ai_instructions_path.read_text()
        
        # Should contain information from ranked findings
        finding_types_in_content = []
        for finding in ranked_findings:
            # Check if finding type appears in content
            type_name = finding.type.value.replace('_', ' ').lower()
            if type_name in ai_content.lower():
                finding_types_in_content.append(finding.type)
        
        assert len(finding_types_in_content) > 0, "AI instructions should reference finding types from input"
        
        # Should contain severity information
        severity_in_content = []
        for finding in ranked_findings:
            if finding.severity.value.lower() in ai_content.lower():
                severity_in_content.append(finding.severity)
        
        assert len(severity_in_content) > 0, "AI instructions should reference severity levels from input"
        
        # Test JSON export contains structured finding data
        json_export_path = Path(generated_files['json_export'])
        import json
        json_data = json.loads(json_export_path.read_text())
        
        assert 'findings' in json_data, "JSON export must contain findings array"
        assert len(json_data['findings']) == len(ranked_findings), "JSON export must contain all findings"
        
        # Verify JSON findings preserve essential data
        for i, json_finding in enumerate(json_data['findings']):
            original_finding = ranked_findings[i]
            
            assert json_finding['id'] == original_finding.id, "JSON finding must preserve ID"
            assert json_finding['type'] == original_finding.type.value, "JSON finding must preserve type"
            assert json_finding['severity'] == original_finding.severity.value, "JSON finding must preserve severity"
            assert json_finding['file_path'] == original_finding.file_path, "JSON finding must preserve file_path"
            assert json_finding['title'] == original_finding.title, "JSON finding must preserve title"
        
        print(f"✅ OutputGenerator boundary contract test passed!")
        print(f"   - Input findings: {len(ranked_findings)}")
        print(f"   - Generated files: {list(generated_files.keys())}")
        print(f"   - AI instructions size: {len(ai_content)} chars")
        print(f"   - JSON findings: {len(json_data['findings'])}")
    
    def test_component_isolation_no_lateral_dependencies(self):
        """Test that components don't have lateral dependencies (clean architecture)."""
        
        # This test verifies architectural principle: components only depend downward
        
        # Test: Scanners should not import from ranker or output modules
        import ast
        from pathlib import Path
        
        scanner_files = [
            Path(__file__).parent.parent.parent / "src" / "brass" / "scanners" / "code_scanner.py",
            Path(__file__).parent.parent.parent / "src" / "brass" / "scanners" / "privacy_scanner.py"
        ]
        
        forbidden_imports = [
            'brass.ranking',
            'brass.output',
            '.ranking',
            '.output'
        ]
        
        for scanner_file in scanner_files:
            if scanner_file.exists():
                content = scanner_file.read_text()
                tree = ast.parse(content)
                
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            assert not any(forbidden in alias.name for forbidden in forbidden_imports), \
                                f"Scanner {scanner_file.name} has forbidden import: {alias.name}"
                    
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            assert not any(forbidden in node.module for forbidden in forbidden_imports), \
                                f"Scanner {scanner_file.name} has forbidden import: from {node.module}"
        
        # Test: Ranker should not import from output module
        ranker_file = Path(__file__).parent.parent.parent / "src" / "brass" / "ranking" / "intelligence_ranker.py"
        
        if ranker_file.exists():
            content = ranker_file.read_text()
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        assert 'brass.output' not in alias.name and '.output' not in alias.name, \
                            f"Ranker has forbidden import: {alias.name}"
                
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        assert 'brass.output' not in node.module and '.output' not in node.module, \
                            f"Ranker has forbidden import: from {node.module}"
        
        print(f"✅ Component isolation test passed!")
        print(f"   - Scanners have no lateral dependencies")
        print(f"   - Ranker has no output dependencies") 
        print(f"   - Clean architecture maintained")
    
    def test_data_flow_direction_enforcement(self, temp_project):
        """Test that data flows in one direction: Scanners → Ranker → OutputGenerator."""
        
        # Create test file
        test_file = temp_project / "dataflow_test.py"
        test_file.write_text('''
# Test file for data flow validation
def test_function():
    api_key = "sk-test123"  # Security issue
    email = "test@example.com"  # Privacy issue
    
    # Complex nested structure (code quality issue)
    if True:
        if True:
            if True:
                return eval("2+2")  # Another security issue
''')
        
        # Stage 1: Scanners produce findings
        code_scanner = CodeScanner(str(temp_project))
        privacy_scanner = Brass2PrivacyScanner(str(temp_project))
        
        stage1_findings = code_scanner.scan([test_file.name]) + privacy_scanner.scan([test_file.name])
        
        # Verify Stage 1 output format
        assert all(isinstance(f, Finding) for f in stage1_findings), "Stage 1 must produce Finding objects"
        assert all('ranking_score' not in f.metadata for f in stage1_findings), "Stage 1 findings must not have ranking data"
        
        # Stage 2: Ranker consumes findings and adds ranking data
        ranker = IntelligenceRanker()
        stage2_findings = ranker.rank_findings(stage1_findings)
        
        # Verify Stage 2 preserves input and adds ranking
        assert len(stage2_findings) == len(stage1_findings), "Stage 2 must preserve all findings"
        assert all('ranking_score' in f.metadata for f in stage2_findings), "Stage 2 must add ranking data"
        
        # Verify stage2 findings are properly ranked
        ranking_scores = [f.metadata['ranking_score'] for f in stage2_findings]
        assert ranking_scores == sorted(ranking_scores, reverse=True), "Stage 2 must sort by ranking score"
        
        # Stage 3: OutputGenerator consumes ranked findings and produces files
        generator = OutputGenerator(str(temp_project))
        stage3_output = generator.generate_intelligence(stage2_findings)
        
        # Verify Stage 3 output format
        assert isinstance(stage3_output, dict), "Stage 3 must produce file mapping"
        assert all(isinstance(k, str) for k in stage3_output.keys()), "Stage 3 keys must be strings"
        assert all(isinstance(v, str) for v in stage3_output.values()), "Stage 3 values must be file paths"
        
        # Verify data flow integrity: original finding data preserved through all stages
        original_ids = {f.id for f in stage1_findings}
        ranked_ids = {f.id for f in stage2_findings}
        
        assert original_ids == ranked_ids, "Finding IDs must be preserved through ranking"
        
        # Verify output files contain data from all stages
        ai_instructions_path = Path(stage3_output['ai_instructions'])
        ai_content = ai_instructions_path.read_text()
        
        # Should contain evidence of original findings
        finding_evidence = sum(1 for f in stage1_findings if f.title.lower() in ai_content.lower())
        assert finding_evidence > 0, "Stage 3 output must contain evidence of Stage 1 findings"
        
        print(f"✅ Data flow direction test passed!")
        print(f"   - Stage 1 (Scanners): {len(stage1_findings)} findings")
        print(f"   - Stage 2 (Ranker): {len(stage2_findings)} ranked findings")  
        print(f"   - Stage 3 (Output): {len(stage3_output)} generated files")
        print(f"   - Finding evidence in output: {finding_evidence} items")
    
    def _create_output_test_project(self, project_dir: Path):
        """Create test project for output generation testing."""
        
        # Security issues
        (project_dir / "security.py").write_text('''
def vulnerable_function(user_input):
    return eval(user_input)

API_KEY = "sk-1234567890abcdef"
''')
        
        # Code quality issues  
        (project_dir / "quality.py").write_text('''
# TODO: Refactor this function
def complex_function(a, b, c, d, e, f):
    if a:
        if b:
            if c:
                if d:
                    if e:
                        if f:
                            return True
    return False

def empty_except():
    try:
        risky_operation()
    except:
        pass
''')
        
        # Privacy issues
        (project_dir / "privacy.py").write_text('''
user_data = {
    "email": "john.doe@example.com",
    "ssn": "123-45-6789",
    "phone": "555-123-4567"
}
''')