"""
Integration test for basic CodeScanner workflow.
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from brass.scanners.professional_code_scanner import ProfessionalCodeScanner as CodeScanner
from brass.models.finding import FindingType, Severity


class TestBasicWorkflow:
    """Integration tests for basic scanning workflow."""
    
    def test_end_to_end_scanning(self):
        """Test complete scanning workflow."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Copy test fixture to temp directory
            fixtures_dir = Path(__file__).parent.parent / "fixtures"
            test_file = fixtures_dir / "test_project.py"
            
            if test_file.exists():
                shutil.copy(test_file, Path(temp_dir) / "test_project.py")
            else:
                # Create minimal test file if fixture doesn't exist
                (Path(temp_dir) / "test_project.py").write_text('''
# TODO: Implement this
def complex_function(a, b, c, d, e, f):
    if a > 0:
        if b > 0:
            for i in range(10):
                if i % 2 == 0:
                    while c > 0:
                        try:
                            if c > 5:
                                return True
                            elif c > 3:
                                return False
                            else:
                                c -= 1
                        except:
                            pass
                        
def dangerous_function(user_input):
    return eval(user_input)
''')
            
            # Run scanner
            scanner = CodeScanner(temp_dir)
            findings = scanner.scan()
            
            # Validate results
            assert len(findings) > 0
            
            # Check we have different types of findings
            finding_types = {f.type for f in findings}
            assert FindingType.CODE_QUALITY in finding_types
            
            # Verify finding structure
            for finding in findings:
                assert finding.id
                assert finding.file_path
                assert finding.detected_by == "CodeScanner"
                assert 0.0 <= finding.confidence <= 1.0
                assert 0.0 <= finding.impact_score <= 1.0
    
    def test_specific_file_scanning(self):
        """Test scanning specific files only."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create multiple test files
            (Path(temp_dir) / "file1.py").write_text("# TODO: Fix this\nprint('hello')")
            (Path(temp_dir) / "file2.py").write_text("print('world')")
            
            scanner = CodeScanner(temp_dir)
            
            # Scan only file1.py
            findings = scanner.scan(["file1.py"])
            
            # Should only have findings from file1.py
            assert len(findings) > 0
            for finding in findings:
                assert finding.file_path == "file1.py"
    
    def test_empty_project_scanning(self):
        """Test scanning empty project."""
        with tempfile.TemporaryDirectory() as temp_dir:
            scanner = CodeScanner(temp_dir)
            findings = scanner.scan()
            
            # Empty project should have no findings
            assert len(findings) == 0
    
    def test_finding_serialization_roundtrip(self):
        """Test that findings can be serialized and deserialized."""
        with tempfile.TemporaryDirectory() as temp_dir:
            (Path(temp_dir) / "test.py").write_text("# TODO: Test serialization")
            
            scanner = CodeScanner(temp_dir)
            original_findings = scanner.scan()
            
            assert len(original_findings) > 0
            
            # Serialize and deserialize each finding
            for original in original_findings:
                data = original.to_dict()
                restored = original.__class__.from_dict(data)
                
                assert restored.id == original.id
                assert restored.type == original.type
                assert restored.severity == original.severity
                assert restored.file_path == original.file_path
                assert restored.confidence == original.confidence