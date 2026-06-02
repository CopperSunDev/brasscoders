"""
Integration tests for Brass2 Privacy Scanner - Regression Prevention
Ensures critical bugs don't reoccur following Brass2 principles.
"""

import pytest
import tempfile
import os
from pathlib import Path
from typing import List

from brass.scanners.brass2_privacy_scanner import Brass2PrivacyScanner
from brass.models.finding import Finding, FindingType, Severity


class TestBrass2PrivacyScannerIntegration:
    """Integration tests for Brass2 Privacy Scanner functionality."""
    
    def test_file_discovery_scope_regression(self):
        """
        REGRESSION TEST: Ensure scanner only processes intended project files.
        
        Prevents Bug #001: File discovery malfunction causing over-scanning.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test file
            test_file = Path(temp_dir) / "test_file.py"
            test_file.write_text('test_card = "4111111111111111"')
            
            scanner = Brass2PrivacyScanner(temp_dir)
            findings = scanner.scan()
            
            # Should find exactly 1 issue from 1 file
            assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}"
            assert findings[0].file_path == "test_file.py"
            
    def test_context_detection_integration(self):
        """
        REGRESSION TEST: Verify context detection works in full scan workflow.
        
        Prevents Bug #002: Context detection working individually but not in practice.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test patterns file
            test_file = Path(temp_dir) / "test_data.py"
            test_file.write_text('''
            test_card = "4111111111111111"  # Visa test
            test_email = "test@example.com"
            ''')
            
            # Create production patterns file
            prod_file = Path(temp_dir) / "production.py"
            prod_file.write_text('''
            user_card = "4532015112830366"
            user_email = "john@company.com"
            ''')
            
            scanner = Brass2PrivacyScanner(temp_dir)
            findings = scanner.scan()
            
            # Verify context detection
            test_findings = [f for f in findings if f.metadata.get('is_test_context')]
            prod_findings = [f for f in findings if not f.metadata.get('is_test_context')]
            
            assert len(test_findings) >= 1, "Should detect test context patterns"
            assert len(prod_findings) >= 1, "Should detect production context patterns"
            
            # Verify severity adjustment for test patterns
            for finding in test_findings:
                assert finding.severity in [Severity.LOW, Severity.MEDIUM], \
                    f"Test pattern should have reduced severity, got {finding.severity}"
    
    def test_sacred_interface_compliance(self):
        """
        BRASS2 COMPLIANCE: Verify scanner returns List[Finding] only.
        
        Ensures sacred Brass2 interface contract is maintained.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            test_file = Path(temp_dir) / "test.py"
            test_file.write_text('email = "test@example.com"')
            
            scanner = Brass2PrivacyScanner(temp_dir)
            findings = scanner.scan()
            
            # Sacred interface compliance
            assert isinstance(findings, list), "Must return List[Finding]"
            if findings:
                assert isinstance(findings[0], Finding), "Must contain Finding objects"
                assert findings[0].type == FindingType.PRIVACY, "Must be privacy findings"
                assert hasattr(findings[0], 'metadata'), "Must have metadata"
    
    def test_modular_detector_independence(self):
        """
        BRASS2 COMPLIANCE: Verify each detector works independently.
        
        Tests single responsibility principle in detector design.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            # Test file with patterns for each detector type
            test_file = Path(temp_dir) / "comprehensive.py"
            test_file.write_text('''
            credit_card = "4111111111111111"
            ssn = "123-45-6789"
            email = "user@example.com"
            phone = "555-123-4567"
            ip = "192.168.1.1"
            ''')
            
            scanner = Brass2PrivacyScanner(temp_dir)
            findings = scanner.scan()
            
            # Should detect all pattern types
            pattern_types = set(f.metadata.get('pattern_type', 'unknown') for f in findings)
            expected_types = {'visa_credit_card', 'us_ssn', 'email_address', 'phone_number', 'ip_address'}
            
            # Verify modular detection (at least most types should be found)
            found_types = pattern_types & expected_types
            assert len(found_types) >= 4, f"Should detect most pattern types, found: {found_types}"
    
    def test_performance_baseline(self):
        """
        PERFORMANCE REGRESSION: Ensure detection performance is maintained.
        
        Validates that fixes don't degrade detection capability.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create multiple files with known patterns
            test_files = {
                "file1.py": 'card = "4111111111111111"',
                "file2.py": 'email = "test@example.com"',
                "file3.py": 'ssn = "123-45-6789"',
                "file4.py": 'phone = "555-123-4567"',
                "file5.py": 'ip = "192.168.1.1"'
            }
            
            for filename, content in test_files.items():
                (Path(temp_dir) / filename).write_text(content)
            
            scanner = Brass2PrivacyScanner(temp_dir)
            findings = scanner.scan()
            
            # Should find at least 5 patterns (one per file)
            assert len(findings) >= 5, f"Should detect at least 5 patterns, found {len(findings)}"
            
            # Verify findings are distributed across files
            files_with_findings = set(f.file_path for f in findings)
            assert len(files_with_findings) >= 4, "Should find issues in multiple files"
    
    def test_error_isolation_brass2_principle(self):
        """
        BRASS2 COMPLIANCE: Verify error isolation prevents cascade failures.
        
        Tests that component failures don't crash the entire system.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create valid file
            valid_file = Path(temp_dir) / "valid.py"
            valid_file.write_text('card = "4111111111111111"')
            
            # Create problematic file (binary content that might cause read errors)
            problem_file = Path(temp_dir) / "problem.py"
            problem_file.write_bytes(b'\x00\x01\x02\x03invalid content')
            
            scanner = Brass2PrivacyScanner(temp_dir)
            findings = scanner.scan()
            
            # Should still process valid files despite errors with problematic ones
            assert len(findings) >= 1, "Should process valid files despite errors"
            valid_findings = [f for f in findings if f.file_path == "valid.py"]
            assert len(valid_findings) >= 1, "Should find patterns in valid file"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])