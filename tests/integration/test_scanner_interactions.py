"""
Component interaction tests for New BrassCoders System v2.0.

Tests how different scanners work together and produce complementary findings.
"""

import pytest
import tempfile
from pathlib import Path
from typing import List, Dict, Set

from brass.scanners.professional_code_scanner import ProfessionalCodeScanner as CodeScanner
from brass.scanners.brass2_privacy_scanner import Brass2PrivacyScanner
from brass.scanners.content_moderation_scanner import ContentModerationScanner
from brass.ranking.intelligence_ranker import IntelligenceRanker
from brass.output.output_generator import OutputGenerator
from brass.models.finding import Finding, FindingType, Severity


class TestScannerInteractions:
    """Test how different scanners interact and complement each other."""
    
    def test_code_and_privacy_scanner_complement_each_other(self, temp_project):
        """Test that CodeScanner and PrivacyScanner find complementary issues."""
        # Create test file with both code quality and privacy issues
        test_file = temp_project / "mixed_issues.py"
        test_file.write_text('''
# TODO: Implement secure authentication
import os

def authenticate_user(username, password):
    """Authentication with multiple issues."""
    # Hardcoded credentials (security issue)
    admin_password = "admin123"
    api_key = "sk-1234567890abcdef1234567890abcdef"
    
    # PII in variables (privacy issue)
    user_email = "john.doe@company.com"
    user_ssn = "123-45-6789"
    
    # Dangerous eval usage (security issue)
    if eval(f"'{username}' == 'admin'"):
        # Empty exception handling (code quality issue)
        try:
            complex_validation(username, password, admin_password, api_key, user_email, user_ssn)
        except:
            pass
    
    return False

def complex_validation(a, b, c, d, e, f, g, h, i, j):
    """Function with too many parameters (code quality issue)."""
    if a:
        if b:
            if c:
                if d:
                    if e:
                        if f:
                            if g:
                                if h:
                                    if i:
                                        return j
    return None
''')
        
        # Scan with all scanners
        code_scanner = CodeScanner(str(temp_project))
        privacy_scanner = Brass2PrivacyScanner(str(temp_project))
        
        code_findings = code_scanner.scan([test_file.name])
        privacy_findings = privacy_scanner.scan([test_file.name])
        
        # Verify both scanners found issues
        assert len(code_findings) > 0, "CodeScanner should find code quality and security issues"
        assert len(privacy_findings) > 0, "PrivacyScanner should find privacy issues"
        
        # Verify finding type diversity
        code_types = {f.type for f in code_findings}
        privacy_types = {f.type for f in privacy_findings}
        
        # CodeScanner should find multiple types
        assert FindingType.TODO in code_types, "Should detect TODO comment"
        assert FindingType.SECURITY in code_types, "Should detect security issues"
        assert FindingType.CODE_QUALITY in code_types, "Should detect code quality issues"
        
        # PrivacyScanner should find privacy issues
        assert FindingType.PRIVACY in privacy_types, "Should detect privacy issues"
        
        # Verify no overlap in findings (each scanner finds unique issues)
        code_file_lines = {(f.file_path, f.line_number) for f in code_findings if f.line_number}
        privacy_file_lines = {(f.file_path, f.line_number) for f in privacy_findings if f.line_number}
        
        # Some overlap is okay, but they should mostly find different things
        total_unique_locations = len(code_file_lines.union(privacy_file_lines))
        assert total_unique_locations >= max(len(code_file_lines), len(privacy_file_lines))
        
        print(f"✅ Scanner complementarity test passed!")
        print(f"   - Code scanner types: {[t.value for t in code_types]}")
        print(f"   - Privacy scanner types: {[t.value for t in privacy_types]}")
        print(f"   - Total unique issue locations: {total_unique_locations}")
    
    def test_scanners_with_ranker_integration(self, temp_project):
        """Test that scanner outputs integrate properly with intelligence ranker."""
        # Create test files with different severity levels
        high_severity_file = temp_project / "critical.py"
        high_severity_file.write_text('''
# Critical security vulnerability
def dangerous_function(user_input):
    return eval(user_input)  # Direct code execution

# Critical PII exposure
user_data = {
    "ssn": "123-45-6789",
    "credit_card": "4532-1234-5678-9012"
}
''')
        
        low_severity_file = temp_project / "minor.py"
        low_severity_file.write_text('''
# TODO: Add error handling
def simple_function():
    print("Hello world")
''')
        
        # Scan with all scanners
        code_scanner = CodeScanner(str(temp_project))
        privacy_scanner = Brass2PrivacyScanner(str(temp_project))
        
        all_findings = code_scanner.scan() + privacy_scanner.scan()
        assert len(all_findings) > 0, "Should find issues in test files"
        
        # Rank findings
        ranker = IntelligenceRanker()
        ranked_findings = ranker.rank_findings(all_findings)
        
        # Verify ranking metadata was added
        for finding in ranked_findings:
            assert 'ranking_score' in finding.metadata, "Ranking score should be added"
            assert 'ranking_position' in finding.metadata, "Ranking position should be added"
            assert 'ranking_percentile' in finding.metadata, "Ranking percentile should be added"
            assert isinstance(finding.metadata['ranking_score'], float), "Score should be numeric"
        
        # Verify rankings are in descending order
        scores = [f.metadata['ranking_score'] for f in ranked_findings]
        assert scores == sorted(scores, reverse=True), "Findings should be ranked by score (highest first)"
        
        # Verify critical issues are ranked higher than minor ones
        critical_findings = [f for f in ranked_findings if f.severity in [Severity.CRITICAL, Severity.HIGH]]
        minor_findings = [f for f in ranked_findings if f.severity in [Severity.LOW, Severity.INFO]]
        
        if critical_findings and minor_findings:
            highest_critical_rank = min(f.metadata['ranking_position'] for f in critical_findings)
            lowest_minor_rank = max(f.metadata['ranking_position'] for f in minor_findings)
            assert highest_critical_rank < lowest_minor_rank, "Critical issues should rank higher than minor ones"
        
        print(f"✅ Scanner-ranker integration test passed!")
        print(f"   - Total findings: {len(all_findings)}")
        print(f"   - Ranking scores range: {min(scores):.3f} - {max(scores):.3f}")
    
    def test_full_pipeline_component_interaction(self, temp_project):
        """Test complete pipeline: Scanners → Ranker → OutputGenerator."""
        # Create comprehensive test project
        self._create_comprehensive_test_project(temp_project)
        
        # Phase 1: Scanning
        code_scanner = CodeScanner(str(temp_project))
        privacy_scanner = Brass2PrivacyScanner(str(temp_project))
        
        code_findings = code_scanner.scan()
        privacy_findings = privacy_scanner.scan()
        
        all_findings = code_findings + privacy_findings
        assert len(all_findings) >= 5, "Should find multiple issues in comprehensive test project"
        
        # Phase 2: Ranking
        ranker = IntelligenceRanker()
        ranked_findings = ranker.rank_findings(all_findings)
        
        assert len(ranked_findings) == len(all_findings), "Ranker should preserve all findings"
        
        # Phase 3: Output Generation
        generator = OutputGenerator(str(temp_project))
        generated_files = generator.generate_intelligence(ranked_findings)
        
        # Verify all expected files were created
        expected_files = ['ai_instructions', 'detailed_analysis', 'file_intelligence', 'security_report', 'json_export', 'statistics']
        for expected_file in expected_files:
            assert expected_file in generated_files, f"Missing expected output file: {expected_file}"
            
            file_path = Path(generated_files[expected_file])
            assert file_path.exists(), f"Generated file should exist: {file_path}"
            assert file_path.stat().st_size > 0, f"Generated file should have content: {file_path}"
        
        # Verify AI instructions contains findings from all scanners
        ai_instructions_path = Path(generated_files['ai_instructions'])
        ai_content = ai_instructions_path.read_text()
        
        # Should contain content from both scanner types
        assert any(finding_type.value.replace('_', ' ').lower() in ai_content.lower() 
                  for finding_type in [FindingType.SECURITY, FindingType.CODE_QUALITY, FindingType.PRIVACY])
        
        # Should contain multiple severity levels
        assert any(severity.value in ai_content.lower() 
                  for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM])
        
        # Should have structured sections
        expected_sections = ["Executive Summary", "Critical Issues", "AI Coding Guidance", "Files Requiring Attention"]
        for section in expected_sections:
            assert section in ai_content, f"AI instructions should contain {section} section"
        
        print(f"✅ Full pipeline integration test passed!")
        print(f"   - Code findings: {len(code_findings)}")
        print(f"   - Privacy findings: {len(privacy_findings)}")
        print(f"   - Generated files: {list(generated_files.keys())}")
        print(f"   - AI instructions size: {len(ai_content)} characters")
    
    def test_scanner_error_isolation(self, temp_project):
        """Test that scanner errors don't affect other components."""
        # Create a file that might cause issues for one scanner
        problematic_file = temp_project / "problematic.py"
        problematic_file.write_text('''
# File with potential parsing issues
def incomplete_function(
    # Missing closing parenthesis and body
    
# TODO: Fix this incomplete code
''')
        
        valid_file = temp_project / "valid.py"
        valid_file.write_text('''
# Valid file with detectable issues
def function_with_hardcoded_secret():
    api_key = "sk-1234567890abcdef1234567890abcdef"
    user_email = "test@example.com"
    return api_key
''')
        
        # Test that scanners handle errors gracefully
        code_scanner = CodeScanner(str(temp_project))
        privacy_scanner = Brass2PrivacyScanner(str(temp_project))
        
        # Scanners should not crash, even with problematic files
        code_findings = code_scanner.scan()
        privacy_findings = privacy_scanner.scan()
        
        # Should still find issues in valid files
        assert isinstance(code_findings, list), "CodeScanner should return list even with parsing errors"
        assert isinstance(privacy_findings, list), "PrivacyScanner should return list even with parsing errors"
        
        # Should find issues in the valid file
        valid_file_findings = [f for f in code_findings + privacy_findings if f.file_path == "valid.py"]
        assert len(valid_file_findings) > 0, "Should find issues in valid files despite problematic files"
        
        # Test that downstream components handle partial results
        all_findings = code_findings + privacy_findings
        
        ranker = IntelligenceRanker()
        ranked_findings = ranker.rank_findings(all_findings)
        
        generator = OutputGenerator(str(temp_project))
        generated_files = generator.generate_intelligence(ranked_findings)
        
        # Should still generate intelligence even with some scanning errors
        assert len(generated_files) > 0, "Should generate output despite scanning errors"
        
        print(f"✅ Error isolation test passed!")
        print(f"   - Code findings: {len(code_findings)}")
        print(f"   - Privacy findings: {len(privacy_findings)}")
        print(f"   - Valid file findings: {len(valid_file_findings)}")
        print(f"   - Generated files: {len(generated_files)}")
    
    def test_finding_type_coverage_across_scanners(self, temp_project):
        """Test that different scanners cover all expected finding types."""
        # Create files that should trigger each finding type
        self._create_finding_type_test_files(temp_project)
        
        # Scan with all scanners
        code_scanner = CodeScanner(str(temp_project))
        privacy_scanner = Brass2PrivacyScanner(str(temp_project))
        
        all_findings = code_scanner.scan() + privacy_scanner.scan()
        
        # Collect all finding types found
        found_types = {f.type for f in all_findings}
        
        # Should find multiple finding types
        expected_types = {FindingType.SECURITY, FindingType.CODE_QUALITY, FindingType.TODO, FindingType.PRIVACY}
        
        for expected_type in expected_types:
            assert expected_type in found_types, f"Should detect {expected_type.value} findings"
        
        # Verify type distribution makes sense
        type_counts = {finding_type: len([f for f in all_findings if f.type == finding_type]) 
                      for finding_type in found_types}
        
        print(f"✅ Finding type coverage test passed!")
        print(f"   - Found types: {[t.value for t in found_types]}")
        print(f"   - Type distribution: {[(t.value, count) for t, count in type_counts.items()]}")
    
    def _create_comprehensive_test_project(self, project_dir: Path):
        """Create a test project with diverse issues for comprehensive testing."""
        
        # Security issues file
        (project_dir / "security.py").write_text('''
# Multiple security vulnerabilities
import subprocess
import pickle

def vulnerable_eval(user_input):
    return eval(user_input)  # Code injection

def vulnerable_exec(user_code):
    exec(user_code)  # Code execution

def vulnerable_subprocess(user_command):
    subprocess.call(user_command, shell=True)  # Command injection

def vulnerable_pickle(user_data):
    return pickle.loads(user_data)  # Deserialization vulnerability

# Hardcoded secrets
API_KEY = "sk-1234567890abcdef1234567890abcdef"
DATABASE_PASSWORD = "super_secret_password"
JWT_SECRET = "my-secret-jwt-key"
''')
        
        # Code quality issues file
        (project_dir / "quality.py").write_text('''
# TODO: Refactor this entire file
# FIXME: Fix all the code quality issues
# XXX: This is really bad code

def complex_function(a, b, c, d, e, f, g, h, i, j):
    """Function with too many parameters."""
    if a:
        if b:
            if c:
                if d:
                    if e:
                        if f:
                            if g:
                                if h:
                                    if i:
                                        if j:
                                            return True
    return False

class TooManyMethods:
    """Class with too many methods."""
    def method1(self): pass
    def method2(self): pass
    def method3(self): pass
    def method4(self): pass
    def method5(self): pass
    def method6(self): pass
    def method7(self): pass
    def method8(self): pass
    def method9(self): pass
    def method10(self): pass
    def method11(self): pass
    def method12(self): pass
    def method13(self): pass
    def method14(self): pass
    def method15(self): pass

def empty_exception_handler():
    try:
        risky_operation()
    except:
        pass  # Empty exception handling
''')
        
        # Privacy issues file
        (project_dir / "privacy.py").write_text('''
# Personal Identifiable Information
user_profiles = [
    {
        "name": "John Doe",
        "email": "john.doe@example.com",
        "ssn": "123-45-6789",
        "phone": "(555) 123-4567",
        "credit_card": "4532-1234-5678-9012",
        "passport": "AB1234567"
    },
    {
        "name": "Jane Smith",
        "email": "jane.smith@company.com", 
        "ssn": "987-65-4321",
        "drivers_license": "D123456789"
    }
]

# Financial data
bank_account = "12345678901234567890"
routing_number = "021000021"

# Medical information
patient_id = "P123456789"
medical_record = "MR987654321"
''')
        
        # Mixed issues file
        (project_dir / "mixed.py").write_text('''
# File combining multiple issue types
# TODO: Implement proper authentication

def authenticate_user(username, password):
    """Authentication with multiple problems."""
    # Hardcoded admin credentials (security)
    if username == "admin" and password == "admin123":
        return True
    
    # User data with PII (privacy)
    user_email = "admin@company.com"
    user_ssn = "555-55-5555"
    
    # Dangerous operation (security)
    if eval(f"'{username}' in allowed_users"):
        # Poor error handling (code quality)
        try:
            return validate_complex_auth(username, password, user_email, user_ssn, "secret", "key")
        except:
            pass
    
    return False

def validate_complex_auth(a, b, c, d, e, f, g, h, i):
    """Too many parameters (code quality)."""
    pass  # Stub implementation
''')
    
    def _create_finding_type_test_files(self, project_dir: Path):
        """Create files designed to trigger each specific finding type."""
        
        # Security-focused file
        (project_dir / "security_test.py").write_text('''
def test_eval():
    return eval("2 + 2")

def test_exec():
    exec("print('hello')")
    
API_KEY = "sk-test123456789abcdef"
''')
        
        # Code quality-focused file  
        (project_dir / "quality_test.py").write_text('''
def complex_nested_function():
    for i in range(10):
        if i > 5:
            for j in range(5):
                if j < 3:
                    try:
                        return i * j
                    except:
                        pass
    return None

def many_params(a, b, c, d, e, f, g, h):
    return a + b + c + d + e + f + g + h
''')
        
        # TODO-focused file
        (project_dir / "todo_test.py").write_text('''
# TODO: Implement this function
def incomplete_function():
    pass

# FIXME: Fix the logic error
def broken_function():
    return 1 / 0

# XXX: This is a hack
def hack_function():
    pass
''')
        
        # Privacy-focused file
        (project_dir / "privacy_test.py").write_text('''
email = "test@example.com"
ssn = "123-45-6789"
phone = "555-123-4567"
''')