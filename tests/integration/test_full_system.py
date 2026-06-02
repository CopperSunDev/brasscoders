"""
Integration test for complete system workflow.
"""

import tempfile
import shutil
from pathlib import Path
from brass.scanners.professional_code_scanner import ProfessionalCodeScanner as CodeScanner
from brass.scanners.brass2_privacy_scanner import Brass2PrivacyScanner
from brass.scanners.content_moderation_scanner import ContentModerationScanner
from brass.ranking.intelligence_ranker import IntelligenceRanker
from brass.output.output_generator import OutputGenerator


class TestFullSystem:
    """Integration tests for complete system workflow."""
    
    def test_end_to_end_workflow(self):
        """Test complete workflow from scanning to intelligence generation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test project with various issues
            self._create_test_project(temp_dir)
            
            # Phase 1: Code scanning
            code_scanner = CodeScanner(temp_dir)
            code_findings = code_scanner.scan()
            
            # Phase 2: Privacy scanning
            privacy_scanner = Brass2Brass2PrivacyScanner(temp_dir)
            privacy_findings = privacy_scanner.scan()
            
            # Phase 2b: Content moderation scanning
            content_scanner = ContentModerationScanner(temp_dir)
            content_findings = content_scanner.scan()
            
            # Combine all findings
            all_findings = code_findings + privacy_findings + content_findings
            assert len(all_findings) > 0
            
            # Phase 3: Intelligence ranking
            ranker = IntelligenceRanker()
            ranked_findings = ranker.rank_findings(all_findings)
            
            # Verify ranking worked
            assert len(ranked_findings) == len(all_findings)
            assert all('ranking_score' in f.metadata for f in ranked_findings)
            
            # Verify highest ranked finding has highest score
            scores = [f.metadata['ranking_score'] for f in ranked_findings]
            assert scores == sorted(scores, reverse=True)
            
            # Phase 4: Output generation
            output_generator = OutputGenerator(temp_dir)
            generated_files = output_generator.generate_intelligence(ranked_findings)
            
            # Verify output files were created
            assert 'ai_instructions' in generated_files
            assert 'detailed_analysis' in generated_files
            assert 'json_export' in generated_files
            
            # Verify files actually exist and have content
            for file_type, file_path in generated_files.items():
                assert Path(file_path).exists()
                assert Path(file_path).stat().st_size > 0
            
            # Verify AI instructions contains expected sections
            ai_instructions_path = Path(generated_files['ai_instructions'])
            ai_content = ai_instructions_path.read_text()
            
            assert "Copper Sun Brass" in ai_content
            assert "Executive Summary" in ai_content
            assert "Critical Issues" in ai_content
            assert "AI Coding Guidance" in ai_content
            
            print(f"✅ End-to-end test passed!")
            print(f"   - Found {len(code_findings)} code issues")
            print(f"   - Found {len(privacy_findings)} privacy issues")
            print(f"   - Generated {len(generated_files)} intelligence files")
    
    def test_different_scanners_produce_different_findings(self):
        """Test that different scanners detect different types of issues."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create files with different types of issues
            (Path(temp_dir) / "complex.py").write_text('''
# TODO: Fix this complex function
def complex_function(a, b, c, d, e, f):
    if a > 0:
        if b > 0:
            for i in range(10):
                if i % 2 == 0:
                    while c > 0:
                        try:
                            if c > 5:
                                return True
                        except:
                            pass
            
def dangerous_eval(user_input):
    return eval(user_input)
''')
            
            (Path(temp_dir) / "privacy.py").write_text('''
# File with privacy issues
user_email = "john.doe@example.com"
ssn = "123-45-6789"
api_key = "abcd1234567890abcd1234567890abcd"
password = "secret123"
''')
            
            # Scan with both scanners
            code_scanner = CodeScanner(temp_dir)
            privacy_scanner = Brass2PrivacyScanner(temp_dir)
            
            code_findings = code_scanner.scan()
            privacy_findings = privacy_scanner.scan()
            
            # Verify we get different types of findings
            code_types = {f.type for f in code_findings}
            privacy_types = {f.type for f in privacy_findings}
            
            # Code scanner should find code quality, security, TODO issues
            assert any(t.value in ['code_quality', 'security', 'todo'] for t in code_types)
            
            # Privacy scanner should find privacy issues
            assert any(t.value == 'privacy' for t in privacy_types)
            
            # Verify specific findings
            todo_findings = [f for f in code_findings if 'TODO' in f.title]
            assert len(todo_findings) > 0
            
            eval_findings = [f for f in code_findings if 'eval' in f.title.lower()]
            assert len(eval_findings) > 0
            
            email_findings = [f for f in privacy_findings if 'email' in f.title.lower()]
            assert len(email_findings) > 0
            
            print(f"✅ Scanner differentiation test passed!")
            print(f"   - Code scanner found: {[t.value for t in code_types]}")
            print(f"   - Privacy scanner found: {[t.value for t in privacy_types]}")
    
    def test_intelligence_ranking_prioritizes_correctly(self):
        """Test that intelligence ranking prioritizes critical issues."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test file with various severity issues
            (Path(temp_dir) / "mixed_issues.py").write_text('''
# TODO: Minor improvement needed
def simple_function():
    pass

# Critical security issue
def security_problem(user_input):
    return eval(user_input)  # Very dangerous
    
# Privacy issue
ssn = "123-45-6789"  # Critical PII exposure
''')
            
            # Scan and rank
            code_scanner = CodeScanner(temp_dir)
            privacy_scanner = Brass2PrivacyScanner(temp_dir)
            
            all_findings = code_scanner.scan() + privacy_scanner.scan()
            
            ranker = IntelligenceRanker()
            ranked_findings = ranker.rank_findings(all_findings)
            
            # Critical/high severity findings should be ranked higher
            top_finding = ranked_findings[0]
            bottom_finding = ranked_findings[-1]
            
            # Top finding should have higher severity than bottom
            severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
            top_severity = severity_order[top_finding.severity.value]
            bottom_severity = severity_order[bottom_finding.severity.value]
            
            assert top_severity >= bottom_severity
            
            # Security and privacy findings should generally rank higher than TODOs
            security_privacy_rankings = []
            todo_rankings = []
            
            for i, finding in enumerate(ranked_findings):
                if finding.type.value in ['security', 'privacy']:
                    security_privacy_rankings.append(i)
                elif finding.type.value == 'todo':
                    todo_rankings.append(i)
            
            if security_privacy_rankings and todo_rankings:
                avg_security_rank = sum(security_privacy_rankings) / len(security_privacy_rankings)
                avg_todo_rank = sum(todo_rankings) / len(todo_rankings)
                assert avg_security_rank < avg_todo_rank  # Lower rank = higher priority
            
            print(f"✅ Intelligence ranking test passed!")
            print(f"   - Top finding: {top_finding.title} ({top_finding.severity.value})")
            print(f"   - Bottom finding: {bottom_finding.title} ({bottom_finding.severity.value})")
    
    def _create_test_project(self, temp_dir: str):
        """Create a test project with various types of issues."""
        project_dir = Path(temp_dir)
        
        # Main application file with complexity issues
        (project_dir / "app.py").write_text('''
# TODO: Refactor this application
import os

def complex_main_function(config, database, cache, logger, metrics, auth_service):
    """Main application function with too many parameters and complexity."""
    if config.debug:
        if database.connected:
            for user in database.get_users():
                if user.active:
                    while cache.size > 1000:
                        try:
                            if auth_service.validate(user):
                                for permission in user.permissions:
                                    if permission.level > 5:
                                        if metrics.enabled:
                                            return True
                                        elif metrics.disabled:
                                            return False
                                        else:
                                            continue
                        except:
                            pass  # FIXME: Empty exception handler
    return None

def dangerous_eval_function(user_input):
    """Security vulnerability - using eval."""
    return eval(user_input)
''')
        
        # Configuration file with privacy issues
        (project_dir / "config.py").write_text('''
# Configuration with exposed secrets
DATABASE_URL = "postgresql://user:password123@localhost/db"
API_KEY = "sk-1234567890abcdef1234567890abcdef"
ADMIN_EMAIL = "admin@company.com"
SUPPORT_PHONE = "555-123-4567"
''')
        
        # User data file with PII
        (project_dir / "users.py").write_text('''
# User data with PII exposure
test_users = [
    {
        "name": "John Doe",
        "email": "john.doe@example.com",
        "ssn": "123-45-6789",
        "phone": "(555) 123-4567"
    },
    {
        "name": "Jane Smith", 
        "email": "jane.smith@example.com",
        "credit_card": "4532-1234-5678-9012"
    }
]
''')
        
        # Utility file with code smells
        (project_dir / "utils.py").write_text('''
# HACK: Temporary utilities
class LargeUtilityClass:
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
    def method16(self): pass
    def method17(self): pass
    def method18(self): pass
    def method19(self): pass
    def method20(self): pass
    def method21(self): pass
    def method22(self): pass
''')