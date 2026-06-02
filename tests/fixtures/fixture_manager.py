"""
Fixture Manager for New BrassCoders System v2.0.

Provides unified access to all test fixtures and helps create comprehensive
test projects for consistent testing across all test suites.
"""

import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Union
from enum import Enum

from .security_test_files import SecurityTestFiles
from .privacy_test_files import PrivacyTestFiles
from .code_quality_test_files import CodeQualityTestFiles


class FixtureType(Enum):
    """Types of test fixtures available."""
    SECURITY = "security"
    PRIVACY = "privacy"
    CODE_QUALITY = "code_quality"
    MIXED = "mixed"
    ALL = "all"


class TestProjectTemplate(Enum):
    """Pre-defined test project templates."""
    MINIMAL = "minimal"              # Basic issues for quick testing
    COMPREHENSIVE = "comprehensive"  # All issue types for thorough testing
    SECURITY_FOCUSED = "security"    # Security vulnerabilities only
    PRIVACY_FOCUSED = "privacy"      # PII/privacy issues only
    QUALITY_FOCUSED = "quality"      # Code quality issues only
    INTEGRATION = "integration"      # Mixed issues for integration testing


class FixtureManager:
    """
    Unified manager for all test fixtures.
    
    Provides consistent access to test data across unit, integration,
    and end-to-end test suites.
    """
    
    def __init__(self):
        """Initialize the fixture manager."""
        self.security_files = SecurityTestFiles()
        self.privacy_files = PrivacyTestFiles()
        self.quality_files = CodeQualityTestFiles()
    
    def create_test_project(self, 
                          template: TestProjectTemplate, 
                          base_dir: Optional[Path] = None) -> Dict[str, Path]:
        """
        Create a test project based on the specified template.
        
        Args:
            template: Template type to create
            base_dir: Directory to create project in (creates temp dir if None)
            
        Returns:
            Dictionary mapping file names to file paths
        """
        if base_dir is None:
            # Create temporary directory
            temp_dir = tempfile.mkdtemp()
            base_dir = Path(temp_dir)
        else:
            base_dir = Path(base_dir)
            base_dir.mkdir(parents=True, exist_ok=True)
        
        created_files = {}
        
        if template == TestProjectTemplate.MINIMAL:
            created_files.update(self._create_minimal_project(base_dir))
        elif template == TestProjectTemplate.COMPREHENSIVE:
            created_files.update(self._create_comprehensive_project(base_dir))
        elif template == TestProjectTemplate.SECURITY_FOCUSED:
            created_files.update(self.security_files.create_security_test_project(base_dir))
        elif template == TestProjectTemplate.PRIVACY_FOCUSED:
            created_files.update(self.privacy_files.create_privacy_test_project(base_dir))
        elif template == TestProjectTemplate.QUALITY_FOCUSED:
            created_files.update(self.quality_files.create_code_quality_test_project(base_dir))
        elif template == TestProjectTemplate.INTEGRATION:
            created_files.update(self._create_integration_project(base_dir))
        else:
            raise ValueError(f"Unknown template: {template}")
        
        return created_files
    
    def get_expected_findings(self, 
                            fixture_type: FixtureType,
                            file_name: Optional[str] = None) -> Dict[str, List[str]]:
        """
        Get expected findings for fixtures.
        
        Args:
            fixture_type: Type of fixture findings to get
            file_name: Specific file name (returns all if None)
            
        Returns:
            Dictionary mapping file names to expected finding descriptions
        """
        if fixture_type == FixtureType.SECURITY:
            findings = self.security_files.get_expected_findings()
        elif fixture_type == FixtureType.PRIVACY:
            findings = self.privacy_files.get_expected_pii_findings()
        elif fixture_type == FixtureType.CODE_QUALITY:
            findings = self.quality_files.get_expected_quality_findings()
        else:
            # Combine all findings
            findings = {}
            findings.update(self.security_files.get_expected_findings())
            findings.update(self.privacy_files.get_expected_pii_findings())
            findings.update(self.quality_files.get_expected_quality_findings())
        
        if file_name:
            return {file_name: findings.get(file_name, [])}
        
        return findings
    
    def create_file_with_issues(self, 
                               file_path: Path,
                               issue_types: List[FixtureType]) -> Path:
        """
        Create a single file with multiple issue types.
        
        Args:
            file_path: Path where to create the file
            issue_types: Types of issues to include
            
        Returns:
            Path to the created file
        """
        content_parts = []
        
        # Add header
        content_parts.append('"""')
        content_parts.append('Mixed test file with multiple issue types.')
        content_parts.append(f'Generated by FixtureManager with types: {[t.value for t in issue_types]}')
        content_parts.append('"""')
        content_parts.append('')
        
        # Add security issues if requested
        if FixtureType.SECURITY in issue_types or FixtureType.ALL in issue_types:
            content_parts.append('# Security vulnerabilities')
            content_parts.append(self.security_files.get_hardcoded_secrets_file().split('\n', 10)[10])
            content_parts.append('')
            content_parts.append(self.security_files.get_eval_injection_file().split('\n', 5)[5])
            content_parts.append('')
        
        # Add privacy issues if requested
        if FixtureType.PRIVACY in issue_types or FixtureType.ALL in issue_types:
            content_parts.append('# Privacy/PII issues')
            content_parts.append(self.privacy_files.get_mixed_pii_file().split('\n', 10)[10])
            content_parts.append('')
        
        # Add code quality issues if requested
        if FixtureType.CODE_QUALITY in issue_types or FixtureType.ALL in issue_types:
            content_parts.append('# Code quality issues')
            content_parts.append(self.quality_files.get_todo_comments_file().split('\n', 5)[5])
            content_parts.append('')
            content_parts.append(self.quality_files.get_empty_exception_handlers_file().split('\n', 5)[5])
            content_parts.append('')
        
        # Write file
        file_path.write_text('\n'.join(content_parts))
        return file_path
    
    def get_fixture_statistics(self) -> Dict[str, Dict[str, int]]:
        """Get statistics about available fixtures."""
        stats = {
            'security': {
                'files': len(self.security_files.get_expected_findings()),
                'expected_findings': sum(len(findings) for findings in 
                                       self.security_files.get_expected_findings().values())
            },
            'privacy': {
                'files': len(self.privacy_files.get_expected_pii_findings()),
                'expected_findings': sum(len(findings) for findings in 
                                       self.privacy_files.get_expected_pii_findings().values())
            },
            'code_quality': {
                'files': len(self.quality_files.get_expected_quality_findings()),
                'expected_findings': sum(len(findings) for findings in 
                                       self.quality_files.get_expected_quality_findings().values())
            }
        }
        
        # Calculate totals
        stats['total'] = {
            'files': sum(s['files'] for s in stats.values()),
            'expected_findings': sum(s['expected_findings'] for s in stats.values())
        }
        
        return stats
    
    def _create_minimal_project(self, base_dir: Path) -> Dict[str, Path]:
        """Create minimal test project with basic issues."""
        files = {}
        
        # Simple security issue
        security_file = base_dir / "simple_security.py"
        security_file.write_text('''
# Simple security vulnerability
def dangerous_eval(user_input):
    return eval(user_input)

# Hardcoded secret
API_KEY = "sk-1234567890abcdef1234567890abcdef"
''')
        files['simple_security.py'] = security_file
        
        # Simple privacy issue
        privacy_file = base_dir / "simple_privacy.py"
        privacy_file.write_text('''
# Simple PII exposure
user_email = "john.doe@example.com"
user_ssn = "123-45-6789"
''')
        files['simple_privacy.py'] = privacy_file
        
        # Simple code quality issue
        quality_file = base_dir / "simple_quality.py"
        quality_file.write_text('''
# TODO: Implement this function
def incomplete_function():
    try:
        risky_operation()
    except:
        pass  # Empty exception handler
''')
        files['simple_quality.py'] = quality_file
        
        return files
    
    def _create_comprehensive_project(self, base_dir: Path) -> Dict[str, Path]:
        """Create comprehensive test project with all issue types."""
        files = {}
        
        # Add all security files
        files.update(self.security_files.create_security_test_project(base_dir))
        
        # Add all privacy files
        files.update(self.privacy_files.create_privacy_test_project(base_dir))
        
        # Add all code quality files
        files.update(self.quality_files.create_code_quality_test_project(base_dir))
        
        # Add mixed file
        mixed_file = base_dir / "comprehensive_mixed.py"
        files['comprehensive_mixed.py'] = self.create_file_with_issues(
            mixed_file, [FixtureType.ALL]
        )
        
        return files
    
    def _create_integration_project(self, base_dir: Path) -> Dict[str, Path]:
        """Create integration test project with representative samples."""
        files = {}
        
        # Representative security issues
        files['eval_injection.py'] = base_dir / "eval_injection.py"
        files['eval_injection.py'].write_text(self.security_files.get_eval_injection_file())
        
        files['hardcoded_secrets.py'] = base_dir / "hardcoded_secrets.py"
        files['hardcoded_secrets.py'].write_text(self.security_files.get_hardcoded_secrets_file())
        
        # Representative privacy issues
        files['email_pii.py'] = base_dir / "email_pii.py"
        files['email_pii.py'].write_text(self.privacy_files.get_email_pii_file())
        
        files['mixed_pii.py'] = base_dir / "mixed_pii.py" 
        files['mixed_pii.py'].write_text(self.privacy_files.get_mixed_pii_file())
        
        # Representative code quality issues
        files['todo_comments.py'] = base_dir / "todo_comments.py"
        files['todo_comments.py'].write_text(self.quality_files.get_todo_comments_file())
        
        files['complexity_issues.py'] = base_dir / "complexity_issues.py"
        files['complexity_issues.py'].write_text(self.quality_files.get_complexity_issues_file())
        
        # Integration-specific mixed file
        integration_file = base_dir / "integration_mixed.py"
        files['integration_mixed.py'] = self.create_file_with_issues(
            integration_file, [FixtureType.SECURITY, FixtureType.PRIVACY, FixtureType.CODE_QUALITY]
        )
        
        return files


# Convenience functions for common fixture operations
def create_temp_project(template: TestProjectTemplate = TestProjectTemplate.MINIMAL) -> Path:
    """Create a temporary test project and return its path."""
    manager = FixtureManager()
    files = manager.create_test_project(template)
    if files:
        # Return the parent directory of the first file
        return list(files.values())[0].parent
    else:
        # Fallback to creating empty temp directory
        return Path(tempfile.mkdtemp())


def get_all_expected_findings() -> Dict[str, List[str]]:
    """Get all expected findings across all fixture types."""
    manager = FixtureManager()
    return manager.get_expected_findings(FixtureType.ALL)


def get_fixture_stats() -> Dict[str, Dict[str, int]]:
    """Get statistics about all available fixtures."""
    manager = FixtureManager()
    return manager.get_fixture_statistics()