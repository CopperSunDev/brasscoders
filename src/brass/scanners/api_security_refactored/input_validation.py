"""
Input Validation Analyzer for API Security Scanner.

Analyzes AI-generated input validation patterns for security vulnerabilities:
- SQL injection risks (f-strings, format() usage)
- Cross-site scripting (XSS) vulnerabilities
- Command injection patterns
"""

import re
from pathlib import Path
from typing import List, Dict

from ...models.finding import Severity
from ...core.logging_config import get_logger  
from .utils import ConfigLoader, FindingFactory, SeverityMapper

logger = get_logger(__name__)


class ValidationPatternMatcher:
    """Pattern matching engine for input validation vulnerabilities."""
    
    # Input validation security patterns
    VALIDATION_PATTERNS = {
        'sql_injection_risk': {
            'patterns': [
                r'execute\([^)]*%s',
                r'query\([^)]*\+.*user_input',
                r'f".*{.*user.*}".*execute',
                r'cursor\.execute.*format\(',
                r'\.execute\(.*\.format\(',
                r'f".*SELECT.*FROM.*{.*}"',  # f-string SQL injection
                r'query\s*=\s*f".*{.*}"'     # f-string queries
            ],
            'description': "Potential SQL injection vulnerability detected. User input appears to be directly used in SQL queries without proper sanitization.",
            'remediation': "Use parameterized queries or prepared statements. Consider using an ORM like SQLAlchemy with proper parameter binding.",
            'references': [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
            ]
        },
        'xss_risk': {
            'patterns': [
                r'render_template.*\|safe',
                r'innerHTML.*user_input',
                r'dangerouslySetInnerHTML',
                r'document\.write\(.*user',
                r'render_template_string.*f".*{.*}"',  # f-string template injection
                r'template\s*=\s*f".*{.*}"'           # f-string templates
            ],
            'description': "Potential cross-site scripting (XSS) vulnerability detected. User input may be rendered without proper escaping.",
            'remediation': "Properly escape user input before rendering. Use template engines with auto-escaping enabled by default.",
            'references': [
                "https://owasp.org/www-community/attacks/xss/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
            ]
        },
        'command_injection': {
            'patterns': [
                r'subprocess.*shell=True.*user_input',
                r'os\.system.*user_input',
                r'eval\(.*user_input',
                r'exec\(.*user_input'
            ],
            'description': "Potential command injection vulnerability detected. User input appears to be used in system commands without sanitization.",
            'remediation': "Avoid using user input in system commands. If necessary, use strict input validation and sanitization.",
            'references': [
                "https://owasp.org/www-community/attacks/Command_Injection",
                "https://cwe.mitre.org/data/definitions/78.html"
            ]
        }
    }
    
    @classmethod
    def find_validation_issues(cls, content: str, file_path: str) -> List[Dict]:
        """Find input validation vulnerabilities in file content."""
        issues = []
        lines = content.split('\n')
        
        for pattern_type, config in cls.VALIDATION_PATTERNS.items():
            for i, line in enumerate(lines, 1):
                for pattern in config['patterns']:
                    if re.search(pattern, line, re.IGNORECASE):
                        issues.append({
                            'vulnerability_type': pattern_type,
                            'line_number': i,
                            'line_content': line.strip(),
                            'matched_pattern': pattern,
                            'config': config
                        })
        
        return issues


class ValidationFindingCreator:
    """Creates Finding objects for input validation vulnerabilities."""
    
    @staticmethod
    def create_validation_finding(issue: Dict, file_path: str):
        """Create Finding object for input validation vulnerability."""
        vuln_type = issue['vulnerability_type']
        config = issue['config']
        
        title = f"Input Validation Vulnerability: {vuln_type.replace('_', ' ').title()}"
        
        # Use hardcoded severity to match original behavior  
        severity_map = {
            'sql_injection_risk': Severity.CRITICAL,
            'xss_risk': Severity.HIGH,
            'command_injection': Severity.CRITICAL
        }
        severity = severity_map.get(vuln_type, Severity.MEDIUM)
        impact_score = SeverityMapper.get_impact_score(severity)
        
        # Confidence levels for different vulnerability types
        confidence_map = {
            'sql_injection_risk': 0.85,
            'xss_risk': 0.8,
            'command_injection': 0.9
        }
        confidence = confidence_map.get(vuln_type, 0.8)
        
        metadata = {
            'vulnerability_type': vuln_type,
            'matched_pattern': issue['matched_pattern'],
            'ai_generated_risk': True
        }
        
        return FindingFactory.create_security_finding(
            finding_id=f"input_validation_{vuln_type}_{issue['line_number']}_{hash(issue['line_content'])}",
            severity=severity,
            file_path=file_path,
            line_number=issue['line_number'],
            title=title,
            description=config['description'],
            detected_by="input_validation_analyzer",
            confidence=confidence,
            impact_score=impact_score,
            code_snippet=issue['line_content'],
            remediation=config['remediation'],
            references=config['references'],
            metadata=metadata
        )


class FileTypeFilter:
    """Filters files for input validation analysis."""
    
    SUPPORTED_EXTENSIONS = {'.py', '.js', '.ts'}
    
    @classmethod
    def should_analyze_file(cls, file_path: str) -> bool:
        """Check if file should be analyzed for input validation."""
        return Path(file_path).suffix in cls.SUPPORTED_EXTENSIONS


class SafeFileReader:
    """Safe file content reader with encoding handling."""
    
    @staticmethod
    def read_content(file_path: str) -> str:
        """Read file content with proper error handling."""
        encodings = ['utf-8', 'latin-1', 'cp1252']
        
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    return f.read()
            except UnicodeDecodeError:
                continue
        
        # If all encodings fail, raise the last exception
        raise UnicodeDecodeError(f"Could not decode file {file_path} with any supported encoding")


class APIInputValidationAnalyzer:
    """Main analyzer for AI-generated input validation patterns."""
    
    def __init__(self, project_path: str):
        """Initialize analyzer with project path."""
        self.project_path = Path(project_path)
        self.pattern_matcher = ValidationPatternMatcher()
        self.finding_creator = ValidationFindingCreator()
        self.file_filter = FileTypeFilter()
        self.file_reader = SafeFileReader()
    
    def analyze_file(self, file_path: str) -> List:
        """Analyze single file for input validation issues."""
        findings = []
        
        if not self.file_filter.should_analyze_file(file_path):
            return findings
        
        try:
            content = self.file_reader.read_content(file_path)
            issues = self.pattern_matcher.find_validation_issues(content, file_path)
            
            for issue in issues:
                if self._is_check_enabled(issue['vulnerability_type']):
                    finding = self.finding_creator.create_validation_finding(issue, file_path)
                    findings.append(finding)
        
        except Exception as e:
            # Create finding for analysis error
            error_finding = FindingFactory.create_analysis_error(
                finding_id=f"input_validation_error_{hash(file_path)}",
                file_path=file_path,
                title="Input Validation Analysis Error",
                description=f"Failed to analyze input validation patterns: {str(e)}",
                detected_by="input_validation_analyzer"
            )
            findings.append(error_finding)
        
        return findings
    
    def _is_check_enabled(self, vulnerability_type: str) -> bool:
        """Check if specific vulnerability type checking is enabled."""
        config = ConfigLoader.get_config()
        validation_config = config.get('api_security', {}).get('input_validation', {})
        
        check_map = {
            'sql_injection_risk': 'check_sql_injection',
            'xss_risk': 'check_xss_risks',
            'command_injection': 'check_command_injection'
        }
        
        check_key = check_map.get(vulnerability_type)
        if check_key:
            return validation_config.get(check_key, True)
        
        return True  # Default to enabled if not configured
    
    def get_supported_extensions(self) -> set:
        """Get supported file extensions for analysis."""
        return self.file_filter.SUPPORTED_EXTENSIONS