"""
Authentication Anti-Pattern Analyzer for API Security Scanner.

Detects authentication security issues commonly introduced by AI code generation:
- Hardcoded secrets and API keys
- Weak JWT implementations  
- Missing rate limiting on API endpoints
"""

import re
from pathlib import Path
from typing import List, Dict

from ...models.finding import Severity
from ...core.logging_config import get_logger
from .utils import ConfigLoader, FindingFactory, SeverityMapper

logger = get_logger(__name__)


class AuthPatternMatcher:
    """Pattern matching engine for authentication anti-patterns."""
    
    # Authentication security patterns with metadata
    AUTH_PATTERNS = {
        'hardcoded_secrets': {
            'patterns': [
                r'password\s*=\s*["\'][^"\']+["\']',
                r'api_key\s*=\s*["\'][^"\']+["\']',
                r'secret\s*=\s*["\'][^"\']+["\']',
                r'token\s*=\s*["\'][^"\']+["\']',
                r'jwt_secret\s*=\s*["\'][^"\']+["\']'
            ],
            'description': "Hardcoded secret or API key detected in source code. This is a critical security vulnerability that exposes sensitive credentials.",
            'remediation': "Move secrets to environment variables or secure configuration. Use tools like python-decouple or similar.",
            'references': [
                "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials",
                "https://cwe.mitre.org/data/definitions/798.html"
            ]
        },
        'weak_jwt': {
            'patterns': [
                r'jwt\.encode\([^,]+,\s*["\']secret["\']',
                r'HS256.*["\']secret["\']',
                r'jwt.*algorithm.*none',  # Algorithm: none vulnerability
                r'jwt\.encode.*key=None'
            ],
            'description': "Weak JWT implementation detected. Using weak secrets or 'none' algorithm can compromise authentication security.",
            'remediation': "Use strong, randomly generated secrets. Avoid 'none' algorithm. Consider using RS256 with proper key management.",
            'references': [
                "https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/",
                "https://tools.ietf.org/html/rfc7519"
            ]
        },
        'missing_rate_limiting': {
            'patterns': [
                r'@app\.route.*POST.*(?!.*rate_limit)',
                r'app\.post.*(?!.*rate_limit)',
                r'@api\.route.*(?!.*rate_limit)',
                r'@flask\.route.*(?!.*rate_limit)'
            ],
            'description': "API endpoint without rate limiting detected. This can lead to abuse, DoS attacks, and resource exhaustion.",
            'remediation': "Implement rate limiting using flask-limiter or similar. Set appropriate limits for your API endpoints.",
            'references': [
                "https://owasp.org/www-project-api-security/",
                "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html"
            ]
        }
    }
    
    # Lines whose first non-whitespace character is one of these are
    # treated as a comment and skipped — they shouldn't fire auth
    # patterns. Discovered 2026-05-21 on whisperx: a Python comment
    # ``# FIX: pyannote-audio 4.0 uses 'token=' not 'use_token='``
    # was matched by the hardcoded_secrets pattern and surfaced as a
    # CRITICAL credential finding. Comments rotting into noise breaks
    # customer trust in the engine's signal/noise ratio.
    #
    # Coverage: Python/Ruby/shell ``#``, JS/TS/Java/Go/Rust/PHP ``//``,
    # and the leading-``*`` line of a C-style block comment. We don't
    # try to track block-comment STATE across lines (``/* ... */``
    # spanning N lines); a fragment of credential text inside such
    # a block remains a possible false positive but is rare and a
    # bigger feature than this fix targets.
    _COMMENT_PREFIXES = ('#', '//')

    @staticmethod
    def _is_comment_line(line: str) -> bool:
        stripped = line.lstrip()
        if not stripped:
            return False
        # ``#`` covers Python/Ruby/shell/YAML; ``//`` and ``/*`` cover
        # JS/TS/Java/Go/Rust/PHP/C/C++. NOT included: bare ``*``-prefix
        # — in Python a leading ``*`` is real code (e.g. ``*args = ...``),
        # so treating it as a comment would silently drop credential
        # detection on legitimate source lines. The JSDoc / Javadoc
        # block-body ``*`` form is acceptable to miss for now since
        # this analyzer is .py-only at the call site (kept in sync
        # with api_security_scanner.py 2026-05-21).
        if stripped[0] == '#':
            return True
        return stripped[:2] in ('//', '/*')

    @classmethod
    def find_patterns_in_content(cls, content: str, file_path: str) -> List[Dict]:
        """Find all authentication patterns in file content."""
        matches = []
        lines = content.split('\n')

        for pattern_type, config in cls.AUTH_PATTERNS.items():
            for i, line in enumerate(lines, 1):
                if cls._is_comment_line(line):
                    continue
                for pattern in config['patterns']:
                    if re.search(pattern, line, re.IGNORECASE):
                        matches.append({
                            'pattern_type': pattern_type,
                            'line_number': i,
                            'line_content': line.strip(),
                            'matched_pattern': pattern,
                            'config': config
                        })

        return matches


class AuthFindingCreator:
    """Creates Finding objects for authentication anti-patterns."""
    
    @staticmethod
    def create_auth_finding(match: Dict, file_path: str):
        """Create Finding object for authentication anti-pattern."""
        pattern_type = match['pattern_type']
        config = match['config']
        
        title = f"AI Authentication Anti-pattern: {pattern_type.replace('_', ' ').title()}"
        
        severity = SeverityMapper.get_severity(pattern_type)
        impact_score = SeverityMapper.get_impact_score(severity)
        
        # Determine confidence based on pattern type
        confidence_map = {
            'hardcoded_secrets': 0.9,
            'weak_jwt': 0.8,
            'missing_rate_limiting': 0.7
        }
        confidence = confidence_map.get(pattern_type, 0.8)
        
        metadata = {
            'pattern_type': pattern_type,
            'matched_pattern': match['matched_pattern'],
            'ai_generated_risk': True
        }
        
        return FindingFactory.create_security_finding(
            finding_id=f"auth_{pattern_type}_{match['line_number']}_{hash(match['line_content'])}",
            severity=severity,
            file_path=file_path,
            line_number=match['line_number'],
            title=title,
            description=config['description'],
            detected_by="auth_pattern_analyzer",
            confidence=confidence,
            impact_score=impact_score,
            code_snippet=match['line_content'],
            remediation=config['remediation'],
            references=config['references'],
            metadata=metadata
        )


class FileContentReader:
    """Handles secure file content reading."""
    
    @staticmethod
    def read_file_content(file_path: str) -> str:
        """Read file content with proper encoding and error handling."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except UnicodeDecodeError:
            # Try with different encoding as fallback
            with open(file_path, 'r', encoding='latin-1') as f:
                return f.read()


class AIAuthPatternAnalyzer:
    """Main analyzer for AI-generated authentication anti-patterns."""
    
    def __init__(self, project_path: str):
        """Initialize analyzer with project path."""
        self.project_path = Path(project_path)
        self.pattern_matcher = AuthPatternMatcher()
        self.finding_creator = AuthFindingCreator()
        self.file_reader = FileContentReader()
    
    def analyze_file(self, file_path: str) -> List:
        """Analyze single file for authentication anti-patterns."""
        findings = []
        
        if not file_path.endswith('.py'):
            return findings
        
        try:
            content = self.file_reader.read_file_content(file_path)
            matches = self.pattern_matcher.find_patterns_in_content(content, file_path)
            
            for match in matches:
                finding = self.finding_creator.create_auth_finding(match, file_path)
                findings.append(finding)
        
        except Exception as e:
            # Create finding for analysis error
            error_finding = FindingFactory.create_analysis_error(
                finding_id=f"auth_analysis_error_{hash(file_path)}",
                file_path=file_path,
                title="Authentication Analysis Error",
                description=f"Failed to analyze authentication patterns: {str(e)}",
                detected_by="auth_pattern_analyzer"
            )
            findings.append(error_finding)
        
        return findings
    
    def get_enabled_checks(self) -> Dict[str, bool]:
        """Get enabled authentication checks from configuration."""
        config = ConfigLoader.get_config()
        auth_config = config.get('api_security', {}).get('authentication', {})
        
        return {
            'hardcoded_secrets': auth_config.get('check_hardcoded_secrets', True),
            'weak_jwt': auth_config.get('check_weak_jwt', True),
            'missing_rate_limiting': auth_config.get('check_missing_rate_limiting', True)
        }