"""
API Security Scanner for New BrassCoders System v2.0.

Provides AI-aware API security analysis detecting:
- Package hallucination (supply chain security risks)  
- Authentication anti-patterns in AI-generated code
- Input validation vulnerabilities
- API design security issues

Follows Brass2 architectural principles:
- Single responsibility (API security analysis only)
- Clean Finding interface integration
- Leverages existing Smart File Classification
- No lateral dependencies on other scanners
"""

import ast
import re
import json
import requests
import importlib.util
from functools import lru_cache
from pathlib import Path
from typing import List, Optional, Dict, Any, Set, Tuple
from dataclasses import dataclass

from ..models.finding import Finding, FindingType, Severity
from ..core.file_classifier import FileClassifier
from ..core.logging_config import get_logger
from ..core.file_integrity import FileIntegrityChecker
from ..core.path_safety import is_within


# Lines longer than this are skipped during pattern matching. Minified JS bundles
# can have lines exceeding 100,000 characters; running every regex against them
# triggers catastrophic backtracking on patterns with ``.*``. Real source code
# almost never has lines this long. Skipping is a no-signal-loss optimization
# because any "issue" a regex finds in a 100KB single line is unactionable noise.
_MAX_LINE_LENGTH = 10_000

# Cap the saved code_snippet length before serialization. Mirrors the privacy
# scanner's redaction principle: even when the snippet isn't a secret, an
# arbitrarily long snippet (a minified JS line, a base64 blob, etc.) bloats the
# YAML output and contributes nothing actionable.
_MAX_SNIPPET_LENGTH = 200


@lru_cache(maxsize=256)
def _compiled_pattern(pattern: str) -> "re.Pattern[str]":
    """Compile and cache a regex pattern. Module-level so the cache survives
    multiple analyzer instances (each scan creates new ones).
    """
    return re.compile(pattern, re.IGNORECASE)


def _truncate_snippet(snippet: str) -> str:
    """Bound a code_snippet for serialization. Empty input returns unchanged."""
    if not snippet:
        return snippet
    if len(snippet) <= _MAX_SNIPPET_LENGTH:
        return snippet
    return snippet[:_MAX_SNIPPET_LENGTH] + "…"


def _is_comment_line(line: str) -> bool:
    """Return True if ``line`` is a single-line comment in any language
    ``AIAuthPatternAnalyzer`` scans across (currently only ``.py``).
    Used to short-circuit auth-pattern matching so a stray ``token=``
    substring inside a code comment doesn't surface as a CRITICAL
    hardcoded-credential finding.

    Coverage:
      - ``#``  Python single-line comment
      - ``//`` reserved for future cross-language coverage (auth
        analyzer is .py-only today; cheap to leave in place)
      - ``/*`` C-style block-comment opener (same)

    Notably NOT included: leading ``*`` body of a C-style block
    (e.g. ``/**\\n * key = "..." \\n */``). Earlier versions matched
    bare ``*``-prefixed lines, but in Python that's not a comment —
    a Python multiplication-prefixed line like ``*args = ...`` (in
    docstring code samples or copy-pasted snippets) is real code and
    must still trigger auth detection. Since this analyzer only sees
    ``.py`` files (gated at ``analyze_file`` line 299-300), the
    JSDoc-body case isn't reachable from here. If/when the analyzer
    is extended to .js/.ts files, add the ``*`` case back with
    explicit file-extension gating.
    """
    stripped = line.lstrip()
    if not stripped:
        return False
    if stripped[0] == '#':
        return True
    return stripped[:2] in ('//', '/*')


# C.8a: known-safe escape-wrapper names. A dangerouslySetInnerHTML match
# whose __html value is one of these (or any plausibly escape-named
# function) is treated as a false positive — the wrapper is the project's
# responsibility, and an escape-shaped name is a strong signal the dev
# intended safety. This is the same posture as the C.7b hardcoded_password
# fix: prefer trust + downstream-AI-coder-triage over reflexive flagging.
_XSS_SAFE_WRAPPER_PATTERN = re.compile(
    r'__html\s*:\s*('
    # Known-safe wrappers by name (case-insensitive).
    r'(?i:safeJsonLd|sanitize|sanitizeHtml|sanitizeMarkdown|sanitizeUrl'
    r'|DOMPurify\.sanitize|escapeHtml|escape|encodeHtml|htmlEncode'
    r'|safeMarkup|safeHtml|cleanHtml|purify)'
    # …or any identifier that starts with "safe" / "escape" / "sanitize"
    # / "encode" / "clean" / "purify" (case-insensitive), followed by a
    # paren (i.e. function call). The (?i:…) above is non-capturing.
    r'|(?i:(?:safe|escape|sanitize|encode|clean|purify)\w*)'
    r')\s*\('
)


def _xss_match_is_safe_wrapper(line: str) -> bool:
    """True if a dangerouslySetInnerHTML match on `line` is wrapping
    its __html value in a function call whose name implies escaping.
    See _XSS_SAFE_WRAPPER_PATTERN."""
    return bool(_XSS_SAFE_WRAPPER_PATTERN.search(line))

logger = get_logger(__name__)


@dataclass
class PackageValidationResult:
    """Result from package existence validation."""
    exists: bool
    source: str  # 'local' or 'registry'
    error_message: Optional[str] = None


class PackageHallucinationDetector:
    """Detects AI-generated references to non-existent packages using AST + registry validation.

    **Network-touching scanner — opt-in only.** Validating an "unknown" import requires
    an outbound HTTPS GET to the language's package registry (PyPI / npm / pkg.go.dev).
    For closed-source codebases that contain private internal package names, this would
    leak those names to a third-party registry. The detector therefore refuses to run
    until ``enabled=True`` is passed explicitly (the CLI exposes this via
    ``--check-package-hallucination``; ``--offline`` overrides it back to off).
    """

    def __init__(self, project_path: str, enabled: bool = False):
        self.project_path = Path(project_path)
        self.enabled = enabled
        self.session = None
        if self.enabled:
            self.session = requests.Session()
            self.session.timeout = 2  # Fast timeout

        self.package_registries = {
            'python': 'https://pypi.org/pypi/{}/json',
            'javascript': 'https://registry.npmjs.org/{}',
            'go': 'https://pkg.go.dev/{}'
        }

    def analyze_file(self, file_path: str) -> List[Finding]:
        """Analyze single file for package hallucination (Following Brass2 pattern)."""
        findings = []

        # When the detector is opt-out (default), make zero outbound calls.
        if not self.enabled:
            return findings

        if not file_path.endswith('.py'):
            return findings

        try:
            content = FileIntegrityChecker.read_with_integrity_check(
                Path(file_path), encoding='utf-8'
            )
            if content is None:
                logger.warning(f"File modified during read, skipping: {file_path}")
                return []
            
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        result = self._validate_package_exists(alias.name, 'python')
                        if not result.exists:
                            findings.append(self._create_hallucination_finding(
                                alias.name, file_path, node.lineno, 'python', 'import', result.error_message
                            ))
                elif isinstance(node, ast.ImportFrom) and node.module:
                    result = self._validate_package_exists(node.module, 'python')
                    if not result.exists:
                        findings.append(self._create_hallucination_finding(
                            node.module, file_path, node.lineno, 'python', 'from_import', result.error_message
                        ))
        except (SyntaxError, UnicodeDecodeError) as e:
            # Create finding for unparseable files
            error_finding = Finding(
                id=f"package_parse_error_{hash(file_path)}",
                type=FindingType.ANALYSIS_ERROR,
                severity=Severity.LOW,
                file_path=file_path,
                title="Package Analysis Parse Error",
                description=f"Could not parse file for import analysis: {str(e)}",
                detected_by="package_hallucination_detector",
                confidence=0.7,
                impact_score=0.1
            )
            findings.append(error_finding)
        
        return findings
    
    def _create_hallucination_finding(self, package_name: str, file_path: str, 
                                    line_number: int, language: str, import_type: str,
                                    error_message: Optional[str] = None) -> Finding:
        """Create Finding object for hallucinated package."""
        description = (f"AI-generated reference to non-existent package '{package_name}'. "
                      f"This could be a supply chain security risk if a malicious package "
                      f"with this name is later published.")
        
        if error_message:
            description += f" Validation error: {error_message}"
        
        return Finding(
            id=f"package_hallucination_{package_name}_{line_number}",
            type=FindingType.SECURITY,  # Package hallucination is a security issue
            severity=Severity.HIGH,     # Supply chain security risk
            file_path=file_path,
            line_number=line_number,
            title=f"Package Hallucination: {package_name}",
            description=description,
            detected_by="package_hallucination_detector",
            confidence=0.95,  # High confidence - either package exists or it doesn't
            impact_score=0.8, # High impact - supply chain risks are serious
            remediation=f"Verify that '{package_name}' is the correct package name. "
                       f"Check for typos or use an alternative package that exists.",
            references=[
                "https://owasp.org/www-community/attacks/Supply_Chain_Attack",
                "https://snyk.io/blog/typosquatting-attacks/"
            ],
            metadata={
                'package_name': package_name,
                'language': language,
                'import_type': import_type,
                'validation_method': 'registry_api'
            }
        )
    
    def _validate_package_exists(self, package_name: str, language: str) -> PackageValidationResult:
        """
        Simple two-step validation:
        1. Check if locally installed (fast)
        2. Check registry if not local (authoritative)
        """
        # Step 1: Fast local check for installed packages
        if language == 'python':
            try:
                spec = importlib.util.find_spec(package_name)
                if spec is not None:
                    return PackageValidationResult(exists=True, source='local')
            except (ImportError, ValueError, ModuleNotFoundError):
                pass
        
        # Step 2: Registry check for packages not locally installed.
        # On network failure (DNS, connection refused, captive portal, slow
        # PyPI), assume the package is valid rather than flagging every
        # uninstalled import as a "package hallucination". The previous
        # behaviour produced a flood of HIGH-severity false positives any
        # time the user's network was off — a worse UX than missing a real
        # hallucination, which only matters if the user explicitly
        # opted into the network check.
        try:
            registry_url = self.package_registries[language].format(package_name)
            response = self.session.get(registry_url, timeout=2)
            exists = response.status_code == 200
            return PackageValidationResult(exists=exists, source='registry')
        except Exception as exc:
            logger.debug(
                f"Registry check for {package_name!r} ({language}) failed: {exc}. "
                "Assuming package exists; rerun online for a definitive answer."
            )
            return PackageValidationResult(
                exists=True,
                source='registry',
                error_message=f"network_unavailable: {exc}",
            )


class AIAuthPatternAnalyzer:
    """Detects AI-generated authentication anti-patterns."""
    
    AI_AUTH_PATTERNS = {
        'hardcoded_secrets': {
            'patterns': [
                r'password\s*=\s*["\'][^"\']+["\']',
                r'api_key\s*=\s*["\'][^"\']+["\']',
                r'secret\s*=\s*["\'][^"\']+["\']',
                r'token\s*=\s*["\'][^"\']+["\']',
                r'jwt_secret\s*=\s*["\'][^"\']+["\']'
            ],
            'severity': Severity.CRITICAL,
            'confidence': 0.9
        },
        'weak_jwt': {
            'patterns': [
                r'jwt\.encode\([^,]+,\s*["\']secret["\']',
                r'HS256.*["\']secret["\']',
                r'jwt.*algorithm.*none',  # Algorithm: none vulnerability
                r'jwt\.encode.*key=None'
            ],
            'severity': Severity.HIGH,
            'confidence': 0.8
        },
        'missing_rate_limiting': {
            'patterns': [
                r'@app\.route.*POST.*(?!.*rate_limit)',
                r'app\.post.*(?!.*rate_limit)',
                r'@api\.route.*(?!.*rate_limit)',
                r'@flask\.route.*(?!.*rate_limit)'
            ],
            'severity': Severity.MEDIUM,
            'confidence': 0.7
        }
    }
    
    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
    
    def analyze_file(self, file_path: str) -> List[Finding]:
        """Analyze single file for authentication anti-patterns."""
        findings = []
        
        if not file_path.endswith('.py'):
            return findings
        
        try:
            content = FileIntegrityChecker.read_with_integrity_check(
                Path(file_path), encoding='utf-8'
            )
            if content is None:
                logger.warning(f"File modified during read, skipping: {file_path}")
                return []
            
            for pattern_type, config in self.AI_AUTH_PATTERNS.items():
                findings.extend(self._check_patterns(
                    content, file_path, pattern_type, config
                ))
        
        except Exception as e:
            # Create finding for analysis error
            error_finding = Finding(
                id=f"auth_analysis_error_{hash(file_path)}",
                type=FindingType.ANALYSIS_ERROR,
                severity=Severity.LOW,
                file_path=file_path,
                title="Authentication Analysis Error",
                description=f"Failed to analyze authentication patterns: {str(e)}",
                detected_by="auth_pattern_analyzer",
                confidence=0.8,
                impact_score=0.1
            )
            findings.append(error_finding)
        
        return findings
    
    def _check_patterns(self, content: str, file_path: str, pattern_type: str,
                       config: Dict) -> List[Finding]:
        """Check content against authentication patterns.

        Performance: patterns are compiled once via the module-level
        ``_compiled_pattern`` cache, and lines longer than ``_MAX_LINE_LENGTH``
        are skipped to avoid catastrophic backtracking on minified bundles.
        """
        findings = []
        lines = content.split('\n')
        lines_already_flagged = set()  # Deduplicate by line for same vulnerability type
        compiled_patterns = [(_compiled_pattern(p), p) for p in config['patterns']]

        for i, line in enumerate(lines, 1):
            if len(line) > _MAX_LINE_LENGTH:
                # Minified bundle line — skip rather than feed to backtracking regex.
                continue
            if _is_comment_line(line):
                # Comments mentioning ``api_key = "..."`` or
                # ``token=`` shouldn't fire as credential findings.
                # Real-world false positive observed 2026-05-21 on
                # whisperx: ``# FIX: pyannote-audio 4.0 uses
                # 'token=' not 'use_token='`` produced a CRITICAL
                # Hardcoded Secrets finding. Cross-language comment
                # markers covered: ``#`` (Python/Ruby/shell/YAML),
                # ``//`` (JS/TS/Java/Go/Rust/PHP), ``/*`` and
                # ``*`` body of C-style block comments.
                continue
            line_key = (i, pattern_type)  # Unique key per line per vulnerability type

            for compiled, pattern in compiled_patterns:
                if compiled.search(line):
                    if line_key not in lines_already_flagged:
                        # The hardcoded_secrets pattern matches lines containing literal
                        # credentials (e.g. ``api_key = "sk_live_..."``). Storing the
                        # raw line in code_snippet would leak the secret into the YAML
                        # output, which is exactly what we're flagging the developer
                        # for. Redact before persisting, then bound the length.
                        snippet = _truncate_snippet(
                            self._redact_secret_in_line(line.strip(), pattern_type)
                        )
                        finding = Finding(
                            id=f"auth_{pattern_type}_{i}_{hash(line)}",
                            type=FindingType.SECURITY,
                            severity=config['severity'],
                            file_path=file_path,
                            line_number=i,
                            title=f"AI Authentication Anti-pattern: {pattern_type.replace('_', ' ').title()}",
                            description=self._get_pattern_description(pattern_type),
                            code_snippet=snippet,
                            detected_by="auth_pattern_analyzer",
                            confidence=config['confidence'],
                            impact_score=self._get_impact_score(config['severity']),
                            remediation=self._get_remediation(pattern_type),
                            references=self._get_references(pattern_type),
                            metadata={
                                'pattern_type': pattern_type,
                                'matched_pattern': pattern,
                                'ai_generated_risk': True,
                                'snippet_redacted': pattern_type == 'hardcoded_secrets',
                            }
                        )
                        findings.append(finding)
                        lines_already_flagged.add(line_key)
                    break  # Only need first match per line per vulnerability type

        return findings

    @staticmethod
    def _redact_secret_in_line(line: str, pattern_type: str) -> str:
        """Replace literal credential values in a line with ``"<REDACTED>"``.

        Only the ``hardcoded_secrets`` pattern requires redaction; other auth
        anti-patterns (weak_jwt, missing_rate_limiting) flag structural issues
        whose lines are safe to surface verbatim.
        """
        if pattern_type != 'hardcoded_secrets':
            return line
        # Match either single-quoted or double-quoted string literals and replace
        # their contents. Conservative: any quoted value on a flagged line is
        # treated as potentially sensitive.
        return re.sub(r'(["\'])([^"\']+)(["\'])', r'\1<REDACTED>\3', line)
    
    def _get_pattern_description(self, pattern_type: str) -> str:
        """Get human-readable description for pattern type."""
        descriptions = {
            'hardcoded_secrets': "Hardcoded secret or API key detected in source code. This is a critical security vulnerability that exposes sensitive credentials.",
            'weak_jwt': "Weak JWT implementation detected. Using weak secrets or 'none' algorithm can compromise authentication security.",
            'missing_rate_limiting': "API endpoint without rate limiting detected. This can lead to abuse, DoS attacks, and resource exhaustion."
        }
        return descriptions.get(pattern_type, "Security anti-pattern detected")
    
    def _get_impact_score(self, severity: Severity) -> float:
        """Convert severity to impact score."""
        impact_map = {
            Severity.CRITICAL: 0.9,
            Severity.HIGH: 0.8,
            Severity.MEDIUM: 0.6,
            Severity.LOW: 0.4,
            Severity.INFO: 0.2
        }
        return impact_map.get(severity, 0.5)
    
    def _get_remediation(self, pattern_type: str) -> str:
        """Get remediation advice for pattern type."""
        remediation_map = {
            'hardcoded_secrets': "Move secrets to environment variables or secure configuration. Use tools like python-decouple or similar.",
            'weak_jwt': "Use strong, randomly generated secrets. Avoid 'none' algorithm. Consider using RS256 with proper key management.",
            'missing_rate_limiting': "Implement rate limiting using flask-limiter or similar. Set appropriate limits for your API endpoints."
        }
        return remediation_map.get(pattern_type, "Review and fix the detected security pattern")
    
    def _get_references(self, pattern_type: str) -> List[str]:
        """Get reference links for pattern type."""
        references_map = {
            'hardcoded_secrets': [
                "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials",
                "https://cwe.mitre.org/data/definitions/798.html"
            ],
            'weak_jwt': [
                "https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/",
                "https://tools.ietf.org/html/rfc7519"
            ],
            'missing_rate_limiting': [
                "https://owasp.org/www-project-api-security/",
                "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html"
            ]
        }
        return references_map.get(pattern_type, [])


class APIInputValidationAnalyzer:
    """Analyzes AI-generated input validation patterns for security vulnerabilities."""
    
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
            'severity': Severity.CRITICAL,
            'confidence': 0.85
        },
        'xss_risk': {
            'patterns': [
                r'render_template.*\|safe',
                r'innerHTML.*user_input',
                # Only fire on dangerouslySetInnerHTML when the __html
                # value is a raw JSON.stringify call or an interpolated
                # expression. Function-call values (safeJsonLd(...),
                # DOMPurify.sanitize(...), escapeHtml(...), etc.) are
                # presumed safe-by-name and excluded via the safe-wrapper
                # post-match filter below — see _xss_match_is_safe_wrapper.
                r'dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:',
                r'document\.write\(.*user',
                r'render_template_string.*f".*{.*}"',  # f-string template injection
                r'template\s*=\s*f".*{.*}"'           # f-string templates
            ],
            'severity': Severity.HIGH,
            'confidence': 0.8
        },
        'command_injection': {
            'patterns': [
                r'subprocess.*shell=True.*user_input',
                r'os\.system.*user_input',
                r'eval\(.*user_input',
                r'exec\(.*user_input'
            ],
            'severity': Severity.CRITICAL,
            'confidence': 0.9
        }
    }
    
    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
    
    def analyze_file(self, file_path: str) -> List[Finding]:
        """Analyze single file for input validation issues."""
        findings = []
        
        if not file_path.endswith(('.py', '.js', '.ts')):
            return findings
        
        try:
            content = FileIntegrityChecker.read_with_integrity_check(
                Path(file_path), encoding='utf-8'
            )
            if content is None:
                logger.warning(f"File modified during read, skipping: {file_path}")
                return []
            
            for pattern_type, config in self.VALIDATION_PATTERNS.items():
                findings.extend(self._check_validation_patterns(
                    content, file_path, pattern_type, config
                ))
        
        except Exception as e:
            # Create finding for analysis error
            error_finding = Finding(
                id=f"input_validation_error_{hash(file_path)}",
                type=FindingType.ANALYSIS_ERROR,
                severity=Severity.LOW,
                file_path=file_path,
                title="Input Validation Analysis Error",
                description=f"Failed to analyze input validation patterns: {str(e)}",
                detected_by="input_validation_analyzer",
                confidence=0.8,
                impact_score=0.1
            )
            findings.append(error_finding)
        
        return findings
    
    def _check_validation_patterns(self, content: str, file_path: str, pattern_type: str,
                                 config: Dict) -> List[Finding]:
        """Check content for input validation vulnerabilities.

        Performance: patterns are compiled once via the module-level
        ``_compiled_pattern`` cache, and lines longer than ``_MAX_LINE_LENGTH``
        are skipped to avoid catastrophic backtracking on minified bundles.
        """
        findings = []
        lines = content.split('\n')
        lines_already_flagged = set()  # Deduplicate by line for same vulnerability type
        compiled_patterns = [(_compiled_pattern(p), p) for p in config['patterns']]

        for i, line in enumerate(lines, 1):
            if len(line) > _MAX_LINE_LENGTH:
                continue
            line_key = (i, pattern_type)  # Unique key per line per vulnerability type

            for compiled, pattern in compiled_patterns:
                if compiled.search(line):
                    # Safe-wrapper filter (C.8a): the dangerouslySetInnerHTML
                    # pattern is the highest-trust-damage FP we've seen.
                    # Skip when the __html value is a function call —
                    # safeJsonLd(...), DOMPurify.sanitize(...), escapeHtml(...)
                    # etc. The user's responsibility to escape inside their
                    # wrapper; we presume escape-shaped names mean it.
                    if pattern_type == 'xss_risk' and _xss_match_is_safe_wrapper(line):
                        continue
                    if line_key not in lines_already_flagged:
                        # First pattern match for this line and vulnerability type.
                        # Bound the snippet length so a long match line can't bloat
                        # the YAML output.
                        finding = Finding(
                            id=f"input_validation_{pattern_type}_{i}_{hash(line)}",
                            type=FindingType.SECURITY,
                            severity=config['severity'],
                            file_path=file_path,
                            line_number=i,
                            title=f"Input Validation Vulnerability: {pattern_type.replace('_', ' ').title()}",
                            description=self._get_validation_description(pattern_type),
                            code_snippet=_truncate_snippet(line.strip()),
                            detected_by="input_validation_analyzer",
                            confidence=config['confidence'],
                            impact_score=self._get_impact_score_from_severity(config['severity']),
                            remediation=self._get_validation_remediation(pattern_type),
                            references=self._get_validation_references(pattern_type),
                            metadata={
                                'vulnerability_type': pattern_type,
                                'matched_pattern': pattern,
                                'ai_generated_risk': True
                            }
                        )
                        findings.append(finding)
                        lines_already_flagged.add(line_key)
                    break  # Only need first match per line per vulnerability type
        
        return findings
    
    def _get_validation_description(self, pattern_type: str) -> str:
        """Get description for validation vulnerability."""
        descriptions = {
            'sql_injection_risk': "Potential SQL injection vulnerability detected. User input appears to be directly used in SQL queries without proper sanitization.",
            'xss_risk': "Potential cross-site scripting (XSS) vulnerability detected. User input may be rendered without proper escaping.",
            'command_injection': "Potential command injection vulnerability detected. User input appears to be used in system commands without sanitization."
        }
        return descriptions.get(pattern_type, "Input validation vulnerability detected")
    
    def _get_validation_remediation(self, pattern_type: str) -> str:
        """Get remediation for validation vulnerability."""
        remediation_map = {
            'sql_injection_risk': "Use parameterized queries or prepared statements. Consider using an ORM like SQLAlchemy with proper parameter binding.",
            'xss_risk': "Properly escape user input before rendering. Use template engines with auto-escaping enabled by default.",
            'command_injection': "Avoid using user input in system commands. If necessary, use strict input validation and sanitization."
        }
        return remediation_map.get(pattern_type, "Implement proper input validation and sanitization")
    
    def _get_validation_references(self, pattern_type: str) -> List[str]:
        """Get reference links for validation vulnerability."""
        references_map = {
            'sql_injection_risk': [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
            ],
            'xss_risk': [
                "https://owasp.org/www-community/attacks/xss/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
            ],
            'command_injection': [
                "https://owasp.org/www-community/attacks/Command_Injection",
                "https://cwe.mitre.org/data/definitions/78.html"
            ]
        }
        return references_map.get(pattern_type, [])
    
    def _get_impact_score_from_severity(self, severity: Severity) -> float:
        """Convert severity to impact score."""
        impact_map = {
            Severity.CRITICAL: 0.9,
            Severity.HIGH: 0.8,
            Severity.MEDIUM: 0.6,
            Severity.LOW: 0.4,
            Severity.INFO: 0.2
        }
        return impact_map.get(severity, 0.5)


class APISecurityScanner:
    """
    AI-aware API security analysis scanner.
    
    Analyzes API implementations for AI-specific security vulnerabilities
    including authentication anti-patterns, package hallucination,
    and input validation issues.
    
    Follows Brass2 architecture:
    - Single responsibility (API security analysis only)
    - Clean Finding interface
    - File classification awareness
    - No lateral dependencies
    """
    
    def __init__(self, project_path: str, check_package_hallucination: bool = False, file_index=None):
        """
        Initialize API Security Scanner.

        Args:
            project_path: Root path of the project to analyze
            check_package_hallucination: When True, validate imports against PyPI/npm/
                pkg.go.dev. Off by default because validation requires outbound HTTPS
                calls that would leak private internal package names to third-party
                registries. The CLI sets this via ``--check-package-hallucination``.
        """
        self.project_path = Path(project_path)
        self.file_classifier = FileClassifier(str(self.project_path))
        # Optional shared FileIndex (Perf #2/#12). Falls back to rglob.
        self.file_index = file_index

        # Initialize component analyzers. Package hallucination detection is the only
        # network-touching analyzer; it must stay default-off.
        self.package_detector = PackageHallucinationDetector(
            project_path, enabled=check_package_hallucination
        )
        self.auth_analyzer = AIAuthPatternAnalyzer(project_path)
        self.input_analyzer = APIInputValidationAnalyzer(project_path)

        logger.info(
            f"API Security Scanner initialized for {project_path} "
            f"(package_hallucination={'ON' if check_package_hallucination else 'OFF'})"
        )
    
    def scan(self, file_paths: Optional[List[str]] = None) -> List[Finding]:
        """
        Perform AI-aware API security analysis on specified files.
        
        Args:
            file_paths: Optional list of specific files to scan.
                       If None, scans all relevant files in project.
        
        Returns:
            List of Finding objects representing detected API security issues
        """
        if file_paths is None:
            file_paths = self._discover_api_files()
        
        all_findings = []
        
        logger.info(f"Scanning {len(file_paths)} files for API security issues")
        
        for file_path in file_paths:
            if not self._should_analyze_file(file_path):
                continue
            
            try:
                file_findings = self._analyze_single_file(file_path)
                
                # Add file classification context to findings (following Brass2 pattern)
                for finding in file_findings:
                    file_context = self.file_classifier.classify_file(file_path)
                    finding.metadata['file_context'] = {
                        'file_type': file_context.file_type.value,
                        'confidence': file_context.confidence,
                        'intended_for_issues': file_context.intended_for_issues,
                        'priority_weight': file_context.priority_weight,
                        'classification_reason': file_context.classification_reason,
                        'is_source_code': file_context.is_source_code(),
                        'is_test_related': file_context.is_test_related()
                    }
                
                all_findings.extend(file_findings)
                
            except Exception as e:
                # Create finding for analysis failure (following Brass2 pattern)
                logger.warning(f"API analysis failed for {file_path}: {e}")
                error_finding = Finding(
                    id=f"api_analysis_error_{hash(file_path)}",
                    type=FindingType.ANALYSIS_ERROR,
                    severity=Severity.LOW,
                    file_path=file_path,
                    title="API Analysis Error",
                    description=f"Failed to analyze file for API security issues: {str(e)}",
                    detected_by="api_security_scanner",
                    confidence=0.9,
                    impact_score=0.1
                )
                all_findings.append(error_finding)
        
        logger.info(f"API Security Scanner found {len(all_findings)} findings")
        return all_findings
    
    def _analyze_single_file(self, file_path: str) -> List[Finding]:
        """Analyze single file for API security issues."""
        findings = []
        
        # Package hallucination detection (high priority for supply chain security)
        findings.extend(self.package_detector.analyze_file(file_path))
        
        # Authentication pattern analysis
        findings.extend(self.auth_analyzer.analyze_file(file_path))
        
        # Input validation analysis  
        findings.extend(self.input_analyzer.analyze_file(file_path))
        
        return findings
    
    def _discover_api_files(self) -> List[str]:
        """Discover files relevant for API analysis.

        Boundary check: rglob will follow symlinks; we refuse anything that resolves
        outside the project root to keep a malicious symlink from steering the API
        scanner into ``~/.aws/credentials``-style targets.
        """
        api_files = []

        # Prefer shared FileIndex over 3 separate rglob walks (Perf #12).
        if self.file_index is not None:
            # Python API-related
            for py_file in self.file_index.files_with_ext('.py'):
                fps = str(py_file)
                if self._is_api_related(fps):
                    api_files.append(fps)
            # JS/TS files (all of them — no _is_api_related gate today)
            for f in self.file_index.files_with_ext('.js', '.ts'):
                api_files.append(str(f))
        else:
            # Python API files
            for py_file in self.project_path.rglob('*.py'):
                if not is_within(py_file, self.project_path):
                    continue
                file_path_str = str(py_file)
                if not self.file_classifier.should_exclude_from_analysis(file_path_str):
                    if self._is_api_related(file_path_str):
                        api_files.append(file_path_str)
            # JavaScript/TypeScript API files
            for js_file in self.project_path.rglob('*.js'):
                if not is_within(js_file, self.project_path):
                    continue
                file_path_str = str(js_file)
                if not self.file_classifier.should_exclude_from_analysis(file_path_str):
                    api_files.append(file_path_str)
            for ts_file in self.project_path.rglob('*.ts'):
                if not is_within(ts_file, self.project_path):
                    continue
                file_path_str = str(ts_file)
                if not self.file_classifier.should_exclude_from_analysis(file_path_str):
                    api_files.append(file_path_str)
        
        # Configuration files
        for config_file in ['package.json', 'requirements.txt', 'go.mod']:
            config_path = self.project_path / config_file
            if config_path.exists():
                api_files.append(str(config_path))
        
        return api_files
    
    def _is_api_related(self, file_path: str) -> bool:
        """Check if Python file is API-related.

        Historical note: this used to scan for keywords like 'api', 'route',
        'flask', etc., but the loop's terminal ``return True`` made the
        keyword check dead code. The intent now is "include every Python
        file" (matching the existing comment); the keyword loop is removed
        rather than kept as misleading apparent filtering.
        """
        return True
    
    def _should_analyze_file(self, file_path: str) -> bool:
        """Determine if file should be analyzed (following Brass2 pattern)."""
        file_path_obj = Path(file_path)
        parts = file_path_obj.parts

        # Skip common build/cache directories
        skip_dirs = {'.git', '__pycache__', 'node_modules', '.brass', 'dist', 'build', '.venv', 'venv'}
        if any(part in skip_dirs for part in parts):
            return False

        # Skip Claude Code agent worktrees (`.claude/worktrees/*`) while
        # PRESERVING `.claude/agents/`, `.claude/skills/`, and other
        # legitimate user-edited config. Mirrors the FilePrefilterScanner
        # rule shipped in c911e05. Without this, the caller-provided
        # file_paths path would slip worktree duplicates into
        # AIAuthPatternAnalyzer, which has no path-exclusion of its own
        # — a disclosure surface flagged in the 2026-05-21 cumulative
        # full-bugs review.
        for i in range(len(parts) - 1):
            if parts[i] == '.claude' and parts[i + 1] == 'worktrees':
                return False
        
        # Skip binary and large files
        if file_path_obj.suffix in {'.pyc', '.so', '.dylib', '.exe', '.dll', '.zip', '.tar', '.gz'}:
            return False
        
        # Skip very large files (> 1MB)
        try:
            if file_path_obj.stat().st_size > 1024 * 1024:
                return False
        except (OSError, IOError):
            return False
        
        return True