"""
API Security Scanner Package - Refactored for CLAUDE.md Compliance.

Provides AI-aware API security analysis through clean, modular architecture:
- Package hallucination detection (supply chain security)
- Authentication anti-pattern analysis (credential security)  
- Input validation vulnerability scanning (injection attacks)

This refactored version addresses all code quality violations identified
in the comprehensive QA analysis while maintaining 100% functional compatibility.

Usage:
    from brass.scanners.api_security_refactored import APISecurityScanner
    
    scanner = APISecurityScanner("/path/to/project")
    findings = scanner.scan()
"""

from .scanner import APISecurityScanner
from .package_hallucination import PackageHallucinationDetector
from .auth_patterns import AIAuthPatternAnalyzer
from .input_validation import APIInputValidationAnalyzer
from .utils import ConfigLoader, FindingFactory

__version__ = "2.0.0"
__author__ = "New BrassCoders System Development Team"

__all__ = [
    'APISecurityScanner',
    'PackageHallucinationDetector', 
    'AIAuthPatternAnalyzer',
    'APIInputValidationAnalyzer',
    'ConfigLoader',
    'FindingFactory'
]