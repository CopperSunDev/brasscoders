"""
Constants for YAML builders to eliminate magic strings.

Centralizes all hardcoded strings used across builders following
Brass2 principles of clean, maintainable code.
"""

class FileTypes:
    """File type constants for classification."""
    UNKNOWN = 'unknown'
    TEST = 'test'
    SOURCE = 'source'
    OTHER = 'other'


class Priorities:
    """Priority level constants for AI guidance."""
    HIGH = 'HIGH'
    MEDIUM = 'MEDIUM'
    LOW = 'LOW'


class RiskLevels:
    """Risk assessment level constants."""
    CRITICAL = 'CRITICAL'
    HIGH = 'HIGH'
    MEDIUM = 'MEDIUM'
    LOW = 'LOW'
    NONE = 'NONE'


class TestIndicators:
    """Patterns for identifying test files."""
    PATTERNS = ['test', 'spec', 'fixture']
    ANALYSIS_ARTIFACTS = ['.brass']
    SOURCE_PATTERNS = ['src/', 'lib/', 'app/']


class Messages:
    """Common message constants."""
    NO_SECURITY_ISSUES = 'No security issues detected'
    IMMEDIATE_ATTENTION = 'Immediate attention required'
    REVIEW_KEY_ISSUES = 'Review and address key issues'
    MONITOR_PRACTICES = 'Monitor and maintain current practices'