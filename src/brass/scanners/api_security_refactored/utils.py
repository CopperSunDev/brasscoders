"""
Shared utilities for API Security Scanner components.

Common functionality used across package hallucination, auth patterns, 
and input validation analyzers.
"""

from pathlib import Path
from typing import List, Optional, Dict
import yaml

from ...models.finding import Finding, FindingType, Severity
from ...core.logging_config import get_logger

logger = get_logger(__name__)


class ConfigLoader:
    """Centralized configuration loading with caching."""
    
    _config_cache = None
    _config_path = None
    
    @classmethod
    def get_config(cls) -> Dict:
        """Load configuration with caching for performance."""
        config_path = Path(__file__).parent / 'config.yaml'
        
        # Return cached config if path hasn't changed
        if cls._config_cache and cls._config_path == config_path:
            return cls._config_cache
        
        try:
            with open(config_path, 'r') as f:
                cls._config_cache = yaml.safe_load(f)
                cls._config_path = config_path
                return cls._config_cache
        except Exception as e:
            logger.warning(f"Failed to load config from {config_path}: {e}")
            return cls._get_default_config()
    
    @classmethod
    def _get_default_config(cls) -> Dict:
        """Fallback configuration."""
        return {
            'api_security': {
                'enabled': True,
                'package_validation': {'registry_timeout_seconds': 2},
                'performance': {'max_concurrent_file_analysis': 10}
            }
        }


class FindingFactory:
    """Factory for creating standardized Finding objects."""
    
    @staticmethod
    def create_security_finding(
        finding_id: str,
        severity: Severity,
        file_path: str,
        line_number: Optional[int],
        title: str,
        description: str,
        detected_by: str,
        confidence: float = 0.9,
        impact_score: float = 0.8,
        code_snippet: Optional[str] = None,
        remediation: Optional[str] = None,
        references: Optional[List[str]] = None,
        metadata: Optional[Dict] = None
    ) -> Finding:
        """Create standardized security finding."""
        return Finding(
            id=finding_id,
            type=FindingType.SECURITY,
            severity=severity,
            file_path=file_path,
            line_number=line_number,
            title=title,
            description=description,
            code_snippet=code_snippet,
            detected_by=detected_by,
            confidence=confidence,
            impact_score=impact_score,
            remediation=FindingFactory._get_remediation_text(remediation),
            references=references or [],
            metadata=metadata or {}
        )
    
    @staticmethod
    def _get_remediation_text(remediation: Optional[str]) -> str:
        """Get remediation text with fallback."""
        return remediation or "Review and address the security issue identified."
    
    @staticmethod
    def create_analysis_error(
        finding_id: str,
        file_path: str,
        title: str,
        description: str,
        detected_by: str
    ) -> Finding:
        """Create standardized analysis error finding."""
        return Finding(
            id=finding_id,
            type=FindingType.ANALYSIS_ERROR,
            severity=Severity.LOW,
            file_path=file_path,
            title=title,
            description=description,
            detected_by=detected_by,
            confidence=0.8,
            impact_score=0.1
        )


class FileUtils:
    """File analysis utilities."""
    
    @staticmethod
    def should_analyze_file(file_path: str) -> bool:
        """Determine if file should be analyzed (optimized version)."""
        file_path_obj = Path(file_path)
        
        # Skip common build/cache directories
        skip_dirs = {'.git', '__pycache__', 'node_modules', '.brass', 
                    'dist', 'build', '.venv', 'venv'}
        if any(part in skip_dirs for part in file_path_obj.parts):
            return False
        
        # Skip binary and large files
        if file_path_obj.suffix in {'.pyc', '.so', '.dylib', '.exe', 
                                   '.dll', '.zip', '.tar', '.gz'}:
            return False
        
        # Skip very large files (> 1MB) - configurable in future
        try:
            if file_path_obj.stat().st_size > 1024 * 1024:
                return False
        except (OSError, IOError):
            return False
        
        return True
    
    @staticmethod
    def is_api_related_file(file_path: str) -> bool:
        """Check if file is API-related for focused analysis."""
        api_indicators = ['api', 'route', 'endpoint', 'server', 
                         'flask', 'fastapi', 'django', 'wsgi']
        file_path_lower = file_path.lower()
        
        # Check file name and directory names
        for indicator in api_indicators:
            if indicator in file_path_lower:
                return True
        
        return True  # Include all Python files for comprehensive analysis


class SeverityMapper:
    """Maps vulnerability types to severity levels based on configuration."""
    
    @staticmethod
    def get_severity(vulnerability_type: str) -> Severity:
        """Get severity level for vulnerability type from configuration."""
        config = ConfigLoader.get_config()
        severity_thresholds = config.get('api_security', {}).get('severity_thresholds', {})
        
        severity_str = severity_thresholds.get(vulnerability_type, 'MEDIUM').upper()
        
        severity_map = {
            'CRITICAL': Severity.CRITICAL,
            'HIGH': Severity.HIGH, 
            'MEDIUM': Severity.MEDIUM,
            'LOW': Severity.LOW,
            'INFO': Severity.INFO
        }
        
        return severity_map.get(severity_str, Severity.MEDIUM)
    
    @staticmethod
    def get_impact_score(severity: Severity) -> float:
        """Convert severity to impact score."""
        impact_map = {
            Severity.CRITICAL: 0.9,
            Severity.HIGH: 0.8,
            Severity.MEDIUM: 0.6,
            Severity.LOW: 0.4,
            Severity.INFO: 0.2
        }
        return impact_map.get(severity, 0.5)