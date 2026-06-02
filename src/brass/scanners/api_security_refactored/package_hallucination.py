"""
Package Hallucination Detector for API Security Scanner.

Detects AI-generated references to non-existent packages using AST parsing
and two-tier validation (local + registry).
"""

import ast
import requests
import importlib.util
from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass

from ...models.finding import Severity
from ...core.logging_config import get_logger
from .utils import ConfigLoader, FindingFactory

logger = get_logger(__name__)


@dataclass
class PackageValidationResult:
    """Result from package existence validation."""
    exists: bool
    source: str  # 'local' or 'registry'
    error_message: Optional[str] = None


class PackageRegistryValidator:
    """Handles package registry validation with session management."""
    
    def __init__(self):
        """Initialize validator with configured registries."""
        self.session = requests.Session()
        config = ConfigLoader.get_config()
        pkg_config = config.get('api_security', {}).get('package_validation', {})
        
        # Configure timeout from config
        timeout = pkg_config.get('registry_timeout_seconds', 2)
        self.session.timeout = timeout
        
        # Load registry URLs from config
        registries = config.get('api_security', {}).get('registries', {})
        self.package_registries = {
            'python': registries.get('python', 'https://pypi.org/pypi/{}/json'),
            'javascript': registries.get('javascript', 'https://registry.npmjs.org/{}'),
            'go': registries.get('go', 'https://pkg.go.dev/{}')
        }
    
    def validate_package(self, package_name: str, language: str) -> PackageValidationResult:
        """Validate package existence using two-tier approach."""
        # Step 1: Fast local check for installed packages
        if self._check_local_package(package_name, language):
            return PackageValidationResult(exists=True, source='local')
        
        # Step 2: Registry check for packages not locally installed
        return self._check_registry_package(package_name, language)
    
    def _check_local_package(self, package_name: str, language: str) -> bool:
        """Fast local package existence check."""
        if language == 'python':
            try:
                spec = importlib.util.find_spec(package_name)
                return spec is not None
            except (ImportError, ValueError, ModuleNotFoundError):
                pass
        return False
    
    def _check_registry_package(self, package_name: str, language: str) -> PackageValidationResult:
        """Check package in registry."""
        try:
            registry_url = self.package_registries[language].format(package_name)
            response = self.session.get(registry_url, timeout=self.session.timeout)
            exists = response.status_code == 200
            return PackageValidationResult(exists=exists, source='registry')
        except Exception as e:
            # If validation fails, assume package doesn't exist for security
            return PackageValidationResult(
                exists=False, 
                source='registry', 
                error_message=str(e)
            )


class ASTPackageExtractor:
    """Extracts package imports from Python AST."""
    
    @staticmethod
    def extract_imports(file_path: str) -> List[tuple]:
        """Extract import statements from Python file."""
        imports = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                tree = ast.parse(f.read())
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append((alias.name, node.lineno, 'import'))
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imports.append((node.module, node.lineno, 'from_import'))
        
        except (SyntaxError, UnicodeDecodeError) as e:
            logger.debug(f"Failed to parse {file_path}: {e}")
            raise
        
        return imports


class HallucinationFindingCreator:
    """Creates Finding objects for package hallucination issues."""
    
    @staticmethod
    def create_hallucination_finding(
        package_name: str, 
        file_path: str,
        line_number: int, 
        language: str, 
        import_type: str,
        error_message: Optional[str] = None
    ):
        """Create Finding object for hallucinated package."""
        description = (
            f"AI-generated reference to non-existent package '{package_name}'. "
            f"This could be a supply chain security risk if a malicious package "
            f"with this name is later published."
        )
        
        if error_message:
            description += f" Validation error: {error_message}"
        
        remediation = (
            f"Verify that '{package_name}' is the correct package name. "
            f"Check for typos or use an alternative package that exists."
        )
        
        references = [
            "https://owasp.org/www-community/attacks/Supply_Chain_Attack",
            "https://snyk.io/blog/typosquatting-attacks/"
        ]
        
        metadata = {
            'package_name': package_name,
            'language': language,
            'import_type': import_type,
            'validation_method': 'registry_api'
        }
        
        return FindingFactory.create_security_finding(
            finding_id=f"package_hallucination_{package_name}_{line_number}",
            severity=Severity.HIGH,  # Supply chain security risk
            file_path=file_path,
            line_number=line_number,
            title=f"Package Hallucination: {package_name}",
            description=description,
            detected_by="package_hallucination_detector",
            confidence=0.95,  # High confidence - either package exists or it doesn't
            impact_score=0.8,  # High impact - supply chain risks are serious
            remediation=remediation,
            references=references,
            metadata=metadata
        )


class PackageHallucinationDetector:
    """Main detector class for package hallucination analysis."""
    
    def __init__(self, project_path: str):
        """Initialize detector with project path."""
        self.project_path = Path(project_path)
        self.validator = PackageRegistryValidator()
        self.extractor = ASTPackageExtractor()
        self.finding_creator = HallucinationFindingCreator()
    
    def analyze_file(self, file_path: str) -> List:
        """Analyze single file for package hallucination."""
        findings = []
        
        if not file_path.endswith('.py'):
            return findings
        
        try:
            imports = self.extractor.extract_imports(file_path)
            
            for package_name, line_number, import_type in imports:
                result = self.validator.validate_package(package_name, 'python')
                if not result.exists:
                    finding = self.finding_creator.create_hallucination_finding(
                        package_name, file_path, line_number, 'python', 
                        import_type, result.error_message
                    )
                    findings.append(finding)
        
        except (SyntaxError, UnicodeDecodeError) as e:
            # Create finding for unparseable files
            error_finding = FindingFactory.create_analysis_error(
                finding_id=f"package_parse_error_{hash(file_path)}",
                file_path=file_path,
                title="Package Analysis Parse Error",
                description=f"Could not parse file for import analysis: {str(e)}",
                detected_by="package_hallucination_detector"
            )
            findings.append(error_finding)
        
        return findings