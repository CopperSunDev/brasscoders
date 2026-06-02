"""
Main API Security Scanner for New BrassCoders System v2.0.

Orchestrates AI-aware API security analysis using specialized analyzers:
- Package hallucination detection
- Authentication anti-pattern analysis  
- Input validation vulnerability scanning

Refactored for CLAUDE.md compliance with clean architecture.
"""

from pathlib import Path
from typing import List, Optional

from ...core.file_classifier import FileClassifier
from ...core.logging_config import get_logger
from .utils import ConfigLoader, FileUtils
from .package_hallucination import PackageHallucinationDetector
from .auth_patterns import AIAuthPatternAnalyzer
from .input_validation import APIInputValidationAnalyzer

logger = get_logger(__name__)


class FileDiscovery:
    """Handles API-related file discovery with configuration support."""
    
    def __init__(self, project_path: str):
        """Initialize file discovery for project."""
        self.project_path = Path(project_path)
        self.config = ConfigLoader.get_config()
    
    def discover_api_files(self) -> List[str]:
        """Discover files relevant for API analysis."""
        api_files = []
        file_config = self.config.get('api_security', {}).get('file_types', {})
        
        # Python API files
        if file_config.get('analyze_python', True):
            api_files.extend(self._find_python_files())
        
        # JavaScript/TypeScript API files
        if file_config.get('analyze_javascript', True):
            api_files.extend(self._find_js_files())
        
        if file_config.get('analyze_typescript', True):
            api_files.extend(self._find_ts_files())
        
        # Configuration files
        if file_config.get('analyze_config_files', True):
            api_files.extend(self._find_config_files())
        
        return api_files
    
    def _find_python_files(self) -> List[str]:
        """Find Python files for analysis."""
        from brass.core.path_safety import is_within
        python_files = []
        for py_file in self.project_path.rglob('*.py'):
            if not is_within(py_file, self.project_path):
                continue
            if FileUtils.should_analyze_file(str(py_file)):
                python_files.append(str(py_file))
        return python_files

    def _find_js_files(self) -> List[str]:
        """Find JavaScript files for analysis."""
        from brass.core.path_safety import is_within
        js_files = []
        for js_file in self.project_path.rglob('*.js'):
            if not is_within(js_file, self.project_path):
                continue
            if FileUtils.should_analyze_file(str(js_file)):
                js_files.append(str(js_file))
        return js_files

    def _find_ts_files(self) -> List[str]:
        """Find TypeScript files for analysis."""
        from brass.core.path_safety import is_within
        ts_files = []
        for ts_file in self.project_path.rglob('*.ts'):
            if not is_within(ts_file, self.project_path):
                continue
            if FileUtils.should_analyze_file(str(ts_file)):
                ts_files.append(str(ts_file))
        return ts_files
    
    def _find_config_files(self) -> List[str]:
        """Find configuration files for analysis."""
        config_files = []
        config_patterns = ['package.json', 'requirements.txt', 'go.mod']
        
        for pattern in config_patterns:
            config_path = self.project_path / pattern
            if config_path.exists():
                config_files.append(str(config_path))
        
        return config_files


class AnalysisOrchestrator:
    """Orchestrates analysis across multiple specialized analyzers."""
    
    def __init__(self, project_path: str):
        """Initialize orchestrator with analyzers."""
        self.project_path = project_path
        self.file_classifier = FileClassifier(project_path)
        
        # Initialize specialized analyzers
        self.package_detector = PackageHallucinationDetector(project_path)
        self.auth_analyzer = AIAuthPatternAnalyzer(project_path)
        self.input_analyzer = APIInputValidationAnalyzer(project_path)
    
    def analyze_files(self, file_paths: List[str]) -> List:
        """Run all analyzers on specified files."""
        all_findings = []
        
        logger.info(f"Analyzing {len(file_paths)} files for API security issues")
        
        for file_path in file_paths:
            if not FileUtils.should_analyze_file(file_path):
                continue
            
            try:
                file_findings = self._analyze_single_file(file_path)
                
                # Add file classification context to findings
                for finding in file_findings:
                    file_context = self.file_classifier.classify_file(file_path)
                    finding.metadata['file_context'] = file_context
                
                all_findings.extend(file_findings)
                
            except Exception as e:
                logger.warning(f"API analysis failed for {file_path}: {e}")
                error_finding = self._create_analysis_error(file_path, str(e))
                all_findings.append(error_finding)
        
        return all_findings
    
    def _analyze_single_file(self, file_path: str) -> List:
        """Analyze single file with all enabled analyzers."""
        findings = []
        
        # Package hallucination detection (high priority for supply chain security)
        if self._is_analyzer_enabled('package_validation'):
            findings.extend(self.package_detector.analyze_file(file_path))
        
        # Authentication pattern analysis
        if self._is_analyzer_enabled('authentication'):
            findings.extend(self.auth_analyzer.analyze_file(file_path))
        
        # Input validation analysis
        if self._is_analyzer_enabled('input_validation'):
            findings.extend(self.input_analyzer.analyze_file(file_path))
        
        return findings
    
    def _is_analyzer_enabled(self, analyzer_type: str) -> bool:
        """Check if specific analyzer is enabled in configuration."""
        config = ConfigLoader.get_config()
        analyzer_config = config.get('api_security', {}).get(analyzer_type, {})
        return analyzer_config.get('enabled', True)
    
    def _create_analysis_error(self, file_path: str, error_message: str):
        """Create standardized analysis error finding."""
        from .utils import FindingFactory
        
        return FindingFactory.create_analysis_error(
            finding_id=f"api_analysis_error_{hash(file_path)}",
            file_path=file_path,
            title="API Analysis Error",
            description=f"Failed to analyze file for API security issues: {error_message}",
            detected_by="api_security_scanner"
        )


class APISecurityScanner:
    """
    Main API Security Scanner class - refactored for CLAUDE.md compliance.
    
    Provides AI-aware API security analysis through specialized analyzers
    while maintaining clean architecture and single responsibility.
    """
    
    def __init__(self, project_path: str):
        """Initialize API Security Scanner."""
        self.project_path = Path(project_path)
        
        # Initialize orchestration components
        self.file_discovery = FileDiscovery(project_path)
        self.orchestrator = AnalysisOrchestrator(project_path)
        
        logger.info(f"API Security Scanner initialized for {project_path}")
    
    def scan(self, file_paths: Optional[List[str]] = None) -> List:
        """
        Perform AI-aware API security analysis.
        
        Args:
            file_paths: Optional list of specific files to scan.
                       If None, scans all relevant files in project.
        
        Returns:
            List of Finding objects representing detected API security issues
        """
        if file_paths is None:
            file_paths = self.file_discovery.discover_api_files()
        
        findings = self.orchestrator.analyze_files(file_paths)
        
        logger.info(f"API Security Scanner found {len(findings)} findings")
        return findings