"""
JavaScriptTypeScriptScanner - Unified scanner for JavaScript and TypeScript analysis.

This component uses Babel parser via Node.js subprocess to analyze JS/TS files for:
- Security vulnerabilities (XSS, eval usage, hardcoded secrets)
- Code quality issues (complexity, function size, parameters)
- Performance patterns and optimization opportunities
- TODO/FIXME comments and technical debt

Follows the established scanner pattern with comprehensive error handling.
"""

import json
import os
import subprocess
import hashlib
from pathlib import Path
from typing import List, Optional, Dict, Any, Union
from datetime import datetime

from brass.models.finding import Finding, FindingType, Severity
from brass.core.file_classifier import FileClassifier
from brass.core.logging_config import get_logger
from brass.core.error_handling import handle_analysis_error, safe_file_operation

logger = get_logger(__name__)

# Configuration constants
MAX_FILE_SIZE_BYTES = 1024 * 1024  # 1MB - Skip files larger than this
MAX_FILES_PER_BATCH = 20  # Process files in batches for performance
BABEL_TIMEOUT_SECONDS = 30  # Timeout for Babel subprocess
DEFAULT_CONFIDENCE = 0.95  # High confidence for AST-based analysis
MAX_JSON_SIZE_BYTES = 10 * 1024 * 1024  # 10MB - Maximum JSON output size from Babel

class JavaScriptTypeScriptScanner:
    """
    Unified scanner for JavaScript and TypeScript ecosystems.
    
    Analyzes all JS/TS file types (.js, .jsx, .ts, .tsx, .mjs, .cjs) using
    Babel parser for AST-based pattern detection and quality analysis.
    
    Features:
    - Security pattern detection (XSS, eval, secrets)
    - Code quality analysis (complexity, function size)
    - Performance optimization opportunities
    - TODO/FIXME technical debt tracking
    - Context-aware analysis with file classification
    
    Example:
        scanner = JavaScriptTypeScriptScanner("/path/to/project")
        findings = scanner.scan()
        print(f"Found {len(findings)} JS/TS issues")
    """
    
    def __init__(self, project_path: str) -> None:
        """
        Initialize JavaScript/TypeScript scanner.
        
        Args:
            project_path: Root path of project to analyze
            
        Raises:
            ValueError: If project_path is empty or None
            FileNotFoundError: If project_path does not exist
        """
        # Enhanced input validation following established pattern
        if not project_path:
            raise ValueError("Project path cannot be empty or None")
        
        # Resolve and validate path
        self.project_path = Path(project_path).resolve()
        if not self.project_path.exists():
            raise FileNotFoundError(f"Project path does not exist: {self.project_path}")
        
        # JavaScript/TypeScript file extensions
        self.js_ts_extensions = {
            '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'
        }
        
        # Standard exclude patterns for performance
        self.exclude_patterns = {
            '.git', '.svn', '.hg', '__pycache__', '.pytest_cache',
            'node_modules', '.venv', 'venv', '.env', 'build', 'dist',
            '.brass', '.idea', '.vscode', '.DS_Store', 'coverage',
            '.nyc_output', 'htmlcov', '.coverage', '.next', '.nuxt',
            # JS/TS specific excludes
            'bower_components', 'jspm_packages', '.webpack', '.parcel-cache',
            'public', 'static', 'assets', '.cache', '.tmp', 'temp',
            # Analysis artifacts
            '.brass_test', 'analysis_data.json', '*.min.js', '*.bundle.js',
            # AI-agent scratch space. Claude Code uses .claude/worktrees/
            # for parallel-agent git worktrees; .claude/ also holds agent
            # config (commands, skills, settings). None of it is customer
            # source. Identified by the whisperx-production triage.
            '.claude',
        }
        
        # Initialize file classifier for context awareness
        self.file_classifier = FileClassifier(str(self.project_path))
        
        # Locate Babel parser script
        self.babel_script_path = self._locate_babel_script()
        
        # Validate Node.js and Babel availability
        self._validate_dependencies()
        
        logger.info(f"JavaScriptTypeScriptScanner initialized for {self.project_path}")
        logger.info(f"Babel script located at: {self.babel_script_path}")
    
    def _should_exclude_path(self, path: Path) -> bool:
        """
        Check if a path should be excluded from analysis using Path-based matching.
        
        Args:
            path: Path object to check
            
        Returns:
            True if path should be excluded, False otherwise
        """
        # Convert to relative path for pattern matching
        try:
            relative_path = path.relative_to(self.project_path)
        except ValueError:
            # Path outside project - exclude it
            return True
        
        # Check each part of the path against exclude patterns
        path_parts = relative_path.parts
        for part in path_parts:
            if part in self.exclude_patterns:
                return True
        
        # Check for pattern-based exclusions (e.g., *.min.js)
        file_name = path.name
        if file_name.endswith('.min.js') or file_name.endswith('.bundle.js'):
            return True
        
        return False
    
    def _locate_babel_script(self) -> Path:
        """
        Locate the Babel parser script.
        
        Returns:
            Path to babel_parser.js script
            
        Raises:
            FileNotFoundError: If Babel script cannot be found
        """
        # Primary location (relative to this scanner file)
        scanner_dir = Path(__file__).parent
        babel_script = scanner_dir.parent / "js_analysis" / "babel_parser.js"
        
        if babel_script.exists():
            return babel_script
        
        # Fallback location (project relative)
        babel_script = self.project_path / "src" / "brass" / "js_analysis" / "babel_parser.js"
        
        if babel_script.exists():
            return babel_script
            
        raise FileNotFoundError(
            f"Babel parser script not found. Expected at: {babel_script}"
        )
    
    def _validate_dependencies(self) -> None:
        """
        Validate Node.js and Babel dependencies are available.
        
        Raises:
            RuntimeError: If required dependencies are missing
        """
        try:
            # Check Node.js availability
            result = subprocess.run(
                ['node', '--version'], 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            if result.returncode != 0:
                raise RuntimeError("Node.js is not available or not working")
            
            logger.info(f"Node.js version: {result.stdout.strip()}")
            
            # Verify Babel script is executable
            if not self.babel_script_path.exists():
                raise RuntimeError(f"Babel script not found: {self.babel_script_path}")
            
            # Test Babel script basic functionality
            test_result = subprocess.run(
                ['node', str(self.babel_script_path)],
                input='', 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            # Script should fail with usage message (exit code 1) when no files provided
            if test_result.returncode != 1:
                logger.warning("Babel script test returned unexpected exit code")
            
        except subprocess.TimeoutExpired:
            raise RuntimeError("Node.js dependency check timed out")
        except FileNotFoundError:
            raise RuntimeError("Node.js is not installed or not in PATH")
        except Exception as e:
            raise RuntimeError(f"Dependency validation failed: {e}")
    
    def scan(self, file_paths: Optional[List[str]] = None) -> List[Finding]:
        """
        Scan JavaScript/TypeScript files for security and quality issues.
        
        Args:
            file_paths: Specific files to scan, or None for auto-discovery
            
        Returns:
            List of Finding objects representing detected issues
        """
        findings = []
        
        try:
            # Discover JS/TS files if not provided
            if file_paths is None:
                file_paths = self._discover_js_ts_files()
            else:
                # Caller-provided list: filter to JS/TS extensions before
                # handing files to Babel. Without this filter, the upstream
                # orchestrator passes ALL prefilter-selected files (including
                # .py, .md, .json, .yml, .html, etc.) and Babel emits a
                # "Parse Error" finding for each non-JS file. Discovered
                # 2026-05-21: 46 false-positive analysis_error findings on
                # a whisperx scan tracked back to Babel parsing the
                # project's .py and .md files.
                file_paths = [
                    fp for fp in file_paths
                    if Path(fp).suffix.lower() in self.js_ts_extensions
                ]

            if not file_paths:
                logger.info("No JavaScript/TypeScript files found to analyze")
                return findings

            logger.info(f"Scanning {len(file_paths)} JS/TS files")
            
            # Process files in batches for performance
            for batch_start in range(0, len(file_paths), MAX_FILES_PER_BATCH):
                batch_end = min(batch_start + MAX_FILES_PER_BATCH, len(file_paths))
                batch_files = file_paths[batch_start:batch_end]
                
                try:
                    batch_findings = self._analyze_file_batch(batch_files)
                    findings.extend(batch_findings)
                except Exception as e:
                    # Handle batch errors gracefully. Emitting one error
                    # finding per file in the batch (up to 20) was producing
                    # 20 nearly-identical entries from a single transient
                    # Babel crash, polluting both the YAML and the
                    # severity-weighted total. One representative error is
                    # enough; ``handle_analysis_error`` already logs the
                    # underlying cause.
                    handle_analysis_error(
                        "JS/TS batch analysis", "JavaScriptTypeScriptScanner",
                        "analyze_batch", e, f"batch {batch_start}-{batch_end}"
                    )
                    findings.append(self._create_analysis_error_finding(
                        batch_files[0] if batch_files else 'batch', str(e)
                    ))
            
            logger.info(f"JavaScript/TypeScript scan complete: {len(findings)} issues found")
            return findings
            
        except Exception as e:
            logger.error(f"JavaScript/TypeScript scan failed: {e}")
            handle_analysis_error(
                "JS/TS scan", "JavaScriptTypeScriptScanner", "scan", e, str(self.project_path)
            )
            return findings
    
    def _discover_js_ts_files(self) -> List[str]:
        """
        Discover all JavaScript/TypeScript files in the project.
        
        Returns:
            List of relative file paths suitable for analysis
        """
        js_ts_files = []
        
        try:
            # Search for files with JS/TS extensions
            from brass.core.path_safety import is_within
            for extension in self.js_ts_extensions:
                pattern = f"**/*{extension}"
                for path in self.project_path.glob(pattern):
                    # Project-root containment first — glob follows symlinks
                    # by default, so a hostile symlink could otherwise feed
                    # the user's home directory into Babel and into findings
                    # whose ``file_path`` is then serialized to YAML.
                    if not is_within(path, self.project_path):
                        continue
                    # Skip excluded directories and files using Path-based matching
                    if self._should_exclude_path(path):
                        continue

                    # Skip very large files for performance
                    try:
                        if path.stat().st_size > MAX_FILE_SIZE_BYTES:
                            logger.info(f"Skipping large file: {path}")
                            continue
                    except OSError:
                        continue  # Skip files with access issues

                    # Return relative path
                    try:
                        relative_path = str(path.relative_to(self.project_path))
                        js_ts_files.append(relative_path)
                    except ValueError:
                        # Skip if path is not relative to project
                        continue
            
            logger.info(f"Discovered {len(js_ts_files)} JS/TS files")
            return js_ts_files
            
        except Exception as e:
            logger.error(f"JS/TS file discovery failed: {e}")
            handle_analysis_error(
                "file discovery", "JavaScriptTypeScriptScanner", "discover_files", 
                e, str(self.project_path)
            )
            return []
    
    def _analyze_file_batch(self, file_paths: List[str]) -> List[Finding]:
        """
        Analyze a batch of JS/TS files using Babel parser.
        
        Args:
            file_paths: List of relative file paths to analyze
            
        Returns:
            List of findings from the batch
        """
        findings = []
        
        try:
            # Convert relative paths to absolute paths for Babel
            absolute_paths = [
                str(self.project_path / file_path) 
                for file_path in file_paths
            ]
            
            # Execute Babel parser script in a sandboxed env. Node honors
            # NODE_OPTIONS, NODE_PATH, NPM_CONFIG_*; a malicious project's
            # env or .npmrc could otherwise hijack the runtime via, e.g.,
            # NODE_OPTIONS='--require ./malicious.js'. We strip those and
            # provide only PATH/HOME/locale.
            sandboxed_env = {
                'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
                'HOME': os.environ.get('HOME', '/tmp'),
                'LANG': 'C',
                'LC_ALL': 'C',
            }
            cmd = ['node', str(self.babel_script_path)] + absolute_paths

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=BABEL_TIMEOUT_SECONDS,
                cwd=str(self.project_path),
                env=sandboxed_env,
            )
            
            if result.returncode != 0:
                logger.error(f"Babel parser failed: {result.stderr}")
                raise RuntimeError(f"Babel analysis failed: {result.stderr}")
            
            # Parse JSON output from Babel script
            # First check JSON size to prevent memory issues
            if len(result.stdout) > MAX_JSON_SIZE_BYTES:
                raise RuntimeError(f"Babel output too large: {len(result.stdout)} bytes (max: {MAX_JSON_SIZE_BYTES})")
            
            try:
                babel_results = json.loads(result.stdout)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Babel output: {e}")
                logger.error(f"Babel stdout: {result.stdout[:500]}")
                raise RuntimeError(f"Invalid JSON from Babel parser: {e}")
            
            # Convert Babel results to Finding objects
            for babel_result in babel_results:
                file_findings = self._babel_result_to_findings(babel_result)
                
                # Add file context to each finding
                enhanced_findings = []
                for finding in file_findings:
                    enhanced_finding = self._add_file_context_to_finding(finding)
                    enhanced_findings.append(enhanced_finding)
                
                findings.extend(enhanced_findings)
            
            return findings
            
        except subprocess.TimeoutExpired:
            error_msg = f"Babel analysis timed out after {BABEL_TIMEOUT_SECONDS}s"
            logger.error(error_msg)
            raise RuntimeError(error_msg)
        except Exception as e:
            logger.error(f"Batch analysis failed: {e}")
            raise
    
    def _babel_result_to_findings(self, babel_result: Dict[str, Any]) -> List[Finding]:
        """
        Convert Babel parser result to Finding objects.
        
        Args:
            babel_result: JSON result from Babel parser
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        # Handle parse errors
        if not babel_result.get('success', False):
            return [self._create_parse_error_finding(babel_result)]
        
        # Convert patterns to findings
        for pattern in babel_result.get('patterns', []):
            finding = self._pattern_to_finding(babel_result['file'], pattern)
            if finding:
                findings.append(finding)
        
        return findings
    
    def _pattern_to_finding(self, file_path: str, pattern: Dict[str, Any]) -> Optional[Finding]:
        """
        Convert a Babel pattern to a Finding object.
        
        Args:
            file_path: Absolute path to the analyzed file
            pattern: Pattern data from Babel parser
            
        Returns:
            Finding object or None if pattern should be filtered
        """
        try:
            # Convert absolute path back to relative
            try:
                relative_path = str(Path(file_path).relative_to(self.project_path))
            except ValueError:
                # File outside project root - use filename only for security
                relative_path = Path(file_path).name
                logger.warning(f"File outside project root: {file_path}, using filename only")
            
            # Map pattern type to FindingType
            finding_type_map = {
                'security': FindingType.SECURITY,
                'quality': FindingType.CODE_QUALITY,
                'performance': FindingType.PERFORMANCE,
                'todo': FindingType.TODO
            }
            
            finding_type = finding_type_map.get(pattern['type'], FindingType.CODE_QUALITY)
            
            # Map severity
            severity_map = {
                'critical': Severity.CRITICAL,
                'high': Severity.HIGH,
                'medium': Severity.MEDIUM,
                'low': Severity.LOW,
                'info': Severity.INFO
            }
            
            severity = severity_map.get(pattern['severity'], Severity.MEDIUM)

            # Test-context downgrade: a hardcoded password in
            # ``e2e/tests/login.spec.ts`` is almost certainly a fixture, not a
            # real credential. Downgrade severity by one rung when we can prove
            # the path is test-related, mirroring what Brass2PrivacyScanner does
            # for Python source. Real production-source findings keep their
            # severity.
            test_context = self._is_test_path(relative_path)
            if test_context and pattern['type'] == 'security':
                severity = self._downgrade_severity(severity)

            # Generate unique ID
            finding_id = self._generate_finding_id(
                relative_path, pattern['pattern'], pattern['line']
            )

            # Bound and (for secret-leak patterns) redact the snippet that
            # Babel returns. Hardcoded-credential patterns surface the
            # literal value verbatim; persisting that into ``.brass/`` would
            # be the same kind of leak the Phase 0 audit closed for the
            # Python auth analyzer.
            raw_snippet = pattern.get('code', '').strip()
            code_snippet = self._sanitize_code_snippet(raw_snippet, pattern['pattern'])

            finding = Finding(
                id=finding_id,
                type=finding_type,
                severity=severity,
                file_path=relative_path,
                line_number=pattern.get('line'),
                column=pattern.get('column'),
                title=f"JS/TS {pattern['type'].title()}: {pattern['pattern']}",
                description=pattern.get('message', f"Detected {pattern['pattern']}"),
                code_snippet=code_snippet,
                confidence=DEFAULT_CONFIDENCE,
                impact_score=self._calculate_impact_score(severity),
                detected_by="JavaScriptTypeScriptScanner",
                remediation=self._get_remediation_advice(pattern),
                metadata={
                    'pattern_type': pattern['pattern'],
                    'language': self._detect_language(relative_path),
                    'analysis_engine': 'babel',
                    'pattern_category': pattern['type'],
                    'babel_pattern': pattern.get('pattern', 'unknown'),
                    'test_context': test_context,
                }
            )
            
            return finding
            
        except Exception as e:
            logger.error(f"Failed to convert pattern to finding: {e}")
            logger.error(f"Pattern data: {pattern}")
            return None
    
    def _create_parse_error_finding(self, babel_result: Dict[str, Any]) -> Finding:
        """
        Create finding for Babel parse errors.
        
        Args:
            babel_result: Failed Babel result
            
        Returns:
            Finding representing the parse error
        """
        try:
            relative_path = str(Path(babel_result['file']).relative_to(self.project_path))
        except ValueError:
            # File outside project root - use filename only for security
            relative_path = Path(babel_result['file']).name
            logger.warning(f"Parse error file outside project root: {babel_result['file']}")
        
        error_info = babel_result.get('errors', [{}])[0] if babel_result.get('errors') else {}
        
        return Finding(
            id=self._generate_finding_id(relative_path, "parse_error", 
                                       error_info.get('line', 0)),
            type=FindingType.ANALYSIS_ERROR,
            severity=Severity.MEDIUM,
            file_path=relative_path,
            line_number=error_info.get('line'),
            column=error_info.get('column'),
            title="JavaScript/TypeScript Parse Error",
            description=f"Failed to parse file: {error_info.get('message', 'Unknown error')}",
            confidence=1.0,
            impact_score=0.3,
            detected_by="JavaScriptTypeScriptScanner",
            remediation="Fix syntax errors in the file",
            metadata={
                'error_type': 'parse_error',
                'language': self._detect_language(relative_path),
                'analysis_engine': 'babel'
            }
        )
    
    def _create_analysis_error_finding(self, file_path: str, error_msg: str) -> Finding:
        """
        Create finding for general analysis errors.
        
        Args:
            file_path: Path to file that caused error
            error_msg: Error message
            
        Returns:
            Finding representing the analysis error
        """
        return Finding(
            id=self._generate_finding_id(file_path, "analysis_error", 0),
            type=FindingType.ANALYSIS_ERROR,
            severity=Severity.LOW,
            file_path=file_path,
            title="JS/TS Analysis Error",
            description=f"Failed to analyze file: {error_msg}",
            confidence=1.0,
            impact_score=0.1,
            detected_by="JavaScriptTypeScriptScanner",
            remediation="Check file accessibility and syntax",
            metadata={
                "error_type": "analysis_error",
                "error_msg": error_msg,
                "language": self._detect_language(file_path)
            }
        )
    
    def _add_file_context_to_finding(self, finding: Finding) -> Finding:
        """
        Add file classification context to finding for intelligent prioritization.
        
        Args:
            finding: Original finding to enhance
            
        Returns:
            Finding with file context added to metadata
        """
        from dataclasses import replace as _replace
        file_context = self.file_classifier.classify_file(finding.file_path)

        # Build a new metadata dict and return a new Finding rather than
        # mutating the input in place — IntelligenceRanker and the rest of
        # the pipeline treat Findings as immutable, and shared dict
        # references would cause spooky-action-at-a-distance.
        new_metadata = dict(finding.metadata or {})
        new_metadata['file_context'] = {
            'file_type': file_context.file_type.value,
            'confidence': file_context.confidence,
            'intended_for_issues': file_context.intended_for_issues,
            'priority_weight': file_context.priority_weight,
            'classification_reason': file_context.classification_reason,
            'is_source_code': file_context.is_source_code(),
            'is_test_related': file_context.is_test_related(),
            'should_prioritize': file_context.should_prioritize_issues()
        }
        return _replace(finding, metadata=new_metadata)
    
    def _detect_language(self, file_path: str) -> str:
        """
        Detect specific language (JavaScript vs TypeScript) from file extension.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Language identifier
        """
        ext = Path(file_path).suffix.lower()
        if ext in {'.ts', '.tsx'}:
            return 'typescript'
        elif ext in {'.jsx'}:
            return 'jsx'
        else:
            return 'javascript'
    
    def _get_remediation_advice(self, pattern: Dict[str, Any]) -> str:
        """
        Get specific remediation advice for detected patterns.
        
        Args:
            pattern: Pattern data from Babel
            
        Returns:
            Remediation advice string
        """
        remediation_map = {
            'dangerous_eval': 'Replace eval() with safer alternatives like JSON.parse() or Function constructor',
            'innerHTML_usage': 'Use textContent or sanitize HTML input to prevent XSS',
            'document_write': 'Use modern DOM manipulation methods instead of document.write()',
            'potential_api_key': 'Move API keys to environment variables or secure configuration',
            'hardcoded_password': 'Store passwords in environment variables or secure vaults',
            'large_function': 'Break large function into smaller, focused functions',
            'too_many_parameters': 'Use parameter objects or reduce function complexity',
            'todo_comment': 'Address TODO item or convert to tracked issue',
            'fixme_comment': 'Fix the identified issue',
            'hack_comment': 'Replace hack with proper implementation'
        }
        
        return remediation_map.get(pattern.get('pattern', ''), 
                                 f"Review and address {pattern.get('pattern', 'issue')}")
    
    # Path components that mark a file as test/fixture context for the purposes
    # of severity downgrade. Mirrors brass2_privacy_scanner.FileContextAnalyzer's
    # whole-component matching strategy — substring matching ``test`` would
    # over-match on names like ``contest.ts`` or ``request.ts``.
    _TEST_DIR_COMPONENTS = frozenset({
        'tests', 'test', 'spec', 'specs', '__tests__', 'e2e', 'fixtures',
        'mocks', '__mocks__', 'cypress', 'playwright',
    })
    _TEST_FILENAME_PREFIXES = ('test_', 'test.')
    _TEST_FILENAME_SUFFIXES = (
        '.test.js', '.test.jsx', '.test.ts', '.test.tsx', '.test.mjs', '.test.cjs',
        '.spec.js', '.spec.jsx', '.spec.ts', '.spec.tsx', '.spec.mjs', '.spec.cjs',
        '_test.js', '_spec.js', '_test.ts', '_spec.ts',
    )

    def _is_test_path(self, relative_path: str) -> bool:
        """True if ``relative_path`` is plausibly a test/fixture file."""
        from pathlib import PurePosixPath
        path = PurePosixPath(relative_path.replace('\\', '/'))
        if {p.lower() for p in path.parts} & self._TEST_DIR_COMPONENTS:
            return True
        name = path.name.lower()
        if any(name.startswith(p) for p in self._TEST_FILENAME_PREFIXES):
            return True
        if any(name.endswith(s) for s in self._TEST_FILENAME_SUFFIXES):
            return True
        return False

    @staticmethod
    def _downgrade_severity(severity: Severity) -> Severity:
        """Drop one severity rung, never below LOW."""
        ladder = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        try:
            idx = ladder.index(severity)
        except ValueError:
            return severity
        return ladder[min(idx + 1, len(ladder) - 1)]

    # Babel pattern names that flag a literal credential. Their `code`
    # field will contain the credential itself; redact before serializing.
    _SECRET_LEAK_PATTERNS = frozenset({
        'hardcoded_password', 'hardcoded-password', 'hardcoded_secret',
        'hardcoded-secret', 'api_key', 'api-key', 'jwt_secret',
        'access_token', 'access-token', 'bearer_token',
    })
    _MAX_SNIPPET_LEN = 200

    @classmethod
    def _sanitize_code_snippet(cls, snippet: str, pattern_name: str) -> str:
        """Bound length, and for secret-leak patterns mask quoted values.

        Mirrors ``api_security_scanner._truncate_snippet`` and
        ``_redact_secret_in_line``. We never want a credential pattern's
        literal match to land verbatim in ``.brass/*.yaml``.
        """
        if not snippet:
            return snippet
        if pattern_name in cls._SECRET_LEAK_PATTERNS:
            import re as _re
            snippet = _re.sub(r'(["\'])([^"\']+)(["\'])', r'\1<REDACTED>\3', snippet)
        if len(snippet) > cls._MAX_SNIPPET_LEN:
            snippet = snippet[:cls._MAX_SNIPPET_LEN] + "…"
        return snippet

    def _calculate_impact_score(self, severity: Severity) -> float:
        """
        Calculate impact score based on severity level.
        
        Args:
            severity: Severity level
            
        Returns:
            Impact score between 0.0 and 1.0
        """
        impact_mapping = {
            Severity.CRITICAL: 0.95,
            Severity.HIGH: 0.8,
            Severity.MEDIUM: 0.6,
            Severity.LOW: 0.4,
            Severity.INFO: 0.2
        }
        
        return impact_mapping.get(severity, 0.6)
    
    def _generate_finding_id(self, file_path: str, pattern: str, line: int) -> str:
        """
        Generate unique finding ID.
        
        Args:
            file_path: Path to the file
            pattern: Pattern name
            line: Line number
            
        Returns:
            Unique finding identifier
        """
        content = f"{file_path}:{pattern}:{line}"
        hash_suffix = hashlib.md5(content.encode(), usedforsecurity=False).hexdigest()[:8]
        return f"js_ts_{hash_suffix}"