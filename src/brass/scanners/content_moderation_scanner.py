"""
ContentModerationScanner - Detects profanity and inappropriate content in code and comments.

This component scans text files for profanity, hate speech, and unprofessional language
that may impact team collaboration and professional standards.
"""

import re
import yaml
import hashlib
from pathlib import Path
from typing import List, Optional, Set, Dict, Any, Pattern, Union
from datetime import datetime

from brass.models.finding import Finding, FindingType, Severity
from brass.core.file_classifier import FileClassifier
from brass.core.logging_config import get_logger
from brass.core.error_handling import handle_analysis_error, safe_file_operation

logger = get_logger(__name__)

# Configuration constants for performance and behavior tuning
MAX_FILE_SIZE_BYTES = 1024 * 1024  # 1MB - Skip files larger than this for performance
DEFAULT_PATTERN_CONFIDENCE = 0.95  # High confidence for regex-based pattern matches
TEST_FILE_CONFIDENCE_MULTIPLIER = 0.8  # Reduce confidence for test context
EXAMPLE_FILE_CONFIDENCE_MULTIPLIER = 0.6  # Reduce confidence for example files
DOCS_FILE_CONFIDENCE_MULTIPLIER = 0.7  # Reduce confidence for documentation
DEFAULT_SEVERITY_FALLBACK = 'medium'  # Fallback severity when not specified


class ContentModerationScanner:
    """
    Content moderation scanner for detecting profanity and inappropriate language.
    
    Analyzes text files to detect:
    - Hate speech indicators
    - Explicit profanity
    - Unprofessional language
    - Casual abbreviations in professional contexts
    
    Uses context-aware detection to reduce false positives in test files.
    """
    
    def __init__(self, project_path: str) -> None:
        """
        Initialize ContentModerationScanner.
        
        Args:
            project_path: Root path of project to analyze
            
        Raises:
            ValueError: If project_path is empty or None
            FileNotFoundError: If project_path does not exist
        """
        # Enhanced input validation
        if not project_path:
            raise ValueError("Project path cannot be empty or None")
        
        # Resolve and validate path
        self.project_path = Path(project_path).resolve()
        if not self.project_path.exists():
            raise FileNotFoundError(f"Project path does not exist: {self.project_path}")
        
        # Standard exclude patterns for professional development
        self.exclude_patterns = {
            '.git', '.svn', '.hg', '__pycache__', '.pytest_cache',
            'node_modules', '.venv', 'venv', '.env', 'build', 'dist',
            '.brass', '.idea', '.vscode', '.DS_Store', 'coverage',
            'archive', 'build_env', 'site-packages', 'backup',
            '.nyc_output', 'htmlcov', '.coverage',
            # Analysis artifacts and test contamination prevention
            '.brass_test', 'analysis_data.json', 'detailed_analysis.yaml',
            'ai_instructions.yaml', 'privacy_analysis.yaml', 'security_report.yaml',
            'file_intelligence.yaml', 'statistics.yaml', '_analysis.yaml',
            'test_output', 'temp_analysis', '.analysis_cache'
        }
        
        # File extensions to scan for content moderation
        self.scannable_extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.cpp', '.c', '.h',
            '.cs', '.php', '.rb', '.go', '.rs', '.kt', '.swift', '.scala',
            '.md', '.txt', '.rst', '.yml', '.yaml', '.json', '.xml',
            '.html', '.css', '.sh', '.bash', '.ps1', '.sql', '.r'
        }
        
        # Initialize file classifier for intelligent context awareness
        self.file_classifier = FileClassifier(str(self.project_path))
        
        # Load profanity patterns from configuration
        self.profanity_patterns = self._load_profanity_patterns()
        
        # Performance optimization: Cache compiled regex patterns  
        self._compiled_patterns_cache: Dict[str, Optional[Pattern[str]]] = {}
        self._compile_all_patterns()
        
        logger.info(f"ContentModerationScanner initialized for {self.project_path}")
        logger.info(f"Loaded {len(self.profanity_patterns)} profanity pattern categories")
    
    def _load_profanity_patterns(self) -> Dict[str, Dict[str, Any]]:
        """
        Load profanity patterns from patterns.yaml configuration file.
        
        Returns:
            Dictionary of profanity patterns with metadata
        """
        # Locate patterns file
        patterns_file = self._locate_patterns_file()
        if not patterns_file:
            return self._get_fallback_patterns()
        
        # Load patterns from file
        try:
            patterns = self._parse_patterns_file(patterns_file)
            logger.info(f"Successfully loaded profanity patterns from {patterns_file}")
            return patterns
        except Exception as e:
            logger.error(f"Failed to load patterns from {patterns_file}: {e}")
            return self._get_fallback_patterns()
    
    def _locate_patterns_file(self) -> Optional[Path]:
        """
        Locate the patterns.yaml file using multiple search paths.
        
        Returns:
            Path to patterns file or None if not found
        """
        # Primary location (neutral config directory)
        patterns_file = self.project_path / "src" / "brass" / "config" / "patterns.yaml"
        if patterns_file.exists():
            return patterns_file
        
        # Fallback location (relative to scanner file)
        scanner_dir = Path(__file__).parent
        patterns_file = scanner_dir.parent / "config" / "patterns.yaml"
        if patterns_file.exists():
            return patterns_file
        
        logger.warning("Patterns file not found in any search path")
        return None
    
    def _parse_patterns_file(self, patterns_file: Path) -> Dict[str, Dict[str, Any]]:
        """
        Parse patterns from YAML file using safe file operations.
        
        Args:
            patterns_file: Path to the patterns.yaml file
            
        Returns:
            Dictionary of profanity patterns
            
        Raises:
            yaml.YAMLError: If YAML parsing fails
        """
        def load_patterns() -> Dict[str, Dict[str, Any]]:
            with open(patterns_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                return data.get('profanity_patterns', {})
        
        return safe_file_operation(
            str(patterns_file), load_patterns, "ContentModerationScanner", 
            "load_patterns", {}
        )
    
    def _get_fallback_patterns(self) -> Dict[str, Dict[str, Any]]:
        """
        Provide minimal hardcoded patterns as fallback.
        
        Returns:
            Dictionary of basic profanity patterns
        """
        logger.warning("Using fallback profanity patterns")
        return {
            'hate_speech_indicators': {
                'pattern': r'\b(?:nazi|kike|spic|chink|nigger|faggot)\b',
                'description': 'Hate speech content',
                'severity': 'high'
            },
            'explicit_profanity': {
                'pattern': r'\b(?:fuck(?:ing|ed|er|s)?|shit(?:ty|s)?|bitch(?:es|y)?|ass(?:hole|es)?|bastard|damn(?:ed)?|hell)\b',
                'description': 'Explicit profanity',
                'severity': 'medium'
            }
        }
    
    def _map_severity(self, pattern_severity: str) -> Severity:
        """
        Map YAML pattern severity to Finding severity enum.
        
        Args:
            pattern_severity: Severity string from patterns.yaml
            
        Returns:
            Corresponding Severity enum value
        """
        severity_mapping = {
            'critical': Severity.CRITICAL,
            'high': Severity.HIGH,
            'medium': Severity.MEDIUM,
            'low': Severity.LOW,
            'info': Severity.INFO
        }
        
        return severity_mapping.get(pattern_severity.lower(), Severity.MEDIUM)
    
    def _add_file_context_to_finding(self, finding: Finding) -> Finding:
        """
        Add file classification context to a Finding object for intelligent prioritization.
        
        Args:
            finding: Original finding to enhance
            
        Returns:
            Finding with file context added to metadata
        """
        file_context = self.file_classifier.classify_file(finding.file_path)
        
        # Add comprehensive file context to metadata
        finding.metadata['file_context'] = {
            'file_type': file_context.file_type.value,
            'confidence': file_context.confidence,
            'intended_for_issues': file_context.intended_for_issues,
            'priority_weight': file_context.priority_weight,
            'classification_reason': file_context.classification_reason,
            'is_source_code': file_context.is_source_code(),
            'is_test_related': file_context.is_test_related(),
            'should_prioritize': file_context.should_prioritize_issues()
        }
        
        return finding
    
    def _apply_context_awareness(self, finding: Finding) -> Finding:
        """
        Apply context-aware adjustments to findings based on file classification.
        
        Test files and documentation may have different standards than production code.
        Includes smart filtering to prevent scanners from flagging their own pattern definitions.
        
        Args:
            finding: Finding to adjust
            
        Returns:
            Finding with context-aware adjustments applied, or None if should be filtered out
        """
        from dataclasses import replace as _replace
        from pathlib import PurePosixPath

        file_context = self.file_classifier.classify_file(finding.file_path)

        # SMART CONTEXT DETECTION: Prevent scanners from flagging their own patterns
        if self._should_skip_scanner_self_flagging(finding):
            # Use ``replace`` rather than mutating the input. Successive
            # multipliers across enhancers were drifting confidence past
            # the [0,1] invariant that ``Finding.__post_init__`` only
            # validates at construction time.
            new_metadata = dict(finding.metadata or {})
            new_metadata['context_adjustment'] = 'scanner_self_pattern_suppressed'
            new_metadata['suppression_reason'] = 'Scanner flagging its own pattern definitions'
            return _replace(
                finding,
                severity=Severity.LOW,
                confidence=0.1,
                description=f"Scanner pattern definition (auto-suppressed): {finding.description}",
                metadata=new_metadata,
            )

        # Whole-path-component test detection mirrors brass2_privacy_scanner's
        # FileContextAnalyzer — substring match on 'test' was over-flagging
        # production files like attest.py / manifest.py / latest.py.
        path_parts = {p.lower() for p in PurePosixPath(finding.file_path.replace('\\', '/')).parts}
        is_test_path = (
            file_context.is_test_related()
            or bool(path_parts & {'tests', 'test', 'spec', 'specs', '__tests__', 'fixtures', 'mocks'})
        )

        new_severity = finding.severity
        new_confidence = finding.confidence
        new_description = finding.description
        new_metadata = dict(finding.metadata or {})

        if is_test_path:
            pattern_name = new_metadata.get('pattern_name', '')
            if finding.severity == Severity.HIGH and pattern_name != 'hate_speech_indicators':
                new_severity = Severity.MEDIUM
            new_confidence = max(0.0, min(1.0, new_confidence * TEST_FILE_CONFIDENCE_MULTIPLIER))
            new_description = f"{new_description} (detected in test context)"
            new_metadata['context_adjustment'] = 'test_file_relaxed'

        elif bool(path_parts & {'example', 'examples', 'sample', 'samples', 'demo', 'demos'}):
            new_confidence = max(0.0, min(1.0, new_confidence * EXAMPLE_FILE_CONFIDENCE_MULTIPLIER))
            new_description = f"{new_description} (detected in example/sample file)"
            new_metadata['context_adjustment'] = 'example_file_relaxed'

        elif file_context.file_type.value in ('documentation', 'config'):
            new_confidence = max(0.0, min(1.0, new_confidence * DOCS_FILE_CONFIDENCE_MULTIPLIER))
            new_description = f"{new_description} (detected in documentation context)"
            new_metadata['context_adjustment'] = 'documentation_context'
        else:
            return finding

        return _replace(
            finding,
            severity=new_severity,
            confidence=new_confidence,
            description=new_description,
            metadata=new_metadata,
        )
    
    def _should_skip_scanner_self_flagging(self, finding: Finding) -> bool:
        """
        Determine if this finding is a scanner flagging its own pattern definitions.
        
        Prevents content moderation scanner from flagging hate speech patterns in its own code,
        privacy scanners from flagging PII patterns, etc.
        
        Args:
            finding: Finding to evaluate
            
        Returns:
            True if this appears to be a scanner flagging its own patterns
        """
        file_path = finding.file_path.lower()
        
        # Check if this is a scanner file
        is_scanner_file = (
            'scanner' in file_path or
            'content_moderation' in file_path or
            'privacy' in file_path or
            '/scanners/' in file_path
        )
        
        if not is_scanner_file:
            return False
            
        # Get the code snippet to analyze context.
        # `.get(key, '')` returns None when the key is present and
        # explicitly None — the default only fires when the key is
        # missing. Same trap with `getattr(..., 'code_snippet', '')`
        # below: the Finding model declares `code_snippet: Optional[str]
        # = None`, so getattr returns None (not '') when the attribute
        # exists with a None value. The content_moderation scanner
        # constructs its OWN findings with `code_snippet=None` (around
        # line 668) to avoid persisting profanity verbatim — and those
        # findings flow back here during the filtering pass. The `or ''`
        # normalization is load-bearing, not defensive paranoia: without
        # it, the `[:100]` slices below raise TypeError.
        code_snippet = finding.metadata.get('code_snippet') or ''
        line_content = finding.metadata.get('matched_text') or ''

        # Also check the Finding's own code_snippet attribute if metadata doesn't have it
        if not code_snippet:
            code_snippet = getattr(finding, 'code_snippet', None) or ''
            
        # Debug logging to understand what we're getting. NOTE: do not
        # log code_snippet/line_content contents at any level — this
        # scanner exists to flag profanity/slurs/credentials and the
        # raw text is exactly what we don't want in brass.log (which
        # may be uploaded with bug reports). Diagnostic info is
        # file:line + length only.
        logger.debug(
            "Scanner self-flag check: file=%s, line=%s, snippet_len=%d, line_len=%d",
            finding.file_path, finding.line_number,
            len(code_snippet), len(line_content),
        )
        
        # Look for pattern definition indicators
        pattern_indicators = [
            'pattern', 'regex', 'r\'', 'r"',  # Regex pattern definitions
            '\'pattern\':', '"pattern":', 'pattern=',  # YAML/dict pattern definitions
            'profanity_patterns', 'hate_speech_indicators',  # Our specific pattern names
            'fallback_patterns', '_get_patterns'  # Pattern loading methods
        ]
        
        # Check if the context suggests this is a pattern definition
        combined_content = f"{code_snippet} {line_content}".lower()
        context_suggests_pattern = any(
            indicator in combined_content
            for indicator in pattern_indicators
        )
        
        if context_suggests_pattern:
            # Don't include `combined_content` in the log message — it
            # carries raw source / flagged content that brass.log
            # shouldn't preserve. file:line is enough for diagnosis.
            logger.warning(
                "SUPPRESSING scanner self-flagging in %s:%s "
                "(pattern indicator matched in source context)",
                finding.file_path, finding.line_number,
            )
            return True
            
        # Extra debugging if we're in a scanner file but didn't suppress
        logger.debug(f"Not suppressing scanner file {finding.file_path}:{finding.line_number} - no pattern indicators found")
            
        return False
    
    def scan(self, file_paths: Optional[List[str]] = None) -> List[Finding]:
        """
        Scan project files for profanity and inappropriate content.
        
        Args:
            file_paths: Specific files to scan, or None for all scannable files
            
        Returns:
            List of Finding objects representing detected content issues
        """
        findings = []
        
        try:
            if file_paths is None:
                file_paths = self._discover_scannable_files()
            else:
                # Caller-provided list: filter to scannable extensions
                # BEFORE running content analysis. Otherwise binary
                # blobs, build artifacts and unrelated file types
                # (.bin, .so, .tsbuildinfo, image files) reach
                # _analyze_file_content. Matches the same orchestrator-
                # bypass bug class fixed in JavaScriptTypeScriptScanner
                # 2026-05-21 (46 false analysis_error findings on
                # whisperx). The discover-path already enforces this
                # whitelist; the caller-list path didn't.
                file_paths = [
                    fp for fp in file_paths
                    if Path(fp).suffix.lower() in self.scannable_extensions
                ]

            logger.info(f"Scanning {len(file_paths)} files for content moderation issues")
            
            for file_path in file_paths:
                try:
                    file_findings = self._analyze_file_content(file_path)
                    
                    # Apply intelligent context awareness and file classification
                    # This enhances findings with metadata and adjusts severity based on file type
                    enhanced_findings = []
                    for finding in file_findings:
                        # Step 1: Add comprehensive file context metadata for prioritization
                        enhanced_finding = self._add_file_context_to_finding(finding)
                        # Step 2: Apply context-aware severity and confidence adjustments
                        enhanced_finding = self._apply_context_awareness(enhanced_finding)
                        enhanced_findings.append(enhanced_finding)
                    
                    findings.extend(enhanced_findings)
                    
                except Exception as e:
                    # Handle individual file analysis errors gracefully
                    handle_analysis_error(
                        "content moderation", "ContentModerationScanner", "analyze_file", e, file_path
                    )
                    # Create error finding for user awareness
                    findings.append(self._create_analysis_error_finding(file_path, str(e)))
            
            logger.info(f"Content moderation scan complete: {len(findings)} issues found")
            return findings
            
        except Exception as e:
            logger.error(f"Content moderation scan failed: {e}")
            handle_analysis_error(
                "content moderation", "ContentModerationScanner", "scan", e, str(self.project_path)
            )
            return []
    
    def _discover_scannable_files(self) -> List[str]:
        """
        Discover all scannable text files in the project.

        Three gates, in order:
          1. ``path.is_file()`` — Next.js generates "file-named directories"
             like ``app/feed.xml/`` (a folder containing route handlers); without
             this check, ``open()`` later raises ``IsADirectoryError``.
          2. ``file_classifier.should_exclude_from_analysis`` — single source of
             truth for ``.next/``, ``node_modules/``, etc. Used to drift; now
             centralized.
          3. ``self.exclude_patterns`` — legacy substring list, preserved for
             scanner-specific exclusions (analysis artifacts).
        """
        scannable_files = []

        try:
            # Search for files with scannable extensions
            for extension in self.scannable_extensions:
                pattern = f"**/*{extension}"
                for path in self.project_path.glob(pattern):
                    # 1) Must actually be a file. Frameworks like Next.js generate
                    # directories named ``feed.xml``, ``robots.txt``, etc.
                    if not path.is_file():
                        continue

                    # 2) Defer to the centralized file classifier, which knows
                    # about ``.next/``, ``.nuxt/``, ``dist/``, ``node_modules/``,
                    # ``prisma/generated/``, etc.
                    if self.file_classifier.should_exclude_from_analysis(str(path)):
                        continue

                    # 3) Scanner-specific exclusion list (analysis artifacts mostly).
                    if any(exclude in str(path) for exclude in self.exclude_patterns):
                        continue

                    # Skip very large files (>1MB) for performance
                    try:
                        if path.stat().st_size > MAX_FILE_SIZE_BYTES:
                            continue
                    except OSError:
                        continue  # Skip files with access issues

                    # Return relative path
                    try:
                        relative_path = str(path.relative_to(self.project_path))
                        scannable_files.append(relative_path)
                    except ValueError:
                        # Skip if path is not relative to project
                        continue

            logger.info(f"Discovered {len(scannable_files)} scannable files")
            return scannable_files

        except Exception as e:
            logger.error(f"File discovery failed: {e}")
            handle_analysis_error(
                "file discovery", "ContentModerationScanner", "discover_files", e, str(self.project_path)
            )
            return []
    
    def _analyze_file_content(self, file_path: str) -> List[Finding]:
        """
        Analyze a single file for profanity and inappropriate content.
        
        Args:
            file_path: Relative path to file to analyze
            
        Returns:
            List of findings for this file
        """
        findings = []
        
        try:
            # Read file content using safe file operation
            full_path = self.project_path / file_path
            
            def read_file_content() -> str:
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read()
            
            content = safe_file_operation(
                file_path, read_file_content, "ContentModerationScanner", "read_content", ""
            )
            
            if not content:  # File reading failed or empty
                return findings
            
            # Analyze content against each profanity pattern
            for pattern_name, pattern_config in self.profanity_patterns.items():
                pattern_findings = self._detect_pattern_in_content(
                    content, file_path, pattern_name, pattern_config
                )
                findings.extend(pattern_findings)
            
            return findings
            
        except Exception as e:
            logger.error(f"Content analysis failed for {file_path}: {e}")
            handle_analysis_error(
                "content analysis", "ContentModerationScanner", "analyze_content", e, file_path
            )
            return []
    
    def _detect_pattern_in_content(
        self, content: str, file_path: str, pattern_name: str, pattern_config: Dict[str, Any]
    ) -> List[Finding]:
        """
        Detect a specific profanity pattern in file content.
        
        Args:
            content: File content to analyze
            file_path: Path to the file being analyzed
            pattern_name: Name of the pattern being checked
            pattern_config: Pattern configuration from patterns.yaml
            
        Returns:
            List of findings for this pattern
        """
        try:
            # Get cached compiled pattern
            compiled_pattern = self._compile_pattern('', pattern_name)  # pattern_name is the key
            if not compiled_pattern:
                return []
            
            # Find all matches in content
            matches = self._find_pattern_matches(content, compiled_pattern)
            
            # Convert matches to findings
            findings = self._create_findings_from_matches(
                matches, file_path, pattern_name, pattern_config
            )
            
            return findings
            
        except Exception as e:
            logger.error(f"Pattern detection failed for {pattern_name}: {e}")
            return []
    
    def _compile_all_patterns(self) -> None:
        """
        Pre-compile all regex patterns for performance optimization.
        
        This method compiles patterns once during initialization,
        avoiding repeated compilation during scanning.
        """
        for pattern_name, pattern_config in self.profanity_patterns.items():
            pattern_str = pattern_config.get('pattern', '')
            if pattern_str:
                compiled = self._compile_single_pattern(pattern_str, pattern_name)
                self._compiled_patterns_cache[pattern_name] = compiled
    
    def _compile_pattern(self, pattern: str, pattern_name: str) -> Optional[Pattern[str]]:
        """
        Get compiled regex pattern from cache or compile if needed.
        
        Args:
            pattern: Regex pattern string (unused - kept for compatibility)
            pattern_name: Name of the pattern to retrieve
            
        Returns:
            Cached compiled regex pattern or None if invalid
        """
        return self._compiled_patterns_cache.get(pattern_name)
    
    def _compile_single_pattern(self, pattern: str, pattern_name: str) -> Optional[Pattern[str]]:
        """
        Compile a single regex pattern with appropriate flags.
        
        Args:
            pattern: Regex pattern string
            pattern_name: Name for error reporting
            
        Returns:
            Compiled regex pattern or None if invalid
        """
        if not pattern:
            return None
            
        try:
            return re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        except re.error as e:
            logger.error(f"Invalid regex pattern '{pattern_name}': {e}")
            return None
    
    def _find_pattern_matches(self, content: str, pattern: Pattern[str]) -> List[Dict[str, Union[str, int]]]:
        """
        Find all matches of a pattern in content with line/column information.
        
        Args:
            content: File content to search
            pattern: Compiled regex pattern
            
        Returns:
            List of match dictionaries with position information
        """
        matches = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for match in pattern.finditer(line):
                matches.append({
                    'text': match.group(),
                    'line_number': line_num,
                    'column': match.start() + 1,
                    'line_content': line.strip(),
                    'match_start': match.start(),
                    'match_end': match.end()
                })
        
        return matches
    
    def _create_findings_from_matches(
        self, matches: List[Dict[str, Any]], file_path: str, 
        pattern_name: str, pattern_config: Dict[str, Any]
    ) -> List[Finding]:
        """
        Create Finding objects from pattern matches.
        
        Args:
            matches: List of match dictionaries
            file_path: Path to the file
            pattern_name: Name of the pattern
            pattern_config: Pattern configuration
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        for match in matches:
            # Don't persist the matched profanity/slur text in serialized
            # output. The whole point of this scanner is "this language
            # appeared here"; emitting the language verbatim turns the
            # ``.brass/`` artifact into a copy of the very content we
            # flagged. file_path:line_number is enough for human review.
            finding = Finding(
                id=self._generate_finding_id(file_path, pattern_name, match['line_number'], match['text']),
                type=FindingType.CODE_QUALITY,
                severity=self._map_severity(pattern_config.get('severity', DEFAULT_SEVERITY_FALLBACK)),
                file_path=file_path,
                line_number=match['line_number'],
                column=match['column'],
                title=f"Content Moderation: {pattern_config.get('description', pattern_name)}",
                description=pattern_config.get('risk', f"Detected {pattern_name} in content"),
                code_snippet=None,
                confidence=DEFAULT_PATTERN_CONFIDENCE,
                impact_score=self._calculate_impact_score(pattern_config.get('severity', DEFAULT_SEVERITY_FALLBACK)),
                detected_by="ContentModerationScanner",
                remediation=pattern_config.get('fix', f"Remove or replace {pattern_name}"),
                metadata={
                    'pattern_name': pattern_name,
                    'pattern_type': 'profanity_detection',
                    'match_start': match['match_start'],
                    'match_end': match['match_end'],
                    # Signal to the YAML output pipeline (Phase D
                    # code_snippet synthesizer) that this finding's
                    # code_snippet was intentionally omitted by the
                    # scanner. Without this flag, Phase D would
                    # re-read the source line and re-emit the very
                    # content this scanner flagged.
                    'code_snippet_intentionally_omitted': True,
                }
            )
            findings.append(finding)
        
        return findings
    
    def _calculate_impact_score(self, severity: str) -> float:
        """
        Calculate impact score based on severity level.
        
        Args:
            severity: Severity level string
            
        Returns:
            Impact score between 0.0 and 1.0
        """
        impact_mapping = {
            'critical': 0.95,
            'high': 0.8,
            'medium': 0.6,
            'low': 0.4,
            'info': 0.2
        }
        
        return impact_mapping.get(severity.lower(), 0.6)
    
    def _generate_finding_id(self, file_path: str, pattern_name: str, line_number: int, matched_text: str) -> str:
        """
        Generate unique finding ID for content moderation findings.
        
        Args:
            file_path: Path to the file
            pattern_name: Name of the matched pattern
            line_number: Line number of the match
            matched_text: The actual matched text
            
        Returns:
            Unique finding identifier
        """
        content = f"{file_path}:{pattern_name}:{line_number}:{matched_text}"
        hash_suffix = hashlib.md5(content.encode(), usedforsecurity=False).hexdigest()[:8]
        return f"content_mod_{hash_suffix}"
    
    def _create_analysis_error_finding(self, file_path: str, error_msg: str) -> Finding:
        """
        Create finding for content analysis errors.
        
        Args:
            file_path: Path to the file that caused the error
            error_msg: Error message description
            
        Returns:
            Finding representing the analysis error
        """
        return Finding(
            id=self._generate_finding_id(file_path, "analysis_error", 0, error_msg),
            type=FindingType.CODE_QUALITY,
            severity=Severity.LOW,
            file_path=file_path,
            title="Content Analysis Error",
            description=f"Failed to analyze file for content moderation: {error_msg}",
            confidence=1.0,
            impact_score=0.1,
            detected_by="ContentModerationScanner",
            remediation="Check file encoding and accessibility",
            metadata={
                "error_type": "content_analysis_failure",
                "error_msg": error_msg
            }
        )