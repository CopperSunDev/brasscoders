"""
AI Context Coherence Scanner - Revolutionary AI-native system coherence analysis.

This scanner detects cross-component consistency violations in AI-generated code,
identifying system coherence problems that AI coders cannot see. Revolutionary
AI development intelligence for ensuring system-wide consistency.
"""

import ast
import re
import hashlib
from pathlib import Path
from typing import List, Optional, Dict, Set, Any, Tuple
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime

from brass.models.finding import Finding, FindingType, Severity
from brass.core.file_classifier import FileClassifier
from brass.core.logging_config import get_logger
from brass.core.error_handling import handle_analysis_error, safe_file_operation

logger = get_logger(__name__)

# Configuration constants for performance and behavior tuning
MAX_FILE_SIZE_BYTES = 1024 * 1024  # 1MB - Skip large files for performance
DEFAULT_COHERENCE_CONFIDENCE = 0.85  # High confidence for cross-component analysis
FUNCTION_SIGNATURE_ANALYSIS_THRESHOLD = 2  # Minimum occurrences to analyze coherence
MAX_COMPONENTS_TO_ANALYZE = 100  # Limit for large projects
MAX_FUNCTIONS_PER_COMPONENT = 50  # Memory management limit

# Analysis performance constants - configurable limits for large projects
MAX_COHERENCE_VIOLATIONS_TO_REPORT = 20  # Avoid overwhelming output
DATA_STRUCTURE_ANALYSIS_THRESHOLD = 3  # Minimum usage patterns to analyze

# Coherence detection patterns
COMMON_FUNCTION_NAMES = {
    'authenticate', 'login', 'logout', 'validate', 'process', 'handle',
    'create', 'update', 'delete', 'get', 'set', 'save', 'load',
    'parse', 'format', 'encode', 'decode', 'send', 'receive'
}

ERROR_HANDLING_PATTERNS = [
    'Exception', 'ValueError', 'TypeError', 'AttributeError', 'KeyError',
    'DatabaseError', 'ConnectionError', 'TimeoutError', 'IOError'
]


@dataclass
class FunctionSignature:
    """Represents a function signature for coherence analysis."""
    name: str
    args: List[str]
    defaults_count: int
    vararg: Optional[str]
    kwarg: Optional[str]
    file_path: str
    line_number: int
    component_name: str


@dataclass
class DataUsagePattern:
    """Represents data structure usage pattern."""
    variable_name: str
    access_patterns: Set[str]  # "dict_key:email", "attribute:email"
    file_path: str
    component_name: str


@dataclass
class ErrorPattern:
    """Represents error handling pattern."""
    exception_type: str
    handler_actions: List[str]  # "log", "reraise", "return_none"
    context: str
    file_path: str
    line_number: int
    component_name: str


@dataclass
class CoherenceViolation:
    """Represents a detected system coherence violation."""
    violation_type: str
    component_a: str
    component_b: str
    details: Dict[str, Any]
    confidence: float
    impact_score: float
    line_numbers: List[int]
    file_paths: List[str]


class AIContextCoherenceScanner:
    """
    AI Context Coherence Scanner for detecting system coherence violations.
    
    Analyzes AI-generated code for cross-component consistency issues:
    - Function signature mismatches across components
    - Data structure inconsistent usage patterns
    - Error handling pattern divergence
    - Cross-component interface violations
    
    Revolutionary AI development intelligence that catches problems
    traditional static analysis tools cannot detect.
    
    Example:
        scanner = AIContextCoherenceScanner("/path/to/project")
        findings = scanner.scan()
        print(f"Found {len(findings)} system coherence violations")
    """
    
    def __init__(self, project_path: str, file_index=None) -> None:
        """
        Initialize AI Context Coherence Scanner.

        Args:
            project_path: Root path of project to analyze
            file_index: Optional shared FileIndex (Perf #2/#12). Falls
                back to per-scanner rglob walk when None.

        Raises:
            ValueError: If project_path is empty or None
            FileNotFoundError: If project_path does not exist
        """
        if not project_path:
            raise ValueError("Project path cannot be empty or None")

        self.project_path = Path(project_path).resolve()
        if not self.project_path.exists():
            raise FileNotFoundError(f"Project path does not exist: {self.project_path}")
        self.file_index = file_index
        
        # Standard exclude patterns following existing scanner pattern
        self.exclude_patterns = {
            '.git', '.svn', '.hg', '__pycache__', '.pytest_cache',
            'node_modules', '.venv', 'venv', '.env', 'build', 'dist',
            '.brass', '.idea', '.vscode', '.DS_Store',
            'archive', 'build_env', 'site-packages', 'backup',
            # AI-agent scratch space — Claude Code worktrees & config.
            '.claude',
        }
        
        # Component analysis state
        self.function_signatures: Dict[str, List[FunctionSignature]] = defaultdict(list)
        self.data_usage_patterns: Dict[str, List[DataUsagePattern]] = defaultdict(list)
        self.error_patterns: List[ErrorPattern] = []
        self.coherence_violations: List[CoherenceViolation] = []

        # 2026-05-19 audit (silent-drop class): files past the
        # MAX_COMPONENTS_TO_ANALYZE cap were truncated invisibly.
        # _discover_python_files() sets this each scan; scan() emits a
        # single INFO summary if > 0.
        self._components_dropped: int = 0

        # File classifier for context awareness (reuse existing infrastructure)
        self.file_classifier = FileClassifier()
        
        logger.info(f"AIContextCoherenceScanner initialized for {self.project_path}")
    
    def scan(self, file_paths: Optional[List[str]] = None) -> List[Finding]:
        """
        Perform AI context coherence analysis.
        
        Args:
            file_paths: Specific files to scan, or None for all Python files
            
        Returns:
            List of Finding objects representing coherence violations
            
        Raises:
            Exception: Re-raises critical errors after logging
        """
        findings = []

        # 2026-05-19 audit (silent-drop class): clear stale drop counter
        # so a re-used scanner instance doesn't report the previous
        # scan's truncation in this scan's summary.
        self._components_dropped = 0

        try:
            # Phase 1: Discover Python files for analysis
            if file_paths:
                python_files = [Path(fp) for fp in file_paths if fp.endswith('.py')]
            else:
                python_files = self._discover_python_files()
            
            logger.info(f"Discovered {len(python_files)} Python files for coherence analysis")
            
            if not python_files:
                logger.info("No Python files found for coherence analysis")
                return findings
            
            # Phase 2: Extract component interfaces via AST analysis
            logger.info("Extracting component interfaces via AST analysis")
            successful_extractions = 0
            for file_path in python_files:
                try:
                    if self._extract_component_interface(file_path):
                        successful_extractions += 1
                except Exception as e:
                    logger.warning(f"Failed to extract interface from {file_path}: {e}")
            
            logger.info(f"Successfully extracted interfaces from {successful_extractions} components")
            
            # Phase 3: Analyze cross-component coherence violations
            logger.info("Analyzing cross-component coherence violations")
            self._analyze_function_signature_coherence()
            self._analyze_data_usage_coherence()
            self._analyze_error_handling_coherence()
            
            logger.info(f"Detected {len(self.coherence_violations)} coherence violations")
            
            # Phase 4: Generate Finding objects
            logger.info("Generating coherence violation findings")
            for violation in self.coherence_violations[:MAX_COHERENCE_VIOLATIONS_TO_REPORT]:
                finding = self._create_coherence_finding(violation)
                findings.append(finding)
            
            self._emit_silent_drop_summary()
            logger.info(f"AI Context Coherence scan complete: {len(findings)} violations found")
            return findings

        except Exception as e:
            error_msg = f"Critical error in AIContextCoherenceScanner: {str(e)}"
            logger.error(error_msg)
            handle_analysis_error(error_msg, "AIContextCoherenceScanner", "scan")
            raise
        finally:
            # Bug Scanner 2026-05-19: summary must fire on the exception
            # path too — that's when operators most need visibility.
            # Idempotent: same log line as the happy-path call above.
            self._emit_silent_drop_summary()

    def _emit_silent_drop_summary(self) -> None:
        """Aggregate INFO line for the MAX_COMPONENTS_TO_ANALYZE cap.
        Called from both happy-path and finally; idempotent.
        """
        if self._components_dropped > 0:
            logger.info(
                f"AIContextCoherence component cap truncated {self._components_dropped} "
                f"file(s) past MAX_COMPONENTS_TO_ANALYZE. Coherence findings may undercount on this scan."
            )
    
    def _discover_python_files(self) -> List[Path]:
        """
        Discover Python files for analysis following established patterns.
        
        Returns:
            List of Python file paths suitable for analysis
        """
        # Prefer shared FileIndex (Perf #12) — saves a tree walk.
        # FileIndex already applied FileClassifier exclusions; we still
        # apply the scanner-specific exclude_patterns + size filter.
        from brass.core.path_safety import is_within
        files = []
        candidates = (
            self.file_index.files_with_ext('.py') if self.file_index is not None
            else self.project_path.rglob('*.py')
        )
        for file_path in candidates:
            if not file_path.is_file():
                continue
            if not is_within(file_path, self.project_path):
                continue
            if any(exclude in file_path.parts for exclude in self.exclude_patterns):
                continue
            try:
                size = file_path.stat().st_size
            except OSError:
                continue
            if size > MAX_FILE_SIZE_BYTES:
                continue
            files.append((file_path, size))

        # Truncating the unsorted ``rglob`` order silently dropped the
        # files past index 100 — different files on different OSes
        # because rglob iteration order is filesystem-dependent. Prefer
        # files with non-trivial source (sort by size desc, then path)
        # so the cap deterministically picks the components most likely
        # to have meaningful interfaces.
        files.sort(key=lambda fs: (-fs[1], str(fs[0])))
        # 2026-05-19 audit (silent-drop class): record cap-truncated
        # components so scan() can surface the gap in its summary log.
        self._components_dropped = max(0, len(files) - MAX_COMPONENTS_TO_ANALYZE)
        return [fp for fp, _ in files[:MAX_COMPONENTS_TO_ANALYZE]]
    
    def _extract_component_interface(self, file_path: Path) -> bool:
        """
        Extract component interface via AST analysis.
        
        Args:
            file_path: Path to Python file to analyze
            
        Returns:
            True if extraction successful, False otherwise
        """
        try:
            content = safe_file_operation(
                str(file_path),
                lambda: file_path.read_text(encoding='utf-8'),
                "AIContextCoherenceScanner",
                "_extract_component_interface",
                ""
            )
            
            if not content:
                return False
            
            # Parse AST
            tree = ast.parse(content)
            component_name = file_path.stem
            
            # Extract function signatures
            function_count = 0
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and function_count < MAX_FUNCTIONS_PER_COMPONENT:
                    if node.name in COMMON_FUNCTION_NAMES or node.name.startswith('_') == False:
                        signature = self._extract_function_signature(node, file_path, component_name)
                        if signature:
                            self.function_signatures[signature.name].append(signature)
                            function_count += 1
            
            # Extract data usage patterns
            self._extract_data_usage_patterns(tree, file_path, component_name)
            
            # Extract error handling patterns
            self._extract_error_patterns(tree, file_path, component_name)
            
            return True
            
        except Exception as e:
            logger.debug(f"AST extraction failed for {file_path}: {e}")
            return False
    
    def _extract_function_signature(self, node: ast.FunctionDef, file_path: Path, component_name: str) -> Optional[FunctionSignature]:
        """
        Extract function signature from AST node.
        
        Args:
            node: AST FunctionDef node
            file_path: Path to source file
            component_name: Name of component
            
        Returns:
            FunctionSignature object or None if extraction fails
        """
        try:
            return FunctionSignature(
                name=node.name,
                args=[arg.arg for arg in node.args.args],
                defaults_count=len(node.args.defaults),
                vararg=node.args.vararg.arg if node.args.vararg else None,
                kwarg=node.args.kwarg.arg if node.args.kwarg else None,
                file_path=str(file_path),
                line_number=node.lineno,
                component_name=component_name
            )
        except Exception as e:
            logger.debug(f"Failed to extract signature for {node.name}: {e}")
            return None
    
    def _extract_data_usage_patterns(self, tree: ast.AST, file_path: Path, component_name: str) -> None:
        """
        Extract data structure usage patterns from AST.
        
        Args:
            tree: AST tree to analyze
            file_path: Path to source file
            component_name: Name of component
        """
        usage_patterns = defaultdict(set)
        
        for node in ast.walk(tree):
            # Detect dictionary access patterns: obj['key']
            if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
                if isinstance(node.value, ast.Name):
                    var_name = node.value.id
                    key = str(node.slice.value)
                    usage_patterns[var_name].add(f"dict_key:{key}")
            
            # Detect attribute access patterns: obj.attr
            elif isinstance(node, ast.Attribute):
                if isinstance(node.value, ast.Name):
                    var_name = node.value.id
                    attr = node.attr
                    usage_patterns[var_name].add(f"attribute:{attr}")
        
        # Store significant usage patterns
        for var_name, patterns in usage_patterns.items():
            if len(patterns) >= DATA_STRUCTURE_ANALYSIS_THRESHOLD:
                pattern = DataUsagePattern(
                    variable_name=var_name,
                    access_patterns=patterns,
                    file_path=str(file_path),
                    component_name=component_name
                )
                self.data_usage_patterns[var_name].append(pattern)
    
    def _extract_error_patterns(self, tree: ast.AST, file_path: Path, component_name: str) -> None:
        """
        Extract error handling patterns from AST.
        
        Args:
            tree: AST tree to analyze
            file_path: Path to source file  
            component_name: Name of component
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.Try):
                for handler in node.handlers:
                    exception_type = 'generic'
                    if handler.type:
                        if isinstance(handler.type, ast.Name):
                            exception_type = handler.type.id
                        elif isinstance(handler.type, ast.Attribute):
                            exception_type = handler.type.attr
                    
                    # Analyze handler actions
                    handler_actions = self._analyze_handler_actions(handler)
                    
                    pattern = ErrorPattern(
                        exception_type=exception_type,
                        handler_actions=handler_actions,
                        context=f"try_block_line_{node.lineno}",
                        file_path=str(file_path),
                        line_number=handler.lineno,
                        component_name=component_name
                    )
                    self.error_patterns.append(pattern)
    
    def _analyze_handler_actions(self, handler: ast.ExceptHandler) -> List[str]:
        """
        Analyze actions taken in exception handler.
        
        Args:
            handler: AST ExceptHandler node
            
        Returns:
            List of action types detected
        """
        actions = []
        
        for node in handler.body:
            if isinstance(node, ast.Expr):
                if isinstance(node.value, ast.Call):
                    # Function call in handler
                    if isinstance(node.value.func, ast.Attribute):
                        if node.value.func.attr in ['error', 'warning', 'info', 'debug']:
                            actions.append('log')
                        elif node.value.func.attr == 'print':
                            actions.append('print')
                    elif isinstance(node.value.func, ast.Name):
                        if node.value.func.id == 'print':
                            actions.append('print')
            elif isinstance(node, ast.Raise):
                actions.append('reraise')
            elif isinstance(node, ast.Return):
                actions.append('return')
            elif isinstance(node, ast.Pass):
                actions.append('pass')
        
        return actions if actions else ['unknown']
    
    def _analyze_function_signature_coherence(self) -> None:
        """Analyze function signature coherence across components."""
        for func_name, signatures in self.function_signatures.items():
            if len(signatures) >= FUNCTION_SIGNATURE_ANALYSIS_THRESHOLD:
                inconsistencies = self._find_signature_inconsistencies(func_name, signatures)
                self.coherence_violations.extend(inconsistencies)
    
    def _find_signature_inconsistencies(self, func_name: str, signatures: List[FunctionSignature]) -> List[CoherenceViolation]:
        """
        Find inconsistencies in function signatures.
        
        Args:
            func_name: Name of function to analyze
            signatures: List of signatures for this function
            
        Returns:
            List of coherence violations found
        """
        violations = []
        
        # Group signatures by their "signature fingerprint"
        signature_groups = defaultdict(list)
        for sig in signatures:
            fingerprint = (tuple(sig.args), sig.defaults_count, sig.vararg, sig.kwarg)
            signature_groups[fingerprint].append(sig)
        
        # If we have multiple different signatures, it's a violation
        if len(signature_groups) > 1:
            fingerprints = list(signature_groups.keys())
            for i in range(len(fingerprints)):
                for j in range(i + 1, len(fingerprints)):
                    group_a = signature_groups[fingerprints[i]]
                    group_b = signature_groups[fingerprints[j]]
                    
                    violation = CoherenceViolation(
                        violation_type="function_signature_mismatch",
                        component_a=group_a[0].component_name,
                        component_b=group_b[0].component_name,
                        details={
                            "function_name": func_name,
                            "signature_a": {
                                "args": group_a[0].args,
                                "defaults": group_a[0].defaults_count,
                                "vararg": group_a[0].vararg,
                                "kwarg": group_a[0].kwarg
                            },
                            "signature_b": {
                                "args": group_b[0].args,
                                "defaults": group_b[0].defaults_count,
                                "vararg": group_b[0].vararg,
                                "kwarg": group_b[0].kwarg
                            }
                        },
                        confidence=0.9,  # High confidence for signature mismatches
                        impact_score=0.8,  # High impact for system coherence
                        line_numbers=[group_a[0].line_number, group_b[0].line_number],
                        file_paths=[group_a[0].file_path, group_b[0].file_path]
                    )
                    violations.append(violation)
        
        return violations
    
    def _analyze_data_usage_coherence(self) -> None:
        """Analyze data structure usage coherence across components."""
        for var_name, patterns in self.data_usage_patterns.items():
            if len(patterns) >= 2:  # Need at least 2 components for comparison
                inconsistencies = self._find_data_usage_inconsistencies(var_name, patterns)
                self.coherence_violations.extend(inconsistencies)
    
    def _find_data_usage_inconsistencies(self, var_name: str, patterns: List[DataUsagePattern]) -> List[CoherenceViolation]:
        """
        Find inconsistencies in data structure usage.
        
        Args:
            var_name: Variable name being analyzed
            patterns: List of usage patterns for this variable
            
        Returns:
            List of coherence violations found
        """
        violations = []
        
        # Look for mixed dict/attribute access patterns
        for i in range(len(patterns)):
            for j in range(i + 1, len(patterns)):
                pattern_a = patterns[i]
                pattern_b = patterns[j]
                
                # Check if one uses dict access and other uses attribute access
                a_has_dict = any(p.startswith("dict_key:") for p in pattern_a.access_patterns)
                a_has_attr = any(p.startswith("attribute:") for p in pattern_a.access_patterns)
                b_has_dict = any(p.startswith("dict_key:") for p in pattern_b.access_patterns)
                b_has_attr = any(p.startswith("attribute:") for p in pattern_b.access_patterns)
                
                if (a_has_dict and b_has_attr and not a_has_attr) or (a_has_attr and b_has_dict and not a_has_dict):
                    violation = CoherenceViolation(
                        violation_type="data_structure_inconsistency",
                        component_a=pattern_a.component_name,
                        component_b=pattern_b.component_name,
                        details={
                            "variable_name": var_name,
                            "component_a_patterns": list(pattern_a.access_patterns),
                            "component_b_patterns": list(pattern_b.access_patterns),
                            "inconsistency": "mixed_dict_attribute_access"
                        },
                        confidence=0.85,
                        impact_score=0.7,
                        line_numbers=[],  # Would need more AST work to get exact lines
                        file_paths=[pattern_a.file_path, pattern_b.file_path]
                    )
                    violations.append(violation)
        
        return violations
    
    def _analyze_error_handling_coherence(self) -> None:
        """Analyze error handling pattern coherence across components."""
        # Group error patterns by exception type
        error_groups = defaultdict(list)
        for pattern in self.error_patterns:
            if pattern.exception_type in ERROR_HANDLING_PATTERNS:
                error_groups[pattern.exception_type].append(pattern)
        
        # Look for inconsistent handling of same exception types
        for exception_type, patterns in error_groups.items():
            if len(patterns) >= 2:
                inconsistencies = self._find_error_handling_inconsistencies(exception_type, patterns)
                self.coherence_violations.extend(inconsistencies)
    
    def _find_error_handling_inconsistencies(self, exception_type: str, patterns: List[ErrorPattern]) -> List[CoherenceViolation]:
        """
        Find inconsistencies in error handling patterns.
        
        Args:
            exception_type: Type of exception being analyzed
            patterns: List of error handling patterns
            
        Returns:
            List of coherence violations found
        """
        violations = []
        
        # Group by handler action sets
        action_groups = defaultdict(list)
        for pattern in patterns:
            action_key = tuple(sorted(pattern.handler_actions))
            action_groups[action_key].append(pattern)
        
        # If we have different handling approaches, it may be a violation
        if len(action_groups) > 1:
            action_keys = list(action_groups.keys())
            for i in range(len(action_keys)):
                for j in range(i + 1, len(action_keys)):
                    group_a = action_groups[action_keys[i]]
                    group_b = action_groups[action_keys[j]]
                    
                    # Only flag as violation if the handling is significantly different
                    if self._are_error_handling_approaches_incompatible(action_keys[i], action_keys[j]):
                        violation = CoherenceViolation(
                            violation_type="error_handling_inconsistency",
                            component_a=group_a[0].component_name,
                            component_b=group_b[0].component_name,
                            details={
                                "exception_type": exception_type,
                                "component_a_actions": list(action_keys[i]),
                                "component_b_actions": list(action_keys[j])
                            },
                            confidence=0.75,  # Medium-high confidence
                            impact_score=0.6,  # Medium impact
                            line_numbers=[group_a[0].line_number, group_b[0].line_number],
                            file_paths=[group_a[0].file_path, group_b[0].file_path]
                        )
                        violations.append(violation)
        
        return violations
    
    def _are_error_handling_approaches_incompatible(self, actions_a: Tuple[str, ...], actions_b: Tuple[str, ...]) -> bool:
        """
        Determine if two error handling approaches are incompatible.
        
        Args:
            actions_a: First set of handler actions
            actions_b: Second set of handler actions
            
        Returns:
            True if approaches are incompatible
        """
        # Consider incompatible if one logs and other doesn't, or one re-raises and other doesn't
        a_logs = 'log' in actions_a
        b_logs = 'log' in actions_b
        a_reraises = 'reraise' in actions_a
        b_reraises = 'reraise' in actions_b
        a_passes = 'pass' in actions_a
        b_passes = 'pass' in actions_b
        
        # Significant incompatibilities
        if (a_logs and not b_logs and b_passes) or (b_logs and not a_logs and a_passes):
            return True  # One logs errors, other silently ignores
        
        if (a_reraises and not b_reraises and not b_logs) or (b_reraises and not a_reraises and not a_logs):
            return True  # One re-raises, other silently handles
        
        return False
    
    def _create_coherence_finding(self, violation: CoherenceViolation) -> Finding:
        """
        Create Finding object for coherence violation.
        
        Args:
            violation: CoherenceViolation object
            
        Returns:
            Finding object for this violation
        """
        # Generate unique ID
        violation_id = hashlib.md5(
            f"{violation.violation_type}_{violation.component_a}_{violation.component_b}".encode()
        ).hexdigest()[:12]
        
        # Create title based on violation type
        title_map = {
            "function_signature_mismatch": "Function Signature Coherence Violation",
            "data_structure_inconsistency": "Data Structure Usage Inconsistency", 
            "error_handling_inconsistency": "Error Handling Pattern Divergence"
        }
        title = title_map.get(violation.violation_type, "System Coherence Violation")
        
        # Create detailed description
        description = self._create_violation_description(violation)
        
        # Determine severity based on impact score
        if violation.impact_score >= 0.8:
            severity = Severity.HIGH
        elif violation.impact_score >= 0.6:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW
        
        # Use first file path as primary location
        primary_file = violation.file_paths[0] if violation.file_paths else ""
        primary_line = violation.line_numbers[0] if violation.line_numbers else None
        
        return Finding(
            id=f"ai_coherence_{violation_id}",
            type=FindingType.CODE_QUALITY,  # System coherence is code quality concern
            severity=severity,
            file_path=primary_file,
            line_number=primary_line,
            title=title,
            description=description,
            confidence=violation.confidence,
            impact_score=violation.impact_score,
            detected_by="AIContextCoherenceScanner",
            code_snippet=None,  # Could extract this in future versions
            remediation=self._create_remediation_guidance(violation),
            references=[
                "https://martinfowler.com/architecture/",
                "https://www.infoq.com/articles/architecture-trends-2024/"
            ],
            metadata={
                "violation_type": violation.violation_type,
                "component_a": violation.component_a,
                "component_b": violation.component_b,
                "ai_coherence_analysis": True,
                "system_wide_impact": True,
                "affected_files": violation.file_paths,
                "detection_method": "cross_component_ast_analysis"
            }
        )
    
    def _create_violation_description(self, violation: CoherenceViolation) -> str:
        """
        Create detailed description for coherence violation.
        
        Args:
            violation: CoherenceViolation object
            
        Returns:
            Detailed description string
        """
        if violation.violation_type == "function_signature_mismatch":
            func_name = violation.details.get("function_name", "unknown")
            sig_a = violation.details.get("signature_a", {})
            sig_b = violation.details.get("signature_b", {})
            
            return (
                f"Function '{func_name}' has inconsistent signatures across components. "
                f"Component '{violation.component_a}' defines it with args {sig_a.get('args', [])}, "
                f"while component '{violation.component_b}' uses args {sig_b.get('args', [])}. "
                f"This inconsistency can cause runtime errors when components interact."
            )
        
        elif violation.violation_type == "data_structure_inconsistency":
            var_name = violation.details.get("variable_name", "unknown")
            inconsistency = violation.details.get("inconsistency", "unknown")
            
            return (
                f"Variable '{var_name}' is accessed inconsistently across components. "
                f"Component '{violation.component_a}' treats it as one data structure type, "
                f"while component '{violation.component_b}' treats it differently. "
                f"This can lead to AttributeError or KeyError exceptions at runtime."
            )
        
        elif violation.violation_type == "error_handling_inconsistency":
            exception_type = violation.details.get("exception_type", "unknown")
            
            return (
                f"Exception type '{exception_type}' is handled inconsistently across components. "
                f"Component '{violation.component_a}' handles it one way, "
                f"while component '{violation.component_b}' uses a different approach. "
                f"Inconsistent error handling can make debugging difficult and create unexpected behavior."
            )
        
        return f"System coherence violation detected between components '{violation.component_a}' and '{violation.component_b}'."
    
    def _create_remediation_guidance(self, violation: CoherenceViolation) -> str:
        """
        Create remediation guidance for coherence violation.
        
        Args:
            violation: CoherenceViolation object
            
        Returns:
            Remediation guidance string
        """
        if violation.violation_type == "function_signature_mismatch":
            return (
                "Standardize the function signature across all components. "
                "Choose the most appropriate signature and update all callers. "
                "Consider using type hints to make expected signatures explicit."
            )
        
        elif violation.violation_type == "data_structure_inconsistency":
            return (
                "Standardize data structure access patterns across components. "
                "Choose either dictionary-style or attribute-style access consistently. "
                "Consider using dataclasses or TypedDict to enforce structure."
            )
        
        elif violation.violation_type == "error_handling_inconsistency":
            return (
                "Standardize error handling approaches across the system. "
                "Establish consistent logging and error propagation patterns. "
                "Document error handling conventions for the development team."
            )
        
        return "Review and standardize the implementation across affected components to ensure system coherence."