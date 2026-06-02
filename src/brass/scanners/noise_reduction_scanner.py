"""
NoiseReductionScanner - Brass2-compliant finding noise filtering.

This scanner implements intelligent noise reduction for findings that cannot be
prefiltered at the file level, following Brass2 single responsibility principles.
"""

import re
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass

from brass.models.finding import Finding, FindingType, Severity
from brass.core.logging_config import get_logger

logger = get_logger(__name__)


@dataclass 
class NoiseReductionStats:
    """Statistics for noise reduction effectiveness."""
    original_count: int
    filtered_count: int
    reduction_percentage: float
    filters_applied: Dict[str, int]


class NoiseReductionScanner:
    """
    Brass2-compliant scanner for finding noise reduction.
    
    Follows single responsibility principle - only handles finding analysis
    and filtering. Does not perform ranking or output generation.
    """
    
    def __init__(self, project_path: str, max_findings_per_file: int = 15) -> None:
        """
        Initialize NoiseReductionScanner.
        
        Args:
            project_path: Root path of project for internal module detection
            max_findings_per_file: Maximum findings to keep per file (default: 15)
        """
        if not project_path:
            raise ValueError("Project path cannot be empty or None")
            
        self.project_path = Path(project_path).resolve()
        if not self.project_path.exists():
            raise FileNotFoundError(f"Project path does not exist: {self.project_path}")
        
        # Evidence-based confidence thresholds (simplified from complex config)
        self.confidence_thresholds = {
            FindingType.SECURITY: 0.65,      # High threshold for security
            FindingType.CODE_QUALITY: 0.55,  # Filter low-confidence style noise
            FindingType.PRIVACY: 0.75,       # Privacy detection should be reliable
            FindingType.TODO: 0.4,           # TODO detection is straightforward
            FindingType.PERFORMANCE: 0.6,    # Performance issues need validation
            FindingType.ARCHITECTURE: 0.7    # Architecture findings are complex
        }
        
        # Style-only codes to suppress (evidence from real analysis)
        self.style_only_codes = {
            'C0103', 'C0301', 'C0304', 'C0305', 'C0326',  # Pylint style
            'R0903', 'R0801', 'W0613'                       # Pylint refactor/warnings
        }
        
        # Configurable per-file limit (evidence: prevents overwhelming output)
        self.max_findings_per_file = max_findings_per_file

        # Build internal module patterns for package hallucination detection
        self.internal_patterns = self._build_internal_patterns()

        # Stats tracking
        self.stats = None

        # 2026-05-21 audit follow-up (silent-drop class): when the
        # per-file "other" bucket cap trims LOW/MEDIUM-priority
        # findings, the count never surfaced anywhere. Most of these
        # drops ARE the cap doing its job (the file is genuinely
        # dense), but on a problem scan an operator needs the number
        # to know whether the cap is shadowing real coverage. The
        # priority bucket already logs at line 340-346 when it
        # truncates; this counter is the parallel observability for
        # the non-priority side. Summed across all files in a scan,
        # emitted as a single INFO line at scan() end when > 0.
        self._other_bucket_dropped: int = 0
        
        logger.info(f"NoiseReductionScanner initialized for {self.project_path}")
    
    def scan(self, input_findings: List[Finding]) -> List[Finding]:
        """
        Scan findings and remove noise while preserving critical issues.
        
        Args:
            input_findings: Findings from other scanners to filter
            
        Returns:
            List of filtered findings with noise removed
        """
        # Reset per-scan counter so a re-used scanner instance doesn't
        # report a previous scan's drops in this scan's summary. Must
        # run BEFORE the empty-input early-return — otherwise a
        # sequence of "scan(big batch)" → "scan([])" → "scan(small
        # batch)" leaks the first scan's counter into the third
        # scan's summary log.
        self._other_bucket_dropped = 0

        if not input_findings:
            return input_findings

        original_count = len(input_findings)
        filters_applied = {}

        logger.info(f"Applying noise reduction to {original_count} findings")

        try:
            # Stage 1: Confidence filtering
            high_confidence = self._filter_by_confidence(input_findings)
            filters_applied['confidence'] = original_count - len(high_confidence)
            
            # Stage 2: Package hallucination filtering  
            real_packages = self._filter_package_hallucinations(high_confidence)
            filters_applied['package_hallucination'] = len(high_confidence) - len(real_packages)
            
            # Stage 3: Style issue filtering
            non_style = self._filter_style_issues(real_packages)
            filters_applied['style_issues'] = len(real_packages) - len(non_style)
            
            # Stage 4: Per-file limits
            final_findings = self._apply_per_file_limits(non_style)
            filters_applied['per_file_limits'] = len(non_style) - len(final_findings)
            
            # Calculate statistics
            filtered_count = len(final_findings)
            reduction_percentage = ((original_count - filtered_count) / original_count) * 100 if original_count > 0 else 0
            
            self.stats = NoiseReductionStats(
                original_count=original_count,
                filtered_count=filtered_count,
                reduction_percentage=reduction_percentage,
                filters_applied=filters_applied
            )
            
            logger.info(f"Noise reduction: {original_count} → {filtered_count} "
                       f"({reduction_percentage:.1f}% reduction)")

            # Surface "other" bucket per-file cap drops as a single
            # aggregate so an operator investigating "why did X not
            # appear?" can spot whether the cap is in play. Priority
            # bucket already logs per-file at line 340-346.
            if self._other_bucket_dropped > 0:
                logger.info(
                    "NoiseReductionScanner per-file 'other' bucket cap "
                    "trimmed %d non-priority finding(s) across all files "
                    "(per-file cap = %d). Set BRASS_MAX_FINDINGS_PER_FILE "
                    "higher to retain more.",
                    self._other_bucket_dropped,
                    self.max_findings_per_file,
                )

            return final_findings
            
        except Exception as e:
            logger.error(f"Noise reduction failed: {e}")
            # Return original findings rather than crash
            return input_findings
    
    def _build_internal_patterns(self) -> List[str]:
        """Build patterns for detecting internal modules (package hallucination prevention)."""
        try:
            project_name = self.project_path.name.lower()
            
            # Common internal module patterns (evidence-based)
            patterns = []
            
            # Main project modules - validate regex compilation
            try:
                project_pattern = rf'^{re.escape(project_name)}\..*'
                re.compile(project_pattern)  # Validate pattern compiles
                patterns.append(project_pattern)
            except re.error as e:
                logger.warning(f"Invalid regex pattern for project '{project_name}': {e}")
                # Use safer literal matching fallback
                patterns.append(f'^{project_name}\\.')  # Simple literal prefix
            
            # Standard patterns (known safe)
            patterns.extend([
                r'^\..*',                                # Relative imports  
                r'^src\..*',                            # src-based imports
                r'^tests?\..*',                         # test modules
            ])
            
            logger.debug(f"Built {len(patterns)} internal module patterns")
            return patterns
            
        except Exception as e:
            logger.warning(f"Error building internal patterns: {e}")
            return []
    
    def _filter_by_confidence(self, findings: List[Finding]) -> List[Finding]:
        """Filter findings below confidence thresholds."""
        filtered = []
        
        for finding in findings:
            threshold = self.confidence_thresholds.get(finding.type, 0.5)
            
            # Always preserve critical findings
            if finding.severity == Severity.CRITICAL:
                filtered.append(finding)
                continue
                
            # Apply confidence threshold
            if finding.confidence >= threshold:
                filtered.append(finding)
        
        return filtered
    
    def _filter_package_hallucinations(self, findings: List[Finding]) -> List[Finding]:
        """Filter false positive package hallucinations for internal modules."""
        if not self.internal_patterns:
            return findings
            
        filtered = []
        
        for finding in findings:
            # Only process package hallucination findings
            if 'package_hallucination' not in finding.id:
                filtered.append(finding)
                continue
            
            # Extract package name
            package_name = self._extract_package_name_from_finding(finding)
            if not package_name:
                filtered.append(finding)  # Keep if can't determine
                continue
            
            # Check if it's an internal module
            is_internal = any(re.match(pattern, package_name) for pattern in self.internal_patterns)
            
            if not is_internal:
                filtered.append(finding)
                
        return filtered
    
    def _extract_package_name_from_finding(self, finding: Finding) -> Optional[str]:
        """Extract package name from package hallucination finding metadata or content."""
        # Try metadata first - safe dictionary access with validation
        if (hasattr(finding, 'metadata') and 
            isinstance(finding.metadata, dict) and 
            'package_name' in finding.metadata):
            return finding.metadata['package_name']
        
        # Extract from title
        if 'Package Hallucination:' in finding.title:
            return finding.title.split('Package Hallucination:')[1].strip()
        
        # Extract from ID with safe list access
        if 'package_hallucination_' in finding.id:
            parts = finding.id.split('_')
            if len(parts) >= 4:  # Ensure minimum required parts for safe slicing
                return '_'.join(parts[2:-1])  # Exclude prefix and line number
            elif len(parts) >= 3:
                # Handle shorter IDs with just prefix_name_line format
                return parts[2]
            else:
                logger.warning(f"Malformed package hallucination ID: {finding.id}")
                return None
        
        return None
    
    def _filter_style_issues(self, findings: List[Finding]) -> List[Finding]:
        """Filter pure style/formatting issues."""
        filtered = []
        
        for finding in findings:
            # Only process Pylint findings
            if getattr(finding, 'detected_by', '') != 'pylint':
                filtered.append(finding)
                continue
            
            # Check if it's a pure style issue
            is_style_only = any(
                code in finding.description or code in finding.title 
                for code in self.style_only_codes
            )
            
            if not is_style_only:
                filtered.append(finding)
        
        return filtered
    
    def _apply_per_file_limits(self, findings: List[Finding]) -> List[Finding]:
        """Apply per-file finding limits to prevent overwhelming output.

        Security and privacy findings are exempted from the cap: a file
        with 30 distinct SECURITY hits is by definition a hot spot the
        user wants to see in full, not a noise issue. The cap targets
        CODE_QUALITY / TODO / PERFORMANCE / ARCHITECTURE / ANALYSIS_ERROR
        — the categories where one file can legitimately spew dozens of
        low-value findings. Without this exemption, pylint findings
        (post-#78b fix, now with non-zero confidence) crowd out
        same-severity bandit security findings on dense vulnerable
        files like bandit_examples/subprocess_shell.py — silently
        dropping required documented vulnerabilities.
        """
        file_findings = {}

        # Group findings by file
        for finding in findings:
            file_path = finding.file_path
            if file_path not in file_findings:
                file_findings[file_path] = []
            file_findings[file_path].append(finding)

        # Apply limits per file with a two-tier cap. SECURITY, PRIVACY,
        # and ANALYSIS_ERROR get a MUCH MORE GENEROUS cap (10x normal)
        # but are not unbounded — a vendored webpack-bundle.js with
        # 800 secrets-scanner hits or generated boilerplate flagging
        # hundreds of B104-equivalents would otherwise flood downstream
        # consumers unconditionally. The 10x multiplier preserves the
        # "hot spot visibility" intent (a real vuln-cluster of 30
        # findings still surfaces in full at the default cap of 15)
        # while bounding pathological cases.
        priority_types = {
            FindingType.SECURITY,
            FindingType.PRIVACY,
            FindingType.ANALYSIS_ERROR,
        }
        # Multiplier kept as a named constant so the relationship is
        # easy to tune later (e.g. raise to 20x if a customer hits the
        # cap on a real codebase, or lower to 5x if noise complaints
        # come in). When max_findings_per_file is 0 (an edge case
        # meaning "drop ALL low-value noise"), priority findings are
        # treated as unbounded — preserving the historical contract
        # where cap=0 dropped noise but never touched SECURITY/PRIVACY.
        PRIORITY_CAP_MULTIPLIER = 10
        if self.max_findings_per_file <= 0:
            priority_cap = float('inf')
        else:
            priority_cap = self.max_findings_per_file * PRIORITY_CAP_MULTIPLIER

        def _cap_sort_key(f):
            return (
                self._severity_to_int(f.severity),
                self._type_to_int(f.type),
                f.confidence,
                getattr(f, 'impact_score', 0),
            )

        limited = []
        # 2026-05-19 audit: CRITICAL CODE_QUALITY findings (notably
        # syntax errors emitted by the AST scanner) are ship-blocking
        # — the file can't even be imported. They route through the
        # priority bucket (10x cap) instead of the standard 15-cap so
        # a generated-code dump can't displace them. Same cap-severity
        # pattern as the typed-block sort fix today.
        def _is_priority(f):
            return (
                f.type in priority_types
                or (f.type == FindingType.CODE_QUALITY and f.severity == Severity.CRITICAL)
            )

        for file_path, file_findings_list in file_findings.items():
            priority = [f for f in file_findings_list if _is_priority(f)]
            other = [f for f in file_findings_list if not _is_priority(f)]

            # Priority bucket gets the generous 10x cap, sorted by the
            # same (severity, type-priority, confidence, impact) key as
            # the non-priority bucket. On normal files (< 150 priority
            # findings) this is a no-op.
            if len(priority) <= priority_cap:
                limited.extend(priority)
            else:
                logger.warning(
                    "Per-file priority cap reached on %s: %d priority "
                    "findings exceed %d budget; trimming to top %d by "
                    "severity / confidence. Suggests file is generated "
                    "/ vendored noise rather than a real hot spot.",
                    file_path, len(priority), priority_cap, priority_cap,
                )
                sorted_priority = sorted(priority, key=_cap_sort_key, reverse=True)
                limited.extend(sorted_priority[:priority_cap])

            # Apply the standard cap to the non-priority bucket.
            if len(other) <= self.max_findings_per_file:
                limited.extend(other)
                continue

            # Sort by severity, then finding-type priority, then
            # confidence, then impact, take top N.
            sorted_other = sorted(other, key=_cap_sort_key, reverse=True)

            # Track drops for end-of-scan observability. The cap is
            # working as designed in nearly all cases — the LOG line
            # at scan() end matters only when an operator is
            # investigating "why did finding X not appear?"
            self._other_bucket_dropped += len(sorted_other) - self.max_findings_per_file
            limited.extend(sorted_other[:self.max_findings_per_file])

        return limited

    def _severity_to_int(self, severity: Severity) -> int:
        """Convert severity to integer for sorting."""
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0
        }.get(severity, 0)

    def _type_to_int(self, finding_type: FindingType) -> int:
        """Convert finding type to integer for sorting tiebreakers in
        the per-file cap. Higher = preferred when severity ties.

        Calibrated so security and privacy beat code-quality / TODO
        noise — matches user priority ("security first") when N
        scanners all flag the same file and the per-file cap has to
        choose. Without this, pylint's higher mapped confidence (0.85
        for `error`) would outrank a bandit HIGH at confidence 0.65 on
        same-severity tied files, hiding the real vulnerability.

        Unknown / new FindingType values get a defensible default of 0
        (same tier as CODE_QUALITY) but a warning is logged so a future
        contributor adding a new type doesn't silently get
        code-quality priority without an explicit decision.
        """
        ranking = {
            FindingType.SECURITY: 5,
            FindingType.PRIVACY: 4,
            FindingType.PERFORMANCE: 3,
            FindingType.ARCHITECTURE: 2,
            FindingType.CODE_QUALITY: 1,
            FindingType.TODO: 0,
            FindingType.ANALYSIS_ERROR: -1,
        }
        if finding_type not in ranking:
            logger.warning(
                "Unknown FindingType %r in _type_to_int — defaulting to "
                "CODE_QUALITY priority. Update _type_to_int to assign "
                "the right tier when adding new FindingType values.",
                finding_type,
            )
        return ranking.get(finding_type, 0)
    
    def get_stats(self) -> Optional[NoiseReductionStats]:
        """Get noise reduction statistics from last scan."""
        return self.stats