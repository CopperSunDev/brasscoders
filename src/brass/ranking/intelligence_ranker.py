"""
IntelligenceRanker - Unified priority ranking system for all findings.

This component takes findings from all scanners and ranks them by importance
for AI consumption, ensuring the most critical issues are prioritized.
"""

import copy
from typing import List, Dict, Optional
from datetime import datetime, timedelta
from dataclasses import replace

from brass.models.finding import Finding, FindingType, Severity
from brass.core.file_classifier import FileClassifier, FileType
from brass.core.logging_config import get_logger

logger = get_logger(__name__)


class _DisabledRegistry:
    """Sentinel used when FrameworkRegistry construction failed once
    so we don't retry for every finding in the same scan."""


class IntelligenceRanker:
    """
    Unified ranking system for all findings from any scanner.
    
    Uses weighted scoring to prioritize findings based on:
    - Severity level
    - Confidence score
    - Impact assessment  
    - Finding type priority
    - File importance
    - Temporal factors (newer findings prioritized)
    - Clustering (related findings get boost)
    """
    
    def __init__(
        self,
        weights: Optional[Dict[str, float]] = None,
        project_path: Optional[str] = None,
    ):
        """
        Initialize IntelligenceRanker for pure ranking logic.

        Args:
            weights: Custom weight configuration for ranking factors.
            project_path: Project root, enables framework-aware severity
                adjustment via FrameworkRegistry. Optional — if omitted,
                no framework adjustment is applied and ranking behaves
                as before (Capability 1 of the algorithmic plan).
        """
        # Framework-aware severity adjustment (Capability 1). Constructed
        # lazily so a project_path=None ranker (used in unit tests) does
        # no extra work.
        self._framework_registry = None
        self._project_path = project_path
        # Lazy-instantiated for risk-bucket classification. Used only by
        # calculate_contextual_risk_level; created on first call to avoid
        # work on rankers that never compute risk summaries.
        self._risk_classifier: Optional[FileClassifier] = None
        # Enhanced weights for contextual prioritization (Smart File Classification impact)
        self.weights = weights or {
            'severity': 0.30,      # Primary factor (reduced to make room for file context)
            'confidence': 0.20,    # How sure we are
            'impact': 0.15,        # Business/security impact (reduced)
            'type_priority': 0.10, # Type of finding (reduced)  
            'file_importance': 0.20, # File criticality (SIGNIFICANTLY INCREASED for contextual prioritization)
            'temporal': 0.05       # Recency boost
        }
        
        # Type priorities (higher = more important)
        self.type_priorities = {
            FindingType.SECURITY: 1.0,      # Highest priority
            FindingType.PRIVACY: 0.95,      # Critical for compliance
            FindingType.ARCHITECTURE: 0.75, # System design issues
            FindingType.CODE_QUALITY: 0.60, # Maintainability
            FindingType.PERFORMANCE: 0.50,  # Optimization
            FindingType.TODO: 0.30          # Development notes
        }
        
        # Severity score mapping
        self.severity_scores = {
            Severity.CRITICAL: 1.0,
            Severity.HIGH: 0.8,
            Severity.MEDIUM: 0.6,
            Severity.LOW: 0.4,
            Severity.INFO: 0.2
        }
        
        logger.info("Intelligence ranker initialized with pure weighted scoring")
    
    def rank_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Rank findings by importance for AI consumption.
        
        Args:
            findings: List of findings from all scanners
            
        Returns:
            Findings sorted by ranking score (highest first)
        """
        if not findings:
            return findings
        
        # Filter out invalid findings
        valid_findings = []
        for item in findings:
            if not isinstance(item, Finding):
                logger.warning(f"Skipping invalid finding object: {type(item)}")
                continue
            valid_findings.append(item)
        
        if not valid_findings:
            # 2026-05-19 audit: today silently returning [] when ALL
            # inputs were malformed cost a multi-day bug chase. Per-item
            # warnings get drowned out at scale; emit a single ERROR
            # naming the input count so the failure is visible in logs
            # even when downstream consumers swallow empty results.
            # Cap-severity pattern (loudness, not silence, on the empty
            # path).
            logger.error(
                "IntelligenceRanker.rank_findings: all %d input findings "
                "were malformed (not Finding instances); returning empty "
                "result. Upstream scanner is likely yielding dicts or "
                "tuples — check scanner output contract.",
                len(findings),
            )
            return []

        # Pre-populate `metadata['file_context']` on each finding from
        # FileClassifier BEFORE scoring. The `_calculate_file_importance`
        # hook at line 286 already reads from `finding.metadata.get
        # ('file_context')` — without this prepopulation step,
        # file_importance always falls back to the legacy text-matching
        # path (line 332), which is far weaker than the classifier's
        # actual output. Net effect: production-code findings now
        # outscore test-file findings at the same severity, instead of
        # tying on text-match heuristics alone.
        #
        # Skipped if no project_path was provided (unit-test rankers
        # without a real filesystem). Existing per-finding
        # `metadata['file_context']` (e.g., from a scanner that
        # pre-classified) is preserved.
        if self._project_path:
            classifier = self._get_risk_classifier()
            for finding in valid_findings:
                if not getattr(finding, 'file_path', None):
                    continue
                if finding.metadata is None:
                    finding.metadata = {}
                if finding.metadata.get('file_context') is not None:
                    continue  # already classified upstream; respect it
                try:
                    file_ctx = classifier.classify_file(finding.file_path)
                    # Store as a plain dict (not the FileContext dataclass
                    # instance) so PyYAML can serialize the metadata when
                    # builders embed it in detailed_analysis.yaml /
                    # file_intelligence.yaml. The scoring path at
                    # `_calculate_smart_file_importance` already supports
                    # this dict shape (line ~341). All consumers in the
                    # downstream YAML pipeline expect `.get()`-style
                    # access, so the dict form matches contract on both
                    # sides.
                    # FileContext exposes is_source_code / is_test_related
                    # / should_prioritize_issues as METHODS (not @property),
                    # so they must be called — assigning the bound method
                    # would produce un-serializable objects in the YAML.
                    finding.metadata['file_context'] = {
                        'file_type': file_ctx.file_type.value,
                        'is_source_code': file_ctx.is_source_code(),
                        'is_test_related': file_ctx.is_test_related(),
                        'should_prioritize': file_ctx.should_prioritize_issues(),
                        'priority_weight': file_ctx.priority_weight,
                        'confidence': file_ctx.confidence,
                    }
                except Exception as exc:  # noqa: BLE001
                    logger.debug(
                        "ranker: file classification failed for %s (%s); "
                        "scoring will fall back to legacy text-matching",
                        finding.file_path, exc,
                    )

        # Framework-aware severity adjustment (Capability 1).
        # Construct lazily so a project_path-less ranker is unaffected.
        framework_registry = self._get_framework_registry()

        # Perf #7: pre-compute clustering index once instead of filtering
        # `all_findings` per-finding-per-call inside the score loop. Was
        # O(N²) (~4M scans on 2000-finding projects); now O(N).
        self._build_clustering_index(valid_findings)

        # Pure ranking logic - no noise reduction (moved to scanner layer)

        # Create immutable copies with ranking metadata for concurrent safety
        ranked_findings_list = []
        for finding in valid_findings:
            # Apply framework-aware severity adjustment BEFORE scoring so
            # the ranker's severity-weighted math uses the adjusted value.
            # Defensive: any registry-side error must never break ranking
            # — silently skip the adjustment for this finding.
            framework_meta = {}
            if framework_registry is not None:
                try:
                    adjusted_severity, framework_meta = framework_registry.adjust_severity(
                        finding.severity,
                        getattr(finding, "file_path", "") or "",
                        snippet=getattr(finding, "code_snippet", None),
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "framework_registry: adjust_severity failed for %s (%s); "
                        "skipping framework adjustment for this finding",
                        getattr(finding, "file_path", "?"), exc,
                    )
                    adjusted_severity = finding.severity
                    framework_meta = {}
                if adjusted_severity != finding.severity:
                    try:
                        finding = replace(finding, severity=adjusted_severity)
                    except (TypeError, AttributeError):
                        adjusted = copy.deepcopy(finding)
                        adjusted.severity = adjusted_severity
                        finding = adjusted

            # Calculate ranking scores
            score = self._calculate_ranking_score(finding, valid_findings)
            factors = self._get_ranking_factors(finding, valid_findings)

            # Create new metadata dictionary combining existing and new data
            existing_metadata = getattr(finding, 'metadata', {}) or {}
            new_metadata = {
                **existing_metadata,  # Preserve existing metadata
                'ranking_score': score,
                'ranking_factors': factors,
            }
            if framework_meta:
                new_metadata['framework_context'] = framework_meta

            # Create new Finding object with updated metadata (immutable operation)
            try:
                # Use replace for dataclass immutability
                ranked_finding = replace(finding, metadata=new_metadata)
            except (TypeError, AttributeError):
                # Fallback for non-dataclass Finding objects
                ranked_finding = copy.deepcopy(finding)
                ranked_finding.metadata = new_metadata

            ranked_findings_list.append(ranked_finding)
        
        # Sort by ranking score (highest first)
        sorted_findings = sorted(ranked_findings_list, key=lambda f: f.metadata['ranking_score'], reverse=True)
        
        # Add position metadata immutably
        final_findings = []
        for i, finding in enumerate(sorted_findings):
            # Create final metadata with position information
            final_metadata = {
                **finding.metadata,
                'ranking_position': i + 1,
                'ranking_percentile': ((len(sorted_findings) - i) / len(sorted_findings)) * 100
            }
            
            # Create final immutable Finding
            try:
                final_finding = replace(finding, metadata=final_metadata)
            except (TypeError, AttributeError):
                final_finding = copy.deepcopy(finding)
                final_finding.metadata = final_metadata
                
            final_findings.append(final_finding)
        
        # Clear per-call clustering index so a stale Counter from a prior
        # rank_findings() call can't leak into a subsequent invocation
        # (e.g. via get_top_findings → rank_findings on a different set).
        self._cluster_index = None

        logger.info(f"Ranked {len(valid_findings)} findings by importance")
        return final_findings
    
    
    def get_top_findings(self, findings: List[Finding], limit: int = 20) -> List[Finding]:
        """Get the top N most important findings."""
        ranked = self.rank_findings(findings)
        return ranked[:limit]
    
    def get_critical_findings(self, findings: List[Finding]) -> List[Finding]:
        """Get only critical and high severity findings."""
        ranked = self.rank_findings(findings)
        return [f for f in ranked if f.is_critical()]
    
    def get_findings_by_type(self, findings: List[Finding], finding_type: FindingType) -> List[Finding]:
        """Get findings of specific type, ranked by importance."""
        type_findings = [f for f in findings if f.type == finding_type]
        return self.rank_findings(type_findings)
    
    def _get_framework_registry(self):
        """Lazy-build the FrameworkRegistry. Returns None when no
        project_path was provided (unit-test path); otherwise caches
        a single registry instance for this ranker."""
        if self._project_path is None:
            return None
        if self._framework_registry is None:
            try:
                from brass.core.framework_registry import FrameworkRegistry
                self._framework_registry = FrameworkRegistry(project_path=self._project_path)
            except Exception as exc:  # noqa: BLE001
                # The registry is a quality-of-life layer; never let a
                # YAML parse error or missing data file break ranking.
                logger.warning(
                    "framework_registry: disabled (%s); ranking will skip "
                    "framework-aware severity adjustment", exc,
                )
                # Sentinel: don't retry per-finding.
                self._framework_registry = _DisabledRegistry()
        if isinstance(self._framework_registry, _DisabledRegistry):
            return None
        return self._framework_registry

    def _calculate_ranking_score(self, finding: Finding, all_findings: List[Finding]) -> float:
        """Calculate weighted ranking score for a finding."""
        
        try:
            # Base scoring factors with type validation
            severity_score = self.severity_scores.get(finding.severity, 0.5)
            confidence_score = getattr(finding, 'confidence', 0.5)
            impact_score = getattr(finding, 'impact_score', 0.5)
            type_score = self.type_priorities.get(finding.type, 0.5)
            
            # Validate all scores are numeric to prevent calculation errors
            for score_name, score_value in [
                ('severity', severity_score), ('confidence', confidence_score),
                ('impact', impact_score), ('type', type_score)
            ]:
                if not isinstance(score_value, (int, float)) or not (0 <= score_value <= 1):
                    logger.warning(f"Invalid {score_name} score {score_value} for finding {finding.id}, using 0.5")
                    if score_name == 'severity':
                        severity_score = 0.5
                    elif score_name == 'confidence':
                        confidence_score = 0.5  
                    elif score_name == 'impact':
                        impact_score = 0.5
                    elif score_name == 'type':
                        type_score = 0.5
            
            # Use Smart File Classification data for enhanced file importance calculation
            # Safe attribute chain access with validation
            file_context = None
            if (hasattr(finding, 'metadata') and 
                isinstance(finding.metadata, dict)):
                file_context = finding.metadata.get('file_context')
            file_score = self._calculate_file_importance(finding.file_path, file_context)
            
            temporal_score = self._calculate_temporal_score(finding)
            
            # Calculate weighted score with error protection
            weighted_score = (
                severity_score * self.weights['severity'] +
                confidence_score * self.weights['confidence'] +
                impact_score * self.weights['impact'] +
                type_score * self.weights['type_priority'] +
                file_score * self.weights['file_importance'] +
                temporal_score * self.weights['temporal']
            )
            
            # Apply clustering boost (findings in same file get slight boost)
            clustering_boost = self._calculate_clustering_boost(finding, all_findings)
            
            # Apply privacy category boost
            privacy_boost = self._calculate_privacy_boost(finding)
            
            final_score = weighted_score + clustering_boost + privacy_boost
            
            # Ensure score stays in reasonable range
            return min(max(final_score, 0.0), 1.0)
            
        except Exception as e:
            logger.warning(f"Error calculating ranking score for finding {finding.id}: {e}")
            # Return default score for malformed findings
            return 0.5
    
    def _calculate_file_importance(self, file_path: str, file_context: Optional[Dict] = None) -> float:
        """Calculate importance score based on file type and location.
        
        Uses Smart File Classification data when available for precise categorization,
        falls back to text matching for backward compatibility.
        
        Args:
            file_path: Path to the file
            file_context: File classification metadata from Smart File Classification System
            
        Returns:
            File importance score (0.0-1.0)
        """
        if file_context:
            return self._calculate_smart_file_importance(file_path, file_context)
        else:
            return self._calculate_legacy_file_importance(file_path)
    
    def _calculate_smart_file_importance(self, file_path: str, file_context) -> float:
        """Calculate importance using Smart File Classification data."""
        # Handle both dict and FileContext object
        if hasattr(file_context, 'priority_weight'):
            base_priority = file_context.priority_weight
            is_source_code = file_context.is_source_code
            file_type = file_context.file_type.value if hasattr(file_context.file_type, 'value') else str(file_context.file_type)
        else:
            # Legacy dict format
            base_priority = file_context.get('priority_weight', 0.5)
            is_source_code = file_context.get('is_source_code', False)
            file_type = file_context.get('file_type', 'unknown')
        
        if is_source_code:
            return self._calculate_source_code_boost(file_path, base_priority)
        elif file_type == 'configuration':
            return min(base_priority + 0.1, 0.8)  # Configuration max 0.8
        else:
            return base_priority
    
    def _calculate_source_code_boost(self, file_path: str, base_priority: float) -> float:
        """Calculate priority boost for source code files based on path patterns."""
        file_path_lower = file_path.lower()
        
        # Critical system files get maximum priority
        if any(critical in file_path_lower for critical in ['main', 'index', 'app', 'server', 'api']):
            return min(base_priority + 0.4, 1.0)
        
        # Security and auth files
        if any(security in file_path_lower for security in ['auth', 'security', 'crypto', 'password']):
            return min(base_priority + 0.35, 1.0)
        
        # Core business logic
        if any(core in file_path_lower for core in ['core', 'model', 'service', 'controller']):
            return min(base_priority + 0.3, 1.0)
        
        # Regular source code files
        return base_priority
    
    def _calculate_legacy_file_importance(self, file_path: str) -> float:
        """Legacy text-based file importance calculation for backward compatibility."""
        file_path_lower = file_path.lower()
        
        # Use file type patterns with decreasing priority
        file_type_priorities = [
            (['main', 'index', 'app', 'server', 'api'], 0.9),
            (['auth', 'security', 'crypto', 'password'], 0.85), 
            (['core', 'model', 'service', 'controller'], 0.8),
            (['config', 'settings', '.env', 'docker'], 0.7),
            (['test', 'spec', '__test__'], 0.3),
            (['doc', 'readme', 'example', 'demo'], 0.2),
            (['build', 'dist', 'node_modules', '.git'], 0.1)
        ]
        
        for patterns, priority in file_type_priorities:
            if any(pattern in file_path_lower for pattern in patterns):
                return priority
        
        return 0.5  # Default importance
    
    def _calculate_temporal_score(self, finding: Finding) -> float:
        """Calculate temporal relevance score (newer findings get boost)."""
        if not hasattr(finding, 'detected_at') or not finding.detected_at:
            return 0.5
        
        now = datetime.now()
        age = now - finding.detected_at
        
        # Boost for recent findings (within last 24 hours)
        if age < timedelta(hours=24):
            return 0.9
        elif age < timedelta(days=7):
            return 0.7
        elif age < timedelta(days=30):
            return 0.5
        else:
            return 0.3
    
    def _calculate_clustering_boost(self, finding: Finding, all_findings: List[Finding]) -> float:
        """Calculate boost for findings clustered in same file.

        Performance: when callers pre-compute file-path counts via
        `_build_clustering_index` and pass them through, this becomes
        O(1). Falls back to O(N) per call when the index is missing,
        which keeps standalone callers correct but slow. The fast path
        is the one exercised by `rank_findings`.
        """
        same_file_count = self._cluster_index_lookup(finding, all_findings) - 1
        if same_file_count >= 5:
            return 0.1
        elif same_file_count >= 3:
            return 0.05
        elif same_file_count >= 1:
            return 0.02
        return 0.0

    def _cluster_index_lookup(self, finding: Finding, all_findings: List[Finding]) -> int:
        """Return the number of findings (including self) sharing this
        finding's file_path. Uses a pre-built index if available.
        """
        cache = getattr(self, "_cluster_index", None)
        if cache is not None:
            return cache.get(finding.file_path, 0)
        # Fallback: linear scan. Only hit by ad-hoc callers that bypass
        # rank_findings; rank_findings always builds the index first.
        return sum(1 for f in all_findings if f.file_path == finding.file_path)

    def _build_clustering_index(self, findings: List[Finding]) -> None:
        """Build file_path → count map once; stash on self for the
        duration of one rank_findings call.
        """
        from collections import Counter
        self._cluster_index = Counter(f.file_path for f in findings)
    
    def _calculate_privacy_boost(self, finding: Finding) -> float:
        """Calculate boost for privacy findings based on category."""
        if finding.type != FindingType.PRIVACY:
            return 0.0
        
        category = finding.privacy_category
        if not category:
            return 0.0
        
        # Critical PII types get extra boost
        critical_categories = ['ssn', 'credit_card', 'password', 'api_key']
        if category in critical_categories:
            return 0.1
        
        # International compliance boost
        if finding.compliance_regions and len(finding.compliance_regions) > 1:
            return 0.05
        
        return 0.0

    def _get_risk_classifier(self) -> FileClassifier:
        """Lazily construct the FileClassifier used for risk bucketing.

        Uses ``self._project_path`` as the project root so absolute
        finding paths get normalized to project-relative form before
        regex matching. ``project_path=None`` is the unit-test fallback
        — the classifier still handles relative paths correctly via
        ``_normalize_path``.
        """
        if self._risk_classifier is None:
            self._risk_classifier = FileClassifier(self._project_path)
        return self._risk_classifier

    def calculate_contextual_risk_level(self, findings: List[Finding]) -> Dict[str, any]:
        """
        Calculate project risk level based on source code vs test file findings.
        
        Uses Smart File Classification to provide accurate risk assessment
        that distinguishes between intentional test data and real source code issues.
        
        Note: This function has legitimate high cyclomatic complexity due to:
        - Multiple risk scoring conditions (critical, medium, low severity paths)
        - Complex statistical breakdown requirements for transparency
        - Contextual file type analysis (source vs test distinction)
        - Rich return structure with detailed assessment data
        This complexity reflects the inherent sophistication of risk assessment
        and should not be broken apart as it would harm comprehensibility.
        
        Returns:
            Dict with risk level, reasoning, and breakdown statistics
        """
        if not findings:
            return {
                'risk_level': 'LOW',
                'risk_score': 0.0,
                'reasoning': 'No findings detected',
                'source_code_findings': 0,
                'test_file_findings': 0,
                'critical_source_issues': 0,
                'overall_assessment': 'Clean project with no detected issues'
            }
        
        # Categorize findings by file type. Buckets:
        #   source_code: SOURCE_CODE (src/, lib/, etc.) — drives risk
        #   test_file:   TEST_FILE / TEST_FIXTURE       — intentional, excluded
        #   other:       UNKNOWN (custom layouts: modal/, services/, etc.) — drives risk
        #   excluded:    BUILD_OUTPUT / CONFIGURATION / DOCUMENTATION — not counted
        #
        # Classification is done via FileClassifier on the finding's
        # file_path, NOT via finding.metadata['file_context']. The
        # metadata dict is only populated by Brass2PrivacyScanner; before
        # this routing change, every other scanner's findings would have
        # fallen through to "other" because the dict was empty — making
        # risk_level depend on which scanner produced the finding rather
        # than where the file lives.
        classifier = self._get_risk_classifier()
        source_code_findings = []
        test_file_findings = []
        other_findings = []
        excluded_count = 0

        for finding in findings:
            file_type = classifier.classify_file(finding.file_path).file_type
            if file_type == FileType.SOURCE_CODE:
                source_code_findings.append(finding)
            elif file_type in (FileType.TEST_FILE, FileType.TEST_FIXTURE):
                test_file_findings.append(finding)
            elif file_type == FileType.UNKNOWN:
                # Custom project layouts (modal/, agents/, worker/, etc.)
                # land here. Without this bucket, projects whose code lives
                # outside the `src/`-style conventions get risk_level=LOW
                # even with dozens of CRITICAL findings (the copper-sun
                # symptom). Counting UNKNOWN as risk-bearing is the fix.
                other_findings.append(finding)
            else:
                # BUILD_OUTPUT / CONFIGURATION / DOCUMENTATION.
                # Configuration code (setup.py, pyproject.toml) and docs
                # are intentionally low-priority — findings there should
                # not drive top-of-report risk_level. Build output should
                # have been filtered upstream; counting here just in case.
                excluded_count += 1

        if excluded_count:
            logger.debug(
                "Risk classification: excluded %d findings in build/config/doc files",
                excluded_count,
            )

        # Risk = source-code + custom-layout findings. Test-bucket and
        # build/config/doc findings are intentionally excluded.
        risk_findings = source_code_findings + other_findings
        critical_source_issues = [f for f in risk_findings if f.severity in [Severity.CRITICAL, Severity.HIGH]]
        medium_source_issues = [f for f in risk_findings if f.severity == Severity.MEDIUM]
        
        # Risk scoring based on actual source code problems
        risk_score = 0.0
        if critical_source_issues:
            risk_score += len(critical_source_issues) * 0.4  # Each critical issue adds significant risk
        if medium_source_issues:
            risk_score += len(medium_source_issues) * 0.2   # Medium issues add moderate risk
        
        # Risk level determination. Messaging uses `risk_findings` (the
        # source+other lump) for counts so the user-facing reasoning matches
        # the math above. Test files remain excluded from the count for the
        # same reason they're excluded from the score: their findings are
        # intentional fixture data.
        if risk_score >= 1.0:
            risk_level = 'HIGH'
            reasoning = f'{len(critical_source_issues)} critical/high issues require immediate attention'
        elif risk_score >= 0.5:
            risk_level = 'MEDIUM'
            # Safe array access: extract severity description before using in f-string
            severity_desc = medium_source_issues[0].severity.value if medium_source_issues else "low"
            reasoning = f'{len(risk_findings)} source-or-app issues detected, mostly {severity_desc} severity'
        elif len(risk_findings) > 0:
            risk_level = 'LOW'
            reasoning = f'{len(risk_findings)} minor issues, no critical problems'
        else:
            risk_level = 'LOW'
            reasoning = 'No non-test issues detected (test file issues are intentional)'

        # Overall assessment
        if len(test_file_findings) > len(risk_findings) * 5:
            overall_assessment = f'Comprehensive test coverage detected ({len(test_file_findings)} test findings vs {len(risk_findings)} non-test issues)'
        elif len(risk_findings) == 0:
            overall_assessment = 'Clean non-test code - all findings are in test files (intentional test data)'
        else:
            overall_assessment = f'Code requires attention: {len(critical_source_issues)} critical, {len(medium_source_issues)} medium priority issues'
        
        return {
            'risk_level': risk_level,
            'risk_score': min(risk_score, 2.0),  # Cap at 2.0 for extreme cases
            'reasoning': reasoning,
            'source_code_findings': len(source_code_findings),
            'test_file_findings': len(test_file_findings),
            'critical_source_issues': len(critical_source_issues),
            'medium_source_issues': len(medium_source_issues),
            'overall_assessment': overall_assessment,
            'breakdown': {
                'source_code_issues': len(source_code_findings),
                'test_file_issues': len(test_file_findings),
                'other_issues': len(other_findings),
                'total_findings': len(findings)
            }
        }
    
    def _get_ranking_factors(self, finding: Finding, all_findings: List[Finding]) -> Dict[str, float]:
        """Get detailed breakdown of ranking factors for transparency."""
        file_context = finding.metadata.get('file_context')
        return {
            'severity_score': self.severity_scores.get(finding.severity, 0.5),
            'confidence_score': finding.confidence,
            'impact_score': finding.impact_score,
            'type_score': self.type_priorities.get(finding.type, 0.5),
            'file_score': self._calculate_file_importance(finding.file_path, file_context),
            'temporal_score': self._calculate_temporal_score(finding),
            'clustering_boost': self._calculate_clustering_boost(finding, all_findings),
            'privacy_boost': self._calculate_privacy_boost(finding)
        }
    
    def generate_ranking_report(self, findings: List[Finding]) -> Dict:
        """
        Generate detailed ranking analysis report.
        
        Note: This function has moderate cyclomatic complexity due to:
        - Statistical aggregation across multiple enum types (FindingType, Severity)
        - Conditional processing for categories that have findings
        - Complex statistical calculations (averages, maximums, counts)
        This complexity is appropriate for a comprehensive reporting function
        and breaking it apart would make the statistical logic harder to follow.
        """
        ranked_findings = self.rank_findings(findings)
        
        # Statistics by type
        type_stats = {}
        for finding_type in FindingType:
            type_findings = [f for f in ranked_findings if f.type == finding_type]
            if type_findings:
                type_stats[finding_type.value] = {
                    'count': len(type_findings),
                    'avg_score': sum(f.metadata['ranking_score'] for f in type_findings) / len(type_findings) if type_findings else 0.0,
                    'top_score': max(f.metadata['ranking_score'] for f in type_findings)
                }
        
        # Statistics by severity
        severity_stats = {}
        for severity in Severity:
            severity_findings = [f for f in ranked_findings if f.severity == severity]
            if severity_findings:
                severity_stats[severity.value] = {
                    'count': len(severity_findings),
                    'avg_score': sum(f.metadata['ranking_score'] for f in severity_findings) / len(severity_findings) if severity_findings else 0.0
                }
        
        return {
            'total_findings': len(ranked_findings),
            'avg_ranking_score': sum(f.metadata['ranking_score'] for f in ranked_findings) / len(ranked_findings) if ranked_findings else 0,
            'top_10_avg_score': sum(f.metadata['ranking_score'] for f in ranked_findings[:10]) / min(10, len(ranked_findings)) if ranked_findings else 0,
            'type_statistics': type_stats,
            'severity_statistics': severity_stats,
            'weights_used': self.weights
        }