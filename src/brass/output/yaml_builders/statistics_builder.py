"""
Statistics builder for performance metrics and trend analysis.

Generates comprehensive statistics YAML with distribution metrics,
file analysis, and performance data. Single responsibility: statistical analysis.
"""

from __future__ import annotations  # so `Dict[str, "ScannerStatus"]` resolves under get_type_hints()

from typing import List, Dict, Any, Optional
from collections import OrderedDict, defaultdict

from brass.models.finding import Finding, Severity
from .base_builder import BaseYAMLBuilder
from .yaml_utils import YAMLUtils


class YAMLStatisticsBuilder(BaseYAMLBuilder):
    """
    Builds statistics YAML with comprehensive metrics and analysis.

    Responsible for generating overview statistics, distribution analysis,
    file metrics, performance data, trend analysis, and (loose end #8)
    per-scanner run health.
    """

    def build(
        self,
        findings: List[Finding],
        *,
        scanner_status: Optional[Dict[str, "ScannerStatus"]] = None,
        scan_duration_seconds: Optional[float] = None,
        peak_memory_mb: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Build complete statistics structure.

        Args:
            findings: All findings for statistical analysis
            scanner_status: Optional per-scanner status map. When provided,
                a `scanner_health` section is added with aggregate counts +
                detail on any skipped/errored scanners. Omitted entirely
                when None (backward-compatible: callers that don't track
                status get the same output as before).
            scan_duration_seconds: Optional wall-clock from the orchestrator
                — when provided, performance_metrics emits real
                analysis_duration + files_per_second instead of nulls.
            peak_memory_mb: Optional peak RSS in MB (parent + largest child
                subprocess). When provided, performance_metrics surfaces
                ``peak_memory_mb`` so operators planning CI/laptop runs
                can see real memory cost rather than guessing.

        Returns:
            Complete statistics dictionary
        """
        sections = [
            ('overview', self._build_statistics_overview(findings)),
            ('distribution', self._build_distribution_stats(findings)),
            ('file_metrics', self._build_file_metrics(findings)),
            ('performance_metrics', self._build_performance_metrics(
                findings, scan_duration_seconds, peak_memory_mb)),
            ('trend_analysis', self._build_trend_analysis(findings)),
        ]
        if scanner_status:
            sections.append(('scanner_health', self._build_scanner_health(scanner_status)))
        return OrderedDict(sections)

    @staticmethod
    def _build_scanner_health(scanner_status: Dict[str, "ScannerStatus"]) -> Dict[str, Any]:
        """Aggregate per-scanner status into a YAML-friendly section.

        Emits aggregate counts unconditionally so consumers can rely on the
        shape. `degraded_scanners` lists every non-ok scanner with its
        reason — empty list when all scanners are ok (rather than absent
        key) so the schema stays predictable.
        """
        total = len(scanner_status)
        ok = sum(1 for s in scanner_status.values() if s.status == 'ok')
        skipped = sum(1 for s in scanner_status.values() if s.status == 'skipped')
        errored = sum(1 for s in scanner_status.values() if s.status == 'errored')
        degraded = [
            OrderedDict([
                ('name', s.name),
                ('status', s.status),
                ('reason', s.reason),
                ('duration_sec', round(s.duration_sec, 3)),
            ])
            for s in scanner_status.values()
            if s.is_degraded()
        ]
        # Stable order: errored first (more urgent), then skipped, then by name.
        status_rank = {'errored': 0, 'skipped': 1}
        degraded.sort(key=lambda d: (status_rank.get(d['status'], 9), d['name']))
        return OrderedDict([
            ('total_scanners', total),
            ('ok', ok),
            ('skipped', skipped),
            ('errored', errored),
            ('degraded_scanners', degraded),
        ])
    
    def _build_statistics_overview(self, findings: List[Finding]) -> Dict[str, Any]:
        """Build statistics overview section."""
        stats = YAMLUtils.generate_summary_stats(findings)
        
        return OrderedDict([
            ('total_findings', stats['total_findings']),
            ('files_analyzed', stats['files_analyzed']),
            ('average_confidence', round(stats['avg_confidence'], 3)),
            ('average_impact', round(stats['avg_impact'], 3))
        ])
    
    def _build_distribution_stats(self, findings: List[Finding]) -> Dict[str, Dict[str, int]]:
        """Build distribution statistics across types and scanners."""
        stats = YAMLUtils.generate_summary_stats(findings)
        
        # Add scanner distribution
        by_scanner = defaultdict(int)
        for finding in findings:
            scanner = finding.detected_by or 'unknown'
            by_scanner[scanner] += 1
        
        return OrderedDict([
            ('by_type', stats['by_type']),
            ('by_severity', stats['by_severity']),
            ('by_scanner', dict(by_scanner))
        ])
    
    def _build_file_metrics(self, findings: List[Finding]) -> Dict[str, List[Dict[str, Any]]]:
        """Build file-level metrics and analysis.

        File-path normalization (2026-05-19 YAML review): scanners emit
        file_path in two different conventions — most use a project-
        relative form (`tests/foo.py`), but a handful emit deeper paths
        carrying the project-name segment (`claude-tools/devwatch/
        coppersun_brass/tests/foo.py`). Without normalization, the same
        logical file shows up twice in `by_file` — once with 15
        findings (most_problematic) and once with 1 finding
        (cleanest_files). Normalize to the project-relative form so
        both buckets agree on file identity.
        """
        by_file: Dict[str, List[Finding]] = defaultdict(list)
        for finding in findings:
            by_file[self._normalize_file_path(finding.file_path)].append(finding)

        file_metrics = []
        for file_path, file_findings in by_file.items():
            critical_count = len([f for f in file_findings
                                if f.severity in [Severity.CRITICAL, Severity.HIGH]])
            score = critical_count * 3 + len(file_findings)

            file_metrics.append({
                'file': file_path,
                'issues': len(file_findings),
                'score': score
            })

        file_metrics.sort(key=lambda x: x['score'], reverse=True)

        most_problematic = file_metrics[:5]
        cleanest_files = [f for f in file_metrics if f['issues'] <= 1][-5:]

        return OrderedDict([
            ('most_problematic', most_problematic),
            ('cleanest_files', cleanest_files)
        ])

    def _normalize_file_path(self, file_path: str) -> str:
        """Strip absolute-style prefixes so scanner output collapses by
        logical file identity. If the path is already project-relative
        (no leading `/`, doesn't contain the project_path as a substring)
        leave it alone. Otherwise, slice off everything up to and
        including the project_path.
        """
        if not file_path:
            return file_path
        project_root_name = self.project_path.name
        # Common absolute-or-deep form: ".../coppersun_brass/tests/foo.py"
        # → "tests/foo.py". Use a fast `find` then slice; cheaper than
        # building Path objects per finding.
        marker = f"/{project_root_name}/"
        idx = file_path.find(marker)
        if idx != -1:
            return file_path[idx + len(marker):]
        # Absolute path that doesn't contain the project root name —
        # rare, but strip the leading slash so it doesn't collide on
        # the same root key.
        if file_path.startswith("/"):
            return file_path.lstrip("/")
        return file_path
    
    def _build_performance_metrics(
        self,
        findings: List[Finding],
        scan_duration_seconds: Optional[float] = None,
        peak_memory_mb: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Build performance metrics for analysis speed.

        Real wall-clock timing is threaded in from the CLI orchestrator
        as `scan_duration_seconds` (2026-05-19 YAML review). When absent
        (older callers, isolated builder tests), fall back to null
        rather than a fabricated placeholder so AI consumers can tell
        "we measured" from "we didn't."

        ``peak_memory_mb`` follows the same null-when-unmeasured rule.
        It reflects parent-process RSS plus the largest scanner
        subprocess (pysa/semgrep/etc), so customers see the real RAM
        footprint of a scan instead of the python-only undercount that
        the field carried before 2026-05-20.
        """
        unique_files = len(set(f.file_path for f in findings))
        if scan_duration_seconds is not None and scan_duration_seconds > 0:
            analysis_duration = f"{scan_duration_seconds:.1f}s"
            files_per_second = round(unique_files / scan_duration_seconds, 2)
        else:
            analysis_duration = None
            files_per_second = None
        return OrderedDict([
            ('analysis_duration', analysis_duration),
            ('files_per_second', files_per_second),
            ('findings_per_file', round(len(findings) / max(unique_files, 1), 2)),
            ('peak_memory_mb', round(peak_memory_mb, 1) if peak_memory_mb is not None else None),
        ])
    
    def _build_trend_analysis(self, findings: List[Finding]) -> Dict[str, Dict[str, int]]:
        """Build trend analysis for complexity and confidence patterns."""
        complexity_dist = self._analyze_complexity_trends(findings)
        confidence_dist = self._analyze_confidence_trends(findings)
        
        return OrderedDict([
            ('complexity_distribution', complexity_dist),
            ('security_confidence', confidence_dist)
        ])
    
    def _analyze_complexity_trends(self, findings: List[Finding]) -> Dict[str, int]:
        """Analyze complexity distribution patterns."""
        complexity_findings = [f for f in findings if 'complexity' in f.title.lower()]
        complexity_dist = {'low': 0, 'medium': 0, 'high': 0}
        
        for finding in complexity_findings:
            if finding.severity == Severity.HIGH:
                complexity_dist['high'] += 1
            elif finding.severity == Severity.MEDIUM:
                complexity_dist['medium'] += 1
            else:
                complexity_dist['low'] += 1
        
        return complexity_dist
    
    def _analyze_confidence_trends(self, findings: List[Finding]) -> Dict[str, int]:
        """Analyze confidence distribution in security findings."""
        security_findings = [f for f in findings if f.type.value == 'security']
        confidence_dist = {'high_confidence': 0, 'medium_confidence': 0, 'low_confidence': 0}
        
        for finding in security_findings:
            if finding.confidence >= 0.8:
                confidence_dist['high_confidence'] += 1
            elif finding.confidence >= 0.5:
                confidence_dist['medium_confidence'] += 1
            else:
                confidence_dist['low_confidence'] += 1
        
        return confidence_dist