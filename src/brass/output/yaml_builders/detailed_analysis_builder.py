"""
Detailed analysis builder for comprehensive technical reporting.

Generates detailed technical analysis YAML with type-specific breakdowns
and comprehensive finding details. Single responsibility: detailed technical analysis.
"""

from typing import List, Dict, Any
from collections import OrderedDict, defaultdict

from brass.models.finding import Finding, FindingType
from .base_builder import BaseYAMLBuilder


class YAMLDetailedAnalysisBuilder(BaseYAMLBuilder):
    """
    Builds detailed analysis YAML with comprehensive technical data.
    
    Responsible for generating detailed analysis organized by finding type
    with full technical details and severity breakdowns.
    """
    
    def build(self, findings: List[Finding]) -> Dict[str, Any]:
        """
        Build complete detailed analysis structure.
        
        Args:
            findings: All findings for detailed analysis
            
        Returns:
            Complete detailed analysis dictionary
        """
        return OrderedDict([
            ('analysis_by_type', self._build_analysis_by_type(findings))
        ])
    
    def _build_analysis_by_type(self, findings: List[Finding]) -> Dict[str, Dict[str, Any]]:
        """Build detailed analysis organized by finding type."""
        analysis = OrderedDict()
        
        for finding_type in FindingType:
            type_findings = [f for f in findings if f.type == finding_type]
            if not type_findings:
                continue
            
            severity_breakdown = self._calculate_severity_breakdown(type_findings)
            findings_list = self._build_detailed_findings_list(type_findings)
            
            analysis[finding_type.value] = OrderedDict([
                ('total_count', len(type_findings)),
                ('severity_breakdown', severity_breakdown),
                ('findings', findings_list)
            ])
        
        return analysis
    
    def _calculate_severity_breakdown(self, findings: List[Finding]) -> Dict[str, int]:
        """Calculate severity distribution for findings."""
        severity_breakdown = defaultdict(int)
        for finding in findings:
            severity_breakdown[finding.severity.value] += 1
        return dict(severity_breakdown)
    
    def _build_detailed_findings_list(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Build detailed findings list with all available information."""
        findings_list = []
        
        for finding in findings:
            finding_data = self._build_comprehensive_finding_data(finding)
            findings_list.append(finding_data)
        
        return findings_list
    
    def _build_comprehensive_finding_data(self, finding: Finding) -> OrderedDict:
        """Build comprehensive finding data with all available fields."""
        # CRITICAL: route the whole Finding through
        # sanitize_finding_for_serialization, not just its metadata.
        # Bandit B105/B106/B107 emit the literal credential value in
        # the `title` / `description` fields ("Possible hardcoded
        # password: 'sk_live_...'") — sanitize_metadata_for_serialization
        # only scrubs metadata, leaving the title/description leaks
        # intact. Observed 2026-05-18 on a coppersun_brass scan: 4
        # Stripe sk_live_ keys leaked through to detailed_analysis.yaml
        # despite metadata.secret_redacted being set elsewhere.
        # See project memory "BrassCoders redaction-bypass — recurring leak class".
        finding = self.sanitize_finding_for_serialization(finding)

        finding_data = OrderedDict([
            ('id', finding.id),
            ('severity', finding.severity.value),
            ('file_path', finding.file_path),
            ('title', finding.title),
            ('description', finding.description),
            ('detected_by', finding.detected_by),
            ('confidence', finding.confidence),
            ('impact_score', finding.impact_score)
        ])

        # Add optional location fields
        if finding.line_number:
            finding_data['line_number'] = finding.line_number

        # Add optional enhancement fields
        if finding.remediation:
            finding_data['remediation'] = finding.remediation

        # Metadata already sanitized by the wrapper above — just emit.
        if finding.metadata:
            finding_data['metadata'] = finding.metadata

        return finding_data