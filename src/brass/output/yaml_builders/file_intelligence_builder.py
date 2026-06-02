"""
File intelligence builder for file-specific analysis and prioritization.

Generates file-focused YAML reports with priority scoring and context analysis.
Single responsibility: file-level intelligence and prioritization.
"""

from typing import List, Dict, Any
from collections import OrderedDict, defaultdict

from brass.models.finding import Finding, Severity
from .base_builder import BaseYAMLBuilder


class YAMLFileIntelligenceBuilder(BaseYAMLBuilder):
    """
    Builds file intelligence YAML with priority analysis.
    
    Responsible for generating file-specific analysis with priority scoring,
    issue grouping by line number, and file classification data.
    """
    
    def build(self, findings: List[Finding]) -> Dict[str, Any]:
        """
        Build complete file intelligence structure.
        
        Args:
            findings: All findings for file analysis
            
        Returns:
            Complete file intelligence dictionary
        """
        return OrderedDict([
            ('files_by_priority', self._build_files_by_priority(findings))
        ])
    
    def _build_files_by_priority(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Build file-specific analysis with priority and context."""
        by_file = defaultdict(list)
        for finding in findings:
            by_file[finding.file_path].append(finding)
        
        files_data = []
        for file_path, file_findings in by_file.items():
            file_data = self._build_file_analysis(file_path, file_findings)
            files_data.append(file_data)
        
        # Sort by priority score
        files_data.sort(key=lambda x: x['priority_score'], reverse=True)
        return files_data[:20]  # Top 20 files
    
    def _build_file_analysis(self, file_path: str, file_findings: List[Finding]) -> OrderedDict:
        """Build comprehensive analysis for a single file."""
        critical_high_count = len([f for f in file_findings 
                                 if f.severity in [Severity.CRITICAL, Severity.HIGH]])
        total_count = len(file_findings)
        priority_score = critical_high_count * 3 + total_count
        
        issues_by_line = self._group_issues_by_line(file_findings)
        file_classification = self._extract_file_classification(file_findings)
        
        file_data = OrderedDict([
            ('file_path', file_path),
            ('total_issues', total_count),
            ('critical_high_issues', critical_high_count),
            ('priority_score', priority_score),
            ('issues_by_line', issues_by_line)
        ])
        
        if file_classification:
            file_data['file_classification'] = file_classification
        
        return file_data
    
    def _group_issues_by_line(self, file_findings: List[Finding]) -> Dict[int, List[Dict[str, Any]]]:
        """Group file issues by line number for easier navigation.

        Each finding is run through `sanitize_finding_for_serialization`
        so secret-leak / PII findings have their literal value stripped
        from title + description. Without this, file_intelligence.yaml
        would leak the credential string when it groups Bandit B105 /
        SecretsScanner findings by file.
        """
        issues_by_line = defaultdict(list)

        for finding in file_findings:
            finding = self.sanitize_finding_for_serialization(finding)
            line_key = finding.line_number or 0
            issue_data = OrderedDict([
                ('id', finding.id),
                ('type', finding.type.value),
                ('severity', finding.severity.value),
                ('title', finding.title),
                ('description', finding.description)
            ])
            issues_by_line[line_key].append(issue_data)

        return dict(issues_by_line)
    
    def _extract_file_classification(self, file_findings: List[Finding]) -> OrderedDict:
        """Extract file classification if available from findings metadata."""
        if not file_findings:
            return None
        
        # Check first finding for file context metadata
        first_finding = file_findings[0]
        if first_finding.metadata and first_finding.metadata.get('file_context'):
            file_context = first_finding.metadata['file_context']
            return OrderedDict([
                ('file_type', file_context.get('file_type', 'unknown')),
                ('is_test_related', file_context.get('is_test_related', False)),
                ('should_prioritize', file_context.get('should_prioritize', True))
            ])
        
        return None