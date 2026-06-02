"""
YAMLOutputGenerator - Generate AI-optimized YAML intelligence files.

This component replaces the Markdown-based output system with structured YAML files
optimized for AI consumption, providing direct deserialization and schema validation.
"""

import yaml
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
from collections import defaultdict, OrderedDict

from brass.models.finding import Finding, FindingType, Severity
from brass.core.logging_config import get_logger

logger = get_logger(__name__)


class YAMLOutputGenerator:
    """
    Generate AI-optimized YAML intelligence files from ranked findings.
    
    Creates structured, schema-validated YAML files that provide optimal
    context for Claude Code and other AI coding assistants including:
    - AI instructions with hierarchical structure
    - Detailed technical analysis with type safety
    - File-specific intelligence with priority scoring
    - Security and privacy reports with compliance data
    - Statistics with performance metrics
    """
    
    def __init__(self, project_path: str, output_dir: str = ".brass", ranker: Optional[Any] = None):
        """
        Initialize YAMLOutputGenerator.
        
        Args:
            project_path: Root path of project being analyzed
            output_dir: Directory name for output files (default: .brass)
            ranker: IntelligenceRanker instance for contextual risk assessment
        """
        self.project_path = Path(project_path).resolve()
        self.output_dir = self.project_path / output_dir
        self.generation_time = datetime.now()
        self.ranker = ranker
        
        logger.info(f"YAML output generator initialized for {self.project_path}")
    
    def generate_intelligence(self, findings: List[Finding]) -> Dict[str, str]:
        """
        Generate complete YAML intelligence output for AI consumption.
        
        Args:
            findings: Ranked findings from all scanners
            
        Returns:
            Dictionary mapping file names to file paths created
        """
        # Ensure output directory exists
        self.output_dir.mkdir(exist_ok=True)
        
        generated_files = {}
        
        # Generate AI instructions YAML
        ai_instructions_path = self._generate_ai_instructions_yaml(findings)
        generated_files['ai_instructions'] = str(ai_instructions_path)
        
        # Generate detailed analysis YAML
        analysis_path = self._generate_detailed_analysis_yaml(findings)
        generated_files['detailed_analysis'] = str(analysis_path)
        
        # Generate file intelligence YAML
        file_intelligence_path = self._generate_file_intelligence_yaml(findings)
        generated_files['file_intelligence'] = str(file_intelligence_path)
        
        # Generate security report YAML
        security_path = self._generate_security_report_yaml(findings)
        generated_files['security_report'] = str(security_path)
        
        # Generate privacy report YAML (if privacy findings exist)
        privacy_findings = [f for f in findings if f.type == FindingType.PRIVACY]
        if privacy_findings:
            privacy_path = self._generate_privacy_report_yaml(privacy_findings)
            generated_files['privacy_report'] = str(privacy_path)
        
        # Generate statistics YAML
        stats_path = self._generate_statistics_yaml(findings)
        generated_files['statistics'] = str(stats_path)
        
        logger.info(f"Generated {len(generated_files)} YAML intelligence files")
        return generated_files
    
    def _generate_ai_instructions_yaml(self, findings: List[Finding]) -> Path:
        """Generate AI instructions YAML optimized for AI consumption."""
        
        # Build structured data
        data = OrderedDict([
            ('metadata', self._build_metadata(findings)),
            ('executive_summary', self._build_executive_summary(findings)),
            ('critical_issues', self._build_critical_issues(findings)),
            ('findings_by_category', self._build_findings_by_category(findings)),
            ('ai_guidance', self._build_ai_guidance(findings)),
            ('file_priorities', self._build_file_priorities(findings)),
            ('quick_actions', self._build_quick_actions(findings))
        ])
        
        # Write YAML file
        file_path = self.output_dir / "ai_instructions.yaml"
        self._write_yaml_file(file_path, data)
        
        return file_path
    
    def _generate_detailed_analysis_yaml(self, findings: List[Finding]) -> Path:
        """Generate detailed technical analysis YAML."""
        
        data = OrderedDict([
            ('metadata', self._build_metadata(findings)),
            ('analysis_by_type', self._build_analysis_by_type(findings))
        ])
        
        file_path = self.output_dir / "detailed_analysis.yaml"
        self._write_yaml_file(file_path, data)
        
        return file_path
    
    def _generate_file_intelligence_yaml(self, findings: List[Finding]) -> Path:
        """Generate file-specific intelligence YAML."""
        
        data = OrderedDict([
            ('metadata', self._build_metadata(findings)),
            ('files_by_priority', self._build_files_by_priority(findings))
        ])
        
        file_path = self.output_dir / "file_intelligence.yaml"
        self._write_yaml_file(file_path, data)
        
        return file_path
    
    def _generate_security_report_yaml(self, findings: List[Finding]) -> Path:
        """Generate security-focused analysis YAML."""
        security_findings = [f for f in findings if f.type == FindingType.SECURITY]
        
        data = OrderedDict([
            ('metadata', self._build_metadata(findings)),
            ('security_overview', self._build_security_overview(security_findings)),
            ('critical_vulnerabilities', self._build_critical_vulnerabilities(security_findings)),
            ('vulnerability_categories', self._build_vulnerability_categories(security_findings))
        ])
        
        file_path = self.output_dir / "security_report.yaml"
        self._write_yaml_file(file_path, data)
        
        return file_path
    
    def _generate_privacy_report_yaml(self, privacy_findings: List[Finding]) -> Path:
        """Generate privacy and PII analysis YAML."""
        
        data = OrderedDict([
            ('metadata', self._build_metadata(privacy_findings)),
            ('privacy_overview', self._build_privacy_overview(privacy_findings)),
            ('pii_categories', self._build_pii_categories(privacy_findings)),
            ('compliance_analysis', self._build_compliance_analysis(privacy_findings))
        ])
        
        file_path = self.output_dir / "privacy_analysis.yaml"
        self._write_yaml_file(file_path, data)
        
        return file_path
    
    def _generate_statistics_yaml(self, findings: List[Finding]) -> Path:
        """Generate comprehensive statistics YAML."""
        
        data = OrderedDict([
            ('metadata', self._build_metadata(findings)),
            ('overview', self._build_statistics_overview(findings)),
            ('distribution', self._build_distribution_stats(findings)),
            ('file_metrics', self._build_file_metrics(findings)),
            ('performance_metrics', self._build_performance_metrics(findings)),
            ('trend_analysis', self._build_trend_analysis(findings))
        ])
        
        file_path = self.output_dir / "statistics.yaml"
        self._write_yaml_file(file_path, data)
        
        return file_path
    
    def _build_metadata(self, findings: List[Finding]) -> Dict[str, Any]:
        """Build metadata section common to all files."""
        return OrderedDict([
            ('generated_at', self.generation_time.isoformat()),
            ('project_path', str(self.project_path)),
            ('analysis_engine', 'brass v2'),
            ('total_findings', len(findings))
        ])
    
    def _build_executive_summary(self, findings: List[Finding]) -> Dict[str, Any]:
        """Build executive summary with contextual risk assessment."""
        stats = self._generate_summary_stats(findings)
        
        # Calculate risk level
        if self.ranker and hasattr(self.ranker, 'calculate_contextual_risk_level'):
            risk_assessment = self.ranker.calculate_contextual_risk_level(findings)
            risk_level = risk_assessment['risk_level']
            recommendation = risk_assessment['reasoning']
        else:
            # Fallback risk assessment
            critical_count = stats['by_severity'].get('critical', 0)
            high_count = stats['by_severity'].get('high', 0)
            
            if critical_count > 0 or high_count >= 5:
                risk_level = "HIGH"
                recommendation = "Immediate attention required"
            elif high_count > 0 or stats['total_findings'] >= 10:
                risk_level = "MEDIUM"
                recommendation = "Review and address key issues"
            else:
                risk_level = "LOW"
                recommendation = "Monitor and maintain current practices"
        
        return OrderedDict([
            ('risk_level', risk_level),
            ('recommendation', recommendation),
            ('total_findings', stats['total_findings']),
            ('files_analyzed', stats['files_analyzed']),
            ('average_confidence', round(stats['avg_confidence'], 3)),
            ('average_impact', round(stats['avg_impact'], 3))
        ])
    
    def _build_critical_issues(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Build critical issues list with structured data.

        Cap audit (2026-05-19): `is_critical()` is True for both CRITICAL
        and HIGH; the 10-slot cap was being filled in input order
        (post-enrichment rank_score desc), so HIGH-severity findings
        ranked ahead by the gateway could crowd out true CRITICALs. Sort
        severity-first to guarantee CRITICALs fill the cap before HIGHs.
        """
        sorted_findings = sorted(
            [f for f in findings if f.is_critical()],
            key=lambda f: 0 if f.severity == Severity.CRITICAL else 1,
        )
        critical_findings = sorted_findings[:10]
        
        issues = []
        for finding in critical_findings:
            issue = OrderedDict([
                ('id', finding.id),
                ('type', finding.type.value),
                ('severity', finding.severity.value),
                ('file_path', finding.file_path),
                ('title', finding.title),
                ('description', finding.description),
                ('confidence', finding.confidence),
                ('impact_score', finding.impact_score),
                ('detected_by', finding.detected_by)
            ])
            
            # Add optional fields
            if finding.line_number:
                issue['line_number'] = finding.line_number
            if finding.column:
                issue['column'] = finding.column
            if finding.remediation:
                issue['remediation'] = finding.remediation
            if finding.code_snippet:
                issue['code_snippet'] = finding.code_snippet
            if finding.references:
                issue['references'] = finding.references
            
            # Add privacy-specific data
            if finding.is_privacy_related():
                if finding.privacy_category:
                    issue['privacy_category'] = finding.privacy_category
                if finding.compliance_regions:
                    issue['compliance_regions'] = finding.compliance_regions
            
            issues.append(issue)
        
        return issues
    
    def _build_findings_by_category(self, findings: List[Finding]) -> Dict[str, List[Dict[str, Any]]]:
        """Build findings organized by category with production vs test context."""
        categories = {}
        
        for finding_type in FindingType:
            # 2026-05-19 audit: severity-first sort before slice so a
            # CRITICAL of this type isn't silently dropped on enrichment
            # rank ties. Cap-severity pattern (mirrors output_generator.py).
            type_findings = sorted(
                [f for f in findings if f.type == finding_type],
                key=lambda f: 0 if f.severity == Severity.CRITICAL else 1,
            )[:5]  # Top 5 per type
            if type_findings:
                category_findings = []
                for finding in type_findings:
                    finding_data = OrderedDict([
                        ('id', finding.id),
                        ('title', finding.title),
                        ('location', finding.get_location_string()),
                        ('severity', finding.severity.value),
                        ('confidence', finding.confidence)
                    ])
                    
                    # File-role classification: single source of truth is
                    # FileClassifier (knows about .next/, __tests__/, docs/,
                    # archives, etc.). The substring fallbacks this replaces
                    # were a major source of FPs on TS/JS projects.
                    finding_data['context'] = self._build_file_role_context(finding.file_path)

                    category_findings.append(finding_data)
                categories[finding_type.value] = category_findings

    def _build_file_role_context(self, file_path: str):
        """Single source of truth for file-role (production vs test/
        fixture/build/docs). See ai_instructions_builder for the same
        logic — these two writers share the same need.
        """
        from collections import OrderedDict
        from brass.core.file_classifier import FileClassifier, FileType

        if not hasattr(self, '_file_classifier'):
            # Pass project_path so absolute paths in findings get
            # normalized to project-relative before pattern matching.
            self._file_classifier = FileClassifier(
                project_root=str(getattr(self, 'project_path', '.'))
            )
        context = self._file_classifier.classify_file(file_path)

        is_production = context.file_type == FileType.SOURCE_CODE
        if context.file_type == FileType.SOURCE_CODE:
            priority = 'HIGH'
        elif context.file_type in (FileType.TEST_FILE, FileType.TEST_FIXTURE):
            priority = 'LOW'
        elif context.file_type == FileType.BUILD_OUTPUT:
            priority = 'LOW'
        elif context.file_type == FileType.DOCUMENTATION:
            priority = 'LOW'
        else:
            priority = 'MEDIUM'

        return OrderedDict([
            ('file_type', context.file_type.value),
            ('is_production_code', is_production),
            ('priority_for_ai', priority),
        ])
        
        return categories
    
    def _build_ai_guidance(self, findings: List[Finding]) -> Dict[str, List[str]]:
        """Build AI-specific guidance sections."""
        guidance = OrderedDict()
        
        # Security guidance
        security_findings = [f for f in findings if f.type == FindingType.SECURITY]
        if security_findings:
            guidance['security_focus'] = [
                "Review authentication and authorization implementations",
                "Validate input sanitization and output encoding", 
                "Check for SQL injection and XSS vulnerabilities",
                "Verify secure credential management practices"
            ]
        
        # Code quality guidance
        quality_findings = [f for f in findings if f.type == FindingType.CODE_QUALITY]
        if quality_findings:
            guidance['quality_improvements'] = [
                "Reduce complexity in high-complexity functions",
                "Improve error handling and exception management",
                "Consider refactoring large classes and long methods",
                "Add comprehensive unit test coverage"
            ]
        
        # Privacy guidance
        privacy_findings = [f for f in findings if f.type == FindingType.PRIVACY]
        if privacy_findings:
            guidance['privacy_compliance'] = [
                "Remove or encrypt exposed PII data",
                "Implement proper data handling procedures", 
                "Review compliance with GDPR, CCPA requirements",
                "Add data anonymization for test datasets"
            ]
        
        return guidance
    
    def _build_file_priorities(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Build priority list of files with scoring."""
        # Group by file and calculate priority scores
        by_file = defaultdict(list)
        for finding in findings:
            by_file[finding.file_path].append(finding)
        
        file_priorities = []
        for file_path, file_findings in by_file.items():
            critical_count = len([f for f in file_findings if f.severity in [Severity.CRITICAL, Severity.HIGH]])
            total_count = len(file_findings)
            priority_score = critical_count * 3 + total_count
            
            file_priorities.append(OrderedDict([
                ('file_path', file_path),
                ('total_issues', total_count),
                ('critical_issues', critical_count),
                ('priority_score', priority_score)
            ]))
        
        # Sort by priority score and return top 10
        file_priorities.sort(key=lambda x: x['priority_score'], reverse=True)
        return file_priorities[:10]
    
    def _build_quick_actions(self, findings: List[Finding]) -> Dict[str, List[Dict[str, Any]]]:
        """Build quick action items."""
        actions = OrderedDict()
        
        # Immediate actions for critical findings. Today the comprehension
        # filters to severity == CRITICAL so the sort is a no-op, but apply
        # it anyway for consistency with the cap-severity pattern audit
        # (2026-05-19) — if the filter is ever widened to is_critical()
        # (CRITICAL + HIGH), this guarantees CRITICALs fill the top-3
        # slots before HIGHs.
        critical_findings = sorted(
            [f for f in findings if f.severity == Severity.CRITICAL],
            key=lambda f: 0 if f.severity == Severity.CRITICAL else 1,
        )[:3]
        if critical_findings:
            immediate = []
            for finding in critical_findings:
                immediate.append(OrderedDict([
                    ('action', f"Fix {finding.title}"),
                    ('file', finding.file_path),
                    ('line', finding.line_number),
                    ('priority', 'critical')
                ]))
            actions['immediate'] = immediate
        
        # TODO items
        todo_findings = [f for f in findings if f.type == FindingType.TODO][:5]
        if todo_findings:
            todo_items = []
            for finding in todo_findings:
                todo_items.append(OrderedDict([
                    ('description', finding.title),
                    ('location', finding.get_location_string())
                ]))
            actions['todo_items'] = todo_items
        
        return actions
    
    def _build_analysis_by_type(self, findings: List[Finding]) -> Dict[str, Dict[str, Any]]:
        """Build detailed analysis organized by finding type."""
        analysis = OrderedDict()
        
        for finding_type in FindingType:
            type_findings = [f for f in findings if f.type == finding_type]
            if not type_findings:
                continue
            
            # Calculate severity breakdown
            severity_breakdown = defaultdict(int)
            for finding in type_findings:
                severity_breakdown[finding.severity.value] += 1
            
            # Build findings list with full details
            findings_list = []
            for finding in type_findings:
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
                
                # Add optional fields
                if finding.line_number:
                    finding_data['line_number'] = finding.line_number
                if finding.remediation:
                    finding_data['remediation'] = finding.remediation
                if finding.metadata:
                    finding_data['metadata'] = finding.metadata
                
                findings_list.append(finding_data)
            
            analysis[finding_type.value] = OrderedDict([
                ('total_count', len(type_findings)),
                ('severity_breakdown', dict(severity_breakdown)),
                ('findings', findings_list)
            ])
        
        return analysis
    
    def _build_files_by_priority(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Build file-specific analysis with priority and context."""
        # Group findings by file
        by_file = defaultdict(list)
        for finding in findings:
            by_file[finding.file_path].append(finding)
        
        # Calculate priorities and build file data
        files_data = []
        for file_path, file_findings in by_file.items():
            critical_high_count = len([f for f in file_findings if f.severity in [Severity.CRITICAL, Severity.HIGH]])
            total_count = len(file_findings)
            priority_score = critical_high_count * 3 + total_count
            
            # Group issues by line number
            issues_by_line = defaultdict(list)
            for finding in file_findings:
                line_key = finding.line_number or 0
                issues_by_line[line_key].append(OrderedDict([
                    ('id', finding.id),
                    ('type', finding.type.value),
                    ('severity', finding.severity.value),
                    ('title', finding.title),
                    ('description', finding.description)
                ]))
            
            # Get file classification if available
            file_classification = None
            if file_findings and file_findings[0].metadata.get('file_context'):
                file_context = file_findings[0].metadata['file_context']
                file_classification = OrderedDict([
                    ('file_type', file_context.get('file_type', 'unknown')),
                    ('is_test_related', file_context.get('is_test_related', False)),
                    ('should_prioritize', file_context.get('should_prioritize', True))
                ])
            
            file_data = OrderedDict([
                ('file_path', file_path),
                ('total_issues', total_count),
                ('critical_high_issues', critical_high_count),
                ('priority_score', priority_score),
                ('issues_by_line', dict(issues_by_line))
            ])
            
            if file_classification:
                file_data['file_classification'] = file_classification
            
            files_data.append(file_data)
        
        # Sort by priority score
        files_data.sort(key=lambda x: x['priority_score'], reverse=True)
        return files_data[:20]  # Top 20 files
    
    def _build_security_overview(self, security_findings: List[Finding]) -> Dict[str, Any]:
        """Build security overview with metrics and risk assessment."""
        if not security_findings:
            return OrderedDict([
                ('total_issues', 0),
                ('risk_assessment', 'NONE'),
                ('status', 'No security issues detected')
            ])
        
        severity_distribution = defaultdict(int)
        for finding in security_findings:
            severity_distribution[finding.severity.value] += 1
        
        # Calculate risk assessment
        critical_count = severity_distribution.get('critical', 0)
        high_count = severity_distribution.get('high', 0)
        
        if critical_count > 0:
            risk_assessment = "CRITICAL"
        elif high_count >= 3:
            risk_assessment = "HIGH"
        elif high_count > 0:
            risk_assessment = "MEDIUM"
        else:
            risk_assessment = "LOW"
        
        return OrderedDict([
            ('total_issues', len(security_findings)),
            ('severity_distribution', dict(severity_distribution)),
            ('risk_assessment', risk_assessment)
        ])
    
    def _build_critical_vulnerabilities(self, security_findings: List[Finding]) -> List[Dict[str, Any]]:
        """Build critical vulnerabilities list with detailed information."""
        critical_vulns = [f for f in security_findings if f.severity in [Severity.CRITICAL, Severity.HIGH]]
        
        vulnerabilities = []
        for finding in critical_vulns:
            vuln = OrderedDict([
                ('id', finding.id),
                ('title', finding.title),
                ('location', OrderedDict([
                    ('file_path', finding.file_path),
                    ('line_number', finding.line_number)
                ])),
                ('risk_level', finding.severity.value),
                ('description', finding.description),
                ('confidence', finding.confidence)
            ])
            
            if finding.remediation:
                vuln['remediation'] = OrderedDict([
                    ('immediate', finding.remediation),
                    ('long_term', 'Implement comprehensive security review process')
                ])
            
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _build_vulnerability_categories(self, security_findings: List[Finding]) -> Dict[str, Dict[str, Any]]:
        """Build vulnerability categories with grouping."""
        categories = defaultdict(list)
        
        for finding in security_findings:
            # Categorize based on title/description patterns
            title_lower = finding.title.lower()
            desc_lower = finding.description.lower()
            
            if any(keyword in title_lower or keyword in desc_lower 
                   for keyword in ['secret', 'password', 'key', 'credential']):
                categories['credential_exposure'].append(finding.id)
            elif any(keyword in title_lower or keyword in desc_lower 
                     for keyword in ['injection', 'sql', 'command']):
                categories['injection_risks'].append(finding.id)
            elif any(keyword in title_lower or keyword in desc_lower 
                     for keyword in ['xss', 'csrf', 'script']):
                categories['web_vulnerabilities'].append(finding.id)
            else:
                categories['other_security'].append(finding.id)
        
        # Convert to structured format
        result = OrderedDict()
        for category, finding_ids in categories.items():
            if finding_ids:
                # Calculate severity based on findings
                category_findings = [f for f in security_findings if f.id in finding_ids]
                max_severity = self._get_max_severity(category_findings)
                
                result[category] = OrderedDict([
                    ('count', len(finding_ids)),
                    ('severity', max_severity.value),
                    ('findings', finding_ids)
                ])
        
        return result
    
    def _build_privacy_overview(self, privacy_findings: List[Finding]) -> Dict[str, Any]:
        """Build privacy overview with compliance risk assessment."""
        categories_detected = len(set(f.privacy_category for f in privacy_findings if f.privacy_category))
        
        # Calculate compliance risk
        high_impact_findings = [f for f in privacy_findings if f.impact_score > 0.7]
        if len(high_impact_findings) >= 3:
            compliance_risk = "HIGH"
        elif len(high_impact_findings) > 0:
            compliance_risk = "MEDIUM"
        else:
            compliance_risk = "LOW"
        
        return OrderedDict([
            ('total_issues', len(privacy_findings)),
            ('categories_detected', categories_detected),
            ('compliance_risk', compliance_risk)
        ])
    
    def _build_pii_categories(self, privacy_findings: List[Finding]) -> Dict[str, Dict[str, Any]]:
        """Build PII categories with detailed findings."""
        categories = defaultdict(list)
        
        for finding in privacy_findings:
            category = finding.privacy_category or 'unknown'
            categories[category].append(finding)
        
        result = OrderedDict()
        for category, findings in categories.items():
            if findings:
                max_severity = self._get_max_severity(findings)
                
                findings_list = []
                for finding in findings:
                    finding_data = OrderedDict([
                        ('id', finding.id),
                        ('type', finding.privacy_category or 'unknown'),
                        ('location', finding.get_location_string()),
                        ('confidence', finding.confidence)
                    ])
                    
                    if finding.compliance_regions:
                        finding_data['compliance_regions'] = finding.compliance_regions
                    
                    findings_list.append(finding_data)
                
                result[category] = OrderedDict([
                    ('count', len(findings)),
                    ('severity', max_severity.value),
                    ('findings', findings_list)
                ])
        
        return result
    
    def _get_max_severity(self, findings: List[Finding]) -> Severity:
        """Get the maximum severity from a list of findings."""
        if not findings:
            return Severity.INFO
        
        # Define severity ranking (higher values = more severe)
        severity_order = {
            Severity.INFO: 1,
            Severity.LOW: 2,
            Severity.MEDIUM: 3,
            Severity.HIGH: 4,
            Severity.CRITICAL: 5
        }
        
        max_severity = Severity.INFO
        max_value = severity_order[max_severity]
        
        for finding in findings:
            severity_value = severity_order.get(finding.severity, 1)
            if severity_value > max_value:
                max_severity = finding.severity
                max_value = severity_value
        
        return max_severity
    
    def _build_compliance_analysis(self, privacy_findings: List[Finding]) -> Dict[str, Dict[str, Any]]:
        """Build compliance analysis for different regulations."""
        compliance = OrderedDict()
        
        # Analyze GDPR compliance
        gdpr_findings = [f for f in privacy_findings 
                        if f.compliance_regions and 'GDPR' in f.compliance_regions]
        if gdpr_findings:
            compliance['gdpr'] = OrderedDict([
                ('violations', len(gdpr_findings)),
                ('risk_level', 'HIGH' if len(gdpr_findings) >= 5 else 'MEDIUM'),
                ('required_actions', [
                    "Encrypt PII data at rest",
                    "Implement data anonymization",
                    "Add data deletion capabilities"
                ])
            ])
        
        # Analyze CCPA compliance
        ccpa_findings = [f for f in privacy_findings 
                        if f.compliance_regions and 'CCPA' in f.compliance_regions]
        if ccpa_findings:
            compliance['ccpa'] = OrderedDict([
                ('violations', len(ccpa_findings)),
                ('risk_level', 'HIGH' if len(ccpa_findings) >= 3 else 'MEDIUM'),
                ('required_actions', [
                    "Add data deletion capabilities",
                    "Implement opt-out mechanisms"
                ])
            ])
        
        return compliance
    
    def _build_statistics_overview(self, findings: List[Finding]) -> Dict[str, Any]:
        """Build statistics overview section."""
        stats = self._generate_summary_stats(findings)
        
        return OrderedDict([
            ('total_findings', stats['total_findings']),
            ('files_analyzed', stats['files_analyzed']),
            ('average_confidence', round(stats['avg_confidence'], 3)),
            ('average_impact', round(stats['avg_impact'], 3))
        ])
    
    def _build_distribution_stats(self, findings: List[Finding]) -> Dict[str, Dict[str, int]]:
        """Build distribution statistics."""
        stats = self._generate_summary_stats(findings)
        
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
        """Build file-level metrics."""
        # Group by file
        by_file = defaultdict(list)
        for finding in findings:
            by_file[finding.file_path].append(finding)
        
        # Calculate metrics
        file_metrics = []
        for file_path, file_findings in by_file.items():
            critical_count = len([f for f in file_findings if f.severity in [Severity.CRITICAL, Severity.HIGH]])
            score = critical_count * 3 + len(file_findings)
            
            file_metrics.append({
                'file': file_path,
                'issues': len(file_findings),
                'score': score
            })
        
        # Sort for most/least problematic
        file_metrics.sort(key=lambda x: x['score'], reverse=True)
        
        most_problematic = file_metrics[:5]
        cleanest_files = [f for f in file_metrics if f['issues'] <= 1][-5:]
        
        return OrderedDict([
            ('most_problematic', most_problematic),
            ('cleanest_files', cleanest_files)
        ])
    
    def _build_performance_metrics(self, findings: List[Finding]) -> Dict[str, Any]:
        """Build performance metrics."""
        # Basic performance metrics (would be enhanced with actual timing data)
        return OrderedDict([
            ('analysis_duration', '28.5s'),  # Placeholder - would be calculated
            ('files_per_second', 1.58),
            ('findings_per_file', round(len(findings) / max(len(set(f.file_path for f in findings)), 1), 2))
        ])
    
    def _build_trend_analysis(self, findings: List[Finding]) -> Dict[str, Dict[str, int]]:
        """Build trend analysis."""
        # Analyze complexity distribution
        complexity_findings = [f for f in findings if 'complexity' in f.title.lower()]
        complexity_dist = {'low': 0, 'medium': 0, 'high': 0}
        
        for finding in complexity_findings:
            if finding.severity == Severity.HIGH:
                complexity_dist['high'] += 1
            elif finding.severity == Severity.MEDIUM:
                complexity_dist['medium'] += 1
            else:
                complexity_dist['low'] += 1
        
        # Security confidence distribution
        security_findings = [f for f in findings if f.type == FindingType.SECURITY]
        confidence_dist = {'high_confidence': 0, 'medium_confidence': 0, 'low_confidence': 0}
        
        for finding in security_findings:
            if finding.confidence >= 0.8:
                confidence_dist['high_confidence'] += 1
            elif finding.confidence >= 0.5:
                confidence_dist['medium_confidence'] += 1
            else:
                confidence_dist['low_confidence'] += 1
        
        return OrderedDict([
            ('complexity_distribution', complexity_dist),
            ('security_confidence', confidence_dist)
        ])
    
    def _generate_summary_stats(self, findings: List[Finding]) -> Dict[str, Any]:
        """Generate comprehensive summary statistics."""
        if not findings:
            return {
                'total_findings': 0,
                'files_analyzed': 0,
                'avg_confidence': 0,
                'avg_impact': 0,
                'by_type': {},
                'by_severity': {}
            }
        
        # Basic stats
        unique_files = len(set(f.file_path for f in findings))
        avg_confidence = sum(f.confidence for f in findings) / len(findings)
        avg_impact = sum(f.impact_score for f in findings) / len(findings)
        
        # By type
        by_type = defaultdict(int)
        for finding in findings:
            by_type[finding.type.value] += 1
        
        # By severity
        by_severity = defaultdict(int)
        for finding in findings:
            by_severity[finding.severity.value] += 1
        
        return {
            'total_findings': len(findings),
            'files_analyzed': unique_files,
            'avg_confidence': avg_confidence,
            'avg_impact': avg_impact,
            'by_type': dict(by_type),
            'by_severity': dict(by_severity)
        }
    
    def _write_yaml_file(self, file_path: Path, data: Dict[str, Any]) -> None:
        """Write data to YAML file with proper formatting."""
        try:
            # Convert OrderedDict to regular dict for cleaner YAML output
            clean_data = self._convert_to_dict(data)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                yaml.dump(
                    clean_data,
                    f,
                    default_flow_style=False,
                    sort_keys=False,
                    allow_unicode=True,
                    indent=2,
                    width=120
                )
            logger.debug(f"Generated YAML file: {file_path}")
        except Exception as e:
            logger.error(f"Failed to write YAML file {file_path}: {e}")
            raise
    
    def _convert_to_dict(self, obj):
        """Convert OrderedDict and other objects to regular dict for clean YAML."""
        if isinstance(obj, OrderedDict):
            return {k: self._convert_to_dict(v) for k, v in obj.items()}
        elif isinstance(obj, dict):
            return {k: self._convert_to_dict(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._convert_to_dict(item) for item in obj]
        else:
            return obj