"""
Security report builder for vulnerability analysis.

Generates security-focused YAML reports with vulnerability categorization,
risk assessment, and detailed security findings. Single responsibility: security analysis.
"""

from typing import List, Dict, Any
from collections import OrderedDict, defaultdict

from brass.models.finding import Finding, Severity
from .base_builder import BaseYAMLBuilder
from .yaml_utils import YAMLUtils


class YAMLSecurityReportBuilder(BaseYAMLBuilder):
    """
    Builds security report YAML with vulnerability analysis.
    
    Responsible for generating security overviews, critical vulnerabilities,
    and vulnerability categorization for security-focused analysis.
    """
    
    def build(self, findings: List[Finding]) -> Dict[str, Any]:
        """
        Build complete security report structure.
        
        Args:
            findings: All findings (filtered to security in orchestrator)
            
        Returns:
            Complete security report dictionary
        """
        security_findings = [f for f in findings if f.type.value == 'security']
        
        return OrderedDict([
            ('security_overview', self._build_security_overview(security_findings)),
            ('critical_vulnerabilities', self._build_critical_vulnerabilities(security_findings)),
            ('vulnerability_categories', self._build_vulnerability_categories(security_findings))
        ])
    
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
        
        risk_assessment = self._calculate_security_risk(severity_distribution)
        
        return OrderedDict([
            ('total_issues', len(security_findings)),
            ('severity_distribution', dict(severity_distribution)),
            ('risk_assessment', risk_assessment)
        ])
    
    def _calculate_security_risk(self, severity_distribution: Dict[str, int]) -> str:
        """Calculate overall security risk level."""
        critical_count = severity_distribution.get('critical', 0)
        high_count = severity_distribution.get('high', 0)
        
        if critical_count > 0:
            return "CRITICAL"
        elif high_count >= 3:
            return "HIGH"
        elif high_count > 0:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _build_critical_vulnerabilities(self, security_findings: List[Finding]) -> List[Dict[str, Any]]:
        """Build critical vulnerabilities list with detailed information."""
        critical_vulns = [f for f in security_findings 
                         if f.severity in [Severity.CRITICAL, Severity.HIGH]]
        
        vulnerabilities = []
        for finding in critical_vulns:
            vuln = self._build_vulnerability_entry(finding)
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _build_vulnerability_entry(self, finding: Finding) -> OrderedDict:
        """Build individual vulnerability entry with all details.

        Routes through `sanitize_finding_for_serialization` so
        secret-leak / PII findings get the literal credential / PII
        value stripped from title + description before serialization.
        Without this, Bandit B105/B106 findings (and SecretsScanner
        findings) would leak the credential string into
        `security_report.yaml` — exactly the surface a customer
        attaches to a "look at what brass found" email or PR.
        """
        finding = self.sanitize_finding_for_serialization(finding)
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

        return vuln
    
    def _build_vulnerability_categories(self, security_findings: List[Finding]) -> Dict[str, Dict[str, Any]]:
        """Build vulnerability categories with intelligent grouping."""
        categories = defaultdict(list)
        
        for finding in security_findings:
            category = self._categorize_vulnerability(finding)
            categories[category].append(finding.id)
        
        # Convert to structured format
        result = OrderedDict()
        for category, finding_ids in categories.items():
            if finding_ids:
                category_findings = [f for f in security_findings if f.id in finding_ids]
                max_severity = YAMLUtils.get_max_severity(category_findings)
                
                result[category] = OrderedDict([
                    ('count', len(finding_ids)),
                    ('severity', max_severity.value),
                    ('findings', finding_ids)
                ])
        
        return result
    
    def _categorize_vulnerability(self, finding: Finding) -> str:
        """Categorize vulnerability based on content analysis."""
        title_lower = finding.title.lower()
        desc_lower = finding.description.lower()
        
        # Credential exposure patterns
        credential_keywords = ['secret', 'password', 'key', 'credential']
        if any(keyword in title_lower or keyword in desc_lower for keyword in credential_keywords):
            return 'credential_exposure'
        
        # Injection vulnerability patterns
        injection_keywords = ['injection', 'sql', 'command']
        if any(keyword in title_lower or keyword in desc_lower for keyword in injection_keywords):
            return 'injection_risks'
        
        # Web vulnerability patterns  
        web_keywords = ['xss', 'csrf', 'script']
        if any(keyword in title_lower or keyword in desc_lower for keyword in web_keywords):
            return 'web_vulnerabilities'
        
        # Default category
        return 'other_security'