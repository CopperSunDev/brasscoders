"""
Privacy report builder for PII and compliance analysis.

Generates privacy-focused YAML reports with PII categorization,
compliance analysis, and privacy risk assessment. Single responsibility: privacy analysis.
"""

from typing import List, Dict, Any, Tuple
from collections import OrderedDict, defaultdict

from brass.models.finding import Finding
from .base_builder import BaseYAMLBuilder
from .yaml_utils import YAMLUtils


class YAMLPrivacyReportBuilder(BaseYAMLBuilder):
    """
    Builds privacy analysis YAML with PII detection and compliance.
    
    Responsible for generating privacy overviews, PII categorization,
    and regulatory compliance analysis for privacy-focused reporting.
    """
    
    def build(self, findings: List[Finding]) -> Dict[str, Any]:
        """
        Build complete privacy report structure.
        
        Args:
            findings: Privacy-related findings only
            
        Returns:
            Complete privacy analysis dictionary
        """
        # Only include compliance_analysis when there's GDPR/CCPA-relevant
        # content — emitting `compliance_analysis: {}` (empty object) was
        # noise the YAML review flagged 2026-05-19. Same defensive pattern
        # operator_notes uses: skip the section entirely when empty rather
        # than ship an empty stub.
        compliance = self._build_compliance_analysis(findings)
        sections: List[Tuple[str, Any]] = [
            ('privacy_overview', self._build_privacy_overview(findings)),
            ('pii_categories', self._build_pii_categories(findings)),
        ]
        if compliance:
            sections.append(('compliance_analysis', compliance))
        return OrderedDict(sections)
    
    def _build_privacy_overview(self, privacy_findings: List[Finding]) -> Dict[str, Any]:
        """Build privacy overview with compliance risk assessment."""
        categories_detected = len(set(f.privacy_category for f in privacy_findings if f.privacy_category))
        compliance_risk = self._calculate_compliance_risk(privacy_findings)
        
        return OrderedDict([
            ('total_issues', len(privacy_findings)),
            ('categories_detected', categories_detected),
            ('compliance_risk', compliance_risk)
        ])
    
    def _calculate_compliance_risk(self, privacy_findings: List[Finding]) -> str:
        """Calculate overall compliance risk level."""
        high_impact_findings = [f for f in privacy_findings if f.impact_score > 0.7]
        
        if len(high_impact_findings) >= 3:
            return "HIGH"
        elif len(high_impact_findings) > 0:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _build_pii_categories(self, privacy_findings: List[Finding]) -> Dict[str, Dict[str, Any]]:
        """Build PII categories with detailed findings."""
        categories = defaultdict(list)
        
        for finding in privacy_findings:
            category = finding.privacy_category or self._extract_category_from_title(finding.title)
            categories[category].append(finding)
        
        result = OrderedDict()
        for category, findings in categories.items():
            if findings:
                max_severity = YAMLUtils.get_max_severity(findings)
                
                findings_list = []
                for finding in findings:
                    finding_data = self._build_pii_finding_data(finding)
                    findings_list.append(finding_data)
                
                result[category] = OrderedDict([
                    ('count', len(findings)),
                    ('severity', max_severity.value),
                    ('findings', findings_list)
                ])
        
        return result
    
    def _build_pii_finding_data(self, finding: Finding) -> OrderedDict:
        """Build PII finding data with privacy-specific information."""
        finding_data = OrderedDict([
            ('id', finding.id),
            ('type', finding.privacy_category or self._extract_category_from_title(finding.title)),
            ('location', finding.get_location_string()),
            ('confidence', finding.confidence)
        ])
        
        if finding.compliance_regions:
            finding_data['compliance_regions'] = finding.compliance_regions
        
        return finding_data
    
    def _extract_category_from_title(self, title: str) -> str:
        """
        Extract PII category from finding title for proper categorization.
        
        Args:
            title: Finding title like "US Social Security Number" or "Email Address"
            
        Returns:
            Category key like "us_ssn", "email", "phone_number", etc.
        """
        # Comprehensive title-to-category mapping based on privacy scanner patterns
        title_mappings = {
            'US Social Security Number': 'us_ssn',
            'Email Address': 'email',
            'Phone Number': 'phone_number',
            'IP Address': 'ip_address',
            'Visa Credit Card Number': 'credit_card',
            'MasterCard Credit Card Number': 'credit_card',
            'American Express Credit Card Number': 'credit_card',
            'Discover Credit Card Number': 'credit_card',
            'Credit Card Number': 'credit_card',
            'UK NHS Number': 'uk_nhs',
            'UK National Insurance Number': 'uk_national_insurance',
            'UK Passport Number': 'uk_passport',
            'Canada Social Insurance Number': 'canada_sin',
            'Australia Medicare Number': 'australia_medicare',
            'Australia Tax File Number': 'australia_tfn',
            'France Social Security Number': 'france_ssn',
            'Germany ID Number': 'germany_id',
            'India Aadhaar Number': 'india_aadhaar',
            'India PAN Number': 'india_pan',
            'Japan My Number': 'japan_my_number',
            'Brazil CPF Number': 'brazil_cpf',
            'IBAN Bank Account': 'iban',
            'US Bank Account Number': 'us_bank_account',
            'US Driver License': 'us_drivers_license',
            'US Passport Number': 'us_passport'
        }
        
        # Direct mapping lookup
        if title in title_mappings:
            return title_mappings[title]
        
        # Fallback pattern matching for variations
        title_lower = title.lower()
        if 'social security' in title_lower or 'ssn' in title_lower:
            return 'us_ssn'
        elif 'email' in title_lower:
            return 'email'
        elif 'phone' in title_lower:
            return 'phone_number'
        elif 'credit card' in title_lower:
            return 'credit_card'
        elif 'ip address' in title_lower:
            return 'ip_address'
        elif 'passport' in title_lower:
            return 'passport'
        elif 'driver' in title_lower and 'license' in title_lower:
            return 'drivers_license'
        elif 'bank account' in title_lower:
            return 'bank_account'
        elif 'iban' in title_lower:
            return 'iban'
        elif 'nhs' in title_lower:
            return 'uk_nhs'
        elif 'medicare' in title_lower:
            return 'australia_medicare'
        elif 'aadhaar' in title_lower:
            return 'india_aadhaar'
        elif 'pan' in title_lower and 'india' in title_lower:
            return 'india_pan'
        else:
            return 'unknown'
    
    def _build_compliance_analysis(self, privacy_findings: List[Finding]) -> Dict[str, Dict[str, Any]]:
        """Build compliance analysis for different regulations."""
        compliance = OrderedDict()
        
        # GDPR compliance analysis
        gdpr_findings = [f for f in privacy_findings 
                        if f.compliance_regions and 'GDPR' in f.compliance_regions]
        if gdpr_findings:
            compliance['gdpr'] = self._build_regulation_compliance('GDPR', gdpr_findings, 5)
        
        # CCPA compliance analysis
        ccpa_findings = [f for f in privacy_findings 
                        if f.compliance_regions and 'CCPA' in f.compliance_regions]
        if ccpa_findings:
            compliance['ccpa'] = self._build_regulation_compliance('CCPA', ccpa_findings, 3)
        
        return compliance
    
    def _build_regulation_compliance(self, regulation: str, findings: List[Finding], high_threshold: int) -> OrderedDict:
        """Build compliance analysis for specific regulation."""
        violation_count = len(findings)
        risk_level = 'HIGH' if violation_count >= high_threshold else 'MEDIUM'
        
        # Regulation-specific required actions
        if regulation == 'GDPR':
            required_actions = [
                "Encrypt PII data at rest",
                "Implement data anonymization",
                "Add data deletion capabilities"
            ]
        elif regulation == 'CCPA':
            required_actions = [
                "Add data deletion capabilities",
                "Implement opt-out mechanisms"
            ]
        else:
            required_actions = ["Review compliance requirements"]
        
        return OrderedDict([
            ('violations', violation_count),
            ('risk_level', risk_level),
            ('required_actions', required_actions)
        ])