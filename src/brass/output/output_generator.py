"""
OutputGenerator - Generate AI-consumable intelligence files.

This component takes ranked findings and generates rich, structured intelligence
files optimized for Claude Code and other AI coding assistants.
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
from collections import defaultdict

from brass.models.finding import Finding, FindingType, Severity
from brass.core.logging_config import get_logger

logger = get_logger(__name__)


class OutputGenerator:
    """
    Generate AI-consumable intelligence files from ranked findings.
    
    Creates structured, rich intelligence files that provide fantastic
    context for Claude Code and other AI coding assistants including:
    - Main AI instructions with prioritized findings
    - Detailed technical analysis
    - File-specific intelligence
    - Security and privacy reports
    - JSON data for programmatic access
    """
    
    def __init__(self, project_path: str, output_dir: str = ".brass", ranker: Optional[Any] = None):
        """
        Initialize OutputGenerator.
        
        Args:
            project_path: Root path of project being analyzed
            output_dir: Directory name for output files (default: .brass)
            ranker: IntelligenceRanker instance for contextual risk assessment
        """
        self.project_path = Path(project_path).resolve()
        self.output_dir = self.project_path / output_dir
        self.generation_time = datetime.now()
        self.ranker = ranker  # Store ranker for contextual risk assessment
        
        logger.info(f"Output generator initialized for {self.project_path}")
    
    def generate_intelligence(self, findings: List[Finding]) -> Dict[str, str]:
        """
        Generate complete intelligence output for AI consumption.
        
        Args:
            findings: Ranked findings from all scanners
            
        Returns:
            Dictionary mapping file names to file paths created
        """
        # Ensure output directory exists
        self.output_dir.mkdir(exist_ok=True)
        
        generated_files = {}
        
        # Generate main AI instructions file
        ai_instructions_path = self._generate_ai_instructions(findings)
        generated_files['ai_instructions'] = str(ai_instructions_path)
        
        # Generate detailed analysis report
        analysis_path = self._generate_detailed_analysis(findings)
        generated_files['detailed_analysis'] = str(analysis_path)
        
        # Generate file-specific intelligence
        file_intelligence_path = self._generate_file_intelligence(findings)
        generated_files['file_intelligence'] = str(file_intelligence_path)
        
        # Generate security report
        security_path = self._generate_security_report(findings)
        generated_files['security_report'] = str(security_path)
        
        # Generate privacy report (if privacy findings exist)
        privacy_findings = [f for f in findings if f.type == FindingType.PRIVACY]
        if privacy_findings:
            privacy_path = self._generate_privacy_report(privacy_findings)
            generated_files['privacy_report'] = str(privacy_path)
        
        # Generate JSON data for programmatic access
        json_path = self._generate_json_export(findings)
        generated_files['json_export'] = str(json_path)
        
        # Generate summary statistics
        stats_path = self._generate_statistics_report(findings)
        generated_files['statistics'] = str(stats_path)
        
        logger.info(f"Generated {len(generated_files)} intelligence files")
        return generated_files
    
    def _generate_ai_instructions(self, findings: List[Finding]) -> Path:
        """
        Generate main AI instructions file optimized for Claude Code.
        
        Note: This function has moderate cyclomatic complexity due to:
        - Multiple report sections with different formatting requirements
        - Conditional content generation based on finding types and severity
        - Complex markdown formatting for professional presentation
        This could benefit from Extract Method refactoring (e.g., _generate_critical_issues_section)
        but the complexity is acceptable for a comprehensive report generator.
        """
        sections = []
        
        # Header with branding
        sections.append("# 🎺 Copper Sun Brass - AI Intelligence Report\n")
        sections.append(f"*Generated: {self.generation_time.strftime('%Y-%m-%d %H:%M:%S')}*\n")
        sections.append(f"*Project: {self.project_path.name}*\n")
        sections.append(f"*Analysis Engine: brass v2*\n\n")
        
        # Executive Summary
        sections.append("## 📊 Executive Summary\n")
        sections.append(self._generate_executive_summary(findings))
        sections.append("\n")
        
        # Critical Issues (Top 10)
        # 2026-05-19 audit: severity-first sort before slice so CRITICAL
        # findings can't be silently dropped by enrichment rank ties. Same
        # cap-severity pattern as ai_instructions_builder._typed_block_sort_key.
        critical_findings = sorted(
            [f for f in findings if f.is_critical()],
            key=lambda f: 0 if f.severity == Severity.CRITICAL else 1,
        )[:10]
        if critical_findings:
            sections.append("## 🚨 Critical Issues Requiring Immediate Attention\n")
            sections.append("These are the highest priority issues that need your immediate focus:\n\n")
            
            for i, finding in enumerate(critical_findings, 1):
                sections.append(f"### {i}. {finding.title}\n")
                sections.append(f"**📍 Location**: `{finding.get_location_string()}`\n")
                sections.append(f"**🏷️ Type**: {finding.type.value.replace('_', ' ').title()}\n")
                sections.append(f"**⚡ Severity**: {finding.severity.value.title()}\n")
                sections.append(f"**📝 Description**: {finding.description}\n")
                
                # Add context explanation
                context_explanation = self._get_context_explanation(finding)
                if context_explanation:
                    sections.append(f"**✨ Why This Matters**: {context_explanation}\n")
                
                # Add business impact if significant
                business_impact = self._get_business_impact(finding)
                if business_impact:
                    sections.append(f"**💥 Business Impact**: {business_impact}\n")
                
                if finding.remediation:
                    # Enhanced contextual fix explanation
                    contextual_fix = self._get_contextual_fix(finding)
                    if contextual_fix:
                        sections.append(f"**🔧 Contextual Fix**: {contextual_fix}\n")
                    else:
                        sections.append(f"**🔧 Fix**: {finding.remediation}\n")
                
                sections.append(f"**🎯 Confidence**: {finding.confidence:.0%}\n")
                sections.append(f"**📈 Impact**: {finding.impact_score:.0%}\n")
                
                # Add privacy-specific info
                if finding.is_privacy_related():
                    if finding.privacy_category:
                        sections.append(f"**🔒 Privacy Category**: {finding.privacy_category}\n")
                    if finding.compliance_regions:
                        sections.append(f"**🌍 Compliance**: {', '.join(finding.compliance_regions)}\n")
                
                sections.append("\n")
        
        # Top Findings by Category
        sections.append("## 📋 Top Findings by Category\n")
        sections.append(self._generate_category_breakdown(findings))
        
        # AI Coding Guidance
        sections.append("## 🤖 AI Coding Guidance\n")
        sections.append(self._generate_ai_guidance(findings))
        
        # File-Specific Intelligence
        sections.append("## 📁 Files Requiring Attention\n")
        sections.append(self._generate_file_priority_list(findings))
        
        # Quick Actions
        sections.append("## ⚡ Quick Actions\n")
        sections.append(self._generate_quick_actions(findings))
        
        # Footer
        sections.append("\n---\n")
        sections.append("*🎺 This intelligence report was generated by **Copper Sun Brass** - ")
        sections.append("AI development intelligence system providing persistent memory and enhanced context for AI coding assistants.*\n")
        
        # Write file
        file_path = self.output_dir / "AI_INSTRUCTIONS.md"
        file_path.write_text("".join(sections), encoding='utf-8')
        
        return file_path
    
    def _generate_detailed_analysis(self, findings: List[Finding]) -> Path:
        """Generate comprehensive technical analysis report."""
        sections = []
        
        sections.append("# 🔬 Detailed Technical Analysis\n")
        sections.append(f"*Generated: {self.generation_time.strftime('%Y-%m-%d %H:%M:%S')}*\n\n")
        
        # Analysis by type
        for finding_type in FindingType:
            type_findings = [f for f in findings if f.type == finding_type]
            if type_findings:
                sections.append(f"## {finding_type.value.replace('_', ' ').title()} Analysis\n")
                sections.append(f"Found {len(type_findings)} {finding_type.value.replace('_', ' ')} issues.\n\n")
                
                # Group by severity
                by_severity = defaultdict(list)
                for finding in type_findings:
                    by_severity[finding.severity].append(finding)
                
                for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
                    severity_findings = by_severity[severity]
                    if severity_findings:
                        sections.append(f"### {severity.value.title()} Severity ({len(severity_findings)} items)\n")
                        
                        for finding in severity_findings[:5]:  # Top 5 per severity
                            sections.append(f"- **{finding.title}** in `{finding.get_location_string()}`\n")
                            sections.append(f"  - {finding.description}\n")
                            if finding.remediation:
                                sections.append(f"  - *Fix*: {finding.remediation}\n")
                        
                        if len(severity_findings) > 5:
                            sections.append(f"  - *...and {len(severity_findings) - 5} more*\n")
                        
                        sections.append("\n")
                
                sections.append("\n")
        
        # Write file
        file_path = self.output_dir / "DETAILED_ANALYSIS.md"
        file_path.write_text("".join(sections), encoding='utf-8')
        
        return file_path
    
    def _generate_file_intelligence(self, findings: List[Finding]) -> Path:
        """Generate file-specific intelligence report."""
        sections = []
        
        sections.append("# 📁 File-Specific Intelligence\n")
        sections.append(f"*Generated: {self.generation_time.strftime('%Y-%m-%d %H:%M:%S')}*\n\n")
        
        # Group findings by file
        by_file = defaultdict(list)
        for finding in findings:
            by_file[finding.file_path].append(finding)
        
        # Sort files by number of issues (most problematic first)
        sorted_files = sorted(by_file.items(), key=lambda x: len(x[1]), reverse=True)
        
        sections.append(f"## 🎯 Most Problematic Files\n")
        sections.append("Files ranked by number and severity of issues:\n\n")
        
        for file_path, file_findings in sorted_files[:20]:  # Top 20 files
            critical_count = len([f for f in file_findings if f.severity in [Severity.CRITICAL, Severity.HIGH]])
            
            sections.append(f"### `{file_path}` ({len(file_findings)} issues, {critical_count} critical/high)\n")
            
            # Group by line number for context
            by_line = defaultdict(list)
            for finding in file_findings:
                line_key = finding.line_number or 0
                by_line[line_key].append(finding)
            
            # Show top issues in this file
            for line_num in sorted(by_line.keys())[:10]:  # Top 10 lines
                line_findings = by_line[line_num]
                for finding in line_findings:
                    if line_num > 0:
                        sections.append(f"- **Line {line_num}**: {finding.title} ({finding.severity.value})\n")
                    else:
                        sections.append(f"- {finding.title} ({finding.severity.value})\n")
                    sections.append(f"  - {finding.description}\n")
            
            sections.append("\n")
        
        # Write file
        file_path = self.output_dir / "FILE_INTELLIGENCE.md"
        file_path.write_text("".join(sections), encoding='utf-8')
        
        return file_path
    
    def _generate_security_report(self, findings: List[Finding]) -> Path:
        """Generate focused security analysis report."""
        security_findings = [f for f in findings if f.type == FindingType.SECURITY]
        
        sections = []
        sections.append("# 🔒 Security Analysis Report\n")
        sections.append(f"*Generated: {self.generation_time.strftime('%Y-%m-%d %H:%M:%S')}*\n\n")
        
        if security_findings:
            sections.append(f"## 📊 Security Overview\n")
            sections.append(f"- **Total Security Issues**: {len(security_findings)}\n")
            
            critical_security = [f for f in security_findings if f.severity == Severity.CRITICAL]
            high_security = [f for f in security_findings if f.severity == Severity.HIGH]
            
            sections.append(f"- **Critical**: {len(critical_security)}\n")
            sections.append(f"- **High**: {len(high_security)}\n\n")
            
            if critical_security or high_security:
                sections.append("## 🚨 Critical Security Issues\n")
                for finding in (critical_security + high_security)[:10]:
                    sections.append(f"### {finding.title}\n")
                    sections.append(f"**Location**: `{finding.get_location_string()}`\n")
                    sections.append(f"**Risk**: {finding.description}\n")
                    if finding.remediation:
                        sections.append(f"**Fix**: {finding.remediation}\n")
                    sections.append("\n")
        else:
            sections.append("## ✅ No Security Issues Detected\n")
            sections.append("No security vulnerabilities were identified in the codebase.\n\n")
        
        # Write file
        file_path = self.output_dir / "SECURITY_REPORT.md"
        file_path.write_text("".join(sections), encoding='utf-8')
        
        return file_path
    
    def _generate_privacy_report(self, privacy_findings: List[Finding]) -> Path:
        """Generate focused privacy analysis report."""
        sections = []
        sections.append("# 🔒 Privacy & PII Analysis Report\n")
        sections.append(f"*Generated: {self.generation_time.strftime('%Y-%m-%d %H:%M:%S')}*\n\n")
        
        sections.append(f"## 📊 Privacy Overview\n")
        sections.append(f"- **Total Privacy Issues**: {len(privacy_findings)}\n")
        
        # Group by privacy category
        by_category = defaultdict(list)
        for finding in privacy_findings:
            category = finding.privacy_category or 'unknown'
            by_category[category].append(finding)
        
        sections.append(f"- **Categories Detected**: {len(by_category)}\n\n")
        
        # Critical findings
        critical_privacy = [f for f in privacy_findings if f.severity in [Severity.CRITICAL, Severity.HIGH]]
        if critical_privacy:
            sections.append("## 🚨 Critical Privacy Issues\n")
            for finding in critical_privacy:
                sections.append(f"### {finding.title}\n")
                sections.append(f"**Location**: `{finding.get_location_string()}`\n")
                sections.append(f"**Category**: {finding.privacy_category or 'Unknown'}\n")
                if finding.compliance_regions:
                    sections.append(f"**Compliance**: {', '.join(finding.compliance_regions)}\n")
                sections.append(f"**Risk**: {finding.description}\n")
                if finding.remediation:
                    sections.append(f"**Fix**: {finding.remediation}\n")
                sections.append("\n")
        
        # Write file
        file_path = self.output_dir / "PRIVACY_ANALYSIS.md"
        file_path.write_text("".join(sections), encoding='utf-8')
        
        return file_path
    
    def _generate_json_export(self, findings: List[Finding]) -> Path:
        """Generate JSON export for programmatic access."""
        data = {
            'metadata': {
                'generated_at': self.generation_time.isoformat(),
                'project_path': str(self.project_path),
                'total_findings': len(findings),
                'generator': 'Copper Sun Brass v2.0'
            },
            'findings': [finding.to_dict() for finding in findings],
            'summary': self._generate_summary_stats(findings)
        }
        
        file_path = self.output_dir / "analysis_data.json"
        file_path.write_text(json.dumps(data, indent=2), encoding='utf-8')
        
        return file_path
    
    def _generate_statistics_report(self, findings: List[Finding]) -> Path:
        """Generate comprehensive statistics report."""
        sections = []
        
        sections.append("# 📈 Analysis Statistics\n")
        sections.append(f"*Generated: {self.generation_time.strftime('%Y-%m-%d %H:%M:%S')}*\n\n")
        
        stats = self._generate_summary_stats(findings)
        
        sections.append("## 📊 Overview\n")
        sections.append(f"- **Total Findings**: {stats['total_findings']}\n")
        sections.append(f"- **Files Analyzed**: {stats['files_analyzed']}\n")
        sections.append(f"- **Average Confidence**: {stats['avg_confidence']:.1%}\n")
        sections.append(f"- **Average Impact**: {stats['avg_impact']:.1%}\n\n")
        
        sections.append("## 🏷️ By Type\n")
        for type_name, count in stats['by_type'].items():
            sections.append(f"- **{type_name.replace('_', ' ').title()}**: {count}\n")
        
        sections.append("\n## ⚡ By Severity\n")
        for severity, count in stats['by_severity'].items():
            sections.append(f"- **{severity.title()}**: {count}\n")
        
        file_path = self.output_dir / "STATISTICS.md"
        file_path.write_text("".join(sections), encoding='utf-8')
        
        return file_path
    
    def _generate_executive_summary(self, findings: List[Finding]) -> str:
        """Generate executive summary statistics with contextual risk assessment."""
        stats = self._generate_summary_stats(findings)
        
        summary = []
        summary.append(f"**📊 Analysis Results**: {stats['total_findings']} issues found across {stats['files_analyzed']} files\n")
        
        # Contextual risk assessment using Smart File Classification
        if self.ranker and hasattr(self.ranker, 'calculate_contextual_risk_level'):
            risk_assessment = self.ranker.calculate_contextual_risk_level(findings)
            
            # Format risk level with emoji
            risk_icons = {
                'HIGH': '🚨',
                'MEDIUM': '⚠️', 
                'LOW': '✅'
            }
            risk_level = f"{risk_icons.get(risk_assessment['risk_level'], '⚠️')} **{risk_assessment['risk_level']} RISK**"
            recommendation = risk_assessment['reasoning']
            
            summary.append(f"**🎯 Risk Level**: {risk_level}\n")
            summary.append(f"**💡 Recommendation**: {recommendation}\n")
            
            # Add contextual breakdown for transparency
            if risk_assessment['source_code_findings'] > 0 or risk_assessment['test_file_findings'] > 0:
                summary.append(f"**📊 Context**: {risk_assessment['source_code_findings']} source code issues, {risk_assessment['test_file_findings']} test file findings\n")
            
        else:
            # Fallback: Legacy risk assessment if ranker not available
            critical_count = stats['by_severity'].get('critical', 0)
            high_count = stats['by_severity'].get('high', 0)
            
            if critical_count > 0 or high_count >= 5:
                risk_level = "🚨 **HIGH RISK**"
                recommendation = "Immediate attention required"
            elif high_count > 0 or stats['total_findings'] >= 10:
                risk_level = "⚠️ **MEDIUM RISK**"
                recommendation = "Review and address key issues"
            else:
                risk_level = "✅ **LOW RISK**"
                recommendation = "Monitor and maintain current practices"
            
            summary.append(f"**🎯 Risk Level**: {risk_level}\n")
            summary.append(f"**💡 Recommendation**: {recommendation}\n")
        
        return "".join(summary)
    
    def _generate_category_breakdown(self, findings: List[Finding]) -> str:
        """Generate breakdown by finding category."""
        sections = []
        
        for finding_type in FindingType:
            # 2026-05-19 audit: severity-first sort before slice so a
            # CRITICAL of this type can't be displaced by HIGH/MEDIUM
            # rank-score ties. Cap-severity pattern.
            type_findings = sorted(
                [f for f in findings if f.type == finding_type],
                key=lambda f: 0 if f.severity == Severity.CRITICAL else 1,
            )[:5]  # Top 5 per type
            if type_findings:
                sections.append(f"### {finding_type.value.replace('_', ' ').title()}\n")
                for finding in type_findings:
                    sections.append(f"- **{finding.title}** (`{finding.file_path}:{finding.line_number or 'N/A'}`) - {finding.severity.value}\n")
                sections.append("\n")
        
        return "".join(sections)
    
    def _generate_ai_guidance(self, findings: List[Finding]) -> str:
        """Generate AI-specific coding guidance."""
        guidance = []
        
        # Security guidance
        security_findings = [f for f in findings if f.type == FindingType.SECURITY]
        if security_findings:
            guidance.append("**🔒 Security Focus Areas:**\n")
            guidance.append("- Review authentication and authorization implementations\n")
            guidance.append("- Validate input sanitization and output encoding\n")
            guidance.append("- Check for SQL injection and XSS vulnerabilities\n\n")
        
        # Code quality guidance
        quality_findings = [f for f in findings if f.type == FindingType.CODE_QUALITY]
        if quality_findings:
            guidance.append("**🧹 Code Quality Improvements:**\n")
            guidance.append("- Reduce complexity in high-complexity functions\n")
            guidance.append("- Improve error handling and exception management\n")
            guidance.append("- Consider refactoring large classes and long methods\n\n")
        
        # Privacy guidance
        privacy_findings = [f for f in findings if f.type == FindingType.PRIVACY]
        if privacy_findings:
            guidance.append("**🔒 Privacy Compliance:**\n")
            guidance.append("- Remove or encrypt exposed PII data\n")
            guidance.append("- Implement proper data handling procedures\n")
            guidance.append("- Review compliance with GDPR, CCPA requirements\n\n")
        
        return "".join(guidance)
    
    def _generate_file_priority_list(self, findings: List[Finding]) -> str:
        """Generate priority list of files to focus on."""
        # Group by file and calculate priority scores
        by_file = defaultdict(list)
        for finding in findings:
            by_file[finding.file_path].append(finding)
        
        file_priorities = []
        for file_path, file_findings in by_file.items():
            critical_count = len([f for f in file_findings if f.severity in [Severity.CRITICAL, Severity.HIGH]])
            total_count = len(file_findings)
            priority_score = critical_count * 3 + total_count
            
            file_priorities.append((file_path, total_count, critical_count, priority_score))
        
        # Sort by priority score
        file_priorities.sort(key=lambda x: x[3], reverse=True)
        
        sections = []
        for file_path, total, critical, _ in file_priorities[:10]:  # Top 10 files
            sections.append(f"- **`{file_path}`** - {total} issues ({critical} critical/high)\n")
        
        return "".join(sections)
    
    def _generate_quick_actions(self, findings: List[Finding]) -> str:
        """Generate quick action items."""
        actions = []
        
        # Top critical findings
        # 2026-05-19 audit: severity is already filtered to CRITICAL here,
        # but stable-sort by severity-first is a no-op safety net consistent
        # with the cap-severity pattern applied elsewhere in this file.
        critical_findings = sorted(
            [f for f in findings if f.severity == Severity.CRITICAL],
            key=lambda f: 0 if f.severity == Severity.CRITICAL else 1,
        )[:3]
        if critical_findings:
            actions.append("**🚨 Immediate Actions:**\n")
            for finding in critical_findings:
                actions.append(f"1. Fix {finding.title} in `{finding.file_path}`\n")
            actions.append("\n")
        
        # TODO items that should be addressed in future development
        todo_findings = [f for f in findings if f.type == FindingType.TODO][:5]
        if todo_findings:
            actions.append("**📝 TODO Items to Address:**\n")
            for finding in todo_findings:
                actions.append(f"- {finding.title} (`{finding.file_path}:{finding.line_number}`)\n")
        
        return "".join(actions)
    
    def _get_context_explanation(self, finding: Finding) -> Optional[str]:
        """Get context explanation for why this finding matters."""
        context_library = {
            # Security context explanations
            FindingType.SECURITY: {
                'sql_injection': "SQL injection vulnerabilities allow attackers to manipulate database queries, potentially accessing, modifying, or deleting sensitive data.",
                'xss': "Cross-site scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by other users, enabling session hijacking and data theft.",
                'auth': "Authentication vulnerabilities can allow unauthorized access to protected resources and user accounts.",
                'default': "Security vulnerabilities expose your application to potential attacks and data breaches, compromising user trust and regulatory compliance."
            },
            # Privacy context explanations
            FindingType.PRIVACY: {
                'pii': "Exposed personal information violates privacy regulations like GDPR and CCPA, potentially resulting in significant fines and legal liability.",
                'profanity': "Inappropriate content in code affects team professionalism and can create hostile work environments or damage company reputation.",
                'default': "Privacy issues can lead to regulatory violations, legal liability, and loss of user trust in your application."
            },
            # Code quality context explanations
            FindingType.CODE_QUALITY: {
                'complexity': "High complexity functions are harder to understand, test, and maintain, leading to increased bugs and development time.",
                'exception': "Poor exception handling can cause silent failures, making debugging difficult and potentially leaving the system in an inconsistent state.",
                'duplicate': "Code duplication increases maintenance burden and creates opportunities for inconsistent behavior when only some copies are updated.",
                'default': "Code quality issues increase technical debt, making the codebase harder to maintain and more prone to bugs."
            },
            # Context explanations for TODO findings
            FindingType.TODO: {
                'default': "Unaddressed TODO items represent incomplete functionality or known issues that could impact system reliability or user experience."
            },
            # Architecture context explanations
            FindingType.ARCHITECTURE: {
                'default': "Architectural issues can make the system harder to scale, maintain, and extend, potentially requiring costly refactoring later."
            },
            # Performance context explanations
            FindingType.PERFORMANCE: {
                'default': "Performance issues directly impact user experience and can lead to increased infrastructure costs and user abandonment."
            }
        }
        
        type_contexts = context_library.get(finding.type, {})
        
        # Try to match specific patterns in title or description
        title_lower = finding.title.lower()
        desc_lower = finding.description.lower()
        
        for pattern, explanation in type_contexts.items():
            if pattern == 'default':
                continue
            if pattern in title_lower or pattern in desc_lower:
                return explanation
        
        # Return default explanation for the type
        return type_contexts.get('default', "This issue may impact code quality, security, or maintainability.")
    
    def _get_business_impact(self, finding: Finding) -> Optional[str]:
        """Get business impact explanation for high-impact findings."""
        # Only show business impact for high-impact findings
        if finding.impact_score < 0.7:
            return None
        
        impact_library = {
            FindingType.SECURITY: "Security breaches can result in data theft, regulatory fines, legal liability, and permanent damage to brand reputation.",
            FindingType.PRIVACY: "Privacy violations can trigger GDPR/CCPA fines up to 4% of annual revenue, plus legal costs and reputational damage.",
            FindingType.CODE_QUALITY: "Poor code quality increases development costs, delays feature delivery, and makes the system unreliable for users.",
            FindingType.PERFORMANCE: "Performance issues drive users away, increase infrastructure costs, and can cause system failures under load."
        }
        
        return impact_library.get(finding.type)
    
    def _get_contextual_fix(self, finding: Finding) -> Optional[str]:
        """Get enhanced contextual fix explanation."""
        if not finding.remediation:
            return None
        
        # Enhanced fixes with context
        contextual_fixes = {
            'empty except': f"{finding.remediation}. Consider specific exception types and add logging to track error patterns for debugging.",
            'high complexity': f"{finding.remediation}. Use Extract Method refactoring to break complex logic into smaller, testable units.",
            'profanity': f"{finding.remediation}. Replace with descriptive technical terms that clearly convey the intended meaning.",
            'todo': f"{finding.remediation}. Create a tracked issue to ensure this work gets prioritized and completed."
        }
        
        title_lower = finding.title.lower()
        desc_lower = finding.description.lower()
        
        for pattern, enhanced_fix in contextual_fixes.items():
            if pattern in title_lower or pattern in desc_lower:
                return enhanced_fix
        
        return None
    
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