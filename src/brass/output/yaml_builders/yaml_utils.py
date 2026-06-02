"""
Shared utilities for YAML generation.

Contains common functions used across multiple builders,
following DRY principle and Brass2 architectural standards.
"""

import yaml
from pathlib import Path
from typing import List, Dict, Any
from collections import defaultdict, OrderedDict
from datetime import datetime

from brass.models.finding import Finding, Severity
from brass.core.logging_config import get_logger
from brass.core.atomic_writer import AtomicFileWriter
from brass.output.redaction_checker import enforce_or_warn

logger = get_logger(__name__)


class YAMLUtils:
    """Utility functions for YAML generation and data processing."""

    @staticmethod
    def write_yaml_file(file_path: Path, data: Dict[str, Any]) -> None:
        """Write data to YAML file via atomic-rename writer.

        Runtime invariant (A-runtime, 2026-05-16): every YAML payload
        is regex-scanned for credential patterns before flushing to
        disk. In WARN mode (default), leaks get logged + a
        ``_brass_leak_warning`` block prepended to the output. In
        STRICT mode (``BRASS_REDACTION_MODE=strict``), the write is
        aborted via :class:`BrassRedactionError`.

        We intentionally do NOT unlink the destination on exception. The atomic
        writer guarantees the destination is either fully replaced or untouched;
        an exception here typically came from ``convert_to_dict`` (before any
        write attempt), and unlinking would destroy the previous good output —
        a real data-loss bug for re-scans.
        """
        clean_data = YAMLUtils.convert_to_dict(data)

        yaml_kwargs = {
            'default_flow_style': False,
            'sort_keys': False,
            'allow_unicode': True,
            'indent': 2,
            'width': 120
        }

        # Serialize to string first so the runtime leak check can scan
        # the actual bytes that would be written. Doing the check on
        # the dict structure would miss anything that emerges during
        # YAML serialization (escape sequences, multi-line block
        # scalars, etc.) — vanishingly unlikely for credential
        # patterns but cheap insurance to check the real output.
        # safe_dump refuses non-primitive Python objects (no
        # `!!python/object` tags), so a stray Finding subclass or
        # custom dataclass slipping past ``convert_to_dict`` raises
        # at dump time rather than emitting a Python-tagged YAML
        # value that downstream `yaml.safe_load` consumers would
        # reject.
        rendered = yaml.safe_dump(clean_data, **yaml_kwargs)
        safe_rendered, _leaks = enforce_or_warn(rendered, file_path=str(file_path))

        # Write the (possibly warning-prepended) text atomically.
        AtomicFileWriter.write_text_atomic(file_path, safe_rendered)
        logger.debug(f"Generated YAML file: {file_path}")
    
    @staticmethod
    def convert_to_dict(obj):
        """Convert OrderedDict and other objects to regular dict for clean YAML."""
        if isinstance(obj, OrderedDict):
            return {k: YAMLUtils.convert_to_dict(v) for k, v in obj.items()}
        elif isinstance(obj, dict):
            return {k: YAMLUtils.convert_to_dict(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [YAMLUtils.convert_to_dict(item) for item in obj]
        else:
            return obj
    
    @staticmethod
    def generate_summary_stats(findings: List[Finding]) -> Dict[str, Any]:
        """Generate comprehensive summary statistics."""
        if not findings:
            return YAMLUtils._create_empty_stats()
        return YAMLUtils._calculate_full_stats(findings)
    
    @staticmethod
    def _create_empty_stats() -> Dict[str, Any]:
        """Create empty statistics structure."""
        return {
            'total_findings': 0,
            'files_analyzed': 0,
            'avg_confidence': 0,
            'avg_impact': 0,
            'by_type': {},
            'by_severity': {}
        }
    
    @staticmethod
    def _calculate_full_stats(findings: List[Finding]) -> Dict[str, Any]:
        """Calculate complete statistics from findings."""
        unique_files = len(set(f.file_path for f in findings))
        avg_confidence = sum(f.confidence for f in findings) / len(findings)
        avg_impact = sum(f.impact_score for f in findings) / len(findings)
        
        by_type = defaultdict(int)
        by_severity = defaultdict(int)
        for finding in findings:
            by_type[finding.type.value] += 1
            by_severity[finding.severity.value] += 1
        
        return {
            'total_findings': len(findings),
            'files_analyzed': unique_files,
            'avg_confidence': avg_confidence,
            'avg_impact': avg_impact,
            'by_type': dict(by_type),
            'by_severity': dict(by_severity)
        }
    
    @staticmethod
    def get_max_severity(findings: List[Finding]) -> Severity:
        """Get the maximum severity from a list of findings."""
        if not findings:
            return Severity.INFO
        
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
    
    @staticmethod
    def build_common_metadata(project_path: Path, generation_time: datetime) -> OrderedDict:
        """Build metadata section common to all files."""
        return OrderedDict([
            ('generated_at', generation_time.isoformat()),
            ('project_path', str(project_path)),
            ('analysis_engine', 'brass v2')
        ])