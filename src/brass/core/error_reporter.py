"""
Structured error reporting system for the BrassCoders system.

Provides comprehensive error collection, analysis, and reporting
capabilities for debugging and system monitoring.
"""

import json
import threading
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from dataclasses import asdict

from brass.core.error_handling import BrassError, ErrorCategory
from brass.core.logging_config import get_logger

logger = get_logger(__name__)


class ErrorReporter:
    """
    Comprehensive error reporting and analysis system.
    
    Collects errors from across the system, analyzes patterns,
    and generates structured reports for debugging and monitoring.
    """
    
    def __init__(self, output_dir: Optional[str] = None):
        """
        Initialize error reporter.
        
        Args:
            output_dir: Directory for error reports (default: .brass)
        """
        self.output_dir = Path(output_dir or '.brass')
        self.errors: List[BrassError] = []
        self.session_start = datetime.now()
    
    def add_error(self, error: BrassError) -> None:
        """
        Add an error to the collection for reporting.
        
        Args:
            error: BrassError instance to add
        """
        self.errors.append(error)
        logger.debug(f"Added error to reporter: {error.component}.{error.operation}")
    
    def get_error_summary(self) -> Dict[str, Any]:
        """
        Generate summary statistics for collected errors.
        
        Returns:
            Dictionary with error summary statistics
        """
        if not self.errors:
            return {
                'total_errors': 0,
                'session_duration': str(datetime.now() - self.session_start),
                'categories': {},
                'components': {},
                'operations': {},
                'files_affected': 0
            }
        
        # Count by various dimensions
        categories = Counter(error.category.name for error in self.errors)
        components = Counter(error.component for error in self.errors)
        operations = Counter(error.operation for error in self.errors)
        files_with_errors = set(error.file_path for error in self.errors if error.file_path)
        
        # Calculate time patterns
        recent_errors = [
            error for error in self.errors 
            if error.timestamp > datetime.now() - timedelta(minutes=5)
        ]
        
        return {
            'total_errors': len(self.errors),
            'session_duration': str(datetime.now() - self.session_start),
            'categories': dict(categories),
            'components': dict(components),
            'operations': dict(operations),
            'files_affected': len(files_with_errors),
            'recent_errors_5min': len(recent_errors),
            'error_rate_per_minute': len(self.errors) / max(1, (datetime.now() - self.session_start).total_seconds() / 60)
        }
    
    def get_error_patterns(self) -> Dict[str, Any]:
        """
        Analyze error patterns for debugging insights.
        
        Returns:
            Dictionary with error pattern analysis
        """
        if not self.errors:
            return {'patterns': []}
        
        patterns = []
        
        # Pattern 1: Repeated errors in same file/operation
        file_operation_errors = defaultdict(list)
        for error in self.errors:
            key = f"{error.file_path}:{error.operation}" if error.file_path else error.operation
            file_operation_errors[key].append(error)
        
        for key, error_list in file_operation_errors.items():
            if len(error_list) > 1:
                patterns.append({
                    'type': 'repeated_error',
                    'location': key,
                    'count': len(error_list),
                    'first_seen': min(e.timestamp for e in error_list).isoformat(),
                    'last_seen': max(e.timestamp for e in error_list).isoformat(),
                    'description': f"Repeated error in {key} ({len(error_list)} times)"
                })
        
        # Pattern 2: Error cascades (multiple errors in short time)
        sorted_errors = sorted(self.errors, key=lambda e: e.timestamp)
        cascade_threshold = timedelta(seconds=10)
        
        i = 0
        while i < len(sorted_errors):
            cascade_errors = [sorted_errors[i]]
            j = i + 1
            
            while j < len(sorted_errors) and (sorted_errors[j].timestamp - cascade_errors[-1].timestamp) <= cascade_threshold:
                cascade_errors.append(sorted_errors[j])
                j += 1
            
            if len(cascade_errors) >= 3:  # Consider 3+ errors in 10 seconds a cascade
                patterns.append({
                    'type': 'error_cascade',
                    'count': len(cascade_errors),
                    'duration': str(cascade_errors[-1].timestamp - cascade_errors[0].timestamp),
                    'start_time': cascade_errors[0].timestamp.isoformat(),
                    'components': list(set(e.component for e in cascade_errors)),
                    'description': f"Error cascade: {len(cascade_errors)} errors in {cascade_errors[-1].timestamp - cascade_errors[0].timestamp}"
                })
            
            i = j if j > i + 1 else i + 1
        
        return {'patterns': patterns}
    
    def generate_error_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive error report.
        
        Returns:
            Complete error report with summary, patterns, and details
        """
        report = {
            'report_generated': datetime.now().isoformat(),
            'session_info': {
                'start_time': self.session_start.isoformat(),
                'duration': str(datetime.now() - self.session_start)
            },
            'summary': self.get_error_summary(),
            'patterns': self.get_error_patterns(),
            'errors': [error.to_dict() for error in self.errors]
        }
        
        # Add recommendations based on patterns
        recommendations = []
        
        if report['summary']['total_errors'] > 10:
            recommendations.append("High error count detected. Review error patterns and consider adding more robust error handling.")
        
        if report['summary']['error_rate_per_minute'] > 2:
            recommendations.append("High error rate detected. This may indicate systemic issues that need investigation.")
        
        cascade_patterns = [p for p in report['patterns']['patterns'] if p['type'] == 'error_cascade']
        if cascade_patterns:
            recommendations.append("Error cascades detected. Review error propagation and consider adding circuit breakers.")
        
        repeated_patterns = [p for p in report['patterns']['patterns'] if p['type'] == 'repeated_error']
        if repeated_patterns:
            recommendations.append("Repeated errors detected. Focus on fixing the most frequent error sources first.")
        
        report['recommendations'] = recommendations
        
        return report
    
    def save_error_report(self, filename: str = 'error_report.json') -> str:
        """
        Save error report to file.
        
        Args:
            filename: Name of report file
            
        Returns:
            Path to saved report file
        """
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            report_path = self.output_dir / filename
            
            report = self.generate_error_report()
            
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Error report saved to {report_path}")
            return str(report_path)
            
        except Exception as e:
            logger.error(f"Failed to save error report: {e}")
            return ""
    
    def get_debugging_hints(self) -> List[str]:
        """
        Generate debugging hints based on error patterns.
        
        Returns:
            List of debugging suggestions
        """
        hints = []
        
        if not self.errors:
            return ["No errors detected in this session."]
        
        # Analyze common error categories with safe array access
        categories = Counter(error.category.name for error in self.errors)
        most_common_list = categories.most_common(1)
        
        if most_common_list:  # Ensure list is not empty before accessing [0]
            most_common_category = most_common_list[0]
            
            if most_common_category[0] == ErrorCategory.FILE_ACCESS.name:
                hints.append("Many file access errors detected. Check file permissions, paths, and disk space.")
            elif most_common_category[0] == ErrorCategory.PARSING.name:
                hints.append("Many parsing errors detected. Review input data format and syntax validation.")
            elif most_common_category[0] == ErrorCategory.ANALYSIS.name:
                hints.append("Many analysis errors detected. Consider adding more robust input validation.")
        
        # Analyze file patterns with safe array access
        files_with_errors = [e.file_path for e in self.errors if e.file_path]
        if files_with_errors:
            file_counts = Counter(files_with_errors)
            most_problematic_list = file_counts.most_common(1)
            if most_problematic_list:  # Ensure list is not empty before accessing [0]
                most_problematic = most_problematic_list[0]
                hints.append(f"File '{most_problematic[0]}' has {most_problematic[1]} errors. Focus debugging efforts here.")
        
        # Analyze components with safe array access
        components = Counter(error.component for error in self.errors)
        most_problematic_component_list = components.most_common(1)
        if most_problematic_component_list:  # Ensure list is not empty before accessing [0]
            most_problematic_component = most_problematic_component_list[0]
            hints.append(f"Component '{most_problematic_component[0]}' generated {most_problematic_component[1]} errors.")
        
        return hints
    
    def clear_errors(self) -> None:
        """Clear collected errors and reset session."""
        logger.info(f"Clearing {len(self.errors)} collected errors")
        self.errors.clear()
        self.session_start = datetime.now()


# Global error reporter instance with thread safety
_global_reporter: Optional[ErrorReporter] = None
_reporter_lock = threading.Lock()

def get_error_reporter(output_dir: Optional[str] = None) -> ErrorReporter:
    """
    Get global error reporter instance (thread-safe).
    
    Uses double-checked locking pattern to ensure thread-safe singleton creation
    while maintaining performance for subsequent accesses.
    
    Args:
        output_dir: Output directory for reports
        
    Returns:
        Global ErrorReporter instance
    """
    global _global_reporter
    # Fast path: reporter already initialized
    if _global_reporter is None:
        # Slow path: acquire lock and double-check
        with _reporter_lock:
            # Double-checked locking: verify reporter still None after acquiring lock
            if _global_reporter is None:
                _global_reporter = ErrorReporter(output_dir)
    return _global_reporter

def report_error(error: BrassError) -> None:
    """
    Report an error to the global error reporter.
    
    Args:
        error: BrassError to report
    """
    reporter = get_error_reporter()
    reporter.add_error(error)

def save_session_error_report() -> str:
    """
    Save current session's error report.
    
    Returns:
        Path to saved report file
    """
    reporter = get_error_reporter()
    return reporter.save_error_report(f'error_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')