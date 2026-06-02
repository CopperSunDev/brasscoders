"""
Core Finding dataclass - unified data structure for all analysis results.
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from enum import Enum
from datetime import datetime


class FindingType(Enum):
    """Types of findings that can be detected."""
    SECURITY = "security"
    PRIVACY = "privacy"
    CODE_QUALITY = "code_quality"
    TODO = "todo"
    ARCHITECTURE = "architecture"
    PERFORMANCE = "performance"
    ANALYSIS_ERROR = "analysis_error"


class Severity(Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """
    Unified data structure for all analysis findings.
    
    This dataclass represents any issue, observation, or insight discovered
    during code analysis, whether from static analysis, privacy scanning,
    or other detection methods.
    """
    
    # Core identification
    id: str                          # Unique finding identifier
    type: FindingType               # Category of finding
    severity: Severity              # Severity level
    
    # Location information
    file_path: str                  # Relative path to file
    line_number: Optional[int] = None      # Line number (if applicable)
    column: Optional[int] = None           # Column number (if applicable)
    
    # Finding details
    title: str = ""                 # Short descriptive title
    description: str = ""           # Detailed description
    code_snippet: Optional[str] = None     # Relevant code snippet
    
    # Analysis metadata
    confidence: float = 0.0         # Confidence score (0.0-1.0)
    impact_score: float = 0.0      # Impact assessment (0.0-1.0)
    detected_by: str = ""          # Component that detected this
    
    # Remediation
    remediation: Optional[str] = None      # How to fix this issue
    references: Optional[List[str]] = None # Links to documentation/standards
    
    # Privacy-specific (for PrivacyScanner findings)
    privacy_category: Optional[str] = None # PII category (if privacy finding)
    compliance_regions: Optional[List[str]] = None # Affected compliance regions
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict) # Additional component-specific data
    detected_at: datetime = field(default_factory=datetime.now) # When this was detected
    
    def __post_init__(self):
        """Validate finding data after initialization."""
        if not self.id:
            raise ValueError("Finding ID cannot be empty")
        
        if not isinstance(self.type, FindingType):
            raise ValueError("Finding type must be a FindingType enum")
        
        if not isinstance(self.severity, Severity):
            raise ValueError("Severity must be a Severity enum")
        
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("Confidence must be between 0.0 and 1.0")
        
        if not (0.0 <= self.impact_score <= 1.0):
            raise ValueError("Impact score must be between 0.0 and 1.0")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for serialization."""
        return {
            'id': self.id,
            'type': self.type.value,
            'severity': self.severity.value,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'column': self.column,
            'title': self.title,
            'description': self.description,
            'code_snippet': self.code_snippet,
            'confidence': self.confidence,
            'impact_score': self.impact_score,
            'detected_by': self.detected_by,
            'remediation': self.remediation,
            'references': self.references,
            'privacy_category': self.privacy_category,
            'compliance_regions': self.compliance_regions,
            'metadata': self.metadata,
            'detected_at': self.detected_at.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Finding':
        """Create finding from dictionary."""
        # Convert enum strings back to enums
        data['type'] = FindingType(data['type'])
        data['severity'] = Severity(data['severity'])
        
        # Convert datetime string back to datetime
        if isinstance(data['detected_at'], str):
            data['detected_at'] = datetime.fromisoformat(data['detected_at'])
        
        return cls(**data)
    
    def is_critical(self) -> bool:
        """Check if this is a critical finding."""
        return self.severity in [Severity.CRITICAL, Severity.HIGH]
    
    def is_privacy_related(self) -> bool:
        """Check if this is a privacy-related finding."""
        return self.type == FindingType.PRIVACY or self.privacy_category is not None
    
    def get_location_string(self) -> str:
        """Get human-readable location string."""
        if self.line_number is not None:
            if self.column is not None:
                return f"{self.file_path}:{self.line_number}:{self.column}"
            else:
                return f"{self.file_path}:{self.line_number}"
        else:
            return self.file_path