# 🔧 Adding New Scanners to BrassCoders System v2.0

> **Complete guide for developers adding new scanner modules**

## 🎯 Overview

This guide provides step-by-step instructions for adding new scanners to the BrassCoders system. After recent improvements, we now have established patterns that new scanners should follow.

## 📋 Scanner Requirements

### **Essential Requirements**
1. **Single Responsibility**: One scanner = one type of analysis
2. **Finding Interface**: Always return `List[Finding]` 
3. **Error Isolation**: Scanner failures don't crash the system
4. **No Lateral Dependencies**: Don't call other scanners
5. **Path Validation**: Robust input validation and error handling
6. **Logging Integration**: Use the BrassCoders logging system

### **Quality Standards**
- **Input validation** with clear error messages
- **Comprehensive documentation** with examples
- **Error handling** using core utilities
- **Performance considerations** for large codebases
- **Test coverage** with unit and integration tests

## 🏗️ Current Scanner Architecture

### **Scanner Pattern (Based on ContentModerationScanner)**
```python
"""
NewAnalysisScanner - Brief description of what it analyzes.

This component scans for [specific type of issues] in code and comments.
Provides context-aware analysis with configurable patterns.
"""

import re
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime

from brass.models.finding import Finding, FindingType, Severity
from brass.core.file_classifier import FileClassifier
from brass.core.logging_config import get_logger
from brass.core.error_handling import handle_analysis_error, safe_file_operation

logger = get_logger(__name__)

# Configuration constants
MAX_FILE_SIZE_BYTES = 1024 * 1024  # 1MB
DEFAULT_PATTERN_CONFIDENCE = 0.95
DEFAULT_SEVERITY_FALLBACK = 'medium'

class NewAnalysisScanner:
    """
    Scans for [specific analysis type] in source code.
    
    Features:
    - Context-aware detection
    - Configurable patterns
    - Performance optimized for large codebases
    - Error isolation and graceful degradation
    
    Example:
        scanner = NewAnalysisScanner("/path/to/project")
        findings = scanner.scan()
        print(f"Found {len(findings)} issues")
    """
    
    def __init__(self, project_path: str) -> None:
        """
        Initialize scanner.
        
        Args:
            project_path: Root path of project to analyze
            
        Raises:
            ValueError: If project_path is empty or None
            FileNotFoundError: If project_path does not exist
        """
        # Enhanced input validation
        if not project_path:
            raise ValueError("Project path cannot be empty or None")
        
        # Resolve and validate path
        self.project_path = Path(project_path).resolve()
        if not self.project_path.exists():
            raise FileNotFoundError(f"Project path does not exist: {self.project_path}")
        
        # Standard exclude patterns
        self.exclude_patterns = {
            '.git', '.svn', '.hg', '__pycache__', '.pytest_cache',
            'node_modules', '.venv', 'venv', '.env', 'build', 'dist',
            '.brass', '.idea', '.vscode', '.DS_Store'
        }
        
        # File classifier for context awareness
        self.file_classifier = FileClassifier()
        
        # Load patterns (implement _load_patterns method)
        self.analysis_patterns = self._load_patterns()
        
        logger.info(f"NewAnalysisScanner initialized for {self.project_path}")
    
    def scan(self) -> List[Finding]:
        """
        Perform analysis scan.
        
        Returns:
            List of Finding objects representing detected issues
            
        Raises:
            Exception: Re-raises critical errors after logging
        """
        findings = []
        
        try:
            # Discover scannable files
            files = self._discover_files()
            logger.info(f"Discovered {len(files)} scannable files")
            
            # Scan each file
            logger.info(f"Scanning {len(files)} files for [analysis type] issues")
            for file_path in files:
                file_findings = self._scan_file(file_path)
                findings.extend(file_findings)
            
            logger.info(f"[Analysis type] scan complete: {len(findings)} issues found")
            return findings
            
        except Exception as e:
            error_msg = f"Critical error in NewAnalysisScanner: {str(e)}"
            logger.error(error_msg)
            handle_analysis_error(error_msg, "NewAnalysisScanner", "scan")
            raise
    
    def _discover_files(self) -> List[Path]:
        """Discover files to analyze."""
        files = []
        for file_path in self.project_path.rglob('*'):
            if (file_path.is_file() 
                and not any(exclude in file_path.parts for exclude in self.exclude_patterns)
                and file_path.stat().st_size <= MAX_FILE_SIZE_BYTES):
                files.append(file_path)
        return files
    
    def _scan_file(self, file_path: Path) -> List[Finding]:
        """Scan individual file for issues."""
        # Implement file-specific scanning logic
        # Return List[Finding]
        pass
    
    def _load_patterns(self) -> Dict[str, Any]:
        """Load analysis patterns from configuration."""
        # Implement pattern loading logic
        pass
```

## 🚫 **Critical: Avoiding Scanner Redundancy**

### **Pre-Implementation Validation**

**Before implementing any new scanner, you MUST verify it won't duplicate existing functionality:**

1. **Run Duplicate Analysis Check**:
   ```bash
   # Test your proposed scanner on the test project
   PYTHONPATH=src python3 -m brass.cli.brass_cli scan test_deployment
   
   # Analyze results for overlapping detections at same file:line locations
   python3 -c "
   # Use the duplicate analysis script from the PhantomAI completion report
   # to verify zero conflicts with existing scanners
   "
   ```

2. **Review Existing Scanner Capabilities**:
   - **ProfessionalCodeScanner**: Security vulnerabilities (Bandit) + Code quality (Pylint) + Legacy patterns
   - **Brass2PrivacyScanner**: PII detection + Data protection compliance
   - **ContentModerationScanner**: Profanity detection + Content appropriateness
   - **JavaScriptTypeScriptScanner**: JS/TS security + complexity + TODOs
   - **PhantomAICodeScanner**: Broken imports + Stub methods + Dead code analysis

3. **Architectural Questions to Answer**:
   - **Unique Detection Space**: What issues does NO other scanner detect?
   - **Complementary Analysis**: How does this enhance (not duplicate) existing findings?
   - **File Type Focus**: Does this analyze file types/patterns others don't cover?
   - **Analysis Depth**: Does this provide deeper insight into issues others identify?

### **🔍 Redundancy Prevention Guidelines**

**✅ ACCEPTABLE New Scanner Types:**
- **New file format support** (e.g., Rust, Go, Swift language analyzers)
- **Specialized domain analysis** (e.g., Docker security, Kubernetes config issues)
- **Unique structural patterns** (e.g., microservice architecture validation)
- **Advanced context analysis** (e.g., business logic consistency checking)

**❌ AVOID Creating Scanners For:**
- **Duplicate security patterns** - Use ProfessionalCodeScanner extension instead
- **Additional TODO detection** - Already covered by multiple scanners
- **Overlapping code quality** - Extend Pylint configuration rather than new scanner
- **Similar import checking** - PhantomAICodeScanner already handles this comprehensively

### **🎯 Integration Decision Framework**

**Ask these questions before proceeding:**

1. **Zero Overlap Test**: Does your scanner find issues at locations NO other scanner detects?
2. **Unique Value Proposition**: What critical gap does this fill that affects AI development intelligence?
3. **Architectural Fit**: Does this follow single responsibility principle without breaking existing separation?
4. **Maintenance Justification**: Will this scanner provide enough unique value to justify long-term maintenance?

**If ANY scanner already detects similar issues at the same locations, consider these alternatives:**
- **Extend existing scanner** - Add your patterns to an existing scanner's configuration
- **Enhance existing logic** - Improve detection accuracy of current scanners
- **Create specialized filter** - Add post-processing logic to existing findings
- **Contribute upstream** - Add your patterns to Bandit, Pylint, or other tools

### **📋 Mandatory Pre-Implementation Checklist**

- [ ] **Duplicate analysis completed** - Verified zero conflicts with existing scanners
- [ ] **Unique value documented** - Clear explanation of what no other scanner detects
- [ ] **Alternative approaches considered** - Confirmed new scanner is the best solution
- [ ] **Architectural review passed** - Maintains clean separation of concerns
- [ ] **Test project validation** - Demonstrated unique findings on real codebase

**⚠️ CRITICAL**: Any new scanner that creates duplicate findings will be rejected. The PhantomAICodeScanner completion report demonstrates the gold standard for zero-conflict integration.

## 📝 Integration Steps

### **1. Create Scanner File**
```bash
# Create new scanner in scanners directory
touch src/brass/scanners/new_analysis_scanner.py
```

### **2. Register in __init__.py**
```python
# src/brass/scanners/__init__.py
from .professional_code_scanner import ProfessionalCodeScanner
from .brass2_privacy_scanner import Brass2PrivacyScanner  
from .content_moderation_scanner import ContentModerationScanner
from .new_analysis_scanner import NewAnalysisScanner  # Add this

__all__ = [
    'ProfessionalCodeScanner', 
    'Brass2PrivacyScanner', 
    'ContentModerationScanner',
    'NewAnalysisScanner'  # Add this
]
```

### **3. Integrate in CLI**
```python
# src/brass/cli/brass_cli.py

# Add import
from brass.scanners.new_analysis_scanner import NewAnalysisScanner

class BrassCLI:
    def __init__(self):
        # Add scanner instance variable
        self.new_analysis_scanner: Optional[NewAnalysisScanner] = None
    
    def _initialize_components(self, project_path: str, output_dir: str = '.brass') -> None:
        """Initialize all system components."""
        # Add scanner initialization
        if not self.new_analysis_scanner:
            self.new_analysis_scanner = NewAnalysisScanner(project_path)
    
    def _handle_scan(self, args: argparse.Namespace) -> int:
        """Handle scan command."""
        # Add scanner execution
        if should_run_new_analysis:
            print("🔍 Running new analysis...")
            new_findings = self.new_analysis_scanner.scan()
            all_findings.extend(new_findings)
            print(f"   Found {len(new_findings)} new analysis issues")
```

### **4. Add CLI Options (Optional)**
```python
# Add specific command line options for your scanner
scan_parser.add_argument(
    '--new-analysis', 
    action='store_true',
    help='🔍 New analysis only: [description of what it does]'
)
```

### **5. Update Version Command**
```python
# In the version command, add your scanner
print("🔧 Core Components:")
print("   • NewAnalysisScanner - [Brief description]")
```

## 🧪 Testing Requirements

### **Unit Tests**
```python
# tests/unit/test_new_analysis_scanner.py
import pytest
from brass.scanners.new_analysis_scanner import NewAnalysisScanner
from brass.models.finding import Finding, FindingType, Severity

class TestNewAnalysisScanner:
    def test_scanner_initialization(self, tmp_path):
        """Test scanner initializes correctly."""
        scanner = NewAnalysisScanner(str(tmp_path))
        assert scanner.project_path == tmp_path
    
    def test_invalid_project_path(self):
        """Test scanner handles invalid paths."""
        with pytest.raises(FileNotFoundError):
            NewAnalysisScanner("/nonexistent/path")
    
    def test_scan_returns_findings(self, tmp_path):
        """Test scan returns Finding objects."""
        scanner = NewAnalysisScanner(str(tmp_path))
        findings = scanner.scan()
        assert isinstance(findings, list)
        for finding in findings:
            assert isinstance(finding, Finding)
```

### **Integration Tests**
```python
# tests/integration/test_new_analysis_integration.py
def test_new_scanner_cli_integration(tmp_path):
    """Test scanner works with CLI."""
    # Test that CLI can instantiate and run your scanner
    pass

def test_new_scanner_finding_format(tmp_path):
    """Test scanner findings integrate with ranking and output."""
    # Test that findings work with intelligence ranker and output generator
    pass
```

## 📊 Finding Creation Guidelines

### **Required Finding Fields**
```python
finding = Finding(
    id=f"new_analysis_{unique_identifier}",  # Unique across all findings
    type=FindingType.CODE_QUALITY,  # or SECURITY, PRIVACY, TODO
    severity=Severity.MEDIUM,  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    file_path=str(file_path),
    line_number=line_number,  # Optional but recommended
    title="Brief descriptive title",
    description="Detailed description of the issue",
    confidence=0.95,  # 0.0 to 1.0
    impact_score=0.0,  # 0.0 to 1.0
    detected_by="NewAnalysisScanner",
    metadata={
        "custom_field": "value",
        "analysis_specific_data": "here"
    }
)
```

### **ID Generation Best Practices**
```python
# Ensure unique IDs - include position info if multiple issues per line
id = f"new_analysis_{hash(file_path)}_{issue_type}_{line_number}"

# For multiple issues on same line, add position/index
id = f"new_analysis_{hash(file_path)}_{issue_type}_{line_number}_{start_pos}"
```

## 🎯 Advanced Patterns

### **Configuration File Support**
```python
def _load_patterns(self) -> Dict[str, Any]:
    """Load patterns from YAML configuration."""
    config_file = Path(__file__).parent.parent / 'config' / 'new_analysis_patterns.yaml'
    
    if config_file.exists():
        return safe_file_operation(
            str(config_file), 
            lambda: yaml.safe_load(config_file.open()),
            "NewAnalysisScanner", 
            "load_patterns", 
            {}
        )
    else:
        return self._get_fallback_patterns()
```

### **Context-Aware Analysis**
```python
def _scan_file(self, file_path: Path) -> List[Finding]:
    """Scan file with context awareness."""
    # Classify file type for context
    file_classification = self.file_classifier.classify_file(file_path)
    
    # Adjust analysis based on file type
    if file_classification.get('is_test_file'):
        # Reduce severity or skip certain checks for test files
        pass
    
    return findings
```

### **Performance Optimization**
```python
def _scan_file(self, file_path: Path) -> List[Finding]:
    """Optimized file scanning."""
    # Skip large files
    if file_path.stat().st_size > MAX_FILE_SIZE_BYTES:
        logger.info(f"Skipping large file: {file_path}")
        return []
    
    # Use efficient file reading
    try:
        content = file_path.read_text(encoding='utf-8', errors='ignore')
    except Exception as e:
        logger.warning(f"Could not read {file_path}: {e}")
        return []
    
    return self._analyze_content(content, file_path)
```

## ✅ Checklist for New Scanners

- [ ] **Scanner Implementation**
  - [ ] Follows established pattern (init, scan, private methods)
  - [ ] Proper input validation and error handling
  - [ ] Uses BrassCoders logging system
  - [ ] Returns List[Finding] with unique IDs
  - [ ] Includes comprehensive docstrings

- [ ] **Integration**
  - [ ] Added to scanners/__init__.py
  - [ ] Integrated in CLI (import, initialize, execute)
  - [ ] Updated version command
  - [ ] Added CLI options if needed

- [ ] **Testing**
  - [ ] Unit tests for core functionality
  - [ ] Integration tests with CLI
  - [ ] Error handling tests
  - [ ] Performance tests for large files

- [ ] **Documentation**
  - [ ] Scanner purpose and usage documented
  - [ ] Configuration options explained
  - [ ] Examples provided
  - [ ] Added to architectural documentation

- [ ] **Configuration**
  - [ ] Pattern files created if needed
  - [ ] Fallback patterns implemented
  - [ ] Configuration documented

## 🎺 Best Practices Summary

1. **Follow the established patterns** - Use existing scanners as templates
2. **Validate inputs thoroughly** - Prevent crashes from bad data
3. **Use core utilities** - Leverage existing error handling and logging
4. **Design for performance** - Handle large codebases efficiently
5. **Test comprehensively** - Unit, integration, and error scenarios
6. **Document clearly** - Help future developers understand your scanner
7. **Maintain architecture** - Single responsibility and clean interfaces

---

*🎺 New BrassCoders System v2.0 - Revolutionary AI Development Intelligence*