# Test Fixtures - New BrassCoders System v2.0

**Purpose**: Provide comprehensive, stable test data for consistent testing across all test suites.

## 🎯 **Overview**

The fixtures package provides organized test data for validating:
- **Security vulnerability detection** (9 vulnerability categories)
- **Privacy/PII detection** (9 PII data types)  
- **Code quality analysis** (6 quality issue categories)
- **Mixed scenario testing** (combination patterns)

## 📁 **Fixture Organization**

### **Core Fixture Files**
- **`security_test_files.py`** - Security vulnerability test data
- **`privacy_test_files.py`** - PII/privacy issue test data  
- **`code_quality_test_files.py`** - Code quality issue test data
- **`fixture_manager.py`** - Unified fixture management system
- **`test_project.py`** - Legacy basic test fixture

### **Fixture Management System**
```python
from tests.fixtures import FixtureManager, TestProjectTemplate

# Create comprehensive test project
manager = FixtureManager()
files = manager.create_test_project(TestProjectTemplate.COMPREHENSIVE)

# Create specific issue type project
security_files = manager.create_test_project(TestProjectTemplate.SECURITY_FOCUSED)
```

## 🛡️ **Security Test Fixtures**

### **Vulnerability Categories Covered**
1. **Code Injection** - `eval()`, `exec()` vulnerabilities
2. **Command Injection** - `subprocess`, `os.system` vulnerabilities  
3. **Deserialization** - `pickle`, `yaml` unsafe loading
4. **Hardcoded Secrets** - API keys, passwords, tokens
5. **Weak Cryptography** - MD5, SHA1, insecure random
6. **SQL Injection** - Dynamic query construction
7. **XSS Vulnerabilities** - Template injection, HTML injection
8. **Path Traversal** - File access without validation

### **Usage Example**
```python
from tests.fixtures import SecurityTestFiles

# Create security test project
security_files = SecurityTestFiles.create_security_test_project(base_dir)

# Get expected findings
expected = SecurityTestFiles.get_expected_findings()
# Returns: {'eval_injection.py': ['eval() usage detected', ...], ...}
```

### **File Structure**
```
security_test_files/
├── eval_injection.py          # eval() vulnerabilities
├── exec_injection.py          # exec() vulnerabilities  
├── subprocess_injection.py    # Command injection
├── deserialization.py         # Unsafe deserialization
├── hardcoded_secrets.py       # Embedded credentials
├── crypto_issues.py           # Weak cryptographic practices
├── sql_injection.py           # SQL injection patterns
├── xss_vulnerabilities.py     # XSS vulnerability patterns
└── path_traversal.py          # Path traversal vulnerabilities
```

## 🔒 **Privacy Test Fixtures**

### **PII Data Types Covered**
1. **Email Addresses** - Various email formats and contexts
2. **Social Security Numbers** - SSN patterns and formats
3. **Phone Numbers** - US/international phone number formats
4. **Credit Cards** - Visa, MasterCard, Amex patterns
5. **Addresses** - Street addresses, postal codes
6. **Medical Information** - Patient IDs, medical records
7. **Financial Data** - Bank accounts, routing numbers, IBAN
8. **Government IDs** - Driver's license, passport, tax ID
9. **Mixed PII** - Multiple data types in single files

### **Usage Example**
```python
from tests.fixtures import PrivacyTestFiles

# Create privacy test project
privacy_files = PrivacyTestFiles.create_privacy_test_project(base_dir)

# Get expected findings
expected = PrivacyTestFiles.get_expected_pii_findings()
# Returns: {'email_pii.py': ['Email address detected', ...], ...}
```

### **File Structure**
```
privacy_test_files/
├── email_pii.py               # Email address patterns
├── ssn_pii.py                 # Social Security Numbers
├── phone_pii.py               # Phone number patterns
├── credit_card_pii.py         # Credit card numbers
├── address_pii.py             # Address information
├── medical_pii.py             # Medical/health data
├── financial_pii.py           # Banking/financial data
├── government_id_pii.py       # Government identifiers
└── mixed_pii.py               # Multiple PII types
```

## 🧹 **Code Quality Test Fixtures**

### **Quality Issue Categories Covered**
1. **Complexity Issues** - High cyclomatic complexity, deep nesting
2. **Long Parameter Lists** - Functions with excessive parameters
3. **Large Classes** - Classes with too many methods
4. **Empty Exception Handlers** - Silent exception swallowing
5. **TODO Comments** - TODO, FIXME, HACK, XXX markers
6. **Long Functions** - Functions exceeding line limits

### **Usage Example**
```python
from tests.fixtures import CodeQualityTestFiles

# Create quality test project
quality_files = CodeQualityTestFiles.create_code_quality_test_project(base_dir)

# Get expected findings
expected = CodeQualityTestFiles.get_expected_quality_findings()
# Returns: {'complexity_issues.py': ['High cyclomatic complexity', ...], ...}
```

### **File Structure**
```
code_quality_test_files/
├── complexity_issues.py           # High complexity functions
├── long_parameter_lists.py        # Excessive parameters
├── large_classes.py               # Classes with too many methods
├── empty_exception_handlers.py    # Empty except blocks
├── todo_comments.py               # TODO/FIXME/HACK comments
└── long_functions.py              # Excessively long functions
```

## 🎛️ **Fixture Manager Usage**

### **Project Templates**
```python
from tests.fixtures import FixtureManager, TestProjectTemplate

manager = FixtureManager()

# Available templates
templates = [
    TestProjectTemplate.MINIMAL,        # Basic issues for quick testing
    TestProjectTemplate.COMPREHENSIVE,  # All issue types
    TestProjectTemplate.SECURITY_FOCUSED,   # Security only
    TestProjectTemplate.PRIVACY_FOCUSED,    # Privacy only  
    TestProjectTemplate.QUALITY_FOCUSED,    # Code quality only
    TestProjectTemplate.INTEGRATION,    # Mixed for integration tests
]

# Create project
files = manager.create_test_project(TestProjectTemplate.COMPREHENSIVE)
```

### **Custom File Creation**
```python
from tests.fixtures import FixtureManager, FixtureType
from pathlib import Path

manager = FixtureManager()

# Create file with specific issue types
test_file = Path("mixed_issues.py")
manager.create_file_with_issues(
    test_file, 
    [FixtureType.SECURITY, FixtureType.PRIVACY]
)
```

### **Expected Findings**
```python
# Get all expected findings
all_findings = manager.get_expected_findings(FixtureType.ALL)

# Get security-specific findings
security_findings = manager.get_expected_findings(FixtureType.SECURITY)

# Get findings for specific file
file_findings = manager.get_expected_findings(
    FixtureType.SECURITY, 
    "eval_injection.py"
)
```

### **Fixture Statistics**
```python
stats = manager.get_fixture_statistics()
# Returns:
# {
#   'security': {'files': 9, 'expected_findings': 27},
#   'privacy': {'files': 9, 'expected_findings': 27}, 
#   'code_quality': {'files': 6, 'expected_findings': 18},
#   'total': {'files': 24, 'expected_findings': 72}
# }
```

## 🚀 **Quick Start Examples**

### **Unit Test Usage**
```python
import pytest
from tests.fixtures import create_temp_project, TestProjectTemplate

@pytest.fixture
def security_project():
    """Create temporary project with security issues."""
    return create_temp_project(TestProjectTemplate.SECURITY_FOCUSED)

def test_security_scanner(security_project):
    scanner = SecurityScanner(str(security_project))
    findings = scanner.scan()
    assert len(findings) > 0
```

### **Integration Test Usage**
```python
from tests.fixtures import FixtureManager, TestProjectTemplate

def test_full_pipeline():
    manager = FixtureManager()
    project_dir = manager.create_test_project(TestProjectTemplate.INTEGRATION)
    
    # Test complete pipeline
    scanner = CodeScanner(str(project_dir))
    findings = scanner.scan()
    
    # Validate against expected findings
    expected = manager.get_expected_findings(FixtureType.ALL)
    assert len(findings) >= len(expected)
```

### **Performance Test Usage**
```python
from tests.fixtures import FixtureManager, TestProjectTemplate

def test_large_project_performance():
    manager = FixtureManager()
    large_project = manager.create_test_project(TestProjectTemplate.COMPREHENSIVE)
    
    start_time = time.time()
    findings = scan_project(large_project)
    duration = time.time() - start_time
    
    assert duration < 10.0  # Should complete within 10 seconds
    assert len(findings) > 50  # Should find many issues
```

## 📊 **Fixture Statistics**

### **Coverage Summary**
- **Total Test Files**: 24+ specialized test files
- **Security Vulnerabilities**: 9 categories, 27+ expected findings
- **Privacy/PII Issues**: 9 data types, 27+ expected findings  
- **Code Quality Issues**: 6 categories, 18+ expected findings
- **Project Templates**: 6 pre-configured templates
- **Mixed Scenarios**: Comprehensive combination testing

### **File Size and Complexity**
- **Small Files**: 50-100 lines (unit test focused)
- **Medium Files**: 100-300 lines (integration test focused)
- **Large Files**: 300+ lines (performance test focused)
- **Realistic Patterns**: Based on real-world code issues

## 🧪 **Integration with Test Suites**

### **Unit Tests** (`tests/unit/`)
- Use **minimal** or **focused** templates for fast, isolated testing
- Single issue type validation
- Quick feedback on scanner logic

### **Integration Tests** (`tests/integration/`)  
- Use **integration** template for component interaction testing
- Mixed issue type validation
- Component boundary verification

### **End-to-End Tests** (`tests/end_to_end/`)
- Use **comprehensive** template for complete workflow testing
- Full pipeline validation
- Real-world scenario simulation

## 💡 **Best Practices**

### **Fixture Selection**
- **Unit tests**: Use focused templates (SECURITY_FOCUSED, PRIVACY_FOCUSED, etc.)
- **Integration tests**: Use INTEGRATION template for balanced coverage
- **Performance tests**: Use COMPREHENSIVE template for maximum load
- **Quick validation**: Use MINIMAL template for fast feedback

### **Expected Findings Validation**
```python
# Always validate against expected findings
expected = manager.get_expected_findings(FixtureType.SECURITY)
actual_findings = scanner.scan()

# Check that we found expected categories
expected_types = set(expected.keys())
actual_types = {f.file_path for f in actual_findings}
assert expected_types.issubset(actual_types)
```

### **Fixture Maintenance**
- **Update fixtures** when adding new detection capabilities
- **Add expected findings** for new vulnerability patterns
- **Test fixture validity** with actual scanners regularly
- **Document fixture changes** in test documentation

## 🎺 **Benefits**

### **Consistency**
- **Standardized test data** across all test suites
- **Reproducible results** with stable fixtures
- **Predictable findings** for validation

### **Comprehensive Coverage**  
- **All issue types** represented with realistic patterns
- **Edge cases** included for thorough testing
- **Real-world scenarios** based on actual vulnerabilities

### **Developer Experience**
- **Easy fixture creation** with template system
- **Clear expected outcomes** for validation
- **Flexible usage patterns** for different test types

---

**🎺 Test fixtures provide the foundation for reliable, comprehensive testing of New BrassCoders System v2.0, ensuring consistent validation across all analysis capabilities.**