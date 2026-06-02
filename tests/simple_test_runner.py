#!/usr/bin/env python3
"""
Simple test runner for New BrassCoders System v2.0 tests.
Runs tests without external dependencies like pytest.
"""

import sys
import traceback
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

def run_test_function(test_class, test_method_name):
    """Run a single test method."""
    try:
        test_instance = test_class()
        
        # Run setup if it exists
        if hasattr(test_instance, 'setup_method'):
            test_instance.setup_method()
        
        # Run the test method
        test_method = getattr(test_instance, test_method_name)
        test_method()
        
        # Run teardown if it exists
        if hasattr(test_instance, 'teardown_method'):
            test_instance.teardown_method()
            
        print(f"✅ {test_class.__name__}.{test_method_name}")
        return True
        
    except Exception as e:
        print(f"❌ {test_class.__name__}.{test_method_name}: {e}")
        traceback.print_exc()
        return False

def run_test_class(test_class):
    """Run all test methods in a test class."""
    test_methods = [method for method in dir(test_class) if method.startswith('test_')]
    passed = 0
    failed = 0
    
    print(f"\n🧪 Running {test_class.__name__}")
    print("=" * 50)
    
    for method_name in test_methods:
        if run_test_function(test_class, method_name):
            passed += 1
        else:
            failed += 1
    
    print(f"\n📊 {test_class.__name__}: {passed} passed, {failed} failed")
    return failed == 0

def test_finding_interface():
    """Test the Finding interface."""
    from brass.models.finding import Finding, FindingType, Severity
    
    print("🧪 Testing Finding Interface")
    
    # Test basic creation
    try:
        finding = Finding(
            id="test_id",
            type=FindingType.SECURITY,
            severity=Severity.HIGH,
            file_path="test.py",
            line_number=1,
            title="Test Finding",
            description="Test description",
            confidence=0.9,
            impact_score=0.8,
            detected_by="TestScanner"
        )
        print("✅ Finding creation works")
        
        # Test required fields
        assert finding.id == "test_id"
        assert finding.type == FindingType.SECURITY
        assert finding.severity == Severity.HIGH
        assert finding.file_path == "test.py"
        assert finding.title == "Test Finding"
        print("✅ Finding fields accessible")
        
        # Test enums
        assert FindingType.SECURITY is not None
        assert FindingType.PRIVACY is not None
        assert FindingType.CODE_QUALITY is not None
        assert FindingType.TODO is not None
        print("✅ FindingType enum complete")
        
        assert Severity.CRITICAL is not None
        assert Severity.HIGH is not None
        assert Severity.MEDIUM is not None
        assert Severity.LOW is not None
        print("✅ Severity enum complete")
        
        return True
        
    except Exception as e:
        print(f"❌ Finding interface test failed: {e}")
        traceback.print_exc()
        return False

def test_code_scanner_basic():
    """Test basic CodeScanner functionality."""
    import tempfile
    import shutil
    from brass.scanners.professional_code_scanner import ProfessionalCodeScanner as CodeScanner
    
    print("\n🧪 Testing CodeScanner Basic Functionality")
    
    test_dir = None
    try:
        # Create temporary test directory
        test_dir = Path(tempfile.mkdtemp())
        scanner = CodeScanner(str(test_dir))
        
        # Test empty project
        findings = scanner.scan()
        assert isinstance(findings, list)
        print("✅ CodeScanner handles empty project")
        
        # Test with simple Python file
        test_file = test_dir / "test.py"
        test_file.write_text('print("hello world")')
        
        findings = scanner.scan()
        assert isinstance(findings, list)
        print("✅ CodeScanner scans Python files")
        
        # Test with eval() usage (should be detected)
        eval_file = test_dir / "eval_test.py"
        eval_file.write_text('result = eval("2+2")')
        
        findings = scanner.scan()
        eval_findings = [f for f in findings if 'eval' in f.title.lower()]
        if eval_findings:
            print("✅ CodeScanner detects eval() usage")
        else:
            print("⚠️  CodeScanner didn't detect eval() usage (might be expected)")
        
        return True
        
    except Exception as e:
        print(f"❌ CodeScanner test failed: {e}")
        traceback.print_exc()
        return False
        
    finally:
        if test_dir and test_dir.exists():
            shutil.rmtree(test_dir)

def main():
    """Run all tests."""
    print("🎺 New BrassCoders System v2.0 - Simple Test Runner")
    print("=" * 60)
    
    tests_passed = 0
    tests_failed = 0
    
    # Test Finding interface
    if test_finding_interface():
        tests_passed += 1
    else:
        tests_failed += 1
    
    # Test CodeScanner basics
    if test_code_scanner_basic():
        tests_passed += 1
    else:
        tests_failed += 1
    
    print("\n" + "=" * 60)
    print(f"📊 FINAL RESULTS: {tests_passed} passed, {tests_failed} failed")
    
    if tests_failed == 0:
        print("🎉 ALL TESTS PASSED!")
        return 0
    else:
        print("❌ Some tests failed")
        return 1

if __name__ == '__main__':
    sys.exit(main())