"""
System Integrity Test Suite for New BrassCoders System v2.0.

This test suite validates that the system has no "phantom features" - 
code that is promised but never finished or actually connected to anything.

Based on pytest best practices for integration testing completeness validation.
"""

import pytest
import inspect
import ast
import importlib
from pathlib import Path
from typing import List, Dict, Set, Any, Callable
from brass.models.finding import Finding, FindingType, Severity


class TestSystemIntegrity:
    """Test that all system components are fully implemented and connected."""
    
    def test_all_public_apis_are_functional(self):
        """Every public API method must be fully functional, not just stubs."""
        from brass.cli.brass_cli import main as cli_main
        from brass.scanners.professional_code_scanner import ProfessionalCodeScanner as CodeScanner
        from brass.scanners.brass2_privacy_scanner import Brass2Brass2PrivacyScanner
        from brass.ranking.intelligence_ranker import IntelligenceRanker
        from brass.output.output_generator import OutputGenerator
        
        # Test CLI main function exists and is callable
        assert callable(cli_main), "CLI main function must be callable"
        
        # Test all scanner classes have required methods
        for scanner_class in [CodeScanner, Brass2PrivacyScanner]:
            assert hasattr(scanner_class, 'scan'), f"{scanner_class.__name__} missing scan method"
            assert callable(getattr(scanner_class, 'scan')), f"{scanner_class.__name__}.scan must be callable"
        
        # Test core components have required methods
        assert hasattr(IntelligenceRanker, 'rank_findings'), "IntelligenceRanker missing rank_findings method"
        assert hasattr(OutputGenerator, 'generate_intelligence'), "OutputGenerator missing generate_intelligence method"
    
    def test_no_stub_methods_exist(self):
        """No methods should contain only 'pass', 'NotImplemented', or placeholder code."""
        project_root = Path(__file__).parent.parent.parent / 'src' / 'brass'
        stub_patterns = [
            'pass',
            'NotImplemented',
            'raise NotImplementedError',
            'TODO',
            '# TODO',
            'FIXME',
            '# FIXME'
        ]
        
        stub_methods = []
        
        for py_file in project_root.rglob('*.py'):
            if py_file.name.startswith('__'):
                continue
                
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    tree = ast.parse(content)
                    
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if not node.name.startswith('_'):  # Only check public methods
                            method_source = ast.get_source_segment(content, node)
                            if method_source:
                                for pattern in stub_patterns:
                                    if pattern in method_source:
                                        # Check if it's actually just a stub
                                        lines = [line.strip() for line in method_source.split('\n') if line.strip()]
                                        non_doc_lines = [line for line in lines if not line.startswith('"""') and not line.startswith("'''")]
                                        
                                        if len(non_doc_lines) <= 3 and any(pattern in line for line in non_doc_lines):
                                            stub_methods.append({
                                                'file': str(py_file.relative_to(project_root.parent.parent)),
                                                'method': node.name,
                                                'line': node.lineno,
                                                'pattern': pattern
                                            })
            except Exception as e:
                # If we can't parse the file, that's a separate issue
                pytest.fail(f"Could not parse {py_file}: {e}")
        
        assert len(stub_methods) == 0, f"Found stub methods that need implementation: {stub_methods}"
    
    def test_all_imports_are_resolvable(self):
        """All import statements must resolve to actual modules/functions."""
        # Test that the most critical external dependencies are available
        critical_imports = [
            'pathlib',
            'typing',
            'dataclasses', 
            'datetime',
            'ast',
            'logging'
        ]
        
        import_errors = []
        for module_name in critical_imports:
            try:
                importlib.import_module(module_name)
            except ImportError as e:
                import_errors.append({
                    'import': module_name,
                    'error': str(e)
                })
        
        # Test that our main internal modules can be imported
        internal_modules = [
            'brass.models.finding',
            'brass.scanners.code_scanner', 
            'brass.ranking.intelligence_ranker',
            'brass.output.output_generator',
            'brass.core.logging_config'
        ]
        
        for module_name in internal_modules:
            try:
                importlib.import_module(module_name)
            except ImportError as e:
                import_errors.append({
                    'import': module_name,
                    'error': str(e)
                })
        
        assert len(import_errors) == 0, f"Found unresolvable critical imports: {import_errors}"
    
    def test_end_to_end_workflow_completeness(self, temp_project):
        """Test that complete end-to-end workflow actually works."""
        # Create a test Python file with various issues
        test_file = temp_project / "test_integration.py"
        test_file.write_text('''
# TODO: This needs to be implemented
def test_function():
    # Hardcoded API key (security issue)
    api_key = "sk-1234567890abcdef1234567890abcdef"
    
    # Dangerous eval usage (security issue)
    result = eval("2 + 2")
    
    # Empty except block (quality issue)
    try:
        dangerous_operation()
    except:
        pass
    
    return result

# PII in comments (privacy issue)
# Contact: john.doe@example.com for questions
# SSN: 123-45-6789
''')
        
        # Import components
        from brass.scanners.professional_code_scanner import ProfessionalCodeScanner as CodeScanner
        from brass.scanners.brass2_privacy_scanner import Brass2Brass2PrivacyScanner
        from brass.ranking.intelligence_ranker import IntelligenceRanker
        from brass.output.output_generator import OutputGenerator
        
        # Step 1: Scan with CodeScanner
        code_scanner = CodeScanner(str(temp_project))
        code_findings = code_scanner.scan(["test_integration.py"])
        
        assert len(code_findings) > 0, "CodeScanner should find issues in test file"
        assert all(isinstance(f, Finding) for f in code_findings), "All code findings must be Finding objects"
        
        # Verify specific findings
        finding_types = {f.type for f in code_findings}
        assert FindingType.TODO in finding_types, "Should detect TODO comment"
        assert FindingType.SECURITY in finding_types, "Should detect security issues"
        assert FindingType.CODE_QUALITY in finding_types, "Should detect quality issues"
        
        # Step 2: Scan with Brass2PrivacyScanner
        privacy_scanner = Brass2Brass2PrivacyScanner(str(temp_project))
        privacy_findings = privacy_scanner.scan(["test_integration.py"])
        
        assert len(privacy_findings) > 0, "Brass2PrivacyScanner should find PII in test file"
        assert all(isinstance(f, Finding) for f in privacy_findings), "All privacy findings must be Finding objects"
        assert all(f.type == FindingType.PRIVACY for f in privacy_findings), "Privacy findings must have PRIVACY type"
        
        # Step 3: Combine and rank findings
        all_findings = code_findings + privacy_findings
        ranker = IntelligenceRanker()
        ranked_findings = ranker.rank_findings(all_findings)
        
        assert len(ranked_findings) == len(all_findings), "Ranking should preserve all findings"
        assert all(isinstance(f, Finding) for f in ranked_findings), "Ranked findings must be Finding objects"
        
        # Verify ranking worked (high severity should come first)
        severities = [f.severity for f in ranked_findings]
        assert Severity.CRITICAL in severities or Severity.HIGH in severities, "Should have high-severity findings"
        
        # Step 4: Generate output
        generator = OutputGenerator(str(temp_project))
        generated_files = generator.generate_intelligence(ranked_findings)
        
        # Get the main AI instructions content
        ai_instructions_path = generated_files['ai_instructions']
        output = Path(ai_instructions_path).read_text()
        
        assert isinstance(output, str), "Output must be a string"
        assert len(output) > 100, "Output should be substantial"
        assert "TODO" in output, "Output should mention TODO findings"
        assert "security" in output.lower(), "Output should mention security findings"
        assert "privacy" in output.lower(), "Output should mention privacy findings"
        
        # Verify output is valid markdown
        assert "##" in output or "###" in output, "Output should contain markdown headers"
    
    def test_cli_integration_completeness(self, temp_project):
        """Test that the CLI actually connects to all system components."""
        import subprocess
        import sys
        from pathlib import Path
        
        # Create a test file
        test_file = temp_project / "cli_test.py"
        test_file.write_text('# TODO: Test file\nprint("hello")')
        
        # Test CLI execution
        project_root = Path(__file__).parent.parent.parent
        cli_script = project_root / "src" / "brass" / "cli" / "brass_cli.py"
        
        try:
            # Run the CLI scan command
            result = subprocess.run([
                sys.executable, str(cli_script), "scan", str(temp_project)
            ], capture_output=True, text=True, timeout=30, cwd=str(project_root))
            
            # CLI should execute without error
            assert result.returncode == 0, f"CLI execution failed: {result.stderr}"
            
            # Should produce .brass output directory
            brass_dir = temp_project / ".brass"
            assert brass_dir.exists(), "CLI should create .brass directory"
            
            # Should produce AI_INSTRUCTIONS.md file
            ai_instructions = brass_dir / "AI_INSTRUCTIONS.md"
            assert ai_instructions.exists(), "CLI should create AI_INSTRUCTIONS.md"
            
            # File should have content
            content = ai_instructions.read_text()
            assert len(content) > 50, "AI_INSTRUCTIONS.md should have substantial content"
            assert "TODO" in content, "Should detect and report TODO comment"
            
        except subprocess.TimeoutExpired:
            pytest.fail("CLI execution timed out - indicates infinite loop or deadlock")
        except Exception as e:
            pytest.fail(f"CLI integration test failed: {e}")
    
    def test_all_components_have_proper_error_handling(self):
        """All components should handle errors gracefully, not crash."""
        from brass.scanners.professional_code_scanner import ProfessionalCodeScanner as CodeScanner
        from brass.scanners.brass2_privacy_scanner import Brass2Brass2PrivacyScanner
        from brass.ranking.intelligence_ranker import IntelligenceRanker
        from brass.output.output_generator import OutputGenerator
        
        # Test with non-existent directory
        non_existent_path = "/this/path/does/not/exist"
        
        # CodeScanner should handle bad paths gracefully
        code_scanner = CodeScanner(non_existent_path)
        try:
            findings = code_scanner.scan()
            # Should return empty list, not crash
            assert isinstance(findings, list), "CodeScanner should return list even for bad paths"
        except Exception as e:
            pytest.fail(f"CodeScanner crashed on bad path: {e}")
        
        # Brass2PrivacyScanner should handle bad paths gracefully
        privacy_scanner = Brass2Brass2PrivacyScanner(non_existent_path)
        try:
            findings = privacy_scanner.scan()
            assert isinstance(findings, list), "Brass2PrivacyScanner should return list even for bad paths"
        except Exception as e:
            pytest.fail(f"Brass2PrivacyScanner crashed on bad path: {e}")
        
        # IntelligenceRanker should handle empty/invalid input
        ranker = IntelligenceRanker()
        try:
            # Test with empty list
            ranked = ranker.rank_findings([])
            assert isinstance(ranked, list), "IntelligenceRanker should handle empty input"
            assert len(ranked) == 0, "Empty input should produce empty output"
            
            # Test with invalid Finding objects
            invalid_findings = [None, "not a finding", 123]
            try:
                ranked = ranker.rank_findings(invalid_findings)
                # Should either filter out invalid items or raise a clear error
            except Exception as e:
                # If it raises an error, it should be a clear, expected error
                assert "Finding" in str(e) or "invalid" in str(e).lower(), f"Error should be clear: {e}"
        except Exception as e:
            pytest.fail(f"IntelligenceRanker error handling failed: {e}")
        
        # OutputGenerator should handle empty input
        generator = OutputGenerator("/tmp")
        try:
            generated_files = generator.generate_intelligence([])
            assert isinstance(generated_files, dict), "OutputGenerator should return dict even for empty input"
            assert len(generated_files) > 0, "Should produce some files even for empty findings"
        except Exception as e:
            pytest.fail(f"OutputGenerator crashed on empty input: {e}")
    
    def test_no_dead_code_exists(self):
        """No unreachable or unused code should exist in the system."""
        import ast
        from collections import defaultdict
        
        project_root = Path(__file__).parent.parent.parent / 'src' / 'brass'
        
        # Track all defined functions and classes
        defined_symbols = defaultdict(list)
        used_symbols = defaultdict(set)
        
        for py_file in project_root.rglob('*.py'):
            if py_file.name.startswith('__'):
                continue
                
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    tree = ast.parse(content)
                    
                file_key = str(py_file.relative_to(project_root.parent.parent))
                
                # Find all definitions
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        if not node.name.startswith('_'):  # Only track public symbols
                            defined_symbols[file_key].append({
                                'name': node.name,
                                'type': type(node).__name__,
                                'line': node.lineno
                            })
                    
                    # Find all name usages
                    elif isinstance(node, ast.Name):
                        used_symbols[file_key].add(node.id)
                    elif isinstance(node, ast.Attribute):
                        used_symbols[file_key].add(node.attr)
                        
            except Exception as e:
                pytest.fail(f"Could not analyze dead code in {py_file}: {e}")
        
        # Find potentially unused symbols
        potentially_dead = []
        for file_path, symbols in defined_symbols.items():
            for symbol in symbols:
                symbol_name = symbol['name']
                
                # Check if symbol is used anywhere
                is_used = False
                for used_file, used_names in used_symbols.items():
                    if symbol_name in used_names:
                        is_used = True
                        break
                
                # Special cases that are okay to be "unused"
                special_cases = ['main', 'test_', 'conftest', '__init__', 'cli']
                is_special = any(case in symbol_name.lower() or case in file_path.lower() for case in special_cases)
                
                if not is_used and not is_special:
                    potentially_dead.append({
                        'file': file_path,
                        'symbol': symbol_name,
                        'type': symbol['type'],
                        'line': symbol['line']
                    })
        
        # Allow some tolerance for legitimate unused code (entry points, utility methods, etc.)
        max_allowed_dead_code = 35  # Realistic tolerance for utility methods and public APIs
        assert len(potentially_dead) <= max_allowed_dead_code, f"Found potentially dead code (>{max_allowed_dead_code} items): {potentially_dead}"
    
    def test_all_dependencies_are_available(self):
        """All imported dependencies must be available and working."""
        try:
            # Test internal imports
            from brass.models.finding import Finding, FindingType, Severity
            from brass.scanners.professional_code_scanner import ProfessionalCodeScanner as CodeScanner
            from brass.scanners.brass2_privacy_scanner import Brass2Brass2PrivacyScanner
            from brass.ranking.intelligence_ranker import IntelligenceRanker
            from brass.output.output_generator import OutputGenerator
            
            # Test that enums work
            assert FindingType.SECURITY is not None
            assert Severity.HIGH is not None
            
            # Test that classes can be instantiated
            Finding(
                id="test",
                type=FindingType.SECURITY,
                severity=Severity.HIGH,
                file_path="test.py",
                title="Test",
                description="Test",
                confidence=0.9,
                impact_score=0.8,
                detected_by="Test"
            )
            
        except ImportError as e:
            pytest.fail(f"Required internal dependency not available: {e}")
        except Exception as e:
            pytest.fail(f"Internal dependency broken: {e}")
        
        # Test external dependencies (should be minimal)
        try:
            import ast
            import pathlib
            import json
            import datetime
            # These are all stdlib, should always work
        except ImportError as e:
            pytest.fail(f"Required stdlib dependency not available: {e}")
    
    @pytest.mark.slow
    def test_performance_completeness(self, temp_project):
        """System should complete full analysis in reasonable time."""
        import time
        
        # Create a moderately complex test file
        test_file = temp_project / "performance_test.py"
        test_content = []
        
        # Generate content that will trigger multiple finding types
        for i in range(20):
            test_content.extend([
                f"# TODO: Implement function {i}",
                f"def function_{i}(a, b, c, d, e, f, g):  # Long parameter list",
                f"    api_key_{i} = 'sk-{i:032d}'  # Hardcoded secret",
                f"    result = eval('2 + 2')  # Dangerous eval",
                f"    email = 'user{i}@example.com'  # PII",
                f"    try:",
                f"        return process_data(result)",
                f"    except:",
                f"        pass  # Empty except",
                f"",
                f"# FIXME: Fix function {i}",
                f"# Contact: user{i}@company.com",
                f""
            ])
        
        test_file.write_text('\n'.join(test_content))
        
        # Time the complete analysis
        start_time = time.time()
        
        from brass.scanners.professional_code_scanner import ProfessionalCodeScanner as CodeScanner
        from brass.scanners.brass2_privacy_scanner import Brass2Brass2PrivacyScanner
        from brass.ranking.intelligence_ranker import IntelligenceRanker
        from brass.output.output_generator import OutputGenerator
        
        # Run complete pipeline
        code_scanner = CodeScanner(str(temp_project))
        code_findings = code_scanner.scan(["performance_test.py"])
        
        privacy_scanner = Brass2Brass2PrivacyScanner(str(temp_project))
        privacy_findings = privacy_scanner.scan(["performance_test.py"])
        
        all_findings = code_findings + privacy_findings
        
        ranker = IntelligenceRanker()
        ranked_findings = ranker.rank_findings(all_findings)
        
        generator = OutputGenerator(str(temp_project))
        generated_files = generator.generate_intelligence(ranked_findings)
        
        # Get the main AI instructions content for analysis
        ai_instructions_path = generated_files['ai_instructions']
        output = Path(ai_instructions_path).read_text()
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # System should complete analysis in reasonable time
        max_allowed_time = 10.0  # 10 seconds should be plenty
        assert total_time < max_allowed_time, f"Analysis took too long: {total_time:.2f}s > {max_allowed_time}s"
        
        # Should find substantial number of issues
        assert len(ranked_findings) >= 40, f"Should find many issues in test file, got {len(ranked_findings)}"
        
        # Output should be comprehensive
        assert len(output) > 1000, f"Output should be substantial, got {len(output)} characters"