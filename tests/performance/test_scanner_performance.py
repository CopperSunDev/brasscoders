"""
Performance benchmarks for scanner components.

Tests CodeScanner and PrivacyScanner performance characteristics
following Brass2 clean architecture principles.
"""

import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from brass.scanners.professional_code_scanner import ProfessionalCodeScanner as CodeScanner
from brass.scanners.brass2_privacy_scanner import Brass2PrivacyScanner as PrivacyScanner
from brass.core.logging_config import BrassLogger

from .benchmark_runner import PerformanceBenchmarker
from .benchmark_fixtures import BenchmarkFixtureGenerator

# Setup logging for benchmarks
BrassLogger.setup_logging(verbose=False)


class ScannerPerformanceBenchmark:
    """
    Performance benchmarks for scanner components.
    
    Following Brass2 principles:
    - Single responsibility: only measures scanner performance
    - Clean interfaces: uses standard benchmark infrastructure
    - Evidence-based: measures actual scan performance
    """
    
    def __init__(self):
        self.benchmarker = PerformanceBenchmarker()
        self.fixture_generator = BenchmarkFixtureGenerator()
    
    def benchmark_code_scanner(self):
        """Benchmark CodeScanner performance across different project sizes."""
        print("🔍 Benchmarking CodeScanner performance...")
        
        # Test with different fixture sizes
        fixtures = [
            self.fixture_generator.create_simple_python_project(),
            self.fixture_generator.create_medium_python_project(),
            self.fixture_generator.create_complex_project_structure()
        ]
        
        try:
            for fixture in fixtures:
                # Create scanner for this fixture
                scanner = CodeScanner(str(fixture.fixture_path))
                
                # Benchmark the scan operation
                self.benchmarker.benchmark_with_profiling(
                    f"CodeScanner - {fixture.name} ({fixture.file_count} files)",
                    lambda: scanner.scan()
                )
                
                # Benchmark individual methods if they're significant
                if fixture.complexity_level == "complex":
                    self.benchmarker.benchmark(
                        f"CodeScanner AST Analysis - {fixture.name}",
                        lambda: scanner._analyze_python_file(fixture.fixture_path / "src" / "auth" / "auth_1.py"),
                        iterations=3
                    )
        
        finally:
            # Cleanup fixtures
            for fixture in fixtures:
                fixture.cleanup()
    
    def benchmark_privacy_scanner(self):
        """Benchmark PrivacyScanner performance across different project sizes."""
        print("🔒 Benchmarking PrivacyScanner performance...")
        
        # Test with different fixture sizes
        fixtures = [
            self.fixture_generator.create_simple_python_project(),
            self.fixture_generator.create_medium_python_project()
        ]
        
        try:
            for fixture in fixtures:
                # Create scanner for this fixture
                scanner = PrivacyScanner(str(fixture.fixture_path))
                
                # Benchmark the scan operation
                self.benchmarker.benchmark_with_profiling(
                    f"PrivacyScanner - {fixture.name} ({fixture.file_count} files)",
                    lambda: scanner.scan()
                )
                
                # Test privacy scanning with different modes
                if scanner.has_content_safety:
                    self.benchmarker.benchmark(
                        f"PrivacyScanner API-Safe - {fixture.name}",
                        lambda: scanner.scan(api_safe_mode=True),
                        iterations=2
                    )
        
        finally:
            # Cleanup fixtures
            for fixture in fixtures:
                fixture.cleanup()
    
    def benchmark_scanner_initialization(self):
        """Benchmark scanner initialization overhead."""
        print("⚡ Benchmarking scanner initialization...")
        
        # Create a simple fixture for initialization testing
        simple_fixture = self.fixture_generator.create_simple_python_project()
        
        try:
            project_path = str(simple_fixture.fixture_path)
            
            # Benchmark CodeScanner initialization
            self.benchmarker.benchmark(
                "CodeScanner initialization",
                lambda: CodeScanner(project_path),
                iterations=10
            )
            
            # Benchmark PrivacyScanner initialization
            self.benchmarker.benchmark(
                "PrivacyScanner initialization", 
                lambda: PrivacyScanner(project_path),
                iterations=10
            )
        
        finally:
            simple_fixture.cleanup()
    
    def benchmark_file_discovery(self):
        """Benchmark file discovery performance."""
        print("📁 Benchmarking file discovery performance...")
        
        # Create complex fixture for file discovery testing
        complex_fixture = self.fixture_generator.create_complex_project_structure()
        
        try:
            scanner = CodeScanner(str(complex_fixture.fixture_path))
            
            # Benchmark file discovery methods
            self.benchmarker.benchmark(
                f"File discovery - {complex_fixture.file_count} files",
                lambda: scanner._discover_python_files(),
                iterations=5
            )
        
        finally:
            complex_fixture.cleanup()
    
    def benchmark_memory_usage_scaling(self):
        """Benchmark memory usage scaling with project size."""
        print("💾 Benchmarking memory usage scaling...")
        
        fixtures = [
            self.fixture_generator.create_simple_python_project(),
            self.fixture_generator.create_medium_python_project(),
            self.fixture_generator.create_complex_project_structure()
        ]
        
        try:
            for fixture in fixtures:
                # Test CodeScanner memory usage
                scanner = CodeScanner(str(fixture.fixture_path))
                
                self.benchmarker.benchmark_with_profiling(
                    f"CodeScanner Memory - {fixture.complexity_level} ({fixture.file_count} files)",
                    lambda: scanner.scan()
                )
        
        finally:
            for fixture in fixtures:
                fixture.cleanup()
    
    def run_all_benchmarks(self):
        """Run complete scanner performance benchmark suite."""
        print("🎺 Starting Scanner Performance Benchmark Suite")
        print("=" * 60)
        
        # Run all benchmark categories
        self.benchmark_scanner_initialization()
        self.benchmark_file_discovery()
        self.benchmark_code_scanner()
        self.benchmark_privacy_scanner()
        self.benchmark_memory_usage_scaling()
        
        # Create and display results
        suite = self.benchmarker.create_suite("Scanner Performance Benchmarks")
        self.benchmarker.print_results(suite)
        
        return suite


def main():
    """Main entry point for scanner performance benchmarks."""
    benchmark = ScannerPerformanceBenchmark()
    
    try:
        suite = benchmark.run_all_benchmarks()
        
        # Performance analysis
        print("\n📊 Performance Analysis:")
        
        # Find slowest operations
        slowest = suite.slowest_result
        if slowest:
            print(f"Slowest operation: {slowest.name} ({slowest.avg_time_per_iteration:.4f}s)")
        
        # Find memory-intensive operations
        memory_results = [r for r in suite.results if r.memory_usage is not None]
        if memory_results:
            memory_intensive = max(memory_results, key=lambda r: r.memory_usage or 0)
            memory_mb = (memory_intensive.memory_usage or 0) / (1024 * 1024)
            print(f"Most memory-intensive: {memory_intensive.name} ({memory_mb:.2f} MB)")
        
        # Performance recommendations
        print("\n💡 Performance Recommendations:")
        
        code_scanner_results = [r for r in suite.results if "CodeScanner" in r.name and "files" in r.name]
        if code_scanner_results:
            avg_time = sum(r.avg_time_per_iteration for r in code_scanner_results) / len(code_scanner_results)
            if avg_time > 2.0:
                print("   ⚠️ CodeScanner performance above 2s target - consider optimization")
            else:
                print("   ✅ CodeScanner performance within acceptable range")
        
        privacy_scanner_results = [r for r in suite.results if "PrivacyScanner" in r.name and "files" in r.name]
        if privacy_scanner_results:
            avg_time = sum(r.avg_time_per_iteration for r in privacy_scanner_results) / len(privacy_scanner_results)
            if avg_time > 3.0:
                print("   ⚠️ PrivacyScanner performance above 3s target - consider optimization")
            else:
                print("   ✅ PrivacyScanner performance within acceptable range")
        
        return 0
        
    except Exception as e:
        print(f"❌ Benchmark failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())