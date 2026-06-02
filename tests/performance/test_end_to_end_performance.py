"""
End-to-end performance benchmarks for New BrassCoders System v2.0.

Tests complete workflow performance following Brass2 clean architecture.
"""

import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from brass.scanners.professional_code_scanner import ProfessionalCodeScanner as CodeScanner
from brass.scanners.brass2_privacy_scanner import Brass2PrivacyScanner as PrivacyScanner
from brass.ranking.intelligence_ranker import IntelligenceRanker
from brass.output.output_generator import OutputGenerator
from brass.core.logging_config import BrassLogger

from .benchmark_runner import PerformanceBenchmarker
from .benchmark_fixtures import BenchmarkFixtureGenerator

# Setup logging for benchmarks
BrassLogger.setup_logging(verbose=False)


class EndToEndPerformanceBenchmark:
    """
    End-to-end performance benchmarks for complete workflows.
    
    Following Brass2 principles:
    - Single responsibility: measures complete workflow performance
    - Clean interfaces: tests actual public APIs
    - Evidence-based: measures real-world usage patterns
    """
    
    def __init__(self):
        self.benchmarker = PerformanceBenchmarker()
        self.fixture_generator = BenchmarkFixtureGenerator()
    
    def benchmark_complete_scan_workflow(self):
        """Benchmark the complete scan workflow from start to finish."""
        print("🎺 Benchmarking complete scan workflow...")
        
        fixtures = [
            self.fixture_generator.create_simple_python_project(),
            self.fixture_generator.create_medium_python_project(),
            self.fixture_generator.create_complex_project_structure()
        ]
        
        try:
            for fixture in fixtures:
                project_path = str(fixture.fixture_path)
                
                def complete_workflow():
                    """Execute complete analysis workflow."""
                    # Initialize components
                    code_scanner = CodeScanner(project_path)
                    privacy_scanner = PrivacyScanner(project_path)
                    ranker = IntelligenceRanker()
                    output_generator = OutputGenerator(project_path, ".brass", ranker)
                    
                    # Run analysis
                    code_findings = code_scanner.scan()
                    privacy_findings = privacy_scanner.scan()
                    all_findings = code_findings + privacy_findings
                    
                    # Process results
                    ranked_findings = ranker.rank_findings(all_findings)
                    output_files = output_generator.generate_intelligence(ranked_findings)
                    
                    return {
                        'total_findings': len(all_findings),
                        'output_files': len(output_files)
                    }
                
                # Benchmark complete workflow
                self.benchmarker.benchmark_with_profiling(
                    f"Complete Workflow - {fixture.complexity_level} ({fixture.file_count} files)",
                    complete_workflow
                )
        
        finally:
            for fixture in fixtures:
                fixture.cleanup()
    
    def benchmark_incremental_analysis(self):
        """Benchmark incremental analysis performance."""
        print("🔄 Benchmarking incremental analysis...")
        
        # Create medium fixture for incremental testing
        medium_fixture = self.fixture_generator.create_medium_python_project()
        
        try:
            project_path = str(medium_fixture.fixture_path)
            
            # Initialize components once
            code_scanner = CodeScanner(project_path)
            privacy_scanner = PrivacyScanner(project_path)
            ranker = IntelligenceRanker()
            output_generator = OutputGenerator(project_path, ".brass", ranker)
            
            # First run (cold start)
            def initial_scan():
                code_findings = code_scanner.scan()
                privacy_findings = privacy_scanner.scan()
                all_findings = code_findings + privacy_findings
                ranked_findings = ranker.rank_findings(all_findings)
                return ranked_findings
            
            self.benchmarker.benchmark(
                "Initial scan (cold start)",
                initial_scan,
                iterations=1
            )
            
            # Subsequent runs (warm cache)
            def subsequent_scan():
                code_findings = code_scanner.scan()
                privacy_findings = privacy_scanner.scan()
                all_findings = code_findings + privacy_findings
                ranked_findings = ranker.rank_findings(all_findings)
                return ranked_findings
            
            self.benchmarker.benchmark(
                "Subsequent scan (warm cache)",
                subsequent_scan,
                iterations=3
            )
        
        finally:
            medium_fixture.cleanup()
    
    def benchmark_component_isolation(self):
        """Benchmark individual component performance in isolation."""
        print("🔧 Benchmarking component isolation...")
        
        medium_fixture = self.fixture_generator.create_medium_python_project()
        
        try:
            project_path = str(medium_fixture.fixture_path)
            
            # Initialize all components
            code_scanner = CodeScanner(project_path)
            privacy_scanner = PrivacyScanner(project_path)
            ranker = IntelligenceRanker()
            output_generator = OutputGenerator(project_path, ".brass", ranker)
            
            # Get sample findings for ranking and output tests
            sample_findings = code_scanner.scan()[:10]  # First 10 findings
            
            # Benchmark each component in isolation
            self.benchmarker.benchmark(
                "CodeScanner only",
                lambda: code_scanner.scan(),
                iterations=3
            )
            
            self.benchmarker.benchmark(
                "PrivacyScanner only",
                lambda: privacy_scanner.scan(),
                iterations=3
            )
            
            self.benchmarker.benchmark(
                "IntelligenceRanker only",
                lambda: ranker.rank_findings(sample_findings),
                iterations=5
            )
            
            self.benchmarker.benchmark(
                "OutputGenerator only",
                lambda: output_generator.generate_intelligence(sample_findings),
                iterations=3
            )
        
        finally:
            medium_fixture.cleanup()
    
    def benchmark_scaling_characteristics(self):
        """Benchmark how performance scales with project size."""
        print("📈 Benchmarking scaling characteristics...")
        
        fixtures = [
            self.fixture_generator.create_simple_python_project(),
            self.fixture_generator.create_medium_python_project(),
            self.fixture_generator.create_complex_project_structure()
        ]
        
        try:
            scaling_data = []
            
            for fixture in fixtures:
                project_path = str(fixture.fixture_path)
                
                def scan_workflow():
                    code_scanner = CodeScanner(project_path)
                    return code_scanner.scan()
                
                result = self.benchmarker.benchmark_with_profiling(
                    f"Scaling test - {fixture.complexity_level}",
                    scan_workflow
                )
                
                scaling_data.append({
                    'complexity': fixture.complexity_level,
                    'file_count': fixture.file_count,
                    'time': result.execution_time,
                    'memory': result.memory_usage or 0
                })
            
            # Analyze scaling characteristics
            print("\n📊 Scaling Analysis:")
            for data in scaling_data:
                time_per_file = data['time'] / data['file_count'] if data['file_count'] > 0 else 0
                memory_mb = data['memory'] / (1024 * 1024)
                print(f"   {data['complexity']:10} - {data['file_count']:3d} files - "
                      f"{data['time']:.3f}s total - {time_per_file:.4f}s/file - {memory_mb:.1f}MB")
        
        finally:
            for fixture in fixtures:
                fixture.cleanup()
    
    def benchmark_error_handling_overhead(self):
        """Benchmark performance impact of error handling."""
        print("🚨 Benchmarking error handling overhead...")
        
        simple_fixture = self.fixture_generator.create_simple_python_project()
        
        try:
            project_path = str(simple_fixture.fixture_path)
            
            # Benchmark normal operation
            def normal_scan():
                scanner = CodeScanner(project_path)
                return scanner.scan()
            
            self.benchmarker.benchmark(
                "Normal operation",
                normal_scan,
                iterations=5
            )
            
            # Benchmark with error conditions (non-existent path)
            def error_prone_scan():
                try:
                    scanner = CodeScanner("/nonexistent/path")
                    return scanner.scan()
                except Exception:
                    return []
            
            self.benchmarker.benchmark(
                "With error handling",
                error_prone_scan,
                iterations=5
            )
        
        finally:
            simple_fixture.cleanup()
    
    def benchmark_concurrent_analysis(self):
        """Benchmark concurrent analysis scenarios."""
        print("🔀 Benchmarking concurrent analysis...")
        
        medium_fixture = self.fixture_generator.create_medium_python_project()
        
        try:
            project_path = str(medium_fixture.fixture_path)
            
            # Sequential analysis
            def sequential_analysis():
                code_scanner = CodeScanner(project_path)
                privacy_scanner = PrivacyScanner(project_path)
                
                code_findings = code_scanner.scan()
                privacy_findings = privacy_scanner.scan()
                
                return len(code_findings) + len(privacy_findings)
            
            self.benchmarker.benchmark(
                "Sequential scanner execution",
                sequential_analysis,
                iterations=3
            )
            
            # Multiple component initialization
            def multiple_initialization():
                scanners = []
                for i in range(3):
                    scanners.append(CodeScanner(project_path))
                return len(scanners)
            
            self.benchmarker.benchmark(
                "Multiple component initialization",
                multiple_initialization,
                iterations=5
            )
        
        finally:
            medium_fixture.cleanup()
    
    def run_all_benchmarks(self):
        """Run complete end-to-end performance benchmark suite."""
        print("🎺 Starting End-to-End Performance Benchmark Suite")
        print("=" * 70)
        
        # Run all benchmark categories
        self.benchmark_complete_scan_workflow()
        self.benchmark_incremental_analysis()
        self.benchmark_component_isolation()
        self.benchmark_scaling_characteristics()
        self.benchmark_error_handling_overhead()
        self.benchmark_concurrent_analysis()
        
        # Create and display results
        suite = self.benchmarker.create_suite("End-to-End Performance Benchmarks")
        self.benchmarker.print_results(suite)
        
        return suite


def main():
    """Main entry point for end-to-end performance benchmarks."""
    benchmark = EndToEndPerformanceBenchmark()
    
    try:
        suite = benchmark.run_all_benchmarks()
        
        # Performance analysis and recommendations
        print("\n📊 End-to-End Performance Analysis:")
        
        # Find workflow bottlenecks
        workflow_results = [r for r in suite.results if "Complete Workflow" in r.name]
        if workflow_results:
            avg_workflow_time = sum(r.avg_time_per_iteration for r in workflow_results) / len(workflow_results)
            print(f"Average complete workflow time: {avg_workflow_time:.3f}s")
            
            if avg_workflow_time > 10.0:
                print("   ⚠️ Workflow time above 10s target - optimization needed")
            else:
                print("   ✅ Workflow performance within target range")
        
        # Component performance breakdown
        component_results = [r for r in suite.results if " only" in r.name]
        if component_results:
            print("\n🔧 Component Performance Breakdown:")
            for result in sorted(component_results, key=lambda r: r.avg_time_per_iteration, reverse=True):
                print(f"   {result.name:<25} {result.avg_time_per_iteration:.4f}s")
        
        # Scaling efficiency
        scaling_results = [r for r in suite.results if "Scaling test" in r.name]
        if len(scaling_results) >= 2:
            simple_time = next((r.avg_time_per_iteration for r in scaling_results if "simple" in r.name), 0)
            complex_time = next((r.avg_time_per_iteration for r in scaling_results if "complex" in r.name), 0)
            
            if simple_time > 0 and complex_time > 0:
                scaling_factor = complex_time / simple_time
                print(f"\n📈 Scaling Factor (complex/simple): {scaling_factor:.1f}x")
                
                if scaling_factor > 10:
                    print("   ⚠️ Poor scaling characteristics - investigate optimization")
                else:
                    print("   ✅ Reasonable scaling characteristics")
        
        # Performance recommendations
        print("\n💡 Performance Recommendations:")
        print("   • Monitor workflow times to stay under 10s for medium projects")
        print("   • Consider caching for repeated analysis operations")
        print("   • Profile memory usage for large projects")
        print("   • Optimize slowest component identified in breakdown")
        
        return 0
        
    except Exception as e:
        print(f"❌ End-to-end benchmark failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())