"""
Performance benchmark runner for New BrassCoders System v2.0.

Provides centralized benchmark execution and timing infrastructure
following clean architecture principles.
"""

import time
import sys
import statistics
from pathlib import Path
from typing import Dict, List, Callable, Any, Optional
from dataclasses import dataclass
from datetime import datetime

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from brass.core.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class BenchmarkResult:
    """Result of a single benchmark run."""
    name: str
    execution_time: float
    memory_usage: Optional[int] = None
    iterations: int = 1
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
    
    @property
    def avg_time_per_iteration(self) -> float:
        """Average time per iteration."""
        return self.execution_time / self.iterations if self.iterations > 0 else 0


@dataclass 
class BenchmarkSuite:
    """Collection of benchmark results."""
    name: str
    results: List[BenchmarkResult]
    timestamp: datetime
    
    @property
    def total_time(self) -> float:
        """Total execution time for all benchmarks."""
        return sum(result.execution_time for result in self.results)
    
    @property
    def fastest_result(self) -> Optional[BenchmarkResult]:
        """Fastest benchmark result."""
        return min(self.results, key=lambda r: r.avg_time_per_iteration) if self.results else None
    
    @property
    def slowest_result(self) -> Optional[BenchmarkResult]:
        """Slowest benchmark result."""
        return max(self.results, key=lambda r: r.avg_time_per_iteration) if self.results else None


class BenchmarkTimer:
    """High-precision timing context manager."""
    
    def __init__(self, name: str = ""):
        self.name = name
        self.start_time = None
        self.end_time = None
    
    def __enter__(self):
        self.start_time = time.perf_counter()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end_time = time.perf_counter()
    
    @property
    def elapsed(self) -> float:
        """Elapsed time in seconds."""
        if self.start_time is None or self.end_time is None:
            return 0.0
        return self.end_time - self.start_time


class PerformanceBenchmarker:
    """
    Main benchmarking class for New BrassCoders System v2.0.
    
    Provides clean, focused performance measurement following
    single responsibility principle.
    """
    
    def __init__(self):
        self.results: List[BenchmarkResult] = []
        self.current_suite_name = "default"
    
    def benchmark(self, 
                 name: str, 
                 func: Callable, 
                 iterations: int = 1,
                 warmup_iterations: int = 0,
                 **kwargs) -> BenchmarkResult:
        """
        Benchmark a function with multiple iterations and warmup.
        
        Args:
            name: Benchmark name
            func: Function to benchmark
            iterations: Number of measurement iterations
            warmup_iterations: Number of warmup iterations (not measured)
            **kwargs: Arguments to pass to function
            
        Returns:
            BenchmarkResult with timing data
        """
        logger.debug(f"Starting benchmark: {name}")
        
        # Warmup iterations
        for _ in range(warmup_iterations):
            try:
                func(**kwargs)
            except Exception as e:
                logger.warning(f"Warmup iteration failed for {name}: {e}")
        
        # Measured iterations
        execution_times = []
        total_start = time.perf_counter()
        
        for i in range(iterations):
            with BenchmarkTimer() as timer:
                try:
                    result = func(**kwargs)
                    execution_times.append(timer.elapsed)
                except Exception as e:
                    logger.error(f"Benchmark iteration {i+1} failed for {name}: {e}")
                    # Continue with other iterations
                    execution_times.append(float('inf'))
        
        total_end = time.perf_counter()
        total_time = total_end - total_start
        
        # Calculate statistics
        valid_times = [t for t in execution_times if t != float('inf')]
        if not valid_times:
            logger.error(f"All iterations failed for benchmark: {name}")
            avg_time = float('inf')
        else:
            avg_time = statistics.mean(valid_times)
        
        # Create result
        benchmark_result = BenchmarkResult(
            name=name,
            execution_time=avg_time,
            iterations=len(valid_times),
            metadata={
                'total_time': total_time,
                'successful_iterations': len(valid_times),
                'failed_iterations': len(execution_times) - len(valid_times),
                'min_time': min(valid_times) if valid_times else float('inf'),
                'max_time': max(valid_times) if valid_times else float('inf'),
                'std_dev': statistics.stdev(valid_times) if len(valid_times) > 1 else 0.0
            }
        )
        
        self.results.append(benchmark_result)
        logger.info(f"Benchmark {name}: {avg_time:.4f}s avg ({len(valid_times)} iterations)")
        
        return benchmark_result
    
    def benchmark_with_profiling(self, name: str, func: Callable, **kwargs) -> BenchmarkResult:
        """
        Benchmark with memory profiling (requires psutil).
        
        Args:
            name: Benchmark name
            func: Function to benchmark
            **kwargs: Arguments to pass to function
            
        Returns:
            BenchmarkResult with timing and memory data
        """
        try:
            import psutil
            import os
            
            process = psutil.Process(os.getpid())
            memory_before = process.memory_info().rss
            
            with BenchmarkTimer() as timer:
                result = func(**kwargs)
            
            memory_after = process.memory_info().rss
            memory_used = memory_after - memory_before
            
            benchmark_result = BenchmarkResult(
                name=name,
                execution_time=timer.elapsed,
                memory_usage=memory_used,
                metadata={
                    'memory_before': memory_before,
                    'memory_after': memory_after,
                    'has_memory_profiling': True
                }
            )
            
        except ImportError:
            logger.warning("psutil not available - running without memory profiling")
            benchmark_result = self.benchmark(name, func, iterations=1, **kwargs)
            benchmark_result.metadata['has_memory_profiling'] = False
        
        return benchmark_result
    
    def create_suite(self, name: str) -> BenchmarkSuite:
        """
        Create a benchmark suite from current results.
        
        Args:
            name: Suite name
            
        Returns:
            BenchmarkSuite with all current results
        """
        suite = BenchmarkSuite(
            name=name,
            results=self.results.copy(),
            timestamp=datetime.now()
        )
        
        # Clear results for next suite
        self.results.clear()
        
        return suite
    
    def print_results(self, suite: BenchmarkSuite = None) -> None:
        """
        Print benchmark results in human-readable format.
        
        Args:
            suite: Optional suite to print (uses current results if None)
        """
        if suite:
            results = suite.results
            print(f"\n🎺 Benchmark Results: {suite.name}")
            print(f"Timestamp: {suite.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        else:
            results = self.results
            print(f"\n🎺 Benchmark Results")
        
        if not results:
            print("No benchmark results available")
            return
        
        print(f"{'='*60}")
        print(f"{'Benchmark Name':<30} {'Time (s)':<12} {'Iterations':<12}")
        print(f"{'-'*60}")
        
        for result in results:
            iterations_str = f"{result.iterations}"
            if result.metadata.get('failed_iterations', 0) > 0:
                iterations_str += f" ({result.metadata['failed_iterations']} failed)"
            
            print(f"{result.name:<30} {result.avg_time_per_iteration:<12.4f} {iterations_str:<12}")
            
            # Show memory usage if available
            if result.memory_usage is not None:
                memory_mb = result.memory_usage / (1024 * 1024)
                print(f"{'  Memory used:':<30} {memory_mb:<12.2f} {'MB':<12}")
        
        print(f"{'='*60}")
        
        if suite:
            print(f"Total execution time: {suite.total_time:.4f}s")
            if suite.fastest_result:
                print(f"Fastest: {suite.fastest_result.name} ({suite.fastest_result.avg_time_per_iteration:.4f}s)")
            if suite.slowest_result:
                print(f"Slowest: {suite.slowest_result.name} ({suite.slowest_result.avg_time_per_iteration:.4f}s)")


def main():
    """Main entry point for benchmark runner."""
    print("🎺 New BrassCoders System v2.0 - Performance Benchmark Runner")
    print("Running basic benchmarking infrastructure tests...")
    
    benchmarker = PerformanceBenchmarker()
    
    # Test the benchmarking infrastructure itself
    def simple_computation():
        """Simple test computation."""
        return sum(range(1000))
    
    def memory_intensive_task():
        """Memory intensive test task."""
        data = [i * 2 for i in range(10000)]
        return len(data)
    
    # Run basic benchmarks
    benchmarker.benchmark("Simple Computation", simple_computation, iterations=5)
    benchmarker.benchmark_with_profiling("Memory Intensive Task", memory_intensive_task)
    
    # Create and display suite
    suite = benchmarker.create_suite("Infrastructure Test")
    benchmarker.print_results(suite)
    
    print("\n✅ Benchmark infrastructure test complete")
    print("Use component-specific benchmark modules for detailed performance testing")


if __name__ == "__main__":
    main()