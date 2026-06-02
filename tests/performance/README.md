# Performance Benchmarking Suite

**New BrassCoders System v2.0** - Performance measurement and optimization tools

## Overview

This suite provides comprehensive performance benchmarking for all system components, following the clean architecture principles of Brass2.

## Components

### Core Benchmarks
- **`benchmark_runner.py`** - Main benchmarking infrastructure
- **`performance_profiler.py`** - Detailed performance profiling tools
- **`benchmark_reporter.py`** - Performance report generation

### Component Benchmarks
- **`test_scanner_performance.py`** - Scanner component performance
- **`test_ranking_performance.py`** - Intelligence ranking performance  
- **`test_output_performance.py`** - Output generation performance
- **`test_end_to_end_performance.py`** - Complete workflow benchmarks

### Utilities
- **`benchmark_fixtures.py`** - Test data generation for benchmarks
- **`performance_baselines.py`** - Performance baseline definitions

## Usage

```bash
# Run all performance benchmarks
python -m tests.performance.benchmark_runner

# Run specific component benchmarks
python -m tests.performance.test_scanner_performance

# Generate performance report
python -m tests.performance.benchmark_reporter --output-dir .brass/performance
```

## Performance Standards

### Target Performance Goals
- **Code Scanner**: < 2 seconds per 1000 lines of code
- **Privacy Scanner**: < 3 seconds per 1000 lines of code
- **Intelligence Ranking**: < 500ms for 100 findings
- **Output Generation**: < 1 second for all files
- **End-to-End Workflow**: < 10 seconds for medium project (10K lines)

### Monitoring Thresholds
- **Performance Regression**: > 20% slower than baseline
- **Memory Usage**: < 100MB for typical project scan
- **File I/O**: Efficient file reading with proper caching

## Architecture

Following Brass2 principles:
- **Single Responsibility**: Each benchmark tests one component
- **Clean Interfaces**: All benchmarks use consistent APIs
- **No Dependencies**: Benchmarks don't depend on each other
- **Evidence-Based**: Actual performance measurement, not assumptions