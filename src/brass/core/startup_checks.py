"""
Startup checks to prevent common user issues.

Performs pre-flight checks before running BrassAI to ensure:
- Python version compatibility
- Required dependencies are available
- Environment is properly configured
- User will have a good experience
"""

import sys
import platform
import os
import shutil
from pathlib import Path
from typing import List, Tuple, Optional
import importlib.util


class StartupError(Exception):
    """Raised when startup checks fail."""
    pass


class StartupChecker:
    """Performs comprehensive startup checks for BrassAI."""
    
    # Minimum Python version required
    MIN_PYTHON_VERSION = (3, 8)
    
    # Required dependencies
    REQUIRED_PACKAGES = [
        'yaml',      # PyYAML
        'requests',  # For API validation
        'radon',     # For code complexity
        'bandit',    # For security scanning
        'pylint',    # For code analysis
    ]
    
    # Optional but recommended packages
    OPTIONAL_PACKAGES = [
        'vulture',   # For dead code detection
        'py_spy',    # For performance profiling
    ]
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.warnings = []
        self.errors = []
    
    def check_all(self) -> bool:
        """
        Run all startup checks.
        
        Returns:
            True if all critical checks pass, False otherwise
        """
        print("🔍 Running startup checks...")
        
        # Critical checks (must pass)
        critical_checks = [
            self.check_python_version,
            self.check_required_dependencies,
            self.check_write_permissions,
        ]
        
        # Non-critical checks (warnings only)
        warning_checks = [
            self.check_optional_dependencies,
            self.check_disk_space,
            self.check_platform_compatibility,
        ]
        
        # Run critical checks
        for check in critical_checks:
            try:
                if not check():
                    return False
            except Exception as e:
                self.errors.append(f"Check failed: {e}")
                return False
        
        # Run warning checks
        for check in warning_checks:
            try:
                check()
            except Exception as e:
                self.warnings.append(f"Warning check failed: {e}")
        
        # Show summary
        if self.warnings:
            print("\n⚠️  Warnings:")
            for warning in self.warnings:
                print(f"   - {warning}")
        
        if self.errors:
            print("\n❌ Errors:")
            for error in self.errors:
                print(f"   - {error}")
            return False
        
        print("✅ All startup checks passed!")
        return True
    
    def check_python_version(self) -> bool:
        """Check Python version compatibility."""
        current_version = sys.version_info[:2]
        min_version = self.MIN_PYTHON_VERSION
        
        if current_version < min_version:
            self.errors.append(
                f"Python {min_version[0]}.{min_version[1]}+ required, "
                f"but you have {current_version[0]}.{current_version[1]}"
            )
            print(f"❌ Python version check failed")
            print(f"   Required: Python {min_version[0]}.{min_version[1]}+")
            print(f"   Current:  Python {current_version[0]}.{current_version[1]}")
            print(f"   Please upgrade Python to continue.")
            return False
        
        if self.verbose:
            print(f"✅ Python version {current_version[0]}.{current_version[1]} OK")
        return True
    
    def check_required_dependencies(self) -> bool:
        """Check that all required dependencies are installed."""
        missing = []
        
        for package in self.REQUIRED_PACKAGES:
            if not self._is_package_available(package):
                missing.append(package)
        
        if missing:
            self.errors.append(f"Missing required packages: {', '.join(missing)}")
            print(f"❌ Dependency check failed")
            print(f"   Missing packages: {', '.join(missing)}")
            print(f"   Install with: pip install {' '.join(missing)}")
            return False
        
        if self.verbose:
            print(f"✅ All {len(self.REQUIRED_PACKAGES)} required dependencies found")
        return True
    
    def check_optional_dependencies(self) -> bool:
        """Check optional dependencies (warnings only)."""
        missing = []
        
        for package in self.OPTIONAL_PACKAGES:
            if not self._is_package_available(package):
                missing.append(package)
        
        if missing:
            self.warnings.append(
                f"Optional packages not installed: {', '.join(missing)}. "
                f"Some features may be limited."
            )
        
        return True
    
    def check_write_permissions(self) -> bool:
        """Check if we can write to the current directory."""
        try:
            test_file = Path(".brass_test_write")
            test_file.write_text("test")
            test_file.unlink()
            return True
        except (OSError, PermissionError) as e:
            self.errors.append(f"Cannot write to current directory: {e}")
            print("❌ Write permission check failed")
            print("   BrassAI needs write access to create output files.")
            print("   Please run from a directory where you have write permissions.")
            return False
    
    def check_disk_space(self) -> bool:
        """Check available disk space (warning only)."""
        try:
            stat = shutil.disk_usage(".")
            free_mb = stat.free / (1024 * 1024)
            
            if free_mb < 100:  # Less than 100MB free
                self.warnings.append(
                    f"Low disk space: {free_mb:.0f}MB free. "
                    f"BrassAI may fail to write output files."
                )
        except Exception:
            pass  # Non-critical
        
        return True
    
    def check_platform_compatibility(self) -> bool:
        """Check platform-specific issues."""
        system = platform.system()
        
        if system == "Windows":
            self.warnings.append(
                "Windows detected. Some features like symlink detection "
                "may work differently. Please report any issues."
            )
        
        return True
    
    def _is_package_available(self, package_name: str) -> bool:
        """Check if a package is available.

        Most entries are Python libraries we detect via ``importlib.util.find_spec``.
        py-spy is the exception — the PyPI package is a Rust binary that installs a
        ``py-spy`` executable on PATH and ships no importable module, so a
        find_spec('py_spy') check always returned None even after a successful
        install (this misfired as a "py_spy not installed" warning until 2026-05-18).
        Probe via shutil.which to match how BrassPerformanceScanner actually uses
        the tool (subprocess invocation of the binary, not an import).
        """
        if package_name == 'py_spy':
            return shutil.which('py-spy') is not None

        import_map = {
            'yaml': 'yaml',
            'requests': 'requests',
            'radon': 'radon',
            'bandit': 'bandit',
            'pylint': 'pylint',
            'vulture': 'vulture',
        }
        import_name = import_map.get(package_name, package_name)
        return importlib.util.find_spec(import_name) is not None


def run_startup_checks(verbose: bool = False) -> bool:
    """
    Run all startup checks.
    
    Args:
        verbose: Show detailed output
        
    Returns:
        True if all critical checks pass
        
    Raises:
        StartupError: If critical checks fail
    """
    checker = StartupChecker(verbose=verbose)
    
    if not checker.check_all():
        error_msg = "\n".join(checker.errors)
        raise StartupError(f"Startup checks failed:\n{error_msg}")
    
    return True