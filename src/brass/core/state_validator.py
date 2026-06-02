"""
State validation and cleanup for BrassAI output directories.

Ensures clean state before scans by validating and repairing
corrupted files from interrupted operations.
"""

import yaml
from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass
from datetime import datetime

from brass.core.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class StateValidationResult:
    """Result of state validation and cleanup operation."""
    directory_exists: bool
    files_validated: int
    files_cleaned: int
    corrupted_files: List[str]
    validation_time_ms: float
    message: str


class StateValidator:
    """
    Validates and repairs .brass directory state before scans.
    
    Handles:
    - Corrupted YAML files from interrupted writes
    - Locked/unreadable files
    - Missing directories
    - Provides clear user feedback
    """
    
    def __init__(self, output_dir: Path):
        """
        Initialize state validator.
        
        Args:
            output_dir: Path to .brass directory to validate
        """
        self.output_dir = output_dir
        self.expected_files = [
            'ai_instructions.yaml',
            'detailed_analysis.yaml',
            'file_intelligence.yaml',
            'security_report.yaml',
            'privacy_report.yaml',
            'statistics.yaml'
        ]
    
    def validate_and_clean(self) -> StateValidationResult:
        """
        Validate output directory and clean corrupted files.
        
        Returns:
            StateValidationResult with details of what was cleaned
        """
        start_time = datetime.now()
        
        # Check if directory exists
        if not self.output_dir.exists():
            duration_ms = (datetime.now() - start_time).total_seconds() * 1000
            return StateValidationResult(
                directory_exists=False,
                files_validated=0,
                files_cleaned=0,
                corrupted_files=[],
                validation_time_ms=duration_ms,
                message="Output directory does not exist - will be created"
            )
        
        # Validate each YAML file
        corrupted_files = []
        files_validated = 0
        
        for filename in self.expected_files:
            file_path = self.output_dir / filename
            if file_path.exists():
                files_validated += 1
                if not self._validate_yaml_file(file_path):
                    corrupted_files.append(filename)
                    self._clean_corrupted_file(file_path)
        
        # Check for brass.log issues
        log_file = self.output_dir / 'brass.log'
        if log_file.exists():
            if not self._validate_log_file(log_file):
                logger.warning(f"Log file may be corrupted or locked: {log_file}")
        
        duration_ms = (datetime.now() - start_time).total_seconds() * 1000
        
        # Build result message
        if corrupted_files:
            message = f"Cleaned {len(corrupted_files)} corrupted files from previous scan"
        else:
            message = "All files valid - no cleanup needed"
        
        return StateValidationResult(
            directory_exists=True,
            files_validated=files_validated,
            files_cleaned=len(corrupted_files),
            corrupted_files=corrupted_files,
            validation_time_ms=duration_ms,
            message=message
        )
    
    def _validate_yaml_file(self, file_path: Path) -> bool:
        """
        Validate that a YAML file is readable and parseable.
        
        Args:
            file_path: Path to YAML file to validate
            
        Returns:
            True if valid, False if corrupted
        """
        try:
            # Try to parse the YAML file
            with open(file_path, 'r', encoding='utf-8') as f:
                yaml.safe_load(f)
            
            # Also check file size - empty files are corrupted
            if file_path.stat().st_size == 0:
                logger.debug(f"Empty file detected: {file_path}")
                return False
                
            return True
            
        except yaml.YAMLError as e:
            logger.debug(f"YAML parse error in {file_path}: {e}")
            return False
        except Exception as e:
            logger.debug(f"Cannot read file {file_path}: {e}")
            return False
    
    def _validate_log_file(self, log_path: Path) -> bool:
        """
        Validate that log file is accessible.
        
        Args:
            log_path: Path to log file
            
        Returns:
            True if accessible, False if locked/corrupted
        """
        try:
            # Try to open in append mode (won't truncate)
            with open(log_path, 'a', encoding='utf-8') as f:
                # If we can open it, it's not locked
                pass
            return True
        except Exception:
            return False
    
    def _clean_corrupted_file(self, file_path: Path) -> None:
        """
        Remove a corrupted file.
        
        Args:
            file_path: Path to corrupted file to remove
        """
        try:
            file_path.unlink()
            logger.info(f"Removed corrupted file: {file_path.name}")
        except Exception as e:
            logger.error(f"Failed to remove corrupted file {file_path}: {e}")
    
    def clean_all(self) -> None:
        """
        Remove entire output directory (for --clean flag).
        
        Useful when user wants to start completely fresh.
        """
        if self.output_dir.exists():
            import shutil
            try:
                shutil.rmtree(self.output_dir)
                logger.info(f"Removed entire output directory: {self.output_dir}")
            except Exception as e:
                logger.error(f"Failed to remove output directory: {e}")
                raise