"""
FileWatcher - Monitor file changes and trigger intelligent re-analysis.

This component watches for file system changes and triggers incremental
analysis to keep intelligence files up-to-date.
"""

import os
import time
import threading
from pathlib import Path
from typing import List, Set, Optional, Callable, Dict
from datetime import datetime, timedelta

from brass.core.logging_config import get_logger

logger = get_logger(__name__)


class FileWatcher:
    """
    File system monitoring for intelligent re-analysis.
    
    Watches project files for changes and triggers incremental analysis
    to keep AI intelligence files current and relevant.
    
    Features:
    - Efficient polling-based monitoring (cross-platform)
    - Smart filtering of relevant file changes
    - Debounced analysis (avoids excessive re-analysis)
    - Graceful shutdown and error handling
    """
    
    def __init__(self, 
                 project_path: str,
                 on_changes_detected: Optional[Callable[[List[str]], None]] = None,
                 poll_interval: float = 2.0,
                 debounce_delay: float = 5.0):
        """
        Initialize FileWatcher.
        
        Args:
            project_path: Root path of project to monitor
            on_changes_detected: Callback function for when changes are detected
            poll_interval: How often to check for changes (seconds)
            debounce_delay: Wait time after changes before triggering analysis (seconds)
        """
        self.project_path = Path(project_path).resolve()
        self.on_changes_detected = on_changes_detected
        self.poll_interval = poll_interval
        self.debounce_delay = debounce_delay
        
        # Monitoring state
        self.is_monitoring = False
        self.monitor_thread = None
        self.shutdown_event = threading.Event()
        
        # File tracking
        self.file_states: Dict[str, Dict] = {}  # file_path -> {mtime, size}
        self.pending_changes: Set[str] = set()
        self.last_change_time: Optional[datetime] = None
        
        # File patterns to monitor
        self.monitored_extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.cpp', '.c', '.h',
            '.cs', '.php', '.rb', '.go', '.rs', '.swift', '.kt', '.scala',
            '.sql', '.yaml', '.yml', '.json', '.xml', '.md', '.txt'
        }
        
        # Patterns to exclude from monitoring
        self.exclude_patterns = {
            '.git', '.svn', '.hg', '__pycache__', '.pytest_cache',
            'node_modules', '.venv', 'venv', '.env', 'build', 'dist',
            '.brass', '.idea', '.vscode', '.DS_Store', 'coverage',
            '.nyc_output', '.coverage', 'htmlcov'
        }
        
        logger.info(f"File watcher initialized for {self.project_path}")
    
    def start_monitoring(self) -> None:
        """Start file monitoring in background thread."""
        if self.is_monitoring:
            logger.warning("File monitoring already started")
            return
        
        self.is_monitoring = True
        self.shutdown_event.clear()
        
        # Initialize file states
        self._scan_initial_state()
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            name="FileWatcher",
            daemon=True
        )
        self.monitor_thread.start()
        
        logger.info("File monitoring started")
    
    def stop_monitoring(self) -> None:
        """Stop file monitoring gracefully."""
        if not self.is_monitoring:
            return
        
        self.is_monitoring = False
        self.shutdown_event.set()
        
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5.0)
        
        logger.info("File monitoring stopped")
    
    def force_scan(self) -> List[str]:
        """Force immediate scan for changes without waiting for debounce."""
        changed_files = self._detect_changes()
        if changed_files:
            self._trigger_analysis(changed_files)
        return changed_files
    
    def add_change_callback(self, callback: Callable[[List[str]], None]) -> None:
        """Add callback function for change notifications."""
        self.on_changes_detected = callback
    
    def get_monitoring_status(self) -> Dict:
        """Get current monitoring status and statistics."""
        return {
            'is_monitoring': self.is_monitoring,
            'monitored_files': len(self.file_states),
            'pending_changes': len(self.pending_changes),
            'last_change_time': self.last_change_time.isoformat() if self.last_change_time else None,
            'poll_interval': self.poll_interval,
            'debounce_delay': self.debounce_delay
        }
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop running in background thread."""
        logger.debug("File monitoring loop started")
        
        try:
            while self.is_monitoring and not self.shutdown_event.is_set():
                try:
                    # Check for file changes
                    changed_files = self._detect_changes()
                    
                    if changed_files:
                        self.pending_changes.update(changed_files)
                        self.last_change_time = datetime.now()
                        logger.debug(f"Detected changes in {len(changed_files)} files")
                    
                    # Check if we should trigger analysis (debounce logic)
                    if self.pending_changes and self._should_trigger_analysis():
                        self._trigger_analysis(list(self.pending_changes))
                        self.pending_changes.clear()
                    
                    # Wait for next poll or shutdown
                    if self.shutdown_event.wait(self.poll_interval):
                        break  # Shutdown requested
                        
                except Exception as e:
                    logger.error(f"Error in file monitoring loop: {e}")
                    time.sleep(self.poll_interval)  # Continue monitoring despite errors
        
        except Exception as e:
            logger.error(f"Fatal error in file monitoring: {e}")
        
        finally:
            logger.debug("File monitoring loop ended")
    
    def _scan_initial_state(self) -> None:
        """Scan and record initial state of all monitored files."""
        self.file_states.clear()
        
        try:
            for file_path in self._discover_monitored_files():
                self._record_file_state(file_path)
            
            logger.info(f"Initial scan complete: monitoring {len(self.file_states)} files")
        
        except Exception as e:
            logger.error(f"Error during initial file scan: {e}")
    
    def _detect_changes(self) -> List[str]:
        """Detect files that have changed since last check."""
        changed_files = []
        
        try:
            # Check existing files for changes
            for file_path in list(self.file_states.keys()):
                if self._has_file_changed(file_path):
                    changed_files.append(file_path)
                    self._record_file_state(file_path)
            
            # Check for new files
            current_files = set(self._discover_monitored_files())
            tracked_files = set(self.file_states.keys())
            
            new_files = current_files - tracked_files
            for file_path in new_files:
                self._record_file_state(file_path)
                changed_files.append(file_path)
            
            # Check for deleted files
            deleted_files = tracked_files - current_files
            for file_path in deleted_files:
                del self.file_states[file_path]
                changed_files.append(file_path)
        
        except Exception as e:
            logger.error(f"Error detecting file changes: {e}")
        
        return changed_files
    
    def _has_file_changed(self, file_path: str) -> bool:
        """Check if a specific file has changed."""
        try:
            full_path = self.project_path / file_path
            
            if not full_path.exists():
                return True  # File was deleted
            
            stat = full_path.stat()
            current_state = {
                'mtime': stat.st_mtime,
                'size': stat.st_size
            }
            
            previous_state = self.file_states.get(file_path, {})
            
            return (current_state['mtime'] != previous_state.get('mtime', 0) or
                    current_state['size'] != previous_state.get('size', 0))
        
        except Exception as e:
            logger.debug(f"Error checking file {file_path}: {e}")
            return False
    
    def _record_file_state(self, file_path: str) -> None:
        """Record current state of a file."""
        try:
            full_path = self.project_path / file_path
            
            if full_path.exists():
                stat = full_path.stat()
                self.file_states[file_path] = {
                    'mtime': stat.st_mtime,
                    'size': stat.st_size,
                    'last_checked': datetime.now()
                }
        
        except Exception as e:
            logger.debug(f"Error recording state for {file_path}: {e}")
    
    def _discover_monitored_files(self) -> List[str]:
        """Discover all files that should be monitored."""
        monitored_files = []
        
        try:
            for root, dirs, files in os.walk(self.project_path):
                # Skip excluded directories
                dirs[:] = [d for d in dirs if d not in self.exclude_patterns]
                
                root_path = Path(root)
                
                for file_name in files:
                    file_path = root_path / file_name
                    
                    # Check if file extension should be monitored
                    if file_path.suffix.lower() in self.monitored_extensions:
                        # Skip files that are too large (>10MB)
                        try:
                            if file_path.stat().st_size > 10 * 1024 * 1024:
                                continue
                        except OSError:
                            continue
                        
                        # Return relative path
                        relative_path = str(file_path.relative_to(self.project_path))
                        monitored_files.append(relative_path)
        
        except Exception as e:
            logger.error(f"Error discovering monitored files: {e}")
        
        return monitored_files
    
    def _should_trigger_analysis(self) -> bool:
        """Check if enough time has passed since last change to trigger analysis."""
        if not self.last_change_time:
            return False
        
        time_since_change = datetime.now() - self.last_change_time
        return time_since_change >= timedelta(seconds=self.debounce_delay)
    
    def _trigger_analysis(self, changed_files: List[str]) -> None:
        """Trigger analysis for changed files."""
        try:
            if self.on_changes_detected:
                logger.info(f"Triggering analysis for {len(changed_files)} changed files")
                self.on_changes_detected(changed_files)
            else:
                logger.debug(f"No callback registered for {len(changed_files)} changed files")
        
        except Exception as e:
            logger.error(f"Error triggering analysis: {e}")
    
    def __enter__(self):
        """Context manager entry."""
        self.start_monitoring()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop_monitoring()


class IncrementalAnalyzer:
    """
    Helper class for incremental analysis of changed files.
    
    Coordinates with scanners to analyze only changed files and
    update intelligence outputs efficiently.
    """
    
    def __init__(self, code_scanner, privacy_scanner, ranker, output_generator):
        """Initialize with scanner components."""
        self.code_scanner = code_scanner
        self.privacy_scanner = privacy_scanner
        self.ranker = ranker
        self.output_generator = output_generator
        
        logger.info("Incremental analyzer initialized")
    
    def analyze_changes(self, changed_files: List[str]) -> Dict:
        """
        Perform incremental analysis on changed files.
        
        Args:
            changed_files: List of file paths that have changed
            
        Returns:
            Dictionary with analysis results and updated files
        """
        try:
            logger.info(f"Starting incremental analysis of {len(changed_files)} files")
            
            # Filter to only analyze relevant files
            relevant_files = self._filter_relevant_files(changed_files)
            
            if not relevant_files:
                logger.info("No relevant files to analyze")
                return {'status': 'no_changes', 'files_analyzed': 0}
            
            # Run scanners on changed files when their signature supports it.
            # Brass2PrivacyScanner.scan() doesn't yet accept a file_paths argument,
            # so it rescans the project on every change in watch mode. This is
            # tolerable: privacy detection is the cheaper of the two, and a future
            # signature change here is the natural place to opt it into the
            # incremental path.
            code_findings = self.code_scanner.scan(relevant_files)
            try:
                privacy_findings = self.privacy_scanner.scan(relevant_files)
            except TypeError:
                privacy_findings = self.privacy_scanner.scan()
            
            # Combine and rank findings
            all_findings = code_findings + privacy_findings
            ranked_findings = self.ranker.rank_findings(all_findings)
            
            # Generate updated intelligence
            output_files = self.output_generator.generate_intelligence(ranked_findings)
            
            result = {
                'status': 'success',
                'files_analyzed': len(relevant_files),
                'findings_detected': len(all_findings),
                'output_files_updated': len(output_files),
                'analysis_timestamp': datetime.now().isoformat()
            }
            
            logger.info(f"Incremental analysis complete: {result}")
            return result
        
        except Exception as e:
            logger.error(f"Error in incremental analysis: {e}")
            return {
                'status': 'error',
                'error_message': str(e),
                'files_analyzed': 0
            }
    
    def _filter_relevant_files(self, changed_files: List[str]) -> List[str]:
        """Filter changed files to only those relevant for analysis."""
        relevant_extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.cpp', '.c', '.h',
            '.cs', '.php', '.rb', '.go', '.rs', '.swift', '.kt', '.scala',
            '.sql', '.yaml', '.yml', '.json', '.xml', '.md', '.txt'
        }
        
        relevant_files = []
        for file_path in changed_files:
            path = Path(file_path)
            if path.suffix.lower() in relevant_extensions:
                # Check if file actually exists (not deleted)
                full_path = self.code_scanner.project_path / file_path
                if full_path.exists():
                    relevant_files.append(file_path)
        
        return relevant_files