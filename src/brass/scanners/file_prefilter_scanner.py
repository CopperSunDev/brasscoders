"""
FilePrefilterScanner - Brass2-compliant deterministic file filtering.

This scanner implements the first stage of hybrid filtering by excluding files
that should not be analyzed, following the "traditional tools" philosophy of Brass2.
"""

import re
import os
from pathlib import Path
from typing import List, Set, Iterator, Optional
from datetime import datetime

from brass.core.logging_config import get_logger
from brass.core.error_handling import handle_analysis_error

logger = get_logger(__name__)

# Configuration constants with environment variable overrides
MAX_FILE_SIZE_MB = int(os.getenv('BRASS_MAX_FILE_SIZE_MB', '10'))  # Maximum file size to analyze (in MB)
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024
MAX_FILES = int(os.getenv('BRASS_MAX_FILES', '100000'))  # Maximum files to analyze
MAX_DEPTH = int(os.getenv('BRASS_MAX_DEPTH', '50'))  # Maximum directory depth
SKIP_BINARY = os.getenv('BRASS_SKIP_BINARY', 'true').lower() == 'true'  # Skip binary files


class FilePrefilterScanner:
    """
    Deterministic file prefiltering following Brass2 principles.
    
    Implements traditional tools approach - fast, deterministic file exclusions
    to prevent wasteful analysis of irrelevant files.
    """
    
    def __init__(self, project_path: str) -> None:
        """
        Initialize FilePrefilterScanner.
        
        Args:
            project_path: Root path of project to analyze
            
        Raises:
            ValueError: If project_path is empty or None
            FileNotFoundError: If project_path does not exist
        """
        if not project_path:
            raise ValueError("Project path cannot be empty or None")
        
        self.project_path = Path(project_path).resolve()
        if not self.project_path.exists():
            raise FileNotFoundError(f"Project path does not exist: {self.project_path}")
        
        # Deterministic exclusion patterns (evidence-based)
        self.exclude_patterns = {
            # System files
            '.DS_Store', '.Spotlight-V100', '.Trashes', 'Thumbs.db',
            'desktop.ini', 'ehthumbs.db',
            
            # Version control
            '.git/', '.hg/', '.svn/', '.bzr/',
            
            # Build artifacts
            'build/', 'dist/', 'target/', 'bin/', 'obj/',
            '__pycache__/', '.pytest_cache/', '.coverage/',
            'node_modules/', '.npm/', 'bower_components/',
            # JS/TS framework build outputs. Aligns this prefilter with
            # FileClassifier.build_patterns (file_classifier.py:214+),
            # which already classifies these as BUILD_OUTPUT. Discovered
            # 2026-05-20: a whisperx scan surfaced 297 SecretsScanner
            # findings inside .next/server/*.js minified bundles —
            # noise that drowns real source-code signal. The bundled-
            # secret risk (NEXT_PUBLIC_* env inlining) is already
            # caught at the source level by the same scanner.
            '.next/', '.nuxt/', '.svelte-kit/', '.turbo/', '.vercel/',
            '.astro/', '.parcel-cache/',

            # Our own output directory. Scanning .brass/ produces meta-
            # false-positives: SecretsScanner re-matches finding snippets
            # in finding_cache.json, PrivacyScanner re-flags PII patterns
            # quoted in detailed_analysis.yaml, etc. Discovered 2026-05-30
            # during Phase F.6: secrets count climbed scan-over-scan
            # (200 → 289 → 372 → 445) as finding_cache.json grew. The
            # FileClassifier already excludes .brass/ in its build_patterns
            # but the prefilter runs first and has its own pattern list —
            # add it here too to keep the two exclusion lists aligned.
            '.brass/',
            
            # Virtual environments and dependencies
            'venv/', 'env/', '.env/', 'virtualenv/', '.venv/',
            'site-packages/', 'lib/python', 'lib64/python',
            'build_env/', 'test_env/', 'dev_env/',
            '.tox/', 'conda-meta/', 'pkgs/',
            '*.egg-info/', '.eggs/', 'pip-wheel-metadata/',
            
            # IDE files
            '.vscode/', '.idea/', '*.swp', '*.swo', '*~',

            # Claude Code agent worktrees — transient, duplicate the
            # project source. Excluding ``.claude/worktrees/`` (and
            # not ``.claude/`` wholesale) preserves any user config
            # in ``.claude/agents/``, ``.claude/skills/``, etc. that
            # the customer might legitimately want scanned. Discovered
            # 2026-05-20: a whisperx scan surfaced 24 redacted-
            # credential findings inside ``.claude/worktrees/agent-*/``
            # — pure noise from a months-old agent run that
            # duplicated the entire repo.
            '.claude/worktrees/',
            
            # Binary and compiled files
            '*.pyc', '*.pyo', '*.class', '*.o', '*.so', '*.dll',
            '*.dylib', '*.exe', '*.bin',
            
            # Archives (definitely binary, cause hangs)
            '*.zip', '*.tar', '*.tar.gz', '*.tgz', '*.rar',
            '*.7z', '*.gz', '*.bz2', '*.xz',
            
            # Database files (binary, can be huge)
            '*.db', '*.sqlite', '*.sqlite3', '*.dump',
            
            # Minified files (known to cause parser issues)
            '*.min.js', '*.min.css',
            
            # Source maps (generated, very large)
            '*.js.map', '*.css.map', '*.map',
            
            # Log files
            '*.log', 'logs/', 'log/',
            
            # Temporary files
            'tmp/', 'temp/', '*.tmp', '*.temp', '*.bak',
            '.cache/', 'cache/',
            
            # Test outputs
            'htmlcov/', '.coverage', 'coverage.xml',
            '.nyc_output/',
            
            # Documentation build outputs
            'docs/build/', '_build/', '_site/',
            
            # Media files (definitely binary)
            '*.jpg', '*.jpeg', '*.png', '*.gif', '*.bmp',
            '*.ico', '*.mp4', '*.mp3', '*.wav', '*.avi',
            
            # Jupyter checkpoints
            '.ipynb_checkpoints/',
            
            # macOS specific
            '__MACOSX/', '.AppleDouble/'
        }
        
        logger.info(f"FilePrefilterScanner initialized for {self.project_path}")
    
    def scan(self) -> List[str]:
        """
        Scan project and return list of files to analyze with production hardening.
        
        Returns:
            List of file paths that should be analyzed by other scanners
        """
        try:
            filtered_files = []
            total_discovered = 0
            excluded_count = 0
            binary_excluded = 0
            symlink_loops = 0
            
            # Use resource-limited discovery
            for file_path in self._discover_files_safe():
                total_discovered += 1
                
                # Apply file limit to total discovered files
                if total_discovered > MAX_FILES:
                    logger.warning(f"Reached maximum file limit ({MAX_FILES}), stopping discovery")
                    break
                
                # Check exclusions with enhanced detection
                exclude_reason = self._should_exclude_enhanced(file_path)
                if exclude_reason:
                    excluded_count += 1
                    if exclude_reason == 'binary':
                        binary_excluded += 1
                    elif exclude_reason == 'symlink_loop':
                        symlink_loops += 1
                else:
                    filtered_files.append(file_path)
            
            # Report comprehensive statistics
            exclusion_percentage = (excluded_count / total_discovered) * 100 if total_discovered else 0
            logger.info(f"File prefiltering: {total_discovered} → {len(filtered_files)} files "
                       f"({exclusion_percentage:.1f}% excluded)")
            
            if binary_excluded > 0:
                logger.info(f"  - Excluded {binary_excluded} binary files")
            if symlink_loops > 0:
                logger.warning(f"  - Detected {symlink_loops} symlink loops")
                
            return filtered_files
            
        except Exception as e:
            logger.error(f"File prefiltering failed: {e}")
            handle_analysis_error(str(e), "FilePrefilterScanner", "scan")
            # Return empty list rather than crash - graceful degradation
            return []
    
    def _discover_files_safe(self) -> Iterator[str]:
        """
        Discover files with symlink loop protection and depth limits.
        
        Yields:
            File paths that exist and are accessible
        """
        visited_real_paths = set()
        
        # Use os.walk for better control over traversal
        for root, dirs, files in os.walk(self.project_path, followlinks=True):
            try:
                # Check depth limit
                current_path = Path(root)
                depth = len(current_path.relative_to(self.project_path).parts)
                if depth > MAX_DEPTH:
                    logger.debug(f"Skipping deep directory (depth={depth}): {root}")
                    dirs[:] = []  # Don't recurse deeper
                    continue
                
                # Resolve real path to detect symlink loops
                real_root = Path(root).resolve()
                if real_root in visited_real_paths:
                    logger.debug(f"Skipping symlink loop: {root} -> {real_root}")
                    dirs[:] = []  # Don't recurse into loop
                    continue
                    
                visited_real_paths.add(real_root)
                
                # Yield files in this directory
                for filename in files:
                    file_path = os.path.join(root, filename)
                    yield file_path
                    
            except (OSError, PermissionError) as e:
                logger.warning(f"Error accessing directory {root}: {e}")
                dirs[:] = []  # Skip this directory tree
    
    def _should_exclude(self, file_path: str) -> bool:
        """
        Determine if file should be excluded from analysis.
        
        Args:
            file_path: Absolute path to file
            
        Returns:
            True if file should be excluded
        """
        try:
            # Validate file path is within project directory (prevent path traversal).
            # Plain ``startswith`` admits sibling dirs whose name shares a prefix —
            # e.g. project ``/tmp/proj`` would accept ``/tmp/proj-attacker/x``. Use
            # the canonical ``is_within`` helper that all rglob walkers now share.
            from brass.core.path_safety import is_within
            file_abs_path = Path(file_path).resolve()
            if not is_within(file_abs_path, self.project_path):
                logger.debug(f"Path traversal attempt blocked: {file_path}")
                return True
            
            # Convert to relative path for pattern matching
            relative_path = file_abs_path.relative_to(self.project_path)
            path_str = str(relative_path)
            
            # Check against exclusion patterns
            for pattern in self.exclude_patterns:
                if self._matches_pattern(path_str, pattern):
                    return True
            
            # Size-based exclusion (files > 10MB likely not source code)
            # Use file handle to prevent TOCTOU race condition
            try:
                with open(file_path, 'rb') as f:
                    # Seek to end to get file size atomically
                    f.seek(0, 2)  # SEEK_END
                    file_size = f.tell()
                    if file_size > MAX_FILE_SIZE_BYTES:
                        return True
                    # File size is acceptable, reset position for potential future reading
                    f.seek(0)
            except (OSError, PermissionError, IOError):
                # If we can't open/read the file, exclude it for safety
                return True
            
            return False
            
        except Exception as e:
            logger.debug(f"Error checking exclusion for {file_path}: {e}")
            # If we can't determine, exclude for safety
            return True
    
    def _matches_pattern(self, path: str, pattern: str) -> bool:
        """
        Check if path matches exclusion pattern.
        
        Args:
            path: Relative file path
            pattern: Exclusion pattern
            
        Returns:
            True if path matches pattern
        """
        # Directory patterns (end with /) - match directory names in path
        # Example: 'build/' matches 'src/build/output.py'
        # Multi-segment forms like '.claude/worktrees/' match any path
        # whose segments contain that exact subsequence — wrapping
        # both pattern and path with leading/trailing '/' ensures the
        # match is on directory boundaries (so 'claude/wor' won't
        # match 'myclaude/worktree').
        if pattern.endswith('/'):
            directory_name = pattern[:-1]  # Remove trailing slash
            if '/' in directory_name:
                return f'/{directory_name}/' in f'/{path}/'
            return directory_name in path.split('/')
        
        # Wildcard patterns (contain *) - convert to regex for flexible matching
        # Example: '*.pyc' becomes '.*\.pyc' regex pattern
        if '*' in pattern:
            # Escape special regex characters except *, then convert * to .*
            regex_pattern = re.escape(pattern).replace(r'\*', '.*')
            return re.match(regex_pattern, path) is not None
        
        # Exact filename matches (no path separators) - match against filename only
        # Example: 'README' matches 'docs/README' but not 'docs/README.md'
        if '/' not in pattern:
            return pattern == Path(path).name
        
        # Path segment matches - simple substring matching for complex patterns
        # Example: 'test/data' matches 'src/test/data/sample.py'
        return pattern in path
    
    def _should_exclude_enhanced(self, file_path: str) -> Optional[str]:
        """
        Enhanced exclusion check with reason tracking.
        
        Args:
            file_path: Path to check
            
        Returns:
            Exclusion reason string or None if not excluded
        """
        # First check standard exclusions
        if self._should_exclude(file_path):
            return 'pattern'
            
        # Binary file detection
        if SKIP_BINARY and self._is_binary_file(file_path):
            return 'binary'
            
        # Additional symlink validation
        try:
            real_path = Path(file_path).resolve()
            if real_path != Path(file_path):
                # It's a symlink - check if it creates a loop
                if str(real_path).startswith(str(self.project_path)):
                    # Check if symlink points to parent directory
                    if self.project_path in real_path.parents:
                        return 'symlink_loop'
        except (OSError, RuntimeError):
            return 'access_error'
            
        return None
    
    def _is_binary_file(self, file_path: str) -> bool:
        """
        Detect if file is binary by content inspection.
        
        Args:
            file_path: Path to file to check
            
        Returns:
            True if file appears to be binary
        """
        try:
            with open(file_path, 'rb') as f:
                # Read first 8KB for analysis
                chunk = f.read(8192)
                
                # Empty file is not binary
                if not chunk:
                    return False
                
                # Check for null bytes (definitive binary indicator)
                if b'\x00' in chunk:
                    return True
                
                # Check for high ratio of non-text bytes
                text_chars = bytearray({7,8,9,10,12,13,27} | set(range(0x20, 0x100)))
                non_text_count = sum(1 for byte in chunk if byte not in text_chars)
                
                # If more than 30% non-text, likely binary
                if non_text_count / len(chunk) > 0.3:
                    return True
                    
                return False
                
        except (OSError, IOError):
            # If can't read, assume binary for safety
            return True
    
    def get_exclusion_stats(self) -> dict:
        """Get statistics about file exclusions."""
        return {
            'exclude_patterns_count': len(self.exclude_patterns),
            'project_path': str(self.project_path),
            'last_scan': datetime.now().isoformat(),
            'max_files': MAX_FILES,
            'max_depth': MAX_DEPTH,
            'skip_binary': SKIP_BINARY
        }