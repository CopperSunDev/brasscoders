"""
BrassCLI - Command-line interface for the new Copper Sun Brass system.

This component provides a user-friendly CLI for running scans, monitoring
files, and generating intelligence reports.
"""

import concurrent.futures
import json
import sys
import os
import argparse
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Optional, List, Tuple, Dict, Set
from datetime import datetime

from brass.scanners.professional_code_scanner import ProfessionalCodeScanner
from brass.scanners.brass2_privacy_scanner import Brass2PrivacyScanner
from brass.scanners.content_moderation_scanner import ContentModerationScanner
from brass.scanners.javascript_typescript_scanner import JavaScriptTypeScriptScanner
from brass.scanners.phantom_ai_code_scanner import PhantomAICodeScanner
from brass.scanners.brass_performance_scanner import BrassPerformanceScanner
from brass.scanners.api_security_scanner import APISecurityScanner
from brass.scanners.ai_context_coherence_scanner import AIContextCoherenceScanner
from brass.scanners.secrets_scanner import SecretsScanner
from brass.scanners.semgrep_taint_scanner import SemgrepTaintScanner
from brass.scanners.ast_grep_scanner import AstGrepScanner
from brass.scanners.pysa_taint_scanner import PysaTaintScanner
from brass.ranking.intelligence_ranker import IntelligenceRanker
from brass.scanners.file_prefilter_scanner import FilePrefilterScanner
from brass.core.file_index import FileIndex
from brass.core import finding_cache as _finding_cache
from brass.core import change_detection as _change_detection
from brass.scanners.noise_reduction_scanner import NoiseReductionScanner
from brass.output.yaml_output_generator_v2 import YAMLOutputGeneratorV2
from brass.monitoring.file_watcher import FileWatcher, IncrementalAnalyzer
from brass.models.finding import Finding
from brass.core.logging_config import BrassLogger, get_logger
from brass.core.error_reporter import get_error_reporter, save_session_error_report
from brass.core.startup_checks import run_startup_checks, StartupError
from brass.core.user_error_handler import setup_global_error_handler, UserFriendlyError, handle_common_errors
from brass.core.state_validator import StateValidator
from brass.core.scanner_status import ScannerStatus

logger = get_logger(__name__)


class BrassCLI:
    """
    Command-line interface for the new Copper Sun Brass system.
    
    Provides commands for:
    - One-time analysis (scan)
    - Continuous monitoring (watch)
    - Report generation
    - System status and configuration
    """
    
    def __init__(self):
        """Initialize CLI with argument parser."""
        self.parser = self._create_parser()
        self.current_directory = Path.cwd()
        
        # Components (initialized on demand)
        self.code_scanner = None
        self.brass2_privacy_scanner = None
        self.content_moderation_scanner = None
        self.javascript_typescript_scanner = None
        self.phantom_ai_code_scanner = None
        self.brass_performance_scanner = None
        self.api_security_scanner = None
        self.ai_context_coherence_scanner = None
        self.secrets_scanner = None
        self.semgrep_taint_scanner = None
        self.ast_grep_scanner = None
        self.pysa_taint_scanner = None
        self.ranker = None
        self.output_generator = None
        self.file_watcher = None

        # Per-scanner status from the most recent scan (loose end #8).
        # Populated in `_run_scanner_task`, dumped to scanner_timings.json
        # and threaded into the YAML output pipeline.
        self._scanner_status: Dict[str, "ScannerStatus"] = {}

        # Environment features (validated before scan)
        self.features = {
            'git_available': False,
            'symlinks_present': False,
            'large_project': False,
            'binary_files_detected': False
        }
    
    def _ensure_component_initialized(self, component_name: str):
        """
        Ensure component is properly initialized before use.
        
        Args:
            component_name: Name of the component attribute
            
        Returns:
            The initialized component
            
        Raises:
            RuntimeError: If component is not initialized
        """
        component = getattr(self, component_name, None)
        if component is None:
            raise RuntimeError(f"Component {component_name} is not initialized. Initialize components before scanning.")
        return component
    
    def run(self, args: Optional[List[str]] = None) -> int:
        """
        Run CLI with provided arguments.
        
        Args:
            args: Command line arguments (uses sys.argv if None)
            
        Returns:
            Exit code (0 = success, non-zero = error)
        """
        try:
            parsed_args = self.parser.parse_args(args)
            
            # Configure logging for scan command - others handle their own logging
            if getattr(parsed_args, 'command', None) != 'scan':
                # Basic logging for non-scan commands
                output_dir = getattr(parsed_args, 'output_dir', '.brass')
                log_file = getattr(parsed_args, 'log_file', None)
                no_log_file = getattr(parsed_args, 'no_log_file', False)
                self._configure_logging(parsed_args.verbose, log_file, no_log_file, output_dir)
            
            # Execute command
            if hasattr(parsed_args, 'func'):
                return parsed_args.func(parsed_args)
            else:
                self.parser.print_help()
                return 1
        
        except KeyboardInterrupt:
            print("\n❌ Operation cancelled by user")
            return 130
        except Exception as e:
            print(f"❌ Error: {e}")
            logger.exception("CLI error")
            return 1
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create command-line argument parser."""
        parser = argparse.ArgumentParser(
            prog='brasscoders',
            description='🎺 BrassCoders for AI Coders v2.0 - Revolutionary AI Development Intelligence',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
💡 Quick Start:
  brasscoders scan                     # 🎯 Complete analysis (recommended)
  brasscoders scan --fast              # ⚡ Quick code review (skip privacy/content)
  brasscoders scan --dev               # 👨‍💻 Developer focus (source code only)

🔍 Selective Analysis:
  brasscoders scan --code              # 🐛 Find bugs, security issues, code quality
  brasscoders scan --privacy           # 🔒 Detect PII, sensitive data exposure  
  brasscoders scan --content           # 🚫 Check for inappropriate content

📁 Project Analysis:
  brasscoders scan /path/to/project    # Analyze specific project
  brasscoders scan --output-dir=.reports  # Custom output location

⚡ Workflow Commands:
  brasscoders watch                    # 👁️ Monitor files for changes
  brasscoders status                   # 📊 View last analysis results
  brasscoders version                  # ℹ️ Show version and components
            """
        )
        
        # Global options
        parser.add_argument(
            '-v', '--verbose',
            action='store_true',
            help='Enable verbose logging'
        )
        
        parser.add_argument(
            '--log-file',
            type=str,
            help='📝 Log file path (default: .brass/brass.log)'
        )
        
        parser.add_argument(
            '--no-log-file',
            action='store_true',
            help='🚫 Disable automatic log file creation'
        )
        
        parser.add_argument(
            '--project-path',
            type=str,
            default='.',
            help='Project path to analyze (default: current directory)'
        )

        parser.add_argument(
            '--offline',
            action='store_true',
            help='🚫 Refuse all outbound network calls. Forces --check-package-hallucination off.'
        )
        
        # Subcommands
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # Scan command with user-friendly help
        scan_parser = subparsers.add_parser(
            'scan', 
            help='🔍 Analyze your code for issues and generate AI intelligence',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description='🎺 BrassCoders for AI Coders - Find bugs, security issues, and quality problems',
            epilog="""
💡 Common Usage Patterns:
  brasscoders scan                     # 🎯 Complete analysis (recommended)
  brasscoders scan --fast             # ⚡ Quick code review (skip privacy/content)
  brasscoders scan --dev              # 👨‍💻 Developer focus (source code only)
  
🔍 Targeted Analysis:
  brasscoders scan --code             # 🐛 Code quality, bugs, security only
  brasscoders scan --privacy          # 🔒 PII detection and data protection
  brasscoders scan --content          # 🚫 Content moderation and policy checks
  
📁 Project Analysis:
  brasscoders scan /path/to/project    # Analyze specific project
  brasscoders scan --output-dir=reports  # Custom output location

✨ What You'll Get:
  • ai_instructions.yaml - Start here! Main guidance optimized for AI assistants
  • detailed_analysis.yaml - Complete technical breakdown of all issues found
  • security_report.yaml - Security vulnerabilities that need immediate attention
  • privacy_analysis.yaml - Personal data (PII) exposure and compliance issues
  • file_intelligence.yaml - File-by-file breakdown showing problems in each file
  • statistics.yaml - Summary metrics and trends across your entire project
            """
        )
        
        # Positional argument
        scan_parser.add_argument(
            'path',
            nargs='?',
            default='.',
            help='📁 Project path to analyze (default: current directory)'
        )
        
        # User-friendly aliases for common workflows
        scan_parser.add_argument(
            '--fast',
            action='store_true',
            help='⚡ Quick scan: code analysis only (skips privacy/content for speed)'
        )
        scan_parser.add_argument(
            '--dev',
            action='store_true', 
            help='👨‍💻 Developer mode: focus on source code (excludes tests/build files)'
        )
        
        # Selective analysis options
        scan_parser.add_argument(
            '--code',
            action='store_true',
            help='🐛 Code analysis only: bugs, security, code quality'
        )
        scan_parser.add_argument(
            '--privacy',
            action='store_true',
            help='🔒 Privacy analysis only: PII detection, data protection'
        )
        scan_parser.add_argument(
            '--content',
            action='store_true',
            help='🚫 Content moderation only: policy violations, inappropriate content'
        )
        
        # Network policy options (default: no outbound calls).
        scan_parser.add_argument(
            '--check-package-hallucination',
            action='store_true',
            help=(
                '🌐 Validate imports against PyPI/npm/pkg.go.dev (sends each unknown '
                'package name over the network). Off by default for privacy; '
                '--offline overrides this back to off.'
            )
        )

        # Phase 2 Performance Enhancement Options
        scan_parser.add_argument(
            '--performance-validation',
            action='store_true',
            help='🔍 Add runtime validation to performance findings (requires py-spy)'
        )
        scan_parser.add_argument(
            '--performance-benchmarking',
            action='store_true',
            help='⏱️ Add quantified performance impact estimates (requires pyperf)'
        )
        scan_parser.add_argument(
            '--performance-full',
            action='store_true',
            help='🏆 Complete performance analysis with validation and benchmarking'
        )
        
        # Legacy options (hidden from help but still functional)
        scan_parser.add_argument(
            '--code-only',
            action='store_true',
            help=argparse.SUPPRESS  # Hidden legacy option
        )
        scan_parser.add_argument(
            '--source-only',
            action='store_true', 
            help=argparse.SUPPRESS  # Hidden legacy option
        )
        scan_parser.add_argument(
            '--privacy-only',
            action='store_true',
            help=argparse.SUPPRESS  # Hidden legacy option
        )
        scan_parser.add_argument(
            '--content-only',
            action='store_true',
            help=argparse.SUPPRESS  # Hidden legacy option
        )
        scan_parser.add_argument(
            '--no-privacy',
            action='store_true',
            help=argparse.SUPPRESS  # Hidden legacy option
        )
        scan_parser.add_argument(
            '--no-content',
            action='store_true',
            help=argparse.SUPPRESS  # Hidden legacy option
        )
        
        # Output configuration
        scan_parser.add_argument(
            '--output-dir',
            type=str,
            default='.brass',
            help='📤 Output directory for intelligence files (default: .brass)'
        )
        # Scanner-level parallelism (Perf #1). Default on; flag to disable.
        scan_parser.add_argument(
            '--no-parallel',
            action='store_true',
            help='Disable parallel scanner execution. Useful for debugging '
                 'or for reproducing previous-baseline timings.',
        )
        scan_parser.add_argument(
            '--max-workers',
            type=int,
            default=None,
            help='Max parallel scanner workers (default: min(cpu_count-1, 6)). '
                 'Lower this on resource-constrained machines.',
        )
        # Perf #4: incremental scanning. When set, Semgrep (and other
        # incremental-aware scanners) restrict their scan to files changed
        # since the given git commit. Big speedup for CI / per-PR flows.
        scan_parser.add_argument(
            '--since-commit',
            type=str,
            default=None,
            metavar='COMMIT',
            help='Incremental scan: only analyze files changed since this '
                 'git commit (against HEAD). Falls back to full scan if not '
                 'in a git repo or the diff fails.',
        )
        # Auto-incremental: use the prior scan's cached HEAD sha (or
        # mtime) as the reference point. Same semantics as --since-commit
        # but the developer doesn't have to know what commit they
        # diverged from. Falls back to full scan if no prior cache.
        scan_parser.add_argument(
            '--incremental',
            action='store_true',
            help='Incremental scan against the prior cached scan state. '
                 'On first scan or when cache is missing/stale, falls '
                 'back to a full scan. File-local scanners (BrassPerf, '
                 'bandit/pylint, secrets, privacy, content moderation, '
                 'JS/TS) re-scan only changed files and merge with '
                 'cached findings for unchanged files. Cross-file '
                 'scanners (Pysa, ast-grep, AIContextCoherence) still '
                 'full-scan for correctness.',
        )
        # Pysa interprocedural taint analysis. Soft-fails if pyre absent.
        scan_parser.add_argument(
            '--no-pysa',
            action='store_true',
            help='Skip the Pysa interprocedural taint scanner',
        )
        # ast-grep pattern analysis. Soft-fails if ast-grep is absent.
        scan_parser.add_argument(
            '--no-ast-grep',
            action='store_true',
            help='Skip the ast-grep pattern-match scanner',
        )
        # Semgrep-OSS taint analysis. Soft-fails if semgrep is absent.
        scan_parser.add_argument(
            '--no-semgrep',
            action='store_true',
            help='Skip the Semgrep-OSS taint scanner',
        )
        # AI enrichment (paid feature, gated by active license)
        scan_parser.add_argument(
            '--no-enrich',
            action='store_true',
            help='Skip the AI enrichment layer even with an active license '
                 '(forces heuristic-only noise filter; use for CI runs or '
                 'when the gateway is unavailable)',
        )
        scan_parser.set_defaults(func=self._cmd_scan)
        
        # Watch command with enhanced help
        watch_parser = subparsers.add_parser(
            'watch', 
            help='👁️ Monitor files for changes and auto-analyze',
            description='🎺 Continuous Monitoring - Watch your code and analyze changes in real-time'
        )
        watch_parser.add_argument(
            '--poll-interval',
            type=float,
            default=2.0,
            help='⏱️ How often to check for file changes (seconds, default: 2.0)'
        )
        watch_parser.add_argument(
            '--debounce-delay',
            type=float,
            default=5.0,
            help='🕐 Wait time before analyzing after changes stop (seconds, default: 5.0)'
        )
        watch_parser.set_defaults(func=self._cmd_watch)
        
        # Status command with enhanced help
        status_parser = subparsers.add_parser(
            'status', 
            help='📊 View last analysis results and statistics',
            description='📊 Analysis Status - Review findings from your latest scan'
        )
        status_parser.set_defaults(func=self._cmd_status)
        
        # Report command with enhanced help
        report_parser = subparsers.add_parser(
            'report', 
            help='📄 Generate custom reports in different formats',
            description='📄 Custom Reports - Generate targeted reports for specific needs'
        )
        report_parser.add_argument(
            '--type',
            choices=['security', 'privacy', 'quality', 'all'],
            default='all',
            help='🎯 Focus area: security, privacy, quality, or all (default: all)'
        )
        report_parser.add_argument(
            '--format',
            choices=['markdown', 'json', 'both'],
            default='markdown',
            help='📋 Output format: markdown, json, or both (default: markdown)'
        )
        report_parser.set_defaults(func=self._cmd_report)
        
        # Filter command — apply BrassCoders noise reduction to a third-party AI
        # reviewer's JSON output (Claude Code, Cursor, etc.).
        filter_parser = subparsers.add_parser(
            'filter',
            help='🪄 Filter an AI reviewer JSON payload through BrassCoders noise reduction',
            description=(
                'Apply BrassCoders noise reduction to a list of AI-generated review '
                'findings. Reads JSON from --input or stdin, writes filtered '
                'JSON to --output or stdout. The input schema is documented in '
                'src/brass/filtering/ai_review_filter.py.'
            )
        )
        filter_parser.add_argument('--input', '-i', type=str, default='-',
                                   help='Path to input JSON (default: stdin).')
        filter_parser.add_argument('--output', '-o', type=str, default='-',
                                   help='Path to filtered JSON output (default: stdout).')
        filter_parser.set_defaults(func=self._cmd_filter)

        # Licensing commands. License management uses LemonSqueezy's License
        # API (https://docs.lemonsqueezy.com/api/license-api). Three of the
        # CLI's subcommands talk to LS:
        #   - brasscoders activate    POST /v1/licenses/activate
        #   - brasscoders license     POST /v1/licenses/validate (cached weekly)
        #   - brasscoders deactivate  POST /v1/licenses/deactivate
        # These are the ONLY commands that touch the network for license
        # management. brasscoders scan / watch / filter / status / version stay
        # offline-first and continue to honor --offline.
        activate_parser = subparsers.add_parser(
            'activate',
            help='🔑 Activate a BrassCoders license key',
            description=(
                'Activate a BrassCoders license key (emailed at purchase or trial '
                'signup) on this machine. Calls LemonSqueezy to register '
                'the activation; persists the license_key + instance_id at '
                '~/.brass/license (0600 perms). One activation per machine; '
                'use brasscoders deactivate to release the slot.'
            )
        )
        activate_parser.add_argument(
            'token',
            metavar='LICENSE_KEY',
            help='The license key (UUID-like string from your LS purchase email)',
        )
        activate_parser.set_defaults(func=self._cmd_activate)

        license_parser = subparsers.add_parser(
            'license',
            help='🔍 Show current license status',
            description=(
                'Display the active license. Re-validates against LemonSqueezy '
                'at most once per week to catch server-side revocations '
                '(cancellations, refunds). Falls back to cached status if LS '
                'is unreachable.'
            )
        )
        license_parser.set_defaults(func=self._cmd_license)

        deactivate_parser = subparsers.add_parser(
            'deactivate',
            help='🗑  Release the activation and remove the local record',
            description=(
                'Release this machine\'s activation slot with LemonSqueezy '
                'and delete ~/.brass/license. BrassCoders continues to work in '
                'OSS-tier mode after this command.'
            )
        )
        deactivate_parser.set_defaults(func=self._cmd_deactivate)

        portal_parser = subparsers.add_parser(
            'portal',
            help='🌐 Open the LemonSqueezy customer portal for this license',
            description=(
                'Open the LemonSqueezy customer portal in your browser to '
                'manage your subscription, update card, view invoices, '
                'cancel, etc. Requires an active license activated on this '
                'machine. The portal URL is fetched fresh each time (LS '
                'session URLs are signed + short-lived).'
            )
        )
        portal_parser.set_defaults(func=self._cmd_portal)

        # Telemetry consent management. Off by default. We track only
        # anonymized usage counts (scan event + finding-type counts +
        # version + platform). Source code, paths, PII never leave the
        # machine.
        telemetry_parser = subparsers.add_parser(
            'telemetry',
            help='📊 Manage opt-in anonymized telemetry',
            description=(
                'Telemetry is OFF by default. When on, BrassCoders sends '
                'anonymized usage counts (scan events, finding-type '
                'distribution, CLI version, OS) to the configured backend. '
                'Source code, paths, emails, and stack traces never leave '
                'your machine. Inspect what would be sent at '
                '~/.brass/telemetry-debug.log.'
            )
        )
        telemetry_parser.add_argument(
            'action',
            choices=['on', 'off', 'status'],
            help="'on' opts in, 'off' opts out, 'status' shows current state"
        )
        telemetry_parser.set_defaults(func=self._cmd_telemetry)

        # Cache management. Surfaces a CLI escape hatch for the on-disk
        # caches BrassCoders writes under ~/.cache/brass/ — primarily the Pysa
        # state cache (10-300 MB per scanned project), optionally the
        # auto-fetched typeshed bundle. See docs/CACHE.md.
        cache_parser = subparsers.add_parser(
            'cache',
            help='🧹 Manage BrassCoders on-disk caches',
            description=(
                'Manage the Pysa state cache (~/.cache/brass/pysa-state/) '
                'and the optional typeshed cache (~/.cache/brass/typeshed/). '
                'See docs/CACHE.md for the full lifecycle.'
            ),
        )
        cache_parser.add_argument(
            'action',
            choices=['clear'],
            help="'clear' removes cached state and frees the disk space",
        )
        cache_parser.add_argument(
            '--include-typeshed',
            action='store_true',
            help='Also remove the auto-fetched typeshed cache '
                 '(~/.cache/brass/typeshed/). BRASS_TYPESHED-redirected '
                 'paths are user-owned and left untouched.',
        )
        cache_parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Report what would be removed without removing it',
        )
        cache_parser.set_defaults(func=self._cmd_cache)

        # Version command with enhanced help
        version_parser = subparsers.add_parser(
            'version',
            help='ℹ️ Show version and component information',
            description='ℹ️ System Information - Version details and component status'
        )
        version_parser.set_defaults(func=self._cmd_version)
        
        return parser
    
    def _configure_logging(self, verbose: bool, log_file: Optional[str] = None, 
                          no_log_file: bool = False, output_dir: str = '.brass') -> None:
        """Configure logging with automatic log file creation."""
        from pathlib import Path
        
        # Determine log file path
        actual_log_file = None
        if not no_log_file:
            if log_file:
                actual_log_file = Path(log_file)
            else:
                # Default: create brass.log in output directory
                actual_log_file = Path(output_dir) / 'brass.log'
        
        BrassLogger.setup_logging(verbose=verbose, log_file=actual_log_file)
        
        # Get logger after setup to ensure proper configuration
        session_logger = get_logger('brass.cli')
        if actual_log_file:
            session_logger.info(f"BrassCoders logging started - session {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            session_logger.debug(f"Logging configured: verbose={verbose}, log_file={actual_log_file}")
        else:
            session_logger.debug(f"Logging configured: verbose={verbose}, no log file")
    
    def _validate_environment(self, project_path: Path) -> None:
        """
        Validate project environment before scanning with production hardening.
        
        Args:
            project_path: Path to project directory
        """
        logger.info("Validating project environment...")
        
        # Check git repository health. _check_git_health returns a tri-state
        # via (available, reason) so we can warn only on the real "corrupted"
        # case — a non-git directory is a normal scan target and shouldn't
        # produce a misleading "features disabled" warning. (As of 2026-05-18
        # no downstream code actually consumes git_available; the flag is
        # reserved for future file-author / temporal-weighting features.)
        self.features['git_available'], git_status = self._check_git_health(project_path)

        # Check for symlinks
        self.features['symlinks_present'] = self._check_symlinks(project_path)

        # Check project size
        self.features['large_project'] = self._check_project_size(project_path)

        # Report environment status
        if git_status == 'corrupted':
            logger.warning("⚠️  Git repository present but unhealthy (timeout or git error) — file-history features will be unavailable when wired up")
        elif git_status == 'absent':
            logger.debug("No .git directory at scan root; file-history features inert (this is normal for subdirectory or tarball scans)")
        if self.features['symlinks_present']:
            logger.info("ℹ️  Symbolic links detected - loop protection enabled")
        if self.features['large_project']:
            logger.warning("⚠️  Large project detected - resource limits will be applied")
    
    def _check_git_health(self, project_path: Path) -> Tuple[bool, str]:
        """
        Check if git repository is healthy and accessible.

        We sandbox the git subprocess against CVE-2022-24765 (malicious .git/config in
        a fuzzy-owned repo) and related issues by clearing inherited git config and
        suppressing prompts. The check itself is informational — if git refuses, we
        gracefully degrade.

        Returns:
            (available, reason) where:
              available = True when git is usable here
              reason in {'ok', 'absent', 'corrupted', 'git_missing'}
            Callers use `reason` to differentiate "not a git repo" (normal, debug)
            from "broken git state" (worth warning about).
        """
        try:
            git_dir = project_path / '.git'
            if not git_dir.exists():
                return False, 'absent'

            sandboxed_env = os.environ.copy()
            sandboxed_env['GIT_CONFIG_GLOBAL'] = '/dev/null'
            sandboxed_env['GIT_CONFIG_SYSTEM'] = '/dev/null'
            sandboxed_env['GIT_CONFIG_NOSYSTEM'] = '1'
            sandboxed_env['GIT_TERMINAL_PROMPT'] = '0'
            sandboxed_env['GIT_ASKPASS'] = '/bin/true'
            sandboxed_env.pop('GIT_DIR', None)
            sandboxed_env.pop('GIT_WORK_TREE', None)

            result = subprocess.run(
                ['git', 'status', '--porcelain'],
                cwd=project_path,
                capture_output=True,
                timeout=5,
                text=True,
                env=sandboxed_env,
            )

            if result.returncode == 0:
                logger.debug("Git repository validated successfully")
                return True, 'ok'
            logger.debug(f"Git repository validation failed: {result.stderr}")
            return False, 'corrupted'

        except subprocess.TimeoutExpired:
            logger.debug("Git operation timed out — repository may be corrupted")
            return False, 'corrupted'
        except (subprocess.SubprocessError, FileNotFoundError):
            logger.debug("Git command not available")
            return False, 'git_missing'
        except Exception as e:
            logger.debug(f"Git validation error: {e}")
            return False, 'corrupted'
    
    def _check_symlinks(self, project_path: Path) -> bool:
        """Check if project contains symbolic links."""
        try:
            # Quick check for any symlinks in top-level directories
            for item in project_path.iterdir():
                if item.is_symlink():
                    return True
                    
            # Check first few subdirectories
            for root, dirs, files in os.walk(project_path):
                depth = len(Path(root).relative_to(project_path).parts)
                if depth > 2:  # Only check first 2 levels for performance
                    break
                    
                for name in dirs + files:
                    path = Path(root) / name
                    if path.is_symlink():
                        return True
                        
            return False
        except Exception as e:
            logger.debug(f"Symlink check error: {e}")
            return False
    
    def _check_project_size(self, project_path: Path) -> bool:
        """Check if project is large (>10K files or >1GB)."""
        try:
            file_count = 0
            total_size = 0
            
            for root, dirs, files in os.walk(project_path):
                file_count += len(files)
                
                # Early exit if already large
                if file_count > 10000:
                    return True
                    
                # Sample size calculation (check every 100th file)
                if file_count % 100 == 0:
                    for f in files[:1]:  # Sample one file
                        try:
                            total_size += (Path(root) / f).stat().st_size
                        except:
                            pass
                            
            # Extrapolate total size
            estimated_size = total_size * 100 if file_count > 0 else 0
            
            return file_count > 10000 or estimated_size > 1_000_000_000
            
        except Exception as e:
            logger.debug(f"Project size check error: {e}")
            return False
    
    def _initialize_components(self, project_path: str, output_dir: str = '.brass',
                               *, check_package_hallucination: bool = False) -> None:
        """Initialize all system components.

        Args:
            project_path: Project root.
            output_dir: Output directory.
            check_package_hallucination: Pass-through for the API security scanner;
                must be opted into explicitly because it triggers outbound HTTPS
                calls that leak imported package names.
        """
        if not self.code_scanner:
            self.code_scanner = ProfessionalCodeScanner(project_path)

        if not self.brass2_privacy_scanner:
            self.brass2_privacy_scanner = Brass2PrivacyScanner(project_path)

        if not self.content_moderation_scanner:
            self.content_moderation_scanner = ContentModerationScanner(project_path)

        if not self.javascript_typescript_scanner:
            try:
                self.javascript_typescript_scanner = JavaScriptTypeScriptScanner(project_path)
            except Exception as e:
                logger.warning(f"JavaScript/TypeScript scanner unavailable: {e}")
                self.javascript_typescript_scanner = None

        if not self.phantom_ai_code_scanner:
            self.phantom_ai_code_scanner = PhantomAICodeScanner(project_path)

        if not self.brass_performance_scanner:
            self.brass_performance_scanner = BrassPerformanceScanner(project_path)

        if not self.api_security_scanner:
            self.api_security_scanner = APISecurityScanner(
                project_path,
                check_package_hallucination=check_package_hallucination,
            )

        if not self.ai_context_coherence_scanner:
            self.ai_context_coherence_scanner = AIContextCoherenceScanner(project_path)

        if not self.secrets_scanner:
            try:
                self.secrets_scanner = SecretsScanner(project_path)
            except Exception as e:
                logger.warning(f"Secrets scanner unavailable: {e}")
                self.secrets_scanner = None

        if not self.semgrep_taint_scanner:
            try:
                self.semgrep_taint_scanner = SemgrepTaintScanner(project_path)
            except Exception as e:
                logger.warning(f"Semgrep taint scanner unavailable: {e}")
                self.semgrep_taint_scanner = None

        if not self.ast_grep_scanner:
            try:
                self.ast_grep_scanner = AstGrepScanner(project_path)
            except Exception as e:
                logger.warning(f"ast-grep scanner unavailable: {e}")
                self.ast_grep_scanner = None

        if not self.pysa_taint_scanner:
            try:
                self.pysa_taint_scanner = PysaTaintScanner(project_path)
            except Exception as e:
                logger.warning(f"Pysa taint scanner unavailable: {e}")
                self.pysa_taint_scanner = None
        
        if not self.ranker:
            # Pass project_path so the ranker can apply framework-aware
            # severity adjustments (Capability 1 of the algorithmic plan).
            self.ranker = IntelligenceRanker(project_path=str(self.project_path))
        
        if not self.output_generator:
            self.output_generator = YAMLOutputGeneratorV2(project_path, output_dir, self.ranker)
    
    def _filter_findings_for_developer_mode(self, findings: List[Finding]) -> List[Finding]:
        """
        Filter findings to show only source code issues for developer focus.
        
        Uses Smart File Classification data to exclude test files, fixtures,
        build artifacts, and other non-production code findings.
        
        Args:
            findings: List of all findings from scanners
            
        Returns:
            List of findings filtered to source code only
        """
        source_code_findings = []
        
        for finding in findings:
            # Safe metadata access with validation
            file_context = {}
            if (hasattr(finding, 'metadata') and 
                isinstance(finding.metadata, dict)):
                file_context = finding.metadata.get('file_context', {})
            
            is_source_code = file_context.get('is_source_code', False) if isinstance(file_context, dict) else False
            
            # Include only findings from actual source code files
            if is_source_code:
                source_code_findings.append(finding)
        
        return source_code_findings
    
    def _validate_project_path(self, args) -> Optional[Path]:
        """
        Validate and resolve the project path from arguments.
        
        Args:
            args: Command line arguments
            
        Returns:
            Resolved project path or None if invalid
        """
        # For scan command, use the positional 'path' argument
        # For other commands, use 'project_path'
        scan_path = getattr(args, 'path', None)
        if scan_path is None:
            scan_path = getattr(args, 'project_path', '.')
        
        logger.debug(f"Path resolution: args.path={getattr(args, 'path', None)}, args.project_path={getattr(args, 'project_path', None)}, selected={scan_path}")
        
        project_path = Path(scan_path).resolve()
        logger.debug(f"Path resolved: {scan_path} -> {project_path}")
        
        if not project_path.exists():
            print(f"❌ Project path does not exist: {project_path}")
            logger.warning(f"Project path validation failed: {project_path} does not exist")
            return None
        
        logger.info(f"Project path validated: {project_path}")
        return project_path
    
    def _print_scan_header(self, project_path: Path, output_dir: str, args) -> None:
        """Print scan header information."""
        print(f"🎺 Copper Sun Brass v2.0 - Scanning {project_path.name}")
        print(f"📁 Project: {project_path}")
        print(f"📤 Output: {project_path / output_dir}")
        
        # Show scan mode information
        if getattr(args, 'fast', False):
            print("⚡ Mode: Fast scan (code analysis only)")
        elif getattr(args, 'dev', False):
            print("👨‍💻 Mode: Developer focus (source code only)")
        elif getattr(args, 'code', False):
            print("🐛 Mode: Code analysis")
        elif getattr(args, 'privacy', False):
            print("🔒 Mode: Privacy analysis")
        elif getattr(args, 'content', False):
            print("🚫 Mode: Content moderation")
        else:
            print("🎯 Mode: Complete analysis")
        print()
    
    @staticmethod
    def _record_peak_rss_mb() -> Optional[float]:
        """Best-effort peak resident-set-size in MB across the parent
        Python process AND any waited-on subprocesses (pysa, semgrep,
        ast-grep, bandit). Returns None on unsupported platforms
        (Windows resource module is absent).

        Why include children: brass spawns multiple scanner subprocesses
        whose RSS is invisible to ``RUSAGE_SELF``. On a 2,821-file
        Django scan (2026-05-20), ``RUSAGE_SELF`` reported 181 MB while
        ``time -l`` (which observes the largest child) reported 1,749
        MB — a 10x undercount that misleads customers about the real
        memory cost of a scan. Including ``RUSAGE_CHILDREN`` closes
        that gap.

        Caveat: ``RUSAGE_CHILDREN.ru_maxrss`` is the MAX peak of any
        single waited child, not the sum across concurrent children.
        For brass that's the right number — the dominant scanner
        (typically pysa on Python codebases) sets the floor on RAM
        needed to run a scan. We report ``max(self, children)``
        because either could dominate depending on the workload.

        macOS ru_maxrss is in BYTES; Linux/BSD in KIBIBYTES. The unit
        difference is documented in ``getrusage(2)`` and trips most
        callers. Dispatch on ``sys.platform`` rather than the value
        magnitude.
        """
        try:
            import resource
        except ImportError:
            return None
        import sys
        rss_self = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        rss_children = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        rss = max(rss_self, rss_children)
        if sys.platform == "darwin":
            return rss / (1024 * 1024)
        return rss / 1024

    def _persist_scanner_timings(self, project_path, output_dir) -> None:
        """Write per-scanner wall-time observability to disk.

        Reads from `self._scanner_timings` (set inside _run_analysis_workflow).
        Single write-point so a future scanner added at the end of the
        pipeline doesn't accidentally get omitted from the timings file.
        """
        timings = getattr(self, "_scanner_timings", None)
        if not timings:
            return
        # Perf #10: include peak-RSS (memory) observability alongside
        # per-scanner timing. Stored under "_meta" so the benchmark
        # harness can pick it up without colliding with scanner names.
        peak_mb = self._record_peak_rss_mb()
        payload = dict(timings)
        if peak_mb is not None:
            payload["_meta_peak_rss_mb"] = round(peak_mb, 1)
        # Loose end #8: per-scanner status (ok/skipped/errored + reason).
        # Same `_meta_*` prefix convention as _meta_peak_rss_mb so the
        # benchmark harness's existing filter ignores it cleanly.
        if self._scanner_status:
            payload["_meta_scanner_status"] = {
                name: s.to_dict() for name, s in self._scanner_status.items()
            }
        out_dir = Path(project_path) / (output_dir or ".brass")
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "scanner_timings.json").write_text(
            json.dumps(payload, indent=2, sort_keys=True)
        )

    def _scanner_for(self, name: str):
        """Map an orchestration scanner name to the live scanner instance.

        Used by _run_scanner_task to read scanner.last_run_status after
        scan() completes. The keys here must stay in sync with the names
        passed to _add() in _run_analysis_workflow and with the attribute
        names initialized in _initialize_components — if the orchestration
        name drifts from the attribute name, last_run_status surfacing
        silently degrades to "ok" (orchestrator default).
        """
        mapping = {
            "code": self.code_scanner,
            "privacy": self.brass2_privacy_scanner,
            "content_moderation": self.content_moderation_scanner,
            "javascript_typescript": self.javascript_typescript_scanner,
            "phantom_ai": self.phantom_ai_code_scanner,
            "brass_performance": self.brass_performance_scanner,
            "api_security": self.api_security_scanner,
            "pysa_taint": self.pysa_taint_scanner,
            "ast_grep": self.ast_grep_scanner,
            "semgrep_taint": self.semgrep_taint_scanner,
            "secrets": self.secrets_scanner,
            "ai_context_coherence": self.ai_context_coherence_scanner,
        }
        return mapping.get(name)

    @staticmethod
    def _print_scanner_result(
        banner: str,
        findings: list,
        exc: Optional[Exception],
        status: "ScannerStatus",
    ) -> None:
        """Format the per-scanner console result line.

        On exception: prefix `⚠️`, label "errored" with the exception.
        On scanner-reported skipped/errored: prefix `⚠️`, suffix the reason.
        On ok: prefix `✓`, show finding count.
        """
        if exc is not None:
            logger.warning("%s analysis failed: %s", banner, exc)
            print(f"   ⚠️ {banner}: errored ({exc})")
            return
        if status.status == "skipped":
            print(f"   ⚠️ {banner}: 0 findings (skipped: {status.reason})")
        elif status.status == "errored":
            print(f"   ⚠️ {banner}: 0 findings (errored: {status.reason})")
        else:
            print(f"   ✓ {banner}: {len(findings)} findings")

    def _run_analysis_workflow(self, args) -> List[Finding]:
        """
        Run the complete analysis workflow using Brass2-compliant hybrid filtering.
        
        Args:
            args: Command line arguments
            
        Returns:
            List of all findings from enabled scanners with noise reduction applied
        """
        # Top-level workflow wall-clock — used to surface analysis_duration
        # in statistics.yaml's performance_metrics. Stored on self so
        # downstream methods like _generate_output (called from a sibling
        # method, not nested) can read it without threading the value
        # through several call sites.
        self._scan_workflow_t0 = time.monotonic()

        # Per-scanner wall-time instrumentation. Each scanner block writes
        # one entry. Dumped to .brass/scanner_timings.json at the end so
        # the benchmark harness can attribute speedups to specific scanners.
        scanner_timings: Dict[str, float] = {}

        @contextmanager
        def time_scanner(name: str):
            t0 = time.monotonic()
            try:
                yield
            finally:
                scanner_timings[name] = round(time.monotonic() - t0, 3)

        # Phase 1: File prefiltering (Brass2-compliant deterministic)
        print("📁 Running file prefiltering...")
        with time_scanner("file_prefilter"):
            prefilter = FilePrefilterScanner(str(self.project_path))
            files_to_analyze = prefilter.scan()
        print(f"   Files selected for analysis: {len(files_to_analyze)}")

        # Shared file enumeration cache. Migrated scanners (Pysa, Semgrep,
        # ast-grep so far) read from this instead of re-walking the tree.
        # Built lazily on first access, but we eagerly build here so its
        # one-time walk time is recorded as a discrete timing entry rather
        # than charged to whichever scanner happens to ask first.
        #
        # Injection contract: scanners are instantiated in
        # `_initialize_components` (before this workflow runs) with
        # file_index=None. We inject the populated cache here as an
        # attribute assignment. Any code path that calls a migrated
        # scanner's `scan()` BEFORE this assignment will silently fall
        # back to the per-scanner rglob walk — correct, just slower. If
        # parallelism (Opt #1) ever pre-fetches scanner output before
        # `_run_analysis_workflow` runs, this contract needs revisiting.
        with time_scanner("file_index"):
            file_index = FileIndex(self.project_path)
            file_index.build()
        # Inject the shared cache into every scanner that has been
        # migrated to honor it. Scanners not in this list still work
        # via their per-scanner rglob fallback path.
        for scanner in (
            self.pysa_taint_scanner,
            self.semgrep_taint_scanner,
            self.ast_grep_scanner,
            self.phantom_ai_code_scanner,
            self.brass_performance_scanner,
            self.api_security_scanner,
            self.ai_context_coherence_scanner,
        ):
            if scanner is not None:
                scanner.file_index = file_index

        # Perf #4: incremental mode. Propagate the user-supplied baseline
        # commit to scanners that support it (currently semgrep).
        since_commit = getattr(args, 'since_commit', None)
        if since_commit and self.semgrep_taint_scanner is not None:
            self.semgrep_taint_scanner.since_commit = since_commit

        # Incremental scan setup (--incremental flag, 2026-05-19). The
        # idea: file-local scanners re-scan only changed files, cached
        # findings for unchanged files come from .brass/finding_cache.json
        # produced by the prior scan. Cross-file scanners always full-scan
        # for correctness. Falls back to a full scan on:
        #   - first run (no cache file)
        #   - schema mismatch / unreadable cache
        #   - both git-diff AND mtime detection failing
        # so the user never silently gets partial output.
        output_dir_for_cache = getattr(args, 'output_dir', '.brass')
        incremental_mode = bool(getattr(args, 'incremental', False))
        cached_findings_by_scanner: Dict[str, list] = {}
        changed_files_set: Set[str] = set()
        incremental_active = False
        # File-local scanners read from this list. Default: same as the
        # full prefilter result (no narrowing). Incremental mode below
        # may overwrite it with the changed-files intersection.
        file_local_scan_files: List[str] = files_to_analyze
        if incremental_mode:
            cache_file_path = _finding_cache.cache_path(self.project_path, output_dir_for_cache)
            cache_payload = _finding_cache.read_cache(cache_file_path)
            if cache_payload is None:
                print("   --incremental: no prior cache; running full scan to seed it.")
            else:
                last_sha = cache_payload.get("last_scan_head_sha")
                last_at = cache_payload.get("last_scan_at")
                changed: Optional[Set[str]] = None
                # Prefer git-based detection when we have a prior HEAD ref.
                if last_sha:
                    changed = _change_detection.files_changed_since_commit(
                        self.project_path, last_sha,
                    )
                if changed is None and last_at:
                    changed = _change_detection.files_changed_since_mtime(
                        self.project_path, last_at,
                    )
                if changed is None:
                    print(
                        "   --incremental: change detection failed (not a git "
                        "repo and mtime fallback errored); running full scan."
                    )
                else:
                    changed_files_set = _change_detection.normalize_changed_files(changed)
                    cached_findings_by_scanner = cache_payload["findings_by_scanner"]
                    incremental_active = True
                    # Two file lists from here on:
                    #   * files_to_analyze — the FULL prefilter result. Used
                    #     by cross-file scanners that need the whole graph
                    #     (AIContextCoherence accepts file_paths but its
                    #     analysis is project-wide).
                    #   * file_local_scan_files — the changed-file slice.
                    #     Used by per-file scanners (BrassPerf, secrets,
                    #     code, privacy, content_moderation, JS/TS) so
                    #     they skip the work that the cache will replay.
                    file_local_scan_files = [
                        fp for fp in files_to_analyze if fp in changed_files_set
                    ]
                    print(
                        f"   --incremental: {len(changed_files_set)} changed file(s) "
                        f"detected; {len(file_local_scan_files)} after prefilter "
                        f"intersection. Reusing cached findings for unchanged files."
                    )

        # Per-language gates (Perf #3). A scanner that can only analyze
        # files of language X has no work to do on a project with zero
        # files of language X. Skipping at the workflow level avoids the
        # scanner's cold-start cost (subprocess spawn, model load, etc.).
        # Each scanner that has a real cold-start (Bandit, Pyre/Pysa,
        # ast-grep, Babel/Node) saves a few seconds.
        _JS_TS_EXTS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
        has_python = bool(file_index.files_with_ext(".py"))
        has_jsts = bool(file_index.files_with_ext(*_JS_TS_EXTS))

        # Phase 2: Analysis on prefiltered files
        all_findings = []

        # Translate user-friendly aliases to legacy flags for internal logic
        self._translate_user_friendly_flags(args)

        # Build the scanner task list. Each entry: (scanner_name, callable,
        # is_enabled_predicate). The predicates encode the existing gate
        # conditions; callables are zero-arg closures that perform the scan
        # and return a list of findings.
        scanner_tasks: List[Tuple[str, str, Callable[[], list]]] = []

        def _add(name: str, banner: str, fn: Callable[[], list], enabled: bool) -> None:
            if enabled:
                scanner_tasks.append((name, banner, fn))

        # File-local scanners read from file_local_scan_files. In
        # --incremental mode that's the narrowed changed-file slice; in
        # normal scans it's the full prefilter result. Routing through
        # _run_scanner_with_files (instead of calling .scan() directly)
        # gives every scanner the cache-narrowed view without per-
        # scanner code changes. 2026-05-19 incremental MVP.
        _add("code", "🔍 code analysis",
             lambda: self._run_scanner_with_files(self.code_scanner, file_local_scan_files),
             not (args.privacy_only or args.content_only) and has_python)

        _add("privacy", "🔒 privacy analysis",
             lambda: self._run_scanner_with_files(self.brass2_privacy_scanner, file_local_scan_files),
             not (args.code_only or args.content_only or getattr(args, 'no_privacy', False)))

        _add("content_moderation", "🚫 content moderation",
             lambda: self._run_scanner_with_files(
                 self._ensure_component_initialized('content_moderation_scanner'),
                 file_local_scan_files,
             ),
             not (args.code_only or args.privacy_only or getattr(args, 'no_content', False)))

        # JavaScript/TypeScript scanner: skip on pure-Python projects.
        if self.javascript_typescript_scanner:
            _add("javascript_typescript", "🟨 JavaScript/TypeScript analysis",
                 lambda: self._run_scanner_with_files(
                     self.javascript_typescript_scanner, file_local_scan_files,
                 ),
                 not (args.privacy_only or args.content_only) and has_jsts)

        # Phantom AI scanner is Python-only (AST patterns).
        if self.phantom_ai_code_scanner:
            _add("phantom_ai", "👻 Phantom AI Code analysis",
                 lambda: self.phantom_ai_code_scanner.scan(),
                 not (args.privacy_only or args.content_only) and has_python)

        # BrassPerf scanner is Python-only. File-local — use the
        # narrowed scan list in --incremental mode.
        if self.brass_performance_scanner:
            _add("brass_performance", "🏆 BrassPerf Performance",
                 lambda: self._run_scanner_with_files(
                     self.brass_performance_scanner, file_local_scan_files,
                 ),
                 not (args.privacy_only or args.content_only) and has_python)

        # API security: Python + JS/TS. Skip only when both languages absent.
        if self.api_security_scanner:
            _add("api_security", "🔐 API Security",
                 lambda: self.api_security_scanner.scan(),
                 not (args.privacy_only or args.content_only) and (has_python or has_jsts))

        # Pysa is Python-only by construction; already has an internal
        # `_has_python_sources()` check but gating here saves a process spawn.
        if self.pysa_taint_scanner:
            _add("pysa_taint", "🧠 Pysa interprocedural taint",
                 lambda: self.pysa_taint_scanner.scan(),
                 not (args.privacy_only or args.content_only)
                 and not getattr(args, 'no_pysa', False)
                 and has_python)

        # ast-grep + semgrep span Python + JS/TS.
        if self.ast_grep_scanner:
            _add("ast_grep", "🔎 ast-grep pattern",
                 lambda: self.ast_grep_scanner.scan(),
                 not (args.privacy_only or args.content_only)
                 and not getattr(args, 'no_ast_grep', False)
                 and (has_python or has_jsts))

        if self.semgrep_taint_scanner:
            _add("semgrep_taint", "🧪 Semgrep taint",
                 lambda: self.semgrep_taint_scanner.scan(),
                 not (args.privacy_only or args.content_only)
                 and not getattr(args, 'no_semgrep', False)
                 and (has_python or has_jsts))

        # Secrets scanner is file-local — narrow to changed files when
        # --incremental is active.
        if self.secrets_scanner:
            _add("secrets", "🔑 Secrets detection",
                 lambda: self._run_scanner_with_files(
                     self.secrets_scanner, file_local_scan_files,
                 ),
                 not (args.privacy_only or args.content_only))

        # AI Context Coherence is Python-only (analyzes class/import graphs).
        if self.ai_context_coherence_scanner:
            _add("ai_context_coherence", "🧠 AI Context Coherence",
                 lambda: self.ai_context_coherence_scanner.scan(),
                 not (args.privacy_only or args.content_only) and has_python)

        # Drift defense: warn if any scheduled scanner name has no entry in
        # _scanner_for(). Such drift would silently degrade last_run_status
        # surfacing to "ok" — scanner could fail silently and no one would
        # notice. Soft warning so the scan still runs; the customer-facing
        # output just won't flag this particular scanner's skip reasons.
        for _name, _banner, _fn in scanner_tasks:
            if self._scanner_for(_name) is None:
                logger.warning(
                    "Scanner '%s' has no _scanner_for() mapping. Its "
                    "last_run_status will silently degrade to 'ok'. "
                    "Update _scanner_for() in brass_cli.py.",
                    _name,
                )

        # Execute scanners. Parallel by default; --no-parallel falls back to
        # sequential (useful for debugging / reproducing timing baselines).
        # ThreadPoolExecutor chosen over ProcessPoolExecutor because most
        # bottleneck scanners (semgrep, pysa, ast-grep, bandit-via-code)
        # shell out to subprocess; threads release the GIL during the
        # subprocess.run wait, so workers overlap naturally. Pure-Python
        # scanners (privacy, content_moderation, etc.) share the GIL but
        # their wall time is small.
        use_parallel = not getattr(args, 'no_parallel', False)
        max_workers = getattr(args, 'max_workers', None)
        if max_workers is None:
            # Default: leave one core free for the OS / IDE / browser.
            # Cap at 6 to limit FD/process pressure on macOS.
            max_workers = max(1, min((os.cpu_count() or 2) - 1, 6))

        def _run_scanner_task(name: str, banner: str, fn: Callable[[], list]) -> Tuple[str, str, list, Optional[Exception], ScannerStatus]:
            """Worker: time the scan, return result or captured exception.

            Returns (name, banner, findings, exception, status).
            - findings is empty when exception is set
            - status is always set (ok / skipped / errored) so the
              orchestrator can surface degraded scanners downstream
              (loose end #8). Scanner-side `last_run_status` is read
              after `fn()` completes; if absent and no exception fired,
              status defaults to `ok`.

            Invariant: at most ONE in-flight `scan()` call per scanner
            instance per CLI run. Each scanner is constructed once in
            `_initialize_components`; `_add()` schedules each name once
            in this workflow. If a future contributor schedules the
            same scanner instance under two tasks (don't), the read of
            `scanner.last_run_status` becomes a data race across the
            ThreadPoolExecutor workers.
            """
            # Construct ScannerStatus AFTER the `with` block exits — the
            # time_scanner context manager records duration on __exit__,
            # so reading scanner_timings[name] inside the with-block always
            # returned 0.0 (the dict's default). Bug introduced in the #8
            # work (commit 4630f93); customer-visible in
            # scanner_timings.json._meta_scanner_status.<name>.duration_sec.
            findings: list = []
            exc_caught: Optional[Exception] = None
            with time_scanner(name):
                try:
                    findings = fn() or []
                except Exception as exc:  # pragma: no cover - error path
                    exc_caught = exc

            duration = scanner_timings.get(name, 0.0)
            if exc_caught is not None:
                status = ScannerStatus(
                    name=name,
                    status="errored",
                    reason=f"{type(exc_caught).__name__}: {exc_caught}",
                    finding_count=0,
                    duration_sec=duration,
                )
                return name, banner, [], exc_caught, status

            scanner_obj = self._scanner_for(name)
            scanner_reported = getattr(scanner_obj, 'last_run_status', None) if scanner_obj else None
            if scanner_reported is not None:
                status_str, reason = scanner_reported
            else:
                status_str, reason = "ok", None
            status = ScannerStatus(
                name=name,
                status=status_str,
                reason=reason,
                finding_count=len(findings),
                duration_sec=duration,
            )
            return name, banner, findings, None, status

        # Track per-scanner output (in addition to the flat all_findings
        # accumulator) so the incremental-scan cache can store findings
        # keyed by scanner. Survives all dispatch modes (parallel,
        # sequential).
        findings_by_scanner: Dict[str, List["Finding"]] = {}

        if use_parallel and len(scanner_tasks) > 1:
            print(f"⚡ Running {len(scanner_tasks)} scanners in parallel (max_workers={max_workers})...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = [pool.submit(_run_scanner_task, name, banner, fn)
                           for name, banner, fn in scanner_tasks]
                for future in concurrent.futures.as_completed(futures):
                    name, banner, findings, exc, status = future.result()
                    self._scanner_status[name] = status
                    self._print_scanner_result(banner, findings, exc, status)
                    if exc is None:
                        all_findings.extend(findings)
                        findings_by_scanner.setdefault(name, []).extend(findings)
        else:
            # Sequential fallback. Preserves the previous behavior exactly,
            # one scanner at a time with its banner line printed before
            # the scan and the finding count after.
            for name, banner, fn in scanner_tasks:
                print(f"   {banner}…")
                name, banner, findings, exc, status = _run_scanner_task(name, banner, fn)
                self._scanner_status[name] = status
                self._print_scanner_result(banner, findings, exc, status)
                if exc is None:
                    all_findings.extend(findings)
                    findings_by_scanner.setdefault(name, []).extend(findings)

        # Incremental-scan merge: inject cached findings for files that
        # weren't part of this scan's changed-files set. Cross-file
        # scanners' caches are excluded inside the cache module — only
        # file-local scanners replay. This restores the FULL current
        # state of findings (fresh changed-file + cached unchanged-file)
        # so the customer sees real coverage, not a delta-only view.
        if incremental_active and cached_findings_by_scanner:
            cached_for_unchanged = _finding_cache.filter_cache_for_unchanged_files(
                cached_findings_by_scanner, changed_files_set,
            )
            merged_count = 0
            for scanner_name, cached_list in cached_for_unchanged.items():
                findings_by_scanner.setdefault(scanner_name, []).extend(cached_list)
                all_findings.extend(cached_list)
                merged_count += len(cached_list)
            if merged_count:
                print(
                    f"🔁 Incremental merge: restored {merged_count} cached "
                    f"findings on unchanged files."
                )

        # Write the cache with the FULL post-merge findings_by_scanner so
        # the next --incremental scan has accurate ground truth to diff
        # against. Best-effort: a write failure logs at warning and the
        # scan still completes (incremental just falls back to full next
        # time). Done before noise reduction / enrichment so the cache
        # stores raw scanner output, not post-processed survivors —
        # that lets us re-apply noise reduction + enrichment consistently
        # across the merged set on every scan.
        try:
            cache_file_for_write = _finding_cache.cache_path(self.project_path, output_dir_for_cache)
            current_head = _change_detection.get_current_head_sha(self.project_path)
            _finding_cache.write_cache(
                cache_file_for_write,
                findings_by_scanner,
                head_sha=current_head,
            )
        except Exception as exc:
            logger.warning("Could not write finding cache: %s", exc)

        # Persist per-scanner timings on the CLI instance so the caller (or
        # any post-scanner phase added later) can dump it. We keep the write
        # to disk in a single place (_persist_scanner_timings) so adding a
        # new scanner doesn't require remembering to update an "end of
        # workflow" sentinel — the dump runs after the whole pipeline.
        self._scanner_timings = scanner_timings
        
        # Phase 2.5: .brassignore — user-defined suppressions.
        # Applied before the noise reducer so suppressed findings never
        # consume downstream enrichment tokens, and before any reporting
        # so counts reflect the user's actual interests.
        from brass.core.brassignore import BrassIgnore, filter_findings as _bi_filter
        brassignore = BrassIgnore.load(self.project_path)
        if brassignore:
            before = len(all_findings)
            all_findings = _bi_filter(all_findings, brassignore)
            dropped = before - len(all_findings)
            if dropped:
                print(f"🙈 .brassignore: dropped {dropped} findings ({before} → {len(all_findings)})")

        # Phase 3: Noise reduction (Brass2-compliant scanner)
        print("🧹 Running intelligent optimization...")
        noise_reducer = NoiseReductionScanner(str(self.project_path))
        clean_findings = noise_reducer.scan(all_findings)

        # Report noise reduction statistics
        stats = noise_reducer.get_stats()
        if stats:
            print(f"   Intelligent optimization: {stats.original_count} → {stats.filtered_count} findings "
                  f"({stats.reduction_percentage:.1f}% reduction)")

        # Cross-scanner overlap pre-stash (Phase F architectural fix,
        # 2026-05-16). The gateway's semantic clusterer will drop
        # cross-scanner same-line peers as duplicates, hiding the
        # cross-scanner agreement signal that's the point of
        # `also_detected_by`. Compute overlap on the pre-enrichment
        # findings and stash peer lists on each finding's metadata
        # so the surviving finding carries them through enrichment's
        # `dataclasses.replace`-based rewriting. ORDER MATTERS: must
        # run BEFORE _maybe_apply_enrichment.
        from brass.output.cross_scanner_overlap import stash_overlap_on_metadata
        clean_findings = stash_overlap_on_metadata(clean_findings)

        # Phase 3.5: AI enrichment (paid feature; gated by active license + --no-enrich opt-out)
        if not getattr(args, 'no_enrich', False):
            clean_findings = self._maybe_apply_enrichment(clean_findings)

        return clean_findings

    def _maybe_apply_enrichment(self, findings):
        """Run findings through the gateway when the license is active.

        Soft-fail to heuristic-only on network / gateway / rate-limit
        errors. Hard-fail on quota exhaustion (per V1 plan §3 locked
        decision: option 2 — sharpest revenue signal).
        """
        from brass.licensing import LicenseStore
        from brass.enrichment import (
            EnrichmentClient,
            EnrichmentClientError,
            EnrichmentRateLimitedError,
            EnrichmentUnavailableError,
            LicenseRejectedError,
            QuotaExhaustedError,
            apply_enrichment,
        )

        record = LicenseStore.default().read()
        if record is None or not record.is_active():
            return findings  # OSS tier or inactive — heuristic only.

        client = EnrichmentClient(
            license_key=record.license_key,
            instance_id=record.instance_id,
        )

        print("✨ Running AI enrichment...")
        try:
            enriched, report = apply_enrichment(findings, str(self.project_path), client)
        except QuotaExhaustedError as exc:
            # Hard fail — locked UX decision.
            print()
            print("❌ Enrichment quota exhausted for this billing period.")
            print(f"   Tokens needed: {exc.tokens_needed:,}")
            print(f"   Tokens remaining: {exc.tokens_remaining:,}")
            if exc.quota_period_end:
                print(f"   Period ends: {exc.quota_period_end}")
            if exc.topup_url:
                print(f"   Top up: {exc.topup_url}")
            print("   Or scan with --no-enrich to fall back to the heuristic filter.")
            raise SystemExit(2)
        except LicenseRejectedError as exc:
            print()
            print(f"❌ License rejected by the enrichment gateway: {exc}")
            print("   This usually means the license was disabled, refunded,")
            print("   or the activation slot was released elsewhere.")
            print("   Run 'brasscoders license' to re-validate, or 'brasscoders scan")
            print("   --no-enrich' to fall back to the heuristic filter.")
            raise SystemExit(2)
        except (EnrichmentRateLimitedError, EnrichmentUnavailableError) as exc:
            print(f"   ⚠️ Enrichment unavailable ({exc}); using heuristic results.")
            return findings
        except EnrichmentClientError as exc:
            # Defensive catch-all: anything else, soft-fail.
            print(f"   ⚠️ Enrichment skipped ({exc}); using heuristic results.")
            return findings

        used_pct = 0
        if report.quota_remaining + report.tokens_used > 0:
            total_period_budget = report.quota_remaining + report.tokens_used
            used_pct = int(round(100 * report.tokens_used / total_period_budget))
        print(
            f"   Enriched: {report.input_count} → {report.output_count} findings "
            f"({report.duplicates_dropped} duplicates dropped)"
        )
        # Telemetry-only: keep token usage in brass.log for support /
        # billing investigations, but hide it from customer-facing
        # stdout. Use a dedicated `brass.telemetry` logger with
        # `propagate = False` so a customer's `logging.basicConfig(stdout)`
        # / `dictConfig` / pipeline log-capture wrapper can't accidentally
        # surface the tokens via root-logger inheritance — the original
        # 2026-05-16 "hide tokens" change relied on the brass.cli logger
        # not propagating, which holds today but isn't enforced.
        _telemetry_logger = get_logger("brass.telemetry")
        _telemetry_logger.propagate = False
        _telemetry_logger.info(
            "Enrichment tokens: %s used; %s remaining",
            f"{report.tokens_used:,}",
            f"{report.quota_remaining:,}",
        )
        # Always-on counter + 80%/95% warnings (locked UX decision in plan §4).
        # The enrich response gives us total remaining but not the monthly
        # allowance, so we fetch quota state to compute the percentage.
        try:
            quota_state = client.quota()
        except EnrichmentClientError:
            quota_state = None
        if quota_state is not None and quota_state.monthly_limit > 0:
            burned = quota_state.monthly_limit - quota_state.monthly_remaining
            pct = int(round(100 * burned / quota_state.monthly_limit))
            if pct >= 95:
                print(
                    f"   🚨 You have used {pct}% of this period's enrichment "
                    f"allowance — top up at https://coppersun.dev/topup"
                )
            elif pct >= 80:
                print(f"   ⚠️  You have used {pct}% of this period's enrichment allowance.")

        return enriched
    
    def _run_scanner_with_files(self, scanner, file_paths: List[str]) -> List[Finding]:
        """
        Run a scanner with prefiltered files.

        Args:
            scanner: Scanner instance to run
            file_paths: List of file paths to analyze. Convention:
                - non-empty list: scan exactly these files
                - empty list: scan ZERO files (return [])
                - None: scanner discovers files itself
            The empty-list short-circuit matters for --incremental: when
            change detection finds no modified files, file-local scanners
            should do zero work. Most scanners' ``if file_paths:`` checks
            treat ``[]`` as falsy and fall back to full discovery, which
            defeats the entire point of incremental mode (observed
            2026-05-19: secrets scanner spent 37.6s on 0 files because
            it treated empty list as "no filter, scan all").

        Returns:
            List of findings from the scanner
        """
        # Short-circuit on empty list: no files to scan = no findings.
        # Skips scanner cold-start (subprocess spawn, model load, etc.).
        if file_paths is not None and len(file_paths) == 0:
            return []
        try:
            # Most scanners support file_paths parameter in their scan method
            if hasattr(scanner, 'scan') and callable(scanner.scan):
                # Try to pass file_paths if scanner supports it
                import inspect
                scan_signature = inspect.signature(scanner.scan)
                if 'file_paths' in scan_signature.parameters:
                    return scanner.scan(file_paths=file_paths)
                else:
                    # Fallback: run scanner normally (it will discover files itself)
                    return scanner.scan()
            else:
                logger.warning(f"Scanner {scanner.__class__.__name__} has no scan method")
                return []
        except Exception as e:
            logger.error(f"Scanner {scanner.__class__.__name__} failed: {e}")
            return []
    
    def _apply_filtering(self, args, all_findings: List[Finding]) -> List[Finding]:
        """
        Apply filtering options to findings based on command arguments.
        
        Args:
            args: Command line arguments
            all_findings: All findings before filtering
            
        Returns:
            Filtered findings list
        """
        findings_to_process = all_findings
        
        # Apply developer mode filtering (both --dev and legacy --source-only)
        if getattr(args, 'dev', False) or getattr(args, 'source_only', False):
            mode_name = "developer mode" if getattr(args, 'dev', False) else "source-only mode"
            print(f"🎯 Applying {mode_name} filtering (source code only)...")
            findings_to_process = self._filter_findings_for_developer_mode(all_findings)
            filtered_count = len(all_findings) - len(findings_to_process)
            print(f"   Filtered out {filtered_count} test/build findings, showing {len(findings_to_process)} source code issues")
        
        return findings_to_process
    
    def _generate_output(self, findings: List[Finding]) -> Tuple[List[Finding], List[str]]:
        """
        Generate ranked findings and output files.
        
        Args:
            findings: Findings to process
            
        Returns:
            Tuple of (ranked_findings, output_files)
        """
        print("📊 Ranking findings by importance...")
        ranked_findings = self.ranker.rank_findings(findings)

        print("📄 Generating intelligence reports...")
        # Loose end #8: pass scanner_status so the YAML output can flag
        # degraded scanners. generate_intelligence accepts the kwarg
        # optionally (callers that don't track status pass nothing).
        # Read the workflow wall-clock that _run_analysis_workflow set on
        # self. Defensive default (None) so isolated callers that bypass
        # the orchestrator don't crash.
        t0 = getattr(self, "_scan_workflow_t0", None)
        scan_duration = round(time.monotonic() - t0, 2) if t0 is not None else None
        # Sample peak RSS once here so statistics.yaml and the on-disk
        # scanner_timings.json both reflect the same reading. Includes
        # subprocess memory (pysa, semgrep, ast-grep, bandit) so the
        # customer-facing number matches `time -l`'s observation.
        peak_memory_mb = self._record_peak_rss_mb()
        output_files = self.output_generator.generate_intelligence(
            ranked_findings,
            scanner_status=self._scanner_status or None,
            scan_duration_seconds=scan_duration,
            peak_memory_mb=peak_memory_mb,
        )

        return ranked_findings, output_files
    
    def _display_results_summary(self, args, all_findings: List[Finding], 
                               findings_to_process: List[Finding], output_files: List[str],
                               ranked_findings: List[Finding], project_path: Path, 
                               output_dir: str) -> None:
        """
        Display comprehensive results summary to user.
        
        Args:
            args: Command line arguments
            all_findings: All findings before filtering
            findings_to_process: Processed findings
            output_files: Generated output files
            ranked_findings: Ranked findings for display
            project_path: Project path
            output_dir: Output directory
        """
        print()
        print("✅ Analysis complete!")
        
        # Show filtering information with user-friendly names
        if getattr(args, 'dev', False) or getattr(args, 'source_only', False):
            mode_name = "developer mode" if getattr(args, 'dev', False) else "source-only mode"
            print(f"📊 Found {len(findings_to_process)} source code issues in {mode_name} (filtered from {len(all_findings)} total)")
        else:
            print(f"📊 Found {len(all_findings)} total issues")
        print(f"📄 Generated {len(output_files)} intelligence files")
        
        # Show top findings
        critical_findings = [f for f in ranked_findings if f.is_critical()]
        if critical_findings:
            print(f"🚨 {len(critical_findings)} critical/high severity issues require attention")
            print("\n🎯 Top Issues:")
            for i, finding in enumerate(critical_findings[:5], 1):
                print(f"   {i}. {finding.title} ({finding.severity.value}) - {finding.get_location_string()}")
        
        print(f"\n📋 View detailed analysis: {project_path / output_dir / 'ai_instructions.yaml'}")
        
        # Show file usage guidance
        print(f"\n📚 How to Use Your Results:")
        print(f"   🤖 For AI coding: Share ai_instructions.yaml with Claude Code")
        print(f"   🔒 For security review: Check security_report.yaml first")
        print(f"   📂 For file-specific issues: Browse file_intelligence.yaml")
        print(f"   📊 For project overview: Review statistics.yaml")
        
        # Add helpful next steps based on analysis mode
        self._show_helpful_next_steps(args, len(all_findings), len(critical_findings))
    
    def _handle_error_reporting(self, project_path: Path, output_dir: str) -> None:
        """
        Handle error reporting at the end of analysis.
        
        Args:
            project_path: Project path
            output_dir: Output directory
        """
        error_reporter = get_error_reporter(str(project_path / output_dir))
        error_summary = error_reporter.get_error_summary()
        
        if error_summary['total_errors'] > 0:
            logger.info(f"Analysis completed with {error_summary['total_errors']} errors")
            error_report_path = error_reporter.save_error_report()
            if error_report_path:
                logger.debug(f"Error report saved to {error_report_path}")
    
    @handle_common_errors
    def _cmd_scan(self, args) -> int:
        """
        Execute scan command.
        
        Orchestrates the complete analysis workflow with reduced complexity
        through method extraction for better maintainability.
        """
        # Validate and setup project path
        project_path = self._validate_project_path(args)
        if not project_path:
            return 1
        
        # Store project path for use in workflow
        self.project_path = project_path
        
        output_dir = args.output_dir or '.brass'
        # Resolve output directory to absolute path for consistency
        resolved_output_dir = str(project_path / output_dir)
        
        # Reconfigure logging with resolved output directory
        log_file = getattr(args, 'log_file', None)
        no_log_file = getattr(args, 'no_log_file', False)
        self._configure_logging(args.verbose, log_file, no_log_file, resolved_output_dir)
        
        self._print_scan_header(project_path, output_dir, args)
        
        # Validate environment before initialization
        self._validate_environment(project_path)
        
        # NEW: Validate output directory state
        state_validator = StateValidator(project_path / output_dir)
        validation_result = state_validator.validate_and_clean()
        
        # Show cleanup message if files were cleaned
        if validation_result.files_cleaned > 0:
            print(f"🧹 {validation_result.message}")
            logger.info(f"State validation: {validation_result.message} "
                       f"(validated {validation_result.files_validated} files in "
                       f"{validation_result.validation_time_ms:.1f}ms)")
        
        # Resolve network policy. --offline is a hard override; everything that talks
        # to the network must respect it. Default is "no outbound calls".
        offline_mode = bool(getattr(args, 'offline', False))
        # Propagate to scanners that check via env var (Pysa typeshed
        # auto-fetch reads BRASS_OFFLINE to gate its git clone). Other
        # network-touching paths in this process branch on offline_mode
        # directly.
        if offline_mode:
            os.environ["BRASS_OFFLINE"] = "1"
        check_package_hallucination = (
            bool(getattr(args, 'check_package_hallucination', False))
            and not offline_mode
        )
        if offline_mode and getattr(args, 'check_package_hallucination', False):
            print("ℹ️  --offline overrides --check-package-hallucination; staying offline.")

        # Initialize system components
        self._initialize_components(
            str(project_path),
            output_dir,
            check_package_hallucination=check_package_hallucination,
        )
        
        # Run analysis and collect findings
        all_findings = self._run_analysis_workflow(args)
        # Persist per-scanner timings for the benchmark harness, regardless
        # of whether findings were produced. Wrapped because timing
        # observability must never break the scan.
        try:
            self._persist_scanner_timings(project_path, output_dir)
        except Exception as exc:
            logger.warning("Failed to persist scanner_timings.json: %s", exc)
        # Empty-findings scans still need YAML output: AI consumers
        # read ``.brass/ai_instructions.yaml`` and expect a predictable
        # file layout — even a clean codebase should emit a confirming
        # "we ran, here's what we checked, no findings" report. Without
        # this, a customer integrating brass into a workflow sees
        # ``.brass/`` materialize with just ``brass.log`` +
        # ``scanner_timings.json`` and has to special-case "did the
        # scan even run?". Discovered 2026-05-21 evaluating
        # tweet-automation-system. Friendly-message stays as a stdout
        # hint; the canonical signal is the populated YAML set.
        if not all_findings:
            print("✅ No issues detected - excellent work!")
        # Apply filtering and process findings (no-op on empty input).
        findings_to_process = self._apply_filtering(args, all_findings)
        if all_findings and not findings_to_process:
            # all_findings was non-empty but filtering removed everything
            # (e.g., --dev mode dropped all test-file findings). Still
            # generate output so the AI consumer sees the filtered view.
            print("✅ No source code issues detected - clean production code!")
        
        # Generate output and reports
        ranked_findings, output_files = self._generate_output(findings_to_process) 
        
        # Display results and summary
        self._display_results_summary(args, all_findings, findings_to_process, 
                                    output_files, ranked_findings, project_path, output_dir)
        
        # Handle error reporting
        self._handle_error_reporting(project_path, output_dir)

        # Operational note: cache size awareness. Lands after the
        # results panel so it reads as a "by the way" footer, not
        # part of the scan results.
        self._print_cache_footer()

        # Emit anonymized telemetry. No-ops when consent is off (the
        # default). Records only counts — never source code, file paths,
        # or PII. Counts are derived from the ``ranked_findings`` list,
        # not from any file content.
        from brass.telemetry import record as _telemetry_record
        try:
            from collections import Counter
            type_counts = Counter(
                getattr(f.type, 'value', str(f.type))
                for f in ranked_findings
            )
            severity_counts = Counter(
                getattr(f.severity, 'value', str(f.severity))
                for f in ranked_findings
            )
            _telemetry_record(
                event='scan',
                total_findings=len(ranked_findings),
                finding_types=dict(type_counts),
                severity_counts=dict(severity_counts),
                fast=bool(getattr(args, 'fast', False)),
                dev_mode=bool(getattr(args, 'dev', False)),
                offline=bool(getattr(args, 'offline', False)),
            )
        except Exception:
            # Telemetry must never bubble into the CLI's normal flow.
            pass

        return 0

    def _translate_user_friendly_flags(self, args) -> None:
        """
        Translate user-friendly command aliases to internal legacy flags.
        
        Args:
            args: Command line arguments to modify
        """
        # Map user-friendly aliases to legacy flags
        if getattr(args, 'fast', False):
            args.code_only = True
            args.no_privacy = True
            args.no_content = True
        
        if getattr(args, 'dev', False):
            args.source_only = True
        
        if getattr(args, 'code', False):
            args.code_only = True
        
        if getattr(args, 'privacy', False):
            args.privacy_only = True
        
        if getattr(args, 'content', False):
            args.content_only = True
    
    def _show_helpful_next_steps(self, args, total_findings: int, critical_count: int) -> None:
        """
        Show context-appropriate next steps to the user.
        
        Args:
            args: Command line arguments
            total_findings: Total number of findings
            critical_count: Number of critical findings
        """
        if total_findings == 0:
            print("\n🎉 No issues found - your code looks great!")
            print("💡 Try running with different scan options to check other aspects:")
            print("   • brasscoders scan --privacy    # Check for sensitive data")
            print("   • brasscoders scan --content    # Check content policies")
            return
        
        print("\n💡 Next Steps:")
        
        if critical_count > 0:
            print(f"   🚨 Priority: Address {critical_count} critical/high severity issues first")
        
        if getattr(args, 'fast', False):
            print("   🔍 Run full analysis: brasscoders scan (includes privacy & content checks)")
        elif getattr(args, 'code', False):
            print("   🔒 Check privacy: brasscoders scan --privacy")
            print("   🚫 Check content: brasscoders scan --content")
        elif getattr(args, 'dev', False):
            print("   📊 See all findings: brasscoders scan (includes test/build files)")
        
        print("   👁️ Monitor changes: brasscoders watch")
        print("   📊 View status: brasscoders status")
    
    def _cmd_watch(self, args) -> int:
        """Execute watch command."""
        project_path = Path(args.project_path).resolve()
        
        if not project_path.exists():
            print(f"❌ Project path does not exist: {project_path}")
            return 1
        
        print(f"👁️ Starting continuous monitoring of {project_path.name}")
        print(f"📁 Project: {project_path}")
        print(f"⏱️ Poll interval: {args.poll_interval}s")
        print(f"🕐 Debounce delay: {args.debounce_delay}s")
        print("\nPress Ctrl+C to stop monitoring...\n")
        
        # Initialize components
        self._initialize_components(str(project_path))
        
        # Create incremental analyzer
        incremental_analyzer = IncrementalAnalyzer(
            self.code_scanner,
            self.brass2_privacy_scanner,
            self.ranker,
            self.output_generator
        )
        
        def on_changes_detected(changed_files: List[str]):
            """Callback for when file changes are detected."""
            print(f"📝 Changes detected in {len(changed_files)} files")
            result = incremental_analyzer.analyze_changes(changed_files)
            
            if result['status'] == 'success':
                print(f"✅ Analysis updated: {result['findings_detected']} findings, {result['output_files_updated']} files updated")
            elif result['status'] == 'no_changes':
                print("ℹ️ No relevant changes to analyze")
            else:
                print(f"❌ Analysis failed: {result.get('error_message', 'Unknown error')}")
        
        # Start monitoring
        try:
            with FileWatcher(
                str(project_path),
                on_changes_detected=on_changes_detected,
                poll_interval=args.poll_interval,
                debounce_delay=args.debounce_delay
            ) as watcher:
                
                print("👁️ Monitoring started - watching for changes...")

                # Block on the watcher's shutdown event rather than busy-
                # spinning every second. The FileWatcher runs its own
                # daemon thread; the main thread just waits to be interrupted.
                try:
                    watcher.shutdown_event.wait()
                except KeyboardInterrupt:
                    pass
        
        except Exception as e:
            print(f"❌ Monitoring error: {e}")
            return 1
        
        print("\n👋 Monitoring stopped")
        return 0
    
    def _cmd_status(self, args) -> int:
        """Execute status command."""
        project_path = Path(args.project_path).resolve()
        output_dir = project_path / '.brass'
        
        print(f"📊 Copper Sun Brass Status - {project_path.name}")
        print(f"📁 Project: {project_path}")
        print()
        
        # Check if analysis has been run
        if not output_dir.exists():
            print("❌ No analysis found - run 'brasscoders scan' first")
            return 1
        
        # Check intelligence files
        intelligence_files = {
            'ai_instructions.yaml': 'Main guidance for AI assistants (start here!)',
            'detailed_analysis.yaml': 'Complete technical breakdown of all issues',
            'security_report.yaml': 'Security vulnerabilities requiring attention',
            'privacy_analysis.yaml': 'Personal data exposure and compliance issues',
            'file_intelligence.yaml': 'File-by-file breakdown of problems found',
            'statistics.yaml': 'Summary metrics and project trends'
        }
        
        print("📄 Intelligence Files:")
        for filename, description in intelligence_files.items():
            file_path = output_dir / filename
            if file_path.exists():
                size = file_path.stat().st_size
                mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
                print(f"   ✅ {filename} - {description} ({size} bytes, {mtime.strftime('%Y-%m-%d %H:%M')})")
            else:
                print(f"   ❌ {filename} - Missing")
        
        # Load and show summary from JSON if available
        json_file = output_dir / 'analysis_data.json'
        if json_file.exists():
            try:
                import json
                with open(json_file, 'r') as f:
                    data = json.load(f)
                
                summary = data.get('summary', {})
                print(f"\n📊 Analysis Summary:")
                print(f"   🔍 Total Findings: {summary.get('total_findings', 0)}")
                print(f"   📁 Files Analyzed: {summary.get('files_analyzed', 0)}")
                print(f"   🎯 Average Confidence: {summary.get('avg_confidence', 0):.1%}")
                print(f"   📈 Average Impact: {summary.get('avg_impact', 0):.1%}")
                
                by_type = summary.get('by_type', {})
                if by_type:
                    print(f"\n🏷️ Findings by Type:")
                    for finding_type, count in by_type.items():
                        print(f"   - {finding_type.replace('_', ' ').title()}: {count}")
                
                by_severity = summary.get('by_severity', {})
                if by_severity:
                    print(f"\n⚡ Findings by Severity:")
                    for severity, count in by_severity.items():
                        print(f"   - {severity.title()}: {count}")
            
            except Exception as e:
                print(f"❌ Error reading analysis data: {e}")
        
        return 0
    
    def _cmd_report(self, args) -> int:
        """Execute report command."""
        print(f"📄 Generating {args.type} report(s) in {args.format} format...")
        
        # This would implement specific report generation
        # For now, point to existing scan functionality
        print("ℹ️ Use 'brasscoders scan' to generate all reports")
        print("   Specific report types will be available in future versions")
        
        return 0
    
    def _cmd_filter(self, args) -> int:
        """Apply BrassCoders noise reduction to an AI reviewer JSON payload."""
        from brass.filtering.ai_review_filter import main as filter_main
        argv = [
            '--input', args.input,
            '--output', args.output,
        ]
        return filter_main(argv)

    def _cmd_activate(self, args) -> int:
        """Activate a BrassCoders license against LemonSqueezy and persist locally."""
        from datetime import datetime, timezone
        from brass.licensing import (
            LicenseAPIError,
            LicenseInvalidError,
            LicenseRecord,
            LicenseStore,
            activate as ls_activate,
        )
        store = LicenseStore.default()
        try:
            result = ls_activate(args.token)
        except LicenseInvalidError as exc:
            print(f"❌ License rejected by LemonSqueezy: {exc}")
            return 1
        except LicenseAPIError as exc:
            print(f"❌ Could not reach LemonSqueezy: {exc}")
            print("   The license API is the only network call this command makes; "
                  "if you're offline, retry when you have connectivity.")
            return 1

        now = datetime.now(timezone.utc).isoformat()
        record = LicenseRecord(
            license_key=result.license_key,
            instance_id=result.instance_id,
            status=result.status,
            activated_at=now,
            last_validated_at=now,
            expires_at=result.expires_at,
            customer_email=result.customer_email,
            product_name=result.product_name,
        )
        store.write(record)

        suffix = "perpetual" if record.expires_at is None else f"expires {record.expires_at}"
        product = result.product_name or "BrassCoders license"
        print(f"✅ Activated {product} ({suffix})")
        if result.activation_limit is not None:
            print(f"   Activations: {result.activation_usage}/{result.activation_limit}")
        print(f"   Stored at:   {store.path}")
        return 0

    def _cmd_license(self, args) -> int:
        """Show the active license. Re-validates against LS if cached state is stale."""
        from datetime import datetime, timezone
        from brass.licensing import (
            LicenseAPIError,
            LicenseInvalidError,
            LicenseStore,
            validate as ls_validate,
        )
        store = LicenseStore.default()
        record = store.read()
        if record is None:
            print("ℹ️  No license activated. BrassCoders is running in OSS-tier mode.")
            print("   To activate: brasscoders activate <license-key>")
            return 0

        # Re-validate against LS at most once a week. Keeps the network
        # surface small while still picking up server-side revocations.
        if record.days_since_validation() >= 7:
            print("🔄 Validating license with LemonSqueezy…")
            try:
                result = ls_validate(record.license_key, instance_id=record.instance_id)
                store.update_validation(
                    status=result.status,
                    validated_at=datetime.now(timezone.utc).isoformat(),
                )
                record = store.read() or record
            except LicenseInvalidError as exc:
                print(f"⚠️  License is no longer valid: {exc}")
                print(f"   File: {store.path}  (run 'brasscoders deactivate' to clear)")
                return 1
            except LicenseAPIError as exc:
                print(f"⚠️  Could not reach LemonSqueezy ({exc}); using cached status.")

        marker = "✅" if record.is_active() else "⚠️ "
        print(f"{marker} {record.product_name or 'BrassCoders license'} — status: {record.status}")
        if record.customer_email:
            print(f"   Email:           {record.customer_email}")
        print(f"   Activated:       {record.activated_at}")
        print(f"   Last validated:  {record.last_validated_at}")
        if record.expires_at:
            print(f"   Expires:         {record.expires_at}")
        else:
            print(f"   Expires:         never (perpetual)")

        # Enrichment quota — paid feature; only meaningful for active licenses.
        if record.is_active():
            self._print_enrichment_quota(record)
        return 0

    def _print_enrichment_quota(self, record) -> None:
        """Fetch + display the current enrichment-token quota for this license.

        Best-effort. A network failure here is informational, not blocking
        — `brasscoders license` is a status command; users still see the
        license details above even if the gateway is down.
        """
        from brass.enrichment import EnrichmentClient, EnrichmentClientError

        client = EnrichmentClient(
            license_key=record.license_key,
            instance_id=record.instance_id,
        )
        try:
            quota = client.quota()
        except EnrichmentClientError as exc:
            print(f"   AI enrichment:   could not fetch quota ({exc})")
            return

        used = quota.monthly_limit - quota.monthly_remaining
        pct = int(round(100 * used / quota.monthly_limit)) if quota.monthly_limit else 0
        print(
            f"   AI enrichment:   {quota.monthly_remaining:,} of "
            f"{quota.monthly_limit:,} monthly tokens remaining ({pct}% used)"
        )
        if quota.topup_remaining > 0:
            print(f"                    + {quota.topup_remaining:,} top-up tokens")
        print(f"   Period ends:     {quota.period_end}")

        # Low-quota warning at 90%+ used — gives customers a heads-up
        # to top up before they hit quota_exhausted mid-scan. Threshold
        # is generous (10M tokens left when monthly_limit is 50M) so
        # the message doesn't surface for normal usage.
        if quota.total_remaining < 10_000_000:
            print(
                f"   ⚠️  Low quota — only {quota.total_remaining:,} tokens left. "
                f"Top up: https://coppersun.dev/topup"
            )

        # Always-useful pointers customers should know about. Kept short.
        print(f"   Manage:          brasscoders portal  (opens billing portal)")
        print(f"   Top up:          https://coppersun.dev/topup")

    def _cmd_deactivate(self, args) -> int:
        """Release the activation slot for this machine and remove the local record."""
        from brass.licensing import (
            LicenseAPIError,
            LicenseInvalidError,
            LicenseStore,
            deactivate as ls_deactivate,
        )
        store = LicenseStore.default()
        record = store.read()
        if record is None:
            print("ℹ️  No license to deactivate.")
            return 0

        try:
            ls_deactivate(record.license_key, instance_id=record.instance_id)
            print("🗑  Released activation slot with LemonSqueezy.")
        except LicenseInvalidError as exc:
            print(f"ℹ️  LemonSqueezy already considers this slot inactive: {exc}")
        except LicenseAPIError as exc:
            print(f"⚠️  Could not reach LemonSqueezy ({exc}); removing local record anyway.")

        store.delete()
        print(f"🗑  Local record removed ({store.path}). BrassCoders is now OSS-tier.")
        return 0

    def _cmd_portal(self, args) -> int:
        """Fetch the LS customer portal URL for the active license and open it in a browser."""
        import webbrowser
        from brass.licensing import LicenseStore
        from brass.enrichment import (
            EnrichmentClient,
            EnrichmentClientError,
            EnrichmentUnavailableError,
            LicenseRejectedError,
        )

        store = LicenseStore.default()
        record = store.read()
        if record is None:
            print("ℹ️  No license activated. To activate: brasscoders activate <license-key>")
            return 1
        if not record.is_active():
            print(f"⚠️  License is {record.status}. Cannot open portal for an inactive license.")
            print("   Run 'brasscoders license' for details.")
            return 1

        client = EnrichmentClient(
            license_key=record.license_key,
            instance_id=record.instance_id,
        )
        try:
            portal_url = client.portal()
        except LicenseRejectedError as exc:
            print(f"⚠️  License rejected by gateway: {exc}")
            print("   Try 'brasscoders license' to see status.")
            return 1
        except EnrichmentUnavailableError as exc:
            print(f"⚠️  Could not fetch portal URL: {exc}")
            print("   You can manage your subscription directly at https://coppersunbrass.lemonsqueezy.com")
            return 1
        except EnrichmentClientError as exc:
            print(f"⚠️  Unexpected error: {exc}")
            return 1

        print(f"🌐 Opening customer portal in your browser…")
        print(f"   {portal_url}")
        try:
            webbrowser.open(portal_url)
        except Exception as exc:
            # Some headless environments (CI, SSH-without-X) can't open
            # a browser. Print the URL so the user can copy it manually.
            print(f"   (Could not auto-open browser: {exc}. Copy the URL above.)")
        return 0

    def _cmd_telemetry(self, args) -> int:
        """Toggle or inspect anonymized telemetry consent."""
        from brass.telemetry import ConsentStore
        store = ConsentStore()
        if args.action == 'on':
            install_id = store.set(enabled=True)
            print("✅ Telemetry: ON")
            print(f"   Install ID:  {install_id}")
            print(f"   Consent at:  {store.path}")
            print("   Inspect what gets recorded: ~/.brass/telemetry-debug.log")
            print("   Disable any time:           brasscoders telemetry off")
            return 0
        if args.action == 'off':
            store.set(enabled=False)
            print("🚫 Telemetry: OFF")
            print(f"   Consent at:  {store.path}")
            return 0
        # status
        enabled = store.is_enabled()
        marker = "ON ✅" if enabled else "OFF 🚫"
        print(f"📊 Telemetry: {marker}")
        if enabled and store.install_id():
            print(f"   Install ID:  {store.install_id()}")
        print(f"   Consent at:  {store.path}")
        print("   Toggle:      brasscoders telemetry on | off")
        return 0

    def _cmd_cache(self, args) -> int:
        """Dispatch `brasscoders cache <action>`. Currently only 'clear'."""
        if args.action == 'clear':
            return self._cmd_cache_clear(args)
        print(f"❌ Unknown cache action: {args.action}")
        return 1

    def _cmd_cache_clear(self, args) -> int:
        """Remove the Pysa state cache (and optionally the typeshed cache).

        Respects BRASS_PYSA_CACHE_ROOT — clears whatever location the var
        points at, not the hardcoded default. The typeshed half always
        targets ~/.cache/brass/typeshed/ (the autofetch path);
        BRASS_TYPESHED-redirected paths are user-owned and left untouched.

        Defense: the typeshed path is also validated against the same
        blocklist + 3-parts check the Pysa root uses, in case $HOME is
        misconfigured (HOME=/, HOME=/tmp, etc).
        """
        import shutil as _shutil  # local import; cli imports are already heavy
        from brass.scanners.pysa_taint_scanner import PysaTaintScanner

        pysa_root = PysaTaintScanner._resolved_cache_root()
        typeshed_root = self._resolved_typeshed_cache_root()

        pysa_bytes = self._dir_size(pysa_root) if pysa_root.exists() else 0
        typeshed_bytes = (
            self._dir_size(typeshed_root)
            if (args.include_typeshed and typeshed_root is not None and typeshed_root.exists())
            else 0
        )

        nothing_to_do = pysa_bytes == 0 and not (
            args.include_typeshed and typeshed_bytes > 0
        )
        if nothing_to_do:
            if args.include_typeshed:
                ts_msg = (
                    str(typeshed_root)
                    if typeshed_root is not None
                    else "(typeshed location rejected by safety check)"
                )
                print(
                    f"✅ No cache to clear ({pysa_root} and {ts_msg} are empty or absent)."
                )
            else:
                print(f"✅ No cache to clear ({pysa_root} is empty or absent).")
            return 0

        total_freed = 0
        had_failure = False

        if pysa_bytes > 0:
            n_projects = sum(1 for p in pysa_root.iterdir() if p.is_dir())
            print(f"🧹 Pysa cache: {pysa_root}")
            print(
                f"   {n_projects} project cache"
                f"{'s' if n_projects != 1 else ''}: "
                f"{self._format_mb(pysa_bytes)} total"
            )
            if args.dry_run:
                print("   (dry-run; not removed)")
            else:
                # Per-entry accounting so a partial failure (mid-rmtree
                # permission error on the Nth hash dir) still reports
                # the bytes we actually freed from the first N-1 dirs.
                freed_here = 0
                first_failure: Optional[Exception] = None
                for entry in pysa_root.iterdir():
                    try:
                        entry_size = self._dir_size(entry) if entry.is_dir() else (
                            entry.stat().st_blocks * 512
                            if hasattr(entry.stat(), 'st_blocks')
                            else entry.stat().st_size
                        )
                    except OSError:
                        entry_size = 0
                    try:
                        if entry.is_dir():
                            _shutil.rmtree(entry, ignore_errors=False)
                        else:
                            entry.unlink()
                        freed_here += entry_size
                    except OSError as exc:
                        if first_failure is None:
                            first_failure = exc
                        had_failure = True
                        # Continue with remaining entries; reporting all
                        # failures is noisier than necessary, but the
                        # partial-success bytes are tracked.
                total_freed += freed_here
                if first_failure is None:
                    print("   ✓ removed")
                else:
                    print(
                        f"   ⚠️  partial: freed {self._format_mb(freed_here)} "
                        f"before {type(first_failure).__name__}: {first_failure}"
                    )

        if args.include_typeshed and typeshed_bytes > 0:
            print(f"🧹 Typeshed cache: {typeshed_root}")
            print(f"   {self._format_mb(typeshed_bytes)}")
            if args.dry_run:
                print("   (dry-run; not removed)")
            else:
                try:
                    _shutil.rmtree(typeshed_root, ignore_errors=False)
                    print("   ✓ removed")
                    # Pysa needs typeshed. The next online scan
                    # auto-refetches (~33MB git clone). In offline mode
                    # the scanner skips with a warning. Flag both
                    # outcomes here so the customer is never surprised.
                    print(
                        "   ℹ️  Next scan will auto-refetch typeshed "
                        "(~33 MB git clone, unless --offline is set)."
                    )
                    total_freed += typeshed_bytes
                except OSError as exc:
                    print(f"   ❌ failed: {exc}")
                    had_failure = True

        print()
        if args.dry_run:
            total_pending = pysa_bytes + typeshed_bytes
            print(
                f"ℹ️  Run without --dry-run to free "
                f"{self._format_mb(total_pending)}."
            )
        else:
            suffix = ' total' if args.include_typeshed else ''
            if had_failure:
                print(
                    f"⚠️  Freed {self._format_mb(total_freed)}{suffix} (partial — "
                    f"some entries could not be removed; see warnings above)."
                )
                return 1
            print(f"✅ Freed {self._format_mb(total_freed)}{suffix}.")
        return 0

    @staticmethod
    def _resolved_typeshed_cache_root() -> Optional[Path]:
        """Compute the typeshed cache path, validated against the same
        blocklist + 3-parts rule that protects the Pysa cache root.

        Default location is `~/.cache/brass/typeshed/`. If $HOME resolves
        to a system path (`/`, `/etc`, `/tmp`, …) or fewer than 3 path
        components, return None — the caller treats that as "no typeshed
        cache to clear" rather than risking rmtree against a system dir.

        This is purely defense-in-depth; under any sane configuration
        Path.home() returns a 3+ component user-owned dir and the check
        passes silently.
        """
        from brass.scanners.pysa_taint_scanner import PysaTaintScanner
        try:
            candidate = (Path.home() / '.cache' / 'brass' / 'typeshed').resolve()
        except (OSError, ValueError):
            return None
        if str(candidate) in PysaTaintScanner._CACHE_ROOT_BLOCKLIST:
            return None
        # ~/.cache/brass/typeshed under a 1-part HOME would still produce
        # a 4-part path, but we keep the >= 3 check symmetric with the
        # Pysa side. Also guard against $HOME being itself in the blocklist.
        try:
            home_resolved = Path.home().resolve()
        except (OSError, ValueError):
            return None
        if (
            str(home_resolved) in PysaTaintScanner._CACHE_ROOT_BLOCKLIST
            or len(home_resolved.parts) < 2
        ):
            return None
        if len(candidate.parts) < 3:
            return None
        return candidate

    @staticmethod
    def _dir_size(path: Path) -> int:
        """Recursive directory size in bytes, reported the way `du -sh`
        reports it: allocated disk blocks, not file-content bytes. The
        two differ significantly for trees full of small files (typeshed
        has 5k+ .pyi files of ~200 bytes each; content-bytes reports
        ~17 MB but actual disk usage is ~33 MB due to 4 KB block
        allocation). Users compare our output to `du -sh`; matching that
        avoids "where did the rest go?" confusion after a clear.

        Uses os.walk(followlinks=False) for deterministic behavior across
        Python versions — Path.rglob's symlink-descent semantics changed
        between 3.11 and 3.13 and we don't want size attribution to vary
        with the interpreter version.

        Falls back to `st_size` when `st_blocks` is unavailable (Windows).
        Unreadable files are skipped consistently with `du`'s permission-
        error behavior.
        """
        total = 0
        try:
            for dirpath, _dirnames, filenames in os.walk(str(path), followlinks=False):
                for fname in filenames:
                    fpath = Path(dirpath) / fname
                    try:
                        if fpath.is_symlink():
                            # Count the link inode itself, not the target
                            # — same convention as `du` without `-L`.
                            st = fpath.lstat()
                        else:
                            st = fpath.stat()
                        blocks = getattr(st, 'st_blocks', None)
                        if blocks is not None:
                            total += blocks * 512
                        else:
                            total += st.st_size
                    except OSError:
                        continue
        except OSError:
            pass
        return total

    @staticmethod
    def _format_mb(n_bytes: int) -> str:
        return f"{n_bytes / (1024 * 1024):.1f} MB"

    def _print_cache_footer(self) -> None:
        """Print a one-line awareness footer about the Pysa cache size.

        Three-level size-based output:
          - < 100 MB: silent (uninteresting; a single populated project
            cache is typical, not "growing unbounded")
          - 100 MB – 1 GB: info-style, suggests `brasscoders cache clear`
          - >= 1 GB: warning-style, recommends `cache clear --include-typeshed`

        Suppress entirely via `BRASS_QUIET_CACHE=1` — for power users and
        CI environments that don't want the noise.

        Best-effort: any error reading the cache root is swallowed so the
        footer never breaks scan output. The footer is operational info,
        not result data.
        """
        if os.environ.get("BRASS_QUIET_CACHE") == "1":
            return
        try:
            from brass.scanners.pysa_taint_scanner import PysaTaintScanner
            cache_root = PysaTaintScanner._resolved_cache_root()
            if not cache_root.exists():
                return
            bytes_used = self._dir_size(cache_root)
            # Silence floor: ignore caches below ~100 MB. A single
            # typical project is 10-300 MB; users only care once they've
            # accumulated past a single-project footprint.
            if bytes_used < 100 * 1024 * 1024:
                return
            # "Project caches" is the canonical user-facing term across
            # brass (matching `brasscoders cache clear`'s output and the
            # ai_instructions.yaml advisory). Each entry is a SHA-hashed
            # subdirectory containing one project's Pyre call graph +
            # config metadata. Phase C's `_prune_stale_entries`
            # (2026-05-16) removes entries whose source dir no longer
            # exists, so the count now closely tracks projects the
            # customer actively scans.
            entry_count = sum(
                1 for p in cache_root.iterdir()
                if p.is_dir() and not p.name.startswith('.')
            )
            if bytes_used >= 1024 ** 3:  # >= 1 GB → warning
                size_str = f"{bytes_used / (1024 ** 3):.1f} GB"
                print(
                    f"⚠️  BrassCoders cache is {size_str} across {entry_count} "
                    f"project caches. Consider 'brasscoders cache clear --include-typeshed' "
                    f"to reclaim disk space."
                )
            else:
                size_str = self._format_mb(bytes_used)
                print(
                    f"🧹 BrassCoders cache: {size_str} across {entry_count} "
                    f"project caches (run 'brasscoders cache clear' to free)"
                )
        except Exception as exc:  # noqa: BLE001 - footer must not break scan
            logger.debug("cache footer suppressed: %s", exc)

    def _cmd_version(self, args) -> int:
        """Execute version command (with optional update check).

        The PyPI freshness check is opt-out via ``--offline`` (which the
        user already passes when they want zero outbound network calls)
        and via the ``BRASS_DISABLE_VERSION_CHECK`` env var. Failures are
        silently swallowed so a captive portal or down PyPI never breaks
        the version command itself. We never auto-update.
        """
        from brass.core.version_check import check_for_updates
        try:
            from brass import __version__ as current_version
        except (ImportError, AttributeError):
            current_version = "2.0.0"

        print("🎺 BrassCoders for AI Coders v2.0 - Revolutionary Intelligence System")
        print("   AI Development Intelligence for Coding Assistants")
        print("   Built with clean architecture and fantastic user experience")
        print()
        print("🔧 Core Components:")
        print("   • ProfessionalCodeScanner - Multi-tool code analysis (Bandit + Pylint + Security)")
        print("   • Brass2PrivacyScanner - Advanced PII detection")
        print("   • ContentModerationScanner - Policy compliance")
        print("   • JavaScriptTypeScriptScanner - Unified JS/TS analysis with Babel")
        print("   • PhantomAICodeScanner - Detects incomplete AI-generated code")
        print("   • BrassPerformanceScanner - Performance Intelligence for AI code (Radon + Vulture + AI patterns)")
        print("   • IntelligenceRanker - Weighted priority system")
        print("   • OutputGenerator - AI-optimized intelligence files")
        print("   • FileWatcher - Real-time change monitoring")
        print("   • CLI - User-friendly command interface")
        print()
        print("💡 Get Started:")
        print("   brasscoders scan                          # Complete analysis")
        print("   brasscoders scan --fast                   # Quick code review")
        print("   brasscoders scan --dev                    # Developer focus")
        print("   brasscoders scan --performance-full       # Complete performance analysis")
        print("   brasscoders watch                         # Monitor changes")
        print()

        # Soft update warning. Skipped when --offline or
        # BRASS_DISABLE_VERSION_CHECK=1; failures are swallowed.
        offline = bool(getattr(args, 'offline', False))
        check = check_for_updates(current_version, offline=offline)
        if check and check.is_stale():
            print(
                f"⚠️  A newer BrassCoders is available: {check.latest} "
                f"(running {check.current}). Update with: "
                f"pipx upgrade brasscoders"
            )
        elif check and check.behind_by == 1:
            print(f"ℹ️  New release available: {check.latest} (running {check.current}).")

        return 0


def main():
    """Main entry point for CLI."""
    # Set up global error handling for better user experience
    setup_global_error_handler()
    
    try:
        # Run startup checks before anything else
        run_startup_checks(verbose=False)
    except StartupError as e:
        print(f"\n❌ Startup checks failed:\n{e}")
        print("\n💡 Please fix the issues above before running BrassAI.")
        return 1
    except Exception as e:
        print(f"\n❌ Unexpected error during startup: {e}")
        return 1
    
    cli = BrassCLI()
    return cli.run()


if __name__ == '__main__':
    sys.exit(main())