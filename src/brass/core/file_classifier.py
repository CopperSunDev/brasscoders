"""
Smart File Classification System for New BrassCoders System v2.0.

Provides intelligent file type detection and context for improved user experience
and accurate issue prioritization.
"""

import re
from pathlib import Path
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Pattern

from brass.core.logging_config import get_logger

logger = get_logger(__name__)


class FileType(Enum):
    """Types of files that can be classified."""
    SOURCE_CODE = "source_code"          # Main application source code
    TEST_FILE = "test_file"              # Unit/integration test files
    TEST_FIXTURE = "test_fixture"        # Test data and fixture files
    CONFIGURATION = "configuration"      # Config, setup, and build files
    DOCUMENTATION = "documentation"      # Documentation and README files
    BUILD_OUTPUT = "build_output"        # Generated/build output files
    UNKNOWN = "unknown"                  # Default fallback


@dataclass
class FileContext:
    """
    Context information about a file's classification and characteristics.
    
    This provides metadata that helps with intelligent issue prioritization
    and user experience improvements.
    """
    file_type: FileType
    confidence: float                    # Classification confidence (0.0-1.0)
    intended_for_issues: bool           # True if file is meant to contain test issues
    priority_weight: float              # Multiplier for ranking (0.0-1.0)
    classification_reason: str          # Human-readable explanation
    
    def is_source_code(self) -> bool:
        """Check if this is actual source code that users care about."""
        return self.file_type == FileType.SOURCE_CODE
    
    def is_test_related(self) -> bool:
        """Check if this is test-related (tests, fixtures, etc.)."""
        return self.file_type in [FileType.TEST_FILE, FileType.TEST_FIXTURE]
    
    def should_prioritize_issues(self) -> bool:
        """Check if issues in this file should be high priority."""
        return self.file_type == FileType.SOURCE_CODE and not self.intended_for_issues


class FileClassifier:
    """
    Intelligent file classification system.
    
    Analyzes file paths and content to determine file type, purpose, and
    appropriate issue prioritization weights.
    """
    
    def __init__(self, project_root: Optional[str] = None):
        """
        Initialize FileClassifier.
        
        Args:
            project_root: Root directory of the project (for relative path analysis)
        """
        self.project_root = Path(project_root) if project_root else None
        self._classification_cache: Dict[str, FileContext] = {}
        self._compile_patterns()
    
    def _compile_patterns(self) -> None:
        """Compile regex patterns for efficient file classification."""
        
        # Common source-file extensions across the ecosystems BrassCoders scans.
        # Kept as a string fragment so individual patterns stay readable.
        _SRC_EXT = r"\.(py|pyi|ts|tsx|js|jsx|mjs|cjs|go|rs|java|kt|rb|php)$"

        # Source code patterns (highest priority). Covers single-package
        # layouts (src/, lib/, app/), Go's pkg/internal convention,
        # Next.js components/, plus Turborepo / Yarn-Workspaces monorepo
        # roots (apps/<pkg>/..., packages/<pkg>/...). The monorepo
        # patterns require the package name to be non-anchored so the
        # actual source files anywhere under apps/<x>/ all qualify.
        self.source_patterns = [
            (re.compile(rf'^src/.*{_SRC_EXT}'), 0.95, "Main source code directory"),
            (re.compile(rf'^[^/]+{_SRC_EXT}'), 0.85, "Root-level source file"),
            (re.compile(rf'^lib/.*{_SRC_EXT}'), 0.90, "Library source code"),
            (re.compile(rf'^app/.*{_SRC_EXT}'), 0.90, "Application source code"),
            (re.compile(rf'^apps/.*{_SRC_EXT}'), 0.92, "Monorepo app source"),
            (re.compile(rf'^packages/.*{_SRC_EXT}'), 0.92, "Monorepo package source"),
            (re.compile(rf'^pkg/.*{_SRC_EXT}'), 0.90, "Package source code"),
            (re.compile(rf'^internal/.*{_SRC_EXT}'), 0.90, "Internal source code"),
            (re.compile(rf'^components/.*{_SRC_EXT}'), 0.90, "UI component source"),
            # Type-declaration files travel with their source — keep
            # them production-classified so .d.ts findings (broken refs,
            # missing types) aren't deprioritized.
            (re.compile(r'.*\.d\.ts$'), 0.85, "TypeScript declaration file"),
            # Catch-all: any lowercase-named top-level directory
            # containing source files. Confidence 0.70 (below canonical
            # `src/` at 0.95) so a domain-specific module directory
            # like `whisper-platform/`, `api-client/`, or
            # `data-processing/` gets the benefit of the doubt without
            # overriding stronger signals from canonical layouts.
            # Vendored / dependency directories are filtered upstream
            # by `should_exclude_from_analysis`, so no negation needed
            # here (the AI consumer's triage_priority depends on
            # `is_production_code: true` — without this catch-all, real
            # production code in non-canonical layouts gets the wrong
            # signal and the AI clears genuine findings).
            (re.compile(rf'^[a-z_][a-z0-9_-]*/.*{_SRC_EXT}'), 0.70, "Source code in custom module directory"),
        ]

        # Build/utility scripts: typically deployment/codegen/maintenance
        # tools, not user-facing application code. Treated as configuration
        # so they get LOW priority (and aren't flagged as production_code).
        self.script_patterns = [
            (re.compile(r'^scripts/.*'), 0.90, "Build/utility scripts directory"),
            (re.compile(r'^tools/.*'), 0.85, "Tooling directory"),
            (re.compile(r'^bin/.*'), 0.85, "Executable scripts directory"),
        ]

        # Test file patterns. Covers Python, JS/TS (Jest/Vitest), and Go.
        self.test_patterns = [
            (re.compile(rf'^tests?/.*test.*{_SRC_EXT}'), 0.95, "Test file in tests directory"),
            (re.compile(rf'^.*test.*\.py$'), 0.80, "Test file by naming convention"),
            (re.compile(r'^tests?/conftest\.py$'), 0.98, "Pytest configuration file"),
            (re.compile(rf'^test_.*{_SRC_EXT}'), 0.90, "Test file with test_ prefix"),
            (re.compile(rf'^.*_test{_SRC_EXT}'), 0.90, "Test file with _test suffix"),
            # JS/TS test conventions (Jest, Vitest, Cypress, Playwright).
            (re.compile(rf'.*\.(test|spec)\.[a-z]+$'), 0.95, "JS/TS test by .test/.spec extension"),
            (re.compile(rf'.*/__tests__/.*'), 0.95, "JS/TS __tests__ directory"),
            (re.compile(rf'^__tests__/.*'), 0.95, "Top-level __tests__ directory"),
            (re.compile(rf'^e2e/.*'), 0.90, "End-to-end test directory"),
            (re.compile(rf'^cypress/.*'), 0.90, "Cypress test directory"),
            (re.compile(rf'^playwright/.*'), 0.90, "Playwright test directory"),
        ]

        # Test fixture patterns
        self.fixture_patterns = [
            (re.compile(rf'^tests?/fixtures/.*'), 0.98, "Test fixture file"),
            (re.compile(rf'^tests?/.*fixtures.*'), 0.95, "Test fixture in tests directory"),
            (re.compile(rf'^fixtures/.*'), 0.90, "Fixture file"),
            (re.compile(rf'^tests?/.*test_data.*'), 0.95, "Test data file"),
            (re.compile(rf'^.*test_project{_SRC_EXT}'), 0.98, "Test project fixture"),
            (re.compile(rf'.*/__mocks__/.*'), 0.95, "JS/TS __mocks__ directory"),
            (re.compile(rf'^__mocks__/.*'), 0.95, "Top-level __mocks__ directory"),
        ]
        
        # Configuration patterns
        self.config_patterns = [
            (re.compile(r'^setup\.py$'), 0.98, "Python setup script"),
            (re.compile(r'^pyproject\.toml$'), 0.98, "Python project configuration"),
            (re.compile(r'^.*\.toml$'), 0.85, "TOML configuration file"),
            (re.compile(r'^.*\.yaml$|.*\.yml$'), 0.85, "YAML configuration file"),
            (re.compile(r'^.*\.json$'), 0.75, "JSON configuration file"),
            (re.compile(r'^requirements.*\.txt$'), 0.90, "Python requirements file"),
            (re.compile(r'^Makefile$|^.*\.mk$'), 0.85, "Build configuration"),
            # JS/TS config files. The `*.config.<ext>` convention is
            # near-universal (vite, vitest, jest, next, tailwind,
            # webpack, rollup, etc.).
            (re.compile(r'.*\.config\.(js|ts|mjs|cjs)$'), 0.90, "JS/TS tool config"),
            (re.compile(r'^(jest|vitest|next|vite|webpack|rollup|tailwind|postcss|babel|eslint|prettier)\.config\..*'), 0.95, "Named JS/TS tool config"),
            # Test-environment setup files. `jest.env.js`, `vitest.env.ts`,
            # `test.env.mjs` etc. routinely contain mock credentials and
            # placeholder emails — they're not production code. Identified
            # by the whisperx-production triage where jest.env.js was
            # being flagged as production and surfacing two mock-credential
            # FPs in the production bucket.
            (re.compile(r'.*(\.|^)(env|setup)\.(js|ts|mjs|cjs)$'), 0.90, "Test-env / setup file"),
        ]
        
        # Documentation patterns
        self.doc_patterns = [
            (re.compile(r'^.*\.md$'), 0.90, "Markdown documentation"),
            (re.compile(r'^README.*'), 0.95, "README file"),
            (re.compile(r'^docs/.*'), 0.90, "Documentation directory"),
            (re.compile(r'^CHANGELOG.*|^HISTORY.*'), 0.90, "Change log file"),
        ]
        
        # Build output patterns. Use ``.*<dir>.*`` for paths that can appear at any
        # depth (monorepos, nested workspaces); ``^<dir>/.*`` only for ones that
        # live at the project root by convention.
        self.build_patterns = [
            (re.compile(r'^\.brass/.*'), 0.98, "BrassCoders output directory"),
            (re.compile(r'^__pycache__/.*'), 0.98, "Python cache directory"),
            (re.compile(r'^\.pytest_cache/.*'), 0.98, "Pytest cache directory"),
            (re.compile(r'^build/.*|^dist/.*|^out/.*'), 0.95, "Build output directory"),
            (re.compile(r'^\.git/.*|^\.svn/.*'), 0.98, "Version control directory"),
            (re.compile(r'^.*\.pyc$'), 0.98, "Python bytecode file"),
            # Enhanced exclusion patterns for large project performance
            (re.compile(r'.*site-packages.*'), 0.98, "Python site-packages directory"),
            (re.compile(r'.*archive/.*'), 0.95, "Archive/legacy directory"),
            (re.compile(r'.*archived/.*'), 0.95, "Archived directory"),
            (re.compile(r'.*/_archive(d)?/.*'), 0.95, "Underscored archive directory"),
            (re.compile(r'^_archive(d)?/.*'), 0.95, "Root-level archive directory"),
            (re.compile(r'.*build_env.*'), 0.98, "Build environment directory"),
            (re.compile(r'.*backup.*'), 0.95, "Backup directory"),
            (re.compile(r'.*\.backup/.*'), 0.95, "Backup directory with dot prefix"),
            (re.compile(r'.*test_project.*'), 0.90, "Test project fixture"),
            (re.compile(r'.*realistic_bad_project_test.*'), 0.90, "Realistic bad project test fixture"),
            (re.compile(r'^venv/.*|^\.venv/.*|^env/.*'), 0.98, "Virtual environment directory"),
            (re.compile(r'.*node_modules.*'), 0.98, "Node.js modules directory"),
            (re.compile(r'^\.tox/.*'), 0.98, "Tox testing environment"),
            (re.compile(r'^\.coverage/.*'), 0.98, "Coverage data directory"),
            (re.compile(r'^htmlcov/.*'), 0.98, "HTML coverage reports"),
            # Web framework build outputs. These are minified bundles that
            # produce false positives (catastrophic-backtracking regex hangs,
            # SQL-injection-shaped strings in third-party SDKs, etc.).
            (re.compile(r'.*\.next(/.*)?$'), 0.98, "Next.js build output"),
            (re.compile(r'.*\.nuxt(/.*)?$'), 0.98, "Nuxt.js build output"),
            (re.compile(r'.*\.svelte-kit(/.*)?$'), 0.98, "SvelteKit build output"),
            (re.compile(r'.*\.turbo(/.*)?$'), 0.98, "Turborepo cache directory"),
            (re.compile(r'.*\.vercel(/.*)?$'), 0.98, "Vercel CLI cache"),
            (re.compile(r'.*\.cache(/.*)?$'), 0.95, "Tool cache directory"),
            (re.compile(r'.*\.parcel-cache(/.*)?$'), 0.98, "Parcel cache directory"),
            (re.compile(r'.*\.astro(/.*)?$'), 0.95, "Astro build output"),
            # Compiled-language build dirs that can balloon with generated code.
            (re.compile(r'^target/.*'), 0.95, "Rust/Java target directory"),
            (re.compile(r'.*\.gradle(/.*)?$'), 0.98, "Gradle cache directory"),
            (re.compile(r'^coverage/.*'), 0.95, "Coverage report directory"),
            # ORM / codegen output. Prisma regenerates this on every schema change;
            # findings inside it are about generated code, not human-authored code.
            (re.compile(r'.*prisma/generated(/.*)?$'), 0.98, "Prisma generated client"),
            (re.compile(r'.*generated/graphql(/.*)?$'), 0.95, "GraphQL codegen output"),
        ]
    
    def classify_file(self, file_path: str) -> FileContext:
        """Classify a file and return its context (memoized per instance).

        ``classify_file`` runs ~50 regex matches to determine type/priority.
        Multiple scanners call it for the same path during a single scan
        (and the same scanner often calls it more than once per finding).
        Memoizing on path keeps the work O(unique paths) instead of
        O(scanners × findings).
        """
        cached = self._classification_cache.get(file_path)
        if cached is not None:
            return cached
        result = self._classify_file_uncached(file_path)
        self._classification_cache[file_path] = result
        return result

    def _classify_file_uncached(self, file_path: str) -> FileContext:
        """Compute classification without consulting the cache."""
        # Normalize path for consistent pattern matching
        normalized_path = self._normalize_path(file_path)
        
        # Try each classification category in priority order
        for file_type, patterns, intended_issues, base_weight in [
            (FileType.BUILD_OUTPUT, self.build_patterns, False, 0.1),
            (FileType.TEST_FIXTURE, self.fixture_patterns, True, 0.2),
            (FileType.TEST_FILE, self.test_patterns, False, 0.3),
            (FileType.CONFIGURATION, self.config_patterns, False, 0.4),
            # scripts/tools/bin: classified as CONFIGURATION (low priority,
            # non-production) since these are build-time tooling.
            (FileType.CONFIGURATION, self.script_patterns, False, 0.4),
            (FileType.DOCUMENTATION, self.doc_patterns, False, 0.2),
            (FileType.SOURCE_CODE, self.source_patterns, False, 1.0),
        ]:
            for pattern, confidence, reason in patterns:
                if pattern.match(normalized_path):
                    # Log exclusion patterns specifically for debugging
                    if file_type == FileType.BUILD_OUTPUT and any(keyword in reason.lower() for keyword in 
                        ['site-packages', 'archive', 'build_env', 'backup', 'test_project', 'venv', 'node_modules']):
                        logger.debug(f"MATCHED_EXCLUSION_PATTERN: {normalized_path} -> {reason} (confidence: {confidence})")
                    
                    return FileContext(
                        file_type=file_type,
                        confidence=confidence,
                        intended_for_issues=intended_issues,
                        priority_weight=base_weight,
                        classification_reason=reason
                    )
        
        # Default classification for unknown files
        return FileContext(
            file_type=FileType.UNKNOWN,
            confidence=0.0,
            intended_for_issues=False,
            priority_weight=0.5,  # Neutral weight
            classification_reason="No matching pattern found"
        )
    
    def _normalize_path(self, file_path: str) -> str:
        """
        Normalize file path for consistent pattern matching.
        
        Args:
            file_path: Original file path
            
        Returns:
            Normalized path suitable for pattern matching
        """
        path = Path(file_path)
        
        # Convert to relative path if we have a project root
        if self.project_root and path.is_absolute():
            try:
                path = path.relative_to(self.project_root)
            except ValueError:
                # File is outside project root, use as-is
                pass
        
        # Convert to forward slashes for consistent pattern matching
        normalized = str(path).replace('\\', '/')
        
        # Remove leading "./" if present
        if normalized.startswith('./'):
            normalized = normalized[2:]
        
        return normalized
    
    def get_file_type_summary(self, file_paths: List[str]) -> Dict[FileType, int]:
        """
        Get a summary of file types in a list of files.
        
        Args:
            file_paths: List of file paths to classify
            
        Returns:
            Dictionary mapping file types to counts
        """
        summary = {file_type: 0 for file_type in FileType}
        
        for file_path in file_paths:
            context = self.classify_file(file_path)
            summary[context.file_type] += 1
        
        return summary
    
    def filter_source_files(self, file_paths: List[str]) -> List[str]:
        """
        Filter list to only include source code files.
        
        Args:
            file_paths: List of file paths to filter
            
        Returns:
            List containing only source code files
        """
        source_files = []
        
        for file_path in file_paths:
            context = self.classify_file(file_path)
            if context.file_type == FileType.SOURCE_CODE:
                source_files.append(file_path)
        
        return source_files
    
    def should_exclude_from_analysis(self, file_path: str) -> bool:
        """
        Check if a file should be excluded from analysis entirely.
        
        Enhanced to prevent analysis artifact contamination and reduce noise.
        
        Args:
            file_path: Path to check
            
        Returns:
            True if file should be excluded
        """
        logger.debug(f"Evaluating exclusion for: {file_path}")
        
        # Standard exclusions - build outputs
        context = self.classify_file(file_path)
        if context.file_type == FileType.BUILD_OUTPUT:
            logger.debug(f"EXCLUDED (BUILD_OUTPUT): {file_path} - {context.classification_reason}")
            return True
            
        # Enhanced exclusions - analysis artifacts and contamination sources
        file_path_lower = file_path.lower()
        
        # Analysis artifacts from our own system. Scanning these produces
        # meta-FPs (e.g. BrassCoders surfacing a finding because it itself wrote
        # a string into BRASS_TRIAGE.md describing the finding). The
        # round-4 brass-seo triage flagged BRASS_TRIAGE.md as needing
        # default exclusion — same logic applies to any human-written
        # triage of BrassCoders output.
        analysis_artifacts = [
            '.brass/', '/.brass/', 'analysis_data.json', 'detailed_analysis.yaml',
            'ai_instructions.yaml', 'privacy_analysis.yaml', 'security_report.yaml',
            'file_intelligence.yaml', 'statistics.yaml', '_analysis.yaml',
            '.brass_test/', 'temp_analysis/', '.analysis_cache/',
            'brass_triage.md', 'brass_triage_v',  # BRASS_TRIAGE.md / _v2.md / _v3.md / etc.
            # Lock files — generated by package managers, contents are
            # not human-authored. Scanning them produces FPs (maintainer
            # emails matched as PII, license hashes matched as secrets,
            # etc.) without value. Identified by the copper-sun triage.
            'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
            'poetry.lock', 'cargo.lock', 'go.sum',
            'gemfile.lock', 'composer.lock',
            # AI-agent scratch space. Claude Code uses .claude/worktrees/
            # for parallel agent operations (git worktrees of the project);
            # those copies should never be scanned independently. Other
            # subdirs (.claude/commands/, .claude/skills/) are agent
            # configuration, also not customer source. Identified by the
            # whisperx-production triage as the single highest-ROI fix.
            '.claude/', '/.claude/',
        ]
        
        for artifact in analysis_artifacts:
            if artifact in file_path_lower:
                logger.debug(f"EXCLUDED (ANALYSIS_ARTIFACT): {file_path} - matched '{artifact}'")
                return True
            
        # Development environment artifacts. Substring matches against the
        # lowercased path. Keep this list aligned with build_patterns above —
        # the regex pass catches most but this is the cheap guard for the
        # rglob-walked discovery paths in the API security scanner.
        dev_artifacts = [
            '.ds_store', '__pycache__/', '.pytest_cache/', '.coverage',
            '.venv/', 'venv/', 'node_modules/', '.git/', '.svn/',
            '.idea/', '.vscode/', 'htmlcov/', '.nyc_output/',
            # Web framework + tool caches. Same set as the regex pass above;
            # re-listed here because some scanners check via this method only.
            '.next/', '.nuxt/', '.svelte-kit/', '.turbo/', '.vercel/',
            '.cache/', '.parcel-cache/', '.astro/', '.gradle/',
            'dist/', 'build/', 'out/', 'target/', 'coverage/',
            'prisma/generated/', 'generated/graphql/',
        ]
        
        for artifact in dev_artifacts:
            if artifact in file_path_lower:
                logger.debug(f"EXCLUDED (DEV_ARTIFACT): {file_path} - matched '{artifact}'")
                return True
        
        logger.debug(f"INCLUDED: {file_path} - passed all exclusion checks")
        return False