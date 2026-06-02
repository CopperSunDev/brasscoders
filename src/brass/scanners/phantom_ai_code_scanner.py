"""
PhantomAICodeScanner - Detects phantom implementations and incomplete AI-generated code.

This scanner identifies code that appears complete but is actually non-functional,
including stub methods, broken imports, dead code, and incomplete implementations
commonly found in AI-generated codebases.
"""

import ast
import hashlib
import importlib
import importlib.util
import sys
from functools import lru_cache
from pathlib import Path
from typing import List, Optional, Dict, Set, Any, Tuple
from collections import defaultdict
from datetime import datetime

from brass.models.finding import Finding, FindingType, Severity
from brass.core.file_classifier import FileClassifier
from brass.core.logging_config import get_logger
from brass.core.error_handling import handle_analysis_error, safe_file_operation

logger = get_logger(__name__)

# Configuration constants
MAX_FILE_SIZE_BYTES = 1024 * 1024  # 1MB - Skip large files for performance
DEFAULT_CONFIDENCE = 0.90  # High confidence for AST-based detection
MAX_DEAD_CODE_TOLERANCE = 15  # Allow some unused code (utility methods, etc.)

# Memory management constants - prevent unbounded dictionary growth
MAX_TRACKED_FILES = 1000  # Maximum files to track for symbol analysis
MAX_SYMBOLS_PER_FILE = 100  # Maximum symbols to track per file
MAX_TOTAL_SYMBOLS = 10000  # Total symbol tracking limit to prevent memory exhaustion

# Analysis performance constants - configurable limits for large projects
MAX_IMPORT_CHECK_FILES = 50  # Maximum files to check for broken imports
MAX_DEAD_CODE_REPORTS = 10   # Maximum dead code findings to report (avoid noise)


# Top-level names of popular PyPI packages. A "Broken Import" for one of
# these is almost certainly a missing-local-dep (the package exists; the
# scanning Python env just doesn't have it installed) rather than an
# AI-hallucinated phantom name. Downgrade to LOW severity so customer
# reports aren't flooded with critical "Broken Import: torch" entries on
# ML / cloud-deploy projects where deps live in the remote runtime.
#
# Update annually from PyPI Top Packages
# (https://pypistats.org / https://hugovk.github.io/top-pypi-packages).
# Current cut: 2026-05 snapshot, organized by category for readability.
# Includes top-level distribution names AND common import aliases
# (e.g. PIL → pillow, cv2 → opencv-python, bs4 → beautifulsoup4).
# All entries MUST be lowercase. The lookup site (`_create_broken_import_finding`)
# calls `module_name.split('.', 1)[0].lower()` before membership testing, so
# PascalCase entries like "PIL" or "Crypto" would be dead. Removed entries:
#   - "PIL", "Crypto", "NumPy"     unreachable (case mismatch — pillow / pycryptodome / numpy already covered)
#   - "google"                     too broad as a top-level allowlist entry; would
#                                  suppress hallucinated `google.totally_made_up.*`
#                                  submodules. Specific google.* SDKs covered via
#                                  `googleapiclient` etc.
#   - "mock"                       stdlib has `unittest.mock`; standalone PyPI `mock`
#                                  is a backport with typosquat-adjacent risk
#   - underscore namespace shims   `google_cloud`, `azure_storage_blob`, `django_db`,
#                                  `rest_framework` — real import top-levels are
#                                  `google`, `azure`, `django`. Top-level matching
#                                  cannot reach these as submodules anyway.
_WELL_KNOWN_PYPI_PACKAGES: frozenset[str] = frozenset({
    # --- ML / AI / data-science -----------------------------------
    "torch", "torchvision", "torchaudio", "transformers", "peft", "trl",
    "unsloth", "vllm", "langchain", "langchain_core", "langchain_community",
    "openai", "anthropic", "cohere", "mistralai", "replicate",
    "groq", "litellm", "instructor", "outlines", "guidance", "dspy",
    "numpy", "pandas", "scipy", "matplotlib", "seaborn", "plotly", "altair",
    "sklearn", "scikit_learn", "xgboost", "lightgbm", "catboost",
    "tensorflow", "keras", "jax", "jaxlib", "flax", "optax", "equinox",
    "datasets", "accelerate", "bitsandbytes", "deepspeed", "fairscale",
    "sentence_transformers", "tokenizers", "einops", "ftfy",
    "huggingface_hub", "safetensors", "diffusers", "controlnet_aux",
    "wandb", "mlflow", "tensorboard", "ray", "modal", "modal_proto",
    "hydra", "omegaconf", "optuna",
    "spacy", "nltk", "gensim", "stanza",
    "polars", "duckdb", "pyarrow", "fastparquet",
    "opencv_python", "cv2", "pillow", "imageio", "scikit_image",
    "imagehash",
    # --- Cloud / infra SDKs ---------------------------------------
    "boto3", "botocore", "aiobotocore", "s3transfer",
    "googleapiclient",
    "azure",
    "kubernetes", "openshift", "docker", "paramiko", "fabric",
    "ansible", "pulumi", "pulumi_aws", "terraform_compliance",
    # --- Web / API frameworks -------------------------------------
    "fastapi", "django", "flask", "starlette", "tornado", "sanic", "bottle",
    "pyramid", "falcon", "hug", "litestar", "aiohttp", "uvicorn", "gunicorn",
    "daphne", "hypercorn",
    "requests", "httpx", "urllib3", "aiofiles",
    "websockets",
    "graphene", "strawberry", "ariadne",
    "djangorestframework", "drf_spectacular",
    "flask_login", "flask_sqlalchemy", "flask_migrate", "flask_cors",
    "fastapi_users", "fastapi_pagination",
    # --- Data / storage / queues ----------------------------------
    "sqlalchemy", "alembic", "tortoise", "peewee",
    "psycopg2", "psycopg2_binary", "psycopg", "asyncpg", "pg8000",
    "pymongo", "motor", "beanie", "mongoengine",
    "redis", "aioredis", "kombu", "celery", "rq", "dramatiq", "huey",
    "kafka_python", "confluent_kafka", "aiokafka",
    "pika", "aio_pika",
    "elasticsearch", "elasticsearch_dsl", "opensearch_py",
    "minio",
    # --- Auth / security / crypto ---------------------------------
    "cryptography", "pycryptodome", "nacl", "pynacl",
    "jose", "jwt", "pyjwt", "authlib", "oauthlib",
    "passlib", "bcrypt", "argon2", "argon2_cffi",
    "certifi", "trustme",
    "detect_secrets",
    # --- Testing / dev tooling ------------------------------------
    "pytest", "pytest_asyncio", "pytest_cov", "pytest_xdist", "pytest_mock",
    "pytest_django", "pytest_benchmark", "hypothesis", "faker", "factory_boy",
    "responses", "vcr", "vcrpy", "freezegun", "time_machine",
    "tox", "nox", "coverage", "pytest_timeout",
    "black", "isort", "flake8", "pylint", "ruff", "mypy", "pyright",
    "bandit", "safety", "pip_audit", "semgrep", "pyre", "pyre_check",
    "pre_commit", "commitizen",
    # --- Common utilities -----------------------------------------
    "click", "typer", "fire", "rich", "tqdm", "loguru", "structlog",
    "yaml", "pyyaml", "toml", "tomli", "tomli_w",
    "jinja2", "mako", "chameleon",
    "pydantic", "pydantic_settings", "marshmallow", "attrs", "cattrs",
    "dataclasses_json", "msgspec",
    "beautifulsoup4", "bs4", "lxml", "html5lib",
    "networkx", "graphviz", "pygraphviz",
    "tenacity", "backoff", "retry",
    "validators", "phonenumbers", "email_validator",
    "python_dateutil", "dateutil", "pendulum", "arrow", "pytz",
    "babel",
    "psutil", "py_spy", "pyperf",
    "pyperclip", "keyring",
    "setuptools", "wheel", "build", "twine", "pip", "poetry", "hatchling",
    "packaging", "importlib_metadata", "importlib_resources",
    # --- Notebooks / scientific UI --------------------------------
    "jupyter", "jupyterlab", "ipython", "ipykernel", "notebook",
    "ipywidgets", "voila", "streamlit", "gradio", "dash", "panel",
    "voyageai",
})

# Self-check: catches regressions where someone adds a PascalCase entry
# that the .lower() lookup would never match. Runs once at module import.
assert all(p == p.lower() for p in _WELL_KNOWN_PYPI_PACKAGES), (
    "_WELL_KNOWN_PYPI_PACKAGES must be all-lowercase (lookup applies .lower())"
)

# Stub detection patterns
STUB_PATTERNS = [
    'pass',
    'NotImplemented', 
    'raise NotImplementedError',
    'TODO',
    '# TODO',
    'FIXME',
    '# FIXME',
    'XXX',
    '# XXX',
    'HACK',
    '# HACK'
]


class PhantomAICodeScanner:
    """
    Scanner for detecting phantom implementations and incomplete AI-generated code.
    
    Detects:
    - Stub methods containing only pass, TODO, NotImplemented
    - Broken imports and missing dependencies  
    - Dead/orphaned code without connections
    - Incomplete API implementations
    - Syntax errors in AI-generated code
    
    Follows Brass2 architectural principles with clean separation of concerns.
    """
    
    def __init__(self, project_path: str, file_index=None) -> None:
        """
        Initialize PhantomAICodeScanner with file classification and error handling.

        Args:
            project_path: Root path of project to analyze
            file_index: Optional shared FileIndex (Perf #2). Falls back to
                per-scanner rglob walk when None.

        Raises:
            ValueError: If project_path is invalid
            FileNotFoundError: If project_path doesn't exist
        """
        if not project_path:
            raise ValueError("Project path cannot be empty or None")

        self.project_path = Path(project_path).resolve()
        if not self.project_path.exists():
            raise FileNotFoundError(f"Project path does not exist: {self.project_path}")

        # Initialize core components following established patterns
        self.file_classifier = FileClassifier(str(self.project_path))
        # Shared file enumeration cache (Perf #2). The CLI injects this
        # post-init; standalone callers may pass via ctor.
        self.file_index = file_index
        
        # Track analysis state for dead code detection
        self._symbol_definitions: Dict[str, List[Dict]] = defaultdict(list)
        self._symbol_usage: Dict[str, Set[str]] = defaultdict(set)

        # 2026-05-19 audit (silent-drop class): per-scan counters of
        # coverage gaps caused by hard caps. Each is summarized once at
        # end of scan() so the operator sees the undercount instead of
        # finding it via missing-data forensics later.
        self._symbol_tracking_skipped: int = 0
        self._dead_code_dropped: int = 0
        self._import_files_dropped: int = 0

        logger.info(f"PhantomAICodeScanner initialized for {self.project_path}")
    
    def scan(self, file_paths: Optional[List[str]] = None) -> List[Finding]:
        """
        Scan for phantom implementations and incomplete AI-generated code.
        
        Args:
            file_paths: Optional list of specific files to scan
            
        Returns:
            List of Finding objects describing phantom code issues
        """
        try:
            findings = []
            
            # Get Python files to analyze
            python_files = self._discover_python_files(file_paths)
            logger.info(f"PhantomAICodeScanner analyzing {len(python_files)} Python files")
            
            # Clear analysis state for this scan
            self._symbol_definitions.clear()
            self._symbol_usage.clear()
            # 2026-05-19 audit (silent-drop class): reset per-scan drop
            # counters so a long-lived scanner instance doesn't carry
            # stale numbers from a previous scan into its summary log.
            self._symbol_tracking_skipped = 0
            self._dead_code_dropped = 0
            self._import_files_dropped = 0
            
            # Phase 1: Analyze individual files for stubs and syntax errors
            for file_path in python_files:
                findings.extend(self._analyze_file(file_path))
            
            # Phase 2: Cross-file analysis for dead code and import validation
            findings.extend(self._analyze_dead_code())
            findings.extend(self._analyze_import_validity(python_files))

            self._emit_silent_drop_summary()
            logger.info(f"PhantomAICodeScanner found {len(findings)} phantom code issues")
            return findings

        except Exception as e:
            logger.error(f"PhantomAICodeScanner scan failed: {e}")
            handle_analysis_error("phantom_detection", "PhantomAICodeScanner", "scan", e)
            return [self._create_analysis_error_finding(str(e))]
        finally:
            # Bug Scanner 2026-05-19: summary must fire on exception path
            # too — that's when operators most need visibility into what
            # was processed before failure. Idempotent; the happy-path
            # call above + this call emit identical INFO lines.
            self._emit_silent_drop_summary()

    def _emit_silent_drop_summary(self) -> None:
        """Aggregate end-of-scan log for PhantomAI's cap-related gaps.
        Called from both happy-path and finally clause; the log line is
        identical and idempotent (counters don't change between calls).
        """
        gap_parts: List[str] = []
        if self._symbol_tracking_skipped > 0:
            gap_parts.append(
                f"{self._symbol_tracking_skipped} file(s) skipped past MAX_TRACKED_FILES cap"
            )
        if self._dead_code_dropped > 0:
            gap_parts.append(
                f"{self._dead_code_dropped} dead-code finding(s) truncated past MAX_DEAD_CODE_REPORTS cap"
            )
        if self._import_files_dropped > 0:
            gap_parts.append(
                f"{self._import_files_dropped} file(s) skipped past MAX_IMPORT_CHECK_FILES cap"
            )
        if gap_parts:
            logger.info(
                "PhantomAI coverage gaps this scan (findings may undercount): "
                + "; ".join(gap_parts)
            )
    
    def _discover_python_files(self, file_paths: Optional[List[str]]) -> List[Path]:
        """
        Discover Python files to analyze with intelligent filtering.
        
        Args:
            file_paths: Optional list of specific files to scan
            
        Returns:
            List of Python file paths to analyze
        """
        if file_paths:
            # Use specified files, converting to Path objects
            return [Path(fp) for fp in file_paths if fp.endswith('.py')]
        
        # Discover all Python files in project with proper exclusions.
        # Prefer the shared FileIndex (already filtered by FileClassifier)
        # over a per-scanner rglob walk — saves an O(n) tree traversal.
        from brass.core.path_safety import is_within
        python_files = []
        if self.file_index is not None:
            candidates = self.file_index.files_with_ext(".py")
        else:
            candidates = list(self.project_path.rglob('*.py'))
        for py_file in candidates:
            file_path_str = str(py_file)

            if not is_within(py_file, self.project_path):
                continue

            # Skip files that start with __ (like __pycache__)
            if py_file.name.startswith('__'):
                continue

            # FileIndex already applied the FileClassifier exclude rules;
            # the rglob fallback path still needs the explicit check.
            if self.file_index is None and self.file_classifier.should_exclude_from_analysis(file_path_str):
                continue
                
            # Skip files that are too large for performance
            try:
                if py_file.stat().st_size > MAX_FILE_SIZE_BYTES:
                    logger.info(f"Skipping large file: {py_file} ({py_file.stat().st_size} bytes)")
                    continue
            except OSError:
                continue
            
            python_files.append(py_file)
        
        return python_files
    
    def _analyze_file(self, file_path: Path) -> List[Finding]:
        """
        Analyze individual file for phantom code patterns.
        
        Args:
            file_path: Path to Python file to analyze
            
        Returns:
            List of findings for this file
        """
        try:
            return self._safe_analyze_file(file_path)
        except Exception as e:
            logger.error(f"Error analyzing {file_path}: {e}")
            handle_analysis_error("file_analysis", "PhantomAICodeScanner", "_analyze_file", e)
            return []
    
    def _safe_analyze_file(self, file_path: Path) -> List[Finding]:
        """
        Safely analyze file with comprehensive error handling.
        
        Args:
            file_path: Path to Python file to analyze
            
        Returns:
            List of findings with graceful error handling
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse AST for analysis
            tree = ast.parse(content, filename=str(file_path))
            
            findings = []
            
            # Detect stub methods
            findings.extend(self._detect_stub_methods(tree, content, file_path))
            
            # Track symbols for dead code analysis
            self._track_symbols(tree, file_path)
            
            return findings
            
        except SyntaxError as e:
            # Python syntax errors - common with incomplete AI code
            return [self._create_syntax_error_finding(file_path, e)]
        except UnicodeDecodeError as e:
            # File encoding issues
            logger.warning(f"Cannot decode file {file_path}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error analyzing {file_path}: {e}")
            handle_analysis_error("safe_analysis", "PhantomAICodeScanner", "_safe_analyze_file", e)
            return []
    
    def _detect_stub_methods(self, tree: ast.AST, content: str, file_path: Path) -> List[Finding]:
        """
        Detect stub methods using AST analysis.
        
        Args:
            tree: Parsed AST
            content: File content for source extraction
            file_path: File being analyzed
            
        Returns:
            List of findings for stub methods
        """
        findings = []
        
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Only check public methods
                if node.name.startswith('_'):
                    continue
                
                # Extract method source code
                try:
                    method_source = ast.get_source_segment(content, node)
                    if not method_source:
                        continue
                    
                    # Check for stub patterns
                    stub_finding = self._analyze_method_for_stubs(
                        node, method_source, file_path
                    )
                    if stub_finding:
                        findings.append(stub_finding)
                        
                except Exception as e:
                    logger.warning(f"Could not extract source for method {node.name} in {file_path}: {e}")
                    # Create finding to alert user of analysis limitation
                    findings.append(self._create_analysis_limitation_finding(
                        file_path, f"Method analysis failed for '{node.name}': {e}"
                    ))
                    continue
        
        return findings
    
    def _analyze_method_for_stubs(self, node: ast.FunctionDef, method_source: str, 
                                 file_path: Path) -> Optional[Finding]:
        """
        Analyze individual method for stub patterns.
        
        Args:
            node: AST function definition node
            method_source: Source code of the method
            file_path: File containing the method
            
        Returns:
            Finding if method is a stub, None otherwise
        """
        # Split into lines and filter out comments/docstrings
        lines = [line.strip() for line in method_source.split('\n') if line.strip()]
        
        # Remove docstring lines. Toggle on the *count* of triple-quotes on
        # a line, not just on prefix presence — a single-line docstring like
        # ``"""Doc."""`` opens and closes on the same line, so a flat toggle
        # would flip ``in_docstring`` once and treat the rest of the method
        # as commentary.
        non_doc_lines = []
        in_docstring = False
        for line in lines:
            triple_double = line.count('"""')
            triple_single = line.count("'''")
            triple_count = triple_double + triple_single
            if triple_count == 0:
                if not in_docstring:
                    non_doc_lines.append(line)
                continue
            # Even count of triple-quotes on a line = balanced (single-line
            # docstring or two adjacent ones); state unchanged. Odd count =
            # the docstring opens or closes here; flip state.
            if triple_count % 2 == 1:
                in_docstring = not in_docstring
        
        # Check if method is mostly stub content
        for pattern in STUB_PATTERNS:
            if any(pattern in line for line in non_doc_lines):
                # Verify it's actually a stub (<=3 meaningful lines)
                if len(non_doc_lines) <= 3:
                    return self._create_stub_method_finding(
                        node, file_path, pattern, method_source
                    )
        
        return None
    
    def _track_symbols(self, tree: ast.AST, file_path: Path) -> None:
        """
        Track symbol definitions and usage for dead code analysis with memory limits.
        
        Args:
            tree: Parsed AST
            file_path: File being analyzed
        """
        # Check global file tracking limit to prevent memory exhaustion.
        # 2026-05-19 audit (silent-drop class): also bump scan-wide counter
        # so the summary line at end of scan() surfaces the coverage gap.
        if len(self._symbol_definitions) >= MAX_TRACKED_FILES:
            logger.warning(f"Symbol tracking limit reached ({MAX_TRACKED_FILES} files), skipping {file_path}")
            self._symbol_tracking_skipped += 1
            return
        
        # Check total symbol count across all files
        total_symbols = sum(len(symbols) for symbols in self._symbol_definitions.values())
        if total_symbols >= MAX_TOTAL_SYMBOLS:
            logger.warning(f"Total symbol limit reached ({MAX_TOTAL_SYMBOLS}), skipping {file_path}")
            self._symbol_tracking_skipped += 1
            return
        
        file_key = str(file_path.relative_to(self.project_path))
        symbols_in_file = 0
        
        # Track definitions with per-file limits
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if not node.name.startswith('_'):  # Only track public symbols
                    # Check per-file limit
                    if symbols_in_file >= MAX_SYMBOLS_PER_FILE:
                        logger.debug(f"Per-file symbol limit reached for {file_path}")
                        break
                        
                    self._symbol_definitions[file_key].append({
                        'name': node.name,
                        'type': type(node).__name__,
                        'line': node.lineno
                    })
                    symbols_in_file += 1
            
            # Track name usage (with reasonable limits)
            elif isinstance(node, ast.Name) and len(self._symbol_usage[file_key]) < 1000:
                self._symbol_usage[file_key].add(node.id)
            elif isinstance(node, ast.Attribute) and len(self._symbol_usage[file_key]) < 1000:
                self._symbol_usage[file_key].add(node.attr)
    
    def _analyze_dead_code(self) -> List[Finding]:
        """
        Analyze for dead/orphaned code across the project with optimized O(N) algorithm.
        
        Returns:
            List of findings for potentially dead code
        """
        potentially_dead = []
        
        # Create efficient lookup set of all used symbols (O(N) preprocessing)
        all_used_symbols = set()
        for used_names in self._symbol_usage.values():
            all_used_symbols.update(used_names)
        
        # Single pass through definitions to check usage (O(N) analysis)
        for file_path, symbols in self._symbol_definitions.items():
            for symbol in symbols:
                symbol_name = symbol['name']
                
                # Fast O(1) lookup instead of O(M) nested loop
                is_used = symbol_name in all_used_symbols
                
                # Skip special cases that are okay to be "unused"
                is_special = self._is_special_symbol(symbol_name, file_path)
                
                if not is_used and not is_special:
                    potentially_dead.append({
                        'file': file_path,
                        'symbol': symbol_name,
                        'type': symbol['type'],
                        'line': symbol['line']
                    })
        
        # Only create findings if dead code exceeds tolerance.
        # Sort deterministically so the truncated set is the same across
        # runs and across operating systems. Symbols defined in code,
        # functions before classes, lower line numbers first.
        findings = []
        if len(potentially_dead) > MAX_DEAD_CODE_TOLERANCE:
            type_priority = {'function': 0, 'class': 1, 'variable': 2}
            potentially_dead.sort(key=lambda d: (
                type_priority.get(d.get('type'), 3),
                d.get('file', ''),
                d.get('line', 0),
                d.get('symbol', ''),
            ))
            # 2026-05-19 audit (silent-drop class): record cap-truncated
            # findings so scan() can surface the undercount in its summary.
            self._dead_code_dropped += max(0, len(potentially_dead) - MAX_DEAD_CODE_REPORTS)
            for dead_item in potentially_dead[:MAX_DEAD_CODE_REPORTS]:
                findings.append(self._create_dead_code_finding(dead_item))
        
        return findings
    
    def _analyze_import_validity(self, python_files: List[Path]) -> List[Finding]:
        """
        Analyze import statements for validity and resolution.
        
        Args:
            python_files: List of Python files to analyze
            
        Returns:
            List of findings for broken imports
        """
        findings = []

        # 2026-05-19 audit (silent-drop class): files past the cap are
        # silently excluded from broken-import analysis. Track the drop
        # so scan() reports the gap in its end-of-scan summary.
        self._import_files_dropped += max(0, len(python_files) - MAX_IMPORT_CHECK_FILES)

        for file_path in python_files[:MAX_IMPORT_CHECK_FILES]:  # Configurable limit for performance
            try:
                findings.extend(self._check_file_imports(file_path))
            except Exception as e:
                logger.debug(f"Could not check imports in {file_path}: {e}")
                continue
        
        return findings
    
    def _check_file_imports(self, file_path: Path) -> List[Finding]:
        """
        Check imports in a specific file for validity.
        
        Args:
            file_path: Python file to check
            
        Returns:
            List of findings for broken imports in this file
        """
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if not self._can_import_module(alias.name):
                            findings.append(self._create_broken_import_finding(
                                file_path, alias.name, node.lineno
                            ))
                elif isinstance(node, ast.ImportFrom):
                    if node.module and not self._can_import_module(node.module):
                        findings.append(self._create_broken_import_finding(
                            file_path, node.module, node.lineno
                        ))
        
        except Exception as e:
            logger.warning(f"Error checking imports in {file_path}: {e}")
            # Create finding to alert user of analysis limitation
            findings.append(self._create_analysis_limitation_finding(
                file_path, f"Import analysis failed: {e}"
            ))
        
        return findings
    
    @staticmethod
    @lru_cache(maxsize=4096)
    def _module_resolves(module_name: str) -> bool:
        """Cached pure function — does this name resolve via importlib?

        Lifted out of the instance so the cache survives across files and
        across runs in the same process. ``find_spec`` walks ``sys.path``
        which can be expensive (filesystem reads per entry) and module
        names repeat across thousands of imports in a real codebase.

        We sanitize ``sys.path`` for the duration of the call: stripping
        empty-string and ``'.'`` entries (which Python prepends to mean
        "current working directory"). Without this, ``find_spec`` against
        a name that happens to exist as a directory in the scanned
        project will resolve and execute that project's package init,
        which is a side-effect surface we don't want when scanning
        untrusted code.
        """
        try:
            saved = list(sys.path)
            try:
                sys.path[:] = [p for p in sys.path if p not in ('', '.')]
                spec = importlib.util.find_spec(module_name)
                return spec is not None
            finally:
                sys.path[:] = saved
        except (ImportError, ValueError, ModuleNotFoundError):
            return False
        except Exception:
            # Circular import, syntax error in a parent package, etc. —
            # assume valid; safer than loading a potentially problematic
            # module just to confirm.
            return True

    def _can_import_module(self, module_name: str) -> bool:
        """Test if a module can be imported successfully (cached, sandboxed)."""
        # Skip relative imports and internal brass modules.
        if module_name.startswith('.') or module_name.startswith('brass.'):
            return True
        return self._module_resolves(module_name)
    
    def _is_special_symbol(self, symbol_name: str, file_path: str) -> bool:
        """
        Enhanced special case detection for symbols that are legitimately unused.
        
        Args:
            symbol_name: Name of the symbol to check
            file_path: Path of the file containing the symbol
            
        Returns:
            True if symbol is a legitimate special case (entry points, framework patterns, etc.)
        """
        # Standard entry points and main functions
        if symbol_name.lower() in ['main', '__main__', 'cli', 'run', 'app']:
            return True
        
        # Test methods and fixtures (common patterns)
        if symbol_name.startswith(('test_', 'fixture_', 'setUp', 'tearDown', 'pytest_')):
            return True
        
        # Framework and library patterns
        if any(framework in file_path.lower() for framework in ['views', 'models', 'admin', 'urls', 'settings']):
            return True
        
        # CLI command patterns
        if symbol_name.endswith(('_command', '_cmd')) or 'command' in symbol_name.lower():
            return True
        
        # Configuration and initialization patterns
        if symbol_name.lower() in ['config', 'configure', 'setup', 'initialize', 'init']:
            return True
        
        # Files that commonly have unused public functions
        if any(special_file in file_path.lower() for special_file in ['__init__', 'cli', 'main', 'setup']):
            return True
        
        return False
    
    def _create_analysis_limitation_finding(self, file_path: Path, issue_description: str) -> Finding:
        """
        Create Finding for analysis limitations that users should be aware of.
        
        Args:
            file_path: Path to the file with analysis issues
            issue_description: Description of what analysis failed
            
        Returns:
            Finding describing the analysis limitation
        """
        return Finding(
            id=f"phantom_limitation_{self._generate_id(file_path, issue_description)}",
            type=FindingType.ANALYSIS_ERROR,
            severity=Severity.LOW,
            file_path=str(file_path.relative_to(self.project_path)),
            line_number=None,
            title="Analysis Limitation",
            description=f"PhantomAICodeScanner encountered limitations analyzing this file: {issue_description}",
            confidence=0.8,
            impact_score=0.3,
            detected_by="PhantomAICodeScanner",
            remediation="Review file structure and syntax. Analysis may be incomplete for this file.",
            metadata={
                "analysis_issue": issue_description,
                "limitation_type": "partial_analysis",
                "ai_code_issue": False  # This is a scanner limitation, not AI code issue
            }
        )
    
    def _create_stub_method_finding(self, node: ast.FunctionDef, file_path: Path, 
                                   pattern: str, method_source: str) -> Finding:
        """Create Finding for stub method."""
        return Finding(
            id=f"phantom_stub_{self._generate_id(file_path, node.name)}",
            type=FindingType.CODE_QUALITY,
            severity=Severity.HIGH,
            file_path=str(file_path.relative_to(self.project_path)),
            line_number=node.lineno,
            title=f"Stub Method Detected: {node.name}",
            description=f"Method '{node.name}' contains only placeholder code ({pattern}) and may not be fully implemented",
            code_snippet=method_source.split('\n')[0] + "...",
            confidence=DEFAULT_CONFIDENCE,
            impact_score=0.8,
            detected_by="PhantomAICodeScanner",
            remediation=f"Implement the '{node.name}' method with actual functionality or remove if not needed",
            references=["https://docs.python.org/3/tutorial/controlflow.html#defining-functions"],
            metadata={
                "stub_pattern": pattern,
                "method_name": node.name,
                "is_async": isinstance(node, ast.AsyncFunctionDef),
                "ai_code_issue": True
            }
        )
    
    def _create_syntax_error_finding(self, file_path: Path, error: SyntaxError) -> Finding:
        """Create Finding for syntax error."""
        return Finding(
            id=f"phantom_syntax_{self._generate_id(file_path)}",
            type=FindingType.CODE_QUALITY,
            severity=Severity.CRITICAL,
            file_path=str(file_path.relative_to(self.project_path)),
            line_number=error.lineno,
            title="Syntax Error in AI-Generated Code",
            description=f"File contains syntax errors that prevent execution: {error.msg}",
            confidence=0.95,
            impact_score=0.9,
            detected_by="PhantomAICodeScanner",
            remediation="Fix syntax errors to ensure code can be executed",
            metadata={
                "syntax_error": str(error),
                "ai_code_issue": True
            }
        )
    
    def _create_dead_code_finding(self, dead_item: Dict) -> Finding:
        """Create Finding for potentially dead code."""
        return Finding(
            id=f"phantom_dead_{self._generate_id(Path(dead_item['file']), dead_item['symbol'])}",
            type=FindingType.CODE_QUALITY,
            severity=Severity.MEDIUM,
            file_path=dead_item['file'],
            line_number=dead_item['line'],
            title=f"Potentially Dead Code: {dead_item['symbol']}",
            description=f"{dead_item['type']} '{dead_item['symbol']}' appears to be unused and may be orphaned",
            confidence=0.7,  # Lower confidence as this can have false positives
            impact_score=0.5,
            detected_by="PhantomAICodeScanner",
            remediation=f"Review if '{dead_item['symbol']}' is actually needed, or remove if orphaned",
            metadata={
                "symbol_type": dead_item['type'],
                "symbol_name": dead_item['symbol'],
                "ai_code_issue": True
            }
        )
    
    def _create_broken_import_finding(self, file_path: Path, module_name: str,
                                     line_number: int) -> Finding:
        """Create Finding for broken import.

        Two distinct outcomes by top-level module name:

        1. **Hallucination candidate** (severity CRITICAL): the name isn't
           in `_WELL_KNOWN_PYPI_PACKAGES`, suggesting the AI may have
           invented a package that doesn't exist. This is the original
           phantom-detection use case.
        2. **Missing local dep** (severity LOW): the name matches a known
           popular PyPI package (`torch`, `transformers`, `boto3`, etc.).
           The dep exists on PyPI; the scanning Python environment just
           doesn't have it installed. Common on ML / cloud-deploy projects
           where deps live in the remote runtime (Modal, Lambda, Docker),
           not the dev machine. Reporting these as CRITICAL phantom
           imports floods the customer report with noise (covers the
           top-10-critical results on copper-sun's full-engine scan).

        The top-level segment is what we check (`numpy.linalg` → `numpy`),
        because the allowlist tracks distribution names not submodules.
        """
        top_level = module_name.split('.', 1)[0].lower()
        is_well_known = top_level in _WELL_KNOWN_PYPI_PACKAGES

        if is_well_known:
            severity = Severity.LOW
            title = f"Missing local dep: {module_name}"
            description = (
                f"Cannot import '{module_name}' in the scanning Python "
                f"environment, but '{top_level}' is a known PyPI package. "
                f"This is normally a dev-env setup issue (deps live in the "
                f"deploy runtime like Modal/Lambda/Docker, not locally), "
                f"NOT an AI-generated phantom import."
            )
            remediation = (
                f"Either install '{top_level}' in the scanning env "
                f"(pip install {top_level}) or — if intentional, e.g. "
                f"deploy-only dep — ignore. BrassCoders cannot tell the two "
                f"cases apart without venv context."
            )
            impact = 0.3
        else:
            severity = Severity.CRITICAL
            title = f"Broken Import: {module_name}"
            description = f"Cannot import module '{module_name}' - module may not exist or not be installed"
            remediation = f"Install missing module '{module_name}' or fix import statement"
            impact = 0.9

        return Finding(
            # Include line_number in the id so the same module imported at
            # multiple sites in the same file produces distinct findings
            # (not 3 records keyed under one id). Observed 2026-05-19: a
            # file imported `coppersun_brass.ml.pure_python_ml` at lines
            # 23, 250, and 356 — all three collapsed to one id because
            # `_generate_id(file_path, module_name)` ignored line.
            id=f"phantom_import_{self._generate_id(file_path, module_name)}_{line_number or 0}",
            type=FindingType.CODE_QUALITY,
            severity=severity,
            file_path=str(file_path.relative_to(self.project_path)),
            line_number=line_number,
            title=title,
            description=description,
            confidence=0.85,
            impact_score=impact,
            detected_by="PhantomAICodeScanner",
            remediation=remediation,
            metadata={
                "module_name": module_name,
                "top_level_module": top_level,
                "is_well_known_pypi": is_well_known,
                "ai_code_issue": True,
            },
        )
    
    def _create_analysis_error_finding(self, error_message: str) -> Finding:
        """Create Finding for analysis errors."""
        return Finding(
            id=f"phantom_error_{hashlib.md5(error_message.encode()).hexdigest()[:8]}",
            type=FindingType.ANALYSIS_ERROR,
            severity=Severity.LOW,
            file_path="analysis_error",
            title="PhantomAICodeScanner Analysis Error",
            description=f"Scanner encountered an error during analysis: {error_message}",
            confidence=0.5,
            impact_score=0.2,
            detected_by="PhantomAICodeScanner",
            remediation="Check scanner configuration and project structure",
            metadata={
                "error_type": "analysis_error",
                "scanner": "PhantomAICodeScanner"
            }
        )
    
    def _generate_id(self, file_path: Path, suffix: str = "") -> str:
        """Generate unique ID for findings."""
        path_str = str(file_path)
        if suffix:
            path_str += f"_{suffix}"
        return hashlib.md5(path_str.encode()).hexdigest()[:12]