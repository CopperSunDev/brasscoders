"""
SecretsScanner — real application-secret detection via detect-secrets (Yelp).

The privacy scanner detects PII (credit cards, SSNs, IBAN, phone numbers, etc.).
This scanner is the SECRETS counterpart: AWS / GCP / Slack / Stripe / GitHub /
JWT / PEM material. The two are complementary and both register findings as
``FindingType.SECURITY`` (secrets) and ``FindingType.PRIVACY`` (PII) respectively.

We use detect-secrets's plugin set rather than rolling our own regexes:
- Coverage is broader and battle-tested against the corpus Yelp publishes.
- New credential formats arrive via library upgrade, not custom code changes.
- Validation (where available) avoids false positives from encoded constants.

**Privacy invariant**: ``Finding.metadata`` never contains the raw secret. Only the
secret type, line number, and a short hash for de-duplication are persisted; this
matches the redaction policy applied to privacy findings (see
``Brass2PrivacyScanner._redact_pii_metadata``).
"""

import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Optional, Tuple

from brass.models.finding import Finding, FindingType, Severity
from brass.core.file_classifier import FileClassifier
from brass.core.logging_config import get_logger
from brass.core.path_safety import is_within


# Cap for the per-scan thread pool. detect-secrets is mostly Python regex which
# the GIL serializes, but file IO and several plugin paths release it; modest
# parallelism still cuts wall-clock time meaningfully on large projects.
# Hard ceiling avoids thrashing on machines with many cores.
_SECRETS_MAX_WORKERS = min(8, max(2, (os.cpu_count() or 4) - 1))
# Below this file-count, the thread-pool overhead outweighs the benefit; do
# the work serially in the main thread.
_PARALLEL_THRESHOLD = 50

# Module-level lock guarding ``default_settings()`` entry. detect-secrets's
# ``get_settings()`` is ``@lru_cache(maxsize=1)`` — a process-global
# singleton. Any concurrent entry into ``default_settings()`` (multiple
# SecretsScanner instances, a parallel-test runner, a future watcher
# loop, etc.) re-introduces the race the per-worker hoist fixed. Holding
# this lock for the duration of a scan keeps the global mutation
# serialized regardless of caller. The GIL-bound regex work inside
# default_settings() means the lock isn't a meaningful perf hit.
import threading as _threading
_DETECT_SECRETS_GLOBAL_LOCK = _threading.Lock()

logger = get_logger(__name__)


class _DetectSecretsNoiseFilter(logging.Filter):
    """Drop the ``No plugins to scan with!`` line from detect-secrets's logger.

    detect-secrets installs its own stderr handler (clearing the root logger's
    handlers in the process) with format ``[%(module)s]\\t%(levelname)s\\t%(message)s``.
    On a real scan, the per-file ``scan_file`` call sometimes fires before a
    given worker thread's plugin context is fully populated, producing one
    ``log.error('No plugins to scan with!')`` per affected file — 212 of them
    in a recent whisperx run. The plugin-context issue is benign (subsequent
    calls in the same thread succeed and produce real findings); the user-
    visible noise is not. Dropping just this one line keeps every other
    detect-secrets log intact so real errors still surface.
    """

    _NOISE_SUBSTRING = "No plugins to scan with"

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            return self._NOISE_SUBSTRING not in record.getMessage()
        except Exception:  # noqa: BLE001 - filtering must not raise
            return True


def _silence_detect_secrets_noise() -> None:
    """Attach :class:`_DetectSecretsNoiseFilter` to detect-secrets's logger
    AND its handler(s) so the filter survives most logging-config resets.

    Idempotent — safe to call from every SecretsScanner construction. We
    target the named logger ``'detect-secrets'`` (set in
    ``detect_secrets/core/log.py``) rather than the root logger so other
    libraries are unaffected.

    Why attach to handlers too: ``logging.config.dictConfig`` with
    ``disable_existing_loggers=True`` (Django/Flask near-default) wipes
    logger-level filters but leaves handlers alone if they were installed
    by a non-config-driven path. detect-secrets installs a StreamHandler
    directly on its logger; attaching the filter to that handler means
    even a config reset that drops the logger filter still suppresses the
    noise at the handler level.

    TODO(upstream): if detect-secrets demotes
    ``log.error('No plugins to scan with!')`` below ERROR level (or
    removes the message entirely), this workaround becomes dead code.
    Track at https://github.com/Yelp/detect-secrets — search for the
    string in their issue tracker before assuming the upstream fix
    landed.
    """
    target = logging.getLogger("detect-secrets")
    if not any(
        isinstance(f, _DetectSecretsNoiseFilter) for f in target.filters
    ):
        target.addFilter(_DetectSecretsNoiseFilter())
    # Also attach to any handlers detect-secrets installed directly on
    # this logger. New handlers added after this call won't have the
    # filter, but those would only appear via a customer's own logging
    # config — which would also have to bypass our logger-level filter
    # to leak noise to stderr.
    for handler in target.handlers:
        if not any(
            isinstance(f, _DetectSecretsNoiseFilter) for f in handler.filters
        ):
            handler.addFilter(_DetectSecretsNoiseFilter())


# detect-secrets plugin types -> severity. Anything that grants direct access to a
# cloud account or production system is CRITICAL; long-lived API keys are HIGH; the
# heuristic plugins (high-entropy / keyword) are MEDIUM because their false-positive
# rate is materially higher.
_SEVERITY_BY_TYPE = {
    'AWS Access Key': Severity.CRITICAL,
    'AWS Sensitive Information': Severity.HIGH,
    'Azure Storage Account access key': Severity.CRITICAL,
    'Cloudant Credentials': Severity.HIGH,
    'GitHub Token': Severity.CRITICAL,
    'GitLab Token': Severity.CRITICAL,
    'Slack Token': Severity.HIGH,
    'Stripe Access Key': Severity.CRITICAL,
    'Twilio API Key': Severity.HIGH,
    'IBM Cloud IAM Key': Severity.HIGH,
    'IBM COS HMAC Credentials': Severity.HIGH,
    'JSON Web Token': Severity.MEDIUM,
    'Mailchimp Access Key': Severity.HIGH,
    'NPM tokens': Severity.HIGH,
    'Private Key': Severity.CRITICAL,
    'PyPI upload token': Severity.CRITICAL,
    'SendGrid API Key': Severity.HIGH,
    'Square OAuth Secret': Severity.HIGH,
    'Twilio Account SID': Severity.MEDIUM,
    'Discord Bot Token': Severity.HIGH,
    'OpenAI Token': Severity.HIGH,
    'Telegram Bot Token': Severity.HIGH,
    'Hex High Entropy String': Severity.MEDIUM,
    'Base64 High Entropy String': Severity.MEDIUM,
    'Secret Keyword': Severity.MEDIUM,
    'Basic Auth Credentials': Severity.HIGH,
}


class SecretsScanner:
    """Detect application secrets using the detect-secrets plugin suite.

    Single responsibility: find leaked credentials in source files. Returns
    ``List[Finding]`` like every other BrassCoders scanner.
    """

    # File types worth scanning. We deliberately include things like .env / .yaml
    # that detect-secrets's keyword plugin handles well.
    SCAN_EXTENSIONS = frozenset({
        '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.kt', '.go', '.rb', '.rs',
        '.cs', '.cpp', '.c', '.h', '.php', '.swift', '.scala',
        '.yml', '.yaml', '.json', '.toml', '.ini', '.cfg', '.conf', '.properties',
        '.env', '.envrc', '.sh', '.bash', '.zsh', '.fish',
        '.md', '.txt', '.tf', '.tfvars',
    })

    MAX_FILE_SIZE_BYTES = 1024 * 1024  # Skip files >1MB; secrets shouldn't be there.

    def __init__(self, project_path: str):
        if not project_path:
            raise ValueError("project_path is required")
        self.project_path = Path(project_path).resolve()
        if not self.project_path.is_dir():
            raise ValueError(f"project_path must be a directory: {project_path}")
        self.file_classifier = FileClassifier(str(self.project_path))
        # Idempotently mute detect-secrets's per-file "No plugins to scan
        # with!" noise. See _silence_detect_secrets_noise for context.
        _silence_detect_secrets_noise()

    def scan(self, file_paths: Optional[List[str]] = None) -> List[Finding]:
        """Scan files for application secrets and return findings.

        Args:
            file_paths: When provided, scan exactly these paths. When ``None``,
                discover candidate files under ``project_path``.
        """
        try:
            from detect_secrets import SecretsCollection
            from detect_secrets.settings import default_settings
        except ImportError:
            logger.warning(
                "detect-secrets not installed; SecretsScanner is a no-op. "
                "Install with: pip install detect-secrets"
            )
            return []

        targets = self._resolve_targets(file_paths)
        if not targets:
            return []

        logger.info(
            f"SecretsScanner analyzing {len(targets)} files "
            f"(workers={_SECRETS_MAX_WORKERS if len(targets) >= _PARALLEL_THRESHOLD else 1})"
        )

        if len(targets) < _PARALLEL_THRESHOLD:
            # Serial path: small project, no gain from threading.
            # Lock guards against concurrent SecretsScanner instances
            # in the same process — see _DETECT_SECRETS_GLOBAL_LOCK.
            collection = SecretsCollection()
            with _DETECT_SECRETS_GLOBAL_LOCK, default_settings():
                for path in targets:
                    try:
                        collection.scan_file(str(path))
                    except Exception as exc:
                        logger.debug(f"SecretsScanner could not scan {path}: {exc}")
            secrets = list(collection)
        else:
            secrets = self._scan_in_parallel(targets, SecretsCollection, default_settings)

        findings: List[Finding] = [self._build_finding(secret, filename) for filename, secret in secrets]
        logger.info(f"SecretsScanner produced {len(findings)} findings")
        return findings

    def _scan_in_parallel(
        self,
        targets: List[Path],
        secrets_collection_cls,
        default_settings,
    ) -> List[Tuple[str, "object"]]:
        """Scan ``targets`` across a thread pool and merge the results.

        Each worker creates its own ``SecretsCollection`` and scans a chunk
        of files. Results are returned as ``(filename, PotentialSecret)``
        tuples. We use threads (not processes) because the
        ``PotentialSecret`` types don't pickle cleanly across processes on
        all platforms, and Python regex releases the GIL often enough that
        thread parallelism still yields a meaningful win on IO-heavy scans.

        CRITICAL: ``default_settings()`` MUST be entered exactly once,
        in the parent thread, NOT once per worker. detect-secrets's
        ``get_settings()`` is ``@lru_cache(maxsize=1)`` — a process-
        global singleton, not thread-local. Each ``default_settings()``
        enter mutates global plugin state, and the matching exit
        restores whatever it was before that enter. If two threads
        enter independently and one exits first, the global plugin
        list is wiped while the other thread is still mid-scan,
        producing "No plugins to scan with" misses that silently
        drop findings for whichever files happened to be scanned
        during the race window. Hoisting the context manager out of
        the worker eliminates the race entirely.
        """

        # Per-worker visibility threshold: warn on the first N failed
        # files (signal that a real plugin / IO issue is happening),
        # demote subsequent failures to debug (avoid log spam in
        # large repos where 200+ binary/large/permission-failed files
        # is normal noise). The summary count surfaces in the
        # caller via the returned dict.
        _PER_CHUNK_WARN_LIMIT = 5

        def _scan_chunk(chunk: List[Path]) -> Tuple[List[Tuple[str, "object"]], int]:
            # Parent thread already holds default_settings(); workers just
            # do scan_file calls against the (now stable) global Settings.
            local = secrets_collection_cls()
            failures = 0
            for path in chunk:
                try:
                    local.scan_file(str(path))
                except Exception as exc:
                    if failures < _PER_CHUNK_WARN_LIMIT:
                        logger.warning(
                            "SecretsScanner could not scan %s: %s", path, exc,
                        )
                    else:
                        logger.debug(
                            "SecretsScanner could not scan %s: %s", path, exc,
                        )
                    failures += 1
            return list(local), failures

        # Distribute files across workers in round-robin order so each chunk
        # has a similar mix of file sizes (more even runtime than range slicing).
        chunks: List[List[Path]] = [[] for _ in range(_SECRETS_MAX_WORKERS)]
        for i, path in enumerate(targets):
            chunks[i % _SECRETS_MAX_WORKERS].append(path)

        merged: List[Tuple[str, "object"]] = []
        total_failures = 0
        # Enter default_settings() ONCE in the parent; all worker threads
        # inherit the configured global plugin list. This single context
        # manager owns the global mutation and only restores on outer
        # exit (after all workers have finished). The module-level lock
        # additionally guards against concurrent SecretsScanner instances
        # (multiple parallel test workers, future watcher loops, etc.).
        with _DETECT_SECRETS_GLOBAL_LOCK, default_settings():
            with ThreadPoolExecutor(max_workers=_SECRETS_MAX_WORKERS) as pool:
                futures = [pool.submit(_scan_chunk, chunk) for chunk in chunks if chunk]
                for fut in as_completed(futures):
                    chunk_secrets, chunk_failures = fut.result()
                    merged.extend(chunk_secrets)
                    total_failures += chunk_failures
        if total_failures > 0:
            logger.info(
                "SecretsScanner: %d total file(s) failed to scan across all "
                "workers (first %d per worker were logged at WARNING level; "
                "rest at DEBUG). Common causes: binary files, encoding errors, "
                "permission denied.",
                total_failures, _PER_CHUNK_WARN_LIMIT,
            )
        return merged

    def _resolve_targets(self, file_paths: Optional[List[str]]) -> List[Path]:
        """Either honor the caller's file list or walk the project root."""
        if file_paths:
            return [Path(p) for p in file_paths if self._candidate_extension(Path(p))]

        targets: List[Path] = []
        for path in self.project_path.rglob('*'):
            if not path.is_file():
                continue
            if not is_within(path, self.project_path):
                continue
            if path.suffix.lower() not in self.SCAN_EXTENSIONS:
                continue
            try:
                if path.stat().st_size > self.MAX_FILE_SIZE_BYTES:
                    continue
            except OSError:
                continue
            if self.file_classifier.should_exclude_from_analysis(str(path)):
                continue
            targets.append(path)
        return targets

    def _candidate_extension(self, path: Path) -> bool:
        return path.suffix.lower() in self.SCAN_EXTENSIONS

    def _build_finding(self, secret, filename: str) -> Finding:
        """Translate a detect-secrets ``PotentialSecret`` into a BrassCoders ``Finding``.

        Crucially, ``secret.secret_value`` is NOT stored in metadata — only the type,
        line number, and a short hash. The redaction obligation here mirrors the
        privacy scanner: a finding that exists *because* something secret was found
        must not embed that thing in serialized output.
        """
        try:
            relative_path = str(Path(filename).resolve().relative_to(self.project_path))
        except (ValueError, OSError):
            relative_path = filename

        secret_type = getattr(secret, 'type', 'Unknown Secret')
        severity = _SEVERITY_BY_TYPE.get(secret_type, Severity.HIGH)
        secret_hash = getattr(secret, 'secret_hash', '') or ''
        line_number = getattr(secret, 'line_number', None)

        return Finding(
            # Include secret_type in the id so detect-secrets flagging the
            # SAME literal as TWO secret-types on the same line doesn't
            # produce duplicate-id-with-conflicting-severity records in
            # file_intelligence.yaml. Observed 2026-05-19 on coppersun_brass
            # where a single literal triggered both a CRITICAL Possible
            # GitHub Token AND a MEDIUM Possible Hex High Entropy String.
            id=f"secret_{(secret_type or 'unknown').replace(' ', '_').lower()}_{secret_hash[:12] or 'unknown'}_{line_number or 0}",
            type=FindingType.SECURITY,
            severity=severity,
            file_path=relative_path,
            line_number=line_number,
            title=f"Possible {secret_type}",
            description=(
                f"detect-secrets identified a candidate {secret_type} at "
                f"{relative_path}:{line_number}. Treat as a potential credential "
                "leak until the source line is reviewed."
            ),
            remediation=(
                "Confirm whether this value is a real credential. If yes: rotate "
                "it immediately, remove it from history, and load it from a "
                "secrets manager or environment variable. If no: add an inline "
                "`pragma: allowlist secret` comment so future scans skip it."
            ),
            confidence=0.85,
            impact_score=0.9,
            detected_by="SecretsScanner",
            metadata={
                'secret_type': secret_type,
                'secret_hash_prefix': secret_hash[:12],
                'detector': 'detect-secrets',
            },
        )
