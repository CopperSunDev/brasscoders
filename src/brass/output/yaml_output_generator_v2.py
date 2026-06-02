"""
YAMLOutputGenerator v2.0 - Refactored for Brass2 architectural compliance.

This is the refactored version following Brass2 principles:
- Single responsibility: orchestration only
- Clean separation of concerns: 7 focused builders
- Functions ≤20 lines, classes ≤200 lines, files ≤500 lines
- Zero breaking changes to existing YAML output format
"""

from collections import OrderedDict
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

from brass.models.finding import Finding, FindingType
from brass.core.logging_config import get_logger
from .yaml_builders import (
    YAMLMetadataBuilder,
    YAMLAIInstructionsBuilder,
    YAMLSecurityReportBuilder,
    YAMLPrivacyReportBuilder,
    YAMLDetailedAnalysisBuilder,
    YAMLStatisticsBuilder,
    YAMLFileIntelligenceBuilder,
    YAMLUtils
)

logger = get_logger(__name__)


class YAMLOutputGeneratorV2:
    """
    Refactored YAML output generator following Brass2 architectural principles.
    
    Orchestrates 7 focused builders to generate AI-optimized YAML intelligence files.
    Single responsibility: coordinate builders and manage file generation.
    
    Architectural compliance:
    - File size: <500 lines (vs 885 lines original)
    - Class size: <200 lines (vs 885 lines original)  
    - Function size: ≤20 lines (vs 19 violations original)
    - Clean separation of concerns
    """
    
    def __init__(self, project_path: str, output_dir: str = ".brass", ranker: Optional[Any] = None):
        """
        Initialize YAML generator with focused builders.
        
        Args:
            project_path: Root path of project being analyzed
            output_dir: Directory name for output files
            ranker: IntelligenceRanker for contextual risk assessment
        """
        self.project_path = Path(project_path).resolve()
        self.output_dir = self.project_path / output_dir
        self.generation_time = datetime.now()
        self.ranker = ranker
        
        # Initialize all builders once for reuse
        self.builders = self._create_builders()
        
        logger.info(f"YAML output generator v2.0 initialized for {self.project_path}")
    
    def _create_builders(self) -> Dict[str, Any]:
        """Create all focused builders for reuse across files."""
        return {
            'metadata': YAMLMetadataBuilder(str(self.project_path), self.generation_time),
            'ai_instructions': YAMLAIInstructionsBuilder(str(self.project_path), self.generation_time, self.ranker),
            'security_report': YAMLSecurityReportBuilder(str(self.project_path), self.generation_time),
            'privacy_report': YAMLPrivacyReportBuilder(str(self.project_path), self.generation_time),
            'detailed_analysis': YAMLDetailedAnalysisBuilder(str(self.project_path), self.generation_time),
            'statistics': YAMLStatisticsBuilder(str(self.project_path), self.generation_time),
            'file_intelligence': YAMLFileIntelligenceBuilder(str(self.project_path), self.generation_time)
        }
    
    def generate_intelligence(
        self,
        findings: List[Finding],
        *,
        scanner_status: Optional[Dict[str, "ScannerStatus"]] = None,
        scan_duration_seconds: Optional[float] = None,
        peak_memory_mb: Optional[float] = None,
    ) -> Dict[str, str]:
        """
        Generate complete YAML intelligence output using focused builders.

        Args:
            findings: Ranked findings from all scanners.
            scanner_status: Optional per-scanner status map (loose end #8).
                When provided, the statistics and ai_instructions builders
                surface skipped/errored scanners so AI consumers can tell
                "scanner ran clean" from "scanner silently failed."

        Returns:
            Dictionary mapping file names to file paths created
        """
        self._ensure_output_directory()
        generated_files = {}

        # Normalize Finding.file_path across all scanners before any
        # builder sees the data. Different scanners historically emit
        # different conventions: some return relative basenames (Pysa,
        # ast-grep, semgrep, privacy, secrets) while others return
        # absolute paths (Bandit/Pylint via subprocess output,
        # API security from raw rglob). Result without normalization:
        # the same file lands twice in file_intelligence.yaml under two
        # different keys (one absolute, one relative). Normalize here
        # as a single chokepoint so AI consumers see one consistent
        # form everywhere — and so future scanners that drift get
        # corrected automatically rather than introducing new duplicates.
        findings = self._normalize_finding_paths(findings)

        # Generate each YAML file using focused builders. Only the
        # statistics and ai_instructions builders receive scanner_status;
        # the others have no use for it and stay scanner-status-blind.
        generated_files.update(self._generate_ai_instructions(findings, scanner_status))
        generated_files.update(self._generate_detailed_analysis(findings))
        generated_files.update(self._generate_file_intelligence(findings))
        generated_files.update(self._generate_security_report(findings))
        generated_files.update(self._generate_privacy_report(findings))
        generated_files.update(self._generate_statistics(findings, scanner_status, scan_duration_seconds, peak_memory_mb))
        # Phase H (2026-05-17): operator_notes.yaml carries operator-
        # facing diagnostics (cache size, etc.) that previously lived
        # inside ai_instructions.yaml as `system_advisories`. Splitting
        # keeps ai_instructions.yaml strictly about the codebase under
        # review and gives operators a stable file to grep.
        generated_files.update(self._generate_operator_notes(findings))

        logger.info(f"Generated {len(generated_files)} YAML intelligence files")
        return generated_files
    
    def _normalize_finding_paths(self, findings: List[Finding]) -> List[Finding]:
        """Project-relative-ize every Finding.file_path that's absolute and
        lives under self.project_path.

        Resolves both the finding path AND project_path before computing
        the relative form. The resolve-both-sides step matters on macOS,
        where `/var/folders/...` symlink-resolves to `/private/var/...`:
        without resolution on the project side, relative_to() would
        ValueError on a path that's logically inside the project but has
        the resolved prefix.

        Paths that are already relative, fail to construct as Path, fail
        to resolve, or fall outside the project root are passed through
        unchanged. Failure modes never break output generation — the
        worst case is the original (un-normalized) path makes it into
        the YAML, which is the pre-fix behavior.
        """
        from dataclasses import replace as _replace
        try:
            project_resolved = self.project_path.resolve()
        except OSError:
            return findings
        normalized: List[Finding] = []
        for f in findings:
            try:
                p = Path(f.file_path)
            except (TypeError, ValueError):
                normalized.append(f)
                continue
            if not p.is_absolute():
                normalized.append(f)
                continue
            try:
                relativized = str(p.resolve().relative_to(project_resolved))
            except (ValueError, OSError):
                # Outside project root, or resolve failed — keep original.
                normalized.append(f)
                continue
            try:
                normalized.append(_replace(f, file_path=relativized))
            except (TypeError, AttributeError):
                # Non-dataclass Finding (fallback path); mutate in place.
                f.file_path = relativized
                normalized.append(f)
        return normalized

    def _ensure_output_directory(self) -> None:
        """Ensure output directory exists with owner-only perms.

        BrassCoders output contains analysis of private source code; .brass/ should not be
        world-readable. POSIX-only chmod, best-effort on Windows.

        Also writes a .gitignore inside the output directory so customers don't
        accidentally commit scan output (cache JSONs, finding YAMLs with file
        paths + line numbers) to their repos. The .gitignore itself is
        whitelisted so it travels with the repo and protects the directory
        on every clone — same pattern Next.js uses for `.next/.gitignore`.
        Observed 2026-05-26 in customer-flow N=3 (brass-seo): a fresh scan
        added ~250KB of YAML/JSON to the project root with no auto-ignore,
        which would have been committed by the next `git add .`.
        """
        self.output_dir.mkdir(exist_ok=True)
        # Idempotent: overwrite on every scan so a stale or hand-edited
        # .gitignore can't silently let scan output leak into git history.
        try:
            (self.output_dir / ".gitignore").write_text("*\n!.gitignore\n")
        except OSError as exc:
            logger.debug(f"Could not write .gitignore in {self.output_dir}: {exc}")
        try:
            import os
            import platform
            if platform.system() != 'Windows':
                os.chmod(self.output_dir, 0o700)
        except OSError as exc:
            logger.debug(f"Could not chmod 0700 on {self.output_dir}: {exc}")
    
    def _generate_ai_instructions(
        self,
        findings: List[Finding],
        scanner_status: Optional[Dict[str, "ScannerStatus"]] = None,
    ) -> Dict[str, str]:
        """Generate AI instructions YAML using focused builder."""
        return self._generate_file_with_builder(
            'ai_instructions', findings, 'ai_instructions.yaml',
            scanner_status=scanner_status,
        )
    
    def _generate_detailed_analysis(self, findings: List[Finding]) -> Dict[str, str]:
        """Generate detailed analysis YAML using focused builder."""
        return self._generate_file_with_builder(
            'detailed_analysis', findings, 'detailed_analysis.yaml'
        )
    
    def _generate_file_intelligence(self, findings: List[Finding]) -> Dict[str, str]:
        """Generate file intelligence YAML using focused builder."""
        return self._generate_file_with_builder(
            'file_intelligence', findings, 'file_intelligence.yaml'
        )
    
    def _generate_security_report(self, findings: List[Finding]) -> Dict[str, str]:
        """Generate security report YAML using focused builder."""
        return self._generate_file_with_builder(
            'security_report', findings, 'security_report.yaml'
        )
    
    def _generate_privacy_report(self, findings: List[Finding]) -> Dict[str, str]:
        """Generate privacy report YAML if privacy findings exist."""
        privacy_findings = [f for f in findings if f.type == FindingType.PRIVACY]
        if not privacy_findings:
            return {}
        
        return self._generate_file_with_builder(
            'privacy_report', privacy_findings, 'privacy_analysis.yaml'
        )
    
    def _generate_statistics(
        self,
        findings: List[Finding],
        scanner_status: Optional[Dict[str, "ScannerStatus"]] = None,
        scan_duration_seconds: Optional[float] = None,
        peak_memory_mb: Optional[float] = None,
    ) -> Dict[str, str]:
        """Generate statistics YAML using focused builder."""
        return self._generate_file_with_builder(
            'statistics', findings, 'statistics.yaml',
            scanner_status=scanner_status,
            scan_duration_seconds=scan_duration_seconds,
            peak_memory_mb=peak_memory_mb,
        )

    def _generate_operator_notes(self, findings: List[Finding]) -> Dict[str, str]:
        """Phase H (2026-05-17): operator-facing diagnostics that used
        to live inside ``ai_instructions.yaml`` as ``system_advisories``.

        Currently surfaces the cache-size advisory only; future operator
        notes (token-quota low, version stale, scanner soft-skipped a
        hard prereq) plug into the same file. Emitted ONLY when there's
        at least one advisory — empty operator_notes.yaml is noise.

        When there are no advisories this scan but a stale
        operator_notes.yaml exists from a prior scan, DELETE the stale
        file. Otherwise customers see a stale operator advisory ("cache
        is huge!") that no longer applies to the current state — worse
        than no file at all. Surfaced 2026-05-30 during Phase F.6
        of the LS launch when the file count was reported as "6 generated"
        while disk showed 7 files (the 7th being a stale operator_notes
        from an earlier scan).
        """
        # Use the AI instructions builder's existing advisory machinery
        # so the cache-size threshold logic doesn't fork.
        builder = self.builders['ai_instructions']
        try:
            advisories = builder._build_system_advisories()
        except Exception as exc:  # noqa: BLE001
            logger.warning("operator_notes: advisory build failed: %s", exc)
            return {}
        if not advisories:
            # Clean up any stale operator_notes.yaml so it doesn't
            # misrepresent current operator state.
            stale = self.output_dir / 'operator_notes.yaml'
            if stale.exists():
                try:
                    stale.unlink()
                    logger.info(
                        "operator_notes: removed stale file (no advisories this scan)"
                    )
                except OSError as exc:
                    # Non-fatal — log and continue. Worst case: stale
                    # file lingers for the customer to delete manually.
                    logger.warning(
                        "operator_notes: failed to remove stale file: %s", exc
                    )
            return {}
        try:
            metadata = self.builders['metadata'].build(findings)
            data = {
                'metadata': metadata,
                'system_advisories': advisories,
                'how_to_read_this_file': (
                    'Operator-facing diagnostics that previously lived '
                    'in ai_instructions.yaml. Each advisory carries '
                    '`level`, `code`, `title`, `summary`, `user_action` '
                    '(the human command), and `ai_action` (the relay '
                    'instruction for AI consumers).'
                ),
            }
            file_path = self.output_dir / 'operator_notes.yaml'
            YAMLUtils.write_yaml_file(file_path, data)
            return {'operator_notes': str(file_path)}
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to generate operator_notes.yaml: %s", exc)
            return {}
    
    def _generate_file_with_builder(
        self,
        builder_name: str,
        findings: List[Finding],
        filename: str,
        scanner_status: Optional[Dict[str, "ScannerStatus"]] = None,
        scan_duration_seconds: Optional[float] = None,
        peak_memory_mb: Optional[float] = None,
    ) -> Dict[str, str]:
        """
        Generate single YAML file using specified builder.

        Args:
            builder_name: Name of builder to use
            findings: Findings data for builder
            filename: Output filename
            scanner_status: Optional per-scanner status map; forwarded to
                builders that opted into the kwarg (currently statistics
                and ai_instructions). Builders that don't accept it just
                receive findings as before.
            scan_duration_seconds: Optional wall-clock of the full scan;
                forwarded to the statistics builder so it can emit real
                analysis_duration / files_per_second instead of nulls.

        Returns:
            Dictionary with generated file mapping
        """
        try:
            builder = self.builders[builder_name]
            metadata = self.builders['metadata'].build(findings)
            if builder_name == 'statistics':
                content = builder.build(
                    findings,
                    scanner_status=scanner_status,
                    scan_duration_seconds=scan_duration_seconds,
                    peak_memory_mb=peak_memory_mb,
                )
            elif scanner_status is not None and builder_name == 'ai_instructions':
                content = builder.build(findings, scanner_status=scanner_status)
            else:
                content = builder.build(findings)

            # AI-instructions-specific metadata enrichment. The AI
            # consumer reads only this file; operational context
            # (which scanners ran, cache state) that lives in other
            # surfaces (CLI footer, scanner_timings.json) is invisible
            # to them. We surface it here so an AI relay to the human
            # can include "Pysa ran, found N findings" or "your cache
            # is at X MB" without further plumbing.
            #
            # Wrapped in its own try/except so a helper-side bug
            # (TypeError from a refactor, etc.) only drops the
            # enrichment block — not the whole YAML write. The outer
            # `except Exception` would abort the file generation
            # otherwise, and the glossary's documented invariants
            # for `metadata` would break silently.
            if builder_name == 'ai_instructions':
                try:
                    # Truthy check (not `is not None`): an empty
                    # `scanner_status={}` shouldn't emit `scanners_run: []`
                    # — that contradicts the glossary's "clean scan
                    # lists everything" framing.
                    if scanner_status:
                        metadata['scanners_run'] = sorted(
                            name for name, status in scanner_status.items()
                            if getattr(status, 'status', None) == 'ok'
                        )
                    from brass.output.yaml_builders.ai_instructions_builder import (
                        YAMLAIInstructionsBuilder,
                    )
                    cache_state = YAMLAIInstructionsBuilder._compute_pysa_cache_state()
                    if cache_state is not None:
                        # Drop the internal byte-precise count; the AI
                        # consumer needs the human-readable MB number,
                        # not byte-level fidelity. OrderedDict preserves
                        # the emit order for stable YAML diffs.
                        metadata['pysa_cache'] = OrderedDict(
                            (k, v) for k, v in cache_state.items()
                            if k != 'size_bytes'
                        )
                except Exception as enrich_exc:  # noqa: BLE001
                    logger.warning(
                        "ai_instructions metadata enrichment skipped: %s",
                        enrich_exc,
                    )

            # Combine metadata with content
            data = {'metadata': metadata}
            data.update(content)
            
            # Write YAML file
            file_path = self.output_dir / filename
            YAMLUtils.write_yaml_file(file_path, data)
            
            return {builder_name: str(file_path)}
            
        except Exception as e:
            logger.error(f"Failed to generate {filename}: {e}")
            return {}