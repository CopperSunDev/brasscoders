"""
AI instructions builder for generating Claude Code optimized guidance.

Builds AI-specific instructions, executive summaries, and actionable guidance
for development intelligence. Single responsibility: AI coder assistance.
"""

from __future__ import annotations  # so `Dict[str, "ScannerStatus"]` resolves under get_type_hints()

import json
import os
import re
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
from collections import OrderedDict, defaultdict
from pathlib import Path

from brass.models.finding import Finding, FindingType, Severity
from .base_builder import BaseYAMLBuilder
from .yaml_utils import YAMLUtils
from .constants import FileTypes, Priorities, RiskLevels, TestIndicators, Messages

# Per-file size cap for code-snippet synthesis (Phase D). Skipping files
# bigger than this keeps memory bounded on minified bundles and generated
# code. Matches the conservative end of static-analysis tool defaults
# (semgrep's --max-target-bytes is 1MB).
_CODE_SNIPPET_MAX_FILE_BYTES = 1 * 1024 * 1024

# Phase G (2026-05-15): Top-N cap on `critical_issues:` in
# ai_instructions.yaml. The AI consumer gets the top N most important
# findings inline; the full list survives in detailed_analysis.yaml.
# Override via BRASS_AI_INSTRUCTIONS_MAX_FINDINGS env var. The default
# matches the typical Claude Code session budget — 50 findings × ~600
# bytes/each ≈ 30KB / ~7.5k tokens for critical_issues, leaving headroom
# for the preamble + executive_summary + ai_guidance + the remediations
# table.
_DEFAULT_CRITICAL_ISSUES_CAP = 50


def _typed_block_sort_key(f: 'Finding') -> Tuple[int, int]:
    """Sort key for typed-block cap selection. Lower = higher priority.

    Tier 1: CRITICAL severity ahead of HIGH (both are `is_critical()`
    True, but the cap-50 slice has to pick a winner).
    Tier 2: within CRITICAL, syntax-error findings ahead of others —
    a syntax error is ship-blocking (the file can't even be imported)
    so it outranks "hardcoded credential on a working file."
    Enrichment rank_score remains as final tie-breaker via Python's
    stable sort.

    Module-level so both `_build_typed_blocks_dict` and
    `_build_critical_issues_alias` can use it consistently. Drift
    between those two sort orders was the bug class fixed today.
    """
    sev = 0 if f.severity == Severity.CRITICAL else 1
    is_syntax = 0 if (f.title or '').startswith('Syntax Error') else 1
    return (sev, is_syntax)

# Phase H (2026-05-17): per-block typed-section caps. Each typed block
# (security_critical, code_quality_attention, architecture_concerns)
# gets its own top-N cap so a noisy single category can't crowd out
# the others. The legacy `critical_issues:` alias is the union of the
# blocks, still capped at the overall default for backwards-compat.
_DEFAULT_BLOCK_CAP = 50

# Phase H (2026-05-17): customer-facing cluster-size display cap.
# Cluster sizes >30 are visually meaningless (a sea of "104 sites") —
# we cap the display value and add an `expansion_hint:` field pointing
# to detailed_analysis.yaml for the actual count. The threshold matches
# the typical AI consumer's ability to act on a finding before the
# information becomes "go look elsewhere" anyway.
_CLUSTER_SIZE_DISPLAY_CAP = 30

# Phase H (2026-05-17): production_focus capacity. The AI consumer in
# "ship-the-PR" mode wants a pre-filtered short list of production-code
# items; the rest of the YAML is for triage. 25 leaves room for the
# block lists without ballooning the file.
_PRODUCTION_FOCUS_CAP = 25

# Phase H (2026-05-17): finding-history persistence path is relative to
# the project root's `.brass/` directory. Stores a {finding_id: ISO-8601
# timestamp} JSON map so cross-scan continuity lets the AI consumer see
# whether a finding is fresh or persistent.
_FINDING_HISTORY_FILENAME = "finding_history.json"


# Phase H (2026-05-17): heuristic category derivation. Used for the
# `executive_summary.findings_by_category` summary so an AI consumer
# learns the shape of issues without parsing 50 entries.
#
# Ordered list — first match wins, so put the more specific tokens
# before the generic ones. Token match is case-insensitive substring
# in the finding's title + description + detected_by combined string.
_CATEGORY_TOKEN_MAP: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("hardcoded_credential", (
        "hardcoded credential", "hardcoded password", "hardcoded secret",
        "hardcoded_password", "hardcoded_secret", "secret_redacted",
        "credential (value redacted)",
    )),
    ("sql_injection", ("sql injection", "sql_injection", "sql-injection")),
    ("path_traversal", ("path traversal", "path_traversal")),
    ("command_injection", (
        "command injection", "command_injection", "shell injection",
    )),
    ("xss", ("xss", "cross-site scripting", "cross_site_scripting")),
    ("weak_crypto", (
        "weak crypto", "weak_crypto", "md5", "sha1", "weak hash",
        "insecure hash",
    )),
    ("deserialization", (
        "deserialization", "pickle.loads", "yaml.load",
    )),
    ("phantom_import", ("broken import", "phantom_import", "phantom import")),
    ("phantom_stub", ("stub method", "phantom_stub")),
    ("phantom_syntax", ("syntax error", "phantom_syntax")),
    ("ai_coherence", ("coherence violation", "ai_coherence", "context coherence")),
    ("pii_email", ("email", "personal email")),
    ("pii_ssn", ("ssn", "social security")),
    ("pii_credit_card", ("credit card", "credit_card")),
    ("content_moderation", ("content moderation", "policy compliance")),
    ("todo", ("todo:", "fixme:", "xxx:", "hack:")),
)


class YAMLAIInstructionsBuilder(BaseYAMLBuilder):
    """
    Builds AI instructions YAML for Claude Code and similar assistants.
    
    Responsible for generating executive summaries, critical issues,
    categorized findings, AI guidance, and quick actions.
    """
    
    def __init__(self, project_path: str, generation_time, ranker: Optional[Any] = None):
        """Initialize with optional ranker for risk assessment."""
        super().__init__(project_path, generation_time)
        self.ranker = ranker
    
    def build(
        self,
        findings: List[Finding],
        *,
        scanner_status: Optional[Dict[str, "ScannerStatus"]] = None,
    ) -> Dict[str, Any]:
        """
        Build complete AI instructions YAML structure.

        Args:
            findings: All findings for AI analysis
            scanner_status: Optional per-scanner status map. When any
                scanner is skipped/errored, an `analysis_completeness`
                field is added inside `executive_summary` so the AI
                consumer can tell "0 findings in category X = clean
                code" from "0 findings = scanner silently failed."
                Omitted entirely when all scanners ran cleanly, to
                keep the clean-run output uncluttered.

        Returns:
            Complete AI instructions dictionary
        """
        # Pre-build the remediation lookup table so `_add_optional_fields`
        # can emit `remediation_ref` instead of inline remediation text.
        # Same-rule findings (e.g., 15 Bandit B324 sites, 228 secrets
        # findings) collapse onto a small number of unique strings,
        # which dedupes the bulk of file size on noisy projects.
        self._remediation_ref_by_text: Dict[str, str] = {}
        remediations_table = self._collect_remediations(findings)

        # Reset the per-call file-content cache used by code-snippet
        # synthesis (Phase D). Lives for the duration of one build()
        # so multiple findings on the same file read it once. ALWAYS
        # initialized here so `_read_file_lines` can rely on its
        # presence — no silent lazy-init fallback that would leak
        # stale content into a subsequent scan.
        self._file_content_cache: Dict[str, Optional[List[str]]] = {}
        # Project root is `self.project_path` already-resolved (per
        # BaseYAMLBuilder.__init__). Cache once per build so the
        # per-finding containment check doesn't re-resolve N times.
        self._resolved_project_root: Path = Path(self.project_path)
        # FileClassifier is lazy-initialized by _classify_via_file_classifier.
        # Reset here so a builder reused across multiple build() calls
        # against different projects doesn't carry a stale classifier
        # bound to the prior project_root.
        if hasattr(self, '_classifier'):
            del self._classifier

        # Phase F (2026-05-15): pre-compute cross-scanner overlap so
        # _add_optional_fields can attach `also_detected_by` per finding
        # in O(1). Bucketed by (file_path, line_number) — O(N) build,
        # O(N) emission, no per-finding scan over the full list.
        self._cross_scanner_overlap: Dict[Tuple[str, int, str], List[str]] = (
            self._compute_cross_scanner_overlap(findings)
        )

        # Phase G (2026-05-15): top-N cap. _build_critical_issues
        # slices to this cap; _build_executive_summary reads
        # `self._truncated_critical_count` to emit a
        # `truncated_findings_count` signal so AI consumers know
        # there are more findings in detailed_analysis.yaml.
        #
        # ORDERING CONTRACT: _build_critical_issues MUST be called
        # before _build_executive_summary, because the summary reads
        # the truncation count side-effect. Sentinel-None enforces:
        # any future refactor that emits summary before criticals
        # will hit an assertion in _build_executive_summary rather
        # than silently emit 0.
        self._critical_issues_cap = self._read_critical_issues_cap()
        self._truncated_critical_count = None  # set by _build_critical_issues
        # Phase H (2026-05-17): per-block truncation counts. Populated
        # by _build_typed_blocks; consumed by _build_executive_summary
        # to emit `truncated_findings_count_by_block` alongside the
        # legacy scalar count.
        self._truncated_by_block: Dict[str, int] = {}
        # 2026-05-21: surfaced-finding-ID set used by
        # `actionable_findings_by_category`. Sentinel None enforces
        # ordering: _build_executive_summary asserts the set has been
        # populated (i.e. typed_blocks + critical_issues_alias both
        # ran first) so a future refactor that reorders or skips
        # those calls hits a loud failure instead of silently emitting
        # an empty field.
        self._surfaced_finding_ids: Optional[set] = None

        # Phase H (2026-05-17): finding-history map (finding_id →
        # first_seen ISO timestamp). Loaded once per build, then each
        # finding's first_seen is looked up. Skipped silently when the
        # history file is unreadable — a missing history doesn't break
        # output generation.
        self._finding_history: Dict[str, str] = self._load_finding_history()
        self._finding_history_updates: Dict[str, str] = {}
        self._scan_timestamp_iso: str = self._current_scan_timestamp()

        # Build typed blocks FIRST. Each block is independently capped
        # (so a single noisy category can't starve the others); the
        # legacy `critical_issues:` alias is the union of the blocks,
        # still capped at the overall default for backwards-compat.
        typed_blocks = self._build_typed_blocks(findings)
        critical_issues = self._build_critical_issues_alias(findings, typed_blocks)

        # Collect the set of finding IDs that actually reach an AI-
        # consumer-visible surface (any typed block + the legacy
        # `critical_issues:` alias). `_build_executive_summary` reads
        # this to emit ``actionable_findings_by_category`` — the
        # filtered-to-surfaced counterpart of ``findings_by_category``.
        # Initialized to None in __init__ for sentinel-fail; populate
        # here as an empty set (zero findings, e.g. clean scan) or a
        # full ID set.
        surfaced: set = set()
        for block_entries in typed_blocks.values():
            for entry in block_entries:
                if isinstance(entry, dict) and entry.get('id'):
                    surfaced.add(entry['id'])
        for entry in critical_issues:
            if isinstance(entry, dict) and entry.get('id'):
                surfaced.add(entry['id'])
        self._surfaced_finding_ids = surfaced

        # Persist any new first_seen timestamps observed this scan so
        # the next scan can attribute findings as continuing/new.
        self._save_finding_history()

        result = OrderedDict([
            ('how_to_read_this_file', self._build_interpretation_guide()),
            ('executive_summary', self._build_executive_summary(findings, scanner_status)),
        ])
        # Phase H (2026-05-17): tool diagnostics now live in
        # operator_notes.yaml. Add a single-line pointer here so an AI
        # consumer reading only ai_instructions.yaml still learns the
        # operator-notes file exists when there's anything to relay.
        tool_health = self._build_tool_health_summary()
        if tool_health is not None:
            result['tool_health_summary'] = tool_health
        # Only emit the `remediations:` table when there's at least one
        # remediation to reference — keeps the clean-run YAML uncluttered.
        if remediations_table:
            result['remediations'] = remediations_table
        # Phase H (2026-05-17): typed blocks (security_critical /
        # code_quality_attention / architecture_concerns / other) are
        # the new primary surface. `critical_issues:` is kept as an
        # alias for backward-compat with consumers that haven't migrated.
        # Deprecation note tells migrators where to look.
        result['_deprecated_critical_issues_note'] = (
            "`critical_issues` is preserved as a backward-compat alias "
            "(union of security_critical + code_quality_attention + "
            "architecture_concerns + other, capped). New consumers "
            "should read the typed blocks directly — `critical_issues` "
            "will be removed in a future major version."
        )
        result['security_critical'] = typed_blocks['security_critical']
        result['code_quality_attention'] = typed_blocks['code_quality_attention']
        result['architecture_concerns'] = typed_blocks['architecture_concerns']
        result['other'] = typed_blocks['other']
        result['critical_issues'] = critical_issues
        # Phase H (2026-05-17): production-code-only pre-filtered view
        # for AI consumers in "ship-the-PR" mode.
        result['production_focus'] = self._build_production_focus(typed_blocks)
        result['ai_guidance'] = self._build_ai_guidance(findings)
        result['file_priorities'] = self._build_file_priorities(findings)
        result['quick_actions'] = self._build_quick_actions(findings)
        return result

    def _collect_remediations(self, findings: List[Finding]) -> OrderedDict:
        """Build the deterministic `remediations:` lookup table.

        Walks the findings that will actually appear in `critical_issues:`
        (the `is_critical()` subset), collects unique remediation
        strings, sorts them alphabetically for stable IDs across runs,
        and assigns ``rem_NNN`` keys. Side effect: populates
        ``self._remediation_ref_by_text`` so `_add_optional_fields`
        can look up a finding's ref id without re-iterating.

        Scoping to critical findings only avoids the orphan-ref
        problem: non-critical findings' remediation strings used to
        land in the table even though no entry in `critical_issues:`
        referenced them (the table is only emitted alongside
        critical_issues today).
        """
        # Strip whitespace before checking truthiness so a remediation
        # of "   " (whitespace-only) doesn't end up as a useless
        # rem_NNN: '   ' entry in the table. Also strips both sides on
        # the stored value to keep the table clean.
        unique_strings = sorted({
            f.remediation.strip() for f in findings
            if f.is_critical() and f.remediation and f.remediation.strip()
        })
        table: OrderedDict[str, str] = OrderedDict()
        for idx, text in enumerate(unique_strings, start=1):
            ref_id = f"rem_{idx:03d}"
            table[ref_id] = text
            self._remediation_ref_by_text[text] = ref_id
        return table

    def _compute_cross_scanner_overlap(
        self, findings: List[Finding],
    ) -> Dict[Tuple[str, int, str], List[str]]:
        """Fallback overlap computation for direct-call paths.

        The CLI pre-computes overlap BEFORE enrichment and stashes
        peer lists on each finding's metadata (see
        ``brass.output.cross_scanner_overlap.stash_overlap_on_metadata``).
        Findings flowing through the CLI path then have
        ``metadata['cross_scanner_overlap_peers']`` set; the builder's
        ``_add_optional_fields`` reads that directly.

        This per-build map is kept as a fallback for direct callers
        (unit tests that pass findings to the builder without going
        through the CLI). Delegates to the shared free function so
        the algorithm has one source of truth.
        """
        from brass.output.cross_scanner_overlap import compute_cross_scanner_overlap
        return compute_cross_scanner_overlap(findings)

    def _build_interpretation_guide(self) -> Dict[str, Any]:
        """Slim AI-consumer guide (Phase H, 2026-05-17).

        Previous versions ran to ~180 lines of prose explaining
        per-scanner characteristics + glossary. An AI consumer can
        parse the structured data natively; this version keeps only
        the essential pointers (triage rule + glossary that names new
        fields). Target: under 100 tokens of prose.
        """
        return OrderedDict([
            ('summary', (
                'Investigative signals — pattern matches worth a look. '
                'Triage with ACT / CLEAR per signal. Each finding carries '
                'a `false_positive_likelihood` heuristic and a `context` '
                'block with `is_production_code` — start there. Surface every '
                'critical/high finding to the user before applying your own '
                'judgment about relevance; the user decides what to dismiss.'
            )),
            ('triage_priority', [
                'Read `production_focus` first — pre-filtered to source code.',
                'Within that, prefer `false_positive_likelihood: LOW` items.',
                'Skip findings whose `context.is_production_code` is false '
                'unless they reflect a project-wide pattern.',
                "Honor `executive_summary.risk_level` and "
                "`executive_summary.recommendation` verbatim — do not "
                "downgrade brass's headline based on your own pruning.",
                'For every critical/high finding, name the file:line and the '
                'remediation. If you believe a finding is irrelevant given '
                'project context the user has but brass does not, say so '
                'explicitly — do not silently drop it from the report.',
            ]),
            ('do_not', [
                "Downgrade `risk_level: HIGH` to LOW because findings 'look "
                "like noise' — HIGH means at least one critical or "
                "high-confidence finding survived noise reduction + "
                "semantic dedup. Pass it through.",
                "Dismiss findings in a directory because your project memory "
                "says the code is 'shelved' or 'legacy' — `context.is_production_code` "
                "is FileClassifier's verdict on file role, not project status. "
                "Surface the finding with context; let the user decide whether "
                "to act.",
                "Mark a finding 'false positive' without reading the actual "
                "source line. `false_positive_likelihood` is a heuristic, not "
                "ground truth; verify before dismissing.",
                "Paraphrase `executive_summary.recommendation` into your own "
                "ordering. BrassCoders's recommendation is the prioritized action "
                "list from the rerank pass; quote it or pass it through.",
            ]),
            ('field_glossary', OrderedDict([
                ('context', 'file_type / is_production_code / priority_for_ai '
                           '— authoritative file-role from FileClassifier.'),
                ('remediation_ref', 'Pointer like rem_NNN into the top-level '
                                    '`remediations:` map.'),
                ('cluster_size', 'N similar findings collapsed by the '
                                 'semantic reranker. Display capped at 30; '
                                 'see `expansion_hint` for the true count.'),
                ('also_detected_by', 'Other scanners that flagged the same '
                                     '(file, line). Multi-scanner agreement '
                                     '= stronger signal.'),
                ('false_positive_likelihood', 'Heuristic LOW/MEDIUM/HIGH '
                                              'derived from confidence + '
                                              'production-code + scanner '
                                              'reputation. Not science — '
                                              'use as a triage hint, not '
                                              'as ground truth.'),
                ('first_seen', 'ISO timestamp from the first scan that '
                               'observed this finding id. Fresh-this-scan '
                               'and continuing-from-last-scan look different.'),
                ('code_snippet_omitted_reason', 'When present, the snippet '
                                                'was dropped to avoid '
                                                're-leaking a credential.'),
                ('production_focus', 'Pre-filtered top-25 production-code '
                                     'items across the typed blocks. AI '
                                     'consumers in "ship-the-PR" mode go '
                                     'here first.'),
                ('typed_blocks', 'security_critical / code_quality_attention '
                                 '/ architecture_concerns / other — each '
                                 'capped independently so a noisy category '
                                 'cannot crowd out the others.'),
                ('tool_health_summary', 'When present, see operator_notes.yaml '
                                        'for operator-facing diagnostics '
                                        '(cache size, version warnings, etc.).'),
                ('actionable_findings_by_category', 'Category counts restricted '
                                                    'to findings that actually '
                                                    'reach a typed block or the '
                                                    '`critical_issues:` alias '
                                                    '— the AI-consumer-visible '
                                                    'surface. Compare against '
                                                    '`findings_by_category` to '
                                                    'see which categories the '
                                                    'AI surface omitted: '
                                                    'non-critical severities '
                                                    'that don\'t route to a '
                                                    'typed block, plus any '
                                                    'long tail past the per-'
                                                    'block cap (see '
                                                    '`truncated_findings_count` '
                                                    'and detailed_analysis.yaml '
                                                    'for the rest).'),
            ])),
            ('learn_more', 'https://coppersun.dev/why-brass'),
        ])

    def _build_interpretation_guide_legacy(self) -> Dict[str, Any]:
        """Kept for reference — the full per-scanner guide. Not emitted
        in the current output (replaced by `_build_interpretation_guide`
        in Phase H, 2026-05-17). Reachable for tests that exercised
        the old shape if they need it.
        """
        return OrderedDict([
            ('summary', (
                'BrassCoders surfaced these as investigative signals — pattern '
                'matches worth a quick look. Each one is a real match in '
                'the source; your job is to decide whether it warrants '
                'action given the project context BrassCoders cannot see. '
                'Two outcomes per signal: ACT (fix or follow up) or '
                'CLEAR (reviewed, no action needed). Use INVESTIGATE '
                'only when you genuinely need more context.'
            )),
            ('triage_priority', [
                'Start with signals whose context.is_production_code is true.',
                'Within those, sort by your own judgment of severity given '
                'project context — not by BrassCoders severity/rank_score alone.',
                'Signals in test fixtures, build outputs, docs, and archived '
                'code can usually be CLEARED quickly unless they reflect a '
                'pattern worth fixing project-wide.',
            ]),
            ('scanner_characteristics', [
                OrderedDict([
                    ('scanner', 'JavaScriptTypeScriptScanner / hardcoded_password'),
                    ('fires_on', 'String literals assigned to credential-named '
                                 'identifiers (password, apiKey, jwt_secret, etc.) '
                                 'with non-placeholder values.'),
                    ('signal_caveats', 'None expected after the AST-context fix; '
                                       'report any unexpected matches.'),
                    ('triage_hint', 'If the value is process.env or a placeholder '
                                    'like "your_password_here", CLEAR.'),
                ]),
                OrderedDict([
                    ('scanner', 'Brass2PrivacyScanner (PII detectors)'),
                    ('fires_on', 'Regex matches for dashed SSN, email, IP, '
                                 'Aadhaar, phone, credit-card-shaped digit '
                                 'groups.'),
                    ('signal_caveats', 'Source code legitimately contains '
                                       'PII-shaped strings — IP literals in '
                                       'docs, API key prefixes that match '
                                       'Aadhaar regex, large numeric IDs. '
                                       'Pre-filtered: Stripe test cards, RFC '
                                       '5737 test IPs, RFC 1918 private IPs, '
                                       'loopback, sentinel test SSNs '
                                       '(000-00-0000, 123-45-6789, etc.), '
                                       'example.com / test.local / noreply '
                                       'emails, and Sentry-DSN content. '
                                       'NOT pre-filtered: most arbitrary '
                                       'numeric IDs in docs — CLEAR those '
                                       'as you see them.'),
                    ('triage_hint', 'Check the file_path. Signals in docs/, '
                                    '__tests__/, fixtures/ are almost always '
                                    'documented test data, not real PII leaks. '
                                    'Add a .brassignore entry if a pattern '
                                    'recurs in this codebase.'),
                ]),
                OrderedDict([
                    ('scanner', 'APISecurityScanner (input-validation patterns)'),
                    ('fires_on', 'Regex patterns suggesting XSS, SQL-injection, '
                                 'command-injection vectors.'),
                    ('signal_caveats', 'Documentation strings or JSDoc examples '
                                       'showing the vulnerable pattern as a '
                                       'counter-example (e.g. "do not do this: '
                                       'dangerouslySetInnerHTML={...}") match '
                                       'the detector even though the actual '
                                       'code is safe — CLEAR those.'),
                    ('triage_hint', 'Read the surrounding lines. If the match '
                                    'is in a comment or docstring describing '
                                    'the bad pattern, CLEAR.'),
                ]),
                OrderedDict([
                    ('scanner', 'ProfessionalCodeScanner (Bandit / Pylint hits)'),
                    ('fires_on', 'Established Python static-analysis rules.'),
                    ('signal_caveats', 'High-precision detectors; signals here '
                                       'usually warrant ACT.'),
                    ('triage_hint', 'Default to ACT unless you can point to '
                                    'specific evidence why this case is different.'),
                ]),
                OrderedDict([
                    ('scanner', 'ContentModerationScanner'),
                    ('fires_on', 'Language-model-flagged content in source / docs.'),
                    ('signal_caveats', 'Confidence below 0.85 is usually too '
                                       'speculative to ACT on — CLEAR by default.'),
                    ('triage_hint', 'Check confidence; ACT only on high-confidence '
                                    'signals in user-facing content.'),
                ]),
            ]),
            ('what_to_output', (
                'A checklist ordered by your own judgment of severity. For each '
                'ACT signal, propose a concrete fix. For each CLEAR signal, '
                'one sentence on why no action is needed so the pattern can be '
                'added to .brassignore if it recurs.'
            )),
            ('field_glossary', OrderedDict([
                ('context', (
                    'file_type / is_production_code / priority_for_ai — '
                    'authoritative file-role classification from FileClassifier. '
                    'Use this to triage; do not re-derive from the path.'
                )),
                ('remediation_ref', (
                    'Pointer like rem_NNN into the top-level `remediations:` '
                    'map. Many findings share the same remediation text; the '
                    'map is the source of truth.'
                )),
                ('code_snippet', (
                    "Inline 3-line excerpt (line ± 1) of the source at "
                    "file_path:line_number. Absent on hardcoded-secret / PII "
                    "findings to avoid re-leaking the redacted value. NOTE: "
                    "all `bandit` findings have their snippet cleared (the "
                    "secret-leak allowlist treats bandit wholesale to catch "
                    "B105/B106/B107), so 'bandit finding without code_snippet' "
                    "does NOT necessarily mean the issue is a secret — the "
                    "finding's title is the authoritative classifier."
                )),
                ('cluster_size', (
                    'When > 1: this surviving finding represents N similar '
                    'findings the semantic reranker clustered as duplicates '
                    'by SEMANTIC similarity (typically across DIFFERENT '
                    'file:line locations). A cluster_size of 15 means one '
                    'site stands in for 14 elsewhere. Absent on non-enriched '
                    'runs or unduplicated findings.'
                )),
                ('also_detected_by', (
                    'List of OTHER scanners that flagged the SAME '
                    '(file_path, line_number). Structural overlap at one '
                    'location — orthogonal to cluster_size. A finding can '
                    'carry both: cluster_size tells you about siblings '
                    'elsewhere, also_detected_by tells you which other rule '
                    'engines agreed HERE.'
                )),
                ('truncated_findings_count', (
                    'In executive_summary. When present, the `critical_issues:` '
                    'list was capped (default 50, override via '
                    'BRASS_AI_INSTRUCTIONS_MAX_FINDINGS env var). N more '
                    'findings of critical/high severity exist in '
                    'detailed_analysis.yaml. The count is over '
                    'critical-or-high findings only, not total_findings.'
                )),
                ('system_advisories', (
                    'Top-level array of operational signals — present only '
                    'when at least one advisory fires (clean runs omit the '
                    'section entirely). Each entry has `level` '
                    '(info / warning / critical), `code` '
                    '(machine-readable identifier like `cache_size_high`), '
                    '`title`, `summary`, `user_action` (the concrete '
                    'command for the human), and `ai_action` (explicit '
                    'instruction telling the AI consumer to relay this '
                    'to the user). Surface every advisory to the human; '
                    'the section was added specifically because customers '
                    'using brass through an AI assistant never see the '
                    'terminal output where these warnings normally live.'
                )),
                ('pysa_cache', (
                    'In metadata. Per-scan snapshot of brass Pysa cache '
                    'state at `~/.cache/brass/pysa-state/`: `size_mb` '
                    '(total disk), `entry_count` (per-project caches), '
                    'and `location` (the cache root path with `$HOME` '
                    'redacted to `~`). Always emitted so the AI consumer '
                    'can decide whether to mention disk usage to the user '
                    'without waiting for the >1 GB system_advisories '
                    'trigger. Below 100 MB is uninteresting; 100 MB - 1 GB '
                    'is fine for daily use; >1 GB triggers a warning-level '
                    'system_advisory and the corresponding `brasscoders cache '
                    'clear --include-typeshed` recommendation.'
                )),
                ('scanners_run', (
                    'In metadata. List of scanner names that completed '
                    'with `status: ok` for this scan. Cross-reference '
                    'with `executive_summary.analysis_completeness` '
                    '(present only when at least one scanner degraded) '
                    'to understand: clean scan = scanners_run lists '
                    'everything, no analysis_completeness section. '
                    'Use scanners_run when reasoning about whether a '
                    'finding category is absent because nothing matched '
                    'OR because the scanner didn\'t run.'
                )),
            ])),
            ('learn_more', 'https://coppersun.dev/why-brass'),
        ])
    
    def _build_executive_summary(
        self,
        findings: List[Finding],
        scanner_status: Optional[Dict[str, "ScannerStatus"]] = None,
    ) -> Dict[str, Any]:
        """Build executive summary with risk assessment.

        When scanner_status indicates any scanner was skipped/errored,
        adds an `analysis_completeness` field so the downstream AI knows
        the findings list is partial. Absent when all scanners ran ok —
        clean runs stay uncluttered.

        Phase H (2026-05-17):
          - `recommendation` is now a synthesized actionable priority
            list (referencing the top production-code findings +
            remediation refs) rather than a generic count.
          - `findings_by_category` summarizes the full findings list
            so an AI consumer can read the issue shape without parsing
            50 entries.
          - `truncated_findings_count_by_block` mirrors the legacy
            scalar `truncated_findings_count` with per-block detail.
        """
        stats = YAMLUtils.generate_summary_stats(findings)

        # Calculate risk level using ranker if available; recommendation
        # is now synthesized from the actual top findings regardless of
        # ranker availability so the output is actionable, not just a
        # severity count.
        if self.ranker and hasattr(self.ranker, 'calculate_contextual_risk_level'):
            risk_assessment = self.ranker.calculate_contextual_risk_level(findings)
            risk_level = risk_assessment['risk_level']
        else:
            risk_level, _ = self._fallback_risk_assessment(stats)
        recommendation = self._synthesize_recommendation(findings)

        summary = OrderedDict([
            ('risk_level', risk_level),
            ('recommendation', recommendation),
            ('total_findings', stats['total_findings']),
            ('files_analyzed', stats['files_analyzed']),
            ('average_confidence', round(stats['avg_confidence'], 3)),
            ('average_impact', round(stats['avg_impact'], 3)),
        ])

        # Phase H (2026-05-17): findings_by_category gives the AI
        # consumer the issue-shape distribution at a glance — a single
        # field summarizing the full findings list. Inside
        # executive_summary (not top-level) so the historical
        # "findings_by_category not at root" invariant is preserved.
        by_category = self._compute_findings_by_category(findings)
        if by_category:
            summary['findings_by_category'] = by_category

        # 2026-05-21: parallel `actionable_findings_by_category` — same
        # shape as ``findings_by_category`` but restricted to findings
        # that actually reach an AI-consumer-visible surface (typed
        # blocks + ``critical_issues:`` alias). Discovered on a
        # whisperx scan where 194 pii_email matches in docs/test
        # files dominated the legacy field even though zero reached
        # the typed blocks. Both fields emit when populated; the
        # legacy ``findings_by_category`` stays for audit completeness.
        #
        # ORDERING CONTRACT (mirrors `_truncated_critical_count`): the
        # set is initialized to ``None`` in ``build()``, populated
        # after `_build_typed_blocks` + `_build_critical_issues_alias`
        # ran. Sentinel-None means those producers were never called
        # this build — treat as "nothing surfaced" and omit the field
        # rather than emit a confusing zero count.
        surfaced_ids = self._surfaced_finding_ids
        if surfaced_ids:
            actionable = [f for f in findings if f.id in surfaced_ids]
            actionable_by_category = self._compute_findings_by_category(actionable)
            if actionable_by_category:
                summary['actionable_findings_by_category'] = actionable_by_category

        # Phase G (2026-05-15): when `critical_issues:` got capped to
        # top-N, surface the count of findings that didn't make it so
        # the AI consumer knows to consult detailed_analysis.yaml for
        # the long tail. Absent when no truncation happened —
        # clean-run output stays uncluttered.
        #
        # Sentinel None means _build_critical_issues_alias was never
        # called in this build(). Treat as 0 (defensive — when this
        # method is exercised standalone in unit tests, no truncation
        # context exists yet).
        truncated = getattr(self, '_truncated_critical_count', None)
        if truncated is not None and truncated > 0:
            summary['truncated_findings_count'] = truncated

        # Phase H (2026-05-17): per-block truncation detail. Only emit
        # when at least one block actually truncated — keeps clean-run
        # output uncluttered.
        per_block = getattr(self, '_truncated_by_block', None) or {}
        per_block_nonzero = {k: v for k, v in per_block.items() if v > 0}
        if per_block_nonzero:
            summary['truncated_findings_count_by_block'] = per_block_nonzero

        if scanner_status:
            completeness = self._build_analysis_completeness(scanner_status)
            if completeness is not None:
                summary['analysis_completeness'] = completeness

        return summary

    def _synthesize_recommendation(self, findings: List[Finding]) -> str:
        """Phase H (2026-05-17): produce an actionable priority sentence
        referencing the top 2-3 production-code findings + their
        remediation refs.

        Ranking rule: production-code first, then severity (critical >
        high > others), then impact_score descending. Picks the top
        2-3 and emits prose that names file + line + remediation_ref.

        Returns a short string suitable for direct relay to a human.
        Heuristic, not hand-curated: this is one synthesis pass, not a
        replacement for the ranker.
        """
        # Filter the findings worth surfacing: critical or high.
        priority_findings = [f for f in findings if f.is_critical()]
        if not priority_findings:
            return (
                "No critical or high-severity findings detected; "
                "review code-quality items in detailed_analysis.yaml "
                "at your discretion."
            )

        # Production-only subset for the actionable lead.
        production = [
            f for f in priority_findings
            if self._classify_via_file_classifier(f.file_path).get(
                'is_production_code'
            )
        ]
        if not production:
            test_count = len(priority_findings)
            return (
                f"No production-code security signals; review "
                f"{test_count} item{'s' if test_count != 1 else ''} in "
                f"test/fixture/docs files at your discretion."
            )

        ranked = sorted(
            production,
            key=lambda f: (
                0 if f.severity == Severity.CRITICAL else 1,
                -float(f.impact_score or 0.0),
            ),
        )
        # Diversify the top-3: prefer findings the recommendation hasn't
        # already mentioned by (file_path, title). Without this, three
        # near-identical findings on consecutive lines of the same file
        # (e.g. hardcoded credentials at lines 110/111/112 of one demo
        # file) dominate the recommendation prose, hiding the rest of
        # the project's critical issues from the AI consumer's first read.
        # 2026-05-19 YAML review caught this on a real coppersun_brass scan.
        # Two-pass greedy: first pass picks at most 1 per (file_path, title);
        # second pass backfills from the originally-ranked tail if we
        # didn't get 3.
        top: List["Finding"] = []
        seen_keys: set = set()
        for f in ranked:
            key = (f.file_path, (f.title or "").strip())
            if key in seen_keys:
                continue
            top.append(f)
            seen_keys.add(key)
            if len(top) == 3:
                break
        # Backfill if diversity was insufficient (e.g. only 1 unique
        # finding type exists in production). Preserves the rank-order
        # of any remaining slots so the prose stays priority-correct.
        if len(top) < 3:
            for f in ranked:
                if f in top:
                    continue
                top.append(f)
                if len(top) == 3:
                    break
        parts: List[str] = []
        for f in top:
            ref_map = getattr(self, '_remediation_ref_by_text', None) or {}
            ref_id = None
            if f.remediation:
                ref_id = ref_map.get(f.remediation.strip())
            ref_str = f" ({ref_id})" if ref_id else ""
            loc = f.file_path
            if f.line_number is not None:
                loc = f"{loc}:{f.line_number}"
            parts.append(
                f"{f.severity.value} {f.title.strip().rstrip('.')} at "
                f"{loc}{ref_str}"
            )
        return "Priority: " + "; then ".join(parts) + "."

    def _compute_findings_by_category(
        self, findings: List[Finding],
    ) -> "OrderedDict[str, int]":
        """Phase H (2026-05-17): category → count over the full findings
        list. Used inside `executive_summary` so an AI consumer learns
        the issue shape without parsing 50 entries.

        Category derivation uses `_derive_category` (heuristic token
        match against title + description + detected_by); falls back to
        `finding.type.value` when no manifest-style category matches.
        """
        counts: Dict[str, int] = defaultdict(int)
        for f in findings:
            counts[self._derive_category(f)] += 1
        # Sort by count descending so the largest categories come first.
        ordered = OrderedDict(
            sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
        )
        return ordered

    @staticmethod
    def _derive_category(finding: Finding) -> str:
        """Map a Finding to a manifest-style category string.

        Token-match heuristic against title + description + detected_by
        combined and lowercased. Falls back to `finding.type.value` for
        anything that doesn't match a known token list — that way new
        scanners get a coarse-but-correct categorization automatically.
        """
        haystack_parts: List[str] = []
        if finding.title:
            haystack_parts.append(finding.title)
        if finding.description:
            haystack_parts.append(finding.description)
        if finding.detected_by:
            haystack_parts.append(finding.detected_by)
        haystack = " ".join(haystack_parts).lower()
        for category, tokens in _CATEGORY_TOKEN_MAP:
            for tok in tokens:
                if tok in haystack:
                    return category
        return finding.type.value

    @staticmethod
    def _build_analysis_completeness(
        scanner_status: Dict[str, "ScannerStatus"],
    ) -> Optional[Dict[str, Any]]:
        """Return None when all scanners are ok (omit the field entirely).
        Otherwise return a structured summary the AI consumer can read to
        understand what categories of signal are missing.
        """
        degraded = [s for s in scanner_status.values() if s.is_degraded()]
        if not degraded:
            return None
        skipped = sum(1 for s in degraded if s.status == 'skipped')
        errored = sum(1 for s in degraded if s.status == 'errored')
        parts = []
        if skipped:
            parts.append(f"{skipped} scanner{'s' if skipped != 1 else ''} skipped")
        if errored:
            parts.append(f"{errored} scanner{'s' if errored != 1 else ''} errored")
        note = (
            " and ".join(parts)
            + " — findings may be incomplete in the affected categories"
        )
        # Stable ordering: errored first (more urgent), then skipped, then by name.
        status_rank = {'errored': 0, 'skipped': 1}
        degraded.sort(key=lambda s: (status_rank.get(s.status, 9), s.name))
        return OrderedDict([
            ('status', 'partial'),
            ('note', note),
            ('degraded', [
                OrderedDict([(s.name, s.reason)]) for s in degraded
            ]),
        ])
    
    def _fallback_risk_assessment(self, stats: Dict[str, Any]) -> tuple:
        """Provide fallback risk assessment when ranker unavailable."""
        critical_count = stats['by_severity'].get('critical', 0)
        high_count = stats['by_severity'].get('high', 0)
        
        if critical_count > 0 or high_count >= 5:
            return RiskLevels.HIGH, Messages.IMMEDIATE_ATTENTION
        elif high_count > 0 or stats['total_findings'] >= 10:
            return RiskLevels.MEDIUM, Messages.REVIEW_KEY_ISSUES
        else:
            return RiskLevels.LOW, Messages.MONITOR_PRACTICES
    
    # Cache-size advisory threshold. Matches the CLI footer's 1 GB
    # warning tier (`brass_cli.py:_print_cache_footer`). Anything below
    # this floor isn't surfaced into the YAML — the CLI footer alone
    # is enough signal for terminal-only users; for AI-assistant users
    # (the audience that needs the YAML version), 1 GB is the point
    # where the customer would meaningfully benefit from being told to
    # run `brasscoders cache clear`.
    _CACHE_ADVISORY_THRESHOLD_BYTES = 1024 ** 3  # 1 GB

    def _build_system_advisories(self) -> List[Dict[str, Any]]:
        """Operational signals for AI consumers of ``ai_instructions.yaml``.

        Customers running brass through Claude Code, Cursor, etc. see
        only the YAML output — the CLI footer's terminal warnings
        never reach them. Each advisory carries explicit ``user_action``
        + ``ai_action`` fields so the AI knows exactly what to relay
        to the human user.

        Currently emits at most one advisory:
          - **cache_size_high**: when the Pysa per-project cache root
            exceeds 1 GB, recommend ``brasscoders cache clear``.

        Future advisories (token-quota low, brass version stale,
        scanner soft-skipped a hard prereq, etc.) plug into the same
        list. Empty list → caller omits the section entirely.
        """
        advisories: List[Dict[str, Any]] = []
        cache_advisory = self._cache_size_advisory()
        if cache_advisory is not None:
            advisories.append(cache_advisory)
        return advisories

    @staticmethod
    def _compute_pysa_cache_state(
        early_exit_at_bytes: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        """Snapshot brass's Pysa cache root: size + entry count + path.

        Returns an OrderedDict suitable for embedding in metadata, or
        None if the cache hasn't been created yet. Best-effort:
        filesystem errors swallow silently so the metadata block never
        breaks the YAML write. ``$HOME`` is redacted to ``~`` so YAMLs
        committed to repos don't leak unix usernames.

        ``early_exit_at_bytes``: if set, the size walk stops once
        ``total_bytes`` crosses that floor. Used by ``_cache_size_advisory``
        which only needs "≥ threshold" — the always-emit metadata
        block passes ``None`` for the exact number.

        Used by BOTH ``_cache_size_advisory`` (the >1 GB action signal)
        and the metadata-section enrichment (always-emit number).
        Single source of truth for the size accounting matches the
        CLI footer's ``_dir_size`` block-aligned (``st_blocks * 512``)
        approach so all three surfaces report the same number.
        """
        try:
            from brass.scanners.pysa_taint_scanner import PysaTaintScanner
            cache_root = PysaTaintScanner._resolved_cache_root()
            if not cache_root.exists():
                return None
            total_bytes = 0
            for dirpath, _dirs, files in os.walk(cache_root, followlinks=False):
                for fname in files:
                    try:
                        st = os.stat(os.path.join(dirpath, fname))
                    except OSError:
                        continue
                    blocks = getattr(st, 'st_blocks', None)
                    total_bytes += (
                        blocks * 512 if blocks is not None else st.st_size
                    )
                if (
                    early_exit_at_bytes is not None
                    and total_bytes >= early_exit_at_bytes
                ):
                    break
            entry_count = sum(
                1 for entry in cache_root.iterdir()
                if entry.is_dir() and not entry.name.startswith('.')
            )
            # Redact $HOME → ~ for repo-committed-YAML privacy.
            # Best-effort: if Path.home() is unset / mismatched the
            # prefix won't match and the full path leaks — that's the
            # advertised behavior, customer-overridden cache roots
            # (BRASS_PYSA_CACHE_ROOT) outside $HOME are the user's
            # call.
            displayed_root = str(cache_root)
            home_str = str(Path.home())
            if displayed_root.startswith(home_str):
                displayed_root = "~" + displayed_root[len(home_str):]
            return OrderedDict([
                ('size_mb', round(total_bytes / (1024 * 1024), 1)),
                ('size_bytes', total_bytes),
                ('entry_count', entry_count),
                ('location', displayed_root),
            ])
        except (OSError, AttributeError, ImportError):
            import logging
            logging.getLogger(__name__).debug(
                "pysa cache state computation suppressed", exc_info=True,
            )
            return None

    @staticmethod
    def _cache_size_advisory() -> Optional[Dict[str, Any]]:
        """Return a structured advisory dict when cache > 1 GB, else None.

        Delegates the size accounting to ``_compute_pysa_cache_state``
        so the advisory and the metadata-section ``pysa_cache`` field
        share one source of truth. The threshold filter is the only
        thing this method adds on top of the state snapshot.
        """
        threshold = (
            YAMLAIInstructionsBuilder._CACHE_ADVISORY_THRESHOLD_BYTES
        )
        # Pass `early_exit_at_bytes=threshold` so the walk stops once
        # we've confirmed the floor; this keeps the advisory's check
        # bounded even on multi-GB caches where the always-emit
        # metadata path needs the full sum.
        state = YAMLAIInstructionsBuilder._compute_pysa_cache_state(
            early_exit_at_bytes=threshold,
        )
        if state is None:
            return None
        if state['size_bytes'] < threshold:
            return None
        size_gb = state['size_bytes'] / (1024 ** 3)
        return OrderedDict([
            ('level', 'warning'),
            ('code', 'cache_size_high'),
            ('title', f"BrassCoders analysis cache is {size_gb:.1f}+ GB"),
            ('summary', (
                f"BrassCoders's Pysa analysis cache at "
                f"{state['location']} now holds {state['entry_count']} "
                f"project caches and exceeds {size_gb:.1f} GB. This is "
                f"normal for long-running multi-project use but the "
                f"disk can be reclaimed without losing scan results."
            )),
            ('user_action', (
                "Run `brasscoders cache clear --include-typeshed` to free "
                "disk space. (`--include-typeshed` adds ~33 MB to the "
                "freed total. The next online scan auto-refetches it; "
                "scans run with `--offline` will skip the Pysa scanner.)"
            )),
            ('ai_action', (
                "Surface this advisory to the user — they may not see "
                "the brass scan terminal output. Suggest the "
                "`brasscoders cache clear` command."
            )),
        ])

    def _finding_history_path(self) -> Path:
        """Phase H (2026-05-17): location of the cross-scan first_seen
        cache. Lives next to the YAML outputs in `.brass/`, owner-only
        chmod is inherited from the parent directory's mkdir.
        """
        return Path(self.project_path) / ".brass" / _FINDING_HISTORY_FILENAME

    def _load_finding_history(self) -> Dict[str, str]:
        """Phase H (2026-05-17): load the {finding_id: first_seen_iso}
        map persisted by the previous scan. Returns an empty dict on
        any failure (missing file, malformed JSON, IO error) — a broken
        history file degrades gracefully into "every finding is fresh".
        """
        path = self._finding_history_path()
        if not path.is_file():
            return {}
        try:
            raw = path.read_text(encoding='utf-8')
            data = json.loads(raw)
        except (OSError, ValueError):
            return {}
        if not isinstance(data, dict):
            return {}
        # Defensive: only retain string→string entries; drop anything
        # malformed without crashing the build.
        return {
            str(k): str(v) for k, v in data.items()
            if isinstance(k, str) and isinstance(v, str)
        }

    def _save_finding_history(self) -> None:
        """Phase H (2026-05-17): persist new first_seen timestamps so
        the next scan can attribute findings as continuing rather than
        fresh.

        Merges any updates accumulated in `_finding_history_updates`
        into the on-disk map. Failure is silent — the field is still
        emitted in YAML even if persistence fails, so the worst-case
        scenario is that the next scan treats some continuing findings
        as fresh (graceful degradation).
        """
        updates = getattr(self, '_finding_history_updates', None) or {}
        if not updates:
            return
        merged = dict(self._finding_history)
        merged.update(updates)
        path = self._finding_history_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(merged, sort_keys=True, indent=2),
                encoding='utf-8',
            )
        except OSError:
            # Silent: the in-memory map still drove this scan's output;
            # next scan will simply re-create new IDs as fresh.
            pass

    def _current_scan_timestamp(self) -> str:
        """ISO-8601 timestamp (UTC, second precision) used as the
        first_seen value for findings encountered for the first time.

        Routed through ``self.generation_time`` when available so all
        findings in a single build share one timestamp — the AI
        consumer reading the YAML sees a coherent scan moment, not
        per-finding clock drift.
        """
        gen = getattr(self, 'generation_time', None)
        if isinstance(gen, datetime):
            try:
                return gen.replace(microsecond=0).isoformat()
            except (ValueError, TypeError):
                pass
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    @staticmethod
    def _read_critical_issues_cap() -> int:
        """Resolve the top-N cap for `critical_issues:` from env or default.

        Honors `BRASS_AI_INSTRUCTIONS_MAX_FINDINGS` (positive int).
        Invalid values fall back to the default — never crash on bad
        env config.
        """
        import os
        raw = os.environ.get('BRASS_AI_INSTRUCTIONS_MAX_FINDINGS')
        if not raw:
            return _DEFAULT_CRITICAL_ISSUES_CAP
        try:
            value = int(raw)
            if value > 0:
                return value
        except ValueError:
            pass
        return _DEFAULT_CRITICAL_ISSUES_CAP

    # Block routing rule (Phase H, 2026-05-17). Source of truth for
    # which FindingType goes into which typed block. Kept as a class
    # attribute so tests can inspect / override if needed.
    _BLOCK_FOR_TYPE: Dict[FindingType, str] = {
        FindingType.SECURITY: 'security_critical',
        FindingType.PRIVACY: 'security_critical',
        FindingType.CODE_QUALITY: 'code_quality_attention',
        FindingType.TODO: 'code_quality_attention',
        FindingType.ARCHITECTURE: 'architecture_concerns',
        FindingType.PERFORMANCE: 'architecture_concerns',
    }
    _BLOCK_NAMES: Tuple[str, ...] = (
        'security_critical',
        'code_quality_attention',
        'architecture_concerns',
        'other',
    )

    def _build_typed_blocks(
        self, findings: List[Finding],
    ) -> "OrderedDict[str, List[Dict[str, Any]]]":
        """Phase H (2026-05-17): partition critical/high findings into
        four typed blocks, each independently capped.

        Routing:
          - SECURITY / PRIVACY → security_critical
          - CODE_QUALITY / TODO → code_quality_attention
          - ARCHITECTURE / PERFORMANCE → architecture_concerns
          - everything else (ANALYSIS_ERROR, etc.) → other

        Each block gets its own cap (_DEFAULT_BLOCK_CAP, override via
        the same BRASS_AI_INSTRUCTIONS_MAX_FINDINGS env var) so a single
        noisy category can't crowd out the others. The dropped-count
        for each block is recorded in `self._truncated_by_block` for
        executive_summary emission.
        """
        cap = getattr(self, '_critical_issues_cap', _DEFAULT_BLOCK_CAP)
        buckets: Dict[str, List[Finding]] = {name: [] for name in self._BLOCK_NAMES}
        for f in findings:
            if not f.is_critical():
                continue
            block = self._BLOCK_FOR_TYPE.get(f.type, 'other')
            buckets[block].append(f)
        # Within each bucket, prioritize before applying the cap.
        # Sort key (lower = higher priority, stable for enrichment
        # rank_score tiebreak):
        #   1. CRITICAL severity ahead of HIGH (observed 2026-05-19 on
        #      coppersun_brass: a code_quality_attention block crowded
        #      with HIGH-severity ContentModerationScanner findings pushed
        #      CRITICAL syntax errors past the cap).
        #   2. Within CRITICAL: syntax-error findings ahead of others.
        #      A "Syntax Error in AI-Generated Code" finding is ship-
        #      blocking — the file can't even be imported — so it should
        #      never be dropped while less-fatal CRITICAL findings (e.g.
        #      hardcoded credentials on a working file) take the slot.
        #      Observed same scan: 2 of 4 broken-file syntax errors
        #      landed past cap-50 in a fully-CRITICAL block.
        out: "OrderedDict[str, List[Dict[str, Any]]]" = OrderedDict()
        self._truncated_by_block = {}
        for name in self._BLOCK_NAMES:
            block_findings = sorted(buckets[name], key=_typed_block_sort_key)
            dropped = max(0, len(block_findings) - cap)
            self._truncated_by_block[name] = dropped
            selected = block_findings[:cap]
            entries = [self._build_finding_data(f) for f in selected]
            # Phase H: if any items were truncated from this block,
            # append a `next_after_truncation` pointer as the final
            # synthetic entry so the AI consumer doesn't miss the long
            # tail in detailed_analysis.yaml. Synthetic entries carry
            # only `_next_after_truncation` so consumers iterating the
            # block can detect the pointer by key.
            if dropped > 0:
                entries.append(OrderedDict([
                    ('_next_after_truncation', (
                        f"{dropped} additional findings beyond the top "
                        f"{cap} are listed in detailed_analysis.yaml "
                        f"ranked by importance."
                    )),
                ]))
            out[name] = entries
        return out

    def _build_critical_issues_alias(
        self,
        findings: List[Finding],
        typed_blocks: "OrderedDict[str, List[Dict[str, Any]]]",
    ) -> List[Dict[str, Any]]:
        """Build the legacy `critical_issues:` alias as the union of
        the typed blocks, capped at the overall default for
        backwards-compat with existing consumers.

        NOTE on "critical": `Finding.is_critical()` returns True for
        BOTH `Severity.CRITICAL` and `Severity.HIGH`. The section is
        therefore "top-priority issues" rather than strictly CRITICAL
        only. The section name `critical_issues:` is preserved for
        backwards compatibility with consumers; new code should read
        the typed blocks directly.

        Findings arrive in priority order: post-enrichment rank_score
        descending for enriched scans, post-IntelligenceRanker order
        otherwise. The first N of the critical subset are therefore
        already the highest-priority ones; slicing [:N] preserves that
        order.

        Truncation is signaled via `executive_summary.truncated_findings_count`
        so an AI consumer knows there are more findings in
        `detailed_analysis.yaml`.

        Override the cap via `BRASS_AI_INSTRUCTIONS_MAX_FINDINGS` env
        var. Default is 50.
        """
        critical_findings = [f for f in findings if f.is_critical()]
        cap = getattr(self, '_critical_issues_cap', _DEFAULT_CRITICAL_ISSUES_CAP)
        # Cap audit (2026-05-19): the legacy `critical_issues:` alias had
        # the same bug class as the typed-block cap fixed earlier today —
        # `is_critical()` is True for both CRITICAL and HIGH, so the
        # `[:cap]` slice in input order let HIGH-severity findings
        # crowd out CRITICAL ones when enrichment rank_score put them
        # ahead. Apply the same severity-first + syntax-error-priority
        # sort here so the alias agrees with the typed blocks on which
        # 50 findings made the cut.
        critical_findings = sorted(critical_findings, key=_typed_block_sort_key)
        truncated = max(0, len(critical_findings) - cap)
        self._truncated_critical_count = truncated
        selected = critical_findings[:cap]
        # Re-use _build_finding_data so the alias entries share the
        # same shape (context block, code_snippet handling, etc.) as
        # the typed-block entries. This double-pass is acceptable —
        # the cap keeps work bounded.
        return [self._build_finding_data(finding) for finding in selected]

    def _build_production_focus(
        self,
        typed_blocks: "OrderedDict[str, List[Dict[str, Any]]]",
    ) -> List[Dict[str, Any]]:
        """Phase H (2026-05-17): pre-filtered production-code subset of
        security_critical + code_quality_attention + architecture_concerns
        for AI consumers in "ship-the-PR" mode. Capped at 25.

        Drops the synthetic `_next_after_truncation` pointer entries
        from the source blocks — those are display hints, not findings
        the AI consumer can act on directly.
        """
        focus: List[Dict[str, Any]] = []
        source_blocks = ('security_critical', 'code_quality_attention',
                         'architecture_concerns')
        for block_name in source_blocks:
            for entry in typed_blocks.get(block_name, []):
                if '_next_after_truncation' in entry:
                    continue
                ctx = entry.get('context') or {}
                if ctx.get('is_production_code'):
                    focus.append(entry)
                    if len(focus) >= _PRODUCTION_FOCUS_CAP:
                        return focus
        return focus

    def _build_tool_health_summary(self) -> Optional[str]:
        """Phase H (2026-05-17): one-line pointer to operator_notes.yaml
        when there's anything operator-facing to relay. Returns None
        when no advisories fire so clean-run output stays uncluttered.

        The detailed content (cache-size warnings, etc.) is in
        operator_notes.yaml, not here — ai_instructions.yaml should
        stay focused on the codebase under review.
        """
        advisories = self._build_system_advisories()
        if not advisories:
            return None
        return (
            f"{len(advisories)} operator-facing advisor"
            f"{'ies' if len(advisories) != 1 else 'y'} — see "
            f"operator_notes.yaml for tool diagnostics."
        )
    
    def _build_finding_data(self, finding: Finding) -> OrderedDict:
        """Build structured finding data with all relevant fields.

        Findings are passed through ``sanitize_finding_for_serialization``
        first so ``code_snippet`` on a SECURITY finding tagged as a
        secret-leak (auth hardcoded_secrets, bandit B105/B106, JS
        hardcoded_password) is dropped before it can be serialized.

        The ``context`` block (file_type / is_production_code /
        priority_for_ai) is attached to every finding so downstream AI
        consumers don't have to re-derive file role from the path on every
        item. Source of truth is ``FileClassifier`` via
        ``_classify_via_file_classifier``.
        """
        finding = self.sanitize_finding_for_serialization(finding)
        issue = self._build_core_finding_data(finding)
        self._add_optional_fields(issue, finding)
        self._add_privacy_specific_data(issue, finding)
        self._add_context_block(issue, finding)
        # Phase H (2026-05-17): false_positive_likelihood is derived
        # from (detected_by × is_production_code × confidence). Added
        # after the context block since it reads `is_production_code`
        # from the just-computed context.
        self._add_false_positive_likelihood(issue, finding)
        # Phase H (2026-05-17): per-finding first_seen timestamp so the
        # AI consumer can tell "new this scan" from "carried over".
        self._add_first_seen(issue, finding)
        # Phase H (2026-05-17): if the secret-redaction sanitizer
        # decided the snippet had to be dropped (or upstream metadata
        # tags this finding as secret_redacted), record an explicit
        # omission reason so the AI consumer doesn't wonder why the
        # snippet is missing.
        self._maybe_record_snippet_omission(issue, finding)
        return issue

    def _add_false_positive_likelihood(
        self, issue: OrderedDict, finding: Finding,
    ) -> None:
        """Phase H (2026-05-17): heuristic LOW/MEDIUM/HIGH classification
        of false-positive likelihood.

        Derivation rule (documented in the field glossary so the AI
        consumer knows it's heuristic, not science):

        - HIGH (likely FP): low-confidence keyword-style detectors firing
          on test files. The combination of "not production code" +
          confidence ≤ 0.75 + a keyword/regex-only scanner is what
          historically dominated the FP queue.
        - LOW (likely TP): high-precision detectors on production code.
          Bandit, Pysa, Semgrep taint + confidence ≥ 0.85 + production
          code = real bug, almost always.
        - MEDIUM: anything in between, or when context is ambiguous.

        The classification is added to every finding emitted via
        `_build_finding_data` — both the typed blocks and the legacy
        `critical_issues:` alias get it.
        """
        # Confidence is canonical at this point — sanitizer doesn't
        # touch it. Default to 0.0 (safest assumption for FP class).
        confidence = float(finding.confidence or 0.0)
        is_production = (issue.get('context') or {}).get(
            'is_production_code', False,
        )
        scanner = (finding.detected_by or "").lower()
        # High-precision detectors — established static-analysis tools
        # with low historical FP rate when they fire on production code.
        high_precision = {
            'bandit', 'pylint', 'pysataintscanner', 'semgreptaintscanner',
            'astgrepscanner', 'professionalcodescanner',
        }
        # Keyword/regex-style detectors that historically produce FPs
        # in non-production contexts (fixtures, docs).
        keyword_style = {
            'secretsscanner', 'auth_pattern_analyzer',
            'input_validation_analyzer', 'brass2privacyscanner',
            'apisecurityscanner',
        }

        if is_production and confidence >= 0.85 and scanner in high_precision:
            likelihood = 'LOW'
        elif (not is_production) and confidence <= 0.75 and scanner in keyword_style:
            likelihood = 'HIGH'
        else:
            likelihood = 'MEDIUM'

        issue['false_positive_likelihood'] = likelihood

    def _add_first_seen(self, issue: OrderedDict, finding: Finding) -> None:
        """Phase H (2026-05-17): attach a `first_seen` ISO-8601 timestamp
        to every finding so the AI consumer can tell freshly-detected
        signals from continuing ones.

        Persistence (`.brass/finding_history.json`) is keyed by finding
        id. New IDs get the current scan timestamp and are recorded for
        the next scan; known IDs return their original timestamp. If
        the history file is unreadable the field still appears, just
        with the current timestamp (degrades gracefully).
        """
        # Defensive lazy-init for direct-call test paths (callers that
        # exercise `_build_finding_data` without going through `build()`).
        # In those paths there's no per-build history state — we still
        # emit `first_seen` so the field shape is uniform across all
        # callers, just sourced from `now()` instead of disk.
        scan_ts = getattr(self, '_scan_timestamp_iso', None)
        if scan_ts is None:
            scan_ts = self._current_scan_timestamp()
            self._scan_timestamp_iso = scan_ts
        if not hasattr(self, '_finding_history_updates'):
            self._finding_history_updates = {}
        fid = finding.id or ""
        if not fid:
            issue['first_seen'] = scan_ts
            return
        history = getattr(self, '_finding_history', None) or {}
        if fid in history:
            issue['first_seen'] = history[fid]
        else:
            issue['first_seen'] = scan_ts
            self._finding_history_updates[fid] = scan_ts

    def _maybe_record_snippet_omission(
        self, issue: OrderedDict, finding: Finding,
    ) -> None:
        """Phase H (2026-05-17): for findings whose snippet was dropped
        because the credential value would re-leak, replace any leftover
        snippet with an explicit `code_snippet_omitted_reason` field.

        The sanitizer already clears `finding.code_snippet` for secret-
        leak findings, and `_add_optional_fields`'s synthesis step
        gates on `metadata.secret_redacted`. But a builder caller could
        still emit a snippet on a finding whose title says "value
        redacted" (e.g. `auth_pattern_analyzer` paired with a snippet
        synthesized from the source line, which would CONTAIN the
        credential). This method is the final gate: any finding with
        `secret_redacted` metadata gets the snippet dropped + an
        explicit reason recorded.
        """
        metadata = finding.metadata or {}
        if metadata.get('secret_redacted'):
            issue.pop('code_snippet', None)
            issue['code_snippet_omitted_reason'] = (
                'credential value would re-expose the secret in scrollback'
            )

    def _add_context_block(self, issue: OrderedDict, finding: Finding) -> None:
        """Attach the AI-prioritization context block to a finding.

        The context (`file_type` / `is_production_code` / `priority_for_ai`)
        is the canonical handoff to downstream AI consumers — they should
        not have to re-derive file role from the path string. Source of
        truth is `_classify_via_file_classifier`, which wraps
        `FileClassifier` and applies brass's priority mapping.
        """
        issue['context'] = self._classify_via_file_classifier(finding.file_path)
    
    def _build_core_finding_data(self, finding: Finding) -> OrderedDict:
        """Build core finding data with required fields."""
        return OrderedDict([
            ('id', finding.id),
            ('type', finding.type.value),
            ('severity', finding.severity.value),
            ('file_path', finding.file_path),
            ('title', finding.title),
            ('description', finding.description),
            ('confidence', finding.confidence),
            ('impact_score', finding.impact_score),
            ('detected_by', finding.detected_by)
        ])
    
    def _add_optional_fields(self, issue: OrderedDict, finding: Finding) -> None:
        """Add optional fields to finding data if present.

        Remediation is emitted as ``remediation_ref: rem_NNN`` pointing
        into the top-level ``remediations:`` table (Phase C, 2026-05-15)
        when a ref was registered during `_collect_remediations`. Falls
        back to inline `remediation:` if the per-call ref map is
        missing (defensive: any direct caller bypassing `build()`).
        """
        if finding.line_number:
            issue['line_number'] = finding.line_number
        if finding.column:
            issue['column'] = finding.column
        if finding.remediation and finding.remediation.strip():
            # Strip on both sides so a finding with leading/trailing
            # whitespace in its remediation string still resolves to the
            # ref (the table stores stripped values per
            # _collect_remediations).
            normalized = finding.remediation.strip()
            ref_map = getattr(self, '_remediation_ref_by_text', None)
            ref_id = ref_map.get(normalized) if ref_map else None
            if ref_id is not None:
                issue['remediation_ref'] = ref_id
            else:
                issue['remediation'] = normalized
        if finding.code_snippet:
            issue['code_snippet'] = finding.code_snippet
        else:
            # Phase D (2026-05-15): synthesize a snippet from the source
            # file when the scanner didn't ship one inline. Skips:
            #   - secret-redacted findings (sanitizer cleared snippet)
            #   - pii-redacted findings (same reason)
            #   - findings whose scanner deliberately set
            #     `code_snippet_intentionally_omitted: True` in metadata
            #     (e.g., ContentModerationScanner doesn't want to
            #     re-emit the slur it detected). Originally these
            #     findings' bypassed the gate because they weren't
            #     PRIVACY or in the secret-leak allowlist.
            metadata = finding.metadata or {}
            if not (metadata.get('secret_redacted')
                    or metadata.get('pii_redacted')
                    or metadata.get('code_snippet_intentionally_omitted')):
                synthesized = self._get_code_snippet(
                    finding.file_path, finding.line_number,
                )
                if synthesized:
                    # Defense in depth (2026-05-19): for findings on
                    # unparseable files (syntax-error class), the
                    # synthesized context lines can contain credentials
                    # from an unterminated string literal. Scrub via the
                    # same redactor BrassPerformanceScanner uses at
                    # source. Title detection matches all three scanners
                    # that emit syntax errors today:
                    #   - PhantomAICodeScanner: "Syntax Error in AI-Generated Code"
                    #   - BrassPerformanceScanner: same
                    #   - pylint (via ProfessionalCodeScanner): "syntax-error"
                    # Case-insensitive prefix check catches all three
                    # without false positives on realistic titles
                    # (no shipping scanner emits non-syntax-error titles
                    # starting with "syntax").
                    if (finding.title or '').lower().startswith('syntax'):
                        synthesized = BaseYAMLBuilder.redact_potential_credential(synthesized)
                    issue['code_snippet'] = synthesized
        if finding.references:
            issue['references'] = finding.references
        # Phase E (2026-05-15): cluster_size signals when a surviving
        # finding represents N>1 sibling findings that the gateway's
        # reranker clustered as duplicates. AI consumers should weigh
        # cluster_size=15 (one representative of 15 sites) more
        # heavily than cluster_size=1 (isolated finding). Only emit
        # when > 1 so the typical-case output stays uncluttered.
        #
        # Phase H (2026-05-17): cap the displayed cluster_size at 30.
        # Counts above that are visually meaningless and the AI consumer
        # can't act on them inline anyway. Emit an `expansion_hint:`
        # alongside that names the true count + points at
        # detailed_analysis.yaml for the full list.
        cluster_size = (finding.metadata or {}).get('cluster_size')
        if isinstance(cluster_size, int) and cluster_size > 1:
            if cluster_size > _CLUSTER_SIZE_DISPLAY_CAP:
                issue['cluster_size'] = _CLUSTER_SIZE_DISPLAY_CAP
                issue['expansion_hint'] = (
                    f"See detailed_analysis.yaml for the remaining "
                    f"{cluster_size - _CLUSTER_SIZE_DISPLAY_CAP} "
                    f"occurrences ({cluster_size} total)."
                )
            else:
                issue['cluster_size'] = cluster_size
        # Phase F (2026-05-15): also_detected_by lists OTHER scanners
        # that flagged the same (file_path, line_number). Tells AI
        # consumers when multiple rule engines agree — a stronger signal
        # than any single scanner alone (e.g., bandit B324 + ast_grep
        # weak-hash on the same line = "this is definitely a real hit").
        #
        # Lookup priority (2026-05-16 architectural fix):
        #   1. metadata['cross_scanner_overlap_peers'] — pre-computed by
        #      the CLI BEFORE enrichment so the peers survive the
        #      gateway's semantic-duplicate drop pass. Without this,
        #      enrichment collapses cross-scanner same-line pairs and
        #      the builder's post-enrichment computation has nothing
        #      to find.
        #   2. self._cross_scanner_overlap — per-build map computed
        #      from whatever findings the builder received. Fallback
        #      for direct-call paths (unit tests).
        metadata = finding.metadata or {}
        # `is None` (not falsy) — a stashed empty list means "the CLI
        # checked and there are no peers"; falling back to the
        # per-build map in that case would surface peers the upstream
        # code deliberately decided not to attach.
        also = metadata.get('cross_scanner_overlap_peers')
        if also is None:
            overlap_map = getattr(self, '_cross_scanner_overlap', None)
            if overlap_map and finding.line_number is not None and finding.file_path and finding.detected_by:
                also = overlap_map.get(
                    (finding.file_path, finding.line_number, finding.detected_by)
                )
        if also:
            issue['also_detected_by'] = also

    def _get_code_snippet(
        self, file_path: Optional[str], line_number: Optional[int],
        context: int = 1,
    ) -> Optional[str]:
        """Read ``file_path`` and return the line at ``line_number`` plus
        ``context`` lines on either side, joined with newlines.

        Returns None on:
          - missing file_path / line_number
          - file outside project, missing, > 1MB, unreadable
          - line_number out of file range

        Uses `self._file_content_cache` so multiple findings on the same
        file read it once per `build()` call. The cache is cleared at
        the start of `build()`.
        """
        if not file_path or not line_number or line_number < 1:
            return None
        lines = self._read_file_lines(file_path)
        if lines is None:
            return None
        # line_number is 1-based; clamp the slice window.
        start = max(0, line_number - 1 - context)
        end = min(len(lines), line_number + context)
        if start >= len(lines):
            return None  # past EOF
        snippet_lines = lines[start:end]
        # Strip trailing newlines from each line so the YAML block
        # doesn't carry stray '\n's at the end of every element.
        return '\n'.join(s.rstrip('\n') for s in snippet_lines)

    def _read_file_lines(self, file_path: str) -> Optional[List[str]]:
        """Cached file-read returning the file as a list of lines, or
        None if the file is unavailable / too large / outside project.

        Caches both successful reads AND None-results for failed reads
        so repeat lookups on the same path don't re-stat / re-fail.

        Normally invoked from inside `build()`, which initializes
        ``self._file_content_cache`` and ``self._resolved_project_root``.
        Defensive lazy-init handles unit tests and other isolation
        callers that exercise builder helpers without a full build.
        Each test constructs a fresh builder so per-instance leakage
        across scans is not a real concern in practice — but DO NOT
        reuse a single builder across multiple production scans
        without going through `build()`, since the cache could then
        carry stale content if files change between scans.
        """
        cache = getattr(self, '_file_content_cache', None)
        if cache is None:
            cache = {}
            self._file_content_cache = cache
        project_root = getattr(self, '_resolved_project_root', None)
        if project_root is None:
            project_root = Path(self.project_path)
            self._resolved_project_root = project_root
        if file_path in cache:
            return cache[file_path]
        abs_path = (project_root / file_path).resolve()
        try:
            abs_path.relative_to(project_root)
        except (ValueError, OSError):
            # Outside project tree → don't read.
            cache[file_path] = None
            return None
        try:
            if not abs_path.is_file():
                cache[file_path] = None
                return None
            if abs_path.stat().st_size > _CODE_SNIPPET_MAX_FILE_BYTES:
                cache[file_path] = None
                return None
            lines = abs_path.read_text(encoding='utf-8', errors='replace').splitlines()
        except OSError:
            cache[file_path] = None
            return None
        cache[file_path] = lines
        return lines
    
    def _add_privacy_specific_data(self, issue: OrderedDict, finding: Finding) -> None:
        """Add privacy-specific data if finding is privacy-related."""
        if finding.is_privacy_related():
            if finding.privacy_category:
                issue['privacy_category'] = finding.privacy_category
            if finding.compliance_regions:
                issue['compliance_regions'] = finding.compliance_regions
    
    def _classify_via_file_classifier(self, file_path: str) -> OrderedDict:
        """Single source of truth for is_production_code / priority.

        FileClassifier knows about build outputs (.next, _archive,
        __tests__, etc.), test files (Jest/Vitest/Cypress conventions
        and Python pytest), docs, configs, and source. The
        substring-based fallback this method replaces was wrong for
        TS/JS projects (treating .next/ build output as production
        code) and a major source of false-positive noise.
        """
        from brass.core.file_classifier import FileClassifier, FileType

        if not hasattr(self, '_classifier'):
            # Pass project_path so absolute paths in findings get
            # normalized to project-relative before pattern matching.
            self._classifier = FileClassifier(project_root=str(self.project_path))
        context = self._classifier.classify_file(file_path)

        # Production code: only SOURCE_CODE. Tests, fixtures, build
        # output, docs, and configs all get is_production_code: false
        # so the downstream AI doesn't treat them as the same priority
        # as application code that ships to users.
        is_production = context.file_type == FileType.SOURCE_CODE

        if context.file_type == FileType.SOURCE_CODE:
            priority = 'HIGH'
        elif context.file_type in (FileType.TEST_FILE, FileType.TEST_FIXTURE):
            priority = 'LOW'
        elif context.file_type == FileType.BUILD_OUTPUT:
            priority = 'LOW'
        elif context.file_type == FileType.DOCUMENTATION:
            priority = 'LOW'
        else:
            priority = 'MEDIUM'

        # Use the enum's friendly value (e.g. "source_code") for the
        # output, matching the human-readable names callers expect.
        return OrderedDict([
            ('file_type', context.file_type.value),
            ('is_production_code', is_production),
            ('priority_for_ai', priority),
        ])
    
    def _build_ai_guidance(self, findings: List[Finding]) -> Dict[str, List[str]]:
        """Build AI-specific guidance sections."""
        guidance = OrderedDict()
        
        # Security guidance
        security_findings = [f for f in findings if f.type == FindingType.SECURITY]
        if security_findings:
            guidance['security_focus'] = [
                "Review authentication and authorization implementations",
                "Validate input sanitization and output encoding", 
                "Check for SQL injection and XSS vulnerabilities",
                "Verify secure credential management practices"
            ]
        
        # Code quality guidance
        quality_findings = [f for f in findings if f.type == FindingType.CODE_QUALITY]
        if quality_findings:
            guidance['quality_improvements'] = [
                "Reduce complexity in high-complexity functions",
                "Improve error handling and exception management",
                "Consider refactoring large classes and long methods",
                "Add comprehensive unit test coverage"
            ]
        
        # Privacy guidance
        privacy_findings = [f for f in findings if f.type == FindingType.PRIVACY]
        if privacy_findings:
            guidance['privacy_compliance'] = [
                "Remove or encrypt exposed PII data",
                "Implement proper data handling procedures", 
                "Review compliance with GDPR, CCPA requirements",
                "Add data anonymization for test datasets"
            ]
        
        return guidance
    
    def _build_file_priorities(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Build priority list of files with scoring."""
        by_file = defaultdict(list)
        for finding in findings:
            by_file[finding.file_path].append(finding)
        
        file_priorities = []
        for file_path, file_findings in by_file.items():
            critical_count = len([f for f in file_findings 
                                if f.severity in [Severity.CRITICAL, Severity.HIGH]])
            total_count = len(file_findings)
            priority_score = critical_count * 3 + total_count
            
            file_priorities.append(OrderedDict([
                ('file_path', file_path),
                ('total_issues', total_count),
                ('critical_issues', critical_count),
                ('priority_score', priority_score)
            ]))
        
        file_priorities.sort(key=lambda x: x['priority_score'], reverse=True)
        return file_priorities[:10]
    
    def _build_quick_actions(self, findings: List[Finding]) -> Dict[str, List[Dict[str, Any]]]:
        """Build quick action items."""
        actions = OrderedDict()
        
        # Immediate actions for critical findings
        # 2026-05-19 audit: use the module-level _typed_block_sort_key so
        # syntax-error CRITICALs win the top-3 slots over other CRITICALs
        # on enrichment rank ties. Cap-severity pattern, syntax-first variant.
        critical_findings = sorted(
            [f for f in findings if f.severity == Severity.CRITICAL],
            key=_typed_block_sort_key,
        )[:3]
        if critical_findings:
            immediate = []
            for finding in critical_findings:
                immediate.append(OrderedDict([
                    ('action', f"Fix {finding.title}"),
                    ('file', finding.file_path),
                    ('line', finding.line_number),
                    ('priority', 'critical')
                ]))
            actions['immediate'] = immediate
        
        # TODO items. Surface cluster_size when present so an AI
        # consumer can see "this 1 surviving TODO represents N similar
        # ones" — the semantic reranker aggressively clusters TODOs as
        # near-duplicates, which is what produced the 70-findings-but-
        # 1-TODO disparity observed in whisperx-production. The total
        # count comes from the pre-cluster finding set.
        all_todos = [f for f in findings if f.type == FindingType.TODO]
        if all_todos:
            todo_items = []
            for finding in all_todos[:5]:
                item = OrderedDict([
                    ('description', finding.title),
                    ('location', finding.get_location_string()),
                ])
                cluster_size = (finding.metadata or {}).get('cluster_size')
                if isinstance(cluster_size, int) and cluster_size > 1:
                    item['cluster_size'] = cluster_size
                todo_items.append(item)
            actions['todo_items'] = todo_items
            if len(all_todos) > 5:
                # Hint to the AI consumer that more TODOs are in
                # detailed_analysis.yaml; the top-5 cap is a
                # readability ceiling, not a coverage statement.
                actions['todo_items_truncated_count'] = (
                    len(all_todos) - 5
                )

        return actions