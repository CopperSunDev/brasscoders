"""
Base class for all YAML builders.

Provides common interface and shared functionality for generating
structured YAML sections from findings data.
"""

import re
import unicodedata
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

from brass.models.finding import Finding, FindingType
from brass.core.path_safety import is_within


# Metadata keys that may contain raw matched PII or surrounding source code. These
# are stripped from any privacy finding before serialization as a defense-in-depth
# layer behind the scanner-side redaction. Update this list rather than adding ad-hoc
# strip calls in individual builders.
PRIVACY_SENSITIVE_METADATA_KEYS = frozenset({
    'matched_text',
    'code_snippet',
    'context_line',
    'raw_match',
    'context',
    # Bandit's `code` field carries the source snippet around the issue —
    # for B105 (hardcoded_password), B106 (hardcoded_password_funcarg),
    # B324 (weak hash), this is the very source line containing the secret.
    'code',
})

# Detector / pattern names that mean the finding's snippet is likely to contain
# the leaked credential itself. Used to extend the privacy redaction to
# secret-leak SECURITY findings — a finding that exists *because* something
# was secret must not embed that thing in serialized output.
_SECRET_LEAK_DETECTORS = frozenset({
    # Entries are matched lowercased (sanitize_metadata_for_serialization
    # does `detected_by.lower()` before lookup), so all entries must
    # be lowercase here.
    'auth_pattern_analyzer',  # AIAuthPatternAnalyzer.hardcoded_secrets
    'bandit',  # B105 / B106 / B107 / B324 hit hardcoded credentials
    # The detect-secrets-backed SecretsScanner. Its findings' raw
    # context contains the credential string itself; sanitization
    # must strip it. Added 2026-05-15 after Phase D's code_snippet
    # synthesis was observed re-emitting the credential payload on a
    # coppersun_brass scan (the synth path reads the source line
    # directly, bypassing detect-secrets' own redaction).
    'secretsscanner',
    # The JS/TS hardcoded-password scanner. Same risk profile as
    # bandit B105/B106 — flags credential literals; the snippet
    # would carry the literal.
    'javascript_typescript',
    'javascripttypescriptscanner',
    # LegacyPatternScanner (TODO/FIXME/HACK/XXX/BUG comment finder).
    # Pre-2026-05-18 these findings were silently dropped by the
    # NoiseReductionScanner confidence filter (default 0.0); the
    # confidence-audit fix unlocked them and the canary test caught
    # the resulting leak: TODO comments routinely embed credentials
    # ("# TODO: rotate AWS_SECRET_KEY=...") and the finding's
    # snippet carried the raw value. Sanitization now strips
    # credential-shaped substrings from these findings.
    'legacy_patterns',
    # NOTE 2026-05-19: BrassPerformanceScanner was briefly added here
    # for "defense in depth" against syntax-error findings whose
    # code_snippet (exc.text) might contain a credential. But the
    # scanner emits MANY non-syntax CODE_QUALITY findings too (high
    # complexity, dead code, AI anti-patterns) — adding the scanner to
    # this allowlist relabeled ALL of them as
    # "Possible hardcoded credential (value redacted)" in the output.
    # Reverted: redaction is now done at source in
    # _build_syntax_error_finding via _redact_potential_credential.
})

_SECRET_LEAK_PATTERN_TYPES = frozenset({
    'hardcoded_secrets',
    'hardcoded_password',
    'hardcoded-password',
    'hardcoded_password_funcarg',
    'api_key',
    'jwt_secret',
})


# Defense-in-depth credential redaction applied to every finding's
# ``description`` field at serialization time. Originally lived as a
# staticmethod on ``LegacyPatternScanner._redact_secret_substrings``
# (2026-05-15); promoted to module-level 2026-05-21 after a full-scan
# audit revealed pylint W0511 (fixme) and C0103 (invalid-name) both
# re-emit the raw comment / identifier text verbatim — and those
# scanners aren't in ``_SECRET_LEAK_DETECTORS``, so the
# `sanitize_finding_for_serialization` early-return skipped redaction
# entirely. This catches the recurring leak class (per the user's
# `project_brass_redaction_bypass_class` memory note: "scanners self-
# redact in the field they own but downstream surfaces re-emit raw
# values") at the output boundary, regardless of which scanner
# produced the finding.
#
# Conservative — false-positives on technical-looking strings are
# fine; missing a secret is the failure mode we're guarding.
_CREDENTIAL_REDACTION_PATTERNS = (
    # <NAME>_(KEY|SECRET|...) = value — case-insensitive so lowercase
    # variants like ``my_api_key = "..."`` from pylint C0103 messages
    # (or non-canonical scanners) also redact. 2026-05-21 cumulative
    # review flagged the prior uppercase-only `[A-Z]` anchor as a
    # bypass for lowercase-identifier leaks.
    (re.compile(
        r'\b([A-Za-z][A-Za-z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASS|PWD|API|AUTH))'
        r'\s*[=:]\s*["\']?[A-Za-z0-9\-_/+.]{8,}["\']?',
        re.IGNORECASE,
    ), r'\1=<redacted>'),
    # GitHub PATs (ghp_, gho_, ghu_, ghs_, ghr_)
    (re.compile(r'\bgh[opusr]_[A-Za-z0-9]{20,}\b'), '<redacted-github-token>'),
    # AWS access keys
    (re.compile(r'\bAKIA[A-Z0-9]{16}\b'), '<redacted-aws-key>'),
    # Stripe live/test keys
    (re.compile(r'\bsk_(?:live|test)_[A-Za-z0-9]{15,}\b'), '<redacted-stripe-key>'),
    # Google API keys (Cloud Platform / Firebase / Maps). Spec is
    # ``AIza`` + 35 chars but variants exist; ``{20,}`` keeps the
    # match permissive without false-positive risk (the ``AIza``
    # prefix is highly specific).
    (re.compile(r'\bAIza[0-9A-Za-z_-]{20,}\b'), '<redacted-google-api-key>'),
    # OpenAI API keys. Legacy form ``sk-<48>`` and newer
    # ``sk-proj-<...>``. Hyphen separator distinguishes from
    # Stripe's underscore form (``sk_live_``, ``sk_test_``) so
    # the two patterns coexist without overlap. Discord bot
    # tokens are NOT covered here — their 3-part-base64 shape
    # collides with JWT and the JWT pattern usually catches them.
    (re.compile(r'\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}\b'), '<redacted-openai-key>'),
    # Anthropic API keys. ``sk-ant-`` prefix is unique to us;
    # tail is 80+ base62 chars (rough — variants exist). The
    # OpenAI pattern above also requires hyphen separator but
    # OpenAI's tail is shorter and lacks ``ant-``, so the
    # patterns don't collide.
    (re.compile(r'\bsk-ant-(?:api03-)?[A-Za-z0-9_-]{80,}\b'), '<redacted-anthropic-key>'),
    # SendGrid API keys: ``SG.<22>.<43>`` (period-separated).
    # Length quantifiers kept ``{20,}/{40,}`` to absorb spec
    # drift; the ``SG.`` prefix + double-period structure is
    # specific enough that false-positive risk is near-zero.
    (re.compile(r'\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{40,}\b'), '<redacted-sendgrid-key>'),
    # Mailgun API keys: ``key-<32 hex>``. The lowercase-hex tail
    # narrows the false-positive surface vs a generic
    # ``key-<anything>``.
    (re.compile(r'\bkey-[a-f0-9]{32}\b'), '<redacted-mailgun-key>'),
    # Twilio Account SID: ``AC<32 hex>`` (case-sensitive ``AC``
    # prefix). Auth tokens follow a similar shape but no
    # distinguishable prefix.
    (re.compile(r'\bAC[a-f0-9]{32}\b'), '<redacted-twilio-sid>'),
    # NPM automation tokens: ``npm_<36 base62>``.
    (re.compile(r'\bnpm_[A-Za-z0-9]{36}\b'), '<redacted-npm-token>'),
    # DigitalOcean PATs: ``dop_v1_<64 hex>``.
    (re.compile(r'\bdop_v1_[a-f0-9]{64}\b'), '<redacted-digitalocean-token>'),
    # Slack tokens (bot, user, app, refresh, app-level)
    (re.compile(r'\bxox[abprs]-[A-Za-z0-9-]{10,}\b'), '<redacted-slack-token>'),
    # JWTs
    (re.compile(
        r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b'
    ), '<redacted-jwt>'),
    # Bearer headers
    (re.compile(r'\bBearer\s+[A-Za-z0-9\-_.]{16,}'), 'Bearer <redacted>'),
    # PEM private-key blocks collapsed to one line (the multi-line
    # form is unlikely to appear in a finding description, but if a
    # scanner ever serialized one with newlines stripped, catch it).
    (re.compile(
        r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----'
    ), '<redacted-pem-private-key>'),
)


def redact_credential_substrings(text: Optional[str]) -> Optional[str]:
    """Replace credential-shaped substrings in ``text`` with
    ``<redacted-...>`` placeholders. ``None`` and empty strings pass
    through unchanged.

    Applied unconditionally to every finding's description / title /
    remediation in ``sanitize_finding_for_serialization`` so a scanner
    emitting raw comment / identifier text (pylint W0511, C0103)
    can't leak the credential through the output YAML. Preserves the
    surrounding text so the AI consumer still understands what was
    detected.

    Unicode normalization: NFKC-folds the input before pattern
    matching, so fullwidth digits / compatibility characters don't
    bypass the ASCII regexes. Pure win for ASCII inputs; closes a
    cheap-attack class on adversarial source files.
    """
    if not text:
        return text
    normalized = unicodedata.normalize('NFKC', text)
    for pattern, placeholder in _CREDENTIAL_REDACTION_PATTERNS:
        normalized = pattern.sub(placeholder, normalized)
    return normalized


class BaseYAMLBuilder(ABC):
    """
    Abstract base class for YAML section builders.

    All builders follow the same pattern:
    1. Take List[Finding] as input
    2. Generate structured Dict[str, Any] for YAML
    3. Follow single responsibility principle
    """

    def __init__(self, project_path: str, generation_time: datetime):
        """
        Initialize builder with project context.

        Args:
            project_path: Root path of project being analyzed
            generation_time: When analysis was performed
        """
        self.project_path = Path(project_path).resolve()
        self.generation_time = generation_time

    @abstractmethod
    def build(self, findings: List[Finding]) -> Dict[str, Any]:
        """
        Build YAML section data from findings.

        Args:
            findings: Filtered findings relevant to this builder

        Returns:
            Dictionary ready for YAML serialization
        """
        pass

    # Detectors that report ``finding.column`` and ``finding.line_number``
    # cleanly enough that we can synthesize a masked snippet showing the
    # variable / context line with the credential value redacted. Used by
    # ``sanitize_finding_for_serialization`` to emit a partial snippet
    # instead of dropping ``code_snippet`` entirely — saves the AI consumer
    # an extra source-file Read to triage real credentials vs placeholders.
    # SecretsScanner (detect-secrets) is excluded: it doesn't report column
    # and re-scanning to recover span risks fuzzy-boundary leaks.
    _COLUMN_AVAILABLE_REDACTORS = frozenset({
        'bandit',
        'javascript_typescript',
        'javascripttypescriptscanner',
    })

    # Regex that finds an assignment ``=`` — not preceded by ``!<>=``
    # (comparison / compound op) and not followed by ``=`` (``==``).
    # Used by ``_synthesize_masked_credential_line`` to locate the
    # right-hand side of an assignment for redaction.
    _ASSIGNMENT_OP_PATTERN = re.compile(r'(?<![!<>=])=(?!=)')

    # Matches a quoted string literal whose content is ≥12 chars —
    # i.e., long enough to plausibly be a credential. Short literals
    # (``"GET"``, ``"hello"``, ``"text/json"``) survive untouched so
    # the AI consumer can still see function arguments and short
    # constants. Long literals get redacted in context lines because
    # the validation scan showed adjacent-line credentials slipping
    # through when only the matched line was masked (e.g.,
    # ``R2_SECRET_KEY = 'mock-secret-key'`` on the line below an
    # already-masked R2_ACCESS_KEY assignment).
    _LONG_QUOTED_LITERAL_PATTERN = re.compile(
        r'''(?P<quote>['"])(?P<body>(?:\\.|(?!(?P=quote)).){12,})(?P=quote)'''
    )

    # Aggressive credential redactor for snippets synthesized from a
    # file with a syntax error. Real-world trigger: an unterminated
    # string literal containing a credential
    # (`AWS_SECRET = "wJalrXUtnFEMI..."`). Strategy:
    # 1) Replace any quoted body ≥8 chars with `<REDACTED: literal>`.
    # 2) Replace everything from an `=` to end-of-line when the RHS
    #    begins with a quote (catches the unterminated case where the
    #    quoted-body regex can't match because there's no closing
    #    quote).
    # Conservative: false positives just lose snippet detail; never
    # leaks raw. Used by both BrassPerformanceScanner's
    # `_build_syntax_error_finding` (at source) and the AI-instructions
    # builder's snippet-synthesis path (defense in depth — PhantomAI-
    # style scanners that emit no inline snippet rely on this).
    _SHORT_QUOTED_LITERAL_PATTERN = re.compile(
        r'''(?P<q>['"])(?:\\.|(?!(?P=q)).){8,}(?P=q)'''
    )
    _UNTERMINATED_RHS_PATTERN = re.compile(
        r'''(=\s*)(['"]).*$''', re.MULTILINE,
    )

    @staticmethod
    def redact_potential_credential(text: Optional[str]) -> str:
        """Strip credential-shaped substrings from a source line / snippet.

        Used in two paths:
        - BrassPerformanceScanner._build_syntax_error_finding scrubs
          `exc.text` before it enters a Finding's code_snippet.
        - ai_instructions_builder's snippet-synthesis path scrubs the
          context lines for any syntax-error finding whose scanner
          didn't pre-redact (e.g. PhantomAICodeScanner).

        Multi-line input is handled (the unterminated-RHS pattern uses
        re.MULTILINE).
        """
        if not text:
            return ""
        cleaned = text.rstrip("\n")
        cleaned = BaseYAMLBuilder._SHORT_QUOTED_LITERAL_PATTERN.sub(
            r"\g<q><REDACTED: literal>\g<q>", cleaned,
        )
        cleaned = BaseYAMLBuilder._UNTERMINATED_RHS_PATTERN.sub(
            r"\1<REDACTED: unterminated literal>", cleaned,
        )
        return cleaned

    @staticmethod
    def _redact_long_quoted_literals(line: str) -> str:
        """Replace every quoted string literal ≥12 chars in ``line``
        with a generic placeholder. Used on the context lines of a
        masked-credential snippet so an adjacent-line credential
        can't leak through the cleartext context surrounding the
        matched line.
        """
        return BaseYAMLBuilder._LONG_QUOTED_LITERAL_PATTERN.sub(
            lambda m: f"{m.group('quote')}<REDACTED: literal>{m.group('quote')}",
            line,
        )

    @staticmethod
    def sanitize_metadata_for_serialization(finding: Finding) -> Dict[str, Any]:
        """Return a serialization-safe copy of ``finding.metadata``.

        Two redaction triggers:
          - ``FindingType.PRIVACY`` — always strip raw matched text and
            surrounding source-code lines. The privacy scanner exists to
            *detect* such material, so persisting it would defeat the purpose.
          - ``FindingType.SECURITY`` whose detector or ``pattern_type`` is in
            the secret-leak allowlist — same logic. A "hardcoded password"
            finding that embeds the password in metadata leaks the very
            credential it's flagging.

        Non-sensitive findings get their metadata back unchanged.
        """
        metadata = dict(finding.metadata or {})

        if finding.type == FindingType.PRIVACY:
            for key in PRIVACY_SENSITIVE_METADATA_KEYS:
                metadata.pop(key, None)
            metadata['pii_redacted'] = True
            return metadata

        # SECURITY findings from credential-leak detectors get full
        # redaction (their existence implies the title/description
        # carries the secret). TODO findings from LegacyPatternScanner
        # get the same treatment because real-world TODO comments
        # routinely include credentials ("# TODO: rotate AWS_SECRET_KEY=...")
        # and the LegacyPatternScanner's description embeds the snippet
        # verbatim. The canary fixture
        # tests/end_to_end/fixtures/credential_minefield/todo_with_secret.py
        # specifically catches a regression here.
        if finding.type in (FindingType.SECURITY, FindingType.TODO):
            detected_by = (finding.detected_by or '').lower()
            pattern_type = (
                metadata.get('pattern_type')
                or metadata.get('pattern')
                or metadata.get('test_name', '')
            )
            pattern_type_lower = str(pattern_type).lower()
            if (detected_by in _SECRET_LEAK_DETECTORS
                    or pattern_type_lower in _SECRET_LEAK_PATTERN_TYPES):
                for key in PRIVACY_SENSITIVE_METADATA_KEYS:
                    metadata.pop(key, None)
                metadata['secret_redacted'] = True
        return metadata

    def sanitize_finding_for_serialization(self, finding: Finding) -> Finding:
        """Return a serialization-safe copy of ``finding`` with redactions
        applied to top-level fields too (``code_snippet``, ``title``,
        ``description``, plus metadata).

        Use this when emitting a Finding's whole shape (not just metadata)
        — e.g. the ai_instructions critical_issues list. Several scanners
        embed the literal credential value into ``title`` /
        ``description`` (Bandit's ``issue_text`` for B105/B106/B107 is
        ``"Possible hardcoded password: 'REAL_LITERAL'"``; the privacy
        scanner's description includes a partial-reveal mask that
        still leaks the last-4 of a card / SSN). All such surfaces are
        scrubbed here to a generic, scanner-aware safe form.
        """
        from dataclasses import replace
        clean_metadata = BaseYAMLBuilder.sanitize_metadata_for_serialization(finding)
        secret = bool(clean_metadata.get('secret_redacted'))
        pii = bool(clean_metadata.get('pii_redacted'))
        if not (secret or pii):
            # Defense-in-depth (2026-05-21): even when the scanner
            # didn't mark this finding as secret-bearing, scrub any
            # vendor-shaped credential substrings from every free-
            # text field before serialization. Pylint W0511 (fixme)
            # and C0103 (invalid-name) re-emit raw comment / identifier
            # text that can contain credentials — and pylint isn't in
            # ``_SECRET_LEAK_DETECTORS`` (and shouldn't be wholesale,
            # since most pylint findings aren't credential-related).
            # The redaction pass is conservative (vendor-prefix
            # patterns only) so non-credential text passes through
            # unchanged.
            #
            # Fields scrubbed: title, description, remediation. The
            # cumulative-review pass found that scrubbing description
            # alone left ``title`` and ``remediation`` as open paths;
            # a future scanner emitting a credential in either field
            # would slip through. ``code_snippet`` is intentionally
            # NOT scrubbed here — scanners that emit it (Bandit B105
            # etc.) self-redact at source; downstream synthesis goes
            # through the masked-snippet path with its own redaction.
            # ``references`` is a list of static URLs; not a leak vector.
            scrubbed_title = redact_credential_substrings(finding.title)
            scrubbed_description = redact_credential_substrings(
                finding.description
            )
            scrubbed_remediation = redact_credential_substrings(
                finding.remediation
            )
            if (
                scrubbed_title != finding.title
                or scrubbed_description != finding.description
                or scrubbed_remediation != finding.remediation
            ):
                return replace(
                    finding,
                    metadata=clean_metadata,
                    title=scrubbed_title,
                    description=scrubbed_description,
                    remediation=scrubbed_remediation,
                )
            return replace(finding, metadata=clean_metadata)

        # Replacement title/description that preserves enough info for
        # the AI consumer to triage (detector, finding-category) without
        # carrying the literal credential / PII value through.
        if secret:
            safe_title = 'Possible hardcoded credential (value redacted)'
            safe_description = (
                'A credential-shaped literal was detected at this location. '
                'The exact value has been redacted to prevent the brass '
                'output from re-exposing it. Inspect the source line '
                'directly to confirm and rotate the credential if real.'
            )
            # Surface the assignment LHS (variable name / dotted path) in
            # the description when we can extract it safely. Lets the AI
            # consumer triage placeholders (``process.env.X = ...``,
            # ``config.PUBLIC_FLAG = "abc"``) vs real credentials
            # (``AWS_KEY = "AKIA..."``) without a Read tool call —
            # while honoring Phase H's decision NOT to emit a
            # code_snippet surface that could re-leak the value.
            # Variable names are public identifiers; the LHS extractor
            # rejects anything containing a quoted literal as defense
            # in depth.
            if finding.file_path and finding.line_number:
                lhs = self._extract_assignment_lhs(
                    finding.file_path, finding.line_number,
                )
                if lhs:
                    safe_description = (
                        f"Variable assignment: `{lhs}`. " + safe_description
                    )
        else:  # pii
            safe_title = 'Possible PII (value redacted)'
            safe_description = (
                'A pattern matching personally-identifiable information '
                'was detected at this location. The exact value has been '
                'redacted; consult the source to confirm before deciding '
                'whether to remove or replace with synthetic test data.'
            )

        # Phase 1 masked-snippet synthesis (2026-05-17): for SECURITY
        # findings from column-available redactors (Bandit, JS/TS), emit
        # a 3-line snippet with the credential value redacted out of the
        # matched line. AI consumers can see the variable name + usage
        # context for triage without an extra source-file Read tool call.
        # SecretsScanner (detect-secrets) lacks column info — skip it
        # safely; current behavior (no snippet) preserved. PII findings
        # also skip — fuzzy regex boundaries make masking risk leakage.
        masked_snippet = None
        if (
            secret
            and not pii
            and (finding.detected_by or '').lower() in self._COLUMN_AVAILABLE_REDACTORS
            and finding.file_path
            and finding.line_number
        ):
            masked_snippet = self._synthesize_masked_credential_snippet(
                finding.file_path, finding.line_number,
            )

        return replace(
            finding,
            metadata=clean_metadata,
            code_snippet=masked_snippet,
            title=safe_title,
            description=safe_description,
        )

    def _synthesize_masked_credential_snippet(
        self, file_path: str, line_number: int, context: int = 1,
    ) -> Optional[str]:
        """Read line ± context from the source file; mask the matched line.

        The matched line is identified by ``line_number`` (1-based). Mask
        strategy: find the first assignment ``=`` and replace the entire
        right-hand side with ``<REDACTED: hardcoded credential>``. If no
        assignment is found (function-call argument, etc.), the matched
        line is replaced wholesale with a sentinel. Surrounding lines are
        emitted unchanged so the AI can see the import / usage context.

        Returns ``None`` on read failure (path resolution, permissions,
        encoding) so the caller falls back to ``code_snippet=None`` — the
        previous behavior. Best-effort: this method must never raise.
        """
        try:
            src_path = Path(file_path)
            if not src_path.is_absolute():
                src_path = self.project_path / src_path
            # Resolve once so the containment check and subsequent
            # read share the same inode-bound path — kills the
            # symlink-flip TOCTOU window. Defense in depth: refuse
            # to read outside project_path even if a buggy scanner
            # emitted a traversal path.
            resolved = src_path.resolve(strict=True)
        except (OSError, RuntimeError):
            return None
        if not is_within(resolved, self.project_path):
            return None
        lines = self._read_file_lines_shared(resolved)
        if lines is None or line_number < 1 or line_number > len(lines):
            return None
        # 1-based line numbers, list is 0-based.
        match_idx = line_number - 1
        start = max(0, match_idx - context)
        end = min(len(lines), match_idx + context + 1)
        snippet_lines = list(lines[start:end])
        match_in_snippet = match_idx - start
        # Context lines: redact long quoted literals to guard against
        # adjacent-line credential leaks (a credential on line N+1
        # would otherwise emit cleartext via the matched line N's
        # context window). The matched line itself gets the full
        # assignment-marker redaction below — but apply the literal-
        # mask to its LHS first so a credential-shaped variable name
        # or dict-key literal doesn't leak either.
        for i in range(len(snippet_lines)):
            if i != match_in_snippet:
                snippet_lines[i] = self._redact_long_quoted_literals(
                    snippet_lines[i]
                )
        matched_line = self._redact_long_quoted_literals(
            snippet_lines[match_in_snippet]
        )
        snippet_lines[match_in_snippet] = self._redact_credential_line(
            matched_line,
        )
        return '\n'.join(snippet_lines)

    @staticmethod
    def _redact_credential_line(line: str) -> str:
        """Return ``line`` with the credential portion replaced by a
        placeholder. Preserves the variable name / function context
        when an assignment ``=`` is present; falls back to a
        whole-line sentinel otherwise.

        Over-masks safely: a comment after the assignment value (e.g.,
        ``KEY = "abc" # production``) gets included in the redaction.
        Acceptable cost — the AI consumer never sees the literal.
        Never includes any character right of the assignment marker
        in the output.
        """
        m = BaseYAMLBuilder._ASSIGNMENT_OP_PATTERN.search(line)
        if m and m.start() > 0:
            # Preserve everything left of the `=` (variable name +
            # whitespace); replace the right-hand side. The match
            # position is the `=` itself, so include it explicitly.
            return line[: m.start()] + '= <REDACTED: hardcoded credential>'
        return '<REDACTED: credential-shaped literal on this line — inspect source directly>'

    # Positive whitelist for the LHS-of-assignment extractor: a chain
    # of identifiers separated by ``.`` or ``[<bracketed>]``, where
    # ``<bracketed>`` is itself an identifier or integer (no quoted
    # literal keys). Matches:
    #   AWS_KEY                          - simple identifier
    #   process.env.X                    - dotted path
    #   obj.cfg.NESTED                   - deeper dotted path
    #   arr[0]                           - integer index
    #   obj[key]                         - identifier index
    # Rejects:
    #   x: int  -> type-annotated assignment
    #   AWS_KEY += -> augmented assignment (operator garbage in LHS)
    #   # comment text -> comments
    #   auth(token -> function call
    #   d["k"] -> quoted key (defense vs credential-shaped key)
    # Anchored so partial matches don't pass. Up to 120 chars to allow
    # deep JS namespacing without losing the hint.
    _SAFE_LHS_PATTERN = re.compile(
        r'^[A-Za-z_$][A-Za-z0-9_$]*'
        r'(?:\.[A-Za-z_$][A-Za-z0-9_$]*'
        r'|\[[A-Za-z_$][A-Za-z0-9_$]*\]'
        r'|\[\d+\])*$'
    )

    # Operator chars that flag augmented / compound assignment when
    # they appear immediately before ``=``. The ``_ASSIGNMENT_OP_PATTERN``
    # negative lookbehind only excludes ``!<>=`` (comparison shapes), so
    # ``+=``, ``-=``, ``*=``, ``/=``, ``%=``, ``&=``, ``|=``, ``^=``,
    # ``@=`` slip through and surface a stray operator in the LHS slice.
    _AUGMENTED_OP_TRAILING_CHARS = frozenset('+-*/%&|^@:')

    def _extract_assignment_lhs(
        self, file_path: str, line_number: int,
    ) -> Optional[str]:
        """Return the LHS of the assignment on ``line_number`` of
        ``file_path``, or ``None`` if extraction isn't safe.

        Strategy: read line N (via the shared file-content cache),
        locate the first ``=`` via ``_ASSIGNMENT_OP_PATTERN``, strip
        the substring before it, then validate.

        Defenses (all silently return None on violation):
          - Path resolved once, then containment check + all subsequent
            ops use the resolved path — eliminates symlink TOCTOU.
          - File must exist and be ≤1 MB (matches the snippet cap).
          - Line must contain an ``=`` somewhere past column 0.
          - LHS must match ``_SAFE_LHS_PATTERN`` (positive whitelist:
            identifier path with optional ``.`` / ``[]`` accessors,
            no quoted keys, no parens, no comment prefixes, no type
            annotations, no augmented-assignment operators).
          - LHS must not match any known credential-shape pattern —
            blocks the edge case where the variable name itself
            is a credential literal (e.g.
            ``AKIAFIXTURE000000000 = "marker"``).
        """
        try:
            src_path = Path(file_path)
            if not src_path.is_absolute():
                src_path = self.project_path / src_path
            # Resolve ONCE; subsequent ops use the resolved inode-bound
            # path so a symlink swap mid-call can't redirect the read.
            resolved = src_path.resolve(strict=True)
        except (OSError, RuntimeError):
            return None
        if not is_within(resolved, self.project_path):
            return None
        lines = self._read_file_lines_shared(resolved)
        if lines is None or line_number < 1 or line_number > len(lines):
            return None
        line = lines[line_number - 1]
        m = BaseYAMLBuilder._ASSIGNMENT_OP_PATTERN.search(line)
        if not m or m.start() == 0:
            return None
        lhs = line[: m.start()].rstrip()
        if not lhs or len(lhs) > 120:
            return None
        # Trailing augmented-assignment operator (``KEY +=``) means the
        # match was on ``=`` of a compound op; reject so we don't
        # surface the operator as part of the variable name.
        if lhs[-1] in self._AUGMENTED_OP_TRAILING_CHARS:
            return None
        lhs = lhs.lstrip()
        if not self._SAFE_LHS_PATTERN.match(lhs):
            return None
        # Defense in depth against the only known re-leak vector: a
        # variable name that itself matches a credential shape. The
        # invariant treats names as public, but this guards against
        # the pathological case (and the scanner-off-by-one case
        # where ``line_number`` lands on a credential-shaped
        # identifier line).
        if BaseYAMLBuilder._lhs_looks_like_credential(lhs):
            return None
        return lhs

    # Credential-shape heuristics applied to the extracted LHS. We
    # don't try to be exhaustive — only the high-confidence vendor
    # prefixes plus a generic "≥24-char base62" cliff. False
    # positives just lose the description hint; never leak.
    _CREDENTIAL_SHAPED_LHS_PATTERNS = (
        re.compile(r'^AKIA[0-9A-Z]{16}$'),                # AWS access key
        re.compile(r'^ghp_[A-Za-z0-9]{36}$'),             # GitHub PAT
        re.compile(r'^gho_[A-Za-z0-9]{36}$'),             # GitHub OAuth
        re.compile(r'^sk_(?:live|test)_[A-Za-z0-9]{16,}$'), # Stripe
        re.compile(r'^xox[abprs]-[A-Za-z0-9-]{10,}$'),    # Slack
        # Generic high-entropy cliff: 32+ chars of [A-Za-z0-9_-] with
        # no dots / brackets (so legitimate dotted paths like
        # ``process.env.SOME_LONG_NAME_THAT_IS_32_CHARS`` survive).
        re.compile(r'^[A-Za-z0-9_-]{32,}$'),
    )

    @staticmethod
    def _lhs_looks_like_credential(lhs: str) -> bool:
        return any(
            pat.match(lhs)
            for pat in BaseYAMLBuilder._CREDENTIAL_SHAPED_LHS_PATTERNS
        )

    def _read_file_lines_shared(self, resolved_path: Path) -> Optional[list]:
        """Return ``resolved_path`` as a list of lines, cached per
        builder instance. Returns None on encoding error / oversized
        file / read failure.

        ``resolved_path`` MUST already be containment-checked by the
        caller — this method does not re-verify. Cache key is the
        string form of the resolved path so callers passing the same
        canonical path get one read.

        Encoding strategy is strict UTF-8: a binary file masquerading
        as text returns None rather than producing a string of
        ``\\ufffd`` characters interspersed with bytes that could
        accidentally satisfy the LHS-shape whitelist.

        Lines are split on ``\\n`` only (not ``splitlines()``) to
        match the line-numbering convention every brass scanner
        uses — avoids off-by-one when a file contains rare unicode
        separators (U+2028 / U+2029) that ``splitlines()`` would
        treat as line breaks.
        """
        cache = getattr(self, '_file_content_cache', None)
        if cache is None:
            cache = {}
            self._file_content_cache = cache
        key = str(resolved_path)
        if key in cache:
            return cache[key]
        try:
            if not resolved_path.is_file():
                cache[key] = None
                return None
            if resolved_path.stat().st_size > 1 * 1024 * 1024:
                cache[key] = None
                return None
            text = resolved_path.read_text(encoding='utf-8', errors='strict')
        except (OSError, UnicodeDecodeError):
            cache[key] = None
            return None
        lines = text.split('\n')
        cache[key] = lines
        return lines