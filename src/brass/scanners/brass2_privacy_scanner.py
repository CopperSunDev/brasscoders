"""
Brass2 Privacy Scanner - Pure Brass2 Architecture Implementation

Built from ground up following Brass2 principles while maintaining original sophistication:
- Single responsibility: PII detection only
- Context awareness: Test vs production file detection  
- Modular detectors: Each PII type is independent component
- Clean interfaces: Returns List[Finding] only
- No lateral dependencies: Completely independent scanner
- International coverage: UK, EU, Australia, Singapore, India patterns
- Sophisticated patterns: Advanced regex detection with validation
- Edge case handling: Robust corner case detection and validation

Maintains full functionality of original while achieving architectural excellence.
"""

import re
import hashlib
import unicodedata
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass

from brass.models.finding import Finding, FindingType, Severity
from brass.core.file_classifier import FileClassifier
from brass.core.logging_config import get_logger
from brass.core.error_handling import handle_analysis_error, safe_file_operation
from brass.core.file_integrity import FileIntegrityChecker
from brass.core.path_safety import is_within

logger = get_logger(__name__)


@dataclass
class PIIMatch:
    """Single PII detection result."""
    pattern_name: str
    match_text: str
    start_pos: int
    end_pos: int
    line_number: int
    confidence: float
    context: str


class FileContextAnalyzer:
    """Analyzes file context to distinguish test vs production patterns."""
    
    def __init__(self):
        """Initialize context analyzer with comprehensive test pattern recognition."""
        # Comprehensive test patterns for context-aware detection
        # These patterns help distinguish between test data and real sensitive information
        self.test_patterns = {
            # Standard test credit cards (industry standard test numbers)
            '4111111111111111',  # Visa test card - always passes Luhn validation
            '5555555555554444',  # MasterCard test card - commonly used in testing
            '378282246310005',   # American Express test card - official test number
            '6011111111111117',  # Discover test card - standard testing pattern
            
            # Test email domains (RFC 2606 reserved domains for testing)
            'example.com', 'test.com', 'example.org',
            'localhost', '127.0.0.1',  # Local development patterns
            
            # Common test credentials (frequently used in development)
            'test@example.com', 'admin@test.com',
            'test123', 'password123', 'admin/password',
            
            # International test patterns (official test formats where available)
            'GB82WEST12345698765432',  # Test IBAN - UK format for testing
            '123 456 7890',  # Test UK NHS number format
            'AB123456C',  # Test UK NINO format
            '1234 5678 9012',  # Test Aadhaar format (India)
            'ABCDE1234F',  # Test India PAN format
            'S1234567A',  # Test Singapore NRIC format
            '123 456 789',  # Test Australia TFN format
            '1234 56789 0'  # Test Australia Medicare format
        }
        
        # Path-component identifiers that *only* appear in test layouts. We match
        # whole path components (e.g. ``tests/``, ``__tests__/``) rather than
        # substrings, otherwise filenames like ``request.py``, ``contest.py``, or
        # ``examples_handler.py`` would be classified as test fixtures and have
        # their PII severity downgraded.
        self.test_dir_components = {
            'tests', 'test', 'spec', 'specs', 'fixture', 'fixtures',
            'mocks', 'examples', '__tests__', 'e2e',
        }
        # Filename suffixes/prefixes that signal a test file directly.
        self.test_filename_prefixes = ('test_',)
        self.test_filename_suffixes = (
            '_test.py', '.test.py', '_spec.py', '.spec.py',
            '_test.js', '.test.js', '_spec.js', '.spec.js',
            '_test.ts', '.test.ts', '_spec.ts', '.spec.ts',
        )

    def is_test_pattern(self, content: str, file_path: str) -> bool:
        """Return True if this file is a test fixture or contains canonical test data.

        We classify a file as test context if:
          (a) any path component matches a known test directory name, OR
          (b) the filename has a recognized test prefix/suffix, OR
          (c) the content contains a known test PII pattern (e.g. the standard
              ``4111111111111111`` Visa test card).

        Substring matching on the full path was too aggressive — files such as
        ``request_handler.py`` or ``contest.py`` were being downgraded as test data.
        """
        from pathlib import PurePosixPath
        path_obj = PurePosixPath(file_path.replace('\\', '/'))
        parts_lower = {p.lower() for p in path_obj.parts}
        if parts_lower & self.test_dir_components:
            return True

        name_lower = path_obj.name.lower()
        if any(name_lower.startswith(p) for p in self.test_filename_prefixes):
            return True
        if any(name_lower.endswith(s) for s in self.test_filename_suffixes):
            return True

        content_lower = content.lower()
        if any(pattern in content_lower for pattern in self.test_patterns):
            return True

        return False


class PIIDetector:
    """Base class for individual PII detectors following single responsibility."""
    
    def __init__(self, pattern_name: str, pattern: str, severity: Severity):
        self.pattern_name = pattern_name
        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.severity = severity
    
    def detect(self, content: str) -> List[PIIMatch]:
        """Detect PII patterns in content."""
        matches = []
        lines = content.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            for match in self.pattern.finditer(line):
                matches.append(PIIMatch(
                    pattern_name=self.pattern_name,
                    match_text=match.group(),
                    start_pos=match.start(),
                    end_pos=match.end(),
                    line_number=line_num,
                    confidence=0.95,  # High confidence for regex patterns
                    context=line.strip()
                ))
        
        return matches


class CreditCardDetector(PIIDetector):
    """Detects credit card numbers with brand identification and Luhn validation."""
    
    def __init__(self):
        # Combined pattern for all major credit card types
        pattern = r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'
        super().__init__("credit_card", pattern, Severity.HIGH)
    
    def detect(self, content: str) -> List[PIIMatch]:
        """Detect credit cards with brand identification and validation."""
        try:
            matches = super().detect(content)
            validated_matches = []
            
            for match in matches:
                try:
                    # Sanitize card number (remove spaces, dashes, etc.)
                    card_num = match.match_text.replace(' ', '').replace('-', '')
                    
                    # Basic length and format validation with error handling
                    if not self._is_valid_format(card_num):
                        continue
                    
                    # Luhn algorithm validation (except for test patterns)
                    # Skip Luhn validation for known test patterns to avoid false negatives
                    if not self._is_test_pattern(card_num) and not self._luhn_validate(card_num):
                        continue
                    
                    # Brand identification with safe string operations
                    if card_num.startswith('4'):
                        match.pattern_name = "visa_credit_card"
                    elif card_num.startswith('5'):
                        match.pattern_name = "mastercard_credit_card"
                    elif card_num.startswith('3'):
                        match.pattern_name = "amex_credit_card"
                    elif card_num.startswith('6'):
                        match.pattern_name = "discover_credit_card"
                    
                    # Adjust confidence based on validation results
                    match.confidence = 0.98 if self._is_test_pattern(card_num) else 0.95
                    validated_matches.append(match)
                    
                except (AttributeError, ValueError, TypeError) as e:
                    # Handle individual match processing errors gracefully
                    logger.debug(f"Error processing credit card match: {e}")
                    continue
            
            return validated_matches
            
        except Exception as e:
            # Handle any unexpected errors in credit card detection
            logger.error(f"Credit card detection failed: {e}")
            return []  # Return empty list to maintain interface contract
    
    def _is_valid_format(self, card_num: str) -> bool:
        """
        Check if card number has valid format.
        
        Args:
            card_num: Credit card number string to validate
            
        Returns:
            True if format is valid (all digits, correct length), False otherwise
        """
        return card_num.isdigit() and len(card_num) in [13, 14, 15, 16, 19]
    
    def _is_test_pattern(self, card_num: str) -> bool:
        """
        Check if this is a known test credit card number.
        
        Args:
            card_num: Credit card number to check against test patterns
            
        Returns:
            True if this is a recognized test card number, False otherwise
        """
        test_cards = {
            '4111111111111111',  # Visa test card (industry standard)
            '5555555555554444',  # MasterCard test card (industry standard)
            '378282246310005',   # American Express test card (industry standard)
            '6011111111111117'   # Discover test card (industry standard)
        }
        return card_num in test_cards
    
    def _luhn_validate(self, card_num: str) -> bool:
        """
        Validate credit card using Luhn algorithm (mod 10 check).
        
        The Luhn algorithm is used by credit card companies to distinguish
        valid numbers from mistyped or otherwise incorrect numbers.
        
        Args:
            card_num: Credit card number string to validate
            
        Returns:
            True if passes Luhn validation, False otherwise
        """
        def luhn_checksum(card_num):
            """Calculate Luhn checksum for given card number."""
            def digits_of(n):
                """Convert number to list of digits."""
                return [int(d) for d in str(n)]
            
            digits = digits_of(card_num)
            odd_digits = digits[-1::-2]  # Every second digit from right to left
            even_digits = digits[-2::-2]  # Remaining digits
            checksum = sum(odd_digits)
            for d in even_digits:
                checksum += sum(digits_of(d*2))  # Double and sum digits
            return checksum % 10
        
        return luhn_checksum(card_num) == 0


class SSNDetector(PIIDetector):
    """Detects US Social Security Numbers (dashed format only).

    The original regex also matched `\\b\\d{9}\\b` (un-dashed 9-digit
    runs), which produced massive false-positive rates in source code:
    LinkedIn URNs, file-size byte counts, GA4 property IDs, image-pixel
    constants — anything with a 9-digit substring was a candidate. Real
    SSNs in code/docs are conventionally written with dashes; the
    recall loss from requiring dashes is negligible compared to the
    FP reduction (4 of 4 round-4 brass-seo SSN FPs were un-dashed).
    """

    def __init__(self):
        pattern = r'\b\d{3}-\d{2}-\d{4}\b'
        super().__init__("us_ssn", pattern, Severity.HIGH)

    def detect(self, content: str) -> List[PIIMatch]:
        """Detect SSNs with validation + known-test-value deny-list."""
        from brass.scanners._known_test_values import is_test_ssn, looks_like_sentry_dsn

        matches = super().detect(content)
        # If the surrounding content is a Sentry DSN, the 32-hex-char key
        # often contains substrings that look like 9-digit SSN matches.
        # Skip the entire content in that case rather than emitting one
        # FP per substring.
        if looks_like_sentry_dsn(content):
            return []

        validated_matches = []
        for match in matches:
            # Drop known-test values entirely (deny-list pre-launch fix).
            if is_test_ssn(match.match_text):
                continue
            ssn = match.match_text.replace('-', '')
            if self._is_valid_ssn(ssn):
                match.confidence = 0.95
                validated_matches.append(match)
        return validated_matches
    
    def _is_valid_ssn(self, ssn: str) -> bool:
        """Validate SSN according to SSA rules."""
        if len(ssn) != 9 or not ssn.isdigit():
            return False
        
        area = ssn[:3]
        group = ssn[3:5]
        serial = ssn[5:9]
        
        # Invalid area numbers
        if area in ['000', '666'] or area.startswith('9'):
            return False
        
        # Invalid group numbers
        if group == '00':
            return False
        
        # Invalid serial numbers
        if serial == '0000':
            return False
        
        return True
    
    def _is_test_ssn(self, ssn: str) -> bool:
        """Check if this is a known test SSN."""
        test_ssns = {'123456789', '987654321', '111111111', '222222222'}
        return ssn in test_ssns


class EmailDetector(PIIDetector):
    """Detects email addresses. Filters obvious test/no-reply addresses
    and Sentry-DSN content (whose o<digits>@<host>.ingest.sentry.io
    format matches the email regex but isn't an email)."""

    def __init__(self):
        pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        super().__init__("email_address", pattern, Severity.MEDIUM)

    def detect(self, content: str) -> List[PIIMatch]:
        from brass.scanners._known_test_values import is_benign_email, looks_like_sentry_dsn
        # C.9: Sentry DSN URLs contain o<digits>@<host>.ingest.sentry.io
        # patterns that match the email regex. The whole content is a
        # Sentry config string — skip all email matches in it.
        if looks_like_sentry_dsn(content):
            return []
        return [m for m in super().detect(content) if not is_benign_email(m.match_text)]


class PhoneDetector(PIIDetector):
    """Detects phone numbers in dashed, parens, and 10-digit formats.

    The parens form uses (?<!\\w)/(?!\\w) lookarounds instead of \\b because
    \\b requires a word/non-word transition and `\\(` is non-word: in
    `phone (555) 123-4567` the space-then-`(` boundary has non-word on
    both sides, so \\b doesn't match there. The lookbehind/lookahead form
    asks "no word character immediately before `(` and immediately after
    the closing digit," which correctly catches the canonical formats
    while still rejecting substring matches inside identifiers.
    """

    def __init__(self):
        pattern = (
            r'\b\d{3}-\d{3}-\d{4}\b'                          # 555-123-4567
            r'|(?<!\w)\(\d{3}\)\s?\d{3}-\d{4}(?!\w)'          # (555) 123-4567 / (555)123-4567
            r'|\b\d{10}\b'                                     # 5551234567
        )
        super().__init__("phone_number", pattern, Severity.MEDIUM)


class IPAddressDetector(PIIDetector):
    """Detects IP addresses. Filters loopback, RFC 1918 private, and
    RFC 5737 documentation ranges (no PII signal)."""

    def __init__(self):
        pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        super().__init__("ip_address", pattern, Severity.LOW)

    def detect(self, content: str) -> List[PIIMatch]:
        from brass.scanners._known_test_values import is_benign_ip
        return [m for m in super().detect(content) if not is_benign_ip(m.match_text)]


class UKNHSDetector(PIIDetector):
    """Detects UK NHS Numbers."""
    
    def __init__(self):
        pattern = r'\b\d{3}\s?\d{3}\s?\d{4}\b'
        super().__init__("uk_nhs", pattern, Severity.HIGH)


class UKNINODetector(PIIDetector):
    """Detects UK National Insurance Numbers."""
    
    def __init__(self):
        pattern = r'\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D]\b'
        super().__init__("uk_nino", pattern, Severity.HIGH)


class IndiaAadhaarDetector(PIIDetector):
    """Detects India Aadhaar Numbers. Filters Stripe test card prefixes
    and known Aadhaar test values (the 12-digit regex collides with
    documented payment-card test fixtures)."""

    def __init__(self):
        pattern = r'\b\d{4}\s?\d{4}\s?\d{4}\b'
        super().__init__("india_aadhaar", pattern, Severity.HIGH)

    def detect(self, content: str) -> List[PIIMatch]:
        from brass.scanners._known_test_values import (
            is_aadhaar_test_value,
            is_stripe_test_card,
        )
        out = []
        for m in super().detect(content):
            if is_aadhaar_test_value(m.match_text):
                continue
            # Stripe 16-digit test cards often produce 12-digit
            # subspan hits that the Aadhaar regex accepts. Check the
            # match against the wider digit-group context.
            digits = re.sub(r'\D', '', m.match_text)
            if is_stripe_test_card(digits):
                continue
            # Also check if the 12 digits are a substring of any 16-digit
            # Stripe test card found earlier in the content.
            sixteen_digit_neighbors = re.findall(
                r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', content,
            )
            if any(is_stripe_test_card(n) for n in sixteen_digit_neighbors):
                continue
            out.append(m)
        return out


class IndiaPANDetector(PIIDetector):
    """Detects India PAN Numbers."""
    
    def __init__(self):
        pattern = r'\b[A-Z]{5}\d{4}[A-Z]\b'
        super().__init__("india_pan", pattern, Severity.HIGH)


class SingaporeNRICDetector(PIIDetector):
    """Detects Singapore NRIC/FIN Numbers."""
    
    def __init__(self):
        pattern = r'\b[STFG]\d{7}[A-Z]\b'
        super().__init__("singapore_nric", pattern, Severity.HIGH)


class AustraliaTFNDetector(PIIDetector):
    """Detects Australia Tax File Numbers."""
    
    def __init__(self):
        pattern = r'\b\d{3}\s?\d{3}\s?\d{3}\b'
        super().__init__("australia_tfn", pattern, Severity.HIGH)


class AustraliaMedicareDetector(PIIDetector):
    """Detects Australia Medicare Numbers."""
    
    def __init__(self):
        pattern = r'\b\d{4}\s?\d{5}\s?\d{1}\b'
        super().__init__("australia_medicare", pattern, Severity.HIGH)


class IBANDetector(PIIDetector):
    """Detects International Bank Account Numbers."""
    
    def __init__(self):
        pattern = r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}[A-Z0-9]{0,16}\b'
        super().__init__("iban", pattern, Severity.HIGH)


class EUVATDetector(PIIDetector):
    """Detects EU VAT Numbers."""
    
    def __init__(self):
        pattern = r'\b[A-Z]{2}\d{8,12}\b'
        super().__init__("eu_vat", pattern, Severity.MEDIUM)


class UKPhoneDetector(PIIDetector):
    """Detects UK Phone Numbers in +44 international and 0-prefix domestic formats.

    Uses (?<!\\w)/(?!\\w) lookarounds instead of \\b on the leading anchor
    because the `+44` alternative starts with `+` (non-word). With \\b,
    a space-then-`+44` sequence has non-word on both sides and no boundary,
    so `Call me at +447123456789` would silently miss. The lookbehind form
    requires "no word character immediately before the number," which
    catches both the `+44...` and `0...` alternatives in any position.
    """

    def __init__(self):
        pattern = r'(?<!\w)(?:\+44|0)\d{10}(?!\w)'
        super().__init__("uk_phone", pattern, Severity.MEDIUM)




class Brass2PrivacyScanner:
    """
    Pure Brass2 privacy scanner following architectural principles:
    - Single responsibility: PII detection only
    - Context awareness: Test vs production distinction
    - Modular design: Independent PII detectors
    - Clean interface: Returns List[Finding]
    """
    
    def __init__(self, project_path: str):
        """Initialize with modular PII detectors and input validation."""
        # Input validation for security hardening
        if not project_path:
            raise ValueError("Project path cannot be empty or None")
        
        # Convert to Path object and validate existence
        self.project_path = Path(project_path)
        if not self.project_path.exists():
            raise FileNotFoundError(f"Project path does not exist: {project_path}")
        
        # Validate that path is a directory
        if not self.project_path.is_dir():
            raise ValueError(f"Project path must be a directory: {project_path}")
        
        # Security check: Ensure path is not a symbolic link to prevent path traversal
        if self.project_path.is_symlink():
            logger.warning(f"Project path is a symbolic link: {project_path}")
        
        # Initialize components with validated path
        self.file_classifier = FileClassifier(str(self.project_path))
        self.context_analyzer = FileContextAnalyzer()
        
        # Modular PII detectors - each with single responsibility
        self.detectors = [
            # US/General patterns
            CreditCardDetector(),
            SSNDetector(),
            EmailDetector(),
            PhoneDetector(),
            IPAddressDetector(),
            
            # International PII patterns
            UKNHSDetector(),
            UKNINODetector(),
            UKPhoneDetector(),
            IndiaAadhaarDetector(),
            IndiaPANDetector(),
            SingaporeNRICDetector(),
            AustraliaTFNDetector(),
            AustraliaMedicareDetector(),
            
            # Financial/Business patterns
            IBANDetector(),
            EUVATDetector()
        ]
    
    def scan(self, file_paths: Optional[List[str]] = None) -> List[Finding]:
        """
        Scan for PII with context awareness.

        Args:
            file_paths: When provided, scan exactly these files instead of
                walking the project. Matches every other scanner's contract;
                IncrementalAnalyzer (watch mode) and FilePrefilterScanner
                pre-narrow the file list and pass it through.
        
        Returns:
            List[Finding] - Sacred Brass2 interface
        """
        findings = []
        target_extensions = {'.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.cpp', '.c', '.h',
                           '.cs', '.php', '.rb', '.go', '.rs', '.swift', '.kt', '.scala',
                           '.sql', '.yaml', '.yml', '.json', '.xml', '.env', '.config',
                           '.properties', '.ini', '.toml', '.md', '.txt'}

        # Honor caller's file list when supplied (matches every other scanner)
        # otherwise fall through to full project discovery.
        if file_paths:
            files_iter = (Path(p) if not isinstance(p, Path) else p for p in file_paths)
            # Same exclusion rules as the discovery path: build outputs,
            # archives, test fixtures, and other non-source paths must be
            # filtered out even when the caller hands us an explicit list.
            # Previously this branch skipped the exclusion check, so .next/
            # / _archive/ etc. would slip through and produce FP findings.
            files_to_scan = [
                p for p in files_iter
                if p.suffix.lower() in target_extensions
                and not self.file_classifier.should_exclude_from_analysis(str(p))
            ]
        else:
            files_to_scan = self._discover_files(target_extensions)

        # Cache resolved project root once. Resolving on every file iteration
        # was a per-file syscall multiplied across 5k+-file projects.
        resolved_project_path = self.project_path.resolve()

        for file_path in files_to_scan:
            relative_path = "unknown_file"  # Default for error handling

            try:
                resolved_file_path = file_path.resolve()
                relative_path = str(resolved_file_path.relative_to(resolved_project_path))
                
                def read_content() -> str:
                    content = FileIntegrityChecker.read_with_integrity_check(
                        file_path, encoding='utf-8', errors='ignore'
                    )
                    if content is None:
                        logger.warning(f"File modified during read, returning empty: {file_path}")
                        return ""
                    return content
                
                content = safe_file_operation(
                    relative_path, read_content, "Brass2PrivacyScanner", "read_file", ""
                )
                
                if not content or not content.strip():
                    continue
                
                # Analyze file context for test vs production
                is_test_context = self.context_analyzer.is_test_pattern(content, relative_path)
                file_context = self.file_classifier.classify_file(relative_path)
                
                # Run all PII detectors
                file_findings = self._scan_file_content(content, relative_path, is_test_context, file_context)
                findings.extend(file_findings)
                
            except Exception as e:
                handle_analysis_error("PII content", "Brass2PrivacyScanner", "scan_file", e, relative_path)
                continue
        
        return findings
    
    def _scan_file_content(self, content: str, file_path: str, is_test_context: bool, file_context) -> List[Finding]:
        """Scan file content with all PII detectors and intelligent context filtering.

        Raw matched text and context lines are kept in metadata only long enough for the
        suppression heuristic to evaluate them, then redacted before the finding leaves
        the scanner. Anything that survives into ``Finding.metadata`` is safe to serialize.
        """
        findings = []

        for detector in self.detectors:
            matches = detector.detect(content)

            for match in matches:
                # Preliminary finding has raw text in metadata so the suppression heuristic
                # can scan for pattern-definition indicators (e.g. 'test_patterns', 'regex').
                preliminary_finding = Finding(
                    id=f"brass2_privacy_{hash(file_path)}_{match.pattern_name}_{match.line_number}_{match.start_pos}",
                    type=FindingType.PRIVACY,
                    severity=detector.severity,
                    file_path=file_path,
                    line_number=match.line_number,
                    title=self._get_finding_title(match.pattern_name),
                    description=f"Detected {self._get_finding_title(match.pattern_name)}: {self._mask_content(match.match_text)}",
                    remediation=self._get_remediation(match.pattern_name, is_test_context),
                    confidence=match.confidence,
                    detected_by="Brass2PrivacyScanner",
                    metadata={
                        'pattern_type': match.pattern_name,
                        'is_test_context': is_test_context,
                        'context_line': match.context,
                        'matched_text': match.match_text,
                        'code_snippet': match.context,
                        'file_context': {
                            'file_type': file_context.file_type.value,
                            'is_test_related': file_context.is_test_related(),
                            'is_source_code': file_context.is_source_code(),
                            'priority_weight': file_context.priority_weight
                        },
                        'why_flagged': self._explain_detection(match.pattern_name, is_test_context)
                    }
                )

                # Apply universal scanner self-flagging prevention while raw text is still
                # present (the heuristic needs it).
                processed_finding = self._apply_universal_context_awareness(preliminary_finding)

                # Apply context-aware severity adjustment.
                processed_finding.severity = self._adjust_severity_for_context(
                    processed_finding.severity, is_test_context, match.match_text
                )

                # Redact raw PII from metadata before the finding is returned.
                self._redact_pii_metadata(processed_finding)

                findings.append(processed_finding)

        # C.8b: consolidate same-(file, line) hits across detectors.
        # When multiple PII detectors fire on the same line — e.g. one
        # 12-digit string matches Aadhaar AND looks NHS-shaped AND fits
        # a phone-number regex — they emit three findings that share a
        # location. Round 5 triage flagged this as noise: the downstream
        # AI coder makes one decision per location, not N. Collapse into
        # a single finding whose `pii_types` lists all detector names.
        return self._consolidate_same_line_findings(findings)

    def _consolidate_same_line_findings(self, findings: List[Finding]) -> List[Finding]:
        """Merge findings sharing the same (file_path, line_number) into
        a single PII-types-list finding. Preserves severity = max,
        confidence = max, and records the merged detector names in
        metadata['pii_types']."""
        from collections import OrderedDict

        groups: "OrderedDict[tuple, List[Finding]]" = OrderedDict()
        for f in findings:
            key = (f.file_path, f.line_number)
            groups.setdefault(key, []).append(f)

        # Severity priority for picking the max — match the Severity enum
        # ordering rather than alphabetic.
        severity_rank = {
            Severity.CRITICAL: 4, Severity.HIGH: 3,
            Severity.MEDIUM: 2, Severity.LOW: 1, Severity.INFO: 0,
        }

        out: List[Finding] = []
        for key, group in groups.items():
            if len(group) == 1:
                out.append(group[0])
                continue

            # Build merged title from all pii_types in the group.
            type_names = []
            seen = set()
            for g in group:
                t = (g.metadata or {}).get('pattern_type') if isinstance(g.metadata, dict) else None
                if t and t not in seen:
                    seen.add(t)
                    type_names.append(t)

            rep = max(group, key=lambda f: severity_rank.get(f.severity, 0))
            rep.title = (
                f"Multiple PII patterns at this location ({len(type_names)}): "
                + ", ".join(self._get_finding_title(t) for t in type_names)
            )
            rep.description = (
                f"This {len(type_names)} PII detectors fired on the same "
                f"(file, line): {', '.join(type_names)}. The digit pattern "
                f"matches multiple PII shapes; one or none may be real. "
                f"Review the line and choose the correct classification "
                f"(or suppress via .brassignore if none apply)."
            )
            rep.confidence = max(g.confidence for g in group)
            if not isinstance(rep.metadata, dict):
                rep.metadata = {}
            rep.metadata['pii_types'] = type_names
            rep.metadata['consolidated_from'] = len(group)
            out.append(rep)

        return out

    def _redact_pii_metadata(self, finding: Finding) -> None:
        """Remove raw matched PII from ``finding.metadata`` in place.

        The privacy scanner exists to *detect* sensitive data; emitting the raw match into
        ``.brass/`` would defeat that purpose. We replace ``matched_text`` with the masked
        form (preserving length-class hints for downstream UX) and drop the surrounding
        ``code_snippet`` / ``context_line`` entirely.
        """
        if not finding.metadata:
            return

        if 'matched_text' in finding.metadata:
            finding.metadata['matched_text'] = self._mask_content(finding.metadata['matched_text'])
        finding.metadata.pop('code_snippet', None)
        finding.metadata.pop('context_line', None)
        finding.metadata['pii_redacted'] = True

        # The Finding's top-level code_snippet field is also a leak vector.
        if finding.code_snippet:
            finding.code_snippet = None
    
    def _apply_universal_context_awareness(self, finding: Finding) -> Finding:
        """
        Universal scanner self-flagging prevention and context awareness.
        
        Prevents any scanner from flagging pattern definitions in:
        - Scanner source files (any scanner, any project)
        - Configuration files containing patterns
        - Documentation describing patterns
        - Analysis artifacts from previous scans
        
        Works universally across client projects by detecting pattern indicators
        rather than hardcoded paths.
        
        Args:
            finding: Finding to evaluate and potentially suppress
            
        Returns:
            Finding with context-aware adjustments applied
        """
        file_path = finding.file_path.lower()

        # Match path components, not substrings. The original
        # ``'brass' in file_path`` matched any project whose path contained
        # the word "brass" anywhere (including this codebase, where every
        # file is under .../brass/...). Same for "security", "analysis", etc.
        # — fine when used to detect brass's own scanner files, lethal when
        # applied to a customer's "brass-foundry" or "security-platform"
        # project, where every legit privacy finding got demoted to LOW.
        from pathlib import PurePosixPath
        path_parts = {p.lower() for p in PurePosixPath(file_path.replace('\\', '/')).parts}
        scanner_dirs = {'scanners', 'detectors', 'analyzers'}
        scanner_filename_tokens = ('_scanner.', '_detector.', '_analyzer.', 'patterns.py')
        name_lower = PurePosixPath(file_path).name.lower()
        is_scanner_file = bool(path_parts & scanner_dirs) or any(
            tok in name_lower for tok in scanner_filename_tokens
        )
        
        # Universal analysis artifact detection (prevents contamination in any project)
        is_analysis_artifact = (
            '.brass' in file_path or
            'analysis' in file_path or
            'report' in file_path or
            'findings' in file_path or
            'privacy_analysis' in file_path or
            'security_report' in file_path or
            'detailed_analysis' in file_path or
            'ai_instructions' in file_path or
            '_analysis.' in file_path or
            '.analysis_' in file_path
        )
        
        # Universal configuration file detection
        is_config_file = (
            'config' in file_path or
            'pattern' in file_path or
            '.yaml' in file_path and ('pattern' in file_path or 'config' in file_path) or
            '.json' in file_path and ('pattern' in file_path or 'config' in file_path)
        )
        
        if not (is_scanner_file or is_analysis_artifact or is_config_file):
            return finding
            
        # Get the context for pattern definition detection
        code_snippet = finding.metadata.get('code_snippet', '')
        line_content = finding.metadata.get('context_line', '')
        matched_text = finding.metadata.get('matched_text', '')
        
        # Universal pattern definition indicators (works across languages and formats)
        pattern_indicators = [
            # Python/code patterns
            'pattern', 'regex', 'r\'', 'r"', '\'pattern\':', '"pattern":', 'pattern=',
            'test_patterns', 'example_patterns', 'fallback_patterns', 'default_patterns',
            '_patterns', 'get_patterns', 'pattern_config', 'pattern_definition',
            
            # YAML/config patterns  
            'pattern:', 'patterns:', 'test_data:', 'example_data:', 'sample_data:',
            'examples:', 'test_cases:', 'fixtures:', 'mock_data:',
            
            # Documentation patterns. Bare ``'test'`` removed — it caused
            # over-suppression on substrings of words like ``attest``,
            # ``latest``, ``manifest``, ``protest``, ``tester``. Test-context
            # downgrades happen earlier via ``is_test_pattern`` which uses
            # whole-component matching.
            'example', 'sample', 'demo', 'illustration', 'documentation',
            'docs', 'readme', 'guide', 'tutorial', 'reference',
            
            # Privacy-specific patterns
            'credit_card', 'visa_test', 'mastercard_test', 'test_card',
            'test_ssn', 'example_ssn', 'sample_phone', 'dummy_data',
            'pii_test', 'privacy_test', 'test_pii', 'mock_pii',
            
            # Universal test indicators
            'test', 'mock', 'fixture', 'stub', 'fake', 'dummy', 'placeholder'
        ]
        
        # Check if the context suggests this is a pattern definition
        combined_content = f"{code_snippet} {line_content} {matched_text}".lower()
        context_suggests_pattern = any(
            indicator in combined_content
            for indicator in pattern_indicators
        )
        
        if context_suggests_pattern:
            # Suppress with clear audit trail
            finding.severity = Severity.LOW
            finding.confidence = 0.1  # Very low confidence
            finding.description = f"Pattern definition (auto-suppressed): {finding.description}"
            finding.metadata['context_adjustment'] = 'universal_scanner_pattern_suppressed'
            finding.metadata['suppression_reason'] = 'Scanner flagging pattern definition in scanner/config/docs'
            finding.metadata['pattern_indicators_found'] = [
                indicator for indicator in pattern_indicators 
                if indicator in combined_content
            ]
            
            logger.debug(
                f"UNIVERSAL SUPPRESSION: Privacy scanner flagging pattern definition in "
                f"{finding.file_path}:{finding.line_number} - "
                f"detected indicators: {finding.metadata['pattern_indicators_found']}"
            )
            return finding
        
        # Universal analysis artifact suppression
        if is_analysis_artifact:
            finding.severity = Severity.LOW
            finding.confidence = 0.05
            finding.description = f"Analysis artifact (auto-suppressed): {finding.description}"
            finding.metadata['context_adjustment'] = 'universal_analysis_artifact_suppressed'
            finding.metadata['suppression_reason'] = 'Scanner flagging previous analysis output'
            
            logger.debug(
                f"UNIVERSAL SUPPRESSION: Analysis artifact contamination prevented in "
                f"{finding.file_path}:{finding.line_number}"
            )
            return finding
            
        return finding
    
    def _adjust_severity_for_context(self, base_severity: Severity, is_test_context: bool, content: str) -> Severity:
        """
        Adjust severity based on test context while maintaining detection.
        
        Args:
            base_severity: Original severity level from detector
            is_test_context: Whether the finding is in a test context
            content: The matched content for additional context analysis
            
        Returns:
            Adjusted severity level appropriate for the context
        """
        if is_test_context:
            # Reduce severity for test contexts but still flag for review
            if base_severity == Severity.HIGH:
                return Severity.MEDIUM
            elif base_severity == Severity.MEDIUM:
                return Severity.LOW
        
        return base_severity
    
    def _get_finding_title(self, pattern_name: str) -> str:
        """Get human-readable title for pattern."""
        titles = {
            # US/General patterns
            'visa_credit_card': 'Visa Credit Card Number',
            'mastercard_credit_card': 'MasterCard Credit Card Number', 
            'amex_credit_card': 'American Express Credit Card Number',
            'discover_credit_card': 'Discover Credit Card Number',
            'credit_card': 'Credit Card Number',
            'us_ssn': 'US Social Security Number',
            'email_address': 'Email Address',
            'phone_number': 'Phone Number',
            'ip_address': 'IP Address',
            
            # International PII patterns
            'uk_nhs': 'UK NHS Number',
            'uk_nino': 'UK National Insurance Number',
            'uk_phone': 'UK Phone Number',
            'india_aadhaar': 'India Aadhaar Number',
            'india_pan': 'India PAN Number',
            'singapore_nric': 'Singapore NRIC/FIN',
            'australia_tfn': 'Australia Tax File Number',
            'australia_medicare': 'Australia Medicare Number',
            
            # Financial/Business patterns
            'iban': 'International Bank Account Number',
            'eu_vat': 'EU VAT Number'
        }
        return titles.get(pattern_name, pattern_name.replace('_', ' ').title())
    
    def _get_remediation(self, pattern_name: str, is_test_context: bool) -> str:
        """Get context-aware remediation advice."""
        if is_test_context:
            return f"Verify this is intentional test data. If so, consider adding clear test context markers."
        
        remediations = {
            # US/General patterns
            'visa_credit_card': 'Replace with test card numbers (4111111111111111) or use environment variables',
            'mastercard_credit_card': 'Replace with test card numbers (5555555555554444) or use environment variables',
            'amex_credit_card': 'Replace with test card numbers (378282246310005) or use environment variables',
            'us_ssn': 'Replace with test SSN (123-45-6789) or use environment variables',
            'email_address': 'Replace with example.com domains or use environment variables',
            'phone_number': 'Use test numbers (555-xxx-xxxx) or environment variables',
            'ip_address': 'Use private IP ranges (192.168.x.x, 10.x.x.x) or environment variables',
            
            # International PII patterns
            'uk_nhs': 'Replace with test NHS number or use environment variables',
            'uk_nino': 'Use test NINO format or environment variables',
            'uk_phone': 'Replace with test UK numbers or environment variables',
            'india_aadhaar': 'Replace with test Aadhaar or secure storage',
            'india_pan': 'Use test PAN format or environment variables',
            'singapore_nric': 'Replace with test NRIC or secure configuration',
            'australia_tfn': 'Use test TFN or environment variables',
            'australia_medicare': 'Replace with test Medicare number',
            
            # Financial/Business patterns
            'iban': 'Use test IBAN or environment variables',
            'eu_vat': 'Replace with test VAT number or configuration'
        }
        return remediations.get(pattern_name, 'Replace with test data or move to secure configuration')
    
    def _explain_detection(self, pattern_name: str, is_test_context: bool) -> str:
        """Explain why this was flagged."""
        if is_test_context:
            return "Detected in test context - verify this is intentional test data"
        else:
            return "Detected in production code - potential privacy/security risk"
    
    def _mask_content(self, content: str) -> str:
        """Mask sensitive content for safe display.

        Previously revealed first-4 + last-4 characters. Security
        review (2026-05-15) flagged this as still-identifying for
        common PII shapes: last-4 of a 16-digit credit card is what
        bank statements expose, last-4 of an SSN plus the area code
        prefix is enough to deanonymize against breach databases,
        first-4 + last-4 of an email still reveals the domain.

        The mask now reveals only the length of the original value,
        not any of its content. AI consumers get "PII detected, value
        16 chars" — enough to know "this is likely a card" without
        getting any of the digits. Consult the source file directly
        for triage; do not rely on the brass output to carry the
        value.
        """
        return f"[REDACTED — {len(content)}-char value]"
    
    def _discover_files(self, target_extensions: Set[str]) -> List[Path]:
        """
        Discover files to scan with proper project scope validation.
        
        This method implements intelligent file discovery following Brass2 principles:
        - Precise filtering to avoid unnecessary scanning
        - Performance optimization through early filtering  
        - Security considerations (file size limits, path validation)
        
        Args:
            target_extensions: Set of file extensions to include (e.g., {'.py', '.js'})
            
        Returns:
            List of Path objects representing files to scan
            
        Note:
            Files larger than 1MB are automatically skipped for performance reasons.
            Hidden files, build artifacts, and common non-source directories are excluded.
        """
        discovered_files = []
        
        # Ensure we're scanning the intended project directory only
        project_root = self.project_path.resolve()
        
        try:
            for file_path in project_root.rglob('*'):
                # Skip non-files (directories, symlinks, etc.)
                if not file_path.is_file():
                    continue

                # Boundary check: refuse to follow symlinks that escape the project
                # root (CVE-class issue — a malicious repo could symlink to
                # ~/.ssh/id_rsa and we'd happily scan it for "PII patterns").
                if not is_within(file_path, project_root):
                    logger.debug(f"Skipping path outside project root: {file_path}")
                    continue

                # Performance optimization: check extension early
                if file_path.suffix.lower() not in target_extensions:
                    continue

                # Apply filtering rules for security and performance
                if self._should_skip_file(file_path):
                    continue
                    
                # Apply FileClassifier exclusions to prevent processing build artifacts
                if self.file_classifier.should_exclude_from_analysis(str(file_path)):
                    continue
                    
                try:
                    # Security: Skip excessively large files (>1MB) to prevent DoS
                    if file_path.stat().st_size > 1024 * 1024:
                        logger.debug(f"Skipping large file: {file_path} ({file_path.stat().st_size} bytes)")
                        continue
                except OSError as e:
                    # Handle file access errors gracefully
                    logger.debug(f"Cannot access file stats for {file_path}: {e}")
                    continue
                    
                discovered_files.append(file_path)
                
        except Exception as e:
            # Handle any unexpected errors during file discovery
            logger.error(f"Error during file discovery: {e}")
            # Continue with empty list rather than crashing
        
        logger.debug(f"Discovered {len(discovered_files)} files to scan")
        return discovered_files
    
    def _should_skip_file(self, file_path: Path) -> bool:
        """
        Check if file should be skipped using Brass2 principle: precise filtering.
        
        Args:
            file_path: Path to check
            
        Returns:
            True if file should be skipped
        """
        # Skip directories that should never be scanned
        skip_dirs = {'.git', '.svn', '.hg', '__pycache__', '.pytest_cache',
                    'node_modules', '.venv', 'venv', '.env', 'build', 'dist',
                    '.brass', '.idea', '.vscode', '.DS_Store', 'coverage'}
        
        # Check if any part of the path contains skip directories
        if any(part in skip_dirs for part in file_path.parts):
            return True
            
        # Skip hidden files (starting with .)
        if file_path.name.startswith('.'):
            return True
            
        # Skip backup and temporary files
        if file_path.name.endswith(('.bak', '.tmp', '.temp', '~')):
            return True
            
        return False