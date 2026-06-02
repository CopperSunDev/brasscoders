"""File-role classification fixes — phase C.5.

Captures the real-world miscategorizations that the brass-seo triage
exposed: TS/JS files under .next/ build output, _archive/ directories,
__tests__/ folders, and docs/ paths were all being marked
is_production_code=True. Each one was a major FP-driver.

Tests run against FileClassifier directly (low-level) and against
the YAML builders (high-level) to guard both layers.
"""

from __future__ import annotations

from collections import OrderedDict

from brass.core.file_classifier import FileClassifier, FileType


# --------------------------------------------------------------------------- #
# Low-level: FileClassifier covers the new path patterns                      #
# --------------------------------------------------------------------------- #


def _classify(path: str) -> FileType:
    return FileClassifier().classify_file(path).file_type


def test_next_build_output_is_build_output():
    assert _classify(".next/required-server-files.json") == FileType.BUILD_OUTPUT
    assert _classify(".next/server/app/api/route.js") == FileType.BUILD_OUTPUT


def test_underscored_archive_directories_are_build_output():
    # The bug: `_archive/` and `_archived/` paths were classified UNKNOWN,
    # so the YAML builder defaulted them to is_production_code=true.
    assert _classify("_archive/old.ts") == FileType.BUILD_OUTPUT
    assert _classify("_archived/old.ts") == FileType.BUILD_OUTPUT
    assert _classify("src/_archive/old.ts") == FileType.BUILD_OUTPUT


def test_dunder_tests_directories_are_test_files():
    # The bug: __tests__/ (Jest / Vitest convention) wasn't recognized,
    # so test fixtures got flagged as production code.
    assert _classify("__tests__/Button.test.tsx") == FileType.TEST_FILE
    assert _classify("components/__tests__/Header.test.tsx") == FileType.TEST_FILE


def test_dotted_test_spec_extensions_are_test_files():
    # Jest / Vitest naming: foo.test.ts, foo.spec.ts.
    assert _classify("lib/foo.test.ts") == FileType.TEST_FILE
    assert _classify("lib/foo.spec.js") == FileType.TEST_FILE


def test_dunder_mocks_directories_are_test_fixtures():
    # Top-level __mocks__ matches the JS/TS __mocks__ pattern only when
    # nested under something (components/__mocks__/...). At project root,
    # __mocks__/axios.ts is fine as TEST_FILE — same end result for the
    # user (low priority, not production code).
    assert _classify("components/__mocks__/Button.tsx") == FileType.TEST_FIXTURE
    # Root-level still classified as test-related (test or fixture, not source).
    assert _classify("__mocks__/axios.ts") in (FileType.TEST_FILE, FileType.TEST_FIXTURE)


def test_typescript_source_files_in_standard_dirs_are_source_code():
    # The bug: TS/JS source files in app/, lib/, src/ were UNKNOWN
    # because source_patterns were Python-only.
    assert _classify("src/index.ts") == FileType.SOURCE_CODE
    assert _classify("app/api/auth/route.ts") == FileType.SOURCE_CODE
    assert _classify("lib/auth.tsx") == FileType.SOURCE_CODE
    assert _classify("components/Header.tsx") == FileType.SOURCE_CODE


def test_go_and_rust_source_files_in_standard_dirs_are_source_code():
    assert _classify("pkg/handler/auth.go") == FileType.SOURCE_CODE
    assert _classify("internal/db/query.go") == FileType.SOURCE_CODE
    assert _classify("src/main.rs") == FileType.SOURCE_CODE


def test_python_classification_unchanged():
    """Regression check: existing Python rules still hold."""
    assert _classify("src/brass/cli.py") == FileType.SOURCE_CODE
    assert _classify("tests/unit/test_foo.py") == FileType.TEST_FILE
    assert _classify("tests/fixtures/sample.py") == FileType.TEST_FIXTURE


# --------------------------------------------------------------------------- #
# High-level: YAML builder produces correct is_production_code                #
# --------------------------------------------------------------------------- #


def test_ai_instructions_builder_marks_next_build_output_as_non_production():
    """The big one: .next/required-server-files.json must NOT be flagged
    as production code in the YAML output."""
    from datetime import datetime, timezone
    from brass.output.yaml_builders.ai_instructions_builder import YAMLAIInstructionsBuilder
    builder = YAMLAIInstructionsBuilder(project_path=".", generation_time=datetime.now(timezone.utc))
    ctx = builder._classify_via_file_classifier(".next/required-server-files.json")
    assert ctx["is_production_code"] is False
    assert ctx["priority_for_ai"] == "LOW"


def test_ai_instructions_builder_marks_archive_as_non_production():
    from datetime import datetime, timezone
    from brass.output.yaml_builders.ai_instructions_builder import YAMLAIInstructionsBuilder
    builder = YAMLAIInstructionsBuilder(project_path=".", generation_time=datetime.now(timezone.utc))
    ctx = builder._classify_via_file_classifier("_archive/old_auth.ts")
    assert ctx["is_production_code"] is False
    assert ctx["priority_for_ai"] == "LOW"


def test_ai_instructions_builder_marks_dunder_tests_as_non_production():
    from datetime import datetime, timezone
    from brass.output.yaml_builders.ai_instructions_builder import YAMLAIInstructionsBuilder
    builder = YAMLAIInstructionsBuilder(project_path=".", generation_time=datetime.now(timezone.utc))
    ctx = builder._classify_via_file_classifier("__tests__/Button.test.tsx")
    assert ctx["is_production_code"] is False
    assert ctx["priority_for_ai"] == "LOW"


def test_ai_instructions_builder_marks_docs_as_non_production():
    """Triage feedback: SSN/Aadhaar findings inside docs/*.md were
    flagged as production code. They should be LOW priority."""
    from datetime import datetime, timezone
    from brass.output.yaml_builders.ai_instructions_builder import YAMLAIInstructionsBuilder
    builder = YAMLAIInstructionsBuilder(project_path=".", generation_time=datetime.now(timezone.utc))
    ctx = builder._classify_via_file_classifier("docs/implementation/VERCEL.md")
    assert ctx["is_production_code"] is False
    assert ctx["priority_for_ai"] == "LOW"


def test_ai_instructions_builder_keeps_real_source_as_production():
    """Regression: actual source files in app/ should still be HIGH."""
    from datetime import datetime, timezone
    from brass.output.yaml_builders.ai_instructions_builder import YAMLAIInstructionsBuilder
    builder = YAMLAIInstructionsBuilder(project_path=".", generation_time=datetime.now(timezone.utc))
    ctx = builder._classify_via_file_classifier("app/api/auth/route.ts")
    assert ctx["is_production_code"] is True
    assert ctx["priority_for_ai"] == "HIGH"


# --------------------------------------------------------------------------- #
# C.11: Lock-file exclusion (copper-sun triage feedback)                      #
# --------------------------------------------------------------------------- #


def test_claude_code_agent_worktrees_excluded():
    """C.12: .claude/worktrees/ holds Claude Code's parallel-agent git
    worktrees — copies of the project, never customer source. Same
    hygiene as .brass/ self-exclusion."""
    from brass.core.file_classifier import FileClassifier
    fc = FileClassifier()
    for path in [
        ".claude/worktrees/agent-abc123/lib/auth.ts",
        ".claude/worktrees/another/src/foo.py",
        "subdir/.claude/worktrees/x/y/file.js",
        ".claude/commands/init.md",
        ".claude/settings.json",
    ]:
        assert fc.should_exclude_from_analysis(path), f"{path} should be excluded"


def test_test_env_files_classified_as_configuration():
    """C.12: jest.env.js / vitest.env.ts / test.setup.js contain mock
    credentials and placeholder emails — they're not production code.
    Identified by the whisperx-production triage."""
    from brass.core.file_classifier import FileClassifier, FileType
    fc = FileClassifier()
    for path in [
        "jest.env.js",
        "vitest.env.ts",
        "test.env.mjs",
        "tests/jest.setup.ts",
    ]:
        assert fc.classify_file(path).file_type == FileType.CONFIGURATION, path


def test_lock_files_excluded_from_analysis():
    """Lock files are generated by package managers — their contents
    are not human-authored. Scanning them produces FPs (npm maintainer
    emails as PII, license hashes as secrets) without value."""
    from brass.core.file_classifier import FileClassifier
    fc = FileClassifier()
    for path in [
        "package-lock.json",
        "apps/web/package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "Cargo.lock",
        "go.sum",
        "Gemfile.lock",
        "composer.lock",
    ]:
        assert fc.should_exclude_from_analysis(path), f"{path} should be excluded"


def test_custom_module_directories_are_source_code():
    """Real-world projects use domain-specific top-level module
    directories (whisper-platform/, api-client/, data-processing/,
    web-handler/) that aren't in the canonical source-pattern allowlist.
    Without a catch-all, these classify as UNKNOWN → is_production_code
    becomes False → the YAML's `how_to_read_this_file.triage_priority`
    rule "Start with signals whose context.is_production_code is true"
    causes an AI consumer to CLEAR real production findings.

    Regression test for the whisperx-production miscategorization
    discovered 2026-05-17 while reading brass's own ai_instructions.yaml
    output as a Claude Code consumer.
    """
    # Real customer-shape directories.
    assert _classify("whisper-platform/diarize_patch.py") == FileType.SOURCE_CODE
    assert _classify("whisper-platform/handler.py") == FileType.SOURCE_CODE
    assert _classify("api-client/auth.ts") == FileType.SOURCE_CODE
    assert _classify("data-processing/transform.py") == FileType.SOURCE_CODE
    # Underscored variants must also resolve.
    assert _classify("audio_processing/encoder.py") == FileType.SOURCE_CODE


def test_custom_module_directories_do_not_override_specific_patterns():
    """The catch-all must NOT shadow stronger signals. A file in
    `src/` should still classify with the canonical 0.95 confidence
    via the specific pattern, not via the 0.70 catch-all."""
    # If the catch-all were too greedy, src/foo.py would still resolve
    # but with the wrong rule. Functionally this test asserts the
    # classification, which should remain SOURCE_CODE — but the
    # confidence is also useful as a guard.
    ctx = FileClassifier().classify_file("src/index.ts")
    assert ctx.file_type == FileType.SOURCE_CODE
    assert ctx.confidence >= 0.85, (
        f"Specific src/ pattern (0.95) should win over catch-all (0.70); "
        f"got confidence {ctx.confidence}"
    )
