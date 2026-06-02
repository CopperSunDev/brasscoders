"""Tests for the .brassignore parser + matchers (phase C.6b)."""

from __future__ import annotations

from dataclasses import dataclass

from brass.core.brassignore import BrassIgnore, filter_findings


@dataclass
class _FakeFinding:
    file_path: str
    metadata: dict


# --------------------------------------------------------------------------- #
# Parsing                                                                     #
# --------------------------------------------------------------------------- #


def test_parse_empty_text_returns_empty_rules():
    bi = BrassIgnore.parse("")
    assert not bi
    assert bi.glob_rules == []
    assert bi.type_rules == set()


def test_parse_skips_comments_and_blank_lines():
    text = """\
# This is a comment
vendor/

# another comment
src/api/
"""
    bi = BrassIgnore.parse(text)
    assert bi.glob_rules == ["vendor/", "src/api/"]


def test_parse_separates_globs_and_type_rules():
    text = """\
vendor/
:hardcoded_password
src/legacy.js
:brass2_privacy.us_ssn
"""
    bi = BrassIgnore.parse(text)
    assert bi.glob_rules == ["vendor/", "src/legacy.js"]
    assert bi.type_rules == {"hardcoded_password", "brass2_privacy.us_ssn"}


def test_load_returns_empty_when_no_file(tmp_path):
    bi = BrassIgnore.load(tmp_path)
    assert not bi


def test_load_reads_brassignore_at_project_root(tmp_path):
    (tmp_path / ".brassignore").write_text("vendor/\n:hardcoded_password\n")
    bi = BrassIgnore.load(tmp_path)
    assert bi.glob_rules == ["vendor/"]
    assert bi.type_rules == {"hardcoded_password"}


# --------------------------------------------------------------------------- #
# Path matching                                                               #
# --------------------------------------------------------------------------- #


def test_directory_rule_matches_descendants():
    bi = BrassIgnore.parse("vendor/")
    assert bi.matches_path("vendor/lib.js")
    assert bi.matches_path("vendor/sub/deep.js")
    assert bi.matches_path("vendor")


def test_directory_rule_anywhere_in_tree():
    bi = BrassIgnore.parse("node_modules/")
    assert bi.matches_path("packages/foo/node_modules/lib.js")
    assert bi.matches_path("node_modules/at-root.js")


def test_directory_rule_does_not_match_partial_name():
    """vendor/ shouldn't match vendored.js — it's a directory rule."""
    bi = BrassIgnore.parse("vendor/")
    assert not bi.matches_path("vendored-deps.js")


def test_anchored_rule_only_matches_at_root():
    bi = BrassIgnore.parse("/scripts/")
    assert bi.matches_path("scripts/build.sh")
    assert not bi.matches_path("packages/foo/scripts/build.sh")


def test_plain_glob_matches_filename_anywhere():
    bi = BrassIgnore.parse("*.tmp")
    assert bi.matches_path("a.tmp")
    assert bi.matches_path("nested/x.tmp")


def test_exact_file_rule():
    bi = BrassIgnore.parse("scripts/legacy-migration.js")
    assert bi.matches_path("scripts/legacy-migration.js")
    assert not bi.matches_path("scripts/legacy-migration-v2.js")


def test_match_is_false_when_no_rules():
    bi = BrassIgnore.empty()
    assert not bi.matches_path("anything")


# --------------------------------------------------------------------------- #
# Type matching                                                               #
# --------------------------------------------------------------------------- #


def test_type_rule_matches_bare_rule_id():
    bi = BrassIgnore.parse(":hardcoded_password")
    assert bi.matches_finding_type("hardcoded_password")
    assert not bi.matches_finding_type("sql_injection")
    assert not bi.matches_finding_type(None)


def test_type_rule_dotted_form():
    bi = BrassIgnore.parse(":brass2_privacy.us_ssn")
    assert bi.matches_finding_type("brass2_privacy.us_ssn")
    assert not bi.matches_finding_type("us_ssn")


# --------------------------------------------------------------------------- #
# filter_findings                                                             #
# --------------------------------------------------------------------------- #


def test_filter_findings_drops_path_matches():
    bi = BrassIgnore.parse("vendor/")
    findings = [
        _FakeFinding("src/auth.ts", {}),
        _FakeFinding("vendor/legacy.js", {}),
        _FakeFinding("lib/util.ts", {}),
    ]
    out = filter_findings(findings, bi)
    assert [f.file_path for f in out] == ["src/auth.ts", "lib/util.ts"]


def test_filter_findings_drops_type_matches():
    bi = BrassIgnore.parse(":hardcoded_password")
    findings = [
        _FakeFinding("a.ts", {"rule_id": "hardcoded_password"}),
        _FakeFinding("b.ts", {"rule_id": "sql_injection"}),
        _FakeFinding("c.ts", {}),
    ]
    out = filter_findings(findings, bi)
    assert [f.file_path for f in out] == ["b.ts", "c.ts"]


def test_filter_findings_drops_dotted_type():
    bi = BrassIgnore.parse(":brass2_privacy.us_ssn")
    findings = [
        _FakeFinding("a.md", {"detector": "brass2_privacy", "rule_id": "us_ssn"}),
        _FakeFinding("b.md", {"detector": "brass2_privacy", "rule_id": "email_address"}),
    ]
    out = filter_findings(findings, bi)
    assert [f.file_path for f in out] == ["b.md"]


def test_filter_findings_passes_through_when_no_rules():
    bi = BrassIgnore.empty()
    findings = [_FakeFinding("a.ts", {})]
    out = filter_findings(findings, bi)
    assert out == findings
