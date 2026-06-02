"""Tests for the raw_files gatherer (post-2C refactor, 2026-05-22).

Pre-2C: this module built the project_signature string on the CLI.
Post-2C: the CLI just gathers raw chunks (README/manifest/entrypoint/
filenames); the gateway constructs the signature server-side.

These tests cover the new gather_raw_files contract:
    - Returns a dict with optional keys: readme, manifest, entrypoint, filenames
    - Each chunk is independently capped
    - Symlinks are refused (security: H1 defense)
    - Empty project returns an empty dict (gateway has a fallback)
"""

from __future__ import annotations

from pathlib import Path

from brass.enrichment.project_signature import (
    gather_raw_files,
    build_project_signature,  # backward-compat alias
    README_CHARS,
    MANIFEST_CHARS,
    ENTRYPOINT_CHARS,
    MAX_TOPLEVEL_FILENAMES,
)


def test_empty_directory_returns_empty_dict(tmp_path):
    raw = gather_raw_files(tmp_path)
    assert isinstance(raw, dict)
    # No fields populated for a bare directory.
    assert "readme" not in raw
    assert "manifest" not in raw
    assert "entrypoint" not in raw
    assert "filenames" not in raw


def test_includes_readme_when_present(tmp_path):
    (tmp_path / "README.md").write_text("# My project\n\nDoes a thing.\n")
    raw = gather_raw_files(tmp_path)
    assert "My project" in raw["readme"]


def test_includes_manifest_when_present(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "my-project"\n')
    raw = gather_raw_files(tmp_path)
    assert "my-project" in raw["manifest"]


def test_includes_entrypoint_when_present(tmp_path):
    (tmp_path / "main.py").write_text("def main():\n    pass\n")
    raw = gather_raw_files(tmp_path)
    assert "def main" in raw["entrypoint"]


def test_lists_toplevel_source_files(tmp_path):
    (tmp_path / "a.py").write_text("")
    (tmp_path / "b.py").write_text("")
    raw = gather_raw_files(tmp_path)
    assert "a.py" in raw["filenames"]
    assert "b.py" in raw["filenames"]


def test_descends_into_common_source_dirs(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "module.py").write_text("")
    raw = gather_raw_files(tmp_path)
    assert "src/module.py" in raw["filenames"]


def test_caps_readme_length(tmp_path):
    # README large enough to bust the cap on its own.
    (tmp_path / "README.md").write_text("X" * 100_000)
    raw = gather_raw_files(tmp_path)
    assert len(raw["readme"]) <= README_CHARS


def test_caps_manifest_length(tmp_path):
    (tmp_path / "pyproject.toml").write_text("X" * 100_000)
    raw = gather_raw_files(tmp_path)
    assert len(raw["manifest"]) <= MANIFEST_CHARS


def test_caps_entrypoint_length(tmp_path):
    (tmp_path / "main.py").write_text("X" * 100_000)
    raw = gather_raw_files(tmp_path)
    assert len(raw["entrypoint"]) <= ENTRYPOINT_CHARS


def test_caps_filename_count(tmp_path):
    for i in range(200):
        (tmp_path / f"file{i:03d}.py").write_text("")
    raw = gather_raw_files(tmp_path)
    assert len(raw["filenames"]) <= MAX_TOPLEVEL_FILENAMES


def test_skips_dotfiles(tmp_path):
    (tmp_path / ".env").write_text("SECRET=x")
    (tmp_path / ".git").mkdir()
    (tmp_path / "real.py").write_text("")
    raw = gather_raw_files(tmp_path)
    assert ".env" not in raw.get("filenames", [])
    assert "real.py" in raw["filenames"]


def test_deterministic_for_same_input(tmp_path):
    (tmp_path / "README.md").write_text("hello")
    (tmp_path / "a.py").write_text("")
    (tmp_path / "b.py").write_text("")
    a = gather_raw_files(tmp_path)
    b = gather_raw_files(tmp_path)
    assert a == b


def test_handles_broken_symlink_without_crashing(tmp_path):
    # Symlink pointing at a non-existent target — read should be skipped.
    bad = tmp_path / "README.md"
    bad.symlink_to(tmp_path / "does-not-exist")
    raw = gather_raw_files(tmp_path)
    # Should not raise; just no readme key.
    assert isinstance(raw, dict)
    assert "readme" not in raw


def test_refuses_to_follow_symlinked_readme_to_external_path(tmp_path):
    """H1: a malicious project containing README.md -> /etc/passwd
    must not exfiltrate the target's contents."""
    secret_file = tmp_path / "secret_outside_project.txt"
    secret_file.write_text("VERY_SENSITIVE_CONTENT_DO_NOT_LEAK")
    (tmp_path / "README.md").symlink_to(secret_file)
    raw = gather_raw_files(tmp_path)
    # readme key is absent because symlinks are refused
    assert "readme" not in raw or "VERY_SENSITIVE_CONTENT_DO_NOT_LEAK" not in raw["readme"]


def test_refuses_to_follow_symlinked_manifest(tmp_path):
    """Same defense for pyproject.toml / package.json / etc."""
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("AWS_SECRET_ACCESS_KEY=AKIAFAKEKEYXX")
    (tmp_path / "pyproject.toml").symlink_to(secret_file)
    raw = gather_raw_files(tmp_path)
    assert "manifest" not in raw or "AWS_SECRET_ACCESS_KEY" not in raw["manifest"]


def test_refuses_to_list_symlinked_toplevel_files(tmp_path):
    """Symlinks in the top-level listing also skipped — name itself
    might leak structure but content reads on linked files would too."""
    target = tmp_path / "secret_dir_marker.txt"
    target.write_text("x")
    (tmp_path / "innocuous_name.py").symlink_to(target)
    (tmp_path / "real.py").write_text("")
    raw = gather_raw_files(tmp_path)
    assert "innocuous_name.py" not in raw.get("filenames", [])
    assert "real.py" in raw["filenames"]


def test_backward_compat_alias_works(tmp_path):
    """`build_project_signature` is kept as an alias for `gather_raw_files`
    so any external caller (or stale import) still gets the new dict
    instead of an AttributeError."""
    (tmp_path / "README.md").write_text("hi")
    a = gather_raw_files(tmp_path)
    b = build_project_signature(tmp_path)
    assert a == b


# --------------------------------------------------------------------------- #
# UTF-16 clamp regression — caught 2026-05-25 on whisperx-production         #
# --------------------------------------------------------------------------- #


def test_readme_with_emoji_does_not_exceed_utf16_cap(tmp_path):
    """Regression: a README of ≥ README_CHARS code points containing
    non-BMP characters (emoji, supplementary CJK) must produce a slice
    whose UTF-16 code-unit length is ≤ README_CHARS — the gateway's
    Zod schema measures UTF-16 code units, not Python code points.

    Before the fix, `text[:5000]` returned 5000 code points; with 5
    emoji that's 5005 UTF-16 code units and Zod rejects with 400.
    """
    # Build a README with 4995 ASCII chars + 5 emoji (each 1 code point
    # in Python but 2 UTF-16 code units). Total: 5000 code points,
    # 5005 UTF-16 code units. Then add a tail to ensure the slice
    # actually engages, not just returns the whole string.
    body = "A" * 4995 + "🎯🏆🚀🚀🔧" + "B" * 200
    (tmp_path / "README.md").write_text(body)
    raw = gather_raw_files(tmp_path)
    readme = raw["readme"]
    # Code-point length (Python's len) can be ≤ cap.
    assert len(readme) <= README_CHARS
    # UTF-16 code-unit length MUST be ≤ cap (this is what Zod measures).
    utf16_units = sum(2 if ord(c) > 0xFFFF else 1 for c in readme)
    assert utf16_units <= README_CHARS, (
        f"UTF-16 length {utf16_units} exceeds cap {README_CHARS} — "
        f"gateway will 400 with 'expected string to have <={README_CHARS} characters'"
    )


def test_clamp_returns_longest_valid_prefix():
    """The clamp should return the LONGEST prefix whose UTF-16 length
    is ≤ max_units — not be conservative (e.g., halving the cap)."""
    from brass.enrichment.project_signature import _clamp_to_utf16_units
    # 100 ASCII chars + 1 emoji at position 100 (UTF-16 unit 100+2 = 102)
    text = "A" * 100 + "🎯" + "B" * 50
    # Cap = 101: emoji at position 100 needs units 101-102; 101+2 > 101, so
    # the emoji is dropped. Result: 100 ASCII chars.
    clamped = _clamp_to_utf16_units(text, 101)
    assert clamped == "A" * 100
    # Cap = 102: emoji fits (100 + 2 = 102). Result: 100 ASCII + emoji.
    clamped = _clamp_to_utf16_units(text, 102)
    assert clamped == "A" * 100 + "🎯"


def test_clamp_pure_ascii_equivalent_to_codepoint_slice():
    """For pure-ASCII text (no characters above U+FFFF), the clamp
    must behave identically to `text[:cap]` — same length, same content,
    no degradation of the common case."""
    from brass.enrichment.project_signature import _clamp_to_utf16_units
    text = "X" * 10_000
    assert _clamp_to_utf16_units(text, 5000) == text[:5000]
    assert _clamp_to_utf16_units(text, 100) == text[:100]
    assert _clamp_to_utf16_units(text, 100_000) == text  # cap larger than text
