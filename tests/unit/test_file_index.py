"""Unit tests for the shared FileIndex cache."""

from __future__ import annotations

from pathlib import Path

from brass.core.file_index import FileIndex


def test_files_with_ext_buckets_by_extension(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "b.py").write_text("y = 2\n")
    (tmp_path / "c.js").write_text("const z = 3;\n")
    (tmp_path / "d.ts").write_text("export const w = 4;\n")

    idx = FileIndex(tmp_path)
    py_files = idx.files_with_ext(".py")
    js_files = idx.files_with_ext(".js")
    multi = idx.files_with_ext(".js", ".ts")

    assert len(py_files) == 2
    assert len(js_files) == 1
    assert len(multi) == 2
    assert all(p.is_absolute() for p in py_files)


def test_build_is_idempotent(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n")
    idx = FileIndex(tmp_path)
    idx.build()
    first = idx.walk_seconds()
    idx.build()  # second call should be a no-op
    assert idx.walk_seconds() == first
    assert len(idx.files_with_ext(".py")) == 1


def test_excludes_via_file_classifier(tmp_path: Path) -> None:
    """The FileClassifier exclusion rules apply during the walk."""
    (tmp_path / "real.py").write_text("x = 1\n")
    # node_modules / .venv / __pycache__ are all in the classifier exclude list
    cache_dir = tmp_path / "__pycache__"
    cache_dir.mkdir()
    (cache_dir / "bytecode.py").write_text("x = 1\n")

    idx = FileIndex(tmp_path)
    py_files = idx.files_with_ext(".py")
    assert len(py_files) == 1
    assert py_files[0].name == "real.py"


def test_extension_lookup_is_case_insensitive(tmp_path: Path) -> None:
    (tmp_path / "upper.PY").write_text("x = 1\n")
    idx = FileIndex(tmp_path)
    # Files indexed by lowercased extension; query also case-insensitive.
    assert len(idx.files_with_ext(".py")) == 1
    assert len(idx.files_with_ext(".PY")) == 1


def test_empty_project_returns_empty_lists(tmp_path: Path) -> None:
    idx = FileIndex(tmp_path)
    assert idx.files_with_ext(".py") == []
    assert idx.files_with_ext(".js", ".ts") == []


def test_unknown_extension_returns_empty(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n")
    idx = FileIndex(tmp_path)
    assert idx.files_with_ext(".nonexistent") == []


def test_does_not_loop_on_self_referential_symlink(tmp_path: Path) -> None:
    """A `link -> .` cycle in the project must not crash the build.

    Pre-fix: rglob followed the symlink and recursed until ELOOP,
    crashing the whole scan before any scanner ran. Post-fix: os.walk
    with followlinks=False just skips the cycle entry.
    """
    (tmp_path / "real.py").write_text("x = 1\n")
    try:
        (tmp_path / "loop").symlink_to(tmp_path)
    except OSError:
        # Some filesystems (e.g., FAT) reject this; skip rather than fail.
        return
    idx = FileIndex(tmp_path)
    idx.build()
    # real.py must still be discovered; loop must not have crashed.
    py_files = idx.files_with_ext(".py")
    assert any(p.name == "real.py" for p in py_files)


def test_files_with_ext_returns_fresh_list(tmp_path: Path) -> None:
    """Caller mutation must not affect the cache."""
    (tmp_path / "a.py").write_text("x = 1\n")
    idx = FileIndex(tmp_path)
    first = idx.files_with_ext(".py")
    first.append(Path("/fake/injected.py"))
    second = idx.files_with_ext(".py")
    assert len(second) == 1
