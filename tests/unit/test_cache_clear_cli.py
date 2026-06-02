"""Unit tests for `brasscoders cache clear`.

First CLI-level test in the suite. Invokes `BrassCLI().run([...])`
directly (bypassing `main()`'s startup checks) and isolates the
filesystem via `BRASS_PYSA_CACHE_ROOT` + an `HOME` env redirect
for the typeshed half.

Every test calls `_isolate_env(monkeypatch, tmp_path)` to enforce
hermetic isolation:
  - sets HOME to tmp_path (so Path.home() resolves under the test dir)
  - sets BRASS_PYSA_CACHE_ROOT under tmp_path
  - unsets BRASS_TYPESHED (developer-shell pollution would otherwise
    leak in; the cache subcommand doesn't read it today but tests
    should be hermetic against future changes)
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from brass.cli.brass_cli import BrassCLI


def _isolate_env(monkeypatch, tmp_path: Path) -> Path:
    """Set up hermetic env for a cache-clear test. Returns the pysa-state
    path the CLI will use. Defensive: asserts that the typeshed path the
    CLI will compute resolves under `tmp_path` — protects against a
    future refactor accidentally targeting the real `~/.cache/brass/`."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("BRASS_TYPESHED", raising=False)
    pysa_root = tmp_path / "pysa-state"
    monkeypatch.setenv("BRASS_PYSA_CACHE_ROOT", str(pysa_root))
    # Guard: confirm Path.home() now resolves under tmp_path. If this
    # assertion ever fails, abort the test before it can rmtree the real
    # ~/.cache/brass/.
    home_resolved = Path.home().resolve()
    tmp_resolved = tmp_path.resolve()
    assert str(home_resolved).startswith(str(tmp_resolved)), (
        f"Test isolation failed: Path.home()={home_resolved} is not under "
        f"tmp_path={tmp_resolved}. Refusing to run destructive cache-clear "
        f"test against the developer's real cache."
    )
    return pysa_root


def _populate_pysa_cache(root: Path, *, n_projects: int = 3, bytes_per_project: int = 4096) -> int:
    """Create N fake per-project cache subdirs under `root`.

    Returns total bytes written (so tests can assert against the
    `_dir_size` reading).
    """
    root.mkdir(parents=True, exist_ok=True)
    total = 0
    for i in range(n_projects):
        subdir = root / f"hash{i:016x}"
        subdir.mkdir()
        payload = subdir / "pysa.cache"
        payload.write_bytes(b"\x00" * bytes_per_project)
        total += bytes_per_project
    return total


def _populate_typeshed(root: Path, *, bytes_in_stdlib: int = 8192) -> int:
    """Create a fake typeshed clone with a `stdlib/` subdir."""
    stdlib = root / "stdlib"
    stdlib.mkdir(parents=True, exist_ok=True)
    payload = stdlib / "__init__.pyi"
    payload.write_bytes(b"\x00" * bytes_in_stdlib)
    return bytes_in_stdlib


def test_cache_clear_empty(tmp_path, monkeypatch, capsys):
    """Cache clear on a non-existent cache root → exit 0, friendly message."""
    cache_root = _isolate_env(monkeypatch, tmp_path)
    # Don't create the dir; verify graceful handling.

    cli = BrassCLI()
    rc = cli.run(["cache", "clear"])

    out = capsys.readouterr().out
    assert rc == 0
    assert "No cache to clear" in out
    assert str(cache_root) in out


def test_cache_clear_populated_removes_subdirs(tmp_path, monkeypatch, capsys):
    """Cache clear on a populated cache → all subdirs removed, root preserved."""
    cache_root = _isolate_env(monkeypatch, tmp_path)
    expected_bytes = _populate_pysa_cache(cache_root, n_projects=3)

    cli = BrassCLI()
    rc = cli.run(["cache", "clear"])

    out = capsys.readouterr().out
    assert rc == 0
    assert "3 project caches" in out
    assert "removed" in out
    assert "Freed" in out
    # Root dir preserved; subdirs gone.
    assert cache_root.exists()
    assert list(cache_root.iterdir()) == []
    # No mention of total bytes in absolute terms (format is MB rounded);
    # just sanity-check we reported something nonzero.
    assert "0.0 MB" not in out or expected_bytes < 1024 * 50  # sanity


def test_cache_clear_include_typeshed(tmp_path, monkeypatch, capsys):
    """--include-typeshed → both pysa-state and typeshed removed."""
    cache_root = _isolate_env(monkeypatch, tmp_path)
    typeshed_root = tmp_path / ".cache" / "brass" / "typeshed"
    _populate_pysa_cache(cache_root, n_projects=2)
    _populate_typeshed(typeshed_root)

    cli = BrassCLI()
    rc = cli.run(["cache", "clear", "--include-typeshed"])

    out = capsys.readouterr().out
    assert rc == 0
    assert "Pysa cache:" in out
    assert "Typeshed cache:" in out
    assert "Freed" in out
    assert "total" in out  # "Freed X.X MB total." with --include-typeshed
    # Both gone.
    assert list(cache_root.iterdir()) == []
    assert not typeshed_root.exists()


def test_cache_clear_dry_run_removes_nothing(tmp_path, monkeypatch, capsys):
    """--dry-run prints what would be removed but leaves disk untouched."""
    cache_root = _isolate_env(monkeypatch, tmp_path)
    _populate_pysa_cache(cache_root, n_projects=2)
    before_subdirs = sorted(p.name for p in cache_root.iterdir())

    cli = BrassCLI()
    rc = cli.run(["cache", "clear", "--dry-run"])

    out = capsys.readouterr().out
    assert rc == 0
    assert "dry-run" in out
    assert "Run without --dry-run" in out
    # Nothing removed.
    after_subdirs = sorted(p.name for p in cache_root.iterdir())
    assert before_subdirs == after_subdirs


def test_cache_clear_only_typeshed_when_pysa_empty(tmp_path, monkeypatch, capsys):
    """--include-typeshed still clears typeshed even when pysa cache is empty,
    AND does not take the early-return 'No cache to clear' path."""
    cache_root = _isolate_env(monkeypatch, tmp_path)
    cache_root.mkdir()  # exists but empty
    typeshed_root = tmp_path / ".cache" / "brass" / "typeshed"
    _populate_typeshed(typeshed_root)

    cli = BrassCLI()
    rc = cli.run(["cache", "clear", "--include-typeshed"])

    out = capsys.readouterr().out
    assert rc == 0
    assert "Typeshed cache:" in out
    # Critical: must NOT have taken the early-return "nothing to clear"
    # path. Without this assertion the test could pass even if the
    # early-return logic incidentally happened to print "Typeshed cache:"
    # via some other code path.
    assert "No cache to clear" not in out
    assert not typeshed_root.exists()


def test_cache_clear_symlink_in_typeshed_does_not_follow(tmp_path, monkeypatch, capsys):
    """Regression test: a symlink inside the typeshed cache pointing OUTSIDE
    must not cause the link target to be deleted. shutil.rmtree's default
    semantics (no symlinks=True, no follow_symlinks) protect against this;
    this test codifies the contract so a future refactor doesn't regress
    into following symlinks.
    """
    _isolate_env(monkeypatch, tmp_path)
    typeshed_root = tmp_path / ".cache" / "brass" / "typeshed"
    _populate_typeshed(typeshed_root)
    # Create an outside-target the rmtree must NOT touch.
    outside = tmp_path / "outside_target"
    outside.mkdir()
    sentinel = outside / "must_survive.txt"
    sentinel.write_text("survive\n")
    # Symlink inside typeshed pointing at the outside dir.
    (typeshed_root / "stdlib" / "evil_link").symlink_to(outside)

    cli = BrassCLI()
    rc = cli.run(["cache", "clear", "--include-typeshed"])

    out = capsys.readouterr().out
    assert rc == 0
    assert not typeshed_root.exists()
    # The outside target and its file must still be intact.
    assert outside.exists()
    assert sentinel.read_text() == "survive\n"


def test_cache_clear_partial_failure_reports_freed_bytes(tmp_path, monkeypatch, capsys):
    """Partial-success protocol: if rmtree fails on the Nth hash dir, the
    bytes freed from the first N-1 should still be reported (and exit 1)."""
    cache_root = _isolate_env(monkeypatch, tmp_path)
    _populate_pysa_cache(cache_root, n_projects=2)
    # Make one of the hash dirs unrmtreeable by creating an unwritable
    # subdir inside it (chmod 0 on the parent so children can't be unlinked).
    # Actually the cleanest cross-platform way: monkeypatch shutil.rmtree to
    # raise on the second call.
    import shutil
    original_rmtree = shutil.rmtree
    calls = {"n": 0}

    def fake_rmtree(path, *a, **kw):
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError(13, "Permission denied (simulated)")
        original_rmtree(path, *a, **kw)

    monkeypatch.setattr("shutil.rmtree", fake_rmtree)

    cli = BrassCLI()
    rc = cli.run(["cache", "clear"])
    out = capsys.readouterr().out

    assert rc == 1  # partial-failure exit code
    assert "partial" in out.lower()
    # Should mention bytes-freed AND the error.
    assert "MB" in out
    assert "Permission denied" in out
    # One of the two dirs should be gone, the other should remain.
    remaining = [p for p in cache_root.iterdir()]
    assert len(remaining) == 1


def test_cache_clear_nothing_to_do_mentions_typeshed_when_requested(tmp_path, monkeypatch, capsys):
    """When both caches are empty AND --include-typeshed is set, the
    'No cache to clear' message should mention both paths so the user
    isn't confused about which one was checked."""
    cache_root = _isolate_env(monkeypatch, tmp_path)
    cache_root.mkdir()
    # Typeshed dir doesn't exist.

    cli = BrassCLI()
    rc = cli.run(["cache", "clear", "--include-typeshed"])

    out = capsys.readouterr().out
    assert rc == 0
    assert "No cache to clear" in out
    assert "pysa-state" in out
    assert "typeshed" in out


def test_cache_no_action_errors(tmp_path, monkeypatch, capsys):
    """`brasscoders cache` with no action → argparse exits with error."""
    _isolate_env(monkeypatch, tmp_path)

    cli = BrassCLI()
    with pytest.raises(SystemExit) as excinfo:
        cli.run(["cache"])
    # argparse exits 2 for missing positional
    assert excinfo.value.code == 2


def test_cache_invalid_action_errors(tmp_path, monkeypatch, capsys):
    """`brasscoders cache wipe` (unknown action) → argparse rejects via choices."""
    _isolate_env(monkeypatch, tmp_path)

    cli = BrassCLI()
    with pytest.raises(SystemExit) as excinfo:
        cli.run(["cache", "wipe"])
    assert excinfo.value.code == 2


# -------------------------------------- cache footer (Tier 1)


def _populate_n_mb(root: Path, mb: int) -> None:
    """Plant N MB of real bytes in a fake project cache under `root`.

    Streams 1 MB chunks to keep peak RAM at ~1 MB regardless of `mb` —
    the previous one-shot `b"\\x00" * mb * 1024 * 1024` allocation
    was OK at 150 MB but the 1.1 GB warning-tier test would balloon
    RAM on memory-constrained CI runners (and on tmpfs-backed tmp
    paths consumes that much RAM directly, not disk).

    Real bytes (not sparse) so `_dir_size`'s `st_blocks * 512`
    reports the same number across filesystems.
    """
    root.mkdir(parents=True, exist_ok=True)
    subdir = root / "fakeproject"
    subdir.mkdir(exist_ok=True)
    payload = subdir / "blob.bin"
    chunk = b"\x00" * (1024 * 1024)  # 1 MB
    with payload.open("wb") as fh:
        for _ in range(mb):
            fh.write(chunk)


def test_print_cache_footer_silent_below_threshold(tmp_path, monkeypatch, capsys):
    """Footer must NOT print for cache < 100 MB (one typical project)."""
    cache_root = _isolate_env(monkeypatch, tmp_path)
    _populate_n_mb(cache_root, mb=10)  # well below 100 MB floor
    monkeypatch.delenv("BRASS_QUIET_CACHE", raising=False)

    cli = BrassCLI()
    cli._print_cache_footer()
    out = capsys.readouterr().out
    assert "cache" not in out.lower()  # nothing printed
    assert out == ""


def test_print_cache_footer_info_tier(tmp_path, monkeypatch, capsys):
    """Cache in 100 MB – 1 GB range → info-style footer with 🧹 prefix."""
    cache_root = _isolate_env(monkeypatch, tmp_path)
    _populate_n_mb(cache_root, mb=150)  # squarely info-tier
    monkeypatch.delenv("BRASS_QUIET_CACHE", raising=False)

    cli = BrassCLI()
    cli._print_cache_footer()
    out = capsys.readouterr().out
    assert "🧹" in out
    assert "BrassCoders cache" in out
    assert "MB" in out
    assert "brasscoders cache clear" in out
    assert "⚠️" not in out  # info-tier, not warning


def test_print_cache_footer_warning_tier(tmp_path, monkeypatch, capsys):
    """Cache > 1 GB → warning-style footer with ⚠️ and --include-typeshed hint."""
    cache_root = _isolate_env(monkeypatch, tmp_path)
    _populate_n_mb(cache_root, mb=1100)  # > 1 GB
    monkeypatch.delenv("BRASS_QUIET_CACHE", raising=False)

    cli = BrassCLI()
    cli._print_cache_footer()
    out = capsys.readouterr().out
    assert "⚠️" in out
    assert "GB" in out
    assert "--include-typeshed" in out


def test_print_cache_footer_suppressed_by_env(tmp_path, monkeypatch, capsys):
    """BRASS_QUIET_CACHE=1 suppresses the footer even when threshold is crossed."""
    cache_root = _isolate_env(monkeypatch, tmp_path)
    _populate_n_mb(cache_root, mb=150)  # would normally print info-tier
    monkeypatch.setenv("BRASS_QUIET_CACHE", "1")

    cli = BrassCLI()
    cli._print_cache_footer()
    out = capsys.readouterr().out
    assert out == ""


def test_print_cache_footer_silent_when_cache_root_absent(tmp_path, monkeypatch, capsys):
    """Cache root doesn't exist (fresh install) → silent, no exception."""
    cache_root = _isolate_env(monkeypatch, tmp_path)
    # Don't create cache_root. _isolate_env only sets the env var.
    monkeypatch.delenv("BRASS_QUIET_CACHE", raising=False)

    cli = BrassCLI()
    cli._print_cache_footer()  # must not raise
    out = capsys.readouterr().out
    assert out == ""
