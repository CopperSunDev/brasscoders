"""Gather raw project context files for the gateway.

Replaces the pre-2C signature builder: the CLI no longer constructs a
final signature string. Instead it gathers the four raw chunks (README,
manifest, entrypoint, top-level filenames) and POSTs them to the
gateway, which constructs the signature server-side. Keeps the
signature-construction algorithm in closed code.

Each chunk is independently capped client-side so the wire payload
stays bounded:
    - README: first 5000 chars
    - Manifest: first 2000 chars (pyproject.toml / package.json / etc)
    - Entrypoint: first 3000 chars (main.py / index.{js,ts} / etc)
    - Top-level source filenames: sorted, capped at 80
"""

from __future__ import annotations

from pathlib import Path
from typing import TypedDict

from brass.enrichment._wire_clamp import clamp_to_utf16_units


# Per-chunk caps. Wire schema (RawFilesSchema on the gateway) enforces
# these as hard maxima; we apply them here so the CLI sends bounded data
# regardless of how large the source files are.
README_CHARS = 5000
MANIFEST_CHARS = 2000
ENTRYPOINT_CHARS = 3000
MAX_TOPLEVEL_FILENAMES = 80
# Per-filename UTF-16 code-unit cap (matches gateway schema:
# z.array(z.string().max(512)).max(80) on `filenames`).
MAX_FILENAME_UTF16_UNITS = 512

README_NAMES = ("README.md", "README.rst", "README.txt", "README", "readme.md")
MANIFEST_NAMES = (
    "pyproject.toml",
    "package.json",
    "Cargo.toml",
    "go.mod",
    "Gemfile",
    "pom.xml",
)
ENTRYPOINT_NAMES = (
    "main.py",
    "__main__.py",
    "app.py",
    "index.ts",
    "index.js",
    "main.go",
    "main.rs",
    "src/main.rs",
)
SOURCE_DIRS = ("src", "lib", "app", "pkg", "internal")


class RawFiles(TypedDict, total=False):
    """Wire shape sent to the gateway under `raw_files`.

    Each key is independently optional — a project without a README
    just sends fewer chunks. The gateway falls back to a generic
    placeholder if every key is absent (rare in practice).
    """
    readme: str
    manifest: str
    entrypoint: str
    filenames: list[str]


def gather_raw_files(project_path: str | Path) -> RawFiles:
    """Return the four raw chunks for `raw_files` in the enrich request.

    Symlinks are explicitly refused so a malicious project containing
    README.md -> /etc/passwd (or ~/.aws/credentials) can't steer raw
    file content into the wire payload.
    """
    root = Path(project_path)
    out: RawFiles = {}

    readme = _read_first_existing(root, README_NAMES, README_CHARS)
    if readme:
        out["readme"] = readme

    manifest = _read_first_existing(root, MANIFEST_NAMES, MANIFEST_CHARS)
    if manifest:
        out["manifest"] = manifest

    entry = _read_first_existing(root, ENTRYPOINT_NAMES, ENTRYPOINT_CHARS)
    if entry:
        out["entrypoint"] = entry

    filenames = _list_toplevel_source_filenames(root)
    if filenames:
        out["filenames"] = filenames

    return out


def _is_safely_inside(path: Path, root: Path) -> bool:
    """Verify `path`'s resolved location remains under `root`.

    `Path.is_symlink()` only catches a symlink on the LEAF. A malicious
    project where an INTERMEDIATE directory is a symlink (e.g.
    `src/ -> /private/etc/`) would let `root / "src/main.rs"` resolve to
    `/private/etc/main.rs` while passing the leaf-only symlink check.
    Resolving the full path and verifying it's relative to root catches
    this class of directory-traversal-via-symlinked-parent.
    """
    try:
        resolved = path.resolve(strict=False)
        return resolved.is_relative_to(root.resolve(strict=False))
    except (OSError, ValueError):
        return False


def _read_first_existing(root: Path, names: tuple[str, ...], cap: int) -> str | None:
    for name in names:
        path = root / name
        # Refuse symlinks: a malicious project containing
        # README.md -> /etc/passwd would otherwise be slurped into the
        # raw_files payload and POSTed off-box.
        if path.is_symlink():
            continue
        # Defense-in-depth against symlinked PARENT directories that
        # `is_symlink()` on the leaf doesn't catch.
        if not _is_safely_inside(path, root):
            continue
        if path.is_file():
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            return clamp_to_utf16_units(text, cap)
    return None


# Backward-compat alias so any external caller that imported the
# private helper from this module still works. The implementation
# lives in `brass.enrichment._wire_clamp` now (shared across wire-
# format builders so the boundary contract isn't reinvented per file).
_clamp_to_utf16_units = clamp_to_utf16_units


def _list_toplevel_source_filenames(root: Path) -> list[str]:
    """Filenames in the project root + first level of common source dirs.

    Bounded to avoid blowing the payload on huge monorepos. Sorted for
    determinism. Skips symlinks so a malicious project can't steer the
    listing toward unrelated paths.
    """
    # Each filename's UTF-16 code-unit length must be ≤ 512 to satisfy
    # the gateway's z.array(z.string().max(512)) cap. Defensive against
    # generated bundler outputs / Windows long-path / non-ASCII filenames
    # — most filenames are well under, but the cap should match the wire
    # contract, not assume.
    out: list[str] = []
    try:
        for child in sorted(root.iterdir()):
            if len(out) >= MAX_TOPLEVEL_FILENAMES:
                break
            if child.name.startswith(".") or child.is_symlink():
                continue
            # Defense-in-depth: skip entries whose resolved path escapes
            # the project root via a symlinked parent. is_symlink() above
            # catches a symlinked leaf; this catches the deeper case.
            if not _is_safely_inside(child, root):
                continue
            if child.is_file():
                out.append(clamp_to_utf16_units(child.name, MAX_FILENAME_UTF16_UNITS))
            elif child.is_dir() and child.name in SOURCE_DIRS:
                try:
                    for sub in sorted(child.iterdir()):
                        if len(out) >= MAX_TOPLEVEL_FILENAMES:
                            break
                        if sub.is_symlink():
                            continue
                        if not _is_safely_inside(sub, root):
                            continue
                        if sub.is_file() and not sub.name.startswith("."):
                            out.append(clamp_to_utf16_units(
                                f"{child.name}/{sub.name}",
                                MAX_FILENAME_UTF16_UNITS,
                            ))
                except OSError:
                    pass
    except OSError:
        return []
    return out[:MAX_TOPLEVEL_FILENAMES]


# --- Backward-compat shim for callers that still expect a builder ----------
# The pre-2C builder is gone (the signature is built server-side now), but
# some tests / external callers may still import it. Re-export
# `gather_raw_files` under the old name so they get something sensible
# while they migrate. Deprecated; remove in a future cleanup pass.
build_project_signature = gather_raw_files
