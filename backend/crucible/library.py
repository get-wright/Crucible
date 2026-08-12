"""Scenarios as files on disk.

The database is an index, not the record. A scenario is source: you open it in
an editor, diff it, review it, commit it. The row in SQLite exists so the
library screen can filter a few thousand of them quickly — but if the database
is deleted the scenarios are still there, and a scenario drafted in the browser
is byte-for-byte the same artifact as one written by hand.

That equivalence is the point of this module. Saving from the GUI writes a file
into the library directory and records where it went; `crucible run <file>`
then takes that path like any other. There is no export step and no format that
only the browser can read.

Two rules are enforced here rather than trusted to callers:

  containment  every path resolves inside the library directory, so a `path`
               that arrives over HTTP can never write outside it.
  atomicity    a write lands via a temporary file and a rename, so an
               interrupted save leaves the previous version intact instead of
               a half-written scenario that no longer parses.
"""

from __future__ import annotations

import os
import re
import unicodedata
from pathlib import Path
from typing import Any

SUFFIX = ".md"

#: Anything that is not a letter, digit or dash collapses to a single dash.
_NOT_SLUG = re.compile(r"[^a-z0-9]+")

#: Reserved on Windows; harmless to avoid everywhere.
_RESERVED = frozenset({
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
})


class LibraryError(ValueError):
    """A path that would write outside the library, or that names nothing."""


def slugify(name: str, *, fallback: str = "scenario") -> str:
    """A filename stem from a scenario name.

    Accents fold to ASCII rather than vanishing, so "Café Ops" becomes
    `cafe-ops` and not `-ops`.
    """
    folded = unicodedata.normalize("NFKD", name or "")
    ascii_only = folded.encode("ascii", "ignore").decode("ascii")
    slug = _NOT_SLUG.sub("-", ascii_only.lower()).strip("-")
    slug = slug[:72].strip("-")
    if not slug or slug in _RESERVED:
        return fallback
    return slug


def resolve(directory: Path, candidate: str) -> Path:
    """Turn a caller-supplied path into an absolute one inside `directory`.

    Accepts a bare stem, a filename, or a path relative to the library. Rejects
    anything that escapes — `../`, an absolute path elsewhere, or a symlinked
    parent — because this value arrives over HTTP.
    """
    if not candidate or not candidate.strip():
        raise LibraryError("empty path")

    directory = directory.resolve()
    raw = Path(candidate.strip())
    target = raw if raw.is_absolute() else directory / raw
    if target.suffix != SUFFIX:
        target = target.with_name(target.name + SUFFIX)

    # Resolved without creating anything. `resolve()` is non-strict, so a file
    # that does not exist yet still normalises `..` and follows symlinks
    # through whatever part of the path is real — which is what makes the
    # containment check below mean something. Nothing is written, and no
    # directory is created, until the path has passed it.
    final = target.resolve()
    if final.parent != directory and directory not in final.parents:
        raise LibraryError(f"path escapes the scenario library: {candidate}")
    return final


def unique_path(directory: Path, stem: str) -> Path:
    """`<stem>.md`, or `<stem>-2.md` … when that name is taken.

    Saving a second scenario called "Untitled" must not silently overwrite the
    first one.
    """
    directory.mkdir(parents=True, exist_ok=True)
    base = directory / f"{stem}{SUFFIX}"
    if not base.exists():
        return base
    for n in range(2, 1000):
        candidate = directory / f"{stem}-{n}{SUFFIX}"
        if not candidate.exists():
            return candidate
    raise LibraryError(f"too many scenarios named {stem!r}")


def write(
    text: str,
    *,
    directory: Path,
    name: str = "",
    path: str | None = None,
) -> Path:
    """Write `text` into the library and return where it landed.

    With `path`, rewrites that file — this is what saving an existing scenario
    does, so editing in the browser updates the file it came from instead of
    littering the directory with copies. Without one, derives a fresh
    non-clobbering filename from `name`.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    target = resolve(directory, path) if path else unique_path(directory, slugify(name))
    # Safe now, and only now: `resolve` has proved the parent is inside the
    # library, so this cannot create a directory somewhere else.
    target.parent.mkdir(parents=True, exist_ok=True)

    # Write-then-rename: a crash mid-save leaves the old file untouched rather
    # than a truncated one that no longer parses.
    tmp = target.with_name(f".{target.name}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, target)
    return target


def read(directory: Path, candidate: str) -> str:
    target = resolve(Path(directory), candidate)
    if not target.is_file():
        raise LibraryError(f"no such scenario file: {candidate}")
    return target.read_text(encoding="utf-8")


def relative(directory: Path, target: Path) -> str:
    """The path as the user would type it — relative when it can be."""
    try:
        return str(Path(target).resolve().relative_to(Path(directory).resolve()))
    except ValueError:
        return str(target)


def listing(directory: Path) -> list[dict[str, Any]]:
    """Every scenario file present, newest first.

    Read from the filesystem, not the database: a file dropped into the
    directory by hand or by `git pull` is part of the library the moment it is
    there, without an import step.
    """
    directory = Path(directory)
    if not directory.is_dir():
        return []
    out = []
    for p in sorted(directory.glob(f"*{SUFFIX}")):
        if p.name.startswith("."):
            continue
        stat = p.stat()
        out.append({
            "path": p.name,
            "bytes": stat.st_size,
            "modified": int(stat.st_mtime),
        })
    return sorted(out, key=lambda r: r["modified"], reverse=True)
