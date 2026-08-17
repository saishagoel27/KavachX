"""Workspace materialisation.

The repository is fetched **outside** the sandbox and handed in as a pinned, hashed, immutable
artifact. Nothing in this module ever runs inside the sandbox, and there is no ``git clone``
anywhere near it.

Layout of a run workspace::

    <workspaces>/<run-short>/
        pristine/     the pinned tree, hashed; never mutated after materialisation
        work/         the mutable copy the sandbox executes against
        _kavachx/     injected harness + structured artifact output (created by the adapter)

``work/`` is reset from ``pristine/`` between gauntlet stages, which is how "the patch is
applied to a COPY" and "differential replay compares before/after" are both literally true.
"""

from __future__ import annotations

import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.core.errors import BadRequest
from app.core.hashing import sha256_text, sha256_tree
from app.core.logging import get_logger

logger = get_logger(__name__)

IGNORED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        ".venv",
        "venv",
        "node_modules",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".kavachx",
        "_kavachx",
        "dist",
        "build",
        ".next",
        "exports",
    }
)

IGNORED_SUFFIXES = frozenset(
    {".pyc", ".pyo", ".so", ".dll", ".dylib", ".exe", ".o", ".a", ".class", ".jar"}
)

MAX_TREE_BYTES = 256 * 1024 * 1024
MAX_FILE_BYTES = 8 * 1024 * 1024


@dataclass(slots=True)
class PinnedSource:
    pristine: Path
    work: Path
    root: Path
    content_sha256: str
    file_count: int
    total_bytes: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "content_sha256": self.content_sha256,
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
            "workspace": str(self.root),
        }


def _ignore(directory: str, names: list[str]) -> set[str]:
    skipped: set[str] = set()
    for name in names:
        if name in IGNORED_DIRS:
            skipped.add(name)
            continue
        if Path(name).suffix.lower() in IGNORED_SUFFIXES:
            skipped.add(name)
    return skipped


def materialise(*, source: Path, workspace_root: Path, run_short: str) -> PinnedSource:
    """Copy ``source`` into a fresh workspace and pin it by content hash."""
    source = source.resolve()
    if not source.is_dir():
        raise BadRequest(f"Source path is not a directory: {source}", code="SOURCE_NOT_FOUND")

    root = workspace_root / f"{run_short.lower()}-{uuid.uuid4().hex[:6]}"
    pristine = root / "pristine"
    work = root / "work"
    root.mkdir(parents=True, exist_ok=True)

    shutil.copytree(source, pristine, ignore=_ignore, dirs_exist_ok=True)

    file_count = 0
    total_bytes = 0
    for path in pristine.rglob("*"):
        if path.is_file():
            size = path.stat().st_size
            if size > MAX_FILE_BYTES:
                path.unlink()
                continue
            file_count += 1
            total_bytes += size
            if total_bytes > MAX_TREE_BYTES:
                raise BadRequest(
                    "Source tree exceeds the ingest size limit.", code="SOURCE_TOO_LARGE"
                )

    content_hash = sha256_tree(pristine)
    shutil.copytree(pristine, work, dirs_exist_ok=True)

    logger.info(
        "workspace.materialised",
        workspace=str(root),
        files=file_count,
        bytes=total_bytes,
        content_sha256=content_hash,
    )
    return PinnedSource(
        pristine=pristine,
        work=work,
        root=root,
        content_sha256=content_hash,
        file_count=file_count,
        total_bytes=total_bytes,
    )


def reset_work(pinned: PinnedSource) -> None:
    """Restore ``work/`` to the pinned tree, discarding any patch or target-side mutation."""
    preserved = pinned.work / "_kavachx"
    keep: dict[str, bytes] = {}
    if preserved.is_dir():
        for path in preserved.rglob("*"):
            if path.is_file():
                keep[str(path.relative_to(preserved))] = path.read_bytes()

    shutil.rmtree(pinned.work, ignore_errors=True)
    shutil.copytree(pinned.pristine, pinned.work, dirs_exist_ok=True)

    if keep:
        target = pinned.work / "_kavachx"
        for rel, data in keep.items():
            out = target / rel
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(data)


def verify_pristine(pinned: PinnedSource) -> bool:
    """Recompute the pinned hash. False means something mutated the immutable tree."""
    return sha256_tree(pinned.pristine) == pinned.content_sha256


def read_work_file(pinned: PinnedSource, relative: str) -> str:
    path = _safe_join(pinned.work, relative)
    return path.read_text(encoding="utf-8", errors="replace")


def read_pristine_file(pinned: PinnedSource, relative: str) -> str:
    path = _safe_join(pinned.pristine, relative)
    return path.read_text(encoding="utf-8", errors="replace")


def write_work_file(pinned: PinnedSource, relative: str, content: str) -> None:
    path = _safe_join(pinned.work, relative)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="")


def _safe_join(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    if not str(candidate).startswith(str(root.resolve())):
        raise BadRequest(f"Path escapes the workspace: {relative}", code="PATH_ESCAPE")
    return candidate


def list_source_files(root: Path, *, suffixes: tuple[str, ...] | None = None) -> list[Path]:
    out: list[Path] = []
    for path in sorted(root.rglob("*")):
        rel_parts = path.relative_to(root).parts
        if any(part in IGNORED_DIRS for part in rel_parts):
            continue
        if not path.is_file():
            continue
        if path.suffix.lower() in IGNORED_SUFFIXES:
            continue
        if suffixes and path.suffix.lower() not in suffixes:
            continue
        out.append(path)
    return out


def destroy(root: Path) -> None:
    shutil.rmtree(root, ignore_errors=True)


def workspace_digest(root: Path) -> str:
    return sha256_text(str(root.resolve()))
