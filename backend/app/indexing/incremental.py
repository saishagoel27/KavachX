"""Incremental indexing: what changed, and what that change affects.

The architecture the spec asks for is in place from the start even though the current build still
re-parses the tree: given two indexes, this module answers *which files changed* and *what the
change reaches*, which is the part that is genuinely hard and the part every consumer needs.

``changed_files`` deliberately compares **content hashes**, not git status. KavachX analyses a
pinned, content-addressed tree that may have no ``.git`` at all (a downloaded archive, a seeded
example, a sandbox workspace copy). A git-diff-only implementation would silently do nothing on
exactly the targets KavachX is most often pointed at. When a git checkout *is* available,
:func:`git_changed_files` is used as a cross-check and its result is unioned in, so a file whose
content hash is unchanged but which git reports as touched is still treated as affected.

The affected closure is the real product: a changed file's symbols, their reverse dependencies,
and the call paths and security flows those participate in. Recomputing that set is what makes an
incremental re-index correct rather than merely fast — miss a reverse dependency and a stale
reachability claim survives into the new index.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.logging import get_logger
from app.indexing.model import CodeGraph, EdgeKind, NodeKind, Precision

logger = get_logger(__name__)


@dataclass
class ChangeSet:
    """What differs between a previous index and the current tree."""

    added: list[str] = field(default_factory=list)
    modified: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    #: How the comparison was made: "content-hash", "content-hash+git", or "none".
    method: str = "none"
    #: True when no previous index was available, so everything is new.
    full: bool = False
    note: str = ""

    @property
    def changed_files(self) -> list[str]:
        return sorted({*self.added, *self.modified, *self.removed})

    @property
    def empty(self) -> bool:
        return not self.changed_files

    def as_dict(self) -> dict[str, Any]:
        return {
            "added": self.added,
            "modified": self.modified,
            "removed": self.removed,
            "changed_files": self.changed_files,
            "method": self.method,
            "full": self.full,
            "note": self.note,
        }


@dataclass
class AffectedClosure:
    """Everything an index must recompute for a given change set."""

    changed_files: list[str] = field(default_factory=list)
    changed_symbols: list[str] = field(default_factory=list)
    #: Symbols that (transitively) call a changed symbol — the reverse-dependency set.
    dependent_symbols: list[str] = field(default_factory=list)
    #: Files importing a changed file.
    dependent_files: list[str] = field(default_factory=list)
    #: Entrypoints whose call paths traverse a changed symbol.
    affected_entrypoints: list[str] = field(default_factory=list)
    #: Truncated when the closure would exceed the cap; the flag prevents a partial closure from
    #: being mistaken for a complete one, which would be the dangerous failure mode.
    truncated: bool = False

    @property
    def all_symbols(self) -> list[str]:
        return sorted({*self.changed_symbols, *self.dependent_symbols})

    def as_dict(self) -> dict[str, Any]:
        return {
            "changed_files": self.changed_files,
            "changed_symbols": self.changed_symbols[:400],
            "dependent_symbols": self.dependent_symbols[:400],
            "dependent_files": self.dependent_files[:200],
            "affected_entrypoints": self.affected_entrypoints[:100],
            "counts": {
                "changed_files": len(self.changed_files),
                "changed_symbols": len(self.changed_symbols),
                "dependent_symbols": len(self.dependent_symbols),
                "dependent_files": len(self.dependent_files),
                "affected_entrypoints": len(self.affected_entrypoints),
            },
            "truncated": self.truncated,
        }


# ---------------------------------------------------------------------------
def file_hashes(graph: CodeGraph) -> dict[str, str]:
    """Per-file content hashes recorded on the graph's FILE nodes.

    The tree-sitter provider stores ``sha256`` per file, so a prior index carries everything the
    comparison needs without re-reading the previous tree — which may no longer exist.
    """
    return {
        node.uid: str(node.attrs.get("sha256", ""))
        for node in graph.nodes_of(NodeKind.FILE.value)
        if node.attrs.get("sha256")
    }


def diff_hashes(previous: dict[str, str], current: dict[str, str]) -> ChangeSet:
    """Compare two file-hash maps."""
    change = ChangeSet(method="content-hash")
    previous_keys = set(previous)
    current_keys = set(current)
    change.added = sorted(current_keys - previous_keys)
    change.removed = sorted(previous_keys - current_keys)
    change.modified = sorted(
        path for path in (previous_keys & current_keys) if previous[path] != current[path]
    )
    return change


def git_changed_files(root: Path, *, base_ref: str = "") -> list[str]:
    """Files git reports as changed, or ``[]`` when there is no usable checkout.

    Used only to *widen* the content-hash result. Returning ``[]`` on any problem is correct here:
    the content-hash comparison is the authority, and git is a cross-check that must never be able
    to shrink the change set.
    """
    if not shutil.which("git") or not (root / ".git").exists():
        return []
    args = ["git", "-C", str(root), "diff", "--name-only"]
    if base_ref:
        args.append(base_ref)
    try:
        out = subprocess.run(
            args, capture_output=True, text=True, timeout=60, check=False
        )
    except Exception as exc:  # pragma: no cover - environment dependent
        logger.warning("incremental.git_diff_failed", error=str(exc)[:200])
        return []
    if out.returncode != 0:
        return []
    return sorted(
        {line.strip().replace("\\", "/") for line in out.stdout.splitlines() if line.strip()}
    )


def compute_change_set(
    *,
    previous_graph: CodeGraph | None,
    current_graph: CodeGraph,
    root: Path | None = None,
    base_ref: str = "",
) -> ChangeSet:
    """The change set between a previous index and the current one."""
    if previous_graph is None:
        current = file_hashes(current_graph)
        return ChangeSet(
            added=sorted(current),
            method="none",
            full=True,
            note="No previous index was available, so the whole tree is treated as new.",
        )

    change = diff_hashes(file_hashes(previous_graph), file_hashes(current_graph))
    if root is not None:
        git_files = git_changed_files(root, base_ref=base_ref)
        if git_files:
            change.method = "content-hash+git"
            known = set(file_hashes(current_graph))
            extra = sorted(set(git_files) & known - set(change.changed_files))
            if extra:
                change.modified = sorted({*change.modified, *extra})
                change.note = (
                    f"{len(extra)} file(s) reported changed by git but content-identical are "
                    "included as modified, because the comparison must never shrink."
                )
    return change


def affected_closure(
    graph: CodeGraph,
    change: ChangeSet,
    *,
    max_depth: int = 6,
    cap: int = 4000,
) -> AffectedClosure:
    """Everything a re-index must recompute for ``change``.

    Walks reverse call edges at ``UNION`` precision on purpose: for deciding *what to recompute*,
    over-approximation is the safe direction — recomputing something that did not need it costs
    time, while missing a reverse dependency leaves a stale fact in the index.
    """
    closure = AffectedClosure(changed_files=change.changed_files)
    changed_files = set(change.changed_files)
    if not changed_files:
        return closure

    changed_symbols = [
        node.uid
        for node in graph.nodes
        if node.file and node.file in changed_files and node.uid not in changed_files
    ]
    closure.changed_symbols = sorted(changed_symbols)

    dependents: set[str] = set()
    for uid in changed_symbols:
        for caller in graph.transitive_callers(
            uid, max_depth=max_depth, precision=Precision.UNION.value
        ):
            dependents.add(caller)
            if len(dependents) >= cap:
                closure.truncated = True
                break
        if closure.truncated:
            break
    dependents -= set(changed_symbols)
    closure.dependent_symbols = sorted(dependents)

    # Files importing a changed file. The tree-sitter provider models imports as statement nodes,
    # so the match is on the statement text containing the changed module's stem.
    stems = {Path(path).stem for path in changed_files if path.endswith((".py", ".js", ".ts"))}
    dependent_files: set[str] = set()
    for node in graph.nodes_of(NodeKind.IMPORT.value):
        statement = str(node.attrs.get("statement", ""))
        if any(stem and stem in statement for stem in stems):
            for edge in graph.in_edges(node.uid, EdgeKind.IMPORTS.value):
                if edge.src not in changed_files:
                    dependent_files.add(edge.src)
    closure.dependent_files = sorted(dependent_files)

    entries = graph.entrypoint_uids()
    affected_entries: set[str] = set()
    for uid in [*changed_symbols, *closure.dependent_symbols]:
        if uid in entries:
            affected_entries.add(uid)
            continue
        result = graph.reachability(uid, precision=Precision.UNION.value, entrypoints=entries)
        if result.reachable and result.path:
            affected_entries.add(result.path[0])
    closure.affected_entrypoints = sorted(affected_entries)

    logger.info(
        "incremental.closure",
        changed_files=len(closure.changed_files),
        changed_symbols=len(closure.changed_symbols),
        dependents=len(closure.dependent_symbols),
        truncated=closure.truncated,
    )
    return closure
