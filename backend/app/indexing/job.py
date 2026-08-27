"""The index job record — indexing as a first-class, auditable stage.

Before this, indexing was an implementation detail: ``tree-sitter happened`` inside a node that
also did probing and world-model construction, and the only trace it left was a symbol count. An
index that silently covered 40% of a repository was indistinguishable from one that covered all of
it, which makes every downstream "we found nothing" unreadable.

:class:`IndexJob` is the record the spec asks for: what was indexed, by what, with what versions,
what it discovered, what it skipped, what went wrong, and how long it took. It is persisted, it is
surfaced in the console, and it travels into the certificate — because the fidelity of the index
bounds every claim built on top of it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


class IndexStatus:
    """Terminal states of an index job.

    ``DEGRADED`` is the important one: indexing succeeded but with reduced fidelity (a provider
    was unavailable, a grammar was missing, files were skipped). It is distinct from ``COMPLETED``
    so that a partial index cannot be read as a complete one, and distinct from ``FAILED`` so a
    usable-but-limited index is not thrown away.
    """

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"


@dataclass
class IndexJob:
    """One indexing run over one pinned tree."""

    # -- identity ---------------------------------------------------------
    #: Reproducible: sha256(source sha + indexer/parser versions + options). See versions.py.
    index_id: str = ""
    repository: str = ""
    commit_sha: str = ""
    source_sha256: str = ""
    #: Structural digest of the produced graph. Two identical indexes agree here.
    graph_hash: str = ""
    #: Derived from actual provider contribution — never asserted. See merge.describe_source.
    graph_source: str = "none"
    versions: dict[str, Any] = field(default_factory=dict)
    options: dict[str, Any] = field(default_factory=dict)

    # -- discovery counters ------------------------------------------------
    languages: dict[str, int] = field(default_factory=dict)
    files_discovered: int = 0
    files_indexed: int = 0
    files_skipped: int = 0
    #: ``[{"path": ..., "reason": ...}]`` — named, not merely counted. An unanalysed file is a
    #: hole in coverage a reader is entitled to see.
    skipped_files: list[dict[str, str]] = field(default_factory=list)
    symbols_discovered: int = 0
    functions: int = 0
    classes: int = 0
    relationships_discovered: int = 0
    call_relationships: int = 0
    import_relationships: int = 0
    resolved_relationships: int = 0
    entrypoints_discovered: int = 0
    tests_discovered: int = 0
    configs_discovered: int = 0
    dependencies_discovered: int = 0

    # -- provider detail ---------------------------------------------------
    providers: list[str] = field(default_factory=list)
    provider_reports: dict[str, Any] = field(default_factory=dict)
    merge_report: dict[str, Any] = field(default_factory=dict)

    # -- diagnostics -------------------------------------------------------
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    status: str = IndexStatus.PENDING

    # -- incremental -------------------------------------------------------
    #: True when this index reused a prior one and only recomputed the affected closure.
    incremental: bool = False
    reused_index_id: str = ""
    changed_files: list[str] = field(default_factory=list)
    affected_symbols: list[str] = field(default_factory=list)

    # -- timing ------------------------------------------------------------
    started_at: str = ""
    completed_at: str = ""
    duration_ms: int = 0
    _monotonic_start: float = 0.0

    # ------------------------------------------------------------------
    def start(self) -> IndexJob:
        self.started_at = datetime.now(timezone.utc).isoformat()
        self._monotonic_start = time.perf_counter()
        self.status = IndexStatus.RUNNING
        return self

    def finish(self, status: str) -> IndexJob:
        self.completed_at = datetime.now(timezone.utc).isoformat()
        if self._monotonic_start:
            self.duration_ms = int((time.perf_counter() - self._monotonic_start) * 1000)
        self.status = status
        return self

    def warn(self, message: str) -> None:
        if message and message not in self.warnings:
            self.warnings.append(message[:600])

    def fail(self, message: str) -> None:
        if message and message not in self.errors:
            self.errors.append(message[:600])

    # ------------------------------------------------------------------
    @property
    def coverage_ratio(self) -> float:
        """Fraction of discovered files that were actually analysed."""
        if not self.files_discovered:
            return 0.0
        return round(self.files_indexed / self.files_discovered, 4)

    @property
    def resolved_ratio(self) -> float:
        """Fraction of relationships a symbol-resolving provider confirmed."""
        if not self.relationships_discovered:
            return 0.0
        return round(self.resolved_relationships / self.relationships_discovered, 4)

    def as_dict(self) -> dict[str, Any]:
        return {
            "index_id": self.index_id,
            "repository": self.repository,
            "commit_sha": self.commit_sha,
            "source_sha256": self.source_sha256,
            "graph_hash": self.graph_hash,
            "graph_source": self.graph_source,
            "versions": self.versions,
            "options": self.options,
            "languages": self.languages,
            "files": {
                "discovered": self.files_discovered,
                "indexed": self.files_indexed,
                "skipped": self.files_skipped,
                "coverage_ratio": self.coverage_ratio,
                "skipped_detail": self.skipped_files[:50],
            },
            "symbols": {
                "total": self.symbols_discovered,
                "functions": self.functions,
                "classes": self.classes,
            },
            "relationships": {
                "total": self.relationships_discovered,
                "calls": self.call_relationships,
                "imports": self.import_relationships,
                "resolved": self.resolved_relationships,
                "resolved_ratio": self.resolved_ratio,
            },
            "discovered": {
                "entrypoints": self.entrypoints_discovered,
                "tests": self.tests_discovered,
                "configs": self.configs_discovered,
                "dependencies": self.dependencies_discovered,
            },
            "providers": self.providers,
            "provider_reports": self.provider_reports,
            "merge_report": self.merge_report,
            "incremental": {
                "enabled": self.incremental,
                "reused_index_id": self.reused_index_id,
                "changed_files": self.changed_files[:100],
                "affected_symbols": self.affected_symbols[:200],
            },
            "errors": self.errors,
            "warnings": self.warnings,
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_ms": self.duration_ms,
        }

    def summary_line(self) -> str:
        """One-line summary for the event stream and logs."""
        return (
            f"{self.files_indexed}/{self.files_discovered} files · "
            f"{self.symbols_discovered} symbols · {self.relationships_discovered} relationships "
            f"({self.resolved_relationships} resolved) · {self.entrypoints_discovered} entrypoints "
            f"· source {self.graph_source} · {self.status}"
        )
