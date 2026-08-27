"""Indexer and parser versions, and the reproducible index identity built from them.

The spec's requirement is that

    repository SHA + indexer version + parser version

deterministically identifies an index. That is what :func:`compute_index_id` provides, and it is
the reason it exists as its own module: the identity must be computable *before* indexing starts
(to decide whether an existing index can be reused) and recomputable afterwards (to prove the
index in the certificate is the one the run actually used).

Two things are deliberately excluded from the identity:

* **Timings and counts.** They vary between runs of the same index and would make every identity
  unique, defeating the purpose.
* **Anything the operator can change without changing the analysis**, such as log level.

Everything that *does* change what the graph contains is included — including the flags that
change indexing behaviour (``--pdg``, the file-size ceiling), because two indexes built with
different ceilings are genuinely different indexes and must not share an id.
"""

from __future__ import annotations

import importlib.metadata
import platform
import sys
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from app.core.hashing import sha256_json
from app.core.logging import get_logger

logger = get_logger(__name__)

#: KavachX's own indexing contract version. Bump this whenever the *meaning* of the produced graph
#: changes — a new edge kind, a changed uid scheme, a different call-resolution rule — so that an
#: index built by an older KavachX is never mistaken for one built by this code.
INDEXER_VERSION = "kavachx.indexing.v1"

#: Python packages whose versions affect the parse result.
_PARSER_PACKAGES = (
    "tree-sitter",
    "tree-sitter-python",
    "tree-sitter-c",
    "tree-sitter-javascript",
)


@lru_cache(maxsize=1)
def parser_versions() -> dict[str, str]:
    """Installed versions of every parser that can change the index.

    A missing grammar is recorded as ``"absent"`` rather than omitted: "we had no C grammar" is a
    fact about the index's fidelity and belongs in its identity, because the same tree indexed
    with and without the C grammar yields different graphs.
    """
    out: dict[str, str] = {}
    for package in _PARSER_PACKAGES:
        try:
            out[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            out[package] = "absent"
    return out


@lru_cache(maxsize=1)
def grammar_availability() -> dict[str, bool]:
    """Which tree-sitter grammars actually load. Installed is not the same as loadable."""
    from app.analysis.indexer import _load_language

    return {
        language: _load_language(language) is not None
        for language in ("python", "c", "javascript")
    }


@dataclass(slots=True)
class IndexerVersions:
    """The full version surface of one indexing run."""

    indexer_version: str = INDEXER_VERSION
    python_version: str = ""
    platform: str = ""
    parsers: dict[str, str] = field(default_factory=dict)
    grammars: dict[str, bool] = field(default_factory=dict)
    gitnexus_version: str = ""
    gitnexus_resolution: str = ""
    node_version: str = ""
    semgrep_version: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "indexer_version": self.indexer_version,
            "python_version": self.python_version,
            "platform": self.platform,
            "parsers": self.parsers,
            "grammars": self.grammars,
            "gitnexus_version": self.gitnexus_version,
            "gitnexus_resolution": self.gitnexus_resolution,
            "node_version": self.node_version,
            "semgrep_version": self.semgrep_version,
        }

    def identity_fields(self) -> dict[str, Any]:
        """The subset that participates in the index id.

        ``gitnexus_resolution`` and ``platform`` are excluded: how the binary was located, and
        which OS ran it, do not change what a given GitNexus version extracts from a given tree.
        Including them would fragment the identity across machines for no analytical reason.
        """
        return {
            "indexer_version": self.indexer_version,
            "parsers": dict(sorted(self.parsers.items())),
            "grammars": dict(sorted(self.grammars.items())),
            "gitnexus_version": self.gitnexus_version,
            "semgrep_version": self.semgrep_version,
        }


def collect_versions(
    *,
    gitnexus_version: str = "",
    gitnexus_resolution: str = "",
    node_version: str = "",
) -> IndexerVersions:
    return IndexerVersions(
        indexer_version=INDEXER_VERSION,
        python_version=sys.version.split()[0],
        platform=f"{platform.system()}-{platform.machine()}",
        parsers=parser_versions(),
        grammars=grammar_availability(),
        gitnexus_version=gitnexus_version,
        gitnexus_resolution=gitnexus_resolution,
        node_version=node_version,
        semgrep_version=_semgrep_version(),
    )


def _semgrep_version() -> str:
    """Semgrep's version, or ``"absent"``. It changes which static candidates are produced."""
    import shutil
    import subprocess

    binary = shutil.which("semgrep")
    if not binary:
        return "absent"
    try:
        out = subprocess.run(
            [binary, "--version"], capture_output=True, text=True, timeout=30, check=False
        )
        return (out.stdout or "").strip().splitlines()[0][:40] or "unknown"
    except Exception:  # pragma: no cover - environment dependent
        return "unknown"


def compute_index_id(
    *,
    source_sha256: str,
    versions: IndexerVersions,
    options: dict[str, Any] | None = None,
) -> str:
    """The reproducible identity of an index.

    Same tree + same indexer/parser versions + same options => same id, on any machine. This is
    what makes "the index in this certificate is the index that produced these findings" a
    checkable claim rather than an assertion.
    """
    return sha256_json(
        {
            "source_sha256": source_sha256,
            "versions": versions.identity_fields(),
            "options": dict(sorted((options or {}).items())),
        }
    )


def index_options() -> dict[str, Any]:
    """Indexing options that change the graph, and therefore the index id."""
    from app.config import settings

    return {
        "gitnexus_enabled": settings.gitnexus_enabled,
        "gitnexus_pdg": settings.gitnexus_pdg,
        "gitnexus_max_file_size_kb": settings.gitnexus_max_file_size_kb,
        "gitnexus_skip_optional_grammars": settings.gitnexus_skip_optional_grammars,
        "max_files": settings.index_max_files,
    }
