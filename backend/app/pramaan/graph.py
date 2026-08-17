"""PRAMAAN evidence graph.

Every claim a certificate makes points at a node in this graph, and every node carries a
``content_hash`` over its canonical serialisation. That is the whole mechanism: a certificate
cannot assert something for which no evidence node exists, and it cannot drift from the evidence
it cites without the hashes changing.

Shape produced for one finding::

    Vulnerability V17
     ├── discovered_by      → graph/static, runtime, fuzzing
     ├── violated_clause    → SAMHITA C060
     ├── code_evidence      → parser.py:46
     ├── runtime_evidence   → trace
     ├── exploit_evidence   → reproduction record
     ├── shielded_by        → shield #3
     ├── repaired_by        → patch iteration 2
     └── verified_by        → mutation PASS · sibling PASS · replay PASS · contract PASS

:meth:`EvidenceGraph.unsupported_claims` is the check that keeps this honest: it reports any
edge pointing at a node that does not exist, and the certificate builder refuses to issue when
that list is non-empty.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.core.hashing import sha256_json
from app.core.logging import get_logger
from app.models.enums import EvidenceNodeType, EvidenceRelation

logger = get_logger(__name__)


@dataclass(slots=True)
class Node:
    ref: str
    type: str
    title: str
    content: str = ""
    meta: dict[str, Any] = field(default_factory=dict)
    produced_by: str = ""

    @property
    def content_hash(self) -> str:
        return sha256_json(
            {
                "ref": self.ref,
                "type": self.type,
                "title": self.title,
                "content": self.content,
                "meta": self.meta,
            }
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "ref": self.ref,
            "type": self.type,
            "title": self.title,
            "content": self.content,
            "content_hash": self.content_hash,
            "meta": self.meta,
            "produced_by": self.produced_by,
        }


@dataclass(slots=True)
class Edge:
    source_ref: str
    relation: str
    target_ref: str
    meta: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "source_ref": self.source_ref,
            "relation": self.relation,
            "target_ref": self.target_ref,
            "meta": self.meta,
        }

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.source_ref, self.relation, self.target_ref)


class EvidenceGraph:
    def __init__(self) -> None:
        self._nodes: dict[str, Node] = {}
        self._edges: dict[tuple[str, str, str], Edge] = {}

    # -- construction ------------------------------------------------------
    def add_node(
        self,
        *,
        ref: str,
        type: str,
        title: str,
        content: str = "",
        meta: dict[str, Any] | None = None,
        produced_by: str = "",
    ) -> Node:
        node = Node(
            ref=ref,
            type=type,
            title=title[:500],
            content=content,
            meta=meta or {},
            produced_by=produced_by,
        )
        self._nodes[ref] = node
        return node

    def add_edge(self, source_ref: str, relation: str, target_ref: str, **meta: Any) -> Edge:
        edge = Edge(source_ref=source_ref, relation=relation, target_ref=target_ref, meta=meta)
        self._edges[edge.key] = edge
        return edge

    def has(self, ref: str) -> bool:
        return ref in self._nodes

    # -- access ------------------------------------------------------------
    @property
    def nodes(self) -> list[Node]:
        return [self._nodes[ref] for ref in sorted(self._nodes)]

    @property
    def edges(self) -> list[Edge]:
        return [self._edges[key] for key in sorted(self._edges)]

    def node(self, ref: str) -> Node | None:
        return self._nodes.get(ref)

    def neighbours(self, ref: str) -> list[tuple[str, str]]:
        return sorted(
            [(edge.relation, edge.target_ref) for edge in self.edges if edge.source_ref == ref]
        )

    def incoming(self, ref: str) -> list[tuple[str, str]]:
        return sorted(
            [(edge.relation, edge.source_ref) for edge in self.edges if edge.target_ref == ref]
        )

    def subgraph_for(self, root_ref: str, *, max_depth: int = 4) -> dict[str, Any]:
        """Everything reachable from one vulnerability node — what the UI renders."""
        seen: set[str] = {root_ref}
        frontier = [root_ref]
        depth = 0
        while frontier and depth < max_depth:
            nxt: list[str] = []
            for ref in frontier:
                for _relation, target in self.neighbours(ref):
                    if target not in seen:
                        seen.add(target)
                        nxt.append(target)
            frontier = nxt
            depth += 1
        return {
            "root": root_ref,
            "nodes": [n.as_dict() for n in self.nodes if n.ref in seen],
            "edges": [
                e.as_dict() for e in self.edges if e.source_ref in seen and e.target_ref in seen
            ],
        }

    # -- integrity ---------------------------------------------------------
    def unsupported_claims(self) -> list[dict[str, str]]:
        """Edges pointing at a node that does not exist.

        A certificate with dangling evidence would be worse than no certificate: it looks
        substantiated and is not. The builder treats a non-empty result here as fatal.
        """
        problems: list[dict[str, str]] = []
        for edge in self.edges:
            if edge.source_ref not in self._nodes:
                problems.append(
                    {
                        "edge": f"{edge.source_ref} -{edge.relation}-> {edge.target_ref}",
                        "problem": f"source node {edge.source_ref} does not exist",
                    }
                )
            if edge.target_ref not in self._nodes:
                problems.append(
                    {
                        "edge": f"{edge.source_ref} -{edge.relation}-> {edge.target_ref}",
                        "problem": f"target node {edge.target_ref} does not exist",
                    }
                )
        return problems

    def orphan_nodes(self) -> list[str]:
        connected: set[str] = set()
        for edge in self.edges:
            connected.add(edge.source_ref)
            connected.add(edge.target_ref)
        return sorted(set(self._nodes) - connected)

    def graph_hash(self) -> str:
        return sha256_json(
            {
                "nodes": [n.content_hash for n in self.nodes],
                "edges": [e.as_dict() for e in self.edges],
            }
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": "kavachx.pramaan.graph.v1",
            "nodes": [n.as_dict() for n in self.nodes],
            "edges": [e.as_dict() for e in self.edges],
            "graph_hash": self.graph_hash(),
            "counts": {"nodes": len(self._nodes), "edges": len(self._edges)},
        }

    def stats(self) -> dict[str, Any]:
        by_type: dict[str, int] = {}
        for node in self.nodes:
            by_type[node.type] = by_type.get(node.type, 0) + 1
        by_relation: dict[str, int] = {}
        for edge in self.edges:
            by_relation[edge.relation] = by_relation.get(edge.relation, 0) + 1
        return {
            "nodes": len(self._nodes),
            "edges": len(self._edges),
            "by_type": by_type,
            "by_relation": by_relation,
            "orphans": len(self.orphan_nodes()),
            "unsupported_claims": len(self.unsupported_claims()),
        }


# ---------------------------------------------------------------------------
# Canonical ref builders — one place, so refs never drift between producers.
# ---------------------------------------------------------------------------
def ref_vulnerability(handle: str) -> str:
    return f"ev:vuln:{handle}"


def ref_channel(channel: str) -> str:
    return f"ev:channel:{channel}"


def ref_clause(clause_id: str) -> str:
    return f"ev:clause:{clause_id}"


def ref_code(location: str) -> str:
    return f"ev:code:{location}"


def ref_runtime(digest: str) -> str:
    return f"ev:runtime:{digest[:16]}"


def ref_reproduction(handle: str) -> str:
    return f"ev:repro:{handle}"


def ref_shield(handle: str) -> str:
    return f"ev:shield:{handle}"


def ref_patch(handle: str, iteration: int) -> str:
    return f"ev:patch:{handle}:v{iteration}"


def ref_gauntlet(handle: str, iteration: int, stage: str) -> str:
    return f"ev:gauntlet:{handle}:v{iteration}:{stage}"


def ref_blast(handle: str) -> str:
    return f"ev:blast:{handle}"


def ref_world_model(digest: str) -> str:
    return f"ev:world:{digest[:16]}"


def ref_sandbox(session_id: str) -> str:
    return f"ev:sandbox:{session_id}"


def ref_certificate(serial: str) -> str:
    return f"ev:cert:{serial}"


NODE_TYPES = EvidenceNodeType
RELATIONS = EvidenceRelation
