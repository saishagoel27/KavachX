"""Code-intelligence evidence for PRAMAAN.

A certificate is only as good as what it lets a reader check. Before the code-intelligence layer
existed, a certificate could say "the finding is reachable" and point at a world-model hash — which
is a digest of a graph the reader has no way to interrogate, built by an indexer whose fidelity was
not recorded.

This module adds the evidence that closes that gap, as first-class nodes in the same evidence graph
the rest of PRAMAAN uses (so the dangling-claim refusal applies to them too):

* **the index** — its reproducible id, the providers that actually contributed, the resolved-vs-
  name-matched relationship ratio, and the health grade;
* **the claim bounds** — what the index is *not* good enough to support, as evidence rather than as
  a footnote;
* **the architecture model and attack surface** — what the application is and what ranked path this
  finding sat on;
* **the security flow** — the source, the sink, the path, the basis, the precision, the sanitizers;
* **the test specification and generated harness** — hashed, so "this test proves it" names a
  specific file;
* **the execution record** — the command, the environment's honest capability flags, per-attempt
  exit codes and output hashes, the reproduction count;
* **coverage** — as a bound, with an explicit "not measured" where nothing ran.

The design rule throughout: an absence is recorded as an absence. A certificate for a run where
coverage was never measured says so, rather than omitting the field and letting a reader assume.
"""

from __future__ import annotations

from typing import Any

from app.core.logging import get_logger
from app.models.enums import EvidenceNodeType, EvidenceRelation
from app.pramaan.graph import EvidenceGraph, ref_vulnerability

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# refs — one place, so they never drift between producer and consumer
# ---------------------------------------------------------------------------
def ref_index(index_id: str) -> str:
    return f"ev:index:{index_id[:16]}"


def ref_index_health(index_id: str) -> str:
    return f"ev:index_health:{index_id[:16]}"


def ref_code_graph(graph_hash: str) -> str:
    return f"ev:code_graph:{graph_hash[:16]}"


def ref_architecture(content_hash: str) -> str:
    return f"ev:architecture:{content_hash[:16]}"


def ref_attack_surface(content_hash: str) -> str:
    return f"ev:attack_surface:{content_hash[:16]}"


def ref_security_flow(flow_ref: str) -> str:
    return f"ev:flow:{flow_ref}"


def ref_test_spec(plan_id: str) -> str:
    return f"ev:testspec:{plan_id[:16]}"


def ref_harness(sha256: str) -> str:
    return f"ev:harness:{sha256[:16]}"


def ref_test_execution(plan_id: str) -> str:
    return f"ev:test_exec:{plan_id[:16]}"


def ref_coverage(digest: str) -> str:
    return f"ev:coverage:{digest[:16]}"


def ref_model_context(context_hash: str) -> str:
    return f"ev:model_context:{context_hash[:16]}"


# ---------------------------------------------------------------------------
def attach(
    graph: EvidenceGraph,
    *,
    finding_handle: str,
    index: dict[str, Any] | None,
    index_health: dict[str, Any] | None,
    graph_summary: dict[str, Any] | None,
    architecture: dict[str, Any] | None,
    attack_surface: dict[str, Any] | None,
    security_flow: dict[str, Any] | None,
    test_plans: list[dict[str, Any]] | None,
    test_executions: list[dict[str, Any]] | None,
    coverage: dict[str, Any] | None,
    model_context: dict[str, Any] | None,
    regression: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Add code-intelligence evidence for one finding. Returns a summary for the document.

    Every node added here is wired to the vulnerability node, so a dangling reference is caught by
    :meth:`EvidenceGraph.unsupported_claims` and the certificate is refused rather than issued with
    an unsupported claim.
    """
    vuln_ref = ref_vulnerability(finding_handle)
    summary: dict[str, Any] = {}

    # -- the index ---------------------------------------------------------
    if index:
        index_id = str(index.get("index_id", ""))
        node_ref = ref_index(index_id)
        relationships = index.get("relationships") or {}
        files = index.get("files") or {}
        graph.add_node(
            ref=node_ref,
            type=EvidenceNodeType.WORLD_MODEL.value,
            title=(
                f"repository index {index_id[:12]} "
                f"({index.get('graph_source', 'unknown')}, {index.get('status', '')})"
            ),
            meta={
                "index_id": index_id,
                "graph_source": index.get("graph_source", ""),
                "status": index.get("status", ""),
                "providers": index.get("providers", []),
                "versions": index.get("versions", {}),
                "options": index.get("options", {}),
                "graph_hash": index.get("graph_hash", ""),
                "files": files,
                "symbols": index.get("symbols", {}),
                "relationships": relationships,
                "discovered": index.get("discovered", {}),
                "duration_ms": index.get("duration_ms", 0),
                # The single most important qualifier on any reachability claim in this document.
                "resolved_relationship_ratio": relationships.get("resolved_ratio", 0.0),
                "reproducibility_note": (
                    "The index id is sha256 over the pinned source hash, the indexer and parser "
                    "versions, and the indexing options. The same tree indexed by the same "
                    "versions with the same options yields this id on any machine."
                ),
            },
            produced_by="indexing/service",
        )
        graph.add_edge(vuln_ref, EvidenceRelation.CODE_EVIDENCE.value, node_ref)
        summary["index"] = {
            "index_id": index_id,
            "graph_source": index.get("graph_source", ""),
            "status": index.get("status", ""),
            "providers": index.get("providers", []),
            "files_indexed": files.get("indexed", 0),
            "files_skipped": files.get("skipped", 0),
            "resolved_relationship_ratio": relationships.get("resolved_ratio", 0.0),
        }

        # -- index health, as its own node -------------------------------
        if index_health:
            health_ref = ref_index_health(index_id)
            graph.add_node(
                ref=health_ref,
                type=EvidenceNodeType.WORLD_MODEL.value,
                title=f"index health grade {index_health.get('grade', '?')}",
                content="\n".join(
                    f"[{c.get('severity', '').upper()}] {c.get('title', '')}: {c.get('detail', '')}"
                    for c in (index_health.get("checks") or [])
                )[:20000],
                meta={
                    "grade": index_health.get("grade", ""),
                    "usable": index_health.get("usable", False),
                    "counts": index_health.get("counts", {}),
                    # Carried as evidence, not prose: these are the claims this run may not make.
                    "claim_bounds": index_health.get("claim_bounds", []),
                },
                produced_by="indexing/health",
            )
            graph.add_edge(vuln_ref, EvidenceRelation.CODE_EVIDENCE.value, health_ref)
            summary["index_health"] = {
                "grade": index_health.get("grade", ""),
                "claim_bounds": index_health.get("claim_bounds", []),
            }

    # -- the code graph ----------------------------------------------------
    if graph_summary:
        graph_hash = str(graph_summary.get("graph_hash", ""))
        node_ref = ref_code_graph(graph_hash)
        graph.add_node(
            ref=node_ref,
            type=EvidenceNodeType.WORLD_MODEL.value,
            title=f"code knowledge graph {graph_hash[:12]}",
            meta=dict(graph_summary),
            produced_by="indexing/merge",
        )
        graph.add_edge(vuln_ref, EvidenceRelation.CODE_EVIDENCE.value, node_ref)
        summary["code_graph"] = {
            "graph_hash": graph_hash,
            "functions": graph_summary.get("functions", 0),
            "call_edges": graph_summary.get("call_edges", 0),
            "entrypoints": graph_summary.get("entrypoints", 0),
            "resolved_edge_ratio": graph_summary.get("resolved_edge_ratio", 0.0),
        }

    # -- architecture and attack surface -----------------------------------
    if architecture:
        arch_ref = ref_architecture(str(architecture.get("content_hash", "")) or "derived")
        graph.add_node(
            ref=arch_ref,
            type=EvidenceNodeType.WORLD_MODEL.value,
            title=f"application model: {architecture.get('application_type', 'unknown')}",
            meta={
                "application_type": architecture.get("application_type", ""),
                "type_evidence": architecture.get("type_evidence", []),
                "languages": architecture.get("languages", {}),
                "frameworks": architecture.get("frameworks", []),
                "authentication": architecture.get("authentication", []),
                "authorization": architecture.get("authorization", []),
                "data_stores": architecture.get("data_stores", []),
                "external_services": architecture.get("external_services", []),
                "trust_boundaries": architecture.get("trust_boundaries", []),
                "sources": architecture.get("sources", {}),
                "sinks": architecture.get("sinks", {}),
                "security_controls": architecture.get("security_controls", []),
                "tests": architecture.get("tests", {}),
                # What the model does not know. Part of the evidence, not a caveat.
                "gaps": architecture.get("gaps", []),
                "model_annotated": architecture.get("model_annotated", False),
            },
            produced_by="understanding/architecture",
        )
        graph.add_edge(vuln_ref, EvidenceRelation.CODE_EVIDENCE.value, arch_ref)
        summary["architecture"] = {
            "application_type": architecture.get("application_type", ""),
            "frameworks": architecture.get("frameworks", []),
            "entrypoints": len(architecture.get("entrypoints", []) or []),
            "gaps": architecture.get("gaps", []),
        }

    if attack_surface:
        surface_ref = ref_attack_surface(
            str(attack_surface.get("content_hash", "")) or "derived"
        )
        graph.add_node(
            ref=surface_ref,
            type=EvidenceNodeType.WORLD_MODEL.value,
            title="attack surface"
            + ("" if attack_surface.get("measured", True) else " (NOT MEASURED)"),
            meta={
                "measured": attack_surface.get("measured", True),
                "counts": attack_surface.get("counts", {}),
                "unauthenticated_entrypoints": attack_surface.get(
                    "unauthenticated_entrypoints", []
                ),
                "unreached_sinks": attack_surface.get("unreached_sinks", []),
                "untested_paths": attack_surface.get("untested_paths", []),
                "notes": attack_surface.get("notes", []),
            },
            produced_by="understanding/attack_surface",
        )
        graph.add_edge(vuln_ref, EvidenceRelation.SCOPED_BY.value, surface_ref)
        summary["attack_surface"] = {
            "measured": attack_surface.get("measured", True),
            "counts": attack_surface.get("counts", {}),
        }

    # -- the security flow this finding came from --------------------------
    if security_flow:
        flow_ref = ref_security_flow(str(security_flow.get("ref", "")))
        graph.add_node(
            ref=flow_ref,
            type=EvidenceNodeType.CODE_LOCATION.value,
            title=(
                f"data flow: {security_flow.get('source_kind', '')} → "
                f"{security_flow.get('sink_kind', '')}"
            ),
            content="\n".join(str(s) for s in (security_flow.get("steps") or []))[:20000],
            meta={
                "ref": security_flow.get("ref", ""),
                "source_kind": security_flow.get("source_kind", ""),
                "sink_kind": security_flow.get("sink_kind", ""),
                "cwe": security_flow.get("cwe", ""),
                # basis + precision are what qualify the flow. A taint-proven flow and a
                # name-matched call path are different claims and must not read the same.
                "basis": security_flow.get("basis", ""),
                "precision": security_flow.get("precision", ""),
                "confidence": security_flow.get("confidence", 0.0),
                "reachable_from_entrypoint": security_flow.get(
                    "reachable_from_entrypoint", False
                ),
                "reachability_measured": security_flow.get("reachability_measured", True),
                "entrypoint": security_flow.get("entrypoint", ""),
                "sanitizers": security_flow.get("sanitizers", []),
                "validators": security_flow.get("validators", []),
                "boundaries": security_flow.get("boundaries", []),
                "covering_tests": security_flow.get("covering_tests", []),
                "notes": security_flow.get("notes", []),
            },
            produced_by="security_model/builder",
        )
        graph.add_edge(vuln_ref, EvidenceRelation.CODE_EVIDENCE.value, flow_ref)
        summary["security_flow"] = {
            "ref": security_flow.get("ref", ""),
            "basis": security_flow.get("basis", ""),
            "precision": security_flow.get("precision", ""),
            "boundaries": security_flow.get("boundaries", []),
            "sanitized": bool(security_flow.get("sanitizers")),
        }

    # -- test specifications and generated harnesses -----------------------
    specs_summary: list[dict[str, Any]] = []
    for plan in test_plans or []:
        plan_id = str(plan.get("plan_id", ""))
        spec = dict(plan.get("spec") or {})
        spec_ref = ref_test_spec(plan_id)
        graph.add_node(
            ref=spec_ref,
            type=EvidenceNodeType.REPRODUCTION.value,
            title=(
                f"test specification {spec.get('strategy', '')} "
                f"(oracle {(spec.get('oracle') or {}).get('kind', '')})"
            ),
            meta={
                "plan_id": plan_id,
                "status": plan.get("status", ""),
                "engine": plan.get("engine", ""),
                "engine_available": plan.get("engine_available", False),
                "engine_reason": plan.get("engine_reason", ""),
                "strategy": spec.get("strategy", ""),
                "oracle": spec.get("oracle", {}),
                "expected_security_property": spec.get("expected_security_property", ""),
                "input_source": spec.get("input_source", ""),
                "reproductions_required": spec.get("reproductions_required", 0),
                "notes": plan.get("notes", []),
                "authority_note": (
                    "A model may propose the fields of this specification. It cannot supply code, "
                    "a command, an interpreter or a path: the harness is generated from a KavachX "
                    "template and every value is inserted as a data literal."
                ),
            },
            produced_by="testing/synthesis",
        )
        graph.add_edge(vuln_ref, EvidenceRelation.EXPLOIT_EVIDENCE.value, spec_ref)

        harness_hash = str(plan.get("harness_sha256", ""))
        if harness_hash:
            harness_ref = ref_harness(harness_hash)
            graph.add_node(
                ref=harness_ref,
                type=EvidenceNodeType.REPRODUCTION.value,
                title=f"generated harness {plan.get('harness_path', '')}",
                meta={
                    "path": plan.get("harness_path", ""),
                    "sha256": harness_hash,
                    "command": plan.get("command", []),
                    "engine": plan.get("engine", ""),
                    # The harness is stored as a run artifact, so this hash identifies a file a
                    # reader can actually fetch and diff.
                    "artifact_note": (
                        "The harness is stored verbatim as a run artifact. This hash identifies "
                        "exactly what was executed."
                    ),
                },
                produced_by="testing/harness",
            )
            graph.add_edge(spec_ref, EvidenceRelation.EXPLOIT_EVIDENCE.value, harness_ref)

        specs_summary.append(
            {
                "plan_id": plan_id,
                "strategy": spec.get("strategy", ""),
                "engine": plan.get("engine", ""),
                "oracle": (spec.get("oracle") or {}).get("kind", ""),
                "status": plan.get("status", ""),
                "harness_sha256": harness_hash,
                "security_property": spec.get("expected_security_property", ""),
            }
        )
    if specs_summary:
        summary["test_specifications"] = specs_summary

    # -- execution records -------------------------------------------------
    executions_summary: list[dict[str, Any]] = []
    for record in test_executions or []:
        if "campaign" in record:
            # A coverage-guided campaign, not a single execution.
            campaign = dict(record.get("campaign") or {})
            executions_summary.append(
                {
                    "kind": "fuzz_campaign",
                    "plan_id": record.get("plan_id", ""),
                    "executions": campaign.get("executions", 0),
                    "rounds": campaign.get("rounds_run", 0),
                    "corpus_size": campaign.get("corpus_size", 0),
                    "signals_found": len(campaign.get("crashes") or []),
                    "coverage": campaign.get("coverage", {}),
                    "model_candidates": (campaign.get("model") or {}).get("candidates", 0),
                    "model_candidates_useful": (campaign.get("model") or {}).get(
                        "candidates_useful", 0
                    ),
                    "stopped_because": campaign.get("stopped_because", ""),
                }
            )
            continue

        plan_id = str(record.get("plan_id", ""))
        exec_ref = ref_test_execution(plan_id)
        graph.add_node(
            ref=exec_ref,
            type=EvidenceNodeType.SANDBOX_EXECUTION.value,
            title=(
                f"test execution {record.get('strategy', '')} — "
                + ("reproduced" if record.get("reproduced") else "did not reproduce")
            ),
            meta={
                "plan_id": plan_id,
                "strategy": record.get("strategy", ""),
                "engine": record.get("engine", ""),
                "command": record.get("command", []),
                "harness_sha256": record.get("harness_sha256", ""),
                "commit_sha": record.get("commit_sha", ""),
                "index_id": record.get("index_id", ""),
                "input_hash": record.get("input_hash", ""),
                # The environment's honest capability flags: a reproduction under the dev adapter
                # and one under gVisor are not equally strong evidence.
                "environment": record.get("environment", {}),
                "reproduced": record.get("reproduced", False),
                "reproduction_count": record.get("reproduction_count", 0),
                "reproductions_required": record.get("reproductions_required", 0),
                "verdict_detail": record.get("verdict_detail", ""),
                "proving_evidence": record.get("proving_evidence", ""),
                "attempts": record.get("attempts", []),
                "coverage": record.get("coverage", {}),
                "error": record.get("error", ""),
            },
            produced_by="testing/executor",
        )
        graph.add_edge(vuln_ref, EvidenceRelation.RUNTIME_EVIDENCE.value, exec_ref)
        spec_ref = ref_test_spec(plan_id)
        if graph.has(spec_ref):
            graph.add_edge(spec_ref, EvidenceRelation.VERIFIED_BY.value, exec_ref)

        executions_summary.append(
            {
                "kind": "test_execution",
                "plan_id": plan_id,
                "strategy": record.get("strategy", ""),
                "engine": record.get("engine", ""),
                "reproduced": record.get("reproduced", False),
                "reproduction_count": record.get("reproduction_count", 0),
                "verdict_detail": record.get("verdict_detail", ""),
                "adapter": (record.get("environment") or {}).get("adapter", ""),
                "network_enforced": (record.get("environment") or {}).get(
                    "network_enforced", False
                ),
            }
        )
    if executions_summary:
        summary["test_executions"] = executions_summary

    # -- coverage ----------------------------------------------------------
    coverage = coverage or {"measured": False, "reason": "No coverage was measured in this run."}
    digest = str(coverage.get("content_hash") or coverage.get("percent", "none"))
    coverage_ref = ref_coverage(str(digest))
    graph.add_node(
        ref=coverage_ref,
        type=EvidenceNodeType.RUNTIME_TRACE.value,
        title=(
            f"coverage {coverage.get('percent', 0.0)}%"
            if coverage.get("measured")
            else "coverage NOT MEASURED"
        ),
        meta={
            "measured": coverage.get("measured", False),
            "reason": coverage.get("reason", ""),
            "source": coverage.get("source", ""),
            "percent": coverage.get("percent", 0.0),
            "covered_statements": coverage.get("covered_statements", 0),
            "total_statements": coverage.get("total_statements", 0),
            "bound_note": (
                "Coverage is the single most important qualifier on any assurance level here: code "
                "that did not execute was not dynamically verified."
            ),
        },
        produced_by="testing/coverage",
    )
    graph.add_edge(vuln_ref, EvidenceRelation.RUNTIME_EVIDENCE.value, coverage_ref)
    summary["coverage"] = {
        "measured": coverage.get("measured", False),
        "percent": coverage.get("percent", 0.0),
        "reason": coverage.get("reason", ""),
    }

    # -- the model context, for inspection ---------------------------------
    if model_context:
        context_hash = str(model_context.get("context_hash", ""))
        context_ref = ref_model_context(context_hash)
        graph.add_node(
            ref=context_ref,
            type=EvidenceNodeType.REPRODUCTION.value,
            title=f"model context {context_hash[:12]} ({model_context.get('task', '')})",
            meta={
                "context_hash": context_hash,
                "version": model_context.get("version", ""),
                "task": model_context.get("task", ""),
                "provider": model_context.get("provider", ""),
                "model": model_context.get("model", ""),
                "size_chars": model_context.get("size_chars", 0),
                "selected_files": model_context.get("selected_files", []),
                "selected_functions": model_context.get("selected_functions", []),
                "code_slice_keys": model_context.get("code_slice_keys", []),
                "tool_call_count": len(model_context.get("tool_calls") or []),
                "budget": model_context.get("budget", {}),
                "used": model_context.get("used", {}),
                # What was dropped for budget. A model reasoning over an elided path should be
                # visible to whoever is debugging its output.
                "dropped": model_context.get("dropped", []),
                "trust_note": (
                    "Repository content reached the model only inside keys prefixed UNTRUSTED_, "
                    "as JSON values, never concatenated into an instruction."
                ),
            },
            produced_by="llm/context",
        )
        graph.add_edge(vuln_ref, EvidenceRelation.DISCOVERED_BY.value, context_ref)
        summary["model_context"] = {
            "context_hash": context_hash,
            "provider": model_context.get("provider", ""),
            "model": model_context.get("model", ""),
            "size_chars": model_context.get("size_chars", 0),
            "selected_functions": model_context.get("selected_functions", []),
            "dropped": model_context.get("dropped", []),
        }

    # -- regression guard --------------------------------------------------
    if regression:
        plans = regression.get("plans") or []
        artifacts = regression.get("artifacts") or []
        mine = [p for p in plans if p.get("finding_handle") == finding_handle]
        if mine or artifacts:
            summary["regression"] = {
                "plans": len(mine),
                "artifacts": [
                    {
                        "path": a.get("path", ""),
                        "framework": a.get("framework", ""),
                        "sha256": a.get("sha256", ""),
                    }
                    for a in artifacts
                ],
                "notes": regression.get("notes", []),
            }

    logger.info(
        "pramaan.intel_evidence",
        finding=finding_handle,
        sections=sorted(summary.keys()),
        nodes=len(graph.nodes),
    )
    return summary


# ---------------------------------------------------------------------------
def explains(summary: dict[str, Any], finding: dict[str, Any]) -> dict[str, str]:
    """The spec's §59 questions, answered from the attached evidence.

    Rendered into the certificate so a reader does not have to reassemble the answers from the
    evidence graph themselves. Every answer here is a restatement of stored evidence — where the
    evidence is absent, the answer says so rather than being omitted.
    """
    flow = summary.get("security_flow") or {}
    index = summary.get("index") or {}
    health = summary.get("index_health") or {}
    coverage = summary.get("coverage") or {}
    specs = summary.get("test_specifications") or []
    executions = [
        e for e in (summary.get("test_executions") or []) if e.get("kind") == "test_execution"
    ]
    proving = next((e for e in executions if e.get("reproduced")), None)

    def _unknown(reason: str) -> str:
        return f"NOT ESTABLISHED — {reason}"

    return {
        "where_is_the_vulnerability": (
            f"{finding.get('location', '') or 'unknown'}"
            + (
                f", root cause at {finding['root_cause_location']}"
                if finding.get("root_cause_location")
                else ""
            )
            + (
                " (root cause verified on the executed path)"
                if finding.get("root_cause_verified")
                else " (root cause UNVERIFIED — taken from the deepest executed frame)"
            )
        ),
        "why_is_the_path_reachable": (
            f"A call path from entrypoint {flow.get('entrypoint') or 'unknown'} at "
            f"{flow.get('precision', 'unknown')} precision, established by "
            f"{flow.get('basis', 'unknown')}."
            + (
                f" {index.get('resolved_relationship_ratio', 0.0) * 100:.0f}% of the index's "
                "relationships were resolved by a symbol-resolving indexer; the remainder are "
                "name matches."
                if index
                else ""
            )
            if flow
            else _unknown("no security flow was attached to this finding")
        ),
        "what_input_controls_it": (
            f"{flow.get('source_kind', '')} crossing {', '.join(flow.get('boundaries') or []) or 'no recorded boundary'}"
            if flow
            else _unknown("no source was attached")
        ),
        "what_sink_is_reached": (
            f"{flow.get('sink_kind', '')}"
            + (
                ", with sanitizer(s) present on the path — presence is not proof of execution"
                if flow.get("sanitized")
                else ", with no sanitizer on the path"
            )
            if flow
            else _unknown("no sink was attached")
        ),
        "what_test_proves_it": (
            f"{proving.get('strategy')} harness via {proving.get('engine')} "
            f"(plan {proving.get('plan_id', '')[:12]}), reproduced "
            f"{proving.get('reproduction_count')}x"
            if proving
            else (
                f"{len(specs)} test specification(s) were generated but none reproduced the "
                "property"
                if specs
                else _unknown("no generated test reproduced this finding")
            )
        ),
        "what_happened_during_execution": (
            f"{proving.get('verdict_detail', '')} Adapter {proving.get('adapter')}, "
            f"network_enforced={proving.get('network_enforced')}."
            if proving
            else _unknown("no execution record reproduced the property")
        ),
        "coverage_bound": (
            f"{coverage.get('percent', 0.0)}% of statements executed; code that did not run was "
            "not dynamically verified."
            if coverage.get("measured")
            else _unknown(str(coverage.get("reason", "coverage was not measured")))
        ),
        "index_bound": (
            "; ".join(health.get("claim_bounds") or [])
            or f"index grade {health.get('grade', '?')} with no recorded claim bounds"
        ),
    }
