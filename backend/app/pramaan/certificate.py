"""Certificate construction.

Assembles the evidence graph for one finding, grades assurance deterministically, then emits a
signed ``certificate.json``.

Refusal conditions — the builder returns an error rather than a weaker certificate:

* the evidence graph has dangling edges (a claim with no evidence node behind it);
* the finding was never validated;
* the assurance grade requires a gauntlet result that does not exist.

Signing is HMAC-SHA256 over the canonical JSON of the document, using a per-deployment key. That
detects tampering by anyone without the key; it is not a public-verifiable signature and the
certificate says so in ``signature.notes`` rather than implying more than it does.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.config import settings
from app.core.hashing import canonical_json, hmac_sign, sha256_json
from app.core.logging import get_logger
from app.models.enums import AssuranceLevel, EvidenceNodeType, EvidenceRelation
from app.pramaan.assurance import LEVEL_DESCRIPTIONS, LEVEL_LABELS, AssuranceAssessment
from app.pramaan.graph import (
    EvidenceGraph,
    ref_blast,
    ref_certificate,
    ref_channel,
    ref_clause,
    ref_code,
    ref_gauntlet,
    ref_patch,
    ref_reproduction,
    ref_runtime,
    ref_sandbox,
    ref_shield,
    ref_vulnerability,
    ref_world_model,
)

logger = get_logger(__name__)

CERTIFICATE_SCHEMA = "kavachx.pramaan.certificate.v1"


@dataclass
class CertificateResult:
    ok: bool = False
    serial: str = ""
    document: dict[str, Any] = field(default_factory=dict)
    certificate_hash: str = ""
    signature: str = ""
    assurance: AssuranceAssessment | None = None
    graph: EvidenceGraph | None = None
    generation_ms: int = 0
    error: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "serial": self.serial,
            "certificate_hash": self.certificate_hash,
            "signature": self.signature,
            "assurance_level": self.assurance.level if self.assurance else "",
            "generation_ms": self.generation_ms,
            "error": self.error,
        }


def build_graph(
    *,
    finding: dict[str, Any],
    channels: list[str],
    clause: dict[str, Any] | None,
    shield: dict[str, Any] | None,
    patches: list[dict[str, Any]],
    gauntlets: list[dict[str, Any]],
    blast: dict[str, Any],
    world_model_hash: str,
    sandbox_stats: dict[str, Any],
    runtime_digest: str,
) -> EvidenceGraph:
    """Wire one finding's evidence into a graph. Refs come from :mod:`app.pramaan.graph`."""
    graph = EvidenceGraph()
    handle = finding["handle"]
    vuln_ref = ref_vulnerability(handle)

    graph.add_node(
        ref=vuln_ref,
        type=EvidenceNodeType.VULNERABILITY.value,
        title=f"{handle} — {finding['title']}",
        content=finding.get("root_cause_summary", ""),
        meta={
            "severity": finding["severity"],
            "cwe": finding.get("cwe", ""),
            "state": finding["state"],
            "location": finding.get("location", ""),
            "reachable": finding.get("reachable", False),
            "root_cause_location": finding.get("root_cause_location", ""),
            "root_cause_verified": finding.get("root_cause_verified", False),
        },
        produced_by="orchestrator",
    )

    # -- discovered_by ----------------------------------------------------
    for channel in channels:
        channel_ref = ref_channel(channel)
        graph.add_node(
            ref=channel_ref,
            type=EvidenceNodeType.DISCOVERY_CHANNEL.value,
            title=f"discovery channel: {channel}",
            meta={"channel": channel},
            produced_by=f"discovery/{channel}",
        )
        graph.add_edge(vuln_ref, EvidenceRelation.DISCOVERED_BY.value, channel_ref)

    # -- violated_clause --------------------------------------------------
    if clause:
        clause_ref = ref_clause(clause["clause_id"])
        graph.add_node(
            ref=clause_ref,
            type=EvidenceNodeType.SAMHITA_CLAUSE.value,
            title=f"SAMHITA {clause['clause_id']} — {clause['description']}",
            content=clause["predicate"],
            meta={
                "clause_id": clause["clause_id"],
                "kind": clause.get("kind", ""),
                "scope": clause.get("scope", ""),
                "status": clause.get("status", ""),
                "observation_count": clause.get("observation_count", 0),
                "holdout_pass_count": clause.get("holdout_pass_count", 0),
                "survived_falsification": clause.get("status") == "SURVIVING",
            },
            produced_by="samhita/falsifier",
        )
        graph.add_edge(vuln_ref, EvidenceRelation.VIOLATED_CLAUSE.value, clause_ref)

    # -- code_evidence ----------------------------------------------------
    for location in {finding.get("location", ""), finding.get("root_cause_location", "")}:
        if not location:
            continue
        code_ref = ref_code(location)
        graph.add_node(
            ref=code_ref,
            type=EvidenceNodeType.CODE_LOCATION.value,
            title=f"code: {location}",
            meta={
                "location": location,
                "is_root_cause": location == finding.get("root_cause_location"),
            },
            produced_by="analysis/world_model",
        )
        graph.add_edge(vuln_ref, EvidenceRelation.CODE_EVIDENCE.value, code_ref)

    # -- runtime_evidence -------------------------------------------------
    if runtime_digest:
        runtime_ref = ref_runtime(runtime_digest)
        graph.add_node(
            ref=runtime_ref,
            type=EvidenceNodeType.RUNTIME_TRACE.value,
            title="runtime observation trace",
            meta={
                "trace_hash": finding.get("trace_hash", ""),
                "coverage_percent": finding.get("coverage_percent", 0.0),
                "observation_hash": runtime_digest,
            },
            produced_by="sandbox/kx_observe",
        )
        graph.add_edge(vuln_ref, EvidenceRelation.RUNTIME_EVIDENCE.value, runtime_ref)

    # -- exploit_evidence -------------------------------------------------
    repro_ref = ref_reproduction(handle)
    graph.add_node(
        ref=repro_ref,
        type=EvidenceNodeType.REPRODUCTION.value,
        # The working exploit itself is deliberately NOT stored in the graph — it is behind the
        # finding:read_pov permission. Only its hash and the deterministic outcome live here.
        title=f"reproduction record for {handle}",
        meta={
            "reproduced": finding.get("reproduced", False),
            "reproduction_count": finding.get("reproduction_count", 0),
            "exit_code": finding.get("exit_code"),
            "sanitizer_signal": finding.get("sanitizer_signal", ""),
            "input_hash": finding.get("input_hash", ""),
            "output_hash": finding.get("output_hash", ""),
            "trace_hash": finding.get("trace_hash", ""),
            "pov_hash": finding.get("pov_hash", ""),
            "pov_kind": finding.get("pov_kind", ""),
            "pov_withheld": True,
        },
        produced_by="validator",
    )
    graph.add_edge(vuln_ref, EvidenceRelation.EXPLOIT_EVIDENCE.value, repro_ref)

    # -- shielded_by ------------------------------------------------------
    if shield:
        shield_ref = ref_shield(shield.get("handle") or handle)
        graph.add_node(
            ref=shield_ref,
            type=EvidenceNodeType.SHIELD.value,
            title=f"shield {shield.get('handle', '')} ({shield.get('mechanism', '')})",
            content=shield.get("rule", ""),
            meta={
                "mechanism": shield.get("mechanism", ""),
                "verified_blocked": shield.get("verified_blocked", False),
                "verified_benign": shield.get("verified_benign", False),
                "benign_pass_count": shield.get("benign_pass_count", 0),
                "benign_total": shield.get("benign_total", 0),
                "deployed": shield.get("deployed", False),
                "reversible": True,
                "revert_command": shield.get("revert_command", ""),
            },
            produced_by="shield",
        )
        graph.add_edge(vuln_ref, EvidenceRelation.SHIELDED_BY.value, shield_ref)

    # -- repaired_by / verified_by ---------------------------------------
    previous_patch_ref = ""
    for patch in patches:
        iteration = int(patch["iteration"])
        patch_ref = ref_patch(handle, iteration)
        graph.add_node(
            ref=patch_ref,
            type=EvidenceNodeType.PATCH.value,
            title=f"patch iteration {iteration} ({patch.get('status', '')})",
            content=patch.get("unified_diff", "")[:20000],
            meta={
                "iteration": iteration,
                "status": patch.get("status", ""),
                "diff_hash": patch.get("diff_hash", ""),
                "files": patch.get("files", []),
                "lines_added": patch.get("lines_added", 0),
                "lines_removed": patch.get("lines_removed", 0),
                "risk": patch.get("risk", ""),
                "policy_passed": patch.get("policy_passed", False),
                "within_blast_radius": patch.get("within_blast_radius", False),
                "reason": patch.get("reason", "")[:2000],
                "refutation_summary": patch.get("refutation_summary", ""),
                "constraints": patch.get("constraints", []),
            },
            produced_by="patching/synthesis",
        )
        graph.add_edge(vuln_ref, EvidenceRelation.REPAIRED_BY.value, patch_ref, iteration=iteration)
        if previous_patch_ref:
            graph.add_edge(patch_ref, EvidenceRelation.SUPERSEDES.value, previous_patch_ref)
        previous_patch_ref = patch_ref

    for gauntlet in gauntlets:
        iteration = int(gauntlet["iteration"])
        patch_ref = ref_patch(handle, iteration)
        for stage in gauntlet.get("stages", []):
            stage_ref = ref_gauntlet(handle, iteration, stage["stage"])
            graph.add_node(
                ref=stage_ref,
                type=EvidenceNodeType.GAUNTLET_RESULT.value,
                title=f"{stage['stage']}: {stage['verdict'].upper()} (patch v{iteration})",
                content=stage.get("detail", ""),
                meta={
                    "stage": stage["stage"],
                    "verdict": stage["verdict"],
                    "iteration": iteration,
                    "cases_total": stage.get("cases_total", 0),
                    "cases_passed": stage.get("cases_passed", 0),
                    "duration_ms": stage.get("duration_ms", 0),
                    "refuting_evidence": stage.get("refuting_evidence", {}),
                    "metrics": {
                        k: v
                        for k, v in (stage.get("metrics") or {}).items()
                        if not k.startswith("_")
                    },
                },
                produced_by=f"gauntlet/{stage['stage']}",
            )
            if graph.has(patch_ref):
                graph.add_edge(patch_ref, EvidenceRelation.VERIFIED_BY.value, stage_ref)
            else:
                graph.add_edge(vuln_ref, EvidenceRelation.VERIFIED_BY.value, stage_ref)

    # -- scoped_by --------------------------------------------------------
    blast_ref = ref_blast(handle)
    graph.add_node(
        ref=blast_ref,
        type=EvidenceNodeType.BLAST_RADIUS.value,
        title=f"blast radius for {handle}: {blast.get('regression_scope', 'unknown')}",
        meta=blast,
        produced_by="patching/blast_radius",
    )
    graph.add_edge(vuln_ref, EvidenceRelation.SCOPED_BY.value, blast_ref)

    # -- executed_in ------------------------------------------------------
    world_ref = ref_world_model(world_model_hash)
    graph.add_node(
        ref=world_ref,
        type=EvidenceNodeType.WORLD_MODEL.value,
        title="world model",
        meta={"content_hash": world_model_hash},
        produced_by="analysis/world_model",
    )
    graph.add_edge(vuln_ref, EvidenceRelation.CODE_EVIDENCE.value, world_ref)

    sandbox_ref = ref_sandbox(str(sandbox_stats.get("session_id", "unknown")))
    graph.add_node(
        ref=sandbox_ref,
        type=EvidenceNodeType.SANDBOX_EXECUTION.value,
        title=f"sandbox session ({sandbox_stats.get('adapter', 'unknown')})",
        meta=sandbox_stats,
        produced_by="sandbox",
    )
    graph.add_edge(vuln_ref, EvidenceRelation.EXECUTED_IN.value, sandbox_ref)

    return graph


def build_certificate(
    *,
    run: dict[str, Any],
    repository: dict[str, Any],
    finding: dict[str, Any],
    assurance: AssuranceAssessment,
    graph: EvidenceGraph,
    clause: dict[str, Any] | None,
    shield: dict[str, Any] | None,
    patches: list[dict[str, Any]],
    gauntlets: list[dict[str, Any]],
    blast: dict[str, Any],
    samhita_stats: dict[str, Any],
    sandbox_stats: dict[str, Any],
    provider_info: dict[str, Any],
    #: Code-intelligence evidence summary from app.pramaan.intel_evidence.attach. Optional so a
    #: caller that has not run the intelligence stages still produces a valid certificate — it
    #: simply says so rather than omitting the section.
    intel: dict[str, Any] | None = None,
    signing_key: str | None = None,
) -> CertificateResult:
    started = time.perf_counter()
    result = CertificateResult()

    dangling = graph.unsupported_claims()
    if dangling:
        result.error = (
            f"Refusing to issue: the evidence graph has {len(dangling)} claim(s) with no "
            f"supporting node. First: {dangling[0]['problem']}"
        )
        logger.error("certificate.refused", reason=result.error, dangling=len(dangling))
        return result

    if not finding.get("reproduced") and assurance.level != AssuranceLevel.R.value:
        result.error = (
            "Refusing to issue a repair certificate for a finding that was never reproduced."
        )
        logger.error("certificate.refused", reason=result.error)
        return result

    serial = _serial(run["short_code"], finding["handle"])
    issued_at = datetime.now(timezone.utc).isoformat()
    verified_patch = next(
        (p for p in patches if p.get("status") == "VERIFIED"),
        patches[-1] if patches else None,
    )
    stage_verdicts = _stage_verdicts(gauntlets)

    document: dict[str, Any] = {
        "schema": CERTIFICATE_SCHEMA,
        "product": "KavachX",
        "title": "PRAMAAN — Certificate of Bounded Empirical Assurance",
        "serial": serial,
        "issued_at": issued_at,
        "assurance": {
            "level": assurance.level,
            "label": LEVEL_LABELS[assurance.level],
            "description": LEVEL_DESCRIPTIONS[assurance.level],
            "kind": "bounded empirical assurance",
            "not_a_formal_proof": True,
            "rationale": assurance.rationale,
            "limitations": assurance.limitations,
            "criteria": assurance.criteria,
        },
        "run": {
            "id": run["id"],
            "short_code": run["short_code"],
            "started_at": run.get("started_at"),
            "finished_at": run.get("finished_at"),
            "analysis_profile": run.get("analysis_profile"),
            "execution_profile": run.get("execution_profile"),
            "time_to_protection_ms": run.get("time_to_protection_ms"),
            "time_to_repair_ms": run.get("time_to_repair_ms"),
            "coverage_percent": run.get("coverage_percent"),
            "tokens_used": run.get("tokens_used"),
            "model_calls": run.get("model_calls"),
            "sandbox_executions": run.get("sandbox_executions"),
            "egress_bytes": run.get("egress_bytes", 0),
        },
        "target": {
            "repository": repository.get("full_name"),
            "provider": repository.get("provider"),
            "branch": run.get("branch"),
            "commit_sha": run.get("commit_sha"),
            "pinned_source_sha256": run.get("pinned_source_sha256"),
            "authority_verified_at": repository.get("authority_verified_at"),
        },
        "finding": {
            "handle": finding["handle"],
            "title": finding["title"],
            "state": finding["state"],
            "severity": finding["severity"],
            "cwe": finding.get("cwe", ""),
            "location": finding.get("location", ""),
            "reachable": finding.get("reachable", False),
            "discovered_by": finding.get("source_channel", ""),
            "root_cause": {
                "location": finding.get("root_cause_location", ""),
                "summary": finding.get("root_cause_summary", ""),
                "verified": finding.get("root_cause_verified", False),
                "chain": finding.get("root_cause_chain", []),
            },
            "reproduction": {
                "reproduced": finding.get("reproduced", False),
                "count": finding.get("reproduction_count", 0),
                "exit_code": finding.get("exit_code"),
                "sanitizer_signal": finding.get("sanitizer_signal", ""),
                "contract_violation": finding.get("contract_violation", ""),
                "input_hash": finding.get("input_hash", ""),
                "output_hash": finding.get("output_hash", ""),
                "trace_hash": finding.get("trace_hash", ""),
                "pov_hash": finding.get("pov_hash", ""),
                "pov_withheld": True,
                "pov_access_note": (
                    "The working exploit is withheld from this document. It is retrievable only "
                    "with the finding:read_pov permission, and every access is written to the "
                    "hash-chained audit log."
                ),
            },
        },
        "violated_clause": clause,
        "shield": shield,
        "patch": (
            {
                "iteration": verified_patch["iteration"],
                "status": verified_patch["status"],
                "diff_hash": verified_patch["diff_hash"],
                "files": verified_patch.get("files", []),
                "lines_added": verified_patch.get("lines_added", 0),
                "lines_removed": verified_patch.get("lines_removed", 0),
                "risk": verified_patch.get("risk", ""),
                "reason": verified_patch.get("reason", ""),
                "expected_effect": verified_patch.get("expected_effect", ""),
                "policy_passed": verified_patch.get("policy_passed", False),
                "within_blast_radius": verified_patch.get("within_blast_radius", False),
                "constraints_carried": verified_patch.get("constraints", []),
            }
            if verified_patch
            else None
        ),
        "patch_history": [
            {
                "iteration": p["iteration"],
                "status": p["status"],
                "diff_hash": p["diff_hash"],
                "refutation_summary": p.get("refutation_summary", ""),
            }
            for p in patches
        ],
        "verification": {
            "gauntlet_verdict": (gauntlets[-1]["verdict"] if gauntlets else "not run"),
            "stages": stage_verdicts,
            "iterations_run": len(gauntlets),
            "max_iterations": assurance.criteria.get("max_patch_iterations"),
        },
        "blast_radius": blast,
        "samhita": {
            "clauses_proposed": samhita_stats.get("proposed", 0),
            "clauses_surviving": samhita_stats.get("surviving", 0),
            "clauses_falsified": samhita_stats.get("falsified", 0),
            "clauses_uncompilable": samhita_stats.get("uncompilable", 0),
            "iterations": samhita_stats.get("iterations", 0),
            "observation_cases": samhita_stats.get("observation_cases", 0),
            "holdout_cases": samhita_stats.get("holdout_cases", 0),
            "note": (
                "Only clauses that survived falsification against held-out observations are used "
                "as evidence."
            ),
        },
        "execution_environment": {
            "sandbox": sandbox_stats,
            "egress_bytes": sandbox_stats.get("egress_bytes", 0),
            "network_enforced": (sandbox_stats.get("capabilities") or {}).get(
                "network_enforced", False
            ),
            "suitable_for_untrusted_code": (sandbox_stats.get("capabilities") or {}).get(
                "suitable_for_untrusted_code", False
            ),
        },
        "reasoning_provider": provider_info,
        # --- code intelligence -------------------------------------------
        #
        # What was analysed, by what, at what fidelity, and what test proved it. Present as
        # structured evidence rather than prose so a reader can check each claim against a node in
        # the evidence graph below.
        "code_intelligence": (
            intel
            if intel
            else {
                "available": False,
                "reason": (
                    "This run did not produce code-intelligence evidence: the index, security "
                    "graph and generated-test stages did not contribute to this finding. Any "
                    "reachability claim here rests on the world model alone."
                ),
            }
        ),
        "explains": (intel or {}).get("explains", {}),
        "evidence_graph": graph.as_dict(),
        "evidence_summary": graph.stats(),
    }

    result.serial = serial
    result.document = document
    result.certificate_hash = sha256_json(document)
    key = signing_key or settings.certificate_signing_key
    result.signature = hmac_sign(result.certificate_hash, key)

    document["signature"] = {
        "algorithm": "HMAC-SHA256",
        "certificate_hash": result.certificate_hash,
        "signature": result.signature,
        "notes": (
            "The signature is an HMAC over the canonical JSON of this document under a "
            "per-deployment key. It detects tampering by anyone without that key. It is not a "
            "public-key signature and is not independently verifiable without the key."
        ),
        "verify": (
            "sha256 the canonical JSON of this document with the `signature` field removed, then "
            "HMAC-SHA256 that digest with the deployment key."
        ),
    }

    cert_ref = ref_certificate(serial)
    graph.add_node(
        ref=cert_ref,
        type=EvidenceNodeType.CERTIFICATE.value,
        title=f"PRAMAAN certificate {serial} — Level {assurance.level}",
        meta={
            "serial": serial,
            "level": assurance.level,
            "certificate_hash": result.certificate_hash,
            "issued_at": issued_at,
        },
        produced_by="pramaan",
    )
    graph.add_edge(cert_ref, EvidenceRelation.ATTESTS.value, ref_vulnerability(finding["handle"]))

    result.assurance = assurance
    result.graph = graph
    result.generation_ms = int((time.perf_counter() - started) * 1000)
    result.ok = True
    logger.info(
        "certificate.issued",
        serial=serial,
        level=assurance.level,
        nodes=len(graph.nodes),
        edges=len(graph.edges),
        ms=result.generation_ms,
    )
    return result


def verify_certificate(
    document: dict[str, Any], *, signing_key: str | None = None
) -> dict[str, Any]:
    """Recompute the hash and signature of a certificate document."""
    payload = {k: v for k, v in document.items() if k != "signature"}
    recomputed_hash = sha256_json(payload)
    declared = document.get("signature") or {}
    key = signing_key or settings.certificate_signing_key
    expected_signature = hmac_sign(recomputed_hash, key)
    return {
        "hash_matches": recomputed_hash == declared.get("certificate_hash"),
        "signature_matches": expected_signature == declared.get("signature"),
        "recomputed_hash": recomputed_hash,
        "declared_hash": declared.get("certificate_hash", ""),
        "canonical_length": len(canonical_json(payload)),
    }


def _serial(run_short: str, finding_handle: str) -> str:
    return f"KX-{run_short.upper()}-{finding_handle.upper()}-{uuid.uuid4().hex[:6].upper()}"


def _stage_verdicts(gauntlets: list[dict[str, Any]]) -> dict[str, Any]:
    if not gauntlets:
        return {}
    latest = gauntlets[-1]
    return {
        stage["stage"]: {
            "verdict": stage["verdict"],
            "detail": stage.get("detail", ""),
            "cases_total": stage.get("cases_total", 0),
            "cases_passed": stage.get("cases_passed", 0),
        }
        for stage in latest.get("stages", [])
    }
