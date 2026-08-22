"""Findings, hypotheses, clauses, patches, gauntlet results, certificates and publishing."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import client_ip, ensure_policy, get_audit, load_certificate, load_run
from app.audit.service import AuditService
from app.auth.deps import Permission, Principal, RequirePermission
from app.core.errors import (
    BadRequest,
    CertificateNotFound,
    ExploitAccessDenied,
    FindingNotFound,
    NotFound,
    PublishBlocked,
)
from app.core.logging import get_logger
from app.db.session import get_db
from app.models.analysis import Finding, Hypothesis, SamhitaClause, Shield
from app.models.audit import AuditAction
from app.models.enums import PUBLISHABLE_PROVIDERS, AssuranceLevel, PatchStatus, RunStatus
from app.models.pramaan import Certificate, EvidenceEdge, EvidenceNode
from app.models.project import Repository
from app.models.repair import GauntletResult, GauntletRun, Patch
from app.models.run import Artifact, Run
from app.patching.policy import PolicyConfig
from app.pramaan.certificate import verify_certificate
from app.schemas.core import (
    CertificateDetail,
    CertificateOut,
    ClauseOut,
    FindingOut,
    GauntletOut,
    GauntletStageOut,
    HypothesisOut,
    PatchOut,
    PublishRequestIn,
    PublishResultOut,
    ShieldOut,
)

logger = get_logger(__name__)
router = APIRouter(tags=["evidence"])


def _finding_out(finding: Finding, *, include_pov: bool) -> FindingOut:
    model = FindingOut.model_validate(finding)
    if include_pov:
        model.pov_payload = finding.pov_payload
        model.pov_access = "granted"
    else:
        # Never serialise the working exploit to a caller without finding:read_pov.
        model.pov_payload = None
        model.pov_access = "withheld"
    return model


# ---------------------------------------------------------------------------
# findings
# ---------------------------------------------------------------------------
@router.get("/runs/{run_id}/findings", response_model=list[FindingOut])
async def list_findings(
    run: Run = Depends(load_run),
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(RequirePermission(Permission.FINDING_READ)),
) -> list[FindingOut]:
    rows = list(
        (
            await db.scalars(
                select(Finding).where(Finding.run_id == run.id).order_by(Finding.handle.asc())
            )
        ).all()
    )
    # The list view never includes exploit material, regardless of role — a working exploit is
    # only ever handed over through the explicit single-finding endpoint, which audits the access.
    return [_finding_out(f, include_pov=False) for f in rows]


@router.get("/runs/{run_id}/findings/{handle}", response_model=FindingOut)
async def get_finding(
    handle: str,
    request: Request,
    include_pov: bool = Query(
        default=False,
        description="Include the working exploit. Requires finding:read_pov and is audited.",
    ),
    run: Run = Depends(load_run),
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(RequirePermission(Permission.FINDING_READ)),
    audit: AuditService = Depends(get_audit),
) -> FindingOut:
    finding = await db.scalar(
        select(Finding).where(Finding.run_id == run.id, Finding.handle == handle)
    )
    if finding is None:
        raise FindingNotFound()

    granted = False
    if include_pov:
        if not principal.can(Permission.FINDING_READ_POV):
            await audit.record(
                tenant_id=principal.tenant_id,
                action=AuditAction.EXPLOIT_ACCESSED,
                actor_user_id=principal.user_id,
                actor_label=principal.label,
                subject_type="finding",
                subject_id=f"{run.short_code}/{handle}",
                source_ip=client_ip(request),
                detail={"granted": False, "role": principal.role, "reason": "permission denied"},
            )
            raise ExploitAccessDenied()
        granted = True
        await audit.record(
            tenant_id=principal.tenant_id,
            action=AuditAction.EXPLOIT_ACCESSED,
            actor_user_id=principal.user_id,
            actor_label=principal.label,
            subject_type="finding",
            subject_id=f"{run.short_code}/{handle}",
            source_ip=client_ip(request),
            detail={
                "granted": True,
                "role": principal.role,
                "pov_hash": finding.pov_hash,
                "pov_kind": finding.pov_kind,
            },
        )
    else:
        await audit.record(
            tenant_id=principal.tenant_id,
            action=AuditAction.FINDING_ACCESSED,
            actor_user_id=principal.user_id,
            actor_label=principal.label,
            subject_type="finding",
            subject_id=f"{run.short_code}/{handle}",
            source_ip=client_ip(request),
            detail={"state": finding.state, "severity": finding.severity},
        )
    return _finding_out(finding, include_pov=granted)


@router.get("/runs/{run_id}/hypotheses", response_model=list[HypothesisOut])
async def list_hypotheses(
    run: Run = Depends(load_run),
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(RequirePermission(Permission.FINDING_READ)),
) -> list[HypothesisOut]:
    rows = list(
        (
            await db.scalars(
                select(Hypothesis)
                .where(Hypothesis.run_id == run.id)
                .order_by(Hypothesis.priority.desc())
            )
        ).all()
    )
    return [HypothesisOut.model_validate(r) for r in rows]


@router.get("/runs/{run_id}/clauses", response_model=list[ClauseOut])
async def list_clauses(
    status: str | None = None,
    run: Run = Depends(load_run),
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(RequirePermission(Permission.FINDING_READ)),
) -> list[ClauseOut]:
    stmt = select(SamhitaClause).where(SamhitaClause.run_id == run.id)
    if status:
        stmt = stmt.where(SamhitaClause.status == status.upper())
    rows = list((await db.scalars(stmt.order_by(SamhitaClause.clause_id.asc()))).all())
    return [ClauseOut.model_validate(r) for r in rows]


@router.get("/runs/{run_id}/shields", response_model=list[ShieldOut])
async def list_shields(
    run: Run = Depends(load_run),
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(RequirePermission(Permission.FINDING_READ)),
) -> list[ShieldOut]:
    rows = list((await db.scalars(select(Shield).where(Shield.run_id == run.id))).all())
    findings = {
        f.id: f.handle
        for f in (await db.scalars(select(Finding).where(Finding.run_id == run.id))).all()
    }
    out: list[ShieldOut] = []
    for row in rows:
        model = ShieldOut.model_validate(row)
        model.finding_handle = findings.get(row.finding_id, "")
        out.append(model)
    return out


# ---------------------------------------------------------------------------
# patches / gauntlet
# ---------------------------------------------------------------------------
@router.get("/runs/{run_id}/patches", response_model=list[PatchOut])
async def list_patches(
    run: Run = Depends(load_run),
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(RequirePermission(Permission.PATCH_READ)),
) -> list[PatchOut]:
    rows = list(
        (
            await db.scalars(
                select(Patch)
                .where(Patch.run_id == run.id)
                .order_by(Patch.finding_id.asc(), Patch.iteration.asc())
            )
        ).all()
    )
    findings = {
        f.id: f.handle
        for f in (await db.scalars(select(Finding).where(Finding.run_id == run.id))).all()
    }
    out: list[PatchOut] = []
    for row in rows:
        model = PatchOut.model_validate(row)
        model.finding_handle = findings.get(row.finding_id, "")
        out.append(model)
    return out


@router.get("/runs/{run_id}/gauntlet", response_model=list[GauntletOut])
async def list_gauntlet(
    run: Run = Depends(load_run),
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(RequirePermission(Permission.PATCH_READ)),
) -> list[GauntletOut]:
    runs = list(
        (
            await db.scalars(
                select(GauntletRun)
                .where(GauntletRun.run_id == run.id)
                .order_by(GauntletRun.created_at.asc())
            )
        ).all()
    )
    results = list(
        (await db.scalars(select(GauntletResult).where(GauntletResult.run_id == run.id))).all()
    )
    findings = {
        f.id: f.handle
        for f in (await db.scalars(select(Finding).where(Finding.run_id == run.id))).all()
    }

    by_run: dict[uuid.UUID, list[GauntletResult]] = {}
    for result in results:
        by_run.setdefault(result.gauntlet_run_id, []).append(result)

    stage_order = {
        "exploit_mutation": 0,
        "sibling_hunt": 1,
        "differential_replay": 2,
        "samhita_recheck": 3,
    }

    return [
        GauntletOut(
            id=row.id,
            finding_handle=findings.get(row.finding_id, ""),
            patch_id=row.patch_id,
            iteration=row.iteration,
            verdict=row.verdict,
            failing_stage=row.failing_stage,
            stages_passed=row.stages_passed,
            stages_total=row.stages_total,
            duration_ms=row.duration_ms,
            summary=row.summary,
            stages=[
                GauntletStageOut(
                    stage=s.stage,
                    verdict=s.verdict,
                    detail=s.detail,
                    refuting_evidence=s.refuting_evidence,
                    metrics=s.metrics,
                    duration_ms=s.duration_ms,
                    cases_total=s.cases_total,
                    cases_passed=s.cases_passed,
                )
                for s in sorted(by_run.get(row.id, []), key=lambda s: stage_order.get(s.stage, 9))
            ],
        )
        for row in runs
    ]


@router.post("/runs/{run_id}/patches/{patch_id}/review", response_model=PatchOut)
async def review_patch(
    patch_id: uuid.UUID,
    request: Request,
    approve: bool = Query(default=True),
    note: str = Query(default=""),
    run: Run = Depends(load_run),
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(RequirePermission(Permission.PATCH_REVIEW)),
    audit: AuditService = Depends(get_audit),
) -> PatchOut:
    patch = await db.get(Patch, patch_id)
    if patch is None or patch.run_id != run.id:
        raise NotFound("No such patch for this run.", code="PATCH_NOT_FOUND")

    await audit.record(
        tenant_id=principal.tenant_id,
        action=AuditAction.PATCH_APPROVED if approve else AuditAction.PATCH_REJECTED,
        actor_user_id=principal.user_id,
        actor_label=principal.label,
        subject_type="patch",
        subject_id=str(patch.id),
        source_ip=client_ip(request),
        detail={
            "iteration": patch.iteration,
            "status": patch.status,
            "diff_hash": patch.diff_hash,
            "note": note[:400],
        },
    )
    model = PatchOut.model_validate(patch)
    finding = await db.get(Finding, patch.finding_id)
    model.finding_handle = finding.handle if finding else ""
    return model


# ---------------------------------------------------------------------------
# certificates
# ---------------------------------------------------------------------------
@router.get("/runs/{run_id}/certificate", response_model=CertificateDetail)
async def get_run_certificate(
    request: Request,
    run: Run = Depends(load_run),
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(RequirePermission(Permission.CERTIFICATE_READ)),
    audit: AuditService = Depends(get_audit),
) -> CertificateDetail:
    """The run's headline certificate — the highest assurance level issued."""
    rows = list((await db.scalars(select(Certificate).where(Certificate.run_id == run.id))).all())
    if not rows:
        raise CertificateNotFound()

    order = {"A": 3, "B": 2, "C": 1, "R": 0}
    certificate = max(rows, key=lambda c: order.get(c.assurance_level, 0))
    await audit.record(
        tenant_id=principal.tenant_id,
        action=AuditAction.CERTIFICATE_DOWNLOADED,
        actor_user_id=principal.user_id,
        actor_label=principal.label,
        subject_type="certificate",
        subject_id=str(certificate.id),
        source_ip=client_ip(request),
        detail={"serial": certificate.serial, "level": certificate.assurance_level},
    )
    return await _certificate_detail(db, certificate)


@router.get("/runs/{run_id}/certificates", response_model=list[CertificateOut])
async def list_certificates(
    run: Run = Depends(load_run),
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(RequirePermission(Permission.CERTIFICATE_READ)),
) -> list[CertificateOut]:
    rows = list((await db.scalars(select(Certificate).where(Certificate.run_id == run.id))).all())
    findings = {
        f.id: f.handle
        for f in (await db.scalars(select(Finding).where(Finding.run_id == run.id))).all()
    }
    out: list[CertificateOut] = []
    for row in rows:
        model = CertificateOut.model_validate(row)
        model.finding_handle = findings.get(row.finding_id, "") if row.finding_id else ""
        out.append(model)
    return out


@router.get("/certificates/{certificate_id}", response_model=CertificateDetail)
async def get_certificate(
    certificate: Certificate = Depends(load_certificate),
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(RequirePermission(Permission.CERTIFICATE_READ)),
) -> CertificateDetail:
    return await _certificate_detail(db, certificate)


@router.get("/certificates/{certificate_id}/download")
async def download_certificate(
    request: Request,
    certificate: Certificate = Depends(load_certificate),
    principal: Principal = Depends(RequirePermission(Permission.CERTIFICATE_READ)),
    audit: AuditService = Depends(get_audit),
) -> Any:
    import json

    await audit.record(
        tenant_id=principal.tenant_id,
        action=AuditAction.CERTIFICATE_DOWNLOADED,
        actor_user_id=principal.user_id,
        actor_label=principal.label,
        subject_type="certificate",
        subject_id=str(certificate.id),
        source_ip=client_ip(request),
        detail={"serial": certificate.serial, "format": "json"},
    )
    return PlainTextResponse(
        json.dumps(certificate.document, indent=2, sort_keys=True, default=str),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="certificate-{certificate.serial}.json"',
            "X-Certificate-Hash": certificate.certificate_hash,
        },
    )


@router.get("/certificates/{certificate_id}/verify")
async def verify(
    certificate: Certificate = Depends(load_certificate),
    principal: Principal = Depends(RequirePermission(Permission.CERTIFICATE_READ)),
) -> dict[str, Any]:
    """Recompute the certificate hash and signature from the stored document."""
    result = verify_certificate(certificate.document)
    return {
        "certificate_id": str(certificate.id),
        "serial": certificate.serial,
        **result,
        "stored_hash": certificate.certificate_hash,
        "stored_signature_algorithm": certificate.signature_algorithm,
        "valid": bool(result["hash_matches"] and result["signature_matches"]),
    }


@router.get("/runs/{run_id}/evidence")
async def get_evidence_graph(
    root: str | None = Query(default=None, description="Limit to the subgraph under this ref"),
    run: Run = Depends(load_run),
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(RequirePermission(Permission.FINDING_READ)),
) -> dict[str, Any]:
    nodes = list(
        (await db.scalars(select(EvidenceNode).where(EvidenceNode.run_id == run.id))).all()
    )
    edges = list(
        (await db.scalars(select(EvidenceEdge).where(EvidenceEdge.run_id == run.id))).all()
    )

    node_payload = [
        {
            "ref": n.ref,
            "type": n.type,
            "title": n.title,
            "content_hash": n.content_hash,
            "produced_by": n.produced_by,
            "meta": n.meta_json,
            "has_content": bool(n.content),
        }
        for n in nodes
    ]
    edge_payload = [
        {"source": e.source_ref, "relation": e.relation, "target": e.target_ref} for e in edges
    ]

    if root:
        keep = {root}
        frontier = [root]
        for _ in range(5):
            nxt: list[str] = []
            for ref in frontier:
                for edge in edge_payload:
                    if edge["source"] == ref and edge["target"] not in keep:
                        keep.add(edge["target"])
                        nxt.append(edge["target"])
            frontier = nxt
        node_payload = [n for n in node_payload if n["ref"] in keep]
        edge_payload = [e for e in edge_payload if e["source"] in keep and e["target"] in keep]

    return {
        "run_id": str(run.id),
        "root": root,
        "nodes": node_payload,
        "edges": edge_payload,
        "counts": {"nodes": len(node_payload), "edges": len(edge_payload)},
    }


@router.get("/runs/{run_id}/evidence/{ref:path}")
async def get_evidence_node(
    ref: str,
    run: Run = Depends(load_run),
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(RequirePermission(Permission.FINDING_READ)),
) -> dict[str, Any]:
    node = await db.scalar(
        select(EvidenceNode).where(EvidenceNode.run_id == run.id, EvidenceNode.ref == ref)
    )
    if node is None:
        raise NotFound(f"No evidence node {ref!r} in this run.", code="EVIDENCE_NOT_FOUND")

    incoming = list(
        (
            await db.scalars(
                select(EvidenceEdge).where(
                    EvidenceEdge.run_id == run.id, EvidenceEdge.target_ref == ref
                )
            )
        ).all()
    )
    outgoing = list(
        (
            await db.scalars(
                select(EvidenceEdge).where(
                    EvidenceEdge.run_id == run.id, EvidenceEdge.source_ref == ref
                )
            )
        ).all()
    )
    return {
        "ref": node.ref,
        "type": node.type,
        "title": node.title,
        "content": node.content,
        "content_hash": node.content_hash,
        "produced_by": node.produced_by,
        "meta": node.meta_json,
        "created_at": node.created_at.isoformat(),
        "provenance": {
            "incoming": [{"source": e.source_ref, "relation": e.relation} for e in incoming],
            "outgoing": [{"relation": e.relation, "target": e.target_ref} for e in outgoing],
        },
    }


# ---------------------------------------------------------------------------
# publish
# ---------------------------------------------------------------------------
@router.post("/runs/{run_id}/publish", response_model=PublishResultOut)
async def publish(
    payload: PublishRequestIn,
    request: Request,
    run: Run = Depends(load_run),
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(RequirePermission(Permission.PATCH_PUBLISH)),
    audit: AuditService = Depends(get_audit),
) -> PublishResultOut:
    """Human publish approval, then the isolated Publisher.

    This endpoint is the only route to the Publisher, and therefore the only route to a GitHub
    credential. It requires ``patch:publish``, an explicit confirmation, and a certificate above
    Level R.
    """
    from app.publisher.service import Publisher, PublishRequest

    if not payload.confirm:
        raise BadRequest("Publishing requires explicit confirmation.", code="CONFIRMATION_REQUIRED")

    certificate = await db.get(Certificate, payload.certificate_id)
    if certificate is None or certificate.run_id != run.id:
        raise CertificateNotFound()
    if certificate.assurance_level == AssuranceLevel.R.value:
        raise PublishBlocked(
            "Assurance Level R: the patch was refuted and withdrawn. It cannot be published.",
            code="ASSURANCE_LEVEL_R",
        )

    finding = await db.get(Finding, certificate.finding_id) if certificate.finding_id else None
    if finding is None:
        raise FindingNotFound()

    patch = await db.scalar(
        select(Patch)
        .where(
            Patch.finding_id == finding.id,
            Patch.status == PatchStatus.VERIFIED.value,
        )
        .order_by(Patch.iteration.desc())
        .limit(1)
    )
    if patch is None:
        raise PublishBlocked(
            "No gauntlet-verified patch exists for this finding.", code="NO_VERIFIED_PATCH"
        )

    repository = await db.get(Repository, run.repository_id)
    if repository is None:
        raise NotFound("The repository row is missing.", code="REPOSITORY_NOT_FOUND")

    # Enforced here as well as at the publish gate: a provider with no installation behind it has no
    # credential, and KavachX must not open a pull request against a repository it was merely
    # allowed to read. Reading published source is research; writing to it is not.
    if repository.provider not in PUBLISHABLE_PROVIDERS:
        raise PublishBlocked(
            f"{repository.full_name} was attached as a {repository.provider} repository, which is "
            "analysis-only. Publishing requires a GitHub App installation that includes the "
            "repository. The patch and its certificate are available as run artifacts.",
            code="PROVIDER_NOT_PUBLISHABLE",
        )

    changes = await db.scalar(
        select(Artifact).where(Artifact.run_id == run.id, Artifact.kind == "changes_md")
    )
    remaining = await db.scalar(
        select(Artifact).where(Artifact.run_id == run.id, Artifact.kind == "remaining_md")
    )

    # Reconstruct old/new content from the pinned diff so the publisher can re-run policy on the
    # exact payload rather than trusting an earlier decision.
    file_changes = _reconstruct_file_changes(patch)
    policy_row = await ensure_policy(db, principal.tenant_id)

    publisher = Publisher()
    result = await publisher.publish(
        PublishRequest(
            repository_full_name=repository.full_name,
            installation_id=repository.installation_id,
            base_branch=run.branch or repository.default_branch,
            base_sha=run.commit_sha or run.pinned_source_sha256,
            run_short_code=run.short_code,
            finding_handle=finding.handle,
            finding_title=finding.title,
            severity=finding.severity,
            cwe=finding.cwe,
            unified_diff=patch.unified_diff,
            file_changes=file_changes,
            certificate_document=certificate.document,
            certificate_hash=certificate.certificate_hash,
            assurance_level=certificate.assurance_level,
            changes_md=changes.content if changes else "",
            remaining_md=remaining.content if remaining else "",
            blast_radius=patch.blast_radius_json,
            root_cause_summary=finding.root_cause_summary,
            violated_clause=await _clause_payload(db, run.id, finding.violated_clause_id),
            approved_by=principal.label,
            policy=PolicyConfig.from_model(policy_row),
        )
    )

    if result.ok:
        patch.status = PatchStatus.PUBLISHED.value
        run.publish_approved_by = principal.user_id
        run.publish_approved_at = datetime.now(timezone.utc)
        if run.status == RunStatus.AWAITING_APPROVAL.value:
            run.status = RunStatus.COMPLETED.value

        import json as _json

        db.add(
            Artifact(
                tenant_id=principal.tenant_id,
                run_id=run.id,
                kind="pr",
                name=f"publish-{finding.handle}.json",
                media_type="application/json",
                content=_json.dumps(
                    {**result.as_dict(), "dry_run_payload": result.dry_run_payload},
                    indent=2,
                    sort_keys=True,
                    default=str,
                ),
                content_hash=result.payload_hash,
                url=result.pull_request_url
                or f"/api/runs/{run.id}/artifacts/publish-{finding.handle}.json",
                meta_json={
                    "dry_run": result.dry_run,
                    "branch": result.branch,
                    "pull_request_number": result.pull_request_number,
                },
            )
        )
        await audit.record(
            tenant_id=principal.tenant_id,
            action=AuditAction.PR_PUBLISHED,
            actor_user_id=principal.user_id,
            actor_label=principal.label,
            subject_type="pull_request",
            subject_id=result.pull_request_url or result.branch,
            source_ip=client_ip(request),
            detail={
                "finding": finding.handle,
                "certificate": certificate.serial,
                "assurance_level": certificate.assurance_level,
                "branch": result.branch,
                "dry_run": result.dry_run,
                "payload_hash": result.payload_hash,
                "note": payload.note[:400],
            },
        )
    else:
        await audit.record(
            tenant_id=principal.tenant_id,
            action=AuditAction.PUBLISH_BLOCKED,
            actor_user_id=principal.user_id,
            actor_label=principal.label,
            subject_type="certificate",
            subject_id=str(certificate.id),
            source_ip=client_ip(request),
            detail={
                "reason": result.blocked_reason,
                "violations": result.policy_violations,
            },
        )

    return PublishResultOut(
        ok=result.ok,
        dry_run=result.dry_run,
        branch=result.branch,
        pull_request_url=result.pull_request_url,
        pull_request_number=result.pull_request_number,
        artifacts_written=result.artifacts_written,
        blocked_reason=result.blocked_reason,
        policy_violations=result.policy_violations,
        payload_hash=result.payload_hash,
        dry_run_payload=result.dry_run_payload,
    )


# ---------------------------------------------------------------------------
async def _certificate_detail(db: AsyncSession, certificate: Certificate) -> CertificateDetail:
    model = CertificateDetail(
        **CertificateOut.model_validate(certificate).model_dump(),
        document=certificate.document,
    )
    if certificate.finding_id:
        finding = await db.get(Finding, certificate.finding_id)
        model.finding_handle = finding.handle if finding else ""
    model.evidence_graph = (certificate.document or {}).get("evidence_graph", {})
    model.verification = (certificate.document or {}).get("verification", {})
    return model


async def _clause_payload(
    db: AsyncSession, run_id: uuid.UUID, clause_id: str
) -> dict[str, Any] | None:
    if not clause_id:
        return None
    clause = await db.scalar(
        select(SamhitaClause).where(
            SamhitaClause.run_id == run_id, SamhitaClause.clause_id == clause_id
        )
    )
    if clause is None:
        return None
    return {
        "clause_id": clause.clause_id,
        "kind": clause.kind,
        "description": clause.description,
        "predicate": clause.predicate,
        "scope": clause.scope,
        "status": clause.status,
        "observation_count": clause.observation_count,
        "holdout_pass_count": clause.holdout_pass_count,
    }


def _reconstruct_file_changes(patch: Patch) -> dict[str, tuple[str, str]]:
    """Read ``(old, new)`` content per changed file from the patch row.

    Content is stored on the patch at synthesis time. It is deliberately **not** rebuilt from the
    unified diff: a diff contains only the changed hunks plus context, so reconstructing from it
    would produce a file consisting of the changed regions alone — and the publisher writes whole
    files. Publishing that would corrupt every file it touched.
    """
    stored = patch.file_contents or {}
    out: dict[str, tuple[str, str]] = {}
    for path, entry in stored.items():
        if not isinstance(entry, dict) or "new" not in entry:
            continue
        out[str(path)] = (str(entry.get("old", "")), str(entry["new"]))

    if not out:
        raise PublishBlocked(
            "This patch has no stored file contents, so the exact verified payload cannot be "
            "reproduced. Refusing to publish a reconstruction.",
            code="PATCH_CONTENT_MISSING",
        )
    missing = sorted(set(patch.files or []) - set(out))
    if missing:
        raise PublishBlocked(
            f"Stored content is missing for {', '.join(missing)}. Refusing to publish a "
            "partial payload.",
            code="PATCH_CONTENT_INCOMPLETE",
        )
    return out
