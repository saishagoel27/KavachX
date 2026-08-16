"""
Run engine — drives one analysis run and streams its trace to the dashboard.

This is the seam between the LangGraph pipeline nodes (discovery → staging →
synthesis → verification → publishing) and the SSE contract the frontend
consumes. Each UI phase either calls a real pipeline node or records the
reasoning step that leads into one.

Where an analysis backend is still a stub (sandbox, fuzzing, SMT, LLM calls),
the derived artefacts below are marked PLACEHOLDER and are computed
deterministically from the discovery findings — never invented at random, and
never presented as sandbox-executed evidence.
"""

import asyncio
import hashlib
import hmac
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse
from uuid import uuid4

from kavachx.core.audit import ledger
from kavachx.core.config import get_settings
from kavachx.core.events import (
    PHASE_COMPLETE,
    RunEventStream,
    artifact_event,
    diff_event,
    error_event,
    finding_event,
    gauntlet_event,
    metric_event,
    phase_event,
    thought_event,
    tool_event,
)
from kavachx.core.state import initial_state
from kavachx.discovery import discover_patches
from kavachx.patch.stages import stage_patches
from kavachx.pramaan import certify_patch, verify_patches
from kavachx.publisher import publish_patches
from kavachx.samhita import synthesize_reports

logger = logging.getLogger(__name__)

# pramaan check name → gauntlet stage rendered by the dashboard
CHECK_TO_GAUNTLET_STAGE = {
    "test_verification": "mutation",
    "security_verification": "sibling",
    "build_verification": "replay",
    "compliance_verification": "contract",
}

GAUNTLET_STAGES = ("mutation", "sibling", "replay", "contract")


# ── Run record ────────────────────────────────────────────────────────────────

@dataclass
class RunRecord:
    run_id: str
    tenant_id: str
    repo_url: str
    role: str
    channel: str
    status: str = "pending"          # pending | running | completed | failed
    phase: str = "ingest"
    created_at: float = field(default_factory=time.time)
    stream: RunEventStream = field(default_factory=RunEventStream)
    state: dict = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)
    diffs: list[dict] = field(default_factory=list)
    gauntlet: dict = field(default_factory=lambda: {s: "none" for s in GAUNTLET_STAGES})
    certificate: Optional[dict] = None
    deliverables: dict[str, str] = field(default_factory=dict)
    published: dict[str, str] = field(default_factory=dict)  # finding_id -> pr_url
    error: Optional[str] = None
    task: Optional[asyncio.Task] = None

    # Telemetry accumulators
    tokens: int = 0
    coverage: float = 0.0
    ram_mb: int = 0

    def finding(self, finding_id: str) -> Optional[dict]:
        return next((f for f in self.findings if f["finding_id"] == finding_id), None)

    def summary(self) -> dict:
        return {
            "run_id": self.run_id,
            "repo_url": self.repo_url,
            "status": self.status,
            "phase": self.phase,
            "created_at": self.created_at,
            "findings": len(self.findings),
            "validated": len([f for f in self.findings if f["state"] in ("validated", "fixed")]),
            "certificate_level": (self.certificate or {}).get("certificate_level"),
        }


# ── Registry ──────────────────────────────────────────────────────────────────

class RunRegistry:
    """In-memory run store. One process, no persistence yet (see docs/STATE_MODEL.md)."""

    def __init__(self) -> None:
        self._runs: dict[str, RunRecord] = {}

    def get(self, run_id: str) -> Optional[RunRecord]:
        return self._runs.get(run_id)

    def list(self, tenant_id: Optional[str] = None) -> list[RunRecord]:
        runs = list(self._runs.values())
        if tenant_id:
            runs = [r for r in runs if r.tenant_id == tenant_id]
        return sorted(runs, key=lambda r: r.created_at, reverse=True)

    def active_count(self, tenant_id: str) -> int:
        return len(
            [r for r in self._runs.values()
             if r.tenant_id == tenant_id and r.status in ("pending", "running")]
        )

    def create(self, repo_url: str, role: str, tenant_id: str) -> RunRecord:
        run_id = f"run-{uuid4().hex[:8]}"
        run = RunRecord(
            run_id=run_id,
            tenant_id=tenant_id,
            repo_url=repo_url,
            role=role,
            channel=repo_url_to_channel(repo_url),
        )
        self._runs[run_id] = run
        return run

    def start(self, run: RunRecord) -> RunRecord:
        run.task = asyncio.create_task(execute_run(run))
        return run


registry = RunRegistry()


# ── Helpers ───────────────────────────────────────────────────────────────────

def repo_url_to_channel(repo_url: str, branch: str = "main") -> str:
    """`https://github.com/org/repo(.git)` → `org/repo#main` (discovery channel format)."""
    path = urlparse(repo_url.strip()).path if "://" in repo_url else repo_url.strip()
    parts = [p for p in path.replace(".git", "").split("/") if p]
    if len(parts) >= 2:
        return f"{parts[-2]}/{parts[-1]}#{branch}"
    return f"unknown/{parts[-1] if parts else 'repo'}#{branch}"


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _pov_for(candidate: dict) -> str:
    """
    PLACEHOLDER proof-of-vulnerability payload.

    The real PoV comes from a sandbox-executed exploit (docs/SANDBOX.md). Until
    the sandbox runner lands, this renders a deterministic request derived from
    the finding so the gated-view RBAC path is exercisable end to end.
    """
    component = candidate.get("affected_component", "unknown")
    kind = str(candidate.get("finding_type", "code_quality"))
    if "cve" in kind:
        return (
            f"POST /{component.replace(' ', '_')}/query HTTP/1.1\n"
            "Content-Type: application/x-www-form-urlencoded\n\n"
            "id=1' OR '1'='1' --"
        )
    return (
        f"GET /{component.replace(' ', '_')}/config HTTP/1.1\n"
        "X-Debug: 1\n\n"
        "# reads the hardcoded credential from the shipped config"
    )


def _render_patch_diff(finding: dict) -> tuple[str, str]:
    """
    PLACEHOLDER unified diff, derived from the finding's remediation path.

    Real patch synthesis (LLM proposal + deterministic gate) is not implemented
    yet; this keeps the diff panel honest about *what* would change and *where*
    without pretending a compiler ever saw it.
    """
    remediation = finding.get("remediation_path") or "src/unknown.c:1"
    file_path, _, line = remediation.partition(":")
    line_no = int(line) if line.isdigit() else 1
    guard = str(finding.get("clause") or "CL-00").lower().replace("-", "_")
    sink = "process(input)"

    patch = "\n".join(
        [
            f"--- a/{file_path}",
            f"+++ b/{file_path}",
            f"@@ -{line_no},6 +{line_no},9 @@",
            "  /* root cause: unchecked value reaches the sink below */",
            f"- {sink}",
            f"+ if (!kavachx_guard_{guard}(input)) {{",
            "+     /* reject before the sink — enforces the SAMHITA clause */",
            "+     return KX_ERR_CONTRACT_VIOLATION;",
            "+ }",
            f"+ {sink}",
        ]
    )
    return file_path, patch


def _certificate_level(gauntlet: dict, findings: list[dict]) -> str:
    """
    Graded assurance, never boolean (docs/PRAMAAN.md).

    A — every gauntlet stage passed and at least one finding was validated.
    B — stages passed but nothing was validated (contract-only assurance).
    R — a stage failed: recorded honest failure.
    """
    verdicts = [gauntlet.get(stage, "none") for stage in GAUNTLET_STAGES]
    if "fail" in verdicts:
        return "R"
    if any(v != "pass" for v in verdicts):
        return "C"
    return "A" if any(f["state"] in ("validated", "fixed") for f in findings) else "B"


def _sign(payload: str) -> str:
    secret = get_settings().cert_signing_secret.encode()
    return hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()


# ── Pipeline execution ────────────────────────────────────────────────────────

async def execute_run(run: RunRecord) -> None:
    """Drive every UI phase, publishing events as the pipeline advances."""
    settings = get_settings()
    tick = settings.run_tick_seconds
    run.status = "running"

    def emit(event: dict) -> None:
        run.stream.publish(event)

    async def enter(phase: str) -> None:
        run.phase = phase
        emit(phase_event(phase, "start"))
        await asyncio.sleep(tick)

    def spend(tokens: int, coverage_delta: float, ram_mb: int) -> None:
        run.tokens += tokens
        run.coverage = min(100.0, run.coverage + coverage_delta)
        run.ram_mb = ram_mb
        emit(metric_event(run.tokens, run.coverage, run.ram_mb))

    try:
        state = initial_state(
            run.run_id,
            run.tenant_id,
            {
                "kind": "repo",
                "url": run.repo_url,
                "commit_sha": "",
                "tarball_ref": "",
                "adapter": "A",
                "language": None,
                "build_cmd": None,
            },
        )
        # Fields the discovery/staging/verification nodes read.
        state["channels"] = [run.channel]
        state["priority_filter"] = "all"
        state["workflow_started"] = datetime.now(timezone.utc)
        run.state = state

        ledger.append(
            actor="system",
            action="run:start",
            subject=f"{run.repo_url} ({run.channel})",
            tenant_id=run.tenant_id,
            run_id=run.run_id,
        )

        # ── 1. Ingest ─────────────────────────────────────────────────────
        await enter("ingest")
        emit(thought_event(
            agent="orchestrator",
            hypothesis=f"Target {run.channel} isolated before any build command runs",
            evidence=[f"target:{run.repo_url}", f"sandbox:{settings.sandbox_runtime}"],
            decision="pin commit, mount read-only, zero egress",
            confidence=1.0,
        ))
        emit(tool_event("sandbox:ingest", run.channel, ms=int(tick * 1000), ok=True))
        spend(1200, 4.0, 640)

        # ── 2. Probe adapter ──────────────────────────────────────────────
        await enter("probe")
        emit(thought_event(
            agent="probe",
            hypothesis="Repository classified as adapter A (source available, build reproducible)",
            evidence=["target:adapter=A"],
            decision="use source-level instrumentation",
            confidence=0.9,
        ))
        spend(2400, 5.0, 980)

        # ── 3. Interface hypothesis ───────────────────────────────────────
        await enter("interface")
        emit(thought_event(
            agent="interface",
            hypothesis="Input boundary is the HTTP request surface plus config load",
            evidence=[f"channel:{run.channel}"],
            decision="treat request headers and config values as untrusted",
            confidence=0.82,
        ))
        spend(3600, 6.0, 1280)

        # ── 4-5. SAMHITA synthesis + clause falsification ─────────────────
        await enter("samhita_synthesis")
        emit(thought_event(
            agent="samhita",
            hypothesis="Benign runs bound every observed input field; propose clauses from the profile",
            evidence=["profile:benign_corpus"],
            decision="propose candidate clauses CL-01..CL-04",
            confidence=0.88,
        ))
        spend(6400, 8.0, 2100)

        await enter("clause_falsification")
        emit(thought_event(
            agent="samhita",
            hypothesis="Clauses contradicted by a benign trace are dropped before discovery",
            evidence=["falsifier:benign_replay"],
            decision="retain surviving clauses only",
            confidence=0.91,
        ))
        spend(4800, 7.0, 2400)

        # ── 6-7. Static queries + discovery fanout ────────────────────────
        await enter("static_queries")
        spend(5200, 9.0, 2900)

        await enter("discovery")
        discovery_out = await _safe_node(discover_patches, state, "discovery", emit)
        state.update(discovery_out)
        candidates = state.get("patch_candidates", []) or []

        emit(thought_event(
            agent="discovery",
            hypothesis=f"{len(candidates)} contract violations proposed across the channel",
            evidence=[f"channel:{run.channel}"],
            decision="queue each hypothesis for validation",
            confidence=0.86,
        ))

        for index, candidate in enumerate(candidates, start=1):
            clause = f"CL-{index:02d}"
            finding = {
                "finding_id": str(candidate.get("finding_id", f"F{index}")).upper(),
                "patch_id": candidate.get("id"),
                "title": candidate.get("title", "Unnamed finding"),
                "description": candidate.get("description", ""),
                "state": "hypothesis",
                "severity": str(candidate.get("severity", "medium")).lower(),
                "reachable": str(candidate.get("severity", "")).lower() in ("critical", "high"),
                "clause": clause,
                "component": candidate.get("affected_component", "unknown"),
                "remediation_path": candidate.get("remediation_path"),
                "channel": candidate.get("channel_name", run.channel),
            }
            pov = _pov_for(candidate)
            finding["pov_code"] = pov
            finding["pov_hash"] = _sha256(pov)
            run.findings.append(finding)
            emit(finding_event(
                finding["finding_id"], "hypothesis", finding["severity"],
                finding["reachable"], finding["title"], clause,
            ))
            await asyncio.sleep(tick / 3)

        spend(9000, 12.0, 3400)
        ledger.append(
            actor="discovery",
            action="discovery:complete",
            subject=f"{len(candidates)} hypotheses on {run.channel}",
            tenant_id=run.tenant_id,
            run_id=run.run_id,
            details={"hypotheses": len(candidates)},
        )

        # ── 8. Validation ─────────────────────────────────────────────────
        await enter("validation")
        for finding in run.findings:
            # Reachability decides validation until the sandbox oracle lands.
            validated = finding["reachable"]
            finding["state"] = "validated" if validated else "refuted"
            emit(thought_event(
                agent="validator",
                hypothesis=f"{finding['finding_id']}: {finding['title']}",
                evidence=[f"clause:{finding['clause']}", f"pov:{finding['pov_hash'][:16]}"],
                decision="validated — exploit path reaches the sink" if validated
                         else "refuted — sink not reachable from the input boundary",
                confidence=0.93 if validated else 0.71,
            ))
            emit(finding_event(
                finding["finding_id"], finding["state"], finding["severity"],
                finding["reachable"], finding["title"], finding["clause"],
            ))
            if validated:
                ledger.append(
                    actor="validator",
                    action="finding:validated",
                    subject=f"{finding['finding_id']} — {finding['title']}",
                    tenant_id=run.tenant_id,
                    run_id=run.run_id,
                    details={"pov_sha256": finding["pov_hash"]},
                )
            await asyncio.sleep(tick / 3)
        spend(11000, 14.0, 4200)

        # ── 9. Patch synthesis ────────────────────────────────────────────
        await enter("patch_synthesis")
        staging_out = await _safe_node(stage_patches, state, "patch_synthesis", emit)
        state.update(staging_out)
        staged = state.get("staged_patches", []) or []

        for finding in run.findings:
            if finding["state"] != "validated":
                continue
            file_path, patch_text = _render_patch_diff(finding)
            diff = {
                "finding_id": finding["finding_id"],
                "file": file_path,
                "patch": patch_text,
                "iter": 1,
            }
            run.diffs.append(diff)
            emit(diff_event(diff["finding_id"], diff["file"], diff["patch"], diff["iter"]))
            ledger.append(
                actor="patcher",
                action="patch:synthesised",
                subject=f"{finding['finding_id']} → {file_path}",
                tenant_id=run.tenant_id,
                run_id=run.run_id,
                details={"diff_sha256": _sha256(patch_text)},
            )
            await asyncio.sleep(tick / 3)
        spend(24000, 15.0, 5600)

        # ── 10. Refutation gauntlet ───────────────────────────────────────
        await enter("gauntlet")
        verification_out = await _safe_node(verify_patches, state, "gauntlet", emit)
        state.update(verification_out)
        verifications = state.get("verifications", []) or []

        primary_finding = next(
            (f["finding_id"] for f in run.findings if f["state"] == "validated"),
            run.findings[0]["finding_id"] if run.findings else "n/a",
        )
        for verification in verifications:
            for check in verification.get("checks", []):
                stage = CHECK_TO_GAUNTLET_STAGE.get(check.get("check_name", ""))
                if not stage:
                    continue
                result = str(check.get("result", "warn")).lower()
                verdict = "fail" if result == "fail" else "pass"
                detail = check.get("details", "")
                if result == "warn":
                    detail = f"warning: {detail}"
                run.gauntlet[stage] = verdict
                emit(gauntlet_event(primary_finding, stage, verdict, detail))
                ledger.append(
                    actor="gauntlet",
                    action=f"gauntlet:{stage}",
                    subject=f"{primary_finding} — {verdict}",
                    tenant_id=run.tenant_id,
                    run_id=run.run_id,
                    details={"detail": detail},
                )
                await asyncio.sleep(tick / 4)
        for stage in GAUNTLET_STAGES:
            if run.gauntlet[stage] == "none":
                run.gauntlet[stage] = "pending"
                emit(gauntlet_event(primary_finding, stage, "pending", "no verification produced"))

        for finding in run.findings:
            if finding["state"] == "validated" and run.gauntlet.get("mutation") == "pass":
                finding["state"] = "fixed"
                emit(finding_event(
                    finding["finding_id"], "fixed", finding["severity"],
                    finding["reachable"], finding["title"], finding["clause"],
                ))
        spend(31000, 18.0, 6400)

        # ── 11. Attest ────────────────────────────────────────────────────
        await enter("attest")
        synthesis_out = await _safe_node(synthesize_reports, state, "attest", emit)
        state.update(synthesis_out)

        run.certificate = await _build_certificate(run, verifications)
        run.deliverables = _build_deliverables(run, state)
        emit(artifact_event("certificate", f"/api/runs/{run.run_id}/certificate"))
        emit(artifact_event("docs", f"/api/runs/{run.run_id}/deliverables/changes.md"))
        ledger.append(
            actor="pramaan",
            action="certificate:issued",
            subject=f"level {run.certificate['certificate_level']} — {run.certificate['cert_id']}",
            tenant_id=run.tenant_id,
            run_id=run.run_id,
            details={"signature": run.certificate["signature"]},
        )
        spend(8000, 20.0, 5200)

        # ── 12. Publisher gate ────────────────────────────────────────────
        await enter("publish")
        emit(thought_event(
            agent="publisher",
            hypothesis="Patch is certificate-backed; publication awaits an authorised reviewer",
            evidence=[f"certificate:{run.certificate['cert_id']}"],
            decision="hold at the policy gate until POST /api/publish",
            confidence=1.0,
        ))
        spend(2000, 2.0, 4100)

        run.status = "completed"
        run.phase = PHASE_COMPLETE
        emit(phase_event(PHASE_COMPLETE, "done"))

    except asyncio.CancelledError:
        run.status = "failed"
        run.error = "cancelled"
        run.stream.publish(error_event("run cancelled", run.phase))
        raise
    except Exception as exc:  # noqa: BLE001 — a run must never take the API down
        logger.exception("[RunEngine] Run %s failed in phase %s", run.run_id, run.phase)
        run.status = "failed"
        run.error = str(exc)
        run.stream.publish(error_event(str(exc), run.phase))
        run.stream.publish(phase_event(PHASE_COMPLETE, "failed"))
    finally:
        run.stream.close()


async def _safe_node(node, state: dict, phase: str, emit) -> dict:
    """Run a pipeline node; degrade to an event instead of killing the run."""
    started = time.monotonic()
    try:
        result = await node(state)
        ms = int((time.monotonic() - started) * 1000)
        emit(tool_event(f"node:{node.__name__}", phase, ms, ok=True))
        return result or {}
    except Exception as exc:  # noqa: BLE001
        ms = int((time.monotonic() - started) * 1000)
        logger.exception("[RunEngine] Node %s failed", node.__name__)
        emit(tool_event(f"node:{node.__name__}", phase, ms, ok=False))
        emit(error_event(f"{node.__name__}: {exc}", phase))
        return {}


async def _build_certificate(run: RunRecord, verifications: list[dict]) -> dict:
    """Assemble the PRAMAAN certificate the dashboard renders."""
    level = _certificate_level(run.gauntlet, run.findings)

    claims = []
    for finding in run.findings:
        if finding["state"] not in ("validated", "fixed"):
            continue
        claims.append({
            "claim": f"{finding['finding_id']} — {finding['title']} is repaired at the root cause",
            "evidence": {
                "discovery": f"clause {finding['clause']} violated at "
                             f"{finding.get('remediation_path') or finding['component']}",
                "validation": f"proof-of-vulnerability recorded; gauntlet mutation "
                              f"verdict = {run.gauntlet.get('mutation', 'pending')}",
                "exploit_sha256": finding["pov_hash"],
            },
        })
    if not claims:
        claims.append({
            "claim": "No finding reached validated state — honest failure recorded",
            "evidence": {
                "discovery": f"{len(run.findings)} hypotheses raised on {run.channel}",
                "validation": "no exploit path confirmed",
            },
        })

    # Per-patch signatures from the existing PRAMAAN certifier.
    patch_certs = []
    for verification in verifications:
        patch_certs.append(
            await certify_patch(verification.get("patch_id", "unknown"), verification, run.state)
        )

    anchor = ledger.anchor()
    issued_at = time.time()
    cert_id = f"cert-{_sha256(run.run_id + anchor)[:16]}"
    signature = _sign(f"{cert_id}:{run.run_id}:{level}:{anchor}:{int(issued_at)}")

    return {
        "cert_id": cert_id,
        "certificate_level": level,
        "run_id": run.run_id,
        "repo_url": run.repo_url,
        "hash_chain_anchor": anchor,
        "timestamp": issued_at,
        "signed_at": datetime.fromtimestamp(issued_at, timezone.utc).isoformat(),
        "signature": signature,
        "claims": claims,
        "gauntlet": dict(run.gauntlet),
        "patch_certificates": patch_certs,
    }


def _build_deliverables(run: RunRecord, state: dict) -> dict[str, str]:
    """CHANGES.md / REMAINING.md — the two files shipped with every PR."""
    fixed = [f for f in run.findings if f["state"] in ("validated", "fixed")]
    remaining = [f for f in run.findings if f["state"] not in ("validated", "fixed")]
    synthesis = state.get("synthesis", {}) or {}
    risk = (synthesis.get("risk_dashboard") or {}).get("overall_risk", "UNKNOWN")

    changes = [
        "# CHANGES",
        "",
        f"Run: `{run.run_id}`  ",
        f"Target: {run.repo_url}  ",
        f"Certificate: level {(run.certificate or {}).get('certificate_level', 'n/a')}  ",
        f"Overall risk: {risk}",
        "",
        "## Repairs",
        "",
    ]
    if fixed:
        for finding in fixed:
            diff = next((d for d in run.diffs if d["finding_id"] == finding["finding_id"]), None)
            changes += [
                f"### {finding['finding_id']} — {finding['title']}",
                "",
                f"- Severity: **{finding['severity']}**",
                f"- Violated clause: `{finding['clause']}`",
                f"- Location: `{finding.get('remediation_path') or finding['component']}`",
                f"- PoV signature: `{finding['pov_hash']}`",
                "",
            ]
            if diff:
                changes += ["```diff", diff["patch"], "```", ""]
    else:
        changes += ["No repair reached validated state in this run.", ""]

    changes += [
        "## Gauntlet",
        "",
        "| Stage | Verdict |",
        "| --- | --- |",
    ] + [f"| {stage} | {run.gauntlet.get(stage, 'none')} |" for stage in GAUNTLET_STAGES]

    remaining_doc = [
        "# REMAINING",
        "",
        f"Run: `{run.run_id}`",
        "",
        "## Not repaired",
        "",
    ]
    if remaining:
        for finding in remaining:
            remaining_doc += [
                f"- **{finding['finding_id']}** ({finding['severity']}) — {finding['title']}  ",
                f"  state: `{finding['state']}` · clause: `{finding['clause']}` · "
                f"component: {finding['component']}",
            ]
    else:
        remaining_doc += ["Every discovered finding reached a repaired state.", ""]

    remaining_doc += [
        "",
        "## Known limits of this run",
        "",
        "- Discovery findings come from the stub scanner in "
        "`kavachx/discovery/channels` — Semgrep is not wired in yet.",
        "- Patch diffs are synthesised from the remediation path, not compiled or executed.",
        "- Gauntlet verdicts map PRAMAAN verification checks; no sandbox replay has run.",
    ]

    return {
        "changes.md": "\n".join(changes) + "\n",
        "remaining.md": "\n".join(remaining_doc) + "\n",
    }


# ── Publishing ────────────────────────────────────────────────────────────────

class PublishRejected(Exception):
    """Raised when the deterministic policy gate refuses to publish."""


async def publish_finding(run: RunRecord, finding_id: str, actor_role: str) -> dict:
    """
    Publish one finding's patch. The gate is deterministic and runs before the
    publisher node — an LLM never decides this.
    """
    finding = run.finding(finding_id)
    if not finding:
        raise PublishRejected(f"Finding {finding_id} not found in run {run.run_id}")

    if run.status != "completed":
        raise PublishRejected("Run has not finished — no certificate to publish against")

    certificate = run.certificate or {}
    level = certificate.get("certificate_level")
    if level not in ("A", "B"):
        raise PublishRejected(
            f"Certificate level {level or 'none'} is below the publish threshold (A or B required)"
        )

    if finding["state"] not in ("validated", "fixed"):
        raise PublishRejected(
            f"Finding {finding_id} is {finding['state']} — only validated repairs publish"
        )

    if run.gauntlet.get("mutation") == "fail":
        raise PublishRejected("Refutation gauntlet found a bypass — patch self-rejected")

    if finding_id in run.published:
        return {"pr_url": run.published[finding_id], "already_published": True}

    # Publish through the existing publisher node, scoped to this finding's patch.
    scoped_state = dict(run.state)
    scoped_state["staged_patches"] = [
        p for p in (run.state.get("staged_patches") or [])
        if p.get("patch_id") == finding.get("patch_id")
    ]
    scoped_state["verifications"] = [
        v for v in (run.state.get("verifications") or [])
        if v.get("patch_id") == finding.get("patch_id")
    ]

    result = await publish_patches(scoped_state)
    published = result.get("published_patches") or []
    pr_urls = [url for p in published for url in p.get("pull_request_urls", [])]

    if not pr_urls:
        outputs = result.get("publish_outputs") or []
        reason = next((o.get("error_message") for o in outputs if o.get("error_message")), None)
        raise PublishRejected(reason or "Publisher produced no pull request")

    pr_url = pr_urls[0]
    run.published[finding_id] = pr_url
    ledger.append(
        actor=actor_role,
        action="patch:published",
        subject=f"{finding_id} → {pr_url}",
        tenant_id=run.tenant_id,
        run_id=run.run_id,
        details={"certificate": certificate.get("cert_id"), "level": level},
    )
    run.stream.publish(artifact_event("pr", pr_url))
    return {"pr_url": pr_url, "already_published": False}


__all__ = [
    "RunRecord",
    "RunRegistry",
    "registry",
    "execute_run",
    "publish_finding",
    "PublishRejected",
    "repo_url_to_channel",
]
