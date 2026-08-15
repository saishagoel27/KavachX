from typing import TypedDict, Literal


class KavachState(TypedDict):

    # ── Identity ──────────────────────────────────────────────────────────
    run_id: str
    phase: str
    tenant_id: str

    # ── Target ────────────────────────────────────────────────────────────
    target: dict
    # {
    #   "kind":        "repo" | "binary" | "service",
    #   "url":         str,
    #   "commit_sha":  str,          # pinned at ingest, never changes
    #   "tarball_ref": str,          # storage key for pre-fetched tarball
    #   "adapter":     "A" | "B" | "C",
    #   "language":    str | None,
    #   "build_cmd":   str | None,
    # }

    # ── World (graph handles only — never contents) ────────────────────────
    world: dict
    # {
    #   "graph_handle":   str,
    #   "ast_handle":     str,
    #   "semgrep_handle": str,
    #   "deploy_handle":  str,
    #   "corpus_handle":  str,
    # }

    # ── Contract (SAMHITA) ────────────────────────────────────────────────
    samhita: list
    # [{ clause_id, predicate, scope, obs_n, status, added_iter, description }]

    benign_corpus_ref: str

    # ── Discovery ─────────────────────────────────────────────────────────
    hypotheses: list
    # [{ hyp_id, channel, clause_id, location, confidence,
    #    reachability, blast_radius, priority, status }]

    validated: list
    # subset of hypotheses with status=="validated", each has exploit_ref

    downgraded: list
    # hypotheses that could not be validated, each has reason

    # ── Attack graph ──────────────────────────────────────────────────────
    attack_graph: dict
    # { nodes, edges, paths }

    priority: list
    # ordered finding IDs by attack-path priority

    # ── Shields ───────────────────────────────────────────────────────────
    shields: list
    # [{ shield_id, finding_id, rule, revert_cmd,
    #    verified_blocked, verified_benign, deployed_at }]

    # ── Patches ───────────────────────────────────────────────────────────
    patches: list
    # [{ patch_id, finding_id, diff, diff_hash, root_cause,
    #    blast_radius, iter, status, refuting_input }]

    patch_iter: int  # hard cap: 3

    # ── Gauntlet ──────────────────────────────────────────────────────────
    gauntlet: dict
    # { mutation, sibling, replay, contract: "pass"|"fail"|"pending", detail }

    # ── PRAMAAN ───────────────────────────────────────────────────────────
    pramaan: dict
    # { nodes: { node_id: { kind, ref, summary } }, edges: [...] }

    certificates: list
    # [{ cert_id, finding_id, level, evidence_hashes, signed_at, signature }]

    # ── Ledger (append-only) ──────────────────────────────────────────────
    ledger: list
    # [{ event, cause, node, timestamp }]

    # ── Budget ────────────────────────────────────────────────────────────
    budget: dict
    # { tokens_used, llm_calls, yield_per_node, wall_seconds }

    # ── Iteration caps (hard, never configurable at runtime) ──────────────
    iter: dict
    # { harness: int (≤3), patch: int (≤3), clause: int (≤2) }


def initial_state(run_id: str, tenant_id: str, target: dict) -> KavachState:
    return KavachState(
        run_id=run_id,
        phase="ingest",
        tenant_id=tenant_id,
        target=target,
        world={},
        samhita=[],
        benign_corpus_ref="",
        hypotheses=[],
        validated=[],
        downgraded=[],
        attack_graph={"nodes": [], "edges": [], "paths": []},
        priority=[],
        shields=[],
        patches=[],
        patch_iter=0,
        gauntlet={
            "mutation": "pending",
            "sibling": "pending",
            "replay": "pending",
            "contract": "pending",
            "detail": {},
        },
        pramaan={"nodes": {}, "edges": []},
        certificates=[],
        ledger=[],
        budget={
            "tokens_used": 0,
            "llm_calls": 0,
            "yield_per_node": {},
            "wall_seconds": 0.0,
        },
        iter={"harness": 0, "patch": 0, "clause": 0},
    )


# ── Phase transition order (for reference) ────────────────────────────────────
PHASES = [
    "ingest",
    "index_repo",
    "contract_synthesis",
    "discovery_fanout",
    "hypothesis_queue",
    "validate",
    "correlate",
    "patch_synthesis",
    "blast_radius",
    "gauntlet",
    "attest",
    "record_honest_failure",
    "publish_gate",
    "publisher",
    "done",
]

# ── Hard iteration caps ────────────────────────────────────────────────────────
ITER_CAP_HARNESS = 3
ITER_CAP_PATCH = 3
ITER_CAP_CLAUSE = 2


# ============================================================================
# PYDANTIC MODELS FOR ORCHESTRATION (STEP 3+)
# ============================================================================
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field
from typing import Optional, Any


class FindingType(str, Enum):
    """Type of security finding."""
    CVE = "cve"
    MISCONFIG = "misconfig"
    COMPLIANCE = "compliance"
    CODE_QUALITY = "code_quality"


class PatchStatus(str, Enum):
    """Patch status throughout its lifecycle."""
    DISCOVERED = "discovered"
    STAGED = "staged"
    VERIFIED = "verified"
    PUBLISHED = "published"
    FAILED = "failed"


class VerificationResult(str, Enum):
    """Verification outcome."""
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"


# ── Discovery Models ────────────────────────────────────────────────────────

class ChannelDiscoveryResult(BaseModel):
    """Result from discovering vulnerabilities in a GitHub channel (repo/branch)."""
    channel_name: str = Field(description="Channel identifier (org/repo#branch)")
    found_count: int = Field(default=0)
    cve_count: int = Field(default=0)
    misconfig_count: int = Field(default=0)
    findings: list[dict] = Field(default_factory=list)
    scan_error: Optional[str] = Field(default=None)
    scanned_at: datetime = Field(default_factory=datetime.utcnow)


class PatchCandidate(BaseModel):
    """A patch candidate discovered during discovery."""
    id: str
    channel_name: str
    finding_type: FindingType
    finding_id: str
    title: str
    description: str
    severity: str
    affected_component: str
    remediation_path: Optional[str] = None
    status: PatchStatus = PatchStatus.DISCOVERED
    created_at: datetime = Field(default_factory=datetime.utcnow)


class DiscoveryBatch(BaseModel):
    """Aggregated discovery results."""
    batch_id: str
    channel_results: list[ChannelDiscoveryResult]
    patch_candidates: list[PatchCandidate] = Field(default_factory=list)
    total_findings: int = 0
    discovery_started: datetime = Field(default_factory=datetime.utcnow)
    discovery_ended: Optional[datetime] = None


# ── Staging Models ────────────────────────────────────────────────────────

class PatchBuildArtifact(BaseModel):
    """Artifact generated during patch build."""
    artifact_type: str
    path: str
    content_hash: str
    size_bytes: int


class StagedPatch(BaseModel):
    """Patch staged for verification & publishing."""
    patch_id: str
    title: str
    description: str
    status: PatchStatus = PatchStatus.STAGED
    artifacts: list[PatchBuildArtifact] = Field(default_factory=list)
    build_output: str = ""
    remediation_steps: list[str] = Field(default_factory=list)
    deploy_instructions: str = ""
    staged_at: datetime = Field(default_factory=datetime.utcnow)
    source_channel: str


# ── Verification Models ────────────────────────────────────────────────────

class VerificationCheck(BaseModel):
    """Individual verification check result."""
    check_name: str
    result: VerificationResult
    details: str
    checked_at: datetime = Field(default_factory=datetime.utcnow)


class PatchVerification(BaseModel):
    """Complete verification report."""
    patch_id: str
    verification_id: str
    checks: list[VerificationCheck] = Field(default_factory=list)
    overall_result: VerificationResult
    verified_at: datetime = Field(default_factory=datetime.utcnow)
    verified_by: str = "pramaan_verifier"


class AuditEntry(BaseModel):
    """Audit log entry for patch lifecycle."""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_type: str  # discovered | staged | verified | published | failed
    patch_id: str
    details: dict = Field(default_factory=dict)
    actor: str = "system"


# ── Publishing Models ────────────────────────────────────────────────────

class PublishedPatch(BaseModel):
    """Published patch record."""
    patch_id: str
    publish_id: str
    title: str
    description: str
    publish_date: datetime = Field(default_factory=datetime.utcnow)
    published_to: list[str]
    pull_request_urls: list[str] = Field(default_factory=list)
    documentation_url: Optional[str] = None


class PublishPatchOutput(BaseModel):
    """Output from patch publishing."""
    patch_id: str
    success: bool
    published_patch: Optional[PublishedPatch] = None
    pr_details: list[dict] = Field(default_factory=list)
    error_message: Optional[str] = None
    published_at: datetime = Field(default_factory=datetime.utcnow)
