"""Request/response schemas for the whole API surface."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.models.enums import AnalysisProfile, ExecutionProfile, Role


class ApiModel(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


# ---------------------------------------------------------------------------
# auth
# ---------------------------------------------------------------------------
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=200)
    full_name: str = Field(default="", max_length=200)
    organisation_name: str = Field(default="", max_length=200)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=200)


class RefreshRequest(BaseModel):
    refresh_token: str


class SwitchOrgRequest(BaseModel):
    organisation_id: uuid.UUID


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int
    organisation_id: uuid.UUID | None = None
    role: str | None = None


class UserOut(ApiModel):
    id: uuid.UUID
    email: str
    full_name: str
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None = None


class MembershipOut(BaseModel):
    organisation_id: uuid.UUID
    organisation_name: str
    organisation_slug: str
    role: str


class MeOut(BaseModel):
    user: UserOut
    memberships: list[MembershipOut]
    active_organisation_id: uuid.UUID | None = None
    active_role: str | None = None
    permissions: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# organisations / members / policy
# ---------------------------------------------------------------------------
class OrganisationCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)


class OrganisationOut(ApiModel):
    id: uuid.UUID
    name: str
    slug: str
    created_at: datetime


class MemberInvite(BaseModel):
    email: EmailStr
    role: Role
    password: str | None = Field(default=None, min_length=12, max_length=200)


class MemberOut(BaseModel):
    user_id: uuid.UUID
    email: str
    full_name: str
    role: str
    created_at: datetime


class RoleUpdate(BaseModel):
    role: Role


class PolicyOut(ApiModel):
    id: uuid.UUID
    name: str
    forbidden_path_globs: list[Any]
    max_diff_lines: int
    max_files_changed: int
    allow_new_dependencies: bool
    allow_new_network_calls: bool
    allow_new_exec: bool
    allow_binary_changes: bool
    require_certificate: bool
    min_assurance_level: str
    require_human_approval: bool
    enforce_blast_radius: bool
    updated_at: datetime


class PolicyUpdate(BaseModel):
    max_diff_lines: int | None = Field(default=None, ge=1, le=5000)
    max_files_changed: int | None = Field(default=None, ge=1, le=100)
    allow_new_dependencies: bool | None = None
    allow_new_network_calls: bool | None = None
    allow_new_exec: bool | None = None
    allow_binary_changes: bool | None = None
    require_certificate: bool | None = None
    min_assurance_level: Literal["A", "B", "C"] | None = None
    require_human_approval: bool | None = None
    enforce_blast_radius: bool | None = None
    forbidden_path_globs: list[str] | None = None


# ---------------------------------------------------------------------------
# projects / repositories
# ---------------------------------------------------------------------------
class ProjectCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    description: str = Field(default="", max_length=1000)


class ProjectOut(ApiModel):
    id: uuid.UUID
    name: str
    slug: str
    description: str
    created_at: datetime
    repository_count: int = 0
    run_count: int = 0


class RepositoryOut(ApiModel):
    id: uuid.UUID
    project_id: uuid.UUID
    provider: str
    full_name: str
    default_branch: str
    private: bool
    local_path: str = ""
    installation_id: int | None = None
    authority_verified_at: datetime | None = None
    authority_evidence: dict[str, Any] = Field(default_factory=dict)
    language_summary: dict[str, Any] = Field(default_factory=dict)


class RepositoryAttach(BaseModel):
    """Attach a repository.

    Three authority paths, in descending capability:

    * ``installation_id`` — a GitHub App installation that includes the repository. The only path
      that can later publish a pull request.
    * ``public`` — a publicly readable GitHub repository, ingested read-only. Analysis only; it can
      never reach the Publisher because there is no credential behind it.
    * ``local_seeded`` — the seeded target inside this repository's ``examples/`` tree (``DEV_MODE``).
    """

    full_name: str = Field(min_length=3, max_length=400)
    installation_id: int | None = None
    #: Blank means "whatever the repository says its default branch is".
    #:
    #: Deliberately not defaulted to ``"main"``: a literal default here would silently override the
    #: branch GitHub actually reports, and any repository still on ``master`` would fail to resolve.
    default_branch: str = Field(default="", max_length=200)
    local_seeded: bool = False
    #: Ingest a public GitHub repository for analysis. Accepts a URL or ``owner/repo``.
    public: bool = False
    #: Required when ``public`` is set: the caller affirms this is authorised research.
    authorisation_confirmed: bool = False


class PublicRepoPreview(BaseModel):
    """What a public repository looks like before you commit to analysing it."""

    full_name: str
    default_branch: str
    description: str = ""
    primary_language: str = ""
    languages: dict[str, int] = Field(default_factory=dict)
    size_kb: int = 0
    stars: int = 0
    archived: bool = False
    fork: bool = False
    license: str = ""
    html_url: str = ""
    head_commit: dict[str, Any] = Field(default_factory=dict)
    publishable: bool = False
    notes: list[str] = Field(default_factory=list)


class InstallationOut(ApiModel):
    id: uuid.UUID
    installation_id: int
    account_login: str
    account_type: str
    repository_selection: str
    suspended: bool
    verified_at: datetime | None = None


# ---------------------------------------------------------------------------
# runs
# ---------------------------------------------------------------------------
class RunCreate(BaseModel):
    repository_id: uuid.UUID
    #: Blank means "the branch the repository actually reports as its default".
    #: Deliberately not defaulted to ``"main"``: a literal here is always truthy, so the
    #: ``payload.branch or repository.default_branch`` fallback in the route could never fire and a
    #: repository still on ``master`` would fail at ingest with "'main' is not a branch".
    branch: str = Field(default="", max_length=300)
    commit_sha: str = Field(default="", max_length=64)
    analysis_profile: AnalysisProfile = AnalysisProfile.STANDARD
    execution_profile: ExecutionProfile = ExecutionProfile.DEV_LOCAL
    max_runtime_seconds: int = Field(default=1800, ge=60, le=14400)
    resource_budget: dict[str, Any] = Field(default_factory=dict)
    #: The caller must affirm authorisation. Recorded in the audit log.
    authorisation_confirmed: bool = False

    @field_validator("commit_sha")
    @classmethod
    def _hex(cls, v: str) -> str:
        if v and not all(c in "0123456789abcdefABCDEF" for c in v):
            raise ValueError("commit_sha must be hexadecimal")
        return v.lower()


class RunOut(ApiModel):
    id: uuid.UUID
    short_code: str
    project_id: uuid.UUID
    repository_id: uuid.UUID
    branch: str
    commit_sha: str
    pinned_source_sha256: str
    analysis_profile: str
    execution_profile: str
    status: str
    phase: str
    phase_status: dict[str, Any]
    #: "full" or "static_only" — see Run.mode. Surfaced on the list as well as the detail so a
    #: static-only run is never mistaken for a clean sweep in a table of results.
    mode: str = "full"
    static_only_reason: str = ""
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    time_to_protection_ms: int | None = None
    time_to_repair_ms: int | None = None
    tokens_used: int
    model_calls: int
    sandbox_executions: int
    coverage_percent: float
    peak_ram_mb: int
    cpu_seconds: float
    egress_bytes: int
    error_code: str
    error_message: str
    abort_requested: bool
    publish_approved_at: datetime | None = None
    repository_full_name: str = ""
    project_name: str = ""


class RunDetail(RunOut):
    findings_total: int = 0
    findings_validated: int = 0
    patches_verified: int = 0
    certificates: list[dict[str, Any]] = Field(default_factory=list)
    shields: list[dict[str, Any]] = Field(default_factory=list)
    clause_summary: dict[str, int] = Field(default_factory=dict)
    world_model: dict[str, Any] = Field(default_factory=dict)
    sandbox: dict[str, Any] = Field(default_factory=dict)
    hypothesis_counts: dict[str, int] = Field(default_factory=dict)
    artifacts: list[dict[str, Any]] = Field(default_factory=list)


class AbortRequest(BaseModel):
    reason: str = Field(default="", max_length=500)


# ---------------------------------------------------------------------------
# findings / hypotheses / clauses
# ---------------------------------------------------------------------------
class FindingOut(ApiModel):
    id: uuid.UUID
    handle: str
    title: str
    state: str
    severity: str
    cwe: str
    source_channel: str
    violated_clause_id: str
    location: str
    reachable: bool
    reachability_score: float
    reproduced: bool
    reproduction_count: int
    exit_code: int | None = None
    sanitizer_signal: str
    contract_violation: str
    input_hash: str
    output_hash: str
    trace_hash: str
    coverage_percent: float
    pov_kind: str
    pov_hash: str
    root_cause_location: str
    root_cause_summary: str
    root_cause_verified: bool
    root_cause_chain: list[Any]
    blast_radius_json: dict[str, Any]
    status_label: str
    validated_at: datetime | None = None
    #: Only populated for callers holding finding:read_pov.
    pov_payload: str | None = None
    pov_access: Literal["granted", "withheld"] = "withheld"


class HypothesisOut(ApiModel):
    id: uuid.UUID
    handle: str
    source_channel: str
    description: str
    location: str
    severity: str
    reachability: float
    confidence: float
    blast_radius: float
    priority: float
    status: str
    cwe: str
    candidate_clause_id: str
    unknown_reason: str
    evidence_refs: list[Any]
    transitions: list[Any]


class ClauseOut(ApiModel):
    id: uuid.UUID
    clause_id: str
    kind: str
    description: str
    predicate: str
    scope: str
    observation_count: int
    status: str
    falsification_reason: str
    counterexample: dict[str, Any]
    holdout_pass_count: int
    holdout_fail_count: int
    evidence_refs: list[Any]


class PatchOut(ApiModel):
    id: uuid.UUID
    finding_id: uuid.UUID
    iteration: int
    status: str
    reason: str
    unified_diff: str
    files: list[Any]
    risk: str
    expected_effect: str
    diff_hash: str
    lines_added: int
    lines_removed: int
    policy_passed: bool
    policy_violations: list[Any]
    within_blast_radius: bool
    constraints: list[Any]
    refutation_summary: str
    verified_at: datetime | None = None
    withdrawn_at: datetime | None = None
    finding_handle: str = ""


class GauntletStageOut(BaseModel):
    stage: str
    verdict: str
    detail: str
    refuting_evidence: dict[str, Any]
    metrics: dict[str, Any]
    duration_ms: int
    cases_total: int
    cases_passed: int


class GauntletOut(BaseModel):
    id: uuid.UUID
    finding_handle: str
    patch_id: uuid.UUID
    iteration: int
    verdict: str
    failing_stage: str
    stages_passed: int
    stages_total: int
    duration_ms: int
    summary: str
    stages: list[GauntletStageOut]


class ShieldOut(ApiModel):
    id: uuid.UUID
    handle: str
    mechanism: str
    rule: str
    rule_json: dict[str, Any]
    deploy_command: str
    revert_command: str
    verified_blocked: bool
    verified_benign: bool
    benign_pass_count: int
    benign_total: int
    deployed_at: datetime | None = None
    reverted_at: datetime | None = None
    finding_handle: str = ""


# ---------------------------------------------------------------------------
# certificates / evidence / artifacts
# ---------------------------------------------------------------------------
class CertificateOut(ApiModel):
    id: uuid.UUID
    run_id: uuid.UUID
    finding_id: uuid.UUID | None = None
    serial: str
    assurance_level: str
    grading_rationale: list[Any]
    limitations: list[Any]
    certificate_hash: str
    signature: str
    signature_algorithm: str
    evidence_node_count: int
    evidence_edge_count: int
    generation_ms: int
    issued_at: datetime | None = None
    finding_handle: str = ""


class CertificateDetail(CertificateOut):
    document: dict[str, Any]
    evidence_graph: dict[str, Any] = Field(default_factory=dict)
    verification: dict[str, Any] = Field(default_factory=dict)


class EvidenceNodeOut(ApiModel):
    ref: str
    type: str
    title: str
    content_hash: str
    produced_by: str
    meta_json: dict[str, Any]
    created_at: datetime


class ArtifactOut(ApiModel):
    id: uuid.UUID
    kind: str
    name: str
    media_type: str
    content_hash: str
    size_bytes: int
    url: str
    created_at: datetime
    meta_json: dict[str, Any]


class PublishRequestIn(BaseModel):
    certificate_id: uuid.UUID
    confirm: bool = False
    note: str = Field(default="", max_length=500)


class PublishResultOut(BaseModel):
    ok: bool
    dry_run: bool
    branch: str
    pull_request_url: str
    pull_request_number: int | None = None
    artifacts_written: list[str]
    blocked_reason: str
    policy_violations: list[dict[str, Any]]
    payload_hash: str
    dry_run_payload: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# audit / dashboard
# ---------------------------------------------------------------------------
class AuditEventOut(ApiModel):
    id: uuid.UUID
    seq: int
    actor_label: str
    action: str
    subject_type: str
    subject_id: str
    request_id: str
    source_ip: str
    detail: dict[str, Any]
    evidence_hash: str
    previous_hash: str
    hash: str
    created_at: datetime


class AuditPage(BaseModel):
    items: list[AuditEventOut]
    total: int
    limit: int
    offset: int
    chain_head: str


class DashboardOut(BaseModel):
    projects: int
    repositories: int
    repositories_verified: int
    runs_total: int
    runs_active: int
    runs_completed: int
    findings_total: int
    findings_validated: int
    findings_refuted: int
    patches_verified: int
    patches_refuted: int
    certificates_total: int
    certificates_by_level: dict[str, int]
    avg_time_to_protection_ms: int | None = None
    avg_time_to_repair_ms: int | None = None
    verification_success_rate: float
    open_pull_requests: int
    residual_risk_items: int
    total_tokens: int
    total_sandbox_executions: int
    egress_bytes: int
    recent_runs: list[RunOut]


class HealthOut(BaseModel):
    status: str
    version: str
    environment: str
    dev_mode: bool


class ReadyOut(BaseModel):
    status: str
    database: bool
    llm_provider: str
    llm_configured: bool
    sandbox_adapter: str
    sandbox_suitable_for_untrusted_code: bool
    github_app_configured: bool
    publisher_dry_run: bool
    active_runs: list[str]
    details: dict[str, Any] = Field(default_factory=dict)
