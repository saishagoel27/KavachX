/**
 * Typed API client.
 *
 * Every call goes through `request`, which attaches the access token, refreshes it once on a 401,
 * and surfaces the backend's structured `{error:{code,message,request_id}}` shape as a typed
 * `ApiError`. That means UI code can branch on `error.code` — `EXPLOIT_ACCESS_DENIED`,
 * `REPOSITORY_NOT_AUTHORISED`, `ASSURANCE_LEVEL_R` — instead of pattern-matching prose.
 */

export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL?.replace(/\/$/, "") ?? "http://localhost:8000";

const ACCESS_KEY = "kavachx.access";
const REFRESH_KEY = "kavachx.refresh";

export class ApiError extends Error {
  code: string;
  status: number;
  requestId: string;
  details?: unknown;

  constructor(status: number, code: string, message: string, requestId = "", details?: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
    this.details = details;
  }
}

export const tokens = {
  access: () => (typeof window === "undefined" ? null : localStorage.getItem(ACCESS_KEY)),
  refresh: () => (typeof window === "undefined" ? null : localStorage.getItem(REFRESH_KEY)),
  set(access: string, refresh: string) {
    if (typeof window === "undefined") return;
    localStorage.setItem(ACCESS_KEY, access);
    localStorage.setItem(REFRESH_KEY, refresh);
  },
  clear() {
    if (typeof window === "undefined") return;
    localStorage.removeItem(ACCESS_KEY);
    localStorage.removeItem(REFRESH_KEY);
  },
};

async function parseError(response: Response): Promise<ApiError> {
  let code = `HTTP_${response.status}`;
  let message = response.statusText || "Request failed.";
  let requestId = response.headers.get("x-request-id") ?? "";
  let details: unknown;
  try {
    const body = await response.json();
    if (body?.error) {
      code = body.error.code ?? code;
      message = body.error.message ?? message;
      requestId = body.error.request_id ?? requestId;
      details = body.error.details;
    }
  } catch {
    /* a non-JSON error body is still an error; keep the status-derived values */
  }
  return new ApiError(response.status, code, message, requestId, details);
}

let refreshInFlight: Promise<boolean> | null = null;

async function refreshTokens(): Promise<boolean> {
  const refresh = tokens.refresh();
  if (!refresh) return false;
  // Collapse concurrent refreshes: a console page fires many requests at once, and racing
  // refreshes would invalidate each other's tokens.
  if (!refreshInFlight) {
    refreshInFlight = (async () => {
      try {
        const response = await fetch(`${API_BASE}/api/auth/refresh`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ refresh_token: refresh }),
        });
        if (!response.ok) return false;
        const data = await response.json();
        tokens.set(data.access_token, data.refresh_token);
        return true;
      } catch {
        return false;
      } finally {
        refreshInFlight = null;
      }
    })();
  }
  return refreshInFlight;
}

export interface RequestOptions extends Omit<RequestInit, "body"> {
  body?: unknown;
  auth?: boolean;
  retryOnUnauthorised?: boolean;
}

export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { body, auth = true, retryOnUnauthorised = true, ...init } = options;
  const headers = new Headers(init.headers);
  if (body !== undefined) headers.set("content-type", "application/json");
  const token = auth ? tokens.access() : null;
  if (token) headers.set("authorization", `Bearer ${token}`);

  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  if (response.status === 401 && auth && retryOnUnauthorised) {
    if (await refreshTokens()) {
      return request<T>(path, { ...options, retryOnUnauthorised: false });
    }
    tokens.clear();
  }

  if (!response.ok) throw await parseError(response);
  if (response.status === 204) return undefined as T;

  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) return (await response.json()) as T;
  return (await response.text()) as unknown as T;
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) => request<T>(path, { method: "POST", body }),
  patch: <T>(path: string, body?: unknown) => request<T>(path, { method: "PATCH", body }),
  del: <T>(path: string) => request<T>(path, { method: "DELETE" }),
  text: (path: string) => request<string>(path),
};

// ---------------------------------------------------------------------------
// Types mirroring the backend schemas.
// ---------------------------------------------------------------------------
export interface TokenPair {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  organisation_id: string | null;
  role: string | null;
}

export interface Membership {
  organisation_id: string;
  organisation_name: string;
  organisation_slug: string;
  role: string;
}

export interface Me {
  user: { id: string; email: string; full_name: string; created_at: string };
  memberships: Membership[];
  active_organisation_id: string | null;
  active_role: string | null;
  permissions: string[];
}

export interface Project {
  id: string;
  name: string;
  slug: string;
  description: string;
  created_at: string;
  repository_count: number;
  run_count: number;
}

export interface Repository {
  id: string;
  project_id: string;
  provider: string;
  full_name: string;
  default_branch: string;
  private: boolean;
  local_path: string;
  installation_id: number | null;
  authority_verified_at: string | null;
  authority_evidence: Record<string, unknown>;
}

export interface SystemLimits {
  run_max_runtime_seconds: number;
  sandbox: {
    cpu_limit: number;
    memory_mb: number;
    pid_limit: number;
    disk_mb: number;
    wall_clock_seconds: number;
  };
  token_budget_per_run: number;
  iteration_limits: { harness: number; patch: number; clause: number };
}

export interface Framework {
  id: string;
  label: string;
  /** Toolchain language, used by the backend to pick the sandbox image. "" = auto-detect. */
  language: string;
  /** "http" (long-running server) | "cli" (request→output) | "" (auto). */
  kind: string;
  /** Default listen port for HTTP frameworks (0 for CLI/auto). */
  port: number;
  install: string;
  build: string;
  start: string;
}

export interface PublicRepoPreview {
  full_name: string;
  default_branch: string;
  description: string;
  primary_language: string;
  languages: Record<string, number>;
  size_kb: number;
  stars: number;
  archived: boolean;
  fork: boolean;
  license: string;
  html_url: string;
  head_commit: { sha?: string; message?: string; author?: string; date?: string; html_url?: string };
  publishable: boolean;
  notes: string[];
}

export interface Run {
  id: string;
  short_code: string;
  project_id: string;
  repository_id: string;
  branch: string;
  commit_sha: string;
  pinned_source_sha256: string;
  analysis_profile: string;
  execution_profile: string;
  status: string;
  phase: string;
  phase_status: Record<string, string>;
  /**
   * "full" or "static_only". A static-only run executed nothing, so its zero validated findings
   * mean "nothing was proved", not "nothing is wrong" — every view that shows result counts must
   * show this alongside them.
   */
  mode: string;
  static_only_reason: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  time_to_protection_ms: number | null;
  time_to_repair_ms: number | null;
  tokens_used: number;
  model_calls: number;
  sandbox_executions: number;
  coverage_percent: number;
  peak_ram_mb: number;
  cpu_seconds: number;
  egress_bytes: number;
  error_code: string;
  error_message: string;
  abort_requested: boolean;
  publish_approved_at: string | null;
  repository_full_name: string;
  project_name: string;
}

export interface RunDetail extends Run {
  findings_total: number;
  findings_validated: number;
  patches_verified: number;
  certificates: Array<{
    id: string;
    serial: string;
    assurance_level: string;
    certificate_hash: string;
    finding_handle: string;
    issued_at: string | null;
    limitations: string[];
  }>;
  shields: Array<{
    id: string;
    handle: string;
    mechanism: string;
    rule: string;
    verified_blocked: boolean;
    verified_benign: boolean;
    benign_pass_count: number;
    benign_total: number;
    active: boolean;
    revert_command: string;
    finding_handle: string;
  }>;
  clause_summary: Record<string, number>;
  world_model: Record<string, any>;
  sandbox: Record<string, any>;
  hypothesis_counts: Record<string, number>;
  artifacts: Array<{
    id: string;
    kind: string;
    name: string;
    media_type: string;
    size_bytes: number;
    content_hash: string;
    url: string;
  }>;
}

export interface Finding {
  id: string;
  handle: string;
  title: string;
  state: string;
  severity: string;
  cwe: string;
  source_channel: string;
  violated_clause_id: string;
  location: string;
  reachable: boolean;
  reachability_score: number;
  reproduced: boolean;
  reproduction_count: number;
  exit_code: number | null;
  sanitizer_signal: string;
  contract_violation: string;
  input_hash: string;
  output_hash: string;
  trace_hash: string;
  coverage_percent: number;
  pov_kind: string;
  pov_hash: string;
  root_cause_location: string;
  root_cause_summary: string;
  root_cause_verified: boolean;
  root_cause_chain: string[];
  blast_radius_json: Record<string, any>;
  status_label: string;
  validated_at: string | null;
  pov_payload: string | null;
  pov_access: "granted" | "withheld";
}

export interface Hypothesis {
  id: string;
  handle: string;
  source_channel: string;
  description: string;
  location: string;
  severity: string;
  reachability: number;
  confidence: number;
  blast_radius: number;
  priority: number;
  status: string;
  cwe: string;
  candidate_clause_id: string;
  unknown_reason: string;
  evidence_refs: string[];
  transitions: Array<Record<string, any>>;
}

export interface Clause {
  id: string;
  clause_id: string;
  kind: string;
  description: string;
  predicate: string;
  scope: string;
  observation_count: number;
  status: string;
  falsification_reason: string;
  counterexample: Record<string, any>;
  holdout_pass_count: number;
  holdout_fail_count: number;
}

export interface Patch {
  id: string;
  finding_id: string;
  finding_handle: string;
  iteration: number;
  status: string;
  reason: string;
  unified_diff: string;
  files: string[];
  risk: string;
  expected_effect: string;
  diff_hash: string;
  lines_added: number;
  lines_removed: number;
  policy_passed: boolean;
  policy_violations: Array<Record<string, any>>;
  within_blast_radius: boolean;
  constraints: string[];
  refutation_summary: string;
  verified_at: string | null;
  withdrawn_at: string | null;
}

export interface GauntletStage {
  stage: string;
  verdict: string;
  detail: string;
  refuting_evidence: Record<string, any>;
  metrics: Record<string, any>;
  duration_ms: number;
  cases_total: number;
  cases_passed: number;
}

export interface GauntletRun {
  id: string;
  finding_handle: string;
  patch_id: string;
  iteration: number;
  verdict: string;
  failing_stage: string;
  stages_passed: number;
  stages_total: number;
  duration_ms: number;
  summary: string;
  stages: GauntletStage[];
}

export interface Certificate {
  id: string;
  run_id: string;
  finding_id: string | null;
  finding_handle: string;
  serial: string;
  assurance_level: string;
  grading_rationale: string[];
  limitations: string[];
  certificate_hash: string;
  signature: string;
  signature_algorithm: string;
  evidence_node_count: number;
  evidence_edge_count: number;
  generation_ms: number;
  issued_at: string | null;
  document?: Record<string, any>;
  evidence_graph?: Record<string, any>;
  verification?: Record<string, any>;
}

export interface Dashboard {
  projects: number;
  repositories: number;
  repositories_verified: number;
  runs_total: number;
  runs_active: number;
  runs_completed: number;
  findings_total: number;
  findings_validated: number;
  findings_refuted: number;
  patches_verified: number;
  patches_refuted: number;
  certificates_total: number;
  certificates_by_level: Record<string, number>;
  avg_time_to_protection_ms: number | null;
  avg_time_to_repair_ms: number | null;
  verification_success_rate: number;
  open_pull_requests: number;
  residual_risk_items: number;
  total_tokens: number;
  total_sandbox_executions: number;
  egress_bytes: number;
  recent_runs: Run[];
}

export interface EvidenceGraph {
  run_id: string;
  root: string | null;
  nodes: Array<{
    ref: string;
    type: string;
    title: string;
    content_hash: string;
    produced_by: string;
    meta: Record<string, any>;
    has_content: boolean;
  }>;
  edges: Array<{ source: string; relation: string; target: string }>;
  counts: { nodes: number; edges: number };
}

export interface AuditEvent {
  id: string;
  seq: number;
  actor_label: string;
  action: string;
  subject_type: string;
  subject_id: string;
  request_id: string;
  source_ip: string;
  detail: Record<string, any>;
  evidence_hash: string;
  previous_hash: string;
  hash: string;
  created_at: string;
}

export interface PublishResult {
  ok: boolean;
  dry_run: boolean;
  branch: string;
  pull_request_url: string;
  pull_request_number: number | null;
  artifacts_written: string[];
  blocked_reason: string;
  policy_violations: Array<Record<string, any>>;
  payload_hash: string;
  dry_run_payload: Record<string, any>;
}

// ---------------------------------------------------------------------------
// Code intelligence.
//
// Every one of these is a projection of what a run *recorded*, never a recomputation. So each can
// come back unavailable — for a run that predates the stage, or one that failed before reaching
// it — and the shape says so explicitly rather than returning an empty object that would read as
// "the stage ran and found nothing".
export interface Unavailable {
  available: false;
  reason: string;
}

export type Projection<T> = ({ available: true } & T) | Unavailable;

export interface IndexHealthCheck {
  id: string;
  severity: "ok" | "warn" | "fail" | string;
  title: string;
  detail: string;
  /** What this check forbids the run from claiming. Empty only when severity is ok. */
  bounds_claim: string;
}

export interface IndexReport {
  index: {
    index_id: string;
    commit_sha: string;
    source_sha256: string;
    graph_hash: string;
    /** Only providers that actually contributed. Never a capability claim. */
    graph_source: string;
    status: string;
    providers: string[];
    versions: Record<string, any>;
    options: Record<string, any>;
    languages: Record<string, number>;
    files: {
      discovered: number;
      indexed: number;
      skipped: number;
      skipped_detail: Array<{ path: string; reason: string }>;
    };
    symbols: { total: number; functions: number; classes: number };
    relationships: {
      total: number;
      calls: number;
      imports: number;
      resolved: number;
      resolved_ratio: number;
    };
    discovered: { entrypoints: number; tests: number; configs: number; dependencies: number };
    incremental: { enabled: boolean; changed_files: string[]; affected_symbols: string[] };
    warnings: string[];
    errors: string[];
    duration_ms: number;
  };
  health: {
    grade: string;
    usable: boolean;
    summary?: string;
    checks: IndexHealthCheck[];
  } & Record<string, any>;
  /** What this index is not good enough to support. Travels into every certificate. */
  claim_bounds: string[];
}

export interface GraphNode {
  uid: string;
  kind: string;
  name: string;
  qualname: string;
  file: string;
  start_line: number;
  end_line: number;
  language: string;
  exported: boolean;
  signature: string;
  parameters: string[];
  decorators: string[];
  docline: string;
  provenance: string[];
}

export interface GraphEdge {
  src: string;
  dst: string;
  kind: string;
  provenance: string[];
  confidence: number;
  /** True when a symbol-resolving provider produced it, not just a name match. */
  resolved: boolean;
  attrs?: Record<string, any>;
}

export interface GraphOverview {
  stats: Record<string, any>;
  providers: string[];
  truncated: boolean;
  warnings: string[];
  entrypoints: GraphNode[];
  sample_nodes: GraphNode[];
  note: string;
}

export interface GraphSubgraph {
  root: string;
  depth: number;
  nodes: GraphNode[];
  edges: GraphEdge[];
  truncated: boolean;
  stats: Record<string, any>;
}

export interface SecurityNode {
  ref: string;
  category: string;
  kind: string;
  file: string;
  line: number;
  location: string;
  owner: string;
  rule_id: string;
  cwe: string;
  severity: string;
  snippet: string;
  why: string;
  confidence: number;
}

export interface SecurityFlowStep {
  kind: string;
  location: string;
  detail: string;
  symbol: string;
}

export interface SecurityFlow {
  ref: string;
  source_ref: string;
  sink_ref: string;
  source_kind: string;
  sink_kind: string;
  cwe: string;
  severity: string;
  steps: SecurityFlowStep[];
  call_path: string[];
  sanitizers: string[];
  validators: string[];
  sanitized: boolean;
  boundaries: string[];
  crosses_trust_boundary: boolean;
  /** taint | call-graph | proximity. */
  basis: string;
  /** resolved | union. */
  precision: string;
  entrypoint: string;
  reachable_from_entrypoint: boolean;
  /** False when there was no entrypoint to search from — unknown, not unreachable. */
  reachability_measured: boolean;
  interpolated: boolean;
  confidence: number;
  covering_tests: string[];
  notes: string[];
}

export interface SecurityModelView {
  content_hash: string;
  index_id: string;
  stats: Record<string, number>;
  taxonomy: Record<string, any>;
  nodes: SecurityNode[];
  flows: SecurityFlow[];
  trust_boundaries: Array<{ kind: string; description: string; members: string[] }>;
  parse_errors: Array<{ path: string; error: string }>;
  warnings: string[];
}

export interface SurfaceItem {
  ref: string;
  entrypoint: string;
  entrypoint_kind: string;
  route: string;
  source_kind: string;
  sink_kind: string;
  sink_location: string;
  cwe: string;
  severity: string;
  /** The six 0–1 factors whose product is the priority. Recorded so a rank is never a bare number. */
  factors: Record<string, number>;
  priority: number;
  measured: boolean;
  externally_controllable: boolean;
  controls: string[];
  sanitizers: string[];
  covering_tests: string[];
  testable: boolean;
  testability_reason: string;
  rationale: string[];
}

export interface ArchitectureView {
  content_hash: string;
  model: {
    application_type: string;
    type_evidence: string[];
    languages: Record<string, number>;
    non_code_files: Record<string, number>;
    frameworks: string[];
    entrypoints: Array<Record<string, any>>;
    modules: Array<Record<string, any>>;
    data_stores: string[];
    authentication: string[];
    trust_boundaries: string[];
    gaps: string[];
  } & Record<string, any>;
  attack_surface: {
    measured: boolean;
    counts: Record<string, number>;
    items: SurfaceItem[];
    unauthenticated_entrypoints: string[];
    unreached_sinks: string[];
    untested_paths: string[];
    notes: string[];
  } & Record<string, any>;
  gaps: string[];
}

export interface TestPlanRecord {
  plan_id: string;
  candidate_ref: string;
  finding_handle: string;
  status: string;
  strategy: string;
  oracle_kind: string;
  engine: string;
  engine_available: boolean;
  engine_reason: string;
  language: string;
  /** Whether the spec came from a model or the deterministic fallback. */
  proposed_by: string;
  harness_path: string;
  harness_sha256: string;
  command: string[];
  security_property: string;
  spec: Record<string, any>;
  provenance: Record<string, any>;
  notes: string[];
}

export interface TestExecutionRecord {
  plan_id: string;
  candidate_ref: string;
  finding_handle: string;
  strategy: string;
  engine: string;
  harness_path: string;
  harness_sha256: string;
  command: string[];
  commit_sha: string;
  index_id: string;
  input_hash: string;
  environment: Record<string, any>;
  reproduced: boolean;
  reproduction_count: number;
  reproductions_required: number;
  verdict_detail: string;
  proving_evidence: string;
  attempts: Array<Record<string, any>>;
  coverage: Record<string, any>;
  campaign: Record<string, any>;
  error: string;
  duration_ms: number;
}

export interface TestsView {
  plans: TestPlanRecord[];
  executions: TestExecutionRecord[];
  counts: Record<string, number>;
}

export interface ModelContextSummary {
  context_hash: string;
  candidate_ref: string;
  task: string;
  version: string;
  provider: string;
  model: string;
  size_chars: number;
  selected_files: string[];
  selected_functions: string[];
  code_slice_keys: string[];
  budget: Record<string, number>;
  used: Record<string, number>;
  /** What did not fit, and why. Never silent. */
  dropped: string[];
  tool_call_count: number;
  note: string;
  tool_calls?: Array<Record<string, any>>;
}

export interface EngineInventory {
  engines: Array<{
    id: string;
    label: string;
    language: string;
    strategies: string[];
    status: "available" | "unavailable" | "unimplemented" | string;
    coverage_feedback: boolean;
    missing_binaries: string[];
    missing_modules: string[];
    reason: string;
    notes: string;
  }>;
  by_language: Record<string, Array<Record<string, any>>>;
  counts: { available: number; unavailable: number; unimplemented: number };
  note: string;
  probe_scope?: string;
  caveat?: string;
}

// ---------------------------------------------------------------------------
export const endpoints = {
  login: (email: string, password: string) =>
    request<TokenPair>("/api/auth/login", {
      method: "POST",
      body: { email, password },
      auth: false,
    }),
  register: (body: {
    email: string;
    password: string;
    full_name?: string;
    organisation_name?: string;
  }) => request<TokenPair>("/api/auth/register", { method: "POST", body, auth: false }),
  me: () => api.get<Me>("/api/auth/me"),
  switchOrg: (organisation_id: string) =>
    api.post<TokenPair>("/api/auth/switch-org", { organisation_id }),
  logout: () => api.post<void>("/api/auth/logout"),

  projects: () => api.get<Project[]>("/api/projects"),
  createProject: (body: { name: string; description?: string }) =>
    api.post<Project>("/api/projects", body),
  repositories: () => api.get<Repository[]>("/api/repositories"),
  attachLocalTarget: (projectId: string, full_name = "examples/vulnerable-demo") =>
    api.post<Repository>(`/api/projects/${projectId}/repositories`, {
      full_name,
      local_seeded: true,
      default_branch: "main",
    }),
  previewPublicRepo: (repo: string, revision = "") =>
    api.get<PublicRepoPreview>(
      `/api/github/public/preview?repo=${encodeURIComponent(repo)}` +
        (revision ? `&revision=${encodeURIComponent(revision)}` : ""),
    ),
  attachPublicRepo: (projectId: string, full_name: string, default_branch = "") =>
    api.post<Repository>(`/api/projects/${projectId}/repositories`, {
      full_name,
      public: true,
      authorisation_confirmed: true,
      // Blank lets the backend use whatever GitHub reports. Sending "main" would break every
      // repository still on "master".
      default_branch,
    }),
  githubApp: () => api.get<Record<string, any>>("/api/github/app"),

  dashboard: () => api.get<Dashboard>("/api/dashboard"),
  runs: (limit = 50) => api.get<Run[]>(`/api/runs?limit=${limit}`),
  run: (id: string) => api.get<RunDetail>(`/api/runs/${id}`),
  createRun: (body: {
    repository_id: string;
    branch: string;
    commit_sha?: string;
    analysis_profile: string;
    execution_profile: string;
    max_runtime_seconds: number;
    authorisation_confirmed: boolean;
    root_directory?: string;
    install_command?: string;
    build_command?: string;
    start_command?: string;
    target_type?: string;
    framework?: string;
    port?: number;
    env_text?: string;
    env_vars?: Record<string, string>;
    benign_requests?: Record<string, unknown>[];
  }) => api.post<Run>("/api/runs", body),
  abortRun: (id: string, reason: string) =>
    api.post<Run>(`/api/runs/${id}/abort`, { reason }),

  findings: (runId: string) => api.get<Finding[]>(`/api/runs/${runId}/findings`),
  finding: (runId: string, handle: string, includePov = false) =>
    api.get<Finding>(
      `/api/runs/${runId}/findings/${handle}${includePov ? "?include_pov=true" : ""}`,
    ),
  hypotheses: (runId: string) => api.get<Hypothesis[]>(`/api/runs/${runId}/hypotheses`),
  clauses: (runId: string) => api.get<Clause[]>(`/api/runs/${runId}/clauses`),
  patches: (runId: string) => api.get<Patch[]>(`/api/runs/${runId}/patches`),
  gauntlet: (runId: string) => api.get<GauntletRun[]>(`/api/runs/${runId}/gauntlet`),
  certificates: (runId: string) => api.get<Certificate[]>(`/api/runs/${runId}/certificates`),
  certificate: (id: string) => api.get<Certificate>(`/api/certificates/${id}`),
  verifyCertificate: (id: string) =>
    api.get<Record<string, any>>(`/api/certificates/${id}/verify`),
  evidence: (runId: string, root?: string) =>
    api.get<EvidenceGraph>(
      `/api/runs/${runId}/evidence${root ? `?root=${encodeURIComponent(root)}` : ""}`,
    ),
  evidenceNode: (runId: string, ref: string) =>
    api.get<Record<string, any>>(`/api/runs/${runId}/evidence/${ref}`),
  artifact: (runId: string, name: string) => api.text(`/api/runs/${runId}/artifacts/${name}`),
  publish: (runId: string, certificateId: string, note = "") =>
    api.post<PublishResult>(`/api/runs/${runId}/publish`, {
      certificate_id: certificateId,
      confirm: true,
      note,
    }),

  audit: (limit = 100, offset = 0) =>
    api.get<{ items: AuditEvent[]; total: number; chain_head: string }>(
      `/api/audit?limit=${limit}&offset=${offset}`,
    ),
  verifyAudit: () => api.get<Record<string, any>>("/api/audit/verify"),

  // --- code intelligence ---------------------------------------------------
  runIndex: (runId: string) => api.get<Projection<IndexReport>>(`/api/runs/${runId}/index`),
  /** With no `uid`, statistics plus entrypoints. The whole graph is deliberately never returned. */
  runGraph: (runId: string, uid = "", depth = 2, limit = 120) =>
    api.get<Projection<GraphOverview> | Projection<GraphSubgraph>>(
      `/api/runs/${runId}/graph?depth=${depth}&limit=${limit}` +
        (uid ? `&uid=${encodeURIComponent(uid)}` : ""),
    ),
  runSecurity: (runId: string) =>
    api.get<Projection<SecurityModelView>>(`/api/runs/${runId}/security`),
  runArchitecture: (runId: string) =>
    api.get<Projection<ArchitectureView>>(`/api/runs/${runId}/architecture`),
  runTests: (runId: string) => api.get<TestsView>(`/api/runs/${runId}/tests`),
  runContexts: (runId: string) => api.get<ModelContextSummary[]>(`/api/runs/${runId}/contexts`),
  runContext: (runId: string, contextHash: string) =>
    api.get<ModelContextSummary>(`/api/runs/${runId}/contexts/${contextHash}`),
  engines: () => api.get<EngineInventory>("/api/system/engines"),
  gitnexusInfo: () => api.get<Record<string, any>>("/api/system/gitnexus"),

  frameworks: () => api.get<{ frameworks: Framework[] }>("/api/system/frameworks"),
  sandboxInfo: () => api.get<Record<string, any>>("/api/system/sandbox"),
  llmInfo: () => api.get<Record<string, any>>("/api/system/llm"),
  limits: () => api.get<SystemLimits>("/api/system/limits"),
  shieldInfo: () => api.get<Record<string, any>>("/api/system/shield"),
  ready: () => request<Record<string, any>>("/ready", { auth: false }),
};
