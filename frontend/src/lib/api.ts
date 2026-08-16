/**
 * Single place where the frontend talks to the KavachX backend.
 *
 * Base URL comes from `VITE_API_BASE_URL` (see frontend/.env):
 *   - absolute (e.g. http://127.0.0.1:8000) → direct cross-origin calls,
 *     which is why the backend enables CORS for this origin.
 *   - empty string                          → same-origin relative paths,
 *     proxied to the backend by the vite dev server (no CORS involved).
 */

const RAW_BASE = (import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8000').trim();

/** Normalised API root — no trailing slash. May be '' for same-origin mode. */
export const API_BASE_URL = RAW_BASE.replace(/\/+$/, '');

const TOKEN_STORAGE_KEY = 'kavachx.session_token';

/** Session token, once the GitHub App login flow is wired up. */
export function getToken(): string | null {
  const fromEnv = import.meta.env.VITE_API_TOKEN;
  if (fromEnv) return fromEnv;
  try {
    return localStorage.getItem(TOKEN_STORAGE_KEY);
  } catch {
    return null;
  }
}

export function setToken(token: string | null): void {
  try {
    if (token) localStorage.setItem(TOKEN_STORAGE_KEY, token);
    else localStorage.removeItem(TOKEN_STORAGE_KEY);
  } catch {
    /* storage unavailable (private mode) — requests fall back to the role param */
  }
}

type QueryValue = string | number | boolean | undefined | null;

/** Build a full URL for an API path, e.g. apiUrl('/api/runs', { role }). */
export function apiUrl(path: string, query?: Record<string, QueryValue>): string {
  const base = `${API_BASE_URL}${path.startsWith('/') ? path : `/${path}`}`;
  if (!query) return base;

  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== null && value !== '') {
      params.append(key, String(value));
    }
  }
  const qs = params.toString();
  return qs ? `${base}?${qs}` : base;
}

export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

async function toApiError(res: Response): Promise<ApiError> {
  let message = `${res.status} ${res.statusText}`;
  try {
    const body = await res.json();
    const detail = body?.detail ?? body?.message ?? body?.error;
    if (typeof detail === 'string') message = detail;
    else if (detail && typeof detail === 'object') message = detail.message ?? message;
  } catch {
    /* non-JSON error body — keep the status line */
  }
  return new ApiError(message, res.status);
}

async function request<T>(path: string, init: RequestInit = {}, query?: Record<string, QueryValue>): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');

  const token = getToken();
  if (token) headers.set('Authorization', `Bearer ${token}`);

  const res = await fetch(apiUrl(path, query), { ...init, headers });
  if (!res.ok) throw await toApiError(res);
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

// ── Types shared with the backend (kavachx/api/routes/runs.py) ──────────────

export interface StartRunResponse {
  run_id: string;
  status: string;
  repo_url: string;
  channel: string;
}

export interface FindingDto {
  finding_id: string;
  title: string;
  description?: string;
  state: 'hypothesis' | 'validated' | 'refuted' | 'fixed';
  severity: string;
  reachable: boolean;
  clause?: string | null;
  component?: string | null;
  remediation_path?: string | null;
  pov_hash?: string;
  /** Present only for roles holding `finding:read_pov` — redacted otherwise. */
  pov_code?: string;
}

export interface CertificateDto {
  cert_id: string;
  certificate_level: string;
  run_id: string;
  repo_url: string;
  hash_chain_anchor: string;
  /** Unix seconds. */
  timestamp: number;
  signed_at: string;
  signature: string;
  claims: Array<{
    claim: string;
    evidence: { discovery: string; validation: string; exploit_sha256?: string };
  }>;
  gauntlet: Record<string, string>;
}

export interface AuditLogDto {
  log_id: number;
  /** Unix seconds. */
  timestamp: number;
  actor: string;
  action: string;
  subject: string;
  evidence_hash: string;
  prev_hash: string;
  run_id: string | null;
}

export interface PublishResponse {
  run_id: string;
  finding_id: string;
  pr_url: string;
  already_published: boolean;
}

// ── Endpoints ───────────────────────────────────────────────────────────────

export const api = {
  health: () => request<Record<string, unknown>>('/health'),

  startRun: (repoUrl: string, role: string) =>
    request<StartRunResponse>('/api/runs', {
      method: 'POST',
      body: JSON.stringify({ repo_url: repoUrl, role }),
    }),

  listFindings: (runId: string, role: string) =>
    request<FindingDto[]>(`/api/runs/${runId}/findings`, {}, { role }),

  getCertificate: (runId: string, role: string) =>
    request<CertificateDto>(`/api/runs/${runId}/certificate`, {}, { role }),

  getAudit: (role: string, runId?: string) =>
    request<AuditLogDto[]>('/api/audit', {}, { role, run_id: runId }),

  publish: (runId: string, findingId: string, role: string) =>
    request<PublishResponse>('/api/publish', {
      method: 'POST',
      body: JSON.stringify({ run_id: runId, finding_id: findingId, role }),
    }),

  abortRun: (runId: string, role: string) =>
    request<{ run_id: string; status: string }>(
      `/api/runs/${runId}/abort`,
      { method: 'POST' },
      { role },
    ),

  /** SSE endpoint — EventSource cannot send headers, so the role rides the query string. */
  streamUrl: (runId: string, role: string) => apiUrl(`/api/runs/${runId}/stream`, { role }),

  /** Download URL for CHANGES.md / REMAINING.md. */
  deliverableUrl: (runId: string, name: 'changes.md' | 'remaining.md', role: string) =>
    apiUrl(`/api/runs/${runId}/deliverables/${name}`, { role }),
};

export default api;
