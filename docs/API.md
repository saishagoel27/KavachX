# API

KavachX exposes a FastAPI backend. The frontend (Next.js) consumes it.
Progress streams over Server-Sent Events — not WebSockets.

Raw model tokens are never streamed. Only structured RunEvents are sent.

---

## Auth flow

Access is granted through a GitHub App, not an OAuth personal token.

```
1. User installs KavachX GitHub App on their repository
2. GitHub redirects to /auth/github/callback with installation_id
3. KavachX verifies the installation via GitHub API
4. KavachX mints a session token (JWT, short-lived)
5. All subsequent requests carry the session token in Authorization header
6. For each GitHub operation, KavachX mints a short-lived installation
   token via GitHub App API — never persisted, never in sandbox
```

### Endpoints

```
GET  /auth/github/install          → redirect to GitHub App install page
GET  /auth/github/callback         → handle installation callback, mint session
POST /auth/logout                  → invalidate session
GET  /auth/me                      → current user + org memberships
```

---

## Runs

```
POST /runs
  Body: { "repo_url": str, "project_id": str }
  Auth: run:start permission
  Returns: { "run_id": str, "status": "started" }

GET  /runs/{run_id}
  Auth: finding:read permission
  Returns: full run summary (no exploit details)

GET  /runs/{run_id}/state
  Auth: maintainer or above
  Returns: full KavachState snapshot

POST /runs/{run_id}/abort
  Auth: run:abort permission
  Returns: { "status": "aborted" }

GET  /runs
  Auth: finding:read permission
  Query params: project_id, status, limit, offset
  Returns: paginated list of run summaries
```

---

## SSE stream

```
GET  /runs/{run_id}/stream
  Auth: finding:read permission
  Content-Type: text/event-stream
  Returns: stream of RunEvent objects (see below)
```

The stream stays open until the run completes or the client disconnects.
Each event is a JSON object on a single line, prefixed with `data: `.

---

## RunEvent types

```typescript
type RunEvent =
  | PhaseEvent
  | ThoughtEvent
  | ToolEvent
  | FindingEvent
  | DiffEvent
  | GauntletEvent
  | MetricEvent
  | ArtifactEvent
```

### PhaseEvent
```json
{
  "t": "phase",
  "phase": "contract_synthesis",
  "status": "start"
}
```
`status`: `"start"` | `"done"` | `"failed"`

### ThoughtEvent
```json
{
  "t": "thought",
  "agent": "samhita",
  "hypothesis": "content_length field may be unbounded",
  "evidence": ["profile:parse_header:content_length", "trace:t001"],
  "decision": "propose clause C017: len(content_length) <= 10",
  "confidence": 0.92
}
```
This is structured reasoning — not raw model tokens.

### ToolEvent
```json
{
  "t": "tool",
  "name": "sandbox:exploit",
  "target": "pov-44",
  "ms": 1240,
  "ok": true
}
```

### FindingEvent
```json
{
  "t": "finding",
  "id": "V17",
  "state": "validated",
  "clause": "C017",
  "severity": "high",
  "reachable": true
}
```
`state`: `"hypothesis"` | `"validated"` | `"refuted"`

### DiffEvent
```json
{
  "t": "diff",
  "finding": "V17",
  "file": "hdr.c",
  "patch": "--- a/hdr.c\n+++ b/hdr.c\n...",
  "iter": 2
}
```

### GauntletEvent
```json
{
  "t": "gauntlet",
  "finding": "V17",
  "stage": "mutation",
  "verdict": "fail",
  "detail": "bypass found: integer overflow at len=2147483648"
}
```
`verdict`: `"pass"` | `"fail"`
A `"fail"` verdict must render loudly in the UI.

### MetricEvent
```json
{
  "t": "metric",
  "tokens": 14200,
  "coverage": 0.43,
  "ram_mb": 3840,
  "egress": 0
}
```
`egress` is always 0. Always.

### ArtifactEvent
```json
{
  "t": "artifact",
  "kind": "certificate",
  "url": "/runs/run-7f3a/artifacts/cert-001"
}
```
`kind`: `"certificate"` | `"pr"` | `"docs"`

---

## Findings

```
GET  /runs/{run_id}/findings
  Auth: finding:read
  Returns: list of findings (no exploit details)

GET  /runs/{run_id}/findings/{finding_id}
  Auth: finding:read
  Returns: finding summary (no exploit details)

GET  /runs/{run_id}/findings/{finding_id}/pov
  Auth: finding:read_pov   ← separate permission, gated
  Returns: exploit details + PoV reference
  Note: exploit is redacted to hash + description for all other roles
```

---

## Patches

```
GET  /runs/{run_id}/patches
  Auth: patch:review
  Returns: list of patch attempts with gauntlet verdicts

POST /runs/{run_id}/patches/{patch_id}/publish
  Auth: patch:publish
  Body: { "approve": true }
  Returns: { "pr_url": str }
  Note: only level A or B certificates reach this endpoint
```

---

## Certificates

```
GET  /runs/{run_id}/certificates
  Auth: finding:read
  Returns: list of certificates (level, signed_at, finding_id)

GET  /runs/{run_id}/certificates/{cert_id}
  Auth: finding:read
  Returns: full certificate JSON including evidence graph

GET  /runs/{run_id}/certificates/{cert_id}/html
  Auth: finding:read
  Returns: rendered HTML view of certificate
```

---

## Artifacts

```
GET  /runs/{run_id}/artifacts/{artifact_name}
  Auth: finding:read (or finding:read_pov for exploit artifacts)
  Returns: artifact file download
```

---

## Projects

```
POST /projects
  Auth: owner
  Body: { "repo_url": str, "installation_id": int }
  Returns: { "project_id": str }

GET  /projects/{project_id}
  Auth: viewer or above
  Returns: project details

PATCH /projects/{project_id}
  Auth: policy:manage
  Body: { "auto_publish": bool }
  Returns: updated project

GET  /projects/{project_id}/runs
  Auth: viewer or above
  Returns: paginated run list
```

---

## Members

```
GET  /projects/{project_id}/members
  Auth: viewer or above
  Returns: member list (roles, not credentials)

POST /projects/{project_id}/members
  Auth: member:manage
  Body: { "user_id": str, "role": str }
  Returns: membership

DELETE /projects/{project_id}/members/{user_id}
  Auth: member:manage
```

---

## Audit log

```
GET  /projects/{project_id}/audit
  Auth: audit:read
  Query params: limit, offset, action, actor_id
  Returns: paginated audit events
```

---

## Error responses

All errors follow this shape:
```json
{
  "error": "permission_denied",
  "message": "finding:read_pov permission required to access exploit details",
  "request_id": "req-abc123"
}
```

Common error codes:
- `permission_denied` — wrong role
- `not_found` — resource doesn't exist or tenant can't see it
- `run_not_found` — run_id doesn't exist
- `invalid_state` — action not valid in current run state
- `rate_limited` — too many concurrent runs for tenant
- `schema_error` — request body failed validation

---

## Rate limiting

Per-tenant concurrency cap: configurable, default 2 concurrent runs.
Enforced at the `POST /runs` endpoint.
Returns `429` with `error: "rate_limited"` if exceeded.

---

## FastAPI app structure

```python
# api/app.py
from fastapi import FastAPI
from api.routes import runs, findings, patches, certificates, auth, projects, members, audit

app = FastAPI(title="KavachX API")

app.include_router(auth.router,         prefix="/auth")
app.include_router(runs.router,         prefix="/runs")
app.include_router(findings.router,     prefix="/runs/{run_id}/findings")
app.include_router(patches.router,      prefix="/runs/{run_id}/patches")
app.include_router(certificates.router, prefix="/runs/{run_id}/certificates")
app.include_router(projects.router,     prefix="/projects")
app.include_router(members.router,      prefix="/projects/{project_id}/members")
app.include_router(audit.router,        prefix="/projects/{project_id}/audit")
```
