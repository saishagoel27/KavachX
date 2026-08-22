# API reference

Base URL `http://localhost:8000`, prefix `/api`. Interactive docs at `/docs`, schema at
`/openapi.json`.

## Authentication

Bearer JWT. **The tenant is baked into the access token** (`tid` + `role`) — you cannot select an
organisation with a header. Switching organisations means re-minting a token through
`/api/auth/switch-org`, which re-checks membership. Membership is also re-verified from the database
on every request, so a revoked role takes effect immediately.

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"demo@kavachx.io","password":"kavachx-demo-2024"}' | jq -r .access_token)

curl -s http://localhost:8000/api/dashboard -H "Authorization: Bearer $TOKEN" | jq
```

## Errors

Every failure has the same shape:

```json
{
  "error": {
    "code": "REPOSITORY_NOT_AUTHORISED",
    "message": "KavachX has no verified authority over this repository.",
    "request_id": "c166820da607422a816ac72dca160caa",
    "details": { "required_permission": "run:start", "role": "VIEWER" }
  }
}
```

Branch on `code`, not on prose. `request_id` is also returned as the `X-Request-Id` header and
appears in every server-side log line for that request.

| Code | Status | Meaning |
| --- | --- | --- |
| `NOT_AUTHENTICATED` | 401 | No or unreadable token |
| `TOKEN_EXPIRED` / `TOKEN_INVALID` | 401 | Expired, wrong type, or revoked by a token-version bump |
| `PERMISSION_DENIED` | 403 | Role lacks the permission; `details.required_permission` names it |
| `EXPLOIT_ACCESS_DENIED` | 403 | `finding:read_pov` required — and the attempt is audited |
| `REPOSITORY_NOT_AUTHORISED` | 403 | No verified authority over the target |
| `TENANT_MISMATCH` | 403 | Cross-tenant access (usually reported as 404 instead) |
| `RUN_NOT_FOUND` / `FINDING_NOT_FOUND` / `CERTIFICATE_NOT_FOUND` | 404 | Missing, **or in another tenant** |
| `RUN_NOT_ABORTABLE` | 409 | Only a queued or running run can be aborted |
| `VALIDATION_ERROR` | 422 | Payload failed validation; `details.errors` lists the fields |
| `ASSURANCE_LEVEL_R` | 422 | Refuted patch — never publishable |
| `POLICY_VIOLATION` / `PUBLISH_BLOCKED` | 422 | The deterministic gate rejected it |
| `PROVIDER_NOT_PUBLISHABLE` | 422 | The target was attached as a public repository, which is analysis-only |
| `PATCH_CONTENT_MISSING` | 422 | Stored patch has no file contents; publishing refuses rather than rebuild files from a diff |
| `REPOSITORY_NOT_PUBLIC` | 403 | The named repository is private or does not exist |
| `REPOSITORY_REFERENCE_INVALID` | 400 | The pasted reference is not a recognisable `owner/repo` |
| `REVISION_NOT_FOUND` | 400 | Branch, tag or commit could not be resolved (GitHub 404 **or** 422) |
| `REPOSITORY_TOO_LARGE` | 413 | Archive exceeded the download or extraction size cap, or the member-count cap |
| `REPOSITORY_ARCHIVE_MALFORMED` | 502 | The archive was truncated or unreadable mid-extraction |
| `GITHUB_RATE_LIMITED` | 502 | The anonymous GitHub API limit (60/hour/IP) was hit |
| `BUDGET_EXCEEDED` | 429 | Run exceeded its token budget |
| `SANDBOX_UNAVAILABLE` / `MODEL_UNAVAILABLE` | 503 | Adapter or provider unreachable |
| `MODEL_CONTRACT_ERROR` | 502 | Model output failed strict schema validation |

A cross-tenant id returns **404, not 403** — a 403 would confirm the id exists.

---

## Auth

| Method | Path | Notes |
| --- | --- | --- |
| `POST` | `/api/auth/register` | Creates a user, an organisation, an OWNER membership and the default policy |
| `POST` | `/api/auth/login` | Returns an access/refresh pair scoped to the first membership |
| `POST` | `/api/auth/refresh` | Re-checks membership before re-issuing |
| `POST` | `/api/auth/switch-org` | Re-mints a token for another organisation you belong to |
| `GET` | `/api/auth/me` | User, memberships, active organisation, role, **resolved permissions** |
| `POST` | `/api/auth/logout` | Audited |
| `GET` | `/api/auth/config` | Non-secret facts the sign-in screen needs |
| `GET`/`POST` | `/api/auth/organisations` | List / create |

## Workspace

| Method | Path | Permission |
| --- | --- | --- |
| `GET` `POST` | `/api/projects` | `project:manage` to create |
| `GET` | `/api/projects/{id}` | member |
| `POST` | `/api/projects/{id}/repositories` | `repository:manage` — verifies authority before attaching |
| `GET` | `/api/repositories` | member |
| `GET` | `/api/github/app` | GitHub token configuration status (auth method, dry-run) |
| `GET` | `/api/github/public/preview` | `repository:manage` — resolve a public repository before attaching |

Transient upstream failures on the public path are retried up to 3 times with backoff — GitHub has
been observed 504-ing `/repos/{owner}/{repo}` while every other endpoint on the same repository
answered normally. The retried set is `429, 500, 502, 503, 504`.

**429 is retried even though it is a 4xx.** It means "you are going too fast", not "you asked for the
wrong thing", and it carries `Retry-After` saying when to return; the header lengthens the wait but is
capped at 30s so a generous value cannot stall a run. A 403 (the hourly anonymous budget is spent),
404 or any other 4xx *is* an answer and is never retried — doing so would burn what remains of the
caller's budget and delay a message they need now.

Extracted sources are cached by commit SHA under `.kavachx/source-cache` (12 entries, LRU). A commit
SHA pins content immutably, so re-fetching it is pure waste — and repeated identical downloads are
what trip codeload's archive throttle in the first place. A cache hit performs no network I/O at all.
| `GET` `POST` `PATCH` | `/api/members`, `/api/members/{id}` | `member:manage`; the last OWNER cannot be demoted |
| `GET` | `/api/roles` | The full permission matrix |
| `GET` `PATCH` | `/api/policy` | `policy:manage` to change; every change is audited with before/after |

Attaching the seeded local target (`DEV_MODE` only):

```bash
curl -X POST "http://localhost:8000/api/projects/$PROJECT_ID/repositories" \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"full_name":"examples/vulnerable-demo","local_seeded":true,"default_branch":"main"}'
```

### Attaching a public GitHub repository

Two steps, because the operator should see what they are about to attach before it is attached.

**1. Preview.** `reference` accepts any form a human would paste — a browse URL, a `/tree/<branch>`
URL, a `.git` or `git@` clone string, or bare `owner/repo`:

```bash
curl -G "http://localhost:8000/api/github/public/preview" \
  -H "Authorization: Bearer $TOKEN" --data-urlencode "reference=pallets/itsdangerous"
```

```json
{
  "full_name": "pallets/itsdangerous",
  "default_branch": "main",
  "description": "Safely pass trusted data to untrusted environments and back.",
  "primary_language": "Python",
  "languages": { "Python": 104233 },
  "size_kb": 412,
  "stars": 2900,
  "archived": false,
  "fork": false,
  "license": "BSD-3-Clause",
  "html_url": "https://github.com/pallets/itsdangerous",
  "head_commit": {
    "sha": "a4a2d1a2b3…",
    "message": "…",
    "author": "…",
    "date": "2026-01-14T09:12:03Z",
    "html_url": "…"
  },
  "publishable": false,
  "notes": [
    "Analysis only — KavachX holds no credential for this repository and cannot publish to it.",
    "No entrypoint or benign corpus is configured, so the run will be STATIC-ONLY."
  ]
}
```

`languages` is GitHub's byte count per language, not a percentage — the console derives the mix from
it. `publishable` is always `false` on this route; it is returned rather than implied so the UI never
has to hardcode the rule.

A private or non-existent repository is refused here, not at run time. `REVISION_NOT_FOUND` covers
both GitHub's 404 and its 422 — the latter is what you get for a branch that does not exist, which is
why the default branch is never assumed to be `main`.

**2. Attach.** `authorisation_confirmed` is required, and `default_branch` should be left blank so
the resolved default is used:

```bash
curl -X POST "http://localhost:8000/api/projects/$PROJECT_ID/repositories" \
  -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"full_name":"pallets/itsdangerous","public":true,"authorisation_confirmed":true}'
```

The row is stored with `provider: "github_public"` and `authority_evidence.publishable: false`. The
HEAD commit is pinned at attach time and recorded in the audit log.

---

## Runs

### `POST /api/runs` → 202

Requires `run:start`, verified authority, and `authorisation_confirmed: true`. Returns as soon as the
row exists; the pipeline runs in the background.

```json
{
  "repository_id": "…",
  "branch": "main",
  "commit_sha": "",
  "analysis_profile": "quick | standard | deep",
  "execution_profile": "dev_local | gvisor | firecracker",
  "max_runtime_seconds": 1800,
  "authorisation_confirmed": true
}
```

`commit_sha` may be blank — the run is then pinned by content hash instead.

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/runs?project_id&status&limit` | List |
| `GET` | `/api/runs/{id}` | Detail: phase map, metrics, certificates, shields, clause summary, world model, sandbox capabilities, artifacts |

Every run payload — list and detail alike — carries `mode` (`"full"` or `"static_only"`) and
`static_only_reason`. **Read the counts through it.** A static-only run executed nothing, so
`findings_validated: 0` and `coverage_percent: 0` mean "nothing was proved", not "nothing is wrong".
The console renders a banner on the detail page and a `STATIC ONLY` chip plus `NOT MEASURED` in place
of the coverage bar in the list, for exactly that reason.
| `POST` | `/api/runs/{id}/abort` | `run:abort`; cooperative, then cancels if the graph does not stop between nodes |
| `GET` | `/api/runs/{id}/checkpoints` | One per node, with a state hash |
| `GET` | `/api/runs/{id}/artifacts` | List |
| `GET` | `/api/runs/{id}/artifacts/{name}` | Raw content; `X-Content-Sha256` header |
| `GET` | `/api/dashboard` | Tenant-wide aggregates, all derived from run state |

---

## Server-Sent Events

```http
GET /api/runs/{run_id}/events
Accept: text/event-stream
```

`EventSource` cannot set headers, so a token may be passed as `?token=…`. It is validated
identically — same signature check, same membership re-check.

Resumption: send `Last-Event-ID: <seq>` (or `?lastEventId=<seq>`). Events are persisted in
PostgreSQL, so the stream replays the tail and then joins live with no gap and no duplicate. A page
refresh loses nothing.

### SSE event names

| Name | Meaning |
| --- | --- |
| `hello` | Connection opened; echoes the replay point |
| `message` | An enveloped run event (see below); carries `id: <seq>` |
| `heartbeat` | Every 15s with the current run status, so proxies keep the connection open |
| `end` | Run reached a terminal state; the stream closes |

### Envelope

```json
{ "seq": 42, "run_id": "…", "ts": "2026-08-17T15:32:31+00:00", "event": { "t": "phase", … } }
```

### Event union

| `t` | Fields |
| --- | --- |
| `phase` | `phase`, `status` (`start`/`done`/`failed`/`blocked`), `detail` |
| `thought` | `agent`, `hypothesis`, `evidence[]`, `decision`, `confidence` |
| `tool` | `name`, `target`, `ms`, `ok`, `detail` |
| `finding` | `id`, `state`, `clause?`, `severity`, `reachable`, `title` |
| `clause` | `clause_id`, `status`, `description`, `scope`, `kind` |
| `shield` | `finding`, `shield_id`, `mechanism`, `verified_blocked`, `verified_benign`, `deployed`, `rule` |
| `diff` | `finding`, `file`, `patch`, `iter`, `patch_id` |
| `gauntlet` | `finding`, `stage`, `verdict` (`pass`/`fail`/`running`), `detail`, `iter` |
| `metric` | `tokens`, `coverage`, `ram_mb`, `egress`, `model_calls`, `sandbox_executions`, `cpu_seconds`, `elapsed_ms` |
| `certificate` | `finding`, `level`, `certificate_hash`, `certificate_id` |
| `artifact` | `kind`, `url`, `name`, `hash` |
| `status` | `status`, `detail` |
| `log` | `stream` (`stdout`/`stderr`/`system`), `line`, `source` |

A `thought` event carries an **application-composed summary** plus evidence handles. There is no
field for raw model output or hidden deliberation, and a test asserts the schema has exactly six
fields.

`GET /api/runs/{id}/events/history?after_seq=&limit=` returns the same events over plain JSON, for
clients that would rather poll.

---

## Findings and evidence

| Method | Path | Permission |
| --- | --- | --- |
| `GET` | `/api/runs/{id}/findings` | `finding:read` — **never** returns exploit material |
| `GET` | `/api/runs/{id}/findings/{handle}?include_pov=` | `finding:read`; `include_pov=true` also needs `finding:read_pov` and is audited either way |
| `GET` | `/api/runs/{id}/hypotheses` | `finding:read` — includes the unknown ledger with reasons |
| `GET` | `/api/runs/{id}/clauses?status=` | `finding:read` |
| `GET` | `/api/runs/{id}/shields` | `finding:read` |
| `GET` | `/api/runs/{id}/patches` | `patch:read` |
| `GET` | `/api/runs/{id}/gauntlet` | `patch:read` — four stages per iteration with refuting evidence |
| `POST` | `/api/runs/{id}/patches/{patch_id}/review` | `patch:review` — records the review decision |
| `GET` | `/api/runs/{id}/evidence?root=` | `finding:read` — the graph, optionally one subgraph |
| `GET` | `/api/runs/{id}/evidence/{ref}` | `finding:read` — one node with full provenance |

`pov_access` is `granted` or `withheld` on every finding response, so a client never has to guess
whether it is looking at redacted data.

---

## Certificates

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/runs/{id}/certificate` | The run's highest-assurance certificate |
| `GET` | `/api/runs/{id}/certificates` | All of them, including Level R |
| `GET` | `/api/certificates/{id}` | Full signed document |
| `GET` | `/api/certificates/{id}/download` | `certificate.json` as an attachment; `X-Certificate-Hash` header |
| `GET` | `/api/certificates/{id}/verify` | Recomputes hash and HMAC from the stored document |

### `POST /api/runs/{id}/publish`

The **only** route to the Publisher, and therefore the only route to a GitHub credential. Requires
`patch:publish`, `confirm: true`, and a certificate above Level R.

```json
{ "certificate_id": "…", "confirm": true, "note": "reviewed by …" }
```

With `PUBLISHER_DRY_RUN=true` (the default) nothing is sent to GitHub and the response carries
`dry_run_payload` — byte-for-byte what would have been pushed, plus the publisher's guarantees.

The route also re-checks the repository's provider against `PUBLISHABLE_PROVIDERS` and returns
`PROVIDER_NOT_PUBLISHABLE` for a public repository — the same check the orchestrator's publish gate
makes, duplicated deliberately so neither layer is the only thing standing between analysis and
somebody else's repository. The patch and certificate remain downloadable as run artifacts.

---

## Audit

| Method | Path | Permission |
| --- | --- | --- |
| `GET` | `/api/audit?action=&limit=&offset=` | `audit:read` — reading is itself audited |
| `GET` | `/api/audit/verify` | `audit:read` — recomputes the whole chain |

---

## System

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/health` | Liveness |
| `GET` | `/ready` | Database, provider, sandbox adapter and its honest capability flags, active runs |
| `GET` | `/metrics` | Prometheus |
| `GET` | `/api/system/sandbox` | Every adapter's readiness and **what it actually enforces** |
| `GET` | `/api/system/llm` | Provider reachability, configured models, the proposes/validates contract |
| `GET` | `/api/system/shield` | Which shield mechanisms are implemented versus architectural |
| `GET` | `/api/system/limits` | Iteration ceilings, sandbox limits, token budget |
| `GET` | `/api/system/config` | Redacted settings snapshot — every secret replaced |

`/api/system/sandbox` is worth calling before you trust a result. It reports
`suitable_for_untrusted_code` and `network_enforced` per adapter, and `honest_warning` when the
active adapter is not an isolation boundary.
