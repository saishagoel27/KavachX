# KavachX

Graph-grounded autonomous cyber-reasoning with proof-carrying repair.

KavachX finds a vulnerability, shields the system in minutes, repairs the root cause,
attacks its own repair, and issues a signed certificate in which every claim drills down
to executable evidence.

---

## What it does

1. You submit a repository URL
2. KavachX indexes it, synthesises a behavioural contract (SAMHITA)
3. Discovers violations via 4 parallel channels
4. Validates each finding with an executable exploit (inside a hardened sandbox)
5. Deploys a reversible shield in minutes
6. Synthesises a root-cause patch
7. Attacks its own patch (Refutation Gauntlet — 4 stages)
8. Issues a signed PRAMAAN certificate with graded assurance
9. Opens a pull request with CHANGES.md, REMAINING.md, and certificate.json

---

## Repository layout

```
kavachx/
├── core/           # KavachState, LangGraph orchestration, work queue
├── samhita/        # Contract synthesis — propose, falsify, survivors
├── pramaan/        # Evidence graph, certificate generation (A/B/C/R)
├── sandbox/        # Sandbox runner, isolation profiles, job dispatch
├── discovery/      # 4 parallel discovery channels
├── patch/          # Patch synthesis, policy gate, gauntlet
├── publisher/      # Branch layout, PR creation, commit signing
├── api/            # FastAPI app, SSE event stream, auth
└── db/             # Postgres models, migrations, RLS policies

docs/
├── ARCHITECTURE.md         # Full system design and component map
├── STATE_MODEL.md          # KavachState fields and transitions
├── SAMHITA.md              # Contract synthesis pipeline
├── PRAMAAN.md              # Evidence graph and certificate levels
├── SANDBOX.md              # Isolation spec and profiles
├── LLM_CALLS.md            # All 6 LLM call types and deterministic gates
├── API.md                  # FastAPI endpoints and SSE events
├── DATABASE.md             # Postgres schema and RLS
└── IMPLEMENTATION_ORDER.md # Build order, P0 vs P1, team ownership
```

---

## Core principles

- **The LLM proposes. It never decides.** Every model call has a schema-validated
  output and a deterministic check that can reject it.
- **world stores handles, not contents.** Agents query the graph — they never load
  a repository into a context window.
- **State is checkpointed after every node.** A run that dies at hour three resumes,
  not restarts.
- **Isolation is live from ingest.** The sandbox is active before any build command runs.
- **Assurance is graded, never boolean.** Certificates are level A, B, C, or R.

---

## Tech stack

| Layer | Technology |
|---|---|
| Language | Python 3.11 |
| Orchestration | LangGraph (thin state machine) |
| API | FastAPI + SSE |
| Database | Postgres with row-level security |
| Sandbox | Firecracker / gVisor microVM |
| Code graph | GitNexus + tree-sitter |
| Static analysis | Semgrep |
| Fuzzing | AFL++ with QEMU mode |
| Sanitizers | ASan / UBSan |
| SMT solver | Z3 |
| LLM runtime | llama.cpp |
| Models | Qwen3-Coder-30B-A3B (workhorse) · Qwen3-4B (router) |
| Auth | GitHub App (fine-grained, short-lived tokens) |

---

## Models

| Role | Model | Size | Notes |
|---|---|---|---|
| Workhorse | Qwen3-Coder-30B-A3B | 18.6 GB | MoE — only ~3.3B active per token |
| Router | Qwen3-4B | ~3 GB | 90% of calls go here |
| Security triage | Foundation-Sec-8B-Reasoning | ~5 GB | Optional, cut first if memory is tight |

Ship two models, not three.

---

## Hard limits (never negotiable)

- Harness synthesis iterations: **≤ 3**
- Patch iterations: **≤ 3**
- Clause refinement iterations: **≤ 2**
- Network egress from sandbox: **zero**
- LLM decides anything in PRAMAAN: **never**

---

## Getting started

Two processes: a FastAPI backend on `:8000` and a Vite/React dashboard on `:5173`.

### 1. Backend

```bash
cd backend
cp .env.example .env          # already present; fill in the <...> values when you have them
uv sync                       # or: .venv/Scripts/python -m pip install -e .
uv run uvicorn app:app --reload --port 8000
```

Check it: `curl http://127.0.0.1:8000/health` · docs at http://127.0.0.1:8000/docs

### 2. Frontend

```bash
cd frontend
cp .env.example .env          # already present
npm install
npm run dev
```

Open http://localhost:5173 and press **Start Quest**.

### How the two connect

| Concern | Where it lives |
|---|---|
| API base URL | `frontend/.env` → `VITE_API_BASE_URL` (consumed only by `src/lib/api.ts`) |
| Allowed browser origins | `backend/.env` → `CORS_ALLOW_ORIGINS` |
| Live run trace | `GET /api/runs/{run_id}/stream` (SSE) → `EventSource` in `App.tsx` |
| Role / permissions | `backend/.env` → `AUTH_REQUIRED`; matrix in `kavachx/api/middleware/rbac.py` |

Both origins must agree: whatever host:port serves the frontend has to appear in
`CORS_ALLOW_ORIGINS`, or the browser blocks every call.

Alternative, CORS-free setup for local dev: set `VITE_API_BASE_URL=` (empty) in
`frontend/.env`. The app then calls same-origin `/api/...` paths and the Vite dev
server proxies them to `VITE_DEV_PROXY_TARGET`.

### Auth

`AUTH_REQUIRED=false` (the default) lets the dashboard pass a `role` parameter so
the RBAC matrix is demonstrable without a login — **local development only**.
Set it to `true` once the GitHub App flow (`/auth/github/install` →
`/auth/github/callback`) hands the frontend a session JWT; store it with
`setToken()` from `src/lib/api.ts` and every request will carry it.

> Component build order lives in `docs/IMPLEMENTATION_ORDER.md`.

---

## Docs

Read these in order before writing any code:

1. `docs/ARCHITECTURE.md`
2. `docs/STATE_MODEL.md`
3. `docs/IMPLEMENTATION_ORDER.md`
4. Then the component doc for whatever you are building

---

## Competition context

- **Event:** AI Kavach — Terrier Cyber Quest 2026
- **Finale:** 6–8 October 2026, New Delhi (36 hours)
- **Scoring:** Innovation 20% · Feasibility 20% · Illustration 20% · Technical Depth 20% · Presentation 20%
- **Constraint:** One laptop, ≤16 GB RAM, zero network egress, air-gapped
