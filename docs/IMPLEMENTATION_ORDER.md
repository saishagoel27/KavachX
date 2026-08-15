# Implementation Order

Read this before writing any code.

The build order is not arbitrary. Sandbox and auth come before analysis.
If you build the clever parts first and retrofit isolation later,
the retrofit never fully works.

---

## P0 — Must work before shortlisting (21 Aug – 10 Sep)

These 11 components must run end-to-end against one known-vulnerable target.
Slide 5 of the submission must carry a real certificate from a real run.

### Step 1 — Project scaffold

Set up the repo structure, dependencies, and dev environment first.
Nothing else can start without this.

```
kavachx/
├── core/
├── samhita/
├── pramaan/
├── sandbox/
├── discovery/
├── patch/
├── publisher/
├── api/
└── db/
```

Files to create:
- `pyproject.toml` — dependencies, Python 3.11
- `.env.example` — all required env vars documented
- `docker-compose.yml` — Postgres + gVisor for local dev
- `db/migrations/` — Alembic setup
- `core/state.py` — KavachState TypedDict (copy from STATE_MODEL.md)



---

### Step 2 — Database + auth

Build this before anything else that touches data or GitHub.

Files:
- `db/models.py` — all tables from DATABASE.md
- `db/migrations/0001_initial_schema.py`
- `db/migrations/0002_rls_policies.py`
- `api/routes/auth.py` — GitHub App install + callback + session
- `api/middleware/tenant.py` — sets `app.tenant_id` per request
- `api/middleware/rbac.py` — permission checks

Test: can you install the GitHub App, get a session, and create a project?



---

### Step 3 — Sandbox runner

Build this before any analysis. Isolation must be live from ingest.

Files:
- `sandbox/profiles.py` — ANALYSIS_PROFILE, EXECUTION_PROFILE
- `sandbox/jobs.py` — JobKind enum, job input/output schemas
- `sandbox/runner.py` — dispatch job to gVisor, collect artifact bundle
- `sandbox/egress.py` — artifact bundle serialisation

For local dev, use gVisor (`runsc`).
For the finale, switch to Firecracker.

Test 1: run a simple `echo hello` job in the sandbox and get the output.
Test 2: run `python -c "import os; os.system('curl google.com')"` and
confirm it fails — no network egress.


---

### Step 4 — Ingest

Files:
- `core/ingest.py` — verify GitHub App installation, resolve commit SHA,
  fetch tarball, store in artifact_store
- `api/routes/runs.py` — POST /runs endpoint

Test: submit a repo URL, get a run_id back, see the tarball stored.



---

### Step 5 — GitNexus indexing (in sandbox)

Files:
- `sandbox/jobs.py` — add INDEX job type
- `core/index_repo.py` — dispatch INDEX job, receive graph handles,
  store in state["world"]

This runs inside the sandbox (analysis profile).
The output is graph handles — never graph contents.

Test: index a small C repo, confirm graph handles are in state["world"].


---

### Step 6 — SAMHITA synthesis

Files:
- `samhita/dsl.py` — clause DSL definition
- `samhita/observer.py` — run target under benign corpus, record profiles
- `samhita/proposer.py` — LLM call 2 (clause proposal)
- `samhita/falsifier.py` — deterministic falsifier
- `samhita/evaluator.py` — clause evaluator

Test 1: run observer on a known target, get boundary profiles.
Test 2: propose clauses, run falsifier, confirm hallucinated clauses deleted.
Test 3: state["samhita"] has ≥ 5 surviving clauses.


---

### Step 7 — One discovery channel (graph/static)

Only one channel for P0. The other three come in P1.

Files:
- `discovery/channels/graph_static.py` — GitNexus queries + Semgrep
- `discovery/fanout.py` — single channel for now, expands in P1
- `core/hypothesis_queue.py` — priority queue, scoring

Test: run graph/static channel on a known-vulnerable target,
confirm at least one hypothesis is produced with a clause_id.


---

### Step 8 — Validator

Files:
- `core/validate.py` — build executable exploit in sandbox, run it,
  confirm crash + clause violation
- `sandbox/jobs.py` — add EXPLOIT job type

Test: take a known PoV, run it in sandbox, confirm sanitizer output
is captured and stored as an artifact.



---

### Step 9 — Patch synthesis + policy gate + gauntlet

Build replay and contract gauntlet stages first.
Mutation and sibling come in P1.

Files:
- `patch/synthesiser.py` — LLM calls 4 + 5 (root-cause + patch authoring)
- `patch/policy_gate.py` — deterministic diff validation
- `patch/gauntlet.py` — orchestrate stages
- `patch/stages/replay.py` — replay benign corpus post-patch
- `patch/stages/contract.py` — re-evaluate all SAMHITA clauses

Test: take a known vulnerable function, synthesise a patch,
run it through policy gate and the two gauntlet stages.



---

### Step 10 — PRAMAAN certificate

Files:
- `pramaan/graph.py` — evidence graph builder
- `pramaan/levels.py` — level assignment logic
- `pramaan/certificate.py` — certificate generation + signing

Test: after a successful gauntlet, generate a certificate.
Confirm level is assigned correctly. Confirm signature verifies.



---

### Step 11 — Publisher (single branch, single PR)

Files:
- `publisher/commit.py` — signed commit, structured trailer
- `publisher/pr.py` — GitHub App PR creation
- `publisher/documents.py` — CHANGES.md, REMAINING.md, certificate.json
- `publisher/branch_layout.py` — single branch for P0
- `core/publish_gate.py` — RBAC check, level A/B only

Test: after a level A certificate, open a PR on a test repo.
Confirm CHANGES.md, REMAINING.md, certificate.json are committed.



---

### Step 12 — SSE stream

Files:
- `api/sse.py` — SSE stream implementation
- `api/events.py` — RunEvent type definitions
- `core/event_bus.py` — internal event bus that nodes publish to

Test: start a run, connect to /runs/{run_id}/stream,
confirm PhaseEvents, ThoughtEvents, FindingEvents arrive in order.



---

### Step 13 — RBAC (3 roles for P0)

For P0, implement only: `owner`, `sec_reviewer`, `viewer`.
Full 6-role RBAC comes in P1.

Files:
- `api/middleware/rbac.py` — permission checks for the 3 P0 roles
- `db/migrations/0003_memberships.py`


---

## P1 — Before the finale (11 Sep – 1 Oct)

These are the highest-variance items. Do not defer past 11 Sep.

### Probe adapters B and C
- Adapter B: bare binary (no source) — QEMU mode AFL++, Frida instrumentation
- Adapter C: network service (port only) — network fuzzing, protocol inference

### Fuzz channel
- `discovery/channels/fuzz.py` — AFL++ campaign management
- `sandbox/jobs.py` — FUZZ job type
- Harness Foundry — synthesises the fuzzing driver (LLM call 1)

### Constraint channel
- `discovery/channels/constraint.py` — Z3 SMT solving
- LLM call 3 (constraint authoring)

### Config channel
- `discovery/channels/config.py` — deployment graph, env analysis

### Full gauntlet
- `patch/stages/mutation.py` — LLM call 6 + fuzzer
- `patch/stages/sibling.py` — structurally similar code path sweep

### Causal analyst
- Reverse execution integration (rr or plain-debugger watchpoint fallback)
- `core/causal.py`

### Shield synthesis
- `core/shield.py` — derive seccomp filter / input-filter from exploit + syscall trace
- Verify: exploit blocked + benign corpus passes

### Full 6-role RBAC
- Add `maintainer`, `developer`, `auditor` roles

### Conflict-aware branch layout
- `publisher/branch_layout.py` — file-overlap graph, parallel vs stacked PR

### Attack graph + correlation
- `core/correlate.py` — correlate validated findings
- `core/attack_graph.py` — build attack paths, priority ordering

---

## Offline bundle (2–5 Oct)

Before the finale, prepare:
- Model weights (Qwen3-Coder-30B-A3B + Qwen3-4B) — downloaded and verified
- Full Python wheelhouse for all target languages
- Pre-compiled AFL++ + QEMU mode
- Pre-compiled Semgrep
- gVisor or Firecracker images as archives
- Pinned dependency lockfile
- Dry-run on 3 targets you have never seen

Record the fallback demo video during this window.

---

## The 36-hour finale

Feature freeze at hour 18. Code freeze at hour 24. No exceptions.

| Hours | Task |
|---|---|
| 0–2 | Recon only. Write no code. Classify target. Freeze adapter choice. |
| 2–6 | Foundry on real target. Goal: any finding carried to a rendered certificate. End-to-end beats deep. |
| 6–12 | SAMHITA synthesis. Directed campaign. Shield on first violation. |
| 12–18 | Patch quality. All four gauntlet stages. Feature freeze at hour 18. |
| 18–24 | Long autonomous run. One person owns only reliability. Deck begins. |
| 24–30 | Code freeze. Package evidence. Build demo script. Record fallback video. |
| 30–36 | Rehearse three times on the clock. Sleep in rotation. |

**Roles:**
- Saish — Substrate (sandbox, probe, fuzz, ingest)
- Teammate 1 — Reasoning (SAMHITA, model calls, patching, gauntlet)
- Teammate 2 — Evidence and Delivery (PRAMAAN, metrics, reliability, demo)

The third role owns 40% of the finale score. Do not understaff it.

---

## What to measure in September (critical)

Take 20 real functions. Request clause proposals in strict JSON.
Measure schema adherence rate.

- Above 85% → proceed normally
- Below 85% → implement GBNF constrained decoding via llama.cpp

This is half a day of work. Discover the need in September, not at hour 6
of the finale.

---

## Definition of done for P0

> Paste a repository URL, watch the system reason in the SSE stream,
> receive a pull request carrying a certificate, CHANGES.md, and REMAINING.md.

That is the bar. Everything else is P1.
