# Architecture

This document describes the full system design of KavachX.
Read this before touching any code.

---

## The inversion

Every other CRS is bug-first:
```
fuzz → crash → ask LLM for patch → re-run crash → done
```

KavachX is specification-first:
```
synthesise contract → direct fuzzer at contract clauses →
finding = clause violation → patch removes violation →
proof = all clauses still hold
```

The contract (SAMHITA) is the regression harness the target never shipped.

---

## Seven planes

The system operates across seven parallel planes simultaneously:

```
┌─────────────────────────────────────────────────────────────┐
│  1. Ingest & Auth      GitHub App · commit SHA · authority  │
│  2. Code Graph         GitNexus · tree-sitter · Semgrep     │
│  3. Contract           SAMHITA synthesis · clause falsifier  │
│  4. Discovery          4 parallel channels → hypothesis queue│
│  5. Validation         Sandbox exploit execution            │
│  6. Repair             Patch synthesis · Gauntlet           │
│  7. Evidence           PRAMAAN · certificate · publisher    │
└─────────────────────────────────────────────────────────────┘
```

---

## Full pipeline

```
ingest
  │  verify GitHub App installation
  │  resolve commit SHA
  │  fetch tarball (never git clone inside sandbox)
  ▼
index_repo
  │  GitNexus in sandbox → returns graph handles (not contents)
  │  tree-sitter AST
  │  Semgrep static pass
  ▼
contract_synthesis  [SAMHITA]
  │  observe target under benign workload
  │  record value profiles at every observable boundary
  │  LLM proposes candidate clauses (schema-constrained)
  │  deterministic falsifier deletes clauses that fail on held-out traces
  │  survivors = the contract (30–60 clauses typically)
  ▼
discovery_fanout  [4 parallel channels]
  ├── channel 1: graph/static  (code graph queries + Semgrep rules)
  ├── channel 2: config        (deployment graph, env, secrets)
  ├── channel 3: fuzz          (AFL++ directed at contract clauses)
  └── channel 4: constraint    (Z3 SMT — blocked branch reachability)
  │
  ▼
hypothesis_queue
  │  priority = reachability × confidence × blast_radius
  │  all unconfirmed hypotheses go to ledger (never discarded)
  ▼
validate
  │  build executable exploit in sandbox
  │  run in sandbox
  │  confirmed → correlate → attack_graph → prioritize
  │  unconfirmed → ledger
  ▼
patch_synthesis
  │  LLM proposes minimal unified diff at ROOT CAUSE (not crash site)
  │  policy gate checks diff before gauntlet
  ▼
blast_radius
  │  impact analysis → enumerate every caller of patched function
  │  those callers' clauses define regression scope
  ▼
gauntlet  [4 parallel stages]
  ├── mutation   : mutate the original exploit — does it still work?
  ├── sibling    : find structurally similar code paths
  ├── replay     : 5000 recorded benign requests — byte-identical?
  └── contract   : all SAMHITA clauses still hold?
  │
  ├── FAIL → refutation becomes a hard constraint → back to patch_synthesis
  │           (max 3 patch iterations, then record_honest_failure)
  └── PASS ▼
  │
attest  [PRAMAAN]
  │  build evidence graph
  │  sign certificate (level A / B / C / R)
  ▼
publish_gate
  │  RBAC check
  │  only level A or B certificates pass
  │  human approval by default (auto-publish opt-in per project)
  ▼
publisher
  │  compute file-overlap graph across all verified patches
  │  disjoint → parallel PRs
  │  overlapping → stacked PRs
  │  commit CHANGES.md + REMAINING.md + certificate.json
  └── open pull request
```

---

## Component map

### `core/`
- `state.py` — KavachState TypedDict definition
- `graph.py` — LangGraph graph definition, node wiring, routing functions
- `queue.py` — hypothesis work queue, priority scoring
- `checkpointer.py` — Postgres-backed LangGraph checkpointer

### `samhita/`
- `observer.py` — runs target under benign workload, records value profiles
- `proposer.py` — LLM call: clause proposal from boundary signatures
- `falsifier.py` — deterministic: deletes clauses that fail on held-out traces
- `evaluator.py` — evaluates a single clause against a trace
- `dsl.py` — clause DSL definition and parser

### `pramaan/`
- `graph.py` — evidence graph builder
- `certificate.py` — certificate generation, signing, level assignment
- `levels.py` — A/B/C/R level definitions and thresholds

### `sandbox/`
- `runner.py` — dispatches jobs to microVM, collects structured output
- `profiles.py` — analysis profile vs execution profile (quota definitions)
- `jobs.py` — job types: index, build, fuzz, exploit, replay
- `egress.py` — structured artifact serialisation channel

### `discovery/`
- `fanout.py` — spawns all 4 channels, merges into hypothesis queue
- `channels/graph_static.py` — GitNexus queries + Semgrep
- `channels/config.py` — deployment graph, env analysis
- `channels/fuzz.py` — AFL++ campaign management
- `channels/constraint.py` — Z3 SMT constraint solving

### `patch/`
- `synthesiser.py` — LLM call: root-cause patch authoring
- `policy_gate.py` — deterministic diff validation before gauntlet
- `gauntlet.py` — orchestrates 4 gauntlet stages
- `stages/mutation.py`
- `stages/sibling.py`
- `stages/replay.py`
- `stages/contract.py`

### `publisher/`
- `branch_layout.py` — file-overlap graph, parallel vs stacked PR decision
- `pr.py` — GitHub App PR creation
- `commit.py` — signed commit, structured trailer
- `documents.py` — CHANGES.md, REMAINING.md, certificate.json generation

### `api/`
- `app.py` — FastAPI application
- `routes/runs.py` — run lifecycle endpoints
- `routes/findings.py` — findings endpoints (with PoV gating)
- `routes/auth.py` — GitHub App auth, installation verification
- `sse.py` — Server-Sent Events stream
- `events.py` — RunEvent type definitions

### `db/`
- `models.py` — SQLAlchemy models
- `rls.py` — row-level security policy helpers
- `migrations/` — Alembic migrations

---

## Trust boundary (critical)

```
┌─────────────────────────────────┐
│  Orchestrator process           │
│  - holds GitHub App token       │
│  - holds DB credentials         │
│  - never executes untrusted code│
└──────────────┬──────────────────┘
               │ structured job dispatch
               │ structured artifact return
               ▼
┌─────────────────────────────────┐
│  Sandbox runner (microVM)       │
│  - holds ZERO secrets           │
│  - no network namespace         │
│  - read-only root filesystem    │
│  - one writable tmpfs scratch   │
│  - executes untrusted code      │
│  - output = diff + evidence     │
└─────────────────────────────────┘
```

The runner's only output channel is a structured artifact bundle.
It cannot reach the orchestrator's credentials under any circumstances.

---

## LLM authority boundary

The model is allowed to **propose**. It is never allowed to **decide**.

| Decision | Who decides |
|---|---|
| Did a crash occur? | Sanitizer + exit status |
| Does a contract clause hold? | Deterministic evaluator |
| Is a patch correct? | Differential replay + contract re-check |
| Deduplication | Stack hash + coverage signature |
| Severity and reachability | Code graph |
| Any measurement | Instrumentation |
| Anything in PRAMAAN | Deterministic evidence collection |

---

## State persistence

Every LangGraph node writes its output to Postgres before returning.
If the process dies, the next run resumes from the last completed node.
This is not optional — it is the architecture.

---

## Routing

All routing is deterministic. No LLM decides which node runs next.

```python
def route_after_gauntlet(state):
    if all(state["gauntlet"][k] == "pass"
           for k in ("mutation", "sibling", "replay", "contract")):
        return "attest"
    if state["patch_iter"] >= 3:
        return "record_honest_failure"
    return "patch_synthesis"
```

---

## Iteration caps (hard, never configurable at runtime)

| Cap | Value |
|---|---|
| Harness synthesis | 3 |
| Patch iterations | 3 |
| Clause refinement | 2 |

There is no unbounded loop anywhere in the system.

---

## Probe adapters

Three adapters for three target types:

| Adapter | Target type | PoC scope |
|---|---|---|
| A | Repository (source available) | PoC v0 — required |
| B | Bare binary (no source) | PoC v1 / finale |
| C | Network service (port only) | PoC v1 / finale |

For the PoC, only adapter A is required.
Adapters B and C are the highest-variance work — do not defer past 11 Sep.

---

## Certificate levels

| Level | Meaning |
|---|---|
| A | All 4 gauntlet stages pass · full replay · all clauses hold |
| B | 3 of 4 gauntlet stages pass · partial replay |
| C | Exploit validated · patch builds · limited verification |
| R | Patch refuted — shield remains deployed, honest failure recorded |

Only A and B certificates pass the publish gate.
Auto-publish is available only for level A.
