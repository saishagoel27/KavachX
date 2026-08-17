# Architecture

## The one rule everything else follows from

```
LLM proposes  →  deterministic system validates  →  state machine decides
```

A model may propose interface hypotheses, SAMHITA clauses, root causes, patches and refutation
strategies. Only deterministic components decide whether a crash occurred, whether a clause holds,
whether an exploit reproduces, whether a patch passes, whether it stayed inside the blast radius,
what assurance level applies, and whether a pull request may be opened.

This is enforced structurally, not by convention:

- Every model call declares a strict Pydantic schema. A schema failure is a hard failure
  (`MODEL_CONTRACT_ERROR`), retried with a repair hint, and then abandoned — never trusted.
- **No response schema anywhere exposes a field a model could use to claim success.** There is no
  `verified`, `confirmed`, `exploitable`, `passes` or `assurance_level` field in
  `app/llm/contracts.py`, and a test asserts that (`test_no_model_contract_can_assert_verification`).
- Repository content reaches a model inside a labelled JSON payload under `payload`, with a system
  instruction stating it is untrusted data. Source is never concatenated into an instruction.

---

## Component map

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ frontend/  Next.js 15 · App Router                                            │
│   landing · login · dashboard · runs · run console · certificate · audit      │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │ Server-Sent Events (structured state transitions)
                                │ REST (JWT bearer, tenant baked into the token)
┌───────────────────────────────▼──────────────────────────────────────────────┐
│ backend/app/api/     request ids · structured errors · Prometheus · CORS      │
│ backend/app/auth/    JWT access+refresh · bcrypt · RBAC · membership recheck  │
│ backend/app/audit/   append-only hash-chained log                             │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────────────┐
│ backend/app/orchestration/   LangGraph state machine                          │
│   10 nodes · checkpoint after every node · hard iteration ceilings            │
└──┬────────────────────────────────────────────────────────────────────────┬──┘
   │                                                                        │
   │  ┌──────────────────────────────────────────────────────────────────┐  │
   ├─▶│ analysis/   tree-sitter index → world model (handles, not text)   │  │
   ├─▶│ samhita/    observe → profile → propose → compile → falsify       │  │
   ├─▶│ discovery/  4 channels → one persistent priority queue            │  │
   ├─▶│ validator/  executable verification jobs, deterministic signals   │  │
   ├─▶│ shield/     reversible mitigation, verified blocked + benign      │  │
   ├─▶│ patching/   root cause → synthesis → policy gate → blast radius   │  │
   ├─▶│ gauntlet/   mutation · sibling · replay · contract re-check       │  │
   ├─▶│ pramaan/    evidence graph → assurance grade → signed certificate │  │
   │  └──────────────────────────────────────────────────────────────────┘  │
   │                                                                        │
┌──▼────────────────────────────────────┐   ┌───────────────────────────────▼──┐
│ sandbox/   HOSTILE CODE EXECUTES HERE │   │ publisher/  THE ONLY CREDENTIAL  │
│   no credentials · no network         │   │   never executes repo code       │
│   non-root · capped · pinned source   │   │   re-runs the policy gate        │
│   dev | gVisor | Firecracker          │   │   new branch only, never force   │
└───────────────────────────────────────┘   └──────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────────────┐
│ PostgreSQL   runs · run_events · checkpoints · clauses · hypotheses           │
│              findings · shields · patches · gauntlet · evidence · audit       │
└──────────────────────────────────────────────────────────────────────────────┘
```

The two boundaries that shape everything: **analysis executes untrusted code and must hold no
credential; publishing holds the only credential and must execute no code.** They are separate
processes' worth of separation even though they run in one service, and a test asserts the import
graph keeps them apart (`test_orchestrator_does_not_import_the_publisher`).

---

## The state machine

`app/orchestration/graph.py` compiles a thin LangGraph. Ten nodes, linear, with one guarded loop.

| Node | Phases emitted | What it does |
| --- | --- | --- |
| `ingest` | ingest | Materialises the repository into a workspace, hashes it, starts the sandbox. For a public target, fetches the codeload tarball **outside** the sandbox into a staging directory, safe-extracts it, then discards the staging copy. Never clones inside the sandbox. |
| `index_repo` | index, probe, world_model | tree-sitter index → world model → confirmed target descriptor. Also decides `static_only`: without a confirmed entrypoint *and* a benign corpus there is nothing to execute, so the dynamic half of the pipeline is skipped rather than faked. |
| `contract_synthesis` | samhita | Observes the benign corpus, proposes clauses, compiles them, falsifies against held-out traces. |
| `discovery_fanout` | discovery, hypothesis_queue | Runs four channels concurrently, correlates candidates, persists the priority queue. |
| `validate` | validation | Turns each hypothesis into an executable sandbox job; promotes only reproduced ones. |
| `shield` | shield | Synthesises and verifies a reversible mitigation. Records time-to-protection. |
| `root_cause` | root_cause, blast_radius | Locates and verifies the root cause; computes the regression scope. |
| `patch_synthesis` | patch, gauntlet | The iteration loop: synthesise → policy gate → apply to a copy → four-stage gauntlet → refute or verify. |
| `attest` | pramaan | Builds the evidence graph, grades assurance, signs the certificate, writes CHANGES/REMAINING. |
| `publish_gate` | publish | Evaluates publishability; parks in `AWAITING_APPROVAL` when policy requires a human. Blocks outright when the target's provider is not in `PUBLISHABLE_PROVIDERS`. |

### Static-only degradation

The decision is made **once**, in `index_repo`, and never re-derived: `ctx.static_only` carries it to
the downstream nodes, and it is mirrored into state as `mode` plus `static_only_reason` so the
checkpoint and the console both show *why*. Each node then honours it explicitly —
`contract_synthesis` skips (no traces to falsify against), `discovery_fanout` runs only the two static
channels and records the other two as **omitted**, and `validate` promotes nothing, because a finding
cannot be `VALIDATED` without a reproduction. A blocked phase is emitted rather than a silent skip,
and `REMAINING.md` names each channel that did not run. This is the normal mode for an arbitrary
public repository; see [HONESTY.md](HONESTY.md) §8.

Several spec nodes are folded where splitting them would only add a state round-trip — the mapping
is documented in `NODE_SEQUENCE`. The patch↔gauntlet loop lives inside one node because its
iteration ceiling and constraint accumulation belong together.

**Every node is wrapped** so that state is checkpointed after it returns (including after a
failure, so the failed state is inspectable), an abort request short-circuits the rest, and an
unexpected exception is recorded in state rather than leaving a half-finished run row.

### Why state and context are separate objects

`KavachState` is a plain JSON-serialisable TypedDict — it is what LangGraph passes between nodes and
what gets checkpointed. `RunContext` holds the live resources (sandbox adapter, provider, world
model, emitter). Those cannot be serialised and must not be: a checkpoint carrying a live sandbox
handle would be a checkpoint you cannot resume.

### Bounded loops

```
harness ≤ 3    patch ≤ 3    clause ≤ 2
```

Enforced in the nodes, carried in state, and surfaced at `/api/system/limits`. There is no path to
an unbounded autonomous loop; `test_graph_node_sequence_is_finite_and_acyclic` asserts no node
repeats. Exceeding the token budget or the wall clock **aborts** the run rather than degrading it.

---

## Long work never blocks the graph

Fuzzing, builds, replay and every sandbox execution run as external processes, awaited on the event
loop through the sandbox adapter. `build_world_model` — CPU-bound and synchronous — runs in a thread.
The run itself is a background asyncio task, so `POST /api/runs` returns as soon as the row exists
and the console can attach to the stream immediately.

---

## Data flow for one finding

```
repository
  → pinned tree (sha256, computed outside the sandbox)
  → world model (files, functions, callers, entrypoints, sinks)
  → SAMHITA (observe benign corpus → value profiles → clauses → falsify)
  → discovery candidate (graph/static, config, fuzzing, runtime)
  → correlated hypothesis (priority = reachability × confidence × blast_radius;
       both graph-derived factors are unmeasurable without an entrypoint, so a
       static-only run ranks by severity × confidence — see HONESTY.md §8)
  → validator executes in the sandbox, twice, in independent processes
  → FINDING (deterministic signal + violated clause + reproduction record)
  → shield (verified blocked + benign)        ── TIME TO PROTECTION
  → root cause (verified on the executed path)
  → blast radius (callers, modules, clauses, allowed paths)
  → patch v1 → policy gate → applied to work/ copy
  → gauntlet: mutation · sibling · replay · contract
       fail → constraint → patch v2 → gauntlet …  (≤ 3)
  → VERIFIED patch                             ── TIME TO REPAIR
  → evidence graph → assurance grade → signed certificate
  → CHANGES.md + REMAINING.md
  → human approval → publisher → branch → commit → PR
```

Every arrow is a persisted state transition, and every transition emits an event.

---

## The world model holds handles, not content

A symbol handle is `path:qualname`. When the reasoning layer needs source it calls
`WorldModel.code_slice(handle)` for a bounded window. The repository is never poured into a prompt.

Two consequences worth naming: context cost stays flat as the target grows, and repository text can
never act as an instruction because it only ever arrives as labelled data.

`WorldModel` answers targeted questions — `reachable_from_entrypoint`, `transitive_callers`,
`blast_radius_score`, `neighbours_of`, `sinks_in`. Call-site resolution prefers same-file, then
same-module, then anywhere, and records ambiguity as multiple edges rather than guessing it away:
an over-approximated caller set makes reachability conservative, which is the safe direction.

---

## Events

The backend emits **structured state transitions**, never raw model tokens and never hidden
chain-of-thought. A `thought` event carries an application-composed summary plus evidence handles;
`ThoughtEvent` has exactly six fields and a test asserts no field for raw model text exists.

Ordering: a per-run asyncio lock assigns `seq` and writes the row *before* any subscriber sees it.
A client reconnecting with `Last-Event-ID: <seq>` replays from PostgreSQL and joins the live tail
with no gap and no duplicate. A stalled browser tab is dropped from live fan-out rather than growing
the backend heap; it recovers everything by reconnecting.

---

## Database

23 tables. Every tenant-owned row carries `tenant_id`, duplicated onto child rows on purpose: it
lets both the repository layer and PostgreSQL RLS filter without a join, so a forgotten join can
never leak across tenants.

`JSONType` is JSONB on PostgreSQL and JSON elsewhere; `UUIDType` is native `uuid` on PostgreSQL and
`CHAR(32)` on SQLite. That variance is why revision `0001_initial` creates the schema from
`Base.metadata` rather than hand-written DDL — see the migration's docstring for the reasoning.

No Redis, no vector database. The specification avoids a vector store deliberately: KavachX's
information is keyed and relational (run → finding → patch → evidence node), so PostgreSQL is the
right and only store.

---

## Observability

- `/health` — liveness
- `/ready` — database, provider, sandbox adapter and its honest capability flags, active runs
- `/metrics` — Prometheus: run duration, phase duration, model calls and tokens by task, schema
  violations, sandbox executions and egress, coverage, findings by state, patch iterations, gauntlet
  stage verdicts, certificate generation time, publish outcomes

Structured JSON logs through **logifyx**, with request-scoped `request_id`, `tenant_id`, `run_id` and
`user_id` injected automatically so one run traces end to end. Secrets are dropped by field name
before the record is created, on top of logifyx's own message masking.

logifyx is the **only** sink for the whole process, not just for code KavachX wrote. Libraries log to
their own stdlib loggers, so `configure_logging()` strips their handlers and installs a bridge on the
root logger that re-emits every record through the shared logifyx instance, preserving origin in
`component` (`component=uvicorn.error`, `component=sqlalchemy.engine.Engine`,
`component=alembic.runtime.migration`). Without it the process emitted two log streams in two formats,
and the half that was unstructured and unmasked was the half nobody was watching. `migrations/env.py`
deliberately does **not** call Alembic's default `fileConfig`, for the same reason. logifyx is a hard
dependency: if it cannot be imported, startup fails rather than quietly downgrading to
`logging.basicConfig` and producing unmasked output.

Exceptions carry `error_type`, `error` and a `traceback` field, rendered by the facade rather than
left to `exc_info` — logifyx's formatter ignores `exc_info`, so `logger.exception(...)` used to record
the event name and nothing about the failure. See [WINDOWS.md](WINDOWS.md) for what that cost.

`LOG_FORMAT` picks the presentation: `console` for logifyx's colour-coded human format (level-coloured
line, blue location), `json` for one JSON object per line. Left unset it follows `DEV_MODE` — colour
while developing, JSON in production. **The two are one switch, not two**: logifyx builds its console
handler with `get_formatter(json_mode, color)` and its file handler with `color=False`, so
`json_mode=True` selects the JSON formatter for *both* sinks and ignores `color` entirely. There is no
"JSON in the file, colour on the console" combination. In `console` format the structured fields are
still present, rendered into the message tail as `event | component=… key=value`, and `logs/kavachx.log`
never receives ANSI escapes either way.

---

## Where to look in the source

| Question | File |
| --- | --- |
| How is the schema whitelist enforced? | `app/samhita/compiler.py` |
| How does a clause get killed? | `app/samhita/falsifier.py` |
| Why is that metric a per-case delta? | `app/samhita/observation.py` |
| How is a finding proved? | `app/validator/service.py` |
| How is the bypass found? | `app/gauntlet/mutation.py` |
| What makes a patch illegal? | `app/patching/policy.py` |
| How is the level decided? | `app/pramaan/assurance.py` |
| Why was a certificate refused? | `app/pramaan/certificate.py` |
| What does the sandbox actually enforce? | `app/sandbox/base.py`, `dev.py`, `gvisor.py` |
| Where is the only GitHub credential? | `app/publisher/service.py` |
