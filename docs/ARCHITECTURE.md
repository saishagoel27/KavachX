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
- Repository content reaches a model inside a labelled JSON payload, under keys physically
  prefixed `UNTRUSTED_`, with a system instruction stating it is untrusted data. Source is never
  concatenated into an instruction.
- **The only route from a model to the sandbox is a schema-validated `TestSpec`**, which a
  KavachX-authored generator turns into a harness. A model cannot supply code, a command, an
  interpreter, a path or a flag. See [TEST_SYNTHESIS.md](TEST_SYNTHESIS.md).
- **Every tool a model can reach is a read-only query.** There is no tool that writes a file, runs a
  command, applies a patch or changes a verdict. See [LLM.md](LLM.md).
- **Remove the model entirely and the pipeline still works.** `deterministic_specs()` derives
  executable, oracle-judged tests from a security flow with no model call at all — which is why this
  is not "LLM + grep + patch".

---

## Component map

The horizontal view of the same thing lives in [diagrams/architecture.mmd](diagrams/architecture.mmd)
and is rendered inline in the root [README](../README.md#architecture); exports for slides are in
[diagrams/](diagrams/README.md). The ASCII map below is the one that stays correct in a terminal.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ frontend/  Next.js 16 · App Router                                            │
│   landing · login · dashboard · runs · run console · certificate · audit      │
│   run console tabs: live · mission · index · graph · security · architecture  │
│                     tests · findings · samhita · patches · gauntlet · context │
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
│   17 nodes · 21 phases · checkpoint after every node · iteration ceilings      │
└──┬────────────────────────────────────────────────────────────────────────┬──┘
   │                                                                        │
   │  ┌──────────────────────────────────────────────────────────────────┐  │
   │  │ ── code intelligence ────────────────────────────────────────────│  │
   ├─▶│ indexing/       GitNexus + tree-sitter → one code knowledge graph │  │
   │  │                 index identity · health grade · claim bounds      │  │
   ├─▶│ security_model/ sources · sinks · sanitizers · taint · boundaries │  │
   ├─▶│ understanding/  application model · attack surface · tests ·      │  │
   │  │                 configuration · dependencies                      │  │
   │  │ ── reasoning ────────────────────────────────────────────────────│  │
   ├─▶│ llm/            24 read-only graph tools · bounded context ·      │  │
   │  │                 role routing · trust-labelled envelopes          │  │
   │  │ ── the pre-existing pipeline ────────────────────────────────────│  │
   ├─▶│ analysis/       tree-sitter index → world model (handles)         │  │
   ├─▶│ samhita/        observe → profile → propose → compile → falsify   │  │
   ├─▶│ discovery/      4 channels → one persistent priority queue        │  │
   ├─▶│ testing/        TestSpec → harness → sandbox → oracle · coverage  │  │
   ├─▶│ validator/      executable verification jobs, deterministic       │  │
   ├─▶│ shield/         reversible mitigation, verified blocked + benign  │  │
   ├─▶│ patching/       root cause → synthesis → policy gate → blast      │  │
   ├─▶│ gauntlet/       mutation · sibling · replay · contract re-check   │  │
   ├─▶│ pramaan/        evidence graph → assurance → signed certificate   │  │
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
│              repository_indexes · security_models · architecture_models       │
│              generated_tests · test_executions · model_contexts               │
└──────────────────────────────────────────────────────────────────────────────┘
```

The two boundaries that shape everything: **analysis executes untrusted code and must hold no
credential; publishing holds the only credential and must execute no code.** They are separate
processes' worth of separation even though they run in one service, and a test asserts the import
graph keeps them apart (`test_orchestrator_does_not_import_the_publisher`).

---

## The state machine

`app/orchestration/graph.py` compiles a thin LangGraph. Seventeen nodes, linear, with one guarded loop.

| Node | Phases emitted | What it does |
| --- | --- | --- |
| `ingest` | ingest | Materialises the repository into a workspace, hashes it, starts the sandbox. For a public target, fetches the codeload tarball **outside** the sandbox into a staging directory, safe-extracts it, then discards the staging copy. Never clones inside the sandbox. |
| `index` | index | Builds the code knowledge graph: GitNexus (resolved) + tree-sitter (name-matched), merged with per-edge provenance. Records a reproducible index identity. Runs against `work/`, never `pristine/`. |
| `index_validate` | index_validate | Ten deterministic checks → a health grade → **claim bounds**: what this index cannot support. Emits `INDEX_HEALTH.md`. |
| `security_model` | security_model | Sources, sinks, sanitizers, validators, auth controls, trust boundaries, and data flows with a stated basis and precision. |
| `understand` | understand | The structured application model and the ranked attack surface. Builds the read-only toolset and context builder every later stage uses. Emits `ARCHITECTURE.md`. |
| `index_repo` | probe, world_model | Confirmed target descriptor + world model. Runs *after* understanding, so the probe can use the graph's entrypoints. Decides `static_only`: without a confirmed entrypoint *and* a benign corpus there is nothing to execute, so the dynamic half of the pipeline is skipped rather than faked. |
| `contract_synthesis` | samhita | Observes the benign corpus, proposes clauses, compiles them, falsifies against held-out traces. |
| `discovery_fanout` | discovery, hypothesis_queue | Runs four channels concurrently, correlates candidates, persists the priority queue. |
| `test_synthesis` | test_synthesis | Ranked candidate → `TestSpec` → generated harness. Probes engine availability **inside the sandbox**. Stores every harness verbatim as an artifact. |
| `execute` | execute | Runs each harness in the sandbox, judged by a deterministic oracle, with independent reproductions. A non-firing fuzz/mutation plan escalates to a coverage-guided campaign. |
| `validate` | validation | Turns each hypothesis into an executable sandbox job; promotes only reproduced ones. |
| `shield` | shield | Synthesises and verifies a reversible mitigation. Records time-to-protection. |
| `root_cause` | root_cause, blast_radius | Locates and verifies the root cause; computes the regression scope. |
| `regression` | regression | Turns each validated finding's *actual reproducing input* into a durable regression test, plus a publishable test file in the target's own framework. |
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

**The code-intelligence stages still run in static-only mode.** Indexing, index validation, the
security model and the architecture/attack-surface model need no execution, so a static-only run
still produces a graded index, evidenced flows with stated basis and precision, and a ranked attack
surface. What it cannot produce is a *reproduction*: `test_synthesis` and `execute` emit **blocked**
with the reason, and no finding can reach `VALIDATED`. That is the distinction the mode exists to
preserve — a static-only run yields better-evidenced *leads*, not weaker findings.

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
  → INDEX: GitNexus + tree-sitter → one code graph, per-edge provenance
       index_id = sha256(source sha + indexer/parser versions + options)
  → INDEX VALIDATION: 10 checks → grade → claim bounds (what this index cannot support)
  → SECURITY MODEL: sources · sinks · sanitizers · controls · trust boundaries
       → data flows, each with basis (taint | call-graph | proximity) and
         precision (resolved | union)
  → UNDERSTAND: application model + attack surface
       priority = severity × controllability × reachability × dataflow × controls × coverage
  → world model + confirmed descriptor (how to drive the target)
  → SAMHITA (observe benign corpus → value profiles → clauses → falsify)
  → discovery candidate (graph/static, config, fuzzing, runtime)
  → TEST SYNTHESIS: candidate → TestSpec → generated harness (KavachX template)
  → EXECUTE: sandbox, independent reproductions, deterministic oracle, coverage
  → correlated hypothesis (priority = reachability × confidence × blast_radius;
       both graph-derived factors are unmeasurable without an entrypoint, so a
       static-only run ranks by severity × confidence — see HONESTY.md §8)
  → validator executes in the sandbox, twice, in independent processes
  → FINDING (deterministic signal + violated clause + reproduction record)
  → shield (verified blocked + benign)        ── TIME TO PROTECTION
  → root cause (verified on the executed path)
  → blast radius (callers, modules, clauses, allowed paths)
  → REGRESSION: the reproducing input preserved as a durable + publishable test
  → patch v1 → policy gate → applied to work/ copy
  → gauntlet: mutation · sibling · replay · contract
       fail → constraint → patch v2 → gauntlet …  (≤ 3)
  → VERIFIED patch                             ── TIME TO REPAIR
  → evidence graph → assurance grade → signed certificate
       (+ index identity, graph provenance, resolved ratio, flow basis/precision,
          harness hash, execution environment, coverage bound, and answers to
          the nine "how do you know?" questions)
  → CHANGES.md + REMAINING.md + INDEX_HEALTH.md + ARCHITECTURE.md
  → human approval → publisher → branch → commit → PR
```

Every arrow is a persisted state transition, and every transition emits an event.

---

## Two graphs, and why

The **code knowledge graph** (`app/indexing/`) is new: GitNexus's resolved relationships merged with
tree-sitter's name-matched ones, every edge tagged with the provider that produced it. It is what
answers reachability, and it answers at a *stated precision*.

The **world model** (`app/analysis/world_model.py`) is retained: it is the structure the static
channel, root-cause verification, blast radius and the sibling hunt already query, and replacing
those call sites wholesale would be a rewrite rather than an upgrade. Its `graph_source` now comes
from the real index job instead of from a check for a binary on `PATH` — see
[CODE_GRAPH.md](CODE_GRAPH.md) for the provenance bug that replaced.

Both hold handles, not content.

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

## The console

`frontend/` renders one page per concern and one tab per stage of evidence. The rule the whole UI
follows is the same one the backend follows: **an absence is rendered as a stated absence.** A panel
whose projection is unavailable says why — "this run predates the stage", "it failed before
reaching it" — rather than drawing an empty panel, because an empty panel reads as *the stage ran
and found nothing*, which is a much stronger claim than the run can support.

| Tab | Component | What it shows |
| --- | --- | --- |
| Live | `PipelineTimeline`, `ReasoningTrace`, `IntelligenceLiveStrip` | Phase timeline, structured thoughts, and the intelligence events as they arrive |
| Index | `IndexHealthPanel` | Index identity, provider provenance, counters, health grade, and **claim bounds** |
| Code Graph | `CodeGraphPanel` | Graph statistics, symbol search, and a bounded subgraph explorer |
| Security Model | `SecurityModelPanel` | Sources, sinks, sanitizers, controls, trust boundaries, and every flow with its basis and precision |
| Architecture | `ArchitecturePanel` | The application model, its `NOT KNOWN` section, and the ranked attack surface with per-item factor arithmetic |
| Tests | `TestSynthesisPanel` | Every generated plan (spec, engine, harness hash, `proposed_by`), every execution record, and the engine inventory |
| Model Context | `ModelContextPanel` | What each model context selected, what it used per section, what it **dropped**, and every graph query it made |

Four details in that surface are load-bearing rather than decorative:

- **Every flow shows `basis` and `precision` as chips, always together**, with the qualifying
  sentence on hover. A taint-proven path and a name-matched call chain are not the same claim, and
  the UI never lets one be mistaken for the other.
- **A graph edge is dashed when it is a name match** and solid when a symbol-resolving provider
  produced it. The subgraph layout is deterministic — concentric rings by distance from the centre
  node — so the same subgraph always draws identically. A force simulation would look better and
  settle somewhere slightly different every time, which is the wrong trade for a view whose whole
  point is that the underlying graph is reproducible.
- **An unavailable engine renders `NOT RUN`, never a pass.** `measured: false` on the attack surface
  renders `UNMEASURED`, never zero.
- **`model_candidates_useful` is shown against `model_candidates`** — the measured score for the
  model's contribution to a fuzzing campaign, rather than its own assessment of it.

`PIPELINE_PHASES` in `lib/events.ts` mirrors `Phase` in `app/models/enums.py`, whose member order is
`PHASE_ORDER`; `LEGACY_PIPELINE_PHASES` mirrors `LEGACY_PHASE_ORDER`. `phasesForRun()` picks between
them from the recorded `phase_status` keys, so a run from an older build shows the stages it actually
had instead of five stages stuck on "pending" — which would read as *these failed*.

---

## Database

29 tables. Every tenant-owned row carries `tenant_id`, duplicated onto child rows on purpose: it
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

---

## Further reading

| Document | Covers |
| --- | --- |
| [INDEXING.md](INDEXING.md) | The index stage, identity, reproducibility, health, incremental support |
| [CODE_GRAPH.md](CODE_GRAPH.md) | The two providers, why both are needed, the merge, GitNexus's licence |
| [SECURITY_MODEL.md](SECURITY_MODEL.md) | Taxonomy, taint analysis, flows, trust boundaries, attack surface |
| [TEST_SYNTHESIS.md](TEST_SYNTHESIS.md) | TestSpec, oracles, engines, harness generation, coverage-guided fuzzing |
| [LLM.md](LLM.md) | Providers, role routing, the graph toolset, context building, injection defence |
| [GAUNTLET.md](GAUNTLET.md) | The four refutation stages and how generated tests feed them |
| [PRAMAAN.md](PRAMAAN.md) | The evidence graph, assurance grading, what a certificate carries |
| [SAMHITA.md](SAMHITA.md) | Behavioural contracts, clause compilation, held-out falsification |
| [SECURITY.md](SECURITY.md) | The trust boundaries, credential handling, authority model |
| [DEMO.md](DEMO.md) | The annotated end-to-end walkthrough |
| [HONESTY.md](HONESTY.md) | **What is implemented, partial, experimental, mocked, or absent** |
