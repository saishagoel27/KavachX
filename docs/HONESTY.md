# What this PoC does and does not do

KavachX is built around the claim that automated security work should state its own bounds. That
obligation applies to KavachX itself. This document is the list.

Read it before treating a KavachX result as an assurance.

---

## 0. Status of every subsystem

The spec asks for this table explicitly. Definitions used below:

| Label | Meaning |
| --- | --- |
| **production-grade** | Deterministic, tested, no known gap that changes a verdict. |
| **implemented** | Complete and exercised end to end; PoC-scale, not hardened for hostile scale. |
| **partial** | Works for a named subset; the excluded cases are reported, never treated as clean. |
| **experimental** | Architecture in place, real but shallow; do not build a decision on it. |
| **mocked** | Deterministic stand-in for a component that would be intelligent in production. |
| **not implemented** | Refuses with a clear message. Never silently degrades. |

### Code intelligence

| Component | Status | Bound |
| --- | --- | --- |
| Repository pinning (content-addressed) | production-grade | — |
| Index identity / reproducibility | production-grade | Verified: identical `index_id` **and** `graph_hash` across separate workspaces. |
| Index health + claim bounds | production-grade | 10 deterministic checks; no model involved. |
| tree-sitter provider | implemented | Python, C, JavaScript/TypeScript only. Call resolution is **by name** — it over-approximates. |
| GitNexus provider | implemented | **Optional.** Absent ⇒ every relationship is a name match. Licence: PolyForm Noncommercial. |
| Provider merge + provenance | production-grade | `graph_source` is derived from actual contribution, never asserted. |
| Incremental change set + affected closure | implemented | Computed and recorded. The re-parse itself is **not yet skipped** — see §12. |
| Test discovery (11 frameworks) | partial | Test→symbol mapping is a **static name reference**, confidence 0.4, never marked resolved. Not measured coverage. |
| Configuration discovery | implemented | 14 roles, 8 setting classes. Line-pattern based. |
| Dependency discovery | implemented | 14 manifests, 8 lockfiles. **No vulnerability database** — see §14. |

### Security model

| Component | Status | Bound |
| --- | --- | --- |
| Taxonomy (extensible registry) | implemented | Defaults + operator JSON override. Coverage is as good as the rules present. |
| Taint analysis | partial | **Intra-procedural, Python only.** Other languages fall back to proximity. |
| Cross-function flow stitching | implemented | Establishes the *path*, not that the value derives from the source. Every flow says so. |
| Trust boundaries | implemented | Derived from (source kind, sink kind). |
| Attack surface ranking | production-grade | Deterministic; all six factors recorded per item. |
| Architecture model | implemented | Derived deterministically; LLM annotations marked and non-authoritative. |

### Testing

| Component | Status | Bound |
| --- | --- | --- |
| TestSpec schema + validation | production-grade | A model cannot supply code, a command, an interpreter or a path. |
| Oracles (13 kinds) | production-grade | Pure functions of an `ExecResult`. `UNSUPPORTED` ≠ `HELD`. |
| Harness generation (Python) | implemented | unit, regression, mutation, property, fuzz, differential. |
| Harness generation (C) | experimental | libFuzzer stub with an **assumed** `(const char*, size_t)` signature; a mismatch fails at compile/link time and is reported as an engine problem. |
| Harness generation (JavaScript) | experimental | fast-check / plain Node. Not exercised end to end in the demo. |
| Harness generation (Go) | not implemented | Draft generator needs a helper KavachX does not inject; reported `unimplemented` rather than run-and-fail. |
| Harness generation (Java, Rust) | not implemented | Registered so they are *reported*, not silently missing. |
| Sandbox execution of harnesses | implemented | Through the existing adapter, unchanged. Independent reproductions. |
| `kx-mutational` fuzz engine | implemented | Always available. Seeded, coverage-aware. |
| Atheris / libFuzzer / AFL++ / Hypothesis / fast-check | implemented, **not installed here** | Probed per run **inside the sandbox**. Absent ⇒ strategy reported **NOT RUN**. |
| Coverage-guided loop | implemented | Python only (reuses `kx_observe`). |
| Code-aware branch seeding | implemented | Python `if`/`while`/`assert`/ternary, literal comparisons and `len()`. |
| Regression tests | implemented | pytest, unittest, vitest. Other frameworks → no artifact, and the suite says so. |

### Reasoning

| Component | Status | Bound |
| --- | --- | --- |
| Provider abstraction | production-grade | mock / llama.cpp / Ollama / vLLM / OpenAI-compatible / Groq. |
| Role routing (small + strong) | implemented | Table-driven. All roles may point at one model. |
| Graph toolset (24 read-only tools) | implemented | Every call recorded. No tool can write, execute or decide. |
| Context builder + hard budget | production-grade | Drops are always reported. |
| Trust separation / injection defence | production-grade | Structural — see §16. |
| Model context inspection | implemented | Selection + tool log, never a raw prompt. |
| Mock proposer | **mocked** | Deterministic scripts for all 12 tasks. Genuine proposer, not intelligent. See §6. |
| Tool-calling loop (model drives tools itself) | not implemented | Context is assembled *for* the model. The toolset exists and is used by the builder; a model-driven loop is not wired. |

### Console

| Component | Status | Bound |
| --- | --- | --- |
| Event union (all 19 event types) | production-grade | Mirrors the backend discriminated union exactly. |
| Phase timeline (21 phases) | production-grade | `phasesForRun()` renders the legacy 15 for a run recorded before the intelligence stages, so missing stages are absent rather than shown stuck on "pending". |
| Index health panel | implemented | Renders the stored health report and claim bounds verbatim. |
| Code graph explorer | partial | The `/graph` projection returns entrypoints plus a **sample** of callables, not every node — so symbol search covers that sample, not the whole graph. Subgraphs around any node are exact. |
| Graph visualisation | implemented | Deterministic ring layout, no external library. Dashed edge = name match. Not a general-purpose graph editor. |
| Security model panel | implemented | Every flow shows `basis` and `precision`; `UNSUPPORTED`/unmeasured states are rendered as such. |
| Architecture + attack surface panel | implemented | Per-item factor arithmetic shown. `NOT KNOWN` is rendered as content, not an appendix. |
| Test synthesis panel | implemented | Unavailable engine ⇒ `NOT RUN`. `model_candidates_useful` shown against `model_candidates`. |
| Model context panel | implemented | Selection, budget, drops and the graph-query log. **Never a raw prompt** — see §16. |
| Live refresh of the intelligence tabs | not implemented | The six intelligence tabs fetch on mount. The Live tab updates from the event stream; the inspection tabs need a tab switch or a reload to pick up a change mid-run. |
| ESLint | not configured | No `eslint.config.js` exists, so `npm run lint` does nothing. `tsc --noEmit` (strict) and `next build` both pass and are the checks actually run. |

### Pipeline (pre-existing, unchanged unless noted)

| Component | Status |
| --- | --- |
| SAMHITA clause compiler + held-out falsification | production-grade |
| Deterministic validator | production-grade |
| Refutation Gauntlet (4 stages) | implemented |
| Blast radius + AST policy gate | implemented |
| PRAMAAN evidence graph + dangling-claim refusal | production-grade |
| Certificate signing | implemented (HMAC — see §4) |
| gVisor sandbox | implemented |
| Firecracker sandbox | **not implemented** — refuses with a preflight report |
| dev sandbox | implemented, **not an isolation boundary** — see §1 |
| Publisher | implemented, dry-run by default |

---

## 1. The execution boundary on a development host is not a boundary

**Claim in the architecture:** the sandbox executes hostile code behind gVisor or a Firecracker
microVM.

**What actually runs by default:** `SANDBOX_ADAPTER=dev`, a local subprocess adapter. It runs the
target as a child of the backend, on the host filesystem, as the host user.

| | dev adapter | gVisor adapter | Firecracker adapter |
| --- | --- | --- | --- |
| Credentials withheld | ✅ enforced (env allowlist, asserted per execution) | ✅ | ✅ |
| Wall-clock timeout | ✅ | ✅ | ✅ |
| Network denied | ⚠️ in-process only, Python targets | ✅ no interface exists | ✅ no interface exists |
| Filesystem isolation | ❌ | ✅ | ✅ |
| Non-root | ⚠️ same user as the backend | ✅ `nobody` | ✅ |
| Capabilities dropped | ❌ | ✅ | ✅ |
| seccomp | ❌ | ✅ | ✅ |
| Read-only root | ❌ | ✅ | ✅ |
| CPU / memory / PID caps | ⚠️ POSIX rlimits only, absent on Windows | ✅ cgroups | ✅ |
| **Safe for untrusted code** | **❌ no** | ✅ | ✅ |

The dev adapter reports `suitable_for_untrusted_code: false` and `network_enforced: false` everywhere
it surfaces — the console header, `/api/system/sandbox`, the run's resource meter, every certificate's
`execution_environment` block, and now **every generated-test execution record**. A reproduction
recorded under the dev adapter and one recorded under gVisor are not equally strong evidence, and the
certificate can tell them apart.

The **Firecracker adapter is not implemented.** It validates its prerequisites and refuses with a
clear message.

**Use gVisor for anything you do not already trust.**

---

## 2. Egress is measured for Python targets, structural for containers

`egress: 0 bytes` means different things per adapter:

- **gVisor / Firecracker** — no network interface, so egress is zero by construction.
- **dev adapter** — an injected `sitecustomize` guard replaces `socket.socket`,
  `create_connection`, the ssl wrapper and `http.client.connect` with functions that raise, and counts
  every attempt. A real, tested measurement, but it covers **Python** targets in the same interpreter
  only. A native binary spawned by the target could open a socket unseen.

**New caveat.** The prover harnesses drive the target as a **subprocess** (necessary — see
[TEST_SYNTHESIS.md](TEST_SYNTHESIS.md)), and the in-process guard does not extend into a child
process. Under the dev adapter, a generated mutation/fuzz harness therefore has *weaker* egress
measurement than the in-process observation path. Under gVisor this is moot: there is no interface.

**GitNexus runs on the host, outside the sandbox.** It is an indexer over an already-pinned tree, not
an execution of the target — but it is a third-party Node process reading target source. It gets a
reduced environment (the sandbox's forbidden-marker assertion is reused, so no credential can reach
it) and `GITNEXUS_LBUG_EXTENSION_INSTALL=load-only`, so it does not reach the network on its own
initiative. It is not sandboxed.

---

## 3. Assurance levels are not proof

Levels A/B/C/R are **bounded empirical assurance**. Every certificate says so in
`assurance.not_a_formal_proof`.

Level A means: the validated exploit no longer reproduces, every mutation attempted failed, the
benign corpus behaved identically, every in-scope clause still holds, and the coverage change was
bounded. It does **not** mean:

- the vulnerability class is absent from the codebase;
- no other input reaches the same weakness;
- code that did not execute is safe;
- a mutation nobody thought of would fail.

The single most important number qualifying any level is **coverage**. On the seeded demo it lands
around 39%. Roughly 60% of statements were never executed and therefore never dynamically verified.
That figure is in the certificate and in `REMAINING.md`.

**Now also qualifying every level: the index.** A certificate carries
`code_intelligence.index.resolved_relationship_ratio` and `index_health.claim_bounds`. On the demo
target with GitNexus that ratio is **0.59**; without it, **0.0**. A reachability claim built on a
0.0-resolved index is a claim built entirely on name matching, and the certificate says so rather
than leaving the reader to assume.

---

## 4. Certificate signing is an HMAC, not a public-key signature

Certificates are signed with HMAC-SHA256 under a per-deployment key (`CERTIFICATE_SIGNING_KEY`). This
detects tampering by anyone without the key. It is **not** independently verifiable by a third party,
because verification requires the same secret. The certificate says this in `signature.notes`.

A production system would want an asymmetric signature and a published verification key.

---

## 5. PostgreSQL row-level security is a second layer, and it is inert for the app's own connection

The primary tenant control is the application layer: the tenant comes from the signed access token,
every loader compares `row.tenant_id`, and a cross-tenant id returns 404 rather than 403. That is what
the tenant-isolation tests exercise, and it works. The new intelligence routes inherit it by depending
on the same `load_run`.

Migration `0002_rls` adds RLS policies keyed on a `kavachx.tenant_id` session variable, plus a
`kavachx_reader` role subject to them. But **the application connects as the table owner, and a table
owner is not subject to RLS unless `FORCE ROW LEVEL SECURITY` is set.** So for the application's own
connection, RLS is currently inert. It is live for any non-owner role.

The audit-log immutability trigger *does* apply to everyone.

---

## 6. The mock proposer is deterministic, and its recipes are scripted

With no `GROQ_API_KEY`, or with `LLM_PROVIDER=mock`, proposals come from
`app/llm/mock_provider.py`. Its output goes through the same strict schema validation, the same
harness generator, the same deterministic validators and the same state machine. It is a genuine
proposer. It is not intelligent.

Its patch recipes (`app/llm/recipes.py`) are hand-written transformations that fire on anchors in real
file content. They produce real diffs, applied to a real workspace copy, verified by real execution.
They also only work on shapes they were written for — for anything else, synthesis fails honestly and
the finding ends at Level R with "no repair synthesised". **That happens in the demo**: the third
finding (CWE-248 in `assets.py`) gets no recipe match and lands at Level R.

Its twelve task scripts now include the code-intelligence tasks, so the demo shows
`candidate → TestSpec → harness → sandbox → reproduction` offline. Those scripts derive every value
from the sink class and the assembled context — the same reasoning the deterministic fallback uses.
**The mock is not smarter than the system**; it stands in for the part that needs judgement.

**What that means for the demo:** the *refutation* is real, the *diffs* are real, the *harnesses* are
real, the *execution* is real, the *verification* is real. The *proposal* is scripted. A hosted or
self-hosted model replaces the proposal step and nothing else.

---

## 7. Discovery and testing coverage is uneven

| Channel / strategy | On the Python demo target | On a native target | On other languages |
| --- | --- | --- | --- |
| Graph / static | ✅ merged code graph + AST rules with taint | ⚠️ line-oriented C checks | ⚠️ tree-sitter where a grammar exists |
| Config / reachability | ✅ finds signals; most are not dynamically provable and land in the unknown ledger with a reason | ✅ same | ✅ same |
| Fuzzing | ✅ real seeded mutational campaign, coverage-guided | ❌ libFuzzer/AFL++ need clang; **reported NOT RUN** | ❌ engine unavailable ⇒ **NOT RUN** |
| Runtime | ✅ observation traces + guard counters | ❌ needs a compiler | ❌ needs a tracer |
| Taint analysis | ✅ intra-procedural | ❌ | ❌ proximity fallback only |
| Generated unit/regression | ✅ | ⚠️ assumed C signature | ⚠️ untested JS path |
| Property tests | ⚠️ needs Hypothesis in the sandbox image — **absent here** | ❌ | ❌ |

Every gap appears in `REMAINING.md` per run, generated from state. On this host, **7 of 13 engines
are unavailable and 3 unimplemented** — that is 7 strategies reported NOT RUN, and the run says which
and why.

---

## 8. On an arbitrary public repository, the run degrades to STATIC-ONLY — and says so

The full pipeline needs an **entrypoint** KavachX can invoke and a **benign workload corpus** to
observe. Without both, there is nothing to execute, so nothing to validate.

| Stage | STATIC-ONLY behaviour |
| --- | --- |
| Index / index validation / security model / understand | ✅ **run** — these need no execution |
| SAMHITA | skipped — clause falsification needs observed traces |
| Discovery | graph/static and config/reachability only; fuzzing and runtime **omitted, not "clean"** |
| Test synthesis | **blocked** — no harness generated, and the reason is recorded |
| Execute | **blocked** — nothing executed, so nothing is proved by reproduction |
| Validation | no execution, so **no finding can reach `VALIDATED`** |
| Patch / gauntlet | not reached |
| Publish | blocked on the provider, independently |

The console shows blocked phases, the run row carries `mode: "static_only"` with the reason, and
`REMAINING.md` records "NOT RUN … zero dynamic coverage". The output is a list of **candidates for
human review**.

**Priority is computed differently, because two of its three factors are unmeasurable.** With no
entrypoint the call graph returns its floor for *every* code finding, which does not merely add noise
— it inverts the ranking. Measured on `we45/Vulnerable-Flask-App`:

| Candidate | Priority (before) | Priority (now) |
| --- | --- | --- |
| CWE-89 SQL injection | 0.01 | 0.550 |
| CWE-1336 template injection | 0.01 | 0.550 |
| CWE-502 unsafe deserialisation | 0.01 | 0.550 |
| LOW "container may run as root" | 0.12 | 0.120 |

The attack surface makes the same substitution and flags it per item. `AttackSurface.measured` is
`False`, and `ReachabilityResult.measured` distinguishes "we looked and found nothing" from "we could
not look".

**Minified bundles are excluded from analysis** — still hashed as part of the pinned tree, named
individually in `index_summary.skipped_files`, and excluded from security classification too.

Pointing KavachX at a public repository and getting ten CRITICAL rows back is **ten static leads**.
Conversely a repository that returns **zero** has not been cleared.

---

## 9. Sibling hunt candidates are "unproved", not "cleared"

When a probe produces no effect, the candidate is recorded as **unproved**, not safe — the probe
drives the same entrypoint operation as the original exploit and may never have executed the
candidate's function. This is why the demo lands at Level B rather than Level A.

---

## 10. Root-cause analysis verifies location, not causality

A proposed root cause is rejected unless it lies in indexed project source **and** on the recorded
execution path. That rules out hallucinated locations. It does **not** prove the location is causally
responsible. On failure the analysis falls back to the deepest executed project frame and sets
`root_cause_verified: false`.

---

## 11. What the code-intelligence layer specifically does *not* establish

The layer added in this upgrade has its own limits, and they are the ones most likely to be
over-read.

- **A `call-graph` flow does not establish data flow.** It establishes that a call path exists
  between a function containing a source and a function containing a sink. Whether the value reaching
  the sink derives from that source was **not** proven — taint is not tracked across the call
  boundary. Every such flow carries that sentence in its `notes`.
- **A `proximity` flow establishes almost nothing.** Source and sink are co-located in one function
  in a language with no taint analyser. It is a lead.
- **`union` precision may include calls that cannot occur.** A name-matched edge is a guess.
- **A sanitizer on a path is not a clearance.** Whether it executed on a given input is a runtime
  question. It lowers confidence and never removes the flow.
- **`unreached_sinks` is not a safe list.** An unresolved call edge, a framework-dispatched handler,
  or a language without full call resolution all produce "not reached".
- **Test→symbol links are static name references**, not measured coverage.
- **The architecture model's `application_type` is a classification**, with its evidence recorded. It
  can be wrong; `type_evidence` shows why it decided.
- **LLM annotations on the architecture model cannot change a derived fact** and are marked
  `model_annotated`.
- **A firing oracle on a SQL, network, auth or crypto sink proves a crash or an observable effect,
  not exploitation** — the sandbox has no database and no network. The plan states this per finding.
- **`explains` in the certificate is a restatement of stored evidence**, not an independent
  argument. Where evidence is absent it says `NOT ESTABLISHED — <reason>`.

We do **not** claim "full repository understanding". The claim is: a reproducible index of stated
fidelity, a graph whose every edge names its provider, flows whose every claim names its basis and
precision, and a health report naming what the index cannot support.

---

## 12. Incremental indexing computes the closure but does not yet skip the re-parse

`compute_change_set()` and `affected_closure()` are implemented and verified (1 changed file → 7
changed symbols → 13 dependent symbols → 3 affected entrypoints). The index job records
`incremental`, `changed_files` and `affected_symbols`.

**But the current build still re-parses the whole tree each run.** The architecture supports reuse —
the index id is exactly the key a cache would use — and the wiring to skip work is not built. So the
*correctness* machinery is there and the *speed* benefit is not. Indexing the 26-file demo takes
13–22 s with GitNexus.

---

## 13. Generated harnesses are real code running in the sandbox

Worth stating plainly because it is the largest new capability and therefore the largest new risk
surface.

KavachX now writes Python (and, experimentally, C/JS) files into `_kavachx/tests/` inside the sandbox
workspace and executes them. Mitigations:

- **Templates are KavachX's.** No model-supplied string becomes code; spec values are inserted as
  data literals through `repr()`/`json.dumps` with a type guard.
- **The spec schema refuses** newlines, NULs, over-long payloads, `..` in a target, and statements in
  a property expression.
- **Property expressions are compiled by the SAMHITA restricted-AST whitelist** before generation —
  no calls, no attribute access, no subscripts, no builtins.
- **Execution uses the existing adapter with existing limits.** No new capability, no relaxed
  sandbox.
- **Every harness is stored verbatim as a run artifact** and hashed, so what executed is auditable.
  The e2e test compiles the stored artifact to prove it is valid source.

The residual risk is the honest one: a generated harness is code, and the dev adapter is not an
isolation boundary (§1).

---

## 14. Dependency information is not vulnerability intelligence

KavachX has **no vulnerability database**. It cannot know whether an installed version is affected by
any advisory, and it never claims to. `SENSITIVE_LIBRARIES` maps a package to a *sink class worth
looking for* — it raises the prior on a candidate found in code. It says "look here", never "this is
vulnerable". `DependencyModel.note` carries this text into every payload that includes it.

---

## 15. GitNexus is optional, and its licence is not KavachX's

**GitNexus is licensed PolyForm Noncommercial 1.0.0.** KavachX is not.

- A **non-commercial** deployment can install it and gets a resolved code graph.
- A **commercial** deployment must obtain a commercial licence from the GitNexus authors or run with
  `GITNEXUS_ENABLED=false` — in which case every relationship is a name match, the index grade is
  capped, and every certificate records `resolved_relationship_ratio: 0.0`.

Reported at runtime by `GET /api/system/gitnexus`. See [CODE_GRAPH.md](CODE_GRAPH.md).

GitNexus also writes to a **machine-global registry** at `~/.gitnexus/registry.json`. KavachX
registers a unique alias per index and deregisters on teardown, but a crashed run can leave a stale
row.

---

## 16. Prompt injection: what is and is not defended

**Assumed:** a repository may contain malicious comments, README instructions, fake security
notices, malicious test descriptions and embedded model instructions.

**Structurally defended:**

- repository text reaches a model only as a JSON **value** under an `UNTRUSTED_`-prefixed key, never
  concatenated into an instruction;
- the system prompt names the trust labels that physically exist in the payload;
- documentation is the smallest section, opt-in per task;
- earlier model output is kept in its own untrusted section, so a hallucination cannot be read back
  as established fact;
- **no model output can grant execution authority** — the only route to the sandbox is a
  schema-validated `TestSpec` turned into a harness by a KavachX template.

**Not defended:** a model can still be *persuaded to waste a run* — to propose a useless TestSpec, a
wrong root cause, or an irrelevant patch. Those cost sandbox time and then fail deterministically.
A successful injection cannot make KavachX run attacker-chosen code, mark a finding validated, or
publish a patch.

---

## 17. Other bounded areas

- **Shields**: only `input_filter` is implemented. seccomp and `LD_PRELOAD` shields are reported as
  `implemented: false` by `/api/system/shield`.
- **Publisher**: defaults to `PUBLISHER_DRY_RUN=true`. The live path is implemented but only
  exercisable with a fine-grained token that has push access. A public repository can never reach it.
- **Public repository ingestion** uses the unauthenticated REST API, subject to GitHub's 60
  requests/hour/IP anonymous limit.
- **Multiple patches, one PR**: one verified patch → one branch → one PR. Conflict-aware batching is
  not built.
- **Regression test artifacts are offered, not applied.** They are written under `_kavachx/`, not into
  the target's `tests/`, and the blast-radius policy still governs whether a test file counts as an
  in-scope change.
- **Checkpointing**: state is written after every node and is inspectable, but there is no *resume
  from checkpoint*.
- **Concurrency**: one process owns the event bus; DB-backed replay is the cross-process source of
  truth.
- **Symbols and relationships are not stored per-row.** The graph is one bounded JSON document plus
  counters — derivable from the pinned tree and the recorded versions. So you cannot SQL-query for
  "every function calling X" across runs.
- **`monaco-editor` is pinned to 0.53.0** to avoid a transitive DOMPurify advisory in 0.54.x.
- **One pre-existing test failure**: `test_local_target_outside_examples_rejected` expects 403 and
  gets 400. It fails identically at the commit before this upgrade — the route normalises
  `full_name` into `examples/` and then reports a missing directory, rather than rejecting the
  configured path. The test encodes behaviour the code no longer has.

---

## What is genuinely real

To be equally precise in the other direction — these are not simulated.

**Pre-existing, still true:**

- The seeded target's vulnerabilities are **reproduced by execution**, twice, in independent
  processes, and a finding is only `VALIDATED` on a deterministic signal.
- SAMHITA clauses are **compiled through a restricted-AST whitelist** and **falsified against
  held-out traces**.
- **Patch v1 is genuinely refuted.** In the verified run: `exploit_mutation 1/19 FAIL`, then patch v2
  passes `19/19`.
- Diffs are **generated by KavachX** and applied to a workspace copy.
- The policy gate's checks are **AST comparisons**, not text matching.
- Certificates are **refused** when the evidence graph has a dangling claim.
- The audit log is **hash-chained and verified** by recomputation.

**New in this upgrade, and verified:**

- The index is **reproducible**: identical `index_id` *and* `graph_hash` across separate workspaces.
- `graph_source` is **derived from actual provider contribution**. The end-to-end test asserts that
  every provider it names is listed as a contributor — a regression guard for the bug where any host
  with a `gitnexus` binary on `PATH` produced runs labelled `gitnexus+tree-sitter` without GitNexus
  ever being invoked.
- The merged graph is **measurably better than either provider**: 118 nodes / 168 edges from 87+99
  and 84+106, with **57 corroborated edges** and a 0.59 resolved ratio.
- Index health **bounds claims**, and every warning/failure records what it forbids.
- The security graph found the **real seeded CWE-78** as a `cli_arg → shell_exec` flow with its full
  path, and the CWE-502 false positive found during development (`json.loads` matching a
  `pickle.loads` rule) is fixed and cannot recur — dotted calls now require an exact match.
- **A generated harness reproduced the vulnerability**: `reproduced=True 2/2` in independent
  processes, proved by a marker that nothing in the target's own output can produce.
- **A post-validation regression test fires on the unpatched build** (1/1) and is emitted as a
  publishable pytest file in the repository's own convention.
- Context assembly is **bounded and honest**: 15,919 chars for the top flow, 28 recorded tool calls,
  and under a 3,000-char budget it drops 5 sections and **reports every one**.
- Certificates carry the index id, graph provenance, resolved ratio, flow basis and precision, the
  harness hash, the execution environment, the coverage bound, and answers to all eight §59
  questions.
- **226 tests pass** (1 pre-existing failure), including the four end-to-end tests and the
  static-only honesty test.
- There is **no `sleep()` anywhere in the pipeline** to make the UI look busy. Every event is a real
  state transition.

---

## Bugs found and fixed while building this

Listed because a document about honesty should show its working, and because several were found only
by *running* the thing rather than reading it.

| Bug | How it presented | Why it mattered |
| --- | --- | --- |
| False `gitnexus` provenance | Runs labelled `gitnexus+tree-sitter` with GitNexus never invoked | A false fidelity claim in every certificate |
| `json.loads` matched the `pickle.loads` rule | CWE-502 CRITICAL at 0.92 confidence on a safe JSON parse | The kind of false positive that makes a tool unusable |
| JSON literals in a Python harness | `if true:` → `NameError` at line 1 | A whole strategy silently "did not reproduce" |
| Raw NUL byte in `fuzzing.py` | `source code string cannot contain null bytes` | Took down the EXECUTE node at import |
| `pytest` probed in the wrong process | `No module named pytest` in the sandbox | Reported as "the oracle did not fire" — indistinguishable from clean |
| Harness called `main(request_dict)` | argparse rejected it, exit 2 | Every generated test reported no reproduction |
| Context shed the *largest* slice | Dropped the sink function under a tight budget | Removed the one slice the proposal needs |
| Severity ignored in flow ordering | MEDIUM traversal above CRITICAL injection | A reviewer reads top-down |
| Config over-counting | 3 config files reported as 15 | Inflated counters, noise for the reachability channel |
| Pre-validation regression spec | `HELD` against a live vulnerability | A regression guard that guards nothing |
| Regression spec rejected | Payload not a separable field | Lost the guard for a genuinely reproduced finding |
| Duplicate `plan_id` | `UNIQUE constraint failed` → run FAILED | Same test counted and executed twice |
| `dep:model` counted as a dependency | N+1 dependencies, including 1 with no manifest | — |
| Two different "files" numbers | Console and health report disagreed | — |
| `.name` as a sanitizer pattern | Matched every `foo.name` | Would have suppressed real flows |
| Windows `.cmd` shim | `WinError 193` | Looked like "GitNexus is broken" |
