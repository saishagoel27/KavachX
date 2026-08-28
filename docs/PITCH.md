# AI Kavach — 5-slide submission content

Speaker-ready copy for the five prescribed slides. Every number here is measured from this
repository, not estimated; the verification command is given alongside each block of claims so the
jury can reproduce them and so nothing drifts as the code changes.

The shortlisting criteria are **resource utilisation, novelty of idea, and how light-weight the
solution is** — so the deck leads with the architectural idea, and carries the footprint numbers on
every slide rather than hiding them in an appendix.

---

## Slide 1 — Introduction, Ideation & Brief Description

### Title

**KavachX — Graph-Grounded Autonomous Cyber Reasoning with Proof-Carrying Repair**

> An LLM that is never trusted, wrapped in a system that must prove everything.

### The problem

An autonomous vulnerability-finder is only useful to a defence operator if its output can be
*trusted without re-doing the work*. Current LLM-based tooling fails exactly there:

- It **hallucinates vulnerabilities** that do not exist, and reports them with high confidence.
- It **claims a fix works** without ever executing the exploit again.
- It reports **"no vulnerabilities found"** when in truth nothing was executed at all.
- It **cannot say how it knows** — there is no evidence trail behind any claim.
- It usually requires shipping source code **to a third-party cloud API**, which for Armed Forces
  infrastructure is disqualifying on its own.

A false "secure" verdict on a fielded system is worse than no scan, because it *stops* the human
review that would have caught the flaw.

### The idea

Invert where authority sits. **The LLM proposes. The deterministic system validates. The state
machine decides.**

The model is used for exactly what it is good at — reading unfamiliar code and proposing where to
look and what to try. It is given authority over **nothing**. It cannot decide whether a
vulnerability exists, whether an exploit reproduced, whether a test passed, whether a patch is safe,
whether a patch stayed inside its blast radius, or whether anything gets published. Each of those is
decided by a deterministic component that executes code in a sandbox and records what happened.

The result is a system whose output is **proof-carrying**: every finding ships with the input that
reproduced it, the environment it reproduced in, and a signed evidence graph that answers *how do
you know?* for each claim.

### Brief description of the solution

A closed autonomous loop over a target repository:

**Index** the code into a knowledge graph → **derive** sources, sinks and data flows over it →
**reason** over the ranked attack surface → **generate** security tests → **execute** them in an
isolated sandbox → **validate** deterministically → **repair** the root cause → **attack its own
patch** → **certify** with evidence, or refuse to certify.

The whole pipeline runs **air-gapped on one machine** against a local model. It also runs with **no
model at all** — degraded but real — because every stage has a deterministic fallback.

### Motivation

We built the honesty properties first and the capability second. The system is designed to be
**unable** to make a claim it cannot evidence: if dynamic analysis did not run, it reports
`STATIC-ONLY` rather than "clean"; if an oracle could not be evaluated it reports `UNSUPPORTED`,
which is deliberately not `HELD`; and the certificate generator **refuses to issue** when a claim has
no supporting evidence node.

---

## Slide 2 — Detailed Methodology

### Step-by-step

**1 · Pin and index.** The target is pinned to an immutable content SHA-256. Two providers index it:
**GitNexus** (resolved symbol references — precise but incomplete) and **tree-sitter** (name-matched
references — complete but imprecise). They are merged into one graph where **every edge carries the
provider that produced it**, so a query can demand `resolved` precision or accept `union`. The index
gets a reproducible identity: `sha256(source + parser versions + options)`.

**2 · Grade the index, and state its bounds.** Ten deterministic checks produce a grade A/B/C/F plus
**claim bounds** — the explicit list of what this index is *not good enough to support*. Those bounds
travel into every certificate the run issues. A 0%-resolved index cannot support a precise
reachability claim, and the run says so in writing.

**3 · Build the security model.** 60 extensible taxonomy rules classify sources, sinks, sanitizers,
validators and auth controls. AST taint analysis proves derivation within a function; call-graph
stitching establishes cross-function paths. **Every flow states its basis** — `taint` (derivation
proven), `call-graph` (path proven, derivation not), or `proximity` (co-located only) — so a weak
signal can never be read as a strong one.

**4 · Rank the attack surface.** Priority is the **product** of six recorded factors: severity,
external controllability, reachability, dataflow confidence, controls on the path, and coverage. A
product, not a sum, because these are conjunctive: a critical sink nothing can reach should rank low.
Every factor is stored, so a rank is never a bare number.

**5 · Ask the model — inside a cage.** The top candidate is turned into a bounded context assembled
through **24 read-only graph tools**, under a hard character budget, in a trust-labelled envelope
where repository text sits under an `UNTRUSTED_repository_code` key. The model returns a
schema-validated `TestSpec`. **No field in that schema can assert a verdict.** Rejected output falls
back to the deterministic path, which still produces a working test.

**6 · Generate the harness — never the model's code.** KavachX generates the harness from **its own
templates**. Model-supplied strings are inserted as **data literals**, never as executable code, so a
malicious or confused proposal cannot become a running program. Engine availability is probed
**inside the sandbox**, because that is the interpreter the harness will actually run in.

**7 · Execute and judge.** The harness runs in the sandbox — no credentials, no network, non-root,
dropped capabilities, read-only root, resource-capped. **13 deterministic oracles** judge the result,
and a finding is only `VALIDATED` when the oracle fires in **N independent processes**. Non-firing
fuzz plans escalate to a coverage-guided campaign with code-aware branch seeding, where an input is
"useful" only if **measured coverage actually moved**.

**8 · Preserve the proof.** The **actual reproducing input** becomes a durable regression test, and it
is verified to fire on the **unpatched** build first — a test that has never fired is not a guard.

**9 · Repair and then attack the repair.** Root cause is located and verified to be on the executed
path. The patch passes an AST policy gate and is applied to a **copy**. It then faces the
**Refutation Gauntlet**: exploit mutation, sibling hunt, differential replay, contract re-check. A
refutation becomes a hard constraint on the next iteration.

**10 · Certify, or refuse.** A PRAMAAN evidence graph is assembled, graded A/B/C/R by deterministic
rule, and HMAC-signed. It answers nine *how do you know?* questions, and any claim without a
supporting evidence node **blocks issuance**.

### Implementation strategy

Built and working today as a 17-node LangGraph state machine over 21 phases, checkpointed after every
node, with server-sent events carrying real state transitions to a live console — **no `sleep()`
anywhere in the demo path**. Every stage degrades explicitly rather than silently: a missing engine
is reported `NOT RUN`, a missing entrypoint switches the run to `STATIC-ONLY`.

---

## Slide 3 — Technology Stack / Flow Diagram

**Use `docs/diagrams/architecture-slide.png`** (horizontal, 3.5:1 — sits under a title with room for
the stack table). Editable source: `architecture.drawio` / `architecture-slide.mmd`.

### Colour contract to put in the slide legend

| Colour | Meaning |
| --- | --- |
| **Teal** | Deterministic. Same input, same output, no model. |
| **Purple** | The **only** model call — and it can only *propose*. |
| **Amber** | A gate. Every model output crosses one first. |
| **Red** | Isolation boundary. Untrusted code runs only here. |
| **Green** | Proof-carrying output + the sole credential holder. |

> The shape is the thesis: a purple box never reaches an outcome without passing an amber gate.

### Stack

| Layer | Technology |
| --- | --- |
| Orchestration | Python 3.13, LangGraph, FastAPI, SQLAlchemy 2 (async), Alembic |
| Code intelligence | GitNexus 1.6.9 (LadybugDB), tree-sitter (Python / C / JavaScript) |
| Static analysis | Custom AST taint analyser, Semgrep, 60-rule extensible taxonomy |
| Dynamic analysis | Custom seeded mutational fuzzer + coverage observer; Atheris, libFuzzer, AFL++, Hypothesis, fast-check supported |
| Isolation | gVisor / Firecracker / dev adapter; env allowlist asserted per execution |
| Models | **Qwen3-Coder-30B-A3B** (MoE, **3B active**) + **Qwen3-4B** router, via llama.cpp / Ollama / vLLM |
| Storage | PostgreSQL 16 (SQLite for single-box), 29 tables, hash-chained audit log |
| Console | Next.js 16, React 19, TypeScript (strict), Tailwind, SSE |

### Footprint — the light-weight argument

| Metric | Value |
| --- | --- |
| Runtime Python dependencies | **23** |
| External services required | **0** — no vector DB, no Redis, no message broker |
| Cloud API calls | **0** — fully air-gapped by default |
| Active model parameters | **3B** (30B MoE) — runs on one workstation GPU |
| Minimum viable run | **SQLite + mock proposer, no GPU, no network** |
| Backend / console | 47,140 / 32,158 lines |
| Tests | **315** (`uv run pytest`) |

The routing table is the resource story: cheap classification goes to the 4B router, and only
expensive reasoning — test synthesis, root cause, patch synthesis — reaches the 30B MoE. Most of the
pipeline is deterministic and consumes **no** model tokens at all.

---

## Slide 4 — Salient Features & Novelty

### The USP

> **KavachX cannot make a claim it cannot prove.** Its honesty properties are structural, not
> promised — they are enforced by schemas, oracles and a certificate generator that refuses to sign.

### Key features

1. **The authority boundary, enforced in code.** A test asserts that no field in any model-facing
   schema can express a verdict — no `verified`, no `reproduced`, no `safe`. The model cannot even
   *represent* the claim it is not allowed to make.

2. **Provenance on every graph edge.** Two indexers with opposite failure modes are merged, and every
   relationship records which produced it. Reachability is answered at a **stated precision**, so
   "reachable" and "reachable if this name match is real" are different answers.

3. **Claim bounds as a first-class output.** The index publishes what it is *not good enough to
   support*, and those bounds propagate into every certificate.

4. **`UNSUPPORTED` is not `HELD`.** An oracle that could not be evaluated never reports the security
   property as holding. "We could not look" and "we looked and found nothing" stay distinct
   everywhere, including in the reachability engine's `measured` flag.

5. **It attacks its own patch.** The Refutation Gauntlet's job is to *break* the fix. On the demo
   target it genuinely refutes patch v1 (`exploit_mutation 1/19 FAIL`) before v2 passes `19/19`.

6. **Regression tests built from the real exploit,** proven to fire on the unpatched build first.

7. **Structural prompt-injection defence.** Repository content is data, never instructions: it
   reaches the model only inside `UNTRUSTED_*` keys as JSON values, and no model output becomes
   executable code — harnesses come from KavachX templates with model strings as data literals.

8. **Air-gapped by construction.** No cloud dependency; the sandbox has no network interface and
   measured egress is 0 bytes. Source code never leaves the perimeter.

9. **Publisher isolation.** Exactly one component holds a write credential, it never executes
   repository code, and a test asserts the import graph keeps the two apart.

10. **Honest degradation.** No entrypoint → `STATIC-ONLY`, stated. No engine → `NOT RUN`, stated. No
    model → deterministic fallback, stated. **Never "clean".**

### Advantages over existing approaches

| | Typical LLM security tool | Classical SAST/DAST | **KavachX** |
| --- | --- | --- | --- |
| Finding is proven by execution | ✗ | partly | **✓ N independent reproductions** |
| Patch is adversarially attacked | ✗ | ✗ | **✓ 4-stage gauntlet** |
| Evidence trail per claim | ✗ | ✗ | **✓ signed evidence graph** |
| Distinguishes "unknown" from "safe" | ✗ | ✗ | **✓ structurally** |
| Runs air-gapped | ✗ | ✓ | **✓** |
| Works with no model at all | ✗ | ✓ | **✓ degraded but real** |

### Novelty in one line

Existing work treats the LLM as the reasoner and bolts verification on afterwards. **KavachX treats
verification as the architecture and the LLM as a replaceable proposal engine inside it.**

---

## Slide 5 — Final Deliverables

### Proof-of-concept — working today

`make demo` runs the full pipeline end to end on a seeded target with **no GPU, no network and no API
key** (SQLite + deterministic mock proposer). Verified trace:

| Stage | Measured result |
| --- | --- |
| Index reproducibility | Identical `index_id` **and** `graph_hash` across separate workspaces |
| Provider merge | 118 nodes, 168 edges, 59% resolved, `graph_source: gitnexus+tree-sitter` |
| Security model | 9 flows, each with stated basis and precision; CWE-78 ranked first |
| Test synthesis | Schema-validated `TestSpec` → generated harness, hash recorded |
| Execution | **`reproduced=True 2/2`** in independent processes, marker-proven |
| Regression | Fires on the unpatched build (`1/1`), publishable pytest artifact emitted |
| Refutation Gauntlet | **Patch v1 genuinely refuted** (`exploit_mutation 1/19 FAIL`) |
| Iteration | Patch v2 survives all four stages (`19/19`) |
| PRAMAAN | Certificates issued at Level **B / B / R** — and R is *never published* |
| Test suite | **315 tests** |

### Deliverables

1. **Working system** — backend, console, sandbox adapters, 65 API operations, migrations.
2. **Live console** — 14 tabs including Index Health, Code Graph explorer, Security Model, Attack
   Surface, Test Synthesis and Model Context inspection.
3. **Signed PRAMAAN certificates** plus `INDEX_HEALTH.md`, `ARCHITECTURE.md`, `CHANGES.md`,
   `REMAINING.md`, every generated harness, and every regression test as run artifacts.
4. **Air-gapped deployment path** — Docker Compose, local model server, zero egress.
5. **Documentation** — 16 documents including `HONESTY.md`, which states plainly what is and is not
   production-grade, with a table of the bugs our own end-to-end runs found.
6. **315-test suite** covering the authority boundary, the oracles, and the honesty invariants.

### Performance objectives for the Grand Finale

| Objective | Target |
| --- | --- |
| Precision | Zero unproven findings — a finding requires N independent reproductions |
| Speed | Time-to-protection (reversible shield) reported separately from time-to-repair |
| Functionality | Full loop on unfamiliar code, degrading explicitly where it cannot proceed |
| Scalability | Incremental re-index via change set + affected closure; per-run resource ceilings |
| Operational fit | Air-gapped, self-hosted, no third-party API, human approval before any write |

### What we will build in the 36 hours

- Extend taint analysis beyond Python and beyond intra-procedural.
- Wire the model-driven tool loop (the 24 tools exist; the model does not yet drive them itself).
- Skip the re-parse on incremental runs — the change set and affected closure are already computed.
- Harden C/Go/Rust harness generation from experimental to exercised.
- Tune against the provided simulated Armed Forces environment, and report honestly where it does
  not yet reach.

> **We would rather present a system that says "I could not determine this" than one that says
> "clean" without having looked.** For fielded defence infrastructure, that is the only useful
> posture.

---

## Appendix — verifying every number in this deck

```bash
# 315 tests
cd backend && uv run pytest -q

# nodes, phases, engines, taxonomy rules, graph tools, LLM tasks
cd backend && uv run python -c "
from app.orchestration.graph import NODE_SEQUENCE
from app.models.enums import PHASE_ORDER
from app.testing.engines import ENGINES
from app.security_model.taxonomy import default_taxonomy
from app.llm.graph_tools import GraphToolset
from app.llm.base import LLMTask
t = default_taxonomy()
print('nodes', len(NODE_SEQUENCE), 'phases', len(PHASE_ORDER))
print('engines', len(ENGINES), 'coverage-feedback', len([e for e in ENGINES if e.coverage_feedback]))
print('taxonomy rules', len(t.all_rules()))
print('tools', len([m for m in dir(GraphToolset) if m.startswith(('get_', 'search_'))]))
print('llm tasks', len([k for k in vars(LLMTask) if not k.startswith('_')]))
"

# 23 runtime dependencies, 0 external services
sed -n '/^dependencies = \[/,/^\]/p' backend/pyproject.toml | grep -c '^    "'

# 65 API operations across 60 distinct paths
grep -rhoE '@router\.(get|post|put|patch|delete)\(' backend/app/api/routes/*.py | wc -l

# 47,140 backend / 32,158 console lines
find backend/app -name '*.py' | xargs wc -l | tail -1

# the end-to-end proof itself
make demo
```

Expected output of the counts block:

```
nodes 17 phases 21
engines 13 coverage-feedback 6
taxonomy rules 60
tools 24
llm tasks 12
```
