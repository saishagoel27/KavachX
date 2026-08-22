# What this PoC does and does not do

KavachX is built around the claim that automated security work should state its own bounds. That
obligation applies to KavachX itself. This document is the list.

Read it before treating a KavachX result as an assurance.

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

The dev adapter reports `suitable_for_untrusted_code: false` and `network_enforced: false`
everywhere it surfaces — the console header, `/api/system/sandbox`, the run's resource meter, and
inside every certificate's `execution_environment` block. It is never dressed up as more than it
is.

The **Firecracker adapter is not implemented**. It validates its prerequisites and refuses with a
clear message. `preflight()` reports exactly what is missing. It does not silently fall back to
something weaker.

**Use gVisor for anything you do not already trust.** The dev adapter exists so the pipeline can be
developed and demonstrated on a Windows laptop against a target that ships in this repository.

---

## 2. Egress is measured for Python targets, structural for containers

`egress: 0 bytes` means different things per adapter:

- **gVisor / Firecracker** — the sandbox has no network interface, so egress is zero by
  construction. Nothing to trust.
- **dev adapter** — an injected `sitecustomize` guard replaces `socket.socket`,
  `create_connection`, the ssl wrapper and `http.client.connect` with functions that raise, and
  counts every attempt. This is a real, tested measurement (see
  `test_sandbox_python_target_cannot_open_a_socket`), but it only covers **Python** targets in the
  same interpreter. A native binary spawned by the target could open a socket and the guard would
  not see it.

---

## 3. Assurance levels are not proof

Levels A/B/C/R are **bounded empirical assurance**. Every certificate says so in
`assurance.not_a_formal_proof`, and every level carries its limitations.

Concretely, Level A means: the validated exploit no longer reproduces, every mutation that was
attempted failed, the benign corpus behaved identically, every in-scope clause still holds, and the
coverage change was bounded. It does **not** mean:

- the vulnerability class is absent from the codebase;
- no other input reaches the same weakness;
- code that did not execute is safe;
- a mutation nobody thought of would fail.

The single most important number qualifying any level is **coverage**. On the seeded demo it lands
around 39%. Roughly 60% of statements were never executed and therefore never dynamically verified.
That figure is in the certificate and in `REMAINING.md`, not buried.

---

## 4. Certificate signing is an HMAC, not a public-key signature

Certificates are signed with HMAC-SHA256 under a per-deployment key
(`CERTIFICATE_SIGNING_KEY`). This detects tampering by anyone without the key. It is **not**
independently verifiable by a third party, because verification requires the same secret. The
certificate says this in `signature.notes` rather than implying more.

A production system would want an asymmetric signature and a published verification key.

---

## 5. PostgreSQL row-level security is a second layer, and it is inert for the app's own connection

The primary tenant control is the application layer: the tenant comes from the signed access token,
every loader compares `row.tenant_id`, and a cross-tenant id returns 404 rather than 403. That is
what the tenant-isolation tests exercise, and it works.

Migration `0002_rls` adds RLS policies keyed on a `kavachx.tenant_id` session variable, plus a
`kavachx_reader` role subject to them. But **the application connects as the table owner, and a
table owner is not subject to RLS unless `FORCE ROW LEVEL SECURITY` is set.** Forcing it would
require setting the session variable on every pooled connection checkout, which this build does not
do. So for the application's own connection, RLS is currently inert. It is live for any non-owner
role.

The audit-log immutability trigger *does* apply to everyone, including the owner.

---

## 6. The mock proposer is deterministic, and its patch recipes are scripted

With no `GROQ_API_KEY`, or with `LLM_PROVIDER=mock`, proposals come from
`app/llm/mock_provider.py` — a deterministic scripted proposer. It is a genuine proposer: its output
goes through the same strict schema validation, the same deterministic validators and the same state
machine. But it is not intelligent.

Its patch recipes (`app/llm/recipes.py`) are hand-written transformations that fire on anchors in
the real file content. They produce real diffs, applied to a real workspace copy, verified by real
execution. They also only work on shapes they were written for — for anything else, synthesis fails
honestly rather than emitting plausible-looking garbage, and the finding ends at Level R with
"no repair synthesised".

**What that means for the demo:** the *refutation* is real (the mutation engine executes payloads
and finds a live bypass), the *diffs* are real, the *verification* is real. The *proposal* is
scripted. A hosted Groq run replaces the proposal step and nothing else. The certificate records
which provider produced its proposals, and whether it fell back.

---

## 7. Discovery coverage is uneven across the four channels

| Channel | On the Python demo target | On a native target |
| --- | --- | --- |
| Graph / static | ✅ tree-sitter index + AST rules with light taint tracking. Semgrep used when installed. | ⚠️ line-oriented C checks only |
| Config / reachability | ✅ finds signals, but almost nothing it finds is dynamically provable — those land in the unknown ledger with a reason | ✅ same |
| Fuzzing | ✅ a real seeded mutational campaign, executed, crashes deduplicated by shape | ❌ libFuzzer/AFL++ path needs a C toolchain; without one the channel reports that it did **not** fuzz |
| Runtime | ✅ observation traces + guard counters | ❌ ASan/UBSan build needs a compiler |

Every gap here appears in `REMAINING.md` per run, generated from state. A channel that could not run
says so; it never reports a clean result it did not earn.

---

## 8. On an arbitrary public repository, the run degrades to STATIC-ONLY — and says so

The full pipeline needs two things the seeded target provides and a stranger's repository usually
does not: an **entrypoint** KavachX can invoke, and a **benign workload corpus** to observe. Without
both, there is nothing to execute, so there is nothing to validate.

Rather than pretend otherwise, `node_index_repo` sets `static_only` and the rest of the graph honours
it:

| Stage | STATIC-ONLY behaviour |
| --- | --- |
| SAMHITA | skipped — clause falsification needs observed traces, and there are none |
| Discovery | graph/static and config/reachability only; fuzzing and runtime are **omitted, not "clean"** |
| Validation | no execution, so **no finding can reach `VALIDATED`** |
| Patch / gauntlet | not reached — KavachX does not repair what it could not reproduce |
| Publish | blocked on the provider, independently of all the above |

The console shows a blocked phase and an explicit `STATIC-ONLY` note, the run row itself carries
`mode: "static_only"` with the reason (so a reload tomorrow shows the same qualifier), and
`REMAINING.md` records "NOT RUN … zero dynamic coverage" for the dynamic channels. The output of such
a run is a list of **candidates for human review**, at the assurance level that honestly implies —
not findings.

**Priority is computed differently, because two of its three factors are unmeasurable.** The queue
normally ranks by `reachability × confidence × blast_radius`. Both reachability and blast radius come
from the call graph, and with no entrypoint the graph returns its floor for *every* code finding —
which does not merely add noise, it inverts the ranking. Measured on `we45/Vulnerable-Flask-App`
before the fix:

| Candidate | Priority (before) | Priority (now) |
| --- | --- | --- |
| CWE-89 SQL injection | 0.01 | 0.550 |
| CWE-1336 template injection | 0.01 | 0.550 |
| CWE-502 unsafe deserialisation | 0.01 | 0.550 |
| LOW "container may run as root" | 0.12 | 0.120 |

The Dockerfile note outranked three critical remote-code-execution candidates, because the config
channel legitimately knows its own findings are reachable (configuration is read at startup) while
the graph could say nothing about the code. So when reachability is unmeasurable, severity stands in
for it and blast radius is **dropped rather than substituted** — multiplying by a uniform floor only
rescales the order while implying a measurement nobody took. Each affected candidate's
`unknown_reason` records that its position reflects severity, not proven exposure.

**Minified bundles are excluded from analysis.** A vendored `static/loader.js` is one 40,000-character
line that trips several sink patterns; on the same repository it contributed dozens of unreadable
"candidate sinks" and one spurious hypothesis. Files identified as build output — by name
(`.min.js`, `.bundle.js`) or by line geometry — are still hashed as part of the pinned tree but are
not indexed, and `index_summary.skipped_files` names every one, because an unanalysed file is a hole
in coverage a reader is entitled to see.

This is worth stating plainly because it is the most likely way to misread the product: pointing
KavachX at a public repository and getting ten CRITICAL rows back looks like ten confirmed
vulnerabilities. It is ten static leads, each of which a human still has to confirm. Conversely, a
public repository that returns **zero** rows has not been cleared — on `pallets/itsdangerous` the
zero is correct, but a zero from a static-only run is only ever the absence of a matching pattern.

---

## 9. Sibling hunt candidates are "unproved", not "cleared"

The sibling hunt probes each candidate with the analogous exploit. When a probe produces no effect,
the candidate is still recorded as **unproved**, not safe — because the probe drives the same
entrypoint operation as the original exploit and may never have executed the candidate's function at
all. "The analogous request did nothing here" and "this code is safe" are different claims.

This is why the seeded demo lands at Level B rather than Level A: structurally similar neighbours
exist that could not be proved safe. Level A requires an empty unproved set.

---

## 10. Root-cause analysis verifies location, not causality

A proposed root cause is rejected unless it lies in indexed project source and on the recorded
execution path (a traceback frame or an observed call scope). That rules out hallucinated locations.

It does **not** prove the location is causally responsible. When verification fails, the analysis
falls back to the deepest executed project frame and sets `root_cause_verified: false`, which the
console shows as `UNVERIFIED`.

---

## 11. Other bounded areas

- **Shields**: only `input_filter` is implemented. seccomp and `LD_PRELOAD` shields are named in
  the architecture and reported as `implemented: false` by `/api/system/shield`. Deriving a sound
  syscall allowlist from one reproduction is not something to improvise.
- **Publisher**: defaults to `PUBLISHER_DRY_RUN=true` and writes the exact intended payload as an
  artifact instead of calling GitHub. The live path is implemented (branch → contents API → PR →
  labels) but is only exercisable with a configured fine-grained token that has push access. A
  public repository can never reach it at all — see [SECURITY.md](SECURITY.md) §1.1.
- **Public repository ingestion** uses the unauthenticated REST API, so it is subject to GitHub's
  anonymous rate limit (60 requests/hour/IP). A 403 is surfaced as a rate-limit message rather than
  being retried behind the operator's back.
- **Multiple patches, one PR**: the publisher does one verified patch → one branch → one PR, as the
  spec's first stage requires. Conflict-aware batching of multiple patches into one PR is not built.
- **GitNexus**: used for the call graph when present on the host; otherwise the graph is built from
  tree-sitter call sites. Which one was used is recorded in `graph_source` and travels into the
  certificate, because the fidelity of every reachability claim depends on it.
- **Checkpointing**: state is written after every node and is fully inspectable, but there is no
  *resume from checkpoint* — a failed run must be restarted.
- **Concurrency**: one process owns the event bus; DB-backed replay is the cross-process source of
  truth. Multi-worker deployment would need a real pub/sub for the live tail.
- **`monaco-editor` is pinned to 0.53.0** to avoid a transitive DOMPurify advisory in 0.54.x.

---

## What is genuinely real

To be equally precise in the other direction — these are not simulated:

- The seeded target's vulnerabilities are **reproduced by execution**, twice, in independent
  processes, and a finding is only `VALIDATED` on a deterministic signal.
- SAMHITA clauses are **compiled through a restricted-AST whitelist** and **falsified against
  held-out traces**. Over-fitted clauses genuinely die; the count appears in every run.
- The mutational fuzzer **executes** its campaign and finds real crashes.
- **Patch v1 is genuinely refuted.** The mutation engine executes payload variants and finds a live
  bypass of the naive filter. If it found none, the stage would pass.
- Diffs are **generated by KavachX** from old/new content and **applied to a workspace copy**; the
  pinned tree's hash is re-verified afterwards.
- The policy gate's dependency, network and exec checks are **AST comparisons**, not text
  matching — a comment mentioning `subprocess` is not a violation, and an aliased call still is.
- Certificates are **refused** when the evidence graph has a dangling claim.
- The audit log is **hash-chained and verified** by recomputation, and the chain covers deletion,
  reordering and in-place edits.
- Every number on the dashboard is aggregated from run state. Nothing is hardcoded, and there is no
  `sleep()` anywhere in the pipeline to make the UI look busy.
