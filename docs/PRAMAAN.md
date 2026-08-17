# PRAMAAN — the evidence graph and assurance levels

PRAMAAN is an evidence graph, not a score. Every claim a certificate makes resolves to a node; every
node carries a content hash. A certificate whose claims do not resolve is **refused**, because a
document that looks substantiated and is not would be worse than no document.

---

## The graph

```
Vulnerability V02
 ├── discovered_by      → graph/static, runtime
 ├── violated_clause    → SAMHITA C088
 ├── code_evidence      → exporter.py:40, exporter.py:24 (root cause), world model
 ├── runtime_evidence   → observation trace
 ├── exploit_evidence   → reproduction record  (the exploit itself is withheld)
 ├── shielded_by        → shield S02
 ├── repaired_by        → patch v1 → patch v2   (v2 supersedes v1)
 ├── verified_by        → mutation PASS · sibling PASS · replay PASS · contract PASS
 ├── scoped_by          → blast radius
 └── executed_in        → sandbox session

Certificate KX-6908-V02-054F15 ── attests ──▶ Vulnerability V02
```

Node types: `vulnerability`, `discovery_channel`, `samhita_clause`, `code_location`, `runtime_trace`,
`reproduction`, `shield`, `patch`, `gauntlet_result`, `blast_radius`, `world_model`,
`sandbox_execution`, `certificate`.

Relations: `discovered_by`, `violated_clause`, `code_evidence`, `runtime_evidence`,
`exploit_evidence`, `shielded_by`, `repaired_by`, `verified_by`, `scoped_by`, `executed_in`,
`attests`, `supersedes`.

### Content hashes

`content_hash = sha256(canonical_json({ref, type, title, content, meta}))`

Canonical JSON means sorted keys and no insignificant whitespace, so two structurally identical
payloads always hash the same. The certificate references these hashes, so it cannot drift from the
evidence it cites without the hashes changing.

### Refusal conditions

`build_certificate` returns an error rather than a weaker certificate when:

1. **The graph has a dangling claim** — an edge pointing at a node that does not exist. Checked by
   `unsupported_claims()`; `test_graph_detects_dangling_claims` covers it.
2. **The finding was never reproduced** and the grade is not Level R.

Refusal is logged and the run continues without that certificate. Nothing weaker is emitted.

### Shared nodes

Several nodes are legitimately shared between findings in one run — the discovery channels, the world
model, the sandbox session. Their refs are stable by design; that is what makes the whole run one
graph rather than N disjoint trees. The persistence layer reuses them instead of re-inserting.

---

## Assurance levels

**These are bounded empirical assurance. They are never formal proof.** Every certificate carries
`assurance.not_a_formal_proof: true` and a populated `limitations` list, and the console renders the
limitations next to the badge rather than in a footnote.

Grading is deterministic — rules over gauntlet results, no model input, no discretion
(`app/pramaan/assurance.py`).

### Level A

Exploit eliminated · all relevant clauses hold · differential replay passes · mutation passes ·
sibling hunt passes with **nothing unproved** · coverage change bounded (≤ 10 points).

Means: the validated exploit no longer reproduces, every attempted mutation failed, the benign corpus
is behaviourally identical, every in-scope clause still holds, and no structurally similar path remains
unexamined.

Does **not** mean: the vulnerability class is absent from the codebase, no other input reaches the
weakness, or code that did not execute is safe.

### Level B

As A, but the sibling hunt shortlisted code paths sharing the weakness pattern that could not be
proved safe. None was exploitable in the probes that ran; they are named in the certificate as
residual risk.

The seeded demo lands here, and the reason is worth stating precisely: a candidate probed *without
effect* is **unproved, not cleared**. The probe drives the same entrypoint operation as the original
exploit, so it may never have executed the candidate's function at all. "The analogous request did
nothing here" and "this code is safe" are different claims, and only the second would justify dropping
it from residual risk.

### Level C

Exploit eliminated, but at least one verification dimension is incomplete — behaviour changed on a
benign case, clauses could not be evaluated, or the coverage swing exceeded the bound. The specific
limitation is named.

### Level R

Patch refuted and withdrawn. The shield remains deployed. Refuting evidence attached.

**Level R can never publish.** The policy gate rejects it and the API returns `ASSURANCE_LEVEL_R` at
422. A Level R certificate exists to record honestly that a finding is *not repaired* — and if no
shield is active either, it says the finding is currently unmitigated.

### Grading inputs

| Input | Source |
| --- | --- |
| `exploit_eliminated` | the gauntlet's mutation stage found no bypass |
| `mutation_pass`, `sibling_pass`, `replay_pass`, `samhita_pass` | stage verdicts |
| `coverage_before` / `coverage_after` | SAMHITA observation vs. post-patch re-check — **the same workload on both sides** |
| `clause_total` / `held` / `unsupported` | the re-check stage |
| `unproved_siblings` | the sibling stage |
| `shield_active` | whether a verified shield is deployed |
| `iteration` / `max_iterations` | the patch loop |

The coverage comparison is deliberate: comparing a single-request proof-of-vulnerability observation
against a twelve-case corpus would report a large "behavioural change" that never happened, and drag
every certificate to Level C for no reason.

---

## The certificate document

`certificate.json` sections:

| Section | Contents |
| --- | --- |
| `assurance` | level, label, description, `not_a_formal_proof`, rationale, **limitations**, criteria |
| `run` | id, short code, timings including **time to protection** and **time to repair**, tokens, egress |
| `target` | repository, provider, branch, commit, **pinned source sha256**, authority timestamp |
| `finding` | handle, severity, CWE, location, reachability, root cause (with `verified`), reproduction record |
| `violated_clause` | the SAMHITA clause, its predicate, and its held-out survival count |
| `shield` | mechanism, verified-blocked, verified-benign, revert command |
| `patch` | iteration, status, diff hash, files, risk, expected effect, **constraints carried forward** |
| `patch_history` | every iteration including refuted ones, with refutation summaries |
| `verification` | the four stage verdicts with detail and case counts |
| `blast_radius` | callers, modules, clauses, allowed paths, regression scope |
| `samhita` | proposed / surviving / falsified counts, iterations, split sizes |
| `execution_environment` | sandbox adapter, **`network_enforced`**, **`suitable_for_untrusted_code`**, egress |
| `reasoning_provider` | which provider proposed, whether it **fell back to mock**, tokens per task |
| `evidence_graph` | the full graph with hashes |
| `signature` | algorithm, certificate hash, HMAC, and how to verify it |

Two things deliberately in there: the sandbox's honest capability flags, so a reader can see whether
the execution boundary was real; and which provider produced the proposals, because "which model said
this" is part of the evidence.

One thing deliberately **not** in there: the working exploit. Certificates carry
`pov_hash` and `pov_withheld: true`.

---

## Signing

```
certificate_hash = sha256(canonical_json(document without "signature"))
signature        = HMAC-SHA256(certificate_hash, CERTIFICATE_SIGNING_KEY)
```

`GET /api/certificates/{id}/verify` recomputes both from the stored document.

**This is an HMAC, not a public-key signature.** It detects tampering by anyone without the key; it is
not independently verifiable by a third party, because verification needs the same secret. The
certificate says so in `signature.notes`. A production system would want an asymmetric signature and a
published verification key — see [HONESTY.md](HONESTY.md) §4.

---

## Deliverable documents

### `CHANGES.md`

One section per verified fix: vulnerability, root cause, violated clause, evidence, assurance level,
blast radius, files changed, PR link.

### `REMAINING.md`

Seven sections, all generated from run state — nothing hand-authored per run:

1. **Unvalidated hypotheses** — with *why* each could not be validated
2. **Refuted patches** — with the refuting evidence and the constraints it produced
3. **Falsified SAMHITA clauses** — a rejected clause is information about the target
4. **Coverage gaps** — the percentage, and per-channel notes including channels that could not run
5. **Unreachable code**
6. **Remaining risk** — unproved siblings, incomplete verification, unrepaired findings, and the
   execution boundary itself when the adapter is not one
7. **Decisions requiring human review**

It closes with an honesty statement naming what the run did not establish. `REMAINING.md` goes into
the pull request alongside `CHANGES.md`, so a reviewer sees what was not proved in the same place as
what was.

A run that reports only its successes is a marketing document. The value of this system is that the
ledger of what it could not establish is generated from the same state, with the same rigour, and
cannot be omitted.
