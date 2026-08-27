# The Refutation Gauntlet

Four stages, all executed against the **patched** workspace copy. Every one of them tries to prove
the patch wrong.

Code: [`backend/app/gauntlet/`](../backend/app/gauntlet/)

```
Patch v1
   ↓
exploit mutation ─── a bypass here is the most decisive refutation there is
   ↓
sibling hunt ─────── the same weakness class, in neighbouring reachable code
   ↓
differential replay ─ did benign behaviour change?
   ↓
SAMHITA re-check ─── do the in-scope behavioural clauses still hold?
   ↓
regression suite ─── does the original reproducing input still fire?
   ↓
PASS → verified          FAIL → refuting evidence becomes a hard constraint → Patch v2
```

**If any stage fails, the patch is REFUTED**, withdrawn, and the refuting evidence becomes a
constraint carried into the next iteration. After three iterations: honest failure, with the shield
left in place and the finding recorded at Level R.

The mutation stage runs first because it produces the payload shapes the sibling hunt reuses.
Stages 2–4 then run concurrently — they need no shared mutable state.

---

## 1. Exploit mutation

Takes the validated proof of vulnerability and attacks the patch with variations of it.

The model proposes mutation *strategies*; every strategy is then **executed** against the patched
build and judged by the same deterministic signal that proved the original finding — the marker in
stdout, the canary content, a nonzero exit.

`_BASELINE_SEPARATORS` and `_BASELINE_TRAVERSALS` are always executed regardless of what the model
returns. A model that returns nothing must not silently weaken the stage.

This is the stage that catches the classic incomplete fix: a patch that rejects `;` looks correct
against the reported payload and falls over the moment `&` is tried.

**Verified in the demo run** — this is real, not staged:

```
patch v1:  exploit_mutation   1/19  FAIL   ← a live bypass of the naive filter
           sibling_hunt       7/7   PASS
           differential_replay 12/12 PASS
           samhita_recheck    50/50 PASS
                    ↓ refutation becomes a constraint
patch v2:  exploit_mutation  19/19  PASS
           sibling_hunt       7/7   PASS
           differential_replay 12/12 PASS
           samhita_recheck    50/50 PASS
```

If the mutation engine found no bypass, the stage would pass. It found one.

---

## 2. Sibling hunt

Searches neighbouring code paths for the same weakness class, then **attempts the analogous exploit
against each candidate**. Finding a structurally similar function is a hint; the verdict depends on
whether an exploit actually works there.

| Outcome | Verdict | Why graded this way |
| --- | --- | --- |
| A sibling is exploitable | **FAIL** | The patch fixed one instance of a class that is still live elsewhere |
| Similar candidates exist, none exploitable | **PASS**, candidates recorded as *unproved* | Exactly what separates Level B from Level A |
| No similar candidates | **PASS** | Nothing outstanding |

### Where the code graph earns its place

The search space comes from the graph, and this is where a resolved graph pays off:

- `graph.siblings_of(uid)` — callables in the same file, then the same module.
- Every sink of the **same category anywhere in the target** — a sibling in another module is
  precisely the case a file-local search misses.
- `graph.callers(uid)` — the multiple-callers shape from the spec:

  ```
  endpoint_A ─┐
  endpoint_B ─┼─▶ vulnerable_function
  endpoint_C ─┘
  ```

  A patch applied at one caller leaves the other two live. The gauntlet asks whether the patch
  protects **all relevant reachable paths**, not just the one the exploit used.

`.gitnexus` is in `PRESERVED_DIRS` for exactly this reason: the sibling hunt queries the graph after
every patch iteration, and a workspace reset that deleted the index would silently downgrade the
search space to whatever tree-sitter alone could see, mid-run, with nothing in the evidence saying
so.

### Unproved is not cleared

When a probe produces no effect the candidate is recorded as **unproved**, not safe — the probe
drives the same entrypoint operation as the original exploit and may never have executed the
candidate's function. "The analogous request did nothing here" and "this code is safe" are different
claims. See [HONESTY.md](HONESTY.md) §9.

---

## 3. Differential replay

Replays the benign corpus before and after the patch and compares response hashes. Any behavioural
divergence is a regression.

The baseline is captured **once**, from the unpatched tree, before any patch is applied. Comparing
against a baseline captured after a patch would compare the patch to itself.

Coverage before and after must be measured over the **same workload**, or the delta is meaningless:
the pre-patch figure is SAMHITA's observation coverage over the benign corpus, and the post-patch
figure is the re-check over that same corpus. Using the single-case proof-of-vulnerability
observation as the baseline would compare one request against twelve and report a large "behavioural
change" that never happened.

---

## 4. SAMHITA re-check

Re-evaluates every surviving clause **in the blast radius** against traces from the patched build.

A clause that survived held-out falsification is real evidence about how the program behaves. If the
patch makes one false, the patch changed behaviour the target relied on.

Clauses that cannot be evaluated after the patch are counted separately as `clauses_unsupported` —
their preservation is *unverified*, not confirmed, and that difference caps assurance at Level C.

---

## Generated tests feed the gauntlet

The test-synthesis subsystem ([TEST_SYNTHESIS.md](TEST_SYNTHESIS.md)) contributes two things.

### The regression plan

Built from the validated finding's **actual reproducing input** — the recorded `pov_request` /
`pov_payload`, never anything regenerated. A regression test built from a reconstructed input tests a
guess about the exploit.

It is re-run against every patch iteration: **a patch is not verified until the original exploit no
longer fires.** Verified against the unpatched build first, so the test is known to be capable of
firing:

```
regression on UNPATCHED build: reproduced=True (1/1)
  PROOF: marker_in_stdout: marker present in stdout
```

A regression test that has never been shown to fire is not a guard, it is a comment.

### The mutation harness

The same generated mutation harness that proved the finding is re-runnable against each patched
build, with the same twelve deterministic mutation families. Its oracle is the same one that proved
the original, so "the patch holds" and "the finding was real" are decided by identical machinery.

---

## Constraints accumulate

`constraints_from_refutation()` turns each failing stage's refuting evidence into a hard constraint
on the next patch:

```
POLICY REJECTED: <summary>. The next patch must satisfy the deterministic publish policy.
REFUTED at exploit_mutation: the '&' separator still reaches the shell.
```

Those constraints go into the synthesis payload for iteration N+1. A patch that violates one will be
refuted again — the loop is not "try again and hope", it is "try again knowing what failed".

---

## What a gauntlet result records

```
verdict · failing_stage · stages_passed / stages_total · duration_ms · summary
per stage: verdict · detail · refuting_evidence · metrics · cases_passed / cases_total
constraints[] · model_calls[]
```

Persisted as `GauntletRun` + `GauntletResult` rows, and every stage becomes an evidence node in the
certificate's graph, wired `patch --verified_by--> stage`.

A failing stage **must** attach `refuting_evidence` — the e2e test asserts it:

```python
if gauntlet["verdict"] == "fail":
    assert gauntlet["failing_stage"]
    failing = next(s for s in gauntlet["stages"] if s["stage"] == gauntlet["failing_stage"])
    assert failing["refuting_evidence"], "a failing stage must attach refuting evidence"
```

---

## Assurance mapping

| Level | Gauntlet state |
| --- | --- |
| **A** | All four PASS, no unproved siblings, coverage change ≤ 10 points |
| **B** | All four PASS, but the sibling hunt left unproved candidates |
| **C** | Exploit eliminated, but replay failed, or clauses unsupported, or coverage moved > 10 points |
| **R** | Any stage FAIL, or the exploit still reproduces → patch withdrawn, shield remains |

Graded by deterministic rules over the stage results
([`pramaan/assurance.py`](../backend/app/pramaan/assurance.py)). No model input, no discretion.

The demo lands at **B / B / R**: two findings repaired with unproved siblings remaining, one with no
recipe match and therefore no repair attempted.

---

## Bounded

```
patch iterations ≤ 3
```

Enforced in the node, carried in state, surfaced at `/api/system/limits`. After three refutations the
run records an honest failure: the finding is `SHIELDED`, not repaired, and `REMAINING.md` says so.

---

## Related

- [TEST_SYNTHESIS.md](TEST_SYNTHESIS.md) — where the generated and regression tests come from.
- [CODE_GRAPH.md](CODE_GRAPH.md) — the graph the sibling hunt searches.
- [SAMHITA.md](SAMHITA.md) — the contract the re-check evaluates.
- [PRAMAAN.md](PRAMAAN.md) — how stage results become evidence.
- [HONESTY.md](HONESTY.md) §9 — why sibling candidates are "unproved", not "cleared".
