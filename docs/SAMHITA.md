# SAMHITA — the executable behavioural contract

SAMHITA is what KavachX reconstructs *before* looking for bugs. Not a document, not a policy file: a
set of compiled, executable predicates over observed behaviour, each one of which had to survive an
attempt to kill it.

```
Benign Workload
      ↓
Observation                (tracing harness, inside the sandbox)
      ↓
Value Profiles             (bounds, ranges, enumerations, counters, containment)
      ↓
LLM Clause Proposal        ← the only step a model participates in
      ↓
Strict JSON Schema         (a schema failure is a model failure)
      ↓
Deterministic Clause Compiler   (restricted-AST whitelist)
      ↓
Held-out Trace Falsification    (against traces the proposer never saw)
      ↓
Surviving Clauses  →  SAMHITA
```

---

## Why observe first

A vulnerability is a violation of something. If you never write down what the software is supposed to
do, "violation" collapses into "crash", and you lose every bug that does not crash — the injection
that succeeds quietly, the traversal that returns the wrong file, the counter that goes backwards.

SAMHITA is that "supposed to do", derived from the software's own benign workload rather than from a
specification nobody wrote.

---

## Observation

The benign corpus is executed **inside the sandbox** under `app/sandbox/harness/kx_observe.py`, which
traces with `sys.settrace` and records, per invocation:

- the function, its file and line;
- a **value profile** per argument — length, line count, numeric value, whether a string matches a
  safe charset, how many shell metacharacters it contains;
- the return profile — `ok`, `seq`, `op`, length, nullability;
- executed lines, for **real** statement coverage computed against an `ast` statement count;
- guard counters — shell invocations, blocked network attempts, reads outside the declared asset root.

Two details in the tracer are load-bearing:

**Frozen frames are excluded.** `Path("<frozen importlib._bootstrap>").resolve()` cheerfully produces
a path *inside* the project root, which floods the observations with standard-library behaviour and
buries the target's own. Filenames starting with `<` are rejected before resolution, and the result
must be a file that exists.

**Guard counters are per-case deltas, not running totals.** A cumulative counter is not comparable
between two runs that executed different numbers of cases — a clause derived from a total would
appear to break the moment the corpus size changed, reporting a regression with nothing behind it.
Snapshotting before and after each case makes `shell_invocations == 1` mean "this operation spawns
one shell", which is a statement about behaviour.

---

## The split

Cases are split deterministically by id, **every third case held out**:

```python
observation, holdout = split_cases(cases)   # 12 cases → 6 / 6
```

Every third rather than a contiguous tail, because a tail split would let the proposer see all the
small inputs and none of the large ones purely by ordering accident.

The proposer sees **value profiles from the observation split only**. The falsifier tests against the
held-out split. Neither ever sees the other's data.

The observation split is executed **twice**, so response determinism is itself observable.

---

## Value profiles

Aggregates only — never raw values beyond a short enumeration. Six kinds, each proposing a different
shape of clause:

| Kind | Derived when | Clause shape |
| --- | --- | --- |
| `length` | numeric, metric names a length or line count | `arg_lines_raw <= 8` |
| `count` | numeric otherwise | `process_invocations <= 3` |
| `zero` | numeric and never non-zero | `reads_outside_root == 0` |
| `monotonic` | a counter observed non-decreasing | `ret_seq >= 1` |
| `boolean` | all values boolean | `ret_ok == True` |
| `enum` | few distinct short strings | `response_op in ["ping", "status", …]` |

`zero` is the strongest claim available — "never observed at all during benign operation" — and the
one an exploit is most likely to violate. `shell_command_metachars == 0` is exactly that, and it is
the clause the command-injection finding breaks.

---

## The compiler is a whitelist

`app/samhita/compiler.py` is why a hallucinated clause cannot become executable. The grammar is
closed:

```
expr := comparison | boolop | unary | arith | atom
atom := NAME | NUMBER | STRING | True | False | None | [atom,…] | (atom,…)
```

Rejected outright, not sanitised: calls, attribute access, subscripts, comprehensions, f-strings,
lambdas, walrus assignments, statements, semicolons, newlines. `NAME` must resolve to a metric present
in the observation namespace. Evaluation runs with `{"__builtins__": {}}`.

Two further rules:

- **A predicate must contain a comparison.** `arg_len_raw` alone asserts nothing and could never fail.
- **A predicate must reference a metric.** `1 <= 2` is not a clause about the software.

```python
compile_predicate("__import__('os').system('rm -rf /')")   # ClauseCompileError
compile_predicate("open('/etc/passwd').read()")            # ClauseCompileError
compile_predicate("obj.attribute == 1")                    # ClauseCompileError
compile_predicate("values[0] == 1")                        # ClauseCompileError
compile_predicate("arg_lines_raw <= 8")                    # compiles
```

---

## Falsification is where trust comes from

Four verdicts, and only one is admissible:

| Verdict | Meaning |
| --- | --- |
| **SURVIVING** | Held on every applicable held-out record, and there was at least one. **Admissible as evidence.** |
| **FALSIFIED** | A held-out record made it false. The counterexample is stored. |
| **UNSUPPORTED** | No held-out record carried the metrics it needs. **Not admitted.** |
| **UNCOMPILABLE** | Rejected by the compiler; never evaluated. |

The `UNSUPPORTED` case is the subtle one. A clause nobody could contradict is not the same as a clause
nobody did contradict, and treating it as evidence would be exactly the unfalsifiable claim this
system exists to avoid. So it is discarded.

`evaluate()` also distinguishes **not-applicable from false**: a record missing a metric the predicate
needs returns `None`, not `False`. Conflating them would falsify clauses using observations that never
claimed to describe them.

```
C027  input_length_bound        FALSIFIED
predicate  arg_len_fmt <= 3
reason     held-out case 008-export-json contradicts it (arg_len_fmt=4)
verdict    not admissible as evidence
```

A typical run on the seeded target: **72 surviving, 20 falsified**. Those twenty are the mechanism
working. They appear in `REMAINING.md`, because a rejected clause is itself information about the
target.

---

## The clause iteration (≤ 2)

Iteration 1 proposes from the observation split. Bounds taken from a partial sample are often too
tight, and the falsifier kills them.

Iteration 2 gets **one** chance: falsified numeric bounds widen to the value that broke them, enum
memberships gain the value that broke them, and the widened clause is re-falsified against the same
held-out split. A `zero` metric that turns out to occur in held-out traces is reclassified as `count`,
because "never happens" was simply wrong.

An enum that would need more than `MAX_ENUM_CARDINALITY` members is dropped rather than widened — a
membership clause over everything asserts nothing.

Then it stops. `clause ≤ 2` is a hard ceiling.

---

## How clauses become evidence

**At validation.** After an exploit reproduces, the validator re-observes it under tracing and
evaluates every surviving clause against that trace. Clauses that are now false are the finding's
**contract violation**. That is what makes a finding contract-grounded — not "a crash happened" but
"clause C088, which survived held-out falsification, is false here".

When several clauses break, the reported one is chosen by **specificity**, not by iteration order: a
clause scoped to the offending function beats one scoped to its file, which beats a global counter that
also happens to be false. The certificate quotes whichever one this picks, so picking well matters.

**At re-check.** Stage 4 of the Refutation Gauntlet re-evaluates every in-scope clause on the patched
build. Two distinct failures, both refutations:

- a clause that held before is now **falsified** — the patch broke a contract;
- a clause that held before is now **unsupported** — the code path it described no longer executes.
  That is a silent behavioural change, and treating it as a pass would let a patch delete
  functionality and call it a fix.

---

## Clause kinds in the demo run

| Clause | Predicate | Scope | Violated by |
| --- | --- | --- | --- |
| `C088` | `arg_safe_charset_report_name == True` | `exporter.py:_archiver_command` | command injection |
| `C011` | `shell_command_metachars == 0` | global | command injection |
| `C060` | `arg_lines_raw <= 8` | `parser.py:parse_header` | header overflow |
| `C007` | `reads_outside_root == 0` | global | path traversal |
| `C009` | `response_ok == True` | global | any crash |

Every one derived from observation, compiled through the whitelist, and survived a held-out attempt to
kill it.

---

## Limits

- SAMHITA is only as good as the benign corpus. A thin corpus yields few clauses and a low coverage
  figure — and the coverage figure travels into every certificate for exactly that reason.
- Metrics are extracted by the harness. A behaviour nobody thought to measure cannot be constrained.
- Clauses are per-invocation predicates. Cross-invocation temporal properties ("never after") are not
  expressible in this grammar.
- The corpus is the *target's own*. If it does not exercise a path, no clause describes that path.
