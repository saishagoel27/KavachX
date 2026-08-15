# SAMHITA — Behavioural Contract Synthesis

*Saṃhitā: a systematically arranged, authoritative collection of rules.*

SAMHITA is the specification the target software never had.
It is synthesised by observation, not written by hand.
Once built, it serves three purposes:
1. Directs the fuzzer (falsify clause N, not chase raw coverage)
2. Defines a finding (a clause violation, not merely a crash)
3. Serves as the regression harness after a patch

---

## Pipeline overview

```
observe target under benign workload
  │
  ▼
record value profiles at every observable boundary
  │
  ▼
LLM proposes candidate clauses  [schema-constrained call]
  │
  ▼
deterministic falsifier runs each clause against held-out traces
  │  clauses that fail → deleted immediately
  │  clauses that pass → survivors
  ▼
survivors = the contract
```

Hallucinated clauses die in milliseconds and never reach a human.

---

## What a clause looks like

A clause is an executable predicate with metadata:

```python
@dataclass
class Clause:
    clause_id:   str           # e.g. "C017"
    predicate:   str           # executable expression in clause DSL
    scope:       str           # "function:parse_header" | "module:auth" | "boundary:http_input"
    obs_n:       int           # number of observations used to propose this
    status:      str           # "active" | "refuted" | "superseded"
    added_iter:  int           # synthesis iteration that produced this
    description: str           # human-readable summary
```

---

## Clause DSL

Clauses are written in a minimal, deterministic DSL.
The DSL has no side effects. Every predicate is a pure boolean function
over an observation record.

### Observation record structure

```python
@dataclass
class Observation:
    boundary:   str            # where this was recorded
    field:      str            # field or variable name
    value:      Any            # the observed value
    timestamp:  float
    trace_id:   str
    call_stack: list[str]
```

### DSL primitives

```
# Length bounds
len(field) <= N
len(field) >= N
len(field) in range(N, M)

# Type constraints
type(field) == T
field is not None
field is None

# Value bounds
field <= N
field >= N
field in {v1, v2, v3}
field not in {v1, v2, v3}

# Monotonicity
field >= prev(field)          # counter never decreases
field <= prev(field)          # counter never increases

# Determinism
result(field) == result(field) # same input → same output

# Absence of dangerous calls
not calls(syscall="execve")
not calls(syscall="system")
not calls(fn="os.system")

# Reachability
not reachable(label="sink_X") given input_matches(pattern)

# Composition
clause_A and clause_B
clause_A or clause_B
not clause_A
```

### Example clauses

```
C001: len(http_header) <= 255
C002: type(user_id) == int
C003: auth_token is not None
C004: not calls(syscall="execve") within scope(parse_input)
C005: response_code in {200, 201, 400, 401, 403, 404, 500}
C017: len(content_length_field) <= 10  # the one that gets violated
```

---

## Observer

`samhita/observer.py`

Runs the target under a benign workload and records value profiles.

```python
class Observer:
    def run(
        self,
        target: dict,
        corpus_ref: str,
        sandbox_runner: SandboxRunner,
    ) -> list[BoundaryProfile]:
        ...
```

A `BoundaryProfile` captures:
```python
@dataclass
class BoundaryProfile:
    boundary:    str
    field:       str
    samples:     list[Any]
    min_val:     Any
    max_val:     Any
    null_rate:   float
    type_dist:   dict[str, float]   # {"int": 0.95, "str": 0.05}
    cardinality: int                # number of distinct values seen
    sample_traces: list[str]        # 3 representative trace IDs
```

The observer runs **inside the sandbox** (execution profile).
It never runs on the host.

---

## Proposer

`samhita/proposer.py`

LLM call: given boundary profiles, propose candidate clauses.

### Input schema (sent to LLM)

```json
{
  "boundary": "parse_header",
  "profiles": [
    {
      "field": "content_length",
      "min": 0,
      "max": 8192,
      "null_rate": 0.0,
      "type": "int",
      "cardinality": 847,
      "sample_traces": ["t001", "t002", "t003"]
    }
  ],
  "sample_observations": [...]
}
```

### Output schema (LLM must return)

```json
{
  "clauses": [
    {
      "predicate": "len(content_length) <= 10",
      "scope": "function:parse_header",
      "description": "content_length field never exceeds 10 characters",
      "confidence": 0.92
    }
  ]
}
```

The output is **schema-validated** before any clause is accepted.
If the LLM returns malformed JSON or violates the schema, the call is
retried once, then the boundary is skipped and logged to ledger.

### What the LLM is NOT allowed to do here
- Decide which clauses are "important"
- Assign clause IDs (the system assigns those)
- Modify existing clauses
- Produce clauses outside the DSL grammar

---

## Falsifier

`samhita/falsifier.py`

Deterministic. No LLM involved.

For each proposed clause:
1. Run the clause predicate against all held-out traces
2. If any trace falsifies the predicate → delete the clause
3. If all traces satisfy the predicate → clause survives

```python
class Falsifier:
    def run(
        self,
        proposed_clauses: list[Clause],
        held_out_traces: list[Trace],
    ) -> list[Clause]:
        survivors = []
        for clause in proposed_clauses:
            if all(self._evaluate(clause, trace) for trace in held_out_traces):
                survivors.append(clause)
        return survivors

    def _evaluate(self, clause: Clause, trace: Trace) -> bool:
        # compile predicate to Python callable
        # execute against trace observations
        # return True if predicate holds, False if falsified
        ...
```

The falsifier is the gatekeeper. Nothing the LLM proposes can survive
without passing this deterministic check.

---

## Evaluator

`samhita/evaluator.py`

Used at two points:
1. During falsification (above)
2. During the gauntlet contract stage — re-evaluates all active clauses
   against post-patch traces

```python
class Evaluator:
    def evaluate_all(
        self,
        clauses: list[Clause],
        traces: list[Trace],
    ) -> dict[str, bool]:
        # returns {clause_id: passed}
        ...

    def evaluate_one(
        self,
        clause: Clause,
        trace: Trace,
    ) -> bool:
        ...
```

---

## Iteration cap

Clause refinement is capped at **2 iterations**.

If after 2 rounds the contract has fewer than 5 surviving clauses,
the run continues with what it has and logs the shortfall to ledger.
It does not loop indefinitely.

---

## Contract quality signals

After synthesis, the contract is assessed:

| Signal | Threshold | Action if below |
|---|---|---|
| Clause count | ≥ 5 | Log warning, continue |
| Clause count | ≥ 20 | Good — proceed normally |
| Falsification rate | < 80% surviving | Log — LLM proposals were poor quality |
| Coverage of boundaries | ≥ 60% | Log warning if below |

These are observability signals, not hard stops.

---

## Output

After synthesis, `state["samhita"]` contains the active contract.
`state["benign_corpus_ref"]` points to the recorded traces used for falsification.

Both are used throughout the rest of the pipeline:
- Discovery channels use clause IDs to direct fuzzing
- Gauntlet contract stage re-evaluates all clauses post-patch
- PRAMAAN references specific clause IDs in the evidence graph
- REMAINING.md lists any clauses that were refuted during the run
