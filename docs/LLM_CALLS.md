# LLM Calls

There are exactly **6 LLM call types** in KavachX.
Every call has a defined input schema, a schema-validated output, and a
deterministic check that can reject it.

The LLM proposes. It never decides.

---

## Models

| Model | Used for |
|---|---|
| Qwen3-Coder-30B-A3B | Calls 3, 4, 5, 6 (complex reasoning) |
| Qwen3-4B | Calls 1, 2 (classification, extraction) |

Route cheap calls to the small model. Never wake the large model for filing.

---

## Call 1 — Interface Hypothesis

**Model:** Qwen3-4B
**Used in:** `discovery/channels/graph_static.py`
**Purpose:** Given observable target surface, propose entry points and input shapes.

### Input
```json
{
  "elf_exports": ["parse_header", "handle_request", "..."],
  "strings": ["Content-Length", "Authorization", "..."],
  "syscall_summary": {"read": 142, "write": 89, "execve": 0},
  "unit_file": "kavachx-target.service",
  "open_ports": [8080, 443],
  "sample_packets": ["...base64..."]
}
```

### Output schema
```json
{
  "entry_points": [
    {
      "name": "parse_header",
      "input_shape": {
        "type": "buffer",
        "max_len": 4096,
        "encoding": "utf-8"
      },
      "confidence": 0.91
    }
  ]
}
```

### Deterministic gate
Harness smoke test: the proposed entry point must produce coverage movement
when exercised with a minimal valid input. If coverage does not move,
the entry point is rejected and logged to ledger.

---

## Call 2 — Clause Proposal

**Model:** Qwen3-4B (simple boundaries) / Qwen3-Coder-30B-A3B (complex)
**Used in:** `samhita/proposer.py`
**Purpose:** Given boundary profiles, propose candidate clauses in the clause DSL.

### Input
```json
{
  "boundary": "parse_header",
  "profiles": [
    {
      "field": "content_length",
      "min": 0,
      "max": 8192,
      "null_rate": 0.0,
      "type_dist": {"int": 1.0},
      "cardinality": 847,
      "sample_traces": ["t001", "t002", "t003"]
    }
  ]
}
```

### Output schema
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

### Deterministic gate
Falsifier: every proposed clause is run against held-out traces.
Any clause that fails on any trace is deleted. The LLM never sees
which clauses survived — it only proposes.

---

## Call 3 — Constraint Authoring

**Model:** Qwen3-Coder-30B-A3B
**Used in:** `discovery/channels/constraint.py`
**Purpose:** Given a blocked branch condition, produce an SMT constraint
over input bytes that would reach it.

### Input
```json
{
  "branch_condition": "if (len > MAX_HEADER_LEN)",
  "source_context": "hdr.c:340-355",
  "decompiled_context": "...",
  "variable_types": {
    "len": "int32_t",
    "MAX_HEADER_LEN": "const int = 255"
  }
}
```

### Output schema
```json
{
  "smt_constraint": "(assert (> len 255))",
  "input_bytes_mapping": {
    "len": {"offset": 4, "size": 4, "encoding": "little_endian_int32"}
  },
  "description": "len field at offset 4 must exceed 255"
}
```

### Deterministic gate
Z3 solver: the constraint is fed to Z3. Z3 must produce a satisfying
input. That input is then executed in the sandbox — the branch must
actually be reached. If the branch is not reached, the constraint is
rejected and logged to ledger.

---

## Call 4 — Root-Cause Hypothesis

**Model:** Qwen3-Coder-30B-A3B
**Used in:** `patch/synthesiser.py`
**Purpose:** Given a causal chain from reverse execution, produce a ranked
hypothesis naming the root cause file and line.

### Input
```json
{
  "crash_site": "hdr.c:812",
  "sanitizer_report": "heap-buffer-overflow at hdr.c:812",
  "reverse_execution_chain": [
    {"frame": "hdr.c:812", "event": "write_oob"},
    {"frame": "hdr.c:340", "event": "last_write_to_len"},
    {"frame": "hdr.c:298", "event": "allocation_site"}
  ],
  "taint_path": ["input_buffer → len → hdr.c:340 → hdr.c:812"],
  "code_slice": "// hdr.c:335-345\nif (len > MAX_HEADER_LEN) { ... }"
}
```

### Output schema
```json
{
  "hypotheses": [
    {
      "rank": 1,
      "file": "hdr.c",
      "line": 340,
      "description": "signed comparison allows negative len to bypass bound",
      "confidence": 0.94
    },
    {
      "rank": 2,
      "file": "hdr.c",
      "line": 298,
      "description": "allocation does not validate len before use",
      "confidence": 0.61
    }
  ]
}
```

### Deterministic gate
A patch at the top-ranked site must survive the gauntlet.
If it does not, the next-ranked hypothesis is tried.
If all hypotheses are exhausted within the patch iteration cap (3),
`record_honest_failure` is called.

---

## Call 5 — Patch Authoring

**Model:** Qwen3-Coder-30B-A3B
**Used in:** `patch/synthesiser.py`
**Purpose:** Given root cause and relevant contract clauses, produce a
minimal unified diff.

### Input
```json
{
  "root_cause": {
    "file": "hdr.c",
    "line": 340,
    "description": "signed comparison allows negative len to bypass bound"
  },
  "relevant_clauses": [
    {
      "clause_id": "C017",
      "predicate": "len(content_length) <= 10",
      "scope": "function:parse_header"
    }
  ],
  "code_slice": "// hdr.c:335-350\n...",
  "previous_attempts": [],
  "refutation_constraints": []
}
```

If this is iteration 2 or 3, `previous_attempts` contains the diffs that
were refuted and `refutation_constraints` contains the inputs that broke them.
The LLM must not repeat a refuted approach.

### Output schema
```json
{
  "diff": "--- a/hdr.c\n+++ b/hdr.c\n@@ -338,7 +338,7 @@\n-  if (len > MAX_HEADER_LEN) {\n+  if (len < 0 || (size_t)len > MAX_HEADER_LEN) {\n",
  "explanation": "cast len to unsigned before comparison to prevent negative bypass",
  "touches_files": ["hdr.c"],
  "new_dependencies": [],
  "new_network_calls": false,
  "new_exec_calls": false
}
```

### Deterministic gate
Policy gate (before gauntlet):
- `new_dependencies` must be empty
- `new_network_calls` must be false
- `new_exec_calls` must be false
- `touches_files` must be within the computed blast radius
- Diff size must be below the cap (configurable, default 200 lines)

Then the full gauntlet (4 stages).

---

## Call 6 — Refutation Strategy

**Model:** Qwen3-Coder-30B-A3B
**Used in:** `patch/gauntlet.py` (mutation stage)
**Purpose:** Given a candidate diff and the original exploit, propose
bypass strategies (not payloads) for the fuzzer to try.

### Input
```json
{
  "diff": "--- a/hdr.c\n+++ b/hdr.c\n...",
  "original_exploit": {
    "pov_ref": "pov-44",
    "description": "negative len bypasses bound check"
  },
  "clause_violated": "C017"
}
```

### Output schema
```json
{
  "bypass_strategies": [
    {
      "strategy": "integer_overflow",
      "description": "overflow the cast to size_t with a very large positive int",
      "target_field": "len",
      "approach": "try values near INT_MAX"
    },
    {
      "strategy": "off_by_one",
      "description": "try len == MAX_HEADER_LEN exactly",
      "target_field": "len",
      "approach": "boundary value"
    }
  ]
}
```

### Deterministic gate
The fuzzer executes these strategies. Only real bypasses count.
If the fuzzer finds no bypass, the mutation stage passes.
The LLM's strategies are hints to the fuzzer — they do not determine
the verdict. The fuzzer's output determines the verdict.

---

## Schema validation

All LLM outputs are validated against their schema before use.

```python
from pydantic import BaseModel, ValidationError

class ClauseProposalOutput(BaseModel):
    clauses: list[ClauseProposal]

def call_llm_with_validation(
    prompt: str,
    output_schema: type[BaseModel],
    model: str,
    max_retries: int = 1,
) -> BaseModel:
    for attempt in range(max_retries + 1):
        raw = llm_call(prompt, model=model)
        try:
            return output_schema.model_validate_json(raw)
        except ValidationError as e:
            if attempt == max_retries:
                raise LLMSchemaError(f"LLM output failed schema validation: {e}")
            # retry once, then raise
```

If schema validation fails after retries, the call is logged to ledger
and the pipeline continues without that result (graceful degradation).

---

## Constrained decoding

If schema adherence drops below ~85% in testing (measure in September),
enable GBNF constrained decoding via llama.cpp:

```python
CLAUSE_PROPOSAL_GRAMMAR = r"""
root   ::= object
object ::= "{" ws "\"clauses\"" ws ":" ws array ws "}"
array  ::= "[" ws (clause ("," ws clause)*)? ws "]"
clause ::= "{" ws fields ws "}"
...
"""
```

This forces the model to produce valid JSON matching the schema.
Half a day of work — discover the need in September, not at the finale.

---

## Token budget

| Call | Typical tokens (in+out) | Model |
|---|---|---|
| Interface hypothesis | ~800 | Qwen3-4B |
| Clause proposal | ~1200 | Qwen3-4B |
| Constraint authoring | ~1500 | Qwen3-Coder-30B-A3B |
| Root-cause hypothesis | ~2000 | Qwen3-Coder-30B-A3B |
| Patch authoring | ~3000 | Qwen3-Coder-30B-A3B |
| Refutation strategy | ~1000 | Qwen3-Coder-30B-A3B |

All token usage is tracked in `state["budget"]["tokens_used"]`.
