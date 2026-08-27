# The security model

Sources, sinks, sanitizers, validators, auth controls, trust boundaries and data flows, layered over
the general code graph.

Code: [`backend/app/security_model/`](../backend/app/security_model/)

The code graph knows that `handle` calls `export_report`. The security graph knows that an
attacker-controlled request field reaches a **shell invocation** through that call, that nothing
sanitised it on the way, and that the path crosses the CLI→application and application→shell trust
boundaries.

---

## The central object

`SecurityFlow` exists so the reasoning layer receives a **structured path** rather than being asked
to infer one from a pile of source, and so every claim about that path traces to the evidence that
produced it.

```
ref                          flow:<source ref>-><sink ref>
source_kind / sink_kind      what enters, what it reaches
cwe / severity               from the sink class, never invented
steps[]                      the ordered path, entrypoint-first
call_path[]                  code-graph uids the value passes through
basis                        taint | call-graph | proximity
precision                    resolved | union
sanitizers[] / validators[]  controls found on *this value*
boundaries[]                 trust boundaries crossed
entrypoint                   where an attacker can reach it
reachable_from_entrypoint    …and whether they can
reachability_measured        …or whether that could not be determined
interpolated                 was the value formatted into a string (the injection shape)
confidence                   deterministic, derived from all of the above
covering_tests[]             tests that statically reference any symbol on the path
notes[]                      what this flow does NOT establish
```

**A flow is never a finding.** It is the best-evidenced hypothesis the static layer can produce.
`app/validator` still has to reproduce it by execution before anything is called validated.

---

## The taxonomy is a registry, not a list

[`taxonomy.py`](../backend/app/security_model/taxonomy.py) ships defaults;
`load_taxonomy()` merges an operator JSON file over them. A rule reusing a built-in `id` **replaces**
it, which is how a deployment tightens or silences a noisy shipped rule (set its confidence to 0)
without forking KavachX.

That extensibility is a requirement, not a nicety: a taxonomy that only knows Flask and `subprocess`
will report a clean result on a codebase built from anything else, and "clean" is the most expensive
thing this system can get wrong.

```jsonc
// SECURITY_TAXONOMY_PATH=/etc/kavachx/taxonomy.json
{
  "sources": [
    { "id": "src.py.ourframework.body", "kind": "http_body",
      "pattern": "\\bctx\\.payload\\b", "languages": ["python"],
      "why": "Our framework's request payload.", "confidence": 0.95 }
  ],
  "sinks": [
    { "id": "sink.py.ourorm.raw", "kind": "sql", "cwe": "CWE-89", "severity": "CRITICAL",
      "pattern": "\\bOurOrm\\.raw\\s*\\(", "callables": ["OurOrm.raw"],
      "why": "Raw SQL bypasses the query builder.", "confidence": 0.9 }
  ],
  "sanitizers": [], "validators": [], "controls": []
}
```

A malformed file is recorded in `errors` and the **defaults still load** — a typo in an override
must not silently disable security analysis. A bad regex is rejected at load time, not at match
time on every line.

### Categories

```
SOURCE  SINK  SANITIZER  VALIDATOR
AUTHENTICATION_CHECK  AUTHORIZATION_CHECK
TRUST_BOUNDARY  EXTERNAL_INPUT  SENSITIVE_DATA  DANGEROUS_OPERATION
```

### Source kinds (16)

```
http_param http_body http_header http_cookie http_path uploaded_file
env_var cli_arg stdin file_read db_record message_queue ipc
user_config network_response deserialized_input
```

### Sink kinds (20)

```
sql shell_exec process_exec template_render deserialisation filesystem
path_construction network_request dynamic_eval dynamic_import html_output
auth_decision authz_decision crypto log_write memory_copy memory_alloc
indexed_write xml_parse redirect
```

### Trust boundaries (11)

```
http_to_application       cli_to_application        environment_to_application
file_to_application       queue_to_application
application_to_database   application_to_shell      application_to_filesystem
application_to_network    application_to_template   application_to_deserialiser
```

Derived from `(source_kind, sink_kind)`, so a boundary crossing is a consequence of the flow rather
than a separate assertion.

---

## Taint analysis

[`taint.py`](../backend/app/security_model/taint.py) — intra-procedural, Python.

The alternative — "a source rule matched somewhere in this function and a sink rule matched
somewhere in this function, therefore data flows between them" — produces a flow for every function
that happens to touch both, and misses the thing that matters: whether the value reaching the sink
is *the same value*, and whether anything constrained it.

Taint propagates through assignments, annotated assignments, augmented assignments, f-strings,
concatenation, `%` formatting, containers, dict keys and values, comprehensions, conditional
expressions, unpacking, subscripts, attribute access, `await`, and calls.

### Stated limits

- **Intra-procedural.** Crossing a function boundary is the code graph's job; the flow builder
  stitches per-function results along call edges. This module never guesses *across* a call.
- **Python only.** Other languages fall back to the builder's line-proximity heuristic, recorded as
  a lower-confidence `basis` rather than presented as taint.
- **A sanitizer lowers confidence; it never clears the flow.** Whether the sanitiser actually ran on
  the exploit input is a runtime question the sandbox answers. A static "this is sanitised,
  therefore safe" conclusion is the false negative that makes static analysis untrustworthy.
- **Field/subscript sensitivity is shallow.** `request.args["a"]` taints the whole expression;
  KavachX does not track which key. Over-approximating within a tainted container is the safe
  direction.
- **Any unrecognised call preserves taint.** Assuming a helper launders its input is how a real flow
  gets lost.

### The false positive this design caught

Call-target matching originally fell back to the **last dotted segment**, so a rule for
`pickle.loads` matched `json.loads`. On the demo target that produced:

```
stdin → deserialisation   cwe=CWE-502  sev=CRITICAL  conf=0.92
  SINK  src/main.py:34   "Unpickling untrusted bytes executes arbitrary constructors."
```

`src/main.py:34` is `return json.loads(data)` — entirely safe. A CRITICAL
arbitrary-code-execution false positive at 0.92 confidence.

The fix distinguishes two matching modes, and the distinction is load-bearing:

| Call shape | Matching |
| --- | --- |
| **dotted** (`json.loads`) | requires an **exact** dotted match — an explicitly qualified call has already said which module it belongs to |
| **bare** (`loads` after `from pickle import loads`) | may match a rule's callable on its last segment, because the qualifier genuinely is not in the call |

Collapsing them is not a small imprecision. It is the difference between a usable tool and one
nobody trusts.

A related overbreadth: the `path_basename` sanitizer pattern included `\.name\b`, which matches
every `foo.name` in a codebase. Because a sanitizer on a path *lowers* a flow's confidence, that
would have quietly suppressed real flows.

---

## Building flows

[`builder.py`](../backend/app/security_model/builder.py) — three deterministic passes.

### 1. Classify

Every line of every indexed file is matched against the taxonomy, producing security nodes
attributed to the enclosing callable via `graph.symbol_at()`.

Comments are skipped: a docstring mentioning `os.system` is not a shell sink, and comment lines are
the single largest source of static-analysis noise. Files the indexer marked
`skipped_reason` (minified bundles) are skipped too — scanning them would reintroduce exactly the
noise the indexer removed.

### 2. Establish flows, in descending order of evidential strength

| Basis | Established by | Confidence |
| --- | --- | --- |
| `taint` | The AST analyser proved derivation within one function | rule prior ±adjustments |
| `call-graph` | Source in A, sink in B, with a call path A→…→B | ×1.0 resolved / ×0.6 union, ×hop decay |
| `proximity` | Same function, no taint analyser for that language | ×0.5, explicitly labelled |

`RESOLVED` precision is searched **first**; `UNION` is the fallback and the flow records which was
used. This is where the resolved graph pays for itself.

Python is never given a proximity flow: it was taint-analysed, and if taint did not prove the pair,
recording a proximity flow would manufacture a claim the stronger analysis already declined.

### 3. Score and bound

Reachability from a declared entrypoint (prepending the entrypoint hops so the flow reads from the
outside in — the order a reviewer thinks in), trust boundaries, covering tests, deterministic
confidence.

An **unreachable flow is not deleted**. An internal helper reached only through a call KavachX could
not resolve is still worth a human look; it is scored down (×0.5) and annotated instead.

---

## Measured on the demo target

```
sources: 17   sinks: 6   sanitizers: 3   validators: 2   controls: 0
flows: 9      reachable: 9   sanitized: 0   unmeasured: 0
trust boundaries: 3
by_source_kind: {cli_arg: 7, deserialized_input: 5, env_var: 3, file_read: 1, stdin: 1}
by_sink_kind:   {filesystem: 3, process_exec: 2, shell_exec: 1}
by_flow_basis:  {call-graph: 8, taint: 1}
parse errors: 0
```

The top flow is the seeded vulnerability:

```
flow:sec:source:src/main.py:38->sec:sink:src/reportsvc/exporter.py:42
cli_arg -> shell_exec   cwe=CWE-78 sev=CRITICAL
basis=call-graph precision=union conf=0.403 reachable=True sanitized=False

  CALL      src/main.py:37                  entrypoint src/main.py:main
  SOURCE    src/main.py:38                  Command-line arguments are supplied by whoever
                                            invokes the program.
  CALL      src/reportsvc/service.py:86     call into entrypoint
  CALL      src/reportsvc/service.py:29     call into handle
  CALL      src/reportsvc/exporter.py:30    call into export_report
  SINK      src/reportsvc/exporter.py:42    A shell interprets metacharacters, so any injected
                                            token becomes a command.

covered by: ['test:tests/test_service.py']
note: Call path of 4 hop(s) … at union precision. Whether the specific value reaching the
      sink derives from this source was not proven by taint analysis across the call boundary.
```

That last note is the flow telling you what it has *not* shown. `controls: 0` is correct — the demo
target has no authentication — and the architecture model reports it as a stated gap rather than as
a finding.

---

## Ordering

`top_flows()` orders by **reachability, then severity, then confidence**.

Severity must precede confidence. This ordering drives both the console and which flows are selected
into the model's context, and sorting on confidence alone put a MEDIUM path-traversal candidate above
a CRITICAL shell injection on the demo target — purely because the traversal happened to be
taint-proven within one function while the injection crossed three call boundaries. A reviewer
reading top-down needs the remote-code-execution first.

Confidence still decides *within* a severity band, and the confidence number itself is never
adjusted to achieve an ordering: it keeps meaning "how strong is the evidence".

---

## The attack surface

[`understanding/attack_surface.py`](../backend/app/understanding/attack_surface.py) answers the
narrower question a reviewer starts from: *which externally reachable entry points lead to dangerous
operations, and in what order should they be looked at?*

Priority is a **product** of six factors in (0,1], each recorded on the item:

```
priority = severity × external_controllability × reachability
         × dataflow_confidence × controls × coverage
```

A product, not a sum, because these are conjunctive: a CRITICAL sink nothing can reach and a
trivially reachable INFO log write should both rank low, and a sum lets one large factor carry an
item that fails on every other axis.

- **external_controllability** — 1.0 remote (HTTP), 0.7 local invoker (argv/stdin/env), 0.4 indirect.
- **reachability** — 1.0 reachable; 0.25 measured-unreachable; **severity substitutes when
  unmeasurable**, the same substitution the hypothesis queue already makes and for the same reason: a
  uniform floor inverts the ranking rather than merely flattening it.
- **controls** — ×0.6 for an auth control on the path, ×0.7 more for a sanitizer. Priority is
  reduced; the item is never removed.
- **coverage** — an untested path scores *higher* (1.0 vs 0.85). Nothing is watching it.

Every item carries `rationale`, beginning with the arithmetic:

```
priority = severity(1.00) × controllability(0.70) × reachability(1.00)
         × dataflow(0.40) × controls(1.00) × coverage(0.85)   =  0.2398
```

`AttackSurface.measured` is `False` when the graph had no entrypoints: an unknown surface, not an
empty one. `unreached_sinks` carries an explicit note that it is **not a clearance** — an unresolved
call edge, a framework-dispatched handler, or a language without full call resolution all produce the
same result.

---

## Configuration

| Setting | Default | Effect |
| --- | --- | --- |
| `SECURITY_TAXONOMY_PATH` | `""` | JSON file of extra/replacement rules. |

Caps: 20,000 candidate (source, sink) pairs for cross-function stitching, 2,000 retained flows,
800 KB per file scanned. Every cap that bites emits a warning naming what was dropped — silent
truncation reads as "covered everything" when it did not.

---

## API

| Endpoint | Returns |
| --- | --- |
| `GET /api/runs/{id}/security` | Stats, nodes, flows, trust boundaries, taxonomy provenance, parse errors. |
| `GET /api/runs/{id}/architecture` | The application model and ranked attack surface. |

---

## Related

- [CODE_GRAPH.md](CODE_GRAPH.md) — the graph this is layered over, and what precision means.
- [TEST_SYNTHESIS.md](TEST_SYNTHESIS.md) — how a flow becomes an executable test.
- [HONESTY.md](HONESTY.md) — what this layer does not establish.
