# Demo walkthrough

The seeded target ships in this repository. No network, no external service, no cloud account
required — everything below runs locally and produces real evidence.

---

## Run it

### The self-contained proof (any OS)

```bash
make demo
```

This drives the full loop against the seeded target in-process on SQLite with the deterministic
proposer — no PostgreSQL, no Docker, no keys — and prints the KAVACH SECURITY PROOF with real
reproduction counts, gauntlet stage tallies and certificate hashes.

Without `make`, the same driver is:

```bash
cd backend && uv run pytest -s -v tests/test_e2e.py::test_full_pipeline
```

### Or drive it from the browser

Bring the stack up (`make dev`, or the two `uv run uvicorn` / `npm run dev` processes) then open
<http://localhost:3000> → **Launch Console** → sign in as `demo@kavachx.io` /
`kavachx-demo-2024` → **New Security Run** → **Start KavachX Analysis**.

---

## The target

`examples/vulnerable-demo` is `reportsvc`, a small JSON-request service with four deliberately
seeded weaknesses, each marked in-source with a `SEEDED VULNERABILITY` comment naming its CWE:

| Where | Class | Trigger |
| --- | --- | --- |
| `exporter.export_report` | OS command injection (CWE-78) | `name` is interpolated into a string run through a shell |
| `parser.parse_header` | Unchecked length boundary (CWE-1284) | more than `MAX_HEADER_SLOTS` lines writes past the slot table |
| `assets.read_asset` | Path traversal (CWE-22) | `ASSET_ROOT / relative_path` is never confined to the root |
| `config.DEFAULT_CONFIG` | Debug enabled (CWE-489) | `debug: true`, `bind_host: 0.0.0.0` shipped as defaults |

The comments are there on purpose. The point is that KavachX has to **prove** each one by execution,
not by reading the comment — and one of them it cannot prove, which is just as important.

`corpus/benign/*.json` holds twelve normal requests. KavachX uses them twice: to observe value
profiles while building SAMHITA, and as the reference behaviour for differential replay.

---

## What happens, phase by phase

### Ingest

The tree is copied to `pristine/` and hashed there — **outside** the sandbox. `work/` is the copy the
sandbox executes against. The console header shows the pinned `sha256`.

If the active adapter is the development one, the console says so immediately, in the header and in
the run log:

```
WARNING: DEVELOPMENT ADAPTER. A host subprocess is not an isolation boundary.
```

### Index — the code knowledge graph

Two providers, merged, every edge tagged with the provider that produced it.

```
tree-sitter   24 files → 84 nodes, 106 edges   (name-matched, complete, imprecise)
GitNexus      26 files → 87 nodes,  99 edges   (resolved, precise, incomplete)
                                    ↓ merge
              118 nodes, 168 edges · 57 corroborated · 59% resolved
              graph_source: gitnexus+tree-sitter
              index_id: 04adf9a6a08a674b… (reproducible)
```

`graph_source` names only providers that **actually contributed**. Both are needed, and the demo
target shows exactly why: GitNexus never resolved the cross-file call
`service.handle → parser.parse_header`, and tree-sitter does — by over-approximation. So:

```
parse_header  [resolved] reachable=False        ← GitNexus resolved no such call
parse_header  [union   ] reachable=True conf=0.55 via=tree-sitter
```

Reachability is answered at a **stated precision**, and every claim built on it inherits that.

Without GitNexus installed (`GITNEXUS_ENABLED=false`) the run still works: `graph_source:
tree-sitter`, 0% resolved, and the health report adds the bound. Nothing is faked and nothing is
skipped.

### Index validation — INDEX HEALTH

Ten deterministic checks, then a grade, then the part that matters — **what this index cannot
support**:

```
INDEX HEALTH

Repository: examples/vulnerable-demo
Index:  04adf9a6a08a674b  (gitnexus+tree-sitter)
Grade:  B

Files:          discovered 24 · indexed 24 · skipped 0
Symbols:        functions 26 · classes 4
Relationships:  calls 29 · imports 28 · resolved 99 of 168 (59%)
Entrypoints: 4   Tests: 1   Configs: 3   Dependencies: 0

Warnings:
  [WARN] Most relationships are name matches, not resolved references

This index cannot support:
  - a precise reachability claim — paths at 'union' precision may include calls that
    cannot actually occur
```

Stored as `INDEX_HEALTH.md`. That last block travels into every certificate this run issues.

### Security model — sources, sinks, and real data flows

```
sources 17 · sinks 6 · sanitizers 3 · validators 2 · controls 0
flows 9 (1 taint-proven, 8 call-graph) · reachable 9 · trust boundaries 3
```

The top flow is the seeded vulnerability, with its full path:

```
cli_arg → shell_exec   CWE-78  CRITICAL   basis=call-graph precision=union conf=0.403

  CALL      src/main.py:37                entrypoint src/main.py:main
  SOURCE    src/main.py:38                Command-line arguments are supplied by whoever
                                          invokes the program.
  CALL      src/reportsvc/service.py:86   call into entrypoint
  CALL      src/reportsvc/service.py:29   call into handle
  CALL      src/reportsvc/exporter.py:30  call into export_report
  SINK      src/reportsvc/exporter.py:42  A shell interprets metacharacters, so any
                                          injected token becomes a command.

note: Whether the specific value reaching the sink derives from this source was not proven
      by taint analysis across the call boundary.
```

**This answers the demo's three questions from indexed evidence** rather than from prose: the path is
reachable because a call chain from a `__main__`-guarded entrypoint exists (at union precision, as
stated); the input is untrusted because `cli_arg` crosses the `cli_to_application` boundary; the sink
is security-sensitive because `shell=True` hands a constructed string to a shell.

And it tells you what it has **not** shown.

### Understand — application model and attack surface

```
APPLICATION            cli_tool
  languages            python (9)
ENTRYPOINTS            4, all unauthenticated
  main(argv)   [cli]       src/main.py:37
  main(argv)   [cli]       src/reportsvc/archiver.py:14
  entrypoint() [library]   src/reportsvc/service.py:86
  handle()     [library]   src/reportsvc/service.py:29
TRUST BOUNDARIES       cli_to_application · application_to_filesystem · application_to_shell
SOURCES                cli_arg×7 · deserialized_input×5 · env_var×3 · file_read×1 · stdin×1
SINKS                  filesystem×3 · process_exec×2 · shell_exec×1
SECURITY CONTROLS      none identified
TESTS                  1 file, 11 cases, pytest

NOT KNOWN
  - No authentication or authorisation control was identified anywhere in the tree. That may
    be correct (a library, an internal CLI) or may mean the controls are expressed in a form
    the taxonomy does not recognise — it is not evidence that the application is unprotected.
  - No dependency manifest was found, so the framework picture is derived from imports alone.
```

The attack surface then ranks every flow, with the arithmetic shown:

```
 1. [CRITICAL] cli_arg → shell_exec @ src/reportsvc/exporter.py:42
    entry src/main.py:main  (no control on the path)  priority 0.2398
    priority = severity(1.00) × controllability(0.70) × reachability(1.00)
             × dataflow(0.40) × controls(1.00) × coverage(0.85)
```

Stored as `ARCHITECTURE.md`. **`NOT KNOWN` is part of the deliverable**, not an appendix.

### Probe → World model

The probe proposes interfaces; every field is then **confirmed against the filesystem** before use.
The console shows the confirmation notes:

```
PROBE  (90%)
  hypothesis  The target exposes a single CLI entrypoint taking one JSON request.
  evidence    source root resolved to 'src'
  evidence    selected src/main.py:main — CLI entrypoint with a __main__ guard
  evidence    benign corpus found at corpus/benign (12 cases)
  decision    Entrypoint confirmed: src/main.py:main
```

### SAMHITA

The twelve cases are split — every third held out — and the observation split is executed twice under
the tracing harness. Value profiles are derived from the observation split **only**.

The proposer sees those profiles and nothing else, then the falsifier tests each compiled predicate
against the held-out traces. On a typical run:

```
PHASE samhita  DONE  72 surviving | 20 falsified | 2 iterations | coverage 39.0%
```

Twenty clauses died. That is the mechanism working, not a defect — a bound derived from a partial
sample is exactly the over-fitted claim held-out falsification exists to kill:

```
CLAUSE C027 FALSIFIED   arg_len_fmt <= 3
  reason  held-out case 008-export-json contradicts it (arg_len_fmt=4)
```

Iteration 2 widens the falsified numeric bounds to the value that broke them and re-falsifies. What
survives is admissible evidence; what does not is listed in `REMAINING.md` and never cited.

Clauses that matter later:

```
C088  arg_safe_charset_report_name == True    exporter.py:_archiver_command
C060  arg_lines_raw <= 8                      parser.py:parse_header
C011  shell_command_metachars == 0            (global)
C007  reads_outside_root == 0                 (global)
```

### Discovery — four channels, concurrently

```
graph/static           6 candidates    tree-sitter + AST rules with light taint tracking
config/reachability    2 candidates    debug enabled, binds all interfaces
fuzzing                3 candidates    120 mutated cases executed, 21 crashed, 3 distinct shapes
runtime                1 candidate     a shell was spawned on the benign path
```

The fuzzer is a real seeded mutational campaign (seed `0x4B415641`, reproducible). Crashes are
deduplicated by `(exception type, project crash site)` and the **shortest** reproducing request is
kept.

Correlation merges the static and runtime reports of the same weakness into one hypothesis listing
both channels, and raises confidence for independent corroboration — capped, because agreement
between two heuristics is not proof.

Candidates with no executable plan go straight to the unknown ledger **with a stated reason**:

```
config/reachability: debug mode is enabled
  reason: Debug mode changes error verbosity. The CLI entrypoint returns the same structured
          response either way, so no execution inside the sandbox can distinguish the two states.
```

That is the honest answer. It is not counted as a finding, and it is not silently dropped.

### Test synthesis — candidate to executable harness

The engine inventory is probed **inside the sandbox**, because that is the interpreter a harness
runs in:

```
test engines: 3 available, 7 unavailable, 3 unimplemented
engine NOT RUN: Hypothesis (property-based) cannot run here — missing module(s): hypothesis
engine NOT RUN: Atheris (libFuzzer for Python) cannot run here — missing module(s): atheris
engine NOT RUN: libFuzzer (clang) cannot run here — missing executable(s): clang
```

Seven unavailable engines mean seven strategies reported **NOT RUN** — never "clean".

Then, for the top candidate:

```
[GENERATED] mutation  engine=kx-mutational  oracle=marker_in_stdout
            harness=_kavachx/tests/kx_mutation_c8d66d325df2.py
            mutation families: separator_injection, encoding_variants
```

The harness is a real file, saved verbatim as a run artifact, carrying its own provenance:

```python
# GENERATED BY KAVACHX — DO NOT EDIT
#
# This harness was generated from a validated TestSpec by app/testing/harness.py.
# Every value below was inserted as a data literal; no model-supplied text is executable here.
#
#   plan_id : c8d66d325df2765f
#   target  : src/reportsvc/exporter.py:export_report
#   strategy: mutation
#   oracle  : marker_in_stdout
#   property: cli_arg must not reach the shell_exec operation at
#             src/reportsvc/exporter.py:42 in a form that changes its behaviour
```

With `LLM_PROVIDER=mock` the spec still comes through the model path — the mock has deterministic
scripts for all twelve tasks — so this step is demonstrated **offline, with no API key**. The
`proposed_by` field records whether a spec came from a model or the deterministic fallback.

### Execute — the harness reproduces the vulnerability

```
mutation  reproduced=True  count=2/2  attempts=2
  verdict: The oracle fired in 2 of 2 independent executions (required 2).
  PROOF  : marker_in_stdout: marker present in stdout — The marker appearing in stdout
           proves the injected command executed: nothing in the target's own output can
           produce it.
  attempt 0: exit=1 signals=[] oracle=FIRED
  attempt 1: exit=1 signals=[] oracle=FIRED
  coverage : measured=True pct=20.0
  env      : dev  network_enforced=False
```

The winning payload, recovered from the harness's own report:

```
kavachx-probe&echo KAVACHX_POV_MARKER_7F3A
```

Two independent processes, one deterministic oracle, and a marker nothing in the target's own output
can produce. The `env` line is there because a reproduction under the dev adapter and one under
gVisor are not equally strong evidence, and the certificate records which.

A fuzz or mutation plan whose oracle does **not** fire escalates to a coverage-guided campaign:
uncovered branches are parsed for the literals their conditions compare against, values are derived
from them, and whether an input was good is decided by **whether coverage actually moved** — not by
the model's confidence in it. `FuzzCampaign` records `model_candidates` alongside
`model_candidates_useful`, which is the honest measured score for the model's contribution.

### Validation — the only place a finding is born

Each hypothesis becomes an executable job. For command injection the validator tries each separator
in turn and lets execution decide which works — `;` on `sh`, `&` on `cmd.exe`:

```
VALIDATE H005 command_injection: reproduced=True n=2 clause=C088
  detail: Injected command executed via the ';' separator; the marker appeared in stdout
          on 2 independent runs.
```

Two confirmations, in **independent processes**. A finding is `VALIDATED` only on a deterministic
signal: a marker in stdout, canary content, a nonzero exit, a sanitizer report.

Then two further deterministic checks run on the re-observed exploit trace:

1. **Contract violation** — which surviving clauses are now false? The most specific one is reported,
   ranked by scope, so the certificate quotes the clause a human would say was broken.
2. **Location consistency** — did the function the hypothesis blamed actually execute?

The second one earns its keep on this target. The static rule flags
`EXPORT_ROOT / report_name` in `exporter.py` as a traversal candidate. A traversal payload *does*
escape containment — but through `assets.read_asset`, not the exporter:

```
VALIDATE H004 path_traversal: reproduced=False
  detail: effect reproduced at a different location
  reason: The payload produced the predicted effect, but _archiver_command (exporter.py)
          never executed. The proof does not belong to this location.
```

A false positive killed by evidence, not by a heuristic.

### Shield — protection first

A filter rule is derived from the **validated** proof of vulnerability, then verified twice: does it
block the exploit, and do all twelve benign cases still pass?

```
SHIELD S02 DEPLOYED  blocked=true  benign 12/12 pass
  rule: REJECT export.name WHEN value contains any of ';' '&' '|' '`' '$' '>' '<'
```

A shield that breaks benign behaviour is worse than no shield, so it is rolled back. `TIME TO
PROTECTION` is recorded here — around **16 seconds**.

The shield is then **reverted in the verification workspace** before the gauntlet runs, so the
gauntlet tests the patch rather than the mitigation.

### Root cause and blast radius

The model proposes a root cause; it is accepted only if it lies in indexed project source **and** on
the recorded execution path. Otherwise the analysis falls back to the deepest executed project frame
and marks itself `UNVERIFIED`.

```
BLAST RADIUS
  ROOT CAUSE  src/reportsvc/exporter.py:40
  AFFECTED FUNCTION  export_report
  1 DIRECT CALLERS → 2 TRANSITIVE CALLERS → 2 MODULES → 50 SAMHITA CLAUSES
  REGRESSION SCOPE  module
```

Only the root-cause file may be edited. Callers are in the *regression* scope — they must be
re-verified — but that is not licence to edit them.

### Regression — the reproduction, preserved

Each validated finding's **actual reproducing input** becomes a durable test, and a publishable one:

```
regression plan built from the reproduction record of V01
  harness: _kavachx/tests/kx_regression_ac0adbd38e68.py
  regression on UNPATCHED build: reproduced=True (1/1)
  PROOF: marker_in_stdout: marker present in stdout
  publishable artifact: tests/test_kavachx_regression_v01.py  (pytest — the repository's
                                                               own convention)
```

It is verified against the **unpatched** build first, so the test is known to be capable of firing. A
regression test that has never been shown to fire is not a guard, it is a comment.

The gauntlet then re-runs it against every patch iteration: a patch is not verified until the
original exploit no longer fires. The publishable file is written under `_kavachx/`, **not** into the
target's `tests/` — the target tree is what is under analysis, and the publisher places it at its
intended path only when a pull request is actually opened.

### Patch v1 — and its refutation

The first patch is naive in the way a rushed human fix is naive: block the character you saw in the
report.

```python
+ if ";" in report_name:
+     raise ExportError("illegal character in report name")
```

It closes the reported payload. Then the mutation stage executes nineteen variants:

```
GAUNTLET exploit_mutation  FAIL  v1
  BYPASS FOUND — mutation 'separator:&' still reproduced the vulnerability
  (injected command executed). The patch blocks the reported payload but not this variant.
```

**This refutation is not staged.** The mutation engine ran payloads and one worked. Had none worked,
the stage would have passed. Notice the other three stages passed — the patch was regression-free and
contract-preserving. It was simply still exploitable.

```
╔════════════════════════════════════════════════════════╗
║ PATCH v1 — REFUTED                                     ║
║   Refutation: exploit_mutation                         ║
║   Result: BYPASS FOUND                                 ║
║   Patch withdrawn                                      ║
║   Constraint added: filtering individual characters is  ║
║     insufficient — remove the unsafe construct entirely ║
║   Generating patch iteration 2                          ║
╚════════════════════════════════════════════════════════╝
```

### Patch v2 — the structural fix

The constraint is a hard input to the next synthesis. Iteration 2 removes the shell entirely:

```python
- return f"{sys.executable} -m reportsvc.archiver --name {report_name} --out {target}"
+ return [sys.executable, "-m", "reportsvc.archiver", "--name", report_name, "--out", str(target)]

+ SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
+ if not SAFE_NAME.match(report_name):
+     raise ExportError("report name must match ^[A-Za-z0-9._-]{1,64}$")

- completed = subprocess.run(command, shell=True, …)
+ completed = subprocess.run(command, shell=False, …)
```

With no shell there is no metacharacter to escape, whatever the separator.

```
GAUNTLET exploit_mutation     PASS  19 mutated payloads executed; none reproduced the vulnerability.
GAUNTLET sibling_hunt         PASS  7 candidates examined; none exploitable. 7 remain unproved.
GAUNTLET differential_replay  PASS  All 12 benign cases produced identical behaviour.
GAUNTLET samhita_recheck      PASS  All 50 in-scope clauses still hold.
```

### PRAMAAN

An evidence graph is built, every node hashed, and the certificate refused outright if any claim
points at a node that does not exist.

```
PRAMAAN V02 → LEVEL B   35ff9cd290ae2cda   21 evidence nodes / 21 edges   signature VALID
```

**Level B, not A** — because the sibling hunt shortlisted seven structurally similar paths it could
not prove safe. A candidate probed without effect is *unproved*, not cleared: the probe drives the
same entrypoint operation and may never have executed that function. The certificate names all seven.

### The finding that could not be repaired

`V03` is an `AssetError` escaping the entrypoint — a genuine robustness finding from the fuzzer, with
no repair recipe. It ends honestly:

```
LEVEL R  V03
  limitation: This finding is not repaired.
  limitation: Patch iteration 1 of a maximum 3.
```

Level R can never publish. The API returns `ASSURANCE_LEVEL_R` at 422 if you try.

### Publish

The run parks in `AWAITING_APPROVAL`. The Publisher — the only component with GitHub credentials — has
not been invoked. After approval:

```
V01: published (DRY RUN)  branch=kavachx/6908-v01-24ab4d
  files: src/reportsvc/assets.py
         .kavachx/certificate-V01.json
         .kavachx/CHANGES.md
         .kavachx/REMAINING.md
         .kavachx/V01.patch
V03: Level R — never published
```

`REMAINING.md` goes into the pull request alongside `CHANGES.md`. A reviewer sees what was not proved
in the same place as what was.

---

## What to look at afterwards

### The new artifacts and endpoints

```bash
# the index: identity, provenance, counters, health grade, claim bounds
curl -H "Authorization: Bearer $TOKEN" localhost:8000/api/runs/$RUN/index

# a bounded subgraph around one symbol (never the whole graph)
curl -H "Authorization: Bearer $TOKEN" \
  "localhost:8000/api/runs/$RUN/graph?uid=src/reportsvc/exporter.py:export_report&depth=2"

# sources, sinks, sanitizers, trust boundaries, flows with basis + precision
curl -H "Authorization: Bearer $TOKEN" localhost:8000/api/runs/$RUN/security

# the application model and the ranked attack surface with per-item factors
curl -H "Authorization: Bearer $TOKEN" localhost:8000/api/runs/$RUN/architecture

# every generated test plan and every execution record
curl -H "Authorization: Bearer $TOKEN" localhost:8000/api/runs/$RUN/tests

# exactly what context the model received, and what was dropped for budget
curl -H "Authorization: Bearer $TOKEN" localhost:8000/api/runs/$RUN/contexts

# engine availability, and GitNexus resolution + licence
curl -H "Authorization: Bearer $TOKEN" localhost:8000/api/system/engines
curl -H "Authorization: Bearer $TOKEN" localhost:8000/api/system/gitnexus
```

Artifacts: `INDEX_HEALTH.md`, `ARCHITECTURE.md`, every `generated_test`, every `regression_test`,
`CHANGES.md`, `REMAINING.md`, and one `certificate-*.json` per finding.

### Prove the index is reproducible

Run the demo twice. `index_id` and `graph_hash` are identical, because the identity is
`sha256(source sha + indexer/parser versions + options)` and the graph hash is structural.

### Prove GitNexus is genuinely optional

```bash
GITNEXUS_ENABLED=false make demo
```

The run still finds, tests, validates, repairs and attests. `graph_source` becomes `tree-sitter`,
`resolved_relationship_ratio` becomes `0.0`, and the health report adds a second claim bound. That
degradation is the honest one — and it is also the configuration a commercial deployment must use,
since GitNexus is PolyForm Noncommercial. See [CODE_GRAPH.md](CODE_GRAPH.md).


| Where | What it shows |
| --- | --- |
| Console → **Live** | Pipeline timeline, reasoning trace, resource meter with `EGRESS 0 B`, shields |
| Console → **SAMHITA** | Surviving and falsified clauses, with each rejection's reason |
| Console → **Findings** | Click a row for the investigation view, the reproduction record, and the exploit gate |
| Console → **Patches** | Monaco diff, unified or split, with the refutation banner on v1 |
| Console → **Gauntlet** | Four stages per iteration, with refuting evidence expandable |
| Console → **Evidence** | The graph — click a node to see what references it and what it supports |
| Certificate page | Level badge, signature verification, blast radius, limitations |
| Console → **Audit** | Hash-chained trail, verified by recomputation |
| `REMAINING.md` | The honest ledger |

---

## Try the RBAC asymmetry

Sign in as `developer@kavachx.io` (same password) and open a finding. The **Reveal working exploit**
button is gone, replaced by:

> Your role does not hold `finding:read_pov`. Working exploits are restricted to owners,
> maintainers and security reviewers.

Then sign in as `reviewer@kavachx.io`: the exploit is revealable, but **Approve & publish** is
replaced by `NEEDS patch:publish`. Both attempts — granted and denied — appear in the audit log.

---

## Determinism

The mutational fuzzer is seeded, the case split is deterministic, and the mock proposer is scripted,
so the same target produces the same campaign every run. Exact counts vary slightly with which
separator works on your host shell.

## Not reproducing?

- **No findings** — is `examples/vulnerable-demo` intact? `python examples/vulnerable-demo/src/main.py --request '{"op":"ping"}'` should print `ok: true`.
- **`entrypoint not confirmed`** — the probe could not find a `__main__` guard; check `src/main.py`.
- **No falsified clauses** — the corpus is too small or too uniform to hold anything out.
- **Patch v1 was not refuted** — your shell rejected every mutation separator. Check the mutation
  stage's metrics for what was actually executed.
