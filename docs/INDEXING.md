# Indexing

`INGEST → INDEX → INDEX_VALIDATE → UNDERSTAND`

Indexing is a first-class KavachX stage with its own record, its own identity and its own health
grade. That is a change from the previous build, where indexing was an implementation detail: a
`build_world_model()` call inside a node that also did probing, whose only trace was a symbol
count. An index that silently covered 40% of a repository was indistinguishable from one that
covered all of it — which makes every downstream "we found nothing" unreadable.

Code: [`backend/app/indexing/`](../backend/app/indexing/)

---

## The stage

| Stage | Node | Produces |
| --- | --- | --- |
| `INGEST` | `nodes.node_ingest` | Pinned, content-addressed source tree |
| `INDEX` | `intel_nodes.node_index` | `CodeGraph` + `IndexJob` |
| `INDEX_VALIDATE` | `intel_nodes.node_index_validate` | `IndexHealthReport`, `INDEX_HEALTH.md` |
| `UNDERSTAND` | `intel_nodes.node_understand` | `ApplicationModel`, `AttackSurface` |

Indexing runs against the **mutable `work/` copy**, never `pristine/`. GitNexus writes its
LadybugDB index into a `.gitnexus/` directory inside whatever it analyses, and writing into the
pinned tree would invalidate the content hash that *is* the run's source identity. `.gitnexus` is
therefore in `IGNORED_DIRS` (so the indexer never indexes its own index) and in `PRESERVED_DIRS`
(so a gauntlet workspace reset does not delete the graph the sibling hunt is still querying).

---

## Index identity

The spec's requirement is that

```
repository SHA + indexer version + parser version
```

deterministically identifies an index. `compute_index_id()` implements exactly that:

```
index_id = sha256({
  source_sha256,                    # the pinned tree
  versions.identity_fields(),       # indexer contract + parser + grammar + gitnexus + semgrep
  options,                          # flags that change what the graph contains
})
```

**Deliberately excluded** from the identity:

- timings and counts — they vary between runs of the same index, which would make every id unique
  and defeat the purpose;
- `platform` and `gitnexus_resolution` — how the binary was located and which OS ran it do not
  change what a given GitNexus version extracts from a given tree, and including them would
  fragment the identity across machines for no analytical reason.

**Deliberately included**: `--pdg`, the file-size ceiling, and grammar availability. Two indexes
built with different ceilings, or one with the C grammar and one without, are genuinely different
indexes and must not share an id.

### Verified

Same tree, two separate workspaces, GitNexus enabled:

```
index_id   A=04adf9a6a08a674b1838453a55e5dfc2  B=04adf9a6a08a674b1838453a55e5dfc2   match
graph_hash A=9b02e46bf98ca89ca782f02db7e7e15a  B=9b02e46bf98ca89ca782f02db7e7e15a   match
nodes  A=117 B=117    edges A=168 B=168
```

`graph_hash` is a **structural** digest — uids, kinds, edges, provenance — and deliberately *not*
line numbers or timings, so it identifies the graph rather than the run that built it. Appending a
comment to a source file changes `source_sha256` (and so the change set) but not `graph_hash`,
because the structure is unchanged. Both are recorded; they answer different questions.

---

## The index job record

`IndexJob` records everything the spec's §7 list asks for:

```
repository · commit SHA · source SHA · index id · graph hash · graph source
indexer / parser / grammar / GitNexus / semgrep versions · options
languages detected
files discovered / indexed / skipped (+ the reason per skipped file, named not counted)
symbols · functions · classes
relationships · calls · imports · resolved
entrypoints · tests · configs · dependencies
provider reports · merge report
errors · warnings
status · started_at · completed_at · duration_ms
incremental: changed files, affected symbols
```

`status` has four values, and the third is the one that matters:

| Status | Meaning |
| --- | --- |
| `COMPLETED` | Full-fidelity index, no warnings. |
| `DEGRADED` | Usable, with named gaps — a provider missing, a grammar absent, files skipped. **Distinct from `COMPLETED` so a partial index cannot be read as a complete one, and from `FAILED` so a usable-but-limited index is not thrown away.** |
| `FAILED` | The tree could not be understood. The run aborts rather than reporting "nothing found". |
| `RUNNING` / `PENDING` | In flight. |

---

## Index validation

Successful parsing is not successful indexing. A parser that returns without raising can produce
zero symbols for a whole language, resolve no imports, find no entrypoints, or skip a third of the
tree — and every one of those looks identical from outside: an index object that exists.

Ten deterministic checks run over the produced index
([`health.py`](../backend/app/indexing/health.py)). No model is involved.

| Check | Asks |
| --- | --- |
| `index.non_empty` | Did indexing produce any nodes at all? |
| `index.file_coverage` | Was every discovered file analysed? Which were skipped, and why? |
| `index.symbols` | Were symbols extracted? Are there suspiciously few for the amount of code? |
| `index.relationships` | Were relationships resolved? Any call edges at all? |
| `index.resolution` | What fraction are *resolved references* vs *name matches*? |
| `index.entrypoints` | Were entrypoints found? (If not, reachability is unmeasurable.) |
| `index.grammars` | Is a parser available for every language actually present? |
| `index.provider` | Did the code-knowledge-graph provider run — and if not, was it disabled or did it break? |
| `index.sections` | Are configuration / dependencies / tests suspiciously empty? |
| `index.language_parity` | Does a language present in the tree produce *no* symbols? (A per-language parse failure, invisible in aggregate counts.) |

Each check returns `ok` / `info` / `warn` / `fail` plus — and this is the load-bearing field —
**`bounds_claim`**: what its outcome forbids the run from claiming. Those bounds are collected into
`claim_bounds`, surfaced in the console, and carried into every certificate.

### Grading

```
A   every supported file indexed, relationships largely resolved, entrypoints found
B   usable, with named gaps (missing grammar, skipped files, unresolved imports)
C   substantial gaps: reachability unmeasurable or coverage poor — findings are leads
F   the index cannot support analysis at all
```

Reachability being unmeasurable caps the grade at C on its own, regardless of warning count: it
removes the graph's central capability, and that is a category difference rather than one warning
among several.

### `INDEX_HEALTH.md`

Stored as a run artifact, in the shape the spec lays out:

```
INDEX HEALTH

Repository: examples/vulnerable-demo
Commit: deadbeef
Index:  04adf9a6a08a674b  (gitnexus+tree-sitter)
Grade:  B

Files:
  discovered: 24
  indexed:    24
  skipped:    0

Symbols:
  functions: 26
  classes:   4

Relationships:
  calls:    29
  imports:  28
  resolved: 99 of 168 (59%)

Entrypoints:  4
Tests:        1
Configs:      3
Dependencies: 0

Warnings:
  [WARN] Most relationships are name matches, not resolved references — Only 59% of
  relationships were resolved by a symbol-resolving indexer. The rest are name matches,
  which over-approximate: a call edge may point at a different function that happens to
  share a name.

This index cannot support:
  - a precise reachability claim — paths at 'union' precision may include calls that
    cannot actually occur
```

That last block is the point of the whole stage.

---

## Incremental indexing

The architecture is in place from the start even though the current build still re-parses the tree.
The hard part — and the part every consumer needs — is *what a change affects*, and that is
implemented ([`incremental.py`](../backend/app/indexing/incremental.py)).

`changed_files` compares **content hashes**, not git status. KavachX analyses a pinned,
content-addressed tree that may have no `.git` at all: a downloaded archive, a seeded example, a
sandbox workspace copy. A git-diff-only implementation would silently do nothing on exactly the
targets KavachX is most often pointed at. Where a git checkout *is* available, `git_changed_files()`
is used as a cross-check and unioned in — it can only ever *widen* the change set, never shrink it.

The affected closure walks reverse call edges at `UNION` precision, deliberately: for deciding what
to recompute, over-approximation is the safe direction. Recomputing something unnecessarily costs
time; missing a reverse dependency leaves a stale reachability fact in the index.

### Verified

One comment appended to `src/reportsvc/parser.py`:

```
changed files:        ['src/reportsvc/parser.py']
changed symbols:      7
dependent symbols:    13
dependent files:      2
affected entrypoints: 3   ['src/main.py:main',
                           'src/reportsvc/service.py:entrypoint',
                           'src/reportsvc/service.py:handle']
truncated:            False
```

Identical trees produce an empty change set (`method: content-hash`, `full: False`).

`AffectedClosure.truncated` exists because a partial closure mistaken for a complete one is the
dangerous failure mode here.

---

## What indexing discovers beyond code

Three discoveries are folded into the same graph rather than kept in side-tables, so
"what tests cover this function" and "what configuration reaches this sink" are one query
interface — and so they cannot drift out of sync with the index.

### Tests — [`understanding/tests_discovery.py`](../backend/app/understanding/tests_discovery.py)

Eleven frameworks: pytest, unittest, Hypothesis, Vitest, Jest, Mocha, Go testing, JUnit,
cargo test, RSpec, PHPUnit. Detection is **content-first**: a repository using unittest also names
its files `test_x.py`, and attributing those to pytest would put the wrong runner command in front
of the harness generator.

Test→symbol mapping is static and conservative: a test is linked to a symbol when it references its
name as an identifier (word-boundary matched, so `parse` does not match `parser`). The edge carries
`basis: "static name reference"` and confidence `0.4`, and is **never marked resolved** — so a
static reference can never be read as measured coverage. Real coverage comes from execution.

### Configuration — [`understanding/config_discovery.py`](../backend/app/understanding/config_discovery.py)

Fourteen roles (environment, application, framework, routing, database, authentication, container,
orchestration, CI, dependency manifest, lockfile, build, webserver, generic) and eight
security-relevant setting classes (`debug_enabled`, `bind_all_interfaces`,
`tls_verification_disabled`, `permissive_cors`, `secret_literal`, `auth_disabled`,
`container_runs_as_root`, `privileged_container`).

Data directories (`corpus/`, `fixtures/`, `testdata/`, `__snapshots__`, `locales/`, …) are excluded
from the *generic* fallback. Without that exclusion, every benign-corpus case counts as a
configuration file: on the seeded demo it turned **3 real config files into 15**, inflating the
index counter and feeding the reachability channel a pile of request payloads to chase. An explicit
role rule still wins, so a `docker-compose.yml` inside `fixtures/` is still read as a compose file.

Lockfiles are inventoried but never scanned for settings — thousands of transitive entries produce
only noise.

### Dependencies — [`understanding/dependencies.py`](../backend/app/understanding/dependencies.py)

Fourteen manifest formats and eight lockfile formats. Its purpose is stated narrowly because it is
easy to overreach: dependency information exists to **improve code understanding and candidate
generation**, not to generate vulnerability reports. KavachX has no vulnerability database, so it
cannot know whether an installed version is affected by anything, and emitting "you use pyyaml,
CVE-XXXX exists" from a package name alone is exactly the unverified claim this system avoids.

What it *is* used for: framework identification (which selects the sandbox toolchain image and the
test engine), and `SENSITIVE_LIBRARIES` — a table mapping a package to a *sink class worth looking
for*. That raises the prior on a candidate the static rules find in code. It says "look here", never
"this is vulnerable".

The dependency model lives in `graph.metadata`, not as a graph node. A synthetic "dependency model"
node was counted by `stats()` as one more dependency, so every target reported N+1 dependencies —
including 1 for a target with no manifest at all.

---

## Configuration

| Setting | Default | Effect |
| --- | --- | --- |
| `INDEX_MAX_FILES` | `4000` | Cap on files handed to the indexers. An unbounded parse is a denial-of-service against our own run. |
| `GITNEXUS_ENABLED` | `true` | Enable the code-knowledge-graph provider. |
| `GITNEXUS_BIN` | `""` | Explicit binary path; highest authority in the resolution chain. |
| `GITNEXUS_ALLOW_NPX` | `false` | Allow `npx` fallback. Off by default — see [CODE_GRAPH.md](CODE_GRAPH.md). |
| `GITNEXUS_PDG` | `false` | Build the CFG/PDG substrate. Real time cost. |
| `GITNEXUS_EXTENSION_INSTALL` | `load-only` | Keeps indexing offline. |
| `GITNEXUS_MAX_FILE_SIZE_KB` | `512` | Per-file parse ceiling. |
| `GITNEXUS_ANALYZE_TIMEOUT_SECONDS` | `900` | Hard timeout on the indexer. |

---

## API

| Endpoint | Returns |
| --- | --- |
| `GET /api/runs/{id}/index` | The index job record, health report and claim bounds. |
| `GET /api/runs/{id}/graph` | Graph statistics and entrypoints; `?uid=` for a bounded subgraph. |
| `GET /api/system/gitnexus` | Provider availability, resolution order, licence, degradation note. |

`/graph` never returns the whole graph. The spec asks for focused subgraphs around a finding, an
entrypoint, a function, a sink or a trust boundary, and that is what `uid` + `depth` provide.

---

## Related

- [CODE_GRAPH.md](CODE_GRAPH.md) — the two providers, why both, and the merge.
- [SECURITY_MODEL.md](SECURITY_MODEL.md) — what is layered on top.
- [HONESTY.md](HONESTY.md) — what this layer does *not* do.
