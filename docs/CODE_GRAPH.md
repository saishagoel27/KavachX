# The code knowledge graph

Two providers, merged, with per-edge provenance. Neither can replace the other, and the reason is
measurable.

Code: [`backend/app/indexing/model.py`](../backend/app/indexing/model.py),
[`gitnexus.py`](../backend/app/indexing/gitnexus.py),
[`treesitter.py`](../backend/app/indexing/treesitter.py),
[`merge.py`](../backend/app/indexing/merge.py)

---

## Why two providers

**GitNexus** ([github.com/abhigyanpatwari/GitNexus](https://github.com/abhigyanpatwari/GitNexus))
indexes a repository into a LadybugDB knowledge graph. It resolves imports, class heritage, field
types and call targets across files — analysis KavachX's own tree-sitter indexer does not attempt.
Every edge it emits is a **resolved fact**.

**tree-sitter** (KavachX's existing [`analysis/indexer.py`](../backend/app/analysis/indexer.py))
parses Python, C and JavaScript/TypeScript and resolves call sites **by name**, preferring the same
file, then the same module, then anywhere. It over-approximates.

The decisive measurement, taken on `examples/vulnerable-demo` before any of this was designed:

> GitNexus produced 8 `CALLS` edges and **missed the cross-file call
> `service.handle → parser.parse_header` entirely** — `gitnexus impact parse_header` returned
> `impactedCount: 0`. The tree-sitter name-matched graph finds it.

So:

| Provider | Character | Failure mode |
| --- | --- | --- |
| GitNexus | **precise, incomplete** | Misses a call it cannot resolve → a reachable sink looks unreachable |
| tree-sitter | **complete, imprecise** | Matches a name that is a different function → an unreachable sink looks reachable |

A security tool cannot accept either failure mode alone. Keeping both, tagged, means reachability
can be computed at a **stated precision** and the answer records which provider's edges supported
it. A single untagged union would launder an over-approximated guess into a "resolved" claim, which
is precisely the class of dishonesty this system exists to avoid.

---

## The internal model

Nothing outside `app/indexing/` knows a GitNexus node id or a tree-sitter node type. Both are
adapted into one provider-neutral model, which is what makes a third provider addable — or GitNexus
removable — without touching discovery, patching or PRAMAAN.

### Node identity is KavachX's

A uid is `path` for a file and `path:qualname` for a symbol — the same `handle` shape
`analysis/indexer.py` has always produced. Adopting the existing shape rather than inventing one is
what lets the World Model, root-cause verification, blast radius and the sibling hunt keep working
against a graph now assembled from two providers.

GitNexus ids are mapped by stripping the label prefix:

```
Function:src/main.py:main   →   src/main.py:main
File:src/main.py            →   src/main.py
proc_0_entrypoint           →   gitnexus/process:proc_0_entrypoint   (namespaced, not stripped)
```

A prefix is only stripped when it really is a label (capitalised, no `/`, no `.`), so a path-shaped
prefix survives intact.

### Node kinds

```
REPOSITORY DIRECTORY FILE MODULE PACKAGE CLASS INTERFACE FUNCTION METHOD
VARIABLE PARAMETER PROPERTY SYMBOL IMPORT EXPORT DEPENDENCY
TEST CONFIGURATION ENTRYPOINT PROCESS CLUSTER UNKNOWN
```

Wider than any single provider reports: the extra kinds are populated by later stages (tests by the
test discoverer, configuration by config discovery, entrypoints by the probe) so everything the
spec's World Model calls for lives in **one graph** rather than in parallel side-tables that drift.

### Edge kinds

Structural, from the indexers:

```
CONTAINS DEFINES IMPORTS EXPORTS CALLS CALLED_BY INHERITS IMPLEMENTS
MEMBER_OF DEPENDS_ON STEP_IN_PROCESS
```

Semantic, written by the security model over the same graph:

```
READS WRITES PASSES_TO RETURNS_TO REACHES FLOWS_TO TAINTS SANITIZES
VALIDATES EXECUTES TESTED_BY CONFIGURED_BY CROSSES_TRUST_BOUNDARY
```

One graph, so a data-flow edge and a call edge are queryable through one interface.

---

## Provenance and confidence

Every node and edge carries the set of providers that reported it.

```python
class Provider:
    GITNEXUS      # resolved
    TREE_SITTER   # name-matched
    REGEX         # tree-sitter's per-file fallback when no grammar loaded
    SEMGREP       # resolved
    KAVACHX       # own AST rules, taxonomy, test/config discovery
    RUNTIME       # observed executing
```

`RESOLVED_PROVIDERS = {gitnexus, runtime, semgrep}`. An edge is `resolved` when at least one of
those produced it.

tree-sitter call edges are damped by resolution tier and by fan-out:

| Tier | Confidence | Rationale |
| --- | --- | --- |
| same file | 0.75 | A same-file name collision is rare and the enclosing scope is known |
| same module | 0.55 | Plausible, but another module could define the same name |
| anywhere | 0.35 | The tier that produces false call edges |

then divided by the number of candidates (capped at 3): if a name matches five definitions, no
single one of them is a 0.35-confidence call.

`CodeGraph.reachability()` propagates the **weakest hop** along a path, so a reachability claim
resting on three guesses reports lower confidence than one resting on three resolved calls.

### Precision

```python
graph.reachability(uid, precision=Precision.RESOLVED)  # gitnexus/runtime/semgrep edges only
graph.reachability(uid, precision=Precision.UNION)     # + name-matched edges
```

Measured on the demo target, this distinction is real rather than theoretical:

```
src/reportsvc/parser.py:parse_header
  [resolved] reachable=False  measured=True  conf=0.0
  [union   ] reachable=True   measured=True  conf=0.55  via=['tree-sitter']
             path=['src/reportsvc/service.py:handle',
                   'src/reportsvc/parser.py:parse_header']
```

### `measured` is not `reachable`

`ReachabilityResult.measured` is `False` when the graph declares **no entrypoints**. With no
entrypoint there is no path to search, so returning `reachable=False` would let "we could not look"
read as "we looked and found nothing". The hypothesis queue already depends on this distinction to
avoid inverting its ranking on static-only runs.

---

## The merge

`merge_graphs()` folds provider graphs into one:

1. **Union of nodes**, field-merged — a symbol carries GitNexus's `isExported` *and* tree-sitter's
   decorators and parameters. The wider line span wins, because `symbol_at()` needs the true body
   extent to attribute a sink line to its function.
2. **Union of edges, provenance preserved.** An edge both providers found is corroborated and
   promoted to confidence 1.0. This is the only path by which a name-matched edge becomes resolved,
   and only because a resolving provider independently produced the same edge.
3. **A derived `graph_source`.**

### The provenance bug this replaced

The previous build did this:

```python
def _gitnexus_available() -> bool:
    if shutil.which("gitnexus"):
        return True
    ...

if _gitnexus_available():
    model.graph_source = "gitnexus+tree-sitter"
```

GitNexus was **never invoked**. Any host with a `gitnexus` binary on `PATH` — installed for
anything, or for nothing — produced runs labelled `gitnexus+tree-sitter`, and that label travelled
into every certificate, where the fidelity of every reachability claim depends on exactly this
field.

`describe_source()` now computes the label from actual node/edge contribution, and the end-to-end
test asserts the invariant directly:

```python
for provider in source.split("+"):
    assert provider in index_payload["index"]["providers"], (
        f"graph_source claims {provider!r} but the index does not list it as a contributor"
    )
```

### Measured on the demo target

With GitNexus:

```
providers=['gitnexus', 'tree-sitter']
gitnexus:    87 nodes,  99 edges
tree-sitter: 84 nodes, 106 edges
merged:     118 nodes, 168 edges
corroborated edges: 57
resolved-only:      42
name-matched-only:  49
resolved ratio:     0.589
graph_source: gitnexus+tree-sitter
index grade: B
```

Without GitNexus (`GITNEXUS_ENABLED=false`):

```
providers=['tree-sitter']
merged: 88 nodes, 126 edges
resolved ratio: 0.0
graph_source: tree-sitter
index grade: B
claim bounds:
  - a precise reachability claim …
  - a resolved (non-approximated) reachability claim
```

Both are usable. Only one can support a resolved reachability claim, and the run says which.

---

## The GitNexus adapter

Built against verified behaviour of 1.6.9 rather than assumption. Each of these caused a real bug
during integration.

### `.gitnexus/` goes inside the analysed tree

A LadybugDB file (3.7 MB on a 26-file repo) plus `meta.json`, `gitnexus.json` and a parse cache.
Hence `work/` not `pristine/`, and `.gitnexus` in both `IGNORED_DIRS` and `PRESERVED_DIRS`.

### The registry is machine-global and keyed by directory basename

`~/.gitnexus/registry.json`. This host already had a `mem0` entry from unrelated prior use, and a
query with no `-r` **fails outright** once any second repository exists:

```
Error: Multiple repositories indexed. Specify which one with the "repo" parameter.
Available: mem0, target-demo
```

Every KavachX workspace directory is named `work`. So the adapter registers a unique alias per
index — `kavachx-<run>-<index_id[:10]>` — passes `-r <alias>` on **every** query, and deregisters on
teardown so the global registry does not accumulate one dead entry per run.

### Flags that are not optional

| Flag | Why |
| --- | --- |
| `--skip-git` | The workspace lives inside the KavachX checkout. Without this, GitNexus walks up to the nearest `.git` and indexes **KavachX itself** instead of the target. |
| `--index-only` | Suppresses every file-injection side effect (`AGENTS.md`, `CLAUDE.md`, `.claude/skills/`). Writing agent instructions into a tree under security analysis would corrupt the pinned artifact *and* hand repository-adjacent text a channel into an agent's prompt. |
| `--name <alias>` | Registry identity, per above. |
| `--max-file-size` | Bounded parse cost on a hostile tree. |

### Output parsing

Query subcommands print JSON on stdout via `fs.writeSync(1, JSON.stringify(x, null, 2))`; pino
warnings go to stderr. So stdout is parsed and stderr is only logged.

`cypher` returns `{"markdown": "<pipe table>", "row_count": N}` for tabular results. Returning a
whole node embeds a JSON blob in a table cell, so every query here selects **scalar columns only**
and the pipe table is parsed deterministically. A malformed row is skipped rather than guessed at.

`impact`, `context` and `trace` return structured JSON directly.

### The graph schema, as observed

```
node labels:  Function File Variable Folder Section Community Class Property Process
one relationship table `CodeRelation`, discriminated by r.type:
  DEFINES(43) CONTAINS(31) MEMBER_OF(11) CALLS(8) IMPORTS(3) STEP_IN_PROCESS(3)
node props:   id, name, filePath, startLine, endLine, isExported, content, description
```

An unmapped `r.type` is recorded as `UNKNOWN` with the original type in `attrs` and raises an index
warning — a new GitNexus release adds relationships we can still see rather than silently dropping.

### Windows

The npm shim ships three spellings: an extensionless shell script, a `.cmd`, and a `.ps1`. Only the
`.cmd` is launchable by `CreateProcess`. Handing `subprocess` the extensionless one fails with

```
[WinError 193] %1 is not a valid Win32 application
```

which looks like "GitNexus is broken" rather than "wrong spelling picked". `_windows_variants()`
resolves `.cmd` first, and `_probe_version()` now returns the underlying error so the reason reaches
the operator instead of only the log.

---

## Installation

GitNexus is resolved in a documented order of authority:

```
GITNEXUS_BIN  →  PATH  →  <repo>/node_modules/.bin  →  npx (opt-in)
```

`npx` is last and **off by default**: it reaches the network on first use per machine and is slow,
and an indexer that silently downloads a package mid-run is not something a security tool should do
unasked.

Repo-local install:

```bash
make gitnexus       # GITNEXUS_SKIP_OPTIONAL_GRAMMARS=1 npm install, at the repository root
make gitnexus-doctor
```

Requires Node ≥ 22. Verified: 254 packages in ~35 s; `@ladybugdb/core` and the tree-sitter
prebuilds resolved without a compiler on Windows.

Indexing the 26-file demo target takes **13–22 s**, dominated by Node startup and LadybugDB init
rather than parsing. FTS/BM25 and vector search degrade to unavailable offline
(`GITNEXUS_LBUG_EXTENSION_INSTALL=load-only`), which costs nothing: KavachX uses the graph, not the
search.

---

## Licence

**GitNexus is licensed [PolyForm Noncommercial 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0/).**
KavachX is not.

This is why GitNexus is an **optional provider** and not a hard dependency. The choice is
deliberate and has two consequences worth stating plainly:

- A **non-commercial** deployment (research, evaluation, education) can install it and gets a
  resolved code graph.
- A **commercial** deployment must either obtain a commercial licence from the GitNexus authors or
  run with `GITNEXUS_ENABLED=false`. In the second case KavachX still indexes, still builds the
  security graph, still generates and executes tests, still validates, repairs and attests — every
  relationship is a name match, the index health report caps the grade and records the bound, and
  every certificate carries `graph_source: tree-sitter` and `resolved_relationship_ratio: 0.0`.

Attribution and the licence are reported at runtime by `GET /api/system/gitnexus`, so an operator
does not have to read this file to find out.

`package.json` at the repository root declares the dependency and carries
`"license": "SEE LICENSE IN docs/CODE_GRAPH.md"` rather than asserting a licence of its own.

---

## Querying the graph

```python
graph.node(uid)                        graph.find_by_name("handle")
graph.search_symbols("export")         graph.symbol_at("src/x.py", 42)
graph.callers(uid, precision=...)      graph.callees(uid, precision=...)
graph.transitive_callers(uid)          graph.siblings_of(uid)
graph.imports_of(file_uid)             graph.members_of(uid)
graph.reachability(uid, precision=...) graph.path_between(src, dst, precision=...)
graph.reachability_score(uid)          graph.blast_radius_score(uid)
graph.subgraph(uid, depth=2)           graph.stats()
graph.content_hash()
```

The same surface is exposed to the reasoning layer as read-only tools — see [LLM.md](LLM.md).

---

## Related

- [INDEXING.md](INDEXING.md) — the stage, identity, health and incremental support.
- [SECURITY_MODEL.md](SECURITY_MODEL.md) — the security semantics layered over this graph.
- [HONESTY.md](HONESTY.md) — the limits.
