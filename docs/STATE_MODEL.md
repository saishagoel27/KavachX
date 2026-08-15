# State Model

KavachX uses a single TypedDict — `KavachState` — as the source of truth
for an entire run. Every LangGraph node reads from it and writes back to it.
Every field is persisted to Postgres after each node completes.

---

## The golden rule

`world` stores **handles**, not contents.

Agents never load a repository into a context window.
They ask the graph targeted questions via handles.
This is both the correctness fix and the resource-utilisation story.

---

## Full definition

```python
from typing import TypedDict, Literal, Optional

class KavachState(TypedDict):

    # ── Identity ──────────────────────────────────────────────────────────
    run_id:   str          # UUID, assigned at ingest
    phase:    str          # current pipeline phase name
    tenant_id: str         # organisation identifier (RLS key)

    # ── Target ────────────────────────────────────────────────────────────
    target: dict
    # {
    #   "kind":        "repo" | "binary" | "service",
    #   "url":         str,          # repo URL or service address
    #   "commit_sha":  str,          # pinned at ingest, never changes
    #   "tarball_ref": str,          # storage key for pre-fetched tarball
    #   "adapter":     "A" | "B" | "C",
    #   "language":    str | None,   # detected primary language
    #   "build_cmd":   str | None,   # detected or synthesised
    # }

    # ── World (graph handles only) ─────────────────────────────────────────
    world: dict
    # {
    #   "graph_handle":    str,   # GitNexus graph ID
    #   "ast_handle":      str,   # tree-sitter AST store key
    #   "semgrep_handle":  str,   # Semgrep results store key
    #   "deploy_handle":   str,   # deployment graph store key
    #   "corpus_handle":   str,   # benign corpus store key
    # }
    # NEVER put file contents, AST nodes, or graph edges here directly.

    # ── Contract (SAMHITA) ────────────────────────────────────────────────
    samhita: list
    # list of clause dicts:
    # {
    #   "clause_id":   str,
    #   "predicate":   str,        # executable predicate in clause DSL
    #   "scope":       str,        # function / module / boundary
    #   "obs_n":       int,        # number of observations used
    #   "status":      "active" | "refuted" | "superseded",
    #   "added_iter":  int,        # which iteration added this clause
    # }

    benign_corpus_ref: str
    # storage key for the recorded benign request corpus
    # this IS the regression oracle — the target never shipped one

    # ── Discovery ─────────────────────────────────────────────────────────
    hypotheses: list
    # list of hypothesis dicts:
    # {
    #   "hyp_id":       str,
    #   "channel":      "graph_static" | "config" | "fuzz" | "constraint",
    #   "clause_id":    str | None,   # which clause this targets
    #   "location":     str,          # file:line or function name
    #   "confidence":   float,        # 0.0 – 1.0
    #   "reachability": float,        # 0.0 – 1.0 from graph
    #   "blast_radius": int,          # estimated affected callers
    #   "priority":     float,        # reachability × confidence × blast
    #   "status":       "pending" | "validated" | "unconfirmed" | "refuted",
    # }

    validated: list
    # subset of hypotheses where status == "validated"
    # each entry has an additional "exploit_ref" key pointing to sandbox output

    downgraded: list
    # hypotheses that could not be validated — kept for REMAINING.md
    # each entry has a "reason" key explaining why

    # ── Attack graph ──────────────────────────────────────────────────────
    attack_graph: dict
    # {
    #   "nodes": [...],   # validated findings as nodes
    #   "edges": [...],   # attack path edges between nodes
    #   "paths": [...],   # ranked attack paths
    # }

    priority: list
    # ordered list of finding IDs by attack-path priority
    # "fixing this closes N downstream attack paths" ordering

    # ── Shields ───────────────────────────────────────────────────────────
    shields: list
    # list of shield dicts:
    # {
    #   "shield_id":        str,
    #   "finding_id":       str,
    #   "rule":             str,      # seccomp filter / input-filter / LD_PRELOAD
    #   "revert_cmd":       str,      # how to undo this shield
    #   "verified_blocked": bool,     # exploit is blocked with shield active
    #   "verified_benign":  bool,     # benign corpus still passes
    #   "deployed_at":      str,      # ISO timestamp
    # }
    # Shield is deployed BEFORE patch synthesis.
    # It remains deployed even if patch is refuted (record_honest_failure).

    # ── Patches ───────────────────────────────────────────────────────────
    patches: list
    # list of patch attempt dicts:
    # {
    #   "patch_id":      str,
    #   "finding_id":    str,
    #   "diff":          str,         # unified diff
    #   "diff_hash":     str,         # sha256 of diff
    #   "root_cause":    str,         # file:line of actual root cause
    #   "blast_radius":  list[str],   # files in regression scope
    #   "iter":          int,         # which iteration (1, 2, or 3)
    #   "status":        "pending" | "passed" | "refuted",
    #   "refuting_input": str | None, # the input that broke it
    # }

    patch_iter: int
    # current patch iteration count for the active finding
    # hard cap: 3

    # ── Gauntlet ──────────────────────────────────────────────────────────
    gauntlet: dict
    # per-stage verdicts for the current patch attempt:
    # {
    #   "mutation":  "pass" | "fail" | "pending",
    #   "sibling":   "pass" | "fail" | "pending",
    #   "replay":    "pass" | "fail" | "pending",
    #   "contract":  "pass" | "fail" | "pending",
    #   "detail":    { stage: str }   # failure detail per stage
    # }

    # ── PRAMAAN ───────────────────────────────────────────────────────────
    pramaan: dict
    # evidence graph:
    # {
    #   "nodes": {
    #     node_id: {
    #       "kind":      "finding" | "clause" | "code" | "graph" |
    #                    "runtime" | "exploit" | "shield" | "patch" |
    #                    "verification",
    #       "ref":       str,    # storage key or hash
    #       "summary":   str,
    #     }
    #   },
    #   "edges": [
    #     { "from": node_id, "to": node_id, "label": str }
    #   ]
    # }

    certificates: list
    # list of certificate dicts:
    # {
    #   "cert_id":        str,
    #   "finding_id":     str,
    #   "level":          "A" | "B" | "C" | "R",
    #   "evidence_hashes": list[str],
    #   "signed_at":      str,        # ISO timestamp
    #   "signature":      str,        # HMAC or asymmetric sig
    # }

    # ── Ledger ────────────────────────────────────────────────────────────
    ledger: list
    # append-only log of every notable event:
    # {
    #   "event":     str,    # "stall" | "refutation" | "unreached_branch" | ...
    #   "cause":     str,
    #   "node":      str,    # which pipeline node
    #   "timestamp": str,
    # }
    # This feeds REMAINING.md — nothing is ever silently discarded.

    # ── Budget ────────────────────────────────────────────────────────────
    budget: dict
    # {
    #   "tokens_used":    int,
    #   "llm_calls":      int,
    #   "yield_per_node": { node_name: float },
    #   "wall_seconds":   float,
    # }

    # ── Iteration caps ────────────────────────────────────────────────────
    iter: dict
    # {
    #   "harness": int,   # max 3
    #   "patch":   int,   # max 3
    #   "clause":  int,   # max 2
    # }
```

---

## Initialisation

When a run starts, `KavachState` is initialised like this:

```python
def initial_state(run_id: str, tenant_id: str, target: dict) -> KavachState:
    return KavachState(
        run_id=run_id,
        phase="ingest",
        tenant_id=tenant_id,
        target=target,
        world={},
        samhita=[],
        benign_corpus_ref="",
        hypotheses=[],
        validated=[],
        downgraded=[],
        attack_graph={"nodes": [], "edges": [], "paths": []},
        priority=[],
        shields=[],
        patches=[],
        patch_iter=0,
        gauntlet={
            "mutation": "pending",
            "sibling": "pending",
            "replay": "pending",
            "contract": "pending",
            "detail": {}
        },
        pramaan={"nodes": {}, "edges": []},
        certificates=[],
        ledger=[],
        budget={
            "tokens_used": 0,
            "llm_calls": 0,
            "yield_per_node": {},
            "wall_seconds": 0.0
        },
        iter={"harness": 0, "patch": 0, "clause": 0},
    )
```

---

## Phase transitions

```
ingest
  → index_repo
  → contract_synthesis
  → discovery_fanout
  → hypothesis_queue
  → validate
  → correlate
  → patch_synthesis
  → blast_radius
  → gauntlet
  → attest              (all gauntlet stages pass)
  → record_honest_failure  (patch_iter >= 3)
  → publish_gate
  → publisher
  → done
```

---

## Persistence contract

After every node completes:
1. The full state is serialised to Postgres (via LangGraph checkpointer)
2. The `phase` field is updated to the next node name
3. The `ledger` is appended with any notable events from that node
4. The `budget` is updated with token/time costs

If the process dies between nodes, the next startup reads the last
checkpoint and resumes from there. No node is ever re-run unless
explicitly retried.

---

## What never goes in state

- File contents
- AST nodes or graph edges (use handles in `world`)
- Raw LLM outputs (only validated, schema-checked results)
- Credentials of any kind
- Sandbox internals
