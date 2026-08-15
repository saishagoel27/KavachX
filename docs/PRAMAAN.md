# PRAMAAN — Proof-Carrying Repair

*Pramāṇa: a means of valid knowledge; evidence.*

PRAMAAN is an evidence graph plus a signed certificate.
Every claim in the certificate carries provenance edges to the artifact
that established it.

The output is not "fixed". It is a signed certificate at level A, B, C,
or R in which every claim drills to executable evidence.

---

## Why graded assurance, not boolean proof

Fuzzing and replay establish **bounded empirical assurance**, not formal proof.
A rigorous evaluator will dismantle any team that claims otherwise.

The correct language is:
> "bounded empirical assurance, graded and evidenced"

Never say "proven" or "formally verified" unless you have a theorem prover
result in the evidence graph.

---

## Certificate levels

| Level | Requirements | Publish gate |
|---|---|---|
| A | All 4 gauntlet stages pass · full 5000-request replay · all SAMHITA clauses hold · exploit blocked 10/10 | Passes — auto-publish available |
| B | 3 of 4 gauntlet stages pass · partial replay (≥ 1000 requests) · ≥ 80% clauses hold | Passes — human approval required |
| C | Exploit validated · patch builds · limited verification only | Does NOT pass publish gate |
| R | Patch refuted — shield remains deployed, honest failure recorded | Does NOT pass publish gate |

Level C and R findings are still valuable — they appear in REMAINING.md
and the shield remains deployed.

---

## Evidence graph structure

```python
@dataclass
class EvidenceNode:
    node_id:  str
    kind:     Literal[
        "finding",
        "clause",
        "code",
        "graph",
        "runtime",
        "exploit",
        "shield",
        "patch",
        "verification"
    ]
    ref:      str      # storage key or sha256 hash of the artifact
    summary:  str      # one-line human-readable description

@dataclass
class EvidenceEdge:
    from_id:  str
    to_id:    str
    label:    str      # "discovered_by" | "violates" | "root_cause" |
                       # "affects" | "blocked_by" | "fixed_by" | "verified_by"

@dataclass
class EvidenceGraph:
    nodes: dict[str, EvidenceNode]
    edges: list[EvidenceEdge]
```

---

## Example evidence graph (the hdr.c case from the spec)

```
V17 (finding)
├── discovered_by  → N1 (graph/static, query #4)
├── violates       → N2 (SAMHITA clause C017 — header length bound)
├── root_cause     → N3 (code: hdr.c:340)
├── affects        → N4 (graph: 14 callers via impact analysis)
├── runtime        → N5 (trace #9231, sanitizer report)
├── exploit        → N6 (PoV #44, sha256:1f0c…, reproduced 10/10)
├── blocked_by     → N7 (shield: filter rule #3, deployed t+3m20s)
├── fixed_by       → N8 (patch diff, sha256:9c4e…, iteration 2)
└── verified_by    → N9 (gauntlet 4/4 · replay 5000/5000 · clauses 40/40)
```

---

## Builder

`pramaan/graph.py`

```python
class EvidenceGraphBuilder:
    def __init__(self, state: KavachState):
        self.state = state
        self.graph = EvidenceGraph(nodes={}, edges=[])

    def add_finding(self, finding_id: str, channel: str) -> str:
        ...

    def add_clause_violation(self, clause_id: str) -> str:
        ...

    def add_code_evidence(self, file: str, line: int) -> str:
        ...

    def add_graph_evidence(self, callers: list[str]) -> str:
        ...

    def add_runtime_evidence(self, trace_id: str, sanitizer_report: str) -> str:
        ...

    def add_exploit_evidence(self, pov_ref: str, reproduced: int, total: int) -> str:
        ...

    def add_shield(self, shield_id: str) -> str:
        ...

    def add_patch(self, patch_id: str, diff_hash: str) -> str:
        ...

    def add_verification(self, gauntlet: dict, replay_count: int, clauses_held: int) -> str:
        ...

    def link(self, from_id: str, to_id: str, label: str) -> None:
        ...

    def build(self) -> EvidenceGraph:
        ...
```

Every `add_*` method:
1. Creates an `EvidenceNode` with a deterministic `node_id`
2. Stores the artifact reference (hash or storage key) — never the artifact itself
3. Returns the `node_id` for linking

---

## Certificate generation

`pramaan/certificate.py`

```python
class CertificateGenerator:
    def generate(
        self,
        finding_id: str,
        evidence_graph: EvidenceGraph,
        gauntlet_results: dict,
        replay_count: int,
        clauses_held: int,
        total_clauses: int,
    ) -> Certificate:
        level = self._assign_level(gauntlet_results, replay_count, clauses_held, total_clauses)
        evidence_hashes = self._collect_hashes(evidence_graph)
        signature = self._sign(finding_id, level, evidence_hashes)
        return Certificate(
            cert_id=generate_uuid(),
            finding_id=finding_id,
            level=level,
            evidence_hashes=evidence_hashes,
            signed_at=utcnow_iso(),
            signature=signature,
        )
```

---

## Level assignment logic

`pramaan/levels.py`

```python
def assign_level(
    gauntlet: dict,
    replay_count: int,
    clauses_held: int,
    total_clauses: int,
    exploit_reproduced: int,
    exploit_total: int,
) -> Literal["A", "B", "C", "R"]:

    stages = ("mutation", "sibling", "replay", "contract")
    passed = sum(1 for s in stages if gauntlet.get(s) == "pass")

    # R — patch was refuted
    if passed == 0 and gauntlet.get("mutation") == "fail":
        return "R"

    # A — everything passes
    if (passed == 4
            and replay_count >= 5000
            and clauses_held == total_clauses
            and exploit_reproduced == exploit_total):
        return "A"

    # B — mostly passes
    if (passed >= 3
            and replay_count >= 1000
            and clauses_held >= int(total_clauses * 0.8)):
        return "B"

    # C — exploit validated, patch builds, limited verification
    if exploit_reproduced > 0:
        return "C"

    return "R"
```

---

## Signing

For the competition, signing uses HMAC-SHA256 with a run-scoped key.
The key is derived from the run_id and a server secret — never stored in state.

```python
def sign_certificate(
    cert_id: str,
    finding_id: str,
    level: str,
    evidence_hashes: list[str],
    server_secret: bytes,
) -> str:
    payload = json.dumps({
        "cert_id": cert_id,
        "finding_id": finding_id,
        "level": level,
        "evidence_hashes": sorted(evidence_hashes),
    }, sort_keys=True).encode()
    return hmac.new(server_secret, payload, hashlib.sha256).hexdigest()
```

---

## certificate.json output format

This is what gets committed to the pull request:

```json
{
  "cert_id": "cert-7f3a-001",
  "run_id": "run-7f3a",
  "finding_id": "V17",
  "level": "A",
  "signed_at": "2026-10-07T14:23:11Z",
  "signature": "9c4e...",
  "summary": {
    "vulnerability": "heap buffer overflow in parse_header()",
    "root_cause": "hdr.c:340 — signed comparison allows negative length",
    "clause_violated": "C017 — header length bound",
    "shield_deployed_at": "t+3m20s",
    "patch_iteration": 2,
    "exploit_reproduced": "10/10 pre-patch, 0/10 post-patch",
    "replay": "5000/5000 byte-identical",
    "clauses_held": "40/40",
    "affected_callers": 14
  },
  "evidence_graph": {
    "nodes": { ... },
    "edges": [ ... ]
  },
  "evidence_hashes": [
    "sha256:1f0c...",
    "sha256:9c4e...",
    "..."
  ]
}
```

---

## What PRAMAAN never contains

- Raw LLM outputs
- Unverified claims
- Boolean "proven" assertions without supporting evidence nodes
- Anything not traceable to a deterministic artifact

Every node in the evidence graph must have a `ref` that points to
a real, retrievable artifact. If the artifact doesn't exist, the node
doesn't exist.
