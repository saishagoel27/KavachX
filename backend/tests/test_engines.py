"""SAMHITA, hypothesis queue, blast radius, policy gate, assurance grading and PRAMAAN."""

from __future__ import annotations

import logging
import uuid
from pathlib import Path

import pytest

from app.analysis.world_model import build_world_model
from app.db.session import session_scope
from app.discovery.base import HypothesisCandidate
from app.discovery.queue import HypothesisQueue, correlation_key
from app.models.enums import (
    AssuranceLevel,
    DiscoveryChannel,
    HypothesisStatus,
    Severity,
    Verdict,
)
from app.patching import blast_radius
from app.patching.diffing import (
    DiffApplyError,
    apply_unified_diff,
    diff_stats,
    make_unified_diff,
)
from app.patching.policy import PolicyConfig, evaluate
from app.pramaan import assurance
from app.pramaan.certificate import verify_certificate
from app.pramaan.graph import EvidenceGraph
from app.samhita.compiler import ClauseCompileError, compile_predicate
from app.samhita.falsifier import evaluate_clause, falsify_proposal, scope_matches
from app.samhita.observation import ObservationRecord, derive_value_profiles, split_cases


# ---------------------------------------------------------------------------
# SAMHITA clause compiler — the whitelist is the security property
# ---------------------------------------------------------------------------
def test_compiler_accepts_simple_bound():
    compiled = compile_predicate("arg_len_raw <= 64")
    assert compiled.metrics == frozenset({"arg_len_raw"})
    assert compiled.evaluate({"arg_len_raw": 10}) is True
    assert compiled.evaluate({"arg_len_raw": 100}) is False


def test_compiler_accepts_boolean_and_membership():
    assert compile_predicate("ret_ok == True").evaluate({"ret_ok": True}) is True
    compiled = compile_predicate('response_op in ["ping", "status"]')
    assert compiled.evaluate({"response_op": "ping"}) is True
    assert compiled.evaluate({"response_op": "export"}) is False


def test_compiler_returns_none_when_metric_absent():
    """Not-applicable is distinct from false; conflating them would falsify wrongly."""
    assert compile_predicate("arg_len_raw <= 8").evaluate({"other": 1}) is None


@pytest.mark.security
@pytest.mark.parametrize(
    "predicate",
    [
        "__import__('os').system('echo pwned')",
        "open('/etc/passwd').read()",
        "eval('1+1') == 2",
        "obj.attribute == 1",
        "values[0] == 1",
        "(lambda: 1)() == 1",
        "[x for x in range(3)] == []",
        "f'{x}' == 'y'",
        "x := 5",
        "exec('x=1') == None",
        "arg_len <= 8; import os",
        "print(1) == None",
    ],
)
def test_compiler_rejects_dangerous_predicates(predicate: str):
    with pytest.raises(ClauseCompileError):
        compile_predicate(predicate)


def test_compiler_requires_a_comparison():
    """A predicate with no comparison asserts nothing and can never be falsified."""
    with pytest.raises(ClauseCompileError):
        compile_predicate("arg_len_raw")


def test_compiler_requires_a_metric():
    with pytest.raises(ClauseCompileError):
        compile_predicate("1 <= 2")


def test_compiler_has_no_builtins():
    compiled = compile_predicate("arg_len_raw <= 8")
    # ``len`` is not reachable from inside a predicate at all.
    assert compiled.evaluate({"arg_len_raw": 1, "len": 5}) is True


# ---------------------------------------------------------------------------
# falsifier
# ---------------------------------------------------------------------------
def _record(scope: str, case: str, **metrics) -> ObservationRecord:
    return ObservationRecord(scope=scope, case_id=case, kind="call", metrics=metrics)


def test_clause_survives_when_holdout_agrees():
    compiled = compile_predicate("arg_lines_raw <= 8")
    result = evaluate_clause(
        compiled,
        [_record("p.py:f", "c1", arg_lines_raw=3), _record("p.py:f", "c2", arg_lines_raw=8)],
        clause_scope="p.py:f",
    )
    assert result.verdict == "SURVIVING"
    assert result.pass_count == 2


def test_clause_falsified_records_counterexample():
    compiled = compile_predicate("arg_lines_raw <= 3")
    result = evaluate_clause(
        compiled,
        [_record("p.py:f", "c1", arg_lines_raw=2), _record("p.py:f", "c9", arg_lines_raw=9)],
        clause_scope="p.py:f",
    )
    assert result.verdict == "FALSIFIED"
    assert result.counterexample["case_id"] == "c9"
    assert result.counterexample["value"] == 9


def test_untested_clause_is_not_admitted():
    """A clause nobody could contradict is not the same as one nobody did."""
    compiled = compile_predicate("never_seen_metric <= 1")
    result = evaluate_clause(compiled, [_record("p.py:f", "c1", other=1)], clause_scope="p.py:f")
    assert result.verdict == "UNSUPPORTED"
    assert not result.survived


def test_uncompilable_predicate_never_reaches_evaluation():
    compiled, result = falsify_proposal(predicate="__import__('os')", scope="*", holdout_records=[])
    assert compiled is None
    assert result.verdict == "UNCOMPILABLE"


def test_scope_matching():
    assert scope_matches("*", "any.py:f")
    assert scope_matches("mod.py:f", "mod.py:f")
    assert scope_matches("mod.py:*", "mod.py:f")
    assert scope_matches("f", "mod.py:f")
    assert not scope_matches("mod.py:g", "mod.py:f")


def test_case_split_is_deterministic_and_disjoint():
    cases = [{"id": f"case-{i:03d}"} for i in range(12)]
    observation, holdout = split_cases(cases)
    assert len(observation) + len(holdout) == 12
    assert not ({c["id"] for c in observation} & {c["id"] for c in holdout})
    again = split_cases(cases)
    assert [c["id"] for c in again[0]] == [c["id"] for c in observation]


def test_value_profiles_classify_metric_kinds():
    from app.samhita.observation import ObservationSet

    observations = ObservationSet(
        records=[
            _record("m.py:f", "c1", arg_len_x=4, flag=True, shell=0, op="ping"),
            _record("m.py:f", "c2", arg_len_x=9, flag=True, shell=0, op="status"),
        ]
    )
    profiles = {(p.metric): p for p in derive_value_profiles(observations)}
    assert profiles["arg_len_x"].kind == "length"
    assert profiles["arg_len_x"].max == 9
    assert profiles["flag"].kind == "boolean" and profiles["flag"].all_true
    assert profiles["shell"].kind == "zero"
    assert profiles["op"].kind == "enum"


# ---------------------------------------------------------------------------
# hypothesis queue
# ---------------------------------------------------------------------------
def test_priority_is_the_product_of_three_factors():
    candidate = HypothesisCandidate(
        handle="H1",
        source_channel=DiscoveryChannel.GRAPH_STATIC.value,
        description="x",
        location="a.py:1",
        reachability=0.5,
        confidence=0.8,
        blast_radius=0.5,
    )
    assert candidate.priority == pytest.approx(0.5 * 0.8 * 0.5)


def test_correlation_key_groups_same_weakness():
    a = HypothesisCandidate(
        handle="H1",
        source_channel="graph/static",
        description="x",
        location="src/e.py:40",
        cwe="CWE-78",
    )
    b = HypothesisCandidate(
        handle="R1",
        source_channel="runtime",
        description="y",
        location="src/e.py:42",
        cwe="CWE-78",
    )
    assert correlation_key(a) == correlation_key(b)


async def test_queue_correlates_and_records_transitions(tenant_a):
    run_id = uuid.uuid4()
    tenant_id = uuid.UUID(tenant_a["organisation_id"])

    from app.models.run import Run

    async with session_scope() as db:
        db.add(
            Run(
                id=run_id,
                tenant_id=tenant_id,
                project_id=uuid.UUID(tenant_a["project_id"]),
                repository_id=uuid.UUID(tenant_a["repository_id"]),
                short_code="QUEU",
            )
        )

    candidates = [
        HypothesisCandidate(
            handle="H1",
            source_channel="graph/static",
            description="shell injection",
            location="src/e.py:40",
            cwe="CWE-78",
            severity=Severity.CRITICAL.value,
            reachability=0.9,
            confidence=0.7,
            blast_radius=0.6,
            validation_plan={"kind": "command_injection"},
        ),
        HypothesisCandidate(
            handle="R1",
            source_channel="runtime",
            description="shell spawned",
            location="src/e.py:42",
            cwe="CWE-78",
            severity=Severity.HIGH.value,
            reachability=0.8,
            confidence=0.85,
            blast_radius=0.5,
            validation_plan={"kind": "command_injection"},
        ),
        HypothesisCandidate(
            handle="C1",
            source_channel="config/reachability",
            description="debug on",
            location="src/c.py:12",
            cwe="CWE-489",
            reachability=0.9,
            confidence=0.7,
            blast_radius=0.3,
            validation_plan={},
            unknown_reason="not dynamically provable",
        ),
    ]

    async with session_scope() as db:
        queue = HypothesisQueue(db, run_id=run_id, tenant_id=tenant_id)
        stats = await queue.push_all(candidates)

    assert stats.merged == 1, "the two CWE-78 candidates should correlate into one"
    assert stats.queued == 1
    assert stats.unknown == 1

    async with session_scope() as db:
        queue = HypothesisQueue(db, run_id=run_id, tenant_id=tenant_id)
        rows = await queue.all()
        merged = next(r for r in rows if r.cwe == "CWE-78")
        # Corroboration raises confidence above either channel alone, but stays capped.
        assert merged.confidence > 0.85
        assert merged.confidence <= 0.95
        assert "graph/static" in merged.source_channel and "runtime" in merged.source_channel

        claimed = await queue.next_queued()
        assert claimed is not None
        assert claimed.status == HypothesisStatus.IN_VALIDATION.value
        assert claimed.transitions[-1]["to"] == HypothesisStatus.IN_VALIDATION.value

        ledger = await queue.ledger()
        assert any(entry["status"] == HypothesisStatus.UNKNOWN.value for entry in ledger)
        assert all(entry["reason"] for entry in ledger), "every ledger entry needs a reason"


# ---------------------------------------------------------------------------
# diffing
# ---------------------------------------------------------------------------
def test_diff_round_trip():
    old = "line one\nline two\nline three\n"
    new = "line one\nline TWO\nline three\n"
    diff = make_unified_diff(path="a.py", old=old, new=new)
    assert apply_unified_diff(old, diff) == new
    stats = diff_stats(diff)
    assert stats.lines_added == 1 and stats.lines_removed == 1
    assert stats.files == ["a.py"]


def test_diff_apply_is_strict_about_context():
    """A fuzzy applier would place a security fix in the wrong location."""
    old = "alpha\nbeta\ngamma\n"
    diff = make_unified_diff(path="a.py", old=old, new="alpha\nBETA\ngamma\n")
    with pytest.raises(DiffApplyError):
        apply_unified_diff("completely\ndifferent\ncontent\n", diff)


# ---------------------------------------------------------------------------
# blast radius
# ---------------------------------------------------------------------------
def test_blast_radius_confines_edits_to_the_root_cause_file(demo_repo_path: Path):
    from app.samhita.engine import SamhitaResult

    model = build_world_model(demo_repo_path)
    radius = blast_radius.compute(
        model=model,
        samhita=SamhitaResult(),
        root_cause_location="src/reportsvc/exporter.py:40",
        root_cause_function="export_report",
    )
    assert radius.allowed_paths == ["src/reportsvc/exporter.py"]
    assert radius.permits("src/reportsvc/exporter.py")
    assert not radius.permits("src/reportsvc/parser.py")
    assert radius.regression_scope in ("local", "module", "multi-module", "service-wide")
    assert len(radius.chain()) == 7


# ---------------------------------------------------------------------------
# policy gate
# ---------------------------------------------------------------------------
def _policy_case(path: str, old: str, new: str):
    diff = make_unified_diff(path=path, old=old, new=new)
    return diff, {path: (old, new)}


@pytest.mark.security
def test_policy_rejects_ci_modification():
    diff, changes = _policy_case(".github/workflows/ci.yml", "on: push\n", "on: pull_request\n")
    decision = evaluate(diff=diff, file_changes=changes, config=PolicyConfig())
    assert not decision.allowed
    assert any(v.code == "FORBIDDEN_PATH" for v in decision.violations)


@pytest.mark.security
@pytest.mark.parametrize(
    "path",
    ["Dockerfile", "uv.lock", "package-lock.json", "pyproject.toml", ".gitignore", "Makefile"],
)
def test_policy_rejects_protected_paths(path: str):
    diff, changes = _policy_case(path, "old\n", "new\n")
    decision = evaluate(diff=diff, file_changes=changes, config=PolicyConfig())
    assert not decision.allowed, f"{path} should be protected"
    assert any(v.code == "FORBIDDEN_PATH" for v in decision.violations)


@pytest.mark.security
def test_policy_rejects_new_dependency():
    diff, changes = _policy_case(
        "src/app.py",
        "import os\n\n\ndef f():\n    return 1\n",
        "import os\nimport requests\n\n\ndef f():\n    return 1\n",
    )
    decision = evaluate(diff=diff, file_changes=changes, config=PolicyConfig())
    assert not decision.allowed
    assert any(v.code == "NEW_DEPENDENCY" for v in decision.violations)


def test_policy_allows_new_stdlib_import():
    diff, changes = _policy_case(
        "src/app.py",
        "import os\n\n\ndef f():\n    return 1\n",
        "import os\nimport re\n\n\ndef f():\n    return 1\n",
    )
    decision = evaluate(
        diff=diff,
        file_changes=changes,
        config=PolicyConfig(),
        assurance_level=AssuranceLevel.A.value,
        has_certificate=True,
    )
    assert decision.allowed, decision.summary


@pytest.mark.security
def test_policy_rejects_new_network_call():
    old = "import httpx\n\n\ndef f():\n    return 1\n"
    new = "import httpx\n\n\ndef f():\n    return httpx.get('http://x')\n"
    diff, changes = _policy_case("src/app.py", old, new)
    decision = evaluate(diff=diff, file_changes=changes, config=PolicyConfig())
    assert not decision.allowed
    assert any(v.code == "NEW_NETWORK_CALL" for v in decision.violations)


@pytest.mark.security
def test_policy_rejects_new_exec_behaviour():
    old = "import subprocess\n\n\ndef f():\n    return 1\n"
    new = "import subprocess\n\n\ndef f():\n    return subprocess.run(['ls'])\n"
    diff, changes = _policy_case("src/app.py", old, new)
    decision = evaluate(diff=diff, file_changes=changes, config=PolicyConfig())
    assert not decision.allowed
    assert any(v.code == "NEW_EXEC_BEHAVIOUR" for v in decision.violations)


def test_policy_ignores_exec_mentioned_in_a_comment():
    """AST-based, not grep-based: a comment about subprocess is not a violation."""
    old = "def f():\n    return 1\n"
    new = "def f():\n    # we deliberately avoid subprocess.run here\n    return 1\n"
    diff, changes = _policy_case("src/app.py", old, new)
    decision = evaluate(
        diff=diff,
        file_changes=changes,
        config=PolicyConfig(),
        assurance_level=AssuranceLevel.A.value,
        has_certificate=True,
    )
    assert decision.allowed, decision.summary


@pytest.mark.security
def test_policy_rejects_binary_modification():
    diff, changes = _policy_case("assets/logo.png", "old\n", "new\n")
    decision = evaluate(diff=diff, file_changes=changes, config=PolicyConfig())
    assert not decision.allowed
    assert any(v.code in ("BINARY_MODIFICATION", "FORBIDDEN_PATH") for v in decision.violations)


@pytest.mark.security
def test_policy_rejects_oversized_diff():
    old = "".join(f"line {i}\n" for i in range(400))
    new = "".join(f"changed {i}\n" for i in range(400))
    diff, changes = _policy_case("src/app.py", old, new)
    decision = evaluate(diff=diff, file_changes=changes, config=PolicyConfig(max_diff_lines=50))
    assert not decision.allowed
    assert any(v.code == "DIFF_TOO_LARGE" for v in decision.violations)


@pytest.mark.security
def test_policy_rejects_edit_outside_blast_radius():
    from app.patching.blast_radius import BlastRadius

    radius = BlastRadius(allowed_paths=["src/allowed.py"])
    diff, changes = _policy_case("src/elsewhere.py", "a\n", "b\n")
    decision = evaluate(diff=diff, file_changes=changes, config=PolicyConfig(), blast=radius)
    assert not decision.allowed
    assert any(v.code == "OUTSIDE_BLAST_RADIUS" for v in decision.violations)


@pytest.mark.security
def test_policy_rejects_level_r_certificate():
    diff, changes = _policy_case("src/app.py", "a = 1\n", "a = 2\n")
    decision = evaluate(
        diff=diff,
        file_changes=changes,
        config=PolicyConfig(),
        assurance_level=AssuranceLevel.R.value,
        has_certificate=True,
    )
    assert not decision.allowed
    assert any(v.code == "ASSURANCE_LEVEL_R" for v in decision.violations)


@pytest.mark.security
def test_policy_rejects_missing_certificate():
    diff, changes = _policy_case("src/app.py", "a = 1\n", "a = 2\n")
    decision = evaluate(
        diff=diff,
        file_changes=changes,
        config=PolicyConfig(),
        assurance_level=None,
        has_certificate=False,
    )
    assert not decision.allowed
    assert any(v.code == "MISSING_CERTIFICATE" for v in decision.violations)


@pytest.mark.security
def test_policy_rejects_level_below_floor():
    diff, changes = _policy_case("src/app.py", "a = 1\n", "a = 2\n")
    decision = evaluate(
        diff=diff,
        file_changes=changes,
        config=PolicyConfig(min_assurance_level=AssuranceLevel.A.value),
        assurance_level=AssuranceLevel.C.value,
        has_certificate=True,
    )
    assert not decision.allowed
    assert any(v.code == "ASSURANCE_BELOW_FLOOR" for v in decision.violations)


def test_policy_allows_a_clean_minimal_patch():
    old = "def f(x):\n    return x\n"
    new = "def f(x):\n    if x < 0:\n        raise ValueError('negative')\n    return x\n"
    diff, changes = _policy_case("src/app.py", old, new)
    decision = evaluate(
        diff=diff,
        file_changes=changes,
        config=PolicyConfig(),
        assurance_level=AssuranceLevel.A.value,
        has_certificate=True,
    )
    assert decision.allowed, decision.summary


# ---------------------------------------------------------------------------
# assurance grading
# ---------------------------------------------------------------------------
class _Stage:
    def __init__(self, stage: str, verdict: str, detail: str = "", metrics=None):
        self.stage = stage
        self.verdict = verdict
        self.detail = detail
        self.cases_total = 4
        self.cases_passed = 4 if verdict == Verdict.PASS.value else 3
        self.metrics = metrics or {}
        self.refuting_evidence = {}


class _Gauntlet:
    def __init__(self, verdict: str, stages: list[_Stage], failing_stage: str = ""):
        self.verdict = verdict
        self.stages = stages
        self.failing_stage = failing_stage


def _all_pass() -> list[_Stage]:
    return [
        _Stage("exploit_mutation", "pass"),
        _Stage("sibling_hunt", "pass"),
        _Stage("differential_replay", "pass"),
        _Stage("samhita_recheck", "pass"),
    ]


def _grade(**overrides):
    defaults = {
        "gauntlet": _Gauntlet(Verdict.PASS.value, _all_pass()),
        "exploit_eliminated": True,
        "shield_active": True,
        "coverage_before": 40.0,
        "coverage_after": 41.0,
        "clause_total": 10,
        "clause_held": 10,
        "clause_unsupported": 0,
        "unproved_siblings": [],
        "iteration": 1,
        "max_iterations": 3,
    }
    defaults.update(overrides)
    return assurance.grade(**defaults)


def test_level_a_requires_everything_clean():
    result = _grade()
    assert result.level == AssuranceLevel.A.value
    assert any("not a formal proof" in item.lower() for item in result.limitations)


def test_level_b_when_siblings_remain_unproved():
    result = _grade(unproved_siblings=[{"location": "src/x.py:10", "why": "similar"}])
    assert result.level == AssuranceLevel.B.value
    assert any("src/x.py:10" in item for item in result.limitations)


def test_level_c_when_clauses_unverifiable():
    result = _grade(clause_unsupported=2)
    assert result.level == AssuranceLevel.C.value


def test_level_c_when_coverage_swing_is_unbounded():
    result = _grade(coverage_before=40.0, coverage_after=80.0)
    assert result.level == AssuranceLevel.C.value
    assert any("Coverage moved" in item for item in result.limitations)


def test_level_r_when_gauntlet_fails():
    stages = _all_pass()
    stages[0] = _Stage("exploit_mutation", "fail", "BYPASS FOUND")
    result = _grade(
        gauntlet=_Gauntlet(Verdict.FAIL.value, stages, "exploit_mutation"),
        exploit_eliminated=False,
    )
    assert result.level == AssuranceLevel.R.value
    assert any("not repaired" in item.lower() for item in result.limitations)
    assert any("shield remains deployed" in item.lower() for item in result.limitations)


def test_level_r_states_when_no_shield_is_active():
    stages = _all_pass()
    stages[2] = _Stage("differential_replay", "fail", "regression")
    result = _grade(
        gauntlet=_Gauntlet(Verdict.FAIL.value, stages, "differential_replay"),
        exploit_eliminated=False,
        shield_active=False,
    )
    assert result.level == AssuranceLevel.R.value
    assert any("unmitigated" in item.lower() for item in result.limitations)


def test_no_level_claims_formal_proof():
    for grade_result in (
        _grade(),
        _grade(unproved_siblings=[{"location": "x"}]),
        _grade(clause_unsupported=1),
    ):
        assert grade_result.as_dict()["not_a_formal_proof"] is True
        assert grade_result.as_dict()["assurance_kind"] == "bounded empirical assurance"


# ---------------------------------------------------------------------------
# PRAMAAN evidence graph
# ---------------------------------------------------------------------------
def test_graph_detects_dangling_claims():
    graph = EvidenceGraph()
    graph.add_node(ref="ev:vuln:V1", type="vulnerability", title="V1")
    graph.add_edge("ev:vuln:V1", "violated_clause", "ev:clause:C1")  # target does not exist
    problems = graph.unsupported_claims()
    assert len(problems) == 1
    assert "ev:clause:C1" in problems[0]["problem"]


def test_graph_hash_changes_with_content():
    def build(title: str) -> str:
        graph = EvidenceGraph()
        graph.add_node(ref="ev:vuln:V1", type="vulnerability", title=title)
        return graph.graph_hash()

    assert build("one") != build("two")


def test_graph_subgraph_walks_relations():
    graph = EvidenceGraph()
    graph.add_node(ref="a", type="vulnerability", title="a")
    graph.add_node(ref="b", type="patch", title="b")
    graph.add_node(ref="c", type="gauntlet_result", title="c")
    graph.add_node(ref="unrelated", type="code_location", title="u")
    graph.add_edge("a", "repaired_by", "b")
    graph.add_edge("b", "verified_by", "c")

    subgraph = graph.subgraph_for("a")
    refs = {node["ref"] for node in subgraph["nodes"]}
    assert refs == {"a", "b", "c"}


def test_certificate_verification_detects_tampering():
    from app.core.hashing import hmac_sign, sha256_json

    document = {"schema": "kavachx.pramaan.certificate.v1", "finding": {"handle": "V1"}}
    digest = sha256_json(document)
    document["signature"] = {
        "algorithm": "HMAC-SHA256",
        "certificate_hash": digest,
        "signature": hmac_sign(digest, "test-certificate-signing-key"),
    }

    clean = verify_certificate(document, signing_key="test-certificate-signing-key")
    assert clean["hash_matches"] and clean["signature_matches"]

    document["finding"]["handle"] = "V2"
    tampered = verify_certificate(document, signing_key="test-certificate-signing-key")
    assert not tampered["hash_matches"]


# ---------------------------------------------------------------------------
# indexer: build output must not masquerade as authored source
# ---------------------------------------------------------------------------
def _tree(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, body in files.items():
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
    return tmp_path


def test_minified_bundle_is_not_indexed_and_contributes_no_sinks(tmp_path: Path):
    """A vendored bundle with an innocuous name must be excluded on line geometry alone.

    This is the failure mode that motivated it: one checked-in ``static/loader.js`` produced dozens
    of "candidate sinks" whose snippets were 300 characters of minified JavaScript, crowding the
    real findings out of the queue.
    """
    from app.analysis.indexer import index_tree, indexer_summary

    root = _tree(
        tmp_path,
        {
            "app/loader.js": "var K={};" + "K.f=function(b,c){return eval(b+c)};" * 400 + "\n",
            "app/real.py": "import subprocess\ndef handler(cmd):\n    subprocess.run(cmd, shell=True)\n",
            "app/ui.js": "function go(x) {\n  return eval(x);\n}\n",
        },
    )
    indexes = {entry.path: entry for entry in index_tree(root)}

    bundle = indexes["app/loader.js"]
    assert bundle.indexer == "skipped"
    assert "minified" in bundle.skipped_reason
    assert bundle.sink_hits == []
    assert bundle.symbols == []
    # Still hashed and counted: it is part of the pinned tree even though it was not analysed.
    assert bundle.sha256 and bundle.lines > 0

    # Authored files are untouched by the heuristic.
    assert indexes["app/real.py"].indexer == "tree-sitter"
    assert indexes["app/real.py"].sink_hits
    assert indexes["app/ui.js"].sink_hits, "an authored .js file must still be scanned"

    summary = indexer_summary(list(indexes.values()))
    assert summary["skipped_count"] == 1
    assert summary["skipped_files"][0]["path"] == "app/loader.js"


@pytest.mark.parametrize(
    "name",
    ["vendor.min.js", "app.bundle.js", "site-bundle.js", "styles.min.css"],
)
def test_bundle_filenames_are_skipped(tmp_path: Path, name: str):
    from app.analysis.indexer import index_file

    target = tmp_path / name
    target.write_text("a=1;\n", encoding="utf-8")
    entry = index_file(target, root=tmp_path)
    assert entry.indexer == "skipped"
    assert "build output" in entry.skipped_reason


def test_a_long_single_line_file_is_not_mistaken_for_a_bundle(tmp_path: Path):
    """One long line in an otherwise normal file must not disqualify the whole file."""
    from app.analysis.indexer import index_file

    body = "import os\n" + "x = 1  # " + ("y" * 300) + "\n" + "def f():\n    os.system('ls')\n"
    target = tmp_path / "app.py"
    target.write_text(body, encoding="utf-8")
    entry = index_file(target, root=tmp_path)
    assert entry.indexer != "skipped"
    assert entry.sink_hits


# ---------------------------------------------------------------------------
# hypothesis priority: unmeasurable reachability must not invert the ranking
# ---------------------------------------------------------------------------
def _candidate(severity: str, **kw) -> HypothesisCandidate:
    return HypothesisCandidate(
        handle="H001",
        source_channel="graph/static",
        description="d",
        location="app.py:1",
        severity=severity,
        **kw,
    )


def test_priority_uses_the_spec_formula_when_reachability_is_measured():
    candidate = _candidate(
        "CRITICAL", reachability=0.5, confidence=0.8, blast_radius=0.5, reachability_measured=True
    )
    assert candidate.priority == pytest.approx(0.5 * 0.8 * 0.5)


def test_unmeasurable_reachability_does_not_bury_critical_findings():
    """The regression this guards was observed on a real repository.

    Without an entrypoint, ``reachability_score`` returns the same floor for every code finding, so
    SQL injection ranked *below* a LOW "container may run as root" note whose channel legitimately
    knows its own findings are reachable. Severity must stand in for the factor that could not be
    measured, or the queue is ordered backwards.
    """
    # A code finding on a target with no entrypoint: the graph can only offer its floor.
    sqli = _candidate(
        "CRITICAL",
        reachability=0.05,
        confidence=0.8,
        blast_radius=0.5,
        reachability_measured=False,
    )
    # A deployment note, whose channel asserts reachability directly and measured it.
    dockerfile = _candidate(
        "LOW", reachability=0.5, confidence=0.6, blast_radius=0.4, reachability_measured=True
    )

    assert sqli.priority > dockerfile.priority, (
        f"critical code finding ({sqli.priority}) must outrank a LOW deployment note "
        f"({dockerfile.priority}) when its reachability was merely unmeasurable"
    )

    # Blast radius is dropped rather than substituted: it comes from the same call graph. Multiplying
    # by its uniform floor is what left the CRITICALs below the LOW note on the first attempt.
    assert sqli.priority == pytest.approx(1.0 * 0.8)


def test_severity_orders_candidates_when_reachability_is_unmeasurable():
    same = {
        "reachability": 0.05,
        "confidence": 0.7,
        "blast_radius": 0.5,
        "reachability_measured": False,
    }
    ranked = sorted(
        (_candidate(sev, **same) for sev in ("LOW", "CRITICAL", "MEDIUM", "HIGH", "INFO")),
        key=lambda c: -c.priority,
    )
    assert [c.severity for c in ranked] == ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def test_measured_reachability_still_wins_within_one_severity():
    """Severity substitution must not flatten real measurements when they exist."""
    near = _candidate(
        "HIGH", reachability=0.9, confidence=0.7, blast_radius=0.5, reachability_measured=True
    )
    far = _candidate(
        "HIGH", reachability=0.15, confidence=0.7, blast_radius=0.5, reachability_measured=True
    )
    assert near.priority > far.priority


# ---------------------------------------------------------------------------
# logging: an exception must arrive with its type and stack
# ---------------------------------------------------------------------------
def test_exception_logging_records_type_and_traceback():
    """A logged exception must carry what you need to diagnose it.

    ``logger.exception("graph.node_failed", node=...)`` used to emit the event name and nothing
    about the exception, because logifyx's formatter ignores ``exc_info``. A node failing with an
    empty ``NotImplementedError()`` therefore logged no type, no message and no stack.
    """
    import logging as stdlib_logging

    from app.core.logging import get_logger

    captured: list[stdlib_logging.LogRecord] = []

    class _Capture(stdlib_logging.Handler):
        def emit(self, record):
            captured.append(record)

    log = get_logger("test.exception")
    handler = _Capture()
    log._logger.addHandler(handler)
    try:
        try:
            raise NotImplementedError()
        except NotImplementedError:
            log.exception("probe.failed", node="contract_synthesis")
    finally:
        log._logger.removeHandler(handler)

    assert captured, "nothing was logged"
    record = captured[-1]
    assert record.error_type == "NotImplementedError"
    # An exception with no message must still say something useful.
    assert "no message" in record.error
    assert "NotImplementedError" in record.traceback
    assert "raise NotImplementedError()" in record.traceback
    # The single-line summary stays greppable: the stack lives in a field, not in the message.
    assert "Traceback" not in record.getMessage()
    assert "node=contract_synthesis" in record.getMessage()


def test_console_format_is_the_default_in_development_and_json_in_production():
    """Colour for humans locally, parseable records in production — without configuration.

    logifyx couples the two: ``json_mode=True`` selects the JSON formatter for both sinks and
    ignores ``color``, so "coloured" and "JSON" are mutually exclusive. Defaulting to JSON meant a
    developer got an uncoloured wall of JSON with no obvious knob.
    """
    from app.config import Settings

    assert Settings(dev_mode=True, log_format=None).log_format == "console"
    assert Settings(dev_mode=False, log_format=None).log_format == "json"
    # An explicit setting always wins over the dev_mode-derived default.
    assert Settings(dev_mode=True, log_format="json").log_format == "json"
    assert Settings(dev_mode=False, log_format="console").log_format == "console"


def test_console_format_emits_ansi_colour_but_the_log_file_never_does():
    """Colour belongs on a terminal. ANSI escapes in a rotated log file are just noise."""
    from logifyx.formatter import get_formatter

    # This is the pairing logifyx's core applies: console gets (json_mode, color), file gets
    # (json_mode, False). Asserting on it here means an upstream change cannot silently un-colour
    # the console or start writing escapes into the file.
    console = get_formatter(False, True)
    file_sink = get_formatter(False, False)
    assert type(console).__name__ == "LogifyxFormatter"
    assert type(file_sink).__name__ == "PlainLogifyxFormatter"

    record = logging.LogRecord(
        name="kavachx",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg="probe.failed | component=test",
        args=(),
        exc_info=None,
    )
    assert "\033[" in console.format(record), "console output must carry colour"
    assert "\033[" not in file_sink.format(record), "the file must stay plain text"

    # json_mode wins over colour: there is nowhere to put an escape in a JSON object.
    assert type(get_formatter(True, True)).__name__ == "CompactJsonFormatter"
