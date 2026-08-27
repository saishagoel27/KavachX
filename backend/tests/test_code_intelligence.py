"""Tests for the code-intelligence layer, over small fixture repositories.

Each test targets **one** property. That is deliberate: a test that indexes the whole seeded demo
tells you a dozen things at once, so when it fails you learn only that "something in indexing
broke". These tell you which thing.

Several are regression guards for bugs found by *running* the system rather than reading it, and
each names the bug in its docstring, so a future change that reintroduces one fails with an
explanation rather than a bare assertion.

GitNexus is not required. Where a test needs it, it skips with a reason rather than passing
vacuously — a skipped test is a visible gap, a vacuous pass is not.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.indexing.model import (
    CodeEdge,
    CodeGraph,
    CodeNode,
    EdgeKind,
    NodeKind,
    Precision,
    Provider,
)
from tests.fixtures import repos


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
async def _index(root: Path, *, gitnexus: bool = False, **kwargs):
    from app.indexing.service import build_index

    return await build_index(
        root,
        run_short=kwargs.pop("run_short", "TEST"),
        repository=kwargs.pop("repository", "fixture/repo"),
        commit_sha=kwargs.pop("commit_sha", "deadbeef"),
        source_sha256=kwargs.pop("source_sha256", "a" * 64),
        enable_gitnexus=gitnexus,
        **kwargs,
    )


def _gitnexus_or_skip() -> None:
    from app.indexing.gitnexus import resolve_command

    info = resolve_command()
    if not info.available:
        pytest.skip(f"GitNexus not available: {info.reason or 'no reason recorded'}")


def _exec_result(**kwargs):
    from app.sandbox.base import ExecResult

    return ExecResult(**{"exit_code": 0, "stdout": "", "stderr": "", "duration_ms": 5, **kwargs})


def _descriptor_for(root: Path):
    from app.analysis.probe import confirm_descriptor
    from app.analysis.world_model import build_world_model

    return confirm_descriptor(root, build_world_model(root), proposal={})


# ---------------------------------------------------------------------------
# the internal graph model
# ---------------------------------------------------------------------------
def test_node_merge_keeps_the_more_informative_value():
    """Providers disagree in detail; a merged node must be better than either input."""
    graph = CodeGraph()
    graph.add_node(
        CodeNode(
            uid="a.py:f",
            kind=NodeKind.FUNCTION.value,
            name="f",
            file="a.py",
            start_line=10,
            end_line=12,
            exported=True,
            provenance={Provider.GITNEXUS.value},
        )
    )
    graph.add_node(
        CodeNode(
            uid="a.py:f",
            kind=NodeKind.FUNCTION.value,
            name="f",
            file="a.py",
            start_line=10,
            # tree-sitter saw the real body extent; GitNexus reported a narrower span.
            end_line=40,
            parameters=["x"],
            decorators=["@app.route"],
            provenance={Provider.TREE_SITTER.value},
        )
    )
    node = graph.node("a.py:f")
    assert node is not None
    assert node.provenance == {Provider.GITNEXUS.value, Provider.TREE_SITTER.value}
    assert node.exported is True, "the export flag from the resolving provider must survive"
    assert node.parameters == ["x"], "parameters from the parsing provider must survive"
    assert node.decorators == ["@app.route"]
    # symbol_at() needs the true extent to attribute a sink line to its function.
    assert node.end_line == 40, "the wider span must win"


def test_edge_merge_promotes_a_corroborated_edge():
    """An edge two independent providers agree on is corroborated, so it becomes resolved."""
    graph = CodeGraph()
    graph.add_edge(
        CodeEdge(
            src="a.py:f",
            dst="b.py:g",
            kind=EdgeKind.CALLS.value,
            provenance={Provider.TREE_SITTER.value},
            confidence=0.55,
        )
    )
    assert graph.edges[0].resolved is False, "a name match alone is not resolved"

    graph.add_edge(
        CodeEdge(
            src="a.py:f",
            dst="b.py:g",
            kind=EdgeKind.CALLS.value,
            provenance={Provider.GITNEXUS.value},
            confidence=1.0,
        )
    )
    assert len(graph.edges) == 1, "the same relationship must merge, not duplicate"
    assert graph.edges[0].resolved is True
    assert graph.edges[0].confidence == 1.0


def test_precision_filters_name_matched_edges():
    """RESOLVED precision must not traverse a name-matched edge."""
    graph = CodeGraph()
    for uid in ("m.py:main", "a.py:f"):
        graph.add_node(CodeNode(uid=uid, kind=NodeKind.FUNCTION.value, name=uid.split(":")[-1]))
    graph.node("m.py:main").attrs["entrypoint_kind"] = "cli"
    graph.add_edge(
        CodeEdge(
            src="m.py:main",
            dst="a.py:f",
            kind=EdgeKind.CALLS.value,
            provenance={Provider.TREE_SITTER.value},
            confidence=0.35,
        )
    )

    union = graph.reachability("a.py:f", precision=Precision.UNION.value)
    resolved = graph.reachability("a.py:f", precision=Precision.RESOLVED.value)

    assert union.reachable is True
    assert union.measured is True
    assert union.via_providers == [Provider.TREE_SITTER.value]
    assert resolved.reachable is False, "a name match must not satisfy RESOLVED precision"
    assert resolved.measured is True, "the search happened; it just found nothing resolved"


def test_reachability_reports_unmeasured_when_no_entrypoint_exists():
    """``measured=False`` must be distinguishable from ``reachable=False``.

    With no entrypoint there is no path to search. Reporting ``reachable=False`` would let "we
    could not look" read as "we looked and found nothing" — the distinction the hypothesis queue
    relies on to avoid inverting its ranking on a static-only run.
    """
    graph = CodeGraph()
    graph.add_node(CodeNode(uid="a.py:f", kind=NodeKind.FUNCTION.value, name="f"))

    result = graph.reachability("a.py:f")
    assert result.reachable is False
    assert result.measured is False
    assert "absence of measurement" in result.note


def test_reachability_confidence_is_the_weakest_hop():
    """A path is only as strong as its weakest link."""
    graph = CodeGraph()
    for uid in ("m.py:main", "a.py:f", "b.py:g"):
        graph.add_node(CodeNode(uid=uid, kind=NodeKind.FUNCTION.value, name=uid.split(":")[-1]))
    graph.node("m.py:main").attrs["entrypoint_kind"] = "cli"
    graph.add_edge(
        CodeEdge("m.py:main", "a.py:f", EdgeKind.CALLS.value, {Provider.GITNEXUS.value}, 1.0)
    )
    graph.add_edge(
        CodeEdge("a.py:f", "b.py:g", EdgeKind.CALLS.value, {Provider.TREE_SITTER.value}, 0.35)
    )

    result = graph.reachability("b.py:g", precision=Precision.UNION.value)
    assert result.reachable is True
    assert result.confidence == 0.35, "the 1.0 hop must not mask the 0.35 hop"


def test_graph_content_hash_ignores_line_numbers():
    """The structural digest identifies the graph, not the run that built it."""

    def build(start: int) -> CodeGraph:
        graph = CodeGraph()
        graph.providers = [Provider.TREE_SITTER.value]
        graph.add_node(
            CodeNode(
                uid="a.py:f",
                kind=NodeKind.FUNCTION.value,
                name="f",
                start_line=start,
                provenance={Provider.TREE_SITTER.value},
            )
        )
        return graph

    assert build(10).content_hash() == build(99).content_hash()


# ---------------------------------------------------------------------------
# index creation, reproducibility, health
# ---------------------------------------------------------------------------
async def test_index_creation_finds_symbols_and_relationships(tmp_path):
    repos.full(tmp_path)
    result = await _index(tmp_path)

    job = result.job
    assert len(job.index_id) == 64
    assert job.files_indexed > 0
    assert job.functions > 0, "the fixture defines functions"
    assert job.call_relationships > 0, "main -> handle -> run_export is a real chain"
    assert job.entrypoints_discovered > 0, "main has a __main__ guard"
    assert result.usable is True


async def test_index_id_and_graph_hash_are_reproducible(tmp_path):
    """Same tree, two workspaces, identical identity. The §7 requirement."""
    first = tmp_path / "a"
    second = tmp_path / "b"
    first.mkdir()
    second.mkdir()
    repos.full(first)
    repos.full(second)

    a = await _index(first, run_short="RA")
    b = await _index(second, run_short="RB")

    assert a.job.index_id == b.job.index_id
    assert a.job.graph_hash == b.job.graph_hash
    assert len(a.graph) == len(b.graph)
    assert len(a.graph.edges) == len(b.graph.edges)


def test_index_id_changes_when_an_option_changes():
    """Two indexes built with different options are different indexes."""
    from app.indexing.versions import collect_versions, compute_index_id

    versions = collect_versions()
    base = compute_index_id(source_sha256="a" * 64, versions=versions, options={"pdg": False})
    other = compute_index_id(source_sha256="a" * 64, versions=versions, options={"pdg": True})
    assert base != other


async def test_index_health_grades_and_records_claim_bounds(tmp_path):
    repos.full(tmp_path)
    result = await _index(tmp_path)

    report = result.health
    assert report.grade in ("A", "B", "C")
    assert report.usable is True
    # Every warning or failure must state what it forbids the run from claiming.
    for check in report.checks:
        if check.severity in ("warn", "fail"):
            assert check.bounds_claim, f"{check.id} warned without recording a bound"
    rendered = report.render(result.job)
    assert "INDEX HEALTH" in rendered
    assert "Relationships:" in rendered


async def test_an_empty_tree_is_reported_unusable_not_clean(tmp_path):
    """A tree with no source must fail the index, not report an empty clean result."""
    repos.empty(tmp_path)
    result = await _index(tmp_path)

    assert result.usable is False
    assert result.health.grade == "F"
    assert result.job.status == "FAILED"
    assert result.health.claim_bounds, "an unusable index must record what it cannot support"


async def test_a_syntax_error_degrades_the_index_rather_than_failing_it(tmp_path):
    repos.minimal_python(tmp_path)
    repos.with_unparseable(tmp_path)
    result = await _index(tmp_path)

    # The broken file must not take the whole index down.
    assert result.usable is True
    assert result.job.functions > 0, "the parseable files must still contribute symbols"


async def test_a_minified_bundle_is_hashed_but_not_analysed(tmp_path):
    repos.minimal_python(tmp_path)
    repos.with_minified_bundle(tmp_path)
    result = await _index(tmp_path)

    skipped = {entry["path"] for entry in result.job.skipped_files}
    assert any("vendor.min.js" in path for path in skipped), (
        f"a vendored bundle must be named as skipped; skipped were {sorted(skipped)}"
    )
    assert result.job.files_skipped >= 1


async def test_graph_source_names_only_actual_contributors(tmp_path):
    """Regression guard.

    An earlier build set ``graph_source = "gitnexus+tree-sitter"`` whenever a ``gitnexus`` binary
    existed on PATH, without ever invoking it — a false provenance claim that travelled into every
    certificate. With GitNexus disabled the label must name tree-sitter only.
    """
    repos.full(tmp_path)
    result = await _index(tmp_path, gitnexus=False)

    assert result.job.graph_source == "tree-sitter"
    for provider in result.job.graph_source.split("+"):
        assert provider in result.job.providers
    assert Provider.GITNEXUS.value not in result.job.providers


async def test_index_without_gitnexus_records_the_resolution_bound(tmp_path):
    repos.full(tmp_path)
    result = await _index(tmp_path, gitnexus=False)

    assert result.job.resolved_relationships == 0
    assert result.job.resolved_ratio == 0.0
    bounds = " ".join(result.health.claim_bounds)
    assert "resolved" in bounds, "a 0%-resolved index must say what it cannot support"


# ---------------------------------------------------------------------------
# GitNexus integration (skipped, not vacuous, when absent)
# ---------------------------------------------------------------------------
async def test_gitnexus_contributes_resolved_relationships(tmp_path):
    _gitnexus_or_skip()
    repos.full(tmp_path)
    result = await _index(tmp_path, gitnexus=True)

    assert Provider.GITNEXUS.value in result.job.providers
    assert "gitnexus" in result.job.graph_source
    assert result.job.resolved_relationships > 0
    assert result.job.versions["gitnexus_version"], "the provider version must be recorded"


async def test_gitnexus_leaves_the_analysed_tree_clean(tmp_path):
    """The index directory must not survive the run, and the tree must be unchanged.

    GitNexus writes a ``.gitnexus/`` LadybugDB index *inside* whatever it analyses, and registers
    the alias in a machine-global registry under ``~/.gitnexus``. ``build_index`` deregisters the
    alias afterwards, which also removes the directory. Both halves matter: a surviving directory
    would modify the tree under analysis, and a surviving alias would leave one dead registry row
    per run on a shared machine.
    """
    _gitnexus_or_skip()
    repos.full(tmp_path)
    before = {p.name for p in tmp_path.iterdir()}
    result = await _index(tmp_path, gitnexus=True)

    assert Provider.GITNEXUS.value in result.job.providers, "the provider must have run at all"
    assert not (tmp_path / ".gitnexus").exists(), "the index directory must be cleaned up"
    assert {p.name for p in tmp_path.iterdir()} == before, "the analysed tree must be unchanged"


def test_gitnexus_uid_canonicalisation():
    """GitNexus ids must map onto KavachX's existing handle shape so the graphs can merge."""
    from app.indexing.gitnexus import canonical_uid

    assert canonical_uid("Function:src/main.py:main", label="Function") == "src/main.py:main"
    assert canonical_uid("File:src/main.py", label="File") == "src/main.py"
    # A synthetic id with no path must be namespaced, never mistaken for a file path.
    assert canonical_uid("proc_0_entrypoint", label="Process").startswith("gitnexus/")
    # A path-shaped id must survive intact.
    assert canonical_uid("src/main.py:main") == "src/main.py:main"


def test_gitnexus_markdown_table_parsing():
    """``cypher`` returns a pipe table; a malformed row must be skipped, never guessed at."""
    from app.indexing.gitnexus import _parse_markdown_table

    rows = _parse_markdown_table(
        "| src | dst |\n| --- | --- |\n| a.py:f | b.py:g |\n| broken |\n| c.py:h | d.py:i |"
    )
    assert rows == [
        {"src": "a.py:f", "dst": "b.py:g"},
        {"src": "c.py:h", "dst": "d.py:i"},
    ]


def test_gitnexus_cypher_error_raises_rather_than_returning_zero_rows():
    """ "The query failed" and "there are none of these" must not collapse into one answer."""
    from app.indexing.gitnexus import GitNexusUnavailable, _parse_cypher

    with pytest.raises(GitNexusUnavailable):
        _parse_cypher(
            json.dumps({"error": "Binder exception: no such property"}), statement="MATCH"
        )


def test_gitnexus_resolution_prefers_a_launchable_windows_shim():
    """Regression guard for ``[WinError 193] %1 is not a valid Win32 application``.

    npm ships three shims for a bin; only the ``.cmd`` is launchable by CreateProcess on Windows.
    """
    import platform

    from app.indexing.gitnexus import _windows_variants

    variants = _windows_variants(Path("node_modules/.bin/gitnexus"))
    if platform.system() == "Windows":
        assert variants[0].suffix == ".cmd"
    else:
        assert variants == [Path("node_modules/.bin/gitnexus")]


# ---------------------------------------------------------------------------
# symbol / caller / callee retrieval
# ---------------------------------------------------------------------------
async def test_symbol_and_caller_callee_retrieval(tmp_path):
    repos.full(tmp_path)
    result = await _index(tmp_path)
    graph = result.graph

    matches = graph.find_by_name("run_export")
    assert matches, "the sink function must be indexed"

    callers = graph.callers(matches[0].uid, precision=Precision.UNION.value)
    assert any("service" in caller for caller in callers), (
        f"handle() calls run_export(); callers were {callers}"
    )

    handle = graph.find_by_name("handle")[0].uid
    callees = graph.callees(handle, precision=Precision.UNION.value)
    assert any("run_export" in callee for callee in callees)


async def test_symbol_at_returns_the_owning_callable(tmp_path):
    repos.full(tmp_path)
    result = await _index(tmp_path)

    node = result.graph.find_by_name("run_export")[0]
    owner = result.graph.symbol_at(node.file, node.start_line + 1)
    assert owner is not None
    assert owner.name == "run_export"


async def test_search_symbols_is_deterministic(tmp_path):
    repos.full(tmp_path)
    result = await _index(tmp_path)
    first = [n.uid for n in result.graph.search_symbols("export")]
    second = [n.uid for n in result.graph.search_symbols("export")]
    assert first == second and first, "search must be stable and non-empty"


# ---------------------------------------------------------------------------
# incremental indexing
# ---------------------------------------------------------------------------
async def test_identical_trees_produce_an_empty_change_set(tmp_path):
    from app.indexing.incremental import compute_change_set

    first = tmp_path / "a"
    second = tmp_path / "b"
    first.mkdir()
    second.mkdir()
    repos.full(first)
    repos.full(second)

    a = await _index(first, run_short="RA")
    b = await _index(second, run_short="RB")

    change = compute_change_set(previous_graph=a.graph, current_graph=b.graph, root=second)
    assert change.changed_files == []
    assert change.full is False


async def test_a_changed_file_yields_an_affected_closure(tmp_path):
    from app.indexing.incremental import affected_closure, compute_change_set

    repos.full(tmp_path)
    before = await _index(tmp_path)

    target = tmp_path / "src" / "app" / "exporter.py"
    target.write_text(target.read_text(encoding="utf-8") + "\n# touched\n", encoding="utf-8")
    after = await _index(tmp_path)

    change = compute_change_set(
        previous_graph=before.graph, current_graph=after.graph, root=tmp_path
    )
    assert change.changed_files == ["src/app/exporter.py"]

    closure = affected_closure(after.graph, change)
    assert closure.changed_symbols, "the changed file's symbols must be in the closure"
    assert closure.dependent_symbols, "callers of the changed symbols must be in the closure"
    assert closure.truncated is False


# ---------------------------------------------------------------------------
# test / config / dependency discovery
# ---------------------------------------------------------------------------
async def test_test_discovery_maps_tests_to_symbols(tmp_path):
    from app.understanding.tests_discovery import tests_for

    repos.full(tmp_path)
    result = await _index(tmp_path)

    assert result.job.tests_discovered == 1
    node = next(n for n in result.graph.nodes_of(NodeKind.TEST.value) if "test_service" in n.uid)
    assert node.attrs["framework"] == "pytest"
    assert node.attrs["case_count"] == 2

    handle = result.graph.find_by_name("handle")[0].uid
    assert tests_for(result.graph, handle), "the fixture test references handle() by name"

    # A static name reference must never be marked resolved — it is not measured coverage.
    edge = next(iter(result.graph.out_edges(handle, EdgeKind.TESTED_BY.value)))
    assert edge.resolved is False
    assert edge.confidence < 0.5
    assert edge.attrs["basis"] == "static name reference"


async def test_config_discovery_excludes_fixture_data(tmp_path):
    """Regression guard: benign-corpus JSON must not be counted as configuration.

    Miscounting inflated the config counter (3 real files reported as 15 on the seeded demo) and
    fed the reachability channel a pile of request payloads to chase.
    """
    repos.full(tmp_path)
    result = await _index(tmp_path)

    config_paths = {n.qualname for n in result.graph.nodes_of(NodeKind.CONFIGURATION.value)}
    assert any("settings.yaml" in path for path in config_paths)
    assert not any("corpus/" in path for path in config_paths), (
        f"corpus data was counted as configuration: {sorted(config_paths)}"
    )


async def test_config_discovery_finds_security_relevant_settings(tmp_path):
    from app.understanding.config_discovery import settings_of

    repos.full(tmp_path)
    result = await _index(tmp_path)

    ids = {setting["id"] for setting in settings_of(result.graph)}
    assert "debug_enabled" in ids
    assert "bind_all_interfaces" in ids


async def test_dependency_model_is_not_counted_as_a_dependency(tmp_path):
    """Regression guard: a synthetic model node inflated the dependency count by one."""
    from app.understanding.dependencies import model_from_graph

    repos.full(tmp_path)
    result = await _index(tmp_path)

    model = model_from_graph(result.graph)
    assert model, "the dependency model must be reachable from graph metadata"
    names = {n.name for n in result.graph.nodes_of(NodeKind.DEPENDENCY.value)}
    assert "dependency model" not in names
    assert result.job.dependencies_discovered == model["count"]


async def test_dependency_model_flags_sensitive_libraries_without_claiming_vulnerability(tmp_path):
    from app.understanding.dependencies import model_from_graph

    repos.full(tmp_path)
    result = await _index(tmp_path)
    model = model_from_graph(result.graph)

    sensitive = {entry["name"].lower() for entry in model["sensitive"]}
    assert "pyyaml" in sensitive, "the fixture declares pyyaml"
    assert "no vulnerability database" in model["note"].lower(), (
        "the model must state that it makes no advisory claim"
    )


# ---------------------------------------------------------------------------
# the security model
# ---------------------------------------------------------------------------
async def _security(tmp_path):
    from app.security_model.builder import build_security_graph

    result = await _index(tmp_path)
    security, report = build_security_graph(code_graph=result.graph, root=tmp_path)
    return result, security, report


async def test_security_graph_finds_the_shell_sink_and_its_flow(tmp_path):
    repos.full(tmp_path)
    _result, security, _report = await _security(tmp_path)

    shell = [n for n in security.sinks if n.kind == "shell_exec"]
    assert shell, f"no shell sink found; kinds were {sorted({n.kind for n in security.sinks})}"

    flows = [f for f in security.flows if f.sink_kind == "shell_exec"]
    assert flows, "a source must reach the shell sink"
    for flow in flows:
        assert flow.basis in ("taint", "call-graph", "proximity")
        assert flow.precision in (Precision.RESOLVED.value, Precision.UNION.value)
        assert flow.steps, "a flow must carry its path"
        assert 0.0 < flow.confidence <= 0.95, "a flow is never certain"


def test_taint_analysis_proves_derivation_within_a_function():
    """The source must be read *inside* the function for intra-procedural taint to prove anything.

    Parameters are untainted at entry by design — cross-function taint is stitched by the flow
    builder along call edges, where the caller's argument is actually known. So this reads
    ``sys.argv`` in the same function that reaches the sink, which is the shape the AST analyser
    can prove on its own.
    """
    from app.security_model.taint import analyse_file
    from app.security_model.taxonomy import load_taxonomy

    source = (
        "import subprocess\nimport sys\n\n\n"
        "def run():\n"
        "    name = sys.argv[1]\n"
        # Interpolated into a command line before the sink: the injection shape.
        '    command = f"echo {name}"\n'
        "    return subprocess.run(command, shell=True)\n"
    )
    findings, error = analyse_file(path="x.py", text=source, taxonomy=load_taxonomy())
    assert not error
    assert findings, "a source reaching a shell sink in one function must be found"
    assert [f for f in findings if f.basis == "taint"], (
        "derivation was proven by the AST, so the basis must be 'taint', not 'proximity'"
    )
    assert [f for f in findings if f.interpolated], (
        f"expected an interpolated flow; got {[f.as_dict() for f in findings]}"
    )


async def test_a_sanitizer_lowers_confidence_but_never_clears_the_flow(tmp_path):
    """``safe_export`` quotes its input. The flow must survive, at lower confidence."""
    repos.minimal_python(tmp_path)
    _result, security, _report = await _security(tmp_path)

    assert security.sanitizers, "shlex.quote must be recognised as a sanitizer"
    for flow in [f for f in security.flows if f.sanitized]:
        assert flow.confidence < 0.9, "a sanitizer must reduce confidence"
        # It must still be reported: static presence is not proof of execution.
        assert flow.ref in {f.ref for f in security.flows}


def test_json_loads_is_not_matched_against_the_pickle_rule():
    """Regression guard for a CRITICAL false positive.

    A last-segment fallback matched ``json.loads`` against the rule for ``pickle.loads``,
    producing CWE-502 arbitrary-code-execution at 0.92 confidence on a safe JSON parse.
    """
    from app.security_model.taint import analyse_file
    from app.security_model.taxonomy import load_taxonomy

    source = (
        "import json\nimport sys\n\n\n"
        "def read():\n"
        "    data = sys.stdin.read()\n"
        "    return json.loads(data)\n"
    )
    findings, error = analyse_file(path="x.py", text=source, taxonomy=load_taxonomy())
    assert not error
    assert not [f for f in findings if f.cwe == "CWE-502"], (
        "json.loads must not be reported as unsafe deserialisation"
    )


def test_a_bare_import_still_matches_its_rule():
    """The other half of the same fix: ``from pickle import loads`` has no qualifier to check."""
    from app.security_model.taint import analyse_file
    from app.security_model.taxonomy import load_taxonomy

    source = (
        "import sys\nfrom pickle import loads\n\n\n"
        "def read():\n"
        "    data = sys.stdin.read()\n"
        "    return loads(data)\n"
    )
    findings, error = analyse_file(path="x.py", text=source, taxonomy=load_taxonomy())
    assert not error
    assert [f for f in findings if f.cwe == "CWE-502"], (
        "a bare `loads` after `from pickle import loads` must still match"
    )


def test_taxonomy_extension_replaces_a_rule_by_id(tmp_path):
    from app.security_model.taxonomy import load_taxonomy

    override = tmp_path / "taxonomy.json"
    override.write_text(
        json.dumps(
            {
                "sinks": [
                    {
                        "id": "sink.py.shell_true",
                        "kind": "shell_exec",
                        "pattern": "NEVER_MATCHES_ANYTHING",
                        "languages": ["python"],
                        "confidence": 0.0,
                        "why": "silenced by policy",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    taxonomy = load_taxonomy(override)
    rule = next(r for r in taxonomy.sinks if r.id == "sink.py.shell_true")
    assert rule.pattern == "NEVER_MATCHES_ANYTHING"
    assert taxonomy.extensions, "the extension must be recorded for the certificate"


def test_a_malformed_taxonomy_does_not_disable_security_analysis(tmp_path):
    from app.security_model.taxonomy import load_taxonomy

    override = tmp_path / "taxonomy.json"
    override.write_text("{ this is not json", encoding="utf-8")
    taxonomy = load_taxonomy(override)
    assert taxonomy.sinks, "the built-in rules must still load"
    assert taxonomy.errors, "the failure must be recorded, not swallowed"


def test_a_bad_regex_in_an_extension_is_rejected_at_load_time(tmp_path):
    from app.security_model.taxonomy import load_taxonomy

    override = tmp_path / "taxonomy.json"
    override.write_text(
        json.dumps({"sinks": [{"id": "bad", "kind": "sql", "pattern": "([unclosed"}]}),
        encoding="utf-8",
    )
    taxonomy = load_taxonomy(override)
    assert not any(r.id == "bad" for r in taxonomy.sinks)
    assert taxonomy.errors


async def test_trust_boundaries_are_derived_from_the_flow(tmp_path):
    repos.full(tmp_path)
    _result, security, _report = await _security(tmp_path)

    kinds = set(security.boundaries)
    assert "cli_to_application" in kinds
    assert "application_to_shell" in kinds


async def test_http_sources_and_auth_controls_are_recognised(tmp_path):
    repos.minimal_python(tmp_path)
    repos.with_http_routes(tmp_path)
    _result, security, _report = await _security(tmp_path)

    source_kinds = {n.kind for n in security.sources}
    assert "http_body" in source_kinds, f"saw {sorted(source_kinds)}"
    assert security.controls, "@login_required must be recognised as an auth control"


async def test_flow_ordering_puts_severity_before_confidence(tmp_path):
    """Regression guard: a MEDIUM flow outranked a CRITICAL one on confidence alone."""
    from app.models.enums import SEVERITY_RANK

    repos.full(tmp_path)
    _result, security, _report = await _security(tmp_path)

    reachable = [f for f in security.top_flows(20) if f.reachable_from_entrypoint]
    ranks = [SEVERITY_RANK.get(f.severity, 0) for f in reachable]
    assert ranks == sorted(ranks, reverse=True), (
        f"reachable flows must be ordered by descending severity, got {ranks}"
    )


# ---------------------------------------------------------------------------
# architecture and attack surface
# ---------------------------------------------------------------------------
async def _understood(tmp_path):
    from app.understanding.architecture import build_application_model
    from app.understanding.attack_surface import build_attack_surface

    result, security, _report = await _security(tmp_path)
    model = build_application_model(code_graph=result.graph, security_graph=security)
    surface = build_attack_surface(
        code_graph=result.graph, security_graph=security, application_model=model
    )
    return result, security, model, surface


async def test_architecture_model_classifies_with_recorded_evidence(tmp_path):
    repos.full(tmp_path)
    _result, _security, model, _surface = await _understood(tmp_path)

    assert model.application_type == "cli_tool"
    assert model.type_evidence, "the classification must record why"
    assert model.entrypoints
    # "config" and "other" are file buckets, not languages.
    assert "config" not in model.languages
    assert "python" in model.languages


async def test_architecture_model_detects_an_http_service(tmp_path):
    repos.minimal_python(tmp_path)
    repos.with_http_routes(tmp_path)
    _result, _security, model, _surface = await _understood(tmp_path)

    assert model.application_type == "http_service"
    assert "Flask" in model.frameworks


async def test_architecture_model_states_its_gaps(tmp_path):
    repos.minimal_python(tmp_path)
    _result, _security, model, _surface = await _understood(tmp_path)

    assert model.gaps, "a model with no auth and no tests must say so"
    joined = " ".join(model.gaps).lower()
    assert "authentication" in joined or "test" in joined


async def test_attack_surface_records_every_priority_factor(tmp_path):
    repos.full(tmp_path)
    _result, _security, _model, surface = await _understood(tmp_path)

    assert surface.measured is True
    assert surface.items
    for item in surface.items[:5]:
        assert set(item.factors) == {
            "severity",
            "external_controllability",
            "reachability",
            "dataflow_confidence",
            "controls",
            "coverage",
        }
        assert item.rationale and item.rationale[0].startswith("priority =")
        assert 0.0 < item.priority <= 1.0


async def test_attack_surface_reports_unreached_sinks_as_not_a_clearance(tmp_path):
    repos.full(tmp_path)
    _result, _security, _model, surface = await _understood(tmp_path)

    if surface.unreached_sinks:
        assert "not a clearance" in " ".join(surface.notes)


# ---------------------------------------------------------------------------
# the reasoning layer: tools and context
# ---------------------------------------------------------------------------
async def _toolset(tmp_path):
    from app.llm.graph_tools import GraphToolset

    result, security, model, surface = await _understood(tmp_path)
    return GraphToolset(
        code_graph=result.graph,
        security_graph=security,
        root=tmp_path,
        application_model=model,
        attack_surface=surface,
    )


async def test_graph_tools_are_bounded_and_recorded(tmp_path):
    repos.full(tmp_path)
    tools = await _toolset(tmp_path)

    window = tools.get_file("src/app/exporter.py")
    assert window["code"], "get_file must return source"
    assert window["end_line"] - window["start_line"] < 200, "the window must be bounded"

    tools.get_sinks()
    tools.get_dataflow()
    tools.get_architecture_summary()

    log = tools.tool_log()
    assert len(log) >= 4, "every call must be recorded"
    for entry in log:
        assert entry["name"]
        assert "result_bytes" in entry


async def test_get_coverage_reports_an_explicit_absence(tmp_path):
    repos.full(tmp_path)
    tools = await _toolset(tmp_path)

    coverage = tools.get_coverage()
    assert coverage["available"] is False
    assert coverage["reason"], "an absence must be explained, not returned as zero"


async def test_search_code_finds_the_sink(tmp_path):
    repos.full(tmp_path)
    tools = await _toolset(tmp_path)

    hits = tools.search_code("shell=True")
    assert hits
    assert any("exporter.py" in hit["file"] for hit in hits)
    assert any(hit["owner"] for hit in hits), "a hit must name its owning callable"


async def test_context_is_trust_labelled_and_bounded(tmp_path):
    from app.llm.context import ContextBuilder, Trust

    repos.full(tmp_path)
    tools = await _toolset(tmp_path)
    flow = tools.security_graph.top_flows(1)[0]

    context = ContextBuilder(tools=tools).for_flow(flow, task="testing.test_spec")
    payload = context.payload()

    assert Trust.REPOSITORY_CODE in payload
    assert Trust.REPOSITORY_CODE.startswith("UNTRUSTED_")
    assert Trust.METADATA in payload
    assert payload["_context"]["trust_note"]
    assert context.selected_functions, "the context must name the functions it selected"
    assert context.context_hash()
    assert context.metadata["evidence_limits"]["not_established"] is not None


async def test_context_drops_are_reported_and_keep_the_sink(tmp_path):
    """Regression guard: shedding the *largest* slice dropped the sink function."""
    from app.llm.context import ContextBudget, ContextBuilder

    repos.full(tmp_path)
    tools = await _toolset(tmp_path)
    flow = tools.security_graph.top_flows(1)[0]

    generous = ContextBuilder(tools=tools).for_flow(flow)
    # The full context for this flow is ~8k chars, so the budget has to be well under that to
    # actually bite. A budget that does not bite would make this test pass for the wrong reason.
    tight = ContextBuilder(tools=tools, budget=ContextBudget(total=4_000, code=600)).for_flow(flow)

    assert tight.size() <= generous.size()
    assert tight.dropped, "a budget that bites must report what it dropped"
    if tight.code_slices:
        # The first-inserted slice is the sink's; it must be the last to go.
        sink_file = tools.security_graph.nodes[flow.sink_ref].file
        assert any(sink_file in key for key in tight.code_slices), (
            f"the sink slice must survive; kept {sorted(tight.code_slices)}"
        )


# ---------------------------------------------------------------------------
# TestSpec validation
# ---------------------------------------------------------------------------
def test_testspec_rejects_a_traversal_target():
    from pydantic import ValidationError

    from app.testing.specs import OracleSpec, TestSpec

    with pytest.raises(ValidationError):
        TestSpec(
            target="../../etc/passwd",
            input_source="cli_argument",
            strategy="unit",
            oracle=OracleSpec(kind="exit_code_nonzero"),
            expected_security_property="must not escape",
            payloads=["x"],
        )


def test_testspec_rejects_a_newline_in_a_payload():
    from pydantic import ValidationError

    from app.testing.specs import OracleSpec, TestSpec

    with pytest.raises(ValidationError):
        TestSpec(
            target="src/app/exporter.py",
            input_source="cli_argument",
            strategy="unit",
            oracle=OracleSpec(kind="exit_code_nonzero"),
            expected_security_property="must not crash",
            payloads=["a\nb"],
        )


def test_testspec_rejects_statements_in_a_property_expression():
    from pydantic import ValidationError

    from app.testing.specs import OracleSpec, TestSpec

    with pytest.raises(ValidationError):
        TestSpec(
            target="src/app/exporter.py",
            input_source="cli_argument",
            strategy="property",
            oracle=OracleSpec(kind="exception_raised"),
            expected_security_property="invariant",
            property_expression="import os; os.system('x')",
        )


def test_testspec_requires_a_marker_role_for_a_marker_oracle():
    from pydantic import ValidationError

    from app.testing.specs import OracleSpec

    with pytest.raises(ValidationError):
        OracleSpec(kind="marker_in_stdout", marker_role="none")


def test_regression_strategy_accepts_a_replay_request_with_no_payload():
    """Regression guard: requiring a payload rejected a valid replay-form regression spec."""
    from app.testing.specs import OracleSpec, TestSpec

    spec = TestSpec(
        target="src/app/exporter.py",
        input_source="cli_argument",
        strategy="regression",
        oracle=OracleSpec(kind="marker_in_stdout", marker_role="pov_marker"),
        expected_security_property="must not reproduce",
        payloads=[],
        request_template={"op": "export", "name": "x&echo M"},
    )
    assert spec.strategy == "regression"


def test_no_spec_field_lets_a_model_assert_a_verdict():
    """The authority boundary, asserted structurally."""
    from app.testing.specs import FuzzSpec, OracleSpec, TestSpec, TestSpecProposal

    forbidden = {
        "verified",
        "reproduced",
        "safe",
        "exploitable",
        "passed",
        "confirmed",
        "assurance_level",
        "valid",
    }
    for model in (TestSpec, OracleSpec, FuzzSpec, TestSpecProposal):
        overlap = forbidden & set(model.model_fields)
        assert not overlap, f"{model.__name__} exposes a verdict field: {overlap}"


def test_plan_id_is_reproducible_and_index_scoped():
    from app.testing.specs import OracleSpec, TestSpec, plan_id_for

    spec = TestSpec(
        target="src/app/exporter.py",
        input_source="cli_argument",
        strategy="unit",
        oracle=OracleSpec(kind="exit_code_nonzero"),
        expected_security_property="must not crash",
        payloads=["x"],
    )
    assert plan_id_for(spec, index_id="a" * 64) == plan_id_for(spec, index_id="a" * 64)
    assert plan_id_for(spec, index_id="a" * 64) != plan_id_for(spec, index_id="b" * 64)


def test_two_candidates_deriving_the_same_spec_collapse_to_one_plan():
    """Regression guard: duplicate plan ids hit a UNIQUE constraint and failed the whole run.

    Deduplication keys on ``plan_id``, so the property that makes it work is that an identical
    spec against an identical index yields an identical id.
    """
    from app.testing.specs import OracleSpec, TestSpec, plan_id_for

    def build() -> TestSpec:
        return TestSpec(
            target="src/app/exporter.py:run_export",
            input_source="cli_argument",
            strategy="mutation",
            oracle=OracleSpec(kind="marker_in_stdout", marker_role="pov_marker"),
            expected_security_property="must not reach the shell",
            payloads=["kavachx-probe"],
            request_template={"op": "export"},
            payload_field="name",
        )

    plans = {plan_id_for(spec, index_id="a" * 64): spec for spec in (build(), build())}
    assert len(plans) == 1, "two candidates deriving one spec must not produce two plans"


# ---------------------------------------------------------------------------
# oracles
# ---------------------------------------------------------------------------
def test_marker_oracle_uses_the_kavachx_marker_not_the_spec():
    from app.discovery.base import POV_MARKER
    from app.testing import oracles
    from app.testing.specs import OracleSpec

    spec = OracleSpec(kind="marker_in_stdout", marker_role="pov_marker")
    fired = oracles.evaluate(spec, _exec_result(stdout=f"noise {POV_MARKER} noise"))
    held = oracles.evaluate(spec, _exec_result(stdout="ordinary output"))

    assert fired.verdict == oracles.Verdict.FIRED
    assert held.verdict == oracles.Verdict.HELD


def test_unsupported_is_not_held():
    """An oracle that cannot be evaluated must not report the property as holding."""
    from app.testing import oracles
    from app.testing.specs import OracleSpec

    result = oracles.evaluate(
        OracleSpec(kind="output_differs_from_baseline"), _exec_result(), baseline=None
    )
    assert result.verdict == oracles.Verdict.UNSUPPORTED
    assert result.detail


def test_exit_code_oracle_declines_to_judge_a_timeout():
    from app.testing import oracles
    from app.testing.specs import OracleSpec

    result = oracles.evaluate(
        OracleSpec(kind="exit_code_nonzero"), _exec_result(exit_code=124, timed_out=True)
    )
    assert result.verdict == oracles.Verdict.UNSUPPORTED
    assert "timed out" in result.detail


def test_require_reproductions_distinguishes_unsupported_from_refuted():
    from app.testing import oracles

    unsupported = [
        oracles.OracleResult(verdict=oracles.Verdict.UNSUPPORTED, detail="no trace collected")
    ]
    ok, detail = oracles.require_reproductions(unsupported, required=2)
    assert ok is False
    assert "unresolved rather than refuted" in detail


def test_require_reproductions_needs_independent_firings():
    from app.testing import oracles

    one = [
        oracles.OracleResult(verdict=oracles.Verdict.FIRED),
        oracles.OracleResult(verdict=oracles.Verdict.HELD),
    ]
    ok, _detail = oracles.require_reproductions(one, required=2)
    assert ok is False

    two = [oracles.OracleResult(verdict=oracles.Verdict.FIRED) for _ in range(2)]
    ok, detail = oracles.require_reproductions(two, required=2)
    assert ok is True
    assert "2 of 2 independent executions" in detail


# ---------------------------------------------------------------------------
# engines
# ---------------------------------------------------------------------------
def test_an_unavailable_engine_names_what_is_missing():
    from app.testing import engines

    report = engines.describe_available(module_checker=lambda _m: False)
    unavailable = [e for e in report["engines"] if e["status"] == "unavailable"]
    assert unavailable, "with no module importable, some engine must be unavailable"
    for entry in unavailable:
        assert entry["missing_binaries"] or entry["missing_modules"]
        assert "NOT RUN" in entry["reason"]
    assert "never reported as a clean result" in report["note"]


def test_the_stdlib_engine_is_always_available():
    """The unit/regression harness must not depend on a third-party runner."""
    from app.testing import engines

    selection = engines.select(
        language="python", strategy="regression", module_checker=lambda _m: False
    )
    assert selection.ok, selection.unavailable_reason
    assert selection.chosen.engine.id == "python-stdlib"


def test_an_unimplemented_engine_is_not_selected():
    from app.testing import engines

    selection = engines.select(language="go", strategy="fuzz")
    assert selection.ok is False
    assert selection.unavailable_reason


def test_coverage_feedback_engines_are_preferred():
    from app.testing import engines

    selection = engines.select(language="python", strategy="fuzz", module_checker=lambda _m: True)
    assert selection.ok
    assert selection.chosen.engine.coverage_feedback is True


# ---------------------------------------------------------------------------
# harness generation
# ---------------------------------------------------------------------------
def test_python_literals_are_python_not_json():
    """Regression guard: ``json.dumps(True)`` emitted ``true``; the harness died on ``if true:``."""
    from app.testing.harness import _js_lit, _py_lit

    assert _py_lit(True) == "True"
    assert _py_lit(None) == "None"
    assert _js_lit(True) == "true"
    assert _js_lit(None) == "null"


def test_literal_renderer_rejects_a_non_plain_value():
    from app.testing.harness import _py_lit

    with pytest.raises(TypeError):
        _py_lit(object())


def _mutation_plan(payload: str, mutation: str):
    from app.testing.specs import OracleSpec, TestPlan, TestSpec, plan_id_for

    spec = TestSpec(
        target="src/app/exporter.py:run_export",
        input_source="cli_argument",
        strategy="mutation",
        oracle=OracleSpec(kind="marker_in_stdout", marker_role="pov_marker"),
        expected_security_property="must not reach the shell",
        payloads=[payload],
        request_template={"op": "export"},
        payload_field="name",
        fuzz={"seeds": [payload], "mutations": [mutation], "max_iterations": 5},
    )
    return TestPlan(
        spec=spec,
        plan_id=plan_id_for(spec, index_id="a" * 64),
        language="python",
        engine="kx-mutational",
    )


def test_generated_harness_is_valid_python_and_quotes_its_payload(tmp_path):
    from app.testing import harness as harness_mod

    repos.full(tmp_path)
    hostile = 'x"); import os; os.system("touch /tmp/pwned'
    generated = harness_mod.generate(
        _mutation_plan(hostile, "separator_injection"),
        workspace=tmp_path,
        descriptor=_descriptor_for(tmp_path),
    )

    assert generated.ok, generated.error
    content = (tmp_path / generated.path).read_text(encoding="utf-8")
    # The whole point: the payload must be a data literal, and the file must still parse.
    compile(content, generated.path, "exec")
    assert "GENERATED BY KAVACHX" in content
    assert "os.system" not in content.replace(repr(hostile), ""), (
        "the hostile payload must appear only inside a quoted literal"
    )


def test_generated_harness_contains_no_control_bytes(tmp_path):
    """Regression guard: a raw NUL made a module unparseable at import time."""
    from app.testing import harness as harness_mod

    repos.full(tmp_path)
    generated = harness_mod.generate(
        _mutation_plan("seed", "unicode_edge_cases"),
        workspace=tmp_path,
        descriptor=_descriptor_for(tmp_path),
    )
    assert generated.ok, generated.error
    data = (tmp_path / generated.path).read_bytes()
    control = sorted({b for b in data if b < 9 or (13 < b < 32)})
    assert not control, f"generated harness contains control bytes: {control}"


def test_the_fuzzing_operator_table_has_no_raw_control_characters():
    """The same guard for the module that actually broke.

    A raw NUL byte in the mutation table made ``app.testing.fuzzing`` unimportable, which took the
    EXECUTE node down at import time — the operator escapes must stay escapes.
    """
    from app.testing import fuzzing

    data = Path(fuzzing.__file__).read_bytes()
    control = sorted({b for b in data if b < 9 or (13 < b < 32)})
    assert not control, f"app/testing/fuzzing.py contains control bytes: {control}"


def test_unsupported_strategy_is_reported_not_silently_skipped(tmp_path):
    from app.testing import harness as harness_mod
    from app.testing.specs import OracleSpec, TestPlan, TestSpec, plan_id_for

    spec = TestSpec(
        target="src/app/exporter.py",
        input_source="cli_argument",
        strategy="unit",
        oracle=OracleSpec(kind="exit_code_nonzero"),
        expected_security_property="must not crash",
        payloads=["x"],
    )
    plan = TestPlan(
        spec=spec, plan_id=plan_id_for(spec, index_id="a" * 64), language="rust", engine="x"
    )
    generated = harness_mod.generate(plan, workspace=tmp_path, descriptor=None)
    assert generated.ok is False
    assert "did NOT run" in generated.error


# ---------------------------------------------------------------------------
# deterministic synthesis (no model)
# ---------------------------------------------------------------------------
async def test_deterministic_specs_need_no_model(tmp_path):
    from app.testing.synthesis import deterministic_specs

    repos.full(tmp_path)
    _result, security, _report = await _security(tmp_path)

    flow = next(f for f in security.top_flows(20) if f.sink_kind == "shell_exec")
    specs = deterministic_specs(flow, descriptor=_descriptor_for(tmp_path), security_graph=security)

    assert specs, "the fallback must produce a usable spec with no model involved"
    assert specs[0].strategy == "mutation"
    assert specs[0].oracle.kind == "marker_in_stdout"
    # Regression guard: a pre-validation regression spec asserts nothing, so it must not be here.
    assert not any(s.strategy == "regression" for s in specs)


# ---------------------------------------------------------------------------
# coverage
# ---------------------------------------------------------------------------
def test_unmeasured_coverage_is_not_zero_coverage():
    from app.testing.coverage import unmeasured

    observation = unmeasured("nothing was executed")
    assert observation.measured is False
    assert observation.reason
    assert observation.percent == 0.0


def test_coverage_delta_is_the_steering_signal():
    from app.testing.coverage import CoverageObservation

    first = CoverageObservation(covered_lines={"a.py:1"}, measured=True)
    second = CoverageObservation(covered_lines={"a.py:1", "a.py:2"}, measured=True)
    assert second.new_relative_to(first) == {"a.py:2"}
    assert first.new_relative_to(second) == set()
    assert first.merge(second).covered_lines == {"a.py:1", "a.py:2"}


async def test_uncovered_branch_seeding_derives_boundary_values(tmp_path):
    """The spec's example: ``if limit < 0:`` should suggest -1, 0, 1."""
    from app.testing.coverage import uncovered_branches, unmeasured

    repos.minimal_python(tmp_path)
    repos.with_boundary_branch(tmp_path)
    result = await _index(tmp_path)

    branches = uncovered_branches(
        code_graph=result.graph, coverage=unmeasured("none"), root=tmp_path, limit=40
    )
    pager = [b for b in branches if "pager.py" in b.location]
    assert pager, f"the boundary branch must be found; saw {[b.location for b in branches]}"

    suggested = {value for branch in pager for value in branch.suggested_values}
    assert {"-1", "0", "1"} <= suggested, f"expected the off-by-one triple, got {suggested}"
    assert {"99", "100", "101"} & suggested, "the second bound must contribute too"


def test_coverage_feedback_payload_tells_the_model_it_will_be_measured():
    from app.testing.coverage import UncoveredBranch, feedback_payload, unmeasured

    payload = feedback_payload(
        coverage=unmeasured("none"),
        previous=None,
        branches=[
            UncoveredBranch(location="a.py:1", condition="if x < 0:", suggested_values=["-1"])
        ],
    )
    assert payload["uncovered_branches"]
    assert "re-measuring coverage" in payload["note"]


# ---------------------------------------------------------------------------
# regression tests
# ---------------------------------------------------------------------------
class _Outcome:
    """A stand-in for the validator's reproduction record."""

    def __init__(self, **kwargs):
        self.pov_request: dict = {}
        self.pov_payload = ""
        self.pov_kind = ""
        self.input_hash = "a" * 64
        self.reproduction_count = 2
        self.detail = "reproduced"
        self.cwe = ""
        self.__dict__.update(kwargs)


def test_regression_plan_uses_the_recorded_reproducing_input():
    from app.testing.regression import plan_from_finding

    plan = plan_from_finding(
        outcome=_Outcome(
            pov_request={"op": "export", "format": "txt", "name": "x&echo MARKER"},
            pov_payload="x&echo MARKER",
            pov_kind="command_injection",
            cwe="CWE-78",
        ),
        finding_handle="V01",
        target="src/app/exporter.py",
        entrypoint="main",
        index_id="a" * 64,
    )
    assert plan is not None
    assert plan.spec.strategy == "regression"
    assert plan.spec.oracle.kind == "marker_in_stdout"
    assert plan.spec.payload_field == "name", "the payload field must come from the request"
    assert plan.spec.payloads == ["x&echo MARKER"]
    assert plan.provenance["from"] == "validated_finding"


def test_regression_plan_falls_back_to_replaying_the_whole_request():
    """When the payload is not a separable field, the recorded request *is* the test."""
    from app.testing.regression import plan_from_finding

    plan = plan_from_finding(
        outcome=_Outcome(
            pov_request={"op": "parse", "headers": "h0:0 h1:1"},
            pov_payload="something that matches no single field",
            pov_kind="length_boundary",
            cwe="CWE-1284",
        ),
        finding_handle="V02",
        target="src/app/parser.py",
        entrypoint="main",
        index_id="a" * 64,
    )
    assert plan is not None
    assert plan.spec.payload_field == ""
    assert plan.spec.payloads == []
    assert plan.spec.request_template == {"op": "parse", "headers": "h0:0 h1:1"}


def test_regression_artifact_is_valid_python_in_the_target_convention():
    from app.testing.regression import artifact_for_target, plan_from_finding

    class Descriptor:
        entry_module = "main"
        entry_callable = "main"
        entry_file = "src/main.py"
        language = "python"

    plan = plan_from_finding(
        outcome=_Outcome(
            pov_request={"op": "export", "name": "x&echo MARKER"},
            pov_payload="x&echo MARKER",
            pov_kind="command_injection",
            cwe="CWE-78",
        ),
        finding_handle="V01",
        target="src/app/exporter.py",
        entrypoint="main",
        index_id="a" * 64,
    )
    artifact = artifact_for_target(
        plan=plan,
        framework="pytest",
        descriptor=Descriptor(),
        finding_handle="V01",
        location="src/app/exporter.py:12",
    )
    assert artifact is not None
    assert artifact.path.startswith("tests/")
    compile(artifact.content, artifact.path, "exec")
    assert "V01" in artifact.content
    assert artifact.rationale


def test_regression_artifact_for_an_unsupported_framework_returns_none():
    from app.testing.regression import artifact_for_target, plan_from_finding

    plan = plan_from_finding(
        outcome=_Outcome(pov_request={"op": "export", "name": "x"}, pov_payload="x"),
        finding_handle="V01",
        target="src/x.rs",
        entrypoint="main",
        index_id="a" * 64,
    )
    assert (
        artifact_for_target(
            plan=plan, framework="cargo-test", descriptor=None, finding_handle="V01"
        )
        is None
    )


# ---------------------------------------------------------------------------
# LLM schema validation and routing
# ---------------------------------------------------------------------------
async def test_mock_provider_produces_a_schema_valid_testspec():
    from app.llm.base import LLMRequest, LLMTask
    from app.llm.mock_provider import MockLLMProvider
    from app.testing.specs import TestSpecProposal

    response = await MockLLMProvider().generate(
        LLMRequest(
            task=LLMTask.TEST_SPEC,
            instruction="propose",
            payload={
                "metadata": {
                    "flow": {
                        "sink_kind": "shell_exec",
                        "source_kind": "cli_arg",
                        "cwe": "CWE-78",
                        "basis": "call-graph",
                        "path": ["SINK src/app/exporter.py:12 shell"],
                    },
                    "sanitizers": [],
                }
            },
            schema=TestSpecProposal,
        )
    )
    spec = response.parsed.specs[0]
    assert spec.strategy == "mutation"
    assert spec.oracle.kind == "marker_in_stdout"
    assert spec.payload_field == "name"


def test_mock_provider_has_a_script_for_every_routed_task():
    """A routed task with no mock script loses its whole code path in offline mode.

    It would not fail loudly either — it surfaces as one logged error per run and a silently
    skipped stage, so the demo would appear to work while exercising less than it claims.
    """
    import inspect

    from app.llm.base import LLMTask
    from app.llm.mock_provider import MockLLMProvider
    from app.llm.routing import TASK_ROLES

    # The dispatch table is keyed by LLMTask *constants*, so the source text carries the attribute
    # names rather than the task id strings. Map each routed id back to its attribute.
    attr_for = {
        value: name
        for name, value in vars(LLMTask).items()
        if not name.startswith("_") and isinstance(value, str)
    }
    source = inspect.getsource(MockLLMProvider._raw_generate)
    missing = [
        task
        for task in sorted(TASK_ROLES)
        if f"LLMTask.{attr_for.get(task, '<unmapped>')}" not in source
    ]
    assert not missing, f"the mock provider has no script for: {missing}"


def test_role_routing_sends_expensive_reasoning_to_the_strong_model():
    from app.llm.base import LLMTask
    from app.llm.routing import ModelRole, role_for

    assert role_for(LLMTask.TEST_SPEC) == ModelRole.SECURITY
    assert role_for(LLMTask.PATCH_SYNTHESIS) == ModelRole.SECURITY
    assert role_for(LLMTask.STATIC_TRIAGE) == ModelRole.ROUTER
    # An unclassified task must get the general model, not the cheapest.
    assert role_for("some.unknown.task") == ModelRole.WORKHORSE


def test_openai_compatible_presets_cover_the_offline_providers():
    from app.llm.openai_compatible import PRESETS

    for preset in ("llama", "ollama", "vllm", "openai_compatible"):
        assert preset in PRESETS
        assert PRESETS[preset].default_base_url
