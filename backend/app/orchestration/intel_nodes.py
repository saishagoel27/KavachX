"""Code-intelligence pipeline nodes: INDEX → INDEX_VALIDATE → UNDERSTAND → SECURITY_MODEL,
and later TEST_SYNTHESIS → EXECUTE → REGRESSION.

These live in their own module rather than being appended to :mod:`app.orchestration.nodes`
because that file is already the largest in the backend, and because the boundary is real: every
node here is part of *understanding* the target or *testing* it, and none of them decides a
verdict. The verdict-bearing nodes (validate, patch, gauntlet, attest) stay where they are.

Every node follows the existing contract exactly — emit ``phase start``, do the work through a
deterministic subsystem, persist, emit ``phase done``/``blocked``/``failed``, return a state delta
— so the graph wrapper's checkpointing, abort handling and error recording apply unchanged.

The honesty rule that shapes all of them: a stage that could not do its work emits ``blocked``
with the reason and records a claim bound, rather than emitting ``done`` over an empty result.
"""

from __future__ import annotations

from typing import Any

from app.core.logging import get_logger
from app.models.enums import Phase
from app.orchestration.state import KavachState, RunContext

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# INDEX
# ---------------------------------------------------------------------------
async def node_index(ctx: RunContext, state: KavachState) -> KavachState:
    """Build the code knowledge graph and record the index job.

    This replaces "tree-sitter happened" with a first-class, reproducible index. It runs against
    the **mutable** ``work/`` copy, never ``pristine/``: GitNexus writes its LadybugDB index into a
    ``.gitnexus/`` directory inside whatever it analyses, and writing into the pinned tree would
    invalidate the content hash that is the run's source identity.
    """
    from app.indexing.service import build_index, graph_summary_for_state
    from app.orchestration.nodes import _emit_metrics, _emit_tools, _mark_phase, _set_phase

    assert ctx.pinned is not None
    phase = Phase.INDEX.value
    await _set_phase(ctx, phase)
    await ctx.emitter.phase_start(phase, "indexing the repository into a code knowledge graph")

    result = await build_index(
        ctx.pinned.work,
        run_short=ctx.short_code,
        repository=str(state.get("target", {}).get("repository", "")),
        commit_sha=str(state.get("target", {}).get("commit_sha", "")),
        source_sha256=ctx.pinned.content_sha256,
    )

    ctx.code_graph = result.graph
    ctx.index_job = result.job
    ctx.index_health = result.health
    ctx.file_indexes = result.file_indexes
    if result.execution_flows:
        # Provider-derived execution flows ride on the graph so the architecture stage can use
        # them without a second query round trip.
        result.graph.metadata["execution_flows"] = result.execution_flows

    await _emit_tools(ctx, result.tool_events)

    job = result.job
    summary = graph_summary_for_state(result)
    state["index"] = job.as_dict()
    state["graph"] = summary

    await ctx.emitter.index(
        index_id=job.index_id,
        status=job.status,
        graph_source=job.graph_source,
        files_discovered=job.files_discovered,
        files_indexed=job.files_indexed,
        files_skipped=job.files_skipped,
        symbols=job.symbols_discovered,
        relationships=job.relationships_discovered,
        resolved_relationships=job.resolved_relationships,
        entrypoints=job.entrypoints_discovered,
        tests=job.tests_discovered,
        configs=job.configs_discovered,
        dependencies=job.dependencies_discovered,
        health_grade=result.health.grade,
        duration_ms=job.duration_ms,
    )
    await ctx.emitter.thought(
        agent="INDEX",
        hypothesis="The repository can be reconstructed as a queryable code knowledge graph.",
        evidence=[
            f"providers: {', '.join(job.providers) or 'none'}",
            f"{job.files_indexed}/{job.files_discovered} files indexed",
            f"{job.symbols_discovered} symbols, {job.relationships_discovered} relationships",
            f"{job.resolved_relationships} relationship(s) resolved by a symbol-resolving indexer "
            f"({job.resolved_ratio * 100:.0f}%)",
            f"index id {job.index_id[:16]} (reproducible from source sha + versions)",
        ],
        decision=(
            f"Index {job.status} from {job.graph_source}. "
            + (
                "Relationships are resolved references."
                if job.resolved_ratio >= 0.5
                else "Most relationships are name matches, so reachability over-approximates."
            )
        ),
        confidence=1.0,
    )

    if not result.usable:
        # A grade of F means the tree could not be understood at all. Continuing would let every
        # downstream "nothing found" read as a clean result.
        detail = result.health.summary
        state["errors"] = [
            *state.get("errors", []),
            {"phase": phase, "error": f"index unusable: {detail}", "at": _now()},
        ]
        await ctx.emitter.phase_failed(phase, f"index unusable: {detail}")
        await _mark_phase(ctx, phase, "failed")
        state["aborted"] = True
        return state

    await _persist_index(ctx, result)
    await _emit_metrics(ctx)
    await ctx.emitter.phase_done(phase, job.summary_line())
    await _mark_phase(ctx, phase, "completed")
    state["phase"] = phase
    return state


# ---------------------------------------------------------------------------
# INDEX_VALIDATE
# ---------------------------------------------------------------------------
async def node_index_validate(ctx: RunContext, state: KavachState) -> KavachState:
    """Validate the index and publish the health report.

    Successful parsing is not successful indexing. This stage turns the deterministic checks into
    a graded report, stores it as an artifact, and records the claims the index cannot support so
    every later stage — and the certificate — inherits the bound.
    """
    from app.orchestration.nodes import _mark_phase, _set_phase, _store_artifact

    phase = Phase.INDEX_VALIDATE.value
    await _set_phase(ctx, phase)
    await ctx.emitter.phase_start(phase, "validating the index")

    if ctx.index_health is None or ctx.index_job is None:
        await ctx.emitter.phase_blocked(phase, "no index was built, so none could be validated")
        await _mark_phase(ctx, phase, "blocked")
        return state

    report = ctx.index_health
    rendered = report.render(ctx.index_job)
    await _store_artifact(
        ctx,
        kind="index_health",
        name="INDEX_HEALTH.md",
        content=f"```\n{rendered}\n```\n",
        meta={"grade": report.grade, "index_id": ctx.index_job.index_id},
    )

    state["index_health"] = report.as_dict()

    for check in report.checks:
        if check.severity in ("warn", "fail"):
            await ctx.emitter.log(
                f"index {check.severity.upper()}: {check.title} — {check.detail}",
                stream="stderr",
                source="index",
            )

    await ctx.emitter.thought(
        agent="INDEX VALIDATION",
        hypothesis="A parser returning without error means the repository was understood.",
        evidence=[
            f"grade {report.grade}",
            f"{len(report.failures)} failing check(s), {len(report.warnings)} warning(s)",
            *[c.title for c in [*report.failures, *report.warnings][:4]],
        ],
        decision=(
            f"Index graded {report.grade}. "
            + (
                f"{len(report.claim_bounds)} claim bound(s) recorded; every downstream result "
                "inherits them."
                if report.claim_bounds
                else "No claim bounds — the index supports the full analysis."
            )
        ),
        confidence=1.0,
    )

    if report.claim_bounds:
        await ctx.emitter.phase_blocked(
            phase,
            f"grade {report.grade} — this index cannot support: "
            + "; ".join(report.claim_bounds[:2]),
        )
        await _mark_phase(ctx, phase, "blocked")
    else:
        await ctx.emitter.phase_done(phase, f"index grade {report.grade}, no claim bounds")
        await _mark_phase(ctx, phase, "completed")
    state["phase"] = phase
    return state


# ---------------------------------------------------------------------------
# SECURITY_MODEL
# ---------------------------------------------------------------------------
async def node_security_model(ctx: RunContext, state: KavachState) -> KavachState:
    """Build the security graph: sources, sinks, sanitizers, controls, boundaries, data flows."""
    import asyncio

    from app.orchestration.nodes import _emit_metrics, _emit_tools, _mark_phase, _set_phase
    from app.security_model.builder import build_security_graph
    from app.security_model.taxonomy import load_taxonomy

    assert ctx.pinned is not None
    phase = Phase.SECURITY_MODEL.value
    await _set_phase(ctx, phase)
    await ctx.emitter.phase_start(phase, "deriving the security graph over the code graph")

    if ctx.code_graph is None:
        await ctx.emitter.phase_blocked(phase, "no code graph exists to derive a security model from")
        await _mark_phase(ctx, phase, "blocked")
        return state

    taxonomy = load_taxonomy()
    # Classification and taint analysis are CPU-bound and synchronous; running them inline would
    # block the event loop the operator's SSE stream is served from.
    security, report = await asyncio.to_thread(
        build_security_graph,
        code_graph=ctx.code_graph,
        root=ctx.pinned.work,
        taxonomy=taxonomy,
    )
    ctx.security_graph = security
    await _persist_security_model(ctx, security)
    await _emit_tools(ctx, report.tool_events)

    stats = security.stats()
    state["security"] = {
        **stats,
        "content_hash": security.content_hash(),
        "taxonomy": security.taxonomy_summary,
        "warnings": security.warnings[:20],
    }

    for flow in security.top_flows(8):
        await ctx.emitter.security_flow(
            ref=flow.ref,
            source_kind=flow.source_kind,
            sink_kind=flow.sink_kind,
            severity=flow.severity,
            cwe=flow.cwe,
            basis=flow.basis,
            precision=flow.precision,
            confidence=flow.confidence,
            reachable=flow.reachable_from_entrypoint,
            sanitized=flow.sanitized,
            path=flow.explain()[:12],
            boundaries=flow.boundaries,
        )

    await ctx.emitter.thought(
        agent="SECURITY MODEL",
        hypothesis="Security semantics can be layered over a general code graph.",
        evidence=[
            f"{stats['sources']} source(s), {stats['sinks']} sink(s)",
            f"{stats['sanitizers']} sanitizer(s), {stats['validators']} validator(s), "
            f"{stats['controls']} auth control(s)",
            f"{stats['flows']} data flow(s): {stats['by_flow_basis']}",
            f"{stats['reachable_flows']} reachable from a declared entrypoint",
            f"{stats['trust_boundaries']} trust boundary(ies)",
        ],
        decision=(
            f"{stats['flows']} evidenced flow(s) derived. A flow is a hypothesis with a stated "
            "basis and precision — never a finding."
        ),
        confidence=1.0,
    )
    await _emit_metrics(ctx)
    if stats["flows"]:
        await ctx.emitter.phase_done(
            phase,
            f"{stats['sources']} sources · {stats['sinks']} sinks · {stats['flows']} flows "
            f"({stats['reachable_flows']} reachable) · {stats['trust_boundaries']} boundaries",
        )
        await _mark_phase(ctx, phase, "completed")
    else:
        await ctx.emitter.phase_blocked(
            phase,
            "no data flow from an external input to a dangerous operation was derived — that is "
            "an absence of derived flows, not evidence of safety",
        )
        await _mark_phase(ctx, phase, "blocked")
    state["phase"] = phase
    return state


# ---------------------------------------------------------------------------
# UNDERSTAND
# ---------------------------------------------------------------------------
async def node_understand(ctx: RunContext, state: KavachState) -> KavachState:
    """Produce the structured application model and the ranked attack surface.

    The model is derived deterministically and is complete without any model call. When a provider
    is configured it may *annotate* the derived model under a strict schema; annotations are marked
    and can never change a count, a boundary, an entrypoint or a control.
    """
    from app.orchestration.nodes import _emit_metrics, _mark_phase, _set_phase, _store_artifact
    from app.understanding.architecture import build_application_model
    from app.understanding.attack_surface import build_attack_surface

    phase = Phase.UNDERSTAND.value
    await _set_phase(ctx, phase)
    await ctx.emitter.phase_start(phase, "building the application model and attack surface")

    if ctx.code_graph is None or ctx.security_graph is None:
        await ctx.emitter.phase_blocked(
            phase, "the code graph or security graph is missing, so nothing could be modelled"
        )
        await _mark_phase(ctx, phase, "blocked")
        return state

    model = build_application_model(
        code_graph=ctx.code_graph, security_graph=ctx.security_graph
    )
    surface = build_attack_surface(
        code_graph=ctx.code_graph,
        security_graph=ctx.security_graph,
        application_model=model,
    )
    ctx.application_model = model
    ctx.attack_surface = surface
    await _persist_architecture(ctx, model, surface)

    # -- the read-only tool surface, built once and reused by every later stage -------------
    from app.llm.context import ContextBuilder
    from app.llm.graph_tools import GraphToolset

    ctx.toolset = GraphToolset(
        code_graph=ctx.code_graph,
        security_graph=ctx.security_graph,
        root=ctx.pinned.work if ctx.pinned else None,
        application_model=model,
        attack_surface=surface,
    )
    ctx.context_builder = ContextBuilder(tools=ctx.toolset)

    state["architecture"] = model.as_dict()
    state["attack_surface"] = surface.as_dict()

    await _store_artifact(
        ctx,
        kind="architecture",
        name="ARCHITECTURE.md",
        content=f"```\n{model.render()}\n```\n\n```\n{surface.render()}\n```\n",
        meta={
            "application_type": model.application_type,
            "content_hash": model.content_hash(),
        },
    )

    await ctx.emitter.architecture(
        application_type=model.application_type,
        languages=model.languages,
        frameworks=model.frameworks,
        entrypoints=len(model.entrypoints),
        unauthenticated_entrypoints=len(surface.unauthenticated_entrypoints),
        data_stores=model.data_stores,
        authentication=model.authentication,
        trust_boundaries=[b.get("kind", "") for b in model.trust_boundaries],
        surface_items=len(surface.items),
        externally_controllable=len(surface.externally_controllable),
        testable=len(surface.testable),
        measured=surface.measured,
        gaps=model.gaps[:6],
    )
    await ctx.emitter.thought(
        agent="UNDERSTAND",
        hypothesis="A structured application model is more useful than a textual summary.",
        evidence=[
            f"type: {model.application_type} ({'; '.join(model.type_evidence[:2])})",
            f"{len(model.entrypoints)} entrypoint(s), "
            f"{len(surface.unauthenticated_entrypoints)} with no control on the path",
            f"{len(surface.items)} ranked attack-surface item(s), "
            f"{len(surface.testable)} testable",
            f"tests: {model.tests.get('files', 0)} file(s), {model.tests.get('cases', 0)} case(s)",
            *model.gaps[:2],
        ],
        decision=(
            f"Application modelled as {model.application_type}; attack surface "
            + ("measured." if surface.measured else "NOT measured (no entrypoint to search from).")
        ),
        confidence=1.0,
    )
    await _emit_metrics(ctx)
    await ctx.emitter.phase_done(
        phase,
        f"{model.application_type} · {len(model.entrypoints)} entrypoints · "
        f"{len(surface.items)} ranked paths · {len(model.gaps)} stated gap(s)",
    )
    await _mark_phase(ctx, phase, "completed")
    state["phase"] = phase
    return state


# ---------------------------------------------------------------------------
# TEST_SYNTHESIS
# ---------------------------------------------------------------------------
async def node_test_synthesis(ctx: RunContext, state: KavachState) -> KavachState:
    """Turn the top attack-surface candidates into generated, executable harnesses."""
    from app.orchestration.nodes import _emit_metrics, _emit_tools, _mark_phase, _set_phase
    from app.testing.engines import async_module_checker, describe_available
    from app.testing.synthesis import TestSynthesisEngine

    phase = Phase.TEST_SYNTHESIS.value
    await _set_phase(ctx, phase)

    if ctx.static_only:
        await ctx.emitter.phase_start(phase, "skipped — nothing can be executed")
        await ctx.emitter.phase_blocked(
            phase,
            "static-only run: "
            + str(state.get("static_only_reason", "the target cannot be executed"))
            + ". No harness was generated, so no candidate can be proved by execution.",
        )
        await _mark_phase(ctx, phase, "blocked")
        return state

    if ctx.security_graph is None or ctx.attack_surface is None or ctx.sandbox is None:
        await ctx.emitter.phase_blocked(phase, "no attack surface or sandbox is available")
        await _mark_phase(ctx, phase, "blocked")
        return state

    await ctx.emitter.phase_start(phase, "generating security tests for the ranked candidates")

    # Engine availability must be probed where the harness will run, not in this process.
    ctx.module_checker = await async_module_checker(ctx.sandbox)
    inventory = describe_available(module_checker=ctx.module_checker)
    await ctx.emitter.log(
        f"test engines: {inventory['counts']['available']} available, "
        f"{inventory['counts']['unavailable']} unavailable, "
        f"{inventory['counts']['unimplemented']} unimplemented",
        source="testing",
    )
    for engine in inventory["engines"]:
        if engine["status"] == "unavailable":
            await ctx.emitter.log(
                f"engine NOT RUN: {engine['reason']}", stream="stderr", source="testing"
            )

    engine = TestSynthesisEngine(
        workspace=ctx.pinned.work,
        index_id=ctx.index_job.index_id if ctx.index_job else "",
        descriptor=ctx.descriptor,
        code_graph=ctx.code_graph,
        security_graph=ctx.security_graph,
        provider=ctx.provider,
        context_builder=ctx.context_builder,
        module_checker=ctx.module_checker,
    )

    budget = {"quick": 2, "standard": 4, "deep": 8}.get(ctx.analysis_profile, 4)
    candidates = [i for i in ctx.attack_surface.top(budget * 2) if i.testable][:budget]
    if not candidates:
        await ctx.emitter.phase_blocked(
            phase,
            "no attack-surface item is drivable by a generated harness "
            + (
                ctx.attack_surface.items[0].testability_reason
                if ctx.attack_surface.items
                else "(no items ranked)"
            ),
        )
        await _mark_phase(ctx, phase, "blocked")
        return state

    plans: list[dict[str, Any]] = []
    generated = 0
    unsupported = 0
    #: plan_id -> the candidate that first produced it.
    #
    # A plan_id is sha256 over the canonical spec plus the index id, so two candidates that yield
    # an identical spec yield an identical plan_id — and on the seeded target they do: two flows
    # reaching the same shell sink produce the same target, strategy, oracle and payload. That is
    # not a collision to work around, it is the same test. Running and storing it twice would waste
    # a sandbox execution and double-count the evidence, so the second candidate records that it
    # shares a test rather than generating another.
    seen_plans: dict[str, str] = {}
    shared = 0

    for item in candidates:
        flow = next((f for f in ctx.security_graph.flows if f.ref == item.ref), None)
        if flow is None:
            continue
        result = await engine.synthesise(flow, max_specs=2)
        ctx.synthesis[flow.ref] = result
        await _emit_tools(ctx, result.tool_events)
        if result.context:
            ctx.model_contexts[flow.ref] = result.context
            await _persist_context(ctx, flow.ref, result.context)

        fresh = []
        for plan in result.plans:
            owner = seen_plans.get(plan.plan_id)
            if owner is not None:
                shared += 1
                plan.notes.append(
                    f"Identical to the test already generated for {owner}; it is executed once "
                    "and its evidence is shared by both candidates."
                )
                continue
            seen_plans[plan.plan_id] = flow.ref
            fresh.append(plan)

        await _persist_plans(
            ctx, fresh, "model" if result.proposal_used else "deterministic"
        )
        for plan in fresh:
            plans.append(plan.as_dict())
            if plan.status == "GENERATED":
                generated += 1
                await ctx.emitter.testspec(
                    plan_id=plan.plan_id,
                    candidate=plan.candidate_ref,
                    strategy=plan.spec.strategy,
                    engine=plan.engine,
                    oracle=plan.spec.oracle.kind,
                    harness_path=plan.harness_path,
                    harness_hash=plan.harness_sha256,
                    security_property=plan.spec.expected_security_property,
                    proposed_by="model" if result.proposal_used else "deterministic",
                )
            else:
                unsupported += 1

    if shared:
        await ctx.emitter.log(
            f"{shared} candidate(s) resolved to a test already generated for another candidate; "
            "each such test is executed once and its evidence shared.",
            source="testing",
        )

        await ctx.emitter.thought(
            agent="TEST SYNTHESIS",
            hypothesis=f"An executable test can prove or refute {flow.ref[:60]}.",
            evidence=[
                f"{flow.source_kind} → {flow.sink_kind} at {flow.precision} precision",
                *result.notes[:3],
            ],
            decision=(
                f"{len(result.executable)} harness(es) generated"
                + (" (model-assisted)" if result.proposal_used else " (deterministic)")
                + (f"; {len(result.unsupported)} unsupported" if result.unsupported else "")
            ),
            confidence=1.0,
        )

    # The generated harnesses are the run's most inspectable artifact: they are exactly what was
    # executed, byte for byte.
    await _store_generated_tests(ctx, plans)

    state["test_plans"] = plans
    state["phase"] = phase
    await _emit_metrics(ctx)
    if generated:
        await ctx.emitter.phase_done(
            phase, f"{generated} harness(es) generated · {unsupported} unsupported"
        )
        await _mark_phase(ctx, phase, "completed")
    else:
        await ctx.emitter.phase_blocked(
            phase, f"no harness could be generated ({unsupported} unsupported)"
        )
        await _mark_phase(ctx, phase, "blocked")
    return state


async def _store_generated_tests(ctx: RunContext, plans: list[dict[str, Any]]) -> None:
    """Store every generated harness as a run artifact."""
    from app.orchestration.nodes import _store_artifact

    if ctx.pinned is None:
        return
    for plan in plans:
        path = plan.get("harness_path") or ""
        if not path:
            continue
        source = ctx.pinned.work / path
        if not source.is_file():
            continue
        try:
            content = source.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        await _store_artifact(
            ctx,
            kind="generated_test",
            name=path.rsplit("/", 1)[-1],
            content=content,
            media_type="text/x-python",
            meta={
                "plan_id": plan.get("plan_id", ""),
                "strategy": plan.get("strategy") or plan.get("spec", {}).get("strategy", ""),
                "engine": plan.get("engine", ""),
                "candidate": plan.get("candidate_ref", ""),
                "sha256": plan.get("harness_sha256", ""),
            },
        )


# ---------------------------------------------------------------------------
# EXECUTE
# ---------------------------------------------------------------------------
async def node_execute(ctx: RunContext, state: KavachState) -> KavachState:
    """Execute the generated harnesses in the sandbox and record oracle verdicts.

    This is where a candidate stops being a hypothesis. The oracle decides; nothing here
    interprets output. A firing oracle that reproduces the required number of times in independent
    processes is what the validation node then promotes to a finding.
    """
    from app.orchestration.nodes import _emit_metrics, _emit_tools, _mark_phase, _set_phase
    from app.testing.coverage import CoverageObservation, unmeasured
    from app.testing.executor import TestExecutor
    from app.testing.fuzzing import CoverageGuidedFuzzer

    phase = Phase.EXECUTE.value
    await _set_phase(ctx, phase)

    if ctx.static_only:
        await ctx.emitter.phase_start(phase, "skipped — nothing can be executed")
        await ctx.emitter.phase_blocked(
            phase,
            "static-only run: no harness was executed, so nothing in this run is proved by "
            "reproduction.",
        )
        await _mark_phase(ctx, phase, "blocked")
        return state

    # Deduplicated by plan_id for the same reason synthesis deduplicates: an identical spec is an
    # identical test, and executing it once per candidate that produced it would multiply sandbox
    # cost while producing the same evidence twice.
    executable: list[Any] = []
    seen_plan_ids: set[str] = set()
    for result in ctx.synthesis.values():
        for plan in result.executable:
            if plan.plan_id in seen_plan_ids:
                continue
            seen_plan_ids.add(plan.plan_id)
            executable.append(plan)

    if not executable or ctx.sandbox is None:
        await ctx.emitter.phase_start(phase, "no generated harness to execute")
        await ctx.emitter.phase_blocked(phase, "no harness was available to execute")
        await _mark_phase(ctx, phase, "blocked")
        return state

    await ctx.emitter.phase_start(
        phase, f"executing {len(executable)} generated harness(es) in the sandbox"
    )

    executor = TestExecutor(
        sandbox=ctx.sandbox,
        workspace=ctx.pinned.work,
        commit_sha=str(state.get("target", {}).get("commit_sha", "")),
        index_id=ctx.index_job.index_id if ctx.index_job else "",
        descriptor=ctx.descriptor,
    )
    fuzzer = CoverageGuidedFuzzer(
        executor=executor,
        code_graph=ctx.code_graph,
        workspace=ctx.pinned.work,
        provider=ctx.provider,
    )

    records: list[dict[str, Any]] = []
    accumulated = unmeasured("No harness has executed yet.")
    reproduced = 0

    rounds = {"quick": 2, "standard": 4, "deep": 8}.get(ctx.analysis_profile, 4)
    executions_budget = {"quick": 12, "standard": 30, "deep": 80}.get(ctx.analysis_profile, 30)

    for plan in executable:
        record = await executor.execute(plan)
        ctx.test_executions.append(record)
        await _persist_execution(ctx, record)
        records.append(record.as_dict())
        await _emit_tools(ctx, record.tool_events)
        if record.reproduced:
            reproduced += 1

        coverage_payload = record.coverage or {}
        if coverage_payload.get("measured"):
            accumulated = accumulated.merge(
                CoverageObservation(
                    covered_lines=set(coverage_payload.get("covered_lines_sample") or []),
                    covered_scopes=set(coverage_payload.get("covered_scopes") or []),
                    total_statements=int(coverage_payload.get("total_statements", 0) or 0),
                    covered_statements=int(coverage_payload.get("covered_statements", 0) or 0),
                    source=str(coverage_payload.get("source", "kx_observe")),
                    measured=True,
                )
            )

        await ctx.emitter.test_result(
            plan_id=plan.plan_id,
            candidate=plan.candidate_ref,
            strategy=plan.spec.strategy,
            engine=plan.engine,
            reproduced=record.reproduced,
            reproduction_count=record.reproduction_count,
            required=record.reproductions_required,
            oracle=plan.spec.oracle.kind,
            evidence=record.proving_evidence or record.verdict_detail,
            coverage_percent=float(coverage_payload.get("percent", 0.0) or 0.0),
            error=record.error,
        )

        # A fuzz/mutation plan whose oracle did not fire gets a coverage-guided campaign: the
        # single-shot payload is the seed, not the whole attempt.
        if (
            not record.reproduced
            and plan.spec.strategy in ("fuzz", "mutation")
            and not record.error
        ):
            campaign = await fuzzer.run(
                plan,
                max_rounds=rounds,
                max_executions=executions_budget,
                focus_symbols=list(plan.provenance.get("call_path") or []) or None,
            )
            await _emit_tools(ctx, campaign.tool_events)
            await ctx.emitter.coverage(
                candidate=plan.candidate_ref,
                percent=float((campaign.coverage or {}).get("percent", 0.0) or 0.0),
                corpus_size=len(campaign.corpus),
                executions=campaign.executions,
                rounds=campaign.rounds_run,
                new_findings=len(campaign.crashes),
                uncovered_branches=len(campaign.uncovered_branches),
                model_candidates=campaign.model_candidates,
                model_candidates_useful=campaign.model_candidates_useful,
                stopped_because=campaign.stopped_because,
            )
            await ctx.emitter.thought(
                agent="COVERAGE-GUIDED FUZZING",
                hypothesis="A guided campaign reaches inputs a single payload does not.",
                evidence=[
                    f"{campaign.executions} execution(s) over {campaign.rounds_run} round(s)",
                    f"corpus {len(campaign.corpus)} (each entry reached something new)",
                    f"model proposed {campaign.model_candidates}, "
                    f"{campaign.model_candidates_useful} of which reached new coverage",
                    f"{len(campaign.uncovered_branches)} branch(es) still uncovered",
                ],
                decision=(
                    f"{len(campaign.crashes)} signal(s) found — {campaign.stopped_because}"
                ),
                confidence=1.0,
            )
            await _persist_execution(ctx, record, campaign=campaign)
            if campaign.crashes:
                reproduced += 1
            records.append({"campaign": campaign.as_dict(), "plan_id": plan.plan_id})

    ctx.coverage = accumulated
    state["test_executions"] = records
    state["phase"] = phase
    await _emit_metrics(ctx)

    # The tool surface gains the measured coverage and runtime observations, so any later model
    # call sees real evidence instead of an "unavailable" placeholder.
    if ctx.toolset is not None:
        ctx.toolset.coverage = accumulated.as_dict()

    if reproduced:
        await ctx.emitter.phase_done(
            phase,
            f"{reproduced}/{len(executable)} harness(es) reproduced their security property "
            f"· coverage {accumulated.percent:.1f}%",
        )
        await _mark_phase(ctx, phase, "completed")
    else:
        await ctx.emitter.phase_blocked(
            phase,
            f"{len(executable)} harness(es) executed and none reproduced its property. That is a "
            "refutation of those candidates, not a clean bill of health for the target.",
        )
        await _mark_phase(ctx, phase, "completed")
    return state


# ---------------------------------------------------------------------------
# REGRESSION
# ---------------------------------------------------------------------------
async def node_regression(ctx: RunContext, state: KavachState) -> KavachState:
    """Preserve each validated finding's reproduction as a durable regression test."""
    from app.orchestration.nodes import _mark_phase, _set_phase, _store_artifact
    from app.testing import harness as harness_mod
    from app.testing import regression as regression_mod

    phase = Phase.REGRESSION.value
    await _set_phase(ctx, phase)

    if not ctx.findings:
        await ctx.emitter.phase_start(phase, "no validated finding to preserve")
        await ctx.emitter.phase_done(phase, "skipped — nothing validated")
        await _mark_phase(ctx, phase, "completed")
        return state

    await ctx.emitter.phase_start(phase, "generating regression tests from the reproductions")

    suite = regression_mod.RegressionSuite()
    framework = _preferred_test_framework(ctx)

    for handle, work in sorted(ctx.findings.items()):
        if work.outcome is None:
            continue
        target = (
            work.root_cause.location.split(":")[0]
            if work.root_cause and work.root_cause.location
            else str(getattr(work.outcome, "crash_site", "") or "").split(":")[0]
        )
        plan = regression_mod.plan_from_finding(
            outcome=work.outcome,
            finding_handle=handle,
            target=target or "src",
            entrypoint=getattr(ctx.descriptor, "entry_callable", "") or "",
            index_id=ctx.index_job.index_id if ctx.index_job else "",
        )
        if plan is None:
            suite.notes.append(
                f"{handle}: no regression test could be built from the reproduction record "
                "(the reproducing input is not expressible as a spec payload)."
            )
            continue

        plan.language = getattr(ctx.descriptor, "language", "python") or "python"
        plan.engine = "python-stdlib"
        generated = harness_mod.generate(
            plan, workspace=ctx.pinned.work, descriptor=ctx.descriptor
        )
        harness_mod.attach(plan, generated)

        artifact = regression_mod.artifact_for_target(
            plan=plan,
            framework=framework,
            descriptor=ctx.descriptor,
            finding_handle=handle,
            location=str(getattr(work.outcome, "crash_site", "") or ""),
        )
        suite.add(plan, artifact)

        if artifact is not None:
            await _store_artifact(
                ctx,
                kind="regression_test",
                name=artifact.path.rsplit("/", 1)[-1],
                content=artifact.content,
                media_type="text/x-python",
                meta={
                    "finding": handle,
                    "framework": artifact.framework,
                    "intended_path": artifact.path,
                    "sha256": artifact.sha256,
                },
            )

    if ctx.pinned is not None:
        suite.write(ctx.pinned.work)
    ctx.regression_suite = suite
    state["regression"] = suite.as_dict()

    await ctx.emitter.thought(
        agent="REGRESSION",
        hypothesis="The input that proved a finding is the most valuable test the run produces.",
        evidence=[
            f"{len(suite.plans)} regression plan(s) built from reproduction records",
            f"{len(suite.artifacts)} publishable test file(s) in the target's own convention "
            f"({framework})",
            *suite.notes[:2],
        ],
        decision=(
            "Each reproduction is preserved as a test the gauntlet re-runs against every patch "
            "iteration, and as a file a maintainer can check."
        ),
        confidence=1.0,
    )
    await ctx.emitter.phase_done(
        phase,
        f"{len(suite.plans)} regression test(s) · {len(suite.artifacts)} publishable artifact(s)",
    )
    await _mark_phase(ctx, phase, "completed")
    state["phase"] = phase
    return state


def _preferred_test_framework(ctx: RunContext) -> str:
    """The framework the target's own tests already use, so a published test fits in."""
    from app.indexing.model import NodeKind

    if ctx.code_graph is None:
        return "pytest"
    counts: dict[str, int] = {}
    for node in ctx.code_graph.nodes_of(NodeKind.TEST.value):
        framework = str(node.attrs.get("framework", ""))
        if framework:
            counts[framework] = counts.get(framework, 0) + 1
    if not counts:
        return "pytest"
    return max(counts.items(), key=lambda kv: kv[1])[0]


def _now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# persistence
#
# Each stage writes one row. They are written here rather than inside the subsystems so the
# subsystems stay usable outside a run (the tests drive them directly with no database at all).
# ---------------------------------------------------------------------------
async def _persist_index(ctx: RunContext, result: Any) -> None:
    from datetime import datetime, timezone

    from app.db.session import session_scope
    from app.models.indexing import RepositoryIndex

    job = result.job
    graph_document = result.graph.as_dict()
    async with session_scope() as db:
        db.add(
            RepositoryIndex(
                tenant_id=ctx.tenant_id,
                run_id=ctx.run_id,
                index_id=job.index_id,
                commit_sha=job.commit_sha,
                source_sha256=job.source_sha256,
                graph_hash=job.graph_hash,
                graph_source=job.graph_source,
                status=job.status,
                versions=job.versions,
                options=job.options,
                providers=job.providers,
                files_discovered=job.files_discovered,
                files_indexed=job.files_indexed,
                files_skipped=job.files_skipped,
                symbols=job.symbols_discovered,
                functions=job.functions,
                classes=job.classes,
                relationships=job.relationships_discovered,
                call_relationships=job.call_relationships,
                import_relationships=job.import_relationships,
                resolved_relationships=job.resolved_relationships,
                entrypoints=job.entrypoints_discovered,
                tests_discovered=job.tests_discovered,
                configs_discovered=job.configs_discovered,
                dependencies_discovered=job.dependencies_discovered,
                languages=job.languages,
                skipped_files=job.skipped_files,
                warnings=job.warnings,
                errors=job.errors,
                health_grade=result.health.grade,
                health=result.health.as_dict(),
                claim_bounds=result.health.claim_bounds,
                graph_json=graph_document,
                graph_truncated=bool(graph_document.get("truncated", False)),
                incremental=job.incremental,
                changed_files=job.changed_files,
                affected_symbols=job.affected_symbols,
                duration_ms=job.duration_ms,
                completed_at=datetime.now(timezone.utc),
            )
        )


async def _persist_security_model(ctx: RunContext, security: Any) -> None:
    from app.db.session import session_scope
    from app.models.indexing import SecurityModelRow

    stats = security.stats()
    async with session_scope() as db:
        db.add(
            SecurityModelRow(
                tenant_id=ctx.tenant_id,
                run_id=ctx.run_id,
                index_id=ctx.index_job.index_id if ctx.index_job else "",
                content_hash=security.content_hash(),
                sources=stats["sources"],
                sinks=stats["sinks"],
                sanitizers=stats["sanitizers"],
                validators=stats["validators"],
                controls=stats["controls"],
                flows=stats["flows"],
                reachable_flows=stats["reachable_flows"],
                sanitized_flows=stats["sanitized_flows"],
                trust_boundaries=stats["trust_boundaries"],
                taxonomy=security.taxonomy_summary,
                model_json=security.as_dict(),
                parse_errors=security.parse_errors[:50],
                warnings=security.warnings[:50],
            )
        )


async def _persist_architecture(ctx: RunContext, model: Any, surface: Any) -> None:
    from app.db.session import session_scope
    from app.models.indexing import ArchitectureModelRow

    async with session_scope() as db:
        db.add(
            ArchitectureModelRow(
                tenant_id=ctx.tenant_id,
                run_id=ctx.run_id,
                content_hash=model.content_hash(),
                application_type=model.application_type,
                languages=model.languages,
                frameworks=model.frameworks,
                entrypoint_count=len(model.entrypoints),
                unauthenticated_entrypoints=len(surface.unauthenticated_entrypoints),
                surface_measured=surface.measured,
                surface_items=len(surface.items),
                externally_controllable=len(surface.externally_controllable),
                testable_items=len(surface.testable),
                model_json=model.as_dict(),
                attack_surface_json=surface.as_dict(),
                gaps=model.gaps,
            )
        )


async def _persist_plans(ctx: RunContext, plans: list[Any], proposed_by: str) -> None:
    from app.db.session import session_scope
    from app.models.indexing import GeneratedTest

    async with session_scope() as db:
        for plan in plans:
            db.add(
                GeneratedTest(
                    tenant_id=ctx.tenant_id,
                    run_id=ctx.run_id,
                    plan_id=plan.plan_id,
                    candidate_ref=plan.candidate_ref[:400],
                    finding_handle=plan.finding_handle,
                    status=plan.status,
                    strategy=plan.spec.strategy,
                    oracle_kind=plan.spec.oracle.kind,
                    engine=plan.engine,
                    engine_available=plan.engine_available,
                    engine_reason=plan.engine_reason,
                    language=plan.language,
                    proposed_by=proposed_by,
                    harness_path=plan.harness_path,
                    harness_sha256=plan.harness_sha256,
                    command=plan.command,
                    security_property=plan.spec.expected_security_property,
                    spec_json=plan.spec.as_dict(),
                    provenance=plan.provenance,
                    notes=plan.notes,
                )
            )


async def _persist_execution(ctx: RunContext, record: Any, campaign: Any = None) -> None:
    from app.db.session import session_scope
    from app.models.indexing import TestExecutionRow

    async with session_scope() as db:
        db.add(
            TestExecutionRow(
                tenant_id=ctx.tenant_id,
                run_id=ctx.run_id,
                plan_id=record.plan_id,
                candidate_ref=record.candidate_ref[:400],
                finding_handle=record.finding_handle,
                strategy=record.strategy,
                engine=record.engine,
                harness_path=record.harness_path,
                harness_sha256=record.harness_sha256,
                command=record.command,
                commit_sha=record.commit_sha,
                index_id=record.index_id,
                input_hash=record.input_hash(),
                environment=record.environment,
                reproduced=record.reproduced,
                reproduction_count=record.reproduction_count,
                reproductions_required=record.reproductions_required,
                verdict_detail=record.verdict_detail,
                proving_evidence=record.proving_evidence,
                attempts=[a.as_dict() for a in record.attempts],
                coverage=record.coverage,
                campaign=campaign.as_dict() if campaign is not None else {},
                error=record.error,
                duration_ms=record.duration_ms,
            )
        )


async def _persist_context(ctx: RunContext, candidate_ref: str, context: dict[str, Any]) -> None:
    from app.db.session import session_scope
    from app.models.indexing import ModelContextRow

    async with session_scope() as db:
        db.add(
            ModelContextRow(
                tenant_id=ctx.tenant_id,
                run_id=ctx.run_id,
                candidate_ref=candidate_ref[:400],
                task=str(context.get("task", ""))[:60],
                context_hash=str(context.get("context_hash", "")),
                context_version=str(context.get("version", ""))[:60],
                provider=str(context.get("provider", ""))[:40],
                model=str(context.get("model", ""))[:120],
                size_chars=int(context.get("size_chars", 0) or 0),
                selected_files=context.get("selected_files", []),
                selected_functions=context.get("selected_functions", []),
                code_slice_keys=context.get("code_slice_keys", []),
                tool_calls=(context.get("tool_calls") or [])[:200],
                budget=context.get("budget", {}),
                used=context.get("used", {}),
                dropped=context.get("dropped", []),
            )
        )
