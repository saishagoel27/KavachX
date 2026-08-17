"""LangGraph wiring.

The graph is deliberately **thin**: linear phases with one guarded loop (patch ↔ gauntlet, which
lives inside :func:`app.orchestration.nodes.node_patch_and_gauntlet` because its iteration
ceiling and constraint accumulation belong together). LangGraph owns transitions and state; the
nodes own work.

Every node is wrapped so that:

* state is checkpointed to PostgreSQL **after** it returns,
* an abort request short-circuits the rest of the graph,
* an unexpected exception is recorded in state and ends the run cleanly rather than leaving a
  half-finished run row behind.

If ``langgraph`` is unavailable the same node sequence runs through an equivalent local executor,
so the pipeline never becomes untestable because of an optional dependency.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from app.core.logging import get_logger
from app.orchestration import nodes
from app.orchestration.state import KavachState, RunContext

logger = get_logger(__name__)

NodeFn = Callable[[RunContext, KavachState], Awaitable[KavachState]]

#: Node order. Names match the spec's node list; several spec nodes are folded into one
#: implementation where splitting them would only add a state round-trip:
#:   index_repo  = probe + index + world_model
#:   discovery_fanout = discovery + hypothesis_queue
#:   validate    = validate + correlate
#:   patch_synthesis = prioritize + patch + blast_radius + gauntlet iteration loop
NODE_SEQUENCE: list[tuple[str, NodeFn]] = [
    ("ingest", nodes.node_ingest),
    ("index_repo", nodes.node_index_repo),
    ("contract_synthesis", nodes.node_contract_synthesis),
    ("discovery_fanout", nodes.node_discovery_fanout),
    ("validate", nodes.node_validate),
    ("shield", nodes.node_shield),
    ("root_cause", nodes.node_root_cause),
    ("patch_synthesis", nodes.node_patch_and_gauntlet),
    ("attest", nodes.node_attest),
    ("publish_gate", nodes.node_publish_gate),
]


def _wrap(
    name: str, fn: NodeFn, ctx: RunContext
) -> Callable[[KavachState], Awaitable[KavachState]]:
    async def wrapped(state: KavachState) -> KavachState:
        if state.get("aborted"):
            return state
        if await nodes._check_abort(ctx):
            state["aborted"] = True
            state["status"] = "ABORTED"
            await ctx.emitter.status("ABORTED", f"abort requested before node {name}")
            return state

        logger.info("graph.node_start", node=name)
        try:
            result = await fn(ctx, state)
        except Exception as exc:
            logger.exception("graph.node_failed", node=name)
            state["errors"] = [
                *state.get("errors", []),
                {
                    "node": name,
                    "error": f"{type(exc).__name__}: {exc}",
                    "at": nodes.now_iso(),
                },
            ]
            state["aborted"] = True
            state["status"] = "FAILED"
            await ctx.emitter.phase_failed(state.get("phase", name), f"{type(exc).__name__}: {exc}")
            await ctx.emitter.log(
                f"node {name} failed: {type(exc).__name__}: {exc}",
                stream="stderr",
                source="orchestrator",
            )
            result = state

        # Checkpoint after every node, always — including after a failure, so the failed state
        # is inspectable.
        await nodes.checkpoint(ctx, name, result)
        logger.info("graph.node_done", node=name, phase=result.get("phase", ""))
        return result

    return wrapped


def build_graph(ctx: RunContext) -> Any:
    """Compile the LangGraph state machine for this run."""
    try:
        from langgraph.graph import END, StateGraph
    except ImportError:  # pragma: no cover
        logger.warning("graph.langgraph_unavailable")
        return None

    builder = StateGraph(KavachState)
    wrapped = [(name, _wrap(name, fn, ctx)) for name, fn in NODE_SEQUENCE]

    for name, fn in wrapped:
        builder.add_node(name, fn)

    builder.set_entry_point(wrapped[0][0])
    for (name, _), (next_name, _) in zip(wrapped, wrapped[1:], strict=False):
        builder.add_conditional_edges(
            name,
            _continue_or_end(next_name),
            {next_name: next_name, END: END},
        )
    builder.add_edge(wrapped[-1][0], END)

    return builder.compile()


def _continue_or_end(next_name: str) -> Callable[[KavachState], str]:
    from langgraph.graph import END

    def router(state: KavachState) -> str:
        # An aborted or failed run must not fall through into later phases; ending here leaves
        # the last good checkpoint as the run's final state.
        return END if state.get("aborted") else next_name

    return router


async def run_graph(ctx: RunContext, state: KavachState) -> KavachState:
    """Execute the graph, falling back to a local executor with identical semantics."""
    compiled = build_graph(ctx)
    if compiled is not None:
        result = await compiled.ainvoke(
            state,
            config={
                "recursion_limit": len(NODE_SEQUENCE) + 8,
                "configurable": {"thread_id": str(ctx.run_id)},
            },
        )
        return dict(result)  # type: ignore[return-value]

    current = state
    for name, fn in NODE_SEQUENCE:
        current = await _wrap(name, fn, ctx)(current)
        if current.get("aborted"):
            break
    return current
