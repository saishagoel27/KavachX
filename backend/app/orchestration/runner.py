"""Run lifecycle: launch, supervise, tear down.

A run executes as a background asyncio task. The HTTP request that starts it returns as soon as
the run row exists, so ``POST /api/runs`` is fast and the console can attach to the event stream
immediately.

Supervision responsibilities:

* enforce the wall-clock ceiling (``RUN_MAX_RUNTIME_SECONDS``) with a hard timeout;
* always tear the sandbox down and always write a terminal run status, including on cancellation;
* keep a registry of in-flight runs so ``POST /api/runs/{id}/abort`` can request cooperative
  cancellation, and so shutdown can drain.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any

from app.config import settings
from app.core.logging import get_logger, run_id_var, tenant_id_var
from app.db.session import session_scope
from app.events.bus import bus
from app.events.emitter import RunEmitter
from app.llm.base import TokenBudget
from app.llm.registry import build_provider
from app.models.enums import PHASE_ORDER, RunStatus
from app.models.run import Run
from app.orchestration.graph import run_graph
from app.orchestration.state import RunContext, initial_state

logger = get_logger(__name__)

#: run_id -> task. Used by abort and by graceful shutdown.
_active: dict[uuid.UUID, asyncio.Task[Any]] = {}


def active_run_ids() -> list[str]:
    return [str(rid) for rid, task in _active.items() if not task.done()]


def is_active(run_id: uuid.UUID) -> bool:
    task = _active.get(run_id)
    return task is not None and not task.done()


async def start_run(
    *,
    run_id: uuid.UUID,
    tenant_id: uuid.UUID,
    project_id: uuid.UUID,
    repository_id: uuid.UUID,
    short_code: str,
    execution_profile: str,
    analysis_profile: str,
    max_runtime_seconds: int | None = None,
    requested_by: uuid.UUID | None = None,
) -> None:
    """Schedule a run. Returns immediately."""
    if is_active(run_id):
        logger.warning("runner.already_active", run_id=str(run_id))
        return

    task = asyncio.create_task(
        _supervise(
            run_id=run_id,
            tenant_id=tenant_id,
            project_id=project_id,
            repository_id=repository_id,
            short_code=short_code,
            execution_profile=execution_profile,
            analysis_profile=analysis_profile,
            max_runtime_seconds=max_runtime_seconds or settings.run_max_runtime_seconds,
            requested_by=requested_by,
        ),
        name=f"kavachx-run-{short_code}",
    )
    _active[run_id] = task
    task.add_done_callback(lambda _t: _active.pop(run_id, None))


async def _supervise(
    *,
    run_id: uuid.UUID,
    tenant_id: uuid.UUID,
    project_id: uuid.UUID,
    repository_id: uuid.UUID,
    short_code: str,
    execution_profile: str,
    analysis_profile: str,
    max_runtime_seconds: int,
    requested_by: uuid.UUID | None,
) -> None:
    run_id_var.set(str(run_id))
    tenant_id_var.set(str(tenant_id))

    emitter = RunEmitter(run_id, tenant_id)
    budget = TokenBudget(limit=settings.llm_run_token_budget)
    provider = build_provider(budget=budget)

    ctx = RunContext(
        run_id=run_id,
        tenant_id=tenant_id,
        project_id=project_id,
        repository_id=repository_id,
        short_code=short_code,
        emitter=emitter,
        provider=provider,
        budget=budget,
        workspace_root=settings.workspace_root,
        execution_profile=execution_profile,
        analysis_profile=analysis_profile,
        requested_by=requested_by,
    )

    await _mark_started(run_id, provider_name=provider.name)
    await emitter.status(RunStatus.RUNNING.value, f"run {short_code} started")
    if provider.name == "mock" and settings.llm_provider != "mock":
        await emitter.log(
            f"The configured provider ({settings.llm_provider}) was unavailable; this run used "
            "the deterministic mock proposer. Every certificate records which provider produced "
            "its proposals.",
            stream="stderr",
            source="llm",
        )

    state = initial_state(run_id=run_id, tenant_id=tenant_id)
    terminal_status = RunStatus.FAILED.value
    error_code = ""
    error_message = ""

    try:
        state = await asyncio.wait_for(run_graph(ctx, state), timeout=max_runtime_seconds)
        if state.get("status") == RunStatus.AWAITING_APPROVAL.value:
            terminal_status = RunStatus.AWAITING_APPROVAL.value
        elif state.get("aborted") and state.get("status") == "ABORTED":
            terminal_status = RunStatus.ABORTED.value
        elif state.get("errors"):
            terminal_status = RunStatus.FAILED.value
            first = state["errors"][0]
            error_code = "NODE_FAILED"
            error_message = str(first.get("error", ""))[:1000]
        else:
            terminal_status = RunStatus.COMPLETED.value

    except TimeoutError:
        terminal_status = RunStatus.FAILED.value
        error_code = "RUN_TIMEOUT"
        error_message = (
            f"The run exceeded its wall-clock limit of {max_runtime_seconds}s and was stopped."
        )
        await emitter.log(error_message, stream="stderr", source="orchestrator")
    except asyncio.CancelledError:
        terminal_status = RunStatus.ABORTED.value
        error_code = "RUN_ABORTED"
        error_message = "The run was aborted."
        await emitter.log(error_message, stream="stderr", source="orchestrator")
        raise
    except Exception as exc:
        terminal_status = RunStatus.FAILED.value
        error_code = type(exc).__name__
        error_message = str(exc)[:1000]
        logger.exception("runner.failed", run_id=str(run_id))
        await emitter.log(
            f"run failed: {error_code}: {error_message}", stream="stderr", source="orchestrator"
        )
    finally:
        # Teardown must happen on every path, including cancellation.
        if ctx.sandbox is not None:
            try:
                await ctx.sandbox.stop()
            except Exception:
                logger.warning("runner.sandbox_stop_failed", run_id=str(run_id))
        try:
            await provider.aclose()
        except Exception:
            pass

        metrics = ctx.refresh_metrics()
        await _mark_finished(
            run_id,
            status=terminal_status,
            error_code=error_code,
            error_message=error_message,
            metrics=metrics,
        )
        await emitter.metric(
            tokens=metrics["tokens"],
            coverage=metrics["coverage"],
            ram_mb=metrics["peak_ram_mb"],
            egress=metrics["egress_bytes"],
            model_calls=metrics["model_calls"],
            sandbox_executions=metrics["sandbox_executions"],
            cpu_seconds=metrics["cpu_seconds"],
        )
        await emitter.status(terminal_status, error_message or f"run {short_code} finished")
        emitter.close()
        logger.info(
            "runner.finished",
            run_id=str(run_id),
            status=terminal_status,
            tokens=metrics["tokens"],
            sandbox_executions=metrics["sandbox_executions"],
        )


async def _mark_started(run_id: uuid.UUID, *, provider_name: str) -> None:
    async with session_scope() as db:
        run = await db.get(Run, run_id)
        if run is None:
            return
        run.status = RunStatus.RUNNING.value
        run.started_at = datetime.now(UTC)
        run.phase_status = dict.fromkeys(PHASE_ORDER, "pending")
        run.resource_budget = {
            **(run.resource_budget or {}),
            "token_limit": settings.llm_run_token_budget,
            "llm_provider": provider_name,
        }


async def _mark_finished(
    run_id: uuid.UUID,
    *,
    status: str,
    error_code: str,
    error_message: str,
    metrics: dict[str, Any],
) -> None:
    async with session_scope() as db:
        run = await db.get(Run, run_id)
        if run is None:
            return
        run.status = status
        run.finished_at = datetime.now(UTC)
        run.error_code = error_code
        run.error_message = error_message
        run.tokens_used = int(metrics.get("tokens", 0))
        run.model_calls = int(metrics.get("model_calls", 0))
        run.sandbox_executions = int(metrics.get("sandbox_executions", 0))
        run.coverage_percent = float(metrics.get("coverage", 0.0))
        run.peak_ram_mb = int(metrics.get("peak_ram_mb", 0))
        run.cpu_seconds = float(metrics.get("cpu_seconds", 0.0))
        run.egress_bytes = int(metrics.get("egress_bytes", 0))
        statuses = dict(run.phase_status or {})
        if status in (RunStatus.FAILED.value, RunStatus.ABORTED.value):
            for phase, phase_status in statuses.items():
                if phase_status in ("pending", "running"):
                    statuses[phase] = "failed" if phase_status == "running" else "pending"
            run.phase_status = statuses


async def request_abort(run_id: uuid.UUID) -> bool:
    """Cooperative abort: set the flag, then cancel if the task does not notice in time."""
    async with session_scope() as db:
        run = await db.get(Run, run_id)
        if run is None:
            return False
        run.abort_requested = True

    task = _active.get(run_id)
    if task is None or task.done():
        return True

    # Give the graph a chance to stop between nodes before cancelling mid-node.
    for _ in range(20):
        await asyncio.sleep(0.25)
        if task.done():
            return True
    task.cancel()
    return True


async def drain(timeout: float = 15.0) -> None:
    """Wait for in-flight runs at shutdown, then cancel whatever is left."""
    tasks = [t for t in _active.values() if not t.done()]
    if not tasks:
        return
    logger.info("runner.draining", runs=len(tasks))
    _done, pending = await asyncio.wait(tasks, timeout=timeout)
    for task in pending:
        task.cancel()
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)


def bus_instance() -> Any:
    return bus
