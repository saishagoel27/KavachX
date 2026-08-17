"""Typed per-run emitter used by the orchestrator and every worker.

Every method here corresponds to a real state transition somewhere in the pipeline. There is
deliberately no ``emit_progress(percent)`` helper: progress is derived from phases that
actually completed.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

from app.events.bus import RunEventBus, bus
from app.events.schemas import (
    ArtifactEvent,
    CertificateEvent,
    ClauseEvent,
    DiffEvent,
    FindingEvent,
    GauntletEvent,
    LogEvent,
    MetricEvent,
    PhaseEvent,
    ShieldEvent,
    StatusEvent,
    ThoughtEvent,
    ToolEvent,
)


class RunEmitter:
    def __init__(
        self,
        run_id: uuid.UUID,
        tenant_id: uuid.UUID,
        event_bus: RunEventBus | None = None,
    ) -> None:
        self.run_id = run_id
        self.tenant_id = tenant_id
        self.bus = event_bus or bus
        self._t0 = time.monotonic()

    @property
    def elapsed_ms(self) -> int:
        return int((time.monotonic() - self._t0) * 1000)

    async def _emit(self, event: Any) -> int:
        return await self.bus.publish(run_id=self.run_id, tenant_id=self.tenant_id, event=event)

    # --- phases -----------------------------------------------------------
    async def phase(self, phase: str, status: str, detail: str = "") -> None:
        await self._emit(PhaseEvent(phase=phase, status=status, detail=detail))

    async def phase_start(self, phase: str, detail: str = "") -> None:
        await self.phase(phase, "start", detail)

    async def phase_done(self, phase: str, detail: str = "") -> None:
        await self.phase(phase, "done", detail)

    async def phase_failed(self, phase: str, detail: str = "") -> None:
        await self.phase(phase, "failed", detail)

    async def phase_blocked(self, phase: str, detail: str = "") -> None:
        await self.phase(phase, "blocked", detail)

    # --- reasoning --------------------------------------------------------
    async def thought(
        self,
        *,
        agent: str,
        hypothesis: str,
        decision: str,
        confidence: float,
        evidence: list[str] | None = None,
    ) -> None:
        await self._emit(
            ThoughtEvent(
                agent=agent,
                hypothesis=hypothesis,
                decision=decision,
                confidence=max(0.0, min(1.0, confidence)),
                evidence=evidence or [],
            )
        )

    # --- tools ------------------------------------------------------------
    async def tool(self, *, name: str, target: str, ms: int, ok: bool, detail: str = "") -> None:
        await self._emit(ToolEvent(name=name, target=target, ms=ms, ok=ok, detail=detail))

    # --- domain objects ---------------------------------------------------
    async def finding(
        self,
        *,
        handle: str,
        state: str,
        severity: str,
        reachable: bool,
        clause: str | None = None,
        title: str = "",
    ) -> None:
        await self._emit(
            FindingEvent(
                id=handle,
                state=state,
                severity=severity,
                reachable=reachable,
                clause=clause or None,
                title=title,
            )
        )

    async def clause(
        self, *, clause_id: str, status: str, description: str, scope: str = "", kind: str = ""
    ) -> None:
        await self._emit(
            ClauseEvent(
                clause_id=clause_id,
                status=status,
                description=description,
                scope=scope,
                kind=kind,
            )
        )

    async def diff(
        self, *, finding: str, file: str, patch: str, iteration: int, patch_id: str = ""
    ) -> None:
        await self._emit(
            DiffEvent(finding=finding, file=file, patch=patch, iter=iteration, patch_id=patch_id)
        )

    async def gauntlet(
        self, *, finding: str, stage: str, verdict: str, detail: str, iteration: int = 1
    ) -> None:
        await self._emit(
            GauntletEvent(
                finding=finding, stage=stage, verdict=verdict, detail=detail, iter=iteration
            )
        )

    async def shield(
        self,
        *,
        finding: str,
        shield_id: str,
        mechanism: str,
        verified_blocked: bool,
        verified_benign: bool,
        deployed: bool,
        rule: str = "",
    ) -> None:
        await self._emit(
            ShieldEvent(
                finding=finding,
                shield_id=shield_id,
                mechanism=mechanism,
                verified_blocked=verified_blocked,
                verified_benign=verified_benign,
                deployed=deployed,
                rule=rule,
            )
        )

    async def certificate(
        self, *, finding: str, level: str, certificate_hash: str, certificate_id: str
    ) -> None:
        await self._emit(
            CertificateEvent(
                finding=finding,
                level=level,
                certificate_hash=certificate_hash,
                certificate_id=certificate_id,
            )
        )

    async def artifact(self, *, kind: str, url: str, name: str = "", digest: str = "") -> None:
        await self._emit(ArtifactEvent(kind=kind, url=url, name=name, hash=digest))

    # --- meters / status --------------------------------------------------
    async def metric(
        self,
        *,
        tokens: int,
        coverage: float,
        ram_mb: int,
        egress: int = 0,
        model_calls: int = 0,
        sandbox_executions: int = 0,
        cpu_seconds: float = 0.0,
    ) -> None:
        await self._emit(
            MetricEvent(
                tokens=tokens,
                coverage=round(coverage, 2),
                ram_mb=ram_mb,
                egress=egress,
                model_calls=model_calls,
                sandbox_executions=sandbox_executions,
                cpu_seconds=round(cpu_seconds, 3),
                elapsed_ms=self.elapsed_ms,
            )
        )

    async def status(self, status: str, detail: str = "") -> None:
        await self._emit(StatusEvent(status=status, detail=detail))

    async def log(self, line: str, *, stream: str = "system", source: str = "") -> None:
        await self._emit(LogEvent(stream=stream, line=line[:4000], source=source))

    def close(self) -> None:
        self.bus.mark_closed(self.run_id)
