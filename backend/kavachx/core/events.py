"""
RunEvent definitions and the in-process event bus behind the SSE stream.

Event shapes follow docs/API.md and are what the React dashboard consumes.
Raw model tokens are never published here — only structured events.
"""

import asyncio
import logging
from typing import Any, AsyncIterator, Optional

logger = logging.getLogger(__name__)

# Phase keys, in order. These are the exact keys the frontend timeline renders
# (frontend/src/App.tsx :: PIPELINE_STEPS) — keep both lists in sync.
UI_PHASES = [
    "ingest",
    "probe",
    "interface",
    "samhita_synthesis",
    "clause_falsification",
    "static_queries",
    "discovery",
    "validation",
    "patch_synthesis",
    "gauntlet",
    "attest",
    "publish",
]

PHASE_COMPLETE = "complete"


# ── Event constructors ────────────────────────────────────────────────────────

def phase_event(phase: str, status: str = "start") -> dict:
    return {"t": "phase", "phase": phase, "status": status}


def thought_event(
    agent: str,
    hypothesis: str,
    evidence: Optional[list[str]] = None,
    decision: str = "",
    confidence: float = 1.0,
) -> dict:
    return {
        "t": "thought",
        "agent": agent,
        "hypothesis": hypothesis,
        "evidence": evidence or [],
        "decision": decision,
        "confidence": confidence,
    }


def tool_event(name: str, target: str, ms: int, ok: bool = True) -> dict:
    return {"t": "tool", "name": name, "target": target, "ms": ms, "ok": ok}


def finding_event(
    finding_id: str,
    state: str,
    severity: str,
    reachable: bool,
    title: str = "",
    clause: Optional[str] = None,
) -> dict:
    return {
        "t": "finding",
        "id": finding_id,
        "state": state,
        "severity": severity,
        "reachable": reachable,
        "title": title,
        "clause": clause,
    }


def diff_event(finding_id: str, file: str, patch: str, iteration: int) -> dict:
    return {
        "t": "diff",
        "finding": finding_id,
        "file": file,
        "patch": patch,
        "iter": iteration,
    }


def gauntlet_event(finding_id: str, stage: str, verdict: str, detail: str = "") -> dict:
    return {
        "t": "gauntlet",
        "finding": finding_id,
        "stage": stage,
        "verdict": verdict,
        "detail": detail,
    }


def metric_event(tokens: int, coverage: float, ram_mb: int) -> dict:
    """`coverage` is a percentage (0-100). `egress` is always 0. Always."""
    return {
        "t": "metric",
        "tokens": tokens,
        "coverage": round(coverage, 1),
        "ram_mb": ram_mb,
        "egress": 0,
    }


def artifact_event(kind: str, url: str) -> dict:
    return {"t": "artifact", "kind": kind, "url": url}


def error_event(message: str, phase: str = "") -> dict:
    return {"t": "error", "message": message, "phase": phase}


# ── Event bus ─────────────────────────────────────────────────────────────────

class RunEventStream:
    """
    Fan-out bus for one run.

    Keeps full history so a client that connects late (or reconnects) receives
    the complete trace before live events resume.
    """

    def __init__(self) -> None:
        self._history: list[dict] = []
        self._subscribers: set[asyncio.Queue] = set()
        self._closed = False

    @property
    def history(self) -> list[dict]:
        return list(self._history)

    @property
    def closed(self) -> bool:
        return self._closed

    def publish(self, event: dict) -> None:
        if self._closed:
            logger.debug("[Events] Dropping event on closed stream: %s", event.get("t"))
            return
        self._history.append(event)
        for queue in list(self._subscribers):
            queue.put_nowait(event)

    def close(self) -> None:
        self._closed = True
        for queue in list(self._subscribers):
            queue.put_nowait(None)  # sentinel — ends every subscriber generator

    async def subscribe(self, keepalive: float = 15.0) -> AsyncIterator[Optional[dict]]:
        """
        Yield the replayed history, then live events.

        Yields ``None`` when `keepalive` seconds pass with no traffic so the
        caller can emit an SSE comment and keep proxies from closing the
        connection. The generator ends once the run closes the stream.
        """
        queue: asyncio.Queue = asyncio.Queue()
        self._subscribers.add(queue)
        try:
            for event in self._history:
                yield event

            if self._closed:
                return

            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=keepalive)
                except asyncio.TimeoutError:
                    yield None  # keepalive tick
                    continue
                if event is None:  # stream closed
                    return
                yield event
        finally:
            self._subscribers.discard(queue)


__all__: list[str] = [
    "UI_PHASES",
    "PHASE_COMPLETE",
    "RunEventStream",
    "phase_event",
    "thought_event",
    "tool_event",
    "finding_event",
    "diff_event",
    "gauntlet_event",
    "metric_event",
    "artifact_event",
    "error_event",
]
