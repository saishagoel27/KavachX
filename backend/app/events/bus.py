"""Run event bus: persist first, then fan out.

Ordering guarantee: a per-run asyncio lock assigns ``seq`` and writes the row before any
subscriber sees it. A client that reconnects with ``Last-Event-ID: <seq>`` therefore replays
from PostgreSQL and then joins the live stream with no gap and no duplicate.
"""

from __future__ import annotations

import asyncio
import uuid
from collections import defaultdict
from datetime import UTC
from typing import Any

from sqlalchemy import func, select

from app.core.logging import get_logger
from app.db.session import session_scope
from app.events.schemas import EnvelopedEvent, RunEventPayload
from app.models.run import RunEvent

logger = get_logger(__name__)

#: Bounded so a stalled browser tab can never grow the backend heap without limit.
SUBSCRIBER_QUEUE_SIZE = 512


class RunEventBus:
    def __init__(self) -> None:
        self._subscribers: dict[uuid.UUID, set[asyncio.Queue[dict[str, Any]]]] = defaultdict(set)
        self._seq: dict[uuid.UUID, int] = {}
        self._locks: dict[uuid.UUID, asyncio.Lock] = {}
        self._closed: set[uuid.UUID] = set()

    # -- internals ---------------------------------------------------------
    def _lock(self, run_id: uuid.UUID) -> asyncio.Lock:
        lock = self._locks.get(run_id)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[run_id] = lock
        return lock

    async def _next_seq(self, run_id: uuid.UUID) -> int:
        if run_id not in self._seq:
            async with session_scope() as db:
                current = await db.scalar(
                    select(func.max(RunEvent.seq)).where(RunEvent.run_id == run_id)
                )
            self._seq[run_id] = int(current or 0)
        self._seq[run_id] += 1
        return self._seq[run_id]

    # -- publishing --------------------------------------------------------
    async def publish(
        self,
        *,
        run_id: uuid.UUID,
        tenant_id: uuid.UUID,
        event: RunEventPayload | dict[str, Any],
    ) -> int:
        payload = event if isinstance(event, dict) else event.model_dump(mode="json")
        kind = str(payload.get("t", "log"))

        async with self._lock(run_id):
            seq = await self._next_seq(run_id)
            async with session_scope() as db:
                db.add(
                    RunEvent(
                        tenant_id=tenant_id,
                        run_id=run_id,
                        seq=seq,
                        t=kind,
                        payload=payload,
                    )
                )
            envelope = {
                "seq": seq,
                "run_id": str(run_id),
                "ts": _now_iso(),
                "event": payload,
            }
            for queue in list(self._subscribers.get(run_id, ())):
                try:
                    queue.put_nowait(envelope)
                except asyncio.QueueFull:
                    # A slow consumer is dropped from the live fan-out; it can still recover
                    # everything by reconnecting with Last-Event-ID.
                    logger.warning("events.subscriber_dropped", run_id=str(run_id), seq=seq)
                    self._subscribers[run_id].discard(queue)
        return seq

    # -- subscription ------------------------------------------------------
    def subscribe(self, run_id: uuid.UUID) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=SUBSCRIBER_QUEUE_SIZE)
        self._subscribers[run_id].add(queue)
        return queue

    def unsubscribe(self, run_id: uuid.UUID, queue: asyncio.Queue[dict[str, Any]]) -> None:
        self._subscribers.get(run_id, set()).discard(queue)
        if not self._subscribers.get(run_id):
            self._subscribers.pop(run_id, None)

    def subscriber_count(self, run_id: uuid.UUID) -> int:
        return len(self._subscribers.get(run_id, ()))

    # -- replay ------------------------------------------------------------
    async def replay(self, *, run_id: uuid.UUID, after_seq: int = 0) -> list[dict[str, Any]]:
        async with session_scope() as db:
            rows = list(
                (
                    await db.scalars(
                        select(RunEvent)
                        .where(RunEvent.run_id == run_id, RunEvent.seq > after_seq)
                        .order_by(RunEvent.seq.asc())
                    )
                ).all()
            )
        return [
            EnvelopedEvent(
                seq=row.seq,
                run_id=str(row.run_id),
                ts=row.created_at.isoformat(),
                event=row.payload,
            ).model_dump()
            for row in rows
        ]

    # -- lifecycle ---------------------------------------------------------
    def mark_closed(self, run_id: uuid.UUID) -> None:
        """Signal every live subscriber that the run reached a terminal state."""
        self._closed.add(run_id)
        for queue in list(self._subscribers.get(run_id, ())):
            with _suppress_full():
                queue.put_nowait({"__terminal__": True, "run_id": str(run_id)})

    def is_closed(self, run_id: uuid.UUID) -> bool:
        return run_id in self._closed

    def forget(self, run_id: uuid.UUID) -> None:
        self._subscribers.pop(run_id, None)
        self._seq.pop(run_id, None)
        self._locks.pop(run_id, None)
        self._closed.discard(run_id)


class _suppress_full:
    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type: type[BaseException] | None, *_: object) -> bool:
        return exc_type is asyncio.QueueFull


def _now_iso() -> str:
    from datetime import datetime

    return datetime.now(UTC).isoformat()


#: Process-wide singleton. One FastAPI worker owns one bus; DB persistence is the
#: cross-process source of truth, which is why replay is always DB-backed.
bus = RunEventBus()
