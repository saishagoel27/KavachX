"""SSE event stream: persistence, replay, authentication and resumption."""

from __future__ import annotations

import asyncio
import json
import uuid

import httpx
import pytest

from app.db.session import session_scope
from app.events.bus import RunEventBus
from app.events.emitter import RunEmitter
from app.models.run import Run, RunEvent
from tests.conftest import auth


async def _make_run(tenant: dict[str, str], short_code: str = "SSE1") -> uuid.UUID:
    async with session_scope() as db:
        run = Run(
            tenant_id=uuid.UUID(tenant["organisation_id"]),
            project_id=uuid.UUID(tenant["project_id"]),
            repository_id=uuid.UUID(tenant["repository_id"]),
            short_code=short_code,
            status="RUNNING",
        )
        db.add(run)
        await db.flush()
        return run.id


# ---------------------------------------------------------------------------
async def test_events_are_persisted_with_monotonic_sequence(tenant_a):
    run_id = await _make_run(tenant_a, "SEQ1")
    tenant_id = uuid.UUID(tenant_a["organisation_id"])
    bus = RunEventBus()
    emitter = RunEmitter(run_id, tenant_id, bus)

    await emitter.phase_start("ingest", "starting")
    await emitter.thought(
        agent="TEST", hypothesis="h", decision="d", confidence=0.5, evidence=["e"]
    )
    await emitter.phase_done("ingest", "done")

    async with session_scope() as db:
        from sqlalchemy import select

        rows = list(
            (
                await db.scalars(
                    select(RunEvent).where(RunEvent.run_id == run_id).order_by(RunEvent.seq)
                )
            ).all()
        )
    assert [row.seq for row in rows] == [1, 2, 3]
    assert [row.t for row in rows] == ["phase", "thought", "phase"]
    assert rows[1].payload["agent"] == "TEST"


async def test_replay_returns_only_the_tail(tenant_a):
    run_id = await _make_run(tenant_a, "SEQ2")
    tenant_id = uuid.UUID(tenant_a["organisation_id"])
    bus = RunEventBus()
    emitter = RunEmitter(run_id, tenant_id, bus)

    for index in range(5):
        await emitter.log(f"line {index}")

    everything = await bus.replay(run_id=run_id)
    assert len(everything) == 5

    tail = await bus.replay(run_id=run_id, after_seq=3)
    assert [item["seq"] for item in tail] == [4, 5]


async def test_subscriber_receives_live_events(tenant_a):
    run_id = await _make_run(tenant_a, "SEQ3")
    tenant_id = uuid.UUID(tenant_a["organisation_id"])
    bus = RunEventBus()
    emitter = RunEmitter(run_id, tenant_id, bus)

    queue = bus.subscribe(run_id)
    await emitter.status("RUNNING", "live")
    envelope = await asyncio.wait_for(queue.get(), timeout=5)
    assert envelope["event"]["t"] == "status"
    assert envelope["event"]["status"] == "RUNNING"
    bus.unsubscribe(run_id, queue)
    assert bus.subscriber_count(run_id) == 0


async def test_thought_events_carry_no_raw_model_text(tenant_a):
    """Only application-composed summaries are emitted — never hidden deliberation."""
    from app.events.schemas import ThoughtEvent

    fields = set(ThoughtEvent.model_fields)
    assert fields == {"t", "agent", "hypothesis", "evidence", "decision", "confidence"}
    for banned in ("raw", "tokens", "completion", "chain_of_thought", "reasoning"):
        assert banned not in fields


async def test_event_schema_rejects_unknown_fields():
    from pydantic import ValidationError

    from app.events.schemas import PhaseEvent

    with pytest.raises(ValidationError):
        PhaseEvent(phase="ingest", status="start", smuggled="value")  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# HTTP surface
# ---------------------------------------------------------------------------
async def test_event_history_endpoint(client: httpx.AsyncClient, tenant_a):
    run_id = await _make_run(tenant_a, "HTTP1")
    bus = RunEventBus()
    emitter = RunEmitter(run_id, uuid.UUID(tenant_a["organisation_id"]), bus)
    await emitter.phase_start("ingest")
    await emitter.phase_done("ingest")

    response = await client.get(
        f"/api/runs/{run_id}/events/history", headers=auth(tenant_a["token"])
    )
    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 2
    assert body["events"][0]["event"]["t"] == "phase"


@pytest.mark.security
async def test_event_stream_requires_authentication(client: httpx.AsyncClient, tenant_a):
    run_id = await _make_run(tenant_a, "AUTH1")
    response = await client.get(f"/api/runs/{run_id}/events")
    assert response.status_code == 401


@pytest.mark.security
async def test_event_stream_rejects_another_tenant(client: httpx.AsyncClient, tenant_a, tenant_b):
    run_id = await _make_run(tenant_b, "XTEN1")
    response = await client.get(f"/api/runs/{run_id}/events", params={"token": tenant_a["token"]})
    assert response.status_code == 404


async def test_event_stream_accepts_a_query_token_and_replays(client: httpx.AsyncClient, tenant_a):
    """EventSource cannot set headers, so a query token is supported — validated identically."""
    run_id = await _make_run(tenant_a, "QRY1")
    bus = RunEventBus()
    emitter = RunEmitter(run_id, uuid.UUID(tenant_a["organisation_id"]), bus)
    await emitter.phase_start("ingest", "one")
    await emitter.phase_done("ingest", "two")

    # A terminal run closes the stream after replay, so the response completes.
    async with session_scope() as db:
        run = await db.get(Run, run_id)
        run.status = "COMPLETED"

    async with client.stream(
        "GET",
        f"/api/runs/{run_id}/events",
        params={"token": tenant_a["token"]},
        timeout=httpx.Timeout(30.0),
    ) as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        payloads: list[dict] = []
        events: list[str] = []
        async for line in response.aiter_lines():
            if line.startswith("event: "):
                events.append(line[7:].strip())
            elif line.startswith("data: "):
                payloads.append(json.loads(line[6:]))
            if events and events[-1] == "end":
                break

    assert events[0] == "hello"
    assert "end" in events
    phases = [p for p in payloads if p.get("event", {}).get("t") == "phase"]
    assert len(phases) == 2
    assert [p["seq"] for p in phases] == [1, 2]


async def test_stream_resumes_from_last_event_id(client: httpx.AsyncClient, tenant_a):
    run_id = await _make_run(tenant_a, "RESUME")
    bus = RunEventBus()
    emitter = RunEmitter(run_id, uuid.UUID(tenant_a["organisation_id"]), bus)
    for index in range(4):
        await emitter.log(f"line {index}")

    async with session_scope() as db:
        run = await db.get(Run, run_id)
        run.status = "COMPLETED"

    async with client.stream(
        "GET",
        f"/api/runs/{run_id}/events",
        params={"token": tenant_a["token"], "lastEventId": 2},
        timeout=httpx.Timeout(30.0),
    ) as response:
        seqs: list[int] = []
        current = ""
        async for line in response.aiter_lines():
            if line.startswith("event: "):
                current = line[7:].strip()
            elif line.startswith("data: "):
                payload = json.loads(line[6:])
                if current == "message":
                    seqs.append(payload["seq"])
            if current == "end":
                break

    # Only the tail after sequence 2 — no gap, no duplicate.
    assert seqs == [3, 4]


async def test_metric_events_report_zero_egress(tenant_a):
    run_id = await _make_run(tenant_a, "MET1")
    bus = RunEventBus()
    emitter = RunEmitter(run_id, uuid.UUID(tenant_a["organisation_id"]), bus)
    await emitter.metric(tokens=100, coverage=42.5, ram_mb=64, egress=0, model_calls=2)

    replay = await bus.replay(run_id=run_id)
    metric = replay[-1]["event"]
    assert metric["egress"] == 0
    assert metric["coverage"] == 42.5
    assert metric["tokens"] == 100
