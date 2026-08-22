"""Hash-chained audit log writer.

The chain is per tenant: each record's ``previous_hash`` is the ``hash`` of the previous
record for that tenant, and ``hash`` covers the record's own semantic fields plus that link.
Verification therefore detects deletion, reordering and in-place edits.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.hashing import canonical_json, sha256_json, sha256_text
from app.core.logging import get_logger, request_id_var
from app.models.audit import AuditEvent

logger = get_logger(__name__)

GENESIS_HASH = "0" * 64


def compute_record_hash(
    *,
    tenant_id: str,
    seq: int,
    actor_label: str,
    action: str,
    subject_type: str,
    subject_id: str,
    timestamp: str,
    evidence_hash: str,
    previous_hash: str,
) -> str:
    return sha256_json(
        {
            "tenant_id": tenant_id,
            "seq": seq,
            "actor": actor_label,
            "action": action,
            "subject_type": subject_type,
            "subject_id": subject_id,
            "timestamp": timestamp,
            "evidence_hash": evidence_hash,
            "previous_hash": previous_hash,
        }
    )


class AuditService:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def record(
        self,
        *,
        tenant_id: uuid.UUID,
        action: str,
        actor_user_id: uuid.UUID | None = None,
        actor_label: str = "system",
        subject_type: str = "",
        subject_id: str = "",
        detail: dict[str, Any] | None = None,
        source_ip: str = "",
        note: str = "",
    ) -> AuditEvent:
        detail = detail or {}

        last = await self.db.scalar(
            select(AuditEvent)
            .where(AuditEvent.tenant_id == tenant_id)
            .order_by(AuditEvent.seq.desc())
            .limit(1)
        )
        seq = (last.seq + 1) if last else 1
        previous_hash = last.hash if last else GENESIS_HASH
        hashed_at = datetime.now(timezone.utc).isoformat()
        evidence_hash = sha256_json(detail) if detail else sha256_text("")

        event = AuditEvent(
            tenant_id=tenant_id,
            seq=seq,
            actor_user_id=actor_user_id,
            actor_label=actor_label,
            action=action,
            subject_type=subject_type,
            subject_id=str(subject_id),
            request_id=request_id_var.get(),
            source_ip=source_ip,
            detail=detail,
            hashed_at=hashed_at,
            evidence_hash=evidence_hash,
            previous_hash=previous_hash,
            note=note,
            hash=compute_record_hash(
                tenant_id=str(tenant_id),
                seq=seq,
                actor_label=actor_label,
                action=action,
                subject_type=subject_type,
                subject_id=str(subject_id),
                timestamp=hashed_at,
                evidence_hash=evidence_hash,
                previous_hash=previous_hash,
            ),
        )
        self.db.add(event)
        await self.db.flush()

        logger.info(
            "audit.record", action=action, subject_type=subject_type, subject_id=str(subject_id)
        )
        return event

    async def list_events(
        self,
        *,
        tenant_id: uuid.UUID,
        limit: int = 100,
        offset: int = 0,
        action: str | None = None,
    ) -> tuple[list[AuditEvent], int]:
        stmt = select(AuditEvent).where(AuditEvent.tenant_id == tenant_id)
        count_stmt = (
            select(func.count()).select_from(AuditEvent).where(AuditEvent.tenant_id == tenant_id)
        )
        if action:
            stmt = stmt.where(AuditEvent.action == action)
            count_stmt = count_stmt.where(AuditEvent.action == action)
        stmt = stmt.order_by(AuditEvent.seq.desc()).limit(limit).offset(offset)
        rows = list((await self.db.scalars(stmt)).all())
        total = int(await self.db.scalar(count_stmt) or 0)
        return rows, total

    async def verify_chain(self, *, tenant_id: uuid.UUID) -> dict[str, Any]:
        """Recompute the whole chain. Returns the first break, if any."""
        events = list(
            (
                await self.db.scalars(
                    select(AuditEvent)
                    .where(AuditEvent.tenant_id == tenant_id)
                    .order_by(AuditEvent.seq.asc())
                )
            ).all()
        )
        previous = GENESIS_HASH
        for index, event in enumerate(events):
            expected_seq = index + 1
            if event.seq != expected_seq:
                return {
                    "valid": False,
                    "checked": index,
                    "total": len(events),
                    "broken_at_seq": event.seq,
                    "reason": f"sequence gap: expected {expected_seq}, found {event.seq}",
                }
            if event.previous_hash != previous:
                return {
                    "valid": False,
                    "checked": index,
                    "total": len(events),
                    "broken_at_seq": event.seq,
                    "reason": "previous_hash does not match the preceding record",
                }
            recomputed = compute_record_hash(
                tenant_id=str(event.tenant_id),
                seq=event.seq,
                actor_label=event.actor_label,
                action=event.action,
                subject_type=event.subject_type,
                subject_id=event.subject_id,
                timestamp=event.hashed_at,
                evidence_hash=event.evidence_hash,
                previous_hash=event.previous_hash,
            )
            if recomputed != event.hash:
                return {
                    "valid": False,
                    "checked": index,
                    "total": len(events),
                    "broken_at_seq": event.seq,
                    "reason": "record hash does not match its contents",
                }
            previous = event.hash
        return {
            "valid": True,
            "checked": len(events),
            "total": len(events),
            "head_hash": previous,
            "broken_at_seq": None,
            "reason": "",
        }

    async def head_hash(self, *, tenant_id: uuid.UUID) -> str:
        last = await self.db.scalar(
            select(AuditEvent)
            .where(AuditEvent.tenant_id == tenant_id)
            .order_by(AuditEvent.seq.desc())
            .limit(1)
        )
        return last.hash if last else GENESIS_HASH


def audit_detail_digest(detail: dict[str, Any]) -> str:
    return sha256_text(canonical_json(detail))
