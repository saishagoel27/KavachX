"""Persistent hypothesis queue.

Priority is ``reachability × confidence × blast_radius``, computed once and stored, so the
ordering a run used is reproducible after the fact.

Two properties matter more than the ordering:

* **Nothing silently disappears.** Every state change is appended to the hypothesis's
  ``transitions`` list with a reason. A hypothesis that could not be validated ends as
  ``UNKNOWN`` with the reason recorded, and that is what REMAINING.md is built from.
* **Correlation, not duplication.** When several channels report the same location, they are
  merged into one hypothesis that lists every contributing channel and takes the strongest
  evidence. Confidence rises for independent corroboration, but is capped — agreement between
  two static heuristics is not proof, and the validator still has to reproduce it.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.discovery.base import HypothesisCandidate
from app.models.analysis import Hypothesis
from app.models.enums import SEVERITY_RANK, HypothesisStatus

logger = get_logger(__name__)

#: Corroboration bonus per additional independent channel, and the ceiling it may reach.
CORROBORATION_BONUS = 0.06
CORROBORATION_CAP = 0.95


@dataclass(slots=True)
class QueueStats:
    pushed: int = 0
    merged: int = 0
    queued: int = 0
    unknown: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "pushed": self.pushed,
            "merged": self.merged,
            "queued": self.queued,
            "unknown": self.unknown,
        }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def correlation_key(candidate: HypothesisCandidate) -> tuple[str, str]:
    """Two candidates describe the same weakness if they share a location and a class."""
    location = candidate.location
    # Fuzzing reports the crash site; static reports the sink line. Same function is enough.
    file = location.split(":")[0]
    weakness = candidate.cwe or candidate.rule_id.rsplit(".", 1)[-1]
    return file, weakness


class HypothesisQueue:
    def __init__(self, db: AsyncSession, *, run_id: uuid.UUID, tenant_id: uuid.UUID) -> None:
        self.db = db
        self.run_id = run_id
        self.tenant_id = tenant_id

    # ------------------------------------------------------------------
    async def push_all(self, candidates: list[HypothesisCandidate]) -> QueueStats:
        stats = QueueStats()
        merged_by_key: dict[tuple[str, str], HypothesisCandidate] = {}
        channels_by_key: dict[tuple[str, str], list[str]] = {}

        for candidate in candidates:
            key = correlation_key(candidate)
            channels_by_key.setdefault(key, []).append(candidate.source_channel)
            existing = merged_by_key.get(key)
            if existing is None:
                merged_by_key[key] = candidate
                continue
            stats.merged += 1
            merged_by_key[key] = _merge(existing, candidate)

        for counter, (key, candidate) in enumerate(
            sorted(merged_by_key.items(), key=lambda item: -item[1].priority), start=1
        ):
            channels = sorted(set(channels_by_key.get(key, [])))
            if len(channels) > 1:
                candidate.confidence = min(
                    CORROBORATION_CAP,
                    candidate.confidence + CORROBORATION_BONUS * (len(channels) - 1),
                )

            handle = f"V{counter:02d}"
            status = (
                HypothesisStatus.QUEUED.value
                if candidate.validation_plan
                else HypothesisStatus.UNKNOWN.value
            )
            reason = (
                "queued for deterministic validation"
                if candidate.validation_plan
                else candidate.unknown_reason or "no executable validation plan could be attached"
            )

            row = Hypothesis(
                tenant_id=self.tenant_id,
                run_id=self.run_id,
                handle=handle,
                source_channel=",".join(channels),
                description=candidate.description[:1000],
                location=candidate.location[:400],
                severity=candidate.severity,
                reachability=candidate.reachability,
                confidence=candidate.confidence,
                blast_radius=candidate.blast_radius,
                priority=candidate.priority,
                evidence_refs=candidate.evidence_refs,
                status=status,
                candidate_clause_id=candidate.candidate_clause_id,
                validation_plan=candidate.validation_plan,
                unknown_reason="" if candidate.validation_plan else reason,
                cwe=candidate.cwe,
                transitions=[
                    {
                        "at": _now(),
                        "from": "",
                        "to": status,
                        "reason": reason,
                        "channels": channels,
                        "priority": candidate.priority,
                    }
                ],
            )
            self.db.add(row)
            stats.pushed += 1
            if status == HypothesisStatus.QUEUED.value:
                stats.queued += 1
            else:
                stats.unknown += 1

        await self.db.flush()
        logger.info("queue.pushed", **stats.as_dict())
        return stats

    # ------------------------------------------------------------------
    async def all(self) -> list[Hypothesis]:
        return list(
            (
                await self.db.scalars(
                    select(Hypothesis)
                    .where(Hypothesis.run_id == self.run_id)
                    .order_by(Hypothesis.priority.desc(), Hypothesis.handle.asc())
                )
            ).all()
        )

    async def next_queued(self) -> Hypothesis | None:
        """Highest-priority queued hypothesis, atomically claimed for validation."""
        row = await self.db.scalar(
            select(Hypothesis)
            .where(
                Hypothesis.run_id == self.run_id,
                Hypothesis.status == HypothesisStatus.QUEUED.value,
            )
            .order_by(Hypothesis.priority.desc(), Hypothesis.handle.asc())
            .limit(1)
        )
        if row is None:
            return None
        await self.transition(row, HypothesisStatus.IN_VALIDATION.value, "claimed by the validator")
        return row

    async def transition(
        self,
        hypothesis: Hypothesis,
        status: str,
        reason: str,
        *,
        detail: dict[str, Any] | None = None,
    ) -> Hypothesis:
        previous = hypothesis.status
        hypothesis.status = status
        entry: dict[str, Any] = {
            "at": _now(),
            "from": previous,
            "to": status,
            "reason": reason,
        }
        if detail:
            entry["detail"] = detail
        # Reassign rather than append so SQLAlchemy sees the JSON column as dirty.
        hypothesis.transitions = [*(hypothesis.transitions or []), entry]
        if status == HypothesisStatus.UNKNOWN.value and not hypothesis.unknown_reason:
            hypothesis.unknown_reason = reason
        await self.db.flush()
        logger.info(
            "queue.transition",
            handle=hypothesis.handle,
            **{"from": previous, "to": status},
        )
        return hypothesis

    async def snapshot(self) -> list[dict[str, Any]]:
        rows = await self.all()
        return [
            {
                "handle": row.handle,
                "source_channel": row.source_channel,
                "description": row.description,
                "location": row.location,
                "severity": row.severity,
                "reachability": row.reachability,
                "confidence": row.confidence,
                "blast_radius": row.blast_radius,
                "priority": row.priority,
                "status": row.status,
                "cwe": row.cwe,
                "candidate_clause_id": row.candidate_clause_id,
                "evidence_refs": row.evidence_refs,
                "unknown_reason": row.unknown_reason,
                "transitions": row.transitions,
            }
            for row in rows
        ]

    async def ledger(self) -> list[dict[str, Any]]:
        """The failure / unknown ledger. Everything that did not reach a validated state."""
        rows = await self.all()
        terminal_unknown = {
            HypothesisStatus.UNKNOWN.value,
            HypothesisStatus.REFUTED.value,
            HypothesisStatus.DOWNGRADED.value,
            HypothesisStatus.QUEUED.value,
            HypothesisStatus.IN_VALIDATION.value,
        }
        return [
            {
                "handle": row.handle,
                "description": row.description,
                "location": row.location,
                "severity": row.severity,
                "status": row.status,
                "cwe": row.cwe,
                "channels": row.source_channel,
                "reason": row.unknown_reason or _implicit_reason(row.status),
                "priority": row.priority,
                "evidence_refs": row.evidence_refs,
            }
            for row in rows
            if row.status in terminal_unknown
        ]

    async def counts(self) -> dict[str, int]:
        rows = await self.all()
        out: dict[str, int] = {}
        for row in rows:
            out[row.status] = out.get(row.status, 0) + 1
        return out


def _implicit_reason(status: str) -> str:
    return {
        HypothesisStatus.QUEUED.value: (
            "Still queued when the run ended — the run's time or resource budget was reached "
            "before this hypothesis was validated."
        ),
        HypothesisStatus.IN_VALIDATION.value: (
            "Validation was in progress when the run ended; no verdict was reached."
        ),
        HypothesisStatus.REFUTED.value: (
            "Validation executed and did not reproduce the predicted behaviour."
        ),
        HypothesisStatus.DOWNGRADED.value: (
            "Reproduced with a weaker impact than predicted; recorded at reduced severity."
        ),
    }.get(status, "No verdict recorded.")


def _merge(a: HypothesisCandidate, b: HypothesisCandidate) -> HypothesisCandidate:
    """Combine two candidates for the same weakness, keeping the stronger evidence."""
    winner, other = (a, b)
    if SEVERITY_RANK.get(b.severity, 0) > SEVERITY_RANK.get(a.severity, 0):
        winner, other = (b, a)

    winner.confidence = max(a.confidence, b.confidence)
    winner.reachability = max(a.reachability, b.reachability)
    winner.blast_radius = max(a.blast_radius, b.blast_radius)
    winner.evidence_refs = sorted({*a.evidence_refs, *b.evidence_refs})
    winner.cwe = winner.cwe or other.cwe
    winner.candidate_clause_id = winner.candidate_clause_id or other.candidate_clause_id
    # An executable plan always beats no plan, regardless of which candidate ranked higher.
    if not winner.validation_plan and other.validation_plan:
        winner.validation_plan = other.validation_plan
        winner.unknown_reason = ""
    if winner.validation_plan:
        winner.unknown_reason = ""
    if other.rule_id and other.rule_id not in winner.rule_id:
        winner.rule_id = f"{winner.rule_id}+{other.rule_id}" if winner.rule_id else other.rule_id
    if other.description and other.description not in winner.description:
        winner.description = f"{winner.description} Corroborated: {other.description}"[:1000]
    return winner
