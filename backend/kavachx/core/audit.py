"""
Hash-chained audit ledger.

Every entry commits to its predecessor: evidence_hash = sha256(prev_hash || entry).
Tampering with any entry breaks every hash after it, which is what the
dashboard's audit modal renders (CURR / PREV per row).

In-memory for now — `kavachx.db.models.AuditEvent` is the persistent home once
the DB session is wired in.
"""

import hashlib
import json
import threading
import time
from typing import Optional

GENESIS_HASH = "0" * 64


class AuditLedger:
    """Append-only, hash-chained event log."""

    def __init__(self) -> None:
        self._entries: list[dict] = []
        self._lock = threading.Lock()

    def append(
        self,
        actor: str,
        action: str,
        subject: str,
        tenant_id: str,
        run_id: Optional[str] = None,
        details: Optional[dict] = None,
    ) -> dict:
        with self._lock:
            prev_hash = self._entries[-1]["evidence_hash"] if self._entries else GENESIS_HASH
            entry = {
                "log_id": len(self._entries) + 1,
                "timestamp": time.time(),
                "actor": actor,
                "action": action,
                "subject": subject,
                "tenant_id": tenant_id,
                "run_id": run_id,
                "details": details or {},
                "prev_hash": prev_hash,
            }
            payload = json.dumps(
                {k: v for k, v in entry.items() if k != "prev_hash"},
                sort_keys=True,
                default=str,
            )
            entry["evidence_hash"] = hashlib.sha256(
                f"{prev_hash}{payload}".encode()
            ).hexdigest()
            self._entries.append(entry)
            return entry

    def list(
        self,
        tenant_id: Optional[str] = None,
        run_id: Optional[str] = None,
        limit: int = 200,
    ) -> list[dict]:
        with self._lock:
            entries = list(self._entries)
        if tenant_id:
            entries = [e for e in entries if e["tenant_id"] == tenant_id]
        if run_id:
            entries = [e for e in entries if e["run_id"] == run_id]
        return entries[-limit:]

    def anchor(self) -> str:
        """Current head of the chain — the anchor a certificate commits to."""
        with self._lock:
            return self._entries[-1]["evidence_hash"] if self._entries else GENESIS_HASH

    def verify(self) -> bool:
        """Recompute the chain. False means an entry was mutated."""
        with self._lock:
            entries = list(self._entries)
        prev_hash = GENESIS_HASH
        for entry in entries:
            if entry["prev_hash"] != prev_hash:
                return False
            payload = json.dumps(
                {k: v for k, v in entry.items() if k not in ("prev_hash", "evidence_hash")},
                sort_keys=True,
                default=str,
            )
            expected = hashlib.sha256(f"{prev_hash}{payload}".encode()).hexdigest()
            if expected != entry["evidence_hash"]:
                return False
            prev_hash = entry["evidence_hash"]
        return True


# Process-wide ledger. Swap for a DB-backed implementation without touching
# callers — the API only depends on append()/list()/anchor().
ledger = AuditLedger()

__all__ = ["AuditLedger", "ledger", "GENESIS_HASH"]
