"""Canonical hashing and signing.

Everything that ends up in a certificate is hashed through :func:`canonical_json` first, so
two structurally identical evidence payloads always produce the same digest regardless of
dict ordering.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any


def canonical_json(value: Any) -> str:
    """Deterministic JSON: sorted keys, no insignificant whitespace, UTF-8 preserved."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_fallback,
    )


def _fallback(obj: Any) -> Any:
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    if isinstance(obj, (set, frozenset)):
        return sorted(obj, key=str)
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    return str(obj)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_text(canonical_json(value))


def sha256_file(path: Path, chunk_size: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_tree(root: Path, *, ignore_dirs: frozenset[str] | None = None) -> str:
    """Content hash of a directory tree.

    This is what "pinned immutable source artifact" means in practice: the sandbox is handed
    a tree whose digest was computed *outside* the sandbox, and any later mutation is
    detectable by recomputing it.
    """
    skip = ignore_dirs or frozenset(
        {".git", "__pycache__", ".venv", "node_modules", ".pytest_cache", ".kavachx"}
    )
    entries: list[tuple[str, str]] = []
    for path in sorted(root.rglob("*")):
        if any(part in skip for part in path.relative_to(root).parts):
            continue
        if path.is_file():
            rel = path.relative_to(root).as_posix()
            entries.append((rel, sha256_file(path)))
    return sha256_json(entries)


def hmac_sign(payload: str, key: str) -> str:
    return hmac.new(key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def hmac_verify(payload: str, key: str, signature: str) -> bool:
    return hmac.compare_digest(hmac_sign(payload, key), signature)


def short_hash(value: str, length: int = 12) -> str:
    return value[:length]
