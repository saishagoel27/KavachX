"""Language-agnostic black-box observation.

The in-process tracing harness (``kx_observe``/``sitecustomize``) is Python-specific: it can only
instrument a Python process. This module is the other half — a **black-box** observer that treats
the target as an opaque request→output program invoked through its own run command (``node cli.js``,
``python tool.py``, ``cargo run``, …), and observes it entirely from the outside:

* **exit code / timeout / sanitizer signals** — did it crash?
* **stdout + stderr** — the output, hashed for differential replay and scanned for planted tokens;
* **filesystem diff** — which files under the workspace were created or modified (a write-side
  effect such as an unexpected file appearing);
* **planted-token detection** — a canary string (for path traversal: unique content in a file the
  target should never read) or an execution marker (for command injection: a token an injected
  command would echo) appearing in the output is deterministic proof of the effect.

It cannot produce the per-function value profiles the Python tracer does — that is the stated cost
of going language-agnostic. What it *can* do is prove an exploit reproduced (crash, or an observed
effect) and drive differential replay, for a CLI in **any** language, all from Python. It runs
through the same :class:`~app.sandbox.base.SandboxAdapter` as everything else, so the isolation,
egress accounting and resource caps are identical to the Python path.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.logging import get_logger
from app.sandbox.base import ExecRequest, SandboxAdapter

logger = get_logger(__name__)

#: Directories not worth snapshotting for the filesystem diff.
_IGNORE_DIRS = frozenset(
    {
        "node_modules", ".git", "target", "dist", "build", ".next", ".venv", "venv",
        "__pycache__", ".cache", "vendor", ".turbo",
    }
)
_SNAPSHOT_MAX_FILES = 8000
_HASH_MAX_BYTES = 2_000_000


@dataclass(slots=True)
class BlackboxObservation:
    case_id: str
    argv: list[str]
    exit_code: int
    timed_out: bool
    crashed: bool
    stdout: str
    stderr: str
    output_hash: str
    duration_ms: int
    egress_bytes: int
    signals: list[str] = field(default_factory=list)
    files_created: list[str] = field(default_factory=list)
    files_modified: list[str] = field(default_factory=list)
    #: Which of the caller's ``watch_tokens`` appeared in stdout/stderr (canary/marker hits).
    tokens_seen: list[str] = field(default_factory=list)
    #: Which of the caller's ``sentinel_paths`` exist after the run (a side-effect write).
    sentinels_created: list[str] = field(default_factory=list)

    @property
    def observed_effect(self) -> bool:
        """True when something happened that a benign request must never cause."""
        return bool(self.tokens_seen or self.sentinels_created or self.crashed)

    def as_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "argv": self.argv,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "crashed": self.crashed,
            "output_hash": self.output_hash,
            "duration_ms": self.duration_ms,
            "egress_bytes": self.egress_bytes,
            "signals": self.signals,
            "files_created": self.files_created,
            "files_modified": self.files_modified,
            "tokens_seen": self.tokens_seen,
            "sentinels_created": self.sentinels_created,
            "observed_effect": self.observed_effect,
        }


def _snapshot(root: Path) -> dict[str, str]:
    """Map every workspace-relative file path to a content digest (size for very large files)."""
    out: dict[str, str] = {}
    if not root.is_dir():
        return out
    count = 0
    for path in root.rglob("*"):
        if count >= _SNAPSHOT_MAX_FILES:
            logger.warning("blackbox.snapshot_capped", files=count)
            break
        if any(part in _IGNORE_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        count += 1
        rel = path.relative_to(root).as_posix()
        try:
            size = path.stat().st_size
            if size > _HASH_MAX_BYTES:
                out[rel] = f"size:{size}"
            else:
                out[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            out[rel] = "unreadable"
    return out


async def observe(
    adapter: SandboxAdapter,
    *,
    argv: Sequence[str],
    case_id: str = "",
    watch_tokens: Sequence[str] = (),
    sentinel_paths: Sequence[str] = (),
    cwd: str = ".",
    stdin: str | None = None,
    timeout_seconds: int | None = None,
    label: str = "",
) -> BlackboxObservation:
    """Run ``argv`` through the sandbox and observe it as an opaque request→output program.

    ``watch_tokens`` are canary/marker strings whose appearance in the output is proof of an
    effect (a leaked file's content, or an injected command's echo). ``sentinel_paths`` are
    workspace-relative files whose creation is proof of a side effect. The workspace is
    snapshotted before and after so genuine file writes are detected regardless of language.
    """
    workspace = adapter.workspace
    before = _snapshot(workspace)

    result = await adapter.execute(
        ExecRequest(
            argv=list(argv),
            cwd=cwd,
            stdin=stdin,
            timeout_seconds=timeout_seconds,
            label=label or f"blackbox:{case_id}",
        )
    )

    after = _snapshot(workspace)
    created = sorted(set(after) - set(before))
    modified = sorted(p for p in (set(after) & set(before)) if after[p] != before[p])

    blob = f"{result.stdout}\n{result.stderr}"
    tokens_seen = [tok for tok in watch_tokens if tok and tok in blob]
    sentinels_created = [p for p in sentinel_paths if (workspace / p).exists()]

    obs = BlackboxObservation(
        case_id=case_id,
        argv=list(argv),
        exit_code=result.exit_code,
        timed_out=result.timed_out,
        crashed=result.crashed,
        stdout=result.stdout,
        stderr=result.stderr,
        output_hash=result.output_hash(),
        duration_ms=result.duration_ms,
        egress_bytes=result.egress_bytes,
        signals=list(result.signals),
        files_created=created,
        files_modified=modified,
        tokens_seen=tokens_seen,
        sentinels_created=sentinels_created,
    )
    logger.info(
        "blackbox.observe",
        case=case_id,
        exit=obs.exit_code,
        crashed=obs.crashed,
        tokens=len(tokens_seen),
        created=len(created),
    )
    return obs
