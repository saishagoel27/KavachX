"""Loop-agnostic process spawning.

``asyncio.create_subprocess_exec`` is not available on every event loop. On Windows it requires a
``ProactorEventLoop``; on a ``SelectorEventLoop`` it raises a bare ``NotImplementedError()`` with no
message, which is remarkably hard to diagnose from a log.

That is not a hypothetical. uvicorn 0.52's loop factory reads:

    if sys.platform == "win32" and not use_subprocess:
        return asyncio.ProactorEventLoop
    return asyncio.SelectorEventLoop

``use_subprocess`` is true whenever ``--reload`` or ``--workers`` is passed — and ``scripts/dev.ps1``
starts the backend with ``--reload``. So the documented way to run KavachX on its primary developer
platform produced a Selector loop, and every sandbox execution failed at the first spawn: SAMHITA
observation, validation, the shield check and the whole gauntlet. The run reported
``NotImplementedError:`` with an empty message and no traceback.

Rather than depend on the host's choice of event loop, spawning happens on a worker thread with the
synchronous ``subprocess`` module. That works identically on Proactor, Selector and uvloop, and it
preserves the semantics the callers rely on: a hard wall-clock timeout, a process-tree kill on
expiry, and captured stdout/stderr.
"""

from __future__ import annotations

import asyncio
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class CompletedProcess:
    """What a spawn produced. ``pid`` is kept for the audit trail."""

    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    pid: int


def _blocking_run(
    argv: list[str],
    *,
    cwd: str | None,
    env: dict[str, str] | None,
    stdin: bytes | None,
    timeout: float,
    preexec_fn: Callable[[], None] | None,
    on_timeout: Callable[[Any], None] | None,
) -> CompletedProcess:
    # Popen and communicate stay on one thread: the object is not shared with the event loop, so
    # there is nothing to synchronise.
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.PIPE if stdin is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=preexec_fn,
    )

    timed_out = False
    try:
        stdout, stderr = process.communicate(stdin, timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        if on_timeout is not None:
            on_timeout(process)
        else:  # pragma: no cover - every caller supplies a tree-killer
            process.kill()
        try:
            # The tree is already dead; this only drains the pipes so the handles close.
            stdout, stderr = process.communicate(timeout=5)
        except Exception:
            stdout, stderr = b"", b""

    return CompletedProcess(
        returncode=process.returncode if process.returncode is not None else 0,
        stdout=stdout or b"",
        stderr=stderr or b"",
        timed_out=timed_out,
        pid=process.pid,
    )


async def run_process(
    argv: list[str],
    *,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
    stdin: bytes | None = None,
    timeout: float,
    preexec_fn: Callable[[], None] | None = None,
    on_timeout: Callable[[Any], None] | None = None,
) -> CompletedProcess:
    """Run ``argv`` to completion on any event loop.

    Raises ``FileNotFoundError`` if the executable does not exist, matching what
    ``create_subprocess_exec`` did, so existing handling is unaffected.

    One worker thread is held for the process's lifetime. Sandbox executions are already bounded by
    the pipeline's own concurrency and each one is heavyweight, so a thread apiece is not the
    constraint here — being able to spawn at all is.
    """
    return await asyncio.to_thread(
        _blocking_run,
        argv,
        cwd=str(cwd) if cwd is not None else None,
        env=env,
        stdin=stdin,
        timeout=timeout,
        preexec_fn=preexec_fn,
        on_timeout=on_timeout,
    )
