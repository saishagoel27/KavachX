"""Development sandbox adapter.

**This is not an isolation boundary.** It runs the target as a child process of the backend,
on the host filesystem, under the host user. It is here so the pipeline can be developed and
demonstrated on a Windows laptop without KVM.

What it *does* genuinely enforce:

* a scrubbed, allowlisted environment — no credentials reach the child, verified on every
  execution by :func:`~app.sandbox.base.assert_no_secrets`;
* a wall-clock timeout, with the process tree killed on expiry;
* the workspace as the working directory, and the pinned tree hashed before and after;
* in-process network denial for Python targets via the injected guard, so
  ``egress_bytes == 0`` is measured rather than asserted;
* POSIX resource limits (address space, CPU seconds, process count, file size) via
  ``resource.setrlimit`` in a preexec hook where the platform supports it.

What it does **not** enforce: kernel-level filesystem isolation, seccomp, capability dropping,
a read-only root, or network denial for non-Python targets. Those need
:mod:`app.sandbox.gvisor` or :mod:`app.sandbox.firecracker`. Every surface that reports sandbox
state — the run console, ``/api/system/sandbox``, and the PRAMAAN certificate — carries
``network_enforced: false`` and ``suitable_for_untrusted_code: false`` for this adapter.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import time
from pathlib import Path

from app.core.logging import get_logger
from app.sandbox.base import (
    ExecRequest,
    ExecResult,
    SandboxAdapter,
    SandboxCapabilities,
    SandboxLimits,
    build_sandbox_env,
    extract_signals,
)
from app.sandbox.spawn import run_process

logger = get_logger(__name__)

HARNESS_DIR_NAME = "_kavachx"
GUARD_REPORT_NAME = "guard-report.json"
IS_WINDOWS = os.name == "nt"


class DevSandboxAdapter(SandboxAdapter):
    name = "dev"

    def __init__(self, *, workspace: Path, limits: SandboxLimits) -> None:
        super().__init__(workspace=workspace, limits=limits)
        self.harness_dir = self.workspace / HARNESS_DIR_NAME
        self.output_dir = self.workspace / HARNESS_DIR_NAME / "out"
        self._started = False

    # ------------------------------------------------------------------
    async def start(self) -> None:
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.harness_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._install_harness()
        self._started = True
        logger.info(
            "sandbox.start",
            adapter=self.name,
            session=self.session_id,
            workspace=str(self.workspace),
        )

    def _install_harness(self) -> None:
        source = Path(__file__).parent / "harness"
        for item in source.glob("*.py"):
            shutil.copy2(item, self.harness_dir / item.name)

    # ------------------------------------------------------------------
    async def execute(self, request: ExecRequest) -> ExecResult:
        if not self._started:
            await self.start()

        cwd = (self.workspace / request.cwd).resolve()
        if not str(cwd).startswith(str(self.workspace.resolve())):
            raise ValueError("execution cwd escaped the workspace")
        cwd.mkdir(parents=True, exist_ok=True)

        guard_report = self.output_dir / f"{GUARD_REPORT_NAME}.{self.execution_count}"
        pythonpath = os.pathsep.join(
            [str(self.harness_dir), *[str(self.workspace / p) for p in ("src", ".")]]
        )
        env = build_sandbox_env(
            {
                "PYTHONPATH": pythonpath,
                "KAVACHX_GUARD_REPORT": str(guard_report),
                "KAVACHX_WORKSPACE_ROOT": str(self.workspace.resolve()),
                "KAVACHX_SANDBOX": "1",
                "KAVACHX_SESSION": self.session_id,
                **request.env,
            }
        )

        timeout = request.timeout_seconds or self.limits.wall_clock_seconds
        started = time.perf_counter()
        cpu_before = _child_cpu_seconds()

        try:
            # Spawned via the threaded helper rather than asyncio's subprocess API: the latter is
            # unavailable on a Windows Selector loop, which is exactly what uvicorn --reload gives
            # us. See app/sandbox/spawn.py.
            completed = await run_process(
                request.argv,
                cwd=str(cwd),
                env=env,
                stdin=request.stdin.encode("utf-8") if request.stdin is not None else None,
                timeout=timeout,
                preexec_fn=_posix_limits(self.limits) if not IS_WINDOWS else None,
                on_timeout=_kill_tree,
            )
        except FileNotFoundError as exc:
            return self._record(
                ExecResult(
                    exit_code=127,
                    stdout="",
                    stderr=f"executable not found: {exc}",
                    duration_ms=0,
                    label=request.label,
                    network_enforced=False,
                )
            )

        timed_out = completed.timed_out
        duration_ms = int((time.perf_counter() - started) * 1000)
        cap = request.max_output_bytes
        stdout = completed.stdout[:cap].decode("utf-8", errors="replace")
        stderr = completed.stderr[:cap].decode("utf-8", errors="replace")

        guard = _read_guard_report(guard_report)
        result = ExecResult(
            exit_code=-1 if timed_out else completed.returncode,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration_ms,
            timed_out=timed_out,
            peak_ram_mb=_peak_child_ram_mb(),
            cpu_seconds=max(0.0, _child_cpu_seconds() - cpu_before),
            egress_bytes=int(guard.get("egress_bytes", 0)),
            network_attempts=int(guard.get("network_attempts", 0)),
            network_enforced=bool(guard.get("network_enforced_in_process", False)),
            signals=extract_signals(stdout, stderr),
            artifacts=self._collect(request.collect_artifacts),
            label=request.label,
        )
        if timed_out:
            result.signals.append("timeout")
        result.artifacts["_guard"] = json.dumps(guard, sort_keys=True)
        return self._record(result)

    def _collect(self, paths: list[str]) -> dict[str, str]:
        out: dict[str, str] = {}
        root = self.workspace.resolve()
        for rel in paths:
            candidate = (self.workspace / rel).resolve()
            if not str(candidate).startswith(str(root)):
                continue
            if candidate.is_file():
                try:
                    out[rel] = candidate.read_text(encoding="utf-8", errors="replace")[:2_000_000]
                except OSError:
                    continue
        return out

    async def stop(self) -> None:
        self._started = False
        logger.info(
            "sandbox.stop",
            adapter=self.name,
            session=self.session_id,
            executions=self.execution_count,
        )

    def capabilities(self) -> SandboxCapabilities:
        return SandboxCapabilities(
            adapter=self.name,
            isolation_model="host subprocess (development only)",
            # Python targets do get in-process denial via the injected guard; the OS is not
            # enforcing anything, so this stays false at the adapter level.
            network_enforced=False,
            filesystem_isolated=False,
            non_root=os.geteuid() != 0 if hasattr(os, "geteuid") else True,
            seccomp=False,
            dropped_capabilities=False,
            read_only_root=False,
            resource_limits_enforced=not IS_WINDOWS,
            suitable_for_untrusted_code=False,
            notes=(
                "DEVELOPMENT ADAPTER. A host subprocess is not an isolation boundary. "
                "Credentials are withheld by an environment allowlist and Python targets run "
                "under an in-process network-denial guard, but there is no kernel-level "
                "confinement. Use the gVisor or Firecracker adapter for anything you do not "
                "already trust."
            ),
        )


# ---------------------------------------------------------------------------
def _posix_limits(limits: SandboxLimits):  # pragma: no cover - POSIX only
    def apply() -> None:
        try:
            import resource

            memory_bytes = limits.memory_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
            cpu = max(1, int(limits.wall_clock_seconds))
            resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
            resource.setrlimit(resource.RLIMIT_NPROC, (limits.pid_limit, limits.pid_limit))
            file_bytes = limits.disk_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_FSIZE, (file_bytes, file_bytes))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            os.setsid()
        except Exception:
            pass

    return apply


def _kill_tree(process) -> None:  # type: ignore[no-untyped-def]
    try:
        if IS_WINDOWS:
            import subprocess

            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                capture_output=True,
                check=False,
                timeout=10,
            )
        else:
            import signal

            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    except Exception:
        try:
            process.kill()
        except Exception:
            pass


def _child_cpu_seconds() -> float:
    try:
        import resource

        usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        return float(usage.ru_utime + usage.ru_stime)
    except Exception:
        return 0.0


def _peak_child_ram_mb() -> int:
    try:
        import resource

        usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        # ru_maxrss is KiB on Linux and bytes on macOS.
        raw = int(usage.ru_maxrss)
        return raw // 1024 if sys.platform != "darwin" else raw // (1024 * 1024)
    except Exception:
        return 0


def _read_guard_report(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
