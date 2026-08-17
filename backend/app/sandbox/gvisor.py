"""gVisor sandbox adapter.

Runs each execution as ``docker run --runtime=runsc`` with the full confinement set. gVisor
intercepts syscalls in userspace, so a container escape has to get through the Sentry rather
than straight to the host kernel — which is why this, and not plain Docker, is the
development-to-production step up.

Flags that matter, and why:

``--network none``            no interface at all, so egress is structurally impossible
``--read-only``              root filesystem immutable
``--tmpfs /workspace/.tmp``  the only writable location, size-capped
``--user 65534:65534``       nobody; never root
``--cap-drop ALL``           no capabilities
``--security-opt no-new-privileges``  setuid binaries cannot elevate
``--security-opt seccomp=…``  explicit profile on top of gVisor's own filtering
``--pids-limit / --memory / --cpus``  resource caps enforced by cgroups
``--mount …,readonly``       the pinned source tree is mounted read-only

The workspace is mounted read-only and a writable overlay lives on the tmpfs, so the target
cannot mutate the pinned tree whose hash was computed outside the sandbox.
"""

from __future__ import annotations

import json
import os
import shutil
import time
from pathlib import Path

from app.core.errors import SandboxUnavailable
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
CONTAINER_WORKSPACE = "/workspace"
CONTAINER_TMP = "/workspace/.tmp"


class GvisorSandboxAdapter(SandboxAdapter):
    name = "gvisor"
    runtime = "runsc"

    def __init__(
        self,
        *,
        workspace: Path,
        limits: SandboxLimits,
        image: str = "kavachx/sandbox:dev",
        seccomp_profile: Path | None = None,
    ) -> None:
        super().__init__(workspace=workspace, limits=limits)
        self.image = image
        self.harness_dir = self.workspace / HARNESS_DIR_NAME
        self.output_dir = self.harness_dir / "out"
        self.seccomp_profile = seccomp_profile
        self._docker: str | None = None

    # ------------------------------------------------------------------
    async def start(self) -> None:
        self._docker = shutil.which("docker")
        if not self._docker:
            raise SandboxUnavailable("docker was not found on PATH.")

        probe = await _run([self._docker, "info", "--format", "{{json .Runtimes}}"])
        if probe.returncode != 0:
            raise SandboxUnavailable(f"docker info failed: {probe.stderr[:200]}")
        try:
            runtimes = json.loads(probe.stdout or "{}")
        except ValueError:
            runtimes = {}
        if self.runtime not in runtimes:
            raise SandboxUnavailable(
                f"The {self.runtime} (gVisor) runtime is not registered with Docker. "
                "Install gVisor and add it to /etc/docker/daemon.json, or set "
                "SANDBOX_ADAPTER=dev for local development."
            )

        self.workspace.mkdir(parents=True, exist_ok=True)
        self.harness_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        for item in (Path(__file__).parent / "harness").glob("*.py"):
            shutil.copy2(item, self.harness_dir / item.name)

        logger.info("sandbox.start", adapter=self.name, image=self.image, session=self.session_id)

    # ------------------------------------------------------------------
    def _docker_argv(self, request: ExecRequest, guard_report_rel: str) -> list[str]:
        assert self._docker
        pythonpath = ":".join(
            [
                f"{CONTAINER_WORKSPACE}/{HARNESS_DIR_NAME}",
                f"{CONTAINER_WORKSPACE}/src",
                CONTAINER_WORKSPACE,
            ]
        )
        env = build_sandbox_env(
            {
                "PYTHONPATH": pythonpath,
                "KAVACHX_GUARD_REPORT": f"{CONTAINER_WORKSPACE}/{guard_report_rel}",
                "KAVACHX_WORKSPACE_ROOT": CONTAINER_WORKSPACE,
                "KAVACHX_SANDBOX": "1",
                "KAVACHX_SESSION": self.session_id,
                "HOME": CONTAINER_TMP,
                "TMPDIR": CONTAINER_TMP,
                **request.env,
            }
        )
        # PATH inside the image, not the host's.
        env["PATH"] = "/usr/local/bin:/usr/bin:/bin"

        argv = [
            self._docker,
            "run",
            "--rm",
            f"--runtime={self.runtime}",
            "--network",
            "none",
            "--read-only",
            "--user",
            "65534:65534",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            f"--pids-limit={self.limits.pid_limit}",
            f"--memory={self.limits.memory_mb}m",
            f"--memory-swap={self.limits.memory_mb}m",
            f"--cpus={self.limits.cpu_limit}",
            "--tmpfs",
            f"{CONTAINER_TMP}:rw,noexec,nosuid,size={self.limits.disk_mb}m",
            "--workdir",
            f"{CONTAINER_WORKSPACE}/{request.cwd}".rstrip("/."),
        ]
        if self.seccomp_profile and self.seccomp_profile.is_file():
            argv += ["--security-opt", f"seccomp={self.seccomp_profile}"]

        # The pinned tree is read-only; only the harness output directory is writable, and it
        # lives on the tmpfs via a bind of its own.
        argv += [
            "--mount",
            f"type=bind,source={self.workspace.resolve()},target={CONTAINER_WORKSPACE},readonly",
            "--mount",
            f"type=bind,source={self.output_dir.resolve()},"
            f"target={CONTAINER_WORKSPACE}/{HARNESS_DIR_NAME}/out",
        ]
        for key, value in env.items():
            argv += ["--env", f"{key}={value}"]
        argv.append(self.image)
        argv += request.argv
        return argv

    async def execute(self, request: ExecRequest) -> ExecResult:
        guard_rel = f"{HARNESS_DIR_NAME}/out/guard-report.{self.execution_count}.json"
        argv = self._docker_argv(request, guard_rel)
        timeout = request.timeout_seconds or self.limits.wall_clock_seconds

        started = time.perf_counter()
        completed = await _run(argv, stdin=request.stdin, timeout=timeout)
        duration_ms = int((time.perf_counter() - started) * 1000)

        guard = _read_json(self.workspace / guard_rel)
        result = ExecResult(
            exit_code=completed.returncode,
            stdout=completed.stdout[: request.max_output_bytes],
            stderr=completed.stderr[: request.max_output_bytes],
            duration_ms=duration_ms,
            timed_out=completed.timed_out,
            peak_ram_mb=0,
            cpu_seconds=0.0,
            # No interface exists in the container, so egress is zero by construction.
            egress_bytes=0,
            network_attempts=int(guard.get("network_attempts", 0)),
            network_enforced=True,
            signals=extract_signals(completed.stdout, completed.stderr),
            artifacts=self._collect(request.collect_artifacts),
            label=request.label,
        )
        if completed.timed_out:
            result.signals.append("timeout")
        return self._record(result)

    def _collect(self, paths: list[str]) -> dict[str, str]:
        out: dict[str, str] = {}
        root = self.workspace.resolve()
        for rel in paths:
            candidate = (self.workspace / rel).resolve()
            if str(candidate).startswith(str(root)) and candidate.is_file():
                try:
                    out[rel] = candidate.read_text(encoding="utf-8", errors="replace")[:2_000_000]
                except OSError:
                    continue
        return out

    async def stop(self) -> None:
        logger.info("sandbox.stop", adapter=self.name, executions=self.execution_count)

    def capabilities(self) -> SandboxCapabilities:
        return SandboxCapabilities(
            adapter=self.name,
            isolation_model="gVisor (runsc) userspace kernel + container confinement",
            network_enforced=True,
            filesystem_isolated=True,
            non_root=True,
            seccomp=True,
            dropped_capabilities=True,
            read_only_root=True,
            resource_limits_enforced=True,
            suitable_for_untrusted_code=True,
            notes=(
                "Syscalls are serviced by the gVisor Sentry rather than the host kernel. "
                "No network interface exists in the sandbox, the pinned source tree is "
                "mounted read-only, and the only writable path is a size-capped noexec tmpfs."
            ),
        )


# ---------------------------------------------------------------------------
class _Completed:
    __slots__ = ("returncode", "stderr", "stdout", "timed_out")

    def __init__(self, returncode: int, stdout: str, stderr: str, timed_out: bool) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out


async def _run(argv: list[str], *, stdin: str | None = None, timeout: int = 120) -> _Completed:
    # Threaded spawn, for the same reason as the dev adapter: independence from whichever event loop
    # the host installed. See app/sandbox/spawn.py.
    completed = await run_process(
        argv,
        stdin=stdin.encode("utf-8") if stdin is not None else None,
        timeout=timeout,
        env={k: v for k, v in os.environ.items() if k in ("PATH", "SYSTEMROOT", "HOME")},
        on_timeout=lambda process: process.kill(),
    )
    if completed.timed_out:
        return _Completed(-1, "", "sandbox execution exceeded wall clock limit", True)
    return _Completed(
        completed.returncode,
        completed.stdout.decode("utf-8", errors="replace"),
        completed.stderr.decode("utf-8", errors="replace"),
        False,
    )


def _read_json(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
