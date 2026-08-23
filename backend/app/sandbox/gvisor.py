"""gVisor sandbox adapter.

Runs each execution as ``docker run --runtime=runsc`` with the full confinement set. gVisor
intercepts syscalls in userspace, so a container escape has to get through the Sentry rather
than straight to the host kernel — which is why this, and not plain Docker, is the
development-to-production step up.

Two postures share this adapter, chosen per execution (see ``ExecRequest.writable`` /
``allow_network``):

* **Execute phase** — the untrusted target. Maximum confinement:
  ``--network none``            no interface at all, so egress is structurally impossible
  ``--read-only``              root filesystem immutable
  ``--user 65534:65534``       nobody; never root
  ``--mount …,readonly``       the pinned source tree is mounted read-only

* **Build phase** — the trusted, operator-authored install/build (``npm install``, ``pip install``,
  ``mvn`` …). It needs the two things the execute phase forbids, and gets only those two:
  ``--network bridge``         reach the package registry
  ``--mount`` (read-write) + ``--user <host uid>``  write ``node_modules`` / a venv into the tree

Both postures keep the rest of the confinement set regardless:
``--tmpfs /workspace/.tmp``  size-capped writable scratch (also holds ``$HOME``, so tool caches land here)
``--cap-drop ALL``           no capabilities
``--security-opt no-new-privileges``  setuid binaries cannot elevate
``--security-opt seccomp=…``  explicit profile on top of gVisor's own filtering
``--pids-limit / --memory / --cpus``  resource caps enforced by cgroups

In the execute phase the pinned tree is read-only, so the target cannot mutate the tree whose hash
was computed outside the sandbox. The build phase runs before the hash-bearing observation and
writes only dependencies operator commands asked for.
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


def _host_user() -> str:
    """``uid:gid`` of the host process, for the writable build phase.

    The workspace bind-mount is owned by the host user, so a container writing ``node_modules`` into
    it must run as that uid — 'nobody' (65534) would be denied. gVisor is Linux-only, so ``getuid``
    exists; the fallback keeps a non-Linux import from raising.
    """
    getuid = getattr(os, "getuid", None)
    getgid = getattr(os, "getgid", None)
    if getuid is not None and getgid is not None:
        return f"{getuid()}:{getgid()}"
    return "0:0"


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

        # Fail fast if the target's toolchain image is not built: otherwise every `docker run` below
        # returns a bare exit 125 ("no such image"), the run limps to zero findings, and the result
        # looks like "nothing wrong" when in truth nothing ran. Name the image and how to build it.
        image_probe = await _run([self._docker, "image", "inspect", self.image])
        if image_probe.returncode != 0:
            raise SandboxUnavailable(
                f"The sandbox image {self.image!r} is not built on this host, so the target's "
                "toolchain is unavailable. Build the per-language sandbox images — run "
                "`bash setup-gvisor-local.sh` (it builds all of them), or build this one directly, "
                "e.g. `docker build -f sandbox/Dockerfile.node -t kavachx/sandbox-node:dev "
                "./sandbox` (…-java / …-go / …-rust for the others).",
                code="SANDBOX_IMAGE_MISSING",
            )

        self.workspace.mkdir(parents=True, exist_ok=True)
        self.harness_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        # The tmpfs mounts at CONTAINER_TMP (/workspace/.tmp). Because the workspace is bind-mounted
        # read-only in the execute phase, that mountpoint cannot be created inside the container —
        # runsc fails container creation with exit 125. Create it on the host first, like the
        # harness output dir, so the mountpoint always exists under the read-only bind.
        (self.workspace / ".tmp").mkdir(parents=True, exist_ok=True)
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

        # Two postures share this adapter. The trusted *build* phase (operator-authored install /
        # build) needs the registry and a writable tree; the untrusted *execute* phase gets neither.
        if request.writable:
            # Build phase: network egress for the package registry, workspace bound read-write, and
            # run as the host uid so writes to the bind mount are permitted (the mount is owned by
            # the host user, not by 'nobody'). The rootfs stays writable because some installers
            # touch it; every other confinement — non-root of the host user, dropped capabilities,
            # no-new-privileges, resource caps, runsc — is unchanged.
            network_args = ["--network", "bridge"]
            user_args = ["--user", _host_user()]
            read_only_root: list[str] = []
            source_mount = (
                f"type=bind,source={self.workspace.resolve()},target={CONTAINER_WORKSPACE}"
            )
        else:
            # Execute phase: no interface at all (egress structurally impossible), read-only rootfs,
            # read-only pinned tree, and the 'nobody' user.
            network_args = ["--network", "none"]
            user_args = ["--user", "65534:65534"]
            read_only_root = ["--read-only"]
            source_mount = (
                f"type=bind,source={self.workspace.resolve()},target={CONTAINER_WORKSPACE},readonly"
            )

        argv = [
            self._docker,
            "run",
            "--rm",
            f"--runtime={self.runtime}",
            *network_args,
            *read_only_root,
            *user_args,
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

        # The output directory is always writable via its own bind; the pinned tree is read-only in
        # the execute phase and read-write in the build phase (see source_mount above).
        argv += [
            "--mount",
            source_mount,
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
            # In the execute phase no interface exists, so egress is zero by construction. The build
            # phase (writable, networked) is a trusted provisioning step, not a proof-bearing run.
            egress_bytes=0,
            network_attempts=int(guard.get("network_attempts", 0)),
            network_enforced=not request.allow_network,
            signals=extract_signals(completed.stdout, completed.stderr),
            artifacts=self._collect(request.collect_artifacts),
            label=request.label,
        )
        if completed.timed_out:
            result.signals.append("timeout")
        return self._record(result)

    # ------------------------------------------------------------------
    @property
    def docker_path(self) -> str | None:
        """The resolved ``docker`` binary, available after :meth:`start`. Used by the HTTP service
        runner to drive ``docker logs`` / ``docker rm`` on the detached server container."""
        return self._docker

    def service_container_argv(
        self,
        *,
        name: str,
        host_port: int,
        container_port: int,
        cwd: str,
        env: dict[str, str],
        start_command: str,
    ) -> list[str]:
        """``docker run`` argv for a **long-running HTTP service** under gVisor.

        Unlike :meth:`execute` (a one-shot, no-network, read-only container), a web service must stay
        up while the prober drives it and must be reachable. So this is detached (``-d``), on
        ``--network bridge`` with the app's port published to loopback only, with the workspace bound
        **read-write** — a service writes logs/uploads that are themselves observable effects — and
        run as the host uid so those writes land on the bind mount. Every other confinement (dropped
        capabilities, no-new-privileges, resource caps, seccomp, runsc) is unchanged. Torn down with
        ``docker rm -f <name>``.
        """
        assert self._docker
        env_map = build_sandbox_env(
            {
                "PORT": str(container_port),
                "HOST": "0.0.0.0",
                "HOME": CONTAINER_TMP,
                "TMPDIR": CONTAINER_TMP,
                **(env or {}),
            }
        )
        env_map["PATH"] = "/usr/local/bin:/usr/bin:/bin"

        argv = [
            self._docker,
            "run",
            "--rm",
            "-d",
            "--name",
            name,
            f"--runtime={self.runtime}",
            "--network",
            "bridge",
            "-p",
            f"127.0.0.1:{host_port}:{container_port}",
            "--user",
            _host_user(),
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
            f"{CONTAINER_WORKSPACE}/{cwd}".rstrip("/."),
        ]
        if self.seccomp_profile and self.seccomp_profile.is_file():
            argv += ["--security-opt", f"seccomp={self.seccomp_profile}"]
        argv += [
            "--mount",
            f"type=bind,source={self.workspace.resolve()},target={CONTAINER_WORKSPACE}",
        ]
        for key, value in env_map.items():
            argv += ["--env", f"{key}={value}"]
        argv += [self.image, "sh", "-c", start_command]
        return argv

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
