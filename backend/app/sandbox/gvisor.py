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
import re
import shutil
import subprocess
import threading
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

#: image → does it ship /usr/bin/time. Probed once per image per process, then reused, so the
#: detection never re-runs a container on a busy host.
_TIME_PROBE_CACHE: dict[str, bool] = {}


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
        #: Whether the image ships GNU ``/usr/bin/time`` (detected once in start()). When present,
        #: each exec is measured for real peak RSS and CPU; when absent those stay zero — never an
        #: error, so an un-rebuilt image degrades gracefully instead of breaking runs.
        self._have_time = False

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

        # Detect GNU time in the image so each exec can be measured for real peak RSS and CPU
        # (getrusage, which gVisor implements). Cached per image so this runs one throwaway container
        # for the whole process lifetime, not one per run — no repeated load on a busy host. Fully
        # optional and defensive: any failure leaves measurement off (metrics report zero), never an
        # error, and no exception escapes start().
        if self.image in _TIME_PROBE_CACHE:
            self._have_time = _TIME_PROBE_CACHE[self.image]
        else:
            try:
                time_probe = await _run(
                    [self._docker, "run", "--rm", self.image, "/usr/bin/time", "--version"],
                    timeout=30,
                )
                self._have_time = time_probe.returncode == 0
            except Exception:
                self._have_time = False
            _TIME_PROBE_CACHE[self.image] = self._have_time

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
    def _docker_argv(
        self,
        request: ExecRequest,
        guard_report_rel: str,
        rusage_rel: str | None = None,
        container_name: str | None = None,
    ) -> list[str]:
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
        # A stable name lets the egress sampler query `docker stats` for this exact container. Only
        # set for the networked build phase; the untrusted execute path is left byte-for-byte as it
        # was.
        if container_name:
            argv += ["--name", container_name]

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
        # Measure real peak RSS + CPU with GNU time inside the container (gVisor implements
        # getrusage). The report goes to the writable output-dir bind — the same dir the guard report
        # already writes to as 'nobody' — and `time` propagates the command's own exit status, so this
        # is transparent. Only applied when the image actually has /usr/bin/time (probed in start()).
        if self._have_time and rusage_rel:
            argv += ["/usr/bin/time", "-v", "-o", f"{CONTAINER_WORKSPACE}/{rusage_rel}"]
        argv += request.argv
        return argv

    async def execute(self, request: ExecRequest) -> ExecResult:
        guard_rel = f"{HARNESS_DIR_NAME}/out/guard-report.{self.execution_count}.json"
        rusage_rel = (
            f"{HARNESS_DIR_NAME}/out/rusage.{self.execution_count}.txt" if self._have_time else None
        )
        # Only the networked build phase needs a name + egress sampling; the untrusted execute path
        # is left exactly as before (no name, no sampler, egress structurally zero).
        container_name = (
            f"kavachx-{self.session_id}-{self.execution_count}" if request.allow_network else None
        )
        argv = self._docker_argv(request, guard_rel, rusage_rel, container_name)
        timeout = request.timeout_seconds or self.limits.wall_clock_seconds

        started = time.perf_counter()
        egress_bytes = 0
        if container_name:
            # Sample the container's outbound bytes in an isolated daemon thread — no event-loop
            # involvement, every error swallowed, so it can never affect the run or the server.
            egress_holder = {"tx": 0}
            stop = threading.Event()
            sampler = threading.Thread(
                target=_egress_sampler,
                args=(self._docker, container_name, egress_holder, stop),
                daemon=True,
            )
            sampler.start()
            try:
                completed = await _run(argv, stdin=request.stdin, timeout=timeout)
            finally:
                stop.set()
                sampler.join(timeout=3)
            egress_bytes = egress_holder["tx"]
        else:
            completed = await _run(argv, stdin=request.stdin, timeout=timeout)
        duration_ms = int((time.perf_counter() - started) * 1000)

        guard = _read_json(self.workspace / guard_rel)
        peak_ram_mb, cpu_seconds = (
            _parse_rusage(self.workspace / rusage_rel) if rusage_rel else (0, 0.0)
        )
        result = ExecResult(
            exit_code=completed.returncode,
            stdout=completed.stdout[: request.max_output_bytes],
            stderr=completed.stderr[: request.max_output_bytes],
            duration_ms=duration_ms,
            timed_out=completed.timed_out,
            peak_ram_mb=peak_ram_mb,
            cpu_seconds=cpu_seconds,
            # Zero and provable in the execute phase (no interface); the real sampled outbound total
            # in the networked build phase. network_enforced records which case this was.
            egress_bytes=egress_bytes,
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


def _parse_rusage(path: Path) -> tuple[int, float]:
    """Parse a GNU ``time -v`` report into ``(peak_ram_mb, cpu_seconds)``.

    Missing or unparseable → ``(0, 0.0)``, so an image without GNU time (or a failed write) simply
    reports zero rather than affecting the run.
    """
    if not path.is_file():
        return 0, 0.0
    peak_kb = 0
    user_s = 0.0
    sys_s = 0.0
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()
            try:
                if "maximum resident set size" in key:
                    peak_kb = int(value)
                elif key == "user time (seconds)":
                    user_s = float(value)
                elif key == "system time (seconds)":
                    sys_s = float(value)
            except ValueError:
                continue
    except OSError:
        return 0, 0.0
    return round(peak_kb / 1024), round(user_s + sys_s, 3)


_BYTE_UNITS = {
    "b": 1,
    "kb": 1000,
    "mb": 1000**2,
    "gb": 1000**3,
    "tb": 1000**4,
    "kib": 1024,
    "mib": 1024**2,
    "gib": 1024**3,
    "tib": 1024**4,
}


def _human_to_bytes(value: str) -> int:
    match = re.match(r"^\s*([0-9.]+)\s*([a-zA-Z]+)\s*$", value)
    if not match:
        return 0
    try:
        number = float(match.group(1))
    except ValueError:
        return 0
    return int(number * _BYTE_UNITS.get(match.group(2).lower(), 1))


def _parse_netio_tx(netio: str) -> int:
    """Bytes leaving the container from a ``docker stats`` NetIO field (``RX / TX``); TX is egress."""
    parts = netio.strip().split("/")
    if len(parts) != 2:
        return 0
    return _human_to_bytes(parts[1])


def _egress_sampler(docker: str, name: str, holder: dict[str, int], stop: threading.Event) -> None:
    """Poll a container's outbound bytes from ``docker stats`` until told to stop.

    Runs in an isolated daemon thread. Every failure is swallowed and it holds the peak TX seen, so
    the worst case is an egress of 0 — it can never affect the run or the backend process.
    """
    while not stop.is_set():
        try:
            probe = subprocess.run(
                [docker, "stats", "--no-stream", "--format", "{{.NetIO}}", name],
                capture_output=True,
                timeout=15,
            )
            if probe.returncode == 0:
                tx = _parse_netio_tx(probe.stdout.decode("utf-8", errors="replace"))
                if tx > holder["tx"]:
                    holder["tx"] = tx
        except Exception:
            pass
        # A relaxed interval: NetIO is cumulative, so a coarse poll still captures near-final egress
        # while barely touching the docker daemon during a long, resource-heavy build.
        stop.wait(5.0)
