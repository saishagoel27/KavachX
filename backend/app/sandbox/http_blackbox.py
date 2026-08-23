"""Black-box observation for long-running HTTP server targets.

The CLI harness (:mod:`app.sandbox.blackbox`) runs a program once per request. A web service is
different: it must be **started once**, driven over HTTP, then stopped. This module does exactly
that, language-agnostically:

1. start the operator's ``start_command`` as a server, with their env, from their root dir, listening
   on an allocated loopback port;
2. wait for the port to accept connections (or bail if the server exits first);
3. send each request over HTTP, capturing status + body (hashed, scanned for planted tokens) and
   the filesystem diff around the call (a write side effect);
4. always tear the server down, so no orphan is left listening.

The server runs on one of two backends, chosen by the sandbox adapter of the run:

* **gVisor** (``service_adapter`` is the gVisor adapter) — the server runs **inside a runsc
  container**: detached, ``--network bridge`` with its port published to loopback, workspace bound
  read-write, torn down with ``docker rm -f``. This is the isolation boundary for a network service.
* **host** (dev profile) — the server runs as a host subprocess, torn down with a process-tree kill.
  No isolation boundary; development only.

As with the CLI harness a vulnerability is only ever reported on a **deterministically observed
effect** (a canary leaked in a response body, an injected command's marker echoed), never a guess.
The server runs through the same allowlisted, proxy-denied environment as the rest of the sandbox.
"""

from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import tempfile
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from app.core.hashing import sha256_text
from app.core.logging import get_logger
from app.sandbox.base import build_sandbox_env
from app.sandbox.blackbox import _snapshot
from app.sandbox.dev import _kill_tree

logger = get_logger(__name__)


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@dataclass(slots=True)
class HttpObservation:
    method: str
    path: str
    status: int
    body: str
    output_hash: str
    duration_ms: int
    files_created: list[str] = field(default_factory=list)
    files_modified: list[str] = field(default_factory=list)
    tokens_seen: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def observed_effect(self) -> bool:
        return bool(self.tokens_seen)

    def as_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "path": self.path,
            "status": self.status,
            "output_hash": self.output_hash,
            "duration_ms": self.duration_ms,
            "files_created": self.files_created,
            "files_modified": self.files_modified,
            "tokens_seen": self.tokens_seen,
            "error": self.error,
            "observed_effect": self.observed_effect,
        }


@dataclass(slots=True)
class HttpProbeResult:
    ready: bool
    port: int
    base_url: str
    observations: list[HttpObservation] = field(default_factory=list)
    server_stdout: str = ""
    server_stderr: str = ""
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "ready": self.ready,
            "port": self.port,
            "base_url": self.base_url,
            "reason": self.reason,
            "observations": [o.as_dict() for o in self.observations],
        }


async def _port_open(host: str, port: int) -> bool:
    try:
        _reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=1.0)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except (OSError, TimeoutError):
        return False


async def _docker_cmd(docker: str, args: Sequence[str], timeout: int = 20) -> tuple[int, str, str]:
    """Run a short docker command off the event loop, returning (returncode, stdout, stderr)."""
    from app.sandbox.spawn import run_process

    completed = await run_process(
        [docker, *args],
        timeout=timeout,
        env={k: v for k, v in os.environ.items() if k in ("PATH", "SYSTEMROOT", "HOME")},
    )
    if getattr(completed, "timed_out", False):
        return -1, "", "docker command timed out"
    return (
        completed.returncode,
        completed.stdout.decode("utf-8", errors="replace"),
        completed.stderr.decode("utf-8", errors="replace"),
    )


class _HostServer:
    """The operator's server as a host subprocess (dev profile — not an isolation boundary)."""

    def __init__(
        self, *, command: str, run_dir: Path, host: str, port: int, env: dict[str, str]
    ) -> None:
        self.command = command
        self.run_dir = run_dir
        self.env = build_sandbox_env({"PORT": str(port), "HOST": host, **env})
        self._proc: subprocess.Popen | None = None
        self._out = tempfile.TemporaryFile()  # noqa: SIM115 - closed in stop()
        self._err = tempfile.TemporaryFile()  # noqa: SIM115 - closed in stop()
        self.reason = ""

    async def start(self) -> bool:
        popen_kwargs: dict[str, Any] = {}
        if os.name == "nt":
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            popen_kwargs["start_new_session"] = True
        # Operator-authored command through the platform shell so `npm start` (a `.cmd` shim on
        # Windows) resolves. The untrusted target itself is never run via a shell.
        spawn = ["cmd", "/c", self.command] if os.name == "nt" else ["sh", "-c", self.command]
        try:
            self._proc = subprocess.Popen(
                spawn,
                cwd=str(self.run_dir),
                env=self.env,
                stdout=self._out,
                stderr=self._err,
                **popen_kwargs,
            )
            return True
        except (FileNotFoundError, OSError) as exc:
            self.reason = f"could not start the server ({self.command!r}): {exc}"
            logger.warning("http_blackbox.spawn_failed", command=self.command, error=str(exc)[:200])
            return False

    async def wait_ready(self, host: str, port: int, timeout: float) -> bool:
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            if self._proc is None or self._proc.poll() is not None:
                return False
            if await _port_open(host, port):
                return True
            await asyncio.sleep(0.25)
        return False

    def not_ready_reason(self) -> str:
        if self._proc is not None and self._proc.poll() is None:
            return "the server did not start listening in time"
        code = self._proc.returncode if self._proc else "?"
        return f"the server process exited early (code {code})"

    def logs(self) -> tuple[str, str]:
        out: list[str] = []
        for handle in (self._out, self._err):
            try:
                handle.seek(0)
                out.append(handle.read()[-2000:].decode("utf-8", errors="replace"))
            except Exception:
                out.append("")
        return out[0], out[1]

    def stop(self) -> None:
        if self._proc is not None:
            _kill_tree(self._proc)
            try:
                self._proc.wait(timeout=10)
            except Exception:
                pass
        for handle in (self._out, self._err):
            try:
                handle.close()
            except Exception:
                pass


class _ContainerServer:
    """The operator's server inside a gVisor container — the isolation boundary for a web service.

    Detached ``docker run -d --runtime=runsc --network bridge`` with the app's port published to
    loopback and the workspace bound read-write (a service writes logs/uploads that are themselves
    observable effects). The adapter builds the argv; teardown is ``docker rm -f``.
    """

    def __init__(
        self,
        adapter: Any,
        *,
        command: str,
        cwd: str,
        env: dict[str, str],
        host_port: int,
        container_port: int,
    ) -> None:
        self.adapter = adapter
        self.docker = adapter.docker_path
        self.command = command
        self.cwd = cwd
        self.env = env
        self.host_port = host_port
        self.container_port = container_port
        self.name = f"kavachx-http-{uuid.uuid4().hex[:12]}"
        self.reason = ""
        self._exited_reason = ""

    async def start(self) -> bool:
        argv = self.adapter.service_container_argv(
            name=self.name,
            host_port=self.host_port,
            container_port=self.container_port,
            cwd=self.cwd,
            env=self.env,
            start_command=self.command,
        )
        from app.sandbox.spawn import run_process

        completed = await run_process(
            argv,
            timeout=90,
            env={k: v for k, v in os.environ.items() if k in ("PATH", "SYSTEMROOT", "HOME")},
        )
        rc = completed.returncode
        if getattr(completed, "timed_out", False) or rc != 0:
            err = completed.stderr.decode("utf-8", errors="replace")[:300]
            self.reason = f"could not start the server container (docker exit {rc}): {err}"
            logger.warning("http_blackbox.container_start_failed", exit=rc, error=err)
            return False
        return True

    async def _running(self) -> bool:
        rc, out, _err = await _docker_cmd(
            self.docker, ["inspect", "-f", "{{.State.Running}}", self.name], timeout=10
        )
        return rc == 0 and out.strip() == "true"

    async def wait_ready(self, host: str, port: int, timeout: float) -> bool:
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            if not await self._running():
                self._exited_reason = "the server container exited before it listened"
                return False
            if await _port_open(host, port):
                return True
            await asyncio.sleep(0.3)
        return False

    def not_ready_reason(self) -> str:
        return self._exited_reason or "the server did not start listening in time"

    def logs(self) -> tuple[str, str]:
        # Best-effort teardown-path capture; docker logs is quick.
        try:
            p = subprocess.run(
                [self.docker, "logs", "--tail", "80", self.name],
                capture_output=True,
                timeout=15,
            )
            return (
                p.stdout.decode("utf-8", errors="replace")[-2000:],
                p.stderr.decode("utf-8", errors="replace")[-2000:],
            )
        except Exception:
            return "", ""

    def stop(self) -> None:
        try:
            subprocess.run([self.docker, "rm", "-f", self.name], capture_output=True, timeout=20)
        except Exception:
            logger.warning("http_blackbox.container_stop_failed", name=self.name)


async def observe_http(
    *,
    start_argv: Sequence[str],
    workspace: Path,
    requests: Sequence[dict[str, Any]],
    cwd: str = ".",
    env: dict[str, str] | None = None,
    host: str = "127.0.0.1",
    port: int | None = None,
    watch_tokens: Sequence[str] = (),
    ready_timeout: float = 30.0,
    request_timeout: float = 10.0,
    service_adapter: Any = None,
    container_port: int | None = None,
) -> HttpProbeResult:
    """Start ``start_argv`` as a server, drive it with ``requests``, and observe each response.

    ``requests`` are dicts of ``{"method": "GET", "path": "/x?y=z"}`` (body optional). ``watch_tokens``
    are canary/marker strings whose appearance in a response body is proof of an effect.

    When ``service_adapter`` exposes ``service_container_argv`` (the gVisor adapter) and a
    ``container_port`` is given, the server runs inside a runsc container; otherwise it runs as a
    host subprocess (dev profile).
    """
    host_port = port or find_free_port()
    base_url = f"http://{host}:{host_port}"
    run_dir = (workspace / cwd).resolve()

    result = HttpProbeResult(ready=False, port=host_port, base_url=base_url)
    if not run_dir.is_dir():
        result.reason = f"root directory {cwd!r} does not exist in the workspace"
        logger.warning("http_blackbox.bad_cwd", cwd=cwd)
        return result

    command = " ".join(start_argv)
    use_container = bool(
        service_adapter is not None
        and container_port
        and getattr(service_adapter, "service_container_argv", None) is not None
    )
    server: Any
    if use_container:
        server = _ContainerServer(
            service_adapter,
            command=command,
            cwd=cwd,
            env=dict(env or {}),
            host_port=host_port,
            container_port=int(container_port),
        )
    else:
        server = _HostServer(
            command=command, run_dir=run_dir, host=host, port=host_port, env=dict(env or {})
        )

    if not await server.start():
        result.reason = server.reason
        return result
    try:
        ready = await server.wait_ready(host, host_port, ready_timeout)
        result.ready = ready
        if not ready:
            result.reason = server.not_ready_reason()
            logger.warning("http_blackbox.not_ready", port=host_port, reason=result.reason)
            return result

        async with httpx.AsyncClient(base_url=base_url, timeout=request_timeout) as client:
            for spec in requests:
                method = str(spec.get("method", "GET")).upper()
                path = str(spec.get("path", "/"))
                body = spec.get("body")
                before = _snapshot(workspace)
                loop = asyncio.get_event_loop()
                started = loop.time()
                try:
                    resp = await client.request(
                        method, path, json=body if body is not None else None
                    )
                    status = resp.status_code
                    text = resp.text
                    error = ""
                except Exception as exc:  # a hang/refused mid-run is itself an observation
                    status = -1
                    text = ""
                    error = str(exc)[:300]
                duration_ms = int((loop.time() - started) * 1000)
                after = _snapshot(workspace)
                blob = text
                result.observations.append(
                    HttpObservation(
                        method=method,
                        path=path,
                        status=status,
                        body=text[:4000],
                        output_hash=sha256_text(f"{status}\n{text}"),
                        duration_ms=duration_ms,
                        files_created=sorted(set(after) - set(before)),
                        files_modified=sorted(
                            p for p in (set(after) & set(before)) if after[p] != before[p]
                        ),
                        tokens_seen=[t for t in watch_tokens if t and t in blob],
                        error=error,
                    )
                )
        return result
    finally:
        result.server_stdout, result.server_stderr = server.logs()
        server.stop()


async def probe_http(
    *,
    start_argv: Sequence[str],
    workspace: Path,
    http_requests: Sequence[dict[str, Any]],
    cwd: str = ".",
    env: dict[str, str] | None = None,
    reproduce: int = 2,
    service_adapter: Any = None,
    container_port: int | None = None,
) -> list[Any]:
    """Adaptively fuzz a running server from its benign HTTP requests, returning confirmed findings.

    For each benign request's query parameters, injection markers and a traversal canary are woven
    in; the server is started once, driven with the whole batch, and a vulnerability is confirmed
    only where the planted token appears in the response — reproduced by sending each exploit
    ``reproduce`` times. Returns :class:`app.analysis.blackbox_probe.BlackboxFinding` objects so the
    orchestrator treats CLI and HTTP findings identically.
    """
    import json
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

    from app.analysis.blackbox_probe import (
        _CANARY_CONTENT,
        _CANARY_NAME,
        _MARKER,
        BlackboxFinding,
    )
    from app.core.hashing import sha256_json, sha256_text
    from app.models.enums import Severity
    from app.validator.service import ValidationOutcome

    try:
        (workspace / _CANARY_NAME).write_text(_CANARY_CONTENT, encoding="utf-8")
    except OSError:
        logger.warning("http_blackbox.canary_write_failed")

    separators = ("&", ";", "|")
    reqs: list[dict[str, Any]] = []
    meta: dict[str, tuple[str, str, str, str]] = {}  # tag -> (vuln, method, base_path, param)
    baseline: dict[str, str] = {}  # benign tag -> base_path (to confirm the route is reachable)

    def _mutation(parts: Any, params: list[tuple[str, str]], index: int, value: str) -> str:
        mutated = list(params)
        mutated[index] = (mutated[index][0], value)
        return urlunsplit(("", "", parts.path, urlencode(mutated), ""))

    for ri, br in enumerate(http_requests):
        method = str(br.get("method", "GET")).upper()
        raw_path = str(br.get("path", "/"))
        parts = urlsplit(raw_path)
        # Benign baseline: send the request unmodified to confirm the route actually responds.
        btag = f"benign:{ri}"
        reqs.append({"method": method, "path": raw_path, "_tag": btag})
        baseline[btag] = parts.path
        params = parse_qsl(parts.query, keep_blank_values=True)
        for pi, (key, value) in enumerate(params):
            for si, sep in enumerate(separators):
                tag = f"inj:{ri}:{pi}:{si}"
                path = _mutation(parts, params, pi, f"{value}{sep} echo {_MARKER}")
                for _ in range(reproduce):
                    reqs.append({"method": method, "path": path, "_tag": tag})
                meta[tag] = ("command_injection", method, parts.path, key)
            tag = f"trav:{ri}:{pi}"
            path = _mutation(parts, params, pi, f"../{_CANARY_NAME}")
            for _ in range(reproduce):
                reqs.append({"method": method, "path": path, "_tag": tag})
            meta[tag] = ("path_traversal", method, parts.path, key)

    if not reqs:
        return []

    result = await observe_http(
        start_argv=start_argv,
        workspace=workspace,
        requests=reqs,
        cwd=cwd,
        env=env,
        watch_tokens=[_MARKER, _CANARY_CONTENT],
        service_adapter=service_adapter,
        container_port=container_port,
    )
    if not result.ready:
        logger.warning("http_blackbox.probe_not_ready", reason=result.reason)
        return []

    # Which routes actually responded to the benign baseline (2xx/3xx) — only fuzz-confirm on these.
    reachable: set[str] = set()
    for obs, spec in zip(result.observations, reqs, strict=False):
        tag = spec["_tag"]
        if tag.startswith("benign:") and 200 <= obs.status < 400:
            reachable.add(baseline[tag])

    hits: dict[str, int] = {}
    sample: dict[str, Any] = {}
    for obs, spec in zip(result.observations, reqs, strict=False):
        tag = spec["_tag"]
        if tag not in meta:  # a benign baseline entry
            continue
        vuln, _method, base_path, _param = meta[tag]
        if base_path not in reachable:
            continue
        token = _MARKER if vuln == "command_injection" else _CANARY_CONTENT
        if token in obs.tokens_seen:
            hits[tag] = hits.get(tag, 0) + 1
            sample.setdefault(tag, obs)

    findings: dict[tuple[str, str, str], BlackboxFinding] = {}
    for tag, count in hits.items():
        if count < reproduce:
            continue
        vuln, method, base_path, param = meta[tag]
        key = (vuln, base_path, param)
        if key in findings:
            continue
        obs = sample[tag]
        cwe = "CWE-78" if vuln == "command_injection" else "CWE-22"
        severity = Severity.CRITICAL.value if vuln == "command_injection" else Severity.HIGH.value
        exploit = {"method": method, "path": obs.path}
        outcome = ValidationOutcome(
            reproduced=True,
            reproduction_count=count,
            exit_code=obs.status,
            sanitizer_signal="",
            contract_violation=f"parameter '{param}' at {base_path} produced an observable effect",
            pov_payload=json.dumps(exploit, sort_keys=True),
            pov_kind=vuln,
            pov_request=exploit,
            input_hash=sha256_json(exploit),
            output_hash=obs.output_hash,
            trace_hash=sha256_text(f"{obs.output_hash}:{vuln}:{param}"),
            severity=severity,
            crash_site=f"{base_path}?{param}",
            detail=(
                f"{vuln.replace('_', ' ')} confirmed over HTTP: {method} {base_path} with a crafted "
                f"'{param}' leaked the planted token, reproduced {count}x."
            ),
            observed_tokens=[param],
            evidence={"kind": vuln, "path": base_path, "param": param, "http": True},
        )
        findings[key] = BlackboxFinding(
            vuln_type=vuln,
            cwe=cwe,
            severity=severity,
            op=base_path,
            field=param,
            location=f"{base_path}?{param}",
            description=f"{vuln.replace('_', ' ')} via '{param}' at {base_path}",
            outcome=outcome,
        )
    logger.info("http_blackbox.probe_done", findings=len(findings))
    return list(findings.values())
