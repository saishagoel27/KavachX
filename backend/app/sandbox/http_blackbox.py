"""Black-box observation for long-running HTTP server targets.

The CLI harness (:mod:`app.sandbox.blackbox`) runs a program once per request. A web service is
different: it must be **started once**, driven over HTTP, then stopped. This module does exactly
that, language-agnostically:

1. start the operator's ``start_command`` as a subprocess, with their env, from their root dir, on
   an allocated loopback port;
2. wait for the port to accept connections (or bail if the process exits first);
3. send each request over HTTP, capturing status + body (hashed, scanned for planted tokens) and
   the filesystem diff around the call (a write side effect);
4. always tear the server down — process-tree kill, so no orphan is left listening.

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


async def _wait_ready(host: str, port: int, proc: subprocess.Popen, timeout: float) -> bool:
    """Poll until the port accepts a connection, or the server process exits, or we time out."""
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if proc.poll() is not None:
            return False  # the server exited before it ever listened
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=1.0
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except (OSError, TimeoutError):
            await asyncio.sleep(0.25)
    return False


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
    ready_timeout: float = 25.0,
    request_timeout: float = 10.0,
) -> HttpProbeResult:
    """Start ``start_argv`` as a server, drive it with ``requests``, and observe each response.

    ``requests`` are dicts of ``{"method": "GET", "path": "/x?y=z"}`` (body optional). ``watch_tokens``
    are canary/marker strings whose appearance in a response body is proof of an effect.
    """
    port = port or find_free_port()
    base_url = f"http://{host}:{port}"
    run_dir = (workspace / cwd).resolve()
    server_env = build_sandbox_env({"PORT": str(port), "HOST": host, **(env or {})})

    result = HttpProbeResult(ready=False, port=port, base_url=base_url)
    if not run_dir.is_dir():
        result.reason = f"root directory {cwd!r} does not exist in the workspace"
        logger.warning("http_blackbox.bad_cwd", cwd=cwd)
        return result

    out_f = tempfile.TemporaryFile()  # noqa: SIM115 - closed in the finally block below
    err_f = tempfile.TemporaryFile()  # noqa: SIM115 - closed in the finally block below
    popen_kwargs: dict[str, Any] = {}
    if os.name == "nt":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        popen_kwargs["start_new_session"] = True

    # Start through the platform shell so operator commands like `npm start` (a `.cmd` shim on
    # Windows, which Popen cannot launch directly) resolve. The start command is operator-authored,
    # not target-supplied, so a shell here is acceptable — the target itself is never run via a shell.
    command = " ".join(start_argv)
    spawn = ["cmd", "/c", command] if os.name == "nt" else ["sh", "-c", command]
    try:
        proc = subprocess.Popen(
            spawn,
            cwd=str(run_dir),
            env=server_env,
            stdout=out_f,
            stderr=err_f,
            **popen_kwargs,
        )
    except (FileNotFoundError, OSError) as exc:
        out_f.close()
        err_f.close()
        result.reason = f"could not start the server ({command!r}): {exc}"
        logger.warning("http_blackbox.spawn_failed", command=command, error=str(exc)[:200])
        return result
    try:
        ready = await _wait_ready(host, port, proc, ready_timeout)
        result.ready = ready
        if not ready:
            result.reason = (
                "the server did not start listening in time"
                if proc.poll() is None
                else f"the server process exited early (code {proc.returncode})"
            )
            logger.warning("http_blackbox.not_ready", port=port, reason=result.reason)
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
                    resp = await client.request(method, path, json=body if body is not None else None)
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
        _kill_tree(proc)
        try:
            proc.wait(timeout=10)
        except Exception:
            pass
        for handle, attr in ((out_f, "server_stdout"), (err_f, "server_stderr")):
            try:
                handle.seek(0)
                setattr(result, attr, handle.read()[-2000:].decode("utf-8", errors="replace"))
            except Exception:
                pass
            finally:
                handle.close()


async def probe_http(
    *,
    start_argv: Sequence[str],
    workspace: Path,
    http_requests: Sequence[dict[str, Any]],
    cwd: str = ".",
    env: dict[str, str] | None = None,
    reproduce: int = 2,
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
