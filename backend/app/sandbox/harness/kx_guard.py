"""KavachX in-sandbox guard and observation instrumentation.

This module runs **inside the sandbox**, in the same interpreter as the target. It has no
KavachX imports and no dependencies beyond the standard library, because it is copied into a
workspace that may be executed by a weaker adapter than the one it was written for.

Responsibilities:

1. **Deny network.** ``socket.socket``, ``socket.create_connection`` and the ssl wrappers are
   replaced with functions that raise. Every attempt is counted. This is what makes
   "egress: 0 bytes" a measurement rather than a claim for Python targets, even under the
   development adapter where the OS is not enforcing anything.
2. **Count shell invocations.** ``subprocess`` entry points are wrapped to record whether
   ``shell=True`` was used and what argv was passed. This is the observable behind the
   ``forbidden_shell_invocation`` SAMHITA clause.
3. **Record filesystem reach.** ``builtins.open`` and ``Path.read_bytes``/``read_text`` record
   the resolved absolute path, so path containment is observable.

Everything observed is written to ``KAVACHX_GUARD_REPORT`` as JSON at interpreter exit.
"""

from __future__ import annotations

import atexit
import builtins
import json
import os
import subprocess
import sys
import time
from pathlib import Path

REPORT_PATH = os.environ.get("KAVACHX_GUARD_REPORT", "")
ALLOW_NETWORK = os.environ.get("KAVACHX_ALLOW_NETWORK", "0") == "1"
#: Directory the target's own asset reads are expected to stay within.
CONTAINMENT_ROOT = os.environ.get("KAVACHX_CONTAINMENT_ROOT", "")
#: The workspace. Reads outside it are the interpreter loading its own standard library and
#: say nothing about the target's containment behaviour, so they are not counted.
WORKSPACE_ROOT = os.environ.get("KAVACHX_WORKSPACE_ROOT", "")

_state: dict[str, object] = {
    "network_attempts": 0,
    "network_targets": [],
    "egress_bytes": 0,
    "shell_invocations": 0,
    "process_invocations": 0,
    "subprocess_calls": [],
    "file_reads": [],
    "file_reads_outside_root": 0,
    "installed": False,
    "started_at": time.time(),
}


def state() -> dict[str, object]:
    return _state


class NetworkDenied(OSError):
    """Raised for any attempt to create a socket inside the sandbox."""


def _record_network(target: object) -> None:
    _state["network_attempts"] = int(_state["network_attempts"]) + 1
    targets = _state["network_targets"]
    if isinstance(targets, list) and len(targets) < 50:
        targets.append(str(target)[:200])


def _install_network_denial() -> None:
    if ALLOW_NETWORK:
        return
    import socket as _socket

    class _DeniedSocket:
        def __init__(self, *args: object, **kwargs: object) -> None:
            _record_network(args[:2] if args else "socket()")
            raise NetworkDenied("KavachX sandbox: network access is denied for analysed code.")

    def _denied(*args: object, **kwargs: object) -> None:
        _record_network(args[0] if args else "connect")
        raise NetworkDenied("KavachX sandbox: network access is denied for analysed code.")

    _socket.socket = _DeniedSocket  # type: ignore[assignment,misc]
    _socket.create_connection = _denied  # type: ignore[assignment]
    _socket.create_server = _denied  # type: ignore[assignment]
    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex"):
        if hasattr(_socket, name):
            setattr(_socket, name, _denied)

    try:
        import ssl as _ssl

        _ssl.SSLContext.wrap_socket = _denied  # type: ignore[assignment,method-assign]
    except Exception:
        pass

    try:
        import http.client as _http

        _http.HTTPConnection.connect = _denied  # type: ignore[assignment,method-assign]
    except Exception:
        pass


def _install_subprocess_recording() -> None:
    original_popen_init = subprocess.Popen.__init__

    def recording_init(self, args, *rest, **kwargs):  # type: ignore[no-untyped-def]
        shell = bool(kwargs.get("shell", False))
        _state["process_invocations"] = int(_state["process_invocations"]) + 1
        if shell:
            _state["shell_invocations"] = int(_state["shell_invocations"]) + 1
        calls = _state["subprocess_calls"]
        if isinstance(calls, list) and len(calls) < 200:
            if isinstance(args, (list, tuple)):
                rendered = [str(a) for a in args]
                argv_count = len(rendered)
            else:
                rendered = [str(args)]
                argv_count = 1
            calls.append(
                {
                    "shell": shell,
                    "argv_count": argv_count,
                    "argv": rendered[:12],
                    "first": rendered[0][:200] if rendered else "",
                }
            )
        return original_popen_init(self, args, *rest, **kwargs)

    subprocess.Popen.__init__ = recording_init  # type: ignore[method-assign]


def _resolve(path: object) -> str:
    try:
        return str(Path(str(path)).resolve())
    except Exception:
        return str(path)[:400]


def _contained_by(candidate: Path, root: Path) -> bool:
    return candidate == root or root in candidate.parents


def _record_read(path: object) -> None:
    resolved = _resolve(path)
    if not CONTAINMENT_ROOT:
        return

    try:
        candidate = Path(resolved)
        root = Path(CONTAINMENT_ROOT).resolve()

        # Module loading is not asset access. Counting it would make the containment metric a
        # measure of how many files the interpreter imported, which no clause can use.
        if candidate.suffix.lower() in (".py", ".pyc", ".pyd", ".pyi", ".so", ".dll"):
            return

        if WORKSPACE_ROOT:
            workspace = Path(WORKSPACE_ROOT).resolve()
            # Only reads the target performs *within its own workspace* are meaningful here;
            # everything else is the interpreter reading its own standard library.
            if not _contained_by(candidate, workspace):
                return
            rel = str(candidate)
            if f"{os.sep}_kavachx{os.sep}" in rel or rel.endswith(f"{os.sep}_kavachx"):
                return

        inside = _contained_by(candidate, root)
    except Exception:
        return

    reads = _state["file_reads"]
    if isinstance(reads, list) and len(reads) < 300:
        reads.append(resolved[:400])
    if not inside:
        _state["file_reads_outside_root"] = int(_state["file_reads_outside_root"]) + 1
        outside = _state.setdefault("reads_outside_root_paths", [])
        if isinstance(outside, list) and len(outside) < 20:
            outside.append(resolved[:400])


def _install_filesystem_recording() -> None:
    original_open = builtins.open

    def recording_open(file, mode="r", *args, **kwargs):  # type: ignore[no-untyped-def]
        if isinstance(file, (str, bytes, os.PathLike)) and "r" in str(mode):
            _record_read(file)
        return original_open(file, mode, *args, **kwargs)

    builtins.open = recording_open  # type: ignore[assignment]

    original_read_bytes = Path.read_bytes
    original_read_text = Path.read_text

    def recording_read_bytes(self):  # type: ignore[no-untyped-def]
        _record_read(self)
        return original_read_bytes(self)

    def recording_read_text(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        _record_read(self)
        return original_read_text(self, *args, **kwargs)

    Path.read_bytes = recording_read_bytes  # type: ignore[method-assign]
    Path.read_text = recording_read_text  # type: ignore[method-assign]


def write_report() -> None:
    if not REPORT_PATH:
        return
    payload = dict(_state)
    payload["finished_at"] = time.time()
    payload["python"] = sys.version.split()[0]
    payload["network_enforced_in_process"] = not ALLOW_NETWORK
    try:
        target = Path(REPORT_PATH)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    except Exception:
        pass


def install() -> None:
    if _state.get("installed"):
        return
    _state["installed"] = True
    _install_network_denial()
    _install_subprocess_recording()
    _install_filesystem_recording()
    atexit.register(write_report)
