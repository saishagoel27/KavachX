"""In-sandbox observation harness.

Runs a list of benign cases against the target entrypoint *in-process* under ``sys.settrace``
and emits one JSON document containing, per case:

* the response and its content hash (for determinism and differential replay),
* every project function that was called, with the value profile of its arguments and return,
* executed line coverage against the target's statement count,
* the guard counters (shell invocations, network attempts, filesystem reach).

This is the raw material SAMHITA clauses are proposed from and falsified against. Nothing here
decides anything — it only records what happened.

Usage::

    python -m kx_observe --spec observe_spec.json --out observations.json
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib
import json
import os
import sys
import time
import traceback
from pathlib import Path
from typing import Any

try:
    import kx_guard
except Exception:  # pragma: no cover
    kx_guard = None  # type: ignore[assignment]

MAX_REPR = 240


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


# ---------------------------------------------------------------------------
# statement counting for real coverage
# ---------------------------------------------------------------------------
def statement_lines(path: Path) -> set[int]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError):
        return set()
    lines: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.stmt) and getattr(node, "lineno", None):
            lines.add(node.lineno)
    return lines


# ---------------------------------------------------------------------------
# tracer
# ---------------------------------------------------------------------------
class Recorder:
    def __init__(self, project_root: Path) -> None:
        self.project_root = project_root.resolve()
        self.covered: dict[str, set[int]] = {}
        self.calls: list[dict[str, Any]] = []
        self.depth = 0
        #: Which benign case is currently executing. Every recorded call is tagged with it so
        #: the observation/held-out split can be made per case rather than per call.
        self.current_case = ""
        self._relative_cache: dict[str, str] = {}

    def _relative(self, filename: str) -> str | None:
        """Map a frame's filename to a project-relative path, or None if it is not ours.

        Frozen and synthetic frames (``<frozen importlib._bootstrap>``, ``<string>``) have no
        real path, and ``Path(...).resolve()`` happily turns them into
        ``<cwd>/<frozen importlib._bootstrap>`` — which lands *inside* the project root and
        floods the observations with stdlib behaviour. Reject them before resolving, and
        require the result to be a file that actually exists.
        """
        if not filename or filename.startswith("<"):
            return None
        cached = self._relative_cache.get(filename)
        if cached is not None:
            return cached or None
        try:
            resolved = Path(filename).resolve()
            if not resolved.is_file():
                self._relative_cache[filename] = ""
                return None
            rel = resolved.relative_to(self.project_root).as_posix()
        except (ValueError, OSError):
            self._relative_cache[filename] = ""
            return None
        # The injected harness is KavachX's own code, not the target's.
        if rel.startswith("_kavachx/"):
            self._relative_cache[filename] = ""
            return None
        self._relative_cache[filename] = rel
        return rel

    def trace(self, frame: Any, event: str, arg: Any) -> Any:
        rel = self._relative(frame.f_code.co_filename)
        if rel is None:
            return None

        if event == "call":
            self.depth += 1
            if len(self.calls) < 4000:
                self.calls.append(
                    {
                        "file": rel,
                        "function": frame.f_code.co_name,
                        "line": frame.f_code.co_firstlineno,
                        "depth": self.depth,
                        "case_id": self.current_case,
                        "args": self._profile_args(frame),
                        "ret": None,
                    }
                )
            return self.trace

        if event == "line":
            self.covered.setdefault(rel, set()).add(frame.f_lineno)
            return self.trace

        if event == "return":
            self.depth = max(0, self.depth - 1)
            for record in reversed(self.calls):
                if (
                    record["file"] == rel
                    and record["function"] == frame.f_code.co_name
                    and record["ret"] is None
                ):
                    record["ret"] = self._profile_value(arg)
                    break
            return self.trace

        return self.trace

    def _profile_args(self, frame: Any) -> dict[str, Any]:
        code = frame.f_code
        names = code.co_varnames[: code.co_argcount]
        out: dict[str, Any] = {}
        for name in names:
            if name in ("self", "cls"):
                continue
            if name in frame.f_locals:
                out[name] = self._profile_value(frame.f_locals[name])
        return out

    @staticmethod
    def _profile_value(value: Any) -> dict[str, Any]:
        profile: dict[str, Any] = {"type": type(value).__name__}
        if isinstance(value, (bool, int, float)):
            profile["value"] = value
        elif isinstance(value, str):
            profile["len"] = len(value)
            profile["lines"] = value.count("\n") + 1 if value else 0
            profile["value"] = value[:MAX_REPR]
        elif isinstance(value, (bytes, bytearray, list, tuple, set)):
            profile["len"] = len(value)
        elif isinstance(value, dict):
            profile["len"] = len(value)
            profile["keys"] = sorted(str(k) for k in list(value)[:20])
            if "ok" in value:
                profile["ok"] = bool(value.get("ok"))
            if "seq" in value and isinstance(value.get("seq"), int):
                profile["seq"] = value["seq"]
            if "op" in value:
                profile["op"] = str(value.get("op"))
        elif value is None:
            profile["value"] = None
        return profile


# ---------------------------------------------------------------------------
def load_entry(spec: dict[str, Any]) -> Any:
    module_name = spec.get("entry_module", "main")
    callable_name = spec.get("entry_callable", "main")
    module = importlib.import_module(module_name)
    entry = getattr(module, callable_name, None)
    if entry is None:
        raise RuntimeError(f"{module_name}.{callable_name} not found")
    return entry


def guard_snapshot() -> dict[str, Any]:
    if kx_guard is None:
        return {}
    state = kx_guard.state()
    calls = state.get("subprocess_calls") or []
    return {
        "shell_invocations": int(state.get("shell_invocations", 0)),
        "process_invocations": int(state.get("process_invocations", 0)),
        "network_attempts": int(state.get("network_attempts", 0)),
        "egress_bytes": int(state.get("egress_bytes", 0)),
        "reads_outside_root": int(state.get("file_reads_outside_root", 0)),
        "subprocess_call_count": len(calls) if isinstance(calls, list) else 0,
        "subprocess_calls": list(calls) if isinstance(calls, list) else [],
    }


def guard_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Per-case guard activity.

    Deltas rather than running totals, because a cumulative counter is not comparable between two
    runs that executed different numbers of cases. A clause derived from a total would appear to
    break the moment the corpus size changed — a false regression with nothing behind it.
    """
    if not after:
        return {}
    delta = {
        key: int(after.get(key, 0)) - int(before.get(key, 0))
        for key in (
            "shell_invocations",
            "process_invocations",
            "network_attempts",
            "egress_bytes",
            "reads_outside_root",
        )
    }
    new_calls = (after.get("subprocess_calls") or [])[int(before.get("subprocess_call_count", 0)) :]
    delta["subprocess_calls"] = new_calls
    return delta


def run_case(entry: Any, case: dict[str, Any], recorder: Recorder) -> dict[str, Any]:
    argv = [str(a) for a in case.get("argv", [])]
    recorder.current_case = str(case.get("id", ""))
    guard_before = guard_snapshot()
    stdout_capture: list[str] = []

    class _Tee:
        def write(self, data: str) -> int:
            stdout_capture.append(data)
            return len(data)

        def flush(self) -> None:
            return None

    original_stdout = sys.stdout
    sys.stdout = _Tee()  # type: ignore[assignment]
    started = time.perf_counter()
    error = ""
    exit_code = 0
    try:
        sys.settrace(recorder.trace)
        result = entry(argv)
        exit_code = int(result) if isinstance(result, int) else 0
    except SystemExit as exc:  # entrypoints may exit
        exit_code = int(exc.code or 0)
    except BaseException:
        exit_code = 1
        error = traceback.format_exc()[-4000:]
    finally:
        sys.settrace(None)
        sys.stdout = original_stdout

    duration_ms = int((time.perf_counter() - started) * 1000)
    stdout = "".join(stdout_capture)
    response: Any = None
    try:
        response = json.loads(stdout.strip().splitlines()[-1]) if stdout.strip() else None
    except (ValueError, IndexError):
        response = None

    return {
        "id": case.get("id", ""),
        "argv": argv,
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "stdout": stdout[-8000:],
        "error": error,
        "response": response,
        "response_hash": sha256_text(canonical(response)) if response is not None else "",
        "stdout_hash": sha256_text(stdout),
        "guard_delta": guard_delta(guard_before, guard_snapshot()),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="kx_observe")
    parser.add_argument("--spec", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    spec = json.loads(Path(args.spec).read_text(encoding="utf-8"))
    project_root = Path(spec.get("project_root", ".")).resolve()
    source_root = Path(spec.get("source_root", ".")).resolve()

    if str(source_root) not in sys.path:
        sys.path.insert(0, str(source_root))

    statements: dict[str, int] = {}
    for path in sorted(source_root.rglob("*.py")):
        rel = path.resolve().relative_to(project_root).as_posix()
        statements[rel] = len(statement_lines(path))

    recorder = Recorder(project_root)
    entry = load_entry(spec)

    passes = int(spec.get("passes", 1))
    cases: list[dict[str, Any]] = list(spec.get("cases", []))
    results: list[dict[str, Any]] = []
    for pass_index in range(passes):
        for case in cases:
            record = run_case(entry, case, recorder)
            record["pass"] = pass_index
            results.append(record)

    covered = {file: sorted(lines) for file, lines in recorder.covered.items()}
    total_statements = sum(statements.values()) or 1
    covered_statements = sum(
        len([ln for ln in lines if ln in statement_lines(project_root / file)])
        for file, lines in covered.items()
        if (project_root / file).is_file()
    )

    guard_state = dict(kx_guard.state()) if kx_guard is not None else {}

    document = {
        "schema": "kavachx.observations.v1",
        "python": sys.version.split()[0],
        "project_root": str(project_root),
        "source_root": str(source_root),
        "passes": passes,
        "cases": results,
        "calls": recorder.calls,
        "coverage": {
            "covered_lines_by_file": covered,
            "statements_by_file": statements,
            "total_statements": total_statements,
            "covered_statements": covered_statements,
            "percent": round(100.0 * covered_statements / total_statements, 2),
        },
        "guard": guard_state,
        "cwd": os.getcwd(),
    }
    Path(args.out).write_text(json.dumps(document, sort_keys=True, default=str), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
