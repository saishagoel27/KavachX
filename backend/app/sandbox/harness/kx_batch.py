"""In-sandbox batch case runner.

Runs a list of cases against the target entrypoint and reports, per case: exit code, stdout,
the response object and its hash, the exception type/message/location if it raised, and the
delta in guard counters (shell invocations, network attempts, reads outside the asset root).

Three stages of the pipeline share this harness, which is deliberate — it means fuzzing,
differential replay and exploit mutation all observe behaviour through exactly the same lens:

* **fuzzing** — thousands of mutated cases, looking for crashes;
* **differential replay** — the benign corpus before and after a patch, compared by hash;
* **exploit mutation** — variant payloads against a patched build.

Cases run in-process for speed. Any case that raises is reported with its full frame list, and
the caller re-runs the interesting ones as isolated processes to obtain the independent exit
code that a finding's reproduction record requires.

Usage::

    python -m kx_batch --spec batch-spec.json --out batch-result.json
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import io
import json
import sys
import time
import traceback
from pathlib import Path
from typing import Any

try:
    import kx_guard
except Exception:  # pragma: no cover
    kx_guard = None  # type: ignore[assignment]


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def guard_snapshot() -> dict[str, int]:
    if kx_guard is None:
        return {}
    state = kx_guard.state()
    return {
        "shell_invocations": int(state.get("shell_invocations", 0)),
        "process_invocations": int(state.get("process_invocations", 0)),
        "network_attempts": int(state.get("network_attempts", 0)),
        "reads_outside_root": int(state.get("file_reads_outside_root", 0)),
    }


def guard_delta(before: dict[str, int], after: dict[str, int]) -> dict[str, int]:
    return {key: after.get(key, 0) - before.get(key, 0) for key in after}


def project_frames(exc_traceback: Any, project_root: Path) -> list[dict[str, Any]]:
    frames: list[dict[str, Any]] = []
    for frame in traceback.extract_tb(exc_traceback):
        filename = frame.filename or ""
        in_project = False
        rel = filename
        try:
            resolved = Path(filename).resolve()
            rel = resolved.relative_to(project_root).as_posix()
            in_project = not rel.startswith("_kavachx/")
        except (ValueError, OSError):
            in_project = False
        frames.append(
            {
                "file": rel,
                "line": frame.lineno or 0,
                "function": frame.name or "",
                "text": (frame.line or "").strip()[:300],
                "in_project": in_project,
            }
        )
    return frames


def frames_from_traceback_text(text: str, project_root: Path) -> list[dict[str, Any]]:
    """Parse a rendered traceback back into structured frames."""
    frames: list[dict[str, Any]] = []
    lines = text.splitlines()
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.startswith('File "'):
            continue
        try:
            after = stripped.split('File "', 1)[1]
            path, remainder = after.split('"', 1)
            parts = remainder.split(",")
            line_no = int(parts[1].strip().removeprefix("line ").strip())
            function = parts[2].strip().removeprefix("in ").strip() if len(parts) > 2 else ""
        except (IndexError, ValueError):
            continue
        rel = path
        in_project = False
        try:
            rel = Path(path).resolve().relative_to(project_root).as_posix()
            in_project = not rel.startswith("_kavachx/")
        except (ValueError, OSError):
            in_project = False
        following = lines[index + 1].strip() if index + 1 < len(lines) else ""
        frames.append(
            {
                "file": rel,
                "line": line_no,
                "function": function,
                "text": following[:300],
                "in_project": in_project,
            }
        )
    return frames


def _shield_verdict(argv: list[str]) -> dict[str, Any] | None:
    """If a shield is deployed and rejects this case, return its response.

    In-process cases never reach ``sitecustomize``'s argv gate, so the shield has to be
    consulted here — otherwise a deployed shield would appear to pass benign verification while
    doing nothing.
    """
    try:
        import os

        if not os.environ.get("KAVACHX_SHIELD_RULES"):
            return None
        import kx_shield

        rule, request = kx_shield.evaluate_argv(argv)
        if rule is None:
            return None
        return kx_shield.blocked_response(request, rule)
    except Exception:
        return None


def run_case(entry: Any, case: dict[str, Any], project_root: Path) -> dict[str, Any]:
    argv = [str(a) for a in case.get("argv", [])]

    shielded = _shield_verdict(argv)
    if shielded is not None:
        rendered = json.dumps(shielded, sort_keys=True)
        return {
            "id": case.get("id", ""),
            "argv": argv,
            "exit_code": 0,
            "duration_ms": 0,
            "stdout": rendered,
            "stderr": "",
            "response": shielded,
            "response_hash": sha256_text(canonical(shielded)),
            "stdout_hash": sha256_text(rendered),
            "error_type": "",
            "error_message": "",
            "frames": [],
            "crash_site": "",
            "guard_delta": {},
            "label": case.get("label", ""),
            "shield_blocked": True,
        }

    buffer = io.StringIO()
    original_stdout = sys.stdout
    original_stderr = sys.stderr
    error_buffer = io.StringIO()

    before = guard_snapshot()
    started = time.perf_counter()
    exit_code = 0
    error_type = ""
    error_message = ""
    frames: list[dict[str, Any]] = []

    sys.stdout = buffer
    sys.stderr = error_buffer
    try:
        outcome = entry(argv)
        exit_code = int(outcome) if isinstance(outcome, int) else 0
    except SystemExit as exc:
        exit_code = int(exc.code or 0)
    except BaseException as exc:
        exit_code = 1
        error_type = type(exc).__name__
        error_message = str(exc)[:500]
        frames = project_frames(exc.__traceback__, project_root)
    finally:
        sys.stdout = original_stdout
        sys.stderr = original_stderr

    duration_ms = int((time.perf_counter() - started) * 1000)
    stdout = buffer.getvalue()
    stderr = error_buffer.getvalue()

    response: Any = None
    for line in reversed(stdout.strip().splitlines()):
        try:
            response = json.loads(line)
            break
        except ValueError:
            continue

    # The target's own CLI catches exceptions and prints a traceback rather than propagating,
    # so a nonzero return with traceback text on stderr is still a crash — and the traceback is
    # then the *only* place the executed path is recorded. Parsing it is what lets a fuzz crash
    # carry a project crash site instead of looking like a harness failure.
    if exit_code != 0 and not error_type and "Traceback" in stderr:
        for line in reversed(stderr.strip().splitlines()):
            if ":" in line and not line.startswith(" "):
                error_type = line.split(":", 1)[0].strip().split(".")[-1]
                error_message = line.split(":", 1)[1].strip()[:500]
                break
    if exit_code != 0 and not frames and "Traceback" in stderr:
        frames = frames_from_traceback_text(stderr, project_root)

    return {
        "id": case.get("id", ""),
        "argv": argv,
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "stdout": stdout[-8000:],
        "stderr": stderr[-8000:],
        "response": response,
        "response_hash": sha256_text(canonical(response)),
        "stdout_hash": sha256_text(stdout),
        "error_type": error_type,
        "error_message": error_message,
        "frames": frames,
        "crash_site": _crash_site(frames),
        "guard_delta": guard_delta(before, guard_snapshot()),
        "label": case.get("label", ""),
    }


def _crash_site(frames: list[dict[str, Any]]) -> str:
    for frame in reversed(frames):
        if frame.get("in_project"):
            return f"{frame['file']}:{frame['line']}"
    return ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="kx_batch")
    parser.add_argument("--spec", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    spec = json.loads(Path(args.spec).read_text(encoding="utf-8"))
    project_root = Path(spec.get("project_root", ".")).resolve()
    source_root = Path(spec.get("source_root", ".")).resolve()
    if str(source_root) not in sys.path:
        sys.path.insert(0, str(source_root))

    module = importlib.import_module(spec.get("entry_module", "main"))
    entry = getattr(module, spec.get("entry_callable", "main"))

    results: list[dict[str, Any]] = []
    stop_after_first_crash = bool(spec.get("stop_after_first_crash", False))
    for case in spec.get("cases", []):
        record = run_case(entry, case, project_root)
        results.append(record)
        if stop_after_first_crash and record["exit_code"] != 0:
            break

    document = {
        "schema": "kavachx.batch.v1",
        "python": sys.version.split()[0],
        "cases": results,
        "guard_total": guard_snapshot(),
        "crashes": len([r for r in results if r["exit_code"] != 0]),
    }
    Path(args.out).write_text(json.dumps(document, sort_keys=True, default=str), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
