"""Deterministic validator.

Takes a hypothesis and its validation plan, builds an executable job, runs it **inside the
sandbox**, and decides from deterministic signals alone whether the finding is real:

* process exit code
* sanitizer / interpreter crash signal
* contract violation (a surviving SAMHITA clause evaluating false on the exploit trace)
* a distinctive marker appearing in output (command execution) or canary content (containment escape)
* reproducibility — the same input must produce the same outcome ``reproductions_required``
  times, in independent processes

No model is consulted here, and there is no code path by which a model could set
``reproduced``. A hypothesis that does not reproduce becomes ``REFUTED`` and is recorded with
what was actually observed instead.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.analysis.probe import TargetDescriptor
from app.core.hashing import sha256_json, sha256_text
from app.core.logging import get_logger
from app.discovery.base import CANARY_CONTENT, CANARY_FILENAME
from app.models.enums import Severity
from app.samhita.engine import SamhitaResult
from app.samhita.falsifier import check_clause_against_records
from app.samhita.observation import ObservationRecord, parse_observations
from app.sandbox.base import ExecRequest, ExecResult, SandboxAdapter

logger = get_logger(__name__)


@dataclass
class ValidationOutcome:
    reproduced: bool = False
    reproduction_count: int = 0
    exit_code: int | None = None
    sanitizer_signal: str = ""
    contract_violation: str = ""
    violated_clause_id: str = ""
    pov_payload: str = ""
    pov_kind: str = ""
    pov_request: dict[str, Any] = field(default_factory=dict)
    input_hash: str = ""
    output_hash: str = ""
    trace_hash: str = ""
    coverage_percent: float = 0.0
    severity: str = Severity.MEDIUM.value
    #: Frames from the crash, used by root-cause analysis.
    trace_frames: list[dict[str, Any]] = field(default_factory=list)
    crash_site: str = ""
    detail: str = ""
    refutation_reason: str = ""
    attempts: list[dict[str, Any]] = field(default_factory=list)
    tool_events: list[dict[str, Any]] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    #: Extra tokens the naive-fix recipe will blacklist (e.g. the working separator).
    observed_tokens: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "reproduced": self.reproduced,
            "reproduction_count": self.reproduction_count,
            "exit_code": self.exit_code,
            "sanitizer_signal": self.sanitizer_signal,
            "contract_violation": self.contract_violation,
            "violated_clause_id": self.violated_clause_id,
            "pov_kind": self.pov_kind,
            "input_hash": self.input_hash,
            "output_hash": self.output_hash,
            "trace_hash": self.trace_hash,
            "coverage_percent": self.coverage_percent,
            "crash_site": self.crash_site,
            "detail": self.detail,
            "refutation_reason": self.refutation_reason,
            "attempts": self.attempts,
        }


class Validator:
    def __init__(
        self,
        *,
        sandbox: SandboxAdapter,
        descriptor: TargetDescriptor,
        samhita: SamhitaResult,
        workspace: Path,
    ) -> None:
        self.sandbox = sandbox
        self.descriptor = descriptor
        self.samhita = samhita
        self.workspace = workspace
        self._canary_planted = False

    # ------------------------------------------------------------------
    async def validate(self, plan: dict[str, Any], *, handle: str) -> ValidationOutcome:
        kind = str(plan.get("kind", ""))
        if not kind:
            return ValidationOutcome(
                refutation_reason="The hypothesis carried no validation plan.",
                detail="not executable",
            )

        dispatch = {
            "command_injection": self._validate_command_injection,
            "length_boundary": self._validate_length_boundary,
            "path_traversal": self._validate_path_traversal,
            "replay_request": self._validate_replay_request,
            "native_crash": self._validate_native,
        }.get(kind)

        if dispatch is None:
            return ValidationOutcome(
                refutation_reason=f"No validator implements plan kind {kind!r}.",
                detail="unsupported plan",
            )

        started = time.perf_counter()
        outcome = await dispatch(plan, handle)
        outcome.tool_events.append(
            {
                "name": f"validator:{kind}",
                "target": handle,
                "ms": int((time.perf_counter() - started) * 1000),
                "ok": outcome.reproduced,
                "detail": outcome.detail or outcome.refutation_reason,
            }
        )
        logger.info(
            "validator.result",
            handle=handle,
            kind=kind,
            reproduced=outcome.reproduced,
            reproductions=outcome.reproduction_count,
        )
        return outcome

    # ------------------------------------------------------------------
    # Command injection: prove a shell executed attacker-supplied content.
    # ------------------------------------------------------------------
    async def _validate_command_injection(
        self, plan: dict[str, Any], handle: str
    ) -> ValidationOutcome:
        outcome = ValidationOutcome(pov_kind="command_injection")
        marker = str(plan.get("marker", "KAVACHX_POV_MARKER"))
        base = str(plan.get("base_value", "kavachx-probe"))
        operation = str(plan.get("operation", "export"))
        field_name = str(plan.get("field", "name"))

        # Which separator works depends on the host shell (`;` on sh, `&` on cmd.exe). Try each
        # and let execution decide, rather than assuming a platform.
        for separator in plan.get("separators", ["&", ";", "|"]):
            payload = f"{base}{separator}echo {marker}"
            request = {"op": operation, field_name: payload}
            if operation == "export":
                request["format"] = "txt"

            confirmations: list[dict[str, Any]] = []
            required = int(plan.get("reproductions_required", 2))
            for attempt in range(required):
                result = await self._run_request(request, label=f"pov:{handle}:{attempt}")
                executed = marker in result.stdout
                confirmations.append(
                    {
                        "separator": separator,
                        "attempt": attempt,
                        "exit_code": result.exit_code,
                        "marker_present": executed,
                        "output_hash": result.output_hash(),
                    }
                )
                if not executed:
                    break

            outcome.attempts.extend(confirmations)
            if len(confirmations) == required and all(c["marker_present"] for c in confirmations):
                outcome.reproduced = True
                outcome.reproduction_count = required
                outcome.exit_code = int(confirmations[-1]["exit_code"])
                outcome.pov_payload = payload
                outcome.pov_request = request
                outcome.observed_tokens = [separator]
                outcome.severity = Severity.CRITICAL.value
                outcome.input_hash = sha256_json(request)
                outcome.output_hash = str(confirmations[-1]["output_hash"])
                outcome.trace_hash = sha256_text(f"command_injection:{separator}:{marker}")
                outcome.sanitizer_signal = "command_execution_confirmed"
                outcome.crash_site = f"{plan.get('target_file', '')}:{plan.get('target_line', 0)}"
                outcome.detail = (
                    f"Injected command executed via the {separator!r} separator; the marker "
                    f"appeared in stdout on {required} independent runs."
                )
                await self._attach_contract_violation(outcome, request, plan)
                return outcome

        outcome.refutation_reason = (
            "No tested separator caused the injected command to execute. Tried: "
            + ", ".join(repr(s) for s in plan.get("separators", []))
        )
        outcome.detail = "not reproducible"
        return outcome

    # ------------------------------------------------------------------
    # Length boundary: escalate until the process actually fails.
    # ------------------------------------------------------------------
    async def _validate_length_boundary(
        self, plan: dict[str, Any], handle: str
    ) -> ValidationOutcome:
        outcome = ValidationOutcome(pov_kind="length_boundary")
        operation = str(plan.get("operation", "parse"))
        field_name = str(plan.get("field", "headers"))

        for count in plan.get("escalation", [8, 9, 12, 20, 64]):
            payload = "\n".join(f"h{i}:{i}" for i in range(int(count)))
            request = {"op": operation, field_name: payload}

            required = int(plan.get("reproductions_required", 2))
            confirmations: list[dict[str, Any]] = []
            frames: list[dict[str, Any]] = []
            for attempt in range(required):
                result = await self._run_request(request, label=f"pov:{handle}:{count}:{attempt}")
                failed = result.exit_code != 0 or bool(result.signals)
                confirmations.append(
                    {
                        "header_lines": count,
                        "attempt": attempt,
                        "exit_code": result.exit_code,
                        "signals": result.signals,
                        "output_hash": result.output_hash(),
                    }
                )
                if not failed:
                    break
                if attempt == 0:
                    frames = _frames_from_stderr(result.stderr)

            outcome.attempts.extend(confirmations)
            if len(confirmations) == required and all(
                c["exit_code"] != 0 or c["signals"] for c in confirmations
            ):
                last = confirmations[-1]
                outcome.reproduced = True
                outcome.reproduction_count = required
                outcome.exit_code = int(last["exit_code"])
                outcome.sanitizer_signal = ",".join(last["signals"]) or "nonzero_exit"
                outcome.pov_payload = payload
                outcome.pov_request = request
                outcome.severity = Severity.HIGH.value
                outcome.input_hash = sha256_json(request)
                outcome.output_hash = str(last["output_hash"])
                outcome.trace_frames = frames
                outcome.crash_site = _project_crash_site(frames) or (
                    f"{plan.get('target_file', '')}:{plan.get('target_line', 0)}"
                )
                outcome.trace_hash = sha256_json(frames)
                outcome.observed_tokens = [str(count)]
                outcome.detail = (
                    f"{count} header lines crash the entrypoint (exit "
                    f"{outcome.exit_code}, signal {outcome.sanitizer_signal}) on {required} "
                    "independent runs."
                )
                await self._attach_contract_violation(outcome, request, plan)
                return outcome

        outcome.refutation_reason = (
            "The input never caused a failure at any tested size: "
            + ", ".join(str(c) for c in plan.get("escalation", []))
        )
        outcome.detail = "not reproducible"
        return outcome

    # ------------------------------------------------------------------
    # Path traversal: read a canary that lives outside the asset root.
    # ------------------------------------------------------------------
    async def _validate_path_traversal(
        self, plan: dict[str, Any], handle: str
    ) -> ValidationOutcome:
        outcome = ValidationOutcome(pov_kind="path_traversal")
        self._plant_canary()
        operation = str(plan.get("operation", "asset"))
        field_name = str(plan.get("field", "path"))

        for payload in plan.get("payloads", [f"../{CANARY_FILENAME}"]):
            request = {"op": operation, field_name: payload}
            required = int(plan.get("reproductions_required", 2))
            confirmations: list[dict[str, Any]] = []
            for attempt in range(required):
                result = await self._run_request(request, label=f"pov:{handle}:{attempt}")
                escaped = CANARY_CONTENT in result.stdout
                confirmations.append(
                    {
                        "payload": payload,
                        "attempt": attempt,
                        "exit_code": result.exit_code,
                        "canary_present": escaped,
                        "output_hash": result.output_hash(),
                    }
                )
                if not escaped:
                    break

            outcome.attempts.extend(confirmations)
            if len(confirmations) == required and all(c["canary_present"] for c in confirmations):
                outcome.reproduced = True
                outcome.reproduction_count = required
                outcome.exit_code = int(confirmations[-1]["exit_code"])
                outcome.pov_payload = payload
                outcome.pov_request = request
                outcome.severity = Severity.HIGH.value
                outcome.input_hash = sha256_json(request)
                outcome.output_hash = str(confirmations[-1]["output_hash"])
                outcome.trace_hash = sha256_text(f"path_traversal:{payload}")
                outcome.sanitizer_signal = "containment_escape_confirmed"
                outcome.crash_site = f"{plan.get('target_file', '')}:{plan.get('target_line', 0)}"
                outcome.observed_tokens = ["../", "..\\"]
                outcome.detail = (
                    f"The payload {payload!r} read a canary file outside the declared asset "
                    f"root on {required} independent runs."
                )
                await self._attach_contract_violation(outcome, request, plan)
                return outcome

        outcome.refutation_reason = (
            "No traversal payload read the canary planted outside the asset root."
        )
        outcome.detail = "not reproducible"
        return outcome

    # ------------------------------------------------------------------
    # Replay: a fuzzer-supplied request that must crash again.
    # ------------------------------------------------------------------
    async def _validate_replay_request(
        self, plan: dict[str, Any], handle: str
    ) -> ValidationOutcome:
        outcome = ValidationOutcome(pov_kind="replay_request")
        request = dict(plan.get("request") or {})
        if not request:
            outcome.refutation_reason = "The plan carried no request to replay."
            return outcome

        expected_type = str(plan.get("expected_error_type", ""))
        required = int(plan.get("reproductions_required", 2))
        confirmations: list[dict[str, Any]] = []
        frames: list[dict[str, Any]] = []

        for attempt in range(required):
            result = await self._run_request(request, label=f"pov:{handle}:{attempt}")
            failed = result.exit_code != 0 or bool(result.signals)
            if attempt == 0:
                frames = _frames_from_stderr(result.stderr)
            confirmations.append(
                {
                    "attempt": attempt,
                    "exit_code": result.exit_code,
                    "signals": result.signals,
                    "output_hash": result.output_hash(),
                    "error_type_present": (expected_type in result.stderr)
                    if expected_type
                    else True,
                }
            )
            if not failed:
                break

        outcome.attempts = confirmations
        if len(confirmations) == required and all(
            c["exit_code"] != 0 or c["signals"] for c in confirmations
        ):
            last = confirmations[-1]
            outcome.reproduced = True
            outcome.reproduction_count = required
            outcome.exit_code = int(last["exit_code"])
            outcome.sanitizer_signal = ",".join(last["signals"]) or "nonzero_exit"
            outcome.pov_payload = json.dumps(request, sort_keys=True)
            outcome.pov_request = request
            outcome.severity = Severity.HIGH.value
            outcome.input_hash = sha256_json(request)
            outcome.output_hash = str(last["output_hash"])
            outcome.trace_frames = frames
            outcome.crash_site = _project_crash_site(frames) or str(
                plan.get("expected_crash_site", "")
            )
            outcome.trace_hash = sha256_json(frames)
            outcome.detail = (
                f"The fuzzer-supplied request reproduced a failure at {outcome.crash_site} "
                f"on {required} independent runs (exit {outcome.exit_code})."
            )
            await self._attach_contract_violation(outcome, request, plan)
            return outcome

        outcome.refutation_reason = (
            "The request did not reproduce a failure when replayed in an isolated process."
        )
        return outcome

    # ------------------------------------------------------------------
    async def _validate_native(self, plan: dict[str, Any], handle: str) -> ValidationOutcome:
        import shutil

        available = [t for t in plan.get("requires_toolchain", []) if shutil.which(t)]
        if not available:
            return ValidationOutcome(
                refutation_reason=(
                    "No C toolchain is available on this host, so the sanitizer-instrumented "
                    "build required to validate this candidate could not be produced. The "
                    "candidate is unresolved, not clean."
                ),
                detail="toolchain unavailable",
            )
        return ValidationOutcome(
            refutation_reason=(
                "Native sanitizer validation is not wired into this PoC build. Use the Python "
                "demo target for the full end-to-end path."
            ),
            detail="native path not implemented",
        )

    # ------------------------------------------------------------------
    async def _run_request(self, request: dict[str, Any], *, label: str) -> ExecResult:
        """One isolated process per attempt — that is what makes reproduction independent."""
        payload = json.dumps(request, sort_keys=True)
        containment_root = (
            str((self.workspace / self.descriptor.asset_dir).resolve())
            if self.descriptor.asset_dir
            else ""
        )
        return await self.sandbox.execute(
            ExecRequest(
                argv=self.descriptor.argv_for(payload),
                cwd=".",
                env={"KAVACHX_CONTAINMENT_ROOT": containment_root} if containment_root else {},
                label=label,
                timeout_seconds=min(60, self.sandbox.limits.wall_clock_seconds),
            )
        )

    def _plant_canary(self) -> None:
        """Place a canary outside the asset root but inside the workspace.

        Reading it proves containment failure without ever touching a real host file.
        """
        if self._canary_planted:
            return
        target = self.workspace / CANARY_FILENAME
        target.write_text(CANARY_CONTENT + "\n", encoding="utf-8")
        self._canary_planted = True

    # ------------------------------------------------------------------
    async def _attach_contract_violation(
        self, outcome: ValidationOutcome, request: dict[str, Any], plan: dict[str, Any]
    ) -> None:
        """Re-observe the exploit under tracing, then do two deterministic checks.

        1. **Contract violation.** Which surviving SAMHITA clauses are false on this trace? That
           is what makes a finding contract-grounded: not "a crash happened" but "clause C0NN,
           which survived held-out falsification, is false here".
        2. **Location consistency.** Did the exploit actually execute the function the
           hypothesis blamed? A static rule can flag ``EXPORT_ROOT / report_name`` as a
           traversal candidate, and a traversal payload against a *different* function will
           still escape containment — attributing that proof to the wrong location would be a
           false finding with real evidence attached. If the hypothesised function never ran,
           the reproduction is withdrawn and the reason recorded.
        """
        spec = {
            "project_root": ".",
            "source_root": self.descriptor.source_root,
            "entry_module": self.descriptor.entry_module,
            "entry_callable": self.descriptor.entry_callable,
            "cases": [{"id": "pov", "argv": ["--request", json.dumps(request, sort_keys=True)]}],
            "passes": 1,
        }
        spec_rel = "_kavachx/out/pov-observe-spec.json"
        out_rel = "_kavachx/out/pov-observations.json"
        (self.workspace / spec_rel).parent.mkdir(parents=True, exist_ok=True)
        (self.workspace / spec_rel).write_text(json.dumps(spec, sort_keys=True), encoding="utf-8")

        containment_root = (
            str((self.workspace / self.descriptor.asset_dir).resolve())
            if self.descriptor.asset_dir
            else ""
        )
        result = await self.sandbox.execute(
            ExecRequest(
                argv=["python", "-m", "kx_observe", "--spec", spec_rel, "--out", out_rel],
                collect_artifacts=[out_rel],
                env={"KAVACHX_CONTAINMENT_ROOT": containment_root} if containment_root else {},
                label="pov:observe",
                timeout_seconds=min(90, self.sandbox.limits.wall_clock_seconds * 2),
            )
        )
        raw = result.artifacts.get(out_rel, "")
        if not raw:
            return

        try:
            observations = parse_observations(json.loads(raw))
        except ValueError:
            return

        outcome.coverage_percent = observations.coverage_percent
        records: list[ObservationRecord] = observations.records
        executed_scopes = observations.scopes()
        outcome.evidence["pov_observation_hash"] = observations.raw_hash
        outcome.evidence["pov_executed_scopes"] = sorted(executed_scopes)

        # --- 2. location consistency -------------------------------------
        target_function = str(plan.get("target_function", ""))
        target_file = str(plan.get("target_file", ""))
        if target_function and executed_scopes:
            expected = f"{target_file}:{target_function}" if target_file else ""
            hit = expected in executed_scopes or any(
                scope.endswith(f":{target_function}") for scope in executed_scopes
            )
            if not hit:
                outcome.reproduced = False
                outcome.reproduction_count = 0
                outcome.refutation_reason = (
                    f"The payload produced the predicted effect, but {target_function} "
                    f"({target_file}) never executed. The proof does not belong to this "
                    "location, so the hypothesis is not confirmed here."
                )
                outcome.detail = "effect reproduced at a different location"
                outcome.evidence["location_consistency"] = {
                    "expected": expected or target_function,
                    "executed": sorted(executed_scopes)[:40],
                    "consistent": False,
                }
                return
            outcome.evidence["location_consistency"] = {
                "expected": expected or target_function,
                "consistent": True,
            }

        # --- 1. contract violation ---------------------------------------
        if not self.samhita.surviving:
            return

        violations: list[tuple[str, str, str]] = []
        for clause in self.samhita.surviving:
            verdict = check_clause_against_records(
                predicate=clause.predicate, scope=clause.scope, records=records
            )
            if verdict.verdict == "FALSIFIED":
                violations.append((clause.clause_id, clause.description, verdict.reason))

        if not violations:
            return

        chosen = max(
            violations,
            key=lambda v: _clause_specificity(
                self.samhita.clause_by_id(v[0]), target_file, target_function
            ),
        )
        outcome.violated_clause_id = chosen[0]
        outcome.contract_violation = f"{chosen[0]}: {chosen[1]}"[:400]
        outcome.evidence["clause_violations"] = [
            {"clause_id": cid, "description": desc, "reason": reason}
            for cid, desc, reason in violations[:8]
        ]


# ---------------------------------------------------------------------------
def _clause_specificity(clause: Any, target_file: str, target_function: str) -> int:
    """Rank violated clauses so the reported one is the most relevant, not the first found.

    A clause scoped to the offending function says far more than a global counter that also
    happens to be false, and the certificate quotes whichever one we pick here.
    """
    if clause is None:
        return 0
    scope = getattr(clause, "scope", "") or ""
    score = 0
    if target_function and scope.endswith(f":{target_function}"):
        score += 100
    if target_file and scope.split(":")[0] == target_file:
        score += 40
    if scope not in ("*", ""):
        score += 10
    # Prefer clauses that constrain the input over ones that merely count resources.
    kind = getattr(clause, "kind", "") or ""
    score += {
        "forbidden_shell_invocation": 8,
        "path_containment": 8,
        "input_length_bound": 6,
        "response_structure": 4,
        "monotonic_counter": 3,
        "nullability_assumption": 2,
        "resource_constraint": 1,
    }.get(kind, 0)
    return score


def _frames_from_stderr(stderr: str) -> list[dict[str, Any]]:
    """Parse a Python traceback into structured frames.

    Root-cause analysis needs the executed path, and the traceback is the only place the
    sandbox reports it for an out-of-process run.
    """
    frames: list[dict[str, Any]] = []
    lines = stderr.splitlines()
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.startswith('File "'):
            continue
        try:
            after_file = stripped.split('File "', 1)[1]
            path, remainder = after_file.split('"', 1)
            parts = remainder.split(",")
            line_no = int(parts[1].strip().removeprefix("line ").strip())
            function = parts[2].strip().removeprefix("in ").strip() if len(parts) > 2 else ""
        except (IndexError, ValueError):
            continue
        text = lines[index + 1].strip() if index + 1 < len(lines) else ""
        normalised = path.replace("\\", "/")
        in_project = "/_kavachx/" not in normalised and (
            "/src/" in normalised or normalised.endswith("main.py")
        )
        frames.append(
            {
                "file": _relative_project_path(normalised),
                "line": line_no,
                "function": function,
                "text": text[:300],
                "in_project": in_project,
            }
        )
    return frames


def _relative_project_path(path: str) -> str:
    """Trim an absolute sandbox path down to a workspace-relative one."""
    for marker in ("/work/", "/pristine/"):
        if marker in path:
            return path.split(marker, 1)[1]
    return path


def _project_crash_site(frames: list[dict[str, Any]]) -> str:
    for frame in reversed(frames):
        if frame.get("in_project"):
            return f"{frame['file']}:{frame['line']}"
    return ""
