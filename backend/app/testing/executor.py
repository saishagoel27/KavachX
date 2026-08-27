"""Executing generated harnesses in the sandbox, and judging them with oracles.

This is the ``EXECUTE`` stage. It takes a :class:`~app.testing.specs.TestPlan` whose harness has
been generated, runs it inside the sandbox the requested number of independent times, and applies
the plan's oracle to each result.

Three invariants, all of which exist because this is the step that produces the evidence a
certificate is built on:

* **The sandbox is entered through the existing adapter, unchanged.** No new execution path, no
  relaxed limits, no extra capability. A generated harness runs under exactly the same isolation,
  environment allowlist and resource ceilings as everything else KavachX executes. If a harness
  needs something the sandbox denies, the harness does not run and that is recorded.
* **Reproductions are independent.** Each attempt is a separate ``execute()`` call, therefore a
  separate process. One firing is not a reproduction; ``reproductions_required`` firings in
  separate processes is.
* **The oracle decides, and its verdict is recorded verbatim.** Nothing here interprets output.
  :mod:`app.testing.oracles` returns FIRED / HELD / UNSUPPORTED and the execution record carries
  it plus the observable that decided it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.hashing import sha256_json, sha256_text
from app.core.logging import get_logger
from app.sandbox.base import ExecRequest, ExecResult, SandboxAdapter
from app.testing import oracles as oracles_mod
from app.testing.coverage import CoverageObservation, from_observation_set, unmeasured
from app.testing.specs import TestPlan, TestPlanStatus

logger = get_logger(__name__)


@dataclass
class Attempt:
    """One independent execution of a harness."""

    index: int
    exit_code: int | None = None
    timed_out: bool = False
    duration_ms: int = 0
    signals: list[str] = field(default_factory=list)
    stdout_hash: str = ""
    stderr_hash: str = ""
    output_hash: str = ""
    peak_ram_mb: int = 0
    cpu_seconds: float = 0.0
    egress_bytes: int = 0
    oracle: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "duration_ms": self.duration_ms,
            "signals": self.signals,
            "stdout_hash": self.stdout_hash,
            "stderr_hash": self.stderr_hash,
            "output_hash": self.output_hash,
            "peak_ram_mb": self.peak_ram_mb,
            "cpu_seconds": self.cpu_seconds,
            "egress_bytes": self.egress_bytes,
            "oracle": self.oracle,
        }


@dataclass
class TestExecution:
    """The complete, reproducible record of running one test plan.

    This is what the spec's §30 list asks a validator to record: the input, the environment, the
    commit, the harness, the command, exit codes, output hashes, sanitizer output, coverage,
    duration, resource usage and reproduction count.
    """

    plan_id: str = ""
    candidate_ref: str = ""
    finding_handle: str = ""
    strategy: str = ""
    engine: str = ""
    #: Workspace-relative harness path plus its content hash — the test is identified, not described.
    harness_path: str = ""
    harness_sha256: str = ""
    command: list[str] = field(default_factory=list)
    #: The pinned tree the test ran against.
    commit_sha: str = ""
    index_id: str = ""
    #: Sandbox adapter + capability snapshot at execution time.
    environment: dict[str, Any] = field(default_factory=dict)
    attempts: list[Attempt] = field(default_factory=list)
    reproduced: bool = False
    reproduction_count: int = 0
    reproductions_required: int = 2
    verdict_detail: str = ""
    #: The oracle's evidence from the first firing attempt — what actually proved it.
    proving_evidence: str = ""
    coverage: dict[str, Any] = field(default_factory=dict)
    #: Files the harness produced, read back out of the sandbox.
    artifacts: dict[str, str] = field(default_factory=dict)
    error: str = ""
    duration_ms: int = 0
    tool_events: list[dict[str, Any]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.error

    def input_hash(self) -> str:
        """Digest of what was fed in. Part of the reproduction record."""
        return sha256_json({"command": self.command, "harness": self.harness_sha256})

    def as_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "candidate_ref": self.candidate_ref,
            "finding_handle": self.finding_handle,
            "strategy": self.strategy,
            "engine": self.engine,
            "harness_path": self.harness_path,
            "harness_sha256": self.harness_sha256,
            "command": self.command,
            "commit_sha": self.commit_sha,
            "index_id": self.index_id,
            "environment": self.environment,
            "input_hash": self.input_hash(),
            "attempts": [a.as_dict() for a in self.attempts],
            "reproduced": self.reproduced,
            "reproduction_count": self.reproduction_count,
            "reproductions_required": self.reproductions_required,
            "verdict_detail": self.verdict_detail,
            "proving_evidence": self.proving_evidence,
            "coverage": self.coverage,
            "artifact_names": sorted(self.artifacts.keys()),
            "error": self.error,
            "duration_ms": self.duration_ms,
        }


class TestExecutor:
    """Runs test plans in the sandbox and judges them."""

    def __init__(
        self,
        *,
        sandbox: SandboxAdapter,
        workspace: Path,
        commit_sha: str = "",
        index_id: str = "",
        descriptor: Any = None,
    ) -> None:
        self.sandbox = sandbox
        self.workspace = workspace
        self.commit_sha = commit_sha
        self.index_id = index_id
        self.descriptor = descriptor

    # ------------------------------------------------------------------
    async def execute(
        self,
        plan: TestPlan,
        *,
        baseline: ExecResult | None = None,
        collect_coverage: bool = True,
    ) -> TestExecution:
        """Run one plan to a verdict."""
        started = time.perf_counter()
        record = TestExecution(
            plan_id=plan.plan_id,
            candidate_ref=plan.candidate_ref,
            finding_handle=plan.finding_handle,
            strategy=plan.spec.strategy,
            engine=plan.engine,
            harness_path=plan.harness_path,
            harness_sha256=plan.harness_sha256,
            command=list(plan.command),
            commit_sha=self.commit_sha,
            index_id=self.index_id,
            reproductions_required=plan.spec.reproductions_required,
            environment=self._environment(),
        )

        if plan.status != TestPlanStatus.GENERATED or not plan.command:
            record.error = (
                f"plan {plan.plan_id[:12]} has no generated harness "
                f"(status {plan.status}); it did NOT run."
            )
            record.duration_ms = int((time.perf_counter() - started) * 1000)
            return record

        # The harness must exist on disk in the workspace the sandbox is bound to. Checking here
        # turns a confusing in-sandbox ImportError into a clear precondition failure.
        if not (self.workspace / plan.harness_path).is_file():
            record.error = (
                f"harness {plan.harness_path} is not present in the workspace; it did NOT run. "
                "A gauntlet workspace reset may have removed it."
            )
            record.duration_ms = int((time.perf_counter() - started) * 1000)
            return record

        oracle_results: list[oracles_mod.OracleResult] = []
        timeout = max(1, min(plan.spec.timeout_ms // 1000, self.sandbox.limits.wall_clock_seconds))

        for index in range(plan.spec.reproductions_required):
            try:
                result = await self.sandbox.execute(
                    ExecRequest(
                        argv=list(plan.command),
                        cwd=".",
                        # The harness reads markers from constants baked into its own source, so
                        # nothing sensitive or variable needs to cross into the environment.
                        env={},
                        collect_artifacts=list(
                            _artifact_paths(plan)
                        ),
                        label=f"test:{plan.spec.strategy}:{plan.plan_id[:8]}:{index}",
                        timeout_seconds=timeout,
                    )
                )
            except Exception as exc:
                record.error = f"sandbox execution failed: {type(exc).__name__}: {str(exc)[:300]}"
                break

            verdict = oracles_mod.evaluate(
                plan.spec.oracle,
                result,
                baseline=baseline,
                markers=plan.markers,
            )
            oracle_results.append(verdict)
            record.attempts.append(
                Attempt(
                    index=index,
                    exit_code=result.exit_code,
                    timed_out=result.timed_out,
                    duration_ms=result.duration_ms,
                    signals=list(result.signals),
                    stdout_hash=sha256_text(result.stdout),
                    stderr_hash=sha256_text(result.stderr),
                    output_hash=result.output_hash(),
                    peak_ram_mb=result.peak_ram_mb,
                    cpu_seconds=result.cpu_seconds,
                    egress_bytes=result.egress_bytes,
                    oracle=verdict.as_dict(),
                )
            )
            record.artifacts.update(result.artifacts)

            # Stop early only when the oracle did NOT fire: a non-firing attempt means the
            # required consecutive reproductions cannot be reached, so further attempts are waste.
            if not verdict.fired:
                break

        if oracle_results and not record.error:
            reproduced, detail = oracles_mod.require_reproductions(
                oracle_results, required=plan.spec.reproductions_required
            )
            record.reproduced = reproduced
            record.reproduction_count = len([r for r in oracle_results if r.fired])
            record.verdict_detail = detail
            firing = next((r for r in oracle_results if r.fired), None)
            if firing is not None:
                record.proving_evidence = f"{firing.kind}: {firing.evidence} — {firing.detail}"

        if collect_coverage:
            record.coverage = (await self._coverage(plan)).as_dict()
        else:
            record.coverage = unmeasured("Coverage collection was not requested.").as_dict()

        record.duration_ms = int((time.perf_counter() - started) * 1000)
        record.tool_events.append(
            {
                "name": f"test:{plan.engine}",
                "target": plan.harness_path,
                "ms": record.duration_ms,
                "ok": record.reproduced,
                "detail": record.verdict_detail or record.error,
            }
        )
        logger.info(
            "testing.executed",
            plan=plan.plan_id[:12],
            strategy=plan.spec.strategy,
            engine=plan.engine,
            reproduced=record.reproduced,
            attempts=len(record.attempts),
            ms=record.duration_ms,
        )
        return record

    # ------------------------------------------------------------------
    async def _coverage(self, plan: TestPlan) -> CoverageObservation:
        """Measure coverage over the harness's own execution, through the existing tracer.

        Reuses ``kx_observe`` rather than adding a second instrumentation path: two coverage
        numbers for one run that disagree would be worse than one number with stated limits.
        """
        if self.descriptor is None or not getattr(self.descriptor, "entry_module", ""):
            return unmeasured(
                "No confirmed entry module, so the in-process tracer cannot be pointed at "
                "anything."
            )
        payloads = plan.spec.payloads or [""]
        request = dict(plan.spec.request_template)
        if plan.spec.payload_field and payloads:
            request[plan.spec.payload_field] = payloads[0]
        if not request:
            return unmeasured("The plan carries no request to observe.")

        import json as _json

        spec_rel = f"_kavachx/out/cov-{plan.plan_id[:12]}-spec.json"
        out_rel = f"_kavachx/out/cov-{plan.plan_id[:12]}.json"
        document = {
            "project_root": ".",
            "source_root": getattr(self.descriptor, "source_root", "."),
            "entry_module": getattr(self.descriptor, "entry_module", ""),
            "entry_callable": getattr(self.descriptor, "entry_callable", ""),
            "cases": [
                {"id": "cov", "argv": ["--request", _json.dumps(request, sort_keys=True)]}
            ],
            "passes": 1,
        }
        path = self.workspace / spec_rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_json.dumps(document, sort_keys=True), encoding="utf-8")

        try:
            result = await self.sandbox.execute(
                ExecRequest(
                    argv=["python", "-m", "kx_observe", "--spec", spec_rel, "--out", out_rel],
                    collect_artifacts=[out_rel],
                    label=f"coverage:{plan.plan_id[:8]}",
                    timeout_seconds=min(90, self.sandbox.limits.wall_clock_seconds * 2),
                )
            )
        except Exception as exc:
            return unmeasured(f"coverage run failed: {type(exc).__name__}: {str(exc)[:200]}")

        raw = result.artifacts.get(out_rel, "")
        if not raw:
            return unmeasured(
                "The tracer produced no observation file, so coverage was not measured for this "
                "test."
            )
        try:
            from app.samhita.observation import parse_observations

            return from_observation_set(parse_observations(_json.loads(raw)))
        except (ValueError, KeyError) as exc:
            return unmeasured(f"observation file could not be parsed: {str(exc)[:160]}")

    def _environment(self) -> dict[str, Any]:
        """The execution environment, as evidence.

        Includes the adapter's honest capability flags: a reproduction recorded under the dev
        adapter and one recorded under gVisor are not equally strong, and the certificate has to be
        able to tell them apart.
        """
        capabilities = self.sandbox.capabilities()
        return {
            "adapter": capabilities.adapter,
            "isolation_model": capabilities.isolation_model,
            "network_enforced": capabilities.network_enforced,
            "suitable_for_untrusted_code": capabilities.suitable_for_untrusted_code,
            "limits": self.sandbox.limits.as_dict(),
            "session_id": self.sandbox.session_id,
        }


def _artifact_paths(plan: TestPlan) -> list[str]:
    """Files this plan's harness is expected to write."""
    from app.testing.harness import HARNESS_DIR

    stem = f"kx_{plan.spec.strategy}_{plan.plan_id[:12]}"
    return [f"{HARNESS_DIR}/out/{stem}.json"]
