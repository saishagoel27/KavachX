"""The security test synthesis engine: candidate → TestSpec → harness → executable plan.

This is the subsystem the spec asks for in §22. It receives everything the earlier stages produced
— the candidate flow, the call graph, the data flow, the source and sink, the framework, the
existing tests, the configuration and any runtime observations — and turns it into test plans that
the sandbox can execute and an oracle can judge.

The division of labour, which is the whole design:

* **The model proposes** a :class:`~app.testing.specs.TestSpec`: what to target, which inputs
  matter, which mutation families are worth trying, what property to assert. That is judgement, and
  it is what a model is genuinely good at.
* **KavachX decides everything else.** The engine (from the detected language and the toolchain
  that is actually installed), the marker values, the harness code, the argv, the timeout ceiling,
  the reproduction count.
* **A deterministic fallback always exists.** :func:`deterministic_specs` derives a usable spec
  from the flow alone. So a run with no model, an unreachable model, or a model that returns
  schema-invalid output still generates and executes real tests — the pipeline never depends on
  the proposal step working.

That last point is why this is not "LLM + patch": remove the model entirely and the system still
finds, tests, validates and repairs. The model makes it better, not possible.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.logging import get_logger
from app.llm.base import LLMRequest, LLMTask
from app.security_model.taxonomy import SinkKind, SourceKind
from app.testing import engines as engines_mod
from app.testing import harness as harness_mod
from app.testing.specs import (
    FuzzSpec,
    OracleSpec,
    TestPlan,
    TestPlanStatus,
    TestSpec,
    TestSpecProposal,
    plan_id_for,
)

logger = get_logger(__name__)

TEST_SPEC_INSTRUCTION = (
    "Propose security TESTS for one evidenced data-flow candidate.\n"
    "You are given the flow (source, sink, path, sanitizers, trust boundaries), bounded code "
    "slices of the functions on that path, the existing tests, the configuration, and what the "
    "evidence does NOT establish.\n"
    "For each test, choose: the strategy, the input source, the oracle, the concrete payloads or "
    "mutation families, and the security property the test is trying to violate.\n"
    "You are describing a testing INTENTION. You are not writing code, choosing a command, or "
    "naming a fuzzing engine — KavachX generates the harness and selects the engine.\n"
    "Do not claim anything is exploitable. Every test you propose will be executed and judged by "
    "a deterministic oracle."
)

#: Sink kind → the oracle that can actually prove it, and the CWE it belongs to.
#:
#: This mapping is the reason a generated test can be judged deterministically: each sink class has
#: an *observable* consequence, and the oracle asserts on that consequence rather than on the
#: shape of the input.
_SINK_ORACLE: dict[str, tuple[str, str, str]] = {
    # sink kind                    (oracle kind,                  marker role,  cwe)
    SinkKind.SHELL_EXEC.value: ("marker_in_stdout", "pov_marker", "CWE-78"),
    SinkKind.PROCESS_EXEC.value: ("marker_in_stdout", "pov_marker", "CWE-78"),
    SinkKind.DYNAMIC_EVAL.value: ("marker_in_stdout", "pov_marker", "CWE-95"),
    SinkKind.PATH_CONSTRUCTION.value: ("canary_content_in_stdout", "canary", "CWE-22"),
    SinkKind.FILESYSTEM.value: ("canary_content_in_stdout", "canary", "CWE-22"),
    SinkKind.DESERIALISATION.value: ("marker_in_stdout", "pov_marker", "CWE-502"),
    SinkKind.TEMPLATE_RENDER.value: ("marker_in_stdout", "pov_marker", "CWE-1336"),
    SinkKind.MEMORY_COPY.value: ("sanitizer_report", "none", "CWE-787"),
    SinkKind.MEMORY_ALLOC.value: ("sanitizer_report", "none", "CWE-789"),
    SinkKind.INDEXED_WRITE.value: ("exception_raised", "none", "CWE-1284"),
    # SQL, network, auth and crypto sinks have no *observable-from-outside* consequence in a
    # sealed sandbox with no database and no network. They get an exception oracle, which proves
    # a crash but not exploitation, and the plan says so.
    SinkKind.SQL.value: ("exception_raised", "none", "CWE-89"),
    SinkKind.NETWORK_REQUEST.value: ("exception_raised", "none", "CWE-918"),
    SinkKind.AUTH_DECISION.value: ("exception_raised", "none", "CWE-347"),
}

#: Mutation families worth trying per sink kind, for the deterministic fallback.
_SINK_MUTATIONS: dict[str, list[str]] = {
    SinkKind.SHELL_EXEC.value: ["separator_injection", "encoding_variants"],
    SinkKind.PROCESS_EXEC.value: ["separator_injection", "encoding_variants"],
    SinkKind.DYNAMIC_EVAL.value: ["separator_injection", "format_specifiers"],
    SinkKind.PATH_CONSTRUCTION.value: ["traversal_sequences", "encoding_variants"],
    SinkKind.FILESYSTEM.value: ["traversal_sequences", "encoding_variants"],
    SinkKind.DESERIALISATION.value: ["type_confusion", "structural_nesting"],
    SinkKind.TEMPLATE_RENDER.value: ["format_specifiers", "separator_injection"],
    SinkKind.MEMORY_COPY.value: ["length_escalation", "boundary_values"],
    SinkKind.MEMORY_ALLOC.value: ["large_values", "negative_numbers", "boundary_values"],
    SinkKind.INDEXED_WRITE.value: ["length_escalation", "boundary_values", "negative_numbers"],
    SinkKind.SQL.value: ["separator_injection", "encoding_variants"],
}

#: Which sink kinds cannot be *proved* exploited inside a sealed sandbox, and why. Attached to the
#: plan so the resulting evidence is never over-read.
_UNPROVABLE: dict[str, str] = {
    SinkKind.SQL.value: (
        "The sandbox has no database, so a SQL sink can be shown to crash or to receive "
        "attacker-shaped input, but not to execute injected SQL."
    ),
    SinkKind.NETWORK_REQUEST.value: (
        "The sandbox has no network interface, so an SSRF sink cannot be shown to reach anything."
    ),
    SinkKind.AUTH_DECISION.value: (
        "Proving an authentication bypass needs a full request lifecycle the harness does not "
        "reconstruct."
    ),
    SinkKind.CRYPTO.value: (
        "A weak-primitive finding is a property of the code, not an observable runtime effect."
    ),
}


@dataclass
class SynthesisResult:
    plans: list[TestPlan] = field(default_factory=list)
    #: Specs that validated but had no available engine/generator.
    unsupported: list[TestPlan] = field(default_factory=list)
    proposal_used: bool = False
    proposal_error: str = ""
    model_call: dict[str, Any] = field(default_factory=dict)
    #: The exact context the model received, for the inspection view.
    context: dict[str, Any] = field(default_factory=dict)
    tool_events: list[dict[str, Any]] = field(default_factory=list)
    duration_ms: int = 0
    notes: list[str] = field(default_factory=list)

    @property
    def executable(self) -> list[TestPlan]:
        return [p for p in self.plans if p.status == TestPlanStatus.GENERATED]

    def as_dict(self) -> dict[str, Any]:
        return {
            "plans": [p.as_dict() for p in self.plans],
            "unsupported": [p.as_dict() for p in self.unsupported],
            "executable": len(self.executable),
            "proposal_used": self.proposal_used,
            "proposal_error": self.proposal_error,
            "duration_ms": self.duration_ms,
            "notes": self.notes,
        }


class TestSynthesisEngine:
    """Turns candidates into executable, oracle-judged test plans."""

    def __init__(
        self,
        *,
        workspace: Path,
        index_id: str,
        descriptor: Any,
        code_graph: Any,
        security_graph: Any,
        provider: Any = None,
        context_builder: Any = None,
        module_checker: Any = None,
    ) -> None:
        self.workspace = workspace
        self.index_id = index_id
        self.descriptor = descriptor
        self.code_graph = code_graph
        self.security_graph = security_graph
        self.provider = provider
        self.context_builder = context_builder
        self.module_checker = module_checker

    # ------------------------------------------------------------------
    async def synthesise(
        self,
        flow: Any,
        *,
        finding_handle: str = "",
        max_specs: int = 3,
    ) -> SynthesisResult:
        """Produce test plans for one security flow."""
        started = time.perf_counter()
        result = SynthesisResult()

        # 1. Deterministic specs first, so there is always something to run.
        specs = deterministic_specs(
            flow, descriptor=self.descriptor, security_graph=self.security_graph
        )
        result.notes.append(
            f"{len(specs)} spec(s) derived deterministically from the flow's sink class."
        )

        # 2. Ask the model for more, if one is configured. Additive, never replacing.
        if self.provider is not None and self.context_builder is not None:
            proposed, error, call, context = await self._propose(flow)
            result.proposal_error = error
            result.model_call = call
            result.context = context
            if proposed:
                result.proposal_used = True
                # Model specs go after the deterministic ones: if the per-candidate cap bites, the
                # test KavachX knows how to judge survives.
                specs.extend(proposed)
                result.notes.append(f"{len(proposed)} additional spec(s) proposed by the model.")
            elif error:
                result.notes.append(f"Model proposal unavailable: {error[:200]}")

        # 3. Deduplicate and cap.
        seen: set[str] = set()
        unique: list[TestSpec] = []
        for spec in specs:
            key = f"{spec.strategy}|{spec.target}|{spec.oracle.kind}|{sorted(spec.payloads)}"
            if key in seen:
                continue
            seen.add(key)
            unique.append(spec)
        if len(unique) > max_specs:
            result.notes.append(
                f"{len(unique) - max_specs} spec(s) dropped by the per-candidate cap "
                f"({max_specs}); they are not reported as having passed."
            )
            unique = unique[:max_specs]

        # 4. Engine selection + harness generation.
        language = getattr(self.descriptor, "language", "") or "python"
        for spec in unique:
            plan = TestPlan(
                spec=spec,
                plan_id=plan_id_for(spec, index_id=self.index_id),
                candidate_ref=flow.ref,
                finding_handle=finding_handle,
                language=language,
                provenance={
                    "flow_ref": flow.ref,
                    "flow_basis": flow.basis,
                    "flow_precision": flow.precision,
                    "flow_confidence": flow.confidence,
                    "source_kind": flow.source_kind,
                    "sink_kind": flow.sink_kind,
                    "entrypoint": flow.entrypoint,
                    "reachable": flow.reachable_from_entrypoint,
                    "index_id": self.index_id,
                },
            )
            unprovable = _UNPROVABLE.get(flow.sink_kind)
            if unprovable:
                plan.notes.append(
                    "LIMIT: " + unprovable + " A firing oracle here proves a crash or an "
                    "observable effect, not exploitation."
                )

            selection = engines_mod.select(
                language=language, strategy=spec.strategy, module_checker=self.module_checker
            )
            if not selection.ok:
                plan.status = TestPlanStatus.UNSUPPORTED
                plan.engine_reason = selection.unavailable_reason
                plan.notes.append(selection.unavailable_reason)
                result.unsupported.append(plan)
                result.plans.append(plan)
                continue

            plan.engine = selection.chosen.engine.id
            plan.engine_available = True
            plan.engine_reason = selection.chosen.engine.notes

            generated = harness_mod.generate(
                plan, workspace=self.workspace, descriptor=self.descriptor
            )
            harness_mod.attach(plan, generated)
            if generated.ok:
                result.tool_events.append(
                    {
                        "name": f"harness:{plan.engine}",
                        "target": generated.path,
                        "ms": 0,
                        "ok": True,
                        "detail": (
                            f"{spec.strategy} harness, oracle {spec.oracle.kind}, "
                            f"sha256:{generated.sha256[:12]}"
                        ),
                    }
                )
            else:
                result.unsupported.append(plan)
            result.plans.append(plan)

        result.duration_ms = int((time.perf_counter() - started) * 1000)
        logger.info(
            "testing.synthesised",
            candidate=flow.ref,
            specs=len(unique),
            executable=len(result.executable),
            unsupported=len(result.unsupported),
            proposal_used=result.proposal_used,
            ms=result.duration_ms,
        )
        return result

    # ------------------------------------------------------------------
    async def _propose(
        self, flow: Any
    ) -> tuple[list[TestSpec], str, dict[str, Any], dict[str, Any]]:
        """Ask the model for extra specs over a bounded context."""
        try:
            context = self.context_builder.for_flow(flow, task=LLMTask.TEST_SPEC)
        except Exception as exc:  # pragma: no cover - context assembly must not kill the run
            return [], f"context assembly failed: {type(exc).__name__}: {exc}", {}, {}

        try:
            response = await self.provider.generate(
                LLMRequest(
                    task=LLMTask.TEST_SPEC,
                    instruction=TEST_SPEC_INSTRUCTION,
                    payload=context.payload(),
                    schema=TestSpecProposal,
                    model_hint="security",
                )
            )
        except Exception as exc:
            return [], f"{type(exc).__name__}: {str(exc)[:300]}", {}, context.as_dict()

        record = context.as_dict()
        record["provider"] = response.provider
        record["model"] = response.model
        # Schema validation already happened in the provider. Anything that reaches here is a
        # well-formed TestSpec; what it *says* is still only a proposal.
        return list(response.parsed.specs), "", response.evidence_payload(), record


# ---------------------------------------------------------------------------
def deterministic_specs(
    flow: Any,
    *,
    descriptor: Any,
    security_graph: Any,
    max_specs: int = 3,
) -> list[TestSpec]:
    """Derive test specs from a flow with no model involved.

    This is the floor of the system's capability. Everything it produces is judged by the same
    oracles as a model-proposed spec, so a run with ``LLM_PROVIDER=mock`` — or with no model
    reachable at all — still generates real, executable, deterministically-judged security tests.
    """
    sink_node = security_graph.nodes.get(flow.sink_ref)
    if sink_node is None:
        return []

    oracle_kind, marker_role, cwe = _SINK_ORACLE.get(
        flow.sink_kind, ("exception_raised", "none", flow.cwe or "")
    )
    target = sink_node.owner or sink_node.file
    entrypoint = flow.entrypoint or getattr(descriptor, "entry_callable", "") or ""
    field_name, template = _request_shape(flow, descriptor)
    property_text = _property_text(flow, sink_node)

    specs: list[TestSpec] = []

    # 1. A mutation spec: the primary prover. Concrete payload families chosen from the sink class.
    mutations = _SINK_MUTATIONS.get(flow.sink_kind, ["boundary_values", "encoding_variants"])
    base_payload = _base_payload(flow, descriptor)
    try:
        specs.append(
            TestSpec(
                target=target,
                entrypoint=entrypoint,
                input_source=_input_source(flow, descriptor),
                strategy="mutation",
                oracle=OracleSpec(
                    kind=oracle_kind,
                    marker_role=marker_role,
                    description=f"Deterministic oracle for a {flow.sink_kind} sink.",
                ),
                expected_security_property=property_text,
                payloads=[base_payload],
                request_template=template,
                payload_field=field_name,
                cwe=cwe or flow.cwe,
                rationale=(
                    f"Derived from flow {flow.ref}: {flow.source_kind} reaches {flow.sink_kind} "
                    f"at {sink_node.location} (basis {flow.basis}, precision {flow.precision})."
                ),
                fuzz=FuzzSpec(
                    seeds=[base_payload],
                    mutations=mutations,
                    max_iterations=200,
                    stop_on_first_signal=True,
                ),
                reproductions_required=2,
            )
        )
    except Exception as exc:  # pragma: no cover - our own construction must be valid
        logger.warning("testing.deterministic_spec_invalid", error=str(exc)[:200])

    # A regression spec is deliberately NOT generated here.
    #
    # Regression means "the input that actually reproduced this must never reproduce it again", and
    # before validation there is no such input — only the benign base value the mutation operators
    # start from. A regression test seeded with a benign payload asserts nothing: it passes on the
    # unpatched build, which is the opposite of what a regression guard is for. Observed directly on
    # the seeded demo target: the pre-validation regression harness reported HELD against a target
    # with a live, reproducible command injection.
    #
    # Regression plans are built after validation by
    # :func:`app.testing.regression.plan_from_finding`, from the reproduction record.

    # 2. A property spec for boundary-shaped sinks, where an invariant is the natural assertion.
    if flow.sink_kind in (
        SinkKind.INDEXED_WRITE.value,
        SinkKind.MEMORY_COPY.value,
        SinkKind.MEMORY_ALLOC.value,
    ):
        try:
            specs.append(
                TestSpec(
                    target=target,
                    entrypoint=entrypoint,
                    input_source=_input_source(flow, descriptor),
                    strategy="property",
                    oracle=OracleSpec(
                        kind="exception_raised",
                        description="The invariant must hold across generated inputs.",
                    ),
                    expected_security_property=(
                        "The target must not crash on any input length, however large."
                    ),
                    # A pure boolean over the harness namespace; compiled by the SAMHITA
                    # restricted-AST whitelist before the harness is written.
                    property_expression="crashed == 0",
                    request_template=template,
                    payload_field=field_name,
                    cwe=cwe or flow.cwe,
                    rationale="Boundary-shaped sink: an invariant generalises better than payloads.",
                    fuzz=FuzzSpec(mutations=["length_escalation"], max_iterations=200),
                )
            )
        except Exception as exc:  # pragma: no cover
            logger.warning("testing.property_spec_invalid", error=str(exc)[:200])

    return specs[:max_specs]


def _input_source(flow: Any, descriptor: Any) -> str:
    """Which interface the harness drives, from the flow's own source kind."""
    if flow.source_kind in (
        SourceKind.HTTP_PARAM.value,
        SourceKind.HTTP_BODY.value,
        SourceKind.HTTP_HEADER.value,
        SourceKind.HTTP_COOKIE.value,
        SourceKind.HTTP_PATH.value,
        SourceKind.UPLOADED_FILE.value,
    ):
        return "http_request"
    if flow.source_kind == SourceKind.STDIN.value:
        return "cli_stdin"
    if flow.source_kind == SourceKind.ENV_VAR.value:
        return "environment_variable"
    if flow.source_kind == SourceKind.FILE_READ.value:
        return "file_content"
    if getattr(descriptor, "entry_callable", ""):
        return "cli_argument"
    return "function_argument"


def _request_shape(flow: Any, descriptor: Any) -> tuple[str, dict[str, Any]]:
    """The request template and payload field for this target's interface.

    Derived from the sink class rather than guessed: an export-shaped sink takes a name, a path
    sink takes a path, a parse sink takes a body. The demo target's own request vocabulary
    (``op``/``name``/``path``/``headers``) is used where it matches, because that is the interface
    the confirmed descriptor actually drives.
    """
    if flow.sink_kind in (SinkKind.PATH_CONSTRUCTION.value, SinkKind.FILESYSTEM.value):
        return "path", {"op": "asset"}
    if flow.sink_kind in (SinkKind.SHELL_EXEC.value, SinkKind.PROCESS_EXEC.value):
        return "name", {"op": "export", "format": "txt"}
    if flow.sink_kind == SinkKind.INDEXED_WRITE.value:
        return "headers", {"op": "parse"}
    if flow.sink_kind == SinkKind.DESERIALISATION.value:
        return "body", {"op": "parse"}
    return "value", {}


def _base_payload(flow: Any, descriptor: Any) -> str:
    """A benign starting value for mutation. Benign on purpose: the mutation operators add the
    attack, and starting from a value the target accepts is what makes the mutated variant reach
    the sink rather than being rejected at the door."""
    if flow.sink_kind in (SinkKind.PATH_CONSTRUCTION.value, SinkKind.FILESYSTEM.value):
        return "report.tmpl"
    if flow.sink_kind == SinkKind.INDEXED_WRITE.value:
        return "h0:0"
    return "kavachx-probe"


def _property_text(flow: Any, sink_node: Any) -> str:
    """The security property the test tries to violate, in one line."""
    return (
        f"{flow.source_kind} must not reach the {flow.sink_kind} operation at "
        f"{sink_node.location} in a form that changes its behaviour"
        + (f" (sanitizers on path: {', '.join(flow.sanitizers)})" if flow.sanitizers else "")
    )
