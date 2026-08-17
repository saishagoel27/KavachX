"""Channel 1 — graph / static.

Semgrep and the built-in AST rules produce raw candidates. The World Model then supplies
reachability (is there a path from an entrypoint?), caller count and blast radius, and the
model triages severity and weakness class. Finally a **validation plan** is attached
deterministically from the rule id — the model never authors the plan, because the plan is what
gets executed.
"""

from __future__ import annotations

import time
from typing import Any

from app.analysis.scanner import RawFinding, scan
from app.analysis.world_model import WorldModel
from app.core.logging import get_logger
from app.discovery.base import (
    CANARY_FILENAME,
    POV_MARKER,
    ChannelResult,
    HypothesisCandidate,
)
from app.llm.base import LLMProvider, LLMRequest, LLMTask
from app.llm.contracts import TriageProposal
from app.models.enums import DiscoveryChannel, Severity
from app.samhita.engine import SamhitaResult

logger = get_logger(__name__)

TRIAGE_INSTRUCTION = (
    "Triage static-analysis candidates for a security run.\n"
    "For each raw candidate assign a severity, the CWE if you recognise the weakness class, "
    "the kind of behavioural clause it would violate, and a confidence.\n"
    "You are triaging only. Do not claim any candidate is exploitable — a separate "
    "deterministic validator decides that by executing it."
)

#: rule id -> (plan kind, cwe, clause kind). The plan is what makes a candidate testable.
_PLAN_BY_RULE: dict[str, tuple[str, str, str]] = {
    "kavachx.python.shell-injection": ("command_injection", "CWE-78", "forbidden_shell_invocation"),
    "kavachx.python.subprocess-shell-true": (
        "command_injection",
        "CWE-78",
        "forbidden_shell_invocation",
    ),
    "kavachx.python.unbounded-index-write": ("length_boundary", "CWE-1284", "input_length_bound"),
    "kavachx.python.path-traversal": ("path_traversal", "CWE-22", "path_containment"),
    "kavachx.python.eval-exec": ("command_injection", "CWE-95", "forbidden_shell_invocation"),
    "kavachx.python.debug-enabled": ("config_exposure", "CWE-489", "response_structure"),
    "kavachx.python.bind-all-interfaces": ("config_exposure", "CWE-1327", "resource_constraint"),
    "kavachx.c.unbounded-memcpy": ("native_crash", "CWE-787", "input_length_bound"),
    # Real-world classes. None has an executable plan against an arbitrary target, so each is
    # reported as an unproven hypothesis with a stated reason rather than a confirmed finding.
    "kavachx.python.sql-injection": ("", "CWE-89", "response_structure"),
    "kavachx.python.insecure-deserialisation": ("", "CWE-502", "forbidden_shell_invocation"),
    "kavachx.python.tls-verification-disabled": ("", "CWE-295", "resource_constraint"),
    "kavachx.python.debug-server": ("", "CWE-489", "response_structure"),
    "kavachx.python.template-injection": ("", "CWE-1336", "forbidden_shell_invocation"),
    "kavachx.python.hardcoded-secret": ("", "CWE-798", "response_structure"),
}

#: Severity for rules that carry no executable plan. Without this they would all default to MEDIUM,
#: which would bury a hardcoded credential underneath a disabled TLS check.
_SEVERITY_BY_RULE: dict[str, str] = {
    "kavachx.python.sql-injection": Severity.CRITICAL.value,
    "kavachx.python.insecure-deserialisation": Severity.CRITICAL.value,
    "kavachx.python.template-injection": Severity.CRITICAL.value,
    "kavachx.python.hardcoded-secret": Severity.HIGH.value,
    "kavachx.python.tls-verification-disabled": Severity.HIGH.value,
    "kavachx.python.debug-server": Severity.HIGH.value,
}


async def run(
    *,
    model: WorldModel,
    provider: LLMProvider,
    samhita: SamhitaResult,
    descriptor: Any,
) -> ChannelResult:
    started = time.perf_counter()
    result = ChannelResult(channel=DiscoveryChannel.GRAPH_STATIC.value)

    scan_started = time.perf_counter()
    raw, scan_meta = await scan(model.root)
    result.tool_events.append(
        {
            "name": "semgrep" if "semgrep" in scan_meta["engines"] else "builtin-ast-rules",
            "target": f"{len(model.files)} files",
            "ms": int((time.perf_counter() - scan_started) * 1000),
            "ok": True,
            "detail": f"{len(raw)} raw candidates from {', '.join(scan_meta['engines'])}",
        }
    )
    result.coverage_notes.append(
        f"static engines: {', '.join(scan_meta['engines'])}"
        + ("" if scan_meta["semgrep_available"] else " (semgrep not installed on this host)")
    )
    if not raw:
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        return result

    enriched = [_enrich(finding, model) for finding in raw]

    triaged: dict[str, dict[str, Any]] = {}
    try:
        response = await provider.generate(
            LLMRequest(
                task=LLMTask.STATIC_TRIAGE,
                instruction=TRIAGE_INSTRUCTION,
                payload={"raw_findings": enriched},
                schema=TriageProposal,
                model_hint="security",
            )
        )
        result.model_calls.append(response.evidence_payload())
        for candidate in response.parsed.candidates:
            triaged[f"{candidate.rule_id}@{candidate.location}"] = candidate.model_dump()
    except Exception as exc:
        # Triage is advisory. Losing it costs us severity nuance, not the candidates.
        logger.warning("discovery.static.triage_failed", error=str(exc)[:300])
        result.coverage_notes.append(f"model triage unavailable ({str(exc)[:120]})")

    for counter, (finding, payload) in enumerate(zip(raw, enriched, strict=True), start=1):
        key = f"{finding.rule_id}@{finding.location}"
        triage = triaged.get(key, {})

        plan_kind, cwe, clause_kind = _PLAN_BY_RULE.get(finding.rule_id, ("", "", ""))
        cwe = cwe or str(triage.get("cwe", ""))
        severity = str(
            _SEVERITY_BY_RULE.get(finding.rule_id)
            or triage.get("severity")
            or _default_severity(plan_kind)
        )
        confidence = float(triage.get("confidence", 0.5))

        reachable = bool(payload["reachable_from_entrypoint"])
        reachability = float(payload["reachability_score"])
        blast = float(payload["blast_radius_score"])
        # With no entrypoint in the world model there is no path to search, so the score above is a
        # floor applied uniformly rather than a measurement of this candidate. Flag it so the
        # priority formula substitutes severity instead of ranking every code finding identically.
        reachability_measured = bool(model.entrypoints)

        clause_id = _match_clause(samhita, finding, clause_kind)
        plan = _build_plan(plan_kind, finding, model, descriptor)

        candidate = HypothesisCandidate(
            handle=f"H{counter:03d}",
            source_channel=DiscoveryChannel.GRAPH_STATIC.value,
            description=finding.message,
            location=finding.location,
            severity=severity,
            reachability=reachability,
            reachability_measured=reachability_measured,
            confidence=confidence,
            blast_radius=blast,
            cwe=cwe,
            candidate_clause_id=clause_id,
            rule_id=finding.rule_id,
            evidence_refs=[f"ev:code:{finding.location}"],
            validation_plan=plan,
            unknown_reason=""
            if plan
            else (
                f"No executable validation plan exists for rule {finding.rule_id}. The candidate "
                "is recorded with its evidence, but KavachX did not reproduce it — treat it as a "
                "lead for human review, not as a confirmed vulnerability."
                + (
                    ""
                    if reachability_measured
                    else " Reachability was not measured: this target has no entrypoint, so no "
                    "call path could be searched. The queue position reflects severity, not "
                    "proven exposure."
                )
            ),
            hypothesis_statement=finding.message,
            decision="Candidate queued for deterministic validation."
            if plan
            else "Recorded in the unknown ledger — not executable.",
        )
        result.candidates.append(candidate)

        result.thoughts.append(
            {
                "agent": "GRAPH / STATIC",
                "hypothesis": finding.message[:400],
                "evidence": [
                    finding.location,
                    f"caller count: {payload['caller_count']}",
                    "reachable from entrypoint"
                    if reachable
                    else "no path from a declared entrypoint",
                    f"rule: {finding.rule_id}",
                ],
                "decision": (
                    f"Candidate violation generated ({candidate.handle}); plan={plan_kind or 'none'}"
                ),
                "confidence": confidence,
            }
        )

    result.duration_ms = int((time.perf_counter() - started) * 1000)
    logger.info(
        "discovery.static.complete",
        candidates=len(result.candidates),
        duration_ms=result.duration_ms,
    )
    return result


# ---------------------------------------------------------------------------
def _enrich(finding: RawFinding, model: WorldModel) -> dict[str, Any]:
    symbol = model.symbol_at(finding.file, finding.line)
    handle = symbol.handle if symbol else ""
    reachable, path = model.reachable_from_entrypoint(handle) if handle else (False, [])
    return {
        **finding.as_dict(),
        "symbol_handle": handle,
        "caller_count": model.caller_count(handle) if handle else 0,
        "reachable_from_entrypoint": reachable,
        "reachability_score": model.reachability_score(handle) if handle else 0.05,
        "blast_radius_score": model.blast_radius_score(handle) if handle else 0.2,
        "entrypoint_path": path,
    }


def _default_severity(plan_kind: str) -> str:
    return {
        "command_injection": Severity.CRITICAL.value,
        "native_crash": Severity.CRITICAL.value,
        "length_boundary": Severity.HIGH.value,
        "path_traversal": Severity.HIGH.value,
        "config_exposure": Severity.MEDIUM.value,
    }.get(plan_kind, Severity.MEDIUM.value)


def _match_clause(samhita: SamhitaResult, finding: RawFinding, clause_kind: str) -> str:
    """Find a surviving clause this candidate plausibly violates.

    Preference order: a clause scoped to the *same function*, then the same file, then any
    surviving clause of the right kind. Only surviving clauses are eligible — a falsified
    clause is not evidence of anything.
    """
    if not clause_kind:
        return ""
    candidates = [c for c in samhita.surviving if c.kind == clause_kind]
    if not candidates:
        return ""

    function_scope = ""
    for clause in candidates:
        if ":" in clause.scope and clause.scope.split(":")[0] == finding.file:
            function_scope = clause.clause_id
            if finding.function and clause.scope.endswith(f":{finding.function}"):
                return clause.clause_id
    return function_scope or candidates[0].clause_id


def _build_plan(
    plan_kind: str, finding: RawFinding, model: WorldModel, descriptor: Any
) -> dict[str, Any]:
    """Attach the executable recipe. Deterministic — derived from the rule, not the model."""
    if not plan_kind:
        return {}

    base: dict[str, Any] = {
        "kind": plan_kind,
        "target_file": finding.file,
        "target_line": finding.line,
        "target_function": finding.function,
        "reproductions_required": 2,
    }

    if plan_kind == "command_injection":
        return {
            **base,
            "operation": "export",
            "field": "name",
            "base_value": "kavachx-probe",
            "marker": POV_MARKER,
            "separators": ["&", ";", "|", "&&", "\n"],
            "success_signal": "marker_in_stdout",
        }
    if plan_kind == "length_boundary":
        return {
            **base,
            "operation": "parse",
            "field": "headers",
            "escalation": [8, 9, 12, 20, 64, 256],
            "success_signal": "nonzero_exit_or_sanitizer",
        }
    if plan_kind == "path_traversal":
        return {
            **base,
            "operation": "asset",
            "field": "path",
            "canary_filename": CANARY_FILENAME,
            "payloads": [
                f"../{CANARY_FILENAME}",
                f"..\\{CANARY_FILENAME}",
                f"a/../../{CANARY_FILENAME}",
                f"./../{CANARY_FILENAME}",
            ],
            "success_signal": "canary_content_in_stdout",
        }
    if plan_kind == "config_exposure":
        # Genuinely not executable against this target: the flag changes error verbosity, and
        # nothing the CLI exposes distinguishes it. Recorded honestly rather than faked.
        return {}
    if plan_kind == "native_crash":
        return {
            **base,
            "requires_toolchain": ["clang", "gcc"],
            "sanitizers": ["address", "undefined"],
            "success_signal": "sanitizer_report",
        }
    return {}
