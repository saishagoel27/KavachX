"""Channel 4 — runtime.

Looks at what the target *actually did* while the benign workload ran, using the observation
traces SAMHITA already collected plus the guard counters. Native targets additionally get
ASan/UBSan builds when a toolchain exists.

The distinctive value of this channel is that it reports behaviour, not shapes. "This function
spawned a shell with an argument that came from its caller" is a runtime fact; the static
channel can only say "there is a ``shell=True`` here". When both channels flag the same site the
correlation step raises confidence, and when only this one does, the behaviour is still on record.
"""

from __future__ import annotations

import shutil
import time

from app.analysis.probe import TargetDescriptor
from app.analysis.world_model import WorldModel
from app.core.logging import get_logger
from app.discovery.base import POV_MARKER, ChannelResult, HypothesisCandidate
from app.models.enums import DiscoveryChannel, Severity
from app.samhita.engine import SamhitaResult

logger = get_logger(__name__)


async def run(
    *,
    model: WorldModel,
    descriptor: TargetDescriptor,
    samhita: SamhitaResult,
) -> ChannelResult:
    started = time.perf_counter()
    result = ChannelResult(channel=DiscoveryChannel.RUNTIME.value)

    observations = samhita.observation_set
    if observations is None or not observations.records:
        result.coverage_notes.append(
            "no runtime observations were available; SAMHITA observation did not produce records"
        )
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        return result

    guard = observations.guard or {}
    counter = 0

    # -- shell invocation with caller-influenced arguments -----------------
    subprocess_calls = [c for c in (guard.get("subprocess_calls") or []) if isinstance(c, dict)]
    shell_calls = [c for c in subprocess_calls if c.get("shell")]
    if shell_calls:
        counter += 1
        site = _shell_site(model)
        symbol = model.symbol_at(*_split(site)) if site else None
        handle = symbol.handle if symbol else ""
        clause_id = _clause_of_kind(samhita, "forbidden_shell_invocation")
        result.candidates.append(
            HypothesisCandidate(
                handle=f"R{counter:03d}",
                source_channel=DiscoveryChannel.RUNTIME.value,
                description=(
                    f"The benign workload spawned a shell {len(shell_calls)} time(s). "
                    "The command string is assembled at runtime, so any caller-controlled "
                    "component of it is interpreted by the shell."
                ),
                location=site or f"{descriptor.entry_file}:1",
                severity=Severity.CRITICAL.value,
                reachability=model.reachability_score(handle) if handle else 0.9,
                confidence=0.85,
                blast_radius=model.blast_radius_score(handle) if handle else 0.5,
                cwe="CWE-78",
                candidate_clause_id=clause_id,
                rule_id="kavachx.runtime.shell-spawn",
                evidence_refs=[f"ev:runtime:{observations.raw_hash[:12]}"]
                + ([f"ev:code:{site}"] if site else []),
                validation_plan={
                    "kind": "command_injection",
                    "operation": "export",
                    "field": "name",
                    "base_value": "kavachx-probe",
                    "marker": POV_MARKER,
                    "separators": ["&", ";", "|", "&&", "\n"],
                    "success_signal": "marker_in_stdout",
                    "reproductions_required": 2,
                    "target_file": site.split(":")[0] if site else descriptor.entry_file,
                    "target_line": int(site.split(":")[-1]) if site else 1,
                    "target_function": symbol.qualname if symbol else "",
                },
                hypothesis_statement=(
                    "A shell is spawned on the benign path with a runtime-assembled command."
                ),
                decision="Candidate violation generated; injection plan attached.",
            )
        )
        result.thoughts.append(
            {
                "agent": "RUNTIME",
                "hypothesis": "Shell spawned with a runtime-assembled command string.",
                "evidence": [
                    site or descriptor.entry_file,
                    f"shell invocations observed: {len(shell_calls)}",
                    f"first command: {str(shell_calls[0].get('first', ''))[:120]}",
                ],
                "decision": "Injection validation plan attached.",
                "confidence": 0.85,
            }
        )

    # -- filesystem reach outside the declared asset root ------------------
    outside = int(guard.get("file_reads_outside_root", 0))
    if outside:
        counter += 1
        result.candidates.append(
            HypothesisCandidate(
                handle=f"R{counter:03d}",
                source_channel=DiscoveryChannel.RUNTIME.value,
                description=(
                    f"{outside} read(s) resolved outside the declared asset root during benign "
                    "operation."
                ),
                location=f"{descriptor.asset_dir or 'assets'}:0",
                severity=Severity.MEDIUM.value,
                reachability=0.7,
                confidence=0.6,
                blast_radius=0.4,
                cwe="CWE-22",
                rule_id="kavachx.runtime.read-outside-root",
                evidence_refs=[f"ev:runtime:{observations.raw_hash[:12]}"],
                validation_plan={},
                unknown_reason=(
                    "Benign reads outside the asset root are a containment smell but not a "
                    "proof of traversal; the static channel's traversal plan covers the "
                    "exploitable form."
                ),
            )
        )

    # -- network attempts --------------------------------------------------
    attempts = int(guard.get("network_attempts", 0))
    if attempts:
        counter += 1
        result.candidates.append(
            HypothesisCandidate(
                handle=f"R{counter:03d}",
                source_channel=DiscoveryChannel.RUNTIME.value,
                description=(
                    f"{attempts} outbound connection attempt(s) were blocked by the sandbox "
                    "guard during benign operation."
                ),
                location=f"{descriptor.entry_file}:1",
                severity=Severity.MEDIUM.value,
                reachability=0.8,
                confidence=0.7,
                blast_radius=0.5,
                cwe="CWE-829",
                rule_id="kavachx.runtime.network-attempt",
                evidence_refs=[f"ev:runtime:{observations.raw_hash[:12]}"],
                validation_plan={},
                unknown_reason=(
                    "The sandbox denies network access, so the intent of the connection cannot "
                    "be established from inside it. Requires human review."
                ),
            )
        )

    # -- clauses that the benign run itself contradicts --------------------
    for clause in samhita.falsified[:6]:
        result.coverage_notes.append(
            f"clause {clause.clause_id} ({clause.predicate}) was falsified by held-out benign "
            "behaviour and is not available as evidence"
        )

    result.coverage_notes.append(
        f"runtime observation: {len(observations.records)} records, "
        f"coverage {observations.coverage_percent:.1f}%, "
        f"egress {guard.get('egress_bytes', 0)} bytes, "
        f"blocked network attempts {attempts}"
    )
    result.coverage_notes.extend(_sanitizer_notes(descriptor))

    result.duration_ms = int((time.perf_counter() - started) * 1000)
    logger.info("discovery.runtime.complete", candidates=len(result.candidates))
    return result


def _sanitizer_notes(descriptor: TargetDescriptor) -> list[str]:
    if descriptor.language != "c":
        return [
            "ASan/UBSan are not applicable to a pure-Python target; the equivalent runtime "
            "signals are uncaught-exception traces and the in-process guard counters."
        ]
    notes: list[str] = []
    for tool in ("clang", "gcc"):
        if shutil.which(tool):
            notes.append(f"{tool} available: ASan/UBSan instrumentation possible")
            return notes
    notes.append(
        "No C compiler available: the ASan/UBSan instrumented build could not be produced. "
        "Native runtime coverage for this target is zero."
    )
    return notes


def _shell_site(model: WorldModel) -> str:
    for sink in model.sinks:
        if sink.category == "shell_exec":
            return f"{sink.file}:{sink.line}"
    for sink in model.sinks:
        if sink.category == "process_exec":
            return f"{sink.file}:{sink.line}"
    return ""


def _split(location: str) -> tuple[str, int]:
    file, _, line = location.rpartition(":")
    try:
        return file, int(line)
    except ValueError:
        return location, 0


def _clause_of_kind(samhita: SamhitaResult, kind: str) -> str:
    for clause in samhita.surviving:
        if clause.kind == kind:
            return clause.clause_id
    return ""
