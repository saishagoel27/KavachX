"""Channel 2 — configuration / reachability.

Inspects configuration, exposed services, permissions, entrypoints and deployment settings.

Most of what this channel finds is *not* dynamically provable against a local CLI target: a
service that binds ``0.0.0.0`` is only dangerous once it is actually listening, and the sandbox
has no network by design. Rather than invent a validation, those candidates carry an explicit
``unknown_reason`` and land in the failure/unknown ledger for REMAINING.md. That is the honest
outcome, and it is the one the spec asks for.
"""

from __future__ import annotations

import time
from typing import Any

from app.analysis.world_model import WorldModel
from app.core.logging import get_logger
from app.discovery.base import ChannelResult, HypothesisCandidate
from app.models.enums import DiscoveryChannel, Severity

logger = get_logger(__name__)

_CATEGORY_META: dict[str, tuple[str, str, str]] = {
    # category -> (severity, cwe, why it cannot be dynamically validated here)
    "debug_enabled": (
        Severity.MEDIUM.value,
        "CWE-489",
        "Debug mode changes error verbosity. The CLI entrypoint returns the same structured "
        "response either way, so no execution inside the sandbox can distinguish the two "
        "states. Confirming this needs a deployed instance and a human decision.",
    ),
    "bind_all_interfaces": (
        Severity.MEDIUM.value,
        "CWE-1327",
        "The sandbox has no network interface by design, so a listening socket cannot be "
        "reached to demonstrate exposure. This is a deployment-configuration risk for review.",
    ),
}


async def run(*, model: WorldModel, descriptor: Any) -> ChannelResult:
    started = time.perf_counter()
    result = ChannelResult(channel=DiscoveryChannel.CONFIG_REACHABILITY.value)

    counter = 0

    # -- configuration signals --------------------------------------------
    for signal in model.config_findings:
        counter += 1
        category = str(signal.get("category", ""))
        severity, cwe, unknown = _CATEGORY_META.get(
            category,
            (Severity.LOW.value, "", "No executable validation plan exists for this signal."),
        )
        location = f"{signal['file']}:{signal['line']}"
        result.candidates.append(
            HypothesisCandidate(
                handle=f"C{counter:03d}",
                source_channel=DiscoveryChannel.CONFIG_REACHABILITY.value,
                description=str(signal.get("message", category)),
                location=location,
                severity=severity,
                # Configuration is read at startup, so it is reachable by definition.
                reachability=0.9,
                confidence=0.75,
                blast_radius=0.35,
                cwe=cwe,
                rule_id=f"kavachx.config.{category}",
                evidence_refs=[f"ev:code:{location}"],
                validation_plan={},
                unknown_reason=unknown,
                hypothesis_statement=str(signal.get("message", category)),
                decision="Recorded in the unknown ledger — configuration risk, not dynamically provable here.",
            )
        )
        result.thoughts.append(
            {
                "agent": "CONFIG / REACHABILITY",
                "hypothesis": str(signal.get("message", category)),
                "evidence": [location, signal.get("snippet", "")[:120]],
                "decision": "No executable plan; queued to the unknown ledger.",
                "confidence": 0.75,
            }
        )

    # -- deployment units --------------------------------------------------
    for unit in model.deployment_units:
        for note in unit.get("signals", []):
            counter += 1
            result.candidates.append(
                HypothesisCandidate(
                    handle=f"C{counter:03d}",
                    source_channel=DiscoveryChannel.CONFIG_REACHABILITY.value,
                    description=f"{unit['file']}: {note}",
                    location=f"{unit['file']}:1",
                    severity=Severity.LOW.value,
                    reachability=0.5,
                    confidence=0.6,
                    blast_radius=0.4,
                    rule_id=f"kavachx.deployment.{unit['kind']}",
                    evidence_refs=[f"ev:code:{unit['file']}:1"],
                    validation_plan={},
                    unknown_reason=(
                        "Deployment configuration is not exercised by the sandbox, which "
                        "executes the target directly rather than through its container."
                    ),
                    hypothesis_statement=f"{unit['file']}: {note}",
                    decision="Recorded for human review.",
                )
            )

    # -- permissions -------------------------------------------------------
    for permission in model.permissions[:10]:
        counter += 1
        location = f"{permission['file']}:{permission['line']}"
        result.candidates.append(
            HypothesisCandidate(
                handle=f"C{counter:03d}",
                source_channel=DiscoveryChannel.CONFIG_REACHABILITY.value,
                description=f"Permission-changing operation: {permission['snippet'][:160]}",
                location=location,
                severity=Severity.LOW.value,
                reachability=0.4,
                confidence=0.45,
                blast_radius=0.3,
                rule_id="kavachx.config.permission_change",
                evidence_refs=[f"ev:code:{location}"],
                validation_plan={},
                unknown_reason=(
                    "Filesystem permission effects are not observable through the sandbox's "
                    "structured artifact output."
                ),
            )
        )

    result.coverage_notes.append(
        f"inspected {len(model.files)} files, {len(model.deployment_units)} deployment units, "
        f"ports {model.ports or 'none declared'}"
    )
    if model.ports:
        result.coverage_notes.append(
            f"declared ports {model.ports} could not be probed: the sandbox has no network."
        )

    result.duration_ms = int((time.perf_counter() - started) * 1000)
    logger.info("discovery.config.complete", candidates=len(result.candidates))
    return result
