"""Black-box adaptive corpus fuzzing + validation for request→output CLIs in any language.

The Python path derives value profiles by tracing inside the process. A black-box target can't be
traced, so this module proves vulnerabilities a different, still-deterministic way:

1. **Learn the interface from the benign corpus.** Each benign request reveals the request shape
   (its ops and string fields) without needing to read the source.
2. **Mutate each string field with an exploit oracle.**
   * command injection — append ``<sep> echo <MARKER>`` for a set of shell separators; if the
     unique marker is echoed, an injected command ran.
   * path traversal — replace the field with ``../<canary>``; a canary file planted above the
     target's root leaks its unique content only if the read escaped confinement.
3. **Confirm only on the observed effect, reproduced independently.** A finding is born solely when
   the planted token appears in the output on ``>= reproduce`` separate runs — never from a guess.

This is the "targeted fuzzing" the design asks for: it spends executions only on fields a real
request actually carries, and it is language-agnostic because it observes from the outside.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from app.core.hashing import sha256_json, sha256_text
from app.core.logging import get_logger
from app.models.enums import Severity
from app.sandbox.base import SandboxAdapter
from app.sandbox.blackbox import observe
from app.validator.service import ValidationOutcome

logger = get_logger(__name__)

_MARKER = "KAVACHX_BBX_MARK_5f31d2"
_CANARY_NAME = ".kavachx_bb_canary.txt"
_CANARY_CONTENT = "KAVACHX_BBX_CANARY_a7c9e4_secret"
#: Separators that chain a second command on some shell (sh uses ';'/'|', cmd.exe uses '&').
_SEPARATORS = ("&", ";", "|", "&&")
_TRAVERSAL_PAYLOADS = (f"../{_CANARY_NAME}", f"../../{_CANARY_NAME}", f"..\\{_CANARY_NAME}")


@dataclass(slots=True)
class BlackboxFinding:
    vuln_type: str  # command_injection | path_traversal
    cwe: str
    severity: str
    op: str
    field: str
    location: str
    description: str
    outcome: ValidationOutcome


def _argv(template: Sequence[str], request: dict[str, Any]) -> list[str]:
    payload = json.dumps(request, sort_keys=True)
    return [a.replace("{payload}", payload) for a in template]


def _string_fields(request: dict[str, Any]) -> list[str]:
    # 'op'/'action' name the endpoint, not user data — skip them as injection targets.
    return [k for k, v in request.items() if isinstance(v, str) and k not in ("op", "action")]


async def _confirm(
    adapter: SandboxAdapter,
    *,
    argv_template: Sequence[str],
    exploit: dict[str, Any],
    token: str,
    label: str,
    reproduce: int,
) -> tuple[int, Any]:
    """Run the exploit request repeatedly; return (times the token was observed, last observation)."""
    seen = 0
    last = None
    for i in range(reproduce):
        obs = await observe(
            adapter,
            argv=_argv(argv_template, exploit),
            case_id=f"{label}#{i}",
            watch_tokens=[token],
            timeout_seconds=30,
        )
        last = obs
        if token in obs.tokens_seen:
            seen += 1
    return seen, last


async def _try_injection(
    adapter: SandboxAdapter,
    argv_template: Sequence[str],
    request: dict[str, Any],
    field: str,
    reproduce: int,
) -> BlackboxFinding | None:
    original = request[field]
    for sep in _SEPARATORS:
        exploit = {**request, field: f"{original}{sep} echo {_MARKER}"}
        # One probe run first; only pay for reproduction if it hits.
        seen, _ = await _confirm(
            adapter,
            argv_template=argv_template,
            exploit=exploit,
            token=_MARKER,
            label=f"inject:{field}:{sep}",
            reproduce=1,
        )
        if not seen:
            continue
        total, last = await _confirm(
            adapter,
            argv_template=argv_template,
            exploit=exploit,
            token=_MARKER,
            label=f"inject:{field}:{sep}:repro",
            reproduce=reproduce,
        )
        if total < reproduce:
            continue
        op = str(request.get("op", ""))
        outcome = ValidationOutcome(
            reproduced=True,
            reproduction_count=total,
            exit_code=last.exit_code,
            sanitizer_signal="",
            contract_violation=f"the value of '{field}' reached a shell and executed a command",
            pov_payload=json.dumps(exploit, sort_keys=True),
            pov_kind="command_injection",
            pov_request=exploit,
            input_hash=sha256_json(exploit),
            output_hash=last.output_hash,
            trace_hash=sha256_text(f"{last.output_hash}:inject:{field}:{sep}"),
            severity=Severity.CRITICAL.value,
            crash_site=f"request.{field}",
            detail=(
                f"An injected command was executed: appending {sep!r} + a marker to '{field}' "
                f"caused the unique marker to be echoed in the output, reproduced {total}x."
            ),
            refutation_reason="",
            observed_tokens=[sep],
            attempts=[{"field": field, "separator": sep, "marker_observed": True}],
            evidence={"kind": "command_injection", "field": field, "separator": sep, "op": op},
        )
        logger.info("blackbox_probe.injection", field=field, sep=sep, op=op, count=total)
        return BlackboxFinding(
            vuln_type="command_injection",
            cwe="CWE-78",
            severity=Severity.CRITICAL.value,
            op=op,
            field=field,
            location=f"request.{field}",
            description=f"OS command injection via '{field}'" + (f" (op={op})" if op else ""),
            outcome=outcome,
        )
    return None


async def _try_traversal(
    adapter: SandboxAdapter,
    argv_template: Sequence[str],
    request: dict[str, Any],
    field: str,
    reproduce: int,
) -> BlackboxFinding | None:
    for payload in _TRAVERSAL_PAYLOADS:
        exploit = {**request, field: payload}
        seen, _ = await _confirm(
            adapter,
            argv_template=argv_template,
            exploit=exploit,
            token=_CANARY_CONTENT,
            label=f"traverse:{field}",
            reproduce=1,
        )
        if not seen:
            continue
        total, last = await _confirm(
            adapter,
            argv_template=argv_template,
            exploit=exploit,
            token=_CANARY_CONTENT,
            label=f"traverse:{field}:repro",
            reproduce=reproduce,
        )
        if total < reproduce:
            continue
        op = str(request.get("op", ""))
        outcome = ValidationOutcome(
            reproduced=True,
            reproduction_count=total,
            exit_code=last.exit_code,
            sanitizer_signal="",
            contract_violation=f"'{field}' read a file outside the intended root",
            pov_payload=json.dumps(exploit, sort_keys=True),
            pov_kind="path_traversal",
            pov_request=exploit,
            input_hash=sha256_json(exploit),
            output_hash=last.output_hash,
            trace_hash=sha256_text(f"{last.output_hash}:traverse:{field}"),
            severity=Severity.HIGH.value,
            crash_site=f"request.{field}",
            detail=(
                f"Path traversal confirmed: setting '{field}' to {payload!r} leaked a canary file "
                f"planted outside the asset root, reproduced {total}x."
            ),
            refutation_reason="",
            observed_tokens=[payload],
            attempts=[{"field": field, "payload": payload, "canary_leaked": True}],
            evidence={"kind": "path_traversal", "field": field, "payload": payload, "op": op},
        )
        logger.info("blackbox_probe.traversal", field=field, op=op, count=total)
        return BlackboxFinding(
            vuln_type="path_traversal",
            cwe="CWE-22",
            severity=Severity.HIGH.value,
            op=op,
            field=field,
            location=f"request.{field}",
            description=f"Path traversal via '{field}'" + (f" (op={op})" if op else ""),
            outcome=outcome,
        )
    return None


async def probe(
    adapter: SandboxAdapter,
    *,
    argv_template: Sequence[str],
    benign_cases: Sequence[dict[str, Any]],
    reproduce: int = 2,
    max_cases: int = 16,
) -> list[BlackboxFinding]:
    """Adaptively fuzz the target from its benign corpus and return confirmed findings.

    Findings are de-duplicated by ``(vuln_type, op, field)`` so the same weakness reached from two
    benign cases is reported once.
    """
    # Plant the traversal canary above the target's asset root (workspace root).
    try:
        (adapter.workspace / _CANARY_NAME).write_text(_CANARY_CONTENT, encoding="utf-8")
    except OSError:
        logger.warning("blackbox_probe.canary_write_failed")

    found: dict[tuple[str, str, str], BlackboxFinding] = {}
    for case in list(benign_cases)[:max_cases]:
        request = case.get("request") if isinstance(case, dict) else None
        if not isinstance(request, dict):
            continue
        op = str(request.get("op", ""))
        for field in _string_fields(request):
            inj_key = ("command_injection", op, field)
            trav_key = ("path_traversal", op, field)
            if inj_key not in found:
                hit = await _try_injection(adapter, argv_template, request, field, reproduce)
                if hit is not None:
                    found[inj_key] = hit
                    continue
            if trav_key not in found:
                hit = await _try_traversal(adapter, argv_template, request, field, reproduce)
                if hit is not None:
                    found[trav_key] = hit

    logger.info("blackbox_probe.done", findings=len(found), cases=min(len(benign_cases), max_cases))
    return list(found.values())
