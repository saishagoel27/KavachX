"""Shield-first response.

::

    Validated Finding → Shield Synthesis → Exploit blocked? + Benign corpus passes?
        → Deploy reversible shield

The point of a shield is time. A real repair needs root-cause analysis, synthesis and four
verification stages; a shield can be in place in seconds and taken out again just as fast. That
is why the console reports **TIME TO PROTECTION** separately from **TIME TO REPAIR**.

Mechanism for this PoC: a **reversible input filter** installed as a sitecustomize-level wrapper
in the workspace copy. It is genuinely deployed, genuinely verified by execution, and genuinely
reverted by deleting one file — no target source is modified, which is what makes it reversible.

The architecture supports stronger mechanisms (seccomp profiles, ``LD_PRELOAD`` guards) and the
:class:`ShieldMechanism` enum names them; only ``input_filter`` is implemented here, and
``describe_mechanisms`` reports that honestly rather than implying otherwise.
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass, field
from enum import Enum

if sys.version_info >= (3, 11):
    from enum import StrEnum
else:
    class StrEnum(str, Enum):
        pass
from pathlib import Path
from typing import Any

from app.analysis.probe import TargetDescriptor
from app.core.hashing import sha256_json
from app.core.logging import get_logger
from app.sandbox.base import ExecRequest, SandboxAdapter
from app.validator.service import ValidationOutcome

logger = get_logger(__name__)

SHIELD_MODULE_NAME = "kx_shield.py"
SHIELD_RULES_NAME = "shield-rules.json"


class ShieldMechanism(StrEnum):
    INPUT_FILTER = "input_filter"
    SECCOMP = "seccomp"
    LD_PRELOAD = "ld_preload"


@dataclass
class ShieldResult:
    ok: bool = False
    mechanism: str = ShieldMechanism.INPUT_FILTER.value
    handle: str = ""
    rule: str = ""
    rule_json: dict[str, Any] = field(default_factory=dict)
    deploy_command: str = ""
    revert_command: str = ""
    verified_blocked: bool = False
    verified_benign: bool = False
    benign_pass_count: int = 0
    benign_total: int = 0
    deployed: bool = False
    detail: str = ""
    error: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    tool_events: list[dict[str, Any]] = field(default_factory=list)
    time_to_protection_ms: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "mechanism": self.mechanism,
            "handle": self.handle,
            "rule": self.rule,
            "rule_json": self.rule_json,
            "deploy_command": self.deploy_command,
            "revert_command": self.revert_command,
            "verified_blocked": self.verified_blocked,
            "verified_benign": self.verified_benign,
            "benign_pass_count": self.benign_pass_count,
            "benign_total": self.benign_total,
            "deployed": self.deployed,
            "detail": self.detail,
            "error": self.error,
        }


def synthesise_rule(outcome: ValidationOutcome, *, handle: str) -> dict[str, Any]:
    """Derive a filter rule from the *validated* proof of vulnerability.

    Deterministic: the rule comes from what the exploit actually did, not from a model's guess
    about what an exploit might do.
    """
    kind = outcome.pov_kind
    operation = str(outcome.pov_request.get("op", "")) if outcome.pov_request else ""

    if kind == "command_injection":
        return {
            "id": handle,
            "kind": "reject_metacharacters",
            "operation": operation or "export",
            "field": "name",
            # Every shell metacharacter, not only the separator that happened to work. A shield
            # is allowed to be blunt — it is reversible and it is not the repair.
            "tokens": [";", "&", "|", "`", "$", ">", "<", "\n", "\r", "(", ")", "{", "}"],
            "reason": "shell metacharacter in a value that reaches a shell command",
        }
    if kind == "length_boundary":
        request = outcome.pov_request or {}
        raw = str(request.get("headers", ""))
        observed = raw.count("\n") + 1 if raw else 9
        return {
            "id": handle,
            "kind": "reject_line_count",
            "operation": operation or "parse",
            "field": "headers",
            # One under the value that crashed: the shield's job is to stop the proven exploit.
            "max_lines": max(1, observed - 1),
            "reason": "header block exceeds the observed safe line count",
        }
    if kind == "path_traversal":
        return {
            "id": handle,
            "kind": "reject_traversal",
            "operation": operation or "asset",
            "field": "path",
            "tokens": ["..", "~", ":", "\\\\"],
            "reason": "path traversal sequence in an asset path",
        }
    if kind == "replay_request":
        return {
            "id": handle,
            "kind": "reject_exact_request",
            "operation": operation,
            "request_hash": outcome.input_hash,
            "reason": "exact request known to crash the entrypoint",
        }
    return {}


def render_shield_module(rules: list[dict[str, Any]]) -> str:
    """Generate the in-workspace shield.

    The shield gates at the **request boundary**, before the target's own code runs, which is
    what a filtering gateway in front of a service actually does. Two entry paths, because the
    target is reached two ways:

    * ``gate_argv()`` — called from ``sitecustomize`` at interpreter startup, so a CLI
      invocation is rejected before ``main.py`` executes a single line;
    * ``evaluate_argv()`` — called by the batch runner for in-process cases.

    Nothing in the target is modified. Deleting this generated file fully reverts the shield.
    """
    header = (
        '"""KavachX shield — generated, reversible input filter.\n\n'
        "Deployed by KavachX as a temporary mitigation for a validated finding. The rules were\n"
        "derived from the proof of vulnerability, not guessed.\n\n"
        "GENERATED FILE. Deleting it reverts the shield completely; no target source was\n"
        "modified to install it.\n"
        f"Rules active: {len(rules)}\n"
        '"""\n'
    )
    return (
        header
        + '''
from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

RULES_PATH = os.environ.get("KAVACHX_SHIELD_RULES", "")
BLOCKED_RESPONSE_KIND = "shielded"

_rules = []
if RULES_PATH and Path(RULES_PATH).is_file():
    try:
        _rules = json.loads(Path(RULES_PATH).read_text(encoding="utf-8"))
    except Exception:
        _rules = []


def rules():
    return _rules


def _request_hash(request):
    canonical = json.dumps(request, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def evaluate(request):
    """Return the first matching rule, or None."""
    if not isinstance(request, dict):
        return None
    operation = str(request.get("op", ""))

    for rule in _rules:
        rule_op = str(rule.get("operation", ""))
        if rule_op and rule_op != operation:
            continue
        kind = rule.get("kind")
        field_name = str(rule.get("field", ""))
        value = request.get(field_name)

        if kind == "reject_metacharacters" and isinstance(value, str):
            if any(token in value for token in rule.get("tokens", [])):
                return rule
        elif kind == "reject_line_count" and isinstance(value, str):
            lines = len([ln for ln in value.split(chr(10)) if ln.strip()])
            if lines > int(rule.get("max_lines", 8)):
                return rule
        elif kind == "reject_traversal" and isinstance(value, str):
            normalised = value.replace(chr(92), "/")
            for token in rule.get("tokens", []):
                if token.replace(chr(92), "/") in normalised:
                    return rule
            try:
                if Path(value).is_absolute():
                    return rule
            except Exception:
                return rule
        elif kind == "reject_exact_request":
            if _request_hash(request) == rule.get("request_hash"):
                return rule

    return None


def request_from_argv(argv):
    """Extract the request object from a CLI argument vector."""
    argv = list(argv or [])
    for index, arg in enumerate(argv):
        if arg == "--request" and index + 1 < len(argv):
            try:
                return json.loads(argv[index + 1])
            except Exception:
                return None
        if arg.startswith("--request="):
            try:
                return json.loads(arg.split("=", 1)[1])
            except Exception:
                return None
        if arg == "--request-file" and index + 1 < len(argv):
            try:
                return json.loads(Path(argv[index + 1]).read_text(encoding="utf-8"))
            except Exception:
                return None
    return None


def blocked_response(request, rule):
    return {
        "ok": False,
        "op": request.get("op") if isinstance(request, dict) else None,
        "error": "request rejected by KavachX shield: " + str(rule.get("reason", "")),
        "kind": BLOCKED_RESPONSE_KIND,
        "shield_id": rule.get("id", ""),
    }


def evaluate_argv(argv):
    """(rule, request) for an argument vector, or (None, request)."""
    request = request_from_argv(argv)
    if request is None:
        return None, None
    return evaluate(request), request


def gate_argv():
    """Reject a CLI invocation before the target runs. Called from sitecustomize."""
    if not _rules:
        return False
    rule, request = evaluate_argv(sys.argv[1:])
    if rule is None:
        return False
    sys.stdout.write(json.dumps(blocked_response(request, rule), sort_keys=True) + chr(10))
    sys.stdout.flush()
    raise SystemExit(0)
'''
    )


class ShieldService:
    """Deploys and verifies shields inside the sandbox workspace."""

    def __init__(
        self,
        *,
        sandbox: SandboxAdapter,
        descriptor: TargetDescriptor,
        workspace: Path,
    ) -> None:
        self.sandbox = sandbox
        self.descriptor = descriptor
        self.workspace = workspace
        self.harness_dir = workspace / "_kavachx"
        self.active_rules: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    @property
    def rules_path(self) -> Path:
        return self.harness_dir / SHIELD_RULES_NAME

    @property
    def module_path(self) -> Path:
        return self.harness_dir / SHIELD_MODULE_NAME

    def _env(self) -> dict[str, str]:
        if not self.rules_path.is_file():
            return {}
        return {
            "KAVACHX_SHIELD_RULES": str(self.rules_path),
            # The wrapper is imported by name so it is active before any target code runs.
            "KAVACHX_SHIELD_MODULE": "kx_shield",
        }

    def _write(self, rules: list[dict[str, Any]]) -> None:
        self.harness_dir.mkdir(parents=True, exist_ok=True)
        self.rules_path.write_text(json.dumps(rules, sort_keys=True), encoding="utf-8")
        self.module_path.write_text(render_shield_module(rules), encoding="utf-8")

    def revert_all(self) -> None:
        for path in (self.rules_path, self.module_path):
            if path.is_file():
                path.unlink()
        self.active_rules = []

    # ------------------------------------------------------------------
    async def deploy(
        self,
        *,
        outcome: ValidationOutcome,
        handle: str,
        benign_cases: list[dict[str, Any]],
        elapsed_ms: int,
    ) -> ShieldResult:
        started = time.perf_counter()
        result = ShieldResult(handle=handle)

        rule = synthesise_rule(outcome, handle=handle)
        if not rule:
            result.error = (
                f"No shield mechanism covers a {outcome.pov_kind!r} finding, so no reversible "
                "mitigation was deployed. The finding relies on the repair path alone."
            )
            result.detail = result.error
            return result

        result.rule_json = rule
        result.rule = _render_rule(rule)
        result.deploy_command = (
            f"cp _kavachx/{SHIELD_MODULE_NAME} <target>/_kavachx/ && "
            f"export KAVACHX_SHIELD_RULES=_kavachx/{SHIELD_RULES_NAME}"
        )
        result.revert_command = (
            f"rm _kavachx/{SHIELD_MODULE_NAME} _kavachx/{SHIELD_RULES_NAME} && "
            "unset KAVACHX_SHIELD_RULES"
        )

        candidate_rules = [*self.active_rules, rule]
        self._write(candidate_rules)

        # -- 1. does the shield actually block the validated exploit? -------
        blocked = await self._exploit_blocked(outcome)
        result.verified_blocked = blocked["blocked"]
        result.evidence["exploit_check"] = blocked
        result.tool_events.append(
            {
                "name": "shield:exploit-check",
                "target": handle,
                "ms": blocked["ms"],
                "ok": blocked["blocked"],
                "detail": blocked["detail"],
            }
        )

        # -- 2. does the benign corpus still pass? -------------------------
        benign = await self._benign_passes(benign_cases)
        result.verified_benign = benign["all_passed"]
        result.benign_pass_count = benign["passed"]
        result.benign_total = benign["total"]
        result.evidence["benign_check"] = benign
        result.tool_events.append(
            {
                "name": "shield:benign-check",
                "target": f"{benign['total']} benign cases",
                "ms": benign["ms"],
                "ok": benign["all_passed"],
                "detail": benign["detail"],
            }
        )

        if result.verified_blocked and result.verified_benign:
            self.active_rules = candidate_rules
            result.ok = True
            result.deployed = True
            result.time_to_protection_ms = elapsed_ms
            result.detail = (
                f"Shield {handle} deployed: the validated exploit is blocked and all "
                f"{benign['total']} benign cases still pass."
            )
            logger.info("shield.deployed", handle=handle, mechanism=result.mechanism)
        else:
            # A shield that breaks benign behaviour is worse than no shield. Roll back.
            self._write(self.active_rules)
            if not self.active_rules:
                self.revert_all()
            reasons: list[str] = []
            if not result.verified_blocked:
                reasons.append("it did not block the validated exploit")
            if not result.verified_benign:
                reasons.append(
                    f"it broke {benign['total'] - benign['passed']} of {benign['total']} "
                    "benign cases"
                )
            result.error = "Shield withdrawn: " + " and ".join(reasons) + "."
            result.detail = result.error
            logger.warning("shield.withdrawn", handle=handle, reason=result.error)

        result.evidence["duration_ms"] = int((time.perf_counter() - started) * 1000)
        result.evidence["rule_hash"] = sha256_json(rule)
        return result

    # ------------------------------------------------------------------
    async def _exploit_blocked(self, outcome: ValidationOutcome) -> dict[str, Any]:
        request = outcome.pov_request or {}
        if not request:
            return {"blocked": False, "ms": 0, "detail": "no proof-of-vulnerability request"}

        started = time.perf_counter()
        exec_result = await self.sandbox.execute(
            ExecRequest(
                argv=self.descriptor.argv_for(json.dumps(request, sort_keys=True)),
                env={**self._env(), "PYTHONSTARTUP": ""},
                label="shield:exploit",
                timeout_seconds=min(60, self.sandbox.limits.wall_clock_seconds),
            )
        )
        ms = int((time.perf_counter() - started) * 1000)

        # Blocked means the *effect* is gone, judged by the same deterministic signal the
        # validator used to prove it in the first place.
        if outcome.pov_kind == "command_injection":
            marker = "KAVACHX_POV_MARKER_7F3A"
            blocked = marker not in exec_result.stdout
            detail = "marker absent from stdout" if blocked else "marker still executed"
        elif outcome.pov_kind == "path_traversal":
            from app.discovery.base import CANARY_CONTENT

            blocked = CANARY_CONTENT not in exec_result.stdout
            detail = "canary not readable" if blocked else "canary still readable"
        else:
            blocked = exec_result.exit_code == 0 and not exec_result.signals
            detail = (
                "entrypoint returned cleanly"
                if blocked
                else f"still failing (exit {exec_result.exit_code})"
            )

        return {
            "blocked": blocked,
            "ms": ms,
            "detail": detail,
            "exit_code": exec_result.exit_code,
            "shield_response": "shielded" in exec_result.stdout,
            "output_hash": exec_result.output_hash(),
        }

    async def _benign_passes(self, cases: list[dict[str, Any]]) -> dict[str, Any]:
        if not cases:
            return {
                "all_passed": False,
                "passed": 0,
                "total": 0,
                "ms": 0,
                "detail": "no benign corpus to verify against",
            }

        spec = {
            "project_root": ".",
            "source_root": self.descriptor.source_root,
            "entry_module": self.descriptor.entry_module,
            "entry_callable": self.descriptor.entry_callable,
            "cases": [{"id": c["id"], "argv": c["argv"]} for c in cases],
        }
        spec_rel = "_kavachx/out/shield-benign-spec.json"
        out_rel = "_kavachx/out/shield-benign-result.json"
        (self.workspace / spec_rel).parent.mkdir(parents=True, exist_ok=True)
        (self.workspace / spec_rel).write_text(json.dumps(spec, sort_keys=True), encoding="utf-8")

        started = time.perf_counter()
        exec_result = await self.sandbox.execute(
            ExecRequest(
                argv=["python", "-c", _BENIGN_RUNNER, spec_rel, out_rel],
                env=self._env(),
                collect_artifacts=[out_rel],
                label="shield:benign",
                timeout_seconds=max(120, self.sandbox.limits.wall_clock_seconds * 2),
            )
        )
        ms = int((time.perf_counter() - started) * 1000)

        raw = exec_result.artifacts.get(out_rel, "")
        if not raw:
            return {
                "all_passed": False,
                "passed": 0,
                "total": len(cases),
                "ms": ms,
                "detail": f"benign verification did not run (exit {exec_result.exit_code})",
            }

        document = json.loads(raw)
        results = document.get("cases", [])
        passed = [
            r
            for r in results
            if r["exit_code"] == 0
            and isinstance(r.get("response"), dict)
            and r["response"].get("kind") != "shielded"
        ]
        blocked_benign = [
            r["id"]
            for r in results
            if isinstance(r.get("response"), dict) and r["response"].get("kind") == "shielded"
        ]
        return {
            "all_passed": len(passed) == len(results) and bool(results),
            "passed": len(passed),
            "total": len(results),
            "ms": ms,
            "detail": (
                f"{len(passed)}/{len(results)} benign cases unaffected"
                + (f"; shield wrongly blocked {blocked_benign}" if blocked_benign else "")
            ),
            "blocked_benign": blocked_benign,
        }


def _render_rule(rule: dict[str, Any]) -> str:
    kind = rule.get("kind", "")
    if kind == "reject_metacharacters":
        return (
            f"REJECT {rule['operation']}.{rule['field']} WHEN value contains any of "
            f"{' '.join(repr(t) for t in rule['tokens'])}"
        )
    if kind == "reject_line_count":
        return (
            f"REJECT {rule['operation']}.{rule['field']} WHEN non-empty line count > "
            f"{rule['max_lines']}"
        )
    if kind == "reject_traversal":
        return (
            f"REJECT {rule['operation']}.{rule['field']} WHEN value contains a traversal "
            f"sequence {rule['tokens']} or is absolute"
        )
    if kind == "reject_exact_request":
        return f"REJECT {rule.get('operation', '*')} WHEN sha256(request) == {rule['request_hash'][:16]}…"
    return json.dumps(rule, sort_keys=True)


def describe_mechanisms() -> list[dict[str, Any]]:
    """What is implemented versus what the architecture supports. Reported to the UI as-is."""
    return [
        {
            "mechanism": ShieldMechanism.INPUT_FILTER.value,
            "implemented": True,
            "reversible": True,
            "notes": (
                "Generated wrapper around the target entrypoint, driven by a rule derived from "
                "the validated proof of vulnerability. Reverted by deleting one generated file; "
                "no target source is modified."
            ),
        },
        {
            "mechanism": ShieldMechanism.SECCOMP.value,
            "implemented": False,
            "reversible": True,
            "notes": (
                "Architecturally supported by the gVisor and Firecracker adapters via "
                "--security-opt seccomp=<profile>. Not synthesised in this PoC build: deriving "
                "a sound syscall allowlist from a single reproduction is not something to "
                "improvise."
            ),
        },
        {
            "mechanism": ShieldMechanism.LD_PRELOAD.value,
            "implemented": False,
            "reversible": True,
            "notes": (
                "Intended for native targets, interposing on the vulnerable libc call. Requires "
                "the C toolchain path, which is not exercised on the Windows demo host."
            ),
        },
    ]


#: Inlined so it needs no separate harness file; it reuses kx_batch's runner.
_BENIGN_RUNNER = (
    "import json,sys,os\n"
    "sys.path.insert(0, os.path.join(os.getcwd(), '_kavachx'))\n"
    "shield = os.environ.get('KAVACHX_SHIELD_MODULE')\n"
    "import kx_batch\n"
    "spec_path, out_path = sys.argv[1], sys.argv[2]\n"
    "spec = json.loads(open(spec_path, encoding='utf-8').read())\n"
    "import importlib, pathlib\n"
    "root = pathlib.Path(spec.get('project_root','.')).resolve()\n"
    "src = pathlib.Path(spec.get('source_root','.')).resolve()\n"
    "sys.path.insert(0, str(src))\n"
    "mod = importlib.import_module(spec.get('entry_module','main'))\n"
    "if shield:\n"
    "    importlib.import_module(shield)\n"
    "entry = getattr(mod, spec.get('entry_callable','main'))\n"
    "results = [kx_batch.run_case(entry, c, root) for c in spec.get('cases', [])]\n"
    "open(out_path,'w',encoding='utf-8').write(json.dumps({'cases':results}, default=str))\n"
)
