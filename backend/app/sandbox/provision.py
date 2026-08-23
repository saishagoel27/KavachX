"""Workspace provisioning — run the operator's install/build commands before observation.

The missing piece for real repositories: a freshly materialised tree has no ``node_modules``, no
installed Python packages, nothing. Executing it then fails and the run falls to static-only. This
runs the **operator-supplied** install and build commands (Vercel/Render style — not guesswork)
inside the workspace, so dependencies exist before the target is exercised.

Isolation follows the working directory: ``npm install`` writes ``node_modules`` into the workspace,
so packages are local to this run, not the global system. Provisioning commands run through a shell
(they are operator-authored, unlike the untrusted target), and every step is reported — command,
exit code, and output tail — so a failed install is visible rather than silently degrading.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from app.core.logging import get_logger
from app.sandbox.base import ExecRequest, SandboxAdapter

logger = get_logger(__name__)

_IS_WINDOWS = os.name == "nt"


@dataclass(slots=True)
class ProvisionStep:
    label: str
    command: str
    exit_code: int
    ok: bool
    duration_ms: int
    output_tail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "command": self.command,
            "exit_code": self.exit_code,
            "ok": self.ok,
            "duration_ms": self.duration_ms,
            "output_tail": self.output_tail,
        }


@dataclass(slots=True)
class ProvisionReport:
    steps: list[ProvisionStep] = field(default_factory=list)
    ok: bool = True
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "steps": [s.as_dict() for s in self.steps],
            "notes": self.notes,
        }


def _shellify(command: str) -> list[str]:
    """Run an operator-authored command line through the platform shell.

    Provisioning is the one place a shell is acceptable: the command is typed by the operator, not
    supplied by the untrusted target. The target itself is always run without a shell.
    """
    if _IS_WINDOWS:
        return ["cmd", "/c", command]
    return ["sh", "-c", command]


async def provision(
    adapter: SandboxAdapter,
    *,
    commands: Sequence[tuple[str, str]],
    cwd: str = ".",
    env: dict[str, str] | None = None,
    timeout_seconds: int = 600,
) -> ProvisionReport:
    """Run ``(label, command)`` pairs in order inside the workspace.

    A failing step is recorded and the run continues (many targets need no build step, and a partial
    install is often enough to observe the vulnerable path). The report is the honest record of what
    ran.
    """
    report = ProvisionReport()
    for label, command in commands:
        command = (command or "").strip()
        if not command:
            continue
        result = await adapter.execute(
            ExecRequest(
                argv=_shellify(command),
                cwd=cwd,
                env=dict(env or {}),
                timeout_seconds=timeout_seconds,
                label=f"provision:{label}",
            )
        )
        tail = (result.stdout[-800:] + ("\n" + result.stderr[-800:] if result.stderr else "")).strip()
        step = ProvisionStep(
            label=label,
            command=command,
            exit_code=result.exit_code,
            ok=result.ok,
            duration_ms=result.duration_ms,
            output_tail=tail[-1000:],
        )
        report.steps.append(step)
        if result.ok:
            logger.info("provision.step_ok", label=label, ms=result.duration_ms)
        else:
            report.ok = False
            report.notes.append(
                f"{label!r} command exited {result.exit_code} — continuing; the target may still "
                "run, or observation may fall back to static-only if it cannot execute"
            )
            logger.warning("provision.step_failed", label=label, exit=result.exit_code)
    return report
