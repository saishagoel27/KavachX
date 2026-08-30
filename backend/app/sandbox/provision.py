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
import re
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
    #: The command that actually ran, after any persistence rewrite.
    command: str
    exit_code: int
    ok: bool
    duration_ms: int
    output_tail: str = ""
    #: What the operator asked for, when it differs from what ran. Empty when nothing was
    #: rewritten, so a reader can always tell whether KavachX changed their command.
    requested_command: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "command": self.command,
            "requested_command": self.requested_command,
            "rewritten": bool(self.requested_command),
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


#: Flags that mean the operator has already chosen where the packages go. If any is present the
#: command is left exactly as written — an explicit choice outranks ours.
_PIP_DESTINATION_FLAGS = ("--target", "--prefix", "--user", "--root", "--editable")

#: An invocation that installs into the *interpreter*, which does not survive the container that
#: ran it. npm, yarn, pnpm, go and cargo all install into the working directory instead, so they
#: are already persistent and are deliberately not matched.
#:
#: Anchored at the start of the segment rather than searched for anywhere in it: a substring test
#: rewrites ``echo "pip install ..."``, which is someone's log line, not an install.
_PIP_COMMAND = re.compile(
    r"""^\s*
        (?:\w+=\S*\s+)*                              # leading FOO=bar environment assignments
        (?:\S*/)?                                    # an optional path to the executable
        (?:
            pip3?(?:\.exe)?\s+install                # pip install / pip3 install
          | python3?(?:\.exe)?\s+-m\s+pip\s+install  # python -m pip install
          | uv\s+pip\s+install                       # uv pip install
        )\b""",
    re.VERBOSE,
)

#: Segment separators in a compound shell command, kept in the split so it can be reassembled.
_SEPARATORS = re.compile(r"(&&|\|\||;)")


def needs_deps_redirect(command: str) -> bool:
    """True when this is a plain pip install that would vanish with its container."""
    lowered = command.lower()
    if not _PIP_COMMAND.match(lowered):
        return False
    if any(flag in f" {lowered} " for flag in _PIP_DESTINATION_FLAGS):
        return False
    if re.search(r"(^|\s)-(t|e)(\s|=)", lowered):  # short forms of --target / --editable
        return False
    # A virtualenv the operator creates inside the workspace persists on its own.
    return "venv" not in lowered and "virtualenv" not in lowered


def rewrite_for_persistence(command: str, deps_dir: str = "") -> str:
    """Redirect a plain ``pip install`` into the workspace so packages outlive the container.

    The operator writes what they would write anywhere else — ``pip install -r requirements.txt``.
    Left alone that installs into the image's site-packages, which is discarded the moment the
    provisioning container exits: every execution is a fresh container, so the execute phase finds
    nothing, no benign case runs, and the run degrades to static-only with no visible cause.
    Appending ``--target`` points it at the one directory that both persists across executions and
    is on ``PYTHONPATH`` (see :data:`app.sandbox.base.DEPS_DIR`).

    Compound commands are redirected segment by segment, so ``pip install -r a.txt && pip install
    b`` is handled in both halves. Anything that is not a bare pip install is returned unchanged.
    """
    target = deps_dir or "${KAVACHX_DEPS_DIR}"
    parts = _SEPARATORS.split(command)
    for index, part in enumerate(parts):
        if _SEPARATORS.fullmatch(part.strip()) or not part.strip():
            continue
        if needs_deps_redirect(part):
            trailing = " " if part.endswith(" ") else ""
            parts[index] = f"{part.rstrip()} --target {target}{trailing}"
    return "".join(parts)


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
    for label, original in commands:
        original = (original or "").strip()
        if not original:
            continue
        # The operator writes the command they would write anywhere else; this is where it is
        # adapted to the fact that every execution is a fresh container. What actually ran is
        # recorded below, alongside what was asked for — the report must not claim to have run
        # something it rewrote.
        command = rewrite_for_persistence(original)
        result = await adapter.execute(
            ExecRequest(
                argv=_shellify(command),
                cwd=cwd,
                env=dict(env or {}),
                timeout_seconds=timeout_seconds,
                label=f"provision:{label}",
                # Provisioning is the trusted build phase: it needs the package registry and a
                # writable tree. Under gVisor this selects the networked, read-write posture; host
                # adapters ignore both flags (already writable and networked).
                writable=True,
                allow_network=True,
            )
        )
        tail = (
            result.stdout[-800:] + ("\n" + result.stderr[-800:] if result.stderr else "")
        ).strip()
        step = ProvisionStep(
            label=label,
            command=command,
            requested_command=original if command != original else "",
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
