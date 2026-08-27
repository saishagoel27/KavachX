"""Regression tests: the reproduced exploit, preserved.

When a finding is validated, the input that proved it is the most valuable test artifact the run
produces. It is a *known* exploit against a *known* location with a *known* deterministic signal —
strictly better evidence than anything a static rule can offer.

This module turns that into two durable things:

1. **A regression :class:`~app.testing.specs.TestPlan`** the gauntlet re-runs against every patch
   iteration. A patch is not verified until the original exploit no longer fires.
2. **A test file written in the target's own convention**, offered as a publishable artifact. If a
   maintainer applies the patch, they get the test that proves it works, in the framework their
   repository already uses — which is the difference between a patch they must trust and one they
   can check.

The second is deliberately *offered*, not applied. It goes into the run's artifacts and, when a
pull request is opened, alongside the patch — and the blast-radius policy still governs whether a
test file counts as an in-scope change.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.hashing import sha256_text
from app.core.logging import get_logger
from app.testing.specs import OracleSpec, TestPlan, TestSpec, plan_id_for

logger = get_logger(__name__)


@dataclass
class RegressionArtifact:
    """A test file in the target's own convention, ready to publish alongside the patch."""

    #: Path relative to the *target repository* root, not the workspace.
    path: str
    content: str
    framework: str
    sha256: str = ""
    #: Why this file exists, for the PR body.
    rationale: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "framework": self.framework,
            "sha256": self.sha256 or sha256_text(self.content),
            "lines": self.content.count("\n") + 1,
            "rationale": self.rationale,
        }


def plan_from_finding(
    *,
    outcome: Any,
    finding_handle: str,
    target: str,
    entrypoint: str,
    index_id: str,
    oracle_kind: str = "",
    marker_role: str = "",
) -> TestPlan | None:
    """Build a regression plan from a validated finding's reproduction record.

    The payload comes from the validator's ``pov_request``/``pov_payload`` — the input that
    actually reproduced — rather than from anything regenerated. A regression test built from a
    reconstructed input is testing a guess about the exploit, not the exploit.
    """
    request = dict(getattr(outcome, "pov_request", {}) or {})
    payload = str(getattr(outcome, "pov_payload", "") or "")
    if not payload and not request:
        return None

    pov_kind = str(getattr(outcome, "pov_kind", "") or "")
    kind, role = _oracle_for(pov_kind, oracle_kind, marker_role)

    # The payload sits in whichever request field carries it. When the validator recorded a
    # structured request the field is recoverable by matching the value.
    payload_field = ""
    for key, value in request.items():
        if isinstance(value, str) and value == payload:
            payload_field = key
            break

    if payload_field:
        # Split form: template + the field the payload goes in. Lets the harness re-substitute.
        template = {k: v for k, v in request.items() if k != payload_field}
        payloads = [payload] if payload else []
    else:
        # Replay form: the whole recorded request *is* the test. This is the common case for a
        # finding whose reproducing input is not a single substitutable field (a header block, a
        # multi-field request, a fuzzer-supplied structure). Splitting it apart would either drop
        # the payload or invent a field name that does not exist.
        template = dict(request)
        payloads = []

    try:
        spec = TestSpec(
            target=target,
            entrypoint=entrypoint,
            input_source="cli_argument",
            strategy="regression",
            oracle=OracleSpec(
                kind=kind,
                marker_role=role,
                description=(
                    "The exact input that reproduced the validated finding must no longer produce "
                    "its signal."
                ),
            ),
            expected_security_property=(
                f"The input that reproduced {finding_handle} must not reproduce it again."
            ),
            payloads=payloads,
            request_template=template,
            payload_field=payload_field,
            cwe=str(getattr(outcome, "cwe", "") or ""),
            rationale=(
                f"Generated from the reproduction record of {finding_handle}: "
                f"{getattr(outcome, 'detail', '')[:200]}"
            ),
            reproductions_required=1,
        )
    except Exception as exc:
        # A payload the spec validator rejects (a newline, an over-long value) cannot become a
        # regression test. Say so rather than silently producing none.
        logger.warning(
            "testing.regression_spec_rejected", handle=finding_handle, error=str(exc)[:200]
        )
        return None

    return TestPlan(
        spec=spec,
        plan_id=plan_id_for(spec, index_id=index_id),
        finding_handle=finding_handle,
        provenance={
            "from": "validated_finding",
            "finding": finding_handle,
            "pov_kind": pov_kind,
            "input_hash": str(getattr(outcome, "input_hash", "") or ""),
            "reproduction_count": int(getattr(outcome, "reproduction_count", 0) or 0),
        },
    )


def _oracle_for(pov_kind: str, override_kind: str, override_role: str) -> tuple[str, str]:
    if override_kind:
        return override_kind, override_role or "none"
    return {
        "command_injection": ("marker_in_stdout", "pov_marker"),
        "path_traversal": ("canary_content_in_stdout", "canary"),
        "length_boundary": ("exit_code_nonzero", "none"),
        "replay_request": ("exit_code_nonzero", "none"),
        "native_crash": ("sanitizer_report", "none"),
    }.get(pov_kind, ("exit_code_nonzero", "none"))


# ---------------------------------------------------------------------------
def artifact_for_target(
    *,
    plan: TestPlan,
    framework: str,
    descriptor: Any,
    finding_handle: str,
    location: str = "",
) -> RegressionArtifact | None:
    """Render the regression test in the target repository's own test convention."""
    spec = plan.spec
    request = dict(spec.request_template)
    if spec.payload_field and spec.payloads:
        request[spec.payload_field] = spec.payloads[0]

    if framework in ("pytest", "hypothesis"):
        return _pytest_artifact(spec, request, descriptor, finding_handle, location)
    if framework == "unittest":
        return _unittest_artifact(spec, request, descriptor, finding_handle, location)
    if framework in ("jest", "vitest", "mocha"):
        return _js_artifact(spec, request, descriptor, finding_handle, location)
    logger.info("testing.regression_artifact_unsupported", framework=framework)
    return None


def _entry_import(descriptor: Any) -> tuple[str, str]:
    module = getattr(descriptor, "entry_module", "") or ""
    callable_name = getattr(descriptor, "entry_callable", "") or ""
    return module, callable_name


def _assertion(spec: TestSpec) -> str:
    """The assertion body, from a fixed table keyed on the oracle."""
    return {
        "marker_in_stdout": (
            'assert MARKER not in rendered, (\n'
            '        "command injection reproduced: the injected marker reached stdout"\n'
            "    )"
        ),
        "canary_content_in_stdout": (
            'assert CANARY not in rendered, (\n'
            '        "path traversal reproduced: content from outside the asset root was read"\n'
            "    )"
        ),
        "exit_code_nonzero": (
            "assert ok, f\"the target crashed on this input: {error.splitlines()[-1] if error else ''}\""
        ),
        "exception_raised": (
            "assert ok, f\"the target raised on this input: {error.splitlines()[-1] if error else ''}\""
        ),
    }.get(spec.oracle.kind, "assert ok, \"the target failed on this input\"")


def _pytest_artifact(
    spec: TestSpec, request: dict[str, Any], descriptor: Any, handle: str, location: str
) -> RegressionArtifact:
    module, callable_name = _entry_import(descriptor)
    from app.discovery.base import CANARY_CONTENT, POV_MARKER

    content = f'''"""Regression test for {handle} — generated by KavachX.

This is the exact input that reproduced the vulnerability before the accompanying patch.
It must keep failing to reproduce it.

  finding  : {handle}
  location : {location or spec.target}
  cwe      : {spec.cwe or "unclassified"}
  property : {spec.expected_security_property}
"""

from __future__ import annotations

import json

from {module} import {callable_name}

MARKER = {json.dumps(POV_MARKER)}
CANARY = {json.dumps(CANARY_CONTENT)}

REQUEST = {json.dumps(request, indent=4, sort_keys=True)}


def test_regression_{handle.lower()}():
    """{spec.expected_security_property[:160]}"""
    ok, rendered, error = True, "", ""
    try:
        response = {callable_name}(REQUEST)
        rendered = json.dumps(response, default=str)
    except Exception as exc:  # noqa: BLE001 - the test asserts on the failure mode
        ok, error = False, f"{{type(exc).__name__}}: {{exc}}"

    {_assertion(spec)}
'''
    return RegressionArtifact(
        path=f"tests/test_kavachx_regression_{handle.lower()}.py",
        content=content,
        framework="pytest",
        sha256=sha256_text(content),
        rationale=(
            f"Preserves the reproduction of {handle} so the weakness cannot silently return. "
            "Written in the repository's existing pytest convention."
        ),
    )


def _unittest_artifact(
    spec: TestSpec, request: dict[str, Any], descriptor: Any, handle: str, location: str
) -> RegressionArtifact:
    module, callable_name = _entry_import(descriptor)
    from app.discovery.base import CANARY_CONTENT, POV_MARKER

    content = f'''"""Regression test for {handle} — generated by KavachX."""

from __future__ import annotations

import json
import unittest

from {module} import {callable_name}

MARKER = {json.dumps(POV_MARKER)}
CANARY = {json.dumps(CANARY_CONTENT)}
REQUEST = {json.dumps(request, indent=4, sort_keys=True)}


class KavachXRegression{handle.upper()}(unittest.TestCase):
    """{spec.expected_security_property[:160]}"""

    def test_does_not_reproduce(self):
        rendered = ""
        try:
            rendered = json.dumps({callable_name}(REQUEST), default=str)
        except Exception as exc:  # noqa: BLE001
            self.fail(f"the target raised on this input: {{type(exc).__name__}}: {{exc}}")
        self.assertNotIn(MARKER, rendered)
        self.assertNotIn(CANARY, rendered)


if __name__ == "__main__":
    unittest.main()
'''
    return RegressionArtifact(
        path=f"tests/test_kavachx_regression_{handle.lower()}.py",
        content=content,
        framework="unittest",
        sha256=sha256_text(content),
        rationale=f"Preserves the reproduction of {handle} in the repository's unittest convention.",
    )


def _js_artifact(
    spec: TestSpec, request: dict[str, Any], descriptor: Any, handle: str, location: str
) -> RegressionArtifact:
    from app.discovery.base import CANARY_CONTENT, POV_MARKER

    entry = getattr(descriptor, "entry_file", "") or spec.target.split(":")[0]
    content = f'''// Regression test for {handle} — generated by KavachX.
//
//   location : {location or spec.target}
//   cwe      : {spec.cwe or "unclassified"}
//   property : {spec.expected_security_property}
import {{ describe, it, expect }} from 'vitest';
import target from {json.dumps("../" + entry)};

const MARKER = {json.dumps(POV_MARKER)};
const CANARY = {json.dumps(CANARY_CONTENT)};
const REQUEST = {json.dumps(request, indent=2, sort_keys=True)};

describe('KavachX regression {handle}', () => {{
  it({json.dumps(spec.expected_security_property[:120])}, () => {{
    const fn = target.entrypoint || target.handle || target.main || target;
    const rendered = JSON.stringify(fn(REQUEST) ?? '');
    expect(rendered).not.toContain(MARKER);
    expect(rendered).not.toContain(CANARY);
  }});
}});
'''
    return RegressionArtifact(
        path=f"tests/kavachx-regression-{handle.lower()}.test.js",
        content=content,
        framework="vitest",
        sha256=sha256_text(content),
        rationale=f"Preserves the reproduction of {handle} in the repository's JS test convention.",
    )


# ---------------------------------------------------------------------------
@dataclass
class RegressionSuite:
    """Every regression plan and artifact a run produced."""

    plans: list[TestPlan] = field(default_factory=list)
    artifacts: list[RegressionArtifact] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def add(self, plan: TestPlan | None, artifact: RegressionArtifact | None) -> None:
        if plan is not None:
            self.plans.append(plan)
        if artifact is not None:
            self.artifacts.append(artifact)

    def write(self, workspace: Path) -> list[str]:
        """Write the artifacts into the workspace's generated-test directory.

        Written under ``_kavachx/`` rather than into ``tests/``: the target tree is the thing under
        analysis, and dropping files into it would change the pinned artifact and pollute a diff
        that is supposed to contain only the patch. The publisher places them at their intended
        ``path`` when a pull request is actually opened.
        """
        from app.testing.harness import HARNESS_DIR

        written: list[str] = []
        for artifact in self.artifacts:
            destination = workspace / HARNESS_DIR / "regression" / Path(artifact.path).name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(artifact.content, encoding="utf-8", newline="\n")
            written.append(str(destination.relative_to(workspace)).replace("\\", "/"))
        return written

    def as_dict(self) -> dict[str, Any]:
        return {
            "plans": [p.as_dict() for p in self.plans],
            "artifacts": [a.as_dict() for a in self.artifacts],
            "notes": self.notes,
        }
