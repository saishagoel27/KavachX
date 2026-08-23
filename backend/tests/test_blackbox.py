"""Language-agnostic black-box observation, exercised against a non-Python (Node.js) target.

Proves the black-box harness can execute an opaque request->output CLI in another language through
the same sandbox and deterministically observe an exploit reproducing — a crash, a planted marker
echoed by an injected command, or a canary file's content leaking through path traversal — with no
Python tracer involved.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from app.sandbox import create_sandbox, materialise
from app.sandbox.blackbox import observe

REPO_ROOT = Path(__file__).resolve().parents[2]
NODE_DEMO = REPO_ROOT / "examples" / "vulnerable-node-demo"

pytestmark = pytest.mark.security

_NODE = shutil.which("node")
requires_node = pytest.mark.skipif(_NODE is None, reason="node is not installed on PATH")


def _argv(request: dict) -> list[str]:
    return ["node", "cli.js", "--request", json.dumps(request, sort_keys=True)]


@requires_node
async def test_blackbox_benign_request_shows_no_effect(tmp_path: Path):
    pinned = materialise(source=NODE_DEMO, workspace_root=tmp_path, run_short="BBN")
    adapter = create_sandbox(workspace=pinned.work, execution_profile="dev_local")
    await adapter.start()
    try:
        obs = await observe(
            adapter,
            argv=_argv({"op": "ping"}),
            case_id="ping",
            watch_tokens=["KAVACHX_"],
            timeout_seconds=30,
        )
        assert obs.exit_code == 0
        assert not obs.crashed
        assert obs.tokens_seen == []
        assert obs.files_created == []
        assert obs.observed_effect is False
    finally:
        await adapter.stop()


@requires_node
async def test_blackbox_reproduces_command_injection(tmp_path: Path):
    pinned = materialise(source=NODE_DEMO, workspace_root=tmp_path, run_short="BBN")
    adapter = create_sandbox(workspace=pinned.work, execution_profile="dev_local")
    await adapter.start()
    try:
        marker = "KAVACHX_MARKER_bb01"
        # Which shell separator works depends on the host shell (';' on sh, '&' on cmd.exe) — let
        # execution decide, exactly as the real validator does.
        reproduced = None
        for sep in ("&", ";", "|"):
            obs = await observe(
                adapter,
                argv=_argv({"op": "export", "name": f"rep {sep} echo {marker}"}),
                case_id=f"inject-{sep}",
                watch_tokens=[marker],
                timeout_seconds=30,
            )
            if marker in obs.tokens_seen:
                reproduced = obs
                break
        assert reproduced is not None, "command injection was not reproduced by any separator"
        assert reproduced.observed_effect is True
    finally:
        await adapter.stop()


@requires_node
async def test_blackbox_reproduces_path_traversal(tmp_path: Path):
    pinned = materialise(source=NODE_DEMO, workspace_root=tmp_path, run_short="BBN")
    adapter = create_sandbox(workspace=pinned.work, execution_profile="dev_local")
    await adapter.start()
    try:
        # Plant a canary one level above the asset root; a confined reader can never reach it.
        canary = "KAVACHX_CANARY_bb02_secret_value"
        (pinned.work / "canary.txt").write_text(canary, encoding="utf-8")
        obs = await observe(
            adapter,
            argv=_argv({"op": "read_asset", "path": "../canary.txt"}),
            case_id="traverse",
            watch_tokens=[canary],
            timeout_seconds=30,
        )
        assert canary in obs.tokens_seen, "path traversal did not leak the canary"
        assert obs.observed_effect is True
    finally:
        await adapter.stop()
