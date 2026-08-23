"""HTTP black-box observation against a long-running Node.js server target."""

from __future__ import annotations

import shutil
from pathlib import Path
from urllib.parse import quote

import pytest

from app.sandbox import materialise
from app.sandbox.http_blackbox import observe_http

REPO_ROOT = Path(__file__).resolve().parents[2]
WEB_DEMO = REPO_ROOT / "examples" / "vulnerable-web-demo"

pytestmark = pytest.mark.security

requires_node = pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")


@requires_node
async def test_http_harness_starts_server_and_reproduces_vulns(tmp_path: Path):
    pinned = materialise(source=WEB_DEMO, workspace_root=tmp_path, run_short="WEB")
    # Plant a canary above the asset root; a confined reader can never reach it.
    canary = "KAVACHX_WEB_CANARY_secret_value"
    (pinned.work / "canary.txt").write_text(canary, encoding="utf-8")

    marker = "KAVACHX_WEB_MARK_77aa"
    injection = quote(f"rep & echo {marker}")
    requests = [
        {"method": "GET", "path": "/ping"},
        {"method": "GET", "path": f"/export?name={injection}"},
        {"method": "GET", "path": "/asset?path=../canary.txt"},
    ]

    result = await observe_http(
        start_argv=["node", "server.js"],
        workspace=pinned.work,
        requests=requests,
        watch_tokens=[marker, canary],
        ready_timeout=30.0,
    )

    assert result.ready, f"server never became ready: {result.reason} / {result.server_stderr}"
    by_path = {o.path: o for o in result.observations}

    # Benign request: healthy, no planted token.
    ping = by_path["/ping"]
    assert ping.status == 200
    assert ping.tokens_seen == []

    # Command injection: the injected marker is echoed back in the response body.
    inject = by_path[f"/export?name={injection}"]
    assert marker in inject.tokens_seen, f"injection not reproduced: {inject.body!r}"

    # Path traversal: the canary planted outside the asset root leaks into the response.
    traverse = by_path["/asset?path=../canary.txt"]
    assert canary in traverse.tokens_seen, f"traversal not reproduced: {traverse.body!r}"
