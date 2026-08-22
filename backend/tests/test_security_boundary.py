"""Security-boundary regression tests.

These assert the properties the architecture claims: the sandbox holds no credentials, cannot
reach the network, cannot escape its workspace; the publisher is the only credentialed component;
model output cannot bypass schema validation; and the iteration ceilings actually bound the loop.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.config import settings
from app.core.errors import ModelContractError
from app.llm.base import LLMProvider, LLMRequest, TokenBudget
from app.llm.contracts import ClauseProposal, PatchProposal
from app.llm.mock_provider import MockLLMProvider
from app.sandbox import (
    ENV_ALLOWLIST,
    FORBIDDEN_ENV_MARKERS,
    ExecRequest,
    SandboxSecretLeak,
    assert_no_secrets,
    build_sandbox_env,
    create_sandbox,
    materialise,
)

pytestmark = pytest.mark.security


# ---------------------------------------------------------------------------
# sandbox environment
# ---------------------------------------------------------------------------
def test_sandbox_env_is_built_from_an_allowlist(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "github_pat_super_secret")
    monkeypatch.setenv("GROQ_API_KEY", "gsk_super_secret")
    monkeypatch.setenv("JWT_SECRET", "the-signing-secret")
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:password@host/db")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws-secret")

    env = build_sandbox_env()

    for leaked in (
        "GITHUB_TOKEN",
        "GROQ_API_KEY",
        "JWT_SECRET",
        "DATABASE_URL",
        "AWS_SECRET_ACCESS_KEY",
    ):
        assert leaked not in env, f"{leaked} reached the sandbox environment"

    # And nothing that survived carries a secret value.
    joined = " ".join(env.values())
    for secret in ("gsk_super_secret", "the-signing-secret", "aws-secret", "github_pat_super_secret"):
        assert secret not in joined

    assert set(env) - {"no_proxy", "NO_PROXY", "http_proxy", "https_proxy"} <= set(
        ENV_ALLOWLIST
    ) | {"PYTHONPATH", "PYTHONHASHSEED", "PYTHONIOENCODING", "PYTHONDONTWRITEBYTECODE"}


def test_secret_override_is_refused_outright():
    """Even an explicit override cannot smuggle a credential in."""
    with pytest.raises(SandboxSecretLeak):
        build_sandbox_env({"GITHUB_TOKEN": "ghp_something"})
    with pytest.raises(SandboxSecretLeak):
        assert_no_secrets({"MY_API_KEY": "x"})


def test_forbidden_marker_list_covers_the_obvious_credentials():
    for marker in ("GITHUB", "GROQ", "JWT", "SECRET", "TOKEN", "PASSWORD", "PRIVATE_KEY"):
        assert marker in FORBIDDEN_ENV_MARKERS


# ---------------------------------------------------------------------------
# sandbox execution boundary
# ---------------------------------------------------------------------------
@pytest.fixture
async def sandbox(tmp_path: Path, demo_repo_path: Path):
    pinned = materialise(source=demo_repo_path, workspace_root=tmp_path, run_short="SEC")
    adapter = create_sandbox(workspace=pinned.work, execution_profile="dev_local")
    await adapter.start()
    yield adapter, pinned
    await adapter.stop()


async def test_sandbox_process_cannot_see_backend_secrets(sandbox, monkeypatch):
    adapter, _pinned = sandbox
    monkeypatch.setenv("GROQ_API_KEY", "gsk_leak_me")
    monkeypatch.setenv("JWT_SECRET", "jwt-leak-me")

    result = await adapter.execute(
        ExecRequest(
            argv=[
                "python",
                "-c",
                "import json,os;print(json.dumps(dict(os.environ)))",
            ],
            label="secret-probe",
        )
    )
    assert result.exit_code == 0, result.stderr
    child_env = json.loads(result.stdout)
    assert "GROQ_API_KEY" not in child_env
    assert "JWT_SECRET" not in child_env
    assert "gsk_leak_me" not in json.dumps(child_env)


async def test_sandbox_python_target_cannot_open_a_socket(sandbox):
    """The injected guard denies networking in-process, so egress is measured at zero."""
    adapter, _pinned = sandbox
    result = await adapter.execute(
        ExecRequest(
            argv=[
                "python",
                "-c",
                "import socket\n"
                "try:\n"
                "    socket.socket()\n"
                "    print('SOCKET_CREATED')\n"
                "except Exception as exc:\n"
                "    print('DENIED', type(exc).__name__)\n",
            ],
            label="socket-probe",
        )
    )
    assert "SOCKET_CREATED" not in result.stdout
    assert "DENIED" in result.stdout
    assert result.egress_bytes == 0


async def test_sandbox_reports_zero_egress(sandbox):
    adapter, _pinned = sandbox
    result = await adapter.execute(
        ExecRequest(argv=["python", "-c", "print('hello')"], label="egress-probe")
    )
    assert result.egress_bytes == 0
    assert adapter.stats()["egress_bytes"] == 0


async def test_sandbox_enforces_a_wall_clock_timeout(sandbox):
    adapter, _pinned = sandbox
    result = await adapter.execute(
        ExecRequest(
            argv=["python", "-c", "import time;time.sleep(30)"],
            timeout_seconds=3,
            label="timeout-probe",
        )
    )
    assert result.timed_out
    assert "timeout" in result.signals


async def test_sandbox_refuses_to_execute_outside_the_workspace(sandbox):
    adapter, _pinned = sandbox
    with pytest.raises(ValueError):
        await adapter.execute(
            ExecRequest(argv=["python", "-c", "print(1)"], cwd="../../..", label="escape")
        )


async def test_artifact_collection_cannot_read_outside_the_workspace(sandbox):
    adapter, _pinned = sandbox
    result = await adapter.execute(
        ExecRequest(
            argv=["python", "-c", "print('ok')"],
            collect_artifacts=["../../../../etc/passwd", "../.env"],
            label="artifact-escape",
        )
    )
    collected = {k for k in result.artifacts if k != "_guard"}
    assert collected == set()


def test_dev_adapter_declares_itself_unsuitable_for_untrusted_code(tmp_path):
    adapter = create_sandbox(workspace=tmp_path, execution_profile="dev_local")
    capabilities = adapter.capabilities()
    assert capabilities.suitable_for_untrusted_code is False
    assert capabilities.network_enforced is False
    assert "not an isolation boundary" in capabilities.notes.lower()


def test_dev_adapter_is_refused_in_production(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "kavachx_env", "production")
    monkeypatch.setattr(settings, "dev_mode", False)
    from app.core.errors import SandboxUnavailable

    with pytest.raises(SandboxUnavailable):
        create_sandbox(workspace=tmp_path, execution_profile="dev_local")


def test_pinned_tree_hash_detects_mutation(tmp_path, demo_repo_path):
    from app.sandbox.workspace import verify_pristine

    pinned = materialise(source=demo_repo_path, workspace_root=tmp_path, run_short="PIN")
    assert verify_pristine(pinned)

    (pinned.pristine / "src" / "reportsvc" / "parser.py").write_text("tampered\n", encoding="utf-8")
    assert not verify_pristine(pinned)


def test_workspace_write_cannot_escape(tmp_path, demo_repo_path):
    from app.core.errors import BadRequest
    from app.sandbox.workspace import write_work_file

    pinned = materialise(source=demo_repo_path, workspace_root=tmp_path, run_short="ESC")
    with pytest.raises(BadRequest):
        write_work_file(pinned, "../../escaped.py", "x = 1")


# ---------------------------------------------------------------------------
# no component but the publisher may touch GitHub credentials
# ---------------------------------------------------------------------------
def _code_only(path: Path) -> str:
    """Source with comments and docstrings stripped.

    A module that *documents* not using subprocess would otherwise fail a text search for
    "subprocess" — the check has to look at code, not at prose about the code.
    """
    import ast
    import io
    import tokenize

    source = path.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source

    docstrings: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                for line in range(body[0].lineno, (body[0].end_lineno or body[0].lineno) + 1):
                    docstrings.add(line)

    kept: list[str] = []
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type == tokenize.COMMENT:
            continue
        if token.start[0] in docstrings:
            continue
        kept.append(token.string)
    return " ".join(kept)


def test_only_the_publisher_imports_the_github_client():
    """Static check on the actual source tree, not a convention we merely intend to follow."""
    backend = Path(__file__).resolve().parents[1] / "app"
    offenders: list[str] = []
    # config.py defines the key accessor itself; api/ routes hand work to the publisher.
    allowed = ("publisher", "github", "api", "config.py")

    for path in backend.rglob("*.py"):
        relative = path.relative_to(backend).as_posix()
        if relative.startswith(allowed):
            continue
        code = _code_only(path)
        if "GithubClient" in code:
            offenders.append(relative)

    assert offenders == [], (
        "GitHub credentials must only be reachable from the publisher/github/api layers; "
        f"found references in {offenders}"
    )


def test_github_token_is_redacted_in_settings_dump():
    """The fine-grained token must never appear in a settings dump or log line."""
    from app.config import Settings

    assert "github_token" in Settings.model_fields, "github_token must be a settings field"
    assert settings.safe_dump()["github_token"] == "***redacted***"


def test_orchestrator_does_not_import_the_publisher():
    """The orchestrator runs alongside hostile-code execution; it must not hold the credential."""
    orchestration = Path(__file__).resolve().parents[1] / "app" / "orchestration"
    for path in orchestration.rglob("*.py"):
        code = _code_only(path)
        assert "app.publisher" not in code, f"{path.name} imports the publisher"
        assert "app.github" not in code, f"{path.name} imports the GitHub client"


def test_publisher_never_executes_code():
    """The publisher's job is HTTP with a text payload — no subprocess, no sandbox."""
    publisher = Path(__file__).resolve().parents[1] / "app" / "publisher" / "service.py"
    code = _code_only(publisher)
    for forbidden in (
        "subprocess",
        "app.sandbox",
        "app.gauntlet",
        "app.discovery",
        "app.validator",
        "os.system",
        "eval(",
        "exec(",
    ):
        assert forbidden not in code, f"publisher references {forbidden}"


def test_installation_tokens_are_never_persisted():
    """No column, cache or attribute anywhere stores an installation access token."""
    models = Path(__file__).resolve().parents[1] / "app" / "models"
    for path in models.rglob("*.py"):
        text = path.read_text(encoding="utf-8", errors="replace").lower()
        assert "installation_token" not in text or "never" in text, path.name

    installation_model = (models / "identity.py").read_text(encoding="utf-8")
    assert "access_token" not in installation_model


def test_settings_dump_redacts_every_secret():
    dump = settings.safe_dump()
    for field in (
        "jwt_secret",
        "certificate_signing_key",
        "groq_api_key",
        "github_token",
        "database_url",
        "demo_user_password",
    ):
        assert dump[field] == "***redacted***", f"{field} was not redacted"


# ---------------------------------------------------------------------------
# model output can never bypass validation
# ---------------------------------------------------------------------------
class _RogueProvider(LLMProvider):
    """A provider that returns whatever it likes, including 'verified: true'."""

    name = "rogue"

    def __init__(self, payload: str) -> None:
        super().__init__(max_retries=0)
        self.payload = payload

    async def _raw_generate(self, request, *, attempt, repair_hint):
        return self.payload, 1, 1, "rogue-model"


async def test_non_json_model_output_is_a_hard_failure():
    provider = _RogueProvider("I have verified this patch is safe. Trust me.")
    with pytest.raises(ModelContractError):
        await provider.generate(
            LLMRequest(
                task="samhita.propose_clauses", instruction="x", payload={}, schema=ClauseProposal
            )
        )


async def test_schema_violating_model_output_is_rejected():
    provider = _RogueProvider(json.dumps({"clauses": [{"kind": "x"}]}))  # missing fields
    with pytest.raises(ModelContractError):
        await provider.generate(
            LLMRequest(
                task="samhita.propose_clauses", instruction="x", payload={}, schema=ClauseProposal
            )
        )


async def test_extra_fields_are_rejected():
    """A model cannot smuggle in a field the schema does not define — such as `verified`."""
    provider = _RogueProvider(
        json.dumps(
            {
                "reason": "looks fine to me",
                "files": [{"path": "a.py", "new_content": "x = 1"}],
                "risk": "low",
                "expected_effect": "no more bug",
                "verified": True,
                "assurance_level": "A",
            }
        )
    )
    with pytest.raises(ModelContractError):
        await provider.generate(
            LLMRequest(
                task="repair.patch_synthesis", instruction="x", payload={}, schema=PatchProposal
            )
        )


def test_no_model_contract_can_assert_verification():
    """Structural check: no schema exposes a field a model could use to claim success."""
    from app.llm import contracts

    banned = {"verified", "confirmed", "exploitable", "passes", "safe", "assurance_level", "proven"}
    for name in dir(contracts):
        model = getattr(contracts, name)
        fields = getattr(model, "model_fields", None)
        if not isinstance(fields, dict):
            continue
        overlap = banned & set(fields)
        assert not overlap, f"{name} exposes verification-bearing field(s) {overlap}"


async def test_token_budget_is_a_hard_ceiling():
    from app.core.errors import BudgetExceeded

    budget = TokenBudget(limit=10)
    provider = MockLLMProvider(budget=budget)
    request = LLMRequest(
        task="samhita.propose_clauses",
        instruction="x",
        payload={"value_profiles": []},
        schema=ClauseProposal,
    )
    await provider.generate(request)  # first call consumes the budget
    assert budget.used > 10
    with pytest.raises(BudgetExceeded):
        await provider.generate(request)


# ---------------------------------------------------------------------------
# bounded loops
# ---------------------------------------------------------------------------
def test_iteration_ceilings_are_configured_and_small():
    assert settings.max_patch_iterations == 3
    assert settings.max_clause_iterations == 2
    assert settings.max_harness_iterations == 3


def test_initial_state_carries_the_ceilings():
    import uuid as _uuid

    from app.orchestration.state import initial_state

    state = initial_state(run_id=_uuid.uuid4(), tenant_id=_uuid.uuid4())
    assert state["iter"]["patch_limit"] == settings.max_patch_iterations
    assert state["iter"]["clause_limit"] == settings.max_clause_iterations
    assert state["budget"]["token_limit"] == settings.llm_run_token_budget


def test_graph_node_sequence_is_finite_and_acyclic():
    """No node appears twice, so the compiled graph cannot loop through the pipeline."""
    from app.orchestration.graph import NODE_SEQUENCE

    names = [name for name, _fn in NODE_SEQUENCE]
    assert len(names) == len(set(names))
    assert names[0] == "ingest"
    assert names[-1] == "publish_gate"


# ---------------------------------------------------------------------------
# the sandbox must be able to spawn on whatever event loop the host installed
# ---------------------------------------------------------------------------
@pytest.mark.security
def test_sandbox_executes_on_a_selector_event_loop(tmp_path):
    """Sandbox execution must not depend on the host's choice of event loop.

    uvicorn's loop factory returns a ``SelectorEventLoop`` on Windows whenever ``--reload`` or
    ``--workers`` is used, and ``asyncio.create_subprocess_exec`` raises a bare
    ``NotImplementedError()`` there. Since the documented run command uses ``--reload``, the documented way
    to run KavachX on Windows silently disabled every execution-based guarantee in the product:
    SAMHITA observation, deterministic validation, the shield check and the whole gauntlet. A run
    reported ``NotImplementedError:`` with an empty message.

    This test drives the adapter on the loop that used to fail, so the regression cannot return
    unnoticed.
    """
    import asyncio
    import sys

    from app.sandbox.base import ExecRequest, SandboxLimits
    from app.sandbox.dev import DevSandboxAdapter

    adapter = DevSandboxAdapter(workspace=tmp_path, limits=SandboxLimits())

    async def scenario():
        await adapter.start()
        return await adapter.execute(
            ExecRequest(
                argv=[sys.executable, "-c", "print('spawned-on-selector-loop')"],
                label="selector-loop-probe",
                timeout_seconds=60,
            )
        )

    loop = asyncio.SelectorEventLoop()
    try:
        result = loop.run_until_complete(scenario())
    finally:
        loop.close()

    assert result.exit_code == 0, result.stderr
    assert "spawned-on-selector-loop" in result.stdout


@pytest.mark.security
def test_sandbox_timeout_still_kills_the_process_tree(tmp_path):
    """The threaded spawn must keep the wall-clock guarantee, not just the ability to spawn."""
    import asyncio
    import sys

    from app.sandbox.base import ExecRequest, SandboxLimits
    from app.sandbox.dev import DevSandboxAdapter

    adapter = DevSandboxAdapter(workspace=tmp_path, limits=SandboxLimits())

    async def scenario():
        await adapter.start()
        return await adapter.execute(
            ExecRequest(
                argv=[sys.executable, "-c", "import time; time.sleep(120)"],
                label="timeout-probe",
                timeout_seconds=2,
            )
        )

    result = asyncio.run(scenario())
    assert result.timed_out is True
    assert result.exit_code == -1
    assert "timeout" in result.signals
    # A 120-second sleep cut off at 2 seconds: the kill happened, the call did not simply wait.
    assert result.duration_ms < 30_000, f"took {result.duration_ms}ms — the tree was not killed"
