"""`.env` parsing and workspace provisioning."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.dotenv import parse_dotenv
from app.sandbox import create_sandbox
from app.sandbox.provision import provision

pytestmark = pytest.mark.security


def test_parse_dotenv_handles_common_shapes():
    text = """
    # a comment
    export DATABASE_URL=postgres://u:p@h/db
    API_KEY="sk-123 with spaces"
    QUOTED='single value'
    INLINE=bar  # trailing note
    HASH_IN_QUOTES="a#b"
    EMPTY=
    DUP=one
    DUP=two
    not a valid line
    """
    env = parse_dotenv(text)
    assert env["DATABASE_URL"] == "postgres://u:p@h/db"
    assert env["API_KEY"] == "sk-123 with spaces"
    assert env["QUOTED"] == "single value"
    assert env["INLINE"] == "bar"
    assert env["HASH_IN_QUOTES"] == "a#b"
    assert env["EMPTY"] == ""
    assert env["DUP"] == "two"  # later wins
    assert "not a valid line" not in env


def test_parse_dotenv_expands_double_quote_escapes():
    assert parse_dotenv('X="line1\\nline2"')["X"] == "line1\nline2"


async def test_provision_runs_install_command_in_the_workspace(tmp_path: Path):
    adapter = create_sandbox(workspace=tmp_path, execution_profile="dev_local")
    await adapter.start()
    try:
        report = await provision(
            adapter,
            commands=[("install", "echo installing> provisioned.txt")],
        )
        assert report.ok is True
        assert report.steps[0].label == "install"
        assert report.steps[0].ok is True
        # The command ran in the workspace — the artifact it wrote is there.
        assert (tmp_path / "provisioned.txt").is_file()
    finally:
        await adapter.stop()


async def test_provision_reports_a_failing_step_without_raising(tmp_path: Path):
    adapter = create_sandbox(workspace=tmp_path, execution_profile="dev_local")
    await adapter.start()
    try:
        report = await provision(
            adapter,
            commands=[("install", "exit 3"), ("build", "echo built> built.txt")],
        )
        # Failure is recorded, not raised, and later steps still run.
        assert report.ok is False
        assert report.steps[0].ok is False
        assert report.steps[0].exit_code == 3
        assert any("install" in note for note in report.notes)
        assert (tmp_path / "built.txt").is_file()
    finally:
        await adapter.stop()
