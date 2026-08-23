"""Run-plan / framework detection."""

from __future__ import annotations

import json
from pathlib import Path

from app.analysis.framework import detect_run_plan


def test_bare_python_cli_is_dynamically_analyzable(demo_repo_path: Path):
    plan = detect_run_plan(demo_repo_path)
    assert plan.language == "python"
    assert plan.kind == "cli"
    assert plan.dynamically_analyzable is True
    assert "command-line" in plan.reason


def test_nextjs_web_app_is_detected_but_static_only(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "poll",
                "dependencies": {"next": "16.0.0", "react": "19.0.0"},
                "scripts": {"dev": "next dev", "build": "next build", "start": "next start"},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "tsconfig.json").write_text("{}", encoding="utf-8")

    plan = detect_run_plan(tmp_path)
    assert plan.language == "typescript"
    assert plan.kind == "web_service"
    assert "next" in plan.frameworks
    assert plan.run_command == ["npm", "run", "start"]
    # No JS tracing harness, so it is detected but never executed.
    assert plan.dynamically_analyzable is False
    assert "statically" in plan.reason


def test_rust_soroban_is_a_smart_contract(tmp_path: Path):
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "poll"\n[dependencies]\nsoroban-sdk = "21.0"\n',
        encoding="utf-8",
    )
    plan = detect_run_plan(tmp_path)
    assert plan.language == "rust"
    assert plan.kind == "smart_contract"
    assert plan.dynamically_analyzable is False


def test_python_web_framework_is_web_service(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("fastapi==0.115\nuvicorn\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    plan = detect_run_plan(tmp_path)
    assert plan.language == "python"
    assert plan.kind == "web_service"
    assert "fastapi" in plan.frameworks
    # Python, but a long-running service with no request→output CLI: static-only.
    assert plan.dynamically_analyzable is False


def test_monorepo_finds_nested_subprojects(tmp_path: Path):
    # A polyglot monorepo: a Next.js frontend, a FastAPI service, and a Soroban contract nested
    # two levels deep — the kind of layout that used to come back "unknown".
    (tmp_path / "frontend").mkdir()
    (tmp_path / "frontend" / "package.json").write_text(
        json.dumps({"dependencies": {"next": "16"}, "scripts": {"dev": "next dev"}}),
        encoding="utf-8",
    )
    (tmp_path / "services" / "api").mkdir(parents=True)
    (tmp_path / "services" / "api" / "requirements.txt").write_text("fastapi\n", encoding="utf-8")
    (tmp_path / "contracts" / "poll").mkdir(parents=True)
    (tmp_path / "contracts" / "poll" / "Cargo.toml").write_text(
        '[package]\nname = "poll"\n[dependencies]\nsoroban-sdk = "21"\n', encoding="utf-8"
    )

    plan = detect_run_plan(tmp_path)
    assert len(plan.subprojects) >= 3, plan.subprojects
    kinds = {sp["kind"] for sp in plan.subprojects}
    assert {"web_service", "smart_contract"} <= kinds
    assert any(sp["language"] == "python" for sp in plan.subprojects)
    # Primary is the most security-relevant surface — the contract.
    assert plan.kind == "smart_contract"
    assert plan.dynamically_analyzable is False


def test_monorepo_with_a_nested_python_cli_is_analyzable(tmp_path: Path):
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "package.json").write_text(
        json.dumps({"dependencies": {"next": "16"}, "scripts": {"dev": "next dev"}}),
        encoding="utf-8",
    )
    (tmp_path / "tools" / "cli").mkdir(parents=True)
    (tmp_path / "tools" / "cli" / "pyproject.toml").write_text(
        '[project]\nname = "t"\n[project.scripts]\nt = "t:main"\n', encoding="utf-8"
    )

    plan = detect_run_plan(tmp_path)
    # A Python CLI exists somewhere in the tree, so the harness gate can reach it.
    assert plan.dynamically_analyzable is True
    assert "command-line target at tools" in plan.reason


def test_readme_commands_are_extracted(tmp_path: Path):
    (tmp_path / "go.mod").write_text("module poll\n\ngo 1.22\n", encoding="utf-8")
    (tmp_path / "main.go").write_text("package main\nfunc main() {}\n", encoding="utf-8")
    (tmp_path / "README.md").write_text(
        "# Poll\n\n## Install\n\n```\ngo mod download\n```\n\n## Run\n\n    go run .\n\nSome prose.\n",
        encoding="utf-8",
    )
    plan = detect_run_plan(tmp_path)
    assert plan.language == "go"
    assert plan.kind == "cli"
    assert any("go mod download" in c for c in plan.readme_commands)
    assert any("go run ." in c for c in plan.readme_commands)
