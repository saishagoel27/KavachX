"""Central configuration.

Every tunable in KavachX lands here so that the security-relevant knobs (sandbox limits,
token budgets, iteration ceilings, credential locations) are auditable in one place.
"""

from __future__ import annotations

import functools
from pathlib import Path
from typing import Literal

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# backend/app/config.py -> backend/app -> backend -> <repo root>
REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = Path(__file__).resolve().parents[1]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(REPO_ROOT / ".env", BACKEND_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- core --------------------------------------------------------------
    kavachx_env: Literal["development", "test", "production"] = "development"
    dev_mode: bool = True
    log_level: str = "INFO"
    #: ``console`` gives logifyx's colour-coded human format; ``json`` gives one JSON object per
    #: line for log aggregation. Left unset, it follows ``dev_mode`` — see ``_default_log_format``.
    #:
    #: logifyx ties the two together: its console handler is built with
    #: ``get_formatter(json_mode, color)`` while the file handler always gets ``color=False``. So
    #: ``json_mode=True`` selects the JSON formatter for *both* sinks and ignores ``color``
    #: entirely. Colour is therefore only available in ``console`` format — the two are one switch,
    #: not two.
    log_format: Literal["json", "console"] | None = None
    api_prefix: str = "/api"

    # --- database ----------------------------------------------------------
    database_url: str = "postgresql+asyncpg://kavachx:kavachx@localhost:5433/kavachx"
    db_echo: bool = False
    db_pool_size: int = 10
    #: Migrate to head and seed the demo tenant during application startup, so starting the API
    #: against an empty database cannot produce the "relation does not exist" class of 500. Both
    #: steps are no-ops once done. Turn it off where schema changes are a deploy step of their own.
    db_auto_provision: bool = True
    #: How long startup provisioning waits for the database to accept connections.
    db_startup_wait_seconds: int = 15

    # --- auth --------------------------------------------------------------
    jwt_secret: str = "change-me-in-production-please-use-a-long-random-value"
    jwt_algorithm: str = "HS256"
    access_token_ttl_seconds: int = 1800
    refresh_token_ttl_seconds: int = 1_209_600
    password_min_length: int = 12

    certificate_signing_key: str = "change-me-certificate-signing-key"

    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"

    # --- llm ---------------------------------------------------------------
    # groq  : hosted Groq inference (default)
    # llama : llama.cpp / any OpenAI-compatible server — the local, air-gapped path
    # mock  : deterministic scripted proposer (offline, used by the test suite)
    llm_provider: Literal["groq", "llama", "mock"] = "groq"
    llm_timeout_seconds: int = 120
    llm_max_retries: int = 2
    llm_max_output_tokens: int = 2048
    llm_temperature: float = 0.1
    llm_run_token_budget: int = 400_000
    #: Fall back to the deterministic mock proposer if the configured provider is
    #: unreachable or has no key, instead of failing the whole run.
    llm_fallback_to_mock: bool = True

    # Groq
    groq_api_key: str = ""
    groq_base_url: str = "https://api.groq.com"
    groq_model_workhorse: str = "llama-3.3-70b-versatile"
    groq_model_router: str = "llama-3.1-8b-instant"
    groq_model_security: str = "llama-3.3-70b-versatile"

    # llama.cpp / OpenAI-compatible local server
    llama_base_url: str = "http://localhost:8080/v1"
    llama_api_key: str = ""
    llama_model_workhorse: str = "Qwen3-Coder-30B-A3B"
    llama_model_router: str = "Qwen3-4B"
    llama_model_security: str = "Foundation-Sec-8B-Reasoning"

    # --- sandbox -----------------------------------------------------------
    sandbox_adapter: Literal["dev", "gvisor", "firecracker"] = "dev"
    sandbox_image: str = "kavachx/sandbox:dev"
    sandbox_cpu_limit: float = 2.0
    sandbox_memory_mb: int = 2048
    sandbox_pid_limit: int = 256
    sandbox_disk_mb: int = 1024
    sandbox_wall_clock_seconds: int = 120
    sandbox_workspace_root: str = ""

    # --- orchestrator ------------------------------------------------------
    max_harness_iterations: int = 3
    max_patch_iterations: int = 3
    max_clause_iterations: int = 2
    run_max_runtime_seconds: int = 1800

    # --- github (fine-grained personal access token) -----------------------
    # A fine-grained PAT with Contents: read/write and Pull requests: read/write, scoped to the
    # repositories KavachX may open pull requests against. There is no GitHub App path.
    github_token: str = ""
    github_api_base: str = "https://api.github.com"
    publisher_dry_run: bool = True

    # --- demo seed ---------------------------------------------------------
    seed_demo: bool = True
    demo_user_email: str = "demo@kavachx.io"
    demo_user_password: str = "kavachx-demo-2024"
    demo_org_name: str = "Kavach Research"
    demo_repo_path: str = ""

    # ------------------------------------------------------------------
    @field_validator("log_level")
    @classmethod
    def _upper(cls, v: str) -> str:
        return v.upper()

    @model_validator(mode="after")
    def _default_log_format(self) -> Settings:
        """Colour for humans in development, JSON for machines in production.

        A developer watching a run wants to spot an ERROR at a glance; an aggregator wants parseable
        records. Defaulting to JSON served neither well locally, and since logifyx's ``color`` flag
        does nothing while ``json_mode`` is on, the effect was a wall of uncoloured JSON with no
        obvious way to change it. An explicit ``LOG_FORMAT`` always wins.
        """
        if self.log_format is None:
            object.__setattr__(self, "log_format", "console" if self.dev_mode else "json")
        return self

    # ------------------------------------------------------------------
    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def repo_root(self) -> Path:
        return REPO_ROOT

    @property
    def workspace_root(self) -> Path:
        """Root under which every sandbox workspace is materialised."""
        if self.sandbox_workspace_root:
            root = Path(self.sandbox_workspace_root)
        else:
            root = REPO_ROOT / ".kavachx" / "workspaces"
        root.mkdir(parents=True, exist_ok=True)
        return root

    @property
    def source_cache_root(self) -> Path:
        """Extracted public repository sources, keyed by commit SHA.

        A commit SHA pins content immutably, so the same key can never mean two different trees —
        which makes re-downloading it pure waste. It is also what trips GitHub's archive throttle:
        repeated runs against one repository hammer codeload for bytes that cannot have changed.
        """
        root = REPO_ROOT / ".kavachx" / "source-cache"
        root.mkdir(parents=True, exist_ok=True)
        return root

    @property
    def artifact_root(self) -> Path:
        root = REPO_ROOT / ".kavachx" / "artifacts"
        root.mkdir(parents=True, exist_ok=True)
        return root

    @property
    def demo_repo_dir(self) -> Path:
        if self.demo_repo_path:
            return Path(self.demo_repo_path).resolve()
        return (REPO_ROOT / "examples" / "vulnerable-demo").resolve()

    @property
    def llm_models(self) -> dict[str, str]:
        """Model ids for the workhorse / router / security roles of the active provider."""
        if self.llm_provider == "groq":
            return {
                "workhorse": self.groq_model_workhorse,
                "router": self.groq_model_router,
                "security": self.groq_model_security,
            }
        if self.llm_provider == "llama":
            return {
                "workhorse": self.llama_model_workhorse,
                "router": self.llama_model_router,
                "security": self.llama_model_security,
            }
        return {"workhorse": "mock-proposer", "router": "mock-router", "security": "mock-sec"}

    @property
    def llm_configured(self) -> bool:
        if self.llm_provider == "groq":
            return bool(self.groq_api_key)
        if self.llm_provider == "llama":
            return bool(self.llama_base_url)
        return True

    @property
    def github_configured(self) -> bool:
        return bool(self.github_token)

    def safe_dump(self) -> dict[str, object]:
        """Settings snapshot with every secret redacted — safe for logs and /health."""
        secret_fields = {
            "jwt_secret",
            "certificate_signing_key",
            "groq_api_key",
            "llama_api_key",
            "github_token",
            "demo_user_password",
            "database_url",
        }
        out: dict[str, object] = {}
        for name in type(self).model_fields:
            out[name] = "***redacted***" if name in secret_fields else getattr(self, name)
        return out


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
