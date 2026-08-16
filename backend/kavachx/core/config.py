"""
Application settings for KavachX.

Every value is read from `backend/.env` (see `.env.example`) with a safe
development default, so the API boots before any secret is filled in.
"""

import os
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# kavachx/core/config.py -> kavachx/core -> kavachx -> backend/
BACKEND_DIR = Path(__file__).resolve().parents[2]
ENV_FILE = BACKEND_DIR / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── API ───────────────────────────────────────────────────────────────
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_reload: bool = True
    log_level: str = "info"

    # ── CORS ──────────────────────────────────────────────────────────────
    # Comma-separated list of browser origins allowed to call this API.
    # Use the exact origins the frontend is served from — "*" disables
    # credentialed requests (browsers refuse wildcard + credentials).
    cors_allow_origins: str = (
        "http://localhost:5173,http://127.0.0.1:5173,"
        "http://localhost:4173,http://127.0.0.1:4173"
    )
    cors_allow_credentials: bool = True
    cors_allow_methods: str = "*"
    cors_allow_headers: str = "*"

    # ── Auth ──────────────────────────────────────────────────────────────
    # When false (dev default) the dashboard endpoints accept a `role` query
    # parameter instead of a session JWT. Flip to true once the GitHub App
    # login flow is wired into the frontend.
    auth_required: bool = False
    demo_tenant_id: str = "demo-tenant"

    jwt_secret: str = "change-me"
    jwt_expiry_seconds: int = 3600
    cert_signing_secret: str = "change-me"

    github_app_id: str = ""
    github_app_private_key_path: str = ""
    github_app_webhook_secret: str = ""

    # ── Database ──────────────────────────────────────────────────────────
    database_url: str = "postgresql+asyncpg://kavachx:kavachx@localhost:5432/kavachx"

    # ── Sandbox / artifacts ───────────────────────────────────────────────
    sandbox_runtime: str = "gvisor"
    sandbox_scratch_dir: str = "/tmp/kavachx-sandbox"
    artifact_store_path: str = "/var/kavachx/artifacts"

    # ── Run engine ────────────────────────────────────────────────────────
    max_concurrent_runs: int = 2
    # Delay between pipeline phases, in seconds. Keeps the SSE trace readable
    # in the UI while the analysis backends are still stubs.
    run_tick_seconds: float = 0.8
    # Seconds between SSE keepalive comments.
    sse_keepalive_seconds: float = 15.0

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.cors_allow_origins.split(",") if o.strip()]

    @property
    def cors_methods(self) -> list[str]:
        return [m.strip() for m in self.cors_allow_methods.split(",") if m.strip()]

    @property
    def cors_headers(self) -> list[str]:
        return [h.strip() for h in self.cors_allow_headers.split(",") if h.strip()]

    @property
    def allow_credentials(self) -> bool:
        # A wildcard origin and credentials are mutually exclusive per the
        # CORS spec — browsers reject the combination outright.
        return self.cors_allow_credentials and "*" not in self.cors_origins


@lru_cache
def get_settings() -> Settings:
    return Settings()


def export_to_environ() -> None:
    """
    Mirror settings into os.environ for modules that read os.environ directly
    (e.g. kavachx.api.routes.auth reads GITHUB_APP_ID at import time).
    Existing environment variables always win.
    """
    settings = get_settings()
    for field_name in Settings.model_fields:
        key = field_name.upper()
        if key in os.environ:
            continue
        value = getattr(settings, field_name)
        os.environ[key] = "" if value is None else str(value)
