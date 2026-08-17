"""Sandbox: the boundary between KavachX and hostile code."""

from app.sandbox.base import (
    ENV_ALLOWLIST,
    FORBIDDEN_ENV_MARKERS,
    ExecRequest,
    ExecResult,
    SandboxAdapter,
    SandboxCapabilities,
    SandboxLimits,
    SandboxSecretLeak,
    assert_no_secrets,
    build_sandbox_env,
    extract_signals,
)
from app.sandbox.factory import create_sandbox, default_limits, describe_available
from app.sandbox.workspace import PinnedSource, materialise, reset_work

__all__ = [
    "ENV_ALLOWLIST",
    "FORBIDDEN_ENV_MARKERS",
    "ExecRequest",
    "ExecResult",
    "PinnedSource",
    "SandboxAdapter",
    "SandboxCapabilities",
    "SandboxLimits",
    "SandboxSecretLeak",
    "assert_no_secrets",
    "build_sandbox_env",
    "create_sandbox",
    "default_limits",
    "describe_available",
    "extract_signals",
    "materialise",
    "reset_work",
]
