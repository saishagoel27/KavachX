"""Sandbox adapter selection."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.config import settings
from app.core.errors import SandboxUnavailable
from app.core.logging import get_logger
from app.models.enums import ExecutionProfile
from app.sandbox.base import SandboxAdapter, SandboxLimits
from app.sandbox.dev import DevSandboxAdapter
from app.sandbox.firecracker import FirecrackerSandboxAdapter
from app.sandbox.gvisor import GvisorSandboxAdapter

logger = get_logger(__name__)

_PROFILE_TO_ADAPTER = {
    ExecutionProfile.DEV_LOCAL.value: "dev",
    ExecutionProfile.GVISOR.value: "gvisor",
    ExecutionProfile.FIRECRACKER.value: "firecracker",
}


def default_limits() -> SandboxLimits:
    return SandboxLimits(
        cpu_limit=settings.sandbox_cpu_limit,
        memory_mb=settings.sandbox_memory_mb,
        pid_limit=settings.sandbox_pid_limit,
        disk_mb=settings.sandbox_disk_mb,
        wall_clock_seconds=settings.sandbox_wall_clock_seconds,
    )


def create_sandbox(
    *,
    workspace: Path,
    execution_profile: str | None = None,
    limits: SandboxLimits | None = None,
    image: str | None = None,
) -> SandboxAdapter:
    """Build the sandbox for a run.

    ``image`` selects the toolchain the target is built and executed against — chosen from the
    detected language (see app/sandbox/images.py), not hardcoded. It matters only for the container
    adapters; the host ``dev`` adapter uses the host's own toolchains and ignores it.
    """
    adapter_name = _PROFILE_TO_ADAPTER.get(execution_profile or "", "") or settings.sandbox_adapter
    limits = limits or default_limits()

    if adapter_name == "dev":
        if not settings.dev_mode and settings.kavachx_env == "production":
            raise SandboxUnavailable(
                "The development sandbox adapter is refused in production. "
                "Set SANDBOX_ADAPTER=gvisor or firecracker.",
                code="DEV_SANDBOX_IN_PRODUCTION",
            )
        return DevSandboxAdapter(workspace=workspace, limits=limits)

    if adapter_name == "gvisor":
        return GvisorSandboxAdapter(
            workspace=workspace, limits=limits, image=image or settings.sandbox_image
        )

    if adapter_name == "firecracker":
        return FirecrackerSandboxAdapter(workspace=workspace, limits=limits)

    raise SandboxUnavailable(f"Unknown sandbox adapter {adapter_name!r}.")


def describe_available() -> dict[str, Any]:
    """Report every adapter's readiness. Backs ``/api/system/sandbox``."""
    probe_workspace = settings.workspace_root / "_probe"
    limits = default_limits()
    out: dict[str, Any] = {"configured": settings.sandbox_adapter, "adapters": {}}

    for name, factory in (
        ("dev", lambda: DevSandboxAdapter(workspace=probe_workspace, limits=limits)),
        (
            "gvisor",
            lambda: GvisorSandboxAdapter(
                workspace=probe_workspace, limits=limits, image=settings.sandbox_image
            ),
        ),
        (
            "firecracker",
            lambda: FirecrackerSandboxAdapter(workspace=probe_workspace, limits=limits),
        ),
    ):
        try:
            adapter = factory()
            entry = adapter.capabilities().as_dict()
            if name == "firecracker":
                entry["missing_prerequisites"] = adapter.preflight()  # type: ignore[attr-defined]
            out["adapters"][name] = entry
        except Exception as exc:
            out["adapters"][name] = {"adapter": name, "error": str(exc)[:300]}

    return out
