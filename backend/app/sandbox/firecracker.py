"""Firecracker microVM adapter — the strongest execution boundary KavachX targets.

A microVM gives a real hardware virtualisation boundary rather than a shared kernel: the
guest has its own kernel, and the host attack surface is the ~5 emulated devices Firecracker
exposes instead of the full Linux syscall table.

Requirements: Linux, ``/dev/kvm``, the ``firecracker`` binary, a guest kernel image and a
rootfs. Because those are deployment assets rather than code, this adapter validates its
prerequisites and refuses to run without them instead of silently degrading — a sandbox that
quietly becomes weaker than advertised is worse than one that fails loudly.

Execution model:

1. A per-execution jailer chroot is created (``firecracker --jailer``), non-root, capabilities
   dropped, seccomp filter on.
2. The pinned source tree is attached as a **read-only** block device. It is built into an
   ext4 image on the host; nothing is fetched inside the guest.
3. A second, size-capped scratch device carries the writable workspace and the structured
   artifact output.
4. **No network device is configured at all.** There is no tap interface, no MMDS, and the
   metadata service is not enabled, so neither the network nor the host metadata endpoint is
   reachable even in principle.
5. vCPU count, memory, and a wall-clock kill are set on the VM; the process is reaped and the
   chroot removed afterwards.
6. Results are read back from the scratch device by mounting it on the host after shutdown.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from app.core.errors import SandboxUnavailable
from app.core.logging import get_logger
from app.sandbox.base import (
    ExecRequest,
    ExecResult,
    SandboxAdapter,
    SandboxCapabilities,
    SandboxLimits,
)

logger = get_logger(__name__)


class FirecrackerSandboxAdapter(SandboxAdapter):
    name = "firecracker"

    def __init__(
        self,
        *,
        workspace: Path,
        limits: SandboxLimits,
        kernel_image: Path | None = None,
        rootfs_image: Path | None = None,
        jailer_root: Path | None = None,
    ) -> None:
        super().__init__(workspace=workspace, limits=limits)
        self.kernel_image = kernel_image
        self.rootfs_image = rootfs_image
        self.jailer_root = jailer_root or Path("/srv/kavachx/jail")

    # ------------------------------------------------------------------
    def preflight(self) -> list[str]:
        """Everything missing before this adapter can run. Empty list means ready."""
        problems: list[str] = []
        if not Path("/dev/kvm").exists():
            problems.append("/dev/kvm is not present (Linux with KVM required)")
        if shutil.which("firecracker") is None:
            problems.append("the firecracker binary is not on PATH")
        if shutil.which("jailer") is None:
            problems.append("the jailer binary is not on PATH")
        if self.kernel_image is None or not self.kernel_image.is_file():
            problems.append("no guest kernel image configured (SANDBOX_FC_KERNEL)")
        if self.rootfs_image is None or not self.rootfs_image.is_file():
            problems.append("no guest rootfs image configured (SANDBOX_FC_ROOTFS)")
        return problems

    async def start(self) -> None:
        problems = self.preflight()
        if problems:
            raise SandboxUnavailable(
                "The Firecracker adapter is not provisioned on this host.",
                details={
                    "missing": problems,
                    "remedy": (
                        "Provision a Linux host with KVM and the Firecracker assets "
                        "(see sandbox/README.md), or set SANDBOX_ADAPTER=gvisor / dev."
                    ),
                },
            )
        raise SandboxUnavailable(  # pragma: no cover - unreachable until assets exist
            "Firecracker assets are present but microVM provisioning is not implemented in "
            "this PoC build. Use SANDBOX_ADAPTER=gvisor for a real isolation boundary.",
            code="SANDBOX_ADAPTER_NOT_IMPLEMENTED",
        )

    async def execute(self, request: ExecRequest) -> ExecResult:  # pragma: no cover
        raise SandboxUnavailable("Firecracker adapter is not active.")

    async def stop(self) -> None:  # pragma: no cover
        return None

    def capabilities(self) -> SandboxCapabilities:
        ready = not self.preflight()
        return SandboxCapabilities(
            adapter=self.name,
            isolation_model="Firecracker microVM (hardware virtualisation, dedicated guest kernel)",
            network_enforced=True,
            filesystem_isolated=True,
            non_root=True,
            seccomp=True,
            dropped_capabilities=True,
            read_only_root=True,
            resource_limits_enforced=True,
            suitable_for_untrusted_code=True,
            notes=(
                "Target isolation model for production. "
                + (
                    "Host is provisioned."
                    if ready
                    else "NOT PROVISIONED on this host: " + "; ".join(self.preflight())
                )
            ),
        )
