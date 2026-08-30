"""Sandbox abstraction.

The sandbox executes **hostile code**. That is not a figure of speech: repository content
under analysis, mutated exploit payloads and model-proposed patches all run in here. The
contract every adapter must satisfy:

* **no credentials** — the environment is built from an allowlist, never inherited;
* **no network** — and the adapter must report whether that is *enforced* or merely *expected*;
* **non-root, no-new-privileges, dropped capabilities, seccomp, read-only root** where the
  platform can express them;
* **CPU / memory / PID / disk / wall-clock caps**;
* **pinned immutable source** — the tree is materialised and hashed *outside* the sandbox and
  never fetched from within it. There is no ``git clone`` inside a sandbox, ever;
* **structured artifact output only** — results come back as declared files plus
  stdout/stderr, not as arbitrary host mutations.

:attr:`SandboxCapabilities.network_enforced` is the honest flag. The development adapter sets
it to ``False`` and says so everywhere it surfaces, because an ordinary local subprocess is
not an isolation boundary and pretending otherwise would be the exact dishonesty this project
is built to avoid.
"""

from __future__ import annotations

import abc
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.hashing import sha256_text


@dataclass(slots=True)
class SandboxLimits:
    cpu_limit: float = 2.0
    memory_mb: int = 2048
    pid_limit: int = 256
    disk_mb: int = 1024
    wall_clock_seconds: int = 120

    def as_dict(self) -> dict[str, Any]:
        return {
            "cpu_limit": self.cpu_limit,
            "memory_mb": self.memory_mb,
            "pid_limit": self.pid_limit,
            "disk_mb": self.disk_mb,
            "wall_clock_seconds": self.wall_clock_seconds,
        }


@dataclass(slots=True)
class SandboxCapabilities:
    """What the adapter actually enforces. Reported to the UI and the certificate verbatim."""

    adapter: str
    isolation_model: str
    network_enforced: bool
    filesystem_isolated: bool
    non_root: bool
    seccomp: bool
    dropped_capabilities: bool
    read_only_root: bool
    resource_limits_enforced: bool
    suitable_for_untrusted_code: bool
    notes: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "adapter": self.adapter,
            "isolation_model": self.isolation_model,
            "network_enforced": self.network_enforced,
            "filesystem_isolated": self.filesystem_isolated,
            "non_root": self.non_root,
            "seccomp": self.seccomp,
            "dropped_capabilities": self.dropped_capabilities,
            "read_only_root": self.read_only_root,
            "resource_limits_enforced": self.resource_limits_enforced,
            "suitable_for_untrusted_code": self.suitable_for_untrusted_code,
            "notes": self.notes,
        }


@dataclass(slots=True)
class ExecRequest:
    """One execution job."""

    #: Argument vector. Never a shell string — the sandbox never spawns a shell for us.
    argv: list[str]
    #: Working directory relative to the workspace root.
    cwd: str = "."
    #: Extra environment. Merged on top of the *allowlisted* base, never the host env.
    env: dict[str, str] = field(default_factory=dict)
    stdin: str | None = None
    timeout_seconds: int | None = None
    #: Workspace-relative paths to read back after the run.
    collect_artifacts: list[str] = field(default_factory=list)
    label: str = ""
    #: Build phase (trusted, operator-authored install/build). Binds the workspace **read-write**
    #: instead of read-only, so ``npm install`` / ``pip install`` can write ``node_modules`` / a
    #: venv into the tree. The untrusted execute phase leaves this False.
    writable: bool = False
    #: Build phase. Gives the container network egress, because a package registry is unreachable
    #: otherwise. The untrusted execute phase leaves this False, so egress there is structurally
    #: zero (no interface exists). Host adapters ignore both flags — the host is already writable
    #: and networked.
    allow_network: bool = False
    #: Maximum captured stdout/stderr, to bound memory on a chatty target.
    max_output_bytes: int = 1_000_000


@dataclass(slots=True)
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False
    peak_ram_mb: int = 0
    cpu_seconds: float = 0.0
    #: Bytes that left the sandbox. Structurally zero when networking is denied.
    egress_bytes: int = 0
    #: Blocked outbound connection attempts observed by the in-workspace guard.
    network_attempts: int = 0
    network_enforced: bool = False
    artifacts: dict[str, str] = field(default_factory=dict)
    #: Sanitizer / crash signals extracted deterministically from the output streams.
    signals: list[str] = field(default_factory=list)
    adapter: str = ""
    label: str = ""

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    @property
    def crashed(self) -> bool:
        return self.exit_code != 0 or self.timed_out or bool(self.signals)

    def output_hash(self) -> str:
        return sha256_text(f"{self.exit_code}\n{self.stdout}\n{self.stderr}")

    def trace_hash(self) -> str:
        return sha256_text("\n".join(self.signals) + "\n" + self.stderr[-4000:])

    def as_evidence(self) -> dict[str, Any]:
        return {
            "adapter": self.adapter,
            "label": self.label,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "duration_ms": self.duration_ms,
            "signals": self.signals,
            "peak_ram_mb": self.peak_ram_mb,
            "cpu_seconds": self.cpu_seconds,
            "egress_bytes": self.egress_bytes,
            "network_attempts": self.network_attempts,
            "network_enforced": self.network_enforced,
            "stdout_hash": sha256_text(self.stdout),
            "stderr_hash": sha256_text(self.stderr),
            "output_hash": self.output_hash(),
        }


#: Sanitizer and interpreter crash markers. Deterministic string matching — no model involved
#: in deciding whether something crashed.
CRASH_SIGNALS: tuple[tuple[str, str], ...] = (
    ("AddressSanitizer", "asan"),
    ("ERROR: AddressSanitizer", "asan"),
    ("LeakSanitizer", "lsan"),
    ("UndefinedBehaviorSanitizer", "ubsan"),
    ("runtime error:", "ubsan"),
    ("ThreadSanitizer", "tsan"),
    ("MemorySanitizer", "msan"),
    ("SEGV on unknown address", "segv"),
    ("Segmentation fault", "segv"),
    ("stack-buffer-overflow", "asan:stack-buffer-overflow"),
    ("heap-buffer-overflow", "asan:heap-buffer-overflow"),
    ("heap-use-after-free", "asan:use-after-free"),
    ("double-free", "asan:double-free"),
    ("Traceback (most recent call last)", "python:uncaught_exception"),
    ("IndexError", "python:IndexError"),
    ("KeyError", "python:KeyError"),
    ("TypeError", "python:TypeError"),
    ("ValueError", "python:ValueError"),
    ("AssertionError", "python:AssertionError"),
    ("RecursionError", "python:RecursionError"),
    ("MemoryError", "python:MemoryError"),
    ("OSError", "python:OSError"),
    ("panicked at", "rust:panic"),
    ("fatal error:", "go:fatal"),
)


def extract_signals(stdout: str, stderr: str) -> list[str]:
    combined = f"{stdout}\n{stderr}"
    found: list[str] = []
    for needle, signal in CRASH_SIGNALS:
        if needle in combined and signal not in found:
            found.append(signal)
    return found


class SandboxAdapter(abc.ABC):
    """One instance manages one workspace for the lifetime of a run."""

    name: str = "abstract"

    def __init__(self, *, workspace: Path, limits: SandboxLimits) -> None:
        self.workspace = workspace
        self.limits = limits
        self.session_id = uuid.uuid4().hex[:12]
        self.execution_count = 0
        self.total_cpu_seconds = 0.0
        self.peak_ram_mb = 0
        self.total_egress_bytes = 0
        self.total_network_attempts = 0

    @abc.abstractmethod
    async def start(self) -> None: ...

    @abc.abstractmethod
    async def execute(self, request: ExecRequest) -> ExecResult: ...

    @abc.abstractmethod
    async def stop(self) -> None: ...

    @abc.abstractmethod
    def capabilities(self) -> SandboxCapabilities: ...

    # -- shared helpers ----------------------------------------------------
    def _record(self, result: ExecResult) -> ExecResult:
        self.execution_count += 1
        self.total_cpu_seconds += result.cpu_seconds
        self.peak_ram_mb = max(self.peak_ram_mb, result.peak_ram_mb)
        self.total_egress_bytes += result.egress_bytes
        self.total_network_attempts += result.network_attempts
        result.adapter = self.name
        return result

    def stats(self) -> dict[str, Any]:
        return {
            "adapter": self.name,
            "session_id": self.session_id,
            "executions": self.execution_count,
            "cpu_seconds": round(self.total_cpu_seconds, 3),
            "peak_ram_mb": self.peak_ram_mb,
            "egress_bytes": self.total_egress_bytes,
            "network_attempts": self.total_network_attempts,
            "limits": self.limits.as_dict(),
            "capabilities": self.capabilities().as_dict(),
        }

    async def __aenter__(self) -> SandboxAdapter:
        await self.start()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.stop()


#: Environment variables the sandbox is allowed to see. Everything else is dropped, which is
#: how "the sandbox has zero secrets" is actually implemented rather than merely asserted.
#: Directory the harness is injected into, inside the workspace. Duplicated by each adapter as a
#: local constant; defined here so the deps directory below can be expressed against it.
HARNESS_DIR = "_kavachx"

#: Where provisioning installs interpreter-level dependencies, relative to the workspace root.
#:
#: It has to be *inside* the workspace, because the workspace bind mount is the only thing that
#: survives an exec: every execution is a fresh container, so anything written to the image's own
#: site-packages is discarded before the next one starts. And it has to be inside ``_kavachx``,
#: because that directory is already both preserved by :func:`app.sandbox.workspace.reset_work`
#: (so a gauntlet reset does not delete the dependencies mid-run) and ignored by the indexer and
#: the content hash (so installed packages never enter the pinned source tree or the code graph).
DEPS_DIR = f"{HARNESS_DIR}/deps"

ENV_ALLOWLIST: tuple[str, ...] = (
    "PATH",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "TEMP",
    "TMP",
    "TMPDIR",
    "HOME",
    "LANG",
    "LC_ALL",
    "PYTHONHASHSEED",
    "PYTHONIOENCODING",
    "PYTHONDONTWRITEBYTECODE",
    "SystemDrive",
    "PROCESSOR_ARCHITECTURE",
)

#: Any variable whose name contains one of these is a hard failure if it somehow reaches the
#: sandbox environment. Checked on every execution, not just in tests.
FORBIDDEN_ENV_MARKERS: tuple[str, ...] = (
    "GITHUB",
    "GROQ",
    "JWT",
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "DATABASE_URL",
    "CERTIFICATE_SIGNING",
    "API_KEY",
    "AWS_",
    "AZURE_",
    "GOOGLE_",
    "OPENAI",
    "ANTHROPIC",
    "CREDENTIAL",
    "PRIVATE_KEY",
)


class SandboxSecretLeak(RuntimeError):
    """Raised if a forbidden variable is about to enter the sandbox environment."""


def build_sandbox_env(overrides: dict[str, str] | None = None) -> dict[str, str]:
    """Construct the sandbox environment from an allowlist.

    Deliberately does **not** start from ``os.environ``.
    """
    import os

    env: dict[str, str] = {}
    for key in ENV_ALLOWLIST:
        value = os.environ.get(key)
        if value:
            env[key] = value

    # Deterministic interpreter behaviour so repeated runs are byte-comparable.
    env.setdefault("PYTHONHASHSEED", "0")
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    # Belt and braces: even if a network call slipped through, there is nowhere to proxy to.
    env["no_proxy"] = "*"
    env["NO_PROXY"] = "*"
    env["http_proxy"] = ""
    env["https_proxy"] = ""

    for key, value in (overrides or {}).items():
        env[key] = value

    assert_no_secrets(env)
    return env


def assert_no_secrets(env: dict[str, str]) -> None:
    upper_allowed = {k.upper() for k in ENV_ALLOWLIST}
    for key in env:
        name = key.upper()
        if name in upper_allowed:
            continue
        for marker in FORBIDDEN_ENV_MARKERS:
            if marker in name:
                raise SandboxSecretLeak(
                    f"Refusing to execute: environment variable {key!r} would expose a "
                    "credential to the sandbox."
                )
