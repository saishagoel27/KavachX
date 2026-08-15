# Sandbox

The sandbox is the most critical security component in KavachX.
Isolation must be live from **ingest** — before any build command runs.

A plain container is NOT sufficient. The sandbox uses a microVM
(Firecracker or gVisor) for every job that touches untrusted code.

---

## Why microVM, not container

Containers share the host kernel. A malicious `setup.py` or `Makefile`
can escape a container via kernel exploits. A microVM has its own kernel.
The attack surface is the hypervisor interface, not the full kernel syscall table.

For the PoC, gVisor is acceptable (easier to set up).
For the finale, Firecracker is preferred (lower overhead, faster startup).

---

## Isolation controls

| Control | Setting |
|---|---|
| Isolation | microVM (Firecracker or gVisor) |
| Network | None — no network namespace at all |
| Filesystem | Read-only root; one writable tmpfs scratch; no host mounts |
| Identity | Non-root UID; no-new-privs; all capabilities dropped; seccomp profile |
| Limits | cgroups v2 — CPU quota, memory cap, PID cap, disk quota, wall-clock kill |
| Secrets | Zero — no environment variables, no token files, no metadata endpoint |
| Source delivery | Pre-fetched tarball at pinned commit SHA — never `git clone` inside sandbox |
| Egress | Structured artifacts only, through a single serialisation channel |

---

## Two profiles

All jobs use the same isolation controls. They differ only in resource quotas.

### Analysis profile
Used for: indexing, static queries, contract synthesis (observer)

```python
ANALYSIS_PROFILE = SandboxProfile(
    cpu_quota_pct=25,
    memory_mb=2048,
    pid_cap=128,
    disk_mb=512,
    wall_clock_seconds=300,    # 5 minutes max
)
```

### Execution profile
Used for: build, fuzz, exploit execution, gauntlet replay

```python
EXECUTION_PROFILE = SandboxProfile(
    cpu_quota_pct=80,
    memory_mb=8192,
    pid_cap=512,
    disk_mb=4096,
    wall_clock_seconds=21600,  # 6 hours max (for fuzzing campaigns)
)
```

---

## Job types

Every sandbox job has a defined input, a defined output, and a wall-clock kill.

```python
class JobKind(str, Enum):
    INDEX       = "index"       # GitNexus indexing → graph handles
    BUILD       = "build"       # compile target → binary + build log
    OBSERVE     = "observe"     # run under benign corpus → value profiles
    FUZZ        = "fuzz"        # AFL++ campaign → crash inputs
    EXPLOIT     = "exploit"     # run PoV → sanitizer output + exit status
    REPLAY      = "replay"      # replay benign corpus → pass/fail per request
    PATCH_BUILD = "patch_build" # apply diff + build → success/fail
    GAUNTLET    = "gauntlet"    # run all 4 gauntlet stages
```

---

## Runner interface

`sandbox/runner.py`

```python
class SandboxRunner:
    def dispatch(
        self,
        job_kind: JobKind,
        payload: dict,
        profile: SandboxProfile,
    ) -> SandboxResult:
        ...
```

`SandboxResult`:
```python
@dataclass
class SandboxResult:
    job_id:      str
    job_kind:    JobKind
    success:     bool
    exit_code:   int
    artifacts:   dict[str, str]   # name → storage key
    stdout_ref:  str              # storage key for stdout (never inline)
    stderr_ref:  str              # storage key for stderr
    wall_seconds: float
    error:       str | None       # if success=False
```

The runner never returns raw file contents inline.
Everything goes through the artifact storage layer (keyed by sha256).

---

## Egress channel

The sandbox has exactly one output channel: a structured artifact bundle.

```python
@dataclass
class ArtifactBundle:
    job_id:    str
    artifacts: dict[str, ArtifactEntry]

@dataclass
class ArtifactEntry:
    name:      str
    sha256:    str
    size_bytes: int
    kind:      str   # "diff" | "log" | "trace" | "report" | "binary"
```

The bundle is serialised as JSON and written to a shared tmpfs mount
that the orchestrator reads after the microVM exits.
The microVM cannot write anywhere else.

---

## Source delivery

The target source is delivered as a pre-fetched tarball at a pinned commit SHA.

```python
def prepare_source(
    repo_url: str,
    commit_sha: str,
    storage: ArtifactStorage,
) -> str:
    # fetch tarball from GitHub API using installation token
    # verify sha256 of tarball
    # store in artifact storage
    # return storage key
    # NEVER git clone inside the sandbox
    ...
```

Why no `git clone` inside the sandbox:
- `git clone` would require network access (which the sandbox has none of)
- Submodule fetches are an attack surface
- Credential helpers could be invoked

---

## Dependency mirror

The sandbox has no network. Dependencies must be pre-populated.

For the PoC:
- Python packages: a pre-built wheelhouse mounted read-only
- System packages: baked into the microVM base image
- No package manager calls inside the sandbox at runtime

For the finale:
- Offline bundle prepared in advance (2–5 Oct window)
- Full wheelhouse for all target languages
- Pre-compiled fuzzers and sanitizer runtimes

---

## Threat model for the sandbox

| Threat | Control |
|---|---|
| Malicious `setup.py` / `Makefile` achieves RCE | microVM — host kernel not reachable |
| Malicious code exfiltrates data via network | No network namespace |
| Malicious code reads host credentials | No secrets in sandbox environment |
| Malicious code writes to host filesystem | Read-only root, tmpfs scratch only |
| Malicious code forks bomb | PID cap via cgroups |
| Malicious code exhausts memory | Memory cap via cgroups |
| Malicious code runs forever | Wall-clock kill |
| Malicious code escapes via metadata endpoint | No network — metadata endpoint unreachable |

---

## What the orchestrator does after a job

1. Reads the artifact bundle from the shared tmpfs
2. Verifies sha256 of each artifact
3. Stores artifacts in the artifact storage layer
4. Updates `KavachState` with storage keys (handles), not contents
5. Destroys the microVM

The microVM is destroyed after every job. There is no persistent sandbox state.
