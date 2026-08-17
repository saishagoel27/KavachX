# gVisor — the real execution boundary

The development adapter is **not an isolation boundary**. gVisor is the smallest step to one.

## Why gVisor and not plain Docker

A container shares the host kernel. A container escape is a kernel-surface problem, and KavachX
deliberately executes hostile code. gVisor (`runsc`) puts a userspace kernel — the Sentry — between
the workload and the host: a syscall from the sandbox is serviced by the Sentry, not by Linux. An
escape has to get through that first.

This is why `docs/HONESTY.md` refuses to describe ordinary Docker isolation as equivalent.

## Install (Linux, or WSL2 on Windows)

```bash
curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
  | sudo tee /etc/apt/sources.list.d/gvisor.list > /dev/null
sudo apt-get update && sudo apt-get install -y runsc
sudo runsc install          # registers the runtime in /etc/docker/daemon.json
sudo systemctl restart docker
docker info --format '{{json .Runtimes}}'   # expect "runsc"
```

## Use it

```bash
make sandbox-image                     # docker build -t kavachx/sandbox:dev ./sandbox
# .env
SANDBOX_ADAPTER=gvisor
SANDBOX_IMAGE=kavachx/sandbox:dev
```

Or pick **gVisor (runsc)** as the execution profile when starting a run.

`GET /api/system/sandbox` reports whether the runtime is actually registered. The adapter refuses to
start with a clear message if it is not — it never silently falls back to something weaker.

## What the adapter passes, and why

| Flag | Why |
| --- | --- |
| `--runtime=runsc` | The boundary itself |
| `--network none` | No interface exists, so egress is zero by construction |
| `--read-only` | Root filesystem immutable |
| `--tmpfs /workspace/.tmp:rw,noexec,nosuid,size=…` | The only writable path, size-capped |
| `--user 65534:65534` | `nobody`; never root |
| `--cap-drop ALL` | No capabilities |
| `--security-opt no-new-privileges` | setuid binaries cannot elevate |
| `--security-opt seccomp=…` | The profile in `sandbox/seccomp-profile.json`, on top of gVisor's own filtering |
| `--pids-limit`, `--memory`, `--cpus` | cgroup-enforced resource caps |
| `--mount …,readonly` | The pinned source tree, read-only |

The pinned tree is mounted read-only and only the harness output directory is writable, so the target
cannot mutate the tree whose hash was computed outside the sandbox.

## Verify it for yourself

```bash
docker run --rm --runtime=runsc --network none kavachx/sandbox:dev \
  python -c "import socket; socket.create_connection(('1.1.1.1',53),2)"
# expect a failure: there is no interface to use

docker run --rm --runtime=runsc kavachx/sandbox:dev python -c "import os; print(os.uname())"
# expect the gVisor kernel string, not the host's
```
