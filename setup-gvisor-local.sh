#!/usr/bin/env bash
# =============================================================================
# KavachX — one-shot local gVisor sandbox setup
# =============================================================================
# Installs Docker Engine + gVisor (runsc), registers the runtime, builds the
# hardened sandbox image, brings up Postgres, applies migrations + seed, and
# (optionally) starts the backend with SANDBOX_ADAPTER=gvisor.
#
# gVisor is Linux-only, so on Windows this MUST run inside WSL2 Ubuntu:
#
#     wsl -d Ubuntu
#     cd /mnt/c/Users/madhu/OneDrive/Desktop/hachathons/KavachX
#     bash setup-gvisor-local.sh          # set everything up, print the run command
#     bash setup-gvisor-local.sh --run    # ... and start the backend at the end
#
# Idempotent: safe to re-run. Every step checks before it acts.
#
# IMPORTANT: If Docker Desktop's WSL integration is enabled for this Ubuntu
# distro, `docker` will point at Docker Desktop's daemon, which CANNOT host the
# runsc runtime. Turn it off first:
#   Docker Desktop → Settings → Resources → WSL Integration → disable "Ubuntu".
# This script detects that case and stops with a clear message.
# =============================================================================
set -euo pipefail

RUN_BACKEND=0
[[ "${1:-}" == "--run" ]] && RUN_BACKEND=1

log()  { printf '\n\033[36m[kavachx]\033[0m %s\n' "$*"; }
warn() { printf '\n\033[33m[kavachx] WARN:\033[0m %s\n' "$*" >&2; }
die()  { printf '\n\033[31m[kavachx] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# --- 0. environment ----------------------------------------------------------
[[ "$(uname -s)" == "Linux" ]] || die "Run this inside WSL2 Ubuntu (wsl -d Ubuntu), not Windows PowerShell."
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"
log "Repository: $REPO_ROOT"

# Keep a Linux-only virtualenv so we never clobber the Windows-side backend/.venv,
# and so uv builds it on the fast Linux filesystem rather than on /mnt/c.
export UV_PROJECT_ENVIRONMENT="$HOME/.cache/kavachx-venv-linux"

start_docker() {
  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -q '^docker'; then
    sudo systemctl start docker || true
  else
    sudo service docker start || true
  fi
}
restart_docker() {
  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -q '^docker'; then
    sudo systemctl restart docker || true
  else
    sudo service docker restart || true
  fi
  sleep 2
}

# --- 1. Docker Engine --------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  log "Installing Docker Engine…"
  curl -fsSL https://get.docker.com | sudo sh
  sudo usermod -aG docker "$USER" || true
  warn "Added you to the 'docker' group. This shell still needs sudo until you re-open it."
fi
start_docker

# Choose whether we need sudo for docker in THIS shell.
DOCKER="docker"
docker info >/dev/null 2>&1 || DOCKER="sudo docker"
$DOCKER info >/dev/null 2>&1 || die "Cannot reach the Docker daemon even with sudo."

# Guard: Docker Desktop's daemon cannot register runsc.
if $DOCKER info --format '{{.OperatingSystem}}' 2>/dev/null | grep -qi 'Docker Desktop'; then
  die "This 'docker' points at Docker Desktop, which cannot host the runsc runtime.
       Disable Docker Desktop → Settings → Resources → WSL Integration for 'Ubuntu',
       then re-run this script so it installs a native Docker Engine inside Ubuntu."
fi
log "Docker daemon reachable (using: $DOCKER)."

# --- 2. gVisor (runsc) -------------------------------------------------------
if ! command -v runsc >/dev/null 2>&1; then
  log "Installing gVisor (runsc)…"
  ARCH="$(uname -m)"
  tmp="$(mktemp -d)"; pushd "$tmp" >/dev/null
  URL="https://storage.googleapis.com/gvisor/releases/release/latest/${ARCH}"
  wget -q "${URL}/runsc" "${URL}/runsc.sha512" \
          "${URL}/containerd-shim-runsc-v1" "${URL}/containerd-shim-runsc-v1.sha512"
  sha512sum -c runsc.sha512 >/dev/null
  sha512sum -c containerd-shim-runsc-v1.sha512 >/dev/null
  sudo mv runsc containerd-shim-runsc-v1 /usr/local/bin/
  sudo chmod a+rx /usr/local/bin/runsc /usr/local/bin/containerd-shim-runsc-v1
  popd >/dev/null; rm -rf "$tmp"
fi
log "runsc: $(runsc --version 2>/dev/null | head -1)"

# --- 3. register runsc with Docker ------------------------------------------
# systrap works without /dev/kvm (the WSL2 default); kvm is faster when present.
PLATFORM=systrap
[[ -e /dev/kvm ]] && PLATFORM=kvm
if ! $DOCKER info --format '{{json .Runtimes}}' 2>/dev/null | grep -q runsc; then
  log "Registering runsc runtime with Docker (platform=$PLATFORM)…"
  sudo /usr/local/bin/runsc install -- --platform="$PLATFORM"
  restart_docker
  docker info >/dev/null 2>&1 || DOCKER="sudo docker"
fi

# --- 4. verify gVisor --------------------------------------------------------
$DOCKER info --format '{{json .Runtimes}}' | grep -q runsc \
  || die "runsc is still not registered with Docker. Check /etc/docker/daemon.json."
log "Running gVisor smoke test (docker run --runtime=runsc hello-world)…"
$DOCKER run --rm --runtime=runsc hello-world >/dev/null \
  || die "gVisor smoke test failed. Try platform=ptrace: sudo runsc install -- --platform=ptrace"
log "gVisor is working."

# --- 5. hardened sandbox image ----------------------------------------------
log "Building kavachx/sandbox:dev…"
$DOCKER build -t kavachx/sandbox:dev ./sandbox

# --- 6. uv (Python toolchain) ------------------------------------------------
if ! command -v uv >/dev/null 2>&1; then
  log "Installing uv…"
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"
fi

# --- 7. Postgres + schema + seed --------------------------------------------
log "Starting Postgres (this Docker daemon, host port 5433)…"
$DOCKER compose up -d postgres
log "Waiting for Postgres to accept connections…"
for i in $(seq 1 40); do
  if $DOCKER compose exec -T postgres pg_isready -U kavachx -d kavachx >/dev/null 2>&1; then
    log "Postgres ready after ~${i}s."; break
  fi
  sleep 1.5
  [[ "$i" == "40" ]] && die "Postgres did not become ready."
done

log "Applying migrations and seeding the demo tenant…"
( cd backend && uv run alembic upgrade head && uv run python -m scripts.seed )

# --- 8. done -----------------------------------------------------------------
log "Setup complete. gVisor sandbox is ready."
cat <<EOF

  Start the backend with the gVisor sandbox:

      cd backend
      SANDBOX_ADAPTER=gvisor UV_PROJECT_ENVIRONMENT="$UV_PROJECT_ENVIRONMENT" \\
        uv run uvicorn app.main:app --host 0.0.0.0 --port 8000

  Confirm it is really using gVisor:

      curl -s localhost:8000/api/system/ready   # sandbox_adapter: "gvisor"
      docker ps --format '{{.Names}}\t{{.Runtime}}'   # sandbox containers show "runsc"

  Log in with demo@kavachx.io / kavachx-demo-2024, then start a Security Run.

EOF

if [[ "$RUN_BACKEND" == "1" ]]; then
  log "Starting backend now (SANDBOX_ADAPTER=gvisor)…"
  cd backend
  exec env SANDBOX_ADAPTER=gvisor uv run uvicorn app.main:app --host 0.0.0.0 --port 8000
fi
