#!/usr/bin/env bash
# =============================================================================
# KavachX — one-shot local gVisor sandbox setup
# =============================================================================
# Installs Docker Engine + gVisor (runsc), registers the runtime, builds the
# hardened sandbox image, brings up Postgres, applies migrations + seed, and
# (optionally) starts the backend with SANDBOX_ADAPTER=gvisor.
#
# gVisor is Linux-only. Run this INSIDE your Ubuntu shell (you already have Ubuntu, so just open it
# directly — no `wsl -d Ubuntu` needed):
#
#     cd /mnt/c/Users/madhu/OneDrive/Desktop/hachathons/KavachX
#     bash setup-gvisor-local.sh          # set everything up, print the run command
#     bash setup-gvisor-local.sh --run    # ... and start the backend at the end
#
# Launched from the Windows mount (/mnt/*), it SYNCS the repo into the native Ubuntu fs (~/KavachX
# by default; override with KAVACHX_NATIVE_DIR) and re-runs there, so nothing touches the slow
# Windows filesystem. Everything after that — source, build, workspaces, venv, .kavachx state — is
# native ext4. Edit on Windows, then re-run to re-sync. Pass --in-place to stay on /mnt instead.
#
# It uses **native Docker Engine (docker-ce) installed inside Ubuntu** (systemd-managed) — the same
# setup as your own docker install script — NOT Docker Desktop. If docker-ce is missing it installs
# it via apt exactly as you do. Idempotent: safe to re-run; every step checks before it acts.
#
# NOTE: if `docker` happens to point at Docker Desktop (its WSL integration enabled for this distro)
# it CANNOT host the runsc runtime — this script detects that and stops with a clear message so your
# native docker-ce is used instead.
# =============================================================================
set -euo pipefail

RUN_BACKEND=0
IN_PLACE=0
REBUILD=0
for arg in "$@"; do
  case "$arg" in
    --run) RUN_BACKEND=1 ;;
    --in-place) IN_PLACE=1 ;;   # stay on the Windows mount instead of syncing to native fs
    --rebuild) REBUILD=1 ;;     # force rebuilding the sandbox image even if it already exists
  esac
done

log()  { printf '\n\033[36m[kavachx]\033[0m %s\n' "$*"; }
warn() { printf '\n\033[33m[kavachx] WARN:\033[0m %s\n' "$*" >&2; }
die()  { printf '\n\033[31m[kavachx] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# --- 0. environment ----------------------------------------------------------
[[ "$(uname -s)" == "Linux" ]] || die "Run this inside your Ubuntu shell, not Windows PowerShell."
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

# --- 0b. work on the NATIVE Ubuntu filesystem, never the Windows mount --------
# Running from /mnt/c means every read/write goes through the slow 9p mount and writes state
# (.kavachx/, artifacts) back onto the Windows filesystem. So when launched from /mnt/*, sync the
# repo once into the native ext4 home and re-exec there — nothing then touches the Windows fs.
NATIVE_DIR="${KAVACHX_NATIVE_DIR:-$HOME/KavachX}"
case "$REPO_ROOT" in
  /mnt/*)
    if [[ "$IN_PLACE" != "1" && "$REPO_ROOT" != "$NATIVE_DIR" ]]; then
      log "Syncing repo to the native Ubuntu filesystem ($NATIVE_DIR) — the Windows mount is left untouched…"
      command -v rsync >/dev/null 2>&1 || { sudo apt-get update -y && sudo apt-get install -y rsync; }
      mkdir -p "$NATIVE_DIR"
      # Excluded dirs are also protected from --delete, so a re-sync keeps the native venv,
      # node_modules and .kavachx state while mirroring your latest source.
      rsync -a --delete \
        --exclude '.git' --exclude 'node_modules' --exclude '.venv' --exclude '.next' \
        --exclude '.kavachx' --exclude 'dist' --exclude 'build' --exclude '__pycache__' \
        --exclude '*.pyc' \
        "$REPO_ROOT/" "$NATIVE_DIR/"
      log "Re-running from the native copy. (Edit on Windows, then re-run to re-sync.)"
      fwd=(--in-place)
      [[ "$RUN_BACKEND" == "1" ]] && fwd+=(--run)
      [[ "$REBUILD" == "1" ]] && fwd+=(--rebuild)
      exec bash "$NATIVE_DIR/setup-gvisor-local.sh" "${fwd[@]}"
    fi
    warn "Running IN PLACE on the Windows mount ($REPO_ROOT) — slower, and .kavachx state is written
       to the Windows filesystem. Drop --in-place to use the native fs instead."
    ;;
esac
log "Repository: $REPO_ROOT"

# Virtualenv + sandbox workspaces. Reuse whatever already exists; create only if missing.
#  - Native repo (normal case): use the project's own backend/.venv (your existing one) and
#    REPO_ROOT/.kavachx/workspaces — nothing is created under ~/.cache.
#  - Only when forced in place on the Windows mount (--in-place) do we redirect to $HOME, because a
#    Windows-side .venv holds .exe files unusable on Linux and /mnt is slow.
case "$REPO_ROOT" in
  /mnt/*)
    export UV_PROJECT_ENVIRONMENT="$HOME/.cache/kavachx-venv-linux"
    export SANDBOX_WORKSPACE_ROOT="$HOME/.kavachx/workspaces"
    ;;
  *)
    export UV_PROJECT_ENVIRONMENT="$REPO_ROOT/backend/.venv"
    export SANDBOX_WORKSPACE_ROOT="$REPO_ROOT/.kavachx/workspaces"
    ;;
esac
mkdir -p "$SANDBOX_WORKSPACE_ROOT"
if [[ -x "$UV_PROJECT_ENVIRONMENT/bin/python" ]]; then
  log "Reusing existing virtualenv: $UV_PROJECT_ENVIRONMENT"
else
  log "No virtualenv yet — uv will create it at $UV_PROJECT_ENVIRONMENT"
fi

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

# --- 1. Docker Engine (native docker-ce inside Ubuntu) -----------------------
if ! command -v docker >/dev/null 2>&1; then
  log "Installing Docker Engine (docker-ce) via apt…"
  sudo apt-get update -y
  sudo apt-get install -y ca-certificates curl gnupg lsb-release
  sudo install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg |
    sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  sudo chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" |
    sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
  sudo apt-get update -y
  sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  sudo systemctl enable docker || true
  sudo usermod -aG docker "$USER" || true
  warn "Added you to the 'docker' group. This shell still needs sudo until you re-open Ubuntu."
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
if [[ "$REBUILD" != "1" ]] && $DOCKER image inspect kavachx/sandbox:dev >/dev/null 2>&1; then
  log "Sandbox image kavachx/sandbox:dev already exists — skipping build (use --rebuild to force)."
else
  log "Building kavachx/sandbox:dev…"
  $DOCKER build -t kavachx/sandbox:dev ./sandbox
fi

# --- 6. uv (Python toolchain) ------------------------------------------------
if ! command -v uv >/dev/null 2>&1; then
  log "Installing uv…"
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"
fi

# --- 7. Postgres + schema + seed --------------------------------------------
if $DOCKER compose ps postgres 2>/dev/null | grep -qiE 'up|running|healthy'; then
  log "Postgres container already running — reusing it."
else
  log "Starting Postgres (this Docker daemon, host port 5433)…"
  $DOCKER compose up -d postgres
fi
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

  Start the backend with the gVisor sandbox (workspaces + venv on the native fs):

      cd backend
      SANDBOX_ADAPTER=gvisor \\
        UV_PROJECT_ENVIRONMENT="$UV_PROJECT_ENVIRONMENT" \\
        SANDBOX_WORKSPACE_ROOT="$SANDBOX_WORKSPACE_ROOT" \\
        uv run uvicorn app.main:app --host 0.0.0.0 --port 8000

  Confirm it is really using gVisor:

      curl -s localhost:8000/ready   # sandbox_adapter: "gvisor"  (health at /health)
      docker ps -q | xargs -r docker inspect --format '{{.Name}} -> {{.HostConfig.Runtime}}'  # sandbox shows runsc during a run

  Log in with demo@kavachx.io / kavachx-demo-2024, then start a Security Run.

EOF

if [[ "$RUN_BACKEND" == "1" ]]; then
  log "Starting backend now (SANDBOX_ADAPTER=gvisor)…"
  cd backend
  exec env SANDBOX_ADAPTER=gvisor SANDBOX_WORKSPACE_ROOT="$SANDBOX_WORKSPACE_ROOT" \
    uv run uvicorn app.main:app --host 0.0.0.0 --port 8000
fi
