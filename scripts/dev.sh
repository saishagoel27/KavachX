#!/usr/bin/env bash
# Start the complete KavachX development environment on Linux, macOS or WSL.
#
#   ./scripts/dev.sh              # postgres + backend + frontend
#   ./scripts/dev.sh --no-docker  # SQLite instead of postgres
#   ./scripts/dev.sh --demo       # then drive the headless end-to-end demo
#   ./scripts/dev.sh --reset      # drop local state first
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND="$REPO_ROOT/backend"
FRONTEND="$REPO_ROOT/frontend"

USE_DOCKER=1
RUN_FRONTEND=1
RUN_DEMO=0
DO_RESET=0

for arg in "$@"; do
  case "$arg" in
    --no-docker) USE_DOCKER=0 ;;
    --no-frontend) RUN_FRONTEND=0 ;;
    --demo) RUN_DEMO=1 ;;
    --reset) DO_RESET=1 ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

CYAN='\033[36m'; GREEN='\033[32m'; YELLOW='\033[33m'; RED='\033[31m'; DIM='\033[2m'; RESET='\033[0m'
step() { printf "\n${CYAN}==> %s${RESET}\n" "$1"; }
ok()   { printf "    ${GREEN}%s${RESET}\n" "$1"; }
warn() { printf "    ${YELLOW}%s${RESET}\n" "$1"; }
fail() { printf "    ${RED}%s${RESET}\n" "$1"; }

printf "\n${CYAN}  KAVACHX${RESET}\n"
printf "${DIM}  Graph-grounded autonomous cyber-reasoning with proof-carrying repair${RESET}\n"

# --- prerequisites ---------------------------------------------------------
step "Checking prerequisites"
command -v uv >/dev/null 2>&1 || {
  fail "uv is not installed. Install it with: curl -LsSf https://astral.sh/uv/install.sh | sh"
  exit 1
}
ok "uv $(uv --version | sed 's/uv //')"

if [ "$RUN_FRONTEND" = "1" ]; then
  command -v node >/dev/null 2>&1 || { fail "node is not installed (need Node.js 20+)"; exit 1; }
  ok "node $(node --version)"
fi

if [ "$USE_DOCKER" = "1" ]; then
  if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    warn "Docker is unavailable; falling back to SQLite"
    USE_DOCKER=0
  else
    ok "Docker is running"
  fi
fi

# --- environment -----------------------------------------------------------
step "Preparing the environment file"
if [ ! -f "$REPO_ROOT/.env" ]; then
  cp "$REPO_ROOT/.env.example" "$REPO_ROOT/.env"
  JWT="$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')"
  CERT="$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')"
  # Generate real secrets rather than running with the shipped placeholders.
  sed -i.bak "s|^JWT_SECRET=.*|JWT_SECRET=$JWT|" "$REPO_ROOT/.env"
  sed -i.bak "s|^CERTIFICATE_SIGNING_KEY=.*|CERTIFICATE_SIGNING_KEY=$CERT|" "$REPO_ROOT/.env"
  rm -f "$REPO_ROOT/.env.bak"
  ok "created .env with generated secrets"
else
  ok ".env already exists (left untouched)"
fi

if [ "$USE_DOCKER" = "0" ]; then
  sed -i.bak "s|^DATABASE_URL=.*|DATABASE_URL=sqlite+aiosqlite:///$BACKEND/kavachx.db|" "$REPO_ROOT/.env"
  rm -f "$REPO_ROOT/.env.bak"
  warn "DATABASE_URL points at SQLite for this session"
fi

if ! grep -qE '^GROQ_API_KEY=.+' "$REPO_ROOT/.env"; then
  warn "GROQ_API_KEY is empty - runs will use the deterministic mock proposer."
  warn "That is fully supported; the certificate records which provider was used."
fi

# --- reset -----------------------------------------------------------------
if [ "$DO_RESET" = "1" ]; then
  step "Resetting local state"
  rm -rf "$REPO_ROOT/.kavachx" && ok "removed sandbox workspaces"
  rm -f "$BACKEND/kavachx.db" && ok "removed the SQLite database"
  if [ "$USE_DOCKER" = "1" ]; then
    (cd "$REPO_ROOT" && docker compose down -v >/dev/null 2>&1) && ok "removed the PostgreSQL volume"
  fi
fi

# --- postgres --------------------------------------------------------------
if [ "$USE_DOCKER" = "1" ]; then
  step "Starting PostgreSQL"
  (cd "$REPO_ROOT" && docker compose up -d postgres)
  printf "    waiting for readiness"
  for _ in $(seq 1 40); do
    if (cd "$REPO_ROOT" && docker compose exec -T postgres pg_isready -U kavachx -d kavachx >/dev/null 2>&1); then
      break
    fi
    printf "."
    sleep 1
  done
  printf "\n"
  ok "PostgreSQL ready on localhost:5433"
fi

# --- backend ---------------------------------------------------------------
step "Installing backend dependencies"
(cd "$BACKEND" && uv sync) || { fail "uv sync failed"; exit 1; }
ok "backend virtualenv ready"

step "Applying database migrations"
(cd "$BACKEND" && uv run alembic upgrade head) || { fail "alembic upgrade failed"; exit 1; }
ok "schema at head"

step "Seeding the demo tenant"
(cd "$BACKEND" && uv run python -m scripts.seed) || warn "seed reported a problem (it may already be applied)"

# --- frontend --------------------------------------------------------------
if [ "$RUN_FRONTEND" = "1" ] && [ ! -d "$FRONTEND/node_modules" ]; then
  step "Installing frontend dependencies"
  (cd "$FRONTEND" && npm install --no-audit --no-fund) || { fail "npm install failed"; exit 1; }
  ok "frontend dependencies ready"
fi

# --- run -------------------------------------------------------------------
step "Starting services"
PIDS=()
cleanup() {
  printf "\n"
  step "Shutting down"
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

(cd "$BACKEND" && uv run uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload) &
PIDS+=($!)
ok "backend starting on http://localhost:8000"

if [ "$RUN_FRONTEND" = "1" ]; then
  (cd "$FRONTEND" && npm run dev) &
  PIDS+=($!)
  ok "frontend starting on http://localhost:3000"
fi

printf "    waiting for the API"
READY=0
for _ in $(seq 1 60); do
  if curl -fsS http://127.0.0.1:8000/ready >/dev/null 2>&1; then READY=1; break; fi
  printf "."
  sleep 1
done
printf "\n"
[ "$READY" = "1" ] && ok "API is ready" || warn "API did not report ready in 60s"

cat <<BANNER

  ------------------------------------------------------------------
  KavachX is running

    Console      http://localhost:3000
    API docs     http://localhost:8000/docs
    Metrics      http://localhost:8000/metrics

    Sign in with
      demo@kavachx.io  /  kavachx-demo-2024        (OWNER)

    Role accounts (same password), for the RBAC asymmetries:
      maintainer@kavachx.io   sees exploits, can publish
      reviewer@kavachx.io     sees exploits, cannot publish
      developer@kavachx.io    no exploit access
      auditor@kavachx.io      audit + certificates only

    Then: Launch Console -> New Security Run -> Start KavachX Analysis
  ------------------------------------------------------------------

BANNER

if [ "$RUN_DEMO" = "1" ]; then
  step "Running the headless end-to-end demo"
  (cd "$REPO_ROOT" && "$BACKEND/.venv/bin/python" scripts/demo_e2e.py --profile quick) || true
fi

wait
