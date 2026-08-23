# Running the backend on a remote gVisor server

Deploy the KavachX **backend on your Ubuntu server** (where Docker + gVisor already live), and use
it from your Windows machine (browser / local frontend). Because the gVisor adapter bind-mounts the
pinned workspace into the container, the backend must run **on the same host as the Docker daemon** —
so the backend goes on the server, not on Windows.

```
Windows (you)                         Ubuntu server (docker + gVisor)
 browser / frontend  ── HTTP :8000 ─▶  backend (uvicorn, SANDBOX_ADAPTER=gvisor)
                                        └─ docker run --runtime=runsc  (sandboxed analysis)
                                        └─ postgres (container, :5433)
```

## Prerequisites on the server (you already have these)
- Docker Engine running (`docker info` works).
- gVisor registered: `docker info --format '{{json .Runtimes}}'` contains `runsc`.
- `git`, `curl` available.

## 1. Get the code onto the server
```bash
ssh <user>@<SERVER-IP>
git clone https://github.com/saishagoel27/KavachX ~/KavachX      # or: rsync/scp the repo up
cd ~/KavachX
```

## 2. Configure the server `.env`
```bash
cp .env.example .env
# generate secrets:
python3 - <<'PY'
import secrets, re, pathlib
p = pathlib.Path(".env"); s = p.read_text()
s = re.sub(r'^JWT_SECRET=.*', 'JWT_SECRET='+secrets.token_urlsafe(48), s, flags=re.M)
s = re.sub(r'^CERTIFICATE_SIGNING_KEY=.*', 'CERTIFICATE_SIGNING_KEY='+secrets.token_urlsafe(48), s, flags=re.M)
p.write_text(s)
PY
```
Then edit `.env` and set at least:
```
SANDBOX_ADAPTER=gvisor
SANDBOX_IMAGE=kavachx/sandbox:dev
DATABASE_URL=postgresql+asyncpg://kavachx:kavachx@localhost:5433/kavachx
LLM_PROVIDER=mock            # or groq, with GROQ_API_KEY set
LLM_FALLBACK_TO_MOCK=true
PUBLISHER_DRY_RUN=true
# allow your frontend origin (see step 5):
CORS_ORIGINS=http://localhost:3000,http://<YOUR-WINDOWS-IP>:3000
# GITHUB_TOKEN=...            # only if you want live PRs
```

## 3. Bring it up (one command)
The setup script sees gVisor is already installed, then builds the sandbox image, starts Postgres,
migrates, seeds, and runs the backend on `0.0.0.0:8000`:
```bash
bash setup-gvisor-local.sh --run
```
(The repo is already on the native fs here, so it runs in place — no sync.)

<details><summary>Or do it manually</summary>

```bash
# One sandbox image per language toolchain; the image is chosen per run from the detected language
# (backend/app/sandbox/images.py). Identical isolation on all of them.
docker build -t kavachx/sandbox:dev      ./sandbox                              # python + clang (default)
docker build -f sandbox/Dockerfile.node -t kavachx/sandbox-node:dev ./sandbox   # node / js / ts / solidity
docker build -f sandbox/Dockerfile.java -t kavachx/sandbox-java:dev ./sandbox   # java / kotlin
docker build -f sandbox/Dockerfile.go   -t kavachx/sandbox-go:dev   ./sandbox   # go
docker build -f sandbox/Dockerfile.rust -t kavachx/sandbox-rust:dev ./sandbox   # rust
docker compose up -d postgres
cd backend
uv run alembic upgrade head
uv run python -m scripts.seed
SANDBOX_ADAPTER=gvisor uv run uvicorn app.main:app --host 0.0.0.0 --port 8000
```
</details>

Keep it alive across your SSH session with `tmux`/`screen`, or run it as a systemd service.

## 4. Verify gVisor is really doing the work
```bash
curl -s localhost:8000/ready | python3 -m json.tool   # sandbox_adapter: "gvisor" (health: /health)
# during a run, in another shell:
# during a run, list running containers and their runtime (the sandbox shows runsc):
docker ps -q | xargs -r docker inspect --format '{{.Name}} -> {{.HostConfig.Runtime}}'
```

## 5. Use it from your Windows machine

**Safest — SSH tunnel** (no open ports; recommended for a security tool with real creds):
```powershell
ssh -L 8000:localhost:8000 -L 3000:localhost:3000 <user>@<SERVER-IP>
```
Then treat the server as if it were local: `http://localhost:8000` is the API.

**Frontend options:**
- Run the frontend **on the server** and browse it via the tunnel at `http://localhost:3000`, or
- Run the frontend **on Windows**, pointed at the server:
  ```bash
  # frontend/.env.local  — this is the API URL (where the backend lives)
  NEXT_PUBLIC_API_BASE_URL=http://localhost:8000     # if using the SSH tunnel
  # or NEXT_PUBLIC_API_BASE_URL=http://<SERVER-IP>:8000 if you exposed port 8000 directly
  cd frontend && npm install && npm run dev
  ```
  Then set the backend's `CORS_ORIGINS` to the **frontend's** origin — the URL the browser loads the
  page from — which is `http://localhost:3000` (NOT the API URL). Add any other origin you open the
  UI from, comma-separated. Auth is a Bearer token (no cookies), so nothing else is needed.

Log in with the seeded `demo@kavachx.io` / `kavachx-demo-2024`, start a Security Run, and every
analysis executes sandboxed under gVisor **on the server**.

## Security notes
- Prefer the **SSH tunnel** over opening `:8000`/`:3000` publicly. If you must expose them, firewall
  to your IP and put the API behind TLS.
- The target's env vars you paste into a run are injected into the sandbox on the server — see the
  isolation note in the New-Run form.
