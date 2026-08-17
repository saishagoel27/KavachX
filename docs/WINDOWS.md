# Windows setup

Windows is the primary development target for this repository. The backend, the frontend and the full
analysis pipeline all run natively — no WSL required for the demo path.

---

## One command

```powershell
.\scripts\dev.ps1
```

Add `-Demo` to drive a full run and print the certificate afterwards:

```powershell
.\scripts\dev.ps1 -Demo
```

The script verifies prerequisites, starts PostgreSQL if Docker Desktop is running (and falls back to
SQLite if not), creates the virtualenv, migrates, seeds, installs frontend dependencies, and opens
both servers in their own PowerShell windows.

| Flag | Effect |
| --- | --- |
| `-SkipDocker` | Use SQLite instead of PostgreSQL. Everything works, including the full pipeline. |
| `-SkipFrontend` | Backend only |
| `-Demo` | Run the headless end-to-end demo after startup |
| `-Reset` | Drop the database, volumes and sandbox workspaces first |

If PowerShell blocks the script:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

---

## Prerequisites

| Tool | Install |
| --- | --- |
| **uv** | `powershell -c "irm https://astral.sh/uv/install.ps1 \| iex"` |
| **Node.js 20+** | <https://nodejs.org> or `winget install OpenJS.NodeJS.LTS` |
| **Docker Desktop** *(optional)* | <https://docs.docker.com/desktop/install/windows-install/> — only for the PostgreSQL path |
| **Git** *(optional)* | `winget install Git.Git` |

Python itself is not a prerequisite — `uv` provisions the interpreter.

---

## Manual steps

```powershell
# 1. environment
Copy-Item .env.example .env

# 2. database — either PostgreSQL via Docker...
docker compose up -d postgres
# ...or SQLite, by editing .env:
#   DATABASE_URL=sqlite+aiosqlite:///C:/code_playground/KavachX_test/backend/kavachx.db

# 3. backend
cd backend
uv sync
uv run alembic upgrade head
uv run python -m scripts.seed
uv run uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

# 4. frontend, in a second window
cd frontend
npm install
npm run dev
```

Then open <http://localhost:3000> and sign in as `demo@kavachx.io` / `kavachx-demo-2024`.

---

## What differs on Windows

### The event loop trap that broke the sandbox (fixed)

Worth recording, because the symptom was almost unreadable and the cause is not obvious.

uvicorn's loop factory (0.52, `uvicorn/loops/asyncio.py`) reads:

```python
if sys.platform == "win32" and not use_subprocess:
    return asyncio.ProactorEventLoop
return asyncio.SelectorEventLoop
```

`use_subprocess` is true whenever `--reload` or `--workers` is passed — and `scripts/dev.ps1` starts
the backend with `--reload`. On Windows, `asyncio.create_subprocess_exec` is **not implemented** on a
`SelectorEventLoop`: it raises a bare `NotImplementedError()` with no message and, because logifyx's
formatter ignored `exc_info`, no traceback either. Every execution-based guarantee in the product
failed at the first spawn — SAMHITA observation, deterministic validation, the shield check, the whole
gauntlet — and the run reported `NotImplementedError:` and nothing else.

So the documented way to run KavachX on its primary developer platform silently disabled the half of
the pipeline that does the proving, while the test suite passed (pytest runs on the default Proactor
policy).

The fix does not depend on how the process is launched: spawning moved to a worker thread using the
synchronous `subprocess` module (`app/sandbox/spawn.py`), which behaves identically on Proactor,
Selector and uvloop and keeps the wall-clock timeout and `taskkill /F /T` tree kill.
`test_sandbox_executes_on_a_selector_event_loop` drives the adapter on the loop that used to fail.

### Resource limits

`resource.setrlimit` does not exist on Windows, so the dev adapter cannot cap address space, CPU
seconds, process count or file size. It **does** enforce the wall-clock timeout — a timed-out process
tree is killed with `taskkill /F /T`.

`peak_ram_mb` reports `0`, because `getrusage` is unavailable. The resource meter shows `n/a` rather
than a fabricated number.

For enforced resource caps, use the gVisor adapter under Docker or WSL2.

### Shell metacharacters

`cmd.exe` and POSIX `sh` disagree about separators: `;` chains on `sh`, `&` on `cmd.exe`, `|` pipes on
both. This is why the validator tries a **set** of separators and lets execution decide which works —
the proof of vulnerability records the one that actually did. Your run may differ from the transcript
in `docs/DEMO.md` by exactly that character, which is correct behaviour rather than drift.

### Console encoding

The Windows console defaults to cp1252 and cannot print box-drawing characters. `scripts/demo_e2e.py`
reconfigures stdout to UTF-8 and falls back to ASCII replacement if that fails. If you still see
mojibake:

```powershell
$env:PYTHONIOENCODING = "utf-8"
chcp 65001
```

### Paths

Absolute paths with drive letters and backslashes work throughout — every internal path is built with
`pathlib` and normalised to forward slashes for storage and display. Long-path support is worth
enabling if you nest this repository deeply:

```powershell
# elevated
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" `
  -Name LongPathsEnabled -Value 1 -PropertyType DWORD -Force
```

### Native target

`examples/vulnerable-c-demo` needs `clang` or `gcc` and does not build with MSVC. The ASan/libFuzzer
path therefore needs WSL2 or Linux. The **Python** demo target is the cross-platform default and
exercises the entire pipeline — nothing in the walkthrough depends on the C target.

When no compiler is present, the fuzzing and runtime channels say so explicitly in `REMAINING.md`
rather than reporting a clean result they did not earn.

---

## The stronger sandbox on Windows

The development adapter is **not an isolation boundary** (see [HONESTY.md](HONESTY.md) §1). For real
isolation you need gVisor, which needs a Linux kernel:

### Docker Desktop with the WSL2 backend

1. Enable the WSL2 backend in Docker Desktop settings.
2. Install gVisor inside the WSL2 distribution and register `runsc` in
   `/etc/docker/daemon.json`.
3. Build the sandbox image: `docker build -t kavachx/sandbox:dev .\sandbox`
4. Set `SANDBOX_ADAPTER=gvisor` in `.env`, or pick **gVisor (runsc)** as the execution profile when
   starting a run.

`GET /api/system/sandbox` reports whether the runtime is actually registered, and the console header
shows the active adapter with an honest safety chip on every page.

---

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `uv: command not found` | Restart the shell after installing uv, or add `%USERPROFILE%\.local\bin` to `PATH`. |
| `docker info` fails | Docker Desktop is not running. Start it, or use `-SkipDocker`. |
| Port 5433 in use | Change the host port in `docker-compose.yml` and `DATABASE_URL`. |
| Port 8000 or 3000 in use | `Get-NetTCPConnection -LocalPort 8000 \| Select-Object OwningProcess` then `Stop-Process`. |
| `Device or resource busy` deleting the SQLite file | The backend still has it open. Stop uvicorn first. |
| Console shows `SANDBOX dev · dev only` | Expected on Windows. That chip is the honest report, not a fault. |
| No findings from a run | Verify the target: `python examples\vulnerable-demo\src\main.py --request '{\"op\":\"ping\"}'` |
| Frontend cannot reach the API | Check `NEXT_PUBLIC_API_BASE_URL` in `.env` and that `/ready` responds. |
| `email-validator` rejects an address | `.local`, `.test` and `.example` are reserved TLDs. Use a normal domain — the seeded accounts use `@kavachx.io`. |

---

## Running the tests

```powershell
cd backend
uv run pytest -q -m "not e2e"      # fast suite
uv run pytest -q -m security       # security-boundary regressions
uv run pytest -q                   # everything, including the full pipeline
```

The suite runs on SQLite with the deterministic mock proposer, so it needs no PostgreSQL, no network
and no API key.
