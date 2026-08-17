<#
.SYNOPSIS
    Start the complete KavachX development environment on Windows.

.DESCRIPTION
    One command path, native on Windows:

      1. verify uv, node and (optionally) Docker Desktop
      2. start PostgreSQL via Docker Compose, or fall back to SQLite if Docker is unavailable
      3. create the backend virtualenv with uv sync
      4. run alembic upgrade head
      5. seed the demo organisation, project, authorised local repository and role accounts
      6. install frontend dependencies
      7. start FastAPI on :8000 and Next.js on :3000

    Both servers run in separate PowerShell windows so their logs stay readable. Ctrl-C in a
    window stops that server.

.PARAMETER SkipDocker
    Do not start PostgreSQL. Uses SQLite instead — everything works, including the full pipeline.

.PARAMETER SkipFrontend
    Start only the backend.

.PARAMETER Demo
    After both services are up, run the headless end-to-end demo and print the certificate.

.PARAMETER Reset
    Drop the local database and workspaces before starting.

.EXAMPLE
    .\scripts\dev.ps1

.EXAMPLE
    .\scripts\dev.ps1 -SkipDocker -Demo
#>
[CmdletBinding()]
param(
    [switch]$SkipDocker,
    [switch]$SkipFrontend,
    [switch]$Demo,
    [switch]$Reset
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$BackendDir = Join-Path $RepoRoot 'backend'
$FrontendDir = Join-Path $RepoRoot 'frontend'

function Write-Step([string]$Message) {
    Write-Host ''
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Ok([string]$Message) {
    Write-Host "    $Message" -ForegroundColor Green
}

function Write-Warn([string]$Message) {
    Write-Host "    $Message" -ForegroundColor Yellow
}

function Write-Fail([string]$Message) {
    Write-Host "    $Message" -ForegroundColor Red
}

function Test-Command([string]$Name) {
    $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

Write-Host ''
Write-Host '  KAVACHX' -ForegroundColor Cyan
Write-Host '  Graph-grounded autonomous cyber-reasoning with proof-carrying repair' -ForegroundColor DarkGray
Write-Host ''

# ---------------------------------------------------------------------------
# 1. prerequisites
# ---------------------------------------------------------------------------
Write-Step 'Checking prerequisites'

if (-not (Test-Command 'uv')) {
    Write-Fail 'uv is not installed.'
    Write-Host '    Install it with:  powershell -c "irm https://astral.sh/uv/install.ps1 | iex"'
    exit 1
}
Write-Ok "uv $((uv --version) -replace 'uv ', '')"

if (-not $SkipFrontend) {
    if (-not (Test-Command 'node')) {
        Write-Fail 'node is not installed. Get Node.js 20+ from https://nodejs.org'
        exit 1
    }
    Write-Ok "node $(node --version)"
}

$UseDocker = -not $SkipDocker
if ($UseDocker) {
    if (-not (Test-Command 'docker')) {
        Write-Warn 'docker not found; falling back to SQLite.'
        $UseDocker = $false
    }
    else {
        docker info 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Warn 'Docker Desktop is not running; falling back to SQLite.'
            Write-Warn 'Start Docker Desktop and re-run for the PostgreSQL path.'
            $UseDocker = $false
        }
        else {
            Write-Ok 'Docker Desktop is running'
        }
    }
}

# ---------------------------------------------------------------------------
# 2. environment file
# ---------------------------------------------------------------------------
Write-Step 'Preparing the environment file'

$EnvFile = Join-Path $RepoRoot '.env'
if (-not (Test-Path $EnvFile)) {
    Copy-Item (Join-Path $RepoRoot '.env.example') $EnvFile
    Write-Ok 'created .env from .env.example'

    # Generate real secrets rather than shipping the placeholders into a running instance.
    $jwt = -join ((1..48) | ForEach-Object { '{0:x}' -f (Get-Random -Minimum 0 -Maximum 16) })
    $cert = -join ((1..48) | ForEach-Object { '{0:x}' -f (Get-Random -Minimum 0 -Maximum 16) })
    $content = Get-Content $EnvFile -Raw
    $content = $content -replace 'JWT_SECRET=.*', "JWT_SECRET=$jwt"
    $content = $content -replace 'CERTIFICATE_SIGNING_KEY=.*', "CERTIFICATE_SIGNING_KEY=$cert"
    Set-Content $EnvFile $content -NoNewline -Encoding UTF8
    Write-Ok 'generated a JWT secret and a certificate signing key'
}
else {
    Write-Ok '.env already exists (left untouched)'
}

if (-not $UseDocker) {
    $sqlite = 'sqlite+aiosqlite:///' + ((Join-Path $BackendDir 'kavachx.db') -replace '\\', '/')
    $content = Get-Content $EnvFile -Raw
    if ($content -notmatch [regex]::Escape($sqlite)) {
        $content = $content -replace 'DATABASE_URL=.*', "DATABASE_URL=$sqlite"
        Set-Content $EnvFile $content -NoNewline -Encoding UTF8
    }
    Write-Warn 'DATABASE_URL points at SQLite for this session'
}

$groq = (Get-Content $EnvFile | Select-String '^GROQ_API_KEY=(.+)$')
if (-not $groq) {
    Write-Warn 'GROQ_API_KEY is empty — runs will use the deterministic mock proposer.'
    Write-Warn 'That is fully supported: the pipeline is identical and the certificate says which'
    Write-Warn 'provider produced its proposals. Add a key to .env to use Groq.'
}

# ---------------------------------------------------------------------------
# 3. reset
# ---------------------------------------------------------------------------
if ($Reset) {
    Write-Step 'Resetting local state'
    $kavachxDir = Join-Path $RepoRoot '.kavachx'
    if (Test-Path $kavachxDir) {
        Remove-Item $kavachxDir -Recurse -Force
        Write-Ok 'removed sandbox workspaces'
    }
    $sqliteFile = Join-Path $BackendDir 'kavachx.db'
    if (Test-Path $sqliteFile) {
        Remove-Item $sqliteFile -Force
        Write-Ok 'removed the SQLite database'
    }
    if ($UseDocker) {
        Push-Location $RepoRoot
        docker compose down -v 2>&1 | Out-Null
        Pop-Location
        Write-Ok 'removed the PostgreSQL volume'
    }
}

# ---------------------------------------------------------------------------
# 4. PostgreSQL
# ---------------------------------------------------------------------------
if ($UseDocker) {
    Write-Step 'Starting PostgreSQL'
    Push-Location $RepoRoot
    docker compose up -d postgres
    if ($LASTEXITCODE -ne 0) { Pop-Location; Write-Fail 'could not start postgres'; exit 1 }

    Write-Host '    waiting for readiness' -NoNewline
    for ($i = 0; $i -lt 40; $i++) {
        docker compose exec -T postgres pg_isready -U kavachx -d kavachx 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { break }
        Write-Host '.' -NoNewline
        Start-Sleep -Seconds 1
    }
    Write-Host ''
    Pop-Location
    Write-Ok 'PostgreSQL ready on localhost:5433'
}

# ---------------------------------------------------------------------------
# 5. backend
# ---------------------------------------------------------------------------
Write-Step 'Installing backend dependencies'
Push-Location $BackendDir
uv sync
if ($LASTEXITCODE -ne 0) { Pop-Location; Write-Fail 'uv sync failed'; exit 1 }
Write-Ok 'backend virtualenv ready'

Write-Step 'Applying database migrations'
uv run alembic upgrade head
if ($LASTEXITCODE -ne 0) { Pop-Location; Write-Fail 'alembic upgrade failed'; exit 1 }
Write-Ok 'schema at head'

Write-Step 'Seeding the demo tenant'
uv run python -m scripts.seed
if ($LASTEXITCODE -ne 0) { Write-Warn 'seed reported a problem (it may already be applied)' }
Pop-Location

# ---------------------------------------------------------------------------
# 6. frontend
# ---------------------------------------------------------------------------
if (-not $SkipFrontend) {
    Write-Step 'Installing frontend dependencies'
    Push-Location $FrontendDir
    if (-not (Test-Path 'node_modules')) {
        npm install --no-audit --no-fund
        if ($LASTEXITCODE -ne 0) { Pop-Location; Write-Fail 'npm install failed'; exit 1 }
    }
    Write-Ok 'frontend dependencies ready'
    Pop-Location
}

# ---------------------------------------------------------------------------
# 7. run
# ---------------------------------------------------------------------------
Write-Step 'Starting services'

$backendCommand = @"
Set-Location '$BackendDir'
Write-Host 'KavachX backend  http://localhost:8000  (docs at /docs)' -ForegroundColor Cyan
uv run uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
"@
Start-Process powershell -ArgumentList '-NoExit', '-Command', $backendCommand
Write-Ok 'backend starting on http://localhost:8000'

if (-not $SkipFrontend) {
    $frontendCommand = @"
Set-Location '$FrontendDir'
Write-Host 'KavachX console  http://localhost:3000' -ForegroundColor Cyan
npm run dev
"@
    Start-Process powershell -ArgumentList '-NoExit', '-Command', $frontendCommand
    Write-Ok 'frontend starting on http://localhost:3000'
}

Write-Host '    waiting for the API' -NoNewline
$ready = $false
for ($i = 0; $i -lt 60; $i++) {
    try {
        $response = Invoke-WebRequest 'http://127.0.0.1:8000/ready' -UseBasicParsing -TimeoutSec 2
        if ($response.StatusCode -eq 200) { $ready = $true; break }
    }
    catch { }
    Write-Host '.' -NoNewline
    Start-Sleep -Seconds 1
}
Write-Host ''

if ($ready) {
    Write-Ok 'API is ready'
}
else {
    Write-Warn 'API did not report ready in 60s — check the backend window'
}

# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '  ------------------------------------------------------------------' -ForegroundColor DarkGray
Write-Host '  KavachX is running' -ForegroundColor Green
Write-Host ''
Write-Host '    Console      http://localhost:3000'
Write-Host '    Landing      http://localhost:3000/'
Write-Host '    API docs     http://localhost:8000/docs'
Write-Host '    Metrics      http://localhost:8000/metrics'
Write-Host ''
Write-Host '    Sign in with' -ForegroundColor DarkGray
Write-Host '      demo@kavachx.io  /  kavachx-demo-2024        (OWNER)'
Write-Host ''
Write-Host '    Role accounts (same password), for the RBAC asymmetries:' -ForegroundColor DarkGray
Write-Host '      maintainer@kavachx.io   sees exploits, can publish'
Write-Host '      reviewer@kavachx.io     sees exploits, cannot publish'
Write-Host '      developer@kavachx.io    no exploit access'
Write-Host '      auditor@kavachx.io      audit + certificates only'
Write-Host ''
Write-Host '    Then: Launch Console -> New Security Run -> Start KavachX Analysis' -ForegroundColor DarkGray
Write-Host '  ------------------------------------------------------------------' -ForegroundColor DarkGray
Write-Host ''

if ($Demo) {
    Write-Step 'Running the headless end-to-end demo'
    Push-Location $RepoRoot
    & (Join-Path $BackendDir '.venv\Scripts\python.exe') (Join-Path $RepoRoot 'scripts\demo_e2e.py') --profile quick
    Pop-Location
}
