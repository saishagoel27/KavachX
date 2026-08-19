# KavachX

**Graph-grounded autonomous cyber-reasoning with proof-carrying repair.**

<p align="center">
  <img src="https://img.shields.io/badge/deploy-self--hosted-6E56CF?style=flat&labelColor=1f2937" alt="self-hosted" />
  <img src="https://img.shields.io/badge/RBAC-15%20permissions-6E56CF?style=flat&labelColor=1f2937" alt="RBAC 15 permissions" />
  <img src="https://img.shields.io/badge/sandbox%20egress-0%20bytes-3DDC84?style=flat&labelColor=1f2937" alt="sandbox egress 0 bytes" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.13-3776AB?style=flat&logo=python&logoColor=white&labelColor=1f2937" alt="Python 3.13" />
  <img src="https://img.shields.io/badge/FastAPI-0.141-009688?style=flat&logo=fastapi&logoColor=white&labelColor=1f2937" alt="FastAPI 0.141" />
  <img src="https://img.shields.io/badge/SQLAlchemy-2.0%20async-D71F00?style=flat&logo=sqlalchemy&logoColor=white&labelColor=1f2937" alt="SQLAlchemy 2.0 async" />
  <img src="https://img.shields.io/badge/LangGraph-1.2-1C3C3C?style=flat&logo=langgraph&logoColor=white&labelColor=1f2937" alt="LangGraph 1.2" />
  <img src="https://img.shields.io/badge/PostgreSQL-16-4169E1?style=flat&logo=postgresql&logoColor=white&labelColor=1f2937" alt="PostgreSQL 16" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Next.js-16-000000?style=flat&logo=nextdotjs&logoColor=white&labelColor=1f2937" alt="Next.js 16" />
  <img src="https://img.shields.io/badge/React-19-61DAFB?style=flat&logo=react&logoColor=white&labelColor=1f2937" alt="React 19" />
  <img src="https://img.shields.io/badge/TypeScript-5.7-3178C6?style=flat&logo=typescript&logoColor=white&labelColor=1f2937" alt="TypeScript 5.7" />
  <img src="https://img.shields.io/badge/Tailwind-3.4-06B6D4?style=flat&logo=tailwindcss&logoColor=white&labelColor=1f2937" alt="Tailwind 3.4" />
  <img src="https://img.shields.io/badge/Docker-Compose-2496ED?style=flat&logo=docker&logoColor=white&labelColor=1f2937" alt="Docker Compose" />
</p>

<p align="center">
  <a href="#the-one-command-path">Quick start</a> ·
  <a href="docs/ARCHITECTURE.md">Architecture</a> ·
  <a href="docs/SECURITY.md">Security</a> ·
  <a href="docs/HONESTY.md">Honesty</a> ·
  <a href="docs/DEMO.md">Demo</a>
</p>

> KavachX does not simply find a crash and generate a patch. It first reconstructs an
> executable behavioural specification called **SAMHITA**, uses that specification to
> discover violations, validates findings deterministically, repairs the root cause,
> attacks its own patch through a **Refutation Gauntlet**, and produces a **PRAMAAN**
> evidence-backed assurance certificate.

```
Understand → Discover → Validate → Shield → Repair → Attack Repair → Verify → Attest → Publish
```

---

## The one command path

### Fastest: the self-contained end-to-end proof

```bash
make demo
```

This drives the full loop — detect → adversarial validation → patch → gauntlet re-attack →
signed certificate — against the seeded vulnerable target, in-process on SQLite with the
deterministic proposer. It needs no PostgreSQL, no Docker and no API keys, and prints the
KAVACH SECURITY PROOF with real reproduction counts, gauntlet stage tallies and certificate
hashes.

### The interactive console

```bash
make bootstrap   # env + deps + PostgreSQL + migrations + demo seed (needs Docker Desktop)
make dev         # FastAPI on :8000, Next.js on :3000
```

Or run the two processes directly, without make:

```powershell
# terminal 1 — API
cd backend; uv run uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
# terminal 2 — console
cd frontend; npm run dev
```

Then open <http://localhost:3000>, click **Launch Console**, and log in with the seeded
credentials (default `demo@kavachx.io` / `kavachx-demo-2024`).

### Full Docker path (Linux / macOS / Windows with Docker Desktop)

```bash
cp .env.example .env
docker compose up --build
```

### Make (Linux / macOS / WSL)

```bash
make bootstrap    # deps + db + migrate + seed
make dev          # run backend + frontend
make demo         # bootstrap, then drive a full run headlessly and print the certificate
make test         # backend test suite
```

---

## What the demo proves

`examples/vulnerable-demo` is a deliberately seeded, fully local vulnerable Python
service. Running it through KavachX produces a **real** end-to-end trace:

| Step | What actually happens |
| --- | --- |
| Ingest | Repository is pinned to an immutable content SHA and copied into a sandbox workspace. |
| Probe / Index | tree-sitter (with a regex fallback) builds the World Model: files, functions, callers, entrypoints, sinks. |
| SAMHITA | Benign workload is executed, value profiles observed, clauses proposed under strict JSON schema, compiled to Python predicates, then **falsified against held-out traces**. Hallucinated clauses die here. |
| Discovery | Four channels (graph/static, config/reachability, fuzzing, runtime) push hypotheses into one persistent priority queue. |
| Validation | Each hypothesis becomes an executable job **inside the sandbox**. A finding is only `VALIDATED` when a deterministic signal (exit code, sanitizer output, contract violation, marker artifact) reproduces. |
| Shield | A reversible input-filter shield is synthesised and verified to block the exploit while the benign corpus still passes. `TIME TO PROTECTION` starts here. |
| Repair | Root cause is located and verified to be on the executed path, then a patch is synthesised and applied to a **copy** in the sandbox. |
| Refutation Gauntlet | Exploit mutation, sibling hunt, differential replay and SAMHITA re-check all execute for real. **Patch v1 is genuinely refuted** — the mutation engine finds a live bypass of the naive filter. |
| Iteration | The refutation becomes a hard constraint. Patch v2 is synthesised and survives all four stages. |
| PRAMAAN | An evidence graph is built, hashed and signed; assurance is graded A/B/C/R by deterministic rules. |
| Publish | `CHANGES.md`, `REMAINING.md` and `certificate.json` go to an isolated Publisher that owns the only GitHub credential in the system. |

Nothing in that table is simulated with `sleep()`. Every UI event is emitted by a real
backend state transition. See [docs/DEMO.md](docs/DEMO.md) for the annotated walkthrough
and [docs/HONESTY.md](docs/HONESTY.md) for an explicit list of what is and is not
production-grade in this PoC.

---

## Analysing a public GitHub repository

Paste a URL into **Target → Public repository** on the New Security Run page. Any form works
(`owner/repo`, a browse URL, a `/tree/<branch>` URL, a clone string). KavachX resolves it,
shows you the language mix, licence and the exact commit it will pin, and requires you to
confirm you are authorised to analyse it.

Two things are true of that path and stated everywhere it matters:

- **It is analysis-only.** `github_public` is deliberately excluded from
  `PUBLISHABLE_PROVIDERS`, enforced independently in the orchestrator's publish gate and in
  the publish route. There is also no credential to misuse — public source is fetched over
  unauthenticated HTTPS with no `Authorization` header at all. Reading published code and
  running it in a sealed sandbox is ordinary security research; opening a pull request
  against a repository you do not control is not.
- **Most public repositories run STATIC-ONLY.** The dynamic half of the pipeline needs an
  entrypoint to invoke and a benign corpus to observe. Without them there is nothing to
  execute, so fuzzing, runtime observation, SAMHITA and validation are **omitted rather
  than reported clean**, no finding can reach `VALIDATED`, and the result is a list of
  candidates for human review. `REMAINING.md` says so explicitly, per run.

Verified against two real repositories: `pallets/itsdangerous` returns zero candidates
(correct for a clean crypto library), and `we45/Vulnerable-Flask-App` surfaces ten,
including CWE-89 SQL injection, CWE-502 `yaml.load`, CWE-1336 template injection, CWE-798 a
hardcoded secret and CWE-295 `jwt.decode(verify=False)`.

---

## Repository layout

```
kavachx/
├── frontend/                 Next.js 16 · TypeScript · Tailwind · Monaco · Recharts
├── backend/                  FastAPI · SQLAlchemy 2 · Alembic · LangGraph
│   └── app/
│       ├── api/              REST + SSE surface
│       ├── auth/             JWT, password hashing, RBAC
│       ├── models/           tenant-scoped SQLAlchemy models
│       ├── orchestration/    LangGraph state machine + checkpointing
│       ├── analysis/         tree-sitter index, world model, semgrep bridge
│       ├── samhita/          proposal → compile → falsify
│       ├── discovery/        four channels + persistent hypothesis queue
│       ├── validator/        deterministic reproduction
│       ├── shield/           reversible mitigation
│       ├── patching/         root cause, synthesis, policy gate, blast radius
│       ├── gauntlet/         mutation · sibling · replay · contract
│       ├── pramaan/          evidence graph, certificate, assurance grading
│       ├── publisher/        isolated GitHub publisher
│       ├── sandbox/          dev / gVisor / Firecracker adapters
│       ├── llm/              provider abstraction (mock · llama.cpp · OpenAI-compatible)
│       └── events/           SSE bus with DB-backed replay
├── sandbox/                  container + isolation profiles for the execution boundary
├── publisher/                notes on the credential boundary
├── examples/
│   ├── vulnerable-demo/      seeded vulnerable Python service (primary, cross-platform)
│   └── vulnerable-c-demo/    seeded C target for the ASan/libFuzzer path (Linux)
├── infrastructure/
├── backend/scripts/          seed (demo tenant, project, authorised local repository)
├── docs/
├── docker-compose.yml
├── .env.example
└── Makefile
```

---

## Engineering principle

**The LLM is never the final authority.**

```
LLM proposes  →  deterministic system validates  →  state machine decides
```

The model may propose interface hypotheses, SAMHITA clauses, root-cause hypotheses,
patches and refutation strategies. Only deterministic components decide whether a crash
occurred, whether a clause holds, whether an exploit reproduces, whether a patch passes,
whether it stayed inside the blast radius, whether a finding is confirmed, what assurance
level applies, and whether a PR may be published. Every model response is parsed through a
strict Pydantic schema; a schema failure is a model failure, never a silent pass.

---

## Safety boundary

KavachX is a **defensive** security research platform.

- A run needs one of exactly three authority paths: a GitHub App installation that actually
  lists the repository, the local seeded target inside this repository's own `examples/`
  tree (`DEV_MODE` only), or a **public** GitHub repository the operator names and confirms
  they are authorised to analyse. There is no personal-access-token path, and `DEV_MODE`
  does not mean "analyse any directory on this machine".
- **Only the first two can publish.** A public repository is somebody else's; KavachX will
  analyse published source and hand you the patch, but it will not open a pull request
  against a repository you do not control, and it holds no credential that would let it.
- The sandbox is treated as hostile-code execution: no credentials, no network, non-root,
  dropped capabilities, read-only root, resource + wall-clock caps.
- Repository content is **data**, never instructions. Model inputs are structured; model
  outputs are schema-validated.
- Working exploits are gated behind the `finding:read_pov` permission and every access is
  written to the hash-chained audit log.

Everything here operates on source code the operator has named and is authorised to
analyse. There is no functionality for scanning arbitrary third-party *systems* — no host
discovery, no network reach, no mass targeting — and none will be added.

---

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — components, data flow, state machine
- [docs/API.md](docs/API.md) — REST + SSE reference
- [docs/DEMO.md](docs/DEMO.md) — annotated end-to-end walkthrough
- [docs/SECURITY.md](docs/SECURITY.md) — threat model, isolation, credential boundary
- [docs/WINDOWS.md](docs/WINDOWS.md) — native Windows setup
- [docs/HONESTY.md](docs/HONESTY.md) — PoC limitations, stated plainly
- [docs/SAMHITA.md](docs/SAMHITA.md) — the behavioural contract engine
- [docs/PRAMAAN.md](docs/PRAMAAN.md) — the evidence graph and assurance levels
