# KavachX

**Graph-grounded autonomous cyber-reasoning with proof-carrying repair.**

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

### Windows (PowerShell) — recommended for this repository

```powershell
.\scripts\dev.ps1
```

That script will:

1. verify `uv`, `node`, and Docker Desktop,
2. start PostgreSQL (`docker compose up -d postgres`),
3. create the backend virtualenv with `uv sync`,
4. run `alembic upgrade head`,
5. seed the demo organisation, project, local authorised repository and demo user,
6. install frontend dependencies,
7. start FastAPI on `:8000` and Next.js on `:3000`.

Then open <http://localhost:3000>, click **Launch Console**, and log in with the seeded
credentials printed by the script (default `demo@kavachx.io` / `kavachx-demo-2024`).

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
├── scripts/                  dev.ps1, dev.sh, seed, headless demo driver
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
