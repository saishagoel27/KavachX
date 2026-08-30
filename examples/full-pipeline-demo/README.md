# full-pipeline-demo — the whole loop, over the live API, visible in the console

Drives KavachX end-to-end against the **seeded vulnerable target** (`examples/vulnerable-demo`) by
creating a **real run through the running server** — so, unlike `make demo` (an in-process pytest),
everything it produces is persisted and shows up live at `<frontend>/console/runs/<id>`.

It walks and reports the full loop from real state:

```
infra/sandbox  ->  ingest -> index -> SAMHITA contract
               ->  discovery (static + runtime + FUZZING)     # the fuzzer is one channel
               ->  validate (reproduce the crash >= 2x)
               ->  shield (block at runtime, benign still passes)
               ->  root cause -> patch -> gauntlet (re-attack)  # a fix that survives
               ->  attest (signed certificate)
```

## 1. Infra setup (once)

On the backend host:

```bash
make bootstrap        # env + deps + Postgres + migrate + seed  (creates the demo tenant & target)
# for the gvisor execution profile also build the sandbox images:
bash setup-gvisor-local.sh          # builds all per-language images
make backend          # run the API on :8000   (keep it running)
```

Frontend (to watch it live):

```bash
make frontend         # console on :3000   (or your Windows frontend pointed at the server)
```

The seed creates operator `demo@kavachx.io` / `kavachx-demo-2024` and the authorised local target
`examples/vulnerable-demo`.

## 2. Run the full pipeline

Stdlib only — no pip installs. From the repository root:

```bash
# Local, trusted seeded demo on the host runtime (matches `make demo`):
python examples/full-pipeline-demo/run_pipeline.py

# Sandboxed under gVisor instead:
python examples/full-pipeline-demo/run_pipeline.py --execution gvisor

# Against a remote backend (and point the console link at your frontend):
python examples/full-pipeline-demo/run_pipeline.py \
    --api http://<SERVER-IP>:8000 --frontend http://<SERVER-IP>:3000 --execution gvisor
```

Options: `--analysis quick|standard|deep`, `--execution dev_local|gvisor|firecracker`,
`--api`, `--frontend`, `--email`, `--password`, `--timeout`. Env vars `KAVACHX_API`,
`KAVACHX_FRONTEND`, `KAVACHX_EMAIL`, `KAVACHX_PASSWORD` are honoured as defaults.

> `dev_local` runs the trusted seeded demo on the host (fast, no image needed). `gvisor` runs it
> inside a runsc container — the demo target is Python, so it uses the default `kavachx/sandbox:dev`
> image; make sure it is built on the backend host.

## 3. What you'll see

The script prints each phase as it completes and then a per-stage summary, e.g.:

```
4. PIPELINE — following each phase to completion
   [OK] ingest
   [OK] index_repo
   [OK] contract_synthesis
   [OK] discovery_fanout
   [OK] validate
   [OK] shield
   [OK] root_cause
   [OK] patch_and_gauntlet
   [OK] attest
   ...
6. DISCOVERY — channels that fired (the fuzzer is one of them)
   fuzzing      N candidate(s)  <- FUZZER
   runtime      N candidate(s)
   static       N candidate(s)
7. VALIDATION — findings proven by re-execution
   1 finding(s), 1 VALIDATED
   - V001 HIGH/CWE-... at reportsvc/...:NN (reproduced 2x, root cause: reportsvc/...:NN)
9. PATCH + GAUNTLET — a fix that survives re-attack
   1 patch(es): 1 VERIFIED, 1 REFUTED first
10. CERTIFICATE — the signed attestation
   KVX-...  level ...  hash ...
RESULT
   PASS — the full loop ran: discovered, proved, shielded, patched, re-attacked, attested.
   Open in the console: http://localhost:3000/console/runs/<id>
```

Open that URL: the **LIVE** tab streams the same pipeline; **SECURITY MISSION / FINDINGS / SAMHITA /
PATCHES / GAUNTLET / EVIDENCE** tabs show the persisted results; the header shows the sandbox adapter
and egress. The run also appears in **Console → Runs**.

## Three demos, three questions

| demo | question it answers |
|------|---------------------|
| [`../fuzz-target-demo`](../fuzz-target-demo) | *does the fuzzer build a campaign and find crashes?* (fuzzer in isolation) |
| this one | *does the whole loop work end-to-end and show in the UI?* (infra → fuzz → validate → patch → cert) |
| [`../platform-walkthrough`](../platform-walkthrough) | *the whole product, narrated, for an audience* — adds the real `git clone`, the publish approval, the pull request branch, and a computed pass/fail verdict |
