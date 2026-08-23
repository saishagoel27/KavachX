# fuzz-target-demo — proving the mutational fuzzer works

A deliberately vulnerable Python CLI whose only purpose is to let you **watch KavachX's fuzzer build
a campaign and find real crashes**. Every operation is correct on the benign corpus and crashes only
on inputs the fuzzer *synthesises* by mutating that corpus.

## What the fuzzer actually is

The fuzzer that runs is the seeded **structured mutational engine** in
[`backend/app/discovery/fuzz_channel.py`](../../backend/app/discovery/fuzz_channel.py):

1. `generate_cases()` takes the benign corpus and produces a deterministic campaign of mutated
   requests (empty a list, zero an int, drop a field, retype a value, change the op). Seeded with
   `0x4B415641` — the same target yields the same campaign every run.
2. Each case is executed in the sandbox by
   [`kx_batch`](../../backend/app/sandbox/harness/kx_batch.py), which records exit code, response,
   and — on an unhandled exception — the **project crash site**.
3. Crashes are deduplicated by `(exception type, crash site)`; each distinct shape becomes one
   hypothesis, kept with its shortest reproducing request.

> The native C/libFuzzer branch only *reports* toolchain availability; it does not compile/run
> libFuzzer inside the pipeline. The engine that finds crashes is this Python mutational one.

## The planted bugs

`src/service.py` — clean on the corpus, crashes on the fuzzer's mutations:

| op        | benign input                          | crash the fuzzer reaches                                   |
|-----------|---------------------------------------|------------------------------------------------------------|
| `average` | `{"total":100,"count":4}`             | `ZeroDivisionError` when `count`→0; `TypeError` if retyped |
| `peak`    | `{"samples":[3,7,2,9,4]}`             | `IndexError` when `samples`→`[]`; `KeyError` if dropped    |
| `weight`  | `{"level":"high"}`                     | `KeyError` when `level` dropped/mutated off the table      |

## Option A — prove the fuzzer in isolation (recommended, fast)

Runs the **real** `generate_cases` and `kx_batch.run_case` against this target — no DB, gVisor, LLM,
or pipeline. From the repository root:

```bash
cd backend
uv run python ../examples/fuzz-target-demo/verify_fuzzer.py
```

Expected output (shape):

```
[1] benign corpus: 3 seed request(s)
      {"op": "average", "total": 100, "count": 4}
      ...
[2] fuzzer built 300 mutated cases (seed 0x4B415641, reproducible)
      fuzz-0001 [strategy0 ] --request {"count": 0, "op": "average", "total": 100}
      ...
[3] benign baseline: 3 run, 0 crashed — OK, corpus is clean
[4] campaign: 300 cases executed, N crashed, M distinct crash shapes (K in project code)
      IndexError         @ src/service.py:39   x..  e.g. ...  ->  list index out of range
      KeyError           @ src/service.py:..   x..  ...
      ZeroDivisionError  @ src/service.py:31   x..  ...
RESULT: PASS - the fuzzer built a campaign, executed it, kept the benign corpus clean, and found
real in-project crashes.
```

Exit code `0` = PASS. It fails loudly if the campaign is empty, the benign corpus is not clean, or
no in-project crash is found — so it is a genuine check, not a demo that always prints "PASS".

## Option B — the full pipeline (fuzz channel → validation → certificate)

Runs the same fuzzer as one channel of a real KavachX run, then validates each crash by re-execution.

1. Attach this folder as a **local seeded target** (dev mode), or point a run at it.
2. Start a run with the **`dev_local`** execution profile (this is a trusted demo — a Python target
   the host can execute) and the **Deep** analysis profile for the widest campaign.
3. Watch the **Discovery → FUZZING** channel: `discovery.fuzz.complete cases=… crashes=… candidates=…`
   in the logs, and the fuzz candidates (`F001`, `F002`, …) appear in the run's Findings/Discovery
   view, each carrying a crash site and a minimal reproducing request.

The full pipeline additionally proves each fuzz crash by independent re-execution before it is ever
called a finding — the fuzzer proposes, validation disposes.
