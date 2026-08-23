#!/usr/bin/env python3
"""Standalone proof that KavachX's mutational fuzzer builds a campaign and finds real crashes.

This drives the **actual** fuzzer code — nothing is reimplemented here:

* ``app.discovery.fuzz_channel.generate_cases`` — the seeded campaign builder, and
* ``app.sandbox.harness.kx_batch.run_case``     — the in-sandbox case executor,

then deduplicates crashes by ``(exception type, project crash site)`` exactly like
``fuzz_channel.run()`` does. No database, no gVisor, no LLM, no LangGraph pipeline — just the fuzzer,
run against this folder's deliberately vulnerable target, so you can watch it work in isolation.

Run it with the backend's environment, from the repository root::

    cd backend && uv run python ../examples/fuzz-target-demo/verify_fuzzer.py

Exit code 0 = the fuzzer built a campaign, executed it, the benign corpus stayed clean, and real
in-project crashes were found. Non-zero = something in that chain did not hold (details printed).
"""

# The fuzzer, batch runner, and target are imported only after the sys.path bootstrap below, so the
# E402 (import-not-at-top) and I001 (import-order) lints are expected for this standalone script.
# ruff: noqa: E402, I001
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
BACKEND = REPO / "backend"

# Make the real fuzzer, the real batch runner, and the target importable.
for path in (BACKEND, BACKEND / "app" / "sandbox" / "harness", HERE / "src"):
    sys.path.insert(0, str(path))

from app.discovery.fuzz_channel import FUZZ_SEED, generate_cases  # the real campaign builder
import kx_batch  # the real in-sandbox case executor
import main as target  # the vulnerable target under test

BUDGET = 300


def load_corpus() -> list[dict]:
    return [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted((HERE / "corpus" / "benign").glob("*.json"))
    ]


def run_batch(cases: list[dict]) -> list[dict]:
    # project_root = HERE, so a crash inside src/service.py resolves to an in-project crash site.
    return [kx_batch.run_case(target.main, case, HERE) for case in cases]


def main() -> int:
    seeds = load_corpus()
    print(f"[1] benign corpus: {len(seeds)} seed request(s)")
    for seed in seeds:
        print(f"      {json.dumps(seed)}")

    # --- the fuzzer BUILDS its campaign (deterministic: same seed → same cases every run) ---------
    cases = generate_cases(seeds, budget=BUDGET, seed=FUZZ_SEED)
    print(f"\n[2] fuzzer built {len(cases)} mutated cases (seed 0x{FUZZ_SEED:X}, reproducible)")
    for case in cases[:6]:
        print(f"      {case['id']} [{case['label']:9}] {case['argv'][1][:78]}")
    print("      ...")

    # --- the benign corpus must itself run cleanly (else 'crashes' would be false positives) ------
    benign_cases = [
        {"id": f"benign-{i}", "argv": ["--request", json.dumps(seed)], "label": "benign"}
        for i, seed in enumerate(seeds)
    ]
    benign_bad = [r for r in run_batch(benign_cases) if r["exit_code"] != 0]
    baseline_ok = not benign_bad
    print(
        f"\n[3] benign baseline: {len(benign_cases)} run, {len(benign_bad)} crashed — "
        + ("OK, corpus is clean" if baseline_ok else "BAD, corpus is not actually benign")
    )

    # --- the fuzzer EXECUTES the campaign through the real batch runner ---------------------------
    records = run_batch(cases)
    crashes = [r for r in records if r["exit_code"] != 0]

    # --- dedup by crash shape, exactly like fuzz_channel.run() ------------------------------------
    buckets: dict[tuple[str, str], dict] = {}
    for record in crashes:
        key = (record.get("error_type", ""), record.get("crash_site", ""))
        bucket = buckets.setdefault(key, {"record": record, "hits": 0})
        bucket["hits"] += 1

    in_project = {key: bucket for key, bucket in buckets.items() if key[1]}
    print(
        f"\n[4] campaign: {len(records)} cases executed, {len(crashes)} crashed, "
        f"{len(buckets)} distinct crash shapes ({len(in_project)} in project code)"
    )
    for (error_type, crash_site), bucket in sorted(in_project.items()):
        record = bucket["record"]
        example = record["argv"][1][:60]
        message = record.get("error_message", "")[:50]
        print(
            f"      {error_type:18} @ {crash_site:20} x{bucket['hits']:<4} "
            f"e.g. {example}  ->  {message}"
        )

    ok = baseline_ok and bool(in_project)
    print(
        "\nRESULT: "
        + (
            "PASS - the fuzzer built a campaign, executed it, kept the benign corpus clean, "
            "and found real in-project crashes."
            if ok
            else "FAIL - see the steps above for which check did not hold."
        )
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
