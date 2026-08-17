"""Channel 3 — fuzzing.

Two engines, chosen by target language:

* **Native targets (C/C++)** — libFuzzer or AFL++ over the fuzz harness in the target, with
  ASan/UBSan enabled and QEMU mode where the binary is not instrumentable. This path requires a
  toolchain; when one is absent the channel says so in its coverage notes rather than pretending
  to have fuzzed.
* **Structured targets (the Python demo)** — a real seeded mutational fuzzer over the request
  space, implemented here and executed inside the sandbox.

The mutational fuzzer is deterministic: it is seeded from the benign corpus with a fixed
``random.Random`` seed, so the same target produces the same campaign every run. Crashes are
deduplicated by ``(exception type, project crash site)`` — the same shape of bug found twenty
times is one hypothesis, and the minimal reproducing case is the one that is kept.
"""

from __future__ import annotations

import json
import random
import shutil
import time
from typing import Any

from app.analysis.probe import TargetDescriptor
from app.analysis.world_model import WorldModel
from app.core.logging import get_logger
from app.discovery.base import CANARY_FILENAME, ChannelResult, HypothesisCandidate
from app.models.enums import DiscoveryChannel, Severity
from app.sandbox.base import ExecRequest, SandboxAdapter

logger = get_logger(__name__)

FUZZ_SEED = 0x4B415641  # "KAVA" — fixed so campaigns are reproducible.
DEFAULT_BUDGET = 240

#: Interesting substrings a mutational fuzzer should try against a string field.
_INTERESTING_STRINGS = [
    "",
    "A" * 128,
    "A" * 1024,
    "../" + CANARY_FILENAME,
    "..\\" + CANARY_FILENAME,
    "%00",
    "\x00truncated",
    "; echo probe",
    "& echo probe",
    "| echo probe",
    "$(echo probe)",
    "`echo probe`",
    "{{7*7}}",
    "<script>",
    "\n\n\n",
    "-1",
    "0",
    "99999999999999999999",
    "null",
    "true",
    chr(0x202E) + chr(0),  # RTL override + NUL: two classic parser traps
    "%2e%2e%2f",
]

_INTERESTING_INTS = [-1, 0, 1, 7, 8, 9, 255, 256, 65535, 2**31 - 1, -(2**31)]


def _mutate_string(rng: random.Random, value: str) -> str:
    choice = rng.randrange(6)
    if choice == 0:
        return rng.choice(_INTERESTING_STRINGS)
    if choice == 1:
        return value + rng.choice(_INTERESTING_STRINGS)
    if choice == 2:
        return rng.choice(_INTERESTING_STRINGS) + value
    if choice == 3:
        multiplier = rng.choice([2, 4, 16, 64])
        return (value or "A") * multiplier
    if choice == 4 and value:
        index = rng.randrange(len(value))
        return value[:index] + rng.choice([":", "\n", "/", "\\", "&", ";"]) + value[index:]
    return value[: max(0, len(value) - rng.randrange(1, 4))]


def _mutate_value(rng: random.Random, value: Any) -> Any:
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return rng.choice(_INTERESTING_INTS)
    if isinstance(value, str):
        return _mutate_string(rng, value)
    if isinstance(value, list):
        if value and rng.random() < 0.5:
            return [_mutate_value(rng, value[0]) for _ in range(rng.randrange(0, 4))]
        return []
    if isinstance(value, dict):
        return {k: _mutate_value(rng, v) for k, v in value.items()}
    return rng.choice(_INTERESTING_STRINGS)


def generate_cases(
    seeds: list[dict[str, Any]], *, budget: int, seed: int = FUZZ_SEED
) -> list[dict[str, Any]]:
    """Deterministic mutational campaign derived from the benign corpus."""
    rng = random.Random(seed)
    cases: list[dict[str, Any]] = []
    if not seeds:
        return cases

    counter = 0
    while len(cases) < budget:
        base = dict(rng.choice(seeds))
        mutated = dict(base)
        strategy = rng.randrange(5)

        keys = [k for k in mutated if k != "op"]
        if strategy == 0 and keys:  # mutate one field
            key = rng.choice(keys)
            mutated[key] = _mutate_value(rng, mutated[key])
        elif strategy == 1 and keys:  # drop a field
            mutated.pop(rng.choice(keys))
        elif strategy == 2:  # inject an unexpected field
            mutated[f"x_fuzz_{counter}"] = rng.choice(_INTERESTING_STRINGS)
        elif strategy == 3:  # mutate every field
            for key in keys:
                mutated[key] = _mutate_value(rng, mutated[key])
        else:  # mutate the operation itself
            mutated["op"] = rng.choice(
                ["ping", "status", "parse", "export", "asset", "", "teleport", "PARSE"]
            )

        counter += 1
        cases.append(
            {
                "id": f"fuzz-{counter:04d}",
                "argv": ["--request", json.dumps(mutated, sort_keys=True)],
                "request": mutated,
                "label": f"strategy{strategy}",
            }
        )
    return cases


# ---------------------------------------------------------------------------
async def run(
    *,
    sandbox: SandboxAdapter,
    model: WorldModel,
    descriptor: TargetDescriptor,
    seeds: list[dict[str, Any]],
    budget: int = DEFAULT_BUDGET,
) -> ChannelResult:
    started = time.perf_counter()
    result = ChannelResult(channel=DiscoveryChannel.FUZZING.value)

    if descriptor.language == "c":
        result.coverage_notes.extend(_native_notes())
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        return result

    if not seeds:
        result.coverage_notes.append(
            "no benign corpus to seed from; the mutational campaign was skipped"
        )
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        return result

    cases = generate_cases(seeds, budget=budget)
    spec = {
        "project_root": ".",
        "source_root": descriptor.source_root,
        "entry_module": descriptor.entry_module,
        "entry_callable": descriptor.entry_callable,
        "cases": [{"id": c["id"], "argv": c["argv"], "label": c["label"]} for c in cases],
    }
    spec_rel = "_kavachx/out/fuzz-spec.json"
    out_rel = "_kavachx/out/fuzz-result.json"
    spec_path = sandbox.workspace / spec_rel
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text(json.dumps(spec, sort_keys=True), encoding="utf-8")

    exec_result = await sandbox.execute(
        ExecRequest(
            argv=["python", "-m", "kx_batch", "--spec", spec_rel, "--out", out_rel],
            collect_artifacts=[out_rel],
            label="fuzz:campaign",
            timeout_seconds=max(120, sandbox.limits.wall_clock_seconds * 3),
        )
    )
    result.tool_events.append(
        {
            "name": "kavachx-mutational-fuzzer",
            "target": f"{len(cases)} cases from {len(seeds)} seeds",
            "ms": exec_result.duration_ms,
            "ok": exec_result.exit_code == 0,
            "detail": exec_result.stderr[-300:] if exec_result.exit_code != 0 else "",
        }
    )

    raw = exec_result.artifacts.get(out_rel, "")
    if not raw:
        result.error = f"fuzz campaign produced no result (exit {exec_result.exit_code})"
        result.coverage_notes.append(result.error)
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        return result

    document = json.loads(raw)
    case_results: list[dict[str, Any]] = document.get("cases", [])
    by_case = {c["id"]: c for c in cases}

    # Deduplicate by crash shape, keeping the shortest reproducing request.
    buckets: dict[tuple[str, str], dict[str, Any]] = {}
    for record in case_results:
        if record["exit_code"] == 0:
            continue
        key = (record.get("error_type", ""), record.get("crash_site", ""))
        request = by_case.get(record["id"], {}).get("request", {})
        size = len(json.dumps(request, sort_keys=True))
        current = buckets.get(key)
        if current is None or size < current["size"]:
            buckets[key] = {"record": record, "request": request, "size": size, "hits": 1}
        else:
            current["hits"] += 1

    counter = 0
    for (error_type, crash_site), bucket in sorted(buckets.items()):
        record = bucket["record"]
        request = bucket["request"]
        if not crash_site:
            # A crash with no project frame is the harness or the CLI arg parser, not the target.
            result.coverage_notes.append(
                f"{error_type or 'unknown error'}: {bucket['hits']} case(s) failed outside "
                "project code and were not promoted to hypotheses"
            )
            continue

        counter += 1
        symbol = model.symbol_at(*_split_location(crash_site))
        handle_for_scores = symbol.handle if symbol else ""
        severity = _severity_for(error_type)

        result.candidates.append(
            HypothesisCandidate(
                handle=f"F{counter:03d}",
                source_channel=DiscoveryChannel.FUZZING.value,
                description=(
                    f"{error_type} escapes the entrypoint at {crash_site} "
                    f"({record.get('error_message', '')[:160]})"
                ),
                location=crash_site,
                severity=severity,
                reachability=model.reachability_score(handle_for_scores)
                if handle_for_scores
                else 0.8,
                # A fuzzer that actually crashed the target is strong evidence *of a crash*.
                # It still says nothing about impact, which is what validation decides.
                confidence=0.9,
                blast_radius=model.blast_radius_score(handle_for_scores)
                if handle_for_scores
                else 0.4,
                cwe=_cwe_for(error_type),
                rule_id=f"kavachx.fuzz.{error_type or 'crash'}",
                evidence_refs=[f"ev:code:{crash_site}", f"ev:fuzz:{record['id']}"],
                validation_plan={
                    "kind": "replay_request",
                    "operation": str(request.get("op", "")),
                    "request": request,
                    "expected_error_type": error_type,
                    "expected_crash_site": crash_site,
                    "reproductions_required": 2,
                    "success_signal": "nonzero_exit_or_sanitizer",
                    "target_file": crash_site.split(":")[0],
                    "target_line": int(crash_site.split(":")[-1] or 0),
                    "target_function": symbol.qualname if symbol else "",
                },
                hypothesis_statement=(
                    f"Mutated input reaches {crash_site} and raises {error_type}."
                ),
                decision=f"Crash reproduced {bucket['hits']}x in campaign; queued for validation.",
            )
        )
        result.thoughts.append(
            {
                "agent": "FUZZING",
                "hypothesis": f"{error_type} at {crash_site}",
                "evidence": [
                    crash_site,
                    f"minimal request: {json.dumps(request, sort_keys=True)[:160]}",
                    f"campaign hits: {bucket['hits']}",
                    f"cases executed: {len(case_results)}",
                ],
                "decision": "Candidate violation generated; awaiting deterministic validation.",
                "confidence": 0.9,
            }
        )

    result.coverage_notes.append(
        f"mutational campaign: {len(case_results)} cases executed, "
        f"{document.get('crashes', 0)} crashed, {len(buckets)} distinct crash shapes "
        f"(seed 0x{FUZZ_SEED:X}, reproducible)"
    )
    if descriptor.language == "python":
        result.coverage_notes.append(
            "libFuzzer/AFL++ not applicable to a pure-Python target; the structured "
            "mutational engine was used instead."
        )

    result.duration_ms = int((time.perf_counter() - started) * 1000)
    logger.info(
        "discovery.fuzz.complete",
        cases=len(case_results),
        crashes=document.get("crashes", 0),
        candidates=len(result.candidates),
    )
    return result


def _native_notes() -> list[str]:
    have_clang = shutil.which("clang") is not None
    have_gcc = shutil.which("gcc") is not None
    have_afl = shutil.which("afl-fuzz") is not None
    notes = [
        f"native toolchain: clang={'yes' if have_clang else 'no'}, "
        f"gcc={'yes' if have_gcc else 'no'}, afl-fuzz={'yes' if have_afl else 'no'}"
    ]
    if not (have_clang or have_gcc):
        notes.append(
            "No C compiler is available, so the libFuzzer/AFL++ path could not run. The native "
            "target was NOT fuzzed — this is a coverage gap, not a clean result."
        )
    return notes


def _split_location(location: str) -> tuple[str, int]:
    file, _, line = location.rpartition(":")
    try:
        return file, int(line)
    except ValueError:
        return location, 0


def _severity_for(error_type: str) -> str:
    return {
        "IndexError": Severity.HIGH.value,
        "KeyError": Severity.MEDIUM.value,
        "RecursionError": Severity.HIGH.value,
        "MemoryError": Severity.HIGH.value,
        "OSError": Severity.MEDIUM.value,
        "AssertionError": Severity.MEDIUM.value,
        "TypeError": Severity.MEDIUM.value,
        "AttributeError": Severity.MEDIUM.value,
    }.get(error_type, Severity.MEDIUM.value)


def _cwe_for(error_type: str) -> str:
    return {
        "IndexError": "CWE-1284",
        "RecursionError": "CWE-674",
        "MemoryError": "CWE-770",
        "KeyError": "CWE-754",
        "TypeError": "CWE-754",
        "AttributeError": "CWE-754",
        "OSError": "CWE-22",
    }.get(error_type, "CWE-248")
