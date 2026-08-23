"""A tiny metrics service with latent bugs a mutational fuzzer is meant to find.

Every operation is correct on the benign corpus (see ``corpus/benign``) and crashes only on inputs
the fuzzer synthesises by mutating that corpus — an emptied list, a zeroed count, a dropped or
retyped field. That is exactly the shape of bug KavachX's fuzz channel exists to surface: reachable
from the entrypoint, invisible to the happy-path tests, deterministic once the input is known.

Nothing here is contrived away from realism: each function is the obvious naive implementation that a
developer writes before thinking about the empty/zero/missing edge cases.
"""

from __future__ import annotations

from typing import Any

_LEVELS = {"low": 1, "medium": 5, "high": 9}


def entrypoint(request: dict[str, Any]) -> dict[str, Any]:
    """Dispatch one request to its operation. Unknown ops are a structured error, not a crash."""
    op = request.get("op")
    if op == "average":
        return {"ok": True, "average": _average(request)}
    if op == "peak":
        return {"ok": True, "peak": _peak(request)}
    if op == "weight":
        return {"ok": True, "weight": _weight(request)}
    return {"ok": False, "error": f"unknown op: {op!r}"}


def _average(request: dict[str, Any]) -> float:
    # ZeroDivisionError when count == 0 (the fuzzer sets ints to 0); KeyError if a field is dropped;
    # TypeError if total/count are retyped to strings.
    return request["total"] / request["count"]


def _peak(request: dict[str, Any]) -> Any:
    # KeyError if 'samples' is dropped; IndexError when samples == [] (the fuzzer empties lists).
    samples = request["samples"]
    highest = samples[0]
    for value in samples[1:]:
        if value > highest:
            highest = value
    return highest


def _weight(request: dict[str, Any]) -> int:
    # KeyError when 'level' is dropped or mutated to a label outside the table.
    return _LEVELS[request["level"]]
