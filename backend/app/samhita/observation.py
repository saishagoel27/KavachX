"""Benign-workload observation and value profiling.

Flow::

    Benign Workload → Observation → Value Profiles

The benign corpus is executed **inside the sandbox** under the tracing harness
(:mod:`app.sandbox.harness.kx_observe`). What comes back is a list of concrete function
invocations with argument/return profiles, plus guard counters and real line coverage.

Those invocations are then split:

* **observation split** — the only thing the clause proposer is shown;
* **held-out split** — never shown to the proposer, used solely to falsify.

The split is by *case*, not by record, so a whole benign scenario is withheld rather than a few
scattered calls. That makes the falsification meaningful: a clause survives only if it
generalises to behaviour the proposer never saw.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.logging import get_logger

logger = get_logger(__name__)

SAFE_CHARSET = re.compile(r"^[A-Za-z0-9._\-/]+$")
#: Only characters that actually change *what command runs*. Brackets and tildes appear in
#: ordinary Windows paths (``Program Files (x86)``), so counting them would make the metric
#: noisy on benign input and weaken every clause derived from it.
SHELL_METACHARS = ";|&`$><\n\r"
MAX_ENUM_CARDINALITY = 8
MAX_ENUM_VALUE_LENGTH = 40

GLOBAL_SCOPE = "*"


@dataclass(slots=True)
class ObservationRecord:
    """One observed event with a flat metric namespace."""

    scope: str
    case_id: str
    kind: str  # call | case | global
    metrics: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "scope": self.scope,
            "case_id": self.case_id,
            "kind": self.kind,
            "metrics": self.metrics,
        }


@dataclass(slots=True)
class ValueProfile:
    scope: str
    metric: str
    kind: str  # length | count | enum | boolean | monotonic | zero | containment
    samples: int = 0
    min: float | None = None
    max: float | None = None
    distinct_values: list[Any] = field(default_factory=list)
    all_true: bool = True
    monotonic: bool = True

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "scope": self.scope,
            "metric": self.metric,
            "kind": self.kind,
            "samples": self.samples,
        }
        if self.min is not None:
            out["min"] = self.min
        if self.max is not None:
            out["max"] = self.max
        if self.distinct_values:
            out["distinct_values"] = self.distinct_values
        if self.kind == "boolean":
            out["all_true"] = self.all_true
        if self.kind == "monotonic":
            out["monotonic"] = self.monotonic
        return out


@dataclass(slots=True)
class ObservationSet:
    records: list[ObservationRecord] = field(default_factory=list)
    coverage_percent: float = 0.0
    covered_statements: int = 0
    total_statements: int = 0
    guard: dict[str, Any] = field(default_factory=dict)
    case_results: list[dict[str, Any]] = field(default_factory=list)
    raw_hash: str = ""

    def scopes(self) -> set[str]:
        return {record.scope for record in self.records}

    def for_scope(self, scope: str) -> list[ObservationRecord]:
        return [r for r in self.records if r.scope == scope]


# ---------------------------------------------------------------------------
def build_observe_spec(
    *,
    project_root: str,
    source_root: str,
    entry_module: str,
    entry_callable: str,
    cases: list[dict[str, Any]],
    passes: int = 1,
) -> dict[str, Any]:
    return {
        "project_root": project_root,
        "source_root": source_root,
        "entry_module": entry_module,
        "entry_callable": entry_callable,
        "cases": cases,
        "passes": passes,
    }


def load_benign_corpus(corpus_dir: Path, *, limit: int = 40) -> list[dict[str, Any]]:
    """Load the benign workload. Each case becomes one CLI invocation."""
    cases: list[dict[str, Any]] = []
    if not corpus_dir.is_dir():
        return cases
    for path in sorted(corpus_dir.glob("*.json"))[:limit]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        cases.append(
            {
                "id": path.stem,
                "argv": ["--request", json.dumps(payload, sort_keys=True)],
                "request": payload,
            }
        )
    return cases


def split_cases(
    cases: list[dict[str, Any]], *, holdout_ratio: float = 0.4
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Deterministic split by case id.

    Every third case is held out, which spreads the holdout across the corpus instead of
    withholding one contiguous tail — a tail split would let a proposer see all the small
    inputs and none of the large ones purely by ordering accident.
    """
    ordered = sorted(cases, key=lambda c: str(c.get("id", "")))
    stride = max(2, round(1 / max(holdout_ratio, 0.05)))
    observation: list[dict[str, Any]] = []
    holdout: list[dict[str, Any]] = []
    for index, case in enumerate(ordered):
        (holdout if index % stride == stride - 1 else observation).append(case)
    if not holdout and ordered:
        holdout.append(ordered[-1])
        observation = ordered[:-1]
    return observation, holdout


# ---------------------------------------------------------------------------
def parse_observations(document: dict[str, Any]) -> ObservationSet:
    """Turn the harness document into metric-bearing records."""
    result = ObservationSet()
    coverage = document.get("coverage") or {}
    result.coverage_percent = float(coverage.get("percent", 0.0) or 0.0)
    result.covered_statements = int(coverage.get("covered_statements", 0) or 0)
    result.total_statements = int(coverage.get("total_statements", 0) or 0)
    result.guard = dict(document.get("guard") or {})
    result.case_results = list(document.get("cases") or [])

    # Function-level records ------------------------------------------------
    for call in document.get("calls") or []:
        file = str(call.get("file", ""))
        function = str(call.get("function", ""))
        if not file or not function or function.startswith("<"):
            continue
        scope = f"{file}:{function}"
        metrics: dict[str, Any] = {}

        for name, profile in (call.get("args") or {}).items():
            if not isinstance(profile, dict):
                continue
            safe_name = _metric_name(name)
            if "len" in profile:
                metrics[f"arg_len_{safe_name}"] = int(profile["len"])
            if "lines" in profile:
                metrics[f"arg_lines_{safe_name}"] = int(profile["lines"])
            value = profile.get("value")
            if isinstance(value, bool):
                metrics[f"arg_bool_{safe_name}"] = value
            elif isinstance(value, (int, float)):
                metrics[f"arg_value_{safe_name}"] = value
            elif isinstance(value, str):
                metrics[f"arg_safe_charset_{safe_name}"] = bool(SAFE_CHARSET.match(value))
                metrics[f"arg_metachars_{safe_name}"] = sum(
                    1 for ch in value if ch in SHELL_METACHARS
                )
                if len(value) <= MAX_ENUM_VALUE_LENGTH:
                    metrics[f"arg_str_{safe_name}"] = value
            elif value is None and profile.get("type") == "NoneType":
                metrics[f"arg_is_none_{safe_name}"] = True

        ret = call.get("ret")
        if isinstance(ret, dict):
            if "ok" in ret:
                metrics["ret_ok"] = bool(ret["ok"])
            if "seq" in ret:
                metrics["ret_seq"] = int(ret["seq"])
            if "op" in ret:
                metrics["ret_op"] = str(ret["op"])
            if "len" in ret:
                metrics["ret_len"] = int(ret["len"])
            if ret.get("type") == "NoneType":
                metrics["ret_is_none"] = True
            elif "type" in ret:
                metrics["ret_is_none"] = False

        if metrics:
            result.records.append(
                ObservationRecord(
                    scope=scope,
                    case_id=str(call.get("case_id", "")),
                    kind="call",
                    metrics=metrics,
                )
            )

    # Case-level records ---------------------------------------------------
    #
    # Guard activity is folded into the per-case record from that case's *delta*, not from the
    # run's running totals. A clause like ``shell_invocations == 1`` then means "this operation
    # spawns one shell", which is a statement about behaviour and stays true whatever the corpus
    # size. A clause over the total would only be a statement about how many cases ran.
    for case in result.case_results:
        metrics: dict[str, Any] = {
            "case_exit_code": int(case.get("exit_code", 0)),
            "case_crashed": int(case.get("exit_code", 0)) != 0,
            "case_has_response": case.get("response") is not None,
        }
        response = case.get("response")
        if isinstance(response, dict):
            metrics["response_ok"] = bool(response.get("ok", False))
            if "op" in response:
                metrics["response_op"] = str(response["op"])
            metrics["response_keys"] = len(response)

        delta = case.get("guard_delta") or {}
        if delta:
            metrics["shell_invocations"] = int(delta.get("shell_invocations", 0))
            metrics["process_invocations"] = int(delta.get("process_invocations", 0))
            metrics["network_attempts"] = int(delta.get("network_attempts", 0))
            metrics["egress_bytes"] = int(delta.get("egress_bytes", 0))
            metrics["reads_outside_root"] = int(delta.get("reads_outside_root", 0))
            metrics["shell_command_metachars"] = _max_metachars(delta.get("subprocess_calls") or [])

        result.records.append(
            ObservationRecord(
                scope=GLOBAL_SCOPE,
                case_id=str(case.get("id", "")),
                kind="case",
                metrics=metrics,
            )
        )
    return result


def _max_metachars(calls: list[Any]) -> int:
    """Worst-case shell metacharacter count across a case's subprocess invocations."""
    worst = 0
    for entry in calls:
        if not isinstance(entry, dict):
            continue
        rendered = " ".join(str(a) for a in (entry.get("argv") or []))
        worst = max(worst, sum(1 for ch in rendered if ch in SHELL_METACHARS))
    return worst


def _metric_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", name)
    return cleaned or "arg"


# ---------------------------------------------------------------------------
def derive_value_profiles(observations: ObservationSet) -> list[ValueProfile]:
    """Aggregate records into per-(scope, metric) profiles."""
    buckets: dict[tuple[str, str], list[Any]] = {}
    for record in observations.records:
        for metric, value in record.metrics.items():
            buckets.setdefault((record.scope, metric), []).append(value)

    profiles: list[ValueProfile] = []
    for (scope, metric), values in sorted(buckets.items()):
        profile = _profile_for(scope, metric, values)
        if profile is not None:
            profiles.append(profile)
    return profiles


def _profile_for(scope: str, metric: str, values: list[Any]) -> ValueProfile | None:
    if not values:
        return None

    if all(isinstance(v, bool) for v in values):
        return ValueProfile(
            scope=scope,
            metric=metric,
            kind="boolean",
            samples=len(values),
            all_true=all(values),
        )

    numeric = [v for v in values if isinstance(v, (int, float)) and not isinstance(v, bool)]
    if numeric and len(numeric) == len(values):
        low, high = min(numeric), max(numeric)
        if metric == "ret_seq":
            monotonic = all(b >= a for a, b in zip(numeric, numeric[1:], strict=False))
            return ValueProfile(
                scope=scope,
                metric=metric,
                kind="monotonic",
                samples=len(numeric),
                min=low,
                max=high,
                monotonic=monotonic,
            )
        if high == 0 and low == 0:
            # Never observed at all during benign operation — the strongest kind of claim,
            # and the one most likely to be violated by an exploit.
            return ValueProfile(
                scope=scope, metric=metric, kind="zero", samples=len(numeric), min=0, max=0
            )
        kind = "length" if ("len" in metric or "lines" in metric) else "count"
        return ValueProfile(
            scope=scope, metric=metric, kind=kind, samples=len(numeric), min=low, max=high
        )

    strings = [v for v in values if isinstance(v, str)]
    if strings and len(strings) == len(values):
        distinct = sorted(set(strings))
        if len(distinct) <= MAX_ENUM_CARDINALITY and all(
            len(v) <= MAX_ENUM_VALUE_LENGTH for v in distinct
        ):
            return ValueProfile(
                scope=scope,
                metric=metric,
                kind="enum",
                samples=len(strings),
                distinct_values=distinct,
            )
    return None


def profiles_payload(profiles: list[ValueProfile], *, limit: int = 300) -> list[dict[str, Any]]:
    """Compact profile list for the proposer. Only aggregates — no raw values."""
    return [p.as_dict() for p in profiles[:limit]]


def widen_profiles(
    base: list[ValueProfile], counterexamples: list[dict[str, Any]]
) -> list[ValueProfile]:
    """Extend numeric bounds with observed counterexamples.

    Used only on clause iteration 2: a bound that was too tight because the proposer saw a
    partial sample gets one chance to widen to the value that actually falsified it. The
    widened clause is then re-falsified against the same held-out split.
    """
    by_key = {(p.scope, p.metric): p for p in base}
    for counter in counterexamples:
        scope = str(counter.get("scope", ""))
        metric = str(counter.get("metric", ""))
        value = counter.get("value")
        profile = by_key.get((scope, metric))
        if profile is None:
            continue

        if isinstance(value, str) and profile.kind == "enum":
            if value not in profile.distinct_values:
                if len(profile.distinct_values) >= MAX_ENUM_CARDINALITY:
                    # Too many distinct values to be a meaningful membership clause; drop it
                    # rather than widen it into something that asserts nothing.
                    by_key.pop((scope, metric), None)
                    continue
                profile.distinct_values = sorted([*profile.distinct_values, value])
                profile.samples += 1
            continue

        if not isinstance(value, (int, float)) or isinstance(value, bool):
            continue
        if profile.kind not in ("length", "count", "zero"):
            continue
        if profile.max is None or value > profile.max:
            profile.max = value
            profile.samples += 1
            if profile.kind == "zero":
                # A metric that was never observed during the observation split but *does*
                # occur in held-out traces is not a "never happens" invariant at all.
                profile.kind = "count"
    return list(by_key.values())
