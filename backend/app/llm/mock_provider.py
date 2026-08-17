"""Deterministic mock proposer.

Purpose: make the whole pipeline reproducible without a network or a GPU, so the test suite
and the offline demo exercise *the same code paths* as a hosted run. It is a **proposer**,
exactly like a real model — it emits JSON that then goes through the identical strict-schema
validation, the identical deterministic validators and the identical state machine.

It cheats at nothing that matters. In particular:

* clause proposals are derived only from the observation split, so the falsifier genuinely
  kills the ones that do not generalise to held-out traces;
* patches are real transformations of the real file contents (see :mod:`app.llm.recipes`);
* mutation payloads are candidate strings — whether any of them actually bypasses a patch is
  decided by executing them in the sandbox, not here.
"""

from __future__ import annotations

import json
import re
from typing import Any

from app.core.hashing import sha256_json
from app.core.logging import get_logger
from app.llm.base import LLMProvider, LLMRequest, LLMTask, TokenBudget
from app.llm.recipes import select_recipe

logger = get_logger(__name__)

_CWE_BY_RULE = {
    "kavachx.python.shell-injection": ("CWE-78", "CRITICAL", "forbidden_shell_invocation"),
    "kavachx.python.subprocess-shell-true": ("CWE-78", "CRITICAL", "forbidden_shell_invocation"),
    "kavachx.python.unbounded-index-write": ("CWE-1284", "HIGH", "input_length_bound"),
    "kavachx.python.path-traversal": ("CWE-22", "HIGH", "path_containment"),
    "kavachx.python.debug-enabled": ("CWE-489", "MEDIUM", "response_structure"),
    "kavachx.python.bind-all-interfaces": ("CWE-1327", "MEDIUM", "resource_constraint"),
    "kavachx.python.eval-exec": ("CWE-95", "CRITICAL", "forbidden_shell_invocation"),
    "kavachx.c.unbounded-memcpy": ("CWE-787", "CRITICAL", "input_length_bound"),
}

#: Shell separators worth trying. Which of these actually work depends on the host shell —
#: the sandbox decides that by running them.
_SEPARATORS = ["&", ";", "|", "&&", "||", "\n", "%0a", "$(:)", "`:`"]


class MockLLMProvider(LLMProvider):
    name = "mock"

    def __init__(self, *, budget: TokenBudget | None = None) -> None:
        super().__init__(timeout_seconds=5, max_retries=0, budget=budget)

    async def _raw_generate(
        self, request: LLMRequest[Any], *, attempt: int, repair_hint: str | None
    ) -> tuple[str, int, int, str]:
        handler = {
            LLMTask.PROBE_INTERFACES: self._probe,
            LLMTask.SAMHITA_PROPOSE: self._clauses,
            LLMTask.STATIC_TRIAGE: self._triage,
            LLMTask.ROOT_CAUSE: self._root_cause,
            LLMTask.PATCH_SYNTHESIS: self._patch,
            LLMTask.MUTATION_STRATEGIES: self._mutations,
            LLMTask.SIBLING_CANDIDATES: self._siblings,
        }.get(request.task)

        if handler is None:
            raise ValueError(f"mock provider has no script for task {request.task!r}")

        result = handler(request.payload)
        raw = json.dumps(result, sort_keys=True)
        system, user = self.build_prompt(request, repair_hint)
        return (
            raw,
            self.estimate_tokens(system) + self.estimate_tokens(user),
            self.estimate_tokens(raw),
            "mock-proposer/deterministic",
        )

    # ------------------------------------------------------------------
    def _probe(self, payload: dict[str, Any]) -> dict[str, Any]:
        files: list[str] = list(payload.get("files", []))
        candidates: list[dict[str, Any]] = list(payload.get("candidate_entrypoints", []))

        interfaces: list[dict[str, Any]] = []
        for candidate in candidates[:20]:
            path = str(candidate.get("path", ""))
            symbol = str(candidate.get("symbol", ""))
            kind = "cli" if path.endswith("main.py") or "__main__" in symbol else "library"
            if any(token in symbol.lower() for token in ("handle", "entrypoint", "dispatch")):
                kind = "library"
            interfaces.append(
                {
                    "entrypoint": f"{path}:{symbol}" if symbol else path,
                    "kind": kind,
                    "input_description": str(candidate.get("signature", ""))[:400],
                    "confidence": 0.9 if kind == "cli" else 0.7,
                }
            )

        build = ""
        test = ""
        for name in files:
            lowered = name.lower()
            if lowered.endswith("build.sh"):
                build = "bash build.sh"
            elif lowered.endswith("makefile") and not build:
                build = "make build"
            if "/tests/" in lowered or lowered.startswith("tests/"):
                test = "python -m pytest tests -q"
        return {"interfaces": interfaces, "build_command": build, "test_command": test}

    # ------------------------------------------------------------------
    def _clauses(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Derive clauses from the *observation split only*.

        Bounds taken from a partial sample are exactly the kind of over-fitted claim the
        held-out falsifier exists to kill, and several of these will not survive.
        """
        profiles: list[dict[str, Any]] = list(payload.get("value_profiles", []))
        clauses: list[dict[str, Any]] = []

        for profile in profiles:
            scope = str(profile.get("scope", ""))
            metric = str(profile.get("metric", ""))
            samples = int(profile.get("samples", 0))
            if not scope or samples == 0:
                continue

            kind = str(profile.get("kind", ""))
            observed_max = profile.get("max")
            observed_min = profile.get("min")
            distinct = profile.get("distinct_values")

            if kind == "length" and isinstance(observed_max, (int, float)):
                clauses.append(
                    {
                        "kind": "input_length_bound",
                        "description": (
                            f"{metric} in {scope} stays within the observed bound of "
                            f"{int(observed_max)}"
                        ),
                        "predicate": f"{metric} <= {int(observed_max)}",
                        "scope": scope,
                        "rationale": f"observed across {samples} benign invocations",
                        "confidence": 0.7,
                    }
                )
            elif kind == "count" and isinstance(observed_max, (int, float)):
                clauses.append(
                    {
                        "kind": "resource_constraint",
                        "description": f"{metric} in {scope} never exceeds {int(observed_max)}",
                        "predicate": f"{metric} <= {int(observed_max)}",
                        "scope": scope,
                        "rationale": f"observed across {samples} benign invocations",
                        "confidence": 0.65,
                    }
                )
            elif kind == "monotonic":
                clauses.append(
                    {
                        "kind": "monotonic_counter",
                        "description": f"{metric} in {scope} increases monotonically",
                        "predicate": f"{metric} >= 1",
                        "scope": scope,
                        "rationale": "counter observed strictly increasing",
                        "confidence": 0.8,
                    }
                )
            elif kind == "zero" and observed_max == 0:
                clauses.append(
                    {
                        "kind": "forbidden_shell_invocation"
                        if "shell" in metric
                        else "resource_constraint",
                        "description": f"{metric} in {scope} is never observed during benign use",
                        "predicate": f"{metric} == 0",
                        "scope": scope,
                        "rationale": f"zero occurrences across {samples} benign invocations",
                        "confidence": 0.85,
                    }
                )
            elif kind == "enum" and isinstance(distinct, list) and distinct:
                allowed = sorted({str(v) for v in distinct})[:12]
                clauses.append(
                    {
                        "kind": "response_structure",
                        "description": f"{metric} in {scope} is one of {allowed}",
                        "predicate": f"{metric} in {json.dumps(allowed)}",
                        "scope": scope,
                        "rationale": f"only these values seen in {samples} invocations",
                        "confidence": 0.6,
                    }
                )
            elif kind == "boolean":
                # Propose the polarity that was actually observed. Asserting `== True` for a
                # metric that was uniformly False would be an invented claim, and the
                # falsifier would rightly kill it — but proposing it at all is a bug, not a
                # useful demonstration of falsification.
                observed = bool(profile.get("all_true", True))
                clauses.append(
                    {
                        "kind": "nullability_assumption",
                        "description": (f"{metric} in {scope} is always {str(observed).lower()}"),
                        "predicate": f"{metric} == {observed}",
                        "scope": scope,
                        "rationale": f"held for all {samples} benign invocations",
                        "confidence": 0.7,
                    }
                )
            elif kind == "containment" and isinstance(observed_min, (int, float)):
                clauses.append(
                    {
                        "kind": "path_containment",
                        "description": f"{metric} in {scope} stays inside its declared root",
                        "predicate": f"{metric} == 1",
                        "scope": scope,
                        "rationale": f"held for all {samples} benign invocations",
                        "confidence": 0.75,
                    }
                )
        return {"clauses": clauses[:200]}

    # ------------------------------------------------------------------
    def _triage(self, payload: dict[str, Any]) -> dict[str, Any]:
        raw: list[dict[str, Any]] = list(payload.get("raw_findings", []))
        out: list[dict[str, Any]] = []
        for item in raw[:40]:
            rule = str(item.get("rule_id", ""))
            cwe, severity, clause_kind = _CWE_BY_RULE.get(rule, ("", "MEDIUM", ""))
            callers = int(item.get("caller_count", 0))
            reachable = bool(item.get("reachable_from_entrypoint", False))
            confidence = 0.55
            if cwe:
                confidence += 0.2
            if reachable:
                confidence += 0.15
            if callers:
                confidence += min(0.1, callers * 0.02)
            out.append(
                {
                    "rule_id": rule,
                    "location": str(item.get("location", ""))[:300],
                    "description": str(item.get("message", ""))[:600],
                    "severity": severity,
                    "candidate_clause_kind": clause_kind,
                    "confidence": round(min(confidence, 0.97), 2),
                    "cwe": cwe,
                }
            )
        return {"candidates": out}

    # ------------------------------------------------------------------
    def _root_cause(self, payload: dict[str, Any]) -> dict[str, Any]:
        frames: list[dict[str, Any]] = list(payload.get("trace_frames", []))
        sink = str(payload.get("sink_location", ""))
        project_frames = [f for f in frames if f.get("in_project")]

        chosen: dict[str, Any] | None = None
        if sink:
            sink_file = sink.split(":")[0]
            for frame in reversed(project_frames):
                if str(frame.get("file", "")).endswith(sink_file):
                    chosen = frame
                    break
        if chosen is None and project_frames:
            chosen = project_frames[-1]

        if chosen is None:
            return {
                "location": sink or "unknown:0",
                "function": "",
                "summary": "No project frame was present in the captured trace.",
                "causal_chain": [],
                "minimal_patch_location": sink or "",
                "confidence": 0.2,
            }

        location = f"{chosen.get('file', '')}:{chosen.get('line', 0)}"
        chain = [
            f"{f.get('file', '')}:{f.get('line', 0)} in {f.get('function', '?')}"
            for f in project_frames
        ]
        default_summary = "An unvalidated caller-controlled value reaches this statement."
        failure_summary = str(payload.get("failure_summary") or default_summary)
        function_name = str(chosen.get("function", "?"))
        return {
            "location": location,
            "function": str(chosen.get("function", "")),
            "summary": (
                f"The failure surfaces at {location} in {function_name}. {failure_summary}"
            )[:800],
            "causal_chain": chain[:12],
            "minimal_patch_location": location,
            "confidence": 0.82,
        }

    # ------------------------------------------------------------------
    def _patch(self, payload: dict[str, Any]) -> dict[str, Any]:
        files: dict[str, str] = dict(payload.get("files", {}))
        cwe = str(payload.get("cwe", ""))
        iteration = int(payload.get("iteration", 1))
        constraints = [str(c) for c in payload.get("constraints", [])]
        blocked = [str(t) for t in payload.get("observed_tokens", [])]

        if not files:
            raise ValueError("patch synthesis payload carried no file contents")

        target_path, content = next(iter(files.items()))
        recipe = select_recipe(
            cwe=cwe,
            content=content,
            iteration=iteration,
            constraints=constraints,
            blocked_tokens=blocked,
        )
        if recipe is None:
            raise ValueError(
                f"no deterministic recipe matched cwe={cwe!r} at iteration {iteration} "
                f"for {target_path}"
            )

        reason = recipe.reason
        if constraints:
            reason += "\n\nConstraints carried forward from refuted iterations:\n" + "\n".join(
                f"- {c}" for c in constraints
            )

        return {
            "reason": reason,
            "files": [{"path": target_path, "new_content": recipe.new_content}],
            "risk": recipe.risk,
            "expected_effect": recipe.expected_effect,
            "invariants_preserved": recipe.invariants_preserved,
        }

    # ------------------------------------------------------------------
    def _mutations(self, payload: dict[str, Any]) -> dict[str, Any]:
        pov = str(payload.get("pov_payload", ""))
        kind = str(payload.get("pov_kind", ""))
        blocked = [str(t) for t in payload.get("blocked_tokens", [])]
        marker = str(payload.get("marker", "KAVACHX_POV_MARKER"))

        strategies: list[dict[str, Any]] = []

        if kind == "command_injection":
            base = str(payload.get("base_value", "rep"))
            for separator in _SEPARATORS:
                if separator in blocked:
                    continue
                strategies.append(
                    {
                        "name": f"separator:{separator.strip() or 'newline'}",
                        "payload": f"{base}{separator}echo {marker}",
                        "rationale": (
                            f"{separator!r} is a command separator in at least one common "
                            "shell and is not in the blocked set."
                        ),
                    }
                )
            strategies.extend(
                [
                    {
                        "name": "encoded-separator",
                        "payload": f"{base}%26echo {marker}",
                        "rationale": "URL-encoded separator in case decoding happens later",
                    },
                    {
                        "name": "quote-break",
                        "payload": f'{base}"&echo {marker}',
                        "rationale": "quote break followed by a separator",
                    },
                    {
                        "name": "whitespace-padded",
                        "payload": f"{base}\t&\techo {marker}",
                        "rationale": "tab padding around the separator",
                    },
                ]
            )
        elif kind == "length_boundary":
            count = int(payload.get("base_count", 9))
            for extra in (0, 1, 8, 64):
                strategies.append(
                    {
                        "name": f"lines:{count + extra}",
                        "payload": "\n".join(f"h{i}:{i}" for i in range(count + extra)),
                        "rationale": f"{count + extra} header lines against the slot table",
                    }
                )
            strategies.append(
                {
                    "name": "blank-line-padding",
                    "payload": "\n\n".join(f"h{i}:{i}" for i in range(count)),
                    "rationale": "blank lines between headers in case they consume a slot",
                }
            )
        elif kind == "path_traversal":
            base = str(payload.get("base_value", "report.tmpl"))
            target = str(payload.get("traversal_target", "KAVACHX_CANARY.txt"))
            strategies.extend(
                [
                    {
                        "name": "dotdot-slash",
                        "payload": f"../{target}",
                        "rationale": "single traversal step",
                    },
                    {
                        "name": "dotdot-backslash",
                        "payload": f"..\\{target}",
                        "rationale": "Windows separator traversal",
                    },
                    {
                        "name": "nested-dotdot",
                        "payload": f"a/../../{target}",
                        "rationale": "traversal through a nested segment",
                    },
                    {
                        "name": "double-encoded",
                        "payload": f"..%2f{target}",
                        "rationale": "encoded separator",
                    },
                    {
                        "name": "prefix-suffix",
                        "payload": f"{base}/../{target}",
                        "rationale": "traversal appended to a legitimate asset name",
                    },
                ]
            )
        else:
            strategies.append(
                {
                    "name": "verbatim-replay",
                    "payload": pov,
                    "rationale": "replay the validated proof of vulnerability unchanged",
                }
            )

        # Verbatim replay is always included: a patch that does not even stop the original
        # payload must fail stage 1.
        if all(s["payload"] != pov for s in strategies) and pov:
            strategies.insert(
                0,
                {
                    "name": "verbatim-replay",
                    "payload": pov,
                    "rationale": "the original validated proof of vulnerability",
                },
            )
        return {"strategies": strategies[:32]}

    # ------------------------------------------------------------------
    def _siblings(self, payload: dict[str, Any]) -> dict[str, Any]:
        pattern = str(payload.get("pattern", ""))
        neighbours: list[dict[str, Any]] = list(payload.get("neighbours", []))
        out: list[dict[str, Any]] = []
        tokens = [t for t in re.split(r"\W+", pattern.lower()) if len(t) > 3]

        for neighbour in neighbours[:24]:
            snippet = str(neighbour.get("snippet", "")).lower()
            hits = sum(1 for token in tokens if token in snippet)
            if hits == 0:
                continue
            out.append(
                {
                    "location": str(neighbour.get("location", ""))[:300],
                    "function": str(neighbour.get("function", ""))[:200],
                    "why": f"shares {hits} indicator(s) with the repaired weakness pattern",
                    "confidence": round(min(0.3 + 0.15 * hits, 0.9), 2),
                }
            )
        return {"candidates": out}

    def fingerprint(self) -> str:
        """Stable identity of the scripted proposer, recorded on model-call evidence."""
        return sha256_json({"provider": self.name, "separators": _SEPARATORS})[:16]
