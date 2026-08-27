"""Coverage as feedback, not decoration.

Coverage appears twice in KavachX and the two uses are different:

1. **As a bound on assurance.** "39% of statements executed" is what stops a Level A certificate
   from being read as "this code is safe". That use already existed via SAMHITA's observation
   coverage; this module gives it a typed home.

2. **As a steering signal.** A coverage-guided loop keeps an input when it reaches something new
   and discards it when it does not. That comparison is what makes guided fuzzing find inputs a
   blind campaign will not, and it needs a delta, not a percentage.

The model may *receive* coverage — covered paths, uncovered branches, newly reached functions —
and propose a better strategy from it. It never computes it, and its proposal is judged by whether
coverage actually moved, which :meth:`CoverageObservation.new_relative_to` decides.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.core.hashing import sha256_json
from app.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class CoverageObservation:
    """Coverage measured from one execution or one campaign."""

    #: ``file:line`` entries that executed.
    covered_lines: set[str] = field(default_factory=set)
    #: Symbol uids / scopes observed executing.
    covered_scopes: set[str] = field(default_factory=set)
    total_statements: int = 0
    covered_statements: int = 0
    #: Where the numbers came from: kx_observe | atheris | libfuzzer | go | none.
    source: str = "none"
    #: False when nothing was executed. Distinct from 0% coverage of an executed run.
    measured: bool = False
    reason: str = ""

    @property
    def percent(self) -> float:
        if not self.total_statements:
            return 0.0
        return round(100.0 * self.covered_statements / self.total_statements, 2)

    def new_relative_to(self, other: CoverageObservation) -> set[str]:
        """Lines this observation reached that ``other`` did not. The steering signal."""
        return self.covered_lines - other.covered_lines

    def merge(self, other: CoverageObservation) -> CoverageObservation:
        """Union of two observations, for accumulating a campaign's reach."""
        return CoverageObservation(
            covered_lines=self.covered_lines | other.covered_lines,
            covered_scopes=self.covered_scopes | other.covered_scopes,
            total_statements=max(self.total_statements, other.total_statements),
            covered_statements=len(self.covered_lines | other.covered_lines)
            or max(self.covered_statements, other.covered_statements),
            source=self.source if self.source != "none" else other.source,
            measured=self.measured or other.measured,
        )

    def as_dict(self, *, limit: int = 400) -> dict[str, Any]:
        return {
            "measured": self.measured,
            "reason": self.reason,
            "source": self.source,
            "percent": self.percent,
            "total_statements": self.total_statements,
            "covered_statements": self.covered_statements,
            "covered_scopes": sorted(self.covered_scopes)[:limit],
            "covered_line_count": len(self.covered_lines),
            "covered_lines_sample": sorted(self.covered_lines)[:limit],
        }

    def content_hash(self) -> str:
        return sha256_json(
            {"lines": sorted(self.covered_lines), "scopes": sorted(self.covered_scopes)}
        )


def unmeasured(reason: str) -> CoverageObservation:
    """An explicit non-measurement.

    Returned instead of an empty observation so downstream code cannot read "we did not measure"
    as "nothing was covered" — the difference between an unknown and a zero.
    """
    return CoverageObservation(measured=False, reason=reason, source="none")


def from_observation_set(observations: Any, *, source: str = "kx_observe") -> CoverageObservation:
    """Adapt the existing SAMHITA observation set into a coverage observation.

    Reuses the harness KavachX already injects rather than adding a second instrumentation path:
    two coverage measurements of the same run that disagree would be worse than one.
    """
    if observations is None:
        return unmeasured("No observation set was produced.")
    covered_lines: set[str] = set()
    covered_scopes: set[str] = set()
    try:
        covered_scopes = set(observations.scopes())
    except Exception:  # pragma: no cover - defensive
        covered_scopes = set()
    for record in getattr(observations, "records", []) or []:
        scope = getattr(record, "scope", "")
        line = getattr(record, "line", 0) or (getattr(record, "metrics", {}) or {}).get("line", 0)
        if scope and line:
            covered_lines.add(f"{scope.split(':')[0]}:{line}")
    total = int(getattr(observations, "total_statements", 0) or 0)
    covered = int(getattr(observations, "covered_statements", 0) or 0)
    return CoverageObservation(
        covered_lines=covered_lines,
        covered_scopes=covered_scopes,
        total_statements=total,
        covered_statements=covered or len(covered_lines),
        source=source,
        measured=bool(covered_scopes or covered_lines or total),
        reason="" if (covered_scopes or total) else "The harness ran but recorded no coverage.",
    )


@dataclass
class UncoveredBranch:
    """A branch the campaign has not reached, with a hint about what would reach it."""

    location: str
    condition: str = ""
    #: Concrete values the code-aware seeder derived from the condition text.
    suggested_values: list[str] = field(default_factory=list)
    owner: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "location": self.location,
            "condition": self.condition,
            "suggested_values": self.suggested_values,
            "owner": self.owner,
        }


def uncovered_branches(
    *,
    code_graph: Any,
    coverage: CoverageObservation,
    root: Any,
    focus_symbols: list[str] | None = None,
    limit: int = 40,
) -> list[UncoveredBranch]:
    """Find unreached conditional branches and derive concrete values that would reach them.

    This is the code-aware half of code-aware fuzzing. The spec's example is exact: if the
    uncovered branch is ``if limit < 0:``, the campaign should try ``-1``, ``0``, ``1`` and
    boundary values rather than random bytes. So the condition text is parsed for comparisons
    against literals, and the literal plus its neighbours become suggested inputs.

    Suggestions are *hints* for the deterministic mutator. Whether an input actually reaches the
    branch is decided by re-measuring coverage, never by assuming.
    """
    import ast
    from pathlib import Path

    from app.indexing.model import NodeKind

    out: list[UncoveredBranch] = []
    focus = set(focus_symbols or [])
    root_path = Path(root)

    for file_node in code_graph.nodes_of(NodeKind.FILE.value):
        if file_node.language != "python" or file_node.attrs.get("skipped_reason"):
            continue
        path = root_path / file_node.uid
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(text)
        except (OSError, SyntaxError, ValueError):
            continue
        lines = text.splitlines()

        for node in ast.walk(tree):
            if not isinstance(node, (ast.If, ast.While, ast.Assert, ast.IfExp)):
                continue
            location = f"{file_node.uid}:{node.lineno}"
            if location in coverage.covered_lines:
                continue
            owner = code_graph.symbol_at(file_node.uid, node.lineno)
            owner_uid = owner.uid if owner else ""
            if focus and owner_uid not in focus:
                continue
            condition = (
                lines[node.lineno - 1].strip()[:200] if node.lineno <= len(lines) else ""
            )
            test = getattr(node, "test", None)
            out.append(
                UncoveredBranch(
                    location=location,
                    condition=condition,
                    suggested_values=_values_for(test),
                    owner=owner_uid,
                )
            )
            if len(out) >= limit:
                logger.info("testing.uncovered_branches", found=len(out), truncated=True)
                return out
    logger.info("testing.uncovered_branches", found=len(out), truncated=False)
    return out


def _values_for(test: Any) -> list[str]:
    """Concrete input values derived from a condition's comparisons against literals."""
    import ast

    values: list[str] = []
    if test is None:
        return values

    for node in ast.walk(test):
        if isinstance(node, ast.Compare):
            for comparator in node.comparators:
                if isinstance(comparator, ast.Constant):
                    literal = comparator.value
                    if isinstance(literal, bool):
                        values.extend(["true", "false"])
                    elif isinstance(literal, int):
                        # The boundary and both sides of it: the classic off-by-one triple.
                        values.extend([str(literal - 1), str(literal), str(literal + 1)])
                    elif isinstance(literal, float):
                        values.extend([str(literal), str(literal - 1), str(literal + 1)])
                    elif isinstance(literal, str):
                        values.extend([literal, literal.upper(), literal + "x", ""])
        elif isinstance(node, ast.Call):
            name = getattr(node.func, "id", "") or getattr(node.func, "attr", "")
            if name == "len":
                # A length comparison wants inputs at, below and above the bound; the bound
                # itself is picked up by the Compare branch above.
                values.extend(["", "x", "x" * 64, "x" * 1024])
    # Deduplicate, preserving order — a stable suggestion list keeps the campaign reproducible.
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered[:12]


def feedback_payload(
    *,
    coverage: CoverageObservation,
    previous: CoverageObservation | None,
    branches: list[UncoveredBranch],
    crashes: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """The coverage feedback block handed to the model when it proposes a better strategy.

    Deliberately small and specific: newly reached functions, the uncovered branches with their
    conditions, and any crash. A model given a full line-by-line coverage map spends its context on
    data it cannot act on.
    """
    newly = sorted(coverage.new_relative_to(previous))[:60] if previous else []
    return {
        "coverage": {
            "measured": coverage.measured,
            "percent": coverage.percent,
            "covered_statements": coverage.covered_statements,
            "total_statements": coverage.total_statements,
            "source": coverage.source,
            "reason": coverage.reason,
        },
        "newly_covered_lines": newly,
        "newly_covered_count": len(newly),
        "uncovered_branches": [b.as_dict() for b in branches[:20]],
        "crashes": (crashes or [])[:10],
        "note": (
            "Propose inputs likely to reach the uncovered branches. Whether they do is decided by "
            "re-measuring coverage after execution, not by your assessment."
        ),
    }
