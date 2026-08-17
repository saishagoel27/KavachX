"""Blast-radius analysis.

::

    ROOT CAUSE
        ↓
    Affected Function
        ↓
    N Callers
        ↓
    M Modules
        ↓
    K SAMHITA Clauses
        ↓
    Regression Scope

Two jobs:

1. **Scope the regression.** Which callers, modules and contract clauses could this change
   affect? That set is what the differential-replay and SAMHITA-recheck stages have to cover.
2. **Bound the patch.** A patch that touches a file outside the computed radius is rejected by
   the policy gate. This is not a style preference: an unbounded patch means the gauntlet
   verified a smaller change than the one being published.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.analysis.world_model import WorldModel
from app.core.logging import get_logger
from app.samhita.engine import SamhitaResult

logger = get_logger(__name__)


@dataclass
class BlastRadius:
    root_cause_location: str = ""
    affected_function: str = ""
    affected_files: list[str] = field(default_factory=list)
    affected_functions: list[str] = field(default_factory=list)
    direct_callers: list[str] = field(default_factory=list)
    transitive_callers: list[str] = field(default_factory=list)
    modules: list[str] = field(default_factory=list)
    dependent_components: list[str] = field(default_factory=list)
    clause_ids: list[str] = field(default_factory=list)
    entrypoints_reached: list[str] = field(default_factory=list)
    #: Files a patch is permitted to touch.
    allowed_paths: list[str] = field(default_factory=list)
    regression_scope: str = ""
    score: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "root_cause_location": self.root_cause_location,
            "affected_function": self.affected_function,
            "affected_files": self.affected_files,
            "affected_functions": self.affected_functions,
            "direct_callers": self.direct_callers,
            "transitive_callers": self.transitive_callers,
            "modules": self.modules,
            "dependent_components": self.dependent_components,
            "clause_ids": self.clause_ids,
            "entrypoints_reached": self.entrypoints_reached,
            "allowed_paths": self.allowed_paths,
            "regression_scope": self.regression_scope,
            "score": self.score,
            "counts": {
                "files": len(self.affected_files),
                "functions": len(self.affected_functions),
                "direct_callers": len(self.direct_callers),
                "transitive_callers": len(self.transitive_callers),
                "modules": len(self.modules),
                "clauses": len(self.clause_ids),
            },
        }

    def chain(self) -> list[str]:
        """The display chain shown in the console panel."""
        return [
            f"ROOT CAUSE  {self.root_cause_location}",
            f"AFFECTED FUNCTION  {self.affected_function or 'unknown'}",
            f"{len(self.direct_callers)} DIRECT CALLERS",
            f"{len(self.transitive_callers)} TRANSITIVE CALLERS",
            f"{len(self.modules)} MODULES",
            f"{len(self.clause_ids)} SAMHITA CLAUSES",
            f"REGRESSION SCOPE  {self.regression_scope}",
        ]

    def permits(self, path: str) -> bool:
        return path in self.allowed_paths


def compute(
    *,
    model: WorldModel,
    samhita: SamhitaResult,
    root_cause_location: str,
    root_cause_function: str = "",
) -> BlastRadius:
    radius = BlastRadius(root_cause_location=root_cause_location)

    file, line = _split(root_cause_location)
    symbol = model.symbol_at(file, line)
    if symbol is None and root_cause_function:
        matches = model.find_symbols(root_cause_function)
        symbol = matches[0] if matches else None

    if symbol is None:
        # Fall back to file-level scope. Wider than necessary is the safe direction: it makes
        # the policy gate more permissive about *where*, but the gauntlet still has to verify
        # everything in the scope.
        radius.affected_files = [file] if file else []
        radius.affected_function = root_cause_function
        radius.allowed_paths = list(radius.affected_files)
        radius.modules = [file.rsplit("/", 1)[0]] if "/" in file else ["."]
        radius.regression_scope = "file"
        radius.clause_ids = [
            c.clause_id for c in samhita.surviving if c.scope.split(":")[0] == file
        ]
        radius.score = 0.4
        return radius

    radius.affected_function = symbol.qualname
    radius.affected_files = [symbol.file]
    radius.affected_functions = [symbol.handle]

    direct = sorted(set(model.callers.get(symbol.handle, [])))
    transitive = model.transitive_callers(symbol.handle)
    radius.direct_callers = direct
    radius.transitive_callers = transitive

    touched = {symbol.file, *(h.split(":")[0] for h in transitive)}
    radius.modules = sorted({p.rsplit("/", 1)[0] or "." for p in touched})

    # Only the file holding the root cause may be edited. Callers are in the *regression*
    # scope — they must be re-verified — but they are not licence to edit.
    radius.allowed_paths = [symbol.file]

    radius.affected_functions = sorted({symbol.handle, *direct})
    radius.clause_ids = sorted(
        {
            c.clause_id
            for c in samhita.surviving
            if c.scope == "*"
            or c.scope.split(":")[0] in touched
            or any(
                c.scope.endswith(f":{h.split(':')[1]}")
                for h in [symbol.handle, *direct]
                if ":" in h
            )
        }
    )

    entry_handles = {e.handle for e in model.entrypoints}
    radius.entrypoints_reached = sorted(
        entry_handles & set(transitive) | (entry_handles & {symbol.handle})
    )

    radius.dependent_components = sorted(
        {
            unit["file"]
            for unit in model.deployment_units
            if any(module in str(unit.get("signals", "")) for module in radius.modules)
        }
    )

    radius.regression_scope = _scope_label(len(transitive), len(radius.modules))
    radius.score = model.blast_radius_score(symbol.handle)

    logger.info(
        "blast_radius.computed",
        function=symbol.qualname,
        direct_callers=len(direct),
        transitive=len(transitive),
        modules=len(radius.modules),
        clauses=len(radius.clause_ids),
    )
    return radius


def _scope_label(transitive: int, modules: int) -> str:
    if transitive == 0:
        return "local"
    if modules <= 1:
        return "module"
    if modules <= 3:
        return "multi-module"
    return "service-wide"


def _split(location: str) -> tuple[str, int]:
    file, _, line = location.rpartition(":")
    try:
        return file, int(line)
    except ValueError:
        return location, 0
