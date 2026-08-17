"""Deterministic clause compiler.

A model proposes a predicate as a string. This module decides whether that string is a
*legal* clause predicate and turns it into an evaluable callable. It is the reason a
hallucinated clause cannot become executable: the grammar below is a whitelist, and anything
outside it — a call, an attribute access, a subscript, a comprehension, an f-string, a walrus —
is rejected outright rather than sanitised.

Allowed grammar::

    predicate  := expr
    expr       := comparison | boolop | unary | arith | atom
    comparison := expr (< <= > >= == != in not-in) expr ...
    boolop     := expr (and | or) expr ...
    unary      := not expr | -expr | +expr
    arith      := expr (+ - * / // % ) expr
    atom       := NAME | NUMBER | STRING | True | False | None | [atom,...] | (atom,...)

``NAME`` must resolve to a metric present in the observation namespace. There is no builtins
access at all: ``eval`` runs with ``{"__builtins__": {}}`` and only the metric namespace.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any

MAX_PREDICATE_LENGTH = 400
MAX_NODES = 120

_ALLOWED_NODES: tuple[type[ast.AST], ...] = (
    ast.Expression,
    ast.Compare,
    ast.BoolOp,
    ast.UnaryOp,
    ast.BinOp,
    ast.Name,
    ast.Load,
    ast.Constant,
    ast.List,
    ast.Tuple,
    ast.Set,
    # operators
    ast.And,
    ast.Or,
    ast.Not,
    ast.USub,
    ast.UAdd,
    ast.Eq,
    ast.NotEq,
    ast.Lt,
    ast.LtE,
    ast.Gt,
    ast.GtE,
    ast.In,
    ast.NotIn,
    ast.Add,
    ast.Sub,
    ast.Mult,
    ast.Div,
    ast.FloorDiv,
    ast.Mod,
)


class ClauseCompileError(ValueError):
    """The proposed predicate is not a legal clause predicate."""


@dataclass(slots=True)
class CompiledClause:
    predicate: str
    metrics: frozenset[str]
    code: Any  # compiled code object

    def evaluate(self, namespace: dict[str, Any]) -> bool | None:
        """Evaluate against one observation record.

        Returns ``None`` when the record does not carry every metric the predicate needs —
        "not applicable", which is distinct from "false". Conflating the two is how a clause
        gets falsified by an observation it never claimed to describe.
        """
        missing = self.metrics - namespace.keys()
        if missing:
            return None
        try:
            result = eval(self.code, {"__builtins__": {}}, dict(namespace))
        except Exception:
            return None
        return bool(result)


def compile_predicate(predicate: str) -> CompiledClause:
    text = (predicate or "").strip()
    if not text:
        raise ClauseCompileError("empty predicate")
    if len(text) > MAX_PREDICATE_LENGTH:
        raise ClauseCompileError(f"predicate exceeds {MAX_PREDICATE_LENGTH} characters")
    if "\n" in text or ";" in text:
        raise ClauseCompileError("predicate must be a single expression")

    try:
        tree = ast.parse(text, mode="eval")
    except SyntaxError as exc:
        raise ClauseCompileError(f"not a valid expression: {exc.msg}") from exc

    nodes = list(ast.walk(tree))
    if len(nodes) > MAX_NODES:
        raise ClauseCompileError("predicate is too complex")

    metrics: set[str] = set()
    for node in nodes:
        if not isinstance(node, _ALLOWED_NODES):
            raise ClauseCompileError(
                f"{type(node).__name__} is not permitted in a clause predicate"
            )
        if isinstance(node, ast.Name):
            if not node.id.replace("_", "").isalnum():
                raise ClauseCompileError(f"illegal metric name {node.id!r}")
            metrics.add(node.id)

    if not metrics:
        raise ClauseCompileError("predicate references no observation metric")

    # A clause must be able to *fail*: a predicate over constants only asserts nothing.
    if not _has_comparison(tree):
        raise ClauseCompileError("predicate must contain at least one comparison")

    code = compile(tree, filename="<samhita-clause>", mode="eval")
    return CompiledClause(predicate=text, metrics=frozenset(metrics), code=code)


def _has_comparison(tree: ast.AST) -> bool:
    return any(isinstance(node, ast.Compare) for node in ast.walk(tree))


def try_compile(predicate: str) -> tuple[CompiledClause | None, str]:
    try:
        return compile_predicate(predicate), ""
    except ClauseCompileError as exc:
        return None, str(exc)
