"""Intra-procedural taint analysis for Python.

The alternative — "a source rule matched somewhere in this function and a sink rule matched
somewhere in this function, therefore data flows from one to the other" — produces a flow for
every function that happens to touch both, and misses the thing that actually matters: whether the
value reaching the sink is *the same value* that came from the source, and whether anything
constrained it on the way.

This module answers that properly for Python by walking the AST of one function and propagating
taint through assignments, f-strings, concatenation, formatting, comprehensions, containers,
unpacking and calls. It reports, per (source, sink) pair inside a function:

* the chain of intermediate variables the value passed through,
* whether a sanitiser or validator was applied **to that value**,
* whether the sink argument is genuinely derived from the source.

Deliberate limits, stated because they bound what a flow may claim:

* **Intra-procedural.** Crossing a function boundary is the code graph's job — the flow builder
  stitches per-function taint results together along call edges. What this module never does is
  guess *across* a call it cannot see.
* **Python only.** Other languages fall back to the flow builder's line-proximity heuristic, which
  is recorded as a lower-confidence basis rather than presented as taint.
* **A sanitiser on the path lowers confidence; it never clears the flow.** Whether the sanitiser
  actually ran on the exploit input is a runtime question, and the sandbox answers it. A static
  "this is sanitised, therefore safe" conclusion is exactly the false negative that makes static
  analysis untrustworthy.
* **Field/subscript sensitivity is shallow.** ``request.args["a"]`` taints the whole expression;
  KavachX does not track which key. Over-approximating within a tainted container is the safe
  direction.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any

from app.core.logging import get_logger
from app.security_model.taxonomy import Rule, Taxonomy

logger = get_logger(__name__)

#: Cap on tracked variables per function. A pathological generated function will not exhaust
#: memory in the process supervising the run.
_MAX_TRACKED = 400
#: Cap on chain length recorded per flow.
_MAX_CHAIN = 24


@dataclass(slots=True)
class TaintStep:
    """One hop a tainted value took inside a function."""

    line: int
    kind: str  # source | assign | transform | sanitize | validate | sink | return
    name: str
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"line": self.line, "kind": self.kind, "name": self.name, "detail": self.detail}


@dataclass
class TaintFinding:
    """A tainted value reaching a sink inside one function."""

    function: str
    file: str
    source_rule: str
    source_kind: str
    source_line: int
    sink_rule: str
    sink_kind: str
    sink_line: int
    cwe: str = ""
    severity: str = "MEDIUM"
    #: Ordered hops from source to sink.
    chain: list[TaintStep] = field(default_factory=list)
    #: Sanitisers/validators applied to *this* value before the sink.
    sanitizers: list[str] = field(default_factory=list)
    validators: list[str] = field(default_factory=list)
    #: "taint" when the AST proved derivation; "proximity" for the fallback.
    basis: str = "taint"
    confidence: float = 0.0
    #: True when the sink argument is a formatted/concatenated string built from the source —
    #: the classic injection shape.
    interpolated: bool = False

    @property
    def sanitized(self) -> bool:
        return bool(self.sanitizers)

    def as_dict(self) -> dict[str, Any]:
        return {
            "function": self.function,
            "file": self.file,
            "source": {
                "rule": self.source_rule,
                "kind": self.source_kind,
                "line": self.source_line,
            },
            "sink": {"rule": self.sink_rule, "kind": self.sink_kind, "line": self.sink_line},
            "cwe": self.cwe,
            "severity": self.severity,
            "chain": [s.as_dict() for s in self.chain],
            "sanitizers": self.sanitizers,
            "validators": self.validators,
            "sanitized": self.sanitized,
            "basis": self.basis,
            "confidence": round(self.confidence, 3),
            "interpolated": self.interpolated,
        }


@dataclass(slots=True)
class _Taint:
    """Taint state attached to one variable name."""

    source_rule: str
    source_kind: str
    source_line: int
    chain: list[TaintStep] = field(default_factory=list)
    sanitizers: list[str] = field(default_factory=list)
    validators: list[str] = field(default_factory=list)
    interpolated: bool = False

    def derive(self, step: TaintStep) -> _Taint:
        return _Taint(
            source_rule=self.source_rule,
            source_kind=self.source_kind,
            source_line=self.source_line,
            chain=[*self.chain[:_MAX_CHAIN], step],
            sanitizers=list(self.sanitizers),
            validators=list(self.validators),
            interpolated=self.interpolated,
        )


def _dotted(node: ast.AST) -> str:
    """Dotted name of a call target or attribute chain, or ``""``."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


class _FunctionTaint(ast.NodeVisitor):
    """Walks one function body, propagating taint."""

    def __init__(
        self,
        *,
        file: str,
        function: str,
        taxonomy: Taxonomy,
        source_lines: list[str],
    ) -> None:
        self.file = file
        self.function = function
        self.taxonomy = taxonomy
        self.lines = source_lines
        self.tainted: dict[str, _Taint] = {}
        self.findings: list[TaintFinding] = []
        self._sanitizer_names = taxonomy.sanitizer_callables()
        self._sink_by_callable = taxonomy.sink_callables()

    # -- helpers -----------------------------------------------------------
    def _line_text(self, line: int) -> str:
        return self.lines[line - 1] if 0 < line <= len(self.lines) else ""

    def _source_rule_for_line(self, line: int) -> Rule | None:
        """Does a source rule match this line?"""
        text = self._line_text(line)
        if not text:
            return None
        best: Rule | None = None
        for rule in self.taxonomy.sources:
            if rule.compiled.search(text) and (best is None or rule.confidence > best.confidence):
                best = rule
        return best

    def _match_callable(
        self, node: ast.Call, candidates: dict[str, Rule]
    ) -> Rule | None:
        """Match a call target against rule callables, without laundering the qualifier.

        Two matching modes, and the distinction between them is load-bearing:

        * **Dotted target** (``json.loads``) — requires an *exact* dotted match. An explicitly
          qualified call has already told us which module it belongs to.
        * **Bare target** (``loads`` after ``from pickle import loads``) — may match a rule's
          callable on its last segment, because the qualifier genuinely is not in the call.

        Collapsing these two, as a naive last-segment match does, is not a small imprecision: it
        makes ``json.loads(data)`` match the rule for ``pickle.loads`` and report CWE-502
        arbitrary-code-execution on a safe JSON parse. Measured on the seeded demo target, that
        single conflation produced a CRITICAL false positive on ``main.py`` at confidence 0.92 —
        which is exactly the kind of result that makes a security tool unusable.
        """
        target = _dotted(node.func)
        if not target:
            return None
        exact = candidates.get(target)
        if exact is not None:
            return exact
        if isinstance(node.func, ast.Name):
            bare = target
            for name, candidate in candidates.items():
                if name.rsplit(".", 1)[-1] == bare:
                    return candidate
        return None

    def _sink_rule_for(self, node: ast.Call, line: int) -> Rule | None:
        """Is this call a sink?

        Callable match first (precise, survives reformatting, never fires on a comment or a string
        that merely contains ``os.system``), then the line pattern for rules expressed as syntax
        rather than as a callee — ``shell=True`` is a keyword argument, not a function name.
        """
        rule = self._match_callable(node, self._sink_by_callable)
        if rule is not None:
            return rule
        text = self._line_text(line)
        for candidate in self.taxonomy.sinks:
            if candidate.compiled.search(text):
                return candidate
        return None

    def _sanitizer_rule_for(self, node: ast.Call) -> Rule | None:
        by_callable: dict[str, Rule] = {}
        for rule in [*self.taxonomy.sanitizers, *self.taxonomy.validators]:
            for name in rule.callables:
                by_callable.setdefault(name, rule)
        return self._match_callable(node, by_callable)

    # -- taint of an expression -------------------------------------------
    def _taint_of(self, node: ast.AST | None) -> _Taint | None:
        """The taint carried by an expression, or ``None``.

        Structural recursion, so ``f"{a}-{sanitize(b)}"`` correctly reports tainted-by-``a`` and
        notes ``b``'s sanitiser only on ``b``'s own contribution.
        """
        if node is None:
            return None

        # A literal source expression: `request.args`, `os.environ`, `sys.argv`.
        line = getattr(node, "lineno", 0)
        if isinstance(node, (ast.Attribute, ast.Subscript, ast.Call, ast.Name)):
            dotted = _dotted(node if not isinstance(node, ast.Subscript) else node.value)
            if dotted:
                rule = self._source_rule_for_line(line)
                # Only treat the line's source match as *this* expression's source when the
                # expression text plausibly is the source — otherwise every expression on a line
                # containing `request.args` would be tainted.
                if rule is not None and rule.compiled.search(dotted):
                    return _Taint(
                        source_rule=rule.id,
                        source_kind=rule.kind,
                        source_line=line,
                        chain=[TaintStep(line, "source", dotted, rule.why)],
                    )

        if isinstance(node, ast.Name):
            return self.tainted.get(node.id)

        if isinstance(node, ast.Subscript):
            # Indexing a tainted container yields a tainted element.
            return self._taint_of(node.value)

        if isinstance(node, ast.Attribute):
            return self._taint_of(node.value)

        if isinstance(node, ast.Starred):
            return self._taint_of(node.value)

        if isinstance(node, ast.Await):
            return self._taint_of(node.value)

        if isinstance(node, ast.BinOp):
            # String concatenation / % formatting: either operand taints the result.
            left = self._taint_of(node.left)
            right = self._taint_of(node.right)
            carrier = left or right
            if carrier is None:
                return None
            derived = carrier.derive(
                TaintStep(line, "transform", "concat/format", "value combined into a string")
            )
            derived.interpolated = True
            return derived

        if isinstance(node, ast.JoinedStr):  # f-string
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    carrier = self._taint_of(value.value)
                    if carrier is not None:
                        derived = carrier.derive(
                            TaintStep(line, "transform", "f-string", "interpolated into a string")
                        )
                        derived.interpolated = True
                        return derived
            return None

        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for element in node.elts:
                carrier = self._taint_of(element)
                if carrier is not None:
                    return carrier.derive(TaintStep(line, "transform", "container", ""))
            return None

        if isinstance(node, ast.Dict):
            for value in [*node.keys, *node.values]:
                carrier = self._taint_of(value)
                if carrier is not None:
                    return carrier.derive(TaintStep(line, "transform", "dict", ""))
            return None

        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            carrier = self._taint_of(node.elt)
            if carrier is not None:
                return carrier
            for generator in node.generators:
                carrier = self._taint_of(generator.iter)
                if carrier is not None:
                    return carrier.derive(TaintStep(line, "transform", "comprehension", ""))
            return None

        if isinstance(node, ast.IfExp):
            return self._taint_of(node.body) or self._taint_of(node.orelse)

        if isinstance(node, ast.Call):
            return self._taint_of_call(node, line)

        return None

    def _taint_of_call(self, node: ast.Call, line: int) -> _Taint | None:
        """Taint flowing out of a call.

        A sanitiser call records itself on the value and keeps it tainted. That is the
        load-bearing decision in this module: marking it clean would turn "a sanitiser appears
        here" into "this is safe", which is a static conclusion about a runtime fact.
        """
        arguments = [*node.args, *[k.value for k in node.keywords if k.value is not None]]
        carrier: _Taint | None = None
        for argument in arguments:
            carrier = self._taint_of(argument)
            if carrier is not None:
                break
        if carrier is None:
            carrier = self._taint_of(node.func) if isinstance(node.func, ast.Attribute) else None
        if carrier is None:
            return None

        sanitizer = self._sanitizer_rule_for(node)
        if sanitizer is not None:
            derived = carrier.derive(
                TaintStep(line, "sanitize", _dotted(node.func), sanitizer.why)
            )
            if sanitizer.category == "VALIDATOR":
                derived.validators = [*derived.validators, sanitizer.id]
            else:
                derived.sanitizers = [*derived.sanitizers, sanitizer.id]
            return derived

        # Any other call is treated as a transform that preserves taint. Over-approximating here
        # is the safe direction: assuming a helper launders its input is how a real flow gets lost.
        return carrier.derive(
            TaintStep(line, "transform", _dotted(node.func) or "call", "passed through a call")
        )

    # -- statements --------------------------------------------------------
    def _assign(self, target: ast.AST, taint: _Taint | None) -> None:
        if isinstance(target, ast.Name):
            if taint is None:
                self.tainted.pop(target.id, None)
            elif len(self.tainted) < _MAX_TRACKED:
                self.tainted[target.id] = taint.derive(
                    TaintStep(getattr(target, "lineno", 0), "assign", target.id, "")
                )
        elif isinstance(target, (ast.Tuple, ast.List)):
            # Unpacking a tainted iterable taints every binding — the element-wise split is not
            # tracked, and assuming otherwise would drop real flows.
            for element in target.elts:
                self._assign(element, taint)
        elif isinstance(target, (ast.Attribute, ast.Subscript)) and taint is not None:
            base = _dotted(target if isinstance(target, ast.Attribute) else target.value)
            root = base.split(".")[0] if base else ""
            if root and len(self.tainted) < _MAX_TRACKED:
                self.tainted[root] = taint

    def visit_Assign(self, node: ast.Assign) -> None:
        taint = self._taint_of(node.value)
        for target in node.targets:
            self._assign(target, taint)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        taint = self._taint_of(node.value)
        self._assign(node.target, taint)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        # `cmd += user_input` — combine existing and incoming taint.
        incoming = self._taint_of(node.value)
        existing = self._taint_of(node.target)
        carrier = existing or incoming
        if carrier is not None:
            derived = carrier.derive(
                TaintStep(node.lineno, "transform", "augmented assignment", "")
            )
            derived.interpolated = True
            self._assign(node.target, derived)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """A call is where a sink is recognised and a finding is produced."""
        rule = self._sink_rule_for(node, node.lineno)
        if rule is not None:
            arguments = [*node.args, *[k.value for k in node.keywords if k.value is not None]]
            for argument in arguments:
                taint = self._taint_of(argument)
                if taint is None:
                    continue
                self._record(taint, rule, node.lineno)
                break
        self.generic_visit(node)

    def _record(self, taint: _Taint, rule: Rule, line: int) -> None:
        chain = [*taint.chain, TaintStep(line, "sink", rule.kind, rule.why)]
        finding = TaintFinding(
            function=self.function,
            file=self.file,
            source_rule=taint.source_rule,
            source_kind=taint.source_kind,
            source_line=taint.source_line,
            sink_rule=rule.id,
            sink_kind=rule.kind,
            sink_line=line,
            cwe=rule.cwe,
            severity=rule.severity,
            chain=chain[:_MAX_CHAIN],
            sanitizers=list(taint.sanitizers),
            validators=list(taint.validators),
            basis="taint",
            interpolated=taint.interpolated,
        )
        finding.confidence = _confidence(finding, rule)
        # One finding per (source line, sink line) pair; the first chain found is the shortest.
        key = (finding.source_line, finding.sink_line, finding.sink_rule)
        if key not in {(f.source_line, f.sink_line, f.sink_rule) for f in self.findings}:
            self.findings.append(finding)


def _confidence(finding: TaintFinding, rule: Rule) -> float:
    """Deterministic confidence for a taint finding.

    Starts from the sink rule's own prior, raised when the value is interpolated into a string
    (the injection shape) and lowered when a sanitiser or validator was applied. It never reaches
    1.0: this is static evidence, and only execution can confirm.
    """
    score = rule.confidence
    if finding.interpolated:
        score += 0.15
    if finding.validators:
        score -= 0.15
    if finding.sanitizers:
        score -= 0.35
    # A long chain is weaker evidence: more inferred hops, more chance one of them launders.
    hops = len([s for s in finding.chain if s.kind == "transform"])
    score -= min(0.2, 0.03 * hops)
    return max(0.05, min(0.95, round(score, 3)))


# ---------------------------------------------------------------------------
def analyse_file(
    *, path: str, text: str, taxonomy: Taxonomy
) -> tuple[list[TaintFinding], str]:
    """Run taint analysis over every function in one Python file.

    Returns ``(findings, error)``. A syntax error is returned rather than raised: a repository
    under analysis is allowed to contain unparseable files, and one bad file must not stop the
    security model from being built for the rest of the tree.
    """
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError) as exc:
        return [], f"{type(exc).__name__}: {str(exc)[:200]}"

    lines = text.splitlines()
    language_taxonomy = taxonomy.for_language("python")
    findings: list[TaintFinding] = []

    class _Collector(ast.NodeVisitor):
        def __init__(self) -> None:
            self.scope: list[str] = []

        def _run(self, node: ast.AST, name: str) -> None:
            qualname = ".".join([*self.scope, name])
            analyser = _FunctionTaint(
                file=path, function=qualname, taxonomy=language_taxonomy, source_lines=lines
            )
            # Parameters are untainted at entry; cross-function taint is stitched by the flow
            # builder along call edges, which is where the caller's argument is actually known.
            for statement in getattr(node, "body", []):
                analyser.visit(statement)
            findings.extend(analyser.findings)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._run(node, node.name)
            self.scope.append(node.name)
            self.generic_visit(node)
            self.scope.pop()

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._run(node, node.name)
            self.scope.append(node.name)
            self.generic_visit(node)
            self.scope.pop()

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            self.scope.append(node.name)
            self.generic_visit(node)
            self.scope.pop()

    _Collector().visit(tree)

    # Module level: code outside any function is executed at import and is worth the same scan.
    module_body = [
        statement
        for statement in tree.body
        if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    ]
    if module_body:
        analyser = _FunctionTaint(
            file=path, function="<module>", taxonomy=language_taxonomy, source_lines=lines
        )
        for statement in module_body:
            analyser.visit(statement)
        findings.extend(analyser.findings)

    return findings, ""
