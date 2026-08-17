"""Static analysis: Semgrep when available, a built-in AST ruleset always.

Two paths, in order of preference:

1. **Semgrep.** If the ``semgrep`` binary is on PATH, the rule pack in
   :data:`SEMGREP_RULES` is written to a temporary file and Semgrep is run over the workspace.
2. **Built-in AST rules.** Always run, and the only path when Semgrep is absent. These are
   real ``ast`` analyses with light intra-procedural data flow — not regex matching. Each rule
   answers a specific structural question, e.g. "is this index variable ever compared against
   a bound anywhere in the function that writes with it?".

Everything produced here is a **candidate**. A candidate becomes a hypothesis, a hypothesis
becomes a finding only after the validator reproduces it inside the sandbox. Nothing in this
module is allowed to conclude that anything is exploitable.
"""

from __future__ import annotations

import ast
import json
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.logging import get_logger
from app.sandbox.spawn import run_process

logger = get_logger(__name__)

SHELL_RUNNERS = {"run", "Popen", "call", "check_call", "check_output"}
OS_EXEC = {"system", "popen", "execv", "execve", "execvp", "spawnl", "spawnv"}


def _render_call(node: ast.AST) -> str:
    """Dotted name of a call target, e.g. ``requests.get`` or ``ssl._create_unverified_context``.

    Returns ``""`` for anything that is not a plain name or attribute chain — a call through a
    subscript or another call is not something these rules try to reason about.
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _render_call(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


@dataclass(slots=True)
class RawFinding:
    rule_id: str
    location: str
    message: str
    file: str
    line: int
    snippet: str = ""
    function: str = ""
    engine: str = "builtin-ast"
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "location": self.location,
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
            "function": self.function,
            "engine": self.engine,
            **self.metadata,
        }


# ---------------------------------------------------------------------------
# Semgrep rule pack — the same intent as the built-in rules, expressed for Semgrep.
# ---------------------------------------------------------------------------
SEMGREP_RULES: dict[str, Any] = {
    "rules": [
        {
            "id": "kavachx.python.subprocess-shell-true",
            "message": "subprocess invoked with shell=True",
            "severity": "ERROR",
            "languages": ["python"],
            "metadata": {"cwe": "CWE-78"},
            "patterns": [{"pattern-either": [{"pattern": "subprocess.$F(..., shell=True, ...)"}]}],
        },
        {
            "id": "kavachx.python.eval-exec",
            "message": "dynamic code evaluation",
            "severity": "ERROR",
            "languages": ["python"],
            "metadata": {"cwe": "CWE-95"},
            "patterns": [{"pattern-either": [{"pattern": "eval(...)"}, {"pattern": "exec(...)"}]}],
        },
        {
            "id": "kavachx.python.path-traversal",
            "message": "path joined from caller-controlled value without containment check",
            "severity": "WARNING",
            "languages": ["python"],
            "metadata": {"cwe": "CWE-22"},
            "patterns": [{"pattern": "$ROOT / $USERPATH"}],
        },
        {
            "id": "kavachx.c.unbounded-memcpy",
            "message": "memcpy with a length that is not visibly clamped",
            "severity": "ERROR",
            "languages": ["c"],
            "metadata": {"cwe": "CWE-787"},
            "patterns": [{"pattern": "memcpy($DST, $SRC, $LEN);"}],
        },
    ]
}


# ---------------------------------------------------------------------------
class _PythonRuleVisitor(ast.NodeVisitor):
    """Built-in AST rules with light intra-procedural reasoning."""

    def __init__(self, path: str, source: str) -> None:
        self.path = path
        self.lines = source.splitlines()
        self.findings: list[RawFinding] = []
        self.function_stack: list[ast.FunctionDef | ast.AsyncFunctionDef] = []

    # -- helpers -----------------------------------------------------------
    def _snippet(self, line: int) -> str:
        if 1 <= line <= len(self.lines):
            return self.lines[line - 1].strip()[:300]
        return ""

    def _current_function(self) -> str:
        return self.function_stack[-1].name if self.function_stack else ""

    def _emit(
        self,
        rule_id: str,
        node: ast.AST,
        message: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        line = getattr(node, "lineno", 0)
        self.findings.append(
            RawFinding(
                rule_id=rule_id,
                location=f"{self.path}:{line}",
                message=message,
                file=self.path,
                line=line,
                snippet=self._snippet(line),
                function=self._current_function(),
                metadata=metadata or {},
            )
        )

    def _params(self) -> set[str]:
        if not self.function_stack:
            return set()
        args = self.function_stack[-1].args
        names = {a.arg for a in [*args.posonlyargs, *args.args, *args.kwonlyargs]}
        if args.vararg:
            names.add(args.vararg.arg)
        if args.kwarg:
            names.add(args.kwarg.arg)
        return names - {"self", "cls"}

    # -- traversal ---------------------------------------------------------
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.function_stack.append(node)
        self._check_unbounded_index_write(node)
        self._check_path_containment(node)
        self.generic_visit(node)
        self.function_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_Call(self, node: ast.Call) -> None:
        self._check_shell(node)
        self._check_dynamic_eval(node)
        self._check_sql_injection(node)
        self._check_deserialisation(node)
        self._check_tls_verification(node)
        self._check_flask_debug(node)
        self._check_template_injection(node)
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        self._check_config_dict(node)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self._check_bind_all(node)
        self._check_hardcoded_secret(node)
        self.generic_visit(node)

    # -- rules added for real-world third-party code ------------------------
    #
    # The seeded demo exercises injection, bounds and traversal. Real repositories fail in a wider
    # but still small set of ways, and a scanner that only knows the demo's shapes would report a
    # clean bill of health on code that is plainly not clean. Each rule below is AST-based and
    # deliberately narrow: it fires on a *constructed* value reaching a dangerous sink, not on the
    # mere presence of a library.

    def _is_dynamic_string(self, node: ast.AST) -> tuple[bool, bool]:
        """(is built at runtime, traces back to a parameter).

        An f-string, ``%`` format, ``.format()`` or ``+`` concatenation is dynamic. A plain literal
        is not — and a literal query or path is not a finding.
        """
        if isinstance(node, ast.Constant):
            return False, False

        dynamic = isinstance(node, (ast.JoinedStr, ast.BinOp)) or (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("format", "join")
        )
        if isinstance(node, ast.Name):
            dynamic = True

        tainted = set()
        names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
        if names:
            tainted = names & (self._params() | self._locals_from_params())
        return dynamic, bool(tainted)

    def _check_sql_injection(self, node: ast.Call) -> None:
        """A query string built at runtime and handed to execute()."""
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr not in (
            "execute",
            "executemany",
            "executescript",
            "raw",
        ):
            return
        if not node.args:
            return

        dynamic, tainted = self._is_dynamic_string(node.args[0])
        if not dynamic:
            return
        # A second positional argument is the parameter sequence — that is the *correct* pattern,
        # so a dynamic first argument alongside it is far more likely to be table-name templating
        # than injection. Report it only when nothing is being parameterised.
        if len(node.args) > 1:
            return

        self._emit(
            "kavachx.python.sql-injection",
            node,
            (
                f"{func.attr}() receives a query string assembled at runtime"
                + (
                    ", reachable from this function's parameters, with no bound parameters."
                    if tainted
                    else " with no bound parameters."
                )
            ),
            {"sink": func.attr, "parameter_influenced": tainted, "parameterised": False},
        )

    def _check_deserialisation(self, node: ast.Call) -> None:
        func = node.func
        if not isinstance(func, ast.Attribute):
            return
        owner = func.value.id if isinstance(func.value, ast.Name) else ""

        if owner == "pickle" and func.attr in ("load", "loads"):
            self._emit(
                "kavachx.python.insecure-deserialisation",
                node,
                f"pickle.{func.attr} executes arbitrary code from its input.",
                {"sink": f"pickle.{func.attr}"},
            )
        elif owner in ("yaml", "ruamel") and func.attr in ("load", "load_all"):
            # yaml.load with an explicit SafeLoader is fine; the bare call is not.
            loader = next((kw for kw in node.keywords if kw.arg in ("Loader", "loader")), None)
            rendered = _render_call(loader.value) if loader else ""
            if "Safe" in rendered or "safe" in rendered:
                return
            self._emit(
                "kavachx.python.insecure-deserialisation",
                node,
                (
                    f"yaml.{func.attr} without a safe loader constructs arbitrary Python objects "
                    "from its input."
                ),
                {"sink": f"yaml.{func.attr}", "loader": rendered or "default"},
            )
        elif owner in ("marshal", "shelve", "dill", "jsonpickle") and func.attr in (
            "load",
            "loads",
            "open",
        ):
            self._emit(
                "kavachx.python.insecure-deserialisation",
                node,
                f"{owner}.{func.attr} deserialises untrusted data into live objects.",
                {"sink": f"{owner}.{func.attr}"},
            )

    def _check_tls_verification(self, node: ast.Call) -> None:
        for keyword in node.keywords:
            if keyword.arg == "verify" and isinstance(keyword.value, ast.Constant):
                if keyword.value.value is False:
                    self._emit(
                        "kavachx.python.tls-verification-disabled",
                        node,
                        (
                            f"{_render_call(node.func)} is called with verify=False, which "
                            "disables certificate validation."
                        ),
                        {"sink": _render_call(node.func)},
                    )
            if keyword.arg in ("ssl_context", "cert_reqs") and isinstance(
                keyword.value, ast.Attribute
            ):
                if keyword.value.attr in ("CERT_NONE", "_create_unverified_context"):
                    self._emit(
                        "kavachx.python.tls-verification-disabled",
                        node,
                        "TLS certificate validation is explicitly disabled.",
                        {"sink": _render_call(node.func)},
                    )
        if _render_call(node.func).endswith("_create_unverified_context"):
            self._emit(
                "kavachx.python.tls-verification-disabled",
                node,
                "ssl._create_unverified_context() disables certificate validation.",
                {"sink": "ssl._create_unverified_context"},
            )

    def _check_flask_debug(self, node: ast.Call) -> None:
        """``app.run(debug=True)`` — the Werkzeug console is a remote shell."""
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "run":
            return
        debug = next((kw for kw in node.keywords if kw.arg == "debug"), None)
        if (
            debug is None
            or not isinstance(debug.value, ast.Constant)
            or debug.value.value is not True
        ):
            return
        host = next((kw for kw in node.keywords if kw.arg == "host"), None)
        exposed = (
            isinstance(host.value, ast.Constant) and host.value.value in ("0.0.0.0", "::")
            if host
            else False
        )
        self._emit(
            "kavachx.python.debug-server",
            node,
            (
                "The development server is started with debug=True"
                + (
                    " and bound to every interface, exposing the interactive debugger."
                    if exposed
                    else ", which enables the interactive debugger."
                )
            ),
            {"sink": _render_call(node.func), "bound_all_interfaces": exposed},
        )

    def _check_template_injection(self, node: ast.Call) -> None:
        rendered = _render_call(node.func)
        if not rendered.endswith("render_template_string"):
            return
        if not node.args:
            return
        dynamic, tainted = self._is_dynamic_string(node.args[0])
        if not dynamic:
            return
        self._emit(
            "kavachx.python.template-injection",
            node,
            (
                "render_template_string() receives a template assembled at runtime"
                + (
                    ", reachable from this function's parameters — the template language is "
                    "executable."
                    if tainted
                    else " — the template language is executable."
                )
            ),
            {"sink": "render_template_string", "parameter_influenced": tainted},
        )

    def _check_hardcoded_secret(self, node: ast.Assign) -> None:
        """A credential-shaped name assigned a non-trivial string literal."""
        if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
            return
        value = node.value.value
        # Short values and obvious placeholders are configuration, not a leak.
        if len(value) < 8 or value.lower() in (
            "changeme",
            "password",
            "secret",
            "your-key-here",
            "todo",
        ):
            return
        if value.startswith(("${", "{{", "<", "os.environ")) or "example" in value.lower():
            return

        markers = ("secret", "password", "passwd", "token", "api_key", "apikey", "private_key")
        for target in node.targets:
            name = ""
            if isinstance(target, ast.Name):
                name = target.id
            elif isinstance(target, ast.Attribute):
                name = target.attr
            elif isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant):
                name = str(target.slice.value)
            if not name:
                continue
            lowered = name.lower()
            if any(marker in lowered for marker in markers):
                self._emit(
                    "kavachx.python.hardcoded-secret",
                    node,
                    (
                        f"{name} is assigned a hardcoded string literal. A credential in source is "
                        "in every clone, every fork and every backup of the repository."
                    ),
                    {"name": name, "value_length": len(value)},
                )
                return

    # -- rules -------------------------------------------------------------
    def _check_shell(self, node: ast.Call) -> None:
        func = node.func
        target = ""
        if isinstance(func, ast.Attribute):
            owner = func.value
            owner_name = owner.id if isinstance(owner, ast.Name) else ""
            if owner_name == "subprocess" and func.attr in SHELL_RUNNERS:
                target = f"subprocess.{func.attr}"
            elif owner_name == "os" and func.attr in OS_EXEC:
                self._emit(
                    "kavachx.python.shell-injection",
                    node,
                    f"os.{func.attr} executes a command string through the shell.",
                    {"sink": f"os.{func.attr}", "shell": True},
                )
                return
        if not target:
            return

        shell_true = any(
            kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
            for kw in node.keywords
        )
        if not shell_true:
            return

        # Is the command a literal, or is it built from something?
        first = node.args[0] if node.args else None
        dynamic = first is not None and not (
            isinstance(first, ast.Constant) and isinstance(first.value, str)
        )
        # Does the command value trace back to a parameter of this function?
        tainted = False
        if dynamic and first is not None:
            names = {n.id for n in ast.walk(first) if isinstance(n, ast.Name)}
            tainted = bool(names & self._params()) or bool(names & self._locals_from_params())

        if dynamic:
            self._emit(
                "kavachx.python.shell-injection",
                node,
                (
                    f"{target} is called with shell=True and a command that is constructed at "
                    "runtime"
                    + (
                        ", reachable from this function's parameters."
                        if tainted
                        else ", not a string literal."
                    )
                ),
                {
                    "sink": target,
                    "shell": True,
                    "dynamic_command": True,
                    "parameter_influenced": tainted,
                },
            )
        else:
            self._emit(
                "kavachx.python.subprocess-shell-true",
                node,
                f"{target} is called with shell=True.",
                {"sink": target, "shell": True, "dynamic_command": False},
            )

    def _locals_from_params(self) -> set[str]:
        """Locals assigned (directly or transitively) from a parameter — taint-lite."""
        if not self.function_stack:
            return set()
        tainted = set(self._params())
        function = self.function_stack[-1]
        for _ in range(4):  # fixed-point in a few passes; bodies here are small
            grew = False
            for node in ast.walk(function):
                if isinstance(node, (ast.Assign, ast.AnnAssign)):
                    value = node.value
                    if value is None:
                        continue
                    sources = {n.id for n in ast.walk(value) if isinstance(n, ast.Name)}
                    if not (sources & tainted):
                        continue
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        for name in ast.walk(target):
                            if isinstance(name, ast.Name) and name.id not in tainted:
                                tainted.add(name.id)
                                grew = True
            if not grew:
                break
        return tainted

    def _check_dynamic_eval(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
            self._emit(
                "kavachx.python.eval-exec",
                node,
                f"{node.func.id}() evaluates code at runtime.",
                {"sink": node.func.id},
            )

    def _check_unbounded_index_write(self, node: ast.FunctionDef) -> None:
        """Indexed write whose index variable is never compared against a bound.

        Looks for ``container[idx] = ...`` where ``idx`` is incremented in the same function
        and no ``Compare`` node in the function tests ``idx`` at all. That is the shape of an
        off-by-any write.
        """
        compared: set[str] = set()
        for compare in ast.walk(node):
            if isinstance(compare, ast.Compare):
                for name in ast.walk(compare):
                    if isinstance(name, ast.Name):
                        compared.add(name.id)

        incremented: set[str] = set()
        for aug in ast.walk(node):
            if isinstance(aug, ast.AugAssign) and isinstance(aug.target, ast.Name):
                incremented.add(aug.target.id)

        for assign in ast.walk(node):
            if not isinstance(assign, ast.Assign):
                continue
            for target in assign.targets:
                if not isinstance(target, ast.Subscript):
                    continue
                index = target.slice
                if not isinstance(index, ast.Name):
                    continue
                if index.id in compared:
                    continue
                if index.id not in incremented:
                    continue
                container = target.value.id if isinstance(target.value, ast.Name) else "<expr>"
                self._emit(
                    "kavachx.python.unbounded-index-write",
                    target,
                    (
                        f"{container}[{index.id}] is written with an index that is incremented "
                        f"in {node.name} but never compared against a bound."
                    ),
                    {
                        "container": container,
                        "index_variable": index.id,
                        "bound_checked": False,
                    },
                )

    def _check_path_containment(self, node: ast.FunctionDef) -> None:
        """``ROOT / user_value`` with no resolve/containment check in the function."""
        params = {a.arg for a in [*node.args.posonlyargs, *node.args.args]} - {"self", "cls"}
        if not params:
            return

        has_containment = False
        for call in ast.walk(node):
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute):
                if call.func.attr in ("resolve", "relative_to", "samefile", "commonpath"):
                    has_containment = True
            if isinstance(call, ast.Compare) and any(
                isinstance(op, (ast.In, ast.NotIn)) for op in call.ops
            ):
                # ``root in candidate.parents`` is the canonical containment test.
                rendered = ast.dump(call)
                if "parents" in rendered or "parts" in rendered:
                    has_containment = True
        if has_containment:
            return

        for binop in ast.walk(node):
            if not isinstance(binop, ast.BinOp) or not isinstance(binop.op, ast.Div):
                continue
            right_names = {n.id for n in ast.walk(binop.right) if isinstance(n, ast.Name)}
            if not (right_names & params):
                continue
            left_name = binop.left.id if isinstance(binop.left, ast.Name) else ""
            if left_name and not any(
                token in left_name.upper() for token in ("ROOT", "DIR", "PATH", "BASE")
            ):
                continue
            self._emit(
                "kavachx.python.path-traversal",
                binop,
                (
                    f"{left_name or 'a base path'} is joined with the caller-supplied value "
                    f"and {node.name} performs no containment check on the result."
                ),
                {"base": left_name, "containment_checked": False},
            )

    def _check_config_dict(self, node: ast.Dict) -> None:
        for key, value in zip(node.keys, node.values, strict=False):
            if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                continue
            name = key.value.lower()
            if name == "debug" and isinstance(value, ast.Constant) and value.value is True:
                self._emit(
                    "kavachx.python.debug-enabled",
                    value,
                    "Debug mode is enabled in a configuration default.",
                    {"config_key": key.value},
                )
            if (
                ("host" in name or "bind" in name)
                and isinstance(value, ast.Constant)
                and value.value in ("0.0.0.0", "::", "*")
            ):
                self._emit(
                    "kavachx.python.bind-all-interfaces",
                    value,
                    f"{key.value} binds every network interface.",
                    {"config_key": key.value, "value": value.value},
                )

    def _check_bind_all(self, node: ast.Assign) -> None:
        if not isinstance(node.value, ast.Constant) or node.value.value not in (
            "0.0.0.0",
            "::",
        ):
            return
        for target in node.targets:
            if isinstance(target, ast.Name) and any(
                token in target.id.lower() for token in ("host", "bind", "addr")
            ):
                self._emit(
                    "kavachx.python.bind-all-interfaces",
                    node,
                    f"{target.id} binds every network interface.",
                    {"config_key": target.id, "value": node.value.value},
                )


# ---------------------------------------------------------------------------
class _CRuleVisitor:
    """Line-oriented C checks for the ASan target. Intentionally minimal."""

    def __init__(self, path: str, source: str) -> None:
        self.path = path
        self.source = source
        self.findings: list[RawFinding] = []

    def run(self) -> list[RawFinding]:
        lines = self.source.splitlines()
        for number, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith(("//", "*", "/*")):
                continue
            for call in ("memcpy", "strcpy", "strcat", "sprintf", "gets"):
                if f"{call}(" not in stripped:
                    continue
                window = "\n".join(lines[max(0, number - 12) : number + 4])
                clamped = any(
                    token in window
                    for token in ("MIN(", "min(", "sizeof", "<=", ">=", "clamp", "CAP")
                )
                if call in ("strcpy", "strcat", "sprintf", "gets") or not clamped:
                    self.findings.append(
                        RawFinding(
                            rule_id="kavachx.c.unbounded-memcpy",
                            location=f"{self.path}:{number}",
                            message=(
                                f"{call} at this line has no visible clamp on the copied "
                                "length within the enclosing block."
                            ),
                            file=self.path,
                            line=number,
                            snippet=stripped[:300],
                            metadata={"call": call, "clamp_visible": clamped},
                        )
                    )
                break
        return self.findings


# ---------------------------------------------------------------------------
def scan_python_file(path: Path, *, root: Path) -> list[RawFinding]:
    rel = path.relative_to(root).as_posix()
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=rel)
    except (OSError, SyntaxError) as exc:
        logger.warning("scanner.parse_failed", path=rel, error=str(exc)[:200])
        return []
    visitor = _PythonRuleVisitor(rel, source)
    visitor.visit(tree)
    return visitor.findings


def scan_c_file(path: Path, *, root: Path) -> list[RawFinding]:
    rel = path.relative_to(root).as_posix()
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return _CRuleVisitor(rel, source).run()


def scan_builtin(root: Path, *, skip_tests: bool = True) -> list[RawFinding]:
    from app.sandbox.workspace import list_source_files

    findings: list[RawFinding] = []
    for path in list_source_files(root):
        rel = path.relative_to(root).as_posix()
        if skip_tests and ("/tests/" in f"/{rel}" or rel.startswith("tests/")):
            continue
        suffix = path.suffix.lower()
        if suffix in (".py", ".pyi"):
            findings.extend(scan_python_file(path, root=root))
        elif suffix in (".c", ".h"):
            findings.extend(scan_c_file(path, root=root))
    findings.sort(key=lambda f: (f.file, f.line, f.rule_id))
    return findings


# ---------------------------------------------------------------------------
def semgrep_available() -> bool:
    return shutil.which("semgrep") is not None


async def scan_semgrep(root: Path, *, timeout: int = 180) -> list[RawFinding]:
    binary = shutil.which("semgrep")
    if binary is None:
        return []

    with tempfile.TemporaryDirectory() as tmp:
        rules_path = Path(tmp) / "kavachx-rules.json"
        rules_path.write_text(json.dumps(SEMGREP_RULES), encoding="utf-8")
        argv = [
            binary,
            "--config",
            str(rules_path),
            "--json",
            "--quiet",
            "--no-git-ignore",
            "--metrics=off",
            "--disable-version-check",
            str(root),
        ]
        try:
            # Threaded spawn so the Semgrep bridge does not depend on the host's event loop
            # supporting subprocesses. See app/sandbox/spawn.py.
            completed = await run_process(
                argv, timeout=timeout, on_timeout=lambda process: process.kill()
            )
            stdout_b, stderr_b = completed.stdout, completed.stderr
        except (TimeoutError, OSError) as exc:
            logger.warning("scanner.semgrep_failed", error=str(exc)[:200])
            return []

    try:
        data = json.loads(stdout_b.decode("utf-8", errors="replace") or "{}")
    except ValueError:
        logger.warning("scanner.semgrep_bad_json", stderr=stderr_b[:200].decode(errors="replace"))
        return []

    out: list[RawFinding] = []
    for result in data.get("results", []):
        try:
            rel = Path(result["path"]).resolve().relative_to(root.resolve()).as_posix()
        except (ValueError, KeyError):
            rel = str(result.get("path", ""))
        line = int((result.get("start") or {}).get("line", 0))
        extra = result.get("extra") or {}
        out.append(
            RawFinding(
                rule_id=str(result.get("check_id", "semgrep.unknown")),
                location=f"{rel}:{line}",
                message=str(extra.get("message", ""))[:600],
                file=rel,
                line=line,
                snippet=str(extra.get("lines", ""))[:300],
                engine="semgrep",
                metadata={"semgrep_severity": extra.get("severity", "")},
            )
        )
    return out


async def scan(root: Path) -> tuple[list[RawFinding], dict[str, Any]]:
    """Run every available engine and merge, de-duplicating by (rule, file, line)."""
    builtin = scan_builtin(root)
    semgrep: list[RawFinding] = []
    if semgrep_available():
        semgrep = await scan_semgrep(root)

    merged: dict[tuple[str, str, int], RawFinding] = {}
    for finding in [*builtin, *semgrep]:
        key = (finding.rule_id.split(".")[-1], finding.file, finding.line)
        # Prefer the Semgrep record when both engines agree — it carries upstream metadata.
        if key not in merged or finding.engine == "semgrep":
            merged[key] = finding

    meta = {
        "engines": ["builtin-ast"] + (["semgrep"] if semgrep else []),
        "semgrep_available": semgrep_available(),
        "builtin_count": len(builtin),
        "semgrep_count": len(semgrep),
        "merged_count": len(merged),
    }
    return sorted(merged.values(), key=lambda f: (f.file, f.line, f.rule_id)), meta
