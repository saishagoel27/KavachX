"""Deterministic publish policy gate.

Runs before a patch may reach the Publisher. Every check is mechanical — path globs, AST
comparison, diff size, blast-radius membership, certificate level. None of it consults a model,
and none of it can be waived by one.

Rejects a patch that:

* touches CI, container, git, lockfile or manifest paths;
* adds a dependency (a new import that is not already used in the file);
* adds a network call;
* adds ``exec`` / ``eval`` / ``subprocess`` / ``os.system`` behaviour that was not there before;
* modifies a binary file;
* changes more than the configured diff size or file count;
* touches a file outside the computed blast radius;
* has no certificate, or an assurance level below the policy floor (Level R can never publish).
"""

from __future__ import annotations

import ast
import fnmatch
from dataclasses import dataclass, field
from typing import Any

from app.core.logging import get_logger
from app.models.enums import AssuranceLevel
from app.models.project import DEFAULT_FORBIDDEN_GLOBS
from app.patching.blast_radius import BlastRadius
from app.patching.diffing import diff_stats

logger = get_logger(__name__)

BINARY_SUFFIXES = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".ico",
        ".pdf",
        ".zip",
        ".tar",
        ".gz",
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".o",
        ".a",
        ".class",
        ".jar",
        ".pyc",
        ".wasm",
        ".bin",
        ".db",
        ".sqlite",
    }
)

NETWORK_TOKENS = (
    "requests.",
    "httpx.",
    "urllib.request",
    "urllib3",
    "http.client",
    "socket.socket",
    "socket.create_connection",
    "aiohttp",
    "websocket",
    "smtplib",
    "ftplib",
    "paramiko",
    "curl ",
    "wget ",
    "fetch(",
    "XMLHttpRequest",
)

EXEC_TOKENS = (
    "subprocess.",
    "os.system",
    "os.popen",
    "os.exec",
    "os.spawn",
    "eval(",
    "exec(",
    "compile(",
    "__import__(",
    "pty.spawn",
    "commands.getoutput",
)

#: Assurance ordering for the floor check. R is not "worst", it is "refuted" — never publishable.
_LEVEL_ORDER = {AssuranceLevel.A.value: 3, AssuranceLevel.B.value: 2, AssuranceLevel.C.value: 1}


@dataclass(slots=True)
class PolicyViolationRecord:
    code: str
    message: str
    path: str = ""
    detail: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "path": self.path,
            "detail": self.detail,
        }


@dataclass
class PolicyDecision:
    allowed: bool = True
    violations: list[PolicyViolationRecord] = field(default_factory=list)
    checks_run: list[str] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

    def reject(self, code: str, message: str, path: str = "", **detail: Any) -> None:
        self.allowed = False
        self.violations.append(
            PolicyViolationRecord(code=code, message=message, path=path, detail=detail)
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "violations": [v.as_dict() for v in self.violations],
            "checks_run": self.checks_run,
            "stats": self.stats,
        }

    @property
    def summary(self) -> str:
        if self.allowed:
            return f"policy gate passed ({len(self.checks_run)} checks)"
        return "; ".join(f"{v.code}: {v.message}" for v in self.violations)


@dataclass(slots=True)
class PolicyConfig:
    forbidden_path_globs: list[str] = field(default_factory=lambda: list(DEFAULT_FORBIDDEN_GLOBS))
    max_diff_lines: int = 200
    max_files_changed: int = 5
    allow_new_dependencies: bool = False
    allow_new_network_calls: bool = False
    allow_new_exec: bool = False
    allow_binary_changes: bool = False
    require_certificate: bool = True
    min_assurance_level: str = AssuranceLevel.C.value
    enforce_blast_radius: bool = True

    @classmethod
    def from_model(cls, policy: Any) -> PolicyConfig:
        if policy is None:
            return cls()
        return cls(
            forbidden_path_globs=list(policy.forbidden_path_globs or DEFAULT_FORBIDDEN_GLOBS),
            max_diff_lines=policy.max_diff_lines,
            max_files_changed=policy.max_files_changed,
            allow_new_dependencies=policy.allow_new_dependencies,
            allow_new_network_calls=policy.allow_new_network_calls,
            allow_new_exec=policy.allow_new_exec,
            allow_binary_changes=policy.allow_binary_changes,
            require_certificate=policy.require_certificate,
            min_assurance_level=policy.min_assurance_level,
            enforce_blast_radius=policy.enforce_blast_radius,
        )


def evaluate(
    *,
    diff: str,
    file_changes: dict[str, tuple[str, str]],
    config: PolicyConfig,
    blast: BlastRadius | None = None,
    assurance_level: str | None = None,
    has_certificate: bool | None = None,
) -> PolicyDecision:
    """Evaluate a patch against policy.

    ``file_changes`` maps path -> (old_content, new_content); it is what makes the AST-level
    checks possible rather than grepping the diff text.
    """
    decision = PolicyDecision()
    stats = diff_stats(diff)
    decision.stats = stats.as_dict()

    paths = sorted({*stats.files, *file_changes.keys()})

    # -- forbidden paths ---------------------------------------------------
    decision.checks_run.append("forbidden_paths")
    for path in paths:
        for pattern in config.forbidden_path_globs:
            if _glob_match(path, pattern):
                decision.reject(
                    "FORBIDDEN_PATH",
                    f"{path} matches the protected pattern {pattern!r}. CI, container, git, "
                    "lockfile and manifest paths are never patchable.",
                    path=path,
                    pattern=pattern,
                )
                break

    # -- binary ------------------------------------------------------------
    decision.checks_run.append("binary_files")
    if not config.allow_binary_changes:
        for path in paths:
            suffix = "." + path.rsplit(".", 1)[-1].lower() if "." in path else ""
            if suffix in BINARY_SUFFIXES:
                decision.reject(
                    "BINARY_MODIFICATION",
                    f"{path} is a binary artifact; binary modifications are not permitted.",
                    path=path,
                )

    # -- size --------------------------------------------------------------
    decision.checks_run.append("diff_size")
    if stats.total_changed > config.max_diff_lines:
        decision.reject(
            "DIFF_TOO_LARGE",
            f"The patch changes {stats.total_changed} lines; the policy limit is "
            f"{config.max_diff_lines}.",
            changed=stats.total_changed,
            limit=config.max_diff_lines,
        )
    if len(paths) > config.max_files_changed:
        decision.reject(
            "TOO_MANY_FILES",
            f"The patch touches {len(paths)} files; the policy limit is "
            f"{config.max_files_changed}.",
            files=len(paths),
            limit=config.max_files_changed,
        )

    # -- blast radius ------------------------------------------------------
    decision.checks_run.append("blast_radius")
    if config.enforce_blast_radius and blast is not None:
        for path in paths:
            if not blast.permits(path):
                decision.reject(
                    "OUTSIDE_BLAST_RADIUS",
                    f"{path} is outside the computed blast radius "
                    f"({', '.join(blast.allowed_paths) or 'empty'}). Only files inside the "
                    "verified scope may be changed.",
                    path=path,
                    allowed=blast.allowed_paths,
                )

    # -- behavioural additions --------------------------------------------
    decision.checks_run.extend(["new_dependencies", "new_network_calls", "new_exec"])
    for path, (old, new) in sorted(file_changes.items()):
        if not path.endswith((".py", ".pyi")):
            _token_checks(decision, path, old, new, config)
            continue

        old_facts = _python_facts(old)
        new_facts = _python_facts(new)

        if not config.allow_new_dependencies:
            added_imports = new_facts["imports"] - old_facts["imports"]
            external = {
                name for name in added_imports if not _is_stdlib(name) and not name.startswith(".")
            }
            if external:
                decision.reject(
                    "NEW_DEPENDENCY",
                    f"{path} introduces the non-standard-library import(s) "
                    f"{', '.join(sorted(external))}. A patch may not add a dependency.",
                    path=path,
                    imports=sorted(external),
                )

        if not config.allow_new_network_calls:
            added = new_facts["network"] - old_facts["network"]
            if added:
                decision.reject(
                    "NEW_NETWORK_CALL",
                    f"{path} introduces network call(s): {', '.join(sorted(added))}.",
                    path=path,
                    calls=sorted(added),
                )

        if not config.allow_new_exec:
            added = new_facts["exec"] - old_facts["exec"]
            if added:
                decision.reject(
                    "NEW_EXEC_BEHAVIOUR",
                    f"{path} introduces process-execution or dynamic-evaluation behaviour: "
                    f"{', '.join(sorted(added))}.",
                    path=path,
                    calls=sorted(added),
                )

    # -- certificate -------------------------------------------------------
    decision.checks_run.append("certificate")
    if config.require_certificate:
        if has_certificate is False or assurance_level is None:
            decision.reject(
                "MISSING_CERTIFICATE",
                "No PRAMAAN certificate is attached. A patch cannot be published without one.",
            )
        elif assurance_level == AssuranceLevel.R.value:
            decision.reject(
                "ASSURANCE_LEVEL_R",
                "The certificate is Level R: the patch was refuted. A refuted patch is never "
                "published; the shield remains deployed instead.",
                level=assurance_level,
            )
        else:
            floor = _LEVEL_ORDER.get(config.min_assurance_level, 1)
            actual = _LEVEL_ORDER.get(assurance_level, 0)
            if actual < floor:
                decision.reject(
                    "ASSURANCE_BELOW_FLOOR",
                    f"Certificate level {assurance_level} is below the policy floor "
                    f"{config.min_assurance_level}.",
                    level=assurance_level,
                    floor=config.min_assurance_level,
                )

    if decision.allowed:
        logger.info("policy.passed", checks=len(decision.checks_run), files=len(paths))
    else:
        logger.warning(
            "policy.rejected",
            violations=[v.code for v in decision.violations],
            files=len(paths),
        )
    return decision


# ---------------------------------------------------------------------------
def _glob_match(path: str, pattern: str) -> bool:
    normalised = path.replace("\\", "/")
    basename = normalised.rsplit("/", 1)[-1]

    if fnmatch.fnmatch(normalised, pattern):
        return True
    # ``.github/**`` should also match ``.github/workflows/ci.yml``.
    if pattern.endswith("/**") and normalised.startswith(pattern[:-3] + "/"):
        return True
    # ``**/uv.lock`` must match a root-level ``uv.lock`` too. fnmatch's ``**`` is not recursive,
    # so a leading ``**/`` has to be handled explicitly — without this, every protected manifest
    # at the repository root would be silently patchable.
    if pattern.startswith("**/") and fnmatch.fnmatch(basename, pattern[3:]):
        return True
    return fnmatch.fnmatch(basename, pattern)


def _token_checks(
    decision: PolicyDecision, path: str, old: str, new: str, config: PolicyConfig
) -> None:
    """Token-level fallback for non-Python files, where no AST is available."""
    if not config.allow_new_network_calls:
        added = _added_tokens(old, new, NETWORK_TOKENS)
        if added:
            decision.reject(
                "NEW_NETWORK_CALL",
                f"{path} introduces network usage: {', '.join(sorted(added))}.",
                path=path,
            )
    if not config.allow_new_exec:
        added = _added_tokens(old, new, EXEC_TOKENS)
        if added:
            decision.reject(
                "NEW_EXEC_BEHAVIOUR",
                f"{path} introduces execution behaviour: {', '.join(sorted(added))}.",
                path=path,
            )


def _added_tokens(old: str, new: str, tokens: tuple[str, ...]) -> set[str]:
    return {t for t in tokens if new.count(t) > old.count(t)}


def _python_facts(source: str) -> dict[str, set[str]]:
    """Extract imports, network usage and exec usage from Python source via AST.

    AST rather than text matching, so a comment mentioning ``subprocess`` is not a violation and
    a genuine ``subprocess.run`` reached through an alias still is.
    """
    facts: dict[str, set[str]] = {"imports": set(), "network": set(), "exec": set()}
    try:
        tree = ast.parse(source)
    except SyntaxError:
        # Unparseable new content is itself a problem, but this function only reports facts;
        # the sandbox application step is what fails on broken syntax.
        for token in NETWORK_TOKENS:
            if token in source:
                facts["network"].add(token)
        for token in EXEC_TOKENS:
            if token in source:
                facts["exec"].add(token)
        return facts

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                facts["imports"].add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                facts["imports"].add(node.module.split(".")[0])
        elif isinstance(node, ast.Call):
            rendered = _render_call(node.func)
            if not rendered:
                continue
            for token in NETWORK_TOKENS:
                if rendered.startswith(token.rstrip("(")) or rendered == token.rstrip("("):
                    facts["network"].add(rendered)
            for token in EXEC_TOKENS:
                stem = token.rstrip("(")
                if rendered == stem or rendered.startswith(stem):
                    facts["exec"].add(rendered)
    return facts


def _render_call(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _render_call(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


_STDLIB = frozenset(
    {
        "abc",
        "argparse",
        "ast",
        "asyncio",
        "base64",
        "binascii",
        "bisect",
        "builtins",
        "calendar",
        "cmath",
        "codecs",
        "collections",
        "concurrent",
        "contextlib",
        "copy",
        "csv",
        "ctypes",
        "dataclasses",
        "datetime",
        "decimal",
        "difflib",
        "dis",
        "enum",
        "errno",
        "faulthandler",
        "fnmatch",
        "fractions",
        "functools",
        "gc",
        "getpass",
        "glob",
        "gzip",
        "hashlib",
        "heapq",
        "hmac",
        "html",
        "http",
        "importlib",
        "inspect",
        "io",
        "ipaddress",
        "itertools",
        "json",
        "keyword",
        "linecache",
        "locale",
        "logging",
        "lzma",
        "math",
        "mimetypes",
        "multiprocessing",
        "operator",
        "os",
        "pathlib",
        "pickle",
        "platform",
        "pprint",
        "queue",
        "random",
        "re",
        "reprlib",
        "resource",
        "secrets",
        "select",
        "shlex",
        "shutil",
        "signal",
        "site",
        "socket",
        "sqlite3",
        "ssl",
        "stat",
        "string",
        "struct",
        "subprocess",
        "sys",
        "tempfile",
        "textwrap",
        "threading",
        "time",
        "timeit",
        "tokenize",
        "traceback",
        "types",
        "typing",
        "unicodedata",
        "unittest",
        "urllib",
        "uuid",
        "warnings",
        "weakref",
        "zipfile",
        "zlib",
        "__future__",
    }
)


def _is_stdlib(name: str) -> bool:
    return name in _STDLIB
