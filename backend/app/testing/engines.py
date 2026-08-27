"""Test and fuzz engine selection — real engines, honestly reported when absent.

The spec is explicit: do not ask the model to reinvent a fuzzing engine, use mature frameworks
appropriate to the target. So this module knows about Hypothesis, Atheris, libFuzzer, AFL++, ASan
and UBSan, ``go test -fuzz``, fast-check, JUnit and cargo — and it *probes* for each rather than
assuming.

The probing is the important part. A tool that says "fuzzing: complete" when no fuzzer was
installed is worse than one that says nothing, because the first is a claim and the second is a
gap. Every engine here reports one of three states:

* ``available`` — the toolchain is present and the harness generator exists.
* ``unavailable`` — the generator exists but the toolchain is missing, with the missing pieces
  named. The strategy is then reported as NOT RUN, never as clean.
* ``unimplemented`` — KavachX has no generator for this (language, strategy) pair yet.

``kx-mutational`` is the fallback and it is a real engine, not a placeholder: it is the
existing seeded mutational fuzzer that already drives the demo, wrapped so it participates in the
same selection and reporting as everything else. It is always available, which is what stops a
missing external toolchain from meaning zero dynamic coverage.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from typing import Any

from app.core.logging import get_logger

logger = get_logger(__name__)


class EngineStatus:
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    UNIMPLEMENTED = "unimplemented"


@dataclass(frozen=True, slots=True)
class Engine:
    """One test/fuzz engine and what it needs."""

    id: str
    label: str
    language: str
    #: Strategies this engine can execute.
    strategies: tuple[str, ...]
    #: Executables that must be on PATH.
    binaries: tuple[str, ...] = ()
    #: Python modules that must be importable *inside the sandbox image*.
    modules: tuple[str, ...] = ()
    #: True when KavachX has a harness generator for this engine.
    implemented: bool = True
    #: Whether the engine produces coverage feedback usable by the guided loop.
    coverage_feedback: bool = False
    notes: str = ""


ENGINES: tuple[Engine, ...] = (
    # -- Python -----------------------------------------------------------
    Engine(
        "python-stdlib",
        "self-running Python harness (pytest-compatible)",
        "python",
        ("unit", "regression", "differential"),
        # Deliberately NO module requirement. The generated unit/regression harness runs itself
        # through a __main__ block using only the standard library, and is *also* a valid pytest
        # module for the maintainer who receives it. Requiring pytest here made the most important
        # strategy unavailable whenever the sandbox image lacked it — and, worse, its absence
        # surfaced as "the oracle did not fire" rather than as a missing engine.
        notes=(
            "Always available. Executes as a plain script; the same file is a valid pytest "
            "module for the target repository's own suite."
        ),
    ),
    Engine(
        "hypothesis",
        "Hypothesis (property-based)",
        "python",
        ("property",),
        modules=("hypothesis",),
        notes="Property tests with shrinking. Counterexamples are minimised automatically.",
    ),
    Engine(
        "atheris",
        "Atheris (libFuzzer for Python)",
        "python",
        ("fuzz",),
        modules=("atheris",),
        coverage_feedback=True,
        notes="Coverage-guided fuzzing of Python with libFuzzer's engine.",
    ),
    Engine(
        "kx-mutational",
        "KavachX seeded mutational fuzzer",
        "python",
        ("fuzz", "mutation"),
        # No external dependency by design: this is the engine that guarantees a target with a
        # driveable entrypoint always gets *some* dynamic coverage.
        coverage_feedback=True,
        notes=(
            "Always available. Seeded, coverage-aware mutational fuzzing through the in-process "
            "observation harness."
        ),
    ),
    # -- C / C++ ----------------------------------------------------------
    Engine(
        "libfuzzer",
        "libFuzzer (clang)",
        "c",
        ("fuzz",),
        binaries=("clang",),
        coverage_feedback=True,
        notes="In-process coverage-guided fuzzing. Needs clang with -fsanitize=fuzzer.",
    ),
    Engine(
        "afl++",
        "AFL++",
        "c",
        ("fuzz",),
        binaries=("afl-fuzz", "afl-clang-fast"),
        coverage_feedback=True,
        notes="Out-of-process coverage-guided fuzzing.",
    ),
    Engine(
        "asan",
        "AddressSanitizer",
        "c",
        ("unit", "regression", "fuzz"),
        binaries=("clang",),
        notes="Memory-error detection. Provides the sanitizer_report oracle its signal.",
    ),
    Engine(
        "ubsan",
        "UndefinedBehaviorSanitizer",
        "c",
        ("unit", "regression", "fuzz"),
        binaries=("clang",),
        notes="Undefined-behaviour detection.",
    ),
    # -- Go ---------------------------------------------------------------
    Engine(
        "go-fuzz",
        "go test -fuzz",
        "go",
        ("fuzz", "unit", "regression"),
        binaries=("go",),
        implemented=False,
        coverage_feedback=True,
        notes=(
            "Native Go fuzzing. A draft harness generator exists but needs a package-level "
            "output-capture helper KavachX does not inject, so selecting it would produce a "
            "guaranteed compile failure. Reported as unimplemented rather than run-and-fail."
        ),
    ),
    # -- JavaScript / TypeScript ------------------------------------------
    Engine(
        "fast-check",
        "fast-check (property-based)",
        "javascript",
        ("property", "fuzz"),
        binaries=("node",),
        modules=("fast-check",),
        notes="Property-based testing with shrinking for JS/TS.",
    ),
    Engine(
        "vitest",
        "Vitest",
        "javascript",
        ("unit", "regression", "differential"),
        binaries=("node",),
        notes="Runs generated unit and regression tests for JS/TS.",
    ),
    # -- Others: registered so they are reported, not silently missing ----
    Engine(
        "junit",
        "JUnit",
        "java",
        ("unit", "regression"),
        binaries=("mvn",),
        implemented=False,
        notes="Registered for reporting; KavachX has no JUnit harness generator yet.",
    ),
    Engine(
        "cargo-fuzz",
        "cargo fuzz",
        "rust",
        ("fuzz",),
        binaries=("cargo",),
        implemented=False,
        coverage_feedback=True,
        notes="Registered for reporting; KavachX has no cargo-fuzz harness generator yet.",
    ),
)


@dataclass
class EngineReport:
    """The availability verdict for one engine."""

    engine: Engine
    status: str
    missing_binaries: list[str] = field(default_factory=list)
    missing_modules: list[str] = field(default_factory=list)
    reason: str = ""

    @property
    def available(self) -> bool:
        return self.status == EngineStatus.AVAILABLE

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.engine.id,
            "label": self.engine.label,
            "language": self.engine.language,
            "strategies": list(self.engine.strategies),
            "status": self.status,
            "coverage_feedback": self.engine.coverage_feedback,
            "missing_binaries": self.missing_binaries,
            "missing_modules": self.missing_modules,
            "reason": self.reason,
            "notes": self.engine.notes,
        }


def probe(engine: Engine, *, module_checker: Any = None) -> EngineReport:
    """Is this engine usable here?

    ``module_checker`` lets the caller test importability *inside the sandbox image* rather than
    in the backend process. That distinction is load-bearing: the backend having ``hypothesis``
    installed says nothing about whether the sandbox that will run the harness does, and probing
    the wrong process is how a generated harness fails at execution with a bare ImportError.
    """
    report = EngineReport(engine=engine, status=EngineStatus.AVAILABLE)

    if not engine.implemented:
        report.status = EngineStatus.UNIMPLEMENTED
        report.reason = engine.notes or "No harness generator exists for this engine."
        return report

    report.missing_binaries = [b for b in engine.binaries if not shutil.which(b)]
    if engine.modules:
        checker = module_checker or _local_module_available
        report.missing_modules = [m for m in engine.modules if not checker(m)]

    if report.missing_binaries or report.missing_modules:
        report.status = EngineStatus.UNAVAILABLE
        parts: list[str] = []
        if report.missing_binaries:
            parts.append("missing executable(s): " + ", ".join(report.missing_binaries))
        if report.missing_modules:
            parts.append("missing module(s): " + ", ".join(report.missing_modules))
        report.reason = (
            f"{engine.label} cannot run here — {'; '.join(parts)}. Tests requiring it are "
            "reported as NOT RUN rather than as clean."
        )
    return report


def _local_module_available(module: str) -> bool:
    """Importability in *this* process.

    A deliberately pessimistic fallback, used only when no sandbox probe is supplied. It is the
    *wrong* process to ask — the backend having ``pytest`` installed says nothing about the sandbox
    image — so callers that care should pass ``module_checker``. See
    :func:`sandbox_module_checker`.
    """
    import importlib.util

    try:
        # A hyphenated npm-style name is not a Python module; treat it as absent here and let a
        # sandbox-side probe decide.
        if "-" in module:
            return False
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError, ModuleNotFoundError):
        return False


def sandbox_module_checker(sandbox: Any) -> Any:
    """Build a module checker that probes **inside the sandbox**, with results cached.

    This is the checker that matters. The harness runs in the sandbox interpreter, so that is the
    interpreter whose package list decides whether a strategy can execute. Asking the backend
    process instead produced a measured failure on this host: ``pytest`` was importable in the
    backend, the engine was reported available, and the generated harness then died in the sandbox
    with ``No module named pytest`` — reported downstream as "the oracle did not fire", which is
    indistinguishable from a clean result.

    One sandbox execution per distinct module, cached for the run. The probe is a bare
    ``importlib.util.find_spec`` in a subprocess: it imports nothing, so a module with import side
    effects cannot do anything during availability checking.
    """
    import asyncio

    cache: dict[str, bool] = {}

    def check(module: str) -> bool:
        if module in cache:
            return cache[module]
        if "-" in module:
            # An npm package. A Python-side probe cannot answer; report absent so the engine is
            # marked unavailable with its missing-module list rather than assumed present.
            cache[module] = False
            return False

        from app.sandbox.base import ExecRequest

        program = (
            "import importlib.util,sys;"
            f"sys.stdout.write('1' if importlib.util.find_spec({module!r}) else '0')"
        )
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        try:
            coroutine = sandbox.execute(
                ExecRequest(
                    argv=["python", "-c", program],
                    label=f"probe:module:{module}",
                    timeout_seconds=30,
                )
            )
            result = (
                asyncio.run_coroutine_threadsafe(coroutine, loop).result(60)
                if loop is not None and loop.is_running()
                else asyncio.run(coroutine)
            )
            available = result.stdout.strip().endswith("1")
        except Exception as exc:  # pragma: no cover - environment dependent
            logger.warning(
                "testing.module_probe_failed", module=module, error=str(exc)[:200]
            )
            available = False
        cache[module] = available
        return available

    return check


async def async_module_checker(sandbox: Any) -> Any:
    """Pre-probe every module any engine needs, then return a synchronous checker.

    Used from async callers (the orchestrator), where scheduling a coroutine from inside a
    synchronous checker is awkward and error-prone. Probing up front costs one short sandbox
    execution per distinct module and makes the rest of selection pure.
    """
    from app.sandbox.base import ExecRequest

    modules = sorted({m for e in ENGINES for m in e.modules if "-" not in m})
    cache: dict[str, bool] = {}
    for module in modules:
        program = (
            "import importlib.util,sys;"
            f"sys.stdout.write('1' if importlib.util.find_spec({module!r}) else '0')"
        )
        try:
            result = await sandbox.execute(
                ExecRequest(
                    argv=["python", "-c", program],
                    label=f"probe:module:{module}",
                    timeout_seconds=30,
                )
            )
            cache[module] = result.stdout.strip().endswith("1")
        except Exception as exc:  # pragma: no cover - environment dependent
            logger.warning("testing.module_probe_failed", module=module, error=str(exc)[:200])
            cache[module] = False
    logger.info("testing.module_probe", **dict(cache))

    def check(module: str) -> bool:
        return cache.get(module, False)

    return check


@dataclass
class EngineSelection:
    """What will actually run, and what will not."""

    chosen: EngineReport | None = None
    considered: list[EngineReport] = field(default_factory=list)
    #: Set when nothing can execute this strategy for this language.
    unavailable_reason: str = ""

    @property
    def ok(self) -> bool:
        return self.chosen is not None and self.chosen.available

    def as_dict(self) -> dict[str, Any]:
        return {
            "chosen": self.chosen.as_dict() if self.chosen else None,
            "considered": [r.as_dict() for r in self.considered],
            "unavailable_reason": self.unavailable_reason,
        }


def select(
    *, language: str, strategy: str, module_checker: Any = None
) -> EngineSelection:
    """Pick the best available engine for one (language, strategy) pair.

    Preference order is coverage-feedback engines first, then anything available, then the
    always-available builtin. Coverage feedback first because a coverage-guided run finds inputs a
    blind one does not, and the whole point of the guided loop is to have that signal.
    """
    selection = EngineSelection()
    candidates = [
        e for e in ENGINES if e.language == language and strategy in e.strategies
    ]
    if not candidates:
        selection.unavailable_reason = (
            f"KavachX has no {strategy!r} engine registered for {language or 'this language'}, so "
            f"the {strategy} strategy did NOT run for this target."
        )
        return selection

    reports = [probe(e, module_checker=module_checker) for e in candidates]
    selection.considered = reports
    available = [r for r in reports if r.available]

    if not available:
        selection.unavailable_reason = (
            f"No {strategy!r} engine is usable for {language}: "
            + "; ".join(r.reason for r in reports if r.reason)
        )
        return selection

    available.sort(
        key=lambda r: (
            not r.engine.coverage_feedback,
            # The builtin is the fallback, so it sorts last among equals.
            r.engine.id == "kx-mutational",
            r.engine.id,
        )
    )
    selection.chosen = available[0]
    return selection


def describe_available(*, module_checker: Any = None) -> dict[str, Any]:
    """Full engine inventory. Backs ``/api/system/engines`` and the certificate."""
    reports = [probe(e, module_checker=module_checker) for e in ENGINES]
    by_language: dict[str, list[dict[str, Any]]] = {}
    for report in reports:
        by_language.setdefault(report.engine.language, []).append(report.as_dict())
    return {
        "engines": [r.as_dict() for r in reports],
        "by_language": by_language,
        "counts": {
            "available": len([r for r in reports if r.status == EngineStatus.AVAILABLE]),
            "unavailable": len([r for r in reports if r.status == EngineStatus.UNAVAILABLE]),
            "unimplemented": len([r for r in reports if r.status == EngineStatus.UNIMPLEMENTED]),
        },
        "note": (
            "An unavailable engine means the corresponding strategy did NOT run. It is never "
            "reported as a clean result."
        ),
    }
