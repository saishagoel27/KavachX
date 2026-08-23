"""Probe: identify what the target *is* before touching it.

Produces a :class:`TargetDescriptor` — how to build it, how to invoke it, where its source root
and benign corpus live. The LLM proposes interface hypotheses here; every field that the rest of
the pipeline actually depends on is then confirmed against the filesystem, because a wrong
entrypoint would silently invalidate every observation downstream.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.analysis.framework import detect_run_plan
from app.analysis.world_model import WorldModel
from app.core.logging import get_logger

logger = get_logger(__name__)

SOURCE_ROOT_CANDIDATES = ("src", "lib", "app", "source", ".")
CORPUS_CANDIDATES = (
    "corpus/benign",
    "corpus",
    "tests/corpus",
    "fixtures/benign",
    "examples/benign",
)
ASSET_CANDIDATES = ("assets", "templates", "static")


@dataclass(slots=True)
class TargetDescriptor:
    language: str = "python"
    source_root: str = "."
    entry_module: str = ""
    entry_callable: str = ""
    entry_file: str = ""
    #: Argument vector template for a single request. ``{payload}`` is substituted.
    cli_argv: list[str] = field(default_factory=list)
    corpus_dir: str = ""
    asset_dir: str = ""
    build_command: list[str] = field(default_factory=list)
    test_command: list[str] = field(default_factory=list)
    interpreter: str = "python"
    confirmed: bool = False
    confirmation_notes: list[str] = field(default_factory=list)
    interface_hypotheses: list[dict[str, Any]] = field(default_factory=list)
    #: Run-plan facts derived from the target's own manifests + README (see analysis.framework).
    project_kind: str = "unknown"
    frameworks: list[str] = field(default_factory=list)
    install_command: list[str] = field(default_factory=list)
    run_command: list[str] = field(default_factory=list)
    readme_commands: list[str] = field(default_factory=list)
    #: Why this target can (or cannot) be executed and observed by KavachX.
    dynamic_reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "language": self.language,
            "source_root": self.source_root,
            "entry_module": self.entry_module,
            "entry_callable": self.entry_callable,
            "entry_file": self.entry_file,
            "cli_argv": self.cli_argv,
            "corpus_dir": self.corpus_dir,
            "asset_dir": self.asset_dir,
            "build_command": self.build_command,
            "test_command": self.test_command,
            "interpreter": self.interpreter,
            "confirmed": self.confirmed,
            "confirmation_notes": self.confirmation_notes,
            "interface_hypotheses": self.interface_hypotheses,
            "project_kind": self.project_kind,
            "frameworks": self.frameworks,
            "install_command": self.install_command,
            "run_command": self.run_command,
            "readme_commands": self.readme_commands,
            "dynamic_reason": self.dynamic_reason,
        }

    def argv_for(self, payload: str) -> list[str]:
        return [arg.replace("{payload}", payload) for arg in self.cli_argv]


def probe_payload(model: WorldModel, *, limit: int = 60) -> dict[str, Any]:
    """Structured, bounded input for the interface-hypothesis model call."""
    return {
        "files": sorted(model.files.keys())[:200],
        "candidate_entrypoints": [
            {
                "path": entry.file,
                "symbol": entry.symbol,
                "kind": entry.kind,
                "signature": entry.signature,
            }
            for entry in model.entrypoints[:limit]
        ],
        "manifests": model.dependencies.get("manifests", []),
        "deployment_units": [unit["file"] for unit in model.deployment_units],
        "languages": model.index_summary.get("by_language", {}),
    }


def confirm_descriptor(
    root: Path,
    model: WorldModel,
    *,
    proposal: dict[str, Any] | None = None,
) -> TargetDescriptor:
    """Build the descriptor from the filesystem, using the proposal only as a hint.

    Order of authority: what is on disk > what the model suggested > defaults.
    """
    proposal = proposal or {}
    descriptor = TargetDescriptor()
    notes: list[str] = []

    languages = model.index_summary.get("by_language", {})
    if languages.get("python"):
        descriptor.language = "python"
    elif languages.get("c"):
        descriptor.language = "c"
    elif languages.get("javascript"):
        descriptor.language = "javascript"

    # -- run plan (framework, kind, build/run/test) from the target's own manifests + README ------
    # This is what lets the Probe understand a Node/Rust/Go/web project instead of assuming a
    # Python main.py. It never *forces* execution: the harness gate below still decides that.
    plan = detect_run_plan(root)
    descriptor.project_kind = plan.kind
    descriptor.frameworks = plan.frameworks
    descriptor.install_command = plan.install_command
    descriptor.run_command = plan.run_command
    descriptor.readme_commands = plan.readme_commands
    descriptor.dynamic_reason = plan.reason
    # Prefer the manifest-derived language when the file index could not classify it (e.g. Rust/Go).
    if descriptor.language == "python" and not languages.get("python") and plan.language != "unknown":
        descriptor.language = plan.language
    for note in plan.evidence:
        notes.append(note)
    notes.append(plan.reason)

    # -- source root -------------------------------------------------------
    for candidate in SOURCE_ROOT_CANDIDATES:
        path = root / candidate if candidate != "." else root
        if not path.is_dir():
            continue
        if any(path.rglob("*.py")) or any(path.rglob("*.c")):
            descriptor.source_root = candidate
            break
    notes.append(f"source root resolved to {descriptor.source_root!r}")

    # -- entrypoint --------------------------------------------------------
    hypotheses = proposal.get("interfaces") or []
    descriptor.interface_hypotheses = [dict(h) for h in hypotheses][:20]

    chosen_file = ""
    chosen_symbol = ""
    for hypothesis in hypotheses:
        raw = str(hypothesis.get("entrypoint", ""))
        if ":" not in raw:
            continue
        path_part, symbol = raw.split(":", 1)
        if (root / path_part).is_file() and hypothesis.get("kind") == "cli":
            chosen_file, chosen_symbol = path_part, symbol.split(".")[-1]
            notes.append(f"model proposed CLI entrypoint {raw}; confirmed on disk")
            break

    if not chosen_file:
        for entry in model.entrypoints:
            if entry.kind == "cli" and (root / entry.file).is_file():
                index = model.files.get(entry.file)
                if index is not None and index.has_main_guard:
                    chosen_file = entry.file
                    chosen_symbol = entry.symbol.split(".")[-1]
                    notes.append(
                        f"selected {chosen_file}:{chosen_symbol} — CLI entrypoint with a "
                        "__main__ guard"
                    )
                    break

    if not chosen_file:
        for entry in model.entrypoints:
            if (root / entry.file).is_file():
                chosen_file = entry.file
                chosen_symbol = entry.symbol.split(".")[-1]
                notes.append(f"fell back to first confirmed entrypoint {chosen_file}")
                break

    if chosen_file:
        descriptor.entry_file = chosen_file
        descriptor.entry_callable = chosen_symbol
        module_path = chosen_file
        prefix = f"{descriptor.source_root}/"
        if descriptor.source_root != "." and module_path.startswith(prefix):
            module_path = module_path[len(prefix) :]
        descriptor.entry_module = module_path.removesuffix(".py").replace("/", ".")
        descriptor.cli_argv = ["python", chosen_file, "--request", "{payload}"]
        descriptor.confirmed = True
    else:
        notes.append("no entrypoint could be confirmed on disk")

    # -- corpus / assets ---------------------------------------------------
    for candidate in CORPUS_CANDIDATES:
        path = root / candidate
        if path.is_dir() and any(path.glob("*.json")):
            descriptor.corpus_dir = candidate
            notes.append(
                f"benign corpus found at {candidate} ({len(list(path.glob('*.json')))} cases)"
            )
            break
    if not descriptor.corpus_dir:
        notes.append(
            "no benign corpus found (looked in corpus/benign, corpus, tests/corpus, "
            "fixtures/benign, examples/benign); SAMHITA and differential replay have nothing "
            "to observe"
        )

    for candidate in ASSET_CANDIDATES:
        if (root / candidate).is_dir():
            descriptor.asset_dir = candidate
            break

    # -- build / test ------------------------------------------------------
    # Prefer commands the project declares about itself; fall back to filesystem heuristics.
    if plan.build_command:
        descriptor.build_command = plan.build_command
    elif (root / "build.sh").is_file():
        descriptor.build_command = ["bash", "build.sh"]
    elif (root / "Makefile").is_file():
        descriptor.build_command = ["make", "build"]
    if plan.test_command:
        descriptor.test_command = plan.test_command
    elif (root / "tests").is_dir():
        descriptor.test_command = ["python", "-m", "pytest", "tests", "-q"]

    descriptor.confirmation_notes = notes
    logger.info(
        "probe.descriptor",
        language=descriptor.language,
        entry=f"{descriptor.entry_file}:{descriptor.entry_callable}",
        corpus=descriptor.corpus_dir,
        confirmed=descriptor.confirmed,
    )
    return descriptor
