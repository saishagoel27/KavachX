"""Framework and run-plan detection.

Answers "what kind of project is this and how is it built, run and tested?" from the target's own
manifests and README — so the Probe no longer assumes every target is a Python ``main.py``.

It is **monorepo-aware**: manifests are discovered with a bounded recursive walk (skipping
``node_modules``/``target``/… and dot-dirs), so a repository that keeps its pieces in
``frontend/``, ``services/api/``, ``contracts/foo/bar/`` and so on is understood as a set of
sub-projects rather than "unknown". Each sub-project is classified independently and the results
are aggregated: a primary classification for description, plus every sub-project listed.

Honesty boundary: detecting *how* to run a project is necessary but not sufficient for dynamic
analysis. KavachX can only observe a target for which it has a tracing harness and a request→output
interface — today that means a **Python or C command-line** target. Everything else is detected and
reported (so the trace can say exactly what it is and how it would run), but marked
``dynamically_analyzable = False`` with a reason, so a run never *pretends* it executed something it
could not.
"""

from __future__ import annotations

import json
import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.logging import get_logger

logger = get_logger(__name__)

README_NAMES = (
    "README.md", "README.rst", "README.txt", "README",
    "INSTALL.md", "SETUP.md", "GETTING_STARTED.md", "CONTRIBUTING.md",
)

MANIFEST_NAMES = (
    "package.json", "pyproject.toml", "setup.py", "requirements.txt",
    "Cargo.toml", "go.mod", "pom.xml", "build.gradle", "composer.json", "Gemfile",
)

#: The languages KavachX has a real tracing harness for. Others are detected but not executed.
DYNAMIC_LANGUAGES = frozenset({"python", "c"})

#: Directories never worth descending into when locating a monorepo's manifests.
_IGNORE_DIRS = frozenset(
    {
        "node_modules", "dist", "build", "target", ".next", ".venv", "venv",
        "__pycache__", ".kavachx", ".turbo", ".cache", "vendor", "site-packages",
        "coverage", ".pytest_cache", ".mypy_cache", ".ruff_cache", "out",
    }
)

#: How security-relevant each kind is, for choosing a monorepo's primary classification.
_KIND_RANK = {"smart_contract": 4, "web_service": 3, "cli": 2, "library": 1, "unknown": 0}

_CMD_PREFIXES = (
    "npm", "pnpm", "yarn", "npx", "node", "deno", "bun",
    "python", "python3", "pip", "pip3", "uv", "poetry", "pytest", "tox",
    "cargo", "rustc", "soroban", "stellar",
    "go", "make", "bash", "sh", "docker", "docker-compose",
    "flask", "uvicorn", "gunicorn", "hypercorn", "django-admin", "manage.py",
    "./", "mvn", "gradle", "dotnet",
)


@dataclass(slots=True)
class RunPlan:
    language: str = "unknown"
    frameworks: list[str] = field(default_factory=list)
    #: cli | web_service | smart_contract | library | unknown
    kind: str = "unknown"
    install_command: list[str] = field(default_factory=list)
    build_command: list[str] = field(default_factory=list)
    run_command: list[str] = field(default_factory=list)
    test_command: list[str] = field(default_factory=list)
    readme_commands: list[str] = field(default_factory=list)
    manifests: list[str] = field(default_factory=list)
    #: One entry per detected sub-project (path + its own classification). Empty for a single project.
    subprojects: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    dynamically_analyzable: bool = False
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "language": self.language,
            "frameworks": self.frameworks,
            "kind": self.kind,
            "install_command": self.install_command,
            "build_command": self.build_command,
            "run_command": self.run_command,
            "test_command": self.test_command,
            "readme_commands": self.readme_commands,
            "manifests": self.manifests,
            "subprojects": self.subprojects,
            "evidence": self.evidence,
            "dynamically_analyzable": self.dynamically_analyzable,
            "reason": self.reason,
        }


def _read(path: Path, *, limit: int = 40_000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return ""


def _load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(_read(path))
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def _load_toml(path: Path) -> dict[str, Any]:
    try:
        return tomllib.loads(_read(path))
    except (tomllib.TOMLDecodeError, OSError):
        return {}


def _readme_commands(root: Path, limit: int = 25) -> list[str]:
    """Pull plausible shell commands out of README/INSTALL/SETUP prose."""
    commands: list[str] = []
    seen: set[str] = set()
    for name in README_NAMES:
        path = root / name
        if not path.is_file():
            continue
        for raw in _read(path).splitlines():
            line = raw.strip().lstrip("$").strip()
            if not line or line.startswith(("#", "//", "<!--", "```")):
                continue
            first = line.split()[0].lower()
            if first.startswith(_CMD_PREFIXES) or first in _CMD_PREFIXES:
                if line not in seen:
                    seen.add(line)
                    commands.append(line[:200])
            if len(commands) >= limit:
                return commands
    return commands


def _scan_manifests(root: Path, *, max_depth: int = 25, max_dirs: int = 60_000) -> list[Path]:
    """Recursive walk collecting every manifest to the bottom of the repo.

    Vendored/build/hidden directories (``node_modules``, ``target``, ``.git``, …) are pruned so the
    walk stays fast even on huge monorepos, but real source directories are followed all the way
    down. ``max_depth``/``max_dirs`` are runaway guards, not a shallow cap — they are large enough
    that any realistic repository is scanned in full, and a hit is logged if ever reached.
    """
    found: list[Path] = []
    root_str = str(root)
    for dirs_seen, (dirpath, dirnames, filenames) in enumerate(os.walk(root)):
        rel = os.path.relpath(dirpath, root_str)
        depth = 0 if rel == "." else rel.count(os.sep) + 1
        # Prune vendored, build and hidden directories in place.
        dirnames[:] = [
            d for d in dirnames if d not in _IGNORE_DIRS and not d.startswith(".")
        ]
        if depth >= max_depth:
            dirnames[:] = []
        if dirs_seen > max_dirs:
            logger.warning("framework.scan_capped", dirs=dirs_seen, note="repo larger than cap")
            break
        for name in MANIFEST_NAMES:
            if name in filenames:
                found.append(Path(dirpath) / name)
    return found


def _has_main_guard(base: Path, *, limit: int = 400) -> bool:
    guard = re.compile(r'if\s+__name__\s*==\s*[\'"]__main__[\'"]')
    for count, path in enumerate(base.rglob("*.py")):
        if count >= limit:
            break
        if guard.search(_read(path, limit=8000)):
            return True
    return False


def _makefile_targets(path: Path) -> set[str]:
    targets: set[str] = set()
    for line in _read(path).splitlines():
        m = re.match(r"^([a-zA-Z][\w-]*)\s*:(?!=)", line)
        if m:
            targets.add(m.group(1))
    return targets


def _classify_dir(base: Path) -> RunPlan:
    """Classify a single project directory whose manifests live directly in ``base``."""
    r = RunPlan()

    # -- Rust / smart contract -------------------------------------------------
    if (base / "Cargo.toml").is_file():
        r.language = "rust"
        cargo = _load_toml(base / "Cargo.toml")
        names = " ".join(
            {**cargo.get("dependencies", {}), **cargo.get("dev-dependencies", {})}
        ).lower()
        if "soroban" in names or "stellar" in names or "contract" in base.name.lower():
            r.kind = "smart_contract"
            r.frameworks = ["soroban" if "soroban" in names else "contract"]
        elif any(w in names for w in ("actix", "axum", "rocket", "warp")):
            r.kind = "web_service"
        elif "bin" in cargo or (base / "src" / "main.rs").is_file():
            r.kind = "cli"
        else:
            r.kind = "library"
        r.build_command = ["cargo", "build", "--release"]
        r.run_command = ["cargo", "run"]
        r.test_command = ["cargo", "test"]

    # -- Solidity (Hardhat/Foundry) -------------------------------------------
    elif next(base.glob("*.sol"), None) is not None or (base / "contracts").is_dir():
        r.language = "solidity"
        r.kind = "smart_contract"
        r.frameworks = ["hardhat" if (base / "hardhat.config.js").is_file() else "solidity"]

    # -- Python (checked before Node in a polyglot repo — it has a harness) ----
    elif (base / "pyproject.toml").is_file() or (base / "setup.py").is_file() or (base / "requirements.txt").is_file():
        r.language = "python"
        deps_blob = ""
        console_scripts = False
        if (base / "pyproject.toml").is_file():
            pp = _load_toml(base / "pyproject.toml")
            project = pp.get("project", {}) if isinstance(pp.get("project"), dict) else {}
            deps_blob = " ".join(project.get("dependencies", []) or [])
            poetry = pp.get("tool", {}).get("poetry", {}) if isinstance(pp.get("tool"), dict) else {}
            deps_blob += " " + " ".join((poetry.get("dependencies", {}) or {}).keys())
            console_scripts = bool(project.get("scripts") or poetry.get("scripts"))
        if (base / "requirements.txt").is_file():
            deps_blob += " " + _read(base / "requirements.txt").lower()
        deps_blob = deps_blob.lower()
        for fw in ("flask", "django", "fastapi", "aiohttp", "starlette", "tornado", "sanic"):
            if fw in deps_blob:
                r.frameworks.append(fw)
        r.install_command = (
            ["uv", "sync"] if (base / "uv.lock").is_file()
            else ["pip", "install", "-r", "requirements.txt"] if (base / "requirements.txt").is_file()
            else ["pip", "install", "-e", "."]
        )
        if r.frameworks:
            r.kind = "web_service"
        elif console_scripts or _has_main_guard(base):
            r.kind = "cli"
        else:
            r.kind = "library"
        if (base / "tests").is_dir() or (base / "test").is_dir():
            r.test_command = ["python", "-m", "pytest", "-q"]

    # -- Node / JS / TS --------------------------------------------------------
    elif (base / "package.json").is_file():
        pkg = _load_json(base / "package.json")
        deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
        scripts = pkg.get("scripts", {}) if isinstance(pkg.get("scripts"), dict) else {}
        r.language = (
            "typescript" if (base / "tsconfig.json").is_file() or "typescript" in deps else "javascript"
        )
        pm = (
            "pnpm" if (base / "pnpm-lock.yaml").is_file()
            else "yarn" if (base / "yarn.lock").is_file()
            else "npm"
        )
        for fw in ("next", "react", "vue", "svelte", "@angular/core", "express", "@nestjs/core", "koa", "fastify", "astro", "vite", "remix"):
            if fw in deps:
                r.frameworks.append(fw.split("/")[0].lstrip("@"))
        web = {"next", "express", "nestjs", "koa", "fastify", "remix"} & set(r.frameworks)
        if web or "start" in scripts or "dev" in scripts:
            r.kind = "web_service"
        elif "bin" in pkg:
            r.kind = "cli"
        else:
            r.kind = "library"
        r.install_command = [pm, "install"]
        if "build" in scripts:
            r.build_command = [pm, "run", "build"]
        if "start" in scripts:
            r.run_command = [pm, "run", "start"]
        elif "dev" in scripts:
            r.run_command = [pm, "run", "dev"]
        if "test" in scripts:
            r.test_command = [pm, "test"]

    # -- Go --------------------------------------------------------------------
    elif (base / "go.mod").is_file():
        r.language = "go"
        r.kind = "cli" if next(base.rglob("main.go"), None) is not None else "library"
        r.build_command = ["go", "build", "./..."]
        r.run_command = ["go", "run", "."]
        r.test_command = ["go", "test", "./..."]

    # -- Java / Kotlin (Maven or Gradle) --------------------------------------
    elif (
        (base / "pom.xml").is_file()
        or (base / "build.gradle").is_file()
        or (base / "build.gradle.kts").is_file()
    ):
        is_gradle = (base / "build.gradle").is_file() or (base / "build.gradle.kts").is_file()
        r.language = (
            "kotlin"
            if (base / "build.gradle.kts").is_file() or next(base.rglob("*.kt"), None) is not None
            else "java"
        )
        blob = ""
        for manifest in ("pom.xml", "build.gradle", "build.gradle.kts"):
            if (base / manifest).is_file():
                blob += _read(base / manifest).lower()
        if "spring" in blob:
            r.frameworks.append("spring")
            r.kind = "web_service"
        else:
            r.kind = "cli"
        if is_gradle:
            gradle = "./gradlew" if (base / "gradlew").is_file() else "gradle"
            r.install_command = [gradle, "build", "-x", "test"]
            r.test_command = [gradle, "test"]
        else:
            mvn = "./mvnw" if (base / "mvnw").is_file() else "mvn"
            r.install_command = [mvn, "-q", "-DskipTests", "package"]
            r.test_command = [mvn, "test"]
        r.build_command = list(r.install_command)
        r.run_command = ["java", "-jar", "target/*.jar"]

    return r


def detect_run_plan(root: Path) -> RunPlan:
    """Classify the project (monorepo-aware) and derive its build/run/test/install commands."""
    plan = RunPlan()
    ev = plan.evidence
    plan.readme_commands = _readme_commands(root)

    manifest_paths = _scan_manifests(root)
    plan.manifests = sorted(str(p.relative_to(root)) for p in manifest_paths)[:60]
    if (root / "Makefile").is_file() and "Makefile" not in plan.manifests:
        plan.manifests.append("Makefile")

    # One project per directory that holds manifests (a monorepo has several).
    project_dirs = sorted({p.parent for p in manifest_paths}, key=lambda d: str(d))
    classified: list[tuple[Path, RunPlan]] = []
    for base in project_dirs:
        sub = _classify_dir(base)
        if sub.language != "unknown":
            classified.append((base, sub))

    if classified:
        # Record every sub-project honestly.
        for base, sub in classified:
            rel = "." if base == root else str(base.relative_to(root))
            plan.subprojects.append(
                {
                    "path": rel,
                    "language": sub.language,
                    "kind": sub.kind,
                    "frameworks": sub.frameworks,
                    "run_command": sub.run_command,
                    "test_command": sub.test_command,
                }
            )

        # Primary = most security-relevant sub-project (contract > service > cli > library).
        primary_base, primary = max(
            classified, key=lambda item: (_KIND_RANK.get(item[1].kind, 0), item[0] == root)
        )
        plan.language = primary.language
        plan.kind = primary.kind
        plan.frameworks = sorted({fw for _, s in classified for fw in s.frameworks})
        plan.install_command = primary.install_command
        plan.build_command = primary.build_command
        plan.run_command = primary.run_command
        plan.test_command = primary.test_command

        # Harness gate: analyzable iff some sub-project is a Python/C command-line target.
        analyzable = next(
            (
                (b, s)
                for b, s in classified
                if s.language in DYNAMIC_LANGUAGES and s.kind == "cli"
            ),
            None,
        )
        if len(classified) > 1:
            ev.append(
                f"monorepo: {len(classified)} sub-projects — "
                + ", ".join(
                    f"{('.' if b == root else b.relative_to(root))} ({s.language} {s.kind})"
                    for b, s in classified[:8]
                )
            )
        else:
            rel = "." if primary_base == root else str(primary_base.relative_to(root))
            ev.append(f"{primary.language} {primary.kind} at {rel}")

        if analyzable is not None:
            abase, asub = analyzable
            rel = "." if abase == root else str(abase.relative_to(root))
            plan.dynamically_analyzable = True
            plan.reason = (
                f"{asub.language} command-line target at {rel} — KavachX can execute and observe it"
            )
        else:
            plan.dynamically_analyzable = False
            plan.reason = _static_reason(plan.language, plan.kind)

    else:
        # No manifest classified: fall back to a bare source tree.
        if next(root.rglob("*.py"), None) is not None:
            plan.language = "python"
            plan.kind = "cli" if _has_main_guard(root) else "library"
            if (root / "tests").is_dir() or (root / "test").is_dir():
                plan.test_command = ["python", "-m", "pytest", "-q"]
            ev.append(f"bare python source tree; kind={plan.kind}")
        elif next(root.rglob("*.c"), None) is not None:
            plan.language = "c"
            plan.kind = "cli"
            ev.append("bare C source tree")
        else:
            ev.append("no recognised manifest; language/kind unknown")
        plan.dynamically_analyzable = plan.language in DYNAMIC_LANGUAGES and plan.kind == "cli"
        plan.reason = (
            f"{plan.language} command-line target — KavachX can execute and observe it"
            if plan.dynamically_analyzable
            else _static_reason(plan.language, plan.kind)
        )

    # -- Makefile hints (fill gaps at the root, never override) -----------------
    if (root / "Makefile").is_file():
        targets = _makefile_targets(root / "Makefile")
        if not plan.build_command and "build" in targets:
            plan.build_command = ["make", "build"]
        if not plan.test_command and "test" in targets:
            plan.test_command = ["make", "test"]
        if not plan.run_command:
            for t in ("run", "start", "dev", "serve"):
                if t in targets:
                    plan.run_command = ["make", t]
                    break

    logger.info(
        "framework.run_plan",
        language=plan.language,
        kind=plan.kind,
        subprojects=len(plan.subprojects),
        dynamic=plan.dynamically_analyzable,
    )
    return plan


def _static_reason(language: str, kind: str) -> str:
    if language not in DYNAMIC_LANGUAGES and language != "unknown":
        return (
            f"detected a {language} {kind}; the dynamic tracing harness currently supports Python "
            "and C, so this target is analysed statically"
        )
    if kind in ("web_service", "smart_contract"):
        return (
            f"detected a {language} {kind}; it has no request→output command-line interface to "
            "observe, so this target is analysed statically"
        )
    if kind == "library":
        return f"detected a {language} library with no runnable entrypoint; analysed statically"
    return "could not determine how to execute this target; analysed statically"
