"""Framework registry — the bridge from a project's framework to its sandbox and run plan.

A framework determines three things KavachX needs before it can execute a target:

* the **language toolchain**, which selects the sandbox image (a Next.js and an Express app both
  need Node; Flask and Django both need Python) — see :mod:`app.sandbox.images`;
* the **observation kind** — a long-running HTTP server vs. a one-shot CLI;
* sensible **default install / build / start commands and a listen port**, offered as prefills in the
  run form (the operator can always edit them).

The operator picks the framework in the run form (auto-inferred from the commands they type, and
overridable). The detector (:mod:`app.analysis.framework`) is the fallback when they pick nothing.
Both feed the same image selection, so a Java or Rust target no longer silently gets the Python
image.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class Framework:
    id: str
    label: str
    #: Toolchain language, used to pick the sandbox image. Empty = "let the detector decide".
    language: str
    #: "http" (long-running server) | "cli" (one-shot request→output) | "" (auto).
    kind: str
    #: Default listen port for HTTP frameworks (0 for CLI/auto).
    port: int = 0
    install: str = ""
    build: str = ""
    start: str = ""
    #: Substrings that, seen in the operator's install/build/start commands, infer this framework.
    signatures: tuple[str, ...] = field(default_factory=tuple)


# Ordered most-specific first: inference walks this list and takes the first framework whose
# signature appears in the operator's commands, so "next" wins over the generic "npm"/"node".
FRAMEWORKS: tuple[Framework, ...] = (
    # -- Node / JavaScript / TypeScript ---------------------------------------
    Framework(
        "next",
        "Next.js",
        "node",
        "http",
        3000,
        "npm install",
        "npm run build",
        "npm run start",
        ("next",),
    ),
    Framework(
        "nestjs",
        "NestJS",
        "node",
        "http",
        3000,
        "npm install",
        "npm run build",
        "npm run start:prod",
        ("nest",),
    ),
    Framework(
        "remix",
        "Remix",
        "node",
        "http",
        3000,
        "npm install",
        "npm run build",
        "npm run start",
        ("remix",),
    ),
    Framework(
        "fastify", "Fastify", "node", "http", 3000, "npm install", "", "npm start", ("fastify",)
    ),
    Framework("koa", "Koa", "node", "http", 3000, "npm install", "", "npm start", ("koa",)),
    Framework(
        "express", "Express", "node", "http", 3000, "npm install", "", "npm start", ("express",)
    ),
    Framework(
        "node-http",
        "Node (HTTP)",
        "node",
        "http",
        3000,
        "npm install",
        "npm run build",
        "npm start",
        ("npm", "node", "pnpm", "yarn"),
    ),
    Framework("node-cli", "Node (CLI)", "node", "cli", 0, "npm install", "", "node .", ()),
    # -- Python ----------------------------------------------------------------
    Framework(
        "fastapi",
        "FastAPI",
        "python",
        "http",
        8000,
        "pip install -r requirements.txt",
        "",
        "uvicorn app.main:app --host 0.0.0.0 --port 8000",
        ("uvicorn", "fastapi", "hypercorn"),
    ),
    Framework(
        "django",
        "Django",
        "python",
        "http",
        8000,
        "pip install -r requirements.txt",
        "",
        "python manage.py runserver 0.0.0.0:8000",
        ("manage.py", "django"),
    ),
    Framework(
        "flask",
        "Flask",
        "python",
        "http",
        5000,
        "pip install -r requirements.txt",
        "",
        "flask run --host 0.0.0.0",
        ("flask", "gunicorn"),
    ),
    Framework(
        "python-http",
        "Python (HTTP)",
        "python",
        "http",
        8000,
        "pip install -r requirements.txt",
        "",
        "python app.py",
        ("starlette", "aiohttp", "tornado", "sanic"),
    ),
    Framework(
        "python-cli",
        "Python (CLI)",
        "python",
        "cli",
        0,
        "pip install -r requirements.txt",
        "",
        "python main.py",
        ("python", "pip", "uv", "poetry"),
    ),
    # -- Java / Kotlin ---------------------------------------------------------
    Framework(
        "spring",
        "Spring Boot",
        "java",
        "http",
        8080,
        "./mvnw -q -DskipTests package",
        "",
        "java -jar target/*.jar",
        ("spring", "mvnw", "gradlew", "mvn", "gradle"),
    ),
    Framework(
        "java-cli",
        "Java (CLI)",
        "java",
        "cli",
        0,
        "./mvnw -q -DskipTests package",
        "",
        "java -jar target/*.jar",
        (),
    ),
    # -- Go --------------------------------------------------------------------
    Framework(
        "go-http",
        "Go (HTTP)",
        "go",
        "http",
        8080,
        "go mod download",
        "go build -o app .",
        "./app",
        ("go run", "go build", "go "),
    ),
    Framework(
        "go-cli", "Go (CLI)", "go", "cli", 0, "go mod download", "go build -o app .", "./app", ()
    ),
    # -- Rust ------------------------------------------------------------------
    Framework(
        "rust-http",
        "Rust (Actix/Axum/Rocket)",
        "rust",
        "http",
        8080,
        "cargo build --release",
        "",
        "./target/release/app",
        ("actix", "axum", "rocket", "warp", "cargo run", "cargo"),
    ),
    Framework(
        "rust-cli",
        "Rust (CLI)",
        "rust",
        "cli",
        0,
        "cargo build --release",
        "",
        "./target/release/app",
        (),
    ),
    # -- Solidity (Hardhat runs on Node) --------------------------------------
    Framework(
        "hardhat",
        "Hardhat (Solidity)",
        "node",
        "cli",
        0,
        "npm install",
        "npx hardhat compile",
        "npx hardhat test",
        ("hardhat",),
    ),
    # -- Fallback --------------------------------------------------------------
    Framework("auto", "Auto-detect / Other", "", "", 0, "", "", "", ()),
)

_BY_ID: dict[str, Framework] = {f.id: f for f in FRAMEWORKS}


def framework_by_id(framework_id: str) -> Framework | None:
    return _BY_ID.get((framework_id or "").strip().lower())


def language_for_framework(framework_id: str) -> str:
    """Toolchain language for a framework id, or '' when unknown / auto (defer to the detector)."""
    fw = framework_by_id(framework_id)
    return fw.language if fw else ""


def kind_for_framework(framework_id: str) -> str:
    fw = framework_by_id(framework_id)
    return fw.kind if fw else ""


def infer_framework(
    *, install: str = "", build: str = "", start: str = "", language: str = ""
) -> str:
    """Best-effort framework id from the operator's commands, falling back to the language.

    Mirrors the frontend inference so a framework the operator did not set explicitly still maps to
    the right image. Returns 'auto' when nothing matches.
    """
    blob = " ".join((install, build, start)).lower()
    if blob.strip():
        for fw in FRAMEWORKS:
            if fw.signatures and any(sig in blob for sig in fw.signatures):
                return fw.id
    lang = (language or "").strip().lower()
    return {
        "typescript": "node-http",
        "javascript": "node-http",
        "python": "python-http",
        "go": "go-http",
        "rust": "rust-http",
        "java": "spring",
        "kotlin": "spring",
        "solidity": "hardhat",
    }.get(lang, "auto")


def public_list() -> list[dict[str, Any]]:
    """Serialisable registry for the run form's framework dropdown."""
    return [
        {
            "id": f.id,
            "label": f.label,
            "language": f.language,
            "kind": f.kind,
            "port": f.port,
            "install": f.install,
            "build": f.build,
            "start": f.start,
        }
        for f in FRAMEWORKS
    ]
