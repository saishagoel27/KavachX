"""Dependency discovery.

Purpose, stated precisely because it is easy to overreach here: dependency information exists to
**improve code understanding and candidate generation**, not to generate vulnerability reports.

KavachX has no vulnerability database, so it cannot know whether the installed version of a
package is affected by anything. Emitting "you use `pyyaml`, CVE-XXXX exists" from a package name
alone would be exactly the kind of unverified claim this system is built to avoid — and the spec
forbids it explicitly.

What the dependency model *is* used for:

* **Framework identification**, which selects the sandbox toolchain image and the test/fuzz engine.
* **Security-sensitive library flags** — a target that imports `yaml`, `pickle`, `jinja2` or
  `subprocess` has a *sink class* worth looking for, which raises the prior on a candidate the
  static rules find in code. The flag says "look here", never "this is vulnerable".
* **Transitive inventory** from lockfiles where one is present, so the attack surface description
  can state what actually ships rather than what is declared.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.logging import get_logger
from app.indexing.model import CodeEdge, CodeGraph, CodeNode, EdgeKind, NodeKind, Provider

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class Manifest:
    filename: str
    ecosystem: str
    language: str


MANIFESTS: tuple[Manifest, ...] = (
    Manifest("pyproject.toml", "pypi", "python"),
    Manifest("requirements.txt", "pypi", "python"),
    Manifest("requirements-dev.txt", "pypi", "python"),
    Manifest("Pipfile", "pypi", "python"),
    Manifest("setup.py", "pypi", "python"),
    Manifest("package.json", "npm", "javascript"),
    Manifest("Cargo.toml", "crates", "rust"),
    Manifest("go.mod", "go", "go"),
    Manifest("Gemfile", "rubygems", "ruby"),
    Manifest("pom.xml", "maven", "java"),
    Manifest("build.gradle", "maven", "java"),
    Manifest("build.gradle.kts", "maven", "kotlin"),
    Manifest("composer.json", "packagist", "php"),
    Manifest("pubspec.yaml", "pub", "dart"),
)

LOCKFILES: tuple[Manifest, ...] = (
    Manifest("package-lock.json", "npm", "javascript"),
    Manifest("yarn.lock", "npm", "javascript"),
    Manifest("pnpm-lock.yaml", "npm", "javascript"),
    Manifest("poetry.lock", "pypi", "python"),
    Manifest("uv.lock", "pypi", "python"),
    Manifest("Cargo.lock", "crates", "rust"),
    Manifest("Gemfile.lock", "rubygems", "ruby"),
    Manifest("composer.lock", "packagist", "php"),
)

#: Packages whose presence implies a sink class worth searching for, mapped to the class and the
#: CWE family it belongs to. This is a *prior*, never a finding — see the module docstring.
#: Extensible: appending a row adds a hint, it does not add a verdict.
SENSITIVE_LIBRARIES: dict[str, tuple[str, str, str]] = {
    # package                    (sink class,           cwe,       why
    "pyyaml": ("deserialisation", "CWE-502", "yaml.load without SafeLoader executes constructors"),
    "yaml": ("deserialisation", "CWE-502", "yaml.load without SafeLoader executes constructors"),
    "dill": ("deserialisation", "CWE-502", "arbitrary object deserialisation"),
    "cloudpickle": ("deserialisation", "CWE-502", "arbitrary object deserialisation"),
    "jinja2": ("template_injection", "CWE-1336", "template rendering from untrusted strings"),
    "mako": ("template_injection", "CWE-1336", "template rendering from untrusted strings"),
    "ejs": ("template_injection", "CWE-1336", "template rendering from untrusted strings"),
    "handlebars": ("template_injection", "CWE-1336", "template rendering from untrusted strings"),
    "sqlalchemy": ("sql", "CWE-89", "raw text() SQL bypasses parameter binding"),
    "psycopg2": ("sql", "CWE-89", "string-formatted SQL"),
    "pymysql": ("sql", "CWE-89", "string-formatted SQL"),
    "mysql2": ("sql", "CWE-89", "string-formatted SQL"),
    "sqlite3": ("sql", "CWE-89", "string-formatted SQL"),
    "knex": ("sql", "CWE-89", "raw() bypasses the query builder"),
    "sequelize": ("sql", "CWE-89", "literal / raw query paths"),
    "requests": ("network", "CWE-918", "outbound requests to caller-influenced URLs"),
    "axios": ("network", "CWE-918", "outbound requests to caller-influenced URLs"),
    "urllib3": ("network", "CWE-918", "outbound requests to caller-influenced URLs"),
    "flask": ("http_entrypoint", "", "HTTP request objects are external input sources"),
    "django": ("http_entrypoint", "", "HTTP request objects are external input sources"),
    "fastapi": ("http_entrypoint", "", "HTTP request objects are external input sources"),
    "express": ("http_entrypoint", "", "HTTP request objects are external input sources"),
    "koa": ("http_entrypoint", "", "HTTP request objects are external input sources"),
    "pyjwt": ("auth_decision", "CWE-347", "signature verification can be disabled"),
    "jsonwebtoken": ("auth_decision", "CWE-347", "signature verification can be disabled"),
    "cryptography": ("crypto", "", "cryptographic primitives used directly"),
    "pycrypto": ("crypto", "CWE-327", "unmaintained; weak primitive defaults"),
    "pycryptodome": ("crypto", "", "cryptographic primitives used directly"),
    "lxml": ("xml", "CWE-611", "external entity resolution"),
    "xmltodict": ("xml", "CWE-611", "external entity resolution"),
    "paramiko": ("process_exec", "CWE-78", "remote command execution"),
    "shelljs": ("shell_exec", "CWE-78", "shell command construction"),
    "serialize-javascript": ("deserialisation", "CWE-502", "code-bearing serialisation"),
    "node-serialize": ("deserialisation", "CWE-502", "code-bearing serialisation"),
    "marked": ("html_output", "CWE-79", "HTML generation from untrusted markdown"),
    "dompurify": ("sanitizer", "", "an HTML sanitiser — a control, not a sink"),
    "bleach": ("sanitizer", "", "an HTML sanitiser — a control, not a sink"),
}


@dataclass
class Dependency:
    name: str
    version_spec: str = ""
    ecosystem: str = ""
    manifest: str = ""
    direct: bool = True
    dev: bool = False
    #: Populated from SENSITIVE_LIBRARIES. A hint for candidate generation.
    sink_class: str = ""
    cwe: str = ""
    why_sensitive: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version_spec": self.version_spec,
            "ecosystem": self.ecosystem,
            "manifest": self.manifest,
            "direct": self.direct,
            "dev": self.dev,
            "sink_class": self.sink_class,
            "cwe": self.cwe,
            "why_sensitive": self.why_sensitive,
        }


@dataclass
class DependencyModel:
    manifests: list[str] = field(default_factory=list)
    lockfiles: list[str] = field(default_factory=list)
    dependencies: list[Dependency] = field(default_factory=list)
    ecosystems: list[str] = field(default_factory=list)
    languages: list[str] = field(default_factory=list)
    #: Count of transitive entries seen in lockfiles. Inventory only.
    transitive_count: int = 0
    note: str = (
        "Dependency information is used for code understanding and candidate generation only. "
        "KavachX has no vulnerability database and makes no claim about whether any version here "
        "is affected by a known advisory."
    )

    @property
    def direct(self) -> list[Dependency]:
        return [d for d in self.dependencies if d.direct]

    @property
    def sensitive(self) -> list[Dependency]:
        return [d for d in self.dependencies if d.sink_class]

    def as_dict(self) -> dict[str, Any]:
        return {
            "manifests": self.manifests,
            "lockfiles": self.lockfiles,
            "count": len(self.dependencies),
            "direct_count": len(self.direct),
            "transitive_count": self.transitive_count,
            "ecosystems": self.ecosystems,
            "languages": self.languages,
            "dependencies": [d.as_dict() for d in self.dependencies[:300]],
            "sensitive": [d.as_dict() for d in self.sensitive],
            "note": self.note,
        }


# ---------------------------------------------------------------------------
_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9_.\-\[\]]+)\s*([><=~!^].*)?$")
_PYPROJECT_DEP = re.compile(r'^\s*"([A-Za-z0-9_.\-\[\]]+)\s*([^"]*)"', re.MULTILINE)
_GO_REQUIRE = re.compile(r"^\s+([\w./\-]+)\s+(v[\w.\-+]+)", re.MULTILINE)
_CARGO_DEP = re.compile(r'^\s*([A-Za-z0-9_\-]+)\s*=\s*[\{"]', re.MULTILINE)
_GEM = re.compile(r"^\s*gem\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?", re.MULTILINE)
_MAVEN_ARTIFACT = re.compile(r"<artifactId>([^<]+)</artifactId>")


def _classify(name: str) -> tuple[str, str, str]:
    key = name.lower().split("[")[0]
    # A scoped npm package (@scope/name) is matched on its bare name too.
    if key.startswith("@") and "/" in key:
        key = key.split("/", 1)[1]
    return SENSITIVE_LIBRARIES.get(key, ("", "", ""))


def _make(name: str, spec: str, manifest: Manifest, *, dev: bool = False, direct: bool = True) -> Dependency:
    sink_class, cwe, why = _classify(name)
    return Dependency(
        name=name,
        version_spec=(spec or "").strip()[:60],
        ecosystem=manifest.ecosystem,
        manifest=manifest.filename,
        direct=direct,
        dev=dev,
        sink_class=sink_class,
        cwe=cwe,
        why_sensitive=why,
    )


def discover(root: Path) -> DependencyModel:
    """Build the dependency model from whatever manifests and lockfiles exist."""
    model = DependencyModel()
    seen: set[tuple[str, str]] = set()

    def push(dependency: Dependency) -> None:
        key = (dependency.ecosystem, dependency.name.lower())
        if key in seen:
            return
        seen.add(key)
        model.dependencies.append(dependency)

    for manifest in MANIFESTS:
        path = root / manifest.filename
        if not path.is_file():
            continue
        model.manifests.append(manifest.filename)
        if manifest.language not in model.languages:
            model.languages.append(manifest.language)
        if manifest.ecosystem not in model.ecosystems:
            model.ecosystems.append(manifest.ecosystem)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        if manifest.filename == "package.json":
            try:
                data = json.loads(text)
            except ValueError:
                continue
            for section, is_dev in (
                ("dependencies", False),
                ("devDependencies", True),
                ("peerDependencies", False),
                ("optionalDependencies", False),
            ):
                for name, spec in (data.get(section) or {}).items():
                    push(_make(str(name), str(spec), manifest, dev=is_dev))
        elif manifest.filename == "pyproject.toml":
            for match in _PYPROJECT_DEP.finditer(text):
                push(_make(match.group(1), match.group(2), manifest))
        elif manifest.filename.startswith("requirements"):
            is_dev = "dev" in manifest.filename
            for line in text.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith(("#", "-")):
                    continue
                match = _REQ_LINE.match(stripped.split(";")[0])
                if match:
                    push(_make(match.group(1), match.group(2) or "", manifest, dev=is_dev))
        elif manifest.filename == "go.mod":
            for match in _GO_REQUIRE.finditer(text):
                push(_make(match.group(1), match.group(2), manifest))
        elif manifest.filename == "Cargo.toml":
            # Only the [dependencies]-ish tables; a bare key=value elsewhere is not a dependency.
            for block in re.split(r"^\[", text, flags=re.MULTILINE):
                if not block.lower().startswith(("dependencies", "dev-dependencies")):
                    continue
                is_dev = block.lower().startswith("dev-")
                for match in _CARGO_DEP.finditer(block):
                    push(_make(match.group(1), "", manifest, dev=is_dev))
        elif manifest.filename == "Gemfile":
            for match in _GEM.finditer(text):
                push(_make(match.group(1), match.group(2) or "", manifest))
        elif manifest.filename in ("pom.xml", "build.gradle", "build.gradle.kts"):
            for match in _MAVEN_ARTIFACT.finditer(text):
                push(_make(match.group(1), "", manifest))
        elif manifest.filename == "composer.json":
            try:
                data = json.loads(text)
            except ValueError:
                continue
            for section, is_dev in (("require", False), ("require-dev", True)):
                for name, spec in (data.get(section) or {}).items():
                    push(_make(str(name), str(spec), manifest, dev=is_dev))

    # Lockfiles: inventory the transitive set without trying to reconstruct the tree.
    for lockfile in LOCKFILES:
        path = root / lockfile.filename
        if not path.is_file():
            continue
        model.lockfiles.append(lockfile.filename)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        model.transitive_count += _count_locked(lockfile.filename, text)

    logger.info(
        "understanding.dependencies_discovered",
        manifests=model.manifests,
        direct=len(model.direct),
        transitive=model.transitive_count,
        sensitive=len(model.sensitive),
    )
    return model


def _count_locked(filename: str, text: str) -> int:
    """Number of locked entries. Best-effort per format; a bad parse returns 0, never a guess."""
    if filename == "package-lock.json":
        try:
            data = json.loads(text)
        except ValueError:
            return 0
        return len(data.get("packages") or data.get("dependencies") or {})
    if filename in ("poetry.lock", "uv.lock", "Cargo.lock"):
        return len(re.findall(r"^\[\[package\]\]", text, re.MULTILINE))
    if filename == "yarn.lock":
        return len(re.findall(r"^\S.*:$", text, re.MULTILINE))
    if filename == "pnpm-lock.yaml":
        return len(re.findall(r"^\s{2}/", text, re.MULTILINE))
    if filename == "Gemfile.lock":
        return len(re.findall(r"^\s{4}\S+ \(", text, re.MULTILINE))
    if filename == "composer.lock":
        try:
            data = json.loads(text)
        except ValueError:
            return 0
        return len(data.get("packages") or []) + len(data.get("packages-dev") or [])
    return 0


def attach(graph: CodeGraph, root: Path) -> int:
    """Write dependencies into the graph as DEPENDENCY nodes. Returns the count."""
    model = discover(root)
    for dependency in model.dependencies:
        uid = f"dep:{dependency.ecosystem}:{dependency.name.lower()}"
        graph.add_node(
            CodeNode(
                uid=uid,
                kind=NodeKind.DEPENDENCY.value,
                name=dependency.name,
                qualname=f"{dependency.ecosystem}/{dependency.name}",
                provenance={Provider.KAVACHX.value},
                attrs=dependency.as_dict(),
            )
        )
        if graph.has(dependency.manifest):
            graph.add_edge(
                CodeEdge(
                    src=dependency.manifest,
                    dst=uid,
                    kind=EdgeKind.DEPENDS_ON.value,
                    provenance={Provider.KAVACHX.value},
                    confidence=1.0,
                )
            )
    # Keep the model reachable for the architecture stage without re-reading the tree. It goes in
    # graph *metadata*, not as a node: a synthetic "dependency model" node would be counted by
    # `stats()` as one additional dependency, so the index would report N+1 dependencies for every
    # target — including 1 for a target with no manifest at all.
    graph.metadata["dependency_model"] = model.as_dict()
    return len(model.dependencies)


def model_from_graph(graph: CodeGraph) -> dict[str, Any]:
    """The stored dependency model, or an empty one."""
    return dict(graph.metadata.get("dependency_model") or {})
