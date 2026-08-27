"""Configuration discovery.

Configuration can invert the security properties of identical code. ``DEBUG=True`` turns a
stack-trace handler into an information-disclosure sink; a bind address of ``0.0.0.0`` turns a
loopback service into an exposed one; a missing ``verify=False`` default decides whether TLS is
checked. Reasoning about source in isolation and then reporting a verdict would be reasoning about
a program that does not exist.

This module finds configuration, classifies each file by *role* (routing, database, auth, CI,
container, dependency manifest, …) and extracts security-relevant settings as structured facts.

It deliberately does **not** decide anything. A ``debug_enabled`` fact is an input to the security
model and the discovery channels, which must still show that it is reachable and, where the target
is executable, reproduce its effect. The existing ``config/reachability`` channel already works
that way; this gives it a real inventory to work from instead of a line-regex sweep.
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


class ConfigRole:
    """What a configuration file governs. Extensible: unknown roles are recorded as GENERIC."""

    ENVIRONMENT = "environment"
    APPLICATION = "application"
    FRAMEWORK = "framework"
    ROUTING = "routing"
    DATABASE = "database"
    AUTHENTICATION = "authentication"
    CONTAINER = "container"
    ORCHESTRATION = "orchestration"
    CI = "ci"
    DEPENDENCY_MANIFEST = "dependency_manifest"
    LOCKFILE = "lockfile"
    BUILD = "build"
    WEBSERVER = "webserver"
    GENERIC = "generic"


#: Filename/path shape -> role. Ordered most specific first.
_ROLE_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(^|/)\.env(\.|$)|(^|/)\.env$"), ConfigRole.ENVIRONMENT),
    (re.compile(r"(^|/)docker-compose\.ya?ml$"), ConfigRole.ORCHESTRATION),
    (re.compile(r"(^|/)Dockerfile"), ConfigRole.CONTAINER),
    (re.compile(r"(^|/)\.github/workflows/"), ConfigRole.CI),
    (re.compile(r"(^|/)(\.gitlab-ci\.ya?ml|\.circleci/|azure-pipelines\.ya?ml|Jenkinsfile)"), ConfigRole.CI),
    (re.compile(r"(^|/)(k8s|kubernetes|helm|charts)/"), ConfigRole.ORCHESTRATION),
    (re.compile(r"(^|/)(nginx|httpd|apache)[^/]*\.conf$"), ConfigRole.WEBSERVER),
    (re.compile(r"(^|/)(alembic\.ini|migrations?/env\.py|knexfile\.\w+|ormconfig\.\w+)$"), ConfigRole.DATABASE),
    (re.compile(r"(^|/)(database|db)\.(ya?ml|json|toml|ini)$"), ConfigRole.DATABASE),
    (re.compile(r"(^|/)(auth|authentication|oauth|keycloak)[^/]*\.(ya?ml|json|toml|ini)$"), ConfigRole.AUTHENTICATION),
    (re.compile(r"(^|/)(routes?|urls?)\.(py|js|ts|ya?ml|json)$"), ConfigRole.ROUTING),
    (re.compile(r"(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.ya?ml|poetry\.lock|uv\.lock|Cargo\.lock|Gemfile\.lock|composer\.lock)$"), ConfigRole.LOCKFILE),
    (re.compile(r"(^|/)(package\.json|pyproject\.toml|requirements[^/]*\.txt|Cargo\.toml|go\.mod|Gemfile|pom\.xml|build\.gradle|composer\.json)$"), ConfigRole.DEPENDENCY_MANIFEST),
    (re.compile(r"(^|/)(next|nuxt|vite|webpack|rollup|tsconfig|babel|tailwind|jest|vitest)\.?[^/]*\.(json|js|ts|mjs|cjs)$"), ConfigRole.FRAMEWORK),
    (re.compile(r"(^|/)(Makefile|CMakeLists\.txt|build\.sh|meson\.build)$"), ConfigRole.BUILD),
    (re.compile(r"(^|/)(settings|config|application)[^/]*\.(py|ya?ml|json|toml|ini|cfg|properties)$"), ConfigRole.APPLICATION),
)

_CONFIG_SUFFIXES = frozenset(
    {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".env", ".properties", ".xml"}
)

#: Directories whose ``.json``/``.yaml`` contents are *data*, not configuration.
#:
#: Without this, every benign-corpus case and every test fixture is counted as a configuration
#: file. That is not a cosmetic miscount: it inflates the index's ``configs_discovered`` counter,
#: it feeds the config/reachability channel a pile of request payloads to chase, and it makes the
#: architecture model claim a service is "configured by" its own test inputs. Measured on the
#: seeded demo target it turned 3 real config files into 15.
_DATA_DIRS = frozenset(
    {
        "corpus",
        "fixtures",
        "fixture",
        "testdata",
        "test-data",
        "__fixtures__",
        "snapshots",
        "__snapshots__",
        "golden",
        "seeds",
        "samples",
        "mocks",
        "__mocks__",
        "locales",
        "i18n",
        "translations",
    }
)

#: Filename stems that make a generic ``.json``/``.yaml`` genuinely configuration. A bare
#: ``001-ping.json`` is not configuration; ``settings.yaml`` is.
_CONFIG_NAME_HINTS = (
    "config",
    "settings",
    "conf",
    "options",
    "env",
    "profile",
    "manifest",
    "policy",
    "rules",
    "schema",
    "app",
    "server",
    "service",
    "logging",
    "secrets",
)

#: Depth at which an unnamed config-suffixed file is still plausibly project configuration.
#: Repository-root and one-level-down files are; a file six directories deep is data.
_MAX_GENERIC_DEPTH = 2

#: Security-relevant settings, as (id, pattern, why-it-matters). Extensible by appending; nothing
#: here concludes anything, each one is a fact for a downstream channel to act on.
_SETTING_RULES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "debug_enabled",
        re.compile(r"\bdebug\b[\"']?\s*[:=]\s*[\"']?(true|1|yes|on)\b", re.IGNORECASE),
        "Debug mode changes error verbosity and can expose stack traces or an interactive console.",
    ),
    (
        "bind_all_interfaces",
        re.compile(r"[\"']?(0\.0\.0\.0|::|\*)[\"']?", re.IGNORECASE),
        "Binding every interface exposes a service beyond loopback.",
    ),
    (
        "tls_verification_disabled",
        re.compile(
            r"(verify\s*[:=]\s*False|rejectUnauthorized\s*[:=]\s*false|"
            r"NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*[\"']?0|insecure_skip_verify\s*[:=]\s*true)",
            re.IGNORECASE,
        ),
        "Disabled certificate verification removes transport authentication.",
    ),
    (
        "permissive_cors",
        re.compile(
            r"(allow[_-]?origins?\s*[:=]\s*[\[\"']?\s*\*|Access-Control-Allow-Origin\s*[:=]\s*\*)",
            re.IGNORECASE,
        ),
        "A wildcard CORS origin lets any site issue credentialed cross-origin requests.",
    ),
    (
        "secret_literal",
        re.compile(
            r"\b(secret|password|passwd|api[_-]?key|token|private[_-]?key)\b[\"']?\s*[:=]\s*"
            r"[\"'][^\"'\s{}$]{8,}[\"']",
            re.IGNORECASE,
        ),
        "A literal credential in configuration is a disclosed credential.",
    ),
    (
        "auth_disabled",
        re.compile(
            r"(auth(entication)?[_-]?(required|enabled)\s*[:=]\s*(false|0|no)|"
            r"require[_-]?auth\s*[:=]\s*(false|0|no))",
            re.IGNORECASE,
        ),
        "Authentication is switched off by configuration.",
    ),
    (
        "container_runs_as_root",
        re.compile(r"^\s*USER\s+root\s*$", re.IGNORECASE | re.MULTILINE),
        "A container running as root removes a containment layer.",
    ),
    (
        "privileged_container",
        re.compile(r"privileged\s*[:=]\s*true", re.IGNORECASE),
        "A privileged container has host-level capabilities.",
    ),
)

_PORT_PATTERN = re.compile(r"port[\"']?\s*[:=]\s*[\"']?(\d{2,5})", re.IGNORECASE)
_MAX_READ_BYTES = 400_000
#: Value-shaped placeholders that are not real credentials. Keeps the secret rule usable.
_PLACEHOLDER = re.compile(
    r"(change[-_]?me|your[-_]|example|placeholder|xxx+|\.\.\.|<[^>]+>|dummy|sample|redacted)",
    re.IGNORECASE,
)


@dataclass
class ConfigSetting:
    id: str
    file: str
    line: int
    snippet: str
    why: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
            "why": self.why,
        }


@dataclass
class DiscoveredConfig:
    path: str
    role: str
    format: str = ""
    settings: list[ConfigSetting] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    #: Environment variable names the file declares or references.
    env_keys: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "role": self.role,
            "format": self.format,
            "settings": [s.as_dict() for s in self.settings],
            "ports": self.ports,
            "env_keys": self.env_keys[:60],
        }


# ---------------------------------------------------------------------------
def _role_for(rel: str) -> str | None:
    """Classify a path, or return ``None`` when it is not configuration.

    An explicit role rule always wins — a ``docker-compose.yml`` inside ``fixtures/`` is still a
    compose file worth reading. Only the *generic* fallback is filtered, because that is the rule
    that would otherwise absorb every JSON fixture in the tree.
    """
    for pattern, role in _ROLE_RULES:
        if pattern.search(rel):
            return role

    path = Path(rel)
    if path.suffix.lower() not in _CONFIG_SUFFIXES:
        return None

    parts = rel.split("/")
    if any(part.lower() in _DATA_DIRS for part in parts[:-1]):
        return None
    if any(part.lower() in ("test", "tests", "spec", "specs", "__tests__") for part in parts[:-1]):
        return None

    stem = path.stem.lower()
    named = any(hint in stem for hint in _CONFIG_NAME_HINTS) or stem.startswith(".")
    shallow = len(parts) <= _MAX_GENERIC_DEPTH
    return ConfigRole.GENERIC if (named or shallow) else None


def _is_prose(rel: str) -> bool:
    return rel.lower().endswith((".md", ".rst", ".txt", ".adoc"))


def discover(root: Path) -> list[DiscoveredConfig]:
    """Inventory configuration files and their security-relevant settings."""
    from app.sandbox.workspace import list_source_files

    out: list[DiscoveredConfig] = []
    for path in list_source_files(root):
        rel = path.relative_to(root).as_posix()
        if _is_prose(rel):
            # Prose mentions configuration without being configuration; scanning it manufactures
            # noise for the reachability channel to chase.
            continue
        role = _role_for(rel)
        if role is None:
            continue
        try:
            if path.stat().st_size > _MAX_READ_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        entry = DiscoveredConfig(
            path=rel, role=role, format=path.suffix.lower().lstrip(".") or path.name
        )

        # A lockfile is inventory, not policy: it is recorded for the dependency model but never
        # scanned for settings, because thousands of transitive entries produce only noise.
        if role != ConfigRole.LOCKFILE:
            for number, line in enumerate(text.splitlines(), start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith(("#", "//", ";")):
                    continue
                for setting_id, pattern, why in _SETTING_RULES:
                    if not pattern.search(line):
                        continue
                    if setting_id == "bind_all_interfaces" and not any(
                        token in line.lower() for token in ("host", "bind", "listen", "addr")
                    ):
                        # `0.0.0.0` inside an unrelated value (a netmask, a version) is not a
                        # bind decision.
                        continue
                    if setting_id == "secret_literal" and _PLACEHOLDER.search(line):
                        continue
                    entry.settings.append(
                        ConfigSetting(
                            id=setting_id,
                            file=rel,
                            line=number,
                            snippet=stripped[:200],
                            why=why,
                        )
                    )
                match = _PORT_PATTERN.search(line)
                if match:
                    port = int(match.group(1))
                    if 0 < port < 65536 and port not in entry.ports:
                        entry.ports.append(port)

        if role == ConfigRole.ENVIRONMENT:
            entry.env_keys = sorted(
                {
                    m.group(1)
                    for m in re.finditer(r"^\s*([A-Z][A-Z0-9_]{2,})\s*=", text, re.MULTILINE)
                }
            )
        elif entry.format == "json":
            # Framework configs carry their meaning in keys; capture top-level keys as env-ish
            # hints without interpreting the values.
            try:
                data = json.loads(text)
                if isinstance(data, dict):
                    entry.env_keys = sorted(str(k) for k in list(data.keys())[:60])
            except ValueError:
                pass

        out.append(entry)

    logger.info(
        "understanding.configs_discovered",
        files=len(out),
        settings=sum(len(c.settings) for c in out),
        roles=sorted({c.role for c in out}),
    )
    return out


def attach(graph: CodeGraph, root: Path) -> int:
    """Write configuration into the graph as CONFIGURATION nodes.

    A config node is linked to the file it came from with ``CONFIGURED_BY``, so a query can ask
    what governs a module. Returns the number of configuration files found.
    """
    configs = discover(root)
    for config in configs:
        uid = f"config:{config.path}"
        graph.add_node(
            CodeNode(
                uid=uid,
                kind=NodeKind.CONFIGURATION.value,
                name=config.path.rsplit("/", 1)[-1],
                qualname=config.path,
                file=config.path,
                provenance={Provider.KAVACHX.value},
                attrs={
                    "role": config.role,
                    "format": config.format,
                    "settings": [s.as_dict() for s in config.settings],
                    "ports": config.ports,
                    "env_keys": config.env_keys[:60],
                },
            )
        )
        if graph.has(config.path):
            graph.add_edge(
                CodeEdge(
                    src=config.path,
                    dst=uid,
                    kind=EdgeKind.CONFIGURED_BY.value,
                    provenance={Provider.KAVACHX.value},
                    confidence=1.0,
                )
            )
    return len(configs)


def settings_of(graph: CodeGraph, *ids: str) -> list[dict[str, Any]]:
    """Every discovered setting, optionally filtered to specific setting ids."""
    wanted = set(ids)
    out: list[dict[str, Any]] = []
    for node in graph.nodes_of(NodeKind.CONFIGURATION.value):
        for setting in node.attrs.get("settings") or []:
            if not wanted or setting.get("id") in wanted:
                out.append(setting)
    return out


def declared_ports(graph: CodeGraph) -> list[int]:
    ports: set[int] = set()
    for node in graph.nodes_of(NodeKind.CONFIGURATION.value):
        for port in node.attrs.get("ports") or []:
            ports.add(int(port))
    return sorted(ports)
