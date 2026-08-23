"""Automatic benign-workload generation.

The goal is fully automatic analysis: the operator points KavachX at a repo and gives basic run
config — KavachX generates the test inputs itself, rather than the operator hand-writing request
patterns. This module does the *generation*; the caller does the *verification* (running each
candidate and keeping only the ones that actually succeed), which is what keeps it honest — a
guessed request that errors is never treated as a valid benign baseline.

What it derives, statically, from the target's own source:

* **HTTP routes** — Express/Koa/Fastify ``app.get('/x')``, FastAPI/Flask decorators, Next.js
  ``app/**/route.ts`` and ``pages/api/**`` files, and raw ``http`` servers that switch on
  ``pathname === '/x'`` — plus the query parameters each handler reads.
* **CLI request shapes** — the operation names a JSON-request CLI dispatches on (``op === "…"``)
  and the request fields it reads (``req.name``, ``request["path"]``), so a candidate request
  carries the fields the vulnerable path actually needs.

Values are benign defaults, except path-like fields, which are filled from a real file in the
asset directory so a read succeeds (and is then mutated into a traversal by the fuzzer).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.logging import get_logger

logger = get_logger(__name__)

_IGNORE_DIRS = frozenset(
    {"node_modules", ".git", "dist", "build", "target", ".next", ".venv", "venv", "__pycache__"}
)
_SOURCE_SUFFIXES = (".js", ".mjs", ".cjs", ".ts", ".tsx", ".py")
_MAX_FILES = 4000
_MAX_ROUTES = 60

# -- HTTP route patterns ------------------------------------------------------
_ROUTE_CALL = re.compile(
    r"""\b(?:app|router|api|server|fastify|bp|blueprint)\.(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]""",
    re.IGNORECASE,
)
_ROUTE_DECORATOR = re.compile(
    r"""@\s*(?:app|router|api)\.(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]""",
    re.IGNORECASE,
)
_FLASK_ROUTE = re.compile(r"""@\s*(?:app|bp|blueprint)\.route\s*\(\s*['"`]([^'"`]+)['"`]""")
_PATHNAME_SWITCH = re.compile(r"""(?:pathname|req\.url|url)\s*===?\s*['"`]([^'"`]+)['"`]""")
_NEXT_METHOD_EXPORT = re.compile(r"export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)")

# -- parameter patterns -------------------------------------------------------
_QUERY_PARAM = re.compile(
    r"""(?:req\.query|request\.args|request\.query_params|\bquery|\bq|params|searchParams)"""
    r"""(?:\.get\(\s*['"]([A-Za-z_]\w*)['"]|\.([A-Za-z_]\w*)|\[\s*['"]([A-Za-z_]\w*)['"]\s*\])"""
)
# -- CLI patterns -------------------------------------------------------------
_OP_LITERAL = re.compile(
    r"""(?:\bop\b\s*===?\s*['"]([\w.-]+)['"]|['"]([\w.-]+)['"]\s*===?\s*\bop\b|case\s+['"]([\w.-]+)['"])"""
)
_REQ_FIELD = re.compile(
    r"""(?:req|request|payload|body|data|args)(?:\.([A-Za-z_]\w*)|\[\s*['"]([A-Za-z_]\w*)['"]\s*\])"""
)
_PATHLIKE = re.compile(r"path|file|asset|dir|template|tmpl|src|dest", re.IGNORECASE)
_NOISE_FIELDS = frozenset(
    {"op", "action", "query", "args", "params", "body", "get", "url", "method", "headers", "on"}
)


@dataclass(slots=True)
class RouteSpec:
    method: str
    path: str
    params: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"method": self.method, "path": self.path, "params": self.params}


def _read(path: Path, *, limit: int = 60_000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return ""


def _iter_source(root: Path):
    count = 0
    for path in root.rglob("*"):
        if count >= _MAX_FILES:
            break
        if any(part in _IGNORE_DIRS for part in path.parts):
            continue
        if path.is_file() and path.suffix.lower() in _SOURCE_SUFFIXES:
            count += 1
            yield path


def _asset_filename(root: Path, asset_dir: str) -> str:
    for candidate in (asset_dir, "assets", "templates", "static", "public"):
        if not candidate:
            continue
        d = root / candidate
        if d.is_dir():
            for f in sorted(d.rglob("*")):
                if f.is_file():
                    return f.relative_to(d).as_posix()
    return "index.html"


def _benign_value(param: str, asset: str) -> str:
    return asset if _PATHLIKE.search(param) else "test"


def _params_in(text: str) -> list[str]:
    found: list[str] = []
    for m in _QUERY_PARAM.finditer(text):
        name = m.group(1) or m.group(2) or m.group(3)
        if name and name not in _NOISE_FIELDS and name not in found:
            found.append(name)
    return found[:8]


# ---------------------------------------------------------------------------
def discover_http_routes(root: Path) -> list[RouteSpec]:
    """Statically discover HTTP routes (method + path + query params) from the source."""
    routes: dict[tuple[str, str], RouteSpec] = {}

    def add(method: str, path: str, params: list[str]) -> None:
        if not path.startswith("/"):
            return
        key = (method.upper(), path)
        if key in routes:
            routes[key].params = sorted(set(routes[key].params) | set(params))
        elif len(routes) < _MAX_ROUTES:
            routes[key] = RouteSpec(method=method.upper(), path=path, params=params)

    for path in _iter_source(root):
        text = _read(path)
        params = _params_in(text)
        rel = path.relative_to(root).as_posix()

        for m in _ROUTE_CALL.finditer(text):
            add(m.group(1), m.group(2), params)
        for m in _ROUTE_DECORATOR.finditer(text):
            add(m.group(1), m.group(2), params)
        for m in _FLASK_ROUTE.finditer(text):
            add("GET", m.group(1), params)
        for m in _PATHNAME_SWITCH.finditer(text):
            add("GET", m.group(1), params)

        # Next.js file-based routing.
        if path.name.startswith("route.") and "/app/" in f"/{rel}":
            segment = rel.split("/app/", 1)[1].rsplit("/", 1)[0]
            route_path = "/" + "/".join(p for p in segment.split("/") if not p.startswith("("))
            methods = _NEXT_METHOD_EXPORT.findall(text) or ["GET"]
            for method in methods:
                add(method, route_path, params)
        elif "/pages/api/" in f"/{rel}" or rel.startswith("pages/api/"):
            after = rel.split("pages/api/", 1)[1]
            route_path = "/api/" + re.sub(r"\.(ts|tsx|js|mjs|cjs)$", "", after)
            route_path = route_path.replace("/index", "") or "/api"
            add("GET", route_path, params)

    return list(routes.values())


def synthesize_http_requests(root: Path, routes: list[RouteSpec], asset_dir: str = "") -> list[dict[str, Any]]:
    """Turn discovered routes into concrete benign candidate requests."""
    asset = _asset_filename(root, asset_dir)
    out: list[dict[str, Any]] = []
    for route in routes:
        path = re.sub(r"[:\[]([A-Za-z_]\w*)\]?", "1", route.path)  # fill :id / [id] path params
        if route.params:
            query = "&".join(f"{p}={_benign_value(p, asset)}" for p in route.params)
            path = f"{path}?{query}"
        out.append({"method": route.method, "path": path})
    return out


def synthesize_cli_candidates(
    root: Path, entry_file: str, asset_dir: str = ""
) -> list[dict[str, Any]]:
    """Derive candidate JSON requests for a CLI from its dispatch ops and the fields it reads."""
    entry = root / entry_file if entry_file else None
    text = _read(entry) if entry and entry.is_file() else ""
    if not text:
        for path in _iter_source(root):
            text += "\n" + _read(path, limit=20_000)

    ops: list[str] = []
    for m in _OP_LITERAL.finditer(text):
        op = m.group(1) or m.group(2) or m.group(3)
        if op and op not in ops:
            ops.append(op)

    fields: list[str] = []
    for m in _REQ_FIELD.finditer(text):
        name = m.group(1) or m.group(2)
        if name and name not in _NOISE_FIELDS and name not in fields:
            fields.append(name)

    asset = _asset_filename(root, asset_dir)
    base = {f: _benign_value(f, asset) for f in fields[:8]}

    candidates: list[dict[str, Any]] = []
    if ops:
        for op in ops[:12]:
            candidates.append({"op": op, **base})
    elif base:
        candidates.append(dict(base))
    else:
        candidates.append({})
    logger.info("workload.cli_candidates", ops=len(ops), fields=len(fields), candidates=len(candidates))
    return candidates
