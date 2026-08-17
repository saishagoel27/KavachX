"""Request dispatch — the single entrypoint of the demo service.

A request is a JSON object::

    {"op": "export", "name": "q3-summary", "format": "csv", "headers": "x-trace:1\\n"}

Supported operations: ``ping``, ``parse``, ``export``, ``asset``, ``status``.
"""

from __future__ import annotations

from typing import Any

from reportsvc import assets, config, exporter, parser

_request_counter = 0


class RequestError(ValueError):
    """Raised for a structurally invalid request."""


def _next_sequence() -> int:
    global _request_counter
    _request_counter += 1
    return _request_counter


def handle(request: dict[str, Any]) -> dict[str, Any]:
    """Dispatch one request and return a response object."""
    if not isinstance(request, dict):
        raise RequestError("request must be an object")

    op = request.get("op")
    if not isinstance(op, str) or not op:
        raise RequestError("missing op")

    sequence = _next_sequence()
    cfg = config.load_config()

    if op == "ping":
        return {"ok": True, "op": op, "seq": sequence, "service": cfg["service_name"]}

    if op == "status":
        return {
            "ok": True,
            "op": op,
            "seq": sequence,
            "debug": cfg.get("debug", False),
            "assets": assets.list_assets(),
        }

    if op == "parse":
        raw = request.get("headers", "")
        headers = parser.parse_header(raw if isinstance(raw, str) else "")
        return {
            "ok": True,
            "op": op,
            "seq": sequence,
            "headers": headers,
            "count": parser.header_count(raw if isinstance(raw, str) else ""),
        }

    if op == "export":
        name = request.get("name")
        if not isinstance(name, str) or not name:
            raise RequestError("export requires a name")
        fmt = request.get("format", "txt")
        result = exporter.export_report(name, fmt if isinstance(fmt, str) else "txt")
        return {"ok": True, "op": op, "seq": sequence, "export": result}

    if op == "asset":
        path = request.get("path")
        if not isinstance(path, str) or not path:
            raise RequestError("asset requires a path")
        return {
            "ok": True,
            "op": op,
            "seq": sequence,
            "content": assets.read_asset(path),
        }

    raise RequestError(f"unknown op: {op}")


def entrypoint(request: dict[str, Any]) -> dict[str, Any]:
    """Public entrypoint. Errors are converted into structured responses."""
    try:
        return handle(request)
    except (RequestError, parser.HeaderError) as exc:
        return {"ok": False, "op": request.get("op"), "error": str(exc), "kind": "request"}
