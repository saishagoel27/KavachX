"""Structured logging on top of **logifyx**.

Two things matter here:

1. **Structure.** Application code calls ``log.info("llm.call", task=..., tokens=...)``.
   The event name is the stable key; the kwargs become real fields (JSON mode) and a
   readable ``key=value`` tail (console mode).
2. **Redaction.** Secrets must never reach a sink. logifyx masks common credential patterns
   in the message body; on top of that we drop any field whose *name* looks like a secret,
   before the record is ever created. Defence in depth, because a leaked token in a log file
   is a real incident even in a PoC.

Request-scoped identifiers (``request_id``, ``tenant_id``, ``run_id``, ``user_id``) are
carried in context variables and injected automatically, so a single run can be traced end
to end across the API, the orchestrator and every worker.
"""

from __future__ import annotations

import logging
import re
import sys
import traceback
from contextvars import ContextVar
from pathlib import Path
from typing import Any

from app.config import REPO_ROOT, settings

request_id_var: ContextVar[str] = ContextVar("request_id", default="")
tenant_id_var: ContextVar[str] = ContextVar("tenant_id", default="")
run_id_var: ContextVar[str] = ContextVar("run_id", default="")
user_id_var: ContextVar[str] = ContextVar("user_id", default="")

_CONTEXT_VARS = (
    ("request_id", request_id_var),
    ("tenant_id", tenant_id_var),
    ("run_id", run_id_var),
    ("user_id", user_id_var),
)

#: Field-name segments that mean "this value is a credential". Matched per segment after
#: splitting on ``_ . -``, so ``tokens`` / ``tokens_in`` / ``max_tokens`` (token *counts*, which
#: the resource meter genuinely needs) are not confused with ``token`` (a credential).
_SECRET_SEGMENTS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "authorization",
        "auth",
        "apikey",
        "credential",
        "credentials",
        "privatekey",
        "signature",
        "jwt",
        "bearer",
        "cookie",
        "session",
    }
)

#: Substrings that are unambiguous regardless of segmentation.
_SECRET_SUBSTRINGS = (
    "password",
    "api_key",
    "apikey",
    "private_key",
    "secret",
    "access_token",
    "refresh_token",
    "github_token",
    "signing_key",
    "client_secret",
    "webhook_secret",
)

#: Explicitly safe names that would otherwise trip the segment rule.
_SECRET_EXEMPT = frozenset(
    {
        "tokens",
        "tokens_in",
        "tokens_out",
        "tokens_total",
        "max_tokens",
        "token_count",
        "token_budget",
        "token_version",
        "tokens_used",
        "session_id",
        "auth_action",
    }
)

#: ``logging.LogRecord`` attribute names we must not shadow via ``extra``.
_RESERVED = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "message",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "taskName",
        "thread",
        "threadName",
    }
)

_configured = False
_LOG_DIR = REPO_ROOT / "logs"
_ROOT_LOGGER_NAME = "kavachx"
_shared_logger: logging.Logger | None = None


def _is_secret_field(name: str) -> bool:
    lowered = name.lower()
    if lowered in _SECRET_EXEMPT:
        return False
    if any(marker in lowered for marker in _SECRET_SUBSTRINGS):
        return True
    segments = re.split(r"[_.\-]+", lowered)
    return any(segment in _SECRET_SEGMENTS for segment in segments)


def _scrub(fields: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in fields.items():
        safe_key = f"f_{key}" if key in _RESERVED else key
        out[safe_key] = "***redacted***" if _is_secret_field(key) else value
    return out


class KavachLogger:
    """Thin structured facade over the single shared logifyx logger.

    Every module gets its own facade, but they all write through one logifyx instance. That
    matters: logifyx configures handlers per logger, so giving each module its own would mean
    a log file and a console handler per module. The module name travels as the ``component``
    field instead.
    """

    __slots__ = ("_logger", "name")

    def __init__(self, name: str, logger: logging.Logger) -> None:
        self.name = name
        self._logger = logger

    # -- internals ---------------------------------------------------------
    def _context(self) -> dict[str, Any]:
        ctx: dict[str, Any] = {"component": self.name}
        for key, var in _CONTEXT_VARS:
            value = var.get()
            if value:
                ctx[key] = value
        return ctx

    # Positional-only: callers legitimately pass fields named `level`, `event`, `exc_info`
    # (e.g. an assurance level). Without the `/` those would collide with the parameter names and
    # raise TypeError deep inside a logging call — which is exactly where you least want one.
    def _emit(self, level: int, event: str, exc_info: bool = False, /, **fields: Any) -> None:
        if not self._logger.isEnabledFor(level):
            return
        merged = _scrub({**self._context(), **fields})

        if exc_info:
            # The traceback is formatted here rather than left to ``exc_info``. logifyx's formatter
            # does not render it, so a ``logger.exception`` call produced an ERROR line naming the
            # event and nothing about the exception — no type, no message, no stack. That cost real
            # debugging time on an empty ``NotImplementedError()`` raised inside asyncio, where the
            # type alone was the entire clue.
            exc_type, exc_value, _ = sys.exc_info()
            if exc_type is not None:
                merged["error_type"] = exc_type.__name__
                merged["error"] = str(exc_value) or f"{exc_type.__name__} (no message)"

        # The traceback is deliberately kept out of the single-line summary and carried as a field,
        # so grep-ability of the message survives while the stack is still recorded.
        tail_fields = {k: v for k, v in merged.items() if k != "traceback"}
        if tail_fields:
            tail = " ".join(f"{k}={_render(v)}" for k, v in tail_fields.items())
            message = f"{event} | {tail}"
        else:
            message = event

        if exc_info and sys.exc_info()[0] is not None:
            merged["traceback"] = traceback.format_exc()[:8000]

        merged["event"] = event
        self._logger.log(level, message, extra=merged, exc_info=exc_info)

    # -- public API --------------------------------------------------------
    def debug(self, event: str, **fields: Any) -> None:
        self._emit(logging.DEBUG, event, **fields)

    def info(self, event: str, **fields: Any) -> None:
        self._emit(logging.INFO, event, **fields)

    def warning(self, event: str, **fields: Any) -> None:
        self._emit(logging.WARNING, event, **fields)

    def error(self, event: str, **fields: Any) -> None:
        self._emit(logging.ERROR, event, **fields)

    def exception(self, event: str, **fields: Any) -> None:
        self._emit(logging.ERROR, event, True, **fields)

    def critical(self, event: str, **fields: Any) -> None:
        self._emit(logging.CRITICAL, event, **fields)

    def bind(self, **fields: Any) -> BoundKavachLogger:
        return BoundKavachLogger(self, fields)


class BoundKavachLogger:
    """A logger with pre-attached fields — e.g. one bound to a run id."""

    __slots__ = ("_bound", "_parent")

    def __init__(self, parent: KavachLogger, bound: dict[str, Any]) -> None:
        self._parent = parent
        self._bound = bound

    def _merge(self, fields: dict[str, Any]) -> dict[str, Any]:
        return {**self._bound, **fields}

    def debug(self, event: str, **fields: Any) -> None:
        self._parent.debug(event, **self._merge(fields))

    def info(self, event: str, **fields: Any) -> None:
        self._parent.info(event, **self._merge(fields))

    def warning(self, event: str, **fields: Any) -> None:
        self._parent.warning(event, **self._merge(fields))

    def error(self, event: str, **fields: Any) -> None:
        self._parent.error(event, **self._merge(fields))

    def exception(self, event: str, **fields: Any) -> None:
        self._parent.exception(event, **self._merge(fields))

    def bind(self, **fields: Any) -> BoundKavachLogger:
        return BoundKavachLogger(self._parent, self._merge(fields))


def _render(value: Any) -> str:
    if isinstance(value, str):
        return value if " " not in value else f'"{value}"'
    if isinstance(value, (int, float, bool)) or value is None:
        return str(value)
    text = str(value)
    return text if len(text) <= 200 else text[:197] + "..."


def configure_logging() -> None:
    """Install logifyx as the process logging backend. Idempotent."""
    global _configured, _shared_logger
    if _configured:
        return

    level = getattr(logging, settings.log_level, logging.INFO)
    _LOG_DIR.mkdir(parents=True, exist_ok=True)
    json_mode = settings.log_format == "json"

    # logifyx is a hard dependency (see pyproject), not an optional enhancement. An earlier version
    # of this function fell back to ``logging.basicConfig`` when the import failed, which meant a
    # broken install silently produced unmasked, unstructured logs — the opposite of the reason
    # logifyx is here. If it cannot be loaded, that is a deployment fault worth failing on.
    from logifyx import Logifyx

    _shared_logger = Logifyx(
        name=_ROOT_LOGGER_NAME,
        level=level,
        json_mode=json_mode,
        # Always requested. logifyx applies it to the console handler only — the file handler is
        # built with ``color=False`` so no ANSI escapes ever reach kavachx.log — and ignores it
        # entirely when ``json_mode`` is true, since the JSON formatter has nowhere to put colour.
        color=True,
        # logifyx also masks credential-shaped substrings inside the rendered message,
        # which catches anything our field-name rule cannot see.
        mask=True,
        log_dir=str(_LOG_DIR),
        file="kavachx.log",
        max_bytes=10_000_000,
        backup_count=5,
    )
    # Instantiating a Logger subclass directly does not register it with the logging
    # manager. Register it so third-party libraries logging under "kavachx.*" and any
    # stdlib lookup resolve to this configured instance rather than a bare placeholder.
    logging.Logger.manager.loggerDict[_ROOT_LOGGER_NAME] = _shared_logger
    _shared_logger.propagate = False

    _route_third_party_logging(level)
    _configured = True


class _LogifyxBridge(logging.Handler):
    """Re-emits stdlib log records through the shared logifyx logger.

    Everything KavachX writes itself already goes through :class:`KavachLogger`. Libraries do not:
    uvicorn, SQLAlchemy and Alembic all log to their own stdlib loggers, so without this bridge the
    process produced *two* log streams — structured, masked, rotated logifyx output for application
    events, and raw stdlib output for everything else. Half a log is worse than one, because the
    half that is missing is the half nobody notices until an incident.

    Records are forwarded with their origin preserved in ``component`` so a uvicorn line is still
    identifiable as uvicorn's, and exception info survives the hop.
    """

    def __init__(self, target: Any) -> None:
        super().__init__()
        self._target = target

    def emit(self, record: logging.LogRecord) -> None:
        if getattr(record, "_kavachx_bridged", False):
            return
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - a broken %-format in a library's own message
            message = str(record.msg)

        try:
            # No redaction pass here on purpose: the shared logifyx logger is constructed with
            # ``mask=True``, which masks credential-shaped substrings in the rendered message. That
            # is the layer that catches a library printing a URL with an embedded token — our own
            # field-name rule (_is_secret_field) cannot see inside someone else's message string.
            self._target.log(
                record.levelno,
                "%s | component=%s",
                message,
                record.name,
                exc_info=record.exc_info,
                extra={"_kavachx_bridged": True},
            )
        except Exception:  # pragma: no cover - logging must never raise into the caller
            pass


def _route_third_party_logging(level: int) -> None:
    """Make logifyx the only sink for the whole process, libraries included."""
    assert _shared_logger is not None

    root = logging.getLogger()
    # Drop handlers other libraries installed (uvicorn adds its own on import) so records reach the
    # bridge instead of being written twice in two different formats.
    for handler in list(root.handlers):
        root.removeHandler(handler)
    root.addHandler(_LogifyxBridge(_shared_logger))
    root.setLevel(level)

    for noisy in (
        "uvicorn",
        "uvicorn.error",
        "uvicorn.access",
        "sqlalchemy",
        "sqlalchemy.engine.Engine",
        "alembic",
        "httpx",
        "httpcore",
        "groq",
        "asyncio",
        "watchfiles",
        "concurrent_log_handler",
    ):
        library = logging.getLogger(noisy)
        # Clear the library's own handlers and let it propagate to the bridged root. Without this,
        # uvicorn keeps writing through its private handler and the bridge never sees the record.
        for handler in list(library.handlers):
            library.removeHandler(handler)
        library.handlers = []
        library.propagate = True
        if noisy in ("uvicorn.access", "sqlalchemy", "sqlalchemy.engine.Engine", "watchfiles"):
            # `sqlalchemy` at INFO emits the whole ORM mapper/relationship/strategy configuration
            # (a wall of "initialize prop …" lines) the first time models load. Keep it at WARNING;
            # SQL echo is controlled separately by DB_ECHO, and alembic's migration logs are their
            # own logger, so "Running upgrade …" still shows.
            library.setLevel(max(level, logging.WARNING))
        else:
            library.setLevel(level)


def get_logger(name: str) -> KavachLogger:
    """Get a structured logger for ``name``. Safe to call at import time."""
    if not _configured:
        configure_logging()
    assert _shared_logger is not None
    short = name.removeprefix("app.").removeprefix("kavachx.")
    return KavachLogger(short, _shared_logger)


def log_directory() -> Path:
    return _LOG_DIR


def shutdown_logging() -> None:
    """Flush logifyx's async handlers on a clean shutdown."""
    try:
        from logifyx import shutdown as logifyx_shutdown

        logifyx_shutdown()
    except Exception:  # pragma: no cover
        logging.shutdown()
