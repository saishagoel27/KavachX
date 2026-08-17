"""FastAPI application.

Cross-cutting behaviour lives here: request ids, structured errors, metrics, CORS and lifespan.
Everything domain-specific is in the routers.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.routes import auth, evidence, runs, system, tenancy
from app.config import settings
from app.core.errors import KavachError
from app.core.logging import (
    configure_logging,
    get_logger,
    request_id_var,
    shutdown_logging,
    tenant_id_var,
    user_id_var,
)
from app.db.session import dispose_engine, get_engine
from app.observability import metrics
from app.orchestration import runner

configure_logging()
logger = get_logger(__name__)

DESCRIPTION = """
**KavachX** — graph-grounded autonomous cyber-reasoning with proof-carrying repair.

The engineering contract behind every endpoint here:

```
LLM proposes  →  deterministic system validates  →  state machine decides
```

A model may propose interface hypotheses, SAMHITA clauses, root causes, patches and refutation
strategies. Only deterministic components decide whether a crash occurred, whether a clause
holds, whether an exploit reproduces, whether a patch passes, whether it stayed inside the blast
radius, what assurance level applies, and whether a pull request may be opened.

**Safety boundary.** Only repositories with verified authority — a GitHub App installation that
actually includes them, or the seeded local target in `DEV_MODE` — can be analysed. The sandbox is
treated as hostile-code execution: no credentials, no network, resource-capped. Working exploits
are gated behind `finding:read_pov` and every access is written to a hash-chained audit log.
"""


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    logger.info(
        "app.startup",
        environment=settings.kavachx_env,
        dev_mode=settings.dev_mode,
        llm_provider=settings.llm_provider,
        sandbox_adapter=settings.sandbox_adapter,
        publisher_dry_run=settings.publisher_dry_run,
    )
    get_engine()
    if settings.sandbox_adapter == "dev":
        logger.warning(
            "app.dev_sandbox_active",
            note=(
                "The development sandbox adapter is active. It is NOT an isolation boundary for "
                "untrusted code."
            ),
        )
    try:
        yield
    finally:
        await runner.drain()
        await dispose_engine()
        logger.info("app.shutdown")
        shutdown_logging()


app = FastAPI(
    title="KavachX API",
    version=system.VERSION,
    description=DESCRIPTION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    contact={"name": "KavachX"},
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-Id", "X-Content-Sha256", "X-Certificate-Hash"],
)


# ---------------------------------------------------------------------------
@app.middleware("http")
async def request_context(request: Request, call_next: Any) -> Response:
    """Assign a request id, time the request, and record metrics."""
    incoming = request.headers.get("x-request-id", "")
    request_id = incoming[:64] if incoming else uuid.uuid4().hex
    request_id_var.set(request_id)
    tenant_id_var.set("")
    user_id_var.set("")
    request.state.request_id = request_id

    started = time.perf_counter()
    label_path = metrics.normalise_path(request.url.path)
    try:
        response = await call_next(request)
    except Exception:
        elapsed = time.perf_counter() - started
        metrics.http_requests.labels(method=request.method, path=label_path, status="500").inc()
        metrics.http_latency.labels(method=request.method, path=label_path).observe(elapsed)
        logger.exception(
            "http.unhandled", method=request.method, path=request.url.path, ms=int(elapsed * 1000)
        )
        raise

    elapsed = time.perf_counter() - started
    metrics.http_requests.labels(
        method=request.method, path=label_path, status=str(response.status_code)
    ).inc()
    metrics.http_latency.labels(method=request.method, path=label_path).observe(elapsed)
    response.headers["X-Request-Id"] = request_id

    if request.url.path not in ("/health", "/ready", "/metrics"):
        logger.info(
            "http.request",
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            ms=int(elapsed * 1000),
        )
    return response


# ---------------------------------------------------------------------------
def _error_response(
    status_code: int, code: str, message: str, request_id: str, details: Any = None
) -> JSONResponse:
    error: dict[str, Any] = {"code": code, "message": message, "request_id": request_id}
    if details:
        error["details"] = details
    return JSONResponse(status_code=status_code, content={"error": error})


@app.exception_handler(KavachError)
async def kavach_error_handler(request: Request, exc: KavachError) -> JSONResponse:
    request_id = getattr(request.state, "request_id", "")
    if exc.status_code >= 500:
        logger.error("api.error", code=exc.code, status=exc.status_code, message=exc.message)
    else:
        logger.info("api.error", code=exc.code, status=exc.status_code)
    return JSONResponse(status_code=exc.status_code, content=exc.to_payload(request_id))


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    return _error_response(
        422,
        "VALIDATION_ERROR",
        "The request payload failed validation.",
        getattr(request.state, "request_id", ""),
        details={
            "errors": [
                {
                    "location": list(error.get("loc", [])),
                    "message": error.get("msg", ""),
                    "type": error.get("type", ""),
                }
                for error in exc.errors()[:20]
            ]
        },
    )


@app.exception_handler(StarletteHTTPException)
async def http_error_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    code = {
        400: "BAD_REQUEST",
        401: "NOT_AUTHENTICATED",
        403: "PERMISSION_DENIED",
        404: "NOT_FOUND",
        405: "METHOD_NOT_ALLOWED",
        409: "CONFLICT",
        429: "RATE_LIMITED",
    }.get(exc.status_code, "HTTP_ERROR")
    return _error_response(
        exc.status_code,
        code,
        str(exc.detail) if exc.detail else "Request failed.",
        getattr(request.state, "request_id", ""),
    )


@app.exception_handler(Exception)
async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    request_id = getattr(request.state, "request_id", "")
    logger.exception("api.unhandled", path=request.url.path)
    # Never leak an internal message or stack detail to a client; the request id ties the
    # response to the full server-side record.
    return _error_response(
        500,
        "INTERNAL_ERROR",
        "An unexpected error occurred. Quote the request id when reporting this.",
        request_id,
    )


# ---------------------------------------------------------------------------
app.include_router(auth.router, prefix=settings.api_prefix)
app.include_router(tenancy.router, prefix=settings.api_prefix)
app.include_router(runs.router, prefix=settings.api_prefix)
app.include_router(evidence.router, prefix=settings.api_prefix)
app.include_router(system.router, prefix=settings.api_prefix)
app.include_router(system.health_router)


@app.get("/metrics", include_in_schema=False)
async def prometheus_metrics() -> Response:
    metrics.runs_active.set(len(runner.active_run_ids()))
    payload, content_type = metrics.render()
    return Response(content=payload, media_type=content_type)


@app.get("/", include_in_schema=False)
async def root() -> dict[str, Any]:
    return {
        "product": "KavachX",
        "tagline": "Graph-grounded autonomous cyber-reasoning with proof-carrying repair.",
        "version": system.VERSION,
        "api": settings.api_prefix,
        "docs": "/docs",
        "health": "/health",
        "ready": "/ready",
        "metrics": "/metrics",
    }
