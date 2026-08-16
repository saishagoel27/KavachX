"""
KavachX: Main FastAPI application with LangGraph orchestration.

Integrates:
- FastAPI async HTTP endpoints + CORS for the Vite frontend
- Dashboard API (`/api`) with an SSE run trace — see kavachx/api/routes/runs.py
- LangGraph state machine for workflow orchestration
- Multi-tenant authentication and RBAC
- Async database operations
- GitHub API integration
- Webhook handling for GitHub events

Run it with:  uv run uvicorn app:app --reload   (or `python app.py`)
"""

import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

# LangGraph and orchestration
from langgraph.graph import StateGraph, END

# KavachX modules — importing the package loads backend/.env first.
from kavachx.api.middleware.rbac import check_permission
from kavachx.api.middleware.tenant import extract_tenant_from_token
from kavachx.api.routes import auth as auth_routes
from kavachx.api.routes import runs as dashboard_routes
from kavachx.core.config import get_settings
from kavachx.core.state import KavachState, initial_state
from kavachx.discovery import discover_patches
from kavachx.patch.stages import stage_patches
from kavachx.pramaan import verify_patches
from kavachx.publisher import publish_patches
from kavachx.samhita import synthesize_reports

settings = get_settings()

logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO))
logger = logging.getLogger(__name__)


# ============================================================================
# Request/Response Models
# ============================================================================

class DiscoverRequest(BaseModel):
    """Request to start patch discovery."""
    channels: list[str]  # List of "org/repo#branch" channels
    priority: str = "all"  # all, critical, high


class WorkflowStatusResponse(BaseModel):
    """Response with workflow status."""
    run_id: str
    phase: str
    status: str
    progress: dict
    patches_discovered: int
    patches_staged: int
    patches_verified: int
    patches_published: int


class ApprovalRequest(BaseModel):
    """Request to approve a patch for publishing."""
    patch_id: str
    approved: bool
    reviewer_notes: str = ""


# ============================================================================
# LangGraph Workflow Definition
# ============================================================================

def _build_workflow_graph():
    """Build the LangGraph state graph for patch orchestration."""
    logger.info("[App] Building workflow graph")

    # Create StateGraph
    graph = StateGraph(KavachState)

    # Add nodes for each phase
    graph.add_node("discover", discover_patches)
    graph.add_node("stage", stage_patches)
    graph.add_node("synthesize", synthesize_reports)
    graph.add_node("verify", verify_patches)
    graph.add_node("publish", publish_patches)

    # Define edges (transitions)
    graph.add_edge("discover", "stage")
    graph.add_edge("stage", "synthesize")
    graph.add_edge("synthesize", "verify")
    graph.add_edge("verify", "publish")
    graph.add_edge("publish", END)

    # Set entry point
    graph.set_entry_point("discover")

    return graph.compile()


# ============================================================================
# Dependency: Get Database Session
# ============================================================================

async def get_db_session() -> AsyncSession:
    """Get async database session."""
    # TODO: Import and use actual AsyncSession from db.models
    # This is a placeholder that assumes db.get_session() exists
    # from kavachx.db.models import get_session
    # async with get_session() as session:
    #     yield session
    pass


# ============================================================================
# Dependency: Verify Tenant & Permissions
# ============================================================================

async def verify_tenant(
    authorization: str = Header(...),
) -> dict:
    """Verify tenant from JWT token."""
    try:
        tenant_id = extract_tenant_from_token(authorization)
        return {"tenant_id": tenant_id}
    except Exception as e:
        logger.error(f"[App.auth] Token verification failed: {e}")
        raise HTTPException(status_code=401, detail="Unauthorized")


# ============================================================================
# Application Lifecycle
# ============================================================================

# Global workflow graph (compiled once at startup)
workflow_graph = None
workflow_runs = {}  # In-memory run tracking (TODO: persist to DB)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle management."""
    # Startup
    logger.info("[App] Starting KavachX")
    global workflow_graph
    workflow_graph = _build_workflow_graph()
    logger.info("[App] Workflow graph built")
    logger.info("[App] CORS origins: %s", settings.cors_origins or "(none configured)")
    if settings.auth_required:
        logger.info("[App] Auth: session token required")
    else:
        logger.warning(
            "[App] Auth: AUTH_REQUIRED=false — dashboard endpoints accept a `role` "
            "parameter. Never run this way outside local development."
        )

    yield

    # Shutdown
    logger.info("[App] Shutting down KavachX")


# ============================================================================
# Create FastAPI App
# ============================================================================

app = FastAPI(
    title="KavachX",
    description="Multi-tenant SaaS for GitHub vulnerability discovery and automated patching",
    version="0.1.0",
    lifespan=lifespan,
)


# ============================================================================
# CORS — the browser calls this API cross-origin from the Vite dev server
# ============================================================================

# Origins come from CORS_ALLOW_ORIGINS in backend/.env (comma separated).
# Credentials are disabled automatically if the list contains "*", because
# browsers reject wildcard + credentials.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=settings.allow_credentials,
    allow_methods=settings.cors_methods,
    allow_headers=settings.cors_headers,
    # The frontend downloads CHANGES.md / REMAINING.md and reads the filename.
    expose_headers=["Content-Disposition"],
    max_age=3600,
)


# ============================================================================
# Routers
# ============================================================================

app.include_router(auth_routes.router, prefix="/auth")
app.include_router(dashboard_routes.router, prefix="/api")


# ============================================================================
# Health Check
# ============================================================================

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "kavachx",
        "version": "0.1.0",
        "auth_required": settings.auth_required,
        "cors_allow_origins": settings.cors_origins,
    }


# ============================================================================
# Discovery Endpoints
# ============================================================================

@app.post("/api/v1/discover")
async def start_discovery(
    request: DiscoverRequest,
    tenant: dict = Depends(verify_tenant),
) -> dict:
    """
    Start patch discovery for specified channels.

    Returns workflow run ID for status tracking.
    """
    run_id = str(uuid4())
    tenant_id = tenant.get("tenant_id")

    logger.info(f"[App.discover] Starting discovery: run={run_id}, tenant={tenant_id}, channels={len(request.channels)}")

    # Initialize workflow state
    state = initial_state(
        run_id,
        tenant_id,
        {"kind": "repo", "url": "", "commit_sha": "", "adapter": "A"},
    )
    state["channels"] = request.channels
    state["priority"] = request.priority
    state["workflow_started"] = datetime.now(timezone.utc)

    # Store run
    workflow_runs[run_id] = {
        "tenant_id": tenant_id,
        "state": state,
        "status": "running",
    }

    # TODO: Execute workflow asynchronously
    # asyncio.create_task(_execute_workflow(run_id, state))

    return {
        "run_id": run_id,
        "tenant_id": tenant_id,
        "status": "started",
        "phase": "discovery",
    }


@app.get("/api/v1/status/{run_id}")
async def get_status(
    run_id: str,
    tenant: dict = Depends(verify_tenant),
) -> WorkflowStatusResponse:
    """Get status of a workflow run."""
    tenant_id = tenant.get("tenant_id")

    # Verify ownership
    run_info = workflow_runs.get(run_id)
    if not run_info:
        raise HTTPException(status_code=404, detail="Run not found")

    if run_info.get("tenant_id") != tenant_id:
        raise HTTPException(status_code=403, detail="Forbidden")

    state = run_info.get("state", {})

    return WorkflowStatusResponse(
        run_id=run_id,
        phase=state.get("phase", "unknown"),
        status=run_info.get("status", "unknown"),
        progress={
            "discovery": bool(state.get("discovery_batch")),
            "staging": bool(state.get("staged_patches")),
            "synthesis": bool(state.get("synthesis")),
            "verification": bool(state.get("verifications")),
            "publishing": bool(state.get("published_patches")),
        },
        patches_discovered=len(state.get("patch_candidates", [])),
        patches_staged=len(state.get("staged_patches", [])),
        patches_verified=len(state.get("verifications", [])),
        patches_published=len(state.get("published_patches", [])),
    )


# ============================================================================
# Approval & Control Endpoints
# ============================================================================

@app.post("/api/v1/approve/{patch_id}")
async def approve_patch(
    patch_id: str,
    request: ApprovalRequest,
    tenant: dict = Depends(verify_tenant),
) -> dict:
    """
    Approve or reject a patch for publishing.

    Manual approval gate for high-risk patches.
    """
    tenant_id = tenant.get("tenant_id")

    logger.info(
        f"[App.approve] Patch: {patch_id}, approved={request.approved}, "
        f"tenant={tenant_id}"
    )

    # TODO: Find patch in database and update approval status
    # await db.set_patch_approval(patch_id, tenant_id, request.approved, request.reviewer_notes)

    return {
        "patch_id": patch_id,
        "approved": request.approved,
        "reviewer_notes": request.reviewer_notes,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ============================================================================
# Webhook Endpoints
# ============================================================================

@app.post("/webhooks/github/push")
async def github_push_webhook(
    payload: dict,
) -> dict:
    """
    Handle GitHub push events.

    Triggered when code is pushed to monitored repositories.
    Initiates discovery scan for that repository.
    """
    logger.info("[App.webhook] Received GitHub push event")

    repo = payload.get("repository", {})
    branch = payload.get("ref", "").split("/")[-1]
    org = repo.get("owner", {}).get("login", "unknown")
    repo_name = repo.get("name", "unknown")

    channel = f"{org}/{repo_name}#{branch}"

    logger.info(f"[App.webhook] Scanning channel: {channel}")

    # TODO: Initiate discovery for this channel
    # asyncio.create_task(_scan_channel(channel))

    return {"status": "queued", "channel": channel}


@app.post("/webhooks/github/pull_request")
async def github_pr_webhook(
    payload: dict,
) -> dict:
    """
    Handle GitHub pull request events.

    Updates PR status tracking for published patches.
    """
    logger.info("[App.webhook] Received GitHub PR event")

    action = payload.get("action")
    pr = payload.get("pull_request", {})

    logger.info(f"[App.webhook] PR action: {action}, number: {pr.get('number')}")

    # TODO: Track PR status changes
    # await db.track_pr_event(pr_number, action)

    return {"status": "tracked", "action": action}


# ============================================================================
# Report Endpoints
# ============================================================================

@app.get("/api/v1/report/{run_id}")
async def get_report(
    run_id: str,
    tenant: dict = Depends(verify_tenant),
) -> dict:
    """Get synthesis report for a run."""
    tenant_id = tenant.get("tenant_id")

    run_info = workflow_runs.get(run_id)
    if not run_info:
        raise HTTPException(status_code=404, detail="Run not found")

    if run_info.get("tenant_id") != tenant_id:
        raise HTTPException(status_code=403, detail="Forbidden")

    state = run_info.get("state", {})
    synthesis = state.get("synthesis", {})

    return {
        "run_id": run_id,
        "synthesis": synthesis,
    }


# ============================================================================
# Admin Endpoints
# ============================================================================

@app.get("/api/v1/admin/runs")
async def list_runs(
    tenant: dict = Depends(verify_tenant),
) -> dict:
    """List all runs for a tenant (admin only)."""
    tenant_id = tenant.get("tenant_id")

    # TODO: Check admin role
    # await check_permission(tenant_id, "admin")

    tenant_runs = [
        (run_id, info)
        for run_id, info in workflow_runs.items()
        if info.get("tenant_id") == tenant_id
    ]

    return {
        "total_runs": len(tenant_runs),
        "runs": [
            {
                "run_id": run_id,
                "status": info.get("status"),
                "phase": info.get("state", {}).get("phase"),
            }
            for run_id, info in tenant_runs
        ],
    }


# ============================================================================
# Error Handlers
# ============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """
    Handle HTTP exceptions.

    `detail` is preserved verbatim — the frontend surfaces it directly (e.g.
    the publish policy-gate rejection message).
    """
    detail = exc.detail
    message = detail if isinstance(detail, str) else detail.get("message", str(detail))
    error = "http_error" if isinstance(detail, str) else detail.get("error", "http_error")

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": error,
            "message": message,
            "detail": detail,
            "status_code": exc.status_code,
        },
        headers=getattr(exc, "headers", None),
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Handle general exceptions."""
    logger.exception(f"[App] Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_error",
            "message": "Internal server error",
            "detail": "Internal server error",
            "status_code": 500,
        },
    )


# ============================================================================
# Async Workflow Execution (TODO: Implement)
# ============================================================================

async def _execute_workflow(run_id: str, state: KavachState):
    """
    Execute the workflow graph for a run.

    TODO: Implement async execution with:
    - workflow_graph.astream(state)
    - Update workflow_runs with state changes
    - Persist state to database
    - Handle errors and recovery
    """
    logger.info(f"[App.execute] Starting workflow: {run_id}")

    # TODO: Execute graph
    # async for output in workflow_graph.astream(state):
    #     workflow_runs[run_id]["state"] = output
    #     await persist_state_to_db(run_id, output)

    logger.info(f"[App.execute] Workflow completed: {run_id}")


# ============================================================================
# Main
# ============================================================================

if __name__ == "__main__":
    import uvicorn

    logger.info("[App] Starting KavachX server")

    uvicorn.run(
        "app:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.api_reload,
        log_level=settings.log_level,
    )
