import os
import time
import uuid
import hashlib
import hmac as _hmac

import httpx
import jwt as pyjwt
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kavachx.db.models import Membership, Organisation

router = APIRouter(tags=["auth"])

# ── Config (read from environment) ────────────────────────────────────────────
GITHUB_APP_ID = os.environ.get("GITHUB_APP_ID", "")
GITHUB_APP_PRIVATE_KEY_PATH = os.environ.get("GITHUB_APP_PRIVATE_KEY_PATH", "")
JWT_SECRET = os.environ.get("JWT_SECRET", "change-me")
JWT_EXPIRY = int(os.environ.get("JWT_EXPIRY_SECONDS", "3600"))
GITHUB_APP_INSTALL_URL = f"https://github.com/apps/kavachx/installations/new"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_private_key() -> str:
    with open(GITHUB_APP_PRIVATE_KEY_PATH) as f:
        return f.read()


def _make_app_jwt() -> str:
    """Short-lived JWT signed with the GitHub App private key."""
    now = int(time.time())
    payload = {"iat": now - 60, "exp": now + 600, "iss": GITHUB_APP_ID}
    return pyjwt.encode(payload, _load_private_key(), algorithm="RS256")


async def _get_installation_token(installation_id: int) -> str:
    """Mint a short-lived installation token. Never persisted, never in sandbox."""
    app_jwt = _make_app_jwt()
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"https://api.github.com/app/installations/{installation_id}/access_tokens",
            headers={
                "Authorization": f"Bearer {app_jwt}",
                "Accept": "application/vnd.github+json",
            },
        )
    if resp.status_code != 201:
        raise HTTPException(status_code=502, detail="GitHub token mint failed")
    return resp.json()["token"]


async def _get_installation_info(installation_id: int) -> dict:
    app_jwt = _make_app_jwt()
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"https://api.github.com/app/installations/{installation_id}",
            headers={
                "Authorization": f"Bearer {app_jwt}",
                "Accept": "application/vnd.github+json",
            },
        )
    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail="GitHub installation lookup failed")
    return resp.json()


def _mint_session(user_id: str, tenant_id: str, role: str) -> str:
    payload = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "role": role,
        "exp": int(time.time()) + JWT_EXPIRY,
    }
    return pyjwt.encode(payload, JWT_SECRET, algorithm="HS256")


def _verify_session(token: str) -> dict:
    try:
        return pyjwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except pyjwt.PyJWTError:
        raise HTTPException(status_code=401, detail={"error": "invalid_token"})


# ── Session dependency ─────────────────────────────────────────────────────────

async def current_session(request: Request) -> dict:
    """FastAPI dependency — verifies JWT and populates request.state."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail={"error": "missing_token"})
    claims = _verify_session(auth.removeprefix("Bearer ").strip())
    request.state.user_id = claims["sub"]
    request.state.tenant_id = claims["tenant_id"]
    request.state.role = claims["role"]
    return claims


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/github/install")
async def github_install():
    """Redirect user to GitHub App installation page."""
    return RedirectResponse(url=GITHUB_APP_INSTALL_URL)


@router.get("/github/callback")
async def github_callback(installation_id: int, request: Request):
    """
    GitHub redirects here after the user installs the App.
    1. Verify the installation exists.
    2. Find or create the Organisation row.
    3. Mint a session JWT.
    """
    info = await _get_installation_info(installation_id)
    account = info.get("account", {})
    github_user_id = str(account.get("id", ""))
    github_login = account.get("login", "unknown")

    # Derive a stable tenant_id from the GitHub account id
    tenant_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"github:{github_user_id}"))
    user_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"github-user:{github_user_id}"))

    # TODO: upsert Organisation row via DB session (wired in Step 4 with DB engine)
    # For now, return the session so auth flow is testable end-to-end.

    token = _mint_session(user_id=user_id, tenant_id=tenant_id, role="owner")
    return {"access_token": token, "token_type": "bearer", "tenant_id": tenant_id}


@router.post("/logout")
async def logout(session: dict = Depends(current_session)):
    # JWT is stateless — client discards the token.
    # Audit event will be added once the DB session is wired in Step 4.
    return {"status": "logged_out"}


@router.get("/me")
async def me(session: dict = Depends(current_session)):
    return {
        "user_id": session["sub"],
        "tenant_id": session["tenant_id"],
        "role": session["role"],
    }
