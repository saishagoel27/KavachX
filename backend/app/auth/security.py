"""Password hashing and JWT issuance/verification."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

import bcrypt
import jwt

from app.config import settings
from app.core.errors import TokenExpired, TokenInvalid, ValidationError

TokenType = Literal["access", "refresh"]

_BCRYPT_ROUNDS = 12
#: bcrypt silently truncates at 72 bytes; reject rather than accept a weakened password.
_BCRYPT_MAX_BYTES = 72


def hash_password(password: str) -> str:
    validate_password_strength(password)
    encoded = password.encode("utf-8")
    return bcrypt.hashpw(encoded, bcrypt.gensalt(rounds=_BCRYPT_ROUNDS)).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        encoded = password.encode("utf-8")
        if len(encoded) > _BCRYPT_MAX_BYTES:
            return False
        return bcrypt.checkpw(encoded, password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def validate_password_strength(password: str) -> None:
    if len(password) < settings.password_min_length:
        raise ValidationError(
            f"Password must be at least {settings.password_min_length} characters long.",
            code="PASSWORD_TOO_WEAK",
        )
    if len(password.encode("utf-8")) > _BCRYPT_MAX_BYTES:
        raise ValidationError("Password must not exceed 72 bytes.", code="PASSWORD_TOO_LONG")
    if password.lower() in {"password", "kavachx", "changeme"}:
        raise ValidationError("Password is too common.", code="PASSWORD_TOO_WEAK")


# ---------------------------------------------------------------------------
def _now() -> datetime:
    return datetime.now(timezone.utc)


def create_token(
    *,
    subject: uuid.UUID | str,
    token_type: TokenType,
    tenant_id: uuid.UUID | str | None = None,
    role: str | None = None,
    token_version: int = 0,
    extra: dict[str, Any] | None = None,
    ttl_seconds: int | None = None,
) -> str:
    if ttl_seconds is None:
        ttl_seconds = (
            settings.access_token_ttl_seconds
            if token_type == "access"
            else settings.refresh_token_ttl_seconds
        )
    issued = _now()
    payload: dict[str, Any] = {
        "sub": str(subject),
        "typ": token_type,
        "iat": int(issued.timestamp()),
        "nbf": int(issued.timestamp()),
        "exp": int((issued + timedelta(seconds=ttl_seconds)).timestamp()),
        "jti": uuid.uuid4().hex,
        "tv": token_version,
        "iss": "kavachx",
    }
    if tenant_id is not None:
        payload["tid"] = str(tenant_id)
    if role is not None:
        payload["role"] = role
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str, *, expected_type: TokenType | None = None) -> dict[str, Any]:
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            issuer="kavachx",
            options={"require": ["exp", "sub", "typ"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenExpired() from exc
    except jwt.InvalidTokenError as exc:
        raise TokenInvalid(f"Token rejected: {exc}") from exc

    if expected_type and payload.get("typ") != expected_type:
        raise TokenInvalid(f"Expected a {expected_type} token but received {payload.get('typ')!r}.")
    return payload


def token_ttl_seconds(token_type: TokenType) -> int:
    return (
        settings.access_token_ttl_seconds
        if token_type == "access"
        else settings.refresh_token_ttl_seconds
    )
