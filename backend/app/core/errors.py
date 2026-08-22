"""Structured API errors.

Every failure leaving the API has the shape::

    {"error": {"code": "RUN_NOT_FOUND", "message": "...", "request_id": "..."}}

so the frontend can branch on ``code`` and a support request can be traced by ``request_id``.
"""

from __future__ import annotations

from typing import Any


class KavachError(Exception):
    """Base class for every deliberate application error."""

    status_code: int = 500
    code: str = "INTERNAL_ERROR"
    message: str = "An unexpected error occurred."

    def __init__(
        self,
        message: str | None = None,
        *,
        code: str | None = None,
        status_code: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.message = message or type(self).message
        self.code = code or type(self).code
        self.status_code = status_code or type(self).status_code
        self.details = details or {}
        super().__init__(self.message)

    def to_payload(self, request_id: str) -> dict[str, Any]:
        error: dict[str, Any] = {
            "code": self.code,
            "message": self.message,
            "request_id": request_id,
        }
        if self.details:
            error["details"] = self.details
        return {"error": error}


# --- 400 -------------------------------------------------------------------
class ValidationError(KavachError):
    status_code = 400
    code = "VALIDATION_ERROR"
    message = "The request payload is invalid."


class BadRequest(KavachError):
    status_code = 400
    code = "BAD_REQUEST"
    message = "The request could not be processed."


# --- 401 / 403 -------------------------------------------------------------
class AuthenticationError(KavachError):
    status_code = 401
    code = "NOT_AUTHENTICATED"
    message = "Authentication is required."


class InvalidCredentials(AuthenticationError):
    code = "INVALID_CREDENTIALS"
    message = "Incorrect email or password."


class TokenExpired(AuthenticationError):
    code = "TOKEN_EXPIRED"
    message = "The access token has expired."


class TokenInvalid(AuthenticationError):
    code = "TOKEN_INVALID"
    message = "The token could not be verified."


class PermissionDenied(KavachError):
    status_code = 403
    code = "PERMISSION_DENIED"
    message = "You do not have permission to perform this action."


class TenantMismatch(KavachError):
    status_code = 403
    code = "TENANT_MISMATCH"
    message = "The requested resource belongs to another organisation."


class ExploitAccessDenied(PermissionDenied):
    code = "EXPLOIT_ACCESS_DENIED"
    message = "Access to working exploit material requires the finding:read_pov permission."


class RepositoryNotAuthorised(KavachError):
    status_code = 403
    code = "REPOSITORY_NOT_AUTHORISED"
    message = (
        "KavachX has no verified authority over this repository. "
        "Configure a fine-grained token with push access to it first."
    )


# --- 404 -------------------------------------------------------------------
class NotFound(KavachError):
    status_code = 404
    code = "NOT_FOUND"
    message = "The requested resource does not exist."


class RunNotFound(NotFound):
    code = "RUN_NOT_FOUND"
    message = "The requested run does not exist."


class ProjectNotFound(NotFound):
    code = "PROJECT_NOT_FOUND"
    message = "The requested project does not exist."


class RepositoryNotFound(NotFound):
    code = "REPOSITORY_NOT_FOUND"
    message = "The requested repository does not exist."


class FindingNotFound(NotFound):
    code = "FINDING_NOT_FOUND"
    message = "The requested finding does not exist."


class CertificateNotFound(NotFound):
    code = "CERTIFICATE_NOT_FOUND"
    message = "No certificate has been issued for this run yet."


# --- 409 / 422 -------------------------------------------------------------
class Conflict(KavachError):
    status_code = 409
    code = "CONFLICT"
    message = "The resource is in a conflicting state."


class EmailAlreadyRegistered(Conflict):
    code = "EMAIL_ALREADY_REGISTERED"
    message = "An account already exists for this email address."


class RunNotAbortable(Conflict):
    code = "RUN_NOT_ABORTABLE"
    message = "Only a queued or running run can be aborted."


class PublishBlocked(KavachError):
    status_code = 422
    code = "PUBLISH_BLOCKED"
    message = "The publish gate rejected this patch."


class PolicyViolation(KavachError):
    status_code = 422
    code = "POLICY_VIOLATION"
    message = "The patch violates the deterministic publish policy."


# --- 429 / 503 -------------------------------------------------------------
class BudgetExceeded(KavachError):
    status_code = 429
    code = "BUDGET_EXCEEDED"
    message = "The run exceeded its configured resource budget."


class SandboxUnavailable(KavachError):
    status_code = 503
    code = "SANDBOX_UNAVAILABLE"
    message = "The execution sandbox is not available."


class ModelUnavailable(KavachError):
    status_code = 503
    code = "MODEL_UNAVAILABLE"
    message = "The configured model provider is unreachable."


class ModelContractError(KavachError):
    """The model returned something that failed strict schema validation.

    This is never recoverable by trusting the output — it is a hard failure of the
    LLM-proposes/system-validates contract.
    """

    status_code = 502
    code = "MODEL_CONTRACT_ERROR"
    message = "The model response failed schema validation."


class GithubNotConfigured(KavachError):
    status_code = 503
    code = "GITHUB_NOT_CONFIGURED"
    message = "No GITHUB_TOKEN is configured on this deployment."
