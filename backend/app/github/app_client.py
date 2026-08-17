"""GitHub App client.

Authentication chain: **App private key → short-lived App JWT → installation access token**.

Rules this module exists to enforce:

* There is **no personal access token path**. Not configurable, not a fallback.
* Installation tokens are minted on demand, held in a local variable, and **never persisted**.
  There is no field, cache or table for them; :meth:`GithubAppClient.installation_token` returns
  one to its caller and keeps nothing.
* The App JWT lives ten minutes at most (GitHub's ceiling) and is regenerated per call rather
  than cached.
* Only the publisher process constructs this client. The orchestrator never imports it, so
  analysis code has no route to a credential even by mistake.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import httpx
import jwt

from app.config import settings
from app.core.errors import GithubNotConfigured, KavachError
from app.core.logging import get_logger

logger = get_logger(__name__)

#: GitHub rejects an App JWT with more than 10 minutes of life.
JWT_TTL_SECONDS = 540
USER_AGENT = "KavachX/1.0"


class GithubApiError(KavachError):
    status_code = 502
    code = "GITHUB_API_ERROR"
    message = "The GitHub API returned an error."


@dataclass(slots=True)
class RepositoryRef:
    owner: str
    name: str
    repo_id: int | None = None
    default_branch: str = "main"
    private: bool = True

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"


class GithubAppClient:
    def __init__(
        self,
        *,
        app_id: str | None = None,
        private_key_pem: str | None = None,
        api_base: str | None = None,
    ) -> None:
        self.app_id = app_id or settings.github_app_id
        self._private_key = private_key_pem or settings.github_private_key_pem()
        self.api_base = (api_base or settings.github_api_base).rstrip("/")

        if not self.app_id or not self._private_key:
            raise GithubNotConfigured(
                "GITHUB_APP_ID and a private key are required. KavachX never uses a personal "
                "access token."
            )

    # ------------------------------------------------------------------
    def _app_jwt(self) -> str:
        """Short-lived App JWT. Generated per call; never cached, never stored."""
        now = int(time.time())
        return jwt.encode(
            {"iat": now - 60, "exp": now + JWT_TTL_SECONDS, "iss": self.app_id},
            self._private_key,
            algorithm="RS256",
        )

    def _client(self, token: str, *, bearer: bool = False) -> httpx.AsyncClient:
        scheme = "Bearer" if bearer else "token"
        return httpx.AsyncClient(
            base_url=self.api_base,
            timeout=httpx.Timeout(30.0),
            headers={
                "Authorization": f"{scheme} {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": USER_AGENT,
            },
        )

    async def _request(
        self,
        method: str,
        path: str,
        *,
        token: str,
        bearer: bool = False,
        json_body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        expected: tuple[int, ...] = (200, 201),
    ) -> Any:
        async with self._client(token, bearer=bearer) as client:
            try:
                response = await client.request(method, path, json=json_body, params=params)
            except httpx.HTTPError as exc:
                raise GithubApiError(f"GitHub request failed: {exc}") from exc

        if response.status_code not in expected:
            raise GithubApiError(
                f"GitHub {method} {path} returned {response.status_code}.",
                details={
                    "status": response.status_code,
                    # The body can echo request content but never a credential we sent.
                    "body": response.text[:400],
                    "path": path,
                },
            )
        if not response.content:
            return {}
        return response.json()

    # ------------------------------------------------------------------
    async def installation_token(
        self, installation_id: int, *, repositories: list[str] | None = None
    ) -> str:
        """Mint an installation access token.

        Returned to the caller and **not stored anywhere**. Scoped to the named repositories when
        given, so a token minted to open one PR cannot touch another repository.
        """
        body: dict[str, Any] = {}
        if repositories:
            body["repositories"] = repositories
        data = await self._request(
            "POST",
            f"/app/installations/{installation_id}/access_tokens",
            token=self._app_jwt(),
            bearer=True,
            json_body=body or None,
            expected=(201,),
        )
        token = str(data.get("token", ""))
        if not token:
            raise GithubApiError("GitHub returned no installation token.")
        logger.info(
            "github.installation_token_minted",
            installation_id=installation_id,
            expires_at=data.get("expires_at"),
            repository_scope=repositories or "installation-wide",
        )
        return token

    async def get_installation(self, installation_id: int) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/app/installations/{installation_id}",
            token=self._app_jwt(),
            bearer=True,
        )

    async def list_installation_repositories(self, installation_id: int) -> list[dict[str, Any]]:
        token = await self.installation_token(installation_id)
        out: list[dict[str, Any]] = []
        page = 1
        while page <= 10:
            data = await self._request(
                "GET",
                "/installation/repositories",
                token=token,
                params={"per_page": 100, "page": page},
            )
            batch = data.get("repositories", [])
            out.extend(batch)
            if len(batch) < 100:
                break
            page += 1
        return out

    async def verify_repository_authority(
        self, installation_id: int, full_name: str
    ) -> dict[str, Any]:
        """Confirm this installation actually grants access to ``full_name``.

        This is the gate on ``run:start``. A repository the user typed but the installation does
        not include is rejected — the user's claim of authority is never taken at face value.
        """
        repositories = await self.list_installation_repositories(installation_id)
        match = next(
            (r for r in repositories if str(r.get("full_name", "")).lower() == full_name.lower()),
            None,
        )
        if match is None:
            return {
                "authorised": False,
                "reason": (
                    f"Installation {installation_id} does not include {full_name}. Grant the "
                    "KavachX GitHub App access to that repository and retry."
                ),
                "available": sorted(str(r.get("full_name", "")) for r in repositories)[:50],
            }
        return {
            "authorised": True,
            "reason": f"Installation {installation_id} includes {full_name}.",
            "repository": {
                "full_name": match.get("full_name"),
                "id": match.get("id"),
                "default_branch": match.get("default_branch", "main"),
                "private": match.get("private", True),
                "permissions": match.get("permissions", {}),
            },
        }

    # ------------------------------------------------------------------
    async def get_ref_sha(self, token: str, repo: RepositoryRef, ref: str) -> str:
        data = await self._request(
            "GET", f"/repos/{repo.full_name}/git/ref/heads/{ref}", token=token
        )
        return str((data.get("object") or {}).get("sha", ""))

    async def get_commit(self, token: str, repo: RepositoryRef, sha: str) -> dict[str, Any]:
        return await self._request("GET", f"/repos/{repo.full_name}/commits/{sha}", token=token)

    async def create_branch(
        self, token: str, repo: RepositoryRef, *, branch: str, from_sha: str
    ) -> dict[str, Any]:
        return await self._request(
            "POST",
            f"/repos/{repo.full_name}/git/refs",
            token=token,
            json_body={"ref": f"refs/heads/{branch}", "sha": from_sha},
            expected=(201,),
        )

    async def get_file(
        self, token: str, repo: RepositoryRef, path: str, ref: str
    ) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/repos/{repo.full_name}/contents/{path}",
            token=token,
            params={"ref": ref},
        )

    async def put_file(
        self,
        token: str,
        repo: RepositoryRef,
        *,
        path: str,
        content_b64: str,
        message: str,
        branch: str,
        sha: str | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "message": message,
            "content": content_b64,
            "branch": branch,
        }
        if sha:
            body["sha"] = sha
        return await self._request(
            "PUT",
            f"/repos/{repo.full_name}/contents/{path}",
            token=token,
            json_body=body,
            expected=(200, 201),
        )

    async def create_pull_request(
        self,
        token: str,
        repo: RepositoryRef,
        *,
        title: str,
        head: str,
        base: str,
        body: str,
        draft: bool = False,
    ) -> dict[str, Any]:
        return await self._request(
            "POST",
            f"/repos/{repo.full_name}/pulls",
            token=token,
            json_body={
                "title": title,
                "head": head,
                "base": base,
                "body": body,
                "draft": draft,
                "maintainer_can_modify": True,
            },
            expected=(201,),
        )

    async def add_labels(
        self, token: str, repo: RepositoryRef, *, issue_number: int, labels: list[str]
    ) -> Any:
        return await self._request(
            "POST",
            f"/repos/{repo.full_name}/issues/{issue_number}/labels",
            token=token,
            json_body={"labels": labels},
            expected=(200, 201),
        )


def parse_full_name(full_name: str) -> RepositoryRef:
    owner, _, name = full_name.partition("/")
    if not owner or not name:
        raise GithubApiError(f"{full_name!r} is not a valid owner/name repository reference.")
    return RepositoryRef(owner=owner, name=name)


def github_available() -> bool:
    return settings.github_app_configured
