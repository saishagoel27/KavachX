"""GitHub client.

Authentication: a **fine-grained personal access token** (``GITHUB_TOKEN``), scoped by the token's
owner to specific repositories and to the minimum permissions KavachX needs — ``Contents:
read/write`` and ``Pull requests: read/write``.

Rules this module exists to enforce:

* The token is read from settings, held in a local attribute, and **never written to the
  database** — there is no column, cache or table for it (see the identity models and the
  ``test_installation_tokens_are_never_persisted`` boundary test).
* Only the publisher process constructs this client. The orchestrator never imports it, so
  analysis code — which executes untrusted target code in a sandbox — has no route to a credential
  even by mistake.
* Authority over a repository is confirmed against the GitHub API (``push`` permission on the
  repo), never taken from the user's claim at face value.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from app.config import settings
from app.core.errors import GithubNotConfigured, KavachError
from app.core.logging import get_logger

logger = get_logger(__name__)

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


class GithubClient:
    def __init__(
        self,
        *,
        token: str | None = None,
        api_base: str | None = None,
    ) -> None:
        self.token = token or settings.github_token
        self.api_base = (api_base or settings.github_api_base).rstrip("/")

        if not self.token:
            raise GithubNotConfigured(
                "GITHUB_TOKEN (a fine-grained personal access token with Contents and "
                "Pull requests read/write) is required to publish to GitHub."
            )

    def _http(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self.api_base,
            timeout=httpx.Timeout(30.0),
            headers={
                # Fine-grained tokens authenticate as a Bearer credential.
                "Authorization": f"Bearer {self.token}",
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
        json_body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        expected: tuple[int, ...] = (200, 201),
    ) -> Any:
        async with self._http() as client:
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
    async def verify_repository_authority(self, full_name: str) -> dict[str, Any]:
        """Confirm the token actually grants write access to ``full_name``.

        This is the gate on publishing. A repository the user typed but the token cannot push to
        is rejected — the user's claim of authority is never taken at face value.
        """
        try:
            repo = await self._request("GET", f"/repos/{full_name}", expected=(200,))
        except GithubApiError as exc:
            return {
                "authorised": False,
                "reason": (
                    f"The configured GITHUB_TOKEN cannot access {full_name} "
                    f"({exc.details.get('status', 'error') if exc.details else 'error'}). "
                    "Grant the token access to that repository and retry."
                ),
            }

        permissions = repo.get("permissions") or {}
        if not permissions.get("push", False):
            return {
                "authorised": False,
                "reason": (
                    f"The configured GITHUB_TOKEN can read {full_name} but does not have write "
                    "(push) access. A fine-grained token needs Contents: read/write and "
                    "Pull requests: read/write."
                ),
                "repository": {
                    "full_name": repo.get("full_name"),
                    "permissions": permissions,
                },
            }
        return {
            "authorised": True,
            "reason": f"The configured GITHUB_TOKEN has push access to {full_name}.",
            "repository": {
                "full_name": repo.get("full_name"),
                "id": repo.get("id"),
                "default_branch": repo.get("default_branch", "main"),
                "private": repo.get("private", True),
                "permissions": permissions,
            },
        }

    # ------------------------------------------------------------------
    async def get_ref_sha(self, repo: RepositoryRef, ref: str) -> str:
        data = await self._request("GET", f"/repos/{repo.full_name}/git/ref/heads/{ref}")
        return str((data.get("object") or {}).get("sha", ""))

    async def get_commit(self, repo: RepositoryRef, sha: str) -> dict[str, Any]:
        return await self._request("GET", f"/repos/{repo.full_name}/commits/{sha}")

    async def create_branch(
        self, repo: RepositoryRef, *, branch: str, from_sha: str
    ) -> dict[str, Any]:
        return await self._request(
            "POST",
            f"/repos/{repo.full_name}/git/refs",
            json_body={"ref": f"refs/heads/{branch}", "sha": from_sha},
            expected=(201,),
        )

    async def get_file(self, repo: RepositoryRef, path: str, ref: str) -> dict[str, Any]:
        return await self._request(
            "GET",
            f"/repos/{repo.full_name}/contents/{path}",
            params={"ref": ref},
        )

    async def put_file(
        self,
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
            json_body=body,
            expected=(200, 201),
        )

    async def create_pull_request(
        self,
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
        self, repo: RepositoryRef, *, issue_number: int, labels: list[str]
    ) -> Any:
        return await self._request(
            "POST",
            f"/repos/{repo.full_name}/issues/{issue_number}/labels",
            json_body={"labels": labels},
            expected=(200, 201),
        )


def parse_full_name(full_name: str) -> RepositoryRef:
    owner, _, name = full_name.partition("/")
    if not owner or not name:
        raise GithubApiError(f"{full_name!r} is not a valid owner/name repository reference.")
    return RepositoryRef(owner=owner, name=name)


def github_available() -> bool:
    return settings.github_configured
