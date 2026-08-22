"""Public GitHub repository ingestion.

Fetches published source for **analysis only**. No credential is used and none is needed: the
GitHub REST API and codeload both serve public repositories unauthenticated. A repository ingested
this way is marked ``github_public`` and can never reach the Publisher, because there is no
installation behind it.

The fetch happens **outside the sandbox**, as the architecture requires — the sandbox receives a
pinned, hashed, immutable tree and never reaches the network itself. There is no ``git clone``
anywhere in this path; a tarball at a resolved commit SHA is both cheaper and easier to bound.

Extraction is the security-sensitive part of this module, so it is deliberately paranoid:

* every member path is resolved and required to stay inside the destination (zip-slip);
* symlinks and hard links are **skipped**, not followed — a link pointing at ``/etc/passwd`` inside
  an archive is a real technique;
* device nodes, FIFOs and anything that is not a regular file or directory are skipped;
* total uncompressed size and member count are capped, so a compression bomb fails with a clear
  error rather than filling the disk.
"""

from __future__ import annotations

import asyncio
import io
import json
import re
import shutil
import tarfile
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from app.config import settings
from app.core.errors import BadRequest, KavachError
from app.core.logging import get_logger

logger = get_logger(__name__)

CODELOAD_BASE = "https://codeload.github.com"
USER_AGENT = "KavachX/1.0 (defensive security research)"

#: Ingest ceilings. A public repository is untrusted input long before its code runs.
MAX_ARCHIVE_BYTES = 120 * 1024 * 1024
MAX_EXTRACTED_BYTES = 400 * 1024 * 1024
MAX_MEMBERS = 40_000
FETCH_TIMEOUT_SECONDS = 120

_OWNER_REPO = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?$")


class RepositoryNotPublic(KavachError):
    status_code = 403
    code = "REPOSITORY_NOT_PUBLIC"
    message = (
        "That repository is not publicly readable. Configure a fine-grained token with access to "
        "it to analyse a private repository."
    )


class RepositoryTooLarge(KavachError):
    status_code = 413
    code = "REPOSITORY_TOO_LARGE"
    message = "The repository exceeds the ingest size limit."


class RepositoryFetchFailed(KavachError):
    status_code = 502
    code = "REPOSITORY_FETCH_FAILED"
    message = "The repository could not be fetched from GitHub."


@dataclass(slots=True)
class PublicRepoRef:
    owner: str
    name: str

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"


@dataclass
class PublicRepoInfo:
    owner: str
    name: str
    default_branch: str
    repo_id: int | None = None
    description: str = ""
    language: str = ""
    size_kb: int = 0
    archived: bool = False
    fork: bool = False
    license_name: str = ""
    stars: int = 0
    html_url: str = ""
    languages: dict[str, int] = field(default_factory=dict)

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"

    def as_evidence(self) -> dict[str, Any]:
        return {
            "method": "github_public",
            "full_name": self.full_name,
            "repository_id": self.repo_id,
            "default_branch": self.default_branch,
            "visibility": "public",
            "archived": self.archived,
            "fork": self.fork,
            "license": self.license_name,
            "stars": self.stars,
            "html_url": self.html_url,
            "note": (
                "Publicly readable source, ingested unauthenticated for analysis only. KavachX "
                "holds no credential for this repository and cannot publish to it."
            ),
        }


# ---------------------------------------------------------------------------
def parse_repo_reference(raw: str) -> PublicRepoRef:
    """Accept the forms a person actually pastes.

    ``https://github.com/owner/repo``, with or without ``.git``, ``/tree/main``, a trailing slash,
    an ``@`` prefix, or just ``owner/repo``.
    """
    value = (raw or "").strip()
    if not value:
        raise BadRequest("Enter a repository.", code="REPOSITORY_REQUIRED")

    value = value.removeprefix("@")
    value = re.sub(r"^git\+", "", value)
    value = re.sub(r"^(https?://|git://|ssh://)?(www\.)?", "", value)
    value = re.sub(r"^git@github\.com:", "", value)
    value = re.sub(r"^github\.com/", "", value)
    value = value.removesuffix(".git").strip("/")

    parts = [p for p in value.split("/") if p]
    if len(parts) < 2:
        raise BadRequest(
            f"{raw!r} is not a GitHub repository. Use https://github.com/owner/repo or owner/repo.",
            code="REPOSITORY_REFERENCE_INVALID",
        )

    owner, name = parts[0], parts[1]
    if not _OWNER_REPO.match(owner) or not _OWNER_REPO.match(name):
        raise BadRequest(
            f"{owner}/{name} is not a valid GitHub owner/repository pair.",
            code="REPOSITORY_REFERENCE_INVALID",
        )
    return PublicRepoRef(owner=owner, name=name)


def _client() -> httpx.AsyncClient:
    # No Authorization header, deliberately. This path must work — and be seen to work — without
    # any credential at all.
    return httpx.AsyncClient(
        timeout=httpx.Timeout(float(FETCH_TIMEOUT_SECONDS)),
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": USER_AGENT,
        },
        follow_redirects=True,
    )


#: Upstream statuses that mean "GitHub had a bad moment", not "your request was wrong".
#:
#: 429 belongs here even though it is a 4xx. An earlier version of this module excluded every 4xx on
#: the reasoning that "a 4xx is an answer, not a failure" — true of 403 and 404, wrong of 429, which
#: is *defined* as "try again later" and carries ``Retry-After`` saying when. codeload throttles
#: tarball downloads separately from the REST API's hourly budget, and re-fetching the same commit
#: repeatedly is enough to trip it; without 429 here, that surfaced as a hard NODE_FAILED at ingest.
_TRANSIENT_STATUSES = frozenset({429, 500, 502, 503, 504})
_MAX_ATTEMPTS = 3
_RETRY_BACKOFF_SECONDS = (0.75, 2.0)
#: A throttle needs a real pause, not the flake backoff — and a server-supplied Retry-After is
#: capped so a generous value cannot stall a run past its wall-clock budget.
_THROTTLE_BACKOFF_SECONDS = (3.0, 8.0)
_MAX_RETRY_AFTER_SECONDS = 30.0


def _retry_delay(response: httpx.Response, attempt: int) -> float:
    """How long to wait before retrying, honouring ``Retry-After`` when the server sends one."""
    table = _THROTTLE_BACKOFF_SECONDS if response.status_code == 429 else _RETRY_BACKOFF_SECONDS
    delay = table[min(attempt, len(table) - 1)]

    header = response.headers.get("retry-after", "").strip()
    if header.isdigit():
        # Only ever lengthens the wait, and never past the cap.
        delay = max(delay, min(float(header), _MAX_RETRY_AFTER_SECONDS))
    return delay


def _upstream_message(status: int, doing: str) -> str:
    """Explain a failed GitHub call in terms the operator can act on.

    ``GitHub returned HTTP 504`` alone reads like a KavachX defect and invites debugging that leads
    nowhere. If the status is one we retried, say so and say whose fault it is — the difference
    between "this is broken" and "GitHub is having a moment, try again shortly" is the whole message.
    """
    if status in _TRANSIENT_STATUSES:
        return (
            f"GitHub returned HTTP {status} while {doing}, on all {_MAX_ATTEMPTS} attempts. This is "
            "an upstream fault on GitHub's side, not a problem with the repository or with KavachX "
            "— it is usually brief. Start the run again in a few minutes."
        )
    return f"GitHub returned HTTP {status} while {doing}."


async def _get_with_retry(client: httpx.AsyncClient, url: str, *, what: str) -> httpx.Response:
    """GET an idempotent GitHub endpoint, retrying only genuine upstream flakes.

    Observed in practice: ``GET /repos/{owner}/{repo}`` returned 504 while
    ``/commits/{ref}`` on the same repository returned 200 and the rate-limit budget was untouched.
    A single blip on GitHub's side was killing the whole run at ingest.

    Deliberately narrow. 403 (the hourly anonymous budget is spent — only time fixes that), 404
    (absent or private) and every other 4xx are answers, not failures: retrying them would waste
    what remains of the caller's budget and delay a message they need to see now. 429 is the
    exception, because it means "you are going too fast", not "you asked for the wrong thing".
    """
    last: httpx.Response | None = None
    for attempt in range(_MAX_ATTEMPTS):
        response = await client.get(url)
        if response.status_code not in _TRANSIENT_STATUSES:
            return response
        last = response
        if attempt < _MAX_ATTEMPTS - 1:
            delay = _retry_delay(response, attempt)
            logger.warning(
                "github.public.transient_upstream",
                what=what,
                status=response.status_code,
                throttled=response.status_code == 429,
                attempt=attempt + 1,
                retry_in_seconds=delay,
            )
            await asyncio.sleep(delay)
    assert last is not None  # the loop runs at least once
    return last


async def resolve_repository(ref: PublicRepoRef) -> PublicRepoInfo:
    """Confirm the repository exists, is public, and read its metadata."""
    api = settings.github_api_base.rstrip("/")
    async with _client() as client:
        try:
            response = await _get_with_retry(
                client, f"{api}/repos/{ref.owner}/{ref.name}", what="repository metadata"
            )
        except httpx.HTTPError as exc:
            raise RepositoryFetchFailed(f"Could not reach GitHub: {exc}") from exc

        if response.status_code == 404:
            raise RepositoryNotPublic(
                f"{ref.full_name} was not found, or is not publicly readable."
            )
        if response.status_code == 403 and "rate limit" in response.text.lower():
            raise RepositoryFetchFailed(
                "GitHub's unauthenticated rate limit was reached. Wait a few minutes, or "
                "configure a fine-grained token for authenticated access.",
                code="GITHUB_RATE_LIMITED",
            )
        if response.status_code >= 400:
            raise RepositoryFetchFailed(
                _upstream_message(response.status_code, f"reading {ref.full_name}"),
                details={"status": response.status_code, "body": response.text[:300]},
            )

        data = response.json()
        # An unauthenticated 200 already implies public, but assert it rather than infer it.
        if data.get("private", False) or data.get("visibility") not in (None, "public"):
            raise RepositoryNotPublic()

        languages: dict[str, int] = {}
        try:
            language_response = await client.get(f"{api}/repos/{ref.owner}/{ref.name}/languages")
            if language_response.status_code < 400:
                languages = {str(k): int(v) for k, v in language_response.json().items()}
        except httpx.HTTPError:
            pass

    info = PublicRepoInfo(
        owner=str((data.get("owner") or {}).get("login", ref.owner)),
        name=str(data.get("name", ref.name)),
        default_branch=str(data.get("default_branch") or "main"),
        repo_id=data.get("id"),
        description=str(data.get("description") or "")[:1000],
        language=str(data.get("language") or ""),
        size_kb=int(data.get("size") or 0),
        archived=bool(data.get("archived")),
        fork=bool(data.get("fork")),
        license_name=str(((data.get("license") or {}) or {}).get("spdx_id") or ""),
        stars=int(data.get("stargazers_count") or 0),
        html_url=str(data.get("html_url") or f"https://github.com/{ref.full_name}"),
        languages=languages,
    )

    if info.size_kb * 1024 > MAX_ARCHIVE_BYTES:
        raise RepositoryTooLarge(
            f"{info.full_name} is roughly {info.size_kb / 1024:.0f} MB, above the "
            f"{MAX_ARCHIVE_BYTES // (1024 * 1024)} MB ingest limit."
        )

    logger.info(
        "github_public.resolved",
        repository=info.full_name,
        default_branch=info.default_branch,
        size_kb=info.size_kb,
        archived=info.archived,
    )
    return info


async def resolve_commit(ref: PublicRepoRef, revision: str) -> dict[str, Any]:
    """Resolve a branch, tag or partial SHA to a full commit SHA.

    Pinning to a resolved SHA is what makes a run reproducible: ``main`` moves, a SHA does not.
    """
    api = settings.github_api_base.rstrip("/")
    async with _client() as client:
        try:
            response = await _get_with_retry(
                client,
                f"{api}/repos/{ref.owner}/{ref.name}/commits/{revision}",
                what=f"revision {revision!r}",
            )
        except httpx.HTTPError as exc:
            raise RepositoryFetchFailed(f"Could not reach GitHub: {exc}") from exc

    # GitHub answers 404 for an unknown ref and 422 for one it cannot parse as a revision. Both
    # mean the same thing to a caller, and reporting 422 as a fetch failure would send someone
    # hunting for a network problem that does not exist.
    if response.status_code in (404, 422):
        raise BadRequest(
            f"{revision!r} is not a branch, tag or commit in {ref.full_name}.",
            code="REVISION_NOT_FOUND",
        )
    if response.status_code >= 400:
        raise RepositoryFetchFailed(
            _upstream_message(response.status_code, f"resolving {revision!r} in {ref.full_name}"),
            details={"status": response.status_code},
        )

    data = response.json()
    commit = data.get("commit") or {}
    author = (commit.get("author") or {}) if isinstance(commit, dict) else {}
    return {
        "sha": str(data.get("sha", "")),
        "message": str(commit.get("message", ""))[:500],
        "author": str(author.get("name", "")),
        "date": str(author.get("date", "")),
        "html_url": str(data.get("html_url", "")),
    }


# ---------------------------------------------------------------------------
def _is_safe_member(member: tarfile.TarInfo, destination: Path) -> tuple[bool, str]:
    """Decide whether one archive member may be extracted."""
    name = member.name.replace("\\", "/")

    if name.startswith("/") or ".." in Path(name).parts:
        return False, "path escapes the destination"
    if member.issym() or member.islnk():
        # Links in an archive are a real traversal technique. Skip rather than resolve.
        return False, "link member"
    if member.ischr() or member.isblk() or member.isfifo() or member.isdev():
        return False, "special file"
    if not (member.isfile() or member.isdir()):
        return False, "not a regular file or directory"

    target = (destination / name).resolve()
    if not str(target).startswith(str(destination.resolve())):
        return False, "resolved path escapes the destination"
    return True, ""


def _safe_extract(archive: tarfile.TarFile, destination: Path) -> dict[str, Any]:
    """Extract with traversal, link, size and count protection."""
    destination.mkdir(parents=True, exist_ok=True)
    extracted = 0
    total_bytes = 0
    skipped: list[dict[str, str]] = []

    for member in archive:
        if extracted >= MAX_MEMBERS:
            raise RepositoryTooLarge(f"The archive contains more than {MAX_MEMBERS} entries.")
        ok, reason = _is_safe_member(member, destination)
        if not ok:
            if len(skipped) < 50:
                skipped.append({"name": member.name[:200], "reason": reason})
            continue

        total_bytes += max(0, member.size)
        if total_bytes > MAX_EXTRACTED_BYTES:
            raise RepositoryTooLarge(
                f"The archive expands beyond the "
                f"{MAX_EXTRACTED_BYTES // (1024 * 1024)} MB extraction limit."
            )

        try:
            archive.extract(member, path=destination, set_attrs=False)
        except (OSError, tarfile.TarError) as exc:
            # A truncated or malformed archive is untrusted input like any other. Convert it to a
            # clear KavachX error rather than letting a bare OSError surface as a 500.
            raise RepositoryFetchFailed(
                f"The archive is malformed at member {member.name[:120]!r}: {exc}",
                code="REPOSITORY_ARCHIVE_MALFORMED",
            ) from exc
        extracted += 1

    return {"members_extracted": extracted, "bytes": total_bytes, "skipped": skipped}


#: Keep the cache bounded. Entries are whole extracted repositories, so a handful is plenty for the
#: pattern this exists to serve: re-running the same target while iterating.
MAX_CACHE_ENTRIES = 12


def _cache_key(ref: PublicRepoRef, sha: str) -> str:
    return f"{ref.owner}-{ref.name}-{sha}".replace("/", "-")


def _copy_tree(source: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for item in source.iterdir():
        target = destination / item.name
        if item.is_dir():
            shutil.copytree(item, target, dirs_exist_ok=True, symlinks=False)
        else:
            shutil.copy2(item, target)


def _prune_cache(keep: Path) -> None:
    """Drop the least-recently-used entries beyond the cap. Never touches ``keep``."""
    try:
        entries = [p for p in settings.source_cache_root.iterdir() if p.is_dir()]
    except OSError:
        return
    if len(entries) <= MAX_CACHE_ENTRIES:
        return
    entries.sort(key=lambda p: p.stat().st_mtime)
    for stale in entries[: len(entries) - MAX_CACHE_ENTRIES]:
        if stale != keep:
            shutil.rmtree(stale, ignore_errors=True)


def _publish_to_cache(source_root: Path, cached: Path, stats: dict[str, Any]) -> None:
    """Fill the cache entry, tolerating a concurrent run that got there first.

    Built under a temporary name and renamed into place, so a reader can never observe a partially
    copied tree. The completion marker is written last for the same reason: its presence is the only
    thing that makes an entry usable, so an interrupted publish simply looks like a miss.
    """
    if cached.exists():
        return
    staging_cache = cached.with_name(cached.name + f".partial-{uuid.uuid4().hex[:8]}")
    try:
        _copy_tree(source_root, staging_cache)
        (staging_cache / ".kavachx-complete.json").write_text(json.dumps(stats), encoding="utf-8")
        try:
            staging_cache.rename(cached)
        except OSError:
            # Another run published the same commit while we were copying. Theirs is equally valid
            # — the key is a commit SHA — so drop ours rather than fighting over the directory.
            shutil.rmtree(staging_cache, ignore_errors=True)
            return
        _prune_cache(keep=cached)
    except OSError as exc:
        # A cache is an optimisation. Failing to populate it must never fail the run.
        shutil.rmtree(staging_cache, ignore_errors=True)
        logger.warning("github_public.cache_write_failed", error=str(exc)[:200])


async def download_source(ref: PublicRepoRef, *, sha: str, destination: Path) -> dict[str, Any]:
    """Download and extract the repository at ``sha`` into ``destination``.

    Runs **outside** the sandbox. The extracted tree is what gets pinned and hashed; the sandbox
    never fetches anything itself.

    A previously extracted tree for the same commit is reused rather than re-downloaded. This is
    safe precisely because the key is a commit SHA: the content behind it cannot change, and the
    materialised workspace is re-hashed afterwards regardless. It is also the actual fix for the
    throttling that made this method fail — three runs against one repository used to mean three
    identical multi-megabyte downloads.
    """
    url = f"{CODELOAD_BASE}/{ref.owner}/{ref.name}/tar.gz/{sha}"
    cached = settings.source_cache_root / _cache_key(ref, sha)
    marker = cached / ".kavachx-complete.json"

    if marker.is_file():
        try:
            stats = json.loads(marker.read_text(encoding="utf-8"))
            _copy_tree(cached, destination)
            # Remove the bookkeeping marker from the materialised copy: the analysed tree must be
            # the repository's own content and nothing of ours, or the pinned hash covers our file.
            (destination / marker.name).unlink(missing_ok=True)
            cached.touch()
            logger.info(
                "github_public.cache_hit",
                repository=ref.full_name,
                sha=sha[:12],
                members=stats.get("members_extracted"),
            )
            return {**stats, "sha": sha, "url": url, "from_cache": True}
        except (OSError, ValueError) as exc:
            # A half-written or unreadable cache entry is worthless; discard it and fetch again.
            logger.warning(
                "github_public.cache_unusable",
                repository=ref.full_name,
                sha=sha[:12],
                error=str(exc)[:200],
            )
            shutil.rmtree(cached, ignore_errors=True)

    buffer = io.BytesIO()

    async with _client() as client:
        for attempt in range(_MAX_ATTEMPTS):
            # The buffer is reset per attempt: a transient failure can arrive mid-stream, after
            # chunks have already been written, and resuming on top of a partial body would produce
            # a corrupt archive that only fails later during extraction.
            buffer.seek(0)
            buffer.truncate(0)
            transient = 0
            retry_after = 0.0
            try:
                async with client.stream("GET", url) as response:
                    if response.status_code in _TRANSIENT_STATUSES:
                        transient = response.status_code
                        retry_after = _retry_delay(response, attempt)
                    elif response.status_code >= 400:
                        raise RepositoryFetchFailed(
                            f"codeload returned HTTP {response.status_code} for "
                            f"{ref.full_name}@{sha[:12]}.",
                            details={"status": response.status_code},
                        )
                    else:
                        async for chunk in response.aiter_bytes(chunk_size=1 << 16):
                            buffer.write(chunk)
                            if buffer.tell() > MAX_ARCHIVE_BYTES:
                                raise RepositoryTooLarge(
                                    f"The archive exceeds the "
                                    f"{MAX_ARCHIVE_BYTES // (1024 * 1024)} MB download limit."
                                )
                        break
            except httpx.HTTPError as exc:
                if attempt == _MAX_ATTEMPTS - 1:
                    raise RepositoryFetchFailed(f"Download failed: {exc}") from exc
                retry_after = _RETRY_BACKOFF_SECONDS[min(attempt, len(_RETRY_BACKOFF_SECONDS) - 1)]
                logger.warning(
                    "github.public.download_retry",
                    repository=ref.full_name,
                    error=str(exc)[:200],
                    attempt=attempt + 1,
                )
            else:
                if attempt == _MAX_ATTEMPTS - 1:
                    if transient == 429:
                        raise RepositoryFetchFailed(
                            f"GitHub is throttling downloads of {ref.full_name} (HTTP 429) and did "
                            f"not relent across {_MAX_ATTEMPTS} attempts. This is codeload's own "
                            "limit on archive downloads, separate from the REST API budget — wait a "
                            "few minutes and start the run again. Nothing is wrong with the "
                            "repository.",
                            code="GITHUB_RATE_LIMITED",
                            details={"status": transient},
                        )
                    raise RepositoryFetchFailed(
                        f"codeload returned HTTP {transient} for {ref.full_name}@{sha[:12]} on "
                        f"{_MAX_ATTEMPTS} consecutive attempts.",
                        details={"status": transient},
                    )
                logger.warning(
                    "github.public.download_retry",
                    repository=ref.full_name,
                    status=transient,
                    throttled=transient == 429,
                    attempt=attempt + 1,
                    retry_in_seconds=retry_after,
                )
            await asyncio.sleep(retry_after)

    archive_bytes = buffer.tell()
    buffer.seek(0)

    # GitHub wraps everything in a single `owner-repo-sha/` directory. Extract to a staging area,
    # then lift that one directory up so the destination is the repository root.
    with tempfile.TemporaryDirectory(prefix="kavachx-ingest-") as staging_name:
        staging = Path(staging_name)
        try:
            with tarfile.open(fileobj=buffer, mode="r:gz") as archive:
                stats = _safe_extract(archive, staging)
        except tarfile.TarError as exc:
            raise RepositoryFetchFailed(f"The archive could not be read: {exc}") from exc

        roots = [p for p in staging.iterdir() if p.is_dir()]
        source_root = roots[0] if len(roots) == 1 else staging

        _copy_tree(source_root, destination)
        _publish_to_cache(source_root, cached, {**stats, "archive_bytes": archive_bytes})

    result = {
        "archive_bytes": archive_bytes,
        "sha": sha,
        "url": url,
        "from_cache": False,
        **stats,
    }
    logger.info(
        "github_public.downloaded",
        repository=ref.full_name,
        sha=sha[:12],
        archive_bytes=archive_bytes,
        members=stats["members_extracted"],
        skipped=len(stats["skipped"]),
    )
    return result


async def ingest(*, full_name: str, revision: str, destination: Path) -> dict[str, Any]:
    """Resolve, pin and download a public repository. One call, used by the ingest node."""
    ref = parse_repo_reference(full_name)
    info = await resolve_repository(ref)
    commit = await resolve_commit(ref, revision or info.default_branch)
    if not commit["sha"]:
        raise RepositoryFetchFailed(f"Could not resolve a commit SHA for {ref.full_name}.")

    download = await download_source(ref, sha=commit["sha"], destination=destination)
    return {"repository": info.as_evidence(), "commit": commit, "download": download}
