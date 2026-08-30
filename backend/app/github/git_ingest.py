"""Authenticated ``git clone`` ingestion for token-verified GitHub repositories.

This is the fetch path for the ``github`` provider — a repository the configured fine-grained
token has **push** access to, confirmed at attach time, and therefore the only kind of repository
KavachX can later open a pull request against.

It is a real clone, not a tarball. The `github_public` path downloads an archive because that is
cheaper and easier to bound for source nobody controls; here the run is against a repository the
operator owns, and a clone gives a true commit SHA and a working copy with history, which is what
the publisher's base commit and the console's provenance both refer to.

Where it runs, and where it does not
------------------------------------
Outside the sandbox, always — like every other fetch. The sandbox receives a pinned, hashed,
immutable tree and never reaches the network, so it can never fetch its own source. Nothing in
this module is importable from the analysis path.

How the credential is handled
-----------------------------
* It is **never put in the remote URL**. A URL-embedded token ends up in ``.git/config``, in the
  reflog, and in any error message that echoes the remote.
* It is **never passed on the command line**. Process arguments are readable by other processes on
  the host.
* It is passed through ``GIT_CONFIG_*`` environment variables as an ``http.extraHeader``, which
  keeps it out of both, and applies only to this one invocation.
* Every error string is scrubbed before it is logged or surfaced.

What the clone is not allowed to do
-----------------------------------
* **No submodules.** ``--no-recurse-submodules`` is explicit: a submodule is a URL controlled by
  the repository under analysis, and following it would fetch an arbitrary third-party tree into
  the pinned artifact.
* **No symlinks survive.** They are removed after checkout, not followed. This matters because
  :func:`app.sandbox.workspace.materialise` copies with ``symlinks=False``, which *dereferences* a
  link — so a repository containing ``config -> /etc/passwd`` would otherwise have that file's
  contents copied into the pinned tree. The tarball path skips links at extraction; this path
  strips them after checkout, so both ingest paths give the same guarantee.
* **No unbounded size.** Total bytes and file count are capped, mirroring the archive path's
  ceilings, and the check runs before anything is handed on.
* **No credential prompt.** ``GIT_TERMINAL_PROMPT=0`` means a repository the token cannot read
  fails immediately instead of hanging a run on an invisible password prompt.
"""

from __future__ import annotations

import asyncio
import base64
import os
import re
import shutil
import stat
import subprocess
import time
from pathlib import Path
from typing import Any

from app.config import settings
from app.core.errors import KavachError
from app.core.logging import get_logger
from app.github.public_ingest import RepositoryTooLarge, parse_repo_reference

logger = get_logger(__name__)

#: Ceilings, matching the archive ingest path so the two cannot drift into different promises.
MAX_CLONE_BYTES = 400 * 1024 * 1024
MAX_CLONE_FILES = 40_000
CLONE_TIMEOUT_SECONDS = 600

_FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
#: Commit metadata, read back in one call. Unit separator between fields, so a commit subject
#: containing any ordinary punctuation cannot break the parse.
_LOG_FORMAT = "%H%x1f%an%x1f%aI%x1f%s"


class CloneFailed(KavachError):
    status_code = 502
    code = "REPOSITORY_CLONE_FAILED"
    message = "The repository could not be cloned."


def _scrub(text: str, token: str) -> str:
    """Remove the credential from anything about to be logged or returned."""
    cleaned = text.strip()
    if token:
        cleaned = cleaned.replace(token, "***")
        # The header value is base64 of "x-access-token:<token>"; scrub that form too.
        encoded = base64.b64encode(f"x-access-token:{token}".encode()).decode("ascii")
        cleaned = cleaned.replace(encoded, "***")
    return cleaned


def _git_env(token: str) -> dict[str, str]:
    """Environment for one git invocation, carrying the credential out of sight.

    ``GIT_CONFIG_COUNT``/``KEY``/``VALUE`` (git 2.31+) injects configuration without a file and
    without an argument, so the header reaches git but reaches neither ``ps`` nor ``.git/config``.
    """
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    # Windows' credential manager will otherwise pop a dialog on a private repository and hang the
    # run until the clone times out.
    env["GCM_INTERACTIVE"] = "Never"
    env["GIT_LFS_SKIP_SMUDGE"] = "1"
    if token:
        header = base64.b64encode(f"x-access-token:{token}".encode()).decode("ascii")
        env["GIT_CONFIG_COUNT"] = "1"
        env["GIT_CONFIG_KEY_0"] = "http.extraHeader"
        env["GIT_CONFIG_VALUE_0"] = f"Authorization: Basic {header}"
    return env


def _run_git(args: list[str], *, cwd: Path | None, token: str, what: str) -> str:
    """Run one git command, or raise :class:`CloneFailed` with a scrubbed message."""
    try:
        # Fixed argv, no shell, and the only interpolated value is a validated owner/repo.
        completed = subprocess.run(
            ["git", *args],
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=_git_env(token),
            timeout=CLONE_TIMEOUT_SECONDS,
            shell=False,
        )
    except FileNotFoundError as exc:
        raise CloneFailed(
            "git is not installed on the KavachX host. A token-verified repository is ingested "
            "by cloning it, so git is required for this provider.",
            code="GIT_NOT_AVAILABLE",
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise CloneFailed(
            f"{what} exceeded the {CLONE_TIMEOUT_SECONDS}s ingest timeout.",
            code="REPOSITORY_CLONE_TIMEOUT",
        ) from exc

    if completed.returncode != 0:
        detail = _scrub(f"{completed.stderr}\n{completed.stdout}", token)[:600]
        raise CloneFailed(f"{what} failed: {detail}")
    return completed.stdout.rstrip("\n")


def _strip_symlinks(root: Path) -> list[dict[str, str]]:
    """Remove every symlink in the checkout. Returns what was removed, for the evidence record."""
    removed: list[dict[str, str]] = []
    for path in sorted(root.rglob("*")):
        if ".git" in path.relative_to(root).parts:
            continue
        if not path.is_symlink():
            continue
        try:
            target = os.readlink(path)
        except OSError:
            target = "unreadable"
        try:
            path.unlink()
        except OSError:
            # A directory symlink on Windows is removed with rmdir, not unlink.
            try:
                os.rmdir(path)
            except OSError:
                logger.warning("github.symlink_not_removed", path=str(path)[:200])
                continue
        if len(removed) < 50:
            removed.append({"path": str(path.relative_to(root))[:200], "target": str(target)[:200]})
    return removed


def _measure(root: Path) -> tuple[int, int]:
    """Files and bytes in the checkout, excluding ``.git``. Raises if either ceiling is crossed."""
    files = 0
    total = 0
    for path in root.rglob("*"):
        if ".git" in path.relative_to(root).parts:
            continue
        if not path.is_file() or path.is_symlink():
            continue
        files += 1
        if files > MAX_CLONE_FILES:
            raise RepositoryTooLarge(f"The repository contains more than {MAX_CLONE_FILES} files.")
        total += path.stat().st_size
        if total > MAX_CLONE_BYTES:
            raise RepositoryTooLarge(
                f"The repository exceeds the {MAX_CLONE_BYTES // (1024 * 1024)} MB ingest limit."
            )
    return files, total


def _force_rmtree(path: Path) -> None:
    # Signature is fixed by shutil.rmtree's onerror contract.
    def _clear_readonly(func, target, _exc):
        try:
            os.chmod(target, stat.S_IWRITE)
            func(target)
        except OSError:
            pass

    if path.exists():
        shutil.rmtree(path, onerror=_clear_readonly)


def _clone_sync(*, full_name: str, revision: str, destination: Path, token: str) -> dict[str, Any]:
    started = time.perf_counter()
    ref = parse_repo_reference(full_name)
    remote = f"{settings.github_clone_base.rstrip('/')}/{ref.owner}/{ref.name}.git"

    _force_rmtree(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)

    revision = (revision or "").strip()
    pinned_sha = bool(_FULL_SHA.match(revision.lower()))

    # A shallow, single-branch clone: the analysis needs the tree at one commit, not the history,
    # and the smaller fetch is the difference between a demo that runs and one that waits.
    args = [
        "clone",
        "--quiet",
        "--depth",
        "1",
        "--single-branch",
        "--no-tags",
        "--no-recurse-submodules",
    ]
    if revision and not pinned_sha:
        args += ["--branch", revision]
    args += [remote, str(destination)]
    _run_git(args, cwd=None, token=token, what=f"cloning {ref.full_name}")

    if pinned_sha:
        # `main` moves and a SHA does not, so an explicitly pinned commit is fetched and checked
        # out rather than trusted to still be the branch head.
        _run_git(
            ["fetch", "--quiet", "--depth", "1", "origin", revision],
            cwd=destination,
            token=token,
            what=f"fetching commit {revision[:12]}",
        )
        _run_git(
            ["checkout", "--quiet", "--detach", "FETCH_HEAD"],
            cwd=destination,
            token=token,
            what=f"checking out commit {revision[:12]}",
        )

    raw = _run_git(
        ["log", "-1", f"--format={_LOG_FORMAT}"],
        cwd=destination,
        token=token,
        what="reading the checked-out commit",
    )
    parts = raw.split("\x1f")
    sha = parts[0] if parts else ""
    if not sha:
        raise CloneFailed(f"The clone of {ref.full_name} produced no commit.")

    branch = _run_git(
        ["rev-parse", "--abbrev-ref", "HEAD"],
        cwd=destination,
        token=token,
        what="reading the branch",
    )
    symlinks = _strip_symlinks(destination)
    files, total_bytes = _measure(destination)

    # The history has served its purpose: the commit is recorded, and the pinned artifact is the
    # tree. Removing .git here keeps it out of the workspace copy and out of the size accounting
    # for anything downstream.
    _force_rmtree(destination / ".git")

    duration_ms = int((time.perf_counter() - started) * 1000)
    logger.info(
        "github.clone_complete",
        repository=ref.full_name,
        commit=sha[:12],
        files=files,
        bytes=total_bytes,
        symlinks_removed=len(symlinks),
        ms=duration_ms,
    )

    return {
        "repository": {
            "method": "github_git_clone",
            "full_name": ref.full_name,
            "remote": remote,
            "note": (
                "Cloned with the configured fine-grained token, outside the sandbox. Submodules "
                "were not followed and symlinks were removed before the tree was pinned."
            ),
        },
        "commit": {
            "sha": sha,
            "author": parts[1] if len(parts) > 1 else "",
            "date": parts[2] if len(parts) > 2 else "",
            "message": parts[3][:500] if len(parts) > 3 else "",
            "html_url": f"https://github.com/{ref.full_name}/commit/{sha}",
        },
        "clone": {
            "branch": branch,
            "requested_revision": revision,
            "pinned_to_commit": pinned_sha,
            "depth": 1,
            "files": files,
            "bytes": total_bytes,
            "symlinks_removed": symlinks,
            "submodules_followed": False,
            "duration_ms": duration_ms,
        },
    }


async def clone_repository(
    *, full_name: str, revision: str, destination: Path, token: str | None = None
) -> dict[str, Any]:
    """Clone ``full_name`` at ``revision`` into ``destination`` and return the fetch evidence.

    ``revision`` may be a branch, a tag, a full commit SHA, or empty for the default branch. The
    call is offloaded to a thread because git is a blocking subprocess and this runs on the same
    event loop that is supervising the run.
    """
    credential = settings.github_token if token is None else token
    if not credential:
        raise CloneFailed(
            "No GITHUB_TOKEN is configured, so a token-verified repository cannot be cloned. "
            "Attach the repository as a public one for analysis-only, or configure a "
            "fine-grained token with access to it.",
            code="GITHUB_NOT_CONFIGURED",
        )
    return await asyncio.to_thread(
        _clone_sync,
        full_name=full_name,
        revision=revision,
        destination=destination,
        token=credential,
    )
