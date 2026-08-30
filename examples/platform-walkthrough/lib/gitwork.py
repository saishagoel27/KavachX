"""Real git operations for the walkthrough.

Everything here shells out to ``git``. There is no simulation: the origin is a real bare
repository, the clone is a real clone with a real remote, and the publisher's branch is a real
branch with a real commit that is really pushed to that origin.

Why an origin is built at all: the analysis target ships as a folder inside this repository, and
you cannot clone a subdirectory of a repository. So the walkthrough first imports that folder into
a repository of its own, then clones it — which is what makes the ingest step operate on a working
copy with git history rather than on the checked-out source tree.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

#: Mirrors ``app.sandbox.workspace.IGNORED_DIRS`` — build output and caches are not source, and
#: committing them would put noise in the pinned tree and in every diff the demo shows.
IGNORED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        ".venv",
        "venv",
        "node_modules",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".kavachx",
        "_kavachx",
        ".gitnexus",
        "dist",
        "build",
        ".next",
        "exports",
    }
)
IGNORED_SUFFIXES = frozenset({".pyc", ".pyo", ".so", ".dll", ".dylib", ".o", ".a", ".class"})

AUTHOR_IMPORT = ("KavachX Walkthrough", "walkthrough@kavachx.local")
AUTHOR_PUBLISHER = ("KavachX Publisher", "publisher@kavachx.local")


class GitError(RuntimeError):
    pass


def git(args: list[str], *, cwd: Path | None = None, check: bool = True) -> str:
    """Run one git command and return its stdout."""
    completed = subprocess.run(
        ["git", *args],
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if check and completed.returncode != 0:
        raise GitError(
            f"git {' '.join(args)} failed ({completed.returncode})\n"
            f"{completed.stdout.strip()}\n{completed.stderr.strip()}".strip()
        )
    return completed.stdout.rstrip("\n")


def git_version() -> str:
    try:
        return git(["--version"])
    except (GitError, FileNotFoundError, OSError) as exc:
        raise GitError(f"git is not available on PATH: {exc}") from exc


def _authored(author: tuple[str, str]) -> list[str]:
    name, email = author
    return [
        "-c",
        f"user.name={name}",
        "-c",
        f"user.email={email}",
        "-c",
        "commit.gpgsign=false",
    ]


def force_rmtree(path: Path) -> None:
    """Remove a tree, including the read-only files git leaves inside ``.git`` on Windows."""

    def _clear_readonly(func, target, _exc):
        try:
            os.chmod(target, stat.S_IWRITE)
            func(target)
        except OSError:
            pass

    if path.exists():
        shutil.rmtree(path, onerror=_clear_readonly)


def _ignore(_directory: str, names: list[str]) -> set[str]:
    skip = set()
    for name in names:
        if name in IGNORED_DIRS or Path(name).suffix.lower() in IGNORED_SUFFIXES:
            skip.add(name)
    return skip


def build_origin(*, source: Path, workdir: Path, name: str, branch: str = "main") -> Path:
    """Import ``source`` into a fresh repository and return a bare origin cloned from it.

    The intermediate working repository is deleted; what remains is a bare repository that
    behaves exactly like a remote you would clone from.
    """
    source = source.resolve()
    if not source.is_dir():
        raise GitError(f"the analysis target does not exist at {source}")

    staging = workdir / "origin-import"
    origin = workdir / f"{name}.git"
    force_rmtree(staging)
    force_rmtree(origin)
    staging.mkdir(parents=True, exist_ok=True)

    shutil.copytree(source, staging, ignore=_ignore, dirs_exist_ok=True)

    git(["init", "--quiet"], cwd=staging)
    git(["add", "-A"], cwd=staging)
    git(
        [
            *_authored(AUTHOR_IMPORT),
            "commit",
            "--quiet",
            "-m",
            f"Initial import of {name}",
        ],
        cwd=staging,
    )
    git(["branch", "-M", branch], cwd=staging)
    git(["clone", "--quiet", "--bare", str(staging), str(origin)])
    force_rmtree(staging)
    return origin


def clone(*, origin: Path, destination: Path) -> Path:
    """Clone ``origin`` into ``destination``. The destination must not already exist."""
    force_rmtree(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    git(["clone", "--quiet", str(origin), str(destination)])
    return destination


def head_sha(repo: Path) -> str:
    return git(["rev-parse", "HEAD"], cwd=repo)


def current_branch(repo: Path) -> str:
    return git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=repo)


def remote_url(repo: Path) -> str:
    return git(["remote", "get-url", "origin"], cwd=repo, check=False)


def tracked_files(repo: Path) -> list[str]:
    listing = git(["ls-files"], cwd=repo)
    return [line for line in listing.splitlines() if line]


def is_repo(path: Path) -> bool:
    return (path / ".git").exists()


def commit_payload(
    *,
    repo: Path,
    branch: str,
    files: dict[str, str],
    message: str,
) -> tuple[str, list[str]]:
    """Create ``branch``, write ``files`` verbatim, commit them, and return (sha, paths).

    ``files`` is the publisher's own payload: path -> complete new file content. Paths are
    written exactly as given, and added with ``-f`` so that an ignore rule in the developer's
    global git configuration cannot silently drop the evidence directory from the commit.
    """
    git(["checkout", "--quiet", "-B", branch], cwd=repo)
    written: list[str] = []
    for relative, content in sorted(files.items()):
        target = (repo / relative).resolve()
        if repo.resolve() not in target.parents:
            raise GitError(f"publisher payload path escapes the clone: {relative}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="\n")
        written.append(relative)

    git(["add", "-f", "--", *written], cwd=repo)
    git([*_authored(AUTHOR_PUBLISHER), "commit", "--quiet", "-m", message], cwd=repo)
    return head_sha(repo), written


def push(repo: Path, branch: str) -> str:
    return git(["push", "--quiet", "origin", branch], cwd=repo, check=False) or (f"origin/{branch}")


def branch_exists_on_origin(repo: Path, branch: str) -> bool:
    listing = git(["ls-remote", "--heads", "origin", branch], cwd=repo, check=False)
    return bool(listing.strip())


def show_stat(repo: Path, ref: str = "HEAD") -> str:
    return git(["show", "--stat", "--oneline", "--no-color", ref], cwd=repo, check=False)


def log_graph(repo: Path, limit: int = 5) -> str:
    return git(
        ["log", f"-{limit}", "--oneline", "--decorate", "--no-color", "--all"],
        cwd=repo,
        check=False,
    )


def diff_against(repo: Path, base: str, head: str = "HEAD") -> str:
    return git(["diff", "--no-color", f"{base}..{head}"], cwd=repo, check=False)
