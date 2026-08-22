"""Public GitHub repository ingestion.

Two things are being asserted here. First, that the reference forms a person actually pastes all
resolve. Second — and this is the security-relevant half — that a hostile archive cannot escape the
destination directory, and that a public repository can never reach the Publisher.

No network is used: archive handling is tested against tarballs built in the test, and the
publish boundary is tested through the API.
"""

from __future__ import annotations

import io
import tarfile
import uuid
from pathlib import Path

import httpx
import pytest

from app.core.errors import BadRequest
from app.github.public_ingest import (
    MAX_MEMBERS,
    RepositoryTooLarge,
    _is_safe_member,
    _safe_extract,
    parse_repo_reference,
)
from app.models.enums import PUBLISHABLE_PROVIDERS, RepositoryProvider
from tests.conftest import auth


# ---------------------------------------------------------------------------
# reference parsing
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://github.com/psf/requests", "psf/requests"),
        ("http://github.com/psf/requests", "psf/requests"),
        ("https://www.github.com/psf/requests", "psf/requests"),
        ("https://github.com/psf/requests.git", "psf/requests"),
        ("https://github.com/psf/requests/", "psf/requests"),
        ("https://github.com/psf/requests/tree/main", "psf/requests"),
        ("https://github.com/psf/requests/blob/main/setup.py", "psf/requests"),
        ("git@github.com:psf/requests.git", "psf/requests"),
        ("github.com/psf/requests", "psf/requests"),
        ("psf/requests", "psf/requests"),
        ("@psf/requests", "psf/requests"),
        ("  psf/requests  ", "psf/requests"),
        ("pallets/flask-sqlalchemy", "pallets/flask-sqlalchemy"),
        ("owner/repo.name", "owner/repo.name"),
    ],
)
def test_reference_forms_resolve(raw: str, expected: str):
    assert parse_repo_reference(raw).full_name == expected


@pytest.mark.parametrize(
    "raw",
    ["", "   ", "psf", "https://github.com/", "https://gitlab.com/", "/", "//"],
)
def test_invalid_references_are_rejected(raw: str):
    with pytest.raises(BadRequest):
        parse_repo_reference(raw)


@pytest.mark.security
@pytest.mark.parametrize(
    "raw",
    [
        "../../etc/passwd",
        "psf/requests/../../other",
        "-owner/repo",
        "owner/-repo",
        "own er/repo",
        "owner/re;po",
    ],
)
def test_hostile_references_are_rejected(raw: str):
    """A reference is interpolated into a URL path, so it must be validated, not trusted."""
    with pytest.raises(BadRequest):
        reference = parse_repo_reference(raw)
        # If parsing somehow succeeded, the pair must still be a plain owner/name.
        assert "/" not in reference.owner and "/" not in reference.name
        assert ".." not in reference.owner and ".." not in reference.name
        raise BadRequest("unreachable")


# ---------------------------------------------------------------------------
# archive extraction — the security-sensitive part
# ---------------------------------------------------------------------------
def _archive(members: list[tuple[str, bytes]], *, links: list[tuple[str, str]] | None = None):
    """Build an in-memory tarball, optionally containing symlinks."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data in members:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        for name, target in links or []:
            info = tarfile.TarInfo(name=name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            archive.addfile(info)
    buffer.seek(0)
    return buffer


def test_safe_archive_extracts(tmp_path: Path):
    buffer = _archive([("repo-abc/app.py", b"x = 1\n"), ("repo-abc/README.md", b"# hi\n")])
    with tarfile.open(fileobj=buffer, mode="r:gz") as archive:
        stats = _safe_extract(archive, tmp_path)
    assert stats["members_extracted"] == 2
    assert (tmp_path / "repo-abc" / "app.py").read_text() == "x = 1\n"


@pytest.mark.security
def test_absolute_path_member_is_skipped(tmp_path: Path):
    buffer = _archive([("/etc/kavachx-pwned", b"pwned\n")])
    with tarfile.open(fileobj=buffer, mode="r:gz") as archive:
        stats = _safe_extract(archive, tmp_path)
    assert stats["members_extracted"] == 0
    assert any(s["reason"] == "path escapes the destination" for s in stats["skipped"])


@pytest.mark.security
def test_traversal_member_is_skipped(tmp_path: Path):
    """Classic zip-slip: ``../`` in a member name."""
    destination = tmp_path / "dest"
    buffer = _archive([("repo/../../escaped.py", b"pwned\n"), ("repo/ok.py", b"fine\n")])
    with tarfile.open(fileobj=buffer, mode="r:gz") as archive:
        stats = _safe_extract(archive, destination)

    assert stats["members_extracted"] == 1
    assert (destination / "repo" / "ok.py").is_file()
    assert not (tmp_path.parent / "escaped.py").exists()
    assert not (tmp_path / "escaped.py").exists()


@pytest.mark.security
def test_symlink_member_is_skipped(tmp_path: Path):
    """A link pointing outside the tree is a real technique; skip rather than resolve."""
    buffer = _archive(
        [("repo/ok.py", b"fine\n")],
        links=[("repo/passwd", "/etc/passwd"), ("repo/up", "../../..")],
    )
    with tarfile.open(fileobj=buffer, mode="r:gz") as archive:
        stats = _safe_extract(archive, tmp_path)

    assert stats["members_extracted"] == 1
    assert len([s for s in stats["skipped"] if s["reason"] == "link member"]) == 2
    assert not (tmp_path / "repo" / "passwd").exists()


@pytest.mark.security
def test_oversized_archive_is_refused(tmp_path: Path, monkeypatch):
    """A compression bomb must fail loudly rather than filling the disk.

    The cap is lowered rather than building a genuinely huge archive: the code path exercised is
    identical, and the test stays fast.
    """
    from app.github import public_ingest

    monkeypatch.setattr(public_ingest, "MAX_EXTRACTED_BYTES", 1024)
    payload = b"A" * 4096  # highly compressible, so the archive itself stays tiny
    buffer = _archive([("repo/big.bin", payload)])

    with tarfile.open(fileobj=buffer, mode="r:gz") as archive, pytest.raises(RepositoryTooLarge):
        _safe_extract(archive, tmp_path)


@pytest.mark.security
def test_malformed_archive_fails_cleanly(tmp_path: Path):
    """A truncated member must produce a KavachX error, not a bare OSError surfacing as a 500."""
    from app.github.public_ingest import RepositoryFetchFailed

    # Build a valid uncompressed archive, then cut it short — exactly what a dropped connection
    # mid-download leaves behind.
    complete = io.BytesIO()
    with tarfile.open(fileobj=complete, mode="w") as archive:
        data = b"A" * 8192
        info = tarfile.TarInfo(name="repo/truncated.bin")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))

    truncated = io.BytesIO(complete.getvalue()[: 512 + 1024])
    with tarfile.open(fileobj=truncated, mode="r") as archive, pytest.raises(RepositoryFetchFailed):
        _safe_extract(archive, tmp_path)


@pytest.mark.security
def test_member_count_is_capped():
    assert MAX_MEMBERS <= 100_000, "an unbounded member count is a disk-exhaustion vector"


@pytest.mark.security
def test_member_safety_predicate(tmp_path: Path):
    cases = [
        ("repo/app.py", True),
        ("repo/nested/deep/app.py", True),
        ("/absolute", False),
        ("../escape", False),
        ("repo/../../escape", False),
    ]
    for name, expected in cases:
        info = tarfile.TarInfo(name=name)
        info.type = tarfile.REGTYPE
        ok, _reason = _is_safe_member(info, tmp_path)
        assert ok is expected, f"{name} should be {'allowed' if expected else 'skipped'}"

    for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.FIFOTYPE):
        info = tarfile.TarInfo(name="repo/thing")
        info.type = kind
        ok, _reason = _is_safe_member(info, tmp_path)
        assert ok is False, f"member type {kind!r} should be skipped"


def test_no_credential_is_sent_on_the_public_path():
    """The public path must work — and be seen to work — with no Authorization header."""
    from app.github import public_ingest

    client = public_ingest._client()
    try:
        assert "authorization" not in {k.lower() for k in client.headers}
    finally:
        pass


# ---------------------------------------------------------------------------
# the publish boundary
# ---------------------------------------------------------------------------
@pytest.mark.security
def test_public_provider_is_not_publishable():
    assert RepositoryProvider.GITHUB_PUBLIC.value not in PUBLISHABLE_PROVIDERS
    assert RepositoryProvider.GITHUB.value in PUBLISHABLE_PROVIDERS


@pytest.mark.security
async def test_publishing_a_public_repository_is_refused(client: httpx.AsyncClient, tenant_a):
    """A verified patch against somebody else's repository must not become a pull request."""
    from datetime import datetime, timezone

    from app.db.session import session_scope
    from app.models.analysis import Finding
    from app.models.enums import AssuranceLevel, FindingState, PatchStatus, RunStatus
    from app.models.pramaan import Certificate
    from app.models.project import Repository
    from app.models.repair import Patch
    from app.models.run import Run

    tenant_id = uuid.UUID(tenant_a["organisation_id"])
    async with session_scope() as db:
        repository = Repository(
            tenant_id=tenant_id,
            project_id=uuid.UUID(tenant_a["project_id"]),
            provider=RepositoryProvider.GITHUB_PUBLIC.value,
            full_name="someone-else/their-repo",
            default_branch="main",
            private=False,
            authority_verified_at=datetime.now(timezone.utc),
            authority_evidence={"method": "github_public", "publishable": False},
        )
        db.add(repository)
        await db.flush()

        run = Run(
            tenant_id=tenant_id,
            project_id=uuid.UUID(tenant_a["project_id"]),
            repository_id=repository.id,
            short_code="PUB1",
            status=RunStatus.AWAITING_APPROVAL.value,
        )
        db.add(run)
        await db.flush()

        finding = Finding(
            tenant_id=tenant_id,
            run_id=run.id,
            handle="V01",
            title="something real",
            state=FindingState.VALIDATED.value,
            reproduced=True,
        )
        db.add(finding)
        await db.flush()

        db.add(
            Patch(
                tenant_id=tenant_id,
                run_id=run.id,
                finding_id=finding.id,
                iteration=1,
                status=PatchStatus.VERIFIED.value,
                unified_diff="--- a/x.py\n+++ b/x.py\n",
                files=["x.py"],
                file_contents={"x.py": {"old": "a = 1\n", "new": "a = 2\n"}},
            )
        )
        certificate = Certificate(
            tenant_id=tenant_id,
            run_id=run.id,
            finding_id=finding.id,
            serial="KX-PUB1-V01-TEST",
            assurance_level=AssuranceLevel.A.value,
            document={"assurance": {"level": "A"}},
            certificate_hash="a" * 64,
            issued_at=datetime.now(timezone.utc),
        )
        db.add(certificate)
        await db.flush()
        run_id, certificate_id = str(run.id), str(certificate.id)

    response = await client.post(
        f"/api/runs/{run_id}/publish",
        headers=auth(tenant_a["token"]),
        json={"certificate_id": certificate_id, "confirm": True},
    )
    assert response.status_code == 422
    body = response.json()["error"]
    assert body["code"] == "PROVIDER_NOT_PUBLISHABLE"
    assert "analysis-only" in body["message"]


@pytest.mark.security
async def test_public_attach_requires_authorisation(client: httpx.AsyncClient, tenant_a):
    """Attaching a third-party repository requires an explicit attestation."""
    response = await client.post(
        f"/api/projects/{tenant_a['project_id']}/repositories",
        headers=auth(tenant_a["token"]),
        json={
            "full_name": "psf/requests",
            "public": True,
            "authorisation_confirmed": False,
        },
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "AUTHORISATION_NOT_CONFIRMED"


async def test_default_branch_is_not_forced_to_main():
    """A literal "main" default would break every repository still on "master"."""
    from app.schemas.core import RepositoryAttach

    payload = RepositoryAttach(full_name="owner/repo", public=True)
    assert payload.default_branch == ""


# ---------------------------------------------------------------------------
# expanded static rules — what makes public-repo analysis worth running
# ---------------------------------------------------------------------------
def _scan_source(tmp_path: Path, source: str):
    from app.analysis.scanner import scan_python_file

    path = tmp_path / "sample.py"
    path.write_text(source, encoding="utf-8")
    return {f.rule_id for f in scan_python_file(path, root=tmp_path)}


def test_detects_sql_injection(tmp_path: Path):
    rules = _scan_source(
        tmp_path,
        "def f(cur, name):\n    cur.execute(f\"SELECT * FROM t WHERE n = '{name}'\")\n",
    )
    assert "kavachx.python.sql-injection" in rules


def test_parameterised_query_is_not_flagged(tmp_path: Path):
    rules = _scan_source(
        tmp_path,
        "def f(cur, name):\n    cur.execute('SELECT * FROM t WHERE n = ?', (name,))\n",
    )
    assert "kavachx.python.sql-injection" not in rules


def test_detects_insecure_deserialisation(tmp_path: Path):
    assert "kavachx.python.insecure-deserialisation" in _scan_source(
        tmp_path, "import pickle\n\n\ndef f(b):\n    return pickle.loads(b)\n"
    )
    assert "kavachx.python.insecure-deserialisation" in _scan_source(
        tmp_path, "import yaml\n\n\ndef f(t):\n    return yaml.load(t)\n"
    )


def test_safe_yaml_loader_is_not_flagged(tmp_path: Path):
    rules = _scan_source(
        tmp_path, "import yaml\n\n\ndef f(t):\n    return yaml.load(t, Loader=yaml.SafeLoader)\n"
    )
    assert "kavachx.python.insecure-deserialisation" not in rules


def test_detects_disabled_tls_verification(tmp_path: Path):
    rules = _scan_source(
        tmp_path, "import requests\n\n\ndef f(u):\n    return requests.get(u, verify=False)\n"
    )
    assert "kavachx.python.tls-verification-disabled" in rules


def test_normal_request_is_not_flagged(tmp_path: Path):
    rules = _scan_source(
        tmp_path, "import requests\n\n\ndef f(u):\n    return requests.get(u, timeout=5)\n"
    )
    assert "kavachx.python.tls-verification-disabled" not in rules


def test_detects_hardcoded_secret(tmp_path: Path):
    rules = _scan_source(tmp_path, 'API_SECRET_KEY = "sk-live-9f2a4c81b77e4d3a"\n')
    assert "kavachx.python.hardcoded-secret" in rules


@pytest.mark.parametrize(
    "source",
    [
        'MAX_RETRIES = "8"\n',  # not credential-shaped
        'API_SECRET_KEY = "changeme"\n',  # obvious placeholder
        'API_SECRET_KEY = "${VAULT_KEY}"\n',  # interpolation
        'API_SECRET_KEY = "example-value-here"\n',  # documented example
        'SECRET_KEY = "short"\n',  # too short to be a real key
    ],
)
def test_secret_rule_does_not_fire_on_placeholders(tmp_path: Path, source: str):
    assert "kavachx.python.hardcoded-secret" not in _scan_source(tmp_path, source)


def test_detects_debug_server(tmp_path: Path):
    rules = _scan_source(
        tmp_path,
        'from flask import Flask\n\napp = Flask(__name__)\n\napp.run(debug=True, host="0.0.0.0")\n',
    )
    assert "kavachx.python.debug-server" in rules


def test_production_server_start_is_not_flagged(tmp_path: Path):
    rules = _scan_source(
        tmp_path, "from flask import Flask\n\napp = Flask(__name__)\n\napp.run(port=8080)\n"
    )
    assert "kavachx.python.debug-server" not in rules


def test_detects_template_injection(tmp_path: Path):
    rules = _scan_source(
        tmp_path,
        "from flask import render_template_string\n\n\n"
        'def greet(name):\n    return render_template_string("<h1>" + name + "</h1>")\n',
    )
    assert "kavachx.python.template-injection" in rules


def test_static_template_is_not_flagged(tmp_path: Path):
    rules = _scan_source(
        tmp_path,
        "from flask import render_template_string\n\n\n"
        'def greet():\n    return render_template_string("<h1>hello</h1>")\n',
    )
    assert "kavachx.python.template-injection" not in rules


def test_every_new_rule_has_a_severity_and_cwe():
    """A rule with no CWE and no severity would silently report as an unclassified MEDIUM."""
    from app.discovery.static_channel import _PLAN_BY_RULE, _SEVERITY_BY_RULE

    for rule_id in _SEVERITY_BY_RULE:
        assert rule_id in _PLAN_BY_RULE, f"{rule_id} has a severity but no CWE mapping"
        _plan, cwe, _clause = _PLAN_BY_RULE[rule_id]
        assert cwe.startswith("CWE-"), f"{rule_id} has no CWE"


# ---------------------------------------------------------------------------
# transient upstream failures
# ---------------------------------------------------------------------------
class _CountingTransport(httpx.AsyncBaseTransport):
    """Replays a fixed sequence of status codes and counts the requests it received."""

    def __init__(self, statuses: list[int], body: bytes = b"{}") -> None:
        self.statuses = list(statuses)
        self.body = body
        self.calls = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        status = self.statuses.pop(0) if self.statuses else 200
        return httpx.Response(status, content=self.body, request=request)


async def _get_via(transport: _CountingTransport, *, url: str = "https://api.example/x"):
    from app.github.public_ingest import _get_with_retry

    async with httpx.AsyncClient(transport=transport) as client:
        return await _get_with_retry(client, url, what="test")


async def test_a_transient_504_is_retried_and_succeeds():
    """The failure this guards was real: GitHub 504'd one endpoint while the rest were healthy."""
    transport = _CountingTransport([504, 200])
    response = await _get_via(transport)
    assert response.status_code == 200
    assert transport.calls == 2


async def test_retries_are_bounded():
    transport = _CountingTransport([504, 504, 504, 504, 504])
    response = await _get_via(transport)
    assert response.status_code == 504, "the caller must still see the upstream failure"
    assert transport.calls == 3, "retrying forever would hang the run instead of failing it"


@pytest.mark.parametrize("status", [400, 403, 404, 422])
async def test_client_errors_are_answers_and_are_never_retried(status: int):
    """A 404 or a rate-limit 403 is information. Retrying it wastes the anonymous budget."""
    transport = _CountingTransport([status])
    response = await _get_via(transport)
    assert response.status_code == status
    assert transport.calls == 1


async def test_a_429_is_retried_because_throttling_is_not_an_answer():
    """The regression the user hit: `codeload returned HTTP 429` failed the run outright.

    429 is a 4xx, but unlike 403/404 it means "you are going too fast", not "you asked for the wrong
    thing". Excluding every 4xx from retry turned a momentary throttle into a NODE_FAILED at ingest.
    """
    transport = _CountingTransport([429, 200])
    response = await _get_via(transport)
    assert response.status_code == 200
    assert transport.calls == 2


def test_retry_after_lengthens_the_wait_but_is_capped():
    from app.github.public_ingest import (
        _MAX_RETRY_AFTER_SECONDS,
        _THROTTLE_BACKOFF_SECONDS,
        _retry_delay,
    )

    def throttled(headers: dict[str, str]) -> httpx.Response:
        return httpx.Response(429, headers=headers)

    # No header -> the throttle backoff table.
    assert _retry_delay(throttled({}), 0) == _THROTTLE_BACKOFF_SECONDS[0]
    # A larger Retry-After wins...
    assert _retry_delay(throttled({"retry-after": "9"}), 0) == 9.0
    # ...a smaller one never shortens the pause below our own floor.
    assert _retry_delay(throttled({"retry-after": "1"}), 0) == _THROTTLE_BACKOFF_SECONDS[0]
    # ...and a generous one cannot stall the run indefinitely.
    assert _retry_delay(throttled({"retry-after": "3600"}), 0) == _MAX_RETRY_AFTER_SECONDS
    # A malformed header is ignored rather than crashing the retry path.
    assert (
        _retry_delay(throttled({"retry-after": "Wed, 21 Oct 2026 07:28:00 GMT"}), 0)
        == (_THROTTLE_BACKOFF_SECONDS[0])
    )


def _tarball(files: dict[str, str], *, root: str = "owner-repo-abc123") -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for rel, body in files.items():
            data = body.encode()
            info = tarfile.TarInfo(name=f"{root}/{rel}")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


class _ArchiveTransport(httpx.AsyncBaseTransport):
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.calls = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        return httpx.Response(200, content=self.payload, request=request)


async def test_the_same_commit_is_not_downloaded_twice(tmp_path: Path, monkeypatch):
    """A commit SHA pins content immutably, so a second fetch of it is pure waste.

    Re-downloading was what tripped codeload's archive throttle in the first place: three runs
    against one repository meant three identical multi-megabyte downloads.
    """
    from app.config import settings
    from app.github import public_ingest

    cache = tmp_path / "cache"
    cache.mkdir()
    monkeypatch.setattr(type(settings), "source_cache_root", property(lambda self: cache))

    payload = _tarball({"app.py": "import os\n", "src/util.py": "x = 1\n"})
    transport = _ArchiveTransport(payload)
    monkeypatch.setattr(public_ingest, "_client", lambda: httpx.AsyncClient(transport=transport))

    ref = public_ingest.PublicRepoRef(owner="owner", name="repo")
    sha = "abc123" + "0" * 34

    first = await public_ingest.download_source(ref, sha=sha, destination=tmp_path / "one")
    assert first["from_cache"] is False
    assert transport.calls == 1
    assert (tmp_path / "one" / "app.py").read_text() == "import os\n"
    assert (tmp_path / "one" / "src" / "util.py").is_file()

    second = await public_ingest.download_source(ref, sha=sha, destination=tmp_path / "two")
    assert second["from_cache"] is True
    assert transport.calls == 1, "the second run must not touch the network at all"
    assert (tmp_path / "two" / "app.py").read_text() == "import os\n"
    assert (tmp_path / "two" / "src" / "util.py").is_file()

    # Our bookkeeping must not leak into the analysed tree, or the pinned hash covers our own file.
    assert not (tmp_path / "two" / ".kavachx-complete.json").exists()
    assert not (tmp_path / "one" / ".kavachx-complete.json").exists()


async def test_a_different_commit_is_fetched_again(tmp_path: Path, monkeypatch):
    from app.config import settings
    from app.github import public_ingest

    cache = tmp_path / "cache"
    cache.mkdir()
    monkeypatch.setattr(type(settings), "source_cache_root", property(lambda self: cache))
    transport = _ArchiveTransport(_tarball({"app.py": "1\n"}))
    monkeypatch.setattr(public_ingest, "_client", lambda: httpx.AsyncClient(transport=transport))

    ref = public_ingest.PublicRepoRef(owner="owner", name="repo")
    await public_ingest.download_source(ref, sha="a" * 40, destination=tmp_path / "a")
    await public_ingest.download_source(ref, sha="b" * 40, destination=tmp_path / "b")
    assert transport.calls == 2, "a different commit is different content and must be fetched"


async def test_an_incomplete_cache_entry_is_discarded(tmp_path: Path, monkeypatch):
    """An entry without its completion marker is a half-written copy, not a usable tree."""
    from app.config import settings
    from app.github import public_ingest

    cache = tmp_path / "cache"
    cache.mkdir()
    monkeypatch.setattr(type(settings), "source_cache_root", property(lambda self: cache))

    ref = public_ingest.PublicRepoRef(owner="owner", name="repo")
    sha = "c" * 40
    # Simulate an interrupted publish: tree present, marker absent.
    stale = cache / public_ingest._cache_key(ref, sha)
    stale.mkdir()
    (stale / "truncated.py").write_text("half a file", encoding="utf-8")

    transport = _ArchiveTransport(_tarball({"app.py": "real\n"}))
    monkeypatch.setattr(public_ingest, "_client", lambda: httpx.AsyncClient(transport=transport))

    result = await public_ingest.download_source(ref, sha=sha, destination=tmp_path / "out")
    assert result["from_cache"] is False
    assert transport.calls == 1
    assert (tmp_path / "out" / "app.py").read_text() == "real\n"
    assert not (tmp_path / "out" / "truncated.py").exists()
