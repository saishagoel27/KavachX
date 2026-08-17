"""GitHub Publisher — the only component with GitHub credentials.

Isolation rules, and how each is actually enforced rather than asserted:

* **It never executes repository code.** This module imports nothing from ``app.sandbox``,
  ``app.analysis``, ``app.discovery`` or ``app.gauntlet``, and runs no subprocess. Its whole job
  is HTTP calls with a text payload.
* **It re-runs the policy gate.** The orchestrator already checked policy; the publisher checks
  again against the artifacts it is about to push. A gate you only pass once is a gate you can
  race.
* **It never pushes to the default branch**, never force-pushes, never rewrites history, never
  amends. Every write goes to a fresh ``kavachx/`` branch created from the analysed commit, via
  the contents API — which has no force option to misuse.
* **The credential is minted per publish**, scoped to the single repository, and discarded when
  this function returns.

``PUBLISHER_DRY_RUN=true`` (the default) writes the full intended payload to an artifact instead
of calling GitHub, so the whole path is exercisable without a live App.
"""

from __future__ import annotations

import base64
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.config import settings
from app.core.hashing import sha256_json, sha256_text
from app.core.logging import get_logger
from app.github.app_client import GithubAppClient, RepositoryRef, parse_full_name
from app.models.enums import AssuranceLevel
from app.patching.diffing import split_multifile_diff
from app.patching.policy import PolicyConfig, evaluate

logger = get_logger(__name__)

BRANCH_PREFIX = "kavachx"
CERTIFICATE_DIR = ".kavachx"


@dataclass
class PublishRequest:
    """Everything the publisher receives. Deliberately plain data — no live objects."""

    repository_full_name: str
    installation_id: int | None
    base_branch: str
    base_sha: str
    run_short_code: str
    finding_handle: str
    finding_title: str
    severity: str
    cwe: str
    unified_diff: str
    #: path -> (old_content, new_content). Used for the policy re-check and the file writes.
    file_changes: dict[str, tuple[str, str]]
    certificate_document: dict[str, Any]
    certificate_hash: str
    assurance_level: str
    changes_md: str
    remaining_md: str
    blast_radius: dict[str, Any]
    root_cause_summary: str = ""
    violated_clause: dict[str, Any] | None = None
    approved_by: str = ""
    policy: PolicyConfig = field(default_factory=PolicyConfig)


@dataclass
class PublishResult:
    ok: bool = False
    dry_run: bool = False
    branch: str = ""
    commit_shas: list[str] = field(default_factory=list)
    pull_request_url: str = ""
    pull_request_number: int | None = None
    artifacts_written: list[str] = field(default_factory=list)
    blocked_reason: str = ""
    policy_violations: list[dict[str, Any]] = field(default_factory=list)
    payload_hash: str = ""
    duration_ms: int = 0
    dry_run_payload: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "dry_run": self.dry_run,
            "branch": self.branch,
            "commit_shas": self.commit_shas,
            "pull_request_url": self.pull_request_url,
            "pull_request_number": self.pull_request_number,
            "artifacts_written": self.artifacts_written,
            "blocked_reason": self.blocked_reason,
            "policy_violations": self.policy_violations,
            "payload_hash": self.payload_hash,
            "duration_ms": self.duration_ms,
        }


class Publisher:
    def __init__(
        self, *, client: GithubAppClient | None = None, dry_run: bool | None = None
    ) -> None:
        self.dry_run = settings.publisher_dry_run if dry_run is None else dry_run
        self._client = client
        if not self.dry_run and self._client is None:
            # Constructed here and nowhere else: the credential boundary is this line.
            self._client = GithubAppClient()

    # ------------------------------------------------------------------
    async def publish(self, request: PublishRequest) -> PublishResult:
        started = time.perf_counter()
        result = PublishResult(dry_run=self.dry_run)

        # -- 1. policy validation (again, on the exact payload) ------------
        decision = evaluate(
            diff=request.unified_diff,
            file_changes=request.file_changes,
            config=request.policy,
            blast=None,  # radius membership was enforced at synthesis; recheck the rest here
            assurance_level=request.assurance_level,
            has_certificate=bool(request.certificate_document),
        )
        if not decision.allowed:
            result.blocked_reason = decision.summary
            result.policy_violations = [v.as_dict() for v in decision.violations]
            result.duration_ms = int((time.perf_counter() - started) * 1000)
            logger.warning(
                "publisher.blocked",
                finding=request.finding_handle,
                violations=[v.code for v in decision.violations],
            )
            return result

        if request.assurance_level == AssuranceLevel.R.value:
            result.blocked_reason = (
                "Assurance Level R: the patch was refuted. A refuted patch is never published."
            )
            result.duration_ms = int((time.perf_counter() - started) * 1000)
            return result

        if not request.file_changes:
            result.blocked_reason = "The patch contains no file changes."
            result.duration_ms = int((time.perf_counter() - started) * 1000)
            return result

        # -- 2. branch name -----------------------------------------------
        branch = _branch_name(request)
        result.branch = branch

        files = _build_file_payload(request)
        result.payload_hash = sha256_json(
            {
                "branch": branch,
                "base_sha": request.base_sha,
                "files": {path: sha256_text(content) for path, content in files.items()},
            }
        )

        if self.dry_run:
            result.ok = True
            result.artifacts_written = sorted(files)
            result.dry_run_payload = {
                "mode": "dry-run",
                "note": (
                    "PUBLISHER_DRY_RUN is enabled, so nothing was sent to GitHub. This payload is "
                    "byte-for-byte what would have been pushed."
                ),
                "repository": request.repository_full_name,
                "base_branch": request.base_branch,
                "base_sha": request.base_sha,
                "branch": branch,
                "pull_request": {
                    "title": _pr_title(request),
                    "body": _pr_body(request),
                    "head": branch,
                    "base": request.base_branch,
                },
                "files": files,
                "guarantees": _guarantees(),
            }
            result.duration_ms = int((time.perf_counter() - started) * 1000)
            logger.info(
                "publisher.dry_run",
                finding=request.finding_handle,
                branch=branch,
                files=len(files),
            )
            return result

        # -- 3-6. live publish --------------------------------------------
        assert self._client is not None
        if request.installation_id is None:
            result.blocked_reason = "No GitHub App installation is linked to this repository."
            result.duration_ms = int((time.perf_counter() - started) * 1000)
            return result

        repo = parse_full_name(request.repository_full_name)
        repo.default_branch = request.base_branch

        # Minted here, scoped to one repository, discarded when this frame exits.
        token = await self._client.installation_token(
            request.installation_id, repositories=[repo.name]
        )
        try:
            if branch == request.base_branch:
                result.blocked_reason = (
                    "Refusing to write to the base branch. KavachX only ever pushes to a new "
                    "kavachx/ branch."
                )
                return result

            await self._client.create_branch(token, repo, branch=branch, from_sha=request.base_sha)
            result.commit_shas = []

            for path, content in sorted(files.items()):
                existing_sha = await self._existing_sha(token, repo, path, request.base_branch)
                response = await self._client.put_file(
                    token,
                    repo,
                    path=path,
                    content_b64=base64.b64encode(content.encode("utf-8")).decode("ascii"),
                    message=_commit_message(request, path),
                    branch=branch,
                    sha=existing_sha,
                )
                commit_sha = str((response.get("commit") or {}).get("sha", ""))
                if commit_sha:
                    result.commit_shas.append(commit_sha)
                result.artifacts_written.append(path)

            pull = await self._client.create_pull_request(
                token,
                repo,
                title=_pr_title(request),
                head=branch,
                base=request.base_branch,
                body=_pr_body(request),
            )
            result.pull_request_url = str(pull.get("html_url", ""))
            result.pull_request_number = int(pull.get("number", 0)) or None

            if result.pull_request_number:
                try:
                    await self._client.add_labels(
                        token,
                        repo,
                        issue_number=result.pull_request_number,
                        labels=[
                            "kavachx",
                            "security",
                            f"assurance-{request.assurance_level.lower()}",
                        ],
                    )
                except Exception as exc:  # labels are cosmetic; never fail a publish on them
                    logger.warning("publisher.label_failed", error=str(exc)[:200])

            result.ok = True
            logger.info(
                "publisher.published",
                finding=request.finding_handle,
                branch=branch,
                pr=result.pull_request_number,
                files=len(result.artifacts_written),
            )
        finally:
            # Explicit: the token must not outlive this call.
            token = ""

        result.duration_ms = int((time.perf_counter() - started) * 1000)
        return result

    async def _existing_sha(
        self, token: str, repo: RepositoryRef, path: str, ref: str
    ) -> str | None:
        try:
            data = await self._client.get_file(token, repo, path, ref)  # type: ignore[union-attr]
        except Exception:
            return None
        sha = data.get("sha") if isinstance(data, dict) else None
        return str(sha) if sha else None


# ---------------------------------------------------------------------------
def _branch_name(request: PublishRequest) -> str:
    slug = request.finding_handle.lower().replace("/", "-")
    suffix = uuid.uuid4().hex[:6]
    return f"{BRANCH_PREFIX}/{request.run_short_code.lower()}-{slug}-{suffix}"


def _commit_message(request: PublishRequest, path: str) -> str:
    if path.startswith(CERTIFICATE_DIR):
        return (
            f"docs(kavachx): add assurance evidence for {request.finding_handle}\n\n"
            f"Certificate {request.certificate_hash[:16]} (Level {request.assurance_level})."
        )
    return (
        f"fix({request.cwe or 'security'}): repair {request.finding_handle} in {path}\n\n"
        f"{request.root_cause_summary[:400]}\n\n"
        f"Verified by the KavachX Refutation Gauntlet. "
        f"Assurance Level {request.assurance_level}. "
        f"Certificate {request.certificate_hash[:16]}."
    )


def _pr_title(request: PublishRequest) -> str:
    return (
        f"[KavachX] {request.severity} {request.cwe or 'security'} — "
        f"{request.finding_title[:90]} (Level {request.assurance_level})"
    )


def _pr_body(request: PublishRequest) -> str:
    clause = request.violated_clause or {}
    blast = request.blast_radius or {}
    verification = (request.certificate_document.get("verification") or {}).get("stages", {})

    lines = [
        "## KavachX — proof-carrying security repair",
        "",
        f"**Finding** `{request.finding_handle}` — {request.finding_title}",
        f"**Severity** {request.severity} · **Weakness** {request.cwe or 'unclassified'}",
        f"**Assurance** **Level {request.assurance_level}** "
        f"(bounded empirical assurance — not a formal proof)",
        f"**Certificate** `{request.certificate_hash}`",
        "",
        "### Root cause",
        "",
        request.root_cause_summary or "_not recorded_",
        "",
    ]

    if clause:
        lines += [
            "### Violated behavioural clause (SAMHITA)",
            "",
            f"- **{clause.get('clause_id', '')}** — {clause.get('description', '')}",
            f"- Predicate `{clause.get('predicate', '')}`",
            "- Survived falsification against held-out benign traces before being used as "
            "evidence.",
            "",
        ]

    lines += [
        "### Verification (Refutation Gauntlet)",
        "",
        "| Stage | Verdict | Detail |",
        "| --- | --- | --- |",
    ]
    for stage, outcome in verification.items():
        detail = str(outcome.get("detail", "")).replace("|", "\\|")[:160]
        lines.append(f"| `{stage}` | **{str(outcome.get('verdict', '')).upper()}** | {detail} |")
    lines += [
        "",
        "### Blast radius",
        "",
        f"- Regression scope **{blast.get('regression_scope', 'unknown')}**",
        f"- {len(blast.get('direct_callers', []))} direct callers · "
        f"{len(blast.get('transitive_callers', []))} transitive · "
        f"{len(blast.get('modules', []))} modules",
        f"- {len(blast.get('clause_ids', []))} behavioural clauses re-checked after the patch",
        "",
        "### What is in this pull request",
        "",
        "- the repair itself",
        f"- `{CERTIFICATE_DIR}/certificate-{request.finding_handle}.json` — the full evidence graph",
        f"- `{CERTIFICATE_DIR}/CHANGES.md` — what was verified",
        f"- `{CERTIFICATE_DIR}/REMAINING.md` — **what was not**, including refuted patches, "
        "coverage gaps and residual risk",
        "",
        "### Limitations",
        "",
    ]
    for limitation in (request.certificate_document.get("assurance") or {}).get("limitations", []):
        lines.append(f"- {limitation}")

    lines += [
        "",
        "---",
        "",
        f"Approved for publication by `{request.approved_by or 'unknown'}`. "
        "The working exploit is withheld from this pull request and from the certificate; it is "
        "available only to roles holding `finding:read_pov`.",
        "",
        "*The working exploit was reproduced deterministically before this repair was attempted, "
        "and the repair was attacked by mutation, sibling hunt, differential replay and contract "
        "re-check before this pull request was opened.*",
    ]
    return "\n".join(lines)


def _build_file_payload(request: PublishRequest) -> dict[str, str]:
    """The exact file set to write: the repair, then the evidence."""
    import json

    files: dict[str, str] = {}
    for path, (_old, new) in request.file_changes.items():
        files[path] = new

    handle = request.finding_handle
    files[f"{CERTIFICATE_DIR}/certificate-{handle}.json"] = json.dumps(
        request.certificate_document, indent=2, sort_keys=True, default=str
    )
    files[f"{CERTIFICATE_DIR}/CHANGES.md"] = request.changes_md
    files[f"{CERTIFICATE_DIR}/REMAINING.md"] = request.remaining_md
    files[f"{CERTIFICATE_DIR}/{handle}.patch"] = request.unified_diff
    return files


def _guarantees() -> dict[str, Any]:
    return {
        "never_pushes_to_default_branch": True,
        "never_force_pushes": True,
        "never_rewrites_history": True,
        "never_amends_commits": True,
        "never_executes_repository_code": True,
        "installation_token_persisted": False,
        "token_scope": "single repository, minted per publish",
        "policy_gate_reevaluated_at_publish": True,
        "generated_at": datetime.now(UTC).isoformat(),
    }


def diff_files(unified_diff: str) -> list[str]:
    return sorted(split_multifile_diff(unified_diff).keys())
