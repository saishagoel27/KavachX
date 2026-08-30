#!/usr/bin/env python3
"""Standalone proof that the walkthrough itself works — no server, no database, no network.

``walkthrough.py`` needs a running backend, so it cannot tell you whether the walkthrough is
sound until the whole stack is up. This does, in a few seconds, and it drives the **real** code:

* ``lib.gitwork``  — the actual git plumbing act 1 and act 12 use, against a real repository it
  builds on disk: origin, clone, branch, commit, push, and a read-back from the origin.
* every rendering act in ``walkthrough.py`` — driven with payloads shaped like the real API
  responses, so a formatting bug or a renamed field is caught here rather than in front of an
  audience.
* **the failure paths** — the same acts driven twice more: once with nothing to report, and once
  with a run where every stage produced records and every one of them failed. The second is the
  one that matters. With no records at all several acts take an early return, so an act that
  claims success without checking its own evidence slips through; giving it a full set of failed
  records forces it down its normal path. A demo that cannot fail is not evidence of anything.

Run it with plain Python from the repository root — there is nothing to install::

    python examples/platform-walkthrough/verify_walkthrough.py

Exit code 0 = the git layer really works, every act renders, and every act fails when it should.
Non-zero = something in that chain did not hold, and the failure is printed.
"""

# The walkthrough module and its lib are importable only after the sys.path bootstrap below.
# ruff: noqa: E402
from __future__ import annotations

import importlib.util
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

from lib import gitwork, ui

_spec = importlib.util.spec_from_file_location("kx_walkthrough", HERE / "walkthrough.py")
assert _spec and _spec.loader
walkthrough = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(walkthrough)

TARGET = REPO_ROOT / "examples" / "vulnerable-demo"
RUN_ID = "00000000-0000-4000-8000-000000000001"
CERT_ID = "00000000-0000-4000-8000-000000000002"
FINDING_ID = "00000000-0000-4000-8000-000000000003"

DIFF = (
    "--- a/src/reportsvc/exporter.py\n"
    "+++ b/src/reportsvc/exporter.py\n"
    "@@ -30,7 +30,7 @@\n"
    '-    return f"{sys.executable} -m reportsvc.archiver --name {report_name}"\n'
    '+    return [sys.executable, "-m", "reportsvc.archiver", "--name", report_name]\n'
)

#: Responses shaped like the real API's, so the acts are exercised the way a run drives them.
POPULATED: dict[str, Any] = {
    f"/api/runs/{RUN_ID}/index": {
        "available": True,
        "index": {
            "index_id": "04adf9a6a08a674b",
            "graph_source": "gitnexus+tree-sitter",
            "files": {"discovered": 24, "indexed": 24, "skipped": 0},
            "symbols": {"total": 30, "functions": 26, "classes": 4},
            "relationships": {"total": 168, "calls": 29, "imports": 28, "resolved": 99},
        },
        "health": {
            "grade": "B",
            "warnings": ["Most relationships are name matches"],
            "claim_bounds": ["a precise reachability claim"],
        },
    },
    f"/api/runs/{RUN_ID}/clauses": [
        {
            "clause_id": "C088",
            "status": "SURVIVING",
            "predicate": "arg_safe_charset == True",
            "scope": "exporter.py:_archiver_command",
            "falsification_reason": "",
        },
        {
            "clause_id": "C027",
            "status": "FALSIFIED",
            "predicate": "arg_len_fmt <= 3",
            "scope": "global",
            "falsification_reason": "held-out case 008 contradicts it",
        },
    ],
    f"/api/runs/{RUN_ID}/hypotheses": [
        {"source_channel": "fuzzing", "handle": "F001"},
        {"source_channel": "static", "handle": "H004"},
    ],
    f"/api/runs/{RUN_ID}/tests": {
        "plans": [
            {
                "plan_id": "c8d66d325df2765f",
                "strategy": "mutation",
                "engine": "kx-mutational",
                "oracle_kind": "marker_in_stdout",
                "status": "GENERATED",
                "proposed_by": "model",
                "engine_reason": "",
            }
        ],
        "executions": [
            {
                "plan_id": "c8d66d325df2765f",
                "campaign": {
                    "rounds_run": 3,
                    "executions": 120,
                    "corpus_size": 18,
                    "crashes": [{"id": 1}],
                    "model": {"rounds": 2, "candidates": 9, "candidates_useful": 3},
                },
            }
        ],
        "counts": {},
    },
    f"/api/runs/{RUN_ID}/findings": [
        {
            "id": FINDING_ID,
            "handle": "V01",
            "state": "VALIDATED",
            "severity": "CRITICAL",
            "cwe": "CWE-78",
            "title": "OS command injection",
            "location": "src/reportsvc/exporter.py:42",
            "source_channel": "static",
            "reproduction_count": 2,
            "pov_kind": "marker_in_stdout",
            "violated_clause_id": "C088",
            "root_cause_location": "src/reportsvc/exporter.py:40",
            "root_cause_verified": True,
            "root_cause_summary": "report_name reaches a shell.",
            "contract_violation": "",
        }
    ],
    f"/api/runs/{RUN_ID}/shields": [
        {
            "handle": "S02",
            "mechanism": "input_filter",
            "rule": "REJECT export.name WHEN value contains ';'",
            "verified_blocked": True,
            "verified_benign": True,
            "benign_pass_count": 12,
            "benign_total": 12,
            "deployed_at": "2026-08-30T10:00:00Z",
            "reverted_at": "",
        }
    ],
    f"/api/runs/{RUN_ID}/patches": [
        {
            "finding_id": FINDING_ID,
            "finding_handle": "V01",
            "iteration": 1,
            "status": "REFUTED",
            "reason": "Reject ';' before the command is built.",
            "refutation_summary": "BYPASS FOUND - 'separator:&' still reproduced it.",
            "constraints": ["character filtering is insufficient"],
            "unified_diff": "",
            "files": ["src/reportsvc/exporter.py"],
            "lines_added": 2,
            "lines_removed": 0,
            "risk": "medium",
            "policy_passed": True,
            "within_blast_radius": True,
            "diff_hash": "abc123",
            "expected_effect": "",
        },
        {
            "finding_id": FINDING_ID,
            "finding_handle": "V01",
            "iteration": 2,
            "status": "VERIFIED",
            "reason": "Remove the shell from the execution path.",
            "refutation_summary": "",
            "constraints": [],
            "unified_diff": DIFF,
            "files": ["src/reportsvc/exporter.py"],
            "lines_added": 12,
            "lines_removed": 6,
            "risk": "low",
            "policy_passed": True,
            "within_blast_radius": True,
            "diff_hash": "def456",
            "expected_effect": "shell=False, name allowlisted.",
        },
    ],
    f"/api/runs/{RUN_ID}/gauntlet": [
        {
            "finding_handle": "V01",
            "iteration": 2,
            "verdict": "pass",
            "failing_stage": "",
            "stages_passed": 4,
            "stages_total": 4,
            "stages": [
                {
                    "stage": "exploit_mutation",
                    "verdict": "pass",
                    "cases_total": 19,
                    "detail": "none reproduced",
                    "refuting_evidence": {},
                }
            ],
        }
    ],
    f"/api/runs/{RUN_ID}/certificates": [
        {
            "id": CERT_ID,
            "finding_id": FINDING_ID,
            "serial": "KVX-2026-0001",
            "finding_handle": "V01",
            "assurance_level": "B",
            "certificate_hash": "35ff9cd290ae2cda",
            "signature_algorithm": "HMAC-SHA256",
            "evidence_node_count": 21,
            "evidence_edge_count": 21,
            "grading_rationale": ["exploit reproduced 2x"],
            "limitations": ["7 sibling paths could not be proved safe"],
        }
    ],
}

#: Everything ran and nothing succeeded. Distinct from an empty run: the acts take their normal
#: path here rather than an early return, so this is the scenario that catches an act which
#: reports success without checking its own evidence.
UNSUCCESSFUL: dict[str, Any] = {
    f"/api/runs/{RUN_ID}/index": {"available": True, "index": {}, "health": {}},
    f"/api/runs/{RUN_ID}/clauses": [
        {
            "clause_id": "C001",
            "status": "FALSIFIED",
            "predicate": "x <= 1",
            "scope": "global",
            "falsification_reason": "held-out trace contradicts it",
        }
    ],
    f"/api/runs/{RUN_ID}/hypotheses": [],
    f"/api/runs/{RUN_ID}/tests": {"plans": [], "executions": [], "counts": {}},
    f"/api/runs/{RUN_ID}/findings": [
        {
            "handle": "H004",
            "state": "REFUTED",
            "severity": "MEDIUM",
            "cwe": "CWE-22",
            "title": "not reproduced",
            "contract_violation": "effect reproduced at a different location",
        }
    ],
    f"/api/runs/{RUN_ID}/shields": [
        {
            "handle": "S01",
            "mechanism": "input_filter",
            "rule": "REJECT x",
            "verified_blocked": False,
            "verified_benign": False,
            "benign_pass_count": 3,
            "benign_total": 12,
            "deployed_at": "",
            "reverted_at": "2026-08-30T10:00:30Z",
        }
    ],
    f"/api/runs/{RUN_ID}/patches": [
        {
            "finding_id": FINDING_ID,
            "finding_handle": "V01",
            "iteration": 3,
            "status": "REFUTED",
            "reason": "third attempt",
            "refutation_summary": "BYPASS FOUND again",
            "constraints": ["still exploitable"],
            "unified_diff": "",
            "files": ["src/reportsvc/exporter.py"],
            "lines_added": 1,
            "lines_removed": 0,
            "risk": "high",
            "policy_passed": True,
            "within_blast_radius": True,
            "diff_hash": "aaa",
            "expected_effect": "",
        }
    ],
    f"/api/runs/{RUN_ID}/gauntlet": [
        {
            "finding_handle": "V01",
            "iteration": 3,
            "verdict": "fail",
            "failing_stage": "exploit_mutation",
            "stages_passed": 1,
            "stages_total": 4,
            "stages": [
                {
                    "stage": "exploit_mutation",
                    "verdict": "fail",
                    "cases_total": 19,
                    "detail": "BYPASS FOUND",
                    "refuting_evidence": {"mutation": "separator:&"},
                }
            ],
        }
    ],
    f"/api/runs/{RUN_ID}/certificates": [
        {
            "id": CERT_ID,
            "finding_id": FINDING_ID,
            "serial": "KVX-2026-0009",
            "finding_handle": "V01",
            "assurance_level": "R",
            "certificate_hash": "deadbeef",
            "signature_algorithm": "HMAC-SHA256",
            "evidence_node_count": 4,
            "evidence_edge_count": 3,
            "grading_rationale": [],
            "limitations": ["This finding is not repaired."],
        }
    ],
}


PUBLISH_OK: dict[str, Any] = {
    "ok": True,
    "dry_run": True,
    "branch": "kavachx/kvx-1-v01-9ab3c1",
    "pull_request_url": "",
    "artifacts_written": ["src/reportsvc/exporter.py", ".kavachx/CHANGES.md"],
    "blocked_reason": "",
    "policy_violations": [],
    "payload_hash": "9f8e7d6c5b4a3928",
    "dry_run_payload": {
        "branch": "kavachx/kvx-1-v01-9ab3c1",
        "base_branch": "main",
        "base_sha": "c0ffee" * 6,
        "pull_request": {
            "title": "[KavachX] CRITICAL CWE-78 (Level B)",
            "head": "kavachx/kvx-1-v01-9ab3c1",
            "base": "main",
            "body": "## KavachX\n\n**Finding** `V01`\n",
        },
        "files": {
            "src/reportsvc/exporter.py": "# patched\n",
            ".kavachx/CHANGES.md": "# changes\n",
        },
        "guarantees": {"never_force_pushes": True},
    },
}


class StubApi:
    """Returns whatever the scenario provides, and nothing it was not given."""

    base = "http://stub"
    token = "stub"

    def __init__(self, data: dict[str, Any], publish: dict[str, Any]) -> None:
        self.data = data
        self.publish_result = publish

    def get(self, path: str, **_params: Any) -> Any:
        if "/verify" in path:
            return {"valid": True, "hash_matches": True, "signature_matches": True}
        return self.data.get(path, {})

    def get_raw(self, _path: str) -> bytes:
        return b'{"certificate": "document"}'

    def post(self, path: str, _body: dict | None = None) -> Any:
        return self.publish_result if path.endswith("/publish") else {}


RENDER_ACTS = (
    "act_index",
    "act_contract",
    "act_fuzz",
    "act_validate",
    "act_shield",
    "act_repair",
    "act_gauntlet",
    "act_certificate",
    "act_pull_request",
)


def _walk(scratch: Path, data: dict[str, Any], publish: dict[str, Any]):
    args = walkthrough.parse_args(["--no-color", "--clone-name", "verify-clone"])
    walk = walkthrough.Walkthrough(args)
    walk.api = StubApi(data, publish)
    walk.run = {"id": RUN_ID, "short_code": "KVX-VERIFY"}
    walk.detail = {"status": "AWAITING_APPROVAL", "time_to_protection_ms": 16234}
    walk.workdir = scratch / "out"
    walk.run_out = walk.workdir / "kvx-verify"
    walk.clone_path = scratch / "no-such-clone"
    return walk


def check_git_layer(scratch: Path) -> None:
    """The plumbing act 1 and act 12 depend on, exercised against a real repository."""
    print("[1] git layer — origin, clone, branch, commit, push")
    work = scratch / "git"
    work.mkdir(parents=True)

    origin = gitwork.build_origin(source=TARGET, workdir=work, name="verify", branch="main")
    assert origin.is_dir(), "build_origin produced no bare repository"

    clone = work / "clone"
    gitwork.clone(origin=origin, destination=clone)
    files = gitwork.tracked_files(clone)
    head = gitwork.head_sha(clone)
    assert files, "the clone contains no tracked files"
    assert len(head) == 40, f"HEAD is not a full sha: {head!r}"
    assert not any("__pycache__" in f or f.startswith(".git/") for f in files), (
        "cache files leaked into the imported tree"
    )
    print(f"    cloned {len(files)} files at {head[:12]} from {origin.name}")

    branch = "kavachx/verify-v01-abc123"
    sha, written = gitwork.commit_payload(
        repo=clone,
        branch=branch,
        files={"src/reportsvc/exporter.py": "# patched\n", ".kavachx/CHANGES.md": "# c\n"},
        message="fix(CWE-78): verify",
    )
    gitwork.push(clone, branch)
    assert gitwork.branch_exists_on_origin(clone, branch), "the branch never reached the origin"
    assert len(written) == 2, written
    assert branch in gitwork.log_graph(clone, 5)
    print(f"    committed {len(written)} files as {sha[:12]} and pushed to origin")

    # A payload path that escapes the clone must be refused, not written.
    try:
        gitwork.commit_payload(
            repo=clone, branch="kavachx/escape", files={"../escaped.txt": "x"}, message="no"
        )
    except gitwork.GitError:
        print("    payload path escaping the clone was refused")
    else:
        raise AssertionError("a payload path outside the clone was accepted")

    print("    OK\n")


def check_acts_render(scratch: Path) -> None:
    """Every act must survive a fully populated run and report PASS."""
    print("[2] every act renders a populated run")
    walk = _walk(scratch / "render", POPULATED, PUBLISH_OK)
    for name in RENDER_ACTS:
        getattr(walk, name)()
    walk.act_proof()

    failed = {k: v[1] for k, v in walk.checks.items() if not v[0]}
    assert not failed, f"acts reported FAIL on good data: {failed}"
    assert walk.certificate.get("serial") == "KVX-2026-0001"
    written = sorted(p.name for p in walk.run_out.glob("*"))
    assert any(n.startswith("certificate-") for n in written), written
    assert "patch-V01.diff" in written, written
    print(f"    {len(walk.checks)} checks all PASS, artifacts written: {len(written)}")
    print("    OK\n")


def check_acts_fail_honestly(scratch: Path) -> None:
    """The check that matters: with nothing to report, every act must record FAIL."""
    print("[3] every act FAILS when the run produced nothing")
    empty_publish = {
        "ok": False,
        "dry_run": True,
        "branch": "",
        "artifacts_written": [],
        "blocked_reason": "no verified patch exists for this finding",
        "policy_violations": [],
        "payload_hash": "",
    }
    walk = _walk(scratch / "empty", {}, empty_publish)
    for name in RENDER_ACTS:
        getattr(walk, name)()
    walk.act_proof()

    passing = {k: v[1] for k, v in walk.checks.items() if v[0]}
    assert not passing, f"acts reported PASS on an empty run: {passing}"
    print(f"    all {len(walk.checks)} checks correctly reported FAIL")

    # And a blocked publish must never be recorded as a pull request.
    assert walk.checks["pull_request"][0] is False
    assert not walk.pr_branch, "a branch was recorded despite the publisher blocking"
    print("    a blocked publish was not recorded as a pull request")
    print("    OK\n")


def check_unsuccessful_run_reports_failure(scratch: Path) -> None:
    """A run that did work and got nowhere must not be reported as a success.

    The empty-run scenario cannot catch this: with no records at all, several acts take an early
    return. Here every stage has records and every one of them failed, so each act runs its normal
    path and has to reach the right verdict from its own evidence.
    """
    print("[4] a run where every stage ran and every stage failed")
    blocked = {
        "ok": False,
        "dry_run": True,
        "branch": "",
        "artifacts_written": [],
        "blocked_reason": "Assurance Level R: the patch was refuted.",
        "policy_violations": [],
        "payload_hash": "",
    }
    walk = _walk(scratch / "unsuccessful", UNSUCCESSFUL, blocked)
    for name in RENDER_ACTS:
        getattr(walk, name)()
    walk.act_proof()

    must_fail = (
        "index",
        "contract",
        "fuzz",
        "validated",
        "shield",
        "repair",
        "gauntlet",
        "certificate",
        "pull_request",
    )
    wrong = {k: walk.checks[k][1] for k in must_fail if k in walk.checks and walk.checks[k][0]}
    assert not wrong, f"acts claimed success on a run that succeeded at nothing: {wrong}"
    print(f"    all {len(must_fail)} stages correctly reported FAIL despite having records")
    print("    OK\n")


def check_verdict_is_computed(scratch: Path) -> None:
    """run_all's exit code must follow the checks, not a constant."""
    print("[5] the final verdict is computed, not asserted")
    good = _walk(scratch / "verdict-good", POPULATED, PUBLISH_OK)
    good.record("x", True, "ok")
    assert all(ok for ok, _ in good.checks.values())

    bad = _walk(scratch / "verdict-bad", POPULATED, PUBLISH_OK)
    bad.record("x", True, "ok")
    bad.record("y", False, "did not happen")
    assert not all(ok for ok, _ in bad.checks.values())
    print("    a single FAIL flips the overall verdict")
    print("    OK\n")


def main() -> int:
    ui.configure(colour=False)
    if not TARGET.is_dir():
        print(f"FAIL: the analysis target is missing at {TARGET}")
        return 1

    scratch = Path(tempfile.mkdtemp(prefix="kx-verify-walkthrough-"))
    print(f"\nverifying the walkthrough — no server, no database, no network\nscratch: {scratch}\n")
    try:
        check_git_layer(scratch)
        check_acts_render(scratch)
        check_acts_fail_honestly(scratch)
        check_unsuccessful_run_reports_failure(scratch)
        check_verdict_is_computed(scratch)
    except AssertionError as exc:
        print(f"\nFAIL: {exc}")
        return 1
    except Exception as exc:  # a crash in an act is exactly what this exists to catch
        print(f"\nFAIL: {type(exc).__name__}: {exc}")
        return 1
    finally:
        gitwork.force_rmtree(scratch)
        shutil.rmtree(scratch, ignore_errors=True)

    print("RESULT: PASS - the git layer works, every act renders, and every act fails honestly.")
    print("Next: `python examples/platform-walkthrough/walkthrough.py` against a running backend.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
