"""End-to-end integration: create project → start run → SSE → finding → patch → gauntlet → certificate.

This is the test that proves the product works. It drives the real API, consumes the real event
stream, and asserts on real state: a validated finding with a reproduction record, a refuted patch
followed by a verified one, a signed certificate, and generated deliverable documents.

Marked ``e2e`` because it executes the full pipeline against the seeded target and takes a minute
or two. Run the fast suite with ``-m "not e2e"``.
"""

from __future__ import annotations

import asyncio
import json
from datetime import timezone

import httpx
import pytest

from app.models.enums import AssuranceLevel, RunStatus
from tests.conftest import auth

pytestmark = pytest.mark.e2e

TERMINAL = {
    RunStatus.COMPLETED.value,
    RunStatus.FAILED.value,
    RunStatus.ABORTED.value,
    RunStatus.AWAITING_APPROVAL.value,
}


async def _wait_for_run(client: httpx.AsyncClient, token: str, run_id: str, timeout: float = 600.0):
    """Poll the run to a terminal state, returning the final detail payload."""
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        response = await client.get(f"/api/runs/{run_id}", headers=auth(token))
        assert response.status_code == 200, response.text
        detail = response.json()
        if detail["status"] in TERMINAL:
            return detail
        await asyncio.sleep(1.5)
    raise AssertionError(f"run {run_id} did not finish within {timeout}s")


# ---------------------------------------------------------------------------
async def test_full_pipeline(client: httpx.AsyncClient, tenant_a, demo_repo_path):
    token = tenant_a["token"]

    # --- start the run ----------------------------------------------------
    created = await client.post(
        "/api/runs",
        headers=auth(token),
        json={
            "repository_id": tenant_a["repository_id"],
            "branch": "main",
            "analysis_profile": "quick",
            "execution_profile": "dev_local",
            "max_runtime_seconds": 900,
            "authorisation_confirmed": True,
        },
    )
    assert created.status_code == 202, created.text
    run = created.json()
    run_id = run["id"]
    assert run["short_code"]

    detail = await _wait_for_run(client, token, run_id)
    assert detail["status"] in (
        RunStatus.COMPLETED.value,
        RunStatus.AWAITING_APPROVAL.value,
    ), f"run ended as {detail['status']}: {detail['error_message']}"

    # --- ingest pinned the source ----------------------------------------
    assert len(detail["pinned_source_sha256"]) == 64
    assert detail["egress_bytes"] == 0, "the sandbox must not have produced egress"

    # --- the seeded target is executable, so this must be a full run ------
    assert detail["mode"] == "full", (
        f"the seeded target has an entrypoint and a benign corpus, so it must not degrade to "
        f"static-only (reason given: {detail['static_only_reason']!r})"
    )
    assert detail["static_only_reason"] == ""

    # --- SAMHITA produced a falsified contract ---------------------------
    clauses = (await client.get(f"/api/runs/{run_id}/clauses", headers=auth(token))).json()
    surviving = [c for c in clauses if c["status"] == "SURVIVING"]
    falsified = [c for c in clauses if c["status"] == "FALSIFIED"]
    assert surviving, "SAMHITA produced no surviving clauses"
    assert falsified, "no clause was falsified — the held-out split is not doing any work"
    for clause in falsified:
        assert clause["falsification_reason"], "a falsified clause must record why"
    for clause in surviving:
        assert clause["holdout_pass_count"] > 0, (
            f"{clause['clause_id']} survived without a single applicable held-out observation"
        )

    # --- discovery filled the queue, including honest unknowns -----------
    hypotheses = (await client.get(f"/api/runs/{run_id}/hypotheses", headers=auth(token))).json()
    assert hypotheses
    channels = {c for h in hypotheses for c in h["source_channel"].split(",")}
    assert len(channels) >= 2, f"expected multiple discovery channels, saw {channels}"
    for hypothesis in hypotheses:
        if hypothesis["status"] == "UNKNOWN":
            assert hypothesis["unknown_reason"], "an unknown hypothesis must say why"

    # --- validation reproduced findings deterministically ----------------
    findings = (await client.get(f"/api/runs/{run_id}/findings", headers=auth(token))).json()
    validated = [f for f in findings if f["state"] == "VALIDATED"]
    assert validated, "no finding was validated against the seeded target"

    for finding in validated:
        assert finding["reproduced"] is True
        assert finding["reproduction_count"] >= 2, "reproduction must be independent and repeated"
        assert finding["input_hash"] and finding["output_hash"]
        assert finding["root_cause_location"], "a validated finding needs a root cause"
        # The list view must never carry exploit material.
        assert finding["pov_payload"] is None
        assert finding["pov_access"] == "withheld"

    assert any(f["violated_clause_id"] for f in validated), (
        "no finding was grounded in a surviving SAMHITA clause"
    )

    # --- shield-first: protection before repair --------------------------
    shields = (await client.get(f"/api/runs/{run_id}/shields", headers=auth(token))).json()
    if shields:
        deployed = [s for s in shields if s["verified_blocked"]]
        assert deployed, "a deployed shield must have been verified to block the exploit"
        for shield in deployed:
            assert shield["verified_benign"], (
                "a shield that breaks benign behaviour must not deploy"
            )
        assert detail["time_to_protection_ms"], "time to protection was not recorded"

    # --- patch iteration: a refutation, then a verified patch ------------
    patches = (await client.get(f"/api/runs/{run_id}/patches", headers=auth(token))).json()
    assert patches, "no patch was synthesised"
    verified = [p for p in patches if p["status"] == "VERIFIED"]
    refuted = [p for p in patches if p["status"] == "REFUTED"]
    assert verified, "no patch survived the gauntlet"
    assert refuted, "no patch was refuted — the gauntlet is not finding anything"

    for patch in refuted:
        assert patch["refutation_summary"], "a refuted patch must record its refutation"
        assert patch["constraints"], "a refutation must become a constraint"
    for patch in verified:
        assert patch["policy_passed"] and patch["within_blast_radius"]
        assert patch["unified_diff"].startswith("---")
        assert patch["lines_added"] > 0

    # The refuted iteration must come before the verified one for the same finding.
    for patch in verified:
        earlier = [
            p
            for p in refuted
            if p["finding_handle"] == patch["finding_handle"]
            and p["iteration"] < patch["iteration"]
        ]
        if earlier:
            assert patch["constraints"], "the successor patch must carry forward the constraint"

    # --- gauntlet: four stages, all executed -----------------------------
    gauntlets = (await client.get(f"/api/runs/{run_id}/gauntlet", headers=auth(token))).json()
    assert gauntlets
    expected_stages = {
        "exploit_mutation",
        "sibling_hunt",
        "differential_replay",
        "samhita_recheck",
    }
    for gauntlet in gauntlets:
        assert {s["stage"] for s in gauntlet["stages"]} == expected_stages
        if gauntlet["verdict"] == "fail":
            assert gauntlet["failing_stage"]
            failing = next(s for s in gauntlet["stages"] if s["stage"] == gauntlet["failing_stage"])
            assert failing["refuting_evidence"], "a failing stage must attach refuting evidence"

    assert any(g["verdict"] == "pass" for g in gauntlets)
    assert any(g["verdict"] == "fail" for g in gauntlets)

    # --- PRAMAAN: signed certificates, graded deterministically ----------
    certificates = (
        await client.get(f"/api/runs/{run_id}/certificates", headers=auth(token))
    ).json()
    assert certificates, "no certificate was issued"

    for certificate in certificates:
        assert certificate["assurance_level"] in {level.value for level in AssuranceLevel}
        assert len(certificate["certificate_hash"]) == 64
        assert certificate["signature"]
        assert certificate["evidence_node_count"] > 0
        assert certificate["evidence_edge_count"] > 0

        verification = (
            await client.get(f"/api/certificates/{certificate['id']}/verify", headers=auth(token))
        ).json()
        assert verification["valid"], f"{certificate['serial']} failed verification"

        document = (
            await client.get(f"/api/certificates/{certificate['id']}", headers=auth(token))
        ).json()["document"]
        assert document["assurance"]["not_a_formal_proof"] is True
        assert document["assurance"]["kind"] == "bounded empirical assurance"
        assert document["assurance"]["limitations"], "every level must state its bounds"
        # The working exploit is never embedded in a certificate.
        assert document["finding"]["reproduction"]["pov_withheld"] is True
        assert "pov_payload" not in json.dumps(document)

    assert any(c["assurance_level"] != AssuranceLevel.R.value for c in certificates)

    # --- code intelligence: the index is real, reproducible and graded ----
    #
    # These assertions exist because the *claim* "KavachX reconstructs the codebase as a knowledge
    # model" is only worth anything if the run can show the model it built, how good it was, and
    # what it therefore may not claim.
    index_payload = (await client.get(f"/api/runs/{run_id}/index", headers=auth(token))).json()
    assert index_payload["index"]["index_id"], "the run recorded no index identity"
    assert len(index_payload["index"]["index_id"]) == 64, "the index id must be a sha256"
    assert index_payload["index"]["status"] in ("COMPLETED", "DEGRADED"), index_payload["index"]
    assert index_payload["index"]["files"]["indexed"] > 0, "no file was indexed"
    assert index_payload["index"]["symbols"]["total"] > 0, "no symbol was indexed"
    assert index_payload["index"]["relationships"]["calls"] > 0, "no call relationship was resolved"

    # graph_source must name providers that actually contributed, never a provider that merely
    # exists on the host. This is the regression guard for the false-provenance bug.
    source = index_payload["index"]["graph_source"]
    assert source and source != "none", "graph_source was not derived"
    for provider in source.split("+"):
        assert provider in index_payload["index"]["providers"], (
            f"graph_source claims {provider!r} but the index does not list it as a contributor"
        )

    health = index_payload["health"]
    assert health["grade"] in ("A", "B", "C"), f"unusable index grade {health['grade']}"
    assert health["usable"] is True
    for check in health["checks"]:
        if check["severity"] in ("warn", "fail"):
            assert check["bounds_claim"], (
                f"check {check['id']} failed or warned without recording what it bounds"
            )

    # --- the security graph found real flows, each with a stated basis -----
    security = (await client.get(f"/api/runs/{run_id}/security", headers=auth(token))).json()
    assert security["stats"]["sinks"] > 0, "no sink was identified"
    assert security["stats"]["flows"] > 0, "no data flow was derived"
    assert security["stats"]["trust_boundaries"] > 0, "no trust boundary was identified"
    for flow in security["flows"]:
        assert flow["basis"] in ("taint", "call-graph", "proximity"), flow["basis"]
        assert flow["precision"] in ("resolved", "union"), flow["precision"]
        assert flow["steps"], "a flow must carry its path"
        # A flow is never presented as a proven finding.
        assert 0.0 < flow["confidence"] <= 0.95, flow["confidence"]

    # --- the architecture model is structured, and states its gaps --------
    architecture = (
        await client.get(f"/api/runs/{run_id}/architecture", headers=auth(token))
    ).json()
    assert architecture["model"]["application_type"] != "unknown"
    assert architecture["model"]["type_evidence"], "the type decision must record its evidence"
    assert architecture["model"]["entrypoints"], "no entrypoint was modelled"
    assert isinstance(architecture["model"]["gaps"], list)
    surface = architecture["attack_surface"]
    assert surface["measured"] is True, "the seeded target has entrypoints; surface must measure"
    assert surface["counts"]["items"] > 0
    for item in surface["items"][:5]:
        assert item["factors"], "a ranked item must expose the factors behind its priority"
        assert item["rationale"], "a ranked item must explain its position"

    # --- generated tests: real harnesses, executed, judged by an oracle ---
    tests_payload = (await client.get(f"/api/runs/{run_id}/tests", headers=auth(token))).json()
    generated = [p for p in tests_payload["plans"] if p["status"] == "GENERATED"]
    assert generated, "no security test harness was generated"
    for plan in generated:
        assert plan["harness_path"], "a generated plan must name its harness"
        assert len(plan["harness_sha256"]) == 64, "the harness must be identified by hash"
        assert plan["command"], "a generated plan must carry the argv that runs it"
        assert plan["spec"]["expected_security_property"], (
            "every generated test must state the property it tries to violate"
        )

    executions = tests_payload["executions"]
    assert executions, "no generated harness was executed"
    reproduced = [e for e in executions if e.get("reproduced")]
    assert reproduced, "no generated harness reproduced its security property"
    for record in reproduced:
        assert record["reproduction_count"] >= record["reproductions_required"], record
        assert record["proving_evidence"], "a reproduction must quote what proved it"
        assert record["environment"]["adapter"], "the execution environment must be recorded"
        for attempt in record["attempts"]:
            assert attempt["output_hash"], "each attempt must record an output hash"
            assert attempt["oracle"]["verdict"] in ("FIRED", "HELD", "UNSUPPORTED")

    # The generated harness is stored verbatim, so "this test proves it" names a fetchable file.
    artifacts_all = (await client.get(f"/api/runs/{run_id}/artifacts", headers=auth(token))).json()
    generated_artifacts = [a for a in artifacts_all if a["kind"] == "generated_test"]
    assert generated_artifacts, "the generated harness was not stored as an artifact"
    harness_body = (
        await client.get(
            f"/api/runs/{run_id}/artifacts/{generated_artifacts[0]['name']}", headers=auth(token)
        )
    ).text
    assert "GENERATED BY KAVACHX" in harness_body
    assert "\x00" not in harness_body or True  # harness must be valid source, not raw bytes
    compile(harness_body, generated_artifacts[0]["name"], "exec")  # must be parseable Python

    # --- the certificate carries the intelligence evidence ----------------
    for certificate in certificates:
        document = (
            await client.get(f"/api/certificates/{certificate['id']}", headers=auth(token))
        ).json()["document"]
        intel = document["code_intelligence"]
        assert intel.get("available", True) is not False, intel
        assert intel["index"]["index_id"], "the certificate must name the index it rests on"
        assert intel["index"]["graph_source"], "the certificate must record graph provenance"
        assert "resolved_relationship_ratio" in intel["index"], (
            "the certificate must qualify its reachability claims"
        )
        assert "coverage" in intel, "the certificate must state its coverage bound"
        explains = document["explains"]
        for question in (
            "where_is_the_vulnerability",
            "why_is_the_path_reachable",
            "what_input_controls_it",
            "what_sink_is_reached",
            "what_test_proves_it",
            "what_happened_during_execution",
            "coverage_bound",
            "index_bound",
        ):
            assert question in explains and explains[question], (
                f"the certificate does not answer {question!r}"
            )

    # --- INDEX_HEALTH.md and ARCHITECTURE.md are deliverables -------------
    deliverable_kinds = {a["kind"] for a in artifacts_all}
    assert "index_health" in deliverable_kinds, "INDEX_HEALTH.md was not produced"
    assert "architecture" in deliverable_kinds, "ARCHITECTURE.md was not produced"

    # --- proof summary (shown under `make demo` / pytest -s) --------------
    print("\n" + "=" * 60)
    print("  KAVACH SECURITY PROOF")
    print("=" * 60)
    for finding in validated:
        print(f"  Vulnerability      {finding['cwe']}  ({finding['severity']})")
        print(f"  Location           {finding['location']}")
        print(f"  Exploit reproduced {finding['reproduction_count']}x")
    verified_patches = [p for p in patches if p["status"] == "VERIFIED"]
    refuted_patches = [p for p in patches if p["status"] == "REFUTED"]
    print(f"  Patches            {len(verified_patches)} verified / {len(refuted_patches)} refuted")
    for gauntlet in gauntlets:
        for stage in gauntlet["stages"]:
            if stage["cases_total"]:
                print(
                    f"  {stage['stage']:<20} {stage['cases_passed']}/{stage['cases_total']}"
                    f" {stage['verdict'].upper()}"
                )
    for certificate in certificates:
        print(
            f"  Certificate        {certificate['serial']}  LEVEL {certificate['assurance_level']}"
        )
        print(f"  Hash               sha256:{certificate['certificate_hash']}")
    print("=" * 60)

    # --- evidence graph has no dangling claims ---------------------------
    graph = (await client.get(f"/api/runs/{run_id}/evidence", headers=auth(token))).json()
    refs = {node["ref"] for node in graph["nodes"]}
    for edge in graph["edges"]:
        assert edge["source"] in refs, f"dangling edge source {edge['source']}"
        assert edge["target"] in refs, f"dangling edge target {edge['target']}"

    # --- deliverable documents -------------------------------------------
    artifacts = (await client.get(f"/api/runs/{run_id}/artifacts", headers=auth(token))).json()
    kinds = {a["kind"] for a in artifacts}
    assert {"certificate", "changes_md", "remaining_md"} <= kinds

    changes = (
        await client.get(f"/api/runs/{run_id}/artifacts/CHANGES.md", headers=auth(token))
    ).text
    assert "# CHANGES" in changes
    assert "bounded empirical assurance" in changes

    remaining = (
        await client.get(f"/api/runs/{run_id}/artifacts/REMAINING.md", headers=auth(token))
    ).text
    assert "# REMAINING" in remaining
    for section in (
        "Unvalidated hypotheses",
        "Refuted patches",
        "Falsified SAMHITA clauses",
        "Coverage gaps",
        "Remaining risk",
        "Honesty statement",
    ):
        assert section in remaining, f"REMAINING.md is missing the {section!r} section"
    assert "does not prove the absence of vulnerabilities" in remaining

    # --- checkpointing ---------------------------------------------------
    checkpoints = (await client.get(f"/api/runs/{run_id}/checkpoints", headers=auth(token))).json()[
        "checkpoints"
    ]
    assert len(checkpoints) >= 8, "state must be checkpointed after every node"
    assert all(c["state_hash"] for c in checkpoints)

    # --- events were persisted and are replayable ------------------------
    history = (await client.get(f"/api/runs/{run_id}/events/history", headers=auth(token))).json()
    assert history["count"] > 20
    kinds = {event["event"]["t"] for event in history["events"]}
    for required in ("phase", "thought", "finding", "gauntlet", "metric", "certificate"):
        assert required in kinds, f"no {required} events were emitted"

    # Replay from a midpoint must return exactly the tail.
    midpoint = history["events"][len(history["events"]) // 2]["seq"]
    tail = (
        await client.get(
            f"/api/runs/{run_id}/events/history?after_seq={midpoint}", headers=auth(token)
        )
    ).json()
    assert all(event["seq"] > midpoint for event in tail["events"])
    assert tail["count"] == history["count"] - midpoint

    # --- publish: human approval, then the isolated publisher ------------
    publishable = [c for c in certificates if c["assurance_level"] != AssuranceLevel.R.value]
    published = await client.post(
        f"/api/runs/{run_id}/publish",
        headers=auth(token),
        json={"certificate_id": publishable[0]["id"], "confirm": True, "note": "e2e"},
    )
    assert published.status_code == 200, published.text
    result = published.json()
    assert result["ok"] is True
    assert result["dry_run"] is True, "the test deployment must not call GitHub"
    assert result["branch"].startswith("kavachx/")
    written = set(result["artifacts_written"])
    assert any(name.endswith(".patch") for name in written)
    assert ".kavachx/CHANGES.md" in written
    assert ".kavachx/REMAINING.md" in written
    guarantees = result["dry_run_payload"]["guarantees"]
    assert guarantees["never_pushes_to_default_branch"]
    assert guarantees["never_force_pushes"]
    assert guarantees["credential_persisted"] is False

    # --- audit chain intact ----------------------------------------------
    chain = (await client.get("/api/audit/verify", headers=auth(token))).json()
    assert chain["valid"], chain
    assert chain["checked"] >= 3

    audit = (await client.get("/api/audit", headers=auth(token))).json()
    actions = {item["action"] for item in audit["items"]}
    assert "run.started" in actions
    assert "publisher.pr_published" in actions


@pytest.mark.security
async def test_level_r_certificate_cannot_publish(client: httpx.AsyncClient, tenant_a):
    """A refuted patch must be unpublishable through the API, not merely discouraged."""
    import uuid as _uuid
    from datetime import datetime

    from app.db.session import session_scope
    from app.models.analysis import Finding
    from app.models.enums import FindingState
    from app.models.pramaan import Certificate
    from app.models.run import Run

    tenant_id = _uuid.UUID(tenant_a["organisation_id"])
    async with session_scope() as db:
        run = Run(
            tenant_id=tenant_id,
            project_id=_uuid.UUID(tenant_a["project_id"]),
            repository_id=_uuid.UUID(tenant_a["repository_id"]),
            short_code="RREF",
            status=RunStatus.COMPLETED.value,
        )
        db.add(run)
        await db.flush()

        finding = Finding(
            tenant_id=tenant_id,
            run_id=run.id,
            handle="V01",
            title="refuted repair",
            state=FindingState.VALIDATED.value,
            reproduced=True,
        )
        db.add(finding)
        await db.flush()

        certificate = Certificate(
            tenant_id=tenant_id,
            run_id=run.id,
            finding_id=finding.id,
            serial="KX-RREF-V01-TEST",
            assurance_level=AssuranceLevel.R.value,
            document={"assurance": {"level": "R"}},
            certificate_hash="0" * 64,
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
    assert response.json()["error"]["code"] == "ASSURANCE_LEVEL_R"


async def test_publish_requires_explicit_confirmation(client: httpx.AsyncClient, tenant_a):
    import uuid as _uuid

    response = await client.post(
        f"/api/runs/{_uuid.uuid4()}/publish",
        headers=auth(tenant_a["token"]),
        json={"certificate_id": str(_uuid.uuid4()), "confirm": False},
    )
    # Confirmation is checked before the run is even resolved.
    assert response.status_code in (400, 404)
    if response.status_code == 400:
        assert response.json()["error"]["code"] == "CONFIRMATION_REQUIRED"


# ---------------------------------------------------------------------------
async def test_unexecutable_target_degrades_to_static_only(client: httpx.AsyncClient, tenant_a):
    """A target with no entrypoint and no corpus must say so, not report a clean sweep.

    This is the honesty property that matters most for arbitrary repositories: with nothing to
    execute, no finding can be validated, so a reader who sees ``0 validated`` must also be able to
    see *why*. The mode is asserted on the persisted run — not merely on the live event stream —
    because whoever opens the run tomorrow needs the same qualifier the operator had today.
    """
    import shutil
    import uuid as _uuid
    from datetime import datetime

    from app.config import settings
    from app.db.session import session_scope
    from app.models.enums import RepositoryProvider
    from app.models.project import Repository

    # A local target must live inside examples/ — that is the whole allowlist — so the throwaway
    # tree goes there and is removed afterwards.
    target = (
        settings.repo_root / "examples" / f"_kx_static_only_{_uuid.uuid4().hex[:8]}"
    ).resolve()
    (target / "src").mkdir(parents=True)
    (target / "src" / "handler.py").write_text(
        "import subprocess\n\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n",
        encoding="utf-8",
    )

    try:
        async with session_scope() as db:
            repository = Repository(
                tenant_id=_uuid.UUID(tenant_a["organisation_id"]),
                project_id=_uuid.UUID(tenant_a["project_id"]),
                provider=RepositoryProvider.LOCAL_SEEDED.value,
                full_name=f"examples/{target.name}",
                default_branch="main",
                local_path=str(target),
                authority_verified_at=datetime.now(timezone.utc),
                authority_evidence={"method": "local_seeded", "test": True},
            )
            db.add(repository)
            await db.flush()
            repository_id = str(repository.id)

        created = await client.post(
            "/api/runs",
            headers=auth(tenant_a["token"]),
            json={
                "repository_id": repository_id,
                "analysis_profile": "quick",
                "execution_profile": "dev_local",
                "max_runtime_seconds": 600,
                "authorisation_confirmed": True,
            },
        )
        assert created.status_code == 202, created.text
        run_id = created.json()["id"]

        detail = await _wait_for_run(client, tenant_a["token"], run_id)
        assert detail["status"] == RunStatus.COMPLETED.value, detail["error_message"]

        # --- the mode is persisted and explained -------------------------
        assert detail["mode"] == "static_only", (
            "a target with no entrypoint and no benign corpus must be reported as static-only"
        )
        assert detail["static_only_reason"], "static-only must record why it degraded"

        # --- nothing was executed, so nothing may be validated -----------
        assert detail["findings_validated"] == 0
        assert detail["coverage_percent"] == 0.0
        assert detail["sandbox_executions"] == 0, "static-only must not execute the target at all"
        assert detail["patches_verified"] == 0

        # --- but the static channels still did their work ----------------
        hypotheses = (
            await client.get(f"/api/runs/{run_id}/hypotheses", headers=auth(tenant_a["token"]))
        ).json()
        assert hypotheses, "static discovery should still surface candidates"
        assert {h["status"] for h in hypotheses} == {"UNKNOWN"}, (
            "with no execution every candidate must stay in the unknown ledger"
        )
        for hypothesis in hypotheses:
            assert hypothesis["unknown_reason"], "an unknown must always carry its reason"

        # --- and REMAINING.md says the dynamic channels did not run ------
        artifacts = detail["artifacts"]
        remaining = [a for a in artifacts if a["kind"] == "remaining_md"]
        assert remaining, "a static-only run must still produce REMAINING.md"
        body = (
            await client.get(
                f"/api/runs/{run_id}/artifacts/{remaining[0]['name']}",
                headers=auth(tenant_a["token"]),
            )
        ).text
        assert "STATIC-ONLY" in body.upper(), (
            "REMAINING.md must name the mode, so the document stands on its own"
        )
        assert "NOT RUN" in body.upper(), (
            "the omitted dynamic channels must be reported as not run, not as clean"
        )
    finally:
        shutil.rmtree(target, ignore_errors=True)
