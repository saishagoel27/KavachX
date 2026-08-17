"""Deliverable documents: CHANGES.md and REMAINING.md.

``CHANGES.md`` covers what was verified. ``REMAINING.md`` covers everything else — and it is the
more important of the two. A run that reports only its successes is a marketing document; the
value of this system is that the ledger of what it could *not* establish is generated from the
same state, with the same rigour, and cannot be omitted.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.models.enums import AssuranceLevel


def _stamp() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def render_changes(
    *,
    run: dict[str, Any],
    repository: dict[str, Any],
    entries: list[dict[str, Any]],
) -> str:
    """One section per verified fix."""
    lines: list[str] = [
        "# CHANGES",
        "",
        f"KavachX run `{run['short_code']}` — {_stamp()}",
        "",
        f"- **Repository** `{repository.get('full_name', 'unknown')}`",
        f"- **Branch** `{run.get('branch', '')}`",
        f"- **Commit** `{run.get('commit_sha', '')[:12] or 'n/a'}`",
        f"- **Pinned source** `sha256:{(run.get('pinned_source_sha256') or '')[:16]}`",
        f"- **Verified fixes** {len(entries)}",
        "",
        "> Every claim below is backed by a PRAMAAN certificate. The assurance levels are "
        "**bounded empirical assurance**, not formal proof — they state what was executed and "
        "observed, within the coverage that was achieved.",
        "",
    ]

    if not entries:
        lines += [
            "## No verified fixes",
            "",
            "This run produced no patch that survived the Refutation Gauntlet. See "
            "`REMAINING.md` for what was found and why nothing could be verified.",
            "",
        ]
        return "\n".join(lines)

    for entry in entries:
        finding = entry["finding"]
        patch = entry.get("patch") or {}
        certificate = entry.get("certificate") or {}
        clause = entry.get("clause")
        blast = entry.get("blast_radius") or {}
        gauntlet = entry.get("gauntlet") or {}

        lines += [
            f"## {finding['handle']} — {finding['title']}",
            "",
            "| | |",
            "| --- | --- |",
            f"| **Severity** | {finding['severity']} |",
            f"| **Weakness** | {finding.get('cwe') or 'unclassified'} |",
            f"| **Assurance** | **Level {certificate.get('assurance_level', '?')}** |",
            f"| **Certificate** | `{certificate.get('certificate_hash', '')[:32]}` |",
            f"| **Discovered by** | {finding.get('source_channel', 'unknown')} |",
            f"| **Patch iteration** | {patch.get('iteration', '?')} |",
            "",
            "### Root cause",
            "",
            f"`{finding.get('root_cause_location', 'unknown')}`"
            + ("" if finding.get("root_cause_verified") else " *(location unverified)*"),
            "",
            finding.get("root_cause_summary", "_not recorded_"),
            "",
        ]

        if clause:
            lines += [
                "### Violated SAMHITA clause",
                "",
                f"- **{clause['clause_id']}** — {clause['description']}",
                f"- Predicate: `{clause['predicate']}`",
                f"- Scope: `{clause.get('scope', '')}`",
                f"- Survived falsification against {clause.get('holdout_pass_count', 0)} "
                f"held-out observations",
                "",
            ]

        lines += [
            "### Evidence",
            "",
            f"- Reproduced **{finding.get('reproduction_count', 0)}×** in independent sandbox "
            f"processes",
            f"- Deterministic signal: `{finding.get('sanitizer_signal') or 'nonzero exit'}`"
            + (f" (exit {finding['exit_code']})" if finding.get("exit_code") is not None else ""),
            f"- Input hash `{(finding.get('input_hash') or '')[:16]}` · trace hash "
            f"`{(finding.get('trace_hash') or '')[:16]}`",
            "- The working exploit is withheld from this document (requires `finding:read_pov`).",
            "",
            "### Verification",
            "",
        ]
        for stage, verdict in (gauntlet.get("stages") or {}).items():
            symbol = "PASS" if verdict.get("verdict") == "pass" else "FAIL"
            lines.append(f"- `{stage}` **{symbol}** — {verdict.get('detail', '')}")
        lines.append("")

        lines += [
            "### Blast radius",
            "",
            f"- Regression scope: **{blast.get('regression_scope', 'unknown')}**",
            f"- {len(blast.get('direct_callers', []))} direct callers · "
            f"{len(blast.get('transitive_callers', []))} transitive · "
            f"{len(blast.get('modules', []))} modules",
            f"- {len(blast.get('clause_ids', []))} SAMHITA clauses re-checked",
            "",
            "### Files changed",
            "",
        ]
        for path in patch.get("files", []):
            lines.append(f"- `{path}`")
        lines += [
            "",
            f"Diff: +{patch.get('lines_added', 0)} / -{patch.get('lines_removed', 0)} "
            f"(`{(patch.get('diff_hash') or '')[:16]}`)",
            "",
        ]
        if entry.get("pull_request_url"):
            lines += [f"**Pull request:** {entry['pull_request_url']}", ""]
        else:
            lines += [
                "**Pull request:** not opened (awaiting human approval, or publishing disabled)",
                "",
            ]
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def render_remaining(
    *,
    run: dict[str, Any],
    repository: dict[str, Any],
    ledger: list[dict[str, Any]],
    refuted_patches: list[dict[str, Any]],
    falsified_clauses: list[dict[str, Any]],
    coverage: dict[str, Any],
    unreachable: list[dict[str, Any]],
    residual_risk: list[dict[str, Any]],
    human_review: list[dict[str, Any]],
    channel_notes: list[dict[str, Any]],
) -> str:
    lines: list[str] = [
        "# REMAINING",
        "",
        f"KavachX run `{run['short_code']}` — {_stamp()}",
        "",
        "Everything this run could **not** establish. Read this before treating the run as a "
        "clean bill of health.",
        "",
        "---",
        "",
        "## 1. Unvalidated hypotheses",
        "",
    ]

    if not ledger:
        lines += ["Every hypothesis reached a terminal validated or refuted state.", ""]
    else:
        lines += [
            "| ID | Location | Severity | Status | Why it could not be validated |",
            "| --- | --- | --- | --- | --- |",
        ]
        for entry in ledger:
            reason = (entry.get("reason") or "").replace("|", "\\|").replace("\n", " ")
            lines.append(
                f"| `{entry['handle']}` | `{entry.get('location', '')}` | "
                f"{entry.get('severity', '')} | {entry.get('status', '')} | {reason} |"
            )
        lines.append("")

    lines += ["## 2. Refuted patches", ""]
    if not refuted_patches:
        lines += ["No patch was refuted in this run.", ""]
    else:
        for patch in refuted_patches:
            lines += [
                f"### {patch.get('finding_handle', '?')} — patch iteration "
                f"{patch.get('iteration', '?')} — REFUTED",
                "",
                f"- **Refuting stage:** `{patch.get('failing_stage', 'unknown')}`",
                f"- **Refutation:** {patch.get('refutation_summary', '')}",
                f"- **Diff hash:** `{(patch.get('diff_hash') or '')[:16]}`",
                "",
                "**Refuting evidence**",
                "",
                "```json",
                _json(patch.get("refuting_evidence") or {}),
                "```",
                "",
                "**Constraint(s) added for the next iteration**",
                "",
            ]
            for constraint in patch.get("constraints", []):
                lines.append(f"- {constraint}")
            lines.append("")

    lines += ["## 3. Falsified SAMHITA clauses", ""]
    if not falsified_clauses:
        lines += ["No proposed clause was falsified.", ""]
    else:
        lines += [
            "These clauses were proposed but contradicted by held-out benign behaviour, so they "
            "are **not** available as evidence. They are listed because a rejected clause is "
            "itself information about the target.",
            "",
            "| Clause | Predicate | Scope | Why it was rejected |",
            "| --- | --- | --- | --- |",
        ]
        for clause in falsified_clauses[:40]:
            reason = (clause.get("falsification_reason") or "").replace("|", "\\|")
            lines.append(
                f"| `{clause['clause_id']}` | `{clause['predicate']}` | "
                f"`{clause.get('scope', '')}` | {reason} |"
            )
        lines.append("")

    lines += [
        "## 4. Coverage gaps",
        "",
        f"- Line coverage at verification time: **{coverage.get('percent', 0):.1f}%** "
        f"({coverage.get('covered_statements', 0)}/{coverage.get('total_statements', 0)} "
        "statements)",
        "- Code that did not execute was not verified by any dynamic stage.",
        "",
    ]
    for note in coverage.get("notes", []):
        lines.append(f"- {note}")
    lines.append("")

    lines += ["### Per-channel coverage", ""]
    for note in channel_notes:
        lines.append(f"**{note['channel']}**")
        lines.append("")
        for item in note.get("notes", []):
            lines.append(f"- {item}")
        lines.append("")

    lines += ["## 5. Unreachable code", ""]
    if not unreachable:
        lines += ["No candidate was dismissed purely on unreachability.", ""]
    else:
        for entry in unreachable:
            reason = entry.get("reason") or "no path from a declared entrypoint"
            lines.append(f"- `{entry.get('location', '')}` — {reason}")
        lines.append("")

    lines += ["## 6. Remaining risk", ""]
    if not residual_risk:
        lines += ["No residual risk was recorded.", ""]
    else:
        for entry in residual_risk:
            lines.append(
                f"- **{entry.get('kind', 'risk')}** at `{entry.get('location', '')}` — "
                f"{entry.get('detail', '')}"
            )
        lines.append("")

    lines += ["## 7. Decisions requiring human review", ""]
    if not human_review:
        lines += ["No decision was escalated.", ""]
    else:
        for entry in human_review:
            lines.append(f"- **{entry.get('subject', '')}** — {entry.get('detail', '')}")
        lines.append("")

    lines += [
        "---",
        "",
        "## Honesty statement",
        "",
        "KavachX reports bounded empirical assurance. It does not prove the absence of "
        "vulnerabilities, and no level in this run should be read as doing so. Specifically:",
        "",
        f"- Only the {coverage.get('percent', 0):.1f}% of statements that executed were "
        "dynamically verified.",
        "- Only the benign corpus present in the repository was used to establish behavioural "
        "equivalence.",
        "- Only the mutations that were actually executed were tried; an unattempted mutation is "
        "not a failed one.",
        "- Findings the run could not reproduce are listed above as unresolved, not as absent.",
        "",
    ]
    return "\n".join(lines)


def _json(value: Any) -> str:
    import json

    return json.dumps(value, indent=2, sort_keys=True, default=str)[:4000]


def build_remaining_inputs(
    *,
    ledger: list[dict[str, Any]],
    patches: list[dict[str, Any]],
    gauntlets: list[dict[str, Any]],
    clauses: list[dict[str, Any]],
    channel_results: list[dict[str, Any]],
    coverage_percent: float,
    covered_statements: int,
    total_statements: int,
    certificates: list[dict[str, Any]],
    world_model_summary: dict[str, Any],
    sandbox_stats: dict[str, Any],
) -> dict[str, Any]:
    """Derive every REMAINING.md section from run state.

    Nothing here is hand-authored per run: if the state says a stage was skipped, the document
    says so.
    """
    refuted: list[dict[str, Any]] = []
    for patch in patches:
        if patch.get("status") not in ("REFUTED", "WITHDRAWN", "POLICY_REJECTED", "APPLY_FAILED"):
            continue
        gauntlet = next(
            (
                g
                for g in gauntlets
                if g.get("iteration") == patch.get("iteration")
                and g.get("finding_handle") == patch.get("finding_handle")
            ),
            {},
        )
        failing_stage = gauntlet.get("failing_stage", "")
        stage_detail = next(
            (s for s in gauntlet.get("stages", []) if s.get("stage") == failing_stage),
            {},
        )
        refuted.append(
            {
                "finding_handle": patch.get("finding_handle", ""),
                "iteration": patch.get("iteration"),
                "diff_hash": patch.get("diff_hash", ""),
                "failing_stage": failing_stage or patch.get("status", ""),
                "refutation_summary": patch.get("refutation_summary")
                or "; ".join(str(v) for v in patch.get("policy_violations", [])),
                "refuting_evidence": stage_detail.get("refuting_evidence", {})
                or {"policy_violations": patch.get("policy_violations", [])},
                "constraints": patch.get("constraints", []),
            }
        )

    residual: list[dict[str, Any]] = []
    for certificate in certificates:
        level = certificate.get("assurance_level", "")
        if level == AssuranceLevel.B.value:
            for limitation in certificate.get("limitations", []):
                if limitation.startswith("unproved:"):
                    location = limitation.removeprefix("unproved:").split("—")[0].strip()
                    residual.append(
                        {
                            "kind": "unproved sibling candidate",
                            "location": location,
                            "detail": limitation,
                        }
                    )
        elif level == AssuranceLevel.C.value:
            for limitation in certificate.get("limitations", []):
                residual.append(
                    {
                        "kind": "incomplete verification",
                        "location": certificate.get("finding_handle", ""),
                        "detail": limitation,
                    }
                )
        elif level == AssuranceLevel.R.value:
            residual.append(
                {
                    "kind": "unrepaired finding (shield only)",
                    "location": certificate.get("finding_handle", ""),
                    "detail": (
                        "The patch was refuted and withdrawn. The reversible shield is the only "
                        "mitigation in place."
                    ),
                }
            )

    capabilities = sandbox_stats.get("capabilities") or {}
    if not capabilities.get("suitable_for_untrusted_code", False):
        residual.append(
            {
                "kind": "execution boundary",
                "location": f"sandbox adapter: {capabilities.get('adapter', 'unknown')}",
                "detail": (
                    "This run used an adapter that is not an isolation boundary for untrusted "
                    f"code. {capabilities.get('notes', '')}"
                ),
            }
        )

    human_review: list[dict[str, Any]] = [
        {
            "subject": f"{entry['handle']} ({entry.get('location', '')})",
            "detail": entry.get("reason", ""),
        }
        for entry in ledger
        if entry.get("status") == "UNKNOWN"
    ]
    for certificate in certificates:
        if certificate.get("assurance_level") in (
            AssuranceLevel.C.value,
            AssuranceLevel.R.value,
        ):
            human_review.append(
                {
                    "subject": f"{certificate.get('finding_handle', '')} — Level "
                    f"{certificate['assurance_level']}",
                    "detail": (
                        "Publishing requires an explicit human decision at this assurance level."
                    ),
                }
            )

    unreachable = [
        {
            "location": entry.get("location", ""),
            "reason": "no path from a declared entrypoint was found in the call graph",
        }
        for entry in ledger
        if "unreachable" in (entry.get("reason") or "").lower()
    ]

    coverage_notes = [
        f"world model: {world_model_summary.get('files', 0)} files, "
        f"{world_model_summary.get('functions', 0)} functions, "
        f"{world_model_summary.get('entrypoints', 0)} entrypoints, "
        f"{world_model_summary.get('sinks', 0)} candidate sinks "
        f"(graph source: {world_model_summary.get('graph_source', 'unknown')})",
        f"sandbox: {sandbox_stats.get('executions', 0)} executions, "
        f"{sandbox_stats.get('egress_bytes', 0)} bytes egress, "
        f"network enforced: {capabilities.get('network_enforced', False)}",
    ]

    return {
        "ledger": ledger,
        "refuted_patches": refuted,
        "falsified_clauses": [c for c in clauses if c.get("status") == "FALSIFIED"],
        "coverage": {
            "percent": coverage_percent,
            "covered_statements": covered_statements,
            "total_statements": total_statements,
            "notes": coverage_notes,
        },
        "unreachable": unreachable,
        "residual_risk": residual,
        "human_review": human_review,
        "channel_notes": [
            {"channel": r.get("channel", ""), "notes": r.get("coverage_notes", [])}
            for r in channel_results
        ],
    }
