"""Index validation — because successful parsing is not successful indexing.

A parser that returns without raising has not told you that it understood the repository. It can
return zero symbols for a whole language, resolve no imports, find no entrypoints, or quietly skip
a third of the tree, and every one of those failures looks identical from the outside: an index
object that exists.

This module runs deterministic checks over the produced index and grades the result. The grade is
not decoration — it bounds what the run may claim. An index with no entrypoints cannot support a
reachability claim; an index that skipped 40% of the tree cannot support "no vulnerabilities
found". Those bounds are written into the report, surfaced in the console and carried into the
certificate.

Every check is a pure function of the index. There is no model involved in deciding whether an
index is healthy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.core.logging import get_logger
from app.indexing.job import IndexJob
from app.indexing.model import CodeGraph, Provider

logger = get_logger(__name__)


class Severity:
    """Check severities. ``FAIL`` degrades the index; it never silently passes."""

    OK = "ok"
    INFO = "info"
    WARN = "warn"
    FAIL = "fail"


class Grade:
    """Overall index fidelity.

    * ``A`` — every supported file indexed, relationships largely resolved, entrypoints found.
    * ``B`` — usable, with named gaps (a missing grammar, some skipped files, unresolved imports).
    * ``C`` — substantial gaps: reachability is unmeasurable or coverage is poor. Findings built on
      it are leads, not measurements.
    * ``F`` — the index cannot support analysis at all.
    """

    A = "A"
    B = "B"
    C = "C"
    F = "F"


@dataclass(slots=True)
class Check:
    id: str
    severity: str
    title: str
    detail: str
    #: What this check's outcome forbids the run from claiming. Empty when it passed.
    bounds_claim: str = ""
    metrics: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "bounds_claim": self.bounds_claim,
            "metrics": self.metrics,
        }


@dataclass
class IndexHealthReport:
    grade: str = Grade.F
    checks: list[Check] = field(default_factory=list)
    #: Claims this index cannot support, collected from every failing/warning check.
    claim_bounds: list[str] = field(default_factory=list)
    summary: str = ""

    @property
    def failures(self) -> list[Check]:
        return [c for c in self.checks if c.severity == Severity.FAIL]

    @property
    def warnings(self) -> list[Check]:
        return [c for c in self.checks if c.severity == Severity.WARN]

    @property
    def usable(self) -> bool:
        """False only when the index cannot support any analysis."""
        return self.grade != Grade.F

    def as_dict(self) -> dict[str, Any]:
        return {
            "grade": self.grade,
            "usable": self.usable,
            "summary": self.summary,
            "checks": [c.as_dict() for c in self.checks],
            "claim_bounds": self.claim_bounds,
            "counts": {
                "ok": len([c for c in self.checks if c.severity == Severity.OK]),
                "info": len([c for c in self.checks if c.severity == Severity.INFO]),
                "warn": len(self.warnings),
                "fail": len(self.failures),
            },
        }

    def render(self, job: IndexJob) -> str:
        """The plain-text INDEX HEALTH block, as the spec lays it out."""
        lines = [
            "INDEX HEALTH",
            "",
            f"Repository: {job.repository or '(unnamed)'}",
            f"Commit: {job.commit_sha or '(none)'}",
            f"Index:  {job.index_id[:16]}  ({job.graph_source})",
            f"Grade:  {self.grade}",
            "",
            "Files:",
            f"  discovered: {job.files_discovered}",
            f"  indexed:    {job.files_indexed}",
            f"  skipped:    {job.files_skipped}",
            "",
            "Symbols:",
            f"  functions: {job.functions}",
            f"  classes:   {job.classes}",
            "",
            "Relationships:",
            f"  calls:    {job.call_relationships}",
            f"  imports:  {job.import_relationships}",
            f"  resolved: {job.resolved_relationships} of {job.relationships_discovered}"
            f" ({job.resolved_ratio * 100:.0f}%)",
            "",
            f"Entrypoints:  {job.entrypoints_discovered}",
            f"Tests:        {job.tests_discovered}",
            f"Configs:      {job.configs_discovered}",
            f"Dependencies: {job.dependencies_discovered}",
        ]
        if self.warnings or self.failures:
            lines += ["", "Warnings:"]
            for check in [*self.failures, *self.warnings]:
                lines.append(f"  [{check.severity.upper()}] {check.title} — {check.detail}")
        if self.claim_bounds:
            lines += ["", "This index cannot support:"]
            lines += [f"  - {bound}" for bound in self.claim_bounds]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
def validate(job: IndexJob, graph: CodeGraph) -> IndexHealthReport:
    """Run every check and grade the index."""
    report = IndexHealthReport()
    checks: list[Check] = []

    checks.append(_check_non_empty(job, graph))
    checks.append(_check_file_coverage(job))
    checks.append(_check_symbols(job, graph))
    checks.append(_check_relationships(job, graph))
    checks.append(_check_resolution(job))
    checks.append(_check_entrypoints(job, graph))
    checks.append(_check_grammars(job))
    checks.append(_check_provider_availability(job))
    checks.append(_check_empty_sections(job, graph))
    checks.append(_check_language_parity(job, graph))

    report.checks = [c for c in checks if c is not None]
    report.claim_bounds = [
        c.bounds_claim
        for c in report.checks
        if c.bounds_claim and c.severity in (Severity.WARN, Severity.FAIL)
    ]
    report.grade = _grade(report)
    report.summary = _summarise(report, job)

    logger.info(
        "indexing.health",
        grade=report.grade,
        failures=len(report.failures),
        warnings=len(report.warnings),
    )
    return report


# ---------------------------------------------------------------------------
def _check_non_empty(job: IndexJob, graph: CodeGraph) -> Check:
    if len(graph) == 0:
        return Check(
            id="index.non_empty",
            severity=Severity.FAIL,
            title="The index is empty",
            detail=(
                "No nodes were produced for this tree. Either it contains no source in a "
                "supported language, or every parser failed."
            ),
            bounds_claim="any statement about this repository's code",
            metrics={"nodes": 0},
        )
    return Check(
        id="index.non_empty",
        severity=Severity.OK,
        title="Index is non-empty",
        detail=f"{len(graph)} nodes, {len(graph.edges)} relationships.",
        metrics={"nodes": len(graph), "edges": len(graph.edges)},
    )


def _check_file_coverage(job: IndexJob) -> Check:
    ratio = job.coverage_ratio
    metrics = {
        "discovered": job.files_discovered,
        "indexed": job.files_indexed,
        "skipped": job.files_skipped,
        "ratio": ratio,
    }
    if job.files_discovered == 0:
        return Check(
            id="index.file_coverage",
            severity=Severity.FAIL,
            title="No files were discovered",
            detail="The walker found nothing to index under the pinned tree.",
            bounds_claim="any statement about this repository's contents",
            metrics=metrics,
        )
    if ratio >= 0.98:
        return Check(
            id="index.file_coverage",
            severity=Severity.OK,
            title="File coverage is complete",
            detail=f"{job.files_indexed} of {job.files_discovered} files analysed.",
            metrics=metrics,
        )
    severity = Severity.WARN if ratio >= 0.75 else Severity.FAIL
    return Check(
        id="index.file_coverage",
        severity=severity,
        title=f"{job.files_skipped} file(s) were not analysed",
        detail=(
            f"{job.files_indexed} of {job.files_discovered} files analysed "
            f"({ratio * 100:.0f}%). Skipped files are still hashed as part of the pinned tree "
            "but contribute no symbols, relationships or sinks."
        ),
        bounds_claim=(
            f"the absence of weaknesses in the {job.files_skipped} unanalysed file(s)"
        ),
        metrics=metrics,
    )


def _check_symbols(job: IndexJob, graph: CodeGraph) -> Check:
    metrics = {"symbols": job.symbols_discovered, "functions": job.functions}
    if job.symbols_discovered == 0:
        return Check(
            id="index.symbols",
            severity=Severity.FAIL,
            title="No symbols were extracted",
            detail=(
                "Files were indexed but no function or class definitions were recovered from "
                "any of them, which means no symbol-level analysis is possible."
            ),
            bounds_claim="any function-level or reachability claim",
            metrics=metrics,
        )
    # A tree with many code files and almost no functions usually means a parser mismatch.
    code_files = sum(
        count
        for language, count in job.languages.items()
        if language in ("python", "c", "javascript")
    )
    if code_files >= 5 and job.functions < code_files // 2:
        return Check(
            id="index.symbols",
            severity=Severity.WARN,
            title="Suspiciously few functions for the amount of code",
            detail=(
                f"{job.functions} function(s) across {code_files} source file(s). A parser may "
                "have silently failed on this language or dialect."
            ),
            bounds_claim="complete symbol coverage of this repository",
            metrics={**metrics, "code_files": code_files},
        )
    return Check(
        id="index.symbols",
        severity=Severity.OK,
        title="Symbols extracted",
        detail=f"{job.functions} function(s), {job.classes} class(es).",
        metrics=metrics,
    )


def _check_relationships(job: IndexJob, graph: CodeGraph) -> Check:
    metrics = {
        "relationships": job.relationships_discovered,
        "calls": job.call_relationships,
        "imports": job.import_relationships,
    }
    if job.relationships_discovered == 0:
        return Check(
            id="index.relationships",
            severity=Severity.FAIL,
            title="No relationships were resolved",
            detail="The graph has nodes but no edges, so it is a symbol list, not a graph.",
            bounds_claim="any reachability, caller/callee or blast-radius claim",
            metrics=metrics,
        )
    if job.call_relationships == 0:
        return Check(
            id="index.relationships",
            severity=Severity.WARN,
            title="No call relationships were found",
            detail=(
                "Structural relationships exist but no call edges. Reachability cannot be "
                "measured, so candidate ranking falls back to severity."
            ),
            bounds_claim="any reachability claim for this target",
            metrics=metrics,
        )
    return Check(
        id="index.relationships",
        severity=Severity.OK,
        title="Relationships resolved",
        detail=(
            f"{job.call_relationships} call and {job.import_relationships} import "
            f"relationship(s) of {job.relationships_discovered} total."
        ),
        metrics=metrics,
    )


def _check_resolution(job: IndexJob) -> Check:
    """How much of the graph is resolved fact vs. name match.

    This is the check that most directly qualifies a reachability claim, which is why it reports
    the ratio rather than a boolean.
    """
    ratio = job.resolved_ratio
    metrics = {
        "resolved": job.resolved_relationships,
        "total": job.relationships_discovered,
        "ratio": ratio,
    }
    if job.relationships_discovered == 0:
        return Check(
            id="index.resolution",
            severity=Severity.INFO,
            title="Resolution not applicable",
            detail="There are no relationships to resolve.",
            metrics=metrics,
        )
    if ratio >= 0.6:
        return Check(
            id="index.resolution",
            severity=Severity.OK,
            title="Relationships are mostly resolved",
            detail=(
                f"{ratio * 100:.0f}% of relationships were confirmed by a symbol-resolving "
                "indexer rather than matched by name."
            ),
            metrics=metrics,
        )
    return Check(
        id="index.resolution",
        severity=Severity.WARN,
        title="Most relationships are name matches, not resolved references",
        detail=(
            f"Only {ratio * 100:.0f}% of relationships were resolved by a symbol-resolving "
            "indexer. The rest are name matches, which over-approximate: a call edge may point "
            "at a different function that happens to share a name."
        ),
        bounds_claim=(
            "a precise reachability claim — paths at 'union' precision may include calls that "
            "cannot actually occur"
        ),
        metrics=metrics,
    )


def _check_entrypoints(job: IndexJob, graph: CodeGraph) -> Check:
    metrics = {"entrypoints": job.entrypoints_discovered}
    if job.entrypoints_discovered == 0:
        return Check(
            id="index.entrypoints",
            severity=Severity.WARN,
            title="No entrypoints were found",
            detail=(
                "Nothing in this tree matched an entrypoint convention (a __main__ guard, an "
                "HTTP route decorator, a known handler name). Without an entrypoint there is no "
                "path to search, so reachability is not measured and priority falls back to "
                "severity."
            ),
            bounds_claim=(
                "any claim that a weakness is or is not externally reachable in this target"
            ),
            metrics=metrics,
        )
    return Check(
        id="index.entrypoints",
        severity=Severity.OK,
        title="Entrypoints found",
        detail=f"{job.entrypoints_discovered} entrypoint(s) identified.",
        metrics=metrics,
    )


def _check_grammars(job: IndexJob) -> Check:
    grammars = dict(job.versions.get("grammars") or {})
    missing = sorted([language for language, available in grammars.items() if not available])
    present_languages = {
        language for language, count in job.languages.items() if count > 0
    }
    # Only complain about a missing grammar for a language this repository actually contains.
    relevant = [language for language in missing if language in present_languages]
    if not relevant:
        return Check(
            id="index.grammars",
            severity=Severity.OK,
            title="Parsers available for every language present",
            detail=(
                "Grammars: "
                + ", ".join(f"{k}={'yes' if v else 'no'}" for k, v in sorted(grammars.items()))
            ),
            metrics={"grammars": grammars},
        )
    return Check(
        id="index.grammars",
        severity=Severity.WARN,
        title=f"No parser for {', '.join(relevant)}",
        detail=(
            f"This repository contains {', '.join(relevant)} but no tree-sitter grammar loaded "
            "for it, so those files were indexed by the conservative regex fallback (fewer "
            "symbols, no call sites) or not at all."
        ),
        bounds_claim=f"complete symbol or call coverage of the {', '.join(relevant)} code",
        metrics={"grammars": grammars, "missing_relevant": relevant},
    )


def _check_provider_availability(job: IndexJob) -> Check:
    """Did the code-knowledge-graph provider actually run?

    Reported as INFO rather than WARN when GitNexus is deliberately disabled, and as WARN when it
    was expected but failed — the operator needs to tell "I turned it off" apart from "it broke".
    """
    from app.config import settings

    gitnexus_report = (job.provider_reports or {}).get("gitnexus") or {}
    contributed = Provider.GITNEXUS.value in job.providers
    metrics = {
        "gitnexus_enabled": settings.gitnexus_enabled,
        "gitnexus_contributed": contributed,
        "gitnexus_version": job.versions.get("gitnexus_version", ""),
    }

    if contributed:
        return Check(
            id="index.provider",
            severity=Severity.OK,
            title="Code knowledge graph provider ran",
            detail=(
                f"GitNexus {job.versions.get('gitnexus_version', '?')} contributed resolved "
                "symbols and relationships."
            ),
            metrics=metrics,
        )
    if not settings.gitnexus_enabled:
        return Check(
            id="index.provider",
            severity=Severity.INFO,
            title="Code knowledge graph provider disabled",
            detail=(
                "GITNEXUS_ENABLED is false, so the index is tree-sitter only and every "
                "relationship is a name match."
            ),
            bounds_claim="a resolved (non-approximated) reachability claim",
            metrics=metrics,
        )
    reason = (
        gitnexus_report.get("error")
        or (job.provider_reports.get("gitnexus_info") or {}).get("reason")
        or "the provider was unavailable"
    )
    return Check(
        id="index.provider",
        severity=Severity.WARN,
        title="Code knowledge graph provider did not run",
        detail=(
            f"GitNexus was expected but did not contribute: {str(reason)[:300]} "
            "Indexing fell back to tree-sitter alone."
        ),
        bounds_claim="a resolved (non-approximated) reachability claim",
        metrics=metrics,
    )


def _check_empty_sections(job: IndexJob, graph: CodeGraph) -> Check:
    """Suspiciously empty graph sections, per the spec's index-validation list."""
    empty: list[str] = []
    if job.configs_discovered == 0:
        empty.append("configuration")
    if job.dependencies_discovered == 0:
        empty.append("dependencies")
    if job.tests_discovered == 0:
        empty.append("tests")
    if not empty:
        return Check(
            id="index.sections",
            severity=Severity.OK,
            title="No empty graph sections",
            detail=(
                f"{job.configs_discovered} config(s), {job.dependencies_discovered} "
                f"dependency(ies), {job.tests_discovered} test(s)."
            ),
            metrics={},
        )
    return Check(
        id="index.sections",
        severity=Severity.INFO,
        title=f"Empty section(s): {', '.join(empty)}",
        detail=(
            "These sections are empty. That is legitimate for some repositories (a library with "
            "no tests, a service with no manifest) but is worth seeing, because each one is an "
            "input the security model would otherwise have used."
        ),
        metrics={"empty_sections": empty},
    )


def _check_language_parity(job: IndexJob, graph: CodeGraph) -> Check:
    """A language present in the tree but absent from the symbol graph.

    Catches the case where files of a language were counted but produced nothing — a per-language
    parser failure, which is invisible in aggregate counts.
    """
    symbol_languages = {
        node.language
        for node in graph.nodes
        if node.is_callable and node.language
    }
    file_languages = {
        language
        for language, count in job.languages.items()
        if count > 0 and language in ("python", "c", "javascript")
    }
    silent = sorted(file_languages - symbol_languages)
    if not silent:
        return Check(
            id="index.language_parity",
            severity=Severity.OK,
            title="Every source language produced symbols",
            detail=f"languages with symbols: {', '.join(sorted(symbol_languages)) or 'none'}",
            metrics={},
        )
    return Check(
        id="index.language_parity",
        severity=Severity.WARN,
        title=f"{', '.join(silent)} file(s) produced no symbols",
        detail=(
            f"The tree contains {', '.join(silent)} files but the graph has no callable symbol "
            "in that language, which indicates a per-language parse failure rather than an "
            "absence of code."
        ),
        bounds_claim=f"any symbol-level claim about the {', '.join(silent)} code",
        metrics={"silent_languages": silent},
    )


# ---------------------------------------------------------------------------
def _grade(report: IndexHealthReport) -> str:
    """Deterministic grading. Failures dominate; warnings accumulate."""
    fatal = {"index.non_empty", "index.file_coverage", "index.symbols", "index.relationships"}
    if any(c.id in fatal and c.severity == Severity.FAIL for c in report.checks):
        return Grade.F
    if report.failures:
        return Grade.C
    warnings = len(report.warnings)
    # Reachability being unmeasurable is a category difference, not one warning among many: it
    # removes the graph's central capability, so it caps the grade at C on its own.
    unmeasurable = any(
        c.id in ("index.entrypoints", "index.relationships") and c.severity == Severity.WARN
        for c in report.checks
    )
    if unmeasurable:
        return Grade.C
    if warnings == 0:
        return Grade.A
    return Grade.B if warnings <= 2 else Grade.C


def _summarise(report: IndexHealthReport, job: IndexJob) -> str:
    if report.grade == Grade.F:
        return (
            "The index is not usable. "
            + (report.failures[0].detail if report.failures else "")
        )
    parts = [f"Index grade {report.grade}", job.summary_line()]
    if report.claim_bounds:
        parts.append(f"{len(report.claim_bounds)} claim bound(s) recorded")
    return " · ".join(parts)
