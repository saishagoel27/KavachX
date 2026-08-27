"""The UNDERSTAND stage: a structured application model, not a textual summary.

The spec is explicit that this stage must not produce prose. A paragraph saying "this appears to
be a Flask web service with some database access" cannot be queried, cannot be diffed between
runs, and cannot be checked against evidence. :class:`ApplicationModel` is structured data with a
field for every question the attack-surface and test-synthesis stages actually ask.

**Everything decision-bearing here is derived deterministically** from the code graph, the security
graph, discovered configuration and discovered dependencies. The model is complete and usable with
no model call at all.

An LLM may then *annotate* it — a one-line purpose per module, a name for the application type —
under a strict schema, and every annotated field is marked ``model_annotated`` so a reader can
tell a derived fact from a proposed description. No annotation can change a count, a boundary, an
entrypoint or a control: those come from the graph.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from app.core.hashing import sha256_json
from app.core.logging import get_logger
from app.indexing.model import CodeGraph, EdgeKind, NodeKind, Precision
from app.security_model.graph import SecurityGraph
from app.security_model.taxonomy import SecurityCategory, SinkKind, SourceKind

logger = get_logger(__name__)


#: Pseudo-languages the file index uses for non-code files. Excluded from ``languages`` so the
#: model never claims a project is written in "config".
_NON_CODE_LANGUAGES: frozenset[str] = frozenset({"config", "other", "unknown", ""})


class ApplicationType:
    """Coarse application shapes. Decides which test/fuzz strategies even apply."""

    HTTP_SERVICE = "http_service"
    CLI_TOOL = "cli_tool"
    LIBRARY = "library"
    WORKER = "background_worker"
    SMART_CONTRACT = "smart_contract"
    FRONTEND = "frontend_application"
    MONOREPO = "monorepo"
    UNKNOWN = "unknown"


@dataclass
class ModuleSummary:
    path: str
    files: int = 0
    callables: int = 0
    #: Security nodes located in this module, by category.
    security: dict[str, int] = field(default_factory=dict)
    entrypoints: list[str] = field(default_factory=list)
    #: LLM-proposed one-liner. Always marked as annotated where it is surfaced.
    purpose: str = ""
    model_annotated: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "files": self.files,
            "callables": self.callables,
            "security": self.security,
            "entrypoints": self.entrypoints,
            "purpose": self.purpose,
            "model_annotated": self.model_annotated,
        }


@dataclass
class EntrypointSummary:
    uid: str
    kind: str
    file: str
    line: int
    signature: str = ""
    #: HTTP method + path where the framework makes it recoverable.
    route: str = ""
    #: Authentication/authorisation controls found on or inside this entrypoint.
    controls: list[str] = field(default_factory=list)
    #: Sinks reachable from here, as ``file:line`` locations.
    reachable_sinks: list[str] = field(default_factory=list)
    #: Security flows whose path starts at this entrypoint.
    flows: list[str] = field(default_factory=list)
    tests: list[str] = field(default_factory=list)

    @property
    def unauthenticated(self) -> bool:
        return not self.controls

    def as_dict(self) -> dict[str, Any]:
        return {
            "uid": self.uid,
            "kind": self.kind,
            "file": self.file,
            "line": self.line,
            "signature": self.signature,
            "route": self.route,
            "controls": self.controls,
            "unauthenticated": self.unauthenticated,
            "reachable_sinks": self.reachable_sinks[:40],
            "reachable_sink_count": len(self.reachable_sinks),
            "flows": self.flows[:40],
            "tests": self.tests,
        }


@dataclass
class ApplicationModel:
    """The structured answer to "what is this application?"."""

    SCHEMA = "kavachx.application_model.v1"

    application_type: str = ApplicationType.UNKNOWN
    #: Evidence for the type decision, so the classification is auditable.
    type_evidence: list[str] = field(default_factory=list)
    languages: dict[str, int] = field(default_factory=dict)
    #: Counts for non-code file buckets (config, other), kept out of ``languages``.
    non_code_files: dict[str, int] = field(default_factory=dict)
    frameworks: list[str] = field(default_factory=list)
    modules: list[ModuleSummary] = field(default_factory=list)
    entrypoints: list[EntrypointSummary] = field(default_factory=list)

    authentication: list[str] = field(default_factory=list)
    authorization: list[str] = field(default_factory=list)
    data_stores: list[str] = field(default_factory=list)
    external_services: list[str] = field(default_factory=list)
    trust_boundaries: list[dict[str, Any]] = field(default_factory=list)
    sensitive_operations: list[dict[str, Any]] = field(default_factory=list)
    sources: dict[str, int] = field(default_factory=dict)
    sinks: dict[str, int] = field(default_factory=dict)
    security_controls: list[dict[str, Any]] = field(default_factory=list)
    configuration: list[dict[str, Any]] = field(default_factory=list)
    dependencies: dict[str, Any] = field(default_factory=dict)
    tests: dict[str, Any] = field(default_factory=dict)
    #: Provider-derived execution flows plus KavachX's own entrypoint→sink paths.
    major_flows: list[dict[str, Any]] = field(default_factory=list)

    #: LLM-proposed prose, always separated from derived facts.
    narrative: str = ""
    narrative_model: str = ""
    model_annotated: bool = False

    #: What this model does not know, and why. Carried into REMAINING.md.
    gaps: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": self.SCHEMA,
            "application_type": self.application_type,
            "type_evidence": self.type_evidence,
            "languages": self.languages,
            "non_code_files": self.non_code_files,
            "frameworks": self.frameworks,
            "modules": [m.as_dict() for m in self.modules],
            "entrypoints": [e.as_dict() for e in self.entrypoints],
            "authentication": self.authentication,
            "authorization": self.authorization,
            "data_stores": self.data_stores,
            "external_services": self.external_services,
            "trust_boundaries": self.trust_boundaries,
            "sensitive_operations": self.sensitive_operations,
            "sources": self.sources,
            "sinks": self.sinks,
            "security_controls": self.security_controls,
            "configuration": self.configuration,
            "dependencies": self.dependencies,
            "tests": self.tests,
            "major_flows": self.major_flows,
            "narrative": self.narrative,
            "narrative_model": self.narrative_model,
            "model_annotated": self.model_annotated,
            "gaps": self.gaps,
        }

    def content_hash(self) -> str:
        """Digest over the *derived* model only — annotations are excluded deliberately.

        Two runs of the same commit must agree on this hash even if one had a model available and
        the other did not, because the derived model is the part anything depends on.
        """
        payload = self.as_dict()
        for key in ("narrative", "narrative_model", "model_annotated"):
            payload.pop(key, None)
        for module in payload.get("modules", []):
            module.pop("purpose", None)
            module.pop("model_annotated", None)
        return sha256_json(payload)

    def render(self) -> str:
        """The plain-text APPLICATION block, in the shape the spec lays out."""
        lines = ["APPLICATION", f"  {self.application_type}"]
        if self.frameworks:
            lines.append(f"  frameworks: {', '.join(self.frameworks)}")
        if self.languages:
            lines.append(
                "  languages: "
                + ", ".join(f"{k} ({v})" for k, v in sorted(self.languages.items()))
            )

        lines += ["", "ENTRYPOINTS"]
        if self.entrypoints:
            for entry in self.entrypoints[:20]:
                label = entry.route or entry.signature or entry.uid
                guard = "unauthenticated" if entry.unauthenticated else ", ".join(entry.controls)
                # The location is not decoration: two modules can both define `main(argv)`, and
                # without it the list shows the same line twice for different entrypoints.
                lines.append(f"  {label}  [{entry.kind}]  ({guard})")
                lines.append(f"      {entry.file}:{entry.line}")
        else:
            lines.append("  none identified")

        for title, values in (
            ("AUTHENTICATION", self.authentication),
            ("AUTHORIZATION", self.authorization),
            ("DATA STORES", self.data_stores),
            ("EXTERNAL SERVICES", self.external_services),
        ):
            lines += ["", title]
            lines += [f"  {value}" for value in values] or ["  none identified"]

        lines += ["", "TRUST BOUNDARIES"]
        lines += [
            f"  {b['kind']}  ({b.get('member_count', 0)} crossing point(s))"
            for b in self.trust_boundaries
        ] or ["  none identified"]

        lines += ["", "SOURCES"]
        lines += [f"  {k}  x{v}" for k, v in sorted(self.sources.items())] or ["  none identified"]

        lines += ["", "SINKS"]
        lines += [f"  {k}  x{v}" for k, v in sorted(self.sinks.items())] or ["  none identified"]

        lines += ["", "SECURITY CONTROLS"]
        lines += [
            f"  {c['kind']} at {c['location']}" for c in self.security_controls[:20]
        ] or ["  none identified"]

        lines += ["", "TESTS"]
        lines.append(
            f"  {self.tests.get('files', 0)} file(s), {self.tests.get('cases', 0)} case(s), "
            f"frameworks: {', '.join(self.tests.get('frameworks', [])) or 'none'}"
        )

        if self.gaps:
            lines += ["", "NOT KNOWN"]
            lines += [f"  - {gap}" for gap in self.gaps]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
#: Import-statement / dependency markers that identify a framework.
_FRAMEWORK_MARKERS: tuple[tuple[str, str], ...] = (
    ("flask", "Flask"),
    ("django", "Django"),
    ("fastapi", "FastAPI"),
    ("starlette", "Starlette"),
    ("aiohttp", "aiohttp"),
    ("tornado", "Tornado"),
    ("bottle", "Bottle"),
    ("express", "Express"),
    ("next", "Next.js"),
    ("nestjs", "NestJS"),
    ("koa", "Koa"),
    ("fastify", "Fastify"),
    ("spring", "Spring"),
    ("gin-gonic", "Gin"),
    ("echo", "Echo"),
    ("actix", "Actix"),
    ("rocket", "Rocket"),
    ("rails", "Rails"),
    ("laravel", "Laravel"),
    ("celery", "Celery"),
    ("hardhat", "Hardhat"),
    ("foundry", "Foundry"),
)

#: Data-store markers.
_DATA_STORE_MARKERS: tuple[tuple[str, str], ...] = (
    ("psycopg", "PostgreSQL"),
    ("asyncpg", "PostgreSQL"),
    ("postgres", "PostgreSQL"),
    ("pymysql", "MySQL"),
    ("mysql", "MySQL"),
    ("sqlite", "SQLite"),
    ("aiosqlite", "SQLite"),
    ("mongo", "MongoDB"),
    ("redis", "Redis"),
    ("elasticsearch", "Elasticsearch"),
    ("cassandra", "Cassandra"),
    ("dynamodb", "DynamoDB"),
    ("sqlalchemy", "SQL (via SQLAlchemy)"),
    ("prisma", "SQL (via Prisma)"),
    ("sequelize", "SQL (via Sequelize)"),
    ("knex", "SQL (via Knex)"),
)

#: Authentication mechanism markers.
_AUTH_MARKERS: tuple[tuple[str, str], ...] = (
    ("jwt", "JWT"),
    ("jsonwebtoken", "JWT"),
    ("oauth", "OAuth"),
    ("saml", "SAML"),
    ("bcrypt", "password hashing (bcrypt)"),
    ("argon2", "password hashing (argon2)"),
    ("passlib", "password hashing (passlib)"),
    ("session", "session cookies"),
    ("passport", "Passport"),
    ("basic_auth", "HTTP Basic"),
    ("apikey", "API key"),
    ("api_key", "API key"),
)

#: External-service markers.
_EXTERNAL_MARKERS: tuple[tuple[str, str], ...] = (
    ("boto3", "AWS"),
    ("google.cloud", "Google Cloud"),
    ("azure", "Azure"),
    ("stripe", "Stripe"),
    ("twilio", "Twilio"),
    ("sendgrid", "SendGrid"),
    ("openai", "OpenAI"),
    ("anthropic", "Anthropic"),
    ("smtplib", "SMTP"),
    ("kafka", "Kafka"),
    ("pika", "RabbitMQ"),
    ("celery", "Celery broker"),
)


def build_application_model(
    *,
    code_graph: CodeGraph,
    security_graph: SecurityGraph,
) -> ApplicationModel:
    """Derive the application model. Deterministic; no model call."""
    model = ApplicationModel()

    # -- languages ---------------------------------------------------------
    # Only real programming languages. The file index uses "config" and "other" as catch-all
    # buckets for non-code files, and listing those as languages ("languages: config (12)") makes
    # the model look like it misidentified the project. Non-code counts are kept separately.
    languages: dict[str, int] = defaultdict(int)
    non_code: dict[str, int] = defaultdict(int)
    for node in code_graph.nodes_of(NodeKind.FILE.value):
        if not node.language:
            continue
        if node.language in _NON_CODE_LANGUAGES:
            non_code[node.language] += 1
        else:
            languages[node.language] += 1
    model.languages = dict(sorted(languages.items(), key=lambda kv: -kv[1]))
    model.non_code_files = dict(sorted(non_code.items(), key=lambda kv: -kv[1]))

    # -- evidence corpus for marker matching -------------------------------
    # Import statements plus declared dependency names. Both, because a framework can be present
    # via a manifest with no import yet indexed, or imported from a vendored copy with no manifest.
    haystack: list[str] = []
    for node in code_graph.nodes_of(NodeKind.IMPORT.value):
        haystack.append(str(node.attrs.get("statement", "")).lower())
    for node in code_graph.nodes_of(NodeKind.DEPENDENCY.value):
        haystack.append(node.name.lower())
    blob = "\n".join(haystack)

    model.frameworks = _match_markers(blob, _FRAMEWORK_MARKERS)
    model.data_stores = _match_markers(blob, _DATA_STORE_MARKERS)
    model.authentication = _match_markers(blob, _AUTH_MARKERS)
    model.external_services = _match_markers(blob, _EXTERNAL_MARKERS)

    # -- security summary --------------------------------------------------
    source_kinds: dict[str, int] = defaultdict(int)
    for node in security_graph.sources:
        source_kinds[node.kind] += 1
    model.sources = dict(sorted(source_kinds.items()))

    sink_kinds: dict[str, int] = defaultdict(int)
    for node in security_graph.sinks:
        sink_kinds[node.kind] += 1
    model.sinks = dict(sorted(sink_kinds.items()))

    model.trust_boundaries = [b.as_dict() for b in security_graph.boundaries.values()]
    model.security_controls = [
        {
            "kind": node.category,
            "mechanism": node.kind,
            "location": node.location,
            "rule": node.rule_id,
            "why": node.why,
        }
        for node in security_graph.controls
    ]
    model.authorization = sorted(
        {
            node.kind
            for node in security_graph.controls
            if node.category == SecurityCategory.AUTHORIZATION_CHECK.value
        }
    )
    if not model.authentication and any(
        node.category == SecurityCategory.AUTHENTICATION_CHECK.value
        for node in security_graph.controls
    ):
        model.authentication = ["explicit checks in code (no library identified)"]

    # Sensitive operations: the sinks that are dangerous regardless of reachability.
    dangerous = {
        SinkKind.SHELL_EXEC.value,
        SinkKind.PROCESS_EXEC.value,
        SinkKind.DYNAMIC_EVAL.value,
        SinkKind.DESERIALISATION.value,
        SinkKind.SQL.value,
        SinkKind.TEMPLATE_RENDER.value,
        SinkKind.AUTH_DECISION.value,
        SinkKind.AUTHZ_DECISION.value,
    }
    model.sensitive_operations = [
        {
            "kind": node.kind,
            "location": node.location,
            "cwe": node.cwe,
            "severity": node.severity,
            "owner": node.owner,
            "why": node.why,
        }
        for node in sorted(security_graph.sinks, key=lambda n: n.ref)
        if node.kind in dangerous
    ]

    # -- modules -----------------------------------------------------------
    by_module: dict[str, ModuleSummary] = {}
    for node in code_graph.nodes_of(NodeKind.FILE.value):
        directory = node.module_dir if node.file else "."
        summary = by_module.setdefault(directory, ModuleSummary(path=directory))
        summary.files += 1
    for node in code_graph.callables():
        directory = node.module_dir
        summary = by_module.setdefault(directory, ModuleSummary(path=directory))
        summary.callables += 1
        if node.attrs.get("entrypoint_kind"):
            summary.entrypoints.append(node.uid)
    for node in security_graph.nodes.values():
        directory = node.file.rsplit("/", 1)[0] if "/" in node.file else "."
        summary = by_module.setdefault(directory, ModuleSummary(path=directory))
        summary.security[node.category] = summary.security.get(node.category, 0) + 1
    model.modules = sorted(by_module.values(), key=lambda m: (-m.callables, m.path))

    # -- entrypoints -------------------------------------------------------
    model.entrypoints = _entrypoint_summaries(code_graph, security_graph)

    # -- configuration -----------------------------------------------------
    model.configuration = [
        {
            "path": node.qualname,
            "role": node.attrs.get("role", ""),
            "settings": [s.get("id") for s in (node.attrs.get("settings") or [])],
            "ports": node.attrs.get("ports") or [],
        }
        for node in sorted(
            code_graph.nodes_of(NodeKind.CONFIGURATION.value), key=lambda n: n.uid
        )
    ]

    # -- dependencies ------------------------------------------------------
    from app.understanding.dependencies import model_from_graph

    model.dependencies = model_from_graph(code_graph)

    # -- tests -------------------------------------------------------------
    test_nodes = code_graph.nodes_of(NodeKind.TEST.value)
    model.tests = {
        "files": len(test_nodes),
        "cases": sum(int(n.attrs.get("case_count", 0) or 0) for n in test_nodes),
        "frameworks": sorted({str(n.attrs.get("framework", "")) for n in test_nodes if n.attrs.get("framework")}),
        "commands": sorted(
            {" ".join(n.attrs.get("command") or []) for n in test_nodes if n.attrs.get("command")}
        ),
    }

    # -- major flows -------------------------------------------------------
    model.major_flows = [
        {
            "ref": flow.ref,
            "summary": f"{flow.source_kind} → {flow.sink_kind}",
            "entrypoint": flow.entrypoint,
            "severity": flow.severity,
            "cwe": flow.cwe,
            "basis": flow.basis,
            "confidence": flow.confidence,
            "steps": [s.location for s in flow.steps],
        }
        for flow in security_graph.top_flows(20)
    ]
    for flow in code_graph.metadata.get("execution_flows") or []:
        model.major_flows.append(
            {
                "ref": str(flow.get("process", "")),
                "summary": "provider-derived execution flow",
                "basis": "gitnexus-process",
                "steps": list(flow.get("members") or [])[:20],
            }
        )

    # -- type classification ----------------------------------------------
    model.application_type, model.type_evidence = _classify(model, code_graph, security_graph)

    # -- gaps --------------------------------------------------------------
    model.gaps = _gaps(model, code_graph, security_graph)

    logger.info(
        "understanding.application_model",
        type=model.application_type,
        frameworks=model.frameworks,
        entrypoints=len(model.entrypoints),
        sources=len(security_graph.sources),
        sinks=len(security_graph.sinks),
        gaps=len(model.gaps),
    )
    return model


# ---------------------------------------------------------------------------
def _match_markers(blob: str, markers: tuple[tuple[str, str], ...]) -> list[str]:
    """Ordered, de-duplicated labels whose marker appears in the evidence blob."""
    out: list[str] = []
    for marker, label in markers:
        if marker in blob and label not in out:
            out.append(label)
    return out


def _entrypoint_summaries(
    code_graph: CodeGraph, security_graph: SecurityGraph
) -> list[EntrypointSummary]:
    """One summary per declared entrypoint, with its controls, reachable sinks and tests."""
    summaries: list[EntrypointSummary] = []
    controls_by_owner: dict[str, list[str]] = defaultdict(list)
    for node in security_graph.controls:
        if node.owner:
            controls_by_owner[node.owner].append(f"{node.kind}@{node.location}")

    flows_by_entry: dict[str, list[str]] = defaultdict(list)
    for flow in security_graph.flows:
        if flow.entrypoint:
            flows_by_entry[flow.entrypoint].append(flow.ref)

    for uid in sorted(code_graph.entrypoint_uids()):
        node = code_graph.node(uid)
        if node is None:
            continue
        # Controls guarding an entrypoint can be on the entrypoint itself (a decorator) or in any
        # callable it reaches before the work happens; both count as "this endpoint is guarded".
        reachable = set(_forward_closure(code_graph, uid))
        controls = list(controls_by_owner.get(uid, []))
        for callee in reachable:
            controls.extend(controls_by_owner.get(callee, []))

        reachable_sinks = sorted(
            {
                sink.location
                for sink in security_graph.sinks
                if sink.owner and (sink.owner == uid or sink.owner in reachable)
            }
        )
        tests = sorted({e.dst for e in code_graph.out_edges(uid, EdgeKind.TESTED_BY.value)})

        summaries.append(
            EntrypointSummary(
                uid=uid,
                kind=str(node.attrs.get("entrypoint_kind") or "unknown"),
                file=node.file,
                line=node.start_line,
                signature=node.signature,
                route=_route_for(node),
                controls=sorted(set(controls)),
                reachable_sinks=reachable_sinks,
                flows=flows_by_entry.get(uid, []),
                tests=tests,
            )
        )
    return summaries


def _forward_closure(code_graph: CodeGraph, uid: str, *, max_depth: int = 6) -> list[str]:
    """Callables reachable forward from ``uid``, at union precision.

    Union precision on purpose: for describing an attack surface, over-approximating what an
    entrypoint can reach is the safe direction — the alternative is telling an operator an
    endpoint cannot reach a shell sink when a name-matched edge says it might.
    """
    seen: set[str] = set()
    frontier = [uid]
    for _ in range(max_depth):
        nxt: list[str] = []
        for current in frontier:
            for callee in code_graph.callees(current, precision=Precision.UNION.value):
                if callee not in seen:
                    seen.add(callee)
                    nxt.append(callee)
        if not nxt:
            break
        frontier = nxt
    seen.discard(uid)
    return sorted(seen)


def _route_for(node: Any) -> str:
    """HTTP method and path from a route decorator, when one is recoverable."""
    import re

    for decorator in node.decorators or []:
        text = str(decorator)
        method = ""
        match = re.search(
            r"@(?:app|router|blueprint|bp)\.(get|post|put|patch|delete|route)", text, re.IGNORECASE
        )
        if match:
            method = match.group(1).upper()
        path_match = re.search(r"[\"']([^\"']+)[\"']", text)
        path = path_match.group(1) if path_match else ""
        methods_match = re.search(r"methods\s*=\s*\[([^\]]+)\]", text)
        if methods_match:
            method = ",".join(
                m.strip().strip("\"'").upper() for m in methods_match.group(1).split(",")
            )
        if path:
            return f"{method or 'ANY'} {path}".strip()
    return ""


def _classify(
    model: ApplicationModel, code_graph: CodeGraph, security_graph: SecurityGraph
) -> tuple[str, list[str]]:
    """Classify the application shape, recording the evidence for the decision."""
    evidence: list[str] = []
    http_frameworks = {
        "Flask", "Django", "FastAPI", "Starlette", "aiohttp", "Tornado", "Bottle",
        "Express", "Next.js", "NestJS", "Koa", "Fastify", "Spring", "Gin", "Echo",
        "Actix", "Rocket", "Rails", "Laravel",
    }
    matched_http = [f for f in model.frameworks if f in http_frameworks]
    http_entries = [e for e in model.entrypoints if e.kind == "http" or e.route]
    cli_entries = [e for e in model.entrypoints if e.kind == "cli"]
    http_sources = [
        k
        for k in model.sources
        if k
        in (
            SourceKind.HTTP_PARAM.value,
            SourceKind.HTTP_BODY.value,
            SourceKind.HTTP_HEADER.value,
            SourceKind.HTTP_COOKIE.value,
            SourceKind.HTTP_PATH.value,
        )
    ]

    if matched_http:
        evidence.append(f"HTTP framework(s) present: {', '.join(matched_http)}")
    if http_entries:
        evidence.append(f"{len(http_entries)} route-decorated entrypoint(s)")
    if http_sources:
        evidence.append(f"HTTP request sources present: {', '.join(http_sources)}")
    if cli_entries:
        evidence.append(f"{len(cli_entries)} CLI entrypoint(s) with a __main__ guard")

    if matched_http or http_entries or http_sources:
        return ApplicationType.HTTP_SERVICE, evidence

    if "Hardhat" in model.frameworks or "Foundry" in model.frameworks:
        evidence.append("smart-contract toolchain present")
        return ApplicationType.SMART_CONTRACT, evidence

    if "Celery" in model.frameworks or "Celery broker" in model.external_services:
        evidence.append("task queue framework present")
        return ApplicationType.WORKER, evidence

    if cli_entries:
        return ApplicationType.CLI_TOOL, evidence

    if model.entrypoints:
        evidence.append("entrypoints exist but match no service or CLI convention")
        return ApplicationType.UNKNOWN, evidence

    evidence.append(
        "no entrypoint matched any convention: the tree exposes symbols but nothing that "
        "starts execution"
    )
    return ApplicationType.LIBRARY, evidence


def _gaps(
    model: ApplicationModel, code_graph: CodeGraph, security_graph: SecurityGraph
) -> list[str]:
    """What this model does not know. Stated, because an omission read as a zero is a lie."""
    gaps: list[str] = []
    if not model.entrypoints:
        gaps.append(
            "No entrypoints were identified, so the attack surface is unknown and reachability "
            "was not measured. Every candidate is ranked by severity rather than by exposure."
        )
    if not security_graph.controls:
        gaps.append(
            "No authentication or authorisation control was identified anywhere in the tree. "
            "That may be correct (a library, an internal CLI) or may mean the controls are "
            "expressed in a form the taxonomy does not recognise — it is not evidence that the "
            "application is unprotected."
        )
    if not model.tests.get("files"):
        gaps.append(
            "No tests were discovered, so no existing coverage can be credited and every "
            "security-sensitive path is untested as far as this index can tell."
        )
    if security_graph.parse_errors:
        gaps.append(
            f"{len(security_graph.parse_errors)} file(s) could not be parsed for data-flow "
            "analysis; flows through them were not computed."
        )
    unmeasured = len(security_graph.unmeasured_flows)
    if unmeasured:
        gaps.append(
            f"{unmeasured} flow(s) have unmeasured reachability because no call path could be "
            "searched."
        )
    proximity = len([f for f in security_graph.flows if f.basis == "proximity"])
    if proximity:
        gaps.append(
            f"{proximity} flow(s) rest on source/sink co-location rather than proven data flow, "
            "because no taint analyser exists for their language."
        )
    if not model.dependencies.get("manifests"):
        gaps.append(
            "No dependency manifest was found, so the framework and library picture is derived "
            "from imports alone."
        )
    return gaps
