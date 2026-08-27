"""Domain enumerations.

Stored as short strings so that migrations stay boring and the values are readable in raw
SQL during an incident. Every state machine in KavachX is expressed here.
"""

import sys
from enum import Enum

if sys.version_info >= (3, 11):
    from enum import StrEnum
else:
    class StrEnum(str, Enum):
        pass


class Role(StrEnum):
    OWNER = "OWNER"
    MAINTAINER = "MAINTAINER"
    SECURITY_REVIEWER = "SECURITY_REVIEWER"
    DEVELOPER = "DEVELOPER"
    VIEWER = "VIEWER"
    AUDITOR = "AUDITOR"


class RunStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ABORTED = "ABORTED"


class Phase(StrEnum):
    """The pipeline stages surfaced in the console timeline.

    Every pre-existing value is preserved verbatim so that runs recorded before the code
    intelligence layer existed still render, and so ``phase_status`` maps stored on old rows keep
    their keys. The new stages are inserted at the points where the work actually happens.
    """

    INGEST = "ingest"
    #: Repository indexing: GitNexus + tree-sitter merged into one code knowledge graph.
    INDEX = "index"
    #: Deterministic index validation and the index health report.
    INDEX_VALIDATE = "index_validate"
    #: Sources, sinks, sanitizers, trust boundaries and data flows over the code graph.
    SECURITY_MODEL = "security_model"
    #: The structured application model and attack surface.
    UNDERSTAND = "understand"
    # Declared *after* the two stages above because that is the order they run in: the probe uses
    # the graph's entrypoints, so understanding happens first. Member order is what PHASE_ORDER
    # exports, and the console renders its timeline from it — a declaration order that disagreed
    # with execution order would draw a timeline that lies about what ran when.
    PROBE = "probe"
    WORLD_MODEL = "world_model"
    SAMHITA = "samhita"
    DISCOVERY = "discovery"
    HYPOTHESIS_QUEUE = "hypothesis_queue"
    #: Candidate -> TestSpec -> generated harness.
    TEST_SYNTHESIS = "test_synthesis"
    #: Harness execution in the sandbox, with coverage feedback.
    EXECUTE = "execute"
    VALIDATION = "validation"
    SHIELD = "shield"
    ROOT_CAUSE = "root_cause"
    #: The reproduced exploit preserved as a durable test. Before PATCH, because the regression
    #: test is built from the reproduction record and must be shown to fire on the *unpatched*
    #: build — a test that has never fired is not a guard.
    REGRESSION = "regression"
    PATCH = "patch"
    BLAST_RADIUS = "blast_radius"
    GAUNTLET = "gauntlet"
    PRAMAAN = "pramaan"
    PUBLISH = "publish"


PHASE_ORDER: list[str] = [p.value for p in Phase]

#: Phases that existed before the code-intelligence upgrade. Used by the console to render a run
#: recorded by an older build without showing the newer stages as perpetually "pending".
LEGACY_PHASE_ORDER: list[str] = [
    Phase.INGEST.value,
    Phase.PROBE.value,
    Phase.INDEX.value,
    Phase.WORLD_MODEL.value,
    Phase.SAMHITA.value,
    Phase.DISCOVERY.value,
    Phase.HYPOTHESIS_QUEUE.value,
    Phase.VALIDATION.value,
    Phase.SHIELD.value,
    Phase.ROOT_CAUSE.value,
    Phase.PATCH.value,
    Phase.BLAST_RADIUS.value,
    Phase.GAUNTLET.value,
    Phase.PRAMAAN.value,
    Phase.PUBLISH.value,
]


class PhaseStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_RANK: dict[str, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


class HypothesisStatus(StrEnum):
    QUEUED = "QUEUED"
    IN_VALIDATION = "IN_VALIDATION"
    VALIDATED = "VALIDATED"
    REFUTED = "REFUTED"
    UNKNOWN = "UNKNOWN"  # -> failure/unknown ledger
    DOWNGRADED = "DOWNGRADED"


class FindingState(StrEnum):
    HYPOTHESIS = "HYPOTHESIS"
    VALIDATED = "VALIDATED"
    REFUTED = "REFUTED"


class DiscoveryChannel(StrEnum):
    GRAPH_STATIC = "graph/static"
    CONFIG_REACHABILITY = "config/reachability"
    FUZZING = "fuzzing"
    RUNTIME = "runtime"


class ClauseStatus(StrEnum):
    PROPOSED = "PROPOSED"
    COMPILED = "COMPILED"
    UNCOMPILABLE = "UNCOMPILABLE"
    FALSIFIED = "FALSIFIED"
    SURVIVING = "SURVIVING"
    VIOLATED = "VIOLATED"


class ClauseKind(StrEnum):
    INPUT_LENGTH_BOUND = "input_length_bound"
    MONOTONIC_COUNTER = "monotonic_counter"
    DETERMINISTIC_OUTPUT = "deterministic_output"
    FORBIDDEN_SHELL = "forbidden_shell_invocation"
    STATE_TRANSITION = "valid_state_transition"
    NULLABILITY = "nullability_assumption"
    RESPONSE_STRUCTURE = "response_structure"
    RESOURCE_CONSTRAINT = "resource_constraint"
    PATH_CONTAINMENT = "path_containment"


class PatchStatus(StrEnum):
    PROPOSED = "PROPOSED"
    POLICY_REJECTED = "POLICY_REJECTED"
    APPLIED = "APPLIED"
    APPLY_FAILED = "APPLY_FAILED"
    REFUTED = "REFUTED"
    VERIFIED = "VERIFIED"
    WITHDRAWN = "WITHDRAWN"
    PUBLISHED = "PUBLISHED"


class GauntletStage(StrEnum):
    EXPLOIT_MUTATION = "exploit_mutation"
    SIBLING_HUNT = "sibling_hunt"
    DIFFERENTIAL_REPLAY = "differential_replay"
    SAMHITA_RECHECK = "samhita_recheck"


GAUNTLET_STAGES: list[str] = [s.value for s in GauntletStage]


class Verdict(StrEnum):
    PASS = "pass"
    FAIL = "fail"


class AssuranceLevel(StrEnum):
    A = "A"
    B = "B"
    C = "C"
    R = "R"


class EvidenceNodeType(StrEnum):
    VULNERABILITY = "vulnerability"
    DISCOVERY_CHANNEL = "discovery_channel"
    SAMHITA_CLAUSE = "samhita_clause"
    CODE_LOCATION = "code_location"
    RUNTIME_TRACE = "runtime_trace"
    REPRODUCTION = "reproduction"
    SHIELD = "shield"
    PATCH = "patch"
    GAUNTLET_RESULT = "gauntlet_result"
    BLAST_RADIUS = "blast_radius"
    WORLD_MODEL = "world_model"
    CERTIFICATE = "certificate"
    SANDBOX_EXECUTION = "sandbox_execution"


class EvidenceRelation(StrEnum):
    DISCOVERED_BY = "discovered_by"
    VIOLATED_CLAUSE = "violated_clause"
    CODE_EVIDENCE = "code_evidence"
    RUNTIME_EVIDENCE = "runtime_evidence"
    EXPLOIT_EVIDENCE = "exploit_evidence"
    SHIELDED_BY = "shielded_by"
    REPAIRED_BY = "repaired_by"
    VERIFIED_BY = "verified_by"
    SCOPED_BY = "scoped_by"
    EXECUTED_IN = "executed_in"
    ATTESTS = "attests"
    SUPERSEDES = "supersedes"


class ArtifactKind(StrEnum):
    CERTIFICATE = "certificate"
    CHANGES_MD = "changes_md"
    REMAINING_MD = "remaining_md"
    PATCH_DIFF = "patch_diff"
    SANDBOX_LOG = "sandbox_log"
    PR = "pr"
    DOCS = "docs"
    WORLD_MODEL = "world_model"
    BENIGN_CORPUS = "benign_corpus"


class AnalysisProfile(StrEnum):
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"


class ExecutionProfile(StrEnum):
    DEV_LOCAL = "dev_local"
    GVISOR = "gvisor"
    FIRECRACKER = "firecracker"


class RepositoryProvider(StrEnum):
    GITHUB = "github"
    LOCAL_SEEDED = "local_seeded"
    #: A public GitHub repository, ingested read-only from published source.
    #:
    #: Analysis-only by construction: no write credential is attached to it, so it can never reach
    #: the Publisher. Reading published source and executing it in a sandbox is ordinary security
    #: research; opening a pull request against a repository you do not control is not.
    GITHUB_PUBLIC = "github_public"


#: Providers that may reach the Publisher.
#:
#: * ``github`` — write authority over the repository, confirmed by the configured fine-grained
#:   token actually having push access. The only provider that can produce a *live* pull request.
#: * ``local_seeded`` — the operator's own tree inside this repository's ``examples/``. No third
#:   party exists to publish to, so the dry-run payload is a demonstration and nothing more. A live
#:   publish still fails without a token that can push to it.
#:
#: ``github_public`` is deliberately absent. It is somebody else's repository: a dry-run payload
#: announcing a push to it would be misleading, and if ``PUBLISHER_DRY_RUN`` were ever turned off it
#: would be an attempted write to a repository the operator does not control.
PUBLISHABLE_PROVIDERS: frozenset[str] = frozenset(
    {RepositoryProvider.GITHUB.value, RepositoryProvider.LOCAL_SEEDED.value}
)
