"""SQLAlchemy models.

Importing this package registers every table on ``Base.metadata`` — Alembic autogenerate
and ``create_all`` both depend on that side effect, so the re-exports below are load-bearing.
"""

from app.db.base import Base
from app.models.analysis import Finding, Hypothesis, SamhitaClause, Shield
from app.models.audit import AuditAction, AuditEvent
from app.models.identity import (
    GithubInstallation,
    Organisation,
    OrganisationMember,
    User,
)
from app.models.pramaan import Certificate, EvidenceEdge, EvidenceNode
from app.models.project import DEFAULT_FORBIDDEN_GLOBS, Policy, Project, Repository
from app.models.repair import GauntletResult, GauntletRun, Patch
from app.models.run import Artifact, Run, RunCheckpoint, RunEvent, WorldModel

__all__ = [
    "DEFAULT_FORBIDDEN_GLOBS",
    "Artifact",
    "AuditAction",
    "AuditEvent",
    "Base",
    "Certificate",
    "EvidenceEdge",
    "EvidenceNode",
    "Finding",
    "GauntletResult",
    "GauntletRun",
    "GithubInstallation",
    "Hypothesis",
    "Organisation",
    "OrganisationMember",
    "Patch",
    "Policy",
    "Project",
    "Repository",
    "Run",
    "RunCheckpoint",
    "RunEvent",
    "SamhitaClause",
    "Shield",
    "User",
    "WorldModel",
]
