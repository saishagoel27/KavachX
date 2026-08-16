import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger, Boolean, Column, DateTime, Float, ForeignKey,
    Integer, String, Text, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, relationship
from sqlalchemy.sql import func


class Base(DeclarativeBase):
    pass


def _uuid():
    return str(uuid.uuid4())


class Organisation(Base):
    __tablename__ = "organisations"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    name = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    projects = relationship("Project", back_populates="organisation")
    memberships = relationship("Membership", back_populates="organisation")


class Project(Base):
    __tablename__ = "projects"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    tenant_id = Column(UUID(as_uuid=False), ForeignKey("organisations.id"), nullable=False)
    repo_url = Column(Text, nullable=False)
    github_app_installation_id = Column(BigInteger, nullable=False)
    auto_publish = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    organisation = relationship("Organisation", back_populates="projects")
    runs = relationship("Run", back_populates="project")


class Run(Base):
    __tablename__ = "runs"

    id = Column(UUID(as_uuid=False), primary_key=True)  # run_id from KavachState
    tenant_id = Column(UUID(as_uuid=False), ForeignKey("organisations.id"), nullable=False)
    project_id = Column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=False)
    commit_sha = Column(Text, nullable=False)
    phase = Column(Text, nullable=False, default="ingest")
    status = Column(Text, nullable=False, default="running")
    # status: running | completed | failed | aborted
    state_snapshot = Column(JSONB)  # full KavachState checkpoint
    started_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    completed_at = Column(DateTime(timezone=True))
    budget_tokens = Column(Integer, nullable=False, default=0)
    budget_seconds = Column(Float, nullable=False, default=0)

    project = relationship("Project", back_populates="runs")
    findings = relationship("Finding", back_populates="run")
    shields = relationship("Shield", back_populates="run")
    patches = relationship("Patch", back_populates="run")
    certificates = relationship("Certificate", back_populates="run")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    tenant_id = Column(UUID(as_uuid=False), ForeignKey("organisations.id"), nullable=False)
    run_id = Column(UUID(as_uuid=False), ForeignKey("runs.id"), nullable=False)
    channel = Column(Text, nullable=False)
    # channel: graph_static | config | fuzz | constraint
    clause_id = Column(Text)
    location = Column(Text, nullable=False)
    severity = Column(Text, nullable=False)
    reachable = Column(Boolean, nullable=False)
    status = Column(Text, nullable=False, default="hypothesis")
    # status: hypothesis | validated | refuted
    exploit_ref = Column(Text)   # storage key, NULL until validated
    pov_hash = Column(Text)      # sha256 of PoV, NULL until validated
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    run = relationship("Run", back_populates="findings")
    shields = relationship("Shield", back_populates="finding")
    patches = relationship("Patch", back_populates="finding")
    certificates = relationship("Certificate", back_populates="finding")


class Shield(Base):
    __tablename__ = "shields"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    tenant_id = Column(UUID(as_uuid=False), ForeignKey("organisations.id"), nullable=False)
    run_id = Column(UUID(as_uuid=False), ForeignKey("runs.id"), nullable=False)
    finding_id = Column(UUID(as_uuid=False), ForeignKey("findings.id"), nullable=False)
    rule = Column(Text, nullable=False)
    revert_cmd = Column(Text, nullable=False)
    verified_blocked = Column(Boolean, nullable=False, default=False)
    verified_benign = Column(Boolean, nullable=False, default=False)
    deployed_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    run = relationship("Run", back_populates="shields")
    finding = relationship("Finding", back_populates="shields")


class Patch(Base):
    __tablename__ = "patches"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    tenant_id = Column(UUID(as_uuid=False), ForeignKey("organisations.id"), nullable=False)
    run_id = Column(UUID(as_uuid=False), ForeignKey("runs.id"), nullable=False)
    finding_id = Column(UUID(as_uuid=False), ForeignKey("findings.id"), nullable=False)
    diff_hash = Column(Text, nullable=False)
    diff_ref = Column(Text, nullable=False)       # storage key
    root_cause = Column(Text, nullable=False)
    iteration = Column(Integer, nullable=False)
    status = Column(Text, nullable=False, default="pending")
    # status: pending | passed | refuted
    refuting_input = Column(Text)                 # storage key, NULL unless refuted
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    run = relationship("Run", back_populates="patches")
    finding = relationship("Finding", back_populates="patches")


class Certificate(Base):
    __tablename__ = "certificates"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    tenant_id = Column(UUID(as_uuid=False), ForeignKey("organisations.id"), nullable=False)
    run_id = Column(UUID(as_uuid=False), ForeignKey("runs.id"), nullable=False)
    finding_id = Column(UUID(as_uuid=False), ForeignKey("findings.id"), nullable=False)
    level = Column(String(1), nullable=False)     # A | B | C | R
    evidence_hashes = Column(ARRAY(Text), nullable=False)
    signature = Column(Text, nullable=False)
    signed_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    run = relationship("Run", back_populates="certificates")
    finding = relationship("Finding", back_populates="certificates")


class AuditEvent(Base):
    __tablename__ = "audit_events"
    # append-only: application role has no UPDATE or DELETE on this table

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id = Column(UUID(as_uuid=False), ForeignKey("organisations.id"), nullable=False)
    run_id = Column(UUID(as_uuid=False))          # nullable — some events are not run-scoped
    actor_id = Column(UUID(as_uuid=False))        # user or system
    action = Column(Text, nullable=False)
    subject_type = Column(Text, nullable=False)
    subject_id = Column(Text, nullable=False)
    evidence_hash = Column(Text)
    metadata = Column(JSONB)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    prev_hash = Column(Text)                      # hash-chained


class ArtifactStore(Base):
    __tablename__ = "artifact_store"

    sha256 = Column(Text, primary_key=True)
    tenant_id = Column(UUID(as_uuid=False), ForeignKey("organisations.id"), nullable=False)
    kind = Column(Text, nullable=False)
    # kind: diff | log | trace | report | binary | corpus | certificate
    size_bytes = Column(Integer, nullable=False)
    storage_path = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())


class Membership(Base):
    __tablename__ = "memberships"

    id = Column(UUID(as_uuid=False), primary_key=True, default=_uuid)
    tenant_id = Column(UUID(as_uuid=False), ForeignKey("organisations.id"), nullable=False)
    user_id = Column(UUID(as_uuid=False), nullable=False)
    project_id = Column(UUID(as_uuid=False))      # NULL = org-level role
    role = Column(Text, nullable=False)
    # role: owner | maintainer | sec_reviewer | developer | viewer | auditor
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("tenant_id", "user_id", "project_id"),
    )

    organisation = relationship("Organisation", back_populates="memberships")
