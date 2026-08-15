# Database

KavachX uses Postgres with row-level security (RLS).
Every table has a `tenant_id` column. RLS policies enforce that
a session can only see rows belonging to its tenant.

---

## Tenancy model

```
Organisation (tenant)
  └── Project (repository)
        └── Run
              ├── Finding
              ├── Hypothesis
              ├── Shield
              ├── Patch
              ├── Certificate
              └── AuditEvent
```

---

## Core tables

### organisations
```sql
CREATE TABLE organisations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### projects
```sql
CREATE TABLE projects (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES organisations(id),
    repo_url        TEXT NOT NULL,
    github_app_installation_id  BIGINT NOT NULL,
    auto_publish    BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### runs
```sql
CREATE TABLE runs (
    id              UUID PRIMARY KEY,           -- run_id from KavachState
    tenant_id       UUID NOT NULL REFERENCES organisations(id),
    project_id      UUID NOT NULL REFERENCES projects(id),
    commit_sha      TEXT NOT NULL,
    phase           TEXT NOT NULL DEFAULT 'ingest',
    status          TEXT NOT NULL DEFAULT 'running',
    -- status: running | completed | failed | aborted
    state_snapshot  JSONB,                      -- full KavachState (LangGraph checkpoint)
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ,
    budget_tokens   INTEGER NOT NULL DEFAULT 0,
    budget_seconds  FLOAT NOT NULL DEFAULT 0
);
```

### findings
```sql
CREATE TABLE findings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES organisations(id),
    run_id          UUID NOT NULL REFERENCES runs(id),
    channel         TEXT NOT NULL,
    -- channel: graph_static | config | fuzz | constraint
    clause_id       TEXT,
    location        TEXT NOT NULL,
    severity        TEXT NOT NULL,
    reachable       BOOLEAN NOT NULL,
    status          TEXT NOT NULL DEFAULT 'hypothesis',
    -- status: hypothesis | validated | refuted
    exploit_ref     TEXT,                       -- storage key, NULL until validated
    pov_hash        TEXT,                       -- sha256 of PoV, NULL until validated
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### shields
```sql
CREATE TABLE shields (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES organisations(id),
    run_id              UUID NOT NULL REFERENCES runs(id),
    finding_id          UUID NOT NULL REFERENCES findings(id),
    rule                TEXT NOT NULL,
    revert_cmd          TEXT NOT NULL,
    verified_blocked    BOOLEAN NOT NULL DEFAULT false,
    verified_benign     BOOLEAN NOT NULL DEFAULT false,
    deployed_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### patches
```sql
CREATE TABLE patches (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES organisations(id),
    run_id          UUID NOT NULL REFERENCES runs(id),
    finding_id      UUID NOT NULL REFERENCES findings(id),
    diff_hash       TEXT NOT NULL,
    diff_ref        TEXT NOT NULL,              -- storage key
    root_cause      TEXT NOT NULL,
    iteration       INTEGER NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    -- status: pending | passed | refuted
    refuting_input  TEXT,                       -- storage key, NULL unless refuted
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### certificates
```sql
CREATE TABLE certificates (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES organisations(id),
    run_id          UUID NOT NULL REFERENCES runs(id),
    finding_id      UUID NOT NULL REFERENCES findings(id),
    level           CHAR(1) NOT NULL CHECK (level IN ('A','B','C','R')),
    evidence_hashes TEXT[] NOT NULL,
    signature       TEXT NOT NULL,
    signed_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### audit_events
```sql
CREATE TABLE audit_events (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       UUID NOT NULL REFERENCES organisations(id),
    run_id          UUID,
    actor_id        UUID,                       -- user or system
    action          TEXT NOT NULL,
    subject_type    TEXT NOT NULL,
    subject_id      TEXT NOT NULL,
    evidence_hash   TEXT,
    metadata        JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    prev_hash       TEXT                        -- hash-chained
);
-- append-only: no UPDATE or DELETE on this table
```

### artifact_store
```sql
CREATE TABLE artifact_store (
    sha256          TEXT PRIMARY KEY,
    tenant_id       UUID NOT NULL REFERENCES organisations(id),
    kind            TEXT NOT NULL,
    -- kind: diff | log | trace | report | binary | corpus | certificate
    size_bytes      INTEGER NOT NULL,
    storage_path    TEXT NOT NULL,              -- filesystem or object store path
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

---

## Row-level security

RLS is enabled on every table that has a `tenant_id` column.

```sql
-- Enable RLS
ALTER TABLE runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE shields ENABLE ROW LEVEL SECURITY;
ALTER TABLE patches ENABLE ROW LEVEL SECURITY;
ALTER TABLE certificates ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE artifact_store ENABLE ROW LEVEL SECURITY;

-- Policy: sessions can only see their own tenant's rows
CREATE POLICY tenant_isolation ON runs
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

CREATE POLICY tenant_isolation ON findings
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- (same pattern for all tables)
```

The application sets `app.tenant_id` at the start of every request:
```python
async def set_tenant_context(conn, tenant_id: str):
    await conn.execute(f"SET LOCAL app.tenant_id = '{tenant_id}'")
```

---

## RBAC — permission model

```sql
CREATE TABLE memberships (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES organisations(id),
    user_id     UUID NOT NULL,
    project_id  UUID,                           -- NULL = org-level role
    role        TEXT NOT NULL,
    -- role: owner | maintainer | sec_reviewer | developer | viewer | auditor
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, user_id, project_id)
);
```

Permission checks are done in the API layer, not in SQL.
The RLS layer enforces tenant isolation.
The API layer enforces role-based access.

### Permission matrix (enforced in API)

| Permission | owner | maintainer | sec_reviewer | developer | viewer | auditor |
|---|---|---|---|---|---|---|
| run:start | ✓ | ✓ | | | | |
| finding:read | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| finding:read_pov | ✓ | ✓ | ✓ | | | |
| patch:review | ✓ | ✓ | ✓ | ✓ | | |
| patch:publish | ✓ | ✓ | | | | |
| policy:manage | ✓ | | | | | |
| member:manage | ✓ | | | | | |
| audit:read | ✓ | ✓ | ✓ | | | ✓ |
| run:abort | ✓ | ✓ | | | | |

`finding:read_pov` is the sensitive one — working exploits are only
visible to roles that explicitly need them.

---

## LangGraph checkpointer

LangGraph needs a checkpointer to persist state after each node.
We implement a Postgres-backed checkpointer:

```python
class PostgresCheckpointer:
    async def put(self, run_id: str, state: KavachState) -> None:
        # serialise state to JSONB
        # upsert into runs.state_snapshot
        # update runs.phase
        ...

    async def get(self, run_id: str) -> KavachState | None:
        # fetch state_snapshot from runs
        # deserialise
        ...
```

This is what makes resume-on-crash work.

---

## Migrations

Use Alembic. Migration files live in `db/migrations/`.

```
db/
  migrations/
    env.py
    versions/
      0001_initial_schema.py
      0002_add_rls_policies.py
      0003_add_audit_chain.py
```

Run migrations before starting the API server.

---

## Indexes

```sql
-- Runs by project, ordered by start time
CREATE INDEX idx_runs_project ON runs (project_id, started_at DESC);

-- Findings by run
CREATE INDEX idx_findings_run ON findings (run_id, status);

-- Audit events by tenant (for audit log queries)
CREATE INDEX idx_audit_tenant ON audit_events (tenant_id, created_at DESC);

-- Artifact lookup by sha256 (already primary key, no extra index needed)
```

---

## Audit log integrity

The audit log is append-only and hash-chained.

```python
def compute_audit_hash(event: dict, prev_hash: str) -> str:
    payload = json.dumps({
        "prev_hash": prev_hash,
        "actor_id": event["actor_id"],
        "action": event["action"],
        "subject_type": event["subject_type"],
        "subject_id": event["subject_id"],
        "evidence_hash": event["evidence_hash"],
        "created_at": event["created_at"],
    }, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()
```

No UPDATE or DELETE is permitted on `audit_events`.
The database role used by the application does not have those privileges
on this table.
