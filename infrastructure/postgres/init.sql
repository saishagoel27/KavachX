-- First-boot SQL for the KavachX database.
--
-- Alembic owns the schema; this file exists only for things migrations cannot do portably:
-- extensions and roles. It runs once, on an empty data directory.

-- gen_random_uuid(), in case a future migration wants a server-side default.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Query statistics, useful when profiling the evidence-graph reads.
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- A read-only role subject to the row-level security policies created by migration 0002_rls.
-- Reporting tools and ad-hoc queries should connect as this role, not as the owner: a table owner
-- is not subject to RLS unless FORCE ROW LEVEL SECURITY is set.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kavachx_reader') THEN
        CREATE ROLE kavachx_reader NOLOGIN;
    END IF;
END
$$;

COMMENT ON DATABASE kavachx IS
    'KavachX — runs, findings, evidence graph, certificates and the hash-chained audit log.';
