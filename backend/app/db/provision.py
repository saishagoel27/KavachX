"""Startup database provisioning: bring the schema to head, then seed the demo tenant.

Why this exists. The Docker entrypoint already runs ``alembic upgrade head`` and the seed before
handing over to uvicorn, but a developer starting the API directly (``make dev``, ``uvicorn
app.main:app``) against a freshly created database gets a server that boots cleanly and then fails
every request with ``relation "users" does not exist``. That failure is indistinguishable from a
real bug at the point where it surfaces — a 500 on ``POST /api/auth/login``. Provisioning at
startup removes the ordering trap: the process that needs the schema is the process that ensures
it.

What it does *not* do. It never creates tables from ``Base.metadata`` directly. Alembic is the only
thing that writes schema, so the automatic path and the manual one produce the identical database
— including the row-level-security policies in ``0002_rls``, which ``create_all`` would silently
skip — and ``alembic_version`` always reflects reality.

Every step is a no-op when its work is already done, so a restart costs one revision check.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import inspect, text
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import AsyncEngine

from app.config import BACKEND_ROOT, settings
from app.core.logging import get_logger
from app.db.session import get_engine

logger = get_logger(__name__)

#: Advisory-lock key ('KXPR'), so that N uvicorn workers or replicas booting at once run the
#: migration and the seed one at a time instead of racing each other into a duplicate-key error.
_ADVISORY_LOCK_KEY = 0x4B58_5052


# ---------------------------------------------------------------------------
# alembic plumbing. Imported lazily: alembic is a runtime dependency of provisioning only, and
# importing it at module scope would pull it into every process that touches app.db.
def _alembic_config() -> object:
    from alembic.config import Config

    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    # Absolute, because the working directory of the serving process is not guaranteed to be
    # backend/ the way it is for `make migrate`.
    config.set_main_option("script_location", str(BACKEND_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", settings.database_url)
    return config


def _head_revision() -> str | None:
    from alembic.script import ScriptDirectory

    return ScriptDirectory.from_config(_alembic_config()).get_current_head()


def _current_revision(connection: Connection) -> str | None:
    from alembic.runtime.migration import MigrationContext

    return MigrationContext.configure(connection).get_current_revision()


def _upgrade_to_head() -> None:
    """Blocking ``alembic upgrade head``; always call via ``asyncio.to_thread``.

    ``migrations/env.py`` drives its own async engine with ``asyncio.run``, which raises inside a
    running event loop — a worker thread gives it the loop-free context it expects.
    """
    from alembic import command

    command.upgrade(_alembic_config(), "head")


# ---------------------------------------------------------------------------
def _table_names(connection: Connection) -> set[str]:
    return set(inspect(connection).get_table_names())


@asynccontextmanager
async def _provision_lock(engine: AsyncEngine) -> AsyncIterator[None]:
    """Serialise provisioning across processes. A no-op on SQLite (single-writer anyway)."""
    if engine.dialect.name != "postgresql":
        yield
        return
    async with engine.connect() as connection:
        await connection.execute(text("SELECT pg_advisory_lock(:key)"), {"key": _ADVISORY_LOCK_KEY})
        try:
            yield
        finally:
            try:
                await connection.execute(
                    text("SELECT pg_advisory_unlock(:key)"), {"key": _ADVISORY_LOCK_KEY}
                )
                await connection.commit()
            except Exception:  # pragma: no cover - lock also dies with the session
                logger.warning("db.advisory_unlock_failed")


async def _wait_for_database(engine: AsyncEngine) -> bool:
    """Poll ``SELECT 1`` until the server answers or the configured budget runs out."""
    deadline = max(0, settings.db_startup_wait_seconds)
    for attempt in range(deadline + 1):
        try:
            async with engine.connect() as connection:
                await connection.execute(text("SELECT 1"))
            if attempt:
                logger.info("db.reachable", after_seconds=attempt)
            return True
        except Exception as exc:
            if attempt == 0:
                logger.info("db.waiting", budget_seconds=deadline, error=str(exc)[:200])
            if attempt < deadline:
                await asyncio.sleep(1)
    return False


async def ensure_schema(engine: AsyncEngine) -> str:
    """Migrate to head if needed.

    Returns what happened: ``created`` (empty database), ``upgraded`` (behind head), ``current``
    (nothing to do) or ``unversioned`` (tables exist but Alembic does not know about them).
    """
    head = _head_revision()
    async with engine.connect() as connection:
        current = await connection.run_sync(_current_revision)
        tables = await connection.run_sync(_table_names)
    existing = tables - {"alembic_version"}

    if current is not None and current == head:
        logger.info("db.schema_current", revision=current, tables=len(existing))
        return "current"

    if current is None and existing:
        # Someone built this database outside Alembic (a stray create_all, a hand-made schema).
        # Upgrading would fail on the first CREATE TABLE and stamping would assert a history that
        # may not be true, so say so loudly and leave it alone.
        logger.warning(
            "db.schema_unversioned",
            tables=len(existing),
            head=head,
            note=(
                "Tables exist but alembic_version is empty, so the schema was not created by a "
                "migration. Auto-migration skipped. Reconcile with 'alembic stamp head' (if the "
                "schema is at head) or drop and recreate the database."
            ),
        )
        return "unversioned"

    await asyncio.to_thread(_upgrade_to_head)
    outcome = "created" if current is None else "upgraded"
    logger.info("db.schema_migrated", outcome=outcome, previous=current or "empty", head=head)
    return outcome


async def ensure_local_examples() -> list[str]:
    """Attach any ``examples/`` folder the demo project does not have yet.

    The seed covers a fresh database, but not the common case: a deployment that was seeded weeks
    ago and has just pulled in new example folders. Without this, those folders exist on disk and
    are invisible in the repository dropdown until somebody attaches them by hand. Adding only —
    repositories attached through the UI are never touched.
    """
    from app.db.examples import ensure_example_repositories

    return await ensure_example_repositories()


async def ensure_demo_seed() -> bool:
    """Seed the demo tenant when it is absent. True if this call created it."""
    from app.db.seed import demo_tenant_present, seed

    if await demo_tenant_present():
        logger.info("db.seed_present", user=settings.demo_user_email)
        return False
    result = await seed()
    logger.info(
        "db.seeded",
        user=result["user_email"],
        organisation=result["organisation_slug"],
        repository=result["repository_id"],
    )
    return True


async def provision_database() -> None:
    """Called once from the application lifespan. Never raises — startup is not the place to die.

    A provisioning failure is logged and ``/ready`` reports ``degraded``; the alternative (crashing
    the process) hides the reason behind a restart loop.
    """
    if not settings.db_auto_provision:
        logger.info("db.provision_disabled", note="DB_AUTO_PROVISION=false")
        return

    engine = get_engine()
    if not await _wait_for_database(engine):
        logger.error(
            "db.unreachable",
            waited_seconds=settings.db_startup_wait_seconds,
            note="Schema and seed skipped. Start the database ('make db') and restart the API.",
        )
        return

    try:
        async with _provision_lock(engine):
            state = await ensure_schema(engine)
            if state == "unversioned":
                return
            if settings.seed_demo:
                await ensure_demo_seed()
                await ensure_local_examples()
    except Exception as exc:
        logger.error(
            "db.provision_failed",
            error_type=type(exc).__name__,
            error=str(exc)[:500],
            note="Run 'make migrate && make seed' to see the full failure.",
        )
