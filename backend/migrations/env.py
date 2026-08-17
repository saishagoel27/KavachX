"""Alembic environment.

The URL comes from ``DATABASE_URL`` rather than ``alembic.ini``, so migrations always target the
same database the application does. Async engines are supported: ``run_migrations_online`` drives
the sync migration context inside a connection acquired from the async engine.
"""

from __future__ import annotations

import asyncio

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

# Importing the models package registers every table on Base.metadata.
from app.config import settings
from app.core.logging import configure_logging
from app.models import Base

config = context.config

# Deliberately *not* ``fileConfig(config.config_file_name)``. Alembic's default template configures
# stdlib handlers from the ``[logger_*]`` sections of alembic.ini, which would give migrations their
# own log format and sink separate from the rest of the application. configure_logging() installs
# logifyx as the single backend and bridges the ``alembic`` and ``sqlalchemy`` loggers into it, so a
# migration's output is masked, structured and rotated like everything else.
configure_logging()

config.set_main_option("sqlalchemy.url", settings.database_url)
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=settings.database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
        # SQLite cannot ALTER most things; batch mode rewrites the table instead. Harmless on
        # PostgreSQL and required for the sqlite path used by the test suite.
        render_as_batch=connection.dialect.name == "sqlite",
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
