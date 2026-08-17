#!/usr/bin/env bash
# Bring the database to head, seed the demo tenant, then hand over to the server.
#
# Migrations run here rather than in a separate job so `docker compose up` is a single command.
# The seed is idempotent, so a restart does not duplicate anything.
set -euo pipefail

echo "[kavachx] waiting for the database"
python - <<'PY'
import asyncio, os, sys
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

url = os.environ.get("DATABASE_URL", "")

async def wait() -> int:
    for attempt in range(60):
        engine = create_async_engine(url)
        try:
            async with engine.connect() as connection:
                await connection.execute(text("SELECT 1"))
            await engine.dispose()
            print(f"[kavachx] database reachable after {attempt}s")
            return 0
        except Exception as exc:
            await engine.dispose()
            if attempt == 0:
                print(f"[kavachx] database not ready yet: {exc}")
            await asyncio.sleep(1)
    print("[kavachx] database never became reachable", file=sys.stderr)
    return 1

sys.exit(asyncio.run(wait()))
PY

echo "[kavachx] applying migrations"
alembic upgrade head

if [ "${SEED_DEMO:-true}" = "true" ]; then
  echo "[kavachx] seeding the demo tenant"
  python -m scripts.seed || echo "[kavachx] seed skipped or already applied"
fi

echo "[kavachx] starting: $*"
exec "$@"
