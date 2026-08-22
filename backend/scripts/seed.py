"""Seed the demo tenant from the command line.

The seed itself lives in :mod:`app.db.seed`, because the application startup provisioner
(:mod:`app.db.provision`) runs the same code. This module is the CLI around it: run it with
``python -m scripts.seed`` from ``backend/`` (or ``make seed``).
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.logging import configure_logging, get_logger
from app.db.seed import ROLE_USERS, SeedError, seed, slugify

configure_logging()
logger = get_logger(__name__)

__all__ = ["ROLE_USERS", "SeedError", "main", "seed", "slugify"]


async def main() -> None:
    try:
        result = await seed()
    except SeedError as exc:
        raise SystemExit(str(exc)) from exc
    print("")
    print("  KavachX demo tenant ready")
    print("  " + "-" * 52)
    print(f"  email        {result['user_email']}")
    print(f"  password     {result['password']}")
    print(f"  organisation {result['organisation_slug']} ({result['organisation_id']})")
    print(f"  project      {result['project_id']}")
    print(f"  repository   {result['repository_id']}")
    print(f"  target path  {result['repository_path']}")
    print("")
    print("  Additional role accounts (same password):")
    for email in result["role_accounts"]:  # type: ignore[union-attr]
        print(f"    - {email}")
    print("")


if __name__ == "__main__":
    asyncio.run(main())
