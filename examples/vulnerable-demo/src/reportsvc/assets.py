"""Static asset lookup for report templates."""

from __future__ import annotations

import os
from pathlib import Path

ASSET_ROOT = Path(os.environ.get("REPORTSVC_ASSET_DIR", "assets"))
MAX_ASSET_BYTES = 65536


class AssetError(RuntimeError):
    """Raised when an asset cannot be served."""


def read_asset(relative_path: str) -> str:
    """Read a template asset by its path relative to :data:`ASSET_ROOT`."""
    if not relative_path:
        raise AssetError("empty asset path")

    # SEEDED VULNERABILITY (CWE-22): the joined path is never confined to ASSET_ROOT, so
    # ../ sequences escape the asset directory.
    candidate = ASSET_ROOT / relative_path

    if not candidate.exists():
        raise AssetError(f"asset not found: {relative_path}")
    if candidate.is_dir():
        raise AssetError(f"asset is a directory: {relative_path}")

    data = candidate.read_bytes()[:MAX_ASSET_BYTES]
    return data.decode("utf-8", errors="replace")


def list_assets() -> list[str]:
    if not ASSET_ROOT.is_dir():
        return []
    return sorted(p.name for p in ASSET_ROOT.iterdir() if p.is_file())
