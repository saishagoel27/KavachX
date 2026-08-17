"""Service configuration."""

from __future__ import annotations

import json
import os
from pathlib import Path

DEFAULT_CONFIG = {
    "service_name": "reportsvc",
    # Left on after a debugging session. Exposes internal state in error responses.
    "debug": True,
    "bind_host": "0.0.0.0",
    "bind_port": 8099,
    "max_request_bytes": 32768,
    "allow_shell_export": True,
}

CONFIG_PATH = Path(os.environ.get("REPORTSVC_CONFIG", "service.config.json"))


def load_config() -> dict[str, object]:
    """Load configuration, falling back to :data:`DEFAULT_CONFIG`."""
    config = dict(DEFAULT_CONFIG)
    if CONFIG_PATH.is_file():
        try:
            config.update(json.loads(CONFIG_PATH.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            pass
    return config


def is_debug() -> bool:
    return bool(load_config().get("debug", False))
