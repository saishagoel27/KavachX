"""
Discovery channels.

Each channel module exposes `async scan(channel, state) -> list[dict]`.
`kavachx.discovery` imports them by name (e.g. `semgrep_scanner`), so a new
channel is added by dropping a module here and referencing it there.
"""

from kavachx.discovery.channels import semgrep_scanner
from kavachx.discovery.channels.semgrep_scanner import scan

__all__ = [
    "semgrep_scanner",
    "scan",
]
