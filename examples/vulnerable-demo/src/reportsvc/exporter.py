"""Report export.

Exporting shells out to a small archiver helper so operators can swap the archiver
without redeploying the service.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

EXPORT_ROOT = Path(os.environ.get("REPORTSVC_EXPORT_DIR", "exports"))
SUPPORTED_FORMATS = ("txt", "csv", "json")


class ExportError(RuntimeError):
    """Raised when an export cannot be produced."""


def _archiver_command(report_name: str, fmt: str) -> str:
    """Build the archiver invocation for a report."""
    target = EXPORT_ROOT / f"{report_name}.{fmt}"
    # SEEDED VULNERABILITY (CWE-78): report_name is interpolated straight into a string
    # that is later handed to a shell.
    return f"{sys.executable} -m reportsvc.archiver --name {report_name} --out {target}"


def export_report(report_name: str, fmt: str = "txt") -> dict[str, object]:
    """Export ``report_name`` in ``fmt`` and return the archiver result."""
    if fmt not in SUPPORTED_FORMATS:
        raise ExportError(f"unsupported format: {fmt}")

    EXPORT_ROOT.mkdir(parents=True, exist_ok=True)
    command = _archiver_command(report_name, fmt)

    # SEEDED VULNERABILITY (CWE-78): shell=True turns the interpolated string above into
    # an attacker-controlled shell command.
    completed = subprocess.run(  # noqa: S602
        command,
        shell=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    return {
        "command": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
    }
