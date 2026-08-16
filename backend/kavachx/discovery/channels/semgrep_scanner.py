"""
Semgrep-based vulnerability scanner for GitHub repositories.

Integrates with Semgrep CLI to scan repositories for:
- CVEs (via Semgrep registry)
- Misconfigurations (IaC, Dockerfile, config files)
- Code quality issues
- Compliance violations
"""

import json
import logging
import subprocess
from typing import Optional

logger = logging.getLogger(__name__)


async def scan(
    channel: str,
    state: dict,
) -> list[dict]:
    """
    Scan a GitHub channel using Semgrep.

    Args:
        channel: Channel name (org/repo#branch)
        state: KavachState for auth context

    Returns:
        List of findings from Semgrep
    """
    logger.info(f"[Semgrep] Scanning {channel}")

    # Parse channel format: org/repo#branch
    try:
        repo_part, branch = channel.split("#")
        org, repo = repo_part.split("/")
    except ValueError:
        logger.error(f"[Semgrep] Invalid channel format: {channel}")
        return []

    # TODO: In real implementation:
    # 1. Clone/checkout the repo at specific branch
    # 2. Run: semgrep --config=p/cwe-top-25 --json --output=findings.json .
    # 3. Parse JSON results
    # 4. Enrich with metadata (component, severity, remediation)

    # For now, return mock findings for demo
    return _mock_findings(channel)


def _mock_findings(channel: str) -> list[dict]:
    """
    Generate mock findings for demo/test purposes.

    In production, this would be actual Semgrep results.
    """
    return [
        {
            "id": f"cve-2024-001",
            "type": "cve",
            "title": "SQL Injection in user input validation",
            "description": "User-supplied input is not properly sanitized before SQL queries",
            "severity": "high",
            "component": "auth module",
            "remediation_path": "kavachx/api/routes/auth.py:45",
            "cwe": "CWE-89",
        },
        {
            "id": f"misconfig-001",
            "type": "misconfig",
            "title": "Hardcoded API keys in environment config",
            "description": "API keys should be fetched from secure storage, not hardcoded",
            "severity": "critical",
            "component": "config",
            "remediation_path": "docker-compose.yml:15",
            "cwe": "CWE-798",
        },
    ]


__all__ = [
    "scan",
]
