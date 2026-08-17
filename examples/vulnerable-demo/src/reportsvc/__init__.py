"""reportsvc — a deliberately vulnerable demo report service.

SECURITY NOTICE
===============
This package contains **intentionally seeded vulnerabilities**. It exists solely as a
deterministic analysis target for the KavachX proof of concept. It is not a library,
it is not maintained, and it must never be deployed or installed anywhere.

Seeded weaknesses (see docs/DEMO.md for the full walkthrough):

* ``exporter.export_report``  — OS command injection via ``shell=True`` (CWE-78)
* ``parser.parse_header``     — unchecked length boundary on a fixed slot table (CWE-1284)
* ``assets.read_asset``       — path traversal outside the asset root (CWE-22)
* ``config.load_config``      — debug mode leaks internal state (CWE-489)
"""

__version__ = "0.4.2"
__all__ = ["assets", "config", "exporter", "parser", "service"]
