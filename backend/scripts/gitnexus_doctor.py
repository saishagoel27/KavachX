"""Report whether GitNexus is usable here, and what a run loses if it is not.

Backs ``make gitnexus-doctor``. It answers one question — *will this machine index with resolved
references, or with name matches only?* — and says what the consequence is either way, because
"GitNexus not found" is not an error: the pipeline runs without it, at a lower and **stated**
precision.

Nothing here indexes anything. It resolves the binary exactly as
:func:`app.indexing.gitnexus.resolve_command` does at run time, so what it prints is what a run
will actually get.
"""

from __future__ import annotations

import sys

from app.config import settings
from app.indexing.gitnexus import resolve_command
from app.indexing.versions import collect_versions

RESOLUTION_NOTES = {
    "env": "found via GITNEXUS_BIN",
    "path": "found on PATH",
    "repo-local": "found in ./gitnexus/node_modules/.bin (installed by `make gitnexus`)",
    "npx": "resolved through npx — this reaches the network on first use",
}


def _line(key: str, value: object) -> None:
    print(f"  {key:<22} {value}")


def main() -> int:
    print("\nGITNEXUS DOCTOR\n" + "=" * 60)

    _line("enabled", settings.gitnexus_enabled)
    _line("GITNEXUS_BIN", settings.gitnexus_bin or "(unset)")
    _line("npx fallback allowed", settings.gitnexus_allow_npx)
    _line("pinned version", settings.gitnexus_version)

    if not settings.gitnexus_enabled:
        print("\n  GitNexus is disabled by configuration (GITNEXUS_ENABLED=false).")
        print("  Runs will index with tree-sitter only. That is a supported configuration:")
        print("  every relationship becomes a name match rather than a resolved reference, and")
        print("  the index health report records that bound on every certificate.\n")
        return 0

    info = resolve_command()
    print()
    _line("available", info.available)
    _line("version", info.version or "-")
    _line("resolution", f"{info.resolution or '-'}  {RESOLUTION_NOTES.get(info.resolution, '')}")
    _line("command", " ".join(info.command) if info.command else "-")
    _line("node", info.node_version or "not found")

    versions = collect_versions(
        gitnexus_version=info.version,
        gitnexus_resolution=info.resolution,
        node_version=info.node_version,
    ).as_dict()
    print("\n  index identity inputs (these decide the reproducible index_id)")
    for key, value in sorted(versions.items()):
        _line(f"  {key}", value)

    print()
    if info.available:
        print("  OK - runs will merge GitNexus (resolved, precise, incomplete) with tree-sitter")
        print("  (name-matched, complete, imprecise), and tag every edge with the provider that")
        print("  produced it. graph_source will name both.\n")
        return 0

    print(f"  NOT AVAILABLE - {info.reason or 'GitNexus could not be resolved.'}")
    print()
    print("  This is not a failure. Runs still index, still derive flows, still fuzz, still")
    print("  validate and still certify - with tree-sitter alone, at 0% resolved references.")
    print("  The index health report adds the bound, and every claim built on reachability")
    print("  inherits it.")
    print()
    print("  To install it repo-locally:   make gitnexus")
    print("  Requires Node >= 22.          See docs/CODE_GRAPH.md")
    print("  Licence: PolyForm Noncommercial 1.0.0 (GitNexus only, not KavachX).\n")
    # Absence is a reportable state, not a broken machine, so this is still a clean exit.
    return 0


if __name__ == "__main__":
    sys.exit(main())
