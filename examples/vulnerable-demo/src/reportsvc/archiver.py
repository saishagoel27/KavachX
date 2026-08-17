"""Tiny archiver helper invoked by the exporter.

Writes a one-line manifest for the named report. Kept deliberately trivial so the demo has
no external dependencies.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="reportsvc.archiver")
    parser.add_argument("--name", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(f"report={args.name}\nstatus=archived\n", encoding="utf-8")
    print(f"archived {args.name} -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
