"""CLI entrypoint for the demo report service.

Reads one JSON request from ``--request``, ``--request-file`` or stdin, dispatches it, and
prints the JSON response on stdout.

Exit codes
----------
0   request handled (including a structured ``ok: false`` response)
1   unhandled exception inside the service — the traceback goes to stderr
2   the CLI itself could not read a valid request
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from reportsvc import service  # noqa: E402


def _read_request(args: argparse.Namespace) -> dict:
    if args.request:
        return json.loads(args.request)
    if args.request_file:
        return json.loads(Path(args.request_file).read_text(encoding="utf-8"))
    data = sys.stdin.read()
    if not data.strip():
        raise ValueError("no request provided")
    return json.loads(data)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="reportsvc")
    parser.add_argument("--request", help="inline JSON request")
    parser.add_argument("--request-file", help="path to a JSON request file")
    args = parser.parse_args(argv)

    try:
        request = _read_request(args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": f"bad request: {exc}"}), file=sys.stderr)
        return 2

    try:
        response = service.entrypoint(request)
    except Exception:
        traceback.print_exc(file=sys.stderr)
        return 1

    print(json.dumps(response, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
