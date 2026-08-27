"""Builders for small fixture repositories.

Every builder returns the tree's root. They write real files rather than mocking the filesystem
because the whole point of the indexing layer is what it does to real source, and a mocked walker
would test the mock.
"""

from __future__ import annotations

import json
from pathlib import Path


def _write(root: Path, relative: str, content: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")
    return path


def minimal_python(root: Path) -> Path:
    """A resolvable call chain from a CLI entrypoint to a shell sink.

    Shaped to exercise the properties the graph layer must get right:

    * ``main`` has a ``__main__`` guard, so it is an entrypoint by convention;
    * ``main -> handle -> run_export`` is a real chain across two files, so a caller/callee query
      and a reachability walk both have something to find;
    * ``run_export`` interpolates its argument into a ``shell=True`` call, so the flow builder has
      a real sink to stitch a call-graph flow to. Note it takes the value as a *parameter*, so
      intra-procedural taint alone cannot prove derivation here — that is stitched along the call
      edge from ``handle``, and the AST-only case is covered separately;
    * ``safe_export`` uses ``shlex.quote``, so there is a sanitizer for the flow builder to find on
      a path — and the flow through it must be reported as lower-confidence, not as absent.
    """
    _write(
        root,
        "src/app/main.py",
        '''"""CLI entrypoint."""

from __future__ import annotations

import argparse
import json
import sys

from app.service import handle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="fixture")
    parser.add_argument("--request", required=True)
    args = parser.parse_args(argv)
    request = json.loads(args.request)
    print(json.dumps(handle(request), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
''',
    )
    _write(
        root,
        "src/app/service.py",
        '''"""Request dispatch."""

from __future__ import annotations

from app.exporter import run_export, safe_export


def handle(request: dict) -> dict:
    operation = request.get("op", "")
    if operation == "export":
        return {"export": run_export(request.get("name", ""))}
    if operation == "safe":
        return {"export": safe_export(request.get("name", ""))}
    return {"ok": True}
''',
    )
    _write(
        root,
        "src/app/exporter.py",
        '''"""Export operations."""

from __future__ import annotations

import shlex
import subprocess


def run_export(name: str) -> dict:
    # A source-derived value interpolated into a shell command line.
    command = f"echo {name}"
    completed = subprocess.run(command, shell=True, capture_output=True, text=True)
    return {"stdout": completed.stdout}


def safe_export(name: str) -> dict:
    # The same operation with the value quoted first: a sanitizer on the path.
    command = f"echo {shlex.quote(name)}"
    completed = subprocess.run(command, shell=True, capture_output=True, text=True)
    return {"stdout": completed.stdout}
''',
    )
    _write(root, "src/app/__init__.py", "")
    _write(
        root,
        "pyproject.toml",
        # One dependency per line: both the conventional layout and the one the pyproject parser
        # anchors on. `pyyaml` is here so the sensitive-library flag has something to find.
        '[project]\nname = "fixture"\nversion = "0.1.0"\n'
        'dependencies = [\n    "pyyaml>=6.0",\n    "requests>=2.0",\n]\n',
    )
    return root


def with_tests(root: Path) -> Path:
    """Add a pytest suite that references two of the symbols, for test discovery."""
    _write(
        root,
        "tests/test_service.py",
        '''"""Fixture test suite."""

import pytest

from app.service import handle


def test_handle_default():
    assert handle({}) == {"ok": True}


def test_handle_export():
    result = handle({"op": "export", "name": "x"})
    assert "export" in result
''',
    )
    return root


def with_config(root: Path) -> Path:
    """Add configuration carrying two security-relevant settings, plus data that is not config.

    The ``corpus/`` JSON files exist to prove the *negative*: they must not be counted as
    configuration. Miscounting them inflates the index's config counter and feeds the
    reachability channel a pile of request payloads to chase.
    """
    _write(root, "settings.yaml", "debug: true\nhost: 0.0.0.0\nport: 8099\n")
    _write(root, ".env", "APP_SECRET=change-me\nAPP_DEBUG=1\n")
    for index in range(3):
        _write(
            root,
            f"corpus/benign/{index:03d}-case.json",
            json.dumps({"op": "export", "name": f"case-{index}"}, indent=2),
        )
    return root


def with_http_routes(root: Path) -> Path:
    """A Flask-shaped module: HTTP sources, a route decorator, and an auth control."""
    _write(
        root,
        "src/app/web.py",
        '''"""HTTP surface."""

from __future__ import annotations

from flask import Flask, request

from app.exporter import run_export

app = Flask(__name__)


def login_required(fn):
    return fn


@app.route("/export", methods=["POST"])
def export_endpoint():
    # An attacker-controlled request body reaching a shell sink.
    name = request.json.get("name", "")
    return run_export(name)


@app.route("/admin", methods=["GET"])
@login_required
def admin_endpoint():
    return {"ok": True}
''',
    )
    return root


def with_unparseable(root: Path) -> Path:
    """A file with a syntax error. Indexing must degrade, not fail."""
    _write(root, "src/app/broken.py", "def broken(:\n    return 1\n")
    return root


def with_minified_bundle(root: Path) -> Path:
    """A vendored bundle. Must be hashed but excluded from analysis."""
    _write(
        root,
        "src/static/vendor.min.js",
        "!function(){" + "var a=1;" * 900 + "}();\n",
    )
    return root


def with_boundary_branch(root: Path) -> Path:
    """A function with an unreached boundary branch, for code-aware fuzzing."""
    _write(
        root,
        "src/app/pager.py",
        '''"""Pagination."""

from __future__ import annotations


def page(limit: int) -> dict:
    if limit < 0:
        raise ValueError("negative limit")
    if limit > 100:
        return {"limit": 100, "clamped": True}
    return {"limit": limit, "clamped": False}
''',
    )
    return root


def empty(root: Path) -> Path:
    """A tree with no source at all. The index must report itself unusable."""
    _write(root, "README.md", "# nothing to see\n")
    return root


def full(root: Path) -> Path:
    """Everything: the standard fixture used by most tests."""
    minimal_python(root)
    with_tests(root)
    with_config(root)
    with_boundary_branch(root)
    return root
