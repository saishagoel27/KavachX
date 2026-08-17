"""Behavioural tests for the demo service.

These are the target's *own* tests. They pass on the vulnerable code and must still pass
after KavachX patches it — that is what the differential-replay stage of the Refutation
Gauntlet checks for behavioural regression.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from reportsvc import assets, parser, service  # noqa: E402


def test_ping_is_ok():
    response = service.handle({"op": "ping"})
    assert response["ok"] is True
    assert response["service"] == "reportsvc"


def test_sequence_is_monotonic():
    first = service.handle({"op": "ping"})["seq"]
    second = service.handle({"op": "ping"})["seq"]
    assert second == first + 1


def test_parse_single_header():
    response = service.handle({"op": "parse", "headers": "x-trace-id:9f2a\n"})
    assert response["headers"] == {"x-trace-id": "9f2a"}
    assert response["count"] == 1


def test_parse_multiple_headers_preserves_order_and_values():
    raw = "x-trace-id:1c04\nx-tenant:globex\naccept:text/csv\n"
    response = service.handle({"op": "parse", "headers": raw})
    assert response["headers"] == {
        "x-trace-id": "1c04",
        "x-tenant": "globex",
        "accept": "text/csv",
    }


def test_parse_rejects_malformed_line():
    result = service.entrypoint({"op": "parse", "headers": "not-a-header\n"})
    assert result["ok"] is False
    assert "malformed" in result["error"]


def test_parse_accepts_slot_capacity():
    raw = "\n".join(f"h{i}:{i}" for i in range(parser.MAX_HEADER_SLOTS))
    response = service.handle({"op": "parse", "headers": raw})
    assert len(response["headers"]) == parser.MAX_HEADER_SLOTS


def test_export_returns_archiver_result(tmp_path, monkeypatch):
    monkeypatch.setenv("REPORTSVC_EXPORT_DIR", str(tmp_path))
    monkeypatch.setattr("reportsvc.exporter.EXPORT_ROOT", tmp_path)
    response = service.handle({"op": "export", "name": "q3-summary", "format": "txt"})
    assert response["ok"] is True
    assert response["export"]["returncode"] == 0
    assert (tmp_path / "q3-summary.txt").is_file()


def test_export_rejects_unknown_format():
    try:
        service.handle({"op": "export", "name": "x", "format": "pdf"})
    except Exception as exc:  # noqa: BLE001
        assert "unsupported format" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected ExportError")


def test_asset_reads_template(monkeypatch):
    root = Path(__file__).resolve().parents[1] / "assets"
    monkeypatch.setattr(assets, "ASSET_ROOT", root)
    content = assets.read_asset("report.tmpl")
    assert "REPORT:" in content


def test_unknown_op_is_rejected():
    result = service.entrypoint({"op": "teleport"})
    assert result["ok"] is False


def test_cli_round_trip(tmp_path):
    main_py = SRC / "main.py"
    completed = subprocess.run(
        [sys.executable, str(main_py), "--request", json.dumps({"op": "ping"})],
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
        timeout=30,
    )
    assert completed.returncode == 0
    assert json.loads(completed.stdout)["ok"] is True
