#!/usr/bin/env python3
"""Drive KavachX's full pipeline end-to-end against the seeded vulnerable target, over the live API.

Unlike ``make demo`` (an in-process pytest), this creates a **real run through the running server**,
so everything it produces is persisted and shows up live in the console at
``<frontend>/console/runs/<id>``. It walks the same loop the product does:

    ingest -> index -> SAMHITA contract -> discovery (incl. the FUZZING channel)
           -> validate (reproduce the crash) -> shield -> root cause
           -> patch + gauntlet (re-attack) -> attest (signed certificate)

and prints, from real state, what each stage produced: the discovery channels that fired (proving
the fuzzer ran), the validated finding with its reproduction count, the deployed shield, the patch
that survived the gauntlet, and the certificate.

Prerequisites (the "infra" — see README):
  * backend up and reachable (default http://localhost:8000)
  * database migrated and seeded (`make bootstrap` / `make seed`)
  * for the gvisor execution profile, the sandbox images built on the backend host

Usage (stdlib only — no pip installs needed):
    python examples/full-pipeline-demo/run_pipeline.py
    python examples/full-pipeline-demo/run_pipeline.py --api http://<SERVER-IP>:8000 --execution gvisor
"""

from __future__ import annotations

import argparse
import json
import os
import time
import urllib.error
import urllib.request

DEFAULT_API = os.environ.get("KAVACHX_API", "http://localhost:8000").rstrip("/")
DEFAULT_FRONTEND = os.environ.get("KAVACHX_FRONTEND", "http://localhost:3000").rstrip("/")
DEFAULT_EMAIL = os.environ.get("KAVACHX_EMAIL", "demo@kavachx.io")
DEFAULT_PASSWORD = os.environ.get("KAVACHX_PASSWORD", "kavachx-demo-2024")
SEEDED_TARGET = "examples/vulnerable-demo"
TERMINAL = {"COMPLETED", "FAILED", "ABORTED", "AWAITING_APPROVAL"}


class Api:
    def __init__(self, base: str, token: str = "") -> None:
        self.base = base
        self.token = token

    def _call(self, method: str, path: str, body: dict | None = None) -> dict:
        url = f"{self.base}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("content-type", "application/json")
        if self.token:
            req.add_header("authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:  # the operator's own API URL
                raw = resp.read().decode()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode()[:400]
            raise SystemExit(f"\nAPI {method} {path} failed: HTTP {exc.code}\n{detail}") from exc
        except urllib.error.URLError as exc:
            raise SystemExit(
                f"\nCould not reach {url} ({exc.reason}). Is the backend up and --api correct?"
            ) from exc

    def get(self, path: str) -> dict:
        return self._call("GET", path)

    def post(self, path: str, body: dict) -> dict:
        return self._call("POST", path, body)


def banner(text: str) -> None:
    print(f"\n{'=' * 70}\n{text}\n{'=' * 70}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Drive the KavachX full pipeline over the live API."
    )
    parser.add_argument("--api", default=DEFAULT_API, help=f"API base (default {DEFAULT_API})")
    parser.add_argument(
        "--frontend", default=DEFAULT_FRONTEND, help="Console base for the run link"
    )
    parser.add_argument("--email", default=DEFAULT_EMAIL)
    parser.add_argument("--password", default=DEFAULT_PASSWORD)
    parser.add_argument("--analysis", default="quick", choices=["quick", "standard", "deep"])
    parser.add_argument(
        "--execution",
        default="dev_local",
        choices=["dev_local", "gvisor", "firecracker"],
        help="dev_local runs the trusted seeded demo on the host; gvisor runs it sandboxed",
    )
    parser.add_argument("--timeout", type=int, default=900, help="seconds to wait for the run")
    args = parser.parse_args()

    api = Api(args.api.rstrip("/"))

    banner("1. AUTH — logging in as the demo operator")
    token = api.post("/api/auth/login", {"email": args.email, "password": args.password})[
        "access_token"
    ]
    api.token = token
    print(f"   logged in as {args.email}")

    banner("2. TARGET — finding the seeded vulnerable repository")
    repos = api.get("/api/repositories")
    target = next((r for r in repos if r["full_name"] == SEEDED_TARGET), None)
    if target is None:
        raise SystemExit(
            f"   seeded target {SEEDED_TARGET!r} not found. Run `make seed` on the backend first."
        )
    if not target.get("authority_verified_at"):
        raise SystemExit(
            f"   {SEEDED_TARGET!r} has no verified authority — reseed the demo tenant."
        )
    print(f"   target: {target['full_name']}  (provider={target['provider']}, authority verified)")

    banner("3. START — creating a real run (visible in the console)")
    run = api.post(
        "/api/runs",
        {
            "repository_id": target["id"],
            "branch": target["default_branch"] or "main",
            "analysis_profile": args.analysis,
            "execution_profile": args.execution,
            "max_runtime_seconds": args.timeout,
            "authorisation_confirmed": True,
        },
    )
    run_id = run["id"]
    console_url = f"{args.frontend.rstrip('/')}/console/runs/{run_id}"
    print(f"   run {run['short_code']} started  ({args.analysis} / {args.execution})")
    print(f"   WATCH IT LIVE:  {console_url}")

    banner("4. PIPELINE — following each phase to completion")
    seen: set[str] = set()
    deadline = time.time() + args.timeout + 60
    detail: dict = {}
    while time.time() < deadline:
        detail = api.get(f"/api/runs/{run_id}")
        for phase, status in (detail.get("phase_status") or {}).items():
            marker = f"{phase}:{status}"
            if status in ("running", "completed", "failed", "blocked") and marker not in seen:
                seen.add(marker)
                glyph = {"running": "..", "completed": "OK", "failed": "XX", "blocked": "--"}.get(
                    status, "  "
                )
                print(f"   [{glyph}] {phase}")
        if detail["status"] in TERMINAL:
            break
        time.sleep(2.0)

    status = detail.get("status", "UNKNOWN")
    print(f"\n   run finished: status={status}  mode={detail.get('mode')}")
    if status not in ("COMPLETED", "AWAITING_APPROVAL"):
        raise SystemExit(f"   run did not complete cleanly: {detail.get('error_message', '')}")

    # --- infra / sandbox evidence ------------------------------------------------
    banner("5. INFRA & SANDBOX — how the target was executed")
    sandbox = detail.get("sandbox") or {}
    print(f"   pinned source sha256 : {detail.get('pinned_source_sha256', '')[:32]}…")
    print(f"   sandbox adapter      : {sandbox.get('adapter', args.execution)}")
    print(f"   sandbox executions   : {detail.get('sandbox_executions')}")
    print(f"   network egress       : {detail.get('egress_bytes')} bytes")
    print(f"   coverage             : {detail.get('coverage_percent')}%")

    # --- discovery: prove the fuzzer ran -----------------------------------------
    banner("6. DISCOVERY — channels that fired (the fuzzer is one of them)")
    hypotheses = api.get(f"/api/runs/{run_id}/hypotheses")
    channels: dict[str, int] = {}
    for hyp in hypotheses:
        channels[hyp["source_channel"]] = channels.get(hyp["source_channel"], 0) + 1
    for channel, count in sorted(channels.items()):
        star = "  <- FUZZER" if channel == "fuzzing" else ""
        print(f"   {channel:12} {count} candidate(s){star}")
    if "fuzzing" not in channels:
        print("   (no fuzzing candidates this run — the seeded bug was found by another channel)")

    # --- validation: reproduced findings -----------------------------------------
    banner("7. VALIDATION — findings proven by re-execution")
    findings = api.get(f"/api/runs/{run_id}/findings")
    validated = [f for f in findings if f["state"] == "VALIDATED"]
    print(f"   {len(findings)} finding(s), {len(validated)} VALIDATED")
    for f in validated:
        print(
            f"   - {f['handle']} {f['severity']}/{f['cwe']} at {f['location']} "
            f"(reproduced {f['reproduction_count']}x, root cause: {f['root_cause_location']})"
        )
        print(f"       PoV access: {f['pov_access']} (the working exploit is withheld by default)")

    # --- shield ------------------------------------------------------------------
    banner("8. SHIELD — runtime mitigation, verified to block while benign still passes")
    for shield in detail.get("shields", []):
        print(
            f"   {shield['handle']}: {shield['mechanism']} — "
            f"blocked={shield['verified_blocked']} benign_ok={shield['verified_benign']} "
            f"({shield['benign_pass_count']}/{shield['benign_total']} benign passed)"
        )
    if detail.get("time_to_protection_ms"):
        print(f"   time to protection: {detail['time_to_protection_ms']} ms")

    # --- patch + gauntlet --------------------------------------------------------
    banner("9. PATCH + GAUNTLET — a fix that survives re-attack")
    patches = api.get(f"/api/runs/{run_id}/patches")
    verified = [p for p in patches if p["status"] == "VERIFIED"]
    refuted = [p for p in patches if p["status"] == "REFUTED"]
    print(f"   {len(patches)} patch(es): {len(verified)} VERIFIED, {len(refuted)} REFUTED first")
    for p in verified:
        print(
            f"   - {p['finding_handle']}: +{p['lines_added']}/-{p['lines_removed']} on "
            f"{', '.join(p['files']) or '?'}  (risk {p['risk']})"
        )
    if detail.get("time_to_repair_ms"):
        print(f"   time to repair: {detail['time_to_repair_ms']} ms")

    # --- certificate -------------------------------------------------------------
    banner("10. CERTIFICATE — the signed attestation")
    certs = api.get(f"/api/runs/{run_id}/certificates")
    for c in certs:
        print(f"   {c['serial']}  level {c['assurance_level']}  hash {c['certificate_hash'][:24]}…")
        for limit in c.get("limitations", []):
            print(f"       limitation: {limit}")

    # --- verdict -----------------------------------------------------------------
    banner("RESULT")
    ok = bool(validated) and bool(verified) and bool(certs)
    print(f"   validated finding : {'yes' if validated else 'NO'}")
    print(f"   verified patch    : {'yes' if verified else 'NO'}")
    print(f"   signed certificate: {'yes' if certs else 'NO'}")
    print(
        "\n   PASS — the full loop ran: discovered, proved, shielded, patched, re-attacked, attested."
        if ok
        else "\n   INCOMPLETE — see the stages above; open the run in the console for detail."
    )
    print(f"\n   Open in the console: {console_url}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
