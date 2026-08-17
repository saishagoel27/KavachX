"""Headless end-to-end demo driver.

Drives the real HTTP API exactly as the browser console does — login, create the run, consume the
SSE stream, then read back findings, patches, gauntlet results and the certificate.

This exists so the full pipeline can be proven from a terminal, and so CI has something to assert
on. It makes no privileged calls and touches no internals: if this script produces a certificate,
the product produced a certificate.

    python scripts/demo_e2e.py                          # against http://localhost:8000
    python scripts/demo_e2e.py --base http://host:8000  # against another instance
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Any

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]

RESET = "\033[0m"
DIM = "\033[2m"
BOLD = "\033[1m"
CYAN = "\033[36m"
GREEN = "\033[32m"
RED = "\033[31m"
AMBER = "\033[33m"


def _prepare_stdout() -> None:
    """Windows consoles default to cp1252, which cannot encode box-drawing characters."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):  # pragma: no cover
        pass


_prepare_stdout()


def line(text: str = "") -> None:
    try:
        print(text, flush=True)
    except UnicodeEncodeError:  # pragma: no cover - last-resort console fallback
        print(text.encode("ascii", "replace").decode("ascii"), flush=True)


def rule(title: str = "") -> None:
    line(f"{DIM}{'-' * 78}{RESET}")
    if title:
        line(f"{BOLD}{title}{RESET}")


class DemoDriver:
    def __init__(self, base: str, email: str, password: str) -> None:
        self.base = base.rstrip("/")
        self.email = email
        self.password = password
        self.token = ""
        self.client = httpx.AsyncClient(timeout=httpx.Timeout(60.0))

    async def close(self) -> None:
        await self.client.aclose()

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    async def _get(self, path: str, **params: Any) -> Any:
        response = await self.client.get(
            f"{self.base}{path}", headers=self._headers(), params=params or None
        )
        response.raise_for_status()
        return response.json()

    async def _post(self, path: str, payload: dict[str, Any] | None = None) -> Any:
        response = await self.client.post(
            f"{self.base}{path}", headers=self._headers(), json=payload
        )
        if response.status_code >= 400:
            line(f"{RED}POST {path} -> {response.status_code}: {response.text[:400]}{RESET}")
        response.raise_for_status()
        return response.json()

    # ------------------------------------------------------------------
    async def wait_for_api(self, attempts: int = 60) -> None:
        for attempt in range(attempts):
            try:
                ready = await self._get("/ready")
                line(
                    f"{GREEN}API ready{RESET} — db={ready['database']} "
                    f"llm={ready['llm_provider']} sandbox={ready['sandbox_adapter']} "
                    f"(untrusted-code-safe: {ready['sandbox_suitable_for_untrusted_code']})"
                )
                if not ready["sandbox_suitable_for_untrusted_code"]:
                    line(
                        f"{AMBER}NOTE: the active sandbox adapter is not an isolation boundary. "
                        f"This is the development adapter.{RESET}"
                    )
                return
            except Exception:
                if attempt == 0:
                    line(f"{DIM}waiting for {self.base} ...{RESET}")
                await asyncio.sleep(1.0)
        raise SystemExit(f"API at {self.base} did not become ready")

    async def login(self) -> None:
        data = await self._post(
            "/api/auth/login", {"email": self.email, "password": self.password}
        )
        self.token = data["access_token"]
        me = await self._get("/api/auth/me")
        line(
            f"{GREEN}authenticated{RESET} as {me['user']['email']} "
            f"role={me['active_role']} permissions={len(me['permissions'])}"
        )

    async def pick_repository(self) -> dict[str, Any]:
        repositories = await self._get("/api/repositories")
        if not repositories:
            raise SystemExit(
                "No repository is attached. Run `python -m scripts.seed` in backend/ first."
            )
        # This walkthrough demonstrates the *full* pipeline, which needs an entrypoint and a benign
        # corpus — so it targets the seeded local repository specifically, not simply whichever row
        # happens to sort first. A public repository attached for a manual experiment would run
        # STATIC-ONLY and none of the validate/patch/gauntlet stages below would have anything to do.
        seeded = [r for r in repositories if r["provider"] == "local_seeded"]
        if not seeded:
            attached = ", ".join(f"{r['full_name']} ({r['provider']})" for r in repositories)
            raise SystemExit(
                "This demo needs the seeded local target, which is not attached.\n"
                f"Attached instead: {attached}\n"
                "Run `python -m scripts.seed` in backend/ to create it."
            )
        repository = seeded[0]
        line(
            f"{GREEN}target{RESET} {repository['full_name']} "
            f"({repository['provider']}) authority_verified="
            f"{bool(repository['authority_verified_at'])}"
        )
        return repository

    async def start_run(self, repository: dict[str, Any], profile: str) -> dict[str, Any]:
        run = await self._post(
            "/api/runs",
            {
                "repository_id": repository["id"],
                # Blank would work too; being explicit shows the resolved branch in the request.
                "branch": repository.get("default_branch") or "",
                "analysis_profile": profile,
                "execution_profile": "dev_local",
                "max_runtime_seconds": 1800,
                "authorisation_confirmed": True,
            },
        )
        line(f"{GREEN}run started{RESET} {run['short_code']} ({run['id']})")
        return run

    # ------------------------------------------------------------------
    async def stream(self, run_id: str) -> dict[str, Any]:
        rule("LIVE EVENT STREAM (Server-Sent Events)")
        counters: dict[str, int] = {}
        started = time.monotonic()

        async with self.client.stream(
            "GET",
            f"{self.base}/api/runs/{run_id}/events",
            headers=self._headers(),
            params={"token": self.token},
            timeout=httpx.Timeout(None, read=None),
        ) as response:
            response.raise_for_status()
            event_name = ""
            async for raw in response.aiter_lines():
                if raw.startswith("event: "):
                    event_name = raw[7:].strip()
                    continue
                if not raw.startswith("data: "):
                    continue
                payload = json.loads(raw[6:])

                if event_name == "end":
                    line(f"{DIM}stream ended — status {payload.get('status')}{RESET}")
                    break
                if event_name in ("hello", "heartbeat"):
                    continue

                event = payload.get("event", {})
                kind = event.get("t", "")
                counters[kind] = counters.get(kind, 0) + 1
                self._render(event, elapsed=time.monotonic() - started)

        return counters

    def _render(self, event: dict[str, Any], *, elapsed: float) -> None:
        kind = event.get("t")
        stamp = f"{DIM}{elapsed:6.1f}s{RESET}"

        if kind == "phase":
            status = event["status"]
            colour = {
                "start": CYAN,
                "done": GREEN,
                "failed": RED,
                "blocked": AMBER,
            }.get(status, "")
            line(
                f"{stamp} {colour}PHASE {event['phase']:<18} {status.upper():<8}{RESET} "
                f"{event.get('detail', '')[:90]}"
            )
        elif kind == "thought":
            line(f"{stamp} {BOLD}{event['agent']}{RESET}  {DIM}({event['confidence']:.0%}){RESET}")
            line(f"        hypothesis  {event['hypothesis'][:110]}")
            for item in event.get("evidence", [])[:5]:
                line(f"        evidence    {DIM}{str(item)[:110]}{RESET}")
            line(f"        decision    {event['decision'][:110]}")
        elif kind == "tool":
            mark = f"{GREEN}ok{RESET}" if event["ok"] else f"{RED}fail{RESET}"
            line(
                f"{stamp} {DIM}tool{RESET} {event['name']:<28} {event['ms']:>6}ms {mark} "
                f"{event.get('detail', '')[:60]}"
            )
        elif kind == "finding":
            colour = {"validated": GREEN, "refuted": DIM, "hypothesis": AMBER}.get(
                event["state"], ""
            )
            line(
                f"{stamp} {colour}FINDING {event['id']:<5} {event['state'].upper():<11}"
                f"{event['severity']:<9}{RESET} clause={event.get('clause') or '-':<6} "
                f"{event.get('title', '')[:60]}"
            )
        elif kind == "clause":
            if event["status"] in ("SURVIVING", "FALSIFIED"):
                colour = GREEN if event["status"] == "SURVIVING" else DIM
                line(
                    f"{stamp} {colour}CLAUSE {event['clause_id']} {event['status']:<10}{RESET} "
                    f"{event['description'][:80]}"
                )
        elif kind == "shield":
            state = "DEPLOYED" if event["deployed"] else "WITHDRAWN"
            colour = GREEN if event["deployed"] else AMBER
            line(
                f"{stamp} {colour}SHIELD {event['shield_id']} {state}{RESET} "
                f"blocked={event['verified_blocked']} benign_ok={event['verified_benign']}"
            )
        elif kind == "diff":
            line(
                f"{stamp} {CYAN}PATCH v{event['iter']}{RESET} {event['finding']} -> "
                f"{event['file']}"
            )
        elif kind == "gauntlet":
            colour = {"pass": GREEN, "fail": RED, "running": DIM}.get(event["verdict"], "")
            if event["verdict"] == "running":
                return
            line(
                f"{stamp} {colour}GAUNTLET {event['stage']:<20} {event['verdict'].upper():<5}"
                f"{RESET} v{event['iter']} {event['detail'][:80]}"
            )
        elif kind == "certificate":
            line(
                f"{stamp} {BOLD}{GREEN}PRAMAAN {event['finding']} -> LEVEL "
                f"{event['level']}{RESET}  {DIM}{event['certificate_hash'][:24]}{RESET}"
            )
        elif kind == "artifact":
            line(f"{stamp} {DIM}artifact {event['kind']:<14} {event.get('name', '')}{RESET}")
        elif kind == "metric":
            line(
                f"{stamp} {DIM}metrics  tokens={event['tokens']} calls={event['model_calls']} "
                f"sandbox={event['sandbox_executions']} coverage={event['coverage']}% "
                f"ram={event['ram_mb']}MB egress={event['egress']}B{RESET}"
            )
        elif kind == "log":
            colour = RED if event["stream"] == "stderr" else DIM
            line(f"{stamp} {colour}{event['line'][:120]}{RESET}")
        elif kind == "status":
            line(f"{stamp} {BOLD}STATUS {event['status']}{RESET} {event.get('detail', '')[:80]}")

    # ------------------------------------------------------------------
    async def report(self, run_id: str) -> int:
        rule("RESULTS")
        run = await self._get(f"/api/runs/{run_id}")
        line(
            f"status={run['status']} phase={run['phase']} "
            f"findings={run['findings_validated']}/{run['findings_total']} "
            f"patched={run['patches_verified']} coverage={run['coverage_percent']:.1f}% "
            f"egress={run['egress_bytes']}B"
        )
        if run["time_to_protection_ms"]:
            line(f"TIME TO PROTECTION  {run['time_to_protection_ms'] / 1000:.1f}s")
        if run["time_to_repair_ms"]:
            line(f"TIME TO REPAIR      {run['time_to_repair_ms'] / 1000:.1f}s")

        rule("FINDINGS")
        for finding in await self._get(f"/api/runs/{run_id}/findings"):
            line(
                f"  {finding['handle']:<4} {finding['severity']:<9}{finding['cwe']:<10}"
                f"{finding['state']:<10} clause={finding['violated_clause_id'] or '-':<6} "
                f"{finding['location']}"
            )
            line(f"       root cause  {finding['root_cause_location']} "
                 f"(verified={finding['root_cause_verified']})")
            line(f"       pov access  {finding['pov_access']}")
            line(f"       status      {finding['status_label']}")

        rule("PATCH ITERATIONS")
        for patch in await self._get(f"/api/runs/{run_id}/patches"):
            colour = GREEN if patch["status"] == "VERIFIED" else (
                RED if patch["status"] in ("REFUTED", "POLICY_REJECTED") else DIM
            )
            line(
                f"  {colour}{patch['finding_handle']} v{patch['iteration']} "
                f"{patch['status']}{RESET} +{patch['lines_added']}/-{patch['lines_removed']} "
                f"{', '.join(patch['files'])}"
            )
            if patch["refutation_summary"]:
                line(f"       {RED}{patch['refutation_summary'][:110]}{RESET}")
            for constraint in patch["constraints"][:2]:
                line(f"       {AMBER}constraint: {str(constraint)[:100]}{RESET}")

        rule("REFUTATION GAUNTLET")
        for gauntlet in await self._get(f"/api/runs/{run_id}/gauntlet"):
            colour = GREEN if gauntlet["verdict"] == "pass" else RED
            line(
                f"  {colour}{gauntlet['finding_handle']} v{gauntlet['iteration']} "
                f"{gauntlet['verdict'].upper()}{RESET} "
                f"({gauntlet['stages_passed']}/{gauntlet['stages_total']} stages)"
            )
            for stage in gauntlet["stages"]:
                mark = f"{GREEN}PASS{RESET}" if stage["verdict"] == "pass" else f"{RED}FAIL{RESET}"
                line(f"       {stage['stage']:<22} {mark}  {stage['detail'][:80]}")

        rule("PRAMAAN CERTIFICATES")
        certificates = await self._get(f"/api/runs/{run_id}/certificates")
        for certificate in certificates:
            line(
                f"  {BOLD}LEVEL {certificate['assurance_level']}{RESET} "
                f"{certificate['finding_handle']} serial={certificate['serial']}"
            )
            line(f"       hash      {certificate['certificate_hash']}")
            line(
                f"       evidence  {certificate['evidence_node_count']} nodes / "
                f"{certificate['evidence_edge_count']} edges"
            )
            verification = await self._get(f"/api/certificates/{certificate['id']}/verify")
            mark = f"{GREEN}VALID{RESET}" if verification["valid"] else f"{RED}INVALID{RESET}"
            line(f"       signature {mark} (hash+HMAC recomputed from the stored document)")
            for limitation in certificate["limitations"][:3]:
                line(f"       {DIM}limitation: {str(limitation)[:100]}{RESET}")

        rule("ARTIFACTS")
        for artifact in await self._get(f"/api/runs/{run_id}/artifacts"):
            line(
                f"  {artifact['kind']:<14} {artifact['name']:<28} "
                f"{artifact['size_bytes']:>7}B  {artifact['content_hash'][:16]}"
            )

        rule("PUBLISH (human approval -> isolated publisher)")
        published = 0
        for certificate in certificates:
            if certificate["assurance_level"] == "R":
                line(f"  {AMBER}{certificate['finding_handle']}: Level R — never published{RESET}")
                continue
            result = await self._post(
                f"/api/runs/{run_id}/publish",
                {
                    "certificate_id": certificate["id"],
                    "confirm": True,
                    "note": "approved by the headless demo driver",
                },
            )
            if result["ok"]:
                published += 1
                mode = "DRY RUN" if result["dry_run"] else "LIVE"
                line(
                    f"  {GREEN}{certificate['finding_handle']}: published ({mode}){RESET} "
                    f"branch={result['branch']}"
                )
                line(f"       files: {', '.join(result['artifacts_written'])}")
                if result["pull_request_url"]:
                    line(f"       PR: {result['pull_request_url']}")
            else:
                line(f"  {RED}{certificate['finding_handle']}: blocked — "
                     f"{result['blocked_reason'][:100]}{RESET}")

        rule("AUDIT CHAIN")
        chain = await self._get("/api/audit/verify")
        mark = f"{GREEN}VALID{RESET}" if chain["valid"] else f"{RED}BROKEN{RESET}"
        line(f"  {mark} — {chain['checked']} records verified, head {chain.get('head_hash', '')[:16]}")

        rule()
        levels = sorted({c["assurance_level"] for c in certificates})
        refuted = [
            p
            for p in await self._get(f"/api/runs/{run_id}/patches")
            if p["status"] == "REFUTED"
        ]
        line(
            f"{BOLD}KavachX found it -> shielded it -> repaired it -> attacked the repair "
            f"-> proved bounded assurance -> produced PRAMAAN -> opened a PR.{RESET}"
        )
        line(
            f"  certificates: {len(certificates)} (levels {', '.join(levels) or 'none'}) | "
            f"patches refuted before success: {len(refuted)} | published: {published}"
        )
        return 0 if certificates else 1


async def main() -> int:
    parser = argparse.ArgumentParser(prog="demo_e2e")
    parser.add_argument("--base", default="http://localhost:8000")
    parser.add_argument("--email", default="demo@kavachx.io")
    parser.add_argument("--password", default="kavachx-demo-2024")
    parser.add_argument(
        "--profile", default="standard", choices=["quick", "standard", "deep"]
    )
    args = parser.parse_args()

    driver = DemoDriver(args.base, args.email, args.password)
    try:
        rule("KAVACHX — END-TO-END DEMO")
        await driver.wait_for_api()
        await driver.login()
        repository = await driver.pick_repository()
        run = await driver.start_run(repository, args.profile)
        await driver.stream(run["id"])
        return await driver.report(run["id"])
    finally:
        await driver.close()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
