#!/usr/bin/env python3
"""KavachX platform walkthrough — the whole product, end to end, in one narrated pass.

Fourteen acts, in the order the platform actually performs them:

    0  preflight     is this deployment able to do what the next thirteen acts will claim?
    1  clone         a real `git clone` of a real repository into a working copy
    2  authorise     attach it, and record on what authority it may be analysed
    3  run           the pipeline, followed live, phase by phase
    4  index         the code knowledge graph and what it cannot support
    5  contract      SAMHITA — behavioural clauses that survived falsification
    6  fuzz          the discovery channels, with the fuzzing campaign called out
    7  validate      a finding is born only when execution reproduces it
    8  shield        runtime mitigation, verified to block while benign still passes
    9  repair        a proposed fix, refuted, then a fix that holds
   10  gauntlet      the four re-attack stages, per patch iteration
   11  certificate   PRAMAAN — signed, hash-verified, with its limitations
   12  pull request  the publisher's payload, on a real branch, pushed to the origin
   13  proof         what was proved, what was not, and where to look

Nothing here fabricates a value. Every number printed was read back from the API or from git; if a
stage produced nothing, the act says so and the final verdict fails. Exit code 0 means the loop
really ran: cloned, indexed, fuzzed, validated, shielded, repaired, re-attacked, attested and
published.

Usage (standard library only — nothing to install):

    python examples/platform-walkthrough/walkthrough.py
    python examples/platform-walkthrough/walkthrough.py --pause          # presenter mode
    python examples/platform-walkthrough/walkthrough.py --stream full    # every event
    python examples/platform-walkthrough/walkthrough.py --api http://HOST:8000 --frontend http://HOST:3000

See README.md in this folder for the presenter's script and the prerequisites.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

from lib import gitwork, ui  # noqa: E402
from lib.api import Api, ApiError, Unreachable  # noqa: E402
from lib.ui import C  # noqa: E402

TERMINAL_STATUSES = {"COMPLETED", "FAILED", "ABORTED", "AWAITING_APPROVAL"}
DEFAULT_API = os.environ.get("KAVACHX_API", "http://localhost:8000")
DEFAULT_FRONTEND = os.environ.get("KAVACHX_FRONTEND", "http://localhost:3000")
DEFAULT_EMAIL = os.environ.get("KAVACHX_EMAIL", "demo@kavachx.io")
DEFAULT_PASSWORD = os.environ.get("KAVACHX_PASSWORD", "kavachx-demo-2024")

#: The analysis target the walkthrough imports and clones. It is the seeded target that ships with
#: KavachX: four deliberately planted weaknesses, each marked in-source with its CWE, and a benign
#: corpus that SAMHITA observes and that differential replay compares against.
DEFAULT_SOURCE = "examples/vulnerable-demo"
DEFAULT_CLONE_NAME = "walkthrough-clone"


class WalkthroughFailed(RuntimeError):
    """An act cannot continue. The message is shown to the operator as written."""


class Walkthrough:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.api = Api(args.api, timeout=args.http_timeout)
        self.frontend = args.frontend.rstrip("/")

        self.source_path = (REPO_ROOT / args.source).resolve()
        self.clone_name = args.clone_name
        self.clone_path = (REPO_ROOT / "examples" / args.clone_name).resolve()
        self.workdir = (HERE / "out").resolve()
        self.run_out: Path = self.workdir

        self.repo_full_name = args.repository or f"examples/{args.clone_name}"
        self.repository: dict[str, Any] = {}
        self.run: dict[str, Any] = {}
        self.detail: dict[str, Any] = {}
        self.events: list[dict[str, Any]] = []
        self.console_url = ""
        self.certificate: dict[str, Any] = {}
        self.publish: dict[str, Any] = {}
        self.pr_branch = ""

        #: Every claim this walkthrough makes, so the final verdict is computed rather than
        #: asserted. Value is (passed, evidence sentence).
        self.checks: dict[str, tuple[bool, str]] = {}

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def record(self, name: str, passed: bool, evidence: str) -> None:
        self.checks[name] = (passed, evidence)

    def save(self, name: str, content: str | bytes) -> Path:
        self.run_out.mkdir(parents=True, exist_ok=True)
        path = self.run_out / name
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8", newline="\n")
        return path

    def rel(self, path: Path) -> str:
        try:
            return str(path.relative_to(REPO_ROOT)).replace("\\", "/")
        except ValueError:
            return str(path)

    def events_of(self, kind: str) -> list[dict[str, Any]]:
        return [event for event in self.events if event.get("t") == kind]

    # ------------------------------------------------------------------
    # ACT 0 — preflight
    # ------------------------------------------------------------------
    def act_preflight(self) -> None:
        ui.act("0", "preflight", "Can this deployment do what the next thirteen acts will claim?")

        ui.section("Tooling on this machine")
        try:
            version = gitwork.git_version()
        except gitwork.GitError as exc:
            raise WalkthroughFailed(
                f"{exc}\n   The walkthrough clones a repository, so git is required. Install git, "
                "or re-run with --skip-clone --repository examples/vulnerable-demo."
            ) from exc
        ui.kv("git", version)
        ui.kv("python", sys.version.split()[0])
        ui.kv("repository root", self.rel(REPO_ROOT) or ".")

        ui.section("Backend readiness")
        try:
            health = self.api.get("/health")
            ready = self.api.get("/ready")
        except Unreachable as exc:
            raise WalkthroughFailed(
                f"{exc}\n   Start the API with `make backend` (or `make dev` for the API and the "
                "console together), then re-run. Use --api if it listens elsewhere."
            ) from exc

        ui.kv("api", self.api.base)
        ui.kv("version", f"{health.get('version', '?')} ({health.get('environment', '?')})")
        database_ok = bool(ready.get("database"))
        ui.kv(
            "database",
            "reachable" if database_ok else "UNREACHABLE",
            colour="" if database_ok else C.RED,
        )
        ui.kv("dev mode", health.get("dev_mode"))
        if not database_ok:
            raise WalkthroughFailed(
                "The API cannot reach its database. Run `make db && make migrate && make seed`."
            )

        ui.section("Execution and reasoning")
        untrusted_ok = bool(ready.get("sandbox_suitable_for_untrusted_code"))
        ui.kv(
            "sandbox adapter",
            ready.get("sandbox_adapter", "?"),
            colour=C.GREEN if untrusted_ok else C.YELLOW,
        )
        ui.kv("isolates untrusted code", untrusted_ok, colour=C.GREEN if untrusted_ok else C.YELLOW)
        if not untrusted_ok:
            ui.warn(
                "This adapter is a host subprocess, not an isolation boundary. That is the right "
                "choice for this trusted seeded target and the wrong one for anything else — the "
                "console header, the run log and the certificate all say so."
            )
        ui.kv("llm provider", ready.get("llm_provider", "?"))
        ui.kv("llm configured", ready.get("llm_configured"))
        if str(ready.get("llm_provider")) == "mock":
            ui.note(
                "The mock provider has deterministic scripts for all twelve routed tasks, so the "
                "model path is exercised offline with no key. A proposal still crosses the same "
                "schema gate, and the sandbox still decides every verdict."
            )

        ui.section("Publishing authority")
        dry_run = bool(ready.get("publisher_dry_run", True))
        ui.kv("github credential", ready.get("github_configured"))
        ui.kv(
            "publisher mode",
            "DRY RUN" if dry_run else "LIVE",
            colour=C.YELLOW if dry_run else C.GREEN,
        )
        if dry_run:
            ui.note(
                "PUBLISHER_DRY_RUN is on, so act 12 receives the byte-for-byte payload the "
                "publisher would have pushed, and commits it to the clone's own origin. Nothing "
                "reaches GitHub. Set PUBLISHER_DRY_RUN=false with a fine-grained token that has "
                "push access to open a real pull request instead."
            )

        ui.section("Test and fuzzing engines on this host")
        try:
            engines = self.api.get("/api/system/engines")
        except ApiError:
            engines = {}
        inventory = engines.get("engines") or []
        counts = engines.get("counts") or {}
        if inventory:
            ui.kv("available", counts.get("available", 0), colour=C.GREEN)
            ui.kv("unavailable here", counts.get("unavailable", 0), colour=C.YELLOW)
            ui.kv("unimplemented", counts.get("unimplemented", 0), colour=C.GREY)
            ui.blank()
            for engine in [e for e in inventory if e.get("status") == "available"]:
                feedback = " (coverage feedback)" if engine.get("coverage_feedback") else ""
                ui.bullet(
                    f"{engine.get('label', engine.get('id', '?'))} "
                    f"[{engine.get('language', '?')}]{feedback}",
                    colour=C.GREEN,
                )
            for engine in [e for e in inventory if e.get("status") == "unavailable"][:6]:
                ui.bullet(
                    f"{engine.get('label', engine.get('id', '?'))} NOT RUN — "
                    f"{engine.get('reason', 'unavailable')}",
                    colour=C.GREY,
                )
            ui.blank()
            ui.note(str(engines.get("note", "")))
            ui.note(str(engines.get("caveat", "")))
        else:
            ui.note("The engine inventory endpoint returned nothing to report.")

        ui.section("Operator")
        try:
            me = self.api.login(self.args.email, self.args.password)
        except ApiError as exc:
            raise WalkthroughFailed(
                f"Login failed for {self.args.email}: HTTP {exc.status}. "
                "Run `make seed` to create the demo operator, or pass --email/--password."
            ) from exc
        ui.kv("signed in as", f"{me.get('email', self.args.email)} ({me.get('role', '?')})")
        ui.kv("organisation", me.get("organisation_name") or me.get("organisation") or "-")

        self.record(
            "preflight",
            True,
            f"backend {health.get('version', '?')} ready; operator authenticated",
        )

    # ------------------------------------------------------------------
    # ACT 1 — clone
    # ------------------------------------------------------------------
    def act_clone(self) -> None:
        ui.act("1", "clone", "Where does the code come from, and what exactly was fetched?")

        if self.args.skip_clone:
            ui.note(
                f"--skip-clone was passed, so the walkthrough analyses the already-attached "
                f"repository {self.repo_full_name!r} instead of cloning one."
            )
            self.record("clone", True, f"skipped by request; using {self.repo_full_name}")
            return

        ui.section("Building the origin")
        ui.note(
            "A subdirectory of a repository cannot be cloned, so the analysis target is first "
            "imported into a repository of its own. What comes out is a real bare repository — "
            "the thing the next step clones from, and the thing act 12 pushes back to."
        )
        self.workdir.mkdir(parents=True, exist_ok=True)
        origin = gitwork.build_origin(
            source=self.source_path,
            workdir=self.workdir,
            name=self.clone_name,
            branch=self.args.branch,
        )
        ui.kv("imported from", self.rel(self.source_path))
        ui.kv("origin", self.rel(origin))

        ui.section("git clone")
        if self.args.keep_clone and gitwork.is_repo(self.clone_path):
            ui.note(f"--keep-clone: reusing the existing clone at {self.rel(self.clone_path)}")
        else:
            gitwork.clone(origin=origin, destination=self.clone_path)

        head = gitwork.head_sha(self.clone_path)
        files = gitwork.tracked_files(self.clone_path)
        ui.kv("working copy", self.rel(self.clone_path))
        ui.kv("remote origin", gitwork.remote_url(self.clone_path))
        ui.kv("branch", gitwork.current_branch(self.clone_path))
        ui.kv("HEAD", head, colour=C.BOLD)
        ui.kv("tracked files", len(files))
        ui.blank()
        ui.line("in the clone:", colour=C.GREY)
        for name in files[:8]:
            ui.line(f"  {name}", colour=C.GREY, indent=5)
        if len(files) > 8:
            ui.line(f"  ... and {len(files) - 8} more", colour=C.GREY, indent=5)

        ui.blank()
        ui.note(
            "This is a working copy with real git history. KavachX does not run anything from it: "
            "at ingest the tree is copied to pristine/ and hashed there, outside the sandbox, and "
            "only a second copy is ever executed."
        )
        self.record("clone", True, f"cloned {len(files)} tracked files at {head[:12]}")

    # ------------------------------------------------------------------
    # ACT 2 — authorise and attach
    # ------------------------------------------------------------------
    def act_attach(self) -> None:
        ui.act("2", "authorise", "On what authority is KavachX allowed to analyse this code?")

        repositories = self.api.get("/api/repositories")
        existing = next((r for r in repositories if r["full_name"] == self.repo_full_name), None)

        if existing is None:
            project_id = self._project_id(repositories)
            ui.section("Attaching")
            ui.note(
                "A local target is accepted only when its resolved path lies inside this "
                "repository's examples/ tree. That is the entire allowlist for local analysis — "
                "an arbitrary directory on disk is refused even in development."
            )
            try:
                existing = self.api.post(
                    f"/api/projects/{project_id}/repositories",
                    {
                        "full_name": self.repo_full_name,
                        "local_seeded": True,
                        "default_branch": self.args.branch,
                        "authorisation_confirmed": True,
                    },
                )
            except ApiError as exc:
                raise WalkthroughFailed(
                    f"Could not attach {self.repo_full_name!r}: HTTP {exc.status}\n{exc.body}"
                ) from exc
        else:
            ui.section("Already attached")
            ui.note(
                "Attachment is idempotent, and every folder under examples/ is attached "
                "automatically when the API starts — so this repository was already on the project."
            )

        self.repository = existing
        evidence = existing.get("authority_evidence") or {}
        ui.kv("repository", existing["full_name"], colour=C.BOLD)
        ui.kv("provider", existing["provider"])
        ui.kv("default branch", existing.get("default_branch") or "-")
        verified = existing.get("authority_verified_at")
        ui.kv(
            "authority verified",
            verified or "NOT VERIFIED",
            colour=C.GREEN if verified else C.RED,
        )
        ui.kv("method", evidence.get("method", "-"))
        if evidence.get("path"):
            ui.kv("resolved path", evidence["path"])
        if evidence.get("note"):
            ui.blank()
            ui.note(str(evidence["note"]))

        if not verified:
            raise WalkthroughFailed(
                f"{existing['full_name']} has no verified authority, so it cannot be analysed."
            )
        self.record(
            "authority",
            True,
            f"{existing['full_name']} attached as {existing['provider']}, authority verified",
        )

    def _project_id(self, repositories: list[dict[str, Any]]) -> str:
        for repository in repositories:
            if repository.get("provider") == "local_seeded":
                return repository["project_id"]
        projects = self.api.get("/api/projects")
        if not projects:
            raise WalkthroughFailed(
                "No project exists on this tenant. Run `make seed` on the backend first."
            )
        return projects[0]["id"]

    # ------------------------------------------------------------------
    # ACT 3 — the run
    # ------------------------------------------------------------------
    def act_run(self) -> None:
        ui.act("3", "run", "What does the pipeline actually do, phase by phase?")

        try:
            self.run = self.api.post(
                "/api/runs",
                {
                    "repository_id": self.repository["id"],
                    "branch": self.repository.get("default_branch") or self.args.branch,
                    "analysis_profile": self.args.analysis,
                    "execution_profile": self.args.execution,
                    "max_runtime_seconds": self.args.run_timeout,
                    "authorisation_confirmed": True,
                },
            )
        except ApiError as exc:
            raise WalkthroughFailed(
                f"Could not start a run: HTTP {exc.status}\n{exc.body}"
            ) from exc

        run_id = self.run["id"]
        self.console_url = f"{self.frontend}/console/runs/{run_id}"
        self.run_out = self.workdir / self.run["short_code"].lower()

        ui.kv("run", self.run["short_code"], colour=C.BOLD)
        ui.kv("analysis profile", self.args.analysis)
        ui.kv("execution profile", self.args.execution)
        ui.kv("watch it live", self.console_url, colour=C.CYAN)
        ui.blank()
        ui.note(
            "Open that URL now. Everything printed below is the same event stream the console "
            "renders — it is read from the durable replay log, so nothing is missed and nothing "
            "is duplicated."
        )

        ui.section("Pipeline")
        try:
            self.detail = self.api.follow(
                run_id,
                on_event=self._render_event,
                terminal=TERMINAL_STATUSES,
                timeout_s=self.args.run_timeout + 180,
            )
        except TimeoutError as exc:
            raise WalkthroughFailed(str(exc)) from exc

        self.save("events.jsonl", "\n".join(json.dumps(e, sort_keys=True) for e in self.events))

        status = self.detail.get("status", "UNKNOWN")
        ui.blank()
        ui.kv(
            "run status",
            status,
            colour=C.GREEN if status in ("COMPLETED", "AWAITING_APPROVAL") else C.RED,
        )
        ui.kv("mode", self.detail.get("mode"))
        if self.detail.get("static_only_reason"):
            ui.warn(str(self.detail["static_only_reason"]))
        ui.kv("pinned source sha256", str(self.detail.get("pinned_source_sha256", ""))[:32] + "…")
        ui.kv("sandbox executions", self.detail.get("sandbox_executions"))
        ui.kv("network egress", f"{self.detail.get('egress_bytes')} bytes")
        ui.kv("coverage", f"{self.detail.get('coverage_percent')}%")
        ui.kv("model calls", self.detail.get("model_calls"))

        if status not in ("COMPLETED", "AWAITING_APPROVAL"):
            raise WalkthroughFailed(
                f"The run ended as {status}: {self.detail.get('error_message', '')}"
            )
        self.record(
            "run",
            True,
            f"{self.run['short_code']} finished {status} with {self.detail.get('sandbox_executions')} "
            f"sandbox executions and {self.detail.get('egress_bytes')} bytes of egress",
        )

    def _render_event(self, event: dict[str, Any]) -> None:
        """Print one run event. ``--stream`` decides how much detail is shown."""
        self.events.append(event)
        mode = self.args.stream
        kind = event.get("t")

        if kind == "phase":
            status = event.get("status", "")
            glyph, colour = {
                "start": ("..", C.GREY),
                "done": ("OK", C.GREEN),
                "failed": ("XX", C.RED),
                "blocked": ("--", C.YELLOW),
            }.get(status, ("  ", ""))
            if status == "start" and mode == "phases":
                return
            detail = str(event.get("detail", ""))[:110]
            ui.raw(
                f"   {colour}[{glyph}]{C.RESET} {event.get('phase', ''):<20} {C.GREY}{detail}{C.RESET}"
            )
            return

        if mode == "phases":
            return

        if kind == "thought":
            ui.raw(
                f"        {C.MAGENTA}~ {event.get('agent', '')}{C.RESET} "
                f"{C.GREY}{str(event.get('decision', ''))[:100]}{C.RESET}"
            )
            if mode == "full":
                for item in event.get("evidence", [])[:6]:
                    ui.raw(f"            {C.GREY}· {str(item)[:96]}{C.RESET}")
            return

        if kind == "finding":
            ui.raw(
                f"        {C.YELLOW}finding{C.RESET} {event.get('id', '')} "
                f"{event.get('state', '')} {event.get('severity', '')} "
                f"{C.GREY}{str(event.get('title', ''))[:70]}{C.RESET}"
            )
            return

        if kind == "gauntlet":
            colour = {"pass": C.GREEN, "fail": C.RED}.get(str(event.get("verdict")), C.GREY)
            ui.raw(
                f"        {colour}gauntlet{C.RESET} v{event.get('iter', '?')} "
                f"{event.get('stage', '')!s:<20} {colour}{str(event.get('verdict', '')).upper()}"
                f"{C.RESET} {C.GREY}{str(event.get('detail', ''))[:60]}{C.RESET}"
            )
            return

        if kind == "shield":
            ui.raw(
                f"        {C.BLUE}shield{C.RESET} {event.get('shield_id', '')} "
                f"blocked={event.get('verified_blocked')} benign_ok={event.get('verified_benign')}"
            )
            return

        if kind == "certificate":
            ui.raw(
                f"        {C.GREEN}certificate{C.RESET} {event.get('finding', '')} "
                f"level {event.get('level', '')} {str(event.get('certificate_hash', ''))[:16]}"
            )
            return

        if kind == "log":
            if event.get("stream") == "stderr":
                ui.raw(f"        {C.YELLOW}! {str(event.get('line', ''))[:100]}{C.RESET}")
            elif mode == "full":
                ui.raw(f"        {C.GREY}{str(event.get('line', ''))[:100]}{C.RESET}")
            return

        if kind == "status":
            ui.raw(
                f"   {C.BOLD}status{C.RESET} {event.get('status', '')} "
                f"{C.GREY}{str(event.get('detail', ''))[:80]}{C.RESET}"
            )
            return

        if mode == "full" and kind in ("clause", "diff", "artifact", "testspec", "test_result"):
            ui.raw(f"        {C.GREY}{kind}: {json.dumps(event, sort_keys=True)[:110]}{C.RESET}")

    # ------------------------------------------------------------------
    # ACT 4 — the index
    # ------------------------------------------------------------------
    def act_index(self) -> None:
        ui.act("4", "index", "What does KavachX know about this code, and how precisely?")

        payload = self.api.get(f"/api/runs/{self.run['id']}/index")
        if not payload.get("available"):
            ui.warn(str(payload.get("reason", "no index was recorded for this run")))
            self.record("index", False, "no index recorded")
            return

        index = payload["index"]
        health = payload.get("health") or {}
        relationships = index.get("relationships", {})
        symbols = index.get("symbols", {})
        files = index.get("files", {})

        ui.section("Code knowledge graph")
        ui.kv("graph source", index.get("graph_source", "?"), colour=C.BOLD)
        ui.kv("index id", str(index.get("index_id", ""))[:24])
        ui.kv(
            "files",
            f"discovered {files.get('discovered')} · indexed {files.get('indexed')} · skipped {files.get('skipped')}",
        )
        ui.kv("symbols", f"functions {symbols.get('functions')} · classes {symbols.get('classes')}")
        ui.kv(
            "relationships",
            f"{relationships.get('total')} total · calls {relationships.get('calls')} · "
            f"imports {relationships.get('imports')}",
        )
        resolved = relationships.get("resolved", 0)
        total = relationships.get("total", 0) or 1
        ui.kv(
            "resolved references",
            f"{resolved} of {relationships.get('total')} ({round(100 * resolved / total)}%)",
        )

        grade = health.get("grade") or index.get("grade") or "?"
        ui.section("Index validation")
        ui.kv("grade", grade, colour=C.GREEN if str(grade) in ("A", "B") else C.YELLOW)
        for warning in (health.get("warnings") or [])[:5]:
            ui.bullet(str(warning), colour=C.YELLOW)

        bounds = health.get("claim_bounds") or health.get("cannot_support") or []
        if bounds:
            ui.blank()
            ui.line("This index cannot support:", colour=C.BOLD)
            for bound in bounds[:5]:
                ui.bullet(str(bound), colour=C.GREY)
            ui.blank()
            ui.note(
                "That block is not an appendix. It travels into every certificate this run issues, "
                "so a claim can never outrun the index it was built on."
            )

        self.record(
            "index",
            bool(index.get("index_id")),
            f"{index.get('graph_source')} index, grade {grade}, {resolved}/{relationships.get('total')} resolved",
        )

    # ------------------------------------------------------------------
    # ACT 5 — SAMHITA
    # ------------------------------------------------------------------
    def act_contract(self) -> None:
        ui.act(
            "5",
            "contract",
            "What does this code normally do — and which of those claims survived being attacked?",
        )

        clauses = self.api.get(f"/api/runs/{self.run['id']}/clauses")
        if not clauses:
            ui.warn("No SAMHITA clauses were recorded for this run.")
            self.record("contract", False, "no clauses recorded")
            return

        by_status: dict[str, list[dict[str, Any]]] = {}
        for clause in clauses:
            by_status.setdefault(str(clause.get("status", "?")), []).append(clause)

        ui.section("Clause ledger")
        for status, group in sorted(by_status.items(), key=lambda kv: -len(kv[1])):
            colour = C.GREEN if "surv" in status.lower() else C.YELLOW
            ui.kv(status, len(group), colour=colour)

        surviving = [c for c in clauses if "surv" in str(c.get("status", "")).lower()]
        falsified = [c for c in clauses if "fals" in str(c.get("status", "")).lower()]

        if surviving:
            ui.blank()
            ui.line("surviving clauses (a sample):", colour=C.BOLD)
            for clause in surviving[:4]:
                ui.line(
                    f"{clause.get('clause_id', '')}  {clause.get('predicate', '')}",
                    colour=C.GREEN,
                    indent=5,
                )
                ui.line(f"   scope {clause.get('scope', '')}", colour=C.GREY, indent=5)

        if falsified:
            ui.blank()
            ui.line("falsified against held-out traces:", colour=C.BOLD)
            for clause in falsified[:3]:
                ui.line(
                    f"{clause.get('clause_id', '')}  {clause.get('predicate', '')}",
                    colour=C.RED,
                    indent=5,
                )
                ui.line(
                    f"   {str(clause.get('falsification_reason', ''))[:88]}",
                    colour=C.GREY,
                    indent=5,
                )
            ui.blank()
            ui.note(
                "Clauses dying here is the mechanism working, not a defect. A bound derived from a "
                "partial sample is exactly the over-fitted claim held-out falsification exists to "
                "kill. What survives is admissible evidence; what does not is never cited again."
            )

        self.record(
            "contract",
            bool(surviving),
            f"{len(surviving)} clause(s) survived falsification, "
            f"{len(falsified)} were killed by held-out traces",
        )

    # ------------------------------------------------------------------
    # ACT 6 — discovery and the fuzzers
    # ------------------------------------------------------------------
    def act_fuzz(self) -> None:
        ui.act("6", "fuzz", "Did the fuzzer actually run, and what did executing it produce?")

        hypotheses = self.api.get(f"/api/runs/{self.run['id']}/hypotheses")
        channels: dict[str, int] = {}
        for hypothesis in hypotheses:
            channel = str(hypothesis.get("source_channel", "?"))
            channels[channel] = channels.get(channel, 0) + 1

        ui.section("Discovery channels that fired")
        if channels:
            ui.table(
                ["channel", "candidates", ""],
                [
                    (name, count, "<- FUZZER" if name == "fuzzing" else "")
                    for name, count in sorted(channels.items())
                ],
            )
        else:
            ui.warn("No discovery candidates were recorded.")

        ui.section("The mutational campaign")
        fuzz_thoughts = [t for t in self.events_of("thought") if t.get("agent") == "FUZZING"]
        campaign_lines = [
            str(event.get("line", ""))
            for event in self.events_of("log")
            if "campaign" in str(event.get("line", "")).lower()
        ]
        if fuzz_thoughts:
            for thought in fuzz_thoughts[:4]:
                ui.line(str(thought.get("hypothesis", "")), colour=C.BOLD, indent=5)
                for item in thought.get("evidence", [])[:4]:
                    ui.line(f"  {str(item)[:86]}", colour=C.GREY, indent=5)
                ui.blank()
        for line in campaign_lines[:3]:
            ui.bullet(line[:150], colour=C.CYAN)

        # Coverage-guided campaigns are recorded per test execution, which is where the honest
        # score for the model's contribution lives.
        try:
            tests = self.api.get(f"/api/runs/{self.run['id']}/tests")
        except ApiError:
            tests = {}
        campaigns = [e for e in tests.get("executions", []) if e.get("campaign")]
        if campaigns:
            ui.blank()
            ui.line("coverage-guided campaigns:", colour=C.BOLD)
            for execution in campaigns[:3]:
                campaign = execution["campaign"]
                model = campaign.get("model", {})
                ui.line(
                    f"{execution.get('plan_id', '')[:12]}  rounds {campaign.get('rounds_run')} · "
                    f"executions {campaign.get('executions')} · corpus {campaign.get('corpus_size')} · "
                    f"crashes {len(campaign.get('crashes', []))}",
                    colour=C.CYAN,
                    indent=5,
                )
                ui.line(
                    f"   model proposed {model.get('candidates', 0)} inputs, "
                    f"{model.get('candidates_useful', 0)} moved coverage",
                    colour=C.GREY,
                    indent=5,
                )
            ui.blank()
            ui.note(
                "Whether a model-proposed input was useful is decided by measured coverage delta, "
                "not by the model's confidence in it."
            )

        ui.section("Harnesses that were generated")
        plans = tests.get("plans", []) if isinstance(tests, dict) else []
        if plans:
            ui.table(
                ["plan", "strategy", "engine", "oracle", "status", "proposed by"],
                [
                    (
                        str(p.get("plan_id", ""))[:12],
                        p.get("strategy", ""),
                        p.get("engine", ""),
                        p.get("oracle_kind", ""),
                        p.get("status", ""),
                        p.get("proposed_by", ""),
                    )
                    for p in plans[:8]
                ],
            )
            unsupported = [p for p in plans if p.get("status") == "UNSUPPORTED"]
            if unsupported:
                ui.blank()
                for plan in unsupported[:3]:
                    ui.bullet(
                        f"{plan.get('engine', '?')} NOT RUN — {plan.get('engine_reason', '')}",
                        colour=C.GREY,
                    )
        else:
            ui.note("No generated harnesses were recorded for this run.")

        fuzz_count = channels.get("fuzzing", 0)
        self.record(
            "fuzz",
            bool(channels),
            f"{sum(channels.values())} candidates across {len(channels)} channels "
            f"({fuzz_count} from fuzzing)",
        )

    # ------------------------------------------------------------------
    # ACT 7 — validation
    # ------------------------------------------------------------------
    def act_validate(self) -> None:
        ui.act("7", "validate", "Which candidates were proved by execution, and which were killed?")

        findings = self.api.get(f"/api/runs/{self.run['id']}/findings")
        validated = [f for f in findings if f.get("state") == "VALIDATED"]

        ui.kv("findings recorded", len(findings))
        ui.kv("VALIDATED", len(validated), colour=C.GREEN if validated else C.RED)

        for finding in validated:
            ui.blank()
            ui.line(
                f"{finding['handle']}  {finding.get('severity', '')}  {finding.get('cwe', '')}  "
                f"{finding.get('title', '')}",
                colour=C.BOLD,
                indent=3,
            )
            ui.kv("location", finding.get("location"), width=22)
            ui.kv("channel", finding.get("source_channel"), width=22)
            ui.kv(
                "reproduced",
                f"{finding.get('reproduction_count')} independent execution(s)",
                colour=C.GREEN,
                width=22,
            )
            ui.kv("proof kind", finding.get("pov_kind"), width=22)
            ui.kv("violated clause", finding.get("violated_clause_id") or "-", width=22)
            ui.kv("root cause", finding.get("root_cause_location") or "-", width=22)
            ui.kv(
                "root cause verified",
                finding.get("root_cause_verified"),
                colour=C.GREEN if finding.get("root_cause_verified") else C.YELLOW,
                width=22,
            )
            if finding.get("root_cause_summary"):
                ui.blank()
                ui.note(str(finding["root_cause_summary"])[:400])

        rejected = [f for f in findings if f.get("state") != "VALIDATED"]
        if rejected:
            ui.blank()
            ui.line("not validated:", colour=C.BOLD)
            for finding in rejected[:5]:
                ui.bullet(
                    f"{finding['handle']} {finding.get('state', '')} — "
                    f"{str(finding.get('contract_violation') or finding.get('title', ''))[:80]}",
                    colour=C.GREY,
                )
            ui.blank()
            ui.note(
                "A candidate that execution did not reproduce stays a hypothesis. It is not "
                "counted as a finding and it is not quietly dropped."
            )

        ui.blank()
        ui.note(
            "The working exploit is withheld: it is available only to roles holding "
            "finding:read_pov, and it is never written into a certificate or a pull request."
        )

        self.record(
            "validated",
            bool(validated),
            f"{len(validated)} of {len(findings)} findings reproduced by independent execution",
        )

    # ------------------------------------------------------------------
    # ACT 8 — shield
    # ------------------------------------------------------------------
    def act_shield(self) -> None:
        ui.act("8", "shield", "How long until the target is protected, before any repair exists?")

        shields = self.api.get(f"/api/runs/{self.run['id']}/shields")
        if not shields:
            ui.note("No shield was deployed for this run.")
            self.record("shield", False, "no shield deployed")
            return

        for shield in shields:
            deployed = bool(shield.get("deployed_at"))
            ui.line(
                f"{shield.get('handle', '')}  {shield.get('mechanism', '')}  "
                f"{'DEPLOYED' if deployed else 'NOT DEPLOYED'}",
                colour=C.GREEN if deployed else C.YELLOW,
                indent=3,
            )
            ui.kv("rule", str(shield.get("rule", ""))[:78], width=22)
            ui.kv(
                "blocks the exploit",
                shield.get("verified_blocked"),
                colour=C.GREEN if shield.get("verified_blocked") else C.RED,
                width=22,
            )
            ui.kv(
                "benign still passes",
                f"{shield.get('benign_pass_count')}/{shield.get('benign_total')}",
                colour=C.GREEN if shield.get("verified_benign") else C.RED,
                width=22,
            )
            if shield.get("reverted_at"):
                ui.kv("reverted at", shield["reverted_at"], width=22)
            ui.blank()

        ttp = self.detail.get("time_to_protection_ms")
        if ttp:
            ui.kv("TIME TO PROTECTION", f"{ttp} ms ({round(ttp / 1000, 1)}s)", colour=C.BOLD)
        ui.note(
            "A shield that breaks benign behaviour is worse than no shield, so both halves are "
            "verified before it is kept. It is then reverted in the verification workspace, so "
            "the gauntlet tests the patch rather than the mitigation."
        )
        self.record(
            "shield",
            any(s.get("verified_blocked") for s in shields),
            f"{len(shields)} shield(s); time to protection {ttp} ms",
        )

    # ------------------------------------------------------------------
    # ACT 9 — proposing and implementing the fix
    # ------------------------------------------------------------------
    def act_repair(self) -> None:
        ui.act("9", "repair", "What fix was proposed, and what did the code actually become?")

        patches = self.api.get(f"/api/runs/{self.run['id']}/patches")
        if not patches:
            ui.warn("No patch was synthesised for this run.")
            self.record("repair", False, "no patch synthesised")
            return

        ui.section("Patch iterations")
        ui.table(
            ["finding", "iter", "status", "+/-", "files", "risk", "policy"],
            [
                (
                    p.get("finding_handle", ""),
                    p.get("iteration", ""),
                    p.get("status", ""),
                    f"+{p.get('lines_added', 0)}/-{p.get('lines_removed', 0)}",
                    ", ".join(str(f) for f in p.get("files", []))[:34],
                    p.get("risk", ""),
                    "pass" if p.get("policy_passed") else "FAIL",
                )
                for p in patches
            ],
        )

        refuted = [p for p in patches if p.get("status") == "REFUTED"]
        verified = [p for p in patches if p.get("status") == "VERIFIED"]

        for patch in refuted[:2]:
            ui.section(
                f"Refuted — {patch.get('finding_handle')} iteration {patch.get('iteration')}"
            )
            ui.note(str(patch.get("reason", ""))[:400])
            if patch.get("refutation_summary"):
                ui.blank()
                ui.line("why it was withdrawn:", colour=C.RED)
                ui.note(str(patch["refutation_summary"])[:400])
            for constraint in patch.get("constraints", [])[:3]:
                ui.bullet(f"constraint carried forward: {constraint}", colour=C.YELLOW)
            ui.blank()
            ui.note(
                "The refutation is not staged. The mutation engine executed variants and one of "
                "them worked; had none worked, the patch would have passed."
            )

        for patch in verified:
            ui.section(
                f"Verified — {patch.get('finding_handle')} iteration {patch.get('iteration')}"
            )
            ui.note(str(patch.get("reason", ""))[:500])
            if patch.get("expected_effect"):
                ui.blank()
                ui.line("expected effect:", colour=C.BOLD)
                ui.note(str(patch["expected_effect"])[:400])
            ui.blank()
            ui.kv("files changed", ", ".join(str(f) for f in patch.get("files", [])))
            ui.kv("diff hash", str(patch.get("diff_hash", ""))[:24])
            ui.kv(
                "within blast radius",
                patch.get("within_blast_radius"),
                colour=C.GREEN if patch.get("within_blast_radius") else C.RED,
            )

            diff = str(patch.get("unified_diff", ""))
            if diff.strip():
                path = self.save(f"patch-{patch.get('finding_handle', 'V')}.diff", diff)
                ui.blank()
                ui.line("the change itself:", colour=C.BOLD)
                withheld = ui.code(diff, limit=self.args.diff_lines)
                if withheld:
                    ui.line(f"... {withheld} more diff lines", colour=C.GREY, indent=5)
                ui.blank()
                ui.line(f"full diff written to {self.rel(path)}", colour=C.GREY, indent=5)

        ttr = self.detail.get("time_to_repair_ms")
        if ttr:
            ui.blank()
            ui.kv("TIME TO REPAIR", f"{ttr} ms ({round(ttr / 1000, 1)}s)", colour=C.BOLD)

        self.record(
            "repair",
            bool(verified),
            f"{len(patches)} iteration(s): {len(verified)} verified, {len(refuted)} refuted first",
        )

    # ------------------------------------------------------------------
    # ACT 10 — the gauntlet
    # ------------------------------------------------------------------
    def act_gauntlet(self) -> None:
        ui.act("10", "gauntlet", "Did the fix survive being attacked on purpose?")

        rounds = self.api.get(f"/api/runs/{self.run['id']}/gauntlet")
        if not rounds:
            ui.warn("No gauntlet round was recorded for this run.")
            self.record("gauntlet", False, "no gauntlet round recorded")
            return

        for round_ in rounds:
            passed = str(round_.get("verdict", "")).lower() in ("pass", "verified")
            ui.section(
                f"{round_.get('finding_handle', '')} · patch iteration {round_.get('iteration')} "
                f"· {str(round_.get('verdict', '')).upper()}"
            )
            ui.kv(
                "stages passed",
                f"{round_.get('stages_passed')} of {round_.get('stages_total')}",
                colour=C.GREEN if passed else C.RED,
            )
            if round_.get("failing_stage"):
                ui.kv("failed at", round_["failing_stage"], colour=C.RED)
            ui.blank()
            ui.table(
                ["stage", "verdict", "cases", "detail"],
                [
                    (
                        stage.get("stage", ""),
                        str(stage.get("verdict", "")).upper(),
                        stage.get("cases_total", 0),
                        str(stage.get("detail", ""))[:56],
                    )
                    for stage in round_.get("stages", [])
                ],
            )
            for stage in round_.get("stages", []):
                evidence = stage.get("refuting_evidence") or {}
                if evidence:
                    ui.blank()
                    ui.line(f"refuting evidence from {stage.get('stage')}:", colour=C.RED)
                    for key, value in list(evidence.items())[:4]:
                        ui.line(f"  {key}: {str(value)[:74]}", colour=C.GREY, indent=5)

        final = rounds[-1]
        self.record(
            "gauntlet",
            str(final.get("verdict", "")).lower() in ("pass", "verified"),
            f"{len(rounds)} round(s); final verdict {final.get('verdict')} "
            f"({final.get('stages_passed')}/{final.get('stages_total')} stages)",
        )

    # ------------------------------------------------------------------
    # ACT 11 — the certificate
    # ------------------------------------------------------------------
    def act_certificate(self) -> None:
        ui.act("11", "certificate", "What is the proof of work, and does it verify?")

        certificates = self.api.get(f"/api/runs/{self.run['id']}/certificates")
        if not certificates:
            ui.warn("No certificate was issued for this run.")
            self.record("certificate", False, "no certificate issued")
            return

        ui.section("Certificates issued")
        ui.table(
            ["serial", "finding", "level", "hash", "evidence"],
            [
                (
                    c.get("serial", ""),
                    c.get("finding_handle", ""),
                    c.get("assurance_level", ""),
                    str(c.get("certificate_hash", ""))[:20],
                    f"{c.get('evidence_node_count')} nodes / {c.get('evidence_edge_count')} edges",
                )
                for c in certificates
            ],
        )

        publishable = [c for c in certificates if c.get("assurance_level") != "R"]
        chosen = self._certificate_for_publish(publishable)
        self.certificate = chosen or (publishable[0] if publishable else certificates[0])

        for certificate in certificates:
            ui.section(f"{certificate.get('serial')} — Level {certificate.get('assurance_level')}")
            ui.kv("finding", certificate.get("finding_handle") or "-")
            ui.kv("hash", certificate.get("certificate_hash"))
            ui.kv("signature algorithm", certificate.get("signature_algorithm"))

            try:
                verification = self.api.get(f"/api/certificates/{certificate['id']}/verify")
            except ApiError:
                verification = {}
            # The endpoint recomputes both the content hash and the signature from the stored
            # document, so a certificate that was edited after issue fails here rather than
            # being taken at its word.
            valid = bool(verification.get("valid"))
            ui.kv(
                "verified",
                "VALID" if valid else "NOT VALID",
                colour=C.GREEN if valid else C.RED,
            )
            for field in ("hash_matches", "signature_matches"):
                if field in verification:
                    ui.kv(
                        field.replace("_", " "),
                        verification[field],
                        colour=C.GREEN if verification[field] else C.RED,
                    )

            for rationale in (certificate.get("grading_rationale") or [])[:4]:
                ui.bullet(str(rationale), colour=C.GREY)
            limitations = certificate.get("limitations") or []
            if limitations:
                ui.blank()
                ui.line("limitations, stated on the certificate itself:", colour=C.YELLOW)
                for limitation in limitations[:6]:
                    ui.bullet(str(limitation), colour=C.YELLOW)

            try:
                document = self.api.get_raw(f"/api/certificates/{certificate['id']}/download")
                path = self.save(f"certificate-{certificate.get('serial', 'kvx')}.json", document)
                ui.blank()
                ui.line(f"saved to {self.rel(path)}", colour=C.GREY, indent=5)
            except ApiError as exc:
                ui.warn(f"could not download the certificate document: HTTP {exc.status}")

        ui.blank()
        ui.note(
            "A level is assigned by rule, not by preference. A certificate whose claim points at "
            "an evidence node that does not exist is refused outright rather than downgraded, and "
            "Level R means the patch was refuted and will never be published."
        )

        self.record(
            "certificate",
            bool(publishable),
            f"{len(certificates)} certificate(s); {len(publishable)} above Level R",
        )

    def _certificate_for_publish(self, certificates: list[dict[str, Any]]) -> dict[str, Any] | None:
        """The certificate whose finding actually has a gauntlet-verified patch behind it."""
        patches = self.api.get(f"/api/runs/{self.run['id']}/patches")
        verified_finding_ids = {
            str(p.get("finding_id")) for p in patches if p.get("status") == "VERIFIED"
        }
        ranked = sorted(certificates, key=lambda c: str(c.get("assurance_level", "Z")))
        for certificate in ranked:
            if str(certificate.get("finding_id")) in verified_finding_ids:
                return certificate
        return None

    # ------------------------------------------------------------------
    # ACT 12 — the pull request
    # ------------------------------------------------------------------
    def act_pull_request(self) -> None:
        ui.act("12", "pull request", "What reaches the repository, and who decided that it could?")

        if not self.certificate:
            ui.warn("There is no publishable certificate, so there is nothing to publish.")
            self.record("pull_request", False, "no publishable certificate")
            return

        ui.section("The approval gate")
        ui.kv("run status", self.detail.get("status"))
        ui.note(
            "The run parks in AWAITING_APPROVAL by policy. The Publisher — the only component "
            "that ever holds a GitHub credential — is not invoked until a human with "
            "patch:publish approves, and it re-runs the policy gate on the exact payload it is "
            "about to push rather than trusting the earlier decision."
        )

        if self.args.no_publish:
            ui.blank()
            ui.warn("--no-publish was passed; the publish approval was not sent.")
            self.record("pull_request", False, "skipped by request")
            return

        try:
            self.publish = self.api.post(
                f"/api/runs/{self.run['id']}/publish",
                {
                    "certificate_id": self.certificate["id"],
                    "confirm": True,
                    "note": "Approved from the KavachX platform walkthrough.",
                },
            )
        except ApiError as exc:
            ui.fail(f"the publish gate refused: HTTP {exc.status}")
            ui.note(exc.body[:600])
            self.record("pull_request", False, f"publish refused with HTTP {exc.status}")
            return

        ui.section("Publisher result")
        ui.kv("ok", self.publish.get("ok"), colour=C.GREEN if self.publish.get("ok") else C.RED)
        ui.kv("mode", "DRY RUN" if self.publish.get("dry_run") else "LIVE")
        ui.kv("branch", self.publish.get("branch"), colour=C.BOLD)
        ui.kv("payload hash", str(self.publish.get("payload_hash", ""))[:32])
        ui.kv("files", len(self.publish.get("artifacts_written", [])))
        for name in self.publish.get("artifacts_written", []):
            ui.bullet(str(name), colour=C.GREY)

        if not self.publish.get("ok"):
            ui.blank()
            ui.fail(str(self.publish.get("blocked_reason", "publishing was blocked")))
            for violation in self.publish.get("policy_violations", []):
                ui.bullet(json.dumps(violation)[:120], colour=C.RED)
            self.record(
                "pull_request", False, str(self.publish.get("blocked_reason", "blocked"))[:120]
            )
            return

        self.save("publish-result.json", json.dumps(self.publish, indent=2, sort_keys=True))

        if not self.publish.get("dry_run"):
            url = self.publish.get("pull_request_url", "")
            ui.blank()
            ui.ok(f"pull request opened: {url}")
            self.pr_branch = str(self.publish.get("branch", ""))
            self.record("pull_request", bool(url), f"live pull request {url}")
            return

        payload = self.publish.get("dry_run_payload") or {}
        self.save("publish-payload.json", json.dumps(payload, indent=2, sort_keys=True))
        pull_request = payload.get("pull_request") or {}

        ui.section("The pull request it would open")
        ui.kv("title", str(pull_request.get("title", ""))[:78])
        ui.kv("head -> base", f"{pull_request.get('head', '')} -> {pull_request.get('base', '')}")
        body = str(pull_request.get("body", ""))
        pr_path = self.save("pull-request.md", f"# {pull_request.get('title', '')}\n\n{body}\n")
        ui.blank()
        withheld = ui.code(body, limit=self.args.pr_lines)
        if withheld:
            ui.line(f"... {withheld} more lines", colour=C.GREY, indent=5)
        ui.blank()
        ui.line(f"full body written to {self.rel(pr_path)}", colour=C.GREY, indent=5)

        for name, value in (payload.get("guarantees") or {}).items():
            ui.kv(name.replace("_", " "), value, width=38)

        if self.args.skip_clone or not gitwork.is_repo(self.clone_path):
            ui.blank()
            ui.note(
                "There is no local clone to apply this payload to, so it stops here as a payload. "
                "Run without --skip-clone to see it committed and pushed."
            )
            self.record(
                "pull_request",
                True,
                f"publisher produced branch {self.publish.get('branch')} "
                f"({len(payload.get('files', {}))} files) in dry-run mode",
            )
            return

        self._materialise_on_clone(payload)

    def _materialise_on_clone(self, payload: dict[str, Any]) -> None:
        """Commit the publisher's own payload onto the clone and push it to the origin."""
        ui.section("Applying that payload to the clone")
        ui.note(
            "The publisher ran in dry-run, so nothing was sent to GitHub. What follows writes its "
            "payload — the same file contents, on the same branch name — into the clone from act "
            "1 and pushes it to that clone's origin. The branch, the commit and the diff below "
            "are real git objects you can inspect."
        )

        base_branch = gitwork.current_branch(self.clone_path)
        base_sha = gitwork.head_sha(self.clone_path)
        branch = str(payload.get("branch") or self.publish.get("branch") or "kavachx/repair")
        files = payload.get("files") or {}
        if not files:
            ui.fail("the publisher payload contained no files")
            self.record("pull_request", False, "publisher payload contained no files")
            return

        certificate = self.certificate
        message = (
            f"fix({certificate.get('finding_handle', 'security')}): "
            f"repair verified by the KavachX Refutation Gauntlet\n\n"
            f"Certificate {certificate.get('certificate_hash', '')[:16]} "
            f"(Level {certificate.get('assurance_level', '?')}).\n"
            f"Run {self.run.get('short_code', '')}. "
            f"Publisher payload {str(self.publish.get('payload_hash', ''))[:16]}."
        )

        try:
            commit_sha, written = gitwork.commit_payload(
                repo=self.clone_path, branch=branch, files=files, message=message
            )
            gitwork.push(self.clone_path, branch)
        except gitwork.GitError as exc:
            ui.fail(f"could not commit the payload onto the clone: {exc}")
            self.record("pull_request", False, f"git refused the payload: {exc}"[:160])
            return

        pushed = gitwork.branch_exists_on_origin(self.clone_path, branch)
        ui.blank()
        ui.kv("base branch", f"{base_branch} @ {base_sha[:12]}")
        ui.kv("new branch", branch, colour=C.BOLD)
        ui.kv("commit", commit_sha, colour=C.BOLD)
        ui.kv("files committed", len(written))
        ui.kv(
            "pushed to origin",
            "yes" if pushed else "NO",
            colour=C.GREEN if pushed else C.RED,
        )
        ui.blank()
        ui.note(
            f"The publisher recorded base_sha {str(payload.get('base_sha', ''))[:20]}… — for a "
            "local target that is the pinned content hash of the analysed tree, not a git commit, "
            f"so the branch was cut from the clone's own HEAD ({base_sha[:12]})."
        )

        ui.blank()
        ui.line("git show --stat:", colour=C.BOLD)
        ui.code(gitwork.show_stat(self.clone_path, commit_sha), limit=20)

        ui.blank()
        ui.line("git log --oneline --all:", colour=C.BOLD)
        ui.code(gitwork.log_graph(self.clone_path, limit=5), limit=6)

        self.pr_branch = branch
        self.record(
            "pull_request",
            pushed,
            f"branch {branch} committed as {commit_sha[:12]} with {len(written)} files "
            f"and pushed to the origin",
        )

    # ------------------------------------------------------------------
    # ACT 13 — proof of work
    # ------------------------------------------------------------------
    def act_proof(self) -> None:
        ui.act("13", "proof of work", "What was proved, what was not, and where can it be checked?")

        ui.section("Claims, and the evidence behind each")
        ui.table(
            ["claim", "verdict", "evidence"],
            [
                (name, "PASS" if passed else "FAIL", evidence)
                for name, (passed, evidence) in self.checks.items()
            ],
        )

        ui.section("Where to look")
        if self.console_url:
            ui.kv("run in the console", self.console_url, colour=C.CYAN)
        if self.certificate:
            ui.kv("certificate serial", self.certificate.get("serial"))
            ui.kv("certificate hash", self.certificate.get("certificate_hash"))
            ui.kv("assurance level", self.certificate.get("assurance_level"), colour=C.BOLD)
        if self.pr_branch:
            ui.kv("pull request branch", self.pr_branch)
        if not self.args.skip_clone and gitwork.is_repo(self.clone_path):
            ui.kv("clone", self.rel(self.clone_path))
        ui.kv("artifacts", self.rel(self.run_out))

        limitations = (self.certificate or {}).get("limitations") or []
        if limitations:
            ui.section("What this run did NOT prove")
            for limitation in limitations[:8]:
                ui.bullet(str(limitation), colour=C.YELLOW)
            ui.blank()
            ui.note(
                "This list is part of the deliverable. A certificate that names nothing it failed "
                "to establish is a certificate nobody should trust."
            )

        passed = all(ok for ok, _ in self.checks.values())
        ui.verdict(
            passed,
            "the full loop ran: cloned, indexed, contracted, fuzzed, validated, shielded, "
            "repaired, re-attacked, attested and published."
            if passed
            else "some stage did not produce what it claims to. See the FAIL rows above.",
        )

    # ------------------------------------------------------------------
    def run_all(self) -> int:
        ui.banner(
            "KAVACHX — PLATFORM WALKTHROUGH",
            "clone -> index -> contract -> fuzz -> validate -> shield -> repair -> "
            "gauntlet -> certificate -> pull request",
        )
        acts = [
            self.act_preflight,
            self.act_clone,
            self.act_attach,
            self.act_run,
            self.act_index,
            self.act_contract,
            self.act_fuzz,
            self.act_validate,
            self.act_shield,
            self.act_repair,
            self.act_gauntlet,
            self.act_certificate,
            self.act_pull_request,
            self.act_proof,
        ]
        for index, act in enumerate(acts):
            act()
            if index < len(acts) - 1:
                ui.pause(self.args.pause)
        return 0 if all(ok for ok, _ in self.checks.values()) else 1


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="walkthrough",
        description="Drive the whole KavachX platform end to end and narrate every stage.",
    )
    connection = parser.add_argument_group("connection")
    connection.add_argument("--api", default=DEFAULT_API, help=f"API base (default {DEFAULT_API})")
    connection.add_argument(
        "--frontend", default=DEFAULT_FRONTEND, help="console base, used for the run link"
    )
    connection.add_argument("--email", default=DEFAULT_EMAIL)
    connection.add_argument("--password", default=DEFAULT_PASSWORD)
    connection.add_argument("--http-timeout", type=int, default=60, help="per-request timeout")

    target = parser.add_argument_group("target")
    target.add_argument(
        "--source",
        default=DEFAULT_SOURCE,
        help=f"folder to import and clone (default {DEFAULT_SOURCE})",
    )
    target.add_argument(
        "--clone-name",
        default=DEFAULT_CLONE_NAME,
        help=f"clone destination under examples/ (default {DEFAULT_CLONE_NAME})",
    )
    target.add_argument("--branch", default="main", help="branch name in the cloned repository")
    target.add_argument(
        "--skip-clone",
        action="store_true",
        help="analyse an already-attached repository instead of cloning (use with --repository)",
    )
    target.add_argument(
        "--keep-clone", action="store_true", help="reuse an existing clone instead of recreating it"
    )
    target.add_argument(
        "--repository",
        default="",
        help="repository full_name to analyse (default examples/<clone-name>)",
    )

    run = parser.add_argument_group("run")
    run.add_argument("--analysis", default="standard", choices=["quick", "standard", "deep"])
    run.add_argument(
        "--execution", default="dev_local", choices=["dev_local", "gvisor", "firecracker"]
    )
    run.add_argument("--run-timeout", type=int, default=1800, help="seconds to allow the run")
    run.add_argument("--no-publish", action="store_true", help="stop before the publish approval")

    presentation = parser.add_argument_group("presentation")
    presentation.add_argument(
        "--pause", action="store_true", help="wait for Enter between acts (presenter mode)"
    )
    presentation.add_argument(
        "--stream",
        default="normal",
        choices=["phases", "normal", "full"],
        help="how much of the run's event stream to print",
    )
    presentation.add_argument("--diff-lines", type=int, default=60, help="diff lines to print")
    presentation.add_argument("--pr-lines", type=int, default=40, help="PR body lines to print")
    presentation.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    ui.configure(colour=not args.no_color)
    walkthrough = Walkthrough(args)
    try:
        return walkthrough.run_all()
    except WalkthroughFailed as exc:
        ui.blank()
        ui.fail(str(exc))
        ui.blank()
        return 2
    except KeyboardInterrupt:
        ui.blank()
        ui.warn("interrupted")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
