"use client";

import { motion, useReducedMotion } from "framer-motion";
import {
  ArrowRight,
  Boxes,
  CircleDot,
  FileCheck2,
  GitPullRequest,
  Lock,
  Network,
  Scale,
  ScanSearch,
  ShieldCheck,
  Swords,
  Target,
  TerminalSquare,
} from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

import { Chip, cn } from "./ui";

const ease = [0.16, 1, 0.3, 1] as const;

function Reveal({ children, delay = 0 }: { children: ReactNode; delay?: number }) {
  const reduced = useReducedMotion();
  if (reduced) return <>{children}</>;
  return (
    <motion.div
      initial={{ opacity: 0, y: 18 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-80px" }}
      transition={{ duration: 0.7, ease, delay }}
    >
      {children}
    </motion.div>
  );
}

function SectionLabel({ index, children }: { index: string; children: ReactNode }) {
  return (
    <div className="mb-4 flex items-center gap-3">
      <span className="font-mono text-mono-label text-accent">{index}</span>
      <span className="h-px w-8 bg-accent/40" />
      <span className="font-mono text-mono-label uppercase text-foreground-subtle">{children}</span>
    </div>
  );
}

function Section({
  id,
  index,
  label,
  title,
  lede,
  children,
  className,
}: {
  id: string;
  index: string;
  label: string;
  title: string;
  lede?: ReactNode;
  children?: ReactNode;
  className?: string;
}) {
  return (
    <section id={id} className={cn("border-t border-border py-20 sm:py-28", className)}>
      <div className="mx-auto max-w-6xl px-6">
        <Reveal>
          <SectionLabel index={index}>{label}</SectionLabel>
          <h2 className="max-w-3xl text-headline-md text-balance sm:text-headline-lg">{title}</h2>
          {lede && (
            <p className="mt-4 max-w-2xl text-body text-foreground-muted text-balance">{lede}</p>
          )}
        </Reveal>
        {children && <div className="mt-12">{children}</div>}
      </div>
    </section>
  );
}

// ---------------------------------------------------------------------------
const STAGES = [
  { key: "understand", label: "Understand", detail: "World model + SAMHITA contract" },
  { key: "discover", label: "Discover", detail: "Four channels, one queue" },
  { key: "validate", label: "Validate", detail: "Deterministic reproduction" },
  { key: "shield", label: "Shield", detail: "Reversible mitigation" },
  { key: "repair", label: "Repair", detail: "Root cause, not crash site" },
  { key: "attack", label: "Attack Repair", detail: "Refutation Gauntlet" },
  { key: "verify", label: "Verify", detail: "Bounded empirical assurance" },
  { key: "attest", label: "Attest", detail: "PRAMAAN evidence graph" },
  { key: "publish", label: "Publish", detail: "Isolated publisher" },
];

function StageRail() {
  return (
    <div className="grid gap-px overflow-hidden rounded-lg border border-border bg-border sm:grid-cols-3 lg:grid-cols-9">
      {STAGES.map((stage, index) => (
        <div key={stage.key} className="group bg-surface p-4 transition-colors hover:bg-surface-high">
          <div className="mb-2 flex items-center gap-2">
            <span className="font-mono text-mono-label text-accent/70">
              {String(index + 1).padStart(2, "0")}
            </span>
            <CircleDot className="h-3 w-3 text-accent/50 transition-colors group-hover:text-accent" />
          </div>
          <div className="font-mono text-mono-label uppercase text-foreground">{stage.label}</div>
          <div className="mt-1 text-[11px] leading-4 text-foreground-faint">{stage.detail}</div>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
function Hero() {
  return (
    <header className="relative overflow-hidden">
      <div className="grid-bg pointer-events-none absolute inset-0 opacity-70" aria-hidden />
      <div
        className="pointer-events-none absolute left-1/2 top-0 h-[520px] w-[900px] -translate-x-1/2
          bg-[radial-gradient(ellipse_at_center,rgba(0,242,255,0.11),transparent_65%)]"
        aria-hidden
      />

      <nav className="relative mx-auto flex max-w-6xl items-center justify-between px-6 py-6">
        <div className="flex items-center gap-2.5">
          <ShieldCheck className="h-5 w-5 text-accent" />
          <span className="font-mono text-sm font-bold tracking-[0.22em] text-foreground">
            KAVACHX
          </span>
        </div>
        <div className="hidden items-center gap-7 md:flex">
          {[
            ["Approach", "#approach"],
            ["SAMHITA", "#samhita"],
            ["Gauntlet", "#gauntlet"],
            ["PRAMAAN", "#pramaan"],
            ["Architecture", "#architecture"],
            ["Security", "#security"],
          ].map(([label, href]) => (
            <a
              key={href}
              href={href}
              className="font-mono text-mono-label uppercase text-foreground-subtle transition-colors hover:text-accent"
            >
              {label}
            </a>
          ))}
        </div>
        <Link href="/console" className="btn-secondary px-3 py-1.5 text-xs">
          Launch Console
        </Link>
      </nav>

      <div className="relative mx-auto max-w-6xl px-6 pb-24 pt-16 sm:pb-32 sm:pt-24">
        <motion.div
          initial={{ opacity: 0, y: 22 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, ease }}
        >
          <Chip tone="accent" className="mb-7">
            <span className="mr-1 inline-block h-1.5 w-1.5 animate-pulse-ring rounded-full bg-accent" />
            Autonomous cyber-reasoning · proof-carrying repair
          </Chip>

          <h1 className="max-w-4xl text-4xl font-bold leading-[1.06] tracking-[-0.03em] text-balance sm:text-6xl">
            Find it. <span className="text-accent">Shield it.</span> Repair it.{" "}
            <span className="text-verified">Prove it.</span>
          </h1>

          <p className="mt-7 max-w-2xl text-base leading-relaxed text-foreground-muted text-balance sm:text-lg">
            KavachX reconstructs the behavioural contract of software, validates vulnerabilities
            against executable evidence, repairs root causes and produces proof-carrying security
            certificates.
          </p>

          <div className="mt-10 flex flex-wrap items-center gap-3">
            <Link href="/console" className="btn-primary">
              Launch Console <ArrowRight className="h-4 w-4" />
            </Link>
            <a href="#architecture" className="btn-secondary">
              View Architecture
            </a>
          </div>

          <div className="mt-14 flex flex-wrap items-center gap-x-8 gap-y-3 font-mono text-mono-data text-foreground-faint">
            <span>LLM proposes</span>
            <ArrowRight className="h-3.5 w-3.5 text-accent/60" />
            <span>deterministic system validates</span>
            <ArrowRight className="h-3.5 w-3.5 text-accent/60" />
            <span className="text-foreground-muted">state machine decides</span>
          </div>
        </motion.div>
      </div>
    </header>
  );
}

// ---------------------------------------------------------------------------
export function Landing() {
  return (
    <main className="relative">
      <Hero />

      {/* 2 — Problem */}
      <Section
        id="problem"
        index="01"
        label="The problem"
        title="A crash is not a finding, and a diff is not a fix."
        lede="Most automated security tooling stops at a stack trace and a plausible patch. Neither is evidence. The gap between 'the scanner flagged this' and 'this is exploitable, and this change fixes it without breaking anything' is where the actual work lives — and it is exactly the work that gets skipped."
      >
        <div className="grid gap-px overflow-hidden rounded-lg border border-border bg-border md:grid-cols-3">
          {[
            {
              icon: <ScanSearch className="h-4 w-4" />,
              title: "Findings without proof",
              body: "A pattern match is a hypothesis. Without a reproduction it is indistinguishable from a false positive, and every hour spent triaging one is an hour not spent on a real bug.",
            },
            {
              icon: <Swords className="h-4 w-4" />,
              title: "Patches without adversaries",
              body: "A fix that stops the payload in the report is not a fix. It is a fix for that payload. Nobody attacks the patch, so nobody finds the variant that walks straight through it.",
            },
            {
              icon: <Scale className="h-4 w-4" />,
              title: "Confidence without bounds",
              body: "\"Fixed\" with no statement of what was tested, what executed, and what was never reached. An unqualified claim cannot be audited, and cannot be trusted.",
            },
          ].map((item, index) => (
            <Reveal key={item.title} delay={index * 0.08}>
              <div className="h-full bg-surface p-6">
                <div className="mb-3 flex h-8 w-8 items-center justify-center rounded border border-refuted/40 bg-refuted/10 text-refuted">
                  {item.icon}
                </div>
                <h3 className="text-headline-sm">{item.title}</h3>
                <p className="mt-2 text-small leading-relaxed text-foreground-muted">{item.body}</p>
              </div>
            </Reveal>
          ))}
        </div>
      </Section>

      {/* 3 — Approach */}
      <Section
        id="approach"
        index="02"
        label="The KavachX approach"
        title="Reconstruct the contract first. Everything else follows from it."
        lede="KavachX does not begin by looking for bugs. It begins by observing how the software behaves when it is working, turning that into an executable specification, and then asking what would have to be true for that specification to be violated."
      >
        <StageRail />
        <Reveal delay={0.1}>
          <div className="mt-8 grid gap-4 md:grid-cols-2">
            <div className="panel p-6">
              <h3 className="text-headline-sm">What the model is allowed to do</h3>
              <ul className="mt-3 space-y-1.5 text-small text-foreground-muted">
                {[
                  "propose interface hypotheses",
                  "propose SAMHITA clauses",
                  "propose root causes",
                  "propose patches",
                  "propose refutation strategies",
                ].map((item) => (
                  <li key={item} className="flex gap-2">
                    <span className="text-accent">·</span>
                    {item}
                  </li>
                ))}
              </ul>
            </div>
            <div className="panel border-verified/25 p-6">
              <h3 className="text-headline-sm">What only deterministic code decides</h3>
              <ul className="mt-3 space-y-1.5 text-small text-foreground-muted">
                {[
                  "whether a crash occurred",
                  "whether a clause holds",
                  "whether an exploit reproduces",
                  "whether a patch passes",
                  "whether the change stayed in the blast radius",
                  "which assurance level applies",
                  "whether a pull request may be opened",
                ].map((item) => (
                  <li key={item} className="flex gap-2">
                    <span className="text-verified">·</span>
                    {item}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </Reveal>
      </Section>

      {/* 4 — SAMHITA */}
      <Section
        id="samhita"
        index="03"
        label="SAMHITA"
        title="An executable behavioural contract, not a document."
        lede="SAMHITA is reconstructed by running the software's own benign workload, profiling what it actually does, and compiling proposed invariants into executable predicates. Anything that does not survive contact with held-out traces is discarded."
      >
        <div className="grid gap-8 lg:grid-cols-[1.1fr_1fr]">
          <Reveal>
            <div className="panel overflow-hidden">
              <div className="panel-header">
                <span className="panel-title">Clause lifecycle</span>
                <Chip tone="accent">deterministic</Chip>
              </div>
              <ol className="divide-y divide-border">
                {[
                  ["Benign workload", "the target's own corpus, executed in the sandbox"],
                  ["Observation", "tracing harness records every call and value profile"],
                  ["Value profiles", "bounds, ranges, enumerations, counters, containment"],
                  ["LLM clause proposal", "candidate invariants — proposals only"],
                  ["Strict JSON schema", "a schema failure is a model failure, never a pass"],
                  ["Clause compiler", "restricted AST; no calls, no attributes, no subscripts"],
                  ["Held-out falsification", "tested against traces the proposer never saw"],
                  ["Surviving clauses", "only these are ever used as evidence"],
                ].map(([title, detail], index) => (
                  <li key={title} className="flex gap-4 px-5 py-3">
                    <span className="mt-0.5 font-mono text-mono-label text-accent/60">
                      {String(index + 1).padStart(2, "0")}
                    </span>
                    <div className="min-w-0">
                      <div className="font-mono text-mono-data text-foreground">{title}</div>
                      <div className="text-[11px] leading-4 text-foreground-faint">{detail}</div>
                    </div>
                  </li>
                ))}
              </ol>
            </div>
          </Reveal>

          <Reveal delay={0.1}>
            <div className="space-y-4">
              <div className="panel p-5">
                <div className="panel-title mb-3">A surviving clause</div>
                <pre className="term overflow-x-auto text-verified">
{`C060  input_length_bound        SURVIVING
scope      reportsvc/parser.py:parse_header
predicate  arg_lines_raw <= 8
observed   6 benign invocations
held out   held on all 6 applicable traces`}
                </pre>
              </div>
              <div className="panel border-refuted/25 p-5">
                <div className="panel-title mb-3">A clause that did not survive</div>
                <pre className="term overflow-x-auto text-refuted">
{`C027  input_length_bound        FALSIFIED
predicate  arg_len_fmt <= 3
reason     held-out case 008-export-json
           contradicts it (arg_len_fmt=4)
verdict    not admissible as evidence`}
                </pre>
              </div>
              <p className="text-small leading-relaxed text-foreground-muted">
                A clause nobody could contradict is not the same as a clause nobody did
                contradict. Clauses with no applicable held-out observation are rejected too —
                an untested invariant is not evidence.
              </p>
            </div>
          </Reveal>
        </div>
      </Section>

      {/* 5 — Gauntlet */}
      <Section
        id="gauntlet"
        index="04"
        label="Refutation Gauntlet"
        title="The patch has to survive an attack before anyone sees it."
        lede="Four stages, all executing against the patched build. Every one of them is trying to prove the repair wrong. If any stage succeeds, the patch is withdrawn and its refutation becomes a hard constraint on the next attempt."
      >
        <div className="grid gap-px overflow-hidden rounded-lg border border-border bg-border md:grid-cols-2 lg:grid-cols-4">
          {[
            {
              n: "01",
              title: "Exploit Mutation",
              body: "Mutate the validated payload and execute every variant. The classic incomplete fix — block one separator, miss the rest — dies here.",
            },
            {
              n: "02",
              title: "Sibling Hunt",
              body: "Search neighbouring paths for the same weakness class and attempt the analogous exploit. A fix for one instance of a live class is not a fix.",
            },
            {
              n: "03",
              title: "Differential Replay",
              body: "Replay the benign corpus before and after, comparing response hashes. Any divergence is a behavioural regression.",
            },
            {
              n: "04",
              title: "SAMHITA Re-check",
              body: "Re-evaluate every in-scope clause on the patched build. A clause that can no longer even be evaluated is a silent behavioural change, and fails too.",
            },
          ].map((stage, index) => (
            <Reveal key={stage.n} delay={index * 0.07}>
              <div className="h-full bg-surface p-6">
                <div className="mb-3 font-mono text-mono-label text-accent">{stage.n}</div>
                <h3 className="text-headline-sm">{stage.title}</h3>
                <p className="mt-2 text-small leading-relaxed text-foreground-muted">
                  {stage.body}
                </p>
              </div>
            </Reveal>
          ))}
        </div>

        <Reveal delay={0.15}>
          <div className="mt-8 overflow-hidden rounded-lg border-2 border-refuted/50 bg-refuted/[0.04] shadow-glow-refuted">
            <div className="flex items-center gap-3 border-b border-refuted/30 px-5 py-3">
              <Swords className="h-4 w-4 text-refuted" />
              <span className="font-mono text-mono-label uppercase text-refuted">
                Patch refuted — real output from the seeded demo
              </span>
            </div>
            <pre className="overflow-x-auto p-5 term text-foreground-muted">
{`PATCH v1  REFUTED at exploit_mutation

  Refutation   BYPASS FOUND
  Payload      kavachx-probe;echo KAVACHX_POV_MARKER_7F3A
  Signal       injected command executed
  Detail       the patch blocks the reported payload but not this variant

  Patch withdrawn
  Constraint added:  filtering individual characters is insufficient —
                     remove the unsafe construct entirely
  Generating patch iteration 2`}
            </pre>
            <div className="border-t border-refuted/30 px-5 py-3 text-small text-foreground-faint">
              Nothing about that refutation is scripted. The mutation engine executed nineteen
              payloads and one of them worked. Had none worked, the stage would have passed.
            </div>
          </div>
        </Reveal>
      </Section>

      {/* 6 — Shield-first */}
      <Section
        id="shield"
        index="05"
        label="Shield-first architecture"
        title="Protection in seconds. Repair when it is provably correct."
        lede="A verified repair takes root-cause analysis, synthesis and four verification stages. A reversible shield takes seconds. KavachX deploys the shield first and reports the two timings separately, because conflating them hides which one you actually have."
      >
        <div className="grid gap-4 md:grid-cols-2">
          <Reveal>
            <div className="panel border-accent/30 p-6">
              <div className="panel-title mb-2">Time to protection</div>
              <div className="font-mono text-4xl font-bold text-accent">15.6s</div>
              <p className="mt-3 text-small leading-relaxed text-foreground-muted">
                A filter rule derived from the validated proof of vulnerability, verified to block
                the exploit while all twelve benign cases still pass. Reverted by deleting one
                generated file — no target source is modified to install it.
              </p>
            </div>
          </Reveal>
          <Reveal delay={0.08}>
            <div className="panel border-verified/30 p-6">
              <div className="panel-title mb-2">Time to repair</div>
              <div className="font-mono text-4xl font-bold text-verified">24.8s</div>
              <p className="mt-3 text-small leading-relaxed text-foreground-muted">
                The root cause removed, through two patch iterations, with all four refutation
                stages passing on the second. The shield is lifted in the verification workspace
                first, so the gauntlet tests the patch rather than the mitigation.
              </p>
            </div>
          </Reveal>
        </div>
      </Section>

      {/* 7 — PRAMAAN */}
      <Section
        id="pramaan"
        index="06"
        label="PRAMAAN"
        title="Every claim points at evidence. Or the certificate is not issued."
        lede="PRAMAAN is an evidence graph, not a score. Each node carries a content hash; each certificate claim resolves to a node. A certificate with a dangling claim is refused outright, because a document that looks substantiated and is not would be worse than no document."
      >
        <div className="grid gap-8 lg:grid-cols-[1fr_1fr]">
          <Reveal>
            <div className="panel p-5">
              <div className="panel-title mb-4">Evidence graph for one finding</div>
              <pre className="term overflow-x-auto text-foreground-muted">
{`Vulnerability V02
 ├── discovered_by      graph/static, runtime
 ├── violated_clause    SAMHITA C088
 ├── code_evidence      exporter.py:40
 ├── runtime_evidence   observation trace
 ├── exploit_evidence   reproduction record
 │                      (working exploit withheld)
 ├── shielded_by        shield S02
 ├── repaired_by        patch v1 -> patch v2
 └── verified_by        mutation      PASS
                        sibling       PASS
                        replay        PASS
                        contract      PASS`}
              </pre>
            </div>
          </Reveal>
          <Reveal delay={0.1}>
            <div className="space-y-3">
              {[
                ["A", "verified", "Exploit eliminated, contract preserved, no residual candidates, coverage change bounded."],
                ["B", "accent", "As A, but the sibling hunt left code paths it could not prove safe. Recorded as residual risk."],
                ["C", "warn", "Exploit eliminated, but behaviour changed or some clauses could not be verified. The limitation is named."],
                ["R", "refuted", "Patch refuted and withdrawn. Shield remains deployed. Refuting evidence attached. Never publishable."],
              ].map(([level, tone, body]) => (
                <div
                  key={level}
                  className={cn(
                    "flex gap-4 rounded-lg border bg-surface p-4",
                    tone === "verified" && "border-verified/35",
                    tone === "accent" && "border-accent/35",
                    tone === "warn" && "border-warn/35",
                    tone === "refuted" && "border-refuted/35",
                  )}
                >
                  <div
                    className={cn(
                      "flex h-10 w-10 shrink-0 items-center justify-center rounded border-2 font-mono text-lg font-bold",
                      tone === "verified" && "border-verified/60 text-verified",
                      tone === "accent" && "border-accent/60 text-accent",
                      tone === "warn" && "border-warn/60 text-warn",
                      tone === "refuted" && "border-refuted/60 text-refuted",
                    )}
                  >
                    {level}
                  </div>
                  <p className="text-small leading-relaxed text-foreground-muted">{body}</p>
                </div>
              ))}
              <p className="pt-2 text-small leading-relaxed text-foreground-faint">
                These are <span className="text-foreground-muted">bounded empirical assurance</span>,
                never formal proof. Each level states what was executed and observed, and each
                certificate carries the bounds that qualify it.
              </p>
            </div>
          </Reveal>
        </div>
      </Section>

      {/* 8 — Architecture */}
      <Section
        id="architecture"
        index="07"
        label="Architecture"
        title="A thin state machine over deterministic components."
        lede="LangGraph owns orchestration and state; every node checkpoints to PostgreSQL when it returns. Long work — fuzzing, builds, replay, sandbox execution — runs as external processes, so the reasoning loop is never blocked on compute."
      >
        <Reveal>
          <div className="panel overflow-x-auto p-6">
            <pre className="term whitespace-pre text-foreground-muted">
{`  Frontend (Next.js)                          Console: SSE, timeline, findings, diff, gauntlet
        │  Server-Sent Events (structured state transitions — never raw model tokens)
        ▼
  FastAPI  ──────────────────────────────────  JWT · RBAC · tenant_id on every row · audit chain
        │
        ▼
  LangGraph orchestrator  ───────────────────  checkpoint after every node · hard iteration limits
        │
        ├── analysis      tree-sitter index → world model (handles, not content)
        ├── samhita       observe → profile → propose → compile → falsify
        ├── discovery     graph/static · config · fuzzing · runtime  →  one priority queue
        ├── validator     executes in the sandbox · deterministic signals only
        ├── shield        reversible mitigation · verified blocked + benign
        ├── patching      root cause → synthesis → policy gate → blast radius
        ├── gauntlet      mutation · sibling · replay · contract re-check
        ├── pramaan       evidence graph → assurance grade → signed certificate
        │
        ▼
  Sandbox  ──────────────────────────────────  no credentials · no network · non-root · capped
        │                                      (gVisor / Firecracker in production)
        ▼
  Publisher  ────────────────────────────────  THE ONLY COMPONENT WITH GITHUB CREDENTIALS
        │                                      never executes repository code
        ▼
  PostgreSQL  ───────────────────────────────  runs · events · evidence · certificates · audit`}
            </pre>
          </div>
        </Reveal>

        <div className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {[
            { icon: <Network className="h-4 w-4" />, label: "World model", value: "handles, not content" },
            { icon: <Boxes className="h-4 w-4" />, label: "Sandbox", value: "hostile-code boundary" },
            { icon: <FileCheck2 className="h-4 w-4" />, label: "Checkpointing", value: "after every node" },
            { icon: <GitPullRequest className="h-4 w-4" />, label: "Publisher", value: "isolated, credentialed" },
          ].map((item, index) => (
            <Reveal key={item.label} delay={index * 0.06}>
              <div className="panel flex items-center gap-3 p-4">
                <span className="text-accent">{item.icon}</span>
                <div className="min-w-0">
                  <div className="font-mono text-mono-label uppercase text-foreground-subtle">
                    {item.label}
                  </div>
                  <div className="truncate text-small text-foreground">{item.value}</div>
                </div>
              </div>
            </Reveal>
          ))}
        </div>
      </Section>

      {/* 9 — Security model */}
      <Section
        id="security"
        index="08"
        label="Security model"
        title="The sandbox is assumed hostile. The publisher is assumed valuable."
        lede="Analysis executes untrusted code and must never hold a credential. Publishing holds the only credential and must never execute code. Those two facts shape the whole architecture."
      >
        <div className="grid gap-px overflow-hidden rounded-lg border border-border bg-border md:grid-cols-2">
          {[
            {
              icon: <Lock className="h-4 w-4" />,
              title: "The sandbox has zero secrets",
              body: "The environment is built from an allowlist, never inherited. Every execution asserts that no variable matching a credential pattern is present — enforced on each run, not just in tests.",
            },
            {
              icon: <Target className="h-4 w-4" />,
              title: "Authority is verified, not claimed",
              body: "A repository can only be analysed if the GitHub App installation actually includes it, or it is the seeded local target inside this repository's own examples tree. Authority is re-checked at run start.",
            },
            {
              icon: <TerminalSquare className="h-4 w-4" />,
              title: "Repository content is data",
              body: "Source reaches the model inside a labelled JSON payload with an explicit instruction that it is untrusted evidence. Model output is schema-validated before anything acts on it.",
            },
            {
              icon: <ShieldCheck className="h-4 w-4" />,
              title: "Exploits are privileged",
              body: "A working exploit requires finding:read_pov — held by owners, maintainers and security reviewers, not developers or auditors. Every access is written to a hash-chained audit log.",
            },
          ].map((item, index) => (
            <Reveal key={item.title} delay={index * 0.06}>
              <div className="h-full bg-surface p-6">
                <div className="mb-3 flex h-8 w-8 items-center justify-center rounded border border-accent/40 bg-accent/10 text-accent">
                  {item.icon}
                </div>
                <h3 className="text-headline-sm">{item.title}</h3>
                <p className="mt-2 text-small leading-relaxed text-foreground-muted">{item.body}</p>
              </div>
            </Reveal>
          ))}
        </div>

        <Reveal delay={0.12}>
          <div className="mt-6 rounded-lg border border-warn/40 bg-warn/[0.04] p-5">
            <div className="mb-2 flex items-center gap-2 font-mono text-mono-label uppercase text-warn">
              <ShieldCheck className="h-4 w-4" />
              Authorised use only
            </div>
            <p className="text-small leading-relaxed text-foreground-muted">
              KavachX analyses only repositories you have explicit authority over. There is no
              functionality here for scanning arbitrary third-party systems, and none will be
              added. On a development host the execution boundary is a subprocess adapter, which
              is <span className="text-warn">not</span> an isolation boundary — the console says
              so on every run rather than implying otherwise.
            </p>
          </div>
        </Reveal>
      </Section>

      {/* 10 — Live demo */}
      <Section
        id="demo"
        index="09"
        label="Live demo"
        title="Watch it find, shield, repair, fail, and prove."
        lede="A seeded vulnerable service ships with KavachX. Start a run and the console streams real state transitions: contract synthesis, four discovery channels, deterministic validation, a shield, a refuted patch, a second patch, four verification stages, and a signed certificate."
      >
        <Reveal>
          <div className="panel overflow-hidden">
            <div className="panel-header">
              <span className="panel-title">Run 6908 · seeded target · abbreviated</span>
              <Chip tone="verified">real output</Chip>
            </div>
            <pre className="overflow-x-auto p-5 term text-foreground-muted">
{`PHASE samhita     DONE     72 surviving | 20 falsified | 2 iterations | coverage 39.0%
PHASE discovery   DONE     12 candidates from 4 channels
FINDING V02       VALIDATED  CRITICAL  clause=C088  exporter.py:40
                  reproduced 2x independently | injected command executed
SHIELD S02        DEPLOYED   blocked=true  benign 12/12 pass
PATCH v1          REFUTED    exploit_mutation: BYPASS FOUND (';' separator)
PATCH v2          VERIFIED   4/4 refutation stages passed
PRAMAAN V02       LEVEL B    35ff9cd290ae2cda | 21 evidence nodes | signature VALID
PUBLISH V02       branch kavachx/6908-v02-0c286c  (human approval required)`}
            </pre>
          </div>
        </Reveal>
        <Reveal delay={0.1}>
          <div className="mt-8 flex flex-wrap items-center gap-3">
            <Link href="/console/runs/new" className="btn-primary">
              Start a run <ArrowRight className="h-4 w-4" />
            </Link>
            <Link href="/console" className="btn-secondary">
              Open the console
            </Link>
          </div>
        </Reveal>
      </Section>

      {/* 11 — CTA */}
      <section className="relative overflow-hidden border-t border-border py-24 sm:py-32">
        <div className="grid-bg pointer-events-none absolute inset-0 opacity-50" aria-hidden />
        <div
          className="pointer-events-none absolute bottom-0 left-1/2 h-[380px] w-[760px] -translate-x-1/2
            bg-[radial-gradient(ellipse_at_bottom,rgba(0,242,255,0.12),transparent_65%)]"
          aria-hidden
        />
        <div className="relative mx-auto max-w-3xl px-6 text-center">
          <Reveal>
            <h2 className="text-headline-md text-balance sm:text-headline-lg">
              Found it. Shielded it. Repaired it. Attacked the repair.
              <br />
              <span className="text-accent">Proved bounded assurance.</span>
            </h2>
            <p className="mx-auto mt-5 max-w-xl text-body text-foreground-muted text-balance">
              Then it wrote down everything it could not prove, and put that in the pull request
              too.
            </p>
            <div className="mt-9 flex flex-wrap items-center justify-center gap-3">
              <Link href="/console" className="btn-primary">
                Launch Console <ArrowRight className="h-4 w-4" />
              </Link>
              <a href="#architecture" className="btn-secondary">
                View Architecture
              </a>
            </div>
          </Reveal>
        </div>
      </section>

      <footer className="border-t border-border py-8">
        <div className="mx-auto flex max-w-6xl flex-col items-center justify-between gap-4 px-6 sm:flex-row">
          <div className="flex items-center gap-2.5">
            <ShieldCheck className="h-4 w-4 text-accent" />
            <span className="font-mono text-mono-label tracking-[0.2em] text-foreground-subtle">
              KAVACHX
            </span>
          </div>
          <p className="text-center font-mono text-mono-data text-foreground-faint sm:text-right">
            Defensive security research platform · bounded empirical assurance, not formal proof
          </p>
        </div>
      </footer>
    </main>
  );
}
