"use client";

import Editor, { DiffEditor } from "@monaco-editor/react";
import { AnimatePresence, motion } from "framer-motion";
import {
  Activity,
  AlertOctagon,
  Check,
  ChevronRight,
  CircleSlash,
  Cpu,
  Eye,
  EyeOff,
  FileCode2,
  Loader2,
  Network,
  ShieldCheck,
  Swords,
  Terminal as TerminalIcon,
  X,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { ApiError, endpoints, type Certificate, type Clause, type Finding, type GauntletRun, type Patch, type RunDetail } from "@/lib/api";
import {
  eventsOfType,
  formatBytes,
  GAUNTLET_LABELS,
  GAUNTLET_STAGES,
  PHASE_LABELS,
  PIPELINE_PHASES,
  type Enveloped,
  type PhaseStatus,
} from "@/lib/events";

import {
  Chip,
  cn,
  EmptyState,
  Hash,
  LevelBadge,
  Metric,
  Panel,
  Progress,
  SeverityChip,
  StateChip,
  Terminal,
  VerdictChip,
} from "./ui";

const MONACO_THEME = "kavachx-dark";

function defineMonacoTheme(monaco: any) {
  monaco.editor.defineTheme(MONACO_THEME, {
    base: "vs-dark",
    inherit: true,
    rules: [
      { token: "comment", foreground: "5e6b6c", fontStyle: "italic" },
      { token: "keyword", foreground: "00dbe7" },
      { token: "string", foreground: "3ddc84" },
      { token: "number", foreground: "f5b642" },
    ],
    colors: {
      "editor.background": "#0d0e0f",
      "editor.foreground": "#e3e2e2",
      "editorLineNumber.foreground": "#3a494b",
      "editorLineNumber.activeForeground": "#849495",
      "editor.selectionBackground": "#00f2ff24",
      "editorGutter.background": "#0d0e0f",
      "diffEditor.insertedTextBackground": "#3ddc8420",
      "diffEditor.removedTextBackground": "#ff6b5e20",
      "editorOverviewRuler.border": "#00000000",
    },
  });
}

// ---------------------------------------------------------------------------
// Panel 1 — Pipeline timeline
// ---------------------------------------------------------------------------
const STATUS_STYLE: Record<PhaseStatus, { dot: string; text: string; ring: string }> = {
  pending: { dot: "bg-surface-highest", text: "text-foreground-faint", ring: "border-border" },
  running: { dot: "bg-accent animate-pulse-ring", text: "text-accent", ring: "border-accent/60" },
  completed: { dot: "bg-verified", text: "text-verified", ring: "border-verified/45" },
  failed: { dot: "bg-refuted", text: "text-refuted", ring: "border-refuted/60" },
  blocked: { dot: "bg-warn", text: "text-warn", ring: "border-warn/60" },
};

export function PipelineTimeline({
  phases,
  detail,
  /**
   * Which stages to render. Defaults to the full pipeline; pass the legacy list for a run recorded
   * before the code-intelligence stages existed, so its missing stages are absent rather than
   * shown stuck on "pending".
   */
  order = PIPELINE_PHASES,
}: {
  phases: Record<string, PhaseStatus>;
  detail: Record<string, string>;
  order?: readonly string[];
}) {
  const completed = order.filter((p) => phases[p] === "completed").length;

  return (
    <Panel
      title="Pipeline"
      subtitle={`${completed}/${order.length} stages complete`}
      actions={<Progress value={(completed / order.length) * 100} />}
      bodyClassName="p-3"
    >
      <ol className="space-y-0.5">
        {order.map((phase, index) => {
          const status = phases[phase] ?? "pending";
          const style = STATUS_STYLE[status];
          return (
            <motion.li
              key={phase}
              layout
              transition={{ duration: 0.25 }}
              className={cn(
                "flex items-center gap-3 rounded-md border px-2.5 py-1.5",
                status === "pending" ? "border-transparent" : style.ring,
                status === "running" && "bg-accent/[0.06]",
                status === "failed" && "bg-refuted/[0.06]",
                status === "blocked" && "bg-warn/[0.05]",
              )}
            >
              <span className="w-5 shrink-0 font-mono text-[10px] text-foreground-faint">
                {String(index + 1).padStart(2, "0")}
              </span>
              <span className={cn("h-2 w-2 shrink-0 rounded-full", style.dot)} />
              <span
                className={cn(
                  "min-w-0 flex-1 truncate font-mono text-mono-data",
                  status === "pending" ? "text-foreground-faint" : "text-foreground",
                )}
              >
                {PHASE_LABELS[phase]}
              </span>
              {detail[phase] && (
                <span
                  className="hidden max-w-[46%] truncate text-[11px] text-foreground-faint lg:block"
                  title={detail[phase]}
                >
                  {detail[phase]}
                </span>
              )}
              <span className={cn("shrink-0 font-mono text-[10px] uppercase", style.text)}>
                {status === "running" ? (
                  <Loader2 className="h-3 w-3 animate-spin" />
                ) : status === "completed" ? (
                  <Check className="h-3 w-3" />
                ) : status === "failed" ? (
                  <X className="h-3 w-3" />
                ) : status === "blocked" ? (
                  <CircleSlash className="h-3 w-3" />
                ) : (
                  "—"
                )}
              </span>
            </motion.li>
          );
        })}
      </ol>
    </Panel>
  );
}

// ---------------------------------------------------------------------------
// Panel 2 — Structured reasoning trace
// ---------------------------------------------------------------------------
export function ReasoningTrace({ events }: { events: Enveloped[] }) {
  const thoughts = eventsOfType(events, "thought");
  const tools = eventsOfType(events, "tool");
  const [tab, setTab] = useState<"reasoning" | "tools">("reasoning");

  return (
    <Panel
      title="Reasoning trace"
      subtitle="hypothesis → evidence → decision"
      actions={
        <div className="flex gap-1">
          {(["reasoning", "tools"] as const).map((id) => (
            <button
              key={id}
              onClick={() => setTab(id)}
              className={cn(
                "rounded px-2 py-0.5 font-mono text-mono-label uppercase transition-colors",
                tab === id ? "bg-accent/15 text-accent" : "text-foreground-subtle hover:text-foreground",
              )}
            >
              {id} {id === "reasoning" ? thoughts.length : tools.length}
            </button>
          ))}
        </div>
      }
      bodyClassName="p-0"
    >
      <div className="max-h-[30rem] overflow-y-auto">
        {tab === "reasoning" ? (
          thoughts.length === 0 ? (
            <EmptyState
              icon={<Activity className="h-5 w-5" />}
              title="No reasoning yet"
              detail="Structured summaries appear as each subsystem reaches a decision."
            />
          ) : (
            <div className="divide-y divide-border">
              <AnimatePresence initial={false}>
                {[...thoughts].reverse().map((thought) => (
                  <motion.article
                    key={thought.seq}
                    initial={{ opacity: 0, y: -6 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.25 }}
                    className="px-4 py-3"
                  >
                    <div className="mb-2 flex items-center gap-2">
                      <span className="font-mono text-mono-label uppercase text-accent">
                        {thought.agent}
                      </span>
                      <span className="ml-auto font-mono text-[10px] text-foreground-faint">
                        {(thought.confidence * 100).toFixed(0)}% confidence
                      </span>
                    </div>
                    <dl className="space-y-1.5">
                      <div>
                        <dt className="font-mono text-[10px] uppercase text-foreground-faint">
                          Hypothesis
                        </dt>
                        <dd className="text-small text-foreground">{thought.hypothesis}</dd>
                      </div>
                      {thought.evidence.length > 0 && (
                        <div>
                          <dt className="font-mono text-[10px] uppercase text-foreground-faint">
                            Evidence
                          </dt>
                          <dd className="space-y-0.5">
                            {thought.evidence.map((item, index) => (
                              <div key={index} className="term text-foreground-muted">
                                {item}
                              </div>
                            ))}
                          </dd>
                        </div>
                      )}
                      <div>
                        <dt className="font-mono text-[10px] uppercase text-foreground-faint">
                          Decision
                        </dt>
                        <dd className="text-small text-foreground-muted">{thought.decision}</dd>
                      </div>
                    </dl>
                  </motion.article>
                ))}
              </AnimatePresence>
            </div>
          )
        ) : tools.length === 0 ? (
          <EmptyState icon={<TerminalIcon className="h-5 w-5" />} title="No tool calls yet" />
        ) : (
          <table className="w-full text-left">
            <thead className="sticky top-0 bg-surface">
              <tr className="border-b border-border">
                {["Tool", "Target", "Time", "Result"].map((head) => (
                  <th key={head} className="px-4 py-2 font-mono text-mono-label uppercase text-foreground-subtle">
                    {head}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {[...tools].reverse().map((tool) => (
                <tr key={tool.seq}>
                  <td className="px-4 py-1.5 term text-foreground">{tool.name}</td>
                  <td className="max-w-[16rem] truncate px-4 py-1.5 term text-foreground-muted" title={tool.target}>
                    {tool.target}
                  </td>
                  <td className="px-4 py-1.5 term tabular-nums text-foreground-faint">
                    {tool.ms}ms
                  </td>
                  <td className="px-4 py-1.5">
                    <Chip tone={tool.ok ? "verified" : "refuted"}>{tool.ok ? "OK" : "FAIL"}</Chip>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <div className="border-t border-border px-4 py-2 text-[11px] leading-4 text-foreground-faint">
        Structured summaries and evidence references only. Hidden model deliberation is never
        displayed, and never stored.
      </div>
    </Panel>
  );
}

// ---------------------------------------------------------------------------
// Panel 3 — Findings
// ---------------------------------------------------------------------------
export function FindingsTable({
  findings,
  clauses,
  onSelect,
  selected,
}: {
  findings: Finding[];
  clauses: Clause[];
  onSelect: (handle: string) => void;
  selected: string | null;
}) {
  const clauseById = useMemo(
    () => new Map(clauses.map((clause) => [clause.clause_id, clause])),
    [clauses],
  );

  return (
    <Panel
      title="Findings"
      subtitle={`${findings.filter((f) => f.state === "VALIDATED").length} validated / ${findings.length}`}
      bodyClassName="p-0"
    >
      {findings.length === 0 ? (
        <EmptyState
          icon={<AlertOctagon className="h-5 w-5" />}
          title="No findings yet"
          detail="A hypothesis becomes a finding only when the validator reproduces it in the sandbox."
        />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="border-b border-border">
                {[
                  "ID",
                  "State",
                  "Severity",
                  "SAMHITA clause",
                  "Reachability",
                  "Evidence",
                  "Root cause",
                  "Status",
                ].map((head) => (
                  <th
                    key={head}
                    className="whitespace-nowrap px-3 py-2 font-mono text-mono-label uppercase text-foreground-subtle"
                  >
                    {head}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {findings.map((finding) => {
                const clause = clauseById.get(finding.violated_clause_id);
                return (
                  <tr
                    key={finding.id}
                    onClick={() => onSelect(finding.handle)}
                    className={cn(
                      "cursor-pointer transition-colors hover:bg-surface-high",
                      selected === finding.handle && "bg-accent/[0.07]",
                    )}
                  >
                    <td className="px-3 py-2 font-mono text-sm font-bold text-accent">
                      {finding.handle}
                    </td>
                    <td className="px-3 py-2">
                      <StateChip state={finding.state} />
                    </td>
                    <td className="px-3 py-2">
                      <SeverityChip severity={finding.severity} />
                      <div className="mt-0.5 font-mono text-[10px] text-foreground-faint">
                        {finding.cwe || "—"}
                      </div>
                    </td>
                    <td className="max-w-[15rem] px-3 py-2">
                      {clause ? (
                        <div title={`${clause.description} — ${clause.predicate}`}>
                          <div className="font-mono text-mono-data text-accent">
                            {clause.clause_id}
                          </div>
                          <div className="truncate term text-foreground-faint">
                            {clause.predicate}
                          </div>
                        </div>
                      ) : (
                        <span className="text-foreground-faint">—</span>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      <Chip tone={finding.reachable ? "warn" : "muted"}>
                        {finding.reachable ? "REACHABLE" : "UNREACHED"}
                      </Chip>
                      <div className="mt-0.5 font-mono text-[10px] text-foreground-faint">
                        {(finding.reachability_score * 100).toFixed(0)}%
                      </div>
                    </td>
                    <td className="px-3 py-2 term text-foreground-muted">
                      <div>{finding.reproduction_count}× reproduced</div>
                      <div className="text-foreground-faint">
                        {finding.sanitizer_signal || `exit ${finding.exit_code ?? "?"}`}
                      </div>
                    </td>
                    <td className="max-w-[14rem] px-3 py-2">
                      <div
                        className="truncate term text-foreground-muted"
                        title={finding.root_cause_location}
                      >
                        {finding.root_cause_location || "—"}
                      </div>
                      {finding.root_cause_location && (
                        <Chip tone={finding.root_cause_verified ? "verified" : "warn"}>
                          {finding.root_cause_verified ? "ON PATH" : "UNVERIFIED"}
                        </Chip>
                      )}
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 text-small text-foreground-muted">
                      {finding.status_label}
                      <ChevronRight className="ml-1 inline h-3 w-3 text-foreground-faint" />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

// ---------------------------------------------------------------------------
// Finding detail (investigation view)
// ---------------------------------------------------------------------------
export function FindingDetail({
  runId,
  finding,
  clause,
  canReadPov,
  onClose,
}: {
  runId: string;
  finding: Finding;
  clause: Clause | undefined;
  canReadPov: boolean;
  onClose: () => void;
}) {
  const [pov, setPov] = useState<string | null>(null);
  const [povError, setPovError] = useState("");
  const [loadingPov, setLoadingPov] = useState(false);

  const revealPov = async () => {
    setLoadingPov(true);
    setPovError("");
    try {
      const detailed = await endpoints.finding(runId, finding.handle, true);
      setPov(detailed.pov_payload ?? "");
    } catch (exc) {
      setPovError(exc instanceof ApiError ? `${exc.code}: ${exc.message}` : "Request failed.");
    } finally {
      setLoadingPov(false);
    }
  };

  const blast = finding.blast_radius_json ?? {};

  return (
    <Panel
      title={`${finding.handle} — investigation`}
      subtitle={finding.location}
      actions={
        <button onClick={onClose} className="btn-ghost px-2 py-1 text-xs" aria-label="Close">
          <X className="h-3.5 w-3.5" />
        </button>
      }
    >
      <div className="grid gap-5 lg:grid-cols-2">
        <div className="space-y-4">
          <div>
            <div className="panel-title mb-2">Finding</div>
            <p className="text-small text-foreground">{finding.title}</p>
            <div className="mt-2 flex flex-wrap gap-1.5">
              <StateChip state={finding.state} />
              <SeverityChip severity={finding.severity} />
              {finding.cwe && <Chip tone="muted">{finding.cwe}</Chip>}
              <Chip tone="muted">{finding.source_channel}</Chip>
            </div>
          </div>

          <div>
            <div className="panel-title mb-2">Root cause</div>
            <div className="term text-accent">{finding.root_cause_location || "—"}</div>
            <p className="mt-1.5 text-small text-foreground-muted">
              {finding.root_cause_summary || "Not recorded."}
            </p>
            {finding.root_cause_chain?.length > 0 && (
              <ol className="mt-2 space-y-0.5 border-l border-border pl-3">
                {finding.root_cause_chain.map((step, index) => (
                  <li key={index} className="term text-foreground-faint">
                    {step}
                  </li>
                ))}
              </ol>
            )}
          </div>

          {clause && (
            <div>
              <div className="panel-title mb-2">Violated SAMHITA clause</div>
              <div className="rounded-md border border-accent/30 bg-accent/[0.05] p-3">
                <div className="font-mono text-mono-data text-accent">{clause.clause_id}</div>
                <div className="mt-1 text-small text-foreground">{clause.description}</div>
                <pre className="mt-2 term text-verified">{clause.predicate}</pre>
                <div className="mt-2 font-mono text-[10px] text-foreground-faint">
                  scope {clause.scope} · observed {clause.observation_count}× · survived{" "}
                  {clause.holdout_pass_count} held-out traces
                </div>
              </div>
            </div>
          )}
        </div>

        <div className="space-y-4">
          <div>
            <div className="panel-title mb-2">Deterministic reproduction record</div>
            <div className="space-y-1.5 rounded-md border border-border bg-surface-lowest p-3">
              {[
                ["reproduced", `${finding.reproduction_count}× in independent processes`],
                ["exit code", String(finding.exit_code ?? "—")],
                ["signal", finding.sanitizer_signal || "—"],
                ["contract", finding.contract_violation || "—"],
                ["input hash", finding.input_hash],
                ["output hash", finding.output_hash],
                ["trace hash", finding.trace_hash],
                ["coverage", `${finding.coverage_percent.toFixed(1)}%`],
              ].map(([label, value]) => (
                <div key={label} className="flex items-baseline justify-between gap-3">
                  <span className="font-mono text-[10px] uppercase text-foreground-faint">
                    {label}
                  </span>
                  <span className="min-w-0 truncate term text-foreground-muted" title={value}>
                    {value.length > 40 ? `${value.slice(0, 20)}…` : value || "—"}
                  </span>
                </div>
              ))}
            </div>
          </div>

          <div>
            <div className="panel-title mb-2">Blast radius</div>
            <div className="rounded-md border border-border bg-surface-lowest p-3">
              <div className="space-y-0.5">
                {[
                  `ROOT CAUSE  ${blast.root_cause_location ?? "—"}`,
                  `AFFECTED FUNCTION  ${blast.affected_function ?? "—"}`,
                  `${(blast.direct_callers ?? []).length} DIRECT CALLERS`,
                  `${(blast.transitive_callers ?? []).length} TRANSITIVE CALLERS`,
                  `${(blast.modules ?? []).length} MODULES`,
                  `${(blast.clause_ids ?? []).length} SAMHITA CLAUSES`,
                  `REGRESSION SCOPE  ${blast.regression_scope ?? "—"}`,
                ].map((line, index) => (
                  <div key={index} className="term text-foreground-muted">
                    {index > 0 && <span className="mr-1 text-accent/50">↓</span>}
                    {line}
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div>
            <div className="panel-title mb-2">Working exploit</div>
            {pov !== null ? (
              <div className="rounded-md border border-refuted/40 bg-refuted/[0.05] p-3">
                <div className="mb-2 flex items-center gap-2">
                  <Chip tone="refuted">POV REVEALED · AUDITED</Chip>
                </div>
                <pre className="term overflow-x-auto whitespace-pre-wrap break-all text-refuted">
                  {pov || "— empty —"}
                </pre>
              </div>
            ) : (
              <div className="rounded-md border border-border bg-surface-lowest p-3">
                <div className="mb-2 flex items-center gap-2">
                  <EyeOff className="h-3.5 w-3.5 text-foreground-faint" />
                  <span className="text-small text-foreground-muted">
                    Withheld — hash <Hash value={finding.pov_hash} length={12} />
                  </span>
                </div>
                {canReadPov ? (
                  <button
                    onClick={() => void revealPov()}
                    disabled={loadingPov}
                    className="btn-danger w-full text-xs"
                  >
                    {loadingPov ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Eye className="h-3.5 w-3.5" />}
                    Reveal working exploit
                  </button>
                ) : (
                  <p className="text-[11px] leading-4 text-foreground-faint">
                    Your role does not hold <code className="font-mono">finding:read_pov</code>.
                    Working exploits are restricted to owners, maintainers and security reviewers.
                  </p>
                )}
                {povError && <p className="mt-2 term text-refuted">{povError}</p>}
                <p className="mt-2 text-[11px] leading-4 text-foreground-faint">
                  Every access — granted or denied — is written to the hash-chained audit log.
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </Panel>
  );
}

// ---------------------------------------------------------------------------
// Panel 4 — Diff viewer
// ---------------------------------------------------------------------------
export function DiffViewer({
  patches,
  gauntlets,
  clauses,
  findings,
}: {
  patches: Patch[];
  gauntlets: GauntletRun[];
  clauses: Clause[];
  findings: Finding[];
}) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [view, setView] = useState<"unified" | "split">("unified");

  const ordered = useMemo(
    () =>
      [...patches].sort(
        (a, b) =>
          a.finding_handle.localeCompare(b.finding_handle) || a.iteration - b.iteration,
      ),
    [patches],
  );
  const selected = ordered.find((p) => p.id === selectedId) ?? ordered[ordered.length - 1];

  const gauntlet = selected
    ? gauntlets.find(
        (g) => g.finding_handle === selected.finding_handle && g.iteration === selected.iteration,
      )
    : undefined;
  const finding = selected
    ? findings.find((f) => f.handle === selected.finding_handle)
    : undefined;
  const clause = finding
    ? clauses.find((c) => c.clause_id === finding.violated_clause_id)
    : undefined;

  const refuted = selected?.status === "REFUTED" || selected?.status === "POLICY_REJECTED";
  const verified = selected?.status === "VERIFIED" || selected?.status === "PUBLISHED";

  const { before, after } = useMemo(() => {
    if (!selected) return { before: "", after: "" };
    const beforeLines: string[] = [];
    const afterLines: string[] = [];
    for (const line of selected.unified_diff.split("\n")) {
      if (line.startsWith("+++") || line.startsWith("---") || line.startsWith("@@")) continue;
      if (line.startsWith("-")) beforeLines.push(line.slice(1));
      else if (line.startsWith("+")) afterLines.push(line.slice(1));
      else if (line.startsWith(" ")) {
        beforeLines.push(line.slice(1));
        afterLines.push(line.slice(1));
      }
    }
    return { before: beforeLines.join("\n"), after: afterLines.join("\n") };
  }, [selected]);

  return (
    <Panel
      title="Patch / diff"
      subtitle={selected ? `${selected.finding_handle} iteration ${selected.iteration}` : undefined}
      actions={
        <div className="flex items-center gap-2">
          {(["unified", "split"] as const).map((id) => (
            <button
              key={id}
              onClick={() => setView(id)}
              className={cn(
                "rounded px-2 py-0.5 font-mono text-mono-label uppercase transition-colors",
                view === id ? "bg-accent/15 text-accent" : "text-foreground-subtle hover:text-foreground",
              )}
            >
              {id}
            </button>
          ))}
        </div>
      }
      bodyClassName="p-0"
    >
      {ordered.length === 0 ? (
        <EmptyState
          icon={<FileCode2 className="h-5 w-5" />}
          title="No patches yet"
          detail="A patch is synthesised only after the root cause has been located and verified on the executed path."
        />
      ) : (
        <div className="flex flex-col">
          <div className="flex gap-1 overflow-x-auto border-b border-border px-3 py-2 no-scrollbar">
            {ordered.map((patch) => {
              const isRefuted = patch.status === "REFUTED" || patch.status === "POLICY_REJECTED";
              const isVerified = patch.status === "VERIFIED" || patch.status === "PUBLISHED";
              return (
                <button
                  key={patch.id}
                  onClick={() => setSelectedId(patch.id)}
                  className={cn(
                    "shrink-0 rounded border px-2.5 py-1 font-mono text-mono-label uppercase transition-colors",
                    selected?.id === patch.id
                      ? isRefuted
                        ? "border-refuted bg-refuted/15 text-refuted"
                        : isVerified
                          ? "border-verified bg-verified/15 text-verified"
                          : "border-accent bg-accent/15 text-accent"
                      : "border-border text-foreground-subtle hover:text-foreground",
                  )}
                >
                  {patch.finding_handle} v{patch.iteration}
                </button>
              );
            })}
          </div>

          {selected && (
            <>
              {/* A failed gauntlet is the most important thing on this screen, so it is
                  unmissable rather than a subtle status pill. */}
              <div
                className={cn(
                  "border-b px-4 py-3",
                  refuted && "border-refuted/40 bg-refuted/[0.07]",
                  verified && "border-verified/40 bg-verified/[0.06]",
                  !refuted && !verified && "border-border",
                )}
              >
                <div className="flex flex-wrap items-center gap-3">
                  <span
                    className={cn(
                      "rounded border-2 px-3 py-1 font-mono text-sm font-bold uppercase tracking-wide",
                      refuted && "border-refuted text-refuted shadow-glow-refuted",
                      verified && "border-verified text-verified shadow-glow-verified",
                      !refuted && !verified && "border-border-strong text-foreground-subtle",
                    )}
                  >
                    PATCH v{selected.iteration} — {selected.status}
                  </span>
                  <span className="term text-foreground-muted">
                    +{selected.lines_added} / −{selected.lines_removed}
                  </span>
                  <Chip tone={selected.policy_passed ? "verified" : "refuted"}>
                    POLICY {selected.policy_passed ? "PASS" : "REJECTED"}
                  </Chip>
                  <Chip tone={selected.within_blast_radius ? "verified" : "refuted"}>
                    {selected.within_blast_radius ? "IN BLAST RADIUS" : "OUT OF RADIUS"}
                  </Chip>
                  <Chip tone="muted">RISK {selected.risk.toUpperCase()}</Chip>
                  <span className="ml-auto term text-foreground-faint">
                    <Hash value={selected.diff_hash} length={12} />
                  </span>
                </div>

                {refuted && selected.refutation_summary && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: "auto" }}
                    className="mt-3 overflow-hidden rounded border border-refuted/50 bg-surface-lowest"
                  >
                    <div className="border-b border-refuted/30 px-3 py-1.5 font-mono text-mono-label uppercase text-refuted">
                      ╔ PATCH REFUTED
                    </div>
                    <div className="space-y-1 px-3 py-2">
                      <div className="term text-foreground">
                        <span className="text-foreground-faint">Refutation: </span>
                        {gauntlet?.failing_stage
                          ? GAUNTLET_LABELS[gauntlet.failing_stage] ?? gauntlet.failing_stage
                          : selected.status}
                      </div>
                      <div className="term text-refuted">{selected.refutation_summary}</div>
                      <div className="term text-foreground-faint">Patch withdrawn</div>
                      {selected.constraints.length > 0 && (
                        <div className="mt-1.5">
                          <div className="font-mono text-[10px] uppercase text-foreground-faint">
                            constraints added for the next iteration
                          </div>
                          {selected.constraints.map((constraint, index) => (
                            <div key={index} className="term text-warn">
                              → {constraint}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </motion.div>
                )}
              </div>

              <div className="grid gap-4 border-b border-border p-4 lg:grid-cols-3">
                <div>
                  <div className="panel-title mb-1.5">Root cause</div>
                  <div className="term text-accent">{finding?.root_cause_location ?? "—"}</div>
                  <p className="mt-1 text-small text-foreground-muted">{selected.reason}</p>
                </div>
                <div>
                  <div className="panel-title mb-1.5">Violated clause</div>
                  {clause ? (
                    <>
                      <div className="term text-accent">{clause.clause_id}</div>
                      <pre className="mt-1 term text-verified">{clause.predicate}</pre>
                    </>
                  ) : (
                    <span className="text-foreground-faint">—</span>
                  )}
                </div>
                <div>
                  <div className="panel-title mb-1.5">Expected effect</div>
                  <p className="text-small text-foreground-muted">{selected.expected_effect}</p>
                </div>
              </div>

              <div className="h-[26rem] border-b border-border">
                {view === "split" ? (
                  <DiffEditor
                    original={before}
                    modified={after}
                    language="python"
                    theme={MONACO_THEME}
                    beforeMount={defineMonacoTheme}
                    options={{
                      readOnly: true,
                      renderSideBySide: true,
                      fontSize: 12,
                      fontFamily: "JetBrains Mono, monospace",
                      minimap: { enabled: false },
                      scrollBeyondLastLine: false,
                      renderOverviewRuler: false,
                    }}
                  />
                ) : (
                  <Editor
                    value={selected.unified_diff}
                    language="diff"
                    theme={MONACO_THEME}
                    beforeMount={defineMonacoTheme}
                    options={{
                      readOnly: true,
                      fontSize: 12,
                      fontFamily: "JetBrains Mono, monospace",
                      minimap: { enabled: false },
                      scrollBeyondLastLine: false,
                      lineNumbers: "on",
                      overviewRulerLanes: 0,
                      wordWrap: "on",
                    }}
                  />
                )}
              </div>

              <div className="flex flex-wrap items-center gap-2 px-4 py-2.5">
                <span className="panel-title">Files</span>
                {selected.files.map((file) => (
                  <Chip key={file} tone="muted">
                    {file}
                  </Chip>
                ))}
                {selected.policy_violations.length > 0 && (
                  <div className="w-full pt-2">
                    <span className="panel-title text-refuted">Policy violations</span>
                    {selected.policy_violations.map((violation, index) => (
                      <div key={index} className="term text-refuted">
                        {String(violation.code)}: {String(violation.message)}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      )}
    </Panel>
  );
}

// ---------------------------------------------------------------------------
// Panel — Refutation Gauntlet
// ---------------------------------------------------------------------------
export function GauntletPanel({
  gauntlets,
  liveStages,
}: {
  gauntlets: GauntletRun[];
  liveStages: Record<string, { verdict: string; detail: string }>;
}) {
  return (
    <Panel
      title="Refutation Gauntlet"
      subtitle={`${gauntlets.filter((g) => g.verdict === "pass").length}/${gauntlets.length} passes`}
      bodyClassName="p-0"
    >
      {gauntlets.length === 0 ? (
        <div className="p-4">
          <div className="grid gap-px overflow-hidden rounded-md border border-border bg-border sm:grid-cols-2 lg:grid-cols-4">
            {GAUNTLET_STAGES.map((stage) => {
              const live = Object.entries(liveStages).find(([key]) => key.endsWith(stage));
              return (
                <div key={stage} className="bg-surface p-3">
                  <div className="mb-1.5 font-mono text-mono-label uppercase text-foreground-subtle">
                    {GAUNTLET_LABELS[stage]}
                  </div>
                  {live ? (
                    <VerdictChip verdict={live[1].verdict} />
                  ) : (
                    <Chip tone="muted">PENDING</Chip>
                  )}
                </div>
              );
            })}
          </div>
          <p className="mt-3 text-[11px] leading-4 text-foreground-faint">
            All four stages execute against the patched build. If any of them succeeds in
            reproducing the vulnerability or detecting a regression, the patch is refuted.
          </p>
        </div>
      ) : (
        <div className="divide-y divide-border">
          {gauntlets.map((gauntlet) => (
            <article key={gauntlet.id} className="p-4">
              <div className="mb-3 flex flex-wrap items-center gap-3">
                <span className="font-mono text-sm font-bold text-accent">
                  {gauntlet.finding_handle} v{gauntlet.iteration}
                </span>
                <VerdictChip verdict={gauntlet.verdict} />
                <span className="term text-foreground-muted">
                  {gauntlet.stages_passed}/{gauntlet.stages_total} stages ·{" "}
                  {(gauntlet.duration_ms / 1000).toFixed(1)}s
                </span>
                <span
                  className={cn(
                    "ml-auto max-w-full truncate text-small",
                    gauntlet.verdict === "pass" ? "text-verified" : "text-refuted",
                  )}
                >
                  {gauntlet.summary}
                </span>
              </div>

              <div className="grid gap-px overflow-hidden rounded-md border border-border bg-border sm:grid-cols-2 lg:grid-cols-4">
                {gauntlet.stages.map((stage) => (
                  <div
                    key={stage.stage}
                    className={cn(
                      "bg-surface p-3",
                      stage.verdict === "fail" && "bg-refuted/[0.07]",
                    )}
                  >
                    <div className="mb-1.5 flex items-center justify-between gap-2">
                      <span className="font-mono text-mono-label uppercase text-foreground-subtle">
                        {GAUNTLET_LABELS[stage.stage] ?? stage.stage}
                      </span>
                      <VerdictChip verdict={stage.verdict} />
                    </div>
                    <p className="text-[11px] leading-4 text-foreground-muted">{stage.detail}</p>
                    {stage.cases_total > 0 && (
                      <div className="mt-1.5 font-mono text-[10px] text-foreground-faint">
                        {stage.cases_passed}/{stage.cases_total} cases ·{" "}
                        {(stage.duration_ms / 1000).toFixed(1)}s
                      </div>
                    )}
                    {stage.verdict === "fail" &&
                      Object.keys(stage.refuting_evidence ?? {}).length > 0 && (
                        <details className="mt-2">
                          <summary className="cursor-pointer font-mono text-[10px] uppercase text-refuted">
                            refuting evidence
                          </summary>
                          <pre className="mt-1 max-h-40 overflow-auto term text-refuted">
                            {JSON.stringify(stage.refuting_evidence, null, 2)}
                          </pre>
                        </details>
                      )}
                  </div>
                ))}
              </div>
            </article>
          ))}
        </div>
      )}
    </Panel>
  );
}

// ---------------------------------------------------------------------------
// Panel 5 — Resource meter
// ---------------------------------------------------------------------------
export function ResourceMeter({
  run,
  metric,
  elapsedMs,
  connected,
}: {
  run: RunDetail;
  metric: {
    tokens: number;
    coverage: number;
    ram_mb: number;
    egress: number;
    model_calls: number;
    sandbox_executions: number;
    cpu_seconds: number;
  } | null;
  elapsedMs: number;
  connected: boolean;
}) {
  const tokens = metric?.tokens ?? run.tokens_used;
  const calls = metric?.model_calls ?? run.model_calls;
  const executions = metric?.sandbox_executions ?? run.sandbox_executions;
  const coverage = metric?.coverage ?? run.coverage_percent;
  const ram = metric?.ram_mb ?? run.peak_ram_mb;
  const cpu = metric?.cpu_seconds ?? run.cpu_seconds;
  const egress = metric?.egress ?? run.egress_bytes;

  const sandbox = run.sandbox ?? {};
  const active = (sandbox.adapters ?? {})[sandbox.configured] ?? {};
  const enforced = Boolean(active.network_enforced);

  return (
    <Panel
      title="Resource meter"
      actions={
        <Chip tone={connected ? "verified" : "muted"}>
          <span
            className={cn(
              "mr-1 inline-block h-1.5 w-1.5 rounded-full",
              connected ? "animate-pulse bg-verified" : "bg-foreground-faint",
            )}
          />
          {connected ? "LIVE" : "IDLE"}
        </Chip>
      }
    >
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {[
          ["Tokens used", tokens.toLocaleString(), "default"],
          ["Model calls", calls.toLocaleString(), "default"],
          ["Sandbox execs", executions.toLocaleString(), "default"],
          ["Elapsed", formatClock(elapsedMs), "accent"],
          ["Coverage", `${coverage.toFixed(1)}%`, coverage > 50 ? "verified" : "warn"],
          ["Peak RAM", ram > 0 ? `${ram} MB` : "n/a", "default"],
          ["CPU", `${cpu.toFixed(1)}s`, "default"],
          ["Network egress", formatBytes(egress), egress === 0 ? "verified" : "refuted"],
        ].map(([label, value, tone]) => (
          <div key={String(label)}>
            <div className="font-mono text-mono-label uppercase text-foreground-subtle">
              {label}
            </div>
            <div
              className={cn(
                "mt-0.5 font-mono text-lg font-bold tabular-nums",
                tone === "accent" && "text-accent",
                tone === "verified" && "text-verified",
                tone === "warn" && "text-warn",
                tone === "refuted" && "text-refuted",
              )}
            >
              {value}
            </div>
          </div>
        ))}
      </div>

      <div className="mt-4 space-y-2">
        <Progress value={coverage} tone={coverage > 50 ? "verified" : "warn"} />
        <div className="flex flex-wrap items-center gap-2">
          <Chip tone="muted" icon={<Cpu className="h-3 w-3" />}>
            SANDBOX {String(sandbox.configured ?? "unknown")}
          </Chip>
          <Chip
            tone={enforced ? "verified" : "warn"}
            icon={<Network className="h-3 w-3" />}
          >
            NETWORK {enforced ? "ENFORCED" : "NOT ENFORCED"}
          </Chip>
          <Chip tone={active.suitable_for_untrusted_code ? "verified" : "warn"}>
            {active.suitable_for_untrusted_code ? "UNTRUSTED-SAFE" : "DEV ADAPTER"}
          </Chip>
        </div>
        {!active.suitable_for_untrusted_code && active.notes && (
          <p className="text-[11px] leading-4 text-warn">{String(active.notes)}</p>
        )}
      </div>
    </Panel>
  );
}

function formatClock(ms: number): string {
  const total = Math.floor(ms / 1000);
  const minutes = Math.floor(total / 60);
  const seconds = total % 60;
  return `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
}

// ---------------------------------------------------------------------------
// Evidence graph
// ---------------------------------------------------------------------------
const NODE_TONE: Record<string, string> = {
  vulnerability: "border-refuted/60 text-refuted",
  samhita_clause: "border-accent/60 text-accent",
  patch: "border-info/60 text-info",
  gauntlet_result: "border-verified/50 text-verified",
  shield: "border-warn/60 text-warn",
  certificate: "border-verified/70 text-verified",
  reproduction: "border-refuted/40 text-foreground-muted",
};

export function EvidenceGraphPanel({ runId }: { runId: string }) {
  const [graph, setGraph] = useState<Awaited<ReturnType<typeof endpoints.evidence>> | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [node, setNode] = useState<Record<string, any> | null>(null);

  useEffect(() => {
    void (async () => {
      try {
        setGraph(await endpoints.evidence(runId));
      } catch {
        /* the graph appears once PRAMAAN has run */
      }
    })();
  }, [runId]);

  useEffect(() => {
    if (!selected) {
      setNode(null);
      return;
    }
    void (async () => {
      try {
        setNode(await endpoints.evidenceNode(runId, selected));
      } catch {
        setNode(null);
      }
    })();
  }, [runId, selected]);

  const byType = useMemo(() => {
    const groups: Record<string, typeof graph extends null ? never : any[]> = {};
    for (const item of graph?.nodes ?? []) {
      (groups[item.type] ??= []).push(item);
    }
    return groups;
  }, [graph]);

  if (!graph || graph.nodes.length === 0) {
    return (
      <Panel title="Evidence graph">
        <EmptyState
          icon={<ShieldCheck className="h-5 w-5" />}
          title="No evidence graph yet"
          detail="PRAMAAN builds the graph when a finding reaches attestation."
        />
      </Panel>
    );
  }

  return (
    <Panel
      title="Evidence graph"
      subtitle={`${graph.counts.nodes} nodes · ${graph.counts.edges} edges`}
      bodyClassName="p-0"
    >
      <div className="grid lg:grid-cols-[1fr_18rem]">
        <div className="max-h-80 space-y-3 overflow-y-auto p-4">
          {Object.entries(byType).map(([type, nodes]) => (
            <div key={type}>
              <div className="mb-1.5 font-mono text-mono-label uppercase text-foreground-subtle">
                {type.replace(/_/g, " ")} · {nodes.length}
              </div>
              <div className="flex flex-wrap gap-1.5">
                {nodes.map((item: any) => (
                  <button
                    key={item.ref}
                    onClick={() => setSelected(item.ref)}
                    className={cn(
                      "max-w-full truncate rounded border bg-surface-lowest px-2 py-1 text-left term transition-colors hover:bg-surface-high",
                      NODE_TONE[type] ?? "border-border text-foreground-muted",
                      selected === item.ref && "ring-1 ring-accent",
                    )}
                    title={item.title}
                  >
                    {item.ref}
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>

        <aside className="border-t border-border p-4 lg:border-l lg:border-t-0">
          {node ? (
            <div className="space-y-3">
              <div>
                <div className="panel-title mb-1">{node.type}</div>
                <div className="text-small text-foreground">{node.title}</div>
              </div>
              <div className="space-y-1">
                <div className="font-mono text-[10px] uppercase text-foreground-faint">
                  content hash
                </div>
                <Hash value={String(node.content_hash ?? "")} length={24} />
                <div className="font-mono text-[10px] uppercase text-foreground-faint">
                  produced by
                </div>
                <div className="term text-foreground-muted">{node.produced_by || "—"}</div>
              </div>
              {node.provenance?.incoming?.length > 0 && (
                <div>
                  <div className="font-mono text-[10px] uppercase text-foreground-faint">
                    referenced by
                  </div>
                  {node.provenance.incoming.map((edge: any, index: number) => (
                    <button
                      key={index}
                      onClick={() => setSelected(edge.source)}
                      className="block truncate term text-accent hover:underline"
                    >
                      {edge.source} —{edge.relation}→
                    </button>
                  ))}
                </div>
              )}
              {node.provenance?.outgoing?.length > 0 && (
                <div>
                  <div className="font-mono text-[10px] uppercase text-foreground-faint">
                    supports
                  </div>
                  {node.provenance.outgoing.map((edge: any, index: number) => (
                    <button
                      key={index}
                      onClick={() => setSelected(edge.target)}
                      className="block truncate term text-accent hover:underline"
                    >
                      —{edge.relation}→ {edge.target}
                    </button>
                  ))}
                </div>
              )}
              {node.content && (
                <details>
                  <summary className="cursor-pointer font-mono text-[10px] uppercase text-foreground-subtle">
                    content
                  </summary>
                  <pre className="mt-1 max-h-48 overflow-auto term text-foreground-muted">
                    {String(node.content).slice(0, 4000)}
                  </pre>
                </details>
              )}
            </div>
          ) : (
            <p className="text-small text-foreground-faint">
              Select a node to see its provenance — what references it, and what it supports.
            </p>
          )}
        </aside>
      </div>
    </Panel>
  );
}

// ---------------------------------------------------------------------------
// SAMHITA contract panel
// ---------------------------------------------------------------------------
export function ContractPanel({ clauses }: { clauses: Clause[] }) {
  const [filter, setFilter] = useState<"SURVIVING" | "FALSIFIED" | "ALL">("SURVIVING");
  const surviving = clauses.filter((c) => c.status === "SURVIVING");
  const falsified = clauses.filter((c) => c.status === "FALSIFIED");
  const shown =
    filter === "ALL" ? clauses : clauses.filter((clause) => clause.status === filter);

  return (
    <Panel
      title="SAMHITA contract"
      subtitle={`${surviving.length} surviving · ${falsified.length} falsified`}
      actions={
        <div className="flex gap-1">
          {(["SURVIVING", "FALSIFIED", "ALL"] as const).map((id) => (
            <button
              key={id}
              onClick={() => setFilter(id)}
              className={cn(
                "rounded px-2 py-0.5 font-mono text-mono-label uppercase transition-colors",
                filter === id
                  ? id === "FALSIFIED"
                    ? "bg-refuted/15 text-refuted"
                    : "bg-accent/15 text-accent"
                  : "text-foreground-subtle hover:text-foreground",
              )}
            >
              {id}
            </button>
          ))}
        </div>
      }
      bodyClassName="p-0"
    >
      {shown.length === 0 ? (
        <EmptyState title="No clauses in this category" />
      ) : (
        <div className="max-h-96 divide-y divide-border overflow-y-auto">
          {shown.map((clause) => (
            <div key={clause.id} className="px-4 py-2.5">
              <div className="flex flex-wrap items-baseline gap-2">
                <span className="font-mono text-mono-data font-bold text-accent">
                  {clause.clause_id}
                </span>
                <Chip tone={clause.status === "SURVIVING" ? "verified" : "refuted"}>
                  {clause.status}
                </Chip>
                <span className="font-mono text-[10px] uppercase text-foreground-faint">
                  {clause.kind}
                </span>
                <span className="ml-auto font-mono text-[10px] text-foreground-faint">
                  {clause.observation_count} obs · {clause.holdout_pass_count} held-out
                </span>
              </div>
              <pre className="mt-1 overflow-x-auto term text-foreground">{clause.predicate}</pre>
              <div className="term text-foreground-faint">scope {clause.scope}</div>
              {clause.status === "FALSIFIED" && clause.falsification_reason && (
                <div className="mt-1 term text-refuted">{clause.falsification_reason}</div>
              )}
            </div>
          ))}
        </div>
      )}
      <div className="border-t border-border px-4 py-2 text-[11px] leading-4 text-foreground-faint">
        Only surviving clauses are used as evidence. A clause with no applicable held-out
        observation is rejected too — an untested invariant is not evidence.
      </div>
    </Panel>
  );
}

// ---------------------------------------------------------------------------
// Shield panel
// ---------------------------------------------------------------------------
export function ShieldPanel({ run }: { run: RunDetail }) {
  if (!run.shields?.length) {
    return (
      <Panel title="Shields">
        <EmptyState
          icon={<ShieldCheck className="h-5 w-5" />}
          title="No shields deployed"
          detail="A shield is synthesised from the validated proof of vulnerability, then verified to block the exploit while the benign corpus still passes."
        />
      </Panel>
    );
  }

  return (
    <Panel
      title="Shields"
      subtitle={`${run.shields.filter((s) => s.active).length} active`}
      bodyClassName="p-0"
    >
      <div className="divide-y divide-border">
        {run.shields.map((shield) => (
          <div key={shield.id} className="px-4 py-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-sm font-bold text-accent">{shield.handle}</span>
              <Chip tone="muted">{shield.mechanism}</Chip>
              <Chip tone={shield.verified_blocked ? "verified" : "refuted"}>
                EXPLOIT {shield.verified_blocked ? "BLOCKED" : "NOT BLOCKED"}
              </Chip>
              <Chip tone={shield.verified_benign ? "verified" : "refuted"}>
                BENIGN {shield.benign_pass_count}/{shield.benign_total}
              </Chip>
              <span className="ml-auto term text-foreground-faint">
                finding {shield.finding_handle}
              </span>
            </div>
            <pre className="mt-2 overflow-x-auto term text-foreground-muted">{shield.rule}</pre>
            <div className="mt-1.5 term text-foreground-faint">
              revert: {shield.revert_command}
            </div>
          </div>
        ))}
      </div>
      <div className="border-t border-border px-4 py-2 text-[11px] leading-4 text-foreground-faint">
        Shields are reverted in the verification workspace before the gauntlet runs, so the
        gauntlet tests the patch rather than the mitigation.
      </div>
    </Panel>
  );
}

// ---------------------------------------------------------------------------
// Live log
// ---------------------------------------------------------------------------
export function LogPanel({ events }: { events: Enveloped[] }) {
  const logs = eventsOfType(events, "log");
  return (
    <Panel title="Evidence console" subtitle={`${logs.length} lines`} bodyClassName="p-3">
      <Terminal
        maxHeight="14rem"
        lines={logs.map((log) => ({
          text: `[${log.source || "system"}] ${log.line}`,
          tone: log.stream === "stderr" ? "stderr" : "dim",
        }))}
      />
    </Panel>
  );
}

// ---------------------------------------------------------------------------
// Security Mission (Red vs Blue)
// ---------------------------------------------------------------------------
function DataFlowTrace({ finding, patched }: { finding: Finding; patched: boolean }) {
  const chain = (finding.root_cause_chain ?? []).filter(Boolean);
  const flow = chain.length
    ? chain
    : [finding.location, finding.root_cause_location].filter(Boolean);
  if (flow.length === 0) return null;

  // The last node is the sink; everything before it is the path that reaches it.
  const path = flow.slice(0, -1);
  const sink = flow[flow.length - 1];

  return (
    <div className="mt-3">
      <div className="mb-1.5 flex items-center gap-2">
        <span className="text-[10px] uppercase font-mono text-foreground-faint">Data flow</span>
        <span
          className={cn(
            "text-[10px] font-mono font-bold",
            patched ? "text-verified" : "text-refuted",
          )}
        >
          source → sink
        </span>
      </div>
      <div className="rounded border border-border/60 bg-surface-lowest p-2.5 font-mono text-[11px] leading-relaxed">
        {path.map((step, index) => (
          <div key={index}>
            <div className="flex items-start gap-1.5 text-foreground-muted">
              <span className="text-accent/60">{index === 0 ? "▸" : "↓"}</span>
              <span className="min-w-0 break-all">{step}</span>
            </div>
          </div>
        ))}
        <div className="mt-0.5 flex items-start gap-1.5">
          <span className={patched ? "text-verified" : "text-refuted"}>
            {patched ? "✓" : "⚠"}
          </span>
          <span
            className={cn(
              "min-w-0 break-all font-bold",
              patched ? "text-verified" : "text-refuted",
            )}
          >
            {sink}
            {finding.cwe ? ` — ${finding.cwe}` : ""}
            {patched ? " (MITIGATED)" : ""}
          </span>
        </div>
        {!patched && finding.root_cause_summary && (
          <p className="mt-1.5 border-t border-border/50 pt-1.5 text-[10px] text-foreground-faint not-italic">
            {finding.root_cause_summary}
          </p>
        )}
      </div>
    </div>
  );
}

export function SecurityMissionPanel({
  run,
  events,
  findings,
  patches,
  gauntlets,
  clauses,
  certificates,
}: {
  run: RunDetail;
  events: Enveloped[];
  findings: Finding[];
  patches: Patch[];
  gauntlets: GauntletRun[];
  clauses: Clause[];
  certificates: Certificate[];
}) {
  const hasFindings = findings.length > 0;
  const isStatic = run.mode === "static_only";

  // ---- Evidence-driven proof state (no fabricated numbers) ----
  // The verified patch is the verification ENGINE's determination (it only reaches VERIFIED after
  // the gauntlet passes) — never an LLM claim. Every number below is read from a real record or
  // shown as pending. Nothing here is hardcoded to success.
  const verifiedPatch =
    patches.find((p) => p.status === "VERIFIED" || p.status === "PUBLISHED") ?? null;
  const refutedPatches = patches.filter(
    (p) => p.status === "REFUTED" || p.status === "POLICY_REJECTED",
  );
  const reproducedFinding =
    findings.find((f) => f.state === "validated" && f.reproduced) ??
    findings.find((f) => f.reproduced) ??
    null;
  const anyValidated = findings.some((f) => f.state === "validated");

  // Gauntlet run tied to the verified patch — mutation + regression numbers come from HERE only.
  const proofGauntlet =
    (verifiedPatch ? gauntlets.find((g) => g.patch_id === verifiedPatch.id) : null) ??
    gauntlets.find((g) => g.verdict === "pass") ??
    null;
  const mutationStage = proofGauntlet?.stages.find((s) => s.stage === "exploit_mutation") ?? null;
  const regressionStage =
    proofGauntlet?.stages.find((s) => s.stage === "differential_replay") ?? null;

  // Certificate for display (serial/hash/level) — only a real, non-refuted certificate.
  const proofCert =
    certificates.find(
      (c) => c.finding_handle === verifiedPatch?.finding_handle && c.assurance_level !== "R",
    ) ??
    certificates.find((c) => c.assurance_level !== "R") ??
    null;

  // The finding this proof is about.
  const verifiedFinding = verifiedPatch
    ? (findings.find((f) => f.handle === verifiedPatch.finding_handle) ?? reproducedFinding)
    : (reproducedFinding ?? findings[0] ?? null);

  // Overall proof status, decided by evidence — VERIFIED only when a patch survived the gauntlet.
  const proofStatus: "VERIFIED" | "FAILED" | "PENDING" | "NONE" = verifiedPatch
    ? "VERIFIED"
    : anyValidated && refutedPatches.length > 0
      ? "FAILED"
      : anyValidated
        ? "PENDING"
        : "NONE";
  const proofTone: "verified" | "refuted" | "warn" =
    proofStatus === "VERIFIED" ? "verified" : proofStatus === "FAILED" ? "refuted" : "warn";
  const proofBanner: Record<typeof proofStatus, string> = {
    VERIFIED: "PATCH VERIFIED ✓",
    FAILED: "PATCH REJECTED ✗",
    PENDING: "VERIFICATION IN PROGRESS",
    NONE: "AWAITING VALIDATED FINDING",
  };

  const stageLine = (
    stage: { verdict: string; cases_passed: number; cases_total: number } | null,
  ) =>
    stage
      ? {
          tone: (stage.verdict === "pass" ? "verified" : "refuted") as "verified" | "refuted",
          text: `${stage.verdict === "pass" ? "✓" : "✗"} ${stage.cases_passed}/${stage.cases_total} ${
            stage.verdict === "pass" ? "PASS" : "FAIL"
          }`,
        }
      : { tone: "warn" as const, text: "… pending" };
  const mutationLine = stageLine(mutationStage);
  const regressionLine = stageLine(regressionStage);

  const proofRows: { label: string; tone: "verified" | "refuted" | "warn"; text: string }[] = [
    {
      label: "1. Adversarial Exploit Reproduced",
      tone: reproducedFinding ? "verified" : "warn",
      text: reproducedFinding
        ? `✓ ${reproducedFinding.reproduction_count}× reproduced`
        : "… pending",
    },
    {
      label: "2. Blue Team Patch Generated",
      tone: patches.length > 0 ? "verified" : "warn",
      text: patches.length > 0 ? `✓ ${patches.length} candidate(s)` : "… pending",
    },
    {
      label: "3. Patch Applied & Survived Gauntlet",
      tone: verifiedPatch ? "verified" : refutedPatches.length > 0 ? "refuted" : "warn",
      text: verifiedPatch
        ? "✓ VERIFIED"
        : refutedPatches.length > 0
          ? `✗ ${refutedPatches.length} refuted`
          : "… pending",
    },
    {
      label: "4. Exploit Mutation Attacks Blocked",
      tone: mutationLine.tone,
      text: mutationLine.text,
    },
    {
      label: "5. Benign Regression Invariants Intact",
      tone: regressionLine.tone,
      text: regressionLine.text,
    },
  ];

  return (
    <div className="space-y-6">
      {isStatic && (
        <div className="rounded-md border border-warn/40 bg-warn/5 p-4 flex gap-3">
          <AlertOctagon className="h-5 w-5 text-warn shrink-0 mt-0.5" />
          <div>
            <h4 className="font-mono font-bold text-warn">STATIC-ONLY ANALYSIS MODE</h4>
            <p className="text-small text-foreground-muted mt-1">
              Adversarial validation and patch synthesis are bypassed because the repository lacks a runtime sandbox environment or is configured as static-only. No cryptographic verification proof can be generated.
            </p>
          </div>
        </div>
      )}

      {!hasFindings ? (
        <div className="grid gap-6 xl:grid-cols-2">
          <Panel
            title={
              <div className="flex items-center gap-2 text-refuted">
                <Swords className="h-5 w-5" />
                <span>Red Team (Adversarial Emulation)</span>
              </div>
            }
            subtitle="Idle / Profiling"
            className="border-refuted/10 bg-refuted/[0.01]"
          >
            <EmptyState
              title="No active attack validation"
              detail="Waiting for discovery phase to propose vulnerability hypotheses. Red Team will automatically emulate adversaries to reproduce any confirmed findings."
            />
          </Panel>

          <Panel
            title={
              <div className="flex items-center gap-2 text-accent">
                <ShieldCheck className="h-5 w-5" />
                <span>Blue Team (Defense & Patch Synthesis)</span>
              </div>
            }
            subtitle="Ingesting / Indexing"
            className="border-accent/10 bg-accent/[0.01]"
          >
            <EmptyState
              title="No active repairs"
              detail="Blue team is currently building the world model, synthesising SAMHITA invariant clauses, or waiting for validated findings."
            />
          </Panel>
        </div>
      ) : (
        <>
          <div className="grid gap-6 xl:grid-cols-2">
            {/* Red Team Column */}
            <div className="space-y-6">
              <Panel
                title={
                  <div className="flex items-center gap-2 text-refuted">
                    <Swords className="h-5 w-5" />
                    <span>Red Team Activity</span>
                  </div>
                }
                subtitle={`${findings.length} findings validation`}
                className="border-refuted/20 bg-surface-lowest shadow-sm"
              >
                <div className="space-y-4">
                  {findings.map((f) => (
                    <div key={f.id} className="border border-border rounded-md p-3.5 bg-surface-card">
                      <div className="flex items-center justify-between gap-2 flex-wrap">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-bold px-2 py-0.5 rounded bg-refuted/10 text-refuted">
                            {f.handle}
                          </span>
                          <span className="font-mono text-xs text-foreground-muted">{f.cwe}</span>
                        </div>
                        <Chip tone={f.state === "validated" ? "refuted" : f.state === "refuted" ? "verified" : "warn"}>
                          {f.state.toUpperCase()}
                        </Chip>
                      </div>

                      <h4 className="font-semibold text-sm mt-2 text-foreground">{f.title}</h4>
                      <p className="text-xs text-foreground-muted mt-1 font-mono">Location: {f.location}</p>

                      <DataFlowTrace
                        finding={f}
                        patched={patches.some(
                          (p) =>
                            p.finding_handle === f.handle &&
                            (p.status === "VERIFIED" || p.status === "PUBLISHED"),
                        )}
                      />

                      {f.reproduction_count > 0 && (
                        <div className="mt-2.5 p-2 bg-surface-lowest rounded border border-border/60 text-xs font-mono space-y-1">
                          <div className="flex justify-between">
                            <span className="text-foreground-muted">Reproduction Count:</span>
                            <span className="text-foreground font-bold">{f.reproduction_count}x</span>
                          </div>
                          {f.exit_code !== null && (
                            <div className="flex justify-between">
                              <span className="text-foreground-muted">Exit Code:</span>
                              <span className="text-refuted font-bold">{f.exit_code}</span>
                            </div>
                          )}
                          {f.sanitizer_signal && (
                            <div className="flex justify-between">
                              <span className="text-foreground-muted">Signal:</span>
                              <span className="text-refuted font-bold">{f.sanitizer_signal}</span>
                            </div>
                          )}
                        </div>
                      )}

                      {f.pov_payload && (
                        <div className="mt-3">
                          <div className="text-[10px] uppercase font-mono text-foreground-faint mb-1">PoV Exploit Payload</div>
                          <pre className="p-2.5 bg-surface-lowest text-[11px] rounded font-mono text-red-400 overflow-x-auto border border-refuted/10 max-h-40">
                            {f.pov_payload}
                          </pre>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </Panel>

              <Panel
                title="Re-Attack & Gauntlet Verdicts"
                subtitle={`${gauntlets.length} iterations run`}
                className="border-refuted/20 bg-surface-lowest shadow-sm"
              >
                {gauntlets.length === 0 ? (
                  <EmptyState title="No gauntlet runs executed yet" />
                ) : (
                  <div className="space-y-4">
                    {gauntlets.map((g, idx) => (
                      <div key={g.id || idx} className="border border-border rounded-md p-3.5 bg-surface-card">
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-xs font-bold text-foreground-muted">
                            Finding {g.finding_handle} (Iter #{g.iteration})
                          </span>
                          <VerdictChip verdict={g.verdict} />
                        </div>

                        <div className="mt-3 grid grid-cols-2 gap-2 text-xs">
                          {g.stages?.map((s) => (
                            <div key={s.stage} className="p-2 bg-surface-lowest rounded border border-border/50 flex justify-between items-center">
                              <span className="font-mono text-[11px] truncate mr-2" title={GAUNTLET_LABELS[s.stage] || s.stage}>
                                {GAUNTLET_LABELS[s.stage] || s.stage}
                              </span>
                              <Chip tone={s.verdict === "pass" ? "verified" : s.verdict === "fail" ? "refuted" : "warn"}>
                                {s.verdict.toUpperCase()}
                              </Chip>
                            </div>
                          ))}
                        </div>

                        {g.summary && (
                          <p className="mt-2.5 text-xs text-foreground-muted italic font-mono bg-surface-lowest p-2 rounded">
                            {g.summary}
                          </p>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </Panel>
            </div>

            {/* Blue Team Column */}
            <div className="space-y-6">
              <Panel
                title={
                  <div className="flex items-center gap-2 text-accent">
                    <ShieldCheck className="h-5 w-5" />
                    <span>Blue Team Activity</span>
                  </div>
                }
                subtitle={`${clauses.length} contracts / ${patches.length} repairs`}
                className="border-accent/20 bg-surface-lowest shadow-sm"
              >
                <div className="space-y-4">
                  {/* SAMHITA Clause summary */}
                  <div className="border border-border rounded-md p-3.5 bg-surface-card">
                    <h4 className="font-semibold text-sm text-foreground mb-2">SAMHITA Executable Invariants</h4>
                    <div className="space-y-2">
                      {clauses.slice(0, 4).map((c) => (
                        <div key={c.id} className="text-xs flex items-center justify-between gap-4 p-1.5 bg-surface-lowest rounded">
                          <span className="font-mono font-bold text-accent truncate max-w-[200px]" title={c.clause_id}>
                            {c.clause_id}
                          </span>
                          <div className="flex items-center gap-2">
                            <span className="text-[10px] text-foreground-faint">{c.kind}</span>
                            <Chip tone={c.status === "SURVIVING" ? "verified" : "refuted"}>
                              {c.status}
                            </Chip>
                          </div>
                        </div>
                      ))}
                      {clauses.length > 4 && (
                        <div className="text-center text-[10px] text-foreground-faint pt-1">
                          + {clauses.length - 4} more invariant clauses
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Patches list */}
                  {patches.map((p, idx) => (
                    <div key={p.id || idx} className="border border-border rounded-md p-3.5 bg-surface-card">
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-xs font-bold px-2 py-0.5 rounded bg-accent/10 text-accent">
                          Patch {p.finding_handle} (Iter #{p.iteration})
                        </span>
                        <Chip tone={p.status === "VERIFIED" ? "verified" : p.status === "REFUTED" ? "refuted" : "warn"}>
                          {p.status.toUpperCase()}
                        </Chip>
                      </div>

                      <div className="text-xs text-foreground-muted mt-2 space-y-1">
                        <div><strong className="text-foreground">Risk Score:</strong> <span className="font-mono">{p.risk || "LOW"}</span></div>
                        <div><strong className="text-foreground">Expected Effect:</strong> {p.expected_effect || "Mitigate vulnerability"}</div>
                      </div>

                      {p.unified_diff && (
                        <div className="mt-3">
                          <div className="text-[10px] uppercase font-mono text-foreground-faint mb-1">Synthesised Repair Code</div>
                          <pre className="p-2.5 bg-surface-lowest text-[11px] rounded font-mono text-green-400 overflow-x-auto border border-accent/10 max-h-40">
                            {p.unified_diff}
                          </pre>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </Panel>
            </div>
          </div>

          {/* Proof of Patch — Kavach Security Verification Proof (evidence-driven, never fabricated) */}
          <div className="pt-4 max-w-2xl mx-auto">
            <div
              className={cn(
                "relative rounded-xl border-2 bg-surface-lowest p-6 md:p-8 transition-all duration-300",
                proofTone === "verified" &&
                  "border-verified/50 shadow-[0_0_20px_rgba(61,220,132,0.15)]",
                proofTone === "refuted" &&
                  "border-refuted/50 shadow-[0_0_20px_rgba(239,68,68,0.12)]",
                proofTone === "warn" && "border-warn/40",
              )}
            >
              {/* Certificate Decorative Corners */}
              {(["top-2 left-2 border-t-2 border-l-2", "top-2 right-2 border-t-2 border-r-2", "bottom-2 left-2 border-b-2 border-l-2", "bottom-2 right-2 border-b-2 border-r-2"] as const).map(
                (pos) => (
                  <div
                    key={pos}
                    className={cn(
                      "absolute w-4 h-4",
                      pos,
                      proofTone === "verified" && "border-verified/60",
                      proofTone === "refuted" && "border-refuted/60",
                      proofTone === "warn" && "border-warn/50",
                    )}
                  />
                ),
              )}

              <div className="text-center space-y-2">
                <div
                  className={cn(
                    "inline-flex items-center justify-center p-2 rounded-full mb-2",
                    proofTone === "verified" && "bg-verified/10 text-verified",
                    proofTone === "refuted" && "bg-refuted/10 text-refuted",
                    proofTone === "warn" && "bg-warn/10 text-warn",
                  )}
                >
                  {proofStatus === "VERIFIED" ? (
                    <ShieldCheck className="h-8 w-8" />
                  ) : proofStatus === "FAILED" ? (
                    <AlertOctagon className="h-8 w-8" />
                  ) : (
                    <Swords className="h-8 w-8" />
                  )}
                </div>
                <h3
                  className={cn(
                    "font-mono text-lg md:text-xl font-bold tracking-wider uppercase",
                    proofTone === "verified" && "text-verified",
                    proofTone === "refuted" && "text-refuted",
                    proofTone === "warn" && "text-warn",
                  )}
                >
                  Kavach Security Verification Proof
                </h3>
                <p className="text-xs text-foreground-faint font-mono">
                  {proofCert
                    ? "DETERMINISTIC CRYPTOGRAPHIC MITIGATION CERTIFICATE"
                    : "PROOF STATE DERIVED FROM LIVE VERIFICATION EVIDENCE"}
                </p>
              </div>

              <div className="mt-6 border-t border-b border-border/80 py-4 font-mono text-xs md:text-sm space-y-3">
                <div className="flex justify-between gap-4">
                  <span className="text-foreground-muted">Target Repository</span>
                  <span className="text-foreground font-bold truncate max-w-[260px] md:max-w-md">
                    {run.repository_full_name || "—"}
                  </span>
                </div>
                <div className="flex justify-between gap-4">
                  <span className="text-foreground-muted">Vulnerability Target</span>
                  <span className="text-refuted font-bold">{verifiedFinding?.cwe || "—"}</span>
                </div>
                <div className="flex justify-between gap-4">
                  <span className="text-foreground-muted">Assurance Level</span>
                  <span
                    className={cn(
                      "font-bold",
                      proofCert ? "text-verified" : "text-foreground-faint",
                    )}
                  >
                    {proofCert ? `LEVEL ${proofCert.assurance_level}` : "not yet issued"}
                  </span>
                </div>

                <div className="border-t border-border/60 my-3 pt-3 space-y-2">
                  {proofRows.map((row) => (
                    <div key={row.label} className="flex items-center justify-between gap-3">
                      <span className="text-foreground-muted">{row.label}</span>
                      <span
                        className={cn(
                          "font-bold shrink-0",
                          row.tone === "verified" && "text-verified",
                          row.tone === "refuted" && "text-refuted",
                          row.tone === "warn" && "text-warn",
                        )}
                      >
                        {row.text}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="mt-6 flex flex-col md:flex-row items-center justify-between gap-4">
                <div className="font-mono text-[10px] text-foreground-faint text-center md:text-left">
                  <div>Serial: {proofCert?.serial || "— pending certificate"}</div>
                  <div
                    className="truncate max-w-[260px] md:max-w-xs"
                    title={proofCert?.certificate_hash}
                  >
                    Hash: {proofCert?.certificate_hash || "— no certificate issued yet"}
                  </div>
                </div>

                <div
                  className={cn(
                    "px-4 py-2 border rounded font-mono text-xs font-bold uppercase tracking-widest",
                    proofTone === "verified" && "border-verified bg-verified/5 text-verified",
                    proofTone === "refuted" && "border-refuted bg-refuted/5 text-refuted",
                    proofTone === "warn" && "border-warn bg-warn/5 text-warn",
                  )}
                >
                  {proofBanner[proofStatus]}
                </div>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
