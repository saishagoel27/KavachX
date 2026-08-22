"use client";

import {
  Activity,
  AlertTriangle,
  FileCheck2,
  GitPullRequest,
  Play,
  ShieldCheck,
  Timer,
} from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";
import {
  Bar,
  BarChart,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { ApiError, endpoints, type Dashboard } from "@/lib/api";
import { formatBytes, formatDuration } from "@/lib/events";
import {
  Chip,
  cn,
  EmptyState,
  ErrorNote,
  Hash,
  LoadingPanel,
  Metric,
  Panel,
  Progress,
} from "@/components/ui";

const LEVEL_COLOUR: Record<string, string> = {
  A: "#3ddc84",
  B: "#00f2ff",
  C: "#f5b642",
  R: "#ff6b5e",
};

const STATUS_TONE: Record<string, "verified" | "accent" | "refuted" | "warn" | "muted"> = {
  COMPLETED: "verified",
  RUNNING: "accent",
  QUEUED: "muted",
  AWAITING_APPROVAL: "warn",
  FAILED: "refuted",
  ABORTED: "muted",
};

export default function DashboardPage() {
  const [data, setData] = useState<Dashboard | null>(null);
  const [error, setError] = useState<ApiError | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const result = await endpoints.dashboard();
        if (!cancelled) {
          setData(result);
          setError(null);
        }
      } catch (exc) {
        if (!cancelled && exc instanceof ApiError) setError(exc);
      }
    };
    void load();
    // Poll rather than stream: the dashboard aggregates across runs, and there is no single
    // run to attach an event stream to.
    const timer = setInterval(load, 6000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  if (error) {
    return <ErrorNote detail={error.message} code={error.code} requestId={error.requestId} />;
  }
  if (!data) return <LoadingPanel label="Loading dashboard" />;

  const levelData = ["A", "B", "C", "R"].map((level) => ({
    level,
    count: data.certificates_by_level[level] ?? 0,
  }));
  const hasCertificates = levelData.some((d) => d.count > 0);

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-headline-md">Dashboard</h1>
          <p className="mt-1 text-small text-foreground-muted">
            Every figure here is aggregated from actual run state.
          </p>
        </div>
        <Link href="/console/runs/new" className="btn-primary">
          <Play className="h-4 w-4" />
          New Security Run
        </Link>
      </header>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Metric
          label="Vulnerabilities found"
          value={data.findings_validated}
          hint={`${data.findings_total} total findings · ${data.findings_refuted} refuted by validation`}
          tone={data.findings_validated > 0 ? "warn" : "default"}
        />
        <Metric
          label="Vulnerabilities fixed"
          value={data.patches_verified}
          hint={`${data.patches_refuted} patches refuted before success`}
          tone={data.patches_verified > 0 ? "verified" : "default"}
        />
        <Metric
          label="Certificates earned"
          value={data.certificates_total}
          hint={
            Object.entries(data.certificates_by_level)
              .map(([level, count]) => `${count}×${level}`)
              .join(" · ") || "none issued yet"
          }
          tone="accent"
        />
        <Metric
          label="Verification success rate"
          value={`${(data.verification_success_rate * 100).toFixed(0)}%`}
          hint="gauntlet-verified patches / patches attempted"
          tone={data.verification_success_rate >= 0.5 ? "verified" : "warn"}
        />
      </div>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Metric
          label="Avg time to protection"
          value={formatDuration(data.avg_time_to_protection_ms)}
          hint="run start → verified reversible shield"
          tone="accent"
        />
        <Metric
          label="Avg time to repair"
          value={formatDuration(data.avg_time_to_repair_ms)}
          hint="run start → gauntlet-verified patch"
          tone="verified"
        />
        <Metric
          label="Open pull requests"
          value={data.open_pull_requests}
          hint="published by the isolated publisher"
        />
        <Metric
          label="Residual risk items"
          value={data.residual_risk_items}
          hint="unproved candidates, limitations, unrepaired findings"
          tone={data.residual_risk_items > 0 ? "warn" : "verified"}
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Panel title="Assurance distribution" className="lg:col-span-1">
          {hasCertificates ? (
            <div className="h-48">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={levelData} margin={{ top: 8, right: 4, bottom: 0, left: -22 }}>
                  <XAxis
                    dataKey="level"
                    stroke="#5e6b6c"
                    tick={{ fontSize: 12, fontFamily: "JetBrains Mono" }}
                    axisLine={{ stroke: "rgba(255,255,255,0.09)" }}
                  />
                  <YAxis
                    stroke="#5e6b6c"
                    allowDecimals={false}
                    tick={{ fontSize: 11, fontFamily: "JetBrains Mono" }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip
                    contentStyle={{
                      background: "#121414",
                      border: "1px solid rgba(255,255,255,0.16)",
                      borderRadius: 6,
                      fontSize: 12,
                      fontFamily: "JetBrains Mono",
                    }}
                  />
                  <Bar dataKey="count" radius={[3, 3, 0, 0]}>
                    {levelData.map((entry) => (
                      <Cell key={entry.level} fill={LEVEL_COLOUR[entry.level]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <EmptyState
              icon={<FileCheck2 className="h-6 w-6" />}
              title="No certificates yet"
              detail="Start a run against the seeded target to produce one."
            />
          )}
          <p className="mt-3 text-[11px] leading-4 text-foreground-faint">
            Levels are <span className="text-foreground-muted">bounded empirical assurance</span>,
            not formal proof. Level R means the patch was refuted and withdrawn.
          </p>
        </Panel>

        <Panel
          title="Recent runs"
          className="lg:col-span-2"
          actions={
            <Link
              href="/console/runs"
              className="font-mono text-mono-label uppercase text-accent hover:underline"
            >
              all runs
            </Link>
          }
          dense
        >
          {data.recent_runs.length === 0 ? (
            <EmptyState
              icon={<Activity className="h-6 w-6" />}
              title="No runs yet"
              detail="The seeded vulnerable target is already attached — start a run to see the full pipeline."
              action={
                <Link href="/console/runs/new" className="btn-secondary mt-2 text-xs">
                  Start the first run
                </Link>
              }
            />
          ) : (
            <div className="divide-y divide-border">
              {data.recent_runs.map((run) => (
                <Link
                  key={run.id}
                  href={`/console/runs/${run.id}`}
                  className="flex items-center gap-4 px-4 py-3 transition-colors hover:bg-surface-high"
                >
                  <span className="font-mono text-sm font-bold text-accent">{run.short_code}</span>
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-small text-foreground">
                      {run.repository_full_name || "—"}
                    </div>
                    <div className="font-mono text-[11px] text-foreground-faint">
                      {run.branch} · {run.analysis_profile} ·{" "}
                      {new Date(run.created_at).toLocaleString()}
                    </div>
                  </div>
                  <div className="hidden w-32 sm:block">
                    <Progress
                      value={run.coverage_percent}
                      tone={run.coverage_percent > 50 ? "verified" : "warn"}
                    />
                    <div className="mt-1 font-mono text-[10px] text-foreground-faint">
                      coverage {run.coverage_percent.toFixed(0)}%
                    </div>
                  </div>
                  <Chip tone={STATUS_TONE[run.status] ?? "muted"}>{run.status}</Chip>
                </Link>
              ))}
            </div>
          )}
        </Panel>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Panel title="Repositories">
          <div className="space-y-3">
            <div className="flex items-baseline justify-between">
              <span className="text-small text-foreground-muted">Attached</span>
              <span className="font-mono text-lg font-bold">{data.repositories}</span>
            </div>
            <div className="flex items-baseline justify-between">
              <span className="text-small text-foreground-muted">Authority verified</span>
              <span
                className={cn(
                  "font-mono text-lg font-bold",
                  data.repositories_verified === data.repositories
                    ? "text-verified"
                    : "text-warn",
                )}
              >
                {data.repositories_verified}
              </span>
            </div>
            <p className="text-[11px] leading-4 text-foreground-faint">
              A run cannot start against a repository without verified authority — either a
              fine-grained token with push access to it, or the seeded local target.
            </p>
          </div>
        </Panel>

        <Panel title="Run activity">
          <div className="space-y-2.5">
            {[
              ["Total", data.runs_total, "muted"],
              ["Active", data.runs_active, "accent"],
              ["Completed", data.runs_completed, "verified"],
            ].map(([label, value, tone]) => (
              <div key={String(label)} className="flex items-baseline justify-between">
                <span className="text-small text-foreground-muted">{label}</span>
                <span
                  className={cn(
                    "font-mono text-lg font-bold",
                    tone === "accent" && "text-accent",
                    tone === "verified" && "text-verified",
                  )}
                >
                  {value}
                </span>
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="Resource totals">
          <div className="space-y-2.5">
            <div className="flex items-baseline justify-between">
              <span className="text-small text-foreground-muted">Model tokens</span>
              <span className="font-mono text-lg font-bold tabular-nums">
                {data.total_tokens.toLocaleString()}
              </span>
            </div>
            <div className="flex items-baseline justify-between">
              <span className="text-small text-foreground-muted">Sandbox executions</span>
              <span className="font-mono text-lg font-bold tabular-nums">
                {data.total_sandbox_executions.toLocaleString()}
              </span>
            </div>
            <div className="flex items-baseline justify-between">
              <span className="text-small text-foreground-muted">Network egress</span>
              <span
                className={cn(
                  "font-mono text-lg font-bold",
                  data.egress_bytes === 0 ? "text-verified" : "text-refuted",
                )}
              >
                {formatBytes(data.egress_bytes)}
              </span>
            </div>
            <p className="text-[11px] leading-4 text-foreground-faint">
              Egress is measured by the in-sandbox guard, not assumed.
            </p>
          </div>
        </Panel>
      </div>

      {data.residual_risk_items > 0 && (
        <div className="flex items-start gap-3 rounded-lg border border-warn/35 bg-warn/[0.04] p-4">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warn" />
          <div className="text-small text-foreground-muted">
            <span className="text-warn">{data.residual_risk_items} residual risk item(s)</span>{" "}
            across issued certificates. Each run's <code className="font-mono">REMAINING.md</code>{" "}
            lists what could not be established — unvalidated hypotheses, refuted patches,
            coverage gaps and decisions needing human review.
          </div>
        </div>
      )}
    </div>
  );
}
