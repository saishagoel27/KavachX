"use client";

import { Activity, Play } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";

import { ApiError, endpoints, type Run } from "@/lib/api";
import { Chip, EmptyState, ErrorNote, LoadingPanel, Panel, Progress } from "@/components/ui";

const STATUS_TONE: Record<string, "verified" | "accent" | "refuted" | "warn" | "muted"> = {
  COMPLETED: "verified",
  RUNNING: "accent",
  QUEUED: "muted",
  AWAITING_APPROVAL: "warn",
  FAILED: "refuted",
  ABORTED: "muted",
};

export default function RunsPage() {
  const [runs, setRuns] = useState<Run[] | null>(null);
  const [error, setError] = useState<ApiError | null>(null);

  useEffect(() => {
    const load = async () => {
      try {
        setRuns(await endpoints.runs(100));
      } catch (exc) {
        if (exc instanceof ApiError) setError(exc);
        setRuns([]);
      }
    };
    void load();
    const timer = setInterval(load, 6000);
    return () => clearInterval(timer);
  }, []);

  if (error) return <ErrorNote detail={error.message} code={error.code} requestId={error.requestId} />;
  if (runs === null) return <LoadingPanel label="Loading runs" />;

  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-headline-md">Runs</h1>
          <p className="mt-1 text-small text-foreground-muted">{runs.length} run(s) in this organisation.</p>
        </div>
        <Link href="/console/runs/new" className="btn-primary">
          <Play className="h-4 w-4" /> New Security Run
        </Link>
      </header>

      <Panel bodyClassName="p-0">
        {runs.length === 0 ? (
          <EmptyState
            icon={<Activity className="h-6 w-6" />}
            title="No runs yet"
            detail="The seeded vulnerable target is already attached and authority-verified."
            action={
              <Link href="/console/runs/new" className="btn-secondary mt-2 text-xs">
                Start the first run
              </Link>
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-border">
                  {["Run", "Repository", "Branch", "Profile", "Tokens", "Coverage", "Status", "Started"].map((head) => (
                    <th key={head} className="whitespace-nowrap px-4 py-2 font-mono text-mono-label uppercase text-foreground-subtle">
                      {head}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {runs.map((run) => (
                  <tr key={run.id} className="hover:bg-surface-high">
                    <td className="px-4 py-2.5">
                      <Link href={`/console/runs/${run.id}`} className="font-mono text-sm font-bold text-accent hover:underline">
                        {run.short_code}
                      </Link>
                    </td>
                    <td className="max-w-[16rem] truncate px-4 py-2.5 text-small text-foreground" title={run.repository_full_name}>
                      {run.repository_full_name || "—"}
                    </td>
                    <td className="px-4 py-2.5 term text-foreground-muted">{run.branch}</td>
                    <td className="px-4 py-2.5 term text-foreground-faint">
                      {run.analysis_profile} / {run.execution_profile}
                    </td>
                    <td className="px-4 py-2.5 term tabular-nums text-foreground-muted">
                      {run.tokens_used > 0 ? run.tokens_used.toLocaleString() : "—"}
                    </td>
                    <td className="w-28 px-4 py-2.5">
                      {run.mode === "static_only" ? (
                        // 0% coverage is the correct number here, but a progress bar reads as a
                        // measurement that came out low rather than one that was never taken.
                        <div className="font-mono text-[10px] text-warn" title={run.static_only_reason}>
                          NOT MEASURED
                        </div>
                      ) : (
                        <>
                          <Progress value={run.coverage_percent} tone={run.coverage_percent > 50 ? "verified" : "warn"} />
                          <div className="mt-1 font-mono text-[10px] text-foreground-faint">
                            {run.coverage_percent.toFixed(0)}%
                          </div>
                        </>
                      )}
                    </td>
                    <td className="px-4 py-2.5">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <Chip tone={STATUS_TONE[run.status] ?? "muted"}>{run.status}</Chip>
                        {run.mode === "static_only" && (
                          <Chip tone="warn" title={run.static_only_reason}>
                            STATIC ONLY
                          </Chip>
                        )}
                      </div>
                    </td>
                    <td className="whitespace-nowrap px-4 py-2.5 term text-foreground-faint">
                      {run.started_at ? new Date(run.started_at).toLocaleString() : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
