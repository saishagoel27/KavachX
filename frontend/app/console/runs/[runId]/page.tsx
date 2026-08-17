"use client";

import { AlertTriangle, ArrowLeft, FileCheck2, Octagon, RefreshCw } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useMemo, useState } from "react";

import { useMe } from "@/components/shell";
import {
  ContractPanel,
  DiffViewer,
  EvidenceGraphPanel,
  FindingDetail,
  FindingsTable,
  GauntletPanel,
  LogPanel,
  PipelineTimeline,
  ReasoningTrace,
  ResourceMeter,
  ShieldPanel,
} from "@/components/run-panels";
import {
  Chip,
  cn,
  ErrorNote,
  Hash,
  LevelBadge,
  LoadingPanel,
  Metric,
  Panel,
  Tabs,
} from "@/components/ui";
import {
  ApiError,
  endpoints,
  type Certificate,
  type Clause,
  type Finding,
  type GauntletRun,
  type Patch,
  type RunDetail,
} from "@/lib/api";
import {
  eventsOfType,
  formatBytes,
  latestMetric,
  useRunStream,
} from "@/lib/events";

const STATUS_TONE: Record<string, "verified" | "accent" | "refuted" | "warn" | "muted"> = {
  COMPLETED: "verified",
  RUNNING: "accent",
  QUEUED: "muted",
  AWAITING_APPROVAL: "warn",
  FAILED: "refuted",
  ABORTED: "muted",
};

export default function RunConsolePage() {
  const params = useParams<{ runId: string }>();
  const runId = params.runId;
  const { me } = useMe();

  const [run, setRun] = useState<RunDetail | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [clauses, setClauses] = useState<Clause[]>([]);
  const [patches, setPatches] = useState<Patch[]>([]);
  const [gauntlets, setGauntlets] = useState<GauntletRun[]>([]);
  const [certificates, setCertificates] = useState<Certificate[]>([]);
  const [error, setError] = useState<ApiError | null>(null);
  const [tab, setTab] = useState("live");
  const [selectedFinding, setSelectedFinding] = useState<string | null>(null);
  const [aborting, setAborting] = useState(false);

  const stream = useRunStream(runId, run?.status ?? "");

  const load = useCallback(async () => {
    try {
      const [detail, f, c, p, g, certs] = await Promise.all([
        endpoints.run(runId),
        endpoints.findings(runId).catch(() => []),
        endpoints.clauses(runId).catch(() => []),
        endpoints.patches(runId).catch(() => []),
        endpoints.gauntlet(runId).catch(() => []),
        endpoints.certificates(runId).catch(() => []),
      ]);
      setRun(detail);
      setFindings(f);
      setClauses(c);
      setPatches(p);
      setGauntlets(g);
      setCertificates(certs);
      setError(null);
    } catch (exc) {
      if (exc instanceof ApiError) setError(exc);
    }
  }, [runId]);

  useEffect(() => {
    void load();
  }, [load]);

  // Refetch the derived collections whenever the stream reports a domain change, and once more
  // when the run ends. The event stream carries the transitions; the REST resources carry the
  // full records the panels render.
  const domainSeq = useMemo(
    () =>
      stream.events.filter((e) =>
        ["finding", "diff", "gauntlet", "certificate", "clause", "shield", "artifact"].includes(
          e.event.t,
        ),
      ).length,
    [stream.events],
  );

  useEffect(() => {
    if (domainSeq === 0) return;
    const timer = setTimeout(() => void load(), 600);
    return () => clearTimeout(timer);
  }, [domainSeq, load]);

  useEffect(() => {
    if (stream.ended) void load();
  }, [stream.ended, load]);

  const abort = async () => {
    setAborting(true);
    try {
      await endpoints.abortRun(runId, "aborted from the console");
      await load();
    } catch (exc) {
      if (exc instanceof ApiError) setError(exc);
    } finally {
      setAborting(false);
    }
  };

  if (error && !run) {
    return <ErrorNote detail={error.message} code={error.code} requestId={error.requestId} />;
  }
  if (!run) return <LoadingPanel label="Loading run" />;

  const phaseDetail: Record<string, string> = {};
  for (const event of eventsOfType(stream.events, "phase")) {
    if (event.detail) phaseDetail[event.phase] = event.detail;
  }
  // Merge the server-side phase map with what the live stream has seen, so a page opened
  // mid-run shows completed phases immediately rather than waiting for new events.
  const phases = { ...(run.phase_status as Record<string, any>), ...stream.phases };

  const liveGauntletStages: Record<string, { verdict: string; detail: string }> = {};
  for (const event of eventsOfType(stream.events, "gauntlet")) {
    liveGauntletStages[`${event.finding}:v${event.iter}:${event.stage}`] = {
      verdict: event.verdict,
      detail: event.detail,
    };
  }

  const metric = latestMetric(stream.events);
  const elapsedMs =
    metric?.elapsed_ms ??
    (run.started_at
      ? (run.finished_at ? new Date(run.finished_at).getTime() : Date.now()) -
        new Date(run.started_at).getTime()
      : 0);

  const bestLevel =
    ["A", "B", "C", "R"].find((level) =>
      certificates.some((certificate) => certificate.assurance_level === level),
    ) ?? "—";

  const finding = findings.find((f) => f.handle === selectedFinding);
  const canReadPov = Boolean(me?.permissions.includes("finding:read_pov"));
  const canAbort =
    Boolean(me?.permissions.includes("run:abort")) &&
    ["QUEUED", "RUNNING"].includes(run.status);

  const tabs = [
    { id: "live", label: "Live" },
    { id: "findings", label: "Findings", count: findings.length },
    { id: "contract", label: "SAMHITA", count: clauses.filter((c) => c.status === "SURVIVING").length },
    { id: "patches", label: "Patches", count: patches.length },
    { id: "gauntlet", label: "Gauntlet", count: gauntlets.length },
    { id: "evidence", label: "Evidence" },
    { id: "artifacts", label: "Artifacts", count: run.artifacts.length },
  ];

  return (
    <div className="space-y-5">
      {/* Header */}
      <header className="panel p-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-3">
              <Link
                href="/console/runs"
                className="text-foreground-faint hover:text-accent"
                aria-label="Back to runs"
              >
                <ArrowLeft className="h-4 w-4" />
              </Link>
              <span className="font-mono text-mono-label tracking-[0.2em] text-foreground-subtle">
                KAVACHX
              </span>
              <h1 className="font-mono text-2xl font-bold text-accent">RUN {run.short_code}</h1>
              <Chip tone={STATUS_TONE[stream.status || run.status] ?? "muted"}>
                {stream.status || run.status}
              </Chip>
              {stream.connected && (
                <Chip tone="accent">
                  <span className="mr-1 inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-accent" />
                  STREAMING
                </Chip>
              )}
            </div>

            <dl className="mt-4 grid gap-x-8 gap-y-1.5 sm:grid-cols-2 lg:grid-cols-3">
              {[
                ["Repository", run.repository_full_name || "—"],
                ["Branch", run.branch],
                ["Commit", run.commit_sha ? run.commit_sha.slice(0, 12) : "—"],
                ["Pinned source", run.pinned_source_sha256.slice(0, 16) || "—"],
                ["Profile", `${run.analysis_profile} · ${run.execution_profile}`],
                ["Elapsed", formatClock(elapsedMs)],
              ].map(([label, value]) => (
                <div key={label} className="flex items-baseline gap-2">
                  <dt className="w-28 shrink-0 font-mono text-[10px] uppercase text-foreground-faint">
                    {label}
                  </dt>
                  <dd className="min-w-0 truncate term text-foreground-muted" title={value}>
                    {value}
                  </dd>
                </div>
              ))}
            </dl>
          </div>

          <div className="flex flex-col items-end gap-2">
            <div className="flex items-center gap-2">
              {stream.ended && !["COMPLETED", "AWAITING_APPROVAL"].includes(run.status) && (
                <button onClick={() => void load()} className="btn-ghost px-2 py-1 text-xs">
                  <RefreshCw className="h-3.5 w-3.5" />
                  Refresh
                </button>
              )}
              {canAbort && (
                <button onClick={() => void abort()} disabled={aborting} className="btn-danger text-xs">
                  <Octagon className="h-3.5 w-3.5" />
                  Abort run
                </button>
              )}
            </div>
            <div className="flex items-center gap-2">
              <Chip tone={run.egress_bytes === 0 ? "verified" : "refuted"}>
                EGRESS {formatBytes(run.egress_bytes)}
              </Chip>
            </div>
          </div>
        </div>

        {run.error_message && (
          <div className="mt-4">
            <ErrorNote title={`Run ${run.status.toLowerCase()}`} detail={run.error_message} code={run.error_code} />
          </div>
        )}

        {run.mode === "static_only" && (
          <div className="mt-4 flex items-start gap-3 rounded-md border border-warn/40 bg-warn/[0.05] p-4">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warn" />
            <div className="min-w-0 text-small text-foreground-muted">
              <span className="text-warn">STATIC-ONLY ANALYSIS.</span> Nothing was executed
              {run.static_only_reason ? ` — ${run.static_only_reason}` : ""}. No finding below is
              validated by reproduction, no SAMHITA contract was built, and no patch was attempted.
              Everything here is a <span className="text-foreground">candidate for human review</span>,
              and a count of zero means nothing was proved — not that nothing is wrong.
            </div>
          </div>
        )}

        {run.status === "AWAITING_APPROVAL" && (
          <div className="mt-4 flex items-start gap-3 rounded-md border border-warn/40 bg-warn/[0.05] p-4">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warn" />
            <div className="min-w-0 text-small text-foreground-muted">
              <span className="text-warn">Awaiting human publish approval.</span> The Publisher —
              the only component holding GitHub credentials — has not been invoked. Review the
              verified patch and its certificate, then publish from the Artifacts tab.
            </div>
          </div>
        )}
      </header>

      {/* Metric cards */}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        <Metric label="Findings" value={run.findings_total} hint={`${run.findings_validated} validated`} />
        <Metric
          label="Validated"
          value={run.findings_validated}
          tone={run.findings_validated > 0 ? "warn" : "default"}
          hint="reproduced deterministically"
        />
        <Metric
          label="Patched"
          value={run.patches_verified}
          tone={run.patches_verified > 0 ? "verified" : "default"}
          hint={`${patches.filter((p) => p.status === "REFUTED").length} refuted first`}
        />
        <Metric
          label="Assurance"
          value={bestLevel}
          tone={bestLevel === "A" || bestLevel === "B" ? "verified" : bestLevel === "R" ? "refuted" : "warn"}
          hint={`${certificates.length} certificate(s)`}
        />
        <Metric
          label="Coverage"
          value={`${(metric?.coverage ?? run.coverage_percent).toFixed(0)}%`}
          tone={(metric?.coverage ?? run.coverage_percent) > 50 ? "verified" : "warn"}
          hint="statements executed"
        />
      </div>

      {(run.time_to_protection_ms || run.time_to_repair_ms) && (
        <div className="grid gap-3 sm:grid-cols-2">
          <Metric
            label="Time to protection"
            value={formatClock(run.time_to_protection_ms ?? 0)}
            tone="accent"
            hint="run start → verified reversible shield"
          />
          <Metric
            label="Time to repair"
            value={run.time_to_repair_ms ? formatClock(run.time_to_repair_ms) : "—"}
            tone="verified"
            hint="run start → gauntlet-verified patch"
          />
        </div>
      )}

      <Tabs tabs={tabs} active={tab} onChange={setTab} />

      {tab === "live" && (
        <div className="space-y-4">
          <div className="grid gap-4 xl:grid-cols-2">
            <PipelineTimeline phases={phases} detail={phaseDetail} />
            <ReasoningTrace events={stream.events} />
          </div>
          <ResourceMeter
            run={run}
            metric={metric}
            elapsedMs={elapsedMs}
            connected={stream.connected}
          />
          <div className="grid gap-4 xl:grid-cols-2">
            <ShieldPanel run={run} />
            <LogPanel events={stream.events} />
          </div>
        </div>
      )}

      {tab === "findings" && (
        <div className="space-y-4">
          <FindingsTable
            findings={findings}
            clauses={clauses}
            onSelect={(handle) => setSelectedFinding(handle === selectedFinding ? null : handle)}
            selected={selectedFinding}
          />
          {finding && (
            <FindingDetail
              runId={runId}
              finding={finding}
              clause={clauses.find((c) => c.clause_id === finding.violated_clause_id)}
              canReadPov={canReadPov}
              onClose={() => setSelectedFinding(null)}
            />
          )}
        </div>
      )}

      {tab === "contract" && <ContractPanel clauses={clauses} />}

      {tab === "patches" && (
        <DiffViewer
          patches={patches}
          gauntlets={gauntlets}
          clauses={clauses}
          findings={findings}
        />
      )}

      {tab === "gauntlet" && (
        <GauntletPanel gauntlets={gauntlets} liveStages={liveGauntletStages} />
      )}

      {tab === "evidence" && <EvidenceGraphPanel runId={runId} />}

      {tab === "artifacts" && (
        <ArtifactsTab
          runId={runId}
          run={run}
          certificates={certificates}
          canPublish={Boolean(me?.permissions.includes("patch:publish"))}
          onChange={load}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
function ArtifactsTab({
  runId,
  run,
  certificates,
  canPublish,
  onChange,
}: {
  runId: string;
  run: RunDetail;
  certificates: Certificate[];
  canPublish: boolean;
  onChange: () => Promise<void>;
}) {
  const [preview, setPreview] = useState<{ name: string; content: string } | null>(null);
  const [publishing, setPublishing] = useState<string | null>(null);
  const [result, setResult] = useState<Record<string, any> | null>(null);
  const [publishError, setPublishError] = useState<string>("");

  const open = async (name: string) => {
    try {
      setPreview({ name, content: await endpoints.artifact(runId, name) });
    } catch (exc) {
      setPreview({ name, content: exc instanceof Error ? exc.message : "Could not load." });
    }
  };

  const publish = async (certificateId: string) => {
    setPublishing(certificateId);
    setPublishError("");
    try {
      const outcome = await endpoints.publish(runId, certificateId, "approved from the console");
      setResult(outcome);
      await onChange();
    } catch (exc) {
      setPublishError(exc instanceof ApiError ? `${exc.code}: ${exc.message}` : "Publish failed.");
    } finally {
      setPublishing(null);
    }
  };

  return (
    <div className="space-y-4">
      <Panel title="Certificates" bodyClassName="p-0">
        {certificates.length === 0 ? (
          <div className="p-4 text-small text-foreground-faint">No certificates issued yet.</div>
        ) : (
          <div className="divide-y divide-border">
            {certificates.map((certificate) => (
              <div key={certificate.id} className="flex flex-wrap items-center gap-4 px-4 py-3">
                <LevelBadge level={certificate.assurance_level} size="sm" />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-bold text-accent">
                      {certificate.finding_handle}
                    </span>
                    <span className="term text-foreground-muted">{certificate.serial}</span>
                  </div>
                  <div className="term text-foreground-faint">
                    <Hash value={certificate.certificate_hash} length={32} /> ·{" "}
                    {certificate.evidence_node_count} nodes / {certificate.evidence_edge_count} edges
                  </div>
                </div>
                <Link
                  href={`/console/certificates/${certificate.id}`}
                  className="btn-secondary px-3 py-1 text-xs"
                >
                  <FileCheck2 className="h-3.5 w-3.5" />
                  View certificate
                </Link>
                {certificate.assurance_level === "R" ? (
                  <Chip tone="refuted">NEVER PUBLISHED</Chip>
                ) : canPublish ? (
                  <button
                    onClick={() => void publish(certificate.id)}
                    disabled={publishing === certificate.id}
                    className="btn-primary px-3 py-1 text-xs"
                  >
                    {publishing === certificate.id ? "Publishing…" : "Approve & publish"}
                  </button>
                ) : (
                  <Chip tone="warn">NEEDS patch:publish</Chip>
                )}
              </div>
            ))}
          </div>
        )}
      </Panel>

      {publishError && <ErrorNote title="Publish blocked" detail={publishError} />}

      {result && (
        <Panel title="Publish result">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <Chip tone={result.ok ? "verified" : "refuted"}>{result.ok ? "PUBLISHED" : "BLOCKED"}</Chip>
              {result.dry_run && <Chip tone="warn">DRY RUN — nothing sent to GitHub</Chip>}
              {result.branch && <span className="term text-foreground-muted">{result.branch}</span>}
            </div>
            {result.pull_request_url && (
              <a
                href={result.pull_request_url}
                target="_blank"
                rel="noreferrer"
                className="term text-accent hover:underline"
              >
                {result.pull_request_url}
              </a>
            )}
            {result.blocked_reason && (
              <div className="term text-refuted">{result.blocked_reason}</div>
            )}
            {result.artifacts_written?.length > 0 && (
              <div>
                <div className="panel-title mb-1">Files in the pull request</div>
                {result.artifacts_written.map((file: string) => (
                  <div key={file} className="term text-foreground-muted">
                    {file}
                  </div>
                ))}
              </div>
            )}
            {result.dry_run_payload?.guarantees && (
              <details>
                <summary className="cursor-pointer font-mono text-mono-label uppercase text-foreground-subtle">
                  publisher guarantees
                </summary>
                <pre className="mt-1.5 max-h-56 overflow-auto term text-foreground-muted">
                  {JSON.stringify(result.dry_run_payload.guarantees, null, 2)}
                </pre>
              </details>
            )}
          </div>
        </Panel>
      )}

      <Panel title="Run artifacts" bodyClassName="p-0">
        {run.artifacts.length === 0 ? (
          <div className="p-4 text-small text-foreground-faint">No artifacts yet.</div>
        ) : (
          <div className="divide-y divide-border">
            {run.artifacts.map((artifact) => (
              <button
                key={artifact.id}
                onClick={() => void open(artifact.name)}
                className="flex w-full items-center gap-4 px-4 py-2.5 text-left hover:bg-surface-high"
              >
                <Chip tone="muted">{artifact.kind}</Chip>
                <span className="min-w-0 flex-1 truncate term text-foreground">{artifact.name}</span>
                <span className="term text-foreground-faint">{artifact.size_bytes} B</span>
                <Hash value={artifact.content_hash} length={12} />
              </button>
            ))}
          </div>
        )}
      </Panel>

      {preview && (
        <Panel
          title={preview.name}
          actions={
            <button onClick={() => setPreview(null)} className="btn-ghost px-2 py-1 text-xs">
              Close
            </button>
          }
          bodyClassName="p-0"
        >
          <pre className="max-h-[32rem] overflow-auto whitespace-pre-wrap p-4 term text-foreground-muted">
            {preview.content}
          </pre>
        </Panel>
      )}
    </div>
  );
}

function formatClock(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000));
  const minutes = Math.floor(total / 60);
  const seconds = total % 60;
  return `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
}
