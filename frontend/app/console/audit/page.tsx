"use client";

import { ScrollText, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";

import { ApiError, endpoints, type AuditEvent } from "@/lib/api";
import { Chip, EmptyState, ErrorNote, Hash, LoadingPanel, Panel } from "@/components/ui";

/** Actions worth surfacing louder: credential-adjacent, publish-adjacent, or destructive. */
const HIGH_SIGNAL = new Set([
  "finding.exploit_accessed",
  "publisher.pr_published",
  "publisher.blocked",
  "policy.changed",
  "run.aborted",
  "repository.authority_rejected",
  "member.role_changed",
]);

export default function AuditPage() {
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [head, setHead] = useState("");
  const [chain, setChain] = useState<Record<string, any> | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [selected, setSelected] = useState<AuditEvent | null>(null);

  useEffect(() => {
    void (async () => {
      try {
        const [page, verified] = await Promise.all([
          endpoints.audit(200, 0),
          endpoints.verifyAudit().catch(() => null),
        ]);
        setEvents(page.items);
        setHead(page.chain_head);
        setChain(verified);
      } catch (exc) {
        if (exc instanceof ApiError) setError(exc);
        setEvents([]);
      }
    })();
  }, []);

  if (error) {
    return <ErrorNote detail={error.message} code={error.code} requestId={error.requestId} />;
  }
  if (events === null) return <LoadingPanel label="Loading audit log" />;

  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-headline-md">Audit log</h1>
          <p className="mt-1 text-small text-foreground-muted">
            Append-only and hash-chained per organisation. Deletion, reordering and in-place edits
            are all detectable.
          </p>
        </div>
        {chain && (
          <div className="flex items-center gap-2">
            <Chip
              tone={chain.valid ? "verified" : "refuted"}
              icon={<ShieldCheck className="h-3 w-3" />}
            >
              CHAIN {chain.valid ? "VALID" : "BROKEN"}
            </Chip>
            <span className="term text-foreground-faint">{chain.checked} records verified</span>
          </div>
        )}
      </header>

      {chain && !chain.valid && (
        <ErrorNote
          title="Audit chain integrity failure"
          detail={`${chain.reason} (at sequence ${chain.broken_at_seq})`}
          code="AUDIT_CHAIN_BROKEN"
        />
      )}

      <Panel subtitle={head ? `head ${head.slice(0, 16)}` : undefined} bodyClassName="p-0">
        {events.length === 0 ? (
          <EmptyState icon={<ScrollText className="h-6 w-6" />} title="No audit events" />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-border">
                  {["Seq", "When", "Actor", "Action", "Subject", "Hash"].map((column) => (
                    <th
                      key={column}
                      className="whitespace-nowrap px-4 py-2 font-mono text-mono-label uppercase text-foreground-subtle"
                    >
                      {column}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {events.map((event) => (
                  <tr
                    key={event.id}
                    onClick={() => setSelected(event.id === selected?.id ? null : event)}
                    className={`cursor-pointer hover:bg-surface-high ${
                      HIGH_SIGNAL.has(event.action) ? "bg-warn/[0.04]" : ""
                    }`}
                  >
                    <td className="px-4 py-2 term tabular-nums text-foreground-faint">
                      {event.seq}
                    </td>
                    <td className="whitespace-nowrap px-4 py-2 term text-foreground-faint">
                      {new Date(event.created_at).toLocaleString()}
                    </td>
                    <td
                      className="max-w-[14rem] truncate px-4 py-2 term text-foreground-muted"
                      title={event.actor_label}
                    >
                      {event.actor_label}
                    </td>
                    <td className="px-4 py-2">
                      <Chip tone={HIGH_SIGNAL.has(event.action) ? "warn" : "muted"}>
                        {event.action}
                      </Chip>
                    </td>
                    <td
                      className="max-w-[16rem] truncate px-4 py-2 term text-foreground-muted"
                      title={`${event.subject_type} ${event.subject_id}`}
                    >
                      {event.subject_type} {event.subject_id}
                    </td>
                    <td className="px-4 py-2">
                      <Hash value={event.hash} length={12} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {selected && (
        <Panel
          title={`Record ${selected.seq} — ${selected.action}`}
          actions={
            <button onClick={() => setSelected(null)} className="btn-ghost px-2 py-1 text-xs">
              Close
            </button>
          }
        >
          <div className="grid gap-4 lg:grid-cols-2">
            <dl className="space-y-1.5">
              {[
                ["actor", selected.actor_label],
                ["subject", `${selected.subject_type} ${selected.subject_id}`],
                ["request id", selected.request_id || "—"],
                ["source ip", selected.source_ip || "—"],
                ["evidence hash", selected.evidence_hash],
                ["previous hash", selected.previous_hash],
                ["hash", selected.hash],
              ].map(([label, value]) => (
                <div key={label} className="flex items-baseline justify-between gap-4">
                  <dt className="shrink-0 font-mono text-[10px] uppercase text-foreground-faint">
                    {label}
                  </dt>
                  <dd className="min-w-0 truncate term text-foreground-muted" title={String(value)}>
                    {String(value)}
                  </dd>
                </div>
              ))}
            </dl>
            <div>
              <div className="panel-title mb-1.5">detail</div>
              <pre className="max-h-64 overflow-auto rounded-md border border-border bg-surface-lowest p-3 term text-foreground-muted">
                {JSON.stringify(selected.detail, null, 2)}
              </pre>
            </div>
          </div>
        </Panel>
      )}
    </div>
  );
}
