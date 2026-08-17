"use client";

import { FileCheck2 } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";

import { ApiError, endpoints, type Certificate, type Run } from "@/lib/api";
import {
  Chip,
  EmptyState,
  ErrorNote,
  Hash,
  LevelBadge,
  LoadingPanel,
  Panel,
} from "@/components/ui";

export default function CertificatesPage() {
  const [rows, setRows] = useState<Array<Certificate & { run: Run }> | null>(null);
  const [error, setError] = useState<ApiError | null>(null);

  useEffect(() => {
    void (async () => {
      try {
        const runs = await endpoints.runs(100);
        const collected: Array<Certificate & { run: Run }> = [];
        for (const run of runs) {
          const certificates = await endpoints.certificates(run.id).catch(() => []);
          for (const certificate of certificates) collected.push({ ...certificate, run });
        }
        setRows(collected);
      } catch (exc) {
        if (exc instanceof ApiError) setError(exc);
        setRows([]);
      }
    })();
  }, []);

  if (error) {
    return <ErrorNote detail={error.message} code={error.code} requestId={error.requestId} />;
  }
  if (rows === null) return <LoadingPanel label="Loading certificates" />;

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-headline-md">Certificates</h1>
        <p className="mt-1 text-small text-foreground-muted">
          PRAMAAN certificates of bounded empirical assurance. Level R records a refuted patch and
          can never authorise a pull request.
        </p>
      </header>

      <Panel bodyClassName="p-0">
        {rows.length === 0 ? (
          <EmptyState
            icon={<FileCheck2 className="h-6 w-6" />}
            title="No certificates issued"
            detail="A certificate is issued when a finding reaches attestation — including when its patch was refuted."
          />
        ) : (
          <div className="divide-y divide-border">
            {rows.map((row) => (
              <Link
                key={row.id}
                href={`/console/certificates/${row.id}`}
                className="flex flex-wrap items-center gap-4 px-4 py-3 transition-colors hover:bg-surface-high"
              >
                <LevelBadge level={row.assurance_level} size="sm" />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-sm font-bold text-accent">
                      {row.run.short_code} / {row.finding_handle}
                    </span>
                    <span className="term text-foreground-muted">{row.serial}</span>
                    <Chip tone="muted">{row.run.repository_full_name}</Chip>
                  </div>
                  <div className="mt-0.5 term text-foreground-faint">
                    <Hash value={row.certificate_hash} length={28} /> · {row.evidence_node_count}{" "}
                    evidence nodes ·{" "}
                    {row.issued_at ? new Date(row.issued_at).toLocaleString() : "—"}
                  </div>
                </div>
                {row.limitations.length > 0 && (
                  <Chip tone="warn">{row.limitations.length} limitation(s)</Chip>
                )}
              </Link>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}
