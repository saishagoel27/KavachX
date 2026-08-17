"use client";

import { ArrowLeft, BadgeCheck, Download, Printer, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";

import { EvidenceGraphPanel } from "@/components/run-panels";
import {
  Chip,
  cn,
  ErrorNote,
  Hash,
  LevelBadge,
  LoadingPanel,
  Panel,
  VerdictChip,
} from "@/components/ui";
import { API_BASE, ApiError, endpoints, type Certificate } from "@/lib/api";
import { GAUNTLET_LABELS } from "@/lib/events";

export default function CertificatePage() {
  const params = useParams<{ certificateId: string }>();
  const id = params.certificateId;

  const [certificate, setCertificate] = useState<Certificate | null>(null);
  const [verification, setVerification] = useState<Record<string, any> | null>(null);
  const [error, setError] = useState<ApiError | null>(null);

  useEffect(() => {
    void (async () => {
      try {
        const [detail, verified] = await Promise.all([
          endpoints.certificate(id),
          endpoints.verifyCertificate(id).catch(() => null),
        ]);
        setCertificate(detail);
        setVerification(verified);
      } catch (exc) {
        if (exc instanceof ApiError) setError(exc);
      }
    })();
  }, [id]);

  if (error) return <ErrorNote detail={error.message} code={error.code} requestId={error.requestId} />;
  if (!certificate) return <LoadingPanel label="Loading certificate" />;

  const doc = certificate.document ?? {};
  const assurance = doc.assurance ?? {};
  const finding = doc.finding ?? {};
  const target = doc.target ?? {};
  const patch = doc.patch ?? null;
  const shield = doc.shield ?? null;
  const clause = doc.violated_clause ?? null;
  const blast = doc.blast_radius ?? {};
  const stages: Record<string, any> = doc.verification?.stages ?? {};
  const samhita = doc.samhita ?? {};
  const environment = doc.execution_environment ?? {};
  const provider = doc.reasoning_provider ?? {};

  const level = certificate.assurance_level;
  const refuted = level === "R";

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3 print:hidden">
        <Link href={`/console/runs/${certificate.run_id}`} className="btn-ghost px-2 py-1 text-xs">
          <ArrowLeft className="h-3.5 w-3.5" />
          Back to run
        </Link>
        <div className="flex items-center gap-2">
          <a
            href={`${API_BASE}/api/certificates/${id}/download`}
            className="btn-secondary text-xs"
            target="_blank"
            rel="noreferrer"
          >
            <Download className="h-3.5 w-3.5" />
            Download certificate.json
          </a>
          <button onClick={() => window.print()} className="btn-secondary text-xs">
            <Printer className="h-3.5 w-3.5" />
            View printable certificate
          </button>
        </div>
      </div>

      {/* Certificate header */}
      <section
        className={cn(
          "relative overflow-hidden rounded-lg border-2 p-8",
          refuted ? "border-refuted/50 bg-refuted/[0.04]" : "border-accent/40 bg-surface",
        )}
      >
        <div className="grid-bg pointer-events-none absolute inset-0 opacity-40" aria-hidden />
        <div
          className={cn(
            "pointer-events-none absolute right-0 top-0 h-64 w-64 translate-x-1/4 -translate-y-1/4 rounded-full blur-3xl",
            refuted ? "bg-refuted/10" : "bg-accent/10",
          )}
          aria-hidden
        />

        <div className="relative flex flex-wrap items-start justify-between gap-8">
          <div className="min-w-0">
            <div className="font-mono text-mono-label tracking-[0.3em] text-accent">PRAMAAN</div>
            <h1 className="mt-2 text-headline-md sm:text-headline-lg">
              Certificate of Bounded Empirical Assurance
            </h1>
            <p className="mt-3 max-w-xl text-small leading-relaxed text-foreground-muted">
              {assurance.description ?? ""}
            </p>
            <div className="mt-4 flex flex-wrap items-center gap-2">
              <Chip tone="muted">{certificate.serial}</Chip>
              <Chip tone="muted">
                issued {certificate.issued_at ? new Date(certificate.issued_at).toLocaleString() : "—"}
              </Chip>
              {verification && (
                <Chip tone={verification.valid ? "verified" : "refuted"} icon={<BadgeCheck className="h-3 w-3" />}>
                  SIGNATURE {verification.valid ? "VALID" : "INVALID"}
                </Chip>
              )}
            </div>
          </div>

          <div className="flex flex-col items-center gap-3">
            <LevelBadge level={level} size="lg" />
            <div className="text-center">
              <div className="font-mono text-mono-label uppercase text-foreground-subtle">
                Level {level}
              </div>
              <div className="max-w-[14rem] text-[11px] leading-4 text-foreground-faint">
                {assurance.label ?? ""}
              </div>
            </div>
          </div>
        </div>

        <div className="relative mt-6 rounded-md border border-border bg-surface-lowest p-3">
          <div className="font-mono text-[10px] uppercase text-foreground-faint">
            certificate hash · {certificate.signature_algorithm}
          </div>
          <div className="mt-1 break-all font-mono text-mono-data text-foreground-muted">
            {certificate.certificate_hash}
          </div>
        </div>
      </section>

      {refuted && (
        <div className="rounded-lg border-2 border-refuted/50 bg-refuted/[0.05] p-5 shadow-glow-refuted">
          <div className="mb-2 flex items-center gap-2 font-mono text-mono-label uppercase text-refuted">
            <ShieldAlert className="h-4 w-4" />
            Level R — this finding is not repaired
          </div>
          <p className="text-small leading-relaxed text-foreground-muted">
            The patch was refuted by execution and withdrawn. This certificate exists to record
            that honestly, with the refuting evidence attached. It can never authorise a pull
            request.
          </p>
        </div>
      )}

      {/* Core facts */}
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Run and target">
          <dl className="space-y-2">
            {[
              ["Run", `${doc.run?.short_code ?? "—"} (${doc.run?.id ?? ""})`],
              ["Repository", target.repository ?? "—"],
              ["Provider", target.provider ?? "—"],
              ["Branch", target.branch ?? "—"],
              ["Commit", target.commit_sha ?? "—"],
              ["Pinned source", target.pinned_source_sha256 ?? "—"],
              ["Authority verified", target.authority_verified_at ?? "—"],
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
        </Panel>

        <Panel title="Finding">
          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-lg font-bold text-accent">{finding.handle}</span>
              <Chip tone="refuted">{finding.severity}</Chip>
              {finding.cwe && <Chip tone="muted">{finding.cwe}</Chip>}
              <Chip tone={finding.reachable ? "warn" : "muted"}>
                {finding.reachable ? "REACHABLE" : "UNREACHED"}
              </Chip>
            </div>
            <p className="text-small text-foreground">{finding.title}</p>
            <div>
              <div className="panel-title mb-1">Root cause</div>
              <div className="term text-accent">{finding.root_cause?.location ?? "—"}</div>
              <p className="mt-1 text-small text-foreground-muted">
                {finding.root_cause?.summary ?? "—"}
              </p>
              <Chip tone={finding.root_cause?.verified ? "verified" : "warn"} className="mt-1.5">
                {finding.root_cause?.verified ? "VERIFIED ON EXECUTION PATH" : "LOCATION UNVERIFIED"}
              </Chip>
            </div>
            <div>
              <div className="panel-title mb-1">Reproduction</div>
              <div className="term text-foreground-muted">
                {finding.reproduction?.count ?? 0}× reproduced · signal{" "}
                {finding.reproduction?.sanitizer_signal || "—"} · exit{" "}
                {String(finding.reproduction?.exit_code ?? "—")}
              </div>
              <p className="mt-1.5 text-[11px] leading-4 text-foreground-faint">
                {finding.reproduction?.pov_access_note ?? ""}
              </p>
            </div>
          </div>
        </Panel>
      </div>

      {/* Verification */}
      <Panel title="Verification — Refutation Gauntlet" bodyClassName="p-0">
        <div className="grid gap-px bg-border sm:grid-cols-2 lg:grid-cols-4">
          {["exploit_mutation", "sibling_hunt", "differential_replay", "samhita_recheck"].map(
            (stage) => {
              const outcome = stages[stage];
              return (
                <div
                  key={stage}
                  className={cn(
                    "bg-surface p-4",
                    outcome?.verdict === "fail" && "bg-refuted/[0.07]",
                  )}
                >
                  <div className="mb-2 flex items-center justify-between gap-2">
                    <span className="font-mono text-mono-label uppercase text-foreground-subtle">
                      {GAUNTLET_LABELS[stage]}
                    </span>
                    {outcome ? <VerdictChip verdict={outcome.verdict} /> : <Chip tone="muted">NOT RUN</Chip>}
                  </div>
                  <p className="text-[11px] leading-4 text-foreground-muted">
                    {outcome?.detail ?? "This stage did not run for this certificate."}
                  </p>
                  {outcome?.cases_total > 0 && (
                    <div className="mt-1.5 font-mono text-[10px] text-foreground-faint">
                      {outcome.cases_passed}/{outcome.cases_total} cases
                    </div>
                  )}
                </div>
              );
            },
          )}
        </div>
      </Panel>

      <div className="grid gap-4 lg:grid-cols-3">
        {clause && (
          <Panel title="Violated SAMHITA clause">
            <div className="font-mono text-mono-data text-accent">{clause.clause_id}</div>
            <p className="mt-1 text-small text-foreground">{clause.description}</p>
            <pre className="mt-2 overflow-x-auto term text-verified">{clause.predicate}</pre>
            <div className="mt-2 font-mono text-[10px] text-foreground-faint">
              scope {clause.scope} · observed {clause.observation_count}× · survived{" "}
              {clause.holdout_pass_count} held-out traces
            </div>
          </Panel>
        )}

        {shield && (
          <Panel title="Shield">
            <div className="flex flex-wrap items-center gap-2">
              <Chip tone="muted">{shield.mechanism}</Chip>
              <Chip tone={shield.verified_blocked ? "verified" : "refuted"}>
                EXPLOIT {shield.verified_blocked ? "BLOCKED" : "NOT BLOCKED"}
              </Chip>
              <Chip tone={shield.verified_benign ? "verified" : "refuted"}>
                BENIGN {shield.benign_pass_count}/{shield.benign_total}
              </Chip>
              <Chip tone={shield.deployed ? "verified" : "warn"}>
                {shield.deployed ? "DEPLOYED" : "WITHDRAWN"}
              </Chip>
            </div>
            <pre className="mt-2 overflow-x-auto term text-foreground-muted">{shield.rule}</pre>
            <div className="mt-1.5 term text-foreground-faint">revert: {shield.revert_command}</div>
          </Panel>
        )}

        {patch && (
          <Panel title="Patch">
            <div className="flex flex-wrap items-center gap-2">
              <Chip tone="accent">ITERATION {patch.iteration}</Chip>
              <Chip tone={patch.status === "VERIFIED" || patch.status === "PUBLISHED" ? "verified" : "warn"}>
                {patch.status}
              </Chip>
              <Chip tone="muted">RISK {String(patch.risk).toUpperCase()}</Chip>
            </div>
            <div className="mt-2 term text-foreground-muted">
              +{patch.lines_added} / −{patch.lines_removed} · <Hash value={patch.diff_hash} length={16} />
            </div>
            <div className="mt-1.5 space-y-0.5">
              {(patch.files ?? []).map((file: string) => (
                <div key={file} className="term text-foreground-faint">
                  {file}
                </div>
              ))}
            </div>
            <p className="mt-2 text-small text-foreground-muted">{patch.expected_effect}</p>
          </Panel>
        )}
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Blast radius">
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
        </Panel>

        <Panel title="Assurance rationale">
          <ul className="space-y-1.5">
            {(assurance.rationale ?? []).map((item: string, index: number) => (
              <li key={index} className="flex gap-2 text-small text-foreground-muted">
                <span className="text-verified">·</span>
                {item}
              </li>
            ))}
          </ul>
          {(assurance.limitations ?? []).length > 0 && (
            <div className="mt-4">
              <div className="panel-title mb-1.5 text-warn">Limitations</div>
              <ul className="space-y-1.5">
                {assurance.limitations.map((item: string, index: number) => (
                  <li key={index} className="flex gap-2 text-small text-foreground-muted">
                    <span className="text-warn">·</span>
                    {item}
                  </li>
                ))}
              </ul>
            </div>
          )}
          <p className="mt-4 border-t border-border pt-3 text-[11px] leading-4 text-foreground-faint">
            This is <span className="text-foreground-muted">bounded empirical assurance</span>, not
            a formal proof. It states what was executed and observed, bounded by the coverage
            achieved, the corpus available, and the mutations attempted.
          </p>
        </Panel>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Panel title="SAMHITA">
          <dl className="space-y-1.5">
            {[
              ["Proposed", samhita.clauses_proposed],
              ["Surviving", samhita.clauses_surviving],
              ["Falsified", samhita.clauses_falsified],
              ["Uncompilable", samhita.clauses_uncompilable],
              ["Iterations", samhita.iterations],
              ["Observation cases", samhita.observation_cases],
              ["Held-out cases", samhita.holdout_cases],
            ].map(([label, value]) => (
              <div key={String(label)} className="flex items-baseline justify-between">
                <dt className="font-mono text-[10px] uppercase text-foreground-faint">{label}</dt>
                <dd className="font-mono text-mono-data text-foreground-muted">
                  {String(value ?? "—")}
                </dd>
              </div>
            ))}
          </dl>
          <p className="mt-2 text-[11px] leading-4 text-foreground-faint">{samhita.note ?? ""}</p>
        </Panel>

        <Panel title="Execution environment">
          <div className="flex flex-wrap gap-1.5">
            <Chip tone="muted">{environment.sandbox?.adapter ?? "unknown"}</Chip>
            <Chip tone={environment.network_enforced ? "verified" : "warn"}>
              NETWORK {environment.network_enforced ? "ENFORCED" : "NOT ENFORCED"}
            </Chip>
            <Chip tone={environment.egress_bytes === 0 ? "verified" : "refuted"}>
              EGRESS {environment.egress_bytes ?? 0} B
            </Chip>
            <Chip tone={environment.suitable_for_untrusted_code ? "verified" : "warn"}>
              {environment.suitable_for_untrusted_code ? "UNTRUSTED-SAFE" : "DEV ADAPTER"}
            </Chip>
          </div>
          <div className="mt-2 term text-foreground-faint">
            {environment.sandbox?.executions ?? 0} executions ·{" "}
            {environment.sandbox?.cpu_seconds ?? 0}s CPU
          </div>
          {environment.sandbox?.capabilities?.notes && (
            <p className="mt-2 text-[11px] leading-4 text-warn">
              {environment.sandbox.capabilities.notes}
            </p>
          )}
        </Panel>

        <Panel title="Reasoning provider">
          <dl className="space-y-1.5">
            {[
              ["Provider", provider.provider],
              ["Configured", provider.configured_provider],
              ["Fell back to mock", String(provider.fell_back_to_mock ?? false)],
              ["Model calls", provider.calls],
              ["Tokens", provider.tokens],
            ].map(([label, value]) => (
              <div key={String(label)} className="flex items-baseline justify-between">
                <dt className="font-mono text-[10px] uppercase text-foreground-faint">{label}</dt>
                <dd className="font-mono text-mono-data text-foreground-muted">
                  {String(value ?? "—")}
                </dd>
              </div>
            ))}
          </dl>
          <p className="mt-2 text-[11px] leading-4 text-foreground-faint">{provider.note ?? ""}</p>
        </Panel>
      </div>

      <div className="print:hidden">
        <EvidenceGraphPanel runId={certificate.run_id} />
      </div>

      <Panel title="Signature verification">
        {verification ? (
          <div className="space-y-1.5">
            <div className="flex flex-wrap items-center gap-2">
              <Chip tone={verification.hash_matches ? "verified" : "refuted"}>
                HASH {verification.hash_matches ? "MATCHES" : "MISMATCH"}
              </Chip>
              <Chip tone={verification.signature_matches ? "verified" : "refuted"}>
                HMAC {verification.signature_matches ? "MATCHES" : "MISMATCH"}
              </Chip>
            </div>
            <div className="term text-foreground-faint">
              recomputed {String(verification.recomputed_hash ?? "").slice(0, 32)}… over{" "}
              {verification.canonical_length} canonical bytes
            </div>
            <p className="text-[11px] leading-4 text-foreground-faint">
              {doc.signature?.notes ?? ""}
            </p>
          </div>
        ) : (
          <span className="text-small text-foreground-faint">Verification unavailable.</span>
        )}
      </Panel>
    </div>
  );
}
