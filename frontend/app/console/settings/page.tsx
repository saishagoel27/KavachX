"use client";

import { Cpu, Lock, Shield, Sliders } from "lucide-react";
import { useEffect, useState } from "react";

import { useMe } from "@/components/shell";
import { Chip, ErrorNote, LoadingPanel, Panel, WarningNote } from "@/components/ui";
import { ApiError, api, endpoints } from "@/lib/api";

interface Policy {
  id: string;
  name: string;
  forbidden_path_globs: string[];
  max_diff_lines: number;
  max_files_changed: number;
  allow_new_dependencies: boolean;
  allow_new_network_calls: boolean;
  allow_new_exec: boolean;
  allow_binary_changes: boolean;
  require_certificate: boolean;
  min_assurance_level: string;
  require_human_approval: boolean;
  enforce_blast_radius: boolean;
}

const TOGGLES: Array<{ key: keyof Policy; label: string; detail: string; invert?: boolean }> = [
  {
    key: "require_certificate",
    label: "Require a PRAMAAN certificate",
    detail: "No patch may be published without one.",
  },
  {
    key: "require_human_approval",
    label: "Require human publish approval",
    detail: "The run parks in AWAITING_APPROVAL until a reviewer with patch:publish approves.",
  },
  {
    key: "enforce_blast_radius",
    label: "Enforce blast radius",
    detail: "Reject a patch that touches a file outside the verified scope.",
  },
  {
    key: "allow_new_dependencies",
    label: "Allow new dependencies",
    detail: "A patch may add a non-standard-library import.",
    invert: true,
  },
  {
    key: "allow_new_network_calls",
    label: "Allow new network calls",
    detail: "A patch may introduce outbound network usage.",
    invert: true,
  },
  {
    key: "allow_new_exec",
    label: "Allow new process execution",
    detail: "A patch may introduce subprocess, eval or exec behaviour.",
    invert: true,
  },
  {
    key: "allow_binary_changes",
    label: "Allow binary modifications",
    detail: "A patch may change a binary artifact.",
    invert: true,
  },
];

export default function SettingsPage() {
  const { me } = useMe();
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [sandbox, setSandbox] = useState<Record<string, any> | null>(null);
  const [llm, setLlm] = useState<Record<string, any> | null>(null);
  const [limits, setLimits] = useState<Record<string, any> | null>(null);
  const [shield, setShield] = useState<Record<string, any> | null>(null);
  const [roles, setRoles] = useState<Record<string, any> | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    void (async () => {
      try {
        const [p, s, l, lim, sh, r] = await Promise.all([
          api.get<Policy>("/api/policy"),
          endpoints.sandboxInfo(),
          endpoints.llmInfo().catch(() => null),
          endpoints.limits(),
          endpoints.shieldInfo(),
          api.get<Record<string, any>>("/api/roles"),
        ]);
        setPolicy(p);
        setSandbox(s);
        setLlm(l);
        setLimits(lim);
        setShield(sh);
        setRoles(r);
      } catch (exc) {
        if (exc instanceof ApiError) setError(exc);
      }
    })();
  }, []);

  const update = async (patch: Partial<Policy>) => {
    setSaving(true);
    setError(null);
    try {
      setPolicy(await api.patch<Policy>("/api/policy", patch));
    } catch (exc) {
      if (exc instanceof ApiError) setError(exc);
    } finally {
      setSaving(false);
    }
  };

  if (!policy || !sandbox || !limits) return <LoadingPanel label="Loading settings" />;

  const canManage = Boolean(me?.permissions.includes("policy:manage"));
  const active = (sandbox.adapters ?? {})[sandbox.configured] ?? {};

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-headline-md">Settings</h1>
        <p className="mt-1 text-small text-foreground-muted">
          Policy is a deterministic gate. Nothing here can be waived by a model.
        </p>
      </header>

      {error && <ErrorNote detail={error.message} code={error.code} requestId={error.requestId} />}

      {!canManage && (
        <WarningNote>
          Your role ({me?.active_role}) does not hold <code className="font-mono">policy:manage</code>,
          so these values are read-only.
        </WarningNote>
      )}

      <Panel title="Publish policy" subtitle={policy.name}>
        <div className="space-y-3">
          {TOGGLES.map((toggle) => {
            const raw = Boolean(policy[toggle.key]);
            const secure = toggle.invert ? !raw : raw;
            return (
              <label
                key={String(toggle.key)}
                className="flex cursor-pointer items-start justify-between gap-4 rounded-md border border-border p-3"
              >
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-small text-foreground">{toggle.label}</span>
                    <Chip tone={secure ? "verified" : "warn"}>{secure ? "SECURE" : "RELAXED"}</Chip>
                  </div>
                  <p className="mt-0.5 text-[11px] leading-4 text-foreground-faint">
                    {toggle.detail}
                  </p>
                </div>
                <input
                  type="checkbox"
                  checked={raw}
                  disabled={!canManage || saving}
                  onChange={(e) => void update({ [toggle.key]: e.target.checked } as Partial<Policy>)}
                  className="mt-1 shrink-0 accent-accent"
                />
              </label>
            );
          })}

          <div className="grid gap-4 sm:grid-cols-3">
            <div>
              <label className="label" htmlFor="max_diff">
                Max diff lines
              </label>
              <input
                id="max_diff"
                type="number"
                min={1}
                value={policy.max_diff_lines}
                disabled={!canManage}
                onChange={(e) => void update({ max_diff_lines: Number(e.target.value) })}
                className="field font-mono"
              />
            </div>
            <div>
              <label className="label" htmlFor="max_files">
                Max files changed
              </label>
              <input
                id="max_files"
                type="number"
                min={1}
                value={policy.max_files_changed}
                disabled={!canManage}
                onChange={(e) => void update({ max_files_changed: Number(e.target.value) })}
                className="field font-mono"
              />
            </div>
            <div>
              <label className="label" htmlFor="min_level">
                Minimum assurance level
              </label>
              <select
                id="min_level"
                value={policy.min_assurance_level}
                disabled={!canManage}
                onChange={(e) => void update({ min_assurance_level: e.target.value })}
                className="field font-mono"
              >
                <option value="A">A</option>
                <option value="B">B</option>
                <option value="C">C</option>
              </select>
            </div>
          </div>

          <div>
            <div className="panel-title mb-1.5">Protected paths (never patchable)</div>
            <div className="flex flex-wrap gap-1.5">
              {policy.forbidden_path_globs.map((glob) => (
                <Chip key={glob} tone="muted">
                  {glob}
                </Chip>
              ))}
            </div>
          </div>
        </div>
      </Panel>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Execution boundary" actions={<Cpu className="h-4 w-4 text-accent" />}>
          <div className="space-y-3">
            {Object.entries(sandbox.adapters ?? {}).map(([name, capability]: [string, any]) => (
              <div
                key={name}
                className={`rounded-md border p-3 ${
                  name === sandbox.configured ? "border-accent/50 bg-accent/[0.05]" : "border-border"
                }`}
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-mono-data text-foreground">{name}</span>
                  {name === sandbox.configured && <Chip tone="accent">ACTIVE</Chip>}
                  <Chip tone={capability.suitable_for_untrusted_code ? "verified" : "warn"}>
                    {capability.suitable_for_untrusted_code ? "UNTRUSTED-SAFE" : "NOT A BOUNDARY"}
                  </Chip>
                </div>
                <div className="mt-1 term text-foreground-faint">
                  {capability.isolation_model ?? capability.error ?? "—"}
                </div>
                {capability.notes && (
                  <p className="mt-1.5 text-[11px] leading-4 text-foreground-faint">
                    {capability.notes}
                  </p>
                )}
                {Array.isArray(capability.missing_prerequisites) &&
                  capability.missing_prerequisites.length > 0 && (
                    <ul className="mt-1.5 space-y-0.5">
                      {capability.missing_prerequisites.map((item: string) => (
                        <li key={item} className="term text-warn">
                          missing: {item}
                        </li>
                      ))}
                    </ul>
                  )}
              </div>
            ))}
          </div>
        </Panel>

        <div className="space-y-4">
          <Panel title="Reasoning provider" actions={<Sliders className="h-4 w-4 text-accent" />}>
            {llm ? (
              <div className="space-y-2">
                <div className="flex flex-wrap items-center gap-2">
                  <Chip tone="muted">{String(llm.provider)}</Chip>
                  <Chip tone={llm.reachable ? "verified" : "warn"}>
                    {llm.reachable ? "REACHABLE" : "UNREACHABLE"}
                  </Chip>
                  {llm.fallback_to_mock && <Chip tone="warn">MOCK FALLBACK ENABLED</Chip>}
                </div>
                <dl className="space-y-1">
                  {Object.entries(llm.models ?? {}).map(([role, model]) => (
                    <div key={role} className="flex items-baseline justify-between gap-3">
                      <dt className="font-mono text-[10px] uppercase text-foreground-faint">
                        {role}
                      </dt>
                      <dd className="truncate term text-foreground-muted">{String(model)}</dd>
                    </div>
                  ))}
                </dl>
                {llm.error && <p className="term text-warn">{String(llm.error)}</p>}
                <p className="text-[11px] leading-4 text-foreground-faint">{String(llm.contract)}</p>
              </div>
            ) : (
              <span className="text-small text-foreground-faint">Provider info unavailable.</span>
            )}
          </Panel>

          <Panel title="Hard limits" actions={<Lock className="h-4 w-4 text-accent" />}>
            <dl className="space-y-1">
              {Object.entries(limits.iteration_limits ?? {}).map(([key, value]) => (
                <div key={key} className="flex items-baseline justify-between">
                  <dt className="font-mono text-[10px] uppercase text-foreground-faint">
                    {key} iterations
                  </dt>
                  <dd className="font-mono text-mono-data text-foreground">{String(value)}</dd>
                </div>
              ))}
              <div className="flex items-baseline justify-between">
                <dt className="font-mono text-[10px] uppercase text-foreground-faint">
                  run max runtime
                </dt>
                <dd className="font-mono text-mono-data text-foreground">
                  {limits.run_max_runtime_seconds}s
                </dd>
              </div>
              <div className="flex items-baseline justify-between">
                <dt className="font-mono text-[10px] uppercase text-foreground-faint">
                  token budget / run
                </dt>
                <dd className="font-mono text-mono-data text-foreground">
                  {Number(limits.token_budget_per_run).toLocaleString()}
                </dd>
              </div>
            </dl>
            <p className="mt-2 text-[11px] leading-4 text-foreground-faint">{String(limits.note)}</p>
          </Panel>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Shield mechanisms" actions={<Shield className="h-4 w-4 text-accent" />}>
          <div className="space-y-2">
            {(shield?.mechanisms ?? []).map((mechanism: any) => (
              <div key={mechanism.mechanism} className="rounded-md border border-border p-3">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-mono-data text-foreground">
                    {mechanism.mechanism}
                  </span>
                  <Chip tone={mechanism.implemented ? "verified" : "muted"}>
                    {mechanism.implemented ? "IMPLEMENTED" : "ARCHITECTURE ONLY"}
                  </Chip>
                </div>
                <p className="mt-1 text-[11px] leading-4 text-foreground-faint">
                  {mechanism.notes}
                </p>
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="Roles and permissions">
          <div className="space-y-2">
            {(roles?.roles ?? []).map((role: any) => (
              <details key={role.role} className="rounded-md border border-border p-3">
                <summary className="cursor-pointer">
                  <span className="font-mono text-mono-data text-foreground">{role.role}</span>
                  {role.permissions.includes("finding:read_pov") && (
                    <Chip tone="refuted" className="ml-2">
                      EXPLOIT ACCESS
                    </Chip>
                  )}
                  {role.permissions.includes("patch:publish") && (
                    <Chip tone="warn" className="ml-1.5">
                      CAN PUBLISH
                    </Chip>
                  )}
                </summary>
                <p className="mt-1.5 text-[11px] leading-4 text-foreground-faint">
                  {role.description}
                </p>
                <div className="mt-2 flex flex-wrap gap-1">
                  {role.permissions.map((permission: string) => (
                    <span
                      key={permission}
                      className="rounded bg-surface-high px-1.5 py-0.5 font-mono text-[10px] text-foreground-subtle"
                    >
                      {permission}
                    </span>
                  ))}
                </div>
              </details>
            ))}
          </div>
        </Panel>
      </div>
    </div>
  );
}
