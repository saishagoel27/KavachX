/**
 * Primitive UI components.
 *
 * Hand-written rather than pulled from a component library, so the semantic colour mapping
 * (verified / refuted / unproved) is defined once and applied consistently — in this product the
 * colour of a badge is information, not decoration.
 */

"use client";

import { clsx, type ClassValue } from "clsx";
import { AlertTriangle, Check, Loader2, Minus, ShieldAlert, X } from "lucide-react";
import type { ReactNode } from "react";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

// ---------------------------------------------------------------------------
export function Panel({
  title,
  subtitle,
  actions,
  children,
  className,
  bodyClassName,
  dense,
}: {
  title?: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
  dense?: boolean;
}) {
  return (
    <section className={cn("panel flex min-h-0 flex-col", className)}>
      {(title || actions) && (
        <header className="panel-header shrink-0">
          <div className="flex min-w-0 items-baseline gap-3">
            {title && <h2 className="panel-title truncate">{title}</h2>}
            {subtitle && (
              <span className="truncate font-mono text-mono-data text-foreground-faint">
                {subtitle}
              </span>
            )}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={cn("min-h-0 flex-1", dense ? "p-0" : "p-4", bodyClassName)}>{children}</div>
    </section>
  );
}

// ---------------------------------------------------------------------------
type Tone = "accent" | "verified" | "refuted" | "warn" | "muted" | "info";

const TONE_CLASS: Record<Tone, string> = {
  accent: "chip-accent",
  verified: "chip-verified",
  refuted: "chip-refuted",
  warn: "chip-warn",
  muted: "chip-muted",
  info: "border-info/45 bg-info/10 text-info",
};

export function Chip({
  tone = "muted",
  children,
  className,
  icon,
  title,
}: {
  tone?: Tone;
  children: ReactNode;
  className?: string;
  icon?: ReactNode;
  /** Hover text. A chip is necessarily terse; this is where the qualifying detail goes. */
  title?: string;
}) {
  return (
    <span className={cn("chip", TONE_CLASS[tone], className)} title={title}>
      {icon}
      {children}
    </span>
  );
}

export const SEVERITY_TONE: Record<string, Tone> = {
  CRITICAL: "refuted",
  HIGH: "warn",
  MEDIUM: "info",
  LOW: "muted",
  INFO: "muted",
};

export function SeverityChip({ severity }: { severity: string }) {
  return <Chip tone={SEVERITY_TONE[severity] ?? "muted"}>{severity}</Chip>;
}

export const STATE_TONE: Record<string, Tone> = {
  VALIDATED: "verified",
  validated: "verified",
  HYPOTHESIS: "warn",
  hypothesis: "warn",
  REFUTED: "refuted",
  refuted: "refuted",
};

export function StateChip({ state }: { state: string }) {
  return <Chip tone={STATE_TONE[state] ?? "muted"}>{state.toUpperCase()}</Chip>;
}

export function VerdictChip({ verdict }: { verdict: string }) {
  if (verdict === "pass") {
    return (
      <Chip tone="verified" icon={<Check className="h-3 w-3" />}>
        PASS
      </Chip>
    );
  }
  if (verdict === "fail") {
    return (
      <Chip tone="refuted" icon={<X className="h-3 w-3" />}>
        FAIL
      </Chip>
    );
  }
  return (
    <Chip tone="muted" icon={<Loader2 className="h-3 w-3 animate-spin" />}>
      RUNNING
    </Chip>
  );
}

export const LEVEL_TONE: Record<string, Tone> = {
  A: "verified",
  B: "accent",
  C: "warn",
  R: "refuted",
};

export function LevelBadge({ level, size = "md" }: { level: string; size?: "sm" | "md" | "lg" }) {
  const tone = LEVEL_TONE[level] ?? "muted";
  const ring = {
    verified: "border-verified/60 text-verified shadow-glow-verified",
    accent: "border-accent/60 text-accent shadow-glow",
    warn: "border-warn/60 text-warn",
    refuted: "border-refuted/60 text-refuted shadow-glow-refuted",
    muted: "border-border-strong text-foreground-subtle",
    info: "border-info/60 text-info",
  }[tone];

  const dims = {
    sm: "h-9 w-9 text-base",
    md: "h-14 w-14 text-2xl",
    lg: "h-28 w-28 text-6xl",
  }[size];

  return (
    <div
      className={cn(
        "flex items-center justify-center rounded-lg border-2 bg-surface-lowest font-mono font-bold",
        ring,
        dims,
      )}
      title={`Assurance level ${level}`}
    >
      {level}
    </div>
  );
}

// ---------------------------------------------------------------------------
export function Metric({
  label,
  value,
  hint,
  tone = "default",
  className,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  tone?: "default" | "accent" | "verified" | "refuted" | "warn";
  className?: string;
}) {
  const valueTone = {
    default: "text-foreground",
    accent: "text-accent",
    verified: "text-verified",
    refuted: "text-refuted",
    warn: "text-warn",
  }[tone];

  return (
    <div className={cn("panel px-4 py-3", className)}>
      <div className="font-mono text-mono-label uppercase text-foreground-subtle">{label}</div>
      <div className={cn("mt-1.5 font-mono text-2xl font-bold tabular-nums", valueTone)}>
        {value}
      </div>
      {hint && <div className="mt-1 text-small text-foreground-faint">{hint}</div>}
    </div>
  );
}

// ---------------------------------------------------------------------------
export function KeyValue({
  items,
  className,
  columns = 1,
}: {
  items: Array<{ label: string; value: ReactNode; mono?: boolean }>;
  className?: string;
  columns?: 1 | 2;
}) {
  return (
    <dl
      className={cn(
        "grid gap-x-6 gap-y-2",
        columns === 2 ? "sm:grid-cols-2" : "grid-cols-1",
        className,
      )}
    >
      {items.map((item) => (
        <div key={item.label} className="flex items-baseline justify-between gap-4">
          <dt className="shrink-0 font-mono text-mono-label uppercase text-foreground-subtle">
            {item.label}
          </dt>
          <dd
            className={cn(
              "min-w-0 truncate text-right text-small text-foreground",
              item.mono && "font-mono text-mono-data",
            )}
            title={typeof item.value === "string" ? item.value : undefined}
          >
            {item.value}
          </dd>
        </div>
      ))}
    </dl>
  );
}

// ---------------------------------------------------------------------------
export function EmptyState({
  icon,
  title,
  detail,
  action,
}: {
  icon?: ReactNode;
  title: string;
  detail?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-12 text-center">
      <div className="text-foreground-faint">{icon ?? <Minus className="h-6 w-6" />}</div>
      <div className="font-mono text-mono-label uppercase text-foreground-subtle">{title}</div>
      {detail && <p className="max-w-md text-small text-foreground-faint">{detail}</p>}
      {action}
    </div>
  );
}

export function Spinner({ className }: { className?: string }) {
  return <Loader2 className={cn("h-4 w-4 animate-spin text-accent", className)} />;
}

export function LoadingPanel({ label = "Loading" }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-3 py-12">
      <Spinner />
      <span className="font-mono text-mono-label uppercase text-foreground-subtle">{label}</span>
    </div>
  );
}

export function ErrorNote({
  title = "Something went wrong",
  detail,
  code,
  requestId,
}: {
  title?: string;
  detail?: string;
  code?: string;
  requestId?: string;
}) {
  return (
    <div className="rounded-md border border-refuted/40 bg-refuted/5 px-4 py-3">
      <div className="flex items-center gap-2 text-refuted">
        <AlertTriangle className="h-4 w-4 shrink-0" />
        <span className="text-sm font-semibold">{title}</span>
        {code && <Chip tone="refuted">{code}</Chip>}
      </div>
      {detail && <p className="mt-1.5 text-small text-foreground-muted">{detail}</p>}
      {requestId && (
        <p className="mt-1 font-mono text-mono-data text-foreground-faint">
          request {requestId}
        </p>
      )}
    </div>
  );
}

export function WarningNote({ children }: { children: ReactNode }) {
  return (
    <div className="flex items-start gap-2.5 rounded-md border border-warn/40 bg-warn/5 px-4 py-3">
      <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-warn" />
      <div className="text-small text-foreground-muted">{children}</div>
    </div>
  );
}

// ---------------------------------------------------------------------------
export function Progress({ value, tone = "accent" }: { value: number; tone?: Tone }) {
  const bar = {
    accent: "bg-accent",
    verified: "bg-verified",
    refuted: "bg-refuted",
    warn: "bg-warn",
    muted: "bg-foreground-subtle",
    info: "bg-info",
  }[tone];
  return (
    <div
      className="h-1.5 w-full overflow-hidden rounded-full bg-surface-highest"
      role="progressbar"
      aria-valuenow={Math.round(value)}
      aria-valuemin={0}
      aria-valuemax={100}
    >
      <div
        className={cn("h-full rounded-full transition-all duration-500", bar)}
        style={{ width: `${Math.max(0, Math.min(100, value))}%` }}
      />
    </div>
  );
}

export function Tabs({
  tabs,
  active,
  onChange,
}: {
  tabs: Array<{ id: string; label: string; count?: number }>;
  active: string;
  onChange: (id: string) => void;
}) {
  return (
    <div
      className="flex gap-1 overflow-x-auto border-b border-border no-scrollbar"
      role="tablist"
    >
      {tabs.map((tab) => (
        <button
          key={tab.id}
          role="tab"
          aria-selected={active === tab.id}
          onClick={() => onChange(tab.id)}
          className={cn(
            "-mb-px shrink-0 border-b-2 px-3.5 py-2 font-mono text-mono-label uppercase transition-colors",
            active === tab.id
              ? "border-accent text-accent"
              : "border-transparent text-foreground-subtle hover:text-foreground",
          )}
        >
          {tab.label}
          {tab.count !== undefined && (
            <span className="ml-1.5 text-foreground-faint">{tab.count}</span>
          )}
        </button>
      ))}
    </div>
  );
}

export function Terminal({
  lines,
  className,
  maxHeight = "18rem",
}: {
  lines: Array<{ text: string; tone?: "default" | "stderr" | "accent" | "dim" }>;
  className?: string;
  maxHeight?: string;
}) {
  return (
    <div
      className={cn(
        "overflow-auto rounded-md border border-border bg-surface-lowest p-3",
        className,
      )}
      style={{ maxHeight }}
    >
      {lines.length === 0 ? (
        <div className="term text-foreground-faint">— no output —</div>
      ) : (
        lines.map((line, index) => (
          <div
            key={index}
            className={cn(
              "term whitespace-pre-wrap break-words",
              line.tone === "stderr" && "text-refuted",
              line.tone === "accent" && "text-accent",
              line.tone === "dim" && "text-foreground-faint",
              (!line.tone || line.tone === "default") && "text-foreground-muted",
            )}
          >
            {line.text}
          </div>
        ))
      )}
    </div>
  );
}

export function Hash({ value, length = 16 }: { value: string; length?: number }) {
  if (!value) return <span className="text-foreground-faint">—</span>;
  return (
    <span className="font-mono text-mono-data text-foreground-subtle" title={value}>
      {value.slice(0, length)}
      {value.length > length && "…"}
    </span>
  );
}
