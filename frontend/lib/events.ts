/**
 * Run event stream types and the SSE hook.
 *
 * The union mirrors the backend `RunEvent` discriminated union exactly. The hook resumes from the
 * highest sequence number it has already seen, so a page refresh or a dropped connection replays
 * from PostgreSQL and rejoins the live tail with no gap and no duplicate.
 */

"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { API_BASE, tokens } from "./api";

export type PhaseStatus = "pending" | "running" | "completed" | "failed" | "blocked";

export type RunEvent =
  | { t: "phase"; phase: string; status: "start" | "done" | "failed" | "blocked"; detail: string }
  | {
      t: "thought";
      agent: string;
      hypothesis: string;
      evidence: string[];
      decision: string;
      confidence: number;
    }
  | { t: "tool"; name: string; target: string; ms: number; ok: boolean; detail: string }
  | {
      t: "finding";
      id: string;
      state: "hypothesis" | "validated" | "refuted";
      clause?: string | null;
      severity: string;
      reachable: boolean;
      title: string;
    }
  | { t: "diff"; finding: string; file: string; patch: string; iter: number; patch_id: string }
  | {
      t: "gauntlet";
      finding: string;
      stage: string;
      verdict: "pass" | "fail" | "running";
      detail: string;
      iter: number;
    }
  | {
      t: "metric";
      tokens: number;
      coverage: number;
      ram_mb: number;
      egress: number;
      model_calls: number;
      sandbox_executions: number;
      cpu_seconds: number;
      elapsed_ms: number;
    }
  | { t: "artifact"; kind: string; url: string; name: string; hash: string }
  | { t: "clause"; clause_id: string; status: string; description: string; scope: string; kind: string }
  | {
      t: "shield";
      finding: string;
      shield_id: string;
      mechanism: string;
      verified_blocked: boolean;
      verified_benign: boolean;
      deployed: boolean;
      rule: string;
    }
  | { t: "certificate"; finding: string; level: string; certificate_hash: string; certificate_id: string }
  | { t: "status"; status: string; detail: string }
  | { t: "log"; stream: "stdout" | "stderr" | "system"; line: string; source: string };

export interface Enveloped {
  seq: number;
  run_id: string;
  ts: string;
  event: RunEvent;
}

export const PIPELINE_PHASES = [
  "ingest",
  "probe",
  "index",
  "world_model",
  "samhita",
  "discovery",
  "hypothesis_queue",
  "validation",
  "shield",
  "root_cause",
  "patch",
  "blast_radius",
  "gauntlet",
  "pramaan",
  "publish",
] as const;

export const PHASE_LABELS: Record<string, string> = {
  ingest: "Ingest",
  probe: "Probe",
  index: "Index",
  world_model: "World Model",
  samhita: "SAMHITA",
  discovery: "Discovery",
  hypothesis_queue: "Hypothesis Queue",
  validation: "Validation",
  shield: "Shield",
  root_cause: "Root Cause",
  patch: "Patch",
  blast_radius: "Blast Radius",
  gauntlet: "Refutation Gauntlet",
  pramaan: "PRAMAAN",
  publish: "Publish",
};

export const GAUNTLET_STAGES = [
  "exploit_mutation",
  "sibling_hunt",
  "differential_replay",
  "samhita_recheck",
] as const;

export const GAUNTLET_LABELS: Record<string, string> = {
  exploit_mutation: "Exploit Mutation",
  sibling_hunt: "Sibling Hunt",
  differential_replay: "Differential Replay",
  samhita_recheck: "SAMHITA Re-check",
};

export interface StreamState {
  events: Enveloped[];
  phases: Record<string, PhaseStatus>;
  connected: boolean;
  ended: boolean;
  status: string;
  lastSeq: number;
  error: string;
}

const TERMINAL = new Set(["COMPLETED", "FAILED", "ABORTED", "AWAITING_APPROVAL"]);

export function useRunStream(runId: string | undefined, initialStatus = ""): StreamState & {
  reconnect: () => void;
} {
  const [events, setEvents] = useState<Enveloped[]>([]);
  const [phases, setPhases] = useState<Record<string, PhaseStatus>>({});
  const [connected, setConnected] = useState(false);
  const [ended, setEnded] = useState(false);
  const [status, setStatus] = useState(initialStatus);
  const [error, setError] = useState("");
  const [nonce, setNonce] = useState(0);
  const lastSeq = useRef(0);

  const reconnect = useCallback(() => {
    setEnded(false);
    setError("");
    setNonce((n) => n + 1);
  }, []);

  useEffect(() => {
    if (!runId) return;
    const token = tokens.access();
    if (!token) {
      setError("Not authenticated.");
      return;
    }

    const params = new URLSearchParams({ token });
    if (lastSeq.current > 0) params.set("lastEventId", String(lastSeq.current));
    const source = new EventSource(`${API_BASE}/api/runs/${runId}/events?${params.toString()}`);

    source.onopen = () => {
      setConnected(true);
      setError("");
    };

    source.addEventListener("message", (raw) => {
      try {
        const envelope = JSON.parse((raw as MessageEvent).data) as Enveloped;
        if (envelope.seq <= lastSeq.current) return;
        lastSeq.current = envelope.seq;
        setEvents((prev) => [...prev, envelope]);

        const event = envelope.event;
        if (event.t === "phase") {
          setPhases((prev) => ({
            ...prev,
            [event.phase]:
              event.status === "start"
                ? "running"
                : event.status === "done"
                  ? "completed"
                  : event.status === "blocked"
                    ? "blocked"
                    : "failed",
          }));
        } else if (event.t === "status") {
          setStatus(event.status);
        }
      } catch {
        /* a malformed frame must not tear down the stream */
      }
    });

    source.addEventListener("heartbeat", (raw) => {
      try {
        const data = JSON.parse((raw as MessageEvent).data);
        if (data.status) setStatus(data.status);
      } catch {
        /* ignore */
      }
    });

    source.addEventListener("end", (raw) => {
      try {
        const data = JSON.parse((raw as MessageEvent).data);
        if (data.status) setStatus(data.status);
      } catch {
        /* ignore */
      }
      setEnded(true);
      setConnected(false);
      source.close();
    });

    source.onerror = () => {
      setConnected(false);
      // EventSource reconnects on its own; only report a hard stop.
      if (source.readyState === EventSource.CLOSED) {
        setError("Event stream closed. Reconnecting…");
      }
    };

    return () => source.close();
  }, [runId, nonce]);

  useEffect(() => {
    if (TERMINAL.has(status)) setEnded(true);
  }, [status]);

  return { events, phases, connected, ended, status, lastSeq: lastSeq.current, error, reconnect };
}

// ---------------------------------------------------------------------------
export function eventsOfType<K extends RunEvent["t"]>(
  events: Enveloped[],
  kind: K,
): Array<Extract<RunEvent, { t: K }> & { seq: number; ts: string }> {
  return events
    .filter((e) => e.event.t === kind)
    .map((e) => ({ ...(e.event as Extract<RunEvent, { t: K }>), seq: e.seq, ts: e.ts }));
}

export function latestMetric(events: Enveloped[]) {
  const metrics = eventsOfType(events, "metric");
  return metrics.length ? metrics[metrics.length - 1] : null;
}

export function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return "—";
  const total = Math.floor(ms / 1000);
  const minutes = Math.floor(total / 60);
  const seconds = total % 60;
  return `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / 1024 ** index).toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}
