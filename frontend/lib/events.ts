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
  | { t: "log"; stream: "stdout" | "stderr" | "system"; line: string; source: string }
  // --- code intelligence ---------------------------------------------------
  | {
      t: "index";
      index_id: string;
      status: string;
      graph_source: string;
      files_discovered: number;
      files_indexed: number;
      files_skipped: number;
      symbols: number;
      relationships: number;
      resolved_relationships: number;
      entrypoints: number;
      tests: number;
      configs: number;
      dependencies: number;
      health_grade: string;
      duration_ms: number;
    }
  | {
      t: "security_flow";
      ref: string;
      source_kind: string;
      sink_kind: string;
      severity: string;
      cwe: string;
      /** taint | call-graph | proximity — what the flow is actually evidenced by. */
      basis: string;
      /** resolved | union — which call edges the path was allowed to use. */
      precision: string;
      confidence: number;
      reachable: boolean;
      sanitized: boolean;
      path: string[];
      boundaries: string[];
    }
  | {
      t: "architecture";
      application_type: string;
      languages: Record<string, number>;
      frameworks: string[];
      entrypoints: number;
      unauthenticated_entrypoints: number;
      data_stores: string[];
      authentication: string[];
      trust_boundaries: string[];
      surface_items: number;
      externally_controllable: number;
      testable: number;
      /** False when no entrypoint existed, so the surface is unknown rather than empty. */
      measured: boolean;
      gaps: string[];
    }
  | {
      t: "testspec";
      plan_id: string;
      candidate: string;
      strategy: string;
      engine: string;
      oracle: string;
      harness_path: string;
      harness_hash: string;
      security_property: string;
      proposed_by: "model" | "deterministic";
    }
  | {
      t: "test_result";
      plan_id: string;
      candidate: string;
      strategy: string;
      engine: string;
      reproduced: boolean;
      reproduction_count: number;
      required: number;
      oracle: string;
      evidence: string;
      coverage_percent: number;
      error: string;
    }
  | {
      t: "coverage";
      candidate: string;
      percent: number;
      corpus_size: number;
      executions: number;
      rounds: number;
      new_findings: number;
      uncovered_branches: number;
      /** How many model-proposed inputs actually reached new coverage, vs how many it proposed. */
      model_candidates: number;
      model_candidates_useful: number;
      stopped_because: string;
    };

export interface Enveloped {
  seq: number;
  run_id: string;
  ts: string;
  event: RunEvent;
}

/**
 * Every phase, in execution order. Mirrors `Phase` in `app/models/enums.py`, whose member order
 * is `PHASE_ORDER` — keep the two in step, because a timeline ordered differently from the
 * pipeline would misrepresent what ran when.
 */
export const PIPELINE_PHASES = [
  "ingest",
  "index",
  "index_validate",
  "security_model",
  "understand",
  "probe",
  "world_model",
  "samhita",
  "discovery",
  "hypothesis_queue",
  "test_synthesis",
  "execute",
  "validation",
  "shield",
  "root_cause",
  "regression",
  "patch",
  "blast_radius",
  "gauntlet",
  "pramaan",
  "publish",
] as const;

/**
 * The phases that existed before the code-intelligence layer. Mirrors `LEGACY_PHASE_ORDER`.
 *
 * A run recorded by an older build has no key for the newer stages, and rendering them would show
 * five stages stuck on "pending" forever — which reads as "these failed" rather than "this run
 * predates them". {@link phasesForRun} picks the right list.
 */
export const LEGACY_PIPELINE_PHASES = [
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

/** Phases only a code-intelligence build emits. Their presence dates a run. */
const INTELLIGENCE_PHASES = [
  "index_validate",
  "security_model",
  "understand",
  "test_synthesis",
  "execute",
  "regression",
] as const;

/**
 * Which phase list to render for this run: the full pipeline, or the legacy one.
 *
 * Decided from the recorded `phase_status` keys rather than from a build version, because the keys
 * are what the run actually wrote.
 */
export function phasesForRun(phaseStatus: Record<string, unknown> | null | undefined): readonly string[] {
  if (!phaseStatus) return PIPELINE_PHASES;
  const known = INTELLIGENCE_PHASES.some((phase) => phase in phaseStatus);
  return known ? PIPELINE_PHASES : LEGACY_PIPELINE_PHASES;
}

export const PHASE_LABELS: Record<string, string> = {
  ingest: "Ingest",
  index: "Index",
  index_validate: "Index Validation",
  security_model: "Security Model",
  understand: "Understand",
  probe: "Probe",
  world_model: "World Model",
  samhita: "SAMHITA",
  discovery: "Discovery",
  hypothesis_queue: "Hypothesis Queue",
  test_synthesis: "Test Synthesis",
  execute: "Execute",
  validation: "Validation",
  shield: "Shield",
  root_cause: "Root Cause",
  regression: "Regression",
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
