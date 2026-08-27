"use client";

/**
 * Console panels for the code-intelligence layer.
 *
 * Every panel here renders a *projection of what a run recorded*, so each one can legitimately
 * come back unavailable — for a run that predates the stage, or one that failed before reaching
 * it. That case is rendered as an explicit reason rather than as an empty panel, because an empty
 * panel reads as "the stage ran and found nothing", which is a different and much stronger claim.
 *
 * The same principle drives the rest of the layout: a data flow always shows its `basis` and
 * `precision`, an unmeasured attack surface says so instead of showing zero, an unavailable engine
 * says NOT RUN rather than passing silently, and a context that shed slices for budget lists what
 * it dropped.
 */

import {
  Activity,
  AlertTriangle,
  Boxes,
  Check,
  ChevronRight,
  Crosshair,
  Database,
  FileCode2,
  FlaskConical,
  GitBranch,
  Layers,
  Loader2,
  Lock,
  Network,
  Search,
  ShieldAlert,
  Target,
  X,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";

import {
  ApiError,
  endpoints,
  type ArchitectureView,
  type EngineInventory,
  type GraphEdge,
  type GraphNode,
  type GraphOverview,
  type GraphSubgraph,
  type IndexReport,
  type ModelContextSummary,
  type SecurityFlow,
  type SecurityModelView,
  type SurfaceItem,
  type TestsView,
} from "@/lib/api";

import {
  Chip,
  cn,
  EmptyState,
  ErrorNote,
  Hash,
  KeyValue,
  LoadingPanel,
  Metric,
  Panel,
  Progress,
  SeverityChip,
  WarningNote,
} from "./ui";

// ---------------------------------------------------------------------------
// shared plumbing
// ---------------------------------------------------------------------------
type Loaded<T> = { state: "loading" } | { state: "error"; error: string } | { state: "ready"; data: T };

function useResource<T>(load: () => Promise<T>, deps: unknown[]): Loaded<T> & { reload: () => void } {
  const [result, setResult] = useState<Loaded<T>>({ state: "loading" });
  const [nonce, setNonce] = useState(0);

  // `load` is recreated on every render by callers that inline it, so the effect keys off the
  // caller's own deps instead. Reloading on identity alone would loop forever.
  const run = useCallback(load, deps);

  useEffect(() => {
    let alive = true;
    setResult({ state: "loading" });
    run()
      .then((data) => alive && setResult({ state: "ready", data }))
      .catch((exc) =>
        alive &&
        setResult({
          state: "error",
          error: exc instanceof ApiError ? `${exc.code}: ${exc.message}` : String(exc),
        }),
      );
    return () => {
      alive = false;
    };
  }, [run, nonce]);

  return { ...result, reload: () => setNonce((n) => n + 1) };
}

/** An absence with a stated reason. Never an empty panel. */
function NotRecorded({ title, reason }: { title: string; reason: string }) {
  return (
    <Panel title={title}>
      <div className="flex items-start gap-3 rounded-md border border-border bg-surface-high/40 px-4 py-3">
        <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-foreground-faint" />
        <div className="min-w-0 text-small text-foreground-muted">
          <span className="text-foreground">NOT RECORDED.</span> {reason}
          <div className="mt-1.5 text-foreground-faint">
            This is an absence of evidence, not evidence of absence — nothing below should be read
            as a clean result.
          </div>
        </div>
      </div>
    </Panel>
  );
}

/**
 * The bound a claim carries. Rendered wherever a number could otherwise be over-read.
 */
function ClaimBounds({ bounds, title = "This cannot support" }: { bounds: string[]; title?: string }) {
  if (bounds.length === 0) return null;
  return (
    <div className="rounded-md border border-warn/40 bg-warn/[0.05] px-4 py-3">
      <div className="flex items-center gap-2 text-warn">
        <ShieldAlert className="h-4 w-4 shrink-0" />
        <span className="font-mono text-mono-label uppercase">{title}</span>
      </div>
      <ul className="mt-2 space-y-1.5">
        {bounds.map((bound) => (
          <li key={bound} className="flex gap-2 text-small text-foreground-muted">
            <span className="select-none text-warn">—</span>
            <span className="min-w-0">{bound}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

const GRADE_TONE: Record<string, "verified" | "accent" | "warn" | "refuted"> = {
  A: "verified",
  B: "accent",
  C: "warn",
  F: "refuted",
};

/**
 * How a flow is evidenced. Two chips, always together, because they qualify every claim built on
 * the flow: a taint-proven path and a name-matched call chain are not the same finding.
 */
function BasisChips({
  basis,
  precision,
  measured = true,
}: {
  basis: string;
  precision: string;
  measured?: boolean;
}) {
  return (
    <>
      <Chip
        tone={basis === "taint" ? "verified" : basis === "call-graph" ? "warn" : "muted"}
        title={
          basis === "taint"
            ? "The AST proved the value reaching the sink derives from this source."
            : basis === "call-graph"
              ? "A call path exists, but derivation across the call boundary was NOT proven."
              : "Source and sink are merely co-located; no data flow between them was established."
        }
      >
        {basis || "unknown"}
      </Chip>
      <Chip
        tone={precision === "resolved" ? "verified" : "warn"}
        title={
          precision === "resolved"
            ? "Every hop is a resolved symbol reference."
            : "At least one hop is a name-matched call edge, so the path may include a call that cannot occur."
        }
      >
        {precision || "unknown"}
      </Chip>
      {!measured && (
        <Chip tone="refuted" title="No entrypoint existed to search from, so reachability is unknown.">
          UNMEASURED
        </Chip>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// Panel — index health
// ---------------------------------------------------------------------------
export function IndexHealthPanel({ runId }: { runId: string }) {
  const result = useResource(() => endpoints.runIndex(runId), [runId]);

  if (result.state === "loading") return <LoadingPanel label="Loading index" />;
  if (result.state === "error") return <ErrorNote title="Could not load the index" detail={result.error} />;
  if (!result.data.available) return <NotRecorded title="Index" reason={result.data.reason} />;

  const { index, health, claim_bounds } = result.data as { available: true } & IndexReport;
  const resolvedPercent = index.relationships.total
    ? (index.relationships.resolved / index.relationships.total) * 100
    : 0;

  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Metric
          label="Health grade"
          value={health.grade || "—"}
          tone={GRADE_TONE[health.grade] ?? "warn"}
          hint={health.usable ? "usable index" : "NOT usable"}
        />
        <Metric
          label="Resolved relationships"
          value={`${resolvedPercent.toFixed(0)}%`}
          tone={resolvedPercent > 40 ? "verified" : "warn"}
          hint={`${index.relationships.resolved} of ${index.relationships.total}`}
        />
        <Metric
          label="Symbols"
          value={index.symbols.total}
          hint={`${index.symbols.functions} functions · ${index.symbols.classes} classes`}
        />
        <Metric
          label="Files"
          value={index.files.indexed}
          tone={index.files.skipped > 0 ? "warn" : "default"}
          hint={`${index.files.discovered} discovered · ${index.files.skipped} skipped`}
        />
      </div>

      <ClaimBounds bounds={claim_bounds} title="This index cannot support" />

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="Identity" subtitle="reproducible">
          <KeyValue
            items={[
              { label: "Index id", value: <Hash value={index.index_id} length={24} />, mono: true },
              { label: "Graph hash", value: <Hash value={index.graph_hash} length={24} />, mono: true },
              {
                label: "Pinned source",
                value: <Hash value={index.source_sha256} length={20} />,
                mono: true,
              },
              { label: "Commit", value: index.commit_sha.slice(0, 12) || "—", mono: true },
              { label: "Status", value: <Chip tone={index.status === "COMPLETED" ? "verified" : index.status === "FAILED" ? "refuted" : "warn"}>{index.status}</Chip> },
              { label: "Duration", value: `${index.duration_ms} ms`, mono: true },
            ]}
          />
          <p className="mt-3 text-small text-foreground-faint">
            The id is <span className="term text-foreground-muted">sha256(source sha + indexer/parser
            versions + options)</span>, so the same tree indexed by the same build is the same index.
            The graph hash is structural and deliberately excludes line numbers.
          </p>
        </Panel>

        <Panel title="Provenance" subtitle={index.graph_source}>
          <div className="flex flex-wrap gap-2">
            {index.providers.length === 0 ? (
              <Chip tone="refuted">no provider contributed</Chip>
            ) : (
              index.providers.map((provider) => (
                <Chip key={provider} tone="accent">
                  {provider}
                </Chip>
              ))
            )}
          </div>
          <p className="mt-3 text-small text-foreground-faint">
            <span className="text-foreground-muted">graph_source</span> names only providers that
            actually contributed an edge or a node to this graph. It is never a statement about what
            was installed or available.
          </p>
          {Object.keys(index.versions).length > 0 && (
            <details className="mt-3">
              <summary className="cursor-pointer font-mono text-mono-label uppercase text-foreground-subtle">
                indexer &amp; parser versions
              </summary>
              <pre className="mt-1.5 max-h-48 overflow-auto term text-foreground-muted">
                {JSON.stringify(index.versions, null, 2)}
              </pre>
            </details>
          )}
        </Panel>
      </div>

      <Panel title="Health checks" subtitle={`${health.checks?.length ?? 0} deterministic checks`} bodyClassName="p-0">
        {!health.checks?.length ? (
          <EmptyState title="No checks recorded" />
        ) : (
          <div className="divide-y divide-border">
            {health.checks.map((check) => (
              <div key={check.id} className="flex gap-3 px-4 py-3">
                <span className="mt-0.5 shrink-0">
                  {check.severity === "ok" ? (
                    <Check className="h-4 w-4 text-verified" />
                  ) : check.severity === "warn" ? (
                    <AlertTriangle className="h-4 w-4 text-warn" />
                  ) : (
                    <X className="h-4 w-4 text-refuted" />
                  )}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-baseline gap-2">
                    <span className="text-small text-foreground">{check.title}</span>
                    <span className="font-mono text-[10px] uppercase text-foreground-faint">
                      {check.id}
                    </span>
                  </div>
                  {check.detail && (
                    <div className="mt-0.5 text-small text-foreground-muted">{check.detail}</div>
                  )}
                  {check.bounds_claim && (
                    <div className="mt-1 flex gap-2 text-small text-warn">
                      <span className="select-none">↳</span>
                      <span className="min-w-0">{check.bounds_claim}</span>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="Discovered" subtitle="from the graph">
          <KeyValue
            columns={2}
            items={[
              { label: "Entrypoints", value: index.discovered.entrypoints, mono: true },
              { label: "Tests", value: index.discovered.tests, mono: true },
              { label: "Configs", value: index.discovered.configs, mono: true },
              { label: "Dependencies", value: index.discovered.dependencies, mono: true },
              { label: "Call edges", value: index.relationships.calls, mono: true },
              { label: "Import edges", value: index.relationships.imports, mono: true },
            ]}
          />
          {Object.keys(index.languages).length > 0 && (
            <div className="mt-3 flex flex-wrap gap-2">
              {Object.entries(index.languages)
                .sort((a, b) => b[1] - a[1])
                .map(([language, count]) => (
                  <Chip key={language} tone="muted">
                    {language} {count}
                  </Chip>
                ))}
            </div>
          )}
        </Panel>

        <Panel
          title="Skipped files"
          subtitle={`${index.files.skipped} excluded from analysis`}
          bodyClassName="p-0"
        >
          {index.files.skipped_detail?.length === 0 ? (
            <div className="p-4 text-small text-foreground-faint">
              Nothing was skipped. Every discovered file was analysed.
            </div>
          ) : (
            <div className="max-h-64 divide-y divide-border overflow-auto">
              {index.files.skipped_detail?.map((entry) => (
                <div key={entry.path} className="flex items-baseline gap-3 px-4 py-2">
                  <span className="min-w-0 flex-1 truncate term text-foreground-muted" title={entry.path}>
                    {entry.path}
                  </span>
                  <span className="shrink-0 text-[11px] text-foreground-faint">{entry.reason}</span>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>

      {(index.warnings.length > 0 || index.errors.length > 0) && (
        <Panel title="Indexer output">
          {index.errors.map((line) => (
            <div key={line} className="term text-refuted">
              {line}
            </div>
          ))}
          {index.warnings.map((line) => (
            <div key={line} className="term text-warn">
              {line}
            </div>
          ))}
        </Panel>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Panel — code knowledge graph
// ---------------------------------------------------------------------------
const EDGE_COLOUR: Record<string, string> = {
  CALLS: "#00dbe7",
  IMPORTS: "#849495",
  CONTAINS: "#3a494b",
  TESTED_BY: "#3ddc84",
  INHERITS: "#f5b642",
};

/**
 * A bounded subgraph, drawn deterministically.
 *
 * Concentric rings by BFS depth from the root, angle by sorted position — so the same subgraph
 * always draws identically. A force simulation would look better and settle somewhere slightly
 * different every time, which is the wrong trade for a view whose whole point is that the
 * underlying graph is reproducible.
 */
function GraphCanvas({
  nodes,
  edges,
  root,
  onSelect,
}: {
  nodes: GraphNode[];
  edges: GraphEdge[];
  root: string;
  onSelect: (uid: string) => void;
}) {
  const layout = useMemo(() => {
    const byUid = new Map(nodes.map((n) => [n.uid, n]));
    const adjacency = new Map<string, Set<string>>();
    for (const edge of edges) {
      if (!byUid.has(edge.src) || !byUid.has(edge.dst)) continue;
      if (!adjacency.has(edge.src)) adjacency.set(edge.src, new Set());
      if (!adjacency.has(edge.dst)) adjacency.set(edge.dst, new Set());
      adjacency.get(edge.src)!.add(edge.dst);
      adjacency.get(edge.dst)!.add(edge.src);
    }

    const depth = new Map<string, number>();
    if (byUid.has(root)) depth.set(root, 0);
    let frontier = byUid.has(root) ? [root] : [];
    let level = 0;
    while (frontier.length > 0 && level < 6) {
      level += 1;
      const next: string[] = [];
      for (const uid of frontier) {
        for (const neighbour of [...(adjacency.get(uid) ?? [])].sort()) {
          if (!depth.has(neighbour)) {
            depth.set(neighbour, level);
            next.push(neighbour);
          }
        }
      }
      frontier = next;
    }
    // Anything the walk never reached (a disconnected fragment of the projection) still needs a
    // place, on the outermost ring, rather than being silently dropped from the drawing.
    const maxDepth = Math.max(0, ...depth.values());
    for (const node of nodes) if (!depth.has(node.uid)) depth.set(node.uid, maxDepth + 1);

    const rings = new Map<number, string[]>();
    for (const [uid, d] of [...depth.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
      if (!rings.has(d)) rings.set(d, []);
      rings.get(d)!.push(uid);
    }

    const width = 900;
    const height = 520;
    const cx = width / 2;
    const cy = height / 2;
    const ringCount = Math.max(1, rings.size - 1);
    const step = Math.min(cx, cy) * 0.86 / ringCount;

    const positions = new Map<string, { x: number; y: number }>();
    for (const [d, uids] of rings) {
      if (d === 0) {
        positions.set(uids[0], { x: cx, y: cy });
        continue;
      }
      const radius = step * d;
      uids.forEach((uid, index) => {
        // Offset each ring so nodes do not line up radially across rings.
        const angle = (index / uids.length) * Math.PI * 2 + d * 0.4;
        positions.set(uid, { x: cx + radius * Math.cos(angle), y: cy + radius * Math.sin(angle) });
      });
    }
    return { positions, width, height, byUid };
  }, [nodes, edges, root]);

  const { positions, width, height, byUid } = layout;

  return (
    <div className="overflow-x-auto">
      <svg viewBox={`0 0 ${width} ${height}`} className="min-w-[720px] w-full" role="img" aria-label="Code graph subgraph">
        {edges.map((edge, index) => {
          const from = positions.get(edge.src);
          const to = positions.get(edge.dst);
          if (!from || !to) return null;
          return (
            <line
              key={`${edge.src}->${edge.dst}:${edge.kind}:${index}`}
              x1={from.x}
              y1={from.y}
              x2={to.x}
              y2={to.y}
              stroke={EDGE_COLOUR[edge.kind] ?? "#3a494b"}
              strokeWidth={edge.resolved ? 1.4 : 1}
              strokeOpacity={edge.resolved ? 0.55 : 0.3}
              /* Dashed means name-matched, not resolved. The distinction is the whole point. */
              strokeDasharray={edge.resolved ? undefined : "4 3"}
            />
          );
        })}
        {[...positions.entries()].map(([uid, point]) => {
          const node = byUid.get(uid);
          if (!node) return null;
          const isRoot = uid === root;
          const isEntry = Boolean(node.kind === "entrypoint");
          return (
            <g
              key={uid}
              transform={`translate(${point.x},${point.y})`}
              onClick={() => onSelect(uid)}
              className="cursor-pointer"
            >
              <circle
                r={isRoot ? 8 : 5}
                fill={isRoot ? "#00f2ff" : isEntry ? "#f5b642" : "#0d0e0f"}
                stroke={isRoot ? "#00f2ff" : isEntry ? "#f5b642" : "#849495"}
                strokeWidth={1.5}
              />
              <text
                x={10}
                y={4}
                className="fill-current font-mono"
                style={{ fontSize: 10, fill: isRoot ? "#00f2ff" : "#849495" }}
              >
                {(node.name || node.uid).slice(0, 28)}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

export function CodeGraphPanel({ runId }: { runId: string }) {
  const [selected, setSelected] = useState("");
  const [query, setQuery] = useState("");
  const [depth, setDepth] = useState(2);

  const overview = useResource(() => endpoints.runGraph(runId), [runId]);
  const subgraph = useResource(
    () => (selected ? endpoints.runGraph(runId, selected, depth, 160) : Promise.resolve(null)),
    [runId, selected, depth],
  );

  if (overview.state === "loading") return <LoadingPanel label="Loading code graph" />;
  if (overview.state === "error")
    return <ErrorNote title="Could not load the code graph" detail={overview.error} />;
  if (!overview.data.available)
    return <NotRecorded title="Code graph" reason={overview.data.reason} />;

  const data = overview.data as { available: true } & GraphOverview;
  const stats = data.stats ?? {};
  const candidates = [...(data.entrypoints ?? []), ...(data.sample_nodes ?? [])];
  const seen = new Set<string>();
  const symbols = candidates.filter((n) => {
    if (!n?.uid || seen.has(n.uid)) return false;
    seen.add(n.uid);
    return true;
  });
  const filtered = query
    ? symbols.filter((n) =>
        `${n.uid} ${n.name} ${n.qualname}`.toLowerCase().includes(query.toLowerCase()),
      )
    : symbols;

  const sub =
    subgraph.state === "ready" && subgraph.data && (subgraph.data as any).available
      ? (subgraph.data as { available: true } & GraphSubgraph)
      : null;

  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Metric label="Nodes" value={stats.nodes ?? "—"} hint={`${stats.files ?? 0} files`} />
        <Metric
          label="Edges"
          value={stats.edges ?? "—"}
          hint={`${stats.resolved_edges ?? stats.resolved ?? 0} resolved`}
        />
        <Metric label="Callables" value={stats.callables ?? stats.functions ?? "—"} />
        <Metric
          label="Entrypoints"
          value={stats.entrypoints ?? data.entrypoints?.length ?? 0}
          tone={(stats.entrypoints ?? 0) > 0 ? "accent" : "warn"}
          hint={(stats.entrypoints ?? 0) > 0 ? undefined : "reachability cannot be measured"}
        />
      </div>

      {data.truncated && (
        <WarningNote>
          The stored graph document was truncated when it was recorded, so this projection is
          incomplete. Counts above come from the full graph; the nodes available to explore do not.
        </WarningNote>
      )}

      <Panel
        title="Explore"
        subtitle={data.providers?.join(" + ") || "no provider"}
        actions={
          <div className="flex items-center gap-2">
            <label className="font-mono text-[10px] uppercase text-foreground-faint" htmlFor="graph-depth">
              depth
            </label>
            <select
              id="graph-depth"
              value={depth}
              onChange={(event) => setDepth(Number(event.target.value))}
              className="rounded border border-border bg-surface-high px-2 py-1 font-mono text-mono-data text-foreground"
            >
              {[1, 2, 3, 4].map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </div>
        }
      >
        <div className="flex items-center gap-2 rounded-md border border-border bg-surface-high px-3 py-2">
          <Search className="h-4 w-4 shrink-0 text-foreground-faint" />
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Filter symbols by name or path…"
            className="min-w-0 flex-1 bg-transparent font-mono text-mono-data text-foreground outline-none placeholder:text-foreground-faint"
          />
          <span className="shrink-0 font-mono text-[10px] text-foreground-faint">
            {filtered.length}/{symbols.length}
          </span>
        </div>

        <div className="mt-3 max-h-56 overflow-auto rounded-md border border-border">
          {filtered.length === 0 ? (
            <div className="p-4 text-small text-foreground-faint">
              No symbol matched. The graph projection returns entrypoints and a sample of callables,
              not every node — the whole graph is deliberately never shipped to the browser.
            </div>
          ) : (
            <div className="divide-y divide-border">
              {filtered.map((node) => (
                <button
                  key={node.uid}
                  onClick={() => setSelected(node.uid)}
                  className={cn(
                    "flex w-full items-center gap-3 px-3 py-2 text-left hover:bg-surface-high",
                    selected === node.uid && "bg-accent/[0.08]",
                  )}
                >
                  <Chip tone={node.kind === "entrypoint" ? "warn" : "muted"}>{node.kind}</Chip>
                  <span className="min-w-0 flex-1 truncate term text-foreground" title={node.uid}>
                    {node.name || node.uid}
                  </span>
                  <span className="hidden shrink-0 text-[11px] text-foreground-faint lg:block">
                    {node.file}
                    {node.start_line ? `:${node.start_line}` : ""}
                  </span>
                  <div className="flex shrink-0 gap-1">
                    {node.provenance?.map((provider) => (
                      <span
                        key={provider}
                        className="font-mono text-[9px] uppercase text-foreground-faint"
                        title={`reported by ${provider}`}
                      >
                        {provider.slice(0, 4)}
                      </span>
                    ))}
                  </div>
                  <ChevronRight className="h-3.5 w-3.5 shrink-0 text-foreground-faint" />
                </button>
              ))}
            </div>
          )}
        </div>
      </Panel>

      {selected && (
        <Panel
          title={`Subgraph · ${selected}`}
          subtitle={sub ? `${sub.nodes.length} nodes · ${sub.edges.length} edges · depth ${sub.depth}` : "loading"}
          actions={
            <button onClick={() => setSelected("")} className="btn-ghost px-2 py-1 text-xs">
              Clear
            </button>
          }
        >
          {subgraph.state === "loading" ? (
            <div className="flex items-center gap-2 py-8 text-small text-foreground-faint">
              <Loader2 className="h-4 w-4 animate-spin" /> Building subgraph…
            </div>
          ) : !sub ? (
            <div className="py-6 text-small text-foreground-faint">
              No subgraph was returned for this node.
            </div>
          ) : (
            <>
              <GraphCanvas
                nodes={sub.nodes}
                edges={sub.edges}
                root={sub.root}
                onSelect={setSelected}
              />
              <div className="mt-3 flex flex-wrap items-center gap-4 border-t border-border pt-3">
                <span className="flex items-center gap-2 text-small text-foreground-faint">
                  <svg width="26" height="6">
                    <line x1="0" y1="3" x2="26" y2="3" stroke="#00dbe7" strokeWidth="1.4" strokeOpacity="0.55" />
                  </svg>
                  resolved reference
                </span>
                <span className="flex items-center gap-2 text-small text-foreground-faint">
                  <svg width="26" height="6">
                    <line
                      x1="0"
                      y1="3"
                      x2="26"
                      y2="3"
                      stroke="#849495"
                      strokeWidth="1"
                      strokeOpacity="0.4"
                      strokeDasharray="4 3"
                    />
                  </svg>
                  name match only — the call may not occur
                </span>
                {sub.truncated && <Chip tone="warn">TRUNCATED at the node limit</Chip>}
              </div>
              <p className="mt-2 text-small text-foreground-faint">
                Layout is deterministic — rings by distance from the centre node — so the same
                subgraph always draws the same way. Click any node to re-centre.
              </p>
            </>
          )}
        </Panel>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Panel — security model
// ---------------------------------------------------------------------------
const CATEGORY_ICON: Record<string, typeof Activity> = {
  source: Database,
  sink: Target,
  sanitizer: ShieldAlert,
  validator: Check,
  authentication_check: Lock,
};

export function SecurityModelPanel({ runId }: { runId: string }) {
  const result = useResource(() => endpoints.runSecurity(runId), [runId]);
  const [openFlow, setOpenFlow] = useState("");

  if (result.state === "loading") return <LoadingPanel label="Loading security model" />;
  if (result.state === "error")
    return <ErrorNote title="Could not load the security model" detail={result.error} />;
  if (!result.data.available)
    return <NotRecorded title="Security model" reason={result.data.reason} />;

  const model = result.data as { available: true } & SecurityModelView;
  const stats = model.stats ?? {};
  const flows = model.flows ?? [];
  const unmeasured = flows.filter((f) => !f.reachability_measured).length;

  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <Metric label="Sources" value={stats.sources ?? 0} />
        <Metric label="Sinks" value={stats.sinks ?? 0} tone={(stats.sinks ?? 0) > 0 ? "warn" : "default"} />
        <Metric label="Sanitizers" value={stats.sanitizers ?? 0} />
        <Metric label="Controls" value={stats.controls ?? 0} tone={(stats.controls ?? 0) === 0 ? "warn" : "verified"} />
        <Metric label="Flows" value={stats.flows ?? flows.length} />
        <Metric
          label="Reachable"
          value={stats.reachable_flows ?? flows.filter((f) => f.reachable_from_entrypoint).length}
          tone="warn"
        />
      </div>

      {unmeasured > 0 && (
        <WarningNote>
          {unmeasured} flow(s) have <span className="text-warn">unmeasured reachability</span> — the
          target declares no entrypoint, so no call path could be searched. That is unknown, not
          unreachable, and ranking below substitutes severity rather than assuming safety.
        </WarningNote>
      )}

      {(stats.controls ?? 0) === 0 && (
        <WarningNote>
          No authentication or authorisation control was identified anywhere in the tree. That may be
          correct (a library, an internal CLI), or it may mean the controls are expressed in a form
          the taxonomy does not recognise. It is <span className="text-warn">not</span> evidence that
          the application is unprotected.
        </WarningNote>
      )}

      <Panel
        title="Data flows"
        subtitle={`${flows.length} evidenced path(s), highest-priority first`}
        bodyClassName="p-0"
      >
        {flows.length === 0 ? (
          <EmptyState
            icon={<Network className="h-6 w-6" />}
            title="No flow was derived"
            detail="No source was found to reach a sink over this graph. Absence of a derived flow is not evidence of safety — it bounds what this analysis looked at."
          />
        ) : (
          <div className="divide-y divide-border">
            {flows.map((flow) => (
              <FlowRow
                key={flow.ref}
                flow={flow}
                open={openFlow === flow.ref}
                onToggle={() => setOpenFlow(openFlow === flow.ref ? "" : flow.ref)}
              />
            ))}
          </div>
        )}
      </Panel>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="Trust boundaries" subtitle={`${model.trust_boundaries?.length ?? 0} crossing(s)`}>
          {!model.trust_boundaries?.length ? (
            <div className="text-small text-foreground-faint">No trust boundary was crossed.</div>
          ) : (
            <div className="space-y-3">
              {model.trust_boundaries.map((boundary) => (
                <div key={boundary.kind}>
                  <div className="flex items-center gap-2">
                    <GitBranch className="h-3.5 w-3.5 text-accent" />
                    <span className="term text-accent">{boundary.kind}</span>
                    <span className="font-mono text-[10px] text-foreground-faint">
                      {boundary.members?.length ?? 0} member(s)
                    </span>
                  </div>
                  {boundary.description && (
                    <div className="mt-0.5 pl-5 text-small text-foreground-muted">
                      {boundary.description}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel title="Rule provenance" subtitle="which taxonomy produced these facts">
          <KeyValue
            items={Object.entries(model.taxonomy ?? {})
              .filter(([, value]) => typeof value === "number" || typeof value === "string")
              .map(([label, value]) => ({ label, value: String(value), mono: true }))}
          />
          {Array.isArray(model.taxonomy?.extensions) && model.taxonomy.extensions.length > 0 && (
            <div className="mt-3">
              <div className="panel-title mb-1">Operator extensions</div>
              {model.taxonomy.extensions.map((line: string) => (
                <div key={line} className="term text-foreground-muted">
                  {line}
                </div>
              ))}
            </div>
          )}
          {Array.isArray(model.taxonomy?.errors) && model.taxonomy.errors.length > 0 && (
            <div className="mt-3">
              <div className="panel-title mb-1 text-refuted">Rule errors</div>
              {model.taxonomy.errors.map((line: string) => (
                <div key={line} className="term text-refuted">
                  {line}
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>

      {model.parse_errors?.length > 0 && (
        <Panel
          title="Files the analyser could not parse"
          subtitle={`${model.parse_errors.length} file(s) — not analysed, not cleared`}
          bodyClassName="p-0"
        >
          <div className="max-h-56 divide-y divide-border overflow-auto">
            {model.parse_errors.map((entry) => (
              <div key={entry.path} className="flex items-baseline gap-3 px-4 py-2">
                <span className="min-w-0 flex-1 truncate term text-foreground-muted">{entry.path}</span>
                <span className="shrink-0 text-[11px] text-refuted">{entry.error}</span>
              </div>
            ))}
          </div>
        </Panel>
      )}
    </div>
  );
}

function FlowRow({
  flow,
  open,
  onToggle,
}: {
  flow: SecurityFlow;
  open: boolean;
  onToggle: () => void;
}) {
  return (
    <div className={cn(open && "bg-surface-high/40")}>
      <button onClick={onToggle} className="flex w-full flex-wrap items-center gap-2 px-4 py-3 text-left hover:bg-surface-high">
        <SeverityChip severity={flow.severity} />
        <span className="term text-foreground">
          {flow.source_kind} <span className="text-foreground-faint">→</span> {flow.sink_kind}
        </span>
        {flow.cwe && <Chip tone="muted">{flow.cwe}</Chip>}
        <BasisChips
          basis={flow.basis}
          precision={flow.precision}
          measured={flow.reachability_measured}
        />
        {flow.reachable_from_entrypoint && flow.reachability_measured && (
          <Chip tone="warn">REACHABLE</Chip>
        )}
        {flow.sanitized && (
          <Chip tone="info" title="A sanitizer appears on the path. Static presence is not proof of execution — it is not a clearance.">
            SANITIZER ON PATH
          </Chip>
        )}
        <span className="ml-auto shrink-0 font-mono text-[10px] text-foreground-faint">
          conf {flow.confidence.toFixed(2)}
        </span>
        <ChevronRight
          className={cn("h-3.5 w-3.5 shrink-0 text-foreground-faint transition-transform", open && "rotate-90")}
        />
      </button>

      {open && (
        <div className="space-y-3 border-t border-border px-4 py-3">
          <div>
            <div className="panel-title mb-1.5">Path</div>
            <ol className="space-y-1">
              {flow.steps.map((step, index) => (
                <li key={`${step.location}:${index}`} className="flex gap-3">
                  <span className="w-16 shrink-0 font-mono text-[10px] uppercase text-accent">
                    {step.kind}
                  </span>
                  <span className="w-52 shrink-0 truncate term text-foreground-muted" title={step.location}>
                    {step.location}
                  </span>
                  <span className="min-w-0 flex-1 text-small text-foreground-faint">{step.detail}</span>
                </li>
              ))}
            </ol>
          </div>

          {flow.boundaries.length > 0 && (
            <div className="flex flex-wrap items-center gap-2">
              <span className="panel-title">Crosses</span>
              {flow.boundaries.map((boundary) => (
                <Chip key={boundary} tone="accent">
                  {boundary}
                </Chip>
              ))}
            </div>
          )}

          {flow.covering_tests.length > 0 && (
            <div className="flex flex-wrap items-center gap-2">
              <span className="panel-title">Referenced by</span>
              {flow.covering_tests.map((test) => (
                <Chip key={test} tone="muted" title="A test statically references a symbol on this path. That is not measured coverage.">
                  {test}
                </Chip>
              ))}
            </div>
          )}

          {flow.notes.length > 0 && (
            <div className="rounded-md border border-border bg-surface/60 px-3 py-2">
              <div className="panel-title mb-1">Not established</div>
              {flow.notes.map((note) => (
                <div key={note} className="text-small text-foreground-muted">
                  {note}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Panel — architecture and attack surface
// ---------------------------------------------------------------------------
export function ArchitecturePanel({ runId }: { runId: string }) {
  const result = useResource(() => endpoints.runArchitecture(runId), [runId]);
  const [openItem, setOpenItem] = useState("");

  if (result.state === "loading") return <LoadingPanel label="Loading architecture" />;
  if (result.state === "error")
    return <ErrorNote title="Could not load the architecture model" detail={result.error} />;
  if (!result.data.available)
    return <NotRecorded title="Architecture" reason={result.data.reason} />;

  const { model, attack_surface: surface } = result.data as { available: true } & ArchitectureView;
  const items: SurfaceItem[] = surface?.items ?? [];

  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Metric label="Application type" value={model.application_type || "unknown"} tone="accent" />
        <Metric
          label="Entrypoints"
          value={model.entrypoints?.length ?? 0}
          tone={(surface?.unauthenticated_entrypoints?.length ?? 0) > 0 ? "warn" : "default"}
          hint={`${surface?.unauthenticated_entrypoints?.length ?? 0} with no control on any path`}
        />
        <Metric
          label="Surface items"
          value={surface?.measured ? items.length : "—"}
          tone={surface?.measured ? "default" : "refuted"}
          hint={surface?.measured ? `${surface?.counts?.externally_controllable ?? 0} remotely controllable` : "NOT MEASURED"}
        />
        <Metric
          label="Testable"
          value={surface?.counts?.testable ?? 0}
          hint="a harness could plausibly drive these"
        />
      </div>

      {!surface?.measured && (
        <WarningNote>
          The attack surface was <span className="text-warn">not measured</span>: no entrypoint was
          identified, so no flow could be shown to be externally reachable. The surface is unknown,
          not empty.
        </WarningNote>
      )}

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="Application model">
          <KeyValue
            items={[
              {
                label: "Languages",
                value:
                  Object.entries(model.languages ?? {})
                    .sort((a, b) => (b[1] as number) - (a[1] as number))
                    .map(([lang, count]) => `${lang} (${count})`)
                    .join(", ") || "—",
              },
              { label: "Frameworks", value: model.frameworks?.join(", ") || "none identified" },
              { label: "Data stores", value: model.data_stores?.join(", ") || "none identified" },
              {
                label: "Authentication",
                value: model.authentication?.join(", ") || "none identified",
              },
            ]}
          />
          {model.type_evidence?.length > 0 && (
            <div className="mt-3">
              <div className="panel-title mb-1">Why this classification</div>
              <ul className="space-y-1">
                {model.type_evidence.map((line: string) => (
                  <li key={line} className="flex gap-2 text-small text-foreground-muted">
                    <span className="select-none text-accent">·</span>
                    <span className="min-w-0">{line}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </Panel>

        <Panel title="Not known" subtitle="part of the deliverable, not an appendix">
          {!(model.gaps?.length || surface?.notes?.length) ? (
            <div className="text-small text-foreground-faint">No gap was recorded.</div>
          ) : (
            <ul className="space-y-2">
              {[...(model.gaps ?? []), ...(surface?.notes ?? [])].map((gap: string) => (
                <li key={gap} className="flex gap-2 text-small text-foreground-muted">
                  <span className="select-none text-warn">—</span>
                  <span className="min-w-0">{gap}</span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>

      <Panel
        title="Attack surface"
        subtitle={`${items.length} ranked path(s) — priority is a product of six factors`}
        bodyClassName="p-0"
      >
        {items.length === 0 ? (
          <EmptyState
            icon={<Crosshair className="h-6 w-6" />}
            title="No ranked path"
            detail="No security flow was available to rank."
          />
        ) : (
          <div className="divide-y divide-border">
            {items.map((item, index) => (
              <div key={item.ref} className={cn(openItem === item.ref && "bg-surface-high/40")}>
                <button
                  onClick={() => setOpenItem(openItem === item.ref ? "" : item.ref)}
                  className="flex w-full flex-wrap items-center gap-2 px-4 py-3 text-left hover:bg-surface-high"
                >
                  <span className="w-6 shrink-0 font-mono text-[10px] text-foreground-faint">
                    {String(index + 1).padStart(2, "0")}
                  </span>
                  <SeverityChip severity={item.severity} />
                  <span className="term text-foreground">
                    {item.source_kind} <span className="text-foreground-faint">→</span> {item.sink_kind}
                  </span>
                  <span className="hidden truncate term text-foreground-faint lg:block" title={item.sink_location}>
                    {item.sink_location}
                  </span>
                  {item.externally_controllable && <Chip tone="refuted">REMOTE</Chip>}
                  {!item.measured && <Chip tone="warn">UNMEASURED</Chip>}
                  {item.testable ? (
                    <Chip tone="accent">TESTABLE</Chip>
                  ) : (
                    <Chip tone="muted" title={item.testability_reason}>
                      NOT TESTABLE
                    </Chip>
                  )}
                  <span className="ml-auto shrink-0 font-mono text-[10px] text-accent">
                    {item.priority.toFixed(4)}
                  </span>
                  <ChevronRight
                    className={cn(
                      "h-3.5 w-3.5 shrink-0 text-foreground-faint transition-transform",
                      openItem === item.ref && "rotate-90",
                    )}
                  />
                </button>

                {openItem === item.ref && (
                  <div className="space-y-3 border-t border-border px-4 py-3">
                    <div>
                      <div className="panel-title mb-1.5">Priority factors</div>
                      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                        {Object.entries(item.factors).map(([factor, value]) => (
                          <div key={factor}>
                            <div className="flex items-baseline justify-between gap-2">
                              <span className="font-mono text-[10px] uppercase text-foreground-subtle">
                                {factor.replace(/_/g, " ")}
                              </span>
                              <span className="font-mono text-mono-data text-foreground">
                                {value.toFixed(2)}
                              </span>
                            </div>
                            <Progress
                              value={value * 100}
                              tone={value > 0.66 ? "refuted" : value > 0.33 ? "warn" : "muted"}
                            />
                          </div>
                        ))}
                      </div>
                    </div>

                    <div>
                      <div className="panel-title mb-1">Rationale</div>
                      <ul className="space-y-1">
                        {item.rationale.map((line, lineIndex) => (
                          <li
                            key={line}
                            className={cn(
                              "text-small",
                              lineIndex === 0
                                ? "term text-accent"
                                : "flex gap-2 text-foreground-muted",
                            )}
                          >
                            {lineIndex === 0 ? line : (
                              <>
                                <span className="select-none text-foreground-faint">·</span>
                                <span className="min-w-0">{line}</span>
                              </>
                            )}
                          </li>
                        ))}
                      </ul>
                    </div>

                    <KeyValue
                      columns={2}
                      items={[
                        { label: "Entrypoint", value: item.route || item.entrypoint || "—", mono: true },
                        { label: "Controls on path", value: item.controls.join(", ") || "none" },
                        { label: "Sanitizers on path", value: item.sanitizers.join(", ") || "none" },
                        { label: "Covering tests", value: item.covering_tests.join(", ") || "none" },
                      ]}
                    />
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </Panel>

      {surface?.unreached_sinks?.length > 0 && (
        <Panel
          title="Sinks no entrypoint reaches"
          subtitle={`${surface.unreached_sinks.length} — unreached by this index, which is not a clearance`}
          bodyClassName="p-0"
        >
          <div className="max-h-56 divide-y divide-border overflow-auto">
            {surface.unreached_sinks.map((sink: string) => (
              <div key={sink} className="px-4 py-2 term text-foreground-muted">
                {sink}
              </div>
            ))}
          </div>
        </Panel>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Panel — test synthesis and execution
// ---------------------------------------------------------------------------
export function TestSynthesisPanel({ runId }: { runId: string }) {
  const tests = useResource(() => endpoints.runTests(runId), [runId]);
  const engines = useResource(() => endpoints.engines().catch(() => null), []);
  const [openPlan, setOpenPlan] = useState("");

  if (tests.state === "loading") return <LoadingPanel label="Loading generated tests" />;
  if (tests.state === "error")
    return <ErrorNote title="Could not load generated tests" detail={tests.error} />;

  const data = tests.data as TestsView;
  const plans = data.plans ?? [];
  const executions = data.executions ?? [];
  const byPlan = new Map(executions.map((execution) => [execution.plan_id, execution]));
  const inventory =
    engines.state === "ready" && engines.data ? (engines.data as EngineInventory) : null;

  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Metric label="Plans" value={data.counts?.plans ?? plans.length} hint={`${data.counts?.generated ?? 0} generated`} />
        <Metric
          label="Unsupported"
          value={data.counts?.unsupported ?? 0}
          tone={(data.counts?.unsupported ?? 0) > 0 ? "warn" : "default"}
          hint="strategy did NOT run"
        />
        <Metric label="Executions" value={data.counts?.executions ?? executions.length} />
        <Metric
          label="Reproduced"
          value={data.counts?.reproduced ?? 0}
          tone={(data.counts?.reproduced ?? 0) > 0 ? "refuted" : "default"}
          hint="oracle fired the required number of times"
        />
      </div>

      {plans.length === 0 ? (
        <NotRecorded
          title="Test synthesis"
          reason="This run generated no test plans. Either it predates test synthesis, or it stopped before reaching the stage."
        />
      ) : (
        <Panel title="Generated tests" subtitle="spec → harness → oracle" bodyClassName="p-0">
          <div className="divide-y divide-border">
            {plans.map((plan) => {
              const execution = byPlan.get(plan.plan_id);
              const open = openPlan === plan.plan_id;
              return (
                <div key={plan.plan_id} className={cn(open && "bg-surface-high/40")}>
                  <button
                    onClick={() => setOpenPlan(open ? "" : plan.plan_id)}
                    className="flex w-full flex-wrap items-center gap-2 px-4 py-3 text-left hover:bg-surface-high"
                  >
                    <Chip tone="accent">{plan.strategy}</Chip>
                    <span className="term text-foreground-muted">{plan.oracle_kind}</span>
                    <Chip tone="muted">{plan.engine || "no engine"}</Chip>
                    <Chip
                      tone={plan.proposed_by === "model" ? "info" : "muted"}
                      title={
                        plan.proposed_by === "model"
                          ? "The spec came from a model, then passed schema validation. KavachX generated the harness."
                          : "The spec came from the deterministic fallback — no model was involved."
                      }
                    >
                      {plan.proposed_by}
                    </Chip>
                    {plan.status === "UNSUPPORTED" ? (
                      <Chip tone="warn" title={plan.engine_reason}>
                        NOT RUN
                      </Chip>
                    ) : execution ? (
                      <Chip tone={execution.reproduced ? "refuted" : "verified"}>
                        {execution.reproduced
                          ? `REPRODUCED ${execution.reproduction_count}/${execution.reproductions_required}`
                          : "DID NOT REPRODUCE"}
                      </Chip>
                    ) : (
                      <Chip tone="muted">NOT EXECUTED</Chip>
                    )}
                    <span className="ml-auto hidden shrink-0 term text-foreground-faint lg:block">
                      {plan.plan_id.slice(0, 12)}
                    </span>
                    <ChevronRight
                      className={cn(
                        "h-3.5 w-3.5 shrink-0 text-foreground-faint transition-transform",
                        open && "rotate-90",
                      )}
                    />
                  </button>

                  {open && (
                    <div className="space-y-3 border-t border-border px-4 py-3">
                      <div className="rounded-md border border-border bg-surface/60 px-3 py-2">
                        <div className="panel-title mb-1">Security property under test</div>
                        <div className="text-small text-foreground-muted">
                          {plan.security_property || "—"}
                        </div>
                      </div>

                      <KeyValue
                        columns={2}
                        items={[
                          { label: "Candidate", value: plan.candidate_ref || "—", mono: true },
                          { label: "Finding", value: plan.finding_handle || "—", mono: true },
                          { label: "Language", value: plan.language || "—" },
                          { label: "Status", value: plan.status },
                          { label: "Harness", value: plan.harness_path || "not generated", mono: true },
                          {
                            label: "Harness sha256",
                            value: plan.harness_sha256 ? <Hash value={plan.harness_sha256} length={20} /> : "—",
                            mono: true,
                          },
                        ]}
                      />

                      {plan.status === "UNSUPPORTED" && plan.engine_reason && (
                        <WarningNote>
                          <span className="text-warn">This strategy did NOT run.</span>{" "}
                          {plan.engine_reason} An unavailable engine is never reported as a clean
                          result.
                        </WarningNote>
                      )}

                      {execution && <ExecutionDetail execution={execution} />}

                      <details>
                        <summary className="cursor-pointer font-mono text-mono-label uppercase text-foreground-subtle">
                          validated TestSpec
                        </summary>
                        <pre className="mt-1.5 max-h-72 overflow-auto term text-foreground-muted">
                          {JSON.stringify(plan.spec, null, 2)}
                        </pre>
                      </details>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </Panel>
      )}

      {inventory && (
        <Panel
          title="Engine inventory"
          subtitle={`${inventory.counts.available} available · ${inventory.counts.unavailable} unavailable · ${inventory.counts.unimplemented} unimplemented`}
          bodyClassName="p-0"
        >
          <div className="divide-y divide-border">
            {inventory.engines.map((engine) => (
              <div key={engine.id} className="flex flex-wrap items-center gap-2 px-4 py-2.5">
                <Chip
                  tone={
                    engine.status === "available"
                      ? "verified"
                      : engine.status === "unavailable"
                        ? "warn"
                        : "muted"
                  }
                >
                  {engine.status === "available" ? "AVAILABLE" : "NOT RUN"}
                </Chip>
                <span className="term text-foreground">{engine.label}</span>
                <span className="font-mono text-[10px] uppercase text-foreground-faint">
                  {engine.language} · {engine.strategies.join("/")}
                </span>
                {engine.coverage_feedback && (
                  <Chip tone="accent" title="Produces coverage feedback usable by the guided loop.">
                    COVERAGE
                  </Chip>
                )}
                {engine.reason && (
                  <span className="min-w-0 flex-1 truncate text-[11px] text-foreground-faint" title={engine.reason}>
                    {engine.reason}
                  </span>
                )}
              </div>
            ))}
          </div>
          <div className="border-t border-border px-4 py-2.5 text-small text-foreground-faint">
            {inventory.note}
            {inventory.caveat && <> {inventory.caveat}</>}
          </div>
        </Panel>
      )}
    </div>
  );
}

function ExecutionDetail({ execution }: { execution: TestsView["executions"][number] }) {
  const coverage = execution.coverage ?? {};
  const campaign = execution.campaign ?? {};
  const measured = coverage.measured !== false;

  return (
    <div className="space-y-3">
      <div className="rounded-md border border-border bg-surface/60 px-3 py-2">
        <div className="panel-title mb-1">Verdict</div>
        <div className="text-small text-foreground-muted">{execution.verdict_detail || "—"}</div>
        {execution.proving_evidence && (
          <div className="mt-1.5 term text-verified">{execution.proving_evidence}</div>
        )}
        {execution.error && <div className="mt-1.5 term text-refuted">{execution.error}</div>}
      </div>

      <KeyValue
        columns={2}
        items={[
          { label: "Input hash", value: <Hash value={execution.input_hash} length={20} />, mono: true },
          { label: "Index id", value: <Hash value={execution.index_id} length={20} />, mono: true },
          { label: "Commit", value: execution.commit_sha.slice(0, 12) || "—", mono: true },
          { label: "Duration", value: `${execution.duration_ms} ms`, mono: true },
          {
            label: "Sandbox adapter",
            value: (
              <Chip
                tone={execution.environment?.network_enforced ? "verified" : "warn"}
                title={
                  execution.environment?.network_enforced
                    ? "Network denial was structurally enforced."
                    : "This adapter is not an isolation boundary; a reproduction here is weaker evidence."
                }
              >
                {String(execution.environment?.adapter ?? "unknown")}
              </Chip>
            ),
          },
          {
            label: "Coverage",
            value: measured ? `${(coverage.percent ?? 0).toFixed(1)}%` : "NOT MEASURED",
            mono: true,
          },
        ]}
      />

      {!measured && coverage.reason && (
        <div className="text-small text-foreground-faint">
          Coverage was not measured: {String(coverage.reason)}. Zero here would have been a
          different claim.
        </div>
      )}

      {execution.attempts?.length > 0 && (
        <div>
          <div className="panel-title mb-1">
            Attempts — independent processes, one deterministic oracle each
          </div>
          <div className="max-h-40 overflow-auto rounded-md border border-border">
            {execution.attempts.map((attempt: any, index: number) => (
              <div
                key={index}
                className="flex flex-wrap items-center gap-3 border-b border-border px-3 py-1.5 last:border-0"
              >
                <span className="w-14 shrink-0 font-mono text-[10px] text-foreground-faint">
                  #{index}
                </span>
                <Chip tone={attempt.oracle === "FIRED" ? "refuted" : attempt.oracle === "HELD" ? "verified" : "muted"}>
                  {attempt.oracle ?? attempt.verdict ?? "—"}
                </Chip>
                <span className="term text-foreground-faint">exit {String(attempt.exit_code ?? "—")}</span>
                {Array.isArray(attempt.signals) && attempt.signals.length > 0 && (
                  <span className="term text-warn">{attempt.signals.join(",")}</span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {Object.keys(campaign).length > 0 && (
        <div>
          <div className="panel-title mb-1">Coverage-guided campaign</div>
          <KeyValue
            columns={2}
            items={[
              { label: "Rounds", value: campaign.rounds ?? 0, mono: true },
              { label: "Executions", value: campaign.executions ?? 0, mono: true },
              { label: "Corpus", value: campaign.corpus_size ?? 0, mono: true },
              { label: "Uncovered branches", value: campaign.uncovered_branches ?? 0, mono: true },
              {
                label: "Model inputs proposed",
                value: campaign.model_candidates ?? 0,
                mono: true,
              },
              {
                label: "…that reached new coverage",
                value: campaign.model_candidates_useful ?? 0,
                mono: true,
              },
            ]}
          />
          {campaign.stopped_because && (
            <div className="mt-1.5 text-small text-foreground-faint">
              Stopped because: {String(campaign.stopped_because)}
            </div>
          )}
          <p className="mt-1.5 text-small text-foreground-faint">
            Whether a proposed input was useful is decided by <span className="text-foreground-muted">re-measuring
            coverage</span>, not by the model&rsquo;s confidence in it.
          </p>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Panel — model context
// ---------------------------------------------------------------------------
export function ModelContextPanel({ runId }: { runId: string }) {
  const contexts = useResource(() => endpoints.runContexts(runId), [runId]);
  const [openHash, setOpenHash] = useState("");
  const detail = useResource(
    () => (openHash ? endpoints.runContext(runId, openHash) : Promise.resolve(null)),
    [runId, openHash],
  );

  if (contexts.state === "loading") return <LoadingPanel label="Loading model contexts" />;
  if (contexts.state === "error")
    return <ErrorNote title="Could not load model contexts" detail={contexts.error} />;

  const rows = contexts.data as ModelContextSummary[];
  if (rows.length === 0) {
    return (
      <NotRecorded
        title="Model context"
        reason="This run assembled no model context. A run with LLM_PROVIDER unset, or one that stopped before reasoning began, records none."
      />
    );
  }

  const full =
    detail.state === "ready" && detail.data ? (detail.data as ModelContextSummary) : null;

  return (
    <div className="space-y-4">
      <Panel title="What the model was given" subtitle={`${rows.length} context(s), newest first`} bodyClassName="p-0">
        <div className="divide-y divide-border">
          {rows.map((row) => {
            const open = openHash === row.context_hash;
            return (
              <div key={row.context_hash} className={cn(open && "bg-surface-high/40")}>
                <button
                  onClick={() => setOpenHash(open ? "" : row.context_hash)}
                  className="flex w-full flex-wrap items-center gap-2 px-4 py-3 text-left hover:bg-surface-high"
                >
                  <Chip tone="accent">{row.task || "unknown task"}</Chip>
                  <span className="min-w-0 truncate term text-foreground-muted" title={row.candidate_ref}>
                    {row.candidate_ref}
                  </span>
                  <Chip tone="muted">{row.size_chars.toLocaleString()} chars</Chip>
                  <Chip tone="muted">{row.tool_call_count} graph queries</Chip>
                  {row.dropped.length > 0 && (
                    <Chip tone="warn" title="Content was shed to fit the budget. What was dropped is listed below.">
                      {row.dropped.length} DROPPED
                    </Chip>
                  )}
                  <span className="ml-auto shrink-0">
                    <Hash value={row.context_hash} length={12} />
                  </span>
                  <ChevronRight
                    className={cn(
                      "h-3.5 w-3.5 shrink-0 text-foreground-faint transition-transform",
                      open && "rotate-90",
                    )}
                  />
                </button>

                {open && (
                  <div className="space-y-3 border-t border-border px-4 py-3">
                    <div className="rounded-md border border-border bg-surface/60 px-3 py-2 text-small text-foreground-faint">
                      {row.note}
                    </div>

                    <KeyValue
                      columns={2}
                      items={[
                        { label: "Provider", value: row.provider || "—" },
                        { label: "Model", value: row.model || "—", mono: true },
                        { label: "Context version", value: row.version, mono: true },
                        { label: "Size", value: `${row.size_chars.toLocaleString()} chars`, mono: true },
                      ]}
                    />

                    <div className="grid gap-4 lg:grid-cols-2">
                      <div>
                        <div className="panel-title mb-1">Budget used per section</div>
                        {Object.entries(row.used).map(([section, used]) => {
                          const ceiling = row.budget?.[section] ?? 0;
                          return (
                            <div key={section} className="mb-1.5">
                              <div className="flex items-baseline justify-between gap-2">
                                <span className="font-mono text-[10px] uppercase text-foreground-subtle">
                                  {section}
                                </span>
                                <span className="font-mono text-mono-data text-foreground-muted">
                                  {used.toLocaleString()}
                                  {ceiling ? ` / ${ceiling.toLocaleString()}` : ""}
                                </span>
                              </div>
                              {ceiling > 0 && <Progress value={(used / ceiling) * 100} />}
                            </div>
                          );
                        })}
                      </div>

                      <div>
                        <div className="panel-title mb-1">Selected</div>
                        <div className="max-h-40 overflow-auto">
                          {row.selected_functions.map((uid) => (
                            <div key={uid} className="truncate term text-foreground-muted" title={uid}>
                              {uid}
                            </div>
                          ))}
                          {row.selected_functions.length === 0 && (
                            <div className="text-small text-foreground-faint">
                              No function was selected.
                            </div>
                          )}
                        </div>
                        {row.code_slice_keys.length > 0 && (
                          <div className="mt-2">
                            <div className="panel-title mb-1">Code slices</div>
                            {row.code_slice_keys.map((key) => (
                              <div key={key} className="truncate term text-foreground-faint" title={key}>
                                {key}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>

                    {row.dropped.length > 0 && (
                      <div className="rounded-md border border-warn/40 bg-warn/[0.05] px-3 py-2">
                        <div className="panel-title mb-1 text-warn">Dropped for budget</div>
                        {row.dropped.map((line) => (
                          <div key={line} className="text-small text-foreground-muted">
                            {line}
                          </div>
                        ))}
                      </div>
                    )}

                    {full?.context_hash === row.context_hash && full.tool_calls && (
                      <div>
                        <div className="panel-title mb-1">
                          Graph queries — the complete record of what this context was built from
                        </div>
                        <div className="max-h-56 overflow-auto rounded-md border border-border">
                          {full.tool_calls.map((call: any, index: number) => (
                            <div
                              key={index}
                              className="flex flex-wrap items-center gap-3 border-b border-border px-3 py-1.5 last:border-0"
                            >
                              <span className="term text-accent">{call.name}</span>
                              <span className="min-w-0 flex-1 truncate text-[11px] text-foreground-faint">
                                {JSON.stringify(call.arguments)}
                              </span>
                              <span className="shrink-0 font-mono text-[10px] text-foreground-faint">
                                {call.result_items} items · {call.result_bytes} B · {call.duration_ms} ms
                              </span>
                              {call.truncated && <Chip tone="warn">TRUNCATED</Chip>}
                              {call.error && <Chip tone="refuted">{call.error}</Chip>}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    {detail.state === "loading" && openHash === row.context_hash && (
                      <div className="flex items-center gap-2 text-small text-foreground-faint">
                        <Loader2 className="h-3.5 w-3.5 animate-spin" /> Loading graph queries…
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </Panel>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Live strip — the intelligence events, as they arrive
// ---------------------------------------------------------------------------
export function IntelligenceLiveStrip({ events }: { events: Array<{ event: any }> }) {
  const index = [...events].reverse().find((e) => e.event.t === "index")?.event;
  const architecture = [...events].reverse().find((e) => e.event.t === "architecture")?.event;
  const flows = events.filter((e) => e.event.t === "security_flow").map((e) => e.event);
  const specs = events.filter((e) => e.event.t === "testspec").map((e) => e.event);
  const results = events.filter((e) => e.event.t === "test_result").map((e) => e.event);
  const coverage = [...events].reverse().find((e) => e.event.t === "coverage")?.event;

  if (!index && !architecture && flows.length === 0 && specs.length === 0) return null;

  return (
    <Panel title="Code intelligence" subtitle="live" bodyClassName="p-3">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {index && (
          <div className="rounded-md border border-border px-3 py-2">
            <div className="flex items-center gap-2">
              <Boxes className="h-3.5 w-3.5 text-accent" />
              <span className="panel-title">Index</span>
              <Chip tone={GRADE_TONE[index.health_grade] ?? "muted"}>{index.health_grade || "—"}</Chip>
            </div>
            <div className="mt-1 term text-foreground-muted">{index.graph_source}</div>
            <div className="term text-foreground-faint">
              {index.symbols} symbols · {index.relationships} edges ·{" "}
              {index.resolved_relationships} resolved
            </div>
          </div>
        )}

        {architecture && (
          <div className="rounded-md border border-border px-3 py-2">
            <div className="flex items-center gap-2">
              <Layers className="h-3.5 w-3.5 text-accent" />
              <span className="panel-title">Architecture</span>
              {!architecture.measured && <Chip tone="refuted">UNMEASURED</Chip>}
            </div>
            <div className="mt-1 term text-foreground-muted">{architecture.application_type}</div>
            <div className="term text-foreground-faint">
              {architecture.entrypoints} entrypoints · {architecture.surface_items} surface items
            </div>
          </div>
        )}

        {flows.length > 0 && (
          <div className="rounded-md border border-border px-3 py-2">
            <div className="flex items-center gap-2">
              <Network className="h-3.5 w-3.5 text-accent" />
              <span className="panel-title">Flows</span>
            </div>
            <div className="mt-1 term text-foreground-muted">{flows.length} evidenced</div>
            <div className="term text-foreground-faint">
              {flows.filter((f) => f.basis === "taint").length} taint-proven ·{" "}
              {flows.filter((f) => f.precision === "resolved").length} resolved
            </div>
          </div>
        )}

        {(specs.length > 0 || coverage) && (
          <div className="rounded-md border border-border px-3 py-2">
            <div className="flex items-center gap-2">
              <FlaskConical className="h-3.5 w-3.5 text-accent" />
              <span className="panel-title">Tests</span>
            </div>
            <div className="mt-1 term text-foreground-muted">
              {specs.length} generated · {results.filter((r) => r.reproduced).length} reproduced
            </div>
            {coverage && (
              <div className="term text-foreground-faint">
                coverage {coverage.percent.toFixed(0)}% · {coverage.model_candidates_useful}/
                {coverage.model_candidates} model inputs useful
              </div>
            )}
          </div>
        )}
      </div>

      {flows.length > 0 && (
        <div className="mt-3 max-h-40 overflow-auto rounded-md border border-border">
          {flows.slice(0, 20).map((flow) => (
            <div
              key={flow.ref}
              className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-1.5 last:border-0"
            >
              <SeverityChip severity={flow.severity} />
              <span className="term text-foreground">
                {flow.source_kind} <span className="text-foreground-faint">→</span> {flow.sink_kind}
              </span>
              <BasisChips basis={flow.basis} precision={flow.precision} />
              <span className="ml-auto shrink-0 font-mono text-[10px] text-foreground-faint">
                {flow.confidence.toFixed(2)}
              </span>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}

// Re-exported so callers can render a bound list without importing the module internals.
export { ClaimBounds, NotRecorded };
