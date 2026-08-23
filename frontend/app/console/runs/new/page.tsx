"use client";

import { Github, Play, ShieldAlert } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { PublicRepoAttach } from "@/components/public-repo";
import { ApiError, endpoints, type Project, type Repository } from "@/lib/api";
import { Chip, ErrorNote, LoadingPanel, Panel, Spinner, WarningNote } from "@/components/ui";

/**
 * Providers that can reach the Publisher — mirrors PUBLISHABLE_PROVIDERS in the backend.
 *
 * `github_public` is absent on purpose: it is somebody else's repository, so a verified patch is
 * delivered as a run artifact rather than a pull request.
 */
const PUBLISHABLE_PROVIDERS = new Set(["github", "local_seeded"]);

const ANALYSIS_PROFILES = [
  {
    id: "quick",
    label: "Quick",
    detail: "3 validations, 60 fuzz cases. Fastest path through the full pipeline.",
  },
  {
    id: "standard",
    label: "Standard",
    detail: "8 validations, 160 fuzz cases. The default.",
  },
  {
    id: "deep",
    label: "Deep",
    detail: "20 validations, 400 fuzz cases. Longest, widest coverage.",
  },
];

const EXECUTION_PROFILES = [
  {
    id: "dev_local",
    label: "Development (local subprocess)",
    detail: "NOT an isolation boundary. The target runs as a subprocess on the HOST and uses the host's runtime (your installed node/python) — only workspace files and installed packages (node_modules) are per-run isolated, not the runtime or OS. Credentials are withheld and Python targets run under an in-process network guard, but there is no kernel-level confinement.",
    safe: false,
  },
  {
    id: "gvisor",
    label: "gVisor (runsc)",
    detail: "Runs inside a container — the runtime comes from the sandbox image, not your host. Userspace kernel, no network interface, read-only root, dropped capabilities, seccomp. Requires Docker (Linux/WSL2) with the runsc runtime registered.",
    safe: true,
  },
  {
    id: "firecracker",
    label: "Firecracker microVM",
    detail: "Hardware virtualisation with a dedicated guest kernel. Requires Linux with KVM and provisioned guest assets.",
    safe: true,
  },
];

// Quick client-side count of KEY=VALUE lines in a pasted .env (the server does the real parse).
function countEnvLines(text: string): number {
  return text
    .split("\n")
    .filter((line) => /^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=/.test(line)).length;
}

// Parse the benign-requests box: one JSON object per line (a CLI request, or {method, path}).
function parseBenignRequests(text: string): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = [];
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) out.push(parsed);
    } catch {
      // ignore malformed lines — the count hint shows the user how many parsed
    }
  }
  return out;
}

export default function NewRunPage() {
  const router = useRouter();
  const [repositories, setRepositories] = useState<Repository[] | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);
  const [showPublic, setShowPublic] = useState(false);
  const [repositoryId, setRepositoryId] = useState("");
  const [branch, setBranch] = useState("main");
  const [commitSha, setCommitSha] = useState("");
  const [analysisProfile, setAnalysisProfile] = useState("standard");
  const [executionProfile, setExecutionProfile] = useState("dev_local");
  const [maxRuntime, setMaxRuntime] = useState(1800);
  const [memoryMb, setMemoryMb] = useState(2048);
  const [tokenBudget, setTokenBudget] = useState(400000);
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  // Vercel/Render-style run configuration (optional; blank means auto-detect at ingest).
  const [rootDirectory, setRootDirectory] = useState("");
  const [installCommand, setInstallCommand] = useState("");
  const [buildCommand, setBuildCommand] = useState("");
  const [startCommand, setStartCommand] = useState("");
  const [targetType, setTargetType] = useState("auto");
  const [envText, setEnvText] = useState("");
  const [envRows, setEnvRows] = useState<{ key: string; value: string }[]>([]);
  const [benignText, setBenignText] = useState("");

  useEffect(() => {
    void (async () => {
      try {
        const [list, projectList] = await Promise.all([
          endpoints.repositories(),
          endpoints.projects().catch(() => []),
        ]);
        setRepositories(list);
        setProjects(projectList);
        const verified = list.find((r) => r.authority_verified_at);
        if (verified) {
          setRepositoryId(verified.id);
          setBranch(verified.default_branch);
        }
        if (list.length === 0) setShowPublic(true);
      } catch (exc) {
        if (exc instanceof ApiError) setError(exc);
        setRepositories([]);
      }
    })();
  }, []);

  const onPublicAttached = (repository: Repository) => {
    setRepositories((current) => [repository, ...(current ?? [])]);
    setRepositoryId(repository.id);
    setBranch(repository.default_branch);
    setShowPublic(false);
    setError(null);
  };

  const selected = repositories?.find((r) => r.id === repositoryId);
  const selectedPublishable = selected
    ? PUBLISHABLE_PROVIDERS.has(selected.provider)
    : true;

  const start = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const env_vars = Object.fromEntries(
        envRows.filter((r) => r.key.trim()).map((r) => [r.key.trim(), r.value]),
      );
      const run = await endpoints.createRun({
        repository_id: repositoryId,
        branch,
        commit_sha: commitSha,
        analysis_profile: analysisProfile,
        execution_profile: executionProfile,
        max_runtime_seconds: maxRuntime,
        authorisation_confirmed: confirmed,
        root_directory: rootDirectory.trim(),
        install_command: installCommand.trim(),
        build_command: buildCommand.trim(),
        start_command: startCommand.trim(),
        target_type: targetType,
        env_text: envText,
        env_vars,
        benign_requests: parseBenignRequests(benignText),
      });
      router.push(`/console/runs/${run.id}`);
    } catch (exc) {
      if (exc instanceof ApiError) setError(exc);
      setBusy(false);
    }
  };

  if (repositories === null) return <LoadingPanel label="Loading repositories" />;

  const chosenExecution = EXECUTION_PROFILES.find((p) => p.id === executionProfile);

  return (
    <div className="mx-auto max-w-3xl space-y-5">
      <header>
        <h1 className="text-headline-md">New Security Run</h1>
        <p className="mt-1 text-small text-foreground-muted">
          The repository is pinned to an immutable content hash before anything executes.
        </p>
      </header>

      {showPublic && (
        <PublicRepoAttach
          projects={projects}
          defaultProjectId={projects[0]?.id}
          onAttached={onPublicAttached}
        />
      )}

      {repositories.length === 0 && !showPublic ? (
        <Panel title="No authorised repository">
          <p className="text-small text-foreground-muted">
            KavachX cannot start a run without a repository it has verified authority over. Attach a
            public GitHub repository below, configure a fine-grained token with push access for a
            private one, or use the seeded local target in development mode.
          </p>
          <div className="mt-4 flex flex-wrap gap-2">
            <button onClick={() => setShowPublic(true)} className="btn-primary text-xs">
              <Github className="h-3.5 w-3.5" />
              Analyse a public repository
            </button>
            <a href="/console/projects" className="btn-secondary text-xs">
              Go to Projects
            </a>
          </div>
        </Panel>
      ) : (
        <form onSubmit={start} className="space-y-5">
          <Panel
            title="Target"
            actions={
              <button
                type="button"
                onClick={() => setShowPublic((v) => !v)}
                className="flex items-center gap-1.5 font-mono text-mono-label uppercase text-accent hover:underline"
              >
                <Github className="h-3.5 w-3.5" />
                {showPublic ? "hide" : "add a public repo"}
              </button>
            }
          >
            <div className="space-y-4">
              <div>
                <label className="label" htmlFor="repository">
                  Repository
                </label>
                <select
                  id="repository"
                  value={repositoryId}
                  onChange={(e) => {
                    setRepositoryId(e.target.value);
                    const next = repositories.find((r) => r.id === e.target.value);
                    if (next) setBranch(next.default_branch);
                  }}
                  className="field"
                  required
                >
                  <option value="">Select a repository…</option>
                  {repositories.map((repository) => (
                    <option
                      key={repository.id}
                      value={repository.id}
                      disabled={!repository.authority_verified_at}
                    >
                      {repository.full_name}
                      {repository.authority_verified_at ? "" : " (authority not verified)"}
                    </option>
                  ))}
                </select>
                {selected && (
                  <div className="mt-2 flex flex-wrap items-center gap-2">
                    <Chip tone="muted">{selected.provider}</Chip>
                    <Chip tone={selected.authority_verified_at ? "verified" : "refuted"}>
                      AUTHORITY {selected.authority_verified_at ? "VERIFIED" : "MISSING"}
                    </Chip>
                    <Chip tone={selectedPublishable ? "verified" : "warn"}>
                      {selectedPublishable ? "CAN PUBLISH" : "ANALYSIS ONLY"}
                    </Chip>
                    {selected.local_path && (
                      <span className="truncate term text-foreground-faint" title={selected.local_path}>
                        {selected.local_path}
                      </span>
                    )}
                  </div>
                )}
                {selected && !selectedPublishable && (
                  <p className="mt-2 text-[11px] leading-4 text-foreground-faint">
                    KavachX holds no credential for this repository, so a verified patch will be
                    delivered as a run artifact rather than a pull request.
                  </p>
                )}
              </div>

              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <label className="label" htmlFor="branch">
                    Branch
                  </label>
                  <input
                    id="branch"
                    value={branch}
                    onChange={(e) => setBranch(e.target.value)}
                    className="field"
                    required
                  />
                </div>
                <div>
                  <label className="label" htmlFor="commit">
                    Commit SHA
                  </label>
                  <input
                    id="commit"
                    value={commitSha}
                    onChange={(e) => setCommitSha(e.target.value.trim())}
                    className="field font-mono"
                    placeholder="blank = pin by content hash"
                    pattern="[0-9a-fA-F]*"
                  />
                </div>
              </div>
            </div>
          </Panel>

          <Panel
            title="Run configuration"
            subtitle="How to install, run and reach the target — like Vercel/Render. Blank = auto-detect."
          >
            <div className="space-y-4">
              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <label className="label" htmlFor="root_directory">
                    Root directory
                  </label>
                  <input
                    id="root_directory"
                    value={rootDirectory}
                    onChange={(e) => setRootDirectory(e.target.value)}
                    className="field font-mono"
                    placeholder="blank = repo root (e.g. services/api)"
                  />
                </div>
                <div>
                  <label className="label" htmlFor="target_type">
                    Target type
                  </label>
                  <select
                    id="target_type"
                    value={targetType}
                    onChange={(e) => setTargetType(e.target.value)}
                    className="field"
                  >
                    <option value="auto">Auto-detect</option>
                    <option value="cli">CLI — request → output</option>
                    <option value="http">Web server — driven over HTTP</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="label" htmlFor="install_command">
                  Install command
                </label>
                <input
                  id="install_command"
                  value={installCommand}
                  onChange={(e) => setInstallCommand(e.target.value)}
                  className="field font-mono"
                  placeholder="npm install   ·   pip install -r requirements.txt   ·   cargo build"
                />
              </div>

              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <label className="label" htmlFor="build_command">
                    Build command <span className="text-foreground-faint">(optional)</span>
                  </label>
                  <input
                    id="build_command"
                    value={buildCommand}
                    onChange={(e) => setBuildCommand(e.target.value)}
                    className="field font-mono"
                    placeholder="npm run build"
                  />
                </div>
                <div>
                  <label className="label" htmlFor="start_command">
                    Start / run command
                  </label>
                  <input
                    id="start_command"
                    value={startCommand}
                    onChange={(e) => setStartCommand(e.target.value)}
                    className="field font-mono"
                    placeholder={
                      targetType === "http"
                        ? "npm start   ·   uvicorn app:app"
                        : "node cli.js --request {payload}"
                    }
                  />
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between">
                  <label className="label" htmlFor="benign_requests">
                    Benign requests{" "}
                    <span className="text-foreground-faint">(optional — auto-generated if blank)</span>
                  </label>
                  <span className="font-mono text-[10px] text-foreground-faint">
                    {parseBenignRequests(benignText).length} parsed
                  </span>
                </div>
                <textarea
                  id="benign_requests"
                  value={benignText}
                  onChange={(e) => setBenignText(e.target.value)}
                  className="field font-mono min-h-[80px]"
                  placeholder={
                    targetType === "http"
                      ? "leave blank — KavachX discovers your routes and generates requests\nor seed one per line: {\"method\":\"GET\",\"path\":\"/export?name=report\"}"
                      : "leave blank — KavachX derives requests from the CLI's ops and fields\nor seed one per line: {\"op\":\"export\",\"name\":\"report\"}"
                  }
                  spellCheck={false}
                />
                <p className="mt-1 text-[11px] leading-4 text-foreground-faint">
                  Leave blank for fully automatic analysis: KavachX discovers the interface
                  (routes / CLI ops), generates candidate requests, verifies each by running it, and
                  fuzzes what works. Add lines only to seed or reach auth-gated paths.
                </p>
              </div>

              <div>
                <div className="flex items-center justify-between">
                  <label className="label" htmlFor="env_text">
                    Environment variables
                  </label>
                  <span className="font-mono text-[10px] text-foreground-faint">
                    {countEnvLines(envText) + envRows.filter((r) => r.key.trim()).length} variable(s)
                  </span>
                </div>
                <textarea
                  id="env_text"
                  value={envText}
                  onChange={(e) => setEnvText(e.target.value)}
                  className="field font-mono min-h-[96px]"
                  placeholder={"Paste a .env to bulk-add:\nDATABASE_URL=postgres://...\nAPI_KEY=sk-..."}
                  spellCheck={false}
                />
                <p className="mt-1 text-[11px] leading-4 text-foreground-faint">
                  Injected into the target when it runs so it can start. They are the target&apos;s
                  own secrets — see the isolation note; do not paste anything you would not run in
                  the sandbox.
                </p>

                {envRows.length > 0 && (
                  <div className="mt-2 space-y-2">
                    {envRows.map((row, i) => (
                      <div key={i} className="flex gap-2">
                        <input
                          value={row.key}
                          onChange={(e) =>
                            setEnvRows((rows) =>
                              rows.map((r, idx) => (idx === i ? { ...r, key: e.target.value } : r)),
                            )
                          }
                          className="field font-mono"
                          placeholder="KEY"
                        />
                        <input
                          value={row.value}
                          onChange={(e) =>
                            setEnvRows((rows) =>
                              rows.map((r, idx) =>
                                idx === i ? { ...r, value: e.target.value } : r,
                              ),
                            )
                          }
                          className="field font-mono"
                          placeholder="value"
                        />
                        <button
                          type="button"
                          onClick={() => setEnvRows((rows) => rows.filter((_, idx) => idx !== i))}
                          className="btn-ghost px-2"
                          aria-label="Remove variable"
                        >
                          ✕
                        </button>
                      </div>
                    ))}
                  </div>
                )}
                <button
                  type="button"
                  onClick={() => setEnvRows((rows) => [...rows, { key: "", value: "" }])}
                  className="btn-secondary mt-2 text-xs"
                >
                  + Add variable
                </button>
              </div>
            </div>
          </Panel>

          <Panel title="Analysis profile">
            <div className="space-y-2">
              {ANALYSIS_PROFILES.map((profile) => (
                <label
                  key={profile.id}
                  className={`flex cursor-pointer gap-3 rounded-md border p-3 transition-colors ${
                    analysisProfile === profile.id
                      ? "border-accent/60 bg-accent/[0.06]"
                      : "border-border hover:border-border-strong"
                  }`}
                >
                  <input
                    type="radio"
                    name="analysis"
                    value={profile.id}
                    checked={analysisProfile === profile.id}
                    onChange={() => setAnalysisProfile(profile.id)}
                    className="mt-1 accent-accent"
                  />
                  <div>
                    <div className="font-mono text-mono-data text-foreground">{profile.label}</div>
                    <div className="text-[11px] leading-4 text-foreground-faint">
                      {profile.detail}
                    </div>
                  </div>
                </label>
              ))}
            </div>
          </Panel>

          <Panel title="Execution profile">
            <div className="space-y-2">
              {EXECUTION_PROFILES.map((profile) => (
                <label
                  key={profile.id}
                  className={`flex cursor-pointer gap-3 rounded-md border p-3 transition-colors ${
                    executionProfile === profile.id
                      ? "border-accent/60 bg-accent/[0.06]"
                      : "border-border hover:border-border-strong"
                  }`}
                >
                  <input
                    type="radio"
                    name="execution"
                    value={profile.id}
                    checked={executionProfile === profile.id}
                    onChange={() => setExecutionProfile(profile.id)}
                    className="mt-1 accent-accent"
                  />
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-mono-data text-foreground">
                        {profile.label}
                      </span>
                      <Chip tone={profile.safe ? "verified" : "warn"}>
                        {profile.safe ? "ISOLATION BOUNDARY" : "DEV ONLY"}
                      </Chip>
                    </div>
                    <div className="text-[11px] leading-4 text-foreground-faint">
                      {profile.detail}
                    </div>
                  </div>
                </label>
              ))}
            </div>
            {chosenExecution && !chosenExecution.safe && (
              <div className="mt-3">
                <WarningNote>
                  You have selected the development adapter. It executes the target as a subprocess
                  <strong> on this host, using the host&apos;s own runtime</strong> (your installed
                  node/python) — the workspace files and installed packages are isolated per run, but
                  the runtime and OS are <strong>not</strong>. For a sandbox that provides its own
                  runtime and kernel-level confinement, use <strong>gVisor</strong> (Linux/WSL2).
                  Use the dev adapter only for code you already trust — such as the seeded demo
                  targets.
                </WarningNote>
              </div>
            )}
          </Panel>

          <Panel title="Limits and budget">
            <div className="grid gap-4 sm:grid-cols-3">
              <div>
                <label className="label" htmlFor="runtime">
                  Max runtime (s)
                </label>
                <input
                  id="runtime"
                  type="number"
                  min={60}
                  max={14400}
                  value={maxRuntime}
                  onChange={(e) => setMaxRuntime(Number(e.target.value))}
                  className="field font-mono"
                />
              </div>
              <div>
                <label className="label" htmlFor="memory">
                  Sandbox memory (MB)
                </label>
                <input
                  id="memory"
                  type="number"
                  min={256}
                  max={16384}
                  value={memoryMb}
                  onChange={(e) => setMemoryMb(Number(e.target.value))}
                  className="field font-mono"
                />
              </div>
              <div>
                <label className="label" htmlFor="tokens">
                  Token budget
                </label>
                <input
                  id="tokens"
                  type="number"
                  min={10000}
                  step={10000}
                  value={tokenBudget}
                  onChange={(e) => setTokenBudget(Number(e.target.value))}
                  className="field font-mono"
                />
              </div>
            </div>
            <p className="mt-3 text-[11px] leading-4 text-foreground-faint">
              Exceeding a ceiling aborts the run rather than degrading it silently. Iteration
              limits are fixed: harness ≤ 3, patch ≤ 3, clause ≤ 2 — there is no path to an
              unbounded autonomous loop.
            </p>
          </Panel>

          <div className="rounded-lg border border-warn/45 bg-warn/[0.05] p-4">
            <div className="mb-2 flex items-center gap-2 font-mono text-mono-label uppercase text-warn">
              <ShieldAlert className="h-4 w-4" />
              Authorisation required
            </div>
            <p className="text-small leading-relaxed text-foreground-muted">
              Only analyse repositories and systems for which you have explicit authorisation.
              This run will execute the target's code, generate working exploits against it, and
              record every action in a hash-chained audit log attributed to your account.
            </p>
            <label className="mt-3 flex cursor-pointer items-start gap-2.5">
              <input
                type="checkbox"
                checked={confirmed}
                onChange={(e) => setConfirmed(e.target.checked)}
                className="mt-0.5 accent-accent"
                required
              />
              <span className="text-small text-foreground">
                I confirm I am authorised to analyse this repository.
              </span>
            </label>
          </div>

          {error && (
            <ErrorNote
              title="Could not start the run"
              detail={error.message}
              code={error.code}
              requestId={error.requestId}
            />
          )}

          <button
            type="submit"
            disabled={busy || !confirmed || !repositoryId}
            className="btn-primary w-full"
          >
            {busy ? <Spinner className="text-accent-on" /> : <Play className="h-4 w-4" />}
            Start KavachX Analysis
          </button>
        </form>
      )}
    </div>
  );
}
