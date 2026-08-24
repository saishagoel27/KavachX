"use client";

import { Github, Play, ShieldAlert } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { PublicRepoAttach } from "@/components/public-repo";
import {
  ApiError,
  endpoints,
  type Framework,
  type Project,
  type Repository,
  type SystemLimits,
} from "@/lib/api";
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

/**
 * Framework signatures for client-side inference — mirrors `infer_framework` in the backend
 * (app/analysis/frameworks.py), ordered most-specific first so "next" wins over the generic "npm".
 * The API's framework list carries labels/commands/ports but not these substrings, so they live here.
 */
const FRAMEWORK_SIGNATURES: [string, string[]][] = [
  ["next", ["next"]],
  ["nestjs", ["nest"]],
  ["remix", ["remix"]],
  ["fastify", ["fastify"]],
  ["koa", ["koa"]],
  ["express", ["express"]],
  ["hardhat", ["hardhat"]],
  ["fastapi", ["uvicorn", "fastapi", "hypercorn"]],
  ["django", ["manage.py", "django"]],
  ["flask", ["flask", "gunicorn"]],
  ["spring", ["spring", "mvnw", "gradlew", "mvn", "gradle"]],
  ["go-http", ["go run", "go build", "go "]],
  ["rust-http", ["actix", "axum", "rocket", "warp", "cargo run", "cargo"]],
  ["python-http", ["starlette", "aiohttp", "tornado", "sanic"]],
  ["node-http", ["npm", "node", "pnpm", "yarn"]],
  ["python-cli", ["python", "pip", "uv", "poetry"]],
];

function inferFrameworkId(install: string, build: string, start: string): string {
  const blob = `${install} ${build} ${start}`.toLowerCase();
  if (!blob.trim()) return "auto";
  for (const [id, sigs] of FRAMEWORK_SIGNATURES) {
    if (sigs.some((s) => blob.includes(s))) return id;
  }
  return "auto";
}

/**
 * Minimal fallback so the dropdown and prefills still work if `/api/system/frameworks` is briefly
 * unreachable. The full list normally comes from the backend registry.
 */
const FALLBACK_FRAMEWORKS: Framework[] = [
  { id: "next", label: "Next.js", language: "node", kind: "http", port: 3000, install: "npm install", build: "npm run build", start: "npm run start" },
  { id: "express", label: "Express", language: "node", kind: "http", port: 3000, install: "npm install", build: "", start: "npm start" },
  { id: "node-cli", label: "Node (CLI)", language: "node", kind: "cli", port: 0, install: "npm install", build: "", start: "node ." },
  { id: "fastapi", label: "FastAPI", language: "python", kind: "http", port: 8000, install: "pip install -r requirements.txt", build: "", start: "uvicorn app.main:app --host 0.0.0.0 --port 8000" },
  { id: "flask", label: "Flask", language: "python", kind: "http", port: 5000, install: "pip install -r requirements.txt", build: "", start: "flask run --host 0.0.0.0" },
  { id: "django", label: "Django", language: "python", kind: "http", port: 8000, install: "pip install -r requirements.txt", build: "", start: "python manage.py runserver 0.0.0.0:8000" },
  { id: "python-cli", label: "Python (CLI)", language: "python", kind: "cli", port: 0, install: "pip install -r requirements.txt", build: "", start: "python main.py" },
  { id: "spring", label: "Spring Boot", language: "java", kind: "http", port: 8080, install: "./mvnw -q -DskipTests package", build: "", start: "java -jar target/*.jar" },
  { id: "go-http", label: "Go (HTTP)", language: "go", kind: "http", port: 8080, install: "go mod download", build: "go build -o app .", start: "./app" },
  { id: "rust-http", label: "Rust (Actix/Axum/Rocket)", language: "rust", kind: "http", port: 8080, install: "cargo build --release", build: "", start: "./target/release/app" },
  { id: "hardhat", label: "Hardhat (Solidity)", language: "node", kind: "cli", port: 0, install: "npm install", build: "npx hardhat compile", start: "npx hardhat test" },
  { id: "auto", label: "Auto-detect / Other", language: "", kind: "", port: 0, install: "", build: "", start: "" },
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

// Keep at most one row per id. A repository can otherwise appear twice — re-attaching one already
// in the list, or the API returning it more than once — which produces duplicate React keys.
function dedupeById<T extends { id: string }>(items: T[]): T[] {
  const seen = new Set<string>();
  const out: T[] = [];
  for (const item of items) {
    if (!seen.has(item.id)) {
      seen.add(item.id);
      out.push(item);
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
  // Backend-enforced ceilings. Sandbox memory/CPU and the token budget are set on the backend and
  // apply to every run — the form shows them read-only so a user can't request more than allowed.
  const [limits, setLimits] = useState<SystemLimits | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  // Vercel/Render-style run configuration (optional; blank means auto-detect at ingest).
  const [rootDirectory, setRootDirectory] = useState("");
  const [installCommand, setInstallCommand] = useState("");
  const [buildCommand, setBuildCommand] = useState("");
  const [startCommand, setStartCommand] = useState("");
  const [targetType, setTargetType] = useState("auto");
  const [framework, setFramework] = useState("auto");
  const [frameworkTouched, setFrameworkTouched] = useState(false);
  const [frameworks, setFrameworks] = useState<Framework[]>(FALLBACK_FRAMEWORKS);
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
        setRepositories(dedupeById(list));
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
    // The framework list backs the dropdown; keep the fallback if it can't be fetched.
    void endpoints
      .frameworks()
      .then((r) => {
        if (r.frameworks?.length) setFrameworks(r.frameworks);
      })
      .catch(() => {});
    // Backend ceilings — used to cap max-runtime and to show the real sandbox memory / token budget.
    void endpoints
      .limits()
      .then((l) => {
        setLimits(l);
        // Default the runtime to the backend ceiling and never exceed it.
        setMaxRuntime((current) => Math.min(current, l.run_max_runtime_seconds));
      })
      .catch(() => {});
  }, []);

  // Auto-infer the framework from the commands the operator types — until they pick one by hand.
  useEffect(() => {
    if (frameworkTouched) return;
    setFramework(inferFrameworkId(installCommand, buildCommand, startCommand));
  }, [installCommand, buildCommand, startCommand, frameworkTouched]);

  // Manual override: remember the choice, prefill any *empty* command fields, and sync target type.
  const onSelectFramework = (id: string) => {
    setFramework(id);
    setFrameworkTouched(true);
    const fw = frameworks.find((f) => f.id === id);
    if (!fw) return;
    if (!installCommand.trim() && fw.install) setInstallCommand(fw.install);
    if (!buildCommand.trim() && fw.build) setBuildCommand(fw.build);
    if (!startCommand.trim() && fw.start) setStartCommand(fw.start);
    if (fw.kind === "http" || fw.kind === "cli") setTargetType(fw.kind);
  };

  const onPublicAttached = (repository: Repository) => {
    setRepositories((current) => dedupeById([repository, ...(current ?? [])]));
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
        framework: framework === "auto" ? "" : framework,
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
              <div>
                <div className="flex items-center justify-between">
                  <label className="label" htmlFor="framework">
                    Framework
                  </label>
                  {framework !== "auto" && (
                    <span className="font-mono text-[10px] text-foreground-faint">
                      {frameworkTouched ? "selected" : "auto-detected from commands"}
                    </span>
                  )}
                </div>
                <select
                  id="framework"
                  value={framework}
                  onChange={(e) => onSelectFramework(e.target.value)}
                  className="field"
                >
                  {frameworks.map((fw) => (
                    <option key={fw.id} value={fw.id}>
                      {fw.label}
                      {fw.language ? ` · ${fw.language}` : ""}
                      {fw.kind ? ` · ${fw.kind}` : ""}
                    </option>
                  ))}
                </select>
                <p className="mt-1 text-[11px] leading-4 text-foreground-faint">
                  Sets the sandbox toolchain (Node / Python / Java / Go / Rust) and whether the target
                  is driven over HTTP or as a CLI. Auto-set from your commands — override it if wrong.
                  Picking one prefills any empty command fields below.
                </p>
              </div>

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
                  max={limits?.run_max_runtime_seconds ?? 14400}
                  value={maxRuntime}
                  onChange={(e) => {
                    const cap = limits?.run_max_runtime_seconds ?? 14400;
                    setMaxRuntime(Math.min(Math.max(60, Number(e.target.value) || 60), cap));
                  }}
                  className="field font-mono"
                />
                {limits && (
                  <p className="mt-1 text-[10px] text-foreground-faint">
                    max {limits.run_max_runtime_seconds}s (backend ceiling)
                  </p>
                )}
              </div>
              <div>
                <label className="label">
                  Sandbox memory (MB){" "}
                  <span className="text-foreground-faint">· set on backend</span>
                </label>
                <div className="field font-mono flex items-center text-foreground-muted">
                  {limits ? limits.sandbox.memory_mb : "—"}
                </div>
                {limits && (
                  <p className="mt-1 text-[10px] text-foreground-faint">
                    {limits.sandbox.cpu_limit} CPU · applies to every run
                  </p>
                )}
              </div>
              <div>
                <label className="label">
                  Token budget <span className="text-foreground-faint">· set on backend</span>
                </label>
                <div className="field font-mono flex items-center text-foreground-muted">
                  {limits ? limits.token_budget_per_run.toLocaleString() : "—"}
                </div>
                {limits && (
                  <p className="mt-1 text-[10px] text-foreground-faint">per-run, backend-enforced</p>
                )}
              </div>
            </div>
            <p className="mt-3 text-[11px] leading-4 text-foreground-faint">
              Sandbox memory/CPU and the token budget are configured on the backend and applied to
              every run — you cannot request more here. Runtime is capped to the backend ceiling.
              Exceeding any of these aborts the run rather than degrading it silently; iteration
              limits are fixed (harness ≤ {limits?.iteration_limits.harness ?? 3}, patch ≤{" "}
              {limits?.iteration_limits.patch ?? 3}, clause ≤ {limits?.iteration_limits.clause ?? 2}).
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
