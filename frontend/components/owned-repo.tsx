"use client";

import { GitBranch, KeyRound, Plus } from "lucide-react";
import { useEffect, useState } from "react";

import {
  ApiError,
  endpoints,
  type GithubConfig,
  type Project,
  type Repository,
} from "@/lib/api";

import { ErrorNote, Panel, Spinner, WarningNote } from "./ui";

/**
 * Attach a GitHub repository the configured fine-grained token can push to.
 *
 * This is the only attach path that can end in a pull request, so the panel says so plainly and
 * shows the publisher's current mode — a demo that promises a PR and then produces a dry-run
 * payload is worse than one that said "dry run" from the start.
 *
 * There is no preview step, unlike the public path. A preview would need to read the repository
 * before authority is confirmed, and the whole point of this path is that authority is confirmed
 * first: the backend asks GitHub whether the token actually has `push`, and rejects the attach
 * with GitHub's own answer if it does not.
 */
export function OwnedRepoAttach({
  projects,
  defaultProjectId,
  onAttached,
}: {
  projects: Project[];
  defaultProjectId?: string;
  onAttached: (repository: Repository) => void;
}) {
  const [input, setInput] = useState("");
  const [branch, setBranch] = useState("");
  const [projectId, setProjectId] = useState(defaultProjectId ?? projects[0]?.id ?? "");
  const [attaching, setAttaching] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [config, setConfig] = useState<GithubConfig | null>(null);
  const [error, setError] = useState<{ code: string; message: string } | null>(null);

  useEffect(() => {
    void (async () => {
      try {
        setConfig(await endpoints.githubApp());
      } catch {
        setConfig(null);
      }
    })();
  }, []);

  const attach = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!input.trim() || !projectId) return;
    setAttaching(true);
    setError(null);
    try {
      const repository = await endpoints.attachGithubRepo(
        projectId,
        input.trim(),
        branch.trim(),
      );
      onAttached(repository);
      setInput("");
      setBranch("");
      setConfirmed(false);
    } catch (exc) {
      setError(
        exc instanceof ApiError
          ? { code: exc.code, message: exc.message }
          : { code: "NETWORK_ERROR", message: "Could not reach the KavachX API." },
      );
    } finally {
      setAttaching(false);
    }
  };

  const tokenMissing = config !== null && !config.configured;

  return (
    <Panel
      title="Analyse a repository you can push to"
      actions={<KeyRound className="h-4 w-4 text-accent" />}
    >
      <p className="text-small text-foreground-muted">
        KavachX confirms with GitHub that the configured fine-grained token actually has{" "}
        <span className="font-mono text-[11px]">push</span> access before attaching. Your claim of
        authority is never taken at face value, and this is the only path that can end in a pull
        request.
      </p>

      {tokenMissing && (
        <div className="mt-3">
          <WarningNote>
            <span className="text-warn">No token configured.</span> Set{" "}
            <span className="font-mono text-[11px]">GITHUB_TOKEN</span> to a fine-grained personal
            access token with <span className="font-mono text-[11px]">Contents: read/write</span>{" "}
            and <span className="font-mono text-[11px]">Pull requests: read/write</span> on the
            repository, then restart the API. Without it, attach a public repository instead —
            analysis works, publishing does not.
          </WarningNote>
        </div>
      )}

      <form onSubmit={attach} className="mt-4 space-y-3">
        <div className="flex flex-col gap-3 sm:flex-row">
          <div className="flex-1">
            <label className="label" htmlFor="owned_repo">
              Repository URL or owner/repo
            </label>
            <input
              id="owned_repo"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              className="field font-mono"
              placeholder="https://github.com/your-org/your-service"
              required
              minLength={3}
              disabled={tokenMissing}
            />
          </div>
          <div className="sm:w-44">
            <label className="label" htmlFor="owned_branch">
              Branch (optional)
            </label>
            <input
              id="owned_branch"
              value={branch}
              onChange={(e) => setBranch(e.target.value)}
              className="field font-mono"
              placeholder="default branch"
              disabled={tokenMissing}
            />
          </div>
        </div>

        <div>
          <label className="label" htmlFor="owned_project">
            Project
          </label>
          <select
            id="owned_project"
            value={projectId}
            onChange={(e) => setProjectId(e.target.value)}
            className="field"
            disabled={tokenMissing}
          >
            {projects.map((project) => (
              <option key={project.id} value={project.id}>
                {project.name}
              </option>
            ))}
          </select>
        </div>

        {error && <ErrorNote title="Could not attach" detail={error.message} code={error.code} />}

        <div className="rounded-md border border-border bg-surface-lowest p-3">
          <div className="flex items-center gap-2 font-mono text-[10px] uppercase text-foreground-faint">
            <GitBranch className="h-3 w-3" />
            what happens on a run
          </div>
          <ul className="mt-2 space-y-1 text-[11px] leading-4 text-foreground-muted">
            <li>
              The repository is <span className="text-foreground">cloned</span> outside the sandbox
              at ingest, pinned to a real commit, then hashed. Submodules are not followed and
              symlinks are removed before the tree is pinned.
            </li>
            <li>
              A verified repair can be published to a new{" "}
              <span className="font-mono text-[11px]">kavachx/</span> branch as a pull request —
              never to the default branch, never force-pushed, and only after a human with{" "}
              <span className="font-mono text-[11px]">patch:publish</span> approves.
            </li>
            {config && (
              <li>
                Publisher is currently{" "}
                <span className={config.publisher_dry_run ? "text-warn" : "text-verified"}>
                  {config.publisher_dry_run ? "in DRY RUN" : "LIVE"}
                </span>
                {config.publisher_dry_run
                  ? " — approving a publish produces the exact payload rather than opening a pull request. Set PUBLISHER_DRY_RUN=false to open real pull requests."
                  : " — approving a publish opens a real pull request on GitHub."}
              </li>
            )}
          </ul>
        </div>

        <label className="flex cursor-pointer items-start gap-2.5 rounded-md border border-warn/40 bg-warn/[0.05] p-3">
          <input
            type="checkbox"
            checked={confirmed}
            onChange={(e) => setConfirmed(e.target.checked)}
            className="mt-0.5 accent-accent"
            disabled={tokenMissing}
          />
          <span className="text-small text-foreground">
            I am authorised to analyse this repository. I understand KavachX will clone it, execute
            its code in a sandbox and generate working exploits against it, and that every action is
            recorded in the audit log against my account.
          </span>
        </label>

        <button
          type="submit"
          disabled={attaching || !confirmed || !projectId || !input.trim() || tokenMissing}
          className="btn-primary w-full"
        >
          {attaching ? <Spinner className="text-accent-on" /> : <Plus className="h-4 w-4" />}
          Verify push access and attach
        </button>
      </form>
    </Panel>
  );
}
