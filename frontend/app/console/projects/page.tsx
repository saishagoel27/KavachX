"use client";

import { FolderGit2, Github, Plus, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";

import { PublicRepoAttach } from "@/components/public-repo";
import { ApiError, endpoints, type Project, type Repository } from "@/lib/api";
import { useMe } from "@/components/shell";
import {
  Chip,
  EmptyState,
  ErrorNote,
  LoadingPanel,
  Panel,
  Spinner,
  WarningNote,
} from "@/components/ui";

export default function ProjectsPage() {
  const { me } = useMe();
  const [projects, setProjects] = useState<Project[] | null>(null);
  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [github, setGithub] = useState<Record<string, any> | null>(null);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [busy, setBusy] = useState(false);
  const [attaching, setAttaching] = useState<string | null>(null);
  const [error, setError] = useState<ApiError | null>(null);

  const load = async () => {
    try {
      const [p, r, g] = await Promise.all([
        endpoints.projects(),
        endpoints.repositories(),
        endpoints.githubApp().catch(() => null),
      ]);
      setProjects(p);
      setRepositories(r);
      setGithub(g);
    } catch (exc) {
      if (exc instanceof ApiError) setError(exc);
      setProjects([]);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const create = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await endpoints.createProject({ name, description });
      setName("");
      setDescription("");
      await load();
    } catch (exc) {
      if (exc instanceof ApiError) setError(exc);
    } finally {
      setBusy(false);
    }
  };

  const attachLocal = async (projectId: string) => {
    setAttaching(projectId);
    setError(null);
    try {
      await endpoints.attachLocalTarget(projectId);
      await load();
    } catch (exc) {
      if (exc instanceof ApiError) setError(exc);
    } finally {
      setAttaching(null);
    }
  };

  if (projects === null) return <LoadingPanel label="Loading projects" />;

  const canManage = Boolean(me?.permissions.includes("project:manage"));
  const canAttach = Boolean(me?.permissions.includes("repository:manage"));

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-headline-md">Projects</h1>
        <p className="mt-1 text-small text-foreground-muted">
          Organisation → Project → Run. A run can only target a repository with verified authority.
        </p>
      </header>

      {error && <ErrorNote detail={error.message} code={error.code} requestId={error.requestId} />}

      {canAttach && projects.length > 0 && (
        <PublicRepoAttach
          projects={projects}
          defaultProjectId={projects[0]?.id}
          onAttached={() => void load()}
        />
      )}

      <Panel title="GitHub App">
        {github?.configured ? (
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <Chip tone="verified">CONFIGURED</Chip>
              <Chip tone={github.publisher_dry_run ? "warn" : "verified"}>
                PUBLISHER {github.publisher_dry_run ? "DRY RUN" : "LIVE"}
              </Chip>
            </div>
            {github.install_url && (
              <a
                href={String(github.install_url)}
                target="_blank"
                rel="noreferrer"
                className="btn-secondary text-xs"
              >
                <Github className="h-3.5 w-3.5" />
                Install the KavachX GitHub App
              </a>
            )}
            <p className="text-[11px] leading-4 text-foreground-faint">{String(github.notes)}</p>
          </div>
        ) : (
          <WarningNote>
            The GitHub App is not configured on this deployment, so GitHub repositories cannot be
            attached. In development mode you can still analyse the seeded local target below —
            that is the only local path KavachX will accept.
          </WarningNote>
        )}
      </Panel>

      {canManage && (
        <Panel title="Create a project">
          <form onSubmit={create} className="flex flex-col gap-3 sm:flex-row sm:items-end">
            <div className="flex-1">
              <label className="label" htmlFor="project_name">
                Name
              </label>
              <input
                id="project_name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="field"
                required
                minLength={2}
                placeholder="Payments service"
              />
            </div>
            <div className="flex-1">
              <label className="label" htmlFor="project_desc">
                Description
              </label>
              <input
                id="project_desc"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                className="field"
                placeholder="optional"
              />
            </div>
            <button type="submit" disabled={busy} className="btn-primary">
              {busy ? <Spinner className="text-accent-on" /> : <Plus className="h-4 w-4" />}
              Create
            </button>
          </form>
        </Panel>
      )}

      {projects.length === 0 ? (
        <Panel>
          <EmptyState
            icon={<FolderGit2 className="h-6 w-6" />}
            title="No projects"
            detail={
              canManage
                ? "Create one above to attach a repository."
                : "Your role cannot create projects. Ask an owner or maintainer."
            }
          />
        </Panel>
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          {projects.map((project) => {
            const projectRepositories = repositories.filter((r) => r.project_id === project.id);
            return (
              <Panel
                key={project.id}
                title={project.name}
                subtitle={project.slug}
                actions={
                  <Chip tone="muted">
                    {project.run_count} run{project.run_count === 1 ? "" : "s"}
                  </Chip>
                }
              >
                {project.description && (
                  <p className="mb-3 text-small text-foreground-muted">{project.description}</p>
                )}

                {projectRepositories.length === 0 ? (
                  <div className="rounded-md border border-border bg-surface-lowest p-3">
                    <p className="text-small text-foreground-muted">No repository attached.</p>
                    {canAttach && (
                      <button
                        onClick={() => void attachLocal(project.id)}
                        disabled={attaching === project.id}
                        className="btn-secondary mt-2.5 text-xs"
                      >
                        {attaching === project.id ? <Spinner /> : <ShieldCheck className="h-3.5 w-3.5" />}
                        Attach the seeded local target
                      </button>
                    )}
                  </div>
                ) : (
                  <div className="space-y-2">
                    {projectRepositories.map((repository) => (
                      <div
                        key={repository.id}
                        className="rounded-md border border-border bg-surface-lowest p-3"
                      >
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-mono text-mono-data text-foreground">
                            {repository.full_name}
                          </span>
                          <Chip tone="muted">{repository.provider}</Chip>
                          <Chip tone={repository.authority_verified_at ? "verified" : "refuted"}>
                            AUTHORITY {repository.authority_verified_at ? "VERIFIED" : "MISSING"}
                          </Chip>
                          <Chip
                            tone={
                              repository.provider === "github_public" ? "warn" : "verified"
                            }
                          >
                            {repository.provider === "github_public"
                              ? "ANALYSIS ONLY"
                              : "CAN PUBLISH"}
                          </Chip>
                        </div>
                        {repository.local_path && (
                          <div className="mt-1 truncate term text-foreground-faint" title={repository.local_path}>
                            {repository.local_path}
                          </div>
                        )}
                        {typeof repository.authority_evidence?.note === "string" && (
                          <p className="mt-1.5 text-[11px] leading-4 text-foreground-faint">
                            {repository.authority_evidence.note}
                          </p>
                        )}
                        <Link
                          href="/console/runs/new"
                          className="btn-secondary mt-2.5 px-3 py-1 text-xs"
                        >
                          Start a run
                        </Link>
                      </div>
                    ))}
                  </div>
                )}
              </Panel>
            );
          })}
        </div>
      )}
    </div>
  );
}
