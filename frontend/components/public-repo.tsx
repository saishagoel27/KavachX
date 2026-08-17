"use client";

import { Github, Plus, Search, Star } from "lucide-react";
import { useState } from "react";

import {
  ApiError,
  endpoints,
  type Project,
  type PublicRepoPreview,
  type Repository,
} from "@/lib/api";

import { Chip, ErrorNote, Panel, Spinner, WarningNote } from "./ui";

/**
 * Attach a public GitHub repository.
 *
 * Two steps on purpose. **Resolve** shows what is about to be ingested — language mix, size,
 * licence, the resolved HEAD commit — before anyone commits to a run, and it makes the
 * analysis-only limitation visible at the moment of choosing rather than at the moment of
 * publishing.
 */
export function PublicRepoAttach({
  projects,
  defaultProjectId,
  onAttached,
}: {
  projects: Project[];
  defaultProjectId?: string;
  onAttached: (repository: Repository) => void;
}) {
  const [input, setInput] = useState("");
  const [projectId, setProjectId] = useState(defaultProjectId ?? projects[0]?.id ?? "");
  const [preview, setPreview] = useState<PublicRepoPreview | null>(null);
  const [resolving, setResolving] = useState(false);
  const [attaching, setAttaching] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [error, setError] = useState<{ code: string; message: string } | null>(null);

  const resolve = async (event: React.FormEvent) => {
    event.preventDefault();
    setResolving(true);
    setError(null);
    setPreview(null);
    setConfirmed(false);
    try {
      setPreview(await endpoints.previewPublicRepo(input.trim()));
    } catch (exc) {
      setError(
        exc instanceof ApiError
          ? { code: exc.code, message: exc.message }
          : { code: "NETWORK_ERROR", message: "Could not reach the KavachX API." },
      );
    } finally {
      setResolving(false);
    }
  };

  const attach = async () => {
    if (!preview || !projectId) return;
    setAttaching(true);
    setError(null);
    try {
      const repository = await endpoints.attachPublicRepo(
        projectId,
        preview.full_name,
        preview.default_branch,
      );
      onAttached(repository);
      setPreview(null);
      setInput("");
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

  const topLanguages = preview
    ? Object.entries(preview.languages)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
    : [];
  const totalBytes = topLanguages.reduce((sum, [, bytes]) => sum + bytes, 0) || 1;

  return (
    <Panel
      title="Analyse a public GitHub repository"
      actions={<Github className="h-4 w-4 text-accent" />}
    >
      <form onSubmit={resolve} className="flex flex-col gap-3 sm:flex-row sm:items-end">
        <div className="flex-1">
          <label className="label" htmlFor="public_repo">
            Repository URL or owner/repo
          </label>
          <input
            id="public_repo"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            className="field font-mono"
            placeholder="https://github.com/psf/requests"
            required
            minLength={3}
          />
        </div>
        <button type="submit" disabled={resolving || !input.trim()} className="btn-secondary">
          {resolving ? <Spinner /> : <Search className="h-4 w-4" />}
          Resolve
        </button>
      </form>

      {error && (
        <div className="mt-3">
          <ErrorNote title="Could not resolve" detail={error.message} code={error.code} />
        </div>
      )}

      {preview && (
        <div className="mt-4 space-y-4">
          <div className="rounded-md border border-border bg-surface-lowest p-4">
            <div className="flex flex-wrap items-center gap-2">
              <a
                href={preview.html_url}
                target="_blank"
                rel="noreferrer"
                className="font-mono text-sm font-bold text-accent hover:underline"
              >
                {preview.full_name}
              </a>
              {preview.primary_language && <Chip tone="muted">{preview.primary_language}</Chip>}
              {preview.license && <Chip tone="muted">{preview.license}</Chip>}
              {preview.archived && <Chip tone="warn">ARCHIVED</Chip>}
              {preview.fork && <Chip tone="warn">FORK</Chip>}
              <span className="ml-auto flex items-center gap-1 font-mono text-[11px] text-foreground-faint">
                <Star className="h-3 w-3" />
                {preview.stars.toLocaleString()}
              </span>
            </div>

            {preview.description && (
              <p className="mt-2 text-small text-foreground-muted">{preview.description}</p>
            )}

            <dl className="mt-3 grid gap-x-6 gap-y-1 sm:grid-cols-2">
              {[
                ["default branch", preview.default_branch],
                ["size", `${(preview.size_kb / 1024).toFixed(1)} MB`],
                [
                  "pinned commit",
                  preview.head_commit.sha ? preview.head_commit.sha.slice(0, 12) : "—",
                ],
                [
                  "committed",
                  preview.head_commit.date
                    ? new Date(preview.head_commit.date).toLocaleDateString()
                    : "—",
                ],
              ].map(([label, value]) => (
                <div key={label} className="flex items-baseline justify-between gap-3">
                  <dt className="font-mono text-[10px] uppercase text-foreground-faint">{label}</dt>
                  <dd className="truncate term text-foreground-muted">{value}</dd>
                </div>
              ))}
            </dl>

            {topLanguages.length > 0 && (
              <div className="mt-3">
                <div className="mb-1.5 font-mono text-[10px] uppercase text-foreground-faint">
                  language mix
                </div>
                <div className="flex h-1.5 overflow-hidden rounded-full bg-surface-highest">
                  {topLanguages.map(([language, bytes], index) => (
                    <div
                      key={language}
                      title={`${language} ${((bytes / totalBytes) * 100).toFixed(0)}%`}
                      style={{ width: `${(bytes / totalBytes) * 100}%` }}
                      className={
                        ["bg-accent", "bg-verified", "bg-warn", "bg-info", "bg-refuted"][index % 5]
                      }
                    />
                  ))}
                </div>
                <div className="mt-1.5 flex flex-wrap gap-1.5">
                  {topLanguages.map(([language, bytes]) => (
                    <span
                      key={language}
                      className="font-mono text-[10px] text-foreground-faint"
                    >
                      {language} {((bytes / totalBytes) * 100).toFixed(0)}%
                    </span>
                  ))}
                </div>
              </div>
            )}

            {preview.head_commit.message && (
              <p className="mt-3 truncate term text-foreground-faint">
                {preview.head_commit.message.split("\n")[0]}
              </p>
            )}
          </div>

          <WarningNote>
            <span className="text-warn">Analysis only.</span> KavachX holds no credential for this
            repository, so it can read the published source and execute it in the sandbox, but it
            can never open a pull request against it. Verified patches and certificates are
            available as run artifacts for a human to apply. Publishing requires a GitHub App
            installation that includes the repository.
          </WarningNote>

          {preview.notes.length > 0 && (
            <ul className="space-y-1">
              {preview.notes.slice(1).map((note, index) => (
                <li key={index} className="flex gap-2 text-[11px] leading-4 text-foreground-faint">
                  <span className="text-warn">·</span>
                  {note}
                </li>
              ))}
            </ul>
          )}

          <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
            <div className="flex-1">
              <label className="label" htmlFor="public_project">
                Project
              </label>
              <select
                id="public_project"
                value={projectId}
                onChange={(e) => setProjectId(e.target.value)}
                className="field"
              >
                {projects.map((project) => (
                  <option key={project.id} value={project.id}>
                    {project.name}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <label className="flex cursor-pointer items-start gap-2.5 rounded-md border border-warn/40 bg-warn/[0.05] p-3">
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(e) => setConfirmed(e.target.checked)}
              className="mt-0.5 accent-accent"
            />
            <span className="text-small text-foreground">
              I am authorised to analyse this repository. I understand KavachX will execute its code
              in a sandbox and generate working exploits against it, and that every action is
              recorded in the audit log against my account.
            </span>
          </label>

          <button
            onClick={() => void attach()}
            disabled={attaching || !confirmed || !projectId}
            className="btn-primary w-full"
          >
            {attaching ? <Spinner className="text-accent-on" /> : <Plus className="h-4 w-4" />}
            Attach {preview.full_name}
          </button>
        </div>
      )}
    </Panel>
  );
}
