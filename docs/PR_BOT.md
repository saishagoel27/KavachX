# PR bot — design decisions and TODO

**Status: proposed. Nothing in this document is built.** It exists to make four decisions
explicit before code is written, because each one moves a boundary this codebase argues for in
writing elsewhere.

The question behind it: *KavachX proves a repair and signs a certificate — how does that repair
reach the repository it belongs to, and under whose identity?*

---

## 1. What already exists

More of the write path is built than the phrase "PR bot" suggests. What is missing is identity,
reach and lifecycle — not the mechanics of opening a pull request.

| Capability | Where | State |
| --- | --- | --- |
| Verify push authority against the API | [`app_client.verify_repository_authority`](../backend/app/github/app_client.py) | done |
| Create branch · read file · write file · open PR · label | `app_client` | done |
| Policy re-check on the exact payload | [`publisher/service.py`](../backend/app/publisher/service.py) | done |
| Branch naming, commit messages, PR title and body | `publisher/service.py` | done |
| File set: repair + certificate + `CHANGES.md` + `REMAINING.md` + `.patch` | `publisher/service.py` | done |
| Dry-run that emits the byte-for-byte payload | `publisher/service.py` | done |
| Human approval gate, `patch:publish` permission | [`routes/evidence.py`](../backend/app/api/routes/evidence.py) | done |
| Level R refused, default branch refused, no force-push, no history rewrite | `publisher/service.py` | done |
| Never executes repository code; credential never persisted | `publisher/service.py`, `app_client` | done |
| Authenticated source fetch (`git clone`) for a token-verified repo | [`github/git_ingest.py`](../backend/app/github/git_ingest.py) | **done — see §6** |
| Bot identity (`kavachx[bot]`) | — | **missing** |
| Per-installation, short-lived credentials | — | **missing** |
| Reach beyond repositories the operator's own token covers | — | **missing** |
| Any relationship with the PR after it is opened | — | **missing** |

### The vestigial clue

`Repository.installation_id` and `PublishRequest.installation_id` both exist and are **always
`None`**. The schema was designed for a GitHub App and then wired to a personal access token. This
work finishes an intended design rather than bolting a new one on.

### One accuracy note to settle either way

[`publisher/service.py`](../backend/app/publisher/service.py) states:

> *"The credential is **minted per publish**, scoped to the single repository, and discarded when
> this function returns."*

With a static `GITHUB_TOKEN` that is **not literally true** — it is read from settings, and its
scope is whatever the token's owner configured, not necessarily one repository. Under a GitHub App
it becomes true exactly as written. So either the App lands, or that sentence softens. In a
codebase whose thesis is that claims must be checkable, it should not stay as-is by default.

- [ ] Decide: App makes the claim true, or reword the docstring.

---

## 2. Decision A — identity: who authors the pull request?

| | A1 · Fine-grained PAT (today) | A2 · GitHub App | A3 · Hybrid |
| --- | --- | --- | --- |
| PR author | the human who owns the token | `kavachx[bot]` | either |
| Reach | repos that one token covers | any repo whose owner **installs** it | both |
| Credential | static, from settings | installation token, ~1 h, per install | both |
| Revocation | edit/rotate the token | owner uninstalls, instantly | both |
| Setup cost | none — works now | App registration, private key, JWT signing, install callback, webhook endpoint | highest |
| Makes the publisher docstring true | no | yes | partly |

**A2 is what "PR bot" actually means.** A PAT-authored PR is a human's PR that a machine wrote;
that is fine for a demo on your own repository and wrong as a product.

- [ ] **Decide A1 / A2 / A3.**
- [ ] If A2 or A3: register the App, decide the permission set (`contents: write`,
      `pull_requests: write`, `metadata: read` — nothing else), store the private key outside the
      database, and persist `installation_id` on attach (the column is already there).

---

## 3. Decision B — write access: direct branch, or fork?

**B1 · Direct branch on the target** — what the publisher does today. Requires `contents: write`
on their repository, so it only works where the owner installed the App or the operator's token
has push access. This is precisely why `github_public` is excluded from `PUBLISHABLE_PROVIDERS`.

**B2 · Fork, then cross-repo PR** — how Dependabot and Renovate operate. The bot forks, pushes the
branch to *its own* fork, and opens `kavachx-bot:branch → owner:main`. Requires **no write access
on the target at all**, and is therefore the only design under which "analyse any public repo and
propose the fix" is possible.

B2 reopens a boundary [`enums.py`](../backend/app/models/enums.py) states deliberately:

> *"Reading published source and executing it in a sandbox is ordinary security research; opening
> a pull request against a repository you do not control is not."*

A fork-PR is genuinely weaker than a direct push — nothing is written to their repository, and a
PR is a proposal a maintainer can close in one click. It is still unsolicited automated contact
with a stranger's project, and at volume it is indistinguishable from spam. If B2 is wanted it
needs to be *chosen*, not inherited.

Conditions I would attach to B2 if it is chosen:

- [ ] Off by default; a tenant-level policy flag, not a config default.
- [ ] A disclosure paragraph in the PR body: automated, unsolicited, who to contact, how to opt out.
- [ ] Rate limit per owner, and a global cap.
- [ ] Honour `SECURITY.md` / `.github/SECURITY.md` — if the project states a disclosure process,
      follow that instead of opening a PR.
- [ ] Rework `verify_repository_authority`: it hard-requires `push` today, which a fork flow will
      never have. It would need to verify "can fork and can open a PR" instead.
- [ ] Never fork-PR a finding whose certificate is Level R (already true) *or* Level C.

- [ ] **Decide B1 / B1+B2-behind-a-flag / B2.**

---

## 4. Decision C — lifecycle: one-shot publish, or an actual bot?

Publishing today is a single in-process call on human approval. A bot usually keeps a relationship
with the PR it opened:

- [ ] Reply to a review comment with the evidence node behind the claim being questioned.
- [ ] Re-run the gauntlet when a maintainer pushes to the branch; update the PR with the new verdict.
- [ ] Post a commit status / check run — `KavachX assurance: Level B`.
- [ ] Withdraw or close the PR if the finding is later refuted, or the certificate is superseded.
- [ ] Record merge/close outcomes, so "how many repairs were accepted" is a real number.

That is webhook-driven and belongs in a worker process, not the request path — the publisher must
stay a component that holds a credential and does nothing else.

**C1** one-shot (today) · **C2** one-shot + status check · **C3** full webhook lifecycle.

- [ ] **Decide C1 / C2 / C3.** C3 is the part that distinguishes this from "a script that opens a
      PR once".

---

## 5. Decision D — where the bot runs

- **D1 · in-process**, from the publish route. Simplest; the PR opens while the operator watches.
  Cannot retry, cannot receive webhooks.
- **D2 · separate worker**, consuming approved-publish events. Needed for C3, for retries, and to
  keep the credential holder off the request path.

- [ ] **Decide D1 / D2.** D2 is implied by C3.

---

## 6. Prerequisite — done

Nothing above could run until ingest could fetch a token-verified repository:
[`node_ingest`](../backend/app/orchestration/nodes.py) previously had a fetch branch only for
`github_public`, and the `github` provider carried no `local_path` — so a run against it failed at
ingest with *"the repository has no resolvable source location"*.

That is now closed by [`github/git_ingest.py`](../backend/app/github/git_ingest.py): a real
`git clone`, run outside the sandbox, credential passed by environment rather than in the URL or
argv, submodules refused, symlinks stripped, size and file-count capped. See
[`docs/INDEXING.md`](INDEXING.md) and the module docstring.

This means the **A1 + B1 + C1 + D1** path — PAT, direct branch, one-shot, in-process — works end
to end today against a repository the configured token can push to. That is the demo path. The
decisions above are about what it becomes afterwards.

---

## 7. Suggested phasing

**Phase 0 — now (done).** Authenticated `git clone` ingest, plus a console panel for attaching a
token-verified repository. Real repo, real clone, real PR, real certificate — under the operator's
own identity, on a repository they control.

**Phase 1 — the bot identity.** GitHub App: registration, JWT → installation token, install
callback, `installation_id` persisted, `GithubClient` able to authenticate either way. Publisher
unchanged apart from where the token comes from. Delete or fulfil the "minted per publish" claim.

**Phase 2 — lifecycle.** Webhook endpoint, worker process, check runs, gauntlet re-run on push,
outcome tracking.

**Phase 3 — reach, only if decided.** Fork-based PRs behind a tenant policy flag, with every
condition in §3 attached.

---

## 8. Open questions

1. Is the demo repository one you own? If yes, Phase 0 is sufficient and A1/B1 need no revisiting.
2. Is `kavachx[bot]` authorship needed on screen, or is PAT authorship acceptable for now?
3. Should the bot do anything after the PR is open, or is one-shot the product?
4. Do you want fork-PRs at all? If yes, that is a stated policy decision, not an implementation
   detail — and this document should record who made it and when.
