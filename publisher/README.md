# Publisher — the credential boundary

The Publisher is implemented in [`backend/app/publisher/service.py`](../backend/app/publisher/service.py).
This directory documents the boundary it enforces, because the boundary is the point.

## Why it is separate

KavachX does two things that must never touch each other:

| | Analysis | Publishing |
| --- | --- | --- |
| Executes untrusted code | **yes** | never |
| Holds a GitHub credential | never | **yes** |

If those mixed, hostile code from an analysed repository would be running in a process that can push
to that repository. So the Publisher is the only component that constructs `GithubAppClient`, and it
runs no code at all.

## Enforced, not assumed

Four tests in `backend/tests/test_security_boundary.py` assert this against the actual source tree:

- `test_only_the_publisher_imports_the_github_client` — walks every module and fails if any outside
  `publisher/`, `github/`, `api/` or `config.py` references `GithubAppClient` or the key accessor.
- `test_orchestrator_does_not_import_the_publisher` — the orchestrator imports neither
  `app.publisher` nor `app.github`.
- `test_publisher_never_executes_code` — no `subprocess`, no `app.sandbox`, no `app.gauntlet`, no
  `eval`, no `exec`. Checked with comments and docstrings stripped, so a module that *documents* not
  using subprocess still passes.
- `test_installation_tokens_are_never_persisted` — no model mentions `access_token`.

## The credential chain

```
GitHub App private key  (a file or a secret manager; never in the database)
        ↓  RS256, regenerated per call, ≤ 9 minutes
App JWT
        ↓  POST /app/installations/{id}/access_tokens  with repositories: [one]
Installation access token
        ↓  held in a local variable, discarded when publish() returns
```

There is no column, cache or attribute anywhere that stores an installation token. Only the
*installation id* is persisted, and that is not a credential.

There is **no personal access token path.** Not configurable, not a fallback.

## What it receives

Plain data — no live objects, nothing that could execute:

```
verified patch (full file contents, stored at synthesis time)
+ PRAMAAN certificate
+ CHANGES.md
+ REMAINING.md
+ blast radius
+ the tenant's policy
```

File contents are read from the patch row rather than reconstructed from the unified diff. A diff
contains only the changed hunks plus context; rebuilding from it would produce a file consisting of
the changed regions alone, and the publisher writes **whole files**. Publishing that would corrupt
every file it touched. If stored content is missing, the publisher refuses rather than reconstructing
(`PATCH_CONTENT_MISSING`).

## What it does

1. **Re-runs the policy gate** on the exact payload. A gate you only pass once is a gate you can race.
2. Refuses a Level R certificate outright.
3. Creates a branch `kavachx/<run>-<finding>-<random>` from the analysed commit.
4. Writes each file through the contents API.
5. Opens a pull request with the finding, the violated clause, the four stage verdicts, the blast
   radius, and — deliberately — the **limitations**.
6. Labels it `kavachx`, `security`, `assurance-<level>`.

## What it never does

- push to the default branch
- force-push
- rewrite history
- amend a commit
- execute repository code
- publish without a certificate above Level R
- publish without human approval, when policy requires it (the default)

The contents API has no force option, which is part of why it is used instead of the git plumbing
API.

## Dry run

`PUBLISHER_DRY_RUN=true` (the default) sends nothing to GitHub and instead returns the complete
intended payload — branch, PR title and body, every file, and the guarantee block — as a run
artifact. The whole path is exercisable without a live GitHub App, and the end-to-end test asserts
the guarantees.

## Scope

One verified patch → one branch → one PR, which is the spec's first stage. Conflict-aware batching of
multiple patches into a single PR is not built; see [../docs/HONESTY.md](../docs/HONESTY.md) §10.
