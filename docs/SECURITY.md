# Security model

KavachX is a defensive security research platform. It executes untrusted code and generates working
exploits. Two facts shape the entire architecture:

> **Analysis executes hostile code and must hold no credential.**
> **Publishing holds the only credential and must execute no code.**

---

## 1. Authorised targets only

A run can only touch a repository with **verified authority**, and authority is re-checked at run
start rather than trusted from attach time — a revoked installation stops new analysis even though
the row still exists.

Three authority paths, and no others:

| Path | How it is verified | May publish |
| --- | --- | --- |
| GitHub App installation | `GET /installation/repositories` must actually include the repository. A repository the caller merely named is rejected with `REPOSITORY_NOT_AUTHORISED`. | yes |
| Local seeded target (`DEV_MODE` only) | The path must resolve **inside this repository's own `examples/` tree**. That is the whole allowlist. | dry-run only |
| Public GitHub repository | `GET /repos/{owner}/{repo}` must return `private: false`. Anything else — 404, private, unreachable — is refused. | **no** |

There is no personal-access-token path. Not configurable, not a fallback. `DEV_MODE` does not mean
"analyse any directory on this machine" — `test_local_target_outside_examples_rejected` asserts it.

The caller must also affirm `authorisation_confirmed: true`, which is recorded in the audit log
alongside the authority evidence.

### 1.1 Public repositories are analysis-only

Reading published source and running it in a sealed sandbox is ordinary security research. Opening a
pull request against a repository you do not control is not. KavachX enforces that distinction
structurally rather than by policy text:

```python
PUBLISHABLE_PROVIDERS = frozenset({"github_app", "local_seeded"})   # github_public is absent
```

That set is checked in **two independent places** — `node_publish_gate` in the orchestrator and the
`POST /api/runs/{id}/publish` route — so neither a graph edit nor a direct API call can route around
the other. A blocked publish returns `PROVIDER_NOT_PUBLISHABLE` and the patch plus its certificate
remain available as run artifacts, which is the honest outcome: KavachX did the analysis and produced
a fix, and delivering that fix is the operator's decision to make through their own channel.

The deeper reason it cannot leak is that there is **no credential to leak**. A public repository is
fetched over unauthenticated HTTPS — `_client()` sends no `Authorization` header at all
(`test_no_credential_is_sent_on_the_public_path`) — so no installation token exists on that path for
the Publisher to use even if the gate were removed.

Ingestion itself treats the archive as hostile input: the tarball is size-capped before and during
extraction, and `_is_safe_member` rejects absolute paths, `..` traversal, symlinks, hard links and
device/FIFO nodes. A truncated or malformed archive becomes `REPOSITORY_ARCHIVE_MALFORMED`, not a
500. Fetch and extraction happen **outside** the sandbox; the sandbox still only ever sees a pinned
immutable copy.

---

## 2. The sandbox holds zero secrets

The sandbox environment is **built from an allowlist**, never inherited from `os.environ`:

```python
ENV_ALLOWLIST = ("PATH", "SYSTEMROOT", "TEMP", "HOME", "LANG", "PYTHONHASHSEED", …)
```

On top of that, `assert_no_secrets` runs on **every execution** and raises `SandboxSecretLeak` if any
variable name contains `GITHUB`, `GROQ`, `JWT`, `SECRET`, `TOKEN`, `PASSWORD`, `DATABASE_URL`,
`API_KEY`, `PRIVATE_KEY`, `AWS_`, `CREDENTIAL` … Even an explicit override cannot smuggle one in.

`test_sandbox_process_cannot_see_backend_secrets` sets real-looking credentials in the parent
environment, dumps the child's environment from inside the sandbox, and asserts none of them
arrived.

## 3. The sandbox has no network

| Adapter | Mechanism |
| --- | --- |
| gVisor / Firecracker | No interface exists (`--network none`, no tap device, no MMDS). Egress is zero by construction. |
| dev | An injected `sitecustomize` guard replaces `socket.socket`, `create_connection`, the ssl wrapper and `http.client.connect` with functions that raise, and counts attempts. |

The dev guard is a real measurement for Python targets — but only for Python targets in the same
interpreter. See [HONESTY.md](HONESTY.md) §2.

## 4. Pinned, immutable source

The repository is fetched **outside** the sandbox, copied into `pristine/`, and hashed there. The
sandbox executes against `work/`, a copy. There is no `git clone` inside a sandbox, ever.

`verify_pristine()` recomputes the tree hash after every patch application; if the pinned tree moved,
the run refuses to continue. Path joins into the workspace are validated
(`test_workspace_write_cannot_escape`), and artifact collection cannot read outside it
(`test_artifact_collection_cannot_read_outside_the_workspace`).

## 5. Resource ceilings

Wall-clock timeout with the process tree killed on expiry; CPU, address space, process count and
file size via POSIX rlimits where available; cgroup caps under the container adapters. Exceeding the
per-run token budget or the wall clock **aborts** the run — it never degrades quietly.

---

## 6. Repository content is data, never instructions

Source reaches a model inside a JSON document under `payload`, with a system prompt that states
plainly it is untrusted evidence extracted from a repository and must never be followed as an
instruction. The world model passes **handles**, and source arrives only as bounded slices.

Model output is parsed through a strict Pydantic schema with `extra="forbid"`. A schema failure is a
hard failure. And no schema anywhere exposes a field a model could use to claim verification — no
`verified`, no `assurance_level`, no `exploitable`. `test_no_model_contract_can_assert_verification`
walks every contract model and asserts it.

SAMHITA predicates get a second layer: a **restricted-AST whitelist** that rejects calls, attribute
access, subscripts, comprehensions, f-strings and walrus assignments, and evaluates with
`{"__builtins__": {}}`. Twelve injection attempts are covered by
`test_compiler_rejects_dangerous_predicates`.

---

## 7. Working exploits are privileged

| Role | `finding:read_pov` | `patch:publish` | `audit:read` |
| --- | --- | --- | --- |
| OWNER | yes | yes | yes |
| MAINTAINER | yes | yes | yes |
| SECURITY_REVIEWER | yes | no | yes |
| DEVELOPER | no | no | no |
| VIEWER | no | no | no |
| AUDITOR | no | no | yes |

An auditor can read the trail and the certificate but never the weapon.

The list endpoint **never** returns exploit material, whatever the role. A working exploit is handed
over only through `GET /api/runs/{id}/findings/{handle}?include_pov=true`, which requires
`finding:read_pov` and writes `finding.exploit_accessed` to the audit log — **including when access
is denied**. Certificates carry the exploit's hash and `pov_withheld: true`, never the payload; the
e2e test asserts `"pov_payload" not in json.dumps(document)`.

---

## 8. Tenant isolation

The tenant comes from the **signed access token** (`tid` + `role`). A client cannot select a tenant
with a header — switching organisations requires re-minting a token through `/api/auth/switch-org`,
which re-checks membership. That removes the whole "forgot to filter by tenant_id" class from the API
layer.

Every loader compares `row.tenant_id` against the principal's and reports a mismatch as **404, not
403** — a 403 would confirm the id exists, which is itself a cross-tenant leak.

Membership is re-verified against the database on every request, so a revoked or downgraded
membership takes effect immediately rather than at token expiry.

See [HONESTY.md](HONESTY.md) §5 for the honest status of PostgreSQL RLS as a second layer.

---

## 9. The publisher is the only credentialed component

- It is the **only** place `GithubAppClient` is constructed. A test walks the source tree and
  asserts no other module (outside `publisher/`, `github/`, `api/`, and `config.py` which defines the
  key accessor) references it.
- The orchestrator — which runs alongside hostile-code execution — imports neither
  `app.publisher` nor `app.github`. Asserted.
- It **never executes repository code**: no subprocess, no sandbox import, no `eval`, no `exec`.
  Asserted against the source with comments and docstrings stripped.
- Chain: App private key → short-lived App JWT (≤ 9 minutes, regenerated per call, never cached) →
  installation access token, **scoped to a single repository**, held in a local variable and
  discarded when the call returns. There is no column, cache or attribute that stores one; a test
  asserts the models never mention `access_token`.
- It **re-runs the policy gate** on the exact payload it is about to push. A gate you only pass once
  is a gate you can race.
- It never pushes to the default branch, never force-pushes, never rewrites history, never amends.
  Every write goes to a fresh `kavachx/` branch created from the analysed commit, through the
  contents API — which has no force option to misuse.

## 10. The publish gate

Deterministic, and nothing a model says can waive it. A patch is rejected if it:

- touches CI, container, git, lockfile, manifest, key or Makefile paths;
- adds a non-standard-library import, a network call, or `subprocess`/`eval`/`exec` behaviour that
  was not there before — decided by **AST comparison**, so a comment mentioning `subprocess` is not a
  violation and an aliased call still is;
- modifies a binary artifact;
- exceeds the diff-size or file-count limit;
- touches a file outside the computed blast radius;
- has no certificate, or a level below the policy floor;
- **has a Level R certificate** — a refuted patch is never published, and the API returns
  `ASSURANCE_LEVEL_R` at 422.

By default `require_human_approval` is on: the run parks in `AWAITING_APPROVAL` and the publisher is
not invoked until a reviewer holding `patch:publish` explicitly approves.

---

## 11. Audit log

Append-only, hash-chained per tenant:

```
hash = sha256(canonical(tenant, seq, actor, action, subject, timestamp, evidence_hash, previous_hash))
```

`seq` is per-tenant and monotonic; combined with `previous_hash` this makes deletion, reordering and
in-place edits detectable. `GET /api/audit/verify` recomputes the entire chain. On PostgreSQL a
trigger refuses `UPDATE` and `DELETE` on `audit_events` outright — a tamper-evident chain is worth
little if rows can be rewritten.

The hashed timestamp is stored as an explicit string rather than re-derived from `created_at`,
because `created_at` round-trips differently across dialects and the chain must not appear broken on
a database nobody touched.

Audited actions include login and failed login, repository authority verification **and rejection**,
run start/abort, finding access, **exploit access (granted and denied)**, patch review, policy
change, certificate issue and download, PR published, publish blocked, and audit reads themselves.

---

## 12. Hardening checklist before any non-local deployment

1. Set real `JWT_SECRET` and `CERTIFICATE_SIGNING_KEY` values (the dev scripts generate them).
2. Set `SANDBOX_ADAPTER=gvisor` and build the sandbox image (`make sandbox-image`). The dev adapter
   refuses to start when `KAVACHX_ENV=production`.
3. Put TLS in front of both services and restrict `CORS_ORIGINS`.
4. Give the application a database role that is **not** the table owner, and set
   `FORCE ROW LEVEL SECURITY` plus a per-checkout `SET kavachx.tenant_id` (see HONESTY.md §5).
5. Replace the HMAC certificate signature with an asymmetric one and publish the verification key.
6. Keep `PUBLISHER_DRY_RUN=true` until you have reviewed a dry-run payload end to end.
7. Store the GitHub App private key in a secret manager, not in `.env`.

## 13. Reporting

This is a research PoC, not a hosted service. If you find a security issue in KavachX itself, open an
issue describing the impact and the reproduction. Do not use it against systems you are not
authorised to test.
