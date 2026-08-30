# platform-walkthrough — the whole platform, end to end, in one narrated pass

This is the demo. One command drives KavachX from an empty working directory to a signed
certificate and a pull request branch, narrating every stage from real state and refusing to
print a number it did not read back from the API or from git.

```
clone -> authorise -> run -> index -> contract -> fuzz -> validate
      -> shield -> repair -> gauntlet -> certificate -> pull request -> proof
```

It exists because the other two examples answer narrower questions. This one answers the
question a demo audience actually asks: *does the whole thing work, and can I check?*

| demo | question it answers |
|---|---|
| [`../fuzz-target-demo`](../fuzz-target-demo) | does the fuzzer build a campaign and find crashes? (the fuzzer alone, no server) |
| [`../full-pipeline-demo`](../full-pipeline-demo) | does the pipeline run over the live API and show up in the console? |
| **this one** | **the whole product: clone, setup, fuzz, propose a fix, implement it, raise the PR, and hand over the certificate** |

---

## Run it

### One-time setup

On the machine running the backend, from the repository root:

```bash
make bootstrap        # .env + dependencies + Postgres + migrations + seed
make backend          # the API on :8000   — keep this running
make frontend         # the console on :3000 — keep this running, in another terminal
```

`make dev` runs the last two together. `make bootstrap` creates the demo operator
`demo@kavachx.io` / `kavachx-demo-2024`.

### Option A — verify the walkthrough itself (no server, seconds)

Same shape as [`../fuzz-target-demo`](../fuzz-target-demo)'s `verify_fuzzer.py`: a self-checking
script with a real exit code, so the example can be checked before the stack is even up.

```bash
python examples/platform-walkthrough/verify_walkthrough.py
```

It drives the real code — `lib.gitwork` against a repository it builds on disk (origin, clone,
branch, commit, push, read-back from the origin), then every rendering act in `walkthrough.py`
against payloads shaped like the real API's. Then the part that matters:

```
[1] git layer - origin, clone, branch, commit, push          OK
[2] every act renders a populated run                        OK
[3] every act FAILS when the run produced nothing            OK
[4] a run where every stage ran and every stage failed       OK
[5] the final verdict is computed, not asserted              OK
```

Check **[4]** is the one that earns its keep. With no records at all, several acts take an early
return — so an act that claims success without consulting its own evidence slips past. Giving it a
full set of *failed* records forces it down its normal path. Sabotage `act_repair` to record `True`
unconditionally and [4] catches it by name:

```
FAIL: acts claimed success on a run that succeeded at nothing:
      {'repair': '1 iteration(s): 0 verified, 1 refuted first'}
```

Exit `0` = the git layer works, every act renders, and every act fails when it should.

### Option B — the full walkthrough (needs the stack)

Standard library only — there is nothing to install for this script.

```bash
python examples/platform-walkthrough/walkthrough.py
```

For a live audience, add `--pause` so it stops between acts and waits for Enter:

```bash
python examples/platform-walkthrough/walkthrough.py --pause
```

Exit code `0` means every claim it made held. A `FAIL` row in act 13 makes the exit code `1` — it
is a check, not a demo that always prints PASS.

Run it on the backend host. Act 1 clones into `examples/`, which the API resolves on its own
filesystem; against a remote backend use `--skip-clone --repository examples/vulnerable-demo`
along with `--api` and `--frontend`.

### Against a real GitHub repository

```bash
python examples/platform-walkthrough/walkthrough.py --github your-org/your-service --pause
```

With `--github` the walkthrough clones nothing itself. It attaches the repository through the
token-verified path — the backend asks GitHub whether the configured `GITHUB_TOKEN` really has
`push` access and refuses the attach if it does not — and the **backend** clones it at ingest
([`git_ingest.py`](../../backend/app/github/git_ingest.py)): outside the sandbox, credential passed
by environment rather than in the URL or argv, submodules not followed, symlinks stripped, `.git`
removed before the tree is pinned.

Act 1 therefore records nothing. It says what is about to happen, and act 3 reads the `git:clone`
event back out of the run's own stream — the claim passes only if that event is there.

This is also the only path that can end in a **real pull request**: set `PUBLISHER_DRY_RUN=false`
on the backend and act 12 opens one on GitHub instead of printing the payload. The same flow is
available in the console under **New Security Run → "Attach a repository you can push to"**.

Requires `GITHUB_TOKEN` to be a fine-grained token with `Contents: read/write` and
`Pull requests: read/write` on that repository. Without one, the attach fails with GitHub's own
reason, which act 2 prints verbatim.

---

## The fourteen acts, and what to say during each

Open `http://localhost:3000/console/runs/<id>` — the script prints the URL in act 3 — and let the
console play alongside the terminal. They are showing the same event stream.

### Act 0 — preflight

Reports git, the API version, database reachability, the **sandbox adapter and whether it isolates
untrusted code**, the LLM provider, whether the publisher is in dry-run, and the full test/fuzz
engine inventory split into available / unavailable / unimplemented.

> Say: *"Before it claims anything it tells you what it is. The dev adapter is a host subprocess,
> not an isolation boundary — and it says so, in the console header and on the certificate. Seven
> engines cannot run on this host, so seven strategies will report NOT RUN, never 'clean'."*

### Act 1 — clone

Imports the analysis target into a repository of its own, then performs a real `git clone` into
`examples/walkthrough-clone`. Prints the origin, the remote, the branch, the HEAD SHA and the
tracked file list.

> Say: *"Real git. Real remote. Real commit SHA. And KavachX will not execute anything from this
> working copy — at ingest the tree is copied to `pristine/` and hashed **outside** the sandbox;
> only a second copy is ever executed."*

The target is [`../vulnerable-demo`](../vulnerable-demo), the seeded `reportsvc` service: four
deliberately planted weaknesses, each marked in-source with its CWE, plus twelve benign requests.
The comments are there on purpose — the point is that KavachX has to **prove** each one by
execution rather than by reading the comment, and one of them it cannot prove.

With `--github`, this act instead explains that the **backend** will clone, and records nothing;
the clone is verified in act 3 from the run's own `git:clone` event.

### Act 2 — authorise

Attaches the clone and prints the authority evidence: provider, method, resolved path, and the
timestamp at which authority was verified.

> Say: *"A local target is accepted only if its resolved path is inside `examples/`. That is the
> entire allowlist. KavachX will not analyse an arbitrary directory even in development."*

### Act 3 — run

Starts a real run and follows its event stream to completion, printing each phase transition and
each agent decision as it happens. Ends with the pinned source hash, sandbox execution count,
**network egress in bytes**, coverage and model-call count.

> Say: *"That is the console's own event log, replayed from the durable record — so nothing is
> missed and nothing is duplicated. Note the egress figure. The sandbox has no network, so it
> cannot fetch its own source, and it cannot phone home."*

### Act 4 — index

The code knowledge graph: providers merged, symbols, relationships, how many references are
*resolved* versus name-matched, the health grade — and then the block that matters, **what this
index cannot support**.

> Say: *"Reachability is answered at a stated precision, and every claim built on it inherits that
> precision. This block travels into every certificate the run issues."*

### Act 5 — contract (SAMHITA)

The behavioural clauses derived from observing the benign corpus, split into what survived
falsification against held-out traces and what was killed.

> Say: *"Clauses dying here is the mechanism working. A bound derived from a partial sample is
> exactly the over-fitted claim held-out falsification exists to kill. What survives is admissible
> evidence; what does not is never cited again."*

### Act 6 — fuzz

The discovery channels that fired, with the fuzzing channel called out; the mutational campaign's
own numbers (cases executed, crashes, distinct shapes, reproducible seed); any coverage-guided
campaign with **how many model-proposed inputs actually moved coverage**; and the generated
harnesses with their engine, oracle and whether a model or the deterministic fallback proposed
each spec.

> Say: *"Whether a model-suggested input was useful is decided by measured coverage delta, not by
> the model's confidence in it. And an engine that cannot run here is recorded as NOT RUN."*

### Act 7 — validate

Findings, with reproduction counts. This is the only place a finding is born.

> Say: *"Two independent processes, one deterministic oracle. A candidate execution did not
> reproduce stays a hypothesis — it is not counted, and it is not quietly dropped. The working
> exploit is withheld; it needs `finding:read_pov`."*

### Act 8 — shield

The runtime mitigation, with both halves verified — it blocks the exploit **and** all benign cases
still pass — plus TIME TO PROTECTION.

> Say: *"Protection before repair. A shield that breaks benign behaviour is worse than no shield,
> so it is rolled back if it does. It is then reverted before the gauntlet, so the gauntlet tests
> the patch rather than the mitigation."*

### Act 9 — repair

Every patch iteration in a table, then the refuted ones with the constraint each refutation
produced, then the verified one with **the actual unified diff**.

> Say: *"The first patch is naive the way a rushed human fix is naive — block the character you
> saw in the report. The gauntlet then executes variants and finds the bypass. That refutation is
> not staged: had no variant worked, the patch would have passed. The bypass becomes a hard
> constraint on the next synthesis, and iteration two removes the shell entirely."*

### Act 10 — gauntlet

Per patch iteration: exploit mutation, sibling hunt, differential replay, SAMHITA re-check — each
with its verdict, case count, and any refuting evidence.

### Act 11 — certificate (PRAMAAN)

Every certificate with its serial, assurance level, hash, evidence node and edge counts, a live
signature verification, the grading rationale, and the **limitations printed on the certificate
itself**. Each document is downloaded to `out/<run>/`.

> Say: *"Level B rather than A, and the certificate says why. A certificate that names nothing it
> failed to establish is a certificate nobody should trust."*

### Act 12 — pull request

Sends the human publish approval, then shows what the Publisher produced: the branch name, the
exact file set, the payload hash, the pull request title and body, and the guarantees it enforces
(never the default branch, never a force push, never executes repository code, credential not
persisted).

With `PUBLISHER_DRY_RUN` on — the default — nothing is sent to GitHub, and the walkthrough then
**commits that byte-for-byte payload onto the clone from act 1 and pushes it to that clone's
origin**. The branch, the commit and the diff are real git objects; `git show --stat` and
`git log --oneline --all` are printed from the clone itself.

> Say: *"The Publisher is the only component that ever holds a credential, and it never executes
> repository code. It re-runs the policy gate on the exact payload it is about to push, because a
> gate you only pass once is a gate you can race. Here it ran in dry-run, and this is its payload
> on a real branch — every byte of it."*

To open a real pull request instead, run with `--github your-org/your-service` against a repository
your `GITHUB_TOKEN` can push to, and set `PUBLISHER_DRY_RUN=false` on the backend. Act 12 then
prints the pull request URL rather than the payload. Act 0 reports which mode is active, so the
demo never claims a live PR it did not open.

### Act 13 — proof of work

Every claim the walkthrough made with the evidence behind it, where to find the run, the
certificate and the branch — and **what this run did not prove**, taken from the certificate's own
limitations.

---

## Options

| flag | default | what it does |
|---|---|---|
| `--pause` | off | presenter mode: wait for Enter between acts |
| `--stream phases\|normal\|full` | `normal` | how much of the run's event stream to print |
| `--analysis quick\|standard\|deep` | `standard` | analysis profile; `deep` widens the fuzzing budget |
| `--execution dev_local\|gvisor\|firecracker` | `dev_local` | sandbox profile; `gvisor` needs the images built |
| `--source PATH` | `examples/vulnerable-demo` | folder to import and clone |
| `--clone-name NAME` | `walkthrough-clone` | clone destination under `examples/` |
| `--skip-clone` | off | analyse an already-attached repository instead of cloning |
| `--keep-clone` | off | reuse an existing clone rather than recreating it |
| `--repository NAME` | `examples/<clone-name>` | repository `full_name` to analyse |
| `--github OWNER/REPO` | — | analyse a real GitHub repo the token can push to; the backend clones it, and a real PR is possible |
| `--no-publish` | off | stop before sending the publish approval |
| `--api` / `--frontend` | localhost | point at a remote backend and console |
| `--email` / `--password` | demo operator | sign in as a different role to show RBAC |
| `--diff-lines` / `--pr-lines` | 60 / 40 | truncate the printed diff and PR body |
| `--no-color` | off | plain output, for recording or piping to a file |

`KAVACHX_API`, `KAVACHX_FRONTEND`, `KAVACHX_EMAIL` and `KAVACHX_PASSWORD` are honoured as
defaults.

### Showing RBAC in the same run

Re-run act 7 as a lower-privileged account to show the asymmetry — `viewer@kavachx.io` and the
other seeded role accounts share the demo password:

```bash
python examples/platform-walkthrough/walkthrough.py --email viewer@kavachx.io --no-publish
```

A viewer cannot start a run or approve a publish, and never sees a working exploit.

---

## What it writes

| path | what it is |
|---|---|
| `examples/walkthrough-clone/` | the clone, with the publisher's branch committed and pushed |
| `out/<clone-name>.git/` | the origin the clone was made from and pushed back to |
| `out/<run>/events.jsonl` | every run event, in order |
| `out/<run>/patch-<finding>.diff` | the verified patch, in full |
| `out/<run>/certificate-<serial>.json` | the signed certificate document |
| `out/<run>/publish-result.json` | the publisher's result |
| `out/<run>/publish-payload.json` | the dry-run payload, byte for byte |
| `out/<run>/pull-request.md` | the pull request title and body |

Both paths are gitignored. Nothing the walkthrough creates is committed to this repository.

After act 12 the clone is left checked out on the publisher's branch, so
`git -C examples/walkthrough-clone diff main` shows the repair immediately.

Re-running recreates the clone and the origin from scratch, so the demo is repeatable. Pass
`--keep-clone` to keep the previous one.

---

## What this walkthrough does not do

- **It does not open a GitHub pull request by default.** `PUBLISHER_DRY_RUN` is on unless you turn
  it off with a credential behind it. Act 0 states which mode is active and act 12 labels its
  output accordingly. A real pull request additionally needs `--github` against a repository the
  token can push to — a public repository is analysis-only by design.
- **It does not isolate untrusted code under `dev_local`.** That profile is a host subprocess and
  is correct only for this trusted seeded target. Use `--execution gvisor` with the sandbox images
  built for a real isolation boundary.
- **It does not prove the target is secure.** It proves specific weaknesses were reproduced,
  repaired and re-attacked. Everything it could not establish is listed in act 13 and on the
  certificate.
- **It does not analyse itself.** This folder is attached in the repository dropdown because every
  folder under `examples/` is, but it is a driver, not an analysis target.

## Troubleshooting

| symptom | fix |
|---|---|
| `could not reach http://localhost:8000` | start the API: `make backend` |
| `The API cannot reach its database` | `make db && make migrate && make seed` |
| `Login failed for demo@kavachx.io` | `make seed`, or pass `--email` / `--password` |
| `git is not available on PATH` | install git, or use `--skip-clone --repository examples/vulnerable-demo` |
| `seeded target not found` after attaching | restart the API — `examples/` folders are attached at startup |
| the run ends `FAILED` | open the console URL; the failing phase names its own reason |
| act 12 prints `PROVIDER_NOT_PUBLISHABLE` | the repository was attached as `github_public`, which is analysis-only by design |
