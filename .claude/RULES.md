# KavachX — Working Rules

## R1. Do not run tests unless explicitly asked

Never run the test suite (or any individual test) on your own initiative.

- Do **not** run `pytest`, `uv run pytest`, `npm test`, `make test`/`test-e2e`/`test-all`,
  `make demo` (it runs the e2e pipeline), or any command whose purpose is to execute tests —
  unless the user has **explicitly** asked for it in that request.
- This includes "just to verify", "to be safe", or after making changes. Finish the code and stop.
- **Allowed without asking** (these are not "running tests"): static checks that don't execute the
  test suite — `ruff check`, `ruff format`, `tsc --noEmit`, `next build`/`npm run build`, and
  importing a module to check it loads. Prefer these to confirm code is sound.
- When you would normally have run tests, instead say so and let the user run them
  (e.g. "changes are lint/typecheck-clean; run `uv run pytest` when you want to validate").
- Only run tests when the user says something like "run the tests", "run pytest", "run the e2e",
  "run make demo", or otherwise clearly requests execution of tests.
