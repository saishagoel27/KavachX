# KavachX — project instructions

Working rules for this repo live in [.claude/RULES.md](.claude/RULES.md). Follow them.

## Most important rule (do not miss this)

**Do NOT run tests unless the user explicitly asks.** Never run `pytest` / `uv run pytest` /
`npm test` / `make test` / `make test-e2e` / `make test-all` / `make demo` (it runs the e2e
pipeline), or any test-executing command, on your own initiative — not even "to verify" or "to be
safe". Finish the code and stop.

Static checks are fine without asking (they don't run the test suite): `ruff check`, `ruff format`,
`tsc --noEmit`, `npm run build` / `next build`, and importing a module to confirm it loads. Use
these to confirm code is sound, then tell the user to run the tests themselves when they want to.

See [.claude/RULES.md](.claude/RULES.md) for the full wording.
