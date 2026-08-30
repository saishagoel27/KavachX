# KavachX
#
# The one command path is `make demo`: it drives the full end-to-end loop (detect → adversarial
# validation → patch → gauntlet re-attack → signed certificate) against the seeded vulnerable
# target, in-process on SQLite + the deterministic proposer, so it needs no Postgres and no keys.
# `make dev` runs the API and console together for the interactive console.

.DEFAULT_GOAL := help
SHELL := /bin/bash

BACKEND := backend
FRONTEND := frontend
#: GitNexus lives in its own directory so the only Node dependency the backend shells out
#: to keeps its manifest, lockfile and node_modules out of the repository root.
GITNEXUS := gitnexus
PY := $(BACKEND)/.venv/bin/python
UV := uv
#: Host interpreter for the stdlib-only walkthrough driver. Override on Windows: PY3=python.
PY3 ?= python3

.PHONY: help
help: ## Show this help
	@echo ""
	@echo "  KavachX — graph-grounded autonomous cyber-reasoning with proof-carrying repair"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
	@echo ""

# ---------------------------------------------------------------------------
.PHONY: env
env: .env ## Create .env from .env.example with generated secrets

.env:
	@cp .env.example .env
	@python3 -c "import re,secrets,pathlib; \
p=pathlib.Path('.env'); s=p.read_text(); \
s=re.sub(r'^JWT_SECRET=.*', 'JWT_SECRET='+secrets.token_urlsafe(48), s, flags=re.M); \
s=re.sub(r'^CERTIFICATE_SIGNING_KEY=.*', 'CERTIFICATE_SIGNING_KEY='+secrets.token_urlsafe(48), s, flags=re.M); \
p.write_text(s)"
	@echo "  created .env with generated secrets"

.PHONY: deps
deps: gitnexus ## Install backend, frontend and code-graph dependencies
	cd $(BACKEND) && $(UV) sync
	cd $(FRONTEND) && npm install --no-audit --no-fund

.PHONY: gitnexus
gitnexus: ## Install GitNexus repo-locally (the code knowledge graph provider)
	@echo ""
	@echo "  Installing GitNexus into ./gitnexus/node_modules — the code knowledge graph provider."
	@echo "  It is OPTIONAL: without it KavachX indexes with tree-sitter only, every"
	@echo "  relationship is a name match rather than a resolved reference, and the index"
	@echo "  health report records that bound. See docs/CODE_GRAPH.md."
	@echo "  Licence: PolyForm Noncommercial 1.0.0 (GitNexus only, not KavachX)."
	@echo ""
	cd $(GITNEXUS) && GITNEXUS_SKIP_OPTIONAL_GRAMMARS=1 npm install --no-audit --no-fund
	@$(GITNEXUS)/node_modules/.bin/gitnexus --version 2>/dev/null \
		|| echo "  GitNexus did not report a version; KavachX will index tree-sitter-only."

.PHONY: gitnexus-doctor
gitnexus-doctor: ## Report GitNexus availability and platform capabilities
	cd $(BACKEND) && $(UV) run python -m scripts.gitnexus_doctor

.PHONY: db
db: ## Start PostgreSQL
	docker compose up -d postgres
	@printf "  waiting for readiness"
	@for i in $$(seq 1 40); do \
		if docker compose exec -T postgres pg_isready -U kavachx -d kavachx >/dev/null 2>&1; then break; fi; \
		printf "."; sleep 1; \
	done; echo ""
	@echo "  PostgreSQL ready on localhost:5433"

.PHONY: migrate
migrate: ## Apply database migrations
	cd $(BACKEND) && $(UV) run alembic upgrade head

.PHONY: revision
revision: ## Autogenerate a migration:  make revision m="add thing"
	cd $(BACKEND) && $(UV) run alembic revision --autogenerate -m "$(m)"

.PHONY: seed
seed: ## Seed the demo tenant, project and authorised local repository
	cd $(BACKEND) && $(UV) run python -m scripts.seed

.PHONY: bootstrap
bootstrap: env deps db migrate seed ## Everything needed before the first run
	@echo ""
	@echo "  Ready. Start the stack with 'make dev', or drive a full run with 'make demo'."

# ---------------------------------------------------------------------------
.PHONY: backend
backend: ## Run the API on :8000
	cd $(BACKEND) && $(UV) run uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

.PHONY: frontend
frontend: ## Run the console on :3000
	cd $(FRONTEND) && npm run dev

.PHONY: dev
dev: ## Run backend (:8000) and frontend (:3000) together; Ctrl-C stops both
	@trap 'kill 0' EXIT; \
	( cd $(BACKEND) && $(UV) run uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload ) & \
	( cd $(FRONTEND) && npm run dev ) & \
	wait

.PHONY: demo
demo: ## Drive the full end-to-end loop against the seeded target and print the certificate
	cd $(BACKEND) && $(UV) run pytest -s -v tests/test_e2e.py::test_full_pipeline

.PHONY: walkthrough
walkthrough: ## Narrated walkthrough over the live API: clone -> fuzz -> repair -> PR -> certificate
	@echo "  needs the API running (make backend / make dev). Pass options with ARGS=..."
	$(PY3) examples/platform-walkthrough/walkthrough.py $(ARGS)

# ---------------------------------------------------------------------------
.PHONY: test
test: ## Run the fast test suite (no end-to-end pipeline)
	cd $(BACKEND) && $(UV) run pytest -q -m "not e2e"

.PHONY: test-e2e
test-e2e: ## Run the end-to-end pipeline test against the seeded target
	cd $(BACKEND) && $(UV) run pytest -q tests/test_e2e.py

.PHONY: test-security
test-security: ## Run only the security-boundary regression tests
	cd $(BACKEND) && $(UV) run pytest -q -m security

.PHONY: test-all
test-all: ## Run every test including the end-to-end pipeline
	cd $(BACKEND) && $(UV) run pytest -q

.PHONY: coverage
coverage: ## Test with a coverage report
	cd $(BACKEND) && $(UV) run pytest -m "not e2e" --cov=app --cov-report=term-missing

.PHONY: lint
lint: ## Lint and typecheck both sides
	cd $(BACKEND) && $(UV) run ruff check app tests
	cd $(FRONTEND) && npx tsc --noEmit

.PHONY: format
format: ## Auto-fix lint findings
	cd $(BACKEND) && $(UV) run ruff check --fix app tests scripts
	cd $(BACKEND) && $(UV) run ruff format app tests scripts

.PHONY: build
build: ## Production build of the frontend
	cd $(FRONTEND) && npm run build

.PHONY: sandbox-image
sandbox-image: ## Build the hardened sandbox image used by the gVisor adapter
	docker build -t kavachx/sandbox:dev ./sandbox

# ---------------------------------------------------------------------------
.PHONY: up
up: env ## Full Docker stack
	docker compose up --build

.PHONY: down
down: ## Stop the Docker stack
	docker compose down

.PHONY: reset
reset: ## Drop the database, workspaces and local artifacts
	docker compose down -v 2>/dev/null || true
	rm -rf .kavachx $(BACKEND)/kavachx.db $(BACKEND)/.pytest-kavachx.db logs
	@echo "  local state cleared"

.PHONY: clean
clean: reset ## Reset, then remove build output and virtualenvs
	rm -rf $(BACKEND)/.venv $(FRONTEND)/node_modules $(FRONTEND)/.next
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	@echo "  clean"

.PHONY: verify
verify: lint test ## Lint, typecheck and run the fast suite — what CI runs
	@echo ""
	@echo "  verified"
