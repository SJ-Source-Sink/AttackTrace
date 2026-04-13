# ─── AttackTrace — Developer Makefile ──────────────────────────────────────
#
# Usage:
#   make up           Start all services
#   make down         Stop all services
#   make build        Rebuild Docker images
#   make migrate      Run pending DB migrations
#   make seed         Seed initial data (superuser + default org)
#   make test-backend Run backend test suite
#   make lint         Lint + type-check backend
#
# Requires: docker, docker-compose (v2), python, node
#
# The DOCKER_COMPOSE variable falls back to `docker compose` (v2 plugin)
# but can be overridden: DOCKER_COMPOSE="docker-compose" make up

DOCKER_COMPOSE ?= docker compose
BACKEND_CONTAINER ?= backend
WORKER_CONTAINER  ?= worker

# Phony targets never correspond to real files
.PHONY: up down restart build logs ps \
        setup update start stop migrate seed backend-shell worker-logs flower-open \
        test-backend lint format \
        install-tools \
        k8s-apply k8s-delete k8s-status \
        help

# ─── Default target ───────────────────────────────────────────────────────────
.DEFAULT_GOAL := help

# ─── First-time setup ─────────────────────────────────────────────────────────

## setup: Full first-time setup — generates .env, builds images, starts services, migrates, seeds
setup:
	@bash setup.sh

## update: Pull latest changes from GitHub and hot-update the running platform
update:
	@bash update.sh

## start: Start all services natively (no Docker) — Python venv + npm dev
start:
	@bash start.sh

## stop: Stop all native services started by start.sh
stop:
	@bash stop.sh

## install-tools: Install all required external tools (ffuf, nuclei, gowitness, SecLists, Playwright)
install-tools:
	@echo "==> Installing AttackTrace external tool dependencies..."
	@bash scripts/install-tools.sh

# ─── Local Docker Compose ─────────────────────────────────────────────────────

## up: Start all services in the background
up:
	@echo "==> Starting AttackTrace platform..."
	@[ -f .env ] || { echo "ERROR: .env not found. Run: cp .env.example .env"; exit 1; }
	$(DOCKER_COMPOSE) up -d
	@echo "==> Services started:"
	@echo "     API:    http://localhost:8000"
	@echo "     UI:     http://localhost:3000"
	@echo "     Flower: http://localhost:5555/flower"

## down: Stop and remove containers (data volumes are preserved)
down:
	@echo "==> Stopping AttackTrace platform..."
	$(DOCKER_COMPOSE) down

## down-volumes: Stop AND remove data volumes (WARNING: destroys DB data)
down-volumes:
	@echo "==> WARNING: This will delete all database and Redis data!"
	@read -p "Are you sure? [y/N] " confirm && [ "$$confirm" = "y" ] || exit 1
	$(DOCKER_COMPOSE) down -v

## restart: Restart all services
restart: down up

## build: Rebuild Docker images from source (no cache)
build:
	@echo "==> Building Docker images..."
	$(DOCKER_COMPOSE) build --no-cache

## build-fast: Rebuild images using layer cache
build-fast:
	$(DOCKER_COMPOSE) build

## logs: Tail logs from all services
logs:
	$(DOCKER_COMPOSE) logs -f

## ps: Show running containers and their status
ps:
	$(DOCKER_COMPOSE) ps

# ─── Database ─────────────────────────────────────────────────────────────────

## migrate: Run all pending Alembic migrations
migrate:
	@echo "==> Running database migrations..."
	$(DOCKER_COMPOSE) exec $(BACKEND_CONTAINER) alembic upgrade head
	@echo "==> Migrations complete."

## migrate-status: Show current migration revision
migrate-status:
	$(DOCKER_COMPOSE) exec $(BACKEND_CONTAINER) alembic current

## migrate-history: Show full migration history
migrate-history:
	$(DOCKER_COMPOSE) exec $(BACKEND_CONTAINER) alembic history --verbose

## migrate-rollback: Roll back the last migration
migrate-rollback:
	@echo "==> Rolling back last migration..."
	$(DOCKER_COMPOSE) exec $(BACKEND_CONTAINER) alembic downgrade -1

## seed: Run initial data seed (creates superuser + default organisation)
seed:
	@echo "==> Seeding initial data..."
	$(DOCKER_COMPOSE) exec $(BACKEND_CONTAINER) python -m app.initial_data
	@echo "==> Seed complete."

# ─── Development Shells ───────────────────────────────────────────────────────

## backend-shell: Open an interactive shell in the backend container
backend-shell:
	$(DOCKER_COMPOSE) exec $(BACKEND_CONTAINER) /bin/bash

## worker-shell: Open an interactive shell in the worker container
worker-shell:
	$(DOCKER_COMPOSE) exec $(WORKER_CONTAINER) /bin/bash

## db-shell: Connect to PostgreSQL interactively
db-shell:
	$(DOCKER_COMPOSE) exec postgres psql -U attacktrace -d attacktrace

## redis-cli: Connect to Redis CLI
redis-cli:
	$(DOCKER_COMPOSE) exec redis redis-cli

# ─── Logs ─────────────────────────────────────────────────────────────────────

## worker-logs: Tail worker container logs
worker-logs:
	$(DOCKER_COMPOSE) logs -f worker

## backend-logs: Tail backend container logs
backend-logs:
	$(DOCKER_COMPOSE) logs -f backend

## beat-logs: Tail worker-beat (scheduler) logs
beat-logs:
	$(DOCKER_COMPOSE) logs -f worker-beat

## flower-open: Open Celery Flower monitoring UI in browser
flower-open:
	@which open >/dev/null 2>&1 && open http://localhost:5555/flower || \
	which xdg-open >/dev/null 2>&1 && xdg-open http://localhost:5555/flower || \
	echo "Open: http://localhost:5555/flower"

# ─── Testing ──────────────────────────────────────────────────────────────────

## test-backend: Run the full backend test suite with coverage
test-backend:
	@echo "==> Running backend tests..."
	$(DOCKER_COMPOSE) exec $(BACKEND_CONTAINER) \
		python -m pytest tests/ \
		  --cov=app \
		  --cov-report=term-missing \
		  --cov-report=html:htmlcov \
		  -v \
		  --tb=short
	@echo "==> Coverage report: htmlcov/index.html"

## test-fast: Run tests without coverage (faster iteration)
test-fast:
	$(DOCKER_COMPOSE) exec $(BACKEND_CONTAINER) \
		python -m pytest tests/ -x -q --tb=short

## test-unit: Run only unit tests (no DB/Redis required)
test-unit:
	$(DOCKER_COMPOSE) exec $(BACKEND_CONTAINER) \
		python -m pytest tests/unit/ -v

# ─── Code Quality ─────────────────────────────────────────────────────────────

## lint: Run ruff linter + mypy type checker on backend
lint:
	@echo "==> Running ruff linter..."
	$(DOCKER_COMPOSE) exec $(BACKEND_CONTAINER) ruff check app/ tests/
	@echo "==> Running mypy type checker..."
	$(DOCKER_COMPOSE) exec $(BACKEND_CONTAINER) mypy app/ --ignore-missing-imports
	@echo "==> Lint complete."

## format: Auto-format backend code with ruff
format:
	$(DOCKER_COMPOSE) exec $(BACKEND_CONTAINER) ruff format app/ tests/
	$(DOCKER_COMPOSE) exec $(BACKEND_CONTAINER) ruff check --fix app/ tests/

## lint-local: Run lint without Docker (requires local venv activated)
lint-local:
	ruff check platform/backend/app/ platform/backend/tests/ && \
	mypy platform/backend/app/ --ignore-missing-imports

# ─── Kubernetes ───────────────────────────────────────────────────────────────

## k8s-apply: Apply all Kubernetes manifests to the current context
k8s-apply:
	@echo "==> Applying Kubernetes manifests..."
	@echo "    Current context: $$(kubectl config current-context)"
	kubectl apply -f k8s/namespace.yaml
	kubectl apply -f k8s/configmap.yaml
	kubectl apply -f k8s/secrets.yaml
	kubectl apply -f k8s/postgres.yaml
	kubectl apply -f k8s/redis.yaml
	kubectl apply -f k8s/backend.yaml
	kubectl apply -f k8s/worker.yaml
	kubectl apply -f k8s/frontend.yaml
	kubectl apply -f k8s/ingress.yaml
	kubectl apply -f k8s/keda-scaledobject.yaml
	@echo "==> Done. Check status with: make k8s-status"

## k8s-delete: Remove all AttackTrace resources from Kubernetes
k8s-delete:
	@echo "==> WARNING: This will delete all AttackTrace resources in the cluster!"
	@read -p "Are you sure? [y/N] " confirm && [ "$$confirm" = "y" ] || exit 1
	kubectl delete namespace attacktrace-platform

## k8s-status: Show all resources in the attacktrace-platform namespace
k8s-status:
	kubectl get all -n attacktrace-platform

## k8s-migrate: Run database migrations in the Kubernetes backend pod
k8s-migrate:
	@echo "==> Running migrations in Kubernetes..."
	kubectl exec -n attacktrace-platform \
		$$(kubectl get pod -n attacktrace-platform -l app=backend -o jsonpath='{.items[0].metadata.name}') \
		-- alembic upgrade head

# ─── Help ─────────────────────────────────────────────────────────────────────

## help: Show this help message
help:
	@echo ""
	@echo "AttackTrace — Development Commands"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@grep -E '^## [a-zA-Z_-]+:' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ": "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' | \
		sed 's/## //'
	@echo ""
