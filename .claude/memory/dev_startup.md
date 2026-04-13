---
name: Dev Startup
description: How to start all AttackTrace services locally for development
type: project
originSessionId: 58800ec8-ee4b-4638-8e58-e37d36bbc2ae
---
## Prerequisites (local dev only)
- PostgreSQL running with `attacktrace` user/db
- Redis running on default port 6379
- nuclei, ffuf installed (run `scripts/install-tools.sh`)

## Start Backend (FastAPI)
```bash
cd /Users/sai/Desktop/Coding/AttackTrace/platform/backend
python3.11 -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## Start Celery Worker
IMPORTANT: Must use `-Q scans,default` — scan tasks route to `scans` queue, watchdog to `default`.
Without this flag, all scans get stuck in "Initializing" forever.
```bash
cd /Users/sai/Desktop/Coding/AttackTrace/platform/backend
python3.11 -m celery -A app.workers.celery_app worker --loglevel=warning --concurrency=4 -Q scans,default
```

## Start Celery Beat (periodic watchdog — required for resilience)
Fires `recover_stuck_scans` every 5 min to requeue lost tasks and fail timed-out scans.
```bash
cd /Users/sai/Desktop/Coding/AttackTrace/platform/backend
python3.11 -m celery -A app.workers.celery_app beat --loglevel=warning
```

## Start Frontend (Next.js)
```bash
cd /Users/sai/Desktop/Coding/AttackTrace/platform/frontend
npm run dev
```

Frontend runs at http://localhost:3000, backend API at http://localhost:8000.

## DB setup (first time)
```bash
# Create DB and user
psql -U postgres -c "CREATE USER attacktrace WITH PASSWORD 'attacktrace';"
psql -U postgres -c "CREATE DATABASE attacktrace OWNER attacktrace;"

# Run migrations
cd /Users/sai/Desktop/Coding/AttackTrace/platform/backend
python3.11 -m alembic upgrade head
```

## Python package install
```bash
cd /Users/sai/Desktop/Coding/AttackTrace
pip install -e .
```

## Install CLI tools (nuclei, ffuf, nmap, etc.)
```bash
cd /Users/sai/Desktop/Coding/AttackTrace
bash scripts/install-tools.sh          # full install
bash scripts/install-tools.sh --check  # check what's installed
bash scripts/install-tools.sh --tools  # tools only (skip Python/Node deps)
```
