---
name: AttackTrace Project Overview
description: AttackTrace enterprise SaaS platform — what it is, key components, current state
type: project
originSessionId: 58800ec8-ee4b-4638-8e58-e37d36bbc2ae
---
AttackTrace (formerly EASD) is a hosted enterprise SaaS platform that wraps the AttackTrace CLI tool in a multi-tenant web application for external attack surface discovery.

**Stack**: FastAPI + SQLAlchemy async (backend), Next.js 15 App Router + React 19 (frontend), Celery + Redis (task queue), PostgreSQL (DB), AttackTrace Python CLI (scan engine).

**Key paths**:
- Project root: `/Users/sai/Desktop/Coding/AttackTrace/`
- Backend: `/Users/sai/Desktop/Coding/AttackTrace/platform/backend/`
- Frontend: `/Users/sai/Desktop/Coding/AttackTrace/platform/frontend/`
- AttackTrace CLI: `/Users/sai/Desktop/Coding/AttackTrace/attacktrace/`
- Wordlists: `/Users/sai/Desktop/Coding/AttackTrace/wordlists/`

**Database**: PostgreSQL `attacktrace` DB, user `attacktrace`, password `attacktrace`

**Fresh install**: `chmod +x setup.sh && ./setup.sh` — one command, handles everything. Or `make setup`.

**Current state (as of April 12, 2026)**:
- Full scan pipeline working end-to-end: create scan → Celery worker → AttackTrace orchestrator → persist assets/findings → show results
- Integrations settings page at `/settings/integrations` for Shodan, Censys, SecurityTrails, GitHub, AlienVault OTX, PassiveTotal credentials
- All API credentials encrypted AES-256-GCM before storage
- Dashboard, scans, assets, findings, reports, nmap, nuclei, ffuf pages all functional
- **Screenshot feature**: captures screenshots of ALL alive webapps during scan (not filtered by status code — captures 401/403/redirect URLs too); stored in `assets.screenshot_url`; served via `/static/screenshots/`; shown as inline thumbnail in asset table Value cell; workspace at `~/.attacktrace/scans` (persistent across reboots)
- **Nmap Scanner** (`/nmap`): SSE streaming scan with 7 scan types, port range, timing T0-T5, parsed host/port table, raw output, export, history
- **Nuclei Scanner** (`/nuclei`): SSE streaming scan with 3-mode template selector (All/Categories/Specific), severity filter, live progress log panel, expandable finding cards, export JSON/CSV/Markdown, history
- **ffuf Fuzzer** (`/ffuf`): SSE streaming scan, wordlist picker with bundled/SecLists/custom modes, live progress log, results table with status/size/words/lines columns. Results parsed from ejson temp file (base64-decoded FUZZ inputs).
- **Reports**: `POST /reports/generate`, `GET /reports` (lists files on disk), `GET /reports/{scan_job_id}/download`; frontend Quick Generate uses most recent completed scan
- **Scan detail pagination**: Assets tab and Findings tab both have prev/next page controls
- **Bundled wordlists**: `wordlists/web/common.txt`, `dns/subdomains.txt`, `api/endpoints.txt` — committed to repo, always available without installing SecLists
- **Notification bell**: functional dropdown in topbar showing 12 most recent scans with status icons, relative time, click-to-navigate; unread badge counts completed/failed scans since last open; persisted in localStorage key `attacktrace:notif:last_seen`; polls every 30s
- **Scan form**: "Company Name" renamed to "Engagement Name" throughout
- **Celery beat watchdog**: `recover_stuck_scans` fires every 5 min — requeues PENDING >5min scans, fails RUNNING >3h scans
- **Scan event replay**: Redis list `scan:{scan_id}:events` replays history on reconnect (no more reset to 0% on nav back)
- **E2E tested (April 2026)**: Full native install verified working — `./start.sh` brings up all 4 services; testphp.vulnweb.com scan completed in ~30s finding 15 assets + 14 findings; Nmap, Nuclei, ffuf standalone scanners all confirmed working
- **tsconfig baseUrl**: `platform/frontend/tsconfig.json` has `"baseUrl": "."` — required for `@/*` imports to resolve on Linux/non-Mac hosts

**AttackTrace API (correct)**:
- `AttackTraceConfig(api_keys=APIKeys(shodan=..., censys_id=..., ...))` — api_keys is nested
- `orchestrator.register_module("name", func)` — no register_*_modules() helpers
- `orchestrator.create_session(company, domains, passive_only, intensity, modules)`
- Task queue: `run_scan` → `scans` queue, `triage_scan_findings` → `ai` queue
