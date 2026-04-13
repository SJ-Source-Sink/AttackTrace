---
name: Architecture & Technical Decisions
description: Key file locations, API contracts, data model quirks, and non-obvious technical decisions
type: project
originSessionId: 58800ec8-ee4b-4638-8e58-e37d36bbc2ae
---
## Python version
Always use `python3.11` (or `/opt/homebrew/bin/python3`). `python3` on this machine maps to 3.14 which lacks uvicorn.

## Rename: EASD → AttackTrace
The application was renamed from EASD to AttackTrace in April 2026. All folder names, class names, env vars, DB credentials, and localStorage keys were updated. The old path `/Users/sai/Desktop/Coding/EASD/` no longer exists — the project is now at `/Users/sai/Desktop/Coding/AttackTrace/`.

Key renamed items:
- Config field: `ATTACKTRACE_WORKSPACE_DIR` (was `EASD_WORKSPACE_DIR`)
- DB: `attacktrace` user/password/dbname (was `easd`)
- localStorage keys: `attacktrace_rt` / `attacktrace_at` (in `lib/auth.ts`)
- Python package: `attacktrace/` directory (was `easd/`)
- Logger: `logging.getLogger("attacktrace.platform")`

## Backend API contracts

**Asset types from backend**: `subdomain`, `ip`, `domain`, `webapp`, `cloud` — NOT `ip_address`, `cloud_resource`. Frontend `TYPE_ICONS` must include both forms for safety.

**Paginated endpoints** return `{"items": [...], "total": N, "page": N, "per_page": N}` — never plain arrays. Frontend must do `Array.isArray(data) ? data : data?.items ?? []`.

**FindingResponse** adds alias fields: `asset_value` (= `affected_asset`), `age_days`, `cve_id`, `remediation_steps`, `ai_triage`, etc. — frontend uses these aliases.

**Reports API**:
- `POST /reports/generate` — body: `{scan_job_id, format, include_evidence}`
- `GET /reports` — lists HTML files from `{ATTACKTRACE_WORKSPACE_DIR}/reports/{org_id}/`
- `GET /reports/{scan_job_id}/download` — regenerates + streams the HTML file

## Frontend patterns

**Toast library**: `sonner` — import `{ toast } from "sonner"`. Use `toast.success("msg")` / `toast.error("msg", { description })`. Never import from `@/hooks/use-toast` (doesn't exist).

**API base URL**: `NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1` in `.env.local`. Backend base (for static files) = `NEXT_PUBLIC_API_URL.replace("/api/v1", "")`.

**SSE streaming**: `fetch()` + `ReadableStream` reader, split on `"\n\n"`, parse `event:` and `data:` lines. Use `/[\s\S]+/m` regex flag (not `/s` flag — targets ES2018+, TypeScript rejects it).

**getAccessToken() is synchronous**: Returns the token string directly — NOT a Promise. Never `await` it.

## Screenshot feature

- Captured by `attacktrace/modules/web/screenshot.py` during the `web` module step (after HTTP probing)
- Saved to `{ATTACKTRACE_WORKSPACE_DIR}/{org_id}/{scan_job_id}/screenshots/{session_id}/{filename}`
- `screenshot_url` column on `assets` table (migration `a3b4c5d6e7f8`)
- Served via FastAPI `StaticFiles` mounted at `/static/screenshots` → `{ATTACKTRACE_WORKSPACE_DIR}`
- Frontend: inline thumbnail in the Value cell of the asset table (only for webapp assets that have one); clicking opens a full modal with Escape-to-close, onError fallback

## ffuf fuzzer (app/api/v1/ffuf.py)

**Output format**: Use `-of ejson` WITH `-o <tempfile>`. Key facts:
- `-of ejson` without `-o` writes plain text paths to stdout, NOT JSON — zero results parsed
- `-o <file>` required to get JSON output; parse the complete file after the process exits
- FUZZ input values inside the ejson `results[].input.FUZZ` field are **base64-encoded** — always decode with `base64.b64decode(...).decode()`
- The ejson file contains one complete JSON object with a `results` array — NOT streaming lines

**Wordlist paths**: NEVER hardcode user-specific paths like `/Users/sai/`. Use:
- `_BUNDLED_DIR = Path(__file__).resolve().parents[5] / "wordlists"` — always available from repo
- `_HOME / "nuclei-templates" / "helpers" / "wordlists"` — if nuclei-templates installed
- `_seclists()` — finds SecLists in macOS brew / Linux apt / manual install locations
- Bundled wordlists are at `{repo}/wordlists/web/common.txt`, `dns/subdomains.txt`, `api/endpoints.txt`

**parents[5] from ffuf.py**: `platform/backend/app/api/v1/ffuf.py` → 5 levels up = repo root

**Streaming**: Both stdout (ejson results) and stderr (progress) drain concurrently via `asyncio.Queue` — same pattern as nuclei.

**Frontend**: `getAccessToken()` is synchronous — do NOT use `await`. The `startScan` dep array must include `wordlistMode` and `customWordlist`.

## Bundled wordlists (wordlists/)

Located at `{repo_root}/wordlists/`:
- `web/common.txt` — ~100 common web paths (quick scans, always available)
- `dns/subdomains.txt` — ~260 subdomain names
- `api/endpoints.txt` — ~80 common API endpoints

These are committed to the repo and work out of the box without installing SecLists. Install script also downloads SecLists and nuclei-templates for larger lists.

## Nuclei scanner (app/api/v1/nuclei.py)

**Critical command flag**: Use `-j` (JSONL to stdout), NOT `-json-export -`. `-json-export` requires a file path — passing `-` creates a file literally named `-` in the cwd and stdout stays empty, causing instant "completion" with zero findings.

**Templates directory**: nuclei v3 on macOS does NOT auto-discover `~/nuclei-templates` when launched from FastAPI. Always explicitly pass `-t <templates_dir>`. Use `_find_templates_dir()` which checks for known subdirs (`http`, `dns`, `ssl`, etc.) — fast, no rglob.

**Template modes in the command**:
- All: `-t <templates_dir>`
- Categories: `-t <templates_dir> -tags cves,exposures,...`
- Specific IDs: `-t <templates_dir> -id <template_id>` (NOT `-t <id>`)

**Template loading is slow**: `_load_templates_sync()` reads 12k+ YAML files (~20s). Runs in `asyncio.to_thread()`. Pre-loaded at server startup via `asyncio.create_task(preload_templates())` in `main.py` lifespan.

**stderr → progress events**: stdout = JSONL findings (`-j`), stderr = progress/stats (`-stats -no-color`). Both drained concurrently via `asyncio.Queue` in `_stream_nuclei()`. Frontend displays stderr as a live progress log panel.

## Scan resilience & Celery

**Queue routing**: Scan tasks route to `"scans"` queue via `task_routes`. Worker MUST be started with `-Q scans,default` — omitting `-Q scans` causes all scans to queue up silently and stay stuck in "Initializing" forever.

**Celery beat watchdog**: `recover_stuck_scans` task (in `scan_worker.py`) runs every 5 min via beat schedule. Behavior:
- PENDING > 5 min → requeues the task
- RUNNING > 3 hours → marks scan FAILED

**Startup recovery**: `main.py` lifespan fires `recover_stuck_scans.apply_async(queue="default")` on startup to clear any scans that got stuck during a previous server crash.

**Redis event replay**: `scan:{scan_id}:events` is a Redis list (24h TTL) that stores all non-finding events in order. `stream_scan_events()` in `scan_service.py` replays this list before subscribing to pub/sub — so reconnecting clients recover full scan state without resetting to 0%.

## Scan delete cascade

When a scan is deleted (`DELETE /scans/{id}`):
- DB: assets/findings cascade-delete via FK `ondelete="CASCADE"` — SQLAlchemy relationships must have `passive_deletes=True` (not just `cascade="all, delete-orphan"`) otherwise async ORM silently skips the DB-level cascade
- Disk: `shutil.rmtree({workspace}/{org_id}/{scan_id}/)` for screenshots
- Disk: `.unlink({workspace}/{org_id}/{scan_id}.db)` for scan SQLite db
- Disk: glob `{workspace}/reports/{org_id}/report_{scan_id}_*.html` for reports

## Native (no-Docker) install gotchas

- **CORS_ORIGINS in .env**: Do NOT set `CORS_ORIGINS` in the generated `.env` — pydantic-settings v2 fails to parse the JSON array even though the field_validator handles it. Let config.py default (`["http://localhost:3000","http://127.0.0.1:3000"]`) apply automatically.
- **bcrypt 5.x + passlib incompatibility**: bcrypt 5.x rejects the 72-byte wrap-bug probe that passlib uses during initialization. Pin `bcrypt==4.0.1` in requirements.txt.
- **pydantic[email] required**: email-validator must be installed for `EmailStr` in schemas. Added as `pydantic[email]>=2.0.0` in requirements.txt.
- **PostgreSQL superuser on macOS (Homebrew)**: The superuser is `$USER` (macOS username), NOT `postgres`. start.sh auto-detects by trying both.
- **npm install vs npm ci**: Use `npm install` (not `npm ci`) — `npm ci` fails on Node 25 due to lock file picomatch version mismatch.
- **tsconfig baseUrl required**: `platform/frontend/tsconfig.json` must have `"baseUrl": "."` in compilerOptions — without it, the `@/*` path alias fails to resolve on Linux and other non-Mac hosts. Fixed in commit `0bb8332`.

## Fresh install / one-command setup

**`setup.sh`** (repo root) — the single entry point for a fresh install:
```bash
chmod +x setup.sh && ./setup.sh
# or: make setup
```
Steps it performs (all idempotent / safe to re-run):
1. Checks Docker + Docker Compose
2. Generates `.env` from `.env.example` with `openssl rand` secrets (skips if `.env` exists)
3. `docker compose build`
4. Starts postgres + redis, polls until healthy
5. Starts backend, waits for `/health`
6. `alembic upgrade head` inside the backend container
7. `python -m app.initial_data` inside the backend container
8. Starts all remaining services
9. Prints login URL, credentials, and invite code

**`platform/backend/app/initial_data.py`** — idempotent seed script:
- Creates default org + workspace + admin user (owner) + open invite code `ATTACKTRACE`
- Reads from env vars: `FIRST_SUPERUSER_EMAIL`, `FIRST_SUPERUSER_PASSWORD`, `FIRST_ORG_NAME`
- Run via: `make seed` or `docker compose exec backend python -m app.initial_data`
- Safe to run multiple times — skips if superuser already exists

**Invite code for self-registration**: `ATTACKTRACE` (open, never-expires, analyst role)

## Install script

`scripts/install-tools.sh` (+ `make install-tools`) installs ffuf, nuclei, gowitness, nmap, SecLists, nuclei-templates, Python deps, Node deps, and Playwright browsers. macOS uses Homebrew; Linux uses apt/go install.

Modes:
- `--check`: show what's installed/missing
- `--tools`: skip Python/Node deps, install only CLI tools

## Alembic migrations
Located at `/platform/backend/alembic/versions/`. Run with:
```bash
cd /Users/sai/Desktop/Coding/AttackTrace/platform/backend && python3.11 -m alembic upgrade head
```
Latest: `cascade_assets_scan` (cascade delete assets when scan deleted; down_revision: `a3b4c5d6e7f8`)

## Key component locations
- Asset table: `components/assets/asset-table.tsx`
- Scan results tabs (with pagination): `components/scans/scan-results-tabs.tsx`
- Sidebar nav items: `components/layout/sidebar.tsx`
- API client: `lib/api.ts`
- Types: `types/index.ts`
- Scan worker (Celery): `app/workers/scan_worker.py`
- Reports API: `app/api/v1/reports.py`
- Nmap API: `app/api/v1/nmap.py`
- Nuclei API: `app/api/v1/nuclei.py`
- ffuf API: `app/api/v1/ffuf.py`
- Auth tokens: `platform/frontend/lib/auth.ts`
- Config/Settings: `platform/backend/app/core/config.py`
- Takeover API: `app/api/v1/takeover.py`
- Takeover page: `app/(app)/takeover/page.tsx`

## Takeover Checker

**Backend** (`app/api/v1/takeover.py`):
- `POST /takeover/scan` — accepts `{hosts: string[]}`, streams SSE events (`checking`, `result`, `done`)
- DNS CNAME chain resolution via dnspython with 8s lifetime timeout, runs in `asyncio.to_thread()`
- Concurrency via `asyncio.Semaphore(20)`
- Result: `{host, status: "vulnerable"|"safe"|"error", cname, service, confidence, evidence}`

**Frontend** (`app/(app)/takeover/page.tsx`):
- `AssetImportPanel` component: collapsible panel with search, type filter tabs (all/subdomain/domain), checkbox list, select-all, "Add N to Scan" button with deduplication
- Reads `?hosts=` URL param on load (initial render + `useSearchParams`) for cross-page pre-population

**Assets → Takeover flow**:
- `AssetTable` has `onCheckTakeover?: (values: string[]) => void` prop
- Bulk action "Check Takeover (N)" button (purple, only shows when subdomain/domain rows are selected)
- `assets/page.tsx` wires: `onCheckTakeover={(values) => router.push('/takeover?hosts=' + values.join(','))}`

## CVE / CVSS enrichment (nuclei.py)

- Module-level `_cvss_cache: dict[str, float | None] = {}` — session-scoped, avoids repeat NVD calls
- `_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)` — extracts from tags, references, template IDs
- `_lookup_cvss(cve_id)` — async, hits `services.nvd.nist.gov/rest/json/cves/2.0`, timeouts: connect=4s, read=8s
- Per finding: extract CVEs → lookup CVSS for the first CVE → attach `cve` (list) and `cvss_score` (float|null) to finding dict before yielding SSE

## Attack Chain tab (scan-results-tabs.tsx)

- `AttackChainTab` component: loads assets + findings concurrently for a scan
- Joins findings to assets client-side by matching `finding.asset_value === asset.value` via Map
- Groups subdomains/IPs under parent domains, renders expandable tree
- `FindingDots` component: up to 4 severity-colored dots per asset node
- Stats bar: total assets / findings / critical / high counts
