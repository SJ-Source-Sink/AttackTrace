# AttackTrace Platform — Comprehensive Technical Write-Up

---

## 1. HIGH-LEVEL ARCHITECTURE

**AttackTrace** is a multi-tenant, enterprise security reconnaissance platform built with:

- **Backend**: FastAPI (async Python) with PostgreSQL async driver (asyncpg)
- **Frontend**: Next.js 15 with React 19, TypeScript, Tailwind CSS
- **Task Queue**: Celery + Redis broker (JSON serialization)
- **Caching**: Redis (multiple databases for different concerns)
- **Database**: PostgreSQL (async with SQLAlchemy 2.0 ORM)
- **Authentication**: JWT (HS256, 8-hour access + 7-day refresh tokens)
- **Encryption**: Fernet (AES-256-GCM via cryptography library)
- **AI Service**: Anthropic Claude API (claude-haiku-4-5-20251001)
- **Monitoring**: Structured logging (structlog), request ID tracking, rate limiting (slowapi)

**Key Infrastructure Paths**:
- Backend: `platform/backend/`
- Frontend: `platform/frontend/`
- CLI: `attacktrace/`

---

## 2. BACKEND API ROUTERS (v1)

All endpoints under `/api/v1/` prefix. OpenAPI docs at `/api/v1/docs`.

Routers in `platform/backend/app/api/v1/`:

| Router | Purpose | Key Endpoints |
|--------|---------|---------------|
| **auth.py** | JWT auth, registration, token refresh | POST /auth/register, /auth/login, /auth/refresh, /auth/logout, GET /auth/me |
| **orgs.py** | Multi-tenant org, workspace, member, API key CRUD | POST /orgs, GET /orgs/{id}, PUT /orgs/{id}, DELETE /orgs/{id}, /orgs/{id}/workspaces, /orgs/{id}/members, /orgs/{id}/api-keys, /orgs/{id}/credentials |
| **scans.py** | Scan lifecycle: create, list, get, cancel, stream SSE | POST /scans, GET /scans, /scans/{id}, DELETE /scans/{id}, GET /scans/{id}/stream (SSE) |
| **assets.py** | Asset inventory, filtering, deduplication | GET /assets, /assets/{id}, POST /assets/search, /assets/{id}/screenshot |
| **findings.py** | Finding CRUD, status/severity updates, comments | GET /findings, /findings/{id}, PUT /findings/{id}/status, POST /findings/{id}/comments, /findings/{id}/suppress, /findings/{id}/unsuppress |
| **reports.py** | HTML/PDF report generation | POST /reports/{scan_id}/generate, GET /reports/{report_id}/download |
| **ai.py** | Claude-powered triage, NL search, executive summaries | POST /ai/triage, /ai/search-findings, /ai/executive-summary, /ai/jira-ticket |
| **ai_scanner.py** | 40+ LLM attack plugins | POST /ai-scanner/scan, GET /ai-scanner/history, /ai-scanner/history/{scan_id}, DELETE /ai-scanner/history/{scan_id} |
| **mcp_scanner.py** | 4-phase MCP server security scanner | POST /mcp-scanner/scan, GET /mcp-scanner/history, /mcp-scanner/history/{scan_id}, DELETE /mcp-scanner/history/{scan_id} |
| **attack_suite.py** | MITRE ATT&CK attack pattern mapping | POST /attack-suite/generate-attacks, GET /attack-suite/patterns |
| **ai_attack_suite.py** | AI-powered attack scenario generation | POST /ai-attack-suite/generate |
| **nuclei.py** | Nuclei template enumeration & execution | GET /nuclei/templates, POST /nuclei/scan |
| **nmap.py** | Nmap service enumeration | POST /nmap/scan, GET /nmap/{job_id}/results |
| **ffuf.py** | Directory/path fuzzing with ffuf | POST /ffuf/scan, GET /ffuf/{job_id}/results |
| **network_graph.py** | Network topology visualization | GET /network-graph/build, /network-graph/export |
| **takeover.py** | Subdomain takeover detection | POST /takeover/scan, GET /takeover/{job_id}/results |
| **firewall.py** | WAF detection (wafw00f) & evasion techniques | POST /firewall/detect, /firewall/bypass-patterns |
| **mobile.py** | Mobile app scanning (iOS/Android) | POST /mobile/scan, GET /mobile/{job_id}/results |
| **cloud.py** | Cloud asset discovery (S3, GCP buckets) | POST /cloud/scan, GET /cloud/{job_id}/results |
| **dashboard.py** | Org-level metrics, KPIs | GET /dashboard/summary, /dashboard/risk-heatmap |
| **notifications.py** | Slack, Jira, Teams, webhook integrations | POST /notifications/channels, GET /notifications/channels, PUT /notifications/channels/{id}, DELETE /notifications/channels/{id} |
| **schedules.py** | Cron-based recurring scans | POST /schedules, GET /schedules, PUT /schedules/{id}, DELETE /schedules/{id} |
| **suppression_rules.py** | Finding suppression policies | POST /suppression-rules, GET /suppression-rules, DELETE /suppression-rules/{id} |
| **testgen.py** | Automated security test generation | POST /testgen/generate, GET /testgen/{job_id}/results |
| **burp_analyzer.py** | Burp Suite XML import & analysis | POST /burp-analyzer/upload, GET /burp-analyzer/{job_id}/findings |
| **attackmapper.py** | Attack path mapping | GET /attack-mapper/paths |
| **cicd.py** | CI/CD pipeline integration | POST /cicd/trigger, GET /cicd/status |
| **webhooks.py** | Outgoing webhooks for events | POST /webhooks, GET /webhooks, DELETE /webhooks/{id} |

Rate limiting: 200 requests/minute globally (configurable via `RATE_LIMIT_PER_MINUTE`).

---

## 3. DATABASE MODELS

All ORM models in `platform/backend/app/models/db/`:

### Core Models

**User** (`user.py`)
- `id` (UUID, PK)
- `email` (unique, indexed)
- `hashed_password` (bcrypt)
- `full_name`
- `is_active`, `is_superuser`
- `last_login` (timestamp)
- `avatar_url`
- Relations: `org_memberships` → OrgMember[]

**OrgMember** (user-org junction)
- `user_id` + `org_id` (composite PK)
- `role` (enum: OWNER | ADMIN | ANALYST | VIEWER)
- `joined_at`
- `tool_permissions` (array of tool IDs for granular RBAC)

**Organization** (`org.py`)
- `id` (UUID)
- `name`, `slug` (unique)
- `plan` (enum: STARTER | PRO | ENTERPRISE)
- `is_active`
- `max_scans_per_month`
- `logo_url`, `sla_config` (JSONB)
- Relations: `workspaces`, `members`, `api_keys`, `credentials`

**Workspace**
- `id` (UUID)
- `org_id` (FK)
- `name`, `description`
- `is_active`
- Relations: `scan_jobs`

**ApiKey**
- `id` (UUID)
- `org_id` (FK), `created_by` (FK → User)
- `name`
- `key_hash` (SHA-256, unique indexed)
- `scopes` (array of permission strings)
- `is_active`
- `expires_at`, `last_used`

**OrgCredentials** (encrypted third-party API keys)
- `org_id` (unique FK)
- `anthropic_key_enc`, `shodan_key_enc`, `censys_id_enc`, `censys_secret_enc`, `securitytrails_key_enc`, `github_token_enc`, `alienvault_key_enc`, `passivetotal_user_enc`, `passivetotal_key_enc`
- All stored as Fernet-encrypted TEXT fields

**InviteCode**
- `id`, `org_id`, `code` (unique)
- `role`, `email` (optional, restricts to specific email)
- `created_by`, `expires_at`
- `used_at`, `used_by`, `is_revoked`

**NotificationChannel**
- `id`, `org_id`, `name`
- `channel_type` (slack | jira | webhook | teams)
- `config_enc` (Fernet-encrypted JSON config)
- `events` (array: "scan.completed", "finding.critical", "sla.breached")

### Scan Models (`scan.py`)

**ScanJob**
- `id` (UUID)
- `org_id`, `workspace_id` (FK), `created_by` (FK → User)
- `target_domains` (array)
- `company_name`, `intensity` (enum: PASSIVE | NORMAL | AGGRESSIVE | PASSIVE_DUE_DILIGENCE)
- `modules_to_skip` (array), `passive_only` (bool)
- `status` (enum: PENDING | RUNNING | COMPLETED | FAILED | CANCELLED)
- `error_message`, `session_id` (AttackTrace CLI reference)
- `started_at`, `completed_at`, `scheduled_at`
- `results_summary` (JSONB), `findings_count` (JSONB with severity breakdown)
- `schedule_cron` (for recurring scans)
- `celery_task_id` (for cancellation)
- Relations: `findings[]`, `assets[]`

**ScanDiff**
- Tracks changes between consecutive scans: new_assets, removed_assets, new_findings, resolved_findings

**ScheduledScan**
- Recurring scan configuration with cron expressions
- Tracks `last_run`, `next_run`, `last_scan_job_id`

### Finding Model (`finding.py`)

**Finding**
- `id` (UUID)
- `org_id`, `scan_job_id` (FK), `asset_id` (FK, optional)
- `source` (enum: "attacktrace" | "msra" | ...), `source_scan_id`
- `title`, `description`, `category`
- `severity` (enum: CRITICAL | HIGH | MEDIUM | LOW | INFO)
- `affected_asset` (text), `evidence` (JSONB), `remediation`
- `references` (array), `cve` (array), `cvss_score` (float)
- AI Triage: `ai_severity`, `ai_reasoning`, `ai_confidence` (0.0-1.0), `ai_triaged_at`
- Lifecycle: `status` (enum: OPEN | IN_PROGRESS | REMEDIATED | ACCEPTED_RISK | FALSE_POSITIVE)
- Suppression: `suppressed`, `suppressed_reason`, `suppressed_by` (FK), `suppressed_until`
- KEV/EPSS: `kev_status` (bool), `epss_score`, `priority_score`
- Risk: `risk_score`, `risk_explanation`
- SLA: `sla_deadline`, `compliance_tags` (array)
- Dedup: `dedup_hash` (SHA-256 for cross-scan deduplication)
- Ticketing: `ticket_ref` (Jira ticket ID)
- Relations: `comments[]`, `suppressions[]`

**FindingComment**
- `id`, `finding_id`, `user_id`
- `body` (text), `created_at`, `updated_at`

**FindingSuppression** (audit trail)
- `id`, `finding_id`, `suppressed_by`
- `action` ("suppress" | "unsuppress")
- `reason`, `until` (optional expiry)

### Asset Model (`asset.py`)

**Asset**
- `id` (UUID)
- `org_id`, `scan_job_id`, `owner_user_id` (all indexed)
- `asset_type` (enum: DOMAIN | SUBDOMAIN | IP | WEBAPP | CLOUD | ENDPOINT)
- `value` (unique within org + type, indexed)
- `metadata_` (JSONB for type-specific data: headers, HTTP status, certificates, cloud provider, etc.)
- `risk_score`, `tags` (array)
- `first_seen`, `last_seen` (timestamps)
- `is_active`, `screenshot_url`
- Relations: `findings[]`

### Audit Model (`audit.py`)

**AuditLog**
- Tracks: create, update, delete, API key generation, member invites
- Fields: `org_id`, `user_id`, `action`, `resource_type`, `resource_id`, `details` (JSONB), `ip_address`, `timestamp`

---

## 4. FRONTEND PAGES

All pages under `platform/frontend/app/(app)/`:

| Page | Purpose |
|------|---------|
| **/dashboard** | Org metrics, risk heatmap, finding breakdown by severity |
| **/dashboard/executive** | Executive summary with KPIs and trend analysis |
| **/scans** | Scan list with status, filtering, pagination |
| **/scans/new** | Create new scan: target entry, intensity selection, module configuration |
| **/scans/[id]** | Scan details: SSE progress streaming, asset list, findings, diff from previous scan |
| **/findings** | Global finding list with filtering (severity, status, category), comments, status transitions |
| **/assets** | Asset inventory with tagging, screenshot view, risk scoring |
| **/reports** | Report generation and download (HTML/PDF) |
| **/ai-scanner** | AI/LLM red-teaming: submit target, select attack categories, view results with heuristic+LLM scores, scan history |
| **/mcp-scanner** | MCP server scanner: probe endpoint, view enumeration (tools/resources/prompts), attack results, secrets detected, scan history |
| **/attack-suite** | MITRE ATT&CK attack pattern mapping |
| **/ai-attack-suite** | AI-powered attack scenario generation |
| **/nuclei** | Template enumeration, custom query execution |
| **/nmap** | Service discovery: port scan, version detection |
| **/ffuf** | Directory/path fuzzing: wordlist selection, pattern matching |
| **/takeover** | Subdomain takeover vulnerability detection |
| **/firewall** | WAF detection results, evasion techniques |
| **/mobile** | Mobile app scanning (iOS/Android), decompilation, permission analysis |
| **/mobile/patterns** | Mobile vulnerability pattern library |
| **/cloud** | Cloud asset discovery: S3 buckets, GCP resources, IAM analysis |
| **/network** | Network topology visualization (D3/XY Flow) |
| **/mitre** | MITRE ATT&CK framework tactics/techniques mapping |
| **/test-generator** | Automated security test generation for OWASP Top 10 |
| **/attackmapper** | Attack path mapping (graph visualization) |
| **/settings** | Profile settings + SLA configuration |
| **/settings/members** | Manage members, roles, invite codes |
| **/settings/integrations** | Connect Slack, Jira, Teams, webhooks |
| **/settings/notifications** | Configure notification channels & event subscriptions |
| **/settings/schedules** | Create/manage recurring scans |
| **/settings/templates** | Save scan templates for quick reuse |
| **/settings/audit-log** | Audit trail of user actions |

**Frontend Stack** (key deps from `package.json`):

| Dependency | Version | Purpose |
|------------|---------|---------|
| next | ^15.3.1 | React framework |
| react | ^19.0.0 | UI library |
| typescript | ^5 | Type safety |
| @tanstack/react-query | ^5.0.0 | Data fetching/caching |
| @tanstack/react-table | ^8.0.0 | Table components |
| @xyflow/react | ^12.10.2 | Graph/network visualization |
| recharts | ^2.12.0 | Charts |
| tailwindcss | ^3.4.0 | CSS utility framework |
| @radix-ui/* | ^1-2.x | Accessible component library |
| react-hook-form | ^7.52.0 | Form state management |
| zod | ^3.23.0 | Schema validation |
| zustand | ^4.5.0 | State management |
| sonner | ^1.5.0 | Toast notifications |
| lucide-react | ^0.400.0 | Icon library |
| date-fns | ^3.6.0 | Date utilities |

---

## 5. ENVIRONMENT VARIABLES & CONFIG

Config file: `platform/backend/app/core/config.py`

```bash
# Application
APP_NAME=AttackTrace
APP_VERSION=1.0.0
DEBUG=false
ENVIRONMENT=production

# API
API_V1_PREFIX=/api/v1
SECRET_KEY=change-me-in-production-use-32-char-min   # HS256 JWT signing
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=480     # 8 hours
REFRESH_TOKEN_EXPIRE_DAYS=7

# Database
DATABASE_URL=postgresql+asyncpg://attacktrace:attacktrace@localhost:5432/attacktrace
DATABASE_READ_REPLICA_URL=          # optional read replica
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=40
DATABASE_POOL_TIMEOUT=30
DATABASE_STATEMENT_TIMEOUT_MS=30000

# Redis
REDIS_URL=redis://localhost:6379/0
REDIS_SCAN_PUBSUB_DB=1              # DB 1: scan events pub/sub

# CORS
CORS_ORIGINS=["http://localhost:3000","http://127.0.0.1:3000"]
CORS_ALLOW_CREDENTIALS=true

# Celery
CELERY_BROKER_URL=redis://localhost:6379/2   # DB 2: task queue
CELERY_RESULT_BACKEND=redis://localhost:6379/3  # DB 3: task results
CELERY_TASK_SOFT_TIME_LIMIT=7200    # 2 hours
CELERY_TASK_TIME_LIMIT=7800         # 2h 10m

# Encryption
KMS_MASTER_KEY=change-me-32-bytes-base64-encoded==  # Fernet AES-256

# Anthropic AI
ANTHROPIC_API_KEY=                  # optional, only for AI features
AI_MODEL=claude-haiku-4-5-20251001
AI_MAX_TOKENS=2048

# AttackTrace CLI
ATTACKTRACE_WORKSPACE_DIR=~/.attacktrace/scans

# MSRA sidecar (Mobile Security Review Assistant)
MSRA_URL=http://localhost:5001

# Pagination
DEFAULT_PAGE_SIZE=50
MAX_PAGE_SIZE=200

# Rate limiting
RATE_LIMIT_PER_MINUTE=60
```

Production validation: Config enforces that `SECRET_KEY` and `KMS_MASTER_KEY` are changed from defaults — fail-fast at startup.

---

## 6. KEY PYTHON DEPENDENCIES (Backend)

File: `platform/backend/requirements.txt`

| Dependency | Version | Purpose |
|------------|---------|---------|
| fastapi | >=0.115.0 | Async web framework |
| uvicorn[standard] | >=0.30.0 | ASGI server |
| sqlalchemy[asyncio] | >=2.0.0 | Async ORM |
| asyncpg | >=0.29.0 | PostgreSQL async driver |
| alembic | >=1.13.0 | Database migrations |
| pydantic[email] | >=2.0.0 | Data validation |
| pydantic-settings | >=2.0.0 | Env-based config |
| passlib[bcrypt] | >=1.7.4 | Password hashing |
| bcrypt | 4.0.1 | Bcrypt hashing (pinned) |
| PyJWT | >=2.8.0 | JWT encoding/decoding |
| redis | >=5.0.0 | Redis client |
| celery | >=5.3.0 | Task queue |
| anthropic | >=0.34.0 | Anthropic Claude API |
| httpx | >=0.27.0 | Async HTTP client |
| python-multipart | >=0.0.9 | Multipart form parsing |
| cryptography | >=42.0.0 | Fernet encryption |
| psycopg2-binary | >=2.9.9 | PostgreSQL sync driver (Celery) |
| pyyaml | >=6.0.0 | YAML parsing (nuclei templates) |
| celery-redbeat | >=2.2.0 | Redis-backed scheduler (HA) |
| slowapi | >=0.1.9 | Rate limiting |
| structlog | >=24.0.0 | Structured logging |
| networkx | >=3.0 | Graph analysis (network mapping) |
| wafw00f | >=2.2.0 | WAF detection |
| dnspython | >=2.6.0 | DNS lookups |
| playwright | >=1.40.0 | Headless browser (screenshots) |
| croniter | >=2.0.0 | Cron expression parsing |
| weasyprint | >=62.0 | PDF generation (reports) |

---

## 7. AI SCANNER: PLUGINS, CATEGORIES, ATTACK STRATEGIES

File: `platform/backend/app/api/v1/ai_scanner.py` (~1,616 lines)

Architecture: Inspired by promptfoo's red-teaming framework. 40+ categorized attack plugins × multiple strategies with dual grading (heuristic + LLM).

### Plugin Categories

**1. Prompt Injection** (OWASP LLM01)
- Direct Instruction Override (MITRE AML.T0051)
- System Prefix Injection
- Completion Attacks
- Context Separator Injection
- Special Token Boundary Exploit
- Indirect Hint Extraction

**2. Jailbreaks** (OWASP LLM01)
- DAN (Do Anything Now)
- STAN (Strive to Assist Now)
- Grandma Exploit
- Role-Play Override
- Hypothetical Framing
- Token Smuggling

**3. Information Disclosure** (OWASP LLM06)
- Training Data Extraction (AML.T0056)
- Prompt Leakage (AML.T0057)
- Credential Inference (AML.T0050)
- Membership Inference
- Model Fingerprinting
- API Key Enumeration

**4. Access Control Bypass** (OWASP LLM05)
- Role Escalation (AML.T0052)
- Permission Override
- Scope Creep
- Tool Abuse

**5. Harmful Content** (OWASP LLM02)
- Malware Generation
- Illegal Activity Guidance
- Violence Escalation
- Phishing Content Generation

**6. Technical Attacks** (OWASP LLM01, LLM02)
- XML External Entity (XXE)
- Denial of Service
- Code Injection
- Unicode Encoding Bypass

**7. Behavioral** (OWASP LLM08, LLM09)
- Excessive Agency (AML.T0059)
- Hallucination Exploitation
- Consistency Failure

### Attack Strategies

Each plugin can execute multiple strategies:

1. **Direct** — single-turn prompt
2. **Adversarial Suffix** — append adversarial text to prompt
3. **Role-play** — assume alternative role/persona
4. **Few-shot** — provide examples of "bad" behavior
5. **Multi-turn** — crescendo attacks across 5 turns (gradual escalation)
6. **Translation** — encode in other languages
7. **Paraphrase** — rephrase attack objective

### Grading Mechanisms

- **Heuristic** (fast, rule-based): Detects `vulnerable_phrases` (e.g., "system prompt", "configuration", "i was told") vs. `safe_phrases` ("cannot", "won't", "not allowed")
- **LLM** (Claude-powered): Calls Anthropic to evaluate response severity

### Endpoints

```
POST /ai-scanner/scan
GET  /ai-scanner/history
GET  /ai-scanner/history/{scan_id}
DELETE /ai-scanner/history/{scan_id}
```

Output per plugin: plugin ID, name, category, OWASP/MITRE mappings, strategies tested, vulnerability score (0.0-1.0), evidence (successful payload + response excerpt), remediation guidance.

---

## 8. MCP SCANNER: 4-PHASE SCAN FLOW

File: `platform/backend/app/api/v1/mcp_scanner.py` (~1,061 lines)

Purpose: Comprehensive security scanner for MCP (Model Context Protocol) servers.

### Phase 1: Discovery

- Probes ~20 common MCP endpoint paths (JSON-RPC + SSE)
- Paths: `/messages`, `/messages/`, `/mcp`, `/mcp/v1`, `/.well-known/mcp`, `/rpc`, `/jsonrpc`, `/api`, `/api/v1`, `/`, etc.
- Sends JSON-RPC `initialize` handshake to confirm MCP server
- Indicator: presence of `protocolVersion`, `serverInfo`, `capabilities` in response
- Severity: HIGH (unauthenticated server confirmation)

### Phase 1b: SSE Detection

- Probes Server-Sent Events endpoints (`/sse`, `/mcp/sse`, `/events`)
- If SSE found, follows up with `SSE_TO_MESSAGE_MAP` to probe corresponding JSON-RPC endpoint

### Phase 2: Enumeration

- Calls `tools/list`, `resources/list`, `prompts/list` JSON-RPC methods
- Extracts tool schemas, resource URIs, system prompts
- Severity: CRITICAL (tools/list) to MEDIUM (prompts/list)

### Phase 3: Attack

| Attack | ID | Severity | OWASP | MITRE | Description |
|--------|----|----|-------|-------|-------------|
| Path Traversal | path_traversal | CRITICAL | A01 | AML.T0057 | Tests `../../etc/passwd` patterns in tool args |
| Remote Code Execution | rce_eval | CRITICAL | A03 | AML.T0057 | Tests `__import__`, `eval`, shell metacharacters |
| SSRF | ssrf | HIGH | A10 | AML.T0057 | Tests `http://localhost:*`, `file://`, `gopher://` URLs |
| Indirect Prompt Injection | indirect_prompt | HIGH | LLM01 | AML.T0051 | Injects markdown/XML in tool responses |
| Command Injection | command_injection | CRITICAL | A03 | AML.T0057 | Shell metacharacters in parameters |
| Template Injection | template_injection | HIGH | A03 | AML.T0057 | Jinja2/Twig/SSTI payloads |

Attack runs against all discovered endpoints + a set of blind paths (even if discovery found nothing).

### Phase 4: Intelligence

Analyzes all collected responses for:
- **Secrets**: AWS keys (`AKIA[0-9A-Z]{16}`), Anthropic keys (`sk-ant-*`), OpenAI keys (`sk-*`), GitHub tokens (`ghp_*`), private keys
- **PII**: Email addresses, phone numbers, SSNs, credit card patterns
- **Malicious Tools**: Dangerous tool names (file_write, execute, system_call)
- **Typosquatting**: Levenshtein distance ≤ 2 against 13 known trusted MCP server names
- **Prompt Injection Markers**: Detects indirect injection in tool descriptions

### Endpoints

```
POST   /mcp-scanner/scan
GET    /mcp-scanner/history
GET    /mcp-scanner/history/{scan_id}
DELETE /mcp-scanner/history/{scan_id}
GET    /mcp-scanner/vulnerabilities   # catalog of all checks
```

History persistence: Filesystem JSON at `{ATTACKTRACE_WORKSPACE_DIR}/mcp-scanner/{org_id}/{scan_id}.json`

---

## 9. CELERY TASK STRUCTURE AND QUEUES

Config: `platform/backend/app/workers/celery_app.py`

Broker: Redis (DB 2 for tasks, DB 3 for results).

### Task Queues

| Queue | Purpose | Tasks |
|-------|---------|-------|
| **scans** | Long-running scan execution | `run_scan` |
| **ai** | AI/LLM operations | `triage_scan_findings` |
| **default** | System maintenance | `recover_stuck_scans`, `check_scheduled_scans` |

Workers start with: `-Q scans,ai,default`

### Key Tasks (`platform/backend/app/workers/`)

**scan_worker.py**:
- `run_scan(scan_job_id)` — Execute AttackTrace session, stream progress via Redis pub/sub, persist findings
- `recover_stuck_scans()` — Periodic (every 5 min): find PENDING/RUNNING scans, retry if timeout exceeded
- `triage_scan_findings(scan_job_id)` — Call Claude to triage findings (severity, reasoning, confidence)

**schedule_worker.py**:
- `check_scheduled_scans()` — Periodic (every 60s): check ScheduledScan for due jobs, enqueue `run_scan`

### Configuration

```python
task_serializer = "json"
task_soft_time_limit = 7200    # 2 hours (SoftTimeLimitExceeded raised)
task_time_limit = 7800         # 2h 10m (hard kill)
task_acks_late = True          # Ack after task completion
task_reject_on_worker_lost = True  # Requeue if worker dies
worker_prefetch_multiplier = 1     # Fair distribution
result_expires = 3600          # Keep results 1 hour
```

### Beat Schedule (periodic tasks)

- `recover-stuck-scans-every-5min`: 300s interval
- `check-scheduled-scans`: 60s interval

### Dead Letter Queue (DLQ)

- Failed tasks (exhausted retries) → Redis list `scans:dlq` (capped at 1000 entries)
- Allows operators to inspect & replay without losing context

---

## 10. AUTHENTICATION MODEL

Auth module: `platform/backend/app/core/security.py`

### JWT Token Structure

**Access Token** (8 hours):
```json
{
  "sub": "user_id (UUID string)",
  "org_id": "org_id (UUID string)",
  "role": "owner|admin|analyst|viewer",
  "iat": 1234567890,
  "exp": 1234567890,
  "type": "access"
}
```

**Refresh Token** (7 days):
```json
{
  "sub": "user_id",
  "iat": 1234567890,
  "exp": 1234567890,
  "type": "refresh",
  "jti": "unique_token_id"
}
```

Signing: HS256 with `SECRET_KEY` (must be ≥32 chars in production).

### Role-Based Access Control

Member roles (enum in `user.py`):
1. **OWNER** — Full org access, member/API key/credential management
2. **ADMIN** — Create scans, manage workspaces, invite members (no credential edit)
3. **ANALYST** — Create/view scans, triage findings, post comments
4. **VIEWER** — Read-only access to findings/assets/scans

**Tool Permissions** (stored in `OrgMember.tool_permissions` array):
- Per-tool access control (e.g., allow "nuclei" but deny "firewall")
- If null, inherit all tools for role
- Allows fine-grained RBAC for compliance/separation of duties

### Authentication Flow

**Registration** (`/auth/register`):
- Validate invite code (must be valid, not expired, not revoked, email match optional)
- Hash password (bcrypt)
- Create User + OrgMember with role from invite
- Return access + refresh tokens

**Login** (`/auth/login`):
- Verify password (bcrypt), check `is_active`, update `last_login`
- Account lockout: 5 failed attempts → 15 min lock (Redis-backed)
- Return tokens with org_id + role

**Token Refresh** (`/auth/refresh`):
- Decode refresh token, check Redis validity
- Rotate: revoke old, issue new refresh token

**API Key Authentication**:
- `ApiKey.key_hash` stored as SHA-256
- Format: `Authorization: Bearer attacktrace_<40-char-token>`
- Constant-time comparison to prevent timing attacks
- Optional expiry + last_used tracking

---

## 11. CREDENTIAL ENCRYPTION

Approach: Fernet (symmetric, authenticated encryption) via `cryptography` library.

### Key Derivation

1. `KMS_MASTER_KEY` env var (32-byte base64-encoded string)
2. Derive key via SHA-256:
   ```python
   derived = hashlib.sha256(KMS_MASTER_KEY.encode()).digest()
   fernet_key = base64.urlsafe_b64encode(derived)
   cipher = Fernet(fernet_key)
   ```

### Operations

- `encrypt_credential(plaintext: str) -> str` — Fernet encrypts, returns base64 ciphertext
- `decrypt_credential(ciphertext: str) -> str` — Fernet decrypts, returns plaintext

### Encrypted Fields (`OrgCredentials` model)

- `anthropic_key_enc`, `shodan_key_enc`, `censys_id_enc`, `censys_secret_enc`
- `securitytrails_key_enc`, `github_token_enc`, `alienvault_key_enc`
- `passivetotal_user_enc`, `passivetotal_key_enc`

`NotificationChannel.config_enc` also stores Fernet-encrypted JSON config (webhook URLs, tokens).

### Security Properties

- Fernet includes timestamp + HMAC-SHA256 for authenticity — tampered ciphertext throws `InvalidToken`
- No plaintext credentials ever logged or exposed in error messages
- `KMS_MASTER_KEY` should be protected via AWS Secrets Manager, HashiCorp Vault, or env secrets
- Key rotation requires rekeying all encrypted fields (not yet automated)

---

## SUMMARY TABLE

| Component | Technology | Purpose | Path |
|-----------|-----------|---------|------|
| API Server | FastAPI + Uvicorn | Multi-tenant REST API | `platform/backend/app/main.py` |
| ORM | SQLAlchemy 2.0 (async) | PostgreSQL data modeling | `platform/backend/app/models/db/` |
| Auth | JWT (HS256) + Refresh tokens | User session management | `platform/backend/app/core/security.py` |
| Encryption | Fernet (AES-256-GCM) | Credential encryption | `platform/backend/app/core/security.py` |
| Task Queue | Celery + Redis | Async scan execution | `platform/backend/app/workers/` |
| Database | PostgreSQL + asyncpg | Persistent data store | Config: `DATABASE_URL` |
| Cache | Redis (3 DBs) | Pub/sub, token revocation, task queue | Config: `REDIS_URL` |
| Frontend | Next.js 15 + React 19 | Web UI | `platform/frontend/` |
| AI Service | Anthropic Claude | Finding triage, NL search, attack generation | `platform/backend/app/services/ai_service.py` |
| AI Scanner | 40+ plugins | LLM red-teaming | `platform/backend/app/api/v1/ai_scanner.py` |
| MCP Scanner | 4-phase scanner | MCP server security testing | `platform/backend/app/api/v1/mcp_scanner.py` |
| Logging | structlog | Structured logging | `platform/backend/app/main.py` |
| Rate Limiting | slowapi | API throttling (200 req/min) | `platform/backend/app/main.py` |

**Health checks**: `GET /health` and `GET /ready` (DB, Redis, Celery broker connectivity)
