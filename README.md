<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Next.js-15-black?style=for-the-badge&logo=next.js&logoColor=white" alt="Next.js">
  <img src="https://img.shields.io/badge/Docker-required-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker">
  <img src="https://img.shields.io/badge/Claude-AI-blueviolet?style=for-the-badge&logo=anthropic&logoColor=white" alt="Claude AI">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Status-Active-success?style=for-the-badge" alt="Status">
</p>

<h1 align="center">AttackTrace</h1>

<p align="center">
  <b>External Attack Surface Management Platform</b>
</p>

<p align="center">
  A full-stack security platform for external attack surface discovery, vulnerability scanning, AI-powered triage, and team-based finding management. Point it at a domain and get a complete picture of your external footprint — subdomains, exposed services, vulnerabilities, cloud assets, and more.
</p>

---

## Platform Preview

<p align="center">
  <img src="docs/images/report-dashboard.png" alt="AttackTrace Dashboard" width="100%">
</p>

<details>
<summary><b>More Screenshots</b></summary>

### Subdomains Discovery
<p align="center">
  <img src="docs/images/report-subdomains.png" alt="Subdomains" width="100%">
</p>

### Web Applications
<p align="center">
  <img src="docs/images/report-webapps.png" alt="Web Applications" width="100%">
</p>

### Screenshot Gallery
<p align="center">
  <img src="docs/images/report-screenshots.png" alt="Screenshot Gallery" width="100%">
</p>

</details>

---

## Features

### Platform

| Category | Capabilities |
|---|---|
| **Dashboard** | Live log-scaled risk score, asset/finding counts, risk trend chart, recent scans |
| **Scans** | Full scan lifecycle management, real-time SSE progress streaming, cancel/delete |
| **Assets** | Filterable asset inventory (domain, subdomain, IP, webapp, cloud), screenshot thumbnails |
| **Findings** | Unified view: recon + mobile findings, expandable rows with evidence/PoC/remediation, severity triage, status workflow, CVE linking, suppression rules |
| **Reports** | Auto-generated HTML reports per scan with full asset and finding detail |
| **Audit Log** | Immutable record of all platform actions by user, type-filtered, CSV export |

### Scan Engine (24 modules)

| Category | Capabilities |
|---|---|
| **Asset Discovery** | Subdomain enumeration, ASN/IP range mapping, certificate transparency, DNS resolution |
| **Infrastructure** | Port scanning (100+ ports), service detection, banner grabbing |
| **Web Analysis** | HTTP probing, technology fingerprinting (60+ signatures), Playwright screenshots |
| **Cloud** | AWS S3, Azure Blob, GCP bucket enumeration |
| **OSINT** | GitHub recon, employee discovery, leaked credential detection |
| **Threat Intel** | Shodan, Censys, SecurityTrails, AlienVault OTX, GreyNoise, URLScan, PassiveTotal |
| **Enrichment** | CVE/CVSS from NVD, KEV status, EPSS score, priority scoring |

### Security Tools

| Tool | Description |
|---|---|
| **Nmap Scanner** | 7 scan types, custom port ranges, parsed results with service/version |
| **Nuclei Scanner** | Template-based scanning, severity filter, live stderr progress, CVE enrichment |
| **ffuf Fuzzer** | Directory/param/subdomain fuzzing, 13 bundled wordlists, custom wordlists |
| **Attack Suite** | 24-module adaptive web scanner — crawler + pattern library from 5700+ bug bounty reports |
| **AI Attack Suite** | Shannon autonomous AI pentester — real exploit execution with CVSS reports |
| **Takeover Checker** | CNAME chain analysis, 42+ service fingerprints, NS/MX takeover detection |
| **Attack Path Mapper** | MITRE ATT&CK-mapped paths for AD, AWS, Azure, GCP, and network infrastructure |
| **Mobile Scanner (MSRA)** | APK/IPA static analysis, dynamic analysis, AI PoC generation, findings federation into central dashboard |
| **Test Case Generator** | OWASP WSTG-based test cases (Standard) or Claude-powered custom cases (AI-Assisted) |

### Mobile Security (MSRA)

MSRA (Mobile Security Review Assistant) is a sidecar service that integrates with AttackTrace for mobile app security analysis.

| Feature | Description |
|---|---|
| **Static Analysis** | Upload APK/IPA/JAR — automated vulnerability scan with MobSF-style findings |
| **Dynamic Analysis** | AI-driven runtime testing — spawns emulator sessions, generates payloads, intercepts traffic |
| **AI PoC Generation** | Claude generates proof-of-concept exploit code for each finding |
| **Findings Federation** | MSRA findings sync into the central Findings dashboard alongside recon findings |
| **Unified View** | All mobile + recon findings in one expandable list with severity, evidence, remediation, and source badges |

**Setup:** Start the MSRA server (automatically handled by `./start.sh`). Access the mobile scanner at `/mobile` in the AttackTrace frontend.

---

### AI Features (Claude-powered)

| Feature | Description |
|---|---|
| **Finding Triage** | Auto-classify severity, detect false positives, confidence score |
| **Executive Summary** | 3-bullet non-technical scan summary with risk posture and next steps |
| **Jira Ticket Generator** | Structured remediation tickets with acceptance criteria and effort estimate |
| **NL Search** | Natural-language query translation to structured asset/finding filters |
| **AI Test Cases** | Customized security test cases based on target, stack, and threat model |

### Team & Access

| Feature | Description |
|---|---|
| **Multi-tenancy** | Organization isolation, per-org API keys and credentials |
| **Roles** | Owner / Admin / Analyst / Viewer with enforced permissions |
| **Team Management** | Direct user creation or shareable invite link (permanent, open, analyst role) |
| **API Keys** | Generate platform API keys for CI/CD pipelines and custom integrations |
| **Integrations** | Jira, Slack, webhook — configured per org with encrypted credential storage |

---

## Stack

| Layer | Technology |
|---|---|
| Backend | FastAPI + SQLAlchemy (async) + Alembic |
| Frontend | Next.js 15 + React 19 + Tailwind CSS + shadcn/ui |
| Task Queue | Celery + Redis (3 queues: default, scans, ai) |
| Database | PostgreSQL 16 |
| AI | Anthropic Claude (claude-haiku-4-5 default, configurable) |
| Scan Engine | AttackTrace Python CLI + nuclei + ffuf + nmap + Playwright |
| Monitoring | Celery Flower |
| Deployment | Docker Compose (dev) · Kubernetes + KEDA (prod) |

---

## Installation

Choose the method that works for your environment.

---

### Option A — Without Docker (recommended for most users)

**Prerequisites:** Python 3.11+, Node.js 18+, PostgreSQL, Redis

Install prerequisites on macOS:
```bash
brew install python@3.11 node postgresql@16 redis
brew services start postgresql@16
brew services start redis
```

Install prerequisites on Ubuntu/Debian:
```bash
sudo apt update && sudo apt install -y python3.11 python3.11-venv nodejs npm postgresql redis-server
sudo systemctl start postgresql redis-server
```

**Then:**

```bash
git clone https://github.com/BaymaxPop23/AttackTrace.git
cd AttackTrace
chmod +x start.sh && ./start.sh
```

Or using Make:
```bash
make start
```

The script will:
1. Create a Python virtual environment and install all dependencies
2. Install frontend Node modules
3. Generate a `.env` with random secrets
4. Create the PostgreSQL database and user
5. Run database migrations
6. Create the default admin account
7. Start backend, Celery worker, Celery beat, Next.js dev server, and MSRA mobile sidecar (if present at `~/Desktop/Coding/MSRA`)

**Stop all services:**
```bash
./stop.sh   # or: make stop
```

---

### Option B — With Docker

**Prerequisites:** [Docker Desktop](https://docs.docker.com/get-docker/) (includes Compose)

```bash
git clone https://github.com/BaymaxPop23/AttackTrace.git
cd AttackTrace
chmod +x setup.sh && ./setup.sh
```

Or using Make:
```bash
make setup
```

**Stop:**
```bash
make down
```

---

### Log in

Once running, open **http://localhost:3000**

| Field | Value |
|---|---|
| Username | `admin` |
| Password | `Ihate13$` |

> Change the default password immediately after first login via **Settings → Profile**.

---

### Install scanning tools (optional but recommended)

To use Nuclei, ffuf, Nmap, and other scanners:

```bash
make install-tools
```

Installs: `nuclei`, `ffuf`, `nmap`, `gowitness`, `SecLists`, `nuclei-templates`, and Playwright browsers.

---

### Configure AI features (optional)

Set your Anthropic API key to enable AI triage, executive summaries, and the AI Attack Suite:

**Native:** Add to `platform/backend/.env`:
```
ANTHROPIC_API_KEY=sk-ant-...
```

**Docker:** Add to `.env` at the repo root, then `make restart`.

The platform works without an API key — AI features are gracefully disabled.

---

## Updating

Pull the latest changes and restart:

**Without Docker:**
```bash
git pull && ./start.sh
```

**With Docker:**
```bash
make update
```

Both automatically run new database migrations before restarting.

---

## Useful Commands

```bash
# Native (no Docker)
make start          # Start all services
make stop           # Stop all services

# Docker
make setup          # First-time Docker setup
make update         # Pull + rebuild + restart
make up             # Start containers
make down           # Stop containers
make logs           # Tail all container logs
make ps             # Container status
make backend-logs   # Backend logs only
make worker-logs    # Worker logs only

# Database
make migrate        # Run pending migrations
make seed           # Re-run initial data seed
make db-shell       # PostgreSQL interactive shell

# Tools
make install-tools  # Install nuclei, ffuf, nmap, etc.
make lint           # Lint + type-check backend
```

---

## Team Members

Go to **Settings → Team Members** to manage your organization:

- **Direct create** — admins can create a user account directly with name, email, password, and role
- **Invite link** — share a permanent invite link; anyone with the code can self-register as Analyst

**Roles:**

| Role | Permissions |
|---|---|
| Owner | Full access, billing, cannot be removed |
| Admin | Manage team, settings, all scans and findings |
| Analyst | Run scans, manage findings, use all tools |
| Viewer | Read-only access to scans, assets, findings |

---

## Third-Party API Keys

Configure enrichment keys at **Settings → Integrations**:

| Service | Used for |
|---|---|
| Shodan | Open ports, CVEs, service banners |
| Censys | Certificate transparency, host discovery |
| SecurityTrails | Passive DNS, subdomain history |
| GitHub Token | Repository recon, secret detection |
| AlienVault OTX | Threat intelligence, IOCs |
| PassiveTotal | Passive DNS, WHOIS history |
| Jira | Automatic remediation ticket creation |
| Slack | Scan completion and critical finding alerts |

All credentials are encrypted with AES-256-GCM before storage.

To generate **platform API keys** for CI/CD pipelines or custom integrations, go to **Settings → API Keys**.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   AttackTrace                        │
│                                                      │
│  ┌──────────────┐    ┌──────────────────────────┐  │
│  │  Next.js 15  │───▶│    FastAPI + SQLAlchemy   │  │
│  │   :3000      │    │        :8000              │  │
│  └──────────────┘    └──────────┬───────────────┘  │
│                                  │                   │
│              ┌───────────────────┼──────────┐        │
│              ▼                   ▼          ▼        │
│       ┌──────────┐        ┌──────────┐  ┌────────┐  │
│       │ Postgres │        │  Redis   │  │ Celery │  │
│       │  :5432   │        │  :6379   │  │ Worker │  │
│       └──────────┘        └──────────┘  └────────┘  │
│                                          (3 queues)  │
│                                     default·scans·ai │
└─────────────────────────────────────────────────────┘
```

- **Celery Worker** runs long scans asynchronously, streaming progress via Redis pub/sub SSE
- **Celery Beat** runs a watchdog every 5 minutes to recover stuck or crashed scans
- **Redis** also stores dashboard stats cache, scan event replay buffer, and AI circuit breaker state
- **Flower** (Celery monitoring UI) available at http://localhost:5555/flower

---

## Kubernetes Deployment

Production manifests are in `k8s/`:

```bash
# Apply all manifests
make k8s-apply

# Run migrations in the cluster
make k8s-migrate

# Check status
make k8s-status
```

Key files:
- `k8s/configmap.yaml` — non-secret config (update `CORS_ORIGINS` and `NEXT_PUBLIC_API_URL` for your domain)
- `k8s/secrets.yaml` — template for secrets (use External Secrets Operator in production)
- `k8s/ingress.yaml` — nginx ingress with TLS (update `app.attacktrace.io` to your domain)
- `k8s/keda-scaledobject.yaml` — worker autoscaling based on Redis queue depth

---

## Troubleshooting

### Native (no Docker)

**Backend fails to start — `SettingsError: error parsing CORS_ORIGINS`**

Remove the `CORS_ORIGINS` line from `platform/backend/.env` — the default in `config.py` already covers `localhost:3000`:
```bash
sed -i '' '/^CORS_ORIGINS=/d' platform/backend/.env
```

**Backend fails to start — `ValueError: password cannot be longer than 72 bytes`**

bcrypt 5.x / passlib incompatibility. Reinstall the pinned version:
```bash
platform/backend/.venv/bin/pip install 'bcrypt==4.0.1'
```

**`psql` not found on macOS**

Homebrew PostgreSQL isn't in PATH. Add it:
```bash
export PATH="/opt/homebrew/opt/postgresql@16/bin:$PATH"
```
Or re-run `start.sh` — it patches PATH automatically.

**`npm ci` fails with lock file error (Node 25+)**

Use `npm install` instead — `start.sh` does this by default.

**Backend port 8000 already in use**
```bash
lsof -ti :8000 | xargs kill -9
```

**Scanning tools not found (nuclei / ffuf / nmap)**
```bash
make install-tools
```

**View logs**
```bash
tail -f logs/backend.log
tail -f logs/worker.log
tail -f logs/frontend.log
```

---

### Docker

**Containers won't start**
```bash
make logs          # Check what's failing
make down && make up
```

**Database migration errors**
```bash
make migrate
```

**Backend not responding after update**
```bash
make backend-logs  # Check for errors
make restart
```

---

### Both modes

**Forgot the admin password**

Reset it directly in the database:
```bash
# Docker:
make db-shell
# Native:
psql -U attacktrace -d attacktrace
# Inside psql — generate hash with: python3 -c "from passlib.context import CryptContext; print(CryptContext(['bcrypt']).hash('NewPassword!'))"
UPDATE users SET hashed_password = '<bcrypt-hash>' WHERE email = 'admin';
```

**Dashboard shows stale asset or finding counts after deleting a scan**

This is fixed in the current version (Redis cache is invalidated on delete). If you're on an older version, click the **Refresh** button on the dashboard or wait up to 5 minutes for the cache to expire.

---

## Legal Notice

AttackTrace is intended for **authorized security testing only**. Only scan targets you own or have explicit written permission to test. Unauthorized scanning may violate computer fraud laws in your jurisdiction. The authors accept no liability for misuse.

---

## License

MIT — see [LICENSE](LICENSE) for details.
