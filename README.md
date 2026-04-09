<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-blue?style=for-the-badge" alt="Platform">
  <img src="https://img.shields.io/badge/Status-Active-success?style=for-the-badge" alt="Status">
</p>

<h1 align="center">AttackTrace</h1>

<p align="center">
  <b>A comprehensive external attack surface discovery tool for red team engagements</b>
</p>

<p align="center">
  Provide a company name or domain, and AttackTrace automatically discovers websites, applications, exposed services, cloud assets, employees, leaked credentials, and potential vulnerabilities — then generates an interactive HTML report.
</p>

---

## Report Preview

<p align="center">
  <img src="docs/images/report-dashboard.png" alt="AttackTrace Dashboard" width="100%">
</p>

<p align="center"><i>Interactive dashboard with attack surface metrics and security findings</i></p>

<details>
<summary><b>View More Screenshots</b></summary>

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

### Discovery Modules

| Module | Description | Type |
|:------:|-------------|:----:|
| **Subdomain Enumeration** | Multi-source discovery via Certificate Transparency, DNS bruteforce, passive sources | Passive |
| **ASN & IP Range Discovery** | BGP/WHOIS lookups to map organization IP space | Passive |
| **Port Scanning** | 100+ ports including SFTP, FTP, SMB, databases, admin panels | Active |
| **Technology Fingerprinting** | 60+ technology signatures (frameworks, CMS, servers) | Active |
| **Cloud Asset Discovery** | AWS S3, Azure Blob, GCP bucket enumeration | Active |

### OSINT Capabilities

| Capability | Description |
|:----------:|-------------|
| **GitHub Intelligence** | Organization repos, commit history, leaked secrets in code |
| **Employee Discovery** | Email patterns, names, positions via Hunter.io |
| **Secret Detection** | API keys, AWS credentials, database passwords, private keys |
| **Credential Exposure** | Check employee emails against breach databases |

### Intelligence Platforms

| Platform | Features |
|:--------:|----------|
| **Shodan InternetDB** | CVEs, open ports, hostnames (no API key required) |
| **Censys** | Certificate & host discovery |
| **SecurityTrails** | Passive DNS, subdomain history |
| **AlienVault OTX** | Threat pulses, IOCs |
| **URLScan.io** | Screenshots, DOM analysis |
| **GreyNoise** | Scanner identification |
| **IPinfo** | Geolocation, ASN, VPN detection |
| **BuiltWith** | Technology stack profiling |
| **Chaos (ProjectDiscovery)** | Massive subdomain database |
| **PassiveTotal / RiskIQ** | Passive DNS, WHOIS history |
| **Wayback Machine** | Historical URLs, config files |

### Breach & Credential Checking

| Service | Features |
|:-------:|----------|
| **HaveIBeenPwned** | Check if employee emails appear in breaches |
| **DeHashed** | Search breach databases for exposed credentials |
| **LeakCheck** | Credential leak verification |
| **Intelligence X** | Dark web, paste sites, breach data |

---

## Interactive HTML Reports

AttackTrace generates professional, self-contained HTML reports with:

- **Dark theme** with modern UI
- **Collapsible sections** for easy navigation
- **Screenshot gallery** with zoom/preview modal
- **Service exploitation guides** with detailed attack techniques
- **Risk scoring** and severity indicators
- **Filtering & search** capabilities

---

## Installation

### Prerequisites

- Python 3.10 or higher
- pip

### Option 1 — pip install (recommended)

```bash
git clone https://github.com/BaymaxPop23/AttackTrace.git
cd AttackTrace
pip install -e .
```

For screenshot support (optional but recommended):

```bash
pip install -e ".[screenshots]"
playwright install chromium
```

### Option 2 — Virtual environment (isolated)

```bash
git clone https://github.com/BaymaxPop23/AttackTrace.git
cd AttackTrace

python3 -m venv venv
source venv/bin/activate          # macOS/Linux
# venv\Scripts\activate           # Windows

pip install -r requirements.txt
pip install -e .

# Optional: screenshot support
playwright install chromium
```

### Verify installation

```bash
attacktrace --help
```

---

## Quick Start

### Interactive Mode

Run without arguments to launch the guided wizard:

```bash
attacktrace
```

The wizard walks you through:
1. Target information (company name and/or domains)
2. Scan intensity (passive / normal / aggressive)
3. Module selection
4. API key configuration
5. Output format

### CLI Scan

```bash
# Scan by company name
attacktrace scan --company "Acme Corp" --domains acme.com

# Passive-only scan (no direct contact with targets)
attacktrace scan --domains example.com --intensity passive

# Full scan with output directory
attacktrace scan --company "Target Inc" --domains target.com --output ./results

# Resume or list past sessions
attacktrace sessions list
attacktrace sessions show <session-id>
```

---

## Configuration

AttackTrace looks for a config file in the following order:

1. `./attacktrace.yaml`
2. `./config/config.yaml`
3. `~/.config/attacktrace/config.yaml`
4. Environment variables (`ATTACKTRACE_` prefix)

### Example `attacktrace.yaml`

```yaml
attacktrace:
  api_keys:
    shodan: ""
    censys_id: ""
    censys_secret: ""
    securitytrails: ""
    github: ""
    hunter: ""
    urlscan: ""
    greynoise: ""
    alienvault: ""
    ipinfo: ""
    builtwith: ""
    chaos: ""
    passivetotal: ""
    passivetotal_user: ""
    hibp: ""
    dehashed: ""
    dehashed_email: ""
    leakcheck: ""
    intelx: ""

  scan:
    intensity: normal        # passive | normal | aggressive
    rate_limit: 1000         # requests per second
    timeout: 10              # seconds
    threads: 200

  modules:
    subdomain:
      bruteforce: true
      bruteforce_threads: 200
      recursive: false
    ports:
      top_ports: 1000
      scan_type: tcp         # tcp | udp | both
      service_detection: true
    web:
      screenshot: true
      tech_detect: true
    cloud:
      providers:
        - aws
        - azure
        - gcp

  output:
    directory: ./results
    formats:
      - json
      - html
    screenshots_dir: ./screenshots
```

### Environment Variables

All API keys can also be set via environment variables:

```bash
export SHODAN_API_KEY="your-key"
export CENSYS_API_ID="your-id"
export CENSYS_API_SECRET="your-secret"
export SECURITYTRAILS_API_KEY="your-key"
export GITHUB_TOKEN="your-token"
export HUNTER_API_KEY="your-key"
export URLSCAN_API_KEY="your-key"
export GREYNOISE_API_KEY="your-key"
export ALIENVAULT_API_KEY="your-key"
export IPINFO_TOKEN="your-token"
export BUILTWITH_API_KEY="your-key"
export CHAOS_API_KEY="your-key"
export HIBP_API_KEY="your-key"
export DEHASHED_API_KEY="your-key"
export DEHASHED_EMAIL="your-email"
export LEAKCHECK_API_KEY="your-key"
export INTELX_API_KEY="your-key"
```

API keys are optional. Modules with missing keys are automatically skipped.

---

## Modules

| Module | Description | Active/Passive |
|:------:|-------------|:--------------:|
| `seed` | WHOIS, Certificate Transparency, ASN discovery | Passive |
| `domain` | Subdomain enumeration from multiple sources | Passive |
| `dns` | DNS resolution for discovered domains | Active |
| `infrastructure` | Port scanning, service detection | Active |
| `enrichment` | Shodan, Censys, SecurityTrails lookups | Passive |
| `intel` | URLScan, GreyNoise, Wayback, CVEs, breach data | Passive |
| `osint` | GitHub repos, commits, employee discovery | Passive |
| `web` | HTTP probing, tech detection, screenshots | Active |
| `cloud` | S3/Azure/GCP bucket enumeration | Active |
| `correlation` | Risk scoring and data correlation | — |

---

## Port Coverage

AttackTrace scans **100+ ports** across multiple categories:

| Category | Ports |
|:--------:|-------|
| **Web** | HTTP (80), HTTPS (443), alt HTTP (8080, 8443, 8888) |
| **File Transfer** | FTP (21), SFTP/SSH (22), FTPS (990), TFTP (69) |
| **Databases** | MySQL (3306), PostgreSQL (5432), MongoDB (27017), Redis (6379), MSSQL (1433), Elasticsearch (9200) |
| **Remote Access** | RDP (3389), VNC (5900), WinRM (5985/5986), Telnet (23) |
| **Directory** | LDAP (389), LDAPS (636), Kerberos (88) |
| **File Sharing** | SMB (445), NFS (2049), NetBIOS (137-139) |
| **Containers** | Docker (2375/2376), Kubernetes API (6443), etcd (2379/2380) |
| **Messaging** | RabbitMQ (5672/15672), Kafka (9092), MQTT (1883) |

---

## Output Structure

```
results/
└── <session-id>/
    ├── scan_results.json        # Raw findings
    └── report.html              # Interactive HTML report

screenshots/
└── <session-id>/
    └── *.png                    # Web application screenshots
```

---

## Secret Detection

GitHub reconnaissance automatically scans for:

| Type | Severity |
|:----:|:--------:|
| AWS Access Keys | `CRITICAL` |
| Private Keys (RSA, PGP, SSH) | `CRITICAL` |
| Database Connection Strings | `CRITICAL` |
| Stripe Secret Keys | `CRITICAL` |
| API Keys / Tokens | `HIGH` |
| Hardcoded Passwords | `HIGH` |
| JWT Secrets | `HIGH` |
| Slack / Discord Tokens | `HIGH` |

---

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check attacktrace/
black --check attacktrace/
```

---

## Legal Notice

AttackTrace is intended for **authorized security testing only**. Only scan targets you own or have explicit written permission to test. Unauthorized scanning may violate computer fraud laws in your jurisdiction. The authors accept no liability for misuse.

---

## License

MIT — see [LICENSE](LICENSE) for details.
