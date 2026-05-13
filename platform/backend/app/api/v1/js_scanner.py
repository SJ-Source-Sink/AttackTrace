"""
JavaScript Analysis Scanner — v2
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Crawls a target, discovers JS files, beautifies minified code, then
analyses for:
  1. API endpoint extraction  (LinkFinder-style + router patterns)
  2. Secret / credential detection  (30+ provider patterns + entropy filter)
  3. DOM XSS sink + source detection  (sinks, sources, jQuery, Angular, React, Vue)
  4. Prototype pollution patterns
  5. PostMessage security issues
  6. WebSocket security & endpoint extraction
  7. Service worker abuse indicators
  8. Environment variable leaks  (REACT_APP_*, NEXT_PUBLIC_*, VITE_*)
  9. Build / webpack artifact leaks  (abs paths, debug flags, TODO+creds)
 10. Source-map exposure
 11. GraphQL introspection exposure
"""

from __future__ import annotations

import asyncio
import json
import math
import re
import string
import uuid as _uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, AsyncGenerator
from urllib.parse import urljoin, urlparse
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.core.config import get_settings as _get_settings
from app.core.dependencies import get_current_org_id, get_current_user
from app.models.db.user import User

router = APIRouter(prefix="/js-scanner", tags=["JS Scanner"])

# ──────────────────────────────────────────────────────────────────────────────
# Filesystem history helpers
# ──────────────────────────────────────────────────────────────────────────────

def _history_dir(org_id: str) -> Path:
    d = Path(_get_settings().ATTACKTRACE_WORKSPACE_DIR) / "js_scanner" / org_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def _save_scan_result(org_id: str, record: dict) -> None:
    try:
        path = _history_dir(org_id) / f"{record['id']}.json"
        path.write_text(json.dumps(record, ensure_ascii=False))
    except Exception:
        pass


def _load_history(org_id: str, limit: int = 50) -> list[dict]:
    try:
        files = sorted(
            _history_dir(org_id).glob("*.json"),
            key=lambda f: f.stat().st_mtime,
            reverse=True,
        )[:limit]
        records = []
        for f in files:
            try:
                records.append(json.loads(f.read_text()))
            except Exception:
                pass
        return records
    except Exception:
        return []


def _load_scan(org_id: str, scan_id: str) -> dict | None:
    try:
        path = _history_dir(org_id) / f"{scan_id}.json"
        if path.exists():
            return json.loads(path.read_text())
    except Exception:
        pass
    return None


def _delete_scan_record(org_id: str, scan_id: str) -> bool:
    try:
        path = _history_dir(org_id) / f"{scan_id}.json"
        if path.exists():
            path.unlink()
            return True
    except Exception:
        pass
    return False


# ──────────────────────────────────────────────────────────────────────────────
# SSE helper
# ──────────────────────────────────────────────────────────────────────────────

def _sse(event: str, data: Any) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


# ──────────────────────────────────────────────────────────────────────────────
# Pydantic model
# ──────────────────────────────────────────────────────────────────────────────

class JSScanRequest(BaseModel):
    target: str
    max_depth: int = 2
    max_files: int = 50
    include_source_maps: bool = True
    include_subdomains: bool = False


# ──────────────────────────────────────────────────────────────────────────────
# Entropy helpers
# ──────────────────────────────────────────────────────────────────────────────

def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = {c: data.count(c) / len(data) for c in set(data) if c in string.printable}
    return -sum(p * math.log2(p) for p in freq.values())


def _is_high_entropy(value: str, threshold: float = 3.5) -> bool:
    return _shannon_entropy(value) >= threshold


# ──────────────────────────────────────────────────────────────────────────────
# jsbeautifier preprocessing
# ──────────────────────────────────────────────────────────────────────────────

def _beautify(js: str) -> str:
    """Beautify minified JS to improve regex accuracy."""
    try:
        import jsbeautifier
        opts = jsbeautifier.default_options()
        opts.unescape_strings = True
        opts.eval_code = False
        opts.max_preserve_newlines = 2
        return jsbeautifier.beautify(js, opts)
    except Exception:
        return js


# ──────────────────────────────────────────────────────────────────────────────
# Detection patterns
# ──────────────────────────────────────────────────────────────────────────────

# ── Endpoint patterns ─────────────────────────────────────────────────────────

ENDPOINT_PATTERNS: list[tuple[str, str]] = [
    # Standard API paths
    (r"""['"`](/api/[^\s'"`<>]{3,})['"`]""",                         "api_path"),
    (r"""['"`](/v\d+/[^\s'"`<>]{3,})['"`]""",                        "versioned_path"),
    # fetch() calls
    (r"""fetch\s*\(\s*['"`]([^'"`]{5,})['"`]""",                     "fetch_call"),
    # axios
    (r"""axios\.(?:get|post|put|delete|patch|head)\s*\(\s*['"`]([^'"`]{5,})['"`]""", "axios_call"),
    # XHR
    (r"""\.open\s*\(\s*['"`](?:GET|POST|PUT|DELETE|PATCH)['"`]\s*,\s*['"`]([^'"`]{5,})['"`]""", "xhr_open"),
    # url config key
    (r"""(?:^|\s)url\s*:\s*['"`]([^'"`]{5,})['"`]""",               "url_property"),
    (r"""baseURL\s*:\s*['"`]([^'"`]{5,})['"`]""",                    "base_url"),
    # Full URLs
    (r"""['"`](https?://[^\s'"`<>]{10,})['"`]""",                    "full_url"),
    # jQuery ajax
    (r"""(?:\$|jQuery)\.(?:ajax|get|post|getJSON)\s*\(\s*['"`]([^'"`]{5,})['"`]""", "jquery_ajax"),
    # React Router v5/v6
    (r"""path\s*:\s*['"`]([/][^'"`\s]{2,})['"`]""",                  "react_route"),
    # Vue / Angular router
    (r"""(?:redirectTo|component)\s*:\s*['"`]([/][^'"`\s]{2,})['"`]""", "router_path"),
    # Express-style routes
    (r"""(?:app|router)\.(?:get|post|put|delete|patch|all|use)\s*\(\s*['"`]([^'"`]{2,})['"`]""", "express_route"),
    # Next.js API routes
    (r"""['"`](/_next/data/[^'"`\s]+|/api/[a-zA-Z0-9/_\-\[\]]{2,})['"`]""", "nextjs_api"),
    # Apollo GraphQL URI
    (r"""uri\s*:\s*['"`]([^'"`]{5,})['"`]""",                        "graphql_uri"),
    # WebSocket endpoints
    (r"""new\s+WebSocket\s*\(\s*['"`](wss?://[^'"`]+)['"`]""",      "websocket"),
    (r"""io\.connect\s*\(\s*['"`]([^'"`]+)['"`]""",                  "socketio"),
    # GraphQL marker (no capture — sets flag)
    (r"""(?i)(graphql|gql`|useQuery|useMutation|__schema)""",         "graphql"),
]

# ── Secret patterns ───────────────────────────────────────────────────────────

JS_SECRET_PATTERNS: list[dict] = [
    # ── Cloud Provider Keys ────────────────────────────────────────────────────
    {"name": "AWS Access Key",              "pattern": r"(AKIA|AIPA|ASIA|AROA|ANPA|ANVA|APKA)[A-Z0-9]{16}",                   "severity": "critical", "check_entropy": False},
    {"name": "AWS Secret Key",              "pattern": r'(?i)aws[_\-\s]*secret[_\-\s]*(?:access[_\-\s]*)?key[^=\n]{0,10}=\s*[\'"]?([A-Za-z0-9/+]{40})', "severity": "critical", "check_entropy": True},
    {"name": "GCP API Key",                 "pattern": r"AIza[0-9A-Za-z\-_]{35}",                                             "severity": "high",     "check_entropy": False},
    {"name": "GCP Service Account Key",     "pattern": r'"type"\s*:\s*"service_account"',                                     "severity": "critical", "check_entropy": False},
    {"name": "Firebase Server Key",         "pattern": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",                           "severity": "critical", "check_entropy": False},
    {"name": "Firebase DB URL",             "pattern": r"https://[a-z0-9-]+\.firebaseio\.com",                                "severity": "high",     "check_entropy": False},
    {"name": "Firebase Config",             "pattern": r"firebaseConfig\s*=\s*\{[^}]{20,}apiKey[^}]+\}",                     "severity": "high",     "check_entropy": False},
    # ── Payment ────────────────────────────────────────────────────────────────
    {"name": "Stripe Live Secret Key",      "pattern": r"sk_live_[0-9a-zA-Z]{24,}",                                          "severity": "critical", "check_entropy": False},
    {"name": "Stripe Restricted Key",       "pattern": r"rk_live_[0-9a-zA-Z]{24,}",                                          "severity": "critical", "check_entropy": False},
    {"name": "Stripe Test Key",             "pattern": r"sk_test_[0-9a-zA-Z]{24,}",                                          "severity": "medium",   "check_entropy": False},
    {"name": "Square Access Token",         "pattern": r"sq0atp-[0-9A-Za-z\-_]{22}",                                         "severity": "critical", "check_entropy": False},
    {"name": "Square OAuth Secret",         "pattern": r"sq0csp-[0-9A-Za-z\-_]{43}",                                         "severity": "critical", "check_entropy": False},
    # ── Communication Platforms ────────────────────────────────────────────────
    {"name": "Slack Bot Token",             "pattern": r"xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}",                          "severity": "high",     "check_entropy": False},
    {"name": "Slack User Token",            "pattern": r"xoxp-[0-9]{11}-[0-9]{11}-[0-9]{11}-[a-f0-9]{32}",                   "severity": "high",     "check_entropy": False},
    {"name": "Slack Legacy Token",          "pattern": r"xox[baprs]-[0-9a-zA-Z\-]{10,}",                                     "severity": "high",     "check_entropy": False},
    {"name": "Slack Webhook",               "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[a-zA-Z0-9]{24}", "severity": "high", "check_entropy": False},
    {"name": "Discord Bot Token",           "pattern": r"[MN][a-zA-Z0-9]{23}\.[a-zA-Z0-9\-_]{6}\.[a-zA-Z0-9\-_]{27}",       "severity": "high",     "check_entropy": False},
    {"name": "Discord Webhook",             "pattern": r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9\-_]{68}", "severity": "high", "check_entropy": False},
    {"name": "Twilio Account SID",          "pattern": r"AC[a-z0-9]{32}",                                                    "severity": "high",     "check_entropy": False},
    {"name": "Twilio Auth Token",           "pattern": r'(?i)twilio[^0-9a-f]{0,30}([0-9a-f]{32})',                           "severity": "critical", "check_entropy": False},
    {"name": "SendGrid API Key",            "pattern": r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}",                       "severity": "critical", "check_entropy": False},
    {"name": "Mailgun API Key",             "pattern": r"key-[0-9a-zA-Z]{32}",                                               "severity": "high",     "check_entropy": False},
    {"name": "Mailchimp API Key",           "pattern": r"[0-9a-f]{32}-us[0-9]{1,2}",                                         "severity": "high",     "check_entropy": False},
    # ── Source Control ─────────────────────────────────────────────────────────
    {"name": "GitHub Classic PAT",          "pattern": r"ghp_[A-Za-z0-9]{36}",                                               "severity": "critical", "check_entropy": False},
    {"name": "GitHub Fine-grained PAT",     "pattern": r"github_pat_[A-Za-z0-9_]{82}",                                       "severity": "critical", "check_entropy": False},
    {"name": "GitHub OAuth Token",          "pattern": r"gho_[A-Za-z0-9]{36}",                                               "severity": "critical", "check_entropy": False},
    {"name": "GitHub App Token",            "pattern": r"ghs_[A-Za-z0-9]{36}",                                               "severity": "critical", "check_entropy": False},
    {"name": "npm Token",                   "pattern": r"npm_[A-Za-z0-9]{36}",                                               "severity": "high",     "check_entropy": False},
    # ── Monitoring / DevOps ────────────────────────────────────────────────────
    {"name": "Sentry DSN",                  "pattern": r"https://[0-9a-f]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+",         "severity": "high",     "check_entropy": False},
    {"name": "Sentry DSN (legacy)",         "pattern": r"https://[0-9a-f]{32}:[0-9a-f]{32}@sentry\.io/[0-9]+",              "severity": "critical", "check_entropy": False},
    {"name": "Datadog API Key",             "pattern": r'(?i)datadog[^0-9a-z]{0,20}([a-zA-Z0-9]{32})',                       "severity": "high",     "check_entropy": True},
    {"name": "PagerDuty API Key",           "pattern": r'(?i)pagerduty[^0-9a-z]{0,20}([a-zA-Z0-9+/]{20})',                  "severity": "high",     "check_entropy": True},
    # ── Geo / Map ──────────────────────────────────────────────────────────────
    {"name": "Mapbox Public Token",         "pattern": r"pk\.[a-zA-Z0-9\-_]{60,}",                                           "severity": "medium",   "check_entropy": False},
    {"name": "Mapbox Secret Token",         "pattern": r"sk\.[a-zA-Z0-9\-_]{60,}",                                           "severity": "critical", "check_entropy": False},
    {"name": "Cloudinary URL",              "pattern": r"cloudinary://[0-9]+:[A-Za-z0-9_\-]+@[a-z]+",                        "severity": "critical", "check_entropy": False},
    # ── E-commerce ─────────────────────────────────────────────────────────────
    {"name": "Shopify Access Token",        "pattern": r"shpat_[a-fA-F0-9]{32}",                                             "severity": "critical", "check_entropy": False},
    {"name": "Shopify Private App",         "pattern": r"shppa_[a-fA-F0-9]{32}",                                             "severity": "critical", "check_entropy": False},
    # ── Auth ────────────────────────────────────────────────────────────────────
    {"name": "JWT Token",                   "pattern": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",   "severity": "high",     "check_entropy": False},
    {"name": "Bearer Token",                "pattern": r"(?i)bearer\s+([a-zA-Z0-9\-._~+/]{20,})",                            "severity": "high",     "check_entropy": True},
    {"name": "Okta API Token",              "pattern": r"00[a-zA-Z0-9\-_]{40}",                                              "severity": "high",     "check_entropy": False},
    # ── Credentials ────────────────────────────────────────────────────────────
    {"name": "Private Key",                 "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",            "severity": "critical", "check_entropy": False},
    {"name": "Hardcoded Password",          "pattern": r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})["\']',       "severity": "high",     "check_entropy": True},
    {"name": "Generic API Key",             "pattern": r'(?i)api[_-]?key\s*[=:]\s*["\']([a-zA-Z0-9_\-]{16,})["\']',         "severity": "high",     "check_entropy": True},
    {"name": "Generic Secret",             "pattern": r'(?i)(?:secret|auth_?token|access_?token)\s*[=:]\s*["\']([a-zA-Z0-9_\-\.+/=]{16,})["\']', "severity": "high", "check_entropy": True},
    # ── Databases ──────────────────────────────────────────────────────────────
    {"name": "MongoDB URI",                 "pattern": r"mongodb(?:\+srv)?://[^\s'\"<]{10,}",                                 "severity": "critical", "check_entropy": False},
    {"name": "DB Connection String",        "pattern": r"(?i)(?:postgres|mysql|mssql|jdbc)://[^:]+:[^@]+@[^\s'\"<]+",        "severity": "critical", "check_entropy": False},
    # ── Internal / Info Disclosure ─────────────────────────────────────────────
    {"name": "Internal IP Address",         "pattern": r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})", "severity": "medium", "check_entropy": False},
    {"name": "Internal URL",               "pattern": r"https?://(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|localhost|127\.0\.0\.1)[/\w]*", "severity": "medium", "check_entropy": False},
    {"name": "TODO with Credentials",      "pattern": r"(?i)//[^\n]*(?:TODO|FIXME|HACK)[^\n]{0,50}(?:password|secret|token|key)",  "severity": "medium", "check_entropy": False},
    {"name": "Commented Credentials",      "pattern": r"(?i)//[^\n]*(?:password|passwd|secret|token|api_?key)\s*[=:][^\n]{4,}",     "severity": "medium", "check_entropy": False},
]

# ── Environment variable leak patterns ────────────────────────────────────────

ENV_LEAK_PATTERNS: list[dict] = [
    {"name": "React Env Var Leak",    "pattern": r"REACT_APP_[A-Z0-9_]+\s*[:=]\s*['\"][^'\"]{4,}['\"]",     "severity": "medium"},
    {"name": "Next.js Env Var Leak",  "pattern": r"NEXT_PUBLIC_[A-Z0-9_]+\s*[:=]\s*['\"][^'\"]{4,}['\"]",   "severity": "medium"},
    {"name": "Vite Env Var Leak",     "pattern": r"VITE_[A-Z0-9_]+\s*[:=]\s*['\"][^'\"]{4,}['\"]",          "severity": "medium"},
    {"name": "process.env Leak",      "pattern": r"process\.env\.([A-Z][A-Z0-9_]{3,})\b",                    "severity": "low"},
    {"name": "process.env Spread",    "pattern": r"\.\.\.process\.env\b",                                     "severity": "high"},
    {"name": "Internal Hostname",     "pattern": r"(?i)(?:staging|dev|internal|local|test|qa)\.[a-z0-9\-]+\.[a-z]{2,}", "severity": "low"},
    {"name": "Debug Mode Enabled",    "pattern": r"(?i)(?:debug|verbose|logging)\s*[=:]\s*true",              "severity": "low"},
    {"name": "Dev Server URL",        "pattern": r"(?i)['\"]https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0):\d{4,5}['\"]", "severity": "low"},
    {"name": "Absolute Path Leak",    "pattern": r"""(?:webpack:///|/home/\w+/|/Users/\w+/)[^\s'"` \n]{5,}""", "severity": "low"},
    {"name": "Console.log of Secret", "pattern": r"console\.(?:log|warn|error|debug)\s*\([^)]*(?:token|password|secret|key|auth)[^)]*\)", "severity": "medium"},
]

# ── DOM XSS sinks ─────────────────────────────────────────────────────────────

DOM_XSS_SINKS: list[dict] = [
    # Core HTML sinks
    {"name": "innerHTML Assignment",         "pattern": r"\.innerHTML\s*[+]?=(?!=)",           "severity": "high"},
    {"name": "outerHTML Assignment",         "pattern": r"\.outerHTML\s*[+]?=(?!=)",           "severity": "high"},
    {"name": "insertAdjacentHTML",           "pattern": r"\.insertAdjacentHTML\s*\(",           "severity": "high"},
    {"name": "document.write",              "pattern": r"document\.write(?:ln)?\s*\(",         "severity": "high"},
    # JS execution sinks
    {"name": "eval()",                      "pattern": r"\beval\s*\(",                         "severity": "critical"},
    {"name": "Function() constructor",      "pattern": r"\bnew\s+Function\s*\(",               "severity": "critical"},
    {"name": "setTimeout with string",      "pattern": r"setTimeout\s*\(\s*['\"`]",            "severity": "high"},
    {"name": "setInterval with string",     "pattern": r"setInterval\s*\(\s*['\"`]",           "severity": "high"},
    # jQuery sinks
    {"name": "jQuery .html()",              "pattern": r"(?:\$|jQuery)\s*\([^)]*\)\s*\.html\s*\(", "severity": "high"},
    {"name": "jQuery .append()",            "pattern": r"(?:\$|jQuery)\s*\([^)]*\)\s*\.(?:append|prepend|after|before)\s*\(", "severity": "medium"},
    {"name": "jQuery.parseHTML()",          "pattern": r"(?:\$|jQuery)\.parseHTML\s*\(",       "severity": "high"},
    # Navigation sinks
    {"name": "location.href assignment",    "pattern": r"(?:location|window\.location)\.href\s*=", "severity": "high"},
    {"name": "location.replace()",         "pattern": r"location\.replace\s*\(",              "severity": "high"},
    {"name": "location.assign()",          "pattern": r"location\.assign\s*\(",               "severity": "high"},
    {"name": "document.location assign",   "pattern": r"document\.location\s*=",              "severity": "high"},
    # React / Angular / Vue framework-specific
    {"name": "React dangerouslySetInnerHTML", "pattern": r"dangerouslySetInnerHTML\s*=",       "severity": "high"},
    {"name": "Angular innerHTML binding",   "pattern": r"\[innerHTML\]\s*=",                   "severity": "high"},
    {"name": "Angular bypassSecurity",      "pattern": r"bypassSecurityTrust(?:Html|Script|Style|ResourceUrl|Url)\s*\(", "severity": "critical"},
    {"name": "Vue v-html directive",        "pattern": r"v-html\s*=",                          "severity": "high"},
    {"name": "Angular $sce.trustAsHtml",    "pattern": r"\$sce\.trustAsHtml\s*\(",             "severity": "high"},
    # Script injection
    {"name": "Dynamic script element",      "pattern": r"createElement\s*\(\s*['\"`]script['\"`]\s*\)", "severity": "critical"},
    # Only flag .src = when the value is likely dynamic (not a string literal)
    {"name": ".src assignment",             "pattern": r"\.src\s*=\s*(?!['\"`\s])(?!null\b)(?!void\b)(?!false\b)(?!true\b)(?!\d)",  "severity": "medium"},
]

# ── DOM XSS sources ───────────────────────────────────────────────────────────

DOM_XSS_SOURCES: list[dict] = [
    {"name": "location.search (URL param source)",  "pattern": r"location\.search\b",              "severity": "info"},
    {"name": "location.hash (URL hash source)",     "pattern": r"location\.hash\b",                "severity": "info"},
    {"name": "location.href (URL source)",          "pattern": r"location\.href\b",                "severity": "info"},
    {"name": "document.referrer (referrer source)", "pattern": r"document\.referrer\b",            "severity": "info"},
    {"name": "window.name (window.name source)",    "pattern": r"\bwindow\.name\b",                "severity": "info"},
    {"name": "document.cookie (cookie source)",     "pattern": r"\bdocument\.cookie\b",            "severity": "info"},
    {"name": "localStorage read",                   "pattern": r"localStorage\.getItem\s*\(",      "severity": "info"},
    {"name": "sessionStorage read",                 "pattern": r"sessionStorage\.getItem\s*\(",    "severity": "info"},
    {"name": "URLSearchParams",                     "pattern": r"\bURLSearchParams\b",             "severity": "info"},
    {"name": "localStorage of sensitive token",     "pattern": r"localStorage\.setItem\s*\(\s*['\"][^'\"]*(?:token|jwt|key|auth|secret)['\"]", "severity": "medium"},
]

# ── Prototype pollution patterns ──────────────────────────────────────────────

PROTOTYPE_POLLUTION_PATTERNS: list[dict] = [
    {"name": "Direct __proto__ Assignment",   "pattern": r"\[(?:\"|\')__proto__(?:\"|\')\]",      "severity": "high"},
    {"name": "constructor.prototype Access",  "pattern": r"\.constructor\.prototype\b",           "severity": "high"},
    {"name": "Unsafe Deep Merge",             "pattern": r"function\s+\w*[Mm]erge\w*\s*\([^)]*\)\s*\{[^}]{0,300}for\s*\([^)]*\bin\b", "severity": "medium"},
    {"name": "Unsafe Object.assign",         "pattern": r"Object\.assign\s*\([^)]*,\s*(?:req\.|request\.|params\.|query\.|body\.)", "severity": "medium"},
    {"name": "Lodash defaultsDeep",          "pattern": r"_\.(?:defaultsDeep|merge)\s*\(",        "severity": "medium"},
    {"name": "JSON.parse to __proto__",      "pattern": r'JSON\.parse[^;]{0,100}\[(?:"|\')?(?:__proto__|constructor|prototype)',  "severity": "high"},
    {"name": "Bracket Access with Variable", "pattern": r"\w+\[(\w+)\]\[(\w+)\]\s*=[^=]",        "severity": "low"},
]

# ── PostMessage security patterns ─────────────────────────────────────────────

POSTMESSAGE_PATTERNS: list[dict] = [
    {"name": "postMessage Wildcard Origin",     "pattern": r"\.postMessage\s*\([^,]+,\s*['\"]?\*['\"]?\s*\)",    "severity": "high"},
    {"name": "postMessage Listener (verify origin)", "pattern": r"addEventListener\s*\(\s*['\"`]message['\"`]",  "severity": "info"},
    {"name": "iframe postMessage Wildcard",     "pattern": r"\.contentWindow\.postMessage\s*\([^)]*\*[^)]*\)",   "severity": "high"},
    {"name": "Dangerous postMessage Handler",   "pattern": r"onmessage\s*=\s*function[^}]{0,200}(?:innerHTML|eval|document\.write)", "severity": "critical"},
]

# ── WebSocket security patterns ───────────────────────────────────────────────

WEBSOCKET_PATTERNS: list[dict] = [
    {"name": "WebSocket without Auth Param",    "pattern": r"new\s+WebSocket\s*\(\s*['\"`](wss?://[^?'\"` ]{5,})['\"`]\s*\)", "severity": "medium"},
    {"name": "WebSocket Message to Sink",       "pattern": r"\.onmessage\s*=[^}]{0,200}(?:innerHTML|eval|document\.write)", "severity": "critical"},
    {"name": "Socket.io Connection",            "pattern": r"io\.connect\s*\(\s*['\"`]([^'\"` ]+)['\"`]",                   "severity": "info"},
]

# ── Service worker patterns ───────────────────────────────────────────────────

SERVICE_WORKER_PATTERNS: list[dict] = [
    {"name": "Service Worker Registration",     "pattern": r"navigator\.serviceWorker\.register\s*\(\s*['\"`]([^'\"` ]+)['\"`]", "severity": "info"},
    {"name": "SW Fetch Interception",           "pattern": r"self\.addEventListener\s*\(\s*['\"`]fetch['\"`]",                   "severity": "info"},
    {"name": "SW importScripts from CDN",       "pattern": r"importScripts\s*\(\s*['\"`](https?://[^'\"` ]+)['\"`]",            "severity": "medium"},
    {"name": "SW Wildcard Scope",               "pattern": r"serviceWorker\.register\s*\([^)]*\{\s*scope\s*:\s*['\"`]/['\"`]",  "severity": "medium"},
    {"name": "SW Dangerous Message Handler",    "pattern": r"self\.addEventListener\s*\(\s*['\"`]message['\"`][^}]{0,300}(?:fetch|eval|importScripts)", "severity": "high"},
]

GRAPHQL_INTROSPECTION_QUERY = json.dumps({
    "query": "{ __schema { types { name } } }"
})

GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphiql", "/query", "/gql"]

MAX_JS_BYTES = 3 * 1024 * 1024  # 3 MB

# ── Known 3rd-party analytics / CDN domains ────────────────────────────────────
# Findings from these files are heavily filtered — they legitimately read cookies,
# URLs, and use dynamic script elements as part of their normal operation.
KNOWN_ANALYTICS_DOMAINS: frozenset[str] = frozenset([
    "google-analytics.com", "googletagmanager.com", "googlesyndication.com",
    "google.com/recaptcha", "recaptcha.net",
    "adobe-dtm.com", "adobedtm.com", "omtrdc.net", "demdex.net",
    "2o7.net", "sc.omtrdc.net",
    "amplitude.com", "hotjar.com", "fullstory.com", "mixpanel.com",
    "segment.com", "heap.io", "mouseflow.com", "crazyegg.com",
    "optimizely.com", "quantummetric.com", "contentsquare.com",
    "datadome.co", "cloudflare.com", "cloudflareinsights.com",
    "newrelic.com", "nr-data.net", "dynatrace.com", "datadog.com",
    "cookielaw.org", "onetrust.com", "evidon.com", "trustarc.com",
    "facebook.net", "fbcdn.net", "connect.facebook.net",
    "twitter.com", "ads-twitter.com", "t.co",
    "linkedin.com", "licdn.com",
    "pinterest.com", "pinimg.com",
    "doubleclick.net", "adsystem.com", "adnxs.com",
    "moatads.com", "scorecardresearch.com", "comscore.com",
    "chartbeat.com", "parsely.com",
    "cdn.amplitude.com", "cdn.segment.com",
])

# Max findings reported per pattern per file (prevents flooding from minified files)
_MAX_PER_PATTERN_PER_FILE = 5
# For info-level sources, even tighter cap
_MAX_SOURCE_PER_FILE = 3


def _is_known_3rd_party(url: str) -> bool:
    """Returns True if URL belongs to a known analytics/advertising CDN domain."""
    try:
        host = urlparse(url).netloc.lower()
        return any(domain in host for domain in KNOWN_ANALYTICS_DOMAINS)
    except Exception:
        return False

COMMON_JS_PATHS = [
    "/static/js/main.chunk.js",
    "/static/js/bundle.js",
    "/static/js/vendors~main.chunk.js",
    "/assets/index.js",
    "/app.js",
    "/main.js",
    "/bundle.js",
    "/manifest.json",
    "/asset-manifest.json",
    "/_next/static/chunks/pages/_app.js",
    "/wp-includes/js/wp-embed.min.js",
]

# Values that indicate false positives (example/placeholder values)
_PLACEHOLDER_PATTERNS = re.compile(
    r'(?i)(example|placeholder|your[-_]?|xxx|test|dummy|fake|sample|demo|<|>|\{\{)',
    re.IGNORECASE,
)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _truncate_match(m: str, keep: int = 8) -> str:
    return m[:keep] + "..." if len(m) > keep else m


def _base_origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _is_same_origin(url: str, origin: str, include_subdomains: bool) -> bool:
    p = urlparse(url)
    o = urlparse(origin)
    if not p.netloc:
        return True
    if p.netloc == o.netloc:
        return True
    if include_subdomains and p.netloc.endswith("." + o.netloc):
        return True
    return False


def _resolve_js_url(src: str, base: str) -> str | None:
    if not src or src.startswith("data:"):
        return None
    if src.startswith("//"):
        src = urlparse(base).scheme + ":" + src
    if src.startswith("http"):
        return src
    return urljoin(base, src)


def _line_number(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1


def _get_context(content: str, pos: int, lines: int = 2) -> str:
    """Return ±`lines` lines of surrounding code for a match position."""
    all_lines = content.splitlines()
    line_idx = content[:pos].count("\n")
    start = max(0, line_idx - lines)
    end = min(len(all_lines), line_idx + lines + 1)
    return "\n".join(all_lines[start:end]).strip()[:300]


def _is_likely_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER_PATTERNS.search(value))


# ──────────────────────────────────────────────────────────────────────────────
# Core analysis function
# ──────────────────────────────────────────────────────────────────────────────

def _analyze_js_content(
    content: str,
    file_url: str,
    beautify: bool = True,
) -> tuple[list[dict], list[dict], bool]:
    """
    Returns (endpoints, all_findings, has_graphql).
    all_findings contains: secrets, dom_xss, dom_sources, prototype_pollution,
                           postmessage, websocket, service_worker, env_leaks
    """
    # Beautify to improve regex accuracy on minified code
    processed = _beautify(content) if beautify and len(content) < MAX_JS_BYTES else content

    endpoints: list[dict] = []
    findings: list[dict] = []
    has_graphql = False
    seen_endpoints: set[str] = set()
    seen_findings: set[str] = set()  # deduplicate by (name, line)
    pattern_counts: dict[str, int] = {}  # pattern_name -> occurrences this file
    is_3rd_party = _is_known_3rd_party(file_url)

    def _add_finding(f: dict) -> None:
        fname = f.get("name", "")
        ftype = f.get("type", "")

        # Skip info-level dom_source findings entirely for known 3rd-party scripts
        # (analytics/CDN scripts legitimately read cookies and URLs)
        if is_3rd_party and ftype == "dom_source":
            return

        # Cap per pattern per file to prevent flooding from minified code
        cap = _MAX_SOURCE_PER_FILE if ftype == "dom_source" else _MAX_PER_PATTERN_PER_FILE
        count = pattern_counts.get(fname, 0) + 1
        pattern_counts[fname] = count
        if count > cap:
            return  # suppress excess occurrences

        key = f"{fname}:{f['line_number']}:{f.get('match', '')[:20]}"
        if key not in seen_findings:
            seen_findings.add(key)
            # Annotate the last allowed finding with suppression note
            if count == cap:
                f = dict(f)
                f["suppressed_note"] = f"Showing {cap} of multiple occurrences — remaining suppressed to reduce noise."
            findings.append(f)

    # ── Endpoints ──────────────────────────────────────────────────────────────
    for pattern, kind in ENDPOINT_PATTERNS:
        for m in re.finditer(pattern, processed, re.IGNORECASE if kind == "graphql" else 0):
            if kind == "graphql":
                has_graphql = True
                continue
            raw = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
            raw = raw.strip()
            # Filter out noise
            if len(raw) < 3:
                continue
            if any(raw.endswith(ext) for ext in (".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".css", ".ico")):
                continue
            if raw in seen_endpoints:
                continue
            seen_endpoints.add(raw)
            endpoints.append({
                "url": raw,
                "kind": kind,
                "file": file_url,
                "line": _line_number(processed, m.start()),
            })

    # GraphQL keyword check
    if re.search(r'(?i)(graphql|gql`|useQuery|useMutation|__schema)', processed):
        has_graphql = True

    # ── Secrets ────────────────────────────────────────────────────────────────
    for spec in JS_SECRET_PATTERNS:
        for m in re.finditer(spec["pattern"], processed, re.IGNORECASE if "(?i)" not in spec["pattern"] else 0):
            raw = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
            if _is_likely_placeholder(raw):
                continue
            if spec.get("check_entropy") and not _is_high_entropy(raw):
                continue
            line = _line_number(processed, m.start())
            _add_finding({
                "type": "secret",
                "name": spec["name"],
                "severity": spec["severity"],
                "file_url": file_url,
                "match": _truncate_match(raw),
                "line_number": line,
                "context": _get_context(processed, m.start()),
                "recommendation": f"Remove hardcoded {spec['name']} from JavaScript. Use server-side environment variables or a secrets manager.",
            })

    # ── Environment variable leaks ─────────────────────────────────────────────
    for spec in ENV_LEAK_PATTERNS:
        for m in re.finditer(spec["pattern"], processed, re.IGNORECASE):
            raw = m.group(0)
            line = _line_number(processed, m.start())
            _add_finding({
                "type": "env_leak",
                "name": spec["name"],
                "severity": spec["severity"],
                "file_url": file_url,
                "match": _truncate_match(raw, 60),
                "line_number": line,
                "context": _get_context(processed, m.start()),
                "recommendation": "Environment variables exposed in client-side JS are readable by anyone. Use server-side APIs to proxy sensitive config.",
            })

    # ── DOM XSS sinks ──────────────────────────────────────────────────────────
    for sink in DOM_XSS_SINKS:
        for m in re.finditer(sink["pattern"], processed, re.IGNORECASE):
            line = _line_number(processed, m.start())
            _add_finding({
                "type": "dom_xss",
                "name": sink["name"],
                "severity": sink["severity"],
                "file_url": file_url,
                "match": _truncate_match(m.group(0), 40),
                "line_number": line,
                "context": _get_context(processed, m.start()),
                "recommendation": f"Avoid using {sink['name']} with untrusted input. Use DOMPurify or safe DOM APIs.",
            })

    # ── DOM XSS sources ────────────────────────────────────────────────────────
    for src in DOM_XSS_SOURCES:
        for m in re.finditer(src["pattern"], processed, re.IGNORECASE):
            line = _line_number(processed, m.start())
            _add_finding({
                "type": "dom_source",
                "name": src["name"],
                "severity": src["severity"],
                "file_url": file_url,
                "match": _truncate_match(m.group(0), 40),
                "line_number": line,
                "context": _get_context(processed, m.start()),
                "recommendation": "Trace this user-controlled source to ensure it does not flow into a dangerous sink without sanitization.",
            })

    # ── Prototype pollution ────────────────────────────────────────────────────
    for pp in PROTOTYPE_POLLUTION_PATTERNS:
        for m in re.finditer(pp["pattern"], processed, re.IGNORECASE):
            line = _line_number(processed, m.start())
            _add_finding({
                "type": "prototype_pollution",
                "name": pp["name"],
                "severity": pp["severity"],
                "file_url": file_url,
                "match": _truncate_match(m.group(0), 40),
                "line_number": line,
                "context": _get_context(processed, m.start()),
                "recommendation": "Sanitize object keys against '__proto__', 'constructor', and 'prototype' before performing deep merges.",
            })

    # ── PostMessage security ───────────────────────────────────────────────────
    for pm in POSTMESSAGE_PATTERNS:
        for m in re.finditer(pm["pattern"], processed, re.IGNORECASE | re.DOTALL):
            line = _line_number(processed, m.start())
            _add_finding({
                "type": "postmessage",
                "name": pm["name"],
                "severity": pm["severity"],
                "file_url": file_url,
                "match": _truncate_match(m.group(0), 50),
                "line_number": line,
                "context": _get_context(processed, m.start()),
                "recommendation": "Always validate event.origin in postMessage listeners and avoid sending messages to wildcard origins.",
            })

    # ── WebSocket security ─────────────────────────────────────────────────────
    for ws in WEBSOCKET_PATTERNS:
        for m in re.finditer(ws["pattern"], processed, re.IGNORECASE | re.DOTALL):
            line = _line_number(processed, m.start())
            _add_finding({
                "type": "websocket",
                "name": ws["name"],
                "severity": ws["severity"],
                "file_url": file_url,
                "match": _truncate_match(m.group(0), 60),
                "line_number": line,
                "context": _get_context(processed, m.start()),
                "recommendation": "Ensure WebSocket connections include authentication tokens and validate the Origin header server-side.",
            })

    # ── Service worker ─────────────────────────────────────────────────────────
    for sw in SERVICE_WORKER_PATTERNS:
        for m in re.finditer(sw["pattern"], processed, re.IGNORECASE | re.DOTALL):
            line = _line_number(processed, m.start())
            _add_finding({
                "type": "service_worker",
                "name": sw["name"],
                "severity": sw["severity"],
                "file_url": file_url,
                "match": _truncate_match(m.group(0), 60),
                "line_number": line,
                "context": _get_context(processed, m.start()),
                "recommendation": "Review service worker scope and ensure it does not intercept sensitive requests or execute untrusted scripts.",
            })

    return endpoints, findings, has_graphql


# ──────────────────────────────────────────────────────────────────────────────
# Main scan generator
# ──────────────────────────────────────────────────────────────────────────────

async def _run_js_scan(
    request: JSScanRequest,
    scan_id: str,
    org_id: str,
) -> AsyncGenerator[str, None]:
    started_at = datetime.now(timezone.utc).isoformat()
    loop = asyncio.get_running_loop()
    start_ts = loop.time()
    target = request.target.strip().rstrip("/")
    # Normalize: prepend https:// if no scheme given (e.g. "example.com" → "https://example.com")
    if target and not target.startswith(("http://", "https://")):
        target = "https://" + target
    origin = _base_origin(target)

    all_findings: list[dict] = []
    all_endpoints: list[dict] = []
    _global_endpoint_seen: set[str] = set()  # cross-file deduplication
    js_files_scanned = 0
    secrets_count = 0
    dom_xss_count = 0
    source_map_count = 0
    graphql_count = 0
    proto_pollution_count = 0
    env_leak_count = 0
    graphql_detected = False

    def _count_finding(f: dict) -> None:
        nonlocal secrets_count, dom_xss_count, proto_pollution_count, env_leak_count
        t = f.get("type", "")
        if t == "secret":
            secrets_count += 1
        elif t in ("dom_xss", "dom_source"):
            dom_xss_count += 1
        elif t == "prototype_pollution":
            proto_pollution_count += 1
        elif t == "env_leak":
            env_leak_count += 1

    yield _sse("start", {"scan_id": scan_id, "target": target})
    yield _sse("progress", {"phase": "discovery", "message": "Fetching target page..."})

    discovered_js: list[str] = []
    seen_urls: set[str] = set()

    async def _safe_get(client: httpx.AsyncClient, url: str, timeout: float = 10.0) -> httpx.Response | None:
        try:
            return await client.get(url, follow_redirects=True, timeout=timeout)
        except Exception:
            return None

    async with httpx.AsyncClient(
        headers={"User-Agent": "Mozilla/5.0 (compatible; AttackTrace/2.0; +https://attacktrace.io)"},
        follow_redirects=True,
        timeout=10.0,
    ) as client:

        main_resp = await _safe_get(client, target)
        inline_scripts: list[str] = []

        if main_resp and main_resp.status_code == 200:
            html = main_resp.text

            # <script src="...">
            for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
                url = _resolve_js_url(m.group(1), target)
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    discovered_js.append(url)

            # <link rel="preload" as="script">
            for m in re.finditer(r'<link[^>]+rel=["\']preload["\'][^>]+as=["\']script["\'][^>]+href=["\']([^"\']+)["\']', html, re.IGNORECASE):
                url = _resolve_js_url(m.group(1), target)
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    discovered_js.append(url)
            for m in re.finditer(r'<link[^>]+href=["\']([^"\']+)["\'][^>]+as=["\']script["\']', html, re.IGNORECASE):
                url = _resolve_js_url(m.group(1), target)
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    discovered_js.append(url)

            # Inline <script> blocks
            for m in re.finditer(r'<script(?:[^>]*)>([\s\S]*?)</script>', html, re.IGNORECASE):
                block = m.group(1).strip()
                if block and len(block) > 20:
                    inline_scripts.append(block)

            # Service worker registration from HTML
            for m in re.finditer(r"navigator\.serviceWorker\.register\s*\(\s*['\"`]([^'\"` ]+)['\"`]", html):
                sw_url = _resolve_js_url(m.group(1), target)
                if sw_url and sw_url not in seen_urls:
                    seen_urls.add(sw_url)
                    discovered_js.append(sw_url)

        # Probe common JS paths
        async def _probe_path(path: str) -> None:
            url = origin + path
            if url in seen_urls:
                return
            r = await _safe_get(client, url)
            if r is None:
                return
            ct = r.headers.get("content-type", "")
            if r.status_code == 200:
                if "javascript" in ct or path.endswith(".js"):
                    seen_urls.add(url)
                    discovered_js.append(url)
                elif "json" in ct and path.endswith(".json"):
                    try:
                        manifest = r.json()
                        for key, val in manifest.items():
                            if isinstance(val, str) and val.endswith(".js"):
                                js_url = _resolve_js_url(val, target)
                                if js_url and js_url not in seen_urls:
                                    seen_urls.add(js_url)
                                    discovered_js.append(js_url)
                        for val in manifest.get("files", {}).values():
                            if isinstance(val, str) and val.endswith(".js"):
                                js_url = _resolve_js_url(val, target)
                                if js_url and js_url not in seen_urls:
                                    seen_urls.add(js_url)
                                    discovered_js.append(js_url)
                    except Exception:
                        pass

        await asyncio.gather(*[_probe_path(p) for p in COMMON_JS_PATHS])

        discovered_js = discovered_js[: request.max_files]

        yield _sse("progress", {
            "phase": "discovery",
            "message": f"Found {len(discovered_js)} JS files + {len(inline_scripts)} inline scripts",
            "urls": discovered_js[:50],
        })

        # ── Inline scripts ────────────────────────────────────────────────────

        for idx, block in enumerate(inline_scripts):
            label = f"inline-script-{idx + 1}"
            eps, fds, gql = _analyze_js_content(block, label, beautify=False)

            for ep in eps:
                if ep["url"] not in _global_endpoint_seen:
                    _global_endpoint_seen.add(ep["url"])
                    yield _sse("endpoint", {"url": ep["url"], "file": label, "line": ep["line"]})
                    all_endpoints.append(ep)

            for f in fds:
                yield _sse("finding", f)
                all_findings.append(f)
                _count_finding(f)

            if gql:
                graphql_detected = True

        # ── JS files (concurrent) ─────────────────────────────────────────────

        total = len(discovered_js)
        semaphore = asyncio.Semaphore(6)
        queue: asyncio.Queue[str | None] = asyncio.Queue()

        async def _fetch_and_enqueue(js_url: str, file_index: int) -> None:
            nonlocal js_files_scanned, graphql_detected, source_map_count
            async with semaphore:
                try:
                    try:
                        resp = await client.get(js_url, follow_redirects=True, timeout=20.0)
                    except Exception as exc:
                        await queue.put(_sse("progress", {
                            "phase": "analysis",
                            "message": f"[{file_index}/{total}] Failed: {js_url[:60]} — {type(exc).__name__}",
                        }))
                        return

                    ct = resp.headers.get("content-type", "")
                    if resp.status_code != 200 or any(x in ct for x in ("image", "font", "audio", "video")):
                        return

                    raw = resp.content
                    if len(raw) > MAX_JS_BYTES:
                        await queue.put(_sse("progress", {
                            "phase": "analysis",
                            "message": f"[{file_index}/{total}] Skipping (too large {len(raw)//1024} KB): {js_url[:60]}",
                        }))
                        return

                    try:
                        content = raw.decode("utf-8", errors="replace")
                    except Exception:
                        return

                    await queue.put(_sse("progress", {
                        "phase": "analysis",
                        "message": f"[{file_index}/{total}] Analyzing {js_url[:80]}",
                    }))

                    eps, fds, gql = await asyncio.get_running_loop().run_in_executor(
                        None, _analyze_js_content, content, js_url, True
                    )
                    js_files_scanned += 1

                    for ep in eps:
                        if ep["url"] not in _global_endpoint_seen:
                            _global_endpoint_seen.add(ep["url"])
                            await queue.put(_sse("endpoint", {"url": ep["url"], "file": js_url, "line": ep["line"]}))
                            all_endpoints.append(ep)

                    for f in fds:
                        await queue.put(_sse("finding", f))
                        all_findings.append(f)
                        _count_finding(f)

                    if gql:
                        graphql_detected = True

                    # Source map detection
                    if request.include_source_maps:
                        map_match = re.search(r"//[#@]\s*sourceMappingURL=(.+)$", content, re.MULTILINE)
                        if map_match:
                            map_ref = map_match.group(1).strip()
                            if not map_ref.startswith("data:"):
                                map_url = _resolve_js_url(map_ref, js_url)
                                if map_url:
                                    try:
                                        map_resp = await client.get(map_url, timeout=10.0)
                                        if map_resp.status_code == 200 and len(map_resp.content) > 100:
                                            finding = {
                                                "type": "source_map",
                                                "name": "JavaScript Source Map Exposed",
                                                "severity": "critical",
                                                "file_url": map_url,
                                                "match": map_url[:60] + "..." if len(map_url) > 60 else map_url,
                                                "line_number": _line_number(content, map_match.start()),
                                                "context": "",
                                                "recommendation": "Remove sourceMappingURL from production builds. Never deploy .map files publicly — they expose full original source.",
                                            }
                                            await queue.put(_sse("finding", finding))
                                            all_findings.append(finding)
                                            source_map_count += 1
                                    except Exception:
                                        pass
                finally:
                    # Always signal completion so the queue consumer can decrement
                    # its counter regardless of whether this file succeeded or was skipped.
                    await queue.put(None)

        bg_tasks = [
            asyncio.create_task(_fetch_and_enqueue(url, i + 1))
            for i, url in enumerate(discovered_js)
        ]

        remaining = len(bg_tasks)
        while remaining > 0:
            item = await queue.get()
            if item is None:
                remaining -= 1
            else:
                yield item

        # ── GraphQL introspection ─────────────────────────────────────────────

        if graphql_detected:
            yield _sse("progress", {"phase": "graphql", "message": "GraphQL detected — testing introspection..."})
            for gql_path in GRAPHQL_PATHS:
                gql_url = origin + gql_path
                try:
                    gql_resp = await client.post(
                        gql_url,
                        content=GRAPHQL_INTROSPECTION_QUERY,
                        headers={"Content-Type": "application/json"},
                        timeout=10.0,
                    )
                    if gql_resp.status_code == 200:
                        body = gql_resp.text
                        if "__schema" in body or '"types"' in body:
                            finding = {
                                "type": "graphql",
                                "name": "GraphQL Introspection Enabled",
                                "severity": "high",
                                "file_url": gql_url,
                                "match": gql_url,
                                "line_number": 0,
                                "context": "",
                                "recommendation": "Disable GraphQL introspection in production. It exposes your full API schema to attackers.",
                            }
                            yield _sse("finding", finding)
                            all_findings.append(finding)
                            graphql_count += 1
                            break
                except Exception:
                    continue

        # ── Complete ──────────────────────────────────────────────────────────

        duration = round(asyncio.get_running_loop().time() - start_ts, 2)
        completed_at = datetime.now(timezone.utc).isoformat()

        completion = {
            "scan_id": scan_id,
            "js_files_scanned": js_files_scanned,
            "endpoints_found": len(all_endpoints),
            "secrets_found": secrets_count,
            "dom_xss_sinks": dom_xss_count,
            "source_maps_exposed": source_map_count,
            "graphql_issues": graphql_count,
            "prototype_pollution": proto_pollution_count,
            "env_leaks": env_leak_count,
            "duration_seconds": duration,
        }
        yield _sse("complete", completion)

        record = {
            "id": scan_id,
            "target": target,
            "started_at": started_at,
            "completed_at": completed_at,
            "options": {
                "max_depth": request.max_depth,
                "max_files": request.max_files,
                "include_source_maps": request.include_source_maps,
                "include_subdomains": request.include_subdomains,
            },
            "findings": all_findings,
            "endpoints": all_endpoints,
            "summary": completion,
        }
        _save_scan_result(org_id, record)


async def _safe_js_scan(
    request: JSScanRequest,
    scan_id: str,
    org_id: str,
) -> AsyncGenerator[str, None]:
    """Wrapper that surfaces unhandled exceptions as SSE error events."""
    import traceback
    try:
        async for chunk in _run_js_scan(request, scan_id, org_id):
            yield chunk
    except Exception as exc:
        yield _sse("error", {
            "message": f"{type(exc).__name__}: {exc}",
            "trace": traceback.format_exc()[-600:],
        })


# ──────────────────────────────────────────────────────────────────────────────
# API Endpoints
# ──────────────────────────────────────────────────────────────────────────────

@router.post("/scan", summary="Analyze JavaScript files on a target")
async def scan_js(
    payload: JSScanRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> StreamingResponse:
    if not payload.target.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="target is required",
        )
    scan_id = str(_uuid.uuid4())
    return StreamingResponse(
        _safe_js_scan(payload, scan_id=scan_id, org_id=str(org_id)),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/history", summary="List previous JS scanner scans")
async def list_history(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    limit: int = Query(default=50, ge=1, le=200),
) -> dict:
    records = _load_history(str(org_id), limit=limit)
    summaries = []
    for r in records:
        summaries.append({
            "id": r.get("id"),
            "target": r.get("target"),
            "started_at": r.get("started_at"),
            "completed_at": r.get("completed_at"),
            "summary": r.get("summary", {}),
        })
    return {"items": summaries, "total": len(summaries)}


@router.get("/history/{scan_id}", summary="Get full details of a previous JS scan")
async def get_history_scan(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> dict:
    record = _load_scan(str(org_id), scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    return record


@router.delete("/history/{scan_id}", summary="Delete a JS scan record")
async def delete_history_scan(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> dict:
    deleted = _delete_scan_record(str(org_id), scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"deleted": True}
