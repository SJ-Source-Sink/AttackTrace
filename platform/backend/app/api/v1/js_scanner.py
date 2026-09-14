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
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings as _get_settings
from app.core.database import get_db
from app.core.dependencies import get_current_org_id, get_current_user
from app.core.remediation import get_remediation
from app.models.db.user import User
from app.services.finding_ingest import ingest_findings

router = APIRouter(prefix="/js-scanner", tags=["JS Scanner"])

# ──────────────────────────────────────────────────────────────────────────────
# Filesystem history helpers
# ──────────────────────────────────────────────────────────────────────────────

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)


def _validate_uuid(value: str, label: str) -> str:
    if not _UUID_RE.match(value):
        raise HTTPException(status_code=400, detail=f"Invalid {label}: must be a UUID")
    return value


def _history_dir(org_id: str) -> Path:
    d = Path(_get_settings().ATTACKTRACE_WORKSPACE_DIR) / "js_scanner" / org_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def _safe_history_path(org_id: str, scan_id: str) -> Path:
    """Build and confine the history file path to the org's history directory."""
    _validate_uuid(scan_id, "scan_id")
    base = _history_dir(org_id)
    candidate = (base / f"{scan_id}.json").resolve()
    if not candidate.is_relative_to(base.resolve()):
        raise HTTPException(status_code=400, detail="Invalid scan_id")
    return candidate


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
        path = _safe_history_path(org_id, scan_id)
        if path.exists():
            return json.loads(path.read_text())
    except HTTPException:
        raise
    except Exception:
        pass
    return None


def _delete_scan_record(org_id: str, scan_id: str) -> bool:
    try:
        path = _safe_history_path(org_id, scan_id)
        if path.exists():
            path.unlink()
            return True
    except HTTPException:
        raise
    except Exception:
        pass
    return False


# ──────────────────────────────────────────────────────────────────────────────
# SSE helper
# ──────────────────────────────────────────────────────────────────────────────

from app.core.sse import sse_event as _sse


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
    # ── AI / ML Providers ─────────────────────────────────────────────────────
    {"name": "OpenAI API Key",             "pattern": r"sk-[a-zA-Z0-9]{48}",                                                         "severity": "critical", "check_entropy": False},
    {"name": "OpenAI Project API Key",     "pattern": r"sk-proj-[A-Za-z0-9\-_]{48,}",                                               "severity": "critical", "check_entropy": False},
    {"name": "Anthropic API Key",          "pattern": r"sk-ant-api\d{2}-[A-Za-z0-9\-_]{93,}",                                       "severity": "critical", "check_entropy": False},
    {"name": "HuggingFace Token",          "pattern": r"hf_[A-Za-z0-9]{34,}",                                                       "severity": "critical", "check_entropy": False},
    {"name": "Cohere API Key",             "pattern": r"(?i)cohere[_\-]?(?:api[_\-]?)?key[^=\n]{0,10}=\s*['\"]([a-zA-Z0-9]{40})['\"]", "severity": "critical", "check_entropy": True},
    # ── Cloud / SaaS ──────────────────────────────────────────────────────────
    {"name": "Azure Storage Account Key",  "pattern": r"AccountKey=[A-Za-z0-9+/]{88}==",                                            "severity": "critical", "check_entropy": False},
    {"name": "Linear API Key",             "pattern": r"lin_api_[A-Za-z0-9]{40}",                                                   "severity": "critical", "check_entropy": False},
    {"name": "Notion API Token",           "pattern": r"secret_[A-Za-z0-9]{43}",                                                    "severity": "critical", "check_entropy": False},
    {"name": "Algolia API Key",            "pattern": r'(?i)algolia[^=\n]{0,30}=\s*[\'"]([A-Za-z0-9]{32})[\'"]',                   "severity": "high",     "check_entropy": True},
    {"name": "Vercel Token",               "pattern": r"(?i)vercel[_\-]?(?:token|api[_\-]?key)[^=\n]{0,10}=\s*['\"]([A-Za-z0-9]{24})['\"]", "severity": "critical", "check_entropy": True},
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

# ── Open redirect patterns ────────────────────────────────────────────────────

OPEN_REDIRECT_PATTERNS: list[dict] = [
    {
        "name": "Open Redirect via URL Parameter",
        "pattern": r"(?:location|window\.location)\.(?:href|assign|replace)\s*[=(]\s*[^;'\"]{0,60}(?:getParam|searchParams\.get|params\.get|query\.|req\.query|url=|redirect=|next=|return=)",
        "severity": "high",
    },
    {
        "name": "Unvalidated Redirect Assignment",
        "pattern": r"(?:location|window\.location)\s*=\s*(?!['\"]/)[a-zA-Z_$][\w$]*(?:\.[a-zA-Z_$][\w$]*)*\s*[;(,]",
        "severity": "medium",
    },
]

# ── JSONP patterns ─────────────────────────────────────────────────────────────

JSONP_PATTERNS: list[dict] = [
    {
        "name": "JSONP Callback Parameter",
        "pattern": r"""['"](https?://[^'"]{5,}\?[^'"]*\bcallback=[^'"]{3,})['"]""",
        "severity": "medium",
    },
    {
        "name": "Dynamic JSONP Window Callback",
        "pattern": r"window\[['\"]\w*[Cc]allback\w*['\"]\]",
        "severity": "medium",
    },
]

# ── Insecure randomness patterns ──────────────────────────────────────────────

INSECURE_RANDOM_PATTERNS: list[dict] = [
    {
        "name": "Math.random() for Security Token",
        "pattern": r"Math\.random\(\)[^;\n]{0,80}(?:token|secret|key|password|nonce|csrf|salt|session|auth)",
        "severity": "high",
    },
    {
        "name": "Security Value Seeded with Math.random",
        "pattern": r"(?:nonce|csrf|token|session(?:Id|Key)|secret)\s*(?:=|\+=)\s*[^;\n]{0,40}Math\.random",
        "severity": "high",
    },
]

# ── Hardcoded credentials in request headers ──────────────────────────────────

HARDCODED_AUTH_PATTERNS: list[dict] = [
    {
        "name": "Hardcoded Authorization Header",
        "pattern": r"""['"]Authorization['"]\s*:\s*['"`](?:Bearer|Basic|Token|ApiKey)\s+[A-Za-z0-9+/=._\-]{10,}['"`]""",
        "severity": "critical",
    },
    {
        "name": "Hardcoded API Key in Request Header",
        "pattern": r"""['"](?:X-Api-Key|X-Auth-Token|X-Access-Token|Api-Key|Apikey)['"]:\s*['"`][A-Za-z0-9+/=._\-]{10,}['"`]""",
        "severity": "high",
    },
]

# ── Library version fingerprinting ────────────────────────────────────────────

LIBRARY_SIGNATURES: list[dict] = [
    {
        "name": "jQuery",
        "pattern": r"jQuery\s+v?([0-9]+\.[0-9]+\.[0-9]+)|[Jj][Qq]uery[/:]([0-9]+\.[0-9]+\.[0-9]+)",
        "vuln_below": "3.5.0",
        "severity": "high",
        "note": "jQuery < 3.5.0 has XSS vulnerabilities (CVE-2020-11022, CVE-2020-11023).",
    },
    {
        "name": "AngularJS 1.x",
        "pattern": r"AngularJS\s+v([1]\.[0-9]+\.[0-9]+)|angular[/:]([1]\.[0-9]+\.[0-9]+)",
        "vuln_below": "9.9.9",  # all 1.x is EOL
        "severity": "high",
        "note": "AngularJS 1.x reached end-of-life Dec 2021. Migrate to Angular 15+.",
    },
    {
        "name": "lodash",
        "pattern": r"lodash\s+([0-9]+\.[0-9]+\.[0-9]+)|lodash[/:]([0-9]+\.[0-9]+\.[0-9]+)",
        "vuln_below": "4.17.21",
        "severity": "medium",
        "note": "lodash < 4.17.21 has prototype pollution (CVE-2021-23337).",
    },
    {
        "name": "moment.js",
        "pattern": r"moment\.js\s+version\s+([0-9]+\.[0-9]+\.[0-9]+)|\"moment\":\s*\"([0-9]+\.[0-9]+\.[0-9]+)\"",
        "vuln_below": "2.29.4",
        "severity": "low",
        "note": "moment.js is in maintenance mode — migrate to date-fns or Day.js.",
    },
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
    # React Create React App
    "/static/js/main.chunk.js",
    "/static/js/bundle.js",
    "/static/js/vendors~main.chunk.js",
    "/static/js/runtime-main.js",
    "/static/js/2.chunk.js",
    # Next.js
    "/_next/static/chunks/pages/_app.js",
    "/_next/static/chunks/main.js",
    "/_next/static/chunks/webpack.js",
    "/_next/static/chunks/polyfills.js",
    "/_next/static/chunks/framework.js",
    "/_next/static/chunks/commons.js",
    "/_next/static/development/_buildManifest.js",
    # Nuxt.js
    "/_nuxt/runtime.js",
    "/_nuxt/commons.js",
    "/_nuxt/app.js",
    "/_nuxt/vendors.js",
    # Vite
    "/assets/index.js",
    "/assets/main.js",
    # Angular
    "/main.js",
    "/polyfills.js",
    "/runtime.js",
    "/vendor.js",
    "/scripts.js",
    # Generic
    "/app.js",
    "/bundle.js",
    "/index.js",
    "/js/app.js",
    "/js/main.js",
    "/js/bundle.js",
    "/dist/bundle.js",
    "/dist/main.js",
    "/build/bundle.js",
    "/build/static/js/main.js",
    # Manifests (parsed for chunk names)
    "/manifest.json",
    "/asset-manifest.json",
    "/webpack-stats.json",
    # WordPress
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
# Security headers + SRI check
# ──────────────────────────────────────────────────────────────────────────────

def _check_security_headers(resp: httpx.Response) -> list[dict]:
    """Check HTTP response headers for security misconfigurations."""
    headers = {k.lower(): v for k, v in resp.headers.items()}
    page_url = str(resp.url)
    findings: list[dict] = []

    def _f(name: str, sev: str, match: str, rec: str) -> dict:
        return {
            "type": "security_header",
            "name": name,
            "severity": sev,
            "file_url": page_url,
            "match": match,
            "line_number": 0,
            "context": "",
            "remediation": rec,
        }

    # CORS
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "")
    if acao == "*" and acac.lower() == "true":
        findings.append(_f(
            "CORS: Wildcard Origin + Allow-Credentials",
            "critical",
            "Access-Control-Allow-Origin: * + Access-Control-Allow-Credentials: true",
            "Browsers reject credentials with wildcard CORS, but the config signals misconfiguration. Set a specific trusted origin.",
        ))
    elif acao == "*":
        findings.append(_f(
            "CORS: Wildcard Allow-Origin",
            "high",
            "Access-Control-Allow-Origin: *",
            "Restrict Access-Control-Allow-Origin to specific trusted origins instead of wildcard.",
        ))

    # CSP
    csp = headers.get("content-security-policy", "")
    if not csp:
        findings.append(_f(
            "Missing Content-Security-Policy",
            "medium",
            "Content-Security-Policy: not present",
            "Add a Content-Security-Policy header to reduce XSS risk. Start with \"default-src 'self'\".",
        ))
    else:
        if "unsafe-inline" in csp and "unsafe-eval" in csp:
            findings.append(_f(
                "CSP: unsafe-inline + unsafe-eval Directives",
                "high",
                csp[:100],
                "Both 'unsafe-inline' and 'unsafe-eval' in CSP provide minimal XSS protection. Use nonces or hashes.",
            ))
        elif "unsafe-inline" in csp:
            findings.append(_f(
                "CSP: unsafe-inline Directive",
                "medium",
                csp[:100],
                "CSP 'unsafe-inline' allows inline scripts, weakening XSS protection. Use nonces or hashes.",
            ))

    # HSTS
    if page_url.startswith("https://") and not headers.get("strict-transport-security"):
        findings.append(_f(
            "Missing HSTS Header",
            "medium",
            "Strict-Transport-Security: not present",
            "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to enforce HTTPS.",
        ))

    # X-Frame-Options / frame-ancestors
    xfo = headers.get("x-frame-options", "")
    has_frame_ancestors = "frame-ancestors" in csp
    if not xfo and not has_frame_ancestors:
        findings.append(_f(
            "Missing Clickjacking Protection",
            "medium",
            "X-Frame-Options: not present, CSP frame-ancestors: not present",
            "Add 'X-Frame-Options: DENY' or CSP 'frame-ancestors 'none'' to prevent clickjacking.",
        ))

    # X-Content-Type-Options
    if headers.get("x-content-type-options", "").lower() != "nosniff":
        findings.append(_f(
            "Missing X-Content-Type-Options",
            "low",
            f"X-Content-Type-Options: {headers.get('x-content-type-options', 'not present')}",
            "Add 'X-Content-Type-Options: nosniff' to prevent MIME-sniffing attacks.",
        ))

    # Referrer-Policy
    if not headers.get("referrer-policy"):
        findings.append(_f(
            "Missing Referrer-Policy",
            "low",
            "Referrer-Policy: not present",
            "Add 'Referrer-Policy: strict-origin-when-cross-origin' to control referrer leakage.",
        ))

    # Server / X-Powered-By version disclosure
    server = headers.get("server", "")
    xpb = headers.get("x-powered-by", "")
    if server and any(v in server.lower() for v in ("apache/", "nginx/", "iis/", "php/", "express/", "werkzeug")):
        findings.append(_f(
            "Server Version Disclosure",
            "low",
            f"Server: {server}",
            "Remove or genericize the Server header to avoid disclosing server software/version.",
        ))
    if xpb:
        findings.append(_f(
            "X-Powered-By Disclosure",
            "low",
            f"X-Powered-By: {xpb}",
            "Remove the X-Powered-By header to avoid disclosing framework/version information.",
        ))

    return findings


def _check_external_sri(html: str, page_url: str) -> list[dict]:
    """Find cross-origin <script> tags missing Subresource Integrity."""
    findings: list[dict] = []
    page_netloc = urlparse(page_url).netloc
    for m in re.finditer(r'<script\s([^>]+)>', html, re.IGNORECASE):
        attrs = m.group(1)
        src_m = re.search(r"""src=['"](https?://[^'"]+)['"]""", attrs, re.IGNORECASE)
        if not src_m:
            continue
        src = src_m.group(1)
        if urlparse(src).netloc == page_netloc:
            continue
        if "integrity=" in attrs.lower():
            continue
        findings.append({
            "type": "sri_missing",
            "name": "External Script Without Subresource Integrity",
            "severity": "medium",
            "file_url": page_url,
            "match": src[:80],
            "line_number": 0,
            "context": m.group(0)[:200],
            "remediation": (
                "Add integrity='sha384-...' and crossorigin='anonymous' to external <script> tags. "
                "Generate SRI hashes at https://www.srihash.org/"
            ),
        })
    return findings


def _detect_library_versions(content: str, file_url: str) -> list[dict]:
    """Fingerprint known JS library versions and flag outdated ones."""
    findings: list[dict] = []
    for lib in LIBRARY_SIGNATURES:
        m = re.search(lib["pattern"], content, re.IGNORECASE)
        if not m:
            continue
        version = next((g for g in m.groups() if g), None)
        if not version:
            continue
        # Parse version tuple for comparison
        try:
            v_parts = tuple(int(x) for x in version.split(".")[:3])
            threshold = tuple(int(x) for x in lib["vuln_below"].split(".")[:3])
            is_vuln = v_parts < threshold
        except Exception:
            is_vuln = True  # assume vulnerable if parse fails
        if is_vuln:
            findings.append({
                "type": "library_vuln",
                "name": f"Outdated {lib['name']} ({version})",
                "severity": lib["severity"],
                "file_url": file_url,
                "match": f"{lib['name']} {version}",
                "line_number": _line_number(content, m.start()),
                "context": _get_context(content, m.start()),
                "remediation": lib.get("note") or f"Upgrade {lib['name']} to {lib['vuln_below']} or later.",
            })
    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Source → Sink taint analysis (confirmed XSS)
# ──────────────────────────────────────────────────────────────────────────────

# Patterns that capture a variable name assigned from a user-controlled source
_TAINT_SOURCE_PATTERNS: list[str] = [
    # var x = location.search / .hash / .href / .pathname
    r'(?:var|let|const)\s+([a-zA-Z_$][\w$]*)\s*=\s*(?:window\.)?location\.(?:search|hash|href|pathname)\b',
    # var x = document.referrer / document.cookie
    r'(?:var|let|const)\s+([a-zA-Z_$][\w$]*)\s*=\s*document\.(?:referrer|cookie)\b',
    # var x = window.name
    r'(?:var|let|const)\s+([a-zA-Z_$][\w$]*)\s*=\s*window\.name\b',
    # var x = new URLSearchParams(...)
    r'(?:var|let|const)\s+([a-zA-Z_$][\w$]*)\s*=\s*new\s+URLSearchParams\s*\(',
    # var x = params.get(...) / searchParams.get(...) / urlParams.get(...)
    r'(?:var|let|const)\s+([a-zA-Z_$][\w$]*)\s*=\s*\w+\.get\s*\([^)]+\)',
    # var x = decodeURIComponent(location...) or atob(location...)
    r'(?:var|let|const)\s+([a-zA-Z_$][\w$]*)\s*=\s*(?:decodeURIComponent|decodeURI|atob|unescape)\s*\([^)]*location',
    # var x = getParameter(...) / getUrlParameter(...) / getQueryParam(...)
    r'(?:var|let|const)\s+([a-zA-Z_$][\w$]*)\s*=\s*(?:getParam|getParameter|getUrlParam|getQueryParam|getQueryString)\s*\(',
    # var x = req.query.* / req.params.* / req.body.* (isomorphic/SSR)
    r'(?:var|let|const)\s+([a-zA-Z_$][\w$]*)\s*=\s*(?:req|request)\.(?:query|params|body)\.\w+',
    # x = e.data (postMessage event)
    r'(?:var|let|const)\s+([a-zA-Z_$][\w$]*)\s*=\s*(?:event|e|evt)\.data\b',
    # Direct reads without assignment (track expressions used in sinks below)
]

# Sink patterns: group(1) captures the expression being written
_TAINT_SINK_PATTERNS: list[tuple[str, str]] = [
    ("innerHTML write",       r'(\w[\w$.]*)\s*\.innerHTML\s*[+]?=\s*([^;\n]{3,120})'),
    ("outerHTML write",       r'(\w[\w$.]*)\s*\.outerHTML\s*[+]?=\s*([^;\n]{3,120})'),
    ("insertAdjacentHTML",    r'\.insertAdjacentHTML\s*\([^,]+,\s*([^)]{3,120})\)'),
    ("document.write",        r'document\.write(?:ln)?\s*\(\s*([^)]{3,120})\)'),
    ("eval()",                r'\beval\s*\(\s*([^)]{3,120})\)'),
    ("Function() constructor", r'\bnew\s+Function\s*\([^)]*([^)]{5,120})\)'),
    ("setTimeout with string", r'setTimeout\s*\(\s*([^,)]{5,120})[,)]'),
    ("jQuery .html()",        r'\.html\s*\(\s*([^)]{3,120})\)'),
    ("jQuery .append()",      r'\.(?:append|prepend|after|before)\s*\(\s*([^)]{3,120})\)'),
    ("location.href redirect", r'(?:window\.)?location\.(?:href|assign|replace)\s*[=(]\s*([^;\n]{3,120})'),
    (".src assignment",        r'(\w[\w$.]*)\.src\s*=\s*([^;\n]{3,80})'),
    ("dangerouslySetInnerHTML", r'dangerouslySetInnerHTML\s*=\s*\{\{?\s*__html\s*:\s*([^}]{3,120})'),
]


def _find_tainted_sinks(content: str, file_url: str) -> list[dict]:
    """
    Source-to-sink taint analysis for DOM XSS.

    Collects variable names assigned from user-controlled sources, then checks
    whether those variables appear in dangerous sink expressions.  Reports as
    'confirmed_xss' (critical) instead of separate source/sink findings.
    """
    findings: list[dict] = []

    # ── Step 1: collect tainted variable names ────────────────────────────────
    tainted_vars: set[str] = set()
    for pattern in _TAINT_SOURCE_PATTERNS:
        for m in re.finditer(pattern, content, re.IGNORECASE):
            var = m.group(1)
            if var and var not in ("i", "j", "k", "n", "x", "e", "t", "r", "o", "s"):
                tainted_vars.add(var)

    # Also directly track readable source expressions (not via variable)
    # so we can catch inline cases like:  el.innerHTML = location.hash
    INLINE_SOURCES = re.compile(
        r'\b(?:location\.(?:search|hash|href|pathname)|document\.(?:referrer|cookie)|window\.name|'
        r'(?:event|e|evt)\.data)\b',
        re.IGNORECASE,
    )

    if not tainted_vars and not re.search(INLINE_SOURCES.pattern, content, re.IGNORECASE):
        return findings

    # ── Step 2: check sinks for tainted variable usage ────────────────────────
    seen_sinks: set[str] = set()

    for sink_name, sink_pattern in _TAINT_SINK_PATTERNS:
        for m in re.finditer(sink_pattern, content, re.IGNORECASE | re.DOTALL):
            # The "value being written" is always the last capturing group
            groups = [g for g in m.groups() if g is not None]
            sink_expr = groups[-1] if groups else m.group(0)
            sink_expr = sink_expr.strip()

            tainted_var_found: str | None = None

            # Check named tainted variables
            for var in tainted_vars:
                if re.search(r'\b' + re.escape(var) + r'\b', sink_expr):
                    tainted_var_found = var
                    break

            # Check inline source expressions flowing directly into sink
            if not tainted_var_found and INLINE_SOURCES.search(sink_expr):
                tainted_var_found = INLINE_SOURCES.search(sink_expr).group(0)  # type: ignore[union-attr]

            if not tainted_var_found:
                continue

            line = _line_number(content, m.start())
            dedup_key = f"{sink_name}:{line}"
            if dedup_key in seen_sinks:
                continue
            seen_sinks.add(dedup_key)

            findings.append({
                "type": "confirmed_xss",
                "name": f"Confirmed DOM XSS — {sink_name}",
                "severity": "critical",
                "file_url": file_url,
                "match": f"{tainted_var_found} → {sink_expr[:70]}",
                "line_number": line,
                "context": _get_context(content, m.start()),
                "remediation": (
                    f"User-controlled value '{tainted_var_found}' flows directly into '{sink_name}'. "
                    "Sanitize with DOMPurify.sanitize() before inserting into the DOM, "
                    "or use safe DOM APIs (textContent, createElement) instead."
                ),
            })

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# HTML page crawler (multi-page JS discovery)
# ──────────────────────────────────────────────────────────────────────────────

async def _crawl_html_pages(
    client: httpx.AsyncClient,
    start_url: str,
    origin: str,
    include_subdomains: bool,
    max_pages: int = 15,
    max_depth: int = 2,
) -> tuple[list[str], list[str], list[str]]:
    """
    BFS-crawl same-origin HTML pages to discover JS files.

    Returns (discovered_js_urls, inline_script_blocks, crawled_page_urls).
    """
    seen_pages: set[str] = {start_url}
    seen_js: set[str] = set()
    discovered_js: list[str] = []
    inline_scripts: list[str] = []
    crawled_pages: list[str] = []
    queue: list[tuple[str, int]] = [(start_url, 0)]

    # File extensions to skip when following links
    _SKIP_EXTS = frozenset((
        ".css", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico",
        ".pdf", ".zip", ".tar", ".gz", ".mp4", ".mp3", ".woff", ".woff2", ".ttf",
        ".xml", ".rss", ".atom",
    ))

    while queue and len(crawled_pages) < max_pages:
        page_url, depth = queue.pop(0)

        try:
            resp = await client.get(page_url, follow_redirects=True, timeout=8.0)
        except Exception:
            continue

        if resp.status_code != 200:
            continue
        ct = resp.headers.get("content-type", "")
        if "html" not in ct:
            continue

        html = resp.text
        crawled_pages.append(page_url)

        # Extract <script src>
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
            js_url = _resolve_js_url(m.group(1), page_url)
            if js_url and js_url not in seen_js:
                seen_js.add(js_url)
                discovered_js.append(js_url)

        # Extract <link rel="preload/modulepreload" as="script">
        for m in re.finditer(
            r'<link[^>]+(?:rel=["\'](?:preload|modulepreload)["\'][^>]+href=["\']([^"\']+)["\']'
            r'|href=["\']([^"\']+)["\'][^>]+rel=["\'](?:preload|modulepreload)["\'])',
            html, re.IGNORECASE,
        ):
            src = m.group(1) or m.group(2)
            if not src:
                continue
            # Only add if it looks like a JS file (or no extension – could be chunked)
            if ".css" not in src.lower():
                js_url = _resolve_js_url(src, page_url)
                if js_url and js_url not in seen_js:
                    seen_js.add(js_url)
                    discovered_js.append(js_url)

        # Extract inline scripts
        for m in re.finditer(r'<script(?:[^>]*)>([\s\S]*?)</script>', html, re.IGNORECASE):
            block = m.group(1).strip()
            if block and len(block) > 20 and "application/ld+json" not in m.group(0):
                inline_scripts.append(block)

        # Parse Next.js __NEXT_DATA__ for buildId
        nd_m = re.search(r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>', html, re.IGNORECASE | re.DOTALL)
        if nd_m:
            try:
                nd = json.loads(nd_m.group(1))
                build_id = nd.get("buildId", "")
                if build_id:
                    for pg in ("/_app", "/_error", "/index"):
                        chunk = f"/_next/static/{build_id}/pages{pg}.js"
                        full = origin + chunk
                        if full not in seen_js:
                            seen_js.add(full)
                            discovered_js.append(full)
            except Exception:
                pass

        # Follow same-origin links at shallower depths
        if depth < max_depth:
            for m in re.finditer(r'<a[^>]+href=["\']([^"\'#][^"\']*)["\']', html, re.IGNORECASE):
                href = m.group(1).strip()
                if not href or href.startswith(("javascript:", "mailto:", "tel:")):
                    continue
                linked = _resolve_js_url(href, page_url)
                if not linked:
                    continue
                # Strip query/fragment for dedup
                from urllib.parse import urldefrag
                linked_clean, _ = urldefrag(linked)
                # Skip non-HTML resource extensions
                path_lower = urlparse(linked_clean).path.lower()
                if any(path_lower.endswith(ext) for ext in _SKIP_EXTS):
                    continue
                if (
                    linked_clean not in seen_pages
                    and _is_same_origin(linked_clean, origin, include_subdomains)
                ):
                    seen_pages.add(linked_clean)
                    queue.append((linked_clean, depth + 1))

    return discovered_js, inline_scripts, crawled_pages


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
                "remediation": f"Remove hardcoded {spec['name']} from JavaScript. Use server-side environment variables or a secrets manager.",
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
                "remediation": "Environment variables exposed in client-side JS are readable by anyone. Use server-side APIs to proxy sensitive config.",
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
                "remediation": f"Avoid using {sink['name']} with untrusted input. Use DOMPurify or safe DOM APIs.",
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
                "remediation": "Trace this user-controlled source to ensure it does not flow into a dangerous sink without sanitization.",
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
                "remediation": "Sanitize object keys against '__proto__', 'constructor', and 'prototype' before performing deep merges.",
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
                "remediation": "Always validate event.origin in postMessage listeners and avoid sending messages to wildcard origins.",
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
                "remediation": "Ensure WebSocket connections include authentication tokens and validate the Origin header server-side.",
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
                "remediation": "Review service worker scope and ensure it does not intercept sensitive requests or execute untrusted scripts.",
            })

    # ── Open redirect ──────────────────────────────────────────────────────────
    for pat in OPEN_REDIRECT_PATTERNS:
        for m in re.finditer(pat["pattern"], processed, re.IGNORECASE | re.DOTALL):
            line = _line_number(processed, m.start())
            _add_finding({
                "type": "open_redirect",
                "name": pat["name"],
                "severity": pat["severity"],
                "file_url": file_url,
                "match": _truncate_match(m.group(0), 60),
                "line_number": line,
                "context": _get_context(processed, m.start()),
                "remediation": "Validate redirect destinations against an allowlist of trusted URLs before redirecting.",
            })

    # ── JSONP ──────────────────────────────────────────────────────────────────
    for pat in JSONP_PATTERNS:
        for m in re.finditer(pat["pattern"], processed, re.IGNORECASE):
            line = _line_number(processed, m.start())
            raw = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
            _add_finding({
                "type": "jsonp",
                "name": pat["name"],
                "severity": pat["severity"],
                "file_url": file_url,
                "match": _truncate_match(raw, 80),
                "line_number": line,
                "context": _get_context(processed, m.start()),
                "remediation": "JSONP is deprecated. Migrate to CORS-enabled APIs. If JSONP must be used, validate the callback name strictly.",
            })

    # ── Insecure randomness ────────────────────────────────────────────────────
    for pat in INSECURE_RANDOM_PATTERNS:
        for m in re.finditer(pat["pattern"], processed, re.IGNORECASE):
            line = _line_number(processed, m.start())
            _add_finding({
                "type": "insecure_random",
                "name": pat["name"],
                "severity": pat["severity"],
                "file_url": file_url,
                "match": _truncate_match(m.group(0), 60),
                "line_number": line,
                "context": _get_context(processed, m.start()),
                "remediation": "Use window.crypto.getRandomValues() or crypto.randomUUID() for security-sensitive random values.",
            })

    # ── Hardcoded auth headers ─────────────────────────────────────────────────
    for pat in HARDCODED_AUTH_PATTERNS:
        for m in re.finditer(pat["pattern"], processed, re.IGNORECASE):
            raw = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
            if _is_likely_placeholder(raw):
                continue
            line = _line_number(processed, m.start())
            _add_finding({
                "type": "hardcoded_auth",
                "name": pat["name"],
                "severity": pat["severity"],
                "file_url": file_url,
                "match": _truncate_match(raw),
                "line_number": line,
                "context": _get_context(processed, m.start()),
                "remediation": "Never hardcode credentials in client-side JS. Fetch tokens at runtime from a secure backend endpoint.",
            })

    # ── Library versions ───────────────────────────────────────────────────────
    for lib_finding in _detect_library_versions(processed, file_url):
        _add_finding(lib_finding)

    # ── Source → Sink taint analysis (confirmed XSS) ──────────────────────────
    for xss_finding in _find_tainted_sinks(processed, file_url):
        _add_finding(xss_finding)

    return endpoints, findings, has_graphql


# ──────────────────────────────────────────────────────────────────────────────
# Finding-table ingestion adapter (app.services.finding_ingest)
# ──────────────────────────────────────────────────────────────────────────────

# `type` -> Finding.category. Groups the ~90 distinct pattern names produced by
# this scanner into a stable, filterable category per detection class.
_JS_TYPE_CATEGORY: dict[str, str] = {
    "secret": "secrets",
    "dom_xss": "dom-xss",
    "dom_source": "dom-xss",
    "confirmed_xss": "dom-xss",
    "prototype_pollution": "prototype-pollution",
    "postmessage": "postmessage-security",
    "websocket": "websocket-security",
    "service_worker": "service-worker-security",
    "env_leak": "env-var-leak",
    "source_map": "source-map-exposure",
    "graphql": "graphql-introspection",
    "security_header": "missing-security-headers",
    "sri_missing": "subresource-integrity",
    "open_redirect": "open-redirect",
    "jsonp": "jsonp",
    "insecure_random": "insecure-randomness",
    "hardcoded_auth": "hardcoded-credentials",
    "library_vuln": "vulnerable-library",
}

# Confidence reflects *how* each pattern was confirmed (the false-positive-gate
# doctrine — see app.core.finding_confidence), not how dangerous it looks:
#   certain — a live value/behavior was directly observed (a downloaded .map
#             file, a real introspection response, a literal header value).
#   high    — a fixed, hard-to-confuse format/marker matched (vendor key
#             prefix, PEM header, wildcard '*' origin literal).
#   medium  — a real code-level indicator with some false-positive risk
#             (entropy-filtered generic secret, a dangerous sink present
#             without proof of a reachable taint source).
#   low     — a broad heuristic or a "missing X" bare-signal check with a
#             materially higher false-positive rate.
_JS_CONFIDENCE_BY_NAME: dict[str, str] = {
    # ── Secrets (JS_SECRET_PATTERNS) ──────────────────────────────────────────
    "AWS Access Key": "high", "AWS Secret Key": "medium",
    "GCP API Key": "high", "GCP Service Account Key": "high",
    "Firebase Server Key": "high", "Firebase DB URL": "low", "Firebase Config": "medium",
    "Stripe Live Secret Key": "high", "Stripe Restricted Key": "high", "Stripe Test Key": "medium",
    "Square Access Token": "high", "Square OAuth Secret": "high",
    "Slack Bot Token": "high", "Slack User Token": "high", "Slack Legacy Token": "high", "Slack Webhook": "high",
    "Discord Bot Token": "high", "Discord Webhook": "high",
    "Twilio Account SID": "low", "Twilio Auth Token": "medium",
    "SendGrid API Key": "high", "Mailgun API Key": "medium", "Mailchimp API Key": "medium",
    "GitHub Classic PAT": "high", "GitHub Fine-grained PAT": "high",
    "GitHub OAuth Token": "high", "GitHub App Token": "high", "npm Token": "high",
    "Sentry DSN": "medium", "Sentry DSN (legacy)": "high",
    "Datadog API Key": "medium", "PagerDuty API Key": "medium",
    "Mapbox Public Token": "low", "Mapbox Secret Token": "high", "Cloudinary URL": "high",
    "Shopify Access Token": "high", "Shopify Private App": "high",
    "JWT Token": "medium", "Bearer Token": "medium", "Okta API Token": "medium",
    "Private Key": "certain", "Hardcoded Password": "medium",
    "Generic API Key": "medium", "Generic Secret": "medium",
    "MongoDB URI": "high", "DB Connection String": "high",
    "Internal IP Address": "low", "Internal URL": "low",
    "TODO with Credentials": "low", "Commented Credentials": "low",
    "OpenAI API Key": "high", "OpenAI Project API Key": "high", "Anthropic API Key": "high",
    "HuggingFace Token": "high", "Cohere API Key": "medium",
    "Azure Storage Account Key": "high", "Linear API Key": "high", "Notion API Token": "high",
    "Algolia API Key": "medium", "Vercel Token": "medium",
    # ── DOM XSS sinks (DOM_XSS_SINKS) ─────────────────────────────────────────
    "innerHTML Assignment": "medium", "outerHTML Assignment": "medium",
    "insertAdjacentHTML": "medium", "document.write": "medium",
    "eval()": "medium", "Function() constructor": "medium",
    "setTimeout with string": "medium", "setInterval with string": "medium",
    "jQuery .html()": "medium", "jQuery .append()": "low", "jQuery.parseHTML()": "medium",
    "location.href assignment": "low", "location.replace()": "low", "location.assign()": "low",
    "document.location assign": "low",
    "React dangerouslySetInnerHTML": "medium", "Angular innerHTML binding": "medium",
    "Angular bypassSecurityTrust": "high", "Vue v-html directive": "medium",
    "Angular $sce.trustAsHtml": "high", "Dynamic script element": "low", ".src assignment": "low",
    # ── DOM XSS sources (DOM_XSS_SOURCES) ─────────────────────────────────────
    "localStorage of sensitive token": "medium",
    # ── Prototype pollution ───────────────────────────────────────────────────
    "Direct __proto__ Assignment": "medium", "constructor.prototype Access": "low",
    "Unsafe Deep Merge": "medium", "Unsafe Object.assign": "medium",
    "Lodash defaultsDeep": "medium", "JSON.parse to __proto__": "medium",
    "Bracket Access with Variable": "low",
    # ── PostMessage ────────────────────────────────────────────────────────────
    "postMessage Wildcard Origin": "high", "iframe postMessage Wildcard": "high",
    "Dangerous postMessage Handler": "high",
    # ── WebSocket / service worker ────────────────────────────────────────────
    "WebSocket without Auth Param": "low", "WebSocket Message to Sink": "medium",
    "SW importScripts from CDN": "low", "SW Wildcard Scope": "low",
    "SW Dangerous Message Handler": "medium",
    # ── Open redirect / JSONP / insecure randomness / hardcoded auth headers ──
    "Open Redirect via URL Parameter": "medium", "Unvalidated Redirect Assignment": "low",
    "JSONP Callback Parameter": "low", "Dynamic JSONP Window Callback": "low",
    "Math.random() for Security Token": "medium", "Security Value Seeded with Math.random": "medium",
    "Hardcoded Authorization Header": "high", "Hardcoded API Key in Request Header": "high",
    # ── Env leaks ──────────────────────────────────────────────────────────────
    "React Env Var Leak": "medium", "Next.js Env Var Leak": "medium", "Vite Env Var Leak": "medium",
    "process.env Leak": "low", "process.env Spread": "medium", "Internal Hostname": "low",
    "Debug Mode Enabled": "low", "Dev Server URL": "low", "Absolute Path Leak": "low",
    "Console.log of Secret": "medium",
    # ── Response-header / SRI / source-map / GraphQL checks ───────────────────
    "CORS: Wildcard Origin + Allow-Credentials": "certain", "CORS: Wildcard Allow-Origin": "certain",
    "Missing Content-Security-Policy": "low",
    "CSP: unsafe-inline + unsafe-eval Directives": "certain", "CSP: unsafe-inline Directive": "certain",
    "Missing HSTS Header": "low", "Missing Clickjacking Protection": "low",
    "Missing X-Content-Type-Options": "low", "Missing Referrer-Policy": "low",
    "Server Version Disclosure": "certain", "X-Powered-By Disclosure": "certain",
    "External Script Without Subresource Integrity": "high",
    "JavaScript Source Map Exposed": "certain",
    "GraphQL Introspection Enabled": "certain",
}


def _js_confidence(f: dict) -> str:
    """Grade confidence for a js_scanner.py finding. Dynamic-title types
    (confirmed_xss's taint-traced source->sink correlation, library_vuln's
    version-fingerprint match) are graded by type; everything else is a fixed
    pattern name looked up directly."""
    ftype = f.get("type", "")
    if ftype == "confirmed_xss":
        return "high"  # two-signal: a tainted source AND a matching sink
    if ftype == "library_vuln":
        return "high"  # literal version fingerprint below a known-vuln threshold
    return _JS_CONFIDENCE_BY_NAME.get(f.get("name", ""), "medium")


def _adapt_js_findings(findings: list[dict]) -> list[dict]:
    """Normalize js_scanner.py findings for finding_ingest.ingest_findings.

    Prefers the finding's own inline remediation text (every current
    detection path writes one under "remediation"; historical scan records
    predating a field rename wrote it under "recommendation") and only falls
    back to the shared app.core.remediation lookup if neither is present.
    """
    adapted = []
    for f in findings:
        name = f.get("name") or "JS finding"
        remediation = f.get("remediation") or f.get("recommendation") or get_remediation(category=name, title=name)
        adapted.append({
            "title": name,
            "description": f.get("context", ""),
            "severity": f.get("severity", "medium"),
            "category": _JS_TYPE_CATEGORY.get(f.get("type", ""), "js-analysis"),
            "affected_asset": f.get("file_url", ""),
            "evidence": {
                "match": f.get("match"),
                "line_number": f.get("line_number"),
                "context": f.get("context"),
                "file_url": f.get("file_url"),
                "suppressed_note": f.get("suppressed_note"),
            },
            "remediation": str(remediation),
            "confidence": _js_confidence(f),
        })
    return adapted


# ──────────────────────────────────────────────────────────────────────────────
# Main scan generator
# ──────────────────────────────────────────────────────────────────────────────

async def _run_js_scan(
    request: JSScanRequest,
    scan_id: str,
    org_id: str,
    db: AsyncSession,
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
    security_header_count = 0
    sri_missing_count = 0
    vuln_lib_count = 0
    open_redirect_count = 0
    hardcoded_auth_count = 0
    confirmed_xss_count = 0

    def _count_finding(f: dict) -> None:
        nonlocal secrets_count, dom_xss_count, proto_pollution_count, env_leak_count
        nonlocal security_header_count, sri_missing_count, vuln_lib_count, open_redirect_count, hardcoded_auth_count
        t = f.get("type", "")
        if t == "secret":
            secrets_count += 1
        elif t in ("dom_xss", "dom_source"):
            dom_xss_count += 1
        elif t == "prototype_pollution":
            proto_pollution_count += 1
        elif t == "env_leak":
            env_leak_count += 1
        elif t == "security_header":
            security_header_count += 1
        elif t == "sri_missing":
            sri_missing_count += 1
        elif t == "library_vuln":
            vuln_lib_count += 1
        elif t == "open_redirect":
            open_redirect_count += 1
        elif t == "hardcoded_auth":
            hardcoded_auth_count += 1
        elif t == "confirmed_xss":
            confirmed_xss_count += 1

    yield _sse("start", {"scan_id": scan_id, "target": target})
    yield _sse("progress", {"phase": "discovery", "message": "Fetching target page..."})

    discovered_js: list[str] = []
    seen_urls: set[str] = set()

    _fetch_error: list[str] = []  # mutable container so inner func can write to it

    async def _safe_get(client: httpx.AsyncClient, url: str, timeout: float = 10.0) -> httpx.Response | None:
        try:
            return await client.get(url, follow_redirects=True, timeout=timeout)
        except httpx.ConnectError as e:
            _fetch_error.append(f"Connection failed: {e}")
        except httpx.TimeoutException:
            _fetch_error.append(f"Timeout after {timeout}s")
        except httpx.SSLError as e:
            _fetch_error.append(f"SSL error (try http://): {e}")
        except Exception as e:
            _fetch_error.append(f"Request failed: {e}")
        return None

    async with httpx.AsyncClient(
        headers={"User-Agent": "Mozilla/5.0 (compatible; AttackTrace/2.0; +https://attacktrace.io)"},
        follow_redirects=True,
        timeout=10.0,
        verify=False,
    ) as client:

        # ── Phase 1: probe main page to check connectivity ────────────────────
        main_resp = await _safe_get(client, target)
        if main_resp is None and _fetch_error:
            err_msg = _fetch_error[-1]
            yield _sse("progress", {"phase": "error", "message": f"Failed to reach {target}: {err_msg}"})
            yield _sse("complete", {
                "scan_id": scan_id, "target": target,
                "js_files_scanned": 0, "endpoints_found": 0, "secrets_found": 0,
                "dom_xss_sinks": 0, "source_maps_exposed": 0, "graphql_issues": 0,
                "prototype_pollution": 0, "env_leaks": 0,
                "security_headers": 0, "sri_missing": 0, "vulnerable_libs": 0,
                "open_redirects": 0, "hardcoded_auth": 0, "confirmed_xss": 0,
                "duration_seconds": 0, "error": err_msg,
            })
            return

        # ── Phase 2: security headers check on main response ──────────────────
        if main_resp and main_resp.status_code == 200:
            yield _sse("progress", {"phase": "headers", "message": "Checking security response headers..."})
            for hdr_finding in _check_security_headers(main_resp):
                yield _sse("finding", hdr_finding)
                all_findings.append(hdr_finding)
                _count_finding(hdr_finding)

        # ── Phase 3: multi-page BFS crawl to discover JS across the site ──────
        yield _sse("progress", {"phase": "crawl", "message": f"Crawling site (max {request.max_depth} levels deep)..."})

        crawl_js, inline_scripts, crawled_pages = await _crawl_html_pages(
            client=client,
            start_url=target,
            origin=origin,
            include_subdomains=request.include_subdomains,
            max_pages=20,
            max_depth=request.max_depth,
        )

        for js_url in crawl_js:
            if js_url not in seen_urls:
                seen_urls.add(js_url)
                discovered_js.append(js_url)

        yield _sse("progress", {
            "phase": "crawl",
            "message": f"Crawled {len(crawled_pages)} pages, found {len(discovered_js)} JS files so far",
            "pages": crawled_pages[:20],
        })

        # ── SRI check from crawled pages' HTML ────────────────────────────────
        if main_resp and main_resp.status_code == 200:
            for sri_finding in _check_external_sri(main_resp.text, target):
                yield _sse("finding", sri_finding)
                all_findings.append(sri_finding)
                _count_finding(sri_finding)

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

                    # Depth-2 discovery: follow import() / require() URLs in this JS
                    for imp_m in re.finditer(
                        r"""(?:import\s*\(\s*|require\s*\(\s*)['"`]([^'"`]+\.js(?:\?[^'"`]*)?)['"`]""",
                        content, re.IGNORECASE,
                    ):
                        more_js = _resolve_js_url(imp_m.group(1), js_url)
                        if (
                            more_js
                            and more_js not in seen_urls
                            and _is_same_origin(more_js, origin, request.include_subdomains)
                            and len(discovered_js) < request.max_files
                        ):
                            seen_urls.add(more_js)
                            discovered_js.append(more_js)

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
                                                "remediation": "Remove sourceMappingURL from production builds. Never deploy .map files publicly — they expose full original source.",
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
                                "remediation": "Disable GraphQL introspection in production. It exposes your full API schema to attackers.",
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
            "security_headers": security_header_count,
            "sri_missing": sri_missing_count,
            "vulnerable_libs": vuln_lib_count,
            "open_redirects": open_redirect_count,
            "hardcoded_auth": hardcoded_auth_count,
            "confirmed_xss": confirmed_xss_count,
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

        try:
            adapted = _adapt_js_findings(all_findings)
            await ingest_findings(db, org_id, source="js_scanner", source_scan_id=scan_id, findings=adapted)
            await db.commit()
        except Exception:
            await db.rollback()


async def _safe_js_scan(
    request: JSScanRequest,
    scan_id: str,
    org_id: str,
    db: AsyncSession,
) -> AsyncGenerator[str, None]:
    """Wrapper that surfaces unhandled exceptions as SSE error events."""
    import traceback
    try:
        async for chunk in _run_js_scan(request, scan_id, org_id, db):
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
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    if not payload.target.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="target is required",
        )
    scan_id = str(_uuid.uuid4())
    return StreamingResponse(
        _safe_js_scan(payload, scan_id=scan_id, org_id=str(org_id), db=db),
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
