"""
Firewall & WAF Scanner API — WAF detection, bypass probing, port firewall mapping,
and firewall rule analysis, all streamed via SSE where applicable.
"""

import asyncio
import difflib
import hashlib
import hmac
import io
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import struct
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Annotated, AsyncGenerator

import httpx
from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import get_current_org_id, get_current_user, require_tool
from app.models.db.audit import AuditLog
from app.models.db.user import User

router = APIRouter(prefix="/firewall", tags=["Firewall"])

# In-memory scan history (all scan types share this dict)
_scan_history: dict[str, dict] = {}


# ── SSE helper ────────────────────────────────────────────────────────────────

def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


# ── WAF signature database ────────────────────────────────────────────────────

WAF_SIGNATURES: list[dict] = [
    {
        "vendor": "Cloudflare",
        "header_patterns": [
            (re.compile(r"^cf-ray$", re.I), None, 80),
            (re.compile(r"^cf-cache-status$", re.I), None, 60),
            (re.compile(r"^cf-request-id$", re.I), None, 60),
            (re.compile(r"^server$", re.I), re.compile(r"cloudflare", re.I), 80),
        ],
        "cookie_patterns": [
            (re.compile(r"^__cfduid$", re.I), 60),
            (re.compile(r"^cf_clearance$", re.I), 80),
            (re.compile(r"^__cf_bm$", re.I), 80),
        ],
        "body_patterns": [
            (re.compile(r"cloudflare", re.I), 40),
            (re.compile(r"cf-ray", re.I), 30),
        ],
    },
    {
        "vendor": "AWS WAF",
        "header_patterns": [
            (re.compile(r"^x-amzn-requestid$", re.I), None, 70),
            (re.compile(r"^x-amzn-trace-id$", re.I), None, 50),
        ],
        "cookie_patterns": [
            (re.compile(r"^aws-waf-token$", re.I), 80),
        ],
        "body_patterns": [
            (re.compile(r"aws\s*waf", re.I), 70),
        ],
    },
    {
        "vendor": "Akamai",
        "header_patterns": [
            (re.compile(r"^x-akamai-", re.I), None, 80),
            (re.compile(r"^akamai-", re.I), None, 80),
            (re.compile(r"^x-check-cacheable$", re.I), None, 40),
            (re.compile(r"^server$", re.I), re.compile(r"akamaighost", re.I), 80),
            (re.compile(r"^server-timing$", re.I), re.compile(r"\bak_p\b", re.I), 80),
            (re.compile(r"^server-timing$", re.I), re.compile(r"\bedge\b", re.I), 30),
        ],
        "cookie_patterns": [
            (re.compile(r"^ak_bmsc$", re.I), 80),
            (re.compile(r"^bm_sz$", re.I), 70),
            (re.compile(r"^bm_mi$", re.I), 70),
            (re.compile(r"^_abck$", re.I), 70),
        ],
        "body_patterns": [
            (re.compile(r"akstat\.io", re.I), 60),
            (re.compile(r"go-mpulse\.net", re.I), 60),
            (re.compile(r"akamaized\.net", re.I), 50),
            (re.compile(r"akamai", re.I), 40),
        ],
    },
    {
        "vendor": "Imperva/Incapsula",
        "header_patterns": [
            (re.compile(r"^x-iinfo$", re.I), None, 80),
            (re.compile(r"^x-cdn$", re.I), re.compile(r"incapsula", re.I), 80),
        ],
        "cookie_patterns": [
            (re.compile(r"^visid_incap_", re.I), 80),
            (re.compile(r"^incap_ses_", re.I), 80),
            (re.compile(r"^nlbi_", re.I), 60),
            (re.compile(r"^reese84$", re.I), 50),
        ],
        "body_patterns": [
            (re.compile(r"incapsula", re.I), 70),
            (re.compile(r"imperva", re.I), 60),
        ],
    },
    {
        "vendor": "F5 BIG-IP",
        "header_patterns": [
            (re.compile(r"^x-wa-info$", re.I), None, 80),
            (re.compile(r"^x-cnection$", re.I), None, 60),
        ],
        "cookie_patterns": [
            (re.compile(r"^TS[0-9a-f]{8}$", re.I), 80),
            (re.compile(r"^TS01", re.I), 70),
            (re.compile(r"^BIGipServer", re.I), 80),
        ],
        "body_patterns": [
            (re.compile(r"BIG-IP", re.I), 60),
        ],
    },
    {
        "vendor": "Barracuda",
        "header_patterns": [
            (re.compile(r"^x-barracuda-", re.I), None, 80),
        ],
        "cookie_patterns": [
            (re.compile(r"^barra_counter_session$", re.I), 80),
        ],
        "body_patterns": [
            (re.compile(r"barracuda", re.I), 60),
        ],
    },
    {
        "vendor": "ModSecurity",
        "header_patterns": [
            (re.compile(r"^x-mod-security$", re.I), None, 80),
        ],
        "cookie_patterns": [],
        "body_patterns": [
            (re.compile(r"modsecurity", re.I), 80),
            (re.compile(r"mod_security", re.I), 80),
        ],
    },
    {
        "vendor": "Sucuri",
        "header_patterns": [
            (re.compile(r"^x-sucuri-id$", re.I), None, 80),
            (re.compile(r"^x-sucuri-cache$", re.I), None, 80),
        ],
        "cookie_patterns": [
            (re.compile(r"^sucuri_cloudproxy_uuid$", re.I), 80),
        ],
        "body_patterns": [
            (re.compile(r"sucuri", re.I), 70),
        ],
    },
    {
        "vendor": "Fastly",
        "header_patterns": [
            (re.compile(r"^fastly-", re.I), None, 80),
            (re.compile(r"^x-fastly-request-id$", re.I), None, 80),
            (re.compile(r"^x-served-by$", re.I), re.compile(r"cache-[a-z]{2}", re.I), 70),
            (re.compile(r"^via$", re.I), re.compile(r"varnish", re.I), 40),
        ],
        "cookie_patterns": [],
        "body_patterns": [
            (re.compile(r"fastly", re.I), 50),
        ],
    },
    {
        "vendor": "Azure Application Gateway",
        "header_patterns": [
            (re.compile(r"^x-ms-routing-name$", re.I), None, 80),
            (re.compile(r"^x-azure-ref$", re.I), None, 80),
        ],
        "cookie_patterns": [
            (re.compile(r"^ARRAffinity$", re.I), 70),
        ],
        "body_patterns": [
            (re.compile(r"application\s*gateway", re.I), 70),
        ],
    },
    {
        "vendor": "Amazon CloudFront",
        "header_patterns": [
            (re.compile(r"^x-amz-cf-pop$", re.I), None, 80),
            (re.compile(r"^x-amz-cf-id$", re.I), None, 70),
            (re.compile(r"^via$", re.I), re.compile(r"CloudFront", re.I), 80),
        ],
        "cookie_patterns": [],
        "body_patterns": [
            (re.compile(r"CloudFront", re.I), 60),
        ],
    },
    # ── NEW VENDORS ──────────────────────────────────────────────────────────
    {
        "vendor": "Fortinet FortiWeb",
        "header_patterns": [
            (re.compile(r"^x-forwarded-fortiweb$", re.I), None, 80),
        ],
        "cookie_patterns": [],
        "body_patterns": [
            (re.compile(r"fortigate", re.I), 70),
            (re.compile(r"fortiweb", re.I), 80),
        ],
    },
    {
        "vendor": "Wallarm",
        "header_patterns": [
            (re.compile(r"^x-wallarm-", re.I), None, 80),
        ],
        "cookie_patterns": [
            (re.compile(r"^wallarm_", re.I), 80),
        ],
        "body_patterns": [],
    },
    {
        "vendor": "Google Cloud Armor",
        "header_patterns": [
            (re.compile(r"^x-cloud-trace-context$", re.I), None, 50),
            (re.compile(r"^via$", re.I), re.compile(r"google", re.I), 60),
        ],
        "cookie_patterns": [],
        "body_patterns": [
            (re.compile(r"google armor", re.I), 80),
        ],
    },
    {
        "vendor": "GCP Load Balancer",
        "header_patterns": [
            (re.compile(r"^x-google-", re.I), None, 70),
        ],
        "cookie_patterns": [],
        "body_patterns": [
            (re.compile(r"google load balancer", re.I), 80),
        ],
    },
    {
        "vendor": "Radware",
        "header_patterns": [],
        "cookie_patterns": [
            (re.compile(r"^st8id$", re.I), 70),
            (re.compile(r"^st8_wl$", re.I), 70),
        ],
        "body_patterns": [
            (re.compile(r"radware", re.I), 70),
        ],
    },
    {
        "vendor": "Sophos UTM",
        "header_patterns": [],
        "cookie_patterns": [],
        "body_patterns": [
            (re.compile(r"sophos", re.I), 70),
            (re.compile(r"astaro", re.I), 60),
        ],
    },
    {
        "vendor": "Citrix ADC/NetScaler",
        "header_patterns": [
            (re.compile(r"^citrix-", re.I), None, 80),
        ],
        "cookie_patterns": [
            (re.compile(r"^NSC_", re.I), 80),
        ],
        "body_patterns": [
            (re.compile(r"citrix netscaler", re.I), 80),
        ],
    },
    {
        "vendor": "Palo Alto",
        "header_patterns": [
            (re.compile(r"^x-pan-", re.I), None, 80),
        ],
        "cookie_patterns": [],
        "body_patterns": [
            (re.compile(r"pan-os", re.I), 80),
        ],
    },
    {
        "vendor": "Nginx + ModSecurity",
        "header_patterns": [],
        "cookie_patterns": [],
        "body_patterns": [
            # Both patterns must match; handled via combined check below
            (re.compile(r"nginx.*modsecurity|modsecurity.*nginx", re.I), 60),
        ],
    },
    {
        "vendor": "Varnish Cache",
        "header_patterns": [
            (re.compile(r"^x-varnish$", re.I), None, 80),
            (re.compile(r"^via$", re.I), re.compile(r"varnish", re.I), 70),
        ],
        "cookie_patterns": [],
        "body_patterns": [],
    },
    {
        "vendor": "Netlify",
        "header_patterns": [
            (re.compile(r"^x-nf-", re.I), None, 80),
            (re.compile(r"^x-nf-request-id$", re.I), None, 80),
        ],
        "cookie_patterns": [],
        "body_patterns": [],
    },
    {
        "vendor": "Vercel",
        "header_patterns": [
            (re.compile(r"^x-vercel-", re.I), None, 80),
            (re.compile(r"^x-deployment-id$", re.I), None, 70),
        ],
        "cookie_patterns": [],
        "body_patterns": [],
    },
    {
        "vendor": "HAProxy",
        "header_patterns": [],
        "cookie_patterns": [
            (re.compile(r"^SERVERID$", re.I), 60),
        ],
        "body_patterns": [
            (re.compile(r"haproxy", re.I), 70),
        ],
    },
]


def _score_response(
    normal_resp: httpx.Response | None,
    malicious_resp: httpx.Response | None,
) -> dict:
    """Score responses against WAF signatures with per-pattern weights."""
    indicators: list[str] = []
    vendor_scores: dict[str, int] = {}

    def _check_response(resp: httpx.Response, label: str) -> None:
        headers = dict(resp.headers)
        cookies = {k: v for k, v in resp.cookies.items()}
        raw_cookie_header = " ".join(
            v for k, v in resp.headers.multi_items() if k.lower() == "set-cookie"
        )
        body = ""
        try:
            body = resp.text[:60000]
        except Exception:
            pass

        for sig in WAF_SIGNATURES:
            v = sig["vendor"]
            score = 0

            for hdr_rx, val_rx, pts in sig.get("header_patterns", []):
                for hdr_name, hdr_val in headers.items():
                    if hdr_rx.match(hdr_name):
                        if val_rx is None or val_rx.search(str(hdr_val)):
                            score += pts
                            indicators.append(
                                f"[{label}] {v}: header '{hdr_name}' matched (+{pts})"
                            )
                            break

            for ck_rx, pts in sig.get("cookie_patterns", []):
                matched = any(ck_rx.match(ck) for ck in cookies)
                if not matched:
                    matched = bool(ck_rx.search(raw_cookie_header))
                if matched:
                    score += pts
                    indicators.append(f"[{label}] {v}: cookie pattern matched (+{pts})")

            for body_rx, pts in sig.get("body_patterns", []):
                if body_rx.search(body):
                    score += pts
                    indicators.append(
                        f"[{label}] {v}: body '{body_rx.pattern}' matched (+{pts})"
                    )

            if score > 0:
                vendor_scores[v] = vendor_scores.get(v, 0) + score

    if normal_resp is not None:
        _check_response(normal_resp, "normal")
    if malicious_resp is not None:
        _check_response(malicious_resp, "malicious")

    blocked_malicious = False
    if (
        normal_resp is not None
        and malicious_resp is not None
        and normal_resp.status_code in (200, 301, 302)
        and malicious_resp.status_code in (403, 406, 429, 503)
    ):
        blocked_malicious = True
        if not vendor_scores:
            vendor_scores["Generic WAF"] = 40
            indicators.append(
                f"[generic] Malicious payload blocked ({malicious_resp.status_code}) "
                f"but normal request succeeded ({normal_resp.status_code}) (+40)"
            )

    best_vendor: str | None = None
    confidence = 0
    if vendor_scores:
        best_vendor = max(vendor_scores, key=lambda k: vendor_scores[k])
        confidence = min(100, vendor_scores[best_vendor])

    return {
        "detected": bool(vendor_scores),
        "vendor": best_vendor,
        "confidence": confidence,
        "vendor_scores": vendor_scores,
        "indicators": indicators,
        "blocked_malicious": blocked_malicious,
        "response_codes": {
            "normal": normal_resp.status_code if normal_resp else None,
            "malicious": malicious_resp.status_code if malicious_resp else None,
        },
    }


# ── Pydantic models ───────────────────────────────────────────────────────────

def _normalize_url(v: str) -> str:
    v = v.strip()
    if not v:
        raise ValueError("Target is required")
    if re.search(r"[;&|`$(){}<>]", v):
        raise ValueError("Target contains invalid characters")
    if not re.match(r"^https?://", v, re.I):
        v = "https://" + v
    return v


class WafDetectRequest(BaseModel):
    target: str
    depth: str = "full"

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        return _normalize_url(v)

    @field_validator("depth")
    @classmethod
    def validate_depth(cls, v: str) -> str:
        if v not in ("quick", "full"):
            raise ValueError("depth must be 'quick' or 'full'")
        return v


class WafBypassRequest(BaseModel):
    target: str
    path: str = "/"
    param: str = "q"
    categories: list[str] | None = None
    cloud_profile: str = "auto"
    waf_detected_vendor: str | None = None

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        return _normalize_url(v)

    @field_validator("path")
    @classmethod
    def validate_path(cls, v: str) -> str:
        v = v.strip()
        if re.search(r"[;&|`$(){}<>]", v):
            raise ValueError("Path contains invalid characters")
        return v

    @field_validator("param")
    @classmethod
    def validate_param(cls, v: str) -> str:
        v = v.strip()
        if re.search(r"[;&|`$(){}<>\s]", v):
            raise ValueError("Param contains invalid characters")
        return v


class PortFirewallRequest(BaseModel):
    target: str
    mode: str = "acl_probe"

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Target is required")
        if re.search(r"[;&|`$(){}<>]", v):
            raise ValueError("Target contains invalid characters")
        return v

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        allowed = {
            "acl_probe", "fin_null_xmas", "source_port", "fragmented", "full_suite",
            "service_version", "decoy_scan", "udp_scan",
        }
        if v not in allowed:
            raise ValueError(f"Mode must be one of: {', '.join(sorted(allowed))}")
        return v


class RateLimitRequest(BaseModel):
    target: str
    path: str = "/"
    max_rps: int = 50

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        return _normalize_url(v)

    @field_validator("max_rps")
    @classmethod
    def validate_rps(cls, v: int) -> int:
        if not 1 <= v <= 200:
            raise ValueError("max_rps must be between 1 and 200")
        return v


class SmugglingRequest(BaseModel):
    target: str

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        return _normalize_url(v)


# ── Module 1: WAF Detection (multi-vector) ────────────────────────────────────

def _extract_server_version(headers: dict) -> str | None:
    """Extract version string from Server header."""
    server = headers.get("server") or headers.get("Server") or ""
    if server:
        return server.strip() or None
    return None


def _fingerprint_body_phase3(body: str, status_code: int) -> list[str]:
    """Phase 3 body fingerprinting for non-2xx responses."""
    signals = []
    if status_code >= 300:
        body_lower = body.lower()
        if "ray id" in body_lower or "cloudflare" in body_lower:
            signals.append("body:cloudflare_block_page")
        if "request id:" in body_lower:
            signals.append("body:aws_waf_block_page")
        if "reference #" in body_lower:
            signals.append("body:akamai_block_page")
        if "access denied" in body_lower:
            signals.append("body:generic_access_denied")
        if "blocked" in body_lower:
            signals.append("body:generic_blocked")
        if "forbidden" in body_lower:
            signals.append("body:generic_forbidden")
    return signals


@router.post("/waf/detect", summary="Detect WAF presence and vendor")
async def detect_waf(
    payload: WafDetectRequest,
    request: Request,
    current_user: Annotated[User, Depends(require_tool("firewall"))],
    org_id: uuid.UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    scan_id = str(uuid.uuid4())

    log = AuditLog(
        org_id=org_id,
        user_id=current_user.id,
        action="tool.firewall.waf_detect",
        resource_type="firewall_scan",
        resource_id=scan_id,
        after_state={"target": payload.target},
        ip_address=request.client.host if request.client else None,
    )
    db.add(log)
    await db.commit()

    if payload.depth == "quick":
        # Quick mode: original behavior
        malicious_param = "?id=1%27%20OR%20%271%27%3D%271"
        normal_url = payload.target
        malicious_url = payload.target.rstrip("/") + "/" + malicious_param

        normal_resp: httpx.Response | None = None
        malicious_resp: httpx.Response | None = None

        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15) as client:
            try:
                normal_resp = await client.get(normal_url)
            except Exception:
                pass
            try:
                malicious_resp = await client.get(malicious_url)
            except Exception:
                pass

        result = _score_response(normal_resp, malicious_resp)
        result["scan_id"] = scan_id
        result["target"] = payload.target
        result["depth"] = "quick"
        result["timestamp"] = datetime.now(timezone.utc).isoformat()
        result["phase_count"] = 1
        result["probes_sent"] = 2
        result["server_version"] = _extract_server_version(dict(normal_resp.headers) if normal_resp else {})
        result["evidence_matrix"] = {"phase1_quick": result.get("indicators", [])}

        _scan_history[scan_id] = {
            "id": scan_id,
            "type": "waf_detect",
            "target": payload.target,
            "status": "completed",
            "started_at": result["timestamp"],
            "completed_at": result["timestamp"],
            "result": result,
        }
        return JSONResponse(content=result)

    # Full multi-phase detection
    base = payload.target.rstrip("/")
    evidence_matrix: dict[str, list[str]] = {}
    all_responses: list[tuple[str, httpx.Response | None]] = []
    probes_sent = 0

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15) as client:
        # Phase 1 — passive header harvest (3 concurrent requests)
        async def _safe_get(url: str, method: str = "GET", **kwargs):
            try:
                if method == "OPTIONS":
                    return await client.options(url, **kwargs)
                return await client.get(url, **kwargs)
            except Exception:
                return None

        p1_normal, p1_404, p1_options = await asyncio.gather(
            _safe_get(base + "/"),
            _safe_get(base + "/this-path-does-not-exist-probe-xyz123"),
            _safe_get(base + "/", method="OPTIONS"),
        )
        probes_sent += 3
        phase1_indicators: list[str] = []

        for label, resp in [("normal", p1_normal), ("404_probe", p1_404), ("options", p1_options)]:
            if resp is not None:
                all_responses.append((label, resp))
                partial = _score_response(resp, None)
                phase1_indicators.extend(
                    f"[phase1/{label}] {ind}" for ind in partial.get("indicators", [])
                )
        evidence_matrix["phase1_headers"] = phase1_indicators

        # Phase 2 — 5-class attack probes (concurrent)
        attack_urls = [
            ("sqli",     base + "/?id=1' OR 1=1--"),
            ("xss",      base + "/?q=<script>alert(1)</script>"),
            ("traversal", base + "/../../etc/passwd"),
            ("ssrf",     base + "/?url=http://169.254.169.254/"),
            ("cmdinj",   base + "/?cmd=;cat /etc/passwd"),
        ]
        attack_resps = await asyncio.gather(
            *[_safe_get(url) for _, url in attack_urls],
            return_exceptions=False,
        )
        probes_sent += 5

        phase2_indicators: list[str] = []
        for (label, _url), resp in zip(attack_urls, attack_resps):
            if resp is not None:
                all_responses.append((f"attack_{label}", resp))
                partial = _score_response(None, resp)
                phase2_indicators.extend(
                    f"[phase2/{label}] {ind}" for ind in partial.get("indicators", [])
                )
        evidence_matrix["phase2_probes"] = phase2_indicators

        # Phase 3 — error page body fingerprinting
        phase3_indicators: list[str] = []
        for label, resp in all_responses:
            if resp is not None and resp.status_code not in (200, 301, 302):
                try:
                    body = resp.text[:2000]
                except Exception:
                    body = ""
                sigs = _fingerprint_body_phase3(body, resp.status_code)
                phase3_indicators.extend(f"[phase3/{label}/{resp.status_code}] {s}" for s in sigs)
        evidence_matrix["phase3_body_fingerprint"] = phase3_indicators

        # Phase 4 — version extraction
        server_version: str | None = None
        for _, resp in all_responses:
            if resp is not None:
                sv = _extract_server_version(dict(resp.headers))
                if sv:
                    server_version = sv
                    break
        phase4_indicators = [f"server_version:{server_version}"] if server_version else []
        evidence_matrix["phase4_version"] = phase4_indicators

    # Aggregate scoring across all responses
    combined_vendor_scores: dict[str, int] = {}
    combined_indicators: list[str] = []
    blocked_malicious = False

    normal_r = p1_normal
    for label, resp in all_responses:
        if "attack" in label and resp is not None:
            partial = _score_response(normal_r, resp)
            for v, s in partial.get("vendor_scores", {}).items():
                combined_vendor_scores[v] = combined_vendor_scores.get(v, 0) + s
            combined_indicators.extend(partial.get("indicators", []))
            if partial.get("blocked_malicious"):
                blocked_malicious = True

    # Also score from phase 1 passive
    if normal_r is not None:
        partial = _score_response(normal_r, None)
        for v, s in partial.get("vendor_scores", {}).items():
            combined_vendor_scores[v] = combined_vendor_scores.get(v, 0) + s
        combined_indicators.extend(partial.get("indicators", []))

    # Body fingerprint vendor scoring
    for ind in phase3_indicators:
        if "cloudflare" in ind:
            combined_vendor_scores["Cloudflare"] = combined_vendor_scores.get("Cloudflare", 0) + 30
        elif "aws_waf" in ind:
            combined_vendor_scores["AWS WAF"] = combined_vendor_scores.get("AWS WAF", 0) + 30
        elif "akamai" in ind:
            combined_vendor_scores["Akamai"] = combined_vendor_scores.get("Akamai", 0) + 30

    # Bayesian normalization: cap at 95 if multiple phases confirm same vendor
    best_vendor: str | None = None
    confidence = 0
    if combined_vendor_scores:
        best_vendor = max(combined_vendor_scores, key=lambda k: combined_vendor_scores[k])
        raw_conf = min(100, combined_vendor_scores[best_vendor])
        # Count how many phases have evidence for best vendor
        phase_confirmations = sum(
            1 for phase_inds in evidence_matrix.values()
            if any(best_vendor.lower().split("/")[0].split(" ")[0] in i.lower() for i in phase_inds)
        )
        if phase_confirmations >= 2:
            confidence = min(95, raw_conf)
        else:
            confidence = raw_conf

    timestamp = datetime.now(timezone.utc).isoformat()
    result = {
        "scan_id": scan_id,
        "target": payload.target,
        "depth": "full",
        "detected": bool(combined_vendor_scores),
        "vendor": best_vendor,
        "confidence": confidence,
        "vendor_scores": combined_vendor_scores,
        "indicators": combined_indicators,
        "blocked_malicious": blocked_malicious,
        "server_version": server_version,
        "evidence_matrix": evidence_matrix,
        "phase_count": 4,
        "probes_sent": probes_sent,
        "timestamp": timestamp,
        "response_codes": {
            "normal": p1_normal.status_code if p1_normal else None,
        },
    }

    _scan_history[scan_id] = {
        "id": scan_id,
        "type": "waf_detect",
        "target": payload.target,
        "status": "completed",
        "started_at": timestamp,
        "completed_at": timestamp,
        "result": result,
    }

    return JSONResponse(content=result)


# ── Module 2: WAF Bypass Probe ────────────────────────────────────────────────

BYPASS_PROBES: list[dict] = [
    # sqli
    {"technique": "baseline_sqli",       "payload": "' OR 1=1--",                 "method": "get_param", "category": "sqli",    "description": "Baseline SQL injection"},
    {"technique": "url_encoded_sqli",    "payload": "%27%20OR%201%3D1--",         "method": "get_param", "category": "sqli",    "description": "URL-encoded SQL injection"},
    {"technique": "double_encoded_sqli", "payload": "%2527%2520OR%25201%253D1--", "method": "get_param", "category": "sqli",    "description": "Double URL-encoded SQL injection"},
    {"technique": "unicode_escape_sqli", "payload": "\\u0027 OR 1=1--",           "method": "get_param", "category": "sqli",    "description": "Unicode escape SQL injection"},
    {"technique": "case_mutation_sqli1", "payload": "' oR 1=1--",                 "method": "get_param", "category": "sqli",    "description": "Case mutation SQL injection (oR)"},
    {"technique": "case_mutation_sqli2", "payload": "' Or 1=1--",                 "method": "get_param", "category": "sqli",    "description": "Case mutation SQL injection (Or)"},
    {"technique": "comment_injection",   "payload": "'/**/OR/**/1=1--",            "method": "get_param", "category": "sqli",    "description": "Comment injection SQL bypass"},
    {"technique": "null_byte_sqli",      "payload": "'\x00 OR 1=1--",             "method": "get_param", "category": "sqli",    "description": "Null byte SQL injection"},
    {"technique": "sqli_unicode_normalization", "payload": "\u02BC OR 1=1--",     "method": "get_param", "category": "sqli",    "description": "Unicode apostrophe normalization bypass"},
    {"technique": "sqli_html_entity",   "payload": "&#39; OR 1=1--",              "method": "get_param", "category": "sqli",    "description": "HTML entity encoded quote"},
    # xss
    {"technique": "xss_baseline",       "payload": "<script>alert(1)</script>",   "method": "get_param", "category": "xss",     "description": "Baseline XSS"},
    {"technique": "xss_encoded",        "payload": "%3Cscript%3Ealert(1)%3C/script%3E", "method": "get_param", "category": "xss", "description": "URL-encoded XSS"},
    {"technique": "xss_case_mutation",  "payload": "<ScRiPt>alert(1)</ScRiPt>",   "method": "get_param", "category": "xss",     "description": "Case-mutated XSS tag"},
    {"technique": "xss_tag_variant",    "payload": "<img src=x onerror=alert(1)>","method": "get_param", "category": "xss",     "description": "IMG onerror XSS variant"},
    {"technique": "xss_utf7",           "payload": "+ADw-script+AD4-alert(1)+ADw-/script+AD4-", "method": "get_param", "category": "xss", "description": "UTF-7 encoded XSS"},
    {"technique": "xss_dom_variant",    "payload": '"><img src=x onerror=alert(document.domain)>', "method": "get_param", "category": "xss", "description": "DOM-based XSS variant"},
    # encoding
    {"technique": "double_url_encode",  "payload": "%2527%2520OR%25201%253D1--",  "method": "get_param", "category": "encoding","description": "Double URL encoding"},
    {"technique": "unicode_fullwidth",  "payload": "\uff05\uff12\uff17 OR 1=1--", "method": "get_param", "category": "encoding","description": "Unicode fullwidth characters"},
    {"technique": "html_entity_sqli",   "payload": "&apos; OR 1=1--",             "method": "get_param", "category": "encoding","description": "HTML entity encoding"},
    {"technique": "null_byte_mid",      "payload": "'\x00 OR 1=1--",              "method": "get_param", "category": "encoding","description": "Null byte mid-payload injection"},
    # verb_mutation
    {"technique": "post_form_sqli",     "payload": "' OR 1=1--",                  "method": "post_form",      "category": "verb_mutation", "description": "POST form-encoded SQL injection", "header_name": None},
    {"technique": "post_json_sqli",     "payload": "' OR 1=1--",                  "method": "post_json",      "category": "verb_mutation", "description": "POST JSON body SQL injection",    "header_name": None},
    {"technique": "post_xml_sqli",      "payload": "' OR 1=1--",                  "method": "post_xml",       "category": "verb_mutation", "description": "POST XML CDATA SQL injection",    "header_name": None},
    {"technique": "put_sqli",           "payload": "' OR 1=1--",                  "method": "get_param",      "category": "verb_mutation", "description": "PUT request with payload",         "header_name": None},
    {"technique": "trace_xst",          "payload": "TRACE",                       "method": "get_param",      "category": "verb_mutation", "description": "TRACE method (XST detection)",     "header_name": None},
    # content_type
    {"technique": "multipart_sqli",     "payload": "' OR 1=1--",                  "method": "post_multipart", "category": "content_type",  "description": "Multipart/form-data SQL injection", "header_name": None},
    {"technique": "malformed_boundary", "payload": "' OR 1=1--",                  "method": "post_multipart", "category": "content_type",  "description": "Malformed multipart boundary",      "header_name": None},
    {"technique": "ct_confusion",       "payload": "' OR 1=1--",                  "method": "post_form",      "category": "content_type",  "description": "Content-type confusion (JSON CT, form body)", "header_name": None},
    {"technique": "xxe_payload",        "payload": "<?xml version=\"1.0\"?><!DOCTYPE test [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>", "method": "post_xml", "category": "content_type", "description": "XXE payload via XML body", "header_name": None},
    {"technique": "ibm037_charset",     "payload": "' OR 1=1--",                  "method": "post_form",      "category": "content_type",  "description": "POST with charset=ibm037",          "header_name": None},
    {"technique": "json_ct_form_body",  "payload": "' OR 1=1--",                  "method": "post_form",      "category": "content_type",  "description": "JSON Content-Type with form body",   "header_name": None},
    # header_injection
    {"technique": "xff_spoof",          "payload": "127.0.0.1",                   "method": "header", "category": "header_injection", "description": "X-Forwarded-For IP spoofing bypass",    "header_name": "X-Forwarded-For"},
    {"technique": "x_originating_ip",  "payload": "127.0.0.1",                   "method": "header", "category": "header_injection", "description": "X-Originating-IP spoofing bypass",      "header_name": "X-Originating-IP"},
    {"technique": "true_client_ip",    "payload": "127.0.0.1",                   "method": "header", "category": "header_injection", "description": "True-Client-IP spoofing bypass",         "header_name": "True-Client-IP"},
    {"technique": "cf_connecting_ip",  "payload": "127.0.0.1",                   "method": "header", "category": "header_injection", "description": "CF-Connecting-IP spoofing bypass",       "header_name": "CF-Connecting-IP"},
    {"technique": "sqli_useragent",    "payload": "Mozilla/5.0 ' OR 1=1--",      "method": "header", "category": "header_injection", "description": "SQL injection in User-Agent header",     "header_name": "User-Agent"},
    {"technique": "sqli_referer",      "payload": "https://evil.com/' OR 1=1--", "method": "header", "category": "header_injection", "description": "SQL injection in Referer header",        "header_name": "Referer"},
]

# Fill in missing header_name keys for non-header probes
for _p in BYPASS_PROBES:
    if "header_name" not in _p:
        _p["header_name"] = None

BLOCKED_STATUSES = {403, 406, 429, 503}

# ── Cloud-specific bypass profiles ───────────────────────────────────────────

CLOUD_PROBES: dict[str, list[dict]] = {
    "cloudflare": [
        {
            "technique": "cf_body_size_bypass",
            "payload": "A" * 8192 + "' OR 1=1--",
            "method": "post_form",
            "category": "cloud_cloudflare",
            "description": "Cloudflare: oversized body bypass (inspection limit test)",
            "header_name": None,
        },
        {
            "technique": "cf_ip_spoof",
            "payload": "' OR 1=1--",
            "method": "header",
            "header_name": "CF-Connecting-IP",
            "category": "cloud_cloudflare",
            "description": "Cloudflare: CF-Connecting-IP spoofing bypass",
        },
        {
            "technique": "cf_true_client_ip",
            "payload": "' OR 1=1--",
            "method": "header",
            "header_name": "True-Client-IP",
            "category": "cloud_cloudflare",
            "description": "Cloudflare: True-Client-IP spoofing bypass",
        },
    ],
    "aws_waf": [
        {
            "technique": "aws_json_null_byte",
            "payload": '{"q": "test\u0000\' OR 1=1--"}',
            "method": "post_json",
            "category": "cloud_aws",
            "description": "AWS WAF: JSON null byte injection bypass",
            "header_name": None,
        },
        {
            "technique": "aws_oversized_json",
            "payload": "' OR 1=1--",
            "method": "post_json",
            "category": "cloud_aws",
            "description": "AWS WAF: oversized JSON body bypass (8KB padding)",
            "header_name": None,
        },
        {
            "technique": "aws_amz_content_type",
            "payload": "' OR 1=1--",
            "method": "post_form",
            "category": "cloud_aws",
            "description": "AWS WAF: application/x-amz-json-1.1 content type (often uninspected)",
            "header_name": None,
        },
    ],
    "azure_front_door": [
        {
            "technique": "azure_fdid",
            "payload": "' OR 1=1--",
            "method": "header",
            "header_name": "X-Azure-FDID",
            "category": "cloud_azure",
            "description": "Azure Front Door: FDID header bypass test",
        },
    ],
    "akamai": [
        {
            "technique": "akamai_crlf_encoding",
            "payload": "value\r\nContent-Encoding: gzip",
            "method": "header",
            "header_name": "X-Custom-Header",
            "category": "cloud_akamai",
            "description": "Akamai: CRLF injection via custom header (Praetorian 2024)",
        },
    ],
    "gcp_cloud_armor": [
        {
            "technique": "gcp_json_bypass",
            "payload": "' OR 1=1--",
            "method": "post_json",
            "category": "cloud_gcp",
            "description": "GCP Cloud Armor: JSON body bypass test",
            "header_name": None,
        },
    ],
}

# Vendor name → cloud profile key mapping for auto-detection
_VENDOR_TO_CLOUD_PROFILE: dict[str, str] = {
    "cloudflare": "cloudflare",
    "aws waf": "aws_waf",
    "amazon cloudfront": "aws_waf",
    "azure application gateway": "azure_front_door",
    "akamai": "akamai",
    "google cloud armor": "gcp_cloud_armor",
    "gcp load balancer": "gcp_cloud_armor",
}

# Remediation rules for bypass report
REMEDIATION_RULES: list[dict] = [
    {
        "category": "content_type",
        "threshold": 0.3,
        "priority": "critical",
        "action": "Enable deep inspection for all content types including multipart/form-data and JSON in your WAF",
        "rationale": "Content-type confusion bypasses indicate the WAF only inspects some content types",
    },
    {
        "category": "header_injection",
        "threshold": 0.3,
        "priority": "high",
        "action": "Validate and strip untrusted IP headers (X-Forwarded-For, True-Client-IP) at the WAF level",
        "rationale": "IP header injection can bypass IP-based rate limiting and geo-blocking",
    },
    {
        "category": "encoding",
        "threshold": 0.3,
        "priority": "high",
        "action": "Enable recursive URL decoding and Unicode normalization in WAF rules",
        "rationale": "Encoding bypass techniques exploit WAF parsers that only decode once",
    },
    {
        "category": "sqli",
        "threshold": 0.3,
        "priority": "high",
        "action": "Update WAF SQL injection ruleset to cover case mutation and comment injection patterns",
        "rationale": "SQLi variants bypass WAFs that use simple string matching without normalization",
    },
    {
        "category": "xss",
        "threshold": 0.3,
        "priority": "medium",
        "action": "Enable HTML entity decoding and case-insensitive XSS pattern matching in WAF rules",
        "rationale": "XSS variants exploit WAFs that match only canonical script tag forms",
    },
    {
        "category": "verb_mutation",
        "threshold": 0.2,
        "priority": "high",
        "action": "Ensure WAF inspects POST/PUT/PATCH request bodies, not only GET parameters",
        "rationale": "Verb mutation bypasses exploit WAFs that only inspect GET query parameters",
    },
]


async def _stream_bypass(
    scan_id: str,
    req: WafBypassRequest,
) -> AsyncGenerator[str, None]:
    started_at = datetime.now(timezone.utc).isoformat()

    # Build probe list
    probes = list(BYPASS_PROBES)

    # Apply cloud profile
    cloud_key: str | None = None
    if req.cloud_profile != "auto":
        cloud_key = req.cloud_profile
    elif req.waf_detected_vendor:
        vendor_lower = req.waf_detected_vendor.lower()
        for vendor_fragment, profile in _VENDOR_TO_CLOUD_PROFILE.items():
            if vendor_fragment in vendor_lower:
                cloud_key = profile
                break

    if cloud_key and cloud_key in CLOUD_PROBES:
        probes = probes + CLOUD_PROBES[cloud_key]

    # Apply category filter
    if req.categories:
        probes = [p for p in probes if p.get("category") in req.categories]

    _scan_history[scan_id] = {
        "id": scan_id,
        "type": "waf_bypass",
        "target": req.target,
        "path": req.path,
        "param": req.param,
        "status": "running",
        "started_at": started_at,
        "probes": [],
    }

    yield _sse("start", {
        "scan_id": scan_id,
        "target": req.target,
        "path": req.path,
        "param": req.param,
        "total_probes": len(probes),
        "timestamp": started_at,
    })

    base_url = req.target.rstrip("/") + req.path
    results: list[dict] = []

    async with httpx.AsyncClient(
        verify=False, follow_redirects=True, timeout=10
    ) as client:
        # Get baseline blocked body fingerprint
        blocked_body_fingerprint: str = ""
        try:
            baseline_resp = await client.get(f"{base_url}?{req.param}=1%27%20OR%201%3D1--")
            if baseline_resp.status_code in BLOCKED_STATUSES:
                try:
                    blocked_body_fingerprint = baseline_resp.text[:500]
                except Exception:
                    pass
        except Exception:
            pass

        for probe in probes:
            technique = probe["technique"]
            payload = probe["payload"]
            method = probe.get("method", "get_param")
            category = probe.get("category", "unknown")

            probe_status: int | None = None
            error: str | None = None
            resp_body: str = ""

            try:
                if method == "get_param":
                    url = f"{base_url}?{req.param}={payload}"
                    resp = await client.get(url)
                elif method == "post_form":
                    resp = await client.post(base_url, data={req.param: payload})
                elif method == "post_json":
                    resp = await client.post(base_url, json={req.param: payload})
                elif method == "post_xml":
                    resp = await client.post(
                        base_url,
                        content=f"<q><![CDATA[{payload}]]></q>",
                        headers={"Content-Type": "text/xml"},
                    )
                elif method == "post_multipart":
                    resp = await client.post(
                        base_url,
                        files={"file": ("test.txt", b"test")},
                        data={req.param: payload},
                    )
                elif method == "header":
                    header_name = probe.get("header_name") or "X-Forwarded-For"
                    resp = await client.get(base_url, headers={header_name: payload})
                else:
                    url = f"{base_url}?{req.param}={payload}"
                    resp = await client.get(url)

                probe_status = resp.status_code
                try:
                    resp_body = resp.text[:500]
                except Exception:
                    resp_body = ""
            except Exception as exc:
                error = str(exc)

            if error:
                result_label = "ERROR"
            elif probe_status in BLOCKED_STATUSES:
                result_label = "BLOCKED"
            elif probe_status == 200:
                result_label = "BYPASS"
                # Body similarity check: does the 200 look like the blocked page?
                if blocked_body_fingerprint and resp_body:
                    sim = difflib.SequenceMatcher(None, resp_body, blocked_body_fingerprint).ratio()
                    if sim > 0.8:
                        result_label = "UNCERTAIN"
            else:
                result_label = "UNCERTAIN"

            probe_result = {
                "technique": technique,
                "payload": payload,
                "status_code": probe_status,
                "result": result_label,
                "error": error,
                "category": category,
            }
            results.append(probe_result)

            yield _sse("probe", probe_result)
            await asyncio.sleep(0.05)

    bypass_count = sum(1 for r in results if r["result"] == "BYPASS")
    blocked_count = sum(1 for r in results if r["result"] == "BLOCKED")
    uncertain_count = sum(1 for r in results if r["result"] == "UNCERTAIN")

    # Compute bypass_rate_by_category
    category_stats: dict[str, dict] = {}
    for r in results:
        cat = r.get("category", "unknown")
        if cat not in category_stats:
            category_stats[cat] = {"bypass": 0, "total": 0}
        category_stats[cat]["total"] += 1
        if r["result"] == "BYPASS":
            category_stats[cat]["bypass"] += 1

    bypass_rate_by_category = {
        cat: (stats["bypass"] / stats["total"] if stats["total"] > 0 else 0.0)
        for cat, stats in category_stats.items()
    }

    completed_at = datetime.now(timezone.utc).isoformat()
    _scan_history[scan_id].update({
        "status": "completed",
        "completed_at": completed_at,
        "probes": results,
        "bypass_rate_by_category": bypass_rate_by_category,
    })

    yield _sse("complete", {
        "scan_id": scan_id,
        "target": req.target,
        "bypassed": bypass_count,
        "blocked": blocked_count,
        "uncertain": uncertain_count,
        "total": len(results),
        "probes": results,
        "bypass_rate_by_category": bypass_rate_by_category,
        "timestamp": completed_at,
    })


@router.post("/waf/bypass", summary="Probe WAF bypass techniques via SSE stream")
async def probe_waf_bypass(
    payload: WafBypassRequest,
    request: Request,
    current_user: Annotated[User, Depends(require_tool("firewall"))],
    org_id: uuid.UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    scan_id = str(uuid.uuid4())

    log = AuditLog(
        org_id=org_id,
        user_id=current_user.id,
        action="tool.firewall.waf_bypass",
        resource_type="firewall_scan",
        resource_id=scan_id,
        after_state={"target": payload.target, "path": payload.path, "param": payload.param},
        ip_address=request.client.host if request.client else None,
    )
    db.add(log)
    await db.commit()

    return StreamingResponse(
        _stream_bypass(scan_id, payload),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ── Module 2b: Bypass Report ──────────────────────────────────────────────────

@router.get("/bypass/report/{scan_id}", summary="Get bypass scan scorecard report")
async def get_bypass_report(
    scan_id: str,
    current_user: Annotated[User, Depends(require_tool("firewall"))],
) -> JSONResponse:
    entry = _scan_history.get(scan_id)
    if not entry:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    if entry.get("type") != "waf_bypass":
        raise HTTPException(status_code=400, detail="Scan is not a waf_bypass type")

    probes: list[dict] = entry.get("probes", [])
    total_probes = len(probes)
    bypassed_count = sum(1 for p in probes if p.get("result") == "BYPASS")
    bypass_rate = bypassed_count / total_probes if total_probes > 0 else 0.0

    # Compute by-category
    category_stats: dict[str, dict] = {}
    for r in probes:
        cat = r.get("category", "unknown")
        if cat not in category_stats:
            category_stats[cat] = {"bypass": 0, "total": 0}
        category_stats[cat]["total"] += 1
        if r.get("result") == "BYPASS":
            category_stats[cat]["bypass"] += 1

    bypass_rate_by_category = {
        cat: (stats["bypass"] / stats["total"] if stats["total"] > 0 else 0.0)
        for cat, stats in category_stats.items()
    }

    # Most effective technique (priority: content_type > header_injection > encoding > sqli > xss)
    category_priority = ["content_type", "header_injection", "encoding", "sqli", "xss"]
    most_effective_technique: str | None = None
    for cat in category_priority:
        for p in probes:
            if p.get("category") == cat and p.get("result") == "BYPASS":
                most_effective_technique = p.get("technique")
                break
        if most_effective_technique:
            break
    if not most_effective_technique:
        for p in probes:
            if p.get("result") == "BYPASS":
                most_effective_technique = p.get("technique")
                break

    # Overall risk
    if bypass_rate > 0.5:
        overall_risk = "Critical"
    elif bypass_rate > 0.3:
        overall_risk = "High"
    elif bypass_rate > 0.1:
        overall_risk = "Medium"
    else:
        overall_risk = "Low"

    # Remediation recommendations
    remediation_recommendations: list[dict] = []
    for rule in REMEDIATION_RULES:
        cat = rule["category"]
        cat_rate = bypass_rate_by_category.get(cat, 0.0)
        if cat_rate >= rule["threshold"]:
            remediation_recommendations.append({
                "priority": rule["priority"],
                "action": rule["action"],
                "rationale": rule["rationale"],
                "category": cat,
                "bypass_rate": round(cat_rate, 3),
            })

    return JSONResponse(content={
        "scan_id": scan_id,
        "target": entry.get("target", ""),
        "overall_risk": overall_risk,
        "bypass_rate": round(bypass_rate, 3),
        "bypass_rate_by_category": {k: round(v, 3) for k, v in bypass_rate_by_category.items()},
        "most_effective_technique": most_effective_technique,
        "total_probes": total_probes,
        "bypassed_count": bypassed_count,
        "remediation_recommendations": remediation_recommendations,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    })


# ── Module 3: Port Firewall Mapper ────────────────────────────────────────────

PORT_MAP_MODES: dict[str, dict] = {
    "acl_probe": {
        "flags": ["-sA", "-T4"],
        "label": "ACK Scan (stateful vs stateless detection)",
        "interpretation": {
            "unfiltered": "Port is unfiltered — no stateful firewall is blocking this port; ACK packet was allowed through.",
            "filtered": "Port is filtered — a stateful firewall is dropping ACK packets, indicating stateful inspection.",
            "default": "ACK scan response indicates intermediate or complex firewall behavior.",
        },
    },
    "fin_null_xmas": {
        "flags": ["-sF", "-T4"],
        "label": "FIN/NULL/XMAS Scan (bypass stateless filters)",
        "interpretation": {
            "open|filtered": "Port is open or filtered — stateless/no firewall present; FIN packet not blocked.",
            "filtered": "Port is filtered — stateful firewall blocks non-SYN packets; strong security posture.",
            "default": "Mixed firewall behavior detected.",
        },
    },
    "source_port": {
        "flags": ["--source-port", "53", "-sS", "-T4"],
        "label": "Source Port 53 Scan (trust-based ACL bypass test)",
        "interpretation": {
            "open": "Port opened when source port is 53 — firewall may trust DNS traffic; ACL bypass possible.",
            "filtered": "Port still filtered even with trusted source port — robust ACL in place.",
            "default": "Source-port trust rules could not be confirmed.",
        },
    },
    "fragmented": {
        "flags": ["-f", "--mtu", "8", "-T4"],
        "label": "Fragmented Packet Scan (evasion test)",
        "interpretation": {
            "open": "Port open with fragmented packets — firewall does not reassemble fragments before inspection.",
            "filtered": "Firewall reassembles and inspects fragmented packets; evasion unlikely.",
            "default": "Fragmentation behavior inconclusive.",
        },
    },
    "service_version": {
        "flags": ["-sV", "--version-intensity", "5", "--script=banner,http-headers", "-T4", "--open"],
        "label": "Service Version Detection (banner grabbing, HTTP headers)",
        "interpretation": {
            "open": "Service identified with version information.",
            "filtered": "Port filtered — service version cannot be determined.",
            "default": "Service detection result.",
        },
    },
    "decoy_scan": {
        "flags": ["-sS", "-D", "RND:5", "-T3"],
        "label": "Decoy Scan (IDS/firewall evasion test with random decoys)",
        "interpretation": {
            "open": "Port open — scan reached target despite decoys.",
            "filtered": "Port filtered.",
            "default": "Decoy scan result.",
        },
    },
    "udp_scan": {
        "flags": ["-sU", "--top-ports", "20", "-T4"],
        "label": "UDP Firewall Probe (top 20 UDP ports)",
        "interpretation": {
            "open": "UDP port open — firewall does not block this UDP service.",
            "open|filtered": "UDP port open or filtered — response ambiguous.",
            "filtered": "UDP port filtered — firewall blocks this UDP traffic.",
            "closed": "UDP port closed — service not running.",
            "default": "UDP firewall behavior noted.",
        },
    },
}

# CVE correlation map
PORT_CVE_MAP: dict[int, list[dict]] = {
    22: [
        {"cve": "CVE-2023-38408", "cvss": 9.8, "desc": "OpenSSH remote code execution via ssh-agent"},
        {"cve": "CVE-2023-51385", "cvss": 6.5, "desc": "OpenSSH command injection via user names"},
    ],
    80: [
        {"cve": "CVE-2021-41773", "cvss": 9.8, "desc": "Apache HTTP Server path traversal (2.4.49)"},
        {"cve": "CVE-2021-42013", "cvss": 9.8, "desc": "Apache HTTP Server path traversal (2.4.50)"},
    ],
    443: [
        {"cve": "CVE-2022-0778", "cvss": 7.5, "desc": "OpenSSL infinite loop via malformed cert"},
        {"cve": "CVE-2014-0160", "cvss": 7.5, "desc": "OpenSSL Heartbleed - TLS heartbeat extension"},
    ],
    3389: [
        {"cve": "CVE-2019-0708", "cvss": 9.8, "desc": "BlueKeep: RDP pre-auth RCE (Windows <2012)"},
        {"cve": "CVE-2023-28284", "cvss": 8.1, "desc": "Microsoft Remote Desktop RCE"},
    ],
    445: [
        {"cve": "CVE-2017-0144", "cvss": 9.3, "desc": "EternalBlue: SMB remote code execution"},
        {"cve": "CVE-2020-0796", "cvss": 10.0, "desc": "SMBGhost: SMB3 compression remote code execution"},
    ],
    3306: [
        {"cve": "CVE-2012-2122", "cvss": 5.1, "desc": "MySQL authentication bypass"},
        {"cve": "CVE-2023-21980", "cvss": 7.1, "desc": "MySQL Server privilege escalation"},
    ],
    5432: [
        {"cve": "CVE-2019-10164", "cvss": 8.8, "desc": "PostgreSQL stack overflow via SCRAM auth"},
        {"cve": "CVE-2023-2454", "cvss": 7.2, "desc": "PostgreSQL arbitrary code execution"},
    ],
    6379: [
        {"cve": "CVE-2022-0543", "cvss": 10.0, "desc": "Redis Lua sandbox escape (Debian/Ubuntu)"},
        {"cve": "CVE-2023-28425", "cvss": 7.5, "desc": "Redis integer overflow in LPOP/RPOP"},
    ],
    27017: [
        {"cve": "CVE-2021-20328", "cvss": 6.8, "desc": "MongoDB specific connection string injection"},
        {"cve": "CVE-2019-2389", "cvss": 6.1, "desc": "MongoDB log injection"},
    ],
    1433: [
        {"cve": "CVE-2020-0618", "cvss": 8.8, "desc": "Microsoft SQL Server RCE via SSRS"},
        {"cve": "CVE-2023-23375", "cvss": 7.8, "desc": "SQL Server ODBC driver RCE"},
    ],
    9200: [
        {"cve": "CVE-2021-22145", "cvss": 7.5, "desc": "Elasticsearch information disclosure via memory allocation"},
        {"cve": "CVE-2023-31419", "cvss": 7.5, "desc": "Elasticsearch StackOverflow via regex"},
    ],
    8080: [
        {"cve": "CVE-2022-42889", "cvss": 9.8, "desc": "Apache Commons Text StringSubstitutor RCE (Text4Shell)"},
    ],
    21: [
        {"cve": "CVE-2011-2523", "cvss": 10.0, "desc": "vsftpd 2.3.4 backdoor command execution"},
    ],
    23: [
        {"cve": "CVE-1999-0848", "cvss": 10.0, "desc": "Telnet cleartext credential transmission"},
    ],
    5900: [
        {"cve": "CVE-2022-47966", "cvss": 9.8, "desc": "VNC authentication bypass variants"},
    ],
}


def _parse_nmap_output(raw: str) -> list[dict]:
    """Parse nmap text output into structured host/port/service records."""
    hosts = []
    current_host: dict | None = None

    for line in raw.splitlines():
        line = line.strip()

        host_match = re.match(r"Nmap scan report for (.+)", line)
        if host_match:
            if current_host:
                hosts.append(current_host)
            current_host = {
                "host": host_match.group(1),
                "ports": [],
                "os": None,
                "status": "up",
            }
            continue

        if current_host is None:
            continue

        port_match = re.match(
            r"(\d+)/(tcp|udp)\s+(open|closed|filtered|unfiltered|open\|filtered)\s+(\S+)?\s*(.*)?",
            line,
        )
        if port_match:
            current_host["ports"].append(
                {
                    "port": int(port_match.group(1)),
                    "protocol": port_match.group(2),
                    "state": port_match.group(3),
                    "service": port_match.group(4) or "",
                    "version": port_match.group(5).strip() if port_match.group(5) else "",
                }
            )
            continue

        os_match = re.match(r"OS details: (.+)", line)
        if os_match and current_host:
            current_host["os"] = os_match.group(1)

    if current_host:
        hosts.append(current_host)

    return hosts


def _interpret_hosts(hosts: list[dict], mode: str) -> list[dict]:
    """Add firewall interpretation and CVE advisories to each port based on scan mode."""
    interp = PORT_MAP_MODES.get(mode, {}).get("interpretation", {})
    for host in hosts:
        for port in host.get("ports", []):
            state = port.get("state", "")
            message = interp.get(state) or interp.get("default", "")
            port["firewall_interpretation"] = message
            port_num = port.get("port")
            if isinstance(port_num, int) and port_num in PORT_CVE_MAP:
                port["cve_advisories"] = PORT_CVE_MAP[port_num]
            else:
                port["cve_advisories"] = []
    return hosts


async def _run_single_mode(
    nmap_bin: str,
    target: str,
    mode: str,
) -> tuple[list[dict], str, int]:
    """Run nmap for a single mode, return (hosts, raw_output, exit_code)."""
    flags = PORT_MAP_MODES[mode]["flags"]
    cmd = [nmap_bin] + flags + ["--system-dns", target]

    raw_lines: list[str] = []
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    assert proc.stdout is not None
    async for line_bytes in proc.stdout:
        raw_lines.append(line_bytes.decode("utf-8", errors="replace").rstrip())
    await proc.wait()

    raw = "\n".join(raw_lines)
    hosts = _parse_nmap_output(raw)
    hosts = _interpret_hosts(hosts, mode)
    return hosts, raw, proc.returncode or 0


# Modes that send raw packets — require root/sudo
_ROOT_REQUIRED_MODES = {"acl_probe", "fin_null_xmas", "fragmented", "decoy_scan", "udp_scan"}


def _can_run_raw_sockets() -> bool:
    import os, socket
    if os.geteuid() == 0:
        return True
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.close()
        return True
    except PermissionError:
        pass
    except Exception:
        pass
    return False


async def _nmap_prefix() -> list[str]:
    if _can_run_raw_sockets():
        return []
    nmap_bin = shutil.which("nmap") or "nmap"
    try:
        proc = await asyncio.create_subprocess_exec(
            "sudo", "-n", nmap_bin, "--version",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()
        if proc.returncode == 0:
            return ["sudo"]
    except Exception:
        pass
    return []


async def _stream_port_map(
    scan_id: str,
    req: PortFirewallRequest,
) -> AsyncGenerator[str, None]:
    nmap_bin = shutil.which("nmap") or "nmap"
    sudo_prefix = await _nmap_prefix()
    started_at = datetime.now(timezone.utc).isoformat()

    _scan_history[scan_id] = {
        "id": scan_id,
        "type": "port_map",
        "target": req.target,
        "mode": req.mode,
        "status": "running",
        "started_at": started_at,
        "modes_run": [],
        "all_hosts": [],
    }

    yield _sse("start", {
        "scan_id": scan_id,
        "target": req.target,
        "mode": req.mode,
        "timestamp": started_at,
    })

    modes_to_run = (
        list(PORT_MAP_MODES.keys()) if req.mode == "full_suite" else [req.mode]
    )

    all_hosts: list[dict] = []
    modes_run: list[dict] = []

    for mode in modes_to_run:
        mode_info = PORT_MAP_MODES[mode]
        flags = mode_info["flags"]

        needs_root = mode in _ROOT_REQUIRED_MODES
        prefix = sudo_prefix if needs_root else []

        if needs_root and not sudo_prefix:
            yield _sse("output", {
                "line": f"[{mode}] SKIPPED: This scan mode ({mode_info['label']}) requires "
                        f"root privileges. Run: sudo visudo and add nmap NOPASSWD, or run "
                        f"the server as root.",
            })
            modes_run.append({
                "mode": mode,
                "label": mode_info["label"],
                "exit_code": -1,
                "hosts": [],
                "skipped": True,
                "skip_reason": "root_required",
            })
            continue

        cmd_preview = " ".join(prefix + [nmap_bin] + flags + ["--system-dns", req.target])
        yield _sse("output", {
            "line": f"[{mode}] Running: {cmd_preview}",
        })

        cmd = prefix + [nmap_bin] + flags + ["--system-dns", req.target]
        raw_lines: list[str] = []

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            assert proc.stdout is not None
            async for line_bytes in proc.stdout:
                line = line_bytes.decode("utf-8", errors="replace").rstrip()
                raw_lines.append(line)
                if "requires root" in line or "QUITTING" in line:
                    yield _sse("output", {
                        "line": f"[{mode}] ERROR: {mode_info['label']} requires root/sudo. "
                                f"Configure passwordless sudo for nmap to enable this mode.",
                    })
                else:
                    yield _sse("output", {"line": f"[{mode}] {line}"})
                await asyncio.sleep(0)

            await proc.wait()
            exit_code = proc.returncode or 0
        except Exception as exc:
            yield _sse("output", {"line": f"[{mode}] ERROR: {exc}"})
            exit_code = 1
            raw_lines = []

        raw = "\n".join(raw_lines)
        hosts = _parse_nmap_output(raw)
        hosts = _interpret_hosts(hosts, mode)
        all_hosts.extend(hosts)

        mode_summary = {
            "mode": mode,
            "label": mode_info["label"],
            "exit_code": exit_code,
            "hosts": hosts,
        }
        modes_run.append(mode_summary)

    completed_at = datetime.now(timezone.utc).isoformat()
    _scan_history[scan_id].update({
        "status": "completed",
        "completed_at": completed_at,
        "modes_run": modes_run,
        "all_hosts": all_hosts,
    })

    yield _sse("complete", {
        "scan_id": scan_id,
        "target": req.target,
        "mode": req.mode,
        "modes_run": modes_run,
        "all_hosts": all_hosts,
        "timestamp": completed_at,
    })


@router.post("/port-map", summary="Port firewall mapper using nmap firewall-specific flags")
async def port_firewall_map(
    payload: PortFirewallRequest,
    request: Request,
    current_user: Annotated[User, Depends(require_tool("firewall"))],
    org_id: uuid.UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    if not shutil.which("nmap"):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="nmap is not installed on this server",
        )
    scan_id = str(uuid.uuid4())

    log = AuditLog(
        org_id=org_id,
        user_id=current_user.id,
        action="tool.firewall.port_map",
        resource_type="firewall_scan",
        resource_id=scan_id,
        after_state={"target": payload.target, "mode": payload.mode},
        ip_address=request.client.host if request.client else None,
    )
    db.add(log)
    await db.commit()

    return StreamingResponse(
        _stream_port_map(scan_id, payload),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ── Module 4: Rule Analyzer ───────────────────────────────────────────────────

SENSITIVE_PORTS = {22, 23, 3389, 5432, 3306, 1433, 27017, 6379, 9200, 5900, 445}


def _detect_format(content: str) -> str:
    """Detect firewall rule format from file content."""
    stripped = content.strip()
    # JSON detection first
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            import json as json_mod
            data = json_mod.loads(stripped)
            if isinstance(data, dict) and "SecurityGroups" in data:
                return "aws_sg_json"
            if isinstance(data, list):
                # list of SGs
                if any("SecurityGroups" in str(item)[:200] for item in data[:3]):
                    return "aws_sg_json"
            if "securityRules" in str(data)[:500]:
                return "azure_nsg_json"
        except Exception:
            pass

    if stripped.startswith("<?xml"):
        return "pfsense_xml"
    lines = [l.strip() for l in stripped.splitlines() if l.strip() and not l.strip().startswith("#")]
    for line in lines[:20]:
        if line.startswith("-A ") or line.startswith("iptables ") or line.startswith("-P "):
            return "iptables"
        if re.match(r"^(permit|deny)\s+(ip|tcp|udp|icmp)", line, re.I):
            return "cisco_acl"
    return "unknown"


def _parse_iptables(content: str) -> list[dict]:
    rules: list[dict] = []
    chain = "FILTER"
    line_num = 0
    for raw_line in content.splitlines():
        line_num += 1
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        chain_header = re.match(r"^:(\w+)\s+(ACCEPT|DROP|RETURN)", line)
        if chain_header:
            chain = chain_header.group(1)
            continue

        append_match = re.match(r"^-A\s+(\S+)\s+(.*)", line)
        if not append_match:
            continue
        chain = append_match.group(1)
        rest = append_match.group(2)

        action = "UNKNOWN"
        action_m = re.search(r"-j\s+(\S+)", rest)
        if action_m:
            action = action_m.group(1)

        proto = ""
        proto_m = re.search(r"-p\s+(\S+)", rest)
        if proto_m:
            proto = proto_m.group(1)

        src = "any"
        src_m = re.search(r"-s\s+(\S+)", rest)
        if src_m:
            src = src_m.group(1)

        dst = "any"
        dst_m = re.search(r"-d\s+(\S+)", rest)
        if dst_m:
            dst = dst_m.group(1)

        port = ""
        port_m = re.search(r"--dport\s+(\S+)", rest)
        if port_m:
            port = port_m.group(1)

        rules.append({
            "chain": chain,
            "action": action,
            "protocol": proto,
            "src": src,
            "dst": dst,
            "port": port,
            "line_num": line_num,
            "raw": line,
        })
    return rules


def _parse_cisco_acl(content: str) -> list[dict]:
    rules: list[dict] = []
    line_num = 0
    for raw_line in content.splitlines():
        line_num += 1
        line = raw_line.strip()
        if not line or line.startswith("!"):
            continue

        m = re.match(
            r"^(permit|deny)\s+(ip|tcp|udp|icmp)\s+(\S+)\s+(\S+)(?:\s+(\S+)\s+(\S+))?(?:\s+eq\s+(\d+))?",
            line, re.I,
        )
        if not m:
            continue

        rules.append({
            "chain": "ACL",
            "action": m.group(1).upper(),
            "protocol": m.group(2).lower(),
            "src": m.group(3),
            "dst": m.group(5) or m.group(4),
            "port": m.group(7) or "",
            "line_num": line_num,
            "raw": line,
        })
    return rules


def _parse_pfsense_xml(content: str) -> list[dict]:
    rules: list[dict] = []
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return rules

    line_num = 0
    for rule in root.iter("rule"):
        line_num += 1
        action_el = rule.find("type")
        action = action_el.text.upper() if action_el is not None and action_el.text else "UNKNOWN"

        proto_el = rule.find("protocol")
        proto = proto_el.text if proto_el is not None and proto_el.text else "any"

        src_el = rule.find("source/address")
        src = src_el.text if src_el is not None and src_el.text else "any"
        if src == "":
            src = "any"

        dst_el = rule.find("destination/address")
        dst = dst_el.text if dst_el is not None and dst_el.text else "any"
        if dst == "":
            dst = "any"

        port_el = rule.find("destination/port")
        port = port_el.text if port_el is not None and port_el.text else ""

        descr_el = rule.find("descr")
        raw = descr_el.text if descr_el is not None and descr_el.text else f"rule #{line_num}"

        rules.append({
            "chain": rule.find("interface").text if rule.find("interface") is not None else "WAN",
            "action": action,
            "protocol": proto,
            "src": src,
            "dst": dst,
            "port": port,
            "line_num": line_num,
            "raw": raw,
        })
    return rules


def _parse_aws_sg(content: str) -> list[dict]:
    """Parse AWS EC2 describe-security-groups JSON output."""
    rules: list[dict] = []
    try:
        import json as json_mod
        data = json_mod.loads(content)
    except Exception:
        return rules

    # Handle both {"SecurityGroups": [...]} and direct list
    sgs = data.get("SecurityGroups", []) if isinstance(data, dict) else data

    for sg in sgs:
        sg_name = sg.get("GroupName", "sg")
        for perm in sg.get("IpPermissions", []):
            protocol = perm.get("IpProtocol", "all")
            from_port = str(perm.get("FromPort", "any"))
            to_port = str(perm.get("ToPort", "any"))
            for ip_range in perm.get("IpRanges", []):
                cidr = ip_range.get("CidrIp", "any")
                port_str = from_port if from_port == to_port else f"{from_port}-{to_port}"
                rules.append({
                    "chain": sg_name,
                    "action": "PERMIT",
                    "protocol": protocol,
                    "src": cidr,
                    "dst": "any",
                    "port": port_str,
                    "line_num": len(rules) + 1,
                    "raw": f"sg permit {protocol} {cidr} port {from_port}-{to_port}",
                })
            # IPv6
            for ip_range in perm.get("Ipv6Ranges", []):
                cidr = ip_range.get("CidrIpv6", "any")
                port_str = from_port if from_port == to_port else f"{from_port}-{to_port}"
                rules.append({
                    "chain": sg_name,
                    "action": "PERMIT",
                    "protocol": protocol,
                    "src": cidr,
                    "dst": "any",
                    "port": port_str,
                    "line_num": len(rules) + 1,
                    "raw": f"sg permit {protocol} {cidr} port {from_port}-{to_port}",
                })
    return rules


def _parse_azure_nsg(content: str) -> list[dict]:
    """Parse Azure NSG JSON output from az network nsg show."""
    rules: list[dict] = []
    try:
        import json as json_mod
        data = json_mod.loads(content)
    except Exception:
        return rules

    security_rules = data.get("securityRules", [])
    if not security_rules and "properties" in data:
        security_rules = data["properties"].get("securityRules", [])

    for idx, rule in enumerate(security_rules):
        props = rule.get("properties", rule)
        access = props.get("access", "Allow").upper()
        action = "PERMIT" if access == "ALLOW" else "DENY"
        protocol = props.get("protocol", "*").lower()
        src = props.get("sourceAddressPrefix", "any")
        dst = props.get("destinationAddressPrefix", "any")
        port = props.get("destinationPortRange", "")
        name = rule.get("name", f"rule-{idx+1}")

        rules.append({
            "chain": data.get("name", "NSG"),
            "action": action,
            "protocol": protocol,
            "src": src,
            "dst": dst,
            "port": port,
            "line_num": idx + 1,
            "raw": f"nsg {action.lower()} {protocol} {src} -> {dst}:{port} ({name})",
        })
    return rules


def _cidr_subsumes(broad: str, specific: str) -> bool:
    """Check if broad CIDR contains specific CIDR/IP."""
    try:
        broad_net = ipaddress.ip_network(broad, strict=False)
        specific_net = ipaddress.ip_network(specific, strict=False)
        return broad_net.supernet_of(specific_net)
    except (ValueError, AttributeError):
        return False


def _is_any_source(src: str) -> bool:
    return src in ("any", "0.0.0.0/0", "0.0.0.0", "all", "::/0", "")


def _is_any_dest(dst: str) -> bool:
    return dst in ("any", "0.0.0.0/0", "0.0.0.0", "all", "::/0", "")


def _rule_signature(rule: dict) -> tuple:
    return (
        rule["chain"],
        rule["action"],
        rule["protocol"],
        rule["src"],
        rule["dst"],
        rule["port"],
    )


def _port_num(port_str: str) -> int | None:
    try:
        return int(port_str)
    except (ValueError, TypeError):
        return None


def _analyze_anomalies(rules: list[dict]) -> list[dict]:
    anomalies: list[dict] = []
    seen_sigs: dict[tuple, int] = {}

    permit_actions = {"ACCEPT", "PERMIT", "PASS", "ALLOW"}
    deny_actions = {"DROP", "DENY", "REJECT", "BLOCK"}

    for idx, rule in enumerate(rules):
        sig = _rule_signature(rule)

        # Redundant: exact duplicate
        if sig in seen_sigs:
            anomalies.append({
                "type": "redundant",
                "severity": "low",
                "rule_line": rule["line_num"],
                "description": (
                    f"Rule at line {rule['line_num']} is an exact duplicate of "
                    f"rule at line {rules[seen_sigs[sig]]['line_num']}."
                ),
                "rule_text": rule["raw"],
                "compliance": [],
            })
        else:
            seen_sigs[sig] = idx

        # Any-Any permit
        if (
            rule["action"] in permit_actions
            and _is_any_source(rule["src"])
            and _is_any_dest(rule["dst"])
            and rule["port"] in ("", "any", "all")
        ):
            anomalies.append({
                "type": "any_any",
                "severity": "critical",
                "rule_line": rule["line_num"],
                "description": (
                    "Rule permits ALL traffic from ANY source to ANY destination on ANY port. "
                    "This is an unrestricted allow rule."
                ),
                "rule_text": rule["raw"],
                "compliance": ["PCI-DSS-4.0-1.3.2", "CIS-12.2", "NIST-SP-800-41-3.3"],
            })

        # Overly broad: permit from 0.0.0.0/0 to sensitive ports
        if rule["action"] in permit_actions and _is_any_source(rule["src"]):
            p = _port_num(rule["port"])
            if p is not None and p in SENSITIVE_PORTS:
                anomalies.append({
                    "type": "overly_broad",
                    "severity": "high",
                    "rule_line": rule["line_num"],
                    "description": (
                        f"Rule permits connections from ANY source to sensitive port {p} "
                        f"({rule['protocol']}). This exposes a sensitive service publicly."
                    ),
                    "rule_text": rule["raw"],
                    "compliance": ["PCI-DSS-4.0-1.3.4", "CIS-12.3"],
                })

    # Shadow rules: later rule shadowed by earlier catch-all of same action
    for i, later in enumerate(rules):
        for earlier in rules[:i]:
            if earlier["chain"] != later["chain"]:
                continue
            if earlier["action"] != later["action"]:
                continue
            src_covers = _is_any_source(earlier["src"]) or earlier["src"] == later["src"]
            dst_covers = _is_any_dest(earlier["dst"]) or earlier["dst"] == later["dst"]
            port_covers = (
                earlier["port"] in ("", "any", "all")
                or earlier["port"] == later["port"]
            )
            proto_covers = (
                earlier["protocol"] in ("any", "all", "ip", "")
                or earlier["protocol"] == later["protocol"]
            )
            if (
                src_covers
                and dst_covers
                and port_covers
                and proto_covers
                and earlier["line_num"] != later["line_num"]
                and _rule_signature(earlier) != _rule_signature(later)
            ):
                anomalies.append({
                    "type": "shadow",
                    "severity": "medium",
                    "rule_line": later["line_num"],
                    "description": (
                        f"Rule at line {later['line_num']} is shadowed by rule at line "
                        f"{earlier['line_num']} — the earlier rule already matches all "
                        f"traffic that this rule would catch."
                    ),
                    "rule_text": later["raw"],
                    "compliance": ["CIS-12.4"],
                })
                break

    # CIDR subsumption check
    for i, rule in enumerate(rules):
        if rule["action"] not in permit_actions:
            continue
        for later in rules[i + 1:]:
            if later["chain"] != rule["chain"]:
                continue
            if later["action"] not in deny_actions:
                continue
            if (
                _cidr_subsumes(rule["src"], later["src"])
                or _cidr_subsumes(rule["dst"], later["dst"])
            ):
                anomalies.append({
                    "type": "cidr_subsumption",
                    "severity": "high",
                    "rule_line": later["line_num"],
                    "description": (
                        f"PERMIT rule at line {rule['line_num']} (src: {rule['src']}) "
                        f"covers a broader address space than the DENY rule at line "
                        f"{later['line_num']} (src: {later['src']}). The deny rule is unreachable."
                    ),
                    "rule_text": later["raw"],
                    "compliance": ["PCI-DSS-4.0-1.3.2", "CIS-12.2"],
                })

    # Conflicting rules
    for i, r1 in enumerate(rules):
        for r2 in rules[i + 1:]:
            if r1["chain"] != r2["chain"]:
                continue
            if r1["protocol"] != r2["protocol"] and "" not in (r1["protocol"], r2["protocol"]):
                continue
            if r1["src"] != r2["src"] or r1["dst"] != r2["dst"] or r1["port"] != r2["port"]:
                continue
            one_permit = r1["action"] in permit_actions and r2["action"] in deny_actions
            one_deny = r1["action"] in deny_actions and r2["action"] in permit_actions
            if one_permit or one_deny:
                anomalies.append({
                    "type": "conflict",
                    "severity": "high",
                    "rule_line": r2["line_num"],
                    "description": (
                        f"Rule at line {r2['line_num']} conflicts with rule at line "
                        f"{r1['line_num']}: one permits and the other denies the same traffic "
                        f"({r1['protocol']} {r1['src']} -> {r1['dst']}:{r1['port']})."
                    ),
                    "rule_text": r2["raw"],
                    "compliance": ["NIST-SP-800-41-3.2"],
                })

    # Missing default-deny check per chain
    chains = set(r["chain"] for r in rules)
    for chain in chains:
        chain_rules = [r for r in rules if r["chain"] == chain]
        if chain_rules:
            last_rule = chain_rules[-1]
            if last_rule["action"] not in deny_actions and last_rule["action"] not in ("RETURN", "LOG"):
                anomalies.append({
                    "type": "missing_default_deny",
                    "severity": "critical",
                    "rule_line": last_rule["line_num"],
                    "description": (
                        f"Chain '{chain}' does not end with a DENY/DROP all rule. "
                        f"All unmatched traffic will be PERMITTED by default."
                    ),
                    "rule_text": f"[Chain {chain} — no terminal deny rule found]",
                    "compliance": ["PCI-DSS-4.0-1.3.1", "NIST-SP-800-41", "CIS-12.1"],
                })

    return anomalies


@router.post("/rules/analyze", summary="Analyze firewall rule file for anomalies")
async def analyze_firewall_rules(
    request: Request,
    current_user: Annotated[User, Depends(require_tool("firewall"))],
    org_id: uuid.UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
    file: UploadFile = File(...),
) -> JSONResponse:
    allowed_extensions = {".txt", ".conf", ".xml", ".json"}
    filename = file.filename or ""
    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in allowed_extensions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file type '{ext}'. Allowed: {', '.join(sorted(allowed_extensions))}",
        )

    raw_bytes = await file.read()
    try:
        content = raw_bytes.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(status_code=400, detail="Could not decode file as UTF-8 text")

    if len(content) > 2_000_000:
        raise HTTPException(status_code=400, detail="File is too large (max 2 MB)")

    fmt = _detect_format(content)
    rules: list[dict] = []

    if fmt == "iptables":
        rules = _parse_iptables(content)
    elif fmt == "cisco_acl":
        rules = _parse_cisco_acl(content)
    elif fmt == "pfsense_xml":
        rules = _parse_pfsense_xml(content)
    elif fmt == "aws_sg_json":
        rules = _parse_aws_sg(content)
    elif fmt == "azure_nsg_json":
        rules = _parse_azure_nsg(content)
    else:
        # Attempt heuristic parse as iptables then cisco
        rules = _parse_iptables(content)
        if not rules:
            rules = _parse_cisco_acl(content)
        if not rules:
            raise HTTPException(
                status_code=400,
                detail="Could not detect or parse the firewall rule format. "
                       "Supported formats: iptables, Cisco ACL, pfSense XML, AWS SG JSON, Azure NSG JSON.",
            )

    anomalies = _analyze_anomalies(rules)

    scan_id = str(uuid.uuid4())
    log = AuditLog(
        org_id=org_id,
        user_id=current_user.id,
        action="tool.firewall.rules_analyze",
        resource_type="firewall_scan",
        resource_id=scan_id,
        after_state={"filename": filename, "format": fmt, "total_rules": len(rules)},
        ip_address=request.client.host if request.client else None,
    )
    db.add(log)
    await db.commit()

    result = {
        "scan_id": scan_id,
        "filename": filename,
        "format": fmt,
        "total_rules": len(rules),
        "anomalies": anomalies,
        "anomaly_count": len(anomalies),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    _scan_history[scan_id] = {
        "id": scan_id,
        "type": "rules_analyze",
        "filename": filename,
        "status": "completed",
        "started_at": result["timestamp"],
        "completed_at": result["timestamp"],
        "result": result,
    }

    return JSONResponse(content=result)


# ── Module 5: Rate Limit Probe ────────────────────────────────────────────────

async def _stream_rate_limit(
    scan_id: str,
    req: RateLimitRequest,
) -> AsyncGenerator[str, None]:
    started_at = datetime.now(timezone.utc).isoformat()
    target_url = req.target.rstrip("/") + req.path

    _scan_history[scan_id] = {
        "id": scan_id,
        "type": "rate_limit",
        "target": req.target,
        "status": "running",
        "started_at": started_at,
    }

    yield _sse("start", {
        "scan_id": scan_id,
        "target": req.target,
        "path": req.path,
        "max_rps": req.max_rps,
        "timestamp": started_at,
    })

    total_requests_sent = 0
    threshold_rps: int | None = None
    reset_window_seconds: int | None = None
    headers_exposed: list[str] = []
    bypass_vectors: list[str] = []
    bot_detection_type = "none"
    enforcement_type = "unknown"
    throttled_body = ""

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=10) as client:
        # Warm-up: 3 requests, record baseline timing
        warmup_times: list[float] = []
        rl_headers_seen: set[str] = set()

        for _ in range(3):
            try:
                t0 = asyncio.get_event_loop().time()
                resp = await client.get(target_url)
                elapsed = (asyncio.get_event_loop().time() - t0) * 1000
                warmup_times.append(elapsed)
                total_requests_sent += 1
                # Check for rate-limit headers
                for hdr in ("x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset", "retry-after"):
                    if hdr in {k.lower() for k in resp.headers.keys()}:
                        rl_headers_seen.add(hdr)
            except Exception:
                warmup_times.append(9999)

        baseline_ms = sum(warmup_times) / len(warmup_times) if warmup_times else 500.0
        headers_exposed = list(rl_headers_seen)

        yield _sse("baseline", {
            "baseline_ms": round(baseline_ms, 2),
            "warmup_requests": 3,
        })

        # Burst testing
        burst_sizes = [1, 5, 10, 20, 50, min(100, req.max_rps)]
        burst_sizes = sorted(set(b for b in burst_sizes if b <= req.max_rps))

        for burst_size in burst_sizes:
            async def _fire(url: str) -> tuple[int, float]:
                try:
                    t0 = asyncio.get_event_loop().time()
                    r = await client.get(url)
                    elapsed = (asyncio.get_event_loop().time() - t0) * 1000
                    return r.status_code, elapsed
                except Exception:
                    return 0, 9999.0

            results_burst = await asyncio.gather(*[_fire(target_url) for _ in range(burst_size)])
            total_requests_sent += burst_size

            status_counts: dict[int, int] = {}
            times: list[float] = []
            for sc, ms in results_burst:
                status_counts[sc] = status_counts.get(sc, 0) + 1
                times.append(ms)

            avg_ms = sum(times) / len(times) if times else 0.0
            throttled = any(sc in (429, 503) for sc in status_counts)

            # Collect RL headers from any throttled response
            if throttled:
                try:
                    resp_check = await client.get(target_url)
                    total_requests_sent += 1
                    for hdr in ("x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset", "retry-after"):
                        if hdr in {k.lower() for k in resp_check.headers.keys()}:
                            rl_headers_seen.add(hdr)
                    headers_exposed = list(rl_headers_seen)
                    # Try to get reset window
                    ra = resp_check.headers.get("retry-after") or resp_check.headers.get("Retry-After")
                    if ra:
                        try:
                            reset_window_seconds = int(ra)
                        except ValueError:
                            pass
                    try:
                        throttled_body = resp_check.text[:1000]
                    except Exception:
                        pass
                except Exception:
                    pass

                if threshold_rps is None:
                    threshold_rps = burst_size

            yield _sse("burst", {
                "burst_size": burst_size,
                "statuses": {str(k): v for k, v in status_counts.items()},
                "avg_ms": round(avg_ms, 2),
                "throttled": throttled,
            })

            if throttled:
                break  # Stop ramping
            await asyncio.sleep(1)

        # Bot detection type from throttled body
        if throttled_body:
            body_lower = throttled_body.lower()
            if "captcha" in body_lower:
                bot_detection_type = "captcha"
            elif "checking your browser" in body_lower or "cf-challenge" in body_lower:
                bot_detection_type = "js_challenge"
            elif "challenge" in body_lower:
                bot_detection_type = "header_challenge"
            else:
                bot_detection_type = "unknown"

        # Enforcement type heuristic
        if "x-ratelimit-limit" in rl_headers_seen:
            enforcement_type = "ip"

        # Bypass test: send with X-Forwarded-For after throttled
        if threshold_rps is not None:
            try:
                bypass_resp = await client.get(
                    target_url, headers={"X-Forwarded-For": "10.0.0.1"}
                )
                total_requests_sent += 1
                if bypass_resp.status_code == 200:
                    bypass_vectors.append("X-Forwarded-For bypass succeeded")
            except Exception:
                pass

    completed_at = datetime.now(timezone.utc).isoformat()
    profile = {
        "threshold_rps": threshold_rps,
        "reset_window_seconds": reset_window_seconds,
        "headers_exposed": headers_exposed,
        "bypass_vectors": bypass_vectors,
        "bot_detection_type": bot_detection_type,
        "enforcement_type": enforcement_type,
        "total_requests_sent": total_requests_sent,
    }

    _scan_history[scan_id].update({
        "status": "completed",
        "completed_at": completed_at,
        "result": profile,
    })

    yield _sse("complete", {
        "scan_id": scan_id,
        **profile,
        "timestamp": completed_at,
    })


@router.post("/ratelimit/probe", summary="Probe rate limiting behavior via SSE stream")
async def probe_rate_limit(
    payload: RateLimitRequest,
    request: Request,
    current_user: Annotated[User, Depends(require_tool("firewall"))],
    org_id: uuid.UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    scan_id = str(uuid.uuid4())

    log = AuditLog(
        org_id=org_id,
        user_id=current_user.id,
        action="tool.firewall.rate_limit",
        resource_type="firewall_scan",
        resource_id=scan_id,
        after_state={"target": payload.target, "path": payload.path, "max_rps": payload.max_rps},
        ip_address=request.client.host if request.client else None,
    )
    db.add(log)
    await db.commit()

    return StreamingResponse(
        _stream_rate_limit(scan_id, payload),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ── Module 6: HTTP Request Smuggling Probe ────────────────────────────────────

async def _stream_smuggling(
    scan_id: str,
    req: SmugglingRequest,
) -> AsyncGenerator[str, None]:
    started_at = datetime.now(timezone.utc).isoformat()

    _scan_history[scan_id] = {
        "id": scan_id,
        "type": "smuggling",
        "target": req.target,
        "status": "running",
        "started_at": started_at,
    }

    yield _sse("start", {
        "scan_id": scan_id,
        "target": req.target,
        "timestamp": started_at,
    })

    # Parse host from target
    import urllib.parse as _urlparse
    parsed = _urlparse.urlparse(req.target)
    base_host = parsed.netloc or parsed.path

    # Baseline timing: 5 normal POST requests
    baseline_times: list[float] = []
    async with httpx.AsyncClient(
        verify=False, http1=True, http2=False, timeout=5
    ) as client:
        for _ in range(5):
            try:
                t0 = asyncio.get_event_loop().time()
                await client.post(req.target, content=b"test=1",
                                  headers={"Content-Type": "application/x-www-form-urlencoded"})
                elapsed = (asyncio.get_event_loop().time() - t0) * 1000
                baseline_times.append(elapsed)
            except Exception:
                baseline_times.append(500.0)

    baseline_ms = sum(baseline_times) / len(baseline_times) if baseline_times else 500.0
    probes_run = 0
    anomalies_detected = 0
    probe_results: list[dict] = []

    # Define smuggling probes
    smuggling_probes = [
        {
            "probe_type": "cl_te",
            "headers": {
                "Content-Length": "13",
                "Transfer-Encoding": "chunked",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            "body": b"0\r\n\r\nGET /ping HTTP/1.1\r\nHost: " + base_host.encode(),
        },
        {
            "probe_type": "te_cl",
            "headers": {
                "Transfer-Encoding": "chunked",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            "body": b"1\r\nG\r\n0\r\n\r\n",
        },
        {
            "probe_type": "te_te_xchunked",
            "headers": {
                "Transfer-Encoding": "xchunked",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            "body": b"0\r\n\r\n",
        },
        {
            "probe_type": "te_te_space_prefix",
            "headers": {
                "Transfer-Encoding ": "chunked",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            "body": b"0\r\n\r\n",
        },
        {
            "probe_type": "te_te_identity",
            "headers": {
                "Transfer-Encoding": "chunked, identity",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            "body": b"0\r\n\r\n",
        },
    ]

    for probe in smuggling_probes:
        probe_type = probe["probe_type"]
        result_code = "NORMAL"
        response_time_ms = 0.0
        detail = ""

        try:
            async with httpx.AsyncClient(
                verify=False, http1=True, http2=False, timeout=5
            ) as client:
                t0 = asyncio.get_event_loop().time()
                resp = await client.post(
                    req.target,
                    content=probe["body"],
                    headers=probe["headers"],
                )
                response_time_ms = (asyncio.get_event_loop().time() - t0) * 1000

                if response_time_ms > baseline_ms * 3:
                    result_code = "TIMING_ANOMALY"
                    anomalies_detected += 1
                    detail = f"Response took {response_time_ms:.0f}ms vs baseline {baseline_ms:.0f}ms"
                elif resp.status_code not in (200, 301, 302, 400, 404, 405):
                    result_code = "RESPONSE_ANOMALY"
                    anomalies_detected += 1
                    detail = f"Unexpected status {resp.status_code}"
                else:
                    detail = f"Status {resp.status_code}, {response_time_ms:.0f}ms"

        except httpx.TimeoutException:
            result_code = "TIMING_ANOMALY"
            anomalies_detected += 1
            response_time_ms = 5000.0
            detail = "Request timed out — potential desync indicator"
        except Exception as exc:
            result_code = "ERROR"
            detail = str(exc)[:200]

        probes_run += 1
        probe_result = {
            "probe_type": probe_type,
            "result": result_code,
            "response_time_ms": round(response_time_ms, 2),
            "baseline_ms": round(baseline_ms, 2),
            "detail": detail,
        }
        probe_results.append(probe_result)
        yield _sse("probe", probe_result)
        await asyncio.sleep(0.1)

    # Desync risk assessment
    if anomalies_detected >= 3:
        desync_risk = "Critical"
        recommendation = "Strong evidence of HTTP desync. Immediately upgrade to HTTP/2 end-to-end or ensure consistent HTTP/1.1 parsing between frontend and backend."
    elif anomalies_detected == 2:
        desync_risk = "High"
        recommendation = "Multiple desync signals detected. Ensure consistent HTTP/1.1 parsing between frontend and backend. Disable Transfer-Encoding: chunked on the frontend proxy if not needed."
    elif anomalies_detected == 1:
        desync_risk = "Medium"
        recommendation = "Single anomaly detected. Review proxy/WAF HTTP/1.1 parsing configuration. Consider enforcing HTTP/2 between client and edge."
    else:
        desync_risk = "Low"
        recommendation = "No significant desync indicators found. Continue monitoring."

    completed_at = datetime.now(timezone.utc).isoformat()
    complete_data = {
        "scan_id": scan_id,
        "desync_risk": desync_risk,
        "anomalies_detected": anomalies_detected,
        "probes_run": probes_run,
        "recommendation": recommendation,
        "timestamp": completed_at,
    }

    _scan_history[scan_id].update({
        "status": "completed",
        "completed_at": completed_at,
        "result": complete_data,
    })

    yield _sse("complete", complete_data)


@router.post("/smuggling/probe", summary="Probe for HTTP request smuggling via SSE stream")
async def probe_smuggling(
    payload: SmugglingRequest,
    request: Request,
    current_user: Annotated[User, Depends(require_tool("firewall"))],
    org_id: uuid.UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    scan_id = str(uuid.uuid4())

    log = AuditLog(
        org_id=org_id,
        user_id=current_user.id,
        action="tool.firewall.smuggling",
        resource_type="firewall_scan",
        resource_id=scan_id,
        after_state={"target": payload.target},
        ip_address=request.client.host if request.client else None,
    )
    db.add(log)
    await db.commit()

    return StreamingResponse(
        _stream_smuggling(scan_id, payload),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ── Scan history ──────────────────────────────────────────────────────────────

@router.get("/scans", summary="Get firewall scan history for current org")
async def get_firewall_scans(
    limit: int = 50,
    current_user: Annotated[User, Depends(require_tool("firewall"))] = None,
    org_id: uuid.UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    from sqlalchemy import select, desc

    result = await db.execute(
        select(AuditLog)
        .where(AuditLog.org_id == org_id)
        .where(AuditLog.action.like("tool.firewall.%"))
        .order_by(desc(AuditLog.created_at))
        .limit(min(limit, 100))
    )
    logs = result.scalars().all()

    return JSONResponse(content={
        "items": [
            {
                "id": str(log.id),
                "action": log.action,
                "scan_type": log.action.replace("tool.firewall.", ""),
                "target": (log.after_state or {}).get("target", "—"),
                "created_at": log.created_at.isoformat() if log.created_at else None,
                "resource_id": str(log.resource_id) if log.resource_id else None,
            }
            for log in logs
        ],
        "total": len(logs),
    })


# ══════════════════════════════════════════════════════════════════════════════
# PHYSICAL FIREWALL SCANNER
# Hardware NGFW fingerprinting, CVE correlation, behavioral analysis
# Supports: Cisco ASA/FTD, Palo Alto PAN-OS, Fortinet FortiGate, Check Point,
#           SonicWall, Juniper SRX, pfSense, OPNsense
# ══════════════════════════════════════════════════════════════════════════════


# ── Physical scanner models ───────────────────────────────────────────────────

class PhysicalScanRequest(BaseModel):
    target: str  # IP or hostname
    scan_mode: str = "full"  # quick | full | aggressive
    include_snmp: bool = True
    include_ike: bool = True
    include_cve_probes: bool = True

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Target is required")
        return v

    @field_validator("scan_mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        if v not in ("quick", "full", "aggressive"):
            raise ValueError("scan_mode must be quick, full, or aggressive")
        return v


# ── Vendor signature database ─────────────────────────────────────────────────

PHYSICAL_VENDORS = {
    "cisco_asa": {
        "name": "Cisco ASA/FTD",
        "ssh_patterns": [r"SSH-2\.0-Cisco", r"SSH-2\.0-AsyncOS"],
        "http_paths": ["/+CSCOE+/logon.html", "/+webvpn+/index.html", "/admin/public/index.html"],
        "http_titles": [r"Cisco ASDM", r"Cisco Adaptive Security Appliance"],
        "http_body": [r"ciscoLogo", r"CSCOE", r"Cisco Systems", r"csc-logo"],
        "http_headers": {"Server": r"Cisco ASDM"},
        "snmp_oid_prefix": "1.3.6.1.4.1.9",
        "snmp_version_oid": "1.3.6.1.4.1.9.9.25.1.1.1.2.5",
        "default_ttl": 255,
        "mgmt_ports": [22, 443, 23, 8443],
        "vpn_paths": ["/+CSCOE+/logon.html", "/+webvpn+/"],
        "vpn_name": "Cisco AnyConnect",
        "color": "#049fd9",
    },
    "paloalto": {
        "name": "Palo Alto Networks PAN-OS",
        "ssh_patterns": [],  # Uses standard OpenSSH — identified by other signals
        "http_paths": ["/php/login.php", "/global-protect/login.esp", "/global-protect/getsoftware.esp"],
        "http_titles": [r"Palo Alto Networks", r"GlobalProtect", r"PAN-OS"],
        "http_body": [r"pan_form_token", r"GlobalProtect", r"PAN-OS", r"paloaltonetworks"],
        "http_headers": {},
        "snmp_oid_prefix": "1.3.6.1.4.1.25461",
        "snmp_version_oid": "1.3.6.1.4.1.25461.2.1.2.1.1.0",
        "default_ttl": 64,
        "mgmt_ports": [22, 443, 3978, 4443],
        "vpn_paths": ["/global-protect/login.esp", "/global-protect/getsoftware.esp"],
        "vpn_name": "GlobalProtect",
        "color": "#fa582d",
    },
    "fortinet": {
        "name": "Fortinet FortiGate",
        "ssh_patterns": [],  # Standard OpenSSH, identified via other signals
        "http_paths": ["/login", "/remote/login", "/remote/logincheck", "/ng/"],
        "http_titles": [r"FortiGate", r"FortiOS", r"Fortinet"],
        "http_body": [r"fgt_lang", r"FortiToken", r"ftm_push", r"fortigate", r"fortinet"],
        "http_headers": {},
        "snmp_oid_prefix": "1.3.6.1.4.1.12356",
        "snmp_version_oid": "1.3.6.1.4.1.12356.101.4.1.1.0",
        "default_ttl": 64,
        "mgmt_ports": [22, 443, 8443, 10443, 541],
        "vpn_paths": ["/remote/login", "/remote/logincheck"],
        "vpn_name": "FortiSSL VPN",
        "color": "#ee3124",
    },
    "checkpoint": {
        "name": "Check Point",
        "ssh_patterns": [],
        "http_paths": ["/sslvpn/Login/Login", "/", "/dana-na/auth/url_default/welcome.cgi"],
        "http_titles": [r"Check Point", r"Gaia"],
        "http_body": [r"cplogo", r"Check Point Software", r"chkp", r"check.point"],
        "http_headers": {},
        "snmp_oid_prefix": "1.3.6.1.4.1.2620",
        "snmp_version_oid": "1.3.6.1.4.1.2620.1.6.4.1.0",
        "default_ttl": 64,
        "mgmt_ports": [22, 443, 257, 18190, 18191, 18192, 8443],
        "vpn_paths": ["/sslvpn/Login/Login"],
        "vpn_name": "Check Point Mobile Access",
        "color": "#d40000",
    },
    "sonicwall": {
        "name": "SonicWall",
        "ssh_patterns": [],
        "http_paths": ["/auth.html", "/"],
        "http_titles": [r"SonicWall", r"SonicOS"],
        "http_body": [r"swm_ver", r"SonicWall", r"sonicwall_logo", r"sonicwall"],
        "http_headers": {"Server": r"SonicWALL"},
        "snmp_oid_prefix": "1.3.6.1.4.1.8741",
        "snmp_version_oid": "1.3.6.1.4.1.8741.1.3.1.3.0",
        "default_ttl": 64,
        "mgmt_ports": [22, 443, 8443, 80],
        "vpn_paths": [],
        "vpn_name": "SonicWall SSL-VPN",
        "color": "#f68b1f",
    },
    "juniper": {
        "name": "Juniper SRX/Junos",
        "ssh_patterns": [r"SSH-2\.0-JUNOS"],
        "http_paths": ["/", "/dana-na/auth"],
        "http_titles": [r"J-Web", r"Juniper Networks"],
        "http_body": [r"juniper_logo", r"Juniper Networks", r"junos", r"jweb"],
        "http_headers": {},
        "snmp_oid_prefix": "1.3.6.1.4.1.2636",
        "snmp_version_oid": "1.3.6.1.4.1.2636.3.1.2.0",
        "default_ttl": 64,
        "mgmt_ports": [22, 443, 830, 80],
        "vpn_paths": ["/dana-na/auth"],
        "vpn_name": "Pulse/Juniper SSL VPN",
        "color": "#009bde",
    },
    "pfsense": {
        "name": "pfSense",
        "ssh_patterns": [],
        "http_paths": ["/index.php", "/"],
        "http_titles": [r"pfSense"],
        "http_body": [r"pfsense", r"pfSense"],
        "http_headers": {},
        "snmp_oid_prefix": None,
        "snmp_version_oid": None,
        "default_ttl": 64,
        "mgmt_ports": [22, 443, 80],
        "vpn_paths": [],
        "vpn_name": "OpenVPN",
        "color": "#212a34",
    },
    "opnsense": {
        "name": "OPNsense",
        "ssh_patterns": [],
        "http_paths": ["/", "/ui/core/firmware"],
        "http_titles": [r"OPNsense"],
        "http_body": [r"opnsense", r"OPNsense"],
        "http_headers": {},
        "snmp_oid_prefix": None,
        "snmp_version_oid": None,
        "default_ttl": 64,
        "mgmt_ports": [22, 443, 80],
        "vpn_paths": [],
        "vpn_name": "OpenVPN",
        "color": "#d94f00",
    },
}

# ── CVE database ──────────────────────────────────────────────────────────────

PHYSICAL_CVE_DB: list[dict] = [
    {
        "id": "CVE-2024-3400", "cvss": 10.0, "vendor_key": "paloalto",
        "severity": "critical", "actively_exploited": True,
        "title": "PAN-OS GlobalProtect Command Injection — Unauthenticated RCE",
        "description": "Unauthenticated remote code execution via GlobalProtect gateway. CVSS 10.0. Actively exploited by UTA0218 (Volt Typhoon). Affects PAN-OS 10.2 < 10.2.9-h1, 11.0 < 11.0.4-h1, 11.1 < 11.1.2-h3.",
        "affected_versions": {"10.2": (0, 9), "11.0": (0, 4), "11.1": (0, 2)},
        "detection": "version+portal",
        "remediation": "Patch immediately. Temp workaround: disable GlobalProtect gateway.",
    },
    {
        "id": "CVE-2024-0012", "cvss": 9.8, "vendor_key": "paloalto",
        "severity": "critical", "actively_exploited": True,
        "title": "PAN-OS Management Interface Authentication Bypass",
        "description": "Unauthenticated management interface access. Chained with CVE-2024-9474 for privilege escalation.",
        "affected_versions": {"10.2": (0, 12), "11.0": (0, 6), "11.1": (0, 5), "11.2": (0, 4)},
        "detection": "version",
        "remediation": "Restrict management interface to trusted IPs. Apply patch.",
    },
    {
        "id": "CVE-2024-21762", "cvss": 9.8, "vendor_key": "fortinet",
        "severity": "critical", "actively_exploited": True,
        "title": "FortiOS SSL-VPN Out-of-Bounds Write — Unauthenticated RCE",
        "description": "Out-of-bounds write in SSL-VPN web management interface allows unauthenticated RCE. CISA KEV listed.",
        "affected_versions": {},
        "detection": "version+portal",
        "remediation": "Upgrade FortiOS. Disable SSL-VPN if not needed.",
    },
    {
        "id": "CVE-2023-27997", "cvss": 9.2, "vendor_key": "fortinet",
        "severity": "critical", "actively_exploited": False,
        "title": "FortiGate SSL-VPN Heap Buffer Overflow — Unauthenticated RCE",
        "description": "Pre-authentication heap-based buffer overflow in SSL-VPN WebGUI.",
        "affected_versions": {},
        "detection": "portal",
        "remediation": "Upgrade to FortiOS 6.0.17, 6.2.15, 6.4.13, 7.0.12, 7.2.5+",
    },
    {
        "id": "CVE-2024-24919", "cvss": 8.6, "vendor_key": "checkpoint",
        "severity": "high", "actively_exploited": True,
        "title": "Check Point Security Gateway Information Disclosure",
        "description": "Path traversal allows reading arbitrary files without authentication. Actively exploited to exfiltrate /etc/shadow.",
        "affected_versions": {},
        "detection": "portal",
        "remediation": "Apply hotfix HF_T-1694_HOTFIX_sk182337 immediately.",
    },
    {
        "id": "CVE-2024-20353", "cvss": 8.6, "vendor_key": "cisco_asa",
        "severity": "high", "actively_exploited": True,
        "title": "Cisco ASA/FTD DoS via Crafted HTTP — ArcaneDoor Campaign",
        "description": "Denial of service via crafted HTTP request. Used in ArcaneDoor espionage campaign attributed to state-sponsored actor.",
        "affected_versions": {},
        "detection": "banner+portal",
        "remediation": "Upgrade ASA firmware. Restrict management interface access.",
    },
    {
        "id": "CVE-2024-20359", "cvss": 6.0, "vendor_key": "cisco_asa",
        "severity": "medium", "actively_exploited": True,
        "title": "Cisco ASA Persistent Local Code Execution — ArcaneDoor",
        "description": "Allows persistence after reboot. Part of ArcaneDoor campaign toolkit.",
        "affected_versions": {},
        "detection": "banner",
        "remediation": "Verify device integrity with 'show version' and compare to known-good baseline.",
    },
    {
        "id": "CVE-2023-20269", "cvss": 5.0, "vendor_key": "cisco_asa",
        "severity": "medium", "actively_exploited": True,
        "title": "Cisco ASA/FTD VPN Brute Force / Unauthorized Session",
        "description": "Allows unauthenticated attackers to brute force VPN credentials. Part of ransomware group TTPs.",
        "affected_versions": {},
        "detection": "portal",
        "remediation": "Enable VPN lockout, MFA for VPN, restrict AnyConnect to known IPs.",
    },
    {
        "id": "CVE-2024-40766", "cvss": 9.8, "vendor_key": "sonicwall",
        "severity": "critical", "actively_exploited": True,
        "title": "SonicWall SonicOS Improper Access Control — CISA KEV",
        "description": "Improper access control in management interface and SSL-VPN. CISA KEV listed.",
        "affected_versions": {},
        "detection": "portal",
        "remediation": "Upgrade SonicOS. Restrict management access to trusted networks.",
    },
    {
        "id": "CVE-2023-36845", "cvss": 9.8, "vendor_key": "juniper",
        "severity": "critical", "actively_exploited": True,
        "title": "Juniper SRX/EX PHP Environment Variable Injection — Unauthenticated RCE",
        "description": "Unauthenticated RCE via J-Web PHP env var injection. Actively exploited in the wild.",
        "affected_versions": {},
        "detection": "portal",
        "remediation": "Upgrade Junos OS. Disable J-Web if not needed.",
    },
    {
        "id": "CVE-2021-20038", "cvss": 9.8, "vendor_key": "sonicwall",
        "severity": "critical", "actively_exploited": True,
        "title": "SonicWall SMA 100 Buffer Overflow — Unauthenticated RCE",
        "description": "Stack-based buffer overflow in SMA 100 management interface.",
        "affected_versions": {},
        "detection": "portal",
        "remediation": "Upgrade SMA firmware to 10.2.0.8-37sv or later.",
    },
]

# ── SNMP community strings to try ─────────────────────────────────────────────

SNMP_COMMUNITIES = [
    "public", "private", "cisco", "firewall", "admin", "monitor",
    "community", "snmp", "fortinet", "checkpoint", "sonicwall",
    "netscreen", "juniper", "paloalto", "network", "secret",
    "manager", "default", "read", "readonly", "1234", "password",
    "internal", "external", "router", "switch", "all", "0",
]

SNMP_OIDS = {
    "sysDescr":    "1.3.6.1.2.1.1.1.0",
    "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysName":     "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    "sysContact":  "1.3.6.1.2.1.1.4.0",
}

# Vendor enterprise OID prefixes
VENDOR_OID_MAP = {
    "1.3.6.1.4.1.9":     "cisco_asa",
    "1.3.6.1.4.1.12356": "fortinet",
    "1.3.6.1.4.1.25461": "paloalto",
    "1.3.6.1.4.1.2620":  "checkpoint",
    "1.3.6.1.4.1.8741":  "sonicwall",
    "1.3.6.1.4.1.2636":  "juniper",
}

# IKE Vendor ID hashes (MD5 prefixes)
IKE_VENDOR_IDS = {
    "09002689dfd6b712":                         "Cisco Unity",
    "afcad71368a1f1c96b8696fc7757060":          "Dead Peer Detection (RFC 3706)",
    "f4ed19e0c114eb516faaac0ee37daf2807cbf9d1": "Check Point FW-1",
    "7d9419a65310ca6f2c179d9215529d56":          "Cisco VPN Concentrator",
    "4048b7d56ebce88525e7de7f00d6c2d3":          "IKE Fragmentation",
    "27bab5dc01ea0760ea4e3190ac27c0d0":          "XAUTH",
    "1e2b516905991c7d7c96fcbfb587e46100":        "Fortinet FortiGate",
}

# ── Phase implementations ──────────────────────────────────────────────────────

async def _port_probe_physical(target: str, ports: list[int], timeout: float = 2.0) -> dict[int, bool]:
    """Phase 1: TCP SYN scan on management ports using asyncio connections."""
    results: dict[int, bool] = {}

    async def check_port(port: int) -> tuple[int, bool]:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port), timeout=timeout
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return port, True
        except Exception:
            return port, False

    tasks = [check_port(p) for p in ports]
    results_list = await asyncio.gather(*tasks)
    return dict(results_list)


async def _ssh_banner_grab(target: str, port: int = 22, timeout: float = 3.0) -> dict:
    """Phase 2a: Grab SSH banner and infer vendor."""
    result = {"open": False, "banner": None, "vendor_hint": None}
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port), timeout=timeout
        )
        banner_bytes = await asyncio.wait_for(reader.read(256), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        banner = banner_bytes.decode("utf-8", errors="ignore").strip()
        result["open"] = True
        result["banner"] = banner

        # Vendor inference from banner
        if re.search(r"Cisco", banner, re.I):
            result["vendor_hint"] = "cisco_asa"
        elif re.search(r"JUNOS", banner, re.I):
            result["vendor_hint"] = "juniper"
        elif re.search(r"FreeBSD", banner, re.I):
            result["vendor_hint"] = "pfsense"  # pfSense/OPNsense run FreeBSD
    except Exception:
        pass
    return result


async def _tls_cert_probe(target: str, port: int = 443, timeout: float = 5.0) -> dict:
    """Phase 2b: Parse TLS certificate for vendor fingerprints."""
    result = {"open": False, "subject": {}, "issuer": {}, "san": [], "vendor_hint": None,
              "fingerprint": None, "expires": None, "self_signed": False, "expired": False}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        loop = asyncio.get_event_loop()

        def _get_cert():
            s = socket.create_connection((target, port), timeout=timeout)
            ss = ctx.wrap_socket(s, server_hostname=target)
            cert_bin = ss.getpeercert(binary_form=True)
            ss.close()
            return cert_bin

        cert_bin = await loop.run_in_executor(None, _get_cert)
        result["open"] = True
        result["fingerprint"] = hashlib.sha256(cert_bin).hexdigest()[:16]

        # Parse with ssl module (no cryptography dependency needed)
        ctx2 = ssl.create_default_context()
        ctx2.check_hostname = False
        ctx2.verify_mode = ssl.CERT_NONE
        pem = ssl.DER_cert_to_PEM_cert(cert_bin)
        cert_dict = ssl.PEM_cert_to_DER_cert(pem)

        # Use raw DER parsing for subject/issuer via ssl module
        with socket.create_connection((target, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=target) as ssock:
                peer = ssock.getpeercert()
                if peer:
                    for field in peer.get("subject", []):
                        for k, v in field:
                            result["subject"][k] = v
                    for field in peer.get("issuer", []):
                        for k, v in field:
                            result["issuer"][k] = v
                    result["san"] = [s for typ, s in peer.get("subjectAltName", [])]
                    result["expires"] = peer.get("notAfter", None)

        # Check self-signed
        if result["subject"] == result["issuer"]:
            result["self_signed"] = True

        # Vendor from cert fields
        cert_text = " ".join([
            result["subject"].get("organizationName", ""),
            result["subject"].get("commonName", ""),
            result["issuer"].get("organizationName", ""),
            result["issuer"].get("commonName", ""),
        ]).lower()

        vendor_cert_map = {
            "cisco": "cisco_asa", "cisco systems": "cisco_asa",
            "fortinet": "fortinet", "fortigate": "fortinet",
            "palo alto": "paloalto",
            "check point": "checkpoint",
            "sonicwall": "sonicwall",
            "juniper": "juniper",
            "pfsense": "pfsense",
            "opnsense": "opnsense",
        }
        for kw, vendor_key in vendor_cert_map.items():
            if kw in cert_text:
                result["vendor_hint"] = vendor_key
                break

    except ssl.SSLError:
        result["open"] = True  # Port is open, just TLS issue
    except Exception:
        pass
    return result


async def _http_fingerprint_physical(target: str, port: int, use_ssl: bool = True) -> dict:
    """Phase 2c: HTTP/HTTPS management page fingerprinting."""
    proto = "https" if use_ssl else "http"
    base = f"{proto}://{target}:{port}"
    result = {"vendor_hint": None, "paths_found": [], "indicators": [], "version": None, "vpn_portal": None}

    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=5.0) as client:
            for vendor_key, sigs in PHYSICAL_VENDORS.items():
                if result["vendor_hint"]:
                    break
                for path in sigs["http_paths"][:3]:
                    try:
                        resp = await client.get(f"{base}{path}")
                        body = resp.text
                        body_low = body.lower()
                        matched = False

                        # Check titles
                        title_m = re.search(r"<title>(.*?)</title>", body, re.I | re.S)
                        title = title_m.group(1).strip() if title_m else ""
                        for pat in sigs["http_titles"]:
                            if re.search(pat, title, re.I):
                                result["vendor_hint"] = vendor_key
                                result["indicators"].append(f"title:{title[:60]}")
                                result["paths_found"].append(path)
                                matched = True
                                break

                        if not matched:
                            # Check body
                            for pat in sigs["http_body"]:
                                if re.search(pat, body_low, re.I):
                                    result["vendor_hint"] = vendor_key
                                    result["indicators"].append(f"body:{pat}")
                                    result["paths_found"].append(path)
                                    matched = True
                                    break

                        if not matched:
                            # Check headers
                            for hdr, pat in sigs["http_headers"].items():
                                if hdr.lower() in {k.lower() for k in resp.headers}:
                                    val = resp.headers.get(hdr, "")
                                    if re.search(pat, val, re.I):
                                        result["vendor_hint"] = vendor_key
                                        result["indicators"].append(f"header:{hdr}={val[:40]}")
                                        result["paths_found"].append(path)
                                        matched = True
                                        break

                        if matched:
                            # Try to extract version
                            for vp in [
                                r"(?:version|ver)[\":\s]+([0-9]+\.[0-9]+[\w\.\-]*)",
                                r"FortiOS\s+([0-9]+\.[0-9]+\.[0-9]+)",
                                r"PAN-OS\s+([0-9]+\.[0-9]+)",
                                r"ASA\s+([0-9]+\.[0-9]+[\w\(\)]*)",
                                r"v([0-9]+\.[0-9]+\.[0-9]+)",
                            ]:
                                vm = re.search(vp, body, re.I)
                                if vm:
                                    result["version"] = vm.group(1)
                                    break
                            # Check VPN portal
                            for vpn_path in sigs["vpn_paths"]:
                                for p_found in result["paths_found"]:
                                    if vpn_path in p_found:
                                        result["vpn_portal"] = sigs["vpn_name"]
                            break
                    except Exception:
                        continue
    except Exception:
        pass
    return result


async def _snmp_probe_physical(target: str) -> dict:
    """Phase 3: SNMP community brute force + OID fingerprinting via raw UDP."""
    result = {"accessible": False, "community": None, "sysDescr": None,
              "sysObjectID": None, "sysName": None, "vendor_hint": None}

    def _build_snmp_get(community: str, oid_str: str, request_id: int = 1) -> bytes:
        """Build minimal SNMPv1 GET-REQUEST packet."""
        def encode_oid(oid_str: str) -> bytes:
            parts = [int(x) for x in oid_str.split(".")]
            first = parts[0] * 40 + parts[1]
            encoded = [first]
            for part in parts[2:]:
                if part < 128:
                    encoded.append(part)
                else:
                    result_parts = []
                    while part > 0:
                        result_parts.append(part & 0x7f)
                        part >>= 7
                    result_parts.reverse()
                    for i, b in enumerate(result_parts):
                        encoded.append(b | (0x80 if i < len(result_parts) - 1 else 0))
            return bytes(encoded)

        def tlv(tag: int, value: bytes) -> bytes:
            length = len(value)
            if length < 128:
                return bytes([tag, length]) + value
            elif length < 256:
                return bytes([tag, 0x81, length]) + value
            else:
                return bytes([tag, 0x82, (length >> 8) & 0xff, length & 0xff]) + value

        oid_encoded = encode_oid(oid_str)
        oid_tlv = tlv(0x06, oid_encoded)
        null_tlv = bytes([0x05, 0x00])
        var_bind = tlv(0x30, oid_tlv + null_tlv)
        var_binds = tlv(0x30, var_bind)

        req_id = struct.pack(">i", request_id)
        req_id_tlv = tlv(0x02, req_id)
        error_status = bytes([0x02, 0x01, 0x00])
        error_index = bytes([0x02, 0x01, 0x00])

        get_request = tlv(0xa0, req_id_tlv + error_status + error_index + var_binds)

        version = bytes([0x02, 0x01, 0x00])  # version = 0 (SNMPv1)
        community_bytes = community.encode()
        community_tlv = tlv(0x04, community_bytes)

        message = tlv(0x30, version + community_tlv + get_request)
        return message

    def _parse_snmp_string(data: bytes) -> str | None:
        """Minimal SNMP response parser — extract first OCTET STRING or OID value."""
        try:
            # Find OCTET STRING (0x04) or OID (0x06) after variable bindings
            idx = 0
            while idx < len(data) - 2:
                tag = data[idx]
                length = data[idx + 1]
                if length & 0x80:
                    extra = length & 0x7f
                    if idx + 1 + extra >= len(data):
                        break
                    length = int.from_bytes(data[idx + 2:idx + 2 + extra], "big")
                    idx += extra
                if tag == 0x04 and length > 0:  # OCTET STRING with content
                    val = data[idx + 2:idx + 2 + length]
                    try:
                        decoded = val.decode("utf-8", errors="replace").strip()
                        if len(decoded) > 2:
                            return decoded
                    except Exception:
                        pass
                idx += 2 + length
        except Exception:
            pass
        return None

    loop = asyncio.get_event_loop()

    def _snmp_get_sync(community: str, oid: str) -> str | None:
        try:
            pkt = _build_snmp_get(community, oid)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1.0)
            sock.sendto(pkt, (target, 161))
            resp, _ = sock.recvfrom(4096)
            sock.close()
            return _parse_snmp_string(resp)
        except Exception:
            return None

    # Try each community string
    for community in SNMP_COMMUNITIES:
        val = await loop.run_in_executor(None, _snmp_get_sync, community, SNMP_OIDS["sysDescr"])
        if val and len(val) > 3:
            result["accessible"] = True
            result["community"] = community
            result["sysDescr"] = val

            # Get sysObjectID and sysName
            for name, oid in [("sysObjectID", SNMP_OIDS["sysObjectID"]),
                               ("sysName", SNMP_OIDS["sysName"])]:
                v = await loop.run_in_executor(None, _snmp_get_sync, community, oid)
                if v:
                    result[name] = v

            # Infer vendor from OID
            oid_str = result.get("sysObjectID", "")
            for prefix, vendor_key in VENDOR_OID_MAP.items():
                if oid_str.startswith(prefix):
                    result["vendor_hint"] = vendor_key
                    break

            # Fallback: sysDescr keyword
            if not result["vendor_hint"]:
                desc = result["sysDescr"].lower()
                keyword_map = {
                    "cisco": "cisco_asa", "fortinet": "fortinet", "fortigate": "fortinet",
                    "palo alto": "paloalto", "pan-os": "paloalto",
                    "check point": "checkpoint", "gaia": "checkpoint",
                    "sonicwall": "sonicwall", "juniper": "juniper", "junos": "juniper",
                    "pfsense": "pfsense", "opnsense": "opnsense",
                }
                for kw, vk in keyword_map.items():
                    if kw in desc:
                        result["vendor_hint"] = vk
                        break
            break

    return result


async def _ike_probe_physical(target: str, timeout: float = 3.0) -> dict:
    """Phase 4: IKEv1 Main Mode probe for VPN/firewall fingerprinting."""
    result = {"ike_open": False, "vendor_ids": [], "vendor_hint": None}

    def _build_ike_probe() -> bytes:
        """Build IKEv1 Main Mode SA proposal."""
        initiator_spi = os.urandom(8)
        # Minimal IKEv1 SA payload: 3DES-SHA1-PSK-DH2
        transform = (
            b"\x00\x00\x00\x24"  # Next=0, Res=0, Len=36
            b"\x01\x01"          # Transform# 1, KEY_IKE
            b"\x00\x00"          # Reserved
            b"\x80\x01\x00\x05" # Encrypt=3DES
            b"\x80\x02\x00\x02" # Hash=SHA1
            b"\x80\x03\x00\x01" # Auth=PSK
            b"\x80\x04\x00\x02" # DH=group2
        )
        proposal = (
            b"\x00\x00\x00\x2c"  # Next=0, Len=44
            b"\x01\x01\x00\x01" # Prop#1, ISAKMP, 1 transform
        ) + initiator_spi + transform
        sa = b"\x00\x00\x00\x30" + proposal  # Next=0, Len=48
        hdr = (
            initiator_spi +
            b"\x00" * 8 +  # Responder SPI
            b"\x01" +      # Next payload = SA
            b"\x10" +      # Version 1.0
            b"\x02" +      # Exchange = Main Mode
            b"\x00" +      # Flags
            b"\x00\x00\x00\x00"  # Msg ID
        )
        total_len = 28 + len(sa)
        hdr += struct.pack("!I", total_len)
        return hdr + sa

    loop = asyncio.get_event_loop()

    def _ike_probe_sync() -> tuple[bool, list[str]]:
        try:
            pkt = _build_ike_probe()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(pkt, (target, 500))
            resp, _ = sock.recvfrom(4096)
            sock.close()
            # Extract Vendor ID payloads (type 13)
            vendor_ids = []
            if len(resp) > 28:
                offset = 28
                next_p = resp[16] if len(resp) > 16 else 0
                while offset < len(resp) - 4 and next_p != 0:
                    cur_p = next_p
                    next_p = resp[offset]
                    plen = struct.unpack("!H", resp[offset+2:offset+4])[0]
                    if cur_p == 13 and plen > 4:  # Vendor ID payload
                        vid = resp[offset+4:offset+plen].hex()
                        vendor_ids.append(vid)
                    if plen < 4:
                        break
                    offset += plen
            return True, vendor_ids
        except Exception:
            return False, []

    ike_open, vendor_ids = await loop.run_in_executor(None, _ike_probe_sync)
    result["ike_open"] = ike_open
    result["vendor_ids"] = vendor_ids[:10]

    # Match known Vendor ID hashes
    for vid in vendor_ids:
        for known_prefix, name in IKE_VENDOR_IDS.items():
            if vid.startswith(known_prefix[:16]):
                result["vendor_hint"] = name
                break

    return result


async def _tcp_behavior_probe(target: str, open_port: int, closed_port: int = 19999) -> dict:
    """Phase 5: TCP behavioral analysis to infer firewall type."""
    result = {
        "stateful": None,
        "response_type": None,
        "ttl": None,
        "tcp_window": None,
        "inference": "unknown",
    }

    try:
        # Measure TTL via ICMP echo using raw socket
        loop = asyncio.get_event_loop()

        def _icmp_ttl() -> tuple[int | None, float | None]:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
                    s.settimeout(2.0)
                    # ICMP echo
                    data = struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"AttackTrace"
                    checksum = 0
                    for i in range(0, len(data), 2):
                        w = data[i] + (data[i+1] << 8) if i+1 < len(data) else data[i]
                        checksum += w
                    checksum = ~((checksum >> 16) + (checksum & 0xffff)) & 0xffff
                    data = struct.pack("!BBHHH", 8, 0, checksum, 1, 1) + b"AttackTrace"
                    start = time.time()
                    s.sendto(data, (target, 0))
                    resp, _ = s.recvfrom(1024)
                    rtt = (time.time() - start) * 1000
                    if len(resp) >= 20:
                        ttl = resp[8]
                        return ttl, round(rtt, 2)
            except PermissionError:
                pass
            except Exception:
                pass
            return None, None

        ttl, rtt = await loop.run_in_executor(None, _icmp_ttl)
        result["ttl"] = ttl
        if rtt:
            result["rtt_ms"] = rtt

        if ttl:
            if ttl >= 252:
                result["inference"] = "Cisco IOS/ASA or Juniper Junos (TTL≈255)"
            elif 60 <= ttl <= 65:
                result["inference"] = "Linux-based firewall (FortiOS/PAN-OS/pfSense/Check Point Gaia)"
            elif 124 <= ttl <= 128:
                result["inference"] = "Windows-based (unusual for perimeter firewall)"

        # TCP ACK probe to test stateful vs stateless
        def _ack_probe(port: int) -> str:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as s:
                    s.settimeout(2.0)
                    # Build ACK packet
                    src_port = 54321
                    seq_num = 12345
                    ack_num = 0
                    offset_res = (5 << 4) | 0
                    flags = 0x10  # ACK
                    window = 64240
                    tcp_header = struct.pack(
                        "!HHLLBBHHH",
                        src_port, port, seq_num, ack_num,
                        offset_res, flags, window, 0, 0
                    )
                    # Build pseudo header for checksum
                    src_ip = socket.gethostbyname(socket.gethostname())
                    pseudo = socket.inet_aton(src_ip) + socket.inet_aton(target) + b"\x00\x06" + struct.pack("!H", len(tcp_header))
                    chk_data = pseudo + tcp_header
                    checksum = 0
                    for i in range(0, len(chk_data), 2):
                        w = chk_data[i] + (chk_data[i+1] << 8) if i+1 < len(chk_data) else chk_data[i]
                        checksum += w
                    checksum = ~((checksum >> 16) + (checksum & 0xffff)) & 0xffff
                    tcp_header = struct.pack(
                        "!HHLLBBHHH",
                        src_port, port, seq_num, ack_num,
                        offset_res, flags, window, checksum, 0
                    )
                    s.sendto(tcp_header, (target, port))
                    resp = s.recv(1024)
                    if len(resp) >= 20:
                        flags_byte = resp[13]
                        if flags_byte & 0x04:  # RST
                            return "rst"
                        elif flags_byte & 0x02:  # SYN
                            return "syn"
                    return "unknown"
            except PermissionError:
                return "no_raw_socket"
            except socket.timeout:
                return "timeout"
            except Exception:
                return "error"

        ack_result = await loop.run_in_executor(None, _ack_probe, open_port)
        result["ack_response"] = ack_result
        if ack_result == "timeout":
            result["stateful"] = True
            result["inference"] += " | Stateful (ACK probe dropped)"
        elif ack_result == "rst":
            result["stateful"] = False
            result["inference"] += " | Stateless or ACL-based (ACK RST received)"

    except Exception as e:
        result["error"] = str(e)

    return result


async def _ssl_vpn_portal_probe(target: str, ports: list[int], timeout: float = 5.0) -> list[dict]:
    """Phase 6: Detect SSL VPN portals exposed on management ports."""
    portals = []
    vpn_paths = [
        ("/+CSCOE+/logon.html", "Cisco AnyConnect"),
        ("/+webvpn+/", "Cisco AnyConnect"),
        ("/global-protect/login.esp", "Palo Alto GlobalProtect"),
        ("/global-protect/getsoftware.esp", "Palo Alto GlobalProtect"),
        ("/remote/login", "Fortinet SSL-VPN"),
        ("/remote/logincheck", "Fortinet SSL-VPN"),
        ("/sslvpn/Login/Login", "Check Point Mobile Access"),
        ("/dana-na/auth/url_default/welcome.cgi", "Juniper Pulse Secure"),
        ("/auth.html", "SonicWall SSL-VPN"),
    ]

    open_ssl_ports = [p for p in ports if p in (443, 4443, 8443, 10443)]
    if not open_ssl_ports:
        return portals

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=timeout) as client:
        for port in open_ssl_ports[:2]:
            for path, vpn_name in vpn_paths:
                try:
                    resp = await client.get(f"https://{target}:{port}{path}")
                    if resp.status_code in (200, 301, 302, 401, 403):
                        body = resp.text.lower()
                        # Confirm it's not a generic 404/500 page
                        if any(kw in body for kw in ["login", "vpn", "connect", "portal", "gateway", "remote"]):
                            portals.append({
                                "path": path,
                                "vpn_name": vpn_name,
                                "port": port,
                                "status_code": resp.status_code,
                                "url": f"https://{target}:{port}{path}",
                            })
                except Exception:
                    continue

    # Deduplicate by vpn_name
    seen = set()
    unique = []
    for p in portals:
        if p["vpn_name"] not in seen:
            seen.add(p["vpn_name"])
            unique.append(p)
    return unique


def _correlate_cves(vendor_key: str | None, version: str | None) -> list[dict]:
    """Phase 7: Correlate detected vendor/version against CVE database."""
    if not vendor_key:
        return []

    results = []
    for cve in PHYSICAL_CVE_DB:
        if cve["vendor_key"] != vendor_key:
            continue

        finding = {**cve}

        # Version-based check if we have version info
        if version and cve.get("affected_versions"):
            try:
                parts = version.replace("(", ".").replace(")", "").split(".")
                major, minor = int(parts[0]), int(parts[1])
                patch = int(parts[2]) if len(parts) > 2 else 0
                key = f"{major}.{minor}"
                if key in cve["affected_versions"]:
                    patch_min, patch_max = cve["affected_versions"][key]
                    if patch_min <= patch < patch_max:
                        finding["version_confirmed"] = True
                else:
                    finding["version_confirmed"] = False
            except Exception:
                finding["version_confirmed"] = None
        else:
            finding["version_confirmed"] = None  # version detection needed

        results.append(finding)

    return sorted(results, key=lambda c: c["cvss"], reverse=True)


def _calculate_risk_score(scan_data: dict) -> dict:
    """Phase 8: Composite risk score calculation."""
    exposure = 0
    vuln = 0
    config = 0
    surface = 0

    # Exposure factors
    open_ports = scan_data.get("open_ports", [])
    if 23 in open_ports:
        exposure += 25  # Telnet is critical
    if 161 in open_ports or scan_data.get("snmp_accessible"):
        exposure += 20
    if len(open_ports) > 3:
        exposure += 10
    if scan_data.get("mgmt_internet_exposed"):
        exposure += 25
    if scan_data.get("ike_open"):
        exposure += 10

    # Vulnerability factors
    cves = scan_data.get("cves", [])
    if cves:
        max_cvss = max(c["cvss"] for c in cves)
        kev_boost = 1.2 if any(c.get("actively_exploited") for c in cves) else 1.0
        vuln = min(100, (max_cvss / 10) * 100 * kev_boost)

    # Configuration risk
    if scan_data.get("snmp_accessible"):
        community = scan_data.get("snmp_community", "")
        if community in ("public", "private", "cisco", "admin"):
            config += 40  # Default/common community
        else:
            config += 20
    if scan_data.get("tls_self_signed"):
        config += 15
    if scan_data.get("tls_expired"):
        config += 20
    if scan_data.get("ssh_open") and not scan_data.get("version"):
        config += 5

    # Attack surface
    surface = min(100, len(open_ports) * 12)

    composite = (
        exposure * 0.25 +
        vuln * 0.40 +
        config * 0.20 +
        surface * 0.15
    )
    composite = min(100, composite)

    return {
        "composite": round(composite, 1),
        "severity": (
            "CRITICAL" if composite >= 80 else
            "HIGH" if composite >= 60 else
            "MEDIUM" if composite >= 40 else
            "LOW" if composite >= 20 else
            "INFO"
        ),
        "breakdown": {
            "exposure": round(exposure * 0.25, 1),
            "vulnerability": round(vuln * 0.40, 1),
            "configuration": round(config * 0.20, 1),
            "attack_surface": round(surface * 0.15, 1),
        },
    }


# ── Main physical scan orchestrator ──────────────────────────────────────────

async def _run_physical_scan(
    target: str,
    scan_mode: str,
    include_snmp: bool,
    include_ike: bool,
    include_cve_probes: bool,
) -> AsyncGenerator[str, None]:
    """Master scan orchestrator — runs all phases and streams SSE events."""

    scan_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat()

    # Define port sets by scan mode
    if scan_mode == "quick":
        mgmt_ports = [22, 443, 80]
        udp_ports = [161] if include_snmp else []
    elif scan_mode == "aggressive":
        mgmt_ports = [22, 23, 80, 443, 257, 541, 830, 3978, 4443, 4444, 8080, 8443, 10443, 18190, 18191]
        udp_ports = [161, 500, 4500] if include_snmp or include_ike else []
    else:  # full
        mgmt_ports = [22, 23, 80, 443, 541, 830, 3978, 4443, 8080, 8443, 10443, 18190]
        udp_ports = [161, 500] if include_snmp or include_ike else []

    yield _sse("start", {
        "scan_id": scan_id, "target": target, "mode": scan_mode,
        "phases": 8, "started_at": started_at,
        "ports_to_check": len(mgmt_ports),
    })

    scan_data: dict = {
        "scan_id": scan_id, "target": target, "mode": scan_mode,
        "vendor_key": None, "vendor_name": None, "version": None,
        "open_ports": [], "ssh_open": False, "snmp_accessible": False,
        "ike_open": False, "tls_self_signed": False, "ssl_vpn_portals": [],
        "cves": [], "indicators": [], "risk_score": {},
    }

    # ── Phase 1: Port Discovery ───────────────────────────────────────────────
    yield _sse("phase", {"phase": 1, "name": "Port Discovery", "status": "running"})
    try:
        port_results = await _port_probe_physical(target, mgmt_ports, timeout=2.5 if scan_mode != "quick" else 1.5)
        open_ports = [p for p, open_ in port_results.items() if open_]
        scan_data["open_ports"] = open_ports
        yield _sse("ports", {
            "open": open_ports,
            "closed": [p for p, open_ in port_results.items() if not open_],
            "total_checked": len(mgmt_ports),
        })
        yield _sse("phase", {"phase": 1, "name": "Port Discovery", "status": "complete",
                              "finding": f"{len(open_ports)} management ports open"})
    except Exception as e:
        yield _sse("phase", {"phase": 1, "name": "Port Discovery", "status": "error", "error": str(e)})
        open_ports = []

    if not open_ports:
        yield _sse("warning", {"message": "No management ports open. Target may be unreachable or fully filtered."})
        # Still continue with HTTP probes on default ports
        open_ports = [443, 22]

    # ── Phase 2a: SSH Banner ──────────────────────────────────────────────────
    vendor_votes: dict[str, int] = {}
    version_hint: str | None = None

    if 22 in open_ports:
        yield _sse("phase", {"phase": 2, "name": "SSH Banner Grab", "status": "running"})
        ssh_result = await _ssh_banner_grab(target)
        scan_data["ssh_open"] = ssh_result["open"]
        if ssh_result.get("banner"):
            yield _sse("ssh_banner", {"banner": ssh_result["banner"], "vendor_hint": ssh_result.get("vendor_hint")})
            if ssh_result.get("vendor_hint"):
                vendor_votes[ssh_result["vendor_hint"]] = vendor_votes.get(ssh_result["vendor_hint"], 0) + 2
        yield _sse("phase", {"phase": 2, "name": "SSH Banner Grab", "status": "complete",
                              "finding": (ssh_result.get("banner") or "No banner")[:60]})

    # ── Phase 2b: TLS Certificate ─────────────────────────────────────────────
    ssl_ports = [p for p in open_ports if p in (443, 4443, 8443, 10443)]
    if ssl_ports:
        yield _sse("phase", {"phase": 3, "name": "TLS Certificate Analysis", "status": "running"})
        cert_result = await _tls_cert_probe(target, ssl_ports[0])
        if cert_result.get("open"):
            scan_data["tls_self_signed"] = cert_result.get("self_signed", False)
            scan_data["tls_expired"] = cert_result.get("expired", False)
            yield _sse("tls_cert", {
                "subject": cert_result.get("subject", {}),
                "issuer": cert_result.get("issuer", {}),
                "san": cert_result.get("san", [])[:5],
                "fingerprint": cert_result.get("fingerprint"),
                "expires": cert_result.get("expires"),
                "self_signed": cert_result.get("self_signed"),
                "vendor_hint": cert_result.get("vendor_hint"),
            })
            if cert_result.get("vendor_hint"):
                vendor_votes[cert_result["vendor_hint"]] = vendor_votes.get(cert_result["vendor_hint"], 0) + 3
        yield _sse("phase", {"phase": 3, "name": "TLS Certificate Analysis", "status": "complete",
                              "finding": f"Issuer: {cert_result.get('issuer', {}).get('organizationName', 'unknown')}"})

    # ── Phase 2c: HTTP Fingerprinting ─────────────────────────────────────────
    http_ports = [p for p in open_ports if p in (443, 4443, 8443, 10443, 80, 8080)]
    if http_ports:
        yield _sse("phase", {"phase": 4, "name": "HTTP Management Interface Fingerprint", "status": "running"})
        use_ssl = http_ports[0] in (443, 4443, 8443, 10443)
        http_result = await _http_fingerprint_physical(target, http_ports[0], use_ssl)
        if http_result.get("vendor_hint"):
            vendor_votes[http_result["vendor_hint"]] = vendor_votes.get(http_result["vendor_hint"], 0) + 4
        if http_result.get("version"):
            version_hint = http_result["version"]
        yield _sse("http_fingerprint", {
            "vendor_hint": http_result.get("vendor_hint"),
            "indicators": http_result.get("indicators", []),
            "paths_found": http_result.get("paths_found", []),
            "version": http_result.get("version"),
            "vpn_portal": http_result.get("vpn_portal"),
        })
        if http_result.get("vpn_portal"):
            scan_data["ssl_vpn_portals"].append({"name": http_result["vpn_portal"], "port": http_ports[0]})
        yield _sse("phase", {"phase": 4, "name": "HTTP Management Interface Fingerprint", "status": "complete",
                              "finding": f"Vendor: {PHYSICAL_VENDORS.get(http_result.get('vendor_hint') or '', {}).get('name', 'Unknown')}"})

    # ── Phase 3: SNMP Probe ───────────────────────────────────────────────────
    if include_snmp and (scan_mode in ("full", "aggressive") or 161 in open_ports):
        yield _sse("phase", {"phase": 5, "name": "SNMP Community Brute Force", "status": "running"})
        snmp_result = await _snmp_probe_physical(target)
        scan_data["snmp_accessible"] = snmp_result["accessible"]
        if snmp_result["accessible"]:
            scan_data["snmp_community"] = snmp_result.get("community")
            yield _sse("snmp", {
                "accessible": True,
                "community": snmp_result.get("community"),
                "sysDescr": snmp_result.get("sysDescr"),
                "sysObjectID": snmp_result.get("sysObjectID"),
                "sysName": snmp_result.get("sysName"),
                "vendor_hint": snmp_result.get("vendor_hint"),
                "severity": "critical" if snmp_result.get("community") in ("public", "private") else "high",
            })
            if snmp_result.get("vendor_hint"):
                vendor_votes[snmp_result["vendor_hint"]] = vendor_votes.get(snmp_result["vendor_hint"], 0) + 5
        else:
            yield _sse("snmp", {"accessible": False})
        yield _sse("phase", {"phase": 5, "name": "SNMP Community Brute Force", "status": "complete",
                              "finding": f"SNMP {'ACCESSIBLE (community: ' + str(snmp_result.get('community')) + ')' if snmp_result['accessible'] else 'not accessible'}"})

    # ── Phase 4: IKE/IPsec Probe ──────────────────────────────────────────────
    if include_ike and scan_mode in ("full", "aggressive"):
        yield _sse("phase", {"phase": 6, "name": "IKE/IPsec VPN Fingerprint", "status": "running"})
        ike_result = await _ike_probe_physical(target)
        scan_data["ike_open"] = ike_result["ike_open"]
        if ike_result["ike_open"]:
            yield _sse("ike", {
                "open": True,
                "vendor_ids": ike_result["vendor_ids"][:5],
                "vendor_hint": ike_result.get("vendor_hint"),
                "finding": "IKE/IPsec VPN endpoint detected",
            })
            if ike_result.get("vendor_hint"):
                scan_data["indicators"].append(f"IKE Vendor ID: {ike_result['vendor_hint']}")
        else:
            yield _sse("ike", {"open": False})
        yield _sse("phase", {"phase": 6, "name": "IKE/IPsec VPN Fingerprint", "status": "complete",
                              "finding": "IKE open" if ike_result["ike_open"] else "No IKE response"})

    # ── Phase 5: TCP Behavioral Analysis ──────────────────────────────────────
    if scan_mode in ("full", "aggressive") and open_ports:
        yield _sse("phase", {"phase": 7, "name": "TCP Behavioral Analysis", "status": "running"})
        tcp_result = await _tcp_behavior_probe(target, open_ports[0])
        yield _sse("tcp_behavior", {
            "ttl": tcp_result.get("ttl"),
            "rtt_ms": tcp_result.get("rtt_ms"),
            "ack_response": tcp_result.get("ack_response"),
            "stateful": tcp_result.get("stateful"),
            "inference": tcp_result.get("inference"),
        })
        if tcp_result.get("ttl") == 255 and not scan_data.get("vendor_key"):
            vendor_votes["cisco_asa"] = vendor_votes.get("cisco_asa", 0) + 1
            vendor_votes["juniper"] = vendor_votes.get("juniper", 0) + 1
        yield _sse("phase", {"phase": 7, "name": "TCP Behavioral Analysis", "status": "complete",
                              "finding": tcp_result.get("inference", "Inconclusive")})

    # ── Phase 6: SSL VPN Portal Detection ────────────────────────────────────
    if open_ports and scan_mode in ("full", "aggressive"):
        yield _sse("phase", {"phase": 8, "name": "SSL VPN Portal Detection", "status": "running"})
        portals = await _ssl_vpn_portal_probe(target, open_ports)
        for p in portals:
            if p not in scan_data["ssl_vpn_portals"]:
                scan_data["ssl_vpn_portals"].append(p)
                yield _sse("vpn_portal", {**p, "severity": "high", "finding": f"{p['vpn_name']} portal exposed"})
        yield _sse("phase", {"phase": 8, "name": "SSL VPN Portal Detection", "status": "complete",
                              "finding": f"{len(portals)} VPN portal(s) detected"})

    # ── Vendor Determination ──────────────────────────────────────────────────
    if vendor_votes:
        best_vendor = max(vendor_votes, key=vendor_votes.get)  # type: ignore[arg-type]
        scan_data["vendor_key"] = best_vendor
        scan_data["vendor_name"] = PHYSICAL_VENDORS.get(best_vendor, {}).get("name", best_vendor)
        scan_data["version"] = version_hint

        yield _sse("vendor_identified", {
            "vendor_key": best_vendor,
            "vendor_name": scan_data["vendor_name"],
            "confidence": min(100, vendor_votes[best_vendor] * 14),
            "version": version_hint,
            "vote_breakdown": vendor_votes,
        })
    else:
        yield _sse("vendor_identified", {
            "vendor_key": None,
            "vendor_name": "Unknown",
            "confidence": 0,
            "version": None,
            "vote_breakdown": {},
        })

    # ── Phase 7: CVE Correlation ──────────────────────────────────────────────
    if include_cve_probes and scan_data.get("vendor_key"):
        yield _sse("phase", {"phase": 9, "name": "CVE Correlation & Active Probes", "status": "running"})
        cves = _correlate_cves(scan_data["vendor_key"], scan_data.get("version"))
        scan_data["cves"] = cves

        for cve in cves:
            yield _sse("cve", {
                "id": cve["id"],
                "cvss": cve["cvss"],
                "severity": cve["severity"],
                "title": cve["title"],
                "description": cve["description"],
                "actively_exploited": cve.get("actively_exploited", False),
                "version_confirmed": cve.get("version_confirmed"),
                "remediation": cve["remediation"],
            })

        yield _sse("phase", {"phase": 9, "name": "CVE Correlation & Active Probes", "status": "complete",
                              "finding": f"{len(cves)} CVE(s) applicable to {scan_data['vendor_name']}"})

    # ── Phase 8: Risk Scoring ─────────────────────────────────────────────────
    scan_data["risk_score"] = _calculate_risk_score(scan_data)
    yield _sse("risk_score", scan_data["risk_score"])

    # ── Final Summary ─────────────────────────────────────────────────────────
    yield _sse("complete", {
        "scan_id": scan_id,
        "target": target,
        "vendor_key": scan_data.get("vendor_key"),
        "vendor_name": scan_data.get("vendor_name", "Unknown"),
        "version": scan_data.get("version"),
        "open_ports": scan_data["open_ports"],
        "snmp_accessible": scan_data["snmp_accessible"],
        "ike_open": scan_data["ike_open"],
        "ssl_vpn_portals": len(scan_data["ssl_vpn_portals"]),
        "cve_count": len(scan_data["cves"]),
        "critical_cves": len([c for c in scan_data["cves"] if c["severity"] == "critical"]),
        "risk_score": scan_data["risk_score"],
        "started_at": started_at,
        "completed_at": datetime.now(timezone.utc).isoformat(),
    })


# ── API endpoints ─────────────────────────────────────────────────────────────

@router.post(
    "/physical/scan",
    summary="Physical/hardware NGFW fingerprinting and CVE assessment",
    description=(
        "Scans a physical firewall (Cisco ASA, Palo Alto PAN-OS, FortiGate, Check Point, "
        "SonicWall, Juniper SRX, pfSense, OPNsense) via management port probing, "
        "SNMP community brute-force, IKE/IPsec fingerprinting, TLS cert analysis, "
        "SSH banner grab, SSL VPN portal detection, and CVE correlation. "
        "Results stream as SSE events."
    ),
)
async def physical_firewall_scan(
    payload: PhysicalScanRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: uuid.UUID = Depends(get_current_org_id),
) -> StreamingResponse:
    return StreamingResponse(
        _run_physical_scan(
            payload.target,
            payload.scan_mode,
            payload.include_snmp,
            payload.include_ike,
            payload.include_cve_probes,
        ),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get(
    "/physical/vendors",
    summary="List supported physical firewall vendors",
)
async def list_physical_vendors(
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict:
    return {
        "vendors": [
            {
                "key": k,
                "name": v["name"],
                "mgmt_ports": v["mgmt_ports"],
                "color": v["color"],
                "vpn_name": v["vpn_name"],
                "cve_count": len([c for c in PHYSICAL_CVE_DB if c["vendor_key"] == k]),
            }
            for k, v in PHYSICAL_VENDORS.items()
        ]
    }


@router.get(
    "/physical/cves",
    summary="List physical firewall CVE database",
)
async def list_physical_cves(
    current_user: Annotated[User, Depends(get_current_user)],
    vendor_key: str | None = None,
    min_cvss: float = 0.0,
) -> dict:
    cves = [
        c for c in PHYSICAL_CVE_DB
        if (not vendor_key or c["vendor_key"] == vendor_key)
        and c["cvss"] >= min_cvss
    ]
    return {
        "items": sorted(cves, key=lambda c: c["cvss"], reverse=True),
        "total": len(cves),
        "critical_count": len([c for c in cves if c["severity"] == "critical"]),
    }
