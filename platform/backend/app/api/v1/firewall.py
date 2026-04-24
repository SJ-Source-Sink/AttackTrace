"""
Firewall & WAF Scanner API — WAF detection, bypass probing, port firewall mapping,
and firewall rule analysis, all streamed via SSE where applicable.
"""

import asyncio
import io
import json
import re
import shutil
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
from app.core.dependencies import get_current_org_id, get_current_user
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

class WafDetectRequest(BaseModel):
    target: str

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Target is required")
        if re.search(r"[;&|`$(){}<>]", v):
            raise ValueError("Target contains invalid characters")
        return v


class WafBypassRequest(BaseModel):
    target: str
    path: str = "/"
    param: str = "q"

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Target is required")
        if re.search(r"[;&|`$(){}<>]", v):
            raise ValueError("Target contains invalid characters")
        return v

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
        allowed = {"acl_probe", "fin_null_xmas", "source_port", "fragmented", "full_suite"}
        if v not in allowed:
            raise ValueError(f"Mode must be one of: {', '.join(sorted(allowed))}")
        return v


# ── Module 1: WAF Detection ───────────────────────────────────────────────────

@router.post("/waf/detect", summary="Detect WAF presence and vendor")
async def detect_waf(
    payload: WafDetectRequest,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
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

    # SQLi probe — chosen to look malicious but harmless
    malicious_param = "?id=1%27%20OR%20%271%27%3D%271"
    normal_url = payload.target
    malicious_url = payload.target.rstrip("/") + "/" + malicious_param

    normal_resp: httpx.Response | None = None
    malicious_resp: httpx.Response | None = None

    async with httpx.AsyncClient(
        verify=False, follow_redirects=True, timeout=15
    ) as client:
        try:
            normal_resp = await client.get(normal_url)
        except Exception as exc:
            pass

        try:
            malicious_resp = await client.get(malicious_url)
        except Exception as exc:
            pass

    result = _score_response(normal_resp, malicious_resp)
    result["scan_id"] = scan_id
    result["target"] = payload.target
    result["timestamp"] = datetime.now(timezone.utc).isoformat()

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


# ── Module 2: WAF Bypass Probe ────────────────────────────────────────────────

BYPASS_PROBES: list[dict] = [
    {"technique": "baseline_sqli",       "payload": "' OR 1=1--",                     "method": "param"},
    {"technique": "url_encoded_sqli",    "payload": "%27%20OR%201%3D1--",             "method": "param"},
    {"technique": "double_encoded_sqli", "payload": "%2527%2520OR%25201%253D1--",     "method": "param"},
    {"technique": "unicode_escape_sqli", "payload": "\\u0027 OR 1=1--",              "method": "param"},
    {"technique": "case_mutation_sqli1", "payload": "' oR 1=1--",                    "method": "param"},
    {"technique": "case_mutation_sqli2", "payload": "' Or 1=1--",                    "method": "param"},
    {"technique": "comment_injection",   "payload": "'/**/OR/**/1=1--",              "method": "param"},
    {"technique": "header_injection",    "payload": "' OR 1=1--",                    "method": "header"},
    {"technique": "null_byte_sqli",      "payload": "'\x00 OR 1=1--",               "method": "param"},
    {"technique": "xss_baseline",        "payload": "<script>alert(1)</script>",      "method": "param"},
    {"technique": "xss_encoded",         "payload": "%3Cscript%3Ealert(1)%3C/script%3E", "method": "param"},
    {"technique": "xss_case_mutation",   "payload": "<ScRiPt>alert(1)</ScRiPt>",     "method": "param"},
    {"technique": "xss_tag_variant",     "payload": "<img src=x onerror=alert(1)>",  "method": "param"},
]

BLOCKED_STATUSES = {403, 406, 429, 503}


async def _stream_bypass(
    scan_id: str,
    req: WafBypassRequest,
) -> AsyncGenerator[str, None]:
    started_at = datetime.now(timezone.utc).isoformat()

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
        "total_probes": len(BYPASS_PROBES),
        "timestamp": started_at,
    })

    base_url = req.target.rstrip("/") + req.path
    results: list[dict] = []

    async with httpx.AsyncClient(
        verify=False, follow_redirects=True, timeout=10
    ) as client:
        for probe in BYPASS_PROBES:
            technique = probe["technique"]
            payload = probe["payload"]
            method = probe["method"]

            probe_status: int | None = None
            error: str | None = None

            try:
                if method == "header":
                    resp = await client.get(
                        base_url,
                        headers={"X-Forwarded-For": payload},
                    )
                else:
                    url = f"{base_url}?{req.param}={payload}"
                    resp = await client.get(url)
                probe_status = resp.status_code
            except Exception as exc:
                error = str(exc)

            if error:
                result_label = "error"
            elif probe_status in BLOCKED_STATUSES:
                result_label = "blocked"
            elif probe_status == 200:
                result_label = "bypass"
            else:
                result_label = "uncertain"

            probe_result = {
                "technique": technique,
                "payload": payload,
                "status": probe_status,
                "result": result_label,
                "error": error,
            }
            results.append(probe_result)

            yield _sse("probe", {"data": probe_result})
            await asyncio.sleep(0.05)

    bypass_count = sum(1 for r in results if r["result"] == "bypass")
    blocked_count = sum(1 for r in results if r["result"] == "blocked")
    uncertain_count = sum(1 for r in results if r["result"] == "uncertain")

    completed_at = datetime.now(timezone.utc).isoformat()
    _scan_history[scan_id].update({
        "status": "completed",
        "completed_at": completed_at,
        "probes": results,
        "summary": {
            "total": len(results),
            "bypass": bypass_count,
            "blocked": blocked_count,
            "uncertain": uncertain_count,
        },
    })

    yield _sse("complete", {
        "scan_id": scan_id,
        "target": req.target,
        "summary": {
            "total": len(results),
            "bypass": bypass_count,
            "blocked": blocked_count,
            "uncertain": uncertain_count,
        },
        "probes": results,
        "timestamp": completed_at,
    })


@router.post("/waf/bypass", summary="Probe WAF bypass techniques via SSE stream")
async def probe_waf_bypass(
    payload: WafBypassRequest,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
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
    """Add firewall interpretation to each port based on scan mode."""
    interp = PORT_MAP_MODES.get(mode, {}).get("interpretation", {})
    for host in hosts:
        for port in host.get("ports", []):
            state = port.get("state", "")
            message = interp.get(state) or interp.get("default", "")
            port["firewall_interpretation"] = message
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


async def _stream_port_map(
    scan_id: str,
    req: PortFirewallRequest,
) -> AsyncGenerator[str, None]:
    nmap_bin = shutil.which("nmap") or "nmap"
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
        cmd_preview = " ".join([nmap_bin] + flags + ["--system-dns", req.target])

        yield _sse("output", {
            "line": f"[{mode}] Running: {cmd_preview}",
        })

        cmd = [nmap_bin] + flags + ["--system-dns", req.target]
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
    current_user: Annotated[User, Depends(get_current_user)],
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

        # :INPUT ACCEPT [0:0]
        chain_header = re.match(r"^:(\w+)\s+(ACCEPT|DROP|RETURN)", line)
        if chain_header:
            chain = chain_header.group(1)
            continue

        # -A CHAIN ...
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
            })
        else:
            seen_sigs[sig] = idx

        # Any-Any permit
        if (
            rule["action"] in ("ACCEPT", "PERMIT", "PASS", "ALLOW")
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
            })

        # Overly broad: permit from 0.0.0.0/0 to sensitive ports
        if rule["action"] in ("ACCEPT", "PERMIT", "PASS", "ALLOW") and _is_any_source(rule["src"]):
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
                })

    # Shadow rules: later rule shadowed by earlier catch-all of same action
    for i, later in enumerate(rules):
        for earlier in rules[:i]:
            if earlier["chain"] != later["chain"]:
                continue
            if earlier["action"] != later["action"]:
                continue
            # Earlier shadows later if earlier is broader (any src/dst/port) on same proto
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
                # Avoid flagging identical rules twice (already caught by redundant check)
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
                })
                break  # Only report the first shadowing rule per rule

    # Conflicting rules: one permits and one denies the same specific traffic
    permit_actions = {"ACCEPT", "PERMIT", "PASS", "ALLOW"}
    deny_actions = {"DROP", "DENY", "REJECT", "BLOCK"}

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
                })

    return anomalies


@router.post("/rules/analyze", summary="Analyze firewall rule file for anomalies")
async def analyze_firewall_rules(
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: uuid.UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
    file: UploadFile = File(...),
) -> JSONResponse:
    allowed_extensions = {".txt", ".conf", ".xml"}
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
    else:
        # Attempt heuristic parse as iptables then cisco
        rules = _parse_iptables(content)
        if not rules:
            rules = _parse_cisco_acl(content)
        if not rules:
            raise HTTPException(
                status_code=400,
                detail="Could not detect or parse the firewall rule format. "
                       "Supported formats: iptables, Cisco ACL, pfSense XML.",
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


# ── Scan history ──────────────────────────────────────────────────────────────

@router.get("/scans", summary="List all firewall scan history")
async def list_firewall_scans(
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict:
    scans = sorted(
        _scan_history.values(),
        key=lambda s: s.get("started_at", ""),
        reverse=True,
    )
    return {"items": scans, "total": len(scans)}
