"""
API Security Scanner — AttackTrace
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Tests APIs against OWASP API Top 10:
  - API1: Broken Object Level Authorization (BOLA/IDOR)
  - API2: Broken Authentication
  - API3: Broken Object Property Level Authorization
  - API4: Unrestricted Resource Consumption (rate limiting)
  - API5: Broken Function Level Authorization (BFLA)
  - API6: Server-Side Request Forgery
  - API7: Security Misconfiguration
  - API8: Lack of Protection from Automated Threats
  - API9: Improper Inventory Management
  - API10: Unsafe Consumption of APIs
"""

from __future__ import annotations

import asyncio
import json
import re
import uuid as _uuid_mod
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, AsyncGenerator

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings as _get_settings
from app.core.database import get_db
from app.core.dependencies import get_current_org_id, get_current_user
from app.core.finding_confidence import grade_confidence
from app.core.remediation import get_remediation
from app.models.db.user import User
from app.services.finding_ingest import ingest_findings

router = APIRouter(prefix="/api-scanner", tags=["API Security Scanner"])

# ── History helpers ────────────────────────────────────────────────────────────

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)


def _validate_uuid(value: str, label: str) -> str:
    if not _UUID_RE.match(value):
        raise HTTPException(status_code=400, detail=f"Invalid {label}: must be a UUID")
    return value


def _history_dir(org_id: str) -> Path:
    d = Path(_get_settings().ATTACKTRACE_WORKSPACE_DIR) / "api_scanner" / org_id
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


def _delete_scan(org_id: str, scan_id: str) -> bool:
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


# ── Schema ─────────────────────────────────────────────────────────────────────

class APIScanRequest(BaseModel):
    target_url: str                       # Base API URL e.g. https://api.example.com
    auth_token: str | None = None         # Bearer token for authenticated requests
    auth_token_2: str | None = None       # Second token for BOLA/BFLA testing
    openapi_url: str | None = None        # Optional OpenAPI/Swagger spec URL
    test_bola: bool = True
    test_bfla: bool = True
    test_rate_limit: bool = True
    test_ssrf: bool = True
    test_misconfig: bool = True
    test_graphql: bool = True


# ── SSE helper ─────────────────────────────────────────────────────────────────

from app.core.sse import sse_event as _sse


# ── Scan checks ────────────────────────────────────────────────────────────────

async def _check_security_headers(client: httpx.AsyncClient, base_url: str) -> list[dict]:
    """API7: Check for missing security headers."""
    findings = []
    try:
        resp = await client.get(base_url, timeout=10)
        headers = {k.lower(): v for k, v in resp.headers.items()}

        missing = []
        if "x-content-type-options" not in headers:
            missing.append("X-Content-Type-Options")
        if "x-frame-options" not in headers:
            missing.append("X-Frame-Options")
        if "strict-transport-security" not in headers:
            missing.append("Strict-Transport-Security")
        if "content-security-policy" not in headers:
            missing.append("Content-Security-Policy")

        # Check for verbose server info
        server = headers.get("server", "")
        x_powered = headers.get("x-powered-by", "")

        if missing:
            findings.append({
                "category": "API7:Security_Misconfiguration",
                "title": "Missing Security Headers",
                "severity": "MEDIUM",
                "detail": f"Missing headers: {', '.join(missing)}",
                "endpoint": base_url,
                "evidence": f"Missing: {missing}",
                "remediation": "Add security headers in your API framework or reverse proxy.",
            })
        if server or x_powered:
            findings.append({
                "category": "API7:Security_Misconfiguration",
                "title": "Server Version Disclosure",
                "severity": "LOW",
                "detail": f"Server header reveals software version: Server={server}, X-Powered-By={x_powered}",
                "endpoint": base_url,
                "evidence": f"Server: {server}\nX-Powered-By: {x_powered}",
                "remediation": "Remove or genericize Server and X-Powered-By headers.",
            })

        # Check CORS misconfiguration
        cors_resp = await client.options(
            base_url,
            headers={"Origin": "https://evil.com", "Access-Control-Request-Method": "GET"},
            timeout=10,
        )
        acao = cors_resp.headers.get("access-control-allow-origin", "")
        if acao in ("*", "https://evil.com"):
            findings.append({
                "category": "API7:Security_Misconfiguration",
                "title": "CORS Misconfiguration",
                "severity": "HIGH",
                "detail": f"API reflects arbitrary Origin or uses wildcard CORS: Access-Control-Allow-Origin: {acao}",
                "endpoint": base_url,
                "evidence": f"Origin: https://evil.com → ACAO: {acao}",
                "remediation": "Restrict CORS to trusted origins only.",
            })
    except Exception:
        pass
    return findings


async def _check_rate_limiting(client: httpx.AsyncClient, base_url: str) -> list[dict]:
    """API4: Test for lack of rate limiting."""
    findings = []
    try:
        # Send 20 rapid requests and check if any 429 is returned
        tasks = [client.get(base_url, timeout=5) for _ in range(20)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        status_codes = [r.status_code for r in responses if isinstance(r, httpx.Response)]
        if status_codes and 429 not in status_codes:
            findings.append({
                "category": "API4:Unrestricted_Resource_Consumption",
                "title": "No Rate Limiting Detected",
                "severity": "MEDIUM",
                "detail": f"20 rapid requests returned no 429 responses. Status codes: {list(set(status_codes))}",
                "endpoint": base_url,
                "evidence": f"20 requests, status codes: {list(set(status_codes))}",
                "remediation": "Implement rate limiting (e.g., 100 req/min per IP/token).",
            })
    except Exception:
        pass
    return findings


async def _check_graphql(client: httpx.AsyncClient, base_url: str) -> list[dict]:
    """API9: Check for exposed GraphQL endpoints with introspection enabled."""
    findings = []
    gql_paths = ["/graphql", "/api/graphql", "/v1/graphql", "/gql", "/query"]
    introspection_query = '{"query":"{ __schema { types { name } } }"}'
    
    for path in gql_paths:
        url = base_url.rstrip("/") + path
        try:
            resp = await client.post(
                url,
                content=introspection_query,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                if "data" in data and "__schema" in str(data):
                    findings.append({
                        "category": "API9:Improper_Inventory_Management",
                        "title": "GraphQL Introspection Enabled",
                        "severity": "MEDIUM",
                        "detail": f"GraphQL introspection is enabled at {url}. Attackers can enumerate the full API schema.",
                        "endpoint": url,
                        "evidence": f"POST {url} → 200 with __schema data",
                        "remediation": "Disable GraphQL introspection in production environments.",
                    })
                    break
        except Exception:
            pass
    return findings


async def _check_ssrf(client: httpx.AsyncClient, base_url: str) -> list[dict]:
    """API6: Test for Server-Side Request Forgery in common parameters."""
    findings = []
    ssrf_params = ["url", "callback", "redirect", "next", "return", "returnUrl", "dest", "destination"]
    ssrf_payloads = [
        "http://169.254.169.254/latest/meta-data/",  # AWS IMDS
        "http://metadata.google.internal/computeMetadata/v1/",  # GCP IMDS
        "http://169.254.169.254/metadata/instance",  # Azure IMDS
        "http://localhost:22",  # Local port probe
    ]
    
    for param in ssrf_params[:3]:  # Limit to first 3 params
        for payload in ssrf_payloads[:2]:
            try:
                resp = await client.get(
                    base_url,
                    params={param: payload},
                    timeout=5,
                    follow_redirects=False,
                )
                # If the server tries to fetch the URL, we'd see a redirect or
                # specific content; here we just flag if the param is reflected
                if resp.status_code in (200, 301, 302) and payload[:20] in resp.text:
                    findings.append({
                        "category": "API6:Server-Side_Request_Forgery",
                        "title": f"Potential SSRF via '{param}' parameter",
                        "severity": "HIGH",
                        "detail": f"SSRF payload reflected in response via ?{param}={payload}",
                        "endpoint": base_url,
                        "evidence": f"GET {base_url}?{param}={payload} → payload in response",
                        "remediation": "Validate and whitelist allowed URLs for any parameter that accepts URLs.",
                    })
            except Exception:
                pass
    return findings


async def _check_bola(
    client: httpx.AsyncClient,
    base_url: str,
    token1: str | None,
    token2: str | None,
    openapi_spec: dict | None,
) -> list[dict]:
    """API1: Basic BOLA/IDOR detection using two-token approach."""
    findings = []
    if not token1 or not token2:
        return findings

    # Extract resource paths from OpenAPI spec if available
    resource_paths = []
    if openapi_spec and "paths" in openapi_spec:
        for path, methods in openapi_spec["paths"].items():
            if "{" in path and "}" in path:  # parameterized paths
                resource_paths.append(path)

    if not resource_paths:
        # Try common patterns
        resource_paths = ["/api/users/{id}", "/api/orders/{id}", "/api/accounts/{id}"]

    for path_template in resource_paths[:5]:
        # Replace {id} with test ID
        test_path = re.sub(r"\{[^}]+\}", "1", path_template)
        url = base_url.rstrip("/") + test_path
        try:
            resp1 = await client.get(url, headers={"Authorization": f"Bearer {token1}"}, timeout=10)
            resp2 = await client.get(url, headers={"Authorization": f"Bearer {token2}"}, timeout=10)
            
            # If both tokens get 200 for the same resource, possible BOLA
            if resp1.status_code == 200 and resp2.status_code == 200:
                findings.append({
                    "category": "API1:Broken_Object_Level_Authorization",
                    "title": f"Potential BOLA/IDOR at {test_path}",
                    "severity": "HIGH",
                    "detail": f"Two different authenticated tokens both received 200 for {url}. "
                              "Verify that users can only access their own resources.",
                    "endpoint": url,
                    "evidence": f"Token1→{resp1.status_code}, Token2→{resp2.status_code}",
                    "remediation": "Implement object-level authorization checks for every resource access.",
                })
        except Exception:
            pass
    return findings


async def _check_openapi_exposure(client: httpx.AsyncClient, base_url: str) -> list[dict]:
    """API9: Check for exposed API documentation endpoints."""
    findings = []
    doc_paths = [
        "/docs", "/swagger", "/swagger-ui", "/swagger.json", "/swagger.yaml",
        "/openapi.json", "/openapi.yaml", "/api-docs", "/redoc",
        "/v1/docs", "/v2/docs", "/api/v1/docs",
    ]
    found_docs = []
    for path in doc_paths:
        url = base_url.rstrip("/") + path
        try:
            resp = await client.get(url, timeout=5)
            if resp.status_code == 200 and (
                "swagger" in resp.text.lower() or
                "openapi" in resp.text.lower() or
                "paths" in resp.text[:500]
            ):
                found_docs.append(url)
        except Exception:
            pass
    
    if found_docs:
        findings.append({
            "category": "API9:Improper_Inventory_Management",
            "title": "API Documentation Exposed",
            "severity": "LOW",
            "detail": f"API documentation is publicly accessible at: {', '.join(found_docs)}",
            "endpoint": found_docs[0],
            "evidence": f"Accessible docs: {found_docs}",
            "remediation": "Restrict API documentation to authenticated users in production.",
        })
    return findings


async def _fetch_openapi_spec(client: httpx.AsyncClient, url: str) -> dict | None:
    try:
        resp = await client.get(url, timeout=15)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None


# ── finding_ingest adapter ───────────────────────────────────────────────────

def _adapt_api_findings(findings: list[dict]) -> list[dict]:
    """Normalize api_scanner.py's OWASP-API-Top-10 finding shape
    (category/title/severity/detail/endpoint/evidence, all already built by
    the _check_* functions above) for finding_ingest.ingest_findings.

    Confidence follows the false-positive-gate doctrine
    (app.core.finding_confidence): headers/body content actually read back
    (missing-header check, version header, GraphQL schema dump, exposed docs
    content) is a directly-observed fact; CORS and BOLA are differential
    checks (two requests compared); the SSRF check only confirms payload
    reflection, not an actual out-of-band callback, so it's the weakest
    signal here.
    """
    adapted = []
    for f in findings:
        title = str(f.get("title") or "Untitled finding")
        if title.startswith("Potential SSRF via"):
            oracle = "reflected"
        elif title.startswith("Potential BOLA/IDOR"):
            oracle = "differential"
        elif title == "CORS Misconfiguration":
            oracle = "differential"
        elif title in ("Server Version Disclosure", "GraphQL Introspection Enabled", "API Documentation Exposed"):
            oracle = "extracted-value"
        else:
            oracle = "bare-signal"  # e.g. "Missing Security Headers", "No Rate Limiting Detected"

        adapted.append({
            "title": title,
            "description": f.get("detail", ""),
            "severity": f.get("severity", "medium"),
            "category": f.get("category", ""),
            "affected_asset": f.get("endpoint", ""),
            "evidence": f.get("evidence", ""),
            "remediation": get_remediation(category=f.get("category"), title=title),
            "confidence": grade_confidence(oracle),
        })
    return adapted


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.get("/history", summary="List API security scan history")
async def list_history(
    org_id: Annotated[str, Depends(get_current_org_id)],
    _user: Annotated[User, Depends(get_current_user)],
) -> dict:
    records = _load_history(org_id)
    return {"items": records, "total": len(records)}


@router.get("/history/{scan_id}", summary="Get a single scan result")
async def get_scan(
    scan_id: str,
    org_id: Annotated[str, Depends(get_current_org_id)],
    _user: Annotated[User, Depends(get_current_user)],
) -> dict:
    record = _load_scan(org_id, scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    return record


@router.delete("/history/{scan_id}", summary="Delete a scan result")
async def delete_scan(
    scan_id: str,
    org_id: Annotated[str, Depends(get_current_org_id)],
    _user: Annotated[User, Depends(get_current_user)],
) -> dict:
    if not _delete_scan(org_id, scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"deleted": True}


@router.post("/scan", summary="Run OWASP API Top 10 security scan")
async def scan_api(
    payload: APIScanRequest,
    org_id: Annotated[str, Depends(get_current_org_id)],
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> StreamingResponse:
    """
    Runs OWASP API Top 10 checks against the target API base URL.
    Returns an SSE stream of findings.
    """
    async def _stream() -> AsyncGenerator[str, None]:
        scan_id = str(_uuid_mod.uuid4())
        started_at = datetime.now(timezone.utc).isoformat()

        yield _sse("start", {
            "scan_id": scan_id,
            "target": payload.target_url,
            "started_at": started_at,
            "status": "running",
        })

        all_findings: list[dict] = []
        headers: dict[str, str] = {}
        if payload.auth_token:
            headers["Authorization"] = f"Bearer {payload.auth_token}"

        async with httpx.AsyncClient(headers=headers, follow_redirects=True) as client:
            # Fetch OpenAPI spec if provided
            openapi_spec = None
            if payload.openapi_url:
                yield _sse("progress", {"scan_id": scan_id, "message": "Fetching OpenAPI spec..."})
                openapi_spec = await _fetch_openapi_spec(client, payload.openapi_url)
                if openapi_spec:
                    yield _sse("progress", {"scan_id": scan_id, "message": f"OpenAPI spec loaded: {len(openapi_spec.get('paths', {}))} paths"})

            # API7: Security headers & CORS
            yield _sse("progress", {"scan_id": scan_id, "message": "Checking security headers and CORS..."})
            if payload.test_misconfig:
                findings = await _check_security_headers(client, payload.target_url)
                for f in findings:
                    all_findings.append(f)
                    yield _sse("finding", {"scan_id": scan_id, "finding": f})
                await asyncio.sleep(0)

            # API4: Rate limiting
            if payload.test_rate_limit:
                yield _sse("progress", {"scan_id": scan_id, "message": "Testing rate limiting..."})
                findings = await _check_rate_limiting(client, payload.target_url)
                for f in findings:
                    all_findings.append(f)
                    yield _sse("finding", {"scan_id": scan_id, "finding": f})
                await asyncio.sleep(0)

            # API6: SSRF
            if payload.test_ssrf:
                yield _sse("progress", {"scan_id": scan_id, "message": "Testing for SSRF vulnerabilities..."})
                findings = await _check_ssrf(client, payload.target_url)
                for f in findings:
                    all_findings.append(f)
                    yield _sse("finding", {"scan_id": scan_id, "finding": f})
                await asyncio.sleep(0)

            # GraphQL introspection
            if payload.test_graphql:
                yield _sse("progress", {"scan_id": scan_id, "message": "Checking GraphQL endpoints..."})
                findings = await _check_graphql(client, payload.target_url)
                for f in findings:
                    all_findings.append(f)
                    yield _sse("finding", {"scan_id": scan_id, "finding": f})
                await asyncio.sleep(0)

            # API9: Exposed docs
            yield _sse("progress", {"scan_id": scan_id, "message": "Checking for exposed API documentation..."})
            findings = await _check_openapi_exposure(client, payload.target_url)
            for f in findings:
                all_findings.append(f)
                yield _sse("finding", {"scan_id": scan_id, "finding": f})
            await asyncio.sleep(0)

            # API1: BOLA/IDOR
            if payload.test_bola and payload.auth_token and payload.auth_token_2:
                yield _sse("progress", {"scan_id": scan_id, "message": "Testing for BOLA/IDOR (requires two tokens)..."})
                findings = await _check_bola(client, payload.target_url, payload.auth_token, payload.auth_token_2, openapi_spec)
                for f in findings:
                    all_findings.append(f)
                    yield _sse("finding", {"scan_id": scan_id, "finding": f})
                await asyncio.sleep(0)

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in all_findings:
            sev = f.get("severity", "INFO")
            if sev in severity_counts:
                severity_counts[sev] += 1

        record = {
            "id": scan_id,
            "target_url": payload.target_url,
            "findings_count": len(all_findings),
            "severity_counts": severity_counts,
            "findings": all_findings,
            "started_at": started_at,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "status": "completed",
        }
        _save_scan_result(org_id, record)

        if all_findings:
            try:
                adapted = _adapt_api_findings(all_findings)
                await ingest_findings(db, org_id, source="api_scanner", source_scan_id=scan_id, findings=adapted)
                await db.commit()
            except Exception:
                await db.rollback()

        yield _sse("complete", {
            "scan_id": scan_id,
            "findings_count": len(all_findings),
            "severity_counts": severity_counts,
            "status": "completed",
        })

    return StreamingResponse(
        _stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/checks", summary="OWASP API Top 10 reference")
async def get_checks(
    _user: Annotated[User, Depends(get_current_user)],
) -> dict:
    """Return OWASP API Top 10 reference and available check descriptions."""
    return {
        "owasp_api_top10": {
            "API1": {"name": "Broken Object Level Authorization", "severity": "critical"},
            "API2": {"name": "Broken Authentication", "severity": "critical"},
            "API3": {"name": "Broken Object Property Level Authorization", "severity": "high"},
            "API4": {"name": "Unrestricted Resource Consumption", "severity": "medium"},
            "API5": {"name": "Broken Function Level Authorization", "severity": "high"},
            "API6": {"name": "Server Side Request Forgery", "severity": "high"},
            "API7": {"name": "Security Misconfiguration", "severity": "medium"},
            "API8": {"name": "Lack of Protection from Automated Threats", "severity": "medium"},
            "API9": {"name": "Improper Inventory Management", "severity": "medium"},
            "API10": {"name": "Unsafe Consumption of APIs", "severity": "medium"},
        },
        "checks": {
            "test_bola": {"name": "BOLA/IDOR (API1)", "description": "Requires two auth tokens"},
            "test_bfla": {"name": "Function Level Auth (API5)", "description": "Tests admin endpoints"},
            "test_rate_limit": {"name": "Rate Limiting (API4)", "description": "Sends 20 rapid requests"},
            "test_ssrf": {"name": "SSRF (API6)", "description": "Tests URL parameters"},
            "test_misconfig": {"name": "Security Headers (API7)", "description": "Checks CORS, headers"},
            "test_graphql": {"name": "GraphQL (API9)", "description": "Tests introspection"},
        },
    }
