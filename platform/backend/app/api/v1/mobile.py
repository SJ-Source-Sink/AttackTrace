"""
Mobile Scanner proxy — forwards authenticated requests to the MSRA sidecar service.

MSRA (Mobile Security Review Assistant) runs as a separate Flask service on MSRA_URL.
All routes here are auth-gated: only authenticated AttackTrace users can reach MSRA.

Proxied endpoints:
  GET  /mobile/scans                    — scan list
  GET  /mobile/scans/{scan_id}          — scan detail + findings
  GET  /mobile/scans/{scan_id}/findings — findings list
  GET  /mobile/scans/{scan_id}/status   — scan progress
  POST /mobile/upload                   — upload APK/IPA/JAR/EXE
  POST /mobile/scans/{scan_id}/dynamic  — trigger dynamic analysis
  GET  /mobile/scans/{scan_id}/dynamic/{job_id} — dynamic job status
  GET  /mobile/scans/{scan_id}/export/{fmt}     — download export
  PATCH /mobile/scans/{scan_id}/findings/{fid}/triage — update triage
  DELETE /mobile/scans/{scan_id}        — delete scan
  GET  /mobile/rules                    — pattern/rule list
  POST /mobile/rules                    — create custom rule
  PUT  /mobile/rules/{rule_id}          — update rule
  DELETE /mobile/rules/{rule_id}        — delete rule
  PATCH /mobile/rules/{rule_id}/toggle  — enable/disable rule
  GET  /mobile/rules/stats              — pattern count per platform
  GET  /mobile/adb-devices              — connected ADB devices
  POST /mobile/ai-triage                — AI triage (generate-poc / test-ai)
  GET  /mobile/health                   — MSRA health check
"""

import hashlib
import logging
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, Response, UploadFile, status
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.config import get_settings
from app.core.database import get_db
from app.core.dependencies import get_current_user, get_current_org_id
from app.models.db.user import User
from app.models.db.finding import Finding, FindingSeverity, FindingStatus

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/mobile", tags=["Mobile Scanner"])
settings = get_settings()

_TIMEOUT = httpx.Timeout(connect=5.0, read=300.0, write=300.0, pool=5.0)

# Headers that must not be forwarded to MSRA
_HOP_BY_HOP = {
    "host", "connection", "keep-alive", "transfer-encoding",
    "te", "trailers", "upgrade", "proxy-authorization",
    "authorization",  # strip our JWT — MSRA has no auth
}


async def _msra_request(
    method: str,
    path: str,
    *,
    params: dict | None = None,
    json: dict | None = None,
    content: bytes | None = None,
    headers: dict | None = None,
) -> httpx.Response:
    url = f"{settings.MSRA_URL}{path}"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.request(
                method,
                url,
                params=params,
                json=json,
                content=content,
                headers=headers or {},
            )
        return resp
    except httpx.ConnectError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": {"code": "MSRA_UNAVAILABLE", "message": "Mobile Scanner service is not reachable. Make sure MSRA is running."}},
        )
    except httpx.TimeoutException:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail={"error": {"code": "MSRA_TIMEOUT", "message": "Mobile Scanner service timed out."}},
        )


def _proxy_response(resp: httpx.Response) -> Response:
    """Convert an httpx response to a FastAPI response, stripping hop-by-hop headers."""
    forward_headers = {
        k: v for k, v in resp.headers.items()
        if k.lower() not in _HOP_BY_HOP
    }
    return Response(
        content=resp.content,
        status_code=resp.status_code,
        headers=forward_headers,
        media_type=resp.headers.get("content-type", "application/json"),
    )


# ── Health ────────────────────────────────────────────────────────────────────

@router.get("/health", summary="Check MSRA service reachability")
async def mobile_health(
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict:
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(3.0)) as client:
            resp = await client.get(f"{settings.MSRA_URL}/api/dashboard/stats")
        return {"status": "ok", "msra_reachable": resp.status_code < 500}
    except Exception:
        return {"status": "degraded", "msra_reachable": False}


# ── Dashboard stats ───────────────────────────────────────────────────────────

@router.get("/stats", summary="MSRA dashboard statistics")
async def mobile_stats(
    current_user: Annotated[User, Depends(get_current_user)],
) -> Response:
    resp = await _msra_request("GET", "/api/dashboard/stats")
    return _proxy_response(resp)


# ── Scans ─────────────────────────────────────────────────────────────────────

@router.get("/scans", summary="List mobile scans")
async def list_scans(
    current_user: Annotated[User, Depends(get_current_user)],
) -> Response:
    # MSRA doesn't have a dedicated list endpoint — we parse dashboard stats
    # which includes the full scan list in the `scans` key.
    resp = await _msra_request("GET", "/api/dashboard/stats")
    return _proxy_response(resp)


@router.get("/scans/{scan_id}/findings", summary="Get findings for a scan")
async def get_findings(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
) -> Response:
    resp = await _msra_request("GET", f"/api/scans/{scan_id}/findings")
    return _proxy_response(resp)


@router.get("/scans/{scan_id}/status", summary="Get scan progress")
async def get_scan_status(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
) -> Response:
    resp = await _msra_request("GET", f"/api/scan/{scan_id}/status")
    return _proxy_response(resp)


@router.delete("/scans/{scan_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete a scan")
async def delete_scan(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
) -> None:
    resp = await _msra_request("DELETE", f"/api/scans/{scan_id}")
    if resp.status_code not in (200, 204):
        raise HTTPException(status_code=resp.status_code, detail=resp.text)


# ── Upload ────────────────────────────────────────────────────────────────────

@router.post("/upload", summary="Upload a mobile app file for scanning")
async def upload_file(
    current_user: Annotated[User, Depends(get_current_user)],
    file: UploadFile = File(...),
) -> Response:
    allowed_suffixes = {".apk", ".apkm", ".xapk", ".ipa", ".jar", ".exe", ".dll"}
    suffix = "." + (file.filename or "").rsplit(".", 1)[-1].lower()
    if suffix not in allowed_suffixes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"code": "INVALID_FILE_TYPE", "message": f"Unsupported file type. Allowed: {', '.join(sorted(allowed_suffixes))}"}},
        )

    _MAX_UPLOAD_BYTES = 500 * 1024 * 1024  # 500 MB
    if file.size and file.size > _MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail={"error": {"code": "FILE_TOO_LARGE", "message": "File exceeds 500 MB limit."}},
        )

    file_bytes = await file.read()
    if len(file_bytes) > _MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail={"error": {"code": "FILE_TOO_LARGE", "message": "File exceeds 500 MB limit."}},
        )

    # Forward as multipart/form-data to MSRA — MSRA expects the field name "apk"
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            resp = await client.post(
                f"{settings.MSRA_URL}/api/upload",
                files={"apk": (file.filename, file_bytes, file.content_type or "application/octet-stream")},
            )
        except httpx.ConnectError:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"error": {"code": "MSRA_UNAVAILABLE", "message": "Mobile Scanner service is not reachable."}},
            )

    return _proxy_response(resp)


# ── Triage ────────────────────────────────────────────────────────────────────

@router.patch("/scans/{scan_id}/findings/{finding_id}/triage", summary="Update finding triage status")
async def triage_finding(
    scan_id: str,
    finding_id: int,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
) -> Response:
    body = await request.json()
    resp = await _msra_request(
        "PATCH",
        f"/api/scans/{scan_id}/findings/{finding_id}/triage",
        json=body,
    )
    return _proxy_response(resp)


# ── Code snippet ──────────────────────────────────────────────────────────────

@router.get("/scans/{scan_id}/findings/{finding_id}/snippet", summary="Get vulnerable code snippet")
async def get_snippet(
    scan_id: str,
    finding_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
) -> Response:
    resp = await _msra_request("GET", f"/api/scans/{scan_id}/findings/{finding_id}/snippet")
    return _proxy_response(resp)


# ── Exports ───────────────────────────────────────────────────────────────────

@router.get("/scans/{scan_id}/export/{fmt}", summary="Export scan findings (pdf|csv|sarif|json)")
async def export_scan(
    scan_id: str,
    fmt: str,
    current_user: Annotated[User, Depends(get_current_user)],
) -> StreamingResponse:
    if fmt not in ("pdf", "csv", "sarif", "json"):
        raise HTTPException(status_code=400, detail="Invalid export format. Use: pdf, csv, sarif, json")

    if fmt == "json":
        # JSON findings come from the findings endpoint
        resp = await _msra_request("GET", f"/api/scans/{scan_id}/findings")
        return StreamingResponse(
            iter([resp.content]),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}.json"'},
        )

    url = f"{settings.MSRA_URL}/api/scans/{scan_id}/export/{fmt}"
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        try:
            async with client.stream("GET", url) as resp:
                headers = {
                    "Content-Disposition": resp.headers.get(
                        "Content-Disposition",
                        f'attachment; filename="scan_{scan_id}.{fmt}"',
                    )
                }
                media_type = resp.headers.get("content-type", "application/octet-stream")
                content = await resp.aread()
        except httpx.ConnectError:
            raise HTTPException(status_code=503, detail="MSRA unavailable")

    return StreamingResponse(
        iter([content]),
        media_type=media_type,
        headers=headers,
    )


# ── Dynamic analysis ──────────────────────────────────────────────────────────

@router.get("/adb-devices", summary="List connected ADB devices")
async def adb_devices(
    current_user: Annotated[User, Depends(get_current_user)],
) -> Response:
    resp = await _msra_request("GET", "/api/dynamic/adb-devices")
    return _proxy_response(resp)


@router.post("/scans/{scan_id}/dynamic", summary="Start dynamic analysis for a finding")
async def start_dynamic(
    scan_id: str,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
) -> Response:
    body = await request.json()
    resp = await _msra_request("POST", "/api/dynamic/verify", json=body)
    return _proxy_response(resp)


@router.get("/dynamic/jobs", summary="List all dynamic analysis jobs")
async def dynamic_jobs(
    current_user: Annotated[User, Depends(get_current_user)],
) -> Response:
    resp = await _msra_request("GET", "/api/dynamic/jobs")
    return _proxy_response(resp)


@router.get("/dynamic/{job_id}", summary="Poll dynamic analysis job")
async def dynamic_job_status(
    job_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
) -> Response:
    resp = await _msra_request("GET", f"/api/dynamic/verify/{job_id}")
    return _proxy_response(resp)


# ── AI ────────────────────────────────────────────────────────────────────────

@router.post("/ai/poc", summary="Generate PoC code for a finding")
async def generate_poc(
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
) -> Response:
    body = await request.json()
    resp = await _msra_request("POST", "/api/generate-poc", json=body)
    return _proxy_response(resp)


# ── Rules / Patterns ──────────────────────────────────────────────────────────

@router.get("/rules/stats", summary="Pattern counts per platform")
async def rule_stats(
    current_user: Annotated[User, Depends(get_current_user)],
) -> Response:
    resp = await _msra_request("GET", "/api/rules/stats")
    return _proxy_response(resp)


@router.get("/rules", summary="List all detection patterns")
async def list_rules(
    current_user: Annotated[User, Depends(get_current_user)],
) -> Response:
    resp = await _msra_request("GET", "/api/rules")
    return _proxy_response(resp)


@router.post("/rules", summary="Create a custom detection rule", status_code=status.HTTP_201_CREATED)
async def create_rule(
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
) -> Response:
    body = await request.json()
    resp = await _msra_request("POST", "/api/rules", json=body)
    return _proxy_response(resp)


@router.put("/rules/{rule_id}", summary="Update a custom rule")
async def update_rule(
    rule_id: str,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
) -> Response:
    body = await request.json()
    resp = await _msra_request("PUT", f"/api/rules/{rule_id}", json=body)
    return _proxy_response(resp)


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete a custom rule")
async def delete_rule(
    rule_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
) -> None:
    await _msra_request("DELETE", f"/api/rules/{rule_id}")


@router.patch("/rules/{rule_id}/toggle", summary="Enable or disable a pattern")
async def toggle_rule(
    rule_id: str,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
) -> Response:
    body = await request.json()
    resp = await _msra_request("PATCH", f"/api/rules/{rule_id}/toggle", json=body)
    return _proxy_response(resp)


# ── MSRA → Central findings sync ──────────────────────────────────────────────

_SEVERITY_MAP = {
    "critical": FindingSeverity.CRITICAL,
    "high":     FindingSeverity.HIGH,
    "medium":   FindingSeverity.MEDIUM,
    "low":      FindingSeverity.LOW,
    "info":     FindingSeverity.INFO,
}


def _msra_dedup_hash(org_id: str, scan_id: str, finding_id: int) -> str:
    key = f"msra|{org_id}|{scan_id}|{finding_id}"
    return hashlib.sha256(key.encode()).hexdigest()


async def _sync_msra_to_db(org_id: str, db: AsyncSession) -> dict:
    """Pull all completed MSRA scans and upsert their findings into the central DB."""
    inserted = 0
    updated = 0
    skipped = 0
    errors = 0

    # Fetch MSRA scan list
    try:
        stats_resp = await _msra_request("GET", "/api/dashboard/stats")
        if stats_resp.status_code != 200:
            return {"error": "MSRA unavailable", "inserted": 0, "updated": 0, "skipped": 0}
        try:
            stats = stats_resp.json()
        except Exception:
            return {"error": "MSRA returned invalid JSON for stats", "inserted": 0, "updated": 0, "skipped": 0}
    except Exception as exc:
        return {"error": str(exc), "inserted": 0, "updated": 0, "skipped": 0}

    scans = stats.get("recent_scans", [])
    done_scans = [s for s in scans if s.get("status") in ("done", "completed")]

    for scan in done_scans:
        scan_id = scan.get("scan_id")
        if not scan_id:
            continue

        # Fetch findings for this MSRA scan
        try:
            findings_resp = await _msra_request("GET", f"/api/scans/{scan_id}/findings")
            if findings_resp.status_code != 200:
                errors += 1
                continue
            try:
                findings_data = findings_resp.json()
            except Exception:
                logger.warning("MSRA returned invalid JSON for scan %s findings", scan_id)
                errors += 1
                continue
        except Exception as exc:
            logger.warning("Failed to fetch MSRA findings for scan %s: %s", scan_id, exc)
            errors += 1
            continue

        msra_findings = findings_data.get("findings", [])
        apk_name = findings_data.get("apk") or scan.get("apk", "")

        for mf in msra_findings:
            fid = mf.get("id")
            if fid is None:
                continue

            dedup = _msra_dedup_hash(org_id, scan_id, fid)

            # Check if already exists
            result = await db.execute(select(Finding).where(Finding.dedup_hash == dedup))
            existing = result.scalar_one_or_none()

            # Map severity
            raw_sev = (mf.get("severity") or "info").lower()
            sev = _SEVERITY_MAP.get(raw_sev, FindingSeverity.INFO)

            # Normalise evidence to dict (MSRA returns it as a dict already)
            evidence = mf.get("evidence")
            if isinstance(evidence, str):
                evidence = {"raw": evidence}

            # CWE list → cve-like array (stored in references; cve stays empty for mobile)
            cwe_list = mf.get("cwe") or []
            if isinstance(cwe_list, str):
                cwe_list = [cwe_list]

            refs = mf.get("references") or []

            if existing is None:
                db.add(Finding(
                    org_id=org_id,
                    scan_job_id=None,
                    source="msra",
                    source_scan_id=scan_id,
                    title=mf.get("title", "Untitled"),
                    description=mf.get("description", ""),
                    severity=sev,
                    category=mf.get("category", ""),
                    affected_asset=apk_name,
                    evidence=evidence,
                    remediation=mf.get("remediation") or "",
                    references=refs,
                    cve=[],
                    status=FindingStatus.OPEN,
                    confidence="certain",
                    dedup_hash=dedup,
                ))
                inserted += 1
            else:
                # Update mutable fields (evidence, remediation, triage_status)
                existing.evidence = evidence
                existing.remediation = mf.get("remediation") or existing.remediation
                # Sync triage status from MSRA → AttackTrace
                msra_triage = mf.get("triage_status", "")
                if msra_triage == "true_positive":
                    existing.false_positive = False
                elif msra_triage == "false_positive":
                    existing.false_positive = True
                    existing.status = FindingStatus.FALSE_POSITIVE
                updated += 1

    try:
        await db.commit()
    except Exception as exc:
        await db.rollback()
        logger.error("MSRA sync commit failed: %s", exc)
        return {"error": str(exc), "inserted": inserted, "updated": updated, "skipped": skipped, "errors": errors + 1}

    return {"inserted": inserted, "updated": updated, "skipped": skipped, "errors": errors}


@router.post("/sync", summary="Sync MSRA findings into central findings DB")
async def sync_msra_findings(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: Annotated[str, Depends(get_current_org_id)],
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await _sync_msra_to_db(str(org_id), db)
    return result
