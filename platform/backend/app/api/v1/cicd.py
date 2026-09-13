"""
CI/CD Scan Gateway — POST /api/v1/cicd/scan
Triggers a scan and waits up to 5 minutes for completion, then returns SARIF 2.1 output.
Designed for GitHub Actions, GitLab CI, Jenkins integration.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings as _get_settings
from app.core.database import get_db
from app.core.dependencies import get_current_org_id, get_current_user
from app.models.db.finding import Finding
from app.models.db.scan import ScanJob, ScanStatus
from app.models.db.user import User
from app.services.scan_service import create_scan, get_scan_by_id
from app.models.schemas.scan import ScanCreate

router = APIRouter(prefix="/cicd", tags=["CI/CD"])

# ── Filesystem history (org-scoped, path-traversal-safe) ─────────────────────

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)


def _validate_uuid(value: str, label: str) -> str:
    if not _UUID_RE.match(value):
        raise HTTPException(status_code=400, detail=f"Invalid {label}: must be a UUID")
    return value


def _history_dir(org_id: str) -> Path:
    d = Path(_get_settings().ATTACKTRACE_WORKSPACE_DIR) / "cicd_gateway" / org_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def _safe_history_path(org_id: str, scan_id: str) -> Path:
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
    path = _safe_history_path(org_id, scan_id)
    if path.exists():
        return json.loads(path.read_text())
    return None


class CICDScanRequest(BaseModel):
    target_domains: list[str]
    intensity: str = "passive"
    timeout_seconds: int = 300  # max 5 min
    fail_on_severity: Optional[str] = "high"  # fail CI if this severity found
    company_name: Optional[str] = None


def _to_sarif(findings: list[Finding], scan_id: str, target: str) -> dict:
    """Convert findings list to SARIF 2.1.0 format."""
    rules = {}
    results = []

    severity_map = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "none",
    }

    for f in findings:
        rule_id = f"AT-{f.title.replace(' ', '-').upper()[:40]}"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description or f.title},
                "helpUri": "https://attacktrace.io/findings",
                "properties": {"tags": ["security", f.severity.value]},
                "defaultConfiguration": {
                    "level": severity_map.get(f.severity.value, "warning")
                },
            }

        results.append({
            "ruleId": rule_id,
            "level": severity_map.get(f.severity.value, "warning"),
            "message": {"text": f.description or f.title},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f.affected_asset or target,
                        "uriBaseId": "%SRCROOT%",
                    }
                }
            }],
            "properties": {
                "severity": f.severity.value,
                "cvss_score": f.cvss_score,
                "affected_asset": f.affected_asset,
                "scan_id": scan_id,
            },
        })

    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "AttackTrace",
                    "version": "1.0.0",
                    "informationUri": "https://attacktrace.io",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": datetime.now(timezone.utc).isoformat(),
            }],
        }],
    }


@router.post(
    "/scan",
    summary="Trigger a CI/CD scan and return SARIF 2.1 output",
    description=(
        "Starts a scan and polls until completion (up to timeout_seconds). "
        "Returns SARIF 2.1 format for GitHub Security tab integration. "
        "Exit code semantics: returns 200 with sarif; check 'ci_failed' field to fail the build."
    ),
)
async def cicd_scan(
    payload: CICDScanRequest,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    # Clamp timeout
    timeout = min(max(payload.timeout_seconds, 30), 600)

    # Create scan
    from app.models.schemas.scan import ScanCreate as _SC
    scan_payload = _SC(
        target_domains=payload.target_domains,
        intensity=payload.intensity,
        company_name=payload.company_name,
    )

    def _get_ip(req: Request) -> str:
        fwd = req.headers.get("X-Forwarded-For")
        if fwd:
            return fwd.split(",")[0].strip()
        return req.client.host if req.client else "unknown"

    job = await create_scan(
        db=db,
        org_id=org_id,
        user_id=current_user.id,
        payload=scan_payload,
        ip_address=_get_ip(request),
    )
    scan_id = job.id

    # Poll until done or timeout
    deadline = asyncio.get_event_loop().time() + timeout
    poll_interval = 5.0

    while asyncio.get_event_loop().time() < deadline:
        await asyncio.sleep(poll_interval)
        # Re-fetch scan from DB
        fresh_job = await get_scan_by_id(db, scan_id, org_id)
        if fresh_job and fresh_job.status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
            break

    # Get final state
    final_job = await get_scan_by_id(db, scan_id, org_id)
    if not final_job:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Fetch findings
    findings_result = await db.execute(
        select(Finding)
        .where(Finding.scan_job_id == scan_id, Finding.org_id == org_id)
        .order_by(Finding.created_at.desc())
    )
    findings = findings_result.scalars().all()

    target = payload.target_domains[0] if payload.target_domains else "unknown"
    sarif = _to_sarif(findings, str(scan_id), target)

    # Determine CI failure
    ci_failed = False
    if payload.fail_on_severity and final_job.status == ScanStatus.COMPLETED:
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        threshold = severity_order.get(payload.fail_on_severity, 1)
        for f in findings:
            if severity_order.get(f.severity.value, 4) <= threshold:
                ci_failed = True
                break

    result = {
        "id": str(scan_id),
        "scan_id": str(scan_id),
        "status": final_job.status.value,
        "target_domains": payload.target_domains,
        "findings_count": len(findings),
        "ci_failed": ci_failed,
        "fail_reason": f"Found findings at or above severity '{payload.fail_on_severity}'" if ci_failed else None,
        "created_at": time.time(),
    }
    _save_scan_result(str(org_id), result)

    return {
        **result,
        "sarif": sarif,
        "github_action_snippet": (
            "# Add to .github/workflows/security.yml:\n"
            "- name: AttackTrace Scan\n"
            "  run: |\n"
            "    curl -X POST $ATTACKTRACE_URL/api/v1/cicd/scan \\\n"
            "      -H 'Authorization: Bearer $ATTACKTRACE_TOKEN' \\\n"
            "      -H 'Content-Type: application/json' \\\n"
            f"      -d '{{\"target_domains\": {json.dumps(payload.target_domains)}, \"intensity\": \"{payload.intensity}\"}}' \\\n"
            "      | tee sarif_output.json\n"
            "- name: Upload SARIF\n"
            "  uses: github/codeql-action/upload-sarif@v3\n"
            "  with:\n"
            "    sarif_file: sarif_output.json\n"
        ),
    }


@router.get("/history", summary="List past CI/CD gateway scans")
async def list_cicd_history(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> dict:
    records = _load_history(str(org_id))
    return {"items": records, "total": len(records)}


@router.get("/history/{scan_id}", summary="Get a past CI/CD gateway scan result")
async def get_cicd_history_item(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> dict:
    record = _load_scan(str(org_id), scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="CI/CD scan record not found")
    return record
