"""
AI-powered endpoints: finding triage, natural language search, executive summary, ticket generation.
"""

from typing import Annotated, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.dependencies import get_current_org_id, get_current_user, require_tool
from app.models.db.asset import Asset
from app.models.db.finding import Finding, FindingSeverity
from app.models.db.org import Organization
from app.models.db.scan import ScanJob, ScanStatus
from app.models.db.user import User
from app.services.ai_service import (
    bulk_triage_findings,
    generate_exec_summary,
    generate_remediation_ticket,
    get_org_ai_config,
    nl_to_filter,
    triage_finding,
)

settings = get_settings()
router = APIRouter(prefix="/ai", tags=["AI"])

FINDING_FILTER_SCHEMA = {
    "scan_job_id": "string (UUID)",
    "severity": "string: critical|high|medium|low|info",
    "status": "string: open|in_progress|remediated|accepted_risk|false_positive",
    "category": "string (partial match)",
    "has_cve": "boolean",
    "min_cvss": "float 0-10",
    "suppressed": "boolean",
    "false_positive": "boolean",
}

ASSET_FILTER_SCHEMA = {
    "asset_type": "string: domain|subdomain|ip|webapp|cloud",
    "scan_job_id": "string (UUID)",
    "search": "string (partial match on value)",
    "min_risk_score": "float 0-10",
    "max_risk_score": "float 0-10",
    "is_active": "boolean",
    "tags": "comma-separated string",
}


class TriageRequest(BaseModel):
    finding_id: str
    include_asset_context: bool = True


class BulkTriageRequest(BaseModel):
    scan_job_id: str
    force_retriage: bool = False
    max_findings: int = 100


class NLSearchRequest(BaseModel):
    query: str
    target: str = "findings"  # "findings" | "assets"


class ExecSummaryRequest(BaseModel):
    scan_job_id: str
    compare_with_scan_id: Optional[str] = None


class TicketRequest(BaseModel):
    finding_id: str


async def _check_ai_configured(org_id, db) -> dict:
    """Resolve org AI config and raise 503 if no API key is available."""
    ai_config = await get_org_ai_config(org_id, db)
    if not ai_config.get("api_key"):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": {
                    "code": "AI_NOT_CONFIGURED",
                    "message": (
                        "No Anthropic API key configured. "
                        "Go to Settings → Integrations → Anthropic Claude to add your key, "
                        "or contact your administrator."
                    ),
                }
            },
        )
    return ai_config


@router.post(
    "/triage",
    summary="AI triage a single finding",
    description=(
        "Uses Claude to analyze a finding, validate severity, "
        "detect false positives, and generate remediation reasoning."
    ),
)
async def triage_finding_endpoint(
    payload: TriageRequest,
    current_user: Annotated[User, Depends(require_tool("ai_triage"))],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    ai_config = await _check_ai_configured(org_id, db)

    try:
        finding_id = UUID(payload.finding_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"code": "INVALID_UUID", "message": "Invalid finding_id"}},
        )

    result = await db.execute(
        select(Finding).where(Finding.id == finding_id, Finding.org_id == org_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "FINDING_NOT_FOUND", "message": "Finding not found"}},
        )

    # Load asset context
    asset_ctx = {}
    if payload.include_asset_context and finding.asset_id:
        asset_result = await db.execute(select(Asset).where(Asset.id == finding.asset_id))
        asset = asset_result.scalar_one_or_none()
        if asset:
            asset_ctx = {
                "type": asset.asset_type.value,
                "value": asset.value,
                "risk_score": asset.risk_score,
                "metadata": asset.metadata_ or {},
            }

    # Load org context
    org_result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = org_result.scalar_one_or_none()
    org_ctx = {"plan": org.plan.value if org else "unknown"}

    try:
        triage_result = await triage_finding(finding, asset_ctx, org_ctx, ai_config=ai_config)
    except RuntimeError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": {"code": "AI_ERROR", "message": str(e)}},
        )

    # Persist AI results back to finding
    ai_sev = triage_result.get("severity", finding.severity.value)
    try:
        finding.ai_severity = FindingSeverity(ai_sev)
    except ValueError:
        finding.ai_severity = finding.severity

    finding.ai_reasoning = triage_result.get("reasoning", "")
    finding.ai_confidence = float(triage_result.get("confidence", 0.0))

    from datetime import datetime, timezone
    finding.ai_triaged_at = datetime.now(timezone.utc)
    db.add(finding)
    await db.flush()

    return {"finding_id": payload.finding_id, **triage_result}


@router.post(
    "/triage/bulk",
    summary="Bulk AI triage all findings in a scan",
    description="Queues AI triage for all un-triaged findings in a completed scan.",
)
async def bulk_triage_endpoint(
    payload: BulkTriageRequest,
    current_user: Annotated[User, Depends(require_tool("ai_triage"))],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    await _check_ai_configured(org_id, db)

    try:
        scan_job_id = UUID(payload.scan_job_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"code": "INVALID_UUID", "message": "Invalid scan_job_id"}},
        )

    # Verify scan belongs to org
    scan_result = await db.execute(
        select(ScanJob).where(ScanJob.id == scan_job_id, ScanJob.org_id == org_id)
    )
    scan_job = scan_result.scalar_one_or_none()
    if not scan_job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "SCAN_NOT_FOUND", "message": "Scan not found"}},
        )

    # Queue background task via Celery
    from app.workers.scan_worker import triage_scan_findings
    task = triage_scan_findings.delay(str(scan_job_id))

    return {
        "task_id": task.id,
        "status": "queued",
        "message": f"AI triage queued for scan {scan_job_id}",
    }


@router.post(
    "/search",
    summary="Natural language search for findings or assets",
    description=(
        "Translates a natural language query into a structured filter. "
        "Example: 'show me critical CVE findings on login pages'"
    ),
)
async def nl_search_endpoint(
    payload: NLSearchRequest,
    current_user: Annotated[User, Depends(require_tool("ai_triage"))],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    ai_config = await _check_ai_configured(org_id, db)

    if payload.target not in ("findings", "assets"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"code": "INVALID_TARGET", "message": "target must be 'findings' or 'assets'"}},
        )

    schema = FINDING_FILTER_SCHEMA if payload.target == "findings" else ASSET_FILTER_SCHEMA

    try:
        filter_dict = await nl_to_filter(payload.query, schema, ai_config=ai_config)
    except RuntimeError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": {"code": "AI_ERROR", "message": str(e)}},
        )

    return {
        "query": payload.query,
        "target": payload.target,
        "filter": filter_dict,
    }


@router.post(
    "/summarize",
    summary="Generate executive summary for a completed scan",
    description=(
        "Generates a 3-bullet markdown executive summary suitable for non-technical stakeholders. "
        "Optionally compare with a previous scan to highlight changes."
    ),
)
async def summarize_scan_endpoint(
    payload: ExecSummaryRequest,
    current_user: Annotated[User, Depends(require_tool("ai_triage"))],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    pass  # generate_exec_summary is template-based; no API key required

    try:
        scan_job_id = UUID(payload.scan_job_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"code": "INVALID_UUID", "message": "Invalid scan_job_id"}},
        )

    scan_result = await db.execute(
        select(ScanJob).where(ScanJob.id == scan_job_id, ScanJob.org_id == org_id)
    )
    scan_job = scan_result.scalar_one_or_none()
    if not scan_job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "SCAN_NOT_FOUND", "message": "Scan not found"}},
        )

    if scan_job.status != ScanStatus.COMPLETED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"code": "SCAN_NOT_COMPLETE", "message": "Scan must be completed"}},
        )

    # Load comparison diff if requested
    diff = None
    if payload.compare_with_scan_id:
        try:
            other_id = UUID(payload.compare_with_scan_id)
            other_result = await db.execute(
                select(ScanJob).where(ScanJob.id == other_id, ScanJob.org_id == org_id)
            )
            other_job = other_result.scalar_one_or_none()
            if other_job and other_job.status == ScanStatus.COMPLETED:
                from app.services.change_detection import compare_scan_jobs
                diff_obj = compare_scan_jobs(other_job, scan_job)
                diff = diff_obj.to_dict()
        except Exception:
            pass

    try:
        summary = await generate_exec_summary(scan_job, diff)
    except RuntimeError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": {"code": "AI_ERROR", "message": str(e)}},
        )

    return {
        "scan_job_id": str(scan_job_id),
        "summary": summary,
        "has_comparison": diff is not None,
    }


@router.post(
    "/ticket",
    summary="Generate Jira-ready remediation ticket for a finding",
    description="Creates a structured ticket with summary, description, priority, labels, and acceptance criteria.",
)
async def generate_ticket_endpoint(
    payload: TicketRequest,
    current_user: Annotated[User, Depends(require_tool("ai_triage"))],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    pass  # generate_remediation_ticket is template-based; no API key required

    try:
        finding_id = UUID(payload.finding_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"code": "INVALID_UUID", "message": "Invalid finding_id"}},
        )

    result = await db.execute(
        select(Finding).where(Finding.id == finding_id, Finding.org_id == org_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "FINDING_NOT_FOUND", "message": "Finding not found"}},
        )

    # Get technologies from asset metadata
    technologies = []
    if finding.asset_id:
        asset_result = await db.execute(select(Asset).where(Asset.id == finding.asset_id))
        asset = asset_result.scalar_one_or_none()
        if asset and asset.metadata_:
            techs = asset.metadata_.get("technologies", [])
            technologies = [t.get("name", "") for t in techs if t.get("name")]

    try:
        ticket = await generate_remediation_ticket(finding, technologies)
    except RuntimeError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": {"code": "AI_ERROR", "message": str(e)}},
        )

    return {"finding_id": str(finding_id), "ticket": ticket}


@router.get(
    "/activity/stream",
    summary="Live feed of every AI/LLM call made in this org",
    description=(
        "Server-Sent Events stream of every AI call anywhere in the platform "
        "(triage, Attack Suite planning, the autonomous agent, the AI/LLM "
        "scanner's grader, etc.) as it happens — provider/model, the full "
        "request sent, the full response, latency, success/failure. Live-only: "
        "nothing is persisted or replayed on reconnect, same as the Attack "
        "Suite AI Agent's transcript. Any org member can watch — this is a "
        "visibility feature, not a privileged action."
    ),
)
async def stream_ai_activity(
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> StreamingResponse:
    from app.services.ai_activity import stream_activity
    return StreamingResponse(
        stream_activity(str(org_id), request),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive",
                 "X-Accel-Buffering": "no"},
    )
