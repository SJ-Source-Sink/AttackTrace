"""
Findings API: list, filter, update lifecycle, add comments, and manage suppressions.
"""

import math
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, List, Optional
from uuid import UUID

from pydantic import BaseModel as _PydanticBaseModel, Field

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dashboard import invalidate_dashboard_cache
from app.core.csv_safety import csv_safe
from app.core.database import get_db
from app.core.dependencies import get_current_org_id, get_current_user
from app.models.db.audit import AuditLog
from app.models.db.finding import (
    Finding,
    FindingComment,
    FindingSeverity,
    FindingStatus,
    FindingSuppression,
)
from app.models.db.suppression_rule import ScanSuppressionRule
from app.models.db.user import OrgMember, User
from app.models.schemas.finding import (
    FindingCommentCreate,
    FindingCommentResponse,
    FindingCreate,
    FindingFilter,
    FindingResponse,
    FindingUpdate,
)
from app.services.notification_service import push_in_app_notification
from app.services.risk_scoring_service import compute_risk_score
from app.services.sla_service import apply_compliance_tags, compute_sla_deadline

router = APIRouter(prefix="/findings", tags=["Findings"])


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@router.post(
    "",
    response_model=FindingResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a manual finding",
)
async def create_finding(
    payload: FindingCreate,
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> FindingResponse:
    try:
        severity_enum = FindingSeverity(payload.severity)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"code": "INVALID_SEVERITY", "message": f"Invalid severity: {payload.severity}"}},
        )
    try:
        status_enum = FindingStatus(payload.status)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"code": "INVALID_STATUS", "message": f"Invalid status: {payload.status}"}},
        )

    # Auto-compute SLA deadline, risk score, and compliance tags
    sla_deadline = compute_sla_deadline(payload.severity, None)
    risk_score, risk_explanation = compute_risk_score(
        payload.severity,
        payload.cvss_score,
        None,
        False,
        None,
    )
    compliance_tags = apply_compliance_tags(
        payload.title, payload.category, payload.description
    )

    # Resolve assigned_to UUID
    assigned_to_uuid: Optional[UUID] = None
    if payload.assigned_to:
        try:
            assigned_to_uuid = UUID(payload.assigned_to)
        except ValueError:
            pass

    finding = Finding(
        org_id=org_id,
        source="manual",
        title=payload.title,
        description=payload.description,
        severity=severity_enum,
        category=payload.category,
        affected_asset=payload.affected_asset,
        evidence=payload.evidence,
        remediation=payload.remediation,
        references=payload.references,
        cve=payload.cve,
        cvss_score=payload.cvss_score,
        status=status_enum,
        ticket_ref=payload.ticket_ref,
        sla_deadline=sla_deadline,
        risk_score=risk_score,
        risk_explanation=risk_explanation,
        compliance_tags=compliance_tags,
        assigned_to=assigned_to_uuid,
    )
    db.add(finding)
    await db.flush()
    await db.refresh(finding)

    log = AuditLog(
        org_id=org_id,
        user_id=current_user.id,
        action="finding.created",
        resource_type="finding",
        resource_id=str(finding.id),
        before_state=None,
        after_state={"source": "manual", "title": finding.title, "severity": payload.severity},
        ip_address=_get_client_ip(request),
    )
    db.add(log)
    await db.flush()

    background_tasks.add_task(invalidate_dashboard_cache, org_id)

    return FindingResponse.from_orm(finding)


@router.get(
    "/timeline",
    summary="Get daily finding counts by severity for a date range",
)
async def findings_timeline(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
    days: Optional[int] = None,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
) -> dict:
    now = datetime.now(timezone.utc)

    if from_date and to_date:
        try:
            start = datetime.fromisoformat(from_date).replace(tzinfo=timezone.utc)
            end = datetime.fromisoformat(to_date).replace(tzinfo=timezone.utc).replace(
                hour=23, minute=59, second=59
            )
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": {"code": "INVALID_DATE", "message": "Dates must be YYYY-MM-DD"}},
            )
    else:
        lookback = max(1, min(days or 30, 365))
        start = (now - timedelta(days=lookback - 1)).replace(hour=0, minute=0, second=0, microsecond=0)
        end = now

    result = await db.execute(
        select(Finding.severity, Finding.created_at)
        .where(
            Finding.org_id == org_id,
            Finding.created_at >= start,
            Finding.created_at <= end,
        )
        .order_by(Finding.created_at.asc())
    )
    rows = result.all()

    # Build a dict of {date_str: {severity: count}}
    day_map: dict = defaultdict(lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
    totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for row in rows:
        day = row.created_at.strftime("%Y-%m-%d")
        sev = row.severity.value
        day_map[day][sev] += 1
        totals[sev] += 1

    # Fill every calendar day in the range (even if no findings)
    data = []
    current_day = start.replace(hour=0, minute=0, second=0, microsecond=0)
    while current_day.date() <= end.date():
        day_str = current_day.strftime("%Y-%m-%d")
        counts = day_map[day_str]
        data.append({
            "date": day_str,
            "critical": counts["critical"],
            "high": counts["high"],
            "medium": counts["medium"],
            "low": counts["low"],
            "info": counts["info"],
            "total": sum(counts.values()),
        })
        current_day += timedelta(days=1)

    return {
        "data": data,
        "totals": totals,
        "from_date": start.strftime("%Y-%m-%d"),
        "to_date": end.strftime("%Y-%m-%d"),
    }


@router.get(
    "",
    summary="List and filter findings with pagination",
    description=(
        "Supports filtering by severity, status, category, scan, asset, CVE presence, "
        "and free-text search. Scoped to the authenticated organization."
    ),
)
async def list_findings(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
    scan_job_id: Optional[str] = None,
    severity: Optional[List[str]] = Query(None),
    finding_status: Optional[List[str]] = Query(None),
    category: Optional[str] = None,
    search: Optional[str] = None,
    asset_id: Optional[str] = None,
    false_positive: Optional[bool] = None,
    suppressed: Optional[bool] = None,
    has_cve: Optional[bool] = None,
    min_cvss: Optional[float] = None,
    kev_only: Optional[bool] = None,
    confidence: Optional[str] = None,
    overdue: bool = False,
    sort_by: str = "created_at",
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
) -> dict:
    query = select(Finding).where(Finding.org_id == org_id)

    if scan_job_id:
        try:
            query = query.where(Finding.scan_job_id == UUID(scan_job_id))
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": {"code": "INVALID_UUID", "message": "Invalid scan_job_id"}},
            )

    if severity:
        try:
            sev_enums = [FindingSeverity(s) for s in severity]
            query = query.where(Finding.severity.in_(sev_enums))
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": {"code": "INVALID_SEVERITY", "message": str(e)}},
            )

    if finding_status:
        try:
            status_enums = [FindingStatus(s) for s in finding_status]
            query = query.where(Finding.status.in_(status_enums))
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": {"code": "INVALID_STATUS", "message": str(e)}},
            )

    if category:
        query = query.where(Finding.category.ilike(f"%{category}%"))

    if search:
        if len(search) > 200:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": {"code": "INVALID_SEARCH", "message": "Search term too long (max 200 chars)"}},
            )
        # Escape LIKE wildcards to prevent full-table scan abuse
        escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        query = query.where(
            Finding.title.ilike(f"%{escaped}%", escape="\\")
            | Finding.description.ilike(f"%{escaped}%", escape="\\")
        )

    if asset_id:
        try:
            query = query.where(Finding.asset_id == UUID(asset_id))
        except ValueError:
            pass

    if false_positive is not None:
        query = query.where(Finding.false_positive == false_positive)

    if suppressed is not None:
        query = query.where(Finding.suppressed == suppressed)

    if has_cve is True:
        query = query.where(func.array_length(Finding.cve, 1) > 0)
    elif has_cve is False:
        query = query.where(
            (Finding.cve == None) | (func.array_length(Finding.cve, 1) == 0)
        )

    if min_cvss is not None:
        query = query.where(Finding.cvss_score >= min_cvss)

    if kev_only:
        query = query.where(Finding.kev_status == True)

    if confidence:
        query = query.where(Finding.confidence == confidence)

    if overdue:
        query = query.where(Finding.sla_deadline < datetime.now(timezone.utc))

    # Count
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar_one()

    # Sort
    if sort_by == "risk_score":
        order_col = Finding.risk_score.desc().nulls_last()
    elif sort_by == "severity":
        order_col = case(
            (Finding.severity == "critical", 0),
            (Finding.severity == "high", 1),
            (Finding.severity == "medium", 2),
            (Finding.severity == "low", 3),
            (Finding.severity == "info", 4),
            else_=5,
        ).asc()
    elif sort_by == "sla_deadline":
        order_col = Finding.sla_deadline.asc().nulls_last()
    else:
        order_col = Finding.created_at.desc()

    offset = (page - 1) * per_page
    query = query.order_by(order_col).offset(offset).limit(per_page)
    result = await db.execute(query)
    findings = result.scalars().all()

    # Get comment counts in one query
    finding_ids = [f.id for f in findings]
    comment_counts = {}
    if finding_ids:
        cc_result = await db.execute(
            select(FindingComment.finding_id, func.count(FindingComment.id).label("cnt"))
            .where(FindingComment.finding_id.in_(finding_ids))
            .group_by(FindingComment.finding_id)
        )
        comment_counts = {row.finding_id: row.cnt for row in cc_result.all()}

    pages = math.ceil(total / per_page) if per_page > 0 else 0

    return {
        "items": [
            FindingResponse.from_orm(f, comment_counts.get(f.id, 0)).model_dump()
            for f in findings
        ],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": pages,
    }


@router.get(
    "/summary/by-severity",
    summary="Get finding count summary grouped by severity",
)
async def finding_severity_summary(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    scan_job_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
) -> dict:
    query = select(
        Finding.severity,
        func.count(Finding.id).label("count")
    ).where(
        Finding.org_id == org_id,
        Finding.suppressed == False,
        Finding.false_positive == False,
    )

    if scan_job_id:
        try:
            query = query.where(Finding.scan_job_id == UUID(scan_job_id))
        except ValueError:
            pass

    query = query.group_by(Finding.severity)
    result = await db.execute(query)

    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for row in result.all():
        summary[row.severity.value] = row.count

    return summary


@router.get(
    "/summary/kev",
    summary="Get count of KEV (CISA Known Exploited Vulnerabilities) findings for the org",
)
async def kev_summary(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    scan_job_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
) -> dict:
    query = select(func.count(Finding.id)).where(
        Finding.org_id == org_id,
        Finding.kev_status == True,
        Finding.suppressed == False,
        Finding.false_positive == False,
    )
    if scan_job_id:
        try:
            query = query.where(Finding.scan_job_id == UUID(scan_job_id))
        except ValueError:
            pass
    total_kev = (await db.execute(query)).scalar_one()
    return {"kev_findings": total_kev}


@router.get(
    "/export",
    summary="Export findings as CSV, JSON, HTML, or PDF",
)
async def export_findings(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
    fmt: str = "json",
    scan_job_id: Optional[str] = None,
    severity: Optional[str] = None,
    finding_status: Optional[str] = None,
    finding_ids: Optional[str] = None,  # comma-separated finding UUIDs — "export selected"
) -> Any:
    from fastapi.responses import StreamingResponse
    import csv, io

    query = select(Finding).where(Finding.org_id == org_id)
    if finding_ids:
        try:
            id_list = [UUID(i.strip()) for i in finding_ids.split(",") if i.strip()]
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": {"code": "INVALID_UUID", "message": "One or more finding_ids are not valid UUIDs"}},
            )
        query = query.where(Finding.id.in_(id_list))
    if scan_job_id:
        try:
            _export_scan_uuid = UUID(scan_job_id)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": {"code": "INVALID_UUID", "message": "Invalid scan_job_id"}},
            )
        query = query.where(Finding.scan_job_id == _export_scan_uuid)
    if severity:
        query = query.where(Finding.severity == severity)
    if finding_status:
        query = query.where(Finding.status == FindingStatus(finding_status))

    # Hard cap to prevent OOM — export at most 10k findings at once
    result = await db.execute(query.order_by(Finding.created_at.desc()).limit(10_000))
    findings = result.scalars().all()

    if fmt in ("html", "pdf"):
        from app.services.export_service import render_findings_html_async, html_to_pdf_bytes
        from app.models.db.asset import Asset

        # Findings have no screenshot of their own — they inherit the one
        # their linked asset already has, via Finding.asset_id (only reliably
        # populated as of the 2026-09-14 asset-linking fix in
        # scan_worker.py's _persist_session_results — older/unresolved
        # findings simply get no screenshot, not an error).
        asset_ids = {f.asset_id for f in findings if f.asset_id}
        screenshot_urls: dict = {}
        if asset_ids:
            asset_rows = await db.execute(
                select(Asset.id, Asset.screenshot_url).where(Asset.id.in_(asset_ids), Asset.screenshot_url.isnot(None))
            )
            shots_by_asset = {row[0]: row[1] for row in asset_rows.all()}
            screenshot_urls = {
                f.id: shots_by_asset[f.asset_id] for f in findings if f.asset_id in shots_by_asset
            }

        html = await render_findings_html_async(
            findings, datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), screenshot_urls=screenshot_urls,
        )
        if fmt == "html":
            return StreamingResponse(
                iter([html]), media_type="text/html",
                headers={"Content-Disposition": "attachment; filename=findings.html"},
            )
        pdf_bytes = await html_to_pdf_bytes(html)
        return StreamingResponse(
            iter([pdf_bytes]), media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=findings.pdf"},
        )

    if fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "id", "title", "severity", "status", "affected_asset", "cvss_score",
            "cve", "kev_status", "epss_score", "risk_score",
            "compliance_tags", "sla_deadline",
            "ai_severity", "ai_confidence", "ai_reasoning",
            "false_positive", "suppressed", "ticket_ref", "created_at",
        ])
        for f in findings:
            writer.writerow([
                str(f.id),
                csv_safe(f.title),
                f.severity.value,
                f.status.value,
                csv_safe(f.affected_asset or ""),
                f.cvss_score or "",
                csv_safe("|".join(f.cve or [])),
                "yes" if getattr(f, "kev_status", False) else "no",
                getattr(f, "epss_score", "") or "",
                getattr(f, "risk_score", "") or "",
                csv_safe("|".join(getattr(f, "compliance_tags", None) or [])),
                f.sla_deadline.isoformat() if getattr(f, "sla_deadline", None) else "",
                f.ai_severity.value if getattr(f, "ai_severity", None) else "",
                f.ai_confidence or "" if getattr(f, "ai_confidence", None) else "",
                csv_safe((f.ai_reasoning or "")) if getattr(f, "ai_reasoning", None) else "",
                "yes" if f.false_positive else "no",
                "yes" if f.suppressed else "no",
                csv_safe(f.ticket_ref or ""),
                f.created_at.isoformat() if f.created_at else "",
            ])
        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=findings.csv"},
        )
    else:
        return {"items": [FindingResponse.from_orm(f, 0).model_dump() for f in findings], "total": len(findings)}


@router.get(
    "/assignees",
    summary="List users who can be assigned to findings",
)
async def list_assignees(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Return org members (id, name, email, role) for the assignment dropdown."""
    result = await db.execute(
        select(User.id, User.full_name, User.email, OrgMember.role)
        .join(OrgMember, OrgMember.user_id == User.id)
        .where(OrgMember.org_id == org_id, User.is_active == True)
        .order_by(User.full_name)
    )
    rows = result.all()
    return {
        "items": [
            {"id": str(r[0]), "name": r[1], "email": r[2], "role": r[3].value if hasattr(r[3], 'value') else r[3]}
            for r in rows
        ]
    }


class BulkStatusPayload(_PydanticBaseModel):
    finding_ids: List[str] = Field(..., min_length=1, max_length=500,
                                   description="Up to 500 finding UUIDs to update in one request")
    status: str = Field(..., description="Target FindingStatus value")


class BulkDeletePayload(_PydanticBaseModel):
    finding_ids: List[str] = Field(..., min_length=1, max_length=500,
                                   description="Up to 500 finding UUIDs to delete in one request")


@router.post(
    "/bulk-status",
    summary="Bulk update finding status (max 500 findings per request)",
)
async def bulk_update_status(
    payload: BulkStatusPayload,
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    try:
        target_status = FindingStatus(payload.status)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"code": "INVALID_STATUS", "message": f"Invalid status: {payload.status}"}},
        )

    # Validate all UUIDs up-front to return a clear 400 instead of a 500
    try:
        uuids = [UUID(fid) for fid in payload.finding_ids]
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"code": "INVALID_UUID", "message": "One or more finding_ids are not valid UUIDs"}},
        )

    from sqlalchemy import update as _update
    stmt = (
        _update(Finding)
        .where(Finding.org_id == org_id, Finding.id.in_(uuids))
        .values(status=target_status, updated_at=datetime.now(timezone.utc))
    )
    result = await db.execute(stmt)
    updated_count = result.rowcount

    # Write a single bulk-action audit log entry listing all affected finding IDs
    if updated_count > 0:
        log = AuditLog(
            org_id=org_id,
            user_id=current_user.id,
            action="finding.bulk_status_changed",
            resource_type="finding_bulk",
            resource_id=f"{updated_count}_findings",
            before_state=None,
            after_state={
                "new_status": payload.status,
                "finding_ids": [str(u) for u in uuids],
                "count": updated_count,
            },
            ip_address=_get_client_ip(request),
        )
        db.add(log)

    if updated_count > 0:
        background_tasks.add_task(invalidate_dashboard_cache, org_id)

    return {"updated": updated_count}


@router.post(
    "/bulk-delete",
    summary="Bulk delete findings (max 500 findings per request)",
)
async def bulk_delete_findings(
    payload: BulkDeletePayload,
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    try:
        uuids = [UUID(fid) for fid in payload.finding_ids]
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"code": "INVALID_UUID", "message": "One or more finding_ids are not valid UUIDs"}},
        )

    from sqlalchemy import delete as _delete
    stmt = _delete(Finding).where(Finding.org_id == org_id, Finding.id.in_(uuids))
    result = await db.execute(stmt)
    deleted_count = result.rowcount

    if deleted_count > 0:
        log = AuditLog(
            org_id=org_id,
            user_id=current_user.id,
            action="finding.bulk_deleted",
            resource_type="finding_bulk",
            resource_id=f"{deleted_count}_findings",
            before_state={"finding_ids": [str(u) for u in uuids], "count": deleted_count},
            after_state=None,
            ip_address=_get_client_ip(request),
        )
        db.add(log)

    if deleted_count > 0:
        background_tasks.add_task(invalidate_dashboard_cache, org_id)

    return {"deleted": deleted_count}


@router.get(
    "/{finding_id}",
    response_model=FindingResponse,
    summary="Get a single finding with full detail",
)
async def get_finding(
    finding_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> FindingResponse:
    finding = await _get_finding_or_404(db, finding_id, org_id)
    cc_result = await db.execute(
        select(func.count(FindingComment.id)).where(FindingComment.finding_id == finding_id)
    )
    comment_count = cc_result.scalar_one()
    return FindingResponse.from_orm(finding, comment_count)


@router.patch(
    "/{finding_id}",
    response_model=FindingResponse,
    summary="Update finding lifecycle (status, severity, FP flag, suppression, ticket ref)",
)
async def update_finding(
    finding_id: UUID,
    payload: FindingUpdate,
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> FindingResponse:
    finding = await _get_finding_or_404(db, finding_id, org_id)

    before_state = {
        "status": finding.status.value,
        "severity": finding.severity.value,
        "false_positive": finding.false_positive,
        "suppressed": finding.suppressed,
    }
    old_assigned_to = finding.assigned_to

    if payload.status is not None:
        try:
            finding.status = FindingStatus(payload.status)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": {"code": "INVALID_STATUS", "message": f"Invalid status: {payload.status}"}},
            )

    if payload.severity is not None:
        try:
            finding.severity = FindingSeverity(payload.severity)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": {"code": "INVALID_SEVERITY", "message": f"Invalid severity: {payload.severity}"}},
            )

    if payload.false_positive is not None:
        finding.false_positive = payload.false_positive
        if payload.false_positive:
            finding.status = FindingStatus.FALSE_POSITIVE

    # Auto-create suppression rule when marking false positive or accepted risk
    _auto_rule_action: Optional[str] = None
    if payload.false_positive is True:
        _auto_rule_action = "false_positive"
    elif payload.status == "accepted_risk":
        _auto_rule_action = "accepted_risk"

    if _auto_rule_action:
        existing_rule_result = await db.execute(
            select(ScanSuppressionRule).where(
                ScanSuppressionRule.org_id == org_id,
                ScanSuppressionRule.finding_title == finding.title,
                ScanSuppressionRule.affected_asset_pattern == finding.affected_asset,
            )
        )
        if not existing_rule_result.scalar_one_or_none():
            new_rule = ScanSuppressionRule(
                org_id=org_id,
                finding_title=finding.title,
                affected_asset_pattern=finding.affected_asset,
                action=_auto_rule_action,
                created_by=current_user.id,
            )
            db.add(new_rule)

    if payload.suppressed is not None:
        old_suppressed = finding.suppressed
        finding.suppressed = payload.suppressed
        finding.suppressed_reason = payload.suppressed_reason
        finding.suppressed_until = payload.suppressed_until
        finding.suppressed_by = current_user.id if payload.suppressed else None

        # Record suppression history
        suppression_record = FindingSuppression(
            finding_id=finding_id,
            suppressed_by=current_user.id,
            action="suppress" if payload.suppressed else "unsuppress",
            reason=payload.suppressed_reason,
            until=payload.suppressed_until,
        )
        db.add(suppression_record)

    if payload.ticket_ref is not None:
        finding.ticket_ref = payload.ticket_ref

    if payload.remediation is not None:
        finding.remediation = payload.remediation

    # "assigned_to" explicitly present in the request body — whether as a
    # UUID string, "", or JSON null — means "act on this field"; omitted
    # entirely means "leave it alone." Checking `is not None` instead of
    # membership in model_fields_set used to silently no-op on an explicit
    # `{"assigned_to": null}` (the natural way a client would ask to clear
    # the field), while only "" actually cleared it — surprising, undocumented
    # behavior found via live testing.
    if "assigned_to" in payload.model_fields_set:
        if not payload.assigned_to:
            finding.assigned_to = None
        else:
            try:
                finding.assigned_to = UUID(payload.assigned_to)
            except ValueError:
                pass

    if payload.accept_risk_info is not None:
        # Server-authoritative accepted_at/accepted_by — never trust client-supplied
        # audit fields for a "who approved this" record.
        finding.accept_risk_info = {
            "reason": payload.accept_risk_info.get("reason", ""),
            "expires_at": payload.accept_risk_info.get("expires_at"),
            "approver": payload.accept_risk_info.get("approver", ""),
            "accepted_at": datetime.now(timezone.utc).isoformat(),
            "accepted_by": str(current_user.id),
        }

    # Recompute risk score if severity changed
    if payload.severity is not None:
        new_score, new_explanation = compute_risk_score(
            finding.severity.value,
            finding.cvss_score,
            finding.epss_score,
            finding.kev_status,
            finding.priority_score,
        )
        finding.risk_score = new_score
        finding.risk_explanation = new_explanation
        finding.sla_deadline = compute_sla_deadline(finding.severity.value, None)

    db.add(finding)

    after_state = {
        "status": finding.status.value,
        "severity": finding.severity.value,
        "false_positive": finding.false_positive,
        "suppressed": finding.suppressed,
    }

    log = AuditLog(
        org_id=org_id,
        user_id=current_user.id,
        action="finding.status_changed",
        resource_type="finding",
        resource_id=str(finding_id),
        before_state=before_state,
        after_state=after_state,
        ip_address=_get_client_ip(request),
    )
    db.add(log)
    await db.flush()
    await db.refresh(finding)

    # Status/severity/false_positive changes all shift dashboard counts
    # (open findings, severity breakdown) — invalidate so the next dashboard
    # load reflects this immediately rather than up to the cache's 5-15min TTL.
    if before_state != after_state:
        background_tasks.add_task(invalidate_dashboard_cache, org_id)

    # Assignment used to be entirely silent — the assignee had no way to
    # learn a finding landed on them short of stumbling onto it in the list.
    if finding.assigned_to is not None and finding.assigned_to != old_assigned_to:
        background_tasks.add_task(
            push_in_app_notification,
            org_id=str(org_id),
            event_type="finding.assigned",
            title=f"Finding assigned to you: {finding.title[:80]}",
            body=f"Assigned by {current_user.full_name or current_user.email}",
            resource_type="finding",
            resource_id=str(finding_id),
            severity=finding.severity.value,
            user_id=str(finding.assigned_to),
        )

    cc_result = await db.execute(
        select(func.count(FindingComment.id)).where(FindingComment.finding_id == finding_id)
    )
    comment_count = cc_result.scalar_one()
    return FindingResponse.from_orm(finding, comment_count)


@router.delete(
    "/{finding_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a finding",
)
async def delete_finding(
    finding_id: UUID,
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> None:
    finding = await _get_finding_or_404(db, finding_id, org_id)
    log = AuditLog(
        org_id=org_id,
        user_id=current_user.id,
        action="finding.deleted",
        resource_type="finding",
        resource_id=str(finding_id),
        before_state={"title": finding.title, "severity": finding.severity.value},
        after_state=None,
        ip_address=_get_client_ip(request),
    )
    db.add(log)
    await db.delete(finding)
    # get_db auto-commits on return; explicit commit removed to keep audit log atomic.
    # invalidate_dashboard_cache is scheduled as a BackgroundTask specifically
    # because it must run AFTER that commit (FastAPI runs background tasks
    # only after the response — and this dependency's teardown commit — has
    # completed), not because it's low-priority.
    background_tasks.add_task(invalidate_dashboard_cache, org_id)


@router.post(
    "/{finding_id}/revalidate",
    summary="Re-check whether a finding still reproduces live",
    description=(
        "Live re-confirms a port/endpoint-shaped finding (raw TCP connect or "
        "HTTP GET against affected_asset) rather than trusting whatever a past "
        "scan recorded indefinitely. Bumps confidence to 'certain' if it still "
        "reproduces, or reports it as stale if it doesn't."
    ),
)
async def revalidate_finding_endpoint(
    finding_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    from app.services.validation_service import revalidate_finding

    finding = await _get_finding_or_404(db, finding_id, org_id)
    result = await revalidate_finding(db, finding)
    db.add(finding)
    return {"finding_id": str(finding_id), "confidence": finding.confidence, **result}


@router.post(
    "/{finding_id}/comments",
    response_model=FindingCommentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add a comment to a finding",
)
async def add_comment(
    finding_id: UUID,
    payload: FindingCommentCreate,
    background_tasks: BackgroundTasks,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> FindingCommentResponse:
    finding = await _get_finding_or_404(db, finding_id, org_id)

    comment = FindingComment(
        finding_id=finding_id,
        user_id=current_user.id,
        body=payload.body,
    )
    db.add(comment)
    await db.flush()
    await db.refresh(comment)

    # Comments used to be entirely silent to everyone but the person who
    # happened to reload the page — notify the finding's assignee (unless
    # they're the one commenting).
    if finding.assigned_to is not None and finding.assigned_to != current_user.id:
        background_tasks.add_task(
            push_in_app_notification,
            org_id=str(org_id),
            event_type="finding.commented",
            title=f"New comment on: {finding.title[:80]}",
            body=f"{current_user.full_name or current_user.email}: {payload.body[:140]}",
            resource_type="finding",
            resource_id=str(finding_id),
            severity="info",
            user_id=str(finding.assigned_to),
        )

    return FindingCommentResponse.from_orm(comment, current_user)


@router.get(
    "/{finding_id}/comments",
    summary="List comments on a finding",
)
async def list_comments(
    finding_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
) -> dict:
    await _get_finding_or_404(db, finding_id, org_id)

    count_result = await db.execute(
        select(func.count()).select_from(FindingComment).where(FindingComment.finding_id == finding_id)
    )
    total = count_result.scalar_one()

    offset = (page - 1) * per_page
    result = await db.execute(
        select(FindingComment, User)
        .join(User, FindingComment.user_id == User.id)
        .where(FindingComment.finding_id == finding_id)
        .order_by(FindingComment.created_at.asc())
        .offset(offset)
        .limit(per_page)
    )
    rows = result.all()
    pages = math.ceil(total / per_page) if per_page > 0 else 0

    return {
        "items": [FindingCommentResponse.from_orm(c, u).model_dump() for c, u in rows],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": pages,
    }


@router.get(
    "/{finding_id}/history",
    summary="Get audit history for a finding",
    description=(
        "Returns AuditLog events recorded against this finding (status changes, "
        "creation, deletion, suppression, etc.), newest first, with the acting "
        "user's display name resolved where available."
    ),
)
async def get_finding_history(
    finding_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    await _get_finding_or_404(db, finding_id, org_id)

    result = await db.execute(
        select(AuditLog, User.full_name, User.email)
        .outerjoin(User, User.id == AuditLog.user_id)
        .where(
            AuditLog.org_id == org_id,
            AuditLog.resource_type == "finding",
            AuditLog.resource_id == str(finding_id),
        )
        .order_by(AuditLog.created_at.desc())
    )
    rows = result.all()

    items = []
    for log, full_name, email in rows:
        items.append({
            "id": str(log.id),
            "action": log.action,
            "before_state": log.before_state,
            "after_state": log.after_state,
            "created_at": log.created_at.isoformat(),
            "user_id": str(log.user_id) if log.user_id else None,
            "user_name": full_name or (email or "Unknown"),
        })

    return {"items": items, "total": len(items)}


@router.get(
    "/sla/compliance",
    summary="Get org-level SLA compliance metrics",
    description=(
        "Returns how many findings per severity were remediated within SLA, "
        "breached SLA, or are still pending. Provides org-level health metrics "
        "for executive reporting."
    ),
)
async def sla_compliance(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
    scan_job_id: Optional[str] = None,
) -> dict:
    from sqlalchemy import case as _case

    now = datetime.now(timezone.utc)

    base_q = select(
        Finding.severity,
        Finding.status,
        Finding.sla_deadline,
    ).where(
        Finding.org_id == org_id,
        Finding.false_positive == False,
        Finding.suppressed == False,
    )

    if scan_job_id:
        try:
            base_q = base_q.where(Finding.scan_job_id == UUID(scan_job_id))
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": {"code": "INVALID_UUID", "message": "Invalid scan_job_id"}},
            )

    result = await db.execute(base_q)
    rows = result.all()

    remediated_statuses = {FindingStatus.REMEDIATED}
    active_statuses = {FindingStatus.OPEN, FindingStatus.IN_PROGRESS}

    severities = ["critical", "high", "medium", "low", "info"]
    compliance: dict = {
        sev: {"within_sla": 0, "breached_sla": 0, "overdue": 0, "total": 0}
        for sev in severities
    }
    totals = {"within_sla": 0, "breached_sla": 0, "overdue": 0, "total": 0}

    for row in rows:
        sev_key = row.severity.value
        bucket = compliance[sev_key]
        bucket["total"] += 1
        totals["total"] += 1

        if row.status in remediated_statuses:
            # Remediated: was it within the SLA window?
            if row.sla_deadline is None or now <= row.sla_deadline:
                bucket["within_sla"] += 1
                totals["within_sla"] += 1
            else:
                bucket["breached_sla"] += 1
                totals["breached_sla"] += 1
        elif row.status in active_statuses:
            if row.sla_deadline and now > row.sla_deadline:
                bucket["overdue"] += 1
                totals["overdue"] += 1

    # Compute compliance percentage per severity
    for sev_key, bucket in compliance.items():
        denominator = bucket["within_sla"] + bucket["breached_sla"]
        bucket["compliance_pct"] = (
            round(bucket["within_sla"] / denominator * 100, 1) if denominator > 0 else None
        )

    overall_denominator = totals["within_sla"] + totals["breached_sla"]
    overall_pct = (
        round(totals["within_sla"] / overall_denominator * 100, 1)
        if overall_denominator > 0 else None
    )

    return {
        "overall": {**totals, "compliance_pct": overall_pct},
        "by_severity": compliance,
        "as_of": now.isoformat(),
    }


# --- Helpers ---

async def _get_finding_or_404(db: AsyncSession, finding_id: UUID, org_id: UUID) -> Finding:
    result = await db.execute(
        select(Finding).where(Finding.id == finding_id, Finding.org_id == org_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "FINDING_NOT_FOUND", "message": "Finding not found"}},
        )
    return finding
