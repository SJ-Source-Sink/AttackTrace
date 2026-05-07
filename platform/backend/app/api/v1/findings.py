"""
Findings API: list, filter, update lifecycle, add comments, and manage suppressions.
"""

import math
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

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
from app.models.db.user import User
from app.models.schemas.finding import (
    FindingCommentCreate,
    FindingCommentResponse,
    FindingCreate,
    FindingFilter,
    FindingResponse,
    FindingUpdate,
)

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
    summary="Export findings as CSV or JSON",
)
async def export_findings(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
    fmt: str = "json",
    scan_job_id: Optional[str] = None,
    severity: Optional[str] = None,
    finding_status: Optional[str] = None,
) -> Any:
    from fastapi.responses import StreamingResponse
    import csv, io

    query = select(Finding).where(Finding.org_id == org_id)
    if scan_job_id:
        query = query.where(Finding.scan_job_id == UUID(scan_job_id))
    if severity:
        query = query.where(Finding.severity == severity)
    if finding_status:
        query = query.where(Finding.status == FindingStatus(finding_status))

    # Hard cap to prevent OOM — export at most 10k findings at once
    result = await db.execute(query.order_by(Finding.created_at.desc()).limit(10_000))
    findings = result.scalars().all()

    if fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["id", "title", "severity", "status", "affected_asset", "cvss_score", "created_at"])
        for f in findings:
            writer.writerow([
                str(f.id), f.title, f.severity.value, f.status.value,
                f.affected_asset or "", f.cvss_score or "",
                f.created_at.isoformat() if f.created_at else ""
            ])
        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=findings.csv"},
        )
    else:
        return {"items": [FindingResponse.from_orm(f, 0).model_dump() for f in findings], "total": len(findings)}


@router.post(
    "/bulk-status",
    summary="Bulk update finding status",
)
async def bulk_update_status(
    payload: dict,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    finding_ids = payload.get("finding_ids", [])
    new_status = payload.get("status")
    if not finding_ids or not new_status:
        raise HTTPException(status_code=400, detail="finding_ids and status required")
    try:
        target_status = FindingStatus(new_status)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid status: {new_status}")

    from sqlalchemy import update as _update
    stmt = (
        _update(Finding)
        .where(Finding.org_id == org_id, Finding.id.in_([UUID(fid) for fid in finding_ids]))
        .values(status=target_status)
    )
    result = await db.execute(stmt)
    await db.commit()
    return {"updated": result.rowcount}


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
    await db.commit()


@router.post(
    "/{finding_id}/comments",
    response_model=FindingCommentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add a comment to a finding",
)
async def add_comment(
    finding_id: UUID,
    payload: FindingCommentCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> FindingCommentResponse:
    await _get_finding_or_404(db, finding_id, org_id)

    comment = FindingComment(
        finding_id=finding_id,
        user_id=current_user.id,
        body=payload.body,
    )
    db.add(comment)
    await db.flush()
    await db.refresh(comment)

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
    page: int = 1,
    per_page: int = 50,
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
