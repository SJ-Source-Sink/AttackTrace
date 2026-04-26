"""
Scheduled Scans API: CRUD + manual trigger for recurring scan schedules.
"""

import math
from datetime import datetime, timezone
from typing import Annotated, Optional
from uuid import UUID

from croniter import croniter
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import get_current_org_id, get_current_user
from app.models.db.scan import ScheduledScan, ScanJob, ScanStatus, ScanIntensity
from app.models.db.user import User

router = APIRouter(prefix="/schedules", tags=["Schedules"])


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class ScheduleCreate(BaseModel):
    name: str = Field(..., max_length=255)
    target_domains: list[str] = Field(..., min_length=1)
    company_name: Optional[str] = Field(None, max_length=255)
    cron_expression: str = Field(..., max_length=100)
    workspace_id: Optional[str] = None
    is_active: bool = True
    scan_config: dict = Field(default_factory=dict)


class ScheduleUpdate(BaseModel):
    name: Optional[str] = Field(None, max_length=255)
    target_domains: Optional[list[str]] = None
    company_name: Optional[str] = Field(None, max_length=255)
    cron_expression: Optional[str] = Field(None, max_length=100)
    workspace_id: Optional[str] = None
    is_active: Optional[bool] = None
    scan_config: Optional[dict] = None


class ScheduleResponse(BaseModel):
    id: str
    org_id: str
    workspace_id: Optional[str]
    created_by: Optional[str]
    name: str
    target_domains: list[str]
    company_name: Optional[str]
    scan_config: dict
    cron_expression: str
    is_active: bool
    last_run: Optional[str]
    next_run: Optional[str]
    last_scan_job_id: Optional[str]
    created_at: str
    updated_at: str

    @classmethod
    def from_orm(cls, obj: ScheduledScan) -> "ScheduleResponse":
        return cls(
            id=str(obj.id),
            org_id=str(obj.org_id),
            workspace_id=str(obj.workspace_id) if obj.workspace_id else None,
            created_by=str(obj.created_by) if obj.created_by else None,
            name=obj.name,
            target_domains=obj.target_domains,
            company_name=obj.company_name,
            scan_config=obj.scan_config or {},
            cron_expression=obj.cron_expression,
            is_active=obj.is_active,
            last_run=obj.last_run.isoformat() if obj.last_run else None,
            next_run=obj.next_run.isoformat() if obj.next_run else None,
            last_scan_job_id=str(obj.last_scan_job_id) if obj.last_scan_job_id else None,
            created_at=obj.created_at.isoformat(),
            updated_at=obj.updated_at.isoformat(),
        )

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _compute_next_run(cron_expr: str) -> datetime:
    """Compute the next run datetime for a cron expression (UTC)."""
    return croniter(cron_expr, datetime.now(timezone.utc)).get_next(datetime)


def _validate_cron(cron_expr: str) -> None:
    """Raise HTTPException if the cron expression is invalid."""
    try:
        croniter(cron_expr, datetime.now(timezone.utc))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": {"code": "INVALID_CRON", "message": f"Invalid cron expression: {exc}"}},
        )


async def _get_schedule_or_404(
    schedule_id: UUID, org_id: UUID, db: AsyncSession
) -> ScheduledScan:
    result = await db.execute(
        select(ScheduledScan).where(
            ScheduledScan.id == schedule_id,
            ScheduledScan.org_id == org_id,
        )
    )
    sched = result.scalar_one_or_none()
    if not sched:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "SCHEDULE_NOT_FOUND", "message": "Schedule not found"}},
        )
    return sched


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "",
    response_model=ScheduleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new scheduled scan",
)
async def create_schedule(
    payload: ScheduleCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> ScheduleResponse:
    _validate_cron(payload.cron_expression)

    workspace_id = UUID(payload.workspace_id) if payload.workspace_id else None

    sched = ScheduledScan(
        org_id=org_id,
        workspace_id=workspace_id,
        created_by=current_user.id,
        name=payload.name,
        target_domains=payload.target_domains,
        company_name=payload.company_name,
        scan_config=payload.scan_config,
        cron_expression=payload.cron_expression,
        is_active=payload.is_active,
        next_run=_compute_next_run(payload.cron_expression) if payload.is_active else None,
    )
    db.add(sched)
    await db.flush()
    await db.refresh(sched)
    await db.commit()
    await db.refresh(sched)

    return ScheduleResponse.from_orm(sched)


@router.get(
    "",
    summary="List scheduled scans for the organisation",
)
async def list_schedules(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
    page: int = 1,
    per_page: int = 50,
) -> dict:
    offset = (page - 1) * per_page

    total_result = await db.execute(
        select(func.count()).select_from(ScheduledScan).where(
            ScheduledScan.org_id == org_id
        )
    )
    total = total_result.scalar_one()

    result = await db.execute(
        select(ScheduledScan)
        .where(ScheduledScan.org_id == org_id)
        .order_by(ScheduledScan.created_at.desc())
        .offset(offset)
        .limit(per_page)
    )
    schedules = result.scalars().all()

    return {
        "items": [ScheduleResponse.from_orm(s) for s in schedules],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": math.ceil(total / per_page) if total else 1,
    }


@router.get(
    "/{schedule_id}",
    response_model=ScheduleResponse,
    summary="Get a single scheduled scan",
)
async def get_schedule(
    schedule_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> ScheduleResponse:
    sched = await _get_schedule_or_404(schedule_id, org_id, db)
    return ScheduleResponse.from_orm(sched)


@router.patch(
    "/{schedule_id}",
    response_model=ScheduleResponse,
    summary="Update a scheduled scan",
)
async def update_schedule(
    schedule_id: UUID,
    payload: ScheduleUpdate,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> ScheduleResponse:
    sched = await _get_schedule_or_404(schedule_id, org_id, db)

    if payload.name is not None:
        sched.name = payload.name
    if payload.target_domains is not None:
        sched.target_domains = payload.target_domains
    if payload.company_name is not None:
        sched.company_name = payload.company_name
    if payload.scan_config is not None:
        sched.scan_config = payload.scan_config
    if payload.workspace_id is not None:
        sched.workspace_id = UUID(payload.workspace_id)

    cron_changed = payload.cron_expression is not None and payload.cron_expression != sched.cron_expression
    if payload.cron_expression is not None:
        _validate_cron(payload.cron_expression)
        sched.cron_expression = payload.cron_expression

    if payload.is_active is not None:
        sched.is_active = payload.is_active

    # Recompute next_run whenever cron changed, active state changed, or both
    if sched.is_active and (cron_changed or payload.is_active is True):
        sched.next_run = _compute_next_run(sched.cron_expression)
    elif not sched.is_active:
        sched.next_run = None

    db.add(sched)
    await db.commit()
    await db.refresh(sched)

    return ScheduleResponse.from_orm(sched)


@router.delete(
    "/{schedule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a scheduled scan",
)
async def delete_schedule(
    schedule_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> None:
    sched = await _get_schedule_or_404(schedule_id, org_id, db)
    await db.delete(sched)
    await db.commit()


@router.post(
    "/{schedule_id}/trigger",
    summary="Manually trigger a scheduled scan immediately",
)
async def trigger_schedule(
    schedule_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    sched = await _get_schedule_or_404(schedule_id, org_id, db)

    cfg = sched.scan_config or {}
    intensity_str = cfg.get("intensity", "passive")
    try:
        intensity = ScanIntensity(intensity_str)
    except ValueError:
        intensity = ScanIntensity.PASSIVE

    modules_to_skip: list[str] = cfg.get("modules_to_skip", [])

    job = ScanJob(
        org_id=org_id,
        workspace_id=sched.workspace_id,
        created_by=current_user.id,
        target_domains=sched.target_domains,
        company_name=sched.company_name,
        intensity=intensity,
        passive_only=(intensity == ScanIntensity.PASSIVE),
        modules_to_skip=modules_to_skip,
        status=ScanStatus.PENDING,
        findings_count={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
    )
    db.add(job)
    await db.flush()
    await db.refresh(job)

    # Dispatch to Celery
    from app.workers.scan_worker import run_scan
    celery_result = run_scan.delay(str(job.id))
    job.celery_task_id = celery_result.id
    db.add(job)

    # Update schedule tracking
    sched.last_run = datetime.now(timezone.utc)
    sched.last_scan_job_id = job.id
    db.add(sched)

    await db.commit()
    await db.refresh(job)

    return {"scan_job_id": str(job.id)}
