"""
Scan management API: create, list, get, cancel, and stream scan events via SSE.
"""

import shutil
from pathlib import Path
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import get_current_org_id, get_current_user
from app.models.db.scan import ScanJob, ScanStatus
from app.models.db.user import User
from app.models.schemas.scan import ScanCreate, ScanResponse
from app.services.scan_service import (
    cancel_scan,
    create_scan,
    get_scan_by_id,
    list_scans,
    stream_scan_events,
)

router = APIRouter(prefix="/scans", tags=["Scans"])


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@router.post(
    "",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Create and launch a new scan",
    description=(
        "Creates a ScanJob and enqueues it for execution. "
        "intensity=passive maps to --passive-only, "
        "intensity=aggressive maps to --intensity aggressive."
    ),
)
async def create_scan_job(
    payload: ScanCreate,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> ScanResponse:
    job = await create_scan(
        db=db,
        org_id=org_id,
        user_id=current_user.id,
        payload=payload,
        ip_address=_get_client_ip(request),
    )
    return ScanResponse.from_orm(job)


@router.get(
    "",
    summary="List scans with filtering and pagination",
)
async def list_scan_jobs(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
    scan_status: str = None,
    workspace_id: str = None,
    target_domain: str = None,
    search: str = None,
    page: int = 1,
    per_page: int = 50,
) -> dict:
    return await list_scans(
        db=db,
        org_id=org_id,
        status=scan_status,
        workspace_id=workspace_id,
        target_domain=target_domain,
        search=search,
        page=page,
        per_page=per_page,
    )


@router.get(
    "/{scan_id}",
    response_model=ScanResponse,
    summary="Get scan details",
)
async def get_scan_job(
    scan_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> ScanResponse:
    job = await get_scan_by_id(db, scan_id, org_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "SCAN_NOT_FOUND", "message": "Scan not found"}},
        )
    return ScanResponse.from_orm(job)


@router.delete(
    "/{scan_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Cancel a running/pending scan or delete a completed/failed/cancelled scan",
)
async def cancel_or_delete_scan_job(
    scan_id: UUID,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> None:
    job = await get_scan_by_id(db, scan_id, org_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "SCAN_NOT_FOUND", "message": "Scan not found"}},
        )

    if job.status in (ScanStatus.PENDING, ScanStatus.RUNNING):
        try:
            await cancel_scan(db, job, current_user.id, _get_client_ip(request))
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": {"code": "INVALID_STATE", "message": str(e)}},
            )
    else:
        from app.core.config import get_settings
        settings = get_settings()
        org_id_str = str(job.org_id)
        scan_id_str = str(job.id)

        await db.delete(job)
        await db.commit()  # DB is source of truth — commit first, then clean up files

        # Invalidate dashboard cache so asset/finding counts update immediately
        try:
            import redis.asyncio as aioredis
            _r = aioredis.from_url(settings.REDIS_URL, socket_connect_timeout=1)
            await _r.delete(f"dashboard:stats:{org_id_str}")
            await _r.aclose()
        except Exception:
            pass

        # Clean up scan files from disk — done AFTER commit so files are only removed
        # once the DB record is durably gone (crash between commit and here is harmless:
        # orphan files waste disk but the next deploy or manual cleanup handles them).
        workspace = Path(settings.ATTACKTRACE_WORKSPACE_DIR)

        scan_dir = workspace / org_id_str / scan_id_str
        if scan_dir.exists():
            shutil.rmtree(scan_dir, ignore_errors=True)

        scan_db = workspace / org_id_str / f"{scan_id_str}.db"
        if scan_db.exists():
            scan_db.unlink(missing_ok=True)

        reports_dir = workspace / "reports" / org_id_str
        if reports_dir.exists():
            for f in reports_dir.glob(f"report_{scan_id_str}_*.html"):
                f.unlink(missing_ok=True)


@router.get(
    "/{scan_id}/stream",
    summary="Stream real-time scan progress via Server-Sent Events",
    description=(
        "Subscribe to live scan events: module_start, module_complete, finding, "
        "status_change, error, complete. Connect with EventSource in the browser. "
        "Pass the JWT as ?token= query param since EventSource cannot set headers."
    ),
    response_class=StreamingResponse,
)
async def scan_stream(
    scan_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    token: str | None = None,
) -> StreamingResponse:
    # Authenticate: accept token from ?token= query param (EventSource can't set headers)
    # or fall back to Authorization header for non-browser clients.
    from uuid import UUID as _UUID
    from jwt.exceptions import InvalidTokenError
    from app.core.security import decode_token

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"error": {"code": "UNAUTHORIZED", "message": "Invalid or expired credentials"}},
    )

    # Resolve token: query param takes precedence (browser EventSource), then header
    raw_token = token
    if not raw_token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            raw_token = auth_header[7:]

    if not raw_token:
        raise credentials_exception

    try:
        payload = decode_token(raw_token)
        if payload.get("type") != "access":
            raise credentials_exception
        user_id = payload.get("sub")
        org_id_str = payload.get("org_id")
        if not user_id or not org_id_str:
            raise credentials_exception
    except (InvalidTokenError, ValueError):
        raise credentials_exception

    from sqlalchemy import select as _select
    from app.models.db.user import User as _User

    result = await db.execute(
        _select(_User).where(_User.id == _UUID(user_id), _User.is_active == True)
    )
    user = result.scalar_one_or_none()
    if not user:
        raise credentials_exception

    org_id = _UUID(org_id_str)

    # Verify scan exists and belongs to org
    job = await get_scan_by_id(db, scan_id, org_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "SCAN_NOT_FOUND", "message": "Scan not found"}},
        )

    # Read Last-Event-ID header for efficient replay (browser sends this automatically
    # on reconnect when EventSource events have id: fields)
    raw_lei = request.headers.get("Last-Event-ID")
    last_event_id: int | None = None
    if raw_lei:
        try:
            last_event_id = int(raw_lei)
        except (ValueError, TypeError):
            pass

    return StreamingResponse(
        stream_scan_events(str(scan_id), request, last_event_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get(
    "/{scan_id}/compare/{other_scan_id}",
    summary="Compare two scans and return a change diff",
)
async def compare_scans(
    scan_id: UUID,
    other_scan_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    job_before = await get_scan_by_id(db, scan_id, org_id)
    job_after = await get_scan_by_id(db, other_scan_id, org_id)

    if not job_before or not job_after:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "SCAN_NOT_FOUND", "message": "One or both scans not found"}},
        )

    if job_before.status != ScanStatus.COMPLETED or job_after.status != ScanStatus.COMPLETED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"code": "SCANS_NOT_COMPLETE", "message": "Both scans must be completed"}},
        )

    from app.services.change_detection import compare_scan_jobs
    diff = compare_scan_jobs(job_before, job_after)
    return diff.to_dict()


@router.get(
    "/{scan_id}/diff",
    summary="Get asset and finding change diff for this scan vs. its prior scan",
)
async def get_scan_diff(
    scan_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    from app.models.db.scan import ScanDiff
    from sqlalchemy import select as _select

    job = await get_scan_by_id(db, scan_id, org_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "SCAN_NOT_FOUND", "message": "Scan not found"}},
        )

    result = await db.execute(
        _select(ScanDiff).where(ScanDiff.scan_id == scan_id, ScanDiff.org_id == org_id)
    )
    scan_diff = result.scalar_one_or_none()
    if not scan_diff:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "DIFF_NOT_FOUND", "message": "No diff computed for this scan yet"}},
        )

    return {
        "scan_id": str(scan_diff.scan_id),
        "previous_scan_id": str(scan_diff.previous_scan_id) if scan_diff.previous_scan_id else None,
        "new_assets": scan_diff.new_assets or [],
        "removed_assets": scan_diff.removed_assets or [],
        "new_findings": scan_diff.new_findings or [],
        "resolved_findings": scan_diff.resolved_findings or [],
        "diff_summary": scan_diff.diff_summary or {},
        "created_at": scan_diff.created_at.isoformat(),
    }
