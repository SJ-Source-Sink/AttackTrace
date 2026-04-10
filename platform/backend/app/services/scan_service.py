"""
Scan service: create, cancel, and query scan jobs.
Manages the lifecycle from DB creation through Celery dispatch to SSE streaming.
"""

import json
import math
from datetime import datetime, timezone
from typing import AsyncGenerator, Optional
from uuid import UUID

import redis.asyncio as aioredis
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models.db.audit import AuditLog
from app.models.db.scan import ScanJob, ScanStatus, ScanIntensity
from app.models.schemas.scan import ScanCreate, ScanResponse

settings = get_settings()

_redis: Optional[aioredis.Redis] = None


def _get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    return _redis


async def create_scan(
    db: AsyncSession,
    org_id: UUID,
    user_id: UUID,
    payload: ScanCreate,
    ip_address: Optional[str] = None,
) -> ScanJob:
    """Create a ScanJob record and enqueue a Celery task."""
    workspace_id = UUID(payload.workspace_id) if payload.workspace_id else None

    job = ScanJob(
        org_id=org_id,
        workspace_id=workspace_id,
        created_by=user_id,
        target_domains=payload.target_domains,
        company_name=payload.company_name,
        intensity=ScanIntensity(payload.intensity),
        passive_only=(payload.intensity == "passive"),
        modules_to_skip=payload.modules_to_skip,
        status=ScanStatus.PENDING,
        scheduled_at=payload.scheduled_at,
        schedule_cron=payload.schedule_cron,
        findings_count={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
    )
    db.add(job)
    await db.flush()
    await db.refresh(job)

    # Write audit log
    log = AuditLog(
        org_id=org_id,
        user_id=user_id,
        action="scan.created",
        resource_type="scan_job",
        resource_id=str(job.id),
        after_state={"target_domains": job.target_domains, "intensity": job.intensity.value},
        ip_address=ip_address,
    )
    db.add(log)
    await db.flush()

    # Enqueue Celery task (import here to avoid circular imports at module load)
    if not payload.scheduled_at:
        from app.workers.scan_worker import run_scan
        celery_result = run_scan.delay(str(job.id))
        job.celery_task_id = celery_result.id
        db.add(job)
        await db.flush()

    # Refresh to load all server-side generated values (updated_at, etc.)
    # before from_orm() accesses them — avoids MissingGreenlet on lazy load
    await db.refresh(job)
    return job


async def cancel_scan(
    db: AsyncSession,
    job: ScanJob,
    user_id: UUID,
    ip_address: Optional[str] = None,
) -> ScanJob:
    """Cancel a running or pending scan."""
    if job.status not in (ScanStatus.PENDING, ScanStatus.RUNNING):
        raise ValueError(f"Cannot cancel scan in status: {job.status.value}")

    before = {"status": job.status.value}

    # Revoke Celery task if present
    if job.celery_task_id:
        from app.workers.celery_app import celery_app
        celery_app.control.revoke(job.celery_task_id, terminate=True, signal="SIGTERM")

    job.status = ScanStatus.CANCELLED
    job.completed_at = datetime.now(timezone.utc)
    db.add(job)
    await db.flush()

    # Publish cancellation event to SSE channel
    r = _get_redis()
    await r.publish(
        f"scan:{job.id}",
        json.dumps({
            "event_type": "status_change",
            "scan_id": str(job.id),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {"status": "cancelled"},
        }),
    )

    # Audit log
    log = AuditLog(
        org_id=job.org_id,
        user_id=user_id,
        action="scan.cancelled",
        resource_type="scan_job",
        resource_id=str(job.id),
        before_state=before,
        after_state={"status": "cancelled"},
        ip_address=ip_address,
    )
    db.add(log)
    await db.flush()

    return job


async def get_scan_by_id(db: AsyncSession, scan_id: UUID, org_id: UUID) -> Optional[ScanJob]:
    """Fetch a scan job, enforcing org_id isolation."""
    result = await db.execute(
        select(ScanJob).where(ScanJob.id == scan_id, ScanJob.org_id == org_id)
    )
    return result.scalar_one_or_none()


async def list_scans(
    db: AsyncSession,
    org_id: UUID,
    status: Optional[str] = None,
    workspace_id: Optional[str] = None,
    target_domain: Optional[str] = None,
    page: int = 1,
    per_page: int = 50,
) -> dict:
    """List scans with optional filters and pagination."""
    query = select(ScanJob).where(ScanJob.org_id == org_id)

    if status:
        query = query.where(ScanJob.status == ScanStatus(status))
    if workspace_id:
        query = query.where(ScanJob.workspace_id == UUID(workspace_id))
    if target_domain:
        query = query.where(ScanJob.target_domains.any(target_domain))

    # Count
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar_one()

    # Paginate
    offset = (page - 1) * per_page
    query = query.order_by(ScanJob.created_at.desc()).offset(offset).limit(per_page)
    result = await db.execute(query)
    jobs = result.scalars().all()

    pages = math.ceil(total / per_page) if per_page > 0 else 0

    return {
        "items": [ScanResponse.from_orm(j) for j in jobs],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": pages,
    }


async def stream_scan_events(scan_id: str) -> AsyncGenerator[str, None]:
    """
    Subscribe to the Redis pub/sub channel for a scan and yield SSE events.
    Replays stored structural events first so reconnecting clients catch up
    without seeing a false restart. Closes when 'complete' or 'error' is received.
    """
    r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    pubsub = r.pubsub()
    await pubsub.subscribe(f"scan:{scan_id}")

    try:
        # Send initial ping
        yield f"data: {json.dumps({'event_type': 'connected', 'scan_id': scan_id, 'timestamp': datetime.now(timezone.utc).isoformat(), 'data': {}})}\n\n"

        # Replay stored structural events (status_change, module_start, module_complete).
        # This lets clients that navigated away and came back catch up immediately.
        replay_key = f"scan:{scan_id}:events"
        stored = await r.lrange(replay_key, 0, -1)
        already_terminal = False
        for raw in stored:
            try:
                payload = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                continue
            yield f"data: {json.dumps(payload)}\n\n"
            event_type = payload.get("event_type")
            if event_type in ("complete", "error"):
                already_terminal = True
                break
            if event_type == "status_change" and payload.get("data", {}).get("status") == "cancelled":
                already_terminal = True
                break

        if already_terminal:
            return

        async for message in pubsub.listen():
            if message["type"] != "message":
                continue

            try:
                payload = json.loads(message["data"])
            except (json.JSONDecodeError, TypeError):
                continue

            yield f"data: {json.dumps(payload)}\n\n"

            # Terminal events — stop streaming
            event_type = payload.get("event_type")
            if event_type in ("complete", "error"):
                break
            if event_type == "status_change":
                data = payload.get("data", {})
                if data.get("status") == "cancelled":
                    break
    finally:
        await pubsub.unsubscribe(f"scan:{scan_id}")
        await pubsub.close()
        await r.aclose()
