"""
Scan service: create, cancel, and query scan jobs.
Manages the lifecycle from DB creation through Celery dispatch to SSE streaming.
"""

import asyncio
import json
import math
import time
from datetime import datetime, timezone
from typing import AsyncGenerator, Optional
from uuid import UUID

import redis.asyncio as aioredis
from fastapi import HTTPException, Request, status
from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models.db.audit import AuditLog
from app.models.db.org import Organization
from app.models.db.scan import ScanJob, ScanStatus, ScanIntensity
from app.models.schemas.scan import ScanCreate, ScanResponse

settings = get_settings()

_redis: Optional[aioredis.Redis] = None

_HEARTBEAT_INTERVAL = 15  # seconds between SSE comment pings
_POLL_INTERVAL = 0.2       # seconds between get_message polls when idle


def _get_redis() -> aioredis.Redis:
    """Return the module-level Redis connection pool, creating it on first call.

    Uses a connection pool (not a single connection) so concurrent requests
    share connections efficiently. max_connections=100 supports up to ~100
    concurrent SSE subscribers + API callers without pool exhaustion.
    socket_keepalive prevents silent drops on idle connections behind proxies.
    """
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            max_connections=100,
            socket_keepalive=True,
            socket_keepalive_options={},
            health_check_interval=30,
        )
    return _redis


async def get_monthly_scan_usage(db: AsyncSession, org_id: UUID) -> tuple[int, int]:
    """
    Return (scans_created_this_calendar_month, max_scans_per_month) for an org.

    Calendar-month (not rolling 30-day) semantics: simpler to reason about
    and matches typical plan/billing-cycle boundaries.
    """
    now = datetime.now(timezone.utc)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    org = await db.get(Organization, org_id)
    limit = org.max_scans_per_month if org is not None else 0

    count_result = await db.execute(
        select(func.count())
        .select_from(ScanJob)
        .where(ScanJob.org_id == org_id, ScanJob.created_at >= month_start)
    )
    used = count_result.scalar_one()
    return used, limit


async def enforce_scan_quota(db: AsyncSession, org_id: UUID) -> None:
    """
    Reject scan creation once an org has hit its Organization.max_scans_per_month
    for the current calendar month, counted from ScanJob rows (the canonical
    "a scan happened" record for the core pipeline).

    Raises HTTPException(429) if at/over quota. No-ops if the org can't be
    resolved (auth dependencies already guarantee a valid org in practice).
    """
    used, limit = await get_monthly_scan_usage(db, org_id)
    if used >= limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": {
                    "code": "SCAN_QUOTA_EXCEEDED",
                    "message": (
                        f"Monthly scan quota ({limit}) exceeded for this plan. "
                        f"{used} of {limit} scans already used this calendar month; "
                        f"0 remaining. Upgrade your plan or wait for the next billing cycle."
                    ),
                    "used": used,
                    "limit": limit,
                    "remaining": 0,
                }
            },
        )


async def create_scan(
    db: AsyncSession,
    org_id: UUID,
    user_id: UUID,
    payload: ScanCreate,
    ip_address: Optional[str] = None,
) -> ScanJob:
    """Create a ScanJob record and enqueue a Celery task."""
    await enforce_scan_quota(db, org_id)

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

    # Commit BEFORE dispatching to Celery.
    # The worker runs in a separate process and queries the DB independently.
    # If we dispatch before committing, the worker may not find the scan record
    # (it's flushed but not yet visible outside this transaction).
    # expire_on_commit=False on AsyncSessionLocal keeps the job object usable.
    await db.commit()
    await db.refresh(job)

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
    search: Optional[str] = None,
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
    if search:
        pattern = f"%{search}%"
        query = query.where(
            or_(
                ScanJob.company_name.ilike(pattern),
                cast(ScanJob.target_domains, String).ilike(pattern),
            )
        )

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


def _is_terminal(payload: dict) -> bool:
    event_type = payload.get("event_type")
    if event_type in ("complete", "error"):
        return True
    if event_type == "status_change" and payload.get("data", {}).get("status") in ("cancelled", "failed"):
        return True
    return False


def _sse_event(payload: dict) -> str:
    """Format a payload dict as an SSE frame with an id: field."""
    event_id = payload.get("event_id", "")
    return f"id: {event_id}\ndata: {json.dumps(payload)}\n\n"


async def stream_scan_events(
    scan_id: str,
    request: Request,
    last_event_id: Optional[int] = None,
) -> AsyncGenerator[str, None]:
    """
    Subscribe to the Redis pub/sub channel for a scan and yield SSE events.

    Improvements over the original implementation:
    - Heartbeat comment (`: ping`) every 15s prevents proxy/LB connection timeouts.
    - Client-disconnect detection via request.is_disconnected() stops the generator
      immediately, releasing the Redis pub/sub connection and CPU.
    - id: field on every event enables native EventSource Last-Event-ID resumption.
    - last_event_id: skip already-seen structural events on reconnect so the client
      only receives events it missed, not the full replay from the start.
    - Finding events from the last 100 are also replayed on reconnect so the live
      feed is not empty after a brief navigation away.
    """
    # Reuse the module-level connection pool instead of spawning a new connection
    # per subscriber. Each pubsub object gets its own dedicated connection from
    # the pool, so 50 concurrent viewers use 50 pooled connections — not 50
    # independent pools.
    r = _get_redis()
    pubsub = r.pubsub()
    await pubsub.subscribe(f"scan:{scan_id}")

    next_heartbeat = time.monotonic() + _HEARTBEAT_INTERVAL

    try:
        # Connected acknowledgment (no id — not a replayable structural event)
        yield f"data: {json.dumps({'event_type': 'connected', 'scan_id': scan_id, 'timestamp': datetime.now(timezone.utc).isoformat(), 'data': {}})}\n\n"

        # Replay structural events (status_change, module_start/complete, complete, error).
        # Skip events with event_id <= last_event_id so reconnecting clients only
        # receive events they actually missed.
        replay_key = f"scan:{scan_id}:events"
        stored_structural = await r.lrange(replay_key, 0, -1)
        already_terminal = False

        for raw in stored_structural:
            try:
                payload = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                continue
            eid = payload.get("event_id")
            if last_event_id is not None and eid is not None and eid <= last_event_id:
                continue  # client already saw this
            yield _sse_event(payload)
            if _is_terminal(payload):
                already_terminal = True
                break

        if already_terminal:
            return

        # Replay last N findings so the live feed is populated on reconnect.
        findings_key = f"scan:{scan_id}:findings"
        stored_findings = await r.lrange(findings_key, 0, -1)
        for raw in stored_findings:
            try:
                payload = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                continue
            eid = payload.get("event_id")
            if last_event_id is not None and eid is not None and eid <= last_event_id:
                continue
            yield _sse_event(payload)

        # Live event loop — poll get_message with short sleep so we can interleave
        # disconnect checks and heartbeat without blocking the event loop.
        while True:
            # Disconnect detection: stop immediately if client navigated away
            if await request.is_disconnected():
                break

            # Heartbeat: keeps the connection alive through proxies (Nginx, ALB)
            # that would otherwise close idle streams after 60-75 s.
            now = time.monotonic()
            if now >= next_heartbeat:
                yield ": ping\n\n"
                next_heartbeat = now + _HEARTBEAT_INTERVAL

            message = await pubsub.get_message(ignore_subscribe_messages=True)
            if message is None:
                await asyncio.sleep(_POLL_INTERVAL)
                continue

            try:
                payload = json.loads(message["data"])
            except (json.JSONDecodeError, TypeError):
                continue

            yield _sse_event(payload)

            if _is_terminal(payload):
                break

    finally:
        await pubsub.unsubscribe(f"scan:{scan_id}")
        await pubsub.close()
        # Don't close `r` — it's the shared module-level pool; closing it would
        # break all other concurrent subscribers. The pool manages its own connections.
