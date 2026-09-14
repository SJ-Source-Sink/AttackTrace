"""
SLA breach detection Celery task.

Finding.sla_deadline (app/services/sla_service.py::compute_sla_deadline) is
computed and stored on every finding at creation time, but nothing ever
checked it against the current time and fired the sla.breached notification
event (which the notification-channel UI and app/api/v1/notifications.py's
VALID_EVENTS have supported since it was added — it was just never dispatched
from anywhere). This worker closes that gap.

Current tasks:
  check_sla_breaches — for every org, finds OPEN findings whose sla_deadline
  has passed and haven't already been flagged, dispatches an sla.breached
  notification for each, then stamps sla_breach_notified_at so the same
  finding is never re-notified on a later run.
"""

import asyncio
import logging
from datetime import datetime, timezone

from app.workers.celery_app import celery_app
from app.workers.scan_worker import _get_sync_engine, _get_session_factory

logger = logging.getLogger("attacktrace.sla")

# Safety bound per run — breaches are re-checked hourly, so a large backlog
# (e.g. after this feature first ships) drains over a few runs rather than
# one run holding a huge result set / blocking beat.
_MAX_FINDINGS_PER_RUN = 500


async def _dispatch_breaches(org_id: str, events: list[tuple[str, dict]]) -> None:
    """Dispatch a batch of sla.breached notification events for one org through a
    single short-lived async session — mirrors easm_worker.py's _dispatch_all,
    the established pattern for bridging a sync Celery task into the async
    dispatch_notifications helper."""
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from sqlalchemy.orm import sessionmaker as _sessionmaker
    from app.services.notification_service import dispatch_notifications
    from app.core.config import get_settings

    settings = get_settings()
    async_db_url = settings.DATABASE_URL
    if not async_db_url.startswith("postgresql+asyncpg"):
        async_db_url = async_db_url.replace("postgresql://", "postgresql+asyncpg://").replace(
            "postgresql+psycopg2://", "postgresql+asyncpg://"
        )
    engine = create_async_engine(async_db_url, pool_pre_ping=True, pool_size=1, max_overflow=0)
    Session = _sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with Session() as db:
            for event_type, payload in events:
                try:
                    await dispatch_notifications(org_id=org_id, event_type=event_type, payload=payload, db_session=db)
                except Exception as exc:
                    logger.warning(f"dispatch_notifications {event_type} failed for org {org_id}: {exc}")
    finally:
        await engine.dispose()


@celery_app.task(
    name="app.workers.sla_worker.check_sla_breaches",
    bind=True,
    max_retries=2,
    default_retry_delay=60,
    ignore_result=True,
)
def check_sla_breaches(self) -> dict:
    """
    Periodic task: find OPEN findings across all orgs whose sla_deadline has
    passed and which haven't already been notified (sla_breach_notified_at
    IS NULL), fire an sla.breached notification for each — grouped per org so
    each org's channels are dispatched through one short-lived async DB
    session — then stamp sla_breach_notified_at so a later run never
    re-notifies the same finding.

    Runs hourly, matching expire_stale_suppressions's cadence — SLA breaches
    don't need minute-level freshness.
    """
    from sqlalchemy import select, update
    from app.models.db.finding import Finding, FindingStatus

    engine = _get_sync_engine()
    SessionFactory = _get_session_factory(engine)

    now = datetime.now(timezone.utc)
    notified_count = 0
    orgs_with_breaches = 0

    with SessionFactory() as session:
        stmt = (
            select(Finding)
            .where(
                Finding.status == FindingStatus.OPEN,
                Finding.sla_deadline.isnot(None),
                Finding.sla_deadline < now,
                Finding.sla_breach_notified_at.is_(None),
            )
            .order_by(Finding.sla_deadline.asc())
            .limit(_MAX_FINDINGS_PER_RUN)
        )
        breached = session.execute(stmt).scalars().all()

        if not breached:
            logger.debug("check_sla_breaches: no newly-breached findings found")
            return {"notified": 0, "orgs": 0}

        by_org: dict[str, list] = {}
        for f in breached:
            by_org.setdefault(str(f.org_id), []).append(f)

        for org_id, findings in by_org.items():
            events: list[tuple[str, dict]] = [
                (
                    "sla.breached",
                    {
                        "finding_id": str(f.id),
                        "scan_id": f.source_scan_id or (str(f.scan_job_id) if f.scan_job_id else ""),
                        "org_id": org_id,
                        "title": f.title,
                        "severity": f.severity.value,
                        "affected_asset": f.affected_asset or "",
                        "sla_deadline": f.sla_deadline.isoformat() if f.sla_deadline else None,
                    },
                )
                for f in findings
            ]

            try:
                asyncio.run(_dispatch_breaches(org_id, events))
            except Exception as exc:
                # dispatch_notifications already swallows per-channel failures
                # internally; this only guards asyncio.run/session setup itself.
                # Still fall through to marking these notified below — a bad
                # webhook/channel config must not cause the same finding to be
                # retried forever.
                logger.warning(f"check_sla_breaches: notification dispatch failed for org {org_id}: {exc}")

            orgs_with_breaches += 1
            ids = [f.id for f in findings]
            session.execute(
                update(Finding).where(Finding.id.in_(ids)).values(sla_breach_notified_at=now)
            )
            session.commit()
            notified_count += len(findings)

    logger.info(f"check_sla_breaches: notified {notified_count} finding(s) across {orgs_with_breaches} org(s)")
    return {"notified": notified_count, "orgs": orgs_with_breaches}
