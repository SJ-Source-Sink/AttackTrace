"""
Celery periodic task: check for scheduled scans that are due and fire them.

Runs every 60 seconds via celery-beat.
"""

import logging
from datetime import datetime, timezone

from celery import shared_task
from croniter import croniter

from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="app.workers.schedule_worker.check_scheduled_scans", bind=True)
def check_scheduled_scans(self):
    """
    Poll the scheduled_scans table for rows that are active and overdue
    (next_run <= now()), create a ScanJob for each, and advance the schedule.
    """
    from app.workers.scan_worker import _get_sync_engine, _get_session_factory
    from app.models.db.scan import ScheduledScan, ScanJob, ScanStatus, ScanIntensity

    engine = _get_sync_engine()
    SessionFactory = _get_session_factory(engine)

    now = datetime.now(timezone.utc)

    with SessionFactory() as session:
        try:
            from sqlalchemy import select, and_

            due_schedules = session.execute(
                select(ScheduledScan).where(
                    and_(
                        ScheduledScan.is_active == True,  # noqa: E712
                        ScheduledScan.next_run != None,  # noqa: E711
                        ScheduledScan.next_run <= now,
                    )
                )
            ).scalars().all()

            for sched in due_schedules:
                try:
                    _fire_scheduled_scan(session, sched, now)
                except Exception as exc:
                    logger.error(
                        f"Failed to fire scheduled scan {sched.id} ({sched.name}): {exc}",
                        exc_info=True,
                    )
                    # Continue processing other schedules even if one fails

            session.commit()
        except Exception as exc:
            logger.error(f"check_scheduled_scans failed: {exc}", exc_info=True)
            session.rollback()


def _fire_scheduled_scan(session, sched: "ScheduledScan", now: datetime) -> None:
    """Create a ScanJob for the given schedule and enqueue it in Celery."""
    from app.models.db.scan import ScanJob, ScanStatus, ScanIntensity

    cfg = sched.scan_config or {}
    intensity_str = cfg.get("intensity", "passive")
    try:
        intensity = ScanIntensity(intensity_str)
    except ValueError:
        intensity = ScanIntensity.PASSIVE

    modules_to_skip: list[str] = cfg.get("modules_to_skip", [])

    job = ScanJob(
        org_id=sched.org_id,
        workspace_id=sched.workspace_id,
        created_by=sched.created_by,
        target_domains=sched.target_domains,
        company_name=sched.company_name,
        intensity=intensity,
        passive_only=(intensity == ScanIntensity.PASSIVE),
        modules_to_skip=modules_to_skip,
        status=ScanStatus.PENDING,
        findings_count={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
    )
    session.add(job)
    session.flush()

    # Dispatch to Celery scan worker
    from app.workers.scan_worker import run_scan
    celery_result = run_scan.apply_async(args=[str(job.id)], queue="scans")
    job.celery_task_id = celery_result.id
    session.add(job)
    session.flush()

    # Update schedule: advance next_run and record last execution
    sched.last_run = now
    sched.last_scan_job_id = job.id
    try:
        sched.next_run = croniter(sched.cron_expression, now).get_next(datetime)
    except Exception as exc:
        logger.warning(
            f"Could not compute next_run for schedule {sched.id}: {exc}. Deactivating."
        )
        sched.is_active = False
        sched.next_run = None

    session.add(sched)

    logger.info(
        f"Fired scheduled scan {sched.id} ({sched.name}) -> scan_job {job.id}; "
        f"next_run={sched.next_run}"
    )
