"""
Celery application setup with Redis broker.
"""

import json
import os
from datetime import datetime, timezone

from celery import Celery
from celery.schedules import crontab
from celery.signals import task_failure
from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "attacktrace_platform",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["app.workers.scan_worker", "app.workers.schedule_worker"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_soft_time_limit=settings.CELERY_TASK_SOFT_TIME_LIMIT,
    task_time_limit=settings.CELERY_TASK_TIME_LIMIT,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    # All scan tasks go to the "scans" queue; default catches everything else.
    # Workers MUST be started with: -Q scans,default
    task_routes={
        "app.workers.scan_worker.run_scan": {"queue": "scans"},
        "app.workers.scan_worker.recover_stuck_scans": {"queue": "default"},
        "app.workers.scan_worker.triage_scan_findings": {"queue": "ai"},
        "app.workers.schedule_worker.check_scheduled_scans": {"queue": "default"},
    },
    task_default_queue="default",
    broker_connection_retry_on_startup=True,
    result_expires=3600,  # Keep results for 1 hour (was 7 days)
    worker_concurrency=int(os.getenv("CELERYD_CONCURRENCY", "4")),
    # Periodic tasks
    beat_schedule={
        "recover-stuck-scans-every-5min": {
            "task": "app.workers.scan_worker.recover_stuck_scans",
            "schedule": 300,  # every 5 minutes
        },
        "check-scheduled-scans": {
            "task": "app.workers.schedule_worker.check_scheduled_scans",
            "schedule": 60.0,  # every 60 seconds
        },
    },
)

# Optionally switch to redbeat for HA beat scheduler
# Set CELERY_BEAT_USE_REDBEAT=true in env to enable
if os.getenv("CELERY_BEAT_USE_REDBEAT", "false").lower() == "true":
    celery_app.conf.beat_scheduler = "redbeat.schedulers:RedBeatScheduler"
    celery_app.conf.redbeat_redis_url = settings.REDIS_URL


# --- Dead Letter Queue handler ---
# When a scan task exhausts all retries, write a structured record to a capped
# Redis list so operators can inspect and replay failed scans without losing context.

@task_failure.connect(sender="app.workers.scan_worker.run_scan")
def on_scan_task_failure(task_id, exception, args, kwargs, traceback, einfo, **kw):
    """Push exhausted scan tasks to a Redis DLQ for operator inspection."""
    try:
        import redis as _redis_sync
        r = _redis_sync.from_url(settings.REDIS_URL, decode_responses=True)
        entry = json.dumps({
            "task_id": task_id,
            "scan_job_id": args[0] if args else kwargs.get("scan_job_id"),
            "error": str(exception)[:500],
            "failed_at": datetime.now(timezone.utc).isoformat(),
        })
        dlq_key = "scans:dlq"
        r.rpush(dlq_key, entry)
        r.ltrim(dlq_key, -1000, -1)  # cap at 1000 entries
        r.close()
    except Exception:
        pass  # DLQ write failure must never crash the signal handler
