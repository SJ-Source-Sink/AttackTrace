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
    include=[
        "app.workers.scan_worker",
        "app.workers.schedule_worker",
        "app.workers.mobile_worker",
        "app.workers.maintenance_worker",
        "app.workers.easm_worker",
        "app.workers.correlation_worker",
        "app.workers.standalone_scan_worker",
        "app.workers.sla_worker",
    ],
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
    # Workers MUST be started with: -Q scans,default,ai
    task_routes={
        "app.workers.scan_worker.run_scan": {"queue": "scans"},
        "app.workers.scan_worker.recover_stuck_scans": {"queue": "default"},
        "app.workers.scan_worker.triage_scan_findings": {"queue": "ai"},
        "app.workers.scan_worker.run_ai_agent_after_scan": {"queue": "ai"},
        "app.workers.schedule_worker.check_scheduled_scans": {"queue": "default"},
        "app.workers.mobile_worker.run_mobile_scan": {"queue": "scans"},
        "app.workers.maintenance_worker.expire_stale_suppressions": {"queue": "default"},
        "app.workers.easm_worker.diff_asset_surface": {"queue": "default"},
        "app.workers.correlation_worker.correlate_after_scan": {"queue": "default"},
        "app.workers.correlation_worker.correlate_all_orgs": {"queue": "default"},
        "app.workers.standalone_scan_worker.run_standalone_scanners_after_scan": {"queue": "scans"},
        "app.workers.sla_worker.check_sla_breaches": {"queue": "default"},
    },
    task_default_queue="default",
    broker_connection_retry_on_startup=True,
    # Results kept for 24 hours — must outlive the longest possible task (7800s ≈ 2h10m)
    result_expires=86400,
    worker_concurrency=int(os.getenv("CELERYD_CONCURRENCY", "4")),
    # Recycle workers after N tasks to prevent memory bloat from long-running scans
    worker_max_tasks_per_child=int(os.getenv("CELERYD_MAX_TASKS_PER_CHILD", "50")),
    # Recycle workers exceeding 400MB RSS
    worker_max_memory_per_child=int(os.getenv("CELERYD_MAX_MEMORY_PER_CHILD", "400000")),
    # Broker transport options: visibility_timeout must exceed the longest task runtime.
    # If a task takes longer than visibility_timeout, Redis requeues it while it's still
    # running — causing duplicate execution. Set to 8 hours to be safe.
    broker_transport_options={
        "visibility_timeout": 28800,  # 8 hours
        "confirm_publish": True,       # Broker acks the enqueue; prevents silent drops
    },
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
        "expire-stale-suppressions-hourly": {
            # Clear suppressed=True on findings whose suppressed_until has passed.
            # Runs hourly; low urgency (findings are suppressed at worst 1h too long).
            "task": "app.workers.maintenance_worker.expire_stale_suppressions",
            "schedule": 3600.0,  # every hour
        },
        "diff-asset-surface-every-6h": {
            "task": "app.workers.easm_worker.diff_asset_surface",
            "schedule": 21600.0,  # every 6 hours
        },
        "correlate-all-orgs-every-6h": {
            # Catches correlations across findings from different scans/tools
            # run at different times, not just within one scan's own batch
            # (that case is covered by the post-scan correlate_after_scan
            # trigger in scan_worker.py instead).
            "task": "app.workers.correlation_worker.correlate_all_orgs",
            "schedule": 21600.0,  # every 6 hours
        },
        "check-sla-breaches-hourly": {
            # Finds OPEN findings whose sla_deadline has passed and fires
            # sla.breached notifications, once per finding. Hourly, matching
            # expire_stale_suppressions's cadence — SLA breaches don't need
            # minute-level freshness.
            "task": "app.workers.sla_worker.check_sla_breaches",
            "schedule": 3600.0,  # every hour
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
