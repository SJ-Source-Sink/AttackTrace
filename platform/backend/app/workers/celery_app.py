"""
Celery application setup with Redis broker.
"""

from celery import Celery
from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "attacktrace_platform",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["app.workers.scan_worker"],
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
    task_routes={
        "app.workers.scan_worker.run_scan": {"queue": "scans"},
        "app.workers.scan_worker.triage_scan_findings": {"queue": "ai"},
    },
    task_default_queue="default",
    broker_connection_retry_on_startup=True,
    result_expires=86400 * 7,  # Keep results for 7 days
)
