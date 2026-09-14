"""
Maintenance Celery tasks: periodic housekeeping that doesn't belong in scan_worker.

Current tasks:
  expire_stale_suppressions — lift suppressed=True on findings whose suppressed_until has passed.
"""

import logging
from datetime import datetime, timezone

from app.workers.celery_app import celery_app
from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


@celery_app.task(
    name="app.workers.maintenance_worker.expire_stale_suppressions",
    bind=True,
    max_retries=2,
    default_retry_delay=60,
    ignore_result=True,
)
def expire_stale_suppressions(self):
    """
    Lift temporary suppressions on findings whose suppressed_until datetime has passed.

    A finding can be suppressed with an expiry date (e.g. "suppress for 30 days while
    the vendor patches"). This task runs hourly and restores such findings to OPEN so
    they re-appear in the active findings list for re-triage.

    At worst, a finding will remain suppressed ~1h longer than intended (the task period).
    """
    try:
        from sqlalchemy import create_engine, update
        from sqlalchemy.orm import sessionmaker

        db_url = settings.DATABASE_URL.replace("postgresql+asyncpg://", "postgresql+psycopg2://")
        engine = create_engine(db_url, pool_pre_ping=True, pool_size=2, max_overflow=2)
        try:
            Session = sessionmaker(bind=engine, expire_on_commit=False)

            now = datetime.now(timezone.utc)

            with Session() as session:
                from app.models.db.finding import Finding, FindingStatus

                stmt = (
                    update(Finding)
                    .where(
                        Finding.suppressed == True,
                        Finding.suppressed_until != None,
                        Finding.suppressed_until <= now,
                    )
                    .values(
                        suppressed=False,
                        suppressed_until=None,
                        suppressed_by=None,
                        suppressed_reason=None,
                        status=FindingStatus.OPEN,
                        updated_at=now,
                    )
                )
                result = session.execute(stmt)
                session.commit()
                count = result.rowcount

            if count > 0:
                logger.info(f"expire_stale_suppressions: lifted suppression on {count} finding(s)")
            else:
                logger.debug("expire_stale_suppressions: no expired suppressions found")
        finally:
            # Must run even if session.execute/commit above raised (which sends
            # control to the except block below and, via self.retry, straight
            # out of this task) — otherwise this connection-pooled engine
            # (pool_size=2, max_overflow=2) leaks up to 4 connections per
            # failed attempt, and this task retries hourly forever.
            engine.dispose()

    except Exception as exc:
        logger.error(f"expire_stale_suppressions failed: {exc}", exc_info=True)
        raise self.retry(exc=exc)
