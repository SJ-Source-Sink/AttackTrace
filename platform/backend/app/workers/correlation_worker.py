"""
Cross-scanner correlation Celery tasks.

Two trigger points for app.services.correlation_engine.run_correlation:
1. `correlate_after_scan(scan_job_id)` — fired right after a scan completes
   (alongside triage_scan_findings/run_ai_agent_after_scan in scan_worker.py),
   so new findings get correlated against the org's existing findings/assets
   immediately.
2. `correlate_all_orgs()` — a periodic Celery Beat pass (every 6h, matching
   easm_worker.diff_asset_surface's cadence) so correlations also form
   between findings discovered by different scans/standalone scanners run at
   different times, not just within one scan's own batch.

Both bridge into the async `correlation_engine.run_correlation` via a
short-lived async engine per call, following the exact pattern already
established in scan_worker.py (_run_agent_once) and easm_worker.py
(_dispatch_all) for calling async code from a sync Celery task.
"""
import logging

from app.workers.celery_app import celery_app
from app.workers.scan_worker import _get_sync_engine, _get_session_factory
from app.core.config import get_settings

logger = logging.getLogger("attacktrace.correlation")
settings = get_settings()


async def _run_correlation_async(org_id: str) -> dict:
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from sqlalchemy.orm import sessionmaker as _sessionmaker
    from app.services.correlation_engine import run_correlation

    async_db_url = settings.DATABASE_URL
    if not async_db_url.startswith("postgresql+asyncpg"):
        async_db_url = async_db_url.replace("postgresql://", "postgresql+asyncpg://").replace(
            "postgresql+psycopg2://", "postgresql+asyncpg://"
        )
    engine = create_async_engine(async_db_url, pool_pre_ping=True, pool_size=1, max_overflow=0)
    Session = _sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with Session() as db:
            result = await run_correlation(db, org_id)
            await db.commit()
            return result
    finally:
        await engine.dispose()


@celery_app.task(
    name="app.workers.correlation_worker.correlate_after_scan",
    bind=True,
    max_retries=1,
    default_retry_delay=30,
)
def correlate_after_scan(self, scan_job_id: str) -> dict:
    """Run the correlation engine for the org that owns this scan, right
    after the scan completes. Fully non-fatal to the scan pipeline — any
    failure here is logged and swallowed, never retried into a scan-blocking
    state."""
    import asyncio
    from uuid import UUID
    from sqlalchemy import select as sync_select
    from app.models.db.scan import ScanJob

    engine = _get_sync_engine()
    SessionFactory = _get_session_factory(engine)

    with SessionFactory() as db:
        try:
            job = db.execute(sync_select(ScanJob).where(ScanJob.id == UUID(scan_job_id))).scalar_one_or_none()
        except ValueError:
            logger.error(f"Invalid scan_job_id for correlation: {scan_job_id!r}")
            return {"error": "invalid_scan_job_id"}
        if not job:
            return {"error": "scan_not_found"}

        try:
            result = asyncio.run(_run_correlation_async(str(job.org_id)))
            logger.info(f"Correlation after scan {scan_job_id}: {result}")
            return result
        except Exception as e:
            logger.exception(f"Correlation engine failed for scan {scan_job_id}: {e}")
            return {"status": "error", "error": str(e)[:500]}


@celery_app.task(name="app.workers.correlation_worker.correlate_all_orgs")
def correlate_all_orgs() -> dict:
    """Periodic pass: run the correlation engine for every org that has any
    open findings. Each org's correlation runs in its own short-lived async
    engine/transaction so one org's failure can't affect another's."""
    import asyncio
    from sqlalchemy import select as sync_select
    from app.models.db.finding import Finding, FindingStatus

    engine = _get_sync_engine()
    SessionFactory = _get_session_factory(engine)

    with SessionFactory() as db:
        org_ids = [
            row[0] for row in db.execute(
                sync_select(Finding.org_id).where(Finding.status == FindingStatus.OPEN).distinct()
            )
        ]

    results = {}
    for org_id in org_ids:
        try:
            results[str(org_id)] = asyncio.run(_run_correlation_async(str(org_id)))
        except Exception as e:
            logger.exception(f"Correlation engine failed for org {org_id}: {e}")
            results[str(org_id)] = {"status": "error", "error": str(e)[:500]}

    logger.info(f"Periodic correlation pass: {len(org_ids)} orgs processed")
    return {"orgs_processed": len(org_ids), "results": results}
