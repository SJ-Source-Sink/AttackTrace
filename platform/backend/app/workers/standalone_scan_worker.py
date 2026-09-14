"""
Auto-chain standalone scanner tools after an AGGRESSIVE core-pipeline scan.

Context: the core scan pipeline (scan_worker.py's own subdomain/DNS/port/web
enumeration) and the ~15 standalone scanner tools (nuclei, secrets, js_scanner,
takeover, api_scanner, cspm, ...) are architecturally separate — each
standalone tool is normally triggered manually from its own page. A user
running an "aggressive" scan reasonably expects that intensity level to mean
"run everything," not just "enumerate more thoroughly." This closes that gap
for a deliberately-curated, non-redundant subset of tools (see each task's
docstring below for why these four and not all ~15).

Bridges into each tool's real async generator/coroutine headlessly (no SSE
client), following the exact pattern already established by
scan_worker.py::_run_agent_once for the Attack Suite Agent — real Finding
rows land via each tool's own existing ingest_findings/DB-write logic as the
generator is driven, so no result-parsing is needed here, only draining.

Each tool runs as its OWN Celery task with its own soft/hard time limit,
rather than one task running all four sequentially. A prior single-task
version hit SoftTimeLimitExceeded in production (confirmed via
celery_app.AsyncResult) — four tools plus up to 200 takeover targets run
back-to-back could exceed the global 2h default, and worse, one slow tool
(e.g. takeover against a long subdomain list) held the worker slot hostage
for everything queued behind it and produced zero results for the tools that
never got to run. Splitting into independent tasks means: a slow/hung tool
only kills itself (bounded by its own limit below, well under the global
default), the other three still complete and their findings still land, and
failures are visible per-tool in Celery/logs instead of as one opaque
whole-chain error.
"""
import logging

from app.workers.celery_app import celery_app
from app.workers.scan_worker import _get_sync_engine, _get_session_factory
from app.core.config import get_settings

logger = logging.getLogger("attacktrace.standalone_scan")
settings = get_settings()

# Bounds so no single tool run can turn one aggressive scan into an
# hours-long chain — mirrors the philosophy of _AUTO_AGENT_BUDGET in
# scan_worker.py (a generous backstop, not a cost control, since these tools
# have no per-call API cost).
_MAX_SUBDOMAINS_FOR_TAKEOVER = 200
_MAX_DOMAINS_PER_TOOL = 3


class _NoOpRequest:
    """Minimal stand-in for FastAPI's Request — nuclei.py/secrets.py's SSE
    generators only ever call `await request.is_disconnected()` to know when
    to stop streaming to a client; there is no client here, so always False
    (never intentionally cancel — the per-task time limits are what actually
    stop this, not a missing "client")."""

    async def is_disconnected(self) -> bool:
        return False


def _load_scan_targets(scan_job_id: str):
    """Sync helper shared by all four tasks: resolve the scan job and its
    discovered domains/subdomains. Returns None if the scan_job_id is
    invalid or the job no longer exists."""
    from uuid import UUID
    from sqlalchemy import select as sync_select
    from app.models.db.scan import ScanJob
    from app.models.db.asset import Asset, AssetType

    engine = _get_sync_engine()
    SessionFactory = _get_session_factory(engine)

    with SessionFactory() as db:
        try:
            job_uuid = UUID(scan_job_id)
        except ValueError:
            logger.error(f"Invalid scan_job_id for standalone-scanner auto-chain: {scan_job_id!r}")
            return None

        job = db.get(ScanJob, job_uuid)
        if not job:
            return None

        subdomain_rows = db.execute(
            sync_select(Asset.value).where(
                Asset.org_id == job.org_id, Asset.asset_type == AssetType.SUBDOMAIN
            ).order_by(Asset.last_seen.desc()).limit(_MAX_SUBDOMAINS_FOR_TAKEOVER)
        ).all()
        subdomains = [row[0] for row in subdomain_rows]

        return {
            "org_id": job.org_id,
            "created_by": job.created_by,
            "target_domains": (job.target_domains or [])[:_MAX_DOMAINS_PER_TOOL],
            "subdomains": subdomains,
        }


def _make_async_session_factory():
    """Short-lived async engine/session factory — mirrors the bridging
    pattern already used by _run_agent_once/correlation_worker for driving
    async code from a sync Celery task without sharing the main app's
    event-loop-bound connection pool."""
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession as _AsyncSession
    from sqlalchemy.orm import sessionmaker as _sessionmaker

    async_db_url = settings.DATABASE_URL
    if not async_db_url.startswith("postgresql+asyncpg"):
        async_db_url = async_db_url.replace("postgresql://", "postgresql+asyncpg://").replace(
            "postgresql+psycopg2://", "postgresql+asyncpg://"
        )
    engine = create_async_engine(async_db_url, pool_pre_ping=True, pool_size=1, max_overflow=0)
    Session = _sessionmaker(engine, class_=_AsyncSession, expire_on_commit=False)
    return engine, Session


async def _run_auto_nuclei(org_id, domains: list[str]) -> dict:
    import uuid as _uuid
    import shutil

    if not shutil.which("nuclei"):
        return {"status": "skipped", "reason": "nuclei not installed"}

    engine, Session = _make_async_session_factory()
    try:
        from app.api.v1.nuclei import _stream_nuclei, NucleiScanRequest
        # Bounded to high-signal categories, not nuclei's full default template
        # set — verified via live testing that a full-template run against one
        # real domain alone can run for 1+ hour. "takeovers" excluded
        # deliberately: the dedicated takeover tool does that fingerprinting
        # more thoroughly already.
        _NUCLEI_AUTO_CATEGORIES = ["cves", "misconfiguration", "exposures", "default-logins"]
        fake_request = _NoOpRequest()
        for domain in domains:
            async with Session() as db:
                scan_id = str(_uuid.uuid4())
                req = NucleiScanRequest(target=domain, categories=_NUCLEI_AUTO_CATEGORIES)
                async for _ in _stream_nuclei(scan_id, req, fake_request, org_id):
                    pass
        return {"status": "completed", "domains_scanned": len(domains), "categories": _NUCLEI_AUTO_CATEGORIES}
    finally:
        await engine.dispose()


async def _run_auto_secrets(org_id, domains: list[str]) -> dict:
    import uuid as _uuid

    engine, Session = _make_async_session_factory()
    try:
        from app.api.v1.secrets import _stream_secret_scan, SecretScanRequest
        fake_request = _NoOpRequest()
        for domain in domains:
            async with Session() as db:
                scan_id = str(_uuid.uuid4())
                req = SecretScanRequest(target=domain, scan_type="url")
                async for _ in _stream_secret_scan(scan_id, str(org_id), req, fake_request, db):
                    pass
        return {"status": "completed", "domains_scanned": len(domains)}
    finally:
        await engine.dispose()


async def _run_auto_js_scanner(org_id, domains: list[str]) -> dict:
    import uuid as _uuid

    engine, Session = _make_async_session_factory()
    try:
        from app.api.v1.js_scanner import _safe_js_scan, JSScanRequest
        for domain in domains:
            async with Session() as db:
                scan_id = str(_uuid.uuid4())
                req = JSScanRequest(target=domain, include_subdomains=True)
                async for _ in _safe_js_scan(req, scan_id, str(org_id), db):
                    pass
        return {"status": "completed", "domains_scanned": len(domains)}
    finally:
        await engine.dispose()


async def _run_auto_takeover(org_id, subdomains: list[str]) -> dict:
    import uuid as _uuid

    if not subdomains:
        return {"status": "skipped", "reason": "no_subdomains"}

    engine, Session = _make_async_session_factory()
    try:
        from app.api.v1.takeover import _stream_takeover_scan, TakeoverRequest
        async with Session() as db:
            scan_id = str(_uuid.uuid4())
            req = TakeoverRequest(targets=subdomains)
            async for _ in _stream_takeover_scan(scan_id, req, "auto-scan@system", org_id, db):
                pass
        return {"status": "completed", "targets_scanned": len(subdomains)}
    finally:
        await engine.dispose()


# Each task gets its own bound, well under the global 2h default
# (CELERY_TASK_SOFT_TIME_LIMIT) — a hang in one tool now fails fast and in
# isolation instead of silently consuming the entire global budget and
# blocking the three tools queued behind it.

@celery_app.task(
    name="app.workers.standalone_scan_worker.run_auto_nuclei",
    bind=True, max_retries=0, soft_time_limit=1800, time_limit=1860,
)
def run_auto_nuclei(self, scan_job_id: str) -> dict:
    import asyncio
    targets = _load_scan_targets(scan_job_id)
    if not targets:
        return {"error": "scan_not_found"}
    try:
        result = asyncio.run(_run_auto_nuclei(targets["org_id"], targets["target_domains"]))
        logger.info(f"Auto nuclei for scan {scan_job_id}: {result}")
        return result
    except Exception as e:
        logger.exception(f"Auto nuclei failed for scan {scan_job_id}: {e}")
        return {"status": "error", "error": str(e)[:500]}


@celery_app.task(
    name="app.workers.standalone_scan_worker.run_auto_secrets",
    bind=True, max_retries=0, soft_time_limit=1200, time_limit=1260,
)
def run_auto_secrets(self, scan_job_id: str) -> dict:
    import asyncio
    targets = _load_scan_targets(scan_job_id)
    if not targets:
        return {"error": "scan_not_found"}
    try:
        result = asyncio.run(_run_auto_secrets(targets["org_id"], targets["target_domains"]))
        logger.info(f"Auto secrets scan for scan {scan_job_id}: {result}")
        return result
    except Exception as e:
        logger.exception(f"Auto secrets scan failed for scan {scan_job_id}: {e}")
        return {"status": "error", "error": str(e)[:500]}


@celery_app.task(
    name="app.workers.standalone_scan_worker.run_auto_js_scanner",
    bind=True, max_retries=0, soft_time_limit=1200, time_limit=1260,
)
def run_auto_js_scanner(self, scan_job_id: str) -> dict:
    import asyncio
    targets = _load_scan_targets(scan_job_id)
    if not targets:
        return {"error": "scan_not_found"}
    try:
        result = asyncio.run(_run_auto_js_scanner(targets["org_id"], targets["target_domains"]))
        logger.info(f"Auto js_scanner for scan {scan_job_id}: {result}")
        return result
    except Exception as e:
        logger.exception(f"Auto js_scanner failed for scan {scan_job_id}: {e}")
        return {"status": "error", "error": str(e)[:500]}


@celery_app.task(
    name="app.workers.standalone_scan_worker.run_auto_takeover",
    bind=True, max_retries=0, soft_time_limit=1800, time_limit=1860,
)
def run_auto_takeover(self, scan_job_id: str) -> dict:
    import asyncio
    targets = _load_scan_targets(scan_job_id)
    if not targets:
        return {"error": "scan_not_found"}
    try:
        result = asyncio.run(_run_auto_takeover(targets["org_id"], targets["subdomains"]))
        logger.info(f"Auto takeover for scan {scan_job_id}: {result}")
        return result
    except Exception as e:
        logger.exception(f"Auto takeover failed for scan {scan_job_id}: {e}")
        return {"status": "error", "error": str(e)[:500]}
