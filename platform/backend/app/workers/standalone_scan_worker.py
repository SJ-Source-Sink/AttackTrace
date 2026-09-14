"""
Auto-chain standalone scanner tools after an AGGRESSIVE core-pipeline scan.

Context: the core scan pipeline (scan_worker.py's own subdomain/DNS/port/web
enumeration) and the ~15 standalone scanner tools (nuclei, secrets, js_scanner,
takeover, api_scanner, cspm, ...) are architecturally separate — each
standalone tool is normally triggered manually from its own page. A user
running an "aggressive" scan reasonably expects that intensity level to mean
"run everything," not just "enumerate more thoroughly." This task closes that
gap for a deliberately-curated, non-redundant subset of tools (see
_run_standalone_scanners' docstring for why these four and not all ~15).

Bridges into each tool's real async generator/coroutine headlessly (no SSE
client), following the exact pattern already established by
scan_worker.py::_run_agent_once for the Attack Suite Agent — real Finding
rows land via each tool's own existing ingest_findings/DB-write logic as the
generator is driven, so no result-parsing is needed here, only draining.
"""
import logging

from app.workers.celery_app import celery_app
from app.workers.scan_worker import _get_sync_engine, _get_session_factory
from app.core.config import get_settings

logger = logging.getLogger("attacktrace.standalone_scan")
settings = get_settings()

# Bounds so this can't turn one aggressive scan into an hours-long chain —
# mirrors the philosophy of _AUTO_AGENT_BUDGET in scan_worker.py (a generous
# backstop, not a cost control, since these tools have no per-call API cost).
_MAX_SUBDOMAINS_FOR_TAKEOVER = 200
_MAX_DOMAINS_PER_TOOL = 3


class _NoOpRequest:
    """Minimal stand-in for FastAPI's Request — nuclei.py/secrets.py's SSE
    generators only ever call `await request.is_disconnected()` to know when
    to stop streaming to a client; there is no client here, so always False
    (never intentionally cancel — the budget/timeout bounds above are what
    actually stop this, not a missing "client")."""

    async def is_disconnected(self) -> bool:
        return False


async def _run_standalone_scanners(org_id, user_id, target_domains: list[str], subdomains: list[str]) -> dict:
    """Run the curated tool set against one scan's discovered targets, on its
    own short-lived async engine (mirrors _run_agent_once/correlation_worker's
    bridging pattern). Each tool's failure is isolated — one tool erroring
    never stops the others."""
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession as _AsyncSession
    from sqlalchemy.orm import sessionmaker as _sessionmaker
    import uuid as _uuid

    async_db_url = settings.DATABASE_URL
    if not async_db_url.startswith("postgresql+asyncpg"):
        async_db_url = async_db_url.replace("postgresql://", "postgresql+asyncpg://").replace(
            "postgresql+psycopg2://", "postgresql+asyncpg://"
        )
    engine = create_async_engine(async_db_url, pool_pre_ping=True, pool_size=1, max_overflow=0)
    Session = _sessionmaker(engine, class_=_AsyncSession, expire_on_commit=False)

    results: dict[str, dict] = {}
    domains = target_domains[:_MAX_DOMAINS_PER_TOOL]
    fake_request = _NoOpRequest()

    try:
        # --- nuclei: template-based CVE/misconfiguration scanning — the
        # core pipeline has no equivalent, this is genuinely new coverage. ---
        try:
            import shutil
            if not shutil.which("nuclei"):
                results["nuclei"] = {"status": "skipped", "reason": "nuclei not installed"}
            else:
                from app.api.v1.nuclei import _stream_nuclei, NucleiScanRequest
                for domain in domains:
                    async with Session() as db:
                        scan_id = str(_uuid.uuid4())
                        req = NucleiScanRequest(target=domain)
                        async for _ in _stream_nuclei(scan_id, req, fake_request, org_id):
                            pass
                results["nuclei"] = {"status": "completed", "domains_scanned": len(domains)}
        except Exception as e:
            logger.exception(f"Auto nuclei scan failed: {e}")
            results["nuclei"] = {"status": "error", "error": str(e)[:500]}

        # --- secrets: dedicated pattern+entropy secret scanning against
        # live pages (deeper than the AI agent's ad-hoc run_secret_scan tool
        # calls, and independent of whether the agent happened to look). ---
        try:
            from app.api.v1.secrets import _stream_secret_scan, SecretScanRequest
            for domain in domains:
                async with Session() as db:
                    scan_id = str(_uuid.uuid4())
                    req = SecretScanRequest(target=domain, scan_type="url")
                    async for _ in _stream_secret_scan(scan_id, str(org_id), req, fake_request, db):
                        pass
            results["secrets"] = {"status": "completed", "domains_scanned": len(domains)}
        except Exception as e:
            logger.exception(f"Auto secrets scan failed: {e}")
            results["secrets"] = {"status": "error", "error": str(e)[:500]}

        # --- js_scanner: static JS bundle analysis (secrets, DOM sinks,
        # prototype pollution, outdated libs) — the core pipeline doesn't
        # parse JS at all. ---
        try:
            from app.api.v1.js_scanner import _safe_js_scan, JSScanRequest
            for domain in domains:
                async with Session() as db:
                    scan_id = str(_uuid.uuid4())
                    req = JSScanRequest(target=domain, include_subdomains=True)
                    async for _ in _safe_js_scan(req, scan_id, str(org_id), db):
                        pass
            results["js_scanner"] = {"status": "completed", "domains_scanned": len(domains)}
        except Exception as e:
            logger.exception(f"Auto js_scanner scan failed: {e}")
            results["js_scanner"] = {"status": "error", "error": str(e)[:500]}

        # --- takeover: dedicated CNAME/NS/MX dangling-record fingerprinting
        # against every discovered subdomain — deeper than anything the core
        # pipeline or the AI agent (scope-restricted, opportunistic) does. ---
        try:
            from app.api.v1.takeover import _stream_takeover_scan, TakeoverRequest
            targets = subdomains[:_MAX_SUBDOMAINS_FOR_TAKEOVER]
            if targets:
                async with Session() as db:
                    scan_id = str(_uuid.uuid4())
                    req = TakeoverRequest(targets=targets)
                    async for _ in _stream_takeover_scan(scan_id, req, "auto-scan@system", org_id, db):
                        pass
                results["takeover"] = {"status": "completed", "targets_scanned": len(targets)}
            else:
                results["takeover"] = {"status": "skipped", "reason": "no_subdomains"}
        except Exception as e:
            logger.exception(f"Auto takeover scan failed: {e}")
            results["takeover"] = {"status": "error", "error": str(e)[:500]}
    finally:
        await engine.dispose()

    return results


@celery_app.task(
    name="app.workers.standalone_scan_worker.run_standalone_scanners_after_scan",
    bind=True,
    max_retries=0,
)
def run_standalone_scanners_after_scan(self, scan_job_id: str) -> dict:
    """Fired only for AGGRESSIVE-intensity scans (checked by the caller
    before dispatch) — runs nuclei, secrets, js_scanner, and takeover against
    the scan's discovered domains/subdomains. Deliberately NOT the full ~15
    standalone-tool catalog: cspm/container_scanner need cloud/registry
    credentials this generic auto-trigger has no basis to assume are
    relevant to this target; api_scanner needs a real API spec/base path to
    be effective rather than a bare domain; email_security/exposure_scanner/
    mcp_scanner are lower-signal or narrower-applicability for a generic web
    target. The four chosen here all operate meaningfully on "a domain" or
    "a list of subdomains" alone, matching what a scan actually produces.
    """
    import asyncio
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
            logger.error(f"Invalid scan_job_id for standalone-scanner chain: {scan_job_id!r}")
            return {"error": "invalid_scan_job_id"}

        job = db.get(ScanJob, job_uuid)
        if not job:
            return {"error": "scan_not_found"}

        subdomain_rows = db.execute(
            sync_select(Asset.value).where(
                Asset.org_id == job.org_id, Asset.asset_type == AssetType.SUBDOMAIN
            ).order_by(Asset.last_seen.desc()).limit(_MAX_SUBDOMAINS_FOR_TAKEOVER)
        ).all()
        subdomains = [row[0] for row in subdomain_rows]

        try:
            results = asyncio.run(
                _run_standalone_scanners(job.org_id, job.created_by, job.target_domains or [], subdomains)
            )
            logger.info(f"Auto standalone-scanner chain for scan {scan_job_id}: {results}")
            return {"status": "completed", "results": results}
        except Exception as e:
            logger.exception(f"Standalone-scanner chain failed for scan {scan_job_id}: {e}")
            return {"status": "error", "error": str(e)[:500]}
