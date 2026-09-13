"""
EASM (External Attack Surface Management) continuous diffing worker.

Runs periodically (independent of any specific scan) to catch attack-surface
drift between scans: snapshots each org's current Asset table, diffs it
against that org's previous snapshot, and fires notifications for new assets,
newly opened ports, and soon-to-expire TLS certs.
"""
import asyncio
import logging
import socket
import ssl
from datetime import datetime, timezone

from app.workers.celery_app import celery_app
from app.workers.scan_worker import _get_sync_engine, _get_session_factory

logger = logging.getLogger("attacktrace.easm")

_CERT_EXPIRY_WARNING_DAYS = 14
_MAX_TLS_CHECKS_PER_ORG = 20


def _check_tls_expiry(hostname: str, port: int = 443, timeout: float = 5.0) -> int | None:
    """Return days until TLS cert expiry for hostname, or None on any failure."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        not_after = cert.get("notAfter") if cert else None
        if not not_after:
            return None
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        return (expiry - datetime.now(timezone.utc)).days
    except Exception:
        return None


async def _dispatch_all(org_id: str, events: list[tuple[str, dict]]) -> None:
    """Dispatch a batch of notification events for one org through a single
    short-lived async session, rather than opening a new DB engine per event."""
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


@celery_app.task(name="app.workers.easm_worker.diff_asset_surface")
def diff_asset_surface() -> dict:
    """
    Periodic task: for every org with assets, snapshot current Asset rows,
    diff against that org's most recent AssetSnapshot, and fire notifications
    for new assets / newly opened ports. Also spot-checks TLS cert expiry for
    a bounded number of webapp/domain assets per org per run.
    """
    from sqlalchemy import select
    from app.models.db.asset import Asset, AssetSnapshot, AssetType

    engine = _get_sync_engine()
    SessionFactory = _get_session_factory(engine)

    orgs_processed = 0
    new_assets_total = 0
    new_ports_total = 0
    certs_checked = 0

    with SessionFactory() as db:
        org_ids = [row[0] for row in db.execute(select(Asset.org_id).distinct())]

        for org_id in org_ids:
            assets = db.execute(select(Asset).where(Asset.org_id == org_id)).scalars().all()
            current: dict[str, dict] = {
                str(a.id): {
                    "value": a.value,
                    "asset_type": a.asset_type.value,
                    "ports": (a.metadata_ or {}).get("ports") or (a.metadata_ or {}).get("open_ports") or [],
                }
                for a in assets
            }

            prev_snapshot_row = db.execute(
                select(AssetSnapshot)
                .where(AssetSnapshot.org_id == org_id)
                .order_by(AssetSnapshot.taken_at.desc())
                .limit(1)
            ).scalar_one_or_none()
            previous: dict = (prev_snapshot_row.snapshot if prev_snapshot_row else {}) or {}

            org_events: list[tuple[str, dict]] = []

            new_asset_ids = [aid for aid in current if aid not in previous]
            for aid in new_asset_ids:
                a = current[aid]
                org_events.append(("asset.discovered", {
                    "org_id": str(org_id), "asset_id": aid,
                    "value": a["value"], "asset_type": a["asset_type"],
                }))
            new_assets_total += len(new_asset_ids)

            for aid, a in current.items():
                if aid not in previous:
                    continue  # first discovery already covered by asset.discovered
                prev_ports = set((previous.get(aid) or {}).get("ports") or [])
                new_ports = set(a["ports"] or []) - prev_ports
                if new_ports:
                    org_events.append(("port.opened", {
                        "org_id": str(org_id), "asset_id": aid,
                        "value": a["value"], "new_ports": sorted(new_ports),
                    }))
                    new_ports_total += len(new_ports)

            # Bounded TLS expiry spot-check (webapp/domain/subdomain assets only)
            web_assets = [
                a for a in assets
                if a.asset_type in (AssetType.WEBAPP, AssetType.DOMAIN, AssetType.SUBDOMAIN)
            ][:_MAX_TLS_CHECKS_PER_ORG]
            for a in web_assets:
                hostname = a.value.split("://")[-1].split("/")[0].split(":")[0]
                days_left = _check_tls_expiry(hostname)
                certs_checked += 1
                if days_left is not None and days_left <= _CERT_EXPIRY_WARNING_DAYS:
                    org_events.append(("cert.expiring", {
                        "org_id": str(org_id), "asset_id": str(a.id),
                        "value": a.value, "days_left": days_left,
                    }))

            if org_events:
                try:
                    asyncio.run(_dispatch_all(str(org_id), org_events))
                except Exception as exc:
                    logger.warning(f"EASM notification dispatch failed for org {org_id}: {exc}")

            db.add(AssetSnapshot(org_id=org_id, snapshot=current, asset_count=len(current)))
            db.commit()
            orgs_processed += 1

    return {
        "orgs_processed": orgs_processed,
        "new_assets": new_assets_total,
        "new_ports": new_ports_total,
        "certs_checked": certs_checked,
    }
