"""
Async asset upsert helper for standalone scanner routers (nmap, ffuf, and any
future point-scanner) that discover host-level detail — open ports, service
banners, discovered paths — outside the main orchestrated scan_worker.py
pipeline (which has its own sync/Celery-only _upsert_asset).

Unlike scan_worker.py's version, this MERGES metadata_ rather than overwriting
it wholesale, so nmap and ffuf can both contribute to the same host's record
without one clobbering the other's fields.
"""
from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.db.asset import Asset, AssetType


async def upsert_asset_async(
    db: AsyncSession,
    org_id: UUID | str,
    asset_type: AssetType,
    value: str,
    metadata_patch: dict,
) -> Asset:
    """Merge metadata_patch into the existing asset's metadata_, or create a
    new asset if none exists yet for (org_id, value, asset_type)."""
    existing = (
        await db.execute(
            select(Asset).where(
                Asset.org_id == org_id, Asset.value == value, Asset.asset_type == asset_type
            )
        )
    ).scalar_one_or_none()

    if existing is not None:
        existing.metadata_ = {**(existing.metadata_ or {}), **metadata_patch}
        db.add(existing)
        return existing

    asset = Asset(org_id=org_id, asset_type=asset_type, value=value, metadata_=metadata_patch)
    db.add(asset)
    try:
        await db.flush()
    except IntegrityError:
        # Lost a race with a concurrent insert for the same (org, value, type) —
        # fall back to updating the row that won.
        await db.rollback()
        existing = (
            await db.execute(
                select(Asset).where(
                    Asset.org_id == org_id, Asset.value == value, Asset.asset_type == asset_type
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            existing.metadata_ = {**(existing.metadata_ or {}), **metadata_patch}
            db.add(existing)
            return existing
    return asset
