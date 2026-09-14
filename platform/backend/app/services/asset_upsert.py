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


def _extract_hostname(affected_asset: str) -> str | None:
    """Best-effort hostname extraction from a Finding.affected_asset string,
    which in practice is often a full URL (https://host/path/file.js), a bare
    hostname, or a non-host string (e.g. "inline-script-21") that shouldn't
    resolve to anything. Returns lowercased hostname, or None if nothing
    host-shaped could be extracted."""
    if not affected_asset:
        return None
    value = affected_asset.strip()
    if "://" in value:
        from urllib.parse import urlparse
        try:
            parsed = urlparse(value)
            host = parsed.hostname
        except ValueError:
            host = None
        return host.lower() if host else None
    # Bare value: only treat it as a hostname if it looks like one (contains
    # a dot or is a plausible IP) — reject arbitrary non-host strings.
    candidate = value.split("/")[0].split(":")[0].strip().lower()
    if not candidate or " " in candidate:
        return None
    if "." not in candidate:
        return None
    return candidate


async def resolve_asset_id(db: AsyncSession, org_id: UUID | str, affected_asset: str) -> UUID | None:
    """Best-effort lookup of the Asset row a Finding's affected_asset string
    refers to, so Finding.asset_id can be populated at creation time instead
    of staying permanently null (a real, previously-unnoticed gap — no
    scanner links findings to Asset rows today, which silently breaks the
    Asset detail page's finding list AND the correlation engine's asset-
    grouping, since both need Finding.asset_id). Read-only: never creates an
    Asset. Tries an exact value match first (handles bare hostnames/IPs
    written to affected_asset directly), then falls back to hostname
    extraction for URL-shaped values. Returns None rather than guessing when
    nothing matches — a missing link is much less harmful than a wrong one."""
    # `Asset.value` is only unique per (org_id, value, asset_type) — the same
    # string (e.g. "127.0.0.1") legitimately exists as more than one asset_type
    # row (IP AND SUBDOMAIN), so this must tolerate multiple matches rather
    # than assume at most one; `.limit(1)` picks arbitrarily among ties, which
    # is fine for this best-effort linking purpose.
    if not affected_asset:
        return None

    exact = (
        await db.execute(
            select(Asset.id).where(Asset.org_id == org_id, Asset.value == affected_asset.strip()).limit(1)
        )
    ).scalar_one_or_none()
    if exact:
        return exact

    host = _extract_hostname(affected_asset)
    if not host:
        return None
    return (
        await db.execute(select(Asset.id).where(Asset.org_id == org_id, Asset.value == host).limit(1))
    ).scalar_one_or_none()
