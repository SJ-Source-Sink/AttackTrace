"""
Asset management API: list, filter, search, and update assets.
"""

import math
from typing import Annotated, List, Optional
from uuid import UUID

from pydantic import BaseModel as _PydanticBaseModel, Field

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.csv_safety import csv_safe
from app.core.database import get_db
from app.core.dependencies import get_current_org_id, get_current_user
from app.models.db.asset import Asset, AssetType
from app.models.db.audit import AuditLog
from app.models.db.user import OrgMember, User
from app.models.schemas.asset import AssetResponse, AssetUpdate

router = APIRouter(prefix="/assets", tags=["Assets"])


def _get_client_ip(request: Request) -> Optional[str]:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


@router.get(
    "",
    summary="List and filter assets with pagination",
    description=(
        "Supports filtering by type, scan, search term, risk score, tags, and active status. "
        "All results are scoped to the authenticated organization."
    ),
)
async def list_assets(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
    asset_type: Optional[str] = None,
    scan_job_id: Optional[str] = None,
    search: Optional[str] = None,
    min_risk_score: Optional[float] = None,
    max_risk_score: Optional[float] = None,
    tags: Optional[str] = None,  # comma-separated
    is_active: Optional[bool] = None,
    has_screenshot: Optional[bool] = None,
    page: int = 1,
    per_page: int = 50,
) -> dict:
    query = select(Asset).where(Asset.org_id == org_id)

    if asset_type:
        try:
            query = query.where(Asset.asset_type == AssetType(asset_type))
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": {"code": "INVALID_ASSET_TYPE", "message": f"Invalid asset type: {asset_type}"}},
            )

    if scan_job_id:
        try:
            query = query.where(Asset.scan_job_id == UUID(scan_job_id))
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": {"code": "INVALID_UUID", "message": "Invalid scan_job_id"}},
            )

    if search:
        query = query.where(Asset.value.ilike(f"%{search}%"))

    if min_risk_score is not None:
        query = query.where(Asset.risk_score >= min_risk_score)

    if max_risk_score is not None:
        query = query.where(Asset.risk_score <= max_risk_score)

    if tags:
        tag_list = [t.strip() for t in tags.split(",") if t.strip()]
        if tag_list:
            # overlap() → asset has ANY of the requested tags (PostgreSQL &&)
            query = query.where(Asset.tags.overlap(tag_list))

    if is_active is not None:
        query = query.where(Asset.is_active == is_active)

    if has_screenshot:
        query = query.where(Asset.screenshot_url.isnot(None))

    # Count
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar_one()

    # Paginate — webapps with screenshots bubble to top, then by risk score, then last seen
    has_screenshot_sort = case((Asset.screenshot_url.isnot(None), 0), else_=1)
    query = query.order_by(
        has_screenshot_sort,
        Asset.risk_score.desc().nulls_last(),
        Asset.last_seen.desc(),
    ).offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(query)
    assets = result.scalars().all()

    pages = math.ceil(total / per_page) if per_page > 0 else 0

    return {
        "items": [AssetResponse.from_orm(a).model_dump() for a in assets],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": pages,
    }


@router.get(
    "/{asset_id}",
    response_model=AssetResponse,
    summary="Get asset details",
)
async def get_asset(
    asset_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> AssetResponse:
    result = await db.execute(
        select(Asset).where(Asset.id == asset_id, Asset.org_id == org_id)
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "ASSET_NOT_FOUND", "message": "Asset not found"}},
        )
    return AssetResponse.from_orm(asset)


@router.patch(
    "/{asset_id}",
    response_model=AssetResponse,
    summary="Update asset tags, owner, risk score, or active status",
)
async def update_asset(
    asset_id: UUID,
    payload: AssetUpdate,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> AssetResponse:
    result = await db.execute(
        select(Asset).where(Asset.id == asset_id, Asset.org_id == org_id)
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "ASSET_NOT_FOUND", "message": "Asset not found"}},
        )

    if payload.tags is not None:
        asset.tags = payload.tags
    if payload.risk_score is not None:
        asset.risk_score = payload.risk_score
    if payload.is_active is not None:
        asset.is_active = payload.is_active
    if payload.owner_user_id is not None:
        try:
            asset.owner_user_id = UUID(payload.owner_user_id)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": {"code": "INVALID_UUID", "message": "Invalid owner_user_id"}},
            )

    db.add(asset)
    await db.flush()
    await db.refresh(asset)
    return AssetResponse.from_orm(asset)


class BulkTagPayload(_PydanticBaseModel):
    ids: List[str] = Field(..., min_length=1, max_length=500,
                            description="Up to 500 asset UUIDs to tag in one request")
    tags: List[str] = Field(..., min_length=1, description="Tags to add (merged with each asset's existing tags)")


class BulkAssignPayload(_PydanticBaseModel):
    ids: List[str] = Field(..., min_length=1, max_length=500,
                            description="Up to 500 asset UUIDs to assign an owner to in one request")
    owner: str = Field(..., description="user_id of the org member to assign as owner")


@router.post(
    "/bulk/tag",
    summary="Bulk-add tags to assets (merges with each asset's existing tags, max 500 per request)",
)
async def bulk_tag_assets(
    payload: BulkTagPayload,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    try:
        uuids = [UUID(aid) for aid in payload.ids]
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"code": "INVALID_UUID", "message": "One or more ids are not valid UUIDs"}},
        )

    new_tags = [t.strip() for t in payload.tags if t.strip()]
    if not new_tags:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"code": "INVALID_TAGS", "message": "No non-empty tags supplied"}},
        )

    result = await db.execute(
        select(Asset).where(Asset.org_id == org_id, Asset.id.in_(uuids))
    )
    assets = result.scalars().all()

    updated_count = 0
    for asset in assets:
        existing = list(asset.tags or [])
        merged = existing + [t for t in new_tags if t not in existing]
        if merged != existing:
            asset.tags = merged
            db.add(asset)
            updated_count += 1

    if updated_count > 0:
        log = AuditLog(
            org_id=org_id,
            user_id=current_user.id,
            action="asset.bulk_tagged",
            resource_type="asset_bulk",
            resource_id=f"{updated_count}_assets",
            before_state=None,
            after_state={"tags_added": new_tags, "asset_ids": [str(u) for u in uuids], "count": updated_count},
            ip_address=_get_client_ip(request),
        )
        db.add(log)

    await db.flush()
    return {"updated": updated_count, "not_found": len(uuids) - len(assets)}


@router.post(
    "/bulk/assign",
    summary="Bulk-assign an owner to assets (max 500 per request)",
)
async def bulk_assign_assets(
    payload: BulkAssignPayload,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    try:
        uuids = [UUID(aid) for aid in payload.ids]
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"code": "INVALID_UUID", "message": "One or more ids are not valid UUIDs"}},
        )

    try:
        owner_uuid = UUID(payload.owner)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"code": "INVALID_UUID", "message": "Invalid owner id"}},
        )

    # Validate the target user is actually a member of this org
    member_check = await db.execute(
        select(OrgMember.user_id).where(OrgMember.org_id == org_id, OrgMember.user_id == owner_uuid)
    )
    if member_check.scalar_one_or_none() is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"code": "NOT_ORG_MEMBER", "message": "Owner must be a member of this organization"}},
        )

    result = await db.execute(
        select(Asset).where(Asset.org_id == org_id, Asset.id.in_(uuids))
    )
    assets = result.scalars().all()

    for asset in assets:
        asset.owner_user_id = owner_uuid
        db.add(asset)

    if assets:
        log = AuditLog(
            org_id=org_id,
            user_id=current_user.id,
            action="asset.bulk_assigned",
            resource_type="asset_bulk",
            resource_id=f"{len(assets)}_assets",
            before_state=None,
            after_state={"owner_user_id": str(owner_uuid), "asset_ids": [str(u) for u in uuids], "count": len(assets)},
            ip_address=_get_client_ip(request),
        )
        db.add(log)

    await db.flush()
    return {"updated": len(assets), "not_found": len(uuids) - len(assets)}


@router.get(
    "/export/csv",
    summary="Export assets as CSV",
)
async def export_assets_csv(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
    ids: Optional[str] = None,  # comma-separated asset UUIDs; omit to export all filtered/visible assets
    asset_type: Optional[str] = None,
    search: Optional[str] = None,
):
    from fastapi.responses import StreamingResponse
    import csv, io

    query = select(Asset).where(Asset.org_id == org_id)

    if ids:
        try:
            id_list = [UUID(i.strip()) for i in ids.split(",") if i.strip()]
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": {"code": "INVALID_UUID", "message": "One or more ids are not valid UUIDs"}},
            )
        query = query.where(Asset.id.in_(id_list))

    if asset_type:
        try:
            query = query.where(Asset.asset_type == AssetType(asset_type))
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": {"code": "INVALID_ASSET_TYPE", "message": f"Invalid asset type: {asset_type}"}},
            )

    if search:
        query = query.where(Asset.value.ilike(f"%{search}%"))

    # Hard cap to prevent OOM — export at most 10k assets at once
    result = await db.execute(query.order_by(Asset.last_seen.desc()).limit(10_000))
    assets = result.scalars().all()

    # Resolve owner names for the export in one query
    owner_ids = {a.owner_user_id for a in assets if a.owner_user_id}
    owner_names: dict = {}
    if owner_ids:
        owner_rows = await db.execute(select(User.id, User.full_name, User.email).where(User.id.in_(owner_ids)))
        owner_names = {r[0]: (r[1] or r[2]) for r in owner_rows.all()}

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "id", "value", "asset_type", "tags", "owner", "risk_score",
        "is_active", "first_seen", "last_seen",
    ])
    for a in assets:
        writer.writerow([
            str(a.id),
            csv_safe(a.value),
            a.asset_type.value,
            csv_safe("|".join(a.tags or [])),
            csv_safe(owner_names.get(a.owner_user_id, "") if a.owner_user_id else ""),
            a.risk_score if a.risk_score is not None else "",
            "yes" if a.is_active else "no",
            a.first_seen.isoformat() if a.first_seen else "",
            a.last_seen.isoformat() if a.last_seen else "",
        ])
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=assets.csv"},
    )


@router.get(
    "/summary/by-type",
    summary="Get asset count summary grouped by type",
)
async def asset_type_summary(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    scan_job_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
) -> dict:
    query = select(Asset.asset_type, func.count(Asset.id).label("count")).where(
        Asset.org_id == org_id, Asset.is_active == True
    )

    if scan_job_id:
        try:
            query = query.where(Asset.scan_job_id == UUID(scan_job_id))
        except ValueError:
            pass

    query = query.group_by(Asset.asset_type)
    result = await db.execute(query)
    rows = result.all()

    return {row.asset_type.value: row.count for row in rows}


@router.get("/surface-diff/recent", summary="Recent attack-surface changes from continuous EASM diffing")
async def get_recent_surface_diff(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
    limit: int = 2,
) -> dict:
    """Diff the two most recent periodic AssetSnapshot rows (written by
    app.workers.easm_worker.diff_asset_surface) and summarize what changed."""
    from app.models.db.asset import AssetSnapshot

    result = await db.execute(
        select(AssetSnapshot)
        .where(AssetSnapshot.org_id == org_id)
        .order_by(AssetSnapshot.taken_at.desc())
        .limit(max(2, limit))
    )
    snapshots = result.scalars().all()
    if len(snapshots) < 2:
        return {
            "has_data": len(snapshots) == 1,
            "last_snapshot_at": snapshots[0].taken_at.isoformat() if snapshots else None,
            "new_assets": [],
            "message": "Need at least two periodic snapshots to diff — check back after the next EASM run.",
        }

    latest, previous = snapshots[0], snapshots[1]
    latest_map: dict = latest.snapshot or {}
    previous_map: dict = previous.snapshot or {}

    new_assets = [
        {"asset_id": aid, **latest_map[aid]}
        for aid in latest_map if aid not in previous_map
    ][:50]
    new_ports = []
    for aid, a in latest_map.items():
        if aid not in previous_map:
            continue
        prev_ports = set((previous_map.get(aid) or {}).get("ports") or [])
        opened = sorted(set(a.get("ports") or []) - prev_ports)
        if opened:
            new_ports.append({"asset_id": aid, "value": a.get("value"), "new_ports": opened})

    return {
        "has_data": True,
        "latest_snapshot_at": latest.taken_at.isoformat(),
        "previous_snapshot_at": previous.taken_at.isoformat(),
        "new_assets": new_assets,
        "new_assets_count": len(new_assets),
        "new_ports": new_ports[:50],
        "new_ports_count": len(new_ports),
    }
