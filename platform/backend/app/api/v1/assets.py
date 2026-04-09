"""
Asset management API: list, filter, search, and update assets.
"""

import math
from typing import Annotated, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import get_current_org_id, get_current_user
from app.models.db.asset import Asset, AssetType
from app.models.db.user import User
from app.models.schemas.asset import AssetFilter, AssetResponse, AssetUpdate

router = APIRouter(prefix="/assets", tags=["Assets"])


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
        Asset.risk_score.desc().nullslast(),
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
