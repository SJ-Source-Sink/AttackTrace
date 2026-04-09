"""
Asset response and filter schemas.
"""

from typing import Any, Optional
from pydantic import BaseModel, Field


class AssetResponse(BaseModel):
    id: str
    org_id: str
    scan_job_id: Optional[str] = None
    asset_type: str
    value: str
    metadata: Optional[dict[str, Any]] = None
    risk_score: Optional[float] = None
    first_seen: str
    last_seen: str
    tags: list[str]
    is_active: bool
    screenshot_url: Optional[str] = None
    created_at: str
    updated_at: str

    @classmethod
    def from_orm(cls, asset) -> "AssetResponse":
        return cls(
            id=str(asset.id),
            org_id=str(asset.org_id),
            scan_job_id=str(asset.scan_job_id) if asset.scan_job_id else None,
            asset_type=asset.asset_type.value,
            value=asset.value,
            metadata=asset.metadata_,
            risk_score=asset.risk_score,
            first_seen=asset.first_seen.isoformat(),
            last_seen=asset.last_seen.isoformat(),
            tags=asset.tags or [],
            is_active=asset.is_active,
            screenshot_url=asset.screenshot_url,
            created_at=asset.created_at.isoformat(),
            updated_at=asset.updated_at.isoformat(),
        )


class AssetFilter(BaseModel):
    asset_type: Optional[str] = None
    scan_job_id: Optional[str] = None
    search: Optional[str] = None
    min_risk_score: Optional[float] = None
    max_risk_score: Optional[float] = None
    tags: Optional[list[str]] = None
    is_active: Optional[bool] = None
    page: int = Field(default=1, ge=1)
    per_page: int = Field(default=50, ge=1, le=200)


class AssetUpdate(BaseModel):
    tags: Optional[list[str]] = None
    owner_user_id: Optional[str] = None
    risk_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    is_active: Optional[bool] = None
