"""
Asset database model: domains, subdomains, IPs, web apps, cloud assets.
"""

import enum
from datetime import datetime
from typing import Optional
from uuid import UUID

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class AssetType(str, enum.Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    WEBAPP = "webapp"
    CLOUD = "cloud"


class Asset(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    Unified asset record for any discovered resource.
    Detailed type-specific data is stored in the metadata JSONB column.
    """

    __tablename__ = "assets"

    org_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scan_job_id: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("scan_jobs.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    owner_user_id: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    asset_type: Mapped[AssetType] = mapped_column(
        Enum(AssetType, name="asset_type"),
        nullable=False,
        index=True,
    )
    value: Mapped[str] = mapped_column(String(1024), nullable=False, index=True)
    metadata_: Mapped[Optional[dict]] = mapped_column("metadata", JSONB, nullable=True)

    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True, index=True)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    tags: Mapped[list[str]] = mapped_column(ARRAY(String), default=list, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    screenshot_url: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)

    # Relationships
    scan_job: Mapped[Optional["ScanJob"]] = relationship(  # type: ignore[name-defined]
        "ScanJob", back_populates="assets"
    )
    findings: Mapped[list["Finding"]] = relationship(  # type: ignore[name-defined]
        "Finding", back_populates="asset"
    )

    def __repr__(self) -> str:
        return f"<Asset id={self.id} type={self.asset_type} value={self.value[:50]}>"
