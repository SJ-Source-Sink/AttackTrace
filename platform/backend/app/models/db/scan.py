"""
ScanJob database model (maps to AttackTrace ScanSession).
"""

import enum
from datetime import datetime
from typing import Optional
from uuid import UUID

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanIntensity(str, enum.Enum):
    PASSIVE = "passive"
    NORMAL = "normal"
    AGGRESSIVE = "aggressive"


class ScanJob(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    Represents a single AttackTrace scan execution.
    Maps to AttackTrace's ScanSession.
    """

    __tablename__ = "scan_jobs"

    org_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    workspace_id: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("workspaces.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    created_by: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Target
    target_domains: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False, default=list)
    company_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Configuration
    intensity: Mapped[ScanIntensity] = mapped_column(
        Enum(ScanIntensity, name="scan_intensity"),
        default=ScanIntensity.PASSIVE,
        nullable=False,
    )
    modules_to_skip: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False, default=list)
    passive_only: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Status
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status"),
        default=ScanStatus.PENDING,
        nullable=False,
        index=True,
    )
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # AttackTrace session reference
    session_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # Timing
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Results
    results_summary: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    findings_count: Mapped[Optional[dict]] = mapped_column(
        JSONB,
        nullable=True,
        default=lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
    )

    # Scheduling
    scheduled_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    schedule_cron: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Celery task ID for cancellation
    celery_task_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Relationships — lazy="raise" prevents accidental sync lazy loads in async context
    findings: Mapped[list["Finding"]] = relationship(  # type: ignore[name-defined]
        "Finding", back_populates="scan_job", cascade="all, delete-orphan", lazy="raise"
    )
    assets: Mapped[list["Asset"]] = relationship(  # type: ignore[name-defined]
        "Asset", back_populates="scan_job", cascade="all, delete-orphan", lazy="raise"
    )
    workspace: Mapped[Optional["Workspace"]] = relationship(  # type: ignore[name-defined]
        "Workspace", back_populates="scan_jobs", lazy="raise"
    )

    def __repr__(self) -> str:
        return f"<ScanJob id={self.id} status={self.status} domains={self.target_domains}>"
