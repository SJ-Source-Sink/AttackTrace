"""
ScanJob database model (maps to AttackTrace ScanSession).
"""

import enum
import uuid
from datetime import datetime
from typing import Optional
from uuid import UUID

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
    text,
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
    PASSIVE_DUE_DILIGENCE = "passive_due_diligence"


class ScanJob(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    Represents a single AttackTrace scan execution.
    Maps to AttackTrace's ScanSession.
    """

    __tablename__ = "scan_jobs"

    __table_args__ = (
        # Composite index for status-filtered org scan list queries
        # (created by enterprise_hardening_001 migration)
        Index("idx_scan_org_status_created", "org_id", "status", "created_at"),
    )

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

    # Optimistic locking — incremented by the worker on each state transition
    # (added by enterprise_hardening_001 migration)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("1"))

    # Relationships — lazy="raise" prevents accidental sync lazy loads in async context.
    # passive_deletes=True tells SQLAlchemy to rely on the DB-level ondelete="CASCADE"
    # rather than loading children in Python (which would fail with lazy="raise" in async).
    findings: Mapped[list["Finding"]] = relationship(  # type: ignore[name-defined]
        "Finding", back_populates="scan_job", cascade="all, delete-orphan", lazy="raise",
        passive_deletes=True,
    )
    assets: Mapped[list["Asset"]] = relationship(  # type: ignore[name-defined]
        "Asset", back_populates="scan_job", cascade="all, delete-orphan", lazy="raise",
        passive_deletes=True,
    )
    workspace: Mapped[Optional["Workspace"]] = relationship(  # type: ignore[name-defined]
        "Workspace", back_populates="scan_jobs", lazy="raise"
    )

    def __repr__(self) -> str:
        return f"<ScanJob id={self.id} status={self.status} domains={self.target_domains}>"


class ScanDiff(Base):
    """Asset and finding change diff between two consecutive scans."""

    __tablename__ = "scan_diffs"

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    org_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scan_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("scan_jobs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    previous_scan_id: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True),
        nullable=True,
    )
    new_assets: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    removed_assets: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    new_findings: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    resolved_findings: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    diff_summary: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default="now()",
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<ScanDiff scan_id={self.scan_id} previous_scan_id={self.previous_scan_id}>"


class ScheduledScan(Base):
    """
    Represents a recurring scheduled scan configuration.
    A cron-based schedule that creates ScanJob instances at each interval.
    """

    __tablename__ = "scheduled_scans"

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    workspace_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("workspaces.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    target_domains: Mapped[list[str]] = mapped_column(
        ARRAY(String()), nullable=False, default=list
    )
    company_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    scan_config: Mapped[dict] = mapped_column(JSONB(), nullable=False, default=dict)
    cron_expression: Mapped[str] = mapped_column(String(100), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean(), nullable=False, default=True)
    last_run: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    next_run: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    last_scan_job_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("scan_jobs.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    def __repr__(self) -> str:
        return f"<ScheduledScan id={self.id} name={self.name} cron={self.cron_expression}>"
