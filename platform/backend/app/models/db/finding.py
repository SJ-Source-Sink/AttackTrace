"""
Finding, FindingComment, and FindingSuppression database models.
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
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class FindingSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    REMEDIATED = "remediated"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"


class Finding(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Security finding discovered during a scan."""

    __tablename__ = "findings"

    org_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scan_job_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("scan_jobs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asset_id: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Core fields
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    severity: Mapped[FindingSeverity] = mapped_column(
        Enum(FindingSeverity, name="finding_severity"),
        nullable=False,
        index=True,
    )
    category: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    affected_asset: Mapped[str] = mapped_column(Text, nullable=False, default="")
    evidence: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    remediation: Mapped[str] = mapped_column(Text, nullable=False, default="")
    references: Mapped[list[str]] = mapped_column(ARRAY(String), default=list, nullable=False)
    cve: Mapped[list[str]] = mapped_column(ARRAY(String), default=list, nullable=False)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Lifecycle
    status: Mapped[FindingStatus] = mapped_column(
        Enum(FindingStatus, name="finding_status"),
        default=FindingStatus.OPEN,
        nullable=False,
        index=True,
    )

    # AI triage fields
    ai_severity: Mapped[Optional[FindingSeverity]] = mapped_column(
        Enum(FindingSeverity, name="finding_severity", create_constraint=False),
        nullable=True,
    )
    ai_reasoning: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ai_confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    ai_triaged_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # False positive / suppression
    false_positive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    suppressed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    suppressed_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    suppressed_by: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    suppressed_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Ticketing integration
    ticket_ref: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)

    # Relationships
    scan_job: Mapped["ScanJob"] = relationship(  # type: ignore[name-defined]
        "ScanJob", back_populates="findings"
    )
    asset: Mapped[Optional["Asset"]] = relationship(  # type: ignore[name-defined]
        "Asset", back_populates="findings"
    )
    comments: Mapped[list["FindingComment"]] = relationship(
        "FindingComment", back_populates="finding", cascade="all, delete-orphan", order_by="FindingComment.created_at"
    )
    suppressions: Mapped[list["FindingSuppression"]] = relationship(
        "FindingSuppression", back_populates="finding", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Finding id={self.id} severity={self.severity} title={self.title[:50]}>"


class FindingComment(Base, UUIDPrimaryKeyMixin):
    """User comment on a finding."""

    __tablename__ = "finding_comments"

    finding_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    finding: Mapped["Finding"] = relationship("Finding", back_populates="comments")
    user: Mapped["User"] = relationship("User")  # type: ignore[name-defined]

    def __repr__(self) -> str:
        return f"<FindingComment id={self.id} finding_id={self.finding_id}>"


class FindingSuppression(Base, UUIDPrimaryKeyMixin):
    """Audit record when a finding is suppressed or un-suppressed."""

    __tablename__ = "finding_suppressions"

    finding_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    suppressed_by: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    action: Mapped[str] = mapped_column(String(32), nullable=False)  # "suppress" | "unsuppress"
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    finding: Mapped["Finding"] = relationship("Finding", back_populates="suppressions")

    def __repr__(self) -> str:
        return f"<FindingSuppression id={self.id} action={self.action}>"
