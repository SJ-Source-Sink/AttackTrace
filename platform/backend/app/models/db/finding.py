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
    Index,
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

    # Composite indexes for the most common multi-column query patterns
    __table_args__ = (
        # org_id + scan_job_id: every "findings for scan X in org Y" query
        Index("idx_finding_org_scan", "org_id", "scan_job_id"),
        # org_id + dedup_hash: cross-scan deduplication lookup
        Index("idx_finding_org_dedup", "org_id", "dedup_hash"),
        # org_id + severity: dashboard severity breakdown
        Index("idx_finding_org_severity", "org_id", "severity"),
        # org_id + status: open/in-progress filter
        Index("idx_finding_org_status", "org_id", "status"),
        # assignment index (created by add_assigned_to_findings migration)
        Index("idx_finding_assigned_to", "assigned_to"),
        # unique constraint on (org_id, dedup_hash) for atomic deduplication
        # (created by enterprise_hardening_001 as a partial unique index)
        Index(
            "uq_finding_org_dedup_hash", "org_id", "dedup_hash",
            unique=True,
            postgresql_where="dedup_hash IS NOT NULL",
        ),
        # partial index: open critical/high findings for dashboard KPI queries
        Index(
            "idx_finding_org_open_critical_high", "org_id", "created_at",
            postgresql_where="status = 'OPEN' AND severity IN ('CRITICAL', 'HIGH')",
        ),
    )

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
    # Source attribution — "attacktrace" (default), "msra", etc.
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="attacktrace", server_default="attacktrace", index=True)
    source_scan_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

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

    # KEV / EPSS enrichment
    confidence: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    kev_status: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    epss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    priority_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # SLA / compliance / risk
    sla_deadline: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    compliance_tags: Mapped[Optional[list[str]]] = mapped_column(ARRAY(String(50)), nullable=True)
    risk_score: Mapped[Optional[float]] = mapped_column(Float(), nullable=True)
    risk_explanation: Mapped[Optional[str]] = mapped_column(Text(), nullable=True)

    # Cross-scan deduplication
    dedup_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    # Ticketing integration
    ticket_ref: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)

    # Accept-risk workflow: {reason, expires_at, approver, accepted_at, accepted_by}
    accept_risk_info: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    # AI triage: 1-2 sentence business-impact statement generated in the same
    # triage call as ai_reasoning/ai_severity (see ai_service.py::triage_finding)
    ai_business_impact: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Cross-scanner correlation engine (app/services/correlation_engine.py):
    # populated only on synthetic "compound finding" rows (source=
    # "correlation_engine") — the UUIDs of the real underlying findings this
    # one was derived from, so a correlated finding is always traceable back
    # to real evidence rather than being an opaque new assertion (matches the
    # false-positive-gate doctrine already used by grade_confidence).
    correlated_finding_ids: Mapped[Optional[list[str]]] = mapped_column(ARRAY(String), nullable=True)

    # Assignment
    assigned_to: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Relationships
    scan_job: Mapped[Optional["ScanJob"]] = relationship(  # type: ignore[name-defined]
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
