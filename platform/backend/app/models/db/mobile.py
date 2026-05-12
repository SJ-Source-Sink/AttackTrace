"""
MobilePattern, MobileScan, and MobileFinding database models.
Self-contained mobile app security scanner — no external sidecar required.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class MobilePattern(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A detection pattern (regex rule) for the mobile scanner.
    Built-in patterns have org_id=NULL. Custom org patterns have org_id set.
    """

    __tablename__ = "mobile_patterns"

    __table_args__ = (
        Index("idx_mpattern_org_platform", "org_id", "platform"),
        Index("idx_mpattern_enabled_platform", "is_enabled", "platform"),
    )

    # NULL = built-in global pattern; set = org-specific custom pattern
    org_id: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    platform: Mapped[str] = mapped_column(String(20), nullable=False)
    # "android" | "ios" | "jar" | "exe" | "all"

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    # "Critical" | "High" | "Medium" | "Low" | "Info"

    category: Mapped[str] = mapped_column(String(128), nullable=False)
    regex_pattern: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cwe: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    is_custom: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    findings: Mapped[list["MobileFinding"]] = relationship(
        "MobileFinding", back_populates="pattern", passive_deletes=True
    )

    def __repr__(self) -> str:
        return f"<MobilePattern {self.platform}:{self.severity} {self.title!r}>"


class MobileScan(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """One uploaded APK/IPA file = one MobileScan row."""

    __tablename__ = "mobile_scans"

    __table_args__ = (
        Index("idx_mscan_org_status", "org_id", "status"),
        Index("idx_mscan_org_created", "org_id", "created_at"),
    )

    org_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    app_name: Mapped[str] = mapped_column(String(255), nullable=False)
    package_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    platform: Mapped[str] = mapped_column(String(20), nullable=False)
    # "android" | "ios" | "jar" | "exe"

    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    # "pending" | "scanning" | "completed" | "failed"

    file_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # {"Critical":0,"High":0,"Medium":0,"Low":0,"Info":0}
    findings_count: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=lambda: {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0},
    )

    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    celery_task_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    progress: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    findings: Mapped[list["MobileFinding"]] = relationship(
        "MobileFinding", back_populates="scan", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<MobileScan {self.app_name} status={self.status}>"


class MobileFinding(Base):
    """A single pattern match within a MobileScan."""

    __tablename__ = "mobile_findings"

    # Integer PK — the frontend types finding IDs as number, matching MSRA's convention
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    scan_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("mobile_scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    pattern_id: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("mobile_patterns.id", ondelete="SET NULL"),
        nullable=True,
    )

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    category: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    file_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    line_number: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    code_snippet: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    triage_status: Mapped[str] = mapped_column(String(32), nullable=False, default="New")
    # "New" | "true_positive" | "false_positive" | "needs_review"
    cwe: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    scan: Mapped["MobileScan"] = relationship("MobileScan", back_populates="findings")
    pattern: Mapped[Optional["MobilePattern"]] = relationship(
        "MobilePattern", back_populates="findings"
    )

    def __repr__(self) -> str:
        return f"<MobileFinding {self.severity} {self.title!r} in scan {self.scan_id}>"
