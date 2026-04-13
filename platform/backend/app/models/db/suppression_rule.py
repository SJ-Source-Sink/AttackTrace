"""ScanSuppressionRule — org-level suppression rules that auto-suppress future findings."""

from datetime import datetime
from typing import Optional
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.db.base import Base, UUIDPrimaryKeyMixin


class ScanSuppressionRule(Base, UUIDPrimaryKeyMixin):
    """Org-level rule that automatically suppresses matching findings in future scans."""

    __tablename__ = "scan_suppression_rules"

    org_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    finding_title: Mapped[str] = mapped_column(Text, nullable=False)
    affected_asset_pattern: Mapped[str] = mapped_column(Text, nullable=False)
    # 'false_positive' | 'accepted_risk' | 'suppress'
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_by: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"<ScanSuppressionRule id={self.id} org={self.org_id} action={self.action}>"
