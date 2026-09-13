"""
User and OrgMember database models.
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
    String,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class MemberRole(str, enum.Enum):
    OWNER = "owner"
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class User(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Platform user account."""

    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(128), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    avatar_url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    totp_secret_enc: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_backup_codes_enc: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)

    # Relationships
    org_memberships: Mapped[list["OrgMember"]] = relationship(
        "OrgMember", back_populates="user", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email}>"


class OrgMember(Base, TimestampMixin):
    """Association between a user and an organization with a role."""

    __tablename__ = "org_members"

    user_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
        nullable=False,
    )
    org_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        primary_key=True,
        nullable=False,
    )
    role: Mapped[MemberRole] = mapped_column(
        Enum(MemberRole, name="member_role"),
        default=MemberRole.ANALYST,
        nullable=False,
    )
    joined_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    tool_permissions: Mapped[Optional[list[str]]] = mapped_column(
        ARRAY(String(50)), nullable=True, default=None
    )

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="org_memberships")
    organization: Mapped["Organization"] = relationship(  # type: ignore[name-defined]
        "Organization", back_populates="members"
    )

    def __repr__(self) -> str:
        return f"<OrgMember user_id={self.user_id} org_id={self.org_id} role={self.role}>"
