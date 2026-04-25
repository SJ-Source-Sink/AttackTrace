"""
Organization and workspace request/response schemas.
"""

import re
from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class OrgCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    slug: Optional[str] = Field(None, min_length=1, max_length=100)
    plan: str = "starter"

    @field_validator("slug", mode="before")
    @classmethod
    def validate_slug(cls, v: Optional[str], info) -> Optional[str]:
        if v is None:
            return v
        if not re.match(r"^[a-z0-9-]+$", v):
            raise ValueError("Slug must contain only lowercase letters, numbers, and hyphens")
        return v


class OrgUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    plan: Optional[str] = None


class OrgResponse(BaseModel):
    id: str
    name: str
    slug: str
    plan: str
    is_active: bool
    max_scans_per_month: int
    logo_url: Optional[str] = None
    created_at: str

    @classmethod
    def from_orm(cls, org) -> "OrgResponse":
        return cls(
            id=str(org.id),
            name=org.name,
            slug=org.slug,
            plan=org.plan.value,
            is_active=org.is_active,
            max_scans_per_month=org.max_scans_per_month,
            logo_url=org.logo_url,
            created_at=org.created_at.isoformat(),
        )


class WorkspaceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)


class WorkspaceUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None


class WorkspaceResponse(BaseModel):
    id: str
    org_id: str
    name: str
    description: Optional[str] = None
    is_active: bool
    created_at: str

    @classmethod
    def from_orm(cls, ws) -> "WorkspaceResponse":
        return cls(
            id=str(ws.id),
            org_id=str(ws.org_id),
            name=ws.name,
            description=ws.description,
            is_active=ws.is_active,
            created_at=ws.created_at.isoformat(),
        )


class MemberInvite(BaseModel):
    email: str
    role: str = "analyst"

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        valid = {"owner", "admin", "analyst", "viewer"}
        if v not in valid:
            raise ValueError(f"Role must be one of: {valid}")
        return v


class MemberUpdate(BaseModel):
    role: str

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        valid = {"owner", "admin", "analyst", "viewer"}
        if v not in valid:
            raise ValueError(f"Role must be one of: {valid}")
        return v


class MemberResponse(BaseModel):
    user_id: str
    org_id: str
    role: str
    joined_at: str
    email: str
    full_name: str
    tool_permissions: Optional[list[str]] = None

    @classmethod
    def from_orm(cls, member, user) -> "MemberResponse":
        return cls(
            user_id=str(member.user_id),
            org_id=str(member.org_id),
            role=member.role.value,
            joined_at=member.joined_at.isoformat(),
            email=user.email,
            full_name=user.full_name,
            tool_permissions=member.tool_permissions,
        )


class MemberPermissionsUpdate(BaseModel):
    tool_permissions: Optional[list[str]] = None

    @field_validator("tool_permissions")
    @classmethod
    def validate_tools(cls, v):
        if v is None:
            return v
        valid = {
            "nmap", "nuclei", "ffuf", "attack_suite", "burp_analyzer",
            "test_generator", "ai_triage", "takeover", "attackmapper",
            "mobile", "firewall", "network_graph", "scans", "findings",
            "assets", "reports",
        }
        bad = set(v) - valid
        if bad:
            raise ValueError(f"Unknown tool keys: {bad}")
        return list(set(v))


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    expires_in_days: Optional[int] = Field(None, ge=1, le=365)
    scopes: list[str] = Field(default_factory=list)


class ApiKeyResponse(BaseModel):
    id: str
    name: str
    scopes: list[str]
    created_at: str
    expires_at: Optional[str] = None
    last_used: Optional[str] = None
    # raw_key only returned on creation
    raw_key: Optional[str] = None

    @classmethod
    def from_orm(cls, key, raw_key: Optional[str] = None) -> "ApiKeyResponse":
        return cls(
            id=str(key.id),
            name=key.name,
            scopes=key.scopes or [],
            created_at=key.created_at.isoformat(),
            expires_at=key.expires_at.isoformat() if key.expires_at else None,
            last_used=key.last_used.isoformat() if key.last_used else None,
            raw_key=raw_key,
        )


class CredentialsUpdate(BaseModel):
    anthropic_key: Optional[str] = None
    shodan_key: Optional[str] = None
    censys_id: Optional[str] = None
    censys_secret: Optional[str] = None
    securitytrails_key: Optional[str] = None
    github_token: Optional[str] = None
    alienvault_key: Optional[str] = None
    passivetotal_user: Optional[str] = None
    passivetotal_key: Optional[str] = None


class PaginatedResponse(BaseModel):
    items: list
    total: int
    page: int
    per_page: int
    pages: int
