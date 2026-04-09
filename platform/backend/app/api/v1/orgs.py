"""
Organization, Workspace, Member, and API Key management API.
"""

import math
import re
from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import get_current_org_id, get_current_user, require_role
from app.core.security import (
    decrypt_credential,
    encrypt_credential,
    generate_api_key,
    hash_api_key,
)
from app.models.db.audit import AuditLog
from app.models.db.org import ApiKey, InviteCode, OrgCredentials, Organization, OrgPlan, Workspace
from app.models.db.user import OrgMember, MemberRole, User
from app.models.schemas.org import (
    ApiKeyCreate,
    ApiKeyResponse,
    CredentialsUpdate,
    MemberInvite,
    MemberResponse,
    MemberUpdate,
    OrgCreate,
    OrgResponse,
    OrgUpdate,
    PaginatedResponse,
    WorkspaceCreate,
    WorkspaceResponse,
    WorkspaceUpdate,
)

router = APIRouter(prefix="/orgs", tags=["Organizations"])


def _slugify(name: str) -> str:
    slug = name.lower()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    return slug.strip("-")[:100]


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# --- Organization CRUD ---

@router.post(
    "",
    response_model=OrgResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new organization",
)
async def create_org(
    payload: OrgCreate,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> OrgResponse:
    slug = payload.slug or _slugify(payload.name)

    # Ensure slug uniqueness
    base_slug = slug
    counter = 1
    while True:
        existing = await db.execute(select(Organization).where(Organization.slug == slug))
        if not existing.scalar_one_or_none():
            break
        slug = f"{base_slug}-{counter}"
        counter += 1

    try:
        plan = OrgPlan(payload.plan)
    except ValueError:
        plan = OrgPlan.STARTER

    org = Organization(name=payload.name, slug=slug, plan=plan)
    db.add(org)
    await db.flush()
    await db.refresh(org)

    # Make creator the owner
    member = OrgMember(user_id=current_user.id, org_id=org.id, role=MemberRole.OWNER)
    db.add(member)

    log = AuditLog(
        org_id=org.id,
        user_id=current_user.id,
        action="org.created",
        resource_type="organization",
        resource_id=str(org.id),
        after_state={"name": org.name, "slug": org.slug, "plan": org.plan.value},
        ip_address=_get_client_ip(request),
    )
    db.add(log)
    await db.flush()

    return OrgResponse.from_orm(org)


@router.get(
    "/{org_id}",
    response_model=OrgResponse,
    summary="Get organization details",
)
async def get_org(
    org_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> OrgResponse:
    org = await _get_org_or_404(db, org_id, current_user.id)
    return OrgResponse.from_orm(org)


@router.patch(
    "/{org_id}",
    response_model=OrgResponse,
    summary="Update organization",
)
async def update_org(
    org_id: UUID,
    payload: OrgUpdate,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> OrgResponse:
    org = await _get_org_or_404(db, org_id, current_user.id)
    await _require_org_role(db, current_user.id, org_id, [MemberRole.OWNER, MemberRole.ADMIN])

    before = {"name": org.name, "plan": org.plan.value}

    if payload.name:
        org.name = payload.name
    if payload.plan:
        try:
            org.plan = OrgPlan(payload.plan)
        except ValueError:
            pass

    db.add(org)

    log = AuditLog(
        org_id=org.id,
        user_id=current_user.id,
        action="org.updated",
        resource_type="organization",
        resource_id=str(org.id),
        before_state=before,
        after_state={"name": org.name, "plan": org.plan.value},
        ip_address=_get_client_ip(request),
    )
    db.add(log)
    await db.flush()
    await db.refresh(org)

    return OrgResponse.from_orm(org)


# --- Members ---

@router.get(
    "/{org_id}/members",
    summary="List organization members",
)
async def list_members(
    org_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
    page: int = 1,
    per_page: int = 50,
) -> dict:
    await _get_org_or_404(db, org_id, current_user.id)

    count_result = await db.execute(
        select(func.count()).select_from(OrgMember).where(OrgMember.org_id == org_id)
    )
    total = count_result.scalar_one()

    offset = (page - 1) * per_page
    members_result = await db.execute(
        select(OrgMember, User)
        .join(User, OrgMember.user_id == User.id)
        .where(OrgMember.org_id == org_id)
        .offset(offset)
        .limit(per_page)
    )
    rows = members_result.all()

    items = [MemberResponse.from_orm(m, u) for m, u in rows]
    pages = math.ceil(total / per_page) if per_page > 0 else 0

    return {"items": [i.model_dump() for i in items], "total": total, "page": page, "per_page": per_page, "pages": pages}


@router.post(
    "/{org_id}/members",
    status_code=status.HTTP_201_CREATED,
    summary="Invite a user to the organization",
)
async def add_member(
    org_id: UUID,
    payload: MemberInvite,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> dict:
    await _get_org_or_404(db, org_id, current_user.id)
    await _require_org_role(db, current_user.id, org_id, [MemberRole.OWNER, MemberRole.ADMIN])

    # Find user by email
    user_result = await db.execute(select(User).where(User.email == payload.email))
    target_user = user_result.scalar_one_or_none()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "USER_NOT_FOUND", "message": "No user found with that email"}},
        )

    # Check not already a member
    existing = await db.execute(
        select(OrgMember).where(OrgMember.user_id == target_user.id, OrgMember.org_id == org_id)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": {"code": "ALREADY_MEMBER", "message": "User is already a member"}},
        )

    try:
        member_role = MemberRole(payload.role)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"code": "INVALID_ROLE", "message": f"Invalid role: {payload.role}"}},
        )

    member = OrgMember(
        user_id=target_user.id,
        org_id=org_id,
        role=member_role,
    )
    db.add(member)

    log = AuditLog(
        org_id=org_id,
        user_id=current_user.id,
        action="member.added",
        resource_type="org_member",
        resource_id=str(target_user.id),
        after_state={"email": target_user.email, "role": payload.role},
        ip_address=_get_client_ip(request),
    )
    db.add(log)
    await db.flush()

    return MemberResponse.from_orm(member, target_user).model_dump()


@router.patch(
    "/{org_id}/members/{user_id}",
    summary="Update a member's role",
)
async def update_member_role(
    org_id: UUID,
    user_id: UUID,
    payload: MemberUpdate,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> dict:
    await _get_org_or_404(db, org_id, current_user.id)
    await _require_org_role(db, current_user.id, org_id, [MemberRole.OWNER, MemberRole.ADMIN])

    result = await db.execute(
        select(OrgMember).where(OrgMember.user_id == user_id, OrgMember.org_id == org_id)
    )
    member = result.scalar_one_or_none()
    if not member:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "MEMBER_NOT_FOUND", "message": "Member not found"}},
        )

    before_role = member.role.value
    member.role = MemberRole(payload.role)
    db.add(member)

    log = AuditLog(
        org_id=org_id,
        user_id=current_user.id,
        action="member.role_changed",
        resource_type="org_member",
        resource_id=str(user_id),
        before_state={"role": before_role},
        after_state={"role": payload.role},
        ip_address=_get_client_ip(request),
    )
    db.add(log)
    await db.flush()

    user_result = await db.execute(select(User).where(User.id == user_id))
    user = user_result.scalar_one()
    return MemberResponse.from_orm(member, user).model_dump()


@router.delete(
    "/{org_id}/members/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove a member from the organization",
)
async def remove_member(
    org_id: UUID,
    user_id: UUID,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> None:
    await _get_org_or_404(db, org_id, current_user.id)
    await _require_org_role(db, current_user.id, org_id, [MemberRole.OWNER, MemberRole.ADMIN])

    result = await db.execute(
        select(OrgMember).where(OrgMember.user_id == user_id, OrgMember.org_id == org_id)
    )
    member = result.scalar_one_or_none()
    if not member:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "MEMBER_NOT_FOUND", "message": "Member not found"}},
        )

    if member.role == MemberRole.OWNER and str(user_id) == str(current_user.id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"code": "CANNOT_REMOVE_OWNER", "message": "Owners cannot remove themselves"}},
        )

    await db.delete(member)

    log = AuditLog(
        org_id=org_id,
        user_id=current_user.id,
        action="member.removed",
        resource_type="org_member",
        resource_id=str(user_id),
        before_state={"role": member.role.value},
        ip_address=_get_client_ip(request),
    )
    db.add(log)
    await db.flush()


# --- Workspaces ---

@router.post(
    "/{org_id}/workspaces",
    response_model=WorkspaceResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a workspace",
)
async def create_workspace(
    org_id: UUID,
    payload: WorkspaceCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> WorkspaceResponse:
    await _get_org_or_404(db, org_id, current_user.id)
    await _require_org_role(db, current_user.id, org_id, [MemberRole.OWNER, MemberRole.ADMIN])

    ws = Workspace(org_id=org_id, name=payload.name, description=payload.description)
    db.add(ws)
    await db.flush()
    await db.refresh(ws)
    return WorkspaceResponse.from_orm(ws)


@router.get(
    "/{org_id}/workspaces",
    summary="List workspaces",
)
async def list_workspaces(
    org_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
    page: int = 1,
    per_page: int = 50,
) -> dict:
    await _get_org_or_404(db, org_id, current_user.id)

    count_result = await db.execute(
        select(func.count()).select_from(Workspace).where(Workspace.org_id == org_id, Workspace.is_active == True)
    )
    total = count_result.scalar_one()

    offset = (page - 1) * per_page
    result = await db.execute(
        select(Workspace)
        .where(Workspace.org_id == org_id, Workspace.is_active == True)
        .order_by(Workspace.created_at.desc())
        .offset(offset)
        .limit(per_page)
    )
    workspaces = result.scalars().all()
    pages = math.ceil(total / per_page) if per_page > 0 else 0

    return {
        "items": [WorkspaceResponse.from_orm(ws).model_dump() for ws in workspaces],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": pages,
    }


@router.patch(
    "/{org_id}/workspaces/{workspace_id}",
    response_model=WorkspaceResponse,
    summary="Update a workspace",
)
async def update_workspace(
    org_id: UUID,
    workspace_id: UUID,
    payload: WorkspaceUpdate,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> WorkspaceResponse:
    await _get_org_or_404(db, org_id, current_user.id)
    await _require_org_role(db, current_user.id, org_id, [MemberRole.OWNER, MemberRole.ADMIN])

    result = await db.execute(
        select(Workspace).where(Workspace.id == workspace_id, Workspace.org_id == org_id)
    )
    ws = result.scalar_one_or_none()
    if not ws:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "WORKSPACE_NOT_FOUND", "message": "Workspace not found"}},
        )

    if payload.name is not None:
        ws.name = payload.name
    if payload.description is not None:
        ws.description = payload.description
    db.add(ws)
    await db.flush()
    await db.refresh(ws)

    return WorkspaceResponse.from_orm(ws)


# --- API Keys ---

@router.post(
    "/{org_id}/api-keys",
    response_model=ApiKeyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create an API key",
    description="Returns the raw key ONCE — it cannot be retrieved again.",
)
async def create_api_key(
    org_id: UUID,
    payload: ApiKeyCreate,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> ApiKeyResponse:
    await _get_org_or_404(db, org_id, current_user.id)
    await _require_org_role(db, current_user.id, org_id, [MemberRole.OWNER, MemberRole.ADMIN])

    raw_key, key_hash = generate_api_key()

    expires_at = None
    if payload.expires_in_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=payload.expires_in_days)

    api_key = ApiKey(
        org_id=org_id,
        created_by=current_user.id,
        name=payload.name,
        key_hash=key_hash,
        expires_at=expires_at,
        scopes=payload.scopes,
    )
    db.add(api_key)

    log = AuditLog(
        org_id=org_id,
        user_id=current_user.id,
        action="api_key.created",
        resource_type="api_key",
        resource_id=None,
        after_state={"name": payload.name, "scopes": payload.scopes},
        ip_address=_get_client_ip(request),
    )
    db.add(log)
    await db.flush()
    await db.refresh(api_key)

    return ApiKeyResponse.from_orm(api_key, raw_key=raw_key)


@router.get(
    "/{org_id}/api-keys",
    summary="List API keys (hashes only, no raw keys)",
)
async def list_api_keys(
    org_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
    page: int = 1,
    per_page: int = 50,
) -> dict:
    await _get_org_or_404(db, org_id, current_user.id)

    count_result = await db.execute(
        select(func.count()).select_from(ApiKey).where(ApiKey.org_id == org_id, ApiKey.is_active == True)
    )
    total = count_result.scalar_one()

    offset = (page - 1) * per_page
    result = await db.execute(
        select(ApiKey)
        .where(ApiKey.org_id == org_id, ApiKey.is_active == True)
        .order_by(ApiKey.created_at.desc())
        .offset(offset)
        .limit(per_page)
    )
    keys = result.scalars().all()
    pages = math.ceil(total / per_page) if per_page > 0 else 0

    return {
        "items": [ApiKeyResponse.from_orm(k).model_dump() for k in keys],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": pages,
    }


@router.delete(
    "/{org_id}/api-keys/{key_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke an API key",
)
async def revoke_api_key(
    org_id: UUID,
    key_id: UUID,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> None:
    await _get_org_or_404(db, org_id, current_user.id)
    await _require_org_role(db, current_user.id, org_id, [MemberRole.OWNER, MemberRole.ADMIN])

    result = await db.execute(
        select(ApiKey).where(ApiKey.id == key_id, ApiKey.org_id == org_id)
    )
    key = result.scalar_one_or_none()
    if not key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "API_KEY_NOT_FOUND", "message": "API key not found"}},
        )

    key.is_active = False
    db.add(key)

    log = AuditLog(
        org_id=org_id,
        user_id=current_user.id,
        action="api_key.revoked",
        resource_type="api_key",
        resource_id=str(key_id),
        ip_address=_get_client_ip(request),
    )
    db.add(log)
    await db.flush()


# --- Credentials ---

@router.put(
    "/{org_id}/credentials",
    summary="Update encrypted API credentials for org",
    description="Credentials are AES-256 encrypted before storage.",
)
async def update_credentials(
    org_id: UUID,
    payload: CredentialsUpdate,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> dict:
    await _get_org_or_404(db, org_id, current_user.id)
    await _require_org_role(db, current_user.id, org_id, [MemberRole.OWNER, MemberRole.ADMIN])

    result = await db.execute(
        select(OrgCredentials).where(OrgCredentials.org_id == org_id)
    )
    creds = result.scalar_one_or_none()

    if not creds:
        creds = OrgCredentials(org_id=org_id)
        db.add(creds)

    if payload.shodan_key is not None:
        creds.shodan_key_enc = encrypt_credential(payload.shodan_key) if payload.shodan_key else None
    if payload.censys_id is not None:
        creds.censys_id_enc = encrypt_credential(payload.censys_id) if payload.censys_id else None
    if payload.censys_secret is not None:
        creds.censys_secret_enc = encrypt_credential(payload.censys_secret) if payload.censys_secret else None
    if payload.securitytrails_key is not None:
        creds.securitytrails_key_enc = encrypt_credential(payload.securitytrails_key) if payload.securitytrails_key else None
    if payload.github_token is not None:
        creds.github_token_enc = encrypt_credential(payload.github_token) if payload.github_token else None
    if payload.alienvault_key is not None:
        creds.alienvault_key_enc = encrypt_credential(payload.alienvault_key) if payload.alienvault_key else None
    if payload.passivetotal_user is not None:
        creds.passivetotal_user_enc = encrypt_credential(payload.passivetotal_user) if payload.passivetotal_user else None
    if payload.passivetotal_key is not None:
        creds.passivetotal_key_enc = encrypt_credential(payload.passivetotal_key) if payload.passivetotal_key else None

    db.add(creds)
    await db.flush()

    log = AuditLog(
        org_id=org_id,
        user_id=current_user.id,
        action="credentials.updated",
        resource_type="org_credentials",
        resource_id=str(org_id),
        ip_address=_get_client_ip(request),
    )
    db.add(log)
    await db.flush()

    # Return which keys are configured (no values)
    return {
        "shodan_key": bool(creds.shodan_key_enc),
        "censys_id": bool(creds.censys_id_enc),
        "censys_secret": bool(creds.censys_secret_enc),
        "securitytrails_key": bool(creds.securitytrails_key_enc),
        "github_token": bool(creds.github_token_enc),
        "alienvault_key": bool(creds.alienvault_key_enc),
        "passivetotal_user": bool(creds.passivetotal_user_enc),
        "passivetotal_key": bool(creds.passivetotal_key_enc),
    }


# ---------------------------------------------------------------------------
# /org  — current-user org context (no org_id in path, derived from JWT)
# ---------------------------------------------------------------------------

org_router = APIRouter(prefix="/org", tags=["Current Org"])


@org_router.get("", summary="Get current user's organization")
async def get_current_org(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    org = await _get_org_or_404(db, org_id, current_user.id)
    return OrgResponse.from_orm(org).model_dump()


@org_router.get("/members", summary="List members of current org")
async def list_current_org_members(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
    page: int = 1,
    per_page: int = 50,
) -> dict:
    count_result = await db.execute(
        select(func.count()).select_from(OrgMember).where(OrgMember.org_id == org_id)
    )
    total = count_result.scalar_one()
    offset = (page - 1) * per_page
    result = await db.execute(
        select(OrgMember, User)
        .join(User, User.id == OrgMember.user_id)
        .where(OrgMember.org_id == org_id)
        .offset(offset).limit(per_page)
    )
    rows = result.all()
    items = [
        {
            "user_id": str(member.user_id),
            "email": user.email,
            "full_name": user.full_name,
            "role": member.role.value,
            "joined_at": member.joined_at.isoformat(),
        }
        for member, user in rows
    ]
    return {"items": items, "total": total, "page": page, "per_page": per_page}


@org_router.post("/members/invite", summary="Invite member to current org")
async def invite_member_to_current_org(
    payload: MemberInvite,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    await _require_org_role(db, current_user.id, org_id, [MemberRole.OWNER, MemberRole.ADMIN])
    result = await db.execute(select(User).where(User.email == payload.email))
    invitee = result.scalar_one_or_none()
    if not invitee:
        raise HTTPException(status_code=404, detail={"error": {"code": "USER_NOT_FOUND", "message": "No user with that email"}})
    existing = await db.execute(
        select(OrgMember).where(OrgMember.user_id == invitee.id, OrgMember.org_id == org_id)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail={"error": {"code": "ALREADY_MEMBER", "message": "User is already a member"}})
    member = OrgMember(user_id=invitee.id, org_id=org_id, role=MemberRole(payload.role))
    db.add(member)
    await db.flush()
    return {"message": "Member added", "email": invitee.email, "role": payload.role}


@org_router.get("/api-keys", summary="List API keys for current org")
async def list_current_org_api_keys(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await db.execute(
        select(ApiKey).where(ApiKey.org_id == org_id).order_by(ApiKey.created_at.desc())
    )
    keys = result.scalars().all()
    return {
        "items": [ApiKeyResponse.from_orm(k).model_dump() for k in keys],
        "total": len(keys),
    }


@org_router.post("/api-keys", summary="Create API key for current org", status_code=201)
async def create_current_org_api_key(
    payload: ApiKeyCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    await _require_org_role(db, current_user.id, org_id, [MemberRole.OWNER, MemberRole.ADMIN])
    raw_key, key_hash, key_prefix = generate_api_key()
    expires_at = None
    if payload.expires_in_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=payload.expires_in_days)
    key = ApiKey(
        org_id=org_id,
        name=payload.name,
        key_hash=key_hash,
        key_prefix=key_prefix,
        created_by=current_user.id,
        scopes=payload.scopes or [],
        expires_at=expires_at,
    )
    db.add(key)
    await db.flush()
    return {**ApiKeyResponse.from_orm(key).model_dump(), "raw_key": raw_key}


@org_router.delete("/api-keys/{key_id}", summary="Delete API key", status_code=204)
async def delete_current_org_api_key(
    key_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> None:
    await _require_org_role(db, current_user.id, org_id, [MemberRole.OWNER, MemberRole.ADMIN])
    result = await db.execute(
        select(ApiKey).where(ApiKey.id == key_id, ApiKey.org_id == org_id)
    )
    key = result.scalar_one_or_none()
    if not key:
        raise HTTPException(status_code=404, detail={"error": {"code": "NOT_FOUND", "message": "API key not found"}})
    await db.delete(key)
    await db.flush()


@org_router.get("/credentials", summary="Get integration credentials status for current org")
async def get_current_org_credentials(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await db.execute(
        select(OrgCredentials).where(OrgCredentials.org_id == org_id)
    )
    creds = result.scalar_one_or_none()
    if not creds:
        return {
            "shodan_key": False,
            "censys_id": False,
            "censys_secret": False,
            "securitytrails_key": False,
            "github_token": False,
            "alienvault_key": False,
            "passivetotal_user": False,
            "passivetotal_key": False,
        }
    return {
        "shodan_key": bool(creds.shodan_key_enc),
        "censys_id": bool(creds.censys_id_enc),
        "censys_secret": bool(creds.censys_secret_enc),
        "securitytrails_key": bool(creds.securitytrails_key_enc),
        "github_token": bool(creds.github_token_enc),
        "alienvault_key": bool(creds.alienvault_key_enc),
        "passivetotal_user": bool(creds.passivetotal_user_enc),
        "passivetotal_key": bool(creds.passivetotal_key_enc),
    }


@org_router.put("/credentials", summary="Update integration credentials for current org")
async def update_current_org_credentials(
    payload: CredentialsUpdate,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    await _require_org_role(db, current_user.id, org_id, [MemberRole.OWNER, MemberRole.ADMIN])

    result = await db.execute(
        select(OrgCredentials).where(OrgCredentials.org_id == org_id)
    )
    creds = result.scalar_one_or_none()

    if not creds:
        creds = OrgCredentials(org_id=org_id)
        db.add(creds)

    if payload.shodan_key is not None:
        creds.shodan_key_enc = encrypt_credential(payload.shodan_key) if payload.shodan_key else None
    if payload.censys_id is not None:
        creds.censys_id_enc = encrypt_credential(payload.censys_id) if payload.censys_id else None
    if payload.censys_secret is not None:
        creds.censys_secret_enc = encrypt_credential(payload.censys_secret) if payload.censys_secret else None
    if payload.securitytrails_key is not None:
        creds.securitytrails_key_enc = encrypt_credential(payload.securitytrails_key) if payload.securitytrails_key else None
    if payload.github_token is not None:
        creds.github_token_enc = encrypt_credential(payload.github_token) if payload.github_token else None
    if payload.alienvault_key is not None:
        creds.alienvault_key_enc = encrypt_credential(payload.alienvault_key) if payload.alienvault_key else None
    if payload.passivetotal_user is not None:
        creds.passivetotal_user_enc = encrypt_credential(payload.passivetotal_user) if payload.passivetotal_user else None
    if payload.passivetotal_key is not None:
        creds.passivetotal_key_enc = encrypt_credential(payload.passivetotal_key) if payload.passivetotal_key else None

    db.add(creds)
    await db.flush()

    log = AuditLog(
        org_id=org_id,
        user_id=current_user.id,
        action="credentials.updated",
        resource_type="org_credentials",
        resource_id=str(org_id),
        ip_address=_get_client_ip(request),
    )
    db.add(log)
    await db.flush()

    return {
        "shodan_key": bool(creds.shodan_key_enc),
        "censys_id": bool(creds.censys_id_enc),
        "censys_secret": bool(creds.censys_secret_enc),
        "securitytrails_key": bool(creds.securitytrails_key_enc),
        "github_token": bool(creds.github_token_enc),
        "alienvault_key": bool(creds.alienvault_key_enc),
        "passivetotal_user": bool(creds.passivetotal_user_enc),
        "passivetotal_key": bool(creds.passivetotal_key_enc),
    }


# --- Invite Codes ---

import secrets as _secrets
import string as _string


def _generate_invite_code() -> str:
    """Generate a human-readable invite code like AttackTrace-A1B2-C3D4."""
    chars = _string.ascii_uppercase + _string.digits
    part1 = "".join(_secrets.choice(chars) for _ in range(4))
    part2 = "".join(_secrets.choice(chars) for _ in range(4))
    return f"AttackTrace-{part1}-{part2}"


@org_router.get("/invite-codes", summary="List invite codes for current org")
async def list_invite_codes(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    await _require_org_role(db, current_user.id, org_id, [MemberRole.OWNER, MemberRole.ADMIN])
    result = await db.execute(
        select(InviteCode)
        .where(InviteCode.org_id == org_id)
        .order_by(InviteCode.created_at.desc())
    )
    codes = result.scalars().all()
    return {
        "items": [
            {
                "id": str(c.id),
                "code": c.code,
                "role": c.role,
                "email": c.email,
                "is_valid": c.is_valid,
                "is_revoked": c.is_revoked,
                "used_at": c.used_at.isoformat() if c.used_at else None,
                "expires_at": c.expires_at.isoformat() if c.expires_at else None,
                "created_at": c.created_at.isoformat(),
            }
            for c in codes
        ]
    }


@org_router.post("/invite-codes", summary="Generate an invite code", status_code=201)
async def create_invite_code(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
    role: str = "member",
    email: Optional[str] = None,
    expires_in_days: Optional[int] = 7,
) -> dict:
    await _require_org_role(db, current_user.id, org_id, [MemberRole.OWNER, MemberRole.ADMIN])

    # Ensure unique code
    for _ in range(10):
        code = _generate_invite_code()
        existing = await db.execute(select(InviteCode).where(InviteCode.code == code))
        if not existing.scalar_one_or_none():
            break

    expires_at = None
    if expires_in_days:
        from datetime import timezone as tz, timedelta
        expires_at = datetime.now(tz.utc) + timedelta(days=expires_in_days)

    invite = InviteCode(
        org_id=org_id,
        created_by=current_user.id,
        code=code,
        role=role,
        email=email.lower() if email else None,
        expires_at=expires_at,
    )
    db.add(invite)
    await db.flush()

    return {
        "id": str(invite.id),
        "code": invite.code,
        "role": invite.role,
        "email": invite.email,
        "expires_at": invite.expires_at.isoformat() if invite.expires_at else None,
        "created_at": invite.created_at.isoformat(),
    }


@org_router.delete("/invite-codes/{code_id}", summary="Revoke an invite code", status_code=204)
async def revoke_invite_code(
    code_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> None:
    await _require_org_role(db, current_user.id, org_id, [MemberRole.OWNER, MemberRole.ADMIN])
    result = await db.execute(
        select(InviteCode).where(InviteCode.id == code_id, InviteCode.org_id == org_id)
    )
    invite = result.scalar_one_or_none()
    if not invite:
        raise HTTPException(status_code=404, detail={"error": {"code": "NOT_FOUND", "message": "Invite code not found"}})
    invite.is_revoked = True
    db.add(invite)
    await db.flush()


# --- Helpers ---

async def _get_org_or_404(db: AsyncSession, org_id: UUID, user_id: UUID) -> Organization:
    result = await db.execute(
        select(Organization)
        .join(OrgMember, OrgMember.org_id == Organization.id)
        .where(Organization.id == org_id, OrgMember.user_id == user_id)
    )
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "ORG_NOT_FOUND", "message": "Organization not found or access denied"}},
        )
    return org


async def _require_org_role(
    db: AsyncSession,
    user_id: UUID,
    org_id: UUID,
    allowed_roles: list[MemberRole],
) -> None:
    result = await db.execute(
        select(OrgMember).where(OrgMember.user_id == user_id, OrgMember.org_id == org_id)
    )
    member = result.scalar_one_or_none()
    if not member or member.role not in allowed_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": {"code": "INSUFFICIENT_PERMISSIONS", "message": "Insufficient permissions"}},
        )
