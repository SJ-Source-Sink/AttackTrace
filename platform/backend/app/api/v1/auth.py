"""
Authentication API: register, login, refresh tokens, current user.
"""

import re
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.dependencies import get_current_user
from uuid import UUID
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    is_refresh_token_valid,
    revoke_refresh_token,
    store_refresh_token,
    verify_password,
)
from app.models.db.org import InviteCode, Organization, OrgPlan
from app.models.db.user import OrgMember, MemberRole, User
from app.models.schemas.auth import (
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)

settings = get_settings()

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _slugify(name: str) -> str:
    """Convert a name to a URL-safe slug."""
    slug = name.lower()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    return slug.strip("-")[:100]


@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
    description="Creates a user and optionally creates an organization. Returns JWT tokens.",
)
async def register(
    payload: RegisterRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    # Validate invite code
    invite_result = await db.execute(
        select(InviteCode).where(InviteCode.code == payload.invite_code.upper().strip())
    )
    invite = invite_result.scalar_one_or_none()

    if not invite or not invite.is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"code": "INVALID_INVITE_CODE", "message": "Invalid or expired invite code"}},
        )

    # If invite is restricted to a specific email, enforce it
    if invite.email and invite.email.lower() != payload.email.lower():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"code": "INVITE_EMAIL_MISMATCH", "message": "This invite code is for a different email address"}},
        )

    # Check email not already taken
    existing = await db.execute(select(User).where(User.email == payload.email))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": {"code": "EMAIL_EXISTS", "message": "Email address already registered"}},
        )

    user = User(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name,
        is_active=True,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)

    # Add user to the invite's org with the specified role
    try:
        member_role = MemberRole(invite.role)
    except ValueError:
        member_role = MemberRole.MEMBER

    member = OrgMember(
        user_id=user.id,
        org_id=invite.org_id,
        role=member_role,
    )
    db.add(member)

    # Only consume single-use (email-restricted) invites; open codes stay reusable
    if invite.email:
        from datetime import timezone as tz
        invite.used_at = datetime.now(tz.utc)
        invite.used_by = user.id
        db.add(invite)

    await db.flush()

    access_token = create_access_token(
        subject=str(user.id),
        org_id=str(invite.org_id),
        role=member_role.value,
    )
    refresh_token = create_refresh_token(subject=str(user.id))
    await store_refresh_token(str(user.id), refresh_token)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate with email and password",
    description="Returns a JWT access token and refresh token.",
)
async def login(
    payload: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    # Load user
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": {"code": "INVALID_CREDENTIALS", "message": "Invalid email or password"}},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": {"code": "ACCOUNT_DISABLED", "message": "Account has been disabled"}},
        )

    # Load first org membership for default context
    member_result = await db.execute(
        select(OrgMember).where(OrgMember.user_id == user.id).order_by(OrgMember.created_at.asc()).limit(1)
    )
    member = member_result.scalar_one_or_none()
    org_id = str(member.org_id) if member else None
    role = member.role.value if member else None

    # Update last_login
    user.last_login = datetime.now(timezone.utc)
    db.add(user)

    access_token = create_access_token(
        subject=str(user.id),
        org_id=org_id,
        role=role,
    )
    refresh_token = create_refresh_token(subject=str(user.id))
    await store_refresh_token(str(user.id), refresh_token)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh an access token",
    description="Exchange a valid refresh token for a new access token.",
)
async def refresh_token(
    payload: RefreshRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"error": {"code": "INVALID_REFRESH_TOKEN", "message": "Invalid or expired refresh token"}},
    )

    try:
        token_data = decode_token(payload.refresh_token)
        if token_data.get("type") != "refresh":
            raise credentials_exception
        user_id = token_data.get("sub")
        if not user_id:
            raise credentials_exception
    except Exception:
        raise credentials_exception

    # Validate token in Redis
    if not await is_refresh_token_valid(user_id, payload.refresh_token):
        raise credentials_exception

    # Load user
    result = await db.execute(select(User).where(User.id == user_id, User.is_active == True))
    user = result.scalar_one_or_none()
    if not user:
        raise credentials_exception

    # Load org context
    member_result = await db.execute(
        select(OrgMember).where(OrgMember.user_id == user.id).order_by(OrgMember.created_at.asc()).limit(1)
    )
    member = member_result.scalar_one_or_none()
    org_id = str(member.org_id) if member else None
    role = member.role.value if member else None

    # Rotate refresh token
    await revoke_refresh_token(user_id, payload.refresh_token)
    new_refresh_token = create_refresh_token(subject=user_id)
    await store_refresh_token(user_id, new_refresh_token)

    access_token = create_access_token(subject=user_id, org_id=org_id, role=role)

    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke refresh token",
    description="Invalidates the provided refresh token.",
)
async def logout(
    payload: RefreshRequest,
) -> None:
    try:
        token_data = decode_token(payload.refresh_token)
        user_id = token_data.get("sub")
        if user_id:
            await revoke_refresh_token(user_id, payload.refresh_token)
    except Exception:
        pass  # Already invalid — fine


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user profile",
)
async def get_me(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    member = None
    org_id_str = getattr(current_user, "_jwt_org_id", None)
    if org_id_str:
        try:
            result = await db.execute(
                select(OrgMember).where(
                    OrgMember.user_id == current_user.id,
                    OrgMember.org_id == UUID(org_id_str),
                )
            )
            member = result.scalar_one_or_none()
        except Exception:
            pass
    return UserResponse.from_orm_user(current_user, member=member)
