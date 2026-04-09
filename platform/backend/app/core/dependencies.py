"""
FastAPI dependency injection: database sessions, authentication, and RBAC.
"""

from typing import Annotated, Optional
from uuid import UUID

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import AsyncSessionLocal, get_db
from app.core.security import decode_token, hash_api_key, is_refresh_token_valid
from app.models.db.user import OrgMember, User, MemberRole
from app.models.db.org import ApiKey

settings = get_settings()

bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Annotated[
        Optional[HTTPAuthorizationCredentials], Security(bearer_scheme)
    ] = None,
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Authenticate a request via JWT Bearer token or API key.

    Raises 401 if no valid credentials are provided.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"error": {"code": "UNAUTHORIZED", "message": "Invalid or expired credentials"}},
        headers={"WWW-Authenticate": "Bearer"},
    )

    if credentials is None:
        raise credentials_exception

    token = credentials.credentials

    # Try JWT first
    try:
        payload = decode_token(token)
        token_type: str = payload.get("type", "")
        if token_type != "access":
            raise credentials_exception
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        # Fall back to API key auth
        return await _authenticate_api_key(token, db, credentials_exception)

    # Load user from DB
    result = await db.execute(
        select(User).where(User.id == UUID(user_id), User.is_active == True)
    )
    user = result.scalar_one_or_none()
    if user is None:
        raise credentials_exception

    # Attach JWT claims to user for downstream use
    user._jwt_org_id = payload.get("org_id")
    user._jwt_role = payload.get("role")

    return user


async def _authenticate_api_key(
    token: str,
    db: AsyncSession,
    exc: HTTPException,
) -> User:
    """Authenticate via hashed API key lookup."""
    from datetime import datetime, timezone

    key_hash = hash_api_key(token)
    result = await db.execute(
        select(ApiKey).where(
            ApiKey.key_hash == key_hash,
            ApiKey.is_active == True,
        )
    )
    api_key = result.scalar_one_or_none()
    if api_key is None:
        raise exc

    # Check expiry
    if api_key.expires_at and api_key.expires_at < datetime.now(timezone.utc):
        raise exc

    # Update last_used
    api_key.last_used = datetime.now(timezone.utc)
    db.add(api_key)
    await db.flush()

    # Load the owning user
    result = await db.execute(
        select(User).where(User.id == api_key.created_by, User.is_active == True)
    )
    user = result.scalar_one_or_none()
    if user is None:
        raise exc

    user._jwt_org_id = str(api_key.org_id)
    user._jwt_role = None

    return user


class RoleChecker:
    """
    Dependency factory for RBAC checks.

    Usage:
        @router.get("/admin-only")
        async def handler(user=Depends(require_role("admin"))):
            ...
    """

    def __init__(self, required_roles: list[str]):
        self.required_roles = [MemberRole(r) for r in required_roles]

    async def __call__(
        self,
        current_user: Annotated[User, Depends(get_current_user)],
        db: AsyncSession = Depends(get_db),
    ) -> User:
        org_id_str = getattr(current_user, "_jwt_org_id", None)
        if org_id_str is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": {"code": "FORBIDDEN", "message": "No organization context"}},
            )

        try:
            org_id = UUID(org_id_str)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": {"code": "INVALID_ORG_ID", "message": "Invalid organization ID in token"}},
            )
        result = await db.execute(
            select(OrgMember).where(
                OrgMember.user_id == current_user.id,
                OrgMember.org_id == org_id,
            )
        )
        member = result.scalar_one_or_none()

        if member is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": {"code": "FORBIDDEN", "message": "Not a member of this organization"}},
            )

        if member.role not in self.required_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": {
                        "code": "INSUFFICIENT_PERMISSIONS",
                        "message": f"Required role: {[r.value for r in self.required_roles]}",
                    }
                },
            )

        return current_user


def require_role(*roles: str):
    """Convenience function that returns a RoleChecker dependency."""
    return RoleChecker(list(roles))


async def get_current_org_id(
    current_user: Annotated[User, Depends(get_current_user)],
) -> UUID:
    """Extract and validate the org_id from the current user's JWT claims."""
    org_id_str = getattr(current_user, "_jwt_org_id", None)
    if org_id_str is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"code": "NO_ORG_CONTEXT", "message": "No organization selected"}},
        )
    try:
        return UUID(org_id_str)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"code": "INVALID_ORG_ID", "message": "Invalid organization ID"}},
        )
