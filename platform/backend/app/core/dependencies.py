"""
FastAPI dependency injection: database sessions, authentication, and RBAC.
"""

from typing import Annotated, Optional
from uuid import UUID

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt.exceptions import InvalidTokenError
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
    except (InvalidTokenError, ValueError):
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
    required_scope: str | None = None,
) -> User:
    """Authenticate via hashed API key lookup with optional scope enforcement."""
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

    # Scope enforcement: if the key has an explicit scope list, it must include the required scope
    if required_scope and api_key.scopes is not None:
        if required_scope not in api_key.scopes and "*" not in api_key.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": {
                    "code": "INSUFFICIENT_SCOPE",
                    "message": f"API key does not have the required scope: '{required_scope}'",
                }},
            )

    # Update last_used (non-blocking — fire and forget the flush)
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
    # Surface scopes for downstream scope-aware checks
    user._api_key_scopes = api_key.scopes  # None = unrestricted, [] = all denied

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


TOOL_KEYS = frozenset({
    "nmap", "nuclei", "ffuf", "attack_suite", "burp_analyzer",
    "test_generator", "ai_triage", "takeover", "attackmapper",
    "mobile", "firewall", "network_graph", "scans", "findings",
    "assets", "reports",
})

TOOL_LABELS = {
    "nmap": "Nmap Scanner",
    "nuclei": "Nuclei Scanner",
    "ffuf": "Web Fuzzer (ffuf)",
    "attack_suite": "Attack Suite",
    "burp_analyzer": "Burp Analyzer",
    "test_generator": "Test Case Generator",
    "ai_triage": "AI Triage",
    "takeover": "Subdomain Takeover",
    "attackmapper": "Attack Mapper",
    "mobile": "Mobile Security",
    "firewall": "Firewall Config",
    "network_graph": "Network Graph",
    "scans": "Scan Jobs",
    "findings": "Findings",
    "assets": "Assets",
    "reports": "Reports",
}


class ToolChecker:
    """
    Dependency that enforces per-tool access control.
    - OWNER / ADMIN: always allowed
    - VIEWER: always blocked from tool execution
    - ANALYST with tool_permissions=None: allowed (unrestricted, backward compat)
    - ANALYST with tool_permissions=[]: blocked from all tools
    - ANALYST with tool_permissions=['nmap',...]: allowed only those tools
    """

    def __init__(self, tool_key: str) -> None:
        self.tool_key = tool_key

    async def __call__(
        self,
        current_user: Annotated[User, Depends(get_current_user)],
        db: AsyncSession = Depends(get_db),
    ) -> User:
        from app.models.db.user import OrgMember, MemberRole
        from sqlalchemy import select

        org_id_str = getattr(current_user, "_jwt_org_id", None)
        if not org_id_str:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": {"code": "NO_ORG_CONTEXT", "message": "No organization context"}},
            )

        try:
            org_uuid = UUID(org_id_str)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": {"code": "INVALID_ORG", "message": "Invalid org ID"}},
            )

        result = await db.execute(
            select(OrgMember).where(
                OrgMember.user_id == current_user.id,
                OrgMember.org_id == org_uuid,
            )
        )
        member = result.scalar_one_or_none()
        if not member:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": {"code": "NOT_MEMBER", "message": "Not a member of this organization"}},
            )

        if member.role in (MemberRole.OWNER, MemberRole.ADMIN):
            return current_user

        if member.role == MemberRole.VIEWER:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": {"code": "VIEWER_CANNOT_RUN_TOOLS",
                                  "message": "Viewers cannot execute tools"}},
            )

        # ANALYST: check tool_permissions
        if member.tool_permissions is None:
            return current_user  # unrestricted

        if self.tool_key not in member.tool_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": {
                    "code": "TOOL_ACCESS_DENIED",
                    "message": f"You don't have access to the '{self.tool_key}' tool",
                }},
            )
        return current_user


def require_tool(tool_key: str) -> ToolChecker:
    """Convenience wrapper — use as a FastAPI dependency."""
    return ToolChecker(tool_key)


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
