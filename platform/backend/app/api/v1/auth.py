"""
Authentication API: register, login, refresh tokens, current user.
"""

import json
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
    decrypt_credential,
    encrypt_credential,
    hash_password,
    is_refresh_token_valid,
    revoke_refresh_token,
    store_refresh_token,
    verify_password,
)
from app.models.db.org import InviteCode, Organization
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


def _client_ip(request: Request) -> str:
    if settings.TRUST_PROXY_HEADERS:
        # Each proxy appends the address it saw, so the leftmost entries are client-supplied and
        # spoofable. Take the Nth from the right, N = number of trusted proxies in front of us.
        parts = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
        hops = max(1, settings.TRUSTED_PROXY_HOPS)
        if len(parts) >= hops:
            return parts[-hops]
    return request.client.host if request.client else "unknown"


async def _redis_call(coro_factory):
    """Run one Redis operation on a short-lived connection; None on any error (callers fail open
    only where noted: /login's lockout reads, which can't work without Redis anyway)."""
    import redis.asyncio as _aioredis

    _r = None
    try:
        _r = _aioredis.from_url(settings.REDIS_URL, socket_connect_timeout=1)
        return await coro_factory(_r)
    except Exception:
        return None
    finally:
        if _r is not None:
            try:
                await _r.aclose()
            except Exception:
                pass


async def _rate_limit(request: Request, bucket: str, limit: int, window: int = 60) -> None:
    """Fixed-window per-IP limiter for unauthenticated auth endpoints."""
    key = f"ratelimit:{bucket}:{_client_ip(request)}"

    async def _hit(r):
        n = await r.incr(key)
        if n == 1:
            await r.expire(key, window)
        return int(n)

    n = await _redis_call(_hit)
    if n is not None and n > limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"error": {"code": "TOO_MANY_REQUESTS", "message": "Too many requests. Slow down and try again shortly."}},
        )



@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
    description="Creates a user and optionally creates an organization. Returns JWT tokens.",
)
async def register(
    payload: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    await _rate_limit(request, "register", settings.AUTH_RATE_LIMIT_PER_MINUTE)
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
    except (ValueError, AttributeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This invite has an invalid role configured. Contact your organization admin.",
        )

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
    summary="Authenticate with email and password",
    description="Returns a JWT access token and refresh token, or an MFA challenge if enabled.",
)
async def login(
    payload: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    # Check account lockout and manage brute-force counters via Redis.
    # Each Redis operation uses a short-lived connection that is always closed
    # in a finally block, preventing connection leaks on all code paths.
    import redis.asyncio as _aioredis

    # Account lockout is keyed on (email, source IP): keying on the email alone would let any
    # stranger lock any user out just by failing logins against their address. A much higher
    # per-account threshold (across all IPs) still stops distributed guessing.
    _email = payload.email.strip().lower()
    _client_ip_str = _client_ip(request)
    _lockout_key = f"lockout:{_email}:{_client_ip_str}"
    _attempt_key = f"loginattempts:{_email}:{_client_ip_str}"
    _acct_lockout_key = f"lockout_acct:{_email}"
    _acct_attempt_key = f"loginattempts_acct:{_email}"
    _ip_lockout_key = f"lockout_ip:{_client_ip_str}"
    _ip_attempt_key = f"loginattempts_ip:{_client_ip_str}"

    async def _redis_op(coro_factory):
        """Execute a Redis coroutine with a dedicated connection; return None on any error."""
        _r = None
        try:
            _r = _aioredis.from_url(settings.REDIS_URL, socket_connect_timeout=1)
            return await coro_factory(_r)
        except Exception:
            return None
        finally:
            if _r is not None:
                try:
                    await _r.aclose()
                except Exception:
                    pass

    # Check lockout (per-account, and per-source-IP as defense-in-depth against
    # credential-stuffing/spray attacks hitting many emails from one IP)
    _locked = await _redis_op(lambda r: r.get(_lockout_key))
    if _locked:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"error": {"code": "ACCOUNT_LOCKED", "message": "Account temporarily locked due to too many failed login attempts. Try again in 15 minutes."}},
        )
    _acct_locked = await _redis_op(lambda r: r.get(_acct_lockout_key))
    if _acct_locked:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"error": {"code": "ACCOUNT_LOCKED", "message": "Too many failed login attempts for this account from multiple sources. Try again in 15 minutes."}},
        )
    _ip_locked = await _redis_op(lambda r: r.get(_ip_lockout_key))
    if _ip_locked:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"error": {"code": "TOO_MANY_REQUESTS", "message": "Too many failed login attempts from this network. Try again in 15 minutes."}},
        )

    # Load user
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(payload.password, user.hashed_password):
        # Increment failed attempt counter; lock the account after 5 failures within
        # 15 min, and lock the source IP after 20 failures (any email) within 15 min.
        async def _increment(r):
            attempts = await r.incr(_attempt_key)
            await r.expire(_attempt_key, 900)
            if int(attempts) >= 5:
                await r.set(_lockout_key, "1", ex=900)
                await r.delete(_attempt_key)

            acct_attempts = await r.incr(_acct_attempt_key)
            await r.expire(_acct_attempt_key, 900)
            if int(acct_attempts) >= 30:
                await r.set(_acct_lockout_key, "1", ex=900)
                await r.delete(_acct_attempt_key)

            ip_attempts = await r.incr(_ip_attempt_key)
            await r.expire(_ip_attempt_key, 900)
            if int(ip_attempts) >= 20:
                await r.set(_ip_lockout_key, "1", ex=900)
                await r.delete(_ip_attempt_key)

        await _redis_op(_increment)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": {"code": "INVALID_CREDENTIALS", "message": "Invalid email or password"}},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": {"code": "ACCOUNT_DISABLED", "message": "Account has been disabled"}},
        )

    # Correct password; if MFA is enabled, require the second factor before issuing real tokens.
    # Counters are NOT cleared here: a correct password alone must not buy a fresh budget of
    # guesses at the second factor (they're cleared once MFA succeeds, or expire after 15 min).
    if user.mfa_enabled:
        mfa_token = create_access_token(subject=str(user.id), extra_claims={"type": "mfa_pending"})
        return {"mfa_required": True, "mfa_token": mfa_token}

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

    # Clear failed attempt counters on successful login
    await _redis_op(lambda r: r.delete(_attempt_key, _lockout_key, _ip_attempt_key))

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    ).model_dump()


@router.post(
    "/mfa/enroll",
    summary="Begin MFA enrollment",
    description="Generates a new TOTP secret for the current user (not yet active until verified).",
)
async def mfa_enroll(
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> dict:
    import pyotp

    secret = pyotp.random_base32()
    current_user.totp_secret_enc = encrypt_credential(secret)
    current_user.mfa_enabled = False
    db.add(current_user)
    await db.flush()

    otpauth_url = pyotp.totp.TOTP(secret).provisioning_uri(
        name=current_user.email, issuer_name="AttackTrace"
    )
    return {"secret": secret, "otpauth_url": otpauth_url}


@router.post(
    "/mfa/verify",
    summary="Complete MFA enrollment",
    description="Verifies a TOTP code against the pending secret and activates MFA.",
)
async def mfa_verify(
    payload: dict,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> dict:
    import pyotp
    import secrets as _secrets_mod

    code = str(payload.get("code", ""))
    if not current_user.totp_secret_enc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No MFA enrollment in progress. Call /auth/mfa/enroll first.",
        )
    secret = decrypt_credential(current_user.totp_secret_enc)
    if not pyotp.TOTP(secret).verify(code, valid_window=1):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid code")

    backup_codes = ["-".join([_secrets_mod.token_hex(2) for _ in range(2)]) for _ in range(8)]
    current_user.mfa_enabled = True
    current_user.mfa_backup_codes_enc = encrypt_credential(json.dumps(backup_codes))
    db.add(current_user)
    await db.flush()

    return {"mfa_enabled": True, "backup_codes": backup_codes}


@router.post(
    "/mfa/disable",
    summary="Disable MFA",
    description="Requires the current password to confirm.",
)
async def mfa_disable(
    payload: dict,
    current_user: Annotated[User, Depends(get_current_user)],
    db: AsyncSession = Depends(get_db),
) -> dict:
    if not verify_password(str(payload.get("password", "")), current_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect password")

    current_user.mfa_enabled = False
    current_user.totp_secret_enc = None
    current_user.mfa_backup_codes_enc = None
    db.add(current_user)
    await db.flush()
    return {"mfa_enabled": False}


@router.post(
    "/mfa/challenge",
    summary="Complete login with a second factor",
    description="Exchanges an mfa_pending token plus a TOTP (or backup) code for real access/refresh tokens.",
)
async def mfa_challenge(
    payload: dict,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    import pyotp

    await _rate_limit(request, "mfa", settings.AUTH_RATE_LIMIT_PER_MINUTE)

    mfa_token = str(payload.get("mfa_token", ""))
    code = str(payload.get("code", ""))
    try:
        claims = decode_token(mfa_token)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired MFA token")
    if claims.get("type") != "mfa_pending":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA token")

    user_id = claims.get("sub")
    result = await db.execute(select(User).where(User.id == UUID(user_id)))
    user = result.scalar_one_or_none()
    if not user or not user.mfa_enabled or not user.totp_secret_enc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="MFA is not enabled for this account")

    # Per-user cap on second-factor guesses (5 wrong codes -> 15 min lock), independent of the
    # mfa_token: otherwise a fresh token from a correct password gives unlimited guesses.
    _mfa_lock_key, _mfa_fail_key = f"mfa_lock:{user.id}", f"mfa_fail:{user.id}"
    if await _redis_call(lambda r: r.get(_mfa_lock_key)):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"error": {"code": "MFA_LOCKED", "message": "Too many invalid codes. Try again in 15 minutes."}},
        )

    secret = decrypt_credential(user.totp_secret_enc)
    valid = pyotp.TOTP(secret).verify(code, valid_window=1)

    if not valid and user.mfa_backup_codes_enc:
        backup_codes = json.loads(decrypt_credential(user.mfa_backup_codes_enc))
        if code in backup_codes:
            valid = True
            backup_codes.remove(code)
            user.mfa_backup_codes_enc = encrypt_credential(json.dumps(backup_codes))
            db.add(user)

    if not valid:
        async def _mfa_fail(r):
            n = await r.incr(_mfa_fail_key)
            await r.expire(_mfa_fail_key, 900)
            if int(n) >= 5:
                await r.set(_mfa_lock_key, "1", ex=900)
                await r.delete(_mfa_fail_key)

        await _redis_call(_mfa_fail)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid code")
    await _redis_call(lambda r: r.delete(_mfa_fail_key, _mfa_lock_key))

    member_result = await db.execute(
        select(OrgMember).where(OrgMember.user_id == user.id).order_by(OrgMember.created_at.asc()).limit(1)
    )
    member = member_result.scalar_one_or_none()
    org_id = str(member.org_id) if member else None
    role = member.role.value if member else None

    user.last_login = datetime.now(timezone.utc)
    db.add(user)

    access_token = create_access_token(subject=str(user.id), org_id=org_id, role=role)
    refresh_token = create_refresh_token(subject=str(user.id))
    await store_refresh_token(str(user.id), refresh_token)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    ).model_dump()


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh an access token",
    description="Exchange a valid refresh token for a new access token.",
)
async def refresh_token(
    payload: RefreshRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    await _rate_limit(request, "refresh", settings.AUTH_RATE_LIMIT_PER_MINUTE * 6)
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
