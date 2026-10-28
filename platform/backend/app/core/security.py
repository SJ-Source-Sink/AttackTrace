"""
Security utilities: JWT token management, password hashing, API key handling,
and credential encryption using AES-256-GCM via Fernet.
"""

import base64
import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

import redis.asyncio as aioredis
from cryptography.fernet import Fernet
import jwt
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext

from app.core.config import get_settings

settings = get_settings()

# --- Password Hashing ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    return pwd_context.verify(plain_password, hashed_password)


# --- JWT Tokens ---
def create_access_token(
    subject: str,
    org_id: Optional[str] = None,
    role: Optional[str] = None,
    extra_claims: Optional[dict] = None,
) -> str:
    """Create a short-lived JWT access token."""
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": subject,
        "iat": now,
        "exp": expire,
        "type": "access",
    }
    if org_id:
        payload["org_id"] = org_id
    if role:
        payload["role"] = role
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_stream_token(user_id: str, org_id: str, scan_id: str, ttl_seconds: int = 60) -> str:
    """Single-purpose token for browser EventSource URLs (which can't send headers).

    A URL ends up in logs and Referer headers, so it must not carry the real access token: this
    one is valid for one scan, for ~1 minute, and is rejected everywhere except the stream route.
    """
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id, "org_id": org_id, "scan_id": scan_id, "type": "sse",
        "iat": now, "exp": now + timedelta(seconds=ttl_seconds),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(subject: str) -> str:
    """Create a long-lived JWT refresh token."""
    now = datetime.now(timezone.utc)
    expire = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    payload = {
        "sub": subject,
        "iat": now,
        "exp": expire,
        "type": "refresh",
        "jti": secrets.token_hex(16),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_token(token: str) -> dict:
    """
    Decode and validate a JWT token.

    Raises:
        JWTError: if token is invalid or expired.
    """
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])


# --- Refresh Token Store (Redis) ---
_redis_client: Optional[aioredis.Redis] = None


def _get_redis() -> aioredis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = aioredis.from_url(
            settings.REDIS_URL,
            db=settings.REDIS_SCAN_PUBSUB_DB,
            decode_responses=True,
        )
    return _redis_client


async def store_refresh_token(user_id: str, token: str) -> None:
    """Store a refresh token in Redis with TTL."""
    r = _get_redis()
    key = f"refresh_token:{user_id}:{hashlib.sha256(token.encode()).hexdigest()}"
    ttl = settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400
    await r.setex(key, ttl, "valid")


async def revoke_refresh_token(user_id: str, token: str) -> None:
    """Revoke a refresh token by deleting it from Redis."""
    r = _get_redis()
    key = f"refresh_token:{user_id}:{hashlib.sha256(token.encode()).hexdigest()}"
    await r.delete(key)


async def is_refresh_token_valid(user_id: str, token: str) -> bool:
    """Check if a refresh token is still valid in Redis."""
    r = _get_redis()
    key = f"refresh_token:{user_id}:{hashlib.sha256(token.encode()).hexdigest()}"
    result = await r.get(key)
    return result == "valid"


async def revoke_all_user_tokens(user_id: str) -> None:
    """Revoke all refresh tokens for a user (logout all sessions)."""
    r = _get_redis()
    pattern = f"refresh_token:{user_id}:*"
    # Use SCAN instead of KEYS to avoid blocking Redis on large keyspaces
    keys = []
    cursor = 0
    while True:
        cursor, partial = await r.scan(cursor, match=pattern, count=100)
        keys.extend(partial)
        if cursor == 0:
            break
    if keys:
        await r.delete(*keys)


# --- API Key Handling ---
def generate_api_key() -> tuple[str, str]:
    """
    Generate a new API key pair.

    Returns:
        (raw_key, hashed_key) — store only the hash, return raw to user once.
    """
    raw_key = "attacktrace_" + secrets.token_urlsafe(40)
    hashed = hashlib.sha256(raw_key.encode()).hexdigest()
    return raw_key, hashed


def hash_api_key(raw_key: str) -> str:
    """Hash an API key for storage/lookup."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


# --- Credential Encryption (AES-256 via Fernet) ---
def _get_fernet() -> Fernet:
    """
    Build a Fernet cipher from KMS_MASTER_KEY.
    KMS_MASTER_KEY must be a URL-safe base64-encoded 32-byte key.
    """
    key = settings.KMS_MASTER_KEY
    # Ensure the key is exactly 32 bytes when decoded; pad or derive if necessary
    raw = key.encode()
    # Derive a 32-byte key using SHA-256 if the raw value isn't already base64-Fernet format
    derived = hashlib.sha256(raw).digest()
    fernet_key = base64.urlsafe_b64encode(derived)
    return Fernet(fernet_key)


def encrypt_credential(plaintext: str) -> str:
    """Encrypt a credential string. Returns a base64-encoded ciphertext string."""
    if not plaintext:
        return ""
    f = _get_fernet()
    return f.encrypt(plaintext.encode()).decode()


def decrypt_credential(ciphertext: str) -> str:
    """Decrypt an encrypted credential string."""
    if not ciphertext:
        return ""
    f = _get_fernet()
    return f.decrypt(ciphertext.encode()).decode()
