"""
Notification Channels API: CRUD + test for Slack, Jira, Teams, and generic webhooks.
"""

import json
import logging
from typing import Annotated, Optional
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import get_current_org_id, get_current_user
from app.core.security import decrypt_credential, encrypt_credential
from app.core.ssrf_guard import SAFE_CLIENT_KWARGS, SSRFValidationError, validate_outbound_url
from app.models.db.org import NotificationChannel
from app.models.db.user import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/notifications", tags=["Notifications"])

# Supported channel types
CHANNEL_TYPES = {"slack", "jira", "webhook", "teams"}

# Events that channels can subscribe to
VALID_EVENTS = {
    "scan.completed", "finding.critical", "sla.breached",
    "asset.discovered", "port.opened", "cert.expiring",
}


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class ChannelCreate(BaseModel):
    name: str = Field(..., max_length=255)
    channel_type: str = Field(..., pattern="^(slack|jira|webhook|teams)$")
    config: dict = Field(default_factory=dict)
    is_active: bool = True
    events: list[str] = Field(default_factory=list)


class ChannelUpdate(BaseModel):
    name: Optional[str] = Field(None, max_length=255)
    channel_type: Optional[str] = Field(None, pattern="^(slack|jira|webhook|teams)$")
    config: Optional[dict] = None
    is_active: Optional[bool] = None
    events: Optional[list[str]] = None


def _mask_config(config: dict) -> dict:
    """Replace secret-looking values with *** for safe client response."""
    secret_keys = {
        "api_token", "api_key", "password", "secret", "token",
        "webhook_url", "url",  # mask URLs partially to avoid leaking endpoints
    }
    masked = {}
    for k, v in config.items():
        if isinstance(v, str) and any(sk in k.lower() for sk in secret_keys):
            masked[k] = "***"
        else:
            masked[k] = v
    return masked


class ChannelResponse(BaseModel):
    id: str
    org_id: str
    name: str
    channel_type: str
    config: dict  # masked
    is_active: bool
    events: list[str]
    created_at: str
    updated_at: str

    @classmethod
    def from_orm(cls, obj: NotificationChannel) -> "ChannelResponse":
        raw_config: dict = {}
        if obj.config_enc:
            try:
                raw_config = json.loads(decrypt_credential(obj.config_enc))
            except Exception:
                raw_config = {}
        return cls(
            id=str(obj.id),
            org_id=str(obj.org_id),
            name=obj.name,
            channel_type=obj.channel_type,
            config=_mask_config(raw_config),
            is_active=obj.is_active,
            events=obj.events or [],
            created_at=obj.created_at.isoformat(),
            updated_at=obj.updated_at.isoformat(),
        )

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _get_channel_or_404(
    channel_id: UUID, org_id: UUID, db: AsyncSession
) -> NotificationChannel:
    result = await db.execute(
        select(NotificationChannel).where(
            NotificationChannel.id == channel_id,
            NotificationChannel.org_id == org_id,
        )
    )
    ch = result.scalar_one_or_none()
    if not ch:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "CHANNEL_NOT_FOUND", "message": "Notification channel not found"}},
        )
    return ch


# Which config keys hold an outbound URL for each channel type — these are
# the fields that get SSRF-validated at create/update time (see
# _validate_channel_urls) and again immediately before every fetch.
_URL_FIELDS_BY_TYPE: dict[str, tuple[str, ...]] = {
    "slack": ("webhook_url",),
    "teams": ("webhook_url",),
    "webhook": ("url",),
    "jira": ("jira_url",),
}


def _validate_channel_urls(channel_type: str, config: dict) -> None:
    """
    Reject a channel create/update up front if any URL field it carries is
    unsafe (private/reserved/loopback address, or a non-http(s) scheme) —
    closes the SSRF hole at the point the URL is first trusted, not just at
    send time. Missing fields are left for the existing required-field
    checks in the test/dispatch code to report; only present, non-empty URL
    fields are validated here.
    """
    for field in _URL_FIELDS_BY_TYPE.get(channel_type, ()):
        value = config.get(field)
        if not value:
            continue
        try:
            validate_outbound_url(value)
        except SSRFValidationError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={"error": {"code": "UNSAFE_URL", "message": f"Invalid {field}: {exc}"}},
            )


def _validate_events(events: list[str]) -> None:
    invalid = set(events) - VALID_EVENTS
    if invalid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": {
                    "code": "INVALID_EVENTS",
                    "message": f"Unknown event types: {', '.join(sorted(invalid))}. "
                               f"Valid events: {', '.join(sorted(VALID_EVENTS))}",
                }
            },
        )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/channels",
    summary="List notification channels for the organisation",
)
async def list_channels(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await db.execute(
        select(NotificationChannel)
        .where(NotificationChannel.org_id == org_id)
        .order_by(NotificationChannel.created_at.desc())
    )
    channels = result.scalars().all()
    return {"items": [ChannelResponse.from_orm(c) for c in channels]}


@router.post(
    "/channels",
    response_model=ChannelResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a notification channel",
)
async def create_channel(
    payload: ChannelCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> ChannelResponse:
    _validate_events(payload.events)
    _validate_channel_urls(payload.channel_type, payload.config)

    config_enc = encrypt_credential(json.dumps(payload.config)) if payload.config else None

    ch = NotificationChannel(
        org_id=org_id,
        name=payload.name,
        channel_type=payload.channel_type,
        config_enc=config_enc,
        is_active=payload.is_active,
        events=payload.events,
    )
    db.add(ch)
    await db.flush()
    await db.refresh(ch)
    await db.commit()
    await db.refresh(ch)

    return ChannelResponse.from_orm(ch)


@router.patch(
    "/channels/{channel_id}",
    response_model=ChannelResponse,
    summary="Update a notification channel",
)
async def update_channel(
    channel_id: UUID,
    payload: ChannelUpdate,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> ChannelResponse:
    ch = await _get_channel_or_404(channel_id, org_id, db)

    if payload.name is not None:
        ch.name = payload.name
    if payload.channel_type is not None:
        ch.channel_type = payload.channel_type
    if payload.is_active is not None:
        ch.is_active = payload.is_active
    if payload.events is not None:
        _validate_events(payload.events)
        ch.events = payload.events
    if payload.config is not None:
        # Merge: start with existing decrypted config, overlay new fields
        existing: dict = {}
        if ch.config_enc:
            try:
                existing = json.loads(decrypt_credential(ch.config_enc))
            except Exception:
                existing = {}
        # Only update keys explicitly provided (allow partial config updates)
        existing.update(payload.config)
        _validate_channel_urls(ch.channel_type, existing)
        ch.config_enc = encrypt_credential(json.dumps(existing))

    db.add(ch)
    await db.commit()
    await db.refresh(ch)

    return ChannelResponse.from_orm(ch)


@router.delete(
    "/channels/{channel_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a notification channel",
)
async def delete_channel(
    channel_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> None:
    ch = await _get_channel_or_404(channel_id, org_id, db)
    await db.delete(ch)
    await db.commit()


@router.post(
    "/channels/{channel_id}/test",
    summary="Send a test notification to verify channel configuration",
)
async def test_channel(
    channel_id: UUID,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    ch = await _get_channel_or_404(channel_id, org_id, db)

    config: dict = {}
    if ch.config_enc:
        try:
            config = json.loads(decrypt_credential(ch.config_enc))
        except Exception:
            return {"success": False, "message": "Failed to decrypt channel configuration"}

    try:
        async with httpx.AsyncClient(timeout=10.0, **SAFE_CLIENT_KWARGS) as client:
            if ch.channel_type == "slack":
                success, message = await _test_slack(client, config)
            elif ch.channel_type == "webhook":
                success, message = await _test_webhook(client, config)
            elif ch.channel_type == "jira":
                success, message = await _test_jira(client, config)
            elif ch.channel_type == "teams":
                success, message = await _test_teams(client, config)
            else:
                return {"success": False, "message": f"Unknown channel type: {ch.channel_type}"}
    except Exception as exc:
        logger.warning(f"Test notification failed for channel {channel_id}: {exc}")
        return {"success": False, "message": f"Request error: {exc}"}

    return {"success": success, "message": message}


# ---------------------------------------------------------------------------
# Channel-specific test functions
# ---------------------------------------------------------------------------


async def _test_slack(client: httpx.AsyncClient, config: dict) -> tuple[bool, str]:
    webhook_url = config.get("webhook_url", "")
    if not webhook_url:
        return False, "Missing webhook_url in Slack configuration"
    try:
        validate_outbound_url(webhook_url)
    except SSRFValidationError as exc:
        return False, f"Invalid webhook_url: {exc}"
    try:
        resp = await client.post(
            webhook_url,
            json={"text": "✅ AttackTrace test notification"},
        )
        if resp.status_code == 200:
            return True, "Slack test message sent successfully"
        # Don't reflect arbitrary response bytes from a caller-supplied URL
        # back to the caller (SSRF read primitive) — status code only.
        return False, f"Slack returned HTTP {resp.status_code}"
    except httpx.RequestError as exc:
        return False, f"Failed to reach Slack: {exc}"


async def _test_webhook(client: httpx.AsyncClient, config: dict) -> tuple[bool, str]:
    url = config.get("url", "")
    if not url:
        return False, "Missing url in webhook configuration"
    try:
        validate_outbound_url(url)
    except SSRFValidationError as exc:
        return False, f"Invalid url: {exc}"
    try:
        resp = await client.post(
            url,
            json={"event": "test", "message": "AttackTrace test notification"},
        )
        if resp.status_code < 300:
            return True, f"Webhook responded with HTTP {resp.status_code}"
        # Don't reflect arbitrary response bytes from a caller-supplied URL
        # back to the caller (SSRF read primitive) — status code only.
        return False, f"Webhook returned HTTP {resp.status_code}"
    except httpx.RequestError as exc:
        return False, f"Failed to reach webhook: {exc}"


async def _test_jira(client: httpx.AsyncClient, config: dict) -> tuple[bool, str]:
    jira_url = config.get("jira_url", "").rstrip("/")
    email = config.get("email", "")
    api_token = config.get("api_token", "")
    if not jira_url or not email or not api_token:
        return False, "Missing jira_url, email, or api_token in Jira configuration"
    try:
        validate_outbound_url(jira_url)
    except SSRFValidationError as exc:
        return False, f"Invalid jira_url: {exc}"
    try:
        resp = await client.get(
            f"{jira_url}/rest/api/3/myself",
            auth=(email, api_token),
            headers={"Accept": "application/json"},
        )
        if resp.status_code == 200:
            # displayName just confirms the credentials resolved to an
            # account — it's not arbitrary response content from a
            # caller-chosen destination, so it's fine to surface.
            try:
                data = resp.json()
                display_name = data.get("displayName", email)
            except Exception:
                display_name = email
            return True, f"Jira credentials valid — authenticated as {display_name}"
        return False, f"Jira returned HTTP {resp.status_code}"
    except httpx.RequestError as exc:
        return False, f"Failed to reach Jira: {exc}"


async def _test_teams(client: httpx.AsyncClient, config: dict) -> tuple[bool, str]:
    webhook_url = config.get("webhook_url", "")
    if not webhook_url:
        return False, "Missing webhook_url in Microsoft Teams configuration"
    try:
        validate_outbound_url(webhook_url)
    except SSRFValidationError as exc:
        return False, f"Invalid webhook_url: {exc}"
    # Adaptive Card payload for Teams incoming webhook
    card_payload = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": "✅ AttackTrace test notification",
                            "weight": "Bolder",
                            "size": "Medium",
                        },
                        {
                            "type": "TextBlock",
                            "text": "Your Microsoft Teams notification channel is configured correctly.",
                            "wrap": True,
                        },
                    ],
                },
            }
        ],
    }
    try:
        resp = await client.post(webhook_url, json=card_payload)
        if resp.status_code in (200, 202):
            return True, "Teams test message sent successfully"
        # Don't reflect arbitrary response bytes from a caller-supplied URL
        # back to the caller (SSRF read primitive) — status code only.
        return False, f"Teams returned HTTP {resp.status_code}"
    except httpx.RequestError as exc:
        return False, f"Failed to reach Teams: {exc}"
