"""
Webhook System — HMAC-SHA256 signed event delivery
Supports: scan.completed, finding.created, asset.discovered, sla.breached
"""

import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from typing import Annotated, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.core.dependencies import get_current_org_id, get_current_user
from app.core.ssrf_guard import SAFE_CLIENT_KWARGS, SSRFValidationError, validate_outbound_url
from app.models.db.user import User

router = APIRouter(prefix="/webhooks", tags=["Webhooks"])

VALID_EVENTS = {
    "scan.completed",
    "finding.created",
    "asset.discovered",
    "sla.breached",
    "scan.failed",
}


class WebhookCreate(BaseModel):
    url: str
    events: list[str]
    secret: Optional[str] = None
    description: Optional[str] = None
    is_active: bool = True


class WebhookResponse(BaseModel):
    id: str
    org_id: str
    url: str
    events: list[str]
    description: Optional[str]
    is_active: bool
    created_at: str
    delivery_count: int = 0
    failure_count: int = 0


def _sign_payload(secret: str, payload: bytes) -> str:
    """Generate HMAC-SHA256 signature."""
    return "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


def _get_webhooks_store(org_id: str) -> str:
    return f"webhooks:{org_id}"


async def _get_redis():
    import redis.asyncio as aioredis
    from app.core.config import get_settings
    settings = get_settings()
    return aioredis.from_url(settings.REDIS_URL, socket_connect_timeout=2)


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    summary="Register a webhook endpoint",
)
async def create_webhook(
    payload: WebhookCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> dict:
    # Validate events
    invalid = [e for e in payload.events if e not in VALID_EVENTS]
    if invalid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid events: {invalid}. Valid: {sorted(VALID_EVENTS)}",
        )

    # Reject an unsafe destination at registration time — SSRF guard (see
    # app/core/ssrf_guard.py). Re-validated again at dispatch time below to
    # catch DNS rebinding between now and delivery.
    try:
        validate_outbound_url(payload.url)
    except SSRFValidationError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid webhook url: {exc}")

    webhook_id = str(uuid.uuid4())
    secret = payload.secret or uuid.uuid4().hex

    webhook = {
        "id": webhook_id,
        "org_id": str(org_id),
        "url": payload.url,
        "events": payload.events,
        "secret": secret,
        "description": payload.description,
        "is_active": payload.is_active,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "delivery_count": 0,
        "failure_count": 0,
    }

    redis = await _get_redis()
    try:
        key = f"webhook:{str(org_id)}:{webhook_id}"
        await redis.set(key, json.dumps(webhook), ex=86400 * 365)  # 1 year TTL
        # Also add to org index
        await redis.sadd(f"webhooks_index:{str(org_id)}", webhook_id)
    finally:
        await redis.aclose()

    # Don't return the secret in the response (only shown at creation)
    return {**webhook, "secret_hint": f"sha256=...(computed from secret: {secret[:4]}...)"}


@router.get(
    "",
    summary="List webhooks for this org",
)
async def list_webhooks(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> dict:
    redis = await _get_redis()
    try:
        org_str = str(org_id)
        webhook_ids = await redis.smembers(f"webhooks_index:{org_str}")
        webhooks = []
        for wid in webhook_ids:
            wid_str = wid.decode() if isinstance(wid, bytes) else wid
            data = await redis.get(f"webhook:{org_str}:{wid_str}")
            if data:
                w = json.loads(data)
                w.pop("secret", None)  # Never expose secret in list
                webhooks.append(w)
    finally:
        await redis.aclose()

    return {"items": webhooks, "total": len(webhooks)}


@router.delete(
    "/{webhook_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a webhook",
)
async def delete_webhook(
    webhook_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> None:
    redis = await _get_redis()
    try:
        key = f"webhook:{str(org_id)}:{webhook_id}"
        deleted = await redis.delete(key)
        if not deleted:
            raise HTTPException(status_code=404, detail="Webhook not found")
        await redis.srem(f"webhooks_index:{str(org_id)}", webhook_id)
    finally:
        await redis.aclose()


@router.post(
    "/{webhook_id}/test",
    summary="Send a test event to a webhook",
)
async def test_webhook(
    webhook_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> dict:
    import httpx

    redis = await _get_redis()
    try:
        key = f"webhook:{str(org_id)}:{webhook_id}"
        data = await redis.get(key)
        if not data:
            raise HTTPException(status_code=404, detail="Webhook not found")
        webhook = json.loads(data)
    finally:
        await redis.aclose()

    # Re-validate at send time — the stored URL passed validation when the
    # webhook was created, but DNS can change since then (rebinding).
    try:
        validate_outbound_url(webhook["url"])
    except SSRFValidationError as exc:
        return {"status": "failed", "error": f"Invalid webhook url: {exc}"}

    test_payload = {
        "event": "webhook.test",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": {"message": "This is a test event from AttackTrace", "org_id": str(org_id)},
    }
    body = json.dumps(test_payload).encode()
    sig = _sign_payload(webhook["secret"], body)

    try:
        async with httpx.AsyncClient(timeout=10.0, **SAFE_CLIENT_KWARGS) as client:
            resp = await client.post(
                webhook["url"],
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "X-AttackTrace-Signature-256": sig,
                    "X-AttackTrace-Event": "webhook.test",
                },
            )
        return {"status": "delivered", "http_status": resp.status_code, "signature": sig}
    except Exception as e:
        return {"status": "failed", "error": str(e)}


async def dispatch_webhook_event(org_id: str, event: str, data: dict) -> None:
    """
    Dispatch a webhook event to all subscribed endpoints for the org.
    Called from scan worker, notification service, etc.
    """
    import httpx

    redis = await _get_redis()
    try:
        webhook_ids = await redis.smembers(f"webhooks_index:{org_id}")
        webhooks_to_notify = []
        for wid in webhook_ids:
            wid_str = wid.decode() if isinstance(wid, bytes) else wid
            raw = await redis.get(f"webhook:{org_id}:{wid_str}")
            if raw:
                w = json.loads(raw)
                if w.get("is_active") and event in w.get("events", []):
                    webhooks_to_notify.append(w)
    finally:
        await redis.aclose()

    if not webhooks_to_notify:
        return

    payload_dict = {
        "event": event,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "org_id": org_id,
        "data": data,
    }
    body = json.dumps(payload_dict).encode()

    async with httpx.AsyncClient(timeout=5.0, **SAFE_CLIENT_KWARGS) as client:
        for webhook in webhooks_to_notify:
            try:
                # Re-validate at dispatch time — DNS can change since the
                # webhook was created (rebinding protection).
                validate_outbound_url(webhook["url"])
                sig = _sign_payload(webhook["secret"], body)
                resp = await client.post(
                    webhook["url"],
                    content=body,
                    headers={
                        "Content-Type": "application/json",
                        "X-AttackTrace-Signature-256": sig,
                        "X-AttackTrace-Event": event,
                    },
                )
                # Update delivery stats in Redis
                new_redis = await _get_redis()
                try:
                    key = f"webhook:{org_id}:{webhook['id']}"
                    raw = await new_redis.get(key)
                    if raw:
                        w_data = json.loads(raw)
                        if resp.status_code < 300:
                            w_data["delivery_count"] = w_data.get("delivery_count", 0) + 1
                        else:
                            w_data["failure_count"] = w_data.get("failure_count", 0) + 1
                        await new_redis.set(key, json.dumps(w_data), keepttl=True)
                finally:
                    await new_redis.aclose()
            except Exception:
                pass
