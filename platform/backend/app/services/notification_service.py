"""
Notification service: in-app and webhook notifications for scan events,
finding alerts, and member activity.
"""

import asyncio
import hashlib
import hmac
import json
import logging
import time
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

import httpx
import redis.asyncio as aioredis

from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

_redis: Optional[aioredis.Redis] = None


def _get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    return _redis


# --- In-App Notifications (stored in Redis stream) ---

async def push_in_app_notification(
    org_id: str,
    event_type: str,
    title: str,
    body: str,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    severity: Optional[str] = None,
    user_id: Optional[str] = None,
) -> None:
    """
    Push an in-app notification to an org's Redis stream.
    Frontend can poll or stream these.
    """
    r = _get_redis()
    notification = {
        "event_type": event_type,
        "title": title,
        "body": body,
        "resource_type": resource_type or "",
        "resource_id": resource_id or "",
        "severity": severity or "info",
        "user_id": user_id or "",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "read": "false",
    }

    stream_key = f"notifications:{org_id}"
    try:
        await r.xadd(stream_key, notification, maxlen=500)
    except Exception as e:
        logger.error(f"Failed to push in-app notification: {e}")


async def get_org_notifications(
    org_id: str,
    last_id: str = "0",
    count: int = 50,
) -> list[dict]:
    """Read in-app notifications from the org's Redis stream."""
    r = _get_redis()
    stream_key = f"notifications:{org_id}"
    try:
        entries = await r.xread({stream_key: last_id}, count=count, block=None)
        if not entries:
            return []
        notifications = []
        for _, messages in entries:
            for msg_id, data in messages:
                notifications.append({"id": msg_id, **data})
        return notifications
    except Exception as e:
        logger.error(f"Failed to read notifications: {e}")
        return []


# --- Webhook Notifications ---

def _sign_webhook_payload(payload: bytes, secret: str) -> str:
    """Generate HMAC-SHA256 signature for webhook payload verification."""
    signature = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return f"sha256={signature}"


async def send_webhook(
    url: str,
    event_type: str,
    payload: dict,
    secret: Optional[str] = None,
    timeout: int = 10,
    max_retries: int = 3,
) -> bool:
    """
    Send a webhook notification with optional HMAC signing.
    Retries up to max_retries times with exponential backoff.
    """
    body = json.dumps({
        "event_type": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": payload,
    }).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "AttackTrace-Platform/1.0",
        "X-AttackTrace-Event": event_type,
    }
    if secret:
        headers["X-AttackTrace-Signature"] = _sign_webhook_payload(body, secret)

    async with httpx.AsyncClient(timeout=timeout) as client:
        for attempt in range(max_retries):
            try:
                response = await client.post(url, content=body, headers=headers)
                if response.status_code < 300:
                    return True
                logger.warning(
                    f"Webhook to {url} returned {response.status_code} (attempt {attempt + 1})"
                )
            except httpx.RequestError as e:
                logger.warning(f"Webhook to {url} failed (attempt {attempt + 1}): {e}")

            if attempt < max_retries - 1:
                await asyncio.sleep(2 ** attempt)

    logger.error(f"All {max_retries} webhook attempts to {url} failed")
    return False


# --- Event-Specific Notification Helpers ---

async def notify_scan_completed(
    org_id: str,
    scan_id: str,
    target_domains: list[str],
    findings_count: dict,
    webhook_url: Optional[str] = None,
    webhook_secret: Optional[str] = None,
) -> None:
    """Notify when a scan completes."""
    total = sum(findings_count.values())
    critical = findings_count.get("critical", 0)
    high = findings_count.get("high", 0)

    severity = "info"
    if critical > 0:
        severity = "critical"
    elif high > 0:
        severity = "high"

    title = f"Scan completed: {', '.join(target_domains)}"
    body = f"Discovered {total} findings ({critical} critical, {high} high)"

    await push_in_app_notification(
        org_id=org_id,
        event_type="scan.completed",
        title=title,
        body=body,
        resource_type="scan_job",
        resource_id=scan_id,
        severity=severity,
    )

    if webhook_url:
        payload = {
            "scan_id": scan_id,
            "org_id": org_id,
            "target_domains": target_domains,
            "findings_count": findings_count,
        }
        asyncio.create_task(
            send_webhook(webhook_url, "scan.completed", payload, webhook_secret)
        )


async def notify_scan_failed(
    org_id: str,
    scan_id: str,
    target_domains: list[str],
    error_message: str,
    webhook_url: Optional[str] = None,
    webhook_secret: Optional[str] = None,
) -> None:
    """Notify when a scan fails."""
    await push_in_app_notification(
        org_id=org_id,
        event_type="scan.failed",
        title=f"Scan failed: {', '.join(target_domains)}",
        body=f"Error: {error_message[:200]}",
        resource_type="scan_job",
        resource_id=scan_id,
        severity="high",
    )

    if webhook_url:
        payload = {
            "scan_id": scan_id,
            "org_id": org_id,
            "target_domains": target_domains,
            "error_message": error_message,
        }
        asyncio.create_task(
            send_webhook(webhook_url, "scan.failed", payload, webhook_secret)
        )


async def notify_critical_finding(
    org_id: str,
    scan_id: str,
    finding_id: str,
    finding_title: str,
    affected_asset: str,
    severity: str,
    webhook_url: Optional[str] = None,
    webhook_secret: Optional[str] = None,
) -> None:
    """Notify for new critical/high findings."""
    if severity not in ("critical", "high"):
        return

    await push_in_app_notification(
        org_id=org_id,
        event_type="finding.created",
        title=f"New {severity} finding: {finding_title[:60]}",
        body=f"Affected: {affected_asset}",
        resource_type="finding",
        resource_id=finding_id,
        severity=severity,
    )

    if webhook_url:
        payload = {
            "finding_id": finding_id,
            "scan_id": scan_id,
            "org_id": org_id,
            "title": finding_title,
            "severity": severity,
            "affected_asset": affected_asset,
        }
        asyncio.create_task(
            send_webhook(webhook_url, "finding.created", payload, webhook_secret)
        )


async def notify_member_added(
    org_id: str,
    invited_by_name: str,
    member_email: str,
    role: str,
) -> None:
    """Notify when a new member joins an organization."""
    await push_in_app_notification(
        org_id=org_id,
        event_type="member.added",
        title=f"New member joined",
        body=f"{member_email} was added as {role} by {invited_by_name}",
        resource_type="org_member",
        severity="info",
    )


# --- Channel-based dispatch (NotificationChannel model) ---


async def dispatch_notifications(
    org_id: str,
    event_type: str,
    payload: dict,
    db_session,
) -> None:
    """
    Query active NotificationChannel rows for this org that subscribe to event_type,
    decrypt their config, and route to the appropriate sender.

    All HTTP failures are logged but not re-raised so a bad channel never
    disrupts the scan pipeline.
    """
    import json
    from sqlalchemy import select, and_
    from app.models.db.org import NotificationChannel
    from app.core.security import decrypt_credential

    try:
        result = await db_session.execute(
            select(NotificationChannel).where(
                and_(
                    NotificationChannel.org_id == org_id,
                    NotificationChannel.is_active == True,  # noqa: E712
                )
            )
        )
        channels = result.scalars().all()
    except Exception as exc:
        logger.error(f"dispatch_notifications: failed to query channels: {exc}")
        return

    for ch in channels:
        if event_type not in (ch.events or []):
            continue

        config: dict = {}
        if ch.config_enc:
            try:
                config = json.loads(decrypt_credential(ch.config_enc))
            except Exception as exc:
                logger.error(f"Failed to decrypt config for channel {ch.id}: {exc}")
                continue

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                if ch.channel_type == "slack":
                    await _dispatch_slack(client, config, event_type, payload)
                elif ch.channel_type == "teams":
                    await _dispatch_teams(client, config, event_type, payload)
                elif ch.channel_type == "webhook":
                    await _dispatch_generic_webhook(client, config, event_type, payload)
                elif ch.channel_type == "jira":
                    await _dispatch_jira(client, config, event_type, payload)
        except Exception as exc:
            logger.error(
                f"dispatch_notifications: channel {ch.id} ({ch.channel_type}) "
                f"failed for event {event_type}: {exc}"
            )


async def _dispatch_slack(
    client: httpx.AsyncClient, config: dict, event_type: str, payload: dict
) -> None:
    webhook_url = config.get("webhook_url", "")
    if not webhook_url:
        return
    text = _format_event_text(event_type, payload)
    resp = await client.post(webhook_url, json={"text": text})
    if resp.status_code != 200:
        logger.warning(f"Slack notification returned {resp.status_code}: {resp.text[:200]}")


async def _dispatch_teams(
    client: httpx.AsyncClient, config: dict, event_type: str, payload: dict
) -> None:
    webhook_url = config.get("webhook_url", "")
    if not webhook_url:
        return
    text = _format_event_text(event_type, payload)
    card = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {"type": "TextBlock", "text": text, "wrap": True},
                    ],
                },
            }
        ],
    }
    resp = await client.post(webhook_url, json=card)
    if resp.status_code not in (200, 202):
        logger.warning(f"Teams notification returned {resp.status_code}: {resp.text[:200]}")


async def _dispatch_generic_webhook(
    client: httpx.AsyncClient, config: dict, event_type: str, payload: dict
) -> None:
    url = config.get("url", "")
    if not url:
        return
    body = {
        "event": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": payload,
    }
    resp = await client.post(url, json=body)
    if resp.status_code >= 300:
        logger.warning(f"Webhook notification returned {resp.status_code}: {resp.text[:200]}")


async def _dispatch_jira(
    client: httpx.AsyncClient, config: dict, event_type: str, payload: dict
) -> None:
    """For finding.critical events, create a Jira issue."""
    if event_type != "finding.critical":
        return

    jira_url = config.get("jira_url", "").rstrip("/")
    email = config.get("email", "")
    api_token = config.get("api_token", "")
    project_key = config.get("project_key", "")

    if not all([jira_url, email, api_token, project_key]):
        logger.warning("Jira dispatch skipped: missing jira_url, email, api_token, or project_key")
        return

    finding_title = payload.get("title", "Critical Finding Detected")
    scan_id = payload.get("scan_id", "")
    affected_asset = payload.get("affected_asset", "")
    severity = payload.get("severity", "critical")

    issue_payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": f"[AttackTrace] {finding_title}",
            "description": {
                "version": 1,
                "type": "doc",
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {
                                "type": "text",
                                "text": (
                                    f"AttackTrace detected a {severity} severity finding.\n\n"
                                    f"Affected asset: {affected_asset}\n"
                                    f"Scan ID: {scan_id}\n"
                                ),
                            }
                        ],
                    }
                ],
            },
            "issuetype": {"name": "Bug"},
            "priority": {"name": "Highest" if severity == "critical" else "High"},
        }
    }

    resp = await client.post(
        f"{jira_url}/rest/api/3/issue",
        json=issue_payload,
        auth=(email, api_token),
        headers={"Accept": "application/json", "Content-Type": "application/json"},
    )
    if resp.status_code in (200, 201):
        issue_key = resp.json().get("key", "?")
        logger.info(f"Created Jira issue {issue_key} for finding: {finding_title}")
    else:
        logger.warning(f"Jira issue creation returned {resp.status_code}: {resp.text[:300]}")


def _format_event_text(event_type: str, payload: dict) -> str:
    """Format a human-readable notification message for an event."""
    if event_type == "scan.completed":
        domains = ", ".join(payload.get("target_domains", []))
        fc = payload.get("findings_count", {})
        critical = fc.get("critical", 0)
        high = fc.get("high", 0)
        total = sum(fc.values()) if fc else 0
        return (
            f"AttackTrace scan completed for {domains} — "
            f"{total} findings ({critical} critical, {high} high)"
        )
    if event_type == "finding.critical":
        title = payload.get("title", "Critical finding")
        asset = payload.get("affected_asset", "")
        sev = payload.get("severity", "critical")
        return f"[AttackTrace] {sev.upper()} finding: {title} — {asset}"
    if event_type == "sla.breached":
        finding_id = payload.get("finding_id", "")
        return f"[AttackTrace] SLA breach: finding {finding_id} has exceeded remediation deadline"
    return f"[AttackTrace] Event: {event_type}"
