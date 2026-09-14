"""
Live scanner activity feed — org-scoped Redis pub/sub broadcasting every
scanner run platform-wide (nmap, nuclei, secrets, js_scanner, takeover,
ffuf, firewall sub-scanners, ...) as it happens: which scanner started,
against what target, every individual request/probe/progress event it
yields, and how it finished — so "what's running right now, and what
exactly is it doing" is visible from one place instead of having to know
which of ~20 separate scanner pages to check.

Mirrors app.services.ai_activity's shape exactly (same Redis pool, same SSE
subscriber pattern, same live-only/no-persistence semantics — nothing is
stored, nothing is replayed on reconnect) — deliberately a sibling feed, not
a merge, since scanner activity and AI-call activity are different enough
volumes/shapes to want separate channels/pages.

Publish side: app.core.sse.tee_scan_activity wraps a scanner's EXISTING SSE
async generator (every scanner already yields "event: X\\ndata: {...}\\n\\n"
strings to its own live client) — it re-publishes each event to this
module's org-wide channel while still yielding it unchanged to the original
caller, so no scanner's internal logic needs to change, only its route
handler's `StreamingResponse(...)` call site (wrap the generator once).
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import AsyncGenerator

from fastapi import Request

from app.services.scan_service import _get_redis

logger = logging.getLogger(__name__)

_HEARTBEAT_INTERVAL = 15
_POLL_INTERVAL = 0.2

# Matches every scanner's SSE format, always exactly
# f"event: {event}\ndata: {json.dumps(data)}\n\n" — see app/core/sse.py and
# the equivalent inline copies in nuclei.py/nmap.py/ffuf.py/takeover.py.
_SSE_RE = re.compile(r"^event:\s*(?P<event>[^\n]+)\ndata:\s*(?P<data>.+?)\n\n\Z", re.DOTALL)


def _channel(org_id: str) -> str:
    return f"scan_activity:{org_id}"


async def publish_scan_activity(org_id: str, event: dict) -> None:
    """Fire-and-forget publish. Never raises — a broken activity feed must
    never break the actual scan it's reporting on."""
    try:
        r = _get_redis()
        await r.publish(_channel(str(org_id)), json.dumps(event, default=str))
    except Exception as exc:
        logger.warning(f"Failed to publish scan activity event for org {org_id}: {exc}")


async def tee_scan_activity(
    org_id, scanner: str, target: str, scan_id: str, gen: AsyncGenerator[str, None]
) -> AsyncGenerator[str, None]:
    """Wrap any existing scanner SSE generator: yields every chunk unchanged
    to the original caller (the scanner's own live client is unaffected),
    while also republishing each event to the org-wide scan-activity channel
    with added scanner/target/scan_id metadata. A malformed/non-SSE chunk is
    still yielded to the caller untouched — only skipped for republishing."""
    start = time.monotonic()
    await publish_scan_activity(org_id, {
        "type": "scan_started", "scanner": scanner, "target": target, "scan_id": scan_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    error: str | None = None
    try:
        async for chunk in gen:
            yield chunk
            m = _SSE_RE.match(chunk)
            if not m:
                continue
            event_type = m.group("event").strip()
            try:
                data = json.loads(m.group("data"))
            except json.JSONDecodeError:
                data = {"raw": m.group("data")}
            if event_type == "error":
                error = json.dumps(data, default=str)[:500]
            await publish_scan_activity(org_id, {
                "type": "scan_event", "scanner": scanner, "target": target, "scan_id": scan_id,
                "event": event_type, "data": data,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
    finally:
        await publish_scan_activity(org_id, {
            "type": "scan_finished", "scanner": scanner, "target": target, "scan_id": scan_id,
            "elapsed_seconds": round(time.monotonic() - start, 1), "error": error,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })


async def stream_scan_activity(org_id: str, request: Request) -> AsyncGenerator[str, None]:
    """Subscribe to this org's scan activity channel and yield SSE frames
    until the client disconnects. No replay, no persistence — live-only,
    matching app.services.ai_activity.stream_activity."""
    r = _get_redis()
    pubsub = r.pubsub()
    await pubsub.subscribe(_channel(str(org_id)))

    next_heartbeat = time.monotonic() + _HEARTBEAT_INTERVAL

    try:
        yield "event: connected\ndata: {}\n\n"

        while True:
            if await request.is_disconnected():
                break

            now = time.monotonic()
            if now >= next_heartbeat:
                yield ": ping\n\n"
                next_heartbeat = now + _HEARTBEAT_INTERVAL

            message = await pubsub.get_message(ignore_subscribe_messages=True)
            if message is None:
                await asyncio.sleep(_POLL_INTERVAL)
                continue

            try:
                payload = message["data"]
                json.loads(payload)
            except (json.JSONDecodeError, TypeError):
                continue

            yield f"event: activity\ndata: {payload}\n\n"
    finally:
        await pubsub.unsubscribe(_channel(str(org_id)))
        await pubsub.close()
        # Don't close `r` — shared module-level pool, other subscribers use it too.
