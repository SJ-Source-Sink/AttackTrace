"""
Live AI activity feed — org-scoped Redis pub/sub broadcasting every LLM call
made anywhere in the platform (triage, Attack Suite planning, the autonomous
agent, the AI/LLM scanner's grader, etc.), so it can be watched live without
persisting anything. Deliberately live-only, mirroring the existing Attack
Suite AI Agent transcript's semantics: nothing is stored, nothing is
replayed on reconnect — this is a window into activity as it happens, not
an audit log.

Publish side lives in app.services.llm_client (the single seam every AI call
already goes through); this module only owns the pub/sub plumbing, reusing
the same Redis connection pool and subscriber shape already proven in
app.services.scan_service for live scan events.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import AsyncGenerator

from fastapi import Request

from app.services.scan_service import _get_redis

logger = logging.getLogger(__name__)

_HEARTBEAT_INTERVAL = 15  # seconds between SSE comment pings — same as scan_service.py
_POLL_INTERVAL = 0.2


def _channel(org_id: str) -> str:
    return f"ai_activity:{org_id}"


async def publish_activity(org_id: str, event: dict) -> None:
    """Fire-and-forget publish. Never raises — a broken activity feed must
    never break the actual AI call it's reporting on."""
    try:
        r = _get_redis()
        await r.publish(_channel(org_id), json.dumps(event, default=str))
    except Exception as exc:
        logger.warning(f"Failed to publish AI activity event for org {org_id}: {exc}")


async def stream_activity(org_id: str, request: Request) -> AsyncGenerator[str, None]:
    """Subscribe to this org's AI activity channel and yield SSE frames until
    the client disconnects. No replay, no persistence — live-only by design."""
    r = _get_redis()
    pubsub = r.pubsub()
    await pubsub.subscribe(_channel(org_id))

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
                json.loads(payload)  # validate before forwarding
            except (json.JSONDecodeError, TypeError):
                continue

            yield f"event: activity\ndata: {payload}\n\n"
    finally:
        await pubsub.unsubscribe(_channel(org_id))
        await pubsub.close()
        # Don't close `r` — shared module-level pool, other subscribers use it too.
