"""Shared Server-Sent Events formatting helper used by every streaming scanner."""
import json


def sse_event(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"
