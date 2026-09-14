"""
Live platform activity feed — what's running, right now, across every
scanner (distinct from /ai/activity/stream, which covers LLM calls only).
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from app.core.dependencies import get_current_org_id, get_current_user
from app.models.db.user import User

router = APIRouter(prefix="/activity", tags=["Activity"])


@router.get(
    "/scans/stream",
    summary="Live feed of every scanner run in this org",
    description=(
        "Server-Sent Events stream of every scanner run anywhere in the "
        "platform (nmap, nuclei, secrets, js_scanner, takeover, ffuf, "
        "firewall sub-scanners, api_scanner, ...) as it happens — which "
        "scanner started, against what target, every individual request/"
        "probe/progress event it yields, and how it finished. Live-only: "
        "nothing is persisted or replayed on reconnect, matching the AI "
        "activity feed's semantics. Any org member can watch — this is a "
        "visibility feature, not a privileged action."
    ),
)
async def stream_scan_activity_endpoint(
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
) -> StreamingResponse:
    from app.services.scan_activity import stream_scan_activity
    return StreamingResponse(
        stream_scan_activity(str(org_id), request),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive",
                 "X-Accel-Buffering": "no"},
    )
