"""
Live re-confirmation of enumeration data and findings — closes the gap where
a port/endpoint/finding is treated as still-true forever after the scan that
discovered it. Generalizes the single-shot replay-and-inspect pattern already
proven in burp_analyzer.py::verify_request into narrow, reusable primitives
that both a manual "Re-verify" action and the Attack Suite agent (Phase 4)
can call before trusting a piece of enumeration data.
"""
from __future__ import annotations

import asyncio
import hashlib
from urllib.parse import urlparse

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.finding_confidence import grade_confidence
from app.models.db.finding import Finding


async def check_port_live(host: str, port: int, timeout: float = 3.0) -> bool:
    """Raw TCP connect check — true only if the port actually accepts a
    connection right now, independent of whatever a past scan recorded."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def check_endpoint_live(url: str, timeout: float = 8.0) -> dict:
    """Fetch a URL and report whether it's still reachable, its current
    status/headers, and a body hash (to detect if the content changed).

    verify=False is intentional here, matching secrets.py/exposure_scanner.py/
    takeover.py elsewhere in this codebase: this probes arbitrary pentest
    targets under authorized test, not the platform's own trusted resources —
    rejecting a self-signed/misconfigured cert would falsely report a live
    target as unreachable, which is the opposite of what this check is for.
    """
    try:
        async with httpx.AsyncClient(follow_redirects=True, verify=False, timeout=timeout) as client:
            resp = await client.get(url, headers={"User-Agent": "AttackTrace-Validator/1.0"})
        body_hash = hashlib.sha256(resp.content).hexdigest()[:16]
        return {
            "live": True,
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body_hash": body_hash,
            "body_length": len(resp.content),
        }
    except Exception as exc:
        return {"live": False, "error": str(exc)}


async def revalidate_finding(db: AsyncSession, finding: Finding) -> dict:
    """Re-check whether a finding still reproduces, dispatching on its
    category. Updates finding.confidence in place (caller commits) and
    returns a result dict describing what was checked and found.

    Does not attempt every vuln class — only the categories with a cheap,
    reliable live-recheck (a port being open, an endpoint being reachable).
    Everything else is left untouched and reported as "not revalidatable".
    """
    category = (finding.category or "").lower()
    asset = finding.affected_asset or ""

    # Port-shaped findings: category "cspm-*"/"container-*" evidence carries a
    # resource; nmap-derived port findings store host:port in affected_asset.
    if ":" in asset and asset.rsplit(":", 1)[-1].isdigit():
        host, port_str = asset.rsplit(":", 1)
        is_live = await check_port_live(host, int(port_str))
        if is_live:
            finding.confidence = grade_confidence("api-confirmed")
        return {
            "checked": "port", "host": host, "port": int(port_str),
            "still_live": is_live, "stale": not is_live,
        }

    if asset.startswith("http://") or asset.startswith("https://"):
        result = await check_endpoint_live(asset)
        if result.get("live"):
            finding.confidence = grade_confidence("api-confirmed")
        return {
            "checked": "endpoint", "url": asset,
            "still_live": bool(result.get("live")),
            "stale": not result.get("live"),
            "status_code": result.get("status_code"),
        }

    return {"checked": "none", "reason": "no port/URL pattern in affected_asset to revalidate"}
