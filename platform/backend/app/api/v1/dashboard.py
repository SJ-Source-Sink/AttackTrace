"""
Dashboard stats endpoint — aggregates across scans, assets, findings.
Results are cached in Redis for 5 minutes per org to reduce DB load at scale.
"""

import json
from typing import Annotated
from uuid import UUID

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.dependencies import get_current_org_id, get_current_user
from app.models.db.asset import Asset
from app.models.db.finding import Finding, FindingStatus
from app.models.db.scan import ScanJob, ScanStatus
from app.models.db.user import User

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])
settings = get_settings()
_CACHE_TTL = 300  # 5 minutes


async def _get_redis() -> aioredis.Redis | None:
    try:
        r = aioredis.from_url(settings.REDIS_URL, socket_connect_timeout=1, decode_responses=True)
        await r.ping()
        return r
    except Exception:
        return None


@router.get("/stats", summary="Get dashboard summary statistics")
async def get_dashboard_stats(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    cache_key = f"dashboard:stats:{org_id}"
    redis = await _get_redis()
    if redis:
        try:
            cached = await redis.get(cache_key)
            if cached:
                await redis.aclose()
                return json.loads(cached)
        except Exception:
            pass

    # Total assets
    total_assets = (
        await db.execute(select(func.count()).where(Asset.org_id == org_id))
    ).scalar_one()

    # Active assets (is_active=True)
    active_assets = (
        await db.execute(select(func.count()).where(Asset.org_id == org_id, Asset.is_active == True))
    ).scalar_one()

    # Findings by severity (open/in_progress only)
    active_statuses = [FindingStatus.OPEN, FindingStatus.IN_PROGRESS]
    findings_q = select(Finding.severity, func.count()).where(
        Finding.org_id == org_id,
        Finding.status.in_(active_statuses),
    ).group_by(Finding.severity)
    findings_rows = (await db.execute(findings_q)).all()
    findings_by_sev = {row[0].value: row[1] for row in findings_rows}

    total_findings = sum(findings_by_sev.values())
    critical = findings_by_sev.get("critical", 0)
    high = findings_by_sev.get("high", 0)
    medium = findings_by_sev.get("medium", 0)
    low = findings_by_sev.get("low", 0)
    info = findings_by_sev.get("info", 0)

    # Risk score (simple: weighted avg based on finding severity)
    risk_score = min(100, (critical * 25 + high * 10 + medium * 3 + low * 1))

    # Active scans
    active_scans = (
        await db.execute(
            select(func.count()).where(
                ScanJob.org_id == org_id,
                ScanJob.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING]),
            )
        )
    ).scalar_one()

    # Total scans
    total_scans = (
        await db.execute(select(func.count()).where(ScanJob.org_id == org_id))
    ).scalar_one()

    # Risk history (last 7 completed scans for trend)
    recent_scans = (
        await db.execute(
            select(ScanJob.completed_at, ScanJob.findings_count)
            .where(ScanJob.org_id == org_id, ScanJob.status == ScanStatus.COMPLETED)
            .order_by(ScanJob.completed_at.desc())
            .limit(7)
        )
    ).all()

    risk_history = []
    for row in reversed(recent_scans):
        fc = row[1] or {}
        c, h, m, l_ = fc.get("critical", 0), fc.get("high", 0), fc.get("medium", 0), fc.get("low", 0)
        score = min(100, c * 25 + h * 10 + m * 3 + l_ * 1)
        risk_history.append({
            "date": row[0].isoformat() if row[0] else None,
            "score": score,
        })

    # Risk trend: compare current score vs previous scan score
    if len(risk_history) >= 2:
        prev_score = risk_history[-2]["score"]
        if risk_score > prev_score:
            risk_trend = "up"
        elif risk_score < prev_score:
            risk_trend = "down"
        else:
            risk_trend = "stable"
    else:
        risk_trend = "stable"

    result = {
        "total_assets": total_assets,
        "active_assets": active_assets,
        "total_findings": total_findings,
        "critical_findings": critical,
        "high_findings": high,
        "medium_findings": medium,
        "low_findings": low,
        "info_findings": info,
        "risk_score": risk_score,
        "risk_trend": risk_trend,
        "active_scans": active_scans,
        "total_scans": total_scans,
        "risk_score_history": risk_history,
    }

    if redis:
        try:
            await redis.set(cache_key, json.dumps(result), ex=_CACHE_TTL)
            await redis.aclose()
        except Exception:
            pass

    return result
