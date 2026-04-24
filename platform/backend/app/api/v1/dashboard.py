"""
Dashboard stats endpoint — aggregates across scans, assets, findings.
Results are cached in Redis for 5 minutes per org to reduce DB load at scale.
"""

import asyncio
import json
import math
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

# Module-level Redis connection pool — created once, reused across requests
_redis_pool: aioredis.Redis | None = None


async def _get_redis() -> aioredis.Redis | None:
    global _redis_pool
    if _redis_pool is None:
        try:
            _redis_pool = aioredis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True,
                socket_connect_timeout=1,
                max_connections=10,
            )
        except Exception:
            return None
    try:
        await _redis_pool.ping()
        return _redis_pool
    except Exception:
        # Pool is unhealthy — reset so it's recreated on the next request
        _redis_pool = None
        return None


@router.get("/stats", summary="Get dashboard summary statistics")
async def get_dashboard_stats(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    cache_key = f"dashboard:stats:{org_id}"
    lock_key = f"dashboard:lock:{org_id}"
    redis = await _get_redis()
    if redis:
        try:
            cached = await redis.get(cache_key)
            if cached:
                return json.loads(cached)
            # Stampede protection: acquire a short-lived lock so only one
            # concurrent request rebuilds the cache. Others serve stale or fall
            # through to the DB (acceptable on very first cold start).
            acquired = await redis.set(lock_key, "1", nx=True, ex=10)
            if not acquired:
                stale = await redis.get(cache_key)
                if stale:
                    return json.loads(stale)
        except Exception:
            redis = None

    # Build all independent queries
    active_statuses = [FindingStatus.OPEN, FindingStatus.IN_PROGRESS]
    findings_q = select(Finding.severity, func.count()).where(
        Finding.org_id == org_id,
        Finding.status.in_(active_statuses),
    ).group_by(Finding.severity)
    recent_scans_q = (
        select(ScanJob.completed_at, ScanJob.findings_count)
        .where(ScanJob.org_id == org_id, ScanJob.status == ScanStatus.COMPLETED)
        .order_by(ScanJob.completed_at.desc())
        .limit(7)
    )

    # Run all independent DB queries in parallel
    (
        total_assets_r,
        active_assets_r,
        findings_rows_r,
        active_scans_r,
        total_scans_r,
        recent_scans_r,
    ) = await asyncio.gather(
        db.execute(select(func.count()).where(Asset.org_id == org_id)),
        db.execute(select(func.count()).where(Asset.org_id == org_id, Asset.is_active == True)),
        db.execute(findings_q),
        db.execute(
            select(func.count()).where(
                ScanJob.org_id == org_id,
                ScanJob.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING]),
            )
        ),
        db.execute(select(func.count()).where(ScanJob.org_id == org_id)),
        db.execute(recent_scans_q),
    )

    total_assets = total_assets_r.scalar_one()
    active_assets = active_assets_r.scalar_one()
    findings_by_sev = {row[0].value: row[1] for row in findings_rows_r.all()}
    active_scans = active_scans_r.scalar_one()
    total_scans = total_scans_r.scalar_one()
    recent_scans = recent_scans_r.all()

    total_findings = sum(findings_by_sev.values())
    critical = findings_by_sev.get("critical", 0)
    high = findings_by_sev.get("high", 0)
    medium = findings_by_sev.get("medium", 0)
    low = findings_by_sev.get("low", 0)
    info = findings_by_sev.get("info", 0)

    # Risk score — log-scaled so it doesn't max out with just a few findings.
    # Each severity tier uses diminishing returns: score grows quickly at first,
    # then levels off. Max of ~100 only with many criticals + highs together.
    # Weights: critical≈20pts base, high≈10pts, medium≈3pts, low≈0.5pts per first occurrence.
    def _log_risk(count: int, weight: float) -> float:
        return weight * math.log1p(count)  # log(1+count) → 0 when count=0

    raw = (
        _log_risk(critical, 20) +
        _log_risk(high,     10) +
        _log_risk(medium,    3) +
        _log_risk(low,     0.5)
    )
    risk_score = round(min(100, raw))

    risk_history = []
    for row in reversed(recent_scans):
        fc = row[1] or {}
        c, h, m, l_ = fc.get("critical", 0), fc.get("high", 0), fc.get("medium", 0), fc.get("low", 0)
        score = round(min(100, _log_risk(c, 20) + _log_risk(h, 10) + _log_risk(m, 3) + _log_risk(l_, 0.5)))
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
            await redis.delete(lock_key)
        except Exception:
            pass

    return result
