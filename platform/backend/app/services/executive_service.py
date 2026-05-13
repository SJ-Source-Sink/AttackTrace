"""
Executive dashboard metrics service.
Provides aggregated KPIs for the executive dashboard view.
"""

from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import case, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import AsyncSessionLocal
from app.models.db.asset import Asset
from app.models.db.finding import Finding, FindingSeverity, FindingStatus
from app.models.db.scan import ScanJob, ScanStatus


async def get_executive_metrics(db: AsyncSession, org_id: UUID) -> dict:
    """
    Compute executive-level security KPIs for the given org.

    Returns:
        dict with mttr_by_severity, risk_trend, new_vs_recurring,
        coverage_percent, open_critical, sla_compliance_percent, generated_at.
    """
    now = datetime.now(timezone.utc)

    # Use a fresh dedicated session to avoid concurrency issues with the
    # request-scoped session (asyncpg does not allow concurrent queries on
    # the same connection, and FastAPI may share the session across dependencies).
    async with AsyncSessionLocal() as session:
        mttr_rows         = await _mttr_by_severity(session, org_id)
        risk_30d          = await _avg_risk_for_period(session, org_id, days=30)
        risk_60d          = await _avg_risk_for_period(session, org_id, days=60)
        risk_90d          = await _avg_risk_for_period(session, org_id, days=90)
        new_recurring     = await _new_vs_recurring(session, org_id)
        coverage_res      = await _coverage_percent(session, org_id, now)
        open_critical_res = await _open_critical_count(session, org_id)
        sla_res           = await _sla_compliance(session, org_id)

    return {
        "mttr_by_severity": mttr_rows,
        "risk_trend": {
            "30d": round(risk_30d, 1),
            "60d": round(risk_60d, 1),
            "90d": round(risk_90d, 1),
        },
        "new_vs_recurring": new_recurring,
        "coverage_percent": round(coverage_res, 1),
        "open_critical": open_critical_res,
        "sla_compliance_percent": round(sla_res, 1),
        "generated_at": now.isoformat(),
    }


async def _mttr_by_severity(db: AsyncSession, org_id: UUID) -> dict:
    """Average days from created_at to updated_at for remediated findings, by severity."""
    result = await db.execute(
        select(
            Finding.severity,
            func.avg(
                func.extract(
                    "epoch",
                    Finding.updated_at - Finding.created_at,
                )
                / 86400.0
            ).label("avg_days"),
        )
        .where(
            Finding.org_id == org_id,
            Finding.status == FindingStatus.REMEDIATED,
            Finding.updated_at.isnot(None),
            Finding.created_at.isnot(None),
        )
        .group_by(Finding.severity)
    )

    rows = result.all()
    mttr: dict = {"critical": None, "high": None, "medium": None, "low": None}
    for row in rows:
        sev = row[0].value if hasattr(row[0], "value") else str(row[0])
        avg_days = float(row[1]) if row[1] is not None else None
        if sev in mttr and avg_days is not None:
            mttr[sev] = round(avg_days, 1)
    return mttr


async def _avg_risk_for_period(db: AsyncSession, org_id: UUID, days: int) -> float:
    """
    Average risk score for findings created in last N days.
    Uses risk_score/priority_score if set; falls back to a severity-derived score:
      critical=90, high=70, medium=45, low=20, info=5.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    severity_score = case(
        (Finding.severity == FindingSeverity.CRITICAL, 90.0),
        (Finding.severity == FindingSeverity.HIGH,     70.0),
        (Finding.severity == FindingSeverity.MEDIUM,   45.0),
        (Finding.severity == FindingSeverity.LOW,      20.0),
        else_=5.0,
    )
    result = await db.execute(
        select(
            func.avg(
                func.coalesce(Finding.risk_score, Finding.priority_score, severity_score)
            )
        ).where(
            Finding.org_id == org_id,
            Finding.created_at >= cutoff,
        )
    )
    val = result.scalar_one_or_none()
    return float(val) if val is not None else 0.0


async def _new_vs_recurring(db: AsyncSession, org_id: UUID) -> dict:
    """
    Count new vs recurring findings for the org.

    A finding is 'new' if no other finding with the same dedup_hash AND
    an earlier created_at exists within the same org.
    Findings without a dedup_hash are always counted as new.
    """
    # Total findings with a dedup_hash in this org
    total_result = await db.execute(
        select(func.count()).where(
            Finding.org_id == org_id,
            Finding.dedup_hash.isnot(None),
        )
    )
    total_with_hash = total_result.scalar_one()

    # Findings without any hash are always "new"
    no_hash_result = await db.execute(
        select(func.count()).where(
            Finding.org_id == org_id,
            Finding.dedup_hash.is_(None),
        )
    )
    no_hash = no_hash_result.scalar_one()

    # Among findings with a hash: those that are NOT the earliest occurrence
    # of their dedup_hash are "recurring"
    if total_with_hash == 0:
        return {"new": no_hash, "recurring": 0}

    # Use a subquery: for each (org_id, dedup_hash) pair find the minimum created_at.
    # Findings whose created_at > that minimum are recurring.
    subq = (
        select(
            Finding.dedup_hash,
            func.min(Finding.created_at).label("first_seen"),
        )
        .where(
            Finding.org_id == org_id,
            Finding.dedup_hash.isnot(None),
        )
        .group_by(Finding.dedup_hash)
        .subquery()
    )

    recurring_result = await db.execute(
        select(func.count())
        .select_from(Finding)
        .join(subq, Finding.dedup_hash == subq.c.dedup_hash)
        .where(
            Finding.org_id == org_id,
            Finding.dedup_hash.isnot(None),
            Finding.created_at > subq.c.first_seen,
        )
    )
    recurring = recurring_result.scalar_one()

    new_with_hash = total_with_hash - recurring
    return {"new": new_with_hash + no_hash, "recurring": recurring}


async def _coverage_percent(db: AsyncSession, org_id: UUID, now: datetime) -> float:
    """
    % of distinct assets that have at least one scan in the last 30 days,
    divided by total org assets.
    """
    cutoff = now - timedelta(days=30)

    total_result = await db.execute(
        select(func.count()).where(Asset.org_id == org_id)
    )
    total_assets = total_result.scalar_one()

    if total_assets == 0:
        return 0.0

    # Assets that appear in at least one completed scan job in the last 30 days
    recent_result = await db.execute(
        select(func.count(func.distinct(Asset.id)))
        .join(ScanJob, ScanJob.id == Asset.scan_job_id)
        .where(
            Asset.org_id == org_id,
            ScanJob.status == ScanStatus.COMPLETED,
            ScanJob.completed_at >= cutoff,
        )
    )
    recent_scanned = recent_result.scalar_one()

    return (recent_scanned / total_assets) * 100.0


async def _open_critical_count(db: AsyncSession, org_id: UUID) -> int:
    """Count of open critical findings."""
    result = await db.execute(
        select(func.count()).where(
            Finding.org_id == org_id,
            Finding.severity == FindingSeverity.CRITICAL,
            Finding.status == FindingStatus.OPEN,
        )
    )
    return result.scalar_one()


async def _sla_compliance(db: AsyncSession, org_id: UUID) -> float:
    """
    % of resolved findings (remediated/accepted_risk/false_positive) that
    were resolved before their sla_deadline (of those that HAVE an sla_deadline).
    """
    resolved_statuses = [
        FindingStatus.REMEDIATED,
        FindingStatus.ACCEPTED_RISK,
        FindingStatus.FALSE_POSITIVE,
    ]

    # Total resolved findings with an sla_deadline
    total_result = await db.execute(
        select(func.count()).where(
            Finding.org_id == org_id,
            Finding.status.in_(resolved_statuses),
            Finding.sla_deadline.isnot(None),
        )
    )
    total_with_sla = total_result.scalar_one()

    if total_with_sla == 0:
        return 100.0  # No SLA deadlines set — treat as 100% compliant

    # Resolved before deadline: updated_at < sla_deadline
    compliant_result = await db.execute(
        select(func.count()).where(
            Finding.org_id == org_id,
            Finding.status.in_(resolved_statuses),
            Finding.sla_deadline.isnot(None),
            Finding.updated_at <= Finding.sla_deadline,
        )
    )
    compliant = compliant_result.scalar_one()

    return (compliant / total_with_sla) * 100.0
