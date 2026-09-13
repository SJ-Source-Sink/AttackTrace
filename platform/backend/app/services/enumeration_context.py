"""
Enumeration Context aggregator — the single source of truth for "everything
this org's scans already know" about its attack surface. Built so Attack
Suite's AI agent (and anything else that plans testing) grounds its decisions
in real Asset/Finding data instead of a single crawler's narrow, in-memory
view of one target.

Pulls current Asset rows (ports/services from nmap, discovered paths from
ffuf — both persisted via app.services.asset_upsert as of this session) plus
open Finding rows (severity, confidence, CVE/CVSS/EPSS/KEV, source scanner)
plus a recent-scan summary, optionally scoped to one target domain.
"""
from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.db.asset import Asset
from app.models.db.finding import Finding, FindingStatus
from app.models.db.scan import ScanJob

_MAX_ASSETS = 500
_MAX_FINDINGS = 500


def _asset_matches_target(value: str, target: str) -> bool:
    value = value.lower()
    target = target.lower().lstrip(".")
    return value == target or value.endswith(f".{target}") or target in value


def _serialize_asset(asset: Asset) -> dict:
    meta = asset.metadata_ or {}
    return {
        "id": str(asset.id),
        "type": asset.asset_type.value if hasattr(asset.asset_type, "value") else asset.asset_type,
        "value": asset.value,
        "ports": meta.get("ports", []),
        "discovered_paths": meta.get("discovered_paths", []),
        "os": meta.get("os"),
        "tech": meta.get("tech") or meta.get("tech_stack"),
        "provider": meta.get("provider"),
        "resolved_ips": meta.get("resolved_ips") or meta.get("ips"),
        "http_status": meta.get("http_status") or meta.get("status_code"),
        "is_active": asset.is_active,
        "last_seen": asset.last_seen.isoformat() if asset.last_seen else None,
    }


def _serialize_finding(finding: Finding) -> dict:
    return {
        "id": str(finding.id),
        "title": finding.title,
        "severity": finding.severity.value if hasattr(finding.severity, "value") else finding.severity,
        "category": finding.category,
        "affected_asset": finding.affected_asset,
        "confidence": finding.confidence,
        "cve": finding.cve or [],
        "cvss_score": finding.cvss_score,
        "epss_score": finding.epss_score,
        "kev_status": finding.kev_status,
        "source": finding.source,
        "remediation": finding.remediation,
    }


async def build_context(db: AsyncSession, org_id: UUID | str, target: str | None = None) -> dict:
    """Assemble the current enumeration+findings picture for an org, optionally
    filtered to assets/findings related to one target domain."""
    asset_stmt = (
        select(Asset)
        .where(Asset.org_id == org_id, Asset.is_active.is_(True))
        .order_by(Asset.last_seen.desc())
        .limit(_MAX_ASSETS)
    )
    assets = list((await db.execute(asset_stmt)).scalars().all())
    if target:
        assets = [a for a in assets if _asset_matches_target(a.value, target)]

    finding_stmt = (
        select(Finding)
        .where(
            Finding.org_id == org_id,
            Finding.status == FindingStatus.OPEN,
            Finding.suppressed.is_(False),
        )
        .order_by(Finding.created_at.desc())
        .limit(_MAX_FINDINGS)
    )
    findings = list((await db.execute(finding_stmt)).scalars().all())
    if target:
        findings = [f for f in findings if _asset_matches_target(f.affected_asset or "", target)]

    scan_stmt = (
        select(ScanJob)
        .where(ScanJob.org_id == org_id)
        .order_by(ScanJob.created_at.desc())
        .limit(5)
    )
    recent_scans = list((await db.execute(scan_stmt)).scalars().all())
    if target:
        recent_scans = [s for s in recent_scans if any(_asset_matches_target(d, target) for d in s.target_domains)]

    return {
        "target": target,
        "asset_count": len(assets),
        "finding_count": len(findings),
        "assets": [_serialize_asset(a) for a in assets],
        "findings": [_serialize_finding(f) for f in findings],
        "recent_scans": [
            {
                "id": str(s.id),
                "target_domains": s.target_domains,
                "status": s.status.value if hasattr(s.status, "value") else s.status,
                "findings_count": s.findings_count,
                "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            }
            for s in recent_scans
        ],
    }
