"""
Change detection service: diff two ScanJob results and classify changes.
Compares assets and findings between scans to surface what's new, gone, or upgraded.
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class ChangeType(str, Enum):
    APPEARED = "APPEARED"
    DISAPPEARED = "DISAPPEARED"
    RISK_UPGRADED = "RISK_UPGRADED"
    RISK_DOWNGRADED = "RISK_DOWNGRADED"
    CHANGED = "CHANGED"


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class AssetChange:
    change_type: ChangeType
    asset_type: str
    value: str
    before: Optional[dict] = None
    after: Optional[dict] = None
    urgency_score: float = 0.0
    description: str = ""


@dataclass
class FindingChange:
    change_type: ChangeType
    title: str
    severity_before: Optional[str] = None
    severity_after: Optional[str] = None
    affected_asset: str = ""
    urgency_score: float = 0.0
    description: str = ""


@dataclass
class ScanDiff:
    scan_before_id: str
    scan_after_id: str
    asset_changes: list[AssetChange] = field(default_factory=list)
    finding_changes: list[FindingChange] = field(default_factory=list)
    appeared_count: int = 0
    disappeared_count: int = 0
    risk_upgraded_count: int = 0
    changed_count: int = 0
    overall_urgency: float = 0.0
    notable_changes: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "scan_before_id": self.scan_before_id,
            "scan_after_id": self.scan_after_id,
            "appeared_count": self.appeared_count,
            "disappeared_count": self.disappeared_count,
            "risk_upgraded_count": self.risk_upgraded_count,
            "changed_count": self.changed_count,
            "overall_urgency": round(self.overall_urgency, 2),
            "notable_changes": self.notable_changes,
            "asset_changes": [
                {
                    "change_type": c.change_type.value,
                    "asset_type": c.asset_type,
                    "value": c.value,
                    "before": c.before,
                    "after": c.after,
                    "urgency_score": round(c.urgency_score, 2),
                    "description": c.description,
                }
                for c in self.asset_changes
            ],
            "finding_changes": [
                {
                    "change_type": fc.change_type.value,
                    "title": fc.title,
                    "severity_before": fc.severity_before,
                    "severity_after": fc.severity_after,
                    "affected_asset": fc.affected_asset,
                    "urgency_score": round(fc.urgency_score, 2),
                    "description": fc.description,
                }
                for fc in self.finding_changes
            ],
        }


def _urgency_for_appeared(asset_type: str, metadata: dict) -> float:
    """Calculate urgency score when an asset appears."""
    base = {
        "cloud": 7.0,
        "ip": 5.0,
        "webapp": 6.0,
        "subdomain": 4.0,
        "domain": 3.0,
    }.get(asset_type, 3.0)

    # Boost if it looks like it has open ports
    if metadata.get("ports") and len(metadata["ports"]) > 5:
        base = min(10.0, base + 1.5)

    return base


def _urgency_for_severity_change(before_sev: str, after_sev: str) -> float:
    """Calculate urgency based on severity escalation."""
    before_idx = SEVERITY_ORDER.get(before_sev, 0)
    after_idx = SEVERITY_ORDER.get(after_sev, 0)
    delta = after_idx - before_idx
    if delta <= 0:
        return 0.0
    # Each severity step up adds 2.5 points
    return min(10.0, 2.5 * delta + 3.0)


def compare_scan_summaries(
    summary_before: dict,
    summary_after: dict,
    scan_before_id: str,
    scan_after_id: str,
) -> ScanDiff:
    """
    Diff two ScanJob.results_summary JSON objects.

    results_summary structure:
    {
        "assets": [
            {"type": str, "value": str, "risk_score": float, "metadata": dict}
        ],
        "findings": [
            {"title": str, "severity": str, "affected_asset": str, "category": str}
        ],
        "total_domains": int, "total_subdomains": int, ...
    }
    """
    diff = ScanDiff(scan_before_id=scan_before_id, scan_after_id=scan_after_id)

    # --- Asset comparison ---
    before_assets = {a["value"]: a for a in (summary_before.get("assets") or [])}
    after_assets = {a["value"]: a for a in (summary_after.get("assets") or [])}

    # Appeared
    for value, asset in after_assets.items():
        if value not in before_assets:
            urgency = _urgency_for_appeared(asset.get("type", ""), asset.get("metadata", {}))
            change = AssetChange(
                change_type=ChangeType.APPEARED,
                asset_type=asset.get("type", "unknown"),
                value=value,
                after=asset,
                urgency_score=urgency,
                description=f"New {asset.get('type', 'asset')} discovered: {value}",
            )
            diff.asset_changes.append(change)
            diff.appeared_count += 1

    # Disappeared
    for value, asset in before_assets.items():
        if value not in after_assets:
            change = AssetChange(
                change_type=ChangeType.DISAPPEARED,
                asset_type=asset.get("type", "unknown"),
                value=value,
                before=asset,
                urgency_score=2.0,
                description=f"{asset.get('type', 'Asset')} no longer detected: {value}",
            )
            diff.asset_changes.append(change)
            diff.disappeared_count += 1

    # Changed (risk score change)
    for value in before_assets:
        if value in after_assets:
            before_risk = before_assets[value].get("risk_score") or 0.0
            after_risk = after_assets[value].get("risk_score") or 0.0
            if abs(after_risk - before_risk) >= 1.0:
                if after_risk > before_risk:
                    change_type = ChangeType.RISK_UPGRADED
                    urgency = min(10.0, 3.0 + (after_risk - before_risk))
                    diff.risk_upgraded_count += 1
                else:
                    change_type = ChangeType.RISK_DOWNGRADED
                    urgency = 1.0

                change = AssetChange(
                    change_type=change_type,
                    asset_type=before_assets[value].get("type", "unknown"),
                    value=value,
                    before=before_assets[value],
                    after=after_assets[value],
                    urgency_score=urgency,
                    description=f"Risk score changed for {value}: {before_risk:.1f} -> {after_risk:.1f}",
                )
                diff.asset_changes.append(change)
                diff.changed_count += 1

    # --- Finding comparison ---
    def finding_key(f: dict) -> str:
        return f"{f.get('title', '')}::{f.get('affected_asset', '')}"

    before_findings = {finding_key(f): f for f in (summary_before.get("findings") or [])}
    after_findings = {finding_key(f): f for f in (summary_after.get("findings") or [])}

    # New findings
    for key, finding in after_findings.items():
        if key not in before_findings:
            sev = finding.get("severity", "info")
            urgency = (SEVERITY_ORDER.get(sev, 0) + 1) * 2.0
            fc = FindingChange(
                change_type=ChangeType.APPEARED,
                title=finding.get("title", ""),
                severity_after=sev,
                affected_asset=finding.get("affected_asset", ""),
                urgency_score=urgency,
                description=f"New {sev} finding: {finding.get('title', '')}",
            )
            diff.finding_changes.append(fc)
            diff.appeared_count += 1

    # Resolved findings
    for key, finding in before_findings.items():
        if key not in after_findings:
            fc = FindingChange(
                change_type=ChangeType.DISAPPEARED,
                title=finding.get("title", ""),
                severity_before=finding.get("severity", "info"),
                affected_asset=finding.get("affected_asset", ""),
                urgency_score=1.0,
                description=f"Finding resolved: {finding.get('title', '')}",
            )
            diff.finding_changes.append(fc)
            diff.disappeared_count += 1

    # Severity escalations
    for key in before_findings:
        if key in after_findings:
            before_sev = before_findings[key].get("severity", "info")
            after_sev = after_findings[key].get("severity", "info")
            if SEVERITY_ORDER.get(after_sev, 0) > SEVERITY_ORDER.get(before_sev, 0):
                urgency = _urgency_for_severity_change(before_sev, after_sev)
                fc = FindingChange(
                    change_type=ChangeType.RISK_UPGRADED,
                    title=before_findings[key].get("title", ""),
                    severity_before=before_sev,
                    severity_after=after_sev,
                    affected_asset=before_findings[key].get("affected_asset", ""),
                    urgency_score=urgency,
                    description=f"Finding severity escalated: {before_sev} -> {after_sev}",
                )
                diff.finding_changes.append(fc)
                diff.risk_upgraded_count += 1

    # Calculate overall urgency (weighted average of top 5 changes)
    all_urgencies = sorted(
        [c.urgency_score for c in diff.asset_changes + diff.finding_changes],
        reverse=True,
    )
    if all_urgencies:
        top_5 = all_urgencies[:5]
        diff.overall_urgency = sum(top_5) / len(top_5)

    # Build notable changes list (top 10 by urgency)
    all_changes = []
    for c in diff.asset_changes:
        all_changes.append({
            "type": "asset",
            "change_type": c.change_type.value,
            "value": c.value,
            "description": c.description,
            "urgency": c.urgency_score,
        })
    for fc in diff.finding_changes:
        all_changes.append({
            "type": "finding",
            "change_type": fc.change_type.value,
            "title": fc.title,
            "description": fc.description,
            "urgency": fc.urgency_score,
        })

    diff.notable_changes = sorted(all_changes, key=lambda x: x["urgency"], reverse=True)[:10]

    return diff


def compare_scan_jobs(job_before, job_after) -> ScanDiff:
    """
    Compare two ScanJob ORM instances using their results_summary.
    Convenience wrapper around compare_scan_summaries.
    """
    before_summary = job_before.results_summary or {}
    after_summary = job_after.results_summary or {}
    return compare_scan_summaries(
        before_summary,
        after_summary,
        str(job_before.id),
        str(job_after.id),
    )
