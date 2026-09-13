"""
Shared finding-ingestion helper for standalone scanners (cspm, secrets,
supply_chain, container_scanner, firewall, exposure_scanner, mcp_scanner,
takeover, email_security) that persist their own filesystem-JSON scan history
but historically never wrote into the shared `Finding` table — making their
findings invisible to the Dashboard, Findings page, SLA tracking, and
Compliance export, and unable to dedupe against the same issue found by a
different tool.

Mirrors the working upsert-by-dedup_hash pattern in
app.api.v1.mobile._sync_msra_to_db, using the same dedup key formula as the
main scan pipeline (app.core.dedup.compute_dedup_hash) so a vulnerability
found by two different tools on the same asset collapses to one row.
"""
from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dedup import compute_dedup_hash
from app.models.db.finding import Finding, FindingSeverity, FindingStatus

_SEVERITY_MAP: dict[str, FindingSeverity] = {
    "critical": FindingSeverity.CRITICAL,
    "high": FindingSeverity.HIGH,
    "medium": FindingSeverity.MEDIUM,
    "low": FindingSeverity.LOW,
    "info": FindingSeverity.INFO,
}


async def ingest_findings(
    db: AsyncSession,
    org_id: UUID | str,
    source: str,
    source_scan_id: str,
    findings: list[dict],
) -> dict:
    """Upsert a batch of normalized findings into the shared Finding table.

    Each dict in `findings` should have: title, description, severity (str),
    category, affected_asset, evidence (dict|None), remediation, references
    (list|None), cve (list|None), confidence (str|None). Info-severity entries
    (e.g. "SPF is properly configured") are skipped — this table is for real
    findings, not all-clear confirmations.

    Does not commit — caller commits alongside its own filesystem-history write
    so both succeed or fail together.
    """
    inserted = 0
    updated = 0
    skipped = 0

    for f in findings:
        severity_raw = str(f.get("severity", "info")).lower()
        if severity_raw == "info":
            skipped += 1
            continue

        title = str(f.get("title") or f.get("name") or "Untitled finding")
        affected_asset = str(f.get("affected_asset") or f.get("resource") or f.get("url") or "")
        cve_list = f.get("cve") or []
        if isinstance(cve_list, str):
            cve_list = [cve_list]

        dedup = compute_dedup_hash(org_id, title, affected_asset, cve_list)

        existing = (
            await db.execute(select(Finding).where(Finding.org_id == org_id, Finding.dedup_hash == dedup))
        ).scalar_one_or_none()

        severity = _SEVERITY_MAP.get(severity_raw, FindingSeverity.INFO)
        evidence = f.get("evidence")
        if isinstance(evidence, str):
            evidence = {"raw": evidence}

        if existing is None:
            db.add(Finding(
                org_id=org_id,
                scan_job_id=None,
                source=source,
                source_scan_id=source_scan_id,
                title=title,
                description=str(f.get("description") or f.get("context") or ""),
                severity=severity,
                category=str(f.get("category") or ""),
                affected_asset=affected_asset,
                evidence=evidence,
                remediation=str(f.get("remediation") or ""),
                references=f.get("references") or [],
                cve=cve_list,
                cvss_score=f.get("cvss_score"),
                status=FindingStatus.OPEN,
                confidence=f.get("confidence"),
                kev_status=bool(f.get("kev_status", False)),
                epss_score=f.get("epss_score"),
                dedup_hash=dedup,
            ))
            inserted += 1
        else:
            # Refresh the mutable evidence trail on a rescan; don't touch
            # lifecycle fields (status/suppressed) the user may have set.
            existing.evidence = evidence
            existing.source_scan_id = source_scan_id
            if f.get("remediation"):
                existing.remediation = str(f.get("remediation"))
            if f.get("confidence"):
                existing.confidence = f.get("confidence")
            if f.get("cvss_score") is not None:
                existing.cvss_score = f.get("cvss_score")
            if f.get("epss_score") is not None:
                existing.epss_score = f.get("epss_score")
            if f.get("kev_status"):
                existing.kev_status = True
            updated += 1

    return {"inserted": inserted, "updated": updated, "skipped": skipped}
