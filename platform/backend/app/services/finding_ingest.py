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

import logging
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dedup import compute_dedup_hash
from app.models.db.finding import Finding, FindingSeverity, FindingStatus
from app.services.notification_service import dispatch_notifications

logger = logging.getLogger(__name__)

_NOTIFY_SEVERITIES = (FindingSeverity.CRITICAL, FindingSeverity.HIGH)

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
    newly_created_critical_high: list[Finding] = []

    # dedup_hash -> Finding object added earlier in *this* call. AsyncSessionLocal
    # is configured with autoflush=False (app.core.database), so a `db.add()`
    # from a few iterations ago is never visible to a later SELECT in the same
    # call — without this, two findings that share a dedup_hash (e.g. the same
    # pattern name matched at multiple lines in the same file, which is common:
    # js_scanner.py alone allows up to 5 per pattern per file) both pass the
    # "not found" check, both get added, and the flush/commit at the end of the
    # request then hits `uq_finding_org_dedup_hash` and crashes the whole scan.
    # This mirrors the same root cause already fixed once in scan_worker.py
    # (commit 5f0306b) for the core pipeline, applied here for every scanner
    # that goes through this shared helper.
    seen_this_call: dict[str, Finding] = {}

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

        existing = seen_this_call.get(dedup)
        if existing is None:
            existing = (
                await db.execute(select(Finding).where(Finding.org_id == org_id, Finding.dedup_hash == dedup))
            ).scalar_one_or_none()

        severity = _SEVERITY_MAP.get(severity_raw, FindingSeverity.INFO)
        evidence = f.get("evidence")
        if isinstance(evidence, str):
            evidence = {"raw": evidence}

        if existing is None:
            new_finding = Finding(
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
            )
            db.add(new_finding)
            seen_this_call[dedup] = new_finding
            inserted += 1
            if severity in _NOTIFY_SEVERITIES:
                newly_created_critical_high.append(new_finding)
        else:
            # Refresh the mutable evidence trail on a rescan; don't touch
            # lifecycle fields (status/suppressed) the user may have set.
            seen_this_call[dedup] = existing
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

    # Notify configured channels (Slack/Jira/Teams/webhooks) for every finding
    # that was NEWLY created (never for updates to an already-existing row via
    # the dedup upsert) with CRITICAL/HIGH severity. Mirrors the payload shape
    # of scan_worker.py's _async_notify_critical_findings for the core
    # pipeline. Flush first so the new rows have real DB-assigned ids to put
    # in the payload; never let a notification failure break ingestion.
    if newly_created_critical_high:
        try:
            await db.flush()
            for nf in newly_created_critical_high:
                try:
                    await dispatch_notifications(
                        org_id=str(org_id),
                        event_type="finding.critical",
                        payload={
                            "finding_id": str(nf.id),
                            "scan_id": source_scan_id,
                            "org_id": str(org_id),
                            "title": nf.title,
                            "severity": nf.severity.value,
                            "affected_asset": nf.affected_asset or "",
                        },
                        db_session=db,
                    )
                except Exception as exc:
                    logger.warning(
                        f"ingest_findings: dispatch_notifications failed for finding {nf.id} "
                        f"(source={source}): {exc}"
                    )
        except Exception as exc:
            logger.warning(
                f"ingest_findings: flush before notification dispatch failed (source={source}): {exc}"
            )

    return {"inserted": inserted, "updated": updated, "skipped": skipped}
