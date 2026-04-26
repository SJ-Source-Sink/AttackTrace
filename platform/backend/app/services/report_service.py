"""
Report generation service.
Builds HTML reports using AttackTrace's html_template and stores them.
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models.db.asset import Asset, AssetType
from app.models.db.finding import Finding, FindingSeverity
from app.models.db.scan import ScanJob, ScanStatus

logger = logging.getLogger(__name__)
settings = get_settings()


async def generate_report(
    db: AsyncSession,
    scan_job_id: UUID,
    org_id: UUID,
    report_format: str = "html",
    include_evidence: bool = True,
    requester_user_id: Optional[UUID] = None,
) -> dict:
    """
    Generate a security report for a completed scan.

    Returns:
        Dict with report metadata: id, path, url, format, generated_at, summary.
    """
    # Load scan job
    result = await db.execute(
        select(ScanJob).where(
            ScanJob.id == scan_job_id,
            ScanJob.org_id == org_id,
        )
    )
    job = result.scalar_one_or_none()
    if job is None:
        raise ValueError(f"Scan job {scan_job_id} not found")

    if job.status != ScanStatus.COMPLETED:
        raise ValueError(f"Cannot generate report for scan in status: {job.status.value}")

    # Load findings
    findings_result = await db.execute(
        select(Finding).where(Finding.scan_job_id == scan_job_id, Finding.org_id == org_id)
    )
    findings = findings_result.scalars().all()

    # Load assets
    assets_result = await db.execute(
        select(Asset).where(Asset.scan_job_id == scan_job_id, Asset.org_id == org_id)
    )
    assets = assets_result.scalars().all()

    # Try to use AttackTrace's HTML template if available
    report_path = None
    report_content = None

    try:
        report_content = _build_html_report(job, findings, assets, include_evidence)
    except Exception as e:
        logger.warning(f"Failed to use AttackTrace html_template: {e}. Using built-in template.")
        report_content = _build_fallback_html_report(job, findings, assets)

    # Save to disk
    report_dir = Path(settings.ATTACKTRACE_WORKSPACE_DIR) / "reports" / str(org_id)
    report_dir.mkdir(parents=True, exist_ok=True)
    report_filename = f"report_{scan_job_id}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.html"
    report_path = report_dir / report_filename

    await asyncio.to_thread(_write_file, report_path, report_content)

    summary = {
        "total_findings": len(findings),
        "by_severity": _count_by_severity(findings),
        "total_assets": len(assets),
        "by_asset_type": _count_by_type(assets),
    }

    return {
        "id": str(scan_job_id),
        "scan_job_id": str(scan_job_id),
        "path": str(report_path),
        "format": report_format,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "filename": report_filename,
    }


async def generate_pdf_report(
    db: AsyncSession,
    scan_job_id: str,
    org_id: UUID,
    workspace_dir: str,
) -> Path:
    """
    Generate a PDF report for a completed scan.

    Generates the HTML report first (if not already present), then converts it
    to PDF using weasyprint running in a thread pool to avoid blocking the event loop.

    Returns:
        Path to the generated PDF file.
    """
    # Resolve an existing HTML report or generate one
    report_dir = Path(workspace_dir) / "reports" / str(org_id)
    existing_html = sorted(
        report_dir.glob(f"report_{scan_job_id}_*.html"),
        key=lambda x: x.stat().st_mtime,
        reverse=True,
    ) if report_dir.exists() else []

    if existing_html and existing_html[0].stat().st_size > 0:
        html_path = existing_html[0]
    else:
        # Generate fresh HTML report
        report_meta = await generate_report(
            db=db,
            scan_job_id=UUID(scan_job_id),
            org_id=org_id,
            report_format="html",
            include_evidence=True,
        )
        html_path = Path(report_meta["path"])

    pdf_path = html_path.with_suffix(".pdf")

    if not pdf_path.exists() or pdf_path.stat().st_size == 0:
        def _generate_pdf() -> None:
            from weasyprint import HTML  # type: ignore[import]
            HTML(filename=str(html_path)).write_pdf(str(pdf_path))

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _generate_pdf)

    return pdf_path


def _write_file(path: Path, content: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _count_by_severity(findings) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        key = f.severity.value
        counts[key] = counts.get(key, 0) + 1
    return counts


def _count_by_type(assets) -> dict:
    counts: dict = {}
    for a in assets:
        key = a.asset_type.value
        counts[key] = counts.get(key, 0) + 1
    return counts


def _build_html_report(job: ScanJob, findings, assets, include_evidence: bool) -> str:
    """Attempt to use AttackTrace's native HTML template."""
    import sys

    # Add AttackTrace to path
    repo_path = Path(__file__).parents[5]
    if str(repo_path) not in sys.path:
        sys.path.insert(0, str(repo_path))

    from attacktrace.reporting.html_template import HTMLReporter
    from attacktrace.core.models import ScanSession, ScanStatus as AttackTraceStatus, Finding as AttackTraceFinding, Severity

    # Build a minimal ScanSession from our DB data
    session = ScanSession(
        id=str(job.id),
        target_company=job.company_name or "",
        target_domains=job.target_domains or [],
        status=AttackTraceStatus.COMPLETED,
    )

    # Map findings
    for f in findings:
        if not include_evidence and f.severity.value == "info":
            continue
        try:
            at_finding = AttackTraceFinding(
                title=f.title,
                description=f.description,
                severity=Severity(f.severity.value),
                category=f.category,
                affected_asset=f.affected_asset,
                remediation=f.remediation,
                cve=f.cve or [],
                cvss_score=f.cvss_score,
            )
            session.findings.append(at_finding)
        except Exception:
            pass

    session.update_statistics()

    reporter = HTMLReporter()
    return reporter.generate(session)


def _build_fallback_html_report(job: ScanJob, findings, assets) -> str:
    """Built-in HTML report template as fallback."""
    fc = job.findings_count or {}
    rs = job.results_summary or {}

    severity_colors = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#d97706",
        "low": "#2563eb",
        "info": "#6b7280",
    }

    findings_html = ""
    for f in sorted(findings, key=lambda x: ["critical", "high", "medium", "low", "info"].index(x.severity.value)):
        color = severity_colors.get(f.severity.value, "#6b7280")
        cves = escape(", ".join(f.cve)) if f.cve else "N/A"
        cvss = f"{f.cvss_score:.1f}" if f.cvss_score else "N/A"
        evidence_json = escape(json.dumps(f.evidence or {}, indent=2)) if f.evidence else "N/A"
        findings_html += f"""
        <div class="finding" style="border-left: 4px solid {color}; padding: 16px; margin: 12px 0; background: #f9fafb; border-radius: 4px;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <h3 style="margin:0; font-size:16px;">{escape(f.title or "")}</h3>
            <span style="background:{color}; color:white; padding:2px 10px; border-radius:12px; font-size:12px; font-weight:bold;">
              {escape(f.severity.value.upper())}
            </span>
          </div>
          <p style="color:#6b7280; margin:4px 0; font-size:13px;">
            {escape(f.category or "")} | Affected: {escape(f.affected_asset or "")} | CVE: {cves} | CVSS: {cvss}
          </p>
          <p style="margin:8px 0;">{escape(f.description or "")}</p>
          <p><strong>Remediation:</strong> {escape(f.remediation or "")}</p>
          <pre style="background:#1f2937; color:#e5e7eb; padding:12px; border-radius:4px; font-size:12px; overflow:auto;">{evidence_json}</pre>
        </div>"""

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    domains = ", ".join(job.target_domains or [])
    total_findings = len(findings)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AttackTrace Security Report - {domains}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background:#fff; color:#111827; }}
    .header {{ background: linear-gradient(135deg, #1e3a5f, #0f2540); color:white; padding:40px; }}
    .header h1 {{ font-size:28px; font-weight:700; }}
    .header .meta {{ margin-top:8px; opacity:0.8; font-size:14px; }}
    .container {{ max-width:1200px; margin:0 auto; padding:32px; }}
    .stats {{ display:grid; grid-template-columns:repeat(5,1fr); gap:16px; margin:24px 0; }}
    .stat-card {{ background:#f9fafb; border:1px solid #e5e7eb; border-radius:8px; padding:16px; text-align:center; }}
    .stat-card .number {{ font-size:32px; font-weight:700; }}
    .stat-card .label {{ font-size:13px; color:#6b7280; margin-top:4px; }}
    .section {{ margin:32px 0; }}
    .section h2 {{ font-size:20px; font-weight:600; margin-bottom:16px; padding-bottom:8px; border-bottom:2px solid #e5e7eb; }}
    .footer {{ text-align:center; padding:24px; color:#9ca3af; font-size:13px; border-top:1px solid #e5e7eb; }}
  </style>
</head>
<body>
  <div class="header">
    <h1>AttackTrace External Attack Surface Report</h1>
    <div class="meta">
      Target: {domains} | Company: {job.company_name or 'N/A'} | Generated: {now} | Scan ID: {job.id}
    </div>
  </div>
  <div class="container">
    <div class="section">
      <h2>Executive Summary</h2>
      <p>This report presents the results of an external attack surface discovery scan
      targeting <strong>{domains}</strong>. The scan discovered
      <strong>{rs.get('total_assets', len(assets))}</strong> assets and
      identified <strong>{total_findings}</strong> security findings.</p>
    </div>
    <div class="section">
      <h2>Findings by Severity</h2>
      <div class="stats">
        <div class="stat-card">
          <div class="number" style="color:#dc2626;">{fc.get('critical', 0)}</div>
          <div class="label">Critical</div>
        </div>
        <div class="stat-card">
          <div class="number" style="color:#ea580c;">{fc.get('high', 0)}</div>
          <div class="label">High</div>
        </div>
        <div class="stat-card">
          <div class="number" style="color:#d97706;">{fc.get('medium', 0)}</div>
          <div class="label">Medium</div>
        </div>
        <div class="stat-card">
          <div class="number" style="color:#2563eb;">{fc.get('low', 0)}</div>
          <div class="label">Low</div>
        </div>
        <div class="stat-card">
          <div class="number" style="color:#6b7280;">{fc.get('info', 0)}</div>
          <div class="label">Info</div>
        </div>
      </div>
    </div>
    <div class="section">
      <h2>Security Findings ({total_findings})</h2>
      {findings_html if findings_html else '<p style="color:#6b7280;">No findings recorded.</p>'}
    </div>
  </div>
  <div class="footer">
    Generated by AttackTrace | {now}
  </div>
</body>
</html>"""
