"""
Report generation service.
Builds a professional security-assessment HTML/PDF report from a scan's
findings and assets.
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


async def _load_scan_context(db: AsyncSession, scan_job_id: UUID, org_id: UUID):
    """Resolve a report target to either an orchestrated ScanJob (the main
    scan pipeline) or a standalone scanner run (cspm/secrets/supply_chain/
    container_scanner/firewall_physical/exposure_scanner/mcp_scanner/
    takeover/email_security) — those write findings with scan_job_id=None
    and source_scan_id=<their own scan id> instead of a ScanJob row, so a
    report for one of those ids previously always 404'd or came back empty.

    Returns (job_or_none, findings, assets, target_domains, company_name).
    Raises ValueError if nothing in this org matches scan_job_id at all.
    """
    job_result = await db.execute(
        select(ScanJob).where(ScanJob.id == scan_job_id, ScanJob.org_id == org_id)
    )
    job = job_result.scalar_one_or_none()

    if job is not None:
        if job.status != ScanStatus.COMPLETED:
            raise ValueError(f"Cannot generate report for scan in status: {job.status.value}")

        findings_result = await db.execute(
            select(Finding).where(Finding.scan_job_id == scan_job_id, Finding.org_id == org_id)
        )
        findings = findings_result.scalars().all()

        assets_result = await db.execute(
            select(Asset).where(Asset.scan_job_id == scan_job_id, Asset.org_id == org_id)
        )
        assets = assets_result.scalars().all()

        return job, findings, assets, (job.target_domains or []), job.company_name

    # Not an orchestrated scan — look for a standalone-scanner run tagged
    # with this id via source_scan_id.
    findings_result = await db.execute(
        select(Finding).where(Finding.source_scan_id == str(scan_job_id), Finding.org_id == org_id)
    )
    findings = findings_result.scalars().all()
    if not findings:
        raise ValueError(f"Scan {scan_job_id} not found")

    target_domains = sorted({f.affected_asset for f in findings if f.affected_asset})[:10]
    return None, findings, [], target_domains, None


async def scan_id_belongs_to_org(db: AsyncSession, scan_job_id: UUID, org_id: UUID) -> bool:
    """Ownership check for the report download routes — true if scan_job_id
    is either a ScanJob or a standalone-scanner source_scan_id in this org."""
    job = (await db.execute(
        select(ScanJob.id).where(ScanJob.id == scan_job_id, ScanJob.org_id == org_id)
    )).scalar_one_or_none()
    if job is not None:
        return True
    finding = (await db.execute(
        select(Finding.id).where(Finding.source_scan_id == str(scan_job_id), Finding.org_id == org_id).limit(1)
    )).scalar_one_or_none()
    return finding is not None


async def generate_report(
    db: AsyncSession,
    scan_job_id: UUID,
    org_id: UUID,
    report_format: str = "html",
    include_evidence: bool = True,
    requester_user_id: Optional[UUID] = None,
) -> dict:
    """
    Generate a security report for a completed scan (orchestrated ScanJob
    or a standalone scanner run — see _load_scan_context).

    Returns:
        Dict with report metadata: id, path, url, format, generated_at, summary.
    """
    job, findings, assets, target_domains, company_name = await _load_scan_context(db, scan_job_id, org_id)

    if not include_evidence:
        findings = [f for f in findings if f.severity.value != "info"]

    report_content = _build_html_report(scan_job_id, target_domains, company_name, findings, assets, job)

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
            # filename= (not string=) — the report template references no
            # external resources, so no url_fetcher is needed to block SSRF
            # here (contrast compliance.py, which does need one).
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


_SOURCE_LABELS = {
    "attacktrace": "Core Scan Pipeline",
    "cspm": "Cloud Security Posture Management",
    "secrets": "Secret Scanner",
    "supply_chain": "Supply Chain Scanner",
    "container_scanner": "Container/Kubernetes Scanner",
    "firewall_physical": "Physical Firewall Scanner",
    "exposure_scanner": "Exposure Scanner",
    "mcp_scanner": "MCP Scanner",
    "takeover": "Subdomain Takeover Scanner",
    "email_security": "Email Security Scanner",
    "msra": "Mobile Scanner",
    "attack_suite_agent": "Attack Suite AI Agent",
}

_SOURCE_METHODOLOGY = {
    "attacktrace": "Automated reconnaissance, subdomain/asset enumeration, port and service scanning, and vulnerability pattern matching against discovered assets.",
    "cspm": "API-based configuration review of cloud provider resources (identity, storage, network, compute) against security benchmarks.",
    "secrets": "Pattern- and entropy-based scanning of web content, JavaScript bundles, and git history for hardcoded credentials and API keys.",
    "supply_chain": "Dependency manifest analysis against known-vulnerability databases (OSV) with CVSS/EPSS/KEV enrichment.",
    "container_scanner": "Image and manifest analysis for vulnerable base layers, exposed secrets, and Kubernetes misconfiguration.",
    "firewall_physical": "Active fingerprinting of perimeter firewall/VPN appliances against known CVEs and default-credential exposure.",
    "exposure_scanner": "Targeted probing for publicly exposed administrative interfaces, debug endpoints, and sensitive files.",
    "mcp_scanner": "Protocol-level testing of Model Context Protocol servers for authentication and tool-execution weaknesses.",
    "takeover": "DNS/CNAME analysis correlated against fingerprints of services vulnerable to subdomain takeover.",
    "email_security": "DNS record analysis of SPF, DKIM, and DMARC configuration for email spoofing exposure.",
    "msra": "Static and dynamic analysis of mobile application binaries and API traffic.",
    "attack_suite_agent": "Autonomous, tool-using AI agent testing grounded in enumerated assets, restricted to in-scope targets.",
}

_CONFIDENCE_LABELS = {
    "certain": ("Certain", "#059669", "Proof-based — directly confirmed (e.g. out-of-band callback, extracted data, API-confirmed state)."),
    "high": ("High", "#2563eb", "Strong corroborating signal from two or more independent checks."),
    "medium": ("Medium", "#d97706", "A single differential or control-comparison signal — plausible but not independently confirmed."),
    "low": ("Low", "#6b7280", "A single weak or heuristic signal (e.g. timing, pattern match) — recommend manual verification."),
}

_SEVERITY_DEFINITIONS = [
    ("Critical", "#dc2626", "Immediate, severe business impact — remote code execution, full authentication bypass, or mass exposure of sensitive data. Requires emergency remediation."),
    ("High", "#ea580c", "Significant impact requiring prompt remediation — session hijacking, sensitive data exposure, or privilege escalation under realistic conditions."),
    ("Medium", "#d97706", "Moderate impact, often requiring specific conditions or user interaction to exploit — e.g. reflected injection, information disclosure."),
    ("Low", "#2563eb", "Minor impact or defense-in-depth weakness — e.g. missing security headers, verbose error messages."),
    ("Info", "#6b7280", "Informational observation with no direct exploitability, included for completeness."),
]

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_SEVERITY_COLORS = {
    "critical": "#dc2626", "high": "#ea580c", "medium": "#d97706", "low": "#2563eb", "info": "#6b7280",
}
_SEVERITY_BG = {
    "critical": "#fef2f2", "high": "#fff7ed", "medium": "#fffbeb", "low": "#eff6ff", "info": "#f9fafb",
}


def _overall_risk_rating(by_severity: dict) -> tuple[str, str]:
    """A single-glance risk rating for the executive summary, driven purely
    by the presence of the most severe open finding — matches the standard
    convention in professional vulnerability assessment reports."""
    if by_severity.get("critical", 0) > 0:
        return "Critical", "#dc2626"
    if by_severity.get("high", 0) > 0:
        return "High", "#ea580c"
    if by_severity.get("medium", 0) > 0:
        return "Medium", "#d97706"
    if by_severity.get("low", 0) > 0:
        return "Low", "#2563eb"
    return "Minimal", "#059669"


def _truncate(value: str, max_len: int = 70) -> str:
    """For compact summary tables only — some scanners record a full URL
    (with query string/tokens) as affected_asset rather than a bare host, and
    an untruncated value there can balloon a summary table across pages.
    Full-length values are always still shown in the per-finding detail."""
    return value if len(value) <= max_len else value[: max_len - 1] + "…"


def _render_evidence(evidence: Optional[dict]) -> str:
    """Flat dicts of primitives render as a clean key/value table; anything
    nested or absent falls back to a formatted JSON block."""
    if not evidence:
        return '<p class="muted">No structured evidence recorded.</p>'
    is_flat = isinstance(evidence, dict) and all(
        not isinstance(v, (dict, list)) or v in ([], {}) for v in evidence.values()
    )
    if is_flat:
        rows = "".join(
            f'<tr><td class="ev-key">{escape(str(k))}</td><td class="ev-val">{escape(str(v))}</td></tr>'
            for k, v in evidence.items() if v not in (None, "", [], {})
        )
        if rows:
            return f'<table class="evidence-table">{rows}</table>'
    return f'<pre class="evidence-json">{escape(json.dumps(evidence, indent=2, default=str))}</pre>'


def _build_html_report(
    scan_job_id: UUID, target_domains: list[str], company_name: Optional[str],
    findings, assets, job=None,
) -> str:
    """Build a professional, detailed HTML security-assessment report.
    Severity counts are computed directly from the findings actually being
    rendered (not a separately cached ScanJob field) so the summary can
    never drift from what's shown below it."""
    by_severity = _count_by_severity(findings)
    total_findings = len(findings)
    total_assets = len(assets)
    risk_label, risk_color = _overall_risk_rating(by_severity)
    now = datetime.now(timezone.utc)
    now_str = now.strftime("%B %d, %Y at %H:%M UTC")
    domains = ", ".join(target_domains) if target_domains else "N/A"
    domains_title = target_domains[0] if target_domains else "Assessment"

    # --- Aggregates for the risk-overview section -------------------------
    findings_with_cve = [f for f in findings if f.cve]
    kev_findings = [f for f in findings if f.kev_status]
    cvss_scores = [f.cvss_score for f in findings if f.cvss_score is not None]
    avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else None

    asset_hit_counts: dict[str, int] = {}
    for f in findings:
        if f.affected_asset:
            asset_hit_counts[f.affected_asset] = asset_hit_counts.get(f.affected_asset, 0) + 1
    top_assets = sorted(asset_hit_counts.items(), key=lambda kv: -kv[1])[:5]

    sources_used = sorted({f.source or "attacktrace" for f in findings})

    # --- Top remediation priorities ------------------------------------
    # A mature security report doesn't just list every finding by raw
    # severity — it tells the reader where to start. Rank across ALL open
    # findings (not just critical/high) by the same urgency signal used for
    # in-tier ordering below: actively-exploited-in-the-wild (KEV) first,
    # then exploitation probability (EPSS), then CVSS, then severity rank —
    # so a KEV-listed HIGH can rank above a CRITICAL with no known exploit.
    _sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    _open_findings = [f for f in findings if f.status.value != "false_positive"]
    top_priority_findings = sorted(
        _open_findings,
        key=lambda f: (
            not f.kev_status, -(f.epss_score or 0.0), -(f.cvss_score or 0.0),
            -_sev_rank.get(f.severity.value, 0),
        ),
    )[:3]

    # --- Scope & methodology ------------------------------------------------
    scan_meta_rows = f"""
      <tr><td>Scan ID</td><td><code>{scan_job_id}</code></td></tr>
      <tr><td>Target(s)</td><td>{escape(domains)}</td></tr>
      <tr><td>Organization</td><td>{escape(company_name or "N/A")}</td></tr>
    """
    if job is not None:
        started = job.started_at.strftime("%Y-%m-%d %H:%M UTC") if job.started_at else "N/A"
        completed = job.completed_at.strftime("%Y-%m-%d %H:%M UTC") if job.completed_at else "N/A"
        scan_meta_rows += f"""
      <tr><td>Scan Intensity</td><td>{escape(str(job.intensity.value if hasattr(job.intensity, "value") else job.intensity))}</td></tr>
      <tr><td>Started</td><td>{started}</td></tr>
      <tr><td>Completed</td><td>{completed}</td></tr>
        """

    methodology_html = "".join(
        f'<li><strong>{escape(_SOURCE_LABELS.get(s, s))}:</strong> {escape(_SOURCE_METHODOLOGY.get(s, "Automated security testing specific to this asset class."))}</li>'
        for s in sources_used
    ) or "<li>No scanner sources recorded.</li>"

    asset_type_counts = _count_by_type(assets)
    asset_type_rows = "".join(
        f'<tr><td>{escape(t.replace("_", " ").title())}</td><td class="num">{c}</td></tr>'
        for t, c in sorted(asset_type_counts.items(), key=lambda kv: -kv[1])
    ) or '<tr><td colspan="2" class="muted">No assets recorded for this scan.</td></tr>'

    top_assets_rows = "".join(
        f'<tr><td title="{escape(a)}">{escape(_truncate(a))}</td><td class="num" style="width:50px;">{c}</td></tr>'
        for a, c in top_assets
    ) or '<tr><td colspan="2" class="muted">N/A</td></tr>'

    # --- Table of contents ---------------------------------------------------
    toc_items = [
        ("exec-summary", "Executive Summary"),
        ("risk-overview", "Risk Overview"),
        ("scope", "Scope & Methodology"),
        ("asset-inventory", "Asset Inventory"),
        ("findings", f"Detailed Findings ({total_findings})"),
        ("appendix", "Appendix: Severity & Confidence Ratings"),
    ]
    toc_html = "".join(f'<li><a href="#{tid}">{escape(label)}</a></li>' for tid, label in toc_items)

    # --- Findings, grouped by severity ---------------------------------------
    findings_html = ""
    finding_index = 0
    for sev in _SEVERITY_ORDER:
        sev_findings = [f for f in findings if f.severity.value == sev]
        if not sev_findings:
            continue
        # Within a severity tier, surface the most urgent findings first:
        # actively-exploited-in-the-wild (CISA KEV) outranks everything,
        # then higher exploitation-probability (EPSS), then higher CVSS.
        # Two CRITICAL findings are not equally urgent if only one is a
        # known, weaponized exploit — severity alone shouldn't decide
        # reading order (industry best practice per CVSS+EPSS+KEV
        # prioritization guidance).
        sev_findings.sort(
            key=lambda f: (not f.kev_status, -(f.epss_score or 0.0), -(f.cvss_score or 0.0))
        )
        color = _SEVERITY_COLORS[sev]
        findings_html += f'<h3 class="sev-group-header" style="color:{color};">{sev.upper()} <span class="muted">({len(sev_findings)})</span></h3>'
        for f in sev_findings:
            finding_index += 1
            fid = f"F-{finding_index:03d}"
            cves = f.cve or []
            cve_badges = "".join(f'<span class="badge badge-cve">{escape(c)}</span>' for c in cves) or '<span class="muted">None</span>'
            cvss = f"{f.cvss_score:.1f}" if f.cvss_score is not None else "N/A"
            epss = f"{f.epss_score * 100:.1f}%" if f.epss_score is not None else "N/A"
            kev_badge = '<span class="badge badge-kev">CISA KEV</span>' if f.kev_status else ""
            conf_key = (f.confidence or "").lower()
            conf_label, conf_color, conf_tooltip = _CONFIDENCE_LABELS.get(conf_key, (f.confidence or "N/A", "#6b7280", ""))
            source_label = escape(_SOURCE_LABELS.get(f.source, f.source or "AttackTrace"))
            refs_html = ""
            if f.references:
                refs_html = '<div class="finding-block"><strong>References</strong><ul class="ref-list">' + "".join(
                    f'<li>{escape(r)}</li>' for r in f.references
                ) + "</ul></div>"

            findings_html += f"""
        <div class="finding" id="finding-{finding_index}" style="border-left-color:{color}; background:{_SEVERITY_BG[sev]};">
          <div class="finding-header">
            <div>
              <span class="finding-id">{fid}</span>
              <h4>{escape(f.title or "Untitled finding")}</h4>
            </div>
            <span class="badge" style="background:{color};">{sev.upper()}</span>
          </div>
          <div class="finding-meta">
            <span><strong>Asset:</strong> {escape(f.affected_asset or "N/A")}</span>
            <span><strong>Category:</strong> {escape(f.category or "N/A")}</span>
            <span><strong>Source:</strong> {source_label}</span>
            <span><strong>Status:</strong> {escape(f.status.value if f.status else "open").replace("_", " ").title()}</span>
          </div>
          <div class="finding-metrics">
            <span><strong>CVSS:</strong> {cvss}</span>
            <span><strong>EPSS:</strong> {epss}</span>
            <span title="{escape(conf_tooltip)}"><strong>Confidence:</strong> <span style="color:{conf_color}; font-weight:600;">{escape(conf_label)}</span></span>
            {kev_badge}
          </div>
          <div class="finding-block"><strong>CVE(s):</strong> {cve_badges}</div>
          <div class="finding-block">
            <strong>Description</strong>
            <p>{escape(f.description or "No description provided.")}</p>
          </div>
          <div class="finding-block remediation">
            <strong>Remediation</strong>
            <p>{escape(f.remediation or "No remediation guidance recorded for this finding.")}</p>
          </div>
          <div class="finding-block">
            <strong>Evidence</strong>
            {_render_evidence(f.evidence)}
          </div>
          {refs_html}
        </div>"""

    if not findings_html:
        findings_html = '<p class="muted">No findings were recorded for this scan.</p>'

    severity_def_rows = "".join(
        f'<tr><td style="width:110px;"><span class="badge" style="background:{c};">{lbl.upper()}</span></td><td>{escape(desc)}</td></tr>'
        for lbl, c, desc in _SEVERITY_DEFINITIONS
    )
    confidence_def_rows = "".join(
        f'<tr><td style="width:110px;"><span style="color:{c}; font-weight:600;">{escape(lbl)}</span></td><td>{escape(desc)}</td></tr>'
        for lbl, c, desc in _CONFIDENCE_LABELS.values()
    )

    avg_cvss_str = f"{avg_cvss:.1f}" if avg_cvss is not None else "N/A"

    def _priority_reason(f) -> str:
        if f.kev_status:
            return "actively exploited in the wild (CISA KEV)"
        if f.epss_score and f.epss_score >= 0.1:
            return f"{f.epss_score * 100:.0f}% predicted exploitation probability (EPSS)"
        if f.cvss_score:
            return f"CVSS {f.cvss_score:.1f}"
        return f"{f.severity.value.upper()} severity"

    top_priorities_html = "".join(
        f"""<li><strong>{escape(f.title or "Untitled finding")}</strong>
            <span class="muted"> — {escape(f.affected_asset or "N/A")} ({_priority_reason(f)})</span>
            {f'<div class="priority-impact">{escape(f.ai_business_impact)}</div>' if getattr(f, "ai_business_impact", None) else ""}
        </li>"""
        for f in top_priority_findings
    ) if top_priority_findings else "<li class=\"muted\">No open findings to prioritize.</li>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Assessment Report — {escape(domains_title)}</title>
  <style>
    @page {{
      size: A4;
      margin: 22mm 16mm 20mm 16mm;
      @bottom-center {{ content: "Page " counter(page) " of " counter(pages); font-size: 9px; color: #9ca3af; }}
      @top-right {{ content: "CONFIDENTIAL"; font-size: 8px; color: #d1d5db; letter-spacing: 1px; }}
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; color:#111827; font-size: 13px; line-height: 1.55; }}
    a {{ color: #1d4ed8; }}
    code {{ font-family: 'SF Mono', Menlo, Consolas, monospace; font-size: 0.92em; background:#f3f4f6; padding: 1px 5px; border-radius: 3px; }}
    .muted {{ color: #9ca3af; }}

    /* Cover page */
    .cover {{ min-height: 235mm; display:flex; flex-direction:column; justify-content:center; page-break-after: always; }}
    .cover .eyebrow {{ color:#60a5fa; font-weight:700; letter-spacing:2px; font-size:12px; text-transform:uppercase; }}
    .cover h1 {{ font-size:36px; font-weight:800; margin-top:14px; color:#0f172a; }}
    .cover .subtitle {{ font-size:18px; color:#475569; margin-top:10px; }}
    .cover .cover-meta {{ margin-top:48px; border-top:1px solid #e2e8f0; padding-top:24px; }}
    .cover .cover-meta div {{ display:flex; justify-content:space-between; padding:6px 0; border-bottom:1px dotted #e2e8f0; max-width: 420px; }}
    .cover .cover-meta span:first-child {{ color:#64748b; }}
    .cover .cover-meta span:last-child {{ font-weight:600; }}
    .cover .risk-chip {{ display:inline-block; margin-top:28px; padding:8px 18px; border-radius:24px; color:white; font-weight:700; font-size:14px; letter-spacing:0.5px; }}
    .cover .confidential {{ margin-top:auto; padding-top: 40px; font-size:11px; color:#94a3b8; max-width: 480px; }}

    /* Table of contents */
    .toc {{ page-break-after: always; }}
    .toc h2 {{ font-size:22px; margin-bottom:20px; }}
    .toc ol {{ list-style:none; counter-reset: toc; }}
    .toc li {{ counter-increment: toc; padding:10px 0; border-bottom:1px solid #f1f5f9; font-size:15px; }}
    .toc li::before {{ content: counter(toc) ". "; color:#94a3b8; font-weight:700; margin-right:6px; }}
    .toc a {{ text-decoration:none; color:#111827; }}

    .section {{ margin: 26px 0; }}
    .section h2 {{ font-size:19px; font-weight:700; margin-bottom:14px; padding-bottom:8px; border-bottom:2px solid #e5e7eb; color:#0f172a; }}
    .section h3 {{ font-size:15px; font-weight:700; margin: 18px 0 8px; }}
    .section p {{ margin: 8px 0; }}

    .stats {{ display:grid; grid-template-columns:repeat(5,1fr); gap:12px; margin:18px 0; }}
    .stat-card {{ background:#f9fafb; border:1px solid #e5e7eb; border-radius:8px; padding:14px 8px; text-align:center; }}
    .stat-card .number {{ font-size:26px; font-weight:800; }}
    .stat-card .label {{ font-size:11px; color:#6b7280; margin-top:2px; text-transform:uppercase; letter-spacing:0.5px; }}

    .priority-list {{ margin:10px 0 0 0; padding-left:22px; }}
    .priority-list li {{ margin-bottom:10px; line-height:1.5; }}
    .priority-impact {{ font-size:12px; color:#4b5563; margin-top:2px; font-style:italic; }}

    table {{ width:100%; border-collapse:collapse; font-size:12.5px; }}
    table.meta-table td {{ padding:6px 4px; border-bottom:1px solid #f1f5f9; }}
    table.meta-table td:first-child {{ color:#6b7280; width:35%; }}
    table.stat-list {{ width:100%; table-layout:fixed; }}
    table.stat-list td {{ padding:9px 0; border-bottom:1px solid #f1f5f9; white-space:nowrap; }}
    table.stat-list td.stat-list-label {{ color:#6b7280; width:65%; }}
    table.stat-list td.stat-list-value {{ font-weight:700; text-align:right; width:35%; }}
    table.data-table {{ table-layout:fixed; }}
    table.data-table th, table.data-table td {{ text-align:left; padding:8px 10px; border-bottom:1px solid #f1f5f9; overflow-wrap:anywhere; word-break:break-word; }}
    table.data-table th {{ background:#f8fafc; font-size:11px; text-transform:uppercase; letter-spacing:0.4px; color:#64748b; }}
    table.data-table td.num {{ text-align:right; font-variant-numeric: tabular-nums; }}
    .two-col {{ display:table; width:100%; table-layout:fixed; }}
    .two-col > div {{ display:table-cell; width:50%; vertical-align:top; padding-right:24px; }}
    .two-col > div:last-child {{ padding-right:0; padding-left:24px; }}

    ul.methodology {{ padding-left: 18px; }}
    ul.methodology li {{ margin: 6px 0; }}

    /* Findings */
    .sev-group-header {{ margin-top:22px; page-break-after: avoid; }}
    .finding {{ border-left: 4px solid; border-radius: 6px; padding: 14px 16px; margin: 12px 0; page-break-inside: avoid; }}
    .finding-header {{ display:flex; justify-content:space-between; align-items:flex-start; gap:10px; }}
    .finding-header h4 {{ font-size:14.5px; display:inline; margin-left:6px; }}
    .finding-id {{ font-family: monospace; font-size:11px; color:#6b7280; }}
    .finding-meta, .finding-metrics {{ display:flex; flex-wrap:wrap; gap:14px; font-size:11.5px; color:#4b5563; margin-top:8px; }}
    .finding-block {{ margin-top:10px; }}
    .finding-block.remediation {{ background: rgba(5,150,105,0.06); border-left: 3px solid #059669; padding: 8px 10px; border-radius: 4px; }}
    .badge {{ display:inline-block; color:white; padding:2px 9px; border-radius:10px; font-size:10.5px; font-weight:700; letter-spacing:0.3px; }}
    .badge-cve {{ background:#4338ca; margin: 2px 4px 2px 0; }}
    .badge-kev {{ background:#b91c1c; }}
    .ref-list {{ padding-left:18px; font-size:12px; }}
    .evidence-table td {{ padding:5px 8px; border-bottom:1px solid #f1f5f9; font-size:12px; }}
    .evidence-table .ev-key {{ color:#6b7280; width:35%; font-family:monospace; }}
    .evidence-json {{ background:#0f172a; color:#e2e8f0; padding:12px; border-radius:6px; font-size:11px; overflow:auto; white-space:pre-wrap; word-break:break-word; }}

    .footer {{ text-align:center; padding:20px; color:#9ca3af; font-size:11px; border-top:1px solid #e5e7eb; margin-top: 30px; }}
  </style>
</head>
<body>

  <!-- Cover page -->
  <div class="cover">
    <div class="eyebrow">AttackTrace &middot; Security Assessment</div>
    <h1>Security Assessment Report</h1>
    <div class="subtitle">{escape(domains_title)}{f" &mdash; {escape(company_name)}" if company_name else ""}</div>
    <span class="risk-chip" style="background:{risk_color};">Overall Risk: {risk_label.upper()}</span>
    <div class="cover-meta">
      <div><span>Target(s)</span><span>{escape(domains)}</span></div>
      <div><span>Report Generated</span><span>{now_str}</span></div>
      <div><span>Total Findings</span><span>{total_findings}</span></div>
      <div><span>Assets Assessed</span><span>{total_assets}</span></div>
      <div><span>Scan ID</span><span>{scan_job_id}</span></div>
    </div>
    <div class="confidential">
      This report contains confidential security information intended solely for the recipient
      organization. It should be handled in accordance with your organization's data classification
      policy and shared only with authorized personnel on a need-to-know basis.
    </div>
  </div>

  <!-- Table of contents -->
  <div class="toc">
    <h2>Table of Contents</h2>
    <ol>{toc_html}</ol>
  </div>

  <div class="section" id="exec-summary">
    <h2>Executive Summary</h2>
    <p>
      This report presents the results of an automated security assessment of
      <strong>{escape(domains)}</strong>, during which <strong>{total_findings}</strong> finding(s)
      were identified across <strong>{total_assets}</strong> discovered asset(s). Based on the
      severity of the most significant issues identified, the overall risk posture of this
      target is assessed as <strong style="color:{risk_color};">{risk_label}</strong>.
    </p>
    <p>
      {f"{by_severity.get('critical', 0)} critical and {by_severity.get('high', 0)} high severity finding(s) were identified and should be prioritized for immediate remediation. " if (by_severity.get('critical', 0) or by_severity.get('high', 0)) else "No critical or high severity findings were identified during this assessment. "}
      {f"{len(kev_findings)} finding(s) correspond to vulnerabilities in CISA's Known Exploited Vulnerabilities (KEV) catalog and represent active, real-world exploitation risk. " if kev_findings else ""}
      Detailed findings, evidence, and remediation guidance for every issue are provided in the
      <a href="#findings">Detailed Findings</a> section of this report.
    </p>
    <div class="stats">
      <div class="stat-card"><div class="number" style="color:{_SEVERITY_COLORS['critical']};">{by_severity.get('critical', 0)}</div><div class="label">Critical</div></div>
      <div class="stat-card"><div class="number" style="color:{_SEVERITY_COLORS['high']};">{by_severity.get('high', 0)}</div><div class="label">High</div></div>
      <div class="stat-card"><div class="number" style="color:{_SEVERITY_COLORS['medium']};">{by_severity.get('medium', 0)}</div><div class="label">Medium</div></div>
      <div class="stat-card"><div class="number" style="color:{_SEVERITY_COLORS['low']};">{by_severity.get('low', 0)}</div><div class="label">Low</div></div>
      <div class="stat-card"><div class="number" style="color:{_SEVERITY_COLORS['info']};">{by_severity.get('info', 0)}</div><div class="label">Info</div></div>
    </div>
    <h3 style="margin-top:24px;">Top Remediation Priorities</h3>
    <p class="muted" style="margin-top:-8px;">Ranked by real-world exploitability (active exploitation, then predicted exploitation probability, then technical severity) — not raw severity alone, since not every CRITICAL finding carries the same actual risk.</p>
    <ol class="priority-list">{top_priorities_html}</ol>
  </div>

  <div class="section" id="risk-overview">
    <h2>Risk Overview</h2>
    <div class="two-col">
      <div>
        <table class="stat-list">
          <tr><td class="stat-list-label">Has a CVE</td><td class="stat-list-value">{len(findings_with_cve)} / {total_findings}</td></tr>
          <tr><td class="stat-list-label">In CISA KEV</td><td class="stat-list-value">{len(kev_findings)}</td></tr>
          <tr><td class="stat-list-label">Avg CVSS</td><td class="stat-list-value">{avg_cvss_str}</td></tr>
        </table>
      </div>
      <div>
        <h3 style="margin-top:0;">Most-Affected Assets</h3>
        <table class="data-table"><tbody>{top_assets_rows}</tbody></table>
      </div>
    </div>
  </div>

  <div class="section" id="scope">
    <h2>Scope &amp; Methodology</h2>
    <table class="meta-table">{scan_meta_rows}</table>
    <h3>Testing Methodology</h3>
    <ul class="methodology">{methodology_html}</ul>
  </div>

  <div class="section" id="asset-inventory">
    <h2>Asset Inventory</h2>
    <p>{total_assets} asset(s) were discovered and assessed during this scan.</p>
    <table class="data-table">
      <thead><tr><th>Asset Type</th><th style="text-align:right;">Count</th></tr></thead>
      <tbody>{asset_type_rows}</tbody>
    </table>
  </div>

  <div class="section" id="findings">
    <h2>Detailed Findings ({total_findings})</h2>
    {findings_html}
  </div>

  <div class="section" id="appendix">
    <h2>Appendix: Severity &amp; Confidence Ratings</h2>
    <h3>Severity Ratings</h3>
    <table class="data-table">{severity_def_rows}</table>
    <h3>Confidence Ratings</h3>
    <p class="muted" style="margin-bottom:8px;">Confidence reflects how the finding was confirmed, not its severity — a low-confidence finding may still be high severity if true.</p>
    <table class="data-table">{confidence_def_rows}</table>
  </div>

  <div class="footer">
    Generated by AttackTrace on {now_str} &middot; This report is confidential and intended for authorized recipients only.
  </div>
</body>
</html>"""
