"""
Compliance Evidence Export API — AttackTrace
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Maps an org's open findings to SOC2 / PCI-DSS / ISO 27001 controls (via the same
CWE inference already used by the MITRE ATT&CK mapper) and generates an
auditor-facing evidence bundle (PDF + CSV) — control-by-control pass/fail with
the specific findings that failed it.

This does not itself constitute certification or a formal audit; it packages
existing scan evidence into the shape an auditor/compliance team can use.
"""

from __future__ import annotations

import csv
import html as _html
import io
from datetime import datetime, timezone
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.attack_mapper import CWE_TO_ATTACK, _infer_cwe_from_title
from app.core.database import get_db
from app.core.dependencies import get_current_org_id, get_current_user
from app.models.db.finding import Finding, FindingStatus
from app.models.db.user import User

router = APIRouter(prefix="/compliance", tags=["Compliance"])

# ── Control catalogues ────────────────────────────────────────────────────────
# Representative subset of controls per framework, each with a human name and
# description, so "not assessed" (no CWE in our data maps to it yet) is a
# meaningful, visible state rather than a silent omission.

FRAMEWORKS: dict[str, dict[str, dict]] = {
    "soc2": {
        "CC6.1": {"name": "Logical access security", "description": "The entity implements logical access security measures to protect against threats from sources outside its system boundaries."},
        "CC6.6": {"name": "Encryption of sensitive data", "description": "The entity implements controls to prevent or detect unauthorized access to sensitive data, including encryption."},
        "CC6.7": {"name": "Restriction of data transmission", "description": "The entity restricts the transmission, movement, and removal of information to authorized users and processes."},
        "CC7.1": {"name": "Detection of security events", "description": "The entity uses detection and monitoring procedures to identify anomalies and security events, including injection/deserialization flaws."},
        "CC7.2": {"name": "Monitoring for security anomalies", "description": "The entity monitors system components for anomalies indicative of malicious acts or unauthorized access."},
    },
    "pci_dss": {
        "3.5": {"name": "Protect stored cryptographic keys and secrets", "description": "Secrets and cryptographic key material are protected from unauthorized disclosure."},
        "4.2": {"name": "Strong cryptography in transit", "description": "Strong cryptography protects cardholder data during transmission over open, public networks."},
        "6.2.1": {"name": "Secure coding for public-facing applications", "description": "Public-facing web applications are protected against known attacks (e.g. XSS, CSRF)."},
        "6.2.4": {"name": "Prevention of common software vulnerabilities", "description": "Software is developed to prevent common coding vulnerabilities (injection, deserialization, XXE, SSRF)."},
        "8.3": {"name": "Strong authentication for all access", "description": "Strong authentication controls, including MFA, are enforced for all access to system components."},
    },
    "iso27001": {
        "A.5.15": {"name": "Access control", "description": "Rules to control physical and logical access to information and associated assets are established."},
        "A.8.16": {"name": "Monitoring activities", "description": "Networks, systems, and applications are monitored for anomalous behavior."},
        "A.8.24": {"name": "Use of cryptography", "description": "Rules for the effective use of cryptography, including key management, are defined and implemented."},
        "A.8.28": {"name": "Secure coding", "description": "Secure coding principles are applied to software development to prevent vulnerabilities."},
    },
}

VALID_FRAMEWORKS = set(FRAMEWORKS.keys())

# CWE -> per-framework control IDs (reuses the same 13-CWE catalogue as the
# MITRE ATT&CK mapper so a finding maps consistently everywhere in the app)
CWE_TO_CONTROLS: dict[str, dict[str, list[str]]] = {
    "CWE-89":  {"soc2": ["CC7.1"], "pci_dss": ["6.2.4"], "iso27001": ["A.8.28"]},
    "CWE-79":  {"soc2": ["CC7.1"], "pci_dss": ["6.2.1"], "iso27001": ["A.8.28"]},
    "CWE-22":  {"soc2": ["CC6.1"], "pci_dss": ["6.2.4"], "iso27001": ["A.8.28"]},
    "CWE-287": {"soc2": ["CC6.1"], "pci_dss": ["8.3"], "iso27001": ["A.5.15"]},
    "CWE-200": {"soc2": ["CC6.1"], "pci_dss": ["3.5"], "iso27001": ["A.5.15"]},
    "CWE-798": {"soc2": ["CC6.6"], "pci_dss": ["3.5"], "iso27001": ["A.8.24"]},
    "CWE-502": {"soc2": ["CC7.1"], "pci_dss": ["6.2.4"], "iso27001": ["A.8.28"]},
    "CWE-611": {"soc2": ["CC7.1"], "pci_dss": ["6.2.4"], "iso27001": ["A.8.28"]},
    "CWE-918": {"soc2": ["CC6.7"], "pci_dss": ["6.2.4"], "iso27001": ["A.8.28"]},
    "CWE-352": {"soc2": ["CC6.1"], "pci_dss": ["6.2.1"], "iso27001": ["A.8.28"]},
    "CWE-416": {"soc2": ["CC7.1"], "pci_dss": ["6.2.4"], "iso27001": ["A.8.28"]},
    "CWE-732": {"soc2": ["CC6.1"], "pci_dss": ["8.3"], "iso27001": ["A.5.15"]},
}


def _finding_cwe(finding: Finding) -> Optional[str]:
    if finding.cve:
        for cve in finding.cve:
            if str(cve).startswith("CWE-"):
                return str(cve)
    return _infer_cwe_from_title(finding.title)


async def _build_coverage(db: AsyncSession, org_id, framework: str) -> dict:
    controls = FRAMEWORKS[framework]
    result = await db.execute(
        select(Finding).where(
            Finding.org_id == org_id,
            Finding.status.in_([FindingStatus.OPEN, FindingStatus.IN_PROGRESS]),
            Finding.suppressed.is_(False),
        )
    )
    findings = result.scalars().all()

    # control_id -> list of failing findings
    control_failures: dict[str, list[dict]] = {cid: [] for cid in controls}
    assessed_cwes: set[str] = set()

    for f in findings:
        cwe = _finding_cwe(f)
        if not cwe or cwe not in CWE_TO_CONTROLS:
            continue
        assessed_cwes.add(cwe)
        for cid in CWE_TO_CONTROLS[cwe].get(framework, []):
            if cid in control_failures:
                control_failures[cid].append({
                    "finding_id": str(f.id),
                    "title": f.title,
                    "severity": f.severity.value,
                    "affected_asset": f.affected_asset,
                    "cwe": cwe,
                })

    # A control is only "not assessed" if none of the CWEs that map to it ever
    # appeared in this org's findings at all (vs. "pass" — assessed, no failures)
    controls_mapping_to_assessed_cwe = {
        cid for cwe in assessed_cwes for cid in CWE_TO_CONTROLS.get(cwe, {}).get(framework, [])
    }

    rows = []
    for cid, meta in controls.items():
        failures = control_failures.get(cid, [])
        if failures:
            state = "fail"
        elif cid in controls_mapping_to_assessed_cwe:
            state = "pass"
        else:
            state = "not_assessed"
        rows.append({
            "control_id": cid,
            "name": meta["name"],
            "description": meta["description"],
            "state": state,
            "failing_findings": failures,
        })

    return {
        "framework": framework,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_controls": len(rows),
        "passing": sum(1 for r in rows if r["state"] == "pass"),
        "failing": sum(1 for r in rows if r["state"] == "fail"),
        "not_assessed": sum(1 for r in rows if r["state"] == "not_assessed"),
        "controls": rows,
    }


def _csv_safe(value: str) -> str:
    """Neutralize CSV formula injection (CWE-1236): a cell starting with
    =, +, -, @, or a tab/CR that a spreadsheet app would interpret as a
    formula prefix. Finding titles can originate from an untrusted scan
    target (e.g. a git commit message), so this must not be skipped."""
    s = str(value or "").replace("\r", " ").replace("\n", " ")
    if s and s[0] in ("=", "+", "-", "@", "\t"):
        return "'" + s
    return s


def _validate_framework(framework: str) -> str:
    if framework not in VALID_FRAMEWORKS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"framework must be one of: {', '.join(sorted(VALID_FRAMEWORKS))}",
        )
    return framework


@router.get("/frameworks", summary="List supported compliance frameworks")
async def list_frameworks(
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict:
    return {
        fw: {"total_controls": len(controls), "controls": controls}
        for fw, controls in FRAMEWORKS.items()
    }


@router.get("/{framework}/coverage", summary="Control-by-control coverage for a framework")
async def get_coverage(
    framework: str,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id=Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> dict:
    _validate_framework(framework)
    return await _build_coverage(db, org_id, framework)


@router.get("/{framework}/export", summary="Export a compliance evidence bundle (PDF or CSV)")
async def export_evidence(
    framework: str,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id=Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
    fmt: str = Query("pdf", pattern="^(pdf|csv)$"),
):
    _validate_framework(framework)
    coverage = await _build_coverage(db, org_id, framework)

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["Control ID", "Name", "State", "Failing Findings", "Finding Titles"])
        for row in coverage["controls"]:
            writer.writerow([
                row["control_id"], row["name"], row["state"],
                len(row["failing_findings"]),
                _csv_safe("; ".join(f["title"] for f in row["failing_findings"][:10])),
            ])
        buf.seek(0)
        return StreamingResponse(
            iter([buf.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={framework}-evidence.csv"},
        )

    # PDF
    try:
        from weasyprint import HTML  # type: ignore[import]
    except ImportError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="PDF generation requires weasyprint, which is not installed on this server.",
        )

    framework_labels = {"soc2": "SOC 2", "pci_dss": "PCI-DSS", "iso27001": "ISO/IEC 27001"}
    state_colors = {"pass": "#16a34a", "fail": "#dc2626", "not_assessed": "#71717a"}
    state_labels = {"pass": "PASS", "fail": "FAIL", "not_assessed": "NOT ASSESSED"}

    rows_html = ""
    for row in coverage["controls"]:
        findings_html = ""
        if row["failing_findings"]:
            items = "".join(
                f"<li>{_html.escape(f['severity'].upper())} — {_html.escape(f['title'])} "
                f"({_html.escape(f['affected_asset']) if f['affected_asset'] else 'n/a'})</li>"
                for f in row["failing_findings"][:20]
            )
            findings_html = f"<ul style='margin:4px 0 0 16px;font-size:11px;color:#52525b'>{items}</ul>"
        rows_html += f"""
        <tr>
          <td style="padding:8px;border-bottom:1px solid #e4e4e7;font-family:monospace">{_html.escape(row['control_id'])}</td>
          <td style="padding:8px;border-bottom:1px solid #e4e4e7">{_html.escape(row['name'])}<br/>
              <span style="font-size:11px;color:#71717a">{_html.escape(row['description'])}</span>{findings_html}</td>
          <td style="padding:8px;border-bottom:1px solid #e4e4e7;text-align:center">
              <span style="color:{state_colors[row['state']]};font-weight:bold">{state_labels[row['state']]}</span>
          </td>
        </tr>"""

    html = f"""
    <html><head><meta charset="utf-8"><style>
      body {{ font-family: -apple-system, Helvetica, Arial, sans-serif; color: #18181b; }}
      h1 {{ font-size: 20px; margin-bottom: 2px; }}
      .meta {{ color: #71717a; font-size: 12px; margin-bottom: 20px; }}
      table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
      th {{ text-align: left; padding: 8px; background: #f4f4f5; border-bottom: 2px solid #d4d4d8; }}
      .summary {{ display: flex; gap: 24px; margin-bottom: 20px; }}
      .stat {{ font-size: 20px; font-weight: bold; }}
      .stat-label {{ font-size: 11px; color: #71717a; }}
    </style></head><body>
      <h1>{_html.escape(framework_labels.get(framework, framework))} Compliance Evidence Bundle</h1>
      <p class="meta">Generated {_html.escape(coverage['generated_at'])} by AttackTrace — derived from live scan findings.
      This is evidence packaging, not a certification.</p>
      <div class="summary">
        <div><div class="stat" style="color:#16a34a">{coverage['passing']}</div><div class="stat-label">PASSING</div></div>
        <div><div class="stat" style="color:#dc2626">{coverage['failing']}</div><div class="stat-label">FAILING</div></div>
        <div><div class="stat" style="color:#71717a">{coverage['not_assessed']}</div><div class="stat-label">NOT ASSESSED</div></div>
      </div>
      <table>
        <thead><tr><th style="width:80px">Control</th><th>Description</th><th style="width:110px">Status</th></tr></thead>
        <tbody>{rows_html}</tbody>
      </table>
    </body></html>
    """

    # Reject every external resource fetch (images, stylesheets, fonts) — the
    # template embeds its own <style> and references nothing external, so
    # this closes the SSRF vector without breaking rendering. Finding titles
    # are HTML-escaped above, but a URL fetcher is defense-in-depth against
    # any injection that slips through (e.g. a CSS url() in an unescaped field
    # added later) and against WeasyPrint following redirects on its own.
    def _no_external_fetch(url: str, *args, **kwargs):
        raise ValueError(f"External resource fetching is disabled (blocked: {url})")

    pdf_bytes = HTML(string=html, url_fetcher=_no_external_fetch).write_pdf()
    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={framework}-evidence.pdf"},
    )
