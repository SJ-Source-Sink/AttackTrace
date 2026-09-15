"""
Shared HTML/PDF export rendering for the findings and assets list views —
a plain, printable tabular export of whatever's currently filtered/selected,
distinct from report_service.py's much heavier per-scan "security assessment
report" (executive summary, methodology, evidence appendix). This is closer
to a nicer CSV: one clean table, ready to print or share.

Security posture matches compliance.py's existing PDF export exactly (same
established pattern in this codebase): every user-controlled string is
html.escape()'d before being embedded, and PDF generation blocks all
external resource fetching (no url_fetcher escape hatch — an injected
`url(...)` in a field that somehow got past escaping still can't make
WeasyPrint fetch anything).
"""
from __future__ import annotations

import asyncio
from html import escape
from typing import Iterable

_SEVERITY_COLORS = {
    "critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04",
    "low": "#2563eb", "info": "#6b7280",
}

_BASE_CSS = """
  * { box-sizing: border-box; }
  body { font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; color: #1a1a1a; margin: 0; padding: 32px; }
  h1 { font-size: 20px; margin: 0 0 4px; }
  .subtitle { color: #666; font-size: 12px; margin: 0 0 24px; }
  table { width: 100%; border-collapse: collapse; table-layout: fixed; font-size: 11px; }
  th { text-align: left; background: #111827; color: #fff; padding: 8px 10px; font-weight: 600; }
  td { padding: 7px 10px; border-bottom: 1px solid #e5e7eb; vertical-align: top; word-wrap: break-word; }
  tr:nth-child(even) td { background: #f9fafb; }
  .sev-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; color: #fff; font-size: 10px; font-weight: 600; text-transform: uppercase; }
  .muted { color: #888; }
  .footer { margin-top: 20px; font-size: 10px; color: #999; }
  @page { size: A4 landscape; margin: 16mm 12mm; }
"""


def _sev_badge(sev: str) -> str:
    color = _SEVERITY_COLORS.get((sev or "").lower(), "#6b7280")
    return f'<span class="sev-badge" style="background:{color}">{escape(sev or "")}</span>'


def render_findings_html(findings: Iterable, generated_at: str, org_name: str = "") -> str:
    rows_html = []
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        st = f.status.value if hasattr(f.status, "value") else str(f.status)
        cve = ", ".join(f.cve or []) if getattr(f, "cve", None) else ""
        dash = '<span class="muted">—</span>'
        cvss_cell = escape(str(f.cvss_score)) if f.cvss_score is not None else dash
        cve_cell = escape(cve) if cve else dash
        conf_cell = escape(f.confidence or "") if f.confidence else dash
        created_cell = escape(f.created_at.strftime("%Y-%m-%d") if f.created_at else "")
        rows_html.append(
            "<tr>"
            f"<td>{_sev_badge(sev)}</td>"
            f"<td>{escape(f.title or '')}</td>"
            f"<td>{escape(st)}</td>"
            f"<td>{escape(f.affected_asset or '')}</td>"
            f"<td>{cvss_cell}</td>"
            f"<td>{cve_cell}</td>"
            f"<td>{conf_cell}</td>"
            f"<td>{created_cell}</td>"
            "</tr>"
        )

    subtitle = f"{org_name + ' — ' if org_name else ''}{len(rows_html)} finding(s) — generated {escape(generated_at)}"
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Findings Export</title><style>{_BASE_CSS}
  col.c-sev {{ width: 8%; }} col.c-title {{ width: 26%; }} col.c-status {{ width: 9%; }}
  col.c-asset {{ width: 20%; }} col.c-cvss {{ width: 6%; }} col.c-cve {{ width: 12%; }}
  col.c-conf {{ width: 9%; }} col.c-date {{ width: 10%; }}
</style></head>
<body>
  <h1>Findings Export</h1>
  <p class="subtitle">{subtitle}</p>
  <table>
    <colgroup>
      <col class="c-sev"><col class="c-title"><col class="c-status"><col class="c-asset">
      <col class="c-cvss"><col class="c-cve"><col class="c-conf"><col class="c-date">
    </colgroup>
    <thead><tr>
      <th>Severity</th><th>Title</th><th>Status</th><th>Affected Asset</th>
      <th>CVSS</th><th>CVE</th><th>Confidence</th><th>Found</th>
    </tr></thead>
    <tbody>{''.join(rows_html) if rows_html else '<tr><td colspan="8" class="muted">No findings match the current filters.</td></tr>'}</tbody>
  </table>
  <p class="footer">Exported from AttackTrace</p>
</body></html>"""


def render_assets_html(assets: Iterable, generated_at: str, owner_names: dict, org_name: str = "") -> str:
    rows_html = []
    for a in assets:
        atype = a.asset_type.value if hasattr(a.asset_type, "value") else str(a.asset_type)
        owner = owner_names.get(a.owner_user_id, "") if a.owner_user_id else ""
        tags = ", ".join(a.tags or [])
        dash = '<span class="muted">—</span>'
        tags_cell = escape(tags) if tags else dash
        owner_cell = escape(owner) if owner else dash
        risk_cell = escape(str(a.risk_score)) if a.risk_score is not None else dash
        first_seen_cell = escape(a.first_seen.strftime("%Y-%m-%d") if a.first_seen else "")
        last_seen_cell = escape(a.last_seen.strftime("%Y-%m-%d") if a.last_seen else "")
        rows_html.append(
            "<tr>"
            f"<td>{escape(atype)}</td>"
            f"<td>{escape(a.value or '')}</td>"
            f"<td>{tags_cell}</td>"
            f"<td>{owner_cell}</td>"
            f"<td>{risk_cell}</td>"
            f"<td>{'Active' if a.is_active else 'Inactive'}</td>"
            f"<td>{first_seen_cell}</td>"
            f"<td>{last_seen_cell}</td>"
            "</tr>"
        )

    subtitle = f"{org_name + ' — ' if org_name else ''}{len(rows_html)} asset(s) — generated {escape(generated_at)}"
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Assets Export</title><style>{_BASE_CSS}
  col.c-type {{ width: 10%; }} col.c-value {{ width: 28%; }} col.c-tags {{ width: 14%; }}
  col.c-owner {{ width: 10%; }} col.c-risk {{ width: 7%; }} col.c-status {{ width: 8%; }}
  col.c-first {{ width: 11.5%; }} col.c-last {{ width: 11.5%; }}
</style></head>
<body>
  <h1>Assets Export</h1>
  <p class="subtitle">{subtitle}</p>
  <table>
    <colgroup>
      <col class="c-type"><col class="c-value"><col class="c-tags"><col class="c-owner">
      <col class="c-risk"><col class="c-status"><col class="c-first"><col class="c-last">
    </colgroup>
    <thead><tr>
      <th>Type</th><th>Value</th><th>Tags</th><th>Owner</th>
      <th>Risk</th><th>Status</th><th>First Seen</th><th>Last Seen</th>
    </tr></thead>
    <tbody>{''.join(rows_html) if rows_html else '<tr><td colspan="8" class="muted">No assets match the current filters.</td></tr>'}</tbody>
  </table>
  <p class="footer">Exported from AttackTrace</p>
</body></html>"""


async def html_to_pdf_bytes(html: str) -> bytes:
    """Convert an already-rendered HTML string to PDF bytes. Blocks all
    external resource fetching (this template references none, so any
    attempt to fetch one is itself a signal something is wrong) and offloads
    the blocking weasyprint call to a thread, matching the established
    pattern in report_service.py/compliance.py."""
    from weasyprint import HTML  # type: ignore[import]

    def _no_external_fetch(url: str, *args, **kwargs):
        raise ValueError(f"External resource fetching is disabled (blocked: {url})")

    def _generate() -> bytes:
        return HTML(string=html, url_fetcher=_no_external_fetch).write_pdf()

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _generate)
