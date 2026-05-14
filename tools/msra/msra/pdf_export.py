"""
PDF report export for MSRA.
Requires weasyprint: pip install weasyprint
"""

from __future__ import annotations

import datetime
import html as _html
from typing import Any, Dict, List


_SEV_COLORS = {
    "Critical": "#ef4444",
    "High":     "#f97316",
    "Medium":   "#eab308",
    "Low":      "#22c55e",
    "Info":     "#06b6d4",
}

_SEV_BG = {
    "Critical": "#fef2f2",
    "High":     "#fff7ed",
    "Medium":   "#fefce8",
    "Low":      "#f0fdf4",
    "Info":     "#ecfeff",
}


def generate_pdf_report(
    findings: List[Dict[str, Any]],
    output_path: str,
    metadata: Dict[str, Any],
) -> None:
    """
    Render a print-optimised HTML doc and write it as PDF via WeasyPrint.

    Args:
        findings:    list of finding dicts (from summary.json / embedded JSON)
        output_path: destination .pdf file path
        metadata:    dict with keys: package, apk, scan_id, severity_counts
    Raises:
        ImportError  if weasyprint is not installed
        RuntimeError on render failure
    """
    try:
        from weasyprint import HTML as _WP
    except ImportError:
        raise ImportError(
            "weasyprint is not installed. Run: pip install weasyprint"
        )

    html_str = _build_html(findings, metadata)
    try:
        _WP(string=html_str).write_pdf(output_path)
    except Exception as exc:
        raise RuntimeError(f"WeasyPrint render failed: {exc}") from exc


# ── HTML builder ──────────────────────────────────────────────────────────────

def _v(obj: Any, *keys: str, default: str = "") -> str:
    """Safe getter that works on both dicts and dataclass objects."""
    for k in keys:
        if isinstance(obj, dict):
            obj = obj.get(k, default)
        else:
            obj = getattr(obj, k, default)
    return str(obj) if obj is not None else default


def _build_html(findings: List[Dict], metadata: Dict) -> str:
    pkg        = _html.escape(str(metadata.get("package") or "unknown"))
    apk        = _html.escape(str(metadata.get("apk") or ""))
    scan_id    = metadata.get("scan_id", "")
    sev_counts = metadata.get("severity_counts") or {}
    now        = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    total      = len(findings)

    sev_summary = _build_severity_summary(sev_counts)
    findings_html = _build_findings(findings)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>MSRA Security Report — {pkg}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    font-size: 11pt;
    color: #1a1a2e;
    background: #ffffff;
    padding: 0;
  }}
  .cover {{
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
    color: #f8fafc;
    padding: 48px 40px 40px;
    page-break-after: always;
  }}
  .cover-logo {{
    font-size: 28pt;
    font-weight: 800;
    letter-spacing: -0.5px;
    color: #38bdf8;
    margin-bottom: 8px;
  }}
  .cover-subtitle {{
    font-size: 13pt;
    color: #94a3b8;
    margin-bottom: 32px;
  }}
  .cover-pkg {{
    font-size: 18pt;
    font-weight: 700;
    color: #f1f5f9;
    word-break: break-all;
    margin-bottom: 6px;
  }}
  .cover-meta {{
    font-size: 10pt;
    color: #64748b;
    margin-top: 4px;
  }}
  .cover-stats {{
    display: flex;
    gap: 16px;
    margin-top: 32px;
    flex-wrap: wrap;
  }}
  .stat-box {{
    background: rgba(255,255,255,0.06);
    border: 1px solid rgba(255,255,255,0.1);
    border-radius: 8px;
    padding: 12px 20px;
    text-align: center;
    min-width: 80px;
  }}
  .stat-num {{
    font-size: 22pt;
    font-weight: 800;
    line-height: 1;
  }}
  .stat-label {{
    font-size: 9pt;
    color: #94a3b8;
    margin-top: 2px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }}
  section {{
    padding: 32px 40px;
  }}
  h2 {{
    font-size: 14pt;
    font-weight: 700;
    color: #0f172a;
    border-bottom: 2px solid #e2e8f0;
    padding-bottom: 8px;
    margin-bottom: 20px;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 10pt;
  }}
  th {{
    background: #f1f5f9;
    text-align: left;
    padding: 8px 12px;
    font-weight: 600;
    color: #475569;
    border-bottom: 2px solid #e2e8f0;
  }}
  td {{
    padding: 8px 12px;
    border-bottom: 1px solid #f1f5f9;
    vertical-align: top;
  }}
  tr:nth-child(even) td {{ background: #fafafa; }}
  .sev-badge {{
    display: inline-block;
    padding: 2px 10px;
    border-radius: 4px;
    font-size: 9pt;
    font-weight: 700;
    color: white;
  }}
  .finding-card {{
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    margin-bottom: 20px;
    overflow: hidden;
    page-break-inside: avoid;
  }}
  .finding-header {{
    padding: 12px 16px;
    display: flex;
    align-items: center;
    gap: 10px;
    border-bottom: 1px solid #e2e8f0;
  }}
  .finding-title {{
    font-size: 11pt;
    font-weight: 700;
    color: #0f172a;
    flex: 1;
  }}
  .finding-body {{
    padding: 14px 16px;
    font-size: 10pt;
  }}
  .finding-meta {{
    color: #64748b;
    font-size: 9pt;
    margin-bottom: 8px;
  }}
  .finding-desc {{
    color: #374151;
    margin-bottom: 10px;
    line-height: 1.6;
  }}
  pre, code {{
    font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
    font-size: 9pt;
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 4px;
    padding: 10px 12px;
    overflow-wrap: break-word;
    white-space: pre-wrap;
    color: #1e293b;
    margin-top: 6px;
  }}
  .label {{
    font-size: 9pt;
    font-weight: 600;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.4px;
    margin-top: 10px;
    margin-bottom: 4px;
  }}
  .footer-bar {{
    background: #f8fafc;
    border-top: 1px solid #e2e8f0;
    padding: 12px 40px;
    font-size: 9pt;
    color: #94a3b8;
    text-align: center;
  }}
  @page {{
    size: A4;
    margin: 0;
  }}
</style>
</head>
<body>

<!-- Cover page -->
<div class="cover">
  <div class="cover-logo">MSRA</div>
  <div class="cover-subtitle">Mobile Security Review Assistant</div>
  <div class="cover-pkg">{pkg}</div>
  <div class="cover-meta">{apk}</div>
  <div class="cover-meta">Scan ID: {_html.escape(scan_id)} &nbsp;·&nbsp; Generated: {now}</div>
  <div class="cover-stats">
    <div class="stat-box">
      <div class="stat-num" style="color:#f8fafc">{total}</div>
      <div class="stat-label">Total</div>
    </div>
    {_cover_stat_boxes(sev_counts)}
  </div>
</div>

<!-- Severity summary -->
<section>
  <h2>Executive Summary</h2>
  {sev_summary}
</section>

<!-- Findings -->
<section>
  <h2>Findings ({total})</h2>
  {findings_html}
</section>

<div class="footer-bar">
  Generated by <strong>MSRA</strong> &mdash; Built by Sai with love &#10084;
  &nbsp;·&nbsp; {now}
</div>

</body>
</html>"""


def _cover_stat_boxes(sev_counts: Dict) -> str:
    parts = []
    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        count = sev_counts.get(sev, 0)
        if count == 0:
            continue
        color = _SEV_COLORS.get(sev, "#94a3b8")
        parts.append(
            f'<div class="stat-box">'
            f'<div class="stat-num" style="color:{color}">{count}</div>'
            f'<div class="stat-label">{sev}</div>'
            f'</div>'
        )
    return "".join(parts)


def _build_severity_summary(sev_counts: Dict) -> str:
    rows = []
    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        count = sev_counts.get(sev, 0)
        color = _SEV_COLORS.get(sev, "#94a3b8")
        rows.append(
            f"<tr><td><span class='sev-badge' style='background:{color}'>{_html.escape(sev)}</span></td>"
            f"<td style='font-weight:700;font-size:13pt'>{count}</td></tr>"
        )
    return f"""<table>
      <thead><tr><th>Severity</th><th>Count</th></tr></thead>
      <tbody>{"".join(rows)}</tbody>
    </table>"""


def _build_findings(findings: List[Dict]) -> str:
    if not findings:
        return "<p style='color:#64748b'>No findings.</p>"

    parts = []
    for i, f in enumerate(findings, 1):
        title    = _html.escape(_v(f, "title", default=f"Finding #{i}"))
        sev      = _v(f, "severity", default="Info")
        color    = _SEV_COLORS.get(sev, "#94a3b8")
        bg       = _SEV_BG.get(sev, "#f8fafc")
        desc     = _html.escape(_v(f, "description", default=""))[:800]
        ev       = f.get("evidence") or {}
        filepath = _html.escape(_v(ev, "file_path", default=""))
        lineno   = _v(ev, "line_number", default="")
        snippet  = _html.escape(_v(ev, "snippet", default=""))[:600]
        adb_cmds = f.get("adb_commands") or []
        extra    = f.get("extra") or {}
        attack   = _html.escape(_v(f, "attack_path", default=""))[:400]

        meta_parts = []
        if filepath:
            meta_parts.append(f"<strong>File:</strong> {filepath}" + (f":{_html.escape(str(lineno))}" if lineno else ""))
        if isinstance(extra, dict) and extra.get("category"):
            meta_parts.append(f"<strong>Category:</strong> {_html.escape(str(extra['category']))}")

        adb_html = ""
        if adb_cmds:
            cmds_text = _html.escape("\n".join(str(c) for c in adb_cmds[:5]))
            adb_html  = f'<div class="label">PoC Commands</div><pre>{cmds_text}</pre>'

        snippet_html = f'<div class="label">Code Snippet</div><pre>{snippet}</pre>' if snippet else ""
        attack_html  = f'<div class="label">Attack Path</div><p class="finding-desc">{attack}</p>' if attack else ""

        parts.append(f"""
<div class="finding-card">
  <div class="finding-header" style="background:{bg}">
    <span style="color:#94a3b8;font-size:9pt;font-weight:600">#{i}</span>
    <span class="finding-title">{title}</span>
    <span class="sev-badge" style="background:{color}">{_html.escape(sev)}</span>
  </div>
  <div class="finding-body">
    <div class="finding-meta">{" &nbsp;·&nbsp; ".join(meta_parts)}</div>
    <div class="finding-desc">{desc}</div>
    {attack_html}
    {snippet_html}
    {adb_html}
  </div>
</div>""")

    return "\n".join(parts)
