"""
PHP2Shell scan report (HTML / PDF / CSV).

Built from a saved scan record (app.api.v1.php_cve history) plus the org's
asset inventory, so the report answers both "which hosts are exposed?" and
"did we cover our discovered assets?" — every scanned target is listed, with
its inventory asset type/risk, including ones where no web service answered.

Every value that came from a remote host (Server / X-Powered-By headers, phpinfo
strings) is attacker-controlled: it is html.escape()'d before embedding and
CSV cells go through csv_safe(). PDF rendering reuses export_service's
network-blocking WeasyPrint wrapper.
"""
from __future__ import annotations

import csv
import io
from html import escape
from typing import Any, Mapping

from app.core.csv_safety import csv_safe
from app.services import php2shell as p2s

STATUS_ORDER = ["vulnerable", "likely_vulnerable", "unverified", "version_hidden", "patched", "not_affected", "no_php", "no_web"]
STATUS_LABEL = {
    "vulnerable": "Vulnerable",
    "likely_vulnerable": "Likely vulnerable",
    "unverified": "Backport unverified",
    "version_hidden": "Version hidden",
    "patched": "Patched",
    "not_affected": "Not affected",
    "no_php": "No PHP detected",
    "no_web": "No web service answered",
}
_STATUS_COLOR = {
    "vulnerable": "#dc2626", "likely_vulnerable": "#ea580c", "unverified": "#ca8a04",
    "version_hidden": "#ca8a04", "patched": "#16a34a", "not_affected": "#6b7280",
    "no_php": "#6b7280", "no_web": "#9ca3af",
}
_ACTION = {"vulnerable", "likely_vulnerable", "unverified", "version_hidden"}


def _host_key(r: Mapping[str, Any]) -> str:
    return r["label"].split(" (")[0]


def _status_of(r: Mapping[str, Any]) -> str:
    a = r.get("assessment")
    if a:
        return a["status"]
    return "no_php"


def build_rows(record: Mapping[str, Any], inventory: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    """One row per fingerprinted web service, plus one per scanned target that
    answered on no port. `inventory` maps lowercase host/IP -> {asset_type,
    risk_score}."""
    rows: list[dict[str, Any]] = []
    answered: set[str] = set()
    for r in record.get("results", []):
        key = _host_key(r).lower()
        answered.add(key)
        answered.add(str(r.get("ip", "")).lower())
        inv = inventory.get(key) or inventory.get(str(r.get("ip", "")).lower()) or {}
        a = r.get("assessment") or {}
        rows.append({
            "target": _host_key(r), "ip": r.get("ip"), "port": r.get("port"), "url": r.get("url"),
            "in_inventory": bool(inv), "asset_type": inv.get("asset_type"), "risk_score": inv.get("risk_score"),
            "php_detected": bool(r.get("php_detected")), "version": r.get("version"),
            "version_source": r.get("version_source"), "status": _status_of(r),
            "fixed_in": a.get("fixed_in"), "reason": a.get("reason"), "sapi": r.get("sapi"),
            "distro": r.get("distro"), "server_header": r.get("server_header"),
            "powered_by": r.get("powered_by"), "phpinfo_url": r.get("phpinfo_url"),
            "upload_progress": r.get("upload_progress"), "memory_limit": r.get("memory_limit"),
            "signals": r.get("signals") or [],
        })
    for t in record.get("scanned_targets", []):
        key = str(t.get("host") or t.get("ip")).lower()
        if key in answered or str(t.get("ip", "")).lower() in answered:
            continue
        inv = inventory.get(key) or inventory.get(str(t.get("ip", "")).lower()) or {}
        rows.append({
            "target": t.get("host") or t.get("ip"), "ip": t.get("ip"), "port": None, "url": None,
            "in_inventory": bool(inv), "asset_type": inv.get("asset_type"), "risk_score": inv.get("risk_score"),
            "php_detected": False, "version": None, "version_source": None, "status": "no_web",
            "fixed_in": None, "reason": "No HTTP service answered on the scanned ports.", "sapi": None,
            "distro": None, "server_header": None, "powered_by": None, "phpinfo_url": None,
            "upload_progress": None, "memory_limit": None, "signals": [],
        })
    rows.sort(key=lambda x: (STATUS_ORDER.index(x["status"]), str(x["target"]), x["port"] or 0))
    return rows


def render_csv(rows: list[dict[str, Any]]) -> str:
    cols = ["target", "ip", "port", "url", "in_inventory", "asset_type", "risk_score", "status", "php_detected",
            "version", "version_source", "fixed_in", "sapi", "distro", "upload_progress", "memory_limit",
            "phpinfo_url", "server_header", "powered_by", "reason"]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r in rows:
        w.writerow([csv_safe(STATUS_LABEL[r["status"]] if c == "status" else r.get(c)) for c in cols])
    return buf.getvalue()


_CSS = """
  body { font-family: -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif; color: #111827; margin: 24px; font-size: 12px; }
  h1 { font-size: 24px; margin: 0 0 4px; } h2 { font-size: 16px; margin: 26px 0 8px; border-bottom: 2px solid #e5e7eb; padding-bottom: 4px; }
  h3 { font-size: 13px; margin: 14px 0 4px; }
  .sub { color: #6b7280; margin-bottom: 14px; }
  .cards { display: table; width: 100%; table-layout: fixed; border-spacing: 8px 0; margin: 0 -8px 10px; }
  .card { display: table-cell; border: 1px solid #e5e7eb; border-radius: 6px; padding: 10px; text-align: center; }
  .card b { display: block; font-size: 22px; } .card span { font-size: 10px; color: #6b7280; }
  table { width: 100%; border-collapse: collapse; margin-top: 6px; }
  th { background: #f3f4f6; text-align: left; padding: 6px 8px; font-size: 10px; text-transform: uppercase; color: #4b5563; }
  td { padding: 5px 8px; border-bottom: 1px solid #e5e7eb; vertical-align: top; word-break: break-word; }
  .badge { display: inline-block; padding: 2px 7px; border-radius: 4px; color: #fff; font-size: 10px; font-weight: 600; white-space: nowrap; }
  .mono { font-family: Menlo, Consolas, monospace; font-size: 11px; } .muted { color: #9ca3af; }
  .callout { border-left: 4px solid #dc2626; background: #fef2f2; padding: 8px 12px; margin: 10px 0; }
  .note { border-left: 4px solid #ca8a04; background: #fefce8; padding: 8px 12px; margin: 10px 0; }
  .host { page-break-inside: avoid; border: 1px solid #e5e7eb; border-radius: 6px; padding: 8px 12px; margin: 8px 0; }
  .footer { margin-top: 24px; font-size: 10px; color: #9ca3af; }
  @page { size: A4 landscape; margin: 14mm 12mm; }
"""


def _badge(status: str) -> str:
    return f'<span class="badge" style="background:{_STATUS_COLOR[status]}">{escape(STATUS_LABEL[status])}</span>'


def _cell(v: Any) -> str:
    return escape(str(v)) if v not in (None, "") else '<span class="muted">—</span>'


def render_html(record: Mapping[str, Any], rows: list[dict[str, Any]], org_name: str, generated_at: str) -> str:
    s = record.get("summary", {})
    counts = {k: sum(1 for r in rows if r["status"] == k) for k in STATUS_ORDER}
    targets_scanned = len(record.get("scanned_targets", [])) or s.get("total_hosts", 0)
    in_inv = len({str(r["target"]).lower() for r in rows if r["in_inventory"]})
    action_rows = [r for r in rows if r["status"] in _ACTION]
    urgent = counts["vulnerable"] + counts["likely_vulnerable"]

    if urgent:
        headline = (f'<div class="callout"><b>{urgent} web service{"s" if urgent != 1 else ""} '
                    f'run a PHP version exposed to PHP2Shell (CVE-2026-109618 / CVE-2026-109619).</b> '
                    f'These are unauthenticated remote-code-execution flaws listed on CISA KEV; patch first.</div>')
    elif action_rows:
        headline = ('<div class="note"><b>No host was proven vulnerable, but some need verification.</b> '
                    'Version strings of distro builds and hidden versions cannot be judged remotely — check the package changelog on those hosts.</div>')
    else:
        headline = '<div class="note"><b>No vulnerable PHP version was observed.</b> This reflects only what the scanned hosts disclosed.</div>'

    cards = "".join(
        f'<div class="card"><b style="color:{_STATUS_COLOR[k]}">{counts[k] if k != "unverified" else counts["unverified"] + counts["version_hidden"]}</b>'
        f'<span>{lbl}</span></div>'
        for k, lbl in [("vulnerable", "Vulnerable"), ("likely_vulnerable", "Likely vulnerable"),
                       ("unverified", "Needs verification"), ("patched", "Patched")]
    ) + (f'<div class="card"><b>{targets_scanned}</b><span>Targets scanned</span></div>'
         f'<div class="card"><b>{in_inv}</b><span>In asset inventory</span></div>')

    def host_table(items: list[dict[str, Any]]) -> str:
        body = "".join(
            f'<tr><td class="mono">{_cell(r["target"])}{("<br><span class=muted>" + escape(str(r["ip"])) + "</span>") if r["ip"] and str(r["ip"]) != str(r["target"]) else ""}</td>'
            f'<td class="mono">{_cell(r["port"])}</td>'
            f'<td>{_cell(r["asset_type"] if r["in_inventory"] else "not in inventory")}</td>'
            f'<td class="mono">{("PHP " + escape(str(r["version"]))) if r["version"] else _cell(None)}</td>'
            f'<td>{_cell(r["version_source"])}</td><td>{_badge(r["status"])}</td></tr>'
            for r in items)
        return ('<table><tr><th>Target</th><th>Port</th><th>Asset</th><th>PHP version</th><th>Source</th><th>Verdict</th></tr>'
                + body + '</table>')

    detail = ""
    for r in action_rows:
        kv = [("Verdict", STATUS_LABEL[r["status"]]), ("Fixed in", r["fixed_in"]), ("Version source", r["version_source"]),
              ("Server header", r["server_header"]), ("X-Powered-By", r["powered_by"]), ("Distro hint", r["distro"]),
              ("SAPI", r["sapi"]), ("session.upload_progress", r["upload_progress"]), ("memory_limit", r["memory_limit"]),
              ("phpinfo()", r["phpinfo_url"])]
        rowsh = "".join(f'<tr><td style="width:170px" class="muted">{escape(k)}</td><td class="mono">{escape(str(v))}</td></tr>'
                        for k, v in kv if v)
        detail += (f'<div class="host"><h3>{_cell(r["target"])}:{_cell(r["port"])} {_badge(r["status"])}</h3>'
                   f'<p>{escape(r["reason"] or "")}</p><table>{rowsh}</table></div>')

    coverage = {}
    for r in rows:
        c = coverage.setdefault(str(r["target"]).lower(), {"target": r["target"], "ip": r["ip"], "inv": r["in_inventory"],
                                                          "type": r["asset_type"], "risk": r["risk_score"], "status": r["status"], "n": 0})
        c["n"] += 1 if r["status"] != "no_web" else 0
        if STATUS_ORDER.index(r["status"]) < STATUS_ORDER.index(c["status"]):
            c["status"] = r["status"]
    cov_body = "".join(
        f'<tr><td class="mono">{_cell(c["target"])}</td><td class="mono">{_cell(c["ip"] if str(c["ip"]) != str(c["target"]) else None)}</td>'
        f'<td>{_cell(c["type"] if c["inv"] else "not in inventory")}</td>'
        f'<td>{_cell(round(c["risk"], 1) if isinstance(c["risk"], (int, float)) else None)}</td>'
        f'<td>{c["n"]}</td><td>{_badge(c["status"])}</td></tr>'
        for c in sorted(coverage.values(), key=lambda c: (STATUS_ORDER.index(c["status"]), str(c["target"]))))

    errs = s.get("errors") or []
    err_html = ""
    if errs:
        err_html = ('<h2>Targets not scanned</h2><table><tr><th>Target</th><th>Reason</th></tr>'
                    + "".join(f'<tr><td class="mono">{escape(str(e.get("target")))}</td><td>{escape(str(e.get("error")))}</td></tr>' for e in errs)
                    + '</table>')

    return f"""<!doctype html><html><head><meta charset="utf-8"><title>PHP2Shell Exposure Report</title><style>{_CSS}</style></head><body>
<h1>PHP2Shell Exposure Report</h1>
<div class="sub">CVE-2026-109618 / CVE-2026-109619 · unauthenticated PHP remote code execution · CVSS 9.2 · CISA KEV<br>
{escape(org_name)} · scan {escape(str(record.get("id", "")))} · {escape(str(record.get("started_at", ""))[:19].replace("T", " "))} UTC · generated {escape(generated_at)}</div>
{headline}
<div class="cards">{cards}</div>

<h2>Exposed and needs-attention services</h2>
{host_table(action_rows) if action_rows else '<p class="muted">None.</p>'}
{detail}

<h2>Remediation</h2>
<p>{escape(p2s.REMEDIATION)}</p>

<h2>Asset coverage</h2>
<p>Every scanned target, joined to the asset inventory. "In inventory" means the host or IP matches a discovered asset.</p>
<table><tr><th>Target</th><th>Resolved IP</th><th>Asset type</th><th>Risk</th><th>Web services</th><th>Worst verdict</th></tr>{cov_body}</table>
{err_html}

<h2>Methodology and limitations</h2>
<p>Ports scanned: {escape(", ".join(str(p) for p in record.get("ports", [])))}. Each web service received benign GET requests only
(<span class="mono">/</span>, <span class="mono">/index.php</span>, common phpinfo paths). The PHP version was read from
<span class="mono">X-Powered-By</span>, <span class="mono">Server</span> or an exposed <span class="mono">phpinfo()</span> and compared with the fixed releases
({escape(", ".join(f"{a}.{b}.{p}" for (a, b), p in sorted(p2s.FIXED_PATCH.items())))}). <b>No exploit traffic was sent</b>: every known trigger is a memory-corrupting
multipart request, so exploitability cannot be proven remotely.</p>
<ul>
<li>Distribution packages backport the fix without changing the version string, so below-fix distro builds are "Backport unverified", not "Vulnerable".</li>
<li>Hosts that hide their PHP version (<span class="mono">expose_php=Off</span>, <span class="mono">ServerTokens Prod</span>) cannot be judged remotely; "Version hidden" is not "safe".</li>
<li>A proxy or WAF can rewrite headers. A phpinfo-sourced version is more reliable than a header-sourced one.</li>
<li>Patched means the version is at or above the fix; PHP workers must also have been restarted after the update.</li>
</ul>
<p class="muted">References: {" · ".join(escape(u) for u in p2s.REFERENCES)}</p>
<div class="footer">Generated by AttackTrace.</div></body></html>"""
