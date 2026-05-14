"""
Dynamic Analysis Report Generator

Generates HTML reports with actual PoC evidence for confirmed vulnerabilities.
"""

import html
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


def generate_dynamic_report(report_data: Dict, output_path: str) -> str:
    """Generate an HTML report for dynamic analysis results."""

    package = html.escape(report_data.get('package', 'Unknown'))
    device = html.escape(report_data.get('device', 'Unknown'))
    start_time = report_data.get('start_time', '')
    end_time = report_data.get('end_time', '')
    summary = report_data.get('summary', {})
    results = report_data.get('results', [])

    # Separate by status
    confirmed = [r for r in results if r.get('status') == 'confirmed']
    likely = [r for r in results if r.get('status') == 'likely_vulnerable']
    inconclusive = [r for r in results if r.get('status') == 'inconclusive']
    not_vuln = [r for r in results if r.get('status') == 'not_vulnerable']

    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dynamic Analysis Report - {package}</title>
    <style>
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --border-color: #30363d;
            --accent-red: #f85149;
            --accent-orange: #d29922;
            --accent-yellow: #e3b341;
            --accent-green: #3fb950;
            --accent-blue: #58a6ff;
            --accent-purple: #a371f7;
        }}

        * {{ box-sizing: border-box; margin: 0; padding: 0; }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 20px;
        }}

        .container {{ max-width: 1200px; margin: 0 auto; }}

        header {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 24px;
        }}

        h1 {{
            font-size: 24px;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 12px;
        }}

        h1 .icon {{ font-size: 28px; }}

        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-top: 16px;
        }}

        .meta-item {{
            background: var(--bg-tertiary);
            padding: 12px 16px;
            border-radius: 6px;
        }}

        .meta-label {{
            font-size: 12px;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .meta-value {{
            font-size: 16px;
            font-weight: 600;
            margin-top: 4px;
        }}

        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}

        .summary-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}

        .summary-card.confirmed {{ border-left: 4px solid var(--accent-red); }}
        .summary-card.likely {{ border-left: 4px solid var(--accent-orange); }}
        .summary-card.inconclusive {{ border-left: 4px solid var(--accent-yellow); }}
        .summary-card.safe {{ border-left: 4px solid var(--accent-green); }}

        .summary-number {{
            font-size: 36px;
            font-weight: 700;
        }}

        .summary-card.confirmed .summary-number {{ color: var(--accent-red); }}
        .summary-card.likely .summary-number {{ color: var(--accent-orange); }}
        .summary-card.inconclusive .summary-number {{ color: var(--accent-yellow); }}
        .summary-card.safe .summary-number {{ color: var(--accent-green); }}

        .summary-label {{
            font-size: 14px;
            color: var(--text-secondary);
            margin-top: 4px;
        }}

        section {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 24px;
            overflow: hidden;
        }}

        .section-header {{
            padding: 16px 20px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .section-header h2 {{
            font-size: 18px;
            font-weight: 600;
        }}

        .section-header .count {{
            background: var(--bg-tertiary);
            padding: 2px 10px;
            border-radius: 12px;
            font-size: 13px;
        }}

        .finding {{
            border-bottom: 1px solid var(--border-color);
            padding: 20px;
        }}

        .finding:last-child {{ border-bottom: none; }}

        .finding-header {{
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            margin-bottom: 12px;
        }}

        .finding-title {{
            font-size: 16px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        .severity-badge {{
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
        }}

        .severity-critical {{ background: #f8514922; color: var(--accent-red); }}
        .severity-high {{ background: #d2992222; color: var(--accent-orange); }}
        .severity-medium {{ background: #e3b34122; color: var(--accent-yellow); }}
        .severity-low {{ background: #3fb95022; color: var(--accent-green); }}

        .confidence {{
            font-size: 13px;
            color: var(--text-secondary);
        }}

        .finding-notes {{
            color: var(--text-secondary);
            margin-bottom: 16px;
        }}

        .poc-section {{
            background: var(--bg-tertiary);
            border-radius: 6px;
            padding: 16px;
            margin-top: 12px;
        }}

        .poc-title {{
            font-size: 13px;
            font-weight: 600;
            color: var(--accent-blue);
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 6px;
        }}

        .poc-command {{
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            padding: 12px;
            font-family: 'SF Mono', Consolas, monospace;
            font-size: 13px;
            overflow-x: auto;
            position: relative;
        }}

        .poc-command code {{
            color: var(--accent-green);
        }}

        .copy-btn {{
            position: absolute;
            top: 8px;
            right: 8px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            padding: 4px 8px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
        }}

        .copy-btn:hover {{
            background: var(--border-color);
            color: var(--text-primary);
        }}

        .evidence {{
            margin-top: 12px;
        }}

        .evidence-title {{
            font-size: 13px;
            font-weight: 600;
            color: var(--accent-purple);
            margin-bottom: 8px;
        }}

        .evidence-output {{
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            padding: 12px;
            font-family: 'SF Mono', Consolas, monospace;
            font-size: 12px;
            white-space: pre-wrap;
            word-break: break-all;
            max-height: 200px;
            overflow-y: auto;
        }}

        .success-output {{ color: var(--accent-green); }}
        .error-output {{ color: var(--accent-red); }}

        .risk-assessment {{
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            padding: 12px;
            margin-top: 12px;
        }}

        .risk-title {{
            font-size: 13px;
            font-weight: 600;
            color: var(--accent-orange);
            margin-bottom: 8px;
        }}

        .risk-item {{
            display: flex;
            align-items: flex-start;
            gap: 8px;
            margin-bottom: 6px;
            font-size: 13px;
        }}

        .risk-icon {{ color: var(--accent-red); }}

        .empty-state {{
            padding: 40px;
            text-align: center;
            color: var(--text-secondary);
        }}

        footer {{
            text-align: center;
            padding: 20px;
            color: var(--text-secondary);
            font-size: 13px;
        }}

        footer a {{
            color: var(--accent-blue);
            text-decoration: none;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>
                <span class="icon">🔬</span>
                Dynamic Analysis Report
            </h1>
            <div class="meta-grid">
                <div class="meta-item">
                    <div class="meta-label">Package</div>
                    <div class="meta-value">{package}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Device</div>
                    <div class="meta-value">{device}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Duration</div>
                    <div class="meta-value">{_calculate_duration(start_time, end_time)}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Total Tests</div>
                    <div class="meta-value">{summary.get('total', 0)}</div>
                </div>
            </div>
        </header>

        <div class="summary-cards">
            <div class="summary-card confirmed">
                <div class="summary-number">{summary.get('confirmed', 0)}</div>
                <div class="summary-label">Confirmed</div>
            </div>
            <div class="summary-card likely">
                <div class="summary-number">{len(likely)}</div>
                <div class="summary-label">Likely Vulnerable</div>
            </div>
            <div class="summary-card inconclusive">
                <div class="summary-number">{summary.get('inconclusive', 0)}</div>
                <div class="summary-label">Inconclusive</div>
            </div>
            <div class="summary-card safe">
                <div class="summary-number">{summary.get('not_vulnerable', 0)}</div>
                <div class="summary-label">Not Vulnerable</div>
            </div>
        </div>

        {_render_findings_section("🔴 Confirmed Vulnerabilities", confirmed, "confirmed")}
        {_render_findings_section("🟠 Likely Vulnerable", likely, "likely")}
        {_render_findings_section("🟡 Inconclusive", inconclusive, "inconclusive")}
        {_render_findings_section("🟢 Not Vulnerable", not_vuln, "safe")}

        <footer>
            Generated by <strong>MSRA</strong> &mdash; Built by Sai with love &#10084;
            &mdash; {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </footer>
    </div>

    <script>
        function copyCommand(btn) {{
            const code = btn.parentElement.querySelector('code');
            navigator.clipboard.writeText(code.textContent);
            btn.textContent = 'Copied!';
            setTimeout(() => btn.textContent = 'Copy', 2000);
        }}
    </script>
</body>
</html>'''

    with open(output_path, 'w') as f:
        f.write(html_content)

    return output_path


def _calculate_duration(start: str, end: str) -> str:
    """Calculate duration between two ISO timestamps."""
    try:
        start_dt = datetime.fromisoformat(start)
        end_dt = datetime.fromisoformat(end)
        duration = (end_dt - start_dt).total_seconds()
        return f"{int(duration)}s"
    except:
        return "N/A"


def _render_findings_section(title: str, findings: List[Dict], section_type: str) -> str:
    """Render a section of findings."""
    if not findings:
        return ""

    findings_html = ""
    for f in findings:
        findings_html += _render_finding(f)

    return f'''
        <section>
            <div class="section-header">
                <h2>{title}</h2>
                <span class="count">{len(findings)}</span>
            </div>
            {findings_html}
        </section>
    '''


def _render_finding(finding: Dict) -> str:
    """Render a single finding."""
    title = html.escape(finding.get('title', finding.get('finding_id', 'Unknown')))
    severity = finding.get('severity', 'medium').lower()
    confidence = finding.get('confidence', 0)
    notes = html.escape(finding.get('notes', ''))
    evidence = finding.get('evidence', {})

    # Handle both legacy (dict) and new (list) evidence formats
    poc_command = ''
    poc_output = ''
    if isinstance(evidence, dict):
        poc_command = evidence.get('command', '')
        poc_output = evidence.get('output', '')
    elif isinstance(evidence, list) and evidence:
        # New format: list of evidence objects
        for e in evidence:
            if isinstance(e, dict):
                if e.get('type') == 'command':
                    poc_command = e.get('data', '') or e.get('description', '')
                elif e.get('type') in ['screenshot', 'logcat', 'hook']:
                    poc_output = e.get('description', '')

    # Generate risk assessment based on finding type
    risk_html = _generate_risk_assessment(finding)

    # Format PoC section
    poc_html = ""
    if poc_command:
        escaped_cmd = html.escape(poc_command)
        poc_html = f'''
            <div class="poc-section">
                <div class="poc-title">⚡ Proof of Concept</div>
                <div class="poc-command">
                    <code>{escaped_cmd}</code>
                    <button class="copy-btn" onclick="copyCommand(this)">Copy</button>
                </div>
            </div>
        '''

    # Format evidence output
    evidence_html = ""
    if poc_output:
        escaped_output = html.escape(poc_output[:1000])
        output_class = "success-output" if finding.get('status') == 'confirmed' else ""
        evidence_html = f'''
            <div class="evidence">
                <div class="evidence-title">📋 Command Output</div>
                <div class="evidence-output {output_class}">{escaped_output}</div>
            </div>
        '''

    confidence_pct = int(confidence * 100)

    return f'''
        <div class="finding">
            <div class="finding-header">
                <div class="finding-title">
                    <span class="severity-badge severity-{severity}">{severity}</span>
                    {title}
                </div>
                <div class="confidence">Confidence: {confidence_pct}%</div>
            </div>
            <div class="finding-notes">{notes}</div>
            {poc_html}
            {evidence_html}
            {risk_html}
        </div>
    '''


def _generate_risk_assessment(finding: Dict) -> str:
    """Generate risk assessment based on finding type."""
    title = finding.get('title', '').lower()
    risks = []

    if 'webview' in title:
        risks = [
            "Attacker can load malicious URLs in the WebView",
            "Potential JavaScript injection (XSS) if JavaScript is enabled",
            "Possible access to local files via file:// URLs",
            "Cookie/session theft if WebView handles sensitive data",
        ]
    elif 'activity' in title and 'exported' in title:
        risks = [
            "Activity can be launched by any app without permission",
            "May expose internal functionality to unauthorized apps",
            "Potential for UI spoofing/phishing attacks",
            "Could bypass authentication if activity handles sensitive actions",
        ]
    elif 'provider' in title:
        risks = [
            "Content provider data may be accessible to other apps",
            "Potential SQL injection if queries aren't parameterized",
            "Path traversal if file paths aren't validated",
            "Sensitive data exposure (PII, credentials, tokens)",
        ]
    elif 'service' in title:
        risks = [
            "Service can be started by malicious apps",
            "May perform privileged operations without proper checks",
            "Potential for denial of service attacks",
        ]
    elif 'receiver' in title:
        risks = [
            "Broadcast receiver accepts intents from any app",
            "Could trigger unintended app behavior",
            "May expose sensitive information in responses",
        ]

    if not risks:
        return ""

    risks_html = "".join([f'<div class="risk-item"><span class="risk-icon">⚠</span>{html.escape(r)}</div>' for r in risks])

    return f'''
        <div class="risk-assessment">
            <div class="risk-title">🎯 Security Risks</div>
            {risks_html}
        </div>
    '''
