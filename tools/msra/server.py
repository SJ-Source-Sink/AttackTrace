"""
MSRA — Mobile Security Review Assistant
========================================
Single-page dashboard: upload APKs, browse scans in the sidebar,
view the full report inline — no separate pages.

Usage:
    python server.py
    ANTHROPIC_API_KEY=sk-ant-... python server.py
    python server.py --port 8080
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import logging
import os
import re
import shutil
import sys
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
import uuid
import zipfile
import tempfile
import urllib.request
import urllib.error
from pathlib import Path

from flask import Flask, Response, abort, jsonify, redirect, request, send_file

sys.path.insert(0, os.path.dirname(__file__))

from msra.scanner import Scanner
from msra.report import generate_html_report
from msra.utils import iter_source_files
from msra import rules_api
from msra.corellium import CorelliumClient
import msra.db as _db

# ── Config ───────────────────────────────────────────────────────────────
UPLOAD_FOLDER   = Path(__file__).parent / "uploads"
REPORTS_FOLDER  = Path(__file__).parent / "reports"
UPLOAD_FOLDER.mkdir(exist_ok=True)
REPORTS_FOLDER.mkdir(exist_ok=True)

DATA_DIR        = Path(__file__).parent / "data"
CUSTOM_DIR      = DATA_DIR / "custom"
DYNAMIC_CFG_F   = CUSTOM_DIR / "dynamic_config.json"

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
CLAUDE_MODEL      = "claude-sonnet-4-6"

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024  # 500 MB

# ── Dynamic analysis job state ────────────────────────────────────────────
import time as _time

_log = logging.getLogger(__name__)


def _load_dynamic_cfg() -> dict:
    if DYNAMIC_CFG_F.exists():
        try:
            return json.loads(DYNAMIC_CFG_F.read_text())
        except Exception:
            pass
    return {"mode": "adb", "corellium_url": "https://app.corellium.com",
            "corellium_token": "", "instance_id": ""}


def _save_dynamic_cfg(cfg: dict):
    CUSTOM_DIR.mkdir(parents=True, exist_ok=True)
    DYNAMIC_CFG_F.write_text(json.dumps(cfg, indent=2))


def _update_job(job_id: str, **kwargs):
    _db.upsert_job(job_id, **kwargs)


def _run_adb(cmd: list, timeout: int = 15) -> tuple[int, str, str]:
    """Run an ADB command, return (returncode, stdout, stderr)."""
    import subprocess as _sp
    try:
        r = _sp.run(["adb"] + cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return -1, "", "adb not found in PATH"
    except _sp.TimeoutExpired:
        return -1, "", "adb command timed out"
    except Exception as e:
        return -1, "", str(e)


def _get_logcat(device_serial: str | None = None, lines: int = 300,
                package: str | None = None) -> str:
    """Capture recent logcat from a device."""
    import subprocess as _sp
    args = ["adb"]
    if device_serial:
        args += ["-s", device_serial]
    args += ["logcat", "-d", "-t", str(lines)]
    if package:
        _pid = _get_app_pid(device_serial, package)
        if _pid:
            args += ["--pid", _pid]
    try:
        r = _sp.run(args, capture_output=True, text=True, timeout=20)
        return r.stdout or r.stderr
    except Exception as e:
        return f"logcat error: {e}"


def _get_app_pid(device_serial: str | None, package: str) -> str:
    args = ["-s", device_serial] if device_serial else []
    _, out, _ = _run_adb(args + ["shell", f"pidof {package}"])
    return out.strip() or ""


def _ai_verify_finding(finding_title: str, finding_desc: str, severity: str,
                        category: str, logcat: str, extra_evidence: str,
                        api_key: str) -> dict:
    """Call Claude to determine if a static finding is a true positive."""
    # Build category-specific verification guidance
    cat_lower = category.lower()
    if "contentprovider" in cat_lower or "owasp-m4" in cat_lower or "injection" in cat_lower:
        specific_guidance = """For SQL injection / ContentProvider findings, look for:
- SQL error messages: "syntax error", "unrecognized token", "no such column", "ambiguous"
- Schema data returned: sqlite_master, sqlite_sequence rows
- Row data returned for a malformed WHERE clause
- SQLiteException in logcat
FALSE POSITIVE signals: "permission denied", provider not exported, exception thrown before query"""
    elif "webview" in cat_lower or "deeplink" in cat_lower:
        specific_guidance = """For WebView / DeepLink findings, look for:
- JavaScript URI execution: logcat shows JS context, alert dialogs, console.log output
- File URI loading: file:// content in WebView (file:///etc/passwd, /sdcard/)
- External URL redirect: app navigated to attacker-controlled domain
- addJavascriptInterface accessible from untrusted content
FALSE POSITIVE signals: WebView disabled, deeplink rejected by intent filter, security policy blocks JS"""
    elif "credential" in cat_lower or "owasp-m1" in cat_lower or "cryptography" in cat_lower:
        specific_guidance = """For credential/crypto findings, look for:
- Plaintext secrets in logcat: password=, api_key=, Bearer token, JWT (eyJ...)
- SharedPreferences XML containing raw credentials
- Weak cipher in use: DES, RC4, ECB mode, MD5 password hashing
- Hardcoded key patterns: AKIA (AWS), AIza (Google), private key headers
FALSE POSITIVE signals: test/demo credentials only, values properly encrypted at rest"""
    elif "network" in cat_lower or "cleartext" in cat_lower or "tls" in cat_lower or "ssl" in cat_lower:
        specific_guidance = """For network/TLS findings, look for:
- HTTP URLs in logcat without TLS: "http://" connections to non-localhost endpoints
- Certificate validation bypass: SSLHandshakeException suppressed, custom TrustManager
- Sensitive data in HTTP body/URL (cleartext PII, tokens)
- MITM evidence: unexpected certificate issuer in logcat
FALSE POSITIVE signals: only localhost or debug HTTP traffic, proper HTTPS everywhere"""
    elif "intent" in cat_lower or "component" in cat_lower or "broadcast" in cat_lower:
        specific_guidance = """For Intent / exported component findings, look for:
- Activity/service successfully started by external am start command
- Broadcast receiver triggered externally, unexpected behavior
- Data passed via Intent extras reaches sensitive operations
- PendingIntent hijack: component intercepts pending intent
FALSE POSITIVE signals: component requires permission that probe doesn't have, not actually exported"""
    elif "storage" in cat_lower or "owasp-m9" in cat_lower:
        specific_guidance = """For data storage findings, look for:
- World-readable files found in /data/data/<package>
- Sensitive data written to external storage (/sdcard/)
- Database files accessible without root (run-as worked)
- Backup enabled + sensitive data included in backup
FALSE POSITIVE signals: files properly permission-restricted, encryption in use"""
    else:
        specific_guidance = """Look for runtime evidence that confirms the static finding:
- Exceptions or errors triggered by probe commands
- Sensitive data appearing in logcat
- Unexpected behavior when interacting with the component
FALSE POSITIVE signals: access denied, feature disabled at runtime, test environment differences"""

    security_logcat = _extract_security_logcat(logcat)

    prompt = f"""You are a senior Android security engineer performing runtime verification of a static analysis finding.

FINDING UNDER REVIEW:
- Title: {finding_title}
- Severity: {severity}
- Category: {category}
- Description: {finding_desc}

RUNTIME EVIDENCE:
--- SECURITY-RELEVANT LOGCAT LINES ---
{security_logcat[:4000]}

--- ADB PROBE OUTPUT & ADDITIONAL EVIDENCE ---
{extra_evidence[:3000]}

VERIFICATION GUIDANCE FOR THIS CATEGORY:
{specific_guidance}

TASK: Determine whether this finding is exploitable at runtime.

Consider:
1. Does the evidence CONFIRM the vulnerability is triggerable? (true_positive)
2. Does the evidence show the app is PROTECTED at runtime? (false_positive)
3. Is evidence INSUFFICIENT to conclude either way? (uncertain)

Common reasons findings are false positives at runtime:
- Android OS permissions block the attack vector
- The code path is never reached
- A newer Android version mitigates the issue
- Emulator/test environment differs from production

Return ONLY valid JSON:
{{
  "verdict": "true_positive" | "false_positive" | "uncertain",
  "confidence": 0-100,
  "reasoning": "2-3 sentences citing specific evidence lines that support the verdict",
  "key_evidence": ["exact log line or probe output snippet that is most significant"],
  "risk_context": "one sentence on the real-world impact if this is exploitable",
  "suggested_action": "specific next step for the analyst"
}}"""

    try:
        payload = json.dumps({
            "model": CLAUDE_MODEL,
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": prompt}]
        }).encode()
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=payload,
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            result = json.loads(resp.read())
        raw = result["content"][0]["text"].strip()
        raw = re.sub(r'^```(?:json)?\s*', '', raw, flags=re.MULTILINE)
        raw = re.sub(r'\s*```$', '', raw, flags=re.MULTILINE)
        verdict = json.loads(raw)
        return verdict
    except Exception as e:
        return {
            "verdict": "uncertain",
            "confidence": 0,
            "reasoning": f"AI analysis failed: {e}",
            "key_evidence": [],
            "risk_context": "Manual review required — AI analysis unavailable.",
            "suggested_action": "Review evidence manually",
            "mode": "error",
        }


def _extract_security_logcat(logcat: str) -> str:
    """
    Filter raw logcat to only lines relevant for security analysis.
    Reduces noise; keeps exceptions, security events, and app I/O.
    """
    SECURITY_KEYWORDS = re.compile(
        r'exception|error|crash|deny|denied|permission|security|ssl|tls|certificate|'
        r'password|token|secret|credential|api.?key|jwt|bearer|auth|'
        r'sqlite|database|cursor|content:/|query|inject|'
        r'webview|javascript|loadurl|file://|intent|deeplink|'
        r'http://|cleartext|network|socket|'
        r'warning|fatal|anr|signal',
        re.IGNORECASE,
    )
    lines = logcat.splitlines()
    relevant = [ln for ln in lines if SECURITY_KEYWORDS.search(ln)]
    # Always keep first/last 10 lines for context
    context = lines[:10] + lines[-10:]
    merged  = list(dict.fromkeys(relevant + context))  # deduplicate, preserve order
    return "\n".join(merged[:300])


def _heuristic_verdict(extra_evidence: str, logcat: str, category: str) -> dict:
    """
    Produce a heuristic verdict from ADB probe output without calling AI.
    Uses regex-based contextual matching to minimise false positives.
    Returns same dict shape as _ai_verify_finding().
    """
    ev        = (extra_evidence + "\n" + logcat).lower()
    log_lower = logcat.lower()
    cat_lower = category.lower()
    key_evidence: list = []
    score = 0

    # ── SQL injection: require SQL error / schema keywords in context ─────────
    _SQL_ERRORS = [
        r'sqlite3?exception',
        r'unrecognized token',
        r'syntax error.*near',
        r'no such (column|table)\b',
        r'ambiguous column name',
        r'exception in android\.database',
        r'malformed query',
        r'near "[^"]+": syntax error',
        r'android\.database\.sqlite\.sqlite\w*exception',
    ]
    _SQL_EXPOSURE = [
        r'sqlite_master',
        r'sqlite_sequence',
        r'android_metadata',
        r'select.{1,60}from.{1,30}sqlite_master',
        r'union\s+select.{1,60}from',
    ]
    for pat in _SQL_ERRORS:
        if re.search(pat, ev):
            score += 20
            key_evidence.append(f"SQL error pattern matched: {pat}")
            break
    for pat in _SQL_EXPOSURE:
        if re.search(pat, ev):
            score += 35
            key_evidence.append(f"SQL schema exposure detected: {pat}")
            break

    # ── Credential / token leak — require key=value context ──────────────────
    _CRED_PATTERNS = [
        (r'password\s*[:=]\s*\S{4,}',             "password value in logcat"),
        (r'passwd\s*[:=]\s*\S{4,}',               "passwd value in logcat"),
        (r'api[_-]?key\s*[:=]\s*[a-z0-9_-]{10,}', "API key in logcat"),
        (r'bearer\s+[a-z0-9_.\-]{20,}',           "Bearer token in logcat"),
        (r'eyj[a-z0-9_-]+\.[a-z0-9_-]+\.[a-z0-9_-]+', "JWT in logcat"),
        (r'akia[0-9a-z]{16}',                     "AWS access key in logcat"),
        (r'aiza[0-9a-z_\-]{35}',                  "Google API key in logcat"),
        (r'-----begin\s+(?:rsa\s+)?private key',  "Private key material in logcat"),
    ]
    for pat, label in _CRED_PATTERNS:
        if re.search(pat, log_lower):
            score += 30
            key_evidence.append(label)

    # ── Path traversal success ─────────────────────────────────────────────────
    _TRAVERSAL_HIT = [
        (r'root:\w*:0:0',           "passwd file content (root:x:0:0)"),
        (r'#!/bin/(sh|bash)',        "Shell script content exposed"),
        (r'/etc/passwd',             "/etc/passwd path in output"),
        (r'/data/data/[a-z.]+/[^/]', "Internal app data path exposed"),
        (r'<manifest\b',             "AndroidManifest.xml content exposed"),
    ]
    for pat, label in _TRAVERSAL_HIT:
        if re.search(pat, ev):
            score += 40
            key_evidence.append(f"Path traversal confirmed: {label}")
            break

    # ── WebView / DeepLink exploitation ──────────────────────────────────────
    if "webview" in cat_lower or "deeplink" in cat_lower:
        if re.search(r'javascript:', ev) and re.search(r'(execut|load|evaluat)', ev):
            score += 35
            key_evidence.append("JavaScript URI executed in WebView")
        if re.search(r'file://.*\.(xml|json|db|passwd|sqlite)', ev):
            score += 30
            key_evidence.append("Sensitive file URI accessed in WebView")
        if re.search(r'addjavascriptinterface', log_lower):
            score += 15
            key_evidence.append("JavaScript interface exposed to WebView")

    # ── ContentProvider returned rows ────────────────────────────────────────
    if "contentprovider" in cat_lower or "owasp-m4" in cat_lower:
        if re.search(r'row \d+:', ev):
            score += 25
            key_evidence.append("ContentProvider returned data rows for probe query")
        if re.search(r'_id\s*=\s*\d', ev):
            score += 15
            key_evidence.append("Database row returned (_id column visible)")

    # ── Security exceptions / crashes that confirm a trigger ─────────────────
    _CRASH_CONFIRM = [
        r'java\.lang\.securityexception(?!.*permission denied)',
        r'fatal exception.*main',
        r'illegalargumentexception.*inject',
        r'force.{1,5}clos',
    ]
    for pat in _CRASH_CONFIRM:
        if re.search(pat, ev):
            score += 12
            key_evidence.append(f"Security-related exception triggered: {pat}")

    # ── Cleartext network traffic ────────────────────────────────────────────
    if re.search(r'http://(?!localhost|127\.0\.0\.1|10\.)', ev):
        score += 10
        key_evidence.append("Cleartext HTTP traffic to external host detected")

    # ── Negative signals (reduce score) ──────────────────────────────────────
    if re.search(r'permission denied', ev):
        penalty = 25 if re.search(r'securityexception.*permission', ev) else 15
        score -= penalty
        key_evidence.append("Permission check blocked probe access")

    if re.search(r'no such provider|unknown uri|uriparser.*error', ev):
        score -= 20
        key_evidence.append("Provider rejected or unknown — URI not accessible")

    if re.search(r'ssl.*handshake|certificate.*pinning|pinning.*failed', ev):
        score -= 10
        key_evidence.append("Certificate pinning may be active")

    # ── Verdict ───────────────────────────────────────────────────────────────
    score = max(score, 0)  # floor at 0

    if score >= 40:
        verdict    = "true_positive"
        confidence = min(90, 55 + score)
        reasoning  = (
            "Runtime probes produced strong indicators consistent with exploitability. "
            "Manual confirmation recommended before reporting to developers."
        )
    elif score >= 15:
        verdict    = "uncertain"
        confidence = min(55, 30 + score)
        reasoning  = (
            "Partial indicators present but evidence is not conclusive. "
            "Run AI-Enhanced Scan or perform manual exploitation attempt."
        )
    else:
        verdict    = "false_positive"
        confidence = 65
        reasoning  = (
            "No strong runtime indicators detected in probe output or logcat. "
            "Finding may be a false positive, or vulnerability requires specific "
            "user interaction / device state not present in automated probing."
        )

    if not key_evidence:
        key_evidence = ["No distinctive security indicators found in runtime output"]

    return {
        "verdict":          verdict,
        "confidence":       confidence,
        "reasoning":        reasoning,
        "key_evidence":     key_evidence,
        "risk_context":     "Heuristic analysis — accuracy limited without AI or manual testing.",
        "suggested_action": (
            "Confirm with manual testing or run AI-Enhanced Scan for deeper analysis."
            if verdict != "false_positive"
            else "Review static analysis context — likely a false positive or requires manual trigger."
        ),
        "mode": "heuristic",
    }


def _launch_app_am(serial_args: list, package: str, timeout: int = 15) -> bool:
    """Launch app via am start (more reliable than monkey for specific activities)."""
    # Try am start with MAIN/LAUNCHER first
    rc, out, err = _run_adb(
        serial_args + ["shell", "am", "start", "-n",
                       f"{package}/{package}.MainActivity",
                       "-a", "android.intent.action.MAIN",
                       "-c", "android.intent.category.LAUNCHER"],
        timeout=timeout)
    if rc == 0 and "error" not in (out + err).lower():
        return True
    # Fallback: query the launcher activity from package manager
    _, pm_out, _ = _run_adb(
        serial_args + ["shell", "cmd", "package", "resolve-activity",
                       "--brief", package], timeout=8)
    for line in pm_out.splitlines():
        line = line.strip()
        if "/" in line and not line.startswith("priority"):
            rc2, _, _ = _run_adb(
                serial_args + ["shell", "am", "start", "-n", line,
                               "-a", "android.intent.action.MAIN",
                               "-c", "android.intent.category.LAUNCHER"],
                timeout=timeout)
            if rc2 == 0:
                return True
    # Last resort: monkey (1 event)
    rc3, _, _ = _run_adb(
        serial_args + ["shell", "monkey", "-p", package,
                       "-c", "android.intent.category.LAUNCHER", "1"],
        timeout=timeout)
    return rc3 == 0


def _fs_snapshot(serial_args: list, package: str) -> set:
    """Snapshot /data/data/<package> file list for diff after probing."""
    _, out, _ = _run_adb(
        serial_args + ["shell", "run-as", package,
                       "find", f"/data/data/{package}", "-type", "f"],
        timeout=15)
    return set(out.splitlines())


def _fs_diff(before: set, after: set) -> list:
    """Return files created or modified since snapshot."""
    return sorted(after - before)


def _frida_load_all_hooks(serial_args: list, package: str) -> list:
    """
    Attempt to load all Frida hooks via subprocess frida CLI.
    Returns list of log lines collected (best-effort; requires frida-tools + frida-server on device).
    """
    import subprocess as _sp, shutil as _sh, tempfile as _tf
    frida_bin = _sh.which("frida")
    if not frida_bin:
        return []

    hooks_dir = Path(__file__).parent / "msra" / "dynamic" / "instrumentation" / "hooks"
    hook_files = ["ssl_bypass.js", "root_bypass.js", "emulator_bypass.js", "api_monitor.js"]
    combined_js = ""
    for hf in hook_files:
        p = hooks_dir / hf
        if p.exists():
            combined_js += f"\n// === {hf} ===\n" + p.read_text(encoding="utf-8") + "\n"

    if not combined_js:
        return []

    tmp = _tf.NamedTemporaryFile(suffix=".js", delete=False, mode="w", encoding="utf-8")
    tmp.write(combined_js)
    tmp.flush()
    tmp_path = tmp.name
    tmp.close()

    serial_flag = ["-D", serial_args[1]] if len(serial_args) >= 2 else []
    logs = []
    try:
        r = _sp.run(
            [frida_bin] + serial_flag + ["-f", package, "--no-pause", "-l", tmp_path,
                                          "--runtime=v8", "-q", "--json"],
            capture_output=True, text=True, timeout=30)
        logs = r.stdout.splitlines()[:200]
    except Exception:
        pass
    finally:
        try:
            import os as _os
            _os.unlink(tmp_path)
        except Exception:
            pass
    return logs


def _dynamic_verify_worker(job_id: str, scan_id: str, finding_idx: int,
                            finding: dict, cfg: dict, use_ai: bool = True):
    """
    Enterprise-grade dynamic analysis pipeline:
      Phase 1 — Device setup & hardening bypass
      Phase 2 — Frida spawn-attach with all hooks
      Phase 3 — App launch + login attempt + UI exploration
      Phase 4 — Component-level probing (all exported components)
      Phase 5 — Evidence collection & AI/heuristic verdict
    """
    try:
        _update_job(job_id, status="running", progress=5,
                    message="Preparing device connection…")

        mode          = cfg.get("mode", "adb")
        device_serial = cfg.get("adb_serial", "")   # local ADB serial
        corellium_adb = None
        client        = None

        # ── 1. Connect to device ─────────────────────────────────────────
        # Auto-fallback: use ADB if Corellium credentials are not configured
        if mode == "corellium":
            token       = cfg.get("corellium_token", "")
            instance_id = cfg.get("instance_id", "")
            if not token or not instance_id:
                _update_job(job_id, message="Corellium not configured — falling back to local ADB…", progress=6)
                mode = "adb"

        if mode == "corellium":
            base_url    = cfg.get("corellium_url", "https://app.corellium.com")
            token       = cfg.get("corellium_token", "")
            instance_id = cfg.get("instance_id", "")
            client = CorelliumClient(token, base_url)
            inst   = client.get_instance(instance_id)
            if not inst.is_on:
                _update_job(job_id, message="Starting Corellium instance…", progress=8)
                client.start_instance(instance_id)
                # Wait up to 60 s for it to come online
                for _ in range(12):
                    _time.sleep(5)
                    inst = client.get_instance(instance_id)
                    if inst.is_on:
                        break
            if inst.adb_addr:
                corellium_adb = inst.adb_addr
                _run_adb(["connect", corellium_adb], timeout=10)
                device_serial = corellium_adb
            _update_job(job_id, message=f"Connected to Corellium: {inst.name}", progress=15)
        else:
            _update_job(job_id, message="Using local ADB device", progress=15)

        # ── 2. Clear logcat BEFORE install/launch so we capture all startup logs ──
        package = finding.get("package", "")
        _update_job(job_id, progress=18, message="Clearing logcat buffer…")
        _run_adb((["-s", device_serial] if device_serial else []) + ["logcat", "-c"], timeout=5)

        # ── 3. Install APK ───────────────────────────────────────────────
        scan_dir = _scan_dir(scan_id)
        apk_candidates = list(scan_dir.glob("*.apk"))
        _update_job(job_id, progress=20, message="Checking APK installation…")

        if apk_candidates:
            # ADB install breaks if the filename contains shell-special chars
            # like parentheses or commas (e.g. apkmirror filenames).
            # Also unwrap XAPK/APKM bundles to extract base.apk first.
            import tempfile as _tempfile
            _src_apk = apk_candidates[0]
            # If the file is a zip bundle containing base.apk, extract it
            try:
                if zipfile.is_zipfile(str(_src_apk)):
                    with zipfile.ZipFile(str(_src_apk)) as _zf:
                        if "base.apk" in _zf.namelist():
                            _tmp_base = Path(_tempfile.gettempdir()) / "msra_base.apk"
                            _tmp_base.write_bytes(_zf.read("base.apk"))
                            _src_apk = _tmp_base
                            _update_job(job_id, progress=21,
                                        message="XAPK bundle detected — extracting base.apk…")
            except Exception:
                pass
            _tmp_apk = Path(_tempfile.gettempdir()) / "msra_install.apk"
            shutil.copy2(str(_src_apk), str(_tmp_apk))
            apk_path = str(_tmp_apk)
            _serial_args = ["-s", device_serial] if device_serial else []
            # Disable Play Protect / package verifier so ADB installs aren't blocked
            _run_adb(_serial_args + ["shell", "settings", "put", "global",
                                     "verifier_verify_adb_installs", "0"], timeout=5)
            _run_adb(_serial_args + ["shell", "settings", "put", "global",
                                     "package_verifier_enable", "0"], timeout=5)
            adb_args = _serial_args + ["install", "-r", "-t", apk_path]
            _update_job(job_id, progress=22, message="Installing APK on device…")
            rc, out, err = _run_adb(adb_args, timeout=120)
            # Re-enable verifier after install attempt
            _run_adb(_serial_args + ["shell", "settings", "put", "global",
                                     "verifier_verify_adb_installs", "1"], timeout=5)
            _run_adb(_serial_args + ["shell", "settings", "put", "global",
                                     "package_verifier_enable", "1"], timeout=5)
            install_combined = (out + err).lower()
            if rc != 0 and "already installed" not in install_combined:
                raw = (err or out).strip()
                if "no_matching_abis" in install_combined or "no matching abis" in install_combined:
                    msg = ("APK architecture mismatch — this APK is built for armeabi/x86 but your "
                           "device/emulator runs arm64-v8a or x86_64. Download the arm64 or "
                           "universal APK variant from APKMirror and re-scan.")
                elif "install_failed_version_downgrade" in install_combined:
                    msg = "Install failed: a newer version is already installed. Uninstall it first."
                elif "install_failed_insufficient_storage" in install_combined:
                    msg = "Install failed: not enough storage on device."
                elif "install_failed_user_restricted" in install_combined:
                    msg = "Install failed: unknown sources / USB install is disabled in device settings."
                elif "verification_failure" in install_combined or "install_failed_verification" in install_combined:
                    msg = ("Install blocked by Play Protect even after disabling verifier. "
                           "On device: Play Store → Profile → Play Protect → disable 'Scan apps with Play Protect'.")
                elif "install_parse_failed" in install_combined or "unexpected_exception" in install_combined:
                    msg = ("APK parse failed — the file may be an XAPK/APKS bundle (multiple split APKs) "
                           "rather than a single APK. Download the full universal APK from APKMirror "
                           "(look for the '(nodpi)' or 'universal' variant, not the '(bundle)' one) "
                           "and re-scan. Alternatively extract the base.apk from the XAPK zip manually.")
                else:
                    msg = f"APK install failed: {raw[:200]}"
                _update_job(job_id, status="error", message=msg, progress=22)
                return
            # Verify package is actually registered before launching
            app_registered = False
            if package:
                for _ in range(6):
                    _time.sleep(2)
                    _, pm_out, _ = _run_adb(
                        (["-s", device_serial] if device_serial else []) + ["shell", "pm", "path", package],
                        timeout=5)
                    if "package:" in pm_out:
                        app_registered = True
                        break
            if package and not app_registered:
                _update_job(job_id, status="error",
                            message=f"APK installed but package '{package}' not found on device — wrong architecture?",
                            progress=22)
                return
        elif package:
            # No APK in scan dir — verify app is already installed
            _, pm_out, _ = _run_adb(
                (["-s", device_serial] if device_serial else []) + ["shell", "pm", "path", package],
                timeout=5)
            if "package:" not in pm_out:
                _update_job(job_id, status="error",
                            message=f"Package '{package}' is not installed on device and no APK was found in the scan. "
                                    f"Install the APK on your device first, then retry.",
                            progress=22)
                return

        _update_job(job_id, progress=28, message=f"Launching {package}…")

        # ── Phase 2: Frida spawn+attach with ALL hooks (best-effort) ─────
        frida_logs = []
        if package:
            _update_job(job_id, progress=29, message="Attaching Frida instrumentation…")
            frida_logs = _frida_load_all_hooks(
                (["-s", device_serial] if device_serial else []), package)

        # ── Phase 3: Launch app properly ─────────────────────────────────
        _update_job(job_id, progress=30, message=f"Launching {package} via am start…")
        adb_prefix = (["-s", device_serial] if device_serial else [])
        _device_ok = False
        if package:
            launched = _launch_app_am(adb_prefix, package, timeout=20)
            if not launched:
                _update_job(job_id, progress=32,
                            message=f"Warning: could not confirm launch of {package} — proceeding anyway")
            else:
                _device_ok = True
            if _device_ok:
                _time.sleep(6)   # wait for app to fully initialize

        # Take filesystem snapshot before probing
        fs_before: set = set()
        if package and _device_ok:
            fs_before = _fs_snapshot(adb_prefix, package)

        _update_job(job_id, progress=38, message="App running — observing startup behavior…")
        if _device_ok:
            _time.sleep(6)   # observe startup network/logcat

        # ── Phase 3b: Login attempt ───────────────────────────────────────
        # Try filling login form with common test credentials so BFS
        # can reach authenticated code paths
        login_attempted = False
        if package and use_ai:
            try:
                _update_job(job_id, progress=40, message="Attempting login screen detection…")
                # Check logcat for login-related keywords
                login_logcat = _get_logcat(adb_prefix[1] if len(adb_prefix) >= 2 else None,
                                          lines=50, package=package)
                # Look for login activity indicators
                if re.search(r'login|sign.?in|auth|credential', login_logcat, re.I):
                    # Try UIAutomator2 to fill credentials if available
                    rc_ui, _, _ = _run_adb(adb_prefix + ["shell",
                        "input", "text", "test@example.com"], timeout=5)
                    _run_adb(adb_prefix + ["shell", "input", "keyevent", "61"], timeout=3)
                    _run_adb(adb_prefix + ["shell", "input", "text", "Password123!"], timeout=5)
                    _run_adb(adb_prefix + ["shell", "input", "keyevent", "66"], timeout=3)
                    login_attempted = True
                    _time.sleep(3)
            except Exception:
                pass

        # ── Phase 4: Targeted ADB probes (all exported components) ────────
        _update_job(job_id, progress=45, message="Running targeted security probes…")
        category  = finding.get("category", "")
        cat_lower = category.lower()
        extra_evidence = ""

        # Frida hook evidence
        if frida_logs:
            frida_evidence = "\n".join(frida_logs[:80])
            extra_evidence += f"\n=== Frida Hook Events ===\n{frida_evidence}\n"

        # Enumerate ALL exported components up front
        _update_job(job_id, progress=46, message="Enumerating exported components…")
        _, dumpsys_out, _ = _run_adb(adb_prefix + ["shell", "dumpsys", "package", package],
                                     timeout=15)
        if dumpsys_out.strip():
            extra_evidence += f"\n=== Package Dump (exported components) ===\n{dumpsys_out[:1200]}\n"

        # Extract authorities from dumpsys
        authorities = re.findall(r'authority=([^\s;]+)', dumpsys_out)

        # ── 4a: ContentProvider / SQL probes ──────────────────────────────
        authority = _extract_authority(finding, package)
        # Also use authorities discovered from dumpsys
        all_authorities = list({authority} | set(authorities[:5]))

        if package and ("contentprovider" in cat_lower or "owasp-m4" in cat_lower
                        or "injection" in cat_lower or not cat_lower):
            _update_job(job_id, progress=48, message="Probing ContentProviders for SQLi…")
            sqli_payloads = [
                ("UNION SELECT",  "1=1) UNION SELECT name,sql,3 FROM sqlite_master--"),
                ("Error-based",   "' OR ''='"),
                ("Boolean blind", "1 AND 1=1"),
                ("Schema dump",   "* FROM sqlite_master--"),
                ("Stacked",       "'; SELECT * FROM sqlite_master;--"),
                ("Blind true",    "1' AND '1'='1"),
                ("Comment bypass","1'--"),
                ("Null byte",     "1\x00' OR '1'='1"),
            ]
            for auth in all_authorities[:3]:
                for payload_name, payload in sqli_payloads:
                    rc, out, err = _run_adb(
                        adb_prefix + ["shell", "content", "query",
                                      "--uri", f"content://{auth}/",
                                      "--where", payload], timeout=10)
                    combined = (out + err).strip()
                    if combined:
                        extra_evidence += (
                            f"\nSQLi [{payload_name}] on {auth}:\n{combined[:500]}\n")
                        if re.search(
                            r'sqlite_master|row \d+:|unrecognized token|syntax error|'
                            r'no such column|ambiguous|near.*syntax', combined, re.I):
                            extra_evidence += "  ^^^ SQL INJECTION CONFIRMED\n"

                # Path traversal on URI
                for traversal in ["../../../etc/passwd", "../../../../data/data",
                                  "%2F..%2F..%2Fetc%2Fpasswd"]:
                    _, out2, _ = _run_adb(
                        adb_prefix + ["shell", "content", "query",
                                      "--uri", f"content://{auth}/{traversal}"], timeout=8)
                    if out2.strip():
                        extra_evidence += f"\nPath traversal [{traversal}] on {auth}:\n{out2[:400]}\n"
                        break

                # Open query (no WHERE — data leakage)
                _, out3, _ = _run_adb(
                    adb_prefix + ["shell", "content", "query",
                                  "--uri", f"content://{auth}/"], timeout=10)
                if out3.strip():
                    extra_evidence += f"\nOpen query on {auth}:\n{out3[:800]}\n"

        # ── 4b: WebView / DeepLink probes ────────────────────────────────
        if "webview" in cat_lower or "deeplink" in cat_lower or "intent" in cat_lower or not cat_lower:
            _update_job(job_id, progress=55, message="Probing WebView/DeepLink attack surfaces…")

            # JavaScript scheme via VIEW intent
            rc, out, _ = _run_adb(
                adb_prefix + ["shell", "am", "start", "-a", "android.intent.action.VIEW",
                              "-d", "javascript:document.location='http://169.254.169.254/'"],
                timeout=10)
            extra_evidence += f"\nJS injection via VIEW: rc={rc} {out[:120]}\n"

            # file:// URI
            rc2, out2, _ = _run_adb(
                adb_prefix + ["shell", "am", "start", "-a", "android.intent.action.VIEW",
                              "-d", "file:///etc/hosts"], timeout=10)
            extra_evidence += f"\nfile:// deeplink: rc={rc2} {out2[:100]}\n"

            # data:// URI
            _run_adb(adb_prefix + ["shell", "am", "start", "-a", "android.intent.action.VIEW",
                                   "-d", "data:text/html,<script>alert(1)</script>"], timeout=10)

            # Intent extras injection against all exported activities
            exported_acts = re.findall(r'activity\s+([^\s]+)\s+filter', dumpsys_out)
            for act in exported_acts[:5]:
                for extra_key in ["url", "uri", "path", "link", "redirect", "file"]:
                    _run_adb(adb_prefix + ["shell", "am", "start", "-n",
                                          f"{package}/{act}",
                                          "--es", extra_key, "javascript:alert(document.cookie)",
                                          "--es", "path", "../../../../etc/passwd"],
                             timeout=8)

            # Post-probe logcat check
            _time.sleep(4)
            post_lc = _get_logcat(device_serial or None, lines=80, package=package)
            if re.search(r'javascript|webview|loadurl|evaluat|file://', post_lc, re.I):
                extra_evidence += f"\nPost-probe WebView logcat:\n{post_lc[:600]}\n"

        # ── 4c: Exported Activity / Service / Receiver probing ────────────
        _update_job(job_id, progress=60, message="Probing exported components directly…")
        # Null-intent crash test on all exported activities
        exported_components = re.findall(
            r'([A-Za-z][A-Za-z0-9_.]+Activity|[A-Za-z][A-Za-z0-9_.]+Service|'
            r'[A-Za-z][A-Za-z0-9_.]+Receiver)', dumpsys_out)
        crash_evidence = []
        for comp in exported_components[:8]:
            rc_c, out_c, _ = _run_adb(
                adb_prefix + ["shell", "am", "start", "-n", f"{package}/{comp}"],
                timeout=8)
            if rc_c == 0 and "error" not in out_c.lower():
                _time.sleep(1)
                # Check for crash
                _, crash_out, _ = _run_adb(
                    adb_prefix + ["shell", "dumpsys", "activity", "|",
                                  "grep", "-i", "crash"], timeout=5)
                if crash_out.strip():
                    crash_evidence.append(f"{comp}: {crash_out.strip()[:100]}")

        if crash_evidence:
            extra_evidence += f"\n=== Component Crashes ===\n" + "\n".join(crash_evidence) + "\n"

        # Exported broadcast receivers
        exported_rcvs = re.findall(
            r'Receiver\s+\{[^}]*\}\s+([A-Za-z][A-Za-z0-9_.]+)', dumpsys_out)
        for rcv in exported_rcvs[:4]:
            # Try all registered actions
            actions = re.findall(
                rf'{re.escape(rcv)}.*?action=([^\s]+)', dumpsys_out[:2000])
            for action in actions[:2]:
                _run_adb(adb_prefix + ["shell", "am", "broadcast",
                                      "-a", action, "-n", f"{package}/{rcv}"], timeout=8)

        # ── 4c-ext: ComponentProber systematic scan ───────────────────────
        if package:
            try:
                from msra.dynamic.verification.component_prober import ComponentProber as _CP
                # Build manifest_components from dumpsys output
                _cp_acts = [
                    {"name": a, "intent_filters": []}
                    for a in re.findall(
                        r'([A-Za-z][A-Za-z0-9_.]+Activity)\s+filter', dumpsys_out)[:10]
                ]
                _cp_provs = [
                    {"authority": auth, "paths": []}
                    for auth in authorities[:5]
                ]
                _cp_rcvs = [
                    {"name": r, "actions": re.findall(
                        rf'{re.escape(r)}.*?action=([^\s]+)', dumpsys_out[:3000])[:3]}
                    for r in re.findall(
                        r'([A-Za-z][A-Za-z0-9_.]+Receiver)', dumpsys_out)[:5]
                ]
                _cp_svcs = [
                    {"name": s}
                    for s in re.findall(
                        r'([A-Za-z][A-Za-z0-9_.]+Service)\s+filter', dumpsys_out)[:5]
                ]
                _comp_manifest = {
                    "activities": _cp_acts,
                    "providers": _cp_provs,
                    "receivers": _cp_rcvs,
                    "services": _cp_svcs,
                }
                _update_job(job_id, progress=62,
                            message=f"ComponentProber: probing {len(_cp_acts)} activities, "
                                    f"{len(_cp_provs)} providers, {len(_cp_rcvs)} receivers…")
                _prober = _CP(package, device_serial=device_serial or None)
                _cp_pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
                _cp_future = _cp_pool.submit(_prober.probe_all, _comp_manifest)
                _cp_pool.shutdown(wait=False)
                try:
                    _probe_results = _cp_future.result(timeout=30)
                except concurrent.futures.TimeoutError:
                    _probe_results = []
                    extra_evidence += "\nComponentProber: timed out (30s) — skipped.\n"
                _update_job(job_id, progress=64, message="Component probing done, collecting evidence…")
                _vuln_probes = [r for r in _probe_results if r.is_vulnerable]
                if _vuln_probes:
                    extra_evidence += "\n=== ComponentProber Findings ===\n"
                    for _pr in _vuln_probes[:15]:
                        extra_evidence += (
                            f"[{_pr.severity.upper()}] {_pr.component_type} "
                            f"{_pr.component} ({_pr.probe_type}): "
                            f"{_pr.evidence[:250]}\n"
                            f"PoC: {_pr.poc_command}\n\n"
                        )
                elif _probe_results:
                    extra_evidence += (
                        f"\nComponentProber: {len(_probe_results)} probes, "
                        f"no confirmed vulnerabilities.\n"
                    )
            except Exception as _cp_e:
                _log.debug("ComponentProber non-fatal: %s", _cp_e)

        # ── 4d: Credential / Storage probes ──────────────────────────────
        _update_job(job_id, progress=65, message="Probing credential and file storage…")
        if package:
            # SharedPreferences file list + content
            _, sp_out, _ = _run_adb(
                adb_prefix + ["shell", "run-as", package,
                              "find", f"/data/data/{package}/shared_prefs", "-name", "*.xml"],
                timeout=8)
            if sp_out.strip():
                extra_evidence += f"\n=== SharedPreferences files ===\n{sp_out[:400]}\n"
                # Read first prefs file content
                for pref_file in sp_out.splitlines()[:2]:
                    _, pref_content, _ = _run_adb(
                        adb_prefix + ["shell", "run-as", package, "cat", pref_file.strip()],
                        timeout=6)
                    if pref_content.strip():
                        extra_evidence += f"\n{pref_file} content:\n{pref_content[:600]}\n"
                        if re.search(r'password|token|secret|key|auth', pref_content, re.I):
                            extra_evidence += "  ^^^ SENSITIVE DATA IN PREFS\n"

            # SQLite databases — list and dump schema
            _, db_out, _ = _run_adb(
                adb_prefix + ["shell", "run-as", package,
                              "find", f"/data/data/{package}/databases", "-name", "*.db"],
                timeout=8)
            if db_out.strip():
                extra_evidence += f"\n=== SQLite databases ===\n{db_out[:300]}\n"
                for db_file in db_out.splitlines()[:2]:
                    _, schema_out, _ = _run_adb(
                        adb_prefix + ["shell", "run-as", package,
                                     "sqlite3", db_file.strip(), ".schema"],
                        timeout=8)
                    if schema_out.strip():
                        extra_evidence += f"\n{db_file} schema:\n{schema_out[:500]}\n"

            # World-readable files
            _, wr_out, _ = _run_adb(
                adb_prefix + ["shell", "find", f"/data/data/{package}",
                              "-perm", "-o=r", "-type", "f"], timeout=10)
            if wr_out.strip():
                extra_evidence += f"\n=== World-readable files ===\n{wr_out[:400]}\n"

            # External storage
            _, ext_out, _ = _run_adb(
                adb_prefix + ["shell", "find", "/sdcard/Android/data",
                              "-path", f"*{package}*"], timeout=10)
            if ext_out.strip():
                extra_evidence += f"\n=== External storage files ===\n{ext_out[:400]}\n"

        # ── 4e: Network security probes ───────────────────────────────────
        _update_job(job_id, progress=68, message="Checking network security…")
        if package:
            _, nsc_out, _ = _run_adb(
                adb_prefix + ["shell", "run-as", package,
                              "cat", f"/data/data/{package}/network_security_config.xml"],
                timeout=8)
            if nsc_out.strip():
                extra_evidence += f"\n=== Network Security Config ===\n{nsc_out[:500]}\n"

            # Check SSL pinning bypass / cert validation in logcat
            _, cert_out, _ = _run_adb(
                adb_prefix + ["shell", "run-as", package,
                              "ls", f"/data/data/{package}/files/"], timeout=6)
            if cert_out.strip():
                extra_evidence += f"\n=== App files dir ===\n{cert_out[:300]}\n"

        # ── Phase 5: Collect evidence ──────────────────────────────────────
        _update_job(job_id, progress=72, message="Capturing logcat output…")
        logcat = _get_logcat(device_serial or None, lines=600, package=package)

        # Corellium network log
        net_evidence = ""
        if client:
            _update_job(job_id, progress=74, message="Capturing Corellium network traffic…")
            net_flows = client.get_network_log(instance_id)
            if net_flows:
                net_evidence = "Network flows:\n" + "\n".join(
                    f"{f.get('method','?')} {f.get('url','?')} → {f.get('status','?')}"
                    for f in net_flows[:30])
                extra_evidence += f"\n=== Network Traffic ===\n{net_evidence}\n"

        # Cleartext HTTP detection
        if re.search(r'http://(?!localhost|127\.0\.0\.1)', logcat, re.I):
            extra_evidence += "\n[!] CLEARTEXT HTTP traffic detected in logcat\n"

        # Filesystem diff — new files created during probing
        if package and fs_before:
            fs_after = _fs_snapshot(adb_prefix, package)
            new_files = _fs_diff(fs_before, fs_after)
            if new_files:
                extra_evidence += f"\n=== New files created during probing ===\n"
                extra_evidence += "\n".join(new_files[:20]) + "\n"

        # ── Phase 5b: Verdict ─────────────────────────────────────────────
        if use_ai:
            _update_job(job_id, progress=82, message="AI analysing all evidence…")
            api_key = ANTHROPIC_API_KEY or cfg.get("anthropic_key", "")
            if api_key:
                verdict = _ai_verify_finding(
                    finding_title=finding.get("title", ""),
                    finding_desc=finding.get("description", ""),
                    severity=finding.get("severity", ""),
                    category=category,
                    logcat=_extract_security_logcat(logcat),
                    extra_evidence=extra_evidence,
                    api_key=api_key,
                )
            else:
                verdict = {
                    "verdict": "uncertain",
                    "confidence": 0,
                    "reasoning": "No API key — set ANTHROPIC_API_KEY or use Basic Scan.",
                    "key_evidence": [],
                    "risk_context": "AI analysis unavailable — configure ANTHROPIC_API_KEY.",
                    "suggested_action": "Configure API key or run Basic Scan",
                    "mode": "no_key",
                }
        else:
            _update_job(job_id, progress=82, message="Running heuristic analysis…")
            verdict = _heuristic_verdict(extra_evidence, logcat, category)

        _update_job(job_id, status="done", progress=100,
                    message="Dynamic analysis complete",
                    logcat=logcat[:8000],
                    evidence=extra_evidence[:4000],
                    verdict=verdict)

    except Exception as exc:
        _update_job(job_id, status="error", progress=100,
                    message=str(exc), verdict=None)

# ── Helpers ──────────────────────────────────────────────────────────────

def _scan_dir(scan_id: str) -> Path:
    return REPORTS_FOLDER / scan_id


def _extract_authority(finding: dict, package: str) -> str:
    """
    Extract the real ContentProvider authority from a finding's ADB commands or extra data.
    Falls back to the conventional {package}.provider guess only as a last resort.
    """
    # Try adb_commands first — they usually contain the real authority
    for cmd in finding.get("adb_commands") or []:
        m = re.search(r'content://([^/\s"\']+)', str(cmd))
        if m:
            return m.group(1)
    # Try extra dict
    extra = finding.get("extra") or {}
    if isinstance(extra, dict):
        if extra.get("authority"):
            return str(extra["authority"])
    # Fall back
    return f"{package}.provider" if package else "unknown.provider"


def _set_status(scan_id: str, **kw):
    _db.upsert_scan(scan_id, **kw)


# ── Concurrency pools ─────────────────────────────────────────────────────────
# Scan pool: max 2 scans running at once (decompile + static analysis is CPU-heavy).
# Excess uploads are queued by the executor and start automatically when a slot frees.
_SCAN_POOL = ThreadPoolExecutor(max_workers=2, thread_name_prefix="scan")

# Dynamic pool: max 3 concurrent finding-verification jobs.
# Each job probes one finding via ADB; I/O-bound so 3 workers gives ~3x throughput.
# Per-device serialisation is handled by ADB's own command queuing.
_DYN_POOL  = ThreadPoolExecutor(max_workers=3, thread_name_prefix="dyn")

# ── Simple in-memory rate limiter ────────────────────────────────────────────
_rate_store: dict = {}  # ip -> (count, window_start)
_RATE_LOCK = threading.Lock()


def _rate_limit(ip: str, max_per_minute: int = 10) -> bool:
    """Return True if the request is allowed, False if rate limit exceeded."""
    now = _time.time()
    with _RATE_LOCK:
        entry = _rate_store.get(ip)
        if entry is None or (now - entry[1]) > 60:
            _rate_store[ip] = (1, now)
            return True
        if entry[0] >= max_per_minute:
            return False
        _rate_store[ip] = (entry[0] + 1, entry[1])
        return True


def _load_summaries() -> list:
    return _db.list_scans()


def _extract_report_body(html: str) -> tuple[str, str, str]:
    """
    Pull the three reusable pieces out of a generated report HTML:
      - inner_css  : everything inside <style>...</style>
      - body_html  : the <div class="main">...</div> block + <footer> block
      - scripts    : ONLY the reportData JSON block + the final inline <script>

    IMPORTANT: We extract scripts by matching at the start-of-line boundary so we
    don't accidentally match <script> tags that appear inside JSON string values
    (e.g. in malicious_apk_code PoC fields that contain XSS payloads).
    """
    # CSS
    css_match = re.search(r'<style>(.*?)</style>', html, re.DOTALL)
    inner_css = css_match.group(1) if css_match else ''

    # Main content div
    main_match = re.search(r'(<div class="main">.*?</div><!-- /main -->)', html, re.DOTALL)
    main_html  = main_match.group(1) if main_match else ''

    # Footer
    foot_match = re.search(r'(<footer class="footer">.*?</footer>)', html, re.DOTALL)
    foot_html  = foot_match.group(1) if foot_match else ''

    body_html = (main_html + '\n' + foot_html) if main_html else html

    # Extract ONLY the two real script blocks we need:
    # 1. The JSON data block:  <script type="application/json" id="reportData">...</script>
    # 2. The final inline JS:  <script>\n... (no src, no type/id, starts at column 0)
    # We match ^<script to avoid matching <script> inside JSON string values.
    script_parts = []

    # JSON data block (identified by id="reportData")
    json_block = re.search(
        r'<script\s+type="application/json"\s+id="reportData"[^>]*>([\s\S]*?)</script>',
        html,
    )
    if json_block:
        script_parts.append(
            f'<script type="application/json" id="reportData">'
            f'{json_block.group(1)}</script>'
        )

    # Final inline script block — anchored at start of line to avoid false positives
    inline_block = re.search(
        r'^<script>\n([\s\S]+?)\n</script>',
        html,
        re.MULTILINE,
    )
    if inline_block:
        script_parts.append(f'<script>\n{inline_block.group(1)}\n</script>')

    scripts = '\n'.join(script_parts)
    return inner_css, body_html, scripts


def _build_dashboard(scan_id: str | None, all_summaries: list, view: str | None = None) -> str:
    """
    Build the full dashboard HTML page.
    If scan_id is provided, embed that scan's report content.
    view='intelligence' shows the Intelligence Hub instead of a report.
    """
    report_css    = ''
    report_body   = ''
    report_scripts= ''
    current       = None

    if scan_id:
        html_path = _scan_dir(scan_id) / 'report.html'
        if html_path.exists():
            raw = html_path.read_text(encoding='utf-8')
            report_css, report_body, report_scripts = _extract_report_body(raw)
            current = next((s for s in all_summaries if s.get('scan_id') == scan_id), None)

    api_configured  = bool(ANTHROPIC_API_KEY)
    hosted_inject   = (
        f'<script>window.__MSRA_HOSTED=true;'
        f'window.__API_KEY_CONFIGURED={json.dumps(api_configured)};</script>'
    )

    # View state
    is_intel         = (view == 'intelligence')
    scans_nav_active = '' if is_intel else 'active'
    intel_nav_active = 'active' if is_intel else ''
    new_scan_btn     = ('' if is_intel else
        '<button class="sb-new-btn sb-new-btn-below" onclick="openUploadPanel()">'
        '<i class="fa-solid fa-plus"></i> New Scan</button>')
    sidebar_label    = 'Rule Overview' if is_intel else 'Recent Scans'

    # Build sidebar scan items
    sidebar_items = ''
    for s in all_summaries:
        sid        = s.get('scan_id', '')
        pkg        = s.get('package', 'unknown')
        apk        = s.get('apk', '')
        total      = s.get('total_findings', 0)
        sev        = s.get('severity_counts', {})
        active     = 'active' if sid == scan_id else ''
        risk_score = s.get('risk_score')

        dot_c = f'<span class="sb-dot c">{sev.get("Critical",0)}C</span>' if sev.get('Critical') else ''
        dot_h = f'<span class="sb-dot h">{sev.get("High",0)}H</span>'     if sev.get('High')     else ''
        dot_m = f'<span class="sb-dot m">{sev.get("Medium",0)}M</span>'   if sev.get('Medium')   else ''

        if risk_score is not None:
            if risk_score >= 70:   rs_c = '#f87171'
            elif risk_score >= 40: rs_c = '#fb923c'
            elif risk_score >= 15: rs_c = '#fbbf24'
            else:                  rs_c = '#4ade80'
            risk_pill = (f'<span style="font-size:9px;font-weight:700;color:{rs_c};'
                         f'padding:1px 5px;border-radius:3px;background:{rs_c}22;margin-left:2px">'
                         f'{risk_score}</span>')
        else:
            risk_pill = ''

        platform     = s.get('platform', 'android')
        if platform == 'ios':
            plat_icon = '<i class="fa-brands fa-apple" style="color:var(--text3);font-size:9px"></i> '
        elif platform == 'jar':
            plat_icon = '<i class="fa-brands fa-java" style="color:#f97316;font-size:9px"></i> '
        elif platform == 'exe':
            plat_icon = '<i class="fa-brands fa-windows" style="color:#0078d4;font-size:9px"></i> '
        else:
            plat_icon = '<i class="fa-brands fa-android" style="color:#22c55e;font-size:9px"></i> '

        sidebar_items += f'''
        <div class="sb-scan-wrap">
          <a href="/scans/{sid}" class="sb-scan-item {active}">
            <div class="sb-pkg" style="display:flex;align-items:center;gap:4px">{plat_icon}{pkg}{risk_pill}</div>
            <div class="sb-meta">
              <span class="sb-apk">{apk}</span>
              <span class="sb-dots">{dot_c}{dot_h}{dot_m}</span>
            </div>
          </a>
          <div class="sb-del-reveal">
            <button class="sb-del-btn" onclick="deleteScan('{sid}')" title="Delete scan">
              <i class="fa-solid fa-trash-can"></i>
              <span>Delete</span>
            </button>
          </div>
        </div>'''

    if not sidebar_items:
        sidebar_items = '<div class="sb-empty">No scans yet</div>'

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>MSRA{" — " + (current.get("package") or current.get("apk") or "Scan") if current else ""}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" crossorigin="anonymous">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/bash.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/languages/java.min.js"></script>
{hosted_inject}
<style>
/* ── RESET & BASE ── */
:root{{
  --bg:#0d1117;--bg2:#161b22;--bg3:#1c2128;
  --border:#30363d;--border2:#21262d;
  --text:#e6edf3;--text2:#8b949e;--text3:#6e7681;
  --accent:#2f81f7;--accent-glow:rgba(47,129,247,.15);
  --critical:#ef4444;--high:#f97316;--medium:#eab308;
  --low:#22c55e;--info:#06b6d4;
  --radius:10px;--radius-sm:6px;
  --sidebar:260px;
}}
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
html{{scroll-behavior:smooth}}
body{{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);
      font-size:14px;line-height:1.6;min-height:100vh;overflow-x:hidden}}
a{{color:var(--accent);text-decoration:none}}
code,pre{{font-family:'JetBrains Mono',monospace}}

/* ── LAYOUT ── */
.dashboard{{display:flex;height:100vh;overflow:hidden}}

/* ── SIDEBAR ── */
.sidebar{{
  width:var(--sidebar);flex-shrink:0;
  background:var(--bg2);border-right:1px solid var(--border);
  display:flex;flex-direction:column;overflow:hidden;
  position:relative;z-index:10;
  transition:width .25s cubic-bezier(.4,0,.2,1);
}}
.sidebar.collapsed{{
  width:0!important;min-width:0!important;border-right:none;
}}
.sb-head{{
  padding:16px 16px 12px;border-bottom:1px solid var(--border);flex-shrink:0;
}}
.sb-brand{{
  display:flex;align-items:center;gap:9px;
  font-weight:700;font-size:15px;color:var(--text);margin-bottom:14px;
}}
.sb-brand i{{color:var(--accent);font-size:17px}}
.sb-new-btn{{
  width:100%;display:flex;align-items:center;justify-content:center;gap:8px;
  padding:8px 12px;border-radius:var(--radius-sm);
  background:var(--accent);border:none;color:#fff;
  font-size:13px;font-weight:600;cursor:pointer;font-family:inherit;
  transition:background .15s;
}}
.sb-new-btn:hover{{background:#388bfd}}
.sb-section-label{{
  padding:10px 16px 6px;font-size:10px;font-weight:700;
  text-transform:uppercase;letter-spacing:.1em;color:var(--text3);flex-shrink:0;
}}
.sb-list{{flex:1;overflow-y:auto;padding:4px 8px 12px}}
.sb-list::-webkit-scrollbar{{width:4px}}
.sb-list::-webkit-scrollbar-track{{background:transparent}}
.sb-list::-webkit-scrollbar-thumb{{background:var(--border);border-radius:2px}}
.sb-scan-item{{
  display:block;padding:10px 10px;border-radius:8px;
  margin-bottom:2px;transition:background .12s;border:1px solid transparent;
  text-decoration:none!important;
}}
.sb-scan-item:hover{{background:var(--bg3)}}
.sb-scan-item.active{{background:var(--bg3);border-color:var(--border)}}
.sb-pkg{{font-size:12px;font-weight:600;color:var(--text);
         white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.sb-meta{{display:flex;align-items:center;justify-content:space-between;margin-top:4px}}
.sb-apk{{font-size:10px;color:var(--text3);font-family:'JetBrains Mono',monospace;
         white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:120px}}
.sb-dots{{display:flex;gap:4px;flex-shrink:0}}
.sb-dot{{padding:1px 5px;border-radius:3px;font-size:9px;font-weight:700}}
.sb-dot.c{{background:rgba(239,68,68,.15);color:#f87171}}
.sb-dot.h{{background:rgba(249,115,22,.15);color:#fb923c}}
.sb-dot.m{{background:rgba(234,179,8,.15);color:#fbbf24}}
.sb-empty{{padding:20px 10px;text-align:center;font-size:12px;color:var(--text3)}}
.sb-foot{{
  padding:14px 14px 12px;border-top:1px solid var(--border);flex-shrink:0;
  display:flex;flex-direction:column;gap:10px;
}}
.sb-foot-link{{
  display:flex;align-items:center;gap:7px;
  font-size:11px;color:var(--text3);padding:5px 6px;border-radius:5px;
  cursor:pointer;transition:background .12s;border:none;background:none;font-family:inherit;width:100%;
}}
.sb-foot-link:hover{{background:var(--bg3);color:var(--text2)}}

/* API key input in sidebar */
.sb-api-section{{display:flex;flex-direction:column;gap:6px}}
.sb-api-label{{
  font-size:10px;font-weight:700;text-transform:uppercase;
  letter-spacing:.08em;color:var(--text3);
  display:flex;align-items:center;gap:6px;
}}
.sb-api-row{{display:flex;gap:5px;align-items:center}}
.sb-api-input{{
  flex:1;background:var(--bg);border:1px solid var(--border);
  color:var(--text);border-radius:5px;
  padding:6px 10px;font-size:11px;font-family:'JetBrains Mono',monospace;
  outline:none;transition:border-color .15s;min-width:0;
}}
.sb-api-input:focus{{border-color:var(--accent)}}
.sb-api-input::placeholder{{color:var(--text3)}}
.sb-api-btn{{
  flex-shrink:0;background:var(--bg3);border:1px solid var(--border);
  color:var(--text2);padding:5px 8px;border-radius:5px;
  font-size:11px;cursor:pointer;transition:all .15s;font-family:inherit;
  display:inline-flex;align-items:center;gap:4px;white-space:nowrap;
}}
.sb-api-btn:hover{{border-color:var(--accent);color:var(--accent)}}
.sb-api-btn.save{{background:rgba(34,197,94,.1);border-color:rgba(34,197,94,.3);color:#4ade80}}
.sb-api-btn.save:hover{{background:rgba(34,197,94,.2)}}
.sb-api-status{{
  font-size:10px;display:flex;align-items:center;gap:5px;height:14px;
}}
.sb-api-status.ok{{color:#4ade80}}
.sb-api-status.warn{{color:#f59e0b}}
.sb-api-status.none{{color:var(--text3)}}

/* ── CONTENT AREA ── */
.content{{flex:1;overflow-y:auto;display:flex;flex-direction:column;}}

/* ── TOPBAR (replaces report's topnav inside content) ── */
.topbar{{
  position:sticky;top:0;z-index:50;
  background:rgba(13,17,23,.97);backdrop-filter:blur(12px);
  border-bottom:1px solid var(--border);
  padding:0 28px;height:52px;
  display:flex;align-items:center;gap:14px;flex-shrink:0;
}}
.topbar-pkg{{
  background:var(--bg2);border:1px solid var(--border);
  padding:3px 12px;border-radius:20px;
  font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text2);
}}
.topbar-spacer{{flex:1}}
.topbar-meta{{display:flex;align-items:center;gap:14px}}
.topbar-meta span{{font-size:12px;color:var(--text2);display:flex;align-items:center;gap:5px}}
.topbar-meta i{{font-size:11px}}
.btn{{display:inline-flex;align-items:center;gap:7px;padding:7px 14px;border-radius:var(--radius-sm);
      font-size:13px;font-weight:500;cursor:pointer;border:1px solid var(--border);
      background:var(--bg2);color:var(--text);transition:all .15s;font-family:inherit}}
.btn:hover{{background:var(--bg3);border-color:var(--accent);color:var(--accent)}}
.btn-primary{{background:var(--accent);border-color:var(--accent);color:#fff}}
.btn-primary:hover{{background:#388bfd;border-color:#388bfd;color:#fff}}
.btn-sm{{padding:5px 12px;font-size:12px}}

/* ── PROGRESS BAR ── */
.scan-progress{{
  background:var(--bg2);border-bottom:1px solid var(--border);
  padding:14px 28px;display:none;align-items:center;gap:16px;flex-shrink:0;
}}
.scan-progress.visible{{display:flex}}
.prog-bar-wrap{{flex:1;height:4px;background:var(--bg3);border-radius:2px;overflow:hidden}}
.prog-bar-fill{{height:100%;background:var(--accent);border-radius:2px;transition:width .4s ease;width:0%}}
.prog-label{{font-size:12px;color:var(--text2);white-space:nowrap}}

/* ── UPLOAD PANEL (slide-in overlay) ── */
.upload-overlay{{
  display:none;position:fixed;inset:0;z-index:200;
  background:rgba(0,0,0,.7);backdrop-filter:blur(4px);
  align-items:center;justify-content:center;
}}
.upload-overlay.open{{display:flex}}
.upload-panel{{
  background:var(--bg2);border:1px solid var(--border);
  border-radius:var(--radius);width:100%;max-width:500px;
  padding:28px;box-shadow:0 20px 60px rgba(0,0,0,.6);
}}
.up-title{{font-size:17px;font-weight:700;margin-bottom:4px;display:flex;align-items:center;gap:10px}}
.up-title i{{color:var(--accent)}}
.up-sub{{font-size:13px;color:var(--text2);margin-bottom:20px}}
.up-dropzone{{
  border:2px dashed var(--border);border-radius:8px;
  padding:36px 24px;text-align:center;cursor:pointer;
  transition:all .2s;position:relative;margin-bottom:16px;
}}
.up-dropzone:hover,.up-dropzone.drag{{border-color:var(--accent);background:rgba(47,129,247,.04)}}
.up-dropzone input{{position:absolute;inset:0;opacity:0;cursor:pointer}}
.up-dropzone i{{font-size:32px;color:var(--accent);margin-bottom:10px;display:block}}
.up-dropzone p{{font-size:13px;color:var(--text2)}}
.up-file-row{{display:flex;align-items:center;gap:10px;margin-bottom:16px}}
.up-file-name{{font-size:12px;color:var(--text2);font-family:'JetBrains Mono',monospace;
               background:var(--bg3);padding:5px 12px;border-radius:5px;border:1px solid var(--border);flex:1;
               white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.up-actions{{display:flex;gap:10px;justify-content:flex-end}}
.up-device-row{{
  background:var(--bg3);border:1px solid var(--border);border-radius:8px;
  padding:10px 14px;margin-bottom:14px;
}}
.up-device-label{{font-size:11.5px;font-weight:600;color:var(--text2);
  display:flex;align-items:center;gap:7px;margin-bottom:6px}}
.up-device-status{{font-size:11px;color:var(--text3);display:flex;align-items:center;gap:5px}}
.up-device-list{{display:flex;flex-direction:column;gap:4px;margin-top:6px}}
.up-device-item{{
  display:flex;align-items:center;gap:8px;font-size:11.5px;padding:4px 0;
}}
.up-device-item input[type=radio]{{accent-color:var(--accent)}}
.up-device-badge{{
  font-size:10px;padding:1px 6px;border-radius:3px;font-weight:600;
  background:rgba(34,197,94,.12);color:var(--low);border:1px solid rgba(34,197,94,.25);
}}

/* ── REPORT CONTENT (injected from scanner) ── */
/* Override topnav from report — not shown in dashboard mode */
.content .topnav{{display:none!important}}
/* Report main padding */
.content .main{{padding:28px 28px 60px}}
/* Intelligence hub fills remaining height */
.content{{display:flex;flex-direction:column}}
#contentArea{{flex:1;display:flex;flex-direction:column;overflow-y:auto}}
#contentArea.intel-view{{overflow:hidden}}
.intel-hub{{flex:1;overflow:hidden}}

/* ── SIDEBAR NAV TABS ── */
.sb-nav{{display:flex;gap:4px;padding:8px 8px 0;flex-shrink:0}}
.sb-nav-btn{{
  flex:1;display:flex;align-items:center;justify-content:center;gap:5px;
  padding:7px 4px;border-radius:7px;font-size:11.5px;font-weight:500;
  cursor:pointer;border:1px solid transparent;
  background:transparent;color:var(--text3);font-family:inherit;
  transition:all .15s;text-decoration:none!important;
}}
.sb-nav-btn:hover{{background:var(--bg3);color:var(--text2)}}
.sb-nav-btn.active{{background:var(--accent);color:#fff;border-color:var(--accent)}}
.sb-new-btn-below{{
  margin:8px 8px 0;width:calc(100% - 16px);display:flex;align-items:center;
  justify-content:center;gap:8px;padding:8px 12px;border-radius:var(--radius-sm);
  background:var(--accent);border:none;color:#fff;font-size:13px;font-weight:600;
  cursor:pointer;font-family:inherit;transition:background .15s;
}}
.sb-new-btn-below:hover{{background:#388bfd}}

/* ── SCAN ITEM WITH DELETE ── */
.sb-scan-wrap{{display:flex;align-items:stretch;border-radius:8px;margin-bottom:2px;
               position:relative;overflow:hidden}}
.sb-scan-wrap .sb-scan-item{{flex:1;min-width:0;border-radius:8px;margin-bottom:0;
  transition:border-radius .22s}}
.sb-scan-wrap:hover .sb-scan-item{{border-radius:8px 0 0 8px}}
/* slide-to-delete reveal zone */
.sb-del-reveal{{
  flex-shrink:0;width:0;overflow:hidden;
  transition:width .22s cubic-bezier(.4,0,.2,1);
  background:#ef4444;border-radius:0 8px 8px 0;
  display:flex;align-items:center;justify-content:center;
}}
.sb-scan-wrap:hover .sb-del-reveal{{width:52px}}
.sb-del-btn{{
  color:#fff;background:transparent;border:none;cursor:pointer;
  display:flex;flex-direction:column;align-items:center;gap:3px;
  padding:0 8px;font-size:11px;white-space:nowrap;
}}
.sb-del-btn span{{font-size:9px;font-weight:600;letter-spacing:.3px}}

/* ── SIDEBAR INTEL STATS ── */
.sb-intel-mini{{padding:4px 8px}}
.sb-intel-mini-row{{
  display:flex;align-items:center;justify-content:space-between;
  padding:5px 8px;border-radius:6px;font-size:11.5px;margin-bottom:2px;
  cursor:pointer;transition:background .12s;
}}
.sb-intel-mini-row:hover{{background:var(--bg3)}}
.sb-intel-mini-row .count{{
  font-weight:700;font-size:12px;
  padding:1px 6px;border-radius:4px;
}}

/* ── INTELLIGENCE HUB (enterprise) ── */
.intel-hub{{display:flex;flex-direction:column;height:100%;overflow:hidden}}
.intel-header{{
  padding:24px 32px 0;background:var(--bg);border-bottom:1px solid var(--border);flex-shrink:0;
}}
.intel-header-top{{
  display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;
}}
.intel-brand{{display:flex;align-items:center;gap:14px}}
.intel-brand-icon{{
  width:40px;height:40px;background:var(--accent-glow);border:1px solid rgba(47,129,247,.3);
  border-radius:10px;display:flex;align-items:center;justify-content:center;
  color:var(--accent);font-size:16px;flex-shrink:0;
}}
.intel-brand h1{{font-size:19px;font-weight:700;color:var(--text);margin-bottom:2px}}
.intel-brand p{{font-size:12px;color:var(--text3)}}
.intel-header-actions{{display:flex;gap:8px}}

/* Stats strip */
.intel-stats-strip{{display:flex;border-top:1px solid var(--border);margin:0 -32px}}
.intel-stat{{
  flex:1;padding:14px 20px;border-right:1px solid var(--border);
  text-align:center;cursor:pointer;transition:background .15s;
  border-top:2px solid transparent;
}}
.intel-stat:last-child{{border-right:none}}
.intel-stat:hover{{background:rgba(255,255,255,.02)}}
.intel-stat.active{{background:var(--accent-glow);border-top-color:var(--accent)}}
.intel-stat-num{{font-size:22px;font-weight:800;line-height:1;margin-bottom:3px}}
.intel-stat-lbl{{font-size:9.5px;font-weight:700;text-transform:uppercase;letter-spacing:.09em;color:var(--text3)}}
.intel-stat.s-all    .intel-stat-num{{color:var(--text)}}
.intel-stat.s-active .intel-stat-num{{color:#4ade80}}
.intel-stat.s-crit   .intel-stat-num{{color:var(--critical)}}
.intel-stat.s-high   .intel-stat-num{{color:var(--high)}}
.intel-stat.s-med    .intel-stat-num{{color:var(--medium)}}
.intel-stat.s-low    .intel-stat-num{{color:var(--low)}}
.intel-stat.s-info   .intel-stat-num{{color:var(--info)}}

/* Scrollable content area */
.intel-body{{flex:1;overflow-y:auto;display:flex;flex-direction:column}}
.intel-body::-webkit-scrollbar{{width:5px}}
.intel-body::-webkit-scrollbar-track{{background:transparent}}
.intel-body::-webkit-scrollbar-thumb{{background:var(--border);border-radius:3px}}

/* Filter toolbar */
.intel-toolbar{{
  display:flex;gap:8px;align-items:center;
  padding:12px 32px;border-bottom:1px solid var(--border2);
  background:var(--bg);position:sticky;top:0;z-index:10;flex-wrap:wrap;
}}
.intel-search-wrap{{flex:1;min-width:180px;position:relative;display:flex;align-items:center}}
.intel-search-icon{{position:absolute;left:11px;color:var(--text3);font-size:11px;pointer-events:none}}
.intel-search{{
  width:100%;padding:7px 12px 7px 30px;background:var(--bg2);
  border:1px solid var(--border);color:var(--text);border-radius:var(--radius-sm);
  font-size:13px;font-family:inherit;outline:none;transition:border-color .15s;
}}
.intel-search:focus{{border-color:var(--accent)}}
.intel-search::placeholder{{color:var(--text3)}}
.intel-filter{{
  background:var(--bg2);border:1px solid var(--border);color:var(--text2);
  border-radius:var(--radius-sm);padding:7px 10px;font-size:12px;
  font-family:inherit;outline:none;cursor:pointer;
}}
.intel-filter:focus{{border-color:var(--accent)}}
.intel-sep{{width:1px;height:22px;background:var(--border);flex-shrink:0;margin:0 2px}}

/* Rules content */
.intel-table-area{{padding:0 32px 40px;flex:1}}
.intel-table-meta{{
  display:flex;align-items:center;justify-content:space-between;
  padding:10px 0 8px;font-size:12px;color:var(--text3);
}}

/* Enterprise table */
.rules-table{{width:100%;border-collapse:collapse;border:1px solid var(--border);border-radius:10px;overflow:hidden}}
.rules-table thead{{background:var(--bg2)}}
.rules-table th{{
  text-align:left;padding:10px 16px;font-size:10px;font-weight:700;
  text-transform:uppercase;letter-spacing:.09em;color:var(--text3);
  border-bottom:1px solid var(--border);white-space:nowrap;user-select:none;
}}
.rules-table th.sortable{{cursor:pointer;transition:color .12s}}
.rules-table th.sortable:hover{{color:var(--text2)}}
.rules-table th.sort-asc::after{{content:' ↑';color:var(--accent)}}
.rules-table th.sort-desc::after{{content:' ↓';color:var(--accent)}}
.rules-table td{{
  padding:12px 16px;font-size:12.5px;border-bottom:1px solid var(--border2);
  vertical-align:middle;
}}
.rules-table tbody tr:last-child td{{border-bottom:none}}
.rules-table tbody tr.rule-row{{cursor:pointer;transition:background .1s}}
.rules-table tbody tr.rule-row:hover td{{background:rgba(255,255,255,.025)}}
.rules-table tbody tr.rule-row.selected td{{background:var(--accent-glow)}}

/* Severity dot-label */
.sev-dot{{display:inline-flex;align-items:center;gap:7px;font-size:12.5px;font-weight:600;white-space:nowrap}}
.sev-dot::before{{content:'';width:8px;height:8px;border-radius:50%;flex-shrink:0}}
.sev-dot.Critical{{color:#f87171}}.sev-dot.Critical::before{{background:var(--critical)}}
.sev-dot.High{{color:#fb923c}}.sev-dot.High::before{{background:var(--high)}}
.sev-dot.Medium{{color:#fbbf24}}.sev-dot.Medium::before{{background:var(--medium)}}
.sev-dot.Low{{color:#4ade80}}.sev-dot.Low::before{{background:var(--low)}}
.sev-dot.Info{{color:#22d3ee}}.sev-dot.Info::before{{background:var(--info)}}

.rule-title-cell{{font-weight:500;color:var(--text);margin-bottom:3px}}
.rule-id-cell{{
  font-family:'JetBrains Mono',monospace;font-size:10.5px;color:var(--text3);
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:200px;display:block;
}}
.cat-pill{{
  display:inline-block;font-size:10.5px;color:var(--text3);background:var(--bg3);
  border:1px solid var(--border);padding:2px 9px;border-radius:4px;
  white-space:nowrap;max-width:150px;overflow:hidden;text-overflow:ellipsis;
}}
.det-pill{{
  display:inline-flex;align-items:center;gap:5px;font-size:10.5px;
  color:var(--text3);background:var(--bg3);border:1px solid var(--border);
  padding:2px 9px;border-radius:4px;white-space:nowrap;
}}
.src-pill{{
  display:inline-block;font-size:10px;font-weight:700;padding:2px 9px;
  border-radius:12px;text-transform:uppercase;letter-spacing:.05em;white-space:nowrap;
}}
.src-pill.builtin{{background:rgba(47,129,247,.1);color:#79c0ff}}
.src-pill.custom{{background:rgba(168,85,247,.1);color:#c084fc}}
.src-pill.community{{background:rgba(34,197,94,.1);color:#4ade80}}
.cwe-mini{{
  font-size:10.5px;padding:2px 8px;border-radius:4px;
  background:rgba(249,115,22,.08);border:1px solid rgba(249,115,22,.2);color:#fb923c;
  white-space:nowrap;
}}

/* Toggle switch */
.toggle-switch{{position:relative;display:inline-flex;width:38px;height:22px;cursor:pointer;flex-shrink:0}}
.toggle-switch input{{opacity:0;width:0;height:0;position:absolute}}
.toggle-track{{
  position:absolute;inset:0;background:var(--bg3);border:1px solid var(--border);
  border-radius:11px;transition:all .2s;
}}
.toggle-track::after{{
  content:'';position:absolute;top:3px;left:3px;width:14px;height:14px;
  background:var(--text3);border-radius:50%;transition:all .2s;
}}
.toggle-switch input:checked + .toggle-track{{background:rgba(47,129,247,.25);border-color:var(--accent)}}
.toggle-switch input:checked + .toggle-track::after{{transform:translateX(16px);background:var(--accent)}}

/* States */
.intel-state{{
  text-align:center;padding:80px 20px;color:var(--text3);
}}
.intel-state .state-icon{{
  font-size:42px;margin-bottom:16px;display:block;opacity:.4;
}}
.intel-state h3{{font-size:16px;font-weight:600;color:var(--text2);margin-bottom:8px}}
.intel-state p{{font-size:13px;line-height:1.7}}

/* ── RULE DETAIL MODAL ── */
.rule-detail-overlay{{
  display:none;position:fixed;inset:0;z-index:400;
  background:rgba(0,0,0,.8);backdrop-filter:blur(8px);
  align-items:center;justify-content:center;padding:28px;
}}
.rule-detail-overlay.open{{display:flex}}
.rdp{{
  background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);
  width:100%;max-width:900px;max-height:88vh;
  display:flex;flex-direction:column;box-shadow:0 40px 100px rgba(0,0,0,.7);
}}
.rdp-head{{padding:20px 24px 0;border-bottom:1px solid var(--border);flex-shrink:0}}
.rdp-head-top{{display:flex;align-items:flex-start;gap:14px;margin-bottom:16px}}
.rdp-sev-icon{{
  width:44px;height:44px;border-radius:10px;display:flex;align-items:center;
  justify-content:center;font-size:17px;flex-shrink:0;margin-top:2px;
}}
.rdp-sev-icon.Critical{{background:rgba(239,68,68,.12);color:#f87171}}
.rdp-sev-icon.High{{background:rgba(249,115,22,.12);color:#fb923c}}
.rdp-sev-icon.Medium{{background:rgba(234,179,8,.12);color:#fbbf24}}
.rdp-sev-icon.Low{{background:rgba(34,197,94,.12);color:#4ade80}}
.rdp-sev-icon.Info{{background:rgba(6,182,212,.12);color:#22d3ee}}
.rdp-head-info{{flex:1;min-width:0}}
.rdp-title{{font-size:17px;font-weight:700;color:var(--text);margin-bottom:8px;line-height:1.3}}
.rdp-pills{{display:flex;gap:8px;flex-wrap:wrap;align-items:center}}
.rdp-actions{{display:flex;gap:7px;flex-shrink:0;margin-top:2px}}
.rdp-close-btn{{
  background:none;border:1px solid var(--border);color:var(--text3);
  cursor:pointer;font-size:13px;padding:5px 10px;border-radius:6px;transition:all .15s;
}}
.rdp-close-btn:hover{{background:var(--bg3);color:var(--text)}}
.rdp-tabs{{display:flex;gap:0;border-bottom:0;margin-top:8px}}
.rdp-tab{{
  padding:9px 18px;font-size:12.5px;font-weight:500;color:var(--text3);
  border-bottom:2px solid transparent;cursor:pointer;transition:all .15s;
  background:none;border-top:none;border-left:none;border-right:none;font-family:inherit;
}}
.rdp-tab:hover{{color:var(--text2)}}
.rdp-tab.active{{color:var(--accent);border-bottom-color:var(--accent)}}
.rdp-body{{flex:1;overflow-y:auto;padding:24px}}
.rdp-body::-webkit-scrollbar{{width:4px}}
.rdp-body::-webkit-scrollbar-thumb{{background:var(--border);border-radius:2px}}
.rdp-pane{{display:none}}
.rdp-pane.active{{display:block}}
.rdp-section{{margin-bottom:24px}}
.rdp-section-title{{
  font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;
  color:var(--text3);padding-bottom:8px;border-bottom:1px solid var(--border2);margin-bottom:12px;
}}
.rdp-text{{font-size:13.5px;color:var(--text2);line-height:1.8}}
.rdp-code-block{{
  background:var(--bg3);border:1px solid var(--border);border-radius:8px;
  padding:14px 16px;font-family:'JetBrains Mono',monospace;font-size:11.5px;
  color:#79c0ff;white-space:pre-wrap;word-break:break-all;margin-bottom:10px;
}}
.rdp-code-meta{{font-size:10px;color:var(--text3);margin-top:-6px;margin-bottom:10px;display:flex;gap:10px}}
.tag-row{{display:flex;gap:6px;flex-wrap:wrap;align-items:center}}
.cwe-link{{
  display:inline-flex;align-items:center;gap:5px;font-size:11.5px;font-weight:600;
  padding:4px 12px;border-radius:6px;background:rgba(249,115,22,.08);
  border:1px solid rgba(249,115,22,.2);color:#fb923c;text-decoration:none;
}}
.cwe-link:hover{{background:rgba(249,115,22,.15)}}
.ref-link{{
  display:inline-flex;align-items:center;gap:5px;font-size:11.5px;
  padding:4px 12px;border-radius:6px;background:var(--bg3);
  border:1px solid var(--border);color:var(--accent);text-decoration:none;
  max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
}}
.ref-link:hover{{border-color:var(--accent);background:var(--accent-glow)}}
.tag-chip-sm{{
  font-size:11px;padding:3px 10px;border-radius:12px;
  background:var(--bg3);border:1px solid var(--border);color:var(--text3);
}}
.tc-item{{
  display:flex;align-items:flex-start;gap:10px;padding:12px 14px;
  border-radius:8px;background:var(--bg3);border:1px solid var(--border);margin-bottom:8px;
}}
.tc-badge{{
  font-size:10px;font-weight:700;padding:3px 8px;border-radius:4px;flex-shrink:0;margin-top:1px;
}}
.tc-badge.match{{background:rgba(34,197,94,.12);color:#4ade80}}
.tc-badge.no-match{{background:rgba(239,68,68,.12);color:#f87171}}
.tc-text{{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text2);white-space:pre-wrap;word-break:break-all}}
.rdp-foot{{
  padding:14px 24px;border-top:1px solid var(--border);
  display:flex;align-items:center;gap:8px;flex-shrink:0;background:var(--bg2);
}}
.rdp-foot-meta{{margin-left:auto;font-size:11px;color:var(--text3);display:flex;gap:12px}}

/* ── RULE FORM MODAL ── */
.rule-modal-overlay{{
  display:none;position:fixed;inset:0;z-index:500;
  background:rgba(0,0,0,.82);backdrop-filter:blur(6px);
  align-items:flex-start;justify-content:center;padding:40px 20px;overflow-y:auto;
}}
.rule-modal-overlay.open{{display:flex}}
.rule-modal{{
  background:var(--bg2);border:1px solid var(--border);
  border-radius:var(--radius);width:100%;max-width:720px;padding:28px;
  box-shadow:0 28px 70px rgba(0,0,0,.65);
}}
.rule-modal-title{{
  font-size:17px;font-weight:700;margin-bottom:22px;
  display:flex;align-items:center;gap:10px;
}}
.rule-modal-title i{{color:var(--accent)}}
.form-grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:4px}}
.form-group{{display:flex;flex-direction:column;gap:6px;margin-bottom:12px}}
.form-group.full{{grid-column:1/-1}}
.form-label{{font-size:10.5px;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:.06em}}
.form-input,.form-select,.form-textarea{{
  background:var(--bg);border:1px solid var(--border);color:var(--text);
  border-radius:var(--radius-sm);padding:9px 13px;font-size:13px;
  font-family:inherit;outline:none;transition:border-color .15s;
}}
.form-textarea{{font-family:'JetBrains Mono',monospace;font-size:11.5px;resize:vertical;min-height:72px}}
.form-input:focus,.form-select:focus,.form-textarea:focus{{border-color:var(--accent)}}
.form-input::placeholder,.form-textarea::placeholder{{color:var(--text3)}}
.form-hint{{font-size:10.5px;color:var(--text3);margin-top:-2px}}
.rule-modal-foot{{
  display:flex;gap:10px;justify-content:flex-end;
  margin-top:20px;padding-top:16px;border-top:1px solid var(--border);
}}

/* ── Dynamic verify button (injected into finding cards) ── */
.dyn-verify-btn{{
  display:inline-flex;align-items:center;gap:4px;
  padding:3px 9px;border-radius:5px;font-size:11px;font-weight:600;
  background:rgba(251,191,36,.12);color:#fbbf24;border:1px solid rgba(251,191,36,.3);
  cursor:pointer;transition:all .15s;flex-shrink:0;
}}
.dyn-verify-btn:hover{{background:rgba(251,191,36,.22);border-color:#fbbf24}}
.dyn-verify-btn.running{{background:rgba(99,102,241,.15);color:var(--accent);border-color:rgba(99,102,241,.4);animation:pulse 1.5s infinite}}
.dyn-verify-btn.done-tp{{background:rgba(239,68,68,.12);color:#f87171;border-color:rgba(239,68,68,.35)}}
.dyn-verify-btn.done-fp{{background:rgba(74,222,128,.1);color:#4ade80;border-color:rgba(74,222,128,.3)}}
.dyn-verify-btn.done-un{{background:rgba(251,191,36,.1);color:#fbbf24;border-color:rgba(251,191,36,.3)}}

/* ── Dynamic Analysis Panel (full overlay) ── */
.dyn-panel-overlay{{
  display:none;position:fixed;inset:0;z-index:600;
  background:rgba(0,0,0,.85);backdrop-filter:blur(8px);
  align-items:flex-start;justify-content:center;padding:40px 20px;overflow-y:auto;
}}
.dyn-panel-overlay.open{{display:flex}}
.dyn-panel{{
  background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);
  width:100%;max-width:820px;box-shadow:0 30px 80px rgba(0,0,0,.7);
  display:flex;flex-direction:column;
}}
.dyn-panel-head{{
  padding:20px 24px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:12px;
}}
.dyn-panel-head-icon{{
  width:36px;height:36px;background:rgba(251,191,36,.12);border:1px solid rgba(251,191,36,.3);
  border-radius:8px;display:flex;align-items:center;justify-content:center;
  color:#fbbf24;font-size:15px;flex-shrink:0;
}}
.dyn-panel-head h2{{font-size:16px;font-weight:700;flex:1}}
.dyn-panel-body{{padding:24px;display:flex;flex-direction:column;gap:20px}}

/* Device config row */
.dyn-mode-tabs{{display:flex;gap:6px;margin-bottom:14px}}
.dyn-mode-btn{{
  padding:7px 16px;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer;
  border:1px solid var(--border);background:var(--bg);color:var(--text3);transition:all .15s;
}}
.dyn-mode-btn.active{{background:rgba(99,102,241,.15);color:var(--accent);border-color:rgba(99,102,241,.4)}}
.dyn-config-row{{display:grid;grid-template-columns:1fr 1fr;gap:12px}}
.dyn-config-row .form-input{{font-size:12px}}
.dyn-config-full{{grid-column:1/-1}}

/* Job cards */
.dyn-jobs-section{{}}
.dyn-section-label{{
  font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;
  color:var(--text3);margin-bottom:10px;
}}
.dyn-job-card{{
  background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:14px 16px;
  margin-bottom:8px;
}}
.dyn-job-top{{display:flex;align-items:center;gap:10px;margin-bottom:8px}}
.dyn-job-icon{{
  width:28px;height:28px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:12px;flex-shrink:0;
}}
.dyn-job-icon.queued{{background:rgba(148,163,184,.1);color:var(--text3)}}
.dyn-job-icon.running{{background:rgba(99,102,241,.12);color:var(--accent)}}
.dyn-job-icon.done-tp{{background:rgba(239,68,68,.12);color:#f87171}}
.dyn-job-icon.done-fp{{background:rgba(74,222,128,.1);color:#4ade80}}
.dyn-job-icon.done-un{{background:rgba(251,191,36,.1);color:#fbbf24}}
.dyn-job-icon.error{{background:rgba(239,68,68,.1);color:#f87171}}
.dyn-job-title{{font-size:13px;font-weight:600;flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.dyn-job-badge{{font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;flex-shrink:0}}
.dyn-job-badge.true-positive{{background:rgba(239,68,68,.15);color:#f87171}}
.dyn-job-badge.false-positive{{background:rgba(74,222,128,.12);color:#4ade80}}
.dyn-job-badge.uncertain{{background:rgba(251,191,36,.12);color:#fbbf24}}
.dyn-job-badge.running{{background:rgba(99,102,241,.12);color:var(--accent)}}
.dyn-job-badge.error{{background:rgba(239,68,68,.1);color:#f87171}}
.dyn-progress{{height:3px;background:var(--bg2);border-radius:2px;overflow:hidden;margin-bottom:6px}}
.dyn-progress-bar{{height:100%;border-radius:2px;transition:width .4s;background:var(--accent)}}
.dyn-progress-bar.done-tp{{background:#f87171}}
.dyn-progress-bar.done-fp{{background:#4ade80}}
.dyn-job-msg{{font-size:11px;color:var(--text3)}}
.dyn-job-reasoning{{font-size:11.5px;color:var(--text2);margin-top:6px;line-height:1.6;border-top:1px solid var(--border);padding-top:8px}}
.dyn-logcat-toggle{{font-size:10px;color:var(--accent);cursor:pointer;margin-top:4px;display:inline-block}}
.dyn-logcat{{
  font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--text3);
  background:var(--bg);border:1px solid var(--border);border-radius:5px;
  padding:8px 10px;max-height:200px;overflow-y:auto;margin-top:6px;
  white-space:pre-wrap;word-break:break-all;display:none;
}}
.dyn-empty{{
  text-align:center;padding:32px;color:var(--text3);font-size:13px;
}}

/* ── Intel sub-nav tabs ── */
.intel-subnav{{display:flex;gap:0;border-bottom:1px solid var(--border);margin:0 -32px;padding:0 32px}}
.intel-subnav-btn{{
  padding:10px 18px;font-size:12.5px;font-weight:600;cursor:pointer;
  background:none;border:none;color:var(--text3);
  border-bottom:2px solid transparent;margin-bottom:-1px;
  transition:color .15s,border-color .15s;
}}
.intel-subnav-btn:hover{{color:var(--text)}}
.intel-subnav-btn.active{{color:var(--accent);border-bottom-color:var(--accent)}}
.intel-subnav-btn i{{margin-right:6px}}

/* ── Sources panel ── */
.sources-panel{{padding:28px 32px;display:flex;flex-direction:column;gap:28px}}
.sources-section-title{{
  font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;
  color:var(--text3);margin-bottom:14px;
}}
/* URL extractor card */
.url-extractor-card{{
  background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:24px;
}}
.url-extractor-card h3{{font-size:15px;font-weight:700;margin-bottom:6px}}
.url-extractor-card p{{font-size:12px;color:var(--text3);margin-bottom:16px}}
.url-input-row{{display:flex;gap:10px;align-items:flex-start}}
.url-input-row .form-input{{flex:1;font-size:13px}}
.url-extract-result{{
  margin-top:18px;border-top:1px solid var(--border2);padding-top:18px;
  display:none;
}}
.url-extract-result.visible{{display:block}}
.suggested-rules-list{{display:flex;flex-direction:column;gap:10px;margin-top:12px}}
.suggested-rule-card{{
  background:var(--bg3);border:1px solid var(--border);border-radius:8px;
  padding:14px 16px;display:flex;align-items:flex-start;gap:14px;
}}
.suggested-rule-card .sev-dot{{margin-top:3px;flex-shrink:0}}
.suggested-rule-info{{flex:1;min-width:0}}
.suggested-rule-title{{font-size:13px;font-weight:600;margin-bottom:3px}}
.suggested-rule-desc{{font-size:11.5px;color:var(--text3);margin-bottom:6px;line-height:1.5}}
.suggested-rule-meta{{display:flex;gap:6px;flex-wrap:wrap}}
.suggested-rule-actions{{display:flex;gap:6px;flex-shrink:0;margin-top:2px}}
.extract-log{{
  font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text3);
  background:var(--bg);border:1px solid var(--border);border-radius:6px;
  padding:10px 14px;margin-top:10px;max-height:120px;overflow-y:auto;
  white-space:pre-wrap;word-break:break-all;
}}
/* Feed source cards */
.feed-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:14px}}
.feed-card{{
  background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);
  padding:18px;display:flex;flex-direction:column;gap:12px;
}}
.feed-card-head{{display:flex;align-items:center;gap:12px}}
.feed-icon{{
  width:36px;height:36px;border-radius:8px;display:flex;align-items:center;justify-content:center;
  font-size:15px;flex-shrink:0;
}}
.feed-icon.nvd{{background:rgba(239,68,68,.12);color:#f87171}}
.feed-icon.owasp{{background:rgba(47,129,247,.12);color:var(--accent)}}
.feed-icon.hackerone{{background:rgba(251,191,36,.12);color:#fbbf24}}
.feed-icon.asb{{background:rgba(74,222,128,.12);color:#4ade80}}
.feed-icon.github{{background:rgba(168,85,247,.12);color:#c084fc}}
.feed-card-title{{font-size:13px;font-weight:600}}
.feed-card-url{{font-size:10.5px;color:var(--text3);font-family:'JetBrains Mono',monospace;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:200px}}
.feed-card-desc{{font-size:11.5px;color:var(--text3);line-height:1.5}}
.feed-card-foot{{display:flex;align-items:center;justify-content:space-between;margin-top:auto}}
.feed-status{{font-size:11px;color:var(--text3);display:flex;align-items:center;gap:5px}}
.feed-status-dot{{width:6px;height:6px;border-radius:50%;background:var(--border)}}
.feed-status-dot.ok{{background:#4ade80}}
.feed-status-dot.running{{background:#fbbf24;animation:pulse 1s infinite}}
.feed-status-dot.error{{background:#f87171}}

/* ── Inherit all report styles ── */
{report_css}

/* ══ HOME DASHBOARD ══ */
.home-dash{{padding:32px 32px 60px;overflow-y:auto}}
.home-kpi-strip{{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:28px}}
.home-kpi-card{{
  background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);
  padding:18px 24px;min-width:110px;flex:1;
}}
.home-kpi-num{{font-size:28px;font-weight:800;line-height:1;color:var(--text);margin-bottom:4px}}
.home-kpi-lbl{{font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--text3)}}
.home-content-row{{display:flex;gap:20px;align-items:flex-start;flex-wrap:wrap}}
.home-chart-card{{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:20px 24px;min-width:240px}}
.home-table-card{{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:20px 24px}}
.home-card-title{{font-size:13px;font-weight:700;color:var(--text);margin-bottom:16px;display:flex;align-items:center;gap:8px}}
.home-card-title i{{color:var(--accent)}}
.home-scan-table{{width:100%;border-collapse:collapse;font-size:12.5px}}
.home-scan-table th{{text-align:left;padding:7px 10px;font-size:10px;font-weight:700;
  text-transform:uppercase;letter-spacing:.08em;color:var(--text3);border-bottom:1px solid var(--border)}}
.home-scan-table td{{padding:9px 10px;border-bottom:1px solid var(--border2);color:var(--text2)}}
.home-scan-table tr:last-child td{{border-bottom:none}}
.home-scan-table tr:hover td{{background:var(--bg3);color:var(--text)}}
.home-legend{{display:flex;flex-wrap:wrap;gap:6px 14px;margin-top:14px;justify-content:center}}
.home-leg-item{{display:flex;align-items:center;gap:5px;font-size:11px;color:var(--text2)}}

/* ══ EXPORT DROPDOWN ══ */
.export-dropdown{{position:relative}}
.export-menu{{
  position:absolute;right:0;top:calc(100% + 4px);z-index:200;
  background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius-sm);
  min-width:170px;box-shadow:0 8px 24px rgba(0,0,0,.4);overflow:hidden;
}}
.export-menu button{{
  display:flex;align-items:center;gap:8px;width:100%;padding:9px 14px;
  background:none;border:none;color:var(--text2);font-size:12.5px;font-family:inherit;
  cursor:pointer;text-align:left;transition:background .12s;
}}
.export-menu button:hover{{background:var(--bg3);color:var(--text)}}
.export-menu button i{{width:14px;text-align:center;color:var(--text3)}}

/* ══ CONTENT TAB BAR ══ */
.content-tab-bar{{
  display:flex;border-bottom:1px solid var(--border);
  padding:0 28px;background:var(--bg);flex-shrink:0;gap:4px;
}}
.content-tab{{
  padding:10px 16px;font-size:13px;font-weight:500;cursor:pointer;
  border:none;border-bottom:2px solid transparent;color:var(--text3);
  background:none;font-family:inherit;transition:color .15s;
  margin-bottom:-1px;
}}
.content-tab:hover{{color:var(--text2)}}
.content-tab.active{{color:var(--accent);border-bottom:2px solid var(--accent)}}

/* ══ FINDINGS PANEL ══ */
#findingsPanel{{display:none;flex-direction:column;min-height:0;flex:1}}
#findingsPanel.active{{display:flex}}

/* Filter bar */
/* ── Scan summary strip ─────────────────────────────────────────────────── */
.scan-summary-strip{{
  display:flex;align-items:center;gap:20px;flex-wrap:wrap;
  padding:14px 28px;border-bottom:1px solid var(--border);
  background:var(--bg2);flex-shrink:0;
}}
.ss-meta{{display:flex;flex-direction:column;gap:3px;min-width:0;flex:1}}
.ss-pkg{{font-size:13px;font-weight:600;color:var(--text);
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:400px}}
.ss-apk,.ss-date{{font-size:11px;color:var(--text3);display:flex;align-items:center;gap:5px}}
.ss-pills{{display:flex;gap:6px;flex-wrap:wrap;align-items:center;flex:2}}
.ss-pill{{
  display:inline-flex;align-items:center;gap:5px;padding:3px 10px;
  border-radius:20px;font-size:11.5px;font-weight:600;cursor:pointer;
  transition:opacity .15s;white-space:nowrap;
}}
.ss-pill:hover{{opacity:.75}}
.ss-pill-dot{{width:6px;height:6px;border-radius:50%;flex-shrink:0}}
.ss-totals{{display:flex;gap:16px;align-items:center;flex-shrink:0}}
.ss-risk,.ss-total-count{{display:flex;flex-direction:column;align-items:center;
  background:var(--bg3);border:1px solid var(--border);border-radius:8px;
  padding:6px 14px;min-width:56px;}}

.findings-filter-bar{{
  position:sticky;top:52px;z-index:40;background:var(--bg);
  border-bottom:1px solid var(--border);padding:10px 28px;
  display:flex;gap:8px;align-items:center;flex-wrap:wrap;flex-shrink:0;
}}
.f-chips{{display:flex;gap:5px;flex-wrap:wrap}}
.f-chip{{
  padding:4px 12px;border-radius:20px;font-size:11.5px;font-weight:600;
  border:1px solid var(--border);background:var(--bg2);color:var(--text3);
  cursor:pointer;transition:all .15s;white-space:nowrap;font-family:inherit;
}}
.f-chip:hover{{color:var(--text2);border-color:var(--text3)}}
.f-chip.active{{background:var(--accent-glow);border-color:var(--accent);color:var(--accent)}}
.f-chip.chip-c.active{{background:rgba(239,68,68,.12);border-color:#ef4444;color:#f87171}}
.f-chip.chip-h.active{{background:rgba(249,115,22,.12);border-color:#f97316;color:#fb923c}}
.f-chip.chip-m.active{{background:rgba(234,179,8,.12);border-color:#eab308;color:#fbbf24}}
.f-chip.chip-l.active{{background:rgba(34,197,94,.12);border-color:#22c55e;color:#4ade80}}
.f-chip.chip-i.active{{background:rgba(6,182,212,.12);border-color:#06b6d4;color:#22d3ee}}
.f-search{{
  flex:1;min-width:160px;padding:6px 12px 6px 32px;background:var(--bg2);
  border:1px solid var(--border);color:var(--text);border-radius:var(--radius-sm);
  font-size:12.5px;font-family:inherit;outline:none;transition:border-color .15s;
}}
.f-search:focus{{border-color:var(--accent)}}
.f-search::placeholder{{color:var(--text3)}}
.f-search-wrap{{position:relative;display:flex;align-items:center;flex:1;min-width:160px}}
.f-search-icon{{position:absolute;left:10px;color:var(--text3);font-size:11px;pointer-events:none}}
.f-select{{
  background:var(--bg2);border:1px solid var(--border);color:var(--text2);
  border-radius:var(--radius-sm);padding:6px 10px;font-size:12px;
  font-family:inherit;outline:none;cursor:pointer;
}}
.f-select:focus{{border-color:var(--accent)}}
.f-result-count{{font-size:11px;color:var(--text3);white-space:nowrap;padding:0 4px}}

/* Findings list */
.findings-list{{padding:16px 28px;flex:1;overflow-y:auto}}
.findings-list::-webkit-scrollbar{{width:5px}}
.findings-list::-webkit-scrollbar-thumb{{background:var(--border);border-radius:3px}}
.finding-row{{
  display:flex;flex-direction:column;gap:0;padding:13px 16px;
  border-radius:8px;border:1px solid var(--border);background:var(--bg2);
  margin-bottom:6px;cursor:pointer;transition:border-color .15s,background .15s;
}}
.finding-row:hover{{border-color:var(--accent);background:var(--bg3)}}
.fr-top{{display:flex;align-items:center;gap:10px;min-width:0}}
.fr-body{{display:flex;flex-direction:column;gap:5px;margin-top:7px;padding-top:7px;
  border-top:1px solid var(--border)}}
.finding-row .fr-sev{{
  flex-shrink:0;width:66px;padding:2px 6px;border-radius:4px;
  font-size:10px;font-weight:700;text-align:center;
}}
.finding-row .fr-title{{flex:1;font-size:13px;font-weight:600;color:var(--text);
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0}}
.finding-row .fr-cat{{font-size:10px;color:var(--text3);white-space:nowrap;
  padding:2px 7px;border-radius:4px;background:var(--bg3);border:1px solid var(--border);flex-shrink:0}}
.finding-row .fr-desc{{
  font-size:12px;color:var(--text2);line-height:1.5;
  display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;
}}
.finding-row .fr-loc{{
  display:flex;align-items:flex-start;gap:6px;font-size:11px;
}}
.finding-row .fr-loc-file{{
  font-family:'JetBrains Mono',monospace;color:var(--accent);
  white-space:nowrap;flex-shrink:0;
}}
.finding-row .fr-snippet{{
  font-family:'JetBrains Mono',monospace;font-size:10.5px;color:var(--text3);
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0;flex:1;
}}
.fr-dyn-btn{{
  flex-shrink:0;width:26px;height:26px;border-radius:6px;
  background:rgba(56,189,248,.1);border:1px solid rgba(56,189,248,.25);
  color:#38bdf8;font-size:9px;cursor:pointer;display:flex;align-items:center;
  justify-content:center;transition:background .15s,border-color .15s;
}}
.fr-dyn-btn:hover{{background:rgba(56,189,248,.2);border-color:rgba(56,189,248,.5)}}
.fr-dyn-btn:disabled{{opacity:.4;cursor:not-allowed}}
.triage-pill{{
  padding:2px 9px;border-radius:4px;font-size:10px;font-weight:700;
  white-space:nowrap;flex-shrink:0;border:1px solid transparent;
}}
.tp-new{{background:rgba(107,114,128,.12);color:#9ca3af;border-color:rgba(107,114,128,.2)}}
.tp-confirmed{{background:rgba(239,68,68,.12);color:#f87171;border-color:rgba(239,68,68,.2)}}
.tp-fp{{background:rgba(6,182,212,.12);color:#22d3ee;border-color:rgba(6,182,212,.2)}}
.tp-accepted{{background:rgba(234,179,8,.12);color:#fbbf24;border-color:rgba(234,179,8,.2)}}
.tp-fixed{{background:rgba(34,197,94,.12);color:#4ade80;border-color:rgba(34,197,94,.2)}}
.tp-inprogress{{background:rgba(168,85,247,.12);color:#c084fc;border-color:rgba(168,85,247,.2)}}

/* ══ DETAIL DRAWER ══ */
.finding-drawer{{
  position:fixed;right:-520px;top:0;bottom:0;width:520px;
  background:var(--bg2);border-left:1px solid var(--border);
  z-index:300;transition:right .25s cubic-bezier(.4,0,.2,1);
  overflow-y:auto;display:flex;flex-direction:column;
}}
.finding-drawer.open{{right:0}}
.finding-drawer::-webkit-scrollbar{{width:5px}}
.finding-drawer::-webkit-scrollbar-thumb{{background:var(--border);border-radius:3px}}
.drawer-backdrop{{
  display:none;position:fixed;inset:0;z-index:299;background:rgba(0,0,0,.5);
  backdrop-filter:blur(2px);
}}
.drawer-backdrop.open{{display:block}}
.drawer-head{{
  position:sticky;top:0;background:var(--bg2);z-index:10;
  padding:16px 20px;border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:10px;flex-shrink:0;
}}
.drawer-close{{
  margin-left:auto;background:none;border:none;color:var(--text3);
  cursor:pointer;font-size:15px;padding:4px;border-radius:4px;transition:color .15s;
}}
.drawer-close:hover{{color:var(--text)}}
.drawer-body{{padding:20px;flex:1}}
.drawer-section{{margin-bottom:20px}}
.drawer-section-title{{
  font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.09em;
  color:var(--text3);margin-bottom:8px;display:flex;align-items:center;gap:6px;
}}
.drawer-desc{{font-size:13px;color:var(--text2);line-height:1.65}}
.drawer-attack{{
  font-size:12.5px;color:var(--text2);line-height:1.6;
  background:rgba(249,115,22,.06);border:1px solid rgba(249,115,22,.2);
  border-radius:6px;padding:12px 14px;
}}
/* Vulnerable code section */
.drawer-vuln-code .dvloc{{
  display:flex;align-items:center;gap:7px;margin-bottom:7px;
  font-size:11px;color:var(--text3);
}}
.drawer-vuln-code .dvloc-file{{
  font-family:'JetBrains Mono',monospace;color:var(--accent);font-weight:600;
}}
.drawer-vuln-code .dvloc-line{{
  background:rgba(56,189,248,.1);border:1px solid rgba(56,189,248,.2);
  color:var(--accent);font-size:10px;padding:0 6px;border-radius:4px;
}}
/* Exploitation section */
.drawer-exploit{{background:rgba(239,68,68,.03);border-radius:8px;}}
.expl-block{{margin-bottom:12px}}
.expl-block:last-child{{margin-bottom:0}}
.expl-sub{{
  font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;
  color:var(--text3);margin-bottom:5px;display:flex;align-items:center;gap:6px;
}}
.expl-list{{
  margin:0;padding-left:18px;font-size:12.5px;color:var(--text2);
  line-height:1.7;
}}
.expl-list li{{margin-bottom:2px}}
/* Dynamic scan inline status in drawer */
.dvloc-loading,.dvloc-error{{font-size:11.5px;color:var(--text3);padding:10px 0;display:flex;align-items:center;gap:6px}}
.dyn-inline-progress{{margin-top:2px}}
.dyn-inline-result{{
  background:var(--bg3);border:1px solid var(--border);border-radius:8px;
  padding:12px 14px;display:flex;flex-direction:column;gap:8px;
}}
.dyn-inline-verdict{{font-size:13px;font-weight:700;display:flex;align-items:center;gap:7px}}
.dyn-inline-reason{{font-size:12px;color:var(--text2);line-height:1.5}}
.dyn-inline-evidence{{margin:0;padding-left:16px;font-size:11.5px;color:var(--text3);line-height:1.6}}
.dyn-inline-action{{font-size:12px;color:var(--medium);display:flex;align-items:flex-start;gap:6px}}
.dyn-inline-error{{font-size:12px;color:var(--critical);display:flex;align-items:center;gap:6px}}
.drawer-code{{
  font-family:'JetBrains Mono',monospace;font-size:11.5px;
  background:var(--bg);border:1px solid var(--border);border-radius:6px;
  padding:12px 14px;overflow-x:auto;color:var(--text2);white-space:pre-wrap;
  word-break:break-all;line-height:1.5;
}}
.drawer-refs{{display:flex;flex-direction:column;gap:5px}}
.drawer-ref-link{{
  font-size:11.5px;color:var(--accent);text-decoration:none;
  word-break:break-all;display:flex;align-items:center;gap:5px;
}}
.drawer-ref-link:hover{{text-decoration:underline}}
/* Triage section in drawer */
.triage-form{{background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:14px}}
.triage-select{{
  width:100%;background:var(--bg2);border:1px solid var(--border);color:var(--text);
  border-radius:var(--radius-sm);padding:7px 10px;font-size:13px;
  font-family:inherit;outline:none;margin-bottom:8px;
}}
.triage-select:focus{{border-color:var(--accent)}}
.triage-note{{
  width:100%;background:var(--bg2);border:1px solid var(--border);color:var(--text);
  border-radius:var(--radius-sm);padding:7px 10px;font-size:12px;
  font-family:inherit;outline:none;resize:vertical;min-height:56px;
  placeholder-color:var(--text3);margin-bottom:8px;
}}
.triage-note:focus{{border-color:var(--accent)}}
.triage-note::placeholder{{color:var(--text3)}}

/* ══ COMPONENT HEATMAP ══ */
.heatmap-section{{padding:0 28px 32px}}
.heatmap-title{{font-size:13px;font-weight:700;color:var(--text);margin-bottom:12px;
  display:flex;align-items:center;gap:7px}}
.heatmap-title i{{color:var(--accent)}}
.heatmap-wrap{{overflow-x:auto}}
.heatmap-table{{border-collapse:collapse;font-size:11px;min-width:100%}}
.heatmap-table th{{
  padding:7px 10px;text-align:center;font-size:10px;font-weight:700;
  text-transform:uppercase;letter-spacing:.07em;color:var(--text3);
  border:1px solid var(--border2);white-space:nowrap;background:var(--bg2);
}}
.heatmap-table th:first-child{{text-align:left;min-width:160px}}
.heatmap-table td{{
  padding:6px 10px;border:1px solid var(--border2);text-align:center;
  font-size:11px;font-weight:600;cursor:pointer;transition:opacity .15s;
  vertical-align:middle;
}}
.heatmap-table td:first-child{{
  text-align:left;font-family:'JetBrains Mono',monospace;font-size:10.5px;
  color:var(--text2);max-width:200px;overflow:hidden;text-overflow:ellipsis;
  white-space:nowrap;cursor:default;
}}
.heatmap-table td:hover{{opacity:.8}}
.hm-0{{background:var(--bg2);color:var(--text3)}}
.hm-1{{background:rgba(234,179,8,.15);color:#fbbf24}}
.hm-2{{background:rgba(249,115,22,.15);color:#fb923c}}
.hm-3{{background:rgba(239,68,68,.15);color:#f87171}}
.hm-4{{background:rgba(239,68,68,.25);color:#ef4444}}

/* Load-more for virtual scroll */
.load-more-row{{text-align:center;padding:14px}}
.load-more-btn{{
  background:var(--bg2);border:1px solid var(--border);color:var(--text2);
  padding:7px 20px;border-radius:var(--radius-sm);font-size:12.5px;
  cursor:pointer;transition:all .15s;font-family:inherit;
}}
.load-more-btn:hover{{border-color:var(--accent);color:var(--accent)}}

/* findings panel sentinel */
#findingsSentinel{{height:1px}}

/* Toast slide-up animation */
@keyframes slideUp{{
  from{{opacity:0;transform:translateY(12px)}}
  to{{opacity:1;transform:translateY(0)}}
}}

/* ══ HAMBURGER BUTTON ══ */
.hamburger{{
  display:inline-flex;align-items:center;justify-content:center;
  width:34px;height:34px;border-radius:var(--radius-sm);
  border:1px solid var(--border);background:transparent;
  color:var(--text2);cursor:pointer;flex-shrink:0;
  transition:all .15s;padding:0;
}}
.hamburger:hover{{color:var(--text);border-color:var(--accent);background:var(--bg2)}}

/* ══ SIDEBAR OVERLAY (mobile backdrop) ══ */
.sidebar-overlay{{
  display:none;position:fixed;inset:0;z-index:99;
  background:rgba(0,0,0,.55);backdrop-filter:blur(3px);
}}
.sidebar-overlay.open{{display:block}}

/* ══ RESPONSIVE ══ */

/* ── Tablet (≤1024px): sidebar narrows ── */
@media (max-width:1024px){{
  :root{{--sidebar:220px}}
  .topbar{{padding:0 20px}}
  .sb-brand{{font-size:13px;gap:7px}}
  .findings-list{{padding:16px 20px}}
  .findings-filter-bar{{padding:8px 20px}}
  .content .main{{padding:24px 20px 60px}}
}}

/* ── Tablet portrait / large phone (≤768px): sidebar hides, hamburger toggles overlay ── */
@media (max-width:768px){{

  /* Sidebar slides off-screen; .open class brings it back */
  .sidebar{{
    position:fixed!important;top:0;left:0;bottom:0;
    width:260px!important;
    transform:translateX(-100%);
    transition:transform .28s cubic-bezier(.4,0,.2,1);
    z-index:200;
    box-shadow:8px 0 32px rgba(0,0,0,.5);
  }}
  .sidebar.open{{transform:translateX(0)}}

  /* Content spans full width */
  .content{{width:100%;min-width:0}}

  /* Topbar */
  .topbar{{padding:0 14px;gap:8px}}
  .topbar-pkg{{
    max-width:130px;overflow:hidden;
    text-overflow:ellipsis;white-space:nowrap;
  }}
  /* Hide verbose meta labels on small screens */
  .topbar-meta>span:first-child{{display:none}}

  /* Detail drawer — full width, slides up from bottom */
  .finding-drawer{{
    width:100%!important;
    right:auto!important;left:0!important;
    top:auto!important;bottom:-100vh;
    height:88vh;
    border-left:none!important;
    border-top:1px solid var(--border)!important;
    border-radius:16px 16px 0 0;
    box-shadow:0 -8px 40px rgba(0,0,0,.5);
    transition:bottom .28s cubic-bezier(.4,0,.2,1)!important;
  }}
  .finding-drawer.open{{bottom:0!important;right:auto!important}}
  /* Drawer drag handle */
  .finding-drawer::before{{
    content:'';display:block;width:40px;height:4px;
    background:var(--border);border-radius:2px;
    margin:10px auto 0;flex-shrink:0;
  }}

  /* Upload panel */
  .upload-panel{{
    margin:12px!important;
    width:calc(100vw - 24px)!important;
    max-width:100%!important;
    padding:24px!important;
  }}

  /* Modals */
  .rule-detail-modal,.rule-form-modal,.dyn-modal{{
    max-width:calc(100vw - 24px)!important;
    max-height:90vh!important;
    margin:12px!important;
  }}

  /* Findings */
  .findings-list{{padding:10px 14px}}
  .findings-filter-bar{{padding:8px 14px;flex-wrap:wrap;height:auto}}
  .f-chips{{flex-wrap:wrap}}
  .fr-cat,.fr-loc{{display:none}}
  .fr-title{{font-size:13px}}

  /* Intelligence hub */
  .rules-table th:nth-child(5),.rules-table td:nth-child(5){{display:none}}
  .intel-stats-strip{{flex-wrap:wrap}}
}}

/* ── Phone (≤480px) ── */
@media (max-width:480px){{
  .topbar{{padding:0 10px;height:48px;gap:6px}}
  .topbar-pkg{{display:none}}
  .topbar-meta{{gap:6px}}
  .topbar-meta>span{{display:none}}

  /* Filter bar stacks vertically */
  .findings-filter-bar{{
    flex-direction:column;align-items:stretch;
    gap:6px;padding:8px 10px;
  }}
  .f-chips{{gap:4px}}
  .f-chips .sev-chip{{padding:3px 8px;font-size:10px}}
  .f-search-wrap{{min-width:0}}
  .f-select{{width:100%}}

  /* Findings list */
  .findings-list{{padding:8px 10px}}
  .finding-row{{padding:10px 12px;border-radius:var(--radius-sm)}}
  .fr-top{{gap:6px}}
  .fr-sev{{width:52px;font-size:10px}}
  .fr-title{{font-size:12px}}
  .fr-desc{{font-size:12px}}

  /* Drawer */
  .finding-drawer{{height:92vh}}
  .drawer-body{{padding:12px 14px}}
  .drawer-head{{padding:12px 14px}}

  /* Upload */
  .up-dropzone{{padding:20px 14px}}
  .up-title{{font-size:15px}}
  .up-sub{{font-size:12px}}
  .up-actions{{flex-direction:column-reverse}}
  .up-actions .btn{{width:100%;justify-content:center}}

  /* Home KPI cards */
  .home-kpi-card{{min-width:calc(50% - 8px)}}

  /* Content tabs smaller */
  .content-tab{{font-size:12px;padding:0 10px}}

  /* Intelligence hub table */
  .rules-table{{font-size:12px}}
  .rules-table th:nth-child(4),.rules-table td:nth-child(4),
  .rules-table th:nth-child(6),.rules-table td:nth-child(6){{display:none}}
}}

</style>
</head>
<body>

<div class="dashboard">

  <!-- Mobile sidebar backdrop -->
  <div class="sidebar-overlay" id="sidebarOverlay" onclick="closeSidebar()"></div>

  <!-- ════ SIDEBAR ════ -->
  <aside class="sidebar" id="mainSidebar">
    <div class="sb-head">
      <div class="sb-brand">
        <i class="fa-solid fa-shield-halved"></i> MSRA
      </div>
    </div>

    <!-- Nav tabs: Scans | Intelligence -->
    <div class="sb-nav">
      <a href="/" class="sb-nav-btn {scans_nav_active}">
        <i class="fa-solid fa-magnifying-glass"></i> Scans
      </a>
      <a href="/?view=intelligence" class="sb-nav-btn {intel_nav_active}">
        <i class="fa-solid fa-brain"></i> Intelligence
      </a>
    </div>

    {new_scan_btn}

    <div class="sb-section-label">{sidebar_label}</div>
    <div class="sb-list" id="sidebarList">
      {sidebar_items if not is_intel else _build_sidebar_intel_stats()}
    </div>

    <div class="sb-foot">
      <div class="sb-api-section">
        <div class="sb-api-label">
          <i class="fa-solid fa-key"></i> Anthropic API Key
        </div>
        <div class="sb-api-row">
          <input class="sb-api-input" type="password" id="sidebarApiKey"
                 placeholder="sk-ant-api03-…" autocomplete="off"
                 oninput="onApiKeyInput()"
                 onkeydown="if(event.key==='Enter') saveApiKey()">
          <button class="sb-api-btn" id="apiKeyToggle" onclick="toggleApiKeyVisibility()" title="Show/hide key">
            <i class="fa-regular fa-eye" id="apiKeyEyeIcon"></i>
          </button>
          <button class="sb-api-btn save" id="apiKeySaveBtn" onclick="saveApiKey()" title="Save key">
            <i class="fa-solid fa-floppy-disk"></i>
          </button>
          <button class="sb-api-btn" id="apiKeyTestBtn" onclick="testApiKey()" title="Test API connection">
            <i class="fa-solid fa-flask"></i>
          </button>
        </div>
        <div class="sb-api-status none" id="apiKeyStatus">
          <i class="fa-solid fa-circle-dot"></i> <span>Not configured</span>
        </div>
      </div>
      <span class="sb-foot-link"><i class="fa-solid fa-code-branch"></i> MSRA v1.0</span>
    </div>
  </aside>

  <!-- ════ MAIN CONTENT ════ -->
  <div class="content{'  intel-view' if is_intel else ''}" id="contentArea">

    <!-- TOP BAR -->
    {_build_topbar(current, view=view)}

    <!-- SCAN PROGRESS (shown during active scan) -->
    <div class="scan-progress" id="scanProgress">
      <i class="fa-solid fa-spinner fa-spin" style="color:var(--accent);font-size:14px"></i>
      <div class="prog-bar-wrap"><div class="prog-bar-fill" id="progFill"></div></div>
      <span class="prog-label" id="progLabel">Scanning…</span>
      <button class="btn btn-sm" onclick="cancelProgressPoll()" style="flex-shrink:0">
        <i class="fa-solid fa-xmark"></i>
      </button>
    </div>

    <!-- MAIN CONTENT: report, findings panel, or intelligence hub -->
    {_build_intelligence_hub() if is_intel else _build_scan_content(scan_id, current, report_body, report_scripts)}

  </div>
</div>

<!-- ════ UPLOAD OVERLAY ════ -->
<div class="upload-overlay" id="uploadOverlay">
  <div class="upload-panel">
    <div class="up-title"><i class="fa-solid fa-cloud-arrow-up"></i> Upload File</div>
    <div class="up-sub">Android APK &nbsp;·&nbsp; iOS IPA &nbsp;·&nbsp; Java JAR &nbsp;·&nbsp; Windows EXE/DLL</div>

    <div class="up-dropzone" id="upDrop">
      <input type="file" id="upFileInput" accept=".apk,.apkm,.xapk,.ipa,.jar,.exe,.dll" onchange="onUpFileSelected(this)">
      <i class="fa-solid fa-file-circle-plus"></i>
      <p>Click or drag a file here<br><span style="font-size:11px;color:var(--text3)"><i class="fa-brands fa-android" style="color:#22c55e"></i> .apk · .apkm · .xapk &nbsp;&nbsp;<i class="fa-brands fa-apple" style="color:var(--text2)"></i> .ipa &nbsp;&nbsp;<i class="fa-brands fa-java" style="color:#f97316"></i> .jar &nbsp;&nbsp;<i class="fa-brands fa-windows" style="color:#0078d4"></i> .exe · .dll &nbsp;·&nbsp; max 250 MB</span></p>
    </div>

    <div class="up-file-row">
      <span class="up-file-name" id="upFileName">No file selected</span>
    </div>

    <!-- Device auto-install section -->
    <div class="up-device-row" id="upDeviceRow">
      <div class="up-device-label">
        <i class="fa-solid fa-mobile-screen-button"></i> Auto-install on device
      </div>
      <div class="up-device-status" id="upDeviceStatus">
        <i class="fa-solid fa-spinner fa-spin" style="font-size:10px"></i> Detecting…
      </div>
      <div class="up-device-list" id="upDeviceList"></div>
    </div>

    <div class="up-actions">
      <button class="btn" onclick="closeUploadPanel()">Cancel</button>
      <button class="btn btn-primary" id="upScanBtn" onclick="startUploadScan()" disabled>
        <i class="fa-solid fa-magnifying-glass"></i> Start Scan
      </button>
    </div>
  </div>
</div>

<!-- ════ CLAUDE POC MODAL (from report) ════ -->
{_poc_modal_html()}

<!-- ════ INTELLIGENCE: ADD/EDIT RULE MODAL ════ -->
<div class="rule-modal-overlay" id="ruleModal">
  <div class="rule-modal">
    <div class="rule-modal-title">
      <i class="fa-solid fa-wand-sparkles"></i>
      <span id="ruleModalTitle">Add Custom Rule</span>
    </div>
    <input type="hidden" id="ruleEditId">
    <div class="form-grid">
      <div class="form-group">
        <label class="form-label">Rule ID</label>
        <input class="form-input" id="ruleFormId" placeholder="e.g. custom-api-key-leak" autocomplete="off">
        <span class="form-hint">Auto-generated if left empty.</span>
      </div>
      <div class="form-group">
        <label class="form-label">Title *</label>
        <input class="form-input" id="ruleFormTitle" placeholder="e.g. Hardcoded API Key in Kotlin" autocomplete="off">
      </div>
      <div class="form-group">
        <label class="form-label">Severity</label>
        <select class="form-select" id="ruleFormSeverity">
          <option>Critical</option><option selected>High</option>
          <option>Medium</option><option>Low</option><option>Info</option>
        </select>
      </div>
      <div class="form-group">
        <label class="form-label">Category</label>
        <select class="form-select" id="ruleFormCategory">
          <option>OWASP-M1-Credentials</option><option>OWASP-M2-SupplyChain</option>
          <option>OWASP-M3-AuthN-AuthZ</option><option>OWASP-M4-InputValidation</option>
          <option>OWASP-M5-Communication</option><option>OWASP-M6-Privacy</option>
          <option>OWASP-M7-BinaryProtection</option><option>OWASP-M8-Misconfiguration</option>
          <option>OWASP-M9-DataStorage</option><option>OWASP-M10-Cryptography</option>
          <option>Intent-DeepLink</option><option>WebView</option>
          <option>Component-Exposure</option><option>Permission</option>
          <option>Network</option><option>Logging</option><option selected>Other</option>
        </select>
      </div>
      <div class="form-group full">
        <label class="form-label">Description</label>
        <textarea class="form-textarea" id="ruleFormDesc" placeholder="What this rule detects and why it matters…" rows="3"></textarea>
      </div>
      <div class="form-group full">
        <label class="form-label">Attack Path / Impact</label>
        <textarea class="form-textarea" id="ruleFormAttack" placeholder="How an attacker exploits this vulnerability…" rows="2"></textarea>
      </div>
      <div class="form-group full">
        <label class="form-label">Remediation</label>
        <textarea class="form-textarea" id="ruleFormRemediation" placeholder="How to fix this vulnerability…" rows="2"></textarea>
      </div>
      <div class="form-group">
        <label class="form-label">Detection Type</label>
        <select class="form-select" id="ruleFormDetType" onchange="updateDetTypeUI()">
          <option value="regex">Regex (Java/Kotlin/XML)</option>
          <option value="manifest">Manifest (AndroidManifest.xml)</option>
        </select>
      </div>
      <div class="form-group">
        <label class="form-label">File Types</label>
        <input class="form-input" id="ruleFormFileTypes" value=".java,.kt" placeholder=".java,.kt,.xml">
        <span class="form-hint">Comma-separated</span>
      </div>
      <div class="form-group full" id="regexPatternGroup">
        <label class="form-label">Regex Pattern(s) — one per line</label>
        <textarea class="form-textarea" id="ruleFormPattern" placeholder="(?i)(apiKey|api_key)\\s*=\\s*[\"'][A-Za-z0-9_\\-]{20,}" rows="3" style="font-family:'JetBrains Mono',monospace;color:#79c0ff"></textarea>
        <span class="form-hint">Java regex. Use (?i) for case-insensitive. One pattern per line.</span>
      </div>
      <div class="form-group full">
        <label class="form-label">CWE IDs</label>
        <input class="form-input" id="ruleFormCwe" placeholder="e.g. CWE-798, CWE-312" autocomplete="off">
        <span class="form-hint">Comma-separated</span>
      </div>
      <div class="form-group full">
        <label class="form-label">References (one URL per line)</label>
        <textarea class="form-textarea" id="ruleFormRefs" placeholder="https://cwe.mitre.org/..." rows="2"></textarea>
      </div>
      <div class="form-group full">
        <label class="form-label">Tags</label>
        <input class="form-input" id="ruleFormTags" placeholder="e.g. credentials, hardcoded, api-key" autocomplete="off">
        <span class="form-hint">Comma-separated</span>
      </div>
    </div>
    <div id="ruleFormError" style="display:none;color:var(--critical);font-size:13px;
         padding:10px 14px;background:rgba(239,68,68,.08);border-radius:6px;
         border:1px solid rgba(239,68,68,.2);margin-bottom:4px"></div>
    <div class="rule-modal-foot">
      <button class="btn" onclick="closeRuleModal()">Cancel</button>
      <button class="btn btn-primary" id="ruleFormSubmit" onclick="submitRuleForm()">
        <i class="fa-solid fa-floppy-disk"></i> Save Rule
      </button>
    </div>
  </div>
</div>
<!-- Hidden file input for import -->
<input type="file" id="importJsonInput" accept=".json" style="display:none" onchange="handleImportFile(this)">

<!-- ════ DYNAMIC ANALYSIS PANEL ════ -->
<div class="dyn-panel-overlay" id="dynPanelOverlay">
  <div class="dyn-panel">
    <div class="dyn-panel-head">
      <div class="dyn-panel-head-icon"><i class="fa-solid fa-bolt"></i></div>
      <h2>Dynamic Verification</h2>
      <div style="margin-left:auto;display:flex;gap:8px;align-items:center">
        <span id="dynDeviceStatus" style="font-size:11px;color:var(--text3)"></span>
        <button class="btn btn-sm" onclick="saveDynConfig()"><i class="fa-solid fa-floppy-disk"></i> Save</button>
        <button class="rdp-close-btn" onclick="closeDynPanel()"><i class="fa-solid fa-xmark"></i> Close</button>
      </div>
    </div>
    <div class="dyn-panel-body">

      <!-- Device Config -->
      <div>
        <div class="dyn-section-label"><i class="fa-solid fa-microchip" style="margin-right:5px"></i>Device Connection</div>
        <div class="dyn-mode-tabs">
          <button class="dyn-mode-btn active" id="modeAdb"       onclick="switchDynMode('adb')"><i class="fa-solid fa-mobile-screen-button"></i> Local ADB</button>
          <button class="dyn-mode-btn"        id="modeCorellium" onclick="switchDynMode('corellium')"><i class="fa-solid fa-cloud"></i> Corellium</button>
        </div>
        <!-- ADB config -->
        <div id="adbConfig">
          <div class="dyn-config-row">
            <div class="form-group">
              <label class="form-label">ADB Device Serial <span style="color:var(--text3)">(leave blank for default)</span></label>
              <input class="form-input" id="dynAdbSerial" placeholder="e.g. emulator-5554 or 192.168.1.5:5555">
            </div>
            <div class="form-group" style="display:flex;align-items:flex-end;gap:8px">
              <button class="btn btn-sm" onclick="refreshAdbDevices()" style="margin-bottom:0">
                <i class="fa-solid fa-rotate"></i> Refresh
              </button>
              <select class="form-select" id="adbDeviceList" onchange="document.getElementById('dynAdbSerial').value=this.value" style="flex:1"></select>
            </div>
          </div>
        </div>
        <!-- Corellium config -->
        <div id="corelliumConfig" style="display:none">
          <div class="dyn-config-row">
            <div class="form-group">
              <label class="form-label">Corellium URL</label>
              <input class="form-input" id="dynCorelliumUrl" placeholder="https://app.corellium.com">
            </div>
            <div class="form-group">
              <label class="form-label">API Token</label>
              <input class="form-input" id="dynCorelliumToken" type="password" placeholder="API key from Corellium settings">
            </div>
            <div class="form-group dyn-config-full" style="display:flex;align-items:flex-end;gap:8px">
              <div style="flex:1">
                <label class="form-label">Instance</label>
                <select class="form-select" id="dynInstanceList"></select>
              </div>
              <button class="btn btn-sm" onclick="fetchCorelliumInstances()"><i class="fa-solid fa-rotate"></i> Fetch Instances</button>
              <button class="btn btn-primary btn-sm" onclick="testCorelliumConnection()"><i class="fa-solid fa-plug"></i> Test</button>
            </div>
          </div>
        </div>
      </div>

      <!-- Active jobs -->
      <div>
        <div class="dyn-section-label"><i class="fa-solid fa-spinner fa-spin" style="margin-right:5px"></i>Active Verifications</div>
        <div id="dynActiveJobs"><div class="dyn-empty">No active jobs</div></div>
      </div>

      <!-- Completed jobs -->
      <div>
        <div class="dyn-section-label"><i class="fa-solid fa-clipboard-check" style="margin-right:5px"></i>Completed</div>
        <div id="dynDoneJobs"><div class="dyn-empty">No completed verifications yet</div></div>
      </div>

    </div>
  </div>
</div>

<!-- SCRIPTS -->
{report_scripts}

<script>
// ── RESPONSIVE SIDEBAR TOGGLE ───────────────────────────────
function toggleSidebar() {{
  const sb  = document.getElementById('mainSidebar');
  const ov  = document.getElementById('sidebarOverlay');
  const open = sb && sb.classList.toggle('open');
  if (ov) ov.classList.toggle('open', open);
}}
function closeSidebar() {{
  const sb = document.getElementById('mainSidebar');
  const ov = document.getElementById('sidebarOverlay');
  if (sb) sb.classList.remove('open');
  if (ov) ov.classList.remove('open');
}}
// Close sidebar on navigation (links inside sidebar)
document.addEventListener('click', e => {{
  if (window.innerWidth <= 768 && e.target.closest('.sb-nav-btn, .scan-item')) {{
    setTimeout(closeSidebar, 120);
  }}
}});
// Close sidebar + drawer on Escape
document.addEventListener('keydown', e => {{
  if (e.key === 'Escape') {{
    closeSidebar();
    closeDrawer();
  }}
}});

// ── UPLOAD PANEL ────────────────────────────────────────────
let _upFile = null;

function openUploadPanel() {{
  document.getElementById('uploadOverlay').classList.add('open');
  _detectAdbDevicesForUpload();
}}
function closeUploadPanel() {{ document.getElementById('uploadOverlay').classList.remove('open'); }}

async function _detectAdbDevicesForUpload() {{
  const statusEl = document.getElementById('upDeviceStatus');
  const listEl   = document.getElementById('upDeviceList');
  if (!statusEl || !listEl) return;
  statusEl.innerHTML = '<i class="fa-solid fa-spinner fa-spin" style="font-size:10px"></i> Detecting devices…';
  listEl.innerHTML = '';
  try {{
    const data = await fetch('/api/dynamic/adb-devices').then(r => r.json());
    const devs = data.devices || [];
    if (devs.length === 0) {{
      statusEl.innerHTML = '<i class="fa-solid fa-circle-xmark" style="color:var(--text3)"></i> No devices connected — Android APKs will not be installed automatically';
      return;
    }}
    statusEl.innerHTML = `<i class="fa-solid fa-circle-check" style="color:var(--low)"></i> ${{devs.length}} device${{devs.length>1?'s':''}} found — Android APKs will be installed automatically after scan`;
    devs.forEach((d, i) => {{
      const label = d.model ? `${{escHtml(d.serial)}} (${{escHtml(d.model)}})` : escHtml(d.serial);
      listEl.innerHTML += `
        <label class="up-device-item">
          <input type="radio" name="upDevice" value="${{escHtml(d.serial)}}" ${{i===0?'checked':''}}>
          <span>${{label}}</span>
          <span class="up-device-badge">connected</span>
        </label>`;
    }});
  }} catch(e) {{
    statusEl.innerHTML = '<i class="fa-solid fa-triangle-exclamation" style="color:var(--medium)"></i> ADB check failed — install will be attempted automatically';
  }}
}}

document.addEventListener('click', e => {{
  if (e.target === document.getElementById('uploadOverlay')) closeUploadPanel();
}});

const upDrop = document.getElementById('upDrop');
upDrop.addEventListener('dragover',  e => {{ e.preventDefault(); upDrop.classList.add('drag'); }});
upDrop.addEventListener('dragleave', () => upDrop.classList.remove('drag'));
upDrop.addEventListener('drop', e => {{
  e.preventDefault(); upDrop.classList.remove('drag');
  if (e.dataTransfer.files[0]) setUpFile(e.dataTransfer.files[0]);
}});

function onUpFileSelected(input) {{ if (input.files[0]) setUpFile(input.files[0]); }}
function setUpFile(f) {{
  const MAX_BYTES = 500 * 1024 * 1024;
  if (f.size > MAX_BYTES) {{
    showToast('File too large — maximum upload size is 500 MB', 'error');
    return;
  }}
  _upFile = f;
  document.getElementById('upFileName').textContent = f.name + ' (' + (f.size/1024/1024).toFixed(1) + ' MB)';
  document.getElementById('upScanBtn').disabled = false;
}}

async function startUploadScan() {{
  if (!_upFile) return;

  // Save selected device serial so _auto_install_apk picks it up
  const selectedRadio = document.querySelector('input[name="upDevice"]:checked');
  if (selectedRadio?.value) {{
    try {{
      const cfg = await fetch('/api/dynamic/config').then(r => r.json());
      await fetch('/api/dynamic/config', {{
        method: 'POST', headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{ ...cfg, adb_serial: selectedRadio.value }}),
      }});
    }} catch(e) {{ /* non-fatal */ }}
  }}

  const fd = new FormData();
  fd.append('apk', _upFile);
  closeUploadPanel();
  showProgress(5, 'Uploading…');

  fetch('/api/upload', {{ method: 'POST', body: fd }})
    .then(r => {{
      if (r.status === 413) throw new Error('File too large (max 250 MB)');
      return r.json();
    }})
    .then(d => {{
      if (d.error) {{ showToast(d.error, 'error'); hideProgress(); return; }}
      pollScan(d.scan_id);
    }})
    .catch(e => {{ showToast('Upload failed: ' + e.message, 'error'); hideProgress(); }});
}}

// ── API KEY MANAGEMENT ──────────────────────────────────────
const API_KEY_STORAGE = 'msra_anthropic_key';

function loadApiKey() {{
  const saved = localStorage.getItem(API_KEY_STORAGE) || '';
  const input = document.getElementById('sidebarApiKey');
  if (input && saved) {{
    input.value = saved;
    setApiKeyStatus('ok', 'Key loaded from storage');
  }} else {{
    const serverConfigured = typeof window.__API_KEY_CONFIGURED !== 'undefined' && window.__API_KEY_CONFIGURED;
    if (serverConfigured) {{
      setApiKeyStatus('ok', 'Configured via environment');
    }} else {{
      setApiKeyStatus('none', 'Not configured');
    }}
  }}
}}

function onApiKeyInput() {{
  const val = document.getElementById('sidebarApiKey').value.trim();
  if (!val) {{
    setApiKeyStatus('none', 'Not configured');
  }} else if (val.startsWith('sk-ant-')) {{
    setApiKeyStatus('warn', 'Press save to apply');
  }} else {{
    setApiKeyStatus('warn', 'Key format looks unusual');
  }}
}}

function saveApiKey() {{
  const val = document.getElementById('sidebarApiKey').value.trim();
  if (!val) {{
    localStorage.removeItem(API_KEY_STORAGE);
    setApiKeyStatus('none', 'Key cleared');
    return;
  }}
  localStorage.setItem(API_KEY_STORAGE, val);
  setApiKeyStatus('ok', 'Key saved \u2713');
  // Brief flash on button
  const btn = document.getElementById('apiKeySaveBtn');
  btn.innerHTML = '<i class="fa-solid fa-check"></i>';
  setTimeout(() => btn.innerHTML = '<i class="fa-solid fa-floppy-disk"></i>', 1500);
}}

async function testApiKey() {{
  const key = _resolveApiKey();
  const btn = document.getElementById('apiKeyTestBtn');
  if (!key) {{
    setApiKeyStatus('none', 'Enter & save a key first');
    showToast('No API key — enter and save one in the sidebar', 'warn');
    return;
  }}
  btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i>';
  btn.disabled  = true;
  setApiKeyStatus('warn', 'Testing connection…');
  try {{
    const res  = await fetch('/api/test-ai', {{
      method: 'POST', headers: {{'Content-Type':'application/json'}},
      body: JSON.stringify({{ api_key: key }}),
    }});
    const data = await res.json();
    btn.innerHTML = '<i class="fa-solid fa-flask"></i>';
    btn.disabled  = false;
    if (data.ok) {{
      setApiKeyStatus('ok', `Connected ✓ — ${{escHtml(data.model||'Claude')}}`);
      showToast('Claude API connected ✓', 'success');
    }} else {{
      setApiKeyStatus('none', `Error: ${{escHtml(data.error||'Check key')}}`);
      showToast('API test failed: ' + (data.error||'Check your key'), 'error');
    }}
  }} catch(e) {{
    btn.innerHTML = '<i class="fa-solid fa-flask"></i>';
    btn.disabled  = false;
    setApiKeyStatus('none', 'Connection failed');
    showToast('API test error: ' + e.message, 'error');
  }}
}}

function toggleApiKeyVisibility() {{
  const input = document.getElementById('sidebarApiKey');
  const icon  = document.getElementById('apiKeyEyeIcon');
  if (input.type === 'password') {{
    input.type = 'text';
    icon.className = 'fa-regular fa-eye-slash';
  }} else {{
    input.type = 'password';
    icon.className = 'fa-regular fa-eye';
  }}
}}

function setApiKeyStatus(state, msg) {{
  const el   = document.getElementById('apiKeyStatus');
  const icons = {{ ok: 'fa-circle-check', warn: 'fa-triangle-exclamation', none: 'fa-circle-dot' }};
  el.className = 'sb-api-status ' + state;
  el.innerHTML = `<i class="fa-solid ${{icons[state] || 'fa-circle-dot'}}"></i> <span>${{msg}}</span>`;
}}

function getActiveApiKey() {{
  // Priority: sidebar localStorage > server env var (indicated by __API_KEY_CONFIGURED)
  return localStorage.getItem(API_KEY_STORAGE) || '';
}}

// Load on page init
document.addEventListener('DOMContentLoaded', loadApiKey);

// ── SCAN PROGRESS POLLING ───────────────────────────────────
let _pollTimer = null;

function showProgress(pct, msg) {{
  document.getElementById('scanProgress').classList.add('visible');
  document.getElementById('progFill').style.width  = pct + '%';
  document.getElementById('progLabel').textContent = msg;
}}
function hideProgress() {{
  document.getElementById('scanProgress').classList.remove('visible');
}}
function cancelProgressPoll() {{
  clearTimeout(_pollTimer); hideProgress();
}}

function pollScan(scanId) {{
  fetch('/api/scan/' + scanId + '/status')
    .then(r => r.json())
    .then(d => {{
      showProgress(d.progress || 0, d.message || '…');
      if (d.status === 'done') {{
        // Navigate to clean URL for completed scan
        window.location.href = '/scans/' + scanId;
      }} else if (d.status === 'error') {{
        hideProgress();
        showToast('Scan failed: ' + (d.message || 'Unknown error'), 'error');
      }} else {{
        _pollTimer = setTimeout(() => pollScan(scanId), 1500);
      }}
    }});
}}

// ── CLAUDE POC MODAL (dashboard copy) ───────────────────────
// These mirror the functions in the injected report scripts but
// source the API key from the sidebar localStorage field.

function _resolveApiKey() {{
  return localStorage.getItem('msra_anthropic_key') || '';
}}

function openPocModal(idx) {{
  const modal = document.getElementById('pocModal');
  if (!modal) return;
  modal.dataset.findingIdx = idx;
  modal.style.display = '';
  modal.classList.add('open');
  const hasKey = !!_resolveApiKey() ||
    (typeof window.__API_KEY_CONFIGURED !== 'undefined' && window.__API_KEY_CONFIGURED);
  const warn = document.getElementById('modalNoKeyWarning');
  if (warn) warn.style.display = hasKey ? 'none' : 'flex';
  showModalState('ready');
}}

function closePocModal() {{
  const modal = document.getElementById('pocModal');
  if (modal) {{ modal.classList.remove('open'); modal.style.display = 'none'; }}
  showModalState('ready');
}}

function showModalState(state) {{
  const get = id => document.getElementById(id);
  if (get('modalReady'))         get('modalReady').style.display      = state==='ready'      ? 'block' : 'none';
  if (get('modalGenerating'))    get('modalGenerating').style.display = state==='generating' ? 'flex'  : 'none';
  if (get('modalResult'))        get('modalResult').style.display     = state==='result'     ? 'flex'  : 'none';
  if (get('modalError'))         get('modalError').style.display      = state==='error'      ? 'block' : 'none';
  if (get('modalFooterGenerate'))get('modalFooterGenerate').style.display = state==='ready'  ? 'flex'  : 'none';
  if (get('modalFooterDownload'))get('modalFooterDownload').style.display = state==='result' ? 'flex'  : 'none';
}}

function openPocModalForFinding(finding) {{
  const modal = document.getElementById('pocModal');
  if (!modal) return;
  modal.dataset.findingJson = JSON.stringify(finding);
  delete modal.dataset.findingIdx;
  modal.style.display = '';
  modal.classList.add('open');
  const hasKey = !!_resolveApiKey() ||
    (typeof window.__API_KEY_CONFIGURED !== 'undefined' && window.__API_KEY_CONFIGURED);
  const warn = document.getElementById('modalNoKeyWarning');
  if (warn) warn.style.display = hasKey ? 'none' : 'flex';
  showModalState('ready');
}}

function runPocGeneration() {{
  const modal  = document.getElementById('pocModal');
  const apiKey = _resolveApiKey();

  let finding, pkg;
  if (modal.dataset.findingJson) {{
    // Called from drawer with full finding object
    finding = JSON.parse(modal.dataset.findingJson);
    try {{
      const rd = document.getElementById('reportData');
      pkg = rd ? JSON.parse(rd.textContent).package || '' : '';
    }} catch(e) {{ pkg = ''; }}
  }} else {{
    // Legacy: called with index into reportData
    const idx    = parseInt(modal.dataset.findingIdx);
    const reportData = JSON.parse(document.getElementById('reportData').textContent);
    finding = reportData.findings[idx] || {{}};
    pkg     = reportData.package || '';
  }}

  const ev  = finding.evidence || {{}};
  const body = {{
    api_key:            apiKey,
    package:            pkg,
    title:              finding.title             || '',
    description:        finding.description       || '',
    severity:           finding.severity          || '',
    category:           finding.category          || '',
    component:          ev.file ? ev.file.split('/').pop().replace(/\.(java|kt)$/, '') : '',
    authority:          pkg + '.provider',
    snippet:            ev.snippet                || finding._liveSnippet || '',
    file_path:          ev.file                   || '',
    poc_text:           finding.poc               || '',
    attack_path:        finding.attack_path       || '',
    attack_description: finding.attack_description|| '',
    attack_steps:       (finding.attack_steps||[]).join('\\n'),
    adb_commands:       (finding.adb_commands||[]).join('\\n'),
  }};

  showModalState('generating');
  fetch('/api/generate-poc', {{
    method: 'POST', headers: {{'Content-Type':'application/json'}},
    body: JSON.stringify(body),
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
    document.querySelectorAll('#modalResult pre code').forEach(b => hljs.highlightElement(b));
  }})
  .catch(e => {{
    document.getElementById('modalErrorMsg').textContent = e.message;
    showModalState('error');
  }});
}}

function renderPocFiles(files) {{
  const tabBar   = document.getElementById('pocFileTabs');
  const paneArea = document.getElementById('pocFilePanes');
  tabBar.innerHTML = ''; paneArea.innerHTML = '';
  files.forEach((f, i) => {{
    const tab = document.createElement('button');
    tab.className   = 'file-tab' + (i===0?' active':'');
    tab.textContent = f.name;
    tab.onclick     = () => switchFileTab(i);
    tabBar.appendChild(tab);
    const pane = document.createElement('div');
    pane.className  = 'file-pane' + (i===0?' active':'');
    pane.id         = 'fpane-' + i;
    pane.innerHTML  = `<pre><code class="language-${{f.language || 'text'}}">${{escHtml(f.content)}}</code></pre>`;
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
  const scanId = _getScanId() || new URLSearchParams(window.location.search).get('scan') || 'report';
  fetch(`/api/download-poc/${{scanId}}`, {{
    method: 'POST', headers: {{'Content-Type':'application/json'}},
    body: JSON.stringify({{ files }}),
  }}).then(r => r.blob()).then(blob => {{
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `poc_${{scanId}}.zip`;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
  }});
}}

function escHtml(s) {{
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}}

document.addEventListener('click', e => {{
  const overlay = document.getElementById('pocModal');
  if (e.target === overlay) closePocModal();
}});
document.addEventListener('keydown', e => {{ if (e.key==='Escape') closePocModal(); }});

// Export JSON
async function exportReport() {{
  const scanId = _getScanId();
  if (!scanId) {{
    // Fallback: grab raw embedded JSON (no triage)
    const el = document.getElementById('reportData') || document.getElementById('findingsData');
    if (!el) {{ showToast('No report data available', 'warn'); return; }}
    const blob = new Blob([el.textContent], {{type:'application/json'}});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'msra_report.json';
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    return;
  }}
  try {{
    const res  = await fetch(`/api/scans/${{scanId}}/findings`);
    const data = await res.json();
    const blob = new Blob([JSON.stringify(data, null, 2)], {{type:'application/json'}});
    const a    = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = (data.package || scanId) + '_msra.json';
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
  }} catch(e) {{
    showToast('Export failed: ' + e.message, 'error');
  }}
}}

async function exportPdf(scanId) {{
  if (!scanId) return;
  showToast('Generating PDF…', 'info');
  try {{
    const res = await fetch('/api/scans/' + scanId + '/export/pdf');
    if (!res.ok) {{
      let msg = 'PDF generation failed';
      try {{ const d = await res.json(); msg = d.error || msg; }} catch {{}}
      showToast(msg, 'error');
      return;
    }}
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'msra_' + scanId + '.pdf';
    document.body.appendChild(a); a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }} catch(e) {{
    showToast('PDF export error: ' + e.message, 'error');
  }}
}}

// ── DELETE SCAN ──────────────────────────────────────────────
async function deleteScan(scanId) {{
  if (!confirm('Delete this scan and all its data? This cannot be undone.')) return;
  try {{
    const res = await fetch(`/api/scans/${{scanId}}`, {{method:'DELETE'}});
    if (res.ok) {{
      // If we're currently viewing the deleted scan, go home
      if (window.location.pathname.startsWith('/scans/' + scanId)) {{
        window.location.href = '/';
      }} else {{
        window.location.reload();
      }}
    }} else {{
      const d = await res.json(); showToast(d.error||'Delete failed', 'error');
    }}
  }} catch(e) {{ showToast('Delete failed: '+e.message, 'error'); }}
}}

// ── INTELLIGENCE HUB (enterprise) ────────────────────────────
let _allRules = [];
let _rulesSort  = {{ key: 'severity', dir: 1 }};
let _openRuleId = null;
let _quickSevFilter = '';
let _quickTagFilter = '';
const SEV_ORDER = {{ Critical:0, High:1, Medium:2, Low:3, Info:4 }};

async function loadIntelHub() {{
  if (!document.getElementById('intelHub')) return;
  try {{
    const [rulesRes, statsRes] = await Promise.all([
      fetch('/api/rules').then(r => r.json()),
      fetch('/api/rules/stats').then(r => r.json()),
    ]);
    _allRules = rulesRes;
    renderIntelStats(statsRes);
    populateCategoryFilter(rulesRes);
    renderRulesTable();
  }} catch(e) {{
    const el = document.getElementById('rulesLoading');
    if (el) {{
      el.innerHTML = `<i class="fa-solid fa-triangle-exclamation state-icon" style="color:var(--critical)"></i>
        <h3>Failed to load rules</h3><p>${{escHtml(e.message)}}</p>`;
    }}
  }}
}}

function renderIntelStats(stats) {{
  const g = id => document.getElementById(id);
  if (!g('statTotal')) return;
  g('statTotal').textContent   = stats.total    || 0;
  g('statEnabled').textContent = stats.enabled  || 0;
  const sev = stats.by_severity || {{}};
  g('statCritical').textContent = sev.Critical || 0;
  g('statHigh').textContent     = sev.High     || 0;
  g('statMedium').textContent   = sev.Medium   || 0;
  g('statLow').textContent      = sev.Low      || 0;
  g('statInfo').textContent     = sev.Info     || 0;
}}

function populateCategoryFilter(rules) {{
  const cats = [...new Set(rules.map(r => r.category))].sort();
  const sel  = document.getElementById('filterCategory');
  if (!sel) return;
  // Remove non-default options first
  while (sel.options.length > 1) sel.remove(1);
  cats.forEach(c => {{
    const opt = document.createElement('option');
    opt.value = c;
    opt.textContent = c.replace(/OWASP-M\d+-/,'').replace(/-/g,' ');
    sel.appendChild(opt);
  }});
}}

function getFilteredRules() {{
  const q   = (document.getElementById('rulesSearch')?.value  || '').toLowerCase();
  const sev = document.getElementById('filterSeverity')?.value || '';
  const cat  = document.getElementById('filterCategory')?.value  || '';
  const src  = document.getElementById('filterSource')?.value    || '';
  const sta  = document.getElementById('filterStatus')?.value    || '';
  const plat = document.getElementById('filterPlatform')?.value  || '';
  return _allRules.filter(r => {{
    if (q    && !r.title.toLowerCase().includes(q) && !r.id.toLowerCase().includes(q) && !r.description.toLowerCase().includes(q)) return false;
    if (sev  && r.severity !== sev) return false;
    if (cat  && r.category !== cat) return false;
    if (src  && r.source   !== src) return false;
    if (plat && r.platform !== plat) return false;
    if (sta === 'enabled'  && !r.enabled) return false;
    if (sta === 'disabled' &&  r.enabled) return false;
    if (_quickTagFilter && !(r.tags||[]).includes(_quickTagFilter)) return false;
    return true;
  }}).sort((a, b) => {{
    const k = _rulesSort.key;
    let va = a[k] ?? '', vb = b[k] ?? '';
    if (k === 'severity') {{ va = SEV_ORDER[va] ?? 99; vb = SEV_ORDER[vb] ?? 99; }}
    return _rulesSort.dir * (va < vb ? -1 : va > vb ? 1 : 0);
  }});
}}

function renderRulesTable() {{
  const filtered = getFilteredRules();
  const loading  = document.getElementById('rulesLoading');
  const empty    = document.getElementById('rulesEmpty');
  const wrap     = document.getElementById('rulesTableWrap');
  const meta     = document.getElementById('rulesMetaText');
  if (loading) loading.style.display = 'none';
  if (!filtered.length) {{
    if (wrap) wrap.style.display = 'none';
    if (empty) empty.style.display = 'block';
    return;
  }}
  if (wrap) wrap.style.display = 'block';
  if (empty) empty.style.display = 'none';
  if (meta) meta.textContent = `Showing ${{filtered.length}} of ${{_allRules.length}} rules`;

  // Update sort headers
  ['severity','title','category','source','created_at'].forEach(k => {{
    const th = document.getElementById('th-'+k);
    if (th) {{
      th.className = 'sortable' + (_rulesSort.key===k ? ' sort-'+(_rulesSort.dir===1?'asc':'desc') : '');
    }}
  }});

  const tbody = document.getElementById('rulesTbody');
  tbody.innerHTML = '';
  filtered.forEach(rule => {{
    const isCustom  = rule.source === 'custom' || (rule.tags||[]).includes('crawled');
    const isIos     = rule.platform === 'ios';
    const isJar     = rule.platform === 'jar';
    const isExe     = rule.platform === 'exe';
    const cweHtml   = (rule.cwe||[]).slice(0,2).map(c=>`<span class="cwe-mini">${{escHtml(c)}}</span>`).join(' ');
    const detIcon   = rule.detection_type === 'manifest'          ? 'fa-file-code'
                    : rule.detection_type === 'plist_key'         ? 'fa-list-check'
                    : rule.detection_type === 'entitlement'       ? 'fa-id-card'
                    : rule.detection_type === 'binary_flag'       ? 'fa-microchip'
                    : rule.detection_type === 'binary_string'     ? 'fa-terminal'
                    : rule.detection_type === 'manifest_attr'     ? 'fa-file-code'
                    : rule.detection_type === 'class_exists'      ? 'fa-cube'
                    : rule.detection_type === 'string_pattern'    ? 'fa-magnifying-glass-plus'
                    : rule.detection_type === 'entry_pattern'     ? 'fa-folder-open'
                    : rule.detection_type === 'library_version'   ? 'fa-box-open'
                    : rule.detection_type === 'duplicate_entries' ? 'fa-copy'
                    : rule.detection_type === 'services_entry'    ? 'fa-plug'
                    : rule.detection_type === 'pe_characteristic' ? 'fa-shield-halved'
                    : rule.detection_type === 'pe_imports'        ? 'fa-arrow-right-arrow-left'
                    : rule.detection_type === 'pe_imports_combo'  ? 'fa-layer-group'
                    : rule.detection_type === 'pe_section'        ? 'fa-table-cells'
                    : rule.detection_type === 'pe_manifest'       ? 'fa-scroll'
                    : 'fa-code';
    const platBadge = isIos
      ? `<span style="font-size:9px;background:rgba(148,163,184,.12);color:var(--text2);border:1px solid rgba(148,163,184,.2);padding:1px 5px;border-radius:3px;margin-right:4px"><i class="fa-brands fa-apple"></i> iOS</span>`
      : isJar
      ? `<span style="font-size:9px;background:rgba(249,115,22,.08);color:#fb923c;border:1px solid rgba(249,115,22,.2);padding:1px 5px;border-radius:3px;margin-right:4px"><i class="fa-brands fa-java"></i> JAR</span>`
      : isExe
      ? `<span style="font-size:9px;background:rgba(0,120,212,.08);color:#60a5fa;border:1px solid rgba(0,120,212,.2);padding:1px 5px;border-radius:3px;margin-right:4px"><i class="fa-brands fa-windows"></i> EXE</span>`
      : `<span style="font-size:9px;background:rgba(34,197,94,.08);color:#4ade80;border:1px solid rgba(34,197,94,.2);padding:1px 5px;border-radius:3px;margin-right:4px"><i class="fa-brands fa-android"></i> Android</span>`;
    const row      = document.createElement('tr');
    row.className  = 'rule-row' + (_openRuleId===rule.id ? ' selected' : '');
    row.onclick    = () => openRuleDetail(rule.id);
    row.innerHTML  = `
      <td>
        <label class="toggle-switch" onclick="event.stopPropagation()">
          <input type="checkbox" ${{rule.enabled?'checked':''}}
                 onchange="toggleRuleEnabled('${{escHtml(rule.id)}}',this.checked)">
          <span class="toggle-track"></span>
        </label>
      </td>
      <td><span class="sev-dot ${{escHtml(rule.severity)}}">${{escHtml(rule.severity)}}</span></td>
      <td>
        <div class="rule-title-cell">${{platBadge}}${{escHtml(rule.title)}}</div>
        <code class="rule-id-cell">${{escHtml(rule.id)}}</code>
      </td>
      <td><span class="cat-pill" title="${{escHtml(rule.category)}}">${{escHtml(rule.category.replace(/OWASP-M\d+-/,''))}}</span></td>
      <td><span class="det-pill"><i class="fa-solid ${{detIcon}}"></i> ${{escHtml(rule.detection_type)}}</span></td>
      <td>${{cweHtml || '<span style="color:var(--text3);font-size:11px">—</span>'}}</td>
      <td><span class="src-pill ${{escHtml(rule.source)}}">${{escHtml(rule.source)}}</span></td>
      <td style="font-size:10px;color:var(--text3);white-space:nowrap">${{rule.created_at ? new Date(rule.created_at*1000).toLocaleDateString('en-US',{{month:'short',day:'numeric',year:'numeric'}}) : '<span style="color:var(--text3)">—</span>'}}</td>
      <td style="text-align:right">
        ${{isCustom ? `<button class="btn btn-sm" style="padding:3px 8px;font-size:10px;color:var(--critical);border-color:rgba(239,68,68,.25)" onclick="event.stopPropagation();deleteRule('${{escHtml(rule.id)}}')" title="Delete"><i class="fa-solid fa-trash"></i></button>` : ''}}
        <i class="fa-solid fa-chevron-right" style="color:var(--text3);font-size:10px;margin-left:6px"></i>
      </td>`;
    tbody.appendChild(row);
  }});
}}

function quickFilter(sev) {{
  _quickSevFilter = sev;
  _quickTagFilter = '';
  // Check if it's actually a tag filter (e.g. 'crawled')
  if (sev && !['Critical','High','Medium','Low','Info','enabled',''].includes(sev)) {{
    _quickTagFilter = sev;
    _quickSevFilter = '';
    sev = '';
    // switch to Rules tab
    switchIntelTab('rules');
  }}
  // Highlight active stat
  document.querySelectorAll('.intel-stat').forEach(el => el.classList.remove('active'));
  if (sev === '') {{ document.getElementById('statAll')?.classList.add('active'); }}
  else if (sev === 'enabled') {{ document.getElementById('statActiveBtn')?.classList.add('active'); }}
  // Sync dropdowns
  const sevSel = document.getElementById('filterSeverity');
  const staSel = document.getElementById('filterStatus');
  if (sevSel) sevSel.value = (sev && sev !== 'enabled') ? sev : '';
  if (staSel) staSel.value = sev === 'enabled' ? 'enabled' : '';
  renderRulesTable();
}}

function filterRules() {{ renderRulesTable(); }}
function sortBy(key) {{
  _rulesSort.dir = _rulesSort.key===key ? -_rulesSort.dir : 1;
  _rulesSort.key = key;
  renderRulesTable();
}}

// ── Rule Detail Modal ────────────────────────────────────────
function openRuleDetail(id) {{
  const rule = _allRules.find(r => r.id === id);
  if (!rule) return;
  _openRuleId = id;
  renderRulesTable();  // update selected highlight

  // Sev icon
  const icon = document.getElementById('rdpSevIcon');
  if (icon) {{
    const icons = {{ Critical:'fa-skull-crossbones', High:'fa-triangle-exclamation',
                    Medium:'fa-exclamation', Low:'fa-info', Info:'fa-circle-info' }};
    icon.className = `rdp-sev-icon ${{rule.severity}}`;
    icon.innerHTML = `<i class="fa-solid ${{icons[rule.severity]||'fa-shield'}}"></i>`;
  }}

  // Title & pills
  const t = document.getElementById('rdpTitle');
  if (t) t.textContent = rule.title;
  const pills = document.getElementById('rdpPills');
  if (pills) {{
    pills.innerHTML = `
      <span class="sev-dot ${{escHtml(rule.severity)}}" style="font-size:12px">${{escHtml(rule.severity)}}</span>
      <span class="cat-pill">${{escHtml(rule.category.replace(/OWASP-M\d+-/,''))}}</span>
      <span class="src-pill ${{escHtml(rule.source)}}">${{escHtml(rule.source)}}</span>`;
  }}

  // Show edit/delete for custom rules
  const editBtn   = document.getElementById('rdpEditBtn');
  const deleteBtn = document.getElementById('rdpDeleteBtn');
  if (editBtn)   editBtn.style.display   = rule.source==='custom' ? 'flex' : 'none';
  if (deleteBtn) deleteBtn.style.display = rule.source==='custom' ? 'flex' : 'none';

  // Toggle
  const tog = document.getElementById('rdpToggle');
  const togLabel = document.getElementById('rdpToggleLabel');
  if (tog) {{ tog.checked = rule.enabled; tog.dataset.ruleId = id; }}
  if (togLabel) togLabel.textContent = rule.enabled ? 'Rule enabled' : 'Rule disabled';

  // Footer meta
  const idEl  = document.getElementById('rdpId');
  const srcEl = document.getElementById('rdpSource');
  if (idEl)  idEl.textContent  = rule.id;
  if (srcEl) srcEl.innerHTML   = `<span class="src-pill ${{escHtml(rule.source)}}">${{escHtml(rule.source)}}</span>`;

  // Overview tab
  setText('rdpDescription', rule.description || '—');
  setText('rdpAttackPath',  rule.attack_path  || '—');
  setText('rdpRemediation', rule.remediation  || '—');

  // Detection tab
  setText('rdpDetType', rule.detection_type || 'regex');
  const patDiv = document.getElementById('rdpPatterns');
  const manDiv = document.getElementById('rdpManifest');
  const patSec = document.getElementById('rdpPatternSection');
  const manSec = document.getElementById('rdpManifestSection');
  const iosSec = document.getElementById('rdpIosSection');
  const jarSec = document.getElementById('rdpJarSection');
  const exeSec = document.getElementById('rdpExeSection');

  const isIosDet = ['plist_key','entitlement','binary_flag'].includes(rule.detection_type);
  const isJarDet = ['manifest_attr','class_exists','string_pattern','entry_pattern',
                    'library_version','duplicate_entries','services_entry'].includes(rule.detection_type);
  const isExeDet = ['pe_characteristic','pe_imports','pe_imports_combo',
                    'pe_section','pe_manifest'].includes(rule.detection_type);

  if (patDiv) {{
    const pats = rule.patterns || [];
    if (rule.detection_type === 'binary_string' || (!isIosDet && !isJarDet && rule.detection_type !== 'manifest')) {{
      patDiv.innerHTML = pats.length
        ? pats.map(p=>`<div class="rdp-code-block">${{escHtml(p.pattern)}}</div>
                       <div class="rdp-code-meta"><span>flags: ${{p.flags||'i'}}</span>${{p.file_types?.length ? `<span>files: ${{p.file_types.join(', ')}}</span>` : ''}}</div>`).join('')
        : '<p style="color:var(--text3);font-size:13px">—</p>';
    }}
    if (patSec) patSec.style.display = (rule.detection_type==='manifest' || isIosDet || isJarDet || isExeDet) ? 'none' : 'block';
  }}
  if (manDiv) {{
    const mcs = rule.manifest_checks || [];
    manDiv.innerHTML = mcs.length
      ? mcs.map(mc=>`<div class="rdp-code-block">${{escHtml(mc.xpath)}}</div>`).join('')
      : '<p style="color:var(--text3);font-size:13px">—</p>';
    if (manSec) manSec.style.display = rule.detection_type==='manifest' ? 'block' : 'none';
  }}
  // iOS-specific detection section
  if (iosSec) {{
    if (isIosDet) {{
      const det = rule.ios_detection || {{}};
      let iosHtml = '';
      if (det.key_path) iosHtml += `<div class="rdp-code-meta"><span style="color:var(--text2)">Key path:</span></div><div class="rdp-code-block">${{escHtml(det.key_path)}}</div>`;
      if (det.key)      iosHtml += `<div class="rdp-code-meta"><span style="color:var(--text2)">Entitlement key:</span></div><div class="rdp-code-block">${{escHtml(det.key)}}</div>`;
      if (det.flag)     iosHtml += `<div class="rdp-code-meta"><span style="color:var(--text2)">Binary flag:</span></div><div class="rdp-code-block">${{escHtml(det.flag)}}</div>`;
      if (det.check)    iosHtml += `<div class="rdp-code-meta"><span style="color:var(--text2)">Condition:</span> <code>${{escHtml(det.check)}}</code></div>`;
      if (det.value !== undefined) iosHtml += `<div class="rdp-code-meta"><span style="color:var(--text2)">Expected value:</span> <code>${{escHtml(String(det.value))}}</code></div>`;
      iosSec.innerHTML = iosHtml || '<p style="color:var(--text3);font-size:13px">—</p>';
      iosSec.style.display = 'block';
    }} else {{
      iosSec.style.display = 'none';
    }}
  }}
  // JAR-specific detection section
  if (jarSec) {{
    if (isJarDet) {{
      const det = rule.jar_detection || {{}};
      let jarHtml = `<div class="rdp-code-meta"><span style="color:var(--text2)">Detection type:</span> <code>${{escHtml(rule.detection_type)}}</code></div>`;
      if (det.attribute)    jarHtml += `<div class="rdp-code-meta"><span style="color:var(--text2)">MANIFEST attribute:</span></div><div class="rdp-code-block">${{escHtml(det.attribute)}}</div>`;
      if (det.check)        jarHtml += `<div class="rdp-code-meta"><span style="color:var(--text2)">Check:</span> <code>${{escHtml(det.check)}}</code></div>`;
      if (det.value !== undefined && det.value !== '') jarHtml += `<div class="rdp-code-meta"><span style="color:var(--text2)">Value:</span> <code>${{escHtml(String(det.value))}}</code></div>`;
      if (det.class_name)   jarHtml += `<div class="rdp-code-meta"><span style="color:var(--text2)">Class name:</span></div><div class="rdp-code-block">${{escHtml(det.class_name)}}</div>`;
      if (det.pattern)      jarHtml += `<div class="rdp-code-meta"><span style="color:var(--text2)">Pattern:</span></div><div class="rdp-code-block">${{escHtml(det.pattern)}}</div>`;
      if (det.name_pattern) jarHtml += `<div class="rdp-code-meta"><span style="color:var(--text2)">Library version pattern:</span></div><div class="rdp-code-block">${{escHtml(det.name_pattern)}}</div>`;
      if (det.interface)    jarHtml += `<div class="rdp-code-meta"><span style="color:var(--text2)">SPI interface:</span></div><div class="rdp-code-block">${{escHtml(det.interface)}}</div>`;
      const jarDetEl = document.getElementById('rdpJarDetection');
      if (jarDetEl) jarDetEl.innerHTML = jarHtml;
      jarSec.style.display = 'block';
    }} else {{
      if (jarSec) jarSec.style.display = 'none';
    }}
  }}
  // EXE/PE-specific detection section
  if (exeSec) {{
    if (isExeDet) {{
      const det = rule.exe_detection || {{}};
      let exeHtml = `<div class="rdp-code-meta"><span style="color:var(--text2)">Detection type:</span> <code>${{escHtml(rule.detection_type)}}</code></div>`;
      if (det.flag)         exeHtml += `<div class="rdp-code-meta"><span style="color:var(--text2)">Security feature:</span> <code>${{escHtml(det.flag)}}</code></div>`;
      if (det.check)        exeHtml += `<div class="rdp-code-meta"><span style="color:var(--text2)">Check:</span> <code>${{escHtml(det.check)}}</code></div>`;
      if (det.apis && det.apis.length) {{
        exeHtml += `<div class="rdp-code-meta"><span style="color:var(--text2)">APIs checked (${{det.match || 'any'}}):</span></div>`;
        exeHtml += `<div class="rdp-code-block">${{escHtml(det.apis.join(', '))}}</div>`;
      }}
      if (det.min_matches)  exeHtml += `<div class="rdp-code-meta"><span style="color:var(--text2)">Min matches for trigger:</span> <code>${{escHtml(String(det.min_matches))}}</code></div>`;
      if (det.pattern)      exeHtml += `<div class="rdp-code-meta"><span style="color:var(--text2)">String pattern:</span></div><div class="rdp-code-block">${{escHtml(det.pattern)}}</div>`;
      const exeDetEl = document.getElementById('rdpExeDetection');
      if (exeDetEl) exeDetEl.innerHTML = exeHtml;
      exeSec.style.display = 'block';
    }} else {{
      if (exeSec) exeSec.style.display = 'none';
    }}
  }}
  setText('rdpConfidence', rule.confidence || '—');
  setText('rdpFPRate',     rule.false_positive_rate || '—');
  setText('rdpAdbCat',     rule.adb_category || '—');

  // References tab
  const cweDiv = document.getElementById('rdpCwe');
  if (cweDiv) {{
    cweDiv.innerHTML = (rule.cwe||[]).map(c =>
      `<a class="cwe-link" href="https://cwe.mitre.org/data/definitions/${{c.replace(/^CWE-/,'')}}.html" target="_blank" rel="noopener"><i class="fa-solid fa-link" style="font-size:9px"></i> ${{escHtml(c)}}</a>`
    ).join('') || '<span style="color:var(--text3);font-size:13px">None</span>';
    if (rule.cve && rule.cve.length) {{
      cweDiv.innerHTML += (rule.cve||[]).map(c=>
        `<span class="tag-chip-sm" style="border-color:rgba(239,68,68,.2);color:#f87171">${{escHtml(c)}}</span>`
      ).join('');
    }}
  }}
  const refDiv = document.getElementById('rdpRefs');
  if (refDiv) {{
    refDiv.innerHTML = (rule.references||[]).map(r => {{
      const lbl = r.replace(/^https?:\/\/(www\.)?/,'').split('/').slice(0,2).join('/');
      return `<a class="ref-link" href="${{escHtml(r)}}" target="_blank" rel="noopener"><i class="fa-solid fa-arrow-up-right-from-square" style="font-size:9px;flex-shrink:0"></i> ${{escHtml(lbl)}}</a>`;
    }}).join('') || '<span style="color:var(--text3);font-size:13px">No references</span>';
  }}
  const tagsDiv = document.getElementById('rdpTags');
  if (tagsDiv) {{
    tagsDiv.innerHTML = (rule.tags||[]).map(t=>`<span class="tag-chip-sm">${{escHtml(t)}}</span>`).join('')
      || '<span style="color:var(--text3);font-size:13px">None</span>';
  }}

  // Test cases tab
  const tcDiv = document.getElementById('rdpTestCases');
  if (tcDiv) {{
    const tcs = rule.test_cases || [];
    tcDiv.innerHTML = tcs.length
      ? tcs.map(tc=>`
          <div class="tc-item">
            <span class="tc-badge ${{tc.should_match?'match':'no-match'}}">${{tc.should_match?'MATCH':'SKIP'}}</span>
            <div>
              <div class="tc-text">${{escHtml(tc.code||'')}}</div>
              ${{tc.description ? `<div style="font-size:11px;color:var(--text3);margin-top:4px">${{escHtml(tc.description)}}</div>` : ''}}
            </div>
          </div>`).join('')
      : `<div class="intel-state" style="padding:40px 0">
           <i class="fa-solid fa-vial state-icon"></i>
           <h3>No test cases</h3>
           <p>This rule has no embedded test cases</p>
         </div>`;
  }}

  // Reset to overview tab
  switchRdpTab('overview');
  document.getElementById('ruleDetailOverlay').classList.add('open');
}}

function closeRuleDetail() {{
  _openRuleId = null;
  document.getElementById('ruleDetailOverlay')?.classList.remove('open');
  if (typeof renderRulesTable === 'function' && document.getElementById('rulesTbody')) renderRulesTable();
}}

function switchRdpTab(name, btn) {{
  document.querySelectorAll('.rdp-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.rdp-pane').forEach(p => p.classList.remove('active'));
  const pane = document.getElementById('rdpPane-'+name);
  if (pane) pane.classList.add('active');
  if (btn) btn.classList.add('active');
  else {{
    // find tab by matching onclick
    document.querySelectorAll('.rdp-tab').forEach(t => {{
      if (t.getAttribute('onclick').includes("'"+name+"'")) t.classList.add('active');
    }});
  }}
}}

function setText(id, text) {{
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}}

function openEditFromDetail() {{
  if (_openRuleId) openEditRuleModal(_openRuleId);
}}

function deleteRuleFromDetail() {{
  if (_openRuleId) {{ closeRuleDetail(); deleteRule(_openRuleId); }}
}}

async function toggleRuleFromDetail(checked) {{
  const id = document.getElementById('rdpToggle')?.dataset.ruleId;
  if (!id) return;
  try {{
    const res  = await fetch(`/api/rules/${{id}}/toggle`, {{method:'PATCH'}});
    const data = await res.json();
    const rule = _allRules.find(r => r.id === id);
    if (rule) {{ rule.enabled = data.enabled; }}
    const togLabel = document.getElementById('rdpToggleLabel');
    if (togLabel) togLabel.textContent = data.enabled ? 'Rule enabled' : 'Rule disabled';
    fetch('/api/rules/stats').then(r=>r.json()).then(renderIntelStats);
    renderRulesTable();
  }} catch(e) {{ console.error('Toggle failed:', e); }}
}}

async function toggleRuleEnabled(id, _newState) {{
  try {{
    const res  = await fetch(`/api/rules/${{id}}/toggle`, {{method:'PATCH'}});
    const data = await res.json();
    const rule = _allRules.find(r => r.id === id);
    if (rule) rule.enabled = data.enabled;
    // Sync detail modal toggle if open
    if (_openRuleId === id) {{
      const tog = document.getElementById('rdpToggle');
      const lbl = document.getElementById('rdpToggleLabel');
      if (tog) tog.checked = data.enabled;
      if (lbl) lbl.textContent = data.enabled ? 'Rule enabled' : 'Rule disabled';
    }}
    fetch('/api/rules/stats').then(r=>r.json()).then(renderIntelStats);
  }} catch(e) {{ console.error('Toggle failed:', e); }}
}}

async function deleteRule(id) {{
  if (!confirm(`Delete rule "${{id}}"? This cannot be undone.`)) return;
  try {{
    const res = await fetch(`/api/rules/${{id}}`, {{method:'DELETE'}});
    if (res.ok) {{
      _allRules = _allRules.filter(r => r.id !== id);
      if (_expandedRule === id) _expandedRule = null;
      const stats = await fetch('/api/rules/stats').then(r=>r.json());
      renderIntelStats(stats);
      renderRulesTable();
    }} else {{
      const d = await res.json(); showToast(d.error||'Delete failed', 'error');
    }}
  }} catch(e) {{ showToast('Delete failed: '+e.message, 'error'); }}
}}

// ── RULE FORM MODAL ──────────────────────────────────────────
function openAddRuleModal() {{
  document.getElementById('ruleModalTitle').textContent = 'Add Custom Rule';
  document.getElementById('ruleFormSubmit').innerHTML = '<i class="fa-solid fa-floppy-disk"></i> Save Rule';
  ['ruleEditId','ruleFormId','ruleFormTitle','ruleFormDesc','ruleFormAttack',
   'ruleFormRemediation','ruleFormPattern','ruleFormCwe','ruleFormRefs','ruleFormTags'].forEach(id => {{
    const el = document.getElementById(id); if (el) el.value = '';
  }});
  document.getElementById('ruleFormId').disabled = false;
  document.getElementById('ruleFormSeverity').value = 'High';
  document.getElementById('ruleFormCategory').value = 'Other';
  document.getElementById('ruleFormDetType').value = 'regex';
  document.getElementById('ruleFormFileTypes').value = '.java,.kt';
  document.getElementById('ruleFormError').style.display = 'none';
  updateDetTypeUI();
  document.getElementById('ruleModal').classList.add('open');
}}

function openEditRuleModal(id) {{
  const rule = _allRules.find(r => r.id === id);
  if (!rule) return;
  document.getElementById('ruleModalTitle').textContent = 'Edit Custom Rule';
  document.getElementById('ruleFormSubmit').innerHTML = '<i class="fa-solid fa-floppy-disk"></i> Update Rule';
  document.getElementById('ruleEditId').value   = id;
  document.getElementById('ruleFormId').value   = rule.id;
  document.getElementById('ruleFormId').disabled = true;
  document.getElementById('ruleFormTitle').value = rule.title||'';
  document.getElementById('ruleFormSeverity').value  = rule.severity||'High';
  document.getElementById('ruleFormCategory').value  = rule.category||'Other';
  document.getElementById('ruleFormDesc').value      = rule.description||'';
  document.getElementById('ruleFormAttack').value    = rule.attack_path||'';
  document.getElementById('ruleFormRemediation').value = rule.remediation||'';
  document.getElementById('ruleFormDetType').value   = rule.detection_type||'regex';
  document.getElementById('ruleFormFileTypes').value = ((rule.patterns||[])[0]?.file_types||['.java','.kt']).join(',');
  document.getElementById('ruleFormPattern').value   = (rule.patterns||[]).map(p=>p.pattern).join('\\n');
  document.getElementById('ruleFormCwe').value  = (rule.cwe||[]).join(', ');
  document.getElementById('ruleFormRefs').value = (rule.references||[]).join('\\n');
  document.getElementById('ruleFormTags').value = (rule.tags||[]).join(', ');
  document.getElementById('ruleFormError').style.display = 'none';
  updateDetTypeUI();
  document.getElementById('ruleModal').classList.add('open');
}}

function closeRuleModal() {{ document.getElementById('ruleModal')?.classList.remove('open'); }}
function updateDetTypeUI() {{
  const dt = document.getElementById('ruleFormDetType')?.value;
  const g  = document.getElementById('regexPatternGroup');
  if (g) g.style.display = dt === 'manifest' ? 'none' : 'flex';
}}

async function submitRuleForm() {{
  const errEl = document.getElementById('ruleFormError');
  errEl.style.display = 'none';
  const title = document.getElementById('ruleFormTitle').value.trim();
  if (!title) {{ errEl.textContent = 'Title is required.'; errEl.style.display='block'; return; }}
  const detType   = document.getElementById('ruleFormDetType').value;
  const patText   = document.getElementById('ruleFormPattern').value.trim();
  const fileTypes = document.getElementById('ruleFormFileTypes').value.split(',').map(s=>s.trim()).filter(Boolean);
  const patterns  = detType==='regex' && patText
    ? patText.split('\\n').filter(p=>p.trim()).map(p=>({{pattern:p.trim(),flags:'i',file_types:fileTypes}}))
    : [];
  const payload = {{
    id:            document.getElementById('ruleFormId').value.trim(),
    title,
    severity:      document.getElementById('ruleFormSeverity').value,
    category:      document.getElementById('ruleFormCategory').value,
    description:   document.getElementById('ruleFormDesc').value.trim(),
    attack_path:   document.getElementById('ruleFormAttack').value.trim(),
    remediation:   document.getElementById('ruleFormRemediation').value.trim(),
    detection_type:detType, patterns,
    cwe:           document.getElementById('ruleFormCwe').value.split(',').map(s=>s.trim()).filter(Boolean),
    references:    document.getElementById('ruleFormRefs').value.split('\\n').map(s=>s.trim()).filter(Boolean),
    tags:          document.getElementById('ruleFormTags').value.split(',').map(s=>s.trim()).filter(Boolean),
  }};
  const editId = document.getElementById('ruleEditId').value;
  const url    = editId ? `/api/rules/${{editId}}` : '/api/rules';
  const method = editId ? 'PUT' : 'POST';
  const btn    = document.getElementById('ruleFormSubmit');
  btn.disabled = true;
  btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Saving…';
  try {{
    const res  = await fetch(url, {{method,headers:{{'Content-Type':'application/json'}},body:JSON.stringify(payload)}});
    const data = await res.json();
    if (!res.ok) throw new Error(data.error||'Save failed');
    if (editId) {{
      const idx = _allRules.findIndex(r=>r.id===editId);
      if (idx!==-1) _allRules[idx]=data;
    }} else {{ _allRules.push(data); }}
    closeRuleModal();
    const stats = await fetch('/api/rules/stats').then(r=>r.json());
    renderIntelStats(stats);
    renderRulesTable();
  }} catch(e) {{
    errEl.textContent = e.message; errEl.style.display='block';
  }} finally {{
    btn.disabled = false;
    btn.innerHTML = `<i class="fa-solid fa-floppy-disk"></i> ${{editId?'Update':'Save'}} Rule`;
  }}
}}

function importRulesClick() {{ document.getElementById('importJsonInput').click(); }}
async function handleImportFile(input) {{
  const file = input.files[0]; if (!file) return;
  try {{
    const text = await file.text();
    const data = JSON.parse(text);
    const rulesList = Array.isArray(data) ? data : (data.patterns || []);
    let added=0, failed=0;
    for (const rule of rulesList) {{
      try {{
        const res = await fetch('/api/rules',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify(rule)}});
        if (res.ok) {{ const r=await res.json(); _allRules.push(r); added++; }}
        else failed++;
      }} catch {{ failed++; }}
    }}
    const stats = await fetch('/api/rules/stats').then(r=>r.json());
    renderIntelStats(stats); renderRulesTable();
    showToast(`Import done: ${{added}} rules added, ${{failed}} skipped/failed.`, added>0?'success':'warn');
  }} catch(e) {{ showToast('Import failed: '+e.message, 'error'); }}
  input.value='';
}}

// ── DYNAMIC ANALYSIS ──────────────────────────────────────────────────────
let _dynScanId = '';
let _dynPollTimer = null;

function openDynPanel(scanId) {{
  _dynScanId = scanId || '';
  document.getElementById('dynPanelOverlay').classList.add('open');
  loadDynConfig();
  refreshDynJobs();
  // Inject verify buttons into any visible finding cards
  injectDynVerifyButtons(_dynScanId);
}}
function closeDynPanel() {{
  document.getElementById('dynPanelOverlay').classList.remove('open');
  if (_dynPollTimer) {{ clearInterval(_dynPollTimer); _dynPollTimer = null; }}
}}

function switchDynMode(mode) {{
  document.getElementById('modeAdb').classList.toggle('active',       mode==='adb');
  document.getElementById('modeCorellium').classList.toggle('active', mode==='corellium');
  document.getElementById('adbConfig').style.display        = mode==='adb'       ? '' : 'none';
  document.getElementById('corelliumConfig').style.display  = mode==='corellium' ? '' : 'none';
}}

async function loadDynConfig() {{
  try {{
    const cfg = await fetch('/api/dynamic/config').then(r=>r.json());
    const mode = cfg.mode || 'adb';
    switchDynMode(mode);
    document.getElementById('dynAdbSerial').value        = cfg.adb_serial || '';
    document.getElementById('dynCorelliumUrl').value     = cfg.corellium_url || 'https://app.corellium.com';
    document.getElementById('dynCorelliumToken').value   = cfg.corellium_token || '';
    if (cfg.instance_id) {{
      const opt = document.createElement('option');
      opt.value = cfg.instance_id; opt.textContent = cfg.instance_id;
      opt.selected = true;
      document.getElementById('dynInstanceList').appendChild(opt);
    }}
    if (mode === 'adb') refreshAdbDevices();
  }} catch(e) {{ console.warn('dyn config load:', e); }}
}}

async function saveDynConfig() {{
  const mode = document.getElementById('modeCorellium').classList.contains('active')
               ? 'corellium' : 'adb';
  const cfg = {{
    mode,
    adb_serial:        document.getElementById('dynAdbSerial').value.trim(),
    corellium_url:     document.getElementById('dynCorelliumUrl').value.trim(),
    corellium_token:   document.getElementById('dynCorelliumToken').value.trim(),
    instance_id:       document.getElementById('dynInstanceList').value,
  }};
  await fetch('/api/dynamic/config', {{
    method:'POST', headers:{{'Content-Type':'application/json'}},
    body: JSON.stringify(cfg)
  }});
  document.getElementById('dynDeviceStatus').textContent = '✓ Saved';
  setTimeout(()=>document.getElementById('dynDeviceStatus').textContent='', 2000);
}}

async function refreshAdbDevices() {{
  try {{
    const data = await fetch('/api/dynamic/adb-devices').then(r=>r.json());
    const sel  = document.getElementById('adbDeviceList');
    sel.innerHTML = '<option value="">-- select --</option>';
    (data.devices || []).forEach(d => {{
      const opt = document.createElement('option');
      opt.value = d.serial; opt.textContent = `${{d.serial}} (${{d.model||'device'}})`;
      sel.appendChild(opt);
    }});
    document.getElementById('dynDeviceStatus').textContent =
      data.devices?.length ? `${{data.devices.length}} device(s) connected` : 'No ADB devices found';
  }} catch(e) {{ document.getElementById('dynDeviceStatus').textContent = 'ADB not available'; }}
}}

async function fetchCorelliumInstances() {{
  const url   = document.getElementById('dynCorelliumUrl').value.trim();
  const token = document.getElementById('dynCorelliumToken').value.trim();
  if (!token) {{ showToast('Enter your Corellium API token first', 'warn'); return; }}
  document.getElementById('dynDeviceStatus').textContent = 'Fetching instances…';
  try {{
    const data = await fetch('/api/dynamic/corellium-instances', {{
      method:'POST', headers:{{'Content-Type':'application/json'}},
      body: JSON.stringify({{url, token}})
    }}).then(r=>r.json());
    const sel = document.getElementById('dynInstanceList');
    sel.innerHTML = '';
    (data.instances || []).forEach(inst => {{
      const opt = document.createElement('option');
      opt.value = inst.id;
      opt.textContent = `${{inst.name}} (${{inst.os}}) — ${{inst.state}}`;
      sel.appendChild(opt);
    }});
    document.getElementById('dynDeviceStatus').textContent =
      `${{(data.instances||[]).length}} Android instance(s)`;
  }} catch(e) {{
    document.getElementById('dynDeviceStatus').textContent = 'Error: ' + e.message;
  }}
}}

async function testCorelliumConnection() {{
  const url   = document.getElementById('dynCorelliumUrl').value.trim();
  const token = document.getElementById('dynCorelliumToken').value.trim();
  document.getElementById('dynDeviceStatus').textContent = 'Testing…';
  try {{
    const data = await fetch('/api/dynamic/corellium-test', {{
      method:'POST', headers:{{'Content-Type':'application/json'}},
      body: JSON.stringify({{url, token}})
    }}).then(r=>r.json());
    document.getElementById('dynDeviceStatus').textContent =
      data.ok ? `✓ Connected as ${{data.user||'user'}}` : `✖ ${{data.error}}`;
  }} catch(e) {{
    document.getElementById('dynDeviceStatus').textContent = 'Connection failed';
  }}
}}

// ── Inject verify buttons into finding cards ─────────────────────────────
function injectDynVerifyButtons(scanId) {{
  document.querySelectorAll('.finding-card').forEach((card, idx) => {{
    if (card.querySelector('.dyn-verify-btn')) return; // already injected
    const header = card.querySelector('.card-header');
    if (!header) return;
    const sev   = card.dataset.sev || '';
    const title = card.querySelector('.card-title')?.textContent?.trim()
                  .replace(/^#\d+\s*/, '') || `Finding ${{idx+1}}`;
    const desc  = card.querySelector('.desc-text')?.textContent?.trim() || '';
    const cat   = card.dataset.cat || '';
    const btn   = document.createElement('button');
    btn.className = 'dyn-verify-btn';
    btn.id        = `dynBtn-${{idx}}`;
    btn.innerHTML = '<i class="fa-solid fa-bolt"></i> Verify';
    btn.title     = 'Run dynamic verification';
    btn.onclick   = (e) => {{
      e.stopPropagation();
      startDynVerify(scanId, idx, title, sev, cat, desc);
    }};
    const meta = header.querySelector('.card-meta');
    if (meta) meta.insertBefore(btn, meta.firstChild);
    else header.appendChild(btn);
  }});
}}

async function startDynVerify(scanId, idx, title, sev, cat, desc) {{
  // Auto-save current config first
  await saveDynConfig();
  // Open the panel
  openDynPanel(scanId);
  document.getElementById(`dynBtn-${{idx}}`).classList.add('running');
  document.getElementById(`dynBtn-${{idx}}`).innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Running';
  try {{
    const res = await fetch('/api/dynamic/verify', {{
      method: 'POST',
      headers: {{'Content-Type':'application/json'}},
      body: JSON.stringify({{
        scan_id: scanId, finding_index: idx,
        finding: {{ title, severity: sev, category: cat, description: desc }}
      }})
    }});
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to start');
    // Poll for updates
    pollDynJob(data.job_id, idx);
  }} catch(e) {{
    const btn = document.getElementById(`dynBtn-${{idx}}`);
    if (btn) {{ btn.classList.remove('running'); btn.innerHTML = '<i class="fa-solid fa-bolt"></i> Verify'; }}
    showToast('Dynamic verify error: ' + e.message, 'error');
  }}
}}

async function pollDynJob(jobId, cardIdx) {{
  refreshDynJobs();
  let _pollAttempts = 0;
  const _POLL_MAX = 150; // 5 minutes at 2s
  const interval = setInterval(async () => {{
    _pollAttempts++;
    try {{
      const data = await fetch(`/api/dynamic/verify/${{jobId}}`).then(r=>r.json());
      renderDynJob(data);
      if (data.status === 'done' || data.status === 'error') {{
        clearInterval(interval);
        updateDynVerifyBtn(cardIdx, data);
      }}
    }} catch {{ clearInterval(interval); }}
    if (_pollAttempts >= _POLL_MAX) {{
      clearInterval(interval);
      const btn = document.getElementById(`dynBtn-${{cardIdx}}`);
      if (btn) {{ btn.classList.remove('running'); btn.innerHTML='<i class="fa-solid fa-clock"></i> Timed out'; }}
    }}
  }}, 2000);
}}

function updateDynVerifyBtn(idx, job) {{
  const btn = document.getElementById(`dynBtn-${{idx}}`);
  if (!btn) return;
  btn.classList.remove('running');
  const v = job.verdict?.verdict || '';
  if (v === 'true_positive')  {{ btn.className='dyn-verify-btn done-tp'; btn.innerHTML='<i class="fa-solid fa-triangle-exclamation"></i> True Positive'; }}
  else if (v === 'false_positive') {{ btn.className='dyn-verify-btn done-fp'; btn.innerHTML='<i class="fa-solid fa-check"></i> False Positive'; }}
  else if (job.status === 'error') {{ btn.className='dyn-verify-btn'; btn.innerHTML='<i class="fa-solid fa-xmark"></i> Error'; }}
  else {{ btn.className='dyn-verify-btn done-un'; btn.innerHTML='<i class="fa-solid fa-question"></i> Uncertain'; }}
}}

async function refreshDynJobs() {{
  try {{
    const jobs = await fetch('/api/dynamic/jobs').then(r=>r.json());
    const active = jobs.filter(j => j.status==='running' || j.status==='queued');
    const done   = jobs.filter(j => j.status==='done' || j.status==='error');
    document.getElementById('dynActiveJobs').innerHTML =
      active.length ? active.map(renderDynJobHTML).join('') : '<div class="dyn-empty">No active jobs</div>';
    document.getElementById('dynDoneJobs').innerHTML =
      done.length   ? done.map(renderDynJobHTML).join('')   : '<div class="dyn-empty">No completed verifications yet</div>';
  }} catch(e) {{}}
}}

function renderDynJobHTML(job) {{
  const v       = job.verdict?.verdict || '';
  const conf    = job.verdict?.confidence ?? '';
  const reason  = job.verdict?.reasoning || '';
  const iconCls = {{queued:'queued',running:'running',done_tp:'done-tp',done_fp:'done-fp',error:'error'}}[
    job.status==='done' ? (v==='true_positive'?'done_tp':v==='false_positive'?'done_fp':'queued') : job.status] || 'queued';
  const iconI   = {{queued:'fa-clock',running:'fa-circle-notch fa-spin',done_tp:'fa-triangle-exclamation',done_fp:'fa-check-circle',error:'fa-xmark-circle'}}[iconCls] || 'fa-clock';
  const badgeCls = {{true_positive:'true-positive',false_positive:'false-positive',uncertain:'uncertain'}}[v] || 'running';
  const badgeTxt = v ? v.replace('_',' ').replace(/\b\w/g,c=>c.toUpperCase()) : (job.status==='error'?'Error':'Running');
  const pct     = job.progress || 0;
  const barCls  = v==='true_positive'?'done-tp':v==='false_positive'?'done-fp':'';
  return `
  <div class="dyn-job-card">
    <div class="dyn-job-top">
      <div class="dyn-job-icon ${{iconCls}}"><i class="fa-solid ${{iconI}}"></i></div>
      <div class="dyn-job-title">${{escHtml(job.finding_title||'Finding')}}</div>
      ${{conf!==''?`<span style="font-size:10px;color:var(--text3)">${{conf}}%</span>`:''}}
      <span class="dyn-job-badge ${{badgeCls}}">${{badgeTxt}}</span>
    </div>
    <div class="dyn-progress"><div class="dyn-progress-bar ${{barCls}}" style="width:${{pct}}%"></div></div>
    <div class="dyn-job-msg">${{escHtml(job.message||'')}}</div>
    ${{reason?`<div class="dyn-job-reasoning"><b>AI Reasoning:</b> ${{escHtml(reason)}}</div>`:''}}\
    ${{job.verdict?.key_evidence?.length?`<div class="dyn-job-reasoning" style="font-size:10.5px"><b>Key Evidence:</b><ul style="margin:4px 0 0 14px">${{job.verdict.key_evidence.map(e=>`<li>${{escHtml(e)}}</li>`).join('')}}</ul></div>`:''}}\
    ${{job.logcat?`<span class="dyn-logcat-toggle" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'block':'none'"><i class="fa-solid fa-terminal"></i> Toggle logcat</span><div class="dyn-logcat">${{escHtml(job.logcat)}}</div>`:''}}\
  </div>`;
}}
function renderDynJob(job) {{ refreshDynJobs(); }}

document.addEventListener('click', e => {{
  if (e.target === document.getElementById('dynPanelOverlay')) closeDynPanel();
}});

// ── INTEL SUB-NAV ─────────────────────────────────────────────────────────
function switchIntelTab(tab) {{
  const rulesEl   = document.getElementById('rulesTableWrap');
  const loadEl    = document.getElementById('rulesLoading');
  const emptyEl   = document.getElementById('rulesEmpty');
  const toolbarEl = document.querySelector('.intel-toolbar');
  const sourcesEl = document.getElementById('sourcesPanel');
  const statStrip = document.querySelector('.intel-stats-strip');

  document.getElementById('subnavRules').classList.toggle('active',   tab==='rules');
  document.getElementById('subnavSources').classList.toggle('active', tab==='sources');

  if (tab === 'rules') {{
    if (toolbarEl)  toolbarEl.style.display  = '';
    if (statStrip)  statStrip.style.display  = '';
    if (sourcesEl)  sourcesEl.style.display  = 'none';
    // restore rules table visibility
    if (loadEl && loadEl.style.display !== 'none') loadEl.style.display = 'flex';
    else if (rulesEl) rulesEl.style.display = '';
  }} else {{
    if (toolbarEl) toolbarEl.style.display  = 'none';
    if (statStrip) statStrip.style.display  = 'none';
    if (loadEl)    loadEl.style.display     = 'none';
    if (emptyEl)   emptyEl.style.display    = 'none';
    if (rulesEl)   rulesEl.style.display    = 'none';
    if (sourcesEl) sourcesEl.style.display  = 'block';
  }}
}}

// ── AI URL EXTRACTOR ───────────────────────────────────────────────────────
async function runUrlExtract() {{
  const url = document.getElementById('extractUrl').value.trim();
  if (!url) {{ showToast('Please enter a URL first', 'warn'); return; }}

  const btn     = document.getElementById('extractBtn');
  const resArea = document.getElementById('extractResult');
  const logEl   = document.getElementById('extractLog');
  const listEl  = document.getElementById('suggestedRules');
  const emptyEl = document.getElementById('extractEmpty');

  btn.disabled = true;
  btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Extracting…';
  resArea.classList.add('visible');
  logEl.style.display   = 'block';
  logEl.textContent     = '⟳ Fetching page content…';
  listEl.innerHTML      = '';
  emptyEl.style.display = 'none';

  try {{
    const res  = await fetch('/api/intel/extract-from-url', {{
      method: 'POST',
      headers: {{'Content-Type':'application/json'}},
      body: JSON.stringify({{ url }})
    }});
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Server error');

    logEl.textContent = data.log || '';
    const rules = data.rules || [];

    if (rules.length === 0) {{
      emptyEl.style.display = 'flex';
    }} else {{
      listEl.innerHTML = '';
      rules.forEach((r, idx) => {{
        const sev   = r.severity || 'High';
        const sevCls = {{'Critical':'c','High':'h','Medium':'m','Low':'l','Info':'i'}}[sev] || 'h';
        listEl.innerHTML += `
          <div class="suggested-rule-card" id="srCard-${{idx}}">
            <span class="sev-dot ${{sevCls}}"></span>
            <div class="suggested-rule-info">
              <div class="suggested-rule-title">${{escHtml(r.title||'Unnamed Rule')}}</div>
              <div class="suggested-rule-desc">${{escHtml((r.description||'').substring(0,160))}}${{(r.description||'').length>160?'…':''}}</div>
              <div class="suggested-rule-meta">
                ${{r.category?`<span class="cat-pill" title="${{escHtml(r.category)}}">${{escHtml(r.category)}}</span>`:''}}
                ${{sev?`<span class="sev-dot ${{sevCls}}" style="margin-top:3px"></span><span style="font-size:11px;color:var(--text3)">${{sev}}</span>`:''}}
                ${{(r.cwe||[]).map(c=>`<span class="cwe-mini">${{escHtml(c)}}</span>`).join('')}}
              </div>
            </div>
            <div class="suggested-rule-actions">
              <button class="btn btn-primary btn-sm" onclick="importSuggestedRule(${{idx}})">
                <i class="fa-solid fa-plus"></i> Add
              </button>
              <button class="btn btn-sm" onclick="document.getElementById('srCard-${{idx}}').remove()">
                <i class="fa-solid fa-xmark"></i>
              </button>
            </div>
          </div>`;
        // store rule data on window for import
        window._suggestedRules = window._suggestedRules || {{}};
        window._suggestedRules[idx] = r;
      }});
    }}
  }} catch(e) {{
    logEl.textContent = '✖ Error: ' + e.message;
  }} finally {{
    btn.disabled = false;
    btn.innerHTML = '<i class="fa-solid fa-wand-magic-sparkles"></i> Extract Rules';
  }}
}}

async function importSuggestedRule(idx) {{
  const rule = (window._suggestedRules || {{}})[idx];
  if (!rule) return;
  try {{
    const res = await fetch('/api/rules', {{
      method:'POST', headers:{{'Content-Type':'application/json'}},
      body: JSON.stringify(rule)
    }});
    if (!res.ok) {{ const d=await res.json(); throw new Error(d.error||'Failed'); }}
    const newRule = await res.json();
    _allRules.push(newRule);
    const stats = await fetch('/api/rules/stats').then(r=>r.json());
    renderIntelStats(stats);
    const card = document.getElementById('srCard-'+idx);
    if (card) {{
      card.style.opacity='0.5';
      card.querySelector('.suggested-rule-actions').innerHTML =
        '<span style="font-size:11px;color:#4ade80"><i class="fa-solid fa-check"></i> Added</span>';
    }}
  }} catch(e) {{ showToast('Could not add rule: '+e.message, 'error'); }}
}}

// ── BLOG SOURCES SYNC (no AI) ─────────────────────────────────────────────
async function runBlogSync() {{
  const btn    = document.getElementById('blogSyncBtn');
  const status = document.getElementById('blogSyncStatus');
  const log    = document.getElementById('blogSyncLog');
  const results= document.getElementById('blogSyncResults');
  btn.disabled = true;
  btn.innerHTML= '<i class="fa-solid fa-spinner fa-spin"></i> Syncing…';
  status.textContent = '';
  log.style.display  = 'block';
  log.textContent    = 'Fetching RSS feeds from security blogs…';
  results.innerHTML  = '';

  try {{
    const res  = await fetch('/api/intel/sources-sync', {{method:'POST'}});
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Sync failed');

    log.textContent = data.log || '';

    const added        = data.added   || 0;
    const updated_c    = data.updated || 0;
    const found        = data.found   || 0;
    const sources      = data.sources || 0;
    const totalCrawled = data.total_crawled || 0;

    if (added > 0 || updated_c > 0) {{
      const parts = [];
      if (added > 0)     parts.push(`${{added}} new rule${{added!==1?'s':''}} added`);
      if (updated_c > 0) parts.push(`${{updated_c}} rule${{updated_c!==1?'s':''}} updated`);
      status.innerHTML = `<span style="color:#34d399"><i class="fa-solid fa-circle-check"></i> ${{parts.join(', ')}} from ${{found}} patterns</span>`;
    }} else if (totalCrawled > 0) {{
      status.innerHTML = `<span style="color:var(--text3)"><i class="fa-solid fa-circle-check" style="color:#34d399"></i> Up to date — ${{totalCrawled}} crawled rule${{totalCrawled!==1?'s':''}} already in your library (<a href="#" onclick="switchIntelTab('rules');quickFilter('crawled');return false" style="color:var(--accent)">view</a>)</span>`;
    }} else {{
      status.innerHTML = `<span style="color:var(--text3)">Checked ${{sources}} sources — ${{found}} patterns found, none matched import criteria</span>`;
    }}

    if (data.source_details && Object.keys(data.source_details).length) {{
      const rows = Object.entries(data.source_details).map(([name, s]) => {{
        const icon = s.found > 0 ? '🟢' : (s.error ? '🔴' : '⚪');
        const pats = s.found > 0 ? ` <span style="color:#34d399;font-weight:600">+${{s.found}} patterns</span>` : '';
        const err  = s.error ? ` <span style="color:#f87171;font-size:10px">${{s.error.substring(0,50)}}</span>` : '';
        return `<div style="padding:4px 0;border-bottom:1px solid var(--border);font-size:11px;display:flex;gap:8px;align-items:center">
          <span>${{icon}}</span>
          <span style="flex:1;color:var(--text)">${{name}}</span>
          <span style="color:var(--text3)">${{s.articles||0}} articles</span>
          ${{pats}}${{err}}
        </div>`;
      }}).join('');
      results.innerHTML = `<div style="border:1px solid var(--border);border-radius:6px;padding:10px 12px;max-height:220px;overflow-y:auto">${{rows}}</div>`;
    }}

    if (added > 0 || true) {{
      const rules = await fetch('/api/rules').then(r=>r.json());
      _allRules = rules;
      const stats = await fetch('/api/rules/stats').then(r=>r.json());
      renderIntelStats(stats); renderRulesTable();
    }}
  }} catch(e) {{
    log.textContent  = 'Error: ' + e.message;
    status.style.color = '#f87171';
  }} finally {{
    btn.disabled = false;
    btn.innerHTML= '<i class="fa-solid fa-rotate"></i> Sync All Sources';
  }}
}}

// ── FEED SYNC ─────────────────────────────────────────────────────────────
async function runFeedSync(feedId) {{
  const dotEl = document.getElementById('feedDot-'+feedId);
  const lblEl = document.getElementById('feedLbl-'+feedId);
  if (!dotEl||!lblEl) return;
  dotEl.className = 'feed-status-dot running';
  lblEl.textContent = 'Syncing…';
  try {{
    const res  = await fetch('/api/intel/feed-sync', {{
      method:'POST', headers:{{'Content-Type':'application/json'}},
      body: JSON.stringify({{ feed: feedId }})
    }});
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Sync failed');
    dotEl.className   = 'feed-status-dot ok';
    const added = data.added || 0;
    lblEl.textContent = added > 0 ? `${{added}} new rules` : 'Up to date';
    if (added > 0) {{
      // reload rules list
      const rules = await fetch('/api/rules').then(r=>r.json());
      _allRules = rules;
      const stats = await fetch('/api/rules/stats').then(r=>r.json());
      renderIntelStats(stats); renderRulesTable();
    }}
  }} catch(e) {{
    dotEl.className   = 'feed-status-dot error';
    lblEl.textContent = 'Error: ' + e.message.substring(0,40);
  }}
}}

// Close modals on outside click / Esc
document.addEventListener('click', e => {{
  if (e.target === document.getElementById('ruleModal'))         closeRuleModal();
  if (e.target === document.getElementById('ruleDetailOverlay')) closeRuleDetail();
}});
document.addEventListener('keydown', e => {{
  if (e.key === 'Escape') {{ closePocModal(); closeRuleModal(); closeRuleDetail(); closeDrawer(); }}
}});

// ── INIT ── (DOM is already ready since this script is at end of body)
if (window.location.search.includes('view=intelligence')) {{
  loadIntelHub();  // call directly — DOMContentLoaded already fired
}}

// Inject dynamic verify buttons into any existing finding cards
(function() {{
  const scanId = _getScanId() || '';
  if (scanId && document.querySelectorAll('.finding-card').length) {{
    injectDynVerifyButtons(scanId);
  }}

  // Deep-link: scroll to a specific finding if __JUMP_FINDING is set
  if (typeof window.__JUMP_FINDING !== 'undefined') {{
    const cards = document.querySelectorAll('.finding-card');
    const target = cards[window.__JUMP_FINDING - 1];
    if (target) {{
      target.scrollIntoView({{behavior: 'smooth', block: 'center'}});
      target.style.transition = 'box-shadow 0.3s ease';
      target.style.boxShadow = '0 0 0 2px var(--accent)';
      setTimeout(() => {{ target.style.boxShadow = ''; }}, 2500);
    }}
  }}
}})();

// ── EXPORT DROPDOWN ──────────────────────────────────────────────────────────
function toggleExportMenu() {{
  const m = document.getElementById('exportMenu');
  if (m) m.style.display = m.style.display === 'none' ? '' : 'none';
}}
function closeExportMenu() {{
  const m = document.getElementById('exportMenu');
  if (m) m.style.display = 'none';
}}
document.addEventListener('click', function(e) {{
  const dd = e.target.closest('.export-dropdown');
  if (!dd) closeExportMenu();
}});

function exportSarif(scanId) {{
  window.location.href = '/api/scans/' + scanId + '/export/sarif';
}}
function exportCsv(scanId) {{
  window.location.href = '/api/scans/' + scanId + '/export/csv';
}}

// ── CONTENT TABS ─────────────────────────────────────────────────────────────
function switchTab(name) {{
  const panels = {{ findings:'findingsPanel', heatmap:'heatmapPanel' }};
  const tabs   = {{ findings:'tabFindings',   heatmap:'tabHeatmap'   }};
  Object.keys(panels).forEach(k => {{
    const p = document.getElementById(panels[k]);
    const t = document.getElementById(tabs[k]);
    if (p) p.style.display = (k === name) ? (k === 'findings' ? 'flex' : 'block') : 'none';
    if (t) t.classList.toggle('active', k === name);
  }});
  if (name === 'findings' && _allFindings.length === 0) loadFindingsTab();
  if (name === 'heatmap'  && !_heatmapBuilt)            buildHeatmap();
}}

// ── FINDINGS TAB ─────────────────────────────────────────────────────────────
let _allFindings = [];
let _filteredFindings = [];
let _renderOffset = 0;
const _PAGE_SIZE  = 50;
let _currentSevFilter    = 'all';
let _filterDebounceTimer = null;
let _heatmapBuilt        = false;
// Helper to get the current scan ID from the URL or the topbar data attribute
function _getScanId() {{
  return window.location.pathname.split('/scans/')[1]?.split('/')[0]
      || document.querySelector('[data-scan-id]')?.dataset.scanId
      || null;
}}
let _currentScanId = _getScanId();

// Sev colors
const SEV_COLORS = {{
  Critical:'#ef4444', High:'#f97316', Medium:'#eab308',
  Low:'#22c55e', Info:'#06b6d4'
}};
const SEV_BG = {{
  Critical:'rgba(239,68,68,.15)', High:'rgba(249,115,22,.15)',
  Medium:'rgba(234,179,8,.15)', Low:'rgba(34,197,94,.15)', Info:'rgba(6,182,212,.15)'
}};
const TRIAGE_CLASS = {{
  'New':'tp-new','Confirmed':'tp-confirmed','False Positive':'tp-fp',
  'Accepted Risk':'tp-accepted','Fixed':'tp-fixed','In Progress':'tp-inprogress'
}};

function loadFindingsTab() {{
  const el = document.getElementById('findingsData');
  if (!el) return;
  let data;
  try {{ data = JSON.parse(el.textContent.split('<\\\\/').join('</')); }} catch(e) {{
    document.getElementById('findingsList').innerHTML =
      '<div style="text-align:center;padding:40px;color:var(--text3)"><i class="fa-solid fa-triangle-exclamation" style="font-size:24px;margin-bottom:8px;display:block;color:var(--high)"></i>Failed to parse findings data.</div>';
    return;
  }}
  if (!data || !data.findings) {{
    document.getElementById('findingsList').innerHTML =
      '<div style="text-align:center;padding:40px;color:var(--text3)"><i class="fa-solid fa-circle-info" style="font-size:24px;margin-bottom:8px;display:block"></i>No findings data available for this scan.</div>';
    return;
  }}

  _allFindings = data.findings;

  // Update severity chip labels with counts
  const sevCounts = {{}};
  _allFindings.forEach(f => {{ sevCounts[f.severity] = (sevCounts[f.severity]||0) + 1; }});
  const allChip = document.querySelector('.f-chip[data-sev="all"]');
  if (allChip) allChip.textContent = 'All (' + _allFindings.length + ')';
  ['Critical','High','Medium','Low','Info'].forEach(sev => {{
    const chip = document.querySelector(`.f-chip[data-sev="${{sev}}"]`);
    if (chip) chip.textContent = sevCounts[sev] ? sev + ' (' + sevCounts[sev] + ')' : sev;
  }});

  // Populate category dropdown
  const cats = [...new Set(_allFindings.map(f => f.category || 'Other').filter(Boolean))].sort();
  const sel = document.getElementById('fFilterCat');
  if (sel) cats.forEach(c => {{ const o = document.createElement('option'); o.value = c; o.textContent = c; sel.appendChild(o); }});

  // Merge triage from server if available (for page reload)
  const sid = _getScanId();
  if (sid) {{
    fetch('/api/scans/' + sid + '/findings').then(r => r.json()).then(d => {{
      if (d.findings) {{
        const triageMap = {{}};
        d.findings.forEach(f => {{ triageMap[f.id] = {{status:f.triage_status||'New',note:f.suppression_note||''}}; }});
        _allFindings.forEach(f => {{
          const t = triageMap[f.id] || {{}};
          f.triage_status = t.status || 'New';
          f.suppression_note = t.note || '';
        }});
      }}
      applyFilters();
    }}).catch(() => applyFilters());
  }} else {{
    applyFilters();
  }}
}}

function applyFilters() {{
  const sev   = _currentSevFilter;
  const cat   = (document.getElementById('fFilterCat')?.value || '').toLowerCase();
  const st    = (document.getElementById('fFilterStatus')?.value || '').toLowerCase();
  const query = (document.getElementById('fSearch')?.value || '').toLowerCase();

  _filteredFindings = _allFindings.filter(f => {{
    if (sev !== 'all' && f.severity !== sev) return false;
    if (cat && (f.category||'').toLowerCase() !== cat) return false;
    if (st  && (f.triage_status||'New').toLowerCase() !== st) return false;
    if (query) {{
      const hay = (f.title+' '+(f.description||'')+' '+(f.evidence?.file||'')).toLowerCase();
      if (!hay.includes(query)) return false;
    }}
    return true;
  }});

  _renderOffset = 0;
  const el = document.getElementById('findingsList');
  if (el) el.innerHTML = '';
  renderNextPage();

  const cnt = document.getElementById('fResultCount');
  if (cnt) cnt.textContent = _filteredFindings.length + ' finding' + (_filteredFindings.length!==1?'s':'');
}}

function renderNextPage() {{
  const el = document.getElementById('findingsList');
  if (!el) return;

  const slice = _filteredFindings.slice(_renderOffset, _renderOffset + _PAGE_SIZE);
  _renderOffset += slice.length;

  if (_renderOffset === 0 && slice.length === 0) {{
    el.innerHTML = '<div style="text-align:center;padding:40px;color:var(--text3)">No findings match the current filters.</div>';
    return;
  }}

  slice.forEach(f => {{
    const div = document.createElement('div');
    div.className = 'finding-row';
    div.onclick = () => openDrawer(f);

    const sev  = f.severity || 'Info';
    const tc   = TRIAGE_CLASS[f.triage_status||'New'] || 'tp-new';

    // Location: file + line
    const ev       = f.evidence || {{}};
    const fileFull = ev.file || '';
    const fileName = fileFull.split('/').pop() || fileFull;
    const lineNum  = ev.line ? `:${{ev.line}}` : '';
    const locHtml  = fileName
      ? `<span class="fr-loc-file">${{escHtml(fileName)}}${{escHtml(lineNum)}}</span>`
      : '';

    // Code snippet: first non-empty line of the snippet block
    let snippetLine = '';
    if (ev.snippet) {{
      const lines = ev.snippet.split('\\n');
      for (const ln of lines) {{
        const stripped = ln.replace(/^\d+:\s*/, '').trim();
        if (stripped) {{ snippetLine = stripped; break; }}
      }}
    }}
    const snippetHtml = snippetLine
      ? `<span class="fr-snippet" title="${{escHtml(snippetLine)}}">${{escHtml(snippetLine)}}</span>`
      : '';

    const locRow = (locHtml || snippetHtml)
      ? `<div class="fr-loc">${{locHtml}}${{snippetHtml}}</div>`
      : '';

    // Description or attack path
    const desc = f.description || f.attack_path || '';
    const descHtml = desc
      ? `<div class="fr-desc">${{escHtml(desc)}}</div>`
      : '';

    const bodyHtml = (descHtml || locRow)
      ? `<div class="fr-body">${{descHtml}}${{locRow}}</div>`
      : '';

    // Dynamic scan button — stops propagation so it doesn't open drawer
    const dynBtn = `<button class="fr-dyn-btn" title="Run dynamic scan for this finding"
        onclick="event.stopPropagation();triggerDynamicScanRow(event,this,${{JSON.stringify(f.id??f.fid??0)}})">
      <i class="fa-solid fa-play"></i>
    </button>`;

    div.innerHTML = `
      <div class="fr-top">
        <span class="fr-sev" style="background:${{SEV_BG[sev]||'rgba(107,114,128,.1)'}};color:${{SEV_COLORS[sev]||'#9ca3af'}}">${{sev}}</span>
        <span class="fr-title">${{escHtml(f.title||'')}}</span>
        <span class="fr-cat">${{escHtml(f.category||'Other')}}</span>
        <span class="triage-pill ${{tc}}" id="tpill-${{f.id??f.fid}}">${{f.triage_status||'New'}}</span>
        ${{dynBtn}}
      </div>
      ${{bodyHtml}}
    `;
    el.appendChild(div);
  }});

  // Remove old load-more
  const old = el.querySelector('.load-more-row');
  if (old) old.remove();

  if (_renderOffset < _filteredFindings.length) {{
    const more = document.createElement('div');
    more.className = 'load-more-row';
    more.innerHTML = `<button class="load-more-btn" onclick="renderNextPage()">
      Load more (${{_filteredFindings.length - _renderOffset}} remaining)
    </button>`;
    el.appendChild(more);
  }}
}}

function setFChip(btn, sev) {{
  document.querySelectorAll('.f-chip').forEach(c => c.classList.remove('active'));
  btn.classList.add('active');
  _currentSevFilter = sev;
  applyFilters();
}}

function setFChipByName(sev) {{
  const chip = document.querySelector(`.f-chip[data-sev="${{sev}}"]`);
  if (chip) setFChip(chip, sev);
}}

function debounceFilter() {{
  clearTimeout(_filterDebounceTimer);
  _filterDebounceTimer = setTimeout(applyFilters, 180);
}}

function escHtml(s) {{
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}}

// ── DETAIL DRAWER ─────────────────────────────────────────────────────────────
let _drawerFinding = null;
let _drawerScanId  = null;

function openDrawer(f) {{
  _drawerFinding = f;
  _drawerScanId = _getScanId() || '';

  const ev = f.evidence || {{}};
  const sev = f.severity || 'Info';
  const tc  = TRIAGE_CLASS[f.triage_status||'New'] || 'tp-new';
  const cweLinks = (f.cwe||[]).map(c =>
    `<a href="https://cwe.mitre.org/data/definitions/${{c.replace('CWE-','')}}.html"
        target="_blank" rel="noopener" class="drawer-ref-link">
      <i class="fa-solid fa-arrow-up-right-from-square" style="font-size:10px"></i> ${{escHtml(c)}}
    </a>`
  ).join('');

  const refLinks = (f.references||[]).slice(0,4).map(r =>
    `<a href="${{escHtml(r)}}" target="_blank" rel="noopener" class="drawer-ref-link">
      <i class="fa-solid fa-link" style="font-size:10px"></i> ${{escHtml(r.replace(/^https?:\/\//,'').substring(0,60))}}
    </a>`
  ).join('');

  // ── Vulnerable Code section ──────────────────────────────────────────────
  let vulnCodeHtml = '';
  if (ev.file || ev.snippet) {{
    const fileName = (ev.file||'').split('/').pop() || ev.file || '';
    const fileLine = ev.line ? `:${{ev.line}}` : '';
    const fullPath = ev.file || '';
    const snippetContent = ev.snippet
      ? `<pre class="drawer-code language-java" id="drawerSnippet">${{escHtml(ev.snippet)}}</pre>`
      : `<div id="drawerSnippet" class="dvloc-loading">
           <i class="fa-solid fa-spinner fa-spin" style="margin-right:6px"></i> Loading code…
         </div>`;
    vulnCodeHtml = `<div class="drawer-section drawer-vuln-code">
      <div class="drawer-section-title">
        <i class="fa-solid fa-bug-slash" style="color:var(--critical)"></i> Vulnerable Code
      </div>
      ${{fullPath ? `<div class="dvloc">
        <i class="fa-solid fa-file-code" style="opacity:.6;font-size:10px"></i>
        <span class="dvloc-file" title="${{escHtml(fullPath)}}">${{escHtml(fileName)}}${{escHtml(fileLine)}}</span>
        ${{ev.line ? `<span class="dvloc-line">line ${{ev.line}}</span>` : ''}}
      </div>` : ''}}
      ${{snippetContent}}
    </div>`;
  }}

  // ── Exploitation section ──────────────────────────────────────────────────
  const prereqs   = f.attack_prerequisites || [];
  const steps     = f.attack_steps         || [];
  const impacts   = f.attack_impact        || [];
  const adbCmds   = f.adb_commands         || [];
  const malCode   = f.malicious_apk_code   || '';
  const atkDesc   = f.attack_description   || f.attack_path || '';
  const atkVector = f.attack_vector        || '';

  let exploitHtml = '';
  if (atkDesc || prereqs.length || steps.length || impacts.length || adbCmds.length || malCode) {{
    const prereqHtml = prereqs.length
      ? `<div class="expl-block">
           <div class="expl-sub"><i class="fa-solid fa-circle-check" style="color:var(--medium)"></i> Prerequisites</div>
           <ul class="expl-list">${{prereqs.map(p=>`<li>${{escHtml(p)}}</li>`).join('')}}</ul>
         </div>` : '';

    const stepsHtml = steps.length
      ? `<div class="expl-block">
           <div class="expl-sub"><i class="fa-solid fa-list-ol" style="color:var(--accent)"></i> Attack Steps</div>
           <ol class="expl-list">${{steps.map(s=>`<li>${{escHtml(s)}}</li>`).join('')}}</ol>
         </div>` : '';

    const impactHtml = impacts.length
      ? `<div class="expl-block">
           <div class="expl-sub"><i class="fa-solid fa-bolt" style="color:var(--high)"></i> Impact</div>
           <ul class="expl-list">${{impacts.map(i=>`<li>${{escHtml(i)}}</li>`).join('')}}</ul>
         </div>` : '';

    const adbHtml = adbCmds.length
      ? `<div class="expl-block">
           <div class="expl-sub" style="display:flex;align-items:center;justify-content:space-between">
             <span><i class="fa-solid fa-terminal" style="color:var(--accent)"></i> ADB Commands</span>
             <button class="btn btn-sm" style="font-size:10px;padding:2px 7px"
               onclick="navigator.clipboard.writeText(${{JSON.stringify(adbCmds.join('\\n'))}}).then(()=>showToast('Copied'))">
               <i class="fa-solid fa-copy"></i>
             </button>
           </div>
           <pre class="drawer-code" style="margin-top:6px">${{escHtml(adbCmds.join('\\n'))}}</pre>
         </div>` : '';

    const malHtml = malCode
      ? `<div class="expl-block">
           <div class="expl-sub" style="display:flex;align-items:center;justify-content:space-between">
             <span><i class="fa-solid fa-virus" style="color:var(--critical)"></i> Malicious App Code</span>
             <button class="btn btn-sm" style="font-size:10px;padding:2px 7px"
               onclick="navigator.clipboard.writeText(${{JSON.stringify(malCode)}}).then(()=>showToast('Copied'))">
               <i class="fa-solid fa-copy"></i>
             </button>
           </div>
           <pre class="drawer-code language-java" style="margin-top:6px">${{escHtml(malCode)}}</pre>
         </div>` : '';

    exploitHtml = `<div class="drawer-section drawer-exploit">
      <div class="drawer-section-title">
        <i class="fa-solid fa-skull-crossbones" style="color:var(--high)"></i> Real-World Exploitation
        ${{atkVector ? `<span style="font-size:10px;background:rgba(249,115,22,.12);color:var(--high);
            border:1px solid rgba(249,115,22,.25);padding:1px 7px;border-radius:4px;margin-left:8px;font-weight:600">
          ${{escHtml(atkVector)}}</span>` : ''}}
      </div>
      ${{atkDesc ? `<div class="drawer-desc" style="margin-bottom:10px">${{escHtml(atkDesc)}}</div>` : ''}}
      ${{prereqHtml}}${{stepsHtml}}${{impactHtml}}${{adbHtml}}${{malHtml}}
    </div>`;
  }}

  const pocHtml = f.poc
    ? `<div class="drawer-section">
         <div class="drawer-section-title" style="display:flex;align-items:center;justify-content:space-between">
           <span><i class="fa-solid fa-flask-vial" style="color:var(--accent)"></i> PoC</span>
           <button class="btn btn-sm" style="font-size:10px;padding:3px 8px" onclick="copyPoc()">
             <i class="fa-solid fa-copy"></i> Copy
           </button>
         </div>
         <pre class="drawer-code" id="drawerPoc">${{escHtml(f.poc)}}</pre>
       </div>`
    : '';

  document.getElementById('findingDrawer').innerHTML = `
    <div class="drawer-head">
      <span style="background:${{SEV_BG[sev]||'rgba(107,114,128,.1)'}};color:${{SEV_COLORS[sev]||'#9ca3af'}};
            padding:2px 10px;border-radius:4px;font-size:11px;font-weight:700">${{sev}}</span>
      <span style="font-size:14px;font-weight:700;color:var(--text);flex:1;min-width:0;
            overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${{escHtml(f.title||'')}}">${{escHtml(f.title||'')}}</span>
      <button class="drawer-close" onclick="closeDrawer()"><i class="fa-solid fa-xmark"></i></button>
    </div>
    <div class="drawer-body">
      <div class="drawer-section" style="padding-bottom:10px">
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
          ${{cweLinks}}
          <span style="font-size:11px;color:var(--text3)">#${{f.id??f.fid??''}}</span>
          <span style="font-size:11px;background:var(--bg3);border:1px solid var(--border);
                color:var(--text3);padding:1px 7px;border-radius:4px">${{escHtml(f.category||'Other')}}</span>
        </div>
      </div>

      <div class="drawer-section">
        <div class="drawer-section-title"><i class="fa-solid fa-circle-info" style="color:var(--accent)"></i> Description</div>
        <div class="drawer-desc">${{escHtml(f.description||'')}}</div>
      </div>

      ${{vulnCodeHtml}}
      ${{exploitHtml}}
      ${{pocHtml}}

      ${{f.remediation ? `<div class="drawer-section">
        <div class="drawer-section-title"><i class="fa-solid fa-shield-halved" style="color:var(--low)"></i> Remediation</div>
        <div class="drawer-desc" style="color:var(--low)">${{escHtml(f.remediation)}}</div>
      </div>` : ''}}

      ${{(cweLinks||refLinks) ? `<div class="drawer-section">
        <div class="drawer-section-title"><i class="fa-solid fa-link"></i> References</div>
        <div class="drawer-refs">${{cweLinks}}${{refLinks}}</div>
      </div>` : ''}}

      <!-- PoC Android App Generation -->
      <div class="drawer-section">
        <div class="drawer-section-title"><i class="fa-solid fa-hammer" style="color:var(--accent)"></i> PoC Android Application</div>
        <div style="font-size:12px;color:var(--text3);margin-bottom:10px">
          Generate a complete, compilable exploit APK targeting this vulnerability using AI.
        </div>
        <button class="btn" onclick="openPocModalForFinding(_drawerFinding)" id="drawerPocBtn"
            style="background:rgba(56,189,248,.12);border-color:rgba(56,189,248,.35);color:#38bdf8;font-size:12px;padding:7px 16px;width:100%">
          <i class="fa-solid fa-wand-magic-sparkles"></i> Generate PoC App with AI
          ${{(!_resolveApiKey() && !window.__API_KEY_CONFIGURED)
            ? `<span style="font-size:9px;background:rgba(239,68,68,.15);color:var(--critical);
                border:1px solid rgba(239,68,68,.3);padding:1px 5px;border-radius:3px;margin-left:4px">NO KEY</span>`
            : `<span style="font-size:9px;background:rgba(34,197,94,.12);color:var(--low);
                border:1px solid rgba(34,197,94,.25);padding:1px 5px;border-radius:3px;margin-left:4px">AI READY</span>`}}
        </button>
      </div>

      <!-- Dynamic Scan -->
      <div class="drawer-section">
        <div class="drawer-section-title"><i class="fa-solid fa-mobile-screen-button" style="color:var(--accent)"></i> Dynamic Verification</div>
        <div style="font-size:12px;color:var(--text3);margin-bottom:12px">
          Run targeted ADB probes against a live device to verify exploitability at runtime.
        </div>
        <div style="display:flex;gap:8px;margin-bottom:4px">
          <button class="btn btn-sm" id="dynScanBtnBasic" onclick="triggerDynamicFromDrawer(false)"
              style="flex:1;background:rgba(56,189,248,.1);border-color:rgba(56,189,248,.3);color:#38bdf8;font-size:12px;padding:7px 12px">
            <i class="fa-solid fa-terminal"></i> Basic ADB Scan
          </button>
          <button class="btn btn-sm" id="dynScanBtnAi" onclick="triggerDynamicFromDrawer(true)"
              style="flex:1;background:rgba(168,85,247,.1);border-color:rgba(168,85,247,.3);color:#c084fc;font-size:12px;padding:7px 12px">
            <i class="fa-solid fa-brain"></i> AI-Enhanced Scan
            ${{(!_resolveApiKey() && !window.__API_KEY_CONFIGURED)
              ? `<span style="font-size:9px;background:rgba(239,68,68,.15);color:var(--critical);border:1px solid rgba(239,68,68,.3);padding:1px 4px;border-radius:3px;margin-left:3px">NO KEY</span>`
              : ''}}
          </button>
        </div>
        <div style="font-size:10px;color:var(--text3);margin-bottom:8px">
          Basic: ADB probes + heuristic verdict — no API key needed &nbsp;|&nbsp; AI: Adds Claude analysis for deeper reasoning
        </div>
        <div id="dynScanStatus" style="margin-top:8px"></div>
      </div>

      <!-- Triage Section -->
      <div class="drawer-section">
        <div class="drawer-section-title"><i class="fa-solid fa-tags" style="color:var(--accent)"></i> Triage Status</div>
        <div class="triage-form">
          <select class="triage-select" id="drawerTriageStatus" onchange="onTriageChange()">
            <option value="New"           ${{(f.triage_status||'New')==='New'?'selected':''}}>New</option>
            <option value="Confirmed"     ${{(f.triage_status||'')==='Confirmed'?'selected':''}}>Confirmed — Verified true positive</option>
            <option value="In Progress"   ${{(f.triage_status||'')==='In Progress'?'selected':''}}>In Progress — Fix in progress</option>
            <option value="False Positive" ${{(f.triage_status||'')==='False Positive'?'selected':''}}>False Positive — Not exploitable</option>
            <option value="Accepted Risk" ${{(f.triage_status||'')==='Accepted Risk'?'selected':''}}>Accepted Risk — Won't fix</option>
            <option value="Fixed"         ${{(f.triage_status||'')==='Fixed'?'selected':''}}>Fixed — Remediated</option>
          </select>
          <textarea class="triage-note" id="drawerTriageNote"
                    placeholder="Add a note (required for False Positive / Accepted Risk)…"
                    rows="2">${{escHtml(f.suppression_note||'')}}</textarea>
          <button class="btn btn-primary btn-sm" onclick="saveTriage()">
            <i class="fa-solid fa-floppy-disk"></i> Save Triage
          </button>
        </div>
      </div>
    </div>
  `;

  // Syntax highlight snippet
  document.querySelectorAll('#findingDrawer pre code, #findingDrawer pre.language-java').forEach(el => {{
    if (window.hljs) hljs.highlightElement(el);
  }});

  const drawerEl = document.getElementById('findingDrawer');
  drawerEl.classList.add('open');
  drawerEl.scrollTop = 0;
  document.getElementById('drawerBackdrop').classList.add('open');

  // If snippet missing, load from API
  const snippetEl = document.getElementById('drawerSnippet');
  if (snippetEl && snippetEl.classList.contains('dvloc-loading')) {{
    const scanId = _drawerScanId || _getScanId();
    const fid    = f.id ?? f.fid;
    if (scanId && fid != null) {{
      fetch(`/api/scans/${{scanId}}/findings/${{fid}}/snippet`)
        .then(r => r.json())
        .then(d => {{
          if (d.snippet && snippetEl) {{
            snippetEl.className   = 'drawer-code language-java';
            snippetEl.tagName !== 'PRE' && (snippetEl.outerHTML = `<pre class="drawer-code language-java" id="drawerSnippet">${{escHtml(d.snippet)}}</pre>`);
            // Use outerHTML swap for pre tag
            const parent = snippetEl.parentElement;
            if (parent) {{
              const pre = document.createElement('pre');
              pre.className = 'drawer-code language-java';
              pre.id = 'drawerSnippet';
              pre.textContent = d.snippet;
              parent.replaceChild(pre, snippetEl);
              if (window.hljs) hljs.highlightElement(pre);
              // Store snippet for PoC generation
              if (_drawerFinding) _drawerFinding._liveSnippet = d.snippet;
            }}
          }} else if (snippetEl) {{
            snippetEl.className = 'dvloc-error';
            snippetEl.innerHTML = `<i class="fa-solid fa-circle-xmark" style="color:var(--text3)"></i> ${{escHtml(d.error||'Code not available')}}`;
          }}
        }})
        .catch(() => {{
          if (snippetEl) {{
            snippetEl.className = 'dvloc-error';
            snippetEl.innerHTML = '<i class="fa-solid fa-circle-xmark" style="color:var(--text3)"></i> Code not available';
          }}
        }});
    }}
  }}
}}

function closeDrawer() {{
  document.getElementById('findingDrawer')?.classList.remove('open');
  document.getElementById('drawerBackdrop')?.classList.remove('open');
}}

function copyPoc() {{
  const el = document.getElementById('drawerPoc');
  if (el) navigator.clipboard.writeText(el.textContent).then(() => showToast('Copied to clipboard'));
}}

async function triggerDynamicFromDrawer(useAi) {{
  if (!_drawerFinding) return;
  const scanId = _drawerScanId || _getScanId();
  if (!scanId) {{ showToast('No scan ID — cannot start dynamic scan', 'error'); return; }}

  // AI scan requires an API key
  if (useAi && !_resolveApiKey() && !window.__API_KEY_CONFIGURED) {{
    showToast('No API key configured. Use Basic ADB Scan or set your key in Settings.', 'error');
    return;
  }}

  const btnBasic = document.getElementById('dynScanBtnBasic');
  const btnAi    = document.getElementById('dynScanBtnAi');
  const status   = document.getElementById('dynScanStatus');
  const activeBtn = useAi ? btnAi : btnBasic;

  if (btnBasic) btnBasic.disabled = true;
  if (btnAi)    btnAi.disabled    = true;
  if (activeBtn) activeBtn.innerHTML = useAi
    ? '<i class="fa-solid fa-spinner fa-spin"></i> Starting AI Scan…'
    : '<i class="fa-solid fa-spinner fa-spin"></i> Starting…';
  if (status) status.innerHTML = '';

  const fid    = _drawerFinding.id ?? _drawerFinding.fid ?? 0;
  const fidx   = typeof fid === 'number' ? fid - 1 : 0;

  try {{
    const res  = await fetch('/api/dynamic/verify', {{
      method: 'POST', headers: {{'Content-Type':'application/json'}},
      body: JSON.stringify({{ scan_id: scanId, finding_index: fidx, finding: _drawerFinding, use_ai: useAi }}),
    }});
    const data = await res.json();
    if (!data.job_id) {{
      if (btnBasic) {{ btnBasic.disabled = false; btnBasic.innerHTML = '<i class="fa-solid fa-terminal"></i> Basic ADB Scan'; }}
      if (btnAi)    {{ btnAi.disabled    = false; btnAi.innerHTML    = '<i class="fa-solid fa-brain"></i> AI-Enhanced Scan'; }}
      showToast(data.error || 'Failed to start dynamic scan', 'error');
      if (status) status.innerHTML = `<div class="dyn-inline-error"><i class="fa-solid fa-circle-xmark"></i> ${{escHtml(data.error||'Failed')}}</div>`;
      return;
    }}
    const jobId = data.job_id;
    const modeLabel = useAi ? 'AI-enhanced' : 'basic ADB';
    if (activeBtn) {{ activeBtn.innerHTML = useAi ? '<i class="fa-solid fa-brain fa-spin"></i> Running…' : '<i class="fa-solid fa-rotate fa-spin"></i> Running…'; }}
    showToast(`Dynamic scan started (${{modeLabel}})`, 'success');
    _pollDynJobInDrawer(jobId, btnBasic, btnAi, status, useAi);
  }} catch(e) {{
    if (btnBasic) {{ btnBasic.disabled = false; btnBasic.innerHTML = '<i class="fa-solid fa-terminal"></i> Basic ADB Scan'; }}
    if (btnAi)    {{ btnAi.disabled    = false; btnAi.innerHTML    = '<i class="fa-solid fa-brain"></i> AI-Enhanced Scan'; }}
    showToast('Dynamic scan error: ' + e.message, 'error');
  }}
}}

async function _pollDynJobInDrawer(jobId, btnBasic, btnAi, statusEl, wasAi) {{
  const VERDICT_MAP = {{
    'true_positive':  {{ label: 'True Positive',  color: 'var(--critical)', icon: 'circle-exclamation' }},
    'false_positive': {{ label: 'False Positive', color: 'var(--low)',      icon: 'circle-check' }},
    'uncertain':      {{ label: 'Uncertain',       color: 'var(--medium)',   icon: 'circle-question' }},
  }};
  const resetBtns = () => {{
    if (btnBasic) {{ btnBasic.disabled = false; btnBasic.innerHTML = '<i class="fa-solid fa-terminal"></i> Basic ADB Scan'; }}
    if (btnAi)    {{ btnAi.disabled    = false; btnAi.innerHTML    = '<i class="fa-solid fa-brain"></i> AI-Enhanced Scan'; }}
  }};
  let attempts = 0;
  const MAX = 120; // 4 minutes
  const interval = setInterval(async () => {{
    attempts++;
    try {{
      const r = await fetch(`/api/dynamic/verify/${{jobId}}`);
      const job = await r.json();
      const done = job.status === 'done' || job.status === 'error';

      if (statusEl) {{
        const pct    = job.progress || 0;
        const verdict = job.verdict || {{}};
        const vKey   = (verdict.verdict || '').toLowerCase();
        const vInfo  = VERDICT_MAP[vKey] || {{ label: job.status || 'Running', color: 'var(--accent)', icon: 'circle-notch' }};
        const modeTag = wasAi
          ? `<span style="font-size:9px;background:rgba(168,85,247,.15);color:#c084fc;border:1px solid rgba(168,85,247,.3);padding:1px 5px;border-radius:3px;margin-left:4px">AI</span>`
          : `<span style="font-size:9px;background:rgba(56,189,248,.15);color:#38bdf8;border:1px solid rgba(56,189,248,.3);padding:1px 5px;border-radius:3px;margin-left:4px">ADB</span>`;

        if (!done) {{
          statusEl.innerHTML = `
            <div class="dyn-inline-progress">
              <div style="display:flex;justify-content:space-between;margin-bottom:4px;font-size:11px;color:var(--text3)">
                <span><i class="fa-solid fa-circle-notch fa-spin" style="color:var(--accent)"></i> ${{escHtml(job.message||'Running…')}}</span>
                <span>${{pct}}%</span>
              </div>
              <div style="height:4px;background:var(--border);border-radius:2px">
                <div style="height:4px;background:var(--accent);border-radius:2px;width:${{pct}}%;transition:width .3s"></div>
              </div>
            </div>`;
        }} else {{
          clearInterval(interval);
          resetBtns();
          if (job.status === 'error') {{
            statusEl.innerHTML = `<div class="dyn-inline-error"><i class="fa-solid fa-circle-xmark"></i> ${{escHtml(job.message||'Scan failed')}}</div>`;
            return;
          }}
          const reasoning = verdict.reasoning || '';
          const evidence  = (verdict.key_evidence || []).slice(0,3);
          const action    = verdict.suggested_action || '';
          const isHeuristic = verdict.mode === 'heuristic';
          statusEl.innerHTML = `
            <div class="dyn-inline-result">
              <div class="dyn-inline-verdict" style="color:${{vInfo.color}}">
                <i class="fa-solid fa-${{vInfo.icon}}"></i>
                ${{escHtml(vInfo.label)}} ${{modeTag}}
                ${{verdict.confidence != null ? `<span style="font-size:10px;opacity:.7;margin-left:4px">(${{verdict.confidence}}% confidence)</span>` : ''}}
                ${{isHeuristic ? `<span style="font-size:9px;color:var(--text3);margin-left:4px">heuristic</span>` : ''}}
              </div>
              ${{reasoning ? `<div class="dyn-inline-reason">${{escHtml(reasoning)}}</div>` : ''}}
              ${{evidence.length ? `<ul class="dyn-inline-evidence">${{evidence.map(e=>`<li>${{escHtml(e)}}</li>`).join('')}}</ul>` : ''}}
              ${{action ? `<div class="dyn-inline-action"><i class="fa-solid fa-lightbulb" style="color:var(--medium)"></i> ${{escHtml(action)}}</div>` : ''}}
            </div>`;
        }}
      }}
    }} catch(e) {{
      // ignore transient fetch errors
    }}
    if (attempts >= MAX) {{
      clearInterval(interval);
      resetBtns();
    }}
  }}, 2000);
}}

async function triggerDynamicScanRow(evt, btn, findingId) {{
  const scanId = _getScanId();
  if (!scanId) {{ showToast('No scan ID', 'error'); return; }}
  const finding = _allFindings.find(f => (f.id??f.fid) == findingId);
  if (!finding) {{ showToast('Finding not found', 'error'); return; }}

  btn.disabled = true;
  btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i>';
  const fidx = typeof finding.id === 'number' ? finding.id - 1 : 0;
  // Row-level quick scan always uses basic ADB (no AI) for speed
  try {{
    const res  = await fetch('/api/dynamic/verify', {{
      method: 'POST', headers: {{'Content-Type':'application/json'}},
      body: JSON.stringify({{ scan_id: scanId, finding_index: fidx, finding, use_ai: false }}),
    }});
    const data = await res.json();
    if (data.job_id) {{
      btn.innerHTML = '<i class="fa-solid fa-check"></i>';
      btn.title = 'Basic ADB scan queued — ' + data.job_id;
      showToast('Basic ADB scan queued', 'success');
      setTimeout(() => {{ btn.disabled = false; btn.innerHTML = '<i class="fa-solid fa-play"></i>'; }}, 3000);
    }} else {{
      btn.disabled = false; btn.innerHTML = '<i class="fa-solid fa-play"></i>';
      showToast(data.error || 'Failed to queue', 'error');
    }}
  }} catch(e) {{
    btn.disabled = false; btn.innerHTML = '<i class="fa-solid fa-play"></i>';
    showToast('Error: ' + e.message, 'error');
  }}
}}

function onTriageChange() {{
  const status = document.getElementById('drawerTriageStatus')?.value || '';
  const noteEl = document.getElementById('drawerTriageNote');
  if (!noteEl) return;
  const requireNote = ['False Positive', 'Accepted Risk'].includes(status);
  noteEl.placeholder = requireNote
    ? 'Please add a justification note…'
    : 'Add a note (optional)…';
  noteEl.style.borderColor = requireNote ? 'var(--medium)' : '';
}}

function saveTriage() {{
  if (!_drawerFinding) return;
  // Ensure we have a scan ID — fall back to URL path
  if (!_drawerScanId) {{
    _drawerScanId = _getScanId() || '';
  }}
  if (!_drawerScanId) {{ showToast('Cannot save — scan ID unknown', 'error'); return; }}

  const statusEl = document.getElementById('drawerTriageStatus');
  const noteEl   = document.getElementById('drawerTriageNote');
  const btn      = document.querySelector('#findingDrawer .btn-primary');
  const status   = statusEl?.value || 'New';
  const note     = noteEl?.value   || '';
  const fid      = _drawerFinding.id ?? _drawerFinding.fid;

  if (btn) {{ btn.disabled = true; btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Saving…'; }}

  fetch(`/api/scans/${{_drawerScanId}}/findings/${{fid}}/triage`, {{
    method: 'PATCH',
    headers: {{'Content-Type':'application/json'}},
    body: JSON.stringify({{status, suppression_note: note}}),
  }}).then(r => r.json()).then(d => {{
    if (btn) {{ btn.disabled = false; btn.innerHTML = '<i class="fa-solid fa-floppy-disk"></i> Save Triage'; }}
    if (d.ok) {{
      // Update in-memory finding
      _drawerFinding.triage_status    = status;
      _drawerFinding.suppression_note = note;
      // Update triage pill in list
      const pill = document.getElementById('tpill-' + fid);
      if (pill) {{
        pill.textContent = status;
        pill.className   = 'triage-pill ' + (TRIAGE_CLASS[status] || 'tp-new');
      }}
      // Update the result count (triage filter might now exclude/include this finding)
      const cnt = document.getElementById('fResultCount');
      if (cnt) {{
        const stFilter = (document.getElementById('fFilterStatus')?.value || '').toLowerCase();
        if (stFilter) applyFilters();
      }}
      showToast('Triage saved');
    }} else {{
      showToast('Save failed: ' + (d.error || 'Unknown error'), 'error');
    }}
  }}).catch(err => {{
    if (btn) {{ btn.disabled = false; btn.innerHTML = '<i class="fa-solid fa-floppy-disk"></i> Save Triage'; }}
    showToast('Save failed: ' + err.message, 'error');
  }});
}}

// ── COMPONENT HEATMAP ────────────────────────────────────────────────────────
function buildHeatmap() {{
  if (_allFindings.length === 0) {{
    if (!_heatmapBuilt) loadFindingsTab();
    setTimeout(buildHeatmap, 400);
    return;
  }}
  _heatmapBuilt = true;
  const wrap = document.getElementById('heatmapWrap');
  if (!wrap) return;

  const SEVS = ['Critical','High','Medium','Low','Info'];

  // Group by top-level component (first 2 segments of file path after /sources/)
  const compMap = {{}};
  _allFindings.forEach(f => {{
    const fp = (f.evidence?.file || '').split('\\\\').join('/');
    let comp = fp.split('/sources/')[1] || fp;
    // Take first 2 path segments as component name
    comp = comp.split('/').slice(0,2).join('/') || fp.split('/').pop() || 'unknown';
    if (!compMap[comp]) compMap[comp] = {{}};
    const sev = f.severity || 'Info';
    compMap[comp][sev] = (compMap[comp][sev]||0) + 1;
  }});

  // Sort by total findings desc, take top 25
  const comps = Object.entries(compMap)
    .map(([c,s]) => [c, s, SEVS.reduce((sum,sv)=>(sum+(s[sv]||0)),0)])
    .sort((a,b)=>b[2]-a[2]).slice(0,25);

  if (!comps.length) {{ wrap.innerHTML='<p style="color:var(--text3)">No findings with file paths.</p>'; return; }}

  let html = '<table class="heatmap-table"><thead><tr><th>Component</th>';
  SEVS.forEach(s => html += `<th style="color:${{SEV_COLORS[s]}}">${{s}}</th>`);
  html += '<th>Total</th></tr></thead><tbody>';

  comps.forEach(([comp, sevMap, total]) => {{
    html += `<tr><td title="${{escHtml(comp)}}">${{escHtml(comp.split('/').pop()||comp)}}</td>`;
    SEVS.forEach(s => {{
      const cnt = sevMap[s]||0;
      const cls = cnt===0?'hm-0':cnt<=2?'hm-1':cnt<=5?'hm-2':cnt<=10?'hm-3':'hm-4';
      const onclick = cnt ? `onclick="filterByComp('${{comp.replace(/'/g,"\\\\'")}}','${{s}}')"` : '';
      html += `<td class="${{cls}}" ${{onclick}}>${{cnt||''}}</td>`;
    }});
    html += `<td style="font-weight:700;color:var(--text)">${{total}}</td></tr>`;
  }});

  html += '</tbody></table>';
  wrap.innerHTML = html;
}}

function filterByComp(comp, sev) {{
  switchTab('findings');
  if (_allFindings.length === 0) loadFindingsTab();
  // Apply sev chip
  document.querySelectorAll('.f-chip').forEach(c => c.classList.remove('active'));
  const chipEl = document.querySelector(`.f-chip[data-sev="${{sev}}"]`);
  if (chipEl) chipEl.classList.add('active');
  _currentSevFilter = sev;
  // Set search to component path
  const s = document.getElementById('fSearch');
  if (s) s.value = comp.split('/').pop() || comp;
  applyFilters();
}}

// ── TOAST NOTIFICATION ────────────────────────────────────────────────────────
function showToast(msg, type='success') {{
  let container = document.getElementById('toastContainer');
  if (!container) {{
    container = document.createElement('div');
    container.id = 'toastContainer';
    container.style.cssText = 'position:fixed;bottom:24px;right:24px;z-index:9999;display:flex;flex-direction:column;gap:8px;pointer-events:none';
    document.body.appendChild(container);
  }}
  const toast = document.createElement('div');
  const cfg = {{
    error:   {{ bg:'rgba(239,68,68,.95)',   border:'#ef4444', icon:'fa-circle-xmark'   }},
    warn:    {{ bg:'rgba(234,179,8,.95)',    border:'#eab308', icon:'fa-triangle-exclamation' }},
    success: {{ bg:'rgba(22,27,34,.97)',     border:'#4ade80', icon:'fa-circle-check'   }},
  }}[type] || {{ bg:'rgba(22,27,34,.97)', border:'#4ade80', icon:'fa-circle-check' }};
  toast.style.cssText = `background:${{cfg.bg}};border:1px solid ${{cfg.border}};color:#fff;
    padding:10px 14px;border-radius:8px;font-size:12.5px;
    box-shadow:0 4px 20px rgba(0,0,0,.5);animation:slideUp .2s ease;
    max-width:340px;display:flex;align-items:center;gap:8px;pointer-events:auto;cursor:pointer;`;
  toast.innerHTML = `<i class="fa-solid ${{cfg.icon}}" style="flex-shrink:0"></i><span>${{escHtml(msg)}}</span>`;
  toast.onclick = () => toast.remove();
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}}

// ── AUTO-INIT ─────────────────────────────────────────────────────────────
(function() {{
  // Auto-load findings if the findings panel exists
  const panel = document.getElementById('findingsPanel');
  if (panel) loadFindingsTab();

  // Auto-scroll sidebar to the active scan item
  const activeItem = document.querySelector('.sb-scan-item.active');
  if (activeItem) activeItem.scrollIntoView({{block:'nearest', behavior:'instant'}});
}})();
</script>

</body>
</html>'''


def _build_scan_content(scan_id: str | None, current: dict | None,
                        report_body: str, report_scripts: str) -> str:
    """Build the main content area for a scan view (tabbed) or home dashboard."""
    if not current:
        return _build_home_dashboard(_load_summaries())

    # Load findings JSON for the Findings tab
    findings_data_json = 'null'
    findings_path = _scan_dir(scan_id) / 'findings.json'
    if findings_path.exists():
        try:
            raw_fj = findings_path.read_text(encoding='utf-8')
            findings_data_json = raw_fj.replace('</', '<\\/')
        except Exception:
            pass
    else:
        # Fallback: parse from report.html embedded JSON
        try:
            rp = _scan_dir(scan_id) / 'report.html'
            if rp.exists():
                raw_r = rp.read_text(encoding='utf-8')
                jm = re.search(
                    r'<script[^>]+id=["\']reportData["\'][^>]*>(.*?)</script>',
                    raw_r, re.DOTALL,
                )
                if jm:
                    findings_data_json = jm.group(1)
        except Exception:
            pass

    # Build scan summary strip (server-side, no JS needed)
    pkg        = current.get('package', 'unknown')
    apk_name   = current.get('apk', '')
    total_f    = current.get('total_findings', 0)
    sev_counts = current.get('severity_counts', {})
    risk_score = current.get('risk_score')
    created_at = current.get('created_at')
    scan_date  = ''
    if created_at:
        import datetime as _dt
        scan_date = _dt.datetime.fromtimestamp(created_at).strftime('%b %d, %Y %H:%M')

    sev_order  = ['Critical', 'High', 'Medium', 'Low', 'Info']
    sev_colors = {'Critical':'#ef4444','High':'#f97316','Medium':'#eab308','Low':'#22c55e','Info':'#3b82f6'}
    sev_pills  = ''
    for sev in sev_order:
        cnt = sev_counts.get(sev, 0)
        if cnt:
            sev_pills += (
                f'<span class="ss-pill" style="background:{sev_colors[sev]}22;'
                f'color:{sev_colors[sev]};border:1px solid {sev_colors[sev]}44" '
                f'onclick="setFChipByName(\'{sev}\')" title="Filter by {sev}">'
                f'<span class="ss-pill-dot" style="background:{sev_colors[sev]}"></span>'
                f'{sev} <strong>{cnt}</strong></span>'
            )

    risk_html = ''
    if risk_score is not None:
        rs_val = round(risk_score)
        rs_color = '#ef4444' if rs_val >= 70 else '#f97316' if rs_val >= 40 else '#eab308' if rs_val >= 20 else '#22c55e'
        risk_html = (
            f'<div class="ss-risk" title="Risk Score">'
            f'<span style="color:{rs_color};font-size:22px;font-weight:700;line-height:1">{rs_val}</span>'
            f'<span style="color:var(--text3);font-size:10px;margin-top:2px">/ 100</span>'
            f'</div>'
        )

    apk_display = apk_name.split('/')[-1] if apk_name else ''

    return f'''
<!-- Content tabs -->
<div class="content-tab-bar">
  <button class="content-tab active" onclick="switchTab('findings')" id="tabFindings">
    <i class="fa-solid fa-list-ul"></i> Findings
  </button>
  <button class="content-tab" onclick="switchTab('heatmap')" id="tabHeatmap">
    <i class="fa-solid fa-table-cells"></i> Heatmap
  </button>
</div>

<!-- ── FINDINGS PANEL (dynamic, from JSON) ── -->
<div id="findingsPanel" class="active">

  <!-- Scan summary strip -->
  <div class="scan-summary-strip">
    <div class="ss-meta">
      <div class="ss-pkg" title="{pkg}">{pkg}</div>
      {f'<div class="ss-apk"><i class="fa-solid fa-file-zipper" style="opacity:.5"></i> {apk_display}</div>' if apk_display else ''}
      {f'<div class="ss-date"><i class="fa-regular fa-clock" style="opacity:.5"></i> {scan_date}</div>' if scan_date else ''}
    </div>
    <div class="ss-pills">{sev_pills}</div>
    <div class="ss-totals">
      {risk_html}
      <div class="ss-total-count">
        <span style="font-size:22px;font-weight:700;color:var(--text);line-height:1">{total_f}</span>
        <span style="color:var(--text3);font-size:10px;margin-top:2px">findings</span>
      </div>
    </div>
  </div>

  <!-- Filter bar -->
  <div class="findings-filter-bar" id="findingsFilterBar">
    <div class="f-chips">
      <button class="f-chip active" onclick="setFChip(this,'all')" data-sev="all">All</button>
      <button class="f-chip chip-c" onclick="setFChip(this,'Critical')" data-sev="Critical">Critical</button>
      <button class="f-chip chip-h" onclick="setFChip(this,'High')" data-sev="High">High</button>
      <button class="f-chip chip-m" onclick="setFChip(this,'Medium')" data-sev="Medium">Medium</button>
      <button class="f-chip chip-l" onclick="setFChip(this,'Low')" data-sev="Low">Low</button>
      <button class="f-chip chip-i" onclick="setFChip(this,'Info')" data-sev="Info">Info</button>
    </div>
    <select class="f-select" id="fFilterCat" onchange="applyFilters()">
      <option value="">All Categories</option>
    </select>
    <select class="f-select" id="fFilterStatus" onchange="applyFilters()">
      <option value="">All Status</option>
      <option value="New">New</option>
      <option value="Confirmed">Confirmed</option>
      <option value="False Positive">False Positive</option>
      <option value="Accepted Risk">Accepted Risk</option>
      <option value="In Progress">In Progress</option>
      <option value="Fixed">Fixed</option>
    </select>
    <div class="f-search-wrap">
      <i class="fa-solid fa-magnifying-glass f-search-icon"></i>
      <input class="f-search" id="fSearch" placeholder="Search findings…" oninput="debounceFilter()">
    </div>
    <span class="f-result-count" id="fResultCount"></span>
  </div>

  <div class="findings-list" id="findingsList">
    <div style="text-align:center;padding:40px;color:var(--text3)">
      <i class="fa-solid fa-spinner fa-spin" style="font-size:20px;margin-bottom:8px;display:block"></i>
      Loading findings…
    </div>
  </div>
</div>

<!-- ── HEATMAP PANEL ── -->
<div id="heatmapPanel" style="display:none">
  <div class="heatmap-section" style="padding-top:24px">
    <div class="heatmap-title"><i class="fa-solid fa-fire"></i> Component Risk Heatmap</div>
    <p style="font-size:12px;color:var(--text3);margin-bottom:16px">
      Files × severity. Click a cell to filter the Findings tab.
    </p>
    <div class="heatmap-wrap" id="heatmapWrap">
      <div style="color:var(--text3);font-size:13px">Loading heatmap…</div>
    </div>
  </div>
</div>

<!-- Embedded findings data for this scan -->
<script type="application/json" id="findingsData">{findings_data_json}</script>

<!-- Detail Drawer -->
<div class="finding-drawer" id="findingDrawer"></div>
<div class="drawer-backdrop" id="drawerBackdrop" onclick="closeDrawer()"></div>
'''


def _build_home_dashboard(all_summaries: list) -> str:
    """Build the home screen shown when no scan is selected."""
    # Aggregate stats
    total_scans   = len(all_summaries)
    total_findings = sum(s.get('total_findings', 0) for s in all_summaries)
    by_sev: dict  = {}
    for s in all_summaries:
        for sev, cnt in s.get('severity_counts', {}).items():
            by_sev[sev] = by_sev.get(sev, 0) + cnt

    sev_order = ['Critical', 'High', 'Medium', 'Low', 'Info']
    sev_colors = {'Critical':'#ef4444','High':'#f97316','Medium':'#eab308','Low':'#22c55e','Info':'#06b6d4'}

    # KPI cards
    kpi_html = f'''
    <div class="home-kpi-card"><div class="home-kpi-num">{total_scans}</div><div class="home-kpi-lbl">Total Scans</div></div>
    <div class="home-kpi-card"><div class="home-kpi-num">{total_findings}</div><div class="home-kpi-lbl">Total Findings</div></div>'''
    for sev in sev_order:
        cnt = by_sev.get(sev, 0)
        if cnt:
            c = sev_colors[sev]
            kpi_html += (f'<div class="home-kpi-card">'
                         f'<div class="home-kpi-num" style="color:{c}">{cnt}</div>'
                         f'<div class="home-kpi-lbl">{sev}</div></div>')

    # Donut chart data
    chart_labels = [s for s in sev_order if by_sev.get(s, 0) > 0]
    chart_data   = [by_sev.get(s, 0) for s in chart_labels]
    chart_colors = [sev_colors[s] for s in chart_labels]

    # Recent scans table
    rows_html = ''
    for s in all_summaries[:10]:
        sid   = s.get('scan_id', '')
        pkg   = s.get('package', 'unknown')
        apk   = s.get('apk', '')
        total = s.get('total_findings', 0)
        rs    = s.get('risk_score')
        sev   = s.get('severity_counts', {})
        crit  = sev.get('Critical', 0)
        high  = sev.get('High', 0)

        if rs is not None:
            if rs >= 70:   rc = '#ef4444'
            elif rs >= 40: rc = '#f97316'
            elif rs >= 15: rc = '#eab308'
            else:          rc = '#22c55e'
            rs_cell = f'<span style="color:{rc};font-weight:700">{rs}</span>'
        else:
            rs_cell = '<span style="color:var(--text3)">—</span>'

        sev_pills = ''
        if crit: sev_pills += f'<span style="background:rgba(239,68,68,.15);color:#f87171;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:700">{crit}C</span> '
        if high: sev_pills += f'<span style="background:rgba(249,115,22,.15);color:#fb923c;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:700">{high}H</span>'

        rows_html += f'''<tr onclick="window.location='/scans/{sid}'" style="cursor:pointer">
          <td style="font-weight:600">{pkg}</td>
          <td style="color:var(--text3);font-family:'JetBrains Mono',monospace;font-size:11px">{apk}</td>
          <td>{sev_pills or f'<span style="color:var(--text3)">{total}</span>'}</td>
          <td style="text-align:center">{rs_cell}</td>
          <td style="text-align:center"><button onclick="event.stopPropagation();deleteScan('{sid}')" title="Delete scan" style="background:transparent;border:none;color:var(--text3);cursor:pointer;padding:4px 6px;border-radius:4px;font-size:12px;transition:color .15s" onmouseover="this.style.color='#ef4444'" onmouseout="this.style.color='var(--text3)'"><i class="fa-solid fa-trash-can"></i></button></td>
        </tr>'''

    if not rows_html:
        rows_html = '<tr><td colspan="4" style="text-align:center;color:var(--text3);padding:24px">No scans yet — upload an APK to get started</td></tr>'

    return f'''
<div class="main home-dash">

  <!-- KPI Strip -->
  <div class="home-kpi-strip">{kpi_html}</div>

  <!-- Charts + Recent Scans Row -->
  <div class="home-content-row">

    <!-- Donut chart -->
    <div class="home-chart-card" {"style='display:none'" if not chart_data else ""}>
      <div class="home-card-title"><i class="fa-solid fa-chart-pie"></i> Severity Distribution</div>
      <div style="position:relative;width:200px;height:200px;margin:0 auto">
        <canvas id="homeSevDonut"></canvas>
        <div style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;
                    justify-content:center;pointer-events:none">
          <div style="font-size:26px;font-weight:800;color:var(--text)">{total_findings}</div>
          <div style="font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em">findings</div>
        </div>
      </div>
      <div class="home-legend" id="homeLegend"></div>
    </div>

    <!-- Recent scans table -->
    <div class="home-table-card" style="flex:1;min-width:0">
      <div class="home-card-title" style="display:flex;align-items:center;justify-content:space-between">
        <span><i class="fa-solid fa-clock-rotate-left"></i> Recent Scans</span>
        <button class="btn btn-primary btn-sm" onclick="openUploadPanel()">
          <i class="fa-solid fa-plus"></i> New Scan
        </button>
      </div>
      <table class="home-scan-table">
        <thead><tr><th>Package</th><th>APK</th><th>Findings</th><th style="text-align:center">Risk</th><th></th></tr></thead>
        <tbody>{rows_html}</tbody>
      </table>
    </div>

  </div>

</div>

<script>
(function() {{
  const labels  = {json.dumps(chart_labels)};
  const data    = {json.dumps(chart_data)};
  const colors  = {json.dumps(chart_colors)};
  if (!labels.length) return;
  const ctx = document.getElementById('homeSevDonut');
  if (!ctx) return;
  new Chart(ctx, {{
    type: 'doughnut',
    data: {{labels, datasets:[{{data, backgroundColor:colors, borderWidth:0, hoverOffset:4}}]}},
    options: {{
      cutout:'72%', responsive:true, maintainAspectRatio:true,
      plugins:{{legend:{{display:false}},tooltip:{{callbacks:{{label:function(c){{return ' '+c.label+': '+c.raw}}}}}}}}
    }}
  }});
  // Legend
  const leg = document.getElementById('homeLegend');
  if (leg) {{
    leg.innerHTML = labels.map((l,i)=>
      `<div class="home-leg-item"><span style="background:${{colors[i]}};width:10px;height:10px;border-radius:50%;display:inline-block;flex-shrink:0"></span> ${{l}} <strong>${{data[i]}}</strong></div>`
    ).join('');
  }}
}})();
</script>'''


def _build_topbar(current: dict | None, view: str | None = None) -> str:
    _hbg = '<button class="hamburger" onclick="toggleSidebar()" aria-label="Menu"><i class="fa-solid fa-bars"></i></button>'

    if view == 'intelligence':
        return f'''<div class="topbar">
          {_hbg}
          <i class="fa-solid fa-brain" style="color:var(--accent);font-size:15px"></i>
          <span style="font-size:14px;font-weight:600;color:var(--text)">Intelligence Hub</span>
          <span class="topbar-sub-label" style="font-size:12px;color:var(--text3);margin-left:4px">· Detection rules &amp; patterns</span>
          <div class="topbar-spacer"></div>
          <button class="btn btn-sm" onclick="importRulesClick()">
            <i class="fa-solid fa-file-import"></i> Import
          </button>
          <button class="btn btn-primary btn-sm" onclick="openAddRuleModal()">
            <i class="fa-solid fa-plus"></i> Add Rule
          </button>
        </div>'''

    if not current:
        return f'''<div class="topbar">
          {_hbg}
          <i class="fa-solid fa-shield-halved" style="color:var(--accent);font-size:16px"></i>
          <span style="font-size:13px;color:var(--text2)">Select or upload a scan</span>
          <div class="topbar-spacer"></div>
        </div>'''

    pkg        = current.get('package', 'unknown')
    apk        = current.get('apk', '')
    total      = current.get('total_findings', 0)
    sev        = current.get('severity_counts', {})
    sid        = current.get('scan_id', '')
    risk_score = current.get('risk_score')

    # Risk score badge
    if risk_score is not None:
        if risk_score >= 70:
            rs_color = '#ef4444'; rs_bg = 'rgba(239,68,68,.12)'
        elif risk_score >= 40:
            rs_color = '#f97316'; rs_bg = 'rgba(249,115,22,.12)'
        elif risk_score >= 15:
            rs_color = '#eab308'; rs_bg = 'rgba(234,179,8,.12)'
        else:
            rs_color = '#22c55e'; rs_bg = 'rgba(34,197,94,.12)'
        risk_badge = (f'<span title="Risk Score: weighted severity total" '
                      f'style="background:{rs_bg};color:{rs_color};padding:3px 10px;'
                      f'border-radius:12px;font-size:11px;font-weight:700;border:1px solid {rs_color}33">'
                      f'Risk {risk_score}</span>')
    else:
        risk_badge = ''

    platform     = current.get('platform', 'android')
    if platform == 'ios':
        plat_label = 'iOS'
        plat_icon  = 'fa-apple'
        plat_color = 'color:var(--text2)'
    elif platform == 'jar':
        plat_label = 'JAR'
        plat_icon  = 'fa-java'
        plat_color = 'color:#f97316'
    elif platform == 'exe':
        plat_label = 'Windows EXE'
        plat_icon  = 'fa-windows'
        plat_color = 'color:#0078d4'
    else:
        plat_label = 'Android'
        plat_icon  = 'fa-android'
        plat_color = 'color:#22c55e'

    crit = sev.get('Critical', 0)
    crit_badge = (f'<span style="background:rgba(239,68,68,.15);color:#f87171;padding:2px 8px;'
                  f'border-radius:4px;font-size:11px;font-weight:700">{crit}C</span> ') if crit else ''

    # Dynamic scan only meaningful for Android (needs ADB)
    if platform == 'ios':
        dyn_btn = (f'<span style="font-size:11px;color:var(--text3);padding:4px 8px" title="Dynamic analysis not available for iOS static scans">'
                   f'<i class="fa-brands fa-apple"></i> iOS Static</span>')
    elif platform == 'jar':
        dyn_btn = (f'<span style="font-size:11px;color:var(--text3);padding:4px 8px" title="Dynamic analysis not available for JAR scans">'
                   f'<i class="fa-brands fa-java"></i> JAR Static</span>')
    elif platform == 'exe':
        dyn_btn = (f'<span style="font-size:11px;color:var(--text3);padding:4px 8px" title="Dynamic analysis not available for Windows PE scans">'
                   f'<i class="fa-brands fa-windows"></i> PE Static</span>')
    else:
        dyn_btn = (f'<button class="btn btn-sm" style="border-color:rgba(251,191,36,.4);color:#fbbf24;'
                   f'background:rgba(251,191,36,.08)" onclick="openDynPanel(\'{sid}\')">'
                   f'<i class="fa-solid fa-bolt"></i> Dynamic</button>')

    return f'''<div class="topbar" data-scan-id="{sid}">
      {_hbg}
      <i class="fa-brands {plat_icon}" style="{plat_color};font-size:14px" title="{plat_label}"></i>
      <span class="topbar-pkg">{pkg}</span>
      {crit_badge}
      {risk_badge}
      <div class="topbar-spacer"></div>
      <div class="topbar-meta">
        <span><i class="fa-regular fa-file-code"></i> {apk}</span>
        <span><i class="fa-solid fa-bullseye"></i> {total} findings</span>
        {dyn_btn}
        <div class="export-dropdown" style="position:relative;display:inline-flex">
          <button class="btn btn-sm export-drop-btn" onclick="toggleExportMenu()" style="gap:5px">
            <i class="fa-solid fa-download"></i> Export
            <i class="fa-solid fa-chevron-down" style="font-size:9px"></i>
          </button>
          <div class="export-menu" id="exportMenu" style="display:none">
            <button onclick="exportReport();closeExportMenu()"><i class="fa-solid fa-code"></i> JSON Report</button>
            <button onclick="exportSarif('{sid}');closeExportMenu()"><i class="fa-solid fa-code-branch"></i> SARIF (CI/CD)</button>
            <button onclick="exportCsv('{sid}');closeExportMenu()"><i class="fa-solid fa-table"></i> CSV</button>
            <button onclick="exportPdf('{sid}');closeExportMenu()"><i class="fa-solid fa-file-pdf"></i> PDF Report</button>
          </div>
        </div>
      </div>
    </div>'''


def _poc_modal_html() -> str:
    """Return the Claude PoC modal HTML (same as injected into report, sans f-string pkg refs)."""
    return '''
<div class="poc-modal-overlay" id="pocModal" style="display:none">
  <div class="poc-modal">
    <div class="poc-modal-head">
      <div class="modal-icon"><i class="fa-solid fa-wand-magic-sparkles"></i></div>
      <div>
        <div class="modal-title">Generate PoC Android App</div>
        <div class="modal-sub">Claude AI writes a complete Android Studio project targeting this vulnerability</div>
      </div>
      <button class="poc-modal-close" onclick="closePocModal()"><i class="fa-solid fa-xmark"></i></button>
    </div>
    <div class="poc-modal-body">
      <div id="modalReady">
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
            <i class="fa-solid fa-circle-info"></i> &nbsp;Generation takes ~15-30s. For authorized security testing only.
          </p>
        </div>
      </div>
      <div id="modalGenerating" style="display:none" class="gen-spinner">
        <div class="spin-icon"></div>
        <p>Claude is writing your exploit app…<br><span style="font-size:11px;color:var(--text3)">15–30 seconds</span></p>
      </div>
      <div id="modalResult" style="display:none;flex-direction:column;gap:0;height:100%">
        <div style="padding:0 0 12px;font-size:13px;color:var(--text2)">
          <i class="fa-solid fa-circle-check" style="color:var(--low)"></i>
          &nbsp;Generated — open in Android Studio or download as ZIP
        </div>
        <div class="file-tabs" id="pocFileTabs"></div>
        <div class="file-panes" id="pocFilePanes"></div>
      </div>
      <div id="modalError" style="display:none" class="modal-error">
        <i class="fa-solid fa-triangle-exclamation"></i>
        &nbsp;<span id="modalErrorMsg">An error occurred.</span>
        <div style="margin-top:10px;font-size:12px;color:var(--text3)">Check your API key and try again.</div>
      </div>
    </div>
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
        <button class="btn" onclick="showModalState(\'ready\');runPocGeneration()">
          <i class="fa-solid fa-rotate"></i> Regenerate
        </button>
        <button class="btn" onclick="closePocModal()" style="margin-left:auto">Close</button>
      </div>
    </div>
  </div>
</div>'''


def _build_sidebar_intel_stats() -> str:
    """Mini rule overview shown in the sidebar when on Intelligence view."""
    try:
        stats = rules_api.get_stats()
        sev   = stats.get("by_severity", {})
        rows  = ""
        for label, key, color in [
            ("Critical", "Critical", "var(--critical)"),
            ("High",     "High",     "var(--high)"),
            ("Medium",   "Medium",   "var(--medium)"),
            ("Low",      "Low",      "var(--low)"),
            ("Info",     "Info",     "var(--info)"),
        ]:
            n = sev.get(key, 0)
            rows += f'''<div class="sb-intel-mini-row" onclick="document.getElementById('filterSeverity').value='{key}';filterRules()">
              <span style="font-size:11.5px;color:var(--text2)">{label}</span>
              <span class="count" style="background:rgba(255,255,255,.05);color:{color}">{n}</span>
            </div>'''
        total   = stats.get("total", 0)
        enabled = stats.get("enabled", 0)
        return f'''<div class="sb-intel-mini">
          <div style="padding:8px 8px 6px;font-size:11px;color:var(--text3)">
            <b style="color:var(--accent);font-size:13px">{total}</b> total &nbsp;·&nbsp;
            <b style="color:#4ade80">{enabled}</b> active
          </div>
          {rows}
        </div>'''
    except Exception:
        return '<div style="padding:12px 16px;font-size:12px;color:var(--text3)">Rules unavailable</div>'


def _build_intelligence_hub() -> str:
    """Return the enterprise Intelligence Hub HTML for the main content area."""
    return '''
<div class="intel-hub" id="intelHub">

  <!-- ── Sticky header with stats strip ── -->
  <div class="intel-header">
    <div class="intel-header-top">
      <div class="intel-brand">
        <div class="intel-brand-icon"><i class="fa-solid fa-brain"></i></div>
        <div>
          <h1>Intelligence Hub</h1>
          <p>MSRA detection rules &nbsp;·&nbsp; 77+ patterns &nbsp;·&nbsp; OWASP Mobile Top 10</p>
        </div>
      </div>
    </div>

    <!-- Sub-nav: Rules | Sources & Updates -->
    <div class="intel-subnav">
      <button class="intel-subnav-btn active" id="subnavRules" onclick="switchIntelTab('rules')">
        <i class="fa-solid fa-list-check"></i>Rules
      </button>
      <button class="intel-subnav-btn" id="subnavSources" onclick="switchIntelTab('sources')">
        <i class="fa-solid fa-satellite-dish"></i>Sources &amp; Updates
      </button>
    </div>

    <!-- Stats strip (populated by JS) -->
    <div class="intel-stats-strip">
      <div class="intel-stat s-all active" id="statAll" onclick="quickFilter('')">
        <div class="intel-stat-num" id="statTotal">—</div>
        <div class="intel-stat-lbl">Total Rules</div>
      </div>
      <div class="intel-stat s-active" id="statActiveBtn" onclick="quickFilter('enabled')">
        <div class="intel-stat-num" id="statEnabled">—</div>
        <div class="intel-stat-lbl">Active</div>
      </div>
      <div class="intel-stat s-crit" onclick="quickFilter('Critical')">
        <div class="intel-stat-num" id="statCritical">—</div>
        <div class="intel-stat-lbl">Critical</div>
      </div>
      <div class="intel-stat s-high" onclick="quickFilter('High')">
        <div class="intel-stat-num" id="statHigh">—</div>
        <div class="intel-stat-lbl">High</div>
      </div>
      <div class="intel-stat s-med" onclick="quickFilter('Medium')">
        <div class="intel-stat-num" id="statMedium">—</div>
        <div class="intel-stat-lbl">Medium</div>
      </div>
      <div class="intel-stat s-low" onclick="quickFilter('Low')">
        <div class="intel-stat-num" id="statLow">—</div>
        <div class="intel-stat-lbl">Low</div>
      </div>
      <div class="intel-stat s-info" onclick="quickFilter('Info')">
        <div class="intel-stat-num" id="statInfo">—</div>
        <div class="intel-stat-lbl">Info</div>
      </div>
    </div>
  </div>

  <!-- ── Scrollable content ── -->
  <div class="intel-body">

    <!-- Filter toolbar (sticky) -->
    <div class="intel-toolbar">
      <div class="intel-search-wrap">
        <i class="fa-solid fa-magnifying-glass intel-search-icon"></i>
        <input class="intel-search" id="rulesSearch" placeholder="Search rules by title, ID, description, CWE…" oninput="filterRules()">
      </div>
      <select class="intel-filter" id="filterSeverity" onchange="filterRules()">
        <option value="">All Severities</option>
        <option>Critical</option><option>High</option><option>Medium</option>
        <option>Low</option><option>Info</option>
      </select>
      <select class="intel-filter" id="filterCategory" onchange="filterRules()">
        <option value="">All Categories</option>
      </select>
      <div class="intel-sep"></div>
      <select class="intel-filter" id="filterPlatform" onchange="filterRules()">
        <option value="">All Platforms</option>
        <option value="android">Android</option>
        <option value="ios">iOS</option>
        <option value="jar">JAR (Java)</option>
        <option value="exe">Windows PE/EXE</option>
      </select>
      <select class="intel-filter" id="filterSource" onchange="filterRules()">
        <option value="">All Sources</option>
        <option value="builtin">Built-in</option>
        <option value="custom">Custom</option>
        <option value="community">Community</option>
      </select>
      <select class="intel-filter" id="filterStatus" onchange="filterRules()">
        <option value="">All Status</option>
        <option value="enabled">Enabled</option>
        <option value="disabled">Disabled</option>
      </select>
    </div>

    <!-- Table area -->
    <div class="intel-table-area">

      <!-- Loading state -->
      <div class="intel-state" id="rulesLoading">
        <i class="fa-solid fa-circle-notch fa-spin state-icon"></i>
        <h3>Loading rules…</h3>
        <p>Fetching detection patterns from the rule store</p>
      </div>

      <!-- Empty / no match state -->
      <div class="intel-state" id="rulesEmpty" style="display:none">
        <i class="fa-solid fa-filter-circle-xmark state-icon"></i>
        <h3>No rules match</h3>
        <p>Try clearing some filters or broadening your search</p>
      </div>

      <!-- Meta bar + table (hidden until loaded) -->
      <div id="rulesTableWrap" style="display:none">
        <div class="intel-table-meta">
          <span id="rulesMetaText" style="color:var(--text3);font-size:12px"></span>
          <span style="font-size:11px;color:var(--text3)">Click a rule to view full details</span>
        </div>
        <div style="overflow-x:auto">
          <table class="rules-table" id="rulesTable">
            <thead>
              <tr>
                <th style="width:50px">Active</th>
                <th class="sortable" id="th-severity" onclick="sortBy('severity')">Severity</th>
                <th class="sortable" id="th-title" onclick="sortBy('title')">Rule</th>
                <th class="sortable" id="th-category" onclick="sortBy('category')">Category</th>
                <th>Detection</th>
                <th>CWE</th>
                <th class="sortable" id="th-source" onclick="sortBy('source')">Source</th>
                <th class="sortable" id="th-created_at" onclick="sortBy('created_at')" style="width:90px">Added</th>
                <th style="width:60px"></th>
              </tr>
            </thead>
            <tbody id="rulesTbody"></tbody>
          </table>
        </div>
      </div>

    </div>

    <!-- ── Sources & Updates Panel ── -->
    <div id="sourcesPanel" style="display:none">
      <div class="sources-panel">

        <!-- AI URL Extractor -->
        <div>
          <div class="sources-section-title"><i class="fa-solid fa-wand-magic-sparkles" style="color:var(--accent);margin-right:6px"></i>AI Rule Extractor</div>
          <div class="url-extractor-card">
            <h3>Extract Rules from Any URL</h3>
            <p>Paste a security advisory, bug bounty report, CVE page, or research article — AI will analyse it and suggest detection rules for your scanner.</p>
            <div class="url-input-row">
              <input class="form-input" id="extractUrl" type="url" placeholder="https://hackerone.com/reports/... or https://cve.mitre.org/...">
              <button class="btn btn-primary" id="extractBtn" onclick="runUrlExtract()">
                <i class="fa-solid fa-wand-magic-sparkles"></i> Extract Rules
              </button>
            </div>
            <div class="url-extract-result" id="extractResult">
              <div id="extractLog" class="extract-log" style="display:none"></div>
              <div id="suggestedRules" class="suggested-rules-list"></div>
              <div id="extractEmpty" class="intel-state" style="display:none;padding:30px 0">
                <i class="fa-solid fa-face-meh state-icon"></i>
                <h3>No rules extracted</h3>
                <p>The page did not contain actionable detection patterns for Android</p>
              </div>
            </div>
          </div>
        </div>

        <!-- Security Blog Sources (no AI) -->
        <div>
          <div class="sources-section-title"><i class="fa-solid fa-newspaper" style="color:#34d399;margin-right:6px"></i>Security Blog Sources <span style="font-size:10px;background:rgba(52,211,153,.15);color:#34d399;border-radius:4px;padding:2px 7px;margin-left:6px;font-weight:600">No AI Required</span></div>
          <div class="url-extractor-card" style="margin-bottom:0">
            <h3 style="margin-bottom:6px">Sync from Security Research Blogs</h3>
            <p style="margin-bottom:6px">Fetches the latest Android vulnerability writeups from Oversecured, Google Project Zero, NowSecure, CheckPoint Research, and 9 other sources via RSS. Extracts detection patterns automatically — <strong>no API key needed</strong>.</p>
            <p style="margin-bottom:14px;font-size:12px;color:var(--text3)"><i class="fa-solid fa-circle-info" style="color:var(--accent)"></i> New rules are added directly to your <strong>Rules</strong> library (tagged <code style="font-size:11px;background:rgba(99,102,241,.15);padding:1px 5px;border-radius:3px">crawled</code>). Already-imported rules are skipped automatically.</p>
            <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
              <button class="btn btn-primary" id="blogSyncBtn" onclick="runBlogSync()">
                <i class="fa-solid fa-rotate"></i> Sync All Sources
              </button>
              <div id="blogSyncStatus" style="font-size:12px;color:var(--text3)"></div>
            </div>
            <div id="blogSyncLog" class="extract-log" style="display:none;margin-top:12px"></div>
            <div id="blogSyncResults" style="margin-top:12px"></div>
          </div>
        </div>

        <!-- External feeds (AI-powered) -->
        <div>
          <div class="sources-section-title"><i class="fa-solid fa-rss" style="color:var(--accent);margin-right:6px"></i>Intelligence Feeds <span style="font-size:10px;background:rgba(99,102,241,.15);color:#818cf8;border-radius:4px;padding:2px 7px;margin-left:6px;font-weight:600">AI-Powered</span></div>
          <p style="font-size:12px;color:var(--text3);margin:0 0 14px 0"><i class="fa-solid fa-key" style="color:#f59e0b;margin-right:4px"></i>Requires <strong style="color:var(--text)">ANTHROPIC_API_KEY</strong> — Claude reads each feed and generates detection rules. Start the server with <code style="font-size:11px;background:rgba(255,255,255,.06);padding:1px 5px;border-radius:3px">ANTHROPIC_API_KEY=sk-ant-... python server.py</code></p>
          <div class="feed-grid" id="feedGrid">

            <div class="feed-card">
              <div class="feed-card-head">
                <div class="feed-icon nvd"><i class="fa-solid fa-database"></i></div>
                <div>
                  <div class="feed-card-title">NVD / CVE Feed</div>
                  <div class="feed-card-url">nvd.nist.gov</div>
                </div>
              </div>
              <div class="feed-card-desc">National Vulnerability Database — Android CVEs with CVSS scores, CWE mappings and affected component info.</div>
              <div class="feed-card-foot">
                <div class="feed-status" id="feedStatus-nvd"><div class="feed-status-dot" id="feedDot-nvd"></div><span id="feedLbl-nvd">Not synced</span></div>
                <button class="btn btn-sm" onclick="runFeedSync('nvd')"><i class="fa-solid fa-rotate"></i> Sync Now</button>
              </div>
            </div>

            <div class="feed-card">
              <div class="feed-card-head">
                <div class="feed-icon owasp"><i class="fa-solid fa-shield-halved"></i></div>
                <div>
                  <div class="feed-card-title">OWASP Mobile Top 10</div>
                  <div class="feed-card-url">owasp.org/www-project-mobile-top-10</div>
                </div>
              </div>
              <div class="feed-card-desc">Latest OWASP Mobile Application Security risks — maps findings to industry-standard categories and remediation guidance.</div>
              <div class="feed-card-foot">
                <div class="feed-status" id="feedStatus-owasp"><div class="feed-status-dot" id="feedDot-owasp"></div><span id="feedLbl-owasp">Not synced</span></div>
                <button class="btn btn-sm" onclick="runFeedSync('owasp')"><i class="fa-solid fa-rotate"></i> Sync Now</button>
              </div>
            </div>

            <div class="feed-card">
              <div class="feed-card-head">
                <div class="feed-icon hackerone"><i class="fa-solid fa-bug"></i></div>
                <div>
                  <div class="feed-card-title">HackerOne Disclosed</div>
                  <div class="feed-card-url">hackerone.com/hacktivity</div>
                </div>
              </div>
              <div class="feed-card-desc">Publicly disclosed Android vulnerability reports from HackerOne bug bounty programs — real-world attack patterns.</div>
              <div class="feed-card-foot">
                <div class="feed-status" id="feedStatus-hackerone"><div class="feed-status-dot" id="feedDot-hackerone"></div><span id="feedLbl-hackerone">Not synced</span></div>
                <button class="btn btn-sm" onclick="runFeedSync('hackerone')"><i class="fa-solid fa-rotate"></i> Sync Now</button>
              </div>
            </div>

            <div class="feed-card">
              <div class="feed-card-head">
                <div class="feed-icon asb"><i class="fa-brands fa-android"></i></div>
                <div>
                  <div class="feed-card-title">Android Security Bulletins</div>
                  <div class="feed-card-url">source.android.com/security/bulletin</div>
                </div>
              </div>
              <div class="feed-card-desc">Monthly Google Android Security Bulletins — patches, CVEs, and affected framework components from the Android team.</div>
              <div class="feed-card-foot">
                <div class="feed-status" id="feedStatus-asb"><div class="feed-status-dot" id="feedDot-asb"></div><span id="feedLbl-asb">Not synced</span></div>
                <button class="btn btn-sm" onclick="runFeedSync('asb')"><i class="fa-solid fa-rotate"></i> Sync Now</button>
              </div>
            </div>

            <div class="feed-card">
              <div class="feed-card-head">
                <div class="feed-icon github"><i class="fa-brands fa-github"></i></div>
                <div>
                  <div class="feed-card-title">GitHub Advisory DB</div>
                  <div class="feed-card-url">github.com/advisories</div>
                </div>
              </div>
              <div class="feed-card-desc">GitHub Security Advisory Database — open-source Android library vulnerabilities with GHSA IDs and affected versions.</div>
              <div class="feed-card-foot">
                <div class="feed-status" id="feedStatus-github"><div class="feed-status-dot" id="feedDot-github"></div><span id="feedLbl-github">Not synced</span></div>
                <button class="btn btn-sm" onclick="runFeedSync('github')"><i class="fa-solid fa-rotate"></i> Sync Now</button>
              </div>
            </div>

          </div>
        </div>

      </div>
    </div>

  </div>
</div>

<!-- ── Rule Detail Modal ── -->
<div class="rule-detail-overlay" id="ruleDetailOverlay">
  <div class="rdp">
    <div class="rdp-head">
      <div class="rdp-head-top">
        <div class="rdp-sev-icon" id="rdpSevIcon"><i class="fa-solid fa-shield"></i></div>
        <div class="rdp-head-info">
          <div class="rdp-title" id="rdpTitle">—</div>
          <div class="rdp-pills" id="rdpPills"></div>
        </div>
        <div class="rdp-actions">
          <button class="btn btn-sm" id="rdpEditBtn" style="display:none" onclick="openEditFromDetail()">
            <i class="fa-solid fa-pen"></i> Edit
          </button>
          <button class="btn btn-sm" id="rdpDeleteBtn"
                  style="display:none;color:var(--critical);border-color:rgba(239,68,68,.3)"
                  onclick="deleteRuleFromDetail()">
            <i class="fa-solid fa-trash"></i>
          </button>
          <button class="rdp-close-btn" onclick="closeRuleDetail()">
            <i class="fa-solid fa-xmark"></i> Close
          </button>
        </div>
      </div>
      <div class="rdp-tabs">
        <button class="rdp-tab active" onclick="switchRdpTab('overview',this)">Overview</button>
        <button class="rdp-tab" onclick="switchRdpTab('detection',this)">Detection</button>
        <button class="rdp-tab" onclick="switchRdpTab('references',this)">References</button>
        <button class="rdp-tab" onclick="switchRdpTab('testcases',this)">Test Cases</button>
      </div>
    </div>
    <div class="rdp-body">
      <div class="rdp-pane active" id="rdpPane-overview">
        <div class="rdp-section">
          <div class="rdp-section-title">Description</div>
          <p class="rdp-text" id="rdpDescription">—</p>
        </div>
        <div class="rdp-section">
          <div class="rdp-section-title">Attack Path &amp; Impact</div>
          <p class="rdp-text" id="rdpAttackPath">—</p>
        </div>
        <div class="rdp-section">
          <div class="rdp-section-title">Remediation</div>
          <p class="rdp-text" id="rdpRemediation">—</p>
        </div>
      </div>
      <div class="rdp-pane" id="rdpPane-detection">
        <div class="rdp-section">
          <div class="rdp-section-title">Detection Type</div>
          <p class="rdp-text" id="rdpDetType">—</p>
        </div>
        <div class="rdp-section" id="rdpPatternSection">
          <div class="rdp-section-title">Regex Patterns</div>
          <div id="rdpPatterns"></div>
        </div>
        <div class="rdp-section" id="rdpManifestSection" style="display:none">
          <div class="rdp-section-title">Manifest Checks (XPath)</div>
          <div id="rdpManifest"></div>
        </div>
        <div class="rdp-section" id="rdpIosSection" style="display:none">
          <div class="rdp-section-title"><i class="fa-brands fa-apple" style="margin-right:5px"></i>iOS Detection Config</div>
          <div id="rdpIosDetection"></div>
        </div>
        <div class="rdp-section" id="rdpJarSection" style="display:none">
          <div class="rdp-section-title"><i class="fa-brands fa-java" style="margin-right:5px;color:#f97316"></i>JAR Detection Config</div>
          <div id="rdpJarDetection"></div>
        </div>
        <div class="rdp-section" id="rdpExeSection" style="display:none">
          <div class="rdp-section-title"><i class="fa-brands fa-windows" style="margin-right:5px;color:#0078d4"></i>PE/EXE Detection Config</div>
          <div id="rdpExeDetection"></div>
        </div>
        <div class="rdp-section">
          <div class="rdp-section-title">Confidence &amp; Quality</div>
          <div style="display:flex;gap:20px">
            <div>
              <div style="font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px">Confidence</div>
              <div class="rdp-text" id="rdpConfidence">—</div>
            </div>
            <div>
              <div style="font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px">False Positive Rate</div>
              <div class="rdp-text" id="rdpFPRate">—</div>
            </div>
            <div>
              <div style="font-size:10px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px">ADB Category</div>
              <div class="rdp-text" id="rdpAdbCat">—</div>
            </div>
          </div>
        </div>
      </div>
      <div class="rdp-pane" id="rdpPane-references">
        <div class="rdp-section">
          <div class="rdp-section-title">CWE / CVE Identifiers</div>
          <div class="tag-row" id="rdpCwe"></div>
        </div>
        <div class="rdp-section">
          <div class="rdp-section-title">External References</div>
          <div class="tag-row" id="rdpRefs"></div>
        </div>
        <div class="rdp-section">
          <div class="rdp-section-title">Tags</div>
          <div class="tag-row" id="rdpTags"></div>
        </div>
      </div>
      <div class="rdp-pane" id="rdpPane-testcases">
        <div class="rdp-section">
          <div class="rdp-section-title">Test Cases</div>
          <div id="rdpTestCases">
            <div class="intel-state" style="padding:40px 0">
              <i class="fa-solid fa-vial state-icon"></i>
              <h3>No test cases</h3>
              <p>This rule has no embedded test cases</p>
            </div>
          </div>
        </div>
      </div>
    </div>
    <div class="rdp-foot">
      <label class="toggle-switch" title="Enable/disable this rule">
        <input type="checkbox" id="rdpToggle" onchange="toggleRuleFromDetail(this.checked)">
        <span class="toggle-track"></span>
      </label>
      <span id="rdpToggleLabel" style="font-size:12px;color:var(--text3);margin-left:6px"></span>
      <div class="rdp-foot-meta">
        <span id="rdpId" style="font-family:'JetBrains Mono',monospace;font-size:10.5px"></span>
        <span id="rdpSource"></span>
      </div>
    </div>
  </div>
</div>'''


# ── Background scan ──────────────────────────────────────────────────────

def _unwrap_bundle(apk_path: Path, out_dir: Path) -> Path:
    """If the uploaded file is an APKM/XAPK bundle (a zip containing base.apk),
    extract base.apk and return its path.  Otherwise return apk_path unchanged."""
    try:
        if not zipfile.is_zipfile(apk_path):
            return apk_path
        with zipfile.ZipFile(apk_path) as zf:
            if "base.apk" in zf.namelist():
                extracted = out_dir / "base.apk"
                extracted.write_bytes(zf.read("base.apk"))
                return extracted
    except Exception:
        pass
    return apk_path


def _auto_install_apk(scan_id: str, apk_path: Path, package: str) -> None:
    """Detect connected ADB devices and install the APK automatically.

    This runs after the scan finishes (non-blocking — never raises).
    Preferred device: the one configured in dynamic_config.json.
    Falls back to the first device returned by `adb devices`.
    """
    try:
        # Load preferred serial from dynamic config
        preferred_serial = ""
        try:
            cfg_path = DYNAMIC_CFG_F
            if cfg_path.exists():
                cfg = json.loads(cfg_path.read_text())
                preferred_serial = cfg.get("adb_serial", "")
        except Exception:
            pass

        # Enumerate connected devices
        rc, out, _ = _run_adb(["devices"], timeout=8)
        if rc != 0:
            return  # adb not available

        # Parse: skip header line, skip "offline" devices
        devices = []
        for line in out.splitlines()[1:]:
            parts = line.strip().split()
            if len(parts) >= 2 and parts[1] == "device":
                devices.append(parts[0])

        if not devices:
            return  # no devices connected — silent skip

        # Pick preferred serial, fall back to first device
        serial = preferred_serial if preferred_serial in devices else devices[0]
        serial_args = ["-s", serial] if serial else []

        _set_status(scan_id, status="done", progress=100,
                    message=f"Installing APK on device {serial or 'default'}…")

        # Install with replace (-r keeps data), grant all permissions at install (-g)
        rc, out, err = _run_adb(serial_args + ["install", "-r", "-g", str(apk_path)], timeout=120)

        if rc == 0 or "success" in (out + err).lower():
            msg = f"✓ APK installed on {serial or 'device'} ({package})"
        elif "already installed" in (out + err).lower():
            msg = f"✓ APK already installed on {serial or 'device'}"
        else:
            msg = f"⚠ APK install on {serial or 'device'} failed: {(err or out)[:120]}"

        # Update the install_status field in DB (non-critical, best effort)
        _set_status(scan_id, status="done", progress=100,
                    message=f"Scan complete. {msg}")
    except Exception:
        pass  # installation failure is never fatal to the scan


def _compute_risk_score(sev_counts: dict) -> float:
    """Compute a 0-100 risk score from severity counts."""
    return round(min(
        sev_counts.get("Critical", 0) * 10 +
        sev_counts.get("High",     0) * 5  +
        sev_counts.get("Medium",   0) * 2  +
        sev_counts.get("Low",      0) * 0.5,
        100.0,
    ), 1)


class _FindingWrapper:
    """Lightweight adapter to make plain-dict findings compatible with report.py."""
    __slots__ = (
        "severity", "title", "description", "category", "remediation",
        "evidence", "adb_commands", "attack_path", "cwe", "references",
        "id", "fid", "_raw", "__dict__",
    )

    def __init__(self, d: dict):
        self.__dict__.update(d)
        sev_str          = d.get("severity", "Info")
        self.severity    = sev_str          # plain string — report.py calls .lower() on it
        self.title       = d.get("title", "")
        self.description = d.get("description", "")
        self.category    = d.get("category", "")
        self.remediation = d.get("remediation", "")
        ev               = d.get("evidence", {}) or {}
        self.evidence    = type("E", (), {
            "file":    ev.get("file", ev.get("file_path", "")),
            "snippet": ev.get("snippet", ""),
            "line":    ev.get("line_number", ev.get("line", 0)),
        })()
        self.adb_commands = d.get("adb_commands", [])
        self.attack_path  = d.get("attack_path", "")
        self.cwe          = d.get("cwe", [])
        self.references   = d.get("references", [])
        self.id           = d.get("id", 0)
        self.fid          = d.get("fid", d.get("id", 0))
        self._raw         = d


def _run_scan(scan_id: str, apk_path: Path):
    out_dir = _scan_dir(scan_id)
    out_dir.mkdir(exist_ok=True)
    try:
        _set_status(scan_id, status="decompiling", progress=5, message="Unpacking APK bundle…")
        # Copy APK into scan dir so dynamic analysis can install it later
        dest_apk = out_dir / apk_path.name
        if not dest_apk.exists():
            shutil.copy2(str(apk_path), str(dest_apk))
        scan_apk = _unwrap_bundle(apk_path, out_dir)
        if scan_apk != apk_path:
            _set_status(scan_id, status="decompiling", progress=10,
                        message=f"Bundle detected — decompiling base.apk with jadx…")
        else:
            _set_status(scan_id, status="decompiling", progress=10, message="Decompiling APK with jadx…")
        decompiled = out_dir / "decompiled"
        jadx = shutil.which("jadx") or "jadx"
        import subprocess
        r = subprocess.run([jadx, "-d", str(decompiled), str(scan_apk)],
                           capture_output=True, timeout=300)
        if not (decompiled / "sources").exists() and not (decompiled / "resources").exists():
            raise RuntimeError(f"jadx failed: {r.stderr.decode()[:400]}")

        _set_status(scan_id, status="scanning", progress=40, message="Scanning decompiled sources…")
        use_sg   = os.environ.get("MSRA_NO_SEMGREP") != "1"
        scanner  = Scanner(str(decompiled), adb_path=None, use_semgrep=use_sg)

        # Heartbeat: increment progress 40→78 while scanner.scan() runs so the
        # UI doesn't appear frozen on large APKs.
        _scan_done_evt = threading.Event()
        def _scan_heartbeat():
            p = 40
            while not _scan_done_evt.wait(timeout=10):
                if p < 78:
                    p = min(p + 3, 78)
                    _set_status(scan_id, status="scanning", progress=p,
                                message="Scanning decompiled sources…")
        _hb = threading.Thread(target=_scan_heartbeat, daemon=True)
        _hb.start()

        findings = scanner.scan()
        _scan_done_evt.set()
        pkg      = scanner.package_name or "unknown"

        # ── Taint analysis (source-sink inter-procedural flows) ─────────────
        _set_status(scan_id, status="scanning", progress=79,
                    message="Running inter-procedural taint analysis…")
        try:
            from msra.analysis.taint_engine import TaintEngine, to_finding as _taint_to_finding
            _taint_manifest = scanner.manifest_data or {}
            _taint_manifest.setdefault("_package", pkg)
            _taint_engine = TaintEngine(str(decompiled), _taint_manifest)
            _taint_flows = _taint_engine.analyze()
            if _taint_flows:
                findings = list(findings) + [_taint_to_finding(f) for f in _taint_flows]
                _log.info("Taint engine: %d flows found for %s", len(_taint_flows), scan_id)
        except Exception as _te:
            _log.warning("Taint engine failed (non-fatal): %s", _te)
            _taint_flows = []

        # ── ICC graph (cross-component taint via Intent forwarding) ─────────
        try:
            from msra.analysis.icc_graph import ICCGraph
            from msra.utils import Finding, Evidence
            _icc = ICCGraph(str(decompiled), _taint_manifest).build()
            _icc_chains = _icc.get_exploitable_chains(_taint_flows)
            if _icc_chains:
                def _icc_to_finding(chain):
                    from msra.utils import Finding, Evidence
                    return Finding(
                        fid=f"ICC_{chain.sink.sink_type.upper()}_{chain.entry_point.split('.')[-1].upper()}",
                        title=f"ICC taint chain: exported {chain.entry_point.split('.')[-1]} → {chain.icc_target.split('.')[-1]} → {chain.sink.sink_api}",
                        severity=chain.severity,
                        description=(
                            f"An exported component forwards untrusted Intent extras to an internal "
                            f"component via ICC. Key '{chain.extra_key}' reaches {chain.sink.sink_api} "
                            f"({chain.sink.sink_type}) in {chain.icc_target}."
                        ),
                        attack_path=(
                            f"Exported: {chain.entry_point}\n"
                            f"→ ICC ({chain.extra_key!r})\n"
                            f"→ Internal: {chain.icc_target}\n"
                            f"→ Sink: {chain.sink.sink_api}"
                        ),
                        adb_commands=chain.poc_commands,
                        evidence=Evidence(
                            file_path=chain.sink.file_path,
                            line_number=chain.sink.line_number,
                            snippet=chain.sink.code_snippet,
                            matched_text=chain.sink.sink_api,
                        ),
                        references=[
                            "https://developer.android.com/topic/security/risks/intent-injection",
                            "https://owasp.org/www-project-mobile-top-10/",
                        ],
                        extra={"icc_chain": True, "extra_key": chain.extra_key},
                    )
                findings = list(findings) + [_icc_to_finding(c) for c in _icc_chains]
                _log.info("ICC graph: %d exploitable chains for %s", len(_icc_chains), scan_id)
        except Exception as _ie:
            _log.debug("ICC graph failed (non-fatal): %s", _ie)

        _set_status(scan_id, status="reporting", progress=80,
                    message=f"Generating report ({len(findings)} findings)…")
        src_count = sum(1 for _ in iter_source_files(str(decompiled)))
        metadata  = {"title": f"{pkg} — Security Assessment",
                     "package": pkg, "apk": apk_path.name,
                     "source_files": src_count}
        generate_html_report(findings, str(out_dir / "report.html"), metadata)

        sev_counts: dict = {}
        for f in findings:
            sev = str(getattr(f.severity, "value", f.severity))
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        # Save findings.json — parsed from the embedded JSON block in report.html
        # so it always matches what the report renders (no duplicate serialisation).
        try:
            raw_report = (out_dir / "report.html").read_text(encoding="utf-8")
            jm = re.search(
                r'<script[^>]+id=["\']reportData["\'][^>]*>(.*?)</script>',
                raw_report, re.DOTALL,
            )
            if jm:
                findings_data = json.loads(jm.group(1).replace('<\\/', '</'))
                (out_dir / "findings.json").write_text(
                    json.dumps(findings_data, indent=2), encoding="utf-8"
                )
        except Exception:
            pass  # non-fatal — API has a fallback

        # Risk score: Critical×10 + High×5 + Medium×2 + Low×0.5, capped at 100
        risk_score = round(min(
            sev_counts.get("Critical", 0) * 10 +
            sev_counts.get("High", 0) * 5 +
            sev_counts.get("Medium", 0) * 2 +
            sev_counts.get("Low", 0) * 0.5,
            100.0,
        ), 1)

        summary = {"scan_id": scan_id, "package": pkg, "apk": apk_path.name,
                   "total_findings": len(findings), "severity_counts": sev_counts,
                   "risk_score": risk_score}
        (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))

        # ── Auto-install APK on connected ADB device ────────────────────────
        _auto_install_apk(scan_id, scan_apk, pkg)

        _set_status(scan_id, status="done", progress=100, message="Scan complete.",
                    package=pkg, total=len(findings), severity_counts=sev_counts,
                    risk_score=risk_score)
    except Exception as exc:
        _set_status(scan_id, status="error",
                    message=f"Scan failed: {type(exc).__name__}: {exc}",
                    traceback=traceback.format_exc())
    finally:
        try: apk_path.unlink(missing_ok=True)
        except Exception: pass


# ── Routes ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    summaries = _load_summaries()
    scan_id   = request.args.get("scan")
    view      = request.args.get("view")

    return Response(_build_dashboard(scan_id, summaries, view=view), mimetype="text/html")


@app.route("/report/<scan_id>")
def legacy_report(scan_id: str):
    """Redirect old /report/<id> URLs to the clean scan URL."""
    return redirect(f"/scans/{scan_id}", code=301)


@app.route("/scans/<scan_id>")
def view_scan(scan_id: str):
    """Clean URL for a specific scan."""
    summaries = _load_summaries()
    if not any(s.get("scan_id") == scan_id for s in summaries):
        abort(404)
    return Response(_build_dashboard(scan_id, summaries), mimetype="text/html")


@app.route("/scans/<scan_id>/findings/<int:finding_idx>")
def view_finding(scan_id: str, finding_idx: int):
    """Deep link to a specific finding — scrolls to it on load."""
    summaries = _load_summaries()
    if not any(s.get("scan_id") == scan_id for s in summaries):
        abort(404)
    html = _build_dashboard(scan_id, summaries)
    jump_script = f'<script>window.__JUMP_FINDING={finding_idx};</script>'
    html = html.replace('</head>', jump_script + '</head>', 1)
    return Response(html, mimetype="text/html")


def _load_findings_data(scan_id: str) -> dict | None:
    """Load findings JSON for a scan — from findings.json or by re-parsing report.html."""
    findings_path = _scan_dir(scan_id) / "findings.json"
    if findings_path.exists():
        try:
            return json.loads(findings_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    # Fallback: extract embedded JSON from report.html
    report_path = _scan_dir(scan_id) / "report.html"
    if report_path.exists():
        try:
            raw = report_path.read_text(encoding="utf-8")
            jm = re.search(
                r'<script[^>]+id=["\']reportData["\'][^>]*>(.*?)</script>',
                raw, re.DOTALL,
            )
            if jm:
                return json.loads(jm.group(1).replace('<\\/', '</'))
        except Exception:
            pass
    return None


def _load_findings_with_triage(scan_id: str) -> dict | None:
    """Load findings JSON and merge triage status from DB into each finding."""
    data = _load_findings_data(scan_id)
    if data is None:
        return None
    triage_map = _db.get_triage_map(scan_id)
    for f in data.get("findings", []):
        fid = f.get("id") or f.get("fid")
        t = triage_map.get(fid, {}) if fid is not None else {}
        f["triage_status"] = t.get("status", "New")
        f["suppression_note"] = t.get("suppression_note", "")
    return data


@app.route("/api/scans/<scan_id>/findings")
def api_findings(scan_id: str):
    """Return findings JSON with triage status merged in."""
    data = _load_findings_with_triage(scan_id)
    if data is None:
        return jsonify({"error": "findings not available"}), 404
    return jsonify(data)


@app.route("/api/scans/<scan_id>/findings/<int:finding_id>/triage", methods=["PATCH"])
def api_triage_finding(scan_id: str, finding_id: int):
    """Update triage status for a finding."""
    body = request.get_json(silent=True) or {}
    status = body.get("status", "New")
    note   = body.get("suppression_note", "")
    valid  = {"New", "Confirmed", "False Positive", "Accepted Risk", "Fixed", "In Progress"}
    if status not in valid:
        return jsonify({"error": f"Invalid status. Valid: {sorted(valid)}"}), 400
    _db.upsert_triage(scan_id, finding_id, status, note)
    return jsonify({"ok": True, "scan_id": scan_id, "finding_id": finding_id, "status": status})


@app.route("/api/scans/<scan_id>/findings/<finding_id>/snippet")
def api_finding_snippet(scan_id: str, finding_id: str):
    """Return actual source code around the vulnerable line for a finding."""
    data = _load_findings_data(scan_id)
    if not data:
        return jsonify({"error": "scan not found"}), 404

    findings = data.get("findings", [])
    # Match by numeric id or string fid
    try:
        fid_int = int(finding_id)
    except ValueError:
        fid_int = None
    finding = next(
        (f for f in findings if f.get("id") == fid_int or str(f.get("fid", "")) == finding_id),
        None,
    )
    if not finding:
        return jsonify({"error": "finding not found"}), 404

    ev        = finding.get("evidence") or {}
    file_path = ev.get("file") or ""
    line_num  = int(ev.get("line") or 0)

    if not file_path or not line_num:
        return jsonify({"error": "no location info"}), 404

    # Resolve path — always rooted within this scan's decompiled directory
    scan_d     = _scan_dir(scan_id)
    decompiled = scan_d / "decompiled"
    p          = Path(file_path)

    if not p.exists() or not str(p.resolve()).startswith(str(decompiled.resolve())):
        # Strip everything up to and including "decompiled/"
        marker = "decompiled/"
        idx    = file_path.find(marker)
        if idx != -1:
            p = decompiled / file_path[idx + len(marker):]
        if not p.exists():
            # Last resort: search for filename in decompiled tree
            fname = Path(file_path).name
            if decompiled.exists():
                matches = list(decompiled.rglob(fname))
                if matches:
                    p = matches[0]

    # Safety: ensure final path is still inside the scan's decompiled dir
    try:
        resolved = p.resolve()
        if decompiled.exists() and not str(resolved).startswith(str(decompiled.resolve())):
            return jsonify({"error": "access denied"}), 403
    except Exception:
        return jsonify({"error": "access denied"}), 403

    if not p.exists():
        return jsonify({"error": f"source file not found: {Path(file_path).name}"}), 404

    try:
        lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
        ctx   = 6
        start = max(0, line_num - ctx - 1)
        end   = min(len(lines), line_num + ctx)
        snippet_lines = []
        for i in range(start, end):
            marker_str = ">>>" if (i + 1 == line_num) else "   "
            snippet_lines.append(f"{i+1:04d}{marker_str} {lines[i]}")
        return jsonify({
            "snippet":   "\n".join(snippet_lines),
            "file":      str(p),
            "file_name": p.name,
            "line":      line_num,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/dashboard/stats")
def api_dashboard_stats():
    """Aggregate stats across all scans — used by the home dashboard."""
    summaries = _load_summaries()
    total_findings = 0
    by_severity: dict = {}
    for s in summaries:
        total_findings += s.get("total_findings", 0)
        for sev, cnt in s.get("severity_counts", {}).items():
            by_severity[sev] = by_severity.get(sev, 0) + cnt
    return jsonify({
        "total_scans": len(summaries),
        "total_findings": total_findings,
        "by_severity": by_severity,
        "recent_scans": summaries[:10],
    })


@app.route("/api/scans/<scan_id>/export/sarif")
def api_export_sarif(scan_id: str):
    """Export findings in SARIF 2.1.0 format for CI/CD integration."""
    data = _load_findings_with_triage(scan_id)
    if data is None:
        return jsonify({"error": "findings not available"}), 404

    sev_map = {"Critical": "error", "High": "error",
               "Medium": "warning", "Low": "note", "Info": "none"}

    rules, results = [], []
    seen_rules: set = set()
    for f in data.get("findings", []):
        rule_id = re.sub(r'[^a-zA-Z0-9_/.-]', '_', f.get("title", "finding"))[:64]
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": f.get("title", ""),
                "shortDescription": {"text": f.get("title", "")},
                "fullDescription": {"text": f.get("description", "")},
                "helpUri": (f.get("references") or [""])[0],
                "properties": {
                    "tags": [f.get("category", "")],
                    "severity": f.get("severity", ""),
                    "cwe": f.get("cwe", []),
                },
            })
        ev = f.get("evidence") or {}
        file_uri = ev.get("file") or ""
        line_num = ev.get("line") or 1
        results.append({
            "ruleId": rule_id,
            "level": sev_map.get(f.get("severity", ""), "warning"),
            "message": {"text": f.get("description", "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": file_uri, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": line_num},
                }
            }],
            "properties": {
                "triage_status": f.get("triage_status", "New"),
                "attack_path": f.get("attack_path", ""),
            },
        })

    sarif = {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "MSRA",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/sai/msra",
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }
    pkg = data.get("package", scan_id)
    sarif_json = json.dumps(sarif, indent=2)
    return Response(
        sarif_json,
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="{pkg}_msra.sarif"'},
    )


@app.route("/api/scans/<scan_id>/export/csv")
def api_export_csv(scan_id: str):
    """Export findings as CSV."""
    data = _load_findings_with_triage(scan_id)
    if data is None:
        return jsonify({"error": "findings not available"}), 404

    import io, csv as _csv
    output = io.StringIO()
    writer = _csv.writer(output)
    writer.writerow(["ID", "Title", "Severity", "Category", "CWE", "File", "Line",
                     "Triage Status", "Description", "Remediation"])
    for f in data.get("findings", []):
        ev = f.get("evidence") or {}
        writer.writerow([
            f.get("id", ""),
            f.get("title", ""),
            f.get("severity", ""),
            f.get("category", ""),
            "; ".join(f.get("cwe", [])),
            ev.get("file", ""),
            ev.get("line", ""),
            f.get("triage_status", "New"),
            f.get("description", ""),
            f.get("remediation", ""),
        ])
    pkg = data.get("package", scan_id)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{pkg}_msra.csv"'},
    )


def _run_ios_scan(scan_id: str, ipa_path: Path):
    """Background thread: static analysis of an IPA file."""
    out_dir = _scan_dir(scan_id)
    out_dir.mkdir(exist_ok=True)
    try:
        _set_status(scan_id, status="scanning", progress=10, message="Extracting IPA…")
        from msra.ios_scanner import scan_ipa
        _set_status(scan_id, status="scanning", progress=25, message="Analysing Info.plist and entitlements…")
        findings, meta = scan_ipa(str(ipa_path))

        bundle_id = meta.get("bundle_id", "unknown")
        app_name  = meta.get("app_name", bundle_id)
        pkg       = bundle_id

        _set_status(scan_id, status="reporting", progress=75,
                    message=f"Generating report ({len(findings)} findings)…")

        wrapped     = [_FindingWrapper(f) for f in findings]
        report_meta = {
            "title":    f"{app_name} — iOS Security Assessment",
            "package":  pkg,
            "apk":      ipa_path.name,
            "platform": "ios",
            "source_files": 0,
        }
        generate_html_report(wrapped, str(out_dir / "report.html"), report_meta)

        findings_data = {
            "package":        pkg,
            "apk":            ipa_path.name,
            "platform":       "ios",
            "total_findings": len(findings),
            "findings":       findings,
        }
        (out_dir / "findings.json").write_text(
            json.dumps(findings_data, indent=2), encoding="utf-8"
        )

        sev_counts: dict = {}
        for f in findings:
            sev_counts[f.get("severity", "Info")] = sev_counts.get(f.get("severity", "Info"), 0) + 1

        risk_score = _compute_risk_score(sev_counts)

        summary = {"scan_id": scan_id, "package": pkg, "apk": ipa_path.name,
                   "platform": "ios", "total_findings": len(findings),
                   "severity_counts": sev_counts, "risk_score": risk_score}
        (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))

        _set_status(scan_id, status="done", progress=100, message="iOS scan complete.",
                    package=pkg, total=len(findings), severity_counts=sev_counts,
                    risk_score=risk_score, platform="ios")
    except Exception as exc:
        _set_status(scan_id, status="error",
                    message=f"iOS scan failed: {type(exc).__name__}: {exc}",
                    traceback=traceback.format_exc())
    finally:
        try: ipa_path.unlink(missing_ok=True)
        except Exception: pass


def _run_jar_scan(scan_id: str, jar_path: Path):
    """Background thread: static analysis of a JAR file."""
    out_dir = _scan_dir(scan_id)
    out_dir.mkdir(exist_ok=True)
    try:
        _set_status(scan_id, status="scanning", progress=10, message="Opening JAR…")
        from msra.jar_scanner import scan_jar
        _set_status(scan_id, status="scanning", progress=25, message="Analysing manifest and class files…")
        findings, meta = scan_jar(str(jar_path))

        main_class = meta.get("main_class") or jar_path.stem
        impl       = meta.get("implementation") or jar_path.name
        pkg        = main_class

        _set_status(scan_id, status="reporting", progress=75,
                    message=f"Generating report ({len(findings)} findings)…")

        wrapped     = [_FindingWrapper(f) for f in findings]
        report_meta = {
            "title":    f"{impl} — JAR Security Assessment",
            "package":  pkg,
            "apk":      jar_path.name,
            "platform": "jar",
            "source_files": 0,
        }
        generate_html_report(wrapped, str(out_dir / "report.html"), report_meta)

        findings_data = {
            "package":        pkg,
            "apk":            jar_path.name,
            "platform":       "jar",
            "total_findings": len(findings),
            "findings":       findings,
        }
        (out_dir / "findings.json").write_text(
            json.dumps(findings_data, indent=2), encoding="utf-8"
        )

        sev_counts: dict = {}
        for f in findings:
            sev_counts[f.get("severity", "Info")] = sev_counts.get(f.get("severity", "Info"), 0) + 1

        risk_score = _compute_risk_score(sev_counts)

        summary = {"scan_id": scan_id, "package": pkg, "apk": jar_path.name,
                   "platform": "jar", "total_findings": len(findings),
                   "severity_counts": sev_counts, "risk_score": risk_score}
        (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))

        _set_status(scan_id, status="done", progress=100, message="JAR scan complete.",
                    package=pkg, total=len(findings), severity_counts=sev_counts,
                    risk_score=risk_score, platform="jar")
    except Exception as exc:
        _set_status(scan_id, status="error",
                    message=f"JAR scan failed: {type(exc).__name__}: {exc}",
                    traceback=traceback.format_exc())
    finally:
        try: jar_path.unlink(missing_ok=True)
        except Exception: pass


def _run_exe_scan(scan_id: str, exe_path: Path):
    """Background thread: static analysis of a Windows PE/EXE file."""
    out_dir = _scan_dir(scan_id)
    out_dir.mkdir(exist_ok=True)
    try:
        _set_status(scan_id, status="scanning", progress=10, message="Parsing PE headers…")
        from msra.exe_scanner import scan_exe
        _set_status(scan_id, status="scanning", progress=30, message="Analysing imports, sections, and strings…")
        findings, meta = scan_exe(str(exe_path))

        product    = meta.get("product_name") or meta.get("original_filename") or exe_path.stem
        orig_name  = meta.get("original_filename") or exe_path.name
        company    = meta.get("company") or ""
        arch       = meta.get("architecture") or "x86"
        pkg        = f"{product} ({arch})" if product else exe_path.stem

        _set_status(scan_id, status="reporting", progress=75,
                    message=f"Generating report ({len(findings)} findings)…")

        wrapped     = [_FindingWrapper(f) for f in findings]
        report_meta = {
            "title":    f"{product} — Windows PE Security Assessment",
            "package":  pkg,
            "apk":      exe_path.name,
            "platform": "exe",
            "source_files": 0,
        }
        generate_html_report(wrapped, str(out_dir / "report.html"), report_meta)

        findings_data = {
            "package":        pkg,
            "apk":            exe_path.name,
            "platform":       "exe",
            "total_findings": len(findings),
            "findings":       findings,
        }
        (out_dir / "findings.json").write_text(
            json.dumps(findings_data, indent=2), encoding="utf-8"
        )

        sev_counts: dict = {}
        for f in findings:
            sev_counts[f.get("severity", "Info")] = sev_counts.get(f.get("severity", "Info"), 0) + 1

        risk_score = _compute_risk_score(sev_counts)

        pefile_note = "" if meta.get("has_pefile") else " (install pefile for full PE analysis)"
        summary = {"scan_id": scan_id, "package": pkg, "apk": exe_path.name,
                   "platform": "exe", "total_findings": len(findings),
                   "severity_counts": sev_counts, "risk_score": risk_score}
        (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))

        _set_status(scan_id, status="done", progress=100,
                    message=f"PE scan complete.{pefile_note}",
                    package=pkg, total=len(findings), severity_counts=sev_counts,
                    risk_score=risk_score, platform="exe")
    except Exception as exc:
        _set_status(scan_id, status="error",
                    message=f"PE scan failed: {type(exc).__name__}: {exc}",
                    traceback=traceback.format_exc())
    finally:
        try: exe_path.unlink(missing_ok=True)
        except Exception: pass


@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": "File too large. Maximum upload size is 500 MB."}), 413


@app.route("/api/upload", methods=["POST"])
def upload():
    if not _rate_limit(request.remote_addr or "unknown", max_per_minute=20):
        return jsonify({"error": "Too many uploads — please wait a minute"}), 429
    if "apk" not in request.files:
        return jsonify({"error": "No file"}), 400
    f = request.files["apk"]
    if not f.filename:
        return jsonify({"error": "No filename"}), 400

    fname_lower = f.filename.lower()
    is_ios     = fname_lower.endswith(".ipa")
    is_jar     = fname_lower.endswith(".jar")
    is_exe     = fname_lower.endswith((".exe", ".dll"))
    is_android = fname_lower.endswith((".apk", ".apkm", ".xapk"))

    if not is_ios and not is_android and not is_jar and not is_exe:
        return jsonify({"error": "File must be APK/APKM/XAPK (Android), IPA (iOS), JAR (Java), or EXE/DLL (Windows)"}), 400

    scan_id   = uuid.uuid4().hex[:12]
    file_path = UPLOAD_FOLDER / f"{scan_id}_{f.filename}"
    f.save(str(file_path))

    if is_ios:
        platform = "ios"
    elif is_jar:
        platform = "jar"
    elif is_exe:
        platform = "exe"
    else:
        platform = "android"

    _db.upsert_scan(scan_id, status="queued", progress=0,
                    message="Queued…", platform=platform,
                    package=f.filename, apk=f.filename)

    # Queue depth before submission — tells the UI how many scans are waiting ahead
    queued_ahead = _SCAN_POOL._work_queue.qsize()

    if is_ios:
        _SCAN_POOL.submit(_run_ios_scan, scan_id, file_path)
    elif is_jar:
        _SCAN_POOL.submit(_run_jar_scan, scan_id, file_path)
    elif is_exe:
        _SCAN_POOL.submit(_run_exe_scan, scan_id, file_path)
    else:
        _SCAN_POOL.submit(_run_scan, scan_id, file_path)

    return jsonify({"scan_id": scan_id, "platform": platform, "queued_ahead": queued_ahead})


@app.route("/api/scan/<scan_id>/status")
def scan_status(scan_id: str):
    data = _db.get_scan(scan_id) or {"status": "unknown", "message": "Not found"}
    data.pop("traceback", None)
    return jsonify(data)


@app.route("/api/queue/status")
def api_queue_status():
    """Return current scan pool and dynamic pool queue depths."""
    scan_q = _SCAN_POOL._work_queue.qsize()   # pending in queue (not yet running)
    dyn_q  = _DYN_POOL._work_queue.qsize()
    return jsonify({
        "scan_pool":  {"max_workers": 2, "queued": scan_q},
        "dyn_pool":   {"max_workers": 3, "queued": dyn_q},
    })


@app.route("/api/test-ai", methods=["POST"])
def api_test_ai():
    """Quick smoke-test: send a tiny message to Claude and return ok/error."""
    data    = request.get_json(force=True, silent=True) or {}
    api_key = data.get("api_key") or ANTHROPIC_API_KEY
    if not api_key:
        return jsonify({"ok": False, "error": "No API key provided"}), 400
    try:
        payload = json.dumps({
            "model":      "claude-haiku-4-5-20251001",
            "max_tokens": 16,
            "messages":   [{"role": "user", "content": "Reply with just: OK"}],
        }).encode()
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=payload,
            headers={
                "x-api-key":         api_key,
                "anthropic-version": "2023-06-01",
                "content-type":      "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read())
        model = body.get("model", "claude")
        return jsonify({"ok": True, "model": model})
    except urllib.error.HTTPError as e:
        try:
            err_body = json.loads(e.read())
            err = err_body.get("error", {}).get("message", str(e))
        except Exception:
            err = str(e)
        return jsonify({"ok": False, "error": err})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/generate-poc", methods=["POST"])
def generate_poc():
    data    = request.get_json(force=True, silent=True) or {}
    api_key = data.get("api_key") or request.headers.get("X-API-Key") or ANTHROPIC_API_KEY
    if not api_key:
        return jsonify({"error": "No Anthropic API key. Set ANTHROPIC_API_KEY or pass api_key in the request."}), 401

    package     = data.get("package", "com.target.app")
    title       = data.get("title", "Unknown Vulnerability")
    description = data.get("description", "")
    severity    = data.get("severity", "High")
    category    = data.get("category", "")
    component   = data.get("component", "")
    authority   = data.get("authority", f"{package}.provider")
    snippet     = data.get("snippet", "")
    file_path   = data.get("file_path", "")
    poc_text    = data.get("poc_text", "")
    attack_path = data.get("attack_path", "")

    try:
        import anthropic as _ant
        client  = _ant.Anthropic(api_key=api_key)
        message = client.messages.create(
            model=CLAUDE_MODEL, max_tokens=8000,
            messages=[{"role": "user", "content": _build_poc_prompt(
                package=package, title=title, description=description,
                severity=severity, category=category, component=component,
                authority=authority, snippet=snippet, file_path=file_path,
                poc_text=poc_text, attack_path=attack_path,
            )}],
        )
        raw   = message.content[0].text
        files = _parse_poc_files(raw)
        return jsonify({"success": True, "files": files, "raw": raw})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


def _build_poc_prompt(*, package, title, description, severity, category,
                       component, authority, snippet, file_path,
                       poc_text, attack_path) -> str:
    short = package.replace(".", "_")[:20]
    return f"""You are a senior Android security researcher writing educational PoC code.

Generate a complete compilable Android application demonstrating this vulnerability for authorized security testing.

## Vulnerability
- **Title:** {title}
- **Severity:** {severity} | **Category:** {category}
- **Target package:** {package}
- **Component:** {component or "(see evidence)"}
- **ContentProvider authority:** {authority}

## Description
{description}

## Vulnerable code
File: {file_path}
```java
{snippet or "(no snippet)"}
```

## Existing PoC commands
```
{poc_text or "(none)"}
```

## Attack scenario
{attack_path or "(see description)"}

---

Generate a complete Android PoC app with package `com.msra.poc.{short}`.

Rules:
- Use EXACT package `{package}`, real component names, authority `{authority}`
- minSdk 24 / targetSdk 34 / compileSdk 34
- Simple UI (TextView / RecyclerView) showing extracted data
- Inline comments explaining each exploitation step

Return ONLY these files, no other text:

### FILE: AndroidManifest.xml
```xml
[content]
```

### FILE: app/build.gradle
```gradle
[content]
```

### FILE: MainActivity.java
```java
[content]
```

### FILE: build.gradle
```gradle
[content]
```

### FILE: settings.gradle
```gradle
[content]
```"""


def _parse_poc_files(raw: str) -> list:
    files = []
    for m in re.finditer(r"###\s*FILE:\s*(.+?)\n```(?:\w+)?\n(.*?)```", raw, re.DOTALL):
        name = m.group(1).strip()
        content = m.group(2).strip()
        ext  = name.rsplit(".", 1)[-1].lower()
        lang = {"java": "java", "kt": "kotlin", "xml": "xml",
                "gradle": "groovy", "kts": "kotlin"}.get(ext, "text")
        files.append({"name": name, "content": content, "language": lang})
    return files


@app.route("/api/download-poc/<scan_id>", methods=["POST"])
def download_poc(scan_id: str):
    if not _rate_limit(request.remote_addr or "unknown", max_per_minute=30):
        return jsonify({"error": "Too many requests — please wait a minute"}), 429
    data  = request.get_json(force=True, silent=True) or {}
    files = data.get("files", [])
    if not files:
        return jsonify({"error": "No files"}), 400
    buf = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
    buf_path = buf.name
    buf.close()
    try:
        with zipfile.ZipFile(buf_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in files:
                zf.writestr(f["name"], f["content"])
        response = send_file(buf_path, as_attachment=True,
                             download_name=f"poc_{scan_id}.zip",
                             mimetype="application/zip")
    finally:
        try:
            import os
            os.unlink(buf_path)
        except Exception:
            pass
    return response


# ── Rules API ────────────────────────────────────────────────────────────

@app.route("/api/rules")
def api_list_rules():
    """List all detection rules."""
    return jsonify(rules_api.get_all_rules())


@app.route("/api/rules/stats")
def api_rules_stats():
    """Return aggregated rule statistics."""
    return jsonify(rules_api.get_stats())


@app.route("/api/rules/<rule_id>/toggle", methods=["PATCH"])
def api_toggle_rule(rule_id: str):
    """Toggle a rule's enabled state."""
    result = rules_api.toggle_rule(rule_id)
    return jsonify(result)


@app.route("/api/rules", methods=["POST"])
def api_create_rule():
    """Create a new custom rule."""
    data = request.get_json(force=True, silent=True) or {}
    try:
        rule = rules_api.create_custom_rule(data)
        return jsonify(rule), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/rules/<rule_id>", methods=["PUT"])
def api_update_rule(rule_id: str):
    """Update a custom rule."""
    data   = request.get_json(force=True, silent=True) or {}
    result = rules_api.update_custom_rule(rule_id, data)
    if result is None:
        return jsonify({"error": "Rule not found or not a custom rule"}), 404
    return jsonify(result)


@app.route("/api/rules/<rule_id>", methods=["DELETE"])
def api_delete_rule(rule_id: str):
    """Delete a custom rule (only custom rules can be deleted)."""
    if rules_api.delete_custom_rule(rule_id):
        return jsonify({"success": True})
    return jsonify({"error": "Rule not found or cannot delete built-in rules"}), 404


# ── Dynamic Analysis API ──────────────────────────────────────────────────

@app.route("/api/dynamic/config", methods=["GET"])
def api_dyn_cfg_get():
    cfg = _load_dynamic_cfg()
    # Never return the token in plaintext (mask it)
    safe = dict(cfg)
    if safe.get("corellium_token"):
        safe["corellium_token"] = "•" * 8
    return jsonify(safe)

@app.route("/api/dynamic/config", methods=["POST"])
def api_dyn_cfg_set():
    data = request.get_json(force=True, silent=True) or {}
    cfg  = _load_dynamic_cfg()
    for k in ("mode", "adb_serial", "corellium_url", "instance_id"):
        if k in data:
            cfg[k] = data[k]
    # Only overwrite token if a non-masked value is provided
    token = data.get("corellium_token", "")
    if token and not set(token).issubset({"•"}):
        cfg["corellium_token"] = token
    _save_dynamic_cfg(cfg)
    return jsonify({"ok": True})


@app.route("/api/dynamic/adb-devices")
def api_dyn_adb_devices():
    import subprocess as _sp
    try:
        r = _sp.run(["adb", "devices", "-l"], capture_output=True, text=True, timeout=10)
        lines   = r.stdout.strip().split("\n")[1:]  # skip header
        devices = []
        for ln in lines:
            ln = ln.strip()
            if not ln or "offline" in ln:
                continue
            parts  = ln.split()
            serial = parts[0]
            model  = next((p.split(":")[1] for p in parts if p.startswith("model:")), "")
            if parts[1] == "device":
                devices.append({"serial": serial, "model": model})
        return jsonify({"devices": devices})
    except FileNotFoundError:
        return jsonify({"devices": [], "error": "adb not found in PATH"})
    except Exception as e:
        return jsonify({"devices": [], "error": str(e)})


@app.route("/api/dynamic/corellium-test", methods=["POST"])
def api_dyn_corellium_test():
    data  = request.get_json(force=True, silent=True) or {}
    url   = (data.get("url") or "https://app.corellium.com").strip()
    token = (data.get("token") or "").strip()
    if not token:
        return jsonify({"ok": False, "error": "Token required"}), 400
    try:
        client = CorelliumClient(token, url)
        user   = client.check_auth()
        return jsonify({"ok": True, "user": user.get("name") or user.get("label") or "authenticated"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/api/dynamic/corellium-instances", methods=["POST"])
def api_dyn_corellium_instances():
    data  = request.get_json(force=True, silent=True) or {}
    url   = (data.get("url") or "https://app.corellium.com").strip()
    token = (data.get("token") or "").strip()
    if not token:
        return jsonify({"error": "Token required"}), 400
    try:
        client    = CorelliumClient(token, url)
        instances = client.list_instances()
        return jsonify({"instances": [i.to_dict() for i in instances]})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/dynamic/verify", methods=["POST"])
def api_dyn_start_verify():
    data        = request.get_json(force=True, silent=True) or {}
    scan_id     = data.get("scan_id", "")
    try:
        finding_idx = int(data.get("finding_index", 0))
    except (ValueError, TypeError):
        return jsonify({"error": "finding_index must be an integer"}), 400
    finding     = data.get("finding", {})
    use_ai      = bool(data.get("use_ai", True))

    if not scan_id:
        return jsonify({"error": "scan_id required"}), 400
    if not _scan_dir(scan_id).exists():
        return jsonify({"error": "Scan not found"}), 404

    # Enrich finding with scan metadata
    summaries = _load_summaries()
    meta      = next((s for s in summaries if s.get("scan_id") == scan_id), {})
    finding.setdefault("package", meta.get("package", ""))

    job_id = uuid.uuid4().hex[:12]
    scan_mode = "ai-enhanced" if use_ai else "basic-adb"
    _db.upsert_job(
        job_id,
        scan_id=scan_id,
        finding_index=finding_idx,
        finding_title=finding.get("title", f"Finding #{finding_idx+1}"),
        status="queued",
        progress=0,
        message=f"Queued ({scan_mode})",
        logcat="",
        evidence="",
    )

    cfg = _load_dynamic_cfg()
    _DYN_POOL.submit(_dynamic_verify_worker, job_id, scan_id, finding_idx, finding, cfg, use_ai)
    return jsonify({"job_id": job_id, "mode": scan_mode}), 202


@app.route("/api/dynamic/verify/<job_id>")
def api_dyn_job_status(job_id: str):
    job = _db.get_job(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job)


@app.route("/api/dynamic/jobs")
def api_dyn_list_jobs():
    return jsonify(_db.list_jobs(limit=50))


# ── Intelligence: AI URL Extractor ───────────────────────────────────────

@app.route("/api/intel/extract-from-url", methods=["POST"])
def api_intel_extract():
    """Fetch a URL, pass content to Claude, return suggested detection rules."""
    if not ANTHROPIC_API_KEY:
        return jsonify({"error": "ANTHROPIC_API_KEY not configured. Set it in the environment to use AI extraction."}), 400

    data = request.get_json(force=True, silent=True) or {}
    url  = (data.get("url") or "").strip()
    if not url or not url.startswith("http"):
        return jsonify({"error": "A valid http/https URL is required"}), 400

    # ── 1. Fetch the URL ────────────────────────────────────────────────
    log_lines = []
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 MSRA-RuleExtractor/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read(200_000)          # cap at 200 KB
        content_type = resp.headers.get("Content-Type", "")
    except urllib.error.URLError as e:
        return jsonify({"error": f"Could not fetch URL: {e}"}), 400
    except Exception as e:
        return jsonify({"error": f"Fetch error: {e}"}), 500

    log_lines.append(f"✓ Fetched {len(raw):,} bytes from {url}")

    # Strip HTML tags to get readable text
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        text = raw.decode("latin-1", errors="replace")

    # Remove script/style blocks and HTML tags
    text = re.sub(r'<(script|style)[^>]*>[\s\S]*?</(script|style)>', ' ', text, flags=re.IGNORECASE)
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    text = text[:12000]   # pass first 12 K chars to Claude

    log_lines.append(f"✓ Extracted {len(text):,} chars of text content")
    log_lines.append("⟳ Calling Claude to analyse for Android detection patterns…")

    # ── 2. Call Claude ──────────────────────────────────────────────────
    prompt = f"""You are a senior Android security researcher.
Analyse the following text (from a security advisory, bug bounty report, CVE description, or research article) and extract Android-specific vulnerability detection rules suitable for a static analysis scanner.

Return a JSON array (and ONLY the JSON array, no prose) of rule objects. Each object must follow this schema:
{{
  "id": "unique-kebab-case-id",
  "title": "Short descriptive title",
  "severity": "Critical|High|Medium|Low|Info",
  "category": "one of: WebView|OWASP-M1-Credentials|OWASP-M4-InputValidation|OWASP-M5-Communication|OWASP-M9-DataStorage|OWASP-M10-Cryptography|Component-Exposure|Intent-DeepLink|Permission|Logging|Other",
  "description": "2-3 sentence technical description",
  "attack_path": "How an attacker exploits this",
  "remediation": "How to fix it",
  "detection_type": "regex",
  "patterns": [{{"pattern": "(?i)regex_pattern_here", "flags": "i", "file_types": [".java", ".kt"]}}],
  "cwe": ["CWE-XXX"],
  "tags": ["android", "relevant-tag"]
}}

Rules:
- Only include rules where you can write a meaningful regex pattern
- Focus on Android Java/Kotlin code patterns
- Prefer specific patterns over generic ones
- If no Android patterns are extractable, return an empty array []

TEXT TO ANALYSE:
{text}"""

    try:
        import urllib.request as _ur
        api_payload = json.dumps({
            "model": CLAUDE_MODEL,
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": prompt}]
        }).encode()
        api_req = _ur.Request(
            "https://api.anthropic.com/v1/messages",
            data=api_payload,
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            method="POST"
        )
        with _ur.urlopen(api_req, timeout=60) as resp:
            api_resp = json.loads(resp.read())
        raw_text = api_resp["content"][0]["text"].strip()
    except Exception as e:
        return jsonify({"error": f"Claude API error: {e}", "log": "\n".join(log_lines)}), 500

    # ── 3. Parse the JSON array from Claude's response ──────────────────
    # Claude sometimes wraps in ```json ... ``` — strip that
    raw_text = re.sub(r'^```(?:json)?\s*', '', raw_text, flags=re.MULTILINE)
    raw_text = re.sub(r'\s*```$', '', raw_text, flags=re.MULTILINE)

    try:
        rules = json.loads(raw_text)
        if not isinstance(rules, list):
            rules = []
    except Exception:
        # Try to find first [...] block
        m = re.search(r'\[[\s\S]*\]', raw_text)
        try:
            rules = json.loads(m.group()) if m else []
        except Exception:
            rules = []

    log_lines.append(f"✓ Claude extracted {len(rules)} candidate rule(s)")
    return jsonify({"rules": rules, "log": "\n".join(log_lines)})


# ── Intelligence: Feed Sync ────────────────────────────────────────────────

# Simple metadata for each feed (URLs we can actually query without auth)
_FEED_META = {
    "nvd": {
        "name": "NVD CVE",
        "url":  "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=android&resultsPerPage=20&cvssV3Severity=HIGH",
    },
    "asb": {
        "name": "Android Security Bulletin",
        "url":  "https://source.android.com/docs/security/bulletin/",
    },
    "owasp": {
        "name": "OWASP Mobile Top 10",
        "url":  "https://owasp.org/www-project-mobile-top-10/",
    },
    "hackerone": {
        "name": "HackerOne Android Disclosures",
        "url":  "https://hackerone.com/hacktivity?querystring=android&disclosed_only=true",
    },
    "github": {
        "name": "GitHub Advisory Database",
        "url":  "https://api.github.com/advisories?ecosystem=maven&per_page=20",
    },
}

@app.route("/api/intel/sources-sync", methods=["POST"])
def api_intel_sources_sync():
    """
    Sync detection patterns from security blog RSS feeds — no AI required.
    Uses ThreatIntelUpdater (keyword/regex extraction) and imports results directly.
    """
    import threading as _th

    try:
        from msra.crawler.updater import ThreatIntelUpdater, UpdateConfig
        from msra.crawler.sources import PatternApprovalManager
        from pathlib import Path as _Path
        import datetime as _dt

        data_dir = _Path(__file__).parent / "data"
        cfg      = UpdateConfig(
            enable_hackerone=True,
            enable_blogs=True,
            max_blog_articles_per_source=5,
            max_hackerone_reports=20,
            auto_approve_enabled=True,
            auto_approve_threshold=0.0,   # accept all extracted patterns
            data_dir=data_dir,
        )
        updater = ThreatIntelUpdater(config=cfg)
        result  = updater.update(force=True, quiet=True)

        # Now import any pending/approved patterns directly into user_rules.
        # The updater writes to data_dir/"data"/"crawled"/<subdir>/*.json
        # We walk all subdirectories recursively to find every crawled pattern file.
        crawled_root = data_dir / "data" / "crawled"
        added = 0
        imported_titles: list = []

        all_existing    = rules_api.get_all_rules()
        existing_ids    = {r.get("id") for r in all_existing}
        # Map title (lowercase) → existing rule dict for update checks
        existing_by_title = {r.get("title", "").strip().lower(): r for r in all_existing}
        updated = 0

        for pf in sorted(crawled_root.rglob("*.json")) if crawled_root.exists() else []:
            try:
                p = json.loads(pf.read_text())
                rule_id = p.get("id") or p.get("rule_id") or f"crawled-{pf.stem}"
                title   = p.get("title") or p.get("name") or rule_id

                # Crawled files store patterns under "detection"."patterns"
                # Fall back to top-level "patterns" or "detections" for other formats.
                raw_patterns = (
                    p.get("detection", {}).get("patterns")
                    or p.get("patterns")
                    or p.get("detections")
                    or []
                )
                patterns = []
                for det in raw_patterns:
                    pat = det.get("pattern") or det.get("regex", "")
                    if pat:
                        patterns.append({
                            "pattern":    pat,
                            "flags":      det.get("flags", "i"),
                            "file_types": det.get("file_types", [".java", ".kt"]),
                        })
                if not patterns:
                    continue

                meta = p.get("metadata", {})
                rule_data = {
                    "id":           rule_id,
                    "title":        title,
                    "severity":     p.get("severity", "Medium"),
                    "category":     p.get("category", "Other"),
                    "description":  p.get("description", ""),
                    "attack_path":  p.get("attack_path", ""),
                    "remediation":  p.get("remediation", ""),
                    "patterns":     patterns,
                    "cwe":          meta.get("cwe", p.get("cwe", [])),
                    "cve":          meta.get("cve", p.get("cve", [])),
                    "references":   meta.get("references", p.get("references", [])),
                    "tags":         list({*p.get("tags", []), "crawled"}),
                    "confidence":   meta.get("confidence", "medium"),
                }

                title_key = title.strip().lower()

                if rule_id in existing_ids:
                    # Exact ID match — check if patterns changed and update if so
                    existing = next((r for r in all_existing if r.get("id") == rule_id), None)
                    if existing and existing.get("source") == "custom":
                        old_pats = {p2.get("pattern", "") for p2 in existing.get("patterns", [])}
                        new_pats = {p2.get("pattern", "") for p2 in patterns}
                        if old_pats != new_pats:
                            rules_api.update_custom_rule(rule_id, rule_data)
                            updated += 1
                    continue

                if title_key in existing_by_title:
                    # Same title, different ID — update patterns if rule is custom/crawled
                    existing = existing_by_title[title_key]
                    if existing.get("source") == "custom":
                        old_pats = {p2.get("pattern", "") for p2 in existing.get("patterns", [])}
                        new_pats = {p2.get("pattern", "") for p2 in patterns}
                        if old_pats != new_pats:
                            rules_api.update_custom_rule(existing["id"], rule_data)
                            updated += 1
                    # Either updated or it's a builtin with same title — don't create duplicate
                    continue

                # New rule — create it
                rules_api.create_custom_rule(rule_data)
                added += 1
                existing_ids.add(rule_id)
                existing_by_title[title_key] = rule_data
                imported_titles.append(title)
            except Exception:
                pass

        # Build a log summary
        log_lines = []
        for src_name, stats in result.source_stats.items():
            art = getattr(stats, "articles_fetched", 0)
            found = getattr(stats, "patterns_found", 0)
            log_lines.append(f"{'✓' if art>0 else '○'} {src_name}: {art} articles, {found} patterns")

        source_details = {}
        for src_name, stats in result.source_stats.items():
            source_details[src_name] = {
                "articles": getattr(stats, "articles_fetched", 0),
                "found":    getattr(stats, "patterns_found", 0),
                "error":    getattr(stats, "errors", [""])[0] if getattr(stats, "errors", []) else "",
            }

        # Total crawled rules already in the system
        total_crawled = sum(
            1 for r in rules_api.get_all_rules()
            if "crawled" in r.get("tags", [])
        )

        return jsonify({
            "success":        True,
            "sources":        len(result.source_stats),
            "found":          result.patterns_found,
            "added":          added,
            "updated":        updated,
            "total_crawled":  total_crawled,
            "log":            "\n".join(log_lines),
            "source_details": source_details,
            "imported":       imported_titles[:20],
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/intel/feed-sync", methods=["POST"])
def api_intel_feed_sync():
    """Fetch an intelligence feed, use Claude to derive rules, import new ones."""
    if not ANTHROPIC_API_KEY:
        return jsonify({"error": "ANTHROPIC_API_KEY not configured"}), 400

    data    = request.get_json(force=True, silent=True) or {}
    feed_id = (data.get("feed") or "").strip()
    if feed_id not in _FEED_META:
        return jsonify({"error": f"Unknown feed: {feed_id}"}), 400

    meta = _FEED_META[feed_id]
    url  = meta["url"]

    # ── 1. Fetch feed ───────────────────────────────────────────────────
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 MSRA-Intel/1.0",
            "Accept": "application/json, text/html, */*",
        })
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read(300_000)
    except Exception as e:
        return jsonify({"error": f"Could not fetch {meta['name']}: {e}"}), 400

    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        text = raw.decode("latin-1", errors="replace")

    # Strip HTML if not JSON
    if not text.lstrip().startswith(("{", "[")):
        text = re.sub(r'<(script|style)[^>]*>[\s\S]*?</(script|style)>', ' ', text, flags=re.IGNORECASE)
        text = re.sub(r'<[^>]+>', ' ', text)
        text = re.sub(r'\s+', ' ', text).strip()

    text = text[:15000]

    # ── 2. Ask Claude to derive rules ───────────────────────────────────
    prompt = f"""You are a senior Android security researcher reviewing data from the {meta['name']} feed.
Extract actionable Android static analysis detection rules from the following content.

Return ONLY a JSON array of rule objects with this schema:
{{
  "id": "unique-kebab-case-id",
  "title": "Short descriptive title",
  "severity": "Critical|High|Medium|Low|Info",
  "category": "WebView|OWASP-M1-Credentials|OWASP-M4-InputValidation|OWASP-M5-Communication|OWASP-M9-DataStorage|OWASP-M10-Cryptography|Component-Exposure|Intent-DeepLink|Permission|Logging|Other",
  "description": "2-3 sentence description",
  "attack_path": "Attack scenario",
  "remediation": "Fix guidance",
  "detection_type": "regex",
  "patterns": [{{"pattern": "(?i)regex_here", "flags": "i", "file_types": [".java", ".kt"]}}],
  "cwe": ["CWE-XXX"],
  "tags": ["android", "{feed_id}"]
}}

Return [] if no useful Android patterns can be derived.

FEED CONTENT:
{text}"""

    try:
        import urllib.request as _ur
        api_payload = json.dumps({
            "model": CLAUDE_MODEL,
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": prompt}]
        }).encode()
        api_req = _ur.Request(
            "https://api.anthropic.com/v1/messages",
            data=api_payload,
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            method="POST"
        )
        with _ur.urlopen(api_req, timeout=60) as resp:
            api_resp = json.loads(resp.read())
        raw_text = api_resp["content"][0]["text"].strip()
    except Exception as e:
        return jsonify({"error": f"Claude API error: {e}"}), 500

    raw_text = re.sub(r'^```(?:json)?\s*', '', raw_text, flags=re.MULTILINE)
    raw_text = re.sub(r'\s*```$', '', raw_text, flags=re.MULTILINE)
    try:
        rules = json.loads(raw_text)
        if not isinstance(rules, list):
            rules = []
    except Exception:
        m = re.search(r'\[[\s\S]*\]', raw_text)
        try:
            rules = json.loads(m.group()) if m else []
        except Exception:
            rules = []

    # ── 3. Import new rules (skip if ID already exists) ─────────────────
    added = 0
    for rule in rules:
        try:
            rules_api.create_custom_rule(rule)
            added += 1
        except ValueError:
            pass  # duplicate ID — skip
        except Exception:
            pass

    return jsonify({"added": added, "total_suggested": len(rules)})


# ── PDF Export ───────────────────────────────────────────────────────────

@app.route("/api/scans/<scan_id>/export/pdf")
def export_pdf(scan_id: str):
    """Generate and stream a PDF report for a scan."""
    scan_dir = _scan_dir(scan_id)
    if not scan_dir.exists() and not _db.get_scan(scan_id):
        return jsonify({"error": "Scan not found"}), 404

    data = _load_findings_with_triage(scan_id)
    if data is None:
        return jsonify({"error": "Findings not available for this scan"}), 404

    findings = data.get("findings", [])

    # Load scan metadata from DB (most up-to-date) + summary.json fallback
    meta = _db.get_scan(scan_id) or {}
    try:
        summary_path = scan_dir / "summary.json"
        if summary_path.exists():
            file_meta = json.loads(summary_path.read_text())
            meta = {**file_meta, **meta}
    except Exception:
        pass

    try:
        from msra.pdf_export import generate_pdf_report
        pdf_path = scan_dir / "report.pdf"
        generate_pdf_report(
            findings=findings,
            output_path=str(pdf_path),
            metadata={
                "package":         meta.get("package", "unknown"),
                "apk":             meta.get("apk", ""),
                "scan_id":         scan_id,
                "severity_counts": meta.get("severity_counts", {}),
            },
        )
        pkg = meta.get("package", scan_id)
        return send_file(
            str(pdf_path),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"{pkg}_msra.pdf",
        )
    except ImportError as e:
        return jsonify({"error": str(e)}), 503
    except Exception as e:
        return jsonify({"error": f"PDF generation failed: {e}"}), 500


# ── Scan Management ───────────────────────────────────────────────────────

@app.route("/api/scans/<scan_id>", methods=["DELETE"])
def api_delete_scan(scan_id: str):
    """Delete a scan and all its data.

    Returns 409 Conflict if the scan is still actively running, to prevent
    destroying the output directory of a live scan worker thread.
    """
    scan_dir = _scan_dir(scan_id)
    scan_rec = _db.get_scan(scan_id)
    if not scan_dir.exists() and not scan_rec:
        return jsonify({"error": "Scan not found"}), 404

    # Refuse to delete a scan that is actively running — the worker thread
    # still holds references to files inside scan_dir and will crash/stop
    # if we rmtree it beneath it.
    active_statuses = {"queued", "decompiling", "scanning", "reporting"}
    current_status = (scan_rec or {}).get("status", "")
    if current_status in active_statuses:
        return jsonify({
            "error": f"Cannot delete a scan that is currently '{current_status}'. "
                     "Wait for it to finish or reach an error state first."
        }), 409

    shutil.rmtree(scan_dir, ignore_errors=True)
    _db.delete_scan(scan_id)
    return jsonify({"success": True})


# ── Main ─────────────────────────────────────────────────────────────────

# ── DB init (runs at import time so dev auto-reload works too) ────────────
_db.init_db()
_db.migrate_from_files(REPORTS_FOLDER)

# ── Reset stale dynamic jobs left in "running" state from a previous session ──
try:
    import sqlite3 as _sqlite3
    with _sqlite3.connect(str(_db.DB_PATH)) as _conn:
        _conn.execute(
            "UPDATE dynamic_jobs SET status='error', message='Interrupted by server restart' "
            "WHERE status='running'"
        )
        _conn.commit()
except Exception:
    pass


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="MSRA — Mobile Security Review Assistant")
    p.add_argument("--port", type=int, default=int(os.environ.get("PORT", 5001)))
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--no-semgrep", action="store_true",
                   help="Disable optional Semgrep analysis pass")
    args = p.parse_args()

    if args.no_semgrep:
        os.environ["MSRA_NO_SEMGREP"] = "1"

    if not ANTHROPIC_API_KEY:
        print("[!] ANTHROPIC_API_KEY not set — Claude PoC generation will prompt for key per request.")
    print(f"[+] MSRA dashboard → http://localhost:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)
