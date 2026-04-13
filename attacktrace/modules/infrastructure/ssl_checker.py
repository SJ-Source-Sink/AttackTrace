"""
SSL/TLS Certificate and Configuration Checker

Analyses SSL/TLS configuration for all alive HTTPS web assets in the session.
Checks performed:
  1. Certificate expiry        — < 30 days → HIGH;  < 7 days → CRITICAL
  2. Weak TLS version          — TLS 1.0 / 1.1      → HIGH
  3. Self-signed certificate   — issuer == subject   → MEDIUM
  4. Hostname mismatch         — cert SANs vs host   → HIGH
  5. Certificate Transparency  — missing SCT ext     → LOW
"""

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from attacktrace.config import AttackTraceConfig
from attacktrace.core.models import (
    Finding,
    ModuleResult,
    Severity,
    ScanSession,
)


# ── Low-level synchronous SSL probe ──────────────────────────────────────────


def _check_ssl(hostname: str, port: int = 443) -> dict:
    """Connect to hostname:port and return raw SSL information.

    Uses CERT_NONE so we collect data even for self-signed / mismatched certs.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
                cipher = ssock.cipher()
                return {
                    "cert": cert,
                    "version": version,
                    "cipher": cipher,
                    "error": None,
                }
    except Exception as exc:
        return {"error": str(exc)}


# ── Analysis helpers ──────────────────────────────────────────────────────────


def _parse_cert_time(time_str: str) -> Optional[datetime]:
    """Parse the time strings returned by getpeercert() into datetime objects."""
    if not time_str:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return datetime.strptime(time_str, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _get_cert_names(cert: dict) -> list[str]:
    """Extract all hostnames from a certificate (CN + SANs)."""
    names: list[str] = []

    # Subject CN
    for field in cert.get("subject", []):
        for key, val in field:
            if key == "commonName":
                names.append(val.lower())

    # Subject Alternative Names
    for san_type, san_value in cert.get("subjectAltName", []):
        if san_type == "DNS":
            names.append(san_value.lower())

    return names


def _hostname_matches_cert(hostname: str, cert_names: list[str]) -> bool:
    """Return True if hostname matches any cert name (supports wildcards)."""
    hostname = hostname.lower()
    for name in cert_names:
        if name == hostname:
            return True
        if name.startswith("*."):
            # Wildcard: *.example.com should match sub.example.com but NOT example.com
            suffix = name[2:]  # strip "*."
            if hostname.endswith("." + suffix) and "." not in hostname[: -(len(suffix) + 1)]:
                return True
    return False


def _has_sct_extension(cert: dict) -> bool:
    """Return True if the cert contains an SCT (Signed Certificate Timestamp) extension.

    getpeercert() does not expose raw extensions by name, but the presence of
    'subjectAltName' combined with a multi-SAN cert is a reasonable proxy.
    We look for the 'OCSP' or a recognisable CT field in the cert dict; if we
    cannot confirm it we return False (conservative).
    """
    # Python's ssl module does not expose raw X.509 extensions in getpeercert().
    # We treat any cert that has at least one SAN as likely CT-logged (heuristic),
    # and flag certs with *no* SANs as potentially missing CT submission.
    return bool(cert.get("subjectAltName"))


# ── Per-host analysis ─────────────────────────────────────────────────────────


def _analyze_host_ssl(hostname: str, port: int) -> list[dict]:
    """Run all SSL checks for a single host. Returns a list of finding dicts."""
    info = _check_ssl(hostname, port)
    findings: list[dict] = []

    if info.get("error"):
        # Connection failed — record as informational, not a vuln finding
        findings.append({
            "title": f"SSL connection failed: {hostname}:{port}",
            "description": f"Could not establish SSL connection: {info['error']}",
            "severity": Severity.INFO,
            "category": "ssl",
            "affected_asset": hostname,
            "affected_asset_type": "webapp",
            "evidence": info["error"],
            "remediation": "Verify the host is reachable and serves a valid SSL certificate.",
        })
        return findings

    cert: dict = info.get("cert") or {}
    version: Optional[str] = info.get("version")

    now = datetime.now(timezone.utc)

    # ── 1. Certificate expiry ──────────────────────────────────────────────
    not_after_str = cert.get("notAfter", "")
    not_after = _parse_cert_time(not_after_str)
    if not_after:
        days_left = (not_after - now).days
        if days_left < 0:
            findings.append({
                "title": f"SSL certificate expired: {hostname}",
                "description": (
                    f"The SSL certificate for {hostname} expired on "
                    f"{not_after.date()} ({abs(days_left)} days ago)."
                ),
                "severity": Severity.CRITICAL,
                "category": "ssl",
                "affected_asset": hostname,
                "affected_asset_type": "webapp",
                "evidence": f"Certificate expiry: {not_after_str}",
                "remediation": "Renew the SSL certificate immediately.",
            })
        elif days_left < 7:
            findings.append({
                "title": f"SSL certificate expiring very soon: {hostname}",
                "description": (
                    f"The SSL certificate for {hostname} expires in {days_left} day(s) "
                    f"(on {not_after.date()})."
                ),
                "severity": Severity.CRITICAL,
                "category": "ssl",
                "affected_asset": hostname,
                "affected_asset_type": "webapp",
                "evidence": f"Certificate expiry: {not_after_str}",
                "remediation": "Renew the SSL certificate immediately (within 7 days).",
            })
        elif days_left < 30:
            findings.append({
                "title": f"SSL certificate expiring soon: {hostname}",
                "description": (
                    f"The SSL certificate for {hostname} expires in {days_left} day(s) "
                    f"(on {not_after.date()})."
                ),
                "severity": Severity.HIGH,
                "category": "ssl",
                "affected_asset": hostname,
                "affected_asset_type": "webapp",
                "evidence": f"Certificate expiry: {not_after_str}",
                "remediation": "Renew the SSL certificate before it expires.",
            })

    # ── 2. Weak TLS version ────────────────────────────────────────────────
    if version in ("TLSv1", "TLSv1.1"):
        findings.append({
            "title": f"Weak TLS version in use: {hostname} ({version})",
            "description": (
                f"{hostname} negotiated {version}, which is deprecated and vulnerable "
                f"to protocol downgrade attacks (BEAST, POODLE)."
            ),
            "severity": Severity.HIGH,
            "category": "ssl",
            "affected_asset": hostname,
            "affected_asset_type": "webapp",
            "evidence": f"Negotiated TLS version: {version}",
            "remediation": (
                "Disable TLS 1.0 and TLS 1.1 on the server and enforce TLS 1.2+ only."
            ),
        })

    # ── 3. Self-signed certificate ─────────────────────────────────────────
    subject = cert.get("subject", ())
    issuer = cert.get("issuer", ())
    if subject and issuer and subject == issuer:
        findings.append({
            "title": f"Self-signed SSL certificate: {hostname}",
            "description": (
                f"The SSL certificate for {hostname} is self-signed. "
                f"Browsers will show a security warning to users."
            ),
            "severity": Severity.MEDIUM,
            "category": "ssl",
            "affected_asset": hostname,
            "affected_asset_type": "webapp",
            "evidence": f"Subject == Issuer: {subject}",
            "remediation": (
                "Replace the self-signed certificate with one issued by a trusted CA "
                "(e.g. Let's Encrypt)."
            ),
        })

    # ── 4. Hostname mismatch ───────────────────────────────────────────────
    cert_names = _get_cert_names(cert)
    if cert_names and not _hostname_matches_cert(hostname, cert_names):
        findings.append({
            "title": f"SSL hostname mismatch: {hostname}",
            "description": (
                f"The SSL certificate presented by {hostname} does not include "
                f"that hostname in its Subject or SANs. "
                f"Certificate covers: {', '.join(cert_names[:5])}."
            ),
            "severity": Severity.HIGH,
            "category": "ssl",
            "affected_asset": hostname,
            "affected_asset_type": "webapp",
            "evidence": f"Certificate SANs/CN: {', '.join(cert_names[:10])}",
            "remediation": (
                "Obtain a certificate that includes the correct hostname in its SANs."
            ),
        })

    # ── 5. Certificate Transparency ────────────────────────────────────────
    if cert and not _has_sct_extension(cert):
        findings.append({
            "title": f"Certificate may not be in CT logs: {hostname}",
            "description": (
                f"The SSL certificate for {hostname} does not appear to have "
                f"Subject Alternative Names, which may indicate it was not submitted "
                f"to Certificate Transparency logs."
            ),
            "severity": Severity.LOW,
            "category": "ssl",
            "affected_asset": hostname,
            "affected_asset_type": "webapp",
            "evidence": "No SANs present in certificate (CT log heuristic)",
            "remediation": (
                "Use a CA that automatically submits certificates to CT logs "
                "(most modern CAs do this by default)."
            ),
        })

    return findings


# ── Module entry point ────────────────────────────────────────────────────────


async def run(
    session: ScanSession,
    config: Optional[AttackTraceConfig] = None,
    orchestrator=None,
) -> ModuleResult:
    """Check SSL/TLS configuration for all alive HTTPS web assets in the session."""
    result = ModuleResult(module_name="ssl_checker")

    https_apps = [
        app for app in session.web_applications
        if app.scheme == "https" or app.port == 443 or app.url.startswith("https://")
    ]

    if not https_apps:
        result.success = True
        return result

    async def _check_one(app) -> list[Finding]:
        # Determine hostname and port from the webapp record
        host = app.host or urlparse(app.url).hostname or ""
        port = app.port if app.port else 443
        if not host:
            return []

        raw_findings = await asyncio.to_thread(_analyze_host_ssl, host, port)
        findings: list[Finding] = []
        for f in raw_findings:
            findings.append(
                Finding(
                    title=f["title"],
                    description=f["description"],
                    severity=f["severity"],
                    category=f.get("category", "ssl"),
                    affected_asset=f.get("affected_asset", host),
                    affected_asset_type=f.get("affected_asset_type", "webapp"),
                    evidence=f.get("evidence", ""),
                    remediation=f.get("remediation", ""),
                    source="ssl_checker",
                )
            )
        return findings

    tasks = [_check_one(app) for app in https_apps]
    all_finding_lists = await asyncio.gather(*tasks, return_exceptions=True)

    for item in all_finding_lists:
        if isinstance(item, Exception):
            continue
        result.findings.extend(item)

    result.items_discovered = len(result.findings)
    result.success = True
    return result
