"""
HTTP probing module.

Probes discovered hosts for web applications and gathers:
- HTTP response data
- Technology fingerprints
- Security headers
- SSL/TLS information
"""

import asyncio
import hashlib
import re
import ssl
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

import httpx

from attacktrace.config import AttackTraceConfig
from attacktrace.core.models import (
    ModuleResult,
    WebApplication,
    Technology,
    Certificate,
    Finding,
    Severity,
    ScanSession,
)


# Import enhanced tech signatures
from attacktrace.modules.web.tech_signatures import detect_technologies as detect_tech_enhanced


# Security headers to check
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]


async def probe_url(
    url: str,
    timeout: float = 10.0,
    follow_redirects: bool = True,
    user_agent: str = "",
) -> Optional[dict]:
    """
    Probe a URL and collect response data.

    Returns:
        Dictionary with response data or None
    """
    headers = {
        "User-Agent": user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=follow_redirects,
            verify=False,  # Allow self-signed certs
        ) as client:
            response = await client.get(url, headers=headers)

            # Get final URL after redirects
            final_url = str(response.url)

            # Extract title
            title = ""
            title_match = re.search(r"<title[^>]*>([^<]+)</title>", response.text, re.IGNORECASE)
            if title_match:
                title = title_match.group(1).strip()

            return {
                "url": url,
                "final_url": final_url,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.text[:50000],  # Limit body size
                "content_length": len(response.content),
                "content_type": response.headers.get("content-type", ""),
                "title": title,
                "response_time": response.elapsed.total_seconds() * 1000,
            }

    except httpx.ConnectTimeout:
        return None
    except httpx.ReadTimeout:
        return None
    except httpx.ConnectError:
        return None
    except ssl.SSLError:
        return None
    except Exception:
        return None


def detect_technologies(headers: dict, body: str, cookies: dict = None, url: str = "") -> list[Technology]:
    """Detect technologies from response headers and body using enhanced signatures."""
    # Use enhanced detection from tech_signatures module
    detected = detect_tech_enhanced(headers, body, cookies, url)

    # Convert to Technology model objects
    technologies = []
    for tech in detected:
        technologies.append(Technology(
            name=tech["name"],
            version=tech.get("version", ""),
            category=tech.get("category", "unknown"),
            confidence=tech.get("confidence", 80),
        ))

    return technologies


def check_security_headers(headers: dict, url: str) -> list[Finding]:
    """Check for missing security headers."""
    findings = []

    headers_lower = {k.lower(): v for k, v in headers.items()}

    missing_headers = []
    for header in SECURITY_HEADERS:
        if header.lower() not in headers_lower:
            missing_headers.append(header)

    if missing_headers:
        finding = Finding(
            title=f"Missing security headers on {url}",
            description=f"The following security headers are missing: {', '.join(missing_headers)}",
            severity=Severity.LOW,
            category="misconfiguration",
            affected_asset=url,
            affected_asset_type="webapp",
            evidence=f"Missing: {', '.join(missing_headers)}",
            source="http_prober",
        )
        findings.append(finding)

    # Check for specific issues
    if "strict-transport-security" not in headers_lower and url.startswith("https"):
        finding = Finding(
            title=f"Missing HSTS header on {url}",
            description="HTTP Strict Transport Security header is not set. This allows downgrade attacks.",
            severity=Severity.MEDIUM,
            category="misconfiguration",
            affected_asset=url,
            affected_asset_type="webapp",
            source="http_prober",
        )
        findings.append(finding)

    return findings


def check_interesting_findings(response_data: dict) -> list[Finding]:
    """Check for interesting findings in the response."""
    findings = []
    url = response_data["url"]
    body = response_data.get("body", "")
    headers = response_data.get("headers", {})

    # Check for debug mode indicators
    debug_patterns = [
        (r"APP_DEBUG\s*=\s*true", "Laravel debug mode enabled"),
        (r"DEBUG\s*=\s*True", "Django debug mode enabled"),
        (r"<b>Warning</b>.*on line", "PHP warnings displayed"),
        (r"<b>Notice</b>.*on line", "PHP notices displayed"),
        (r"Traceback \(most recent call last\)", "Python traceback exposed"),
        (r"Exception in thread", "Java exception exposed"),
        (r"<title>phpinfo\(\)</title>", "phpinfo() exposed"),
    ]

    for pattern, description in debug_patterns:
        if re.search(pattern, body, re.IGNORECASE):
            finding = Finding(
                title=f"{description} on {url}",
                description=f"Debug information is exposed: {description}",
                severity=Severity.HIGH,
                category="information_disclosure",
                affected_asset=url,
                affected_asset_type="webapp",
                source="http_prober",
            )
            findings.append(finding)

    # Check for directory listing
    if re.search(r"Index of /|Directory listing for", body, re.IGNORECASE):
        finding = Finding(
            title=f"Directory listing enabled on {url}",
            description="Directory listing is enabled, exposing file structure",
            severity=Severity.MEDIUM,
            category="misconfiguration",
            affected_asset=url,
            affected_asset_type="webapp",
            source="http_prober",
        )
        findings.append(finding)

    # Check for exposed configuration files
    config_patterns = [
        (r"DB_PASSWORD|DATABASE_URL|MYSQL_PWD", "Database credentials potentially exposed"),
        (r"AWS_ACCESS_KEY|aws_secret", "AWS credentials potentially exposed"),
        (r"PRIVATE.KEY|-----BEGIN RSA PRIVATE KEY", "Private key potentially exposed"),
    ]

    for pattern, description in config_patterns:
        if re.search(pattern, body, re.IGNORECASE):
            finding = Finding(
                title=f"{description} on {url}",
                description=f"Sensitive information potentially exposed: {description}",
                severity=Severity.CRITICAL,
                category="information_disclosure",
                affected_asset=url,
                affected_asset_type="webapp",
                source="http_prober",
            )
            findings.append(finding)

    return findings


async def get_ssl_certificate(host: str, port: int = 443) -> Optional[Certificate]:
    """Get SSL certificate information."""
    try:
        # Create SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=context),
            timeout=10.0,
        )

        # Get certificate
        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj:
            cert_der = ssl_obj.getpeercert(binary_form=True)
            cert_dict = ssl_obj.getpeercert()

            if cert_dict:
                # Parse certificate
                subject = dict(x[0] for x in cert_dict.get("subject", []))
                issuer = dict(x[0] for x in cert_dict.get("issuer", []))

                # Get SANs
                san = []
                for type_name, value in cert_dict.get("subjectAltName", []):
                    if type_name == "DNS":
                        san.append(value)

                # Calculate fingerprint
                fingerprint = hashlib.sha256(cert_der).hexdigest() if cert_der else ""

                cert = Certificate(
                    subject=subject.get("commonName", ""),
                    issuer=issuer.get("commonName", ""),
                    san=san,
                    fingerprint_sha256=fingerprint,
                )

                # Parse dates
                not_before = cert_dict.get("notBefore")
                not_after = cert_dict.get("notAfter")

                if not_after:
                    try:
                        from email.utils import parsedate_to_datetime
                        cert.not_after = parsedate_to_datetime(not_after)
                        cert.is_expired = cert.not_after < datetime.now(cert.not_after.tzinfo)
                    except Exception:
                        pass

                writer.close()
                await writer.wait_closed()
                return cert

        writer.close()
        await writer.wait_closed()

    except Exception:
        pass

    return None


async def run(
    session: ScanSession,
    config: AttackTraceConfig,
    orchestrator,
) -> ModuleResult:
    """
    Run HTTP probing on discovered hosts.

    Args:
        session: Current scan session
        config: AttackTrace configuration
        orchestrator: Orchestrator instance

    Returns:
        ModuleResult with web application data
    """
    result = ModuleResult(
        module_name="http_prober",
        started_at=datetime.utcnow(),
    )

    # Collect URLs to probe
    urls_to_probe: set[str] = set()

    # Add URLs from subdomains
    for subdomain in session.subdomains:
        urls_to_probe.add(f"https://{subdomain.fqdn}")
        urls_to_probe.add(f"http://{subdomain.fqdn}")

    # Add URLs from domains
    for domain in session.domains:
        urls_to_probe.add(f"https://{domain.fqdn}")
        urls_to_probe.add(f"http://{domain.fqdn}")

    # Add URLs from IPs with HTTP ports
    http_ports = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000]
    for ip in session.ip_addresses:
        for port in ip.ports:
            if port.number in http_ports or "http" in port.service.name.lower():
                scheme = "https" if port.number in [443, 8443] else "http"
                urls_to_probe.add(f"{scheme}://{ip.address}:{port.number}")

    if not urls_to_probe:
        result.success = True
        result.completed_at = datetime.utcnow()
        return result

    # Probe URLs concurrently
    semaphore = asyncio.Semaphore(config.scan.threads)

    async def probe_with_semaphore(url: str):
        async with semaphore:
            return await probe_url(
                url,
                timeout=config.scan.timeout,
                follow_redirects=config.modules.web.follow_redirects,
                user_agent=config.modules.web.user_agent,
            )

    tasks = [probe_with_semaphore(url) for url in urls_to_probe]
    responses = await asyncio.gather(*tasks, return_exceptions=True)

    # Process responses
    seen_urls: set[str] = set()

    for response_data in responses:
        if not isinstance(response_data, dict):
            continue

        url = response_data["url"]
        final_url = response_data.get("final_url", url)

        # Avoid duplicates
        if final_url in seen_urls:
            continue
        seen_urls.add(final_url)

        # Parse URL
        parsed = urlparse(final_url)

        # Detect technologies
        technologies = detect_technologies(
            response_data.get("headers", {}),
            response_data.get("body", ""),
            cookies=None,  # Could extract cookies from headers if needed
            url=final_url,
        )

        # Create web application object
        webapp = WebApplication(
            url=url,
            scheme=parsed.scheme,
            host=parsed.hostname or "",
            port=parsed.port or (443 if parsed.scheme == "https" else 80),
            path=parsed.path or "/",
            title=response_data.get("title", ""),
            status_code=response_data.get("status_code", 0),
            content_length=response_data.get("content_length", 0),
            content_type=response_data.get("content_type", ""),
            redirect_url=final_url if final_url != url else "",
            final_url=final_url,
            technologies=technologies,
            headers=response_data.get("headers", {}),
            response_time_ms=int(response_data.get("response_time", 0)),
            is_alive=True,
            source="http_prober",
        )

        # Get SSL certificate for HTTPS
        if parsed.scheme == "https":
            cert = await get_ssl_certificate(
                parsed.hostname,
                parsed.port or 443,
            )
            if cert:
                webapp.certificate = cert
                result.certificates.append(cert)

        result.web_applications.append(webapp)

        # Check security headers
        findings = check_security_headers(response_data.get("headers", {}), final_url)
        result.findings.extend(findings)

        # Check for interesting findings
        interesting_findings = check_interesting_findings(response_data)
        result.findings.extend(interesting_findings)

    result.items_discovered = len(result.web_applications)
    result.success = True
    result.completed_at = datetime.utcnow()

    return result
