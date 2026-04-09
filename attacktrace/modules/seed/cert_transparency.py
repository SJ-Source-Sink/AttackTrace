"""
Certificate Transparency Log discovery module.

Uses crt.sh to discover domains and subdomains from CT logs.
"""

import asyncio
import re
from datetime import datetime
from typing import Optional

import httpx

from attacktrace.config import AttackTraceConfig
from attacktrace.core.models import (
    ModuleResult,
    Subdomain,
    Certificate,
    ScanSession,
)


CRT_SH_URL = "https://crt.sh/"


async def query_crtsh(domain: str, timeout: int = 30) -> list[dict]:
    """
    Query crt.sh for certificates containing the domain.

    Args:
        domain: Domain to search for
        timeout: Request timeout in seconds

    Returns:
        List of certificate records
    """
    results = []

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        try:
            # Query crt.sh JSON API
            response = await client.get(
                CRT_SH_URL,
                params={
                    "q": f"%.{domain}",
                    "output": "json",
                },
            )

            if response.status_code == 200:
                try:
                    results = response.json()
                except Exception:
                    # Sometimes returns empty or invalid JSON
                    pass

        except httpx.TimeoutException:
            pass
        except Exception:
            pass

    return results


def extract_domains_from_cert(cert_data: dict) -> set[str]:
    """Extract domain names from certificate data."""
    domains = set()

    # Get name_value which contains the CN and SANs
    name_value = cert_data.get("name_value", "")

    # Split by newlines and filter
    for name in name_value.split("\n"):
        name = name.strip().lower()
        if name and not name.startswith("*"):
            # Validate it looks like a domain
            if re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$", name):
                domains.add(name)
        elif name.startswith("*."):
            # Wildcard - add the base domain
            base = name[2:]
            if re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$", base):
                domains.add(base)

    # Also check common_name
    common_name = cert_data.get("common_name", "").strip().lower()
    if common_name and not common_name.startswith("*"):
        if re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$", common_name):
            domains.add(common_name)

    return domains


def parse_certificate(cert_data: dict, parent_domain: str) -> Optional[Certificate]:
    """Parse certificate data into a Certificate object."""
    try:
        cert = Certificate(
            serial_number=str(cert_data.get("serial_number", "")),
            subject=cert_data.get("common_name", ""),
            issuer=cert_data.get("issuer_name", ""),
            san=list(extract_domains_from_cert(cert_data)),
        )

        # Parse dates
        not_before = cert_data.get("not_before")
        not_after = cert_data.get("not_after")

        if not_before:
            try:
                cert.not_before = datetime.fromisoformat(not_before.replace("Z", "+00:00"))
            except Exception:
                pass

        if not_after:
            try:
                cert.not_after = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
                cert.is_expired = cert.not_after < datetime.utcnow()
            except Exception:
                pass

        return cert

    except Exception:
        return None


async def run(
    session: ScanSession,
    config: AttackTraceConfig,
    orchestrator,
) -> ModuleResult:
    """
    Run certificate transparency discovery.

    Args:
        session: Current scan session
        config: AttackTrace configuration
        orchestrator: Orchestrator instance

    Returns:
        ModuleResult with discovered subdomains and certificates
    """
    result = ModuleResult(
        module_name="cert_transparency",
        started_at=datetime.utcnow(),
    )

    discovered_domains: set[str] = set()
    certificates: list[Certificate] = []

    # Get domains to search
    search_domains = set(session.target_domains)

    # Also search company name variations if provided
    if session.target_company:
        # Create domain-like search terms from company name
        company_slug = session.target_company.lower()
        company_slug = re.sub(r"[^a-z0-9]", "", company_slug)
        if company_slug:
            search_domains.add(company_slug + ".com")
            search_domains.add(company_slug + ".net")
            search_domains.add(company_slug + ".org")

    # Query crt.sh for each domain
    for domain in search_domains:
        try:
            certs = await query_crtsh(domain, timeout=config.scan.timeout)

            for cert_data in certs:
                # Extract domains from certificate
                cert_domains = extract_domains_from_cert(cert_data)
                discovered_domains.update(cert_domains)

                # Parse certificate
                cert = parse_certificate(cert_data, domain)
                if cert and cert.serial_number:
                    # Avoid duplicates
                    if not any(c.serial_number == cert.serial_number for c in certificates):
                        certificates.append(cert)

            # Rate limiting
            await asyncio.sleep(0.5)

        except Exception:
            continue

    # Create subdomain objects
    for fqdn in discovered_domains:
        # Determine parent domain
        parent = None
        for target_domain in session.target_domains:
            if fqdn.endswith("." + target_domain) or fqdn == target_domain:
                parent = target_domain
                break

        if parent:
            subdomain = Subdomain(
                fqdn=fqdn,
                parent_domain=parent,
                source="crt.sh",
            )
            result.subdomains.append(subdomain)

    result.certificates = certificates
    result.items_discovered = len(result.subdomains) + len(certificates)
    result.success = True
    result.completed_at = datetime.utcnow()

    return result
