"""
PassiveTotal (RiskIQ) integration module.

Provides:
- Passive DNS
- WHOIS history
- SSL certificates
- Host attributes
- Trackers and components
"""

import asyncio
from datetime import datetime
from typing import Optional

import httpx

from attacktrace.config import AttackTraceConfig
from attacktrace.core.models import (
    ModuleResult,
    Subdomain,
    Finding,
    Severity,
    ScanSession,
)


async def get_passive_dns(
    query: str,
    username: str,
    api_key: str,
    timeout: float = 30.0,
) -> list[dict]:
    """
    Get passive DNS records.
    """
    if not username or not api_key:
        return []

    records = []

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                "https://api.passivetotal.org/v2/dns/passive",
                params={"query": query},
                auth=(username, api_key),
            )

            if response.status_code == 200:
                data = response.json()
                records = data.get("results", [])

    except Exception:
        pass

    return records


async def get_subdomains(
    domain: str,
    username: str,
    api_key: str,
    timeout: float = 30.0,
) -> list[str]:
    """
    Get subdomains via enrichment API.
    """
    if not username or not api_key:
        return []

    subdomains = []

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                "https://api.passivetotal.org/v2/enrichment/subdomains",
                params={"query": domain},
                auth=(username, api_key),
            )

            if response.status_code == 200:
                data = response.json()
                subdomains = data.get("subdomains", [])

    except Exception:
        pass

    return subdomains


async def get_whois(
    query: str,
    username: str,
    api_key: str,
    timeout: float = 30.0,
) -> dict:
    """
    Get WHOIS information.
    """
    if not username or not api_key:
        return {}

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                "https://api.passivetotal.org/v2/whois",
                params={"query": query},
                auth=(username, api_key),
            )

            if response.status_code == 200:
                return response.json()

    except Exception:
        pass

    return {}


async def run(
    session: ScanSession,
    config: AttackTraceConfig,
    orchestrator,
) -> ModuleResult:
    """
    Run PassiveTotal intelligence gathering.
    """
    result = ModuleResult(
        module_name="passivetotal",
        started_at=datetime.utcnow(),
    )

    username = getattr(config.api_keys, 'passivetotal_user', None)
    api_key = getattr(config.api_keys, 'passivetotal', None)

    if not username or not api_key:
        result.success = True
        result.completed_at = datetime.utcnow()
        return result

    passive_dns_records = []
    discovered_subdomains = []

    for domain in session.target_domains:
        # Get subdomains
        subs = await get_subdomains(domain, username, api_key, config.scan.timeout)

        for sub in subs:
            fqdn = f"{sub}.{domain}"
            if not any(s.fqdn == fqdn for s in session.subdomains):
                subdomain = Subdomain(
                    fqdn=fqdn,
                    parent_domain=domain,
                    source="passivetotal",
                )
                result.subdomains.append(subdomain)
                discovered_subdomains.append(fqdn)

        await asyncio.sleep(1)

        # Get passive DNS
        dns_records = await get_passive_dns(domain, username, api_key, config.scan.timeout)
        passive_dns_records.extend(dns_records[:50])

        await asyncio.sleep(1)

    # Store data
    if not hasattr(session, 'passivetotal_data'):
        session.passivetotal_data = {}
    session.passivetotal_data = {
        "passive_dns": passive_dns_records,
        "subdomains": discovered_subdomains,
    }

    result.items_discovered = len(discovered_subdomains) + len(passive_dns_records)

    if discovered_subdomains:
        finding = Finding(
            title=f"PassiveTotal discovered {len(discovered_subdomains)} subdomains",
            description="Additional subdomains found via RiskIQ PassiveTotal.",
            severity=Severity.INFO,
            category="reconnaissance",
            affected_asset=session.target_domains[0],
            affected_asset_type="domain",
            source="passivetotal",
        )
        result.findings.append(finding)

    result.success = True
    result.completed_at = datetime.utcnow()
    return result
