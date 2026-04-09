"""
Chaos by ProjectDiscovery integration.

Provides:
- Massive subdomain database
- Bug bounty program subdomains
- Regularly updated
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


async def get_subdomains(
    domain: str,
    api_key: str,
    timeout: float = 30.0,
) -> list[str]:
    """
    Get subdomains from Chaos database.
    """
    if not api_key:
        return []

    subdomains = []

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"https://dns.projectdiscovery.io/dns/{domain}/subdomains",
                headers={
                    "Authorization": api_key,
                    "User-Agent": "AttackTrace-Scanner/1.0",
                },
            )

            if response.status_code == 200:
                data = response.json()
                subdomains = data.get("subdomains", [])

    except Exception:
        pass

    return subdomains


async def run(
    session: ScanSession,
    config: AttackTraceConfig,
    orchestrator,
) -> ModuleResult:
    """
    Run Chaos subdomain discovery.
    """
    result = ModuleResult(
        module_name="chaos",
        started_at=datetime.utcnow(),
    )

    api_key = getattr(config.api_keys, 'chaos', None)

    if not api_key:
        result.success = True
        result.completed_at = datetime.utcnow()
        return result

    discovered_subdomains = []

    for domain in session.target_domains:
        subdomains = await get_subdomains(domain, api_key, config.scan.timeout)

        for sub in subdomains:
            fqdn = f"{sub}.{domain}" if not sub.endswith(domain) else sub

            # Check if already known
            if not any(s.fqdn == fqdn for s in session.subdomains):
                subdomain = Subdomain(
                    fqdn=fqdn,
                    parent_domain=domain,
                    source="chaos",
                )
                result.subdomains.append(subdomain)
                discovered_subdomains.append(fqdn)

        await asyncio.sleep(0.5)

    result.items_discovered = len(discovered_subdomains)

    if discovered_subdomains:
        finding = Finding(
            title=f"Chaos discovered {len(discovered_subdomains)} new subdomains",
            description="ProjectDiscovery Chaos database returned additional subdomains.",
            severity=Severity.INFO,
            category="reconnaissance",
            affected_asset=session.target_domains[0],
            affected_asset_type="domain",
            source="chaos",
        )
        result.findings.append(finding)

    result.success = True
    result.completed_at = datetime.utcnow()
    return result
