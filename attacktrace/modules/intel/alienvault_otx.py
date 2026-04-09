"""
AlienVault OTX integration module.

Provides:
- Threat pulses
- Indicators of Compromise (IOCs)
- Domain/IP reputation
- Related malware samples
"""

import asyncio
from datetime import datetime
from typing import Optional

import httpx

from attacktrace.config import AttackTraceConfig
from attacktrace.core.models import (
    ModuleResult,
    Finding,
    Severity,
    ScanSession,
)


async def get_domain_indicators(
    domain: str,
    api_key: Optional[str] = None,
    timeout: float = 30.0,
) -> dict:
    """
    Get OTX indicators for a domain.
    """
    headers = {"User-Agent": "AttackTrace-Scanner/1.0"}
    if api_key:
        headers["X-OTX-API-KEY"] = api_key

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
                headers=headers,
            )

            if response.status_code == 200:
                return response.json()

    except Exception:
        pass

    return {}


async def get_domain_malware(
    domain: str,
    api_key: Optional[str] = None,
    timeout: float = 30.0,
) -> list:
    """
    Get malware samples associated with domain.
    """
    headers = {"User-Agent": "AttackTrace-Scanner/1.0"}
    if api_key:
        headers["X-OTX-API-KEY"] = api_key

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/malware",
                headers=headers,
            )

            if response.status_code == 200:
                data = response.json()
                return data.get("data", [])

    except Exception:
        pass

    return []


async def get_ip_indicators(
    ip: str,
    api_key: Optional[str] = None,
    timeout: float = 30.0,
) -> dict:
    """
    Get OTX indicators for an IP.
    """
    headers = {"User-Agent": "AttackTrace-Scanner/1.0"}
    if api_key:
        headers["X-OTX-API-KEY"] = api_key

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers=headers,
            )

            if response.status_code == 200:
                return response.json()

    except Exception:
        pass

    return {}


async def get_pulses(
    indicator: str,
    indicator_type: str,
    api_key: Optional[str] = None,
    timeout: float = 30.0,
) -> list:
    """
    Get threat pulses mentioning an indicator.
    """
    headers = {"User-Agent": "AttackTrace-Scanner/1.0"}
    if api_key:
        headers["X-OTX-API-KEY"] = api_key

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{indicator}/general",
                headers=headers,
            )

            if response.status_code == 200:
                data = response.json()
                return data.get("pulse_info", {}).get("pulses", [])

    except Exception:
        pass

    return []


async def run(
    session: ScanSession,
    config: AttackTraceConfig,
    orchestrator,
) -> ModuleResult:
    """
    Run AlienVault OTX intelligence gathering.
    """
    result = ModuleResult(
        module_name="alienvault_otx",
        started_at=datetime.utcnow(),
    )

    api_key = getattr(config.api_keys, 'alienvault', None)
    threat_data = []
    malware_associations = []

    # Check domains
    for domain in session.target_domains:
        indicators = await get_domain_indicators(domain, api_key, config.scan.timeout)

        if indicators:
            pulses = indicators.get("pulse_info", {}).get("pulses", [])

            threat_data.append({
                "type": "domain",
                "indicator": domain,
                "pulse_count": len(pulses),
                "pulses": [p.get("name") for p in pulses[:5]],
                "validation": indicators.get("validation", []),
            })

            if pulses:
                result.items_discovered += 1

        # Check for malware
        malware = await get_domain_malware(domain, api_key, config.scan.timeout)
        if malware:
            malware_associations.append({
                "domain": domain,
                "samples": len(malware),
                "hashes": [m.get("hash") for m in malware[:5]],
            })

        await asyncio.sleep(0.5)

    # Check IPs
    for ip in session.ip_addresses[:20]:
        indicators = await get_ip_indicators(ip.address, api_key, config.scan.timeout)

        if indicators:
            pulses = indicators.get("pulse_info", {}).get("pulses", [])

            if pulses:
                threat_data.append({
                    "type": "ip",
                    "indicator": ip.address,
                    "pulse_count": len(pulses),
                    "pulses": [p.get("name") for p in pulses[:5]],
                    "reputation": indicators.get("reputation", 0),
                })
                result.items_discovered += 1

        await asyncio.sleep(0.5)

    # Store data
    if not hasattr(session, 'otx_data'):
        session.otx_data = {}
    session.otx_data = {
        "threats": threat_data,
        "malware": malware_associations,
    }

    # Create findings
    if threat_data:
        high_pulse_indicators = [t for t in threat_data if t["pulse_count"] > 5]

        if high_pulse_indicators:
            finding = Finding(
                title=f"{len(high_pulse_indicators)} indicator(s) appear in multiple threat pulses",
                description="These domains/IPs appear in AlienVault OTX threat intelligence pulses.",
                severity=Severity.MEDIUM,
                category="threat_intel",
                affected_asset=", ".join(t["indicator"] for t in high_pulse_indicators[:5]),
                affected_asset_type="mixed",
                evidence=str([f"{t['indicator']}: {t['pulse_count']} pulses" for t in high_pulse_indicators]),
                source="alienvault_otx",
            )
            result.findings.append(finding)

    if malware_associations:
        finding = Finding(
            title=f"{len(malware_associations)} domain(s) associated with malware",
            description="These domains have been associated with malware samples in OTX.",
            severity=Severity.HIGH,
            category="threat_intel",
            affected_asset=", ".join(m["domain"] for m in malware_associations),
            affected_asset_type="domain",
            source="alienvault_otx",
        )
        result.findings.append(finding)

    result.success = True
    result.completed_at = datetime.utcnow()
    return result
