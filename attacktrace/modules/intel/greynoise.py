"""
GreyNoise integration module.

Identifies:
- Known scanners and crawlers
- Malicious vs benign traffic sources
- Noise classification
- Actor information
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


async def query_ip_community(
    ip: str,
    timeout: float = 30.0,
) -> dict:
    """
    Query GreyNoise Community API (free).
    """
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"https://api.greynoise.io/v3/community/{ip}",
                headers={"User-Agent": "AttackTrace-Scanner/1.0"},
            )

            if response.status_code == 200:
                return response.json()

    except Exception:
        pass

    return {}


async def query_ip_context(
    ip: str,
    api_key: str,
    timeout: float = 30.0,
) -> dict:
    """
    Query GreyNoise Context API (paid).
    """
    if not api_key:
        return {}

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"https://api.greynoise.io/v2/noise/context/{ip}",
                headers={
                    "key": api_key,
                    "User-Agent": "AttackTrace-Scanner/1.0",
                },
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
    Run GreyNoise intelligence gathering.
    """
    result = ModuleResult(
        module_name="greynoise",
        started_at=datetime.utcnow(),
    )

    api_key = getattr(config.api_keys, 'greynoise', None)
    known_scanners = []
    malicious_ips = []

    # Check all discovered IPs
    ips_to_check = [ip.address for ip in session.ip_addresses]

    for ip_addr in ips_to_check[:50]:  # Limit API calls
        if api_key:
            data = await query_ip_context(ip_addr, api_key, config.scan.timeout)
        else:
            data = await query_ip_community(ip_addr, config.scan.timeout)

        if data.get("seen") or data.get("noise"):
            classification = data.get("classification", "unknown")

            info = {
                "ip": ip_addr,
                "noise": data.get("noise", False),
                "riot": data.get("riot", False),  # Rule It Out - known benign
                "classification": classification,
                "name": data.get("name", ""),
                "link": data.get("link", f"https://viz.greynoise.io/ip/{ip_addr}"),
                "last_seen": data.get("last_seen", ""),
                "tags": data.get("tags", []),
            }

            if classification == "malicious":
                malicious_ips.append(info)

            known_scanners.append(info)
            result.items_discovered += 1

        await asyncio.sleep(0.3)

    # Store data
    if not hasattr(session, 'greynoise_data'):
        session.greynoise_data = {}
    session.greynoise_data = {
        "scanners": known_scanners,
        "malicious": malicious_ips,
    }

    # Create findings
    if malicious_ips:
        finding = Finding(
            title=f"{len(malicious_ips)} IP(s) classified as malicious by GreyNoise",
            description="These IPs have been observed performing malicious activity on the internet.",
            severity=Severity.HIGH,
            category="threat_intel",
            affected_asset=", ".join(ip["ip"] for ip in malicious_ips[:5]),
            affected_asset_type="ip",
            evidence=str([ip["ip"] for ip in malicious_ips]),
            source="greynoise",
        )
        result.findings.append(finding)

    if known_scanners:
        finding = Finding(
            title=f"{len(known_scanners)} IP(s) identified as internet scanners",
            description="These IPs are known to GreyNoise as scanners/crawlers.",
            severity=Severity.INFO,
            category="threat_intel",
            affected_asset=session.target_company or "",
            affected_asset_type="organization",
            source="greynoise",
        )
        result.findings.append(finding)

    result.success = True
    result.completed_at = datetime.utcnow()
    return result
