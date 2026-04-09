"""
IPinfo.io integration module.

Provides:
- IP geolocation
- ASN information
- Company/hosting detection
- Privacy detection (VPN, proxy, Tor)
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


async def get_ip_info(
    ip: str,
    api_key: Optional[str] = None,
    timeout: float = 30.0,
) -> dict:
    """
    Get IP information from IPinfo.io.
    """
    url = f"https://ipinfo.io/{ip}/json"
    if api_key:
        url += f"?token={api_key}"

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url)

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
    Run IPinfo enrichment.
    """
    result = ModuleResult(
        module_name="ipinfo",
        started_at=datetime.utcnow(),
    )

    api_key = getattr(config.api_keys, 'ipinfo', None)
    ip_details = []

    for ip in session.ip_addresses[:50]:
        info = await get_ip_info(ip.address, api_key, config.scan.timeout)

        if info:
            # Update IP object
            ip.country = info.get("country", "")
            ip.city = info.get("city", "")
            ip.asn_org = info.get("org", "")

            detail = {
                "ip": ip.address,
                "hostname": info.get("hostname", ""),
                "city": info.get("city", ""),
                "region": info.get("region", ""),
                "country": info.get("country", ""),
                "org": info.get("org", ""),
                "postal": info.get("postal", ""),
                "timezone": info.get("timezone", ""),
            }

            # Check for privacy services
            privacy = info.get("privacy", {})
            if privacy:
                detail["vpn"] = privacy.get("vpn", False)
                detail["proxy"] = privacy.get("proxy", False)
                detail["tor"] = privacy.get("tor", False)
                detail["hosting"] = privacy.get("hosting", False)

            ip_details.append(detail)
            result.items_discovered += 1

        await asyncio.sleep(0.2)

    # Store data
    if not hasattr(session, 'ipinfo_data'):
        session.ipinfo_data = []
    session.ipinfo_data = ip_details

    # Create findings for interesting cases
    hosting_ips = [d for d in ip_details if d.get("hosting")]
    if hosting_ips:
        finding = Finding(
            title=f"{len(hosting_ips)} IP(s) identified as hosting/cloud providers",
            description="These IPs are in hosting provider ranges.",
            severity=Severity.INFO,
            category="infrastructure",
            affected_asset=", ".join(d["ip"] for d in hosting_ips[:5]),
            affected_asset_type="ip",
            source="ipinfo",
        )
        result.findings.append(finding)

    result.success = True
    result.completed_at = datetime.utcnow()
    return result
