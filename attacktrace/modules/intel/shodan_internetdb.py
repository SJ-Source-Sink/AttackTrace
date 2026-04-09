"""
Shodan InternetDB integration module.

Free API that provides:
- Open ports
- Known vulnerabilities (CVEs)
- Hostnames
- Tags
- CPEs

No authentication required!
"""

import asyncio
from datetime import datetime

import httpx

from attacktrace.config import AttackTraceConfig
from attacktrace.core.models import (
    ModuleResult,
    Finding,
    Severity,
    ScanSession,
    Port,
    PortState,
    Service,
)


async def query_ip(
    ip: str,
    timeout: float = 30.0,
) -> dict:
    """
    Query Shodan InternetDB for IP information.
    No API key required!
    """
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"https://internetdb.shodan.io/{ip}",
                headers={"User-Agent": "AttackTrace-Scanner/1.0"},
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
    Run Shodan InternetDB enrichment (free, no auth).
    """
    result = ModuleResult(
        module_name="shodan_internetdb",
        started_at=datetime.utcnow(),
    )

    vulnerable_ips = []
    enriched_count = 0

    # Get all IPs
    ips_to_check = list(session.ip_addresses)

    # Also get IPs from subdomains
    for subdomain in session.subdomains:
        for ip_addr in subdomain.resolved_ips:
            if not any(ip.address == ip_addr for ip in ips_to_check):
                from attacktrace.core.models import IPAddress
                ips_to_check.append(IPAddress(address=ip_addr, version=4, source="subdomain"))

    for ip in ips_to_check[:100]:  # Limit
        data = await query_ip(ip.address, config.scan.timeout)

        if data and "ports" in data:
            # Update ports
            for port_num in data.get("ports", []):
                existing_port = next((p for p in ip.ports if p.number == port_num), None)
                if not existing_port:
                    ip.ports.append(Port(
                        number=port_num,
                        protocol="tcp",
                        state=PortState.OPEN,
                        service=Service(name="unknown"),
                    ))

            # Store CVEs
            cves = data.get("vulns", [])
            if cves:
                ip.tags.extend([f"CVE:{cve}" for cve in cves[:10]])
                vulnerable_ips.append({
                    "ip": ip.address,
                    "cves": cves,
                    "ports": data.get("ports", []),
                    "hostnames": data.get("hostnames", []),
                })

            # Store hostnames
            hostnames = data.get("hostnames", [])
            if hostnames and not ip.hostnames:
                ip.hostnames = hostnames

            # Store CPEs
            cpes = data.get("cpes", [])
            if cpes:
                ip.tags.extend([f"CPE:{cpe}" for cpe in cpes[:5]])

            enriched_count += 1
            result.items_discovered += 1

        await asyncio.sleep(0.2)

    # Create findings for vulnerabilities
    if vulnerable_ips:
        # Critical CVEs
        critical_cves = []
        for vip in vulnerable_ips:
            for cve in vip["cves"]:
                if any(year in cve for year in ["2023", "2024", "2025", "2026"]):
                    critical_cves.append((vip["ip"], cve))

        if critical_cves:
            finding = Finding(
                title=f"{len(critical_cves)} recent CVE(s) detected on target IPs",
                description="Recent vulnerabilities detected via Shodan InternetDB.",
                severity=Severity.CRITICAL,
                category="vulnerability",
                affected_asset=", ".join(set(c[0] for c in critical_cves[:5])),
                affected_asset_type="ip",
                evidence=str(critical_cves[:10]),
                source="shodan_internetdb",
            )
            result.findings.append(finding)

        finding = Finding(
            title=f"{len(vulnerable_ips)} IP(s) with known vulnerabilities",
            description=f"Shodan InternetDB reports CVEs for these IPs. Total CVEs: {sum(len(v['cves']) for v in vulnerable_ips)}",
            severity=Severity.HIGH,
            category="vulnerability",
            affected_asset=", ".join(v["ip"] for v in vulnerable_ips[:10]),
            affected_asset_type="ip",
            evidence=str([{"ip": v["ip"], "cve_count": len(v["cves"])} for v in vulnerable_ips]),
            source="shodan_internetdb",
        )
        result.findings.append(finding)

    # Store in session
    if not hasattr(session, 'internetdb_data'):
        session.internetdb_data = {}
    session.internetdb_data = {
        "vulnerable_ips": vulnerable_ips,
        "enriched_count": enriched_count,
    }

    result.success = True
    result.completed_at = datetime.utcnow()
    return result
