"""
ASN and IP Range discovery module.

Discovers IP ranges associated with an organization through:
- ASN lookups
- BGP data
- WHOIS IP lookups
- RIPE/ARIN/APNIC databases
"""

import asyncio
import re
from datetime import datetime
from typing import Optional
from ipaddress import ip_network

import httpx

from attacktrace.config import AttackTraceConfig
from attacktrace.core.models import (
    ModuleResult,
    IPAddress,
    Finding,
    Severity,
    ScanSession,
)


async def query_bgpview_asn_search(
    org_name: str,
    timeout: float = 30.0,
) -> list[dict]:
    """
    Search for ASNs by organization name using BGPView API.

    Returns:
        List of ASN records
    """
    results = []

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"https://api.bgpview.io/search?query_term={org_name}"
            )

            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "ok":
                    # Get ASN results
                    asns = data.get("data", {}).get("asns", [])
                    results.extend(asns)

    except Exception:
        pass

    return results


async def query_bgpview_asn_prefixes(
    asn: int,
    timeout: float = 30.0,
) -> list[str]:
    """
    Get IP prefixes announced by an ASN.

    Returns:
        List of CIDR prefixes
    """
    prefixes = []

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"https://api.bgpview.io/asn/{asn}/prefixes"
            )

            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "ok":
                    # IPv4 prefixes
                    ipv4_prefixes = data.get("data", {}).get("ipv4_prefixes", [])
                    for prefix in ipv4_prefixes:
                        prefixes.append(prefix.get("prefix", ""))

                    # IPv6 prefixes
                    ipv6_prefixes = data.get("data", {}).get("ipv6_prefixes", [])
                    for prefix in ipv6_prefixes:
                        prefixes.append(prefix.get("prefix", ""))

    except Exception:
        pass

    return [p for p in prefixes if p]


async def query_hackertarget_asn(
    target: str,
    timeout: float = 30.0,
) -> list[dict]:
    """
    Query HackerTarget for ASN information.
    Target can be an IP, domain, or ASN number.

    Returns:
        List of ASN info dictionaries
    """
    results = []

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"https://api.hackertarget.com/aslookup/?q={target}"
            )

            if response.status_code == 200 and "error" not in response.text.lower():
                # Parse response lines
                for line in response.text.strip().split("\n"):
                    parts = line.split(",")
                    if len(parts) >= 3:
                        results.append({
                            "ip": parts[0].strip() if "." in parts[0] or ":" in parts[0] else "",
                            "asn": parts[1].strip().replace("AS", ""),
                            "org": parts[2].strip() if len(parts) > 2 else "",
                        })

    except Exception:
        pass

    return results


async def query_ipinfo(
    ip: str,
    timeout: float = 30.0,
) -> Optional[dict]:
    """
    Query ipinfo.io for IP information.

    Returns:
        IP info dictionary
    """
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(f"https://ipinfo.io/{ip}/json")

            if response.status_code == 200:
                return response.json()

    except Exception:
        pass

    return None


async def query_ripe_search(
    query: str,
    timeout: float = 30.0,
) -> list[dict]:
    """
    Search RIPE database for organization resources.

    Returns:
        List of resource records
    """
    results = []

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            # Search for inet/inet6num objects
            response = await client.get(
                "https://rest.db.ripe.net/search.json",
                params={
                    "query-string": query,
                    "type-filter": "inetnum,inet6num,aut-num",
                    "flags": "no-filtering",
                }
            )

            if response.status_code == 200:
                data = response.json()
                objects = data.get("objects", {}).get("object", [])

                for obj in objects:
                    obj_type = obj.get("type", "")
                    attributes = obj.get("attributes", {}).get("attribute", [])

                    record = {"type": obj_type}
                    for attr in attributes:
                        name = attr.get("name", "")
                        value = attr.get("value", "")
                        if name in ["inetnum", "inet6num", "aut-num", "netname", "descr", "org-name"]:
                            record[name] = value

                    if record.get("inetnum") or record.get("inet6num") or record.get("aut-num"):
                        results.append(record)

    except Exception:
        pass

    return results


def parse_inetnum_to_cidr(inetnum: str) -> Optional[str]:
    """
    Convert RIPE inetnum format (start - end) to CIDR.

    Example: "192.168.0.0 - 192.168.255.255" -> "192.168.0.0/16"
    """
    try:
        if " - " in inetnum:
            start, end = inetnum.split(" - ")
            start = start.strip()
            end = end.strip()

            # Try to find the smallest CIDR that contains both
            from ipaddress import ip_address, summarize_address_range

            start_ip = ip_address(start)
            end_ip = ip_address(end)

            cidrs = list(summarize_address_range(start_ip, end_ip))
            if cidrs:
                return str(cidrs[0])

        return inetnum

    except Exception:
        return None


async def discover_asn_from_known_ips(
    ips: list[str],
    timeout: float = 30.0,
) -> dict[int, dict]:
    """
    Discover ASNs from known IP addresses.

    Returns:
        Dictionary mapping ASN to info
    """
    asn_info: dict[int, dict] = {}

    for ip in ips[:20]:  # Limit lookups
        try:
            asn_data = await query_hackertarget_asn(ip, timeout)
            for entry in asn_data:
                asn_str = entry.get("asn", "")
                if asn_str and asn_str.isdigit():
                    asn = int(asn_str)
                    if asn not in asn_info:
                        asn_info[asn] = {
                            "asn": asn,
                            "org": entry.get("org", ""),
                            "sample_ips": [],
                        }
                    asn_info[asn]["sample_ips"].append(ip)

            await asyncio.sleep(0.5)

        except Exception:
            continue

    return asn_info


async def run(
    session: ScanSession,
    config: AttackTraceConfig,
    orchestrator,
) -> ModuleResult:
    """
    Run ASN and IP range discovery.

    Args:
        session: Current scan session
        config: AttackTrace configuration
        orchestrator: Orchestrator instance

    Returns:
        ModuleResult with discovered IP ranges
    """
    result = ModuleResult(
        module_name="asn_discovery",
        started_at=datetime.utcnow(),
    )

    discovered_asns: dict[int, dict] = {}
    discovered_prefixes: set[str] = set()
    items_discovered = 0

    # 1. Search for ASNs by company name
    if session.target_company:
        try:
            asn_results = await query_bgpview_asn_search(
                session.target_company,
                config.scan.timeout,
            )

            for asn_data in asn_results:
                asn = asn_data.get("asn")
                if asn:
                    discovered_asns[asn] = {
                        "asn": asn,
                        "name": asn_data.get("name", ""),
                        "description": asn_data.get("description", ""),
                        "country": asn_data.get("country_code", ""),
                    }

            await asyncio.sleep(0.5)

        except Exception:
            pass

    # 2. Discover ASNs from already-known IPs
    known_ips = [ip.address for ip in session.ip_addresses]
    for subdomain in session.subdomains:
        known_ips.extend(subdomain.resolved_ips)
    known_ips = list(set(known_ips))

    if known_ips:
        asn_from_ips = await discover_asn_from_known_ips(known_ips, config.scan.timeout)

        # Merge with discovered ASNs
        for asn, info in asn_from_ips.items():
            if asn not in discovered_asns:
                discovered_asns[asn] = info

    # 3. Get IP prefixes for each discovered ASN
    for asn, info in discovered_asns.items():
        try:
            prefixes = await query_bgpview_asn_prefixes(asn, config.scan.timeout)
            discovered_prefixes.update(prefixes)
            info["prefixes"] = prefixes

            await asyncio.sleep(0.5)

        except Exception:
            continue

    # 4. Search RIPE for organization resources
    if session.target_company:
        try:
            ripe_results = await query_ripe_search(
                session.target_company,
                config.scan.timeout,
            )

            for record in ripe_results:
                if record.get("inetnum"):
                    cidr = parse_inetnum_to_cidr(record["inetnum"])
                    if cidr:
                        discovered_prefixes.add(cidr)
                elif record.get("inet6num"):
                    cidr = parse_inetnum_to_cidr(record["inet6num"])
                    if cidr:
                        discovered_prefixes.add(cidr)
                elif record.get("aut-num"):
                    asn_str = record["aut-num"].replace("AS", "")
                    if asn_str.isdigit():
                        asn = int(asn_str)
                        if asn not in discovered_asns:
                            discovered_asns[asn] = {
                                "asn": asn,
                                "name": record.get("netname", ""),
                                "description": record.get("descr", ""),
                            }

        except Exception:
            pass

    # 5. Create findings and IP addresses from discovered prefixes
    # Note: We don't want to scan entire /16 blocks, but we record them
    for prefix in discovered_prefixes:
        try:
            network = ip_network(prefix, strict=False)

            # Only add individual IPs for small ranges (/28 or smaller)
            if network.prefixlen >= 28:
                for ip_addr in network.hosts():
                    ip_str = str(ip_addr)
                    if ip_str not in [ip.address for ip in session.ip_addresses]:
                        ip = IPAddress(
                            address=ip_str,
                            version=network.version,
                            source="asn_discovery",
                            tags=["asn_range"],
                        )
                        result.ip_addresses.append(ip)
                        items_discovered += 1

                        # Limit individual IPs
                        if items_discovered > 500:
                            break

            # Record larger ranges as findings for manual review
            if network.prefixlen < 24:
                finding = Finding(
                    title=f"Large IP range discovered: {prefix}",
                    description=f"IP range {prefix} appears to belong to the target organization. "
                               f"Contains {network.num_addresses} addresses.",
                    severity=Severity.INFO,
                    category="infrastructure",
                    affected_asset=prefix,
                    affected_asset_type="ip_range",
                    source="asn_discovery",
                )
                result.findings.append(finding)

        except Exception:
            continue

        if items_discovered > 500:
            break

    # 6. Create summary finding for discovered ASNs
    if discovered_asns:
        asn_list = ", ".join(
            f"AS{asn} ({info.get('name', info.get('org', 'Unknown'))})"
            for asn, info in list(discovered_asns.items())[:10]
        )

        finding = Finding(
            title=f"Discovered {len(discovered_asns)} ASN(s) for target",
            description=f"The following autonomous systems appear to belong to the target: {asn_list}",
            severity=Severity.INFO,
            category="infrastructure",
            affected_asset=session.target_company or session.target_domains[0] if session.target_domains else "",
            affected_asset_type="organization",
            evidence=f"ASNs: {', '.join(f'AS{asn}' for asn in discovered_asns.keys())}",
            source="asn_discovery",
        )
        result.findings.append(finding)

    # Store discovered prefixes in session metadata
    if discovered_prefixes:
        session.target_ip_ranges.extend(list(discovered_prefixes))

    result.items_discovered = items_discovered + len(discovered_asns)
    result.success = True
    result.completed_at = datetime.utcnow()

    return result
