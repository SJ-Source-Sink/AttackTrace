"""
DNS resolution module.

Resolves discovered subdomains to IP addresses and collects DNS records.
"""

import asyncio
from datetime import datetime
from typing import Optional

import dns.asyncresolver
import dns.resolver
import dns.rdatatype

from attacktrace.config import AttackTraceConfig
from attacktrace.core.models import (
    ModuleResult,
    Subdomain,
    IPAddress,
    DNSRecord,
    ScanSession,
)


async def resolve_hostname(
    hostname: str,
    record_type: str = "A",
    timeout: float = 5.0,
) -> list[str]:
    """
    Resolve a hostname to get DNS records.

    Args:
        hostname: Hostname to resolve
        record_type: DNS record type (A, AAAA, MX, TXT, CNAME, NS)
        timeout: Resolution timeout

    Returns:
        List of resolved values
    """
    results = []
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    try:
        answers = await resolver.resolve(hostname, record_type)
        for rdata in answers:
            if record_type == "MX":
                results.append(str(rdata.exchange).rstrip("."))
            elif record_type == "TXT":
                # Join TXT record parts
                results.append("".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings))
            elif record_type in ("CNAME", "NS"):
                results.append(str(rdata.target).rstrip("."))
            else:
                results.append(str(rdata))
    except dns.resolver.NXDOMAIN:
        pass
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NoNameservers:
        pass
    except dns.asyncresolver.NXDOMAIN:
        pass
    except dns.asyncresolver.NoAnswer:
        pass
    except asyncio.TimeoutError:
        pass
    except Exception:
        pass

    return results


async def get_all_dns_records(hostname: str, timeout: float = 5.0) -> list[DNSRecord]:
    """Get all DNS records for a hostname concurrently."""
    records = []
    record_types = ["A", "AAAA", "MX", "TXT", "CNAME", "NS"]

    # Resolve all record types concurrently for speed
    async def resolve_type(rtype: str) -> list[DNSRecord]:
        type_records = []
        try:
            values = await resolve_hostname(hostname, rtype, timeout)
            for value in values:
                record = DNSRecord(
                    record_type=rtype,
                    value=value,
                )
                type_records.append(record)
        except Exception:
            pass
        return type_records

    # Run all DNS queries concurrently
    results = await asyncio.gather(
        *[resolve_type(rtype) for rtype in record_types],
        return_exceptions=True
    )

    for res in results:
        if isinstance(res, list):
            records.extend(res)

    return records


async def resolve_subdomain(
    subdomain: Subdomain,
    timeout: float = 5.0,
) -> tuple[Subdomain, list[str]]:
    """
    Resolve a subdomain and update its data.

    Returns:
        Tuple of (updated subdomain, list of resolved IPs)
    """
    ips = []

    # Resolve A, AAAA, and CNAME records concurrently
    a_task = resolve_hostname(subdomain.fqdn, "A", timeout)
    aaaa_task = resolve_hostname(subdomain.fqdn, "AAAA", timeout)
    cname_task = resolve_hostname(subdomain.fqdn, "CNAME", timeout)

    a_records, aaaa_records, cnames = await asyncio.gather(
        a_task, aaaa_task, cname_task, return_exceptions=True
    )

    if isinstance(a_records, list):
        ips.extend(a_records)
    if isinstance(aaaa_records, list):
        ips.extend(aaaa_records)

    # Follow CNAME chain if needed
    cname_chain = []
    if isinstance(cnames, list) and cnames:
        cname_chain.extend(cnames)
        current = cnames[0]
        max_depth = 10

        for _ in range(max_depth - 1):
            cname_results, cname_ips = await asyncio.gather(
                resolve_hostname(current, "CNAME", timeout),
                resolve_hostname(current, "A", timeout),
                return_exceptions=True
            )

            if isinstance(cname_ips, list):
                ips.extend(cname_ips)

            if isinstance(cname_results, list) and cname_results:
                cname_chain.extend(cname_results)
                current = cname_results[0]
            else:
                break

    subdomain.resolved_ips = list(set(ips))
    subdomain.cname_chain = cname_chain
    subdomain.is_alive = len(ips) > 0

    return subdomain, ips


async def run(
    session: ScanSession,
    config: AttackTraceConfig,
    orchestrator,
) -> ModuleResult:
    """
    Run DNS resolution for all discovered subdomains.

    Args:
        session: Current scan session
        config: AttackTrace configuration
        orchestrator: Orchestrator instance

    Returns:
        ModuleResult with resolved data
    """
    result = ModuleResult(
        module_name="dns_resolver",
        started_at=datetime.utcnow(),
    )

    all_ips: set[str] = set()
    semaphore = asyncio.Semaphore(config.scan.threads)

    async def resolve_with_semaphore(subdomain: Subdomain):
        async with semaphore:
            return await resolve_subdomain(subdomain, config.scan.timeout)

    # Resolve all subdomains
    tasks = [resolve_with_semaphore(s) for s in session.subdomains]

    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results:
            if isinstance(res, tuple):
                subdomain, ips = res
                all_ips.update(ips)
                result.subdomains.append(subdomain)

    # Also resolve root domains
    for domain in session.domains:
        dns_records = await get_all_dns_records(domain.fqdn, config.scan.timeout)
        domain.dns_records = dns_records

        # Get A records for the domain
        for record in dns_records:
            if record.record_type == "A":
                all_ips.add(record.value)

        result.domains.append(domain)

    # Create IPAddress objects
    existing_ips = {ip.address for ip in session.ip_addresses}

    for ip_addr in all_ips:
        if ip_addr not in existing_ips:
            # Determine IP version
            version = 6 if ":" in ip_addr else 4

            ip = IPAddress(
                address=ip_addr,
                version=version,
                source="dns_resolution",
            )
            result.ip_addresses.append(ip)

    result.items_discovered = len(result.ip_addresses)
    result.success = True
    result.completed_at = datetime.utcnow()

    return result
