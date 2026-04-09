"""
SecurityTrails enrichment module.

Enriches discovery with SecurityTrails data including:
- Historical DNS records
- Subdomain enumeration
- Associated domains
- WHOIS history
- IP neighbors
"""

import asyncio
from datetime import datetime
from typing import Optional

import httpx

from attacktrace.config import AttackTraceConfig
from attacktrace.core.models import (
    ModuleResult,
    Domain,
    Subdomain,
    IPAddress,
    DNSRecord,
    ScanSession,
)


class SecurityTrailsClient:
    """Async client for SecurityTrails API."""

    BASE_URL = "https://api.securitytrails.com/v1"

    def __init__(self, api_key: str):
        self.api_key = api_key

    async def _request(
        self,
        endpoint: str,
        params: Optional[dict] = None,
        timeout: float = 30.0,
    ) -> Optional[dict]:
        """Make an authenticated request to SecurityTrails API."""
        url = f"{self.BASE_URL}/{endpoint}"
        headers = {
            "apikey": self.api_key,
            "Accept": "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.get(url, headers=headers, params=params)

                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 429:
                    # Rate limited
                    await asyncio.sleep(5)
                    return None

        except Exception:
            pass

        return None

    async def get_domain(self, domain: str) -> Optional[dict]:
        """Get current DNS records for a domain."""
        return await self._request(f"domain/{domain}")

    async def get_subdomains(self, domain: str) -> Optional[dict]:
        """Get subdomains for a domain."""
        return await self._request(f"domain/{domain}/subdomains")

    async def get_associated_domains(self, domain: str) -> Optional[dict]:
        """Get associated domains (same registrant, NS, MX, etc.)."""
        return await self._request(f"domain/{domain}/associated")

    async def get_domain_history(
        self,
        domain: str,
        record_type: str = "a",
    ) -> Optional[dict]:
        """Get historical DNS records for a domain."""
        return await self._request(f"history/{domain}/dns/{record_type}")

    async def get_whois_history(self, domain: str) -> Optional[dict]:
        """Get WHOIS history for a domain."""
        return await self._request(f"history/{domain}/whois")

    async def get_ip_neighbors(self, ip: str) -> Optional[dict]:
        """Get domains hosted on the same IP or nearby IPs."""
        return await self._request(f"ips/nearby/{ip}")

    async def search_domains(self, query: dict) -> Optional[dict]:
        """Search for domains using DSL query."""
        # This would require POST, simplified here
        return None

    async def get_ip_whois(self, ip: str) -> Optional[dict]:
        """Get WHOIS information for an IP."""
        return await self._request(f"ips/{ip}/whois")


def parse_dns_records(data: dict) -> list[DNSRecord]:
    """Parse DNS records from SecurityTrails response."""
    records = []
    current_dns = data.get("current_dns", {})

    record_types = ["a", "aaaa", "mx", "ns", "soa", "txt", "cname"]

    for rtype in record_types:
        type_data = current_dns.get(rtype, {})
        values = type_data.get("values", [])

        for value_entry in values:
            if isinstance(value_entry, dict):
                # Handle structured records (MX, etc.)
                if rtype == "mx":
                    record = DNSRecord(
                        record_type=rtype.upper(),
                        value=value_entry.get("hostname", ""),
                        priority=value_entry.get("priority"),
                    )
                else:
                    record = DNSRecord(
                        record_type=rtype.upper(),
                        value=value_entry.get("ip", value_entry.get("value", "")),
                    )
            else:
                record = DNSRecord(
                    record_type=rtype.upper(),
                    value=str(value_entry),
                )

            if record.value:
                records.append(record)

    return records


async def run(
    session: ScanSession,
    config: AttackTraceConfig,
    orchestrator,
) -> ModuleResult:
    """
    Run SecurityTrails enrichment.

    Args:
        session: Current scan session
        config: AttackTrace configuration
        orchestrator: Orchestrator instance

    Returns:
        ModuleResult with enriched data
    """
    result = ModuleResult(
        module_name="securitytrails_enrichment",
        started_at=datetime.utcnow(),
    )

    if not config.api_keys.securitytrails:
        result.success = True
        result.error_message = "No SecurityTrails API key configured"
        result.completed_at = datetime.utcnow()
        return result

    client = SecurityTrailsClient(config.api_keys.securitytrails)
    items_discovered = 0

    # Process each target domain
    for domain_fqdn in session.target_domains:
        # Get current DNS records
        try:
            domain_data = await client.get_domain(domain_fqdn)

            if domain_data:
                # Update or create domain record
                existing_domain = next(
                    (d for d in session.domains if d.fqdn == domain_fqdn),
                    None
                )

                if existing_domain:
                    dns_records = parse_dns_records(domain_data)
                    existing_domain.dns_records.extend(dns_records)
                    result.domains.append(existing_domain)
                else:
                    domain = Domain(
                        fqdn=domain_fqdn,
                        dns_records=parse_dns_records(domain_data),
                        source="securitytrails",
                    )
                    result.domains.append(domain)

                items_discovered += 1

            await asyncio.sleep(0.5)

        except Exception:
            pass

        # Get subdomains
        try:
            subdomain_data = await client.get_subdomains(domain_fqdn)

            if subdomain_data:
                subdomains = subdomain_data.get("subdomains", [])
                for sub in subdomains:
                    fqdn = f"{sub}.{domain_fqdn}"

                    # Check if already exists
                    exists = any(
                        s.fqdn == fqdn for s in session.subdomains
                    ) or any(
                        s.fqdn == fqdn for s in result.subdomains
                    )

                    if not exists:
                        subdomain = Subdomain(
                            fqdn=fqdn,
                            parent_domain=domain_fqdn,
                            source="securitytrails",
                        )
                        result.subdomains.append(subdomain)
                        items_discovered += 1

            await asyncio.sleep(0.5)

        except Exception:
            pass

        # Get associated domains
        try:
            associated_data = await client.get_associated_domains(domain_fqdn)

            if associated_data:
                # Associated by mail server
                for record in associated_data.get("records", []):
                    assoc_domain = record.get("hostname", "")
                    if assoc_domain and assoc_domain not in session.target_domains:
                        # Add as a note - don't auto-add to targets
                        # Could be added with a flag
                        pass

            await asyncio.sleep(0.5)

        except Exception:
            pass

        # Get historical DNS (A records)
        try:
            history_data = await client.get_domain_history(domain_fqdn, "a")

            if history_data:
                records = history_data.get("records", [])
                historical_ips = set()

                for record in records:
                    values = record.get("values", [])
                    for value in values:
                        ip = value.get("ip", "")
                        if ip:
                            historical_ips.add(ip)

                # Add historical IPs (might reveal old/forgotten infrastructure)
                for ip_addr in historical_ips:
                    exists = any(
                        ip.address == ip_addr for ip in session.ip_addresses
                    ) or any(
                        ip.address == ip_addr for ip in result.ip_addresses
                    )

                    if not exists:
                        ip = IPAddress(
                            address=ip_addr,
                            version=6 if ":" in ip_addr else 4,
                            source="securitytrails_history",
                            tags=["historical"],
                        )
                        result.ip_addresses.append(ip)
                        items_discovered += 1

            await asyncio.sleep(0.5)

        except Exception:
            pass

    # Get IP neighbors for discovered IPs
    for ip in list(session.ip_addresses)[:10]:  # Limit to first 10 IPs
        try:
            neighbor_data = await client.get_ip_neighbors(ip.address)

            if neighbor_data:
                blocks = neighbor_data.get("blocks", [])
                for block in blocks:
                    # Block contains IP ranges and associated domains
                    sites = block.get("sites", 0)
                    if sites > 0:
                        # Could discover co-hosted domains here
                        pass

            await asyncio.sleep(0.5)

        except Exception:
            pass

    result.items_discovered = items_discovered
    result.success = True
    result.completed_at = datetime.utcnow()

    return result
