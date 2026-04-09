"""
WHOIS lookup module.

Performs WHOIS lookups to gather domain registration information
and discover related domains.
"""

import asyncio
from datetime import datetime
from typing import Optional
import re

from attacktrace.config import AttackTraceConfig
from attacktrace.core.models import (
    ModuleResult,
    Domain,
    ScanSession,
)


async def whois_lookup(domain: str) -> Optional[dict]:
    """
    Perform WHOIS lookup for a domain.

    Args:
        domain: Domain to lookup

    Returns:
        Dictionary with WHOIS data or None
    """
    try:
        import whois
        # python-whois is synchronous, run in executor
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, whois.whois, domain)

        if result:
            return {
                "domain_name": result.domain_name,
                "registrar": result.registrar,
                "whois_server": result.whois_server,
                "creation_date": result.creation_date,
                "expiration_date": result.expiration_date,
                "updated_date": result.updated_date,
                "name_servers": result.name_servers,
                "status": result.status,
                "emails": result.emails,
                "dnssec": result.dnssec,
                "name": result.name,
                "org": result.org,
                "address": result.address,
                "city": result.city,
                "state": result.state,
                "registrant_postal_code": result.registrant_postal_code,
                "country": result.country,
            }
    except Exception:
        pass

    return None


def normalize_date(date_value) -> Optional[datetime]:
    """Normalize various date formats to datetime."""
    if date_value is None:
        return None

    if isinstance(date_value, datetime):
        return date_value

    if isinstance(date_value, list):
        date_value = date_value[0] if date_value else None

    if isinstance(date_value, str):
        # Try common formats
        formats = [
            "%Y-%m-%d",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%d-%b-%Y",
        ]
        for fmt in formats:
            try:
                return datetime.strptime(date_value, fmt)
            except ValueError:
                continue

    return None


def normalize_list(value) -> list[str]:
    """Normalize value to a list of strings."""
    if value is None:
        return []

    if isinstance(value, str):
        return [value]

    if isinstance(value, list):
        return [str(v) for v in value if v]

    return []


async def run(
    session: ScanSession,
    config: AttackTraceConfig,
    orchestrator,
) -> ModuleResult:
    """
    Run WHOIS lookups for target domains.

    Args:
        session: Current scan session
        config: AttackTrace configuration
        orchestrator: Orchestrator instance

    Returns:
        ModuleResult with domain information
    """
    result = ModuleResult(
        module_name="whois_lookup",
        started_at=datetime.utcnow(),
    )

    # Get domains to lookup
    domains_to_check = set(session.target_domains)

    # If we have a company name but no domains, try to guess common domains
    if session.target_company and not domains_to_check:
        company_lower = session.target_company.lower().strip()

        # Common company suffixes to strip
        company_suffixes = [
            r'\s+inc\.?$', r'\s+llc\.?$', r'\s+ltd\.?$', r'\s+limited$',
            r'\s+corp\.?$', r'\s+corporation$', r'\s+co\.?$', r'\s+company$',
            r'\s+plc\.?$', r'\s+gmbh$', r'\s+ag$', r'\s+sa$', r'\s+srl$',
            r'\s+holdings?$', r'\s+group$', r'\s+international$', r'\s+intl\.?$',
        ]

        # Get base company name without suffixes
        base_name = company_lower
        for suffix in company_suffixes:
            base_name = re.sub(suffix, '', base_name, flags=re.IGNORECASE)
        base_name = base_name.strip()

        # Generate variations
        variations = set()

        # Base name without suffix (most likely the actual domain)
        base_slug = re.sub(r"[^a-z0-9]", "", base_name)
        if base_slug:
            variations.add(base_slug)

        # Full company name (including suffix)
        full_slug = re.sub(r"[^a-z0-9]", "", company_lower)
        if full_slug and full_slug != base_slug:
            variations.add(full_slug)

        # Hyphenated versions for multi-word names
        base_hyphen = re.sub(r"\s+", "-", base_name)
        base_hyphen = re.sub(r"[^a-z0-9-]", "", base_hyphen).strip('-')
        if base_hyphen and '-' in base_hyphen:
            variations.add(base_hyphen)

        # Common TLDs to try
        tlds = ["com", "net", "org", "io", "co"]

        for variation in variations:
            if variation:
                for tld in tlds:
                    domains_to_check.add(f"{variation}.{tld}")

    # Perform WHOIS lookups
    for domain in domains_to_check:
        try:
            whois_data = await whois_lookup(domain)

            if whois_data:
                # Create Domain object
                domain_obj = Domain(
                    fqdn=domain,
                    registrar=whois_data.get("registrar") or "",
                    registrant_name=whois_data.get("name") or "",
                    registrant_org=whois_data.get("org") or "",
                    registrant_email=(
                        whois_data.get("emails")[0]
                        if isinstance(whois_data.get("emails"), list) and whois_data.get("emails")
                        else whois_data.get("emails") or ""
                    ),
                    creation_date=normalize_date(whois_data.get("creation_date")),
                    expiration_date=normalize_date(whois_data.get("expiration_date")),
                    updated_date=normalize_date(whois_data.get("updated_date")),
                    name_servers=normalize_list(whois_data.get("name_servers")),
                    source="whois",
                )

                result.domains.append(domain_obj)

                # Add domain to session targets if not already there
                if domain not in session.target_domains:
                    session.target_domains.append(domain)

            # Rate limiting
            await asyncio.sleep(1.0)  # WHOIS servers are sensitive to rate

        except Exception:
            continue

    result.items_discovered = len(result.domains)
    result.success = True
    result.completed_at = datetime.utcnow()

    return result
