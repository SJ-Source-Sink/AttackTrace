"""
BuiltWith integration module.

Provides detailed technology profiling:
- Frameworks and libraries
- Analytics and tracking
- CDN and hosting
- E-commerce platforms
- CMS systems
- JavaScript libraries
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
    Technology,
)


async def get_domain_tech(
    domain: str,
    api_key: str,
    timeout: float = 30.0,
) -> dict:
    """
    Get technology profile from BuiltWith.
    """
    if not api_key:
        return {}

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"https://api.builtwith.com/v21/api.json",
                params={
                    "KEY": api_key,
                    "LOOKUP": domain,
                },
            )

            if response.status_code == 200:
                return response.json()

    except Exception:
        pass

    return {}


async def get_free_tech(
    domain: str,
    timeout: float = 30.0,
) -> list[dict]:
    """
    Get basic tech info from BuiltWith free lookup.
    """
    technologies = []

    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            response = await client.get(
                f"https://api.builtwith.com/free1/api.json",
                params={"KEY": "free", "LOOKUP": domain},
            )

            if response.status_code == 200:
                data = response.json()
                groups = data.get("groups", [])
                for group in groups:
                    for cat in group.get("categories", []):
                        for tech in cat.get("live", []):
                            technologies.append({
                                "name": tech.get("Name", ""),
                                "tag": tech.get("Tag", ""),
                                "description": tech.get("Description", ""),
                            })

    except Exception:
        pass

    return technologies


async def run(
    session: ScanSession,
    config: AttackTraceConfig,
    orchestrator,
) -> ModuleResult:
    """
    Run BuiltWith technology profiling.
    """
    result = ModuleResult(
        module_name="builtwith",
        started_at=datetime.utcnow(),
    )

    api_key = getattr(config.api_keys, 'builtwith', None)
    tech_profiles = []

    for domain in session.target_domains:
        if api_key:
            data = await get_domain_tech(domain, api_key, config.scan.timeout)

            if data and data.get("Results"):
                for res in data["Results"]:
                    paths = res.get("Result", {}).get("Paths", [])
                    for path in paths:
                        for tech in path.get("Technologies", []):
                            tech_profiles.append({
                                "domain": domain,
                                "name": tech.get("Name", ""),
                                "tag": tech.get("Tag", ""),
                                "categories": tech.get("Categories", []),
                                "description": tech.get("Description", ""),
                            })
        else:
            # Use free API
            techs = await get_free_tech(domain, config.scan.timeout)
            for tech in techs:
                tech["domain"] = domain
                tech_profiles.append(tech)

        await asyncio.sleep(1)

    # Deduplicate
    seen = set()
    unique_tech = []
    for t in tech_profiles:
        key = f"{t['domain']}:{t['name']}"
        if key not in seen:
            seen.add(key)
            unique_tech.append(t)

    tech_profiles = unique_tech

    # Store data
    if not hasattr(session, 'builtwith_data'):
        session.builtwith_data = []
    session.builtwith_data = tech_profiles

    result.items_discovered = len(tech_profiles)

    if tech_profiles:
        finding = Finding(
            title=f"BuiltWith identified {len(tech_profiles)} technologies",
            description="Detailed technology stack profiling from BuiltWith.",
            severity=Severity.INFO,
            category="reconnaissance",
            affected_asset=session.target_domains[0],
            affected_asset_type="domain",
            evidence=", ".join(set(t["name"] for t in tech_profiles[:20])),
            source="builtwith",
        )
        result.findings.append(finding)

    result.success = True
    result.completed_at = datetime.utcnow()
    return result
