"""
URLScan.io integration module.

Provides:
- Domain/URL scanning
- Screenshots
- DOM analysis
- Technology detection
- Network request logging
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


async def search_domain(
    domain: str,
    api_key: Optional[str] = None,
    timeout: float = 30.0,
) -> list[dict]:
    """
    Search URLScan.io for existing scans of a domain.
    """
    headers = {"User-Agent": "AttackTrace-Scanner/1.0"}
    if api_key:
        headers["API-Key"] = api_key

    results = []
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"https://urlscan.io/api/v1/search/?q=domain:{domain}",
                headers=headers,
            )

            if response.status_code == 200:
                data = response.json()
                results = data.get("results", [])

    except Exception:
        pass

    return results


async def get_scan_result(
    uuid: str,
    api_key: Optional[str] = None,
    timeout: float = 30.0,
) -> dict:
    """
    Get detailed scan result by UUID.
    """
    headers = {"User-Agent": "AttackTrace-Scanner/1.0"}
    if api_key:
        headers["API-Key"] = api_key

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"https://urlscan.io/api/v1/result/{uuid}/",
                headers=headers,
            )

            if response.status_code == 200:
                return response.json()

    except Exception:
        pass

    return {}


async def submit_scan(
    url: str,
    api_key: str,
    visibility: str = "unlisted",
    timeout: float = 30.0,
) -> Optional[str]:
    """
    Submit a URL for scanning. Returns scan UUID.
    """
    if not api_key:
        return None

    headers = {
        "API-Key": api_key,
        "Content-Type": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                "https://urlscan.io/api/v1/scan/",
                headers=headers,
                json={"url": url, "visibility": visibility},
            )

            if response.status_code == 200:
                data = response.json()
                return data.get("uuid")

    except Exception:
        pass

    return None


async def run(
    session: ScanSession,
    config: AttackTraceConfig,
    orchestrator,
) -> ModuleResult:
    """
    Run URLScan.io intelligence gathering.
    """
    result = ModuleResult(
        module_name="urlscan",
        started_at=datetime.utcnow(),
    )

    api_key = getattr(config.api_keys, 'urlscan', None)
    urlscan_data = []

    for domain in session.target_domains:
        # Search existing scans
        scans = await search_domain(domain, api_key, config.scan.timeout)

        for scan in scans[:10]:  # Limit per domain
            scan_uuid = scan.get("_id")
            if not scan_uuid:
                continue

            # Get detailed result
            details = await get_scan_result(scan_uuid, api_key, config.scan.timeout)

            if details:
                urlscan_data.append({
                    "domain": domain,
                    "url": scan.get("page", {}).get("url", ""),
                    "screenshot": f"https://urlscan.io/screenshots/{scan_uuid}.png",
                    "report": f"https://urlscan.io/result/{scan_uuid}/",
                    "technologies": details.get("meta", {}).get("processors", {}).get("wappa", []),
                    "ip": details.get("page", {}).get("ip", ""),
                    "asn": details.get("page", {}).get("asn", ""),
                    "server": details.get("page", {}).get("server", ""),
                    "requests": len(details.get("data", {}).get("requests", [])),
                })

                result.items_discovered += 1

            await asyncio.sleep(0.5)

    # Store data in session
    if not hasattr(session, 'urlscan_data'):
        session.urlscan_data = []
    session.urlscan_data = urlscan_data

    if urlscan_data:
        finding = Finding(
            title=f"URLScan.io intelligence for {len(urlscan_data)} URLs",
            description=f"Found {len(urlscan_data)} historical scans with screenshots and technology data.",
            severity=Severity.INFO,
            category="intelligence",
            affected_asset=session.target_domains[0] if session.target_domains else "",
            affected_asset_type="domain",
            source="urlscan",
        )
        result.findings.append(finding)

    result.success = True
    result.completed_at = datetime.utcnow()
    return result
