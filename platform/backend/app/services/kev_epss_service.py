"""
CISA KEV + EPSS enrichment service (async).

KEV feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
EPSS API: https://api.first.org/data/v1/epss?cve=CVE-XXXX-XXXXX

Caches KEV list in-process with 1h TTL. Calls EPSS per CVE with in-process cache.
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

_kev_cache: set[str] = set()  # CVE IDs in KEV
_kev_loaded_at: Optional[datetime] = None
_KEV_TTL_HOURS = 1

_epss_cache: dict[str, Optional[float]] = {}  # CVE ID -> EPSS score

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"


async def get_kev_set() -> set[str]:
    """Returns the set of CVE IDs in the CISA KEV catalog. Cached 1h."""
    global _kev_cache, _kev_loaded_at
    now = datetime.now(timezone.utc)
    if _kev_loaded_at and (now - _kev_loaded_at) < timedelta(hours=_KEV_TTL_HOURS):
        return _kev_cache
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(KEV_URL)
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            _kev_cache = {v["cveID"] for v in vulns if "cveID" in v}
            _kev_loaded_at = now
            logger.info(f"Loaded {len(_kev_cache)} CVEs from CISA KEV")
    except Exception as e:
        logger.warning(f"Failed to fetch CISA KEV: {e}")
    return _kev_cache


async def get_epss_score(cve_id: str) -> Optional[float]:
    """Returns EPSS score (0.0-1.0) for a CVE. Cached in-process."""
    if cve_id in _epss_cache:
        return _epss_cache[cve_id]
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(EPSS_URL, params={"cve": cve_id})
            resp.raise_for_status()
            data = resp.json()
            items = data.get("data", [])
            if items:
                score = float(items[0].get("epss", 0.0))
                _epss_cache[cve_id] = score
                return score
    except Exception as e:
        logger.debug(f"EPSS lookup failed for {cve_id}: {e}")
    _epss_cache[cve_id] = None
    return None


def compute_priority_score(
    cvss: Optional[float], epss: Optional[float], kev: bool
) -> float:
    """
    Composite priority score (0.0-10.0).

    - KEV = automatic 10.0 (exploited in the wild)
    - Otherwise: (EPSS * 0.6 + CVSS_normalized * 0.4) * 10
    """
    if kev:
        return 10.0
    cvss_norm = (cvss or 0.0) / 10.0
    epss_val = epss or 0.0
    return round((epss_val * 0.6 + cvss_norm * 0.4) * 10.0, 2)


async def enrich_finding_kev_epss(
    finding_cves: list[str], cvss_score: Optional[float]
) -> dict:
    """
    For a list of CVE IDs on a finding, compute KEV status, EPSS score, priority_score.
    Returns dict with keys: kev_status, epss_score, priority_score
    """
    if not finding_cves:
        return {"kev_status": False, "epss_score": None, "priority_score": None}

    kev_set = await get_kev_set()
    kev_status = any(cve in kev_set for cve in finding_cves)

    # Get EPSS for the first/primary CVE
    epss_score = await get_epss_score(finding_cves[0])

    priority_score = compute_priority_score(cvss_score, epss_score, kev_status)

    return {
        "kev_status": kev_status,
        "epss_score": epss_score,
        "priority_score": priority_score,
    }
