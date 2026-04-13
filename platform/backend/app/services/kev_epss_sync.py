"""Synchronous KEV/EPSS helpers for use in Celery workers."""

import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

_kev_cache: set[str] = set()
_epss_cache: dict[str, Optional[float]] = {}

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"


def load_kev() -> set[str]:
    """Load CISA KEV catalog synchronously. Cached in-process."""
    global _kev_cache
    if _kev_cache:
        return _kev_cache
    try:
        with httpx.Client(timeout=15) as client:
            resp = client.get(KEV_URL)
            resp.raise_for_status()
            vulns = resp.json().get("vulnerabilities", [])
            _kev_cache = {v["cveID"] for v in vulns if "cveID" in v}
            logger.info(f"KEV sync: loaded {len(_kev_cache)} CVEs")
    except Exception as e:
        logger.warning(f"KEV load failed: {e}")
    return _kev_cache


def get_epss_sync(cve_id: str) -> Optional[float]:
    """Return EPSS score for a CVE synchronously. Cached in-process."""
    if cve_id in _epss_cache:
        return _epss_cache[cve_id]
    try:
        with httpx.Client(timeout=10) as client:
            resp = client.get(EPSS_URL, params={"cve": cve_id})
            resp.raise_for_status()
            items = resp.json().get("data", [])
            score = float(items[0]["epss"]) if items else None
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
