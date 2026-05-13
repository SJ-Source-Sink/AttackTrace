"""
CISA KEV + EPSS enrichment service (async).

KEV feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
EPSS API: https://api.first.org/data/v1/epss?cve=CVE-XXXX-XXXXX (supports comma-separated batch)

Caching strategy:
  - KEV set: Redis, 24h TTL (CISA updates once/day). Falls back to in-process set if Redis unavailable.
  - EPSS scores: Redis, 24h TTL + in-process LRU (1000 entries) to avoid repeated Redis lookups.
  - Redis cache is shared across all worker processes, preventing duplicate HTTP calls at scale.

EPSS strategy: when a finding has multiple CVEs, fetch all and use the maximum score.
This correctly reflects the highest exploitation probability across the CVE set.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# In-process fallback (used when Redis is unavailable)
_kev_cache_local: set[str] = set()
_kev_loaded_at_local: Optional[datetime] = None

# Bounded in-process EPSS cache to limit memory usage (LRU eviction via insertion order)
_epss_cache_local: dict[str, Optional[float]] = {}
_EPSS_LOCAL_MAX = 2000

_KEV_CACHE_KEY = "kev:set"
_KEV_LOADED_KEY = "kev:loaded_at"
_EPSS_CACHE_PREFIX = "epss:"
_KEV_TTL_SECONDS = 86_400      # 24 hours — CISA publishes daily
_EPSS_TTL_SECONDS = 86_400     # 24 hours

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"


def _get_redis():
    """Return the shared async Redis pool from scan_service (created on first use)."""
    try:
        from app.services.scan_service import _get_redis as _sr
        return _sr()
    except Exception:
        return None


async def get_kev_set() -> set[str]:
    """Returns the set of CVE IDs in the CISA KEV catalog.

    Uses Redis as the primary cache (24h TTL, shared across all processes).
    Falls back to in-process cache when Redis is unavailable.
    """
    global _kev_cache_local, _kev_loaded_at_local

    # Try Redis first
    r = _get_redis()
    if r:
        try:
            raw = await r.get(_KEV_CACHE_KEY)
            if raw:
                return set(json.loads(raw))
        except Exception as exc:
            logger.debug(f"KEV Redis read failed: {exc}")

    # Check in-process fallback
    now = datetime.now(timezone.utc)
    if _kev_loaded_at_local and (now - _kev_loaded_at_local) < timedelta(seconds=_KEV_TTL_SECONDS):
        return _kev_cache_local

    # Fetch from CISA
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(KEV_URL)
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            kev_set = {v["cveID"] for v in vulns if "cveID" in v}
            logger.info(f"Loaded {len(kev_set)} CVEs from CISA KEV")

            # Write to Redis with TTL
            if r:
                try:
                    await r.set(_KEV_CACHE_KEY, json.dumps(list(kev_set)), ex=_KEV_TTL_SECONDS)
                except Exception as exc:
                    logger.debug(f"KEV Redis write failed: {exc}")

            # Update in-process fallback
            _kev_cache_local = kev_set
            _kev_loaded_at_local = now
            return kev_set
    except Exception as exc:
        logger.warning(f"Failed to fetch CISA KEV: {exc}")
        return _kev_cache_local  # return stale data rather than empty set


async def _get_epss_batch(cve_ids: list[str]) -> dict[str, Optional[float]]:
    """Fetch EPSS scores for multiple CVEs in one HTTP request.

    Checks local in-process cache first, then Redis, then FIRST.org API.
    Returns {cve_id: score_or_None}.
    """
    results: dict[str, Optional[float]] = {}
    to_fetch: list[str] = []

    # 1. Check in-process cache
    for cve in cve_ids:
        if cve in _epss_cache_local:
            results[cve] = _epss_cache_local[cve]
        else:
            to_fetch.append(cve)

    if not to_fetch:
        return results

    # 2. Check Redis cache
    r = _get_redis()
    redis_misses: list[str] = []
    if r:
        try:
            pipe_keys = [f"{_EPSS_CACHE_PREFIX}{cve}" for cve in to_fetch]
            cached_values = await r.mget(*pipe_keys)
            for cve, val in zip(to_fetch, cached_values):
                if val is not None:
                    score = None if val == "null" else float(val)
                    results[cve] = score
                    _set_local_epss(cve, score)
                else:
                    redis_misses.append(cve)
        except Exception as exc:
            logger.debug(f"EPSS Redis read failed: {exc}")
            redis_misses = to_fetch
    else:
        redis_misses = to_fetch

    if not redis_misses:
        return results

    # 3. Batch fetch from FIRST.org API (supports comma-separated CVE list)
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(EPSS_URL, params={"cve": ",".join(redis_misses)})
            resp.raise_for_status()
            data = resp.json()
            fetched: dict[str, float] = {}
            for item in data.get("data", []):
                cve = item.get("cve", "")
                if cve:
                    fetched[cve] = float(item.get("epss", 0.0))

            # Write back to Redis and in-process cache
            for cve in redis_misses:
                score = fetched.get(cve)
                results[cve] = score
                _set_local_epss(cve, score)
                if r:
                    try:
                        await r.set(
                            f"{_EPSS_CACHE_PREFIX}{cve}",
                            str(score) if score is not None else "null",
                            ex=_EPSS_TTL_SECONDS,
                        )
                    except Exception:
                        pass

    except Exception as exc:
        logger.debug(f"EPSS batch fetch failed for {redis_misses}: {exc}")
        for cve in redis_misses:
            results[cve] = None
            _set_local_epss(cve, None)

    return results


def _set_local_epss(cve: str, score: Optional[float]) -> None:
    """Insert into bounded in-process EPSS dict; evict oldest entry when full."""
    if len(_epss_cache_local) >= _EPSS_LOCAL_MAX:
        # Evict the oldest entry (Python 3.7+ dicts maintain insertion order)
        oldest = next(iter(_epss_cache_local))
        del _epss_cache_local[oldest]
    _epss_cache_local[cve] = score


async def get_epss_score(cve_id: str) -> Optional[float]:
    """Returns EPSS score (0.0–1.0) for a single CVE. Cached in Redis + in-process."""
    result = await _get_epss_batch([cve_id])
    return result.get(cve_id)


def compute_priority_score(
    cvss: Optional[float], epss: Optional[float], kev: bool
) -> float:
    """
    Composite priority score (0.0–10.0).

    - KEV = automatic 10.0 (actively exploited in the wild)
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

    EPSS: uses the maximum score across all CVEs on the finding (not just the first).
    A finding with CVE-2021-44228 (Log4Shell, EPSS ~0.97) and CVE-2020-1234 (EPSS ~0.01)
    should be prioritised at 0.97, not 0.01.

    Returns dict with keys: kev_status, epss_score, priority_score
    """
    if not finding_cves:
        return {"kev_status": False, "epss_score": None, "priority_score": None}

    # Run KEV lookup and EPSS batch fetch concurrently
    kev_set, epss_scores = await asyncio.gather(
        get_kev_set(),
        _get_epss_batch(finding_cves),
    )

    kev_status = any(cve in kev_set for cve in finding_cves)

    # Max EPSS across all CVEs on this finding
    valid_scores = [s for s in epss_scores.values() if s is not None]
    epss_score = max(valid_scores) if valid_scores else None

    priority_score = compute_priority_score(cvss_score, epss_score, kev_status)

    return {
        "kev_status": kev_status,
        "epss_score": epss_score,
        "priority_score": priority_score,
    }
