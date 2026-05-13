"""
Vulnerability enrichment service — EPSS, CISA KEV, CVSS v4.
All APIs are free and require no key.

Provides:
  enrich_cve(cve_id)           → {epss_score, epss_percentile, is_kev, kev_date_added,
                                   cvss_v4_score, cvss_v4_vector}
  batch_enrich_cves(cve_ids)   → {cve_id: {...}, ...}
  get_kev_catalog()            → set[str]   (cached 1 h)
  get_epss_scores(cve_ids)     → {cve_id: (score, percentile)}  (cached 24 h)
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone, timedelta
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────

_EPSS_BATCH_URL = "https://api.first.org/data/v1/epss"
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_HTTP_TIMEOUT = httpx.Timeout(connect=4.0, read=10.0, write=4.0, pool=4.0)

# ── Caches ─────────────────────────────────────────────────────────────────────

# KEV: set of CVE IDs that are in the catalog + mapping cveID → dateAdded
_kev_ids: set[str] = set()
_kev_date_added: dict[str, str] = {}
_kev_loaded_at: Optional[datetime] = None
_KEV_TTL = timedelta(hours=1)

# EPSS: (score, percentile) tuples, valid 24 h
_epss_cache: dict[str, tuple[float, float]] = {}
_epss_cached_at: dict[str, float] = {}   # monotonic timestamp
_EPSS_TTL_SECS = 86_400  # 24 h

# CVSS v4: indefinite cache (NVD scores don't change)
_cvss_v4_cache: dict[str, tuple[Optional[float], Optional[str]]] = {}

# ── Circuit breakers ───────────────────────────────────────────────────────────
# Each breaker is {"fail_count": int, "open_until": float (monotonic)}

_breaker: dict[str, dict] = {
    "epss":  {"fail_count": 0, "open_until": 0.0},
    "kev":   {"fail_count": 0, "open_until": 0.0},
    "nvd":   {"fail_count": 0, "open_until": 0.0},
}

_BREAKER_THRESHOLD = 5
_BREAKER_BACKOFF = 600.0  # 10 minutes


def _is_open(name: str) -> bool:
    """Return True if the circuit breaker for *name* is tripped (API is skipped)."""
    b = _breaker[name]
    if b["open_until"] and time.monotonic() < b["open_until"]:
        return True
    return False


def _record_failure(name: str) -> None:
    b = _breaker[name]
    b["fail_count"] += 1
    if b["fail_count"] >= _BREAKER_THRESHOLD:
        b["open_until"] = time.monotonic() + _BREAKER_BACKOFF
        logger.warning(
            "enrichment_service: circuit breaker OPEN for %s after %d failures. "
            "Skipping for %.0f s.",
            name, b["fail_count"], _BREAKER_BACKOFF,
        )


def _record_success(name: str) -> None:
    b = _breaker[name]
    b["fail_count"] = 0
    b["open_until"] = 0.0


# ── Public helpers ─────────────────────────────────────────────────────────────

async def get_kev_catalog() -> set[str]:
    """
    Fetch and cache the full CISA KEV catalog.
    Returns a set of CVE IDs. Cached for 1 hour.
    """
    global _kev_ids, _kev_date_added, _kev_loaded_at

    now = datetime.now(timezone.utc)
    if _kev_loaded_at and (now - _kev_loaded_at) < _KEV_TTL:
        return _kev_ids

    if _is_open("kev"):
        return _kev_ids  # return stale cache rather than erroring

    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            resp = await client.get(_KEV_URL, headers={"Accept": "application/json"})
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            _kev_ids = {v["cveID"] for v in vulns if "cveID" in v}
            _kev_date_added = {
                v["cveID"]: v.get("dateAdded", "")
                for v in vulns if "cveID" in v
            }
            _kev_loaded_at = now
            _record_success("kev")
            logger.info("enrichment_service: loaded %d KEV entries", len(_kev_ids))
    except Exception as exc:
        _record_failure("kev")
        logger.warning("enrichment_service: KEV fetch failed: %s", exc)

    return _kev_ids


async def get_epss_scores(cve_ids: list[str]) -> dict[str, tuple[float, float]]:
    """
    Batch EPSS lookup for up to 100 CVEs per API call.

    Returns {cve_id: (epss_score, epss_percentile)}.
    Results that are already cached and fresh are returned without an API call.
    Only uncached / stale CVEs are fetched.
    """
    if not cve_ids:
        return {}

    now_mono = time.monotonic()
    result: dict[str, tuple[float, float]] = {}
    to_fetch: list[str] = []

    for cve in cve_ids:
        upper = cve.upper()
        cached_at = _epss_cached_at.get(upper)
        if cached_at is not None and (now_mono - cached_at) < _EPSS_TTL_SECS and upper in _epss_cache:
            result[upper] = _epss_cache[upper]
        else:
            to_fetch.append(upper)

    if not to_fetch or _is_open("epss"):
        return result

    # Fetch in batches of 100 (API limit)
    for batch_start in range(0, len(to_fetch), 100):
        batch = to_fetch[batch_start : batch_start + 100]
        cve_param = ",".join(batch)
        try:
            async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
                resp = await client.get(
                    _EPSS_BATCH_URL,
                    params={"cve": cve_param},
                    headers={"Accept": "application/json"},
                )
                resp.raise_for_status()
                data = resp.json()
                for item in data.get("data", []):
                    cve_id = item.get("cve", "").upper()
                    score = float(item.get("epss", 0.0))
                    percentile = float(item.get("percentile", 0.0))
                    _epss_cache[cve_id] = (score, percentile)
                    _epss_cached_at[cve_id] = time.monotonic()
                    result[cve_id] = (score, percentile)
                _record_success("epss")
        except Exception as exc:
            _record_failure("epss")
            logger.warning("enrichment_service: EPSS batch fetch failed: %s", exc)
            break  # don't retry remaining batches if circuit is tripping

    return result


async def _get_cvss_v4(cve_id: str) -> tuple[Optional[float], Optional[str]]:
    """
    Fetch CVSS v4 score + vector from NVD for a single CVE.
    Also stores CVSS v3.x score as a side effect.
    Cached indefinitely.
    """
    upper = cve_id.upper()
    if upper in _cvss_v4_cache:
        return _cvss_v4_cache[upper]

    if _is_open("nvd"):
        return (None, None)

    v4_score: Optional[float] = None
    v4_vector: Optional[str] = None

    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            resp = await client.get(
                _NVD_CVE_URL,
                params={"cveId": upper},
                headers={"Accept": "application/json"},
            )
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    metrics = vulns[0].get("cve", {}).get("metrics", {})
                    v40_entries = metrics.get("cvssMetricV40", [])
                    if v40_entries:
                        cvss_data = v40_entries[0].get("cvssData", {})
                        raw_score = cvss_data.get("baseScore")
                        raw_vector = cvss_data.get("vectorString")
                        if raw_score is not None:
                            v4_score = float(raw_score)
                        if raw_vector:
                            v4_vector = str(raw_vector)
                _record_success("nvd")
    except Exception as exc:
        _record_failure("nvd")
        logger.debug("enrichment_service: NVD CVSS v4 fetch failed for %s: %s", upper, exc)

    # Cache even on miss so we don't hammer NVD for the same CVE
    if len(_cvss_v4_cache) > 8192:
        # Evict oldest 1024
        for k in list(_cvss_v4_cache.keys())[:1024]:
            del _cvss_v4_cache[k]
    _cvss_v4_cache[upper] = (v4_score, v4_vector)
    return (v4_score, v4_vector)


async def enrich_cve(cve_id: str) -> dict:
    """
    Enrich a single CVE with EPSS, KEV, and CVSS v4 data.

    Returns:
        {
            "epss_score":      float | None,
            "epss_percentile": float | None,
            "is_kev":          bool,
            "kev_date_added":  str | None,
            "cvss_v4_score":   float | None,
            "cvss_v4_vector":  str | None,
        }
    """
    upper = cve_id.upper()

    # Fan out KEV + EPSS concurrently; CVSS v4 is a separate NVD call
    import asyncio
    kev_task = asyncio.create_task(get_kev_catalog())
    epss_task = asyncio.create_task(get_epss_scores([upper]))
    cvss_task = asyncio.create_task(_get_cvss_v4(upper))

    kev_set, epss_map, (v4_score, v4_vector) = await asyncio.gather(
        kev_task, epss_task, cvss_task, return_exceptions=False
    )

    epss_pair = epss_map.get(upper)
    epss_score: Optional[float] = epss_pair[0] if epss_pair else None
    epss_percentile: Optional[float] = epss_pair[1] if epss_pair else None
    is_kev = upper in kev_set
    kev_date = _kev_date_added.get(upper) if is_kev else None

    return {
        "epss_score":      epss_score,
        "epss_percentile": epss_percentile,
        "is_kev":          is_kev,
        "kev_date_added":  kev_date,
        "cvss_v4_score":   v4_score,
        "cvss_v4_vector":  v4_vector,
    }


async def batch_enrich_cves(cve_ids: list[str]) -> dict[str, dict]:
    """
    Enrich multiple CVEs concurrently.

    Returns a mapping {cve_id: enrichment_dict} for every CVE in *cve_ids*.
    Resilient: individual failures return None fields rather than raising.
    """
    import asyncio

    if not cve_ids:
        return {}

    unique = list({c.upper() for c in cve_ids})

    # Pre-fetch KEV catalog and batch EPSS in one round-trip
    kev_set = await get_kev_catalog()
    epss_map = await get_epss_scores(unique)

    # CVSS v4 — one NVD call per CVE (with cache)
    v4_tasks = {cve: asyncio.create_task(_get_cvss_v4(cve)) for cve in unique}
    v4_results: dict[str, tuple[Optional[float], Optional[str]]] = {}
    for cve, task in v4_tasks.items():
        try:
            v4_results[cve] = await task
        except Exception:
            v4_results[cve] = (None, None)

    result: dict[str, dict] = {}
    for cve in unique:
        epss_pair = epss_map.get(cve)
        epss_score = epss_pair[0] if epss_pair else None
        epss_percentile = epss_pair[1] if epss_pair else None
        is_kev = cve in kev_set
        kev_date = _kev_date_added.get(cve) if is_kev else None
        v4_score, v4_vector = v4_results.get(cve, (None, None))
        result[cve] = {
            "epss_score":      epss_score,
            "epss_percentile": epss_percentile,
            "is_kev":          is_kev,
            "kev_date_added":  kev_date,
            "cvss_v4_score":   v4_score,
            "cvss_v4_vector":  v4_vector,
        }

    return result
