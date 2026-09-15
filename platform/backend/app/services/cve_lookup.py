"""
Best-effort, bounded lookup of recent/severe CVEs for a detected technology
name, against NVD's public REST API — lightweight RAG-style grounding for
the Attack Suite AI Agent so it can reason about specific, real, current
vulnerabilities for a target's actual tech stack instead of only generic
tradecraft from its training data.

Deliberately NOT precise CPE version-range matching (that needs a much
heavier CPE-match integration) — this is a free-text keyword search against
NVD, sorted by severity/recency, clearly framed to the model as "potentially
relevant" rather than "confirmed applicable." Still real grounding value: a
model reasoning about "nginx" in the abstract vs. one shown 5 real, recent,
high-severity nginx CVEs with descriptions will prioritize differently.

Must never block or break an agent run: every failure mode (network error,
timeout, rate limit, malformed response) is caught and returns an empty
list, silently. No API key is configured (NVD's public rate limit without
one is low — ~5 req/30s), so this is called at most once or twice per run,
never per turn.
"""
from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_TIMEOUT = 6.0
_RESULTS_PER_PAGE = 20


async def lookup_recent_cves(tech: str, limit: int = 5) -> list[dict]:
    """Best-effort: up to `limit` real CVEs for `tech`, sorted by severity
    then recency. Returns [] on any failure — never raises."""
    if not tech or not tech.strip():
        return []
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                _NVD_URL,
                params={"keywordSearch": tech.strip(), "resultsPerPage": _RESULTS_PER_PAGE},
                headers={"User-Agent": "AttackTrace-Platform/1.0"},
            )
        if resp.status_code != 200:
            logger.info(f"CVE lookup for {tech!r} returned HTTP {resp.status_code}, skipping")
            return []
        data = resp.json()
    except Exception as exc:
        logger.info(f"CVE lookup for {tech!r} failed (non-fatal, continuing without it): {exc}")
        return []

    items = []
    for vuln in data.get("vulnerabilities", []):
        try:
            cve = vuln["cve"]
            cve_id = cve["id"]
            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
            )
            metrics = cve.get("metrics", {})
            cvss_score = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    cvss_score = metrics[key][0]["cvssData"]["baseScore"]
                    break
            items.append({
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "published": (cve.get("published") or "")[:10],
                "description": desc[:280],
            })
        except (KeyError, IndexError, TypeError):
            continue

    items.sort(key=lambda x: (x["cvss_score"] or 0, x["published"]), reverse=True)
    return items[:limit]
