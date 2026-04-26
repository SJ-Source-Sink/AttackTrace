"""
Historical URL and parameter discovery service.

Uses gau (GetAllUrls) and/or waybackurls to surface historical URLs
from the Wayback Machine and other sources, extracting query parameters
to identify injectable endpoints.
"""

import asyncio
import shutil
from urllib.parse import urlparse, parse_qs


async def run_url_discovery(target_domain: str) -> list[dict]:
    """Run gau and/or waybackurls to find historical URLs.
    Returns list of {url, params: list[str], source}
    """
    results = []

    # Try gau
    gau = shutil.which("gau") or shutil.which("gau-offline")
    if gau:
        try:
            proc = await asyncio.create_subprocess_exec(
                gau, target_domain, "--threads", "5", "--timeout", "30",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            for line in stdout.decode().splitlines():
                line = line.strip()
                if line and line.startswith("http"):
                    params = _extract_params(line)
                    results.append({"url": line, "params": params, "source": "gau"})
        except Exception:
            pass

    # Try waybackurls
    wayback = shutil.which("waybackurls")
    if wayback:
        try:
            proc = await asyncio.create_subprocess_exec(
                wayback, target_domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            for line in stdout.decode().splitlines():
                line = line.strip()
                if line and line.startswith("http"):
                    params = _extract_params(line)
                    results.append({"url": line, "params": params, "source": "waybackurls"})
        except Exception:
            pass

    # Deduplicate by URL
    seen = set()
    deduped = []
    for r in results:
        if r["url"] not in seen:
            seen.add(r["url"])
            deduped.append(r)
    return deduped[:2000]  # Cap at 2000 URLs


def _extract_params(url: str) -> list[str]:
    try:
        parsed = urlparse(url)
        return list(parse_qs(parsed.query).keys())
    except Exception:
        return []
