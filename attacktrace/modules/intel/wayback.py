"""
Wayback Machine integration module.

Discovers:
- Historical snapshots
- Old endpoints and paths
- Removed pages
- JavaScript files with secrets
- Old API endpoints
"""

import asyncio
import re
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

import httpx

from attacktrace.config import AttackTraceConfig
from attacktrace.core.models import (
    ModuleResult,
    Finding,
    Severity,
    ScanSession,
)


async def get_snapshots(
    domain: str,
    timeout: float = 30.0,
) -> list[str]:
    """
    Get all archived URLs for a domain from Wayback Machine.
    """
    urls = []

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"https://web.archive.org/cdx/search/cdx",
                params={
                    "url": f"*.{domain}/*",
                    "output": "text",
                    "fl": "original",
                    "collapse": "urlkey",
                    "limit": "5000",
                },
            )

            if response.status_code == 200:
                urls = response.text.strip().split("\n")
                urls = [u for u in urls if u]

    except Exception:
        pass

    return urls


def extract_interesting_urls(urls: list[str]) -> dict:
    """
    Categorize URLs into interesting findings.
    """
    results = {
        "api_endpoints": [],
        "admin_panels": [],
        "config_files": [],
        "backup_files": [],
        "js_files": [],
        "sensitive_paths": [],
        "subdomains": set(),
    }

    # Patterns for interesting files
    patterns = {
        "api_endpoints": [
            r"/api/", r"/v1/", r"/v2/", r"/v3/",
            r"/graphql", r"/rest/", r"/json/",
        ],
        "admin_panels": [
            r"/admin", r"/administrator", r"/wp-admin",
            r"/manager", r"/dashboard", r"/portal",
            r"/cpanel", r"/phpmyadmin", r"/adminer",
        ],
        "config_files": [
            r"\.env$", r"\.config$", r"config\.", r"settings\.",
            r"\.ini$", r"\.conf$", r"\.yaml$", r"\.yml$",
            r"web\.config", r"\.htaccess", r"\.htpasswd",
        ],
        "backup_files": [
            r"\.bak$", r"\.backup$", r"\.old$", r"\.orig$",
            r"\.sql$", r"\.dump$", r"\.tar\.gz$", r"\.zip$",
            r"~$", r"\.swp$", r"\.save$",
        ],
        "js_files": [
            r"\.js$", r"\.min\.js$", r"bundle\.js",
            r"app\.js", r"main\.js", r"config\.js",
        ],
        "sensitive_paths": [
            r"/\.git", r"/\.svn", r"/\.hg",
            r"/debug", r"/trace", r"/test",
            r"/backup", r"/dump", r"/export",
            r"/internal", r"/private", r"/secret",
            r"phpinfo", r"info\.php", r"test\.php",
        ],
    }

    for url in urls:
        try:
            parsed = urlparse(url)
            path = parsed.path.lower()

            # Extract subdomains
            results["subdomains"].add(parsed.netloc)

            # Check patterns
            for category, pattern_list in patterns.items():
                for pattern in pattern_list:
                    if re.search(pattern, path, re.IGNORECASE):
                        if url not in results[category]:
                            results[category].append(url)
                        break

        except Exception:
            continue

    results["subdomains"] = list(results["subdomains"])
    return results


async def run(
    session: ScanSession,
    config: AttackTraceConfig,
    orchestrator,
) -> ModuleResult:
    """
    Run Wayback Machine reconnaissance.
    """
    result = ModuleResult(
        module_name="wayback",
        started_at=datetime.utcnow(),
    )

    all_urls = []
    categorized = {
        "api_endpoints": [],
        "admin_panels": [],
        "config_files": [],
        "backup_files": [],
        "js_files": [],
        "sensitive_paths": [],
        "subdomains": [],
    }

    for domain in session.target_domains:
        urls = await get_snapshots(domain, config.scan.timeout)
        all_urls.extend(urls)

        if urls:
            extracted = extract_interesting_urls(urls)

            for key in categorized:
                if key == "subdomains":
                    categorized[key].extend(extracted[key])
                else:
                    categorized[key].extend(extracted[key][:50])  # Limit per category

        await asyncio.sleep(1)

    # Deduplicate
    for key in categorized:
        categorized[key] = list(set(categorized[key]))

    # Store data
    if not hasattr(session, 'wayback_data'):
        session.wayback_data = {}
    session.wayback_data = {
        "total_urls": len(all_urls),
        **categorized,
    }

    result.items_discovered = len(all_urls)

    # Create findings
    if categorized["config_files"]:
        finding = Finding(
            title=f"Archived configuration files found ({len(categorized['config_files'])})",
            description="Wayback Machine has archived configuration files that may contain secrets.",
            severity=Severity.HIGH,
            category="information_disclosure",
            affected_asset=session.target_domains[0],
            affected_asset_type="domain",
            evidence="\n".join(categorized["config_files"][:10]),
            source="wayback",
        )
        result.findings.append(finding)

    if categorized["backup_files"]:
        finding = Finding(
            title=f"Archived backup files found ({len(categorized['backup_files'])})",
            description="Backup files in Wayback Machine may contain sensitive data.",
            severity=Severity.HIGH,
            category="information_disclosure",
            affected_asset=session.target_domains[0],
            affected_asset_type="domain",
            evidence="\n".join(categorized["backup_files"][:10]),
            source="wayback",
        )
        result.findings.append(finding)

    if categorized["sensitive_paths"]:
        finding = Finding(
            title=f"Sensitive paths archived ({len(categorized['sensitive_paths'])})",
            description="Git repos, debug pages, and other sensitive paths found in archives.",
            severity=Severity.MEDIUM,
            category="information_disclosure",
            affected_asset=session.target_domains[0],
            affected_asset_type="domain",
            evidence="\n".join(categorized["sensitive_paths"][:10]),
            source="wayback",
        )
        result.findings.append(finding)

    if categorized["api_endpoints"]:
        finding = Finding(
            title=f"API endpoints discovered ({len(categorized['api_endpoints'])})",
            description="Historical API endpoints found that may still be active.",
            severity=Severity.INFO,
            category="reconnaissance",
            affected_asset=session.target_domains[0],
            affected_asset_type="domain",
            evidence="\n".join(categorized["api_endpoints"][:10]),
            source="wayback",
        )
        result.findings.append(finding)

    result.success = True
    result.completed_at = datetime.utcnow()
    return result
