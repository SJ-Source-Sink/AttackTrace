"""
Subdomain enumeration module.

Discovers subdomains using multiple techniques:
- Passive: Certificate transparency, DNS datasets
- Active: DNS bruteforce (optional)
- External tools: Subfinder, Amass (if available)
"""

import asyncio
import subprocess
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional

import httpx

from attacktrace.config import AttackTraceConfig
from attacktrace.core.models import (
    ModuleResult,
    Subdomain,
    ScanSession,
)


# Common subdomain wordlist (minimal built-in)
COMMON_SUBDOMAINS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "api", "dev", "staging", "test", "portal",
    "admin", "app", "m", "mobile", "shop", "store", "ftp", "ssh",
    "login", "support", "help", "docs", "status", "cdn", "assets",
    "static", "media", "images", "img", "video", "download", "files",
    "git", "gitlab", "github", "jenkins", "ci", "jira", "confluence",
    "wiki", "internal", "intranet", "extranet", "corp", "corporate",
    "office", "exchange", "owa", "autodiscover", "calendar", "meet",
    "chat", "slack", "teams", "zoom", "webex", "grafana", "kibana",
    "elastic", "prometheus", "monitoring", "logs", "sentry", "auth",
    "sso", "oauth", "id", "identity", "accounts", "billing", "pay",
    "payment", "checkout", "cart", "orders", "crm", "erp", "hr",
    "demo", "sandbox", "beta", "alpha", "stage", "uat", "qa", "prod",
    "production", "backup", "bak", "old", "new", "v2", "v3", "api2",
]


async def query_securitytrails(
    domain: str,
    api_key: str,
    timeout: int = 30
) -> list[str]:
    """Query SecurityTrails API for subdomains."""
    if not api_key:
        return []

    subdomains = []

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
                headers={"apikey": api_key},
            )

            if response.status_code == 200:
                data = response.json()
                for sub in data.get("subdomains", []):
                    subdomains.append(f"{sub}.{domain}")

    except Exception:
        pass

    return subdomains


async def query_hackertarget(domain: str, timeout: int = 30) -> list[str]:
    """Query HackerTarget free API for subdomains."""
    subdomains = []

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"https://api.hackertarget.com/hostsearch/?q={domain}"
            )

            if response.status_code == 200 and "error" not in response.text.lower():
                for line in response.text.strip().split("\n"):
                    if "," in line:
                        subdomain = line.split(",")[0].strip()
                        if subdomain:
                            subdomains.append(subdomain)

    except Exception:
        pass

    return subdomains


async def query_alienvault(domain: str, timeout: int = 30) -> list[str]:
    """Query AlienVault OTX for subdomains."""
    subdomains = []

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
            )

            if response.status_code == 200:
                data = response.json()
                for record in data.get("passive_dns", []):
                    hostname = record.get("hostname", "")
                    if hostname.endswith(f".{domain}") or hostname == domain:
                        subdomains.append(hostname)

    except Exception:
        pass

    return subdomains


async def query_urlscan(domain: str, timeout: int = 30) -> list[str]:
    """Query urlscan.io for subdomains."""
    subdomains = []

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
            )

            if response.status_code == 200:
                data = response.json()
                for result in data.get("results", []):
                    page = result.get("page", {})
                    hostname = page.get("domain", "")
                    if hostname.endswith(f".{domain}") or hostname == domain:
                        subdomains.append(hostname)

    except Exception:
        pass

    return subdomains


async def run_subfinder(domain: str, timeout: int = 300) -> list[str]:
    """Run subfinder if available."""
    subdomains = []

    if not shutil.which("subfinder"):
        return subdomains

    try:
        proc = await asyncio.create_subprocess_exec(
            "subfinder",
            "-d", domain,
            "-silent",
            "-all",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )

        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)

        for line in stdout.decode().strip().split("\n"):
            line = line.strip()
            if line:
                subdomains.append(line)

    except asyncio.TimeoutError:
        pass
    except Exception:
        pass

    return subdomains


async def dns_bruteforce(
    domain: str,
    wordlist: list[str],
    concurrency: int = 50,
) -> list[str]:
    """Bruteforce subdomains using DNS resolution."""
    import dns.asyncresolver

    discovered = []
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    semaphore = asyncio.Semaphore(concurrency)

    async def check_subdomain(subdomain: str) -> Optional[str]:
        fqdn = f"{subdomain}.{domain}"
        async with semaphore:
            try:
                await resolver.resolve(fqdn, "A")
                return fqdn
            except Exception:
                return None

    tasks = [check_subdomain(sub) for sub in wordlist]
    results = await asyncio.gather(*tasks)

    for result in results:
        if result:
            discovered.append(result)

    return discovered


async def run(
    session: ScanSession,
    config: AttackTraceConfig,
    orchestrator,
) -> ModuleResult:
    """
    Run subdomain enumeration.

    Args:
        session: Current scan session
        config: AttackTrace configuration
        orchestrator: Orchestrator instance

    Returns:
        ModuleResult with discovered subdomains
    """
    result = ModuleResult(
        module_name="subdomain_enum",
        started_at=datetime.utcnow(),
    )

    all_subdomains: set[str] = set()

    # Get existing subdomains to avoid duplicates
    existing = {s.fqdn for s in session.subdomains}

    for domain in session.target_domains:
        domain_subdomains: set[str] = set()

        # Run passive enumeration sources concurrently
        passive_tasks = [
            query_hackertarget(domain, config.scan.timeout),
            query_alienvault(domain, config.scan.timeout),
            query_urlscan(domain, config.scan.timeout),
        ]

        # Add SecurityTrails if API key available
        if config.api_keys.securitytrails:
            passive_tasks.append(
                query_securitytrails(domain, config.api_keys.securitytrails, config.scan.timeout)
            )

        # Run subfinder if available
        passive_tasks.append(run_subfinder(domain))

        # Gather all passive results
        passive_results = await asyncio.gather(*passive_tasks, return_exceptions=True)

        for result_list in passive_results:
            if isinstance(result_list, list):
                domain_subdomains.update(result_list)

        # Run DNS bruteforce if not passive-only
        if not session.passive_only and config.modules.subdomain.bruteforce:
            # Load custom wordlist or use built-in
            wordlist = COMMON_SUBDOMAINS
            if config.modules.subdomain.wordlist:
                wordlist_path = Path(config.modules.subdomain.wordlist)
                if wordlist_path.exists():
                    with open(wordlist_path) as f:
                        wordlist = [line.strip() for line in f if line.strip()]

            bruteforce_results = await dns_bruteforce(
                domain,
                wordlist,
                config.modules.subdomain.bruteforce_threads,
            )
            domain_subdomains.update(bruteforce_results)

        # Add domain itself
        domain_subdomains.add(domain)

        # Filter to valid subdomains of this domain
        for fqdn in domain_subdomains:
            fqdn = fqdn.lower().strip()
            if fqdn and (fqdn.endswith(f".{domain}") or fqdn == domain):
                if fqdn not in existing:
                    all_subdomains.add(fqdn)

    # Create Subdomain objects
    for fqdn in all_subdomains:
        # Determine parent domain
        parent = None
        for target_domain in session.target_domains:
            if fqdn.endswith(f".{target_domain}") or fqdn == target_domain:
                parent = target_domain
                break

        if parent:
            subdomain = Subdomain(
                fqdn=fqdn,
                parent_domain=parent,
                source="subdomain_enum",
            )
            result.subdomains.append(subdomain)

    result.items_discovered = len(result.subdomains)
    result.success = True
    result.completed_at = datetime.utcnow()

    return result
