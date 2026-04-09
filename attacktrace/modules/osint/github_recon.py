"""
GitHub reconnaissance module.

Discovers:
- Organization repositories
- Employee commits and emails
- Leaked secrets in code
- Internal URLs and endpoints
- Technology stack indicators
"""

import asyncio
import re
from datetime import datetime
from typing import Optional
from urllib.parse import quote

import httpx

from attacktrace.config import AttackTraceConfig
from attacktrace.core.models import (
    ModuleResult,
    Finding,
    Severity,
    ScanSession,
)


# Patterns for secret detection in code
SECRET_PATTERNS = [
    # API Keys
    (r'(?i)(api[_-]?key|apikey)["\s:=]+["\']?([a-zA-Z0-9_\-]{20,})["\']?', "API Key", Severity.HIGH),
    (r'(?i)(secret[_-]?key|secretkey)["\s:=]+["\']?([a-zA-Z0-9_\-]{20,})["\']?', "Secret Key", Severity.HIGH),
    (r'(?i)(access[_-]?token|accesstoken)["\s:=]+["\']?([a-zA-Z0-9_\-]{20,})["\']?', "Access Token", Severity.HIGH),

    # AWS
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID", Severity.CRITICAL),
    (r'(?i)aws[_-]?secret[_-]?access[_-]?key["\s:=]+["\']?([a-zA-Z0-9/+=]{40})["\']?', "AWS Secret Key", Severity.CRITICAL),

    # Private Keys
    (r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', "Private Key", Severity.CRITICAL),
    (r'-----BEGIN PGP PRIVATE KEY BLOCK-----', "PGP Private Key", Severity.CRITICAL),

    # Database
    (r'(?i)(mysql|postgres|mongodb|redis)://[^\s<>"]+:[^\s<>"]+@[^\s<>"]+', "Database Connection String", Severity.CRITICAL),
    (r'(?i)(db[_-]?password|database[_-]?password)["\s:=]+["\']?([^\s"\']{8,})["\']?', "Database Password", Severity.HIGH),

    # Cloud
    (r'(?i)(azure[_-]?storage[_-]?key|storage[_-]?account[_-]?key)["\s:=]+["\']?([a-zA-Z0-9/+=]{40,})["\']?', "Azure Storage Key", Severity.CRITICAL),
    (r'(?i)(gcp[_-]?api[_-]?key|google[_-]?api[_-]?key)["\s:=]+["\']?([a-zA-Z0-9_\-]{20,})["\']?', "GCP API Key", Severity.HIGH),

    # Auth
    (r'(?i)(password|passwd|pwd)["\s:=]+["\']?([^\s"\']{8,})["\']?', "Hardcoded Password", Severity.HIGH),
    (r'(?i)(jwt[_-]?secret|jwt[_-]?key)["\s:=]+["\']?([a-zA-Z0-9_\-]{20,})["\']?', "JWT Secret", Severity.HIGH),
    (r'(?i)(auth[_-]?token|bearer[_-]?token)["\s:=]+["\']?([a-zA-Z0-9_\-\.]{20,})["\']?', "Auth Token", Severity.HIGH),

    # Slack/Discord
    (r'xox[baprs]-[0-9a-zA-Z]{10,}', "Slack Token", Severity.HIGH),
    (r'(?i)discord[_-]?token["\s:=]+["\']?([a-zA-Z0-9_\-\.]{50,})["\']?', "Discord Token", Severity.HIGH),

    # Stripe
    (r'sk_live_[0-9a-zA-Z]{24}', "Stripe Secret Key", Severity.CRITICAL),
    (r'pk_live_[0-9a-zA-Z]{24}', "Stripe Publishable Key", Severity.MEDIUM),

    # Generic
    (r'(?i)(client[_-]?secret)["\s:=]+["\']?([a-zA-Z0-9_\-]{20,})["\']?', "Client Secret", Severity.HIGH),
    (r'(?i)(private[_-]?key)["\s:=]+["\']?([a-zA-Z0-9_\-/+=]{20,})["\']?', "Private Key Value", Severity.HIGH),
]

# Patterns for internal URLs
URL_PATTERNS = [
    r'https?://[a-zA-Z0-9\-]+\.internal\.[a-zA-Z0-9\-\.]+',
    r'https?://[a-zA-Z0-9\-]+\.corp\.[a-zA-Z0-9\-\.]+',
    r'https?://[a-zA-Z0-9\-]+\.local[a-zA-Z0-9\-\.]*',
    r'https?://localhost:[0-9]+[/a-zA-Z0-9\-_\.]*',
    r'https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[:/][^\s<>"\']+',
    r'https?://[a-zA-Z0-9\-]+\.dev\.[a-zA-Z0-9\-\.]+',
    r'https?://[a-zA-Z0-9\-]+\.staging\.[a-zA-Z0-9\-\.]+',
    r'https?://[a-zA-Z0-9\-]+\.test\.[a-zA-Z0-9\-\.]+',
]


async def search_github_org(
    org_name: str,
    token: Optional[str] = None,
    timeout: float = 30.0,
) -> dict:
    """
    Get GitHub organization information.
    """
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "AttackTrace-Scanner/1.0",
    }
    if token:
        headers["Authorization"] = f"token {token}"

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"https://api.github.com/orgs/{quote(org_name)}",
                headers=headers,
            )
            if response.status_code == 200:
                return response.json()
    except Exception:
        pass

    return {}


async def get_org_repos(
    org_name: str,
    token: Optional[str] = None,
    timeout: float = 30.0,
    max_repos: int = 100,
) -> list[dict]:
    """
    Get repositories for a GitHub organization.
    """
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "AttackTrace-Scanner/1.0",
    }
    if token:
        headers["Authorization"] = f"token {token}"

    repos = []
    page = 1

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            while len(repos) < max_repos:
                response = await client.get(
                    f"https://api.github.com/orgs/{quote(org_name)}/repos",
                    headers=headers,
                    params={"per_page": 100, "page": page, "type": "all"},
                )

                if response.status_code != 200:
                    break

                page_repos = response.json()
                if not page_repos:
                    break

                repos.extend(page_repos)
                page += 1

                if len(page_repos) < 100:
                    break

                await asyncio.sleep(0.5)

    except Exception:
        pass

    return repos[:max_repos]


async def get_repo_commits(
    owner: str,
    repo: str,
    token: Optional[str] = None,
    timeout: float = 30.0,
    max_commits: int = 100,
) -> list[dict]:
    """
    Get recent commits for a repository.
    """
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "AttackTrace-Scanner/1.0",
    }
    if token:
        headers["Authorization"] = f"token {token}"

    commits = []

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"https://api.github.com/repos/{quote(owner)}/{quote(repo)}/commits",
                headers=headers,
                params={"per_page": min(max_commits, 100)},
            )

            if response.status_code == 200:
                commits = response.json()

    except Exception:
        pass

    return commits[:max_commits]


async def search_code_for_secrets(
    query: str,
    token: Optional[str] = None,
    timeout: float = 30.0,
) -> list[dict]:
    """
    Search GitHub code for potential secrets.
    Note: Requires authentication for code search.
    """
    if not token:
        return []

    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"token {token}",
        "User-Agent": "AttackTrace-Scanner/1.0",
    }

    results = []

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                "https://api.github.com/search/code",
                headers=headers,
                params={"q": query, "per_page": 50},
            )

            if response.status_code == 200:
                data = response.json()
                results = data.get("items", [])

    except Exception:
        pass

    return results


async def search_github_users(
    company: str,
    domain: str,
    token: Optional[str] = None,
    timeout: float = 30.0,
) -> list[dict]:
    """
    Search for GitHub users associated with a company.
    """
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "AttackTrace-Scanner/1.0",
    }
    if token:
        headers["Authorization"] = f"token {token}"

    users = []

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            # Search by company name
            response = await client.get(
                "https://api.github.com/search/users",
                headers=headers,
                params={"q": f'"{company}" in:company', "per_page": 50},
            )

            if response.status_code == 200:
                data = response.json()
                users.extend(data.get("items", []))

            await asyncio.sleep(1)  # Rate limiting

            # Search by email domain
            if domain:
                response = await client.get(
                    "https://api.github.com/search/users",
                    headers=headers,
                    params={"q": f"{domain} in:email", "per_page": 50},
                )

                if response.status_code == 200:
                    data = response.json()
                    for user in data.get("items", []):
                        if user not in users:
                            users.append(user)

    except Exception:
        pass

    return users


async def get_user_details(
    username: str,
    token: Optional[str] = None,
    timeout: float = 30.0,
) -> dict:
    """
    Get detailed information about a GitHub user.
    """
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "AttackTrace-Scanner/1.0",
    }
    if token:
        headers["Authorization"] = f"token {token}"

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"https://api.github.com/users/{quote(username)}",
                headers=headers,
            )

            if response.status_code == 200:
                return response.json()

    except Exception:
        pass

    return {}


def extract_emails_from_commits(commits: list[dict]) -> set[str]:
    """
    Extract email addresses from commit data.
    """
    emails = set()

    for commit in commits:
        commit_data = commit.get("commit", {})

        author = commit_data.get("author", {})
        if author and author.get("email"):
            email = author["email"]
            # Filter out noreply and bot emails
            if not any(x in email.lower() for x in ["noreply", "users.noreply", "bot@", "action@"]):
                emails.add(email)

        committer = commit_data.get("committer", {})
        if committer and committer.get("email"):
            email = committer["email"]
            if not any(x in email.lower() for x in ["noreply", "users.noreply", "bot@", "action@"]):
                emails.add(email)

    return emails


def scan_content_for_secrets(content: str, source: str) -> list[Finding]:
    """
    Scan content for leaked secrets.
    """
    findings = []

    for pattern, secret_type, severity in SECRET_PATTERNS:
        matches = re.finditer(pattern, content)
        for match in matches:
            # Avoid false positives
            matched_text = match.group(0)
            if len(matched_text) > 200:  # Too long, probably false positive
                continue
            if "example" in matched_text.lower() or "placeholder" in matched_text.lower():
                continue

            finding = Finding(
                title=f"Potential {secret_type} exposed in {source}",
                description=f"Found potential {secret_type} in code. This should be reviewed and rotated if valid.",
                severity=severity,
                category="secret_exposure",
                affected_asset=source,
                affected_asset_type="code",
                evidence=matched_text[:100] + "..." if len(matched_text) > 100 else matched_text,
                source="github_recon",
            )
            findings.append(finding)

    return findings


def extract_internal_urls(content: str) -> set[str]:
    """
    Extract internal/development URLs from content.
    """
    urls = set()

    for pattern in URL_PATTERNS:
        matches = re.finditer(pattern, content, re.IGNORECASE)
        for match in matches:
            urls.add(match.group(0))

    return urls


async def run(
    session: ScanSession,
    config: AttackTraceConfig,
    orchestrator,
) -> ModuleResult:
    """
    Run GitHub reconnaissance.
    """
    result = ModuleResult(
        module_name="github_recon",
        started_at=datetime.utcnow(),
    )

    token = config.api_keys.github if hasattr(config.api_keys, 'github') else None

    # Determine org names to search
    org_names = []
    if session.target_company:
        # Convert company name to potential GitHub org names
        company_clean = re.sub(r'[^a-zA-Z0-9]', '', session.target_company.lower())
        company_hyphen = re.sub(r'[^a-zA-Z0-9]', '-', session.target_company.lower()).strip('-')
        org_names.extend([company_clean, company_hyphen, session.target_company])

    # Also check domain-based org names
    for domain in session.target_domains:
        domain_name = domain.split('.')[0]
        if domain_name not in org_names:
            org_names.append(domain_name)

    discovered_repos = []
    discovered_emails = set()
    discovered_users = []
    internal_urls = set()
    items_discovered = 0

    # Search for organizations
    for org_name in org_names[:5]:  # Limit org searches
        org_info = await search_github_org(org_name, token, config.scan.timeout)

        if org_info and org_info.get("login"):
            items_discovered += 1

            # Create finding for discovered org
            finding = Finding(
                title=f"GitHub organization found: {org_info['login']}",
                description=f"GitHub organization '{org_info['login']}' appears to belong to target. "
                           f"Public repos: {org_info.get('public_repos', 0)}. "
                           f"Description: {org_info.get('description', 'N/A')}",
                severity=Severity.INFO,
                category="osint",
                affected_asset=f"https://github.com/{org_info['login']}",
                affected_asset_type="github_org",
                source="github_recon",
            )
            result.findings.append(finding)

            # Get organization repos
            repos = await get_org_repos(org_info["login"], token, config.scan.timeout)

            for repo in repos:
                repo_info = {
                    "name": repo.get("name"),
                    "full_name": repo.get("full_name"),
                    "url": repo.get("html_url"),
                    "description": repo.get("description", ""),
                    "language": repo.get("language", ""),
                    "stars": repo.get("stargazers_count", 0),
                    "forks": repo.get("forks_count", 0),
                    "is_private": repo.get("private", False),
                    "created_at": repo.get("created_at", ""),
                    "updated_at": repo.get("updated_at", ""),
                }
                discovered_repos.append(repo_info)
                items_discovered += 1

                # Get commits for email extraction
                commits = await get_repo_commits(
                    org_info["login"],
                    repo["name"],
                    token,
                    config.scan.timeout,
                    max_commits=50,
                )

                emails = extract_emails_from_commits(commits)
                discovered_emails.update(emails)

                await asyncio.sleep(0.3)  # Rate limiting

            await asyncio.sleep(1)

    # Search for users by company
    if session.target_company:
        domain = session.target_domains[0] if session.target_domains else ""
        users = await search_github_users(
            session.target_company,
            domain,
            token,
            config.scan.timeout,
        )

        for user in users[:30]:  # Limit user lookups
            user_details = await get_user_details(user["login"], token, config.scan.timeout)

            if user_details:
                user_info = {
                    "username": user_details.get("login"),
                    "name": user_details.get("name", ""),
                    "email": user_details.get("email", ""),
                    "company": user_details.get("company", ""),
                    "location": user_details.get("location", ""),
                    "bio": user_details.get("bio", ""),
                    "public_repos": user_details.get("public_repos", 0),
                    "url": user_details.get("html_url"),
                }
                discovered_users.append(user_info)

                if user_info["email"]:
                    discovered_emails.add(user_info["email"])

                items_discovered += 1

            await asyncio.sleep(0.5)

    # Search for secrets in code (requires token)
    if token and session.target_domains:
        for domain in session.target_domains[:3]:
            # Search for domain references
            search_queries = [
                f'"{domain}" password',
                f'"{domain}" api_key',
                f'"{domain}" secret',
                f'"{domain}" token',
            ]

            for query in search_queries:
                code_results = await search_code_for_secrets(query, token, config.scan.timeout)

                for item in code_results[:10]:
                    repo_name = item.get("repository", {}).get("full_name", "unknown")
                    file_path = item.get("path", "unknown")

                    # Note: We can't get file content from search results
                    # Just flag that there are references
                    finding = Finding(
                        title=f"Potential sensitive reference in {repo_name}",
                        description=f"Code search found references to '{domain}' with sensitive keywords "
                                   f"in file: {file_path}. Manual review recommended.",
                        severity=Severity.MEDIUM,
                        category="secret_exposure",
                        affected_asset=f"https://github.com/{repo_name}",
                        affected_asset_type="code",
                        evidence=f"File: {file_path}",
                        source="github_recon",
                    )
                    result.findings.append(finding)

                await asyncio.sleep(2)  # Heavy rate limiting for code search

    # Create finding for discovered emails
    if discovered_emails:
        # Filter emails by target domain
        target_emails = set()
        other_emails = set()

        for email in discovered_emails:
            domain = email.split('@')[-1].lower()
            if any(d in domain for d in [d.lower() for d in session.target_domains]):
                target_emails.add(email)
            else:
                other_emails.add(email)

        if target_emails:
            finding = Finding(
                title=f"Discovered {len(target_emails)} employee emails from GitHub commits",
                description=f"Email addresses found in Git commits. These can be used for phishing or credential stuffing attacks.",
                severity=Severity.MEDIUM,
                category="osint",
                affected_asset=session.target_company or session.target_domains[0],
                affected_asset_type="organization",
                evidence=", ".join(list(target_emails)[:20]),
                source="github_recon",
            )
            result.findings.append(finding)

    # Store in session metadata for report
    session.github_data = {
        "repos": discovered_repos,
        "users": discovered_users,
        "emails": list(discovered_emails),
        "internal_urls": list(internal_urls),
    }

    result.items_discovered = items_discovered
    result.success = True
    result.completed_at = datetime.utcnow()

    return result
