"""
Employee discovery module.

Discovers employees and their information through:
- Collecting ALL emails with company domain from multiple sources
- Hunter.io API for email enrichment
- GitHub user discovery
- Web scraping discovered pages
- Certificate transparency emails
- Breach database searches
- Then mapping emails back to employee identities
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


# Common email patterns used by organizations (used for reverse mapping)
EMAIL_PATTERNS = [
    "{first}.{last}",           # john.doe@company.com
    "{first}{last}",            # johndoe@company.com
    "{f}{last}",                # jdoe@company.com
    "{first}_{last}",           # john_doe@company.com
    "{first}-{last}",           # john-doe@company.com
    "{last}.{first}",           # doe.john@company.com
    "{last}{first}",            # doejohn@company.com
    "{last}{f}",                # doej@company.com
    "{first}",                  # john@company.com
    "{last}",                   # doe@company.com
    "{f}.{last}",               # j.doe@company.com
    "{first}.{l}",              # john.d@company.com
    "{f}{l}",                   # jd@company.com
]

# Generic/non-personal email prefixes to classify
GENERIC_EMAIL_PREFIXES = {
    "info", "contact", "support", "help", "sales", "admin", "administrator",
    "webmaster", "postmaster", "hostmaster", "abuse", "noreply", "no-reply",
    "donotreply", "do-not-reply", "marketing", "hr", "careers", "jobs",
    "press", "media", "pr", "legal", "billing", "accounts", "accounting",
    "finance", "security", "privacy", "compliance", "feedback", "enquiries",
    "enquiry", "hello", "hi", "team", "office", "reception", "general",
    "service", "services", "customerservice", "customer-service", "orders",
    "shipping", "returns", "newsletter", "subscribe", "unsubscribe",
}


async def query_hunter_domain(
    domain: str,
    api_key: str,
    timeout: float = 30.0,
) -> dict:
    """
    Query Hunter.io for domain email information.
    """
    if not api_key:
        return {}

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                "https://api.hunter.io/v2/domain-search",
                params={
                    "domain": domain,
                    "api_key": api_key,
                    "limit": 100,
                },
            )

            if response.status_code == 200:
                return response.json().get("data", {})

    except Exception:
        pass

    return {}


async def query_hunter_email_finder(
    domain: str,
    first_name: str,
    last_name: str,
    api_key: str,
    timeout: float = 30.0,
) -> dict:
    """
    Find specific email using Hunter.io.
    """
    if not api_key:
        return {}

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                "https://api.hunter.io/v2/email-finder",
                params={
                    "domain": domain,
                    "first_name": first_name,
                    "last_name": last_name,
                    "api_key": api_key,
                },
            )

            if response.status_code == 200:
                return response.json().get("data", {})

    except Exception:
        pass

    return {}


async def query_clearbit_company(
    domain: str,
    timeout: float = 30.0,
) -> dict:
    """
    Query Clearbit for company information (free tier).
    """
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"https://company.clearbit.com/v2/companies/find",
                params={"domain": domain},
            )

            if response.status_code == 200:
                return response.json()

    except Exception:
        pass

    return {}


async def search_phonebook_cz(
    domain: str,
    timeout: float = 30.0,
) -> list[str]:
    """
    Search phonebook.cz for emails (IntelX service).
    Note: Requires API key for full access.
    """
    emails = []

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            # This is a simplified version - full access requires API
            response = await client.get(
                f"https://phonebook.cz/api/v1/search",
                params={"term": domain, "type": "email"},
            )

            if response.status_code == 200:
                data = response.json()
                emails = data.get("emails", [])

    except Exception:
        pass

    return emails


async def search_emailrep(
    email: str,
    timeout: float = 30.0,
) -> dict:
    """
    Check email reputation and verify existence.
    """
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"https://emailrep.io/{quote(email)}",
                headers={"Accept": "application/json"},
            )

            if response.status_code == 200:
                return response.json()

    except Exception:
        pass

    return {}


async def discover_from_google_dorks(
    domain: str,
    timeout: float = 30.0,
) -> list[dict]:
    """
    Discover employees using search engine patterns.
    Note: This is a placeholder - actual implementation would need
    to use a search API or scraping service.
    """
    # Common patterns that reveal employee info:
    # site:linkedin.com/in "works at {company}"
    # site:{domain} "@{domain}" filetype:pdf
    # site:github.com "{domain}" in:email

    # For now, return empty as this requires external APIs
    return []


async def discover_from_breach_data(
    domain: str,
    timeout: float = 30.0,
) -> list[str]:
    """
    Check for emails in known breach databases.
    Note: Uses Have I Been Pwned API if available.
    """
    # HIBP requires API key and doesn't support domain-wide searches
    # This would need to be implemented with a paid breach data service
    return []


async def collect_emails_from_web_pages(
    urls: list[str],
    domain: str,
    timeout: float = 10.0,
    max_pages: int = 50,
) -> set[str]:
    """
    Scrape discovered web pages for email addresses with the target domain.

    Args:
        urls: List of web application URLs to scrape
        domain: Target domain to filter emails
        timeout: Request timeout
        max_pages: Maximum pages to scrape

    Returns:
        Set of discovered email addresses
    """
    emails = set()
    email_pattern = re.compile(
        r'[a-zA-Z0-9._%+-]+@' + re.escape(domain),
        re.IGNORECASE
    )

    # Also match subdomains
    subdomain_pattern = re.compile(
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]*\.' + re.escape(domain),
        re.IGNORECASE
    )

    async def fetch_page(url: str) -> set[str]:
        page_emails = set()
        try:
            async with httpx.AsyncClient(
                timeout=timeout,
                verify=False,
                follow_redirects=True
            ) as client:
                response = await client.get(url)
                if response.status_code == 200:
                    content = response.text

                    # Find emails matching domain
                    for match in email_pattern.finditer(content):
                        email = match.group(0).lower()
                        page_emails.add(email)

                    # Find emails matching subdomains
                    for match in subdomain_pattern.finditer(content):
                        email = match.group(0).lower()
                        page_emails.add(email)

        except Exception:
            pass
        return page_emails

    # Process pages with concurrency limit
    semaphore = asyncio.Semaphore(10)

    async def fetch_with_limit(url: str) -> set[str]:
        async with semaphore:
            return await fetch_page(url)

    tasks = [fetch_with_limit(url) for url in urls[:max_pages]]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, set):
            emails.update(result)

    return emails


async def collect_emails_from_certificates(
    domains: list[str],
    certificates: list,
) -> set[str]:
    """
    Extract email addresses from certificate data.
    Certificates sometimes contain admin/contact emails.
    """
    emails = set()

    for cert in certificates:
        # Check subject fields
        subject = getattr(cert, 'subject', {}) or {}
        if isinstance(subject, dict):
            email = subject.get('emailAddress', '') or subject.get('email', '')
            if email and any(d in email.lower() for d in domains):
                emails.add(email.lower())

        # Check SAN (Subject Alternative Names) for email addresses
        san = getattr(cert, 'san', []) or []
        for name in san:
            if '@' in name and any(d in name.lower() for d in domains):
                emails.add(name.lower())

    return emails


async def query_dehashed_emails(
    domain: str,
    api_key: str,
    email: str,
    timeout: float = 30.0,
) -> list[str]:
    """
    Query DeHashed for emails with the target domain.
    Returns list of emails found in breach data.
    """
    if not api_key or not email:
        return []

    emails = []
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                "https://api.dehashed.com/search",
                params={"query": f"email_domain:{domain}"},
                auth=(email, api_key),
                headers={"Accept": "application/json"},
            )

            if response.status_code == 200:
                data = response.json()
                for entry in data.get("entries", []):
                    if entry.get("email"):
                        emails.append(entry["email"].lower())
    except Exception:
        pass

    return emails


async def query_intelx_emails(
    domain: str,
    api_key: str,
    timeout: float = 30.0,
) -> list[str]:
    """
    Query Intelligence X for emails with the target domain.
    """
    if not api_key:
        return []

    emails = []
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            # Start search
            response = await client.post(
                "https://2.intelx.io/intelligent/search",
                headers={"x-key": api_key},
                json={
                    "term": f"@{domain}",
                    "buckets": [],
                    "lookuplevel": 0,
                    "maxresults": 100,
                    "timeout": 5,
                    "datefrom": "",
                    "dateto": "",
                    "sort": 2,
                    "media": 0,
                    "terminate": [],
                },
            )

            if response.status_code == 200:
                data = response.json()
                search_id = data.get("id")

                if search_id:
                    await asyncio.sleep(2)  # Wait for results

                    # Get results
                    result_response = await client.get(
                        f"https://2.intelx.io/intelligent/search/result",
                        headers={"x-key": api_key},
                        params={"id": search_id},
                    )

                    if result_response.status_code == 200:
                        result_data = result_response.json()
                        for record in result_data.get("records", []):
                            name = record.get("name", "")
                            # Extract emails from the record
                            email_matches = re.findall(
                                r'[a-zA-Z0-9._%+-]+@' + re.escape(domain),
                                name,
                                re.IGNORECASE
                            )
                            emails.extend([e.lower() for e in email_matches])
    except Exception:
        pass

    return emails


async def enrich_email_hunter(
    email: str,
    api_key: str,
    timeout: float = 30.0,
) -> dict:
    """
    Use Hunter.io to enrich an email address with person information.
    """
    if not api_key:
        return {}

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                "https://api.hunter.io/v2/email-verifier",
                params={"email": email, "api_key": api_key},
            )

            if response.status_code == 200:
                data = response.json().get("data", {})
                return {
                    "first_name": data.get("first_name", ""),
                    "last_name": data.get("last_name", ""),
                    "status": data.get("status", ""),
                    "score": data.get("score", 0),
                    "position": data.get("position", ""),
                    "company": data.get("company", ""),
                    "linkedin": data.get("linkedin", ""),
                    "twitter": data.get("twitter", ""),
                }
    except Exception:
        pass

    return {}


def reverse_map_email_to_name(email: str) -> tuple[str, str]:
    """
    Try to extract first/last name from email local part.

    Returns:
        Tuple of (first_name, last_name) - may be empty strings if unable to determine
    """
    local_part = email.split('@')[0].lower()
    first_name = ""
    last_name = ""

    # Skip if it's a generic email
    if local_part in GENERIC_EMAIL_PREFIXES:
        return ("", "")

    # Try common separators
    separators = ['.', '_', '-']
    for sep in separators:
        if sep in local_part:
            parts = local_part.split(sep)
            if len(parts) == 2:
                # Assume first.last or last.first
                # Most common is first.last
                first_name = parts[0].capitalize()
                last_name = parts[1].capitalize()
                return (first_name, last_name)
            elif len(parts) > 2:
                # Could be first.middle.last
                first_name = parts[0].capitalize()
                last_name = parts[-1].capitalize()
                return (first_name, last_name)

    # No separator - could be firstlast, flast, or single name
    # If it looks like a single common name, treat it as first name
    if len(local_part) <= 10 and local_part.isalpha():
        first_name = local_part.capitalize()

    return (first_name, last_name)


def classify_email(email: str) -> str:
    """
    Classify an email as 'personal', 'generic', or 'unknown'.

    Personal emails likely belong to individuals.
    Generic emails are role-based (info@, support@, etc.)
    """
    local_part = email.split('@')[0].lower()

    # Check for generic prefixes
    if local_part in GENERIC_EMAIL_PREFIXES:
        return "generic"

    # Check for numeric-only (likely auto-generated)
    if local_part.isdigit():
        return "unknown"

    # Check for very long random strings (likely system-generated)
    if len(local_part) > 30 and not any(c in local_part for c in ['.', '_', '-']):
        return "unknown"

    # Check for patterns that suggest personal email
    if '.' in local_part or '_' in local_part or '-' in local_part:
        return "personal"

    # Short alphabetic strings are likely personal
    if local_part.isalpha() and 2 <= len(local_part) <= 15:
        return "personal"

    return "unknown"


def generate_email_permutations(
    first_name: str,
    last_name: str,
    domain: str,
) -> list[str]:
    """
    Generate possible email addresses for a person.
    """
    emails = []

    first = first_name.lower().strip()
    last = last_name.lower().strip()
    f = first[0] if first else ""
    l = last[0] if last else ""

    for pattern in EMAIL_PATTERNS:
        try:
            email = pattern.format(first=first, last=last, f=f, l=l)
            email = f"{email}@{domain}"
            emails.append(email)
        except Exception:
            continue

    return emails


def detect_email_pattern(emails: list[str], domain: str) -> Optional[str]:
    """
    Detect the email pattern used by an organization.
    """
    if not emails:
        return None

    pattern_scores = {}

    for email in emails:
        local_part = email.split('@')[0].lower()

        # Check various patterns
        if '.' in local_part:
            parts = local_part.split('.')
            if len(parts) == 2:
                if len(parts[0]) == 1:
                    pattern_scores["{f}.{last}"] = pattern_scores.get("{f}.{last}", 0) + 1
                elif len(parts[1]) == 1:
                    pattern_scores["{first}.{l}"] = pattern_scores.get("{first}.{l}", 0) + 1
                else:
                    pattern_scores["{first}.{last}"] = pattern_scores.get("{first}.{last}", 0) + 1
        elif '_' in local_part:
            pattern_scores["{first}_{last}"] = pattern_scores.get("{first}_{last}", 0) + 1
        elif '-' in local_part:
            pattern_scores["{first}-{last}"] = pattern_scores.get("{first}-{last}", 0) + 1
        else:
            # No separator
            if len(local_part) <= 3:
                pattern_scores["{f}{l}"] = pattern_scores.get("{f}{l}", 0) + 1
            else:
                pattern_scores["{first}{last}"] = pattern_scores.get("{first}{last}", 0) + 1

    if pattern_scores:
        return max(pattern_scores, key=pattern_scores.get)

    return None


async def run(
    session: ScanSession,
    config: AttackTraceConfig,
    orchestrator,
) -> ModuleResult:
    """
    Run employee discovery.

    New approach:
    1. Collect ALL emails with @company.com from multiple sources
    2. Classify emails as personal vs generic (role-based)
    3. Enrich personal emails to map back to employee identities
    4. Report findings
    """
    result = ModuleResult(
        module_name="employee_discovery",
        started_at=datetime.utcnow(),
    )

    discovered_employees = []
    all_domain_emails = set()  # ALL emails with company domain
    personal_emails = set()    # Personal emails (likely individuals)
    generic_emails = set()     # Generic/role-based emails (info@, support@, etc.)
    email_pattern = None
    items_discovered = 0

    # Get API keys
    hunter_key = config.api_keys.hunter if hasattr(config.api_keys, 'hunter') else None
    dehashed_key = config.api_keys.dehashed if hasattr(config.api_keys, 'dehashed') else None
    dehashed_email = config.api_keys.dehashed_email if hasattr(config.api_keys, 'dehashed_email') else None
    intelx_key = config.api_keys.intelx if hasattr(config.api_keys, 'intelx') else None

    # =========================================================================
    # PHASE 1: Collect ALL emails with company domain from multiple sources
    # =========================================================================

    for domain in session.target_domains:
        # Source 1: Hunter.io domain search
        if hunter_key:
            hunter_data = await query_hunter_domain(domain, hunter_key, config.scan.timeout)

            if hunter_data:
                # Get email pattern
                pattern = hunter_data.get("pattern")
                if pattern:
                    email_pattern = pattern

                # Get ALL discovered emails
                for email_data in hunter_data.get("emails", []):
                    email = email_data.get("value", "")
                    if email:
                        all_domain_emails.add(email.lower())

                        # Store enriched data for later
                        employee = {
                            "email": email.lower(),
                            "first_name": email_data.get("first_name", ""),
                            "last_name": email_data.get("last_name", ""),
                            "position": email_data.get("position", ""),
                            "department": email_data.get("department", ""),
                            "linkedin": email_data.get("linkedin", ""),
                            "twitter": email_data.get("twitter", ""),
                            "phone": email_data.get("phone_number", ""),
                            "confidence": email_data.get("confidence", 0),
                            "source": "hunter.io",
                            "classification": "personal",
                        }
                        discovered_employees.append(employee)
                        items_discovered += 1

                await asyncio.sleep(1)

        # Source 2: GitHub commits (if github_recon already ran)
        if session.github_data:
            github_emails = session.github_data.get("emails", [])
            for email in github_emails:
                email_lower = email.lower()
                if domain.lower() in email_lower:
                    all_domain_emails.add(email_lower)

        # Source 3: Phonebook.cz (IntelX email search)
        phonebook_emails = await search_phonebook_cz(domain, config.scan.timeout)
        for email in phonebook_emails:
            if domain.lower() in email.lower():
                all_domain_emails.add(email.lower())

        # Source 4: DeHashed breach data
        if dehashed_key and dehashed_email:
            breach_emails = await query_dehashed_emails(
                domain, dehashed_key, dehashed_email, config.scan.timeout
            )
            for email in breach_emails:
                all_domain_emails.add(email.lower())
            await asyncio.sleep(1)

        # Source 5: Intelligence X
        if intelx_key:
            intelx_emails = await query_intelx_emails(domain, intelx_key, config.scan.timeout)
            for email in intelx_emails:
                all_domain_emails.add(email.lower())
            await asyncio.sleep(1)

        # Source 6: Web pages from discovered web applications
        if session.web_applications:
            webapp_urls = [
                webapp.final_url or webapp.url
                for webapp in session.web_applications
                if webapp.is_alive
            ]
            web_emails = await collect_emails_from_web_pages(
                webapp_urls, domain, config.scan.timeout
            )
            all_domain_emails.update(web_emails)

        # Source 7: Certificate emails
        if session.certificates:
            cert_emails = await collect_emails_from_certificates(
                session.target_domains, session.certificates
            )
            all_domain_emails.update(cert_emails)

    # =========================================================================
    # PHASE 2: Classify and deduplicate emails
    # =========================================================================

    existing_employee_emails = {emp["email"] for emp in discovered_employees}

    for email in all_domain_emails:
        classification = classify_email(email)

        if classification == "generic":
            generic_emails.add(email)
        elif classification == "personal":
            personal_emails.add(email)

            # Add to employees if not already there
            if email not in existing_employee_emails:
                first_name, last_name = reverse_map_email_to_name(email)

                # Determine source based on where we found it
                source = "osint"
                if session.github_data:
                    if email in [e.lower() for e in session.github_data.get("emails", [])]:
                        source = "github"

                employee = {
                    "email": email,
                    "first_name": first_name,
                    "last_name": last_name,
                    "position": "",
                    "department": "",
                    "linkedin": "",
                    "twitter": "",
                    "phone": "",
                    "confidence": 50,  # Lower confidence for non-Hunter emails
                    "source": source,
                    "classification": "personal",
                }
                discovered_employees.append(employee)
                existing_employee_emails.add(email)
                items_discovered += 1
        else:
            # Unknown classification - still track but lower priority
            personal_emails.add(email)

    # =========================================================================
    # PHASE 3: Enrich personal emails to get names (if Hunter key available)
    # =========================================================================

    if hunter_key:
        # Only enrich emails that don't have names yet
        emails_to_enrich = [
            emp for emp in discovered_employees
            if not emp.get("first_name") and not emp.get("last_name")
            and emp.get("source") != "hunter.io"
        ]

        # Limit API calls
        for emp in emails_to_enrich[:20]:
            enriched = await enrich_email_hunter(emp["email"], hunter_key, config.scan.timeout)
            if enriched.get("first_name") or enriched.get("last_name"):
                emp["first_name"] = enriched.get("first_name", emp["first_name"])
                emp["last_name"] = enriched.get("last_name", emp["last_name"])
                emp["position"] = enriched.get("position", emp["position"])
                emp["linkedin"] = enriched.get("linkedin", emp["linkedin"])
                emp["twitter"] = enriched.get("twitter", emp["twitter"])
                emp["confidence"] = enriched.get("score", emp["confidence"])
                emp["source"] = f"{emp['source']}+hunter"
            await asyncio.sleep(0.5)

    # =========================================================================
    # PHASE 4: Detect email pattern if not already known
    # =========================================================================

    if not email_pattern and personal_emails:
        email_pattern = detect_email_pattern(list(personal_emails), session.target_domains[0])

    # =========================================================================
    # PHASE 5: Create findings
    # =========================================================================

    # Finding: All discovered emails
    if all_domain_emails:
        finding = Finding(
            title=f"Discovered {len(all_domain_emails)} email address(es) for {session.target_domains[0]}",
            description=f"Collected {len(all_domain_emails)} email addresses with the target domain from "
                       f"multiple OSINT sources. This includes {len(personal_emails)} personal emails and "
                       f"{len(generic_emails)} generic/role-based addresses.",
            severity=Severity.MEDIUM,
            category="osint",
            affected_asset=session.target_company or session.target_domains[0],
            affected_asset_type="organization",
            evidence=f"Sample emails: {', '.join(list(all_domain_emails)[:15])}",
            source="employee_discovery",
        )
        result.findings.append(finding)

    # Finding: Employees with identified names
    named_employees = [e for e in discovered_employees if e.get("first_name") or e.get("last_name")]
    if named_employees:
        emp_list = ", ".join(
            f"{e.get('first_name', '')} {e.get('last_name', '')} ({e.get('email', '')})"
            for e in named_employees[:10]
        )
        finding = Finding(
            title=f"Identified {len(named_employees)} employee name(s)",
            description=f"Mapped {len(named_employees)} email addresses to employee names through "
                       f"OSINT enrichment. These can be used for targeted phishing.",
            severity=Severity.MEDIUM,
            category="osint",
            affected_asset=session.target_company or session.target_domains[0],
            affected_asset_type="organization",
            evidence=emp_list,
            source="employee_discovery",
        )
        result.findings.append(finding)

    # Finding: High-value targets (executives)
    executive_keywords = ["ceo", "cto", "cfo", "cio", "ciso", "vp", "vice president",
                        "director", "head of", "chief", "president", "founder"]

    executives = []
    for emp in discovered_employees:
        position = (emp.get("position") or "").lower()
        if any(kw in position for kw in executive_keywords):
            executives.append(emp)

    if executives:
        exec_list = ", ".join(
            f"{e.get('first_name', '')} {e.get('last_name', '')} ({e.get('position', '')})"
            for e in executives[:10]
        )
        finding = Finding(
            title=f"Identified {len(executives)} executive(s) / high-value targets",
            description=f"Found executive-level employees who may be high-value targets for spear phishing.",
            severity=Severity.HIGH,
            category="osint",
            affected_asset=session.target_company or session.target_domains[0],
            affected_asset_type="organization",
            evidence=exec_list,
            source="employee_discovery",
        )
        result.findings.append(finding)

    # Finding: Generic emails (useful for enumeration)
    if generic_emails:
        finding = Finding(
            title=f"Discovered {len(generic_emails)} generic/role-based email(s)",
            description=f"Found role-based email addresses (info@, support@, etc.). "
                       f"These can indicate departments and services available.",
            severity=Severity.LOW,
            category="osint",
            affected_asset=session.target_company or session.target_domains[0],
            affected_asset_type="organization",
            evidence=f"Generic emails: {', '.join(sorted(generic_emails)[:20])}",
            source="employee_discovery",
        )
        result.findings.append(finding)

    # Finding: Email pattern
    if email_pattern:
        finding = Finding(
            title=f"Email pattern detected: {email_pattern}@domain.com",
            description=f"The organization uses the email pattern '{email_pattern}' for employee emails. "
                       f"This can be used to generate valid email addresses from employee names.",
            severity=Severity.LOW,
            category="osint",
            affected_asset=session.target_domains[0] if session.target_domains else "",
            affected_asset_type="domain",
            evidence=f"Pattern: {email_pattern}",
            source="employee_discovery",
        )
        result.findings.append(finding)

    # =========================================================================
    # Store data in session for report generation
    # =========================================================================

    session.employee_data = {
        "employees": discovered_employees,
        "emails": list(all_domain_emails),
        "personal_emails": list(personal_emails),
        "generic_emails": list(generic_emails),
        "email_pattern": email_pattern,
    }

    result.items_discovered = items_discovered
    result.success = True
    result.completed_at = datetime.utcnow()

    return result
