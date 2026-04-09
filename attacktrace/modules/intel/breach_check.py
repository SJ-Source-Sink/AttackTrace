"""
Breach and credential exposure checking module.

Integrates with:
- HaveIBeenPwned (HIBP)
- DeHashed
- Intelligence X (IntelX)
- LeakCheck
- BreachDirectory

Checks if employee emails appear in known data breaches.
"""

import asyncio
import hashlib
from datetime import datetime
from typing import Optional

import httpx

from attacktrace.config import AttackTraceConfig
from attacktrace.core.models import (
    ModuleResult,
    Finding,
    Severity,
    ScanSession,
)


async def check_hibp_breaches(
    email: str,
    api_key: str,
    timeout: float = 30.0,
) -> list[dict]:
    """
    Check HaveIBeenPwned for breaches containing this email.
    Requires API key ($3.50/month).
    """
    if not api_key:
        return []

    breaches = []

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers={
                    "hibp-api-key": api_key,
                    "User-Agent": "AttackTrace-Scanner",
                },
                params={"truncateResponse": "false"},
            )

            if response.status_code == 200:
                breaches = response.json()

    except Exception:
        pass

    return breaches


async def check_hibp_pastes(
    email: str,
    api_key: str,
    timeout: float = 30.0,
) -> list[dict]:
    """
    Check HaveIBeenPwned for pastes containing this email.
    """
    if not api_key:
        return []

    pastes = []

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}",
                headers={
                    "hibp-api-key": api_key,
                    "User-Agent": "AttackTrace-Scanner",
                },
            )

            if response.status_code == 200:
                pastes = response.json()

    except Exception:
        pass

    return pastes


async def check_dehashed(
    query: str,
    api_key: str,
    email: str,
    timeout: float = 30.0,
) -> list[dict]:
    """
    Search DeHashed for leaked credentials.
    Returns emails, passwords, hashes, usernames, etc.
    """
    if not api_key or not email:
        return []

    results = []

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                "https://api.dehashed.com/search",
                params={"query": f"email:{query}"},
                auth=(email, api_key),
                headers={"Accept": "application/json"},
            )

            if response.status_code == 200:
                data = response.json()
                results = data.get("entries", [])

    except Exception:
        pass

    return results


async def check_leakcheck(
    email: str,
    api_key: str,
    timeout: float = 30.0,
) -> list[dict]:
    """
    Check LeakCheck.io for breaches.
    """
    if not api_key:
        return []

    results = []

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"https://leakcheck.io/api/public",
                params={
                    "key": api_key,
                    "check": email,
                    "type": "email",
                },
            )

            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    results = data.get("sources", [])

    except Exception:
        pass

    return results


async def check_intelx(
    query: str,
    api_key: str,
    timeout: float = 30.0,
) -> dict:
    """
    Search Intelligence X for breaches, pastes, dark web.
    """
    if not api_key:
        return {}

    results = {"records": 0, "breaches": []}

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            # Start search
            response = await client.post(
                "https://2.intelx.io/intelligent/search",
                headers={"x-key": api_key},
                json={
                    "term": query,
                    "maxresults": 100,
                    "media": 0,
                    "sort": 2,
                    "terminate": [],
                },
            )

            if response.status_code == 200:
                data = response.json()
                search_id = data.get("id")

                if search_id:
                    await asyncio.sleep(2)

                    # Get results
                    result_response = await client.get(
                        f"https://2.intelx.io/intelligent/search/result",
                        headers={"x-key": api_key},
                        params={"id": search_id},
                    )

                    if result_response.status_code == 200:
                        result_data = result_response.json()
                        results["records"] = result_data.get("records", 0)
                        results["breaches"] = [
                            {
                                "name": r.get("name", ""),
                                "date": r.get("date", ""),
                                "bucket": r.get("bucket", ""),
                            }
                            for r in result_data.get("records", [])[:20]
                        ]

    except Exception:
        pass

    return results


async def check_breach_directory(
    email: str,
    timeout: float = 30.0,
) -> list[str]:
    """
    Check BreachDirectory (free, limited).
    """
    sources = []

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"https://breachdirectory.org/api/breach/email/{email}",
                headers={"User-Agent": "AttackTrace-Scanner"},
            )

            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    sources = data.get("result", [])

    except Exception:
        pass

    return sources


async def run(
    session: ScanSession,
    config: AttackTraceConfig,
    orchestrator,
) -> ModuleResult:
    """
    Run breach checking for discovered emails.
    """
    result = ModuleResult(
        module_name="breach_check",
        started_at=datetime.utcnow(),
    )

    # Get API keys
    hibp_key = getattr(config.api_keys, 'hibp', None)
    dehashed_key = getattr(config.api_keys, 'dehashed', None)
    dehashed_email = getattr(config.api_keys, 'dehashed_email', None)
    leakcheck_key = getattr(config.api_keys, 'leakcheck', None)
    intelx_key = getattr(config.api_keys, 'intelx', None)

    # Collect emails to check
    emails_to_check = set()

    # From employee discovery
    if session.employee_data:
        emails_to_check.update(session.employee_data.get('emails', []))

    # From GitHub
    if session.github_data:
        emails_to_check.update(session.github_data.get('emails', []))

    # Filter to target domain emails only
    target_domains = [d.lower() for d in session.target_domains]
    emails_to_check = [
        e for e in emails_to_check
        if any(d in e.lower() for d in target_domains)
    ]

    if not emails_to_check:
        result.success = True
        result.completed_at = datetime.utcnow()
        return result

    # Track results
    breached_emails = []
    credential_exposures = []
    total_breaches = 0

    # Concurrent email checking with per-service rate limiting
    semaphore = asyncio.Semaphore(5)  # Max 5 emails checked concurrently

    async def check_single_email(email: str) -> dict:
        """Check a single email against all breach services concurrently."""
        async with semaphore:
            email_breaches = []
            has_password_exposed = False
            local_cred_exposures = []

            # Run all API checks concurrently for this email
            tasks = []

            if hibp_key:
                tasks.append(("hibp_breaches", check_hibp_breaches(email, hibp_key, config.scan.timeout)))
                tasks.append(("hibp_pastes", check_hibp_pastes(email, hibp_key, config.scan.timeout)))

            if dehashed_key and dehashed_email:
                tasks.append(("dehashed", check_dehashed(email, dehashed_key, dehashed_email, config.scan.timeout)))

            if leakcheck_key:
                tasks.append(("leakcheck", check_leakcheck(email, leakcheck_key, config.scan.timeout)))

            if intelx_key:
                tasks.append(("intelx", check_intelx(email, intelx_key, config.scan.timeout)))

            if not hibp_key and not dehashed_key:
                tasks.append(("breachdir", check_breach_directory(email, config.scan.timeout)))

            # Execute all checks concurrently
            if tasks:
                task_names = [t[0] for t in tasks]
                task_coros = [t[1] for t in tasks]
                results = await asyncio.gather(*task_coros, return_exceptions=True)

                for name, res in zip(task_names, results):
                    if isinstance(res, Exception):
                        continue

                    if name == "hibp_breaches" and res:
                        email_breaches.extend([b.get("Name", "Unknown") for b in res])
                    elif name == "hibp_pastes" and res:
                        email_breaches.append(f"{len(res)} paste(s)")
                    elif name == "dehashed" and res:
                        for entry in res:
                            if entry.get("password") or entry.get("hashed_password"):
                                has_password_exposed = True
                                local_cred_exposures.append({
                                    "email": email,
                                    "source": entry.get("database_name", "Unknown"),
                                    "has_password": bool(entry.get("password")),
                                    "has_hash": bool(entry.get("hashed_password")),
                                })
                        email_breaches.append(f"DeHashed: {len(res)} entries")
                    elif name == "leakcheck" and res:
                        email_breaches.extend(res)
                    elif name == "intelx" and isinstance(res, dict) and res.get("records", 0) > 0:
                        email_breaches.append(f"IntelX: {res['records']} records")
                    elif name == "breachdir" and res:
                        email_breaches.extend(res[:5])

            # Small delay to respect rate limits
            await asyncio.sleep(0.5)

            return {
                "email": email,
                "breaches": list(set(email_breaches)),
                "breach_count": len(email_breaches),
                "password_exposed": has_password_exposed,
                "cred_exposures": local_cred_exposures,
            }

    # Check all emails concurrently
    email_results = await asyncio.gather(
        *[check_single_email(email) for email in list(emails_to_check)[:50]],
        return_exceptions=True
    )

    for res in email_results:
        if isinstance(res, Exception):
            continue
        if res.get("breaches"):
            breached_emails.append({
                "email": res["email"],
                "breaches": res["breaches"],
                "breach_count": res["breach_count"],
                "password_exposed": res["password_exposed"],
            })
            total_breaches += res["breach_count"]
            result.items_discovered += 1
        credential_exposures.extend(res.get("cred_exposures", []))

    # Store results
    if not hasattr(session, 'breach_data'):
        session.breach_data = {}
    session.breach_data = {
        "breached_emails": breached_emails,
        "credential_exposures": credential_exposures,
        "total_breaches": total_breaches,
        "emails_checked": len(emails_to_check),
    }

    # Create findings
    if credential_exposures:
        finding = Finding(
            title=f"CRITICAL: {len(credential_exposures)} credential(s) exposed in breaches",
            description="Employee passwords or password hashes found in data breaches. "
                       "These credentials may still be valid or reused on other systems.",
            severity=Severity.CRITICAL,
            category="credential_exposure",
            affected_asset=session.target_company or session.target_domains[0],
            affected_asset_type="organization",
            evidence="\n".join([
                f"{c['email']} - {c['source']} (password: {c['has_password']}, hash: {c['has_hash']})"
                for c in credential_exposures[:10]
            ]),
            source="breach_check",
        )
        result.findings.append(finding)

    if breached_emails:
        # Separate by severity
        password_exposed = [b for b in breached_emails if b["password_exposed"]]
        email_only = [b for b in breached_emails if not b["password_exposed"]]

        if email_only:
            finding = Finding(
                title=f"{len(email_only)} employee email(s) found in data breaches",
                description="These employee emails appear in known data breaches. "
                           "Check if passwords were exposed and if they may have been reused.",
                severity=Severity.HIGH,
                category="credential_exposure",
                affected_asset=session.target_company or session.target_domains[0],
                affected_asset_type="organization",
                evidence="\n".join([
                    f"{b['email']}: {', '.join(b['breaches'][:3])}"
                    for b in email_only[:10]
                ]),
                source="breach_check",
            )
            result.findings.append(finding)

    result.success = True
    result.completed_at = datetime.utcnow()
    return result
