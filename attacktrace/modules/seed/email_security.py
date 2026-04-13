"""
Email security checks: SPF, DKIM, DMARC, BIMI
"""

import asyncio
import dns.resolver
import dns.exception
from datetime import datetime
from typing import Optional

from attacktrace.core.models import (
    ModuleResult,
    Finding,
    Severity,
)

# Common DKIM selectors to probe
DKIM_SELECTORS = [
    "default",
    "google",
    "mail",
    "dkim",
    "k1",
    "selector1",
    "selector2",
]


def _make_resolver() -> dns.resolver.Resolver:
    """Create a DNS resolver with sane defaults."""
    r = dns.resolver.Resolver()
    r.timeout = 5
    r.lifetime = 5
    return r


def _query_txt(name: str) -> list[str]:
    """
    Synchronously query TXT records for *name*.

    Returns a list of decoded TXT strings, or an empty list on failure.
    """
    resolver = _make_resolver()
    records: list[str] = []
    try:
        answers = resolver.resolve(name, "TXT", lifetime=5)
        for rdata in answers:
            # Each TXT record may be composed of multiple strings; join them.
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
            records.append(txt)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    except dns.exception.Timeout:
        pass
    except Exception:
        pass
    return records


def _check_spf(domain: str) -> list[Finding]:
    """Check SPF record for *domain*."""
    findings: list[Finding] = []
    txt_records = _query_txt(domain)

    spf_record: Optional[str] = None
    for txt in txt_records:
        if txt.strip().lower().startswith("v=spf1"):
            spf_record = txt.strip()
            break

    if spf_record is None:
        findings.append(
            Finding(
                title="Missing SPF record",
                description=(
                    f"No SPF (Sender Policy Framework) TXT record was found for {domain}. "
                    "Without an SPF record, any mail server can send email claiming to be "
                    "from this domain, making phishing and spoofing trivial."
                ),
                severity=Severity.HIGH,
                category="misconfiguration",
                affected_asset=domain,
                affected_asset_type="domain",
                remediation=(
                    "Add a TXT record to your DNS with a valid SPF policy. "
                    'At minimum: "v=spf1 include:<your-mail-provider> -all". '
                    "Use -all (hard fail) to reject unauthorized senders."
                ),
                confidence="certain",
                source="email_security",
            )
        )
        return findings

    lower = spf_record.lower()

    if "+all" in lower:
        findings.append(
            Finding(
                title="SPF allows all senders (+all) — completely open",
                description=(
                    f"The SPF record for {domain} contains '+all', which means every mail "
                    "server in the world is authorized to send email on behalf of this domain. "
                    f"Record: {spf_record}"
                ),
                severity=Severity.CRITICAL,
                category="misconfiguration",
                affected_asset=domain,
                affected_asset_type="domain",
                evidence=spf_record,
                remediation=(
                    "Replace '+all' with '-all' in your SPF record immediately. "
                    "'-all' causes receiving servers to reject mail from unauthorized senders. "
                    "Example: \"v=spf1 include:<your-mail-provider> -all\""
                ),
                confidence="certain",
                source="email_security",
            )
        )
    elif "~all" in lower:
        findings.append(
            Finding(
                title="SPF uses softfail (~all) instead of hard fail (-all)",
                description=(
                    f"The SPF record for {domain} ends with '~all' (softfail). "
                    "Softfail only marks unauthorized mail as suspicious; it does not cause "
                    "rejection. Many receiving mail servers will still deliver softfail messages. "
                    f"Record: {spf_record}"
                ),
                severity=Severity.MEDIUM,
                category="misconfiguration",
                affected_asset=domain,
                affected_asset_type="domain",
                evidence=spf_record,
                remediation=(
                    "Change '~all' to '-all' (hard fail) in your SPF record once you have "
                    "enumerated all legitimate sending sources. Monitor SPF failures first "
                    "if you are unsure of all senders."
                ),
                confidence="certain",
                source="email_security",
            )
        )
    # If -all or ?all with no obvious issues — no finding

    return findings


def _check_dmarc(domain: str) -> list[Finding]:
    """Check DMARC record for *domain*."""
    findings: list[Finding] = []
    dmarc_name = f"_dmarc.{domain}"
    txt_records = _query_txt(dmarc_name)

    dmarc_record: Optional[str] = None
    for txt in txt_records:
        if txt.strip().lower().startswith("v=dmarc1"):
            dmarc_record = txt.strip()
            break

    if dmarc_record is None:
        findings.append(
            Finding(
                title="Missing DMARC record",
                description=(
                    f"No DMARC (Domain-based Message Authentication, Reporting & Conformance) "
                    f"record was found at _dmarc.{domain}. Without DMARC, receiving mail servers "
                    "have no policy guidance for handling SPF/DKIM failures, leaving the domain "
                    "exposed to spoofing."
                ),
                severity=Severity.HIGH,
                category="misconfiguration",
                affected_asset=domain,
                affected_asset_type="domain",
                remediation=(
                    f"Add a TXT record at _dmarc.{domain} with a DMARC policy. "
                    "Start with a monitoring policy and progressively enforce: "
                    '"v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com" → '
                    '"v=DMARC1; p=quarantine;" → "v=DMARC1; p=reject;"'
                ),
                confidence="certain",
                source="email_security",
            )
        )
        return findings

    # Extract policy value
    policy: Optional[str] = None
    for part in dmarc_record.split(";"):
        part = part.strip()
        if part.lower().startswith("p="):
            policy = part[2:].strip().lower()
            break

    if policy == "none":
        findings.append(
            Finding(
                title="DMARC policy is 'none' (monitor only, no enforcement)",
                description=(
                    f"The DMARC record for {domain} has p=none, which means DMARC is in "
                    "monitoring mode only. Spoofed emails will still be delivered; the policy "
                    "provides no protection — only reporting. "
                    f"Record: {dmarc_record}"
                ),
                severity=Severity.MEDIUM,
                category="misconfiguration",
                affected_asset=domain,
                affected_asset_type="domain",
                evidence=dmarc_record,
                remediation=(
                    "After reviewing DMARC aggregate reports to ensure legitimate mail is "
                    "passing SPF/DKIM, upgrade the policy to p=quarantine and eventually p=reject."
                ),
                confidence="certain",
                source="email_security",
            )
        )
    elif policy == "quarantine":
        findings.append(
            Finding(
                title="DMARC policy is 'quarantine' — consider upgrading to reject",
                description=(
                    f"The DMARC record for {domain} uses p=quarantine. Spoofed messages are "
                    "sent to spam/junk instead of being outright rejected. This provides "
                    "partial protection but allows spoofed mail to reach recipients' spam folders. "
                    f"Record: {dmarc_record}"
                ),
                severity=Severity.LOW,
                category="misconfiguration",
                affected_asset=domain,
                affected_asset_type="domain",
                evidence=dmarc_record,
                remediation=(
                    "Once you have confirmed all legitimate mail sources pass DMARC checks, "
                    "upgrade the policy to p=reject for full enforcement."
                ),
                confidence="certain",
                source="email_security",
            )
        )
    # p=reject — no finding

    return findings


def _check_dkim(domain: str) -> list[Finding]:
    """Check common DKIM selectors for *domain*."""
    findings: list[Finding] = []
    found_selector: Optional[str] = None

    for selector in DKIM_SELECTORS:
        name = f"{selector}._domainkey.{domain}"
        records = _query_txt(name)
        for txt in records:
            # A valid DKIM record starts with v=DKIM1 or contains p= (public key)
            if "v=dkim1" in txt.lower() or "p=" in txt.lower():
                found_selector = selector
                break
        if found_selector:
            break

    if found_selector is None:
        findings.append(
            Finding(
                title="No DKIM record found (tried common selectors)",
                description=(
                    f"No DKIM (DomainKeys Identified Mail) TXT record was found for {domain} "
                    f"using common selectors: {', '.join(DKIM_SELECTORS)}. "
                    "Without DKIM, outgoing mail cannot be cryptographically signed, making "
                    "it easier to spoof and reducing deliverability."
                ),
                severity=Severity.MEDIUM,
                category="misconfiguration",
                affected_asset=domain,
                affected_asset_type="domain",
                remediation=(
                    "Configure DKIM signing in your mail provider and publish the public key "
                    "as a TXT record at <selector>._domainkey.<domain>. Most mail providers "
                    "(Google Workspace, Microsoft 365, etc.) offer step-by-step DKIM setup guides."
                ),
                confidence="firm",
                source="email_security",
            )
        )

    return findings


def _check_bimi(domain: str) -> list[Finding]:
    """Check BIMI record for *domain* (informational only)."""
    findings: list[Finding] = []
    bimi_name = f"default._bimi.{domain}"
    records = _query_txt(bimi_name)

    for txt in records:
        if txt.strip().lower().startswith("v=bimi1"):
            findings.append(
                Finding(
                    title="BIMI record present — brand indicator configured",
                    description=(
                        f"A BIMI (Brand Indicators for Message Identification) record was found "
                        f"at {bimi_name}. This is a positive security and branding signal: "
                        "supported mail clients will display the organization's logo next to "
                        "authenticated email. "
                        f"Record: {txt.strip()}"
                    ),
                    severity=Severity.INFO,
                    category="misconfiguration",
                    affected_asset=domain,
                    affected_asset_type="domain",
                    evidence=txt.strip(),
                    remediation="No action required. Ensure the BIMI logo URL remains accessible.",
                    confidence="certain",
                    source="email_security",
                )
            )
            break

    return findings


async def run(
    session,
    config,
    orchestrator,
) -> ModuleResult:
    """
    Run email security checks (SPF, DKIM, DMARC, BIMI) for all session domains.

    Args:
        session: Current scan session
        config: AttackTrace configuration
        orchestrator: Orchestrator instance

    Returns:
        ModuleResult containing email security findings
    """
    result = ModuleResult(
        module_name="email_security",
        started_at=datetime.utcnow(),
    )

    # Collect root domains: prefer session.domains list, fall back to target_domains
    domains_to_check: list[str] = []
    if session.domains:
        domains_to_check = [d.fqdn for d in session.domains]
    elif session.target_domains:
        domains_to_check = list(session.target_domains)

    if not domains_to_check:
        result.success = True
        result.completed_at = datetime.utcnow()
        return result

    loop = asyncio.get_event_loop()

    for domain in domains_to_check:
        # Run all checks concurrently per domain using executor (dns.resolver is sync)
        spf_findings, dmarc_findings, dkim_findings, bimi_findings = await asyncio.gather(
            loop.run_in_executor(None, _check_spf, domain),
            loop.run_in_executor(None, _check_dmarc, domain),
            loop.run_in_executor(None, _check_dkim, domain),
            loop.run_in_executor(None, _check_bimi, domain),
        )

        result.findings.extend(spf_findings)
        result.findings.extend(dmarc_findings)
        result.findings.extend(dkim_findings)
        result.findings.extend(bimi_findings)

    result.items_discovered = len(result.findings)
    result.success = True
    result.completed_at = datetime.utcnow()

    return result
