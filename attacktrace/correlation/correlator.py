"""
Data correlation module.

Analyzes and correlates discovered data to:
- Build relationships between assets
- Deduplicate findings
- Calculate risk scores
- Generate insights
"""

from datetime import datetime
from collections import defaultdict

from attacktrace.config import AttackTraceConfig
from attacktrace.core.models import (
    ModuleResult,
    Finding,
    Severity,
    ScanSession,
)


def calculate_ip_risk_score(session: ScanSession, ip_address: str) -> float:
    """Calculate risk score for an IP address."""
    score = 0.0

    # Find IP record
    ip = next((ip for ip in session.ip_addresses if ip.address == ip_address), None)
    if not ip:
        return score

    # High-risk ports
    high_risk_ports = {
        22: 2.0,    # SSH
        23: 3.0,    # Telnet
        3389: 2.5,  # RDP
        5900: 2.0,  # VNC
        27017: 4.0, # MongoDB
        6379: 4.0,  # Redis
        9200: 3.5,  # Elasticsearch
        11211: 3.0, # Memcached
    }

    for port in ip.ports:
        if port.number in high_risk_ports:
            score += high_risk_ports[port.number]

    # Count of open ports
    open_port_count = len([p for p in ip.ports if p.state.value == "open"])
    if open_port_count > 20:
        score += 2.0
    elif open_port_count > 10:
        score += 1.0

    # Cloud provider bonus (usually better managed)
    if ip.cloud_provider:
        score *= 0.8

    return min(10.0, score)


def calculate_webapp_risk_score(session: ScanSession, webapp_url: str) -> float:
    """Calculate risk score for a web application."""
    score = 0.0

    # Find webapp
    webapp = next((w for w in session.web_applications if w.url == webapp_url), None)
    if not webapp:
        return score

    # Check for concerning technologies
    concerning_tech = ["wordpress", "drupal", "joomla", "php"]
    for tech in webapp.technologies:
        if tech.name.lower() in concerning_tech:
            score += 1.0

    # Missing security headers (from findings)
    related_findings = [
        f for f in session.findings
        if f.affected_asset == webapp_url
    ]

    for finding in related_findings:
        if "security headers" in finding.title.lower():
            score += 0.5
        if "debug" in finding.title.lower():
            score += 3.0

    # HTTP vs HTTPS
    if webapp.scheme == "http":
        score += 1.5

    # Expired certificate
    if webapp.certificate and webapp.certificate.is_expired:
        score += 2.0

    return min(10.0, score)


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate findings."""
    seen = set()
    unique = []

    for finding in findings:
        # Create a key based on title and affected asset
        key = (finding.title.lower(), finding.affected_asset.lower())
        if key not in seen:
            seen.add(key)
            unique.append(finding)

    return unique


def aggregate_by_severity(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Group findings by severity."""
    grouped = defaultdict(list)
    for finding in findings:
        grouped[finding.severity.value].append(finding)
    return dict(grouped)


def generate_summary_findings(session: ScanSession) -> list[Finding]:
    """Generate summary/insight findings based on overall data."""
    findings = []

    # Check for large attack surface
    total_subdomains = len(session.subdomains)
    if total_subdomains > 100:
        finding = Finding(
            title="Large subdomain footprint detected",
            description=f"Discovered {total_subdomains} subdomains. A large attack surface "
                       "increases the risk of misconfigurations and forgotten assets.",
            severity=Severity.INFO,
            category="insight",
            affected_asset=session.target_company or session.target_domains[0] if session.target_domains else "",
            affected_asset_type="organization",
            source="correlator",
        )
        findings.append(finding)

    # Check for development/staging exposure
    dev_keywords = ["dev", "stage", "staging", "test", "uat", "beta", "demo", "sandbox"]
    exposed_dev = []
    for subdomain in session.subdomains:
        for keyword in dev_keywords:
            if keyword in subdomain.fqdn.lower() and subdomain.is_alive:
                exposed_dev.append(subdomain.fqdn)
                break

    if exposed_dev:
        finding = Finding(
            title=f"Development/staging environments exposed ({len(exposed_dev)} found)",
            description="Development and staging environments are accessible from the internet. "
                       "These often have weaker security controls and may contain sensitive data.",
            severity=Severity.MEDIUM,
            category="exposure",
            affected_asset=", ".join(exposed_dev[:5]),
            affected_asset_type="subdomain",
            evidence=f"Found: {', '.join(exposed_dev[:10])}",
            source="correlator",
        )
        findings.append(finding)

    # Check for multiple cloud providers
    cloud_providers = set()
    for ip in session.ip_addresses:
        if ip.cloud_provider:
            cloud_providers.add(ip.cloud_provider.value)

    if len(cloud_providers) > 1:
        finding = Finding(
            title="Multi-cloud infrastructure detected",
            description=f"Infrastructure spans multiple cloud providers: {', '.join(cloud_providers)}. "
                       "Ensure consistent security policies across all providers.",
            severity=Severity.INFO,
            category="insight",
            affected_asset=session.target_company or "",
            affected_asset_type="organization",
            source="correlator",
        )
        findings.append(finding)

    # Check for many open ports
    total_open_ports = sum(
        len([p for p in ip.ports if p.state.value == "open"])
        for ip in session.ip_addresses
    )
    if total_open_ports > 100:
        finding = Finding(
            title=f"High number of open ports ({total_open_ports})",
            description="A large number of open ports increases the attack surface. "
                       "Review and close unnecessary services.",
            severity=Severity.MEDIUM,
            category="exposure",
            affected_asset=session.target_company or "",
            affected_asset_type="organization",
            source="correlator",
        )
        findings.append(finding)

    return findings


def correlate_assets(session: ScanSession) -> dict:
    """
    Build correlation map between assets.

    Returns:
        Dictionary with correlation data
    """
    correlations = {
        "domain_to_ips": defaultdict(list),
        "ip_to_domains": defaultdict(list),
        "ip_to_webapps": defaultdict(list),
        "subdomain_to_webapps": defaultdict(list),
    }

    # Domain to IP mappings
    for subdomain in session.subdomains:
        for ip in subdomain.resolved_ips:
            correlations["domain_to_ips"][subdomain.fqdn].append(ip)
            correlations["ip_to_domains"][ip].append(subdomain.fqdn)

    # IP to webapp mappings
    for webapp in session.web_applications:
        if webapp.host:
            # Find IPs for this host
            for subdomain in session.subdomains:
                if subdomain.fqdn == webapp.host:
                    for ip in subdomain.resolved_ips:
                        correlations["ip_to_webapps"][ip].append(webapp.url)
            correlations["subdomain_to_webapps"][webapp.host].append(webapp.url)

    return {k: dict(v) for k, v in correlations.items()}


async def run(
    session: ScanSession,
    config: AttackTraceConfig,
    orchestrator,
) -> ModuleResult:
    """
    Run data correlation and analysis.

    Args:
        session: Current scan session
        config: AttackTrace configuration
        orchestrator: Orchestrator instance

    Returns:
        ModuleResult with analysis findings
    """
    result = ModuleResult(
        module_name="correlator",
        started_at=datetime.utcnow(),
    )

    # Deduplicate existing findings
    session.findings = deduplicate_findings(session.findings)

    # Generate summary findings
    summary_findings = generate_summary_findings(session)
    result.findings.extend(summary_findings)

    # Build correlations
    correlations = correlate_assets(session)

    # Calculate risk scores for high-value assets
    # (This data could be stored in session metadata if needed)

    # Update session statistics
    session.update_statistics()

    result.items_discovered = len(result.findings)
    result.success = True
    result.completed_at = datetime.utcnow()

    return result
