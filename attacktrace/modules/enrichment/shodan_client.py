"""
Shodan enrichment module.

Enriches discovered IPs with Shodan data including:
- Service information
- Banners
- Vulnerabilities
- Historical data
- Exposed databases (MongoDB, Redis, Elasticsearch, etc.)
- Exposed services (Jenkins, Docker, Kubernetes, etc.)
"""

import asyncio
from datetime import datetime
from typing import Optional

import httpx

from attacktrace.config import AttackTraceConfig
from attacktrace.core.models import (
    ModuleResult,
    IPAddress,
    Port,
    Service,
    PortState,
    GeoLocation,
    CloudProvider,
    Finding,
    Severity,
    ScanSession,
)


# Services to specifically search for in Shodan
SHODAN_SERVICE_SEARCHES = {
    # Databases
    "mongodb": {
        "query": 'product:"MongoDB"',
        "severity": Severity.CRITICAL,
        "category": "database_exposure",
        "description": "MongoDB database server exposed to internet",
    },
    "redis": {
        "query": 'product:"Redis"',
        "severity": Severity.CRITICAL,
        "category": "database_exposure",
        "description": "Redis cache/database exposed to internet",
    },
    "elasticsearch": {
        "query": 'product:"Elastic" port:9200',
        "severity": Severity.HIGH,
        "category": "database_exposure",
        "description": "Elasticsearch cluster exposed to internet",
    },
    "mysql": {
        "query": 'product:"MySQL"',
        "severity": Severity.HIGH,
        "category": "database_exposure",
        "description": "MySQL database exposed to internet",
    },
    "postgresql": {
        "query": 'product:"PostgreSQL"',
        "severity": Severity.HIGH,
        "category": "database_exposure",
        "description": "PostgreSQL database exposed to internet",
    },
    "cassandra": {
        "query": 'port:9042 product:"Cassandra"',
        "severity": Severity.HIGH,
        "category": "database_exposure",
        "description": "Cassandra database exposed to internet",
    },
    "couchdb": {
        "query": 'product:"CouchDB"',
        "severity": Severity.HIGH,
        "category": "database_exposure",
        "description": "CouchDB database exposed to internet",
    },
    "memcached": {
        "query": 'product:"Memcached"',
        "severity": Severity.MEDIUM,
        "category": "cache_exposure",
        "description": "Memcached cache exposed to internet",
    },
    # CI/CD & DevOps
    "jenkins": {
        "query": 'http.title:"Dashboard [Jenkins]" OR http.component:"jenkins"',
        "severity": Severity.HIGH,
        "category": "service_exposure",
        "description": "Jenkins CI/CD server exposed to internet",
    },
    "gitlab": {
        "query": 'http.title:"GitLab"',
        "severity": Severity.MEDIUM,
        "category": "service_exposure",
        "description": "GitLab instance exposed to internet",
    },
    "docker": {
        "query": 'port:2375,2376 product:"Docker"',
        "severity": Severity.CRITICAL,
        "category": "service_exposure",
        "description": "Docker API exposed to internet - potential container escape",
    },
    "kubernetes": {
        "query": 'port:6443,8443,10250 "kube"',
        "severity": Severity.CRITICAL,
        "category": "service_exposure",
        "description": "Kubernetes API exposed to internet",
    },
    "etcd": {
        "query": 'port:2379 product:"etcd"',
        "severity": Severity.CRITICAL,
        "category": "service_exposure",
        "description": "etcd key-value store exposed to internet",
    },
    # Monitoring
    "grafana": {
        "query": 'http.title:"Grafana"',
        "severity": Severity.MEDIUM,
        "category": "service_exposure",
        "description": "Grafana dashboard exposed to internet",
    },
    "kibana": {
        "query": 'http.title:"Kibana" OR kibana',
        "severity": Severity.MEDIUM,
        "category": "service_exposure",
        "description": "Kibana dashboard exposed to internet",
    },
    "prometheus": {
        "query": 'http.title:"Prometheus" port:9090',
        "severity": Severity.MEDIUM,
        "category": "service_exposure",
        "description": "Prometheus monitoring exposed to internet",
    },
    # Message Queues
    "rabbitmq": {
        "query": 'port:5672,15672 product:"RabbitMQ"',
        "severity": Severity.HIGH,
        "category": "service_exposure",
        "description": "RabbitMQ message broker exposed to internet",
    },
    "kafka": {
        "query": 'port:9092 "kafka"',
        "severity": Severity.HIGH,
        "category": "service_exposure",
        "description": "Kafka message broker exposed to internet",
    },
}

# Service module names in Shodan that indicate exposed services
SHODAN_MODULE_SEVERITY = {
    "mongodb": (Severity.CRITICAL, "MongoDB database"),
    "redis": (Severity.CRITICAL, "Redis cache/database"),
    "elastic": (Severity.HIGH, "Elasticsearch"),
    "elasticsearch": (Severity.HIGH, "Elasticsearch"),
    "mysql": (Severity.HIGH, "MySQL database"),
    "postgresql": (Severity.HIGH, "PostgreSQL database"),
    "postgres": (Severity.HIGH, "PostgreSQL database"),
    "cassandra": (Severity.HIGH, "Cassandra database"),
    "couchdb": (Severity.HIGH, "CouchDB database"),
    "memcached": (Severity.MEDIUM, "Memcached cache"),
    "docker": (Severity.CRITICAL, "Docker API"),
    "kubernetes": (Severity.CRITICAL, "Kubernetes API"),
    "etcd": (Severity.CRITICAL, "etcd key-value store"),
    "jenkins": (Severity.HIGH, "Jenkins CI/CD"),
    "gitlab": (Severity.MEDIUM, "GitLab"),
    "grafana": (Severity.MEDIUM, "Grafana dashboard"),
    "kibana": (Severity.MEDIUM, "Kibana dashboard"),
    "prometheus": (Severity.MEDIUM, "Prometheus monitoring"),
    "rabbitmq": (Severity.HIGH, "RabbitMQ"),
    "kafka": (Severity.HIGH, "Kafka"),
    "ftp": (Severity.MEDIUM, "FTP server"),
    "telnet": (Severity.HIGH, "Telnet server"),
    "smb": (Severity.HIGH, "SMB file sharing"),
    "rdp": (Severity.MEDIUM, "Remote Desktop"),
    "vnc": (Severity.MEDIUM, "VNC remote access"),
}


async def query_shodan_internetdb(ip: str, timeout: float = 10.0) -> Optional[dict]:
    """
    Query Shodan InternetDB (FREE, no API key required).

    Returns basic information about an IP including:
    - Open ports
    - Hostnames
    - CPEs (Common Platform Enumeration)
    - Tags
    - Vulnerabilities

    Args:
        ip: IP address to query
        timeout: Request timeout

    Returns:
        InternetDB data or None
    """
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(f"https://internetdb.shodan.io/{ip}")

            if response.status_code == 200:
                return response.json()

    except Exception:
        pass

    return None


async def query_shodan(ip: str, api_key: str) -> Optional[dict]:
    """
    Query Shodan API for IP information.

    Args:
        ip: IP address to query
        api_key: Shodan API key

    Returns:
        Shodan host data or None
    """
    if not api_key:
        return None

    try:
        import shodan
        api = shodan.Shodan(api_key)

        # Run sync API call in executor
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, api.host, ip)
        return result

    except Exception:
        return None


async def search_shodan_org(org_name: str, api_key: str) -> list[dict]:
    """
    Search Shodan for hosts belonging to an organization.

    Args:
        org_name: Organization name to search
        api_key: Shodan API key

    Returns:
        List of host data
    """
    if not api_key:
        return []

    try:
        import shodan
        api = shodan.Shodan(api_key)

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            lambda: api.search(f'org:"{org_name}"')
        )
        return result.get("matches", [])

    except Exception:
        return []


async def search_shodan_services(
    org_name: str,
    domains: list[str],
    api_key: str,
    services: list[str] = None,
) -> list[dict]:
    """
    Search Shodan for specific exposed services belonging to an organization.

    Args:
        org_name: Organization name
        domains: Target domains
        api_key: Shodan API key
        services: List of service types to search for (e.g., ['mongodb', 'redis'])
                  If None, searches for all known dangerous services.

    Returns:
        List of matches with service info
    """
    if not api_key:
        return []

    services = services or list(SHODAN_SERVICE_SEARCHES.keys())
    all_matches = []

    try:
        import shodan
        api = shodan.Shodan(api_key)
        loop = asyncio.get_event_loop()

        for service_key in services:
            if service_key not in SHODAN_SERVICE_SEARCHES:
                continue

            service_info = SHODAN_SERVICE_SEARCHES[service_key]
            base_query = service_info["query"]

            # Build query with org/domain filter
            queries = []
            if org_name:
                queries.append(f'{base_query} org:"{org_name}"')
            for domain in domains[:3]:  # Limit domain queries
                queries.append(f'{base_query} hostname:"{domain}"')
                queries.append(f'{base_query} ssl:"{domain}"')

            for query in queries:
                try:
                    result = await loop.run_in_executor(
                        None,
                        lambda q=query: api.search(q, limit=20)
                    )

                    for match in result.get("matches", []):
                        match["_at_service_type"] = service_key
                        match["_at_severity"] = service_info["severity"]
                        match["_at_category"] = service_info["category"]
                        match["_at_description"] = service_info["description"]
                        all_matches.append(match)

                    await asyncio.sleep(1.0)  # Rate limiting

                except Exception:
                    continue

    except Exception:
        pass

    # Deduplicate by IP
    seen_ips = set()
    unique_matches = []
    for match in all_matches:
        ip = match.get("ip_str")
        if ip and ip not in seen_ips:
            seen_ips.add(ip)
            unique_matches.append(match)

    return unique_matches


def parse_internetdb_data(internetdb_data: dict, ip: IPAddress) -> tuple[IPAddress, list[Finding]]:
    """Parse Shodan InternetDB data and update IP address record."""
    findings = []

    # Hostnames
    hostnames = internetdb_data.get("hostnames", [])
    if hostnames:
        ip.hostnames = hostnames
        ip.reverse_dns = hostnames

    # Ports
    ports = internetdb_data.get("ports", [])
    for port_num in ports:
        if not any(p.number == port_num for p in ip.ports):
            port = Port(
                number=port_num,
                protocol="tcp",
                state=PortState.OPEN,
                service=Service(name="unknown"),
            )
            ip.ports.append(port)

    # CPEs (can indicate specific software)
    cpes = internetdb_data.get("cpes", [])
    for cpe in cpes:
        cpe_lower = cpe.lower()
        # Check for known dangerous services in CPE
        for service_name, (severity, desc) in SHODAN_MODULE_SEVERITY.items():
            if service_name in cpe_lower:
                finding = Finding(
                    title=f"{desc} detected on {ip.address}",
                    description=f"Shodan InternetDB indicates {desc} is running on this host.",
                    severity=severity,
                    category="service_exposure",
                    affected_asset=ip.address,
                    affected_asset_type="ip",
                    evidence=f"CPE: {cpe}",
                    source="shodan_internetdb",
                )
                findings.append(finding)
                break

    # Tags (e.g., "database", "self-signed", "cloud")
    tags = internetdb_data.get("tags", [])
    dangerous_tags = {
        "database": (Severity.HIGH, "Database service"),
        "self-signed": (Severity.LOW, "Self-signed certificate"),
        "compromised": (Severity.CRITICAL, "Potentially compromised host"),
        "malware": (Severity.CRITICAL, "Malware indicators"),
        "c2": (Severity.CRITICAL, "Command & Control indicators"),
    }

    for tag in tags:
        tag_lower = tag.lower()
        if tag_lower in dangerous_tags:
            severity, desc = dangerous_tags[tag_lower]
            finding = Finding(
                title=f"{desc} indicator on {ip.address}",
                description=f"Shodan tagged this host as '{tag}'",
                severity=severity,
                category="threat_indicator",
                affected_asset=ip.address,
                affected_asset_type="ip",
                evidence=f"Tags: {', '.join(tags)}",
                source="shodan_internetdb",
            )
            findings.append(finding)

    # Vulnerabilities
    vulns = internetdb_data.get("vulns", [])
    for vuln_id in vulns:
        finding = Finding(
            title=f"Vulnerability {vuln_id} on {ip.address}",
            description=f"Shodan InternetDB indicates this host may be vulnerable to {vuln_id}",
            severity=Severity.HIGH if "CVE-" in vuln_id else Severity.MEDIUM,
            category="vulnerability",
            affected_asset=ip.address,
            affected_asset_type="ip",
            cve=[vuln_id] if vuln_id.startswith("CVE-") else [],
            source="shodan_internetdb",
        )
        findings.append(finding)

    return ip, findings


def parse_shodan_data(shodan_data: dict, ip: IPAddress) -> IPAddress:
    """Parse Shodan data and update IP address record."""
    # Basic info
    ip.asn = shodan_data.get("asn", "").replace("AS", "")
    if ip.asn:
        try:
            ip.asn = int(ip.asn)
        except ValueError:
            ip.asn = None

    ip.asn_org = shodan_data.get("org", "")

    # Geolocation
    ip.geolocation = GeoLocation(
        country=shodan_data.get("country_name", ""),
        country_code=shodan_data.get("country_code", ""),
        city=shodan_data.get("city", ""),
        latitude=shodan_data.get("latitude"),
        longitude=shodan_data.get("longitude"),
    )

    # Cloud provider detection
    cloud_keywords = {
        "amazon": CloudProvider.AWS,
        "aws": CloudProvider.AWS,
        "microsoft": CloudProvider.AZURE,
        "azure": CloudProvider.AZURE,
        "google": CloudProvider.GCP,
        "digitalocean": CloudProvider.DIGITALOCEAN,
    }

    org_lower = ip.asn_org.lower()
    for keyword, provider in cloud_keywords.items():
        if keyword in org_lower:
            ip.cloud_provider = provider
            break

    # Hostnames
    ip.hostnames = shodan_data.get("hostnames", [])
    ip.reverse_dns = shodan_data.get("hostnames", [])

    # OS fingerprint
    ip.os_fingerprint = shodan_data.get("os", "")

    # Ports and services
    for service_data in shodan_data.get("data", []):
        port_num = service_data.get("port")
        if port_num:
            # Check if we already have this port
            existing_port = next(
                (p for p in ip.ports if p.number == port_num),
                None
            )

            service = Service(
                name=service_data.get("_shodan", {}).get("module", "unknown"),
                product=service_data.get("product", ""),
                version=service_data.get("version", ""),
                banner=service_data.get("data", "")[:500],
                cpe=service_data.get("cpe", []),
            )

            if existing_port:
                # Update existing port with Shodan data
                if not existing_port.service.product:
                    existing_port.service = service
            else:
                # Add new port
                port = Port(
                    number=port_num,
                    protocol=service_data.get("transport", "tcp"),
                    state=PortState.OPEN,
                    service=service,
                )
                ip.ports.append(port)

    return ip


def extract_vulnerabilities(shodan_data: dict, ip: IPAddress) -> list[Finding]:
    """Extract vulnerability and service exposure findings from Shodan data."""
    findings = []

    vulns = shodan_data.get("vulns", [])
    for vuln_id in vulns:
        finding = Finding(
            title=f"Potential vulnerability: {vuln_id}",
            description=f"Shodan detected potential vulnerability {vuln_id} on {ip.address}",
            severity=Severity.HIGH,
            category="vulnerability",
            affected_asset=ip.address,
            affected_asset_type="ip",
            cve=[vuln_id] if vuln_id.startswith("CVE-") else [],
            source="shodan",
        )
        findings.append(finding)

    # Check for specific dangerous services
    for service_data in shodan_data.get("data", []):
        module = service_data.get("_shodan", {}).get("module", "").lower()
        port = service_data.get("port", 0)
        data = service_data.get("data", "")
        product = service_data.get("product", "").lower()

        # Check module against known dangerous services
        if module in SHODAN_MODULE_SEVERITY:
            severity, desc = SHODAN_MODULE_SEVERITY[module]

            # Determine if it's unauthenticated
            is_unauth = False
            extra_info = ""

            if module in ["mongodb", "mongo"]:
                if "totalSize" in data or "serverStatus" in data:
                    is_unauth = True
                    extra_info = "Database appears accessible without authentication"

            elif module in ["redis"]:
                if "redis_version" in data and "NOAUTH" not in data.upper():
                    is_unauth = True
                    extra_info = "Redis responds without authentication"

            elif module in ["elasticsearch", "elastic"]:
                if "cluster_name" in data:
                    is_unauth = True
                    extra_info = "Cluster info exposed"

            elif module in ["docker"]:
                if "Docker" in data or "API version" in data:
                    is_unauth = True
                    extra_info = "Docker API exposed - critical security risk"

            elif module in ["kubernetes", "kubelet"]:
                is_unauth = True
                extra_info = "Kubernetes component exposed"

            elif module in ["etcd"]:
                is_unauth = True
                extra_info = "etcd key-value store exposed"

            elif module in ["jenkins"]:
                if "X-Jenkins" in data or "Dashboard" in data:
                    extra_info = "Jenkins CI/CD exposed"

            elif module in ["memcached"]:
                if "STAT" in data:
                    is_unauth = True
                    extra_info = "Memcached responds to commands"

            # Create finding
            if is_unauth:
                severity = Severity.CRITICAL

            finding = Finding(
                title=f"{'CRITICAL: ' if is_unauth else ''}{desc} exposed on {ip.address}:{port}",
                description=f"{desc} is accessible from the internet. {extra_info}",
                severity=severity,
                category="service_exposure",
                affected_asset=f"{ip.address}:{port}",
                affected_asset_type=module,
                evidence=data[:300] if data else f"Module: {module}",
                source="shodan",
            )
            findings.append(finding)

        # Also check product names
        elif product:
            for service_name, (severity, desc) in SHODAN_MODULE_SEVERITY.items():
                if service_name in product:
                    finding = Finding(
                        title=f"{desc} detected on {ip.address}:{port}",
                        description=f"{desc} appears to be running on this host.",
                        severity=severity,
                        category="service_exposure",
                        affected_asset=f"{ip.address}:{port}",
                        affected_asset_type=service_name,
                        evidence=f"Product: {service_data.get('product', '')} {service_data.get('version', '')}",
                        source="shodan",
                    )
                    findings.append(finding)
                    break

        # Check for other dangerous services by port
        dangerous_ports = {
            27017: ("MongoDB", Severity.CRITICAL),
            27018: ("MongoDB", Severity.CRITICAL),
            6379: ("Redis", Severity.CRITICAL),
            9200: ("Elasticsearch", Severity.HIGH),
            5984: ("CouchDB", Severity.HIGH),
            2379: ("etcd", Severity.CRITICAL),
            2375: ("Docker API", Severity.CRITICAL),
            2376: ("Docker API", Severity.CRITICAL),
            5672: ("RabbitMQ", Severity.HIGH),
            11211: ("Memcached", Severity.MEDIUM),
            9042: ("Cassandra", Severity.HIGH),
            9092: ("Kafka", Severity.HIGH),
            6443: ("Kubernetes API", Severity.CRITICAL),
            10250: ("Kubelet", Severity.CRITICAL),
        }

        if port in dangerous_ports and module not in SHODAN_MODULE_SEVERITY:
            service_name, severity = dangerous_ports[port]
            finding = Finding(
                title=f"{service_name} port open on {ip.address}:{port}",
                description=f"Port {port} commonly used by {service_name} is open.",
                severity=severity,
                category="service_exposure",
                affected_asset=f"{ip.address}:{port}",
                affected_asset_type="port",
                evidence=f"Open port: {port}",
                source="shodan",
            )
            findings.append(finding)

    return findings


async def run(
    session: ScanSession,
    config: AttackTraceConfig,
    orchestrator,
) -> ModuleResult:
    """
    Run Shodan enrichment on discovered IP addresses.

    This module:
    1. Uses Shodan InternetDB (FREE) for basic enrichment of all IPs
    2. Uses Shodan API (if key provided) for detailed host info
    3. Searches for exposed services (MongoDB, Redis, Jenkins, etc.)
    4. Searches by organization name for additional IPs
    5. Detects dangerous services and misconfigurations

    Args:
        session: Current scan session
        config: AttackTrace configuration
        orchestrator: Orchestrator instance

    Returns:
        ModuleResult with enriched data
    """
    result = ModuleResult(
        module_name="shodan_enrichment",
        started_at=datetime.utcnow(),
    )

    enriched_count = 0
    has_api_key = bool(config.api_keys.shodan)

    # Phase 1: Use FREE Shodan InternetDB for all IPs
    if orchestrator.console:
        orchestrator.console.print("[dim]Querying Shodan InternetDB (free)...[/dim]")

    internetdb_semaphore = asyncio.Semaphore(10)

    async def query_internetdb_with_limit(ip: IPAddress):
        async with internetdb_semaphore:
            internetdb_data = await query_shodan_internetdb(ip.address)
            if internetdb_data:
                return parse_internetdb_data(internetdb_data, ip)
            return (ip, [])

    # Query InternetDB for all IPs
    internetdb_tasks = [query_internetdb_with_limit(ip) for ip in session.ip_addresses]
    internetdb_results = await asyncio.gather(*internetdb_tasks, return_exceptions=True)

    for result_data in internetdb_results:
        if isinstance(result_data, tuple):
            ip, findings = result_data
            result.findings.extend(findings)
            if findings:
                enriched_count += 1

    # Phase 2: Use Shodan API for detailed info (if key provided)
    if has_api_key:
        if orchestrator.console:
            orchestrator.console.print("[dim]Enriching IPs with Shodan API...[/dim]")

        for ip in session.ip_addresses[:50]:  # Limit to avoid rate limits
            try:
                shodan_data = await query_shodan(ip.address, config.api_keys.shodan)

                if shodan_data:
                    # Update IP with Shodan data
                    ip = parse_shodan_data(shodan_data, ip)
                    result.ip_addresses.append(ip)

                    # Extract vulnerability findings
                    findings = extract_vulnerabilities(shodan_data, ip)
                    result.findings.extend(findings)

                    enriched_count += 1

                # Rate limiting (Shodan has strict rate limits)
                await asyncio.sleep(1.0)

            except Exception:
                continue

        # Phase 3: Search by organization name for additional IPs
        if session.target_company:
            if orchestrator.console:
                orchestrator.console.print(f"[dim]Searching Shodan for organization: {session.target_company}...[/dim]")

            try:
                org_results = await search_shodan_org(
                    session.target_company,
                    config.api_keys.shodan
                )

                existing_ips = {ip.address for ip in session.ip_addresses}

                for host_data in org_results[:50]:  # Limit results
                    ip_addr = host_data.get("ip_str")
                    if ip_addr and ip_addr not in existing_ips:
                        # New IP discovered through org search
                        ip = IPAddress(
                            address=ip_addr,
                            version=6 if ":" in ip_addr else 4,
                            source="shodan_org_search",
                        )
                        ip = parse_shodan_data({"data": [host_data]}, ip)
                        result.ip_addresses.append(ip)

                        # Also check for service exposure
                        findings = extract_vulnerabilities({"data": [host_data]}, ip)
                        result.findings.extend(findings)

                        existing_ips.add(ip_addr)
                        enriched_count += 1

            except Exception:
                pass

        # Phase 4: Search for specific exposed services
        if session.target_company or session.target_domains:
            if orchestrator.console:
                orchestrator.console.print("[dim]Searching Shodan for exposed services (databases, CI/CD, etc.)...[/dim]")

            try:
                service_matches = await search_shodan_services(
                    session.target_company or "",
                    session.target_domains,
                    config.api_keys.shodan,
                    services=None,  # Search for all known services
                )

                existing_ips = {ip.address for ip in session.ip_addresses} | {ip.address for ip in result.ip_addresses}

                for match in service_matches:
                    ip_addr = match.get("ip_str")
                    service_type = match.get("_at_service_type", "unknown")
                    severity = match.get("_at_severity", Severity.MEDIUM)
                    category = match.get("_at_category", "service_exposure")
                    description = match.get("_at_description", "Exposed service")

                    # Create finding for the exposed service
                    port = match.get("port", 0)
                    finding = Finding(
                        title=f"{description}: {ip_addr}:{port}",
                        description=f"Shodan search found {service_type} exposed for target organization.",
                        severity=severity,
                        category=category,
                        affected_asset=f"{ip_addr}:{port}",
                        affected_asset_type=service_type,
                        evidence=match.get("data", "")[:300],
                        source="shodan_service_search",
                    )
                    result.findings.append(finding)

                    # Add IP if not already known
                    if ip_addr and ip_addr not in existing_ips:
                        ip = IPAddress(
                            address=ip_addr,
                            version=6 if ":" in ip_addr else 4,
                            source="shodan_service_search",
                        )
                        ip.ports.append(Port(
                            number=port,
                            protocol=match.get("transport", "tcp"),
                            state=PortState.OPEN,
                            service=Service(
                                name=service_type,
                                product=match.get("product", ""),
                                version=match.get("version", ""),
                            ),
                        ))
                        result.ip_addresses.append(ip)
                        existing_ips.add(ip_addr)
                        enriched_count += 1

            except Exception:
                pass

    else:
        # No API key - just report that we used InternetDB
        if orchestrator.console:
            orchestrator.console.print(
                "[yellow]Note: Add Shodan API key for deeper service discovery[/yellow]"
            )

    # Create summary finding if many exposed services found
    service_findings = [f for f in result.findings if f.category in ["service_exposure", "database_exposure"]]
    if len(service_findings) > 3:
        critical_count = sum(1 for f in service_findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in service_findings if f.severity == Severity.HIGH)

        summary = Finding(
            title=f"Multiple exposed services detected ({len(service_findings)} total)",
            description=f"Shodan identified {len(service_findings)} exposed services including "
                       f"{critical_count} critical and {high_count} high severity. "
                       f"These may include databases, CI/CD systems, and other sensitive infrastructure.",
            severity=Severity.CRITICAL if critical_count > 0 else Severity.HIGH,
            category="exposure_summary",
            affected_asset=session.target_company or session.target_domains[0] if session.target_domains else "",
            affected_asset_type="organization",
            evidence=f"Services found: {', '.join(set(f.affected_asset_type for f in service_findings[:10]))}",
            source="shodan",
        )
        result.findings.insert(0, summary)

    result.items_discovered = enriched_count
    result.success = True
    result.completed_at = datetime.utcnow()

    return result
