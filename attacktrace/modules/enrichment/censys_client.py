"""
Censys enrichment module.

Enriches discovered assets with Censys data including:
- Host information
- Service details
- Certificate data
- Historical records
- Exposed service detection (databases, CI/CD, containers, etc.)
"""

import asyncio
from datetime import datetime
from typing import Optional
import base64

import httpx

from attacktrace.config import AttackTraceConfig
from attacktrace.core.models import (
    ModuleResult,
    IPAddress,
    Port,
    Service,
    PortState,
    Certificate,
    GeoLocation,
    CloudProvider,
    Finding,
    Severity,
    ScanSession,
)


# Service-specific Censys search queries for finding exposed resources
# These queries are used to discover exposed services by organization/domain
CENSYS_SERVICE_SEARCHES = {
    # Databases
    "mongodb": {
        "query": 'services.service_name:"MONGODB"',
        "ports": [27017, 27018, 27019],
        "severity": Severity.CRITICAL,
        "title": "MongoDB Database Exposed",
        "description": "MongoDB database server accessible from the internet without apparent authentication.",
        "category": "exposed_database",
    },
    "redis": {
        "query": 'services.service_name:"REDIS"',
        "ports": [6379, 6380],
        "severity": Severity.CRITICAL,
        "title": "Redis Server Exposed",
        "description": "Redis in-memory database accessible from the internet. May allow unauthorized data access or command execution.",
        "category": "exposed_database",
    },
    "elasticsearch": {
        "query": 'services.service_name:"ELASTICSEARCH"',
        "ports": [9200, 9300],
        "severity": Severity.HIGH,
        "title": "Elasticsearch Cluster Exposed",
        "description": "Elasticsearch cluster accessible from the internet without authentication.",
        "category": "exposed_database",
    },
    "mysql": {
        "query": 'services.service_name:"MYSQL"',
        "ports": [3306],
        "severity": Severity.HIGH,
        "title": "MySQL Database Exposed",
        "description": "MySQL database server accessible from the internet.",
        "category": "exposed_database",
    },
    "postgresql": {
        "query": 'services.service_name:"POSTGRESQL"',
        "ports": [5432],
        "severity": Severity.HIGH,
        "title": "PostgreSQL Database Exposed",
        "description": "PostgreSQL database server accessible from the internet.",
        "category": "exposed_database",
    },
    "memcached": {
        "query": 'services.service_name:"MEMCACHED"',
        "ports": [11211],
        "severity": Severity.MEDIUM,
        "title": "Memcached Server Exposed",
        "description": "Memcached caching server accessible from the internet. May leak cached data.",
        "category": "exposed_database",
    },
    "cassandra": {
        "query": 'services.port:9042',
        "ports": [9042, 7000, 7001],
        "severity": Severity.HIGH,
        "title": "Cassandra Database Exposed",
        "description": "Apache Cassandra database accessible from the internet.",
        "category": "exposed_database",
    },
    "couchdb": {
        "query": 'services.http.response.html_title:"CouchDB"',
        "ports": [5984],
        "severity": Severity.HIGH,
        "title": "CouchDB Database Exposed",
        "description": "Apache CouchDB database accessible from the internet.",
        "category": "exposed_database",
    },

    # CI/CD and DevOps
    "jenkins": {
        "query": 'services.http.response.html_title:"Jenkins" OR services.http.response.html_title:"Dashboard [Jenkins]"',
        "ports": [8080, 8443, 80, 443],
        "severity": Severity.HIGH,
        "title": "Jenkins CI/CD Server Exposed",
        "description": "Jenkins automation server accessible from the internet. May allow code execution or credential exposure.",
        "category": "exposed_service",
    },
    "gitlab": {
        "query": 'services.http.response.html_title:"GitLab"',
        "ports": [80, 443, 8080],
        "severity": Severity.MEDIUM,
        "title": "GitLab Instance Exposed",
        "description": "GitLab instance accessible from the internet. Verify authentication and access controls.",
        "category": "exposed_service",
    },
    "sonarqube": {
        "query": 'services.http.response.html_title:"SonarQube"',
        "ports": [9000, 443],
        "severity": Severity.MEDIUM,
        "title": "SonarQube Server Exposed",
        "description": "SonarQube code analysis server accessible from the internet. May expose code quality data.",
        "category": "exposed_service",
    },
    "nexus": {
        "query": 'services.http.response.html_title:"Nexus Repository"',
        "ports": [8081, 443],
        "severity": Severity.MEDIUM,
        "title": "Nexus Repository Exposed",
        "description": "Nexus artifact repository accessible from the internet.",
        "category": "exposed_service",
    },
    "artifactory": {
        "query": 'services.http.response.html_title:"Artifactory"',
        "ports": [8081, 8082, 443],
        "severity": Severity.MEDIUM,
        "title": "JFrog Artifactory Exposed",
        "description": "JFrog Artifactory repository accessible from the internet.",
        "category": "exposed_service",
    },

    # Container and Orchestration
    "docker_api": {
        "query": 'services.port:2375 OR services.port:2376',
        "ports": [2375, 2376],
        "severity": Severity.CRITICAL,
        "title": "Docker API Exposed",
        "description": "Docker daemon API accessible from the internet. Critical security risk allowing container manipulation.",
        "category": "exposed_service",
    },
    "docker_registry": {
        "query": 'services.http.response.headers.Docker-Distribution-Api-Version:*',
        "ports": [5000, 443],
        "severity": Severity.HIGH,
        "title": "Docker Registry Exposed",
        "description": "Docker container registry accessible from the internet. May expose container images.",
        "category": "exposed_service",
    },
    "kubernetes_api": {
        "query": 'services.port:6443 AND services.tls.certificates.leaf.parsed.subject.common_name:*kubernetes*',
        "ports": [6443, 8443],
        "severity": Severity.CRITICAL,
        "title": "Kubernetes API Server Exposed",
        "description": "Kubernetes API server accessible from the internet. May allow cluster manipulation.",
        "category": "exposed_service",
    },
    "etcd": {
        "query": 'services.port:2379',
        "ports": [2379, 2380],
        "severity": Severity.CRITICAL,
        "title": "etcd Server Exposed",
        "description": "etcd key-value store exposed. May contain Kubernetes secrets and configuration.",
        "category": "exposed_service",
    },
    "portainer": {
        "query": 'services.http.response.html_title:"Portainer"',
        "ports": [9000, 9443],
        "severity": Severity.HIGH,
        "title": "Portainer Dashboard Exposed",
        "description": "Portainer container management UI accessible from the internet.",
        "category": "exposed_service",
    },

    # Message Queues
    "rabbitmq": {
        "query": 'services.http.response.html_title:"RabbitMQ Management"',
        "ports": [15672, 5672],
        "severity": Severity.HIGH,
        "title": "RabbitMQ Management Exposed",
        "description": "RabbitMQ message broker management interface accessible from the internet.",
        "category": "exposed_service",
    },
    "kafka": {
        "query": 'services.port:9092',
        "ports": [9092, 9093],
        "severity": Severity.HIGH,
        "title": "Apache Kafka Exposed",
        "description": "Apache Kafka message broker accessible from the internet.",
        "category": "exposed_service",
    },

    # Monitoring and Logging
    "kibana": {
        "query": 'services.http.response.html_title:"Kibana"',
        "ports": [5601],
        "severity": Severity.MEDIUM,
        "title": "Kibana Dashboard Exposed",
        "description": "Kibana visualization dashboard accessible from the internet. May expose log data.",
        "category": "exposed_service",
    },
    "grafana": {
        "query": 'services.http.response.html_title:"Grafana"',
        "ports": [3000],
        "severity": Severity.MEDIUM,
        "title": "Grafana Dashboard Exposed",
        "description": "Grafana monitoring dashboard accessible from the internet.",
        "category": "exposed_service",
    },
    "prometheus": {
        "query": 'services.http.response.html_title:"Prometheus"',
        "ports": [9090],
        "severity": Severity.MEDIUM,
        "title": "Prometheus Server Exposed",
        "description": "Prometheus metrics server accessible from the internet. May expose internal metrics.",
        "category": "exposed_service",
    },

    # Admin Panels
    "phpmyadmin": {
        "query": 'services.http.response.html_title:"phpMyAdmin"',
        "ports": [80, 443, 8080],
        "severity": Severity.HIGH,
        "title": "phpMyAdmin Exposed",
        "description": "phpMyAdmin database management panel accessible from the internet.",
        "category": "exposed_service",
    },
    "adminer": {
        "query": 'services.http.response.html_title:"Adminer"',
        "ports": [80, 443, 8080],
        "severity": Severity.HIGH,
        "title": "Adminer Database Manager Exposed",
        "description": "Adminer database management tool accessible from the internet.",
        "category": "exposed_service",
    },

    # Remote Access
    "rdp": {
        "query": 'services.service_name:"RDP"',
        "ports": [3389],
        "severity": Severity.HIGH,
        "title": "RDP Service Exposed",
        "description": "Remote Desktop Protocol service accessible from the internet.",
        "category": "exposed_service",
    },
    "vnc": {
        "query": 'services.service_name:"VNC"',
        "ports": [5900, 5901, 5902],
        "severity": Severity.HIGH,
        "title": "VNC Service Exposed",
        "description": "VNC remote access service accessible from the internet.",
        "category": "exposed_service",
    },
    "ssh": {
        "query": 'services.service_name:"SSH"',
        "ports": [22],
        "severity": Severity.INFO,
        "title": "SSH Service Detected",
        "description": "SSH service accessible from the internet. Ensure key-based auth and no default credentials.",
        "category": "exposed_service",
    },
    "telnet": {
        "query": 'services.service_name:"TELNET"',
        "ports": [23],
        "severity": Severity.HIGH,
        "title": "Telnet Service Exposed",
        "description": "Telnet service accessible from the internet. Transmits credentials in cleartext.",
        "category": "exposed_service",
    },

    # Legacy/Insecure Protocols
    "smb": {
        "query": 'services.port:445',
        "ports": [445, 139],
        "severity": Severity.CRITICAL,
        "title": "SMB Service Exposed",
        "description": "SMB/CIFS file sharing service exposed to the internet. High risk for ransomware and data theft.",
        "category": "exposed_service",
    },
    "ftp": {
        "query": 'services.service_name:"FTP"',
        "ports": [21],
        "severity": Severity.MEDIUM,
        "title": "FTP Service Exposed",
        "description": "FTP service accessible from the internet. Credentials transmitted in cleartext.",
        "category": "exposed_service",
    },
    "nfs": {
        "query": 'services.port:2049',
        "ports": [2049, 111],
        "severity": Severity.HIGH,
        "title": "NFS Service Exposed",
        "description": "NFS file sharing service exposed to the internet.",
        "category": "exposed_service",
    },
}

# Severity mapping for various service types detected by port
CENSYS_PORT_SEVERITY = {
    # Critical - immediate access possible
    27017: Severity.CRITICAL,  # MongoDB
    6379: Severity.CRITICAL,   # Redis
    2375: Severity.CRITICAL,   # Docker API (unencrypted)
    2379: Severity.CRITICAL,   # etcd
    6443: Severity.CRITICAL,   # Kubernetes API
    445: Severity.CRITICAL,    # SMB

    # High - sensitive service exposure
    9200: Severity.HIGH,       # Elasticsearch
    3306: Severity.HIGH,       # MySQL
    5432: Severity.HIGH,       # PostgreSQL
    8080: Severity.HIGH,       # Common web services (Jenkins, etc.)
    5672: Severity.HIGH,       # RabbitMQ
    3389: Severity.HIGH,       # RDP
    5900: Severity.HIGH,       # VNC

    # Medium - requires review
    11211: Severity.MEDIUM,    # Memcached
    5601: Severity.MEDIUM,     # Kibana
    9090: Severity.MEDIUM,     # Prometheus
    3000: Severity.MEDIUM,     # Grafana

    # Low/Info
    22: Severity.INFO,         # SSH (normal)
    80: Severity.INFO,         # HTTP
    443: Severity.INFO,        # HTTPS
}


class CensysClient:
    """Async client for Censys API."""

    BASE_URL = "https://search.censys.io/api/v2"

    def __init__(self, api_id: str, api_secret: str):
        self.api_id = api_id
        self.api_secret = api_secret
        self._auth = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()

    async def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[dict] = None,
        json_data: Optional[dict] = None,
        timeout: float = 30.0,
    ) -> Optional[dict]:
        """Make an authenticated request to Censys API."""
        url = f"{self.BASE_URL}/{endpoint}"
        headers = {
            "Authorization": f"Basic {self._auth}",
            "Accept": "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.request(
                    method,
                    url,
                    headers=headers,
                    params=params,
                    json=json_data,
                )

                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 429:
                    # Rate limited
                    await asyncio.sleep(5)
                    return None

        except Exception:
            pass

        return None

    async def get_host(self, ip: str) -> Optional[dict]:
        """Get host information for an IP address."""
        return await self._request("GET", f"hosts/{ip}")

    async def search_hosts(
        self,
        query: str,
        per_page: int = 50,
        cursor: Optional[str] = None,
    ) -> Optional[dict]:
        """Search for hosts matching a query."""
        params = {"q": query, "per_page": per_page}
        if cursor:
            params["cursor"] = cursor
        return await self._request("GET", "hosts/search", params=params)

    async def get_certificate(self, fingerprint: str) -> Optional[dict]:
        """Get certificate details by SHA256 fingerprint."""
        return await self._request("GET", f"certificates/{fingerprint}")

    async def search_certificates(
        self,
        query: str,
        per_page: int = 50,
    ) -> Optional[dict]:
        """Search for certificates."""
        params = {"q": query, "per_page": per_page}
        return await self._request("GET", "certificates/search", params=params)

    async def search_services_by_org(
        self,
        org_name: str,
        service_query: str,
        per_page: int = 100,
    ) -> Optional[dict]:
        """
        Search for specific services associated with an organization.

        Args:
            org_name: Organization name to search for
            service_query: Service-specific query to combine with org search
            per_page: Results per page

        Returns:
            Search results or None
        """
        # Combine org search with service query
        query = f'(autonomous_system.name:"{org_name}" OR services.tls.certificates.leaf.parsed.subject.organization:"{org_name}") AND ({service_query})'
        return await self.search_hosts(query, per_page=per_page)

    async def search_services_by_domain(
        self,
        domain: str,
        service_query: str,
        per_page: int = 100,
    ) -> Optional[dict]:
        """
        Search for specific services associated with a domain.

        Args:
            domain: Domain to search for
            service_query: Service-specific query to combine with domain search
            per_page: Results per page

        Returns:
            Search results or None
        """
        # Search by domain in DNS names or certificate SANs
        query = f'(dns.names:"{domain}" OR services.tls.certificates.leaf.parsed.names:"{domain}") AND ({service_query})'
        return await self.search_hosts(query, per_page=per_page)

    async def search_exposed_service(
        self,
        service_type: str,
        org_name: Optional[str] = None,
        domain: Optional[str] = None,
        per_page: int = 50,
    ) -> list[dict]:
        """
        Search for a specific exposed service type.

        Args:
            service_type: Key from CENSYS_SERVICE_SEARCHES
            org_name: Optional organization name to filter
            domain: Optional domain to filter
            per_page: Results per page

        Returns:
            List of matching hosts
        """
        if service_type not in CENSYS_SERVICE_SEARCHES:
            return []

        service_config = CENSYS_SERVICE_SEARCHES[service_type]
        base_query = service_config["query"]
        results = []

        try:
            if org_name:
                data = await self.search_services_by_org(org_name, base_query, per_page)
                if data and data.get("result", {}).get("hits"):
                    results.extend(data["result"]["hits"])

            if domain:
                data = await self.search_services_by_domain(domain, base_query, per_page)
                if data and data.get("result", {}).get("hits"):
                    # Avoid duplicates
                    existing_ips = {r.get("ip") for r in results}
                    for hit in data["result"]["hits"]:
                        if hit.get("ip") not in existing_ips:
                            results.append(hit)

        except Exception:
            pass

        return results


def parse_censys_host(data: dict, ip: IPAddress) -> IPAddress:
    """Parse Censys host data and update IP address record."""
    result = data.get("result", {})

    # Autonomous System info
    autonomous_system = result.get("autonomous_system", {})
    if autonomous_system:
        ip.asn = autonomous_system.get("asn")
        ip.asn_org = autonomous_system.get("name", "")
        ip.asn_country = autonomous_system.get("country_code", "")

    # Location
    location = result.get("location", {})
    if location:
        ip.geolocation = GeoLocation(
            country=location.get("country", ""),
            country_code=location.get("country_code", ""),
            city=location.get("city", ""),
            latitude=location.get("coordinates", {}).get("latitude"),
            longitude=location.get("coordinates", {}).get("longitude"),
        )

    # Cloud provider detection
    cloud_info = result.get("cloud", {})
    if cloud_info:
        provider_map = {
            "AWS": CloudProvider.AWS,
            "AMAZON": CloudProvider.AWS,
            "AZURE": CloudProvider.AZURE,
            "MICROSOFT": CloudProvider.AZURE,
            "GOOGLE": CloudProvider.GCP,
            "GCP": CloudProvider.GCP,
            "DIGITALOCEAN": CloudProvider.DIGITALOCEAN,
        }
        provider_name = cloud_info.get("provider", "").upper()
        for key, provider in provider_map.items():
            if key in provider_name:
                ip.cloud_provider = provider
                ip.cloud_region = cloud_info.get("region", "")
                break

    # Services/Ports
    services = result.get("services", [])
    for svc in services:
        port_num = svc.get("port")
        if not port_num:
            continue

        # Check if we already have this port
        existing_port = next((p for p in ip.ports if p.number == port_num), None)

        service = Service(
            name=svc.get("service_name", "unknown"),
            product=svc.get("software", [{}])[0].get("product", "") if svc.get("software") else "",
            version=svc.get("software", [{}])[0].get("version", "") if svc.get("software") else "",
            banner=svc.get("banner", "")[:500] if svc.get("banner") else "",
        )

        if existing_port:
            if not existing_port.service.product:
                existing_port.service = service
        else:
            port = Port(
                number=port_num,
                protocol=svc.get("transport_protocol", "tcp").lower(),
                state=PortState.OPEN,
                service=service,
            )
            ip.ports.append(port)

    # DNS names
    dns = result.get("dns", {})
    if dns:
        names = dns.get("names", [])
        ip.hostnames = list(set(ip.hostnames + names))
        ip.reverse_dns = list(set(ip.reverse_dns + dns.get("reverse_dns", {}).get("names", [])))

    # Operating system
    os_info = result.get("operating_system", {})
    if os_info:
        os_parts = []
        if os_info.get("vendor"):
            os_parts.append(os_info["vendor"])
        if os_info.get("product"):
            os_parts.append(os_info["product"])
        if os_info.get("version"):
            os_parts.append(os_info["version"])
        ip.os_fingerprint = " ".join(os_parts)

    return ip


def parse_censys_certificate(data: dict) -> Optional[Certificate]:
    """Parse Censys certificate data."""
    result = data.get("result", {})
    if not result:
        return None

    parsed = result.get("parsed", {})
    if not parsed:
        return None

    cert = Certificate(
        serial_number=parsed.get("serial_number", ""),
        subject=parsed.get("subject_dn", ""),
        issuer=parsed.get("issuer_dn", ""),
        fingerprint_sha256=result.get("fingerprint_sha256", ""),
    )

    # Subject Alternative Names
    names = parsed.get("names", [])
    cert.san = names

    # Validity
    validity = parsed.get("validity", {})
    if validity:
        try:
            if validity.get("start"):
                cert.not_before = datetime.fromisoformat(
                    validity["start"].replace("Z", "+00:00")
                )
            if validity.get("end"):
                cert.not_after = datetime.fromisoformat(
                    validity["end"].replace("Z", "+00:00")
                )
                cert.is_expired = cert.not_after < datetime.utcnow()
        except Exception:
            pass

    # Self-signed check
    cert.is_self_signed = parsed.get("subject_dn") == parsed.get("issuer_dn")

    return cert


def extract_findings(data: dict, ip: IPAddress) -> list[Finding]:
    """Extract security findings from Censys data."""
    findings = []
    result = data.get("result", {})

    services = result.get("services", [])
    for svc in services:
        service_name = svc.get("service_name", "").lower()
        port = svc.get("port", 0)
        banner = svc.get("banner", "")
        http_response = svc.get("http", {}).get("response", {})
        html_title = http_response.get("html_title", "").lower()

        # Databases
        if service_name == "mongodb" or port == 27017:
            findings.append(Finding(
                title=f"MongoDB Database Exposed on {ip.address}:{port}",
                description="MongoDB database server accessible from the internet without apparent authentication.",
                severity=Severity.CRITICAL,
                category="exposed_database",
                affected_asset=ip.address,
                affected_asset_type="ip",
                evidence=banner[:300] if banner else "",
                remediation="Restrict MongoDB access to internal networks. Enable authentication and use TLS.",
                source="censys",
            ))

        elif service_name == "redis" or port == 6379:
            findings.append(Finding(
                title=f"Redis Server Exposed on {ip.address}:{port}",
                description="Redis in-memory database accessible from the internet. May allow unauthorized data access or command execution.",
                severity=Severity.CRITICAL,
                category="exposed_database",
                affected_asset=ip.address,
                affected_asset_type="ip",
                evidence=banner[:300] if banner else "",
                remediation="Restrict Redis access to internal networks. Enable authentication with requirepass.",
                source="censys",
            ))

        elif service_name == "elasticsearch" or port == 9200:
            findings.append(Finding(
                title=f"Elasticsearch Cluster Exposed on {ip.address}:{port}",
                description="Elasticsearch cluster accessible from the internet without authentication.",
                severity=Severity.HIGH,
                category="exposed_database",
                affected_asset=ip.address,
                affected_asset_type="ip",
                evidence=banner[:300] if banner else "",
                remediation="Enable X-Pack security or restrict access to internal networks.",
                source="censys",
            ))

        elif service_name == "mysql" or port == 3306:
            findings.append(Finding(
                title=f"MySQL Database Exposed on {ip.address}:{port}",
                description="MySQL database server accessible from the internet.",
                severity=Severity.HIGH,
                category="exposed_database",
                affected_asset=ip.address,
                affected_asset_type="ip",
                evidence=banner[:300] if banner else "",
                remediation="Restrict MySQL access to internal networks. Use strong passwords and TLS.",
                source="censys",
            ))

        elif service_name == "postgresql" or port == 5432:
            findings.append(Finding(
                title=f"PostgreSQL Database Exposed on {ip.address}:{port}",
                description="PostgreSQL database server accessible from the internet.",
                severity=Severity.HIGH,
                category="exposed_database",
                affected_asset=ip.address,
                affected_asset_type="ip",
                evidence=banner[:300] if banner else "",
                remediation="Restrict PostgreSQL access. Configure pg_hba.conf properly.",
                source="censys",
            ))

        elif service_name == "memcached" or port == 11211:
            findings.append(Finding(
                title=f"Memcached Server Exposed on {ip.address}:{port}",
                description="Memcached caching server accessible from the internet. May leak cached data and be used for amplification attacks.",
                severity=Severity.MEDIUM,
                category="exposed_database",
                affected_asset=ip.address,
                affected_asset_type="ip",
                remediation="Restrict Memcached to localhost or internal networks.",
                source="censys",
            ))

        elif port == 9042:  # Cassandra
            findings.append(Finding(
                title=f"Cassandra Database Exposed on {ip.address}:{port}",
                description="Apache Cassandra database accessible from the internet.",
                severity=Severity.HIGH,
                category="exposed_database",
                affected_asset=ip.address,
                affected_asset_type="ip",
                evidence=banner[:300] if banner else "",
                remediation="Enable authentication and restrict access to internal networks.",
                source="censys",
            ))

        # CI/CD and DevOps
        elif "jenkins" in html_title:
            findings.append(Finding(
                title=f"Jenkins CI/CD Server Exposed on {ip.address}:{port}",
                description="Jenkins automation server accessible from the internet. May allow code execution or credential exposure.",
                severity=Severity.HIGH,
                category="exposed_service",
                affected_asset=ip.address,
                affected_asset_type="ip",
                evidence=f"HTML Title: {http_response.get('html_title', '')}",
                remediation="Restrict Jenkins access. Enable authentication and configure security realm.",
                source="censys",
            ))

        elif "gitlab" in html_title:
            findings.append(Finding(
                title=f"GitLab Instance Detected on {ip.address}:{port}",
                description="GitLab instance accessible from the internet. Verify authentication and access controls.",
                severity=Severity.MEDIUM,
                category="exposed_service",
                affected_asset=ip.address,
                affected_asset_type="ip",
                evidence=f"HTML Title: {http_response.get('html_title', '')}",
                remediation="Ensure GitLab has proper authentication and review signup settings.",
                source="censys",
            ))

        elif "sonarqube" in html_title:
            findings.append(Finding(
                title=f"SonarQube Server Exposed on {ip.address}:{port}",
                description="SonarQube code analysis server accessible from the internet. May expose code quality data.",
                severity=Severity.MEDIUM,
                category="exposed_service",
                affected_asset=ip.address,
                affected_asset_type="ip",
                evidence=f"HTML Title: {http_response.get('html_title', '')}",
                source="censys",
            ))

        # Container and Orchestration
        elif port in [2375, 2376]:
            findings.append(Finding(
                title=f"Docker API Exposed on {ip.address}:{port}",
                description="Docker daemon API accessible from the internet. Critical security risk allowing container manipulation and host access.",
                severity=Severity.CRITICAL,
                category="exposed_service",
                affected_asset=ip.address,
                affected_asset_type="ip",
                evidence=banner[:300] if banner else "",
                remediation="Never expose Docker API to the internet. Use TLS client authentication if remote access needed.",
                source="censys",
            ))

        elif port == 6443 and ("kubernetes" in banner.lower() or "k8s" in banner.lower()):
            findings.append(Finding(
                title=f"Kubernetes API Server Exposed on {ip.address}:{port}",
                description="Kubernetes API server accessible from the internet. May allow cluster manipulation.",
                severity=Severity.CRITICAL,
                category="exposed_service",
                affected_asset=ip.address,
                affected_asset_type="ip",
                evidence=banner[:300] if banner else "",
                remediation="Restrict API server access. Use private endpoints or VPN.",
                source="censys",
            ))

        elif port in [2379, 2380]:  # etcd
            findings.append(Finding(
                title=f"etcd Server Exposed on {ip.address}:{port}",
                description="etcd key-value store exposed to the internet. May contain Kubernetes secrets and configuration.",
                severity=Severity.CRITICAL,
                category="exposed_service",
                affected_asset=ip.address,
                affected_asset_type="ip",
                evidence=banner[:300] if banner else "",
                remediation="Never expose etcd to the internet. Restrict to cluster nodes only.",
                source="censys",
            ))

        elif "portainer" in html_title:
            findings.append(Finding(
                title=f"Portainer Dashboard Exposed on {ip.address}:{port}",
                description="Portainer container management UI accessible from the internet.",
                severity=Severity.HIGH,
                category="exposed_service",
                affected_asset=ip.address,
                affected_asset_type="ip",
                evidence=f"HTML Title: {http_response.get('html_title', '')}",
                remediation="Restrict Portainer access to internal networks or use VPN.",
                source="censys",
            ))

        # Check HTTP headers for Docker Registry
        headers = http_response.get("headers", {})
        if headers.get("docker-distribution-api-version"):
            findings.append(Finding(
                title=f"Docker Registry Exposed on {ip.address}:{port}",
                description="Docker container registry accessible from the internet. May expose container images.",
                severity=Severity.HIGH,
                category="exposed_service",
                affected_asset=ip.address,
                affected_asset_type="ip",
                evidence=f"Docker-Distribution-Api-Version: {headers.get('docker-distribution-api-version')}",
                remediation="Enable authentication for Docker registry. Use TLS.",
                source="censys",
            ))

        # Message Queues
        elif "rabbitmq" in html_title:
            findings.append(Finding(
                title=f"RabbitMQ Management Exposed on {ip.address}:{port}",
                description="RabbitMQ message broker management interface accessible from the internet.",
                severity=Severity.HIGH,
                category="exposed_service",
                affected_asset=ip.address,
                affected_asset_type="ip",
                evidence=f"HTML Title: {http_response.get('html_title', '')}",
                remediation="Restrict RabbitMQ management to internal networks. Change default credentials.",
                source="censys",
            ))

        elif port in [9092, 9093]:  # Kafka
            findings.append(Finding(
                title=f"Apache Kafka Exposed on {ip.address}:{port}",
                description="Apache Kafka message broker accessible from the internet.",
                severity=Severity.HIGH,
                category="exposed_service",
                affected_asset=ip.address,
                affected_asset_type="ip",
                evidence=banner[:300] if banner else "",
                remediation="Restrict Kafka access. Enable SASL authentication.",
                source="censys",
            ))

        # Monitoring and Logging
        elif "kibana" in html_title:
            findings.append(Finding(
                title=f"Kibana Dashboard Exposed on {ip.address}:{port}",
                description="Kibana visualization dashboard accessible from the internet. May expose sensitive log data.",
                severity=Severity.MEDIUM,
                category="exposed_service",
                affected_asset=ip.address,
                affected_asset_type="ip",
                evidence=f"HTML Title: {http_response.get('html_title', '')}",
                remediation="Enable X-Pack security or restrict Kibana access.",
                source="censys",
            ))

        elif "grafana" in html_title:
            findings.append(Finding(
                title=f"Grafana Dashboard Exposed on {ip.address}:{port}",
                description="Grafana monitoring dashboard accessible from the internet.",
                severity=Severity.MEDIUM,
                category="exposed_service",
                affected_asset=ip.address,
                affected_asset_type="ip",
                evidence=f"HTML Title: {http_response.get('html_title', '')}",
                remediation="Enable authentication. Review data source permissions.",
                source="censys",
            ))

        elif "prometheus" in html_title or port == 9090:
            if "prometheus" in html_title or "prometheus" in banner.lower():
                findings.append(Finding(
                    title=f"Prometheus Server Exposed on {ip.address}:{port}",
                    description="Prometheus metrics server accessible from the internet. May expose internal metrics and service topology.",
                    severity=Severity.MEDIUM,
                    category="exposed_service",
                    affected_asset=ip.address,
                    affected_asset_type="ip",
                    evidence=f"HTML Title: {http_response.get('html_title', '')}",
                    remediation="Restrict Prometheus access to internal networks.",
                    source="censys",
                ))

        # Admin Panels
        elif "phpmyadmin" in html_title:
            findings.append(Finding(
                title=f"phpMyAdmin Exposed on {ip.address}:{port}",
                description="phpMyAdmin database management panel accessible from the internet.",
                severity=Severity.HIGH,
                category="exposed_service",
                affected_asset=ip.address,
                affected_asset_type="ip",
                evidence=f"HTML Title: {http_response.get('html_title', '')}",
                remediation="Restrict phpMyAdmin to localhost or use VPN. Enable strong authentication.",
                source="censys",
            ))

        elif "adminer" in html_title:
            findings.append(Finding(
                title=f"Adminer Database Manager Exposed on {ip.address}:{port}",
                description="Adminer database management tool accessible from the internet.",
                severity=Severity.HIGH,
                category="exposed_service",
                affected_asset=ip.address,
                affected_asset_type="ip",
                evidence=f"HTML Title: {http_response.get('html_title', '')}",
                remediation="Remove Adminer from production or restrict access.",
                source="censys",
            ))

        # Remote Access
        elif service_name == "rdp" or port == 3389:
            findings.append(Finding(
                title=f"RDP Service Exposed on {ip.address}:{port}",
                description="Remote Desktop Protocol service accessible from the internet. High risk for brute force and exploitation.",
                severity=Severity.HIGH,
                category="exposed_service",
                affected_asset=ip.address,
                affected_asset_type="ip",
                remediation="Use VPN for RDP access. Enable Network Level Authentication.",
                source="censys",
            ))

        elif service_name == "vnc" or port in [5900, 5901, 5902]:
            findings.append(Finding(
                title=f"VNC Service Exposed on {ip.address}:{port}",
                description="VNC remote access service accessible from the internet.",
                severity=Severity.HIGH,
                category="exposed_service",
                affected_asset=ip.address,
                affected_asset_type="ip",
                remediation="Use VPN for VNC access. Enable strong passwords.",
                source="censys",
            ))

        elif service_name == "telnet" or port == 23:
            findings.append(Finding(
                title=f"Telnet Service Exposed on {ip.address}:{port}",
                description="Telnet transmits data in cleartext and should not be exposed to the internet.",
                severity=Severity.HIGH,
                category="exposed_service",
                affected_asset=ip.address,
                affected_asset_type="ip",
                remediation="Replace Telnet with SSH. Disable Telnet service.",
                source="censys",
            ))

        # Legacy/Insecure Protocols
        elif port == 445:  # SMB
            findings.append(Finding(
                title=f"SMB Service Exposed on {ip.address}:{port}",
                description="SMB/CIFS file sharing service exposed to the internet. High risk for ransomware and data theft.",
                severity=Severity.CRITICAL,
                category="exposed_service",
                affected_asset=ip.address,
                affected_asset_type="ip",
                remediation="Never expose SMB to the internet. Use VPN for file sharing.",
                source="censys",
            ))

        elif service_name == "ftp" or port == 21:
            anon_access = "anonymous" in banner.lower() if banner else False
            findings.append(Finding(
                title=f"FTP Service Exposed on {ip.address}:{port}" + (" (Anonymous Access)" if anon_access else ""),
                description="FTP service accessible from the internet. Credentials transmitted in cleartext." + (" Anonymous access enabled." if anon_access else ""),
                severity=Severity.HIGH if anon_access else Severity.MEDIUM,
                category="exposed_service",
                affected_asset=ip.address,
                affected_asset_type="ip",
                evidence=banner[:200] if banner else "",
                remediation="Replace FTP with SFTP. Disable anonymous access.",
                source="censys",
            ))

        elif port == 2049:  # NFS
            findings.append(Finding(
                title=f"NFS Service Exposed on {ip.address}:{port}",
                description="NFS file sharing service exposed to the internet.",
                severity=Severity.HIGH,
                category="exposed_service",
                affected_asset=ip.address,
                affected_asset_type="ip",
                remediation="Restrict NFS to internal networks. Review export permissions.",
                source="censys",
            ))

    # Check for expired/self-signed certificates
    for svc in services:
        tls = svc.get("tls", {})
        if tls:
            cert = tls.get("certificates", {}).get("leaf", {})
            if cert:
                parsed = cert.get("parsed", {})
                validity = parsed.get("validity", {})

                if validity.get("end"):
                    try:
                        end_date = datetime.fromisoformat(
                            validity["end"].replace("Z", "+00:00")
                        )
                        if end_date < datetime.utcnow():
                            findings.append(Finding(
                                title=f"Expired SSL Certificate on {ip.address}:{svc.get('port')}",
                                description=f"SSL certificate expired on {end_date.strftime('%Y-%m-%d')}",
                                severity=Severity.LOW,
                                category="misconfiguration",
                                affected_asset=ip.address,
                                affected_asset_type="ip",
                                source="censys",
                            ))
                    except Exception:
                        pass

                # Self-signed certificate check
                subject = parsed.get("subject_dn", "")
                issuer = parsed.get("issuer_dn", "")
                if subject and subject == issuer:
                    findings.append(Finding(
                        title=f"Self-Signed Certificate on {ip.address}:{svc.get('port')}",
                        description="SSL certificate is self-signed and not trusted by browsers.",
                        severity=Severity.LOW,
                        category="misconfiguration",
                        affected_asset=ip.address,
                        affected_asset_type="ip",
                        source="censys",
                    ))

    return findings


def create_finding_from_service_search(
    service_type: str,
    ip_address: str,
    port: int,
    evidence: str = "",
) -> Finding:
    """Create a finding from a service-specific search result."""
    if service_type not in CENSYS_SERVICE_SEARCHES:
        return Finding(
            title=f"Exposed Service on {ip_address}:{port}",
            description=f"Service detected on port {port}",
            severity=Severity.MEDIUM,
            category="exposed_service",
            affected_asset=ip_address,
            affected_asset_type="ip",
            source="censys",
        )

    config = CENSYS_SERVICE_SEARCHES[service_type]
    return Finding(
        title=f"{config['title']} on {ip_address}:{port}",
        description=config["description"],
        severity=config["severity"],
        category=config["category"],
        affected_asset=ip_address,
        affected_asset_type="ip",
        evidence=evidence[:500] if evidence else "",
        source="censys",
    )


async def run(
    session: ScanSession,
    config: AttackTraceConfig,
    orchestrator,
) -> ModuleResult:
    """
    Run Censys enrichment on discovered IP addresses.

    Includes:
    - Phase 1: Enrich known IPs with host data
    - Phase 2: Search certificates by domain
    - Phase 3: Search hosts by organization
    - Phase 4: Search for exposed services (databases, CI/CD, containers, etc.)

    Args:
        session: Current scan session
        config: AttackTrace configuration
        orchestrator: Orchestrator instance

    Returns:
        ModuleResult with enriched data
    """
    result = ModuleResult(
        module_name="censys_enrichment",
        started_at=datetime.utcnow(),
    )

    if not config.api_keys.censys_id or not config.api_keys.censys_secret:
        result.success = True
        result.error_message = "No Censys API credentials configured"
        result.completed_at = datetime.utcnow()
        return result

    client = CensysClient(config.api_keys.censys_id, config.api_keys.censys_secret)
    enriched_count = 0
    discovered_ips = set()

    # Track existing IPs to avoid duplicates
    for ip in session.ip_addresses:
        discovered_ips.add(ip.address)

    # =====================================================
    # Phase 1: Enrich each known IP with host data
    # =====================================================
    for ip in session.ip_addresses:
        try:
            host_data = await client.get_host(ip.address)

            if host_data:
                ip = parse_censys_host(host_data, ip)
                result.ip_addresses.append(ip)

                # Extract findings
                findings = extract_findings(host_data, ip)
                result.findings.extend(findings)

                enriched_count += 1

            # Rate limiting
            await asyncio.sleep(0.5)

        except Exception:
            continue

    # =====================================================
    # Phase 2: Search for certificates by domain
    # =====================================================
    for domain in session.target_domains:
        try:
            cert_data = await client.search_certificates(f"names:{domain}")
            if cert_data and cert_data.get("result", {}).get("hits"):
                for hit in cert_data["result"]["hits"][:20]:  # Limit results
                    cert = parse_censys_certificate({"result": hit})
                    if cert:
                        result.certificates.append(cert)

            await asyncio.sleep(0.5)

        except Exception:
            continue

    # =====================================================
    # Phase 3: Search for hosts by organization name
    # =====================================================
    if session.target_company:
        try:
            search_data = await client.search_hosts(
                f'autonomous_system.name:"{session.target_company}"',
                per_page=50,
            )

            if search_data and search_data.get("result", {}).get("hits"):
                for hit in search_data["result"]["hits"]:
                    ip_addr = hit.get("ip")
                    if ip_addr and ip_addr not in discovered_ips:
                        new_ip = IPAddress(
                            address=ip_addr,
                            version=6 if ":" in ip_addr else 4,
                            source="censys_search",
                        )
                        new_ip = parse_censys_host({"result": hit}, new_ip)
                        result.ip_addresses.append(new_ip)

                        # Extract findings from org search results too
                        findings = extract_findings({"result": hit}, new_ip)
                        result.findings.extend(findings)

                        discovered_ips.add(ip_addr)
                        enriched_count += 1

            await asyncio.sleep(1.0)

        except Exception:
            pass

    # =====================================================
    # Phase 4: Search for exposed services by org/domain
    # =====================================================
    # Priority services to search for (critical/high severity)
    priority_services = [
        "mongodb", "redis", "elasticsearch", "mysql", "postgresql",
        "docker_api", "kubernetes_api", "etcd", "jenkins", "smb",
        "docker_registry", "rabbitmq", "rdp", "vnc", "phpmyadmin",
    ]

    for service_type in priority_services:
        try:
            # Search by organization name
            if session.target_company:
                hits = await client.search_exposed_service(
                    service_type,
                    org_name=session.target_company,
                )

                for hit in hits[:20]:  # Limit per service
                    ip_addr = hit.get("ip")
                    if not ip_addr:
                        continue

                    # Get the port for this service
                    service_config = CENSYS_SERVICE_SEARCHES[service_type]
                    detected_port = None

                    for svc in hit.get("services", []):
                        if svc.get("port") in service_config["ports"]:
                            detected_port = svc.get("port")
                            break

                    if not detected_port:
                        detected_port = service_config["ports"][0]

                    # Create finding
                    finding = create_finding_from_service_search(
                        service_type,
                        ip_addr,
                        detected_port,
                        evidence=f"Discovered via Censys search for {session.target_company}",
                    )
                    result.findings.append(finding)

                    # Add IP if new
                    if ip_addr not in discovered_ips:
                        new_ip = IPAddress(
                            address=ip_addr,
                            version=6 if ":" in ip_addr else 4,
                            source=f"censys_service_{service_type}",
                        )
                        new_ip = parse_censys_host({"result": hit}, new_ip)
                        result.ip_addresses.append(new_ip)
                        discovered_ips.add(ip_addr)
                        enriched_count += 1

            # Search by domain
            for domain in session.target_domains[:3]:  # Limit domain searches
                hits = await client.search_exposed_service(
                    service_type,
                    domain=domain,
                )

                for hit in hits[:10]:  # Limit per domain
                    ip_addr = hit.get("ip")
                    if not ip_addr or ip_addr in discovered_ips:
                        continue

                    service_config = CENSYS_SERVICE_SEARCHES[service_type]
                    detected_port = None

                    for svc in hit.get("services", []):
                        if svc.get("port") in service_config["ports"]:
                            detected_port = svc.get("port")
                            break

                    if not detected_port:
                        detected_port = service_config["ports"][0]

                    finding = create_finding_from_service_search(
                        service_type,
                        ip_addr,
                        detected_port,
                        evidence=f"Discovered via Censys search for {domain}",
                    )
                    result.findings.append(finding)

                    # Add IP if new
                    new_ip = IPAddress(
                        address=ip_addr,
                        version=6 if ":" in ip_addr else 4,
                        source=f"censys_service_{service_type}",
                    )
                    new_ip = parse_censys_host({"result": hit}, new_ip)
                    result.ip_addresses.append(new_ip)
                    discovered_ips.add(ip_addr)
                    enriched_count += 1

                await asyncio.sleep(0.5)

            # Rate limiting between service searches
            await asyncio.sleep(1.0)

        except Exception:
            continue

    # Deduplicate findings by title
    seen_finding_titles = set()
    unique_findings = []
    for finding in result.findings:
        if finding.title not in seen_finding_titles:
            seen_finding_titles.add(finding.title)
            unique_findings.append(finding)
    result.findings = unique_findings

    result.items_discovered = enriched_count + len(result.certificates)
    result.success = True
    result.completed_at = datetime.utcnow()

    return result
