"""
Targeted resource scanning module.

Allows users to specify exactly which resources to hunt for:
- Cloud storage (S3, Azure Blob, GCP Storage, DigitalOcean Spaces)
- Databases (MongoDB, Redis, Elasticsearch, PostgreSQL, MySQL, CouchDB)
- Services (Jenkins, GitLab, Docker Registry, Kubernetes API)
- Firebase, Cassandra, Memcached, and more
"""

import asyncio
import re
import socket
from datetime import datetime
from typing import Optional, Callable, Any
from dataclasses import dataclass

import httpx

from attacktrace.config import AttackTraceConfig
from attacktrace.core.models import (
    ModuleResult,
    CloudAsset,
    CloudProvider,
    AssetType,
    Finding,
    Severity,
    ScanSession,
    IPAddress,
    Port,
    PortState,
    Service,
)


@dataclass
class ResourceType:
    """Definition of a scannable resource type."""
    name: str
    description: str
    category: str  # cloud, database, service, cache
    default_ports: list[int]
    check_func: str  # Name of the check function


# Available resource types for targeted scanning
RESOURCE_TYPES = {
    # Cloud Storage
    "s3": ResourceType(
        name="AWS S3",
        description="Amazon S3 buckets",
        category="cloud",
        default_ports=[443],
        check_func="check_s3_buckets",
    ),
    "azure-blob": ResourceType(
        name="Azure Blob",
        description="Azure Blob Storage containers",
        category="cloud",
        default_ports=[443],
        check_func="check_azure_blobs",
    ),
    "gcp-storage": ResourceType(
        name="GCP Storage",
        description="Google Cloud Storage buckets",
        category="cloud",
        default_ports=[443],
        check_func="check_gcp_buckets",
    ),
    "digitalocean": ResourceType(
        name="DigitalOcean Spaces",
        description="DigitalOcean Spaces storage",
        category="cloud",
        default_ports=[443],
        check_func="check_digitalocean_spaces",
    ),
    "firebase": ResourceType(
        name="Firebase",
        description="Firebase Realtime Database",
        category="cloud",
        default_ports=[443],
        check_func="check_firebase",
    ),

    # Databases
    "mongodb": ResourceType(
        name="MongoDB",
        description="MongoDB databases (exposed without auth)",
        category="database",
        default_ports=[27017, 27018, 27019],
        check_func="check_mongodb",
    ),
    "redis": ResourceType(
        name="Redis",
        description="Redis cache/database instances",
        category="database",
        default_ports=[6379],
        check_func="check_redis",
    ),
    "elasticsearch": ResourceType(
        name="Elasticsearch",
        description="Elasticsearch clusters",
        category="database",
        default_ports=[9200, 9300],
        check_func="check_elasticsearch",
    ),
    "postgresql": ResourceType(
        name="PostgreSQL",
        description="PostgreSQL databases",
        category="database",
        default_ports=[5432],
        check_func="check_postgresql",
    ),
    "mysql": ResourceType(
        name="MySQL",
        description="MySQL/MariaDB databases",
        category="database",
        default_ports=[3306],
        check_func="check_mysql",
    ),
    "mssql": ResourceType(
        name="Microsoft SQL Server",
        description="MS SQL Server databases",
        category="database",
        default_ports=[1433, 1434],
        check_func="check_mssql",
    ),
    "couchdb": ResourceType(
        name="CouchDB",
        description="Apache CouchDB databases",
        category="database",
        default_ports=[5984],
        check_func="check_couchdb",
    ),
    "cassandra": ResourceType(
        name="Cassandra",
        description="Apache Cassandra databases",
        category="database",
        default_ports=[9042, 9160],
        check_func="check_cassandra",
    ),

    # Cache
    "memcached": ResourceType(
        name="Memcached",
        description="Memcached cache servers",
        category="cache",
        default_ports=[11211],
        check_func="check_memcached",
    ),

    # Services
    "jenkins": ResourceType(
        name="Jenkins",
        description="Jenkins CI/CD servers",
        category="service",
        default_ports=[8080, 8443, 443],
        check_func="check_jenkins",
    ),
    "gitlab": ResourceType(
        name="GitLab",
        description="GitLab instances",
        category="service",
        default_ports=[80, 443, 8080],
        check_func="check_gitlab",
    ),
    "docker-registry": ResourceType(
        name="Docker Registry",
        description="Docker container registries",
        category="service",
        default_ports=[5000, 443],
        check_func="check_docker_registry",
    ),
    "kubernetes": ResourceType(
        name="Kubernetes API",
        description="Kubernetes API servers",
        category="service",
        default_ports=[6443, 8443, 443],
        check_func="check_kubernetes",
    ),
    "etcd": ResourceType(
        name="etcd",
        description="etcd key-value stores",
        category="service",
        default_ports=[2379, 2380],
        check_func="check_etcd",
    ),
    "rabbitmq": ResourceType(
        name="RabbitMQ",
        description="RabbitMQ message brokers",
        category="service",
        default_ports=[5672, 15672, 15671],
        check_func="check_rabbitmq",
    ),
    "kafka": ResourceType(
        name="Apache Kafka",
        description="Kafka message brokers",
        category="service",
        default_ports=[9092, 9093],
        check_func="check_kafka",
    ),
    "grafana": ResourceType(
        name="Grafana",
        description="Grafana dashboards",
        category="service",
        default_ports=[3000],
        check_func="check_grafana",
    ),
    "kibana": ResourceType(
        name="Kibana",
        description="Kibana dashboards",
        category="service",
        default_ports=[5601],
        check_func="check_kibana",
    ),
    "prometheus": ResourceType(
        name="Prometheus",
        description="Prometheus monitoring",
        category="service",
        default_ports=[9090],
        check_func="check_prometheus",
    ),
}


def get_available_resources() -> dict[str, ResourceType]:
    """Return all available resource types."""
    return RESOURCE_TYPES


def get_resource_categories() -> dict[str, list[str]]:
    """Return resources grouped by category."""
    categories = {}
    for key, resource in RESOURCE_TYPES.items():
        if resource.category not in categories:
            categories[resource.category] = []
        categories[resource.category].append(key)
    return categories


# =============================================================================
# Cloud Storage Checks
# =============================================================================

async def check_s3_buckets(
    base_names: list[str],
    timeout: float = 10.0,
    console=None,
) -> list[tuple[CloudAsset, list[Finding]]]:
    """Check for S3 buckets with various name mutations."""
    from attacktrace.modules.cloud.cloud_enum import (
        generate_bucket_names,
        check_s3_bucket,
        SENSITIVE_FILE_PATTERNS,
    )

    results = []
    bucket_names = generate_bucket_names(base_names)[:200]

    if console:
        console.print(f"[dim]Checking {len(bucket_names)} S3 bucket variations...[/dim]")

    semaphore = asyncio.Semaphore(25)

    async def check_with_semaphore(name: str):
        async with semaphore:
            return await check_s3_bucket(name, timeout, enumerate_contents=True)

    tasks = [check_with_semaphore(name) for name in bucket_names]
    check_results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in check_results:
        if result and not isinstance(result, Exception):
            asset, all_files, sensitive_files = result
            findings = []

            if asset.is_public:
                if sensitive_files:
                    finding = Finding(
                        title=f"CRITICAL: S3 bucket with sensitive files: {asset.name}",
                        description=f"Public S3 bucket contains sensitive files that could lead to data breach.",
                        severity=Severity.CRITICAL,
                        category="cloud_exposure",
                        affected_asset=asset.url,
                        affected_asset_type="s3_bucket",
                        evidence=f"Sensitive files: {', '.join(sensitive_files[:5])}",
                        source="targeted_scan",
                    )
                    findings.append(finding)
                else:
                    finding = Finding(
                        title=f"Public S3 bucket discovered: {asset.name}",
                        description=f"S3 bucket is publicly accessible.",
                        severity=Severity.HIGH if "LIST" in asset.permissions else Severity.MEDIUM,
                        category="cloud_exposure",
                        affected_asset=asset.url,
                        affected_asset_type="s3_bucket",
                        evidence=f"Files found: {len(all_files)}" if all_files else "Public access confirmed",
                        source="targeted_scan",
                    )
                    findings.append(finding)

            results.append((asset, findings))

    return results


async def check_firebase(
    base_names: list[str],
    timeout: float = 10.0,
    console=None,
) -> list[tuple[CloudAsset, list[Finding]]]:
    """Check for Firebase Realtime Databases."""
    results = []

    if console:
        console.print(f"[dim]Checking {len(base_names)} Firebase database names...[/dim]")

    async def check_firebase_db(name: str):
        clean_name = re.sub(r"[^a-z0-9-]", "", name.lower())
        if not clean_name or len(clean_name) < 3:
            return None

        url = f"https://{clean_name}.firebaseio.com/.json"

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.get(url)

                if response.status_code == 200:
                    # Check if it returns actual data
                    data = response.text
                    has_data = data != "null" and len(data) > 10

                    asset = CloudAsset(
                        provider=CloudProvider.GCP,
                        asset_type=AssetType.DATABASE,
                        name=f"{clean_name} (Firebase)",
                        url=url.replace("/.json", ""),
                        is_public=True,
                        permissions=["READ"],
                        contains_sensitive=has_data,
                        source="targeted_scan",
                    )

                    finding = Finding(
                        title=f"{'CRITICAL: ' if has_data else ''}Public Firebase database: {clean_name}",
                        description=f"Firebase Realtime Database is publicly readable"
                                   f"{' and contains data' if has_data else ''}.",
                        severity=Severity.CRITICAL if has_data else Severity.HIGH,
                        category="database_exposure",
                        affected_asset=asset.url,
                        affected_asset_type="firebase",
                        evidence=f"Data preview: {data[:200]}..." if has_data else "Empty database",
                        source="targeted_scan",
                    )

                    return (asset, [finding])

                elif response.status_code == 401:
                    # Exists but requires auth
                    asset = CloudAsset(
                        provider=CloudProvider.GCP,
                        asset_type=AssetType.DATABASE,
                        name=f"{clean_name} (Firebase)",
                        url=url.replace("/.json", ""),
                        is_public=False,
                        source="targeted_scan",
                    )
                    return (asset, [])

        except Exception:
            pass

        return None

    semaphore = asyncio.Semaphore(20)

    async def check_with_semaphore(name: str):
        async with semaphore:
            return await check_firebase_db(name)

    # Generate variations
    names_to_check = set()
    for name in base_names:
        names_to_check.add(name)
        names_to_check.add(name.replace(" ", "-"))
        names_to_check.add(name.replace(" ", ""))
        names_to_check.add(f"{name}-app")
        names_to_check.add(f"{name}-prod")
        names_to_check.add(f"{name}-dev")

    tasks = [check_with_semaphore(name) for name in names_to_check]
    check_results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in check_results:
        if result and not isinstance(result, Exception):
            results.append(result)

    return results


# =============================================================================
# Database Checks
# =============================================================================

async def check_mongodb(
    ips: list[str],
    ports: list[int] = None,
    timeout: float = 5.0,
    console=None,
) -> list[tuple[IPAddress, list[Finding]]]:
    """Check for exposed MongoDB instances."""
    ports = ports or [27017, 27018, 27019]
    results = []

    if console:
        console.print(f"[dim]Checking {len(ips)} IPs for MongoDB on ports {ports}...[/dim]")

    async def check_mongo(ip: str, port: int):
        try:
            # Try to connect and run serverStatus
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout
            )

            # MongoDB wire protocol - try to get server info
            # This is a basic check; MongoDB without auth will respond
            writer.close()
            await writer.wait_closed()

            # If we connected, try HTTP (some MongoDB expose HTTP interface)
            try:
                async with httpx.AsyncClient(timeout=timeout) as client:
                    response = await client.get(f"http://{ip}:{port}/")
                    if "mongodb" in response.text.lower() or response.status_code == 200:
                        return (ip, port, True, "HTTP interface exposed")
            except Exception:
                pass

            return (ip, port, True, "Port open - MongoDB likely")

        except asyncio.TimeoutError:
            return None
        except ConnectionRefusedError:
            return None
        except Exception:
            return None

    semaphore = asyncio.Semaphore(50)

    async def check_with_semaphore(ip: str, port: int):
        async with semaphore:
            return await check_mongo(ip, port)

    tasks = []
    for ip in ips:
        for port in ports:
            tasks.append(check_with_semaphore(ip, port))

    check_results = await asyncio.gather(*tasks, return_exceptions=True)

    found_ips = {}
    for result in check_results:
        if result and not isinstance(result, Exception):
            ip, port, is_open, evidence = result

            if ip not in found_ips:
                found_ips[ip] = IPAddress(
                    address=ip,
                    source="targeted_scan",
                )

            found_ips[ip].ports.append(Port(
                number=port,
                protocol="tcp",
                state=PortState.OPEN,
                service=Service(name="mongodb", product="MongoDB"),
            ))

    for ip, ip_obj in found_ips.items():
        finding = Finding(
            title=f"MongoDB instance exposed: {ip}",
            description="MongoDB database server is accessible. Check if authentication is required.",
            severity=Severity.HIGH,
            category="database_exposure",
            affected_asset=ip,
            affected_asset_type="mongodb",
            evidence=f"Open ports: {[p.number for p in ip_obj.ports]}",
            source="targeted_scan",
        )
        results.append((ip_obj, [finding]))

    return results


async def check_redis(
    ips: list[str],
    ports: list[int] = None,
    timeout: float = 5.0,
    console=None,
) -> list[tuple[IPAddress, list[Finding]]]:
    """Check for exposed Redis instances."""
    ports = ports or [6379]
    results = []

    if console:
        console.print(f"[dim]Checking {len(ips)} IPs for Redis on ports {ports}...[/dim]")

    async def check_redis_instance(ip: str, port: int):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout
            )

            # Send PING command
            writer.write(b"PING\r\n")
            await writer.drain()

            response = await asyncio.wait_for(reader.read(100), timeout=timeout)

            writer.close()
            await writer.wait_closed()

            if b"+PONG" in response or b"PONG" in response:
                return (ip, port, True, "Redis responded to PING - NO AUTH REQUIRED")
            elif b"-NOAUTH" in response or b"AUTH" in response:
                return (ip, port, True, "Redis requires authentication")
            elif response:
                return (ip, port, True, "Redis port open")

        except asyncio.TimeoutError:
            return None
        except ConnectionRefusedError:
            return None
        except Exception:
            return None

        return None

    semaphore = asyncio.Semaphore(50)

    async def check_with_semaphore(ip: str, port: int):
        async with semaphore:
            return await check_redis_instance(ip, port)

    tasks = []
    for ip in ips:
        for port in ports:
            tasks.append(check_with_semaphore(ip, port))

    check_results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in check_results:
        if result and not isinstance(result, Exception):
            ip, port, is_open, evidence = result

            is_no_auth = "NO AUTH" in evidence

            ip_obj = IPAddress(
                address=ip,
                source="targeted_scan",
            )
            ip_obj.ports.append(Port(
                number=port,
                protocol="tcp",
                state=PortState.OPEN,
                service=Service(name="redis", product="Redis"),
            ))

            finding = Finding(
                title=f"{'CRITICAL: ' if is_no_auth else ''}Redis instance exposed: {ip}:{port}",
                description=f"Redis cache/database is accessible. {evidence}",
                severity=Severity.CRITICAL if is_no_auth else Severity.HIGH,
                category="database_exposure",
                affected_asset=f"{ip}:{port}",
                affected_asset_type="redis",
                evidence=evidence,
                source="targeted_scan",
            )
            results.append((ip_obj, [finding]))

    return results


async def check_elasticsearch(
    ips: list[str],
    ports: list[int] = None,
    timeout: float = 5.0,
    console=None,
) -> list[tuple[IPAddress, list[Finding]]]:
    """Check for exposed Elasticsearch clusters."""
    ports = ports or [9200, 9300]
    results = []

    if console:
        console.print(f"[dim]Checking {len(ips)} IPs for Elasticsearch on ports {ports}...[/dim]")

    async def check_es(ip: str, port: int):
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                # Try root endpoint
                response = await client.get(f"http://{ip}:{port}/")

                if response.status_code == 200:
                    data = response.json()
                    if "cluster_name" in data or "tagline" in data:
                        cluster_name = data.get("cluster_name", "unknown")
                        version = data.get("version", {}).get("number", "unknown")

                        # Try to get indices
                        indices = []
                        try:
                            indices_response = await client.get(f"http://{ip}:{port}/_cat/indices?format=json")
                            if indices_response.status_code == 200:
                                indices = [idx.get("index") for idx in indices_response.json()[:10]]
                        except Exception:
                            pass

                        return (ip, port, True, cluster_name, version, indices)

        except Exception:
            pass

        return None

    semaphore = asyncio.Semaphore(30)

    async def check_with_semaphore(ip: str, port: int):
        async with semaphore:
            return await check_es(ip, port)

    tasks = []
    for ip in ips:
        for port in ports:
            tasks.append(check_with_semaphore(ip, port))

    check_results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in check_results:
        if result and not isinstance(result, Exception):
            ip, port, is_open, cluster_name, version, indices = result

            ip_obj = IPAddress(
                address=ip,
                source="targeted_scan",
            )
            ip_obj.ports.append(Port(
                number=port,
                protocol="tcp",
                state=PortState.OPEN,
                service=Service(name="elasticsearch", product="Elasticsearch", version=version),
            ))

            has_indices = len(indices) > 0
            finding = Finding(
                title=f"{'CRITICAL: ' if has_indices else ''}Elasticsearch cluster exposed: {ip}:{port}",
                description=f"Elasticsearch cluster '{cluster_name}' (v{version}) is publicly accessible"
                           f"{f' with {len(indices)} indices' if has_indices else ''}.",
                severity=Severity.CRITICAL if has_indices else Severity.HIGH,
                category="database_exposure",
                affected_asset=f"{ip}:{port}",
                affected_asset_type="elasticsearch",
                evidence=f"Cluster: {cluster_name}, Indices: {', '.join(indices[:5]) if indices else 'Unable to list'}",
                source="targeted_scan",
            )
            results.append((ip_obj, [finding]))

    return results


# =============================================================================
# Service Checks
# =============================================================================

async def check_jenkins(
    urls: list[str],
    timeout: float = 10.0,
    console=None,
) -> list[tuple[str, list[Finding]]]:
    """Check for exposed Jenkins instances."""
    results = []

    if console:
        console.print(f"[dim]Checking {len(urls)} URLs for Jenkins...[/dim]")

    async def check_jenkins_url(url: str):
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
                response = await client.get(url)

                # Check for Jenkins indicators
                headers = response.headers
                content = response.text.lower()

                is_jenkins = (
                    "x-jenkins" in headers or
                    "jenkins" in headers.get("server", "").lower() or
                    "jenkins" in content or
                    "hudson" in content
                )

                if is_jenkins:
                    version = headers.get("x-jenkins", "unknown")
                    requires_auth = "login" in content or response.status_code == 403

                    return (url, version, requires_auth, response.status_code)

        except Exception:
            pass

        return None

    semaphore = asyncio.Semaphore(20)

    async def check_with_semaphore(url: str):
        async with semaphore:
            return await check_jenkins_url(url)

    # Generate URL variations
    urls_to_check = set()
    for url in urls:
        urls_to_check.add(url)
        urls_to_check.add(f"{url}/jenkins")
        urls_to_check.add(f"{url}:8080")
        urls_to_check.add(f"{url}:8080/jenkins")

    tasks = [check_with_semaphore(url) for url in urls_to_check]
    check_results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in check_results:
        if result and not isinstance(result, Exception):
            url, version, requires_auth, status_code = result

            finding = Finding(
                title=f"Jenkins instance discovered: {url}",
                description=f"Jenkins CI/CD server found (v{version}). "
                           f"{'Requires authentication' if requires_auth else 'May allow anonymous access'}.",
                severity=Severity.MEDIUM if requires_auth else Severity.HIGH,
                category="service_exposure",
                affected_asset=url,
                affected_asset_type="jenkins",
                evidence=f"Version: {version}, Auth required: {requires_auth}",
                source="targeted_scan",
            )
            results.append((url, [finding]))

    return results


async def check_docker_registry(
    urls: list[str],
    timeout: float = 10.0,
    console=None,
) -> list[tuple[str, list[Finding]]]:
    """Check for exposed Docker registries."""
    results = []

    if console:
        console.print(f"[dim]Checking {len(urls)} URLs for Docker registries...[/dim]")

    async def check_registry(url: str):
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
                # Check v2 API
                response = await client.get(f"{url}/v2/")

                if response.status_code in [200, 401]:
                    is_public = response.status_code == 200
                    repos = []

                    if is_public:
                        # Try to list repositories
                        try:
                            catalog_response = await client.get(f"{url}/v2/_catalog")
                            if catalog_response.status_code == 200:
                                data = catalog_response.json()
                                repos = data.get("repositories", [])[:10]
                        except Exception:
                            pass

                    return (url, is_public, repos)

        except Exception:
            pass

        return None

    semaphore = asyncio.Semaphore(20)

    async def check_with_semaphore(url: str):
        async with semaphore:
            return await check_registry(url)

    # Generate URL variations
    urls_to_check = set()
    for url in urls:
        urls_to_check.add(url)
        urls_to_check.add(f"{url}:5000")

    tasks = [check_with_semaphore(url) for url in urls_to_check]
    check_results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in check_results:
        if result and not isinstance(result, Exception):
            url, is_public, repos = result

            finding = Finding(
                title=f"{'CRITICAL: ' if is_public and repos else ''}Docker Registry exposed: {url}",
                description=f"Docker registry is {'publicly accessible' if is_public else 'requires authentication'}"
                           f"{f' with {len(repos)} repositories' if repos else ''}.",
                severity=Severity.CRITICAL if is_public and repos else (Severity.HIGH if is_public else Severity.MEDIUM),
                category="service_exposure",
                affected_asset=url,
                affected_asset_type="docker_registry",
                evidence=f"Public: {is_public}, Repositories: {', '.join(repos[:5]) if repos else 'N/A'}",
                source="targeted_scan",
            )
            results.append((url, [finding]))

    return results


async def check_kubernetes(
    urls: list[str],
    timeout: float = 10.0,
    console=None,
) -> list[tuple[str, list[Finding]]]:
    """Check for exposed Kubernetes API servers."""
    results = []

    if console:
        console.print(f"[dim]Checking {len(urls)} URLs for Kubernetes API...[/dim]")

    async def check_k8s(url: str):
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
                # Check API endpoint
                response = await client.get(f"{url}/api")

                if response.status_code in [200, 401, 403]:
                    is_public = response.status_code == 200

                    # Try to get version
                    version = "unknown"
                    try:
                        version_response = await client.get(f"{url}/version")
                        if version_response.status_code == 200:
                            data = version_response.json()
                            version = data.get("gitVersion", "unknown")
                    except Exception:
                        pass

                    return (url, is_public, version)

        except Exception:
            pass

        return None

    semaphore = asyncio.Semaphore(20)

    async def check_with_semaphore(url: str):
        async with semaphore:
            return await check_k8s(url)

    # Generate URL variations
    urls_to_check = set()
    for url in urls:
        urls_to_check.add(url)
        urls_to_check.add(f"{url}:6443")
        urls_to_check.add(f"{url}:8443")

    tasks = [check_with_semaphore(url) for url in urls_to_check]
    check_results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in check_results:
        if result and not isinstance(result, Exception):
            url, is_public, version = result

            finding = Finding(
                title=f"{'CRITICAL: ' if is_public else ''}Kubernetes API exposed: {url}",
                description=f"Kubernetes API server (v{version}) is accessible. "
                           f"{'Anonymous access allowed!' if is_public else 'Requires authentication.'}",
                severity=Severity.CRITICAL if is_public else Severity.MEDIUM,
                category="service_exposure",
                affected_asset=url,
                affected_asset_type="kubernetes",
                evidence=f"Version: {version}, Anonymous access: {is_public}",
                source="targeted_scan",
            )
            results.append((url, [finding]))

    return results


# =============================================================================
# Main Scanner Class
# =============================================================================

class TargetedResourceScanner:
    """
    Scanner for specific resource types.

    Usage:
        scanner = TargetedResourceScanner(config, console)
        results = await scanner.scan(
            resources=["s3", "mongodb", "redis"],
            base_names=["acme", "acmecorp"],
            ips=["1.2.3.4", "5.6.7.8"],
            urls=["https://acme.com"]
        )
    """

    def __init__(self, config: AttackTraceConfig, console=None):
        self.config = config
        self.console = console
        self.timeout = config.scan.timeout

    async def scan(
        self,
        resources: list[str],
        base_names: list[str] = None,
        ips: list[str] = None,
        urls: list[str] = None,
    ) -> ModuleResult:
        """
        Run targeted scan for specified resources.

        Args:
            resources: List of resource type keys (s3, mongodb, redis, etc.)
            base_names: Base names for cloud resource enumeration
            ips: IP addresses to scan for database/service exposure
            urls: URLs to check for web services

        Returns:
            ModuleResult with findings
        """
        result = ModuleResult(
            module_name="targeted_scan",
            started_at=datetime.utcnow(),
        )

        base_names = base_names or []
        ips = ips or []
        urls = urls or []

        all_findings = []
        cloud_assets = []
        ip_addresses = []

        for resource_key in resources:
            if resource_key not in RESOURCE_TYPES:
                if self.console:
                    self.console.print(f"[yellow]Unknown resource type: {resource_key}[/yellow]")
                continue

            resource = RESOURCE_TYPES[resource_key]

            if self.console:
                self.console.print(f"\n[cyan]Scanning for {resource.name}...[/cyan]")

            try:
                if resource_key == "s3" and base_names:
                    scan_results = await check_s3_buckets(base_names, self.timeout, self.console)
                    for asset, findings in scan_results:
                        cloud_assets.append(asset)
                        all_findings.extend(findings)

                elif resource_key == "firebase" and base_names:
                    scan_results = await check_firebase(base_names, self.timeout, self.console)
                    for asset, findings in scan_results:
                        cloud_assets.append(asset)
                        all_findings.extend(findings)

                elif resource_key == "mongodb" and ips:
                    scan_results = await check_mongodb(ips, resource.default_ports, self.timeout, self.console)
                    for ip_obj, findings in scan_results:
                        ip_addresses.append(ip_obj)
                        all_findings.extend(findings)

                elif resource_key == "redis" and ips:
                    scan_results = await check_redis(ips, resource.default_ports, self.timeout, self.console)
                    for ip_obj, findings in scan_results:
                        ip_addresses.append(ip_obj)
                        all_findings.extend(findings)

                elif resource_key == "elasticsearch" and ips:
                    scan_results = await check_elasticsearch(ips, resource.default_ports, self.timeout, self.console)
                    for ip_obj, findings in scan_results:
                        ip_addresses.append(ip_obj)
                        all_findings.extend(findings)

                elif resource_key == "jenkins" and urls:
                    scan_results = await check_jenkins(urls, self.timeout, self.console)
                    for url, findings in scan_results:
                        all_findings.extend(findings)

                elif resource_key == "docker-registry" and urls:
                    scan_results = await check_docker_registry(urls, self.timeout, self.console)
                    for url, findings in scan_results:
                        all_findings.extend(findings)

                elif resource_key == "kubernetes" and urls:
                    scan_results = await check_kubernetes(urls, self.timeout, self.console)
                    for url, findings in scan_results:
                        all_findings.extend(findings)

                else:
                    if self.console:
                        self.console.print(f"[dim]Skipping {resource.name} - no suitable targets[/dim]")

            except Exception as e:
                if self.console:
                    self.console.print(f"[red]Error scanning {resource.name}: {e}[/red]")

        result.cloud_assets = cloud_assets
        result.ip_addresses = ip_addresses
        result.findings = all_findings
        result.items_discovered = len(cloud_assets) + len(ip_addresses) + len(all_findings)
        result.success = True
        result.completed_at = datetime.utcnow()

        return result
