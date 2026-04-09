"""
Pydantic data models for AttackTrace.

These models represent all discoverable assets and findings during
attack surface discovery.
"""

from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
import uuid


class Severity(str, Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanStatus(str, Enum):
    """Scan session status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class PortState(str, Enum):
    """Port states."""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNKNOWN = "unknown"


class CloudProvider(str, Enum):
    """Cloud service providers."""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    DIGITALOCEAN = "digitalocean"
    OTHER = "other"


class AssetType(str, Enum):
    """Cloud asset types."""
    BUCKET = "bucket"
    BLOB = "blob"
    VM = "vm"
    FUNCTION = "function"
    DATABASE = "database"
    CONTAINER = "container"
    OTHER = "other"


def generate_id() -> str:
    """Generate a unique ID."""
    return str(uuid.uuid4())[:8]


class BaseAsset(BaseModel):
    """Base class for all discoverable assets."""
    id: str = Field(default_factory=generate_id)
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    source: str = Field(default="manual", description="Discovery source/module")
    tags: list[str] = Field(default_factory=list)
    notes: str = ""


class GeoLocation(BaseModel):
    """Geographic location data."""
    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    latitude: Optional[float] = None
    longitude: Optional[float] = None


class Organization(BaseAsset):
    """Represents the target organization."""
    name: str
    aliases: list[str] = Field(default_factory=list)
    description: str = ""
    industry: str = ""
    website: str = ""


class DNSRecord(BaseModel):
    """DNS record data."""
    record_type: str  # A, AAAA, MX, TXT, CNAME, NS, SOA, etc.
    value: str
    ttl: int = 0
    priority: Optional[int] = None  # For MX records


class Certificate(BaseModel):
    """SSL/TLS certificate data."""
    id: str = Field(default_factory=generate_id)
    serial_number: str = ""
    subject: str = ""
    issuer: str = ""
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    san: list[str] = Field(default_factory=list, description="Subject Alternative Names")
    fingerprint_sha256: str = ""
    is_expired: bool = False
    is_self_signed: bool = False


class Subdomain(BaseAsset):
    """Subdomain discovered during enumeration."""
    fqdn: str
    parent_domain: str
    resolved_ips: list[str] = Field(default_factory=list)
    cname_chain: list[str] = Field(default_factory=list)
    is_wildcard: bool = False
    is_alive: bool = False
    http_status: Optional[int] = None


class Domain(BaseAsset):
    """Root domain with associated data."""
    fqdn: str
    registrar: str = ""
    registrant_name: str = ""
    registrant_org: str = ""
    registrant_email: str = ""
    creation_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    updated_date: Optional[datetime] = None
    name_servers: list[str] = Field(default_factory=list)
    dns_records: list[DNSRecord] = Field(default_factory=list)
    subdomains: list[str] = Field(default_factory=list, description="List of subdomain FQDNs")


class Service(BaseModel):
    """Service running on a port."""
    name: str = "unknown"
    product: str = ""
    version: str = ""
    extra_info: str = ""
    cpe: list[str] = Field(default_factory=list)
    banner: str = ""


class Port(BaseModel):
    """Port with service information."""
    number: int
    protocol: str = "tcp"
    state: PortState = PortState.UNKNOWN
    service: Service = Field(default_factory=Service)
    scripts_output: dict[str, str] = Field(default_factory=dict)


class IPAddress(BaseAsset):
    """IP address with associated data."""
    address: str
    version: int = 4  # IPv4 or IPv6
    asn: Optional[int] = None
    asn_org: str = ""
    asn_country: str = ""
    reverse_dns: list[str] = Field(default_factory=list)
    geolocation: GeoLocation = Field(default_factory=GeoLocation)
    cloud_provider: Optional[CloudProvider] = None
    cloud_region: str = ""
    ports: list[Port] = Field(default_factory=list)
    hostnames: list[str] = Field(default_factory=list)
    os_fingerprint: str = ""


class Technology(BaseModel):
    """Detected technology/software."""
    name: str
    version: str = ""
    category: str = ""  # web-server, framework, cms, etc.
    confidence: int = 100  # 0-100


class WebApplication(BaseAsset):
    """Web application discovered."""
    url: str
    scheme: str = "https"
    host: str = ""
    port: int = 443
    path: str = "/"
    title: str = ""
    status_code: int = 0
    content_length: int = 0
    content_type: str = ""
    redirect_url: str = ""
    final_url: str = ""
    technologies: list[Technology] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)
    certificate: Optional[Certificate] = None
    screenshot_path: str = ""
    screenshot_base64: str = ""  # Base64 encoded screenshot for HTML embedding
    favicon_hash: str = ""
    response_time_ms: int = 0
    is_alive: bool = False


class CloudAsset(BaseAsset):
    """Cloud asset (bucket, blob, etc.)."""
    provider: CloudProvider
    asset_type: AssetType
    name: str
    url: str = ""
    region: str = ""
    is_public: bool = False
    permissions: list[str] = Field(default_factory=list)
    contains_sensitive: bool = False


class Finding(BaseAsset):
    """Security finding or issue discovered."""
    title: str
    description: str
    severity: Severity
    category: str = ""  # misconfiguration, exposure, vulnerability, etc.
    affected_asset: str = ""  # Reference to the affected asset
    affected_asset_type: str = ""  # domain, ip, webapp, etc.
    evidence: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    cve: list[str] = Field(default_factory=list)
    cvss_score: Optional[float] = None
    false_positive: bool = False


class ModuleResult(BaseModel):
    """Result from a discovery module execution."""
    module_name: str
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    success: bool = False
    error_message: str = ""
    items_discovered: int = 0
    domains: list[Domain] = Field(default_factory=list)
    subdomains: list[Subdomain] = Field(default_factory=list)
    ip_addresses: list[IPAddress] = Field(default_factory=list)
    web_applications: list[WebApplication] = Field(default_factory=list)
    cloud_assets: list[CloudAsset] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    certificates: list[Certificate] = Field(default_factory=list)


class ScanSession(BaseModel):
    """Represents a complete scan session."""
    id: str = Field(default_factory=generate_id)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    status: ScanStatus = ScanStatus.PENDING

    # Target information
    target_company: str = ""
    target_domains: list[str] = Field(default_factory=list)
    target_ip_ranges: list[str] = Field(default_factory=list)

    # Configuration
    modules_enabled: list[str] = Field(default_factory=list)
    intensity: str = "normal"
    passive_only: bool = False

    # Results
    organization: Optional[Organization] = None
    domains: list[Domain] = Field(default_factory=list)
    subdomains: list[Subdomain] = Field(default_factory=list)
    ip_addresses: list[IPAddress] = Field(default_factory=list)
    web_applications: list[WebApplication] = Field(default_factory=list)
    cloud_assets: list[CloudAsset] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    certificates: list[Certificate] = Field(default_factory=list)

    # Module execution history
    module_results: list[ModuleResult] = Field(default_factory=list)

    # OSINT data (populated by osint modules)
    github_data: dict = Field(default_factory=dict, description="GitHub recon results")
    employee_data: dict = Field(default_factory=dict, description="Employee discovery results")
    cloud_data: dict = Field(default_factory=dict, description="Cloud enumeration details (file listings)")

    # Statistics
    total_domains: int = 0
    total_subdomains: int = 0
    total_ips: int = 0
    total_ports: int = 0
    total_web_apps: int = 0
    total_cloud_assets: int = 0
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0

    def update_statistics(self) -> None:
        """Update all statistics based on current data."""
        self.total_domains = len(self.domains)
        self.total_subdomains = len(self.subdomains)
        self.total_ips = len(self.ip_addresses)
        self.total_ports = sum(len(ip.ports) for ip in self.ip_addresses)
        self.total_web_apps = len(self.web_applications)
        self.total_cloud_assets = len(self.cloud_assets)
        self.total_findings = len(self.findings)

        self.critical_findings = sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
        self.high_findings = sum(1 for f in self.findings if f.severity == Severity.HIGH)
        self.medium_findings = sum(1 for f in self.findings if f.severity == Severity.MEDIUM)
        self.low_findings = sum(1 for f in self.findings if f.severity == Severity.LOW)

        self.updated_at = datetime.utcnow()
