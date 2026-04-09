"""
Cloud asset enumeration module.

Discovers cloud assets such as:
- AWS S3 buckets (with content enumeration)
- Azure Blob storage
- GCP Storage buckets
- Firebase databases
- DigitalOcean Spaces
- Cloud endpoints from web pages and DNS
"""

import asyncio
import re
from datetime import datetime
from typing import Optional
from xml.etree import ElementTree

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
)


# Extended bucket name patterns/mutations
BUCKET_MUTATIONS = [
    # Base patterns
    "{name}",
    "{name}2",
    "{name}1",
    # Backup patterns
    "{name}-backup",
    "{name}-backups",
    "{name}-bak",
    "{name}-db-backup",
    "{name}-database-backup",
    "{name}-sql-backup",
    "{name}-mysql-backup",
    "{name}-pg-backup",
    "{name}-mongo-backup",
    # Data patterns
    "{name}-data",
    "{name}-files",
    "{name}-storage",
    "{name}-store",
    # Asset patterns
    "{name}-assets",
    "{name}-static",
    "{name}-media",
    "{name}-uploads",
    "{name}-images",
    "{name}-img",
    "{name}-videos",
    "{name}-content",
    # Document patterns
    "{name}-docs",
    "{name}-documents",
    "{name}-reports",
    "{name}-invoices",
    "{name}-contracts",
    # Access patterns
    "{name}-public",
    "{name}-private",
    "{name}-internal",
    "{name}-external",
    "{name}-shared",
    # Environment patterns
    "{name}-dev",
    "{name}-development",
    "{name}-staging",
    "{name}-stage",
    "{name}-stg",
    "{name}-uat",
    "{name}-qa",
    "{name}-prod",
    "{name}-production",
    "{name}-prd",
    "{name}-test",
    "{name}-testing",
    "{name}-sandbox",
    "{name}-demo",
    # Technical patterns
    "{name}-logs",
    "{name}-log",
    "{name}-archive",
    "{name}-archives",
    "{name}-web",
    "{name}-www",
    "{name}-cdn",
    "{name}-s3",
    "{name}-bucket",
    "{name}-app",
    "{name}-api",
    "{name}-mobile",
    "{name}-ios",
    "{name}-android",
    # Reverse patterns
    "backup-{name}",
    "backups-{name}",
    "data-{name}",
    "files-{name}",
    "assets-{name}",
    "static-{name}",
    "media-{name}",
    "logs-{name}",
    # No separator patterns
    "{name}backup",
    "{name}backups",
    "{name}data",
    "{name}files",
    "{name}assets",
    "{name}static",
    "{name}media",
    "{name}logs",
    "{name}dev",
    "{name}prod",
    "{name}staging",
    # AWS-specific patterns
    "{name}-aws",
    "{name}-s3-bucket",
    "aws-{name}",
    "s3-{name}",
    # Config/secrets patterns (high value targets)
    "{name}-config",
    "{name}-configs",
    "{name}-secrets",
    "{name}-credentials",
    "{name}-keys",
    "{name}-env",
    "{name}-terraform",
    "{name}-tf-state",
    "{name}-cloudformation",
]

# Sensitive file patterns to look for in bucket contents
SENSITIVE_FILE_PATTERNS = [
    r"\.env",
    r"\.git",
    r"\.ssh",
    r"credentials",
    r"password",
    r"secret",
    r"private[_-]?key",
    r"\.pem$",
    r"\.key$",
    r"\.p12$",
    r"\.pfx$",
    r"id_rsa",
    r"\.sql$",
    r"\.sql\.gz$",
    r"\.sql\.bz2$",
    r"backup.*\.sql",
    r"dump.*\.sql",
    r"database.*\.sql",
    r"\.bak$",
    r"\.backup$",
    r"\.old$",
    r"\.orig$",
    r"config\.(json|yaml|yml|xml|ini)",
    r"settings\.(json|yaml|yml|py)",
    r"application\.(properties|yml|yaml)",
    r"web\.config",
    r"wp-config\.php",
    r"\.htpasswd",
    r"\.htaccess",
    r"terraform\.tfstate",
    r"\.tfvars$",
    r"docker-compose",
    r"Dockerfile",
    r"\.npmrc",
    r"\.pypirc",
    r"\.netrc",
    r"\.aws/credentials",
    r"\.kube/config",
]

# AWS S3 regions to check
AWS_REGIONS = [
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "eu-west-1",
    "eu-west-2",
    "eu-central-1",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast-1",
]


def generate_bucket_names(base_names: list[str]) -> list[str]:
    """Generate bucket name mutations from base names."""
    buckets = set()

    for name in base_names:
        # Clean the name
        clean_name = re.sub(r"[^a-z0-9-]", "", name.lower())
        clean_name = re.sub(r"-+", "-", clean_name).strip("-")

        if not clean_name or len(clean_name) < 3:
            continue

        for pattern in BUCKET_MUTATIONS:
            bucket_name = pattern.format(name=clean_name)
            if 3 <= len(bucket_name) <= 63:
                buckets.add(bucket_name)

        # Also try with dots replaced by dashes
        if "." in name:
            dotless = name.replace(".", "-").lower()
            dotless = re.sub(r"[^a-z0-9-]", "", dotless)
            for pattern in BUCKET_MUTATIONS[:5]:  # Just main patterns
                bucket_name = pattern.format(name=dotless)
                if 3 <= len(bucket_name) <= 63:
                    buckets.add(bucket_name)

    return list(buckets)


async def enumerate_s3_contents(
    bucket_name: str,
    url: str,
    client: httpx.AsyncClient,
    max_keys: int = 1000,
) -> tuple[list[str], list[str]]:
    """
    Enumerate S3 bucket contents and identify sensitive files.

    Returns:
        Tuple of (all_files, sensitive_files)
    """
    all_files = []
    sensitive_files = []

    try:
        response = await client.get(url, params={"max-keys": max_keys})
        if response.status_code == 200 and "<Contents>" in response.text:
            # Parse XML response
            try:
                root = ElementTree.fromstring(response.text)
                # Handle namespace
                ns = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}

                # Try with namespace first
                contents = root.findall(".//s3:Contents", ns)
                if not contents:
                    # Try without namespace
                    contents = root.findall(".//Contents")

                for content in contents:
                    key_elem = content.find("s3:Key", ns)
                    if key_elem is None:
                        key_elem = content.find("Key")
                    if key_elem is not None and key_elem.text:
                        file_key = key_elem.text
                        all_files.append(file_key)

                        # Check if it matches sensitive patterns
                        for pattern in SENSITIVE_FILE_PATTERNS:
                            if re.search(pattern, file_key, re.IGNORECASE):
                                sensitive_files.append(file_key)
                                break
            except ElementTree.ParseError:
                pass
    except Exception:
        pass

    return all_files, sensitive_files


async def check_s3_bucket(
    bucket_name: str,
    timeout: float = 10.0,
    enumerate_contents: bool = True,
) -> Optional[tuple[CloudAsset, list[str], list[str]]]:
    """
    Check if an S3 bucket exists and is accessible.

    Returns:
        Tuple of (CloudAsset, all_files, sensitive_files) if bucket exists, None otherwise
    """
    # Try different URL formats and regions
    urls_to_try = [
        f"https://{bucket_name}.s3.amazonaws.com",
        f"https://s3.amazonaws.com/{bucket_name}",
    ]

    # Add region-specific URLs for better coverage
    for region in AWS_REGIONS[:3]:  # Try top 3 regions
        urls_to_try.append(f"https://{bucket_name}.s3.{region}.amazonaws.com")

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        for url in urls_to_try:
            try:
                response = await client.head(url)

                # Bucket exists
                if response.status_code in [200, 403, 301, 307]:
                    is_public = response.status_code == 200
                    permissions = []
                    all_files = []
                    sensitive_files = []

                    # Try to list contents if public
                    if is_public and enumerate_contents:
                        try:
                            all_files, sensitive_files = await enumerate_s3_contents(
                                bucket_name, url, client
                            )
                            if all_files:
                                permissions.append("LIST")
                        except Exception:
                            pass

                    # Detect region from redirect
                    region = ""
                    if response.status_code in [301, 307]:
                        location = response.headers.get("x-amz-bucket-region", "")
                        if location:
                            region = location

                    asset = CloudAsset(
                        provider=CloudProvider.AWS,
                        asset_type=AssetType.BUCKET,
                        name=bucket_name,
                        url=url,
                        region=region,
                        is_public=is_public,
                        permissions=permissions,
                        source="cloud_enum",
                    )
                    return (asset, all_files, sensitive_files)

            except httpx.ConnectTimeout:
                continue
            except httpx.ReadTimeout:
                continue
            except Exception:
                continue

    return None


async def check_firebase_database(
    project_name: str,
    timeout: float = 10.0,
) -> Optional[CloudAsset]:
    """
    Check if a Firebase Realtime Database is publicly accessible.
    """
    url = f"https://{project_name}.firebaseio.com/.json"

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url)

            if response.status_code == 200:
                # Database is publicly readable
                asset = CloudAsset(
                    provider=CloudProvider.GCP,
                    asset_type=AssetType.DATABASE,
                    name=f"{project_name} (Firebase)",
                    url=url.replace("/.json", ""),
                    is_public=True,
                    permissions=["READ"],
                    source="cloud_enum",
                )
                return asset
            elif response.status_code == 401:
                # Database exists but requires auth
                asset = CloudAsset(
                    provider=CloudProvider.GCP,
                    asset_type=AssetType.DATABASE,
                    name=f"{project_name} (Firebase)",
                    url=url.replace("/.json", ""),
                    is_public=False,
                    source="cloud_enum",
                )
                return asset
    except Exception:
        pass

    return None


async def check_digitalocean_space(
    space_name: str,
    region: str = "nyc3",
    timeout: float = 10.0,
) -> Optional[CloudAsset]:
    """
    Check if a DigitalOcean Space exists and is accessible.
    """
    url = f"https://{space_name}.{region}.digitaloceanspaces.com"

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.head(url)

            if response.status_code in [200, 403]:
                is_public = response.status_code == 200
                permissions = []

                if is_public:
                    list_response = await client.get(url)
                    if "<Contents>" in list_response.text:
                        permissions.append("LIST")

                asset = CloudAsset(
                    provider=CloudProvider.DIGITALOCEAN,
                    asset_type=AssetType.BUCKET,
                    name=space_name,
                    url=url,
                    region=region,
                    is_public=is_public,
                    permissions=permissions,
                    source="cloud_enum",
                )
                return asset
    except Exception:
        pass

    return None


async def extract_cloud_urls_from_webapps(
    session: ScanSession,
    timeout: float = 10.0,
) -> dict[str, set[str]]:
    """
    Extract cloud storage URLs from discovered web applications.
    Looks for S3, Azure, GCP URLs in page content.
    """
    cloud_urls = {
        "s3": set(),
        "azure": set(),
        "gcp": set(),
        "firebase": set(),
        "digitalocean": set(),
    }

    # Patterns to find cloud URLs
    patterns = {
        "s3": [
            r'https?://([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])\.s3[.-]([a-z0-9-]+)?\.?amazonaws\.com',
            r'https?://s3[.-]([a-z0-9-]+)?\.?amazonaws\.com/([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])',
        ],
        "azure": [
            r'https?://([a-z0-9]{3,24})\.blob\.core\.windows\.net',
        ],
        "gcp": [
            r'https?://storage\.googleapis\.com/([a-z0-9][a-z0-9\-_.]{1,61}[a-z0-9])',
            r'https?://([a-z0-9][a-z0-9\-_.]{1,61}[a-z0-9])\.storage\.googleapis\.com',
        ],
        "firebase": [
            r'https?://([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])\.firebaseio\.com',
            r'https?://([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])\.firebasestorage\.googleapis\.com',
        ],
        "digitalocean": [
            r'https?://([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])\.([a-z0-9]+)\.digitaloceanspaces\.com',
        ],
    }

    async def fetch_and_extract(url: str):
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                response = await client.get(url)
                if response.status_code == 200:
                    content = response.text

                    for provider, provider_patterns in patterns.items():
                        for pattern in provider_patterns:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            for match in matches:
                                if isinstance(match, tuple):
                                    cloud_urls[provider].add(match[0])
                                else:
                                    cloud_urls[provider].add(match)
        except Exception:
            pass

    # Extract from web applications
    tasks = []
    for webapp in session.web_applications[:30]:  # Limit to avoid too many requests
        if webapp.is_alive:
            url = webapp.final_url or webapp.url
            tasks.append(fetch_and_extract(url))

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

    return cloud_urls


async def check_azure_blob(
    container_name: str,
    account_name: str,
    timeout: float = 10.0,
) -> Optional[CloudAsset]:
    """
    Check if an Azure Blob container exists and is accessible.

    Returns:
        CloudAsset if container exists, None otherwise
    """
    url = f"https://{account_name}.blob.core.windows.net/{container_name}?restype=container&comp=list"

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url)

            if response.status_code == 200:
                asset = CloudAsset(
                    provider=CloudProvider.AZURE,
                    asset_type=AssetType.BLOB,
                    name=f"{account_name}/{container_name}",
                    url=f"https://{account_name}.blob.core.windows.net/{container_name}",
                    is_public=True,
                    permissions=["LIST"],
                    source="cloud_enum",
                )
                return asset
            elif response.status_code == 404:
                # Container doesn't exist
                return None
            elif response.status_code in [403, 409]:
                # Container exists but not public
                asset = CloudAsset(
                    provider=CloudProvider.AZURE,
                    asset_type=AssetType.BLOB,
                    name=f"{account_name}/{container_name}",
                    url=f"https://{account_name}.blob.core.windows.net/{container_name}",
                    is_public=False,
                    source="cloud_enum",
                )
                return asset

    except Exception:
        pass

    return None


async def check_gcp_bucket(
    bucket_name: str,
    timeout: float = 10.0,
) -> Optional[CloudAsset]:
    """
    Check if a GCP Storage bucket exists and is accessible.

    Returns:
        CloudAsset if bucket exists, None otherwise
    """
    url = f"https://storage.googleapis.com/{bucket_name}"

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url)

            if response.status_code == 200:
                is_public = True
                permissions = []

                # Check if we can list
                if "<Contents>" in response.text or "ListBucketResult" in response.text:
                    permissions.append("LIST")

                asset = CloudAsset(
                    provider=CloudProvider.GCP,
                    asset_type=AssetType.BUCKET,
                    name=bucket_name,
                    url=url,
                    is_public=is_public,
                    permissions=permissions,
                    source="cloud_enum",
                )
                return asset
            elif response.status_code == 403:
                # Bucket exists but not public
                asset = CloudAsset(
                    provider=CloudProvider.GCP,
                    asset_type=AssetType.BUCKET,
                    name=bucket_name,
                    url=url,
                    is_public=False,
                    source="cloud_enum",
                )
                return asset

    except Exception:
        pass

    return None


def create_findings_for_public_assets(
    assets: list[CloudAsset],
    sensitive_files_map: dict[str, list[str]] = None,
) -> list[Finding]:
    """Create findings for publicly accessible cloud assets."""
    findings = []
    sensitive_files_map = sensitive_files_map or {}

    for asset in assets:
        if asset.is_public:
            # Check if sensitive files were found
            sensitive_files = sensitive_files_map.get(asset.name, [])

            if sensitive_files:
                # Critical finding - sensitive files exposed
                finding = Finding(
                    title=f"CRITICAL: Sensitive files exposed in public {asset.provider.value.upper()} bucket: {asset.name}",
                    description=f"A publicly accessible {asset.asset_type.value} contains potentially sensitive files "
                               f"including credentials, backups, or configuration files. This could lead to data breach or system compromise.",
                    severity=Severity.CRITICAL,
                    category="cloud_exposure",
                    affected_asset=asset.url,
                    affected_asset_type="cloud_asset",
                    evidence=f"Sensitive files found: {', '.join(sensitive_files[:10])}{'...' if len(sensitive_files) > 10 else ''}",
                    source="cloud_enum",
                    remediation="Immediately review bucket permissions and remove public access. "
                               "Rotate any exposed credentials. Review all files for sensitive data.",
                )
                findings.append(finding)
            elif "LIST" in asset.permissions:
                # High - listable bucket
                finding = Finding(
                    title=f"Public {asset.provider.value.upper()} {asset.asset_type.value} with LIST permission: {asset.name}",
                    description=f"A publicly accessible {asset.asset_type.value} allows listing contents. "
                               f"Attackers can enumerate all files to find sensitive data.",
                    severity=Severity.HIGH,
                    category="cloud_exposure",
                    affected_asset=asset.url,
                    affected_asset_type="cloud_asset",
                    evidence=f"Permissions: {', '.join(asset.permissions)}",
                    source="cloud_enum",
                    remediation="Review bucket permissions and restrict public access.",
                )
                findings.append(finding)
            else:
                # Medium - public but not listable
                finding = Finding(
                    title=f"Public {asset.provider.value.upper()} {asset.asset_type.value} found: {asset.name}",
                    description=f"A publicly accessible {asset.asset_type.value} was discovered. "
                               f"While contents cannot be listed, individual files may be accessible if URLs are known.",
                    severity=Severity.MEDIUM,
                    category="cloud_exposure",
                    affected_asset=asset.url,
                    affected_asset_type="cloud_asset",
                    evidence=f"Bucket exists and accepts public requests",
                    source="cloud_enum",
                    remediation="Review bucket permissions and ensure only intended files are public.",
                )
                findings.append(finding)
        else:
            # Bucket exists but not public - informational
            finding = Finding(
                title=f"{asset.provider.value.upper()} {asset.asset_type.value} discovered: {asset.name}",
                description=f"A {asset.asset_type.value} was discovered belonging to the target. "
                           f"While not publicly accessible, it confirms cloud infrastructure usage.",
                severity=Severity.INFO,
                category="cloud_discovery",
                affected_asset=asset.url,
                affected_asset_type="cloud_asset",
                evidence=f"Bucket exists (403 Forbidden - authentication required)",
                source="cloud_enum",
            )
            findings.append(finding)

    return findings


async def run(
    session: ScanSession,
    config: AttackTraceConfig,
    orchestrator,
) -> ModuleResult:
    """
    Run cloud asset enumeration.

    Performs comprehensive cloud discovery:
    1. Generate bucket name mutations from company/domain names
    2. Check AWS S3, GCP Storage, Azure Blob, Firebase, DigitalOcean
    3. Extract cloud URLs from discovered web applications
    4. Enumerate bucket contents for sensitive files
    5. Generate findings with severity based on exposure level

    Args:
        session: Current scan session
        config: AttackTrace configuration
        orchestrator: Orchestrator instance

    Returns:
        ModuleResult with discovered cloud assets
    """
    result = ModuleResult(
        module_name="cloud_enum",
        started_at=datetime.utcnow(),
    )

    # Generate base names from company and domains
    base_names = []

    if session.target_company:
        # Clean company name for bucket names
        company_lower = session.target_company.lower()

        # Strip common suffixes
        for suffix in [" inc", " llc", " ltd", " corp", " co", " company", " holdings", " group"]:
            if company_lower.endswith(suffix):
                company_lower = company_lower[:-len(suffix)]

        company_clean = re.sub(r"[^a-zA-Z0-9\s-]", "", company_lower)
        base_names.append(company_clean)
        base_names.append(company_clean.replace(" ", "-"))
        base_names.append(company_clean.replace(" ", ""))

        # Also try abbreviated versions
        words = company_clean.split()
        if len(words) > 1:
            # First letters of each word
            abbreviation = "".join(w[0] for w in words if w)
            if len(abbreviation) >= 2:
                base_names.append(abbreviation)

    for domain in session.target_domains:
        # Use domain without TLD
        parts = domain.split(".")
        if len(parts) >= 2:
            base_names.append(parts[0])
            base_names.append(".".join(parts[:-1]))
            # Full domain with dots replaced
            base_names.append(domain.replace(".", "-"))

    # Generate bucket name mutations
    bucket_names = generate_bucket_names(base_names)

    if not bucket_names:
        result.success = True
        result.completed_at = datetime.utcnow()
        return result

    # Get enabled providers
    providers = config.modules.cloud.providers

    # Increase limit for more thorough enumeration
    max_checks = 300
    bucket_names = list(set(bucket_names))[:max_checks]

    discovered_assets: list[CloudAsset] = []
    sensitive_files_map: dict[str, list[str]] = {}
    all_files_map: dict[str, list[str]] = {}
    semaphore = asyncio.Semaphore(25)  # Limit concurrent requests

    async def check_s3_with_enum(name: str):
        async with semaphore:
            result = await check_s3_bucket(name, config.scan.timeout, enumerate_contents=True)
            if result:
                asset, all_files, sensitive_files = result
                if all_files:
                    all_files_map[name] = all_files
                if sensitive_files:
                    sensitive_files_map[name] = sensitive_files
                return asset
            return None

    async def check_gcp_with_semaphore(name: str):
        async with semaphore:
            return await check_gcp_bucket(name, config.scan.timeout)

    async def check_azure_with_semaphore(container: str, account: str):
        async with semaphore:
            return await check_azure_blob(container, account, config.scan.timeout)

    async def check_firebase_with_semaphore(name: str):
        async with semaphore:
            return await check_firebase_database(name, config.scan.timeout)

    async def check_do_with_semaphore(name: str, region: str):
        async with semaphore:
            return await check_digitalocean_space(name, region, config.scan.timeout)

    tasks = []

    # AWS S3 checks
    if "aws" in providers:
        for bucket_name in bucket_names:
            tasks.append(check_s3_with_enum(bucket_name))

    # GCP Storage checks
    if "gcp" in providers:
        for bucket_name in bucket_names:
            tasks.append(check_gcp_with_semaphore(bucket_name))

    # Firebase checks (use base names, not mutations)
    if "gcp" in providers:
        for name in base_names[:10]:
            clean_name = re.sub(r"[^a-z0-9-]", "", name.lower())
            if clean_name:
                tasks.append(check_firebase_with_semaphore(clean_name))

    # Azure checks
    if "azure" in providers and session.target_company:
        account_name = re.sub(r"[^a-z0-9]", "", session.target_company.lower())[:24]
        if len(account_name) >= 3:
            azure_containers = [
                "public", "data", "files", "backup", "backups", "assets", "web",
                "static", "media", "uploads", "images", "logs", "archive",
                "documents", "docs", "reports", "config", "dev", "staging", "prod",
            ]
            for container in azure_containers:
                tasks.append(check_azure_with_semaphore(container, account_name))

            # Also try domain-based account names
            for domain in session.target_domains[:3]:
                domain_account = re.sub(r"[^a-z0-9]", "", domain.split(".")[0].lower())[:24]
                if domain_account and domain_account != account_name and len(domain_account) >= 3:
                    for container in azure_containers[:10]:
                        tasks.append(check_azure_with_semaphore(container, domain_account))

    # DigitalOcean Spaces checks
    if "digitalocean" in providers or True:  # Always check DO
        do_regions = ["nyc3", "sfo3", "ams3", "sgp1", "fra1"]
        for name in base_names[:5]:
            clean_name = re.sub(r"[^a-z0-9-]", "", name.lower())
            if clean_name and len(clean_name) >= 3:
                for region in do_regions[:2]:  # Check 2 regions
                    tasks.append(check_do_with_semaphore(clean_name, region))

    # Execute all enumeration checks
    if orchestrator.console:
        orchestrator.console.print(f"[dim]Checking {len(tasks)} cloud storage endpoints...[/dim]")

    results = await asyncio.gather(*tasks, return_exceptions=True)

    for asset in results:
        if isinstance(asset, CloudAsset):
            discovered_assets.append(asset)

    # Phase 2: Extract cloud URLs from web applications
    if session.web_applications:
        if orchestrator.console:
            orchestrator.console.print("[dim]Extracting cloud URLs from web pages...[/dim]")

        cloud_urls = await extract_cloud_urls_from_webapps(session, config.scan.timeout)

        # Check discovered cloud URLs
        extra_tasks = []

        for bucket_name in cloud_urls.get("s3", set()):
            if bucket_name not in [a.name for a in discovered_assets]:
                extra_tasks.append(check_s3_with_enum(bucket_name))

        for project_name in cloud_urls.get("firebase", set()):
            if project_name not in [a.name.replace(" (Firebase)", "") for a in discovered_assets]:
                extra_tasks.append(check_firebase_with_semaphore(project_name))

        if extra_tasks:
            extra_results = await asyncio.gather(*extra_tasks, return_exceptions=True)
            for asset in extra_results:
                if isinstance(asset, CloudAsset):
                    asset.source = "webapp_extraction"
                    discovered_assets.append(asset)

    # Create findings for discovered assets
    findings = create_findings_for_public_assets(discovered_assets, sensitive_files_map)

    # Add summary finding if multiple assets found
    if len(discovered_assets) > 3:
        public_count = sum(1 for a in discovered_assets if a.is_public)
        sensitive_count = len(sensitive_files_map)

        finding = Finding(
            title=f"Cloud infrastructure discovered: {len(discovered_assets)} storage endpoints",
            description=f"Discovered {len(discovered_assets)} cloud storage endpoints belonging to the target. "
                       f"{public_count} are publicly accessible"
                       f"{f' and {sensitive_count} contain sensitive files' if sensitive_count else ''}.",
            severity=Severity.HIGH if sensitive_count > 0 else (Severity.MEDIUM if public_count > 0 else Severity.INFO),
            category="cloud_discovery",
            affected_asset=session.target_company or session.target_domains[0],
            affected_asset_type="organization",
            evidence=f"Providers: {', '.join(set(a.provider.value for a in discovered_assets))}",
            source="cloud_enum",
        )
        findings.insert(0, finding)

    # Store file listings in session for detailed reporting
    if not hasattr(session, 'cloud_data'):
        session.cloud_data = {}
    session.cloud_data = {
        "all_files": all_files_map,
        "sensitive_files": sensitive_files_map,
    }

    result.cloud_assets = discovered_assets
    result.findings = findings
    result.items_discovered = len(discovered_assets)
    result.success = True
    result.completed_at = datetime.utcnow()

    return result
