"""
Configuration management for AttackTrace.

Handles loading configuration from files, environment variables,
and provides sensible defaults.
"""

import os
from pathlib import Path
from typing import Optional
import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class APIKeys(BaseModel):
    """API keys for external services."""
    # Core enrichment
    shodan: str = ""
    censys_id: str = ""
    censys_secret: str = ""
    securitytrails: str = ""
    virustotal: str = ""
    binaryedge: str = ""

    # OSINT
    hunter: str = ""
    github: str = ""

    # Intelligence platforms
    urlscan: str = ""
    greynoise: str = ""
    alienvault: str = ""
    ipinfo: str = ""
    builtwith: str = ""
    chaos: str = ""  # ProjectDiscovery Chaos

    # PassiveTotal / RiskIQ
    passivetotal: str = ""
    passivetotal_user: str = ""

    # Breach checking
    hibp: str = ""  # HaveIBeenPwned
    dehashed: str = ""
    dehashed_email: str = ""
    leakcheck: str = ""
    intelx: str = ""  # Intelligence X


class SubdomainConfig(BaseModel):
    """Subdomain enumeration settings."""
    wordlist: str = ""
    resolvers: str = ""
    bruteforce: bool = True
    bruteforce_threads: int = 200  # Increased for faster DNS bruteforce
    recursive: bool = False
    max_depth: int = 2


class PortScanConfig(BaseModel):
    """Port scanning settings."""
    top_ports: int = 1000
    custom_ports: list[int] = Field(default_factory=list)
    scan_type: str = "tcp"  # tcp, udp, both
    service_detection: bool = True
    version_detection: bool = True
    os_detection: bool = False
    script_scan: bool = False


class WebConfig(BaseModel):
    """Web discovery settings."""
    screenshot: bool = True
    tech_detect: bool = True
    follow_redirects: bool = True
    max_redirects: int = 5
    screenshot_timeout: int = 30
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


class CloudConfig(BaseModel):
    """Cloud enumeration settings."""
    providers: list[str] = Field(default_factory=lambda: ["aws", "azure", "gcp"])
    mutations: bool = True
    permutations_wordlist: str = ""


class ScanConfig(BaseModel):
    """General scan settings."""
    intensity: str = "normal"  # passive, normal, aggressive
    rate_limit: int = 1000  # requests/packets per second
    timeout: int = 10  # seconds
    retries: int = 2
    threads: int = 200  # Increased for better parallelism
    delay_between_requests: float = 0.0


class OutputConfig(BaseModel):
    """Output settings."""
    directory: str = "./results"
    formats: list[str] = Field(default_factory=lambda: ["json", "html"])
    screenshots_dir: str = "./screenshots"
    save_raw_responses: bool = False


class ScopeConfig(BaseModel):
    """Scope control settings."""
    exclude_ips: list[str] = Field(default_factory=list)
    exclude_domains: list[str] = Field(default_factory=list)
    exclude_cidrs: list[str] = Field(default_factory=list)
    include_only_cidrs: list[str] = Field(default_factory=list)
    respect_robots_txt: bool = True


class ModulesConfig(BaseModel):
    """Module-specific configurations."""
    subdomain: SubdomainConfig = Field(default_factory=SubdomainConfig)
    ports: PortScanConfig = Field(default_factory=PortScanConfig)
    web: WebConfig = Field(default_factory=WebConfig)
    cloud: CloudConfig = Field(default_factory=CloudConfig)


class AttackTraceConfig(BaseSettings):
    """Main AttackTrace configuration."""

    model_config = SettingsConfigDict(
        env_prefix="ATTACKTRACE_",
        env_nested_delimiter="__",
        case_sensitive=False,
    )

    # API Keys - can be set via environment variables
    api_keys: APIKeys = Field(default_factory=APIKeys)

    # Scan settings
    scan: ScanConfig = Field(default_factory=ScanConfig)

    # Module settings
    modules: ModulesConfig = Field(default_factory=ModulesConfig)

    # Output settings
    output: OutputConfig = Field(default_factory=OutputConfig)

    # Scope settings
    scope: ScopeConfig = Field(default_factory=ScopeConfig)

    # External tools paths
    tools: dict[str, str] = Field(default_factory=dict)

    @classmethod
    def load_from_file(cls, config_path: Path) -> "AttackTraceConfig":
        """Load configuration from a YAML file."""
        if not config_path.exists():
            return cls()

        with open(config_path) as f:
            data = yaml.safe_load(f) or {}

        # Handle nested 'attacktrace' key if present
        if "attacktrace" in data:
            data = data["attacktrace"]

        return cls(**data)

    @classmethod
    def load(cls, config_path: Optional[Path] = None) -> "AttackTraceConfig":
        """
        Load configuration from multiple sources with priority:
        1. Provided config file path
        2. ./attacktrace.yaml or ./config/config.yaml
        3. ~/.config/attacktrace/config.yaml
        4. Environment variables
        5. Defaults
        """
        config_files = [
            config_path,
            Path("./attacktrace.yaml"),
            Path("./config/config.yaml"),
            Path.home() / ".config" / "attacktrace" / "config.yaml",
        ]

        for path in config_files:
            if path and path.exists():
                config = cls.load_from_file(path)
                # Override with environment variables
                config._load_env_overrides()
                return config

        # Return default config with env overrides
        config = cls()
        config._load_env_overrides()
        return config

    def _load_env_overrides(self) -> None:
        """Load API keys from environment variables."""
        env_mappings = {
            # Core
            "SHODAN_API_KEY": "shodan",
            "CENSYS_API_ID": "censys_id",
            "CENSYS_API_SECRET": "censys_secret",
            "SECURITYTRAILS_API_KEY": "securitytrails",
            "VIRUSTOTAL_API_KEY": "virustotal",
            "BINARYEDGE_API_KEY": "binaryedge",
            # OSINT
            "HUNTER_API_KEY": "hunter",
            "GITHUB_TOKEN": "github",
            # Intel platforms
            "URLSCAN_API_KEY": "urlscan",
            "GREYNOISE_API_KEY": "greynoise",
            "ALIENVAULT_API_KEY": "alienvault",
            "IPINFO_TOKEN": "ipinfo",
            "BUILTWITH_API_KEY": "builtwith",
            "CHAOS_API_KEY": "chaos",
            "PASSIVETOTAL_API_KEY": "passivetotal",
            "PASSIVETOTAL_USER": "passivetotal_user",
            # Breach checking
            "HIBP_API_KEY": "hibp",
            "DEHASHED_API_KEY": "dehashed",
            "DEHASHED_EMAIL": "dehashed_email",
            "LEAKCHECK_API_KEY": "leakcheck",
            "INTELX_API_KEY": "intelx",
        }

        for env_var, key_name in env_mappings.items():
            value = os.getenv(env_var, "")
            if value:
                setattr(self.api_keys, key_name, value)

    def save(self, config_path: Path) -> None:
        """Save configuration to a YAML file."""
        config_path.parent.mkdir(parents=True, exist_ok=True)

        with open(config_path, "w") as f:
            yaml.dump(
                {"attacktrace": self.model_dump(exclude_none=True)},
                f,
                default_flow_style=False,
                sort_keys=False,
            )

    def get_output_dir(self, session_id: str) -> Path:
        """Get output directory for a scan session."""
        output_dir = Path(self.output.directory) / session_id
        output_dir.mkdir(parents=True, exist_ok=True)
        return output_dir

    def get_screenshots_dir(self, session_id: str) -> Path:
        """Get screenshots directory for a scan session."""
        screenshots_dir = Path(self.output.screenshots_dir) / session_id
        screenshots_dir.mkdir(parents=True, exist_ok=True)
        return screenshots_dir

    def is_in_scope(self, target: str) -> bool:
        """Check if a target (domain or IP) is in scope."""
        from netaddr import IPAddress, IPNetwork
        import validators

        # Check exclusions first
        if target in self.scope.exclude_domains:
            return False

        if target in self.scope.exclude_ips:
            return False

        # Check if it's an IP address
        if validators.ipv4(target) or validators.ipv6(target):
            ip = IPAddress(target)

            # Check CIDR exclusions
            for cidr in self.scope.exclude_cidrs:
                if ip in IPNetwork(cidr):
                    return False

            # Check include-only CIDRs if specified
            if self.scope.include_only_cidrs:
                for cidr in self.scope.include_only_cidrs:
                    if ip in IPNetwork(cidr):
                        return True
                return False

        # Check domain exclusions
        for excluded in self.scope.exclude_domains:
            if target.endswith(excluded):
                return False

        return True


# Default configuration instance
_config: Optional[AttackTraceConfig] = None


def get_config() -> AttackTraceConfig:
    """Get the global configuration instance."""
    global _config
    if _config is None:
        _config = AttackTraceConfig.load()
    return _config


def set_config(config: AttackTraceConfig) -> None:
    """Set the global configuration instance."""
    global _config
    _config = config
