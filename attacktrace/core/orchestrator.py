"""
Orchestrator for AttackTrace discovery pipeline.

Coordinates the execution of discovery modules in the correct order,
manages data flow between modules, and handles the overall scan lifecycle.
"""

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional, Callable, Any
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskID

from attacktrace.config import AttackTraceConfig, get_config
from attacktrace.core.models import (
    ScanSession,
    ScanStatus,
    Organization,
    ModuleResult,
)
from attacktrace.core.database import Database


# Type alias for module functions
ModuleFunction = Callable[[ScanSession, AttackTraceConfig, "Orchestrator"], ModuleResult]


class Orchestrator:
    """
    Orchestrates the attack surface discovery pipeline.

    Manages module execution order, data persistence, and progress reporting.
    """

    # Module execution order
    MODULE_ORDER = [
        "seed",           # Initial discovery (WHOIS, crt.sh, ASN)
        "domain",         # Domain/subdomain enumeration
        "dns",            # DNS resolution
        "infrastructure", # Port scanning, service detection
        "enrichment",     # Shodan, Censys enrichment
        "intel",          # Threat intel, CVEs, breach data
        "osint",          # GitHub recon, employee discovery
        "web",            # Web application discovery
        "cloud",          # Cloud asset enumeration
        "correlation",    # Data correlation and risk scoring
    ]

    def __init__(
        self,
        config: Optional[AttackTraceConfig] = None,
        db_path: Optional[Path] = None,
        console: Optional[Console] = None,
    ):
        """
        Initialize the orchestrator.

        Args:
            config: AttackTrace configuration. If None, loads from default locations.
            db_path: Path to database file. If None, creates in output directory.
            console: Rich console for output. If None, creates a new one.
        """
        self.config = config or get_config()
        self.console = console or Console()
        self.db: Optional[Database] = None
        self.db_path = db_path
        self.session: Optional[ScanSession] = None

        # Registered modules
        self._modules: dict[str, ModuleFunction] = {}

        # Event callbacks
        self._on_module_start: list[Callable[[str], None]] = []
        self._on_module_complete: list[Callable[[str, ModuleResult], None]] = []
        self._on_finding: list[Callable[[Any], None]] = []

        # Progress tracking
        self._progress: Optional[Progress] = None
        self._task_ids: dict[str, TaskID] = {}

    def register_module(self, name: str, func: ModuleFunction) -> None:
        """Register a discovery module."""
        self._modules[name] = func

    def on_module_start(self, callback: Callable[[str], None]) -> None:
        """Register a callback for module start events."""
        self._on_module_start.append(callback)

    def on_module_complete(self, callback: Callable[[str, ModuleResult], None]) -> None:
        """Register a callback for module completion events."""
        self._on_module_complete.append(callback)

    def on_finding(self, callback: Callable[[Any], None]) -> None:
        """Register a callback for new findings."""
        self._on_finding.append(callback)

    def _init_database(self, session_id: str) -> None:
        """Initialize the database for a session."""
        if self.db_path:
            db_file = self.db_path
        else:
            output_dir = self.config.get_output_dir(session_id)
            db_file = output_dir / "attacktrace.db"

        self.db = Database(db_file)

    def create_session(
        self,
        company: str = "",
        domains: Optional[list[str]] = None,
        ip_ranges: Optional[list[str]] = None,
        modules: Optional[list[str]] = None,
        passive_only: bool = False,
        intensity: str = "normal",
    ) -> ScanSession:
        """
        Create a new scan session.

        Args:
            company: Target company name
            domains: List of known root domains
            ip_ranges: List of known IP ranges (CIDR notation)
            modules: List of modules to run. If None, runs all.
            passive_only: If True, only runs passive discovery modules
            intensity: Scan intensity (passive, normal, aggressive)

        Returns:
            Created ScanSession object
        """
        self.session = ScanSession(
            target_company=company,
            target_domains=domains or [],
            target_ip_ranges=ip_ranges or [],
            modules_enabled=modules or self.MODULE_ORDER.copy(),
            passive_only=passive_only,
            intensity=intensity,
            status=ScanStatus.PENDING,
        )

        # Initialize organization
        if company:
            self.session.organization = Organization(
                name=company,
                source="user_input",
            )

        # Initialize database
        self._init_database(self.session.id)
        self.db.create_session(self.session)

        return self.session

    def load_session(self, session_id: str) -> Optional[ScanSession]:
        """Load an existing session."""
        self._init_database(session_id)
        self.session = self.db.get_session(session_id)
        return self.session

    # Module execution phases for parallel execution
    # Modules in the same phase can run concurrently
    MODULE_PHASES = [
        ["seed"],                                          # Phase 1: Initial discovery
        ["domain", "osint"],                               # Phase 2: Subdomain + OSINT (parallel)
        ["dns"],                                           # Phase 3: DNS resolution
        ["infrastructure", "enrichment", "intel", "web", "cloud"],  # Phase 4: All enrichment (parallel)
        ["correlation"],                                   # Phase 5: Final correlation
    ]

    async def run(self) -> ScanSession:
        """
        Run the discovery pipeline with parallel module execution.

        Modules are grouped into phases based on dependencies.
        Within each phase, modules run concurrently for maximum speed.

        Returns:
            Completed ScanSession with all discovered data
        """
        if not self.session:
            raise ValueError("No session created. Call create_session first.")

        if not self.db:
            raise ValueError("Database not initialized.")

        # Update session status
        self.session.status = ScanStatus.RUNNING
        self.db.update_session(self.session)

        try:
            # Filter modules based on passive_only mode
            modules_to_run = set(self._get_modules_to_run())

            # Run phases sequentially, modules within phases in parallel
            for phase in self.MODULE_PHASES:
                # Get modules in this phase that should run
                phase_modules = [m for m in phase if m in modules_to_run and m in self._modules]

                if not phase_modules:
                    continue

                # Notify module starts
                for module_name in phase_modules:
                    for callback in self._on_module_start:
                        callback(module_name)

                # Run all modules in this phase concurrently
                if len(phase_modules) == 1:
                    # Single module - run directly
                    await self._execute_module(phase_modules[0])
                else:
                    # Multiple modules - run in parallel
                    tasks = [self._execute_module(m) for m in phase_modules]
                    await asyncio.gather(*tasks, return_exceptions=True)

            # Update final statistics
            self.session.update_statistics()
            self.session.status = ScanStatus.COMPLETED
            self.db.update_session(self.session)

            # Cleanup HTTP clients
            try:
                from attacktrace.utils.http_client import cleanup_http_clients
                await cleanup_http_clients()
            except Exception:
                pass

        except Exception as e:
            self.session.status = ScanStatus.FAILED
            self.db.update_session(self.session)
            raise

        return self.session

    async def _execute_module(self, module_name: str) -> None:
        """Execute a single module with error handling and result merging."""
        try:
            result = await self._run_module(module_name)
            self.session.module_results.append(result)

            # Merge results into session (thread-safe)
            self._merge_module_result(result)

            # Notify module complete
            for callback in self._on_module_complete:
                callback(module_name, result)

        except Exception as e:
            self.console.print(f"[red]Error in module '{module_name}': {e}[/red]")
            result = ModuleResult(
                module_name=module_name,
                success=False,
                error_message=str(e),
                completed_at=datetime.utcnow(),
            )
            self.session.module_results.append(result)

    def _get_modules_to_run(self) -> list[str]:
        """Get the list of modules to run based on configuration."""
        # Web is included in passive because HTTP probing is minimally intrusive
        # and needed for screenshots and tech detection
        passive_modules = {"seed", "domain", "dns", "enrichment", "intel", "osint", "web", "correlation"}

        modules = []
        for module in self.MODULE_ORDER:
            if module not in self.session.modules_enabled:
                continue

            if self.session.passive_only and module not in passive_modules:
                continue

            modules.append(module)

        return modules

    async def _run_module(self, module_name: str) -> ModuleResult:
        """Run a single module."""
        module_func = self._modules[module_name]
        result = ModuleResult(
            module_name=module_name,
            started_at=datetime.utcnow(),
        )

        try:
            # Run the module (supports both sync and async)
            if asyncio.iscoroutinefunction(module_func):
                module_result = await module_func(self.session, self.config, self)
            else:
                module_result = module_func(self.session, self.config, self)

            if module_result:
                result = module_result

            result.success = True
            result.completed_at = datetime.utcnow()

        except Exception as e:
            result.success = False
            result.error_message = str(e)
            result.completed_at = datetime.utcnow()
            raise

        return result

    def _merge_module_result(self, result: ModuleResult) -> None:
        """Merge module results into the session using O(1) lookups."""
        # Build lookup sets for O(1) membership testing
        existing_domains = {d.fqdn for d in self.session.domains}
        existing_subdomains = {s.fqdn for s in self.session.subdomains}
        existing_ips = {ip.address for ip in self.session.ip_addresses}

        # Merge domains
        for domain in result.domains:
            if domain.fqdn not in existing_domains:
                self.session.domains.append(domain)
                self.db.add_domain(self.session.id, domain)
                existing_domains.add(domain.fqdn)

        # Merge subdomains (add new ones, update existing with resolved data)
        for subdomain in result.subdomains:
            if subdomain.fqdn not in existing_subdomains:
                self.session.subdomains.append(subdomain)
                self.db.add_subdomain(self.session.id, subdomain)
                existing_subdomains.add(subdomain.fqdn)
            else:
                # Update existing subdomain with resolved IPs and is_alive status
                for existing in self.session.subdomains:
                    if existing.fqdn == subdomain.fqdn:
                        existing.resolved_ips = subdomain.resolved_ips
                        existing.is_alive = subdomain.is_alive
                        existing.cname_chain = subdomain.cname_chain
                        break
                self.db.update_subdomain(self.session.id, subdomain)

        # Merge IP addresses (update existing IPs with new data like ports)
        for ip in result.ip_addresses:
            if ip.address not in existing_ips:
                self.session.ip_addresses.append(ip)
                self.db.add_ip_address(self.session.id, ip)
                existing_ips.add(ip.address)
            else:
                # Update existing IP with new data (ports, services, etc.)
                for existing_ip in self.session.ip_addresses:
                    if existing_ip.address == ip.address:
                        # Merge ports (add new ports, don't duplicate)
                        existing_ports = {p.number for p in existing_ip.ports}
                        for port in ip.ports:
                            if port.number not in existing_ports:
                                existing_ip.ports.append(port)
                                existing_ports.add(port.number)

                        # Update other fields if they have new data
                        if ip.asn and not existing_ip.asn:
                            existing_ip.asn = ip.asn
                        if ip.asn_org and not existing_ip.asn_org:
                            existing_ip.asn_org = ip.asn_org
                        if ip.reverse_dns and not existing_ip.reverse_dns:
                            existing_ip.reverse_dns = ip.reverse_dns
                        if ip.geolocation.country and not existing_ip.geolocation.country:
                            existing_ip.geolocation = ip.geolocation
                        if ip.cloud_provider and not existing_ip.cloud_provider:
                            existing_ip.cloud_provider = ip.cloud_provider
                        if ip.hostnames:
                            existing_hostnames = set(existing_ip.hostnames)
                            for hostname in ip.hostnames:
                                if hostname not in existing_hostnames:
                                    existing_ip.hostnames.append(hostname)

                        # Update in database
                        self.db.update_ip_address(self.session.id, existing_ip)
                        break

        # Merge web applications
        for webapp in result.web_applications:
            self.session.web_applications.append(webapp)
            self.db.add_web_application(self.session.id, webapp)

        # Merge cloud assets
        for asset in result.cloud_assets:
            self.session.cloud_assets.append(asset)
            self.db.add_cloud_asset(self.session.id, asset)

        # Merge findings
        for finding in result.findings:
            self.session.findings.append(finding)
            self.db.add_finding(self.session.id, finding)
            # Notify finding callbacks
            for callback in self._on_finding:
                callback(finding)

        # Merge certificates
        for cert in result.certificates:
            self.session.certificates.append(cert)
            self.db.add_certificate(self.session.id, cert)

        # Update session in database
        self.db.update_session(self.session)

    def add_domain(self, fqdn: str, source: str = "manual") -> None:
        """Add a domain to the current session."""
        if not self.session or not self.db:
            return

        from attacktrace.core.models import Domain
        domain = Domain(fqdn=fqdn, source=source)

        if fqdn not in [d.fqdn for d in self.session.domains]:
            self.session.domains.append(domain)
            self.db.add_domain(self.session.id, domain)
            self.session.target_domains.append(fqdn)
            self.db.update_session(self.session)

    def add_subdomain(self, fqdn: str, parent_domain: str, source: str = "manual") -> None:
        """Add a subdomain to the current session."""
        if not self.session or not self.db:
            return

        from attacktrace.core.models import Subdomain
        subdomain = Subdomain(fqdn=fqdn, parent_domain=parent_domain, source=source)

        if not self.db.subdomain_exists(self.session.id, fqdn):
            self.session.subdomains.append(subdomain)
            self.db.add_subdomain(self.session.id, subdomain)

    def add_ip(self, address: str, source: str = "manual") -> None:
        """Add an IP address to the current session."""
        if not self.session or not self.db:
            return

        from attacktrace.core.models import IPAddress
        ip = IPAddress(address=address, source=source)

        if not self.db.ip_exists(self.session.id, address):
            self.session.ip_addresses.append(ip)
            self.db.add_ip_address(self.session.id, ip)

    def get_statistics(self) -> dict:
        """Get current session statistics."""
        if not self.session:
            return {}

        self.session.update_statistics()
        return {
            "domains": self.session.total_domains,
            "subdomains": self.session.total_subdomains,
            "ip_addresses": self.session.total_ips,
            "open_ports": self.session.total_ports,
            "web_applications": self.session.total_web_apps,
            "cloud_assets": self.session.total_cloud_assets,
            "findings": {
                "total": self.session.total_findings,
                "critical": self.session.critical_findings,
                "high": self.session.high_findings,
                "medium": self.session.medium_findings,
                "low": self.session.low_findings,
            },
        }

    def cancel(self) -> None:
        """Cancel the current scan."""
        if self.session:
            self.session.status = ScanStatus.CANCELLED
            if self.db:
                self.db.update_session(self.session)

    def cleanup(self) -> None:
        """Clean up resources."""
        if self.db:
            self.db.close()
            self.db = None
