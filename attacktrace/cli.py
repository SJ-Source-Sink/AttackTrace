"""
Command-line interface for AttackTrace.

Provides commands for running discovery scans, managing sessions,
and generating reports.
"""

import asyncio
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.live import Live
from rich.layout import Layout
from rich.prompt import Prompt, Confirm
from rich import box

from attacktrace import __version__
from attacktrace.config import AttackTraceConfig, set_config
from attacktrace.core.orchestrator import Orchestrator
from attacktrace.core.models import ScanStatus, Severity
from attacktrace.core.database import Database

# Initialize Typer app
app = typer.Typer(
    name="attacktrace",
    help="AttackTrace - Red Team Reconnaissance Tool",
    add_completion=False,
    rich_markup_mode="rich",
    invoke_without_command=True,
)

console = Console()


@app.callback()
def main(ctx: typer.Context):
    """
    AttackTrace - AttackTrace

    Run without arguments to start interactive mode.
    """
    if ctx.invoked_subcommand is None:
        # No subcommand provided, run interactive wizard
        run_interactive_wizard()


def run_interactive_wizard():
    """Run interactive wizard for scan configuration."""
    print_banner()

    console.print("\n[bold cyan]Welcome to AttackTrace Interactive Mode[/bold cyan]")
    console.print("[dim]Answer the following questions to configure your scan.[/dim]\n")

    # Step 1: Target Information
    console.print("[bold yellow]━━━ Step 1: Target Information ━━━[/bold yellow]\n")

    company = Prompt.ask(
        "[cyan]Company/Organization name[/cyan]",
        default="",
    )

    domains_input = Prompt.ask(
        "[cyan]Target domains[/cyan] [dim](comma-separated, e.g., example.com,example.org)[/dim]",
        default="",
    )
    domains = [d.strip() for d in domains_input.split(",") if d.strip()] if domains_input else []

    if not company and not domains:
        console.print("\n[red]Error: You must provide either a company name or at least one domain.[/red]")
        raise typer.Exit(1)

    ip_ranges_input = Prompt.ask(
        "[cyan]IP ranges to include[/cyan] [dim](optional, CIDR notation, e.g., 10.0.0.0/24)[/dim]",
        default="",
    )
    ip_ranges = [i.strip() for i in ip_ranges_input.split(",") if i.strip()] if ip_ranges_input else []

    # Step 2: Scan Configuration
    console.print("\n[bold yellow]━━━ Step 2: Scan Configuration ━━━[/bold yellow]\n")

    # Scan intensity
    console.print("[cyan]Scan intensity:[/cyan]")
    console.print("  [dim]1)[/dim] passive  - Only passive reconnaissance (OSINT, no direct contact)")
    console.print("  [dim]2)[/dim] normal   - Standard scanning with rate limiting")
    console.print("  [dim]3)[/dim] aggressive - Fast scanning, more noise")

    intensity_choice = Prompt.ask(
        "\n[cyan]Select intensity[/cyan]",
        choices=["1", "2", "3", "passive", "normal", "aggressive"],
        default="2",
    )

    intensity_map = {"1": "passive", "2": "normal", "3": "aggressive"}
    intensity = intensity_map.get(intensity_choice, intensity_choice)
    passive_only = intensity == "passive"

    # Step 3: Module Selection
    console.print("\n[bold yellow]━━━ Step 3: Module Selection ━━━[/bold yellow]\n")

    all_modules = [
        ("seed", "Seed Discovery", "WHOIS, Certificate Transparency, ASN discovery"),
        ("domain", "Domain Enumeration", "Subdomain discovery from multiple sources"),
        ("dns", "DNS Resolution", "Resolve discovered domains to IPs"),
        ("infrastructure", "Port Scanning", "Discover open ports and services (SFTP, FTP, SMB, etc.)"),
        ("enrichment", "Enrichment", "Shodan, Censys, SecurityTrails lookups"),
        ("intel", "Intelligence", "URLScan, GreyNoise, Wayback, breach data, CVEs"),
        ("osint", "OSINT", "GitHub repos, commits, employees, leaked secrets"),
        ("web", "Web Probing", "HTTP probing, tech detection, screenshots"),
        ("cloud", "Cloud Assets", "S3 buckets, Azure blobs, GCP storage"),
        ("correlation", "Correlation", "Correlate data and calculate risk scores"),
    ]

    console.print("[cyan]Available modules:[/cyan]")
    for i, (key, name, desc) in enumerate(all_modules, 1):
        console.print(f"  [dim]{i})[/dim] [bold]{name}[/bold] - {desc}")

    console.print("\n[dim]Press Enter to run all modules, or enter module numbers to skip.[/dim]")
    skip_input = Prompt.ask(
        "[cyan]Modules to SKIP[/cyan] [dim](comma-separated numbers, e.g., 4,5)[/dim]",
        default="",
    )

    selected_modules = [m[0] for m in all_modules]
    if skip_input:
        skip_indices = [int(x.strip()) - 1 for x in skip_input.split(",") if x.strip().isdigit()]
        selected_modules = [m[0] for i, m in enumerate(all_modules) if i not in skip_indices]

    # Step 4: Output Configuration
    console.print("\n[bold yellow]━━━ Step 4: Output Configuration ━━━[/bold yellow]\n")

    output_dir = Prompt.ask(
        "[cyan]Output directory[/cyan]",
        default="./results",
    )

    generate_html = Confirm.ask(
        "[cyan]Generate HTML report when complete?[/cyan]",
        default=True,
    )

    # Summary and Confirmation
    console.print("\n[bold yellow]━━━ Scan Configuration Summary ━━━[/bold yellow]\n")

    summary_table = Table(box=box.ROUNDED, show_header=False)
    summary_table.add_column("Setting", style="cyan")
    summary_table.add_column("Value", style="white")

    if company:
        summary_table.add_row("Company", company)
    if domains:
        summary_table.add_row("Domains", ", ".join(domains))
    if ip_ranges:
        summary_table.add_row("IP Ranges", ", ".join(ip_ranges))
    summary_table.add_row("Intensity", intensity)
    summary_table.add_row("Modules", ", ".join(selected_modules))
    summary_table.add_row("Output", output_dir)
    summary_table.add_row("HTML Report", "Yes" if generate_html else "No")

    console.print(summary_table)

    if not Confirm.ask("\n[bold cyan]Start scan with these settings?[/bold cyan]", default=True):
        console.print("[yellow]Scan cancelled.[/yellow]")
        raise typer.Exit(0)

    # Run the scan
    console.print("\n[bold green]Starting scan...[/bold green]\n")

    # Load configuration
    config = AttackTraceConfig.load()
    config.output.directory = output_dir
    set_config(config)

    # Create orchestrator and session
    orchestrator = Orchestrator(config=config, console=console)
    _register_modules(orchestrator)

    session = orchestrator.create_session(
        company=company,
        domains=domains,
        ip_ranges=ip_ranges,
        modules=selected_modules,
        passive_only=passive_only,
        intensity=intensity,
    )

    console.print(f"[bold green]Session created:[/bold green] {session.id}")
    console.print(f"[dim]Output directory: {config.get_output_dir(session.id)}[/dim]\n")

    # Run discovery with progress display
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            main_task = progress.add_task(
                "[cyan]Running discovery...",
                total=len(selected_modules)
            )

            def on_module_start(name: str):
                progress.update(main_task, description=f"[cyan]Running {name}...")
                # Show module-specific info
                module_info = {
                    "seed": "WHOIS, Certificate Transparency, ASN discovery",
                    "domain": "Subdomain enumeration from multiple sources",
                    "dns": "DNS resolution and validation",
                    "infrastructure": "Port scanning and service detection",
                    "enrichment": "Shodan, Censys, SecurityTrails enrichment",
                    "intel": "Threat intel, CVEs, Wayback, breach data",
                    "osint": "GitHub recon, employee discovery",
                    "web": "HTTP probing, tech detection, screenshots",
                    "cloud": "S3 buckets, Azure blobs, GCP storage",
                    "correlation": "Data correlation and risk scoring",
                }
                console.print(f"\n[bold cyan]▶ {name.upper()}[/bold cyan] - {module_info.get(name, '')}")

            def on_module_complete(name: str, result):
                progress.advance(main_task)
                status = "[green]✓[/green]" if result.success else "[red]✗[/red]"

                # Show detailed results for each module
                console.print(f"  {status} [bold]{name}[/bold]: {result.items_discovered} items")

                # Show breakdown of what was found
                details = []
                if result.domains:
                    details.append(f"[cyan]{len(result.domains)} domains[/cyan]")
                if result.subdomains:
                    details.append(f"[cyan]{len(result.subdomains)} subdomains[/cyan]")
                if result.ip_addresses:
                    total_ports = sum(len(ip.ports) for ip in result.ip_addresses)
                    details.append(f"[cyan]{len(result.ip_addresses)} IPs[/cyan]")
                    if total_ports:
                        details.append(f"[green]{total_ports} open ports[/green]")
                if result.web_applications:
                    alive = sum(1 for w in result.web_applications if w.is_alive)
                    details.append(f"[cyan]{len(result.web_applications)} web apps ({alive} alive)[/cyan]")
                if result.cloud_assets:
                    public = sum(1 for c in result.cloud_assets if c.is_public)
                    details.append(f"[cyan]{len(result.cloud_assets)} cloud assets[/cyan]")
                    if public:
                        details.append(f"[red]{public} PUBLIC[/red]")
                if result.certificates:
                    details.append(f"[cyan]{len(result.certificates)} certificates[/cyan]")
                if result.findings:
                    critical = sum(1 for f in result.findings if f.severity.value == "critical")
                    high = sum(1 for f in result.findings if f.severity.value == "high")
                    if critical:
                        details.append(f"[red]{critical} CRITICAL[/red]")
                    if high:
                        details.append(f"[yellow]{high} HIGH[/yellow]")
                    if len(result.findings) - critical - high > 0:
                        details.append(f"[dim]{len(result.findings) - critical - high} other findings[/dim]")

                if details:
                    console.print(f"    └─ {', '.join(details)}")

                # Show sample of interesting discoveries
                if result.findings:
                    for finding in result.findings[:3]:
                        severity_color = {"critical": "red", "high": "yellow", "medium": "blue"}.get(finding.severity.value, "dim")
                        console.print(f"       [{severity_color}]• {finding.title[:70]}{'...' if len(finding.title) > 70 else ''}[/{severity_color}]")

            orchestrator.on_module_start(on_module_start)
            orchestrator.on_module_complete(on_module_complete)

            # Add finding callback for real-time critical finding alerts
            def on_finding(finding):
                if finding.severity.value in ["critical", "high"]:
                    severity_color = "red" if finding.severity.value == "critical" else "yellow"
                    # Only show if not already shown in module complete
                    pass  # Findings shown in module_complete for cleaner output

            orchestrator.on_finding(on_finding)

            asyncio.run(orchestrator.run())

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        orchestrator.cancel()
    finally:
        orchestrator.cleanup()

    # Display results summary
    _display_results_summary(session)

    console.print(f"\n[bold green]Scan complete![/bold green]")
    console.print(f"Results saved to: {config.get_output_dir(session.id)}")

    # Generate HTML report if requested
    if generate_html:
        db_file = Path(output_dir) / session.id / "attacktrace.db"
        if db_file.exists():
            db = Database(db_file)

            # Generate report in reports folder
            reports_dir = Path("./reports")
            reports_dir.mkdir(parents=True, exist_ok=True)
            target_name = company or (domains[0] if domains else "scan")
            target_name = re.sub(r'[^\w\-]', '_', target_name)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_path = reports_dir / f"attacktrace_{target_name}_{timestamp}.html"

            _export_html(db, session, report_path)
            db.close()

            console.print(f"\n[bold cyan]Opening report...[/bold cyan]")
            import subprocess
            subprocess.run(["open", str(report_path)], check=False)

    console.print(f"\nView detailed results: [cyan]attacktrace report {session.id}[/cyan]")


def print_banner():
    """Print the AttackTrace banner."""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║     ███████╗ █████╗ ███████╗██████╗                          ║
    ║     ██╔════╝██╔══██╗██╔════╝██╔══██╗                         ║
    ║     █████╗  ███████║███████╗██║  ██║                         ║
    ║     ██╔══╝  ██╔══██║╚════██║██║  ██║                         ║
    ║     ███████╗██║  ██║███████║██████╔╝                         ║
    ║     ╚══════╝╚═╝  ╚═╝╚══════╝╚═════╝                          ║
    ║                                                               ║
    ║     AttackTrace                         ║
    ║     v{version}                                                    ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """.format(version=__version__)
    console.print(banner, style="bold cyan")


@app.command()
def discover(
    company: Optional[str] = typer.Option(
        None, "--company", "-c",
        help="Target company name for discovery"
    ),
    domains: Optional[str] = typer.Option(
        None, "--domains", "-d",
        help="Comma-separated list of known root domains"
    ),
    ip_ranges: Optional[str] = typer.Option(
        None, "--ip-ranges", "-i",
        help="Comma-separated list of IP ranges (CIDR notation)"
    ),
    output: Path = typer.Option(
        Path("./results"), "--output", "-o",
        help="Output directory for results"
    ),
    modules: Optional[str] = typer.Option(
        None, "--modules", "-m",
        help="Comma-separated list of modules to run"
    ),
    skip_modules: Optional[str] = typer.Option(
        None, "--skip-modules",
        help="Comma-separated list of modules to skip"
    ),
    intensity: str = typer.Option(
        "normal", "--intensity",
        help="Scan intensity: passive, normal, aggressive"
    ),
    passive_only: bool = typer.Option(
        False, "--passive-only", "-p",
        help="Only run passive discovery (no active scanning)"
    ),
    config_file: Optional[Path] = typer.Option(
        None, "--config", "-C",
        help="Path to configuration file"
    ),
    quiet: bool = typer.Option(
        False, "--quiet", "-q",
        help="Minimal output"
    ),
):
    """
    Run attack surface discovery against a target.

    Examples:
        attacktrace discover --company "Acme Corp"
        attacktrace discover --domains acme.com,acmecorp.com
        attacktrace discover --company "Acme" --passive-only
    """
    if not quiet:
        print_banner()

    # Validate inputs
    if not company and not domains:
        console.print("[red]Error: Either --company or --domains must be specified[/red]")
        raise typer.Exit(1)

    # Load configuration
    config = AttackTraceConfig.load(config_file)
    config.output.directory = str(output)
    set_config(config)

    # Parse inputs
    domain_list = [d.strip() for d in domains.split(",")] if domains else []
    ip_range_list = [i.strip() for i in ip_ranges.split(",")] if ip_ranges else []

    # Parse modules
    module_list = None
    if modules:
        module_list = [m.strip() for m in modules.split(",")]

    if skip_modules:
        skip_list = [m.strip() for m in skip_modules.split(",")]
        if module_list is None:
            module_list = Orchestrator.MODULE_ORDER.copy()
        module_list = [m for m in module_list if m not in skip_list]

    # Create orchestrator and session
    orchestrator = Orchestrator(config=config, console=console)

    # Register discovery modules
    _register_modules(orchestrator)

    session = orchestrator.create_session(
        company=company or "",
        domains=domain_list,
        ip_ranges=ip_range_list,
        modules=module_list,
        passive_only=passive_only,
        intensity=intensity,
    )

    console.print(f"\n[bold green]Session created:[/bold green] {session.id}")
    console.print(f"[dim]Output directory: {config.get_output_dir(session.id)}[/dim]\n")

    # Display target info
    _display_target_info(session, company, domain_list, ip_range_list)

    # Run discovery with progress display
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            main_task = progress.add_task(
                "[cyan]Running discovery...",
                total=len(orchestrator._get_modules_to_run())
            )

            current_module = {"name": ""}

            def on_module_start(name: str):
                current_module["name"] = name
                progress.update(main_task, description=f"[cyan]Running {name}...")
                if not quiet:
                    module_info = {
                        "seed": "WHOIS, Certificate Transparency, ASN discovery",
                        "domain": "Subdomain enumeration from multiple sources",
                        "dns": "DNS resolution and validation",
                        "infrastructure": "Port scanning and service detection",
                        "enrichment": "Shodan, Censys, SecurityTrails enrichment",
                        "intel": "Threat intel, CVEs, Wayback, breach data",
                        "osint": "GitHub recon, employee discovery",
                        "web": "HTTP probing, tech detection, screenshots",
                        "cloud": "S3 buckets, Azure blobs, GCP storage",
                        "correlation": "Data correlation and risk scoring",
                    }
                    console.print(f"\n[bold cyan]▶ {name.upper()}[/bold cyan] - {module_info.get(name, '')}")

            def on_module_complete(name: str, result):
                progress.advance(main_task)
                if not quiet:
                    status = "[green]✓[/green]" if result.success else "[red]✗[/red]"
                    console.print(f"  {status} [bold]{name}[/bold]: {result.items_discovered} items")

                    # Show breakdown of discoveries
                    details = []
                    if result.domains:
                        details.append(f"[cyan]{len(result.domains)} domains[/cyan]")
                    if result.subdomains:
                        details.append(f"[cyan]{len(result.subdomains)} subdomains[/cyan]")
                    if result.ip_addresses:
                        total_ports = sum(len(ip.ports) for ip in result.ip_addresses)
                        details.append(f"[cyan]{len(result.ip_addresses)} IPs[/cyan]")
                        if total_ports:
                            details.append(f"[green]{total_ports} open ports[/green]")
                    if result.web_applications:
                        alive = sum(1 for w in result.web_applications if w.is_alive)
                        details.append(f"[cyan]{len(result.web_applications)} web apps ({alive} alive)[/cyan]")
                    if result.cloud_assets:
                        public = sum(1 for c in result.cloud_assets if c.is_public)
                        details.append(f"[cyan]{len(result.cloud_assets)} cloud assets[/cyan]")
                        if public:
                            details.append(f"[red]{public} PUBLIC[/red]")
                    if result.certificates:
                        details.append(f"[cyan]{len(result.certificates)} certs[/cyan]")
                    if result.findings:
                        critical = sum(1 for f in result.findings if f.severity.value == "critical")
                        high = sum(1 for f in result.findings if f.severity.value == "high")
                        if critical:
                            details.append(f"[red]{critical} CRITICAL[/red]")
                        if high:
                            details.append(f"[yellow]{high} HIGH[/yellow]")

                    if details:
                        console.print(f"    └─ {', '.join(details)}")

                    # Show sample findings
                    if result.findings:
                        for finding in result.findings[:2]:
                            sev_color = {"critical": "red", "high": "yellow", "medium": "blue"}.get(finding.severity.value, "dim")
                            console.print(f"       [{sev_color}]• {finding.title[:65]}{'...' if len(finding.title) > 65 else ''}[/{sev_color}]")

            orchestrator.on_module_start(on_module_start)
            orchestrator.on_module_complete(on_module_complete)

            # Run async discovery
            asyncio.run(orchestrator.run())

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        orchestrator.cancel()
    except Exception as e:
        console.print(f"\n[red]Error during discovery: {e}[/red]")
        raise typer.Exit(1)
    finally:
        orchestrator.cleanup()

    # Display results summary
    _display_results_summary(session)

    console.print(f"\n[bold green]Scan complete![/bold green]")
    console.print(f"Results saved to: {config.get_output_dir(session.id)}")
    console.print(f"\nView detailed results: [cyan]attacktrace report {session.id}[/cyan]")


@app.command()
def scan(
    interactive: bool = typer.Option(
        True, "--interactive", "-i",
        help="Run in interactive mode (default)"
    ),
    company: Optional[str] = typer.Option(
        None, "--company", "-c",
        help="Target company name"
    ),
    domains: Optional[str] = typer.Option(
        None, "--domains", "-d",
        help="Comma-separated list of domains"
    ),
):
    """
    Start a new attack surface discovery scan.

    Run without arguments for interactive wizard, or provide options directly.

    Examples:
        attacktrace scan                           # Interactive wizard
        attacktrace scan -c "Acme Corp"            # Quick scan with company name
        attacktrace scan -d example.com,example.org
    """
    if company or domains:
        # Direct mode - call discover with provided args
        ctx = typer.Context(discover)
        discover(
            company=company,
            domains=domains,
            ip_ranges=None,
            output=Path("./results"),
            modules=None,
            skip_modules=None,
            intensity="normal",
            passive_only=False,
            config_file=None,
            quiet=False,
        )
    else:
        # Interactive mode
        run_interactive_wizard()


@app.command()
def resume(
    session_id: str = typer.Argument(..., help="Session ID to resume"),
    config_file: Optional[Path] = typer.Option(
        None, "--config", "-C",
        help="Path to configuration file"
    ),
):
    """Resume a previous scan session."""
    print_banner()

    config = AttackTraceConfig.load(config_file)
    set_config(config)

    orchestrator = Orchestrator(config=config, console=console)
    session = orchestrator.load_session(session_id)

    if not session:
        console.print(f"[red]Session not found: {session_id}[/red]")
        raise typer.Exit(1)

    console.print(f"[green]Resuming session: {session_id}[/green]")
    console.print(f"Status: {session.status.value}")

    # Register modules and continue
    _register_modules(orchestrator)

    try:
        asyncio.run(orchestrator.run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted[/yellow]")
        orchestrator.cancel()
    finally:
        orchestrator.cleanup()

    _display_results_summary(session)


@app.command("list")
def list_sessions(
    status: Optional[str] = typer.Option(
        None, "--status", "-s",
        help="Filter by status (pending, running, completed, failed)"
    ),
    limit: int = typer.Option(20, "--limit", "-n", help="Maximum sessions to show"),
):
    """List all scan sessions."""
    # Find database files in results directory
    results_dir = Path("./results")
    if not results_dir.exists():
        console.print("[yellow]No results directory found[/yellow]")
        raise typer.Exit(0)

    table = Table(title="Scan Sessions", box=box.ROUNDED)
    table.add_column("ID", style="cyan")
    table.add_column("Target", style="white")
    table.add_column("Status", style="white")
    table.add_column("Domains", justify="right")
    table.add_column("IPs", justify="right")
    table.add_column("Findings", justify="right")
    table.add_column("Created", style="dim")

    session_count = 0
    for session_dir in sorted(results_dir.iterdir(), reverse=True):
        if not session_dir.is_dir():
            continue

        db_file = session_dir / "attacktrace.db"
        if not db_file.exists():
            continue

        try:
            db = Database(db_file)
            sessions = db.list_sessions(limit=1)
            db.close()

            for session in sessions:
                if status and session.status.value != status:
                    continue

                # Color code status
                status_style = {
                    "pending": "yellow",
                    "running": "blue",
                    "completed": "green",
                    "failed": "red",
                    "cancelled": "dim",
                }.get(session.status.value, "white")

                target = session.target_company or ", ".join(session.target_domains[:2])
                if len(target) > 30:
                    target = target[:27] + "..."

                findings_str = f"{session.critical_findings}C/{session.high_findings}H/{session.medium_findings}M"

                table.add_row(
                    session.id,
                    target,
                    f"[{status_style}]{session.status.value}[/{status_style}]",
                    str(session.total_domains + session.total_subdomains),
                    str(session.total_ips),
                    findings_str,
                    session.created_at.strftime("%Y-%m-%d %H:%M") if session.created_at else "-",
                )
                session_count += 1

                if session_count >= limit:
                    break

        except Exception:
            continue

        if session_count >= limit:
            break

    if session_count == 0:
        console.print("[yellow]No sessions found[/yellow]")
    else:
        console.print(table)


@app.command("hunt")
def hunt_resources(
    resources: str = typer.Argument(
        ...,
        help="Comma-separated resource types to hunt (e.g., s3,mongodb,redis)"
    ),
    company: Optional[str] = typer.Option(
        None, "--company", "-c",
        help="Target company name"
    ),
    domains: Optional[str] = typer.Option(
        None, "--domains", "-d",
        help="Comma-separated list of target domains"
    ),
    ips: Optional[str] = typer.Option(
        None, "--ips", "-i",
        help="Comma-separated list of IP addresses to scan"
    ),
    list_resources: bool = typer.Option(
        False, "--list", "-l",
        help="List all available resource types"
    ),
    config_file: Optional[Path] = typer.Option(
        None, "--config", "-C",
        help="Path to configuration file"
    ),
):
    """
    Hunt for specific resource types (S3, MongoDB, Redis, etc.)

    Examples:
        attacktrace hunt s3,firebase -c "Acme Corp"
        attacktrace hunt mongodb,redis,elasticsearch --ips 10.0.0.1,10.0.0.2
        attacktrace hunt jenkins,docker-registry -d acme.com
        attacktrace hunt --list  # Show all available resource types
    """
    from attacktrace.modules.targeted.resource_scanner import (
        TargetedResourceScanner,
        get_available_resources,
        get_resource_categories,
    )

    print_banner()

    # List available resources if requested
    if list_resources or resources == "list":
        console.print("\n[bold cyan]Available Resource Types[/bold cyan]\n")

        categories = get_resource_categories()
        all_resources = get_available_resources()

        for category, resource_keys in sorted(categories.items()):
            console.print(f"[bold yellow]{category.upper()}[/bold yellow]")
            for key in sorted(resource_keys):
                resource = all_resources[key]
                console.print(f"  [cyan]{key:20}[/cyan] - {resource.description}")
            console.print()

        console.print("[dim]Usage: attacktrace hunt <resource1>,<resource2> -c 'Company' -d domain.com[/dim]")
        raise typer.Exit(0)

    # Validate inputs
    if not company and not domains and not ips:
        console.print("[red]Error: At least one of --company, --domains, or --ips must be specified[/red]")
        raise typer.Exit(1)

    # Parse resource types
    resource_list = [r.strip().lower() for r in resources.split(",") if r.strip()]
    available = get_available_resources()

    invalid_resources = [r for r in resource_list if r not in available]
    if invalid_resources:
        console.print(f"[red]Unknown resource types: {', '.join(invalid_resources)}[/red]")
        console.print(f"[dim]Run 'attacktrace hunt --list' to see available types[/dim]")
        raise typer.Exit(1)

    # Load configuration
    config = AttackTraceConfig.load(config_file)
    set_config(config)

    # Parse inputs
    domain_list = [d.strip() for d in domains.split(",")] if domains else []
    ip_list = [i.strip() for i in ips.split(",")] if ips else []

    # Generate base names for cloud enumeration
    base_names = []
    if company:
        # Clean company name
        company_lower = company.lower()
        for suffix in [" inc", " llc", " ltd", " corp", " co"]:
            if company_lower.endswith(suffix):
                company_lower = company_lower[:-len(suffix)]
        base_names.append(company_lower)
        base_names.append(company_lower.replace(" ", "-"))
        base_names.append(company_lower.replace(" ", ""))

    for domain in domain_list:
        parts = domain.split(".")
        if len(parts) >= 2:
            base_names.append(parts[0])

    # Generate URLs from domains
    urls = []
    for domain in domain_list:
        urls.append(f"https://{domain}")
        urls.append(f"http://{domain}")

    # Display scan info
    console.print(f"\n[bold green]Targeted Resource Hunt[/bold green]")
    console.print(f"[cyan]Resources:[/cyan] {', '.join(resource_list)}")
    if company:
        console.print(f"[cyan]Company:[/cyan] {company}")
    if domain_list:
        console.print(f"[cyan]Domains:[/cyan] {', '.join(domain_list)}")
    if ip_list:
        console.print(f"[cyan]IPs:[/cyan] {', '.join(ip_list)}")
    console.print()

    # Run targeted scan
    scanner = TargetedResourceScanner(config, console)

    try:
        result = asyncio.run(scanner.scan(
            resources=resource_list,
            base_names=base_names,
            ips=ip_list,
            urls=urls,
        ))

        # Display results
        console.print(f"\n[bold green]{'═' * 50}[/bold green]")
        console.print(f"[bold green]Scan Complete[/bold green]")
        console.print(f"[bold green]{'═' * 50}[/bold green]\n")

        if result.cloud_assets:
            console.print(f"[cyan]Cloud Assets Found: {len(result.cloud_assets)}[/cyan]")
            for asset in result.cloud_assets:
                status = "[red]PUBLIC[/red]" if asset.is_public else "[green]Private[/green]"
                console.print(f"  • {asset.provider.value.upper()} {asset.asset_type.value}: {asset.name} - {status}")

        if result.ip_addresses:
            console.print(f"\n[cyan]Services Found: {len(result.ip_addresses)}[/cyan]")
            for ip in result.ip_addresses:
                for port in ip.ports:
                    console.print(f"  • {ip.address}:{port.number} - {port.service.name}")

        if result.findings:
            console.print(f"\n[bold yellow]Findings: {len(result.findings)}[/bold yellow]")

            # Group by severity
            by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
            for finding in result.findings:
                by_severity[finding.severity.value].append(finding)

            for severity in ["critical", "high", "medium", "low", "info"]:
                findings = by_severity[severity]
                if findings:
                    color = {"critical": "red", "high": "yellow", "medium": "blue", "low": "dim", "info": "dim"}[severity]
                    console.print(f"\n  [{color}]{severity.upper()} ({len(findings)})[/{color}]")
                    for finding in findings[:5]:  # Show top 5 per severity
                        console.print(f"    • {finding.title}")
                        if finding.evidence:
                            console.print(f"      [dim]{finding.evidence[:80]}...[/dim]" if len(finding.evidence) > 80 else f"      [dim]{finding.evidence}[/dim]")

        if not result.findings and not result.cloud_assets and not result.ip_addresses:
            console.print("[yellow]No resources found[/yellow]")

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted[/yellow]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def report(
    session_id: str = typer.Argument(..., help="Session ID to generate report for"),
    format: str = typer.Option(
        "cli", "--format", "-f",
        help="Output format: cli, json, csv, html"
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Output file path"
    ),
):
    """Generate a report for a scan session."""
    # Find the session database
    results_dir = Path("./results")
    db_file = results_dir / session_id / "attacktrace.db"

    if not db_file.exists():
        console.print(f"[red]Session not found: {session_id}[/red]")
        raise typer.Exit(1)

    db = Database(db_file)
    session = db.get_session(session_id)

    if not session:
        console.print(f"[red]Session data not found: {session_id}[/red]")
        raise typer.Exit(1)

    if format == "cli":
        _display_full_report(db, session)
    elif format == "json":
        import json
        data = db.export_session(session_id)
        if output:
            with open(output, "w") as f:
                json.dump(data, f, indent=2, default=str)
            console.print(f"[green]Report saved to: {output}[/green]")
        else:
            console.print_json(data=data)
    elif format == "csv":
        _export_csv(db, session, output)
    elif format == "html":
        # Save to reports folder by default
        if output:
            report_path = output
        else:
            reports_dir = Path("./reports")
            reports_dir.mkdir(parents=True, exist_ok=True)
            target_name = session.target_company or (session.target_domains[0] if session.target_domains else "scan")
            target_name = re.sub(r'[^\w\-]', '_', target_name)  # Sanitize filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_path = reports_dir / f"attacktrace_{target_name}_{timestamp}.html"
        _export_html(db, session, report_path)
    else:
        console.print(f"[red]Unknown format: {format}[/red]")
        raise typer.Exit(1)

    db.close()


@app.command()
def config(
    init: bool = typer.Option(False, "--init", help="Initialize a new config file"),
    show: bool = typer.Option(False, "--show", help="Show current configuration"),
    setup: bool = typer.Option(False, "--setup", "-s", help="Interactive API key setup wizard"),
    path: Path = typer.Option(
        Path("./config/config.yaml"), "--path", "-p",
        help="Config file path"
    ),
):
    """Manage AttackTrace configuration."""
    if setup:
        _run_api_key_setup(path)
    elif init:
        cfg = AttackTraceConfig()
        cfg.save(path)
        console.print(f"[green]Configuration file created: {path}[/green]")
        console.print("[dim]Run 'attacktrace config --setup' to add your API keys[/dim]")
    elif show:
        cfg = AttackTraceConfig.load()
        _display_config(cfg)
    else:
        console.print("Use --setup for interactive API key wizard, --init to create config, or --show to view")


def _display_config(cfg: AttackTraceConfig):
    """Display current configuration with masked API keys."""
    console.print("\n[bold cyan]━━━ Current Configuration ━━━[/bold cyan]\n")

    # API Keys
    console.print("[bold yellow]API Keys:[/bold yellow]")
    api_keys = [
        ("Shodan", cfg.api_keys.shodan),
        ("Censys ID", cfg.api_keys.censys_id),
        ("Censys Secret", cfg.api_keys.censys_secret),
        ("SecurityTrails", cfg.api_keys.securitytrails),
        ("VirusTotal", cfg.api_keys.virustotal),
        ("Hunter.io", cfg.api_keys.hunter),
        ("GitHub", cfg.api_keys.github),
        ("BinaryEdge", cfg.api_keys.binaryedge),
    ]

    for name, key in api_keys:
        if key:
            masked = key[:4] + "*" * (len(key) - 8) + key[-4:] if len(key) > 8 else "****"
            console.print(f"  [green]✓[/green] {name}: {masked}")
        else:
            console.print(f"  [dim]✗[/dim] {name}: [dim]Not configured[/dim]")

    # Scan settings
    console.print("\n[bold yellow]Scan Settings:[/bold yellow]")
    console.print(f"  Intensity: {cfg.scan.intensity}")
    console.print(f"  Threads: {cfg.scan.threads}")
    console.print(f"  Timeout: {cfg.scan.timeout}s")
    console.print(f"  Rate Limit: {cfg.scan.rate_limit}/s")

    console.print("\n[dim]Run 'attacktrace config --setup' to modify API keys[/dim]")


def _run_api_key_setup(config_path: Path):
    """Interactive API key setup wizard."""
    print_banner()

    console.print("\n[bold cyan]━━━ API Key Setup Wizard ━━━[/bold cyan]")
    console.print("[dim]Configure API keys for external services. Press Enter to skip any key.[/dim]\n")

    # Load existing config or create new
    if config_path.exists():
        cfg = AttackTraceConfig.load_from_file(config_path)
        console.print(f"[dim]Loading existing config from: {config_path}[/dim]\n")
    else:
        cfg = AttackTraceConfig()
        console.print(f"[dim]Creating new config at: {config_path}[/dim]\n")

    # Define API keys with descriptions and how to get them
    api_keys_info = [
        {
            "name": "Shodan",
            "attr": "shodan",
            "description": "Search engine for internet-connected devices",
            "features": "IP enrichment, service detection, vulnerability data",
            "url": "https://account.shodan.io/",
            "env_var": "SHODAN_API_KEY",
        },
        {
            "name": "Censys",
            "attr": "censys_id",
            "attr2": "censys_secret",
            "description": "Internet-wide scanning and certificate transparency",
            "features": "Certificate search, host discovery, TLS analysis",
            "url": "https://search.censys.io/account/api",
            "env_var": "CENSYS_API_ID / CENSYS_API_SECRET",
            "is_pair": True,
        },
        {
            "name": "SecurityTrails",
            "attr": "securitytrails",
            "description": "DNS and domain intelligence platform",
            "features": "Historical DNS, subdomain discovery, WHOIS history",
            "url": "https://securitytrails.com/app/account/credentials",
            "env_var": "SECURITYTRAILS_API_KEY",
        },
        {
            "name": "Hunter.io",
            "attr": "hunter",
            "description": "Email finder and verification service",
            "features": "Employee discovery, email patterns, contact info",
            "url": "https://hunter.io/api-keys",
            "env_var": "HUNTER_API_KEY",
        },
        {
            "name": "GitHub",
            "attr": "github",
            "description": "GitHub API for repository and user discovery",
            "features": "Org repos, commit emails, code search, leaked secrets",
            "url": "https://github.com/settings/tokens",
            "env_var": "GITHUB_TOKEN",
        },
        {
            "name": "VirusTotal",
            "attr": "virustotal",
            "description": "Malware and URL scanning service",
            "features": "Domain reputation, IP analysis, file scanning",
            "url": "https://www.virustotal.com/gui/my-apikey",
            "env_var": "VIRUSTOTAL_API_KEY",
        },
        {
            "name": "BinaryEdge",
            "attr": "binaryedge",
            "description": "Internet scanning and threat intelligence",
            "features": "Port scanning data, vulnerability detection",
            "url": "https://app.binaryedge.io/account/api",
            "env_var": "BINARYEDGE_API_KEY",
        },
        # Intelligence Platforms
        {
            "name": "URLScan.io",
            "attr": "urlscan",
            "description": "URL scanning and analysis service",
            "features": "Screenshots, DOM analysis, tech detection, network requests",
            "url": "https://urlscan.io/user/signup",
            "env_var": "URLSCAN_API_KEY",
        },
        {
            "name": "GreyNoise",
            "attr": "greynoise",
            "description": "Internet scanner and noise identification",
            "features": "Identify scanners, malicious IPs, benign crawlers",
            "url": "https://viz.greynoise.io/account/api-key",
            "env_var": "GREYNOISE_API_KEY",
        },
        {
            "name": "AlienVault OTX",
            "attr": "alienvault",
            "description": "Open Threat Exchange - threat intelligence",
            "features": "IOCs, threat pulses, malware associations",
            "url": "https://otx.alienvault.com/api",
            "env_var": "ALIENVAULT_API_KEY",
        },
        {
            "name": "IPinfo",
            "attr": "ipinfo",
            "description": "IP geolocation and ASN data",
            "features": "Geolocation, company detection, VPN/proxy detection",
            "url": "https://ipinfo.io/signup",
            "env_var": "IPINFO_TOKEN",
        },
        {
            "name": "BuiltWith",
            "attr": "builtwith",
            "description": "Technology profiling service",
            "features": "Detailed tech stack, frameworks, analytics, CMS",
            "url": "https://builtwith.com/",
            "env_var": "BUILTWITH_API_KEY",
        },
        {
            "name": "Chaos (ProjectDiscovery)",
            "attr": "chaos",
            "description": "Massive subdomain database",
            "features": "Subdomain discovery, bug bounty programs",
            "url": "https://chaos.projectdiscovery.io/",
            "env_var": "CHAOS_API_KEY",
        },
        {
            "name": "PassiveTotal",
            "attr": "passivetotal",
            "attr2": "passivetotal_user",
            "description": "RiskIQ PassiveTotal - passive DNS and WHOIS",
            "features": "Passive DNS, WHOIS history, certificates, trackers",
            "url": "https://community.riskiq.com/",
            "env_var": "PASSIVETOTAL_API_KEY / PASSIVETOTAL_USER",
            "is_pair": True,
        },
        # Breach Checking
        {
            "name": "HaveIBeenPwned",
            "attr": "hibp",
            "description": "Breach notification service",
            "features": "Check if emails appear in data breaches",
            "url": "https://haveibeenpwned.com/API/Key",
            "env_var": "HIBP_API_KEY",
        },
        {
            "name": "DeHashed",
            "attr": "dehashed",
            "attr2": "dehashed_email",
            "description": "Breach database with credentials",
            "features": "Search breaches for emails, passwords, usernames",
            "url": "https://dehashed.com/",
            "env_var": "DEHASHED_API_KEY / DEHASHED_EMAIL",
            "is_pair": True,
        },
        {
            "name": "LeakCheck",
            "attr": "leakcheck",
            "description": "Credential leak checking",
            "features": "Check emails in breach databases",
            "url": "https://leakcheck.io/",
            "env_var": "LEAKCHECK_API_KEY",
        },
        {
            "name": "Intelligence X",
            "attr": "intelx",
            "description": "Dark web and breach intelligence",
            "features": "Paste sites, dark web, breach data",
            "url": "https://intelx.io/",
            "env_var": "INTELX_API_KEY",
        },
    ]

    changes_made = False

    for key_info in api_keys_info:
        console.print(f"\n[bold yellow]━━━ {key_info['name']} ━━━[/bold yellow]")
        console.print(f"[dim]{key_info['description']}[/dim]")
        console.print(f"[cyan]Features:[/cyan] {key_info['features']}")
        console.print(f"[cyan]Get key at:[/cyan] {key_info['url']}")
        console.print(f"[cyan]Env var:[/cyan] {key_info['env_var']}")

        # Show current value if set
        current_value = getattr(cfg.api_keys, key_info['attr'], "")
        if current_value:
            masked = current_value[:4] + "*" * 8 + current_value[-4:] if len(current_value) > 8 else "****"
            console.print(f"[green]Current:[/green] {masked}")

        if key_info.get('is_pair'):
            # Handle Censys which has ID and Secret
            api_id = Prompt.ask(
                f"\n[cyan]{key_info['name']} API ID[/cyan]",
                default=getattr(cfg.api_keys, key_info['attr'], "") or "",
                password=False,
            )
            api_secret = Prompt.ask(
                f"[cyan]{key_info['name']} API Secret[/cyan]",
                default=getattr(cfg.api_keys, key_info['attr2'], "") or "",
                password=True,
            )

            if api_id:
                setattr(cfg.api_keys, key_info['attr'], api_id)
                changes_made = True
            if api_secret:
                setattr(cfg.api_keys, key_info['attr2'], api_secret)
                changes_made = True
        else:
            # Single key
            new_value = Prompt.ask(
                f"\n[cyan]API Key[/cyan]",
                default=current_value or "",
                password=True,
            )

            if new_value and new_value != current_value:
                setattr(cfg.api_keys, key_info['attr'], new_value)
                changes_made = True
            elif new_value:
                # Keep existing
                pass

    # Scan settings
    console.print("\n[bold yellow]━━━ Scan Settings ━━━[/bold yellow]")

    if Confirm.ask("\n[cyan]Configure scan settings?[/cyan]", default=False):
        console.print("\n[cyan]Scan Intensity:[/cyan]")
        console.print("  [dim]1)[/dim] passive    - OSINT only, no direct contact with targets")
        console.print("  [dim]2)[/dim] normal     - Balanced scanning with rate limiting")
        console.print("  [dim]3)[/dim] aggressive - Fast scanning, more network noise")

        intensity = Prompt.ask(
            "[cyan]Select intensity[/cyan]",
            choices=["1", "2", "3", "passive", "normal", "aggressive"],
            default="2",
        )
        intensity_map = {"1": "passive", "2": "normal", "3": "aggressive"}
        cfg.scan.intensity = intensity_map.get(intensity, intensity)

        threads = Prompt.ask(
            "[cyan]Concurrent threads[/cyan]",
            default=str(cfg.scan.threads),
        )
        if threads.isdigit():
            cfg.scan.threads = int(threads)

        timeout = Prompt.ask(
            "[cyan]Request timeout (seconds)[/cyan]",
            default=str(cfg.scan.timeout),
        )
        if timeout.isdigit():
            cfg.scan.timeout = int(timeout)

        changes_made = True

    # Save configuration
    if changes_made or not config_path.exists():
        console.print("\n[bold yellow]━━━ Save Configuration ━━━[/bold yellow]")

        if Confirm.ask(f"\n[cyan]Save configuration to {config_path}?[/cyan]", default=True):
            config_path.parent.mkdir(parents=True, exist_ok=True)
            cfg.save(config_path)
            console.print(f"\n[bold green]✓ Configuration saved to: {config_path}[/bold green]")

            # Also offer to set environment variables
            console.print("\n[dim]Tip: You can also set API keys via environment variables:[/dim]")
            for key_info in api_keys_info:
                console.print(f"  [dim]export {key_info['env_var']}=your_key[/dim]")
        else:
            console.print("[yellow]Configuration not saved.[/yellow]")
    else:
        console.print("\n[dim]No changes made.[/dim]")

    # Summary
    console.print("\n[bold cyan]━━━ Configuration Summary ━━━[/bold cyan]")
    _display_config(cfg)

    console.print("\n[bold green]Setup complete![/bold green]")
    console.print("Run [cyan]attacktrace scan[/cyan] to start a discovery scan.")


@app.command()
def setup():
    """Interactive setup wizard for API keys and configuration."""
    _run_api_key_setup(Path("./config/config.yaml"))


@app.command()
def version():
    """Show AttackTrace version."""
    console.print(f"AttackTrace version {__version__}")


def _register_modules(orchestrator: Orchestrator) -> None:
    """Register all discovery modules with the orchestrator."""
    # Import and register modules
    from attacktrace.modules.seed.cert_transparency import run as cert_transparency_run
    from attacktrace.modules.seed.whois_lookup import run as whois_run
    from attacktrace.modules.seed.asn_discovery import run as asn_run
    from attacktrace.modules.domain.subdomain_enum import run as subdomain_run
    from attacktrace.modules.domain.dns_resolver import run as dns_run
    from attacktrace.modules.infrastructure.port_scanner import run as port_scan_run
    from attacktrace.modules.enrichment.shodan_client import run as shodan_run
    from attacktrace.modules.enrichment.censys_client import run as censys_run
    from attacktrace.modules.enrichment.securitytrails_client import run as securitytrails_run
    from attacktrace.modules.web.http_prober import run as http_probe_run
    from attacktrace.modules.web.screenshot import run as screenshot_run
    from attacktrace.modules.cloud.cloud_enum import run as cloud_enum_run
    from attacktrace.correlation.correlator import run as correlator_run

    orchestrator.register_module("seed", _combined_seed_module)
    orchestrator.register_module("domain", subdomain_run)
    orchestrator.register_module("dns", dns_run)
    orchestrator.register_module("infrastructure", port_scan_run)
    orchestrator.register_module("enrichment", _combined_enrichment_module)
    orchestrator.register_module("intel", _combined_intel_module)
    orchestrator.register_module("osint", _combined_osint_module)
    orchestrator.register_module("web", _combined_web_module)
    orchestrator.register_module("cloud", cloud_enum_run)
    orchestrator.register_module("correlation", correlator_run)


async def _combined_seed_module(session, config, orchestrator):
    """Combined seed module that runs WHOIS, cert transparency, and ASN discovery."""
    from attacktrace.modules.seed.cert_transparency import run as cert_run
    from attacktrace.modules.seed.whois_lookup import run as whois_run
    from attacktrace.modules.seed.asn_discovery import run as asn_run
    from attacktrace.core.models import ModuleResult

    result = ModuleResult(module_name="seed")

    # Run WHOIS lookup
    whois_result = await whois_run(session, config, orchestrator)
    if whois_result:
        result.domains.extend(whois_result.domains)

    # Run certificate transparency
    cert_result = await cert_run(session, config, orchestrator)
    if cert_result:
        result.subdomains.extend(cert_result.subdomains)
        result.certificates.extend(cert_result.certificates)

    # Run ASN discovery
    asn_result = await asn_run(session, config, orchestrator)
    if asn_result:
        result.ip_addresses.extend(asn_result.ip_addresses)
        result.findings.extend(asn_result.findings)

    result.items_discovered = len(result.domains) + len(result.subdomains) + len(result.ip_addresses)
    return result


async def _combined_enrichment_module(session, config, orchestrator):
    """Combined enrichment module that runs Shodan, Censys, and SecurityTrails."""
    from attacktrace.modules.enrichment.shodan_client import run as shodan_run
    from attacktrace.modules.enrichment.censys_client import run as censys_run
    from attacktrace.modules.enrichment.securitytrails_client import run as securitytrails_run
    from attacktrace.core.models import ModuleResult

    result = ModuleResult(module_name="enrichment")

    # Run Shodan enrichment
    if config.api_keys.shodan:
        shodan_result = await shodan_run(session, config, orchestrator)
        if shodan_result:
            result.ip_addresses.extend(shodan_result.ip_addresses)
            result.findings.extend(shodan_result.findings)

    # Run Censys enrichment
    if config.api_keys.censys_id and config.api_keys.censys_secret:
        censys_result = await censys_run(session, config, orchestrator)
        if censys_result:
            result.ip_addresses.extend(censys_result.ip_addresses)
            result.certificates.extend(censys_result.certificates)
            result.findings.extend(censys_result.findings)

    # Run SecurityTrails enrichment
    if config.api_keys.securitytrails:
        st_result = await securitytrails_run(session, config, orchestrator)
        if st_result:
            result.domains.extend(st_result.domains)
            result.subdomains.extend(st_result.subdomains)
            result.ip_addresses.extend(st_result.ip_addresses)

    result.items_discovered = len(result.ip_addresses) + len(result.subdomains)
    return result


async def _combined_web_module(session, config, orchestrator):
    """Combined web module that runs HTTP probing and screenshots."""
    from attacktrace.modules.web.http_prober import run as http_probe_run
    from attacktrace.modules.web.screenshot import capture_screenshot, check_screenshot_capabilities
    from attacktrace.core.models import ModuleResult
    from pathlib import Path
    import asyncio

    result = ModuleResult(module_name="web")

    # Run HTTP probing first
    http_result = await http_probe_run(session, config, orchestrator)
    if http_result:
        result.web_applications.extend(http_result.web_applications)
        result.certificates.extend(http_result.certificates)
        result.findings.extend(http_result.findings)

    # Update session with web applications for screenshot module
    session.web_applications = result.web_applications.copy()

    # Run screenshot capture
    if config.modules.web.screenshot and result.web_applications:
        # Check available screenshot methods
        capabilities = check_screenshot_capabilities()

        if not any(capabilities.values()):
            if orchestrator.console:
                orchestrator.console.print(
                    "[yellow]Screenshot capture unavailable. Install one of:[/yellow]\n"
                    "  • Playwright: [cyan]pip install playwright && playwright install chromium[/cyan]\n"
                    "  • Chrome/Chromium browser\n"
                    "  • gowitness: [cyan]go install github.com/sensepost/gowitness@latest[/cyan]"
                )
        else:
            screenshots_dir = config.get_screenshots_dir(session.id)
            screenshots_dir.mkdir(parents=True, exist_ok=True)

            if orchestrator.console:
                methods = [k for k, v in capabilities.items() if v]
                orchestrator.console.print(f"[cyan]Capturing screenshots using: {', '.join(methods)}[/cyan]")

            # Capture screenshots directly for each live web application
            semaphore = asyncio.Semaphore(4)
            live_apps = [app for app in result.web_applications if app.is_alive and app.status_code in range(200, 500)]

            async def capture_for_webapp(webapp):
                async with semaphore:
                    url = webapp.final_url or webapp.url
                    try:
                        screenshot_path = await capture_screenshot(
                            url,
                            screenshots_dir,
                            config.modules.web.screenshot_timeout,
                        )
                        if screenshot_path:
                            webapp.screenshot_path = screenshot_path
                    except Exception as e:
                        pass
                    return webapp

            if live_apps:
                if orchestrator.console:
                    orchestrator.console.print(f"[cyan]Screenshotting {len(live_apps)} live web applications...[/cyan]")

                # Capture all screenshots concurrently
                await asyncio.gather(
                    *[capture_for_webapp(app) for app in live_apps],
                    return_exceptions=True
                )

                # Count successful screenshots
                screenshot_count = sum(1 for app in result.web_applications if app.screenshot_path)
                if orchestrator.console:
                    orchestrator.console.print(f"[green]Captured {screenshot_count} screenshots[/green]")

    result.items_discovered = len(result.web_applications)
    result.success = True
    return result


async def _combined_intel_module(session, config, orchestrator):
    """Combined intelligence module for threat intel and breach checking."""
    from attacktrace.core.models import ModuleResult

    result = ModuleResult(module_name="intel")

    # Shodan InternetDB (free, no auth) - CVEs and ports
    try:
        from attacktrace.modules.intel.shodan_internetdb import run as internetdb_run
        internetdb_result = await internetdb_run(session, config, orchestrator)
        if internetdb_result:
            result.findings.extend(internetdb_result.findings)
            result.items_discovered += internetdb_result.items_discovered
    except Exception:
        pass

    # Wayback Machine (free) - historical URLs
    try:
        from attacktrace.modules.intel.wayback import run as wayback_run
        wayback_result = await wayback_run(session, config, orchestrator)
        if wayback_result:
            result.findings.extend(wayback_result.findings)
            result.items_discovered += wayback_result.items_discovered
    except Exception:
        pass

    # AlienVault OTX (free) - threat intel
    try:
        from attacktrace.modules.intel.alienvault_otx import run as otx_run
        otx_result = await otx_run(session, config, orchestrator)
        if otx_result:
            result.findings.extend(otx_result.findings)
            result.items_discovered += otx_result.items_discovered
    except Exception:
        pass

    # URLScan.io
    if config.api_keys.urlscan:
        try:
            from attacktrace.modules.intel.urlscan import run as urlscan_run
            urlscan_result = await urlscan_run(session, config, orchestrator)
            if urlscan_result:
                result.findings.extend(urlscan_result.findings)
                result.items_discovered += urlscan_result.items_discovered
        except Exception:
            pass

    # GreyNoise
    try:
        from attacktrace.modules.intel.greynoise import run as greynoise_run
        greynoise_result = await greynoise_run(session, config, orchestrator)
        if greynoise_result:
            result.findings.extend(greynoise_result.findings)
            result.items_discovered += greynoise_result.items_discovered
    except Exception:
        pass

    # IPinfo
    if config.api_keys.ipinfo:
        try:
            from attacktrace.modules.intel.ipinfo import run as ipinfo_run
            ipinfo_result = await ipinfo_run(session, config, orchestrator)
            if ipinfo_result:
                result.findings.extend(ipinfo_result.findings)
                result.items_discovered += ipinfo_result.items_discovered
        except Exception:
            pass

    # Chaos (ProjectDiscovery)
    if config.api_keys.chaos:
        try:
            from attacktrace.modules.intel.chaos_projectdiscovery import run as chaos_run
            chaos_result = await chaos_run(session, config, orchestrator)
            if chaos_result:
                result.subdomains.extend(chaos_result.subdomains)
                result.findings.extend(chaos_result.findings)
                result.items_discovered += chaos_result.items_discovered
        except Exception:
            pass

    # PassiveTotal
    if config.api_keys.passivetotal:
        try:
            from attacktrace.modules.intel.passivetotal import run as pt_run
            pt_result = await pt_run(session, config, orchestrator)
            if pt_result:
                result.subdomains.extend(pt_result.subdomains)
                result.findings.extend(pt_result.findings)
                result.items_discovered += pt_result.items_discovered
        except Exception:
            pass

    # BuiltWith
    try:
        from attacktrace.modules.intel.builtwith import run as builtwith_run
        builtwith_result = await builtwith_run(session, config, orchestrator)
        if builtwith_result:
            result.findings.extend(builtwith_result.findings)
            result.items_discovered += builtwith_result.items_discovered
    except Exception:
        pass

    # Breach checking (after OSINT has gathered emails)
    if config.api_keys.hibp or config.api_keys.dehashed or config.api_keys.leakcheck:
        try:
            from attacktrace.modules.intel.breach_check import run as breach_run
            breach_result = await breach_run(session, config, orchestrator)
            if breach_result:
                result.findings.extend(breach_result.findings)
                result.items_discovered += breach_result.items_discovered
        except Exception:
            pass

    return result


async def _combined_osint_module(session, config, orchestrator):
    """Combined OSINT module that runs GitHub recon and employee discovery."""
    from attacktrace.modules.osint.github_recon import run as github_run
    from attacktrace.modules.osint.employee_discovery import run as employee_run
    from attacktrace.core.models import ModuleResult

    result = ModuleResult(module_name="osint")

    # Run GitHub reconnaissance
    github_result = await github_run(session, config, orchestrator)
    if github_result:
        result.findings.extend(github_result.findings)
        result.items_discovered += github_result.items_discovered

    # Run employee discovery (benefits from GitHub data)
    employee_result = await employee_run(session, config, orchestrator)
    if employee_result:
        result.findings.extend(employee_result.findings)
        result.items_discovered += employee_result.items_discovered

    return result


def _display_target_info(session, company, domains, ip_ranges):
    """Display target information."""
    table = Table(title="Target Information", box=box.ROUNDED)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="white")

    if company:
        table.add_row("Company", company)
    if domains:
        table.add_row("Domains", ", ".join(domains))
    if ip_ranges:
        table.add_row("IP Ranges", ", ".join(ip_ranges))
    table.add_row("Session ID", session.id)
    table.add_row("Mode", "Passive Only" if session.passive_only else session.intensity.capitalize())

    console.print(table)
    console.print()


def _display_results_summary(session):
    """Display a summary of scan results."""
    session.update_statistics()

    console.print("\n")

    # Summary panel
    summary = Table(box=box.ROUNDED, show_header=False)
    summary.add_column("Metric", style="cyan")
    summary.add_column("Count", justify="right", style="bold")

    summary.add_row("Domains", str(session.total_domains))
    summary.add_row("Subdomains", str(session.total_subdomains))
    summary.add_row("IP Addresses", str(session.total_ips))
    summary.add_row("Open Ports", str(session.total_ports))
    summary.add_row("Web Applications", str(session.total_web_apps))
    summary.add_row("Cloud Assets", str(session.total_cloud_assets))

    console.print(Panel(summary, title="Discovery Summary", border_style="green"))

    # Findings panel
    if session.total_findings > 0:
        findings_table = Table(box=box.ROUNDED, show_header=False)
        findings_table.add_column("Severity", style="white")
        findings_table.add_column("Count", justify="right")

        findings_table.add_row("[red]Critical[/red]", str(session.critical_findings))
        findings_table.add_row("[orange1]High[/orange1]", str(session.high_findings))
        findings_table.add_row("[yellow]Medium[/yellow]", str(session.medium_findings))
        findings_table.add_row("[blue]Low[/blue]", str(session.low_findings))

        console.print(Panel(findings_table, title="Findings", border_style="red"))


def _display_full_report(db: Database, session):
    """Display a full CLI report."""
    console.print(f"\n[bold]Report for Session: {session.id}[/bold]\n")

    _display_results_summary(session)

    # Domains
    domains = db.get_domains(session.id)
    if domains:
        console.print("\n[bold cyan]Domains:[/bold cyan]")
        for domain in domains:
            console.print(f"  - {domain.fqdn}")

    # Top subdomains
    subdomains = db.get_subdomains(session.id)
    if subdomains:
        console.print(f"\n[bold cyan]Subdomains ({len(subdomains)} total):[/bold cyan]")
        for subdomain in subdomains[:20]:
            status = "[green]alive[/green]" if subdomain.is_alive else "[dim]unknown[/dim]"
            console.print(f"  - {subdomain.fqdn} {status}")
        if len(subdomains) > 20:
            console.print(f"  ... and {len(subdomains) - 20} more")

    # IP Addresses with open ports
    ips = db.get_ip_addresses(session.id)
    if ips:
        console.print(f"\n[bold cyan]IP Addresses ({len(ips)} total):[/bold cyan]")
        for ip in ips[:15]:
            ports_str = ", ".join(str(p.number) for p in ip.ports[:5])
            if ip.ports:
                console.print(f"  - {ip.address} [{ports_str}]")
            else:
                console.print(f"  - {ip.address}")
        if len(ips) > 15:
            console.print(f"  ... and {len(ips) - 15} more")

    # Findings
    findings = db.get_findings(session.id)
    if findings:
        console.print(f"\n[bold cyan]Findings ({len(findings)} total):[/bold cyan]")

        for finding in sorted(findings, key=lambda f: ["critical", "high", "medium", "low", "info"].index(f.severity.value)):
            severity_colors = {
                "critical": "red",
                "high": "orange1",
                "medium": "yellow",
                "low": "blue",
                "info": "dim",
            }
            color = severity_colors.get(finding.severity.value, "white")
            console.print(f"  [{color}][{finding.severity.value.upper()}][/{color}] {finding.title}")
            console.print(f"    [dim]{finding.description[:100]}...[/dim]" if len(finding.description) > 100 else f"    [dim]{finding.description}[/dim]")


def _export_csv(db: Database, session, output: Optional[Path]):
    """Export data to CSV files."""
    import csv

    base_path = output or Path(f"export_{session.id}")
    base_path.mkdir(parents=True, exist_ok=True)

    # Export subdomains
    subdomains = db.get_subdomains(session.id)
    with open(base_path / "subdomains.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["FQDN", "Parent Domain", "Resolved IPs", "Is Alive", "HTTP Status"])
        for s in subdomains:
            writer.writerow([s.fqdn, s.parent_domain, ",".join(s.resolved_ips), s.is_alive, s.http_status])

    # Export IPs
    ips = db.get_ip_addresses(session.id)
    with open(base_path / "ip_addresses.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Address", "ASN", "ASN Org", "Open Ports", "Cloud Provider"])
        for ip in ips:
            ports = ",".join(str(p.number) for p in ip.ports if p.state.value == "open")
            writer.writerow([ip.address, ip.asn, ip.asn_org, ports, ip.cloud_provider])

    # Export findings
    findings = db.get_findings(session.id)
    with open(base_path / "findings.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Severity", "Title", "Description", "Affected Asset", "Category"])
        for finding in findings:
            writer.writerow([finding.severity.value, finding.title, finding.description, finding.affected_asset, finding.category])

    console.print(f"[green]CSV files exported to: {base_path}[/green]")


def _export_html(db: Database, session, output: Path):
    """Export data to professional HTML report with embedded screenshots."""
    from jinja2 import Template
    from datetime import datetime
    from collections import Counter
    import base64
    from attacktrace.reporting.html_template import HTML_TEMPLATE

    template = Template(HTML_TEMPLATE)
    session.update_statistics()

    # Get all data
    subdomains = db.get_subdomains(session.id)
    ips = db.get_ip_addresses(session.id)
    webapps = db.get_web_applications(session.id)
    findings = db.get_findings(session.id)
    cloud_assets = db.get_cloud_assets(session.id)

    # Load and embed screenshots as base64
    for webapp in webapps:
        if webapp.screenshot_path and Path(webapp.screenshot_path).exists():
            try:
                with open(webapp.screenshot_path, "rb") as img_file:
                    webapp.screenshot_base64 = base64.b64encode(img_file.read()).decode('utf-8')
            except Exception:
                pass  # Skip if we can't read the screenshot

    # Sort findings by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings_sorted = sorted(findings, key=lambda f: severity_order.get(f.severity.value, 5))

    # Build technology summary
    tech_counter = Counter()
    for webapp in webapps:
        for tech in webapp.technologies:
            tech_counter[tech.name] += 1

    # Get OSINT data from session
    github_data = getattr(session, 'github_data', {}) or {}
    employee_data = getattr(session, 'employee_data', {}) or {}

    github_repos = github_data.get('repos', [])
    github_users = github_data.get('users', [])
    github_emails = github_data.get('emails', [])
    employees = employee_data.get('employees', [])
    email_pattern = employee_data.get('email_pattern', '')

    # Target name
    target = session.target_company or (session.target_domains[0] if session.target_domains else "Unknown")

    # Count screenshots
    screenshots_count = sum(1 for w in webapps if w.screenshot_base64 or w.screenshot_path)

    html = template.render(
        target=target,
        session_id=session.id,
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        stats={
            "domains": session.total_domains,
            "subdomains": len(subdomains),
            "ips": len(ips),
            "ports": session.total_ports,
            "webapps": len(webapps),
            "screenshots": screenshots_count,
            "cloud": len(cloud_assets),
            "findings": len(findings),
            "critical": sum(1 for f in findings if f.severity.value == "critical"),
            "high": sum(1 for f in findings if f.severity.value == "high"),
            "medium": sum(1 for f in findings if f.severity.value == "medium"),
            "low": sum(1 for f in findings if f.severity.value == "low"),
        },
        findings=findings_sorted,
        subdomains=subdomains,
        ips=ips,
        webapps=webapps,
        cloud_assets=cloud_assets,
        tech_summary=dict(tech_counter.most_common(20)),
        # OSINT data
        github_repos=github_repos,
        github_users=github_users,
        github_emails=github_emails,
        employees=employees,
        email_pattern=email_pattern,
    )

    with open(output, "w") as f:
        f.write(html)

    console.print(f"[green]HTML report saved to: {output}[/green]")


if __name__ == "__main__":
    app()
