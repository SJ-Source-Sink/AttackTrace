"""
Port scanning module.

Discovers open ports and services using multiple methods:
- Socket-based scanning (built-in)
- Masscan integration (if available)
- Nmap integration (if available)
"""

import asyncio
import shutil
import socket
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional
import re

from attacktrace.config import AttackTraceConfig
from attacktrace.core.models import (
    ModuleResult,
    IPAddress,
    Port,
    Service,
    PortState,
    Finding,
    Severity,
    ScanSession,
)


# Common ports for quick scan - expanded for infrastructure discovery
TOP_PORTS = [
    # File Transfer
    20, 21,        # FTP data/control
    22,            # SSH/SFTP
    69,            # TFTP
    115,           # SFTP (legacy)
    873,           # rsync
    990, 989,      # FTPS implicit

    # Web
    80, 443,       # HTTP/HTTPS
    8080, 8443,    # HTTP alt/HTTPS alt
    8000, 8888,    # Common dev servers
    9000, 9090,    # Various web admin
    3000, 5000,    # Node.js/Flask dev

    # Email
    25, 465, 587,  # SMTP/SMTPS
    110, 995,      # POP3/POP3S
    143, 993,      # IMAP/IMAPS

    # Databases
    1433,          # MSSQL
    1521,          # Oracle
    3306,          # MySQL
    5432,          # PostgreSQL
    6379,          # Redis
    9200, 9300,    # Elasticsearch
    27017, 27018,  # MongoDB
    11211,         # Memcached
    5984,          # CouchDB
    7474,          # Neo4j
    8529,          # ArangoDB
    28015,         # RethinkDB

    # Remote Access
    23,            # Telnet
    3389,          # RDP
    5900, 5901,    # VNC
    5985, 5986,    # WinRM
    2222,          # SSH alt

    # Network Services
    53,            # DNS
    67, 68,        # DHCP
    88,            # Kerberos
    111,           # RPC
    123,           # NTP
    135,           # MSRPC
    137, 138, 139, # NetBIOS
    161, 162,      # SNMP
    389, 636,      # LDAP/LDAPS
    445,           # SMB/CIFS
    500, 4500,     # IPSec/IKE
    514,           # Syslog
    1194,          # OpenVPN
    1701,          # L2TP
    1723,          # PPTP

    # Storage/File Sharing
    2049,          # NFS
    3260,          # iSCSI

    # Message Queues
    5672, 5671,    # RabbitMQ (AMQP)
    9092,          # Kafka
    61616,         # ActiveMQ

    # Container/Orchestration
    2375, 2376,    # Docker
    2379, 2380,    # etcd
    6443,          # Kubernetes API
    10250,         # Kubelet

    # CI/CD & DevOps
    8081,          # Nexus
    8082,          # Artifactory
    9418,          # Git

    # Admin Interfaces
    10000,         # Webmin
    10443,         # Various admin
    7001, 7002,    # WebLogic
    8009,          # AJP
    9043, 9060,    # WebSphere

    # Misc
    1099,          # Java RMI
    1883, 8883,    # MQTT
    4444,          # Metasploit (check for compromise)
    5044,          # Logstash Beats
    8161,          # ActiveMQ Web Console
]

# Legacy alias
TOP_100_PORTS = TOP_PORTS

# Service signatures for banner grabbing
SERVICE_SIGNATURES = {
    b"SSH-": "ssh",
    b"220 ": "ftp/smtp",
    b"HTTP/": "http",
    b"* OK": "imap",
    b"+OK": "pop3",
    b"MySQL": "mysql",
    b"PostgreSQL": "postgresql",
    b"MongoDB": "mongodb",
    b"Redis": "redis",
    b"220-": "ftp",
    b"-ERR": "redis",
    b"AMQP": "amqp",
    b"RFB ": "vnc",
    b"Memcached": "memcached",
    b"couchdb": "couchdb",
    b"elasticsearch": "elasticsearch",
    b"OpenSSH": "ssh",
    b"vsftpd": "ftp",
    b"ProFTPD": "ftp",
    b"Pure-FTPd": "ftp",
    b"FileZilla": "ftp",
    b"Microsoft FTP": "ftp",
    b"Serv-U": "ftp",
    b"220 Microsoft": "ftp",
    b"SFTP": "sftp",
}


async def tcp_connect_scan(
    ip: str,
    port: int,
    timeout: float = 3.0,
) -> tuple[bool, str]:
    """
    Perform TCP connect scan on a single port.

    Returns:
        Tuple of (is_open, banner)
    """
    banner = ""

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )

        # Try to grab banner
        try:
            writer.write(b"\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            banner = data.decode("utf-8", errors="ignore").strip()
        except Exception:
            pass

        writer.close()
        await writer.wait_closed()
        return True, banner

    except asyncio.TimeoutError:
        return False, ""
    except ConnectionRefusedError:
        return False, ""
    except OSError:
        return False, ""
    except Exception:
        return False, ""


def identify_service(port: int, banner: str) -> Service:
    """Identify service based on port number and banner."""
    service = Service(name="unknown")

    # Check banner signatures
    banner_bytes = banner.encode() if banner else b""
    for signature, service_name in SERVICE_SIGNATURES.items():
        if signature in banner_bytes:
            service.name = service_name
            service.banner = banner
            break

    # Fall back to well-known ports
    if service.name == "unknown":
        port_services = {
            # File Transfer
            20: "ftp-data",
            21: "ftp",
            22: "ssh/sftp",
            69: "tftp",
            115: "sftp",
            873: "rsync",
            989: "ftps-data",
            990: "ftps",

            # Web
            80: "http",
            443: "https",
            3000: "http-dev",
            5000: "http-dev",
            8000: "http-alt",
            8080: "http-proxy",
            8443: "https-alt",
            8888: "http-alt",
            9000: "http-alt",
            9090: "http-admin",

            # Email
            25: "smtp",
            110: "pop3",
            143: "imap",
            465: "smtps",
            587: "submission",
            993: "imaps",
            995: "pop3s",

            # Databases
            1433: "mssql",
            1521: "oracle",
            3306: "mysql",
            5432: "postgresql",
            5984: "couchdb",
            6379: "redis",
            7474: "neo4j",
            8529: "arangodb",
            9200: "elasticsearch",
            9300: "elasticsearch-cluster",
            11211: "memcached",
            27017: "mongodb",
            27018: "mongodb",
            28015: "rethinkdb",

            # Remote Access
            23: "telnet",
            2222: "ssh-alt",
            3389: "rdp",
            5900: "vnc",
            5901: "vnc",
            5985: "winrm-http",
            5986: "winrm-https",

            # Network Services
            53: "dns",
            67: "dhcp-server",
            68: "dhcp-client",
            88: "kerberos",
            111: "rpcbind",
            123: "ntp",
            135: "msrpc",
            137: "netbios-ns",
            138: "netbios-dgm",
            139: "netbios-ssn",
            161: "snmp",
            162: "snmptrap",
            389: "ldap",
            445: "smb",
            500: "isakmp",
            514: "syslog",
            636: "ldaps",
            1194: "openvpn",
            1701: "l2tp",
            1723: "pptp",
            4500: "ipsec-nat-t",

            # Storage
            2049: "nfs",
            3260: "iscsi",

            # Message Queues
            5671: "amqps",
            5672: "amqp",
            9092: "kafka",
            61616: "activemq",

            # Containers
            2375: "docker",
            2376: "docker-tls",
            2379: "etcd",
            2380: "etcd-peer",
            6443: "kubernetes-api",
            10250: "kubelet",

            # CI/CD
            8081: "nexus",
            8082: "artifactory",
            9418: "git",

            # Admin
            7001: "weblogic",
            7002: "weblogic-ssl",
            8009: "ajp",
            9043: "websphere-admin",
            9060: "websphere-admin-ssl",
            10000: "webmin",

            # Misc
            1099: "java-rmi",
            1883: "mqtt",
            4444: "metasploit",
            5044: "logstash",
            8161: "activemq-admin",
            8883: "mqtt-tls",
        }
        service.name = port_services.get(port, "unknown")

    # Extract version from banner if possible
    if banner:
        service.banner = banner[:500]  # Limit banner size

        # Try to extract version
        version_patterns = [
            r"(\d+\.\d+\.\d+)",
            r"(\d+\.\d+)",
            r"version\s+(\S+)",
        ]
        for pattern in version_patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                service.version = match.group(1)
                break

    return service


async def scan_ip_ports(
    ip: str,
    ports: list[int],
    timeout: float = 3.0,
    concurrency: int = 100,
) -> list[Port]:
    """Scan multiple ports on a single IP."""
    open_ports = []
    semaphore = asyncio.Semaphore(concurrency)

    async def scan_port(port: int):
        async with semaphore:
            is_open, banner = await tcp_connect_scan(ip, port, timeout)
            if is_open:
                service = identify_service(port, banner)
                return Port(
                    number=port,
                    protocol="tcp",
                    state=PortState.OPEN,
                    service=service,
                )
            return None

    tasks = [scan_port(p) for p in ports]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, Port):
            open_ports.append(result)

    return open_ports


async def run_masscan(
    ips: list[str],
    ports: str = "1-65535",
    rate: int = 1000,
    timeout: int = 300,
) -> dict[str, list[int]]:
    """
    Run masscan if available.

    Returns:
        Dictionary mapping IP addresses to lists of open ports
    """
    results: dict[str, list[int]] = {}

    if not shutil.which("masscan"):
        return results

    # Create temporary file for targets
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        for ip in ips:
            f.write(f"{ip}\n")
        targets_file = f.name

    # Create temporary file for output
    output_file = tempfile.mktemp(suffix=".txt")

    try:
        proc = await asyncio.create_subprocess_exec(
            "masscan",
            "-iL", targets_file,
            "-p", ports,
            "--rate", str(rate),
            "-oL", output_file,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )

        await asyncio.wait_for(proc.wait(), timeout=timeout)

        # Parse output
        if Path(output_file).exists():
            with open(output_file) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("open"):
                        parts = line.split()
                        if len(parts) >= 4:
                            port = int(parts[2])
                            ip = parts[3]
                            if ip not in results:
                                results[ip] = []
                            results[ip].append(port)

    except asyncio.TimeoutError:
        pass
    except Exception:
        pass
    finally:
        # Cleanup
        Path(targets_file).unlink(missing_ok=True)
        Path(output_file).unlink(missing_ok=True)

    return results


def check_dangerous_services(ip: IPAddress) -> list[Finding]:
    """Check for dangerous exposed services."""
    findings = []

    dangerous_services = {
        # Critical - Databases often with no auth
        "mongodb": (Severity.CRITICAL, "MongoDB exposed", "MongoDB database is exposed to the internet. This may allow unauthorized access to data."),
        "redis": (Severity.CRITICAL, "Redis exposed", "Redis is exposed to the internet. Redis often has no authentication by default."),
        "couchdb": (Severity.CRITICAL, "CouchDB exposed", "CouchDB is exposed to the internet. Check for admin party mode (no auth)."),
        "memcached": (Severity.CRITICAL, "Memcached exposed", "Memcached is exposed to the internet. Can be used for DDoS amplification and often has no auth."),
        "etcd": (Severity.CRITICAL, "etcd exposed", "etcd is exposed to the internet. May contain sensitive Kubernetes secrets."),

        # Critical - Container/Orchestration
        "docker": (Severity.CRITICAL, "Docker API exposed", "Docker API is exposed to the internet. This allows container escape and host compromise."),
        "kubelet": (Severity.CRITICAL, "Kubelet exposed", "Kubernetes Kubelet is exposed. May allow container access and secrets extraction."),
        "kubernetes-api": (Severity.CRITICAL, "Kubernetes API exposed", "Kubernetes API server is exposed. Check for anonymous auth."),

        # High - Databases
        "elasticsearch": (Severity.HIGH, "Elasticsearch exposed", "Elasticsearch is exposed to the internet. Check for authentication."),
        "mysql": (Severity.HIGH, "MySQL exposed", "MySQL database is exposed to the internet."),
        "postgresql": (Severity.HIGH, "PostgreSQL exposed", "PostgreSQL database is exposed to the internet."),
        "mssql": (Severity.HIGH, "MSSQL exposed", "Microsoft SQL Server is exposed to the internet."),
        "oracle": (Severity.HIGH, "Oracle DB exposed", "Oracle database is exposed to the internet."),
        "neo4j": (Severity.HIGH, "Neo4j exposed", "Neo4j graph database is exposed to the internet."),

        # High - Directory Services
        "ldap": (Severity.HIGH, "LDAP exposed", "LDAP service is exposed. May allow directory enumeration."),
        "ldaps": (Severity.HIGH, "LDAPS exposed", "LDAPS service is exposed. Check for anonymous binds."),

        # High - Message Queues
        "amqp": (Severity.HIGH, "RabbitMQ exposed", "RabbitMQ (AMQP) is exposed. Check for default credentials (guest/guest)."),
        "kafka": (Severity.HIGH, "Kafka exposed", "Apache Kafka is exposed to the internet."),
        "activemq": (Severity.HIGH, "ActiveMQ exposed", "ActiveMQ is exposed. Check for default admin credentials."),

        # High - Admin Interfaces
        "webmin": (Severity.HIGH, "Webmin exposed", "Webmin admin interface is exposed to the internet."),
        "java-rmi": (Severity.HIGH, "Java RMI exposed", "Java RMI registry is exposed. May allow remote code execution."),
        "weblogic": (Severity.HIGH, "WebLogic exposed", "Oracle WebLogic admin is exposed. Check for known vulnerabilities."),
        "websphere": (Severity.HIGH, "WebSphere exposed", "IBM WebSphere admin is exposed."),

        # Medium - Remote Access
        "rdp": (Severity.MEDIUM, "RDP exposed", "Remote Desktop Protocol is exposed. Ensure NLA is enabled and strong authentication."),
        "vnc": (Severity.MEDIUM, "VNC exposed", "VNC is exposed to the internet. Ensure it's password protected."),
        "winrm": (Severity.MEDIUM, "WinRM exposed", "Windows Remote Management is exposed. Verify authentication requirements."),
        "ssh": (Severity.LOW, "SSH exposed", "SSH is exposed. Ensure password authentication is disabled and key-based auth is used."),

        # Medium - Legacy Protocols
        "telnet": (Severity.MEDIUM, "Telnet exposed", "Telnet transmits data in cleartext. Consider using SSH instead."),
        "rpcbind": (Severity.MEDIUM, "RPC exposed", "RPC portmapper is exposed. May allow service enumeration."),
        "snmp": (Severity.MEDIUM, "SNMP exposed", "SNMP is exposed. Check for public/private community strings."),

        # Medium - Network Services
        "smb": (Severity.MEDIUM, "SMB exposed", "SMB/CIFS is exposed. Check for null session and signing requirements."),
        "netbios": (Severity.MEDIUM, "NetBIOS exposed", "NetBIOS services are exposed. May allow enumeration."),
        "nfs": (Severity.MEDIUM, "NFS exposed", "NFS is exposed to the internet. Check for exported shares."),
        "rsync": (Severity.MEDIUM, "rsync exposed", "rsync is exposed. Check for anonymous access to shares."),
        "iscsi": (Severity.MEDIUM, "iSCSI exposed", "iSCSI target is exposed. May allow unauthorized storage access."),

        # Medium - File Transfer
        "ftp": (Severity.MEDIUM, "FTP exposed", "FTP service is exposed. Credentials transmitted in cleartext. Consider SFTP."),
        "tftp": (Severity.MEDIUM, "TFTP exposed", "TFTP is exposed. No authentication - check for sensitive files."),

        # Low - Info gathering
        "smtp": (Severity.LOW, "SMTP exposed", "SMTP is exposed. Check for open relay and user enumeration."),

        # Suspicious
        "metasploit": (Severity.CRITICAL, "Metasploit listener detected", "Port 4444 is open - commonly used by Metasploit. This may indicate a compromise."),
    }

    for port in ip.ports:
        if port.state != PortState.OPEN:
            continue

        service_name = port.service.name.lower() if port.service else ""

        for service, (severity, title, description) in dangerous_services.items():
            if service in service_name:
                finding = Finding(
                    title=f"{title} on {ip.address}:{port.number}",
                    description=description,
                    severity=severity,
                    category="exposed_service",
                    affected_asset=ip.address,
                    affected_asset_type="ip",
                    evidence=f"Port {port.number} running {service_name}",
                    source="port_scanner",
                )
                findings.append(finding)

    return findings


async def run(
    session: ScanSession,
    config: AttackTraceConfig,
    orchestrator,
) -> ModuleResult:
    """
    Run port scanning on discovered IP addresses.

    Args:
        session: Current scan session
        config: AttackTrace configuration
        orchestrator: Orchestrator instance

    Returns:
        ModuleResult with port/service data
    """
    result = ModuleResult(
        module_name="port_scanner",
        started_at=datetime.utcnow(),
    )

    console = orchestrator.console

    if session.passive_only:
        # Skip active scanning in passive mode
        console.print("  [dim]Port scanning skipped (passive mode)[/dim]")
        result.success = True
        result.completed_at = datetime.utcnow()
        return result

    # Get all IPs to scan
    ips_to_scan = [ip.address for ip in session.ip_addresses]

    # Also get IPs from subdomains
    for subdomain in session.subdomains:
        ips_to_scan.extend(subdomain.resolved_ips)

    ips_to_scan = list(set(ips_to_scan))

    if not ips_to_scan:
        console.print("  [dim]No IPs to scan[/dim]")
        result.success = True
        result.completed_at = datetime.utcnow()
        return result

    # Determine ports to scan
    ports_to_scan = TOP_100_PORTS.copy()
    if config.modules.ports.custom_ports:
        ports_to_scan.extend(config.modules.ports.custom_ports)
    ports_to_scan = list(set(ports_to_scan))

    console.print(f"  [cyan]Scanning {len(ips_to_scan)} IPs for {len(ports_to_scan)} common ports...[/cyan]")

    # Check if we should use masscan for speed (enabled for normal+ intensity)
    masscan_results = {}
    if len(ips_to_scan) > 5 and config.scan.intensity in ("normal", "aggressive"):
        console.print("  [dim]Using masscan for initial discovery...[/dim]")
        port_range = ",".join(str(p) for p in ports_to_scan)
        masscan_results = await run_masscan(
            ips_to_scan,
            port_range,
            config.scan.rate_limit,
        )
        if masscan_results:
            console.print(f"  [green]Masscan found open ports on {len(masscan_results)} hosts[/green]")

    # Scan multiple IPs concurrently
    ip_semaphore = asyncio.Semaphore(10)  # Max 10 IPs scanned concurrently

    async def scan_single_ip(ip_addr: str) -> tuple:
        """Scan a single IP and return results."""
        async with ip_semaphore:
            # Check scope
            if not config.is_in_scope(ip_addr):
                return (ip_addr, [], [])

            # Get ports to scan for this IP
            if ip_addr in masscan_results:
                ip_ports = masscan_results[ip_addr]
            else:
                ip_ports = ports_to_scan

            # Scan ports
            open_ports = await scan_ip_ports(
                ip_addr,
                ip_ports,
                timeout=config.scan.timeout,
                concurrency=config.scan.threads,
            )

            return (ip_addr, open_ports, [])

    # Scan all IPs concurrently
    scan_results = await asyncio.gather(
        *[scan_single_ip(ip) for ip in ips_to_scan],
        return_exceptions=True
    )

    # Process results
    total_open_ports = 0
    hosts_with_ports = 0

    for res in scan_results:
        if isinstance(res, Exception):
            continue

        ip_addr, open_ports, _ = res
        if not open_ports:
            continue

        hosts_with_ports += 1
        total_open_ports += len(open_ports)

        # Show discovered ports
        port_list = [str(p.number) for p in open_ports[:10]]
        port_str = ", ".join(port_list)
        if len(open_ports) > 10:
            port_str += f" (+{len(open_ports) - 10} more)"

        # Color-code services for dangerous ones
        services = [p.service.name for p in open_ports if p.service.name != "unknown"]
        if services:
            console.print(f"    [green]{ip_addr}[/green] → {len(open_ports)} ports: {port_str}")
            console.print(f"      [dim]Services: {', '.join(services[:8])}[/dim]")
        else:
            console.print(f"    [green]{ip_addr}[/green] → {len(open_ports)} ports: {port_str}")

        # Find or create IP record
        existing_ip = next(
            (ip for ip in session.ip_addresses if ip.address == ip_addr),
            None
        )

        if existing_ip:
            # Merge ports instead of replacing (preserve Shodan/Censys data)
            existing_port_nums = {p.number for p in existing_ip.ports}
            for port in open_ports:
                if port.number not in existing_port_nums:
                    existing_ip.ports.append(port)
                    existing_port_nums.add(port.number)

            result.ip_addresses.append(existing_ip)

            # Check for dangerous services
            findings = check_dangerous_services(existing_ip)
            for f in findings:
                console.print(f"      [bold red]⚠ {f.title}[/bold red]")
            result.findings.extend(findings)
        else:
            ip = IPAddress(
                address=ip_addr,
                version=6 if ":" in ip_addr else 4,
                ports=open_ports,
                source="port_scanner",
            )
            result.ip_addresses.append(ip)

            findings = check_dangerous_services(ip)
            for f in findings:
                console.print(f"      [bold red]⚠ {f.title}[/bold red]")
            result.findings.extend(findings)

    # Summary
    if hosts_with_ports > 0:
        console.print(f"  [bold green]Found {total_open_ports} open ports across {hosts_with_ports} hosts[/bold green]")
    else:
        console.print("  [yellow]No open ports found[/yellow]")

    result.items_discovered = sum(len(ip.ports) for ip in result.ip_addresses)
    result.success = True
    result.completed_at = datetime.utcnow()

    return result
