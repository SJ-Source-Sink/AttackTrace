"""
Input validation utilities.
"""

import re
from typing import Optional
import ipaddress


def is_valid_domain(domain: str) -> bool:
    """Check if a string is a valid domain name."""
    if not domain or len(domain) > 253:
        return False

    # Remove trailing dot if present
    if domain.endswith("."):
        domain = domain[:-1]

    # Check each label
    labels = domain.split(".")
    if len(labels) < 2:
        return False

    for label in labels:
        if not label or len(label) > 63:
            return False
        # Labels must be alphanumeric with hyphens (not at start/end)
        if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$", label):
            # Allow single-character labels
            if not re.match(r"^[a-zA-Z0-9]$", label):
                return False

    return True


def is_valid_ipv4(ip: str) -> bool:
    """Check if a string is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_valid_ipv6(ip: str) -> bool:
    """Check if a string is a valid IPv6 address."""
    try:
        ipaddress.IPv6Address(ip)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_valid_ip(ip: str) -> bool:
    """Check if a string is a valid IP address (v4 or v6)."""
    return is_valid_ipv4(ip) or is_valid_ipv6(ip)


def is_valid_cidr(cidr: str) -> bool:
    """Check if a string is a valid CIDR notation."""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_valid_port(port: int) -> bool:
    """Check if a port number is valid."""
    return isinstance(port, int) and 1 <= port <= 65535


def is_valid_url(url: str) -> bool:
    """Check if a string is a valid URL."""
    pattern = re.compile(
        r"^https?://"  # http:// or https://
        r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|"  # domain
        r"localhost|"  # localhost
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"  # or IP
        r"(?::\d+)?"  # optional port
        r"(?:/?|[/?]\S+)$",
        re.IGNORECASE,
    )
    return bool(pattern.match(url))


def sanitize_domain(domain: str) -> Optional[str]:
    """Sanitize and normalize a domain name."""
    if not domain:
        return None

    # Lowercase
    domain = domain.lower().strip()

    # Remove protocol if present
    for prefix in ["https://", "http://", "//", "www."]:
        if domain.startswith(prefix):
            domain = domain[len(prefix):]

    # Remove path
    domain = domain.split("/")[0]

    # Remove port
    domain = domain.split(":")[0]

    # Remove trailing dot
    if domain.endswith("."):
        domain = domain[:-1]

    if is_valid_domain(domain):
        return domain

    return None


def sanitize_ip(ip: str) -> Optional[str]:
    """Sanitize and normalize an IP address."""
    if not ip:
        return None

    ip = ip.strip()

    if is_valid_ipv4(ip):
        return str(ipaddress.IPv4Address(ip))
    elif is_valid_ipv6(ip):
        return str(ipaddress.IPv6Address(ip))

    return None


def parse_port_range(port_str: str) -> list[int]:
    """
    Parse a port specification string into a list of ports.

    Examples:
        "80" -> [80]
        "80,443" -> [80, 443]
        "80-85" -> [80, 81, 82, 83, 84, 85]
        "80,443,8000-8005" -> [80, 443, 8000, 8001, 8002, 8003, 8004, 8005]
    """
    ports = set()

    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-")
                start, end = int(start), int(end)
                if is_valid_port(start) and is_valid_port(end) and start <= end:
                    ports.update(range(start, end + 1))
            except ValueError:
                continue
        else:
            try:
                port = int(part)
                if is_valid_port(port):
                    ports.add(port)
            except ValueError:
                continue

    return sorted(ports)
