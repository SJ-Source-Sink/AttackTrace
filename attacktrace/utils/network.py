"""
Network utility functions.
"""

import asyncio
import socket
from typing import Optional
from ipaddress import ip_address, ip_network


# Cloud provider IP ranges (partial list for common checks)
CLOUD_IP_RANGES = {
    "aws": [
        "3.0.0.0/8",
        "13.0.0.0/8",
        "15.0.0.0/8",
        "18.0.0.0/8",
        "23.0.0.0/8",
        "34.0.0.0/8",
        "35.0.0.0/8",
        "52.0.0.0/8",
        "54.0.0.0/8",
        "99.0.0.0/8",
    ],
    "azure": [
        "13.64.0.0/11",
        "20.0.0.0/8",
        "40.64.0.0/10",
        "51.0.0.0/8",
        "52.0.0.0/8",
        "104.40.0.0/13",
        "137.116.0.0/15",
        "168.61.0.0/16",
    ],
    "gcp": [
        "34.64.0.0/10",
        "34.128.0.0/10",
        "35.184.0.0/13",
        "35.192.0.0/12",
        "35.208.0.0/12",
        "35.224.0.0/12",
        "35.240.0.0/13",
    ],
    "digitalocean": [
        "104.131.0.0/16",
        "104.236.0.0/16",
        "107.170.0.0/16",
        "138.68.0.0/16",
        "139.59.0.0/16",
        "142.93.0.0/16",
        "157.230.0.0/16",
        "159.65.0.0/16",
        "159.89.0.0/16",
        "161.35.0.0/16",
        "162.243.0.0/16",
        "165.22.0.0/16",
        "167.71.0.0/16",
        "167.172.0.0/16",
        "174.138.0.0/16",
        "178.62.0.0/16",
        "188.166.0.0/16",
        "192.241.0.0/16",
        "206.189.0.0/16",
        "209.97.0.0/16",
    ],
}


def detect_cloud_provider(ip: str) -> Optional[str]:
    """
    Detect which cloud provider an IP belongs to.

    Returns:
        Cloud provider name or None
    """
    try:
        ip_obj = ip_address(ip)
    except ValueError:
        return None

    for provider, ranges in CLOUD_IP_RANGES.items():
        for cidr in ranges:
            if ip_obj in ip_network(cidr, strict=False):
                return provider

    return None


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is private."""
    try:
        ip_obj = ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False


def is_reserved_ip(ip: str) -> bool:
    """Check if an IP address is reserved."""
    try:
        ip_obj = ip_address(ip)
        return ip_obj.is_reserved or ip_obj.is_multicast or ip_obj.is_loopback
    except ValueError:
        return False


async def reverse_dns(ip: str, timeout: float = 5.0) -> list[str]:
    """
    Perform reverse DNS lookup.

    Returns:
        List of hostnames or empty list
    """
    try:
        loop = asyncio.get_event_loop()
        result = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyaddr, ip),
            timeout=timeout,
        )
        return [result[0]] + list(result[1])
    except (socket.herror, socket.gaierror, asyncio.TimeoutError, OSError):
        return []


async def check_tcp_port(
    host: str,
    port: int,
    timeout: float = 3.0,
) -> bool:
    """
    Check if a TCP port is open.

    Returns:
        True if port is open, False otherwise
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False


def expand_cidr(cidr: str, max_ips: int = 256) -> list[str]:
    """
    Expand a CIDR notation to list of IP addresses.

    Args:
        cidr: CIDR notation (e.g., "192.168.1.0/24")
        max_ips: Maximum number of IPs to return

    Returns:
        List of IP addresses
    """
    try:
        network = ip_network(cidr, strict=False)
        ips = []
        for i, ip in enumerate(network.hosts()):
            if i >= max_ips:
                break
            ips.append(str(ip))
        return ips
    except ValueError:
        return []


def calculate_cidr_from_ips(ips: list[str]) -> Optional[str]:
    """
    Calculate the smallest CIDR that contains all given IPs.

    Args:
        ips: List of IP addresses

    Returns:
        CIDR notation or None
    """
    if not ips:
        return None

    try:
        from ipaddress import collapse_addresses, ip_address, ip_network

        ip_objects = [ip_address(ip) for ip in ips]

        # Check if all IPs are the same version
        v4_ips = [ip for ip in ip_objects if ip.version == 4]
        v6_ips = [ip for ip in ip_objects if ip.version == 6]

        if v4_ips and not v6_ips:
            # Convert to /32 networks and collapse
            networks = [ip_network(f"{ip}/32") for ip in v4_ips]
            collapsed = list(collapse_addresses(networks))
            if len(collapsed) == 1:
                return str(collapsed[0])
        elif v6_ips and not v4_ips:
            networks = [ip_network(f"{ip}/128") for ip in v6_ips]
            collapsed = list(collapse_addresses(networks))
            if len(collapsed) == 1:
                return str(collapsed[0])

        return None

    except Exception:
        return None
