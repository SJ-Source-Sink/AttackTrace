"""
Outbound scan-target policy shared by every scanner.

Scanners run from the platform host, so an unrestricted target lets any analyst probe the
host's own loopback services (Postgres, Redis, the API itself), the LAN, or a cloud metadata
endpoint (169.254.169.254) and read the results back. By default only globally routable
addresses are allowed; self-hosters scanning internal ranges opt in with
ALLOW_PRIVATE_SCAN_TARGETS=true. Link-local/multicast/unspecified (which includes the cloud
metadata address) are blocked even then.

Hostnames are resolved here and every returned address is checked. A name that doesn't resolve
is allowed through (subdomain-takeover scanning targets exactly those) since nothing can be
connected to. Resolution here is a point-in-time check, not DNS pinning: scanners that must
withstand DNS rebinding (php2shell) pin the resolved IP themselves.
"""

import ipaddress
import socket
from urllib.parse import urlsplit

from app.core.config import get_settings


def _embedded_v4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    if ip.ipv4_mapped:
        return ip.ipv4_mapped
    if ip in ipaddress.ip_network("::/96"):  # IPv4-compatible (deprecated): ::a.b.c.d
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip in ipaddress.ip_network("::ffff:0:0:0/96"):  # SIIT: ::ffff:0:a.b.c.d
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip in ipaddress.ip_network("64:ff9b::/96"):
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip in ipaddress.ip_network("2002::/16"):
        return ipaddress.IPv4Address((int(ip) >> 80) & 0xFFFFFFFF)
    return None


def blocked_reason(ip: ipaddress._BaseAddress, allow_private: bool) -> str | None:
    """Why the platform refuses to send traffic to this address, or None."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.teredo:  # (server, client) -- judge both embedded IPv4s
            for v4 in ip.teredo:
                reason = blocked_reason(v4, allow_private)
                if reason:
                    return reason
        ip = _embedded_v4(ip) or ip
    if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return "link-local/multicast/unspecified address (always blocked)"
    # Fail closed: anything not globally routable (private, loopback, CGNAT
    # 100.64/10, documentation, reserved, ...) needs the explicit opt-in.
    if (not ip.is_global or ip.is_reserved) and not allow_private:
        return "non-public address (set ALLOW_PRIVATE_SCAN_TARGETS=true to scan internal ranges)"
    return None


def _host_of(token: str) -> str:
    """Bare host from a URL, host:port, [v6]:port, or plain host/IP."""
    token = token.strip()
    if "://" in token:
        return (urlsplit(token).hostname or "").strip()
    token = token.split("/", 1)[0] if "/" in token and not _is_cidr(token) else token
    if token.startswith("["):
        return token[1 : token.find("]")] if "]" in token else token[1:]
    if token.count(":") == 1:  # host:port (a bare IPv6 has several colons)
        return token.split(":", 1)[0]
    return token


def _is_cidr(token: str) -> bool:
    try:
        ipaddress.ip_network(token, strict=False)
        return "/" in token
    except ValueError:
        return False


def scan_target_problem(raw: str) -> str | None:
    """Reason a scan target must be refused, or None. Accepts URLs, hosts, IPs, CIDRs, and
    whitespace/comma separated lists of those."""
    allow_private = bool(get_settings().ALLOW_PRIVATE_SCAN_TARGETS)
    for token in raw.replace(",", " ").split():
        if _is_cidr(token):
            net = ipaddress.ip_network(token, strict=False)
            for addr in (net.network_address, net.broadcast_address):
                reason = blocked_reason(addr, allow_private)
                if reason:
                    return f"{token}: {reason}"
            continue
        host = _host_of(token)
        if not host:
            continue
        try:
            addrs = [ipaddress.ip_address(host.split("%")[0])]
        except ValueError:
            try:
                infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
            except socket.gaierror:
                continue  # unresolvable: nothing to connect to
            addrs = []
            for info in infos:
                try:
                    addrs.append(ipaddress.ip_address(info[4][0].split("%")[0]))
                except ValueError:
                    continue
        for addr in addrs:
            reason = blocked_reason(addr, allow_private)
            if reason:
                return f"{host} -> {addr}: {reason}"
    return None


def guard_scan_target(value):
    """Pydantic-validator helper: returns the value, or raises ValueError (-> HTTP 422)."""
    if value is None:
        return value
    items = value if isinstance(value, (list, tuple)) else [value]
    for item in items:
        if isinstance(item, str) and item.strip():
            problem = scan_target_problem(item)
            if problem:
                raise ValueError(f"Target not allowed: {problem}")
    return value
