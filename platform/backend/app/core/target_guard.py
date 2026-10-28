"""
Outbound scan-target policy shared by every scanner.

Scanners run from the platform host, so an unrestricted target lets any analyst probe the
host's own loopback services (Postgres, Redis, the API itself), the LAN, or a cloud metadata
endpoint (169.254.169.254) and read the results back. By default only globally routable
addresses are allowed; self-hosters scanning internal ranges opt in with
ALLOW_PRIVATE_SCAN_TARGETS=true. Link-local/multicast/unspecified (which includes the cloud
metadata address) are blocked even then.

Hostnames are resolved here and every returned address is checked. A name that doesn't resolve
is refused unless the caller opts in (subdomain-takeover scanning targets exactly those).
Resolution here is a point-in-time check, not DNS pinning: scanners that must
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


def _host_of(token: str) -> str | None:
    """Host the way the HTTP clients that consume the target will parse it, or None when the
    token can't be parsed unambiguously (callers must then refuse it).

    Scheme-less input is parsed as a network location (``//host``) so userinfo, ports, paths and
    scp-style ``git@host:org/repo`` yield the real host instead of a string that merely fails to
    resolve; a mismatch between this parser and the client is what a guard bypass needs.
    """
    token = token.strip()
    if "\\" in token:  # backslash handling differs between URL parsers: refuse
        return None
    try:
        return ipaddress.ip_address(token.split("%")[0]).compressed  # bare IPv4/IPv6
    except ValueError:
        pass
    try:
        host = urlsplit(token if "://" in token else "//" + token).hostname
    except ValueError:
        return None
    return host or None


def _is_cidr(token: str) -> bool:
    try:
        ipaddress.ip_network(token, strict=False)
        return "/" in token
    except ValueError:
        return False


def scan_target_problem(raw: str, allow_unresolvable: bool = False) -> str | None:
    """Reason a scan target must be refused, or None. Accepts URLs, hosts, IPs, CIDRs, and
    whitespace/comma separated lists of those.

    Fails closed: unparseable targets and names that don't resolve are refused. Only callers that
    legitimately target non-resolving names (subdomain takeover, ffuf FUZZ hosts) pass
    ``allow_unresolvable=True``.
    """
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
        if host is None:
            return f"{token[:60]}: could not be parsed as a host or URL"
        try:
            addrs = [ipaddress.ip_address(host.split("%")[0])]
        except ValueError:
            try:
                infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
            except socket.gaierror:
                if allow_unresolvable:
                    continue  # nothing to connect to (e.g. dangling DNS for takeover checks)
                return f"{host}: does not resolve"
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


def guard_scan_target(value, allow_unresolvable: bool = False):
    """Pydantic-validator helper: returns the value, or raises ValueError (-> HTTP 422)."""
    if value is None:
        return value
    items = value if isinstance(value, (list, tuple)) else [value]
    for item in items:
        if isinstance(item, str) and item.strip():
            problem = scan_target_problem(item, allow_unresolvable)
            if problem:
                raise ValueError(f"Target not allowed: {problem}")
    return value
