"""
Shared SSRF guard for any code path that fetches an org-supplied URL —
Slack/Jira/Teams/generic webhook config, notification-channel test calls,
outbound webhook dispatch, anything where a URL crosses a tenant boundary
(a user typed it into a form) before this server makes an outbound HTTP
request to it.

Closes two confirmed audit findings:
  - Reflected SSRF in app/api/v1/notifications.py's channel test functions
    (webhook_url/url/jira_url fetched with no validation at all, and the
    response status/body echoed back to the caller — a read-oriented SSRF
    into the internal network / cloud metadata service).
  - Blind SSRF in app/api/v1/webhooks.py (create_webhook/test_webhook/
    dispatch_webhook_event) and app/services/notification_service.py
    (send_webhook/_dispatch_slack/_dispatch_teams/_dispatch_generic_webhook)
    — same missing validation; the response isn't reflected so it's blind,
    but it still lets an org member make this server issue arbitrary
    internal HTTP requests.

Two checks are required, not one:
  1. Validate scheme + resolved IP before ever connecting — resolving the
     hostname (rather than only rejecting literal internal IPs in the URL)
     is what catches a DNS name that points at an internal address.
  2. Don't blindly follow redirects — a hostname that resolves safely at
     validation time can still 3xx to an internal address. This codebase
     already established the fix for that: attack_agent.py's tool-use HTTP
     probes and compliance.py's PDF url_fetcher both refuse to auto-follow
     redirects on a target they don't control (`follow_redirects=False`,
     3xx reported/handled as-is, never chased). Callers here should build
     their httpx.AsyncClient the same way — see `SAFE_CLIENT_KWARGS` below.
"""

import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}

# Pass as **SAFE_CLIENT_KWARGS to httpx.AsyncClient(...) at every call site
# that fetches an org-supplied URL, so redirects are never auto-followed
# (matches the existing attack_agent.py / compliance.py convention in this
# codebase — see module docstring).
SAFE_CLIENT_KWARGS = {"follow_redirects": False}


class SSRFValidationError(ValueError):
    """Raised by validate_outbound_url() when a URL fails SSRF validation."""


def _is_unsafe_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    # IPv4-mapped IPv6 addresses (::ffff:127.0.0.1 etc.) must be judged by
    # their embedded IPv4 semantics, not just the outer IPv6 ranges.
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def validate_outbound_url(url: str) -> None:
    """
    Raise SSRFValidationError if `url` is not safe for this server to make
    an outbound request to. Call this BEFORE constructing/issuing any
    request built from an org-supplied URL — at the point the URL is first
    saved (webhook/channel creation and update) AND again immediately
    before every dispatch (DNS can change between the two — re-validating
    at send time is what catches DNS rebinding, not just a one-time check).

    Checks:
      - Scheme must be http:// or https:// (rejects file://, gopher://,
        data://, etc.).
      - Hostname must be present and must resolve (via socket.getaddrinfo,
        covering both A and AAAA records).
      - Every resolved address must be public/routable — rejects private
        (RFC1918: 10/8, 172.16/12, 192.168/16), loopback (127/8, ::1),
        link-local (169.254/16 — this includes the AWS/GCP/Azure cloud
        metadata address 169.254.169.254 — and fe80::/10), reserved,
        multicast, and unspecified (0.0.0.0) ranges, for both IPv4 and
        IPv6 (including fc00::/7 unique-local, which `is_private` covers).
    """
    if not url or not isinstance(url, str):
        raise SSRFValidationError("URL is required")

    url = url.strip()
    parsed = urlparse(url)

    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise SSRFValidationError(
            f"Unsupported URL scheme '{parsed.scheme or '(none)'}' — only http:// and https:// are allowed"
        )

    hostname = parsed.hostname
    if not hostname:
        raise SSRFValidationError("URL has no hostname")

    try:
        addrinfo = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise SSRFValidationError(f"Could not resolve hostname '{hostname}': {exc}") from exc

    resolved_ips = {info[4][0].split("%")[0] for info in addrinfo}  # strip IPv6 zone id
    if not resolved_ips:
        raise SSRFValidationError(f"Hostname '{hostname}' did not resolve to any address")

    for ip_str in resolved_ips:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            raise SSRFValidationError(f"Hostname '{hostname}' resolved to an unparseable address")
        if _is_unsafe_ip(ip):
            raise SSRFValidationError(
                f"URL host '{hostname}' resolves to a private/reserved address ({ip_str}) — not allowed"
            )


def is_safe_outbound_url(url: str) -> bool:
    """Boolean convenience wrapper around validate_outbound_url()."""
    try:
        validate_outbound_url(url)
        return True
    except SSRFValidationError:
        return False
