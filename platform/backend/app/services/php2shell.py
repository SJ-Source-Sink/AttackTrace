"""
PHP2Shell (CVE-2026-109618 / CVE-2026-109619) exposure detection.

Two unauthenticated RCE flaws in the PHP engine itself, fixed 2026-10-21 in
8.2.35 / 8.3.36 / 8.4.27 / 8.5.12; added to CISA KEV 2026-10-26. Vulnerable
code dates to PHP 5.4.0.

Why this is fingerprinting and not an exploit check: every known trigger is a
crafted multipart/form-data request that corrupts or frees engine memory, so
no safe remote probe can prove exploitability, and none is sent here. What an
outside observer *can* do is (a) tell whether a host runs PHP, (b) read the
version PHP volunteers (X-Powered-By / Server / an exposed phpinfo()), and
(c) judge it against the fixed releases. The hard part is honesty about what
that proves:

  * Supported branches below the fixed patch level are vulnerable -- unless a
    distro/vendor backported the fix, which keeps the old version string
    (Ubuntu 24.04 ships 8.3.6 forever). A distro hint therefore downgrades the
    verdict to "unverified" instead of crying wolf.
  * 7.4 / 8.0 / 8.1 got no upstream release (source backports only).
  * 5.4-7.3 have no fix from anyone upstream.
  * expose_php=Off + ServerTokens Prod hides the version: PHP can be detected
    but not judged -- reported separately, never as "safe".

Only benign GETs are issued. Nothing here sends multipart bodies.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from dataclasses import dataclass, field
from typing import Any

import httpx

CVES = ["CVE-2026-109618", "CVE-2026-109619"]
CVSS = 9.2  # CVSS v4.0, both CVEs
FIXED_PATCH: dict[tuple[int, int], int] = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
BACKPORT_ONLY = {(7, 4), (8, 0), (8, 1)}  # EOL: source backports / vendor packages only
MIN_AFFECTED = (5, 4)

REFERENCES = [
    "https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/",
    "https://www.rapid7.com/blog/post/etr-cve-2026-109618-and-cve-2026-109619-critical-unauthenticated-remote-code-execution-in-php/",
    "https://sansec.io/research/php2shell",
    "https://watchtowr.com/intelligence/php-cve-2026-109618-faq/",
]

REMEDIATION = (
    "Update PHP to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or a vendor package that lists "
    "CVE-2026-109618 and CVE-2026-109619 in its changelog, then restart ALL PHP workers "
    "(php-fpm / Apache / LiteSpeed) -- the fix does not apply until they restart. "
    "PHP 8.1 and older have no upstream release: use a distribution/LTS package or the "
    "PHP team's source backports (7.4, 8.0, 8.1), or migrate to a supported branch; "
    "5.4-7.3 have no fix at all. Verify a distro build with: "
    "`zgrep CVE-2026-109618 /usr/share/doc/php*-common/changelog.Debian.gz` (Debian/Ubuntu) or "
    "`rpm -q --changelog php-common | grep CVE-2026-109618` (RHEL family). "
    "Stop-gaps only (NOT a fix): set session.upload_progress.enabled=0 and, on PHP 8.5, "
    "fatal_error_backtraces=0 in php.ini / the FPM pool (not ini_set or .user.ini -- too late); "
    "cap post_max_size (8M, or 32M if uploads are needed); block multipart/form-data at the "
    "edge if the app doesn't use it; restrict internet exposure of the host."
)

# ── Version assessment (pure) ────────────────────────────────────────────────

_VER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(.*)$")
_PRERELEASE_RE = re.compile(r"(alpha|beta|rc\d*|dev)", re.I)
# Signals that a distro/vendor built this PHP, i.e. may carry backports that
# the upstream version string does not reflect.
_DISTRO_SUFFIX_RE = re.compile(r"(ubuntu|deb\d+u?\d*|\+deb|\.el\d|\.fc\d|\.amzn|remi|sury|alpine|\.suse|\.sles|\.ol\d)", re.I)
_DISTRO_SERVER_RE = re.compile(
    r"\((ubuntu|debian|red hat[^)]*|centos[^)]*|rocky[^)]*|almalinux|amazon[^)]*|fedora|suse[^)]*|oracle[^)]*)\)",
    re.I,
)


def parse_version(raw: str) -> tuple[int, int, int, str] | None:
    m = _VER_RE.match(raw.strip())
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4)


def distro_hint(version_suffix: str = "", server_header: str = "") -> str | None:
    m = _DISTRO_SUFFIX_RE.search(version_suffix or "")
    if m:
        return m.group(1).lower()
    m = _DISTRO_SERVER_RE.search(server_header or "")
    if m:
        return m.group(1).lower()
    return None


def assess_version(version: str, distro: str | None) -> dict[str, Any]:
    """Judge a PHP version string.

    status: patched | vulnerable | likely_vulnerable | unverified | not_affected
    """
    parsed = parse_version(version)
    if not parsed:
        return {"status": "unverified", "branch": None, "fixed_in": None,
                "reason": f"Could not parse PHP version {version!r}."}
    major, minor, patch, suffix = parsed
    branch = (major, minor)
    branch_s = f"{major}.{minor}"

    if _PRERELEASE_RE.search(suffix):
        return {"status": "unverified", "branch": branch_s, "fixed_in": None,
                "reason": f"Pre-release/dev build ({version}); patch level cannot be judged."}

    if branch < MIN_AFFECTED:
        return {"status": "not_affected", "branch": branch_s, "fixed_in": None,
                "reason": f"PHP {branch_s} predates the vulnerable code (introduced in 5.4.0). "
                          "Still end-of-life and unpatched for countless other issues."}

    if branch in FIXED_PATCH:
        fixed = f"{major}.{minor}.{FIXED_PATCH[branch]}"
        if patch >= FIXED_PATCH[branch]:
            return {"status": "patched", "branch": branch_s, "fixed_in": fixed,
                    "reason": f"{version} >= {fixed} (fixed upstream). Assumes workers were restarted after the update."}
        if distro:
            return {"status": "unverified", "branch": branch_s, "fixed_in": fixed,
                    "reason": f"{version} is below upstream fix {fixed}, but this looks like a {distro} build; "
                              "distributions backport the fix without changing the version string. "
                              "Check the package changelog for CVE-2026-109618."}
        return {"status": "vulnerable", "branch": branch_s, "fixed_in": fixed,
                "reason": f"{version} is below the fixed release {fixed} and shows no sign of a vendor backport."}

    if branch > (8, 5):
        return {"status": "patched", "branch": branch_s, "fixed_in": None,
                "reason": f"PHP {branch_s} is newer than any affected branch."}

    if branch in BACKPORT_ONLY:
        if distro:
            return {"status": "unverified", "branch": branch_s, "fixed_in": None,
                    "reason": f"PHP {branch_s} is EOL with no upstream fix; this looks like a {distro} build, "
                              "which may carry a vendor backport. Check the package changelog."}
        return {"status": "likely_vulnerable", "branch": branch_s, "fixed_in": None,
                "reason": f"PHP {branch_s} is EOL: upstream shipped no release, only source backports. "
                          "Unless this build applied them (rare outside distro packages), it is vulnerable."}

    # 5.4 - 7.3 and 8.x gaps (none today): no fix exists from the PHP team.
    if distro:
        return {"status": "unverified", "branch": branch_s, "fixed_in": None,
                "reason": f"PHP {branch_s} has no fix from the PHP team; this looks like a {distro} build "
                          "(ELTS/ESM vendors sometimes backport). Check the package changelog."}
    return {"status": "vulnerable", "branch": branch_s, "fixed_in": None,
            "reason": f"PHP {branch_s} is affected and no fix exists from the PHP team."}


# ── Target expansion + safety ────────────────────────────────────────────────

MAX_HOSTS = 1024
MAX_PORTS = 10
DEFAULT_PORTS = [80, 443, 8080, 8443]
_TLS_PORTS = {443, 8443, 9443, 4443}


@dataclass(frozen=True)
class Target:
    ip: str
    host_header: str | None  # original hostname when the input was a name
    label: str


def _embedded_v4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    if ip.ipv4_mapped:
        return ip.ipv4_mapped
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
    if not ip.is_global and not allow_private:
        return "non-public address (set ALLOW_PRIVATE_SCAN_TARGETS=true to scan internal ranges)"
    return None


async def expand_targets(
    raw: list[str], allow_private: bool
) -> tuple[list[Target], list[dict[str, str]]]:
    """IPs, CIDRs and hostnames -> concrete targets. Hostnames are resolved
    once here and connected to by IP (DNS pinning)."""
    targets: list[Target] = []
    errors: list[dict[str, str]] = []
    seen: set[tuple[str, str | None]] = set()
    loop = asyncio.get_running_loop()

    def add(t: Target) -> bool:
        key = (t.ip, t.host_header)
        if key in seen:
            return True
        if len(targets) >= MAX_HOSTS:
            return False
        seen.add(key)
        targets.append(t)
        return True

    for entry in raw:
        entry = entry.strip()
        if not entry or entry.startswith("#"):
            continue
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            net = None
        if net is not None:
            if net.num_addresses > MAX_HOSTS:
                errors.append({"target": entry, "error": f"range too large (max {MAX_HOSTS} addresses)"})
                continue
            hosts = [net.network_address] if net.num_addresses == 1 else list(net.hosts()) or list(net)
            for ip in hosts:
                reason = blocked_reason(ip, allow_private)
                if reason:
                    errors.append({"target": str(ip), "error": reason})
                    break  # same range, same verdict -- report once
                if not add(Target(str(ip), None, str(ip))):
                    errors.append({"target": entry, "error": f"host limit {MAX_HOSTS} reached"})
                    break
            continue
        # hostname
        if not re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?", entry):
            errors.append({"target": entry, "error": "not an IP, CIDR or valid hostname"})
            continue
        try:
            infos = await loop.getaddrinfo(entry, None, type=socket.SOCK_STREAM)
        except OSError as exc:
            errors.append({"target": entry, "error": f"DNS resolution failed: {exc}"})
            continue
        for ip_s in sorted({i[4][0] for i in infos}):
            ip = ipaddress.ip_address(ip_s)
            reason = blocked_reason(ip, allow_private)
            if reason:
                errors.append({"target": f"{entry} ({ip_s})", "error": reason})
                continue
            if not add(Target(ip_s, entry, f"{entry} ({ip_s})")):
                errors.append({"target": entry, "error": f"host limit {MAX_HOSTS} reached"})
                break
    return targets, errors


# ── Fingerprinting ───────────────────────────────────────────────────────────

_PHPINFO_PATHS = ["/phpinfo.php", "/info.php", "/php_info.php", "/phpinfo", "/i.php", "/test.php", "/php.php"]
_EASTER_EGG = "/?=PHPE9568F36-D428-11d2-A769-00AA001ACF42"
_MAX_BODY = 262144
_POWERED_RE = re.compile(r"PHP/([0-9][\w.\-+~]*)", re.I)
_PHPINFO_VER_RE = re.compile(r'<h1 class="p">\s*PHP Version\s*([0-9][\w.\-+~]*)', re.I)
_PHPINFO_VER_ALT_RE = re.compile(r">PHP Version\s*</td>\s*<td[^>]*>\s*([0-9][\w.\-+~]*)", re.I)
_PHPINFO_SAPI_RE = re.compile(r"Server API\s*</td>\s*<td[^>]*>\s*([^<]+?)\s*</td>", re.I)
_PHPINFO_UPLOAD_RE = re.compile(r"session\.upload_progress\.enabled\s*</td>\s*<td[^>]*>\s*(On|Off|1|0)", re.I)
_PHPINFO_MEM_RE = re.compile(r"memory_limit\s*</td>\s*<td[^>]*>\s*([^<]+?)\s*</td>", re.I)
_PHPINFO_BT_RE = re.compile(r"fatal_error_backtraces\s*</td>\s*<td[^>]*>\s*(On|Off|1|0)", re.I)
_PHPINFO_OS_RE = re.compile(r"System\s*</td>\s*<td[^>]*>\s*([^<]+?)\s*</td>", re.I)


def _is_phpinfo(body: str) -> bool:
    return "phpinfo()" in body[:4000].lower() or ("PHP Version" in body and "Zend Engine" in body)


@dataclass
class HostResult:
    label: str
    ip: str
    port: int
    scheme: str
    url: str
    php_detected: bool = False
    version: str | None = None
    version_source: str | None = None  # phpinfo | x-powered-by | server
    server_header: str | None = None
    powered_by: str | None = None
    distro: str | None = None
    sapi: str | None = None
    windows: bool = False
    phpinfo_url: str | None = None
    upload_progress: str | None = None
    memory_limit: str | None = None
    fatal_error_backtraces: str | None = None
    signals: list[str] = field(default_factory=list)
    assessment: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}


def _url(scheme: str, ip: str, port: int, path: str) -> str:
    host = f"[{ip}]" if ":" in ip else ip
    return f"{scheme}://{host}:{port}{path}"


async def _get(client: httpx.AsyncClient, t: Target, scheme: str, port: int, path: str) -> httpx.Response | None:
    headers = {"Host": t.host_header} if t.host_header else {}
    ext = {"sni_hostname": t.host_header} if (t.host_header and scheme == "https") else {}
    try:
        async with client.stream("GET", _url(scheme, t.ip, port, path), headers=headers,
                                 extensions=ext) as resp:
            chunks: list[bytes] = []
            size = 0
            async for chunk in resp.aiter_bytes():
                chunks.append(chunk)
                size += len(chunk)
                if size >= _MAX_BODY:
                    break
            resp._content = b"".join(chunks)[:_MAX_BODY]  # keep body for the caller
            return resp
    except (httpx.HTTPError, OSError, ValueError):
        return None


def _absorb_headers(res: HostResult, resp: httpx.Response) -> None:
    h = resp.headers
    server = h.get("server")
    if server and not res.server_header:
        res.server_header = server
    if server and "win" in server.lower():
        res.windows = True
    pb = h.get("x-powered-by")
    if pb and "php" in pb.lower():
        res.php_detected = True
        res.powered_by = res.powered_by or pb
        m = _POWERED_RE.search(pb)
        if m and not res.version:
            res.version, res.version_source = m.group(1), "x-powered-by"
            res.signals.append(f"X-Powered-By: {pb}")
    if server:
        m = _POWERED_RE.search(server)
        if m:
            res.php_detected = True
            if not res.version:
                res.version, res.version_source = m.group(1), "server"
            res.signals.append(f"Server: {server}")
        if "mod_php" in server.lower() or re.search(r"\bmod_php", server, re.I):
            res.php_detected = True
            res.sapi = res.sapi or "apache2handler (mod_php)"
    for cookie in h.get_list("set-cookie"):
        if cookie.lower().startswith("phpsessid="):
            res.php_detected = True
            res.signals.append("PHPSESSID cookie")
            break


def _absorb_phpinfo(res: HostResult, body: str, url: str) -> bool:
    if not _is_phpinfo(body):
        return False
    res.php_detected = True
    res.phpinfo_url = url
    m = _PHPINFO_VER_RE.search(body) or _PHPINFO_VER_ALT_RE.search(body)
    if m:
        res.version, res.version_source = m.group(1), "phpinfo"
    m = _PHPINFO_SAPI_RE.search(body)
    if m:
        res.sapi = m.group(1).strip()
    m = _PHPINFO_UPLOAD_RE.search(body)
    if m:
        res.upload_progress = "On" if m.group(1).lower() in ("on", "1") else "Off"
    m = _PHPINFO_MEM_RE.search(body)
    if m:
        res.memory_limit = m.group(1).strip()
    m = _PHPINFO_BT_RE.search(body)
    if m:
        res.fatal_error_backtraces = "On" if m.group(1).lower() in ("on", "1") else "Off"
    m = _PHPINFO_OS_RE.search(body)
    if m and "windows" in m.group(1).lower():
        res.windows = True
    res.signals.append(f"phpinfo() exposed at {url}")
    return True


def finalize(res: HostResult) -> HostResult:
    if res.version:
        parsed = parse_version(res.version)
        suffix = parsed[3] if parsed else ""
        # A Windows build is upstream (windows.php.net): no distro backports.
        res.distro = None if res.windows else distro_hint(suffix, res.server_header or "")
        res.assessment = assess_version(res.version, res.distro)
    elif res.php_detected:
        res.assessment = {
            "status": "version_hidden", "branch": None, "fixed_in": None,
            "reason": "PHP is running here but does not disclose its version "
                      "(expose_php=Off / ServerTokens Prod), so PHP2Shell exposure cannot be determined remotely. "
                      "Check the installed version on the host.",
        }
    return res


async def fingerprint(
    client: httpx.AsyncClient, t: Target, port: int, probe_phpinfo: bool = True
) -> HostResult | None:
    """Fingerprint one ip:port. None when nothing answers HTTP there."""
    scheme = "https" if port in _TLS_PORTS else "http"
    first = await _get(client, t, scheme, port, "/")
    if first is None:
        return None
    res = HostResult(label=t.label, ip=t.ip, port=port, scheme=scheme, url=_url(scheme, t.ip, port, "/"))
    if t.host_header:
        res.url = f"{scheme}://{t.host_header}:{port}/"
    _absorb_headers(res, first)

    # PHP's own entrypoint: a PHP-handled response carries X-Powered-By even
    # when "/" is served by a static index.
    idx = await _get(client, t, scheme, port, "/index.php")
    if idx is not None and idx.status_code < 500:
        _absorb_headers(res, idx)

    if probe_phpinfo:
        for path in _PHPINFO_PATHS:
            r = await _get(client, t, scheme, port, path)
            if r is None or r.status_code != 200:
                continue
            _absorb_headers(res, r)
            if _absorb_phpinfo(res, r.text, _url(scheme, t.ip, port, path) if not t.host_header
                               else f"{scheme}://{t.host_header}:{port}{path}"):
                break

    if not res.php_detected:
        # expose_php=On easter-egg logo -- proves PHP even when headers are stripped
        r = await _get(client, t, scheme, port, _EASTER_EGG)
        if (r is not None and r.status_code == 200
                and r.headers.get("content-type", "").lower().startswith("image/")
                and r.content[:4] in (b"\x89PNG", b"GIF8")):
            res.php_detected = True
            res.signals.append("PHP logo easter egg (expose_php=On)")
    return finalize(res)


def make_client(timeout: float = 8.0) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        # Targets are arbitrary hosts, often with self-signed/expired certs; we only
        # read public banners and send no credentials, so verification adds nothing.
        verify=False,
        follow_redirects=False,  # never let a target bounce us to an internal address
        timeout=httpx.Timeout(timeout, connect=4.0),
        headers={"User-Agent": "AttackTrace-PHP2Shell-Check/1.0", "Accept": "*/*"},
        limits=httpx.Limits(max_connections=50),
    )
