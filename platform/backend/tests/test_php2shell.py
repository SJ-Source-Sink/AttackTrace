"""PHP2Shell (CVE-2026-109618/109619) detection: verdict table, target safety,
and real fingerprinting against local fake servers (no external traffic)."""
import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app.services import php2shell as p2s

PHPINFO = (
    '<html><head><title>phpinfo()</title></head><body><div class="center">'
    '<table><tr class="h"><td><a href="http://www.php.net/"></a><h1 class="p">PHP Version 8.2.20</h1></td></tr></table>'
    '<table><tr><td class="e">Server API </td><td class="v">FPM/FastCGI </td></tr>'
    '<tr><td class="e">System </td><td class="v">Linux web1 5.15 </td></tr>'
    '<tr><td class="e">session.upload_progress.enabled </td><td class="v">On </td><td class="v">On </td></tr>'
    '<tr><td class="e">memory_limit </td><td class="v">128M </td><td class="v">128M </td></tr>'
    '</table>This program makes use of the Zend Scripting Language Engine</body></html>'
)

# name -> (headers, {path: (status, content_type, body)})
SITES = {
    "vuln": ({"X-Powered-By": "PHP/8.3.10"}, {}),
    "patched": ({"X-Powered-By": "PHP/8.3.36"}, {}),
    "distro": ({"X-Powered-By": "PHP/8.1.2-1ubuntu2.14", "Server": "Apache/2.4.52 (Ubuntu)"}, {}),
    "eol": ({"X-Powered-By": "PHP/7.4.33"}, {}),
    "hidden": ({"Set-Cookie": "PHPSESSID=abc; path=/"}, {}),
    "phpinfo": ({}, {"/phpinfo.php": (200, "text/html", PHPINFO)}),
    "plain": ({"Server": "nginx/1.25"}, {}),
    "win": ({"X-Powered-By": "PHP/8.2.12", "Server": "Microsoft-IIS/10.0 Win64"}, {}),
}


def _make_handler(headers, pages):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            status, ctype, body = pages.get(self.path.split("?")[0], (200, "text/html", "<html>hi</html>"))
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body.encode())
    return H


@pytest.fixture(scope="module")
def servers():
    started, ports = [], {}
    for name, (headers, pages) in SITES.items():
        srv = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(headers, pages))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        started.append(srv)
        ports[name] = srv.server_address[1]
    yield ports
    for s in started:
        s.shutdown()


def _fp(port):
    async def go():
        async with p2s.make_client() as c:
            return await p2s.fingerprint(c, p2s.Target("127.0.0.1", None, "127.0.0.1"), port)
    return asyncio.run(go())


@pytest.mark.parametrize("version,distro,status", [
    ("8.3.35", None, "vulnerable"), ("8.3.36", None, "patched"), ("8.3.40", None, "patched"),
    ("8.2.34", None, "vulnerable"), ("8.2.35", None, "patched"),
    ("8.4.26", None, "vulnerable"), ("8.4.27", None, "patched"),
    ("8.5.11", None, "vulnerable"), ("8.5.12", None, "patched"), ("8.6.0", None, "patched"),
    ("8.3.6", "ubuntu", "unverified"),
    ("8.1.34", None, "likely_vulnerable"), ("8.0.30", None, "likely_vulnerable"), ("7.4.33", None, "likely_vulnerable"),
    ("8.1.2", "ubuntu", "unverified"),
    ("7.3.33", None, "vulnerable"), ("5.6.40", None, "vulnerable"), ("5.4.0", None, "vulnerable"),
    ("5.3.29", None, "not_affected"),
    ("8.3.36-dev", None, "unverified"), ("garbage", None, "unverified"),
])
def test_assess_version(version, distro, status):
    assert p2s.assess_version(version, distro)["status"] == status


def test_distro_hint():
    assert p2s.distro_hint("-1ubuntu2.14") == "ubuntu"
    assert p2s.distro_hint("-1+deb12u3") is not None
    assert p2s.distro_hint("", "Apache/2.4.52 (Ubuntu)") == "ubuntu"
    assert p2s.distro_hint("", "nginx") is None


def test_blocked_targets():
    import ipaddress as ip
    assert p2s.blocked_reason(ip.ip_address("169.254.169.254"), True)
    assert p2s.blocked_reason(ip.ip_address("::ffff:169.254.169.254"), True)
    assert p2s.blocked_reason(ip.ip_address("64:ff9b::a9fe:a9fe"), True)
    assert p2s.blocked_reason(ip.ip_address("127.0.0.1"), False)
    assert p2s.blocked_reason(ip.ip_address("127.0.0.1"), True) is None
    assert p2s.blocked_reason(ip.ip_address("93.184.216.34"), False) is None


def test_expand_targets():
    t, e = asyncio.run(p2s.expand_targets(["93.184.216.34", "93.184.216.0/30", "10.0.0.1", "bad host!", "0.0.0.0/0"], False))
    assert {x.ip for x in t} >= {"93.184.216.34", "93.184.216.1", "93.184.216.2"}
    msgs = " | ".join(x["error"] for x in e)
    assert "private" in msgs and "not an IP" in msgs and "too large" in msgs


@pytest.mark.parametrize("site,status,detected", [
    ("vuln", "vulnerable", True), ("patched", "patched", True), ("distro", "unverified", True),
    ("eol", "likely_vulnerable", True), ("hidden", "version_hidden", True),
    ("phpinfo", "vulnerable", True), ("win", "vulnerable", True),
])
def test_fingerprint_sites(servers, site, status, detected):
    r = _fp(servers[site])
    assert r is not None and r.php_detected is detected
    assert r.assessment["status"] == status, r.to_dict()


def test_fingerprint_phpinfo_details(servers):
    r = _fp(servers["phpinfo"])
    assert r.version == "8.2.20" and r.version_source == "phpinfo"
    assert r.upload_progress == "On" and r.sapi.startswith("FPM") and r.memory_limit == "128M"
    from app.api.v1.php_cve import host_to_findings
    titles = [f["title"] for f in host_to_findings(r.to_dict())]
    assert any("vulnerable PHP version" in t for t in titles) and "phpinfo() page publicly exposed" in titles
    f = host_to_findings(r.to_dict())[0]
    assert f["cve"] == p2s.CVES and f["kev_status"] and f["confidence"] == "high" and f["severity"] == "critical"


def test_non_php_and_closed(servers):
    r = _fp(servers["plain"])
    assert r is not None and not r.php_detected and r.assessment is None
    assert _fp(1) is None  # nothing listening


def test_patched_yields_no_finding(servers):
    from app.api.v1.php_cve import host_to_findings
    assert host_to_findings(_fp(servers["patched"]).to_dict()) == []
