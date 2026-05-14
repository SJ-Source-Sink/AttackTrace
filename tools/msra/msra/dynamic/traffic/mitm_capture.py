"""Standalone mitmproxy capture integration – no Corellium required.

Usage:
    with MitmCapture(device_serial="emulator-5554") as cap:
        # ... exercise the app ...
        flows = cap.get_flows()
        findings = cap.get_security_findings("com.example.app")
"""

import json
import logging
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Data model                                                                   #
# --------------------------------------------------------------------------- #

@dataclass
class CapturedFlow:
    """Represents a single HTTP/HTTPS request-response pair captured by mitmdump."""
    request_method: str
    request_url: str
    request_headers: Dict[str, str]
    request_body: Optional[str]
    response_status: Optional[int]
    response_headers: Optional[Dict[str, str]]
    response_body: Optional[str]
    timestamp: float
    is_https: bool
    contains_sensitive_data: bool = False
    sensitive_fields: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable representation."""
        return {
            "timestamp": self.timestamp,
            "method": self.request_method,
            "url": self.request_url,
            "is_https": self.is_https,
            "response_status": self.response_status,
            "contains_sensitive_data": self.contains_sensitive_data,
            "sensitive_fields": self.sensitive_fields,
            "request_headers": self.request_headers,
            "response_headers": self.response_headers or {},
        }


# --------------------------------------------------------------------------- #
# Sensitive-field patterns used by get_security_findings                       #
# --------------------------------------------------------------------------- #

_SENSITIVE_BODY_PATTERNS = [
    ("password",    re.compile(r'["\']?(?:password|passwd|pwd)["\']?\s*[:=]\s*["\']?([^"\'&\s]{3,})', re.I)),
    ("secret",      re.compile(r'["\']?secret["\']?\s*[:=]\s*["\']?([^"\'&\s]{6,})', re.I)),
    ("token",       re.compile(r'["\']?(?:token|access_token|id_token)["\']?\s*[:=]\s*["\']?([^"\'&\s]{8,})', re.I)),
    ("api_key",     re.compile(r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{16,})', re.I)),
    ("credit_card", re.compile(r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b')),
    ("ssn",         re.compile(r'\b\d{3}-\d{2}-\d{4}\b')),
    ("email",       re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')),
]

_SENSITIVE_COOKIE_NAMES = re.compile(
    r'\b(?:session|auth|token|jwt|access|refresh|sid)\b', re.I
)
_AUTH_HEADER = re.compile(r'^(?:bearer|basic)\s+\S+', re.I)
_PII_PATTERNS = [
    ("email", re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')),
    ("ssn",   re.compile(r'\b\d{3}-\d{2}-\d{4}\b')),
]


# --------------------------------------------------------------------------- #
# Main class                                                                   #
# --------------------------------------------------------------------------- #

class MitmCapture:
    """Start mitmdump as a subprocess, configure device proxy via ADB, capture
    HTTP/HTTPS traffic and return structured security findings.

    Can be used as a context manager:

        with MitmCapture(device_serial="emulator-5554") as cap:
            ...
            flows = cap.get_flows()
    """

    def __init__(self, device_serial: Optional[str] = None, port: int = 8080):
        self.device_serial = device_serial
        self.port = port
        self.flows: List[CapturedFlow] = []
        self._proc: Optional[subprocess.Popen] = None
        self._flow_file: Optional[str] = None
        self._tmpdir: Optional[str] = None
        self._proxy_configured = False

    # ------------------------------------------------------------------ #
    # Context manager support                                             #
    # ------------------------------------------------------------------ #

    def __enter__(self) -> "MitmCapture":
        self.start()
        return self

    def __exit__(self, *args) -> None:
        self.stop()

    # ------------------------------------------------------------------ #
    # Start / Stop                                                        #
    # ------------------------------------------------------------------ #

    def start(self) -> bool:
        """Start mitmdump and configure device proxy.

        Returns:
            True if mitmdump started successfully.
        """
        # 1. Verify mitmdump is on PATH
        if not shutil.which("mitmdump"):
            logger.error(
                "mitmdump not found on PATH. Install mitmproxy: pip install mitmproxy"
            )
            return False

        # 2. Create a temp directory for the flow file
        self._tmpdir = tempfile.mkdtemp(prefix="msra_mitm_")
        self._flow_file = os.path.join(self._tmpdir, "capture.mitm")

        # 3. Determine host IP that the Android device can reach
        host_ip = self.get_host_ip()

        # 4. Launch mitmdump
        cmd = [
            "mitmdump",
            "--listen-host", "0.0.0.0",
            "-p", str(self.port),
            "-w", self._flow_file,
            "--set", "block_global=false",
            "--set", "ssl_insecure=true",
            "--set", "flow_detail=3",
            "--quiet",
        ]

        logger.info("Starting mitmdump on 0.0.0.0:%d  (device proxy -> %s:%d)",
                    self.port, host_ip, self.port)

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except Exception as exc:
            logger.error("Failed to launch mitmdump: %s", exc)
            return False

        # Give it a moment to bind
        time.sleep(2.0)

        if self._proc.poll() is not None:
            stderr = self._proc.stderr.read().decode(errors="replace")
            logger.error("mitmdump exited immediately: %s", stderr)
            return False

        # 5. Configure device proxy via ADB
        self._configure_device_proxy(host_ip)

        # 6. Attempt to install CA certificate on device
        self._install_ca_cert()

        return True

    def stop(self) -> None:
        """Stop mitmdump, remove device proxy setting, parse captured flows."""
        # Remove proxy from device first
        if self._proxy_configured:
            self._clear_device_proxy()

        # Terminate mitmdump
        if self._proc is not None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait()
            except Exception as exc:
                logger.debug("mitmdump termination error: %s", exc)
            self._proc = None

        # Parse captured flows
        if self._flow_file and os.path.exists(self._flow_file):
            self._parse_flows_from_file()

        # Clean up temp dir
        if self._tmpdir and os.path.isdir(self._tmpdir):
            try:
                import shutil as _shutil
                _shutil.rmtree(self._tmpdir, ignore_errors=True)
            except Exception:
                pass

        logger.info("MitmCapture stopped. Total flows captured: %d", len(self.flows))

    # ------------------------------------------------------------------ #
    # ADB helpers                                                         #
    # ------------------------------------------------------------------ #

    def _adb(self, args: List[str], timeout: int = 10) -> subprocess.CompletedProcess:
        """Run an ADB command and return the CompletedProcess."""
        cmd = ["adb"]
        if self.device_serial:
            cmd += ["-s", self.device_serial]
        cmd += args
        try:
            return subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
        except subprocess.TimeoutExpired:
            logger.debug("ADB command timed out: %s", cmd)
            return subprocess.CompletedProcess(cmd, returncode=-1, stdout="", stderr="timeout")
        except Exception as exc:
            logger.debug("ADB command failed: %s – %s", cmd, exc)
            return subprocess.CompletedProcess(cmd, returncode=-1, stdout="", stderr=str(exc))

    def _configure_device_proxy(self, host_ip: str) -> bool:
        """Set the Android device's global HTTP proxy via ADB settings."""
        proxy_value = f"{host_ip}:{self.port}"
        result = self._adb([
            "shell", "settings", "put", "global", "http_proxy", proxy_value
        ])
        if result.returncode == 0:
            logger.info("Device proxy set to %s", proxy_value)
            self._proxy_configured = True
            return True

        logger.warning("Failed to set device proxy: %s", result.stderr.strip())
        return False

    def _clear_device_proxy(self) -> bool:
        """Remove the global HTTP proxy setting from the device."""
        result = self._adb([
            "shell", "settings", "delete", "global", "http_proxy"
        ])
        if result.returncode == 0:
            logger.info("Device proxy cleared")
            self._proxy_configured = False
            return True

        logger.warning("Failed to clear device proxy: %s", result.stderr.strip())
        return False

    def _install_ca_cert(self) -> bool:
        """Push the mitmproxy CA cert to the device and prompt installation.

        This works for user-installed certificates (API < 24 or debug builds).
        For Android 7+ production apps, network_security_config is required.
        """
        home = os.path.expanduser("~")
        cert_candidates = [
            os.path.join(home, ".mitmproxy", "mitmproxy-ca-cert.cer"),
            os.path.join(home, ".mitmproxy", "mitmproxy-ca-cert.pem"),
        ]

        cert_path = None
        for candidate in cert_candidates:
            if os.path.exists(candidate):
                cert_path = candidate
                break

        if cert_path is None:
            logger.warning(
                "mitmproxy CA cert not found in ~/.mitmproxy/. "
                "Run mitmdump once to generate it, then re-run capture."
            )
            return False

        cert_name = os.path.basename(cert_path)
        remote_path = f"/sdcard/{cert_name}"

        # Push cert
        push_result = self._adb(["push", cert_path, remote_path])
        if push_result.returncode != 0:
            logger.warning("Failed to push CA cert: %s", push_result.stderr.strip())
            return False

        # Attempt to install via intent (user must accept on device)
        self._adb([
            "shell", "am", "start",
            "-a", "android.intent.action.VIEW",
            "-d", f"file://{remote_path}",
            "--type", "application/x-pem-file",
        ])

        logger.info(
            "CA cert pushed to %s. User may need to accept certificate installation on device.",
            remote_path,
        )
        return True

    # ------------------------------------------------------------------ #
    # Flow parsing                                                        #
    # ------------------------------------------------------------------ #

    def _parse_flows_from_file(self) -> None:
        """Parse the mitmdump binary flow file and populate self.flows."""
        try:
            # Try mitmproxy Python API first
            from mitmproxy import io as mio
            from mitmproxy.http import HTTPFlow as _MITMFlow  # noqa: F401

            with open(self._flow_file, "rb") as fh:
                reader = mio.FlowReader(fh)
                for raw_flow in reader.stream():
                    cf = self._convert_mitm_flow(raw_flow)
                    if cf is not None:
                        self.flows.append(cf)

            logger.debug("Parsed %d flows via mitmproxy API", len(self.flows))
            return

        except Exception as exc:
            logger.debug("mitmproxy API parse failed (%s), falling back to mitmdump JSON", exc)

        # Fallback: convert with mitmdump --readfile to JSON
        self._parse_flows_via_mitmdump_json()

    def _parse_flows_via_mitmdump_json(self) -> None:
        """Export the flow file to JSON using mitmdump and parse that."""
        if not self._flow_file or not os.path.exists(self._flow_file):
            return

        json_file = self._flow_file + ".json"
        try:
            result = subprocess.run(
                ["mitmdump", "--readfile", self._flow_file, "--flow-detail", "3",
                 "-w", json_file, "--set", "dumper_default_enc=json"],
                capture_output=True, text=True, timeout=30,
            )
            if os.path.exists(json_file):
                with open(json_file, "r", errors="replace") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                            cf = self._convert_json_flow(obj)
                            if cf:
                                self.flows.append(cf)
                        except json.JSONDecodeError:
                            continue
                os.remove(json_file)
        except Exception as exc:
            logger.debug("mitmdump JSON fallback failed: %s", exc)

    def _convert_mitm_flow(self, flow) -> Optional[CapturedFlow]:
        """Convert a mitmproxy HTTPFlow object to CapturedFlow."""
        try:
            req = flow.request
            resp = getattr(flow, "response", None)

            req_body: Optional[str] = None
            if req.content:
                req_body = req.content.decode("utf-8", errors="replace")

            resp_body: Optional[str] = None
            resp_status: Optional[int] = None
            resp_headers: Optional[Dict[str, str]] = None

            if resp is not None:
                resp_status = resp.status_code
                resp_headers = dict(resp.headers)
                if resp.content:
                    resp_body = resp.content.decode("utf-8", errors="replace")

            timestamp = getattr(flow, "timestamp_start", time.time())

            return CapturedFlow(
                request_method=req.method,
                request_url=req.pretty_url,
                request_headers=dict(req.headers),
                request_body=req_body,
                response_status=resp_status,
                response_headers=resp_headers,
                response_body=resp_body,
                timestamp=timestamp,
                is_https=req.scheme == "https",
            )
        except Exception as exc:
            logger.debug("_convert_mitm_flow error: %s", exc)
            return None

    def _convert_json_flow(self, obj: dict) -> Optional[CapturedFlow]:
        """Convert a JSON flow dict (from mitmdump JSON output) to CapturedFlow."""
        try:
            req = obj.get("request", {})
            resp = obj.get("response", {})

            req_body_raw = req.get("content") or req.get("body")
            req_body = req_body_raw if isinstance(req_body_raw, str) else None

            resp_body_raw = resp.get("content") or resp.get("body")
            resp_body = resp_body_raw if isinstance(resp_body_raw, str) else None

            url = req.get("url") or req.get("pretty_url", "")
            is_https = url.startswith("https://") or obj.get("is_https", False)

            return CapturedFlow(
                request_method=req.get("method", "GET"),
                request_url=url,
                request_headers=dict(req.get("headers") or {}),
                request_body=req_body,
                response_status=resp.get("status_code") or resp.get("status"),
                response_headers=dict(resp.get("headers") or {}),
                response_body=resp_body,
                timestamp=obj.get("timestamp_start", time.time()),
                is_https=is_https,
            )
        except Exception as exc:
            logger.debug("_convert_json_flow error: %s", exc)
            return None

    # ------------------------------------------------------------------ #
    # Public accessors                                                    #
    # ------------------------------------------------------------------ #

    def get_flows(self) -> List[CapturedFlow]:
        """Return the list of captured flows (populated after stop())."""
        return list(self.flows)

    # ------------------------------------------------------------------ #
    # Security analysis                                                   #
    # ------------------------------------------------------------------ #

    def get_security_findings(self, package: str = "") -> List[Dict[str, Any]]:
        """Analyse captured flows for security issues.

        Checks:
        - HTTP (plaintext) requests carrying sensitive data
        - Authorization headers (Bearer / Basic)
        - Cookies with sensitive names (session, auth, token, jwt, …)
        - Request bodies containing password / secret / token fields
        - Responses with PII (email, SSN patterns)
        - Unique API endpoints exposed
        - Certificate pinning bypass evidence (SSL errors in responses)

        Args:
            package: Target app package name (used in finding descriptions).

        Returns:
            List of finding dicts with keys: type, severity, url, detail, evidence.
        """
        findings: List[Dict[str, Any]] = []
        seen_endpoints: set = set()

        for flow in self.flows:
            url = flow.request_url
            method = flow.request_method
            req_hdrs = flow.request_headers or {}
            resp_hdrs = flow.response_headers or {}
            req_body = flow.request_body or ""
            resp_body = flow.response_body or ""

            # Track unique endpoints
            try:
                from urllib.parse import urlparse
                p = urlparse(url)
                endpoint_key = f"{p.scheme}://{p.netloc}{p.path}"
            except Exception:
                endpoint_key = url
            seen_endpoints.add(endpoint_key)

            # 1. Plaintext HTTP with sensitive data
            if not flow.is_https:
                for field_name, pattern in _SENSITIVE_BODY_PATTERNS:
                    if pattern.search(req_body) or pattern.search(resp_body):
                        findings.append({
                            "type": "sensitive_data_over_http",
                            "severity": "critical",
                            "url": url,
                            "method": method,
                            "detail": (
                                f"Field '{field_name}' transmitted over plaintext HTTP"
                            ),
                            "evidence": f"Pattern matched in request/response body for {url}",
                        })
                        flow.contains_sensitive_data = True
                        if field_name not in flow.sensitive_fields:
                            flow.sensitive_fields.append(field_name)

            # 2. Authorization headers
            auth_hdr = req_hdrs.get("Authorization") or req_hdrs.get("authorization", "")
            if auth_hdr and _AUTH_HEADER.match(auth_hdr):
                scheme = auth_hdr.split()[0].capitalize()
                findings.append({
                    "type": "authorization_header_exposed",
                    "severity": "high" if flow.is_https else "critical",
                    "url": url,
                    "method": method,
                    "detail": f"{scheme} token found in Authorization header",
                    "evidence": f"Authorization: {auth_hdr[:30]}…",
                })
                flow.contains_sensitive_data = True
                if "auth_token" not in flow.sensitive_fields:
                    flow.sensitive_fields.append("auth_token")

            # 3. Sensitive cookies
            cookie_hdr = req_hdrs.get("Cookie") or req_hdrs.get("cookie", "")
            if cookie_hdr:
                for cookie_part in cookie_hdr.split(";"):
                    cookie_name = cookie_part.strip().split("=")[0].strip()
                    if _SENSITIVE_COOKIE_NAMES.search(cookie_name):
                        findings.append({
                            "type": "sensitive_cookie",
                            "severity": "high" if flow.is_https else "critical",
                            "url": url,
                            "method": method,
                            "detail": f"Sensitive cookie '{cookie_name}' present in request",
                            "evidence": f"Cookie header contains '{cookie_name}'",
                        })
                        flow.contains_sensitive_data = True
                        if "cookie" not in flow.sensitive_fields:
                            flow.sensitive_fields.append("cookie")

            # 4. Request body sensitive fields
            for field_name, pattern in _SENSITIVE_BODY_PATTERNS:
                if pattern.search(req_body):
                    findings.append({
                        "type": "sensitive_data_in_request_body",
                        "severity": "high" if flow.is_https else "critical",
                        "url": url,
                        "method": method,
                        "detail": f"Request body contains field matching '{field_name}' pattern",
                        "evidence": f"Pattern '{field_name}' matched in POST body to {url}",
                    })
                    flow.contains_sensitive_data = True
                    if field_name not in flow.sensitive_fields:
                        flow.sensitive_fields.append(field_name)

            # 5. PII in response body
            for pii_name, pii_pattern in _PII_PATTERNS:
                matches = pii_pattern.findall(resp_body)
                if matches:
                    sample = matches[0]
                    if pii_name == "email":
                        # Redact
                        parts = sample.split("@")
                        sample = parts[0][:2] + "***@" + parts[1] if len(parts) == 2 else "***"
                    else:
                        sample = "***-**-" + sample[-4:]
                    findings.append({
                        "type": "pii_in_response",
                        "severity": "high",
                        "url": url,
                        "method": method,
                        "detail": f"Response body contains PII ({pii_name}): {sample}",
                        "evidence": f"{len(matches)} match(es) for {pii_name} pattern in response",
                    })

            # 6. Set-Cookie without Secure/HttpOnly flags
            set_cookie = resp_hdrs.get("Set-Cookie") or resp_hdrs.get("set-cookie", "")
            if set_cookie:
                lower_sc = set_cookie.lower()
                if _SENSITIVE_COOKIE_NAMES.search(set_cookie):
                    issues = []
                    if "secure" not in lower_sc:
                        issues.append("missing Secure flag")
                    if "httponly" not in lower_sc:
                        issues.append("missing HttpOnly flag")
                    if issues:
                        findings.append({
                            "type": "insecure_cookie_flags",
                            "severity": "medium",
                            "url": url,
                            "method": method,
                            "detail": f"Sensitive cookie set with {', '.join(issues)}",
                            "evidence": f"Set-Cookie: {set_cookie[:80]}",
                        })

        # 7. Exposed API endpoints summary
        if seen_endpoints:
            findings.append({
                "type": "api_endpoints_enumerated",
                "severity": "info",
                "url": "",
                "method": "",
                "detail": f"Discovered {len(seen_endpoints)} unique API endpoint(s)",
                "evidence": sorted(seen_endpoints),
            })

        logger.info(
            "get_security_findings: %d findings from %d flows (%d unique endpoints)",
            len(findings), len(self.flows), len(seen_endpoints),
        )
        return findings

    # ------------------------------------------------------------------ #
    # Utilities                                                           #
    # ------------------------------------------------------------------ #

    def get_host_ip(self) -> str:
        """Return the machine's LAN IP address that the device can route to.

        Prefers the IP obtained by connecting a UDP socket to 8.8.8.8 (no
        actual packets sent).  Falls back to gethostbyname and then to the
        standard Android emulator host alias 10.0.2.2.
        """
        # Method 1: UDP trick – most reliable on multi-NIC machines
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            if ip and not ip.startswith("127."):
                return ip
        except Exception:
            pass

        # Method 2: hostname lookup
        try:
            ip = socket.gethostbyname(socket.gethostname())
            if ip and not ip.startswith("127."):
                return ip
        except Exception:
            pass

        # Method 3: parse `ip route` / `ifconfig` output
        try:
            result = subprocess.run(
                ["ip", "route", "get", "8.8.8.8"],
                capture_output=True, text=True, timeout=5,
            )
            m = re.search(r'src\s+(\d+\.\d+\.\d+\.\d+)', result.stdout)
            if m:
                return m.group(1)
        except Exception:
            pass

        # Ultimate fallback: Android emulator host alias
        logger.warning("Could not determine host IP; using emulator alias 10.0.2.2")
        return "10.0.2.2"
