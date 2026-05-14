"""mitmproxy management for traffic interception."""

import os
import time
import signal
import logging
import subprocess
import threading
import tempfile
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Callable
from pathlib import Path

from ..device.base import DeviceInterface
from ..exceptions import ProxyError, ProxyNotAvailableError, ProxyConfigError

logger = logging.getLogger(__name__)


# Check for mitmproxy availability
_MITMPROXY_AVAILABLE = False
try:
    import mitmproxy
    from mitmproxy import options
    from mitmproxy.tools import dump
    _MITMPROXY_AVAILABLE = True
except ImportError:
    mitmproxy = None


def is_mitmproxy_available() -> bool:
    """Check if mitmproxy is available."""
    return _MITMPROXY_AVAILABLE


@dataclass
class HTTPFlow:
    """Represents an HTTP request/response flow."""
    timestamp: float
    method: str
    url: str
    host: str
    path: str
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: Optional[bytes] = None
    status_code: Optional[int] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: Optional[bytes] = None
    content_type: Optional[str] = None
    is_https: bool = False
    client_ip: str = ""
    duration: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp,
            "method": self.method,
            "url": self.url,
            "host": self.host,
            "path": self.path,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "is_https": self.is_https,
            "request_size": len(self.request_body) if self.request_body else 0,
            "response_size": len(self.response_body) if self.response_body else 0,
            "duration": self.duration,
        }


class ProxyManager:
    """Manage mitmproxy for traffic interception."""

    def __init__(self, device: DeviceInterface,
                 host: str = "0.0.0.0",
                 port: int = 8080):
        self._device = device
        self._host = host
        self._port = port
        self._process: Optional[subprocess.Popen] = None
        self._flows: List[HTTPFlow] = []
        self._running = False
        self._flow_file: Optional[str] = None
        self._lock = threading.Lock()
        self._callbacks: List[Callable[[HTTPFlow], None]] = []

    def is_available(self) -> bool:
        """Check if proxy can be started."""
        return is_mitmproxy_available()

    def start(self, capture_bodies: bool = True) -> bool:
        """Start the proxy server.

        Args:
            capture_bodies: Whether to capture request/response bodies.

        Returns:
            True if started successfully.
        """
        if self._running:
            return True

        if not is_mitmproxy_available():
            logger.warning("mitmproxy not available")
            return False

        try:
            # Create temp directory for flow file
            self._flow_file = tempfile.mktemp(suffix='.flow')

            # Start mitmproxy in dump mode
            cmd = [
                "mitmdump",
                "-p", str(self._port),
                "--listen-host", self._host,
                "-w", self._flow_file,
                "--set", "block_global=false",
            ]

            if not capture_bodies:
                cmd.extend(["--set", "flow_detail=1"])

            logger.info(f"Starting proxy on {self._host}:{self._port}")

            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            # Wait for proxy to start
            time.sleep(2)

            if self._process.poll() is None:
                self._running = True
                logger.info("Proxy started successfully")
                return True
            else:
                stderr = self._process.stderr.read().decode()
                logger.error(f"Proxy failed to start: {stderr}")
                return False

        except FileNotFoundError:
            logger.error("mitmdump not found. Install mitmproxy.")
            return False
        except Exception as e:
            logger.error(f"Failed to start proxy: {e}")
            return False

    def stop(self) -> List[HTTPFlow]:
        """Stop the proxy and return captured flows.

        Returns:
            List of captured HTTPFlow objects.
        """
        if not self._running:
            return self._flows

        self._running = False

        # Terminate proxy process
        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self._process = None

        # Parse captured flows
        if self._flow_file and os.path.exists(self._flow_file):
            self._parse_flows()
            os.remove(self._flow_file)

        logger.info(f"Proxy stopped. Captured {len(self._flows)} flows.")
        return self._flows

    def configure_device(self) -> bool:
        """Configure device to use proxy.

        Returns:
            True if configured successfully.
        """
        # Get host machine's IP address
        import socket
        try:
            # Get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            host_ip = s.getsockname()[0]
            s.close()
        except Exception:
            host_ip = "10.0.2.2"  # Android emulator host

        # Set proxy on device
        success = self._device.set_proxy(host_ip, self._port)

        if success:
            logger.info(f"Device proxy set to {host_ip}:{self._port}")
        else:
            logger.error("Failed to configure device proxy")

        return success

    def clear_device_proxy(self) -> bool:
        """Clear proxy settings from device."""
        return self._device.clear_proxy()

    def get_flows(self, host_filter: Optional[str] = None) -> List[HTTPFlow]:
        """Get captured flows.

        Args:
            host_filter: Filter by host (optional).

        Returns:
            List of HTTPFlow objects.
        """
        with self._lock:
            flows = self._flows.copy()

        if host_filter:
            flows = [f for f in flows if host_filter in f.host]

        return flows

    def get_flow_count(self) -> int:
        """Get number of captured flows."""
        return len(self._flows)

    def add_callback(self, callback: Callable[[HTTPFlow], None]):
        """Add callback for new flows."""
        self._callbacks.append(callback)

    def _parse_flows(self):
        """Parse flows from mitmproxy flow file."""
        if not self._flow_file or not os.path.exists(self._flow_file):
            return

        try:
            from mitmproxy import io as mio

            with open(self._flow_file, "rb") as f:
                reader = mio.FlowReader(f)
                for flow in reader.stream():
                    http_flow = self._convert_flow(flow)
                    if http_flow:
                        with self._lock:
                            self._flows.append(http_flow)

        except Exception as e:
            logger.error(f"Failed to parse flows: {e}")

    def _convert_flow(self, flow) -> Optional[HTTPFlow]:
        """Convert mitmproxy flow to HTTPFlow."""
        try:
            request = flow.request
            response = flow.response

            http_flow = HTTPFlow(
                timestamp=flow.timestamp_start,
                method=request.method,
                url=request.pretty_url,
                host=request.host,
                path=request.path,
                request_headers=dict(request.headers),
                request_body=request.content,
                is_https=request.scheme == "https",
                client_ip=flow.client_conn.address[0] if flow.client_conn else "",
            )

            if response:
                http_flow.status_code = response.status_code
                http_flow.response_headers = dict(response.headers)
                http_flow.response_body = response.content
                http_flow.content_type = response.headers.get("content-type")
                http_flow.duration = (flow.timestamp_end or 0) - flow.timestamp_start

            return http_flow

        except Exception as e:
            logger.debug(f"Failed to convert flow: {e}")
            return None

    def export_flows(self, output_path: str, format: str = "json") -> bool:
        """Export captured flows to file.

        Args:
            output_path: Output file path.
            format: Export format ('json', 'har', 'csv').

        Returns:
            True if exported successfully.
        """
        flows = self.get_flows()

        try:
            if format == "json":
                import json
                data = [f.to_dict() for f in flows]
                with open(output_path, 'w') as f:
                    json.dump(data, f, indent=2)

            elif format == "har":
                har = self._to_har(flows)
                import json
                with open(output_path, 'w') as f:
                    json.dump(har, f, indent=2)

            elif format == "csv":
                import csv
                with open(output_path, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=[
                        'timestamp', 'method', 'url', 'host', 'status_code',
                        'content_type', 'request_size', 'response_size', 'duration'
                    ])
                    writer.writeheader()
                    for flow in flows:
                        writer.writerow(flow.to_dict())

            else:
                logger.error(f"Unknown export format: {format}")
                return False

            logger.info(f"Exported {len(flows)} flows to {output_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to export flows: {e}")
            return False

    def _to_har(self, flows: List[HTTPFlow]) -> Dict:
        """Convert flows to HAR format."""
        entries = []

        for flow in flows:
            entry = {
                "startedDateTime": time.strftime(
                    "%Y-%m-%dT%H:%M:%S.000Z",
                    time.gmtime(flow.timestamp)
                ),
                "time": flow.duration * 1000,
                "request": {
                    "method": flow.method,
                    "url": flow.url,
                    "headers": [{"name": k, "value": v}
                               for k, v in flow.request_headers.items()],
                    "bodySize": len(flow.request_body) if flow.request_body else 0,
                },
                "response": {
                    "status": flow.status_code or 0,
                    "headers": [{"name": k, "value": v}
                               for k, v in flow.response_headers.items()],
                    "bodySize": len(flow.response_body) if flow.response_body else 0,
                    "content": {
                        "size": len(flow.response_body) if flow.response_body else 0,
                        "mimeType": flow.content_type or "",
                    },
                },
            }
            entries.append(entry)

        return {
            "log": {
                "version": "1.2",
                "creator": {
                    "name": "MSRA",
                    "version": "2.0"
                },
                "entries": entries
            }
        }

    def get_ca_cert_path(self) -> Optional[str]:
        """Get path to mitmproxy CA certificate."""
        # Default mitmproxy CA location
        home = os.path.expanduser("~")
        ca_path = os.path.join(home, ".mitmproxy", "mitmproxy-ca-cert.pem")

        if os.path.exists(ca_path):
            return ca_path

        # Try DER format
        der_path = os.path.join(home, ".mitmproxy", "mitmproxy-ca-cert.cer")
        if os.path.exists(der_path):
            return der_path

        return None

    @property
    def is_running(self) -> bool:
        """Check if proxy is running."""
        return self._running and self._process is not None and self._process.poll() is None
