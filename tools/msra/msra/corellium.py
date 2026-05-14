"""
Corellium API client for MSRA dynamic analysis.
Supports Android virtual device management, APK installation,
ADB tunnelling, console commands, and network monitoring.
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ── Data Models ───────────────────────────────────────────────────────────────

@dataclass
class CorelliumProject:
    id: str
    name: str


@dataclass
class CorelliumInstance:
    id: str
    name: str
    state: str          # on | off | creating | deleting | restoring | paused
    flavor: str         # device model
    os: str             # e.g. "13.0.0"
    ip: str
    wifi_ip: str
    adb_host: Optional[str] = None
    adb_port: Optional[int] = None

    @property
    def is_on(self) -> bool:
        return self.state == "on"

    @property
    def adb_addr(self) -> Optional[str]:
        if self.adb_host and self.adb_port:
            return f"{self.adb_host}:{self.adb_port}"
        return None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "state": self.state,
            "flavor": self.flavor,
            "os": self.os,
            "ip": self.ip,
            "wifi_ip": self.wifi_ip,
            "adb_host": self.adb_host,
            "adb_port": self.adb_port,
            "adb_addr": self.adb_addr,
        }


# ── Client ────────────────────────────────────────────────────────────────────

class CorelliumClient:
    """Thin wrapper around the Corellium REST API v1."""

    def __init__(self, api_token: str, base_url: str = "https://app.corellium.com"):
        self.api_token = api_token.strip()
        self.base_url  = base_url.rstrip("/")
        self._api      = f"{self.base_url}/api/v1"

    # ── Internal ──────────────────────────────────────────────────────────────

    def _req(self, method: str, path: str, body: Any = None, timeout: int = 30) -> Any:
        url     = f"{self._api}{path}"
        data    = json.dumps(body).encode() if body is not None else None
        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type":  "application/json",
            "Accept":        "application/json",
        }
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Corellium {exc.code}: {detail[:300]}")
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Network error reaching Corellium: {exc.reason}")

    # ── Auth & Status ─────────────────────────────────────────────────────────

    def check_auth(self) -> dict:
        """Verify the API token and return user info."""
        return self._req("GET", "/users/me")

    # ── Projects ──────────────────────────────────────────────────────────────

    def list_projects(self) -> List[CorelliumProject]:
        data = self._req("GET", "/projects")
        return [CorelliumProject(id=p["id"], name=p["name"]) for p in (data or [])]

    # ── Instances ─────────────────────────────────────────────────────────────

    def list_instances(self, project_id: str | None = None) -> List[CorelliumInstance]:
        path = "/instances"
        if project_id:
            path += f"?project={project_id}"
        data = self._req("GET", path) or []
        result = []
        for inst in data:
            if inst.get("type") != "android":
                continue
            result.append(self._parse_instance(inst))
        return result

    def get_instance(self, instance_id: str) -> CorelliumInstance:
        inst = self._req("GET", f"/instances/{instance_id}")
        return self._parse_instance(inst)

    def start_instance(self, instance_id: str):
        return self._req("POST", f"/instances/{instance_id}/start")

    def stop_instance(self, instance_id: str):
        return self._req("POST", f"/instances/{instance_id}/stop")

    def _parse_instance(self, inst: dict) -> CorelliumInstance:
        return CorelliumInstance(
            id       = inst["id"],
            name     = inst.get("name", ""),
            state    = inst.get("state", ""),
            flavor   = inst.get("flavor", ""),
            os       = inst.get("os", ""),
            ip       = inst.get("ip", ""),
            wifi_ip  = inst.get("wifiIp", ""),
            adb_host = inst.get("adbAddr") or None,
            adb_port = inst.get("adbPort") or None,
        )

    # ── App Management ────────────────────────────────────────────────────────

    def list_apps(self, instance_id: str) -> List[dict]:
        return self._req("GET", f"/instances/{instance_id}/agent/v1/app/apps") or []

    def install_app_from_url(self, instance_id: str, url: str) -> dict:
        return self._req("POST", f"/instances/{instance_id}/agent/v1/app/apps",
                         {"url": url}, timeout=120)

    def launch_app(self, instance_id: str, bundle_id: str) -> dict:
        return self._req("POST",
                         f"/instances/{instance_id}/agent/v1/app/apps/{bundle_id}/run")

    def terminate_app(self, instance_id: str, bundle_id: str) -> dict:
        return self._req("POST",
                         f"/instances/{instance_id}/agent/v1/app/apps/{bundle_id}/kill")

    # ── Console / Logcat ─────────────────────────────────────────────────────

    def get_console_log(self, instance_id: str, lines: int = 500) -> str:
        """Fetch recent console/logcat output."""
        try:
            data = self._req("GET",
                             f"/instances/{instance_id}/consoleLog?lines={lines}",
                             timeout=20)
            return data.get("log", "") if isinstance(data, dict) else str(data)
        except Exception:
            return ""

    def run_input(self, instance_id: str, text: str):
        """Type text on the virtual device screen."""
        return self._req("POST", f"/instances/{instance_id}/agent/v1/ui/input",
                         {"text": text})

    # ── Network ───────────────────────────────────────────────────────────────

    def start_network_monitor(self, instance_id: str) -> dict:
        return self._req("POST", f"/instances/{instance_id}/sslsplit/enable")

    def stop_network_monitor(self, instance_id: str) -> dict:
        return self._req("DELETE", f"/instances/{instance_id}/sslsplit/enable")

    def get_network_log(self, instance_id: str) -> List[dict]:
        try:
            return self._req("GET", f"/instances/{instance_id}/netdump") or []
        except Exception:
            return []

    # ── Screenshot ───────────────────────────────────────────────────────────

    def take_screenshot(self, instance_id: str) -> bytes | None:
        """Return raw PNG bytes or None on failure."""
        url     = f"{self._api}/instances/{instance_id}/screenshot.png"
        headers = {"Authorization": f"Bearer {self.api_token}"}
        req     = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.read()
        except Exception:
            return None
