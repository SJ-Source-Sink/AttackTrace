"""
Nmap network scanner API — runs nmap and streams results via SSE.
"""

import asyncio
import json
import re
import shutil
import subprocess
import uuid
from datetime import datetime, timezone
from typing import Annotated, AsyncGenerator

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.dependencies import get_current_org_id, get_current_user, require_tool
from app.models.db.audit import AuditLog
from app.models.db.user import User

router = APIRouter(prefix="/nmap", tags=["Nmap"])

# In-memory scan history (per process lifetime — good enough for a scanner tool)
_scan_history: dict[str, dict] = {}

# ── Nuclei tag suggestions per open port ──────────────────────────────────────

PORT_TO_NUCLEI_TAGS: dict[int, list[str]] = {
    22: ["ssh"],
    25: ["smtp"],
    80: ["http", "web"],
    443: ["ssl", "tls", "https"],
    3306: ["mysql", "databases"],
    5432: ["postgresql", "databases"],
    6379: ["redis", "network"],
    27017: ["mongodb", "databases"],
    8080: ["http", "web"],
    8443: ["ssl", "tls"],
    9200: ["elasticsearch", "network"],
}


def _suggest_nuclei_tags(hosts: list[dict]) -> list[str]:
    """Return a deduplicated, sorted list of nuclei tags for all open ports found."""
    tags: set[str] = set()
    for host in hosts:
        for port_info in host.get("ports", []):
            if port_info.get("state") == "open":
                port_num = port_info.get("port")
                if port_num in PORT_TO_NUCLEI_TAGS:
                    tags.update(PORT_TO_NUCLEI_TAGS[port_num])
    return sorted(tags)

SCAN_PRESETS: dict[str, list[str]] = {
    "quick": ["-T4", "-F"],
    "full_port": ["-T4", "-p-"],
    "service_version": ["-sV", "-T4"],
    "os_detection": ["-O", "-T4"],
    "stealth_syn": ["-sS", "-T4"],
    "aggressive": ["-A", "-T4"],
    "custom": [],
}

# Presets that send raw packets — require CAP_NET_RAW or root
_ROOT_REQUIRED_PRESETS = {"stealth_syn", "os_detection"}


def _has_raw_socket_capability() -> bool:
    """Return True if process can open raw sockets (root, setcap, or CAP_NET_RAW)."""
    import os, socket
    if os.geteuid() == 0:
        return True
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.close()
        return True
    except PermissionError:
        return False
    except Exception:
        return False


class NmapScanRequest(BaseModel):
    target: str
    scan_type: str = "quick"
    ports: str | None = None
    timing: str = "T4"
    custom_flags: str | None = None

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Target is required")
        # Basic sanity — block shell metacharacters
        if re.search(r"[;&|`$(){}<>]", v):
            raise ValueError("Target contains invalid characters")
        return v

    @field_validator("timing")
    @classmethod
    def validate_timing(cls, v: str) -> str:
        if not re.match(r"^T[0-5]$", v):
            raise ValueError("Timing must be T0–T5")
        return v

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip()
        if v and not re.match(r"^[\d,\-]+$", v):
            raise ValueError("Ports must be numbers, commas, or ranges (e.g. 80,443,1-1024)")
        return v or None

    @field_validator("custom_flags")
    @classmethod
    def validate_custom_flags(cls, v: str | None) -> str | None:
        if v is None:
            return v
        # Block dangerous shell chars
        if re.search(r"[;&|`$(){}<>]", v or ""):
            raise ValueError("Custom flags contain invalid characters")
        return v


def _build_nmap_cmd(req: NmapScanRequest) -> list[str]:
    nmap_bin = shutil.which("nmap") or "nmap"
    cmd = [nmap_bin]

    if req.scan_type in SCAN_PRESETS and req.scan_type != "custom":
        cmd.extend(SCAN_PRESETS[req.scan_type])
    elif req.custom_flags:
        cmd.extend(req.custom_flags.split())

    # Override timing if explicit
    cmd = [c for c in cmd if not c.startswith("-T")]
    cmd.append(f"-{req.timing}")

    if req.ports:
        cmd.extend(["-p", req.ports])

    # Use system DNS resolver — nmap's built-in resolver can fail in subprocess envs
    cmd.append("--system-dns")
    cmd.append(req.target)
    return cmd


def _parse_nmap_output(raw: str) -> list[dict]:
    """Parse nmap text output into structured host/port/service records."""
    hosts = []
    current_host: dict | None = None

    for line in raw.splitlines():
        line = line.strip()

        host_match = re.match(r"Nmap scan report for (.+)", line)
        if host_match:
            if current_host:
                hosts.append(current_host)
            current_host = {
                "host": host_match.group(1),
                "ports": [],
                "os": None,
                "status": "up",
            }
            continue

        if current_host is None:
            continue

        # Port line: 80/tcp   open   http    Apache httpd 2.4
        port_match = re.match(
            r"(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)?\s*(.*)?", line
        )
        if port_match:
            current_host["ports"].append(
                {
                    "port": int(port_match.group(1)),
                    "protocol": port_match.group(2),
                    "state": port_match.group(3),
                    "service": port_match.group(4) or "",
                    "version": port_match.group(5).strip() if port_match.group(5) else "",
                }
            )
            continue

        # OS detection
        os_match = re.match(r"OS details: (.+)", line)
        if os_match and current_host:
            current_host["os"] = os_match.group(1)

    if current_host:
        hosts.append(current_host)

    return hosts


async def _stream_nmap(scan_id: str, req: NmapScanRequest, request: Request) -> AsyncGenerator[str, None]:
    cmd = _build_nmap_cmd(req)

    def _sse(event: str, data: dict) -> str:
        return f"event: {event}\ndata: {json.dumps(data)}\n\n"

    yield _sse("start", {
        "scan_id": scan_id,
        "command": " ".join(cmd),
        "target": req.target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    _scan_history[scan_id] = {
        "id": scan_id,
        "target": req.target,
        "command": " ".join(cmd),
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "raw": "",
        "hosts": [],
    }

    raw_output = []
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

        if proc.stdout is None:
            raise RuntimeError("Failed to open subprocess stdout pipe")
        async for line_bytes in proc.stdout:
            line = line_bytes.decode("utf-8", errors="replace").rstrip()
            if await request.is_disconnected():
                proc.terminate()
                return
            raw_output.append(line)
            yield _sse("output", {"line": line})
            await asyncio.sleep(0)

        await proc.wait()
        raw = "\n".join(raw_output)
        hosts = _parse_nmap_output(raw)

        suggested_tags = _suggest_nuclei_tags(hosts)

        _scan_history[scan_id].update({
            "status": "completed" if proc.returncode == 0 else "failed",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "raw": raw,
            "hosts": hosts,
            "exit_code": proc.returncode,
            "suggested_nuclei_tags": suggested_tags,
        })

        yield _sse("complete", {
            "scan_id": scan_id,
            "hosts": hosts,
            "exit_code": proc.returncode,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "suggested_nuclei_tags": suggested_tags,
        })

    except Exception as exc:
        _scan_history[scan_id].update({"status": "failed", "error": str(exc)})
        yield _sse("error", {"message": str(exc)})


@router.post("/scan", summary="Run an nmap scan and stream results")
async def run_nmap_scan(
    payload: NmapScanRequest,
    request: Request,
    current_user: Annotated[User, Depends(require_tool("nmap"))],
    org_id: uuid.UUID = Depends(get_current_org_id),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    if not shutil.which("nmap"):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="nmap is not installed on this server",
        )
    if payload.scan_type in _ROOT_REQUIRED_PRESETS and not _has_raw_socket_capability():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Scan type '{payload.scan_type}' requires raw socket privileges (CAP_NET_RAW). "
                "Fix options: (1) run `sudo setcap cap_net_raw,cap_net_admin=eip $(which nmap)` on the server, "
                "(2) add `cap_add: [NET_RAW, NET_ADMIN]` to the Docker Compose service, "
                "or (3) run the backend as root. Use 'quick', 'full_port', or 'service_version' scans without root."
            ),
        )
    scan_id = str(uuid.uuid4())

    log = AuditLog(
        org_id=org_id,
        user_id=current_user.id,
        action="tool.nmap.scan",
        resource_type="nmap_scan",
        resource_id=scan_id,
        after_state={"target": payload.target, "scan_type": payload.scan_type},
        ip_address=request.client.host if request.client else None,
    )
    db.add(log)
    await db.commit()

    return StreamingResponse(
        _stream_nmap(scan_id, payload, request),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/scans", summary="List nmap scan history")
async def list_nmap_scans(
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict:
    scans = sorted(
        _scan_history.values(),
        key=lambda s: s.get("started_at", ""),
        reverse=True,
    )
    return {"items": scans, "total": len(scans)}


@router.get("/scans/{scan_id}", summary="Get nmap scan result")
async def get_nmap_scan(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict:
    scan = _scan_history.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan
