"""
Nmap network scanner API — runs nmap and streams results via SSE.
"""

import asyncio
import ipaddress
import json
import re
import shutil
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, AsyncGenerator

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.target_guard import guard_scan_target
from app.core.config import get_settings as _get_settings
from app.core.database import get_db
from app.core.dependencies import get_current_org_id, get_current_user, require_tool
from app.core.scan_args import reject_option_like, validate_nmap_flags
from app.models.db.asset import AssetType
from app.models.db.audit import AuditLog
from app.models.db.user import User
from app.services.asset_upsert import upsert_asset_async
from app.services.enrichment_service import enrich_cve, batch_enrich_cves, get_kev_catalog


# ── Filesystem history (org-scoped) — same pattern as secrets.py/cspm.py ─────

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)


def _validate_uuid(value: str, label: str) -> str:
    if not _UUID_RE.match(value):
        raise HTTPException(status_code=400, detail=f"Invalid {label}: must be a UUID")
    return value


def _history_dir(org_id: str) -> Path:
    d = Path(_get_settings().ATTACKTRACE_WORKSPACE_DIR) / "nmap" / org_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def _safe_history_path(org_id: str, scan_id: str) -> Path:
    """Build and confine the history file path to the org's history directory."""
    _validate_uuid(scan_id, "scan_id")
    base = _history_dir(org_id)
    candidate = (base / f"{scan_id}.json").resolve()
    if not candidate.is_relative_to(base.resolve()):
        raise HTTPException(status_code=400, detail="Invalid scan_id")
    return candidate


def _save_scan_result(org_id: str, record: dict) -> None:
    """Persist a completed scan record as JSON."""
    try:
        path = _history_dir(org_id) / f"{record['id']}.json"
        path.write_text(json.dumps(record, ensure_ascii=False))
    except Exception:
        pass


def _load_history(org_id: str, limit: int = 50) -> list[dict]:
    """Load scan history for an org, newest first."""
    try:
        files = sorted(
            _history_dir(org_id).glob("*.json"),
            key=lambda f: f.stat().st_mtime,
            reverse=True,
        )[:limit]
        records = []
        for f in files:
            try:
                records.append(json.loads(f.read_text()))
            except Exception:
                pass
        return records
    except Exception:
        return []


def _load_scan(org_id: str, scan_id: str) -> dict | None:
    """Load a single scan record by ID."""
    try:
        path = _safe_history_path(org_id, scan_id)
        if path.exists():
            return json.loads(path.read_text())
    except HTTPException:
        raise
    except Exception:
        pass
    return None


def _delete_scan(org_id: str, scan_id: str) -> bool:
    try:
        path = _safe_history_path(org_id, scan_id)
        if path.exists():
            path.unlink()
            return True
    except HTTPException:
        raise
    except Exception:
        pass
    return False


_HOST_WITH_RESOLVED_NAME = re.compile(r"^(\S+)\s+\(([0-9a-fA-F:.]+)\)$")


def _clean_host_value(host: str) -> str:
    """nmap's "Nmap scan report for <name>" line becomes "name (ip)" when
    reverse DNS resolves — use just the IP as the canonical asset value so a
    hostname+IP compound string never ends up persisted as one Asset.value."""
    m = _HOST_WITH_RESOLVED_NAME.match(host)
    return m.group(2) if m else host


def _classify_host(host: str) -> AssetType:
    try:
        ipaddress.ip_address(host)
        return AssetType.IP
    except ValueError:
        return AssetType.SUBDOMAIN

_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

router = APIRouter(prefix="/nmap", tags=["Nmap"])

# In-memory scan history (per process lifetime — good enough for a scanner tool)
_scan_history: dict[str, dict] = {}

# ── Nuclei tag suggestions per open port ──────────────────────────────────────

PORT_TO_NUCLEI_TAGS: dict[int, list[str]] = {
    21:    ["ftp", "network"],
    22:    ["ssh"],
    23:    ["telnet", "network"],
    25:    ["smtp"],
    53:    ["dns", "network"],
    80:    ["http", "web"],
    110:   ["pop3", "network"],
    111:   ["rpc", "network"],
    135:   ["rpc", "windows"],
    139:   ["smb", "network"],
    161:   ["snmp", "network"],
    389:   ["ldap", "network"],
    443:   ["ssl", "tls", "https"],
    445:   ["smb", "network", "windows"],
    636:   ["ldap", "network"],
    1433:  ["mssql", "databases"],
    1521:  ["oracle", "databases"],
    3306:  ["mysql", "databases"],
    3389:  ["rdp", "windows"],
    4443:  ["https", "web"],
    5432:  ["postgresql", "databases"],
    5900:  ["vnc", "network"],
    6379:  ["redis", "network"],
    6443:  ["kubernetes", "network"],
    8080:  ["http", "web"],
    8443:  ["ssl", "tls"],
    8888:  ["http", "web"],
    9000:  ["network"],
    9090:  ["http", "web"],
    9200:  ["elasticsearch", "network"],
    27017: ["mongodb", "databases"],
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
    "quick":          ["-T4", "-F"],
    "full_port":      ["-T4", "-p-"],
    "service_version":["-sV", "-T4"],
    "service_enum":   ["-sV", "--script=banner,default", "-T4"],
    "nse_vuln":       ["-sV", "--script=vuln,safe,auth,discovery", "-T4"],
    "os_detection":   ["-O", "-T4"],
    "stealth_syn":    ["-sS", "-T4"],
    "aggressive":     ["-A", "-T4"],
    "custom":         [],
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
    @field_validator("target")
    @classmethod
    def _guard_scan_target(cls, v):
        # Block loopback/private/metadata addresses unless ALLOW_PRIVATE_SCAN_TARGETS (see target_guard)
        return guard_scan_target(v)

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
        return reject_option_like(v)

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
        # Allowlist only: nmap flags like -iL/-oN/--script <path> read or write server files
        validate_nmap_flags(v)
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
    """
    Parse nmap text output into structured host/port/service records.

    Also extracts CVE IDs from NSE script output lines (e.g. vuln scripts).
    Each host gains a top-level ``cve_ids`` list (deduplicated, sorted).
    Each port entry also carries ``nse_scripts`` (list of script output lines)
    and ``cve_ids`` extracted from those scripts.
    """
    hosts: list[dict] = []
    current_host: dict | None = None
    current_port: dict | None = None  # last port we parsed (for NSE output attribution)

    # All CVE IDs seen for the current host (for host-level aggregation)
    host_cves: set[str] = set()

    def _finish_host() -> None:
        nonlocal current_host, current_port, host_cves
        if current_host:
            current_host["cve_ids"] = sorted(host_cves)
            hosts.append(current_host)
        current_host = None
        current_port = None
        host_cves = set()

    for line in raw.splitlines():
        stripped = line.strip()

        host_match = re.match(r"Nmap scan report for (.+)", stripped)
        if host_match:
            _finish_host()
            current_host = {
                "host": host_match.group(1),
                "ports": [],
                "os": None,
                "status": "up",
                "cve_ids": [],
            }
            continue

        if current_host is None:
            continue

        # Port line: 80/tcp   open   http    Apache httpd 2.4
        port_match = re.match(
            r"(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)?\s*(.*)?", stripped
        )
        if port_match:
            current_port = {
                "port": int(port_match.group(1)),
                "protocol": port_match.group(2),
                "state": port_match.group(3),
                "service": port_match.group(4) or "",
                "version": port_match.group(5).strip() if port_match.group(5) else "",
                "nse_scripts": [],
                "cve_ids": [],
            }
            current_host["ports"].append(current_port)
            continue

        # OS detection
        os_match = re.match(r"OS details: (.+)", stripped)
        if os_match:
            current_host["os"] = os_match.group(1)
            continue

        # NSE script output: lines indented under a port OR host-level scripts.
        # NSE lines typically start with "|" or "| " — capture them for CVE extraction.
        if stripped.startswith("|") or stripped.startswith("_"):
            # Extract any CVE IDs from this NSE output line
            cves_in_line = [m.upper() for m in _CVE_PATTERN.findall(stripped)]
            if cves_in_line:
                host_cves.update(cves_in_line)
                if current_port is not None:
                    current_port["cve_ids"] = sorted(
                        set(current_port["cve_ids"]) | set(cves_in_line)
                    )
            # Record the raw NSE line on the current port (if any)
            if current_port is not None:
                current_port["nse_scripts"].append(stripped)

    _finish_host()
    return hosts


async def _stream_nmap(
    scan_id: str, req: NmapScanRequest, request: Request, org_id: uuid.UUID, db: AsyncSession
) -> AsyncGenerator[str, None]:
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
        "org_id": str(org_id),
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

        # Collect all CVE IDs found by NSE scripts across all hosts
        all_nse_cves: list[str] = []
        for host in hosts:
            all_nse_cves.extend(host.get("cve_ids", []))
        all_nse_cves = sorted(set(all_nse_cves))

        # Enrich NSE CVE findings with EPSS + KEV data
        nse_enrichment: dict[str, dict] = {}
        if all_nse_cves:
            try:
                nse_enrichment = await asyncio.wait_for(
                    batch_enrich_cves(all_nse_cves), timeout=15.0
                )
            except (asyncio.TimeoutError, Exception):
                pass  # best-effort; leave empty

        _scan_history[scan_id].update({
            "status": "completed" if proc.returncode == 0 else "failed",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "raw": raw,
            "hosts": hosts,
            "exit_code": proc.returncode,
            "suggested_nuclei_tags": suggested_tags,
            "nse_cve_ids": all_nse_cves,
            "nse_enrichment": nse_enrichment,
        })

        # Persist open ports/services onto the Asset record — this was never
        # written anywhere before (nmap results were SSE-only + an in-memory
        # dict lost on restart), which is also why the network map never had
        # port data to show.
        try:
            for host in hosts:
                open_ports = [
                    {"port": p["port"], "protocol": p["protocol"], "service": p["service"], "version": p["version"]}
                    for p in host.get("ports", [])
                    if p.get("state") == "open"
                ]
                clean_value = _clean_host_value(host["host"])
                await upsert_asset_async(
                    db, org_id, _classify_host(clean_value), clean_value,
                    {"ports": open_ports, "os": host.get("os"), "nmap_cve_ids": host.get("cve_ids", [])},
                )
            await db.commit()
        except Exception:
            await db.rollback()

        # Persist the completed scan to disk — the in-memory dict above is
        # only good for the process lifetime; without this, history was lost
        # on every backend restart.
        _save_scan_result(str(org_id), _scan_history[scan_id])

        yield _sse("complete", {
            "scan_id": scan_id,
            "hosts": hosts,
            "exit_code": proc.returncode,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "suggested_nuclei_tags": suggested_tags,
            "nse_cve_ids": all_nse_cves,
            "nse_enrichment": nse_enrichment,
        })

    except Exception as exc:
        _scan_history[scan_id].update({"status": "failed", "error": str(exc)})
        _save_scan_result(str(org_id), _scan_history[scan_id])
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

    from app.services.scan_activity import tee_scan_activity
    return StreamingResponse(
        tee_scan_activity(org_id, "nmap", payload.target, scan_id, _stream_nmap(scan_id, payload, request, org_id, db)),
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
    org_id: uuid.UUID = Depends(get_current_org_id),
) -> dict:
    scans = sorted(
        (s for s in _scan_history.values() if s.get("org_id") == str(org_id)),
        key=lambda s: s.get("started_at", ""),
        reverse=True,
    )
    return {"items": scans, "total": len(scans)}


@router.get("/scans/{scan_id}", summary="Get nmap scan result")
async def get_nmap_scan(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: uuid.UUID = Depends(get_current_org_id),
) -> dict:
    scan = _scan_history.get(scan_id)
    if not scan or scan.get("org_id") != str(org_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


# ── Filesystem-backed history endpoints (survive backend restarts) ───────────

@router.get("/history", summary="List nmap scan history (disk-persisted)")
async def list_history(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: uuid.UUID = Depends(get_current_org_id),
) -> dict:
    records = _load_history(str(org_id))
    # Lightweight summaries — omit raw output / per-port NSE script text
    summaries = []
    for r in records:
        summaries.append({
            "id": r.get("id"),
            "target": r.get("target"),
            "command": r.get("command"),
            "status": r.get("status"),
            "started_at": r.get("started_at"),
            "completed_at": r.get("completed_at"),
            "host_count": len(r.get("hosts", [])),
            "open_port_count": sum(
                1 for h in r.get("hosts", []) for p in h.get("ports", []) if p.get("state") == "open"
            ),
        })
    return {"items": summaries, "total": len(summaries)}


@router.get("/history/{scan_id}", summary="Get a single nmap scan result (disk-persisted)")
async def get_history_item(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: uuid.UUID = Depends(get_current_org_id),
) -> dict:
    record = _load_scan(str(org_id), scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    return record


@router.delete("/history/{scan_id}", summary="Delete a nmap scan result")
async def delete_history_item(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: uuid.UUID = Depends(get_current_org_id),
) -> dict:
    deleted = _delete_scan(str(org_id), scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"ok": True, "scan_id": scan_id}
