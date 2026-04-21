"""
AttackMapper integration — runs attack path visualizations via the attackmapper CLI
and streams results via SSE.

Commands used:
  attackmapper <infra> --format json -o <file>         → all techniques for infra
  attackmapper full-chain --infra <infra> --format json -o <file>  → full attack chain
  attackmapper threat-intel --infra <infra> --format json -o <file> → threat intel
"""

import asyncio
import json
import os
import shutil
import tempfile
import uuid
from datetime import datetime, timezone
from typing import Annotated, AsyncGenerator

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator

from app.core.dependencies import get_current_user
from app.models.db.user import User

router = APIRouter(prefix="/attackmapper", tags=["AttackMapper"])

# In-memory scan history
_scan_history: dict[str, dict] = {}

INFRA_LABELS: dict[str, str] = {
    "ad": "Active Directory",
    "aws": "Amazon Web Services",
    "azure": "Microsoft Azure",
    "gcp": "Google Cloud Platform",
    "network": "Network Infrastructure",
}

VALID_INFRA = set(INFRA_LABELS.keys())


class AttackMapperRequest(BaseModel):
    infrastructure_type: str
    category: str | None = None
    phase: str | None = None
    search: str | None = None

    @field_validator("infrastructure_type")
    @classmethod
    def validate_infra(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in VALID_INFRA:
            raise ValueError(f"infrastructure_type must be one of: {', '.join(sorted(VALID_INFRA))}")
        return v

    @field_validator("category", "phase", "search")
    @classmethod
    def validate_text_field(cls, v: str | None) -> str | None:
        if v is None:
            return v
        import re
        if re.search(r"[;&|`$(){}<>]", v):
            raise ValueError("Field contains invalid characters")
        return v.strip() or None


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


async def _run_attackmapper_cmd(cmd: list[str], output_file: str) -> dict | None:
    """Run an attackmapper command and return parsed JSON output."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)

        if proc.returncode == 0 and os.path.exists(output_file):
            with open(output_file, "r") as f:
                return json.load(f)
        return None
    except (asyncio.TimeoutError, Exception):
        return None
    finally:
        try:
            if os.path.exists(output_file):
                os.unlink(output_file)
        except OSError:
            pass


async def _stream_attackmapper(scan_id: str, req: AttackMapperRequest) -> AsyncGenerator[str, None]:
    am_bin = shutil.which("attackmapper") or "attackmapper"
    infra = req.infrastructure_type
    infra_label = INFRA_LABELS[infra]

    _scan_history[scan_id] = {
        "id": scan_id,
        "infrastructure_type": infra,
        "infrastructure_label": infra_label,
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "techniques": [],
        "attack_chain": None,
        "threat_intel": None,
    }

    yield _sse("start", {
        "scan_id": scan_id,
        "infrastructure_type": infra,
        "infrastructure_label": infra_label,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    techniques = []
    attack_chain = None
    threat_intel = None
    error_msg = None

    try:
        # ── Step 1: Fetch attack techniques ──────────────────────────────────
        yield _sse("progress", {"message": f"Loading {infra_label} attack techniques..."})

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tech_file = tmp.name

        tech_cmd = [am_bin, infra, "--format", "json", "--output", tech_file]
        if req.category:
            tech_cmd += ["--category", req.category]
        if req.phase:
            tech_cmd += ["--phase", req.phase]
        if req.search:
            tech_cmd += ["--search", req.search]

        tech_data = await _run_attackmapper_cmd(tech_cmd, tech_file)
        if tech_data:
            techniques = tech_data.get("techniques", [])
            yield _sse("progress", {
                "message": f"Loaded {len(techniques)} techniques for {infra_label}",
            })
        else:
            yield _sse("progress", {"message": "Warning: Could not load techniques"})

        await asyncio.sleep(0)

        # ── Step 2: Fetch full attack chain ───────────────────────────────────
        yield _sse("progress", {"message": "Building full attack chain..."})

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            chain_file = tmp.name

        chain_cmd = [am_bin, "full-chain", "--infra", infra, "--format", "json", "--output", chain_file]
        chain_data = await _run_attackmapper_cmd(chain_cmd, chain_file)
        if chain_data:
            attack_chain = chain_data.get("attack_path")
            step_count = len(attack_chain.get("steps", [])) if attack_chain else 0
            yield _sse("progress", {"message": f"Attack chain built: {step_count} steps"})
        else:
            yield _sse("progress", {"message": "Warning: Could not build attack chain"})

        await asyncio.sleep(0)

        # ── Step 3: Fetch threat intelligence ────────────────────────────────
        yield _sse("progress", {"message": "Fetching threat intelligence..."})

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            intel_file = tmp.name

        intel_cmd = [am_bin, "threat-intel", "--infra", infra, "--format", "json", "--output", intel_file]
        intel_data = await _run_attackmapper_cmd(intel_cmd, intel_file)
        if intel_data:
            threat_intel = intel_data.get("threat_intel")
            cve_count = len(threat_intel.get("critical_cves", [])) if threat_intel else 0
            yield _sse("progress", {"message": f"Threat intel loaded: {cve_count} critical CVEs"})
        else:
            yield _sse("progress", {"message": "Warning: Could not load threat intelligence"})

        _scan_history[scan_id].update({
            "status": "completed",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "techniques": techniques,
            "attack_chain": attack_chain,
            "threat_intel": threat_intel,
        })

        yield _sse("complete", {
            "scan_id": scan_id,
            "infrastructure_type": infra,
            "infrastructure_label": infra_label,
            "technique_count": len(techniques),
            "chain_steps": len(attack_chain.get("steps", [])) if attack_chain else 0,
            "critical_cves": len(threat_intel.get("critical_cves", [])) if threat_intel else 0,
            "techniques": techniques,
            "attack_chain": attack_chain,
            "threat_intel": threat_intel,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    except Exception as exc:
        error_msg = str(exc)
        _scan_history[scan_id].update({"status": "failed", "error": error_msg})
        yield _sse("error", {"message": error_msg})


@router.post("/scan", summary="Run an AttackMapper analysis and stream results")
async def run_attackmapper_scan(
    payload: AttackMapperRequest,
    current_user: Annotated[User, Depends(get_current_user)],
) -> StreamingResponse:
    if not shutil.which("attackmapper"):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="attackmapper is not installed on this server",
        )
    scan_id = str(uuid.uuid4())
    return StreamingResponse(
        _stream_attackmapper(scan_id, payload),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/scans", summary="List AttackMapper scan history")
async def list_attackmapper_scans(
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict:
    scans = sorted(
        _scan_history.values(),
        key=lambda s: s.get("started_at", ""),
        reverse=True,
    )
    # Return lightweight summaries (no full technique data)
    summaries = []
    for s in scans:
        summaries.append({
            "id": s["id"],
            "infrastructure_type": s["infrastructure_type"],
            "infrastructure_label": s["infrastructure_label"],
            "status": s["status"],
            "started_at": s.get("started_at"),
            "completed_at": s.get("completed_at"),
            "technique_count": len(s.get("techniques", [])),
            "chain_steps": len(s.get("attack_chain", {}).get("steps", [])) if s.get("attack_chain") else 0,
            "critical_cves": len(s.get("threat_intel", {}).get("critical_cves", [])) if s.get("threat_intel") else 0,
        })
    return {"items": summaries, "total": len(summaries)}


@router.get("/scans/{scan_id}", summary="Get AttackMapper scan result")
async def get_attackmapper_scan(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict:
    scan = _scan_history.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


async def _stream_update_intel() -> AsyncGenerator[str, None]:
    """Stream `attackmapper update-intel` output as SSE progress lines."""
    import re

    am_bin = shutil.which("attackmapper") or "attackmapper"
    items_total = 0
    failed: list[str] = []

    yield _sse("start", {
        "message": "Starting threat intelligence update from internet sources...",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    try:
        proc = await asyncio.create_subprocess_exec(
            am_bin, "update-intel",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        assert proc.stdout is not None
        assert proc.stderr is not None

        # Use a queue so we can interleave stdout + stderr lines
        queue: asyncio.Queue[tuple[str, str] | None] = asyncio.Queue()

        async def enqueue(stream: asyncio.StreamReader) -> None:
            async for raw in stream:
                line = raw.decode("utf-8", errors="replace").rstrip()
                if line:
                    await queue.put(("line", line))
            await queue.put(None)  # sentinel

        t1 = asyncio.create_task(enqueue(proc.stdout))
        t2 = asyncio.create_task(enqueue(proc.stderr))

        sentinels = 0
        while sentinels < 2:
            item = await queue.get()
            if item is None:
                sentinels += 1
                continue
            _, line = item
            icon = "⟳"
            if line.startswith("[+]"):
                icon = "✓"
                m = re.search(r"(\d+) items cached", line)
                if m:
                    items_total += int(m.group(1))
            elif line.startswith("[-]"):
                icon = "✗"
                src = line[4:].split(":")[0].strip()
                if src:
                    failed.append(src)
            elif "Warning" in line:
                icon = "⚠"
            yield _sse("progress", {"line": line, "icon": icon})

        await proc.wait()
        await t1
        await t2

        # Fetch final stats
        stats_proc = await asyncio.create_subprocess_exec(
            am_bin, "stats",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stats_out, _ = await asyncio.wait_for(stats_proc.communicate(), timeout=15)
        stats_text = stats_out.decode("utf-8", errors="replace")

        cached_cves = 0
        last_updated = datetime.now(timezone.utc).isoformat()
        m_cves = re.search(r"Cached CVEs:\s*(\d+)", stats_text)
        m_updated = re.search(r"Last Updated:\s*(\S+)", stats_text)
        if m_cves:
            cached_cves = int(m_cves.group(1))
        if m_updated:
            last_updated = m_updated.group(1)

        yield _sse("complete", {
            "message": "Threat intelligence update complete",
            "items_fetched": items_total,
            "cached_cves": cached_cves,
            "failed_sources": failed,
            "last_updated": last_updated,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    except Exception as exc:
        yield _sse("error", {"message": str(exc)})


@router.post("/update-intel", summary="Update threat intelligence from internet sources (streaming)")
async def update_intel(
    current_user: Annotated[User, Depends(get_current_user)],
) -> StreamingResponse:
    if not shutil.which("attackmapper"):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="attackmapper is not installed on this server",
        )
    return StreamingResponse(
        _stream_update_intel(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


_INTEL_DB = os.path.expanduser("~/.cache/attackmapper/intel_cache.db")


@router.get("/cves", summary="Get CVEs from the local threat intel cache")
async def get_cves(
    current_user: Annotated[User, Depends(get_current_user)],
    infra: str | None = None,
    severity: str | None = None,
    limit: int = 200,
) -> dict:
    """Query the attackmapper SQLite cache for CVEs directly — bypasses the CLI's hardcoded top-10 limit."""
    import sqlite3 as _sqlite3
    import re

    if not os.path.exists(_INTEL_DB):
        return {"items": [], "total": 0, "note": "Intel cache not found — run Update Intel first"}

    try:
        conn = _sqlite3.connect(_INTEL_DB)
        cursor = conn.cursor()

        query = "SELECT cve_id, description, cvss_score, severity, affected_products, affected_infrastructure, exploitation_status, references_json, published_date FROM cves WHERE 1=1"
        params: list = []

        if infra:
            query += ' AND affected_infrastructure LIKE ?'
            params.append(f'%"{infra}"%')

        if severity:
            query += " AND severity = ?"
            params.append(severity.lower())

        query += " ORDER BY cvss_score DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        rows = cursor.fetchall()

        # Count total without limit
        count_q = "SELECT COUNT(*) FROM cves WHERE 1=1"
        count_p: list = []
        if infra:
            count_q += ' AND affected_infrastructure LIKE ?'
            count_p.append(f'%"{infra}"%')
        if severity:
            count_q += " AND severity = ?"
            count_p.append(severity.lower())
        cursor.execute(count_q, count_p)
        total = cursor.fetchone()[0]
        conn.close()

        items = []
        for row in rows:
            try:
                affected_products = json.loads(row[4]) if row[4] else []
            except Exception:
                affected_products = []
            try:
                affected_infra = json.loads(row[5]) if row[5] else []
            except Exception:
                affected_infra = []
            try:
                references = json.loads(row[7]) if row[7] else []
            except Exception:
                references = []
            items.append({
                "cve_id": row[0],
                "description": row[1] or "",
                "cvss_score": row[2] or 0.0,
                "severity": row[3] or "unknown",
                "affected_products": affected_products,
                "affected_infrastructure": affected_infra,
                "exploitation_status": row[6] or "",
                "references": references,
                "published_date": row[8] or "",
            })

        return {"items": items, "total": total, "returned": len(items)}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/stats", summary="Get AttackMapper cache statistics")
async def get_attackmapper_stats(
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict:
    am_bin = shutil.which("attackmapper") or "attackmapper"
    try:
        import re
        proc = await asyncio.create_subprocess_exec(
            am_bin, "stats",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
        text = stdout.decode("utf-8", errors="replace")

        stats: dict = {
            "techniques": {},
            "cached_cves": 0,
            "cached_threat_actors": 0,
            "custom_feeds": 0,
            "last_updated": None,
            "raw": text,
        }

        for line in text.splitlines():
            m = re.match(r"\s*(\w[\w\s]+) Module:\s*(\d+) techniques", line)
            if m:
                stats["techniques"][m.group(1).strip().lower()] = int(m.group(2))
            m2 = re.search(r"Cached CVEs:\s*(\d+)", line)
            if m2:
                stats["cached_cves"] = int(m2.group(1))
            m3 = re.search(r"Cached Threat Actors:\s*(\d+)", line)
            if m3:
                stats["cached_threat_actors"] = int(m3.group(1))
            m4 = re.search(r"Last Updated:\s*(\S+)", line)
            if m4:
                stats["last_updated"] = m4.group(1)

        return stats
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
