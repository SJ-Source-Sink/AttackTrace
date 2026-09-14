"""
AttackMapper integration — calls the attackmapper Python API directly (no subprocess).
Works on any machine after git pull with no pip install required.
"""

import asyncio
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, AsyncGenerator

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator

from app.core.config import get_settings as _get_settings
from app.core.dependencies import get_current_org_id, get_current_user, require_tool
from app.models.db.user import User

router = APIRouter(prefix="/attackmapper", tags=["AttackMapper"])

# ── Ensure bundled attackmapper package is importable ────────────────────────
# Repo layout:  <repo>/tools/attackmapper/attackmapper/__init__.py
# This file:    <repo>/platform/backend/app/api/v1/attackmapper.py
# We try multiple candidate paths to handle different working directories.
def _ensure_attackmapper_on_path() -> None:
    import importlib.util
    if importlib.util.find_spec("attackmapper"):
        return  # already importable (pip-installed)
    this_file = Path(__file__).resolve()
    # Walk up from this file looking for tools/attackmapper
    for parent in this_file.parents:
        candidate = parent / "tools" / "attackmapper"
        if (candidate / "attackmapper" / "__init__.py").exists():
            if str(candidate) not in sys.path:
                sys.path.insert(0, str(candidate))
            return

_ensure_attackmapper_on_path()


def _am_available() -> bool:
    try:
        import importlib.util
        return importlib.util.find_spec("attackmapper") is not None
    except Exception:
        return False


def _get_module(infra: str):
    """Return the right infrastructure module instance for the given infra key."""
    from attackmapper.modules.ad.techniques import ADModule
    from attackmapper.modules.aws.techniques import AWSModule
    from attackmapper.modules.azure.techniques import AzureModule
    from attackmapper.modules.gcp.techniques import GCPModule
    from attackmapper.modules.network.techniques import NetworkModule
    _MAP = {"ad": ADModule, "aws": AWSModule, "azure": AzureModule, "gcp": GCPModule, "network": NetworkModule}
    cls = _MAP.get(infra)
    if not cls:
        raise ValueError(f"Unknown infra: {infra}")
    m = cls()
    m.load_techniques()
    return m

# In-memory scan history
_scan_history: dict[str, dict] = {}

# ── Filesystem history (org-scoped) — same pattern as secrets.py/cspm.py ─────

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)


def _validate_uuid(value: str, label: str) -> str:
    if not _UUID_RE.match(value):
        raise HTTPException(status_code=400, detail=f"Invalid {label}: must be a UUID")
    return value


def _history_dir(org_id: str) -> Path:
    d = Path(_get_settings().ATTACKTRACE_WORKSPACE_DIR) / "attackmapper" / org_id
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


from app.core.sse import sse_event as _sse


def _technique_to_dict(tech) -> dict:
    """Convert an AttackTechnique model to a plain dict using its own serializer."""
    if hasattr(tech, "to_dict"):
        return tech.to_dict()
    # fallback for any future shape changes
    return {
        "id": getattr(tech, "id", ""),
        "mitre_id": getattr(tech, "mitre_id", ""),
        "name": getattr(tech, "name", ""),
        "phase": str(getattr(tech, "phase", "") or ""),
        "infrastructure": str(getattr(tech, "infrastructure", "") or ""),
        "description": getattr(tech, "description", ""),
        "prerequisites": list(getattr(tech, "prerequisites", []) or []),
        "tools": list(getattr(tech, "tools", []) or []),
        "commands": list(getattr(tech, "commands", []) or []),
        "detection": getattr(tech, "detection", ""),
        "references": list(getattr(tech, "references", []) or []),
        "next_techniques": list(getattr(tech, "next_techniques", []) or []),
        "risk_level": getattr(tech, "risk_level", "medium"),
    }


def _chain_to_dict(chain) -> dict | None:
    """Convert an AttackPath model to a plain dict using its own serializer."""
    if chain is None:
        return None
    if hasattr(chain, "to_dict"):
        return chain.to_dict()
    # fallback
    steps = []
    for step in getattr(chain, "steps", []):
        steps.append({
            "step_number": getattr(step, "step_number", 0),
            "technique": _technique_to_dict(step.technique) if getattr(step, "technique", None) else {},
            "description": getattr(step, "description", ""),
        })
    return {
        "id": getattr(chain, "id", ""),
        "name": getattr(chain, "name", ""),
        "infrastructure": str(getattr(chain, "infrastructure", "") or ""),
        "start_phase": str(getattr(chain, "start_phase", "") or ""),
        "end_phase": str(getattr(chain, "end_phase", "") or ""),
        "steps": steps,
        "total_risk_score": getattr(chain, "total_risk_score", 0.0),
    }


async def _stream_attackmapper(scan_id: str, req: AttackMapperRequest, org_id: uuid.UUID) -> AsyncGenerator[str, None]:
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
        "org_id": str(org_id),
    }

    yield _sse("start", {
        "scan_id": scan_id,
        "infrastructure_type": infra,
        "infrastructure_label": infra_label,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    techniques: list[dict] = []
    attack_chain: dict | None = None
    threat_intel: dict | None = None

    try:
        # ── Step 1: Load attack techniques ───────────────────────────────────
        yield _sse("progress", {"message": f"Loading {infra_label} attack techniques..."})
        await asyncio.sleep(0)

        mod = await asyncio.to_thread(_get_module, infra)
        raw_techs = mod.get_all_techniques()

        # Apply filters
        if req.phase:
            raw_techs = [t for t in raw_techs if str(getattr(t, "phase", "")).lower() == req.phase.lower()]
        if req.category:
            raw_techs = [t for t in raw_techs if req.category.lower() in str(getattr(t, "name", "")).lower()
                         or req.category.lower() in str(getattr(t, "description", "")).lower()]
        if req.search:
            q = req.search.lower()
            raw_techs = [t for t in raw_techs if q in str(getattr(t, "name", "")).lower()
                         or q in str(getattr(t, "description", "")).lower()]

        techniques = [_technique_to_dict(t) for t in raw_techs]
        yield _sse("progress", {"message": f"Loaded {len(techniques)} techniques for {infra_label}"})
        await asyncio.sleep(0)

        # ── Step 2: Build full attack chain ──────────────────────────────────
        yield _sse("progress", {"message": "Building full attack chain..."})
        await asyncio.sleep(0)

        raw_chain = await asyncio.to_thread(mod.generate_full_chain)
        attack_chain = _chain_to_dict(raw_chain)
        step_count = len(attack_chain.get("steps", [])) if attack_chain else 0
        yield _sse("progress", {"message": f"Attack chain built: {step_count} steps"})
        await asyncio.sleep(0)

        # ── Step 3: Threat intelligence ──────────────────────────────────────
        yield _sse("progress", {"message": "Fetching threat intelligence..."})
        await asyncio.sleep(0)

        from attackmapper.intel.manager import ThreatIntelManager
        from attackmapper.core.models import InfrastructureType as _IT
        _INFRA_TYPE_MAP = {
            "ad": _IT.ACTIVE_DIRECTORY, "aws": _IT.AWS,
            "azure": _IT.AZURE, "gcp": _IT.GCP, "network": _IT.NETWORK,
        }
        mgr = ThreatIntelManager()
        report = await asyncio.to_thread(mgr.get_threat_report, _INFRA_TYPE_MAP[infra])

        cves = [
            {"cve_id": c.cve_id, "description": c.description, "cvss_score": c.cvss_score,
             "severity": c.severity, "exploitation_status": c.exploitation_status}
            for c in (report.critical_cves or [])
        ]
        actors = [
            {"name": a.name, "aliases": a.aliases, "description": a.description,
             "ttps": a.ttps, "recent_activity": a.recent_activity}
            for a in (report.active_threat_actors or [])
        ]
        threat_intel = {
            "critical_cves": cves,
            "active_threat_actors": actors,
            "trending_techniques": report.trending_techniques or [],
            "last_updated": report.last_updated,
        }
        yield _sse("progress", {"message": f"Threat intel loaded: {len(cves)} critical CVEs"})

        _scan_history[scan_id].update({
            "status": "completed",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "techniques": techniques,
            "attack_chain": attack_chain,
            "threat_intel": threat_intel,
        })

        # Persist the completed scan to disk — the in-memory dict above is
        # only good for the process lifetime; without this, history was lost
        # on every backend restart.
        _save_scan_result(str(org_id), _scan_history[scan_id])

        yield _sse("complete", {
            "scan_id": scan_id,
            "infrastructure_type": infra,
            "infrastructure_label": infra_label,
            "technique_count": len(techniques),
            "chain_steps": step_count,
            "critical_cves": len(cves),
            "techniques": techniques,
            "attack_chain": attack_chain,
            "threat_intel": threat_intel,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    except Exception as exc:
        _scan_history[scan_id].update({"status": "failed", "error": str(exc)})
        _save_scan_result(str(org_id), _scan_history[scan_id])
        yield _sse("error", {"message": str(exc)})


@router.post("/scan", summary="Run an AttackMapper analysis and stream results")
async def run_attackmapper_scan(
    payload: AttackMapperRequest,
    current_user: Annotated[User, Depends(require_tool("attackmapper"))],
    org_id: uuid.UUID = Depends(get_current_org_id),
) -> StreamingResponse:
    if not _am_available():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="attackmapper is not installed on this server",
        )
    scan_id = str(uuid.uuid4())
    from app.services.scan_activity import tee_scan_activity
    return StreamingResponse(
        tee_scan_activity(org_id, "attackmapper", payload.infrastructure_type, scan_id, _stream_attackmapper(scan_id, payload, org_id)),
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
    org_id: uuid.UUID = Depends(get_current_org_id),
) -> dict:
    scans = sorted(
        (s for s in _scan_history.values() if s.get("org_id") == str(org_id)),
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
    org_id: uuid.UUID = Depends(get_current_org_id),
) -> dict:
    scan = _scan_history.get(scan_id)
    if not scan or scan.get("org_id") != str(org_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


# ── Filesystem-backed history endpoints (survive backend restarts) ───────────

@router.get("/history", summary="List AttackMapper scan history (disk-persisted)")
async def list_history(
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: uuid.UUID = Depends(get_current_org_id),
) -> dict:
    records = _load_history(str(org_id))
    # Lightweight summaries — no full technique/chain/intel data
    summaries = []
    for r in records:
        summaries.append({
            "id": r.get("id"),
            "infrastructure_type": r.get("infrastructure_type"),
            "infrastructure_label": r.get("infrastructure_label"),
            "status": r.get("status"),
            "started_at": r.get("started_at"),
            "completed_at": r.get("completed_at"),
            "technique_count": len(r.get("techniques", [])),
            "chain_steps": len((r.get("attack_chain") or {}).get("steps", [])),
            "critical_cves": len((r.get("threat_intel") or {}).get("critical_cves", [])),
        })
    return {"items": summaries, "total": len(summaries)}


@router.get("/history/{scan_id}", summary="Get a single AttackMapper scan result (disk-persisted)")
async def get_history_item(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: uuid.UUID = Depends(get_current_org_id),
) -> dict:
    record = _load_scan(str(org_id), scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    return record


@router.delete("/history/{scan_id}", summary="Delete an AttackMapper scan result")
async def delete_history_item(
    scan_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    org_id: uuid.UUID = Depends(get_current_org_id),
) -> dict:
    deleted = _delete_scan(str(org_id), scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"ok": True, "scan_id": scan_id}


async def _stream_update_intel() -> AsyncGenerator[str, None]:
    """Stream threat intel update progress using the Python API directly."""
    from attackmapper.intel.manager import ThreatIntelManager

    yield _sse("start", {
        "message": "Starting threat intelligence update from internet sources...",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    progress_events: list[dict] = []

    def _progress(source: str, status: str, count: int = 0) -> None:
        icon = "✓" if status == "success" else ("✗" if status == "error" else ("⚠" if "skip" in status else "⟳"))
        line = f"[{source}] {status}" + (f" — {count} items" if count else "")
        progress_events.append({"line": line, "icon": icon, "source": source, "status": status, "count": count})

    try:
        mgr = ThreatIntelManager()
        # update_intel is async — run it as a background task
        stats_task = asyncio.create_task(mgr.update_intel(progress_callback=_progress))

        # Stream progress events while the update runs
        last_sent = 0
        while not stats_task.done():
            while last_sent < len(progress_events):
                yield _sse("progress", progress_events[last_sent])
                last_sent += 1
            await asyncio.sleep(0.2)

        # Drain any remaining events
        while last_sent < len(progress_events):
            yield _sse("progress", progress_events[last_sent])
            last_sent += 1

        stats = await stats_task

        cache_stats = await asyncio.to_thread(mgr.cache.get_stats)
        yield _sse("complete", {
            "message": "Threat intelligence update complete",
            "items_fetched": stats.get("cves", 0) + stats.get("actors", 0),
            "cached_cves": cache_stats.get("cve_count", 0),
            "failed_sources": stats.get("errors", []),
            "last_updated": cache_stats.get("last_update") or datetime.now(timezone.utc).isoformat(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_items": stats.get("cves", 0) + stats.get("actors", 0) + stats.get("techniques", 0),
        })

    except Exception as exc:
        yield _sse("error", {"message": str(exc)})


@router.post("/update-intel", summary="Update threat intelligence from internet sources (streaming)")
async def update_intel(
    current_user: Annotated[User, Depends(require_tool("attackmapper"))],
) -> StreamingResponse:
    if not _am_available():
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

# Country/attribution keywords parsed from MITRE ATT&CK descriptions
_COUNTRY_PATTERNS: list[tuple[str, str]] = [
    ("Russia", "🇷🇺 Russia"),
    ("Russian", "🇷🇺 Russia"),
    ("China", "🇨🇳 China"),
    ("Chinese", "🇨🇳 China"),
    ("North Korea", "🇰🇵 North Korea"),
    ("North Korean", "🇰🇵 North Korea"),
    ("Iran", "🇮🇷 Iran"),
    ("Iranian", "🇮🇷 Iran"),
    ("Israel", "🇮🇱 Israel"),
    ("Pakistan", "🇵🇰 Pakistan"),
    ("India", "🇮🇳 India"),
    ("Vietnam", "🇻🇳 Vietnam"),
    ("Turkey", "🇹🇷 Turkey"),
    ("Belarus", "🇧🇾 Belarus"),
    ("United States", "🇺🇸 United States"),
    ("Gaza", "🇵🇸 Gaza"),
]


def _extract_country(description: str) -> str:
    """Infer country attribution from MITRE-style description text."""
    for keyword, label in _COUNTRY_PATTERNS:
        if keyword in description:
            return label
    return "Unknown"


def _strip_mitre_links(text: str) -> str:
    """Remove [Label](url) markdown links, keep only the label."""
    import re as _re
    return _re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)


def _extract_active_since(description: str) -> str | None:
    """Parse 'active since at least YYYY' from description."""
    import re as _re
    m = _re.search(r"active since at least (\w+ \d{4}|\d{4})", description)
    return m.group(1) if m else None


@router.get("/apt-groups", summary="List APT groups / threat actors from the local intel cache")
async def get_apt_groups(
    current_user: Annotated[User, Depends(get_current_user)],
    search: str | None = None,
    country: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    """Return threat actor records from the attackmapper SQLite cache with parsed attribution."""
    import sqlite3 as _sqlite3
    import re as _re

    if not os.path.exists(_INTEL_DB):
        return {"items": [], "total": 0, "note": "Intel cache not found — run Update Intel first"}

    try:
        conn = _sqlite3.connect(_INTEL_DB)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT name, aliases, description, targeted_infrastructure, ttps, "
            "recent_activity, references_json, cached_at FROM threat_actors"
        )
        rows = cursor.fetchall()
        conn.close()

        items = []
        for row in rows:
            name, aliases_raw, description, infra_raw, ttps_raw, recent_activity, refs_raw, cached_at = row
            description = description or ""
            clean_desc = _strip_mitre_links(description)

            try:
                aliases: list[str] = json.loads(aliases_raw) if aliases_raw else []
            except Exception:
                aliases = []
            # Remove the name itself from aliases list
            aliases = [a for a in aliases if a.lower() != name.lower()]

            try:
                ttps: list[str] = json.loads(ttps_raw) if ttps_raw else []
            except Exception:
                ttps = []
            try:
                references: list[str] = json.loads(refs_raw) if refs_raw else []
            except Exception:
                references = []

            attribution = _extract_country(clean_desc)
            active_since = _extract_active_since(clean_desc)

            # Derive activity status
            status = "active"
            if recent_activity == "inactive" or "disbanded" in clean_desc.lower():
                status = "inactive"
            elif not active_since:
                status = "unknown"

            # Build a 2-sentence excerpt (strip citation noise)
            excerpt = _re.sub(r"\(Citation:[^)]+\)", "", clean_desc).strip()
            sentences = [s.strip() for s in excerpt.split(".") if len(s.strip()) > 20]
            excerpt = ". ".join(sentences[:2]) + ("." if sentences else "")

            items.append({
                "name": name,
                "aliases": aliases[:6],
                "attribution": attribution,
                "active_since": active_since,
                "status": status,
                "excerpt": excerpt[:400],
                "techniques_count": len(ttps),
                "references_count": len(references),
                "cached_at": cached_at,
            })

        # Filter
        if search:
            q = search.lower()
            items = [
                it for it in items
                if q in it["name"].lower()
                or any(q in a.lower() for a in it["aliases"])
                or q in it["excerpt"].lower()
                or q in it["attribution"].lower()
            ]
        if country:
            items = [it for it in items if country.lower() in it["attribution"].lower()]

        # Sort: active first, then alphabetically
        STATUS_ORDER = {"active": 0, "unknown": 1, "inactive": 2}
        items.sort(key=lambda x: (STATUS_ORDER.get(x["status"], 1), x["name"]))

        total = len(items)
        return {"items": items[offset: offset + limit], "total": total}

    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


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


class CorrelateRequest(BaseModel):
    cve_ids: list[str]
    infrastructure_type: str = "ad"

    @field_validator("infrastructure_type")
    @classmethod
    def validate_infra_type(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in VALID_INFRA:
            raise ValueError(f"infrastructure_type must be one of: {', '.join(sorted(VALID_INFRA))}")
        return v

    @field_validator("cve_ids")
    @classmethod
    def validate_cve_ids(cls, v: list[str]) -> list[str]:
        import re
        cleaned = []
        for cve in v:
            cve = cve.strip().upper()
            if re.match(r"^CVE-\d{4}-\d+$", cve):
                cleaned.append(cve)
        if not cleaned:
            raise ValueError("No valid CVE IDs provided (expected format: CVE-YYYY-NNNNN)")
        return cleaned[:50]  # cap at 50


def _tokenize(text: str) -> set[str]:
    """Extract meaningful lowercase tokens from text, removing stop words."""
    import re as _re
    text = text.lower()
    text = _re.sub(r"[^a-z0-9\s]", " ", text)
    stopwords = {
        "the", "a", "an", "and", "or", "in", "on", "at", "to", "for", "of",
        "with", "this", "that", "is", "are", "was", "be", "by", "from", "it",
        "its", "as", "can", "may", "via", "using", "use", "used", "allow",
        "allows", "attacker", "attackers", "remote", "local", "access",
        "could", "when", "which", "has", "have", "not", "if", "into",
    }
    return {w for w in text.split() if len(w) > 2 and w not in stopwords}


@router.post("/correlate", summary="Correlate CVE IDs to attack techniques via keyword scoring")
async def correlate_cves(
    payload: CorrelateRequest,
    current_user: Annotated[User, Depends(require_tool("attackmapper"))],
) -> dict:
    """
    Match CVE IDs to relevant attack techniques using keyword overlap scoring.
    Boosts: infrastructure match ×1.5, in-the-wild exploitation ×1.2, CVSS≥9 ×1.3.
    """
    import sqlite3 as _sqlite3

    # ── 1. Load CVE details from SQLite cache ─────────────────────────────────
    cve_map: dict[str, dict] = {}
    if os.path.exists(_INTEL_DB):
        conn = _sqlite3.connect(_INTEL_DB)
        cursor = conn.cursor()
        placeholders = ",".join("?" * len(payload.cve_ids))
        cursor.execute(
            f"SELECT cve_id, description, cvss_score, severity, affected_products, "
            f"affected_infrastructure, exploitation_status FROM cves WHERE cve_id IN ({placeholders})",
            payload.cve_ids,
        )
        for row in cursor.fetchall():
            try:
                products = json.loads(row[4]) if row[4] else []
            except Exception:
                products = []
            try:
                infra = json.loads(row[5]) if row[5] else []
            except Exception:
                infra = []
            cve_map[row[0]] = {
                "cve_id": row[0],
                "description": row[1] or "",
                "cvss_score": row[2] or 0.0,
                "severity": row[3] or "unknown",
                "affected_products": products,
                "affected_infrastructure": infra,
                "exploitation_status": row[6] or "",
            }
        conn.close()

    # ── 2. Load techniques via Python API ────────────────────────────────────
    techniques: list[dict] = []
    try:
        mod = await asyncio.to_thread(_get_module, payload.infrastructure_type)
        techniques = [_technique_to_dict(t) for t in mod.get_all_techniques()]
    except Exception:
        techniques = []

    # Pre-tokenize techniques once
    tech_token_cache: list[tuple[dict, set[str]]] = []
    for tech in techniques:
        tokens: set[str] = _tokenize(tech.get("name", ""))
        tokens |= _tokenize(tech.get("description", ""))
        for item in tech.get("tools", []):
            tokens |= _tokenize(item)
        for item in tech.get("prerequisites", []):
            tokens |= _tokenize(item)
        tech_token_cache.append((tech, tokens))

    # ── 3. Score each CVE ─────────────────────────────────────────────────────
    results = []

    for cve_id in payload.cve_ids:
        cve = cve_map.get(cve_id)
        if not cve:
            results.append({
                "cve": {"cve_id": cve_id, "not_found": True},
                "techniques": [],
                "error": "CVE not found in local cache — run Update Intel to populate the database.",
            })
            continue

        cve_tokens = _tokenize(cve["description"])
        for p in cve["affected_products"]:
            cve_tokens |= _tokenize(p)

        scored = []
        for tech, tech_tokens in tech_token_cache:
            if not cve_tokens or not tech_tokens:
                continue
            overlap = cve_tokens & tech_tokens
            if not overlap:
                continue

            # Jaccard-like score normalised by geometric mean of token set sizes
            base_score = len(overlap) / (len(cve_tokens) ** 0.5 * len(tech_tokens) ** 0.5 + 1e-9)

            multiplier = 1.0
            if payload.infrastructure_type in (tech.get("infrastructure") or "").lower():
                multiplier *= 1.5
            if cve["exploitation_status"] == "in-the-wild":
                multiplier *= 1.2
            if cve["cvss_score"] >= 9.0:
                multiplier *= 1.3
            elif cve["cvss_score"] >= 7.0:
                multiplier *= 1.1

            final_score = base_score * multiplier
            if final_score >= 0.15:
                confidence = "high"
            elif final_score >= 0.07:
                confidence = "medium"
            else:
                confidence = "low"

            scored.append({
                "technique": tech,
                "score": round(final_score, 4),
                "confidence": confidence,
                "matched_keywords": sorted(list(overlap))[:10],
            })

        scored.sort(key=lambda x: x["score"], reverse=True)
        results.append({"cve": cve, "techniques": scored[:8]})

    return {"results": results, "infrastructure_type": payload.infrastructure_type}


@router.get("/stats", summary="Get AttackMapper cache statistics")
async def get_attackmapper_stats(
    current_user: Annotated[User, Depends(get_current_user)],
) -> dict:
    try:
        from attackmapper.intel.manager import ThreatIntelManager
        mgr = ThreatIntelManager()
        cache_stats = await asyncio.to_thread(mgr.cache.get_stats)

        # Count techniques per module
        tech_counts: dict[str, int] = {}
        for infra_key in INFRA_LABELS:
            try:
                mod = await asyncio.to_thread(_get_module, infra_key)
                tech_counts[infra_key] = len(mod.get_all_techniques())
            except Exception:
                tech_counts[infra_key] = 0

        total_items = (
            sum(tech_counts.values())
            + cache_stats.get("cve_count", 0)
            + cache_stats.get("threat_actor_count", 0)
        )
        return {
            "techniques": tech_counts,
            "cached_cves": cache_stats.get("cve_count", 0),
            "cached_threat_actors": cache_stats.get("threat_actor_count", 0),
            "custom_feeds": cache_stats.get("custom_feed_count", 0),
            "last_updated": cache_stats.get("last_update"),
            "total_items": total_items,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
