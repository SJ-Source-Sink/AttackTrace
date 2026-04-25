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

from app.core.dependencies import get_current_user, require_tool
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
    current_user: Annotated[User, Depends(require_tool("attackmapper"))],
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
            "total_items": items_total,
        })

    except Exception as exc:
        yield _sse("error", {"message": str(exc)})


@router.post("/update-intel", summary="Update threat intelligence from internet sources (streaming)")
async def update_intel(
    current_user: Annotated[User, Depends(require_tool("attackmapper"))],
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

    # ── 2. Load techniques via CLI ─────────────────────────────────────────────
    am_bin = shutil.which("attackmapper") or "attackmapper"
    techniques: list[dict] = []
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tech_file = tmp.name
    tech_data = await _run_attackmapper_cmd(
        [am_bin, payload.infrastructure_type, "--format", "json", "--output", tech_file],
        tech_file,
    )
    if tech_data:
        techniques = tech_data.get("techniques", [])

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

        stats["total_items"] = (
            sum(stats["techniques"].values())
            + stats["cached_cves"]
            + stats["cached_threat_actors"]
        )
        return stats
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
